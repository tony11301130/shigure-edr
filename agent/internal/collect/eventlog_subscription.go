package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

const (
	defaultWindowsEventLogQueueSize = 1024
	defaultWindowsEventLogStateFile = "windows-eventlog-checkpoints.json"
)

type WindowsEventLogRecord struct {
	Query        string
	LogName      string
	EventID      int
	RecordID     int64
	ProviderName string
	TimeCreated  string
	Message      string
	User         string
	ProcessID    string
	Raw          map[string]any
}

type WindowsEventLogSubscriberOptions struct {
	QueueSize      int
	CheckpointPath string
}

type WindowsEventLogSubscriber struct {
	tenantID       string
	checkpointPath string
	queue          chan WindowsEventLogRecord
	cancel         context.CancelFunc
	done           chan struct{}

	mu              sync.Mutex
	running         bool
	started         bool
	droppedEvents   int
	processedEvents int
	skippedEvents   int
	recordGaps      int
	lastGap         string
	lastError       string
	events          []agentapi.NormalizedEvent
	checkpoints     map[string]int64
}

var (
	defaultWindowsEventLogSubscriberMu     sync.Mutex
	defaultWindowsEventLogSubscriber       *WindowsEventLogSubscriber
	defaultWindowsEventLogCheckpointPathMu sync.Mutex
	defaultWindowsEventLogCheckpointPath   string
)

func NewWindowsEventLogSubscriber(tenantID string, opts WindowsEventLogSubscriberOptions) *WindowsEventLogSubscriber {
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultWindowsEventLogQueueSize
	}
	if opts.CheckpointPath == "" {
		opts.CheckpointPath = filepath.Join(os.TempDir(), defaultWindowsEventLogStateFile)
	}
	s := &WindowsEventLogSubscriber{
		tenantID:       tenantID,
		checkpointPath: opts.CheckpointPath,
		queue:          make(chan WindowsEventLogRecord, opts.QueueSize),
		done:           make(chan struct{}),
		checkpoints:    map[string]int64{},
	}
	if err := s.loadCheckpoints(); err != nil {
		s.lastError = err.Error()
	}
	return s
}

func defaultWindowsEventLogSubscriberForTenant(tenantID string) *WindowsEventLogSubscriber {
	defaultWindowsEventLogSubscriberMu.Lock()
	defer defaultWindowsEventLogSubscriberMu.Unlock()
	if defaultWindowsEventLogSubscriber != nil {
		return defaultWindowsEventLogSubscriber
	}
	defaultWindowsEventLogSubscriber = NewWindowsEventLogSubscriber(tenantID, WindowsEventLogSubscriberOptions{CheckpointPath: defaultWindowsEventLogCheckpointPathValue()})
	return defaultWindowsEventLogSubscriber
}

func StartDefaultWindowsEventLogSubscriber(ctx context.Context, tenantID, checkpointPath string) error {
	defaultWindowsEventLogSubscriberMu.Lock()
	subscriber := defaultWindowsEventLogSubscriber
	if subscriber == nil || checkpointPath != "" && subscriber.checkpointPath != checkpointPath {
		defaultWindowsEventLogSubscriber = NewWindowsEventLogSubscriber(tenantID, WindowsEventLogSubscriberOptions{CheckpointPath: checkpointPath})
		subscriber = defaultWindowsEventLogSubscriber
	}
	defaultWindowsEventLogSubscriberMu.Unlock()
	return subscriber.Start(ctx)
}

func StopDefaultWindowsEventLogSubscriber() {
	defaultWindowsEventLogSubscriberMu.Lock()
	subscriber := defaultWindowsEventLogSubscriber
	defaultWindowsEventLogSubscriberMu.Unlock()
	if subscriber != nil {
		subscriber.Stop()
	}
}

func DrainDefaultWindowsEventLogSubscriptionEvents(tenantID string, max int) []agentapi.NormalizedEvent {
	return defaultWindowsEventLogSubscriberForTenant(tenantID).DrainEvents(max)
}

func WindowsEventLogSubscriberHealth() map[string]any {
	defaultWindowsEventLogSubscriberMu.Lock()
	defer defaultWindowsEventLogSubscriberMu.Unlock()
	if defaultWindowsEventLogSubscriber == nil {
		return map[string]any{
			"collector":        "windows_event_log_subscription",
			"status":           "disabled",
			"running":          false,
			"queue_capacity":   0,
			"queue_depth":      0,
			"dropped_events":   0,
			"processed_events": 0,
			"skipped_events":   0,
			"record_gaps":      0,
			"last_gap":         "",
			"last_error":       "",
		}
	}
	return defaultWindowsEventLogSubscriber.Health()
}

func SetDefaultWindowsEventLogCheckpointPathForTest(path string) {
	defaultWindowsEventLogCheckpointPathMu.Lock()
	defaultWindowsEventLogCheckpointPath = path
	defaultWindowsEventLogCheckpointPathMu.Unlock()
	defaultWindowsEventLogSubscriberMu.Lock()
	defaultWindowsEventLogSubscriber = nil
	defaultWindowsEventLogSubscriberMu.Unlock()
}

func defaultWindowsEventLogCheckpointPathValue() string {
	defaultWindowsEventLogCheckpointPathMu.Lock()
	defer defaultWindowsEventLogCheckpointPathMu.Unlock()
	return defaultWindowsEventLogCheckpointPath
}

func (s *WindowsEventLogSubscriber) Start(ctx context.Context) error {
	if s.checkpointPath == "" {
		return errors.New("event log checkpoint path required")
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	if s.started {
		s.done = make(chan struct{})
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true
	s.started = true
	s.mu.Unlock()

	go s.run(runCtx)
	if err := startPlatformWindowsEventLogSource(runCtx, s); err != nil {
		cancel()
		s.setLastError(err)
		s.Stop()
		return err
	}
	return nil
}

func (s *WindowsEventLogSubscriber) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	running := s.running
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if running {
		<-done
	}
}

func (s *WindowsEventLogSubscriber) Enqueue(record WindowsEventLogRecord) bool {
	select {
	case s.queue <- record:
		return true
	default:
		s.mu.Lock()
		s.droppedEvents++
		s.mu.Unlock()
		return false
	}
}

func (s *WindowsEventLogSubscriber) Observe(record WindowsEventLogRecord) (agentapi.NormalizedEvent, bool, error) {
	key := eventLogCheckpointKey(record)
	if key == "" {
		return agentapi.NormalizedEvent{}, false, errors.New("event log record query or log name required")
	}
	if record.RecordID <= 0 {
		return agentapi.NormalizedEvent{}, false, errors.New("event log record id required")
	}

	s.mu.Lock()
	last := s.checkpoints[key]
	if record.RecordID <= last {
		s.skippedEvents++
		s.mu.Unlock()
		return agentapi.NormalizedEvent{}, false, nil
	}
	if last > 0 && record.RecordID > last+1 {
		s.recordGaps++
		s.lastGap = fmt.Sprintf("%s:%d-%d", key, last+1, record.RecordID-1)
	}
	s.checkpoints[key] = record.RecordID
	s.processedEvents++
	s.mu.Unlock()

	if err := s.saveCheckpoints(); err != nil {
		s.mu.Lock()
		s.lastError = err.Error()
		s.mu.Unlock()
		return agentapi.NormalizedEvent{}, false, err
	}
	return s.eventFromRecord(record), true, nil
}

func (s *WindowsEventLogSubscriber) DrainEvents(max int) []agentapi.NormalizedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if max <= 0 || max > len(s.events) {
		max = len(s.events)
	}
	out := append([]agentapi.NormalizedEvent(nil), s.events[:max]...)
	s.events = append(s.events[:0], s.events[max:]...)
	return out
}

func (s *WindowsEventLogSubscriber) Health() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := "stopped"
	if s.running {
		status = "running"
	}
	return map[string]any{
		"collector":        "windows_event_log_subscription",
		"status":           status,
		"running":          s.running,
		"queue_capacity":   cap(s.queue),
		"queue_depth":      len(s.queue),
		"dropped_events":   s.droppedEvents,
		"processed_events": s.processedEvents,
		"skipped_events":   s.skippedEvents,
		"record_gaps":      s.recordGaps,
		"last_gap":         s.lastGap,
		"last_error":       s.lastError,
	}
}

func (s *WindowsEventLogSubscriber) setLastError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
}

func (s *WindowsEventLogSubscriber) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.running = false
		close(s.done)
		s.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case record := <-s.queue:
			event, accepted, err := s.Observe(record)
			if err != nil {
				continue
			}
			if accepted {
				s.mu.Lock()
				s.events = append(s.events, event)
				s.mu.Unlock()
			}
		}
	}
}

func (s *WindowsEventLogSubscriber) eventFromRecord(record WindowsEventLogRecord) agentapi.NormalizedEvent {
	profile := eventLogProfile(record.Query, record.LogName, record.EventID)
	raw := map[string]any{
		"collector":    "windows_event_log",
		"platform":     "windows_evtsubscribe",
		"query":        profile.Name,
		"event_id":     record.EventID,
		"record_id":    record.RecordID,
		"provider":     record.ProviderName,
		"log_name":     record.LogName,
		"time_created": record.TimeCreated,
		"message":      record.Message,
	}
	for key, value := range record.Raw {
		raw[key] = value
	}
	mitre := []string{}
	if profile.MITRE != "" {
		mitre = append(mitre, profile.MITRE)
	}
	return agentapi.NormalizedEvent{
		Source:        "windows_event_log",
		EventType:     profile.EventType,
		TenantID:      s.tenantID,
		SourceEventID: strconv.FormatInt(record.RecordID, 10),
		Host:          record.RawString("host"),
		User:          firstNonEmptyEventLogString(record.User, userFromEventLogRecord(profile, record.Message)),
		ProcessID:     record.ProcessID,
		CommandLine:   commandLineFromEventLogRecord(profile, record.Message),
		Severity:      profile.Severity,
		Mitre:         mitre,
		Raw:           raw,
	}
}

func (r WindowsEventLogRecord) RawString(key string) string {
	if r.Raw == nil {
		return ""
	}
	if value, ok := r.Raw[key].(string); ok {
		return value
	}
	return ""
}

func (s *WindowsEventLogSubscriber) loadCheckpoints() error {
	b, err := os.ReadFile(s.checkpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var checkpoints map[string]int64
	if err := json.Unmarshal(b, &checkpoints); err != nil {
		return err
	}
	s.checkpoints = checkpoints
	return nil
}

func (s *WindowsEventLogSubscriber) saveCheckpoints() error {
	s.mu.Lock()
	checkpoints := map[string]int64{}
	for key, value := range s.checkpoints {
		checkpoints[key] = value
	}
	s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.checkpointPath), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(checkpoints, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.checkpointPath, b, 0600)
}

type windowsEventLogProfile struct {
	Name      string
	LogName   string
	EventType string
	Severity  string
	MITRE     string
}

func eventLogProfile(query, logName string, eventID int) windowsEventLogProfile {
	profiles := []windowsEventLogProfile{
		{Name: "powershell_operational", LogName: "Microsoft-Windows-PowerShell/Operational", EventType: "script_result", Severity: "medium", MITRE: "T1059.001"},
		{Name: "security_auth", LogName: "Security", EventType: "auth_event", Severity: "info"},
		{Name: "service_control_manager", LogName: "System", EventType: "endpoint_state", Severity: "medium", MITRE: "T1543.003"},
		{Name: "task_scheduler", LogName: "Microsoft-Windows-TaskScheduler/Operational", EventType: "endpoint_state", Severity: "low", MITRE: "T1053.005"},
	}
	for _, profile := range profiles {
		if query == profile.Name || logName == profile.LogName {
			return profile
		}
	}
	return windowsEventLogProfile{Name: firstNonEmptyEventLogString(query, logName, "unknown"), LogName: logName, EventType: "endpoint_state", Severity: "info"}
}

func eventLogCheckpointKey(record WindowsEventLogRecord) string {
	profile := eventLogProfile(record.Query, record.LogName, record.EventID)
	return profile.Name
}

func commandLineFromEventLogRecord(profile windowsEventLogProfile, message string) string {
	if profile.Name != "powershell_operational" {
		return ""
	}
	return compactEventLogMessage(message, 2000)
}

func userFromEventLogRecord(profile windowsEventLogProfile, message string) string {
	if profile.Name != "security_auth" {
		return ""
	}
	for _, label := range []string{"Account Name:", "帳戶名稱:"} {
		idx := strings.Index(message, label)
		if idx >= 0 {
			line := strings.SplitN(message[idx+len(label):], "\n", 2)[0]
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func compactEventLogMessage(message string, max int) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > max {
		return message[:max]
	}
	return message
}

func firstNonEmptyEventLogString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
