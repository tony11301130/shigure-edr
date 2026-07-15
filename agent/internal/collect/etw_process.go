package collect

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

const (
	ETWProcessStart = "process_start"
	ETWProcessStop  = "process_stop"

	defaultETWProcessQueueSize = 1024
)

type ETWProcessRecord struct {
	Kind            string
	Host            string
	ProcessID       uint32
	ParentProcessID uint32
	ProcessName     string
	ImagePath       string
	ImageHash       string
	CommandLine     string
	CreateTime      string
	ExitTime        string
	User            string
	Raw             map[string]any
}

type ETWProcessCollectorOptions struct {
	QueueSize int
}

type ETWProcessCollector struct {
	tenantID string
	tracker  *ProcessTracker
	queue    chan ETWProcessRecord
	cancel   context.CancelFunc
	done     chan struct{}

	mu              sync.Mutex
	running         bool
	started         bool
	droppedEvents   int
	processedEvents int
	lastError       string
	events          []agentapi.NormalizedEvent
}

var (
	defaultETWProcessCollectorMu sync.Mutex
	defaultETWProcessCollector   *ETWProcessCollector
)

func NewETWProcessCollector(tenantID string, tracker *ProcessTracker, opts ETWProcessCollectorOptions) *ETWProcessCollector {
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultETWProcessQueueSize
	}
	return &ETWProcessCollector{
		tenantID: tenantID,
		tracker:  tracker,
		queue:    make(chan ETWProcessRecord, opts.QueueSize),
		done:     make(chan struct{}),
	}
}

func defaultETWProcessCollectorForTenant(tenantID string) *ETWProcessCollector {
	defaultETWProcessCollectorMu.Lock()
	defer defaultETWProcessCollectorMu.Unlock()
	if defaultETWProcessCollector != nil {
		return defaultETWProcessCollector
	}
	inv := HostInventory()
	tracker := defaultProcessTrackerFor(inv.Host, hostBootID())
	defaultETWProcessCollector = NewETWProcessCollector(tenantID, tracker, ETWProcessCollectorOptions{})
	return defaultETWProcessCollector
}

func DrainDefaultETWProcessEvents(tenantID string, max int) []agentapi.NormalizedEvent {
	return defaultETWProcessCollectorForTenant(tenantID).DrainEvents(max)
}

func StartDefaultETWProcessCollector(ctx context.Context, tenantID string) error {
	return defaultETWProcessCollectorForTenant(tenantID).Start(ctx)
}

func StopDefaultETWProcessCollector() {
	defaultETWProcessCollectorMu.Lock()
	collector := defaultETWProcessCollector
	defaultETWProcessCollectorMu.Unlock()
	if collector != nil {
		collector.Stop()
	}
}

func (c *ETWProcessCollector) Start(ctx context.Context) error {
	if c.tracker == nil {
		return errors.New("process tracker required")
	}
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	if c.started {
		c.done = make(chan struct{})
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true
	c.started = true
	c.mu.Unlock()

	go c.run(runCtx)
	return nil
}

func (c *ETWProcessCollector) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	running := c.running
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if running {
		<-done
	}
}

func (c *ETWProcessCollector) Enqueue(record ETWProcessRecord) bool {
	select {
	case c.queue <- record:
		return true
	default:
		c.mu.Lock()
		c.droppedEvents++
		c.mu.Unlock()
		return false
	}
}

func (c *ETWProcessCollector) Observe(record ETWProcessRecord) agentapi.NormalizedEvent {
	event := c.eventFromRecord(record)
	switch record.Kind {
	case ETWProcessStop:
		event = c.tracker.ObserveProcessExit(event)
	default:
		event = c.tracker.ObserveProcessStart(event)
	}
	c.mu.Lock()
	c.processedEvents++
	c.mu.Unlock()
	return event
}

func (c *ETWProcessCollector) DrainEvents(max int) []agentapi.NormalizedEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if max <= 0 || max > len(c.events) {
		max = len(c.events)
	}
	out := append([]agentapi.NormalizedEvent(nil), c.events[:max]...)
	c.events = append(c.events[:0], c.events[max:]...)
	return out
}

func (c *ETWProcessCollector) Health() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := "stopped"
	if c.running {
		status = "running"
	}
	return map[string]any{
		"collector":        "windows_etw_process",
		"status":           status,
		"running":          c.running,
		"queue_capacity":   cap(c.queue),
		"queue_depth":      len(c.queue),
		"dropped_events":   c.droppedEvents,
		"processed_events": c.processedEvents,
		"last_error":       c.lastError,
	}
}

func ETWProcessCollectorHealth() map[string]any {
	defaultETWProcessCollectorMu.Lock()
	defer defaultETWProcessCollectorMu.Unlock()
	if defaultETWProcessCollector == nil {
		return map[string]any{
			"collector":        "windows_etw_process",
			"status":           "disabled",
			"running":          false,
			"queue_capacity":   0,
			"queue_depth":      0,
			"dropped_events":   0,
			"processed_events": 0,
			"last_error":       "",
		}
	}
	return defaultETWProcessCollector.Health()
}

func (c *ETWProcessCollector) run(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.running = false
		close(c.done)
		c.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case record := <-c.queue:
			event := c.Observe(record)
			c.mu.Lock()
			c.events = append(c.events, event)
			c.mu.Unlock()
		}
	}
}

func (c *ETWProcessCollector) eventFromRecord(record ETWProcessRecord) agentapi.NormalizedEvent {
	eventType := "process_start"
	if record.Kind == ETWProcessStop {
		eventType = "process_stop"
	}
	raw := map[string]any{
		"collector": "windows_etw_process",
		"platform":  "windows_etw",
		"kind":      record.Kind,
	}
	for key, value := range record.Raw {
		raw[key] = value
	}
	event := agentapi.NormalizedEvent{
		Source:            "windows_etw",
		EventType:         eventType,
		TenantID:          c.tenantID,
		Host:              record.Host,
		ProcessName:       record.ProcessName,
		ProcessID:         strconv.FormatUint(uint64(record.ProcessID), 10),
		ProcessCreateTime: record.CreateTime,
		ProcessExitTime:   record.ExitTime,
		ImagePath:         record.ImagePath,
		ImageHash:         record.ImageHash,
		CommandLine:       record.CommandLine,
		User:              record.User,
		Severity:          "info",
		Raw:               raw,
	}
	if record.ParentProcessID != 0 {
		event.ParentProcessID = strconv.FormatUint(uint64(record.ParentProcessID), 10)
	}
	return event
}
