package collect

import (
	"sync"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

const (
	defaultExitedRetention = 5 * time.Minute
	defaultMaxExited       = 1024
)

type ProcessTrackerOptions struct {
	ExitedRetention time.Duration
	MaxExited       int
	Now             func() time.Time
}

type ProcessTracker struct {
	host              string
	bootID            string
	exitedRetention   time.Duration
	maxExited         int
	now               func() time.Time
	snapshotObserved  bool
	missingParentGaps int
	lastGapReason     string
	activeByPID       map[string]trackedProcess
	activeByEntity    map[string]trackedProcess
	retainedExitedPID map[string][]trackedProcess
}

type trackedProcess struct {
	PID        string
	EntityID   string
	CreateTime string
	ImagePath  string
	ImageHash  string
	ExitedAt   time.Time
}

func NewProcessTracker(host, bootID string, opts ProcessTrackerOptions) *ProcessTracker {
	if opts.ExitedRetention <= 0 {
		opts.ExitedRetention = defaultExitedRetention
	}
	if opts.MaxExited <= 0 {
		opts.MaxExited = defaultMaxExited
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &ProcessTracker{
		host:              host,
		bootID:            bootID,
		exitedRetention:   opts.ExitedRetention,
		maxExited:         opts.MaxExited,
		now:               opts.Now,
		activeByPID:       map[string]trackedProcess{},
		activeByEntity:    map[string]trackedProcess{},
		retainedExitedPID: map[string][]trackedProcess{},
	}
}

func (t *ProcessTracker) ObserveSnapshot(tenantID string, events []agentapi.NormalizedEvent) []agentapi.NormalizedEvent {
	if len(events) == 0 {
		return events
	}
	current := map[string]trackedProcess{}
	out := make([]agentapi.NormalizedEvent, len(events))
	for i := range events {
		event := events[i]
		if event.TenantID == "" {
			event.TenantID = tenantID
		}
		t.applyIdentity(&event)
		out[i] = event
		if event.ProcessID != "" {
			current[event.ProcessID] = processFromEvent(event, time.Time{})
		}
	}

	gapReason := "parent_not_observed_in_snapshot"
	if !t.snapshotObserved {
		gapReason = "parent_not_observed_in_startup_snapshot"
	}
	for i := range out {
		t.resolveParent(&out[i], current, gapReason)
		if out[i].ProcessID != "" {
			t.rememberActive(processFromEvent(out[i], time.Time{}))
		}
	}
	t.snapshotObserved = true
	t.purgeExited()
	return out
}

func (t *ProcessTracker) ObserveProcessStart(event agentapi.NormalizedEvent) agentapi.NormalizedEvent {
	t.applyIdentity(&event)
	t.resolveParent(&event, nil, "parent_not_observed_by_tracker")
	if event.ProcessID != "" {
		t.rememberActive(processFromEvent(event, time.Time{}))
	}
	t.purgeExited()
	return event
}

func (t *ProcessTracker) ObserveProcessExit(event agentapi.NormalizedEvent) agentapi.NormalizedEvent {
	if event.EventType == "" {
		event.EventType = "process_stop"
	}
	if active, ok := t.activeByPID[event.ProcessID]; ok {
		if event.ProcessEntityID == "" {
			event.ProcessEntityID = active.EntityID
		}
		if event.ProcessCreateTime == "" {
			event.ProcessCreateTime = active.CreateTime
		}
		if event.ImagePath == "" {
			event.ImagePath = active.ImagePath
		}
		if event.ImageHash == "" {
			event.ImageHash = active.ImageHash
		}
	}
	t.applyIdentity(&event)
	if event.ProcessID != "" {
		delete(t.activeByPID, event.ProcessID)
		if event.ProcessEntityID != "" {
			delete(t.activeByEntity, event.ProcessEntityID)
		}
		t.retainedExitedPID[event.ProcessID] = append(t.retainedExitedPID[event.ProcessID], processFromEvent(event, t.now()))
	}
	t.purgeExited()
	return event
}

func (t *ProcessTracker) Health() map[string]any {
	retained := 0
	for _, processes := range t.retainedExitedPID {
		retained += len(processes)
	}
	return map[string]any{
		"active_processes":         len(t.activeByPID),
		"active_process_entities":  len(t.activeByEntity),
		"retained_exited":          retained,
		"missing_parent_gaps":      t.missingParentGaps,
		"last_gap_reason":          t.lastGapReason,
		"snapshot_observed":        t.snapshotObserved,
		"exited_retention_seconds": int(t.exitedRetention.Seconds()),
	}
}

func (t *ProcessTracker) rememberActive(process trackedProcess) {
	if process.PID != "" {
		if existing, ok := t.activeByPID[process.PID]; ok && existing.EntityID != process.EntityID {
			delete(t.activeByEntity, existing.EntityID)
		}
		t.activeByPID[process.PID] = process
	}
	if process.EntityID != "" {
		t.activeByEntity[process.EntityID] = process
	}
}

func (t *ProcessTracker) applyIdentity(event *agentapi.NormalizedEvent) {
	if event.Raw == nil {
		event.Raw = map[string]any{}
	}
	if event.Host == "" {
		event.Host = t.host
	}
	ApplyProcessIdentity(event, t.bootID)
}

func (t *ProcessTracker) resolveParent(event *agentapi.NormalizedEvent, current map[string]trackedProcess, missingReason string) {
	if event.ParentProcessID == "" || event.ParentProcessEntityID != "" {
		return
	}
	if parent, ok := current[event.ParentProcessID]; ok {
		event.ParentProcessEntityID = parent.EntityID
		event.MissingParentReason = ""
		return
	}
	if parent, ok := t.activeByPID[event.ParentProcessID]; ok {
		event.ParentProcessEntityID = parent.EntityID
		event.MissingParentReason = ""
		return
	}
	if parent, ok := t.retainedParent(event.ParentProcessID); ok {
		event.ParentProcessEntityID = parent.EntityID
		event.MissingParentReason = ""
		return
	}
	event.MissingParentReason = missingReason
	t.missingParentGaps++
	t.lastGapReason = missingReason
}

func (t *ProcessTracker) retainedParent(pid string) (trackedProcess, bool) {
	retained := t.retainedExitedPID[pid]
	for i := len(retained) - 1; i >= 0; i-- {
		if t.now().Sub(retained[i].ExitedAt) <= t.exitedRetention {
			return retained[i], true
		}
	}
	return trackedProcess{}, false
}

func (t *ProcessTracker) purgeExited() {
	total := 0
	for pid, retained := range t.retainedExitedPID {
		filtered := retained[:0]
		for _, process := range retained {
			if t.now().Sub(process.ExitedAt) <= t.exitedRetention {
				filtered = append(filtered, process)
			}
		}
		if len(filtered) == 0 {
			delete(t.retainedExitedPID, pid)
			continue
		}
		t.retainedExitedPID[pid] = filtered
		total += len(filtered)
	}
	for total > t.maxExited {
		var oldestPID string
		oldestIndex := -1
		var oldestTime time.Time
		for pid, retained := range t.retainedExitedPID {
			for i, process := range retained {
				if oldestIndex == -1 || process.ExitedAt.Before(oldestTime) {
					oldestPID = pid
					oldestIndex = i
					oldestTime = process.ExitedAt
				}
			}
		}
		if oldestIndex == -1 {
			return
		}
		retained := t.retainedExitedPID[oldestPID]
		t.retainedExitedPID[oldestPID] = append(retained[:oldestIndex], retained[oldestIndex+1:]...)
		if len(t.retainedExitedPID[oldestPID]) == 0 {
			delete(t.retainedExitedPID, oldestPID)
		}
		total--
	}
}

func processFromEvent(event agentapi.NormalizedEvent, exitedAt time.Time) trackedProcess {
	return trackedProcess{
		PID:        event.ProcessID,
		EntityID:   event.ProcessEntityID,
		CreateTime: event.ProcessCreateTime,
		ImagePath:  event.ImagePath,
		ImageHash:  event.ImageHash,
		ExitedAt:   exitedAt,
	}
}

var (
	defaultProcessTrackersMu sync.Mutex
	defaultProcessTrackers   = map[string]*ProcessTracker{}
)

func observeProcessSnapshotEvents(tenantID, bootID string, events []agentapi.NormalizedEvent) []agentapi.NormalizedEvent {
	if len(events) == 0 {
		return events
	}
	host := events[0].Host
	tracker := defaultProcessTrackerFor(host, bootID)
	return tracker.ObserveSnapshot(tenantID, events)
}

func defaultProcessTrackerFor(host, bootID string) *ProcessTracker {
	key := host + "\x00" + bootID
	defaultProcessTrackersMu.Lock()
	defer defaultProcessTrackersMu.Unlock()
	tracker, ok := defaultProcessTrackers[key]
	if !ok {
		tracker = NewProcessTracker(host, bootID, ProcessTrackerOptions{})
		defaultProcessTrackers[key] = tracker
	}
	return tracker
}

func ProcessTrackerHealth() map[string]any {
	defaultProcessTrackersMu.Lock()
	defer defaultProcessTrackersMu.Unlock()

	health := map[string]any{
		"active_processes":         0,
		"active_process_entities":  0,
		"retained_exited":          0,
		"missing_parent_gaps":      0,
		"last_gap_reason":          "",
		"snapshot_observed":        false,
		"exited_retention_seconds": int(defaultExitedRetention.Seconds()),
	}
	for _, tracker := range defaultProcessTrackers {
		trackerHealth := tracker.Health()
		health["active_processes"] = health["active_processes"].(int) + trackerHealth["active_processes"].(int)
		health["active_process_entities"] = health["active_process_entities"].(int) + trackerHealth["active_process_entities"].(int)
		health["retained_exited"] = health["retained_exited"].(int) + trackerHealth["retained_exited"].(int)
		health["missing_parent_gaps"] = health["missing_parent_gaps"].(int) + trackerHealth["missing_parent_gaps"].(int)
		if reason := trackerHealth["last_gap_reason"].(string); reason != "" {
			health["last_gap_reason"] = reason
		}
		if trackerHealth["snapshot_observed"].(bool) {
			health["snapshot_observed"] = true
		}
	}
	return health
}
