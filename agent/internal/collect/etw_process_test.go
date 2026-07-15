package collect

import (
	"context"
	"testing"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func TestETWProcessCollectorNormalizesCreateAndStopThroughTracker(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})
	collector := NewETWProcessCollector("default", tracker, ETWProcessCollectorOptions{})

	parent := collector.Observe(ETWProcessRecord{
		Kind:        ETWProcessStart,
		Host:        "PEI01",
		ProcessID:   100,
		ProcessName: "explorer.exe",
		ImagePath:   "C:/Windows/explorer.exe",
		CreateTime:  "2026-07-15T00:00:00Z",
	})
	child := collector.Observe(ETWProcessRecord{
		Kind:            ETWProcessStart,
		Host:            "PEI01",
		ProcessID:       200,
		ParentProcessID: 100,
		ProcessName:     "powershell.exe",
		ImagePath:       "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
		CommandLine:     "powershell -enc SQBFAFgA",
		CreateTime:      "2026-07-15T00:00:02Z",
	})
	stop := collector.Observe(ETWProcessRecord{
		Kind:      ETWProcessStop,
		Host:      "PEI01",
		ProcessID: 200,
		ExitTime:  "2026-07-15T00:00:05Z",
	})

	if child.Source != "windows_etw" || child.EventType != "process_start" {
		t.Fatalf("expected ETW process_start event, got source=%q type=%q", child.Source, child.EventType)
	}
	if child.ParentProcessEntityID != parent.ProcessEntityID {
		t.Fatalf("expected parent entity %q, got %q", parent.ProcessEntityID, child.ParentProcessEntityID)
	}
	if child.ProcessEntityID == "" || child.ProcessIdentityConfidence != "high" {
		t.Fatalf("expected high-confidence child entity, got id=%q confidence=%q", child.ProcessEntityID, child.ProcessIdentityConfidence)
	}
	if stop.EventType != "process_stop" || stop.ProcessEntityID != child.ProcessEntityID {
		t.Fatalf("expected stop event for child entity %q, got type=%q entity=%q", child.ProcessEntityID, stop.EventType, stop.ProcessEntityID)
	}
	if stop.ProcessExitTime != "2026-07-15T00:00:05Z" {
		t.Fatalf("expected stop exit time, got %q", stop.ProcessExitTime)
	}
}

func TestETWProcessCollectorBoundedQueueReportsDrops(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})
	collector := NewETWProcessCollector("default", tracker, ETWProcessCollectorOptions{QueueSize: 1})

	if !collector.Enqueue(ETWProcessRecord{Kind: ETWProcessStart, Host: "PEI01", ProcessID: 100, CreateTime: "2026-07-15T00:00:00Z"}) {
		t.Fatalf("expected first enqueue to fit")
	}
	if collector.Enqueue(ETWProcessRecord{Kind: ETWProcessStart, Host: "PEI01", ProcessID: 101, CreateTime: "2026-07-15T00:00:01Z"}) {
		t.Fatalf("expected second enqueue to be dropped by bounded queue")
	}

	health := collector.Health()
	if health["dropped_events"] != 1 {
		t.Fatalf("expected dropped event health, got %+v", health)
	}
	if health["queue_capacity"] != 1 || health["queue_depth"] != 1 {
		t.Fatalf("expected bounded queue health, got %+v", health)
	}
}

func TestETWProcessCollectorStartsStopsAndDrainsEvents(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})
	collector := NewETWProcessCollector("default", tracker, ETWProcessCollectorOptions{QueueSize: 4})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := collector.Start(ctx); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	if !collector.Enqueue(ETWProcessRecord{Kind: ETWProcessStart, Host: "PEI01", ProcessID: 100, ImagePath: "C:/Windows/notepad.exe", CreateTime: "2026-07-15T00:00:00Z"}) {
		t.Fatalf("expected enqueue to succeed")
	}

	deadline := time.Now().Add(time.Second)
	var events []agentapi.NormalizedEvent
	for time.Now().Before(deadline) {
		events = collector.DrainEvents(10)
		if len(events) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(events) != 1 || events[0].ProcessID != "100" {
		t.Fatalf("expected one normalized event, got %#v", events)
	}
	collector.Stop()
	if collector.Health()["running"] != false {
		t.Fatalf("expected stopped collector health, got %+v", collector.Health())
	}
}

func TestSnapshotTelemetryDrainsEnabledETWProcessEvents(t *testing.T) {
	resetDefaultCollectorsForTest()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := defaultETWProcessCollectorForTenant("default")
	if err := collector.Start(ctx); err != nil {
		t.Fatalf("start default ETW collector: %v", err)
	}
	defer collector.Stop()

	if !collector.Enqueue(ETWProcessRecord{Kind: ETWProcessStart, Host: "PEI01", ProcessID: 100, ImagePath: "C:/Windows/notepad.exe", CreateTime: "2026-07-15T00:00:00Z"}) {
		t.Fatalf("expected enqueue to succeed")
	}

	var events []agentapi.NormalizedEvent
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events = SnapshotTelemetryWithOptions("default", 10, TelemetryOptions{CollectETWProcessEvents: true})
		if len(events) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(events) != 2 {
		t.Fatalf("expected endpoint state plus one ETW event, got %#v", events)
	}
	if events[1].Source != "windows_etw" || events[1].ProcessID != "100" {
		t.Fatalf("expected drained ETW process event, got %#v", events[1])
	}
}

func resetDefaultCollectorsForTest() {
	defaultETWProcessCollectorMu.Lock()
	defaultETWProcessCollector = nil
	defaultETWProcessCollectorMu.Unlock()

	defaultProcessTrackersMu.Lock()
	defaultProcessTrackers = map[string]*ProcessTracker{}
	defaultProcessTrackersMu.Unlock()
}
