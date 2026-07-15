package collect

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsEventLogSubscriberNormalizesRecordsAndPersistsCheckpoint(t *testing.T) {
	checkpointPath := filepath.Join(t.TempDir(), "eventlog-checkpoints.json")
	subscriber := NewWindowsEventLogSubscriber("default", WindowsEventLogSubscriberOptions{
		CheckpointPath: checkpointPath,
		QueueSize:      4,
	})

	event, accepted, err := subscriber.Observe(WindowsEventLogRecord{
		Query:        "powershell_operational",
		LogName:      "Microsoft-Windows-PowerShell/Operational",
		EventID:      4104,
		RecordID:     40,
		ProviderName: "Microsoft-Windows-PowerShell",
		TimeCreated:  "2026-07-15T01:00:00Z",
		Message:      "ScriptBlockText powershell -enc SQBFAFgA",
	})
	if err != nil {
		t.Fatalf("observe event log record: %v", err)
	}
	if !accepted {
		t.Fatalf("expected first record to be accepted")
	}
	if event.Source != "windows_event_log" || event.EventType != "script_result" {
		t.Fatalf("expected normalized PowerShell event, got source=%q type=%q", event.Source, event.EventType)
	}
	if event.SourceEventID != "40" || event.CommandLine == "" {
		t.Fatalf("expected source event id and compact command line, got %#v", event)
	}
	if event.Raw["platform"] != "windows_evtsubscribe" || event.Raw["query"] != "powershell_operational" {
		t.Fatalf("expected subscription raw metadata, got %#v", event.Raw)
	}

	restarted := NewWindowsEventLogSubscriber("default", WindowsEventLogSubscriberOptions{
		CheckpointPath: checkpointPath,
		QueueSize:      4,
	})
	_, duplicateAccepted, err := restarted.Observe(WindowsEventLogRecord{
		Query:    "powershell_operational",
		LogName:  "Microsoft-Windows-PowerShell/Operational",
		EventID:  4104,
		RecordID: 40,
		Message:  "duplicate after restart",
	})
	if err != nil {
		t.Fatalf("observe duplicate after restart: %v", err)
	}
	if duplicateAccepted {
		t.Fatalf("expected checkpoint to skip duplicate record after restart")
	}

	next, nextAccepted, err := restarted.Observe(WindowsEventLogRecord{
		Query:        "powershell_operational",
		LogName:      "Microsoft-Windows-PowerShell/Operational",
		EventID:      4104,
		RecordID:     41,
		ProviderName: "Microsoft-Windows-PowerShell",
		TimeCreated:  "2026-07-15T01:00:05Z",
		Message:      "new record after restart",
	})
	if err != nil {
		t.Fatalf("observe next after restart: %v", err)
	}
	if !nextAccepted || next.SourceEventID != "41" {
		t.Fatalf("expected next record to be accepted after checkpoint, got accepted=%v event=%#v", nextAccepted, next)
	}
}

func TestWindowsEventLogSubscriberReportsRecordGapsAndQueueDrops(t *testing.T) {
	subscriber := NewWindowsEventLogSubscriber("default", WindowsEventLogSubscriberOptions{
		CheckpointPath: filepath.Join(t.TempDir(), "eventlog-checkpoints.json"),
		QueueSize:      1,
	})

	if _, accepted, err := subscriber.Observe(WindowsEventLogRecord{Query: "security_auth", LogName: "Security", EventID: 4624, RecordID: 10}); err != nil || !accepted {
		t.Fatalf("expected first auth record accepted, accepted=%v err=%v", accepted, err)
	}
	if _, accepted, err := subscriber.Observe(WindowsEventLogRecord{Query: "security_auth", LogName: "Security", EventID: 4625, RecordID: 14}); err != nil || !accepted {
		t.Fatalf("expected gapped auth record accepted, accepted=%v err=%v", accepted, err)
	}

	health := subscriber.Health()
	if health["record_gaps"] != 1 {
		t.Fatalf("expected one visible record gap, got %+v", health)
	}
	if health["last_gap"] == "" {
		t.Fatalf("expected last gap details in health, got %+v", health)
	}

	if !subscriber.Enqueue(WindowsEventLogRecord{Query: "task_scheduler", LogName: "Microsoft-Windows-TaskScheduler/Operational", EventID: 106, RecordID: 20}) {
		t.Fatalf("expected first enqueue to fit")
	}
	if subscriber.Enqueue(WindowsEventLogRecord{Query: "task_scheduler", LogName: "Microsoft-Windows-TaskScheduler/Operational", EventID: 140, RecordID: 21}) {
		t.Fatalf("expected second enqueue to be dropped")
	}
	if health := subscriber.Health(); health["dropped_events"] != 1 || health["queue_depth"] != 1 {
		t.Fatalf("expected drop and queue depth health, got %+v", health)
	}
}

func TestSnapshotTelemetryDrainsEnabledWindowsEventLogSubscriptionEvents(t *testing.T) {
	resetDefaultCollectorsForTest()
	checkpointPath := filepath.Join(t.TempDir(), "eventlog-checkpoints.json")
	SetDefaultWindowsEventLogCheckpointPathForTest(checkpointPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subscriber := defaultWindowsEventLogSubscriberForTenant("default")
	if err := subscriber.Start(ctx); err != nil {
		t.Fatalf("start default event log subscriber: %v", err)
	}
	defer subscriber.Stop()

	if !subscriber.Enqueue(WindowsEventLogRecord{
		Query:        "service_control_manager",
		LogName:      "System",
		EventID:      7045,
		RecordID:     100,
		ProviderName: "Service Control Manager",
		TimeCreated:  "2026-07-15T02:00:00Z",
		Message:      "A service was installed",
	}) {
		t.Fatalf("expected enqueue to succeed")
	}

	var events []any
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		normalized := SnapshotTelemetryWithOptions("default", 10, TelemetryOptions{CollectWindowsEventLogSubscriptions: true})
		events = make([]any, len(normalized))
		for i := range normalized {
			events[i] = normalized[i]
		}
		if len(normalized) == 2 {
			if normalized[1].Source == "windows_event_log" && normalized[1].SourceEventID == "100" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected endpoint state plus one subscribed event, got %#v", events)
}
