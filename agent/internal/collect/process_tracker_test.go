package collect

import (
	"testing"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func TestProcessTrackerResolvesParentsWithinStartupSnapshot(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})

	events := tracker.ObserveSnapshot("default", []agentapi.NormalizedEvent{
		processStart("default", "PEI01", "100", "", "2026-07-15T01:00:00Z", "C:/Windows/explorer.exe"),
		processStart("default", "PEI01", "200", "100", "2026-07-15T01:01:00Z", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
	})

	parent := events[0]
	child := events[1]
	if parent.ProcessEntityID == "" {
		t.Fatalf("expected parent process entity id")
	}
	if child.ParentProcessEntityID != parent.ProcessEntityID {
		t.Fatalf("expected child parent entity %q, got %q", parent.ProcessEntityID, child.ParentProcessEntityID)
	}
	if child.MissingParentReason != "" {
		t.Fatalf("expected resolved parent without gap, got %q", child.MissingParentReason)
	}
}

func TestProcessTrackerRetainsExitedParentsForLateChildResolution(t *testing.T) {
	now := time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC)
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{
		ExitedRetention: time.Minute,
		Now: func() time.Time {
			return now
		},
	})

	parent := tracker.ObserveProcessStart(processStart("default", "PEI01", "100", "", "2026-07-15T01:00:00Z", "C:/Windows/explorer.exe"))
	tracker.ObserveProcessExit(agentapi.NormalizedEvent{TenantID: "default", Host: "PEI01", ProcessID: "100", ProcessExitTime: "2026-07-15T01:00:30Z", Severity: "info", Raw: map[string]any{}})
	now = now.Add(30 * time.Second)

	child := tracker.ObserveProcessStart(processStart("default", "PEI01", "200", "100", "2026-07-15T01:00:40Z", "C:/Windows/cmd.exe"))

	if child.ParentProcessEntityID != parent.ProcessEntityID {
		t.Fatalf("expected retained parent entity %q, got %q", parent.ProcessEntityID, child.ParentProcessEntityID)
	}
	if child.MissingParentReason != "" {
		t.Fatalf("expected retained parent without gap, got %q", child.MissingParentReason)
	}
}

func TestProcessTrackerStopsResolvingExpiredExitedParents(t *testing.T) {
	now := time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC)
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{
		ExitedRetention: time.Second,
		Now: func() time.Time {
			return now
		},
	})

	tracker.ObserveProcessStart(processStart("default", "PEI01", "100", "", "2026-07-15T01:00:00Z", "C:/Windows/explorer.exe"))
	tracker.ObserveProcessExit(agentapi.NormalizedEvent{TenantID: "default", Host: "PEI01", ProcessID: "100", ProcessExitTime: "2026-07-15T01:00:01Z", Severity: "info", Raw: map[string]any{}})
	now = now.Add(2 * time.Second)

	child := tracker.ObserveProcessStart(processStart("default", "PEI01", "200", "100", "2026-07-15T01:00:05Z", "C:/Windows/cmd.exe"))

	if child.ParentProcessEntityID != "" {
		t.Fatalf("expected expired parent to remain unresolved, got %q", child.ParentProcessEntityID)
	}
	if child.MissingParentReason != "parent_not_observed_by_tracker" {
		t.Fatalf("expected tracker gap after retention expiry, got %q", child.MissingParentReason)
	}
}

func TestProcessTrackerRepresentsPIDReuseSafely(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})

	first := tracker.ObserveProcessStart(processStart("default", "PEI01", "300", "", "2026-07-15T01:00:00Z", "C:/Windows/notepad.exe"))
	tracker.ObserveProcessExit(agentapi.NormalizedEvent{TenantID: "default", Host: "PEI01", ProcessID: "300", ProcessExitTime: "2026-07-15T01:01:00Z", Severity: "info", Raw: map[string]any{}})
	second := tracker.ObserveProcessStart(processStart("default", "PEI01", "300", "", "2026-07-15T01:05:00Z", "C:/Windows/calc.exe"))
	child := tracker.ObserveProcessStart(processStart("default", "PEI01", "400", "300", "2026-07-15T01:06:00Z", "C:/Windows/conhost.exe"))

	if first.ProcessEntityID == second.ProcessEntityID {
		t.Fatalf("expected PID reuse to produce distinct entities, both were %q", first.ProcessEntityID)
	}
	if child.ParentProcessEntityID != second.ProcessEntityID {
		t.Fatalf("expected child to link current PID owner %q, got %q", second.ProcessEntityID, child.ParentProcessEntityID)
	}
}

func TestProcessTrackerReplacesActiveEntityWhenPIDIsReusedWithoutExit(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})

	first := tracker.ObserveProcessStart(processStart("default", "PEI01", "300", "", "2026-07-15T01:00:00Z", "C:/Windows/notepad.exe"))
	second := tracker.ObserveProcessStart(processStart("default", "PEI01", "300", "", "2026-07-15T01:05:00Z", "C:/Windows/calc.exe"))

	if first.ProcessEntityID == second.ProcessEntityID {
		t.Fatalf("expected reused PID to produce a new entity")
	}
	if health := tracker.Health(); health["active_process_entities"] != 1 {
		t.Fatalf("expected old active entity to be replaced, got %+v", health)
	}
}

func TestProcessTrackerMarksRestartOrMissingParentGap(t *testing.T) {
	tracker := NewProcessTracker("PEI01", "boot-a", ProcessTrackerOptions{})

	child := tracker.ObserveProcessStart(processStart("default", "PEI01", "500", "404", "2026-07-15T01:00:00Z", "C:/Windows/cmd.exe"))

	if child.ParentProcessEntityID != "" {
		t.Fatalf("expected no fabricated parent entity, got %q", child.ParentProcessEntityID)
	}
	if child.MissingParentReason != "parent_not_observed_by_tracker" {
		t.Fatalf("expected tracker gap reason, got %q", child.MissingParentReason)
	}
	if child.ProcessIdentityConfidence != "high" {
		t.Fatalf("expected high process identity confidence, got %q", child.ProcessIdentityConfidence)
	}
	health := tracker.Health()
	if health["missing_parent_gaps"] != 1 {
		t.Fatalf("expected one missing parent gap in health, got %+v", health)
	}
	if health["last_gap_reason"] != "parent_not_observed_by_tracker" {
		t.Fatalf("expected last gap reason in health, got %+v", health)
	}
	if health["active_process_entities"] != 1 {
		t.Fatalf("expected one active process entity in health, got %+v", health)
	}
}

func processStart(tenantID, host, pid, parentPID, createTime, imagePath string) agentapi.NormalizedEvent {
	return agentapi.NormalizedEvent{
		Source:            "internal",
		EventType:         "process_start",
		TenantID:          tenantID,
		Host:              host,
		ProcessID:         pid,
		ParentProcessID:   parentPID,
		ProcessCreateTime: createTime,
		ImagePath:         imagePath,
		Severity:          "info",
		Raw:               map[string]any{},
	}
}
