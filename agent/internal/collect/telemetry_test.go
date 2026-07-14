package collect

import (
	"strings"
	"testing"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func TestSnapshotTelemetryWithAllCollectorsDisabledStillReportsEndpointState(t *testing.T) {
	events := SnapshotTelemetryWithOptions("default", 10, TelemetryOptions{})
	if len(events) != 1 || events[0].EventType != "endpoint_state" {
		t.Fatalf("expected only endpoint_state when collectors disabled, got %#v", events)
	}
}

func TestDefaultTelemetryOptionsEnablesCollectors(t *testing.T) {
	opts := DefaultTelemetryOptions()
	if !opts.CollectProcessSnapshot || !opts.CollectNetworkSnapshot || !opts.CollectWindowsEventLogs {
		t.Fatalf("default telemetry options should enable all collectors: %+v", opts)
	}
}

func TestSnapshotTelemetryIncludesEndpointState(t *testing.T) {
	events := SnapshotTelemetryWithOptions("default", 5, TelemetryOptions{})
	if len(events) == 0 || events[0].EventType != "endpoint_state" {
		t.Fatalf("expected endpoint_state first event, got %#v", events)
	}
}

func TestApplyProcessIdentityBuildsDeterministicEntityIDs(t *testing.T) {
	bootID := "boot-a"
	event := agentapi.NormalizedEvent{
		Host:              "PEI01",
		ProcessID:         "200",
		ParentProcessID:   "100",
		ImagePath:         "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
		ProcessCreateTime: "2026-07-14T01:02:00Z",
		Raw: map[string]any{
			"parent_process_create_time": "2026-07-14T01:00:00Z",
			"parent_image_path":          "C:/Windows/explorer.exe",
		},
	}

	ApplyProcessIdentity(&event, bootID)

	if event.BootID != bootID {
		t.Fatalf("expected boot id %q, got %q", bootID, event.BootID)
	}
	if event.ProcessEntityID == "" || !strings.HasPrefix(event.ProcessEntityID, "peid:") {
		t.Fatalf("expected process entity id, got %q", event.ProcessEntityID)
	}
	if event.ParentProcessEntityID == "" || event.ParentProcessEntityID == event.ProcessEntityID {
		t.Fatalf("expected distinct parent process entity id, got %q", event.ParentProcessEntityID)
	}
	if event.ProcessIdentityConfidence != "high" {
		t.Fatalf("expected high confidence, got %q", event.ProcessIdentityConfidence)
	}
}

func TestApplyProcessIdentityMarksMissingParentWithoutFakeCertainty(t *testing.T) {
	event := agentapi.NormalizedEvent{
		Host:              "PEI01",
		ProcessID:         "300",
		ParentProcessID:   "999",
		ProcessCreateTime: "2026-07-14T03:00:00Z",
		Raw:               map[string]any{},
	}

	ApplyProcessIdentity(&event, "boot-a")

	if event.ParentProcessEntityID != "" {
		t.Fatalf("expected no parent entity id without parent create/image hints, got %q", event.ParentProcessEntityID)
	}
	if event.ProcessIdentityConfidence != "medium" {
		t.Fatalf("expected medium confidence without image hint, got %q", event.ProcessIdentityConfidence)
	}
	if event.MissingParentReason != "parent_identity_unavailable" {
		t.Fatalf("expected missing parent reason, got %q", event.MissingParentReason)
	}
}

func TestLinuxProcStatParsersKeepPIDAttributesSeparateFromEntityIdentity(t *testing.T) {
	stat := "200 (powershell.exe) S 100 99 99 0 -1 4194560 1 2 3 4 5 6 7 8 9 10 11 12 987654 15"

	if got := parsePPID(stat); got != "100" {
		t.Fatalf("expected parent pid 100, got %q", got)
	}
	if got := parseStartTime(stat); got != "987654" {
		t.Fatalf("expected start time 987654, got %q", got)
	}
}
