package collect

import "testing"

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
