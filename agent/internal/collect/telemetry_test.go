package collect

import "testing"

func TestSnapshotTelemetryWithAllCollectorsDisabled(t *testing.T) {
	events := SnapshotTelemetryWithOptions("default", 10, TelemetryOptions{})
	if len(events) != 0 {
		t.Fatalf("expected no events when all collectors disabled, got %d", len(events))
	}
}

func TestDefaultTelemetryOptionsEnablesCollectors(t *testing.T) {
	opts := DefaultTelemetryOptions()
	if !opts.CollectProcessSnapshot || !opts.CollectNetworkSnapshot || !opts.CollectWindowsEventLogs {
		t.Fatalf("default telemetry options should enable all collectors: %+v", opts)
	}
}
