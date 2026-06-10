package collect

import "open-edr-mdr-agent/agent/internal/agentapi"

type TelemetryOptions struct {
	CollectProcessSnapshot  bool
	CollectNetworkSnapshot  bool
	CollectWindowsEventLogs bool
}

func DefaultTelemetryOptions() TelemetryOptions {
	return TelemetryOptions{CollectProcessSnapshot: true, CollectNetworkSnapshot: true, CollectWindowsEventLogs: true}
}

func SnapshotTelemetry(tenantID string, maxEvents int) []agentapi.NormalizedEvent {
	return SnapshotTelemetryWithOptions(tenantID, maxEvents, DefaultTelemetryOptions())
}

func SnapshotTelemetryWithOptions(tenantID string, maxEvents int, opts TelemetryOptions) []agentapi.NormalizedEvent {
	if maxEvents <= 0 {
		maxEvents = 50
	}
	var events []agentapi.NormalizedEvent
	if opts.CollectProcessSnapshot {
		events = append(events, platformProcessSnapshot(tenantID, maxEvents)...)
	}
	if opts.CollectNetworkSnapshot && len(events) < maxEvents {
		events = append(events, platformNetworkSnapshot(tenantID, maxEvents-len(events))...)
	}
	if opts.CollectWindowsEventLogs && len(events) < maxEvents {
		events = append(events, platformEventLogSnapshot(tenantID, maxEvents-len(events))...)
	}
	if len(events) > maxEvents {
		return events[:maxEvents]
	}
	return events
}
