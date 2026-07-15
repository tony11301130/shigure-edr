package collect

import "open-edr-mdr-agent/agent/internal/agentapi"

type TelemetryOptions struct {
	CollectProcessSnapshot  bool
	CollectNetworkSnapshot  bool
	CollectWindowsEventLogs bool
	CollectETWProcessEvents bool
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
	events = append(events, EndpointStateTelemetry(tenantID))
	if opts.CollectProcessSnapshot {
		events = append(events, platformProcessSnapshot(tenantID, maxEvents)...)
	}
	if opts.CollectNetworkSnapshot && len(events) < maxEvents {
		events = append(events, platformNetworkSnapshot(tenantID, maxEvents-len(events))...)
	}
	if opts.CollectWindowsEventLogs && len(events) < maxEvents {
		events = append(events, platformEventLogSnapshot(tenantID, maxEvents-len(events))...)
	}
	if opts.CollectETWProcessEvents && len(events) < maxEvents {
		events = append(events, DrainDefaultETWProcessEvents(tenantID, maxEvents-len(events))...)
	}
	if len(events) > maxEvents {
		return events[:maxEvents]
	}
	return events
}

func EndpointStateTelemetry(tenantID string) agentapi.NormalizedEvent {
	inv := HostInventory()
	return agentapi.NormalizedEvent{
		Source: "internal", EventType: "endpoint_state", TenantID: tenantID,
		Host: inv.Host, IPAddress: inv.IPAddress, Severity: "info",
		Raw: map[string]any{"inventory": inv, "collector": "agent_endpoint_state"},
	}
}
