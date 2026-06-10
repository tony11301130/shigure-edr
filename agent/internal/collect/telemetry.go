package collect

import "open-edr-mdr-agent/agent/internal/agentapi"

func SnapshotTelemetry(tenantID string, maxEvents int) []agentapi.NormalizedEvent {
	if maxEvents <= 0 {
		maxEvents = 50
	}
	var events []agentapi.NormalizedEvent
	events = append(events, platformProcessSnapshot(tenantID, maxEvents)...)
	if len(events) < maxEvents {
		events = append(events, platformNetworkSnapshot(tenantID, maxEvents-len(events))...)
	}
	if len(events) > maxEvents {
		return events[:maxEvents]
	}
	return events
}
