package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/collect"
	"open-edr-mdr-agent/agent/internal/spool"
	"open-edr-mdr-agent/agent/internal/state"
)

func TestRunCycleReportsBoundedSpoolHealthInHeartbeat(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	spoolPath := filepath.Join(dir, "spool.jsonl")
	limits := spool.Limits{MaxRecords: 1, MaxBytes: 4096}
	for _, id := range []string{"dropped", "retained"} {
		if _, err := spool.AppendEventsBounded(spoolPath, []agentapi.NormalizedEvent{{
			Source: "internal", EventType: "process_start", TenantID: "default", Host: "SPOOL01", Severity: "info", Raw: map[string]any{"id": id},
		}}, limits); err != nil {
			t.Fatalf("append spool record: %v", err)
		}
	}

	var heartbeatHealth map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/agents/agent-1/events":
			http.Error(w, "still offline", http.StatusServiceUnavailable)
		case "/api/v1/agents/agent-1/heartbeat":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode heartbeat: %v", err)
			}
			heartbeatHealth = body["health"].(map[string]any)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok", "tasks_pending": false, "config_version": 1,
				"config": map[string]any{
					"version": 1, "task_poll_seconds": 15, "heartbeat_seconds": 30, "upload_interval_seconds": 15,
					"max_snapshot_events": 25, "collect_snapshot": false, "collect_process_snapshot": false,
					"collect_network_snapshot": false, "collect_windows_event_logs": false, "demo_suspicious_event": false,
					"features": map[string]any{"collector_gates_explicit": true},
				},
			})
		case "/api/v1/agents/agent-1/tasks/claim":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{}})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agentState := &state.State{TenantID: "default", AgentID: "agent-1", AgentToken: "agent-token", CredentialVersion: 1}
	if err := state.Save(statePath, agentState); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := runCycle(agentapi.New(server.URL), agentState, statePath, spoolPath, limits, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25}); err != nil {
		t.Fatalf("run cycle: %v", err)
	}

	spoolHealth := heartbeatHealth["spool"].(map[string]any)
	if spoolHealth["pressure_state"] != "pressure" {
		t.Fatalf("expected pressure state, got %+v", spoolHealth)
	}
	if spoolHealth["records"].(float64) != 1 || spoolHealth["dropped_records"].(float64) != 1 || spoolHealth["retried_records"].(float64) != 1 {
		t.Fatalf("expected bounded spool counters in heartbeat, got %+v", spoolHealth)
	}
	if _, ok := spoolHealth["oldest_record_age_seconds"]; !ok {
		t.Fatalf("expected oldest age field, got %+v", spoolHealth)
	}
	if _, ok := spoolHealth["upload_lag_seconds"]; !ok {
		t.Fatalf("expected upload lag field, got %+v", spoolHealth)
	}
	if _, ok := spoolHealth["replayed_records"]; !ok {
		t.Fatalf("expected replay counter field, got %+v", spoolHealth)
	}
	if _, ok := spoolHealth["blocked_records"]; !ok {
		t.Fatalf("expected blocked counter field, got %+v", spoolHealth)
	}
	if processTracker, ok := heartbeatHealth["process_tracker"].(map[string]any); !ok {
		t.Fatalf("expected process tracker health in heartbeat, got %+v", heartbeatHealth)
	} else if _, ok := processTracker["active_processes"]; !ok {
		t.Fatalf("expected process tracker active count, got %+v", processTracker)
	}
	if etwProcess, ok := heartbeatHealth["windows_etw_process"].(map[string]any); !ok {
		t.Fatalf("expected ETW process collector health in heartbeat, got %+v", heartbeatHealth)
	} else if etwProcess["status"] == "" {
		t.Fatalf("expected ETW process collector status, got %+v", etwProcess)
	}
	if eventLogSubscriber, ok := heartbeatHealth["windows_event_log_subscription"].(map[string]any); !ok {
		t.Fatalf("expected Windows Event Log subscriber health in heartbeat, got %+v", heartbeatHealth)
	} else if eventLogSubscriber["status"] == "" {
		t.Fatalf("expected Windows Event Log subscriber status, got %+v", eventLogSubscriber)
	}
}

func TestRunCycleStartsETWProcessCollectorWhenFeatureEnabled(t *testing.T) {
	collectResetDefaultCollectorsForTest()
	defer collect.StopDefaultETWProcessCollector()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	spoolPath := filepath.Join(dir, "spool.jsonl")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/agents/agent-1/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok", "tasks_pending": false, "config_version": 1,
				"config": map[string]any{
					"version": 1, "task_poll_seconds": 15, "heartbeat_seconds": 30, "upload_interval_seconds": 15,
					"max_snapshot_events": 25, "collect_snapshot": false, "collect_process_snapshot": false,
					"collect_network_snapshot": false, "collect_windows_event_logs": false, "demo_suspicious_event": false,
					"features": map[string]any{"collector_gates_explicit": true, "windows_etw": true},
				},
			})
		case "/api/v1/agents/agent-1/tasks/claim":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{}})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agentState := &state.State{TenantID: "default", AgentID: "agent-1", AgentToken: "agent-token", CredentialVersion: 1}
	if err := state.Save(statePath, agentState); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := runCycle(agentapi.New(server.URL), agentState, statePath, spoolPath, spool.Limits{}, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25, Features: map[string]any{"windows_etw": true}}); err != nil {
		t.Fatalf("run cycle: %v", err)
	}

	if health := collect.ETWProcessCollectorHealth(); health["running"] != true {
		t.Fatalf("expected ETW collector to be running, got %+v", health)
	}

	if _, err := runCycle(agentapi.New(server.URL), agentState, statePath, spoolPath, spool.Limits{}, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25, Features: map[string]any{"windows_etw": false}}); err != nil {
		t.Fatalf("run disabled cycle: %v", err)
	}
	if health := collect.ETWProcessCollectorHealth(); health["running"] != false {
		t.Fatalf("expected ETW collector to stop when feature is disabled, got %+v", health)
	}
}

func TestRunCycleStartsWindowsEventLogSubscriberWhenFeatureEnabled(t *testing.T) {
	collectResetDefaultCollectorsForTest()
	defer collect.StopDefaultWindowsEventLogSubscriber()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	spoolPath := filepath.Join(dir, "spool.jsonl")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/agents/agent-1/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok", "tasks_pending": false, "config_version": 1,
				"config": map[string]any{
					"version": 1, "task_poll_seconds": 15, "heartbeat_seconds": 30, "upload_interval_seconds": 15,
					"max_snapshot_events": 25, "collect_snapshot": false, "collect_process_snapshot": false,
					"collect_network_snapshot": false, "collect_windows_event_logs": true, "demo_suspicious_event": false,
					"features": map[string]any{"collector_gates_explicit": true, "windows_eventlog_subscriptions": true},
				},
			})
		case "/api/v1/agents/agent-1/tasks/claim":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{}})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agentState := &state.State{TenantID: "default", AgentID: "agent-1", AgentToken: "agent-token", CredentialVersion: 1}
	if err := state.Save(statePath, agentState); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := runCycle(agentapi.New(server.URL), agentState, statePath, spoolPath, spool.Limits{}, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25, Features: map[string]any{"windows_eventlog_subscriptions": true}}); err != nil {
		t.Fatalf("run cycle: %v", err)
	}

	if health := collect.WindowsEventLogSubscriberHealth(); health["running"] != true {
		t.Fatalf("expected Event Log subscriber to be running, got %+v", health)
	}

	if _, err := runCycle(agentapi.New(server.URL), agentState, statePath, spoolPath, spool.Limits{}, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25, Features: map[string]any{"windows_eventlog_subscriptions": false}}); err != nil {
		t.Fatalf("run disabled cycle: %v", err)
	}
	if health := collect.WindowsEventLogSubscriberHealth(); health["running"] != false {
		t.Fatalf("expected Event Log subscriber to stop when feature is disabled, got %+v", health)
	}
}

func collectResetDefaultCollectorsForTest() {
	collect.StopDefaultETWProcessCollector()
	collect.StopDefaultWindowsEventLogSubscriber()
}
