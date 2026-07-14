package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/spool"
	"open-edr-mdr-agent/agent/internal/state"
)

func TestEnrollStoresCredentialVersionFromServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/enroll" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":          "tenant-a",
			"agent_id":           "agent-1",
			"agent_token":        "agent-secret",
			"credential_version": 4,
			"config":             map[string]any{},
		}); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}))
	defer server.Close()

	got, err := enroll(agentapi.New(server.URL), "tenant-bootstrap-token")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	if got.AgentToken != "agent-secret" {
		t.Fatalf("expected per-agent credential from server")
	}
	if got.CredentialVersion != 4 {
		t.Fatalf("expected credential version 4, got %d", got.CredentialVersion)
	}
}

func TestRunCycleAppliesCredentialUpdateFromHeartbeat(t *testing.T) {
	requestTokens := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTokens[r.URL.Path] = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/agents/agent-1/heartbeat":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"tasks_pending":  false,
				"config_version": 1,
				"config": map[string]any{
					"version":                    1,
					"task_poll_seconds":          15,
					"heartbeat_seconds":          30,
					"upload_interval_seconds":    15,
					"max_snapshot_events":        25,
					"collect_snapshot":           false,
					"collect_process_snapshot":   false,
					"collect_network_snapshot":   false,
					"collect_windows_event_logs": false,
					"demo_suspicious_event":      false,
					"features":                   map[string]any{"collector_gates_explicit": true},
				},
				"credential_update": map[string]any{
					"agent_token":        "new-secret",
					"credential_version": 2,
				},
			}); err != nil {
				t.Fatalf("write heartbeat: %v", err)
			}
		case "/api/v1/agents/agent-1/tasks/claim":
			if err := json.NewEncoder(w).Encode(map[string]any{"tasks": []any{}}); err != nil {
				t.Fatalf("write tasks: %v", err)
			}
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	spoolPath := filepath.Join(dir, "spool.jsonl")
	s := &state.State{TenantID: "tenant-a", AgentID: "agent-1", AgentToken: "old-secret", CredentialVersion: 1}
	if err := state.Save(statePath, s); err != nil {
		t.Fatalf("save initial state: %v", err)
	}

	_, err := runCycle(agentapi.New(server.URL), s, statePath, spoolPath, spool.Limits{}, agentapi.AgentConfig{CollectSnapshot: false, MaxSnapshotEvents: 25})
	if err != nil {
		t.Fatalf("run cycle: %v", err)
	}

	if s.AgentToken != "new-secret" || s.CredentialVersion != 2 {
		t.Fatalf("credential update was not applied in memory: %+v", s)
	}
	persisted, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if persisted.AgentToken != "new-secret" || persisted.CredentialVersion != 2 {
		t.Fatalf("credential update was not persisted: %+v", persisted)
	}
	if requestTokens["/api/v1/agents/agent-1/tasks/claim"] != "Bearer new-secret" {
		t.Fatalf("expected tasks claim to use rotated credential, got %q", requestTokens["/api/v1/agents/agent-1/tasks/claim"])
	}
}
