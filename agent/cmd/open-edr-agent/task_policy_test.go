package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/spool"
	"open-edr-mdr-agent/agent/internal/state"
)

func TestExecuteAndReportReturnsBlockedForDestructiveTask(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/agent-1/tasks/task-1/result" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer server.Close()

	dir := t.TempDir()
	executeAndReport(
		agentapi.New(server.URL),
		&state.State{AgentID: "agent-1", AgentToken: "agent-token"},
		filepath.Join(dir, "spool.jsonl"),
		spool.Limits{},
		agentapi.Task{TaskID: "task-1", TaskType: "kill_process", Args: map[string]any{"pid": os.Getpid()}},
	)

	if body["status"] != "blocked_by_policy" {
		t.Fatalf("expected blocked status, got %#v", body)
	}
	result := body["result"].(map[string]any)
	if result["reason"] != "destructive_task_blocked" || result["policy_version"] != "read_only_v1" {
		t.Fatalf("expected policy block metadata, got %#v", result)
	}
}
