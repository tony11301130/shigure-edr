package spool

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/state"
)

func eventWithID(id string) agentapi.NormalizedEvent {
	return agentapi.NormalizedEvent{
		Source:    "internal",
		EventType: "process_start",
		TenantID:  "default",
		Host:      "SPOOL01",
		Severity:  "info",
		Raw:       map[string]any{"id": id},
	}
}

func TestBoundedAppendDropsOldestRecordsAndPersistsCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	limits := Limits{MaxRecords: 2, MaxBytes: 4096}

	for _, id := range []string{"oldest", "middle", "newest"} {
		if _, err := AppendEventsBounded(path, []agentapi.NormalizedEvent{eventWithID(id)}, limits); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	summary, err := Summary(path, limits)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.Records != 2 {
		t.Fatalf("expected two queued records, got %+v", summary)
	}
	if summary.AcceptedRecords != 3 || summary.DroppedRecords != 1 {
		t.Fatalf("expected accepted/dropped counters to persist, got %+v", summary)
	}
	if summary.PressureState != "pressure" {
		t.Fatalf("expected pressure state after drop, got %+v", summary)
	}

	records, err := readRecords(path)
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	gotIDs := []string{}
	for _, rec := range records {
		gotIDs = append(gotIDs, rec.Events[0].Raw["id"].(string))
	}
	if want := []string{"middle", "newest"}; gotIDs[0] != want[0] || gotIDs[1] != want[1] {
		t.Fatalf("expected newest records retained, got %v", gotIDs)
	}

	reloaded, err := Summary(path, limits)
	if err != nil {
		t.Fatalf("reload summary: %v", err)
	}
	if reloaded.DroppedRecords != 1 || reloaded.AcceptedRecords != 3 {
		t.Fatalf("expected counters to survive reload, got %+v", reloaded)
	}
}

func TestBoundedAppendPreservesTaskResultsBeforeTelemetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	limits := Limits{MaxRecords: 2, MaxBytes: 4096}

	if _, err := AppendTaskResultBounded(path, "task-1", "succeeded", map[string]any{"ok": true}, "", limits); err != nil {
		t.Fatalf("append task result: %v", err)
	}
	if _, err := AppendEventsBounded(path, []agentapi.NormalizedEvent{eventWithID("old-telemetry")}, limits); err != nil {
		t.Fatalf("append old telemetry: %v", err)
	}
	if _, err := AppendEventsBounded(path, []agentapi.NormalizedEvent{eventWithID("new-telemetry")}, limits); err != nil {
		t.Fatalf("append new telemetry: %v", err)
	}

	records, err := readRecords(path)
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two records, got %d", len(records))
	}
	if records[0].Kind != "task_result" || records[0].TaskResult.TaskID != "task-1" {
		t.Fatalf("expected task result to be preserved before telemetry, got %+v", records)
	}
	if records[1].Events[0].Raw["id"] != "new-telemetry" {
		t.Fatalf("expected newest telemetry to remain, got %+v", records[1])
	}
}

func TestOversizeRecordIsBlockedBeforeWritingSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	summary, err := AppendEventsBounded(path, []agentapi.NormalizedEvent{{
		Source: "internal", EventType: "process_start", TenantID: "default", Host: "SPOOL01", Severity: "info",
		Raw: map[string]any{"payload": "this record is larger than the byte limit"},
	}}, Limits{MaxBytes: 16, MaxRecords: 10})
	if err != nil {
		t.Fatalf("append oversize: %v", err)
	}

	if summary.Records != 0 || summary.BlockedRecords != 1 || summary.PressureState != "blocked" {
		t.Fatalf("expected oversize record to be blocked before queueing, got %+v", summary)
	}
	if info, err := os.Stat(path); err == nil && info.Size() > 16 {
		t.Fatalf("spool exceeded limit after blocked append: %d", info.Size())
	}
}

func TestFlushUpdatesReplayAndRetryCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	limits := Limits{MaxRecords: 10, MaxBytes: 4096}
	if _, err := AppendEventsBounded(path, []agentapi.NormalizedEvent{eventWithID("replay")}, limits); err != nil {
		t.Fatalf("append: %v", err)
	}

	failUpload := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/agent-1/events":
			if failUpload {
				http.Error(w, "offline", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": 1, "alerts_generated": 0})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	agentState := &state.State{TenantID: "default", AgentID: "agent-1", AgentToken: "agent-token"}
	if _, err := FlushBounded(path, agentapi.New(server.URL), agentState, limits); err != nil {
		t.Fatalf("failed flush should keep queued records without returning error: %v", err)
	}
	summary, err := Summary(path, limits)
	if err != nil {
		t.Fatalf("summary after retry: %v", err)
	}
	if summary.RetriedRecords != 1 || summary.Records != 1 {
		t.Fatalf("expected retry counter and remaining record, got %+v", summary)
	}

	failUpload = false
	if _, err := FlushBounded(path, agentapi.New(server.URL), agentState, limits); err != nil {
		t.Fatalf("successful flush: %v", err)
	}
	summary, err = Summary(path, limits)
	if err != nil {
		t.Fatalf("summary after replay: %v", err)
	}
	if summary.UploadedRecords != 1 || summary.ReplayedRecords != 1 || summary.Records != 0 || summary.PressureState != "ok" {
		t.Fatalf("expected replayed record and empty spool, got %+v", summary)
	}
	if summary.LastSuccessfulUploadAt == "" || summary.UploadLagSeconds < 0 {
		t.Fatalf("expected successful upload timestamp and lag, got %+v", summary)
	}
}
