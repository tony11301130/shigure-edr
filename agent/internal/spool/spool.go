package spool

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/state"
)

type TaskResult struct {
	TaskID string         `json:"task_id"`
	Status string         `json:"status"`
	Result map[string]any `json:"result"`
	Error  string         `json:"error,omitempty"`
}

type Record struct {
	Kind       string                     `json:"kind"`
	CreatedAt  string                     `json:"created_at,omitempty"`
	Events     []agentapi.NormalizedEvent `json:"events,omitempty"`
	TaskResult *TaskResult                `json:"task_result,omitempty"`
}

type Limits struct {
	MaxBytes   int64
	MaxRecords int
}

type SpoolSummary struct {
	Bytes                  int64  `json:"bytes"`
	Records                int    `json:"records"`
	AcceptedRecords        int64  `json:"accepted_records"`
	DroppedRecords         int64  `json:"dropped_records"`
	BlockedRecords         int64  `json:"blocked_records"`
	UploadedRecords        int64  `json:"uploaded_records"`
	ReplayedRecords        int64  `json:"replayed_records"`
	RetriedRecords         int64  `json:"retried_records"`
	OldestRecordAgeSeconds int64  `json:"oldest_record_age_seconds"`
	LastSuccessfulUploadAt string `json:"last_successful_upload_at,omitempty"`
	UploadLagSeconds       int64  `json:"upload_lag_seconds"`
	PressureState          string `json:"pressure_state"`
}

func AppendEvents(path string, events []agentapi.NormalizedEvent) error {
	_, err := AppendEventsBounded(path, events, Limits{})
	return err
}

func AppendEventsBounded(path string, events []agentapi.NormalizedEvent, limits Limits) (SpoolSummary, error) {
	if len(events) == 0 {
		return Summary(path, limits)
	}
	return appendRecordBounded(path, Record{Kind: "events", Events: events}, limits)
}

func AppendTaskResult(path string, taskID, status string, result map[string]any, msg string) error {
	_, err := AppendTaskResultBounded(path, taskID, status, result, msg, Limits{})
	return err
}

func AppendTaskResultBounded(path string, taskID, status string, result map[string]any, msg string, limits Limits) (SpoolSummary, error) {
	return appendRecordBounded(path, Record{Kind: "task_result", TaskResult: &TaskResult{TaskID: taskID, Status: status, Result: result, Error: msg}}, limits)
}

func Flush(path string, client *agentapi.Client, s *state.State) error {
	_, err := FlushBounded(path, client, s, Limits{})
	return err
}

func FlushBounded(path string, client *agentapi.Client, s *state.State, limits Limits) (SpoolSummary, error) {
	records, err := readRecords(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	if len(records) == 0 {
		return Summary(path, limits)
	}
	meta, err := loadSummary(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	remaining := []Record{}
	uploadedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, rec := range records {
		switch rec.Kind {
		case "events":
			if err := client.IngestEvents(s.AgentID, s.AgentToken, rec.Events); err != nil {
				meta.RetriedRecords++
				remaining = append(remaining, rec)
			} else {
				meta.UploadedRecords++
				meta.ReplayedRecords++
				meta.LastSuccessfulUploadAt = uploadedAt
			}
		case "task_result":
			if rec.TaskResult == nil {
				continue
			}
			tr := rec.TaskResult
			if err := client.SendTaskResult(s.AgentID, s.AgentToken, tr.TaskID, tr.Status, tr.Result, tr.Error); err != nil {
				meta.RetriedRecords++
				remaining = append(remaining, rec)
			} else {
				meta.UploadedRecords++
				meta.ReplayedRecords++
				meta.LastSuccessfulUploadAt = uploadedAt
			}
		}
	}
	if err := rewrite(path, remaining); err != nil {
		return SpoolSummary{}, err
	}
	if err := saveSummary(path, meta); err != nil {
		return SpoolSummary{}, err
	}
	return Summary(path, limits)
}

func appendRecordBounded(path string, rec Record, limits Limits) (SpoolSummary, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return SpoolSummary{}, err
	}
	if rec.CreatedAt == "" {
		rec.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	records, err := readRecords(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta, err := loadSummary(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta.AcceptedRecords++
	records = append(records, rec)
	trimmed, dropped, retainedNew, err := trimRecords(records, rec.CreatedAt, limits)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta.DroppedRecords += int64(dropped)
	if !retainedNew {
		meta.BlockedRecords++
	}
	if err := rewrite(path, trimmed); err != nil {
		return SpoolSummary{}, err
	}
	if err := saveSummary(path, meta); err != nil {
		return SpoolSummary{}, err
	}
	return Summary(path, limits)
}

func Summary(path string, limits Limits) (SpoolSummary, error) {
	meta, err := loadSummary(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	records, err := readRecords(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta.Records = len(records)
	if info, err := os.Stat(path); err == nil {
		meta.Bytes = info.Size()
	}
	meta.OldestRecordAgeSeconds = oldestAgeSeconds(records)
	meta.UploadLagSeconds = uploadLagSeconds(meta, records)
	meta.PressureState = "ok"
	if meta.BlockedRecords > 0 && len(records) == 0 {
		meta.PressureState = "blocked"
	}
	if len(records) > 0 && (meta.DroppedRecords > 0 || meta.BlockedRecords > 0) {
		meta.PressureState = "pressure"
	}
	if limits.MaxRecords > 0 && len(records) >= limits.MaxRecords && meta.DroppedRecords > 0 {
		meta.PressureState = "pressure"
	}
	if limits.MaxBytes > 0 && meta.Bytes >= limits.MaxBytes && meta.DroppedRecords > 0 {
		meta.PressureState = "pressure"
	}
	return meta, nil
}

func enforceLimits(path string, limits Limits) (SpoolSummary, error) {
	if limits.MaxRecords <= 0 && limits.MaxBytes <= 0 {
		return Summary(path, limits)
	}
	records, err := readRecords(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta, err := loadSummary(path)
	if err != nil {
		return SpoolSummary{}, err
	}
	trimmed, dropped, _, err := trimRecords(records, "", limits)
	if err != nil {
		return SpoolSummary{}, err
	}
	meta.DroppedRecords += int64(dropped)
	if err := rewrite(path, trimmed); err != nil {
		return SpoolSummary{}, err
	}
	if err := saveSummary(path, meta); err != nil {
		return SpoolSummary{}, err
	}
	return Summary(path, limits)
}

func trimRecords(records []Record, newRecordCreatedAt string, limits Limits) ([]Record, int, bool, error) {
	retainedNew := newRecordCreatedAt == ""
	dropped := 0
	for limits.MaxRecords > 0 && len(records) > limits.MaxRecords {
		idx := dropCandidateIndex(records)
		if records[idx].CreatedAt == newRecordCreatedAt {
			retainedNew = false
		}
		records = append(records[:idx], records[idx+1:]...)
		dropped++
	}
	for limits.MaxBytes > 0 && recordsSize(records) > limits.MaxBytes && len(records) > 0 {
		idx := dropCandidateIndex(records)
		if records[idx].CreatedAt == newRecordCreatedAt {
			retainedNew = false
		}
		records = append(records[:idx], records[idx+1:]...)
		dropped++
	}
	if newRecordCreatedAt != "" {
		for _, rec := range records {
			if rec.CreatedAt == newRecordCreatedAt {
				retainedNew = true
				break
			}
		}
	}
	return records, dropped, retainedNew, nil
}

func dropCandidateIndex(records []Record) int {
	for idx, rec := range records {
		if rec.Kind != "task_result" {
			return idx
		}
	}
	return 0
}

func recordsSize(records []Record) int64 {
	size := int64(0)
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		size += int64(len(b) + 1)
	}
	return size
}

func readRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var records []Record
	s := bufio.NewScanner(f)
	for s.Scan() {
		var rec Record
		if err := json.Unmarshal(s.Bytes(), &rec); err == nil {
			records = append(records, rec)
		}
	}
	return records, s.Err()
}

func rewrite(path string, records []Record) error {
	if len(records) == 0 {
		_ = os.Remove(path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func metadataPath(path string) string {
	return path + ".meta.json"
}

func loadSummary(path string) (SpoolSummary, error) {
	b, err := os.ReadFile(metadataPath(path))
	if os.IsNotExist(err) {
		return SpoolSummary{PressureState: "ok"}, nil
	}
	if err != nil {
		return SpoolSummary{}, err
	}
	var summary SpoolSummary
	if err := json.Unmarshal(b, &summary); err != nil {
		return SpoolSummary{}, err
	}
	if summary.PressureState == "" {
		summary.PressureState = "ok"
	}
	return summary, nil
}

func saveSummary(path string, summary SpoolSummary) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metadataPath(path), append(b, '\n'), 0600)
}

func oldestAgeSeconds(records []Record) int64 {
	if len(records) == 0 {
		return 0
	}
	var oldest time.Time
	for _, rec := range records {
		if rec.CreatedAt == "" {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, rec.CreatedAt)
		if err != nil {
			continue
		}
		if oldest.IsZero() || created.Before(oldest) {
			oldest = created
		}
	}
	if oldest.IsZero() {
		return 0
	}
	age := time.Since(oldest).Seconds()
	if age < 0 {
		return 0
	}
	return int64(age)
}

func uploadLagSeconds(summary SpoolSummary, records []Record) int64 {
	if summary.LastSuccessfulUploadAt != "" {
		uploadedAt, err := time.Parse(time.RFC3339Nano, summary.LastSuccessfulUploadAt)
		if err == nil {
			lag := time.Since(uploadedAt).Seconds()
			if lag < 0 {
				return 0
			}
			return int64(lag)
		}
	}
	return oldestAgeSeconds(records)
}
