package spool

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"

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
	Events     []agentapi.NormalizedEvent `json:"events,omitempty"`
	TaskResult *TaskResult                `json:"task_result,omitempty"`
}

func AppendEvents(path string, events []agentapi.NormalizedEvent) error {
	if len(events) == 0 {
		return nil
	}
	return appendRecord(path, Record{Kind: "events", Events: events})
}

func AppendTaskResult(path string, taskID, status string, result map[string]any, msg string) error {
	return appendRecord(path, Record{Kind: "task_result", TaskResult: &TaskResult{TaskID: taskID, Status: status, Result: result, Error: msg}})
}

func Flush(path string, client *agentapi.Client, s *state.State) error {
	records, err := readRecords(path)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	remaining := []Record{}
	for _, rec := range records {
		switch rec.Kind {
		case "events":
			if err := client.IngestEvents(s.AgentID, s.AgentToken, rec.Events); err != nil {
				remaining = append(remaining, rec)
			}
		case "task_result":
			if rec.TaskResult == nil {
				continue
			}
			tr := rec.TaskResult
			if err := client.SendTaskResult(s.AgentID, s.AgentToken, tr.TaskID, tr.Status, tr.Result, tr.Error); err != nil {
				remaining = append(remaining, rec)
			}
		}
	}
	return rewrite(path, remaining)
}

func appendRecord(path string, rec Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
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
