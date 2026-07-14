package tasks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExecuteBlocksUnknownTask(t *testing.T) {
	res, err := Execute("arbitrary_shell", map[string]any{"cmd": "whoami"})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got %v", err)
	}
	if res["blocked"] != true {
		t.Fatalf("expected blocked result, got %#v", res)
	}
}

func TestFileExistsAndHash(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hash-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	exists, err := Execute("file_exists", map[string]any{"path": f.Name()})
	if err != nil {
		t.Fatal(err)
	}
	if exists["exists"] != true {
		t.Fatalf("expected file to exist, got %#v", exists)
	}

	hash, err := Execute("file_hash", map[string]any{"path": f.Name()})
	if err != nil {
		t.Fatal(err)
	}
	if hash["sha256"] == "" {
		t.Fatalf("expected sha256, got %#v", hash)
	}
}

func TestInventoryTask(t *testing.T) {
	res, err := Execute("inventory", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if res["inventory"] == nil {
		t.Fatalf("expected inventory, got %#v", res)
	}
}

func TestWindowsEventLogsTaskUsesAllowlistedProfiles(t *testing.T) {
	res, err := Execute("windows_event_logs", map[string]any{"profile": "powershell", "max_events": 500})
	if err != nil {
		t.Fatal(err)
	}
	if res["profile"] != "powershell" {
		t.Fatalf("expected powershell profile, got %#v", res)
	}

	blocked, err := Execute("windows_event_logs", map[string]any{"profile": "arbitrary-log"})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked for unsupported profile, got %v", err)
	}
	if blocked["blocked"] != true {
		t.Fatalf("expected blocked result, got %#v", blocked)
	}
}

func TestDirectoryAndReadFileChunk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}
	listed, err := Execute("list_directory", map[string]any{"path": dir, "max_entries": 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed["entries"].([]map[string]any)) != 1 {
		t.Fatalf("expected one entry, got %#v", listed)
	}
	chunk, err := Execute("read_file_chunk", map[string]any{"path": path, "offset": 6, "max_bytes": 5, "reason": "triage", "case_id": "case-1"})
	if err != nil {
		t.Fatal(err)
	}
	if chunk["text_preview"] != "world" {
		t.Fatalf("expected world preview, got %#v", chunk)
	}
	if chunk["sha256"] != "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7" {
		t.Fatalf("expected chunk sha256, got %#v", chunk)
	}
	if chunk["reason"] != "triage" || chunk["case_id"] != "case-1" {
		t.Fatalf("expected audit fields, got %#v", chunk)
	}
}

func TestDefaultReadOnlyPolicyBlocksMutatingPrototypeTasks(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	copyPath := filepath.Join(dir, "evidence", "copy.txt")
	if err := os.WriteFile(src, []byte("malware-ish"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		taskType string
		args     map[string]any
		reason   string
	}{
		{name: "copy", taskType: "copy_file", args: map[string]any{"source_path": src, "destination_path": copyPath}, reason: "mutating_task_blocked"},
		{name: "delete", taskType: "delete_file", args: map[string]any{"path": src, "confirm_sha256": "0"}, reason: "destructive_task_blocked"},
		{name: "quarantine", taskType: "quarantine_file", args: map[string]any{"source_path": src, "quarantine_dir": filepath.Join(dir, "quarantine")}, reason: "destructive_task_blocked"},
		{name: "kill", taskType: "kill_process", args: map[string]any{"pid": os.Getpid()}, reason: "destructive_task_blocked"},
		{name: "service", taskType: "service_control", args: map[string]any{"service_name": "Spooler", "action": "stop"}, reason: "destructive_task_blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Execute(tc.taskType, tc.args)
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("expected ErrBlocked, got %v %#v", err, res)
			}
			if res["blocked"] != true || res["reason"] != tc.reason {
				t.Fatalf("expected %s block, got %#v", tc.reason, res)
			}
			if res["policy_version"] != "read_only_v1" {
				t.Fatalf("expected policy version, got %#v", res)
			}
		})
	}
}

func TestCollectFileProducesUploadPayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(path, []byte("endpoint evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := Execute("collect_file", map[string]any{"path": path, "max_bytes": 1024, "reason": "triage", "case_id": "case-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res["sha256"] == "" || res["upload_file"] == nil {
		t.Fatalf("expected upload payload, got %#v", res)
	}
	if res["reason"] != "triage" || res["case_id"] != "case-1" || res["policy_version"] != "read_only_v1" {
		t.Fatalf("expected evidence audit fields, got %#v", res)
	}
	upload := res["upload_file"].(map[string]any)
	if upload["content_base64"] == "" || upload["path"] != path {
		t.Fatalf("bad upload payload %#v", upload)
	}
	metadata := upload["metadata"].(map[string]any)
	if metadata["reason"] != "triage" || metadata["case_id"] != "case-1" {
		t.Fatalf("missing audit metadata %#v", metadata)
	}
}

func TestEvidenceCollectionRequiresReasonAndExplicitLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.txt")
	if err := os.WriteFile(path, []byte("endpoint evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		taskType string
		args     map[string]any
		reason   string
	}{
		{name: "chunk missing limit", taskType: "read_file_chunk", args: map[string]any{"path": path, "reason": "triage", "case_id": "case-1"}, reason: "max_bytes_required"},
		{name: "chunk missing reason", taskType: "read_file_chunk", args: map[string]any{"path": path, "offset": 0, "max_bytes": 16, "case_id": "case-1"}, reason: "reason_required"},
		{name: "collect missing reason", taskType: "collect_file", args: map[string]any{"path": path, "max_bytes": 1024, "case_id": "case-1"}, reason: "reason_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Execute(tc.taskType, tc.args)
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("expected ErrBlocked, got %v %#v", err, res)
			}
			if res["reason"] != tc.reason {
				t.Fatalf("expected reason %q, got %#v", tc.reason, res)
			}
		})
	}
}

func TestProcessDetailCurrentProcess(t *testing.T) {
	res, err := Execute("process_detail", map[string]any{"pid": os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	if res["pid"] == nil || res["name"] == "" {
		t.Fatalf("expected process detail, got %#v", res)
	}
}

func TestProcessTreeCurrentProcess(t *testing.T) {
	res, err := Execute("process_tree", map[string]any{"pid": os.Getpid()})
	if err != nil {
		t.Fatal(err)
	}
	if res["nodes"] == nil {
		t.Fatalf("expected process tree nodes, got %#v", res)
	}
}

func TestAutorunsCollect(t *testing.T) {
	res, err := Execute("autoruns_collect", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if res["platform"] == "" {
		t.Fatalf("expected platform, got %#v", res)
	}
}

func TestListeningPorts(t *testing.T) {
	res, err := Execute("listening_ports", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if res["platform"] == "" {
		t.Fatalf("expected platform, got %#v", res)
	}
}
