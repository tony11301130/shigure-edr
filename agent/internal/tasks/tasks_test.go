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
	chunk, err := Execute("read_file_chunk", map[string]any{"path": path, "offset": 6, "max_bytes": 5})
	if err != nil {
		t.Fatal(err)
	}
	if chunk["text_preview"] != "world" {
		t.Fatalf("expected world preview, got %#v", chunk)
	}
}

func TestCopyQuarantineAndDeleteRequireHash(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	copyPath := filepath.Join(dir, "evidence", "copy.txt")
	if err := os.WriteFile(src, []byte("malware-ish"), 0600); err != nil {
		t.Fatal(err)
	}
	copied, err := Execute("copy_file", map[string]any{"source_path": src, "destination_path": copyPath})
	if err != nil {
		t.Fatal(err)
	}
	if copied["bytes_copied"].(int64) == 0 {
		t.Fatalf("expected copied bytes, got %#v", copied)
	}
	mismatch, err := Execute("delete_file", map[string]any{"path": copyPath, "confirm_sha256": "bad"})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected hash mismatch block, got %v %#v", err, mismatch)
	}
	h, err := hashFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := Execute("delete_file", map[string]any{"path": copyPath, "confirm_sha256": h})
	if err != nil {
		t.Fatal(err)
	}
	if deleted["deleted"] != true {
		t.Fatalf("expected deleted, got %#v", deleted)
	}

	quarantineDir := filepath.Join(dir, "quarantine")
	moved, err := Execute("quarantine_file", map[string]any{"source_path": src, "quarantine_dir": quarantineDir})
	if err != nil {
		t.Fatal(err)
	}
	if moved["moved"] != true {
		t.Fatalf("expected moved, got %#v", moved)
	}
}
