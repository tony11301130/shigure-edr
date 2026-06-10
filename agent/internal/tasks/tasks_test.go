package tasks

import (
	"errors"
	"os"
	"testing"
)

func TestExecuteBlocksUnknownTask(t *testing.T) {
	res, err := Execute("delete_file", map[string]any{"path": "C:/important"})
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
