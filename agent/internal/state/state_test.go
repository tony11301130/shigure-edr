package state

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadPreservesCredentialVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := &State{
		TenantID:          "tenant-a",
		AgentID:           "agent-1",
		AgentToken:        "agent-secret",
		CredentialVersion: 3,
	}

	if err := Save(path, want); err != nil {
		t.Fatalf("save state: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}

	if got.CredentialVersion != 3 {
		t.Fatalf("expected credential version 3, got %d", got.CredentialVersion)
	}
	if got.AgentToken != "agent-secret" {
		t.Fatalf("expected agent token to round trip")
	}
}
