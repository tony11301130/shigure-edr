package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type State struct {
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	AgentToken string `json:"agent_token"`
}

func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func Save(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
