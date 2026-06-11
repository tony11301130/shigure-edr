package tasks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func quarantineFile(args map[string]any) (map[string]any, error) {
	src, _ := args["source_path"].(string)
	dir, _ := args["quarantine_dir"].(string)
	if src == "" || dir == "" {
		return nil, errors.New("source_path and quarantine_dir required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	dst := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UTC().Unix(), filepath.Base(src)))
	if err := os.Rename(src, dst); err != nil {
		return nil, err
	}
	return map[string]any{"source_path": src, "quarantine_path": dst, "moved": true}, nil
}

func deleteFile(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	confirm, _ := args["confirm_sha256"].(string)
	if path == "" || confirm == "" {
		return nil, errors.New("path and confirm_sha256 required")
	}
	actual, err := hashFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(actual, confirm) {
		return map[string]any{"path": path, "deleted": false, "sha256": actual, "reason": "confirm_sha256_mismatch"}, ErrBlocked
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return map[string]any{"path": path, "deleted": true, "sha256": actual}, nil
}

func killProcess(args map[string]any) (map[string]any, error) {
	pid := intArg(args, "pid", 0)
	if pid <= 0 {
		return nil, errors.New("pid required")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	if err := p.Kill(); err != nil {
		return nil, err
	}
	return map[string]any{"pid": pid, "killed": true}, nil
}

func serviceControl(args map[string]any) (map[string]any, error) {
	name, _ := args["service_name"].(string)
	action, _ := args["action"].(string)
	if !safeServiceName(name) {
		return nil, errors.New("invalid service_name")
	}
	if action != "status" && action != "start" && action != "stop" {
		return nil, errors.New("invalid action")
	}
	var cmd string
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmd = "sc.exe"
		scAction := map[string]string{"status": "query", "start": "start", "stop": "stop"}[action]
		cmdArgs = []string{scAction, name}
	} else {
		cmd = "systemctl"
		cmdArgs = []string{action, name}
	}
	out, err := runCommand(15*time.Second, cmd, cmdArgs...)
	return map[string]any{"service_name": name, "action": action, "output": out}, err
}

func safeServiceName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
