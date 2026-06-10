package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"open-edr-mdr-agent/agent/internal/collect"
)

var ErrBlocked = errors.New("blocked_by_policy")

var Allowed = map[string]bool{
	"inventory": true, "process_list": true, "network_connections": true, "service_list": true, "scheduled_tasks": true, "file_exists": true, "file_hash": true,
}

func Execute(taskType string, args map[string]any) (map[string]any, error) {
	if !Allowed[taskType] {
		return map[string]any{"blocked": true, "reason": "task is not read-only allowlisted"}, ErrBlocked
	}
	switch taskType {
	case "inventory":
		return map[string]any{"inventory": collect.HostInventory()}, nil
	case "process_list":
		return map[string]any{"processes": processList()}, nil
	case "network_connections":
		return map[string]any{"connections": networkConnections()}, nil
	case "service_list":
		return map[string]any{"services": serviceList()}, nil
	case "scheduled_tasks":
		return map[string]any{"scheduled_tasks": scheduledTasks()}, nil
	case "file_exists":
		path, _ := args["path"].(string)
		if path == "" {
			return nil, errors.New("path required")
		}
		_, err := os.Stat(path)
		return map[string]any{"path": path, "exists": err == nil}, nil
	case "file_hash":
		path, _ := args["path"].(string)
		if path == "" {
			return nil, errors.New("path required")
		}
		h, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		return map[string]any{"path": path, "sha256": h}, nil
	default:
		return nil, ErrBlocked
	}
}

func processList() []map[string]any {
	if runtime.GOOS != "linux" {
		return []map[string]any{{"note": "native process collector for this OS is pending"}}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := []map[string]any{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		cmd, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		out = append(out, map[string]any{"pid": pid, "name": strings.TrimSpace(string(comm)), "cmdline": strings.ReplaceAll(string(cmd), "\x00", " ")})
		if len(out) >= 200 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["pid"].(int) < out[j]["pid"].(int) })
	return out
}

func networkConnections() []map[string]any {
	ifaces, _ := net.Interfaces()
	out := []map[string]any{}
	for _, iface := range ifaces {
		out = append(out, map[string]any{"interface": iface.Name, "flags": iface.Flags.String()})
	}
	return out
}

func serviceList() []map[string]any {
	if runtime.GOOS != "linux" {
		return []map[string]any{{"note": "native service collector for this OS is pending"}}
	}
	roots := []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"}
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".service") || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, map[string]any{"name": name, "source": root})
			if len(out) >= 200 {
				return out
			}
		}
	}
	return out
}

func scheduledTasks() []map[string]any {
	out := []map[string]any{}
	if runtime.GOOS != "linux" {
		return []map[string]any{{"note": "native scheduled task collector for this OS is pending"}}
	}
	paths := []string{"/etc/crontab"}
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, map[string]any{"path": p, "type": "crontab"})
		}
	}
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			out = append(out, map[string]any{"path": filepath.Join(dir, e.Name()), "type": "cron"})
		}
	}
	return out
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
