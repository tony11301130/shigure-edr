package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"open-edr-mdr-agent/agent/internal/collect"
)

var ErrBlocked = errors.New("blocked_by_policy")

type TaskMeta struct {
	Risk        string
	Destructive bool
}

var Catalog = map[string]TaskMeta{
	"inventory": {Risk: "low"}, "process_list": {Risk: "low"}, "network_connections": {Risk: "low"}, "service_list": {Risk: "low"}, "scheduled_tasks": {Risk: "low"}, "windows_event_logs": {Risk: "low"}, "file_exists": {Risk: "low"}, "file_hash": {Risk: "low"},
	"agent_identity": {Risk: "low"}, "list_directory": {Risk: "low"}, "read_file_chunk": {Risk: "medium"}, "copy_file": {Risk: "medium"},
	"quarantine_file": {Risk: "high", Destructive: true}, "delete_file": {Risk: "high", Destructive: true}, "kill_process": {Risk: "high", Destructive: true}, "service_control": {Risk: "high", Destructive: true},
}

var Allowed = func() map[string]bool {
	out := map[string]bool{}
	for k := range Catalog {
		out[k] = true
	}
	return out
}()

func Execute(taskType string, args map[string]any) (map[string]any, error) {
	meta, ok := Catalog[taskType]
	if !ok {
		return map[string]any{"blocked": true, "reason": "task is not allowlisted", "task_type": taskType, "executed_at": time.Now().UTC().Format(time.RFC3339)}, ErrBlocked
	}
	result, err := executeAllowed(taskType, args)
	if result == nil {
		result = map[string]any{}
	}
	result["task_type"] = taskType
	result["risk"] = meta.Risk
	result["destructive"] = meta.Destructive
	result["executed_at"] = time.Now().UTC().Format(time.RFC3339)
	return result, err
}

func executeAllowed(taskType string, args map[string]any) (map[string]any, error) {
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
	case "windows_event_logs":
		return windowsEventLogs(args)
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
	case "agent_identity":
		return agentIdentity()
	case "list_directory":
		return listDirectory(args)
	case "read_file_chunk":
		return readFileChunk(args)
	case "copy_file":
		return copyFileTask(args)
	case "quarantine_file":
		return quarantineFile(args)
	case "delete_file":
		return deleteFile(args)
	case "kill_process":
		return killProcess(args)
	case "service_control":
		return serviceControl(args)
	default:
		return nil, ErrBlocked
	}
}

func processList() []map[string]any {
	if runtime.GOOS == "windows" {
		out, err := runCommand(15*time.Second, "tasklist.exe", "/fo", "csv", "/nh")
		row := map[string]any{"format": "tasklist_csv", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
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
	if runtime.GOOS == "windows" {
		out, err := runCommand(15*time.Second, "netstat.exe", "-ano")
		row := map[string]any{"format": "netstat_ano", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
	ifaces, _ := net.Interfaces()
	out := []map[string]any{}
	for _, iface := range ifaces {
		out = append(out, map[string]any{"interface": iface.Name, "flags": iface.Flags.String()})
	}
	return out
}

func serviceList() []map[string]any {
	if runtime.GOOS == "windows" {
		out, err := runCommand(20*time.Second, "sc.exe", "query", "state=", "all")
		row := map[string]any{"format": "sc_query", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
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
	if runtime.GOOS == "windows" {
		out, err := runCommand(20*time.Second, "schtasks.exe", "/query", "/fo", "csv", "/v")
		row := map[string]any{"format": "schtasks_csv", "output": out}
		if err != nil {
			row["error"] = err.Error()
		}
		return []map[string]any{row}
	}
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

func windowsEventLogs(args map[string]any) (map[string]any, error) {
	profile, _ := args["profile"].(string)
	if profile == "" {
		profile = "powershell"
	}
	maxEvents := intArg(args, "max_events", 25)
	if maxEvents <= 0 {
		maxEvents = 25
	}
	if maxEvents > 100 {
		maxEvents = 100
	}
	return platformWindowsEventLogs(profile, maxEvents)
}

func agentIdentity() (map[string]any, error) {
	if runtime.GOOS == "windows" {
		out, err := runCommand(5*time.Second, "whoami.exe", "/all")
		return map[string]any{"platform": runtime.GOOS, "whoami_all": out, "is_local_system_hint": strings.Contains(strings.ToLower(out), "nt authority\\system")}, err
	}
	out, err := runCommand(5*time.Second, "id")
	return map[string]any{"platform": runtime.GOOS, "id": out, "is_root_hint": strings.Contains(out, "uid=0(")}, err
}

func listDirectory(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	max := intArg(args, "max_entries", 100)
	if max <= 0 || max > 500 {
		max = 100
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, e := range entries {
		info, _ := e.Info()
		row := map[string]any{"name": e.Name(), "is_dir": e.IsDir()}
		if info != nil {
			row["size"] = info.Size()
			row["mode"] = info.Mode().String()
			row["mod_time"] = info.ModTime().UTC().Format(time.RFC3339)
		}
		out = append(out, row)
		if len(out) >= max {
			break
		}
	}
	return map[string]any{"path": path, "entries": out, "truncated": len(entries) > len(out)}, nil
}

func readFileChunk(args map[string]any) (map[string]any, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return nil, errors.New("path required")
	}
	offset := int64(intArg(args, "offset", 0))
	maxBytes := intArg(args, "max_bytes", 4096)
	if maxBytes <= 0 || maxBytes > 65536 {
		maxBytes = 4096
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	data := buf[:n]
	return map[string]any{"path": path, "offset": offset, "bytes_read": n, "base64": base64.StdEncoding.EncodeToString(data), "text_preview": safePreview(data)}, nil
}

func copyFileTask(args map[string]any) (map[string]any, error) {
	src, _ := args["source_path"].(string)
	dst, _ := args["destination_path"].(string)
	if src == "" || dst == "" {
		return nil, errors.New("source_path and destination_path required")
	}
	bytes, err := copyFile(src, dst)
	if err != nil {
		return nil, err
	}
	return map[string]any{"source_path": src, "destination_path": dst, "bytes_copied": bytes}, nil
}

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

func intArg(args map[string]any, key string, fallback int) int {
	v, ok := args[key]
	if !ok {
		return fallback
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		i, err := strconv.Atoi(t)
		if err == nil {
			return i
		}
	}
	return fallback
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

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, in)
}

func safePreview(data []byte) string {
	s := string(data)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			return r
		}
		return '�'
	}, s)
	if len(s) > 4096 {
		return s[:4096]
	}
	return s
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

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("command timed out")
	}
	return string(out), err
}
