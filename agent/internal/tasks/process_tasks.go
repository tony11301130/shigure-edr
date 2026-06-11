package tasks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func processList() []map[string]any {
	if runtime.GOOS == "windows" {
		out, err := runCommand(15*time.Second, "tasklist.exe", "/fo", "csv", "/nh")
		row := map[string]any{"format": "tasklist_csv", "output": out, "rows": parseWindowsTasklistCSV(out)}
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

func processDetail(args map[string]any) (map[string]any, error) {
	pid := intArg(args, "pid", 0)
	if pid <= 0 {
		return nil, errors.New("pid required")
	}
	if runtime.GOOS == "windows" {
		query := fmt.Sprintf("Get-CimInstance Win32_Process -Filter \"ProcessId=%d\" | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress", pid)
		out, err := runCommand(15*time.Second, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", query)
		return map[string]any{"pid": pid, "format": "win32_process_json", "output": out}, err
	}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	comm, _ := os.ReadFile(filepath.Join(base, "comm"))
	cmd, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	stat, _ := os.ReadFile(filepath.Join(base, "stat"))
	ppid := ""
	fields := strings.Fields(string(stat))
	if len(fields) > 3 {
		ppid = fields[3]
	}
	res := map[string]any{"pid": pid, "ppid": ppid, "name": strings.TrimSpace(string(comm)), "cmdline": strings.ReplaceAll(string(cmd), "\x00", " "), "exe": exe}
	if exe != "" {
		if h, err := hashFile(exe); err == nil {
			res["exe_sha256"] = h
		}
	}
	return res, nil
}

func processTree(args map[string]any) (map[string]any, error) {
	pid := intArg(args, "pid", 0)
	if pid <= 0 {
		return nil, errors.New("pid required")
	}
	if runtime.GOOS == "windows" {
		query := fmt.Sprintf("$p=%d; Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $p -or $_.ParentProcessId -eq $p } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress", pid)
		out, err := runCommand(20*time.Second, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", query)
		return map[string]any{"pid": pid, "format": "win32_process_tree_json", "output": out}, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	nodes := []map[string]any{}
	for _, e := range entries {
		cpid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		fields := strings.Fields(string(stat))
		if len(fields) <= 3 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[3])
		if cpid != pid && ppid != pid {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		cmd, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		nodes = append(nodes, map[string]any{"pid": cpid, "ppid": ppid, "name": strings.TrimSpace(string(comm)), "cmdline": strings.ReplaceAll(string(cmd), "\x00", " ")})
	}
	return map[string]any{"pid": pid, "nodes": nodes}, nil
}
