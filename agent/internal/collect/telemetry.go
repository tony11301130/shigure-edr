package collect

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func SnapshotTelemetry(tenantID string, maxEvents int) []agentapi.NormalizedEvent {
	if maxEvents <= 0 {
		maxEvents = 50
	}
	var events []agentapi.NormalizedEvent
	events = append(events, processSnapshot(tenantID, maxEvents)...)
	if len(events) < maxEvents {
		events = append(events, networkSnapshot(tenantID, maxEvents-len(events))...)
	}
	if len(events) > maxEvents {
		return events[:maxEvents]
	}
	return events
}

func processSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	inv := HostInventory()
	if runtime.GOOS != "linux" {
		return []agentapi.NormalizedEvent{{Source: "internal", EventType: "process_start", TenantID: tenantID, Host: inv.Host, ProcessName: os.Args[0], ProcessID: strconv.Itoa(os.Getpid()), CommandLine: strings.Join(os.Args, " "), Severity: "info", Raw: map[string]any{"collector": "process_snapshot", "note": "native collector pending for this OS"}}}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := []agentapi.NormalizedEvent{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		cmd, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		stat, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		ppid := parsePPID(string(stat))
		out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: "process_start", TenantID: tenantID, Host: inv.Host, ProcessName: strings.TrimSpace(string(comm)), ProcessID: strconv.Itoa(pid), ParentProcessID: ppid, CommandLine: strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " ")), Severity: "info", Raw: map[string]any{"collector": "process_snapshot"}})
		if len(out) >= max {
			break
		}
	}
	return out
}

func networkSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	if runtime.GOOS != "linux" {
		return nil
	}
	inv := HostInventory()
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	out := []agentapi.NormalizedEvent{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		first := true
		for s.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(s.Text())
			if len(fields) < 3 {
				continue
			}
			remoteIP, remotePort := parseProcNetAddr(fields[2])
			if remoteIP == "" || remoteIP == "0.0.0.0" {
				continue
			}
			port := remotePort
			out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: "network_connection", TenantID: tenantID, Host: inv.Host, RemoteIP: remoteIP, RemotePort: &port, Severity: "info", Raw: map[string]any{"collector": "network_snapshot", "state": fields[3], "source_file": path}})
			if len(out) >= max {
				_ = f.Close()
				return out
			}
		}
		_ = f.Close()
	}
	return out
}

func parsePPID(stat string) string {
	idx := strings.LastIndex(stat, ")")
	if idx == -1 || len(stat) <= idx+4 {
		return ""
	}
	fields := strings.Fields(stat[idx+1:])
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}

func parseProcNetAddr(v string) (string, int) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	hexIP := parts[0]
	if len(hexIP) == 8 {
		b1, _ := strconv.ParseInt(hexIP[6:8], 16, 32)
		b2, _ := strconv.ParseInt(hexIP[4:6], 16, 32)
		b3, _ := strconv.ParseInt(hexIP[2:4], 16, 32)
		b4, _ := strconv.ParseInt(hexIP[0:2], 16, 32)
		return fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4), int(port64)
	}
	return hexIP, int(port64)
}
