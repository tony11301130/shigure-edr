package tasks

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func networkConnections() []map[string]any {
	if runtime.GOOS == "windows" {
		out, err := runCommand(15*time.Second, "netstat.exe", "-ano")
		row := map[string]any{"format": "netstat_ano", "output": out, "rows": parseWindowsNetstatANO(out)}
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

func listeningPorts() (map[string]any, error) {
	if runtime.GOOS == "windows" {
		out, err := runCommand(15*time.Second, "netstat.exe", "-ano", "-p", "tcp")
		rows := []map[string]any{}
		for _, row := range parseWindowsNetstatANO(out) {
			if row["state"] == "LISTENING" {
				rows = append(rows, row)
			}
		}
		return map[string]any{"platform": "windows", "format": "netstat_ano", "output": out, "rows": rows}, err
	}
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	rows := []map[string]any{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			local := fields[1]
			parts := strings.Split(local, ":")
			port := 0
			if len(parts) == 2 {
				p64, _ := strconv.ParseInt(parts[1], 16, 32)
				port = int(p64)
			}
			rows = append(rows, map[string]any{"source": file, "local_raw": local, "port": port, "state": "LISTEN", "inode": fields[9]})
		}
	}
	return map[string]any{"platform": runtime.GOOS, "listeners": rows}, nil
}
