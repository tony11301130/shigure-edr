//go:build windows

package collect

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

type winProcess struct {
	ProcessID       int    `json:"ProcessId"`
	ParentProcessID int    `json:"ParentProcessId"`
	Name            string `json:"Name"`
	CommandLine     string `json:"CommandLine"`
	ExecutablePath  string `json:"ExecutablePath"`
}

type winNetConn struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	OwningProcess int    `json:"OwningProcess"`
	State         string `json:"State"`
}

func platformProcessSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	inv := HostInventory()
	cmd := `Get-CimInstance Win32_Process | Select-Object -First ` + strconv.Itoa(max) + ` ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | ConvertTo-Json -Compress`
	var rows []winProcess
	if err := runPowerShellJSON(cmd, &rows); err != nil {
		return []agentapi.NormalizedEvent{{Source: "internal", EventType: "generic", TenantID: tenantID, Host: inv.Host, Severity: "low", Raw: map[string]any{"collector": "process_snapshot", "platform": "windows_cim", "error": err.Error()}}}
	}
	out := []agentapi.NormalizedEvent{}
	for _, row := range rows {
		out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: "process_start", TenantID: tenantID, Host: inv.Host, ProcessName: firstNonEmpty(row.ExecutablePath, row.Name), ProcessID: strconv.Itoa(row.ProcessID), ParentProcessID: strconv.Itoa(row.ParentProcessID), CommandLine: row.CommandLine, Severity: "info", Raw: map[string]any{"collector": "process_snapshot", "platform": "windows_cim", "image": row.ExecutablePath}})
	}
	return out
}

func platformNetworkSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	inv := HostInventory()
	cmd := `Get-NetTCPConnection | Where-Object {$_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::'} | Select-Object -First ` + strconv.Itoa(max) + ` LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | ConvertTo-Json -Compress`
	var rows []winNetConn
	if err := runPowerShellJSON(cmd, &rows); err != nil {
		return []agentapi.NormalizedEvent{{Source: "internal", EventType: "generic", TenantID: tenantID, Host: inv.Host, Severity: "low", Raw: map[string]any{"collector": "network_snapshot", "platform": "windows_powershell", "error": err.Error()}}}
	}
	out := []agentapi.NormalizedEvent{}
	for _, row := range rows {
		port := row.RemotePort
		out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: "network_connection", TenantID: tenantID, Host: inv.Host, ProcessID: strconv.Itoa(row.OwningProcess), RemoteIP: row.RemoteAddress, RemotePort: &port, Severity: "info", Raw: map[string]any{"collector": "network_snapshot", "platform": "windows_powershell", "local_address": row.LocalAddress, "local_port": row.LocalPort, "state": row.State}})
	}
	return out
}

func runPowerShellJSON(command string, out any) error {
	b, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command).Output()
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(b))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		return json.Unmarshal([]byte(text), out)
	}
	// PowerShell ConvertTo-Json emits a single object, not an array, for one row.
	switch ptr := out.(type) {
	case *[]winProcess:
		var one winProcess
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return err
		}
		*ptr = []winProcess{one}
	case *[]winNetConn:
		var one winNetConn
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return err
		}
		*ptr = []winNetConn{one}
	default:
		return json.Unmarshal([]byte(text), out)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
