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

type winLogEvent struct {
	ID           int    `json:"Id"`
	RecordID     int64  `json:"RecordId"`
	ProviderName string `json:"ProviderName"`
	LogName      string `json:"LogName"`
	TimeCreated  string `json:"TimeCreated"`
	Message      string `json:"Message"`
}

type winEventLogQuery struct {
	Name      string
	LogName   string
	IDs       string
	EventType string
	Severity  string
	MITRE     string
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

func platformEventLogSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	if max <= 0 {
		return nil
	}
	inv := HostInventory()
	queries := []winEventLogQuery{
		{Name: "powershell_operational", LogName: "Microsoft-Windows-PowerShell/Operational", IDs: "4103,4104", EventType: "script_result", Severity: "medium", MITRE: "T1059.001"},
		{Name: "security_auth", LogName: "Security", IDs: "4624,4625,4648", EventType: "auth_event", Severity: "info", MITRE: ""},
		{Name: "service_control_manager", LogName: "System", IDs: "7045", EventType: "endpoint_state", Severity: "medium", MITRE: "T1543.003"},
		{Name: "task_scheduler", LogName: "Microsoft-Windows-TaskScheduler/Operational", IDs: "106,140,141,200,201", EventType: "endpoint_state", Severity: "low", MITRE: "T1053.005"},
	}
	out := []agentapi.NormalizedEvent{}
	perQuery := max / len(queries)
	if perQuery < 1 {
		perQuery = 1
	}
	for _, q := range queries {
		if len(out) >= max {
			break
		}
		remaining := max - len(out)
		limit := perQuery
		if limit > remaining {
			limit = remaining
		}
		events, err := queryWindowsEventLog(q, limit)
		if err != nil {
			out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: "generic", TenantID: tenantID, Host: inv.Host, Severity: "low", Raw: map[string]any{"collector": "windows_event_log", "query": q.Name, "platform": "windows_getwinevent", "error": err.Error()}})
			continue
		}
		for _, ev := range events {
			if len(out) >= max {
				break
			}
			raw := map[string]any{"collector": "windows_event_log", "platform": "windows_getwinevent", "query": q.Name, "event_id": ev.ID, "record_id": ev.RecordID, "provider": ev.ProviderName, "log_name": ev.LogName, "time_created": ev.TimeCreated, "message": ev.Message}
			mitre := []string{}
			if q.MITRE != "" {
				mitre = append(mitre, q.MITRE)
			}
			out = append(out, agentapi.NormalizedEvent{Source: "internal", EventType: q.EventType, TenantID: tenantID, SourceEventID: strconv.FormatInt(ev.RecordID, 10), Host: inv.Host, Severity: q.Severity, Raw: raw, CommandLine: commandLineFromLog(q, ev.Message), User: userFromLog(q, ev.Message), Mitre: mitre})
		}
	}
	return out
}

func queryWindowsEventLog(q winEventLogQuery, max int) ([]winLogEvent, error) {
	cmd := `Get-WinEvent -FilterHashtable @{LogName='` + q.LogName + `'; Id=` + q.IDs + `} -MaxEvents ` + strconv.Itoa(max) + ` -ErrorAction Stop | Select-Object Id,RecordId,ProviderName,LogName,TimeCreated,Message | ConvertTo-Json -Compress`
	var rows []winLogEvent
	if err := runPowerShellJSON(cmd, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func commandLineFromLog(q winEventLogQuery, message string) string {
	if q.Name != "powershell_operational" {
		return ""
	}
	return compactLogMessage(message, 2000)
}

func userFromLog(q winEventLogQuery, message string) string {
	if q.Name != "security_auth" {
		return ""
	}
	for _, label := range []string{"Account Name:", "帳戶名稱:"} {
		idx := strings.Index(message, label)
		if idx >= 0 {
			line := strings.SplitN(message[idx+len(label):], "\n", 2)[0]
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func compactLogMessage(message string, max int) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > max {
		return message[:max]
	}
	return message
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
	case *[]winLogEvent:
		var one winLogEvent
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return err
		}
		*ptr = []winLogEvent{one}
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
