//go:build windows

package tasks

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type eventLogProfile struct {
	Name    string
	LogName string
	IDs     string
}

type taskWinEvent struct {
	ID           int    `json:"Id"`
	RecordID     int64  `json:"RecordId"`
	ProviderName string `json:"ProviderName"`
	LogName      string `json:"LogName"`
	TimeCreated  string `json:"TimeCreated"`
	Message      string `json:"Message"`
}

var eventLogProfiles = map[string]eventLogProfile{
	"powershell": {Name: "powershell", LogName: "Microsoft-Windows-PowerShell/Operational", IDs: "4103,4104"},
	"auth":       {Name: "auth", LogName: "Security", IDs: "4624,4625,4648"},
	"service":    {Name: "service", LogName: "System", IDs: "7045"},
	"task":       {Name: "task", LogName: "Microsoft-Windows-TaskScheduler/Operational", IDs: "106,140,141,200,201"},
}

func platformWindowsEventLogs(profile string, maxEvents int) (map[string]any, error) {
	p, ok := eventLogProfiles[profile]
	if !ok {
		return map[string]any{"blocked": true, "reason": "unsupported windows_event_logs profile", "allowed_profiles": []string{"powershell", "auth", "service", "task"}}, ErrBlocked
	}
	cmd := `$events = @(Get-WinEvent -FilterHashtable @{LogName='` + p.LogName + `'; Id=` + p.IDs + `} -MaxEvents ` + strconv.Itoa(maxEvents) + ` -ErrorAction SilentlyContinue); $events | Select-Object Id,RecordId,ProviderName,LogName,TimeCreated,Message | ConvertTo-Json -Compress`
	var rows []taskWinEvent
	if err := runTaskPowerShellJSON(cmd, &rows); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, row := range rows {
		out = append(out, map[string]any{"id": row.ID, "record_id": row.RecordID, "provider": row.ProviderName, "log_name": row.LogName, "time_created": row.TimeCreated, "message": compactTaskMessage(row.Message, 4000)})
	}
	return map[string]any{"profile": p.Name, "log_name": p.LogName, "event_ids": p.IDs, "events": out}, nil
}

func runTaskPowerShellJSON(command string, out *[]taskWinEvent) error {
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
	var one taskWinEvent
	if err := json.Unmarshal([]byte(text), &one); err != nil {
		return fmt.Errorf("parse Get-WinEvent JSON: %w", err)
	}
	*out = []taskWinEvent{one}
	return nil
}

func compactTaskMessage(message string, max int) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > max {
		return message[:max]
	}
	return message
}
