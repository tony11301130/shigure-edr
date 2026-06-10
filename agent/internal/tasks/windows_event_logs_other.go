//go:build !windows

package tasks

func platformWindowsEventLogs(profile string, maxEvents int) (map[string]any, error) {
	allowed := map[string]bool{"powershell": true, "auth": true, "service": true, "task": true}
	if !allowed[profile] {
		return map[string]any{"blocked": true, "reason": "unsupported windows_event_logs profile", "allowed_profiles": []string{"powershell", "auth", "service", "task"}}, ErrBlocked
	}
	return map[string]any{"profile": profile, "events": []map[string]any{}, "note": "windows_event_logs task is only available on Windows"}, nil
}
