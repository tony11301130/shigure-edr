//go:build windows

package collect

import "strings"

func hostBootID() string {
	var lastBoot string
	err := runPowerShellJSON(`(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | ConvertTo-Json -Compress`, &lastBoot)
	if err == nil {
		if bootID := strings.TrimSpace(lastBoot); bootID != "" {
			return "windows_last_boot:" + bootID
		}
	}
	return "windows_boot_id_unavailable"
}
