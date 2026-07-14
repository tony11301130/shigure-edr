//go:build linux

package collect

import (
	"os"
	"strings"
)

func hostBootID() string {
	if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		if bootID := strings.TrimSpace(string(data)); bootID != "" {
			return bootID
		}
	}
	return "linux_boot_id_unavailable"
}
