package collect

import (
	"net"
	"os"
	"runtime"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

type Inventory struct {
	Host      string `json:"host"`
	IPAddress string `json:"ip_address,omitempty"`
	OS        string `json:"os"`
	GoOS      string `json:"go_os"`
	GoArch    string `json:"go_arch"`
}

func HostInventory() Inventory {
	host, _ := os.Hostname()
	return Inventory{Host: host, IPAddress: firstNonLoopbackIP(), OS: runtime.GOOS, GoOS: runtime.GOOS, GoArch: runtime.GOARCH}
}

func DemoSuspiciousPowerShellEvent(tenantID string) agentapi.NormalizedEvent {
	inv := HostInventory()
	event := agentapi.NormalizedEvent{
		Source: "internal", EventType: "process_start", TenantID: tenantID, Host: inv.Host,
		ProcessName: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ProcessID: "4242", ParentProcessID: "100",
		ImagePath:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CommandLine: "powershell.exe -enc SQBFAFgA", Severity: "info", Raw: map[string]any{"collector": "demo"},
	}
	ApplyProcessIdentity(&event, hostBootID())
	return event
}

func firstNonLoopbackIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
