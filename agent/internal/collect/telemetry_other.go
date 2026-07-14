//go:build !linux && !windows

package collect

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func platformProcessSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	inv := HostInventory()
	bootID := hostBootID()
	event := agentapi.NormalizedEvent{Source: "internal", EventType: "process_start", TenantID: tenantID, Host: inv.Host, ProcessName: os.Args[0], ProcessID: strconv.Itoa(os.Getpid()), ImagePath: os.Args[0], CommandLine: strings.Join(os.Args, " "), Severity: "info", Raw: map[string]any{"collector": "process_snapshot", "platform": runtime.GOOS, "note": "native collector pending for this OS"}}
	return observeProcessSnapshotEvents(tenantID, bootID, []agentapi.NormalizedEvent{event})
}

func platformNetworkSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	return nil
}

func platformEventLogSnapshot(tenantID string, max int) []agentapi.NormalizedEvent {
	return nil
}
