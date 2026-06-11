package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/collect"
	"open-edr-mdr-agent/agent/internal/spool"
	"open-edr-mdr-agent/agent/internal/state"
	"open-edr-mdr-agent/agent/internal/tasks"
)

const version = "0.1.0-dev"

type agentOptions struct {
	Server            string
	EnrollToken       string
	StatePath         string
	SpoolPath         string
	Once              bool
	DemoEvent         bool
	CollectSnapshot   bool
	MaxSnapshotEvents int
	Interval          time.Duration
}

func main() {
	server := flag.String("server", "http://127.0.0.1:8000", "backend server URL")
	enrollToken := flag.String("enroll-token", "dev-token", "tenant enrollment token")
	statePath := flag.String("state", defaultStatePath(), "agent state path")
	spoolPath := flag.String("spool", defaultSpoolPath(), "offline spool JSONL path")
	once := flag.Bool("once", false, "run one heartbeat/telemetry/task cycle then exit")
	demoEvent := flag.Bool("demo-suspicious-event", false, "send a demo suspicious PowerShell event for detection smoke test")
	collectSnapshot := flag.Bool("collect-snapshot", true, "send limited process/network telemetry snapshot each cycle")
	maxSnapshotEvents := flag.Int("max-snapshot-events", 25, "maximum snapshot telemetry events per cycle")
	interval := flag.Duration("interval", 15*time.Second, "fallback loop interval before backend config is received")
	installSvc := flag.Bool("install-service", false, "install as Windows service and exit")
	uninstallSvc := flag.Bool("uninstall-service", false, "uninstall Windows service and exit")
	serviceName := flag.String("service-name", "OpenEDRMDRAgent", "Windows service name")
	serviceDisplayName := flag.String("service-display-name", "Open EDR MDR Agent", "Windows service display name")
	flag.Parse()

	opts := agentOptions{Server: *server, EnrollToken: *enrollToken, StatePath: *statePath, SpoolPath: *spoolPath, Once: *once, DemoEvent: *demoEvent, CollectSnapshot: *collectSnapshot, MaxSnapshotEvents: *maxSnapshotEvents, Interval: *interval}

	if *installSvc {
		if err := installService(*serviceName, *serviceDisplayName, *server, *enrollToken, *statePath, *spoolPath); err != nil {
			log.Fatalf("install service failed: %v", err)
		}
		log.Printf("service installed: %s", *serviceName)
		return
	}
	if *uninstallSvc {
		if err := uninstallService(*serviceName); err != nil {
			log.Fatalf("uninstall service failed: %v", err)
		}
		log.Printf("service uninstalled: %s", *serviceName)
		return
	}
	serviceHandled, err := runWindowsServiceIfNeeded(*serviceName, opts)
	if err != nil {
		log.Fatalf("service failed: %v", err)
	}
	if serviceHandled {
		return
	}
	if err := runAgent(opts, nil); err != nil {
		log.Fatalf("agent stopped with error: %v", err)
	}
}

func runAgent(opts agentOptions, stop <-chan struct{}) error {
	client := agentapi.New(opts.Server)
	agentState, err := state.Load(opts.StatePath)
	if err != nil {
		log.Printf("state not found, enrolling: %v", err)
		agentState, err = enroll(client, opts.EnrollToken)
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		if err := state.Save(opts.StatePath, agentState); err != nil {
			return fmt.Errorf("save state failed: %w", err)
		}
		log.Printf("enrolled agent_id=%s tenant_id=%s", agentState.AgentID, agentState.TenantID)
	}

	runtimeConfig := agentapi.AgentConfig{TaskPollSeconds: int(opts.Interval.Seconds()), HeartbeatSeconds: int(opts.Interval.Seconds()), UploadIntervalSeconds: int(opts.Interval.Seconds()), MaxSnapshotEvents: opts.MaxSnapshotEvents, CollectSnapshot: opts.CollectSnapshot, CollectProcessSnapshot: true, CollectNetworkSnapshot: true, CollectWindowsEventLogs: true, DemoSuspiciousEvent: opts.DemoEvent}
	for {
		newConfig, err := runCycle(client, agentState, opts.SpoolPath, runtimeConfig)
		if err != nil {
			log.Printf("cycle error: %v", err)
		}
		if newConfig != nil {
			runtimeConfig = mergeCLIOverrides(*newConfig, opts.DemoEvent, opts.MaxSnapshotEvents)
		}
		if opts.Once {
			return nil
		}
		sleepSeconds := runtimeConfig.TaskPollSeconds
		if sleepSeconds <= 0 {
			sleepSeconds = int(opts.Interval.Seconds())
		}
		select {
		case <-stop:
			log.Printf("stop requested")
			return nil
		case <-time.After(time.Duration(sleepSeconds) * time.Second):
		}
	}
}

func enroll(client *agentapi.Client, token string) (*state.State, error) {
	inv := collect.HostInventory()
	res, err := client.Enroll(agentapi.EnrollmentRequest{
		EnrollmentToken: token, Host: inv.Host, IPAddress: inv.IPAddress, OS: inv.OS, AgentVersion: version,
		Metadata: map[string]any{"go_os": runtime.GOOS, "go_arch": runtime.GOARCH},
	})
	if err != nil {
		return nil, err
	}
	return &state.State{TenantID: res.TenantID, AgentID: res.AgentID, AgentToken: res.AgentToken}, nil
}

func runCycle(client *agentapi.Client, s *state.State, spoolPath string, cfg agentapi.AgentConfig) (*agentapi.AgentConfig, error) {
	if err := spool.Flush(spoolPath, client, s); err != nil {
		log.Printf("spool flush failed: %v", err)
	}
	inv := collect.HostInventory()
	heartbeat, err := client.Heartbeat(s.AgentID, s.AgentToken, map[string]any{
		"host": inv.Host, "ip_address": inv.IPAddress, "os": inv.OS, "agent_version": version,
		"health": agentHealth(spoolPath),
	})
	if err != nil {
		log.Printf("heartbeat failed, continuing so telemetry can spool if needed: %v", err)
	}

	events := []agentapi.NormalizedEvent{}
	if cfg.CollectSnapshot {
		events = append(events, collect.SnapshotTelemetryWithOptions(s.TenantID, cfg.MaxSnapshotEvents, collect.TelemetryOptions{CollectProcessSnapshot: cfg.CollectProcessSnapshot, CollectNetworkSnapshot: cfg.CollectNetworkSnapshot, CollectWindowsEventLogs: cfg.CollectWindowsEventLogs})...)
	}
	if cfg.DemoSuspiciousEvent {
		events = append(events, collect.DemoSuspiciousPowerShellEvent(s.TenantID))
	}
	if len(events) > 0 {
		if err := client.IngestEvents(s.AgentID, s.AgentToken, events); err != nil {
			if spoolErr := spool.AppendEvents(spoolPath, events); spoolErr != nil {
				return heartbeatConfig(heartbeat), fmt.Errorf("ingest events: %w; spool failed: %v", err, spoolErr)
			}
			log.Printf("ingest failed, events spooled: %v", err)
		}
	}

	claimed, err := client.ClaimTasks(s.AgentID, s.AgentToken, 5)
	if err != nil {
		return heartbeatConfig(heartbeat), fmt.Errorf("claim tasks: %w", err)
	}
	for _, task := range claimed {
		executeAndReport(client, s, spoolPath, task)
	}
	return heartbeatConfig(heartbeat), nil
}

func heartbeatConfig(h *agentapi.HeartbeatResponse) *agentapi.AgentConfig {
	if h == nil {
		return nil
	}
	return &h.Config
}

func agentHealth(spoolPath string) map[string]any {
	spoolSize := int64(0)
	if info, err := os.Stat(spoolPath); err == nil {
		spoolSize = info.Size()
	}
	return map[string]any{
		"status":            "ok",
		"pid":               os.Getpid(),
		"version":           version,
		"runtime_os":        runtime.GOOS,
		"runtime_arch":      runtime.GOARCH,
		"spool_path":        spoolPath,
		"spool_bytes":       spoolSize,
		"task_capabilities": len(tasks.Allowed),
	}
}

func mergeCLIOverrides(cfg agentapi.AgentConfig, forceDemo bool, fallbackMaxSnapshotEvents int) agentapi.AgentConfig {
	if cfg.TaskPollSeconds <= 0 {
		cfg.TaskPollSeconds = 15
	}
	if cfg.MaxSnapshotEvents <= 0 {
		cfg.MaxSnapshotEvents = fallbackMaxSnapshotEvents
	}
	// Older configs may predate per-collector gates. Keep existing deploys collecting by default.
	if cfg.Features == nil || cfg.Features["collector_gates_explicit"] != true {
		cfg.CollectProcessSnapshot = true
		cfg.CollectNetworkSnapshot = true
		cfg.CollectWindowsEventLogs = true
	}
	if forceDemo {
		cfg.DemoSuspiciousEvent = true
	}
	return cfg
}

func executeAndReport(client *agentapi.Client, s *state.State, spoolPath string, task agentapi.Task) {
	result, err := tasks.Execute(task.TaskType, task.Args)
	if err == nil {
		if upload, ok := result["upload_file"].(map[string]any); ok {
			resp, uploadErr := uploadTaskEvidence(client, s, upload)
			if uploadErr != nil {
				err = uploadErr
			} else {
				result["evidence"] = map[string]any{"raw_ref": resp.RawRef, "sha256": resp.SHA256, "size": resp.Size}
			}
			delete(result, "upload_file")
		}
	}
	status := "succeeded"
	msg := ""
	if err != nil {
		if errors.Is(err, tasks.ErrBlocked) {
			status = "blocked_by_policy"
		} else {
			status = "failed"
		}
		msg = err.Error()
	}
	if sendErr := client.SendTaskResult(s.AgentID, s.AgentToken, task.TaskID, status, result, msg); sendErr != nil {
		if spoolErr := spool.AppendTaskResult(spoolPath, task.TaskID, status, result, msg); spoolErr != nil {
			log.Printf("task result upload failed task_id=%s: %v; spool failed: %v", task.TaskID, sendErr, spoolErr)
			return
		}
		log.Printf("task result upload failed task_id=%s, spooled: %v", task.TaskID, sendErr)
	}
}

func uploadTaskEvidence(client *agentapi.Client, s *state.State, upload map[string]any) (*agentapi.EvidenceUploadResponse, error) {
	kind, _ := upload["kind"].(string)
	path, _ := upload["path"].(string)
	sha, _ := upload["sha256"].(string)
	content, _ := upload["content_base64"].(string)
	size := int64(0)
	switch v := upload["size"].(type) {
	case int:
		size = int64(v)
	case int64:
		size = v
	case float64:
		size = int64(v)
	}
	metadata := map[string]any{}
	if m, ok := upload["metadata"].(map[string]any); ok {
		metadata = m
	}
	return client.UploadEvidence(s.AgentID, s.AgentToken, agentapi.EvidenceUploadRequest{Kind: kind, Path: path, SHA256: sha, Size: size, ContentBase64: content, Metadata: metadata})
}

func defaultStatePath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "open-edr-mdr-agent", "open-edr-scoreboard.json")
}

func defaultSpoolPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "open-edr-mdr-agent", "spool.jsonl")
}
