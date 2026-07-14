package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"open-edr-mdr-agent/agent/internal/agentapi"
	"open-edr-mdr-agent/agent/internal/collect"
	"open-edr-mdr-agent/agent/internal/spool"
	"open-edr-mdr-agent/agent/internal/state"
	"open-edr-mdr-agent/agent/internal/tasks"
)

const version = "0.1.0-dev"

var defaultSpoolLimits = spool.Limits{MaxBytes: 50 * 1024 * 1024, MaxRecords: 10000}

type agentOptions struct {
	Profile           string
	ConfigPath        string
	Server            string
	EnrollToken       string
	ServerTrust       string
	StatePath         string
	SpoolPath         string
	SpoolMaxBytes     int64
	SpoolMaxRecords   int
	Once              bool
	DemoEvent         bool
	CollectSnapshot   bool
	MaxSnapshotEvents int
	Interval          time.Duration
}

func main() {
	configPath := flag.String("config", "", "agent JSON config path")
	profile := flag.String("profile", "", "runtime profile: dev, demo, or production")
	server := flag.String("server", "http://127.0.0.1:8000", "backend server URL")
	enrollToken := flag.String("enroll-token", "dev-token", "tenant enrollment token")
	serverTrust := flag.String("server-trust", "", "server trust mode or CA bundle path for production profile")
	statePath := flag.String("state", defaultStatePath(), "agent state path")
	spoolPath := flag.String("spool", defaultSpoolPath(), "offline spool JSONL path")
	spoolMaxBytes := flag.Int64("spool-max-bytes", defaultSpoolLimits.MaxBytes, "maximum offline spool bytes before oldest records are dropped")
	spoolMaxRecords := flag.Int("spool-max-records", defaultSpoolLimits.MaxRecords, "maximum offline spool records before oldest records are dropped")
	once := flag.Bool("once", false, "run one heartbeat/telemetry/task cycle then exit")
	demoEvent := flag.Bool("demo-suspicious-event", false, "send a demo suspicious PowerShell event for detection smoke test")
	collectSnapshot := flag.Bool("collect-snapshot", true, "send limited process/network telemetry snapshot each cycle")
	maxSnapshotEvents := flag.Int("max-snapshot-events", 25, "maximum snapshot telemetry events per cycle")
	interval := flag.Duration("interval", 15*time.Second, "fallback loop interval before backend config is received")
	installSvc := flag.Bool("install-service", false, "install as Windows service and exit")
	uninstallSvc := flag.Bool("uninstall-service", false, "uninstall Windows service and exit")
	serviceName := flag.String("service-name", "ShioriAgent", "Windows service name")
	serviceDisplayName := flag.String("service-display-name", "Shiori Agent", "Windows service display name")
	installDir := flag.String("install-dir", defaultInstallDir(), "Windows service binary install directory")
	flag.Parse()

	opts := agentOptions{Profile: *profile, ConfigPath: *configPath, Server: *server, EnrollToken: *enrollToken, ServerTrust: *serverTrust, StatePath: *statePath, SpoolPath: *spoolPath, SpoolMaxBytes: *spoolMaxBytes, SpoolMaxRecords: *spoolMaxRecords, Once: *once, DemoEvent: *demoEvent, CollectSnapshot: *collectSnapshot, MaxSnapshotEvents: *maxSnapshotEvents, Interval: *interval}
	if err := applyConfigFile(&opts); err != nil {
		log.Fatalf("load config failed: %v", err)
	}
	if err := validateAgentOptions(opts); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	if *installSvc {
		if err := installService(*serviceName, *serviceDisplayName, opts, *installDir); err != nil {
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

func validateAgentOptions(opts agentOptions) error {
	profile := strings.ToLower(strings.TrimSpace(opts.Profile))
	switch profile {
	case "":
		return fmt.Errorf("profile is required; choose dev, demo, or production")
	case "dev", "demo":
		return nil
	case "production":
	default:
		return fmt.Errorf("unknown profile %q", opts.Profile)
	}

	parsed, err := url.Parse(opts.Server)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("server URL is invalid")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("production requires https server URL")
	}
	token := strings.ToLower(strings.TrimSpace(opts.EnrollToken))
	if token == "" {
		if _, err := os.Stat(opts.StatePath); err != nil {
			return fmt.Errorf("production requires an enrollment token until agent state exists")
		}
	} else if token == "dev-token" || token == "enroll-token" || token == "changeme" || token == "change-me" {
		return fmt.Errorf("production enrollment token must not use a default or dev value")
	}
	if strings.TrimSpace(opts.ServerTrust) == "" {
		return fmt.Errorf("production requires server trust configuration")
	}
	return nil
}

type bootstrapConfig struct {
	Profile         string `json:"profile"`
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token"`
	ServerTrust     string `json:"server_trust"`
	SpoolMaxBytes   int64  `json:"spool_max_bytes"`
	SpoolMaxRecords int    `json:"spool_max_records"`
}

func applyConfigFile(opts *agentOptions) error {
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return nil
	}
	b, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg bootstrapConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if cfg.Profile != "" {
		opts.Profile = cfg.Profile
	}
	if cfg.ServerURL != "" {
		opts.Server = cfg.ServerURL
	}
	opts.EnrollToken = cfg.EnrollmentToken
	if cfg.ServerTrust != "" {
		opts.ServerTrust = cfg.ServerTrust
	}
	if cfg.SpoolMaxBytes > 0 {
		opts.SpoolMaxBytes = cfg.SpoolMaxBytes
	}
	if cfg.SpoolMaxRecords > 0 {
		opts.SpoolMaxRecords = cfg.SpoolMaxRecords
	}
	return nil
}

func scrubEnrollmentTokenFromConfig(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		return nil
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if _, ok := cfg["enrollment_token"]; !ok {
		return nil
	}
	delete(cfg, "enrollment_token")
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	out = append(out, '\n')
	return os.WriteFile(configPath, out, 0600)
}

func serviceRuntimeArgs(opts agentOptions) []string {
	args := []string{}
	if strings.TrimSpace(opts.ConfigPath) != "" {
		args = append(args, "--config", opts.ConfigPath)
	} else {
		args = append(args, "--profile", opts.Profile, "--server", opts.Server, "--enroll-token", opts.EnrollToken)
		if opts.ServerTrust != "" {
			args = append(args, "--server-trust", opts.ServerTrust)
		}
	}
	args = append(args, "--state", opts.StatePath, "--spool", opts.SpoolPath)
	if opts.SpoolMaxBytes > 0 {
		args = append(args, "--spool-max-bytes", fmt.Sprintf("%d", opts.SpoolMaxBytes))
	}
	if opts.SpoolMaxRecords > 0 {
		args = append(args, "--spool-max-records", fmt.Sprintf("%d", opts.SpoolMaxRecords))
	}
	return args
}

func runAgent(opts agentOptions, stop <-chan struct{}) error {
	client, err := agentapi.NewWithTrust(opts.Server, opts.ServerTrust)
	if err != nil {
		return fmt.Errorf("configure server trust: %w", err)
	}
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
		if err := scrubEnrollmentTokenFromConfig(opts.ConfigPath); err != nil {
			return fmt.Errorf("scrub enrollment token from config failed: %w", err)
		}
		log.Printf("enrolled agent_id=%s tenant_id=%s", agentState.AgentID, agentState.TenantID)
	}

	runtimeConfig := agentapi.AgentConfig{TaskPollSeconds: int(opts.Interval.Seconds()), HeartbeatSeconds: int(opts.Interval.Seconds()), UploadIntervalSeconds: int(opts.Interval.Seconds()), MaxSnapshotEvents: opts.MaxSnapshotEvents, CollectSnapshot: opts.CollectSnapshot, CollectProcessSnapshot: true, CollectNetworkSnapshot: true, CollectWindowsEventLogs: true, DemoSuspiciousEvent: opts.DemoEvent}
	spoolLimits := opts.spoolLimits()
	for {
		newConfig, err := runCycle(client, agentState, opts.StatePath, opts.SpoolPath, spoolLimits, runtimeConfig)
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

func (opts agentOptions) spoolLimits() spool.Limits {
	limits := defaultSpoolLimits
	if opts.SpoolMaxBytes > 0 {
		limits.MaxBytes = opts.SpoolMaxBytes
	}
	if opts.SpoolMaxRecords > 0 {
		limits.MaxRecords = opts.SpoolMaxRecords
	}
	return limits
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
	return &state.State{TenantID: res.TenantID, AgentID: res.AgentID, AgentToken: res.AgentToken, CredentialVersion: res.CredentialVersion}, nil
}

func runCycle(client *agentapi.Client, s *state.State, statePath string, spoolPath string, spoolLimits spool.Limits, cfg agentapi.AgentConfig) (*agentapi.AgentConfig, error) {
	if _, err := spool.FlushBounded(spoolPath, client, s, spoolLimits); err != nil {
		log.Printf("spool flush failed: %v", err)
	}
	inv := collect.HostInventory()
	heartbeat, err := client.Heartbeat(s.AgentID, s.AgentToken, map[string]any{
		"host": inv.Host, "ip_address": inv.IPAddress, "os": inv.OS, "agent_version": version,
		"health": agentHealth(spoolPath, spoolLimits),
	})
	if err != nil {
		log.Printf("heartbeat failed, continuing so telemetry can spool if needed: %v", err)
	} else if heartbeat != nil && heartbeat.CredentialUpdate != nil {
		update := heartbeat.CredentialUpdate
		if strings.TrimSpace(update.AgentToken) != "" && update.CredentialVersion > s.CredentialVersion {
			s.AgentToken = update.AgentToken
			s.CredentialVersion = update.CredentialVersion
			if err := state.Save(statePath, s); err != nil {
				return heartbeatConfig(heartbeat), fmt.Errorf("save rotated credential: %w", err)
			}
			log.Printf("agent credential rotated to version=%d", s.CredentialVersion)
		}
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
			if _, spoolErr := spool.AppendEventsBounded(spoolPath, events, spoolLimits); spoolErr != nil {
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
		executeAndReport(client, s, spoolPath, spoolLimits, task)
	}
	return heartbeatConfig(heartbeat), nil
}

func heartbeatConfig(h *agentapi.HeartbeatResponse) *agentapi.AgentConfig {
	if h == nil {
		return nil
	}
	return &h.Config
}

func agentHealth(spoolPath string, spoolLimits spool.Limits) map[string]any {
	spoolSize := int64(0)
	if info, err := os.Stat(spoolPath); err == nil {
		spoolSize = info.Size()
	}
	spoolSummary, err := spool.Summary(spoolPath, spoolLimits)
	if err != nil {
		spoolSummary = spool.SpoolSummary{Bytes: spoolSize, PressureState: "unknown"}
	}
	return map[string]any{
		"status":            "ok",
		"pid":               os.Getpid(),
		"version":           version,
		"runtime_os":        runtime.GOOS,
		"runtime_arch":      runtime.GOARCH,
		"spool_path":        spoolPath,
		"spool_bytes":       spoolSize,
		"spool":             spoolHealth(spoolSummary),
		"process_tracker":   collect.ProcessTrackerHealth(),
		"task_capabilities": len(tasks.Allowed),
	}
}

func spoolHealth(summary spool.SpoolSummary) map[string]any {
	return map[string]any{
		"bytes":                     summary.Bytes,
		"records":                   summary.Records,
		"pressure_state":            summary.PressureState,
		"accepted_records":          summary.AcceptedRecords,
		"dropped_records":           summary.DroppedRecords,
		"blocked_records":           summary.BlockedRecords,
		"uploaded_records":          summary.UploadedRecords,
		"replayed_records":          summary.ReplayedRecords,
		"retried_records":           summary.RetriedRecords,
		"oldest_record_age_seconds": summary.OldestRecordAgeSeconds,
		"last_successful_upload_at": summary.LastSuccessfulUploadAt,
		"upload_lag_seconds":        summary.UploadLagSeconds,
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

func executeAndReport(client *agentapi.Client, s *state.State, spoolPath string, spoolLimits spool.Limits, task agentapi.Task) {
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
		if _, spoolErr := spool.AppendTaskResultBounded(spoolPath, task.TaskID, status, result, msg, spoolLimits); spoolErr != nil {
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

func defaultInstallDir() string {
	if runtime.GOOS == "windows" {
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			return filepath.Join(programFiles, "Shiori")
		}
		return `C:\Program Files\Shiori`
	}
	return "."
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "Shiori")
		}
		return `C:\ProgramData\Shiori`
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "shiori-agent")
}

func defaultStatePath() string {
	return filepath.Join(defaultDataDir(), "shiori-agent-state.json")
}

func defaultSpoolPath() string {
	return filepath.Join(defaultDataDir(), "spool.jsonl")
}
