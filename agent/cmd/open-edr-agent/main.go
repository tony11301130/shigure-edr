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

func main() {
	server := flag.String("server", "http://127.0.0.1:8000", "backend server URL")
	enrollToken := flag.String("enroll-token", "dev-token", "tenant enrollment token")
	statePath := flag.String("state", defaultStatePath(), "agent state path")
	spoolPath := flag.String("spool", defaultSpoolPath(), "offline spool JSONL path")
	once := flag.Bool("once", false, "run one heartbeat/telemetry/task cycle then exit")
	demoEvent := flag.Bool("demo-suspicious-event", false, "send a demo suspicious PowerShell event for detection smoke test")
	collectSnapshot := flag.Bool("collect-snapshot", true, "send limited process/network telemetry snapshot each cycle")
	maxSnapshotEvents := flag.Int("max-snapshot-events", 25, "maximum snapshot telemetry events per cycle")
	interval := flag.Duration("interval", 15*time.Second, "loop interval")
	flag.Parse()

	client := agentapi.New(*server)
	agentState, err := state.Load(*statePath)
	if err != nil {
		log.Printf("state not found, enrolling: %v", err)
		agentState, err = enroll(client, *enrollToken)
		if err != nil {
			log.Fatalf("enrollment failed: %v", err)
		}
		if err := state.Save(*statePath, agentState); err != nil {
			log.Fatalf("save state failed: %v", err)
		}
		log.Printf("enrolled agent_id=%s tenant_id=%s", agentState.AgentID, agentState.TenantID)
	}

	for {
		if err := runCycle(client, agentState, *spoolPath, *demoEvent, *collectSnapshot, *maxSnapshotEvents); err != nil {
			log.Printf("cycle error: %v", err)
		}
		if *once {
			return
		}
		time.Sleep(*interval)
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

func runCycle(client *agentapi.Client, s *state.State, spoolPath string, sendDemo bool, collectSnapshot bool, maxSnapshotEvents int) error {
	if err := spool.Flush(spoolPath, client, s); err != nil {
		log.Printf("spool flush failed: %v", err)
	}
	inv := collect.HostInventory()
	_, err := client.Heartbeat(s.AgentID, s.AgentToken, map[string]any{
		"host": inv.Host, "ip_address": inv.IPAddress, "os": inv.OS, "agent_version": version,
		"health": map[string]any{"status": "ok"},
	})
	if err != nil {
		log.Printf("heartbeat failed, continuing so telemetry can spool if needed: %v", err)
	}

	events := []agentapi.NormalizedEvent{}
	if collectSnapshot {
		events = append(events, collect.SnapshotTelemetry(s.TenantID, maxSnapshotEvents)...)
	}
	if sendDemo {
		events = append(events, collect.DemoSuspiciousPowerShellEvent(s.TenantID))
	}
	if len(events) > 0 {
		if err := client.IngestEvents(s.AgentID, s.AgentToken, events); err != nil {
			if spoolErr := spool.AppendEvents(spoolPath, events); spoolErr != nil {
				return fmt.Errorf("ingest events: %w; spool failed: %v", err, spoolErr)
			}
			log.Printf("ingest failed, events spooled: %v", err)
		}
	}

	claimed, err := client.ClaimTasks(s.AgentID, s.AgentToken, 5)
	if err != nil {
		return fmt.Errorf("claim tasks: %w", err)
	}
	for _, task := range claimed {
		executeAndReport(client, s, spoolPath, task)
	}
	return nil
}

func executeAndReport(client *agentapi.Client, s *state.State, spoolPath string, task agentapi.Task) {
	result, err := tasks.Execute(task.TaskType, task.Args)
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

func defaultStatePath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "open-edr-mdr-agent", "agent-state.json")
}

func defaultSpoolPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "open-edr-mdr-agent", "spool.jsonl")
}
