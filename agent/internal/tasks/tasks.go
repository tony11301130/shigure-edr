package tasks

import (
	"errors"
	"os"
	"time"

	"open-edr-mdr-agent/agent/internal/collect"
)

var ErrBlocked = errors.New("blocked_by_policy")

const PolicyVersion = "read_only_v1"

type TaskMeta struct {
	Risk        string
	Destructive bool
	Mutating    bool
}

var Catalog = map[string]TaskMeta{
	"inventory": {Risk: "low"}, "process_list": {Risk: "low"}, "process_detail": {Risk: "low"}, "process_tree": {Risk: "low"}, "network_connections": {Risk: "low"}, "service_list": {Risk: "low"}, "scheduled_tasks": {Risk: "low"}, "windows_event_logs": {Risk: "low"}, "file_exists": {Risk: "low"}, "file_hash": {Risk: "low"},
	"agent_identity": {Risk: "low"}, "autoruns_collect": {Risk: "low"}, "registry_query": {Risk: "low"}, "listening_ports": {Risk: "low"}, "list_directory": {Risk: "low"}, "read_file_chunk": {Risk: "medium"}, "copy_file": {Risk: "medium", Mutating: true}, "collect_file": {Risk: "medium"},
	"quarantine_file": {Risk: "high", Destructive: true}, "delete_file": {Risk: "high", Destructive: true}, "kill_process": {Risk: "high", Destructive: true}, "service_control": {Risk: "high", Destructive: true},
}

var Allowed = func() map[string]bool {
	out := map[string]bool{}
	for k, meta := range Catalog {
		if meta.Destructive || meta.Mutating {
			continue
		}
		out[k] = true
	}
	return out
}()

func Execute(taskType string, args map[string]any) (map[string]any, error) {
	meta, ok := Catalog[taskType]
	if !ok {
		return blockedResult(taskType, TaskMeta{Risk: "unknown"}, "task_not_allowlisted"), ErrBlocked
	}
	if meta.Destructive {
		return blockedResult(taskType, meta, "destructive_task_blocked"), ErrBlocked
	}
	if meta.Mutating {
		return blockedResult(taskType, meta, "mutating_task_blocked"), ErrBlocked
	}
	result, err := executeAllowed(taskType, args)
	if result == nil {
		result = map[string]any{}
	}
	result["task_type"] = taskType
	result["risk"] = meta.Risk
	result["destructive"] = meta.Destructive
	result["policy_version"] = PolicyVersion
	result["response_mode"] = "read_only"
	result["executed_at"] = time.Now().UTC().Format(time.RFC3339)
	return result, err
}

func blockedResult(taskType string, meta TaskMeta, reason string) map[string]any {
	return map[string]any{
		"blocked":        true,
		"reason":         reason,
		"task_type":      taskType,
		"risk":           meta.Risk,
		"destructive":    meta.Destructive,
		"policy_version": PolicyVersion,
		"response_mode":  "read_only",
		"executed_at":    time.Now().UTC().Format(time.RFC3339),
	}
}

func executeAllowed(taskType string, args map[string]any) (map[string]any, error) {
	switch taskType {
	case "inventory":
		return map[string]any{"inventory": collect.HostInventory()}, nil
	case "process_list":
		return map[string]any{"processes": processList()}, nil
	case "process_detail":
		return processDetail(args)
	case "process_tree":
		return processTree(args)
	case "network_connections":
		return map[string]any{"connections": networkConnections()}, nil
	case "listening_ports":
		return listeningPorts()
	case "service_list":
		return map[string]any{"services": serviceList()}, nil
	case "scheduled_tasks":
		return map[string]any{"scheduled_tasks": scheduledTasks()}, nil
	case "windows_event_logs":
		return windowsEventLogs(args)
	case "file_exists":
		path, _ := args["path"].(string)
		if path == "" {
			return nil, errors.New("path required")
		}
		_, err := os.Stat(path)
		return map[string]any{"path": path, "exists": err == nil}, nil
	case "file_hash":
		path, _ := args["path"].(string)
		if path == "" {
			return nil, errors.New("path required")
		}
		h, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		return map[string]any{"path": path, "sha256": h}, nil
	case "agent_identity":
		return agentIdentity()
	case "autoruns_collect":
		return autorunsCollect()
	case "registry_query":
		return registryQuery(args)
	case "list_directory":
		return listDirectory(args)
	case "read_file_chunk":
		return readFileChunk(args)
	case "copy_file":
		return copyFileTask(args)
	case "collect_file":
		return collectFile(args)
	case "quarantine_file":
		return quarantineFile(args)
	case "delete_file":
		return deleteFile(args)
	case "kill_process":
		return killProcess(args)
	case "service_control":
		return serviceControl(args)
	default:
		return nil, ErrBlocked
	}
}
