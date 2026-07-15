# Shigure Response Toolbox

The Shigure endpoint agent is designed to run as a Windows Service. When installed from an elevated PowerShell prompt with the default `--install-service` path, Windows creates the service without an explicit `obj=` account, so the service runs as `LocalSystem`.

This gives the agent enough local authority to collect investigation evidence after the server queues a task. Under the MVP `read_only_v1` policy, the agent does not execute high-risk or mutating response actions even if they are accidentally dispatched.

## Deploy as LocalSystem

The command and path examples below use the Shigure runtime defaults for new deployments. Shiori names remain available only through explicit legacy compatibility overrides.

```powershell
.\shigure-agent.exe --install-service --server http://192.168.1.93:8765 --enroll-token <token>
sc.exe start ShigureAgent
sc.exe qc ShigureAgent
```

Default Windows install paths:

```text
Binary: C:\Program Files\Shigure\shigure-agent.exe
State:  C:\ProgramData\Shigure\shigure-agent-state.json
Spool:  C:\ProgramData\Shigure\spool.jsonl
```

The service installer may be launched from a temporary deployment directory, but it copies the binary into `C:\Program Files\Shigure` before creating the service.

For a legacy prototype endpoint, pass explicit overrides such as `--service-name ShioriAgent`, `--service-display-name "Shiori Agent"`, `--service-binary-name shiori-agent.exe`, `--install-dir "C:\Program Files\Shiori"`, `--state C:\ProgramData\Shiori\shiori-agent-state.json`, and `--spool C:\ProgramData\Shiori\spool.jsonl`.

Confirm:

```text
SERVICE_START_NAME : LocalSystem
```

Then queue `agent_identity` and confirm the result contains `NT AUTHORITY\SYSTEM`.

## Task catalog

The admin API exposes the catalog at:

```text
GET /api/v1/admin/task-catalog
```

The older compatibility route remains:

```text
GET /api/v1/admin/readonly-scripts
```

## Low-risk collection tasks

- `inventory`
- `agent_identity`
- `process_list`
- `network_connections`
- `service_list`
- `scheduled_tasks`
- `windows_event_logs`
- `file_exists`
- `file_hash`
- `list_directory`

Example:

```json
{
  "tenant_id": "default",
  "agent_id": "<agent-id>",
  "task_type": "agent_identity",
  "args": {}
}
```

## Medium-risk evidence tasks

- `read_file_chunk` — bounded file read, returns base64 and a safe text preview.
- `collect_file` — upload a bounded file to server raw evidence storage.

Example:

```json
{
  "tenant_id": "default",
  "agent_id": "<agent-id>",
  "task_type": "read_file_chunk",
  "requested_by": "analyst@example.test",
  "args": {
    "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "offset": 0,
    "max_bytes": 4096,
    "reason": "triage suspicious PowerShell alert",
    "case_id": "case-123"
  }
}
```

## High-risk response tasks

These are not MVP analyst actions. Under `read_only_v1`, the server records them as `blocked_by_policy` and the endpoint blocks them again before execution if they somehow arrive.

- `quarantine_file`
- `delete_file`
- `kill_process`
- `service_control` (`status`, `start`, `stop`)
- `copy_file`

These prototype implementations are future capability stubs only. Enabling them requires a later policy/RBAC/audit/approval decision.

Example:

```json
{
  "tenant_id": "default",
  "agent_id": "<agent-id>",
  "task_type": "delete_file",
  "args": {
    "path": "C:\\Temp\\bad.exe",
    "confirm_sha256": "<expected sha256>"
  }
}
```

Expected MVP result:

```json
{
  "status": "blocked_by_policy",
  "error": "destructive_task_blocked",
  "result": {
    "policy_version": "read_only_v1",
    "response_mode": "read_only",
    "task_type": "delete_file"
  }
}
```

## Windows native collectors

On Windows, the agent now uses fixed native commands for common inventory tasks:

- `tasklist.exe /fo csv /nh`
- `netstat.exe -ano`
- `sc.exe query state= all`
- `schtasks.exe /query /fo csv /v`

`process_list`, `network_connections`, and `listening_ports` preserve the raw command output and also expose parsed `rows` for downstream UI, reporting, and investigation workflows.

The agent does not expose arbitrary shell execution through these tasks.

## V2 investigation and evidence tasks

Additional explicit-dispatch investigation tasks:

- `process_detail` — return details for a PID. Linux returns `/proc` fields and executable hash when available. Windows returns fixed Win32_Process JSON from PowerShell/CIM.
- `process_tree` — return the target PID plus direct children. Windows returns fixed Win32_Process JSON.
- `autoruns_collect` — collect common persistence locations. Windows includes Run keys, startup folders, services, and scheduled tasks. Linux includes cron/systemd/profile locations.
- `registry_query` — read-only Windows registry query using `reg.exe query`; unsupported on non-Windows endpoints.
- `listening_ports` — return listening TCP ports. Windows uses `netstat.exe -ano -p tcp`; Linux parses `/proc/net/tcp*`.

Evidence upload endpoint used by the agent:

```text
POST /api/v1/agents/{agent_id}/evidence
```

The server-side evidence module validates uploaded file evidence before storage: base64 must decode, declared size must match decoded bytes, and declared SHA-256 must match the decoded content. Raw evidence reference generation is centralized so events, alerts, task results, and agent uploads use one storage seam.

Admin evidence lookup:

```text
GET /api/v1/admin/raw-evidence?raw_ref=<raw-ref>
GET /api/v1/admin/raw-evidence/by-hash/{sha256}
```

Task lifecycle admin endpoints:

```text
POST /api/v1/admin/tasks/{task_id}/cancel
POST /api/v1/admin/tasks/{task_id}/retry
POST /api/v1/admin/tasks/expire-stale
```

Agent heartbeat now reports health metadata including pid, version, runtime OS/arch, spool path/size, and task capability count.

Every telemetry cycle includes one `endpoint_state` internal event so endpoint presence is searchable in the event store even when optional process/network/log collectors are disabled.

## Architecture notes

- Agent task execution is split by locality: dispatch/catalog, file/evidence tasks, process tasks, network tasks, system/persistence tasks, response tasks, command helpers, and Windows parsers.
- Server task catalog metadata is represented as typed task definitions while preserving the public `READONLY_TASK_CATALOG` JSON shape.
- Evidence validation/reference generation is centralized in `open_edr_mdr_agent.api.evidence` instead of being embedded directly in store methods.
