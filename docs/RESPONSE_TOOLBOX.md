# Response Toolbox

The endpoint agent is designed to run as a Windows Service. When installed from an elevated PowerShell prompt with the default `--install-service` path, Windows creates the service without an explicit `obj=` account, so the service runs as `LocalSystem`.

This gives the agent enough local authority to perform EDR response work after the server explicitly queues a task. The agent does not autonomously execute high-risk response actions.

## Deploy as LocalSystem

```powershell
.\open-edr-agent.exe --install-service --server http://192.168.1.93:8765 --enroll-token <token>
sc.exe start OpenEDRMDRAgent
sc.exe qc OpenEDRMDRAgent
```

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
- `copy_file` — local endpoint copy for evidence preservation.

Example:

```json
{
  "tenant_id": "default",
  "agent_id": "<agent-id>",
  "task_type": "read_file_chunk",
  "args": {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "offset": 0, "max_bytes": 4096}
}
```

## High-risk response tasks

These are only executed when explicitly queued by an admin/API caller. They are marked `risk=high`, `destructive=true`, and `requires_explicit_dispatch=true` in the catalog and task result metadata.

- `quarantine_file`
- `delete_file`
- `kill_process`
- `service_control` (`status`, `start`, `stop`)

`delete_file` requires a `confirm_sha256` argument. The agent hashes the target file immediately before deletion and blocks the task if the hash does not match.

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

## Windows native collectors

On Windows, the agent now uses fixed native commands for common inventory tasks:

- `tasklist.exe /fo csv /nh`
- `netstat.exe -ano`
- `sc.exe query state= all`
- `schtasks.exe /query /fo csv /v`

The agent does not expose arbitrary shell execution through these tasks.
