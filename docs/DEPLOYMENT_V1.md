# Intranet V1 Deployment Runbook

This runbook captures the current single-tenant intranet deployment path for the M1 prototype. It intentionally keeps the endpoint-facing shape to one branded Windows agent and a central server with outbound agent polling only.

## Server

1. Create an isolated Python environment and install the project.
2. Set runtime configuration:

```bash
export OPEN_EDR_MDR_DB=/var/lib/open-edr-mdr/open-edr-mdr.sqlite3
export OPEN_EDR_MDR_PROFILE=production
export OPEN_EDR_MDR_ADMIN_TOKEN='<operator-admin-token>'
export OPEN_EDR_MDR_DEV_ENROLLMENT_TOKEN='<initial-enrollment-token>'
export OPEN_EDR_MDR_SERVER_TRUST=system
```

Production mode rejects the built-in `dev-admin-token` / `dev-token` shortcuts and requires an explicit server trust mode. `system` means the agent should use normal operating-system certificate validation; use a CA bundle path when the deployment relies on a private intranet CA.

For local smoke tests only, keep the profile as `dev` or `demo`; those profiles continue to allow HTTP and dev bootstrap credentials.

3. Start the API behind an intranet reverse proxy:

```bash
open-edr-mdr-agent serve --host 127.0.0.1 --port 8080
```

4. Validate server health and UI:

```bash
curl http://127.0.0.1:8080/health
# UI: http://<intranet-host>/ui
```

## Windows agent

The agent communicates outbound to the server. It enrolls once, stores local state, heartbeats for config, uploads telemetry, polls for queued read-only tasks, and uploads task results with raw evidence hashes.

The current binary, service, and Windows path examples still use Shiori compatibility names until the planned Shigure runtime naming migration lands.

```powershell
.\shiori-agent.exe `
  --profile production `
  --server https://edr.internal.example `
  --enroll-token <initial-enrollment-token> `
  --server-trust system `
  --state C:\ProgramData\Shiori\shiori-agent-state.json `
  --spool C:\ProgramData\Shiori\spool.jsonl
```

Install as a Windows Service after validating the command line. The installer copies the service binary to `C:\Program Files\Shiori\shiori-agent.exe` and stores endpoint state/spool files under `C:\ProgramData\Shiori` by default:

```powershell
.\shiori-agent.exe --install-service --profile production --server https://edr.internal.example --enroll-token <initial-enrollment-token> --server-trust system
Start-Service ShioriAgent
sc.exe qc ShioriAgent
```

Uninstall if needed:

```powershell
Stop-Service ShioriAgent
& 'C:\Program Files\Shiori\shiori-agent.exe' --uninstall-service
```

## Analyst validation checklist

- Enrolled endpoint appears in `/api/v1/admin/agents` and `/ui`.
- Heartbeat returns tenant config and `tasks_pending` state.
- Events appear in `/api/v1/admin/events` and can be filtered by host, process, user, remote IP, domain, indicator, or SHA256.
- Alerts appear for encoded PowerShell, suspicious script networking, Windows service/task event logs, and known IOC matches.
- Read-only tasks can be queued only from the catalog; malformed args are rejected server-side.
- Task results include `raw_ref` and `raw_hash` and can be fetched through raw evidence APIs.
- Cases can attach alerts, events, task results, and raw evidence references.
- Saved hunts can be created, updated, disabled, executed, and reviewed.

## V1 safety boundaries

Do not add or enable destructive response actions in V1: no host isolation, kill process, file delete/write, registry write/delete, reboot, or logoff. Tasking remains read-only investigation and evidence collection.
