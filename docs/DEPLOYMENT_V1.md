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
.\shiori-agent.exe --install-service --config C:\ProgramData\Shiori\shiori-agent-config.json
Start-Service ShioriAgent
sc.exe qc ShioriAgent
```

The generated deployment package copies `shiori-agent-config.json` into `C:\ProgramData\Shiori` and installs the service with `--config`; the service command line should not contain the enrollment token. After the first successful enrollment, the agent removes `enrollment_token` from the installed config file so restart/authentication uses only the state file's per-agent credential. Direct `--enroll-token` startup remains available for dev/demo/manual diagnostics, but production service installs should prefer config-file bootstrap.

Uninstall if needed:

```powershell
Stop-Service ShioriAgent
& 'C:\Program Files\Shiori\shiori-agent.exe' --uninstall-service
```

## Agent credential lifecycle

- Enrollment tokens are tenant-scoped bootstrap material. They are used only by `/api/v1/enroll`.
- After enrollment, the server returns a per-agent credential and a credential version. The agent stores these in `C:\ProgramData\Shiori\shiori-agent-state.json`.
- Heartbeat, telemetry upload, task claim/result upload, and evidence upload authenticate with the per-agent credential, not the enrollment token.
- Admins can schedule an agent credential rotation when routine rotation or suspected exposure requires it. The rotation API records the next credential version without returning the new secret; the agent receives the new credential on its next successful heartbeat, persists it to local state, and uses it for subsequent heartbeat, telemetry, task, and evidence calls.
- Admins can revoke an agent credential for retired or compromised endpoints. Revoked agents cannot heartbeat, upload events, claim tasks, or upload evidence.
- If local state is lost or corrupt, recover by revoking the old agent credential, placing a fresh short-lived or max-use enrollment token into the agent config, and enrolling the endpoint again. Do not restore the originally used bootstrap token.
- Credential lifecycle events distinguish `enrolled`, `authenticated`, `rotation_scheduled`, `rotated`, and `revoked` for operator audit and troubleshooting.

## Bounded local spool

- The local spool is bounded by `spool_max_bytes` and `spool_max_records` in the agent config. The current deployment package defaults to 50 MiB and 10,000 records.
- When the spool exceeds either limit, the agent drops the oldest queued records first and keeps newer telemetry or task results. This favors recent investigation context during long outages.
- The agent persists spool counters next to the JSONL spool and reports them in heartbeat health under `spool`: queued bytes/records, pressure state, accepted records, dropped records, blocked records, uploaded records, replayed records, retried records, oldest queued record age, last successful upload time, and upload lag.
- Operators should treat `pressure_state=pressure` or increasing `dropped_records` as data-loss risk: restore backend connectivity, validate endpoint disk health, and consider collecting targeted evidence from the endpoint after recovery.
- Dropped records are not silently recoverable from the agent spool. Alerts, cases, and evidence packages should mention the telemetry gap when spool pressure occurred during the investigated time window.

## Analyst validation checklist

- Enrolled endpoint appears in `/api/v1/admin/agents` and `/ui`.
- Heartbeat returns tenant config and `tasks_pending` state.
- Events appear in `/api/v1/admin/events` and can be filtered by host, process, user, remote IP, domain, indicator, or SHA256.
- Alerts appear for encoded PowerShell, suspicious script networking, Windows service/task event logs, and known IOC matches.
- Read-only tasks can be queued only from the catalog; malformed args are rejected server-side.
- Unknown, destructive, explicit-dispatch response, and local copy/staging tasks are recorded as `blocked_by_policy` and are not dispatched under `read_only_v1`.
- Evidence collection tasks require explicit byte limits, reason, and case context.
- Task results include policy metadata plus `raw_ref` and `raw_hash` and can be fetched through raw evidence APIs.
- Cases can attach alerts, events, task results, and raw evidence references.
- Saved hunts can be created, updated, disabled, executed, and reviewed.

## V1 safety boundaries

Do not add or enable destructive response actions in V1: no host isolation, kill process, file delete/write, registry write/delete, service start/stop, reboot, or logoff. Tasking remains read-only investigation and bounded evidence collection. See `docs/adr/0002-read-only-response-boundary.md`.
