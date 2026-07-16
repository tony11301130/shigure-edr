# Shigure Prototype P0

Prototype P0 is the fastest useful demo path for Shigure. It is not the RC0
commercial release gate.

The goal is a single Windows endpoint talking to one Shigure server with the
Web UI showing endpoint status, telemetry, alerts, read-only tasks, and evidence
flow.

Demo presentation material is in `docs/prototype-p0-demo/`.

## Scope

Prototype P0 demonstrates:

- Shigure API and Web UI on an intranet-reachable dev server.
- One enrolled Windows endpoint running `ShigureAgent`.
- Endpoint online/offline status and heartbeat health.
- Process/event telemetry already validated in the Windows lab.
- Windows Event Log and Windows process trace evidence from RC0 validation.
- Read-only task queueing and evidence upload.
- Raw evidence references and hashes.

Prototype P0 explicitly does not claim:

- Production readiness.
- Multi-tenant hardening.
- Long-term retention.
- ClickHouse-backed telemetry validation.
- Destructive response actions.
- Customer production deployment support.

## Current Prototype Profile

The prototype profile is intentionally local and reversible:

- Server profile: `dev`
- Control-plane store: SQLite
- Telemetry projection: SQLite
- Raw evidence store: local object store
- Endpoint count: one Windows lab endpoint
- Storage/load/retention: not validated for production

The RC0 release gate remains blocked until ClickHouse or an approved equivalent
storage lab is available.

## Scripts

Start a local prototype server:

```bash
scripts/prototype_start.sh
```

Validate the currently running prototype:

```bash
scripts/prototype_validate.sh
```

Switch the lab config to quiet mode so the Windows endpoint keeps heartbeating
but does not keep growing the dev SQLite telemetry store:

```bash
scripts/prototype_config_quiet.sh
```

Switch back to demo mode when you want fresh endpoint process snapshots during a
demo:

```bash
scripts/prototype_config_demo.sh
```

Stop a server started by `scripts/prototype_start.sh`:

```bash
scripts/prototype_stop.sh
```

These scripts use:

- `SHIGURE_PROTOTYPE_URL`, default `http://127.0.0.1:8765`
- `SHIGURE_PROTOTYPE_ADMIN_TOKEN`, default `dev-admin-token`
- `SHIGURE_PROTOTYPE_TENANT`, default `default`
- `SHIGURE_PROTOTYPE_DB`, default `.scratch/prototype-p0/prototype.sqlite3`

Do not write real credentials into these scripts or this document. Pass them by
environment variable when needed.

## Demo Flow

Use this as the operator script:

1. Start or confirm the API/UI server.

   ```bash
   scripts/prototype_validate.sh
   ```

2. Open the UI:

   ```text
   http://<server-ip>:8765/ui
   ```

3. Confirm the Windows endpoint is online.

   Expected lab endpoint:

   ```text
   DESKTOP-29R9I3A
   ```

4. Show summary counts:

   - Agents
   - Events
   - Alerts
   - Tasks
   - Raw evidence

5. Show endpoint health:

   - `ShigureAgent` status online
   - spool pressure
   - collector health
   - Windows Event Log disabled unless intentionally enabled
   - Windows process trace disabled unless intentionally enabled

6. Show telemetry and alert history.

   The RC0 lab evidence includes:

   - Windows Event Log subscription live ingest.
   - Windows process trace live ingest.
   - read-only task and evidence flow.

7. Queue only read-only tasks from the task catalog.

   Good demo candidates:

   - file exists
   - file hash
   - Windows event logs with bounded arguments

8. Show raw evidence references and hashes after a task completes.

9. End the demo by switching to quiet mode:

   ```bash
   scripts/prototype_config_quiet.sh
   ```

## Runtime Hygiene

For short demos, demo mode is useful:

```bash
scripts/prototype_config_demo.sh
```

For idle time, quiet mode is safer:

```bash
scripts/prototype_config_quiet.sh
```

Quiet mode keeps heartbeat/task polling active but disables routine process
snapshot collection. This prevents the dev SQLite DB and local raw evidence
store from growing while nobody is watching the demo.

If the prototype will not be used again soon, also stop the Windows lab service
manually:

```powershell
Stop-Service ShigureAgent
```

Do not leave Event Log or process trace collectors enabled after a demo unless
you are actively collecting validation evidence.

## Known Limits

- SQLite telemetry is fine for the demo but not a production storage answer.
- The current Web UI is an internal MVP console, not a polished product console.
- Endpoint coverage is a single lab Windows machine.
- The process trace producer used for the RC0 gate is Windows WMI process trace
  surfaced through the existing `ETWProcessCollector` boundary, not a pure ETW
  session consumer.
- ClickHouse storage/load/retention remains the real RC0 release blocker.
- #20-#26 remain product backlog and should stay blocked until #18 is resolved
  or explicitly descoped.

## Pass Criteria

Prototype P0 is healthy when:

- `scripts/prototype_validate.sh` exits successfully.
- The UI loads.
- At least one Windows endpoint is online.
- Read-only task flow works.
- Evidence refs and hashes are visible.
- Event Log and process trace collectors are disabled after the demo.
- The operator can explain that storage retention is not production validated.
