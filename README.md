# Open EDR MDR Agent

Prototype project for building an in-house EDR + MDR endpoint layer from open-source sensors.

The first goal is **Fidelis Endpoint tool-kit parity**, not a kernel-level EDR driver.

## Target interface

This project exposes a Fidelis-like provider contract:

- `list_alerts()`
- `get_alert_by_id(alert_id)`
- `get_endpoint_context(hostname/ip)`
- `query_events(...)`
- `trace_process_chain(...)`
- `hunt_indicator(indicator)`
- `list_readonly_scripts()`
- `run_readonly_script(helper, host, ...)`

Your existing MDR can depend on this interface while the backend source changes from Fidelis to open-source sensors.

## Sensor fusion plan

| Source | Role | Fidelis-like capability |
|---|---|---|
| Wazuh | alert source / log collection | `list_alerts`, `get_alert_by_id` |
| Sysmon | Windows behavior telemetry | process, network, DNS, file, registry events |
| osquery / Fleet | endpoint state query | inventory, processes, services, users, startup items |
| Velociraptor | evidence/artifact collection | read-only scripts, file/hash/autoruns/event logs |
| Falco / Tetragon | Linux/container runtime | process/network/syscall/container behavior |

## Current status

This is an initial runnable prototype:

- normalized event schema
- Fidelis-like provider interface
- composite provider
- local JSONL provider for smoke tests
- normalizers for Sysmon/Wazuh/Falco-style records
- CLI commands that mimic MDR tools

It does **not** yet connect to live Wazuh/Fleet/Velociraptor APIs. Those adapters are the next step.

## Quick start

```bash
cd /opt/open-edr-mdr-agent
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
open-edr-mdr-agent init-sample-data
open-edr-mdr-agent alerts
open-edr-mdr-agent endpoint-context --host POS01
open-edr-mdr-agent query-events --host POS01
open-edr-mdr-agent trace-process-chain --host POS01 --process-id 4242
open-edr-mdr-agent hunt powershell
```

Run the M0 backend:

```bash
open-edr-mdr-agent serve --host 127.0.0.1 --port 8765 --db /tmp/open-edr-mdr.sqlite3
```

Run the automated M0 backend+agent smoke test:

```bash
scripts/m0_smoke.sh
```

Build the Windows agent and install it as the single branded endpoint service:

```powershell
# Cross-build from Linux dev host
GOOS=windows GOARCH=amd64 go build -o open-edr-agent.exe ./agent/cmd/open-edr-agent

# On Windows as Administrator
.\open-edr-agent.exe --install-service --server https://edr.example.local --enroll-token <tenant-token>
sc.exe start OpenEDRMDRAgent

# The agent binary detects Windows Service context and runs through the Service Control Manager.
# Running the same binary from a console keeps the foreground loop behavior for diagnostics.

# Remove service if needed
.\open-edr-agent.exe --uninstall-service
```

If you do not want a venv, you can also run with `PYTHONPATH=.`:

```bash
cd /opt/open-edr-mdr-agent
PYTHONPATH=. python3 -m open_edr_mdr_agent.cli init-sample-data
PYTHONPATH=. python3 -m open_edr_mdr_agent.cli alerts
```

## Safety model

Initial scope is read-only:

- collect telemetry
- normalize events
- generate alerts
- support analyst investigation
- collect read-only evidence

High-impact response actions such as isolation, process kill, file delete, or registry changes should be added only after:

1. explicit approval workflow
2. tenant-scoped authorization
3. tamper-resistant audit log
4. rollback / safety testing

## Next adapters

- `WazuhProvider`: consume Wazuh alerts API or `alerts.json`
- `FleetOsqueryProvider`: call Fleet API / scheduled query results
- `VelociraptorProvider`: call Velociraptor API and artifact collections
- `SysmonProvider`: read Windows Event Forwarding / Wazuh / OpenSearch normalized Sysmon events
- `FalcoTetragonProvider`: consume JSON alerts/events from Linux/Kubernetes runtime sensors
