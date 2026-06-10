# Open EDR MDR Agent Progress

Last updated: 2026-06-10 UTC

## Current objective

Build the M0 intranet-first, single-agent Windows EDR vertical slice while keeping the schema/API multi-tenant-ready.

## Decisions locked

| Decision | Status |
|---|---|
| Customer installs one branded agent, not multiple third-party agents | Decided |
| V1 OS target | Windows-only first |
| Agent language | Go, with small C/C++ shims only if needed |
| Detection placement | Server-side first; agent lightweight tagging only |
| Upload mode | Hybrid batch + high-value flush + offline spool |
| Task delivery | Agent polling `/tasks/claim`, no inbound endpoint port |
| Platform scale target | 10,000 active Windows endpoints across tenants |
| Multi-tenancy | Required from day one in schema/API |
| Storage model | Shared storage + mandatory `tenant_id`; future dedicated partitions |
| Enrollment | Tenant-scoped token + agent-generated key pair/credential |
| Communication auth | HTTPS + agent credential/signed requests first; mTLS future profile |
| Build sequence | Intranet single-tenant vertical slice first, multi-tenant-ready always |

## Milestones

| ID | Milestone | Status | Notes |
|---|---|---|---|
| M0.0 | Repo/version control/progress tracking | Done | Git initialized on `main`; progress log created |
| M0.1 | Backend API + SQLite store | Done | FastAPI + SQLite: enrollment, heartbeat, ingest, detection alert insert, task claim/result, query |
| M0.2 | Go agent skeleton | Done | Go loop supports enrollment, heartbeat, demo telemetry upload, offline spool, task polling |
| M0.3 | Read-only task execution | Partial | inventory, process_list, network_connections, service_list, scheduled_tasks, file_exists, file_hash implemented; Windows-native API depth pending |
| M0.4 | Minimal telemetry collectors | Partial | Cross-platform snapshot collector sends process command line/parent PID and basic network snapshot; Windows ETW/Event Log collectors pending |
| M0.5 | Server-side detection | Done for M0 | Built-in tests for encoded PowerShell, script+network, service/task, IOC, and agent telemetry gap |
| M0.6 | MDR query/evidence workflow | Partial | Admin APIs list agents/events/alerts/tasks; event filters include host/type/process/remote_ip/domain/indicator |
| M0.7 | Local integration smoke test | Done | `scripts/m0_smoke.sh` validates backend + Go agent E2E |
| M1.0 | Agent config/policy update | Done | Tenant config API, heartbeat config response, Go agent runtime config apply |
| M1.1 | Raw evidence/schema hardening | Done | Normalized events/alerts include raw_ref/raw_hash; SQLite raw_evidence store/API added |
| M1.2 | Detection rule loader | Done | YAML rule loader with equals/contains/regex conditions; backend can load/reload custom rules |
| M1.3 | MDR case/evidence workflow | Done | Cases can be created from alerts, updated, and linked to event/task/raw evidence refs |
| M1.4 | Load simulator | Done | `scripts/load_sim.py` simulates enrollment/heartbeat/ingest/detection; small local run validated |
| M1.5 | Platform telemetry collector split | Done | OS-specific collector interface; Linux /proc implementation; Windows PowerShell/CIM read-only snapshot path cross-builds |
| M1.6 | Windows service install skeleton | Done | Agent supports `--install-service` / `--uninstall-service`; Windows cross-build passes |
| M1.7 | MDR investigation APIs | Done | Endpoint context, indicator hunt, and process-chain APIs over current event/alert/task store |
| M1.8 | SQLite schema migration guard | Done | Startup adds new raw_ref/raw_hash columns to legacy M0 tables; regression test added |
| M1.9 | Windows Event Log telemetry snapshot | Done | Read-only Get-WinEvent collector for PowerShell, auth, service install, scheduled task operational logs |
| M1.10 | Windows Event Log detections | Done | Built-in detections for suspicious PowerShell script blocks, service install, and scheduled task changes |
| M1.11 | Collector policy gates | Done | Tenant config can independently enable/disable process, network, and Windows Event Log collectors |
| M1.12 | Windows Event Log evidence task | Done | Read-only `windows_event_logs` task with allowlisted profiles for PowerShell/auth/service/task logs |
| M1.13 | Task result evidence hashing | Done | Completed task results now get raw_ref/raw_hash and are stored in raw_evidence |
| M1.14 | Alert-to-case auto evidence | Done | Creating a case from an alert auto-attaches the alert and alert raw evidence refs |
| M1.15 | Tenant operational summary API | Done | Admin summary endpoint reports counts and status/severity distributions for agents/events/alerts/cases/tasks/evidence |
| M1.16 | Windows Service runtime entrypoint | Done | Agent now detects Windows Service context and runs via SCM service handler with stop/shutdown handling |
| M1.17 | Intranet EDR/MDR goal baseline | Done | Formalized intranet-first V1 goal, Fidelis parity, threat hunting, server tasking, and minimal UI scope |
| M1.18 | Minimal intranet UI | Done | FastAPI-served single-page UI for summary, agents, alerts, cases, tasks, and indicator hunt |
| M1.19 | Fidelis exact lookup parity | Done | Added tenant-scoped `get_alert_by_id` and `get_exact_event` admin APIs |
| M1.20 | Read-only script catalog parity | Done | Added `list_readonly_scripts` catalog and server-side allowlist for task creation |
| M1.21 | Fidelis query/context parity | Done | Added count/related events plus behavior-context and network-context investigation APIs |
| M1.22 | Saved hunt workflow | Done | Saved hunts can be created, listed, executed, and reviewed with run results |
| M1.23 | Read-only task argument validation | Done | Server validates catalog args before queueing tasks, including required paths and allowlisted Windows Event Log profiles |
| M1.24 | Saved hunt lifecycle controls | Done | Saved hunts can be updated/disabled, filtered by enabled state, and disabled hunts cannot be run |
| M1.25 | Task timeout maintenance | Done | Admin maintenance endpoint marks stale claimed tasks as timed_out with explicit timeout error |
| M1.26 | Raw evidence index API | Done | Analysts can list tenant-scoped raw evidence refs by kind before fetching exact payloads |
| M1.27 | Exact agent lookup API | Done | Admin API can fetch a single tenant-scoped agent record by agent_id |
| M1.28 | Exact task lookup API | Done | Admin API can fetch a single tenant-scoped task by task_id for result/detail workflows |
| M1.29 | Event query user/hash dimensions | Done | Event storage/query supports user and SHA256 hash filters with migration guard |
| M1.30 | UI hunt/evidence panels | Done | Minimal intranet UI now surfaces saved hunts and raw evidence references alongside cases/tasks |

## Work log

- 2026-06-10: Created initial project skeleton, spec, schemas, local JSON provider, CLI, sample smoke test.
- 2026-06-10: Updated spec through grill decisions: single agent, Windows-first, Go agent, server-side detection, hybrid upload, polling tasks, 10k platform multi-tenant target, intranet-first development.
- 2026-06-10: Initialized git repository and committed initial spec/prototype.
- 2026-06-10: Implemented M0.1 backend API with SQLite store and minimal server-side detection. Added integration test for enroll → heartbeat → ingest → alert → task → result.
- 2026-06-10: Implemented Go agent skeleton with enrollment, heartbeat, demo suspicious event upload, polling task claim, and allowlisted read-only task execution. Local E2E against FastAPI backend succeeded: alert generated and `process_list` task completed.
- 2026-06-10: Added agent JSONL offline spool for event batches and task results; verified E2E still succeeds with `file_exists` task.
- 2026-06-10: Added limited process/network telemetry snapshot collector and wired it into the agent loop. Verified Go tests, Python tests, build, and live upload against local backend.
- 2026-06-10: Added MDR query filters for events and task list endpoint; tests cover indicator hunt, process query, and task result evidence.
- 2026-06-10: Expanded read-only task catalog with `service_list` and `scheduled_tasks` safe collectors.
- 2026-06-10: Added detection tests and built-in rules for encoded PowerShell, script interpreter network connection, service/task persistence command, and safe smoke-test IOC match.
- 2026-06-10: Added agent health/telemetry gap detection maintenance API and test.
- 2026-06-10: Added automated M0 smoke script. Latest run: 11 events ingested, suspicious PowerShell alert generated, file_exists task succeeded.
- 2026-06-10: Added dev admin token protection for admin/MDR APIs; updated tests and smoke script.
- 2026-06-10: Added `open-edr-mdr-agent serve` CLI command and README quick-start notes.
- 2026-06-10: Added cross-tenant task creation guard; tests verify tenant mismatch is rejected.
- 2026-06-10: Added tenant agent config API and heartbeat config sync; Go agent applies task polling/snapshot/demo settings from backend. Tests and smoke pass.
- 2026-06-10: Added raw evidence hashing/reference fields and SQLite raw_evidence API. Events/alerts now carry `raw_ref` and `raw_hash`; tests and smoke pass.
- 2026-06-10: Added YAML detection rule loader and custom rule execution path. Example rule file added; tests and smoke pass.
- 2026-06-10: Added MDR case/evidence SQLite tables and APIs. Tests cover alert-to-case, evidence attachment, and case update workflow.
- 2026-06-10: Added load simulator and docs. Local validation: 25 agents, 50 events, 25 alerts in ~0.7s.
- 2026-06-10: Split telemetry collector into OS-specific files. Added Windows process/network snapshot collector using fixed read-only PowerShell/CIM commands as interim path before ETW/API collectors. `GOOS=windows GOARCH=amd64 go build` passes.
- 2026-06-10: Added Windows service install/uninstall skeleton to keep endpoint deployment as one branded agent service. `go test ./...` and Windows cross-build pass.
- 2026-06-10: Added MDR investigation APIs for endpoint context, indicator hunt, and process-chain lookup. `pytest`, Go tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added lightweight SQLite migration guard for new event/alert raw evidence columns so legacy M0 DBs continue working.
- 2026-06-10: Added Windows Event Log snapshot collector using fixed read-only Get-WinEvent queries for PowerShell 4103/4104, Security 4624/4625/4648, service install 7045, and Task Scheduler operational events. `pytest`, Go tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added built-in server-side detections for Windows Event Log telemetry: suspicious PowerShell script block content, service installation, and scheduled task changes. Tests/smoke pass.
- 2026-06-10: Added per-collector policy gates in tenant config and Go agent runtime apply path. Process, network, and Windows Event Log collectors can be toggled independently. Tests/smoke pass.
- 2026-06-10: Added read-only `windows_event_logs` task with fixed allowlisted profiles (`powershell`, `auth`, `service`, `task`) and max event clamp. Tests/smoke pass.
- 2026-06-10: Added raw evidence hashing/references for completed task results so MDR evidence can be traced and attached to cases. Tests/smoke pass.
- 2026-06-10: Creating a case from an alert now automatically attaches the alert and alert raw evidence as case evidence. Tests/smoke pass.
- 2026-06-10: Added `/api/v1/admin/summary` with tenant-scoped operational counts and status/severity distributions. Tests/smoke pass.
- 2026-06-10: Added real Windows Service runtime entrypoint using `golang.org/x/sys/windows/svc`; console mode still works. Service stop/shutdown requests signal the agent loop to exit cleanly. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Formalized `GOAL.md`: intranet-first EDR/MDR V1, one Windows agent, central server, reverse-proxy-friendly queued jobs, Fidelis API parity, threat hunting, and minimal UI. Multi-tenant expansion remains future-safe through tenant-aware schema.
- 2026-06-10: Added minimal FastAPI-served intranet UI at `/ui` with dashboard summary, agents, alerts, cases, tasks, and indicator hunt. Tests/smoke pass.
- 2026-06-10: Added Fidelis parity exact lookup APIs for alert ID and event ID with tenant scoping. Tests/smoke pass.
- 2026-06-10: Added read-only task/script catalog API and server-side task allowlist enforcement to match Fidelis `list_readonly_scripts` / safe `run_readonly_script` workflow. Tests/smoke pass.
- 2026-06-10: Added Fidelis parity query/context APIs: event count, related events, behavior context, and network context. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added saved hunt workflow for threat hunting: create/list hunts, execute against events/alerts, and persist hunt run results. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added server-side read-only task argument validation so unsafe/malformed task requests are rejected before endpoints claim them. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added saved hunt lifecycle controls: patch/update hunts, filter enabled hunts, and block disabled hunt execution. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added task timeout maintenance so claimed tasks that exceed their timeout can be marked `timed_out` server-side. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added raw evidence index API with tenant and kind filters so analysts can browse evidence references without pulling payloads. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added tenant-scoped exact agent lookup API for endpoint detail workflows. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added tenant-scoped exact task lookup API for task detail/result workflows. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added user and SHA256 event query dimensions plus migration guard for legacy SQLite event tables. Tests, Windows cross-build, and smoke pass.
- 2026-06-10: Added saved hunt and raw evidence reference panels to the minimal intranet UI. Tests, Windows cross-build, and smoke pass.
