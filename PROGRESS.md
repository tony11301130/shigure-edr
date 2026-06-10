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
| M0.7 | Local integration smoke test | Pending | one simulated/real agent end-to-end |

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
