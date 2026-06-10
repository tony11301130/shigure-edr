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
| M0.2 | Go agent skeleton | Pending | service-ready loop, config, enrollment, heartbeat, upload, task polling |
| M0.3 | Read-only task execution | Pending | inventory, process list, net connections, services, scheduled tasks, file exists/hash |
| M0.4 | Minimal telemetry collectors | Pending | process command line, parent PID, network, DNS/event-log hooks where available |
| M0.5 | Server-side detection | Pending | suspicious PowerShell, script+network, service/task, IOC, telemetry gap |
| M0.6 | MDR query/evidence workflow | Pending | recent events, alerts, task result evidence |
| M0.7 | Local integration smoke test | Pending | one simulated/real agent end-to-end |

## Work log

- 2026-06-10: Created initial project skeleton, spec, schemas, local JSON provider, CLI, sample smoke test.
- 2026-06-10: Updated spec through grill decisions: single agent, Windows-first, Go agent, server-side detection, hybrid upload, polling tasks, 10k platform multi-tenant target, intranet-first development.
- 2026-06-10: Initialized git repository and committed initial spec/prototype.
- 2026-06-10: Implemented M0.1 backend API with SQLite store and minimal server-side detection. Added integration test for enroll → heartbeat → ingest → alert → task → result.
