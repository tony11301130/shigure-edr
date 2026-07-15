# ADR 0007: PostgreSQL Control-Plane Store Profile

Date: 2026-07-15

## Status

Accepted

## Context

Shigure's commercial MVP separates storage responsibilities:

- PostgreSQL owns mutable control-plane and workflow records.
- ClickHouse will own high-volume endpoint telemetry and hunt/timeline
  projection in the next storage step.
- S3-compatible object storage owns raw evidence blobs.
- SQLite remains for local development, smoke tests, and demos.

Before this ADR, production profile could still boot against the SQLite store.
That hid a commercial-readiness gap because enrollment tokens, agents, tasks,
alerts, cases, hunts, audit-like credential events, and raw evidence metadata
were all backed by a prototype database path.

## Decision

Production profile now defaults to the PostgreSQL control-plane store and
requires `OPEN_EDR_MDR_POSTGRES_DSN`. Dev and demo profiles continue to use
SQLite unless explicitly configured otherwise.

Configuration:

- `OPEN_EDR_MDR_PROFILE=production`
- `OPEN_EDR_MDR_CONTROL_PLANE_STORE=postgresql`
- `OPEN_EDR_MDR_POSTGRES_DSN=postgresql://...`

The PostgreSQL store keeps the same public store/API contract as the SQLite
store for the current MVP slice. This lets the API, workflow, and tests exercise
the same behaviors across both stores while the later ClickHouse ticket moves
high-volume telemetry projection out of the control-plane store.

The first migration marker is `001_control_plane` in `schema_migrations`.
The schema covers:

- enrollment tokens
- agents and agent credential lifecycle events
- tenant configs
- tasks
- alerts
- cases and case evidence links
- hunts and hunt runs
- raw evidence metadata

Raw evidence payloads do not move back into SQL. PostgreSQL stores only metadata
and object refs produced by the raw object storage adapter.

Admins can inspect active storage through:

- `/api/v1/admin/storage-profile`
- `/api/v1/admin/raw-evidence/storage-config`

## Validation

The standard test suite still runs on SQLite so local dev and smoke tests remain
fast and self-contained.

PostgreSQL validation is env-gated with
`OPEN_EDR_MDR_TEST_POSTGRES_DSN`. When set, the test resets the target schema and
runs a production-profile vertical slice through public APIs:

- migration marker exists
- enrollment works for multiple tenants
- cross-tenant tasking is rejected
- task claim/result lifecycle works
- event ingestion generates alert workflow records
- case creation links alert raw evidence metadata
- agent evidence upload stores raw metadata and object refs without SQL payloads

## Consequences

- A production server without PostgreSQL configuration fails early instead of
  silently using SQLite.
- SQLite remains available through explicit test injection and non-production
  profiles.
- PostgreSQL is now the source of truth for workflow/control-plane metadata in
  production profile.
- ClickHouse telemetry projection is covered separately by ADR 0008; PostgreSQL
  remains focused on workflow/control-plane metadata.
