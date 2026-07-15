# ADR 0008: ClickHouse Telemetry Projection

Date: 2026-07-15

## Status

Accepted

## Context

Shigure now separates production storage responsibilities:

- PostgreSQL owns correctness-heavy control-plane and workflow records.
- S3-compatible object storage owns raw evidence blobs.
- SQLite remains the local development, smoke, and demo path.

The remaining commercial-readiness gap is high-volume endpoint telemetry.
Timeline and hunt query paths must not rely on PostgreSQL as the long-term event
lake for the 10,000 endpoint MVP target.

## Decision

Production profile now defaults telemetry projection to ClickHouse and requires
`OPEN_EDR_MDR_CLICKHOUSE_DSN`. Dev and demo profiles keep the existing SQLite
event query path unless `OPEN_EDR_MDR_TELEMETRY_PROJECTION=clickhouse` is set.

Configuration:

- `OPEN_EDR_MDR_PROFILE=production`
- `OPEN_EDR_MDR_CONTROL_PLANE_STORE=postgresql`
- `OPEN_EDR_MDR_POSTGRES_DSN=postgresql://...`
- `OPEN_EDR_MDR_TELEMETRY_PROJECTION=clickhouse`
- `OPEN_EDR_MDR_CLICKHOUSE_DSN=http://clickhouse:8123/?database=shigure`

The API now routes normalized event query seams through a telemetry projection:

- `/api/v1/admin/events`
- `/api/v1/admin/events/count`
- `/api/v1/admin/events/related`
- `/api/v1/admin/events/{event_id}`
- saved hunt runs

The control-plane store still owns alerts, cases, tasks, enrollment, agent
state, hunt definitions, hunt run records, and raw evidence metadata. Event
ingest writes normalized telemetry metadata through the control-plane path for
current API compatibility, then projects the same enriched events to ClickHouse.
Raw blobs remain object refs; ClickHouse receives `raw_ref` / `raw_hash`, not
the source payload as SQL-owned evidence.

The first ClickHouse table family is:

- `shigure_events` for normalized endpoint events.
- `shigure_process_edges` for parent/child process entity edges.
- `shigure_event_rollups_hourly` for hourly event and gap rollups.

The normalized event table uses daily partitions and a 30-day hot TTL:

```sql
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (tenant_id, endpoint_id, event_time, event_type, process_entity_id, event_id)
TTL event_time + INTERVAL 30 DAY
```

Hourly rollups use a 180-day TTL.

## Validation

The default test suite stays self-contained and uses SQLite-compatible seams.
ClickHouse behavior has two validation layers:

- Public API tests inject a ClickHouse-shaped telemetry projection and verify
  event list/count/related queries plus saved hunt runs return comparable
  results.
- Schema tests assert process entity columns, daily partitions, and TTL clauses.
- `OPEN_EDR_MDR_TEST_CLICKHOUSE_DSN` enables an optional live ClickHouse
  insert/query round trip when a local or CI ClickHouse instance is available.

The reusable fixture `tests/fixtures/clickhouse_projection_events.json` is the
first projection/load-test seed for timeline and hunt paths.

## Consequences

- A production server without ClickHouse configuration fails early instead of
  silently querying only PostgreSQL/SQLite for telemetry.
- Timeline and hunt APIs now have an explicit projection seam.
- ClickHouse owns append-only telemetry and rollups; PostgreSQL remains the
  source of truth for workflow/control-plane records.
- Future work can deepen rollups, collector health summaries, and load tests
  without changing the public investigation API.
