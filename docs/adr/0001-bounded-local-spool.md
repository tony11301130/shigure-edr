# ADR 0001: Bounded Local Spool

## Status

Accepted

## Context

Shigure agents can lose backend connectivity while still collecting telemetry or task results. The commercial MVP release bar treats unbounded local spool growth as a release blocker, because an offline endpoint must not consume unlimited disk and operators must be able to see telemetry loss risk.

## Decision

The agent local spool is bounded by both byte and record limits. The deployment default is 50 MiB and 10,000 records.

When limits are reached, the agent applies backpressure by dropping queued records locally instead of growing the spool without bound. The drop policy preserves high-value task results before lower-value telemetry. If an incoming record cannot fit even after lower-value records are dropped, that incoming record is blocked from entering the spool.

The agent records spool health in heartbeat metadata:

- queued bytes and records
- pressure state
- accepted records
- dropped records
- blocked records
- uploaded records
- replayed records
- retried records
- oldest queued record age
- last successful upload time
- upload lag

## Consequences

Operators can see spool pressure and data-loss risk through agent metadata. During investigations, spool pressure or increasing drop/block counters should be treated as a telemetry gap and called out in case evidence or handoff packages.

Dropped or blocked records are not recoverable from the local spool. Recovery action is operational: restore backend connectivity, validate endpoint disk health, and collect targeted evidence if the outage overlapped the investigation window.
