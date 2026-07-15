# ADR 0004: Windows ETW Process Collector Boundary

## Status

Accepted

## Context

Shigure's MVP process graph needs process create and stop telemetry that is not dependent on periodic process snapshots. The local `ProcessTracker` already owns stable process entity IDs, parent resolution, exited-process retention, PID reuse handling, and gap metadata.

The Windows collector research recommends ETW as the long-term source for process lifecycle telemetry, but it also identifies real implementation risks:

- Some Go ETW libraries require CGO and a MinGW toolchain.
- Some pure-Go ETW libraries have licensing or maturity concerns for a commercial endpoint agent.
- ETW callback behavior, shutdown, parsing, and loss reporting must be validated under Windows service runtime before the collector can be called production-grade.
- A krabsetw shim is acceptable only if it stays small and does not own policy, tasking, upload, spool, or process graph logic.

## Decision

Shigure will keep the Go agent as the product boundary and process graph owner.

The first ETW implementation boundary is an internal Go `ETWProcessCollector` seam:

- ETW process records normalize into `process_start` and `process_stop` `NormalizedEvent` values.
- Normalized records are fed into `ProcessTracker`.
- Callback-facing ingestion uses a bounded queue.
- Queue drops, processed counts, running state, and last error are visible in heartbeat collector health.
- The backend feature flag `features.windows_etw == true` is required before ETW process events are drained into the telemetry cycle.

No GPL ETW dependency is added to the core agent. No CGO-only ETW dependency is accepted without a separate Windows service validation result.

The krabsetw shim remains a fallback, not the default. Introduce it only if the pure-Go Windows ETW source cannot satisfy the service-grade validation bar for create/stop delivery, parsing, shutdown, or loss visibility.

## Consequences

The process graph and collector health contract can be tested deterministically on non-Windows hosts. Windows runtime validation remains mandatory before enabling ETW collection in an MVP deployment.

The current bridge snapshot collector remains available. It should be treated as fallback telemetry, not the long-term process lineage source.

If a shim is needed later, only the ETW session setup, callback parsing, and minimal record handoff may move into native code. Process identity, parent resolution, buffering policy, upload, spool, tasking, and endpoint policy enforcement remain in Go.
