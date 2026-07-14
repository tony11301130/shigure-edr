# ADR 0003: Process Entity Identity

## Status

Accepted

## Context

Shigure investigations need process graph, timeline, hunt, and evidence pivots that remain useful when operating systems reuse PIDs. A PID is only a short-lived local attribute; treating it as identity can connect unrelated executions after process exit and PID reuse.

The MVP must remain compatible with existing PID-based telemetry and APIs while introducing a stable process identity contract for new telemetry.

## Decision

Process telemetry uses `process_entity_id` as the process identity. `process_id` remains a raw PID attribute and is not sufficient identity by itself.

Process identity is derived from endpoint and execution hints:

- host or endpoint identity
- boot ID
- PID
- process create time
- image path or image hash when available

Parent links prefer `parent_process_entity_id`. `parent_process_id` remains a raw parent PID attribute for compatibility and incomplete collectors.

Events may include identity support metadata:

- `boot_id`
- `process_create_time`
- `process_exit_time`
- `image_path`
- `image_hash`
- `process_identity_confidence`
- `missing_parent_reason`

Investigation APIs prefer entity links when `process_entity_id` is supplied. Legacy `process_id` queries continue to work as compatibility paths.

## Consequences

Process-chain results can distinguish two executions that reused the same PID. Missing or uncertain parent links are represented as gaps instead of being inferred with fake certainty.

Collectors may initially produce lower-confidence identity when create time or image hints are missing. Later process graph work can improve confidence with richer Windows event and process-tracking sources without changing the public event contract.
