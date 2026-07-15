# ADR 0005: Windows Event Log Subscription Collector Boundary

## Status

Accepted

## Context

Shigure's MVP telemetry contract needs PowerShell, authentication, service, and scheduled-task signals without relying on repeated broad `Get-WinEvent` polling. The current polling collector remains useful as a bridge and for analyst pull-based evidence tasks, but it should not be the long-term background telemetry path.

Windows Event Log supports subscription-based collection. The Windows collector research recommends native subscriptions with checkpoint state so restart behavior is visible and duplicate/loss conditions are not silent.

## Decision

Shigure will add an agent-side `WindowsEventLogSubscriber` boundary for background Event Log telemetry.

- The collector covers the MVP profiles: PowerShell Operational, Security auth, Service Control Manager, and Task Scheduler Operational.
- Windows runtime collection uses a long-running Event Log subscription source through .NET `EventLogWatcher` from the Windows agent process.
- Go remains the product boundary for queueing, normalization, checkpointing, health, upload, spool, tasking, and policy.
- Each accepted record updates a per-profile checkpoint file adjacent to the agent state path.
- Restarted collectors skip records already at or behind the checkpoint.
- Record-ID jumps after a checkpoint increment visible gap counters instead of being hidden.
- Callback-facing ingestion uses a bounded queue with drop counters in heartbeat health.
- `features.windows_eventlog_subscriptions == true` enables the subscription path and disables the recurring background `Get-WinEvent` snapshot path for Event Log telemetry.
- The read-only `windows_event_logs` analyst task remains allowlisted and pull-based evidence collection.

## Consequences

The background collector no longer depends on repeated broad polling when the feature is enabled. Existing demo/local behavior remains usable because the bridge snapshot collector is still available when the feature flag is disabled.

Windows lab validation is still required before using this path in a pilot. The lab must prove service start/stop behavior, event delivery, checkpoint restart, visible gaps, queue pressure, and that upload/task loops continue while subscribed events are flowing.
