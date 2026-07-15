# Windows Event Log Subscription Lab

This checklist validates the #10 Windows Event Log subscription collector before `features.windows_eventlog_subscriptions` is enabled in a Windows pilot.

## Preconditions

- Windows test VM with PowerShell Operational and Task Scheduler Operational logs enabled.
- Security auditing configured enough to produce 4624/4625/4648 where the test expects auth events.
- Shigure agent built for `windows/amd64`.
- Test backend reachable by the agent.
- Agent config can explicitly set `features.windows_eventlog_subscriptions=true`.
- Snapshot Event Log collection remains available as fallback for the first lab run.

## Runtime Checks

1. Install or run the agent as a Windows service.
2. Confirm enrollment, heartbeat, task claim, telemetry upload, and local spool still work.
3. Enable `features.windows_eventlog_subscriptions=true` for the test tenant or agent policy.
4. Restart the agent service and verify heartbeat includes `windows_event_log_subscription`.
5. Generate a PowerShell event, for example a script block event on the PowerShell Operational channel.
6. Generate a service install event and a scheduled task event in a disposable test namespace.
7. Verify uploaded events include:
   - `source=windows_event_log`
   - `raw.collector=windows_event_log`
   - `raw.platform=windows_evtsubscribe`
   - `raw.query` as one of `powershell_operational`, `security_auth`, `service_control_manager`, or `task_scheduler`
   - `source_event_id` from the Windows Event Log record ID
8. Restart the agent service and verify duplicate records at or behind the checkpoint are not uploaded again.
9. Stop the agent, generate events, restart the agent, then verify record-ID gaps are visible in `windows_event_log_subscription.record_gaps` or `last_gap`.
10. Run a short event burst and verify queue depth/drop counters are visible while upload and task loops continue.
11. Disable `features.windows_eventlog_subscriptions` and verify the agent returns to the bridge `Get-WinEvent` snapshot behavior when `collect_windows_event_logs=true`.

## Failure Criteria

Treat the subscription path as failed for MVP if any of these are true:

- The subscriber cannot start or stop cleanly under Windows Service Control Manager stop/shutdown.
- PowerShell, Security, Service Control Manager, or Task Scheduler records are missed without visible health.
- Restart causes silent duplication or silent loss around the checkpoint.
- Queue pressure is invisible.
- Event subscription handling blocks telemetry upload, local spool, heartbeat, or task execution.
- The bridge `windows_event_logs` evidence task stops working.
