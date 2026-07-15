# Windows ETW Process Collector Lab

This checklist validates the #9 ETW process collector boundary before `features.windows_etw` is enabled in a Windows pilot.

## Preconditions

- Windows test VM joined to the expected intranet-style environment.
- Shigure agent built for `windows/amd64`.
- Test backend reachable over the selected dev or production profile.
- Agent config can explicitly set `features.windows_etw` to `true`.
- Snapshot process collection remains enabled as fallback during the first lab run.

## Runtime Checks

1. Install or run the agent as a Windows service.
2. Confirm enrollment, heartbeat, task claim, telemetry upload, and local spool still work.
3. Enable `features.windows_etw=true` for the test tenant or agent policy.
4. Restart the agent service and verify heartbeat includes `windows_etw_process`.
5. Start a known child process tree, for example `cmd.exe /c powershell -NoProfile -Command "$pid"`.
6. Verify process create events are uploaded with:
   - `source=windows_etw`
   - `event_type=process_start`
   - `process_id`
   - `parent_process_id`
   - `process_entity_id`
   - `parent_process_entity_id` when the parent was observed
   - `process_create_time`
   - `image_path` or `image_hash` when available
7. Exit the test process and verify a `process_stop` event uses the same `process_entity_id` and includes `process_exit_time`.
8. Stop and start the agent service during process churn, then verify gap or loss health is visible instead of silently presenting uncertain graph links.
9. Run a short high-churn test and verify upload/task loops continue while collector drop counters remain visible.
10. Disable `features.windows_etw` and verify the agent returns to snapshot fallback behavior.

## Failure Criteria

Treat the pure-Go ETW path as failed for MVP if any of these are true:

- The collector cannot start or stop cleanly under Windows Service Control Manager stop/shutdown.
- Process create or stop events are lost without visible health counters.
- Required PID, parent PID, create time, exit time, or image fields cannot be parsed reliably enough to build process entities.
- Callback handling blocks on upload, disk-heavy work, hashing, or graph reconstruction.
- Cross-build or runtime requirements are worse than a small supervised krabsetw shim.

If this checklist fails, keep the Go `ProcessTracker` and `ETWProcessCollector` contract, then implement the smallest possible krabsetw shim that emits the same lifecycle records into the Go collector boundary.
