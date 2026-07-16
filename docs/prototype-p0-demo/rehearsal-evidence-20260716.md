# Prototype P0 Rehearsal Evidence - 2026-07-16

This records the latest successful Prototype P0 demo rehearsal.

## Result

Status: passed

The rehearsal covered:

- UI/API availability.
- Windows endpoint online status.
- Events, alerts, tasks, and raw evidence readability.
- Demo mode switch.
- Read-only `file_hash` task.
- Evidence `raw_ref` and `raw_hash`.
- Final quiet mode switch.
- Final prototype validation.

## Runtime Target

- UI: `http://192.168.1.93:8765/ui`
- Endpoint: `DESKTOP-29R9I3A`
- Agent ID: `8ebaf5cf-45bd-4597-a26f-77a6e4adee8c`

## Demo Task

- Task type: `file_hash`
- Task ID: `574839ea-a6ba-415d-99a7-eecc1953653e`
- Target: `C:\Program Files\Shigure\shigure-agent.exe`
- Status: `succeeded`
- Agent file SHA256:
  `80553ccfc1ab2118d5c31b79a45114b5b4b99d6e06f2d5f2244a37643dd7a3a5`

## Evidence

- Evidence raw hash:
  `f82e00c512c2e76c779e3b62d4d51678d4f0161976a966741a5b382914f1022c`
- Evidence raw ref:
  `object://raw-evidence/default/task_result/574839ea-a6ba-415d-99a7-eecc1953653e/f82e00c512c2e76c779e3b62d4d51678d4f0161976a966741a5b382914f1022c.json`

## Final Quiet State

- `collect_process_snapshot=false`
- `max_snapshot_events=0`
- `windows_etw=false`
- `windows_eventlog_subscriptions=false`
- ETW collector: stopped
- Event Log collector: disabled
- `scripts/prototype_validate.sh`: passed with no warnings

## Not Claimed

- Production readiness.
- ClickHouse-backed retention.
- Multi-endpoint scale.
- Destructive response workflow.
- Customer production deployment support.
