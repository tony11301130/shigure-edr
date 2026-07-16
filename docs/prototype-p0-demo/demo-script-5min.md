# 5-Minute Demo Script

Audience goal: show that Shigure can manage one Windows endpoint, receive
endpoint telemetry, surface alerts, run read-only tasks, and preserve evidence
references.

## Before The Demo

Run the health check:

```bash
scripts/prototype_validate.sh
```

Switch to demo mode if you want fresh process snapshot events:

```bash
scripts/prototype_config_demo.sh
```

Open:

```text
http://192.168.1.93:8765/ui
```

## 0:00-0:30 - Frame The Prototype

Say:

> This is Shigure Prototype P0. The goal is not to claim production readiness.
> The goal is to show a working Windows intranet EDR prototype: one Windows
> endpoint, one Shigure server, live endpoint status, telemetry, alerts,
> read-only tasking, and evidence references.

Point out:

- This is a dev/sqlite prototype.
- ClickHouse retention is not claimed here.
- Only read-only tasks are used in the demo.

## 0:30-1:15 - Endpoint Online

In the UI, show the endpoint list or summary.

Expected endpoint:

```text
DESKTOP-29R9I3A
```

Call out:

- Endpoint is online.
- Agent ID is stable.
- Heartbeat and health are visible.

Expected Agent ID:

```text
8ebaf5cf-45bd-4597-a26f-77a6e4adee8c
```

## 1:15-2:00 - Telemetry And Alerts

Show the events and alerts views.

Call out:

- Recent endpoint telemetry is visible.
- Alerts are visible from Windows service, scheduled task, PowerShell, or lab
  validation activity.
- Events include raw evidence references and hashes when available.

Avoid overclaiming:

> This prototype shows the workflow and evidence shape. Long-term production
> retention is still a release gate.

## 2:00-3:30 - Read-Only Task Flow

Queue a read-only task from the task catalog.

Recommended task:

```text
file_hash
```

Recommended target:

```text
C:\Program Files\Shigure\shigure-agent.exe
```

Expected result:

- Task moves to succeeded.
- File SHA256 is returned.
- Evidence `raw_ref` is created.
- Evidence `raw_hash` is visible.

Latest successful rehearsal task:

```text
Task ID: 574839ea-a6ba-415d-99a7-eecc1953653e
Status: succeeded
Agent file SHA256: 80553ccfc1ab2118d5c31b79a45114b5b4b99d6e06f2d5f2244a37643dd7a3a5
Evidence raw_hash: f82e00c512c2e76c779e3b62d4d51678d4f0161976a966741a5b382914f1022c
```

## 3:30-4:30 - Evidence Story

Show raw evidence or task detail.

Say:

> The important point is that Shigure does not only show a task result. It also
> records an evidence reference and hash, so an analyst can tie the UI result
> back to the stored raw evidence.

Latest rehearsal raw reference:

```text
object://raw-evidence/default/task_result/574839ea-a6ba-415d-99a7-eecc1953653e/f82e00c512c2e76c779e3b62d4d51678d4f0161976a966741a5b382914f1022c.json
```

## 4:30-5:00 - Close And Boundaries

Say:

> This is the first useful prototype loop: endpoint online, telemetry visible,
> alerts visible, read-only tasking works, and evidence is traceable. The next
> release engineering blocker is storage/load/retention with ClickHouse or an
> approved equivalent storage lab.

End by switching back to quiet mode:

```bash
scripts/prototype_config_quiet.sh
scripts/prototype_validate.sh
```

Expected final state:

- Validation passes.
- Event Log collector is disabled.
- Windows process trace collector is stopped.
- Routine process snapshot collection is quiet.
