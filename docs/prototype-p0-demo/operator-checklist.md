# Operator Checklist

Use this checklist when preparing or running the Prototype P0 demo.

## Pre-Demo

- Confirm you are on `main`.
- Confirm there are no unexpected local changes:

  ```bash
  git status --short --branch
  ```

- Confirm the prototype is healthy:

  ```bash
  scripts/prototype_validate.sh
  ```

- Open the UI:

  ```text
  http://192.168.1.93:8765/ui
  ```

- Confirm at least one endpoint is online.
- Confirm endpoint `DESKTOP-29R9I3A` is visible.
- Confirm Event Log and process trace collectors are not accidentally left on.

## During Demo

- Start with the prototype boundary:
  - dev/sqlite
  - single Windows endpoint
  - read-only tasks only
  - storage retention not production validated
- Show endpoint online status.
- Show events.
- Show alerts.
- Queue a read-only task.
- Confirm task success.
- Show evidence `raw_ref` and `raw_hash`.

## Safe Task Choices

- `file_exists`
- `file_hash`
- bounded Windows event log collection

Avoid destructive response actions in Prototype P0.

## Post-Demo

Switch back to quiet mode:

```bash
scripts/prototype_config_quiet.sh
```

Validate final state:

```bash
scripts/prototype_validate.sh
```

Expected:

- UI still loads.
- Endpoint is still online.
- No validation warnings.
- ETW/EventLog collectors are stopped or disabled.
- Event growth is not abnormal.

If the prototype will not be used again soon, stop the Windows lab service from
an elevated PowerShell session:

```powershell
Stop-Service ShigureAgent
```
