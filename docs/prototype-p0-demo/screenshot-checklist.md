# Screenshot Checklist

Capture these screenshots for a short Prototype P0 walkthrough.

Recommended naming pattern:

```text
prototype-p0-01-ui-summary.png
prototype-p0-02-endpoint-online.png
prototype-p0-03-events.png
prototype-p0-04-alerts.png
prototype-p0-05-task-catalog.png
prototype-p0-06-task-succeeded.png
prototype-p0-07-raw-evidence.png
prototype-p0-08-validate-passed.png
```

## Required Screenshots

1. UI summary
   - Show dashboard or summary counts.
   - Include agents, events, alerts, tasks, and raw evidence if visible.

2. Endpoint online
   - Show `DESKTOP-29R9I3A`.
   - Show online/healthy state.

3. Events view
   - Show recent endpoint telemetry.
   - Prefer a row with raw reference or hash visible.

4. Alerts view
   - Show Windows service, scheduled task, PowerShell, or validation-related
     alerts.

5. Task catalog
   - Show read-only tasks.
   - Avoid showing or selecting destructive actions.

6. Task success
   - Show `file_hash` task succeeded.
   - Include task ID if the UI exposes it.

7. Raw evidence
   - Show `raw_ref`.
   - Show `raw_hash`.

8. Final validation
   - Terminal screenshot of:

     ```bash
     scripts/prototype_validate.sh
     ```

   - The screenshot should show no warnings.

## Optional Screenshots

- `scripts/prototype_config_demo.sh` output before the demo.
- `scripts/prototype_config_quiet.sh` output after the demo.
- Endpoint collector health showing ETW/EventLog disabled after the demo.

## Avoid

- Do not capture credentials or shell history containing credentials.
- Do not show enrollment tokens.
- Do not show unrelated local files or private notes.
- Do not imply ClickHouse retention is validated.
