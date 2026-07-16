# Shigure Prototype P0 Demo Pack

This folder contains the operator-facing material for a fast Shigure Prototype
P0 demo.

Prototype P0 is not the RC0 commercial release gate. It is a single Windows
endpoint and one Shigure Web UI server showing endpoint status, telemetry,
alerts, read-only tasks, and evidence references.

## Files

- `demo-script-5min.md` - minute-by-minute live demo flow.
- `talk-track.md` - spoken script in Traditional Chinese.
- `screenshot-checklist.md` - the screenshots to capture before or during a
  demo.
- `operator-checklist.md` - pre-demo, live-demo, and post-demo checklist.
- `rehearsal-evidence-20260716.md` - latest successful rehearsal evidence.

## Current Demo Target

- UI: `http://192.168.1.93:8765/ui`
- Endpoint: `DESKTOP-29R9I3A`
- Agent ID: `8ebaf5cf-45bd-4597-a26f-77a6e4adee8c`
- Mode after rehearsal: quiet mode

## Recommended Next Step

Before showing this to another person, run:

```bash
scripts/prototype_validate.sh
```

Then follow `demo-script-5min.md`.

Keep the message clear: this is a working prototype, not production release
readiness. Storage retention is still not production validated.
