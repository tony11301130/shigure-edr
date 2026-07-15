# Release Validation

Shigure commercial MVP release readiness is a layered gate, not a feature checklist. A release candidate must have evidence for automated tests, deterministic golden dataset replay, MDR workflow replay, safe response/evidence handling, Windows lab validation, storage/load checks, and known-gap review.

## Automated Gates

Run these on every release candidate:

- Python API and workflow tests: `.venv/bin/python -m pytest -q`
- Agent Go tests: `go test ./...` from `agent/`
- Windows agent cross-build: `GOOS=windows GOARCH=amd64 go build ./cmd/open-edr-agent`
- Prototype vertical slice: `scripts/m0_smoke.sh`
- Release validation harness: `.venv/bin/python -m pytest -q tests/test_release_validation_harness.py`

The release validation harness replays golden process graph data, MVP detection scenarios, and the alert-to-handoff MDR workflow through public API seams.

## Golden Datasets

The canonical fixture is `tests/fixtures/release_validation_golden.json`.

It covers:

- Stable `process_entity_id` graph identity.
- Parent chain and recursive descendants.
- PID reuse isolation.
- Missing parent / agent restart gap visibility.
- Timeline association by process entity.
- Detection replay for encoded PowerShell, service/task changes, process-attributed network IOC activity, and file/hash IOC activity.
- Required load query paths for alert queue, endpoint timeline, process graph, indicator hunt, and case evidence.

PID-only trees are not enough for the release gate. Any missing parent or restart uncertainty must remain visible in graph `gaps`.

## Release Report Validation

Use `scripts/release_validation.py` to validate a JSON release evidence report:

```bash
scripts/release_validation.py --report release-report.json
```

`tests/fixtures/release_report_example.json` shows the expected report shape.

The report must include passed automated gates, passed lab gates, load scenarios with metric targets, reviewed blockers, and required documents.

Blocking findings include:

- Silent process graph uncertainty.
- Destructive task exposure.
- Unaudited evidence.
- Missing MDR workflow steps.
- Missing Windows runtime validation.
- Unbounded spool behavior.
- Production dev-token or HTTP shortcuts.

## Lab Gates

The automated harness cannot replace Windows runtime validation. Release evidence must include:

- Windows service lifecycle validation.
- ETW process collector lab validation.
- Windows Event Log subscription lab validation.
- Storage/load/retention validation.

Relevant lab documents:

- `docs/WINDOWS_RELEASE_LAB.md`
- `docs/WINDOWS_ETW_PROCESS_LAB.md`
- `docs/WINDOWS_EVENT_LOG_SUBSCRIPTION_LAB.md`
- `docs/LOAD_TESTING.md`

## Passing Standard

A commercial MVP release candidate passes only when the automated harness is green, lab evidence is attached, load scenarios have measured results or documented pilot limits, and known gaps contain no release blockers.
