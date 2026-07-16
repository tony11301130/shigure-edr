# Shigure Product UI Benchmark: Fidelis and PRE Security

This document turns the private Fidelis UI review and the local PRE Security feature inventory into a Shigure product UI direction. It is a product-planning note, not an implementation spec, and it intentionally excludes credentials, customer endpoint names, private screenshots, and exported proprietary rule bodies.

## Sources

- Fidelis Endpoint console, reviewed through an authorized read-only browser session on 2026-07-17.
- Private Fidelis UI capture artifacts under ignored local scratch space: `.scratch/ui-benchmark-20260717/fidelis/`.
- PRE Security local analysis report: `/opt/presecurity/presecurity-feature-inventory.md`.
- PRE Security local route screenshots and scan artifacts under `/opt/presecurity/artifacts/`.

Do not commit the private Fidelis screenshots, raw UI scan, downloaded assets, or credential material. The scratch capture exists only to support local design analysis.

## Executive Decision

For Shigure productization, use **Fidelis as the primary EDR workflow reference** and **PRE Security as the product-shell and analyst-narrative reference**.

That means:

- Shigure should adopt Fidelis-style density, navigation, saved searches, tables, filters, endpoint inventory, task flow, and investigation workflows.
- Shigure should not copy Fidelis visual styling directly. The Fidelis UI is operationally useful, but visually dated and noisy.
- Shigure should borrow PRE's clearer SOC story: dashboard narrative, operator guidance, case context, AI-assisted explanations, and higher-level threat posture.
- Shigure should remain an endpoint-first EDR/MDR product, not become a broad SIEM/XDR suite in Product UI P0.

The first productized Shigure UI should feel like a modern EDR analyst console: dense, fast, evidence-first, and calm under pressure.

## Fidelis Takeaways

Fidelis is a strong reference for how a mature endpoint product organizes operator work.

Useful patterns to copy conceptually:

- **Alerts-first landing page**
  - The operator starts from an alert queue, not a marketing dashboard.
  - Bulk acknowledgement, delete/review actions, severity, source, endpoint, artifact, and time columns are immediately visible.
  - Saved searches and common filters are first-class UI concepts.

- **Persistent left navigation**
  - Main areas are stable and discoverable: Alerts, Investigation, Behaviors, Executables, Installed Software, Reports, Tasks, Endpoints, Configuration.
  - This fits repeated SOC/EDR work better than card-heavy navigation.

- **Investigation data tables**
  - Behaviors expose process-like fields: time, endpoint, user, PID, parent PID, process name, path, command line, signatures, and hashes.
  - Executables expose file inventory fields: first seen, file type, size, endpoint first seen, OS type, path, sandbox result, and hashes.
  - Installed software exposes software inventory and vulnerability shape: publisher, version, CVE score/count, endpoint count, OS, install date.

- **Task center**
  - Task selection is a wizard.
  - Task status is a separate work queue with script package, creator, start/end time, status, and alert association.
  - Schedules are separate from one-shot tasks.

- **Endpoint and group administration**
  - Endpoint list and detail views are core product surfaces.
  - Group configuration binds agent behavior, process blocking, threat detection, installer/update controls, and detection content administration.

Patterns to avoid copying directly:

- Overly cramped legacy layout.
- Multiple duplicate nav entries.
- Modal-heavy interactions where a side drawer would be easier.
- Visual style that feels older than the product Shigure should become.
- Mixing destructive and read-only response controls without clearer safety boundaries.

## PRE Security Takeaways

PRE Security is a better reference for product narrative and modern SOC positioning than for Shigure's immediate EDR information architecture.

Useful patterns to copy conceptually:

- **Autonomous operator layer**
  - A guided analyst/copilot surface can explain alerts, summarize evidence, and help decide next steps.
  - For Shigure, this should come after core endpoint and alert workflows are reliable.

- **Threat center story**
  - PRE organizes detections, predictions, MITRE mapping, active entities, and event details into a coherent SOC story.
  - Shigure should borrow the clarity of "what matters now" and "why this is risky".

- **Triage/cases**
  - Incident stages, case creation, analyst notes, and benign/false-positive handling are product-grade SOC concepts.
  - Shigure should support this once alert queue and evidence views are stable.

- **Data readiness and runtime health**
  - PRE makes data quality visible.
  - Shigure needs an equivalent: endpoint online state, collector state, storage profile, event growth, evidence pipeline health, and rule coverage.

Patterns to defer:

- Full predictive posture scoring.
- Broad SIEM/XDR ingestion.
- Multi-tenant MSSP administration.
- AI-native workflows as the first screen.
- Large threat-map or global stream views unless Shigure has enough real telemetry to justify them.

## Shigure Product UI P0 Information Architecture

Product UI P0 should prioritize a small number of serious work surfaces instead of many shallow pages.

### 1. Alert Queue

This should be the default landing page.

Core capabilities:

- Filter by time range, severity, rule source, MITRE technique, endpoint, artifact, status, and evidence state.
- Toggle list, group-by, and compact charts.
- Save searches.
- Acknowledge, assign, mark benign, and add notes.
- Open an alert details drawer without losing queue context.
- Show raw evidence refs, hashes, task links, and related events.

Design note:

Use Fidelis density, but modernize the interaction with a right-side details drawer, stable column presets, and clearer status chips.

### 2. Endpoint Dossier

This is the second product surface.

Core capabilities:

- Endpoint list with online state, last contact, OS, agent version, group, collector state, and risk count.
- Endpoint detail with heartbeat, spool pressure, task history, active collectors, recent events, recent alerts, and evidence count.
- Collector state should be explicit: process snapshot, process trace, Event Log, file scan, and future registry/software inventory.

Design note:

This is where Shigure can become more useful than a generic alert UI. Endpoint health and evidence continuity are central to trust.

### 3. Investigation Workspace

This should connect alerts, events, processes, tasks, and evidence.

Core capabilities:

- Timeline by endpoint and time window.
- Process tree / parent-child view.
- Event detail panel with normalized fields and raw evidence pointer.
- Hash/path/user/process filters.
- "Promote to case" or "add to investigation" action.
- Analyst notes.

Design note:

Start with one focused endpoint investigation view. Do not build a broad graph product before the core table/timeline works.

### 4. Task Center

This should productize the current read-only response boundary.

Core capabilities:

- Task catalog with clear read-only/destructive classification.
- Task wizard for selecting endpoint(s), arguments, and timeout.
- Task status queue.
- Evidence output view with raw_ref, raw_hash, result summary, and execution metadata.
- Schedules can be deferred until one-shot tasks are polished.

Design note:

Keep destructive response actions out of P0 unless the safety model is fully explicit. Shigure's current trust story is read-only validation.

### 5. Detection Library

This is the productized home for what is currently built-in detection logic plus future Sigma-derived content.

Core capabilities:

- First-party Shigure baseline rules.
- Rule type: alert, enrichment, hunt.
- Rule status: enabled, draft, disabled.
- MITRE mapping.
- Source and license attribution.
- Last validation status against Shigure telemetry.

Design note:

This should not import Fidelis rule bodies. Use Fidelis as private coverage reference, SigmaHQ as first public seed, and Splunk Security Content as coverage/story reference.

### 6. Admin and Runtime Health

This should keep operators from confusing demo state with production state.

Core capabilities:

- Server profile and storage profile.
- Endpoint enrollment / installer path.
- Agent group configuration.
- Collector configuration.
- Evidence storage health.
- Storage/load/retention gate status.

Design note:

Runtime truth should be visible in-product. If Shigure is running dev/sqlite, the UI should say so plainly.

## Recommended Visual Direction

Shigure should not look like either reference exactly.

Recommended style:

- **Shell:** compact left nav, persistent top status bar, dense content region.
- **Tables:** primary workhorse component; fixed headers, compact rows, column presets, saved filters.
- **Details:** right-side drawer for alert/event/task/endpoint detail.
- **Color:** restrained neutral base, severity and state colors used sparingly and consistently.
- **Typography:** compact data font for tables and hashes, clean sans for labels and navigation.
- **Cards:** only for repeated entity summaries or dashboard modules, not as the whole layout language.
- **Charts:** small supporting charts only when they help triage; do not lead with decorative dashboards.

Signature product element:

> Evidence ribbon: every alert, event, and task detail should show a compact chain of normalized event, raw evidence reference, hash, collector, and endpoint state.

This makes Shigure feel evidence-first instead of just alert-first.

## Implementation Order

### Product UI P0-A: Alert Queue

Start here.

- Create the product-grade alert queue layout.
- Add saved-search shaped filter model, even if persistence is simple at first.
- Add alert detail drawer.
- Show rule, MITRE, severity, evidence, endpoint, and task relationships.

Mapped issue: `#21 Alert Queue Analyst Facets`

### Product UI P0-B: Endpoint Dossier

- Productize endpoint list/detail.
- Expose online state, collector state, agent version, task history, and recent evidence.

Mapped issue: `#20 Endpoint Dossier Parity`

### Product UI P0-C: Investigation Workspace

- Build timeline/process/event details around current telemetry.
- Keep graph ambitions small until fields are stable.

Mapped issue: `#22 Behavior Timeline and Process Graph Workspace`

### Product UI P0-D: Task Center

- Polish read-only task catalog/status/evidence.
- Make safety boundary visible.

Mapped issue: `#23 Task Risk/Evidence/Audit UX`

### Product UI P0-E: Detection Library

- Define schema and rule registry UI.
- Move first-party baseline rules out of code.
- Add Sigma pilot after schema lands.

Mapped issue: `#26 Detection Rule Registry`

## Non-Goals For The Next Build Pass

- Do not clone the Fidelis UI skin.
- Do not import Fidelis proprietary rule bodies into Shigure.
- Do not turn PRE's full AI/SIEM/XDR suite into Shigure scope.
- Do not start broad predictive scoring before Shigure has production storage and enough telemetry.
- Do not build destructive response UI before the response safety boundary is productized.
- Do not treat `.scratch/` benchmark data as committable product assets.

## Productization Decision

The next Shigure productization work should be:

**Product UI P0: Alerts-first EDR console**

Scope:

- Alert Queue.
- Alert details drawer.
- Endpoint summary context.
- Evidence ribbon.
- Task/evidence links.
- Runtime profile banner.

This is the smallest product UI step that moves Shigure from a prototype console toward a credible EDR operator product while staying aligned with the current Windows endpoint telemetry and read-only response boundary.
