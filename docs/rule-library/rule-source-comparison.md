# Shigure Rule Source Comparison

This note compares the detection-content sources currently cached for Shigure planning. It is a planning document, not a rule import, and it does not make any runtime changes.

## Current Local Cache

The local cache lives under ignored `.scratch/` paths:

- Open/public detection content: `.scratch/open-detection-content-20260716/`
- Fidelis full private rule capture: `.scratch/fidelis-detection-rules-full-20260716/`

These folders are intentionally not committed. Treat them as private research/reference material until each source has a clear licensing and conversion decision.

## Executive Decision

Use **SigmaHQ** as the first Shigure rule-library seed.

Use **Splunk Security Content** as a secondary source for coverage analysis, analytic-story structure, and MITRE mapping.

Use **Fidelis** only as private reference material for coverage comparison. Do not copy Fidelis rule bodies into Shigure.

Use **YARA content** only after Shigure has a file/content scan path. It is not a substitute for endpoint behavior alert rules.

Use **Elastic detection-rules** as an engineering reference, not as an import source, because the repository is under Elastic License 2.0 rather than a standard permissive open-source license.

## Source Matrix

| Source | Cached Commit | License / Status | Local Content Shape | Shigure Fit | Recommendation |
|---|---|---|---|---|---|
| SigmaHQ/sigma | `bc433784ede7` | Rules are under Detection Rule License 1.1. Source: `.scratch/open-detection-content-20260716/repos/sigma/LICENSE:3` | YAML Sigma rules. 3,142 rule YAML files under `rules/`; 2,403 Windows rule YAML files; 1,182 Windows process-creation rules; 208 PowerShell rules; 247 registry rules. | Best match for vendor-neutral detection logic and Shigure's current Windows endpoint direction. | Primary seed. Build a Sigma-to-Shigure converter after Shigure rule schema is defined. |
| splunk/security_content | `d51afa603f23` | Apache License 2.0. Source: `.scratch/open-detection-content-20260716/repos/splunk-security-content/LICENSE:1` | YAML detections. 2,124 detection YAML files; 1,469 endpoint detections. | Strong coverage and story structure, but many rules expect Splunk SPL/data models. | Use for coverage mapping and selected manual ports, not direct import. |
| Yara-Rules/rules | `0f93570194a8` | GPL-2.0 license file. Source: `.scratch/open-detection-content-20260716/repos/yara-rules/LICENSE:1` | 566 `.yar/.yara` files. | Useful only when Shigure supports file scan, sample scan, or artifact scan. | Keep as malware/file detection reference. Do not bundle into product without GPL review. |
| Neo23x0/signature-base | `43b2b2faafda` | Detection Rule License 1.1. Source: `.scratch/open-detection-content-20260716/repos/signature-base/LICENSE:1` | 750 YARA files plus small Sigma/IOC-adjacent content. | Useful for file/content signatures and some detection ideas. | Reference only until Shigure has a file scan path and attribution handling. |
| elastic/detection-rules | `c574163383be` | Elastic License 2.0. Source: `.scratch/open-detection-content-20260716/repos/elastic-detection-rules/LICENSE.txt:1` | 1,973 TOML rules under `rules/`; mature validation/packaging model. | Good engineering reference, but not a clean open-source seed for Shigure content. | Study schema/tooling ideas. Do not import rules as Shigure-owned content. |
| Fidelis Detection Rules | local capture `20260716` | Vendor/product content captured from the Fidelis Management console. Source: `.scratch/fidelis-detection-rules-full-20260716/manifest.json` | 699 full rules; 373 have `createAlert=true`; 326 are detection/enrichment/context rules; all are enabled. | Very valuable for coverage comparison, but tied to Fidelis data model and proprietary content. | Private reference only. Do not commit or port rule bodies directly. |

## Licensing Notes

This section is not legal advice. It is an engineering risk read to keep the prototype from accidentally turning private or source-available content into Shigure-owned product content.

- Sigma's repo license file says the Sigma specification/logo and the repository rules have separate licensing, and that the rules are under DRL 1.1. Source: `.scratch/open-detection-content-20260716/repos/sigma/LICENSE:3`
- DRL 1.1 allows use, copy, modification, publication, distribution, sublicensing, and sale, but requires attribution retention and match-message attribution when supplied. Source: `.scratch/open-detection-content-20260716/repos/signature-base/LICENSE:3`
- Splunk Security Content is Apache-2.0, which is generally easier for product incorporation as long as notices and license obligations are handled. Source: `.scratch/open-detection-content-20260716/repos/splunk-security-content/LICENSE:1`
- Yara-Rules/rules uses GPL-2.0; do not embed it wholesale into a proprietary product path without a license review. Source: `.scratch/open-detection-content-20260716/repos/yara-rules/LICENSE:1`
- Elastic detection-rules uses Elastic License 2.0 and includes hosted-service and license-notice restrictions. Source: `.scratch/open-detection-content-20260716/repos/elastic-detection-rules/LICENSE.txt:16`
- Fidelis rule bodies should remain private reference material unless there is a separate explicit rights decision.

## Shigure Telemetry Fit

Shigure Prototype P0 currently demonstrates:

- Windows endpoint online/heartbeat.
- Process snapshot telemetry.
- Windows process trace telemetry.
- Windows Event Log telemetry.
- Read-only task and raw evidence flow.

That means the first external rule seed should prefer Windows endpoint detections that can map to process, service, scheduled task, PowerShell, registry, file, and event-log fields.

Current fit by source:

- **SigmaHQ:** strongest direct fit because Windows process creation, PowerShell, registry, file, and event-log categories are explicit.
- **Splunk Security Content:** strong topic coverage, but detection logic is often SPL/data-model-shaped.
- **Fidelis:** strong topic coverage and endpoint focus, but proprietary and field-model-specific.
- **YARA / signature-base:** useful only after file scan or artifact scan exists.
- **Elastic:** useful for schema, testing, and packaging ideas, but avoid content import.

## Recommended Rule Model

Before importing any external rules, define Shigure's own rule schema with at least three content classes:

1. `alert`
   - Creates a visible alert when matched.
   - Needs severity, confidence, title, description, MITRE mapping, evidence fields, and a deterministic rule ID.

2. `enrichment`
   - Adds behavior labels, risk signals, or tags to normalized events or process entities.
   - Does not necessarily create an alert.

3. `hunt`
   - Query/search content for analyst-driven investigation.
   - Useful for coverage, dashboards, and demo stories, but not automatically alerting.

This distinction matters because Fidelis has 373 `createAlert=true` rules and 326 `createAlert=false` rules. Importing all 699 as Shigure alerts would over-alert and misrepresent the source content.

## Conversion Strategy

### Phase 1: Schema First

Create `configs/shigure-rules.example.yaml` and a runtime loader that supports:

- `id`
- `name`
- `type`: `alert`, `enrichment`, or `hunt`
- `source_license`
- `source_url`
- `source_rule_id`
- `author`
- `severity`
- `confidence`
- `mitre`
- `logsource`
- `conditions`
- `evidence_fields`
- `tags`

The schema should explicitly carry source attribution, because Sigma/DRL content can require attribution in shared rules and match messages.

### Phase 2: Sigma Pilot

Start with 10-20 Sigma Windows rules:

- PowerShell encoded command / suspicious script execution.
- Service installation / service creation.
- Scheduled task creation or modification.
- Suspicious process parent-child patterns.
- Registry persistence events.

Port them manually first. Do not build a bulk converter before the Shigure rule schema has survived a small pilot.

### Phase 3: Converter

Build `tools/convert_sigma_to_shigure_rules.py` only after the pilot. The converter should:

- Reject unsupported Sigma features clearly.
- Preserve original source fields and author attribution.
- Mark confidence as `review_required` until each converted rule has a Shigure telemetry test.
- Output into a generated folder that is not automatically treated as production content.

### Phase 4: Coverage Mapping

Use Fidelis and Splunk as coverage maps:

- Which MITRE techniques are represented?
- Which are relevant to Windows intranet EDR?
- Which are supported by current Shigure telemetry?
- Which need new collectors or fields?

Do not treat coverage mapping as a rule import.

## First 10 Candidate Areas

The first Shigure rule-library pilot should focus on areas already proven in Prototype P0 and RC0 validation:

1. Encoded PowerShell command.
2. Suspicious PowerShell script block.
3. Windows service installed.
4. Scheduled task created or modified.
5. PowerShell launched by scripting host.
6. Suspicious `rundll32` execution.
7. Process execution from temp/AppData paths.
8. Registry run-key persistence.
9. Suspicious remote admin tooling pattern.
10. Known IOC match.

These align with the existing Shigure baseline rules and the downloaded Sigma/Fidelis coverage, while staying within the current Windows endpoint telemetry footprint.

## What Not To Do

- Do not commit `.scratch/open-detection-content-20260716/` wholesale.
- Do not commit `.scratch/fidelis-detection-rules-full-20260716/`.
- Do not import all Sigma rules into runtime at once.
- Do not convert YARA rules until file scanning exists.
- Do not present Fidelis-derived rule bodies as Shigure-owned content.
- Do not treat Elastic detection-rules as an open-source seed.

## Recommended Next Ticket

Create a Shigure issue:

**Rule Library P0: Shigure detection schema and Sigma pilot**

Scope:

- Define Shigure rule YAML schema.
- Move existing built-in baseline rules out of Python code into first-party Shigure YAML.
- Add loader tests.
- Add 10-20 manually reviewed Sigma-derived Windows rules with source attribution.
- Add a validation report showing which rules can fire from current Windows telemetry.
- Keep Fidelis as private coverage reference only.

Non-goals:

- No bulk import.
- No Fidelis body import.
- No Elastic content import.
- No YARA runtime until file scan exists.
