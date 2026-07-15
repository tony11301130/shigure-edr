# Windows Release Lab

This checklist records the manual Windows runtime evidence required before a Shigure commercial MVP release candidate can pass the release gate.

## Required Environment

- Clean Windows VM joined to an isolated lab network.
- Shigure server reachable over the intended release transport.
- Release candidate `shigure-agent-package.zip`, `shigure-agent.exe`, and `shigure-agent-config.json`.
- Release validation report that links to captured logs, screenshots, or exported JSON.
- Signing certificate or documented unsigned-lab exception for the candidate artifact.
- Published SHA256 checksums for the package, binary, config template, and release notes.

## Required Checks

1. Verify package and binary SHA256 checksums before installation.
2. Verify Authenticode signature status, signer, timestamp, and certificate chain, or record the unsigned-lab exception.
3. Install the Windows agent package with default Shigure names.
4. Confirm `ShigureAgent` exists, has display name `Shigure Agent`, and points to `C:\Program Files\Shigure\shigure-agent.exe`.
5. Confirm installed config and state paths are under `C:\ProgramData\Shigure`.
6. Enroll with a tenant-scoped enrollment token.
7. Confirm heartbeat includes agent version, collector health, spool pressure, policy version, upload health, and task health.
8. Upload telemetry and confirm server-side detection creates an alert.
9. Claim and complete an allowed read-only task.
10. Upload task result evidence and confirm raw refs include hash and size metadata.
11. Restart the service and confirm state, credentials, spool, and policy survive.
12. Reboot the VM and confirm the service resumes without duplicate enrollment.
13. Validate repair or reinstall preserves endpoint state and bounded spool files unless an operator intentionally resets them.
14. Validate upgrade from previous package to the candidate package preserves state, credentials, policy/config version, and spool.
15. Simulate a failed upgrade and validate rollback guidance restores the previous working package without silent state loss.
16. Validate uninstall removes `ShigureAgent` while preserving auditable server records.
17. Generate a handoff/export containing the lifecycle timestamps and artifact hashes.

## Legacy Shiori Compatibility Check

Run only when validating an upgrade path from prototype deployments:

1. Generate a deployment package with `naming=shiori` or install with explicit overrides: `--service-name ShioriAgent`, `--service-display-name "Shiori Agent"`, `--service-binary-name shiori-agent.exe`, `--install-dir "C:\Program Files\Shiori"`, `--state C:\ProgramData\Shiori\shiori-agent-state.json`, and `--spool C:\ProgramData\Shiori\spool.jsonl`.
2. Confirm the old names appear only because the override was explicit.
3. Confirm the same enrollment, heartbeat, task, evidence, restart, and uninstall checks pass.

## Blockers

- Agent cannot enroll or heartbeat after install.
- Default package installs Shiori names without an explicit compatibility override.
- Artifact checksum or signature evidence is missing.
- Long-term bootstrap enrollment token remains as the runtime identity.
- Production transport permits HTTP or skips server certificate validation.
- Read-only tasking cannot claim, complete, and upload auditable evidence.
- Service restart or reboot loses credential, spool, or policy state silently.
- Upgrade, rollback, uninstall, or repair leaves the release owner unable to explain endpoint state.

## Evidence

Attach the following to the release validation report:

- Agent package version and commit SHA.
- SHA256 checksums and Authenticode signature output.
- Lab VM OS version.
- Enrollment, heartbeat, telemetry upload, task, evidence, restart, reboot, repair, upgrade, rollback, uninstall, and handoff timestamps.
- Links or paths to server logs, agent logs, handoff JSON, and raw evidence refs.
