# Windows Release Lab

This checklist records the manual Windows runtime evidence required before a Shigure commercial MVP release candidate can pass the release gate.

## Required Environment

- Clean Windows VM joined to an isolated lab network.
- Shigure server reachable over the intended release transport.
- Release candidate agent package and configuration.
- Release validation report that links to captured logs, screenshots, or exported JSON.

## Required Checks

1. Install the Windows agent package.
2. Enroll with a tenant-scoped enrollment token.
3. Confirm heartbeat includes agent version, collector health, spool pressure, policy version, upload health, and task health.
4. Upload telemetry and confirm server-side detection creates an alert.
5. Claim and complete an allowed read-only task.
6. Upload task result evidence and confirm raw refs include hash and size metadata.
7. Restart the service and confirm state, credentials, spool, and policy survive.
8. Reboot the VM and confirm the service resumes without duplicate enrollment.
9. Validate uninstall removes the service while preserving auditable server records.
10. Validate repair or reinstall behavior and record any state preservation limits.

## Blockers

- Agent cannot enroll or heartbeat after install.
- Long-term bootstrap enrollment token remains as the runtime identity.
- Production transport permits HTTP or skips server certificate validation.
- Read-only tasking cannot claim, complete, and upload auditable evidence.
- Service restart or reboot loses credential, spool, or policy state silently.
- Uninstall or repair leaves the release owner unable to explain endpoint state.

## Evidence

Attach the following to the release validation report:

- Agent package version and commit SHA.
- Lab VM OS version.
- Enrollment, heartbeat, telemetry upload, task, evidence, restart, reboot, uninstall, and repair timestamps.
- Links or paths to server logs, agent logs, handoff JSON, and raw evidence refs.
