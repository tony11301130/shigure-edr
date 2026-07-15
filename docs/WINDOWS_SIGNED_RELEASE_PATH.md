# Windows Signed Release Path

This document defines the release-owner evidence required for a Shigure Windows agent package before a commercial MVP release candidate can pass the release gate.

## Artifacts

Each release candidate should publish:

- `shigure-agent.exe`
- `shigure-agent-config.json` template without a long-lived enrollment token
- `shigure-agent-package.zip`
- SHA256 checksum manifest
- release notes with commit SHA, package version, and known gaps

Legacy prototype packages may use Shiori names only when the release owner explicitly validates the `naming=shiori` compatibility path.

## Signature And Checksum Evidence

For signed releases, capture:

- Authenticode signer subject and certificate chain
- timestamp authority and timestamp
- signature verification output
- SHA256 for the binary, package, config template, and release notes

Unsigned lab builds must be marked as lab-only in the release report and cannot be promoted as production artifacts.

## Manual Upgrade Flow

1. Verify the candidate package checksum and signature.
2. Stop `ShigureAgent`.
3. Back up `C:\ProgramData\Shigure\shigure-agent-state.json`, `spool.jsonl`, and `shigure-agent-config.json`.
4. Install the candidate package.
5. Start `ShigureAgent`.
6. Confirm heartbeat reports the candidate version and preserved credential/config state.
7. Confirm queued telemetry or task results in the bounded spool are not silently lost.

## RMM Upgrade Flow

RMM deployment should run the same steps non-interactively:

- preflight checksum/signature verification
- service stop
- package install or repair
- service start
- postflight heartbeat and version check
- rollback trigger if enrollment, heartbeat, or task polling fails

The RMM job output should be attached to the release report.

## Rollback Flow

If postflight validation fails:

1. Stop `ShigureAgent`.
2. Reinstall the previous known-good package.
3. Restore the backed-up config/state/spool only if the failed upgrade changed them.
4. Start `ShigureAgent`.
5. Confirm heartbeat, credential version, policy/config version, and spool health.

Rollback must not silently mint a duplicate endpoint identity. If state is lost or intentionally reset, revoke the old credential and enroll with a fresh short-lived token.
