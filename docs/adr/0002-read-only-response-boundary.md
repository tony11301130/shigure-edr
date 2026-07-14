# ADR 0002: Read-Only Response Boundary

## Status

Accepted

## Context

Shigure's commercial MVP is a Windows intranet MDR investigation EDR. The agent may run with privileged local service rights, so endpoint tasking must not expose destructive response as a normal analyst workflow.

The MVP needs read-only investigation and bounded evidence collection, while mutating response actions require later RBAC, approvals, action history, rollback semantics, and Windows validation.

## Decision

The default response policy is `read_only_v1`.

Normal analyst task catalog APIs expose only read-only and bounded evidence tasks. Mutating or destructive prototype actions are not shown in the MVP catalog.

The server enforces the policy when tasks are requested. Unknown tasks, destructive tasks, explicit-dispatch response stubs, and endpoint-local copy/staging are recorded as `blocked_by_policy` tasks with policy metadata instead of being dispatched.

The agent enforces the same policy before execution. Even if a disallowed task reaches an endpoint, the agent returns a `blocked_by_policy` result and does not call the destructive implementation.

Allowed evidence collection must include bounded limits, reason, and case context. File evidence uploads validate size and SHA256 and store raw evidence references.

Task audit metadata includes:

- `policy_version`
- `response_mode`
- `requested_by`
- `risk`
- `destructive`
- `reason` and `case_id` when applicable
- `raw_ref` and `raw_hash` after completion

## Consequences

The MVP can support investigation workflows without promising prevention or remediation. Prototype response code can remain in the tree as blocked future capability, but it cannot be exposed or executed by default.

Reopening destructive response requires a separate decision and implementation work for RBAC, approvals, immutable audit, endpoint-side signed policy, rollback semantics, and Windows lab validation.
