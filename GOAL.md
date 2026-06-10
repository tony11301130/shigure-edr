# Goal: Intranet-First Open EDR/MDR V1

## Mission

Build an in-house EDR/MDR platform for internal network deployment first, with a single installable Windows agent, a central server, MDR analyst APIs, task/job dispatch, threat hunting workflows, and a minimal V1 UI.

The system should eventually grow into multi-tenant SaaS/MSSP mode, but V1 optimizes for an intranet single-tenant deployment while preserving tenant-aware schema and API fields so multi-tenancy is not a rewrite.

## V1 Deployment Shape

```text
Windows Endpoint(s)
  └─ Open EDR MDR Agent Windows Service
      ├─ telemetry collection
      ├─ offline spool
      ├─ heartbeat
      ├─ task/job polling
      └─ read-only evidence collection

Intranet Server
  ├─ API server
  ├─ event/task/case storage
  ├─ server-side detections
  ├─ threat hunting APIs
  ├─ reverse-proxy-friendly task control plane
  └─ minimal web UI
```

## Non-Negotiable Scope Boundaries

- One branded customer-installed Windows agent.
- No requirement for customers to install Sysmon/Wazuh/osquery/Velociraptor separately.
- Open-source projects may be used as references, embedded components, adapters, or optional server-side integrations.
- Agent-to-server communication is outbound from endpoint only.
- Server controls endpoints by queuing jobs/tasks; agent polls and executes allowlisted work.
- V1 tasks are read-only investigation/evidence tasks unless explicitly changed later.
- No V1 destructive response actions:
  - no isolate host
  - no kill process
  - no delete/write file
  - no registry write/delete
  - no reboot/logoff

## Fidelis API Parity Target

The server must expose equivalents for the Fidelis-style MDR toolkit capabilities:

- `list_alerts`
- `get_alert_by_id`
- `get_endpoint_context`
- `query_events`
- `trace_process_chain`
- `hunt_indicator`
- `list_readonly_scripts`
- `run_readonly_script`
- case/evidence workflow for MDR follow-up

The implementation does not need to mimic Fidelis internals; it needs to preserve analyst capability and workflow.

## Agent Capabilities

Windows agent must support:

- Windows Service deployment.
- Enrollment with server.
- Heartbeat and config sync.
- Telemetry upload.
- Offline spool and retry.
- Task/job polling.
- Read-only task execution.
- Evidence result upload with raw hash/reference.

Telemetry targets:

- process snapshot and process ancestry
- network connections
- Windows Event Logs
- PowerShell operational logs
- Security auth events
- Service Control Manager events
- Task Scheduler events
- DNS where feasible
- registry/service/task persistence evidence where feasible

## Server Capabilities

Server must support:

- endpoint enrollment and credentials
- agent heartbeat/config policy
- event ingestion
- server-side detection rules
- YAML/custom rule loading
- raw evidence hashing/references
- task/job creation and result tracking
- MDR cases and evidence linking
- investigation APIs
- operational summary/statistics
- minimal V1 UI

## Threat Hunting Scope

Threat hunting should include:

- indicator hunt across events/alerts/evidence
- process chain reconstruction
- endpoint context aggregation
- suspicious PowerShell/script behavior
- service/task persistence hunting
- network connection hunting
- raw evidence retrieval
- case-driven investigation workflow

Future deeper hunting integrations may draw ideas or adapters from:

- osquery/Fleet query concepts
- Velociraptor artifact concepts
- Sigma-like detection rules
- Sysmon schema concepts
- Wazuh-style alert normalization

But the endpoint-facing V1 remains one branded agent.

## Minimal V1 UI

UI only needs to be good enough for intranet V1:

- dashboard / summary
- agents list
- alerts list/detail
- event search
- endpoint context
- indicator hunt
- cases/evidence
- create read-only task/job
- view task results

Polish is secondary; operational usefulness is primary.

## Current Development Rule

Continue building in small deployable vertical slices:

1. implement capability
2. add/adjust tests
3. run validation gates
4. update progress docs
5. git commit
6. continue unless blocked by a major architecture/product decision

Validation gates should normally include:

- Python tests
- Go tests
- Windows cross-build
- M0 smoke test

## Future Multi-Tenant Direction

Even though V1 is intranet-first, retain:

- `tenant_id` in schema
- tenant-scoped enrollment tokens
- tenant-scoped config
- tenant-scoped admin queries
- tenant isolation tests

Multi-tenant UI/RBAC/billing/tenant administration can come later.
