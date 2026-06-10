# Open EDR + MDR System Spec

Status: Draft v0.1  
Owner goal: build an owned EDR + MDR system that can replace the Fidelis Endpoint toolkit capability inside `FidelisMDR_alertbased`, without endpoint blocking/containment in the first product scope.

## 1. Product intent

Build a read-first EDR + MDR platform with our own endpoint layer and MDR workflow.

The system must:

1. Provide every read-only/evidence function currently used by the FidelisMDR alert-based toolkit.
2. Collect endpoint telemetry expected from an EDR: command line, process tree, network flows, DNS, file, registry, auth/logon, persistence, and endpoint health.
3. Normalize all telemetry into a vendor-neutral schema.
4. Generate alerts and support MDR investigation/case workflow.
5. Avoid blocking/containment by default: no isolation, kill process, delete file, registry modification, or endpoint tampering in v1.
6. Keep a future-safe interface so response actions can be added later behind approval and audit controls.

Non-goal for v1:

- Kernel-driver anti-malware prevention.
- Inline blocking.
- Autonomous remediation.
- Stealth/tamper-resistant adversarial agent hardening.
- Full SIEM replacement.

## 2. Existing FidelisMDR parity target

The current `/opt/FidelisMDR_alertbased` toolkit exposes these relevant capabilities.

### 2.1 Alert APIs

Must support equivalent functions:

- `list_alerts(limit, time range, filters)`
- `get_alert_by_id(alert_id)`
- alert severity mapping
- alert MITRE mapping
- alert raw evidence preservation
- alert identity extraction: rule, time, host, user, process, hash, target IDs

Acceptance criteria:

- Given an alert ID, MDR can retrieve normalized alert identity and raw source evidence.
- Alerts can be filtered by tenant, host, severity, rule, MITRE technique, time range, source.
- All alert records carry immutable raw payload references.

### 2.2 Endpoint inventory/context

Must support equivalent functions:

- `get_endpoint_context(hostname?, ip_address?)`
- `list_endpoints`
- `search_endpoint_by_ip`
- endpoint online/agent health preflight

Required fields:

- tenant/customer ID
- hostname
- FQDN if available
- primary IPs
- MACs if available
- OS name/version/build
- architecture
- agent version
- agent connected/last seen
- enrollment time
- user/session hints
- endpoint role/tags
- isolation state field, even if always false in v1
- installed sensor sources: sysmon, wazuh, osquery, velociraptor, falco, tetragon, native-agent

Acceptance criteria:

- MDR can verify whether an endpoint exists and whether evidence collection is likely to succeed.
- Endpoint context can be returned within 2 seconds for a known host from indexed state.

### 2.3 Event querying

Must support equivalent functions:

- `query_events`
- `query_events_v3`-style structured criteria
- `count_events`
- `query_related_events(entity_type, column, value, time window)`
- `get_exact_event(target_id/event_id)`

Required query dimensions:

- tenant
- host
- user
- process name
- process ID
- parent process ID
- command line contains/exact
- file path
- hash MD5/SHA1/SHA256
- remote IP/port
- domain/DNS query
- registry path/key/value
- event type
- source tool
- MITRE tag
- time range

Acceptance criteria:

- Query API can reproduce baseline Fidelis investigation checks without knowing which backend sensor produced the event.
- Queries are stable across Wazuh/Sysmon/osquery/Velociraptor/Falco/Tetragon backends.

### 2.4 Process chain

Must support equivalent function:

- `trace_process_chain(alert_id?, target_id?, event_time?, max_depth)`

Required data:

- process GUID/event ID if available
- PID
- parent PID
- image path
- command line
- user
- working directory if available
- hashes/signature where available
- start/end time where available
- children of suspicious parent process

Acceptance criteria:

- For a process alert, MDR can rebuild parent chain and relevant child processes for the alert window.
- If PID reuse prevents certainty, result must show confidence and missing links.

### 2.5 Behavior context

Must support equivalent function:

- `query_behavior_context(...)`

Required event classes:

- process start/end
- command line
- script interpreter execution
- file create/modify/delete/rename
- registry create/modify/delete
- service creation/modification
- scheduled task creation/modification
- startup/autorun changes
- module/image load where available
- process access/injection indicators where available
- security product status changes where available

Acceptance criteria:

- Baseline MDR check `behavior_context` can answer: what happened near alert time on the endpoint?
- Events can be correlated by host, user, process ID, process GUID, hash, and time window.

### 2.6 Network context

Must support equivalent functions:

- `query_network_context(...)`
- `query_process_network_context(...)`

Required data:

- local IP/port
- remote IP/port
- protocol
- direction when available
- process name/PID/process GUID
- user when available
- DNS query and resolved answer if available
- TLS SNI/cert metadata if available from network sensor, optional for endpoint v1
- connection timestamp and duration where available
- bytes in/out where available

Acceptance criteria:

- MDR can answer whether the alert process or its parent/children made network connections.
- MDR can hunt all endpoints that contacted an IP/domain in a time range.

### 2.7 Indicator hunting/prevalence

Must support equivalent functions:

- `hunt_indicator(indicator)`
- `query_related_events`
- `indicator_prevalence`

Indicators:

- hash
- file path
- process name
- command line fragment
- IP
- domain
- URL if available
- registry key/path
- user
- endpoint name

Acceptance criteria:

- MDR can determine whether an alert is isolated to one host or appears across the organization.
- Prevalence results include counts by host, user, process, and first/last seen.

### 2.8 Read-only scripts / artifact collection

Must support equivalent functions:

- `list_available_scripts`
- `list_fidelis_tasks`
- `run_readonly_script`
- `get_script_job_results`
- `get_script_job_targets`

Initial artifact catalog must include equivalents for current allowlisted Fidelis scripts:

- Agent Rules
- AntiVirus Information
- ARP Cache
- Autoruns
- Certificates
- CPU Load
- Disk Volumes
- DNS Cache
- File Exists
- File Hash
- Get Agent Config
- Hotfix Search By KB Number
- Process List
- Restore Points List
- Routing Table
- SpectreMeltdown
- Startup Programs
- Unquoted Service Paths
- Unquoted Uninstall Paths
- Windows Features
- Windows Firewall Status

Additional recommended artifacts:

- logged-on users
- local users/groups
- services
- scheduled tasks
- recent PowerShell history/logs
- recent Windows Security events
- recent Sysmon events
- browser downloads/history metadata, if policy permits
- installed software
- network connections
- listening ports
- suspicious file stat/hash

Acceptance criteria:

- Read-only artifact execution has job ID, status, target status, start/end time, stdout/stderr or structured rows, and raw evidence storage.
- Endpoint connectivity preflight blocks jobs when the agent is offline.
- No artifact may modify endpoint state in v1.

### 2.9 Client file/manual evidence request

Must support equivalent functions:

- `request_client_files`
- `analyze_client_logs`

Acceptance criteria:

- Analyst can create a structured evidence request when remote collection is insufficient.
- Uploaded logs/files can be attached to case evidence and analyzed without mixing them into endpoint telemetry as trusted source events.

### 2.10 Excluded high-impact Fidelis functions for v1

These exist in Fidelis toolkit but must be disabled/not implemented in v1 runtime:

- `isolate_host`
- `terminate_process`
- `delete_endpoint`
- `execute_containment_script`
- delete file
- network isolation remove/add

Spec requirement:

- APIs may exist as stubs returning `blocked_by_policy` for interface compatibility.
- All high-impact calls must be audited even when blocked.

## 3. Telemetry requirements

### 3.1 Windows endpoint telemetry

V1 scope: Windows first. Linux/macOS/container are not customer-facing v1 agent targets.

Minimum viable Windows telemetry:

Collection strategy:

- Implement as our own Windows service/agent.
- Collect Windows native events and ETW directly where practical.
- Do not require customer-side Sysmon installation.
- Use Sysmon-like semantics as a reference event model for process, network, DNS, file, and registry telemetry.
- Preserve raw Windows event/ETW fields alongside normalized events.

- Process creation with full command line.
- Parent/child process relationship.
- Process hash where possible.
- Process signer/publisher where possible.
- Network connection with process attribution.
- DNS query with process attribution where possible.
- File creation/modification of suspicious paths.
- Registry persistence paths.
- Scheduled task changes.
- Service creation/modification.
- Logon/logoff/auth failures.
- PowerShell execution/logs where available.
- WMI/remote execution events where available.
- Agent heartbeat and health.

Preferred v1 implementation stack:

- Our own Windows service/agent for process/network/DNS/file/registry/auth telemetry.
- Windows Event Log and ETW providers where practical.
- Built-in endpoint state/inventory collectors inspired by osquery.
- Built-in read-only artifact collectors inspired by Velociraptor.
- Backend alert/rule engine inspired by Wazuh/Sigma, not a required Wazuh deployment.

### 3.2 Linux endpoint telemetry

Deferred beyond v1. Keep the normalized schema compatible, but do not block Windows v1 on Linux support.

Minimum viable Linux telemetry:

- process exec with argv/command line
- parent process
- user/uid/euid
- network connect/listen
- DNS where available
- file writes in sensitive paths
- service/systemd changes
- cron changes
- auth logs/sudo/ssh
- package install/removal
- agent heartbeat

Preferred source stack:

- auditd/eBPF/Tetragon for exec/network.
- Wazuh for log/FIM/alert forwarding.
- osquery for state/inventory.
- Velociraptor for artifacts.
- Falco for runtime detections.

### 3.3 Container/Kubernetes telemetry

Minimum viable telemetry:

- container process execution
- container image/pod/namespace metadata
- network connect
- file writes to sensitive locations
- privilege escalation indicators
- host mount/container escape indicators

Preferred source stack:

- Tetragon/Falco.
- Kubernetes audit logs where available.

## 4. Normalized schema

Every event must normalize to `NormalizedEvent`.

Required common fields:

- `id`
- `tenant_id`
- `source`
- `source_event_id`
- `event_type`
- `timestamp`
- `ingested_at`
- `host`
- `ip_address`
- `user`
- `severity`
- `mitre[]`
- `raw_ref`
- `raw_hash`

Process fields:

- `process_guid`
- `process_id`
- `process_name`
- `process_path`
- `command_line`
- `working_directory`
- `parent_process_guid`
- `parent_process_id`
- `parent_process_name`
- `parent_command_line`
- `hash_md5/hash_sha1/hash_sha256`
- `signature_status`
- `publisher`

Network fields:

- `local_ip`
- `local_port`
- `remote_ip`
- `remote_port`
- `protocol`
- `direction`
- `domain`
- `dns_answers[]`
- `url`
- `bytes_in/out`

File fields:

- `file_path`
- `file_name`
- `file_extension`
- `file_size`
- `hash_*`
- `file_operation`

Registry fields:

- `registry_key`
- `registry_value_name`
- `registry_value_data`
- `registry_operation`

Auth fields:

- `logon_type`
- `source_ip`
- `target_user`
- `auth_result`

## 5. Architecture

```text
Endpoint sensors
  Sysmon / Wazuh agent / osquery / Velociraptor / Falco / Tetragon / future native agent
        ↓
Local spool + secure transport
        ↓
Collector Gateway
        ↓
Normalizer
        ↓
Event Store + Raw Evidence Store
        ↓
Detection / Correlation Engine
        ↓
Alert Store
        ↓
MDR Case Workflow
        ↓
Read-only Evidence Collection
```

### 5.1 Components

#### Endpoint sensor bundle

Responsible for:

- collecting telemetry
- local buffering
- signing/encrypting transport
- heartbeat
- executing read-only artifact jobs

#### Collector Gateway

Responsible for:

- authentication/mTLS
- tenant routing
- rate limiting/backpressure
- raw event acceptance
- write-ahead queue

#### Normalizer

Responsible for:

- source-specific parsing
- schema normalization
- event type mapping
- entity extraction
- raw evidence reference generation

#### Event Store

Responsible for:

- time-range query
- endpoint query
- indicator query
- process/network correlation
- retention policy

Candidate stores:

- OpenSearch for MVP search/analytics.
- ClickHouse for high-volume long-term telemetry.
- PostgreSQL for metadata/cases/config.
- Object storage/filesystem for raw evidence.

#### Detection Engine

Responsible for:

- Sigma-like rules
- Wazuh/Falco alert ingestion
- correlation/dedup
- MITRE mapping
- severity/confidence
- alert suppression/allowlist

#### MDR Case Layer

Responsible for:

- case creation
- analyst notes
- evidence timeline
- investigation checklist
- customer report
- escalation/notification


### 5.5 V1 scale target

### 5.8 Communication authentication

V1 default: HTTPS with agent credential/signed requests or short-lived agent tokens.

Requirements:

- All agent/server communication uses TLS.
- After enrollment, agent authenticates with its own credential, not the enrollment token.
- Requests must be scoped to one `agent_id` and one `tenant_id`.
- Backend must verify agent status, revocation state, tenant binding, and request freshness.
- Credentials must support rotation and revocation.
- mTLS is not required for the first intranet validation slice, but the protocol and identity model must not prevent future mTLS support.

Future high-security profile:

- mTLS with tenant/agent certificates.
- Certificate lifecycle automation.
- Optional private CA per deployment or tenant.

### 5.9 Development sequence: intranet-first, multi-tenant-ready

Build order:

1. Intranet single-tenant vertical slice.
2. Agent enrollment/heartbeat/upload/tasking loop.
3. EDR telemetry collection and server-side detection loop.
4. MDR query/task/evidence workflow.
5. Multi-tenant hardening and scale tests.
6. Internet-facing/proxy/NAT production hardening.

Important constraint:

- Even during the single-tenant intranet slice, all schemas and APIs must carry `tenant_id`.
- The first tenant can be `default` or `lab`, but code must not assume global single tenant.
- Do not postpone tenant boundaries in data models; only postpone full multi-tenant operations/UI/hardening.

Why:

- Intranet validation proves the core EDR loop quickly.
- Keeping `tenant_id` from day one avoids painful rewrites later.
- Multi-tenant security can be hardened after telemetry/tasking/detection are proven.

### 5.7 Agent enrollment and identity

V1 enrollment uses tenant-scoped enrollment tokens plus agent-generated identity.

Enrollment flow:

1. Backend/operator creates an enrollment token for one tenant.
2. Token has expiry, max-use count, optional installer binding, and revocation status.
3. Installer receives token via command-line argument, config file, MDM/RMM deployment variable, or generated tenant installer.
4. On first start, agent generates `agent_id` and local key pair.
5. Agent calls enrollment API with token, public key, host identity, and agent metadata.
6. Backend validates token and binds the agent to exactly one `tenant_id`.
7. Backend returns long-term agent credential/certificate and initial config.
8. Agent stores credential securely using Windows-protected storage where possible.
9. Future communication uses agent credential/certificate, not the enrollment token.

Security requirements:

- Enrollment token must never become the long-term credential.
- Enrollment tokens must be tenant-scoped, revocable, expiring, and optionally use-count limited.
- Agent credential rotation must be supported.
- Agent decommission/revoke must invalidate future communication.
- Duplicate/reinstalled host handling must be defined by policy: new agent ID by default, optional reassociation by hardware/host fingerprint with analyst approval.

### 5.6 Multi-tenant requirement

Multi-tenancy is a v1 hard requirement.

Storage model decision:

- V1 uses shared storage for events, alerts, tasks, artifacts, cases, and audit logs.
- Every row/document/object must include `tenant_id`.
- `tenant_id` must be part of partition/routing/index strategy where supported.
- API/service layer must inject tenant filters server-side; clients/operators cannot supply or override tenant scope freely.
- Cross-tenant queries are admin-only and must be explicitly audited.
- Storage abstraction must support future migration of large tenants to dedicated indexes/tables/partitions.
- Agent protocol remains tenant-scoped and should not change if backend storage is later split per tenant.

Requirements:

- Every agent belongs to exactly one tenant/customer at enrollment time.
- Every event, alert, task, artifact, case, raw evidence object, and audit log carries `tenant_id`.
- Backend APIs must enforce tenant isolation before query execution and before object retrieval.
- Agent tokens/certificates are tenant-scoped.
- Task assignment must verify that the operator, task, and target agent are in the same tenant scope.
- Detection rules may be global, tenant-enabled, tenant-disabled, or tenant-overridden.
- Retention policy may be tenant-specific later, even if v1 uses a global default.
- Storage indexes/tables may be shared in v1, but tenant filters and access control are mandatory.
- Future option: large tenants can be moved to dedicated indexes/storage partitions without changing the agent protocol.

V1 platform target scale: at least 10,000 active Windows endpoints across multiple tenants.

Design assumptions:

- At least 10,000 agents send heartbeat on configurable intervals.
- At least 10,000 agents upload batched telemetry with high-value immediate flush.
- Backend can assign/read task state for any endpoint.
- Detection engine can process normal endpoint telemetry load from at least 10,000 agents.
- Pilot deployments may start at 100-300 endpoints, but architecture and load tests must target at least 10,000 platform-wide endpoints.
- Do not overbuild for 100k endpoints in v1, but avoid choices that make 50k+ impossible later.

Initial load-test targets:

- 10,000 concurrent registered agents across multiple tenants.
- heartbeat interval: 30-60 seconds configurable.
- task polling interval: 10-30 seconds configurable.
- telemetry upload interval: 5-30 seconds configurable or batch-size triggered.
- backend must survive temporary reconnect storm after network outage.

### 5.4 Task delivery mode

V1 uses agent-initiated polling.

Requirements:

- Agent calls backend `POST /tasks/claim` or equivalent every configurable 10-30 seconds.
- Agent must not require inbound firewall/NAT openings.
- Heartbeat response may include `tasks_pending=true` to ask the agent to claim immediately.
- Task claims must be atomic so one task is not executed twice by the same or different agent.
- Tasks must have timeout, lease, retry, and cancellation states.
- Future modes may add long-poll, WebSocket, MQTT, or gRPC stream, but they are not v1 requirements.

Task state model:

```text
queued -> claimed -> running -> succeeded|failed|timed_out|cancelled|blocked_by_policy
```

### 5.3 Agent upload mode

V1 uses hybrid upload.

Normal telemetry:

- Batch upload every configurable interval, default 5-30 seconds.
- Also flush when batch size reaches configured threshold.
- Apply backpressure to avoid endpoint/network overload.

High-value events:

- Flush immediately or near-immediately.
- Examples: suspicious PowerShell tag, suspicious service/task creation, IOC hit, agent health critical, telemetry collector failure.

Task results:

- Upload immediately after task completion.
- If offline, persist in local spool and replay after reconnect.

Offline behavior:

- Agent writes telemetry/results to local encrypted or access-controlled spool.
- Spool has size/time limits from backend policy.
- Oldest low-value telemetry may be dropped first under pressure; task results and high-value events have higher priority.

### 5.2 Single-agent deployment requirement

Customer-facing deployment must be one agent.

Implementation language decision:

- Agent core language: Go.
- Windows service, local queue/spool, TLS transport, config receiver, heartbeat, and artifact executor are implemented in Go.
- Windows native events/ETW collectors should be implemented in Go first using Windows API bindings.
- Small C/C++ shims are allowed only for low-level Windows APIs that are impractical or unstable from Go.
- Backend/MDR integration may remain Python/current stack.

The agent must include or implement these modules behind one service/installer:

- telemetry collector
- local event spool
- secure transport client
- policy/config receiver
- read-only artifact executor
- health/heartbeat reporter
- upgrade/uninstall lifecycle

The system may use open-source projects as design references, test data sources, or internal optional integrations, but the standard customer endpoint deployment must not require multiple separate agents.

### 6.0 Detection placement decision

V1 detection authority lives on the server/backend.

Agent responsibilities:

- collect telemetry
- preserve raw fields
- attach lightweight tags where cheap and deterministic, e.g. `script_interpreter`, `encoded_command_hint`, `network_connection`, `persistence_location`
- optionally suppress extremely noisy non-security events only by signed backend policy
- never make final severity/case decisions in v1

Backend responsibilities:

- normalize events
- run detection rules
- correlate multiple events
- enrich indicators
- assign severity/confidence
- generate alerts/cases
- keep detection logic versioned and auditable

Reason:

- MDR analysts need centralized, versioned, auditable detection logic.
- Server-side rules can be updated without endpoint upgrades.
- Agent stays simpler and safer.
- Future local detection can be added for offline mode or high-value detections after v1.

## 6. Detection and alert requirements

Rule types:

- static IOC match
- Sigma-like event match
- behavior sequence/correlation
- prevalence/anomaly hints
- source-native alert passthrough

Required alert fields:

- alert ID
- tenant
- rule ID/version
- title/description
- severity/confidence
- MITRE tactic/technique
- host/user/process summary
- evidence event refs
- first/last seen
- dedup/correlation key
- recommended baseline checks

Minimum built-in detections:

- encoded PowerShell
- suspicious script interpreter from Office/browser/download path
- credential dumping indicators
- suspicious scheduled task/service creation
- autorun registry persistence
- suspicious outbound network by scripting process
- lateral movement/auth anomalies
- known malicious hash/IP/domain
- endpoint agent offline/disabled

## 7. Read-only safety policy

v1 mode: `read_only`.

Allowed:

- query telemetry
- collect read-only endpoint state
- hash files
- list files only when scoped
- read selected logs/artifact outputs
- collect diagnostic logs

Blocked:

- isolate host
- kill process
- delete file
- write file
- modify registry
- change firewall
- install/uninstall software
- reboot/logoff
- memory/disk acquisition unless separately approved as evidence collection v2

Every tool has:

- risk level
- required inputs
- allowed roles
- tenant scope
- audit trail
- timeout
- output size limit

## 7.5 First build milestones: agent loop + EDR detection loop

Storage retention is intentionally deferred. Before deciding how long to store data, build the smallest real EDR loop: one agent collects endpoint behavior, sends it back, backend normalizes it, detection rules generate alerts, and MDR can task the agent for read-only evidence.

Goal:

- Prove that one Windows agent can collect EDR telemetry, enroll, heartbeat, receive tasks, locally spool data/results, upload data back to the MDR backend, and trigger basic detections from collected behavior.

Milestone name: `M0 Agent Transport + Telemetry + Detection Loop`

Required agent features:

1. Install/run as a Windows service.
2. Generate or receive a unique agent ID.
3. Enroll to backend with tenant/customer identity.
4. Send heartbeat with hostname, OS, IP, agent version, uptime, and health.
5. Collect minimum EDR telemetry: process creation with command line, parent PID/process tree, network connections, DNS where available, service/task changes, selected auth/PowerShell events.
6. Maintain local spool/queue for outbound telemetry/results.
7. Upload batched telemetry/results over TLS.
8. Poll or receive tasking from backend.
9. Execute only allowlisted read-only commands.
10. Return structured task status and output.
11. Persist task/audit logs locally.
12. Support config/rule update from backend.
13. Fail closed for unknown or high-impact tasks.

Required backend features:

1. Agent enrollment endpoint.
2. Heartbeat ingestion endpoint.
3. Event/result ingestion endpoint.
4. Event normalizer.
5. Minimal event store sufficient for recent query and detection testing.
6. Basic detection engine with rule loading and alert generation.
7. Task creation API.
8. Task fetch/claim API.
9. Task result API.
10. Agent inventory table.
11. Basic tenant scoping.
12. Basic auth token or mTLS design placeholder.
13. CLI/API to send a task to one agent.

Initial detection rules:

- encoded/suspicious PowerShell command line.
- script interpreter with outbound network connection.
- suspicious scheduled task/service creation.
- suspicious child process from Office/browser/download path.
- known bad hash/IP/domain IOC match.
- agent offline/telemetry gap alert.

Initial allowlisted tasks:

- `whoami` equivalent via safe API/native call, not shell where possible.
- hostname/os/ip inventory.
- process list.
- network connection list.
- service list.
- scheduled task list.
- file exists.
- file hash.

Explicitly blocked in this milestone:

- arbitrary shell execution.
- process kill.
- file delete/write.
- registry write/delete.
- host isolation.
- software install/uninstall.
- reboot/logoff.

Acceptance criteria:

- A Windows endpoint running the agent appears online in backend inventory.
- Agent sends process command line and network telemetry to backend.
- Backend normalizes telemetry into `NormalizedEvent`.
- At least one behavior rule can generate a normalized alert from agent telemetry.
- MDR can query recent events for host/process/IP/domain.
- Backend can assign a read-only task to the agent.
- Agent fetches/receives the task, executes it, and uploads structured result.
- If network is unavailable, telemetry/result is spooled locally and uploaded after reconnect.
- Unknown/high-impact task returns `blocked_by_policy`.
- No separate Sysmon/Wazuh/osquery/Velociraptor installation is required.

## 8. Implementation phases

### Phase 0 — spec and interface

Deliverables:

- `EndpointProvider` interface
- `NormalizedEvent` schema
- local JSON provider
- CLI smoke tests
- this spec

Acceptance:

- local sample data can produce alert, endpoint context, query events, process chain, indicator hunt.

### Phase 1 — Agent telemetry, detection, transport, and tasking loop

Deliverables:

- Go Windows service skeleton.
- minimum EDR telemetry collectors: process command line, parent PID, network connection, DNS where available, service/task/auth/PowerShell event hooks.
- enrollment, heartbeat, local spool, upload, and task polling.
- backend enrollment/heartbeat/ingestion/task APIs.
- event normalizer and minimal detection engine.
- initial EDR behavior rules and alert generation.
- read-only task allowlist and blocked high-impact stubs.
- minimal inventory/process/network/file-hash task results.

Acceptance:

- One installed Windows agent can send EDR telemetry back and receive safe read-only tasks from backend.
- Backend can generate at least one alert from agent telemetry.
- Existing MDR can see endpoint online/offline status, recent events, generated alerts, and task result evidence.

### Phase 2 — Native Windows agent telemetry MVP

Deliverables:

- Windows service/agent skeleton.
- Process creation collector with full command line and parent PID.
- Network connection collector with process attribution where available.
- DNS collector where available.
- File/registry persistence-focused collectors.
- Windows Event Log collectors for PowerShell/auth/service/task events.
- Local spool and secure upload protocol.
- Process/network/DNS/file/registry normalizers.
- Query API over stored events.

Acceptance:

- Can collect Windows command line and process-attributed network connections from our own agent.
- Can trace process chain for a native-agent process alert.
- No Sysmon/Wazuh/osquery/Velociraptor installation is required on the customer endpoint.

### Phase 3 — osquery/Fleet endpoint state

Deliverables:

- Fleet/osquery adapter.
- Inventory tables.
- process list/services/users/listening ports/software/startup artifacts.

Acceptance:

- `get_endpoint_context` includes inventory and last seen state.
- `run_readonly_script(process_list|startup_programs|routing_table)` has working implementation.

### Phase 4 — Velociraptor evidence collection

Deliverables:

- Velociraptor API adapter.
- artifact catalog mapped to Fidelis readonly task names.
- job submit/status/result/target APIs.

Acceptance:

- Current Fidelis allowlisted read-only scripts have equivalents or documented gaps.

### Phase 5 — Linux/container runtime

Deliverables:

- Falco/Tetragon ingestion.
- Linux process/network/file/auth normalizers.
- container metadata mapping.

Acceptance:

- Linux/container events can be queried through the same MDR APIs.

### Phase 6 — Detection/correlation engine

Deliverables:

- Sigma-like rule loader.
- correlation/dedup engine.
- MITRE mapping.
- alert generation and suppression.

Acceptance:

- Built-in detection set produces normalized alerts from endpoint telemetry.

### Phase 7 — MDR case integration

Deliverables:

- case evidence timeline
- investigation checklist execution
- report generation hooks
- customer evidence request flow

Acceptance:

- A generated alert can be investigated end-to-end without Fidelis Endpoint.

### Phase 8 — Native agent research

Deliverables:

- decision doc for native agent vs sensor bundle
- Windows ETW/Sysmon replacement analysis
- Linux eBPF/auditd replacement analysis
- secure update/identity design

Acceptance:

- We know which parts are worth building in-house and which should remain external sensors.

## 9. Test strategy

Test levels:

- schema unit tests
- normalizer tests with real sample events
- provider contract tests
- process chain reconstruction tests
- query correctness tests
- artifact job lifecycle tests
- safety policy tests
- MDR workflow integration tests

Golden datasets:

- encoded PowerShell
- Office child process
- malware hash prevalence
- suspicious DNS/network connection
- scheduled task persistence
- lateral movement via remote logon
- benign enterprise deployment false-positive case

## 10. Open design questions

These are unresolved and must be grilled one by one before implementation hardens.

1. DECIDED: v1 must include a single custom/branded customer-installed agent from the beginning. It must not require customers to install multiple visible agents.
2. DECIDED: v1 is Windows-only first. Linux/container support is deferred to later phases after Windows agent parity is stable.
3. DECIDED: Windows v1 agent collects native Windows events/ETW directly. It must not require Sysmon installation, but may use a Sysmon-like event model for schema design.
4. DECIDED: v1 Windows agent implementation language is Go. Use Go for service core, local spool, transport, config, artifact execution, and Windows API/ETW integration first; allow small C/C++ shims only where Go bindings are insufficient.
5. DEFERRED: event retention defaults to Hot 30 days + Warm 180 days, but this does not block the first agent milestone. First milestone is transport/tasking skeleton.
4. Is OpenSearch acceptable for MVP storage, or do we need ClickHouse early because endpoint telemetry volume will be high?
5. Should raw command lines be stored as-is, or do we need PII/secret redaction at ingestion?
6. DECIDED: v1 detection is server-side first. Agent performs lightweight local tagging/prefiltering only; backend normalizer/rule engine generates authoritative alerts.
7. DECIDED: agent upload mode is hybrid. Normal telemetry is batched; high-value events and task results flush immediately; offline data is spooled and replayed after reconnect.
8. DECIDED: v1 task delivery uses agent-initiated polling. Agent polls `/tasks/claim` every configurable 10-30 seconds; heartbeat may hint immediate claim. No inbound customer endpoint port is required. Long-poll/WebSocket/gRPC stream are future upgrades.
9. DECIDED: v1 platform target scale is at least 10,000 active Windows endpoints across multiple tenants. Pilot may start smaller, but ingestion, heartbeat, tasking, detection, and MDR workflow must be designed/tested against 10,000 platform-wide active agents. Multi-tenant isolation is required from day one.
10. DECIDED: v1 multi-tenant storage uses shared indexes/tables with mandatory `tenant_id` ACL and partition keys. The storage abstraction must allow large tenants to move to dedicated indexes/partitions later without changing the agent protocol.
11. DECIDED: agent enrollment uses tenant-scoped enrollment tokens plus agent-generated key pairs. Enrollment tokens are short-lived/revocable/tenant-scoped; after enrollment, the agent authenticates with its own long-term credential/certificate.
12. DECIDED: v1 communication authentication defaults to HTTPS with agent credential/signed requests or short-lived agent tokens. mTLS is reserved as a future high-security deployment profile.
13. DECIDED: development sequence starts with an intranet single-tenant vertical slice, while keeping tenant_id and tenant boundaries in the schema/API from day one. Multi-tenant production behavior is enabled after the inner loop is proven.
7. Are customers allowed to run Velociraptor/osquery/Wazuh agents, or do they require one branded agent installer?
8. Does MDR need near-real-time alerting under 1 minute, or is 5-15 minutes acceptable?
9. What customer isolation model is required: separate index/db per tenant or shared storage with tenant ACL?
10. What evidence collection is acceptable legally/policy-wise: process list only, file hash, selected file download, browser artifacts?

## 11. Recommended v1 position

Recommended answer:

Build v1 as a single customer-installed agent, not a visible bundle of multiple third-party agents.

Important product decision:

- Customers install exactly one branded agent/installer.
- The agent may internally reuse open-source techniques, event schemas, or embedded components where licensing and operations allow, but the customer-facing deployment must be one agent.
- Do not require customers to separately install Sysmon + Wazuh + osquery + Velociraptor.
- Open-source EDR projects remain reference designs and optional backend inspirations, not the v1 deployment model.

Start with:

- Windows-first single native/service agent.
- Native Windows telemetry collection for command line, process tree, network flow, DNS, file, registry, auth, persistence, and agent health.
- Built-in read-only artifact collection equivalent to the Fidelis allowlisted scripts.
- Secure local spool + collector transport.
- OpenSearch or ClickHouse for event/search storage.
- PostgreSQL for MDR cases/config.
- Object storage/filesystem for raw evidence.
- No blocking or containment.

Why:

- This matches the product requirement: one customer-side agent.
- It avoids customer operational friction and agent sprawl.
- It still lets us absorb the good parts of Sysmon/osquery/Velociraptor/Falco/Tetragon into our own design.
- It is harder than sensor fusion, so the implementation phases must prioritize a narrow Windows MVP first.
