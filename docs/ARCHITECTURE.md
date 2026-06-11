# Architecture

## Product goal

Build an owned EDR + MDR system similar in shape to commercial EDR/MDR products:

```text
Endpoint sensors / agent
  -> collector / gateway
  -> normalized event schema
  -> detection + correlation
  -> MDR case workflow
  -> evidence collection / optional response
```

## Design decision

Do not start with a kernel/driver agent. Start with open-source sensor fusion:

```text
Sysmon + Wazuh + osquery + Velociraptor + Falco/Tetragon
        ↓
Shiori Agent Provider Layer
        ↓
Fidelis-like MDR tool interface
        ↓
Existing FidelisMDR_alertbased workflow
```

This gives us production learning before writing fragile endpoint internals.

## Core abstractions

### NormalizedEvent

One event shape for all sensor data.

Important fields:

- source
- event_type
- tenant_id
- host
- user
- process_name / process_id
- parent_process_name / parent_process_id
- command_line
- file_path / hash
- remote_ip / remote_port
- domain
- registry_key
- mitre
- raw

### EndpointProvider

Provider contract designed to match the Fidelis Endpoint toolkit:

```python
list_alerts()
get_alert_by_id(alert_id)
get_endpoint_context(hostname/ip)
query_events(...)
trace_process_chain(...)
hunt_indicator(indicator)
list_readonly_scripts()
run_readonly_script(helper, host, ...)
```

### CompositeEndpointProvider

Merges multiple providers behind one interface.

Example:

```text
WazuhProvider.list_alerts
SysmonProvider.query_events
FleetOsqueryProvider.get_endpoint_context
VelociraptorProvider.run_readonly_script
FalcoProvider.query_events
```

The MDR layer does not need to know which tool produced the evidence.

## Capability parity with Fidelis Endpoint toolkit

| Fidelis capability | Open-source replacement path |
|---|---|
| list alerts | Wazuh alerts / Sigma engine |
| get alert by id | Wazuh/OpenSearch alert store |
| endpoint context | osquery/Fleet + Wazuh agent inventory |
| query behavior context | Sysmon/Wazuh/OpenSearch |
| query network context | Sysmon Event ID 3, Tetragon, Falco |
| DNS query | Sysmon Event ID 22, DNS logs, osquery where available |
| process chain | Sysmon Event ID 1 parent PID + event timeline |
| file query/hash | Velociraptor artifact or osquery hash table |
| read-only scripts | Velociraptor artifacts / osquery packs |
| containment | future phase only, approval-gated |

## Phases

### Phase 0 — current prototype

- Define interface
- Define schemas
- Local JSONL provider
- CLI smoke tests

### Phase 1 — live ingestion

- Wazuh alert adapter
- Sysmon event adapter from Wazuh/OpenSearch/file tail
- osquery/Fleet adapter

### Phase 2 — evidence collection

- Velociraptor provider
- artifact catalog mapped to read-only helper names

### Phase 3 — detection engine

- Sigma-like rule format
- MITRE mapping
- dedup/correlation
- alert confidence and evidence timeline

### Phase 4 — in-house agent

Only after telemetry needs are proven:

- endpoint heartbeat
- local buffering
- signed config/policy
- secure update
- ETW/eBPF native collectors where needed

### Phase 5 — controlled response

- isolate host
- kill process
- collect file
- delete/quarantine file

Must be approval-gated and fully audited.
