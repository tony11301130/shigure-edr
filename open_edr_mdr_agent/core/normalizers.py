from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .schemas import Alert, EventType, NormalizedEvent, Severity, Source


def parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def severity(value: Any) -> Severity:
    text = str(value or "info").lower()
    if text.isdigit():
        level = int(text)
        # Wazuh uses 0-15-ish rule levels; many EDRs use 1-5.
        if level >= 14:
            return Severity.CRITICAL
        if level >= 10:
            return Severity.HIGH
        if level >= 7:
            return Severity.MEDIUM
        if level >= 3:
            return Severity.LOW
        return Severity.INFO
    if text in {"critical", "crit", "fatal"}:
        return Severity.CRITICAL
    if text in {"high", "error"}:
        return Severity.HIGH
    if text in {"medium", "med", "warning"}:
        return Severity.MEDIUM
    if text in {"low"}:
        return Severity.LOW
    return Severity.INFO


def sysmon_to_event(raw: Dict[str, Any], tenant_id: str = "default") -> NormalizedEvent:
    event_id = str(raw.get("EventID") or raw.get("event_id") or raw.get("event.code") or "")
    type_map = {
        "1": EventType.PROCESS_START,
        "3": EventType.NETWORK_CONNECTION,
        "11": EventType.FILE_EVENT,
        "12": EventType.REGISTRY_EVENT,
        "13": EventType.REGISTRY_EVENT,
        "22": EventType.DNS_QUERY,
    }
    return NormalizedEvent(
        source=Source.SYSMON,
        tenant_id=tenant_id,
        event_type=type_map.get(event_id, EventType.GENERIC),
        timestamp=parse_ts(raw.get("UtcTime") or raw.get("@timestamp") or raw.get("timestamp")),
        host=raw.get("Computer") or raw.get("host") or raw.get("host.name"),
        user=raw.get("User") or raw.get("user.name"),
        process_name=raw.get("Image") or raw.get("process.name"),
        process_id=str(raw.get("ProcessId") or raw.get("process.pid") or "") or None,
        parent_process_name=raw.get("ParentImage") or raw.get("process.parent.name"),
        parent_process_id=str(raw.get("ParentProcessId") or raw.get("process.parent.pid") or "") or None,
        command_line=raw.get("CommandLine") or raw.get("process.command_line"),
        file_path=raw.get("TargetFilename") or raw.get("file.path"),
        hash_sha256=raw.get("SHA256") or raw.get("hash.sha256"),
        remote_ip=raw.get("DestinationIp") or raw.get("destination.ip"),
        remote_port=int(raw["DestinationPort"]) if str(raw.get("DestinationPort", "")).isdigit() else None,
        domain=raw.get("QueryName") or raw.get("dns.question.name"),
        registry_key=raw.get("TargetObject") or raw.get("registry.path"),
        raw=raw,
    )


def wazuh_to_alert(raw: Dict[str, Any], tenant_id: str = "default") -> Alert:
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    return Alert(
        alert_id=str(raw.get("id") or raw.get("timestamp") or rule.get("id")),
        title=rule.get("description") or raw.get("title") or "Wazuh alert",
        severity=severity(rule.get("level")),
        timestamp=parse_ts(raw.get("timestamp") or raw.get("@timestamp")),
        host=agent.get("name") or raw.get("host"),
        description=raw.get("full_log") or raw.get("description"),
        mitre=[str(t) for t in (rule.get("mitre", {}).get("id") or [])],
        source=Source.WAZUH,
        raw={**raw, "tenant_id": tenant_id},
    )


def falco_to_event(raw: Dict[str, Any], tenant_id: str = "default") -> NormalizedEvent:
    output_fields = raw.get("output_fields") or {}
    return NormalizedEvent(
        source=Source.FALCO,
        tenant_id=tenant_id,
        event_type=EventType.PROCESS_START if output_fields.get("proc.name") else EventType.GENERIC,
        timestamp=parse_ts(raw.get("time") or raw.get("timestamp")),
        host=output_fields.get("host.hostname") or raw.get("hostname"),
        user=output_fields.get("user.name"),
        process_name=output_fields.get("proc.name"),
        process_id=str(output_fields.get("proc.pid") or "") or None,
        command_line=output_fields.get("proc.cmdline"),
        alert_title=raw.get("rule"),
        severity=severity(raw.get("priority")),
        raw=raw,
    )
