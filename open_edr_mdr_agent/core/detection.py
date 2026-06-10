from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .rules import GenericRule, detect_with_rules

from .schemas import Alert, EventType, NormalizedEvent, Severity, Source


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    title: str
    severity: Severity
    mitre: tuple[str, ...]


POWERSHELL_ENCODED = DetectionRule(
    rule_id="builtin.windows.powershell.encoded_command",
    title="Suspicious encoded PowerShell command",
    severity=Severity.HIGH,
    mitre=("T1059.001",),
)

SCRIPT_NETWORK = DetectionRule(
    rule_id="builtin.windows.script_interpreter_network",
    title="Script interpreter network connection",
    severity=Severity.MEDIUM,
    mitre=("T1059", "T1105"),
)

SUSPICIOUS_SERVICE_TASK = DetectionRule(
    rule_id="builtin.windows.persistence.service_or_task_change",
    title="Suspicious service or scheduled task change",
    severity=Severity.MEDIUM,
    mitre=("T1053", "T1543"),
)

IOC_MATCH = DetectionRule(
    rule_id="builtin.ioc.match",
    title="Known bad indicator match",
    severity=Severity.HIGH,
    mitre=("T1204",),
)

SCRIPT_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
ENCODED_RE = re.compile(r"(?i)(-|/)(enc|encodedcommand|e)\b")
SERVICE_TASK_RE = re.compile(r"(?i)\b(schtasks|new-scheduledtask|create-service|new-service|sc\.exe\s+create)\b")
BUILTIN_BAD_IPS = {"203.0.113.10"}  # Documentation TEST-NET value used as a safe built-in smoke-test IOC.
BUILTIN_BAD_DOMAINS = {"malicious.example"}
BUILTIN_BAD_HASHES = {"0" * 64}


def detect_event(event: NormalizedEvent, custom_rules: Optional[Iterable[GenericRule]] = None) -> List[Alert]:
    alerts: List[Alert] = []
    cmd = event.command_line or ""
    proc = (event.process_name or "").split("\\")[-1].lower()

    if event.event_type == EventType.PROCESS_START:
        if proc in {"powershell.exe", "pwsh.exe"} and ENCODED_RE.search(cmd):
            alerts.append(_alert_from_event(event, POWERSHELL_ENCODED, cmd))
        if SERVICE_TASK_RE.search(cmd):
            alerts.append(_alert_from_event(event, SUSPICIOUS_SERVICE_TASK, cmd))

    if event.event_type == EventType.NETWORK_CONNECTION and proc in SCRIPT_NAMES:
        alerts.append(_alert_from_event(event, SCRIPT_NETWORK, f"{event.process_name} connected to {event.remote_ip}:{event.remote_port}"))

    if _ioc_hit(event):
        alerts.append(_alert_from_event(event, IOC_MATCH, f"IOC match in event {event.id}"))

    if custom_rules:
        alerts.extend(detect_with_rules(event, custom_rules))

    return alerts


def detect_many(events: Iterable[NormalizedEvent], custom_rules: Optional[Iterable[GenericRule]] = None) -> List[Alert]:
    alerts: List[Alert] = []
    for event in events:
        alerts.extend(detect_event(event, custom_rules=custom_rules))
    return alerts


def _ioc_hit(event: NormalizedEvent) -> bool:
    return bool(
        (event.remote_ip and event.remote_ip in BUILTIN_BAD_IPS)
        or (event.domain and event.domain.lower() in BUILTIN_BAD_DOMAINS)
        or (event.hash_sha256 and event.hash_sha256.lower() in BUILTIN_BAD_HASHES)
        or (event.hash_md5 and event.hash_md5.lower() in BUILTIN_BAD_HASHES)
    )


def _alert_from_event(event: NormalizedEvent, rule: DetectionRule, description: Optional[str]) -> Alert:
    return Alert(
        alert_id=f"{rule.rule_id}:{event.id}",
        title=rule.title,
        severity=rule.severity,
        timestamp=event.timestamp,
        host=event.host,
        user=event.user,
        process_name=event.process_name,
        description=description,
        mitre=list(rule.mitre),
        source=Source.INTERNAL,
        raw={"rule_id": rule.rule_id, "event_id": event.id, "tenant_id": event.tenant_id},
    )
