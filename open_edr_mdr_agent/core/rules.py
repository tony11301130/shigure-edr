from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Optional

import yaml

from .schemas import Alert, NormalizedEvent, Severity, Source


@dataclass(frozen=True)
class RuleCondition:
    field: str
    op: str
    value: Any


@dataclass(frozen=True)
class GenericRule:
    rule_id: str
    title: str
    severity: Severity = Severity.MEDIUM
    mitre: tuple[str, ...] = field(default_factory=tuple)
    event_type: Optional[str] = None
    conditions: tuple[RuleCondition, ...] = field(default_factory=tuple)
    description: str = ""


def load_rules(path: str | Path | None) -> List[GenericRule]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    rules = []
    for item in data.get("rules", []):
        rules.append(GenericRule(
            rule_id=str(item["rule_id"]),
            title=str(item["title"]),
            severity=Severity(str(item.get("severity", "medium")).lower()),
            mitre=tuple(str(x) for x in item.get("mitre", []) or []),
            event_type=item.get("event_type"),
            conditions=tuple(RuleCondition(field=str(c["field"]), op=str(c.get("op", "equals")), value=c.get("value")) for c in item.get("conditions", []) or []),
            description=str(item.get("description") or ""),
        ))
    return rules


def detect_with_rules(event: NormalizedEvent, rules: Iterable[GenericRule]) -> List[Alert]:
    alerts: List[Alert] = []
    for rule in rules:
        if rule.event_type and event.event_type.value != rule.event_type:
            continue
        if all(_match(event, cond) for cond in rule.conditions):
            alerts.append(Alert(
                alert_id=f"{rule.rule_id}:{event.id}",
                title=rule.title,
                severity=rule.severity,
                timestamp=event.timestamp,
                host=event.host,
                user=event.user,
                process_name=event.process_name,
                description=rule.description or f"Rule {rule.rule_id} matched event {event.id}",
                mitre=list(rule.mitre),
                source=Source.INTERNAL,
                raw={"rule_id": rule.rule_id, "event_id": event.id, "tenant_id": event.tenant_id},
            ))
    return alerts


def _match(event: NormalizedEvent, cond: RuleCondition) -> bool:
    actual = getattr(event, cond.field, None)
    op = cond.op.lower()
    expected = cond.value
    if op == "exists":
        return actual is not None and actual != ""
    if actual is None:
        return False
    actual_s = str(actual)
    expected_s = str(expected)
    if op == "equals":
        return actual_s == expected_s
    if op == "iequals":
        return actual_s.lower() == expected_s.lower()
    if op == "contains":
        return expected_s in actual_s
    if op == "icontains":
        return expected_s.lower() in actual_s.lower()
    if op == "regex":
        return re.search(expected_s, actual_s) is not None
    raise ValueError(f"unsupported rule condition op: {cond.op}")
