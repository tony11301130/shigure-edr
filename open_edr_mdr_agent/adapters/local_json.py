from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from open_edr_mdr_agent.core.normalizers import falco_to_event, sysmon_to_event, wazuh_to_alert
from open_edr_mdr_agent.core.provider import EndpointProvider
from open_edr_mdr_agent.core.schemas import Alert, EndpointContext, EventType, NormalizedEvent, ScriptResult, Source


class LocalJsonProvider(EndpointProvider):
    """Development provider backed by local JSONL files.

    This lets us build and test the Fidelis-like interface before wiring real
    Wazuh/Fleet/Velociraptor APIs. Each line is a JSON object.
    """

    name = "local-json-open-edr"

    def __init__(self, root: str | Path, tenant_id: str = "default"):
        self.root = Path(root)
        self.tenant_id = tenant_id

    def _read_jsonl(self, name: str) -> List[Dict[str, Any]]:
        path = self.root / name
        if not path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def _events(self) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        events.extend(sysmon_to_event(row, self.tenant_id) for row in self._read_jsonl("sysmon.jsonl"))
        events.extend(falco_to_event(row, self.tenant_id) for row in self._read_jsonl("falco.jsonl"))
        for row in self._read_jsonl("osquery.jsonl"):
            events.append(NormalizedEvent(source=Source.OSQUERY, tenant_id=self.tenant_id, event_type=EventType.ENDPOINT_STATE, host=row.get("host"), raw=row))
        for row in self._read_jsonl("velociraptor.jsonl"):
            events.append(NormalizedEvent(source=Source.VELOCIRAPTOR, tenant_id=self.tenant_id, event_type=EventType.SCRIPT_RESULT, host=row.get("host"), raw=row))
        return events

    def list_alerts(self, limit: int = 50) -> List[Alert]:
        alerts = [wazuh_to_alert(row, self.tenant_id) for row in self._read_jsonl("wazuh-alerts.jsonl")]
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        return next((a for a in self.list_alerts(limit=10000) if a.alert_id == str(alert_id)), None)

    def get_endpoint_context(self, hostname: Optional[str] = None, ip_address: Optional[str] = None) -> List[EndpointContext]:
        matches: List[EndpointContext] = []
        for row in self._read_jsonl("endpoints.jsonl"):
            if hostname and row.get("host") != hostname:
                continue
            if ip_address and row.get("ip_address") != ip_address:
                continue
            matches.append(EndpointContext(
                host=row.get("host") or hostname or "unknown",
                ip_address=row.get("ip_address"),
                os=row.get("os"),
                agent_connected=row.get("agent_connected"),
                agent_version=row.get("agent_version"),
                isolated=row.get("isolated"),
                sources=[Source(s) for s in row.get("sources", []) if s in Source._value2member_map_],
                raw=row,
            ))
        return matches

    def query_events(self, *, host: Optional[str] = None, event_type: Optional[str] = None, indicator: Optional[str] = None, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, limit: int = 500) -> List[NormalizedEvent]:
        events = self._events()
        if host:
            events = [e for e in events if e.host == host]
        if event_type:
            events = [e for e in events if e.event_type.value == event_type]
        if indicator:
            needle = indicator.lower()
            events = [e for e in events if needle in e.model_dump_json().lower()]
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def trace_process_chain(self, *, host: str, process_id: Optional[str] = None, event_id: Optional[str] = None) -> List[NormalizedEvent]:
        events = [e for e in self._events() if e.host == host and e.event_type == EventType.PROCESS_START]
        by_pid = {e.process_id: e for e in events if e.process_id}
        current = by_pid.get(process_id) if process_id else None
        if not current and event_id:
            current = next((e for e in events if e.id == event_id), None)
        if not current:
            return []
        chain = [current]
        seen = {current.process_id}
        while current.parent_process_id and current.parent_process_id not in seen:
            parent = by_pid.get(current.parent_process_id)
            if not parent:
                break
            chain.append(parent)
            seen.add(parent.process_id)
            current = parent
        return list(reversed(chain))

    def hunt_indicator(self, indicator: str, limit: int = 500) -> List[NormalizedEvent]:
        return self.query_events(indicator=indicator, limit=limit)

    def list_readonly_scripts(self) -> List[Dict[str, Any]]:
        return [
            {"name": "process_list", "source": "osquery", "description": "List running processes."},
            {"name": "autoruns", "source": "osquery/velociraptor", "description": "List persistence/autorun locations."},
            {"name": "dns_cache", "source": "velociraptor", "description": "Collect DNS cache."},
            {"name": "file_hash", "source": "velociraptor", "description": "Hash a file path."},
        ]

    def run_readonly_script(self, helper_name: str, host: str, **kwargs: Any) -> ScriptResult:
        return ScriptResult(helper_name=helper_name, host=host, status="simulated", result={"kwargs": kwargs, "note": "LocalJsonProvider is a development stub."})
