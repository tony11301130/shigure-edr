from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from .schemas import Alert, EndpointContext, NormalizedEvent, ScriptResult


class EndpointProvider(ABC):
    """Fidelis-like endpoint provider contract.

    This is the compatibility seam for the existing MDR tooling. Concrete
    providers may be backed by Fidelis, Sysmon+Wazuh, osquery, Velociraptor,
    Falco, Tetragon, or a future in-house agent.
    """

    name: str

    @abstractmethod
    def list_alerts(self, limit: int = 50) -> List[Alert]: ...

    @abstractmethod
    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]: ...

    @abstractmethod
    def get_endpoint_context(self, hostname: Optional[str] = None, ip_address: Optional[str] = None) -> List[EndpointContext]: ...

    @abstractmethod
    def query_events(
        self,
        *,
        host: Optional[str] = None,
        event_type: Optional[str] = None,
        indicator: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[NormalizedEvent]: ...

    @abstractmethod
    def trace_process_chain(self, *, host: str, process_id: Optional[str] = None, event_id: Optional[str] = None) -> List[NormalizedEvent]: ...

    @abstractmethod
    def hunt_indicator(self, indicator: str, limit: int = 500) -> List[NormalizedEvent]: ...

    @abstractmethod
    def list_readonly_scripts(self) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def run_readonly_script(self, helper_name: str, host: str, **kwargs: Any) -> ScriptResult: ...


class CompositeEndpointProvider(EndpointProvider):
    """Fan-out provider that merges multiple open-source EDR backends."""

    name = "composite-open-source-edr"

    def __init__(self, providers: Iterable[EndpointProvider]):
        self.providers = list(providers)

    def list_alerts(self, limit: int = 50) -> List[Alert]:
        alerts: List[Alert] = []
        for provider in self.providers:
            alerts.extend(provider.list_alerts(limit=limit))
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        for provider in self.providers:
            found = provider.get_alert_by_id(alert_id)
            if found:
                return found
        return None

    def get_endpoint_context(self, hostname: Optional[str] = None, ip_address: Optional[str] = None) -> List[EndpointContext]:
        contexts: List[EndpointContext] = []
        for provider in self.providers:
            contexts.extend(provider.get_endpoint_context(hostname=hostname, ip_address=ip_address))
        return contexts

    def query_events(self, **kwargs: Any) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        limit = int(kwargs.get("limit") or 500)
        for provider in self.providers:
            events.extend(provider.query_events(**kwargs))
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def trace_process_chain(self, *, host: str, process_id: Optional[str] = None, event_id: Optional[str] = None) -> List[NormalizedEvent]:
        chain: List[NormalizedEvent] = []
        for provider in self.providers:
            chain.extend(provider.trace_process_chain(host=host, process_id=process_id, event_id=event_id))
        return sorted(chain, key=lambda e: e.timestamp)

    def hunt_indicator(self, indicator: str, limit: int = 500) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        for provider in self.providers:
            events.extend(provider.hunt_indicator(indicator=indicator, limit=limit))
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def list_readonly_scripts(self) -> List[Dict[str, Any]]:
        scripts: List[Dict[str, Any]] = []
        for provider in self.providers:
            scripts.extend(provider.list_readonly_scripts())
        return scripts

    def run_readonly_script(self, helper_name: str, host: str, **kwargs: Any) -> ScriptResult:
        for provider in self.providers:
            names = {item.get("name") for item in provider.list_readonly_scripts()}
            if helper_name in names:
                return provider.run_readonly_script(helper_name, host, **kwargs)
        raise ValueError(f"No provider can run read-only helper: {helper_name}")
