from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich import print
from rich.table import Table

from open_edr_mdr_agent.adapters.local_json import LocalJsonProvider
from open_edr_mdr_agent.core.provider import CompositeEndpointProvider

app = typer.Typer(help="Shiori endpoint security fusion prototype")


def provider(data_dir: str = "./sample-data") -> CompositeEndpointProvider:
    return CompositeEndpointProvider([LocalJsonProvider(data_dir)])


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, db: str = "/tmp/open-edr-mdr-agent.sqlite3"):
    """Run the M0 backend API server."""
    import os
    import uvicorn

    os.environ["OPEN_EDR_MDR_DB"] = db
    uvicorn.run("open_edr_mdr_agent.api.app:app", host=host, port=port, reload=False)


@app.command()
def alerts(data_dir: str = "./sample-data", limit: int = 20):
    """List normalized alerts."""
    rows = provider(data_dir).list_alerts(limit=limit)
    table = Table("id", "severity", "host", "title", "source")
    for a in rows:
        table.add_row(a.alert_id, a.severity.value, a.host or "", a.title, a.source.value)
    print(table)


@app.command("endpoint-context")
def endpoint_context(host: Optional[str] = None, ip: Optional[str] = None, data_dir: str = "./sample-data"):
    """Get endpoint context like Fidelis get_endpoint_context."""
    rows = provider(data_dir).get_endpoint_context(hostname=host, ip_address=ip)
    print(json.dumps([r.model_dump(mode="json") for r in rows], ensure_ascii=False, indent=2))


@app.command("query-events")
def query_events(host: Optional[str] = None, event_type: Optional[str] = None, indicator: Optional[str] = None, data_dir: str = "./sample-data", limit: int = 20):
    """Query normalized endpoint events."""
    rows = provider(data_dir).query_events(host=host, event_type=event_type, indicator=indicator, limit=limit)
    print(json.dumps([r.model_dump(mode="json") for r in rows], ensure_ascii=False, indent=2))


@app.command("hunt")
def hunt(indicator: str, data_dir: str = "./sample-data", limit: int = 20):
    """Hunt an indicator across all fused sources."""
    rows = provider(data_dir).hunt_indicator(indicator=indicator, limit=limit)
    print(json.dumps([r.model_dump(mode="json") for r in rows], ensure_ascii=False, indent=2))


@app.command("trace-process-chain")
def trace_process_chain(host: str, process_id: str, data_dir: str = "./sample-data"):
    """Rebuild process parent chain from normalized telemetry."""
    rows = provider(data_dir).trace_process_chain(host=host, process_id=process_id)
    print(json.dumps([r.model_dump(mode="json") for r in rows], ensure_ascii=False, indent=2))


@app.command("scripts")
def scripts(data_dir: str = "./sample-data"):
    """List read-only evidence helpers."""
    print(json.dumps(provider(data_dir).list_readonly_scripts(), ensure_ascii=False, indent=2))


@app.command("init-sample-data")
def init_sample_data(data_dir: str = "./sample-data"):
    """Create sample JSONL data for local smoke tests."""
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "endpoints.jsonl").write_text(json.dumps({"host":"POS01","ip_address":"10.0.0.10","os":"Windows","agent_connected":True,"agent_version":"prototype","sources":["sysmon","wazuh","osquery"]}) + "\n", encoding="utf-8")
    (root / "wazuh-alerts.jsonl").write_text(json.dumps({"id":"a-1","timestamp":"2026-06-10T11:00:00Z","agent":{"name":"POS01"},"rule":{"level":10,"description":"Suspicious PowerShell encoded command","mitre":{"id":["T1059.001"]}},"full_log":"powershell -enc ..."}) + "\n", encoding="utf-8")
    (root / "sysmon.jsonl").write_text("\n".join([
        json.dumps({"EventID":1,"UtcTime":"2026-06-10T10:59:00Z","Computer":"POS01","User":"DOMAIN\\user","Image":"C:\\Windows\\explorer.exe","ProcessId":"100","ParentProcessId":"4","CommandLine":"explorer.exe"}),
        json.dumps({"EventID":1,"UtcTime":"2026-06-10T11:00:00Z","Computer":"POS01","User":"DOMAIN\\user","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessId":"4242","ParentProcessId":"100","CommandLine":"powershell.exe -enc SQBFAFgA"}),
        json.dumps({"EventID":3,"UtcTime":"2026-06-10T11:00:05Z","Computer":"POS01","Image":"powershell.exe","ProcessId":"4242","DestinationIp":"203.0.113.10","DestinationPort":"443"}),
    ]) + "\n", encoding="utf-8")
    (root / "falco.jsonl").write_text("", encoding="utf-8")
    (root / "osquery.jsonl").write_text(json.dumps({"host":"POS01","table":"programs","name":"7-Zip"}) + "\n", encoding="utf-8")
    (root / "velociraptor.jsonl").write_text(json.dumps({"host":"POS01","artifact":"Windows.Sysinternals.Autoruns","rows":[]}) + "\n", encoding="utf-8")
    print(f"sample data created at {root}")


if __name__ == "__main__":
    app()
