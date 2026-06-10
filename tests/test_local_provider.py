from open_edr_mdr_agent.adapters.local_json import LocalJsonProvider
from open_edr_mdr_agent.core.schemas import EventType


def test_local_provider_smoke(tmp_path):
    (tmp_path / "endpoints.jsonl").write_text('{"host":"POS01","ip_address":"10.0.0.10","sources":["sysmon"]}\n')
    (tmp_path / "wazuh-alerts.jsonl").write_text('{"id":"a-1","timestamp":"2026-06-10T11:00:00Z","agent":{"name":"POS01"},"rule":{"level":10,"description":"Suspicious PowerShell"}}\n')
    (tmp_path / "sysmon.jsonl").write_text('{"EventID":1,"UtcTime":"2026-06-10T11:00:00Z","Computer":"POS01","Image":"powershell.exe","ProcessId":"42","ParentProcessId":"1"}\n')
    (tmp_path / "falco.jsonl").write_text("")
    (tmp_path / "osquery.jsonl").write_text("")
    (tmp_path / "velociraptor.jsonl").write_text("")

    provider = LocalJsonProvider(tmp_path)
    assert provider.list_alerts()[0].alert_id == "a-1"
    assert provider.get_endpoint_context(hostname="POS01")[0].ip_address == "10.0.0.10"
    assert provider.query_events(host="POS01")[0].event_type == EventType.PROCESS_START
    assert provider.hunt_indicator("powershell")
