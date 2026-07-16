from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app
from open_edr_mdr_agent.core.schemas import Alert, Severity, Source

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_alert_list_filters_by_severity_and_host(tmp_path):
    client = TestClient(create_app(tmp_path / "alert-filters.sqlite3", create_dev_token=True))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "ALERT01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}
    event = {"source": "internal", "event_type": "process_start", "tenant_id": "default", "host": "ALERT01", "process_name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA", "severity": "info"}
    ingest = client.post(f"/api/v1/agents/{auth['agent_id']}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200

    hit = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "severity": "high", "host": "ALERT01"})
    assert hit.status_code == 200
    assert len(hit.json()) == 1
    assert hit.json()[0]["title"] == "Suspicious encoded PowerShell command"

    by_title = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "title": "encoded PowerShell"})
    assert by_title.status_code == 200
    assert len(by_title.json()) == 1

    miss = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "severity": "critical", "host": "ALERT01"})
    assert miss.status_code == 200
    assert miss.json() == []


def test_alert_list_filters_by_analyst_facets(tmp_path):
    app = create_app(tmp_path / "alert-facets.sqlite3", create_dev_token=True)
    client = TestClient(app)
    app.state.store.insert_alerts(
        [
            Alert(
                alert_id="facet-1",
                title="Windows scheduled task changed",
                severity=Severity.MEDIUM,
                host="FACET01",
                user="alice",
                process_name="schtasks.exe",
                description="created task for updater",
                mitre=["T1053.005"],
                source=Source.INTERNAL,
                raw_ref="object://raw-evidence/default/facet-1.json",
                raw_hash="a" * 64,
                raw={"rule_id": "builtin.windows.scheduled_task.changed", "artifact": "schtasks.exe", "indicator": "203.0.113.10"},
            ),
            Alert(
                alert_id="facet-2",
                title="Known bad indicator match",
                severity=Severity.HIGH,
                host="FACET02",
                user="bob",
                process_name="powershell.exe",
                description="IOC match",
                mitre=["T1204"],
                source=Source.INTERNAL,
                raw={"rule_id": "builtin.ioc.match", "indicator": "malicious.example"},
            ),
        ]
    )

    by_mitre = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "mitre": "T1053.005"})
    assert by_mitre.status_code == 200
    assert [a["alert_id"] for a in by_mitre.json()] == ["facet-1"]

    by_artifact = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "artifact": "schtasks.exe"})
    assert by_artifact.status_code == 200
    assert [a["alert_id"] for a in by_artifact.json()] == ["facet-1"]

    by_indicator = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "indicator": "malicious.example"})
    assert by_indicator.status_code == 200
    assert [a["alert_id"] for a in by_indicator.json()] == ["facet-2"]

    with_evidence = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "has_evidence": "true"})
    assert with_evidence.status_code == 200
    assert {a["alert_id"] for a in with_evidence.json()} == {"facet-1", "facet-2"}

    without_evidence = client.get("/api/v1/admin/alerts", headers=ADMIN, params={"tenant_id": "default", "has_evidence": "false"})
    assert without_evidence.status_code == 200
    assert without_evidence.json() == []
