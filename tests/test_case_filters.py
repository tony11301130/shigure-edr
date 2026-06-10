from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_case_list_filters_by_severity_and_assignee(tmp_path):
    client = TestClient(create_app(tmp_path / "case-filters.sqlite3", create_dev_token=True))
    high = client.post("/api/v1/admin/cases", headers=ADMIN, json={"tenant_id": "default", "title": "High case", "severity": "high"})
    low = client.post("/api/v1/admin/cases", headers=ADMIN, json={"tenant_id": "default", "title": "Low case", "severity": "low"})
    assert high.status_code == 200
    assert low.status_code == 200

    patched = client.patch(f"/api/v1/admin/cases/{high.json()['case_id']}", headers=ADMIN, params={"tenant_id": "default"}, json={"status": "investigating", "assignee": "alice"})
    assert patched.status_code == 200

    filtered = client.get("/api/v1/admin/cases", headers=ADMIN, params={"tenant_id": "default", "severity": "high", "assignee": "alice"})
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1
    assert filtered.json()[0]["title"] == "High case"

    miss = client.get("/api/v1/admin/cases", headers=ADMIN, params={"tenant_id": "default", "severity": "high", "assignee": "bob"})
    assert miss.status_code == 200
    assert miss.json() == []
