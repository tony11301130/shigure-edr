from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app


def test_minimal_ui_served(tmp_path):
    client = TestClient(create_app(tmp_path / "ui.sqlite3", create_dev_token=True))
    res = client.get("/ui")
    assert res.status_code == 200
    assert "OPEN EDR MDR" in res.text
    assert "/api/v1/admin/summary" in res.text


def test_root_redirects_to_ui(tmp_path):
    client = TestClient(create_app(tmp_path / "ui-redirect.sqlite3", create_dev_token=True))
    res = client.get("/", follow_redirects=False)
    assert res.status_code in (302, 307)
    assert res.headers["location"] == "/ui"
