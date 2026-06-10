from pathlib import Path

from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app

ADMIN = {"Authorization": "Bearer dev-admin-token"}


def test_agent_config_download_contains_enrollment_material(tmp_path):
    client = TestClient(create_app(tmp_path / "deploy-config.sqlite3", create_dev_token=True))
    res = client.get(
        "/api/v1/admin/downloads/agent-config",
        headers=ADMIN,
        params={"tenant_id": "default", "server_url": "https://edr.intra", "max_uses": 2},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["tenant_id"] == "default"
    assert body["server_url"] == "https://edr.intra"
    assert body["enrollment_token"]
    assert "--install-service" in body["install_command"]
    assert "Content-Disposition" in res.headers

    tokens = client.get("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "default"}).json()["tokens"]
    assert any(t["token_prefix"] == f"{body['enrollment_token'][:6]}..." for t in tokens)


def test_windows_agent_binary_download_uses_configured_path(tmp_path, monkeypatch):
    exe = tmp_path / "open-edr-agent.exe"
    exe.write_bytes(b"MZ-test-agent")
    monkeypatch.setenv("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", str(exe))
    client = TestClient(create_app(tmp_path / "deploy-binary.sqlite3", create_dev_token=True))
    res = client.get("/api/v1/admin/downloads/agent/windows", headers=ADMIN)
    assert res.status_code == 200
    assert res.content == b"MZ-test-agent"
    assert "open-edr-agent.exe" in res.headers.get("content-disposition", "")


def test_minimal_ui_contains_endpoint_task_and_download_controls(tmp_path):
    client = TestClient(create_app(tmp_path / "deploy-ui.sqlite3", create_dev_token=True))
    res = client.get("/ui")
    assert res.status_code == 200
    text = res.text
    assert "Reporting Endpoints" in text
    assert "Reverse-Proxy Job Dispatch" in text
    assert "DOWNLOAD AGENT EXE" in text
    assert "DOWNLOAD CONFIG" in text
    assert "/api/v1/admin/tasks" in text
    assert "/api/v1/admin/downloads/agent-config" in text
