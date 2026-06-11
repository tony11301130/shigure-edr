import io
import json
import zipfile
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


def test_agent_package_zip_contains_binary_config_and_installer(tmp_path, monkeypatch):
    exe = tmp_path / "open-edr-agent.exe"
    exe.write_bytes(b"MZ-test-agent")
    monkeypatch.setenv("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", str(exe))
    client = TestClient(create_app(tmp_path / "deploy-package.sqlite3", create_dev_token=True))
    res = client.get(
        "/api/v1/admin/downloads/agent/package",
        headers=ADMIN,
        params={"tenant_id": "default", "server_url": "https://edr.intra", "max_uses": 2},
    )
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    assert "open-edr-agent-package.zip" in res.headers.get("content-disposition", "")

    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        names = set(zf.namelist())
        assert {"open-edr-agent.exe", "open-edr-agent-config.json", "install.ps1", "README.txt"} <= names
        assert zf.read("open-edr-agent.exe") == b"MZ-test-agent"
        config = json.loads(zf.read("open-edr-agent-config.json"))
        assert config["tenant_id"] == "default"
        assert config["server_url"] == "https://edr.intra"
        assert config["enrollment_token"]
        assert config["identity_file"] == "open-edr-scoreboard.json"
        assert "per-endpoint credential" in config["enrollment_model"]["stage_2"]
        install_ps1 = zf.read("install.ps1").decode()
        assert "--enroll-token" in install_ps1
        assert "--config" not in install_ps1
        assert "open-edr-scoreboard.json" in zf.read("README.txt").decode()


def test_minimal_ui_contains_endpoint_task_and_download_controls(tmp_path):
    client = TestClient(create_app(tmp_path / "deploy-ui.sqlite3", create_dev_token=True))
    res = client.get("/ui")
    assert res.status_code == 200
    text = res.text
    assert "Reporting Endpoints" in text
    assert "Reverse-Proxy Job Dispatch" in text
    assert "DOWNLOAD DEPLOYMENT ZIP" in text
    assert "DOWNLOAD CONFIG" in text
    assert "/api/v1/admin/tasks" in text
    assert "/api/v1/admin/downloads/agent/package" in text
    assert "/api/v1/admin/downloads/agent-config" in text
