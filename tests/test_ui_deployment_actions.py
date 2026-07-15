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
    assert "--config" in body["install_command"]
    assert "--enroll-token" not in body["install_command"]
    assert body["agent_filename"] == "shigure-agent.exe"
    assert body["install_dir"] == "C:\\Program Files\\Shigure"
    assert body["data_dir"] == "C:\\ProgramData\\Shigure"
    assert body["identity_file"] == "C:\\ProgramData\\Shigure\\shigure-agent-state.json"
    assert body["installed_config_file"] == "C:\\ProgramData\\Shigure\\shigure-agent-config.json"
    assert body["start_command"] == "sc.exe start ShigureAgent"
    assert "--service-name ShigureAgent" in body["install_command"]
    assert '--service-display-name "Shigure Agent"' in body["install_command"]
    assert "--service-binary-name shigure-agent.exe" in body["install_command"]
    assert "Content-Disposition" in res.headers

    tokens = client.get("/api/v1/admin/enrollment-tokens", headers=ADMIN, params={"tenant_id": "default"}).json()["tokens"]
    assert any(t["token_prefix"] == f"{body['enrollment_token'][:6]}..." for t in tokens)


def test_windows_agent_binary_download_uses_configured_path(tmp_path, monkeypatch):
    exe = tmp_path / "shigure-agent.exe"
    exe.write_bytes(b"MZ-test-agent")
    monkeypatch.setenv("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", str(exe))
    client = TestClient(create_app(tmp_path / "deploy-binary.sqlite3", create_dev_token=True))
    res = client.get("/api/v1/admin/downloads/agent/windows", headers=ADMIN)
    assert res.status_code == 200
    assert res.content == b"MZ-test-agent"
    assert "shigure-agent.exe" in res.headers.get("content-disposition", "")


def test_agent_package_zip_contains_binary_config_and_installer(tmp_path, monkeypatch):
    exe = tmp_path / "shigure-agent.exe"
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
    assert "shigure-agent-package.zip" in res.headers.get("content-disposition", "")

    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        names = set(zf.namelist())
        assert {"shigure-agent.exe", "shigure-agent-config.json", "install.ps1", "README.txt"} <= names
        assert zf.read("shigure-agent.exe") == b"MZ-test-agent"
        config = json.loads(zf.read("shigure-agent-config.json"))
        assert config["tenant_id"] == "default"
        assert config["server_url"] == "https://edr.intra"
        assert config["enrollment_token"]
        assert config["install_dir"] == "C:\\Program Files\\Shigure"
        assert config["data_dir"] == "C:\\ProgramData\\Shigure"
        assert config["identity_file"] == "C:\\ProgramData\\Shigure\\shigure-agent-state.json"
        assert config["spool_file"] == "C:\\ProgramData\\Shigure\\spool.jsonl"
        assert config["spool_max_bytes"] == 52428800
        assert config["spool_max_records"] == 10000
        assert "per-endpoint credential" in config["enrollment_model"]["stage_2"]
        install_ps1 = zf.read("install.ps1").decode()
        assert "--enroll-token" not in install_ps1
        assert "--install-dir" in install_ps1
        assert "--config" in install_ps1
        assert "sc.exe start ShigureAgent" in install_ps1
        assert '"--service-binary-name", "shigure-agent.exe"' in install_ps1
        readme = zf.read("README.txt").decode()
        assert "Shigure Agent deployment package" in readme
        assert "C:\\ProgramData\\Shigure\\shigure-agent-state.json" in readme
        assert "service command line does not contain the enrollment token" in readme
        assert "removes enrollment_token from the installed config" in readme


def test_agent_package_supports_explicit_shiori_legacy_naming(tmp_path, monkeypatch):
    exe = tmp_path / "legacy.exe"
    exe.write_bytes(b"MZ-test-agent")
    monkeypatch.setenv("OPEN_EDR_MDR_WINDOWS_AGENT_EXE", str(exe))
    client = TestClient(create_app(tmp_path / "deploy-legacy-package.sqlite3", create_dev_token=True))
    res = client.get(
        "/api/v1/admin/downloads/agent/package",
        headers=ADMIN,
        params={"tenant_id": "default", "server_url": "https://edr.intra", "naming": "shiori"},
    )
    assert res.status_code == 200
    assert "shiori-agent-package.zip" in res.headers.get("content-disposition", "")

    with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
        assert {"shiori-agent.exe", "shiori-agent-config.json", "install.ps1", "README.txt"} <= set(zf.namelist())
        config = json.loads(zf.read("shiori-agent-config.json"))
        assert config["naming_profile"] == "shiori"
        assert config["service_name"] == "ShioriAgent"
        assert config["service_binary_name"] == "shiori-agent.exe"
        assert config["install_dir"] == "C:\\Program Files\\Shiori"
        assert config["identity_file"] == "C:\\ProgramData\\Shiori\\shiori-agent-state.json"
        install_ps1 = zf.read("install.ps1").decode()
        assert "sc.exe start ShioriAgent" in install_ps1
        assert '"--service-binary-name", "shiori-agent.exe"' in install_ps1
        assert "Legacy Shiori compatibility naming" in zf.read("README.txt").decode()

    config_res = client.get(
        "/api/v1/admin/downloads/agent-config",
        headers=ADMIN,
        params={"tenant_id": "default", "server_url": "https://edr.intra", "naming": "shiori"},
    )
    assert config_res.status_code == 200
    body = config_res.json()
    assert body["service_name"] == "ShioriAgent"
    assert "--service-name ShioriAgent" in body["install_command"]
    assert '--service-display-name "Shiori Agent"' in body["install_command"]
    assert "--service-binary-name shiori-agent.exe" in body["install_command"]


def test_minimal_ui_contains_endpoint_task_and_download_controls(tmp_path):
    client = TestClient(create_app(tmp_path / "deploy-ui.sqlite3", create_dev_token=True))
    res = client.get("/ui")
    assert res.status_code == 200
    text = res.text
    assert client.app.title == "Shigure API"
    assert "Investigation queue" in text
    assert "Recommended next steps" in text
    assert "Deploy Shigure Agent" in text
    assert "shigure-agent-package.zip" in text
    assert "shigure-agent.exe" in text
    assert "shigure-agent-config.json" in text
    assert "Related" in text and "Host day" in text
    assert "/api/v1/admin/tasks" in text
    assert "/api/v1/admin/downloads/agent/package" in text
    assert "/api/v1/admin/downloads/agent-config" in text
