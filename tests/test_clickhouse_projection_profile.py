from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from open_edr_mdr_agent.api.app import create_app
from open_edr_mdr_agent.api.store import SQLiteStore
from open_edr_mdr_agent.core.schemas import NormalizedEvent

ADMIN = {"Authorization": "Bearer dev-admin-token"}
FIXTURE_DIR = Path(__file__).parent / "fixtures"


class RecordingTelemetryProjection(SQLiteStore):
    storage_profile = "clickhouse"

    def __init__(self, path):
        super().__init__(path)
        self.inserted_batches: list[tuple[str, int]] = []

    def insert_events(self, agent_id: str, events):
        events = list(events)
        self.inserted_batches.append((agent_id, len(events)))
        return super().insert_events(agent_id, events)

    def telemetry_retention_policy(self):
        return {
            "hot_normalized_telemetry_days": 30,
            "warm_rollup_days": 180,
            "rollups": ["event_rollups_hourly", "collector_health_hourly", "telemetry_gaps_hourly"],
        }


def test_admin_storage_profile_reports_clickhouse_telemetry_projection(tmp_path):
    control = SQLiteStore(tmp_path / "control.sqlite3")
    telemetry = RecordingTelemetryProjection(tmp_path / "telemetry.sqlite3")
    client = TestClient(create_app(tmp_path / "ignored.sqlite3", profile="dev", create_dev_token=True, store=control, telemetry_store=telemetry))

    res = client.get("/api/v1/admin/storage-profile", headers=ADMIN)

    assert res.status_code == 200, res.text
    assert res.json()["control_plane_store"] == "sqlite"
    assert res.json()["telemetry_projection"]["storage_provider"] == "clickhouse"
    assert res.json()["telemetry_projection"]["retention"]["hot_normalized_telemetry_days"] == 30
    assert "telemetry_gaps_hourly" in res.json()["telemetry_projection"]["retention"]["rollups"]


def test_event_queries_and_hunts_read_from_telemetry_projection(tmp_path):
    control = SQLiteStore(tmp_path / "control.sqlite3")
    telemetry = RecordingTelemetryProjection(tmp_path / "telemetry.sqlite3")
    client = TestClient(create_app(tmp_path / "ignored.sqlite3", profile="dev", create_dev_token=True, store=control, telemetry_store=telemetry))
    enroll = client.post("/api/v1/enroll", json={"enrollment_token": "dev-token", "host": "CH01", "os": "Windows", "agent_version": "dev"})
    auth = enroll.json()
    headers = {"Authorization": f"Bearer {auth['agent_token']}"}
    event = json.loads((FIXTURE_DIR / "clickhouse_projection_events.json").read_text())["events"][0]
    process_entity_id = event["process_entity_id"]
    hash_sha256 = event["hash_sha256"]

    ingest = client.post(f"/api/v1/agents/{auth['agent_id']}/events", headers=headers, json={"events": [event]})
    assert ingest.status_code == 200, ingest.text
    assert telemetry.inserted_batches == [(auth["agent_id"], 1)]

    by_entity = client.get("/api/v1/admin/events", headers=ADMIN, params={"tenant_id": "default", "process_entity_id": process_entity_id})
    assert by_entity.status_code == 200, by_entity.text
    assert [item["process_entity_id"] for item in by_entity.json()] == [process_entity_id]
    assert by_entity.json()[0]["raw_ref"].startswith("object://raw-evidence/default/event/")

    counted = client.get("/api/v1/admin/events/count", headers=ADMIN, params={"tenant_id": "default", "hash_sha256": hash_sha256})
    assert counted.status_code == 200, counted.text
    assert counted.json()["count"] == 1

    related = client.get("/api/v1/admin/events/related", headers=ADMIN, params={"tenant_id": "default", "entity_type": "remote_ip", "value": "203.0.113.77"})
    assert related.status_code == 200, related.text
    assert [item["host"] for item in related.json()] == ["CH01"]

    hunt = client.post("/api/v1/admin/hunts", headers=ADMIN, json={"tenant_id": "default", "name": "ClickHouse IOC", "indicator": "203.0.113.77"})
    run = client.post(f"/api/v1/admin/hunts/{hunt.json()['hunt_id']}/run", headers=ADMIN, params={"tenant_id": "default"})
    assert run.status_code == 200, run.text
    assert run.json()["result"]["event_count"] == 1
    assert run.json()["result"]["summary"]["impacted_endpoints"] == ["CH01"]


def test_clickhouse_schema_uses_daily_partitions_ttl_and_process_columns():
    from open_edr_mdr_agent.api.clickhouse_store import ClickHouseTelemetryStore

    schema = "\n".join(ClickHouseTelemetryStore.schema_statements())

    assert "PARTITION BY toYYYYMMDD(event_time)" in schema
    assert "TTL event_time + INTERVAL 30 DAY" in schema
    assert "process_entity_id String" in schema
    assert "parent_process_entity_id String" in schema
    assert "CREATE TABLE IF NOT EXISTS shigure_event_rollups_hourly" in schema
    assert "TTL bucket_start + INTERVAL 180 DAY" in schema


def test_clickhouse_projection_round_trips_when_configured():
    from open_edr_mdr_agent.api.clickhouse_store import ClickHouseTelemetryStore

    dsn = os.environ.get("OPEN_EDR_MDR_TEST_CLICKHOUSE_DSN")
    if not dsn:
        pytest.skip("OPEN_EDR_MDR_TEST_CLICKHOUSE_DSN is required for ClickHouse projection tests")
    store = ClickHouseTelemetryStore(dsn)
    event_data = json.loads((FIXTURE_DIR / "clickhouse_projection_events.json").read_text())["events"][0]
    event_data = {**event_data, "tenant_id": f"test-{os.getpid()}", "host": f"CH-{os.getpid()}"}
    event = NormalizedEvent.model_validate(event_data)

    assert store.insert_events("agent-clickhouse-test", [event]) == 1
    assert store.count_events(event.tenant_id, process_entity_id=event.process_entity_id) >= 1
    assert store.list_events(event.tenant_id, remote_ip=event.remote_ip, limit=1)[0].process_entity_id == event.process_entity_id
    assert store.related_events(event.tenant_id, "hash_sha256", event.hash_sha256, limit=1)[0].host == event.host
