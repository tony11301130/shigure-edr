import sqlite3

from open_edr_mdr_agent.api.store import SQLiteStore
from open_edr_mdr_agent.core.schemas import EventType, NormalizedEvent, Source


def test_store_adds_raw_reference_columns_to_legacy_tables(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        create table events (
            id text primary key,
            tenant_id text not null,
            agent_id text,
            host text,
            event_type text not null,
            source text not null,
            timestamp text not null,
            process_name text,
            process_id text,
            command_line text,
            remote_ip text,
            domain text,
            event_json text not null
        );
        create table alerts (
            alert_id text primary key,
            tenant_id text not null,
            title text not null,
            severity text not null,
            timestamp text not null,
            host text,
            user text,
            process_name text,
            alert_json text not null
        );
        """
    )
    conn.close()

    store = SQLiteStore(db)
    event = NormalizedEvent(
        source=Source.INTERNAL,
        event_type=EventType.PROCESS_START,
        tenant_id="default",
        host="LEGACY01",
        process_name="cmd.exe",
        process_id="123",
        process_entity_id="peid:LEGACY01:boot-a:123:2026-07-14T00:00:00Z",
        parent_process_entity_id="peid:LEGACY01:boot-a:1:2026-07-14T00:00:00Z",
        boot_id="boot-a",
        process_create_time="2026-07-14T00:00:00Z",
        image_path="C:/Windows/System32/cmd.exe",
        image_hash="c" * 64,
        process_identity_confidence="high",
        raw={"legacy": True},
    )
    assert store.insert_events("agent-1", [event]) == 1

    rows = store.list_events("default", host="LEGACY01")
    assert rows[0].raw_ref
    assert rows[0].raw_hash
    assert rows[0].process_entity_id == "peid:LEGACY01:boot-a:123:2026-07-14T00:00:00Z"
