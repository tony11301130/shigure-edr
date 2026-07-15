from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from open_edr_mdr_agent.api.object_storage import RawObjectStore, object_store_from_env
from open_edr_mdr_agent.api.store import SQLiteStore, utc_now


SCHEMA_VERSION = "001_control_plane"


class PostgreSQLStore(SQLiteStore):
    storage_profile = "postgresql"

    def __init__(self, dsn: str, *, raw_object_store: RawObjectStore | None = None, object_store_base_dir: str | Path = "/tmp/shigure-postgres"):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ModuleNotFoundError as exc:
            raise ValueError("postgresql_driver_missing") from exc
        self.dsn = dsn
        self.path = Path(object_store_base_dir)
        self._psycopg = psycopg
        self._row_factory = dict_row
        self.raw_object_store = raw_object_store or object_store_from_env(object_store_base_dir)
        self.init_schema()

    @contextmanager
    def connect(self):
        conn = self._psycopg.connect(self.dsn, row_factory=self._row_factory)
        wrapped = _PostgreSQLConnection(conn)
        try:
            yield wrapped
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        super().init_schema()
        with self.connect() as conn:
            conn.execute(
                """
                create table if not exists schema_migrations (
                    version text primary key,
                    applied_at text not null
                )
                """
            )
            conn.execute(
                "insert into schema_migrations(version, applied_at) values (?, ?) on conflict do nothing",
                (SCHEMA_VERSION, utc_now()),
            )

    def _ensure_column(self, conn: "_PostgreSQLConnection", table: str, column: str, ddl_type: str) -> None:
        row = conn.execute(
            """
            select column_name name
            from information_schema.columns
            where table_schema = current_schema()
              and table_name = ?
              and column_name = ?
            """,
            (table, column),
        ).fetchone()
        if not row:
            conn.execute(f"alter table {table} add column {column} {ddl_type}")


class _PostgreSQLConnection:
    def __init__(self, conn: Any):
        self._conn = conn

    def execute(self, sql: str, params: Iterable[Any] | None = None):
        return self._conn.execute(_translate_sql(sql), tuple(params or ()))

    def executemany(self, sql: str, params_seq: Iterable[Iterable[Any]]) -> None:
        translated = _translate_sql(sql)
        with self._conn.cursor() as cur:
            cur.executemany(translated, [tuple(params) for params in params_seq])

    def executescript(self, script: str) -> None:
        for statement in _split_sql_script(script):
            self.execute(statement)


def _split_sql_script(script: str) -> list[str]:
    return [statement.strip() for statement in script.split(";") if statement.strip()]


def _translate_sql(sql: str) -> str:
    translated = sql.strip()
    translated = re.sub(r"\border by created_at,\s*rowid\b", "order by created_at", translated, flags=re.IGNORECASE)
    translated = _quote_reserved_columns(translated)
    translated = _translate_insert_or_replace(translated)
    translated = _translate_insert_or_ignore(translated)
    translated = translated.replace("?", "%s")
    return translated


def _quote_reserved_columns(sql: str) -> str:
    translated = re.sub(r"\buser\s+text\b", '"user" text', sql, flags=re.IGNORECASE)
    translated = re.sub(r'(?<!")\buser\b(?!")', '"user"', translated, flags=re.IGNORECASE)
    return translated


def _translate_insert_or_ignore(sql: str) -> str:
    match = re.match(r"insert\s+or\s+ignore\s+into\s+(.+)", sql, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return sql
    return f"insert into {match.group(1)} on conflict do nothing"


def _translate_insert_or_replace(sql: str) -> str:
    match = re.match(
        r"insert\s+or\s+replace\s+into\s+([a-z_]+)\(([^)]+)\)\s+values\s*\((.+)\)",
        sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return sql
    table = match.group(1)
    columns = [column.strip() for column in match.group(2).split(",")]
    values = match.group(3)
    conflict_columns = {"tenant_configs": "tenant_id", "enrollment_tokens": "token"}.get(table)
    if not conflict_columns:
        return sql
    assignments = [f"{column}=excluded.{column}" for column in columns if column != conflict_columns]
    return f"insert into {table}({', '.join(columns)}) values ({values}) on conflict ({conflict_columns}) do update set {', '.join(assignments)}"
