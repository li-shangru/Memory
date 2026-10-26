"""Synthetic detail-paging query plans and additive legacy-Store healing."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from memory.database import open_database, writer_session
from memory.keys import load_master_key
from memory.model import RuntimePaths
from memory.runtime import load_runtime_identity

SCHEMA = Path(__file__).resolve().parents[1] / "src/memory/schema.sql"
QUERIES = {
    "idx_memory_lineage_history": (
        "SELECT revision_id, recorded_at, rowid FROM memory_revisions "
        "WHERE lineage_id = ? AND recorded_at = ? AND rowid > ? "
        "ORDER BY recorded_at, rowid LIMIT 257",
        ("synthetic-lineage", 0, 0),
    ),
    "idx_memory_guard_governed": (
        "SELECT guard_lineage_id FROM memory_guard_links "
        "WHERE governed_lineage_id = ? AND guard_lineage_id > ? "
        "AND revoked_at IS NULL ORDER BY guard_lineage_id LIMIT 257",
        ("synthetic-lineage", ""),
    ),
    "idx_memory_guard_active": (
        "SELECT governed_lineage_id FROM memory_guard_links "
        "WHERE guard_lineage_id = ? AND governed_lineage_id > ? "
        "AND revoked_at IS NULL ORDER BY governed_lineage_id LIMIT 257",
        ("synthetic-lineage", ""),
    ),
}


def _assert_plans(connection: sqlite3.Connection) -> None:
    for index, (query, parameters) in QUERIES.items():
        steps = [
            str(row[3])
            for row in connection.execute("EXPLAIN QUERY PLAN " + query, parameters)
        ]
        assert any("SEARCH" in step and index in step for step in steps), steps
        assert not any("TEMP B-TREE" in step for step in steps), steps
    later = [
        str(row[3])
        for row in connection.execute(
            "EXPLAIN QUERY PLAN SELECT revision_id, recorded_at, rowid "
            "FROM memory_revisions WHERE lineage_id = ? AND recorded_at > ? "
            "ORDER BY recorded_at, rowid LIMIT 257",
            ("synthetic-lineage", 0),
        )
    ]
    assert any("idx_memory_lineage_history" in step for step in later), later
    assert not any("TEMP B-TREE" in step for step in later), later


def test_fresh_detail_paging_uses_keyset_indexes() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(SCHEMA.read_text())
        _assert_plans(connection)


def _state(paths: RuntimePaths) -> tuple[set[str], int]:
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='index'"
            )
        }
        generation = int(
            connection.execute("SELECT audit_generation FROM store_meta").fetchone()[0]
        )
        return indexes & QUERIES.keys(), generation
    finally:
        connection.close()


def test_detail_indexes_heal_atomically_once_without_read_mutation(
    synthetic_store: RuntimePaths,
) -> None:
    with writer_session(synthetic_store) as connection:
        for index in QUERIES:
            connection.execute(f"DROP INDEX IF EXISTS {index}")
    absent, before = _state(synthetic_store)
    assert not absent
    assert _state(synthetic_store) == (set(), before)
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with writer_session(synthetic_store):
            raise RuntimeError("synthetic rollback")
    assert _state(synthetic_store) == (set(), before)
    with writer_session(synthetic_store) as connection:
        _assert_plans(connection)
    assert _state(synthetic_store) == (set(QUERIES), before + 1)
    with writer_session(synthetic_store):
        pass
    assert _state(synthetic_store) == (set(QUERIES), before + 1)
