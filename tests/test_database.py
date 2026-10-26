from __future__ import annotations

import base64
import importlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]  # no stubs

from memory import model
from memory.inbox import _DUPLICATE_CAPTURES_SQL
from memory.model import RuntimePaths

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "src" / "memory" / "schema.sql"
SOURCES_BLOB_INDEX_NAME = "idx_sources_blob_id"

ORDINARY_TABLES = {
    "store_meta",
    "source_blobs",
    "sources",
    "inbox_batches",
    "inbox_batch_issues",
    "inbox_batch_sources",
    "memory_lineages",
    "memory_revisions",
    "memory_evidence",
    "current_memory_heads",
    "change_sets",
    "change_set_revisions",
    "change_items",
    "change_item_evidence",
    "batch_source_decisions",
    "approvals",
    "applications",
    "application_memories",
}


def test_schema_is_one_strict_disposable_v1_without_a_migration_ledger() -> None:
    """Catch non-strict tables or a migration engine entering the MVP schema."""
    assert SCHEMA_PATH.is_file()
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        table_rows = connection.execute("PRAGMA table_list").fetchall()
        ordinary = {
            str(row[1]): int(row[5])
            for row in table_rows
            if str(row[1]) in ORDINARY_TABLES
        }
        virtual = {
            str(row[1])
            for row in table_rows
            if str(row[1]) in {"source_fts", "memory_fts"}
        }
        user_version = connection.execute("PRAGMA user_version").fetchone()
    finally:
        connection.close()

    assert ordinary == dict.fromkeys(ORDINARY_TABLES, 1)
    assert virtual == {"source_fts", "memory_fts"}
    assert user_version == (1,)
    assert not any("migration" in name for name in ordinary)


def test_fresh_schema_marks_source_projection_with_capture_rowid() -> None:
    """Catch a fresh Store lacking the rowid-bound projection format marker."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        columns = [
            str(row[1]) for row in connection.execute("PRAGMA table_info(source_fts)")
        ]
    finally:
        connection.close()

    assert columns == ["source_id", "capture_rowid", "utf8_text", "original_name"]


def test_batch_response_metadata_has_strict_disposable_schema_constraints() -> None:
    """Catch persisted scan warnings or continuation state accepting invalid rows."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO inbox_batches "
            "(batch_id, sealed_at, source_count, has_more) VALUES (?, ?, ?, ?)",
            ("bat_" + "1" * 32, 1, 1, 0),
        )
        connection.execute(
            "INSERT INTO inbox_batch_issues (batch_id, code, count) VALUES (?, ?, ?)",
            ("bat_" + "1" * 32, "changed", 1),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO inbox_batches "
                "(batch_id, sealed_at, source_count, has_more) VALUES (?, ?, ?, ?)",
                ("bat_" + "2" * 32, 1, 1, 2),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO inbox_batch_issues (batch_id, code, count) "
                "VALUES (?, ?, ?)",
                ("bat_" + "1" * 32, "synthetic_unknown", 1),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO inbox_batch_issues (batch_id, code, count) "
                "VALUES (?, ?, ?)",
                ("bat_" + "1" * 32, "symlink", 0),
            )
        connection.execute(
            "INSERT INTO inbox_batches "
            "(batch_id, capture_request_id, sealed_at, source_count, has_more) "
            "VALUES (?, ?, ?, ?, ?)",
            ("bat_" + "3" * 32, "cap_" + "4" * 32, 2, 1, 0),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO inbox_batches "
                "(batch_id, capture_request_id, sealed_at, source_count, has_more) "
                "VALUES (?, ?, ?, ?, ?)",
                ("bat_" + "5" * 32, "cap_" + "4" * 32, 3, 1, 0),
            )
        for invalid_request in ("cap_short", "req_" + "6" * 32, "cap_" + "G" * 32):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO inbox_batches "
                    "(batch_id, capture_request_id, sealed_at, source_count, has_more) "
                    "VALUES (?, ?, ?, ?, ?)",
                    ("bat_" + "7" * 32, invalid_request, 4, 1, 0),
                )
    finally:
        connection.close()


def test_source_origin_schema_allows_only_inbox_or_owner_correction() -> None:
    """Catch correction provenance being dropped or widened to arbitrary text."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO inbox_batches "
            "(batch_id, sealed_at, source_count, has_more) VALUES (?, 1, 1, 0)",
            ("bat_" + "8" * 32,),
        )
        connection.execute(
            "INSERT INTO source_blobs "
            "(blob_id, sha256, byte_length, original_bytes, utf8_text) "
            "VALUES (?, ?, 1, ?, ?)",
            ("blb_" + "9" * 32, "a" * 64, b"x", "x"),
        )
        connection.execute(
            "INSERT INTO sources "
            "(source_id, blob_id, batch_id, origin, original_name, media_type, "
            "authorship, sensitivity, captured_at) "
            "VALUES (?, ?, ?, 'owner_correction', 'synthetic.md', "
            "'text/markdown', 'owner', 'restricted', 1)",
            ("src_" + "b" * 32, "blb_" + "9" * 32, "bat_" + "8" * 32),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO sources "
                "(source_id, blob_id, batch_id, origin, original_name, media_type, "
                "authorship, sensitivity, captured_at) "
                "VALUES (?, ?, ?, 'synthetic_other', 'other.md', "
                "'text/markdown', 'owner', 'restricted', 1)",
                ("src_" + "c" * 32, "blb_" + "9" * 32, "bat_" + "8" * 32),
            )
    finally:
        connection.close()


def test_schema_pins_runtime_audit_origin_and_direct_owner_adapter_boundaries() -> None:
    """Catch disposable schema v1 drifting from the approved approval contract."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        store_columns = {
            str(row[1]): (str(row[2]), int(row[3]))
            for row in connection.execute("PRAGMA table_info(store_meta)")
        }
        revision_columns = {
            str(row[1]): (str(row[2]), int(row[3]))
            for row in connection.execute("PRAGMA table_info(change_set_revisions)")
        }
        schema_sql = {
            str(name): str(sql)
            for name, sql in connection.execute(
                "SELECT name, sql FROM sqlite_schema WHERE type = 'table'"
            )
        }
    finally:
        connection.close()

    assert store_columns["runtime_mode"] == ("TEXT", 1)
    assert store_columns["audit_generation"] == ("INTEGER", 1)
    assert revision_columns["adapter_origin"] == ("TEXT", 1)
    assert "runtime_mode = 'personal'" in schema_sql["store_meta"]
    assert "audit_generation >= 0" in schema_sql["store_meta"]
    assert (
        "adapter_origin IN ('mcp', 'owner_ui', 'cli', 'system')"
        in schema_sql["change_set_revisions"]
    )
    assert (
        "adapter IN ('mcp_elicitation', 'local_owner_ui', 'os_owner_presence_cli')"
        in " ".join(schema_sql["approvals"].split())
    )
    assert "interactive_cli" not in schema_sql["approvals"]


def write_runtime_identity(root: Path, store_id: str = "2" * 32) -> RuntimePaths:
    runtime = importlib.import_module("memory.runtime")
    paths: RuntimePaths = runtime.resolve_runtime(root)
    paths.root.mkdir(mode=0o700)
    paths.inbox.mkdir(mode=0o700)
    paths.inbox_claims.mkdir(mode=0o700)
    paths.inbox_staging.mkdir(mode=0o700)
    payload = {
        "product": "memory",
        "schema_lineage": "memory-store-v1",
        "schema_version": 1,
        "store_id": store_id,
        "runtime_mode": "personal",
        "inbox_path": str(paths.inbox),
    }
    descriptor = paths.identity.open("x", encoding="utf-8")
    try:
        json.dump(payload, descriptor, sort_keys=True, separators=(",", ":"))
        descriptor.write("\n")
    finally:
        descriptor.close()
    paths.identity.chmod(0o600)
    return paths


def test_new_database_is_encrypted_and_uses_pinned_sqlcipher_settings(
    tmp_path: Path,
) -> None:
    """Catch plaintext custody or drift from the approved SQLCipher profile."""
    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"k" * 32

    assert hasattr(database, "open_database")
    connection = database.open_database(
        paths, key, read_only=False, create_missing=True
    )
    try:
        identity = connection.execute(
            "SELECT product, schema_lineage, schema_version, store_id, "
            "runtime_mode, audit_generation FROM store_meta"
        ).fetchone()
        settings = {
            "cipher_page_size": str(
                connection.execute("PRAGMA cipher_page_size").fetchone()[0]
            ),
            "kdf_iter": str(connection.execute("PRAGMA kdf_iter").fetchone()[0]),
            "cipher_hmac_algorithm": str(
                connection.execute("PRAGMA cipher_hmac_algorithm").fetchone()[0]
            ),
            "cipher_kdf_algorithm": str(
                connection.execute("PRAGMA cipher_kdf_algorithm").fetchone()[0]
            ),
        }
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    finally:
        connection.close()

    assert identity == (
        "memory",
        "memory-store-v1",
        1,
        "2" * 32,
        "personal",
        0,
    )
    assert settings == {
        "cipher_page_size": "4096",
        "kdf_iter": "256000",
        "cipher_hmac_algorithm": "HMAC_SHA512",
        "cipher_kdf_algorithm": "PBKDF2_HMAC_SHA512",
    }
    assert journal_mode == ("wal",)
    assert synchronous == (2,)
    assert foreign_keys == (1,)
    raw = paths.database.read_bytes()
    assert not raw.startswith(b"SQLite format 3\x00")
    assert b"memory" not in raw


def test_writer_open_fails_closed_when_the_database_is_missing(
    tmp_path: Path,
) -> None:
    """Catch a writer session silently recreating a deleted Store as empty.

    Every read path refuses a missing store.sqlite3 as wrong_product, but
    the writer branch quietly minted a fresh empty database under the same
    runtime identity -- so a long-running MCP or UI process whose database
    was removed mid-session would mask the loss by writing new batches into
    an empty replacement. Creation belongs to initialization alone.
    """
    from memory.errors import WrongProductError

    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"w" * 32
    database.open_database(paths, key, read_only=False, create_missing=True).close()
    paths.database.unlink()

    with pytest.raises(WrongProductError, match="database is missing"):
        database.open_database(paths, key, read_only=False)

    assert not paths.database.exists()


def test_writer_open_does_not_recreate_database_removed_after_initial_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only explicit initialization may create a file after an absence race."""
    from memory.errors import WrongProductError

    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    paths.database.write_bytes(b"synthetic retained database sentinel")
    paths.database.chmod(0o600)
    retained = tmp_path / "synthetic-original-database"
    original_exists = Path.exists
    moved = False

    def remove_before_second_check(path: Path) -> bool:
        nonlocal moved
        if path == paths.database and not moved:
            moved = True
            path.rename(retained)
        return original_exists(path)

    def refuse_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("missing existing Store must not reach native connect")

    monkeypatch.setattr(Path, "exists", remove_before_second_check)
    monkeypatch.setattr(sqlcipher, "connect", refuse_connect)
    with pytest.raises(WrongProductError, match="database is missing"):
        database.open_database(paths, b"w" * 32, read_only=False)

    assert moved
    assert not paths.database.exists()
    assert retained.read_bytes() == b"synthetic retained database sentinel"


def test_writer_open_does_not_recreate_database_removed_at_native_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from memory.errors import StoreError

    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"w" * 32
    database.open_database(paths, key, read_only=False, create_missing=True).close()
    retained = tmp_path / "synthetic-original-database"
    original_bytes = paths.database.read_bytes()
    original_connect = sqlcipher.connect
    moved = False

    def remove_at_connect(*args: object, **kwargs: object) -> object:
        nonlocal moved
        assert not moved
        moved = True
        paths.database.rename(retained)
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(sqlcipher, "connect", remove_at_connect)
    with pytest.raises(StoreError):
        database.open_database(paths, key, read_only=False)

    assert moved
    assert not paths.database.exists()
    assert retained.read_bytes() == original_bytes


def test_read_only_open_sets_query_only_and_refuses_writes(tmp_path: Path) -> None:
    """Catch a supposedly read-only advice connection that still accepts writes."""
    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"r" * 32
    database.open_database(paths, key, read_only=False, create_missing=True).close()

    connection = database.open_database(paths, key, read_only=True)
    try:
        query_only = connection.execute("PRAGMA query_only").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        identity = connection.execute("SELECT product FROM store_meta").fetchone()
        with pytest.raises(sqlcipher.OperationalError):
            connection.execute(
                "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
                ("synthetic-lineage", 1),
            )
    finally:
        connection.close()

    assert query_only == (1,)
    assert foreign_keys == (1,)
    assert identity == ("memory",)


def test_read_only_open_sees_committed_rows_while_wal_writer_remains_open(
    tmp_path: Path,
) -> None:
    """Catch immutable readers silently omitting live committed WAL pages."""
    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"v" * 32
    database.open_database(paths, key, read_only=False, create_missing=True).close()
    writer = database.open_database(paths, key, read_only=False)
    try:
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute(
            "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
            ("synthetic-live-wal-lineage", 1),
        )
        writer.commit()
        assert Path(f"{paths.database}-wal").stat().st_size > 0

        reader = database.open_database(paths, key, read_only=True)
        try:
            count = reader.execute("SELECT count(*) FROM memory_lineages").fetchone()
        finally:
            reader.close()
    finally:
        writer.close()

    assert count == (1,)


def crash_new_database_on_pragma(
    root: Path,
    key: bytes,
    pragma: str,
    exit_code: int,
) -> subprocess.CompletedProcess[str]:
    """Crash a real child at one exact initial-database PRAGMA boundary."""
    script = """
import os
import sys
from pathlib import Path

from memory import database
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path(sys.argv[1]))
key = bytes.fromhex(sys.argv[2])
target = " ".join(sys.argv[3].split()).casefold()
exit_code = int(sys.argv[4])
connect = database.sqlcipher.connect

class CrashAtPragma:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, *arguments):
        if " ".join(sql.split()).casefold() == target:
            os._exit(exit_code)
        return self.connection.execute(sql, *arguments)

    def __getattr__(self, name):
        return getattr(self.connection, name)

database.sqlcipher.connect = lambda *args, **kwargs: CrashAtPragma(
    connect(*args, **kwargs)
)
database.open_database(paths, key, read_only=False, create_missing=True)
raise SystemExit("initialization unexpectedly returned")
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-c", script, str(root), key.hex(), pragma, str(exit_code)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def crash_after_durable_schema_before_wal(
    root: Path,
    key: bytes,
    exit_code: int,
) -> subprocess.CompletedProcess[str]:
    """Leave the exact committed pre-WAL state of an interrupted initialization."""
    script = """
import os
import sys
from importlib import resources
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlcipher

from memory import database
from memory.runtime import load_runtime_identity, resolve_runtime

paths = resolve_runtime(Path(sys.argv[1]))
key = bytes.fromhex(sys.argv[2])
identity = load_runtime_identity(paths)
connection = sqlcipher.connect(str(paths.database))
database._apply_cipher_settings(connection, key)
connection.execute("PRAGMA foreign_keys = ON")
assert connection.execute("PRAGMA journal_mode = DELETE").fetchone() == ("delete",)
connection.execute("PRAGMA synchronous = FULL")
schema = resources.files("memory").joinpath("schema.sql").read_text(
    encoding="utf-8"
)
connection.executescript(schema)
connection.execute(
    "INSERT INTO store_meta "
    "(singleton, product, schema_lineage, schema_version, store_id, "
    "runtime_mode, audit_generation) VALUES (1, ?, ?, ?, ?, ?, 0)",
    (
        identity.product,
        identity.schema_lineage,
        identity.schema_version,
        identity.store_id,
        identity.runtime_mode.value,
    ),
)
connection.commit()
assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
assert connection.execute("PRAGMA synchronous").fetchone() == (2,)
os._exit(int(sys.argv[3]))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-c", script, str(root), key.hex(), str(exit_code)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def assert_retried_runtime_uses_wal_full(paths: RuntimePaths, key: bytes) -> None:
    """Assert the repaired runtime identity and writer durability profile."""
    database = importlib.import_module("memory.database")
    runtime = importlib.import_module("memory.runtime")
    assert (
        runtime.initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL).store_id
        == "2" * 32
    )
    connection = database.open_database(paths, key, read_only=True)
    try:
        identity = connection.execute(
            "SELECT product, schema_lineage, schema_version, store_id, "
            "runtime_mode FROM store_meta"
        ).fetchone()
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
    finally:
        connection.close()

    assert identity == (
        "memory",
        "memory-store-v1",
        1,
        "2" * 32,
        "personal",
    )
    assert journal_mode == ("wal",)
    assert synchronous == (2,)


def test_initial_schema_survives_process_crash_at_checkpoint_entry(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the schema commit remaining only in WAL when checkpoint starts."""
    paths = write_runtime_identity(tmp_path / "store")
    key = b"x" * 32
    synthetic_keychain[("memory", "2" * 32)] = base64.b64encode(key).decode("ascii")
    crashed = crash_new_database_on_pragma(
        paths.root,
        key,
        "PRAGMA wal_checkpoint(TRUNCATE)",
        91,
    )

    assert crashed.returncode == 91, crashed.stderr
    assert_retried_runtime_uses_wal_full(paths, key)
    assert synthetic_keychain == {
        ("memory", "2" * 32): base64.b64encode(key).decode("ascii")
    }


def test_initialize_retry_repairs_crash_before_initial_wal_transition(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a durable pre-WAL Store being returned without its WAL profile."""
    paths = write_runtime_identity(tmp_path / "store")
    key = b"t" * 32
    synthetic_keychain[("memory", "2" * 32)] = base64.b64encode(key).decode("ascii")
    crashed = crash_after_durable_schema_before_wal(
        paths.root,
        key,
        92,
    )

    assert crashed.returncode == 92, crashed.stderr
    assert_retried_runtime_uses_wal_full(paths, key)
    assert synthetic_keychain == {
        ("memory", "2" * 32): base64.b64encode(key).decode("ascii")
    }


def test_initial_schema_checkpoint_fails_closed_when_truncation_is_busy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch initialization returning before all committed WAL frames are durable."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"b" * 32
    real_connect = database.sqlcipher.connect

    class BusyCheckpointConnection:
        def __init__(self) -> None:
            self.connection: sqlite3.Connection = real_connect(str(paths.database))
            self.reader: sqlite3.Connection | None = None

        def execute(self, sql: str, parameters: Sequence[object] = ()) -> object:
            result = self.connection.execute(sql, parameters)
            if " ".join(sql.split()).casefold() == "pragma journal_mode = wal":
                owner = self

                class JournalModeCursor:
                    def fetchone(self) -> object:
                        row = result.fetchone()
                        owner._hold_wal_reader()
                        return row

                return JournalModeCursor()
            return result

        def _hold_wal_reader(self) -> None:
            self.connection.execute(
                "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
                ("synthetic-checkpoint-contention", 1),
            )
            self.connection.commit()
            reader = real_connect(str(paths.database))
            database._apply_cipher_settings(reader, key)
            reader.execute("BEGIN")
            assert reader.execute(
                "SELECT lineage_id FROM memory_lineages"
            ).fetchone() == ("synthetic-checkpoint-contention",)
            self.connection.execute("PRAGMA busy_timeout = 0")
            self.reader = reader

        def executescript(self, script: str) -> object:
            return self.connection.executescript(script)

        def commit(self) -> None:
            self.connection.commit()

        def close(self) -> None:
            if self.reader is not None:
                self.reader.close()
            self.connection.close()

    monkeypatch.setattr(
        database.sqlcipher,
        "connect",
        lambda *_args, **_kwargs: BusyCheckpointConnection(),
    )
    returned: sqlite3.Connection | None = None
    try:
        with pytest.raises(errors.StoreOpenError, match="checkpoint"):
            returned = database.open_database(
                paths, key, read_only=False, create_missing=True
            )
    finally:
        if returned is not None:
            returned.close()

    assert not paths.database.exists()
    assert not Path(f"{paths.database}-wal").exists()
    assert not Path(f"{paths.database}-shm").exists()


@pytest.mark.parametrize(
    ("column", "foreign_value"),
    [
        ("product", "synthetic-foreign-product"),
        ("schema_lineage", "synthetic-foreign-lineage"),
        ("store_id", "3" * 32),
    ],
)
def test_foreign_database_identity_is_rejected_without_writes(
    tmp_path: Path,
    column: str,
    foreign_value: str,
) -> None:
    """Catch writable setup occurring before product/lineage/Store-ID checks."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"i" * 32
    connection = database.open_database(
        paths, key, read_only=False, create_missing=True
    )
    connection.execute(f"UPDATE store_meta SET {column} = ?", (foreign_value,))
    connection.commit()
    connection.close()
    before = {
        suffix: Path(f"{paths.database}{suffix}").read_bytes()
        for suffix in ("", "-wal")
        if Path(f"{paths.database}{suffix}").exists()
    }

    with pytest.raises(errors.WrongProductError):
        database.open_database(paths, key, read_only=True)

    after = {
        suffix: Path(f"{paths.database}{suffix}").read_bytes()
        for suffix in ("", "-wal")
        if Path(f"{paths.database}{suffix}").exists()
    }
    assert after == before


def test_wrong_key_is_refused_without_database_mutation(tmp_path: Path) -> None:
    """Catch a wrong Keychain value being treated as a usable Store key."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    database.open_database(
        paths, b"c" * 32, read_only=False, create_missing=True
    ).close()
    before = paths.database.read_bytes()

    with pytest.raises(errors.KeyMismatchError):
        database.open_database(paths, b"w" * 32, read_only=True)

    assert paths.database.read_bytes() == before


def test_plaintext_or_foreign_database_is_wrong_product_without_mutation(
    tmp_path: Path,
) -> None:
    """Catch a foreign SQLite file being interpreted as a key failure or upgraded."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    foreign = sqlite3.connect(paths.database)
    foreign.execute("CREATE TABLE synthetic_foreign_record (value TEXT) STRICT")
    foreign.execute("INSERT INTO synthetic_foreign_record VALUES ('unchanged')")
    foreign.commit()
    foreign.close()
    before = paths.database.read_bytes()

    with pytest.raises(errors.WrongProductError):
        database.open_database(paths, b"f" * 32, read_only=True)

    assert paths.database.read_bytes() == before


def test_encrypted_foreign_schema_with_the_same_key_is_wrong_product(
    tmp_path: Path,
) -> None:
    """Catch a decryptable non-Store database being mistaken for a wrong key."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"e" * 32
    foreign = sqlcipher.connect(str(paths.database))
    foreign.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
    foreign.execute("PRAGMA cipher_page_size = 4096")
    foreign.execute("PRAGMA kdf_iter = 256000")
    foreign.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    foreign.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    foreign.execute("CREATE TABLE synthetic_foreign_record (value TEXT) STRICT")
    foreign.commit()
    foreign.close()

    with pytest.raises(errors.WrongProductError):
        database.open_database(paths, key, read_only=True)


def test_writer_session_uses_a_nonblocking_process_lock_and_commits(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch blocking or concurrent Store writers and missing transaction commit."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "store")
    key = b"s" * 32
    synthetic_keychain[("memory", "2" * 32)] = base64.b64encode(key).decode("ascii")
    database.open_database(paths, key, read_only=False, create_missing=True).close()

    assert hasattr(database, "writer_session")
    with database.writer_session(paths) as first:
        first.execute(
            "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
            ("synthetic-lineage", 1),
        )
        with pytest.raises(errors.StoreBusyError):
            with database.writer_session(paths):
                pytest.fail("a second writer acquired the same Store")

    reopened = database.open_database(paths, key, read_only=True)
    try:
        count = reopened.execute("SELECT count(*) FROM memory_lineages").fetchone()
    finally:
        reopened.close()

    assert count == (1,)
    assert stat.S_IMODE(paths.writer_lock.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("overrides", "distribution_version"),
    [
        ({"PRAGMA cipher_status": None}, "0.6.2+sqlcipher4.17.0.memory1"),
        ({"PRAGMA cipher_status": ("0",)}, "0.6.2+sqlcipher4.17.0.memory1"),
        (
            {"PRAGMA cipher_version": ("4.16.0 community",)},
            "0.6.2+sqlcipher4.17.0.memory1",
        ),
        ({"SELECT sqlite_version()": ("3.53.2",)}, "0.6.2+sqlcipher4.17.0.memory1"),
        ({"PRAGMA cipher_provider": ("synthetic",)}, "0.6.2+sqlcipher4.17.0.memory1"),
        (
            {"PRAGMA compile_options": [("THREADSAFE=1",)]},
            "0.6.2+sqlcipher4.17.0.memory1",
        ),
        ({}, "0.6.2+sqlcipher4.17.0"),
        ({}, "0.6.2"),
    ],
)
def test_native_engine_attestation_rejects_every_downgrade_or_plain_driver(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, Sequence[object] | None],
    distribution_version: str,
) -> None:
    """Prove package, cipher, provider, version, and features all fail closed."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    rows: dict[str, Sequence[object] | list[Sequence[object]] | None] = {
        "PRAGMA cipher_status": ("1",),
        "PRAGMA cipher_version": ("4.17.0 community",),
        "SELECT sqlite_version()": ("3.53.3",),
        "PRAGMA cipher_provider": ("openssl",),
        "PRAGMA compile_options": [
            (option,) for option in database.REQUIRED_SQLITE_COMPILE_OPTIONS
        ],
    }
    rows.update(overrides)

    class SyntheticCursor:
        def __init__(
            self,
            result: Sequence[object] | list[Sequence[object]] | None,
        ) -> None:
            self._result = result

        def fetchone(self) -> Sequence[object] | None:
            if isinstance(self._result, list):
                return self._result[0] if self._result else None
            return self._result

        def fetchall(self) -> list[Sequence[object]]:
            if isinstance(self._result, list):
                return self._result
            return [] if self._result is None else [self._result]

    class SyntheticConnection:
        def execute(self, statement: str) -> SyntheticCursor:
            return SyntheticCursor(rows[statement])

    monkeypatch.setattr(
        database.metadata,
        "version",
        lambda _name: distribution_version,
    )

    with pytest.raises(errors.StoreOpenError):
        database._validate_native_engine(SyntheticConnection())


def test_native_engine_attestation_accepts_exact_or_newer_supported_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove normalized status and version comparisons accept the selected kernel."""
    database = importlib.import_module("memory.database")

    class SyntheticCursor:
        def __init__(self, rows: list[Sequence[object]]) -> None:
            self._rows = rows

        def fetchone(self) -> Sequence[object] | None:
            return self._rows[0] if self._rows else None

        def fetchall(self) -> list[Sequence[object]]:
            return self._rows

    class SyntheticConnection:
        def execute(self, statement: str) -> SyntheticCursor:
            values: dict[str, list[Sequence[object]]] = {
                "PRAGMA cipher_status": [(1,)],
                "PRAGMA cipher_version": [("4.18.1 community",)],
                "SELECT sqlite_version()": [("3.54.0",)],
                "PRAGMA cipher_provider": [("openssl",)],
                "PRAGMA compile_options": [
                    (option,) for option in database.REQUIRED_SQLITE_COMPILE_OPTIONS
                ],
            }
            return SyntheticCursor(values[statement])

    monkeypatch.setattr(
        database.metadata,
        "version",
        lambda _name: "0.6.2+sqlcipher4.17.0.memory1",
    )

    database._validate_native_engine(SyntheticConnection())


def test_new_database_is_removed_when_native_attestation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a refused native kernel leaving a file that looks initialized."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "attestation-refused")

    def refuse(_connection: sqlite3.Connection) -> None:
        raise errors.StoreOpenError("encrypted database engine attestation failed")

    monkeypatch.setattr(database, "_validate_native_engine", refuse, raising=False)

    with pytest.raises(errors.StoreOpenError):
        database.open_database(paths, b"a" * 32, read_only=False, create_missing=True)

    assert not paths.database.exists()


def read_audit_generation(paths: RuntimePaths, key: bytes) -> int:
    database = importlib.import_module("memory.database")
    connection = database.open_database(paths, key, read_only=True)
    try:
        row = connection.execute(
            "SELECT audit_generation FROM store_meta WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return int(row[0])


def _sources_blob_index_state(
    paths: RuntimePaths,
) -> tuple[str | None, tuple[str, ...], int]:
    """Read the committed index, real duplicate plan, and audit generation."""
    database = importlib.import_module("memory.database")
    keys = importlib.import_module("memory.keys")
    runtime = importlib.import_module("memory.runtime")
    identity = runtime.load_runtime_identity(paths)
    key = keys.load_master_key(identity)
    connection = database.open_database(paths, key, read_only=True)
    try:
        index_row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?",
            (SOURCES_BLOB_INDEX_NAME,),
        ).fetchone()
        plan = tuple(
            str(row[3])
            for row in connection.execute(
                f"EXPLAIN QUERY PLAN {_DUPLICATE_CAPTURES_SQL}",
                ("bat_" + "d" * 32,),
            ).fetchall()
        )
        generation_row = connection.execute(
            "SELECT audit_generation FROM store_meta WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert generation_row is not None
    return (
        None if index_row is None else str(index_row[0]),
        plan,
        int(generation_row[0]),
    )


def _assert_duplicate_plan_uses_blob_index(plan: tuple[str, ...]) -> None:
    """Require a blob-key search, without pinning unrelated planner wording."""
    assert any(
        f"SEARCH earlier USING INDEX {SOURCES_BLOB_INDEX_NAME}" in step
        and "blob_id=?" in step
        for step in plan
    ), plan
    assert not any("SCAN earlier" in step for step in plan), plan


def test_fresh_schema_indexes_the_real_duplicate_capture_lookup() -> None:
    """Keep maximum-batch publication independent of retained Store size."""
    database = importlib.import_module("memory.database")
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    assert hasattr(database, "SOURCES_BLOB_ID_INDEX_SQL")
    index_ddl = str(database.SOURCES_BLOB_ID_INDEX_SQL)
    assert " ".join(index_ddl.split()) in " ".join(schema.split())

    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(schema)
        index_row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?",
            (SOURCES_BLOB_INDEX_NAME,),
        ).fetchone()
        plan = tuple(
            str(row[3])
            for row in connection.execute(
                f"EXPLAIN QUERY PLAN {_DUPLICATE_CAPTURES_SQL}",
                ("bat_" + "f" * 32,),
            ).fetchall()
        )
    finally:
        connection.close()

    assert index_row is not None
    assert " ".join(str(index_row[0]).split()) == " ".join(
        index_ddl.replace(" IF NOT EXISTS", "").split()
    )
    _assert_duplicate_plan_uses_blob_index(plan)


def test_existing_store_heals_duplicate_index_atomically_and_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Heal legacy Stores in one generation-bound transaction, or not at all."""
    database = importlib.import_module("memory.database")
    with database.writer_session(synthetic_store) as connection:
        connection.execute(f"DROP INDEX IF EXISTS {SOURCES_BLOB_INDEX_NAME}")
    absent_sql, _plan, generation_before = _sources_blob_index_state(synthetic_store)
    assert absent_sql is None

    with database.writer_session(synthetic_store):
        pass

    healed_sql, healed_plan, generation_after = _sources_blob_index_state(
        synthetic_store
    )
    assert healed_sql is not None
    _assert_duplicate_plan_uses_blob_index(healed_plan)
    assert generation_after == generation_before + 1

    with database.writer_session(synthetic_store):
        pass
    assert _sources_blob_index_state(synthetic_store)[2] == generation_after

    with database.writer_session(synthetic_store) as connection:
        connection.execute(f"DROP INDEX {SOURCES_BLOB_INDEX_NAME}")
    absent_sql, _plan, rollback_generation = _sources_blob_index_state(synthetic_store)
    assert absent_sql is None

    with pytest.raises(RuntimeError, match="synthetic index-heal rollback"):
        with database.writer_session(synthetic_store):
            raise RuntimeError("synthetic index-heal rollback")

    rolled_back_sql, _plan, rolled_back_generation = _sources_blob_index_state(
        synthetic_store
    )
    assert rolled_back_sql is None
    assert rolled_back_generation == rollback_generation


def test_audit_generation_increments_once_per_changed_commit_not_rollback_or_noop(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Pin authoritative, projection-only, combined, rollback, and no-op writes."""
    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "audit-store")
    key = b"a" * 32
    synthetic_keychain[("memory", "2" * 32)] = base64.b64encode(key).decode("ascii")
    database.open_database(paths, key, read_only=False, create_missing=True).close()

    assert read_audit_generation(paths, key) == 0
    with database.writer_session(paths) as connection:
        connection.execute(
            "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
            ("lin_authoritative", 1),
        )
    assert read_audit_generation(paths, key) == 1

    with database.writer_session(paths) as connection:
        connection.execute(
            "INSERT INTO source_fts (source_id, utf8_text) VALUES (?, ?)",
            ("src_projection", "synthetic projection"),
        )
    assert read_audit_generation(paths, key) == 2

    with database.writer_session(paths) as connection:
        connection.execute(
            "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
            ("lin_combined", 2),
        )
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            ("mem_projection", "synthetic combined", "synthetic"),
        )
    assert read_audit_generation(paths, key) == 3

    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with database.writer_session(paths) as connection:
            connection.execute(
                "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
                ("lin_rollback", 3),
            )
            raise RuntimeError("synthetic rollback")
    assert read_audit_generation(paths, key) == 3

    with database.writer_session(paths):
        pass
    assert read_audit_generation(paths, key) == 3


def test_audit_generation_rolls_back_after_writer_process_crash(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a crashed transaction publishing its row or audit generation."""
    database = importlib.import_module("memory.database")
    paths = write_runtime_identity(tmp_path / "audit-crash-store")
    key = b"c" * 32
    synthetic_keychain[("memory", "2" * 32)] = base64.b64encode(key).decode("ascii")
    database.open_database(paths, key, read_only=False, create_missing=True).close()
    script = """
import os
import sys
from pathlib import Path
from memory import database
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path(sys.argv[1]))
key = bytes.fromhex(sys.argv[2])
database.load_master_key = lambda _identity: key
with database.writer_session(paths) as connection:
    connection.execute(
        "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
        ("lin_crashed", 4),
    )
    os._exit(93)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(paths.root), key.hex()],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert crashed.returncode == 93, crashed.stderr
    assert read_audit_generation(paths, key) == 0
    reopened = database.open_database(paths, key, read_only=True)
    try:
        assert reopened.execute(
            "SELECT count(*) FROM memory_lineages WHERE lineage_id = 'lin_crashed'"
        ).fetchone() == (0,)
    finally:
        reopened.close()


def test_database_identity_requires_structurally_valid_audit_generation(
    tmp_path: Path,
) -> None:
    """Catch foreign/missing or negative audit generations being accepted."""
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = write_runtime_identity(tmp_path / "missing-generation")
    key = b"g" * 32
    foreign = sqlcipher.connect(str(paths.database))
    database._apply_cipher_settings(foreign, key)
    foreign.execute(
        "CREATE TABLE store_meta ("
        "singleton INTEGER PRIMARY KEY, product TEXT, schema_lineage TEXT, "
        "schema_version INTEGER, store_id TEXT, runtime_mode TEXT)"
    )
    foreign.execute(
        "INSERT INTO store_meta VALUES (1, ?, ?, 1, ?, ?)",
        ("memory", "memory-store-v1", "2" * 32, "personal"),
    )
    foreign.execute("PRAGMA user_version = 1")
    foreign.commit()
    foreign.close()

    with pytest.raises(errors.WrongProductError):
        database.open_database(paths, key, read_only=True)

    paths = write_runtime_identity(tmp_path / "negative-generation")
    database.open_database(paths, key, read_only=False, create_missing=True).close()
    connection = database.open_database(paths, key, read_only=False)
    connection.execute("PRAGMA ignore_check_constraints = ON")
    connection.execute("UPDATE store_meta SET audit_generation = -1")
    connection.commit()
    connection.close()
    with pytest.raises(errors.WrongProductError):
        database.open_database(paths, key, read_only=True)
