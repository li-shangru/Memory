"""Encrypted Store database boundary."""

from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from importlib import metadata, resources
from pathlib import Path
from typing import Any, Protocol, cast

from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]

from memory.errors import (
    InvalidArgumentError,
    KeyMismatchError,
    StoreOpenError,
    WrongProductError,
)
from memory.keys import load_master_key
from memory.model import RuntimePaths, SecretBytes, StoreIdentity
from memory.runtime import _writer_lock, load_runtime_identity

type Connection = sqlite3.Connection
#: One row as the driver hands it back: positional, heterogeneous, and
#: meaningful only beside the SELECT that produced it. Naming it lets a row
#: converter be typed as `Callable[[Row], T]` instead of `Any`, which is what
#: makes a generic page function actually check its converter.
type Row = Sequence[Any]
PINNED_CIPHER_SETTINGS = {
    "cipher_page_size": "4096",
    "kdf_iter": "256000",
    "cipher_hmac_algorithm": "HMAC_SHA512",
    "cipher_kdf_algorithm": "PBKDF2_HMAC_SHA512",
}
SQLCIPHER_DISTRIBUTION = "memory-sqlcipher3"
SQLCIPHER_DISTRIBUTION_VERSION = "0.6.2+sqlcipher4.17.0.memory1"
MINIMUM_SQLCIPHER_VERSION = (4, 17, 0)
MINIMUM_SQLITE_VERSION = (3, 53, 3)
REQUIRED_SQLITE_COMPILE_OPTIONS = frozenset(
    {
        "HAS_CODEC",
        "ENABLE_COLUMN_METADATA",
        "ENABLE_FTS3",
        "ENABLE_FTS3_PARENTHESIS",
        "ENABLE_FTS4",
        "ENABLE_FTS5",
        "ENABLE_MATH_FUNCTIONS",
        "ENABLE_PERCENTILE",
        "ENABLE_RTREE",
        "ENABLE_STAT4",
        "ENABLE_UPDATE_DELETE_LIMIT",
        "EXTRA_INIT=sqlcipher_extra_init",
        "EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",
        "SOUNDEX",
        "USE_URI",
        "TEMP_STORE=2",
        "THREADSAFE=1",
        "MAX_VARIABLE_NUMBER=250000",
        "DEFAULT_PAGE_SIZE=4096",
        "DEFAULT_CACHE_SIZE=-8000",
    }
)
SOURCES_BLOB_ID_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_sources_blob_id ON sources(blob_id)"
)
INBOX_SCAN_PROGRESS_SQL = """CREATE TABLE IF NOT EXISTS inbox_scan_progress (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    token TEXT NOT NULL
) STRICT"""
INBOX_SCAN_CANDIDATES_SQL = """CREATE TABLE IF NOT EXISTS inbox_scan_candidates (
    token TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    name TEXT NOT NULL,
    PRIMARY KEY (token, ordinal),
    UNIQUE (token, name)
) STRICT"""
MEMORY_DETAIL_INDEXES_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_memory_lineage_history "
    "ON memory_revisions(lineage_id, recorded_at)",
    "CREATE INDEX IF NOT EXISTS idx_memory_guard_governed "
    "ON memory_guard_links(governed_lineage_id, guard_lineage_id) "
    "WHERE revoked_at IS NULL",
    "CREATE INDEX IF NOT EXISTS idx_memory_guard_active "
    "ON memory_guard_links(guard_lineage_id, governed_lineage_id) "
    "WHERE revoked_at IS NULL",
)
MEMORY_GUARD_LINKS_SQL = """CREATE TABLE IF NOT EXISTS memory_guard_links (
    guard_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    governed_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    revoked_at INTEGER,
    revoking_application_id TEXT REFERENCES applications(application_id),
    PRIMARY KEY (guard_lineage_id, governed_lineage_id),
    CHECK (guard_lineage_id <> governed_lineage_id)
) STRICT"""
CHANGE_REVISION_GUARD_LINKS_SQL = """CREATE TABLE IF NOT EXISTS change_revision_guard_links (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    guard_item_id TEXT,
    guard_lineage_id TEXT,
    governed_item_id TEXT,
    governed_lineage_id TEXT,
    PRIMARY KEY (revision_id, ordinal),
    CHECK ((guard_item_id IS NULL) <> (guard_lineage_id IS NULL)),
    CHECK ((governed_item_id IS NULL) <> (governed_lineage_id IS NULL))
) STRICT"""
CHANGE_REVISION_GUARD_REVOCATIONS_SQL = """CREATE TABLE IF NOT EXISTS change_revision_guard_revocations (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    guard_item_id TEXT,
    guard_lineage_id TEXT,
    governed_item_id TEXT,
    governed_lineage_id TEXT,
    PRIMARY KEY (revision_id, ordinal),
    CHECK ((guard_item_id IS NULL) <> (guard_lineage_id IS NULL)),
    CHECK ((governed_item_id IS NULL) <> (governed_lineage_id IS NULL))
) STRICT"""
#: The two columns a guard link needs to record its own revocation, declared
#: exactly as `ALTER TABLE ADD COLUMN` will add them to a store that already
#: holds the three-column table. `CREATE TABLE IF NOT EXISTS` never alters an
#: existing table, so this is the only path by which such a store reaches the
#: current shape. Both are nullable with no default, which is the one column
#: shape `ALTER TABLE ADD COLUMN` accepts on a STRICT table -- and, with
#: foreign keys on, the one shape it accepts for a REFERENCES column at all.
MEMORY_GUARD_LINK_REVOCATION_COLUMNS = {
    "revoked_at": "INTEGER",
    "revoking_application_id": "TEXT REFERENCES applications(application_id)",
}


def _table_columns(connection: Connection, table: str) -> set[str]:
    """Name every column one table currently declares."""
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def guard_revocations_recorded(connection: Connection) -> bool:
    """Report whether memory_guard_links can hold a revocation on this store.

    Read paths never heal, so they ask this before naming either column: a
    store the writer-side heal has not reached yet holds no revoked link by
    construction, and reading it as if every link were live is exactly right.
    """
    return set(MEMORY_GUARD_LINK_REVOCATION_COLUMNS) <= _table_columns(
        connection, "memory_guard_links"
    )


def _ensure_auxiliary_tables(connection: Connection) -> None:
    """Create additive schema objects missing from older Store shapes."""
    connection.execute(SOURCES_BLOB_ID_INDEX_SQL)
    connection.execute(INBOX_SCAN_PROGRESS_SQL)
    connection.execute(INBOX_SCAN_CANDIDATES_SQL)
    connection.execute(MEMORY_GUARD_LINKS_SQL)
    connection.execute(CHANGE_REVISION_GUARD_LINKS_SQL)
    connection.execute(CHANGE_REVISION_GUARD_REVOCATIONS_SQL)
    present = _table_columns(connection, "memory_guard_links")
    for name, declaration in MEMORY_GUARD_LINK_REVOCATION_COLUMNS.items():
        if name not in present:
            connection.execute(
                f"ALTER TABLE memory_guard_links ADD COLUMN {name} {declaration}"
            )
    for statement in MEMORY_DETAIL_INDEXES_SQL:
        connection.execute(statement)


@dataclass(frozen=True)
class _DatabaseDirectoryAuthority:
    paths: RuntimePaths
    anchored_paths: RuntimePaths
    root_descriptor: int
    database_identity: tuple[int, int]
    identity: StoreIdentity
    validate: Callable[[], None]
    require_private: bool


_DATABASE_AUTHORITY: ContextVar[_DatabaseDirectoryAuthority | None] = ContextVar(
    "memory_database_directory_authority", default=None
)


class _NativeFileIdentity(Protocol):
    def file_identity(self) -> tuple[int, int]: ...


def _validate_connection_authority(paths: RuntimePaths, connection: Connection) -> None:
    """Match the native opened main-file inode, never just its current name."""
    authority = _DATABASE_AUTHORITY.get()
    if authority is None or authority.paths != paths:
        return
    _validate_database_authority(paths)
    try:
        native = cast(_NativeFileIdentity, connection).file_identity()
    except (AttributeError, sqlcipher.Error) as error:
        raise StoreOpenError("native Store database identity is unavailable") from error
    if (
        not isinstance(native, tuple)
        or len(native) != 2
        or any(
            not isinstance(value, int) or isinstance(value, bool) for value in native
        )
    ):
        raise StoreOpenError("native Store database identity is invalid")
    if native != authority.database_identity:
        raise InvalidArgumentError("Store native database identity changed")
    _validate_database_authority(paths)


@contextmanager
def _database_directory_authority(
    paths: RuntimePaths,
    root_descriptor: int,
    validate: Callable[[], None],
    *,
    require_private: bool = True,
) -> Iterator[None]:
    """Bind one operation's SQLite database and WAL to a held macOS directory.

    SQLite preserves the inode namespace in its filename. A lexical ancestor
    replacement cannot redirect a later connection or WAL sidecar creation.
    Persisted runtime paths retain their ordinary lexical spelling.
    """
    validate()
    root = os.fstat(root_descriptor)
    anchor = Path(f"/.vol/{root.st_dev}/{root.st_ino}")
    anchored_root = anchor.stat()
    if (anchored_root.st_dev, anchored_root.st_ino) != (root.st_dev, root.st_ino):
        raise InvalidArgumentError("Store database directory changed")
    anchored = replace(
        paths,
        root=anchor,
        database=anchor / "store.sqlite3",
        identity=anchor / "runtime.json",
    )
    database = os.stat(
        "store.sqlite3",
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    identity = load_runtime_identity(anchored)
    if identity.inbox_path != str(paths.inbox):
        raise InvalidArgumentError("Store runtime identity changed")
    authority = _DatabaseDirectoryAuthority(
        paths,
        anchored,
        root_descriptor,
        (database.st_dev, database.st_ino),
        identity,
        validate,
        require_private,
    )
    scope_handle = _DATABASE_AUTHORITY.set(authority)
    pin: Connection | None = None
    try:
        _validate_database_authority(paths)
        # SQLite must own this pin's descriptor lifecycle. Closing an ordinary
        # os.open descriptor releases every process POSIX lock on the inode,
        # including locks belonging to unrelated live SQLite connections.
        # The read-only engine connection retains no read transaction or writer
        # session, and uses SQLite's shared-inode deferred-close handling.
        pin = open_database(paths, load_master_key(identity), read_only=True)
        _validate_connection_authority(paths, pin)
        yield
    finally:
        try:
            if pin is not None:
                pin.close()
        finally:
            _DATABASE_AUTHORITY.reset(scope_handle)


def _validate_database_authority(paths: RuntimePaths) -> None:
    authority = _DATABASE_AUTHORITY.get()
    if authority is None or authority.paths != paths:
        return
    authority.validate()
    named = os.stat(
        "store.sqlite3",
        dir_fd=authority.root_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_uid != os.geteuid()
        or named.st_nlink != 1
        or (authority.require_private and stat.S_IMODE(named.st_mode) != 0o600)
        or (named.st_dev, named.st_ino) != authority.database_identity
    ):
        raise InvalidArgumentError("Store database identity changed")


def _database_runtime_identity(paths: RuntimePaths) -> StoreIdentity:
    authority = _DATABASE_AUTHORITY.get()
    if authority is None or authority.paths != paths:
        return load_runtime_identity(paths)
    _validate_database_authority(paths)
    identity = load_runtime_identity(authority.anchored_paths)
    if identity != authority.identity:
        raise InvalidArgumentError("Store runtime identity changed")
    return identity


def _database_file_path(paths: RuntimePaths) -> Path:
    authority = _DATABASE_AUTHORITY.get()
    if authority is not None and authority.paths == paths:
        _validate_database_authority(paths)
        return authority.anchored_paths.database
    return paths.database


def _database_uri(paths: RuntimePaths, database_path: Path) -> str:
    authority = _DATABASE_AUTHORITY.get()
    if authority is not None and authority.paths == paths:
        return database_path.as_uri()
    return database_path.resolve().as_uri()


def open_database(
    paths: RuntimePaths,
    key: SecretBytes,
    read_only: bool,
    *,
    create_missing: bool = False,
) -> Connection:
    """Open, configure, and identity-check one encrypted Store database.

    Only initialization passes `create_missing`. An ordinary writer whose
    database file is gone fails closed exactly as a reader does: silently
    minting a fresh empty database under the surviving runtime identity
    would mask the loss of the real Store behind an empty replacement.
    """
    if len(key) != 32:
        raise ValueError("Store key must be exactly 32 bytes")
    identity = _database_runtime_identity(paths)
    database_path = _database_file_path(paths)
    if not create_missing and not database_path.is_file():
        raise WrongProductError("Store database is missing")
    if read_only:
        _preflight_database(paths, key, identity)
    existing = database_path.exists()
    if not existing and not create_missing:
        raise WrongProductError("Store database is missing")

    created = False
    connection: Connection | None = None
    try:
        if read_only:
            uri = f"{_database_uri(paths, database_path)}?mode=ro"
            connection = cast(Connection, sqlcipher.connect(uri, uri=True))
        elif existing:
            # mode=rw cannot silently recreate an existing Store removed after
            # the preceding checks. Keep the writer's lexical path spelling.
            uri = f"{database_path.absolute().as_uri()}?mode=rw"
            connection = cast(Connection, sqlcipher.connect(uri, uri=True))
        else:
            descriptor = os.open(
                database_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
            created = True
            connection = cast(Connection, sqlcipher.connect(str(database_path)))

        _validate_connection_authority(paths, connection)
        _apply_cipher_settings(connection, key)
        if existing:
            connection.execute("PRAGMA foreign_keys = ON")
            if read_only:
                connection.execute("PRAGMA query_only = ON")
            _validate_identity(connection, identity)
            if not read_only:
                _validate_connection_authority(paths, connection)
                _configure_writer(connection)
        else:
            _configure_initial_writer(connection)
            _create_schema(connection, identity)
            _configure_writer(connection)
            _checkpoint_database(connection)
        return connection
    except sqlcipher.DatabaseError as error:
        if connection is not None:
            connection.close()
        if created:
            _remove_created_database(database_path)
            raise StoreOpenError("encrypted Store initialization failed") from error
        if _has_plaintext_sqlite_header(database_path):
            raise WrongProductError("foreign plaintext database refused") from error
        raise KeyMismatchError(
            "Store key does not unlock the selected database"
        ) from error
    except BaseException:
        if connection is not None:
            connection.close()
        if created:
            _remove_created_database(database_path)
        raise


def _preflight_database(
    paths: RuntimePaths,
    key: SecretBytes,
    identity: StoreIdentity | None = None,
) -> None:
    """Validate an existing database without observing or creating WAL sidecars."""
    if len(key) != 32:
        raise ValueError("Store key must be exactly 32 bytes")
    expected = _database_runtime_identity(paths) if identity is None else identity
    database_path = _database_file_path(paths)
    if not database_path.is_file():
        raise WrongProductError("Store database is missing")

    connection: Connection | None = None
    try:
        uri = f"{_database_uri(paths, database_path)}?mode=ro&immutable=1"
        connection = cast(Connection, sqlcipher.connect(uri, uri=True))
        _validate_connection_authority(paths, connection)
        _apply_cipher_settings(connection, key)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA query_only = ON")
        _validate_identity(connection, expected)
    except sqlcipher.DatabaseError as error:
        if _has_plaintext_sqlite_header(database_path):
            raise WrongProductError("foreign plaintext database refused") from error
        raise KeyMismatchError(
            "Store key does not unlock the selected database"
        ) from error
    finally:
        if connection is not None:
            connection.close()


@contextmanager
def writer_session(paths: RuntimePaths) -> Iterator[Connection]:
    """Yield one bounded writable transaction under a nonblocking file lock."""
    with _writer_lock(paths):
        with _writer_transaction(paths) as connection:
            yield connection


@contextmanager
def _writer_transaction(paths: RuntimePaths) -> Iterator[Connection]:
    """Yield a bounded transaction when the caller already owns the Store lock."""
    identity = _database_runtime_identity(paths)
    key = load_master_key(identity)
    connection = open_database(paths, key, read_only=False)
    try:
        _validate_connection_authority(paths, connection)
        connection.execute("BEGIN IMMEDIATE")
        schema_version_before = connection.execute("PRAGMA schema_version").fetchone()
        changes_before = connection.total_changes
        try:
            _ensure_auxiliary_tables(connection)
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            _validate_connection_authority(paths, connection)
            schema_version_after = connection.execute(
                "PRAGMA schema_version"
            ).fetchone()
            rows_changed = connection.total_changes > changes_before
            schema_changed = schema_version_after != schema_version_before
            if schema_changed or rows_changed:
                updated = connection.execute(
                    "UPDATE store_meta SET audit_generation = audit_generation + 1 "
                    "WHERE singleton = 1"
                )
                if updated.rowcount != 1:
                    raise WrongProductError("database audit generation is missing")
            connection.commit()
    finally:
        connection.close()


def _apply_cipher_settings(connection: Connection, key: SecretBytes) -> None:
    connection.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
    for name, value in PINNED_CIPHER_SETTINGS.items():
        connection.execute(f"PRAGMA {name} = {value}")
    connection.execute("PRAGMA cipher_memory_security = ON")
    _validate_native_engine(connection)


def _validate_native_engine(connection: Connection) -> None:
    """Attest the locked encrypted kernel before any Store content access."""
    try:
        distribution_version = metadata.version(SQLCIPHER_DISTRIBUTION)
    except metadata.PackageNotFoundError as error:
        raise StoreOpenError("encrypted database engine attestation failed") from error
    if distribution_version != SQLCIPHER_DISTRIBUTION_VERSION:
        raise StoreOpenError("encrypted database engine attestation failed")

    status = _native_scalar(connection, "PRAGMA cipher_status")
    cipher_version = _native_version(
        _native_scalar(connection, "PRAGMA cipher_version"),
    )
    sqlite_version = _native_version(
        _native_scalar(connection, "SELECT sqlite_version()"),
    )
    provider = _native_scalar(connection, "PRAGMA cipher_provider")
    option_rows = connection.execute("PRAGMA compile_options").fetchall()
    if status != "1" or provider != "openssl":
        raise StoreOpenError("encrypted database engine attestation failed")
    if (
        cipher_version < MINIMUM_SQLCIPHER_VERSION
        or sqlite_version < MINIMUM_SQLITE_VERSION
    ):
        raise StoreOpenError("encrypted database engine attestation failed")
    options = {
        str(row[0]) for row in option_rows if len(row) == 1 and isinstance(row[0], str)
    }
    if not REQUIRED_SQLITE_COMPILE_OPTIONS <= options:
        raise StoreOpenError("encrypted database engine attestation failed")


def _native_scalar(connection: Connection, statement: str) -> str:
    row = connection.execute(statement).fetchone()
    if row is None or len(row) != 1:
        raise StoreOpenError("encrypted database engine attestation failed")
    value = row[0]
    if not isinstance(value, str | int):
        raise StoreOpenError("encrypted database engine attestation failed")
    return str(value)


def _native_version(raw: str) -> tuple[int, int, int]:
    components = raw.split(maxsplit=1)[0].split(".")
    if len(components) != 3 or any(not component.isascii() for component in components):
        raise StoreOpenError("encrypted database engine attestation failed")
    try:
        return cast(
            tuple[int, int, int], tuple(int(component) for component in components)
        )
    except ValueError as error:
        raise StoreOpenError("encrypted database engine attestation failed") from error


def _configure_writer(connection: Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
    connection.execute("PRAGMA synchronous = FULL")
    synchronous = connection.execute("PRAGMA synchronous").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    if journal_mode != ("wal",) or synchronous != (2,) or foreign_keys != (1,):
        raise StoreOpenError("Store writer configuration did not complete")


def _configure_initial_writer(connection: Connection) -> None:
    """Keep the first identity commit in the durable main database."""
    connection.execute("PRAGMA foreign_keys = ON")
    journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
    connection.execute("PRAGMA synchronous = FULL")
    synchronous = connection.execute("PRAGMA synchronous").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    if journal_mode != ("delete",) or synchronous != (2,) or foreign_keys != (1,):
        raise StoreOpenError("initial Store writer configuration did not complete")


def _create_schema(connection: Connection, identity: StoreIdentity) -> None:
    schema = (
        resources.files("memory").joinpath("schema.sql").read_text(encoding="utf-8")
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


def _checkpoint_database(connection: Connection) -> None:
    """Require the initial WAL transition to finish without pending frames."""
    checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if (
        checkpoint is None
        or len(checkpoint) != 3
        or checkpoint[0] != 0
        or checkpoint[1] != checkpoint[2]
    ):
        raise StoreOpenError("initial Store checkpoint did not complete")


def _validate_identity(connection: Connection, expected: StoreIdentity) -> None:
    user_version = connection.execute("PRAGMA user_version").fetchone()
    try:
        row = connection.execute(
            "SELECT product, schema_lineage, schema_version, store_id, "
            "runtime_mode, audit_generation "
            "FROM store_meta WHERE singleton = 1"
        ).fetchone()
    except sqlcipher.OperationalError as error:
        raise WrongProductError("database has a foreign schema") from error
    wanted = (
        expected.product,
        expected.schema_lineage,
        expected.schema_version,
        expected.store_id,
        expected.runtime_mode.value,
    )
    if (
        row is None
        or tuple(row[:5]) != wanted
        or not isinstance(row[5], int)
        or row[5] < 0
        or user_version != (expected.schema_version,)
    ):
        raise WrongProductError("database identity does not match the Store runtime")


def _remove_created_database(database: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{database}{suffix}")
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


_PLAINTEXT_HEADER_PROBE = """
import os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SystemExit(2)
        plaintext = os.read(fd, 16) == b"SQLite format 3\\x00"
    finally:
        os.close(fd)
except OSError:
    raise SystemExit(2)
raise SystemExit(0 if plaintext else 1)
"""


def _has_plaintext_sqlite_header(database: Path) -> bool:
    # A raw main-file FD close in this process would release POSIX locks held by
    # unrelated SQLite connections. This bounded child returns only a boolean;
    # no key or database bytes cross the process boundary.
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _PLAINTEXT_HEADER_PROBE, str(database)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except OSError, subprocess.TimeoutExpired:
        return False
    return result.returncode == 0
