"""Recoverable, descriptor-bound publication of a new encrypted Store.

An intent owns exact directory and file identities, never just a pathname. The
unpublished database is disposable until a durable ready record. No plaintext
key is recorded, and existing Stores never enter this protocol.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import Foundation  # type: ignore[import-untyped]
from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]

from memory.errors import (
    InitializationError,
    KeyMissingError,
    StoreOpenError,
    WrongProductError,
)
from memory.initialization_fs import (
    BoundDirectory,
    DirectoryPins,
    file_metadata,
    open_file,
    read_file,
    require_distinct_layout,
)
from memory.initialization_fs import (
    identity as file_identity,
)
from memory.model import RuntimeMode, RuntimePaths, SecretBytes, StoreIdentity

INTENT = ".initialization.intent.json"
STAGED_IDENTITY = ".initialization.runtime.json"
STAGED_DATABASE = ".initialization.store.sqlite3"
ARTIFACTS = (INTENT, STAGED_IDENTITY, STAGED_DATABASE)
_FORMAT = "memory-initialization.v1"


def _init_checkpoint(name: str) -> None:
    """Process-death seam; every name is exercised in test_initialization.py."""


def _encoded(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def _identity_payload(identity: StoreIdentity) -> dict[str, object]:
    return {
        "product": identity.product,
        "schema_lineage": identity.schema_lineage,
        "schema_version": identity.schema_version,
        "store_id": identity.store_id,
        "runtime_mode": identity.runtime_mode.value,
        "inbox_path": identity.inbox_path,
    }


def _anchored(paths: RuntimePaths, root: BoundDirectory) -> RuntimePaths:
    anchor = root.anchor
    return dataclasses.replace(
        paths,
        root=anchor,
        identity=anchor / paths.identity.name,
        database=anchor / paths.database.name,
        writer_lock=anchor / paths.writer_lock.name,
        inbox_claims=anchor / paths.inbox_claims.name,
        inbox_staging=anchor / paths.inbox_staging.name,
        ui_session_lock=anchor / paths.ui_session_lock.name,
    )


def _optional_directory(pins: DirectoryPins, path: Path) -> BoundDirectory | None:
    try:
        return pins.open(path)
    except FileNotFoundError:
        return None


def _layout(
    pins: DirectoryPins, paths: RuntimePaths, root: BoundDirectory, *, create: bool
) -> tuple[BoundDirectory, BoundDirectory, BoundDirectory]:
    inbox = pins.open(paths.inbox, create=create)
    claims = pins.open(paths.inbox_claims, create=create)
    staging = pins.open(paths.inbox_staging, create=create)
    require_distinct_layout(root, inbox, claims, staging)
    pins.validate()
    return inbox, claims, staging


def initialize(
    paths: RuntimePaths, *, mode: RuntimeMode, inbox_argument: Path | None
) -> StoreIdentity:
    from memory import runtime

    with DirectoryPins() as pins:
        root = _optional_directory(pins, paths.root)
        if root is not None:
            has_intent = file_metadata(root, INTENT) is not None
            has_identity = file_metadata(root, paths.identity.name) is not None
            if not has_intent and has_identity:
                return _reopen(pins, root, paths, mode, inbox_argument)
            if not has_intent:
                unexpected = set(os.listdir(root.descriptor)) - {paths.writer_lock.name}
                if unexpected:
                    raise InitializationError(
                        "Store home must be empty; incomplete preparation requires recovery"
                    )
        else:
            root = pins.open(paths.root, create=True, parents=True)
        pins.validate()
        with runtime._writer_lock(paths, root_descriptor=root.descriptor):
            pins.validate()
            if file_metadata(root, INTENT) is not None:
                return _recover(pins, root, paths, mode, inbox_argument)
            if file_metadata(root, paths.identity.name) is not None:
                return _reopen(pins, root, paths, mode, inbox_argument, locked=True)
            if set(os.listdir(root.descriptor)) - {paths.writer_lock.name}:
                raise InitializationError(
                    "Store initialization preparation is incomplete"
                )
            return _prepare(pins, root, paths, mode)


def _reopen(
    pins: DirectoryPins,
    root: BoundDirectory,
    paths: RuntimePaths,
    mode: RuntimeMode,
    inbox_argument: Path | None,
    *,
    locked: bool = False,
    authorized_files: dict[str, tuple[int, int]] | None = None,
) -> StoreIdentity:
    from memory import runtime
    from memory.database import _database_directory_authority, open_database

    anchored = _anchored(paths, root)
    files: dict[str, tuple[int, int]] = {}
    for name in (paths.identity.name, paths.database.name):
        metadata = file_metadata(root, name)
        if metadata is not None:
            files[name] = file_identity(metadata)
    if authorized_files is not None and files != authorized_files:
        raise InitializationError("Store authorized file identity changed")
    authorized_files = files
    selected = runtime.load_runtime_identity(anchored)
    runtime._require_matching_runtime(selected, mode, inbox_argument, paths)
    paths = dataclasses.replace(paths, inbox=Path(selected.inbox_path))
    anchored = _anchored(paths, root)
    # Bind every existing directory before the first Keychain/database access.
    inbox = _optional_directory(pins, paths.inbox)
    claims = _optional_directory(pins, paths.inbox_claims)
    staging = _optional_directory(pins, paths.inbox_staging)
    if inbox is not None:
        require_distinct_layout(root, inbox, claims, staging)
    for name in (paths.identity.name, paths.database.name, paths.writer_lock.name):
        metadata = file_metadata(root, name)
        if metadata is not None and metadata.st_nlink != 1:
            raise InitializationError("Store runtime file has unexpected hard links")

    def validate_authorized_files() -> None:
        pins.validate()
        for name, expected in files.items():
            current = file_metadata(root, name)
            if current is None or file_identity(current) != expected:
                raise InitializationError("Store authorized file identity changed")

    validate_authorized_files()
    if paths.database.name not in files:
        raise WrongProductError(
            "Store database is missing; no initialization intent owns recovery"
        )
    with _database_directory_authority(
        anchored, root.descriptor, validate_authorized_files, require_private=False
    ):
        selected, key, _database_exists, database_repair = (
            runtime._preflight_initialized_runtime(anchored)
        )
    needs_repair = runtime._runtime_needs_repair(paths)
    pins.validate()
    for name, expected in authorized_files.items():
        current = file_metadata(root, name)
        if current is None or file_identity(current) != expected:
            raise InitializationError("Store authorized file identity changed")
    if not needs_repair and not database_repair:
        return selected
    if not locked:
        with runtime._writer_lock(paths, root_descriptor=root.descriptor):
            return _reopen(
                pins,
                root,
                paths,
                mode,
                inbox_argument,
                locked=True,
                authorized_files=authorized_files,
            )
    inbox, claims, staging = _layout(pins, paths, root, create=True)
    for directory in (root, inbox, claims, staging):
        pins.validate()
        os.fchmod(directory.descriptor, 0o700)
    for name in (paths.identity.name, paths.database.name):
        metadata = file_metadata(root, name)
        if metadata is not None and stat.S_IMODE(metadata.st_mode) != 0o600:
            expected_file = authorized_files.get(name)
            if expected_file is None:
                raise InitializationError("Store authorized file identity changed")
            if name == paths.database.name:
                _repair_database_mode(root, expected_file)
            else:
                descriptor = _open_owned_file(root, name, list(expected_file))
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
    pins.validate()
    if database_repair:
        with _database_directory_authority(
            anchored, root.descriptor, validate_authorized_files
        ):
            connection = open_database(anchored, key, read_only=False)
            connection.close()
    pins.validate()
    return selected


_DATABASE_PERMISSION_REPAIR = """
import os, stat, sys
root, device, inode = (int(value) for value in sys.argv[1:])
fd = os.open("store.sqlite3", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
try:
    opened = os.fstat(fd)
    named = os.stat("store.sqlite3", dir_fd=root, follow_symlinks=False)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (device, inode)
        or (named.st_dev, named.st_ino) != (device, inode)):
        raise SystemExit(2)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
"""


def _repair_database_mode(root: BoundDirectory, expected: tuple[int, int]) -> None:
    # Closing any raw main-database FD would release this process's POSIX locks,
    # including locks held by unrelated live SQLite readers. Use a separate
    # process for the rare chmod repair, passing only directory authority and IDs.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _DATABASE_PERMISSION_REPAIR,
            str(root.descriptor),
            str(expected[0]),
            str(expected[1]),
        ],
        pass_fds=(root.descriptor,),
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise InitializationError(
            "Store database permission repair refused changed authority"
        )
    current = file_metadata(root, "store.sqlite3")
    if current is None or file_identity(current) != expected:
        raise InitializationError("Store database permission repair authority changed")


def _create_file(root: BoundDirectory, name: str, value: bytes) -> os.stat_result:
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=root.descriptor,
    )
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise InitializationError("Store initialization write did not complete")
        offset += written


def _prepare(
    pins: DirectoryPins, root: BoundDirectory, paths: RuntimePaths, mode: RuntimeMode
) -> StoreIdentity:
    from memory import runtime

    inbox, claims, staging = _layout(pins, paths, root, create=True)
    for directory in (root, inbox, claims, staging):
        pins.validate()
        os.fchmod(directory.descriptor, 0o700)
    selected = StoreIdentity(
        product=runtime.PRODUCT,
        schema_lineage=runtime.SCHEMA_LINEAGE,
        schema_version=runtime.SCHEMA_VERSION,
        store_id=secrets.token_hex(16),
        runtime_mode=mode,
        inbox_path=str(paths.inbox),
    )
    key = secrets.token_bytes(32)
    identity_file = _create_file(
        root, STAGED_IDENTITY, _encoded(_identity_payload(selected))
    )
    database_file = _create_file(root, STAGED_DATABASE, b"")
    os.fsync(root.descriptor)
    _init_checkpoint("prepared_files")
    pins.validate()
    record: dict[str, Any] = {
        "format": _FORMAT,
        "identity": _identity_payload(selected),
        "phase": "prepared",
        "root": list(root.identity),
        "inbox": list(inbox.identity),
        "claims": list(claims.identity),
        "staging": list(staging.identity),
        "identity_file": list(file_identity(identity_file)),
        "database_file": list(file_identity(database_file)),
        "key_digest": hashlib.sha256(key).hexdigest(),
    }
    intent_file = _create_file(root, INTENT, _encoded(record))
    os.fsync(root.descriptor)
    _init_checkpoint("intent_durable")
    return _complete(pins, root, paths, selected, record, intent_file, key=key)


def _read_intent(
    root: BoundDirectory,
) -> tuple[dict[str, Any], os.stat_result, int]:
    metadata = file_metadata(root, INTENT)
    if (
        metadata is None
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise InitializationError("Store initialization intent is unsafe")
    encoded = read_file(root, INTENT, limit=65_536)
    lines = encoded.splitlines(keepends=True)
    if lines and not lines[-1].endswith(b"\n"):
        lines.pop()
    if not lines:
        raise InitializationError(
            "Store initialization intent is incomplete; preserve artifacts"
        )
    complete_size = sum(len(line) for line in lines)
    records: list[dict[str, Any]] = []
    try:
        for line in lines:
            value: Any = json.loads(line)
            if not isinstance(value, dict) or _encoded(value) != line:
                raise ValueError
            if (
                set(value)
                != {
                    "format",
                    "identity",
                    "phase",
                    "root",
                    "inbox",
                    "claims",
                    "staging",
                    "identity_file",
                    "database_file",
                    "key_digest",
                }
                or value["format"] != _FORMAT
                or value["phase"] not in {"prepared", "ready"}
            ):
                raise ValueError
            if any(
                not isinstance(value[name], list)
                or len(value[name]) != 2
                or any(type(part) is not int or part < 0 for part in value[name])
                for name in (
                    "root",
                    "inbox",
                    "claims",
                    "staging",
                    "identity_file",
                    "database_file",
                )
            ):
                raise ValueError
            digest = value["key_digest"]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ValueError
            if records:
                previous = records[-1]
                immutable = set(value) - {"phase", "key_digest"}
                if any(previous[name] != value[name] for name in immutable):
                    raise ValueError
                if previous["phase"] == "ready" and value != previous:
                    raise ValueError
            records.append(value)
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise InitializationError(
            "Store initialization intent is invalid; preserve artifacts"
        ) from error
    return records[-1], metadata, complete_size


def _recover(
    pins: DirectoryPins,
    root: BoundDirectory,
    paths: RuntimePaths,
    mode: RuntimeMode,
    inbox_argument: Path | None,
) -> StoreIdentity:
    from memory import runtime

    record, intent_file, complete_size = _read_intent(root)
    if record["root"] != list(root.identity):
        raise InitializationError("Store initialization root identity changed")
    payload = record["identity"]
    # Reuse the exact public identity parser through the owned staged/public file.
    identity_name = (
        STAGED_IDENTITY
        if file_metadata(root, STAGED_IDENTITY) is not None
        else paths.identity.name
    )
    _require_owned_file(root, identity_name, record["identity_file"])
    if read_file(root, identity_name) != _encoded(payload):
        raise InitializationError("Store initialization identity changed")
    selected = runtime._parse_runtime_identity(paths, payload)
    runtime._require_matching_runtime(selected, mode, inbox_argument, paths)
    paths = dataclasses.replace(paths, inbox=Path(selected.inbox_path))
    inbox, claims, staging = _layout(pins, paths, root, create=False)
    for name, directory in (("inbox", inbox), ("claims", claims), ("staging", staging)):
        if record[name] != list(directory.identity):
            raise InitializationError("Store initialization directory identity changed")
    public_names = (paths.database.name, paths.identity.name)
    if record["phase"] == "prepared" and any(
        file_metadata(root, name) is not None for name in public_names
    ):
        raise InitializationError(
            "Store initialization public files lack a durable ready record"
        )
    database_name = (
        STAGED_DATABASE
        if file_metadata(root, STAGED_DATABASE) is not None
        else paths.database.name
    )
    _require_owned_file(root, database_name, record["database_file"])
    if complete_size < intent_file.st_size:
        descriptor = _open_owned_file(
            root, INTENT, list(file_identity(intent_file)), writable=True
        )
        try:
            if os.fstat(descriptor).st_size != intent_file.st_size:
                raise InitializationError(
                    "Store initialization intent changed during recovery"
                )
            os.ftruncate(descriptor, complete_size)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return _complete(pins, root, paths, selected, record, intent_file)


def _require_owned_file(
    root: BoundDirectory, name: str, expected: list[int]
) -> os.stat_result:
    metadata = file_metadata(root, name)
    if (
        metadata is None
        or list(file_identity(metadata)) != expected
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise InitializationError("Store initialization artifact ownership changed")
    return metadata


def _open_owned_file(
    root: BoundDirectory, name: str, expected: list[int], *, writable: bool = False
) -> int:
    descriptor = open_file(root, name, writable=writable)
    metadata = os.fstat(descriptor)
    if list(file_identity(metadata)) != expected or metadata.st_nlink != 1:
        os.close(descriptor)
        raise InitializationError(
            "Store initialization opened artifact ownership changed"
        )
    return descriptor


def _file_reference(descriptor: int) -> Any:
    metadata = os.fstat(descriptor)
    anchor = f"/.vol/{metadata.st_dev}/{metadata.st_ino}"
    reference = Foundation.NSURL.fileURLWithPath_(anchor).fileReferenceURL()
    if reference is None or file_identity(
        os.stat(str(reference.path()))
    ) != file_identity(metadata):
        raise InitializationError("Store initialization file reference changed")
    return reference


def _append_record(
    root: BoundDirectory, record: dict[str, Any], expected: os.stat_result
) -> None:
    _require_owned_file(root, INTENT, list(file_identity(expected)))
    descriptor = _open_owned_file(
        root, INTENT, list(file_identity(expected)), writable=True
    )
    try:
        os.lseek(descriptor, 0, os.SEEK_END)
        _write_all(descriptor, _encoded(record))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _complete(
    pins: DirectoryPins,
    root: BoundDirectory,
    paths: RuntimePaths,
    selected: StoreIdentity,
    record: dict[str, Any],
    intent_file: os.stat_result,
    *,
    key: SecretBytes | None = None,
) -> StoreIdentity:
    from memory.keys import create_master_key, load_master_key

    pins.validate()
    allowed = {
        paths.writer_lock.name,
        paths.inbox_claims.name,
        paths.inbox_staging.name,
        paths.database.name,
        paths.identity.name,
        *ARTIFACTS,
    }
    entries = set(os.listdir(root.descriptor))
    try:
        default_inbox = os.stat("inbox", dir_fd=root.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if (
            stat.S_ISDIR(default_inbox.st_mode)
            and list(file_identity(default_inbox)) == record["inbox"]
        ):
            # A case-insensitive volume preserves the spelling used by mkdir.
            # Permit only its actual single directory entry for the bound Inbox,
            # not arbitrary names whose text merely resembles "inbox".
            names = []
            for name in entries:
                entry = os.stat(name, dir_fd=root.descriptor, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode) and file_identity(
                    entry
                ) == file_identity(default_inbox):
                    names.append(name)
            if len(names) != 1:
                raise InitializationError("Store default Inbox directory entry changed")
            allowed.add(names[0])
    if entries - allowed:
        raise InitializationError(
            "Store initialization has unowned entries; preserve artifacts"
        )
    if record["phase"] == "prepared" and any(
        file_metadata(root, name) is not None
        for name in (paths.database.name, paths.identity.name)
    ):
        raise InitializationError(
            "Store initialization public files lack a durable ready record"
        )
    staged = file_metadata(root, STAGED_DATABASE)
    database_name = STAGED_DATABASE if staged is not None else paths.database.name
    database_file = _require_owned_file(root, database_name, record["database_file"])
    for name, expected in (
        (paths.database.name, record["database_file"]),
        (paths.identity.name, record["identity_file"]),
    ):
        if file_metadata(root, name) is not None:
            _require_owned_file(root, name, expected)
    try:
        loaded = load_master_key(selected)
    except KeyMissingError:
        if (
            record["phase"] != "prepared"
            or database_file.st_size != 0
            or any(
                file_metadata(root, name) is not None
                for name in (paths.database.name, paths.identity.name)
            )
        ):
            raise
        if key is None:
            key = secrets.token_bytes(32)
            record = {**record, "key_digest": hashlib.sha256(key).hexdigest()}
            _append_record(root, record, intent_file)
        pins.validate()
        loaded = create_master_key(selected, material=key)
    if hashlib.sha256(loaded).hexdigest() != record["key_digest"]:
        raise InitializationError("Store initialization key ownership changed")
    _init_checkpoint("key_durable")
    pins.validate()
    if record["phase"] == "prepared":
        _build_database(root, record, selected, loaded)
        pins.validate()
        record = {**record, "phase": "ready"}
        _append_record(root, record, intent_file)
        _init_checkpoint("database_ready")
    pins.validate()
    _publish(root, STAGED_DATABASE, paths.database.name, record["database_file"])
    _init_checkpoint("database_published")
    pins.validate()
    _publish(root, STAGED_IDENTITY, paths.identity.name, record["identity_file"])
    _init_checkpoint("identity_published")
    pins.validate()
    _finish_database(root, paths.database.name, record, selected, loaded)
    pins.validate()
    if any(
        file_metadata(root, name) is not None
        for name in (STAGED_DATABASE, STAGED_IDENTITY)
    ):
        raise InitializationError(
            "Store initialization staged name has a foreign replacement"
        )
    _init_checkpoint("staging_removed")
    pins.validate()
    _remove_intent(root, intent_file)
    _init_checkpoint("intent_removed")
    pins.validate()
    return selected


def _build_database(
    root: BoundDirectory,
    record: dict[str, Any],
    selected: StoreIdentity,
    key: SecretBytes,
) -> None:
    from memory import database

    _require_owned_file(root, STAGED_DATABASE, record["database_file"])
    descriptor = _open_owned_file(
        root, STAGED_DATABASE, record["database_file"], writable=True
    )
    try:
        # No published Store can have this inode in the prepared state. Rebuilding
        # an interrupted stage never removes or replaces a directory entry.
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        connection = cast(
            database.Connection,
            sqlcipher.connect(
                f"/.vol/{os.fstat(descriptor).st_dev}/{os.fstat(descriptor).st_ino}"
            ),
        )
        try:
            database._apply_cipher_settings(connection, key)
            database._configure_initial_writer(connection)
            if connection.execute("PRAGMA journal_mode = MEMORY").fetchone() != (
                "memory",
            ):
                raise StoreOpenError(
                    "Store initialization staging journal is unavailable"
                )
            _init_checkpoint("database_started")
            database._create_schema(connection, selected)
            database._validate_identity(connection, selected)
            _init_checkpoint("schema_created")
            # The same inode-bound connection can persist WAL mode without ever
            # creating a WAL transaction. All schema bytes are already in main.
            database._configure_writer(connection)
            _init_checkpoint("wal_configured")
            database._checkpoint_database(connection)
        finally:
            connection.close()
        _require_owned_file(root, STAGED_DATABASE, record["database_file"])
        os.fsync(descriptor)
        os.fsync(root.descriptor)
    finally:
        os.close(descriptor)


def _publish(
    root: BoundDirectory, staged: str, public: str, expected: list[int]
) -> None:
    if file_metadata(root, public) is not None:
        _require_owned_file(root, public, expected)
        return
    _require_owned_file(root, staged, expected)
    descriptor = _open_owned_file(root, staged, expected)
    try:
        reference = _file_reference(descriptor)
        destination = Foundation.NSURL.fileURLWithPath_(str(root.anchor / public))
        moved, _error = (
            Foundation.NSFileManager.defaultManager().moveItemAtURL_toURL_error_(
                reference, destination, None
            )
        )
        if not moved:
            raise InitializationError(
                "Store initialization publication refused a winner or changed source"
            )
        _require_owned_file(root, public, expected)
        if file_metadata(root, staged) is not None:
            raise InitializationError("Store initialization source name was replaced")
        os.fsync(root.descriptor)
    finally:
        os.close(descriptor)


def _remove_intent(root: BoundDirectory, expected: os.stat_result) -> None:
    _require_owned_file(root, INTENT, list(file_identity(expected)))
    descriptor = _open_owned_file(root, INTENT, list(file_identity(expected)))
    try:
        reference = _file_reference(descriptor)
        removed, _error = (
            Foundation.NSFileManager.defaultManager().removeItemAtURL_error_(
                reference, None
            )
        )
        if not removed:
            raise InitializationError(
                "Store initialization intent cleanup did not complete"
            )
        os.fsync(root.descriptor)
        if file_metadata(root, INTENT) is not None:
            raise InitializationError("Store initialization intent name was replaced")
    finally:
        os.close(descriptor)


def _finish_database(
    root: BoundDirectory,
    name: str,
    record: dict[str, Any],
    selected: StoreIdentity,
    key: SecretBytes,
) -> None:
    from memory import database

    _require_owned_file(root, name, record["database_file"])
    descriptor = _open_owned_file(root, name, record["database_file"])
    try:
        metadata = os.fstat(descriptor)
        anchor = Path(f"/.vol/{metadata.st_dev}/{metadata.st_ino}")
        uri = anchor.as_uri() + "?mode=ro&immutable=1"
        connection = cast(database.Connection, sqlcipher.connect(uri, uri=True))
        try:
            database._apply_cipher_settings(connection, key)
            database._validate_identity(connection, selected)
        finally:
            connection.close()
        _require_owned_file(root, name, record["database_file"])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(root.descriptor)
