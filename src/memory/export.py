"""Owner-present, complete plaintext logical export; no MCP or restore adapter."""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable
from pathlib import Path
from typing import TextIO, cast

import Foundation  # type: ignore[import-untyped]

from memory import __version__
from memory.database import (
    Connection,
    _database_directory_authority,
    _database_runtime_identity,
    _NativeFileIdentity,
    _validate_connection_authority,
    open_database,
)
from memory.errors import InitializationError, InvalidArgumentError
from memory.initialization import _file_reference
from memory.initialization_fs import BoundDirectory, DirectoryPins, identity, open_file
from memory.keys import load_master_key
from memory.model import RuntimePaths
from memory.ui.owner_presence import (
    OwnerPresenceVerifier,
    require_export_owner_presence,
)

EXPORT_FORMAT = "memory.export.v1"
RETAINED_TABLES = (
    "store_meta",
    "source_blobs",
    "inbox_batches",
    "inbox_batch_issues",
    "sources",
    "inbox_batch_sources",
    "memory_lineages",
    "change_sets",
    "change_set_revisions",
    "change_items",
    "change_item_evidence",
    "batch_source_decisions",
    "applications",
    "memory_revisions",
    "memory_evidence",
    "current_memory_heads",
    "approvals",
    "application_memories",
    "memory_guard_links",
    "change_revision_guard_links",
    "change_revision_guard_revocations",
)
OPTIONAL_TABLES = frozenset(
    {
        "memory_guard_links",
        "change_revision_guard_links",
        "change_revision_guard_revocations",
    }
)
SCHEDULER_TABLES = frozenset({"inbox_scan_progress", "inbox_scan_candidates"})
EXCLUSIONS = (
    "rebuildable search projections",
    "transient scan scheduler",
    "uncaptured Inbox files and filesystem recovery/staging state",
    "runtime configuration and encryption keys",
)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _abs(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _absent(directory: BoundDirectory, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise InvalidArgumentError("export destination already exists")


def _require_no_acl(descriptor: int) -> None:
    """Mode bits do not override inherited macOS allow ACLs; require none."""
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_valid.argtypes = [ctypes.c_void_p]
    library.acl_valid.restype = ctypes.c_int
    library.acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    # sys/acl.h: ACL_TYPE_EXTENDED=0x100, ACL_FIRST_ENTRY=0.
    ctypes.set_errno(0)
    acl = library.acl_get_fd_np(descriptor, 0x100)
    if not acl and ctypes.get_errno() == errno.ENOENT:
        # Darwin's descriptor API uses ENOENT for KAUTH_FILESEC_NOACL.
        return
    if not acl:
        raise InvalidArgumentError("export ACL privacy cannot be verified")
    try:
        if library.acl_valid(acl) != 0:
            raise InvalidArgumentError("export ACL is invalid")
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = library.acl_get_entry(acl, 0, ctypes.byref(entry))
        # Darwin returns 0 for an entry, -1/EINVAL at the end of a valid ACL.
        if result != -1 or ctypes.get_errno() != errno.EINVAL:
            raise InvalidArgumentError(
                "export directory and file must have no extended ACL entries"
            )
    finally:
        library.acl_free(acl)


def _owned_file(directory: BoundDirectory, name: str, descriptor: int) -> None:
    current = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
    opened = os.fstat(descriptor)
    if (
        identity(current) != identity(opened)
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) != 0o600
        or current.st_nlink != 1
    ):
        raise InvalidArgumentError("export file authority changed")


def _write_snapshot(
    connection: Connection, stream: TextIO, generation: int
) -> dict[str, int]:
    # table_list distinguishes real tables from virtual and FTS shadow tables.
    present = {
        str(row[1])
        for row in connection.execute("PRAGMA main.table_list")
        if row[2] == "table" and not str(row[1]).startswith("sqlite_")
    }
    unknown = present - set(RETAINED_TABLES) - SCHEDULER_TABLES
    missing = set(RETAINED_TABLES) - OPTIONAL_TABLES - present
    if unknown or missing:
        raise InvalidArgumentError(
            "Store table inventory is not supported for complete export"
        )
    metadata = {
        "format": EXPORT_FORMAT,
        "product_version": __version__,
        "encrypted": False,
        "sensitivity_scope": "all",
        "audit_generation": generation,
        "scope": "all retained records, including drafts, rejected and superseded history",
        "excluded": EXCLUSIONS,
        "encoding": {
            "text": "UTF-8",
            "binary": {"base64": "RFC 4648 padded base64"},
            "_rowid": "original table row coordinate; not a memory identifier",
            "json_columns": "Columns ending in _json retain their original JSON text",
        },
    }
    stream.write(_json(metadata)[:-1] + ',"tables":{')
    counts: dict[str, int] = {}
    for index, table in enumerate(RETAINED_TABLES):
        if index:
            stream.write(",")
        stream.write(_json(table) + ":")
        columns = (
            connection.execute(f'PRAGMA table_info("{table}")').fetchall()
            if table in present
            else []
        )
        count = (
            int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
            if table in present
            else 0
        )
        counts[table] = count
        header = {
            "present": table in present,
            "columns": [
                {
                    "name": row[1],
                    "type": row[2],
                    "not_null": bool(row[3]),
                    "primary_key_position": row[5],
                }
                for row in columns
            ],
            "row_count": count,
        }
        stream.write(_json(header)[:-1] + ',"rows":[')
        if table in present:
            for ordinal, row in enumerate(
                connection.execute(f'SELECT rowid, * FROM "{table}" ORDER BY rowid')
            ):
                if ordinal:
                    stream.write(",")
                record: dict[str, object] = {"_rowid": row[0]}
                for column, value in zip(columns, row[1:], strict=True):
                    record[str(column[1])] = (
                        {"base64": base64.b64encode(value).decode("ascii")}
                        if isinstance(value, bytes)
                        else value
                    )
                if table == "source_blobs":
                    raw = row[
                        1
                        + next(
                            i for i, c in enumerate(columns) if c[1] == "original_bytes"
                        )
                    ]
                    if (
                        not isinstance(raw, bytes)
                        or len(raw) != record["byte_length"]
                        or hashlib.sha256(raw).hexdigest() != record["sha256"]
                    ):
                        raise InvalidArgumentError(
                            "retained source blob integrity failed"
                        )
                stream.write(_json(record))
        stream.write("]}")
    stream.write("}}\n")
    return counts


def _publish(
    connection: Connection,
    directory: BoundDirectory,
    validate: Callable[[], None],
    name: str,
    generation: int,
) -> dict[str, int]:
    temporary = ".memory-export-" + secrets.token_hex(16) + ".tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory.descriptor,
    )
    try:
        reference = _file_reference(descriptor)
    except BaseException:
        # No plaintext has been written. Retain the empty private file if the
        # OS cannot prove a reference for identity-safe cleanup.
        os.close(descriptor)
        raise InvalidArgumentError(
            "export file reference unavailable; empty private temporary retained"
        ) from None
    completed = False
    try:
        validate()
        _owned_file(directory, temporary, descriptor)
        _require_no_acl(descriptor)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            counts = _write_snapshot(connection, stream, generation)
            stream.flush()
            os.fsync(descriptor)
        validate()
        _owned_file(directory, temporary, descriptor)
        _require_no_acl(descriptor)
        _absent(directory, name)
        moved, _error = (
            Foundation.NSFileManager.defaultManager().moveItemAtURL_toURL_error_(
                reference,
                Foundation.NSURL.fileURLWithPath_(str(directory.anchor / name)),
                None,
            )
        )
        if not moved:
            raise InvalidArgumentError(
                "export publication refused a winner or changed source"
            )
        validate()
        _owned_file(directory, name, descriptor)
        _require_no_acl(descriptor)
        os.fsync(directory.descriptor)
        completed = True
        return counts
    finally:
        try:
            if not completed:
                # The file reference follows only our held inode, including a
                # rename during failure; it cannot delete a substituted leaf.
                removed, _error = (
                    Foundation.NSFileManager.defaultManager().removeItemAtURL_error_(
                        reference, None
                    )
                )
                if not removed:
                    raise InvalidArgumentError(
                        "private export cleanup did not complete"
                    )
                os.fsync(directory.descriptor)
        finally:
            os.close(descriptor)


def export_store(
    paths: RuntimePaths, output: Path, *, verifier: OwnerPresenceVerifier | None = None
) -> dict[str, object]:
    """Export all retained data after one fresh OS challenge; never overwrite."""
    output = _abs(output)
    try:
        with DirectoryPins() as pins:
            root = pins.open(paths.root)
            inbox = pins.open(paths.inbox)
            directory = pins.open(output.parent)
            if (
                stat.S_IMODE(directory.metadata.st_mode) != 0o700
                or root.identity in (*directory.ancestors, directory.identity)
                or inbox.identity in (*directory.ancestors, directory.identity)
            ):
                raise InvalidArgumentError(
                    "export requires a private mode-0700 directory outside Store and Inbox"
                )
            _require_no_acl(directory.descriptor)
            _absent(directory, output.name)
            identity_descriptor = open_file(root, "runtime.json")
            try:
                identity_bytes = os.read(identity_descriptor, 16_385)
                if len(identity_bytes) > 16_384:
                    raise InvalidArgumentError("Store identity is oversized")

                def validate_filesystem() -> None:
                    pins.validate()
                    for private in (root, directory):
                        current = os.fstat(private.descriptor)
                        if (
                            current.st_uid != os.geteuid()
                            or stat.S_IMODE(current.st_mode) != 0o700
                        ):
                            raise InvalidArgumentError(
                                "export directory privacy changed"
                            )
                    _require_no_acl(directory.descriptor)
                    _owned_file(root, "runtime.json", identity_descriptor)
                    if os.pread(identity_descriptor, 16_385, 0) != identity_bytes:
                        raise InvalidArgumentError("Store identity bytes changed")

                with _database_directory_authority(
                    paths, root.descriptor, validate_filesystem
                ):
                    return _export_bound(
                        paths,
                        output,
                        root,
                        directory,
                        identity_descriptor,
                        validate_filesystem,
                        verifier,
                    )
            finally:
                os.close(identity_descriptor)
    except (OSError, InitializationError) as error:
        raise InvalidArgumentError(
            "export destination or runtime is unsafe or unavailable"
        ) from error


def _export_bound(
    paths: RuntimePaths,
    output: Path,
    root: BoundDirectory,
    directory: BoundDirectory,
    identity_descriptor: int,
    validate_filesystem: Callable[[], None],
    verifier: OwnerPresenceVerifier | None,
) -> dict[str, object]:
    store_identity = _database_runtime_identity(paths)
    connection = open_database(paths, load_master_key(store_identity), read_only=True)
    try:

        def validate() -> None:
            validate_filesystem()
            _validate_connection_authority(paths, connection)
            if _database_runtime_identity(paths) != store_identity:
                raise InvalidArgumentError("Store identity changed during export")

        connection.execute("BEGIN")
        generation = int(
            connection.execute("SELECT audit_generation FROM store_meta").fetchone()[0]
        )
        binding = hashlib.sha256(
            _json(
                {
                    "store_id": store_identity.store_id,
                    "format": EXPORT_FORMAT,
                    "scope": "all",
                    "audit_generation": generation,
                    "destination": str(output),
                    "directory_identity": directory.identity,
                    "database_identity": cast(
                        _NativeFileIdentity, connection
                    ).file_identity(),
                    "runtime_identity": identity(os.fstat(identity_descriptor)),
                    "root_identity": root.identity,
                }
            ).encode()
        ).hexdigest()
        require_export_owner_presence(
            store_identity.store_id, str(output), binding, verifier=verifier
        )
        validate()
        _absent(directory, output.name)
        counts = _publish(connection, directory, validate, output.name, generation)
    finally:
        connection.close()
    return {"format": EXPORT_FORMAT, "output": str(output), "row_counts": counts}
