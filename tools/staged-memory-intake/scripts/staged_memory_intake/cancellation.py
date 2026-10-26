"""Exact, recoverable withdrawal of an unscanned published promotion.

The unchanged transaction receipt remains evidence. An immutable private intent
binds the current copies before any move; a separate immutable completion marker
fences a crash before active-pointer detachment. Originals are never opened.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from staged_memory_intake.config import resolve_memory_paths
from staged_memory_intake.model import (
    MAX_PROMOTION_CANDIDATES,
    CommandRunner,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    NoPublicationFault,
    PublicationFault,
    TransactionReceipt,
    TransactionState,
    identity_payload,
    parse_identity_payload,
)
from staged_memory_intake.publish import published_name
from staged_memory_intake.securefs import (
    canonical_json_bytes,
    descriptor_identity,
    descriptor_volume,
    directory_identity,
)
from staged_memory_intake.state import TransactionStore

_SCHEMA = "staged-memory-intake.publication-cancellation.v1"
_INTENT_SUFFIX = ".cancellation.json"
_MARKER_SUFFIX = ".cancelled.json"
_TX = re.compile(r"tx_[0-9a-f]{32}")
_HASH = re.compile(r"[0-9a-f]{64}")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_LIMIT = 256 * 1024


def _error(code: str = "cancellation_ambiguous", *, state: bool = False) -> IntakeError:
    return IntakeError(code, "state" if state else "drift")


def _names(descriptor: int) -> set[str]:
    return set(os.listdir(descriptor))


def _stat(descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _directory(path: Path, stack: ExitStack, *, parent: int | None = None) -> int:
    descriptor = os.open(
        path if parent is None else path.name, _DIRECTORY_FLAGS, dir_fd=parent
    )
    stack.callback(os.close, descriptor)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        raise _error("cancellation_authority_changed")
    return descriptor


def _require_directory(descriptor: int, identity: DirectoryIdentity) -> None:
    if descriptor_identity(descriptor) != identity:
        raise _error("cancellation_authority_changed")


def _require_path_directory(path: Path, descriptor: int) -> None:
    metadata = path.lstat()
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
        or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise _error("cancellation_authority_changed")


def _stable(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_file(directory: int, name: str, *, limit: int = _LIMIT) -> bytes:
    # Check the entry before opening, and use NONBLOCK even if it becomes a FIFO.
    observed = _stat(directory, name)
    if observed is None or not stat.S_ISREG(observed.st_mode):
        raise _error()
    descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (
            not _stable(observed, before)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size > limit
        ):
            raise _error()
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = _stat(directory, name)
        if (
            current is None
            or not _stable(before, after)
            or not _stable(after, current)
            or len(raw) != before.st_size
        ):
            raise _error()
        return bytes(raw)
    finally:
        os.close(descriptor)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cancellation key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
        if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
            raise ValueError("invalid cancellation encoding")
    except (ValueError, UnicodeError) as error:
        raise _error("invalid_cancellation", state=True) from error
    return value


def _integer(value: object, *, maximum: int | None = None) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or (maximum is not None and value > maximum)
    ):
        raise _error("invalid_cancellation", state=True)
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise _error("invalid_cancellation", state=True)
    return value


def _identity(value: object) -> DirectoryIdentity:
    try:
        return parse_identity_payload(value)
    except ValueError as error:
        raise _error("invalid_cancellation", state=True) from error


@dataclass(frozen=True, slots=True)
class _File:
    ordinal: int
    name: str
    sha256: str
    byte_length: int
    identity: DirectoryIdentity
    mtime_ns: int

    def payload(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "name": self.name,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "identity": identity_payload(self.identity),
            "mode": 0o600,
            "mtime_ns": self.mtime_ns,
        }


@dataclass(frozen=True, slots=True)
class _Intent:
    transaction_id: str
    manifest_digest: str
    receipt_sha256: str
    state_identity: DirectoryIdentity
    inbox_identity: DirectoryIdentity
    archive_identity: DirectoryIdentity
    files: tuple[_File, ...]

    @property
    def archive_name(self) -> str:
        return f"cancelled-publication-{self.transaction_id}"

    def payload(self) -> dict[str, object]:
        return {
            "schema": _SCHEMA,
            "phase": "pending",
            "transaction_id": self.transaction_id,
            "manifest_digest": self.manifest_digest,
            "receipt_sha256": self.receipt_sha256,
            "state_identity": identity_payload(self.state_identity),
            "inbox_identity": identity_payload(self.inbox_identity),
            "archive_identity": identity_payload(self.archive_identity),
            "archive_name": self.archive_name,
            "files": [entry.payload() for entry in self.files],
        }

    def marker(self) -> dict[str, object]:
        return {
            "schema": _SCHEMA,
            "phase": "cancelled",
            "transaction_id": self.transaction_id,
            "manifest_digest": self.manifest_digest,
            "receipt_sha256": self.receipt_sha256,
            "intent_sha256": hashlib.sha256(
                canonical_json_bytes(self.payload())
            ).hexdigest(),
            "archived_count": len(self.files),
        }


def _parse_intent(raw: bytes, transaction_id: str) -> _Intent:
    value = _json(raw)
    expected = {
        "schema",
        "phase",
        "transaction_id",
        "manifest_digest",
        "receipt_sha256",
        "state_identity",
        "inbox_identity",
        "archive_identity",
        "archive_name",
        "files",
    }
    if (
        set(value) != expected
        or value["schema"] != _SCHEMA
        or value["phase"] != "pending"
        or value["transaction_id"] != transaction_id
    ):
        raise _error("invalid_cancellation", state=True)
    raw_files = value["files"]
    if (
        not isinstance(raw_files, list)
        or not 1 <= len(raw_files) <= MAX_PROMOTION_CANDIDATES
    ):
        raise _error("invalid_cancellation", state=True)
    files: list[_File] = []
    for ordinal, item in enumerate(raw_files):
        if not isinstance(item, dict) or set(item) != {
            "ordinal",
            "name",
            "sha256",
            "byte_length",
            "identity",
            "mode",
            "mtime_ns",
        }:
            raise _error("invalid_cancellation", state=True)
        name = item["name"]
        if (
            item["ordinal"] != ordinal
            or isinstance(item["ordinal"], bool)
            or item["mode"] != 0o600
            or isinstance(item["mode"], bool)
            or not isinstance(name, str)
            or Path(name).name != name
            or name in {"", ".", ".."}
            or "\0" in name
        ):
            raise _error("invalid_cancellation", state=True)
        files.append(
            _File(
                ordinal,
                name,
                _hash(item["sha256"]),
                _integer(item["byte_length"], maximum=_LIMIT),
                _identity(item["identity"]),
                _integer(item["mtime_ns"]),
            )
        )
    result = _Intent(
        transaction_id,
        _hash(value["manifest_digest"]),
        _hash(value["receipt_sha256"]),
        _identity(value["state_identity"]),
        _identity(value["inbox_identity"]),
        _identity(value["archive_identity"]),
        tuple(files),
    )
    if (
        value["archive_name"] != result.archive_name
        or len({item.name for item in files}) != len(files)
        or canonical_json_bytes(result.payload()) != raw
    ):
        raise _error("invalid_cancellation", state=True)
    return result


def _load_intent(directory: int, transaction_id: str) -> _Intent | None:
    name = transaction_id + _INTENT_SUFFIX
    if _stat(directory, name) is None:
        if _stat(directory, transaction_id + _MARKER_SUFFIX) is not None:
            raise _error("invalid_cancellation", state=True)
        return None
    return _parse_intent(_read_file(directory, name), transaction_id)


def _cancelled(directory: int, intent: _Intent) -> bool:
    name = intent.transaction_id + _MARKER_SUFFIX
    if _stat(directory, name) is None:
        return False
    if _json(_read_file(directory, name)) != intent.marker():
        raise _error("invalid_cancellation", state=True)
    return True


def _write_exclusive(
    directory: int,
    name: str,
    payload: Mapping[str, object],
    fault: PublicationFault,
    role: str,
) -> None:
    raw = canonical_json_bytes(payload)
    if _stat(directory, name) is not None:
        if _read_file(directory, name) != raw:
            raise _error("invalid_cancellation", state=True)
        os.fsync(directory)
        return
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        fault.checkpoint(f"{role}_temporary")
        offset = 0
        while offset < len(raw):
            # A torn unpromoted temporary stays private and inert on retry.
            written = os.write(descriptor, raw[offset : offset + max(1, len(raw) // 2)])
            if written <= 0:
                raise _error()
            offset += written
            fault.checkpoint(f"{role}_partial")
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if _read_file(directory, temporary) != raw:
            raise _error("invalid_cancellation", state=True)
        current = _stat(directory, temporary)
        if current is None or not _stable(observed, current):
            raise _error("invalid_cancellation", state=True)
        fault.checkpoint(f"{role}_fsynced")
        try:
            _rename_entries_no_replace(directory, directory, temporary, name)
        except FileExistsError as error:
            if _read_file(directory, name) != raw:
                raise _error("invalid_cancellation", state=True) from error
            os.fsync(directory)
            return
        fault.checkpoint(f"{role}_renamed")
        promoted = _stat(directory, name)
        if (
            promoted is None
            or (promoted.st_dev, promoted.st_ino) != (observed.st_dev, observed.st_ino)
            or _read_file(directory, name) != raw
        ):
            raise _error("invalid_cancellation", state=True)
        os.fsync(directory)
        fault.checkpoint(f"{role}_durable")
    finally:
        os.close(descriptor)


def _eligible(receipt: TransactionReceipt) -> None:
    if (
        receipt.state is not TransactionState.PUBLISHED
        or receipt.scan_started
        or receipt.batch_id is not None
        or receipt.scan_source_ids
        or receipt.scan_issues
        or receipt.scan_has_more is not None
        or receipt.scan_page_has_more is not None
        or receipt.source_bindings
        or receipt.duplicate_notices
        or receipt.change_set_id is not None
        or receipt.revision_id is not None
        or receipt.review_digest is not None
        or receipt.application_id is not None
        or receipt.memory_ids
        or receipt.standing_guard_violations
        or receipt.cleanup_entries
    ):
        raise _error("cancellation_not_allowed", state=True)
    if not 1 <= len(receipt.candidates) <= MAX_PROMOTION_CANDIDATES or len(
        receipt.published_files
    ) != len(receipt.candidates):
        raise _error("cancellation_not_allowed", state=True)
    for ordinal, (candidate, published) in enumerate(
        zip(receipt.candidates, receipt.published_files, strict=True)
    ):
        if (
            candidate.ordinal != ordinal
            or published.ordinal != ordinal
            or published.prepared_name != candidate.prepared_name
            or published.inbox_name != published_name(receipt.transaction_id, candidate)
            or published.sha256 != candidate.prepared_sha256
            or not 1 <= published.byte_length <= _LIMIT
        ):
            raise _error("cancellation_not_allowed", state=True)


def _authority(
    config: IntakeConfig, receipt: TransactionReceipt, runner: CommandRunner
) -> None:
    if (
        receipt.notes_root != str(config.notes_root)
        or receipt.notes_identity != config.notes_identity
        or receipt.memory_home
        != (None if config.memory_home is None else str(config.memory_home))
        or receipt.memory_inbox != str(config.memory_inbox)
        or receipt.inbox_identity != config.inbox_identity
    ):
        raise _error("cancellation_authority_changed")
    _notes_authority(config, receipt)
    paths = resolve_memory_paths(config.memory_home, runner)
    if (
        paths.inbox != config.memory_inbox
        or paths.inbox_identity != receipt.inbox_identity
    ):
        raise _error("cancellation_authority_changed")


def _notes_authority(config: IntakeConfig, receipt: TransactionReceipt) -> None:
    """Bind only the root itself; cancellation never inventories originals."""
    try:
        live = directory_identity(config.notes_root)
    except IntakeError as error:
        if error.code == "volume_unidentified":
            raise
        raise _error("cancellation_authority_changed") from error
    if live != receipt.notes_identity:
        raise _error("cancellation_authority_changed")


def _bind_file(
    directory: int, entry: _File, stack: ExitStack, *, initial: bool = False
) -> int:
    metadata = _stat(directory, entry.name)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        raise _error()
    descriptor = os.open(entry.name, _READ_FLAGS, dir_fd=directory)
    stack.callback(os.close, descriptor)
    _require_file(directory, descriptor, entry, initial=initial)
    return descriptor


def _require_file(
    directory: int, descriptor: int, entry: _File, *, initial: bool = False
) -> None:
    before = os.fstat(descriptor)
    path = _stat(directory, entry.name)
    if (
        path is None
        or not _stable(before, path)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or before.st_size != entry.byte_length
        or (
            not initial
            and (
                DirectoryIdentity(descriptor_volume(descriptor), before.st_ino)
                != entry.identity
                or before.st_mtime_ns != entry.mtime_ns
            )
        )
    ):
        raise _error()
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    length = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        length += len(chunk)
        if length > entry.byte_length:
            raise _error()
    after = os.fstat(descriptor)
    path = _stat(directory, entry.name)
    if (
        path is None
        or not _stable(before, after)
        or not _stable(after, path)
        or length != entry.byte_length
        or digest.hexdigest() != entry.sha256
    ):
        raise _error()


def _locations(inbox: int, archive: int, intent: _Intent) -> tuple[bool, ...]:
    inbox_names, archive_names = _names(inbox), _names(archive)
    expected = {entry.name for entry in intent.files}
    if (
        inbox_names | archive_names != expected
        or inbox_names & archive_names
        or not inbox_names <= expected
        or not archive_names <= expected
    ):
        raise _error()
    return tuple(entry.name in archive_names for entry in intent.files)


def _rename_entries_no_replace(
    source: int, destination: int, source_name: str, destination_name: str
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameatx_np
    except AttributeError as error:  # pragma: no cover - macOS-only companion
        raise OSError(errno.ENOTSUP, "exclusive rename unavailable") from error
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if (
        rename(
            source,
            os.fsencode(source_name),
            destination,
            os.fsencode(destination_name),
            0x00000004,
        )
        != 0
    ):
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code))


_MOVE_REFERENCE_SCRIPT = r"""ObjC.import('Foundation');
function run(argv) {
    if (argv.length !== 5) { throw new Error('invalid arguments'); }
    const manager = $.NSFileManager.defaultManager;
    const reference = $.NSURL.fileURLWithPath($(argv[0])).fileReferenceURL;
    if (!reference || !reference.isFileReferenceURL) {
        throw new Error('reference unavailable');
    }
    const attributes = manager.attributesOfItemAtPathError(reference.path, null);
    if (!attributes ||
        ObjC.unwrap(attributes.objectForKey($.NSFileSystemNumber).stringValue) !== argv[2] ||
        ObjC.unwrap(attributes.objectForKey($.NSFileSystemFileNumber).stringValue) !== argv[3] ||
        ObjC.unwrap(attributes.objectForKey($.NSFilePosixPermissions).stringValue) !== argv[4] ||
        ObjC.unwrap(attributes.objectForKey($.NSFileType)) !== ObjC.unwrap($.NSFileTypeRegular)) {
        throw new Error('identity changed');
    }
    const destination = $.NSURL.fileURLWithPath($(argv[1]));
    if (!manager.moveItemAtURLToURLError(reference, destination, null)) {
        throw new Error('exclusive move refused');
    }
    return '';
}"""


def _move_bound_file(source: int, destination: int, name: str) -> None:
    """Move the descriptor's referent, preserving any replaced visible name.

    macOS inode anchors bind both the source and destination directory, as in
    Memory's initialization publisher. Foundation refuses an existing target.
    """
    file = os.fstat(source)
    parent = os.fstat(destination)
    source_anchor = f"/.vol/{file.st_dev}/{file.st_ino}"
    destination_anchor = f"/.vol/{parent.st_dev}/{parent.st_ino}/{name}"
    result = subprocess.run(
        [
            "/usr/bin/osascript",
            "-l",
            "JavaScript",
            "-e",
            _MOVE_REFERENCE_SCRIPT,
            source_anchor,
            destination_anchor,
            str(file.st_dev),
            str(file.st_ino),
            str(stat.S_IMODE(file.st_mode)),
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0 or result.stderr or result.stdout.strip():
        raise _error()


def _status(
    intent: _Intent, *, cancelled: bool, archived_count: int
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": "staged-memory-intake.status.v1",
        "status": "cancelled" if cancelled else "cancellation_pending",
        "transaction_id": intent.transaction_id,
        "manifest_digest": intent.manifest_digest,
        "published_count": len(intent.files),
        "archived_count": archived_count,
        "scan_started": False,
    }
    if not cancelled:
        result["recovery_command"] = "cancel-publication"
    return result


def cancellation_status(
    store: TransactionStore, transaction_id: str | None = None
) -> dict[str, object] | None:
    """Report only an explicitly selected cancellation or pending recovery."""
    try:
        store.state_root.lstat()
    except FileNotFoundError:
        return None
    with store.lock(), ExitStack() as stack:
        directory = _directory(store.state_root, stack)
        names = sorted(
            name
            for name in _names(directory)
            if name.endswith((_INTENT_SUFFIX, _MARKER_SUFFIX))
        )
        if not names:
            return None
        active = store.active()
        selected: _Intent | None = None
        completed = False
        for name in names:
            suffix = _INTENT_SUFFIX if name.endswith(_INTENT_SUFFIX) else _MARKER_SUFFIX
            identifier = name[: -len(suffix)]
            if _TX.fullmatch(identifier) is None:
                raise _error("invalid_cancellation", state=True)
            intent = _load_intent(directory, identifier)
            if intent is None:
                raise _error("invalid_cancellation", state=True)
            if (
                hashlib.sha256(
                    _read_file(directory, identifier + ".json", limit=16 * 1024 * 1024)
                ).hexdigest()
                != intent.receipt_sha256
            ):
                raise _error("cancellation_receipt_changed")
            marked = _cancelled(directory, intent)
            attached = active is not None and active.transaction_id == identifier
            if transaction_id is not None:
                if identifier != transaction_id:
                    continue
            elif marked and not attached:
                continue
            if selected is not None and selected != intent:
                raise _error("cancellation_pending", state=True)
            selected, completed = intent, marked and not attached
        if selected is None:
            return None
        archived_count = 0
        try:
            archive = _directory(
                store.state_root / selected.archive_name, stack, parent=directory
            )
            _require_directory(archive, selected.archive_identity)
            archived_count = len(
                _names(archive) & {entry.name for entry in selected.files}
            )
        except (OSError, IntakeError) as error:
            # Reporting recovery never certifies archive bytes or invents completion.
            if completed:
                raise _error() from error
        return _status(selected, cancelled=completed, archived_count=archived_count)


def cancel_publication(
    config: IntakeConfig,
    store: TransactionStore,
    transaction_id: str,
    manifest_digest: str,
    runner: CommandRunner,
    fault: PublicationFault | None = None,
) -> dict[str, object]:
    """Withdraw one exact unscanned publication without touching its originals."""
    if (
        _TX.fullmatch(transaction_id) is None
        or _HASH.fullmatch(manifest_digest) is None
    ):
        raise _error("invalid_arguments", state=True)
    checkpoint = fault or NoPublicationFault()
    with store.lock(), ExitStack() as stack:
        state = _directory(store.state_root, stack)
        receipt = store.load(transaction_id)
        _eligible(receipt)
        if not hmac.compare_digest(receipt.manifest_digest, manifest_digest):
            raise _error("wrong_manifest_digest", state=True)
        receipt_raw = _read_file(
            state, transaction_id + ".json", limit=16 * 1024 * 1024
        )
        receipt_hash = hashlib.sha256(receipt_raw).hexdigest()
        intent = _load_intent(state, transaction_id)
        marked = intent is not None and _cancelled(state, intent)
        if marked:
            os.fsync(state)
        active = store.active()
        if not marked and active != receipt:
            raise _error("inactive_transaction", state=True)
        if intent is not None:
            if (
                intent.manifest_digest != manifest_digest
                or intent.receipt_sha256 != receipt_hash
            ):
                raise _error("cancellation_receipt_changed")
            _require_directory(state, intent.state_identity)
            if len(intent.files) != len(receipt.published_files):
                raise _error("cancellation_receipt_changed")
        # A completed replay must not depend on or touch a newer Inbox transaction.
        if marked and active != receipt:
            assert intent is not None
            archive = _directory(
                store.state_root / intent.archive_name, stack, parent=state
            )
            _require_directory(archive, intent.archive_identity)
            _require_path_directory(store.state_root, state)
            _require_path_directory(store.state_root / intent.archive_name, archive)
            if _names(archive) != {entry.name for entry in intent.files}:
                raise _error()
            for entry in intent.files:
                _bind_file(archive, entry, stack)
            return _status(intent, cancelled=True, archived_count=len(intent.files))
        _authority(config, receipt, runner)
        inbox = _directory(config.memory_inbox, stack)
        _require_directory(inbox, receipt.inbox_identity)
        archive_name = f"cancelled-publication-{transaction_id}"
        if intent is None:
            if _names(inbox) != {entry.inbox_name for entry in receipt.published_files}:
                raise _error()
            files: list[_File] = []
            descriptors: list[int] = []
            for published in receipt.published_files:
                provisional = _File(
                    published.ordinal,
                    published.inbox_name,
                    published.sha256,
                    published.byte_length,
                    receipt.inbox_identity,
                    0,
                )
                descriptor = _bind_file(inbox, provisional, stack, initial=True)
                observed = os.fstat(descriptor)
                files.append(
                    _File(
                        provisional.ordinal,
                        provisional.name,
                        provisional.sha256,
                        provisional.byte_length,
                        DirectoryIdentity(
                            descriptor_volume(descriptor), observed.st_ino
                        ),
                        observed.st_mtime_ns,
                    )
                )
                descriptors.append(descriptor)
            try:
                os.mkdir(archive_name, 0o700, dir_fd=state)
                os.fsync(state)
            except FileExistsError:
                pass
            archive = _directory(store.state_root / archive_name, stack, parent=state)
            # Only an empty private archive can be adopted before intent; no copy
            # has moved yet, so interruption in directory preparation is harmless.
            if _names(archive) or descriptor_volume(archive) != descriptor_volume(
                inbox
            ):
                raise _error()
            intent = _Intent(
                transaction_id,
                manifest_digest,
                receipt_hash,
                descriptor_identity(state),
                receipt.inbox_identity,
                descriptor_identity(archive),
                tuple(files),
            )
            for entry, descriptor in zip(intent.files, descriptors, strict=True):
                _require_file(inbox, descriptor, entry)
            if _names(inbox) != {entry.name for entry in intent.files}:
                raise _error()
            _require_path_directory(store.state_root, state)
            _require_path_directory(config.memory_inbox, inbox)
            _require_path_directory(store.state_root / archive_name, archive)
            _write_exclusive(
                state,
                transaction_id + _INTENT_SUFFIX,
                intent.payload(),
                checkpoint,
                "intent",
            )
            checkpoint.checkpoint("cancellation_intent")
        else:
            archive = _directory(store.state_root / archive_name, stack, parent=state)
            _require_directory(archive, intent.archive_identity)
            # A prior process may have died just after intent rename. Prove
            # that its containing directory is durable before moving copies.
            _write_exclusive(
                state,
                transaction_id + _INTENT_SUFFIX,
                intent.payload(),
                checkpoint,
                "intent",
            )
        for entry, published in zip(intent.files, receipt.published_files, strict=True):
            if (entry.ordinal, entry.name, entry.sha256, entry.byte_length) != (
                published.ordinal,
                published.inbox_name,
                published.sha256,
                published.byte_length,
            ):
                raise _error("cancellation_receipt_changed")
        locations = _locations(inbox, archive, intent)
        bound = [
            _bind_file(archive if moved else inbox, entry, stack)
            for entry, moved in zip(intent.files, locations, strict=True)
        ]
        for entry, descriptor, moved in zip(
            intent.files, bound, locations, strict=True
        ):
            if moved:
                continue
            checkpoint.checkpoint(f"before_archive_{entry.ordinal}")
            _notes_authority(config, receipt)
            _require_path_directory(store.state_root, state)
            _require_path_directory(config.memory_inbox, inbox)
            _require_path_directory(store.state_root / archive_name, archive)
            if (
                _load_intent(state, transaction_id) != intent
                or _read_file(state, transaction_id + ".json", limit=16 * 1024 * 1024)
                != receipt_raw
            ):
                raise _error("cancellation_receipt_changed")
            _locations(inbox, archive, intent)
            _require_file(inbox, descriptor, entry)
            try:
                _move_bound_file(descriptor, archive, entry.name)
            except OSError as error:
                raise _error() from error
            checkpoint.checkpoint(f"archive_{entry.ordinal}_renamed")
            _require_file(archive, descriptor, entry)
            os.fsync(archive)
            os.fsync(inbox)
            checkpoint.checkpoint(f"archive_{entry.ordinal}_durable")

        def verify_final() -> None:
            _require_path_directory(store.state_root, state)
            _require_path_directory(config.memory_inbox, inbox)
            _require_path_directory(store.state_root / archive_name, archive)
            _require_directory(archive, intent.archive_identity)
            _authority(config, receipt, runner)
            if not all(_locations(inbox, archive, intent)):
                raise _error()
            for entry, descriptor in zip(intent.files, bound, strict=True):
                _require_file(archive, descriptor, entry)
            if (
                store.active() != receipt
                or _read_file(state, transaction_id + ".json", limit=16 * 1024 * 1024)
                != receipt_raw
                or _load_intent(state, transaction_id) != intent
            ):
                raise _error("cancellation_receipt_changed")

        verify_final()
        os.fsync(archive)
        os.fsync(inbox)
        checkpoint.checkpoint("cancellation_verified")
        verify_final()
        _write_exclusive(
            state,
            transaction_id + _MARKER_SUFFIX,
            intent.marker(),
            checkpoint,
            "marker",
        )
        checkpoint.checkpoint("cancelled_marker")
        verify_final()
        if not _cancelled(state, intent):
            raise _error("invalid_cancellation", state=True)
        store.detach_cancelled_publication(
            receipt, state_descriptor=state, receipt_sha256=receipt_hash
        )
        checkpoint.checkpoint("active_detached")
        return _status(intent, cancelled=True, archived_count=len(intent.files))
