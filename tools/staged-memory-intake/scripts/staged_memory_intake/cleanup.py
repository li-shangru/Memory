"""Verified-only, journaled movement of exact originals to macOS Trash."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Literal, NoReturn, Protocol

from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    MAX_PROMOTION_CANDIDATES,
    CleanupEntry,
    CleanupFailure,
    CleanupOutcome,
    CommandRunner,
    CompletedCommand,
    IntakeConfig,
    IntakeError,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.securefs import directory_identity
from staged_memory_intake.state import TransactionStore

CREATE_FILE_REFERENCE_SCRIPT: Final = r"""ObjC.import('Foundation');
function run(argv) {
    if (argv.length !== 1) { throw new Error('invalid arguments'); }
    const manager = $.NSFileManager.defaultManager;
    const pathURL = $.NSURL.fileURLWithPath($(argv[0]));
    const referenceURL = pathURL.fileReferenceURL;
    if (!referenceURL) { throw new Error('reference unavailable'); }
    const referencePath = ObjC.unwrap(referenceURL.path);
    const attributes = manager.attributesOfItemAtPathError($(referencePath), null);
    if (!attributes) { throw new Error('reference unavailable'); }
    return JSON.stringify({
        device: ObjC.unwrap(
            attributes.objectForKey($.NSFileSystemNumber).stringValue
        ),
        inode: ObjC.unwrap(
            attributes.objectForKey($.NSFileSystemFileNumber).stringValue
        ),
        mode: ObjC.unwrap(
            attributes.objectForKey($.NSFilePosixPermissions).stringValue
        ),
        reference: ObjC.unwrap(referenceURL.absoluteString)
    });
}"""

TRASH_FILE_REFERENCE_SCRIPT: Final = r"""ObjC.import('Foundation');
function run(argv) {
    if (argv.length !== 4) { throw new Error('invalid arguments'); }
    const manager = $.NSFileManager.defaultManager;
    const referenceURL = $.NSURL.URLWithString($(argv[0]));
    if (!referenceURL || !referenceURL.isFileReferenceURL) {
        throw new Error('invalid reference');
    }
    const referencePath = ObjC.unwrap(referenceURL.path);
    const attributes = manager.attributesOfItemAtPathError($(referencePath), null);
    if (!attributes) { throw new Error('reference unavailable'); }
    const observedDevice = ObjC.unwrap(
        attributes.objectForKey($.NSFileSystemNumber).stringValue
    );
    const observedInode = ObjC.unwrap(
        attributes.objectForKey($.NSFileSystemFileNumber).stringValue
    );
    const observedMode = ObjC.unwrap(
        attributes.objectForKey($.NSFilePosixPermissions).stringValue
    );
    if (
        observedDevice !== argv[1] || observedInode !== argv[2] ||
        observedMode !== argv[3]
    ) { throw new Error('identity changed'); }
    const result = manager.trashItemAtURLResultingItemURLError(
        referenceURL, null, null
    );
    if (!result) { throw new Error('trash failed'); }
    return '';
}"""

_PREPARED_LIMIT = 256 * 1024
_SOURCE_LIMIT = 64 * 1024 * 1024
_TRASH_TIMEOUT_SECONDS = 60.0


class Trash(Protocol):
    """Recoverable one-file disposal boundary."""

    def create_reference(self, source: TrashSource) -> TrashReference: ...

    def trash_reference(
        self,
        source: TrashSource,
        reference: TrashReference,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class TrashSource:
    """One exact open source retained across the recoverable handoff."""

    path: Path
    descriptor: int
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, slots=True)
class TrashReference:
    """Opaque reference token passed unchanged between Trash adapter stages."""

    token: object


@dataclass(frozen=True, slots=True)
class _FileReference:
    url: str


@dataclass(frozen=True, slots=True)
class _SubprocessRunner:
    """Production argument-array subprocess adapter."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        result = subprocess.run(
            argv,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return CompletedCommand(
            returncode=result.returncode,
            stdout=result.stdout.encode(),
            stderr=result.stderr.encode(),
        )


_DEFAULT_RUNNER: Final[CommandRunner] = _SubprocessRunner()


@dataclass(frozen=True, slots=True)
class MacOSTrash:
    """Move one exact open file through Foundation's recoverable Trash."""

    runner: CommandRunner = _DEFAULT_RUNNER

    @staticmethod
    def _require_live_source(source: TrashSource) -> None:
        try:
            metadata = os.fstat(source.descriptor)
        except OSError as error:
            raise IntakeError("trash_failed", "trash", retryable=True) from error
        if not stat.S_ISREG(metadata.st_mode) or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
        ) != (source.device, source.inode, source.mode):
            raise IntakeError("trash_failed", "trash", retryable=True)

    def _run(self, argv: Sequence[str]) -> CompletedCommand:
        try:
            result = self.runner.run(argv, timeout_seconds=_TRASH_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as error:
            raise IntakeError("trash_failed", "trash", retryable=True) from error
        if result.returncode != 0 or result.stderr:
            raise IntakeError("trash_failed", "trash", retryable=True)
        return result

    def create_reference(self, source: TrashSource) -> TrashReference:
        """Create and validate one file-reference URL for the open source."""
        self._require_live_source(source)
        result = self._run(
            [
                "/usr/bin/osascript",
                "-l",
                "JavaScript",
                "-e",
                CREATE_FILE_REFERENCE_SCRIPT,
                str(source.path),
            ]
        )
        try:
            payload = json.loads(result.stdout)
            if not isinstance(payload, dict) or set(payload) != {
                "device",
                "inode",
                "mode",
                "reference",
            }:
                raise ValueError
            device = int(payload["device"])
            inode = int(payload["inode"])
            mode = int(payload["mode"])
            reference = payload["reference"]
            if not isinstance(reference, str) or not reference.startswith("file:"):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise IntakeError("trash_failed", "trash", retryable=True) from error
        if (device, inode, mode) != (
            source.device,
            source.inode,
            stat.S_IMODE(source.mode),
        ):
            raise IntakeError("trash_failed", "trash", retryable=True)
        return TrashReference(_FileReference(reference))

    def trash_reference(
        self,
        source: TrashSource,
        reference: TrashReference,
    ) -> None:
        """Move the exact validated file reference to recoverable Trash."""
        if not isinstance(reference.token, _FileReference):
            raise IntakeError("trash_failed", "trash", retryable=True)
        self._require_live_source(source)
        result = self._run(
            [
                "/usr/bin/osascript",
                "-l",
                "JavaScript",
                "-e",
                TRASH_FILE_REFERENCE_SCRIPT,
                reference.token.url,
                str(source.device),
                str(source.inode),
                str(stat.S_IMODE(source.mode)),
            ]
        )
        if result.stdout.strip():
            raise IntakeError("trash_failed", "trash", retryable=True)

    def move(self, source: TrashSource) -> None:
        reference = self.create_reference(source)
        self.trash_reference(source, reference)


@dataclass(frozen=True, slots=True)
class _CleanupTarget:
    """Ephemeral path binding for one body-free journal ordinal."""

    path: Path
    entry: CleanupEntry


@dataclass(slots=True)
class _OpenedTarget:
    """One no-follow descriptor retained from complete-set preflight."""

    target: _CleanupTarget
    descriptor: int
    source: TrashSource
    closed: bool = False

    def close(self) -> None:
        if not self.closed:
            os.close(self.descriptor)
            self.closed = True


def _checkpoint(name: str, ordinal: int) -> None:
    """Deterministic interruption seam; production never interrupts."""
    del name, ordinal


def _state_error(
    code: str,
    *,
    state: TransactionState | None = None,
    ordinal: int | None = None,
) -> IntakeError:
    return IntakeError(code, "state", state=state, ordinal=ordinal)


def _drift_error(code: str, *, ordinal: int | None = None) -> IntakeError:
    return IntakeError(code, "drift", ordinal=ordinal)


def _trash_error(
    code: Literal["trash_failed", "cleanup_ambiguous"],
    *,
    ordinal: int,
) -> IntakeError:
    return IntakeError(
        code,
        "trash",
        retryable=code == "trash_failed",
        ordinal=ordinal,
    )


def _validate_cleanup_authority(
    config: IntakeConfig,
    receipt: TransactionReceipt,
) -> None:
    expected_home = None if config.memory_home is None else str(config.memory_home)
    if (
        Path(receipt.notes_root) != config.notes_root
        or receipt.notes_identity != config.notes_identity
        or receipt.memory_home != expected_home
        or Path(receipt.memory_inbox) != config.memory_inbox
        or receipt.inbox_identity != config.inbox_identity
    ):
        raise _drift_error("cleanup_authority_changed")
    try:
        notes_identity = directory_identity(config.notes_root)
        inbox_identity = directory_identity(config.memory_inbox)
        directory_identity(config.notes_root / NUMBERED_LAYOUT.prepared)
        directory_identity(config.notes_root / NUMBERED_LAYOUT.staged)
    except IntakeError as error:
        raise _drift_error("cleanup_authority_changed") from error
    if (
        notes_identity != receipt.notes_identity
        or inbox_identity != receipt.inbox_identity
    ):
        raise _drift_error("cleanup_authority_changed")


def _require_verified_receipt(receipt: TransactionReceipt) -> None:
    candidate_count = len(receipt.candidates)
    candidate_ordinals = tuple(candidate.ordinal for candidate in receipt.candidates)
    binding_ordinals = tuple(binding.ordinal for binding in receipt.source_bindings)
    published_ordinals = tuple(value.ordinal for value in receipt.published_files)
    if (
        receipt.state
        not in {TransactionState.VERIFIED, TransactionState.CLEANUP_PENDING}
        or candidate_count == 0
        or candidate_count > MAX_PROMOTION_CANDIDATES
        or candidate_ordinals != tuple(range(candidate_count))
        or receipt.application_id is None
        or receipt.batch_id is None
        or receipt.change_set_id is None
        or receipt.revision_id is None
        or receipt.review_digest is None
        or len(receipt.memory_ids) != candidate_count
        or len(set(receipt.memory_ids)) != candidate_count
        or binding_ordinals != tuple(range(candidate_count))
        or len({value.source_id for value in receipt.source_bindings})
        != candidate_count
        or published_ordinals != tuple(range(candidate_count))
    ):
        raise _state_error("cleanup_not_verified", state=receipt.state)
    for candidate, binding, published in zip(
        receipt.candidates,
        receipt.source_bindings,
        receipt.published_files,
        strict=True,
    ):
        if (
            binding.inbox_name != published.inbox_name
            or binding.blob_digest != candidate.prepared_sha256
            or published.prepared_name != candidate.prepared_name
            or published.sha256 != candidate.prepared_sha256
        ):
            raise _state_error("cleanup_not_verified", state=receipt.state)
    staged_hashes: dict[str, str] = {}
    for candidate in receipt.candidates:
        prior = staged_hashes.setdefault(candidate.source_name, candidate.source_sha256)
        if prior != candidate.source_sha256:
            raise _state_error("cleanup_not_verified", state=receipt.state)
    if receipt.state is TransactionState.VERIFIED and receipt.cleanup_entries:
        raise _state_error("invalid_cleanup_journal", state=receipt.state)


def _name_hash(
    receipt: TransactionReceipt,
    role: Literal["prepared", "staged"],
    name: str,
) -> str:
    return hmac.new(
        bytes.fromhex(receipt.manifest_digest),
        f"{role}\0{name}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _target(
    receipt: TransactionReceipt,
    role: Literal["prepared", "staged"],
    name: str,
    content_sha256: str,
) -> _CleanupTarget:
    folder = NUMBERED_LAYOUT.prepared if role == "prepared" else NUMBERED_LAYOUT.staged
    return _CleanupTarget(
        path=Path(receipt.notes_root) / folder / name,
        entry=CleanupEntry(
            role=role,
            name_sha256=_name_hash(receipt, role, name),
            content_sha256=content_sha256,
            intent_recorded=False,
            failure=None,
            outcome=None,
        ),
    )


def _cleanup_targets(receipt: TransactionReceipt) -> tuple[_CleanupTarget, ...]:
    prepared = tuple(
        _target(
            receipt,
            "prepared",
            candidate.prepared_name,
            candidate.prepared_sha256,
        )
        for candidate in receipt.candidates
    )
    staged: list[_CleanupTarget] = []
    seen_sources: set[str] = set()
    for candidate in receipt.candidates:
        if candidate.source_name in seen_sources:
            continue
        seen_sources.add(candidate.source_name)
        staged.append(
            _target(
                receipt,
                "staged",
                candidate.source_name,
                candidate.source_sha256,
            )
        )
    return (*prepared, *staged)


def _validate_journal(
    receipt: TransactionReceipt,
    targets: tuple[_CleanupTarget, ...],
) -> None:
    if receipt.state is TransactionState.VERIFIED:
        return
    if len(receipt.cleanup_entries) != len(targets):
        raise _state_error("invalid_cleanup_journal", state=receipt.state)
    for current, target in zip(receipt.cleanup_entries, targets, strict=True):
        expected = target.entry
        if (
            current.role != expected.role
            or not hmac.compare_digest(current.name_sha256, expected.name_sha256)
            or not hmac.compare_digest(
                current.content_sha256,
                expected.content_sha256,
            )
            or (
                current.failure in {"trash_failed", "cleanup_ambiguous"}
                and not current.intent_recorded
            )
        ):
            raise _state_error("invalid_cleanup_journal", state=receipt.state)


def _hash_descriptor(descriptor: int, *, limit: int) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("unsafe source")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = limit + 1
    observed = 0
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        digest.update(chunk)
        observed += len(chunk)
        remaining -= len(chunk)
    after = os.fstat(descriptor)
    if observed > limit or (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise OSError("unsafe source")
    return digest.hexdigest()


def _open_target(target: _CleanupTarget) -> _OpenedTarget:
    limit = _PREPARED_LIMIT if target.entry.role == "prepared" else _SOURCE_LIMIT
    try:
        parent_descriptor = os.open(
            target.path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            descriptor = os.open(
                target.path.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
    except OSError as error:
        raise IntakeError("unsafe_regular_file", "drift") from error
    try:
        metadata = os.fstat(descriptor)
        observed = _hash_descriptor(descriptor, limit=limit)
        if not hmac.compare_digest(observed, target.entry.content_sha256):
            raise IntakeError("unsafe_regular_file", "drift")
        return _OpenedTarget(
            target=target,
            descriptor=descriptor,
            source=TrashSource(
                path=target.path,
                descriptor=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                mode=metadata.st_mode,
            ),
        )
    except OSError as error:
        os.close(descriptor)
        raise IntakeError("unsafe_regular_file", "drift") from error
    except BaseException:
        os.close(descriptor)
        raise


def _bind_parent_entry(opened: _OpenedTarget) -> None:
    try:
        parent_descriptor = os.open(
            opened.target.path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            metadata = os.stat(
                opened.target.path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        finally:
            os.close(parent_descriptor)
        descriptor_metadata = os.fstat(opened.descriptor)
    except OSError as error:
        raise IntakeError("unsafe_regular_file", "drift") from error
    descriptor_identity = (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
        descriptor_metadata.st_mode,
    )
    if (
        descriptor_identity
        != (
            opened.source.device,
            opened.source.inode,
            opened.source.mode,
        )
        or descriptor_identity != (metadata.st_dev, metadata.st_ino, metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise IntakeError("unsafe_regular_file", "drift")


def _require_exact_retained_bytes(opened: _OpenedTarget) -> None:
    """Re-prove one retained descriptor's stable bytes against authorization."""
    limit = _PREPARED_LIMIT if opened.target.entry.role == "prepared" else _SOURCE_LIMIT
    try:
        observed = _hash_descriptor(opened.descriptor, limit=limit)
    except OSError as error:
        raise IntakeError("unsafe_regular_file", "drift") from error
    if not hmac.compare_digest(observed, opened.target.entry.content_sha256):
        raise IntakeError("unsafe_regular_file", "drift")


def _parent_entry_still_names_source(opened: _OpenedTarget) -> bool:
    """Report whether the original path still names the retained source."""
    try:
        parent_descriptor = os.open(
            opened.target.path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            metadata = os.stat(
                opened.target.path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        finally:
            os.close(parent_descriptor)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise IntakeError("unsafe_regular_file", "drift") from error
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
    ) == (
        opened.source.device,
        opened.source.inode,
        opened.source.mode,
    )


def _path_status(target: _CleanupTarget) -> Literal["exact", "absent", "unsafe"]:
    try:
        opened = _open_target(target)
    except IntakeError:
        try:
            target.path.lstat()
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unsafe"
        return "unsafe"
    opened.close()
    return "exact"


def _replace_entry(
    entries: tuple[CleanupEntry, ...],
    ordinal: int,
    replacement: CleanupEntry,
) -> tuple[CleanupEntry, ...]:
    return (*entries[:ordinal], replacement, *entries[ordinal + 1 :])


def _persist_entries(
    store: TransactionStore,
    receipt: TransactionReceipt,
    entries: tuple[CleanupEntry, ...],
) -> TransactionReceipt:
    return store.advance(
        receipt,
        TransactionState.CLEANUP_PENDING,
        cleanup_entries=entries,
    )


def _record_failure(
    store: TransactionStore,
    receipt: TransactionReceipt,
    ordinal: int,
    failure: CleanupFailure,
) -> NoReturn:
    current = receipt.cleanup_entries[ordinal]
    entries = _replace_entry(
        receipt.cleanup_entries,
        ordinal,
        replace(current, failure=failure),
    )
    _persist_entries(store, receipt, entries)
    if failure == "cleanup_drift":
        raise _drift_error(failure, ordinal=ordinal)
    raise _trash_error(failure, ordinal=ordinal)


def _initial_or_current_entries(
    receipt: TransactionReceipt,
    targets: tuple[_CleanupTarget, ...],
) -> tuple[CleanupEntry, ...]:
    if receipt.state is TransactionState.VERIFIED:
        return tuple(target.entry for target in targets)
    return receipt.cleanup_entries


def _preflight_all(
    store: TransactionStore,
    receipt: TransactionReceipt,
    targets: tuple[_CleanupTarget, ...],
) -> TransactionReceipt:
    entries = _initial_or_current_entries(receipt, targets)
    for ordinal, target in enumerate(targets):
        entry = entries[ordinal]
        if entry.outcome is not None:
            continue
        if entry.failure == "cleanup_ambiguous":
            if receipt.state is TransactionState.VERIFIED:
                raise _state_error("invalid_cleanup_journal", state=receipt.state)
            raise _trash_error(
                "cleanup_ambiguous",
                ordinal=ordinal,
            )
        if _path_status(target) == "exact":
            continue
        failure: CleanupFailure = (
            "cleanup_ambiguous" if entry.intent_recorded else "cleanup_drift"
        )
        if receipt.state is TransactionState.VERIFIED:
            persisted = _persist_entries(store, receipt, entries)
            _record_failure(store, persisted, ordinal, failure)
        _record_failure(store, receipt, ordinal, failure)
    if receipt.state is TransactionState.VERIFIED:
        return _persist_entries(store, receipt, entries)
    return receipt


def _open_all_remaining(
    store: TransactionStore,
    receipt: TransactionReceipt,
    targets: tuple[_CleanupTarget, ...],
) -> tuple[_OpenedTarget | None, ...]:
    opened: list[_OpenedTarget | None] = []
    try:
        for ordinal, target in enumerate(targets):
            entry = receipt.cleanup_entries[ordinal]
            if entry.outcome is not None:
                opened.append(None)
                continue
            try:
                opened.append(_open_target(target))
            except IntakeError, OSError:
                failure: CleanupFailure = (
                    "cleanup_ambiguous" if entry.intent_recorded else "cleanup_drift"
                )
                _record_failure(store, receipt, ordinal, failure)
    except BaseException:
        for value in opened:
            if value is not None:
                value.close()
        raise
    return tuple(opened)


def _record_trash_failure(
    store: TransactionStore,
    receipt: TransactionReceipt,
    target: _CleanupTarget,
    ordinal: int,
) -> NoReturn:
    failure: CleanupFailure = (
        "trash_failed" if _path_status(target) == "exact" else "cleanup_ambiguous"
    )
    _record_failure(store, receipt, ordinal, failure)


def _finish_if_resolved(
    store: TransactionStore,
    receipt: TransactionReceipt,
) -> TransactionReceipt:
    if not all(entry.outcome is not None for entry in receipt.cleanup_entries):
        return receipt
    return store.advance(
        receipt,
        TransactionState.COMPLETE,
        cleanup_entries=receipt.cleanup_entries,
    )


def _require_complete_journal(receipt: TransactionReceipt) -> None:
    if receipt.state is not TransactionState.COMPLETE:
        raise _state_error("cleanup_not_verified", state=receipt.state)
    pending = replace(receipt, state=TransactionState.CLEANUP_PENDING)
    _require_verified_receipt(pending)
    targets = _cleanup_targets(receipt)
    _validate_journal(receipt, targets)
    if not receipt.cleanup_entries or not all(
        entry.outcome is not None for entry in receipt.cleanup_entries
    ):
        raise _state_error("invalid_cleanup_journal", state=receipt.state)


def replay_complete_cleanup(
    store: TransactionStore,
    transaction_id: str,
) -> TransactionReceipt:
    """Validate and replay an exact COMPLETE receipt without config or Trash."""
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError as error:
            raise _state_error("cleanup_not_verified") from error
        _require_complete_journal(receipt)
        return receipt


def cleanup(
    config: IntakeConfig,
    store: TransactionStore,
    transaction_id: str,
    trash: Trash,
) -> TransactionReceipt:
    """Move only a completely verified transaction's unchanged originals."""
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError as error:
            raise _state_error("cleanup_not_verified") from error
        active = store.active()
        if receipt.state is TransactionState.COMPLETE:
            _require_complete_journal(receipt)
            return receipt
        if active != receipt:
            raise _state_error("cleanup_not_verified", state=receipt.state)
        _require_verified_receipt(receipt)
        _validate_cleanup_authority(config, receipt)
        targets = _cleanup_targets(receipt)
        _validate_journal(receipt, targets)
        current = _preflight_all(store, receipt, targets)
        opened = _open_all_remaining(store, current, targets)
        try:
            for ordinal, target in enumerate(targets):
                entry = current.cleanup_entries[ordinal]
                if entry.outcome is not None:
                    continue
                exact_source = opened[ordinal]
                if exact_source is None:
                    raise AssertionError("unresolved target lacks retained descriptor")
                try:
                    _bind_parent_entry(exact_source)
                    _require_exact_retained_bytes(exact_source)
                except IntakeError, OSError:
                    failure: CleanupFailure = (
                        "cleanup_ambiguous"
                        if entry.intent_recorded
                        else "cleanup_drift"
                    )
                    _record_failure(store, current, ordinal, failure)
                _checkpoint("before_move", ordinal)
                try:
                    reference = trash.create_reference(exact_source.source)
                except (IntakeError, OSError, subprocess.SubprocessError) as error:
                    if entry.intent_recorded:
                        _record_trash_failure(store, current, target, ordinal)
                    raise _trash_error("trash_failed", ordinal=ordinal) from error
                try:
                    _require_exact_retained_bytes(exact_source)
                except IntakeError, OSError:
                    failure = (
                        "cleanup_ambiguous"
                        if entry.intent_recorded
                        else "cleanup_drift"
                    )
                    _record_failure(store, current, ordinal, failure)
                if not entry.intent_recorded or entry.failure is not None:
                    entry = replace(entry, intent_recorded=True, failure=None)
                    entries = _replace_entry(current.cleanup_entries, ordinal, entry)
                    current = _persist_entries(store, current, entries)
                _checkpoint("after_intent", ordinal)
                try:
                    _require_exact_retained_bytes(exact_source)
                    trash.trash_reference(exact_source.source, reference)
                except IntakeError, OSError, subprocess.SubprocessError:
                    _record_trash_failure(store, current, target, ordinal)
                _checkpoint("after_move", ordinal)
                try:
                    source_still_named = _parent_entry_still_names_source(exact_source)
                except IntakeError, OSError:
                    _record_failure(store, current, ordinal, "cleanup_ambiguous")
                if source_still_named:
                    _record_failure(store, current, ordinal, "trash_failed")
                moved = replace(
                    current.cleanup_entries[ordinal],
                    failure=None,
                    outcome="moved",
                )
                entries = _replace_entry(current.cleanup_entries, ordinal, moved)
                current = _persist_entries(store, current, entries)

            return _finish_if_resolved(store, current)
        finally:
            for value in opened:
                if value is not None:
                    value.close()


def reconcile_cleanup(
    store: TransactionStore,
    transaction_id: str,
    ordinal: int,
    outcome: CleanupOutcome,
) -> TransactionReceipt:
    """Apply one direct owner decision to one recorded cleanup uncertainty."""
    if outcome not in {"moved", "preserved"}:
        raise _state_error("invalid_cleanup_reconciliation", ordinal=ordinal)
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError as error:
            raise _state_error(
                "invalid_cleanup_reconciliation",
                ordinal=ordinal,
            ) from error
        active = store.active()
        if receipt.state is TransactionState.COMPLETE:
            if ordinal < 0 or ordinal >= len(receipt.cleanup_entries):
                raise _state_error(
                    "invalid_cleanup_reconciliation",
                    state=receipt.state,
                    ordinal=ordinal,
                )
            completed = receipt.cleanup_entries[ordinal]
            if completed.outcome == outcome:
                return receipt
            raise _state_error(
                "cleanup_reconciliation_conflict",
                state=receipt.state,
                ordinal=ordinal,
            )
        if active != receipt or receipt.state is not TransactionState.CLEANUP_PENDING:
            raise _state_error(
                "invalid_cleanup_reconciliation",
                state=receipt.state,
                ordinal=ordinal,
            )
        if ordinal < 0 or ordinal >= len(receipt.cleanup_entries):
            raise _state_error(
                "invalid_cleanup_reconciliation",
                state=receipt.state,
                ordinal=ordinal,
            )
        entry = receipt.cleanup_entries[ordinal]
        if entry.outcome is not None:
            if entry.outcome == outcome:
                return receipt
            raise _state_error(
                "cleanup_reconciliation_conflict",
                state=receipt.state,
                ordinal=ordinal,
            )
        # cleanup_drift means the bytes at the recorded path stopped matching
        # the authorization before any move intent existed: nothing moved, so
        # the only honest owner resolution is `preserved`. Refusing every
        # reconciliation for that state wedged the receipt in CLEANUP_PENDING
        # forever -- the applied memories are already safe in the Store --
        # while `moved` would claim bytes reached the Trash that never did.
        if entry.failure not in {"trash_failed", "cleanup_ambiguous"} and not (
            entry.failure == "cleanup_drift" and outcome == "preserved"
        ):
            raise _state_error(
                "cleanup_reconciliation_not_required",
                state=receipt.state,
                ordinal=ordinal,
            )
        reconciled = replace(entry, outcome=outcome)
        entries = _replace_entry(receipt.cleanup_entries, ordinal, reconciled)
        current = _persist_entries(store, receipt, entries)
        return _finish_if_resolved(store, current)
