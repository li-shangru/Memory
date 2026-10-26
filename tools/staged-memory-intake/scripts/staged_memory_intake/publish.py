"""Durable exact Inbox publication and transaction-owned recovery."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from staged_memory_intake.config import resolve_memory_paths
from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    CommandRunner,
    CompletedCommand,
    IntakeConfig,
    IntakeError,
    ParsedPrepared,
    PublicationFault,
    PublishedFile,
    ReceiptCandidate,
    ReceiptGuardLink,
    TransactionReceipt,
    TransactionState,
    reraise_volume_unidentified,
)
from staged_memory_intake.names import visible_inbox_name
from staged_memory_intake.prepared import build_preview, parse_prepared
from staged_memory_intake.securefs import (
    descriptor_volume,
    directory_identity,
    inventory,
    read_regular,
)
from staged_memory_intake.state import TransactionStore

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_PREPARED_LIMIT = 256 * 1024
_SOURCE_LIMIT = 64 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_RENAME_EXCL = 0x00000004


@dataclass(frozen=True, slots=True)
class _BoundHiddenFile:
    """One exact hidden regular file retained across exclusive publication."""

    descriptor: int
    device: int
    inode: int
    mode: int
    byte_length: int
    sha256: str
    mtime_ns: int
    ctime_ns: int
    readable: bool


@dataclass(frozen=True, slots=True)
class _SubprocessRunner:
    """Production argument-array runner for public Memory path resolution."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return CompletedCommand(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


_MEMORY_PATHS_RUNNER: CommandRunner = _SubprocessRunner()


def _error(code: str) -> IntakeError:
    return IntakeError(code, "state")


def _drift(code: str) -> IntakeError:
    return IntakeError(code, "drift")


def published_name(transaction_id: str, candidate: ReceiptCandidate) -> str:
    """Return one collision-specific deterministic visible Inbox basename."""
    return visible_inbox_name(
        transaction_id,
        candidate.ordinal,
        candidate.prepared_sha256,
        candidate.prepared_name,
    )


def staged_name(transaction_id: str, candidate: ReceiptCandidate) -> str:
    """Return one content-free transaction-derived hidden Inbox basename."""
    name = (
        f".staged-memory-intake-{transaction_id}-{candidate.ordinal:02d}-"
        f"{candidate.prepared_sha256[:12]}.tmp"
    )
    if len(name.encode("utf-8")) > 255:
        raise _error("staged_name_too_long")
    return name


def _same_candidate(candidate: ReceiptCandidate, parsed: ParsedPrepared) -> bool:
    return (
        candidate.prepared_name == parsed.prepared_name
        and candidate.source_name == parsed.source_name
        and candidate.prepared_sha256 == parsed.prepared_sha256
        and candidate.source_sha256 == parsed.source_sha256
        and candidate.statement_sha256 == parsed.statement_sha256
        and candidate.statement_utf8_bytes == parsed.statement_utf8_bytes
        and candidate.evidence_char_start == parsed.evidence_char_start
        and candidate.evidence_char_end == parsed.evidence_char_end
        and candidate.evidence_sha256 == parsed.evidence_sha256
        and candidate.metadata.kind == parsed.requested_metadata.kind
        and candidate.metadata.occurred_on == parsed.requested_metadata.occurred_on
        and candidate.metadata.valid_from == parsed.requested_metadata.valid_from
        and candidate.metadata.valid_to == parsed.requested_metadata.valid_to
        and candidate.metadata.tags == parsed.requested_metadata.tags
    )


def _validate_authorities(
    config: IntakeConfig,
    receipt: TransactionReceipt,
    memory_paths_runner: CommandRunner,
) -> None:
    expected_home = config.memory_home
    if (
        Path(receipt.notes_root) != config.notes_root
        or receipt.notes_identity != config.notes_identity
        or receipt.memory_home
        != (None if expected_home is None else str(expected_home))
        or Path(receipt.memory_inbox) != config.memory_inbox
        or receipt.inbox_identity != config.inbox_identity
    ):
        raise _drift("publication_authority_changed")
    try:
        current_notes = directory_identity(config.notes_root)
        paths = resolve_memory_paths(config.memory_home, memory_paths_runner)
    except IntakeError as error:
        # Memory's own CLI failing to answer -- a missing binary, a timeout,
        # stderr noise -- says nothing about directory authority; those
        # failures keep their retryable memory-category names instead of
        # being re-coded as terminal drift.
        if error.category == "memory":
            raise
        reraise_volume_unidentified(error)
        raise _drift("publication_authority_changed") from error
    if current_notes != receipt.notes_identity:
        raise _drift("publication_authority_changed")
    if (
        (expected_home is not None and paths.home != expected_home)
        or paths.inbox != config.memory_inbox
        or paths.inbox_identity != receipt.inbox_identity
    ):
        raise _drift("publication_authority_changed")


def _validate_candidate(config: IntakeConfig, candidate: ReceiptCandidate) -> bytes:
    try:
        prepared_bytes = read_regular(
            config.notes_root / NUMBERED_LAYOUT.prepared,
            candidate.prepared_name,
            limit=_PREPARED_LIMIT,
        )
        staged_bytes = read_regular(
            config.notes_root / NUMBERED_LAYOUT.staged,
            candidate.source_name,
            limit=_SOURCE_LIMIT,
        )
        parsed = parse_prepared(
            candidate.prepared_name,
            prepared_bytes,
            staged_bytes,
        )
    except IntakeError as error:
        raise _drift("publication_drift") from error
    if not _same_candidate(candidate, parsed):
        raise _drift("publication_drift")
    return prepared_bytes


def _guard_endpoint_json(
    item_id: str | None,
    lineage_id: str | None,
    item_names: dict[str, str],
) -> dict[str, str]:
    if item_id is not None:
        try:
            return {"prepared_name": item_names[item_id]}
        except KeyError as error:
            raise _error("publication_ambiguous") from error
    if lineage_id is None:
        raise _error("publication_ambiguous")
    return {"lineage_id": lineage_id}


def _guard_raw(
    guard: ReceiptGuardLink,
    item_names: dict[str, str],
) -> str:
    return json.dumps(
        {
            "guard": _guard_endpoint_json(
                guard.guard_item_id,
                guard.guard_lineage_id,
                item_names,
            ),
            "governed": _guard_endpoint_json(
                guard.governed_item_id,
                guard.governed_lineage_id,
                item_names,
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _rebuild_approved_preview(
    config: IntakeConfig,
    receipt: TransactionReceipt,
) -> None:
    item_names = {
        candidate.client_item_id: candidate.prepared_name
        for candidate in receipt.candidates
    }
    if len(item_names) != len(receipt.candidates):
        raise _error("publication_ambiguous")
    try:
        rebuilt = build_preview(
            config,
            [candidate.prepared_name for candidate in receipt.candidates],
            [_guard_raw(guard, item_names) for guard in receipt.guard_links],
        )
    except IntakeError as error:
        raise _drift("publication_drift") from error
    if not hmac.compare_digest(rebuilt.manifest_digest, receipt.manifest_digest):
        raise _drift("publication_drift")
    if tuple(candidate.client_item_id for candidate in rebuilt.candidates) != tuple(
        candidate.client_item_id for candidate in receipt.candidates
    ):
        raise _error("publication_ambiguous")


def _validate_preconditions(
    config: IntakeConfig,
    receipt: TransactionReceipt,
    memory_paths_runner: CommandRunner,
) -> tuple[bytes, ...]:
    _validate_authorities(config, receipt, memory_paths_runner)
    if any(
        candidate.metadata.sensitivity != receipt.batch_sensitivity
        for candidate in receipt.candidates
    ):
        raise _error("publication_ambiguous")
    _rebuild_approved_preview(config, receipt)
    return tuple(
        _validate_candidate(config, candidate) for candidate in receipt.candidates
    )


def _validate_receipt_candidates(
    transaction_id: str,
    candidates: tuple[ReceiptCandidate, ...],
) -> None:
    if tuple(value.ordinal for value in candidates) != tuple(range(len(candidates))):
        raise _error("publication_ambiguous")
    visible_names = tuple(published_name(transaction_id, value) for value in candidates)
    hidden_names = tuple(staged_name("tx_" + ("0" * 32), value) for value in candidates)
    if len(set(visible_names)) != len(visible_names) or len(set(hidden_names)) != len(
        hidden_names
    ):
        raise _error("publication_ambiguous")


def _open_directory(path: Path, *, ambiguous: bool = False) -> int:
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except OSError as error:
        if ambiguous:
            raise _error("publication_ambiguous") from error
        raise _drift("publication_drift") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        if ambiguous:
            raise _error("publication_ambiguous")
        raise _drift("publication_drift")
    return descriptor


def _require_directory_identity(
    descriptor: int,
    receipt: TransactionReceipt,
) -> None:
    # Volume UUID plus inode survives reboots. The recorded cost (v1.7.4
    # review, finding 6): a same-UUID block clone mounted at the expected
    # path passes checks the old boot-assigned device axis refused, so
    # publication recovery could complete into the clone. Accepted: the
    # clone holds the same owner's bytes, every write path re-proves
    # structure before mutating, and no persistable axis distinguishes a
    # faithful clone from its original across a reboot.
    metadata = os.fstat(descriptor)
    if (
        metadata.st_ino != receipt.inbox_identity.inode
        or descriptor_volume(descriptor) != receipt.inbox_identity.volume
    ):
        raise _drift("publication_authority_changed")


def _fsync(descriptor: int, role: str) -> None:
    """Make one file or directory durable; role is a mutation-test seam."""
    del role
    os.fsync(descriptor)


def _write_all(descriptor: int, payload: bytes) -> tuple[str, int]:
    digest = hashlib.sha256()
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + _COPY_CHUNK]
        written = os.write(descriptor, chunk)
        if written <= 0:
            raise _error("publication_write_failed")
        digest.update(chunk[:written])
        offset += written
    return digest.hexdigest(), offset


def _entry_stat(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _descriptor_sha256(descriptor: int) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    length = 0
    while True:
        chunk = os.read(descriptor, _COPY_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
        length += len(chunk)
    return digest.hexdigest(), length


def _same_bound_entry(
    metadata: os.stat_result,
    bound: _BoundHiddenFile,
    *,
    require_original_stability: bool,
) -> bool:
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_dev == bound.device
        and metadata.st_ino == bound.inode
        and metadata.st_mode == bound.mode
        and metadata.st_size == bound.byte_length
        and (
            not require_original_stability
            or (
                metadata.st_mtime_ns == bound.mtime_ns
                and metadata.st_ctime_ns == bound.ctime_ns
            )
        )
    )


def _bound_hidden_file(
    descriptor: int,
    metadata: os.stat_result,
    expected_hash: str,
    expected_length: int,
    *,
    readable: bool,
) -> _BoundHiddenFile:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != expected_length
    ):
        raise _error("publication_ambiguous")
    return _BoundHiddenFile(
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        byte_length=expected_length,
        sha256=expected_hash,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
        readable=readable,
    )


def _close_bound_hidden(bound: _BoundHiddenFile) -> None:
    os.close(bound.descriptor)


def _close_bound_hidden_files(
    bounds: Sequence[_BoundHiddenFile | None],
) -> None:
    failure: OSError | None = None
    for bound in bounds:
        if bound is None:
            continue
        try:
            _close_bound_hidden(bound)
        except OSError as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise failure


def _require_bound_identity(
    inbox_descriptor: int,
    name: str,
    bound: _BoundHiddenFile,
    *,
    require_original_stability: bool,
) -> None:
    descriptor_before = os.fstat(bound.descriptor)
    entry_before = _entry_stat(inbox_descriptor, name)
    descriptor_after = os.fstat(bound.descriptor)
    entry_after = _entry_stat(inbox_descriptor, name)
    if (
        entry_before is None
        or entry_after is None
        or not _same_bound_entry(
            descriptor_before,
            bound,
            require_original_stability=require_original_stability,
        )
        or not _same_bound_entry(
            descriptor_after,
            bound,
            require_original_stability=require_original_stability,
        )
        or not _same_bound_entry(
            entry_before,
            bound,
            require_original_stability=require_original_stability,
        )
        or not _same_bound_entry(
            entry_after,
            bound,
            require_original_stability=require_original_stability,
        )
        or descriptor_before.st_mtime_ns != descriptor_after.st_mtime_ns
        or descriptor_before.st_ctime_ns != descriptor_after.st_ctime_ns
        or entry_before.st_mtime_ns != entry_after.st_mtime_ns
        or entry_before.st_ctime_ns != entry_after.st_ctime_ns
    ):
        raise _error("publication_ambiguous")


def _open_bound_hidden(
    directory: int,
    name: str,
    expected_hash: str,
    expected_length: int,
) -> _BoundHiddenFile:
    observed = _entry_stat(directory, name)
    if (
        observed is None
        or not stat.S_ISREG(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o600
        or observed.st_size != expected_length
    ):
        raise _error("publication_ambiguous")
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
    except OSError as error:
        raise _error("publication_ambiguous") from error
    try:
        descriptor_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or stat.S_IMODE(descriptor_before.st_mode) != 0o600
            or descriptor_before.st_dev != observed.st_dev
            or descriptor_before.st_ino != observed.st_ino
            or descriptor_before.st_mode != observed.st_mode
            or descriptor_before.st_size != expected_length
        ):
            raise _error("publication_ambiguous")
        digest, length = _descriptor_sha256(descriptor)
        descriptor_after = os.fstat(descriptor)
        observed_after = _entry_stat(directory, name)
        if (
            digest != expected_hash
            or length != expected_length
            or observed_after is None
            or descriptor_before.st_dev != descriptor_after.st_dev
            or descriptor_before.st_ino != descriptor_after.st_ino
            or descriptor_before.st_mode != descriptor_after.st_mode
            or descriptor_before.st_size != descriptor_after.st_size
            or descriptor_before.st_mtime_ns != descriptor_after.st_mtime_ns
            or descriptor_before.st_ctime_ns != descriptor_after.st_ctime_ns
            or observed.st_dev != observed_after.st_dev
            or observed.st_ino != observed_after.st_ino
            or observed.st_mode != observed_after.st_mode
            or observed.st_size != observed_after.st_size
            or observed.st_mtime_ns != observed_after.st_mtime_ns
            or observed.st_ctime_ns != observed_after.st_ctime_ns
        ):
            raise _error("publication_ambiguous")
        bound = _bound_hidden_file(
            descriptor,
            descriptor_after,
            expected_hash,
            expected_length,
            readable=True,
        )
        _require_bound_identity(
            directory,
            name,
            bound,
            require_original_stability=True,
        )
        return bound
    except BaseException:
        os.close(descriptor)
        raise


def _require_bound_entry(
    inbox_descriptor: int,
    name: str,
    bound: _BoundHiddenFile,
    *,
    require_original_stability: bool,
) -> None:
    _require_bound_identity(
        inbox_descriptor,
        name,
        bound,
        require_original_stability=require_original_stability,
    )
    if bound.readable:
        descriptor_before = os.fstat(bound.descriptor)
        digest, length = _descriptor_sha256(bound.descriptor)
        descriptor_after = os.fstat(bound.descriptor)
        if (
            not _same_bound_entry(
                descriptor_before,
                bound,
                require_original_stability=require_original_stability,
            )
            or not _same_bound_entry(
                descriptor_after,
                bound,
                require_original_stability=require_original_stability,
            )
            or descriptor_before.st_mtime_ns != descriptor_after.st_mtime_ns
            or descriptor_before.st_ctime_ns != descriptor_after.st_ctime_ns
            or digest != bound.sha256
            or length != bound.byte_length
        ):
            raise _error("publication_ambiguous")
    _require_bound_identity(
        inbox_descriptor,
        name,
        bound,
        require_original_stability=require_original_stability,
    )


def _create_hidden_file(
    inbox_descriptor: int,
    name: str,
    candidate: ReceiptCandidate,
    payload: bytes,
    fault: PublicationFault,
) -> _BoundHiddenFile:
    try:
        descriptor = os.open(
            name,
            _WRITE_FLAGS,
            0o600,
            dir_fd=inbox_descriptor,
        )
    except OSError as error:
        raise _error("publication_ambiguous") from error
    try:
        os.fchmod(descriptor, 0o600)
        copied_hash, copied_length = _write_all(descriptor, payload)
        if copied_hash != candidate.prepared_sha256 or copied_length != len(payload):
            raise _drift("publication_drift")
        _fsync(descriptor, "staged_file")
        metadata = os.fstat(descriptor)
        bound = _bound_hidden_file(
            descriptor,
            metadata,
            candidate.prepared_sha256,
            copied_length,
            readable=False,
        )
        _require_bound_identity(
            inbox_descriptor,
            name,
            bound,
            require_original_stability=True,
        )
        if candidate.ordinal == 0:
            fault.checkpoint("staged_file_0_fsynced")
        _require_bound_identity(
            inbox_descriptor,
            name,
            bound,
            require_original_stability=True,
        )
        _require_bound_entry(
            inbox_descriptor,
            name,
            bound,
            require_original_stability=True,
        )
        return bound
    except BaseException:
        os.close(descriptor)
        raise


def _exact_entry_names(descriptor: int) -> tuple[str, ...]:
    return tuple(
        sorted(name for name in os.listdir(descriptor) if name not in {".", ".."})
    )


def _safe_entry_name(name: str) -> bool:
    path = PurePosixPath(name)
    return "\x00" not in name and path.parts == (name,) and name not in {".", ".."}


def _rename_no_replace(
    source_name: str,
    destination_name: str,
    *,
    directory_descriptor: int,
) -> None:
    """Atomically rename one Inbox entry without replacing its destination."""
    if not _safe_entry_name(source_name) or not _safe_entry_name(destination_name):
        raise OSError(errno.EINVAL, "unsafe publication name")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameatx = library.renameatx_np
    except AttributeError as error:  # pragma: no cover - the workflow is macOS-only
        raise OSError(errno.ENOTSUP, "exclusive rename is unavailable") from error
    renameatx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameatx(
        directory_descriptor,
        os.fsencode(source_name),
        directory_descriptor,
        os.fsencode(destination_name),
        _RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


def _rename_bound_exclusive(
    source_name: str,
    destination_name: str,
    *,
    inbox_descriptor: int,
    source: _BoundHiddenFile,
) -> None:
    """Exclusively publish only while the hidden path denotes the bound file."""
    _require_bound_entry(
        inbox_descriptor,
        source_name,
        source,
        require_original_stability=True,
    )
    try:
        _rename_no_replace(
            source_name,
            destination_name,
            directory_descriptor=inbox_descriptor,
        )
    except OSError as error:
        raise _error("publication_ambiguous") from error
    _require_bound_entry(
        inbox_descriptor,
        destination_name,
        source,
        require_original_stability=False,
    )


def _inventory_publication(
    inbox_descriptor: int,
    transaction_id: str,
    candidates: tuple[ReceiptCandidate, ...],
    payloads: tuple[bytes, ...],
) -> tuple[bool, ...]:
    visible_names = {published_name(transaction_id, value) for value in candidates}
    hidden_names = {staged_name(transaction_id, value) for value in candidates}
    root_entries = set(_exact_entry_names(inbox_descriptor))
    if not root_entries <= visible_names | hidden_names:
        raise _error("publication_ambiguous")
    visible: list[bool] = []
    for candidate, payload in zip(candidates, payloads, strict=True):
        hidden_name = staged_name(transaction_id, candidate)
        visible_name = published_name(transaction_id, candidate)
        has_hidden = hidden_name in root_entries
        has_visible = visible_name in root_entries
        if has_hidden and has_visible:
            raise _error("publication_ambiguous")
        for present_name in (
            hidden_name if has_hidden else None,
            visible_name if has_visible else None,
        ):
            if present_name is None:
                continue
            bound = _open_bound_hidden(
                inbox_descriptor,
                present_name,
                candidate.prepared_sha256,
                len(payload),
            )
            _close_bound_hidden(bound)
        visible.append(has_visible)
    return tuple(visible)


def _open_publication_entries(
    inbox_descriptor: int,
    transaction_id: str,
    candidates: tuple[ReceiptCandidate, ...],
    payloads: tuple[bytes, ...],
) -> tuple[list[bool], list[_BoundHiddenFile | None]]:
    visible_names = {published_name(transaction_id, value) for value in candidates}
    hidden_names = {staged_name(transaction_id, value) for value in candidates}
    root_entries = set(_exact_entry_names(inbox_descriptor))
    if not root_entries <= visible_names | hidden_names:
        raise _error("publication_ambiguous")
    visible: list[bool] = []
    retained: list[_BoundHiddenFile | None] = []
    try:
        for candidate, payload in zip(candidates, payloads, strict=True):
            hidden_name = staged_name(transaction_id, candidate)
            visible_name = published_name(transaction_id, candidate)
            has_hidden = hidden_name in root_entries
            has_visible = visible_name in root_entries
            if has_hidden and has_visible:
                raise _error("publication_ambiguous")
            if has_hidden:
                bound = _open_bound_hidden(
                    inbox_descriptor,
                    hidden_name,
                    candidate.prepared_sha256,
                    len(payload),
                )
                retained.append(bound)
            else:
                retained.append(None)
            if has_visible:
                bound = _open_bound_hidden(
                    inbox_descriptor,
                    visible_name,
                    candidate.prepared_sha256,
                    len(payload),
                )
                _close_bound_hidden(bound)
            visible.append(has_visible)
        return visible, retained
    except BaseException:
        _close_bound_hidden_files(retained)
        raise


def _revalidate_publication_entries(
    inbox_descriptor: int,
    transaction_id: str,
    candidates: tuple[ReceiptCandidate, ...],
    payloads: tuple[bytes, ...],
    visible: Sequence[bool],
    retained: Sequence[_BoundHiddenFile | None],
) -> None:
    expected_names = {
        (
            published_name(transaction_id, candidate)
            if is_visible
            else staged_name(transaction_id, candidate)
        )
        for candidate, is_visible in zip(candidates, visible, strict=True)
    }
    if set(_exact_entry_names(inbox_descriptor)) != expected_names:
        raise _error("publication_ambiguous")
    for candidate, payload, is_visible, bound in zip(
        candidates,
        payloads,
        visible,
        retained,
        strict=True,
    ):
        if is_visible:
            opened = _open_bound_hidden(
                inbox_descriptor,
                published_name(transaction_id, candidate),
                candidate.prepared_sha256,
                len(payload),
            )
            _close_bound_hidden(opened)
            if bound is not None:
                raise _error("publication_ambiguous")
            continue
        if bound is None:
            raise _error("publication_ambiguous")
        _require_bound_entry(
            inbox_descriptor,
            staged_name(transaction_id, candidate),
            bound,
            require_original_stability=True,
        )


def _published_records(
    transaction_id: str,
    candidates: tuple[ReceiptCandidate, ...],
    payloads: tuple[bytes, ...],
) -> tuple[PublishedFile, ...]:
    return tuple(
        PublishedFile(
            ordinal=candidate.ordinal,
            prepared_name=candidate.prepared_name,
            inbox_name=published_name(transaction_id, candidate),
            sha256=candidate.prepared_sha256,
            byte_length=len(payload),
        )
        for candidate, payload in zip(candidates, payloads, strict=True)
    )


def _finish_publication_locked(
    receipt: TransactionReceipt,
    payloads: tuple[bytes, ...],
    store: TransactionStore,
    fault: PublicationFault,
    *,
    initial: bool,
) -> TransactionReceipt:
    inbox_descriptor = _open_directory(Path(receipt.memory_inbox), ambiguous=True)
    retained: list[_BoundHiddenFile | None] = []
    try:
        _require_directory_identity(inbox_descriptor, receipt)
        if initial and _exact_entry_names(inbox_descriptor) != ():
            raise _error("publication_ambiguous")
        visible, retained = _open_publication_entries(
            inbox_descriptor,
            receipt.transaction_id,
            receipt.candidates,
            payloads,
        )
        for candidate, payload, is_visible in zip(
            receipt.candidates,
            payloads,
            visible,
            strict=True,
        ):
            if is_visible:
                continue
            hidden_name = staged_name(receipt.transaction_id, candidate)
            if retained[candidate.ordinal] is None:
                retained[candidate.ordinal] = _create_hidden_file(
                    inbox_descriptor,
                    hidden_name,
                    candidate,
                    payload,
                    fault,
                )
        _fsync(inbox_descriptor, "inbox_staging")
        fault.checkpoint("staging_files_fsynced")

        _revalidate_publication_entries(
            inbox_descriptor,
            receipt.transaction_id,
            receipt.candidates,
            payloads,
            visible,
            retained,
        )
        for candidate, is_visible in zip(
            receipt.candidates,
            visible,
            strict=True,
        ):
            if is_visible:
                continue
            hidden_name = staged_name(receipt.transaction_id, candidate)
            visible_name = published_name(receipt.transaction_id, candidate)
            bound = retained[candidate.ordinal]
            if bound is None:
                raise _error("publication_ambiguous")
            _rename_bound_exclusive(
                hidden_name,
                visible_name,
                inbox_descriptor=inbox_descriptor,
                source=bound,
            )
            if candidate.ordinal == 0:
                fault.checkpoint("visible_file_0_renamed")
            _fsync(inbox_descriptor, "inbox_visible")
            if candidate.ordinal == 0:
                fault.checkpoint("visible_directory_fsynced")

        expected_names = {
            published_name(receipt.transaction_id, value)
            for value in receipt.candidates
        }
        if set(_exact_entry_names(inbox_descriptor)) != expected_names:
            raise _error("publication_ambiguous")
        for candidate, payload in zip(receipt.candidates, payloads, strict=True):
            bound = _open_bound_hidden(
                inbox_descriptor,
                published_name(receipt.transaction_id, candidate),
                candidate.prepared_sha256,
                len(payload),
            )
            _close_bound_hidden(bound)
        current = store.load(receipt.transaction_id)
        if current.state is TransactionState.PUBLISHED:
            return current
        published = store.advance(
            current,
            TransactionState.PUBLISHED,
            published_files=_published_records(
                receipt.transaction_id,
                receipt.candidates,
                payloads,
            ),
        )
        fault.checkpoint("published_receipt")
        return published
    finally:
        try:
            _close_bound_hidden_files(retained)
        finally:
            os.close(inbox_descriptor)


def publish(
    config: IntakeConfig,
    store: TransactionStore,
    transaction_id: str,
    fault: PublicationFault,
    *,
    memory_paths_runner: CommandRunner | None = None,
) -> TransactionReceipt:
    """Publish exactly one approved set into a literally empty Inbox."""
    runner = (
        _MEMORY_PATHS_RUNNER if memory_paths_runner is None else memory_paths_runner
    )
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError as error:
            raise _error("publication_not_authorized") from error
        active = store.active()
        if active != receipt or receipt.state is not TransactionState.OWNER_AUTHORIZED:
            raise _error("publication_not_authorized")
        _validate_receipt_candidates(receipt.transaction_id, receipt.candidates)
        payloads = _validate_preconditions(config, receipt, runner)
        if inventory(config.memory_inbox) != ():
            raise _error("inbox_not_empty")
        publishing = store.advance(receipt, TransactionState.PUBLISHING)
        fault.checkpoint("publishing_receipt")
        return _finish_publication_locked(
            publishing,
            payloads,
            store,
            fault,
            initial=True,
        )


def recover_publication(
    config: IntakeConfig,
    store: TransactionStore,
    transaction_id: str,
    fault: PublicationFault,
    *,
    memory_paths_runner: CommandRunner | None = None,
) -> TransactionReceipt:
    """Complete only the exact receipt-owned publication idempotently."""
    runner = (
        _MEMORY_PATHS_RUNNER if memory_paths_runner is None else memory_paths_runner
    )
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError as error:
            raise _error("publication_not_authorized") from error
        active = store.active()
        if active != receipt or receipt.state not in {
            TransactionState.PUBLISHING,
            TransactionState.PUBLISHED,
        }:
            raise _error("publication_not_authorized")
        _validate_receipt_candidates(receipt.transaction_id, receipt.candidates)
        payloads = _validate_preconditions(config, receipt, runner)
        if receipt.state is TransactionState.PUBLISHED:
            inbox_descriptor = _open_directory(config.memory_inbox, ambiguous=True)
            try:
                _require_directory_identity(inbox_descriptor, receipt)
                visible = _inventory_publication(
                    inbox_descriptor,
                    receipt.transaction_id,
                    receipt.candidates,
                    payloads,
                )
                if not all(visible):
                    raise _error("publication_ambiguous")
                expected = {
                    published_name(receipt.transaction_id, value)
                    for value in receipt.candidates
                }
                if set(_exact_entry_names(inbox_descriptor)) != expected:
                    raise _error("publication_ambiguous")
            finally:
                os.close(inbox_descriptor)
            return receipt
        return _finish_publication_locked(
            receipt,
            payloads,
            store,
            fault,
            initial=False,
        )
