"""Settled inbox discovery and atomic source custody."""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from memory.database import (
    Connection,
    _database_directory_authority,
    _database_runtime_identity,
    _writer_transaction,
    open_database,
)
from memory.errors import (
    InvalidArgumentError,
    NoEligibleSourcesError,
    RequestLimitError,
    SourceTooLargeError,
    StaleCursorError,
    StoreBusyError,
    StoreUnavailableError,
)
from memory.keys import load_master_key
from memory.model import (
    INBOX_ISSUE_CODES,
    Authorship,
    CapturedCorrection,
    CaptureRecoveryIssue,
    CustodyKind,
    DuplicateCapture,
    ExactCaptureMetadata,
    InboxBatch,
    Issue,
    Page,
    PrivateStagedEntry,
    RuntimePaths,
    SecretBytes,
    Sensitivity,
    SourceCaptureOrigin,
    StagedInboxEntry,
    StoreIdentity,
)
from memory.runtime import _writer_lock, load_runtime_identity
from memory.sources import (
    MAX_PAGE_SIZE,
    _decode_cursor,
    _encode_cursor,
    media_type_for_name,
    retained_utf8_text,
    searchable_text,
    source_projection_uses_capture_rowid,
)
from memory.staging_provenance import (
    MAX_PUBLICATION_ROLLBACK_SLOT_BYTES,
    PublicationRollbackSlotRecord,
    StagingArtifactIdentity,
    decode_publication_rollback_slot,
    encode_publication_rollback_slot,
    publication_rollback_slot_member_names,
)

SETTLE_SECONDS = 5.0
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_BATCH_BYTES = 256 * 1024 * 1024
MAX_BATCH_FILES = 64
_STREAM_BYTES = 1024 * 1024
_CLAIM_MANIFEST = "manifest.json"
_CLAIM_FILES = "files"
_BATCH_ID = re.compile(r"bat_[0-9a-f]{32}")
_CAPTURE_REQUEST_ID = re.compile(r"cap_[0-9a-f]{32}")
_ENTRY_ID = re.compile(r"ent_[0-9a-f]{32}\.stage")
_EXACT_READY_SUFFIX = ".ready.json"
_EXACT_READY_TEMP = re.compile(r"\.ready-[0-9a-f]{32}\.tmp")
_EXACT_READY_FORMAT = "memory.private-exact-entry.v1"
_EXACT_INTENT_SUFFIX = ".intent.json"
_EXACT_INTENT_TEMP = re.compile(
    r"\.intent-(?:(?P<entry_id>ent_[0-9a-f]{32}\.stage)-)?[0-9a-f]{32}\.tmp"
)
_EXACT_INTENT_FORMAT = "memory.private-exact-intent.v2"
_RECOVERY_PAYLOAD = re.compile(r"\.recovery-([0-9a-f]{32})\.stage")
_RECOVERY_MANIFEST = re.compile(r"\.recovery-([0-9a-f]{32})\.json")
_RECOVERY_TEMP = re.compile(r"\.recovery-([0-9a-f]{32})\.tmp")
_RECOVERY_FORMAT = "memory.private-custody-recovery.v1"
_WITHDRAWAL_DIRECTORY = re.compile(r"\.withdrawal-([0-9a-f]{32})")
_RECOVERY_ISSUE_OPERATION = "inbox.recovery.issues.list"
_WITHDRAWAL_CHILD = "withdrawn"
_ROLLBACK_SLOT_RECORD = re.compile(r"\.rollback-slot-([0-9a-f]{32})\.json")
_MAX_PRIVATE_RECOVERY_ATTEMPTS = 8
_CLAIM_FORMAT = "memory.inbox-claim.v2"
_CREATE_ARTIFACT = re.compile(r"\.create-(bat_[0-9a-f]{32})-[0-9a-f]{16}\.tmp")
_CLEANUP_ARTIFACT = re.compile(r"\.cleanup-(bat_[0-9a-f]{32})-[0-9a-f]{16}\.tmp")
_RENAME_EXCL = 0x00000004
_SCAN_LOCK = ".inbox-scan.lock"
_SCAN_METADATA_ROWS = 64
_SCAN_METADATA_BYTES = 16 * 1024


class Clock(Protocol):
    """Time boundary injected below inbox-domain inputs."""

    def time(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


def _checkpoint(_name: str) -> None:
    """Expose durable filesystem boundaries to crash-injection tests."""


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Production clock with the fixed settle wait."""

    def time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    """Internal scan limits; MCP never exposes these controls."""

    settle_seconds: float = SETTLE_SECONDS
    file_byte_limit: int = MAX_FILE_BYTES
    batch_byte_limit: int = MAX_BATCH_BYTES
    batch_file_limit: int = MAX_BATCH_FILES

    def __post_init__(self) -> None:
        if self.settle_seconds < 0:
            raise ValueError("settle_seconds must be nonnegative")
        if self.file_byte_limit < 1:
            raise ValueError("file_byte_limit must be positive")
        if self.batch_byte_limit < self.file_byte_limit:
            raise ValueError("batch_byte_limit must allow one maximum-size file")
        if not 1 <= self.batch_file_limit <= MAX_BATCH_FILES:
            raise ValueError("batch_file_limit must be between 1 and 64")


@dataclass(frozen=True, slots=True)
class _VisibleCandidate:
    """One discovered inbox entry, before anything has read its bytes.

    Discovery records only what `stat` reports, because that is exactly what
    the settle window is defined over: a file is settled when its size and
    mtime are unchanged across the window. Discovery, settling and the bounded
    digest selection run outside the Store writer lock; custody validates the
    selected identities and content again under that lock.
    """

    name: str
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class _VisibleFile:
    entry_id: str
    name: str
    device: int
    inode: int
    size: int
    modified_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _Capture:
    name: str
    media_type: str
    original_bytes: bytes
    utf8_text: str | None


@dataclass(slots=True)
class _Claim:
    path: Path
    batch_id: str
    custody_kind: CustodyKind
    source_origin: SourceCaptureOrigin
    capture_request_id: str | None
    exact_metadata: ExactCaptureMetadata | None
    sealed_at: int
    authorship: Authorship
    sensitivity: Sensitivity
    entries: list[_VisibleFile]
    issues: Counter[str]
    has_more: bool


@dataclass(frozen=True, slots=True)
class _ClaimArtifact:
    path: Path
    batch_id: str
    phase: str


@dataclass(frozen=True, slots=True)
class _RuntimeRoot:
    paths: RuntimePaths
    root_descriptor: int
    inbox_descriptor: int
    claims_descriptor: int
    staging_descriptor: int
    root_identity: tuple[int, int]
    inbox_identity: tuple[int, int]
    claims_identity: tuple[int, int]
    staging_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class RuntimeDirectoryAuthority:
    """Startup-bound identities for the runtime's filesystem capabilities."""

    root_identity: tuple[int, int]
    inbox_identity: tuple[int, int]
    claims_identity: tuple[int, int]
    staging_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _ExactStageIntent:
    entry_id: str
    display_name: str
    max_bytes: int
    payload_byte_length: int
    phase: str
    payload_device: int | None
    payload_inode: int | None
    metadata: ExactCaptureMetadata


@dataclass(frozen=True, slots=True)
class _PrivateRecoveryReservation:
    recovery_id: str
    kind: Literal[
        "exact_incomplete",
        "ordinary_publication",
        "owner_correction_handoff",
    ]
    payload_name: str
    entry_id: str
    byte_length: int
    sha256: str
    expected_identity: tuple[int, ...]
    capture_request_id: str | None = None
    batch_id: str | None = None


@dataclass(frozen=True, slots=True)
class _PublicationRollbackOutcome:
    state: Literal["quarantined", "replacement_preserved", "uncertain"]
    marker_durable: bool
    barriers_durable: bool


@dataclass(frozen=True, slots=True)
class _RollbackSlot:
    """One authenticated, locked, idle ordinary publication rollback bundle."""

    record: PublicationRollbackSlotRecord
    payload_descriptor: int
    payload_identity: tuple[int, ...]
    manifest_descriptor: int
    manifest_identity: tuple[int, ...]
    withdrawal_descriptor: int
    withdrawal_identity: tuple[int, int]


class _BoundRollbackSlotMembers(dict[str, StagingArtifactIdentity]):
    """Authenticated issue-pass members and the idle leases that prove them."""

    __slots__ = ("artifact_names", "descriptors")

    def __init__(self, artifact_names: tuple[str, ...]) -> None:
        super().__init__()
        self.artifact_names = artifact_names
        self.descriptors: dict[str, int] = {}

    def close(self) -> None:
        for descriptor in self.descriptors.values():
            _close_descriptor_best_effort(descriptor)
        self.descriptors.clear()


@dataclass(slots=True)
class _ExactRecoveryInspection:
    """One preflighted issue snapshot whose idle bundle leases stay retained."""

    runtime: _RuntimeRoot
    identity: StoreIdentity
    directory_authority: RuntimeDirectoryAuthority
    bound_slots: _BoundRollbackSlotMembers
    live_slot_members: set[str]
    issues: tuple[CaptureRecoveryIssue, ...]
    exact_state_inspected: bool = False

    def inspect_exact_state(self) -> None:
        """Snapshot normalized exact state once, before any capture commit."""
        if self.exact_state_inspected:
            raise InvalidArgumentError("exact recovery state was already inspected")
        issues = list(self.issues)
        _append_exact_recovery_state_issues(self.runtime, issues)
        self.issues = tuple(sorted(issues, key=lambda issue: issue.issue_id))
        self.exact_state_inspected = True

    def final_issues(self) -> list[CaptureRecoveryIssue]:
        """Return the complete pre-mutation issue snapshot without I/O."""
        if not self.exact_state_inspected:
            raise InvalidArgumentError("exact recovery state was not inspected")
        return list(self.issues)


@dataclass(frozen=True, slots=True)
class _PreheldPublicationRollback:
    anchor: _PrivateRecoveryReservation
    anchor_descriptor: int
    manifest_descriptor: int
    manifest_identity: tuple[int, ...]
    withdrawal_name: str
    withdrawal_descriptor: int
    withdrawal_identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class _BoundRename:
    source_name: str
    destination_name: str
    source_directory_descriptor: int
    destination_directory_descriptor: int
    source_descriptor: int
    expected_identity: tuple[int, ...]
    expected_sha256: str


_BOUND_RENAME: ContextVar[_BoundRename | None] = ContextVar(
    "memory_bound_rename",
    default=None,
)


class _ExactIncompleteError(InvalidArgumentError):
    """The bound payload is a stable proper prefix left by interrupted writing."""


class _ExactStageLeaseBusy(Exception):
    """A live process still owns the exact staged payload inode."""


class _StagePayloadLeaseUnavailable(InvalidArgumentError):
    """A staged-payload lease failed for a reason other than contention."""


class _DrainedStageSlotUnavailable(Exception):
    """One candidate zero-byte ordinary staging slot cannot be leased."""


def scan_inbox(
    paths: RuntimePaths,
    authorship: Authorship = Authorship.OWNER,
    sensitivity: Sensitivity = Sensitivity.RESTRICTED,
    *,
    clock: Clock | None = None,
    policy: ScanPolicy = ScanPolicy(),
) -> InboxBatch:
    """Seal one settled, nonempty inbox pass into encrypted custody."""
    try:
        return _scan_inbox(
            paths,
            authorship,
            sensitivity,
            clock=clock,
            policy=policy,
        )
    except OSError as error:
        raise StoreUnavailableError("Store inbox filesystem is unavailable") from error


def count_visible_inbox_entries(
    paths: RuntimePaths,
    *,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> int:
    """Count complete regular Inbox entries through pinned directory descriptors."""
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            count = 0
            for name in os.listdir(runtime.inbox_descriptor):
                if name.startswith(".") or not _safe_entry_name(name):
                    continue
                metadata = _stat_entry(runtime.inbox_descriptor, name)
                if metadata is not None and stat.S_ISREG(metadata.st_mode):
                    count += 1
            _verify_runtime_root(runtime)
            return count
    except OSError as error:
        raise StoreUnavailableError("Store inbox filesystem is unavailable") from error


def list_staged_entries(
    paths: RuntimePaths,
    *,
    cursor: str | None,
    limit: int,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> Page[StagedInboxEntry]:
    """List literal visible regular files through a stable opaque traversal."""
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_PAGE_SIZE
    ):
        raise InvalidArgumentError("staged Inbox page limit is invalid")
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            identity = load_runtime_identity(paths)
            after, upper = _staged_cursor_bounds(cursor, store_id=identity.store_id)
            entries: list[StagedInboxEntry] = []
            names = sorted(os.listdir(runtime.inbox_descriptor))
            if upper is None:
                upper = names[-1] if names else ""
            for name in names:
                if name.startswith("."):
                    continue
                if name <= after or name > upper or not _safe_entry_name(name):
                    continue
                metadata = _stat_entry(runtime.inbox_descriptor, name)
                if (
                    metadata is None
                    or stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                ):
                    continue
                entries.append(
                    StagedInboxEntry(
                        display_name=name,
                        byte_length=metadata.st_size,
                        staged_at_ns=metadata.st_mtime_ns,
                    )
                )
                if len(entries) > limit:
                    break
            _verify_runtime_root(runtime)
            has_more = len(entries) > limit
            visible = tuple(entries[:limit])
            next_cursor = (
                _encode_staged_cursor(
                    store_id=identity.store_id,
                    upper=upper,
                    after=visible[-1].display_name,
                )
                if has_more
                else None
            )
            return Page(items=visible, next_cursor=next_cursor, has_more=has_more)
    except OSError as error:
        raise StoreUnavailableError("Store inbox filesystem is unavailable") from error


def stage_inbox_entry(
    paths: RuntimePaths,
    *,
    owner_filename: str,
    chunks: Iterable[bytes],
    max_bytes: int = MAX_FILE_BYTES,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> StagedInboxEntry:
    """Stage and exclusively publish one streamed owner file into the Inbox."""
    _validate_stage_arguments(owner_filename, chunks, max_bytes)
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            entry, descriptor, source_identity = _stage_private_entry_in_runtime(
                runtime,
                display_name=owner_filename,
                chunks=chunks,
                max_bytes=max_bytes,
            )
            try:
                return publish_staged_inbox_entry(
                    paths,
                    entry,
                    directory_authority=directory_authority,
                    _preheld_source=(descriptor, source_identity),
                )
            finally:
                _close_descriptor_best_effort(descriptor)
    except InvalidArgumentError, RequestLimitError, StoreBusyError:
        raise
    except OSError as error:
        raise InvalidArgumentError("Store staging filesystem is unavailable") from error


def stage_private_entry(
    paths: RuntimePaths,
    *,
    display_name: str,
    chunks: Iterable[bytes],
    max_bytes: int,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> PrivateStagedEntry:
    """Stream bytes into one globally reserved private mode-0600 staging entry."""
    _validate_stage_arguments(display_name, chunks, max_bytes)
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            entry, descriptor, _source_identity = _stage_private_entry_in_runtime(
                runtime,
                display_name=display_name,
                chunks=chunks,
                max_bytes=max_bytes,
            )
            _close_descriptor_best_effort(descriptor)
            return entry
    except InvalidArgumentError, RequestLimitError, StoreBusyError:
        raise
    except OSError as error:
        raise InvalidArgumentError("Store staging filesystem is unavailable") from error


def _stage_private_entry_in_runtime(
    runtime: _RuntimeRoot,
    *,
    display_name: str,
    chunks: Iterable[bytes],
    max_bytes: int,
) -> tuple[PrivateStagedEntry, int, tuple[int, ...]]:
    """Return one complete ordinary entry while retaining its inode lease."""
    for _attempt in range(_MAX_PRIVATE_RECOVERY_ATTEMPTS):
        entry_id, descriptor = _reserve_ordinary_stage_slot(runtime)
        try:
            entry = _stream_reserved_private_slot(
                runtime,
                entry_id=entry_id,
                descriptor=descriptor,
                display_name=display_name,
                chunks=chunks,
                max_bytes=max_bytes,
            )
        except _DrainedStageSlotUnavailable:
            continue
        try:
            source_identity = _bound_private_entry_identity(
                runtime,
                entry,
                descriptor,
                verify_digest=False,
            )
        except BaseException:
            _reclaim_bound_ordinary_stage_slot(runtime, entry_id, descriptor)
            _close_descriptor_best_effort(descriptor)
            raise
        return entry, descriptor, source_identity
    raise InvalidArgumentError("Store private staging capacity is unavailable")


def _reserve_ordinary_stage_slot(runtime: _RuntimeRoot) -> tuple[str, int]:
    """Count and exclusively create one ordinary slot under the writer lock.

    The critical section ends as soon as one fresh pathname and descriptor are
    reserved; validation, stream consumption, hashing, fsync, and publication
    all run after the Store writer lock is released.
    """
    with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
        occupied = sum(
            _ENTRY_ID.fullmatch(name) is not None
            for name in os.listdir(runtime.staging_descriptor)
        )
        if occupied >= _MAX_PRIVATE_RECOVERY_ATTEMPTS:
            raise InvalidArgumentError("Store private staging capacity is unavailable")
        return _create_one_fresh_private_slot(
            runtime,
            attempts=_MAX_PRIVATE_RECOVERY_ATTEMPTS - occupied,
        )


def _create_one_fresh_private_slot(
    runtime: _RuntimeRoot,
    *,
    attempts: int,
) -> tuple[str, int]:
    """Exclusively create and lock one fresh ordinary staging identity."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _attempt in range(attempts):
        entry_id = f"ent_{secrets.token_hex(16)}.stage"
        try:
            descriptor = os.open(
                entry_id,
                flags,
                0o600,
                dir_fd=runtime.staging_descriptor,
            )
        except FileExistsError, FileNotFoundError:
            continue
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _close_descriptor_best_effort(descriptor)
            continue
        except BaseException:
            _close_descriptor_best_effort(descriptor)
            raise
        return entry_id, descriptor
    raise InvalidArgumentError("Store private staging capacity is unavailable")


def _stream_reserved_private_slot(
    runtime: _RuntimeRoot,
    *,
    entry_id: str,
    descriptor: int,
    display_name: str,
    chunks: Iterable[bytes],
    max_bytes: int,
) -> PrivateStagedEntry:
    """Validate and consume one reserved slot without holding the writer lock."""
    digest = hashlib.sha256()
    total = 0
    ready_to_return = False
    safe_to_drain = False
    try:
        os.fchmod(descriptor, 0o600)
        initial = os.fstat(descriptor)
        initial_path = _stat_entry(runtime.staging_descriptor, entry_id)
        if (
            initial_path is None
            or _publication_identity(initial) != _publication_identity(initial_path)
            or not stat.S_ISREG(initial.st_mode)
            or initial.st_uid != os.geteuid()
            or initial.st_nlink != 1
            or stat.S_IMODE(initial.st_mode) != 0o600
            or initial.st_size != 0
        ):
            raise _DrainedStageSlotUnavailable
        safe_to_drain = True
        if (
            _stat_entry(
                runtime.staging_descriptor,
                entry_id + _EXACT_INTENT_SUFFIX,
            )
            is not None
            or _stat_entry(
                runtime.staging_descriptor,
                entry_id + _EXACT_READY_SUFFIX,
            )
            is not None
        ):
            raise _DrainedStageSlotUnavailable
        os.ftruncate(descriptor, 0)
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise InvalidArgumentError("staged Inbox chunk is invalid")
            if total + len(chunk) > max_bytes:
                raise RequestLimitError("staged Inbox entry exceeds its byte limit")
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise InvalidArgumentError("staged Inbox write failed")
                view = view[written:]
            digest.update(chunk)
            total += len(chunk)
        if total == 0:
            # A completed slot always holds bytes, which is what lets the
            # recovery pass treat a zero-length slot as proof of an abandoned
            # reservation rather than a guess. Without this an empty upload is
            # indistinguishable from a reservation whose writer died, and the
            # pass would delete it out from under the publication that owns it.
            # An empty file is also evidence of nothing, so refusing costs the
            # owner a capture that could support no memory anyway.
            raise InvalidArgumentError("staged Inbox entry is empty")
        os.fsync(descriptor)
        _checkpoint("staging.file_fsync")
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != total
        ):
            raise InvalidArgumentError("staged Inbox entry is unsafe")
        os.fsync(runtime.staging_descriptor)
        _checkpoint("staging.directory_fsync")
        _verify_runtime_root(runtime)
        ready_to_return = True
        return PrivateStagedEntry(
            entry_id=entry_id,
            display_name=display_name,
            byte_length=total,
            sha256=digest.hexdigest(),
        )
    finally:
        if not ready_to_return:
            if safe_to_drain:
                _drain_descriptor_best_effort(descriptor)
                _reclaim_bound_ordinary_stage_slot(runtime, entry_id, descriptor)
            _close_descriptor_best_effort(descriptor)
        if not ready_to_return:
            try:
                os.fsync(runtime.staging_descriptor)
            except OSError:
                pass


def stage_exact_private_entry(
    paths: RuntimePaths,
    *,
    display_name: str,
    chunks: Iterable[bytes],
    max_bytes: int,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> PrivateStagedEntry:
    """Stage exact bytes and durably bind their recovery metadata."""
    _validate_exact_metadata(metadata)
    _validate_stage_arguments(display_name, chunks, max_bytes)
    exact_chunks, payload_byte_length = _prepare_exact_chunks(
        chunks,
        max_bytes=max_bytes,
        expected_sha256=metadata.payload_sha256,
    )
    _promote_exact_intent_temps(paths, directory_authority)
    _recover_exact_stage_intents(paths, directory_authority)
    _promote_exact_ready_temps(paths, directory_authority)
    _consume_owner_correction_handoffs(paths, directory_authority)
    recovery_issues = _exact_recovery_issues(paths, directory_authority)
    if any(issue.code == "ambiguous_claim" for issue in recovery_issues):
        raise InvalidArgumentError("exact capture reservation is ambiguous")
    if recovery_issues:
        raise InvalidArgumentError("exact capture recovery is quarantined")
    return _stage_exact_entry_unchecked(
        paths,
        display_name=display_name,
        exact_chunks=exact_chunks,
        payload_byte_length=payload_byte_length,
        max_bytes=max_bytes,
        metadata=metadata,
        directory_authority=directory_authority,
    )


def _stage_exact_entry_unchecked(
    paths: RuntimePaths,
    *,
    display_name: str,
    exact_chunks: tuple[bytes, ...],
    payload_byte_length: int,
    max_bytes: int,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None,
) -> PrivateStagedEntry:
    """Reserve, bind, and publish one exact entry without the recovery gate.

    The public path refuses on any recovery issue before reaching here.
    Handoff replay runs *as part of* recovery normalization, so it must stage
    without re-entering the gate that the not-yet-replayed handoff itself
    trips; it stages exactly what the durable pair proves, so the gate's
    protection -- never stage over unexplained custody -- is preserved by
    the replay's own proofs.
    """
    existing = _find_matching_exact_ready(
        paths,
        display_name,
        metadata,
        directory_authority,
    )
    if existing is not None:
        return existing
    intent = _ExactStageIntent(
        entry_id=f"ent_{secrets.token_hex(16)}.stage",
        display_name=display_name,
        max_bytes=max_bytes,
        payload_byte_length=payload_byte_length,
        phase="reserved",
        payload_device=None,
        payload_inode=None,
        metadata=metadata,
    )
    entry: PrivateStagedEntry | None = None
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            descriptor = _reserve_exact_stage_slot(runtime, intent.entry_id)
            try:
                # The inode lease precedes the first visible intent and remains
                # held until both successful publications are durable and the
                # intent is gone. Recovery can therefore distinguish a live
                # publisher from the identical crash residue without borrowing
                # the Store-wide writer lock across payload streaming.
                _write_exact_intent(runtime, intent)
                entry = _stage_exact_bound_payload(
                    runtime,
                    intent,
                    exact_chunks,
                    descriptor=descriptor,
                )
                if entry.sha256 != metadata.payload_sha256:
                    raise InvalidArgumentError(
                        "exact staged payload digest is mismatched"
                    )
                _write_exact_ready(runtime, entry, metadata)
                bound_intent = _load_exact_intent(runtime, intent.entry_id)
                _cleanup_exact_intent(runtime, bound_intent)
                return entry
            finally:
                _close_descriptor_best_effort(descriptor)
    except BaseException:
        published = entry is not None and _published_exact_ready_matches(
            paths, entry, metadata, directory_authority
        )
        if not published:
            _rollback_exact_intent(paths, intent, directory_authority)
        raise


def _prepare_exact_chunks(
    chunks: Iterable[bytes],
    *,
    max_bytes: int,
    expected_sha256: str,
) -> tuple[tuple[bytes, ...], int]:
    """Validate one replayable exact stream before reserving filesystem state."""
    retained: list[bytes] = []
    digest = hashlib.sha256()
    total = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise InvalidArgumentError("staged Inbox chunk is invalid")
        if total + len(chunk) > max_bytes:
            raise RequestLimitError("staged Inbox entry exceeds its byte limit")
        retained.append(chunk)
        digest.update(chunk)
        total += len(chunk)
    if total < 1 or digest.hexdigest() != expected_sha256:
        raise InvalidArgumentError("exact staged payload digest is mismatched")
    return tuple(retained), total


def _reserve_exact_stage_slot(runtime: _RuntimeRoot, entry_id: str) -> int:
    """Create and lease one exact payload identity inside the global bound.

    Exact capture uses the same short writer-lock-held critical section and the
    same global `ent_*.stage` occupancy bound as ordinary staging, so neither
    path can mint reservations that starve the other. The global lock is
    released as soon as the empty inode exists and its per-inode lease is held;
    every payload byte is written outside the global critical section.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
        occupied = sum(
            _ENTRY_ID.fullmatch(name) is not None
            for name in os.listdir(runtime.staging_descriptor)
        )
        if occupied >= _MAX_PRIVATE_RECOVERY_ATTEMPTS:
            raise InvalidArgumentError("Store private staging capacity is unavailable")
        try:
            descriptor = os.open(
                entry_id,
                flags,
                0o600,
                dir_fd=runtime.staging_descriptor,
            )
        except OSError as error:
            raise InvalidArgumentError("exact payload creation failed") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as error:
            _reclaim_bound_ordinary_stage_slot(runtime, entry_id, descriptor)
            _close_descriptor_best_effort(descriptor)
            if isinstance(error, OSError):
                raise InvalidArgumentError("exact payload lease failed") from error
            raise
        return descriptor


def _stage_exact_bound_payload(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
    chunks: tuple[bytes, ...],
    *,
    descriptor: int,
) -> PrivateStagedEntry:
    """Bind and fill an exact inode while the caller retains its lease."""
    try:
        os.fchmod(descriptor, 0o600)
        empty = os.fstat(descriptor)
        if (
            not stat.S_ISREG(empty.st_mode)
            or empty.st_uid != os.geteuid()
            or empty.st_nlink != 1
            or stat.S_IMODE(empty.st_mode) != 0o600
            or empty.st_size != 0
        ):
            raise InvalidArgumentError("exact payload inode is unsafe")
        os.fsync(descriptor)
        _checkpoint("exact.payload_empty_file_fsync")
        os.fsync(runtime.staging_descriptor)
        _checkpoint("exact.payload_empty_directory_fsync")
        bound = _ExactStageIntent(
            entry_id=intent.entry_id,
            display_name=intent.display_name,
            max_bytes=intent.max_bytes,
            payload_byte_length=intent.payload_byte_length,
            phase="payload_bound",
            payload_device=empty.st_dev,
            payload_inode=empty.st_ino,
            metadata=intent.metadata,
        )
        _write_exact_intent(runtime, bound, replace=True)
        for chunk in chunks:
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "exact payload write failed")
                view = view[written:]
        _checkpoint("exact.payload_before_file_fsync")
        os.fsync(descriptor)
        _checkpoint("exact.payload_file_fsync")
        # Preserve the historical checkpoint while ordinary staging stays separate.
        _checkpoint("staging.file_fsync")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (empty.st_dev, empty.st_ino)
            or _publication_identity(after)
            != _publication_identity(
                os.stat(
                    intent.entry_id,
                    dir_fd=runtime.staging_descriptor,
                    follow_symlinks=False,
                )
            )
            or after.st_size != intent.payload_byte_length
            or _descriptor_sha256(descriptor) != intent.metadata.payload_sha256
        ):
            raise InvalidArgumentError("exact payload custody changed")
        os.fsync(runtime.staging_descriptor)
        _checkpoint("exact.payload_directory_fsync")
        _checkpoint("staging.directory_fsync")
        _verify_runtime_root(runtime)
        return PrivateStagedEntry(
            entry_id=intent.entry_id,
            display_name=intent.display_name,
            byte_length=intent.payload_byte_length,
            sha256=intent.metadata.payload_sha256,
        )
    except OSError as error:
        raise InvalidArgumentError("exact payload staging failed") from error


def _published_exact_ready_matches(
    paths: RuntimePaths,
    entry: PrivateStagedEntry,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> bool:
    """Preserve bytes once their exact recovery manifest is visible and valid."""
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            try:
                loaded_entry, loaded_metadata = _load_exact_ready(
                    runtime, entry.entry_id
                )
                return loaded_entry == entry and loaded_metadata == metadata
            except InvalidArgumentError:
                for name in sorted(os.listdir(runtime.staging_descriptor)):
                    if _EXACT_READY_TEMP.fullmatch(name) is None:
                        continue
                    try:
                        loaded_entry, loaded_metadata = _load_exact_ready_temporary(
                            runtime, name
                        )
                    except InvalidArgumentError:
                        continue
                    if loaded_entry == entry and loaded_metadata == metadata:
                        return True
                return False
    except InvalidArgumentError, OSError:
        return False


def _find_matching_exact_ready(
    paths: RuntimePaths,
    display_name: str,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> PrivateStagedEntry | None:
    matches: list[PrivateStagedEntry] = []
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if not name.endswith(_EXACT_READY_SUFFIX):
                    continue
                entry_id = name[: -len(_EXACT_READY_SUFFIX)]
                try:
                    entry, existing = _load_exact_ready(
                        runtime, entry_id, require_file=False
                    )
                except InvalidArgumentError:
                    continue
                if (
                    existing.capture_request_id != metadata.capture_request_id
                    and existing.batch_id != metadata.batch_id
                ):
                    continue
                if existing != metadata or entry.display_name != display_name:
                    raise InvalidArgumentError("exact capture reservation is ambiguous")
                matches.append(entry)
    except OSError as error:
        raise InvalidArgumentError("exact staging filesystem is unavailable") from error
    if len(matches) > 1:
        raise InvalidArgumentError("exact capture reservation is ambiguous")
    return matches[0] if matches else None


def publish_staged_inbox_entry(
    paths: RuntimePaths,
    entry: PrivateStagedEntry,
    *,
    directory_authority: RuntimeDirectoryAuthority | None = None,
    _preheld_source: tuple[int, tuple[int, ...]] | None = None,
) -> StagedInboxEntry:
    """Exclusively publish one validated private entry to its literal name."""
    _validate_private_entry(entry)
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            owns_descriptor = _preheld_source is None
            if _preheld_source is None:
                descriptor, source_identity = _open_bound_private_entry(runtime, entry)
            else:
                descriptor, source_identity = _preheld_source
                if (
                    _bound_private_entry_identity(runtime, entry, descriptor)
                    != source_identity
                ):
                    raise InvalidArgumentError(
                        "private staged entry custody is invalid"
                    )
            renamed = False
            preheld: _PreheldPublicationRollback | None = None
            retain_anchor = False
            try:
                try:
                    preheld = _prepare_publication_rollback(
                        runtime,
                        descriptor,
                        source_identity,
                        entry,
                    )
                except BaseException:
                    _remove_bound_private_before_publication(
                        runtime,
                        descriptor,
                        source_identity,
                        entry,
                    )
                    raise
                try:
                    _rename_bound_no_replace(
                        entry.entry_id,
                        entry.display_name,
                        source_descriptor=runtime.staging_descriptor,
                        destination_descriptor=runtime.inbox_descriptor,
                        bound_descriptor=descriptor,
                        expected_identity=source_identity,
                        expected_sha256=entry.sha256,
                        quarantine_descriptor=preheld.withdrawal_descriptor,
                    )
                    renamed = True
                    _checkpoint("staging.publish_rename")
                    _sync_published_directories(runtime)
                except BaseException as first_error:
                    if not renamed:
                        cleaned = _remove_bound_private_before_publication(
                            runtime,
                            descriptor,
                            source_identity,
                            entry,
                        )
                        retain_anchor = not cleaned
                        raise
                    published = _reconcile_published_entry(
                        runtime,
                        descriptor,
                        source_identity,
                        entry,
                    )
                    if published is None:
                        retain_anchor = True
                        _rollback_exact_published_entry(
                            runtime,
                            descriptor,
                            source_identity,
                            entry,
                            preheld,
                        )
                        raise InvalidArgumentError(
                            "Store Inbox publication reconciliation failed"
                        ) from first_error
                    try:
                        _sync_published_directories(runtime)
                    except BaseException as retry_error:
                        retain_anchor = True
                        rollback = _rollback_exact_published_entry(
                            runtime,
                            descriptor,
                            source_identity,
                            entry,
                            preheld,
                        )
                        if rollback.state not in {
                            "quarantined",
                            "replacement_preserved",
                            "uncertain",
                        }:
                            raise AssertionError(
                                "unknown publication rollback state"
                            ) from retry_error
                        raise InvalidArgumentError(
                            "Store Inbox publication durability failed"
                        ) from retry_error
                    published = _reconcile_published_entry(
                        runtime,
                        descriptor,
                        source_identity,
                        entry,
                    )
                    if published is None:
                        retain_anchor = True
                        _rollback_exact_published_entry(
                            runtime,
                            descriptor,
                            source_identity,
                            entry,
                            preheld,
                        )
                        raise InvalidArgumentError(
                            "Store Inbox publication reconciliation failed"
                        ) from first_error
                    return published
                published = _reconcile_published_entry(
                    runtime,
                    descriptor,
                    source_identity,
                    entry,
                )
                if published is None:
                    retain_anchor = True
                    _rollback_exact_published_entry(
                        runtime,
                        descriptor,
                        source_identity,
                        entry,
                        preheld,
                    )
                    raise InvalidArgumentError(
                        "Store Inbox publication destination is mismatched"
                    )
                return published
            finally:
                try:
                    if preheld is not None:
                        _release_publication_rollback(
                            runtime,
                            preheld,
                            retain_anchor=retain_anchor,
                            renamed=renamed,
                            source_descriptor=descriptor,
                            source_identity=source_identity,
                            entry=entry,
                        )
                finally:
                    _reclaim_bound_ordinary_stage_slot(
                        runtime,
                        entry.entry_id,
                        descriptor,
                    )
                    if owns_descriptor:
                        _close_descriptor_best_effort(descriptor)
    except OSError as error:
        raise InvalidArgumentError("Store Inbox publication failed") from error


def _open_bound_private_entry(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
) -> tuple[int, tuple[int, ...]]:
    flags = os.O_RDWR | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(entry.entry_id, flags, dir_fd=runtime.staging_descriptor)
    keep_open = False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source_identity = _bound_private_entry_identity(runtime, entry, descriptor)
        keep_open = True
        return descriptor, source_identity
    finally:
        if not keep_open:
            _close_descriptor_best_effort(descriptor)


def _bound_private_entry_identity(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    descriptor: int,
    *,
    verify_digest: bool = True,
) -> tuple[int, ...]:
    """Reprove one locked ordinary payload against its private pathname."""
    path_metadata = _verify_private_file(runtime, entry)
    descriptor_metadata = os.fstat(descriptor)
    if _publication_identity(descriptor_metadata) != _publication_identity(
        path_metadata
    ) or (verify_digest and _descriptor_sha256(descriptor) != entry.sha256):
        raise InvalidArgumentError("private staged entry custody is invalid")
    return _publication_identity(descriptor_metadata)


def _reconcile_published_entry(
    runtime: _RuntimeRoot,
    descriptor: int,
    expected_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
) -> StagedInboxEntry | None:
    """Prove that the literal destination is still the retained source inode."""
    try:
        _verify_runtime_root(runtime)
        source_before = os.fstat(descriptor)
        destination_before = _stat_entry(
            runtime.inbox_descriptor,
            entry.display_name,
        )
        digest = _descriptor_sha256(descriptor)
        source_after = os.fstat(descriptor)
        destination_after = _stat_entry(
            runtime.inbox_descriptor,
            entry.display_name,
        )
        if (
            destination_before is None
            or destination_after is None
            or _publication_identity(source_before) != expected_identity
            or _publication_identity(source_after) != expected_identity
            or _publication_identity(destination_before) != expected_identity
            or _publication_identity(destination_after) != expected_identity
            or _publication_stability(source_before)
            != _publication_stability(source_after)
            or _publication_stability(destination_before)
            != _publication_stability(destination_after)
            or digest != entry.sha256
        ):
            return None
        return StagedInboxEntry(
            display_name=entry.display_name,
            byte_length=entry.byte_length,
            staged_at_ns=destination_after.st_mtime_ns,
        )
    except InvalidArgumentError, OSError:
        return None


def _remove_bound_private_before_publication(
    runtime: _RuntimeRoot,
    descriptor: int,
    expected_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
) -> bool:
    """Drain the retained private inode without mutating a raced pathname."""
    try:
        descriptor_before = os.fstat(descriptor)
        digest = _descriptor_sha256(descriptor)
        descriptor_after = os.fstat(descriptor)
        if (
            _publication_identity(descriptor_before) != expected_identity
            or _publication_identity(descriptor_after) != expected_identity
            or _publication_stability(descriptor_before)
            != _publication_stability(descriptor_after)
            or digest != entry.sha256
        ):
            return False
        _checkpoint("staging.prepublication_before_cleanup")
        _checkpoint("staging.prepublication_before_descriptor_drain")
        if not _drain_verified_descriptor(
            descriptor,
            expected_identity,
            entry.sha256,
        ):
            if not _seal_and_drain_failed_private_cleanup(
                descriptor,
                expected_identity,
                entry.sha256,
            ):
                return False
        _reclaim_bound_ordinary_stage_slot(runtime, entry.entry_id, descriptor)
        os.fsync(runtime.staging_descriptor)
        _checkpoint("staging.prepublication_cleanup_directory_fsync")
        return True
    except InvalidArgumentError, OSError:
        return False


def _publication_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
    )


def _publication_stability(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _sync_published_directories(runtime: _RuntimeRoot) -> None:
    """Complete both publication barriers, reporting any real failed barrier."""
    failures: list[BaseException] = []
    barriers = (
        (
            runtime.staging_descriptor,
            "staging.publish_staging_directory_fsync",
        ),
        (
            runtime.inbox_descriptor,
            "staging.publish_inbox_directory_fsync",
        ),
    )
    for descriptor, checkpoint in barriers:
        try:
            os.fsync(descriptor)
            _checkpoint(checkpoint)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise failures[0]
    _checkpoint("staging.publish_directories_fsync")
    _verify_runtime_root(runtime)


def _prepare_publication_rollback(
    runtime: _RuntimeRoot,
    source_descriptor: int,
    source_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
) -> _PreheldPublicationRollback:
    """Hold authenticated private byte custody and a withdrawal capability."""
    slot = _acquire_authenticated_rollback_slot(runtime)
    if slot is None:
        raise InvalidArgumentError("publication rollback anchor is unavailable")
    try:
        if not _copy_bound_source_to_anchor(
            runtime,
            source_descriptor,
            source_identity,
            entry,
            slot.payload_descriptor,
            slot.record.payload.name,
        ):
            _drain_descriptor_best_effort(slot.payload_descriptor)
            raise InvalidArgumentError("publication rollback anchor is unavailable")
        metadata = os.fstat(slot.payload_descriptor)
        reservation = _PrivateRecoveryReservation(
            recovery_id=slot.record.slot_id,
            kind="ordinary_publication",
            payload_name=slot.record.payload.name,
            entry_id=entry.entry_id,
            byte_length=entry.byte_length,
            sha256=entry.sha256,
            expected_identity=_publication_identity(metadata),
        )
        os.fsync(runtime.staging_descriptor)
        _checkpoint("staging.publication_anchor_directory_fsync")
        _verify_runtime_root(runtime)
    except BaseException:
        _close_descriptor_best_effort(slot.payload_descriptor)
        _close_descriptor_best_effort(slot.manifest_descriptor)
        _close_descriptor_best_effort(slot.withdrawal_descriptor)
        raise
    return _PreheldPublicationRollback(
        anchor=reservation,
        anchor_descriptor=slot.payload_descriptor,
        manifest_descriptor=slot.manifest_descriptor,
        manifest_identity=slot.manifest_identity,
        withdrawal_name=slot.record.withdrawal.name,
        withdrawal_descriptor=slot.withdrawal_descriptor,
        withdrawal_identity=slot.withdrawal_identity,
    )


def _acquire_authenticated_rollback_slot(
    runtime: _RuntimeRoot,
) -> _RollbackSlot | None:
    """Lease one proven idle rollback bundle, minting a fresh one when needed.

    Reusable candidates are discovered only through valid authenticated slot
    records. An occupant whose name and shape merely look reusable is never
    opened for reuse, truncated, renamed, relocated, unlinked, or chmodded.

    Legacy v1 records are retired before anything else: they bound members to
    a boot-assigned device number, so they can never be reused, and leaving
    them counted against the slot budget is how a reboot used to burn one
    budget entry per publication until every publication was refused.
    """
    identity = load_runtime_identity(runtime.paths)
    master_key = load_master_key(identity)
    records = _authenticated_slot_records(
        runtime,
        store_id=identity.store_id,
        master_key=master_key,
    )
    reusable = {
        slot_id: record
        for slot_id, record in records.items()
        if record.format_version == 2
    }
    legacy = {
        slot_id: record
        for slot_id, record in records.items()
        if record.format_version != 2
    }
    reclaimed = sum(
        _retire_legacy_rollback_slot(runtime, legacy[slot_id])
        for slot_id in sorted(legacy)
    )
    for slot_id in sorted(reusable):
        slot = _open_verified_rollback_slot(runtime, reusable[slot_id])
        if slot is not None:
            return slot
    retired = sum(
        _retire_retained_rollback_slot(runtime, reusable[slot_id])
        for slot_id in sorted(reusable)
    )
    remaining = max(
        0,
        _MAX_PRIVATE_RECOVERY_ATTEMPTS - len(records) + reclaimed + retired,
    )
    for _attempt in range(remaining):
        record = _create_fresh_rollback_slot(
            runtime,
            store_id=identity.store_id,
            master_key=master_key,
        )
        if record is None:
            continue
        slot = _open_verified_rollback_slot(runtime, record)
        if slot is not None:
            return slot
    return None


def _retire_retained_rollback_slot(
    runtime: _RuntimeRoot,
    record: PublicationRollbackSlotRecord,
) -> bool:
    """Reclaim the reuse capability of one bundle retained for owner recovery.

    A bundle whose anchor payload must stay readable can never return to the
    idle state, so it would otherwise occupy its slot budget forever and
    eventually refuse every publication. Only the authenticated slot record is
    removed, and only after proving that no live holder has the bundle locked
    and that its durable recovery manifest already binds the retained payload
    on its own. The retained bytes, the manifest, and the withdrawal directory
    all stay in place and remain visible as owner recovery issues.
    """
    payload_descriptor = _open_locked_retained_slot_file(runtime, record.payload)
    if payload_descriptor is None:
        return False
    manifest_descriptor: int | None = None
    try:
        manifest_descriptor = _open_locked_retained_slot_file(runtime, record.manifest)
        if manifest_descriptor is None:
            return False
        try:
            reservation = _load_private_recovery_manifest(runtime, record.manifest.name)
        except InvalidArgumentError:
            return False
        if (
            reservation.recovery_id != record.slot_id
            or reservation.payload_name != record.payload.name
            or not _verified_private_recovery_payload(runtime, reservation)
        ):
            return False
        return _unlink_authenticated_slot_record(runtime, record.slot_id)
    finally:
        for descriptor in (payload_descriptor, manifest_descriptor):
            if descriptor is not None:
                _close_descriptor_best_effort(descriptor)


def _retire_legacy_rollback_slot(
    runtime: _RuntimeRoot,
    record: PublicationRollbackSlotRecord,
) -> bool:
    """Retire one pre-v2 slot record so a reboot stops burning the budget.

    A v1 record bound each member to a boot-assigned device number, so it can
    never be reused. An idle bundle is removed member by member under
    continuously held exclusive locks with the record unlinked last, so a
    crash mid-retire leaves an authenticated record whose remaining members
    are re-proven -- absent members tolerated -- and the retire simply runs
    again. A bundle retaining real recovery bytes keeps every member and
    retires through the durable-manifest path instead, staying visible as
    owner recovery debt.
    """
    reclaimed = _reclaim_idle_legacy_bundle(runtime, record)
    if reclaimed is not None:
        return reclaimed
    return _retire_retained_rollback_slot(runtime, record)


def _reclaim_idle_legacy_bundle(
    runtime: _RuntimeRoot,
    record: PublicationRollbackSlotRecord,
) -> bool | None:
    """Remove one provably idle legacy bundle and its record, record last.

    Returns None when a present member cannot be proven idle here, so the
    retained-bundle path judges the bundle instead, and False when a removal
    step failed after the proof, leaving a later acquisition to retry the
    remainder.
    """
    held: list[tuple[StagingArtifactIdentity, int, tuple[int, ...] | None]] = []
    try:
        for member in (record.payload, record.manifest, record.withdrawal):
            if _stat_entry(runtime.staging_descriptor, member.name) is None:
                continue
            if member.file_type == "regular":
                opened = _open_locked_idle_slot_file(runtime, member)
                if opened is None:
                    return None
                held.append((member, opened[0], opened[1]))
            else:
                opened_directory = _open_locked_empty_withdrawal(runtime, member)
                if opened_directory is None:
                    return None
                held.append((member, opened_directory[0], None))
        for member, descriptor, identity in held:
            if identity is not None:
                if not _unlink_bound_staging_entry(
                    runtime,
                    member.name,
                    descriptor,
                    identity,
                ):
                    return False
            elif not _remove_bound_empty_directory(runtime, member.name, descriptor):
                return False
    finally:
        for _member, descriptor, _identity in held:
            _close_descriptor_best_effort(descriptor)
    return _unlink_authenticated_slot_record(runtime, record.slot_id)


def _unlink_authenticated_slot_record(
    runtime: _RuntimeRoot,
    slot_id: str,
) -> bool:
    """Remove one slot record only while its exact inode is held open."""
    name = f".rollback-slot-{slot_id}.json"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=runtime.staging_descriptor)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        return _unlink_bound_staging_entry(
            runtime,
            name,
            descriptor,
            _publication_identity(metadata),
        )
    except OSError:
        return False
    finally:
        _close_descriptor_best_effort(descriptor)


def _remove_bound_empty_directory(
    runtime: _RuntimeRoot,
    name: str,
    descriptor: int,
) -> bool:
    """Remove one staging directory only while its exact inode is held open.

    Mirrors `_unlink_bound_staging_entry` for the one removable directory
    shape: the name must still resolve to the held, already-proven inode with
    nothing inside immediately before the removal, and the held inode must be
    gone from the tree afterwards -- a replacement created at the name fails
    the post-check instead of counting as removed.
    """
    try:
        before = os.fstat(descriptor)
        path_before = _stat_entry(runtime.staging_descriptor, name)
        if (
            path_before is None
            or not stat.S_ISDIR(before.st_mode)
            or (before.st_dev, before.st_ino)
            != (path_before.st_dev, path_before.st_ino)
            or tuple(os.listdir(descriptor))
        ):
            return False
        os.rmdir(name, dir_fd=runtime.staging_descriptor)
        # A removed directory's descriptor still reports two links on macOS,
        # so removal is proven by the name no longer resolving to the held
        # inode rather than by the file-shaped nlink check.
        path_after = _stat_entry(runtime.staging_descriptor, name)
        if path_after is not None and (path_after.st_dev, path_after.st_ino) == (
            before.st_dev,
            before.st_ino,
        ):
            return False
        os.fsync(runtime.staging_descriptor)
        return True
    except OSError:
        return False


def _open_locked_retained_slot_file(
    runtime: _RuntimeRoot,
    member: StagingArtifactIdentity,
) -> int | None:
    """Open, lock, and prove one authenticated nonempty regular slot member."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    keep_open = False
    try:
        descriptor = os.open(member.name, flags, dir_fd=runtime.staging_descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = os.fstat(descriptor)
        path = _stat_entry(runtime.staging_descriptor, member.name)
        if (
            path is None
            or member.file_type != "regular"
            or _publication_identity(before) != _publication_identity(path)
            or not stat.S_ISREG(before.st_mode)
            or before.st_dev != _staging_device(runtime)
            or (before.st_ino, before.st_uid) != (member.inode, member.uid)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != member.mode
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size == 0
        ):
            return None
        keep_open = True
        return descriptor
    except OSError:
        return None
    finally:
        if descriptor is not None and not keep_open:
            _close_descriptor_best_effort(descriptor)


def _authenticated_slot_records(
    runtime: _RuntimeRoot,
    *,
    store_id: str,
    master_key: SecretBytes,
) -> dict[str, PublicationRollbackSlotRecord]:
    """Load every published slot record that authenticates for this Store."""
    records: dict[str, PublicationRollbackSlotRecord] = {}
    for name in sorted(os.listdir(runtime.staging_descriptor)):
        match = _ROLLBACK_SLOT_RECORD.fullmatch(name)
        if match is None:
            continue
        encoded = _read_slot_record_bytes(runtime, name)
        if encoded is None:
            continue
        try:
            record = decode_publication_rollback_slot(
                encoded,
                expected_store_id=store_id,
                master_key=master_key,
            )
        except InvalidArgumentError:
            continue
        if record.slot_id != match.group(1):
            continue
        records[record.slot_id] = record
    return records


def _read_slot_record_bytes(runtime: _RuntimeRoot, name: str) -> bytes | None:
    """Read one bounded, owner-only, stable slot record without following links."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=runtime.staging_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > MAX_PUBLICATION_ROLLBACK_SLOT_BYTES
        ):
            return None
        encoded = bytearray()
        while chunk := os.read(descriptor, 4096):
            encoded.extend(chunk)
            if len(encoded) > MAX_PUBLICATION_ROLLBACK_SLOT_BYTES:
                return None
        after = os.fstat(descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, name)
        if (
            path_after is None
            or _publication_identity(before) != _publication_identity(after)
            or _publication_identity(before) != _publication_identity(path_after)
            or _publication_stability(before) != _publication_stability(after)
            or _publication_stability(before) != _publication_stability(path_after)
        ):
            return None
        return bytes(encoded)
    except OSError:
        return None
    finally:
        if descriptor is not None:
            _close_descriptor_best_effort(descriptor)


def _open_verified_rollback_slot(
    runtime: _RuntimeRoot,
    record: PublicationRollbackSlotRecord,
) -> _RollbackSlot | None:
    """Lock and reprove every authenticated member of one idle rollback bundle."""
    if record.format_version != 2:
        return None
    payload: tuple[int, tuple[int, ...]] | None = None
    manifest: tuple[int, tuple[int, ...]] | None = None
    withdrawal: tuple[int, tuple[int, int]] | None = None
    verified = False
    try:
        payload = _open_locked_idle_slot_file(runtime, record.payload)
        if payload is None:
            return None
        manifest = _open_locked_idle_slot_file(runtime, record.manifest)
        if manifest is None:
            return None
        withdrawal = _open_locked_empty_withdrawal(runtime, record.withdrawal)
        if withdrawal is None:
            return None
        verified = True
    finally:
        if not verified:
            for opened in (payload, manifest, withdrawal):
                if opened is not None:
                    _close_descriptor_best_effort(opened[0])
    try:
        os.fsync(withdrawal[0])
        os.fsync(runtime.staging_descriptor)
        _checkpoint("staging.withdrawal_directory_fsync")
        _verify_runtime_root(runtime)
    except BaseException as error:
        for opened_descriptor in (payload[0], manifest[0], withdrawal[0]):
            _close_descriptor_best_effort(opened_descriptor)
        raise InvalidArgumentError(
            "publication withdrawal capability is unavailable"
        ) from error
    return _RollbackSlot(
        record=record,
        payload_descriptor=payload[0],
        payload_identity=payload[1],
        manifest_descriptor=manifest[0],
        manifest_identity=manifest[1],
        withdrawal_descriptor=withdrawal[0],
        withdrawal_identity=withdrawal[1],
    )


def _open_locked_idle_slot_file(
    runtime: _RuntimeRoot,
    member: StagingArtifactIdentity,
) -> tuple[int, tuple[int, ...]] | None:
    """Open, lock, and prove one authenticated zero-byte regular slot member."""
    flags = os.O_RDWR | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    keep_open = False
    try:
        descriptor = os.open(member.name, flags, dir_fd=runtime.staging_descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = os.fstat(descriptor)
        path = _stat_entry(runtime.staging_descriptor, member.name)
        after = os.fstat(descriptor)
        if (
            path is None
            or member.file_type != "regular"
            or _publication_identity(before) != _publication_identity(path)
            or _publication_identity(before) != _publication_identity(after)
            or not stat.S_ISREG(before.st_mode)
            or before.st_dev != _staging_device(runtime)
            or (before.st_ino, before.st_uid) != (member.inode, member.uid)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != member.mode
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != 0
        ):
            return None
        keep_open = True
        return descriptor, _publication_identity(before)
    except OSError:
        return None
    finally:
        if descriptor is not None and not keep_open:
            _close_descriptor_best_effort(descriptor)


def _open_locked_empty_withdrawal(
    runtime: _RuntimeRoot,
    member: StagingArtifactIdentity,
) -> tuple[int, tuple[int, int]] | None:
    """Open, lock, and prove one authenticated empty withdrawal directory."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    keep_open = False
    try:
        descriptor = os.open(member.name, flags, dir_fd=runtime.staging_descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata = os.fstat(descriptor)
        path = _stat_entry(runtime.staging_descriptor, member.name)
        empty = not tuple(os.listdir(descriptor))
        after = os.fstat(descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, member.name)
        if (
            path is None
            or path_after is None
            or member.file_type != "directory"
            or (metadata.st_dev, metadata.st_ino) != (path.st_dev, path.st_ino)
            or (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino)
            or (metadata.st_dev, metadata.st_ino)
            != (path_after.st_dev, path_after.st_ino)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != _staging_device(runtime)
            or (metadata.st_ino, metadata.st_uid) != (member.inode, member.uid)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != member.mode
            or stat.S_IMODE(after.st_mode) != member.mode
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or not empty
            or _stat_entry(descriptor, _WITHDRAWAL_CHILD) is not None
        ):
            return None
        keep_open = True
        return descriptor, (metadata.st_dev, metadata.st_ino)
    except OSError:
        return None
    finally:
        if descriptor is not None and not keep_open:
            _close_descriptor_best_effort(descriptor)


def _create_fresh_rollback_slot(
    runtime: _RuntimeRoot,
    *,
    store_id: str,
    master_key: SecretBytes,
) -> PublicationRollbackSlotRecord | None:
    """Exclusively mint one bundle and publish its authenticated provenance."""
    slot_id = secrets.token_hex(16)
    payload_name, manifest_name, withdrawal_name = (
        publication_rollback_slot_member_names(slot_id)
    )
    record_name = f".rollback-slot-{slot_id}.json"
    temporary_name = f".rollback-slot-{slot_id}.tmp"
    file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    payload_descriptor: int | None = None
    manifest_descriptor: int | None = None
    withdrawal_descriptor: int | None = None
    temporary_descriptor: int | None = None
    try:
        for occupied in (
            payload_name,
            manifest_name,
            withdrawal_name,
            record_name,
            temporary_name,
        ):
            if _stat_entry(runtime.staging_descriptor, occupied) is not None:
                return None
        try:
            payload_descriptor = os.open(
                payload_name,
                file_flags,
                0o600,
                dir_fd=runtime.staging_descriptor,
            )
            manifest_descriptor = os.open(
                manifest_name,
                file_flags,
                0o600,
                dir_fd=runtime.staging_descriptor,
            )
            os.mkdir(withdrawal_name, 0o700, dir_fd=runtime.staging_descriptor)
            withdrawal_descriptor = os.open(
                withdrawal_name,
                directory_flags,
                dir_fd=runtime.staging_descriptor,
            )
        except FileExistsError:
            return None
        os.fchmod(payload_descriptor, 0o600)
        os.fchmod(manifest_descriptor, 0o600)
        payload = os.fstat(payload_descriptor)
        manifest = os.fstat(manifest_descriptor)
        withdrawal = os.fstat(withdrawal_descriptor)
        if (
            not stat.S_ISREG(payload.st_mode)
            or not stat.S_ISREG(manifest.st_mode)
            or not stat.S_ISDIR(withdrawal.st_mode)
            or payload.st_uid != os.geteuid()
            or manifest.st_uid != os.geteuid()
            or withdrawal.st_uid != os.geteuid()
            or payload.st_nlink != 1
            or manifest.st_nlink != 1
            or payload.st_size != 0
            or manifest.st_size != 0
            or stat.S_IMODE(payload.st_mode) != 0o600
            or stat.S_IMODE(manifest.st_mode) != 0o600
            or stat.S_IMODE(withdrawal.st_mode) != 0o700
            or tuple(os.listdir(withdrawal_descriptor))
        ):
            return None
        record = PublicationRollbackSlotRecord(
            slot_id=slot_id,
            payload=_slot_member_identity(payload_name, payload, "regular"),
            manifest=_slot_member_identity(manifest_name, manifest, "regular"),
            withdrawal=_slot_member_identity(
                withdrawal_name,
                withdrawal,
                "directory",
            ),
        )
        encoded = encode_publication_rollback_slot(
            record,
            store_id=store_id,
            master_key=master_key,
        )
        temporary_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | (file_flags & ~os.O_RDWR),
            0o600,
            dir_fd=runtime.staging_descriptor,
        )
        os.fchmod(temporary_descriptor, 0o600)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(temporary_descriptor, remaining)
            if written <= 0:
                return None
            remaining = remaining[written:]
        os.fsync(temporary_descriptor)
        _checkpoint("staging.publication_slot_record_file_fsync")
        os.close(temporary_descriptor)
        temporary_descriptor = None
        _rename_no_replace(
            temporary_name,
            record_name,
            source_descriptor=runtime.staging_descriptor,
            destination_descriptor=runtime.staging_descriptor,
        )
        os.fsync(runtime.staging_descriptor)
        _checkpoint("staging.publication_slot_record_publish")
        _verify_runtime_root(runtime)
        return record
    except InvalidArgumentError, OSError:
        return None
    finally:
        for opened in (
            temporary_descriptor,
            withdrawal_descriptor,
            manifest_descriptor,
            payload_descriptor,
        ):
            if opened is not None:
                _close_descriptor_best_effort(opened)


def _slot_member_identity(
    name: str,
    metadata: os.stat_result,
    file_type: Literal["regular", "directory"],
) -> StagingArtifactIdentity:
    # The device is deliberately not recorded: the kernel reassigns `st_dev`
    # at every boot, and a persisted device invalidated every stored slot on
    # reboot. Verification instead requires every member to live on the
    # staging directory's current device.
    return StagingArtifactIdentity(
        name=name,
        device=None,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        file_type=file_type,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _staging_device(runtime: _RuntimeRoot) -> int:
    """The staging directory's current boot-assigned device number."""
    return os.fstat(runtime.staging_descriptor).st_dev


def _copy_bound_source_to_anchor(
    runtime: _RuntimeRoot,
    source_descriptor: int,
    source_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
    anchor_descriptor: int,
    anchor_name: str,
) -> bool:
    try:
        source_before = os.fstat(source_descriptor)
        if (
            _publication_identity(source_before) != source_identity
            or _descriptor_sha256(source_descriptor) != entry.sha256
        ):
            return False
        os.ftruncate(anchor_descriptor, 0)
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        os.lseek(anchor_descriptor, 0, os.SEEK_SET)
        total = 0
        digest = hashlib.sha256()
        while chunk := os.read(source_descriptor, _STREAM_BYTES):
            total += len(chunk)
            if total > entry.byte_length:
                return False
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(anchor_descriptor, view)
                if written <= 0:
                    return False
                view = view[written:]
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        os.fsync(anchor_descriptor)
        source_after = os.fstat(source_descriptor)
        anchor_after = os.fstat(anchor_descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, anchor_name)
        return (
            total == entry.byte_length
            and digest.hexdigest() == entry.sha256
            and _publication_identity(source_after) == source_identity
            and _publication_stability(source_before)
            == _publication_stability(source_after)
            and path_after is not None
            and _publication_identity(anchor_after) == _publication_identity(path_after)
            and stat.S_ISREG(anchor_after.st_mode)
            and anchor_after.st_uid == os.geteuid()
            and anchor_after.st_nlink == 1
            and stat.S_IMODE(anchor_after.st_mode) == 0o600
            and anchor_after.st_size == entry.byte_length
            and _descriptor_sha256(anchor_descriptor) == entry.sha256
        )
    except OSError:
        return False
    finally:
        os.lseek(source_descriptor, 0, os.SEEK_SET)


def _release_publication_rollback(
    runtime: _RuntimeRoot,
    preheld: _PreheldPublicationRollback,
    *,
    retain_anchor: bool,
    renamed: bool,
    source_descriptor: int,
    source_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
) -> None:
    """Release preheld custody only after proving or classifying every copy."""
    try:
        if retain_anchor:
            if renamed and not _publication_descriptor_is_drained(
                source_descriptor,
                source_identity,
            ):
                rollback = _rollback_exact_published_entry(
                    runtime,
                    source_descriptor,
                    source_identity,
                    entry,
                    preheld,
                )
                if not rollback.barriers_durable:
                    return
                marker_durable = rollback.marker_durable
            else:
                marker_durable = False
            if not marker_durable:
                marker_durable = _ensure_preheld_publication_manifest(runtime, preheld)
            if not renamed and marker_durable:
                cleaned = _drain_verified_descriptor(
                    source_descriptor,
                    source_identity,
                    entry.sha256,
                ) or _seal_and_drain_failed_private_cleanup(
                    source_descriptor,
                    source_identity,
                    entry.sha256,
                )
                if cleaned:
                    try:
                        os.fsync(runtime.staging_descriptor)
                    except OSError:
                        pass
            return
        anchor_clean = _drain_verified_descriptor(
            preheld.anchor_descriptor,
            preheld.anchor.expected_identity,
            preheld.anchor.sha256,
        )
        if anchor_clean:
            return
        if renamed:
            _rollback_exact_published_entry(
                runtime,
                source_descriptor,
                source_identity,
                entry,
                preheld,
            )
        else:
            _ensure_preheld_publication_manifest(runtime, preheld)
            _sync_rollback_directories(runtime)
        raise InvalidArgumentError("Store Inbox publication cleanup failed")
    finally:
        _close_descriptor_best_effort(preheld.anchor_descriptor)
        _close_descriptor_best_effort(preheld.manifest_descriptor)
        _close_descriptor_best_effort(preheld.withdrawal_descriptor)


def _publication_descriptor_is_drained(
    descriptor: int,
    expected_identity: tuple[int, ...],
) -> bool:
    """Recognize the exact nonempty source inode after verified zeroing."""
    if expected_identity[6] == 0:
        return False
    try:
        metadata = os.fstat(descriptor)
        return (
            (metadata.st_dev, metadata.st_ino, metadata.st_uid) == expected_identity[:3]
            and metadata.st_nlink == expected_identity[3]
            and stat.S_IFMT(metadata.st_mode) == expected_identity[4]
            and stat.S_IMODE(metadata.st_mode) == expected_identity[5]
            and metadata.st_size == 0
        )
    except OSError:
        return False


def _close_descriptor_best_effort(descriptor: int) -> None:
    """Attempt one close without converting an already-classified outcome."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def _drain_descriptor_best_effort(descriptor: int) -> None:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            return
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if after.st_nlink != 1:
            return
    except OSError:
        pass


def _drain_verified_descriptor(
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> bool:
    """Drain one exact bound inode even if its pathname has been detached."""
    try:
        before = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_uid) != expected_identity[:3]
            or before.st_nlink != expected_identity[3]
            or expected_identity[3] != 1
            or stat.S_IFMT(before.st_mode) != expected_identity[4]
            or stat.S_IMODE(before.st_mode) != expected_identity[5]
            or before.st_size != expected_identity[6]
            or _descriptor_sha256(descriptor) != expected_sha256
        ):
            return False
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        return (
            (after.st_dev, after.st_ino, after.st_uid) == expected_identity[:3]
            and after.st_nlink == expected_identity[3]
            and stat.S_IFMT(after.st_mode) == expected_identity[4]
            and stat.S_IMODE(after.st_mode) == expected_identity[5]
            and after.st_size == 0
        )
    except OSError:
        return False


def _seal_and_drain_failed_private_cleanup(
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> bool:
    """Make a failed descriptor cleanup unreadable before one final drain."""
    try:
        before = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_uid) != expected_identity[:3]
            or before.st_nlink != expected_identity[3]
            or expected_identity[3] != 1
            or stat.S_IFMT(before.st_mode) != expected_identity[4]
            or stat.S_IMODE(before.st_mode) not in {0, expected_identity[5]}
            or before.st_size != expected_identity[6]
            or _descriptor_sha256(descriptor) != expected_sha256
        ):
            return False
        if stat.S_IMODE(before.st_mode) != 0:
            os.fchmod(descriptor, 0)
            os.fsync(descriptor)
        sealed = os.fstat(descriptor)
        if (
            (sealed.st_dev, sealed.st_ino, sealed.st_uid) != expected_identity[:3]
            or sealed.st_nlink != expected_identity[3]
            or not stat.S_ISREG(sealed.st_mode)
            or stat.S_IMODE(sealed.st_mode) != 0
            or sealed.st_size != expected_identity[6]
        ):
            return False
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        drained = os.fstat(descriptor)
        if (
            (drained.st_dev, drained.st_ino, drained.st_uid) != expected_identity[:3]
            or drained.st_nlink != expected_identity[3]
            or not stat.S_ISREG(drained.st_mode)
            or stat.S_IMODE(drained.st_mode) != 0
            or drained.st_size != 0
        ):
            return False
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        return (
            (final.st_dev, final.st_ino, final.st_uid) == expected_identity[:3]
            and final.st_nlink == expected_identity[3]
            and stat.S_ISREG(final.st_mode)
            and stat.S_IMODE(final.st_mode) == 0o600
            and final.st_size == 0
        )
    except OSError:
        return False


def _rollback_exact_published_entry(
    runtime: _RuntimeRoot,
    descriptor: int,
    expected_identity: tuple[int, ...],
    entry: PrivateStagedEntry,
    preheld: _PreheldPublicationRollback,
) -> _PublicationRollbackOutcome:
    """Make exact source bytes private before any rollback crash checkpoint."""
    marker_durable = False
    state: Literal["quarantined", "replacement_preserved", "uncertain"] = "uncertain"
    uncertain = False
    source_drained = False
    try:
        withdrawn_exact = _withdrawn_payload_matches_descriptor(
            preheld,
            descriptor,
            expected_identity,
            entry.sha256,
        )
    except BaseException:
        withdrawn_exact = False
    privacy_proven = False
    for _attempt in range(_MAX_PRIVATE_RECOVERY_ATTEMPTS):
        names = _stable_bound_inbox_names(
            runtime,
            descriptor,
            expected_identity,
            entry.sha256,
        )
        if names is None:
            break
        if withdrawn_exact:
            privacy_proven = not names
            break
        if not names:
            privacy_proven = True
            state = "replacement_preserved"
            break
        if len(names) != 1:
            break
        try:
            _rename_current_bound_no_replace(
                names[0],
                _WITHDRAWAL_CHILD,
                source_descriptor=runtime.inbox_descriptor,
                destination_descriptor=preheld.withdrawal_descriptor,
                bound_descriptor=descriptor,
                expected_identity=expected_identity,
                expected_sha256=entry.sha256,
            )
        except InvalidArgumentError, OSError:
            continue
        try:
            withdrawn_exact = _withdrawn_payload_matches_descriptor(
                preheld,
                descriptor,
                expected_identity,
                entry.sha256,
            )
        except BaseException:
            withdrawn_exact = False
        if withdrawn_exact:
            state = "quarantined"

    if not privacy_proven:
        try:
            source_drained = _seal_and_drain_failed_private_cleanup(
                descriptor,
                expected_identity,
                entry.sha256,
            )
        except BaseException:
            source_drained = False
        privacy_proven = source_drained
        if not privacy_proven:
            uncertain = True

    try:
        os.fsync(preheld.withdrawal_descriptor)
    except BaseException:
        uncertain = True
    if not privacy_proven:
        for directory_descriptor in (
            runtime.inbox_descriptor,
            runtime.staging_descriptor,
        ):
            try:
                os.fsync(directory_descriptor)
            except BaseException:
                pass
        return _PublicationRollbackOutcome(
            state="uncertain",
            marker_durable=False,
            barriers_durable=False,
        )

    privacy_barriers = _sync_rollback_directories(runtime)
    if not privacy_barriers:
        uncertain = True

    for checkpoint in (
        "staging.publish_before_rollback",
        "staging.publish_before_rollback_quarantine",
        "staging.publish_rollback_quarantine",
    ):
        try:
            _checkpoint(checkpoint)
        except BaseException:
            uncertain = True

    try:
        anchor_verified = _preheld_anchor_matches(runtime, preheld)
    except BaseException:
        anchor_verified = False
    if anchor_verified:
        try:
            marker_durable = _ensure_preheld_publication_manifest(runtime, preheld)
        except BaseException:
            marker_durable = False
    if marker_durable:
        drained = source_drained
        if not drained:
            try:
                drained = _drain_verified_descriptor(
                    descriptor,
                    expected_identity,
                    entry.sha256,
                )
            except BaseException:
                drained = False
        if not drained:
            try:
                drained = _seal_and_drain_failed_private_cleanup(
                    descriptor,
                    expected_identity,
                    entry.sha256,
                )
            except BaseException:
                drained = False
        if not drained:
            uncertain = True
        elif withdrawn_exact:
            try:
                recycled = _recycle_drained_withdrawal_child(
                    runtime,
                    preheld,
                    descriptor,
                    expected_identity,
                    entry.entry_id,
                )
            except BaseException:
                recycled = False
            if not recycled:
                uncertain = True
    elif anchor_verified and withdrawn_exact and privacy_barriers:
        try:
            anchor_consolidated = _drain_verified_descriptor(
                preheld.anchor_descriptor,
                preheld.anchor.expected_identity,
                preheld.anchor.sha256,
            )
        except BaseException:
            anchor_consolidated = False
        if not anchor_consolidated:
            uncertain = True
    else:
        uncertain = True
    try:
        os.fsync(preheld.withdrawal_descriptor)
        _checkpoint("staging.withdrawal_directory_rollback_fsync")
    except BaseException:
        uncertain = True
    barriers_durable = _sync_rollback_directories(runtime)
    if uncertain:
        state = "uncertain"
    return _PublicationRollbackOutcome(
        state=state,
        marker_durable=marker_durable,
        barriers_durable=barriers_durable,
    )


def _stable_bound_inbox_names(
    runtime: _RuntimeRoot,
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> tuple[str, ...] | None:
    """Enumerate every stable Inbox name for the retained source inode."""

    def snapshot() -> tuple[tuple[str, tuple[int, ...], tuple[int, ...]], ...]:
        matches: list[tuple[str, tuple[int, ...], tuple[int, ...]]] = []
        for name in sorted(os.listdir(runtime.inbox_descriptor)):
            metadata = _stat_entry(runtime.inbox_descriptor, name)
            if metadata is None:
                continue
            if (metadata.st_dev, metadata.st_ino, metadata.st_uid) != (
                expected_identity[:3]
            ):
                continue
            matches.append(
                (
                    name,
                    _publication_identity(metadata),
                    _publication_stability(metadata),
                )
            )
        return tuple(matches)

    try:
        descriptor_before = os.fstat(descriptor)
        directory_before = os.fstat(runtime.inbox_descriptor)
        digest = _descriptor_sha256(descriptor)
        first = snapshot()
        second = snapshot()
        descriptor_after = os.fstat(descriptor)
        directory_after = os.fstat(runtime.inbox_descriptor)
        if (
            (
                descriptor_before.st_dev,
                descriptor_before.st_ino,
                descriptor_before.st_uid,
            )
            != expected_identity[:3]
            or (
                descriptor_after.st_dev,
                descriptor_after.st_ino,
                descriptor_after.st_uid,
            )
            != expected_identity[:3]
            or descriptor_before.st_nlink < expected_identity[3]
            or descriptor_after.st_nlink != descriptor_before.st_nlink
            or stat.S_IFMT(descriptor_before.st_mode) != expected_identity[4]
            or stat.S_IFMT(descriptor_after.st_mode) != expected_identity[4]
            or stat.S_IMODE(descriptor_before.st_mode) != expected_identity[5]
            or stat.S_IMODE(descriptor_after.st_mode) != expected_identity[5]
            or descriptor_before.st_size != expected_identity[6]
            or descriptor_after.st_size != expected_identity[6]
            or _publication_stability(descriptor_before)
            != _publication_stability(descriptor_after)
            or digest != expected_sha256
            or (directory_before.st_dev, directory_before.st_ino)
            != runtime.inbox_identity
            or (directory_after.st_dev, directory_after.st_ino)
            != runtime.inbox_identity
            or _publication_stability(directory_before)
            != _publication_stability(directory_after)
            or first != second
        ):
            return None
        return tuple(item[0] for item in first)
    except InvalidArgumentError, OSError:
        return None


def _rename_current_bound_no_replace(
    source_name: str,
    destination_name: str,
    *,
    source_descriptor: int,
    destination_descriptor: int,
    bound_descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> None:
    """Move one currently bound path while accepting stable hard-link drift."""
    current = os.fstat(bound_descriptor)
    if (
        (current.st_dev, current.st_ino, current.st_uid) != expected_identity[:3]
        or current.st_nlink < expected_identity[3]
        or stat.S_IFMT(current.st_mode) != expected_identity[4]
        or stat.S_IMODE(current.st_mode) != expected_identity[5]
        or current.st_size != expected_identity[6]
        or _descriptor_sha256(bound_descriptor) != expected_sha256
    ):
        raise OSError(errno.ESTALE, "Store source binding changed before rollback")
    binding = _BoundRename(
        source_name=source_name,
        destination_name=destination_name,
        source_directory_descriptor=source_descriptor,
        destination_directory_descriptor=destination_descriptor,
        source_descriptor=bound_descriptor,
        expected_identity=_publication_identity(current),
        expected_sha256=expected_sha256,
    )
    reset_handle = _BOUND_RENAME.set(binding)
    try:
        _rename_no_replace(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )
    finally:
        _BOUND_RENAME.reset(reset_handle)
    if _bound_payload_matches_path_core(
        destination_descriptor,
        destination_name,
        bound_descriptor,
        expected_identity,
        expected_sha256,
    ):
        return
    _restore_quarantined_replacement(
        None,
        destination_name,
        source_name,
        source_descriptor=destination_descriptor,
        destination_descriptor=source_descriptor,
    )
    raise OSError(errno.ESTALE, "Store rollback source changed during rename")


def _recycle_drained_withdrawal_child(
    runtime: _RuntimeRoot,
    preheld: _PreheldPublicationRollback,
    descriptor: int,
    expected_identity: tuple[int, ...],
    entry_id: str,
) -> bool:
    """Move one descriptor-proven zero child back into its vacant stage slot."""
    try:
        withdrawal = os.fstat(preheld.withdrawal_descriptor)
        withdrawal_path = _stat_entry(
            runtime.staging_descriptor,
            preheld.withdrawal_name,
        )
        before = os.fstat(descriptor)
        child_before = _stat_entry(
            preheld.withdrawal_descriptor,
            _WITHDRAWAL_CHILD,
        )
        if (
            withdrawal_path is None
            or (withdrawal.st_dev, withdrawal.st_ino) != preheld.withdrawal_identity
            or (withdrawal_path.st_dev, withdrawal_path.st_ino)
            != preheld.withdrawal_identity
            or child_before is None
            or (before.st_dev, before.st_ino, before.st_uid) != expected_identity[:3]
            or _publication_identity(before) != _publication_identity(child_before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != 0
            or _stat_entry(runtime.staging_descriptor, entry_id) is not None
        ):
            return False
        _rename_no_replace(
            _WITHDRAWAL_CHILD,
            entry_id,
            source_descriptor=preheld.withdrawal_descriptor,
            destination_descriptor=runtime.staging_descriptor,
        )
        _checkpoint("staging.withdrawal_child_recycled")
        after = os.fstat(descriptor)
        staged = _stat_entry(runtime.staging_descriptor, entry_id)
        if (
            staged is not None
            and _publication_identity(after) == _publication_identity(before)
            and _publication_identity(staged) == _publication_identity(before)
        ):
            return True
        _restore_quarantined_replacement(
            runtime,
            entry_id,
            _WITHDRAWAL_CHILD,
            source_descriptor=runtime.staging_descriptor,
            destination_descriptor=preheld.withdrawal_descriptor,
        )
        return False
    except InvalidArgumentError, OSError:
        return False


def _preheld_anchor_matches(
    runtime: _RuntimeRoot,
    preheld: _PreheldPublicationRollback,
) -> bool:
    try:
        descriptor = preheld.anchor_descriptor
        before = os.fstat(descriptor)
        path_before = _stat_entry(
            runtime.staging_descriptor,
            preheld.anchor.payload_name,
        )
        digest = _descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        path_after = _stat_entry(
            runtime.staging_descriptor,
            preheld.anchor.payload_name,
        )
        return (
            path_before is not None
            and path_after is not None
            and _publication_identity(before) == preheld.anchor.expected_identity
            and _publication_identity(after) == preheld.anchor.expected_identity
            and _publication_identity(path_before) == preheld.anchor.expected_identity
            and _publication_identity(path_after) == preheld.anchor.expected_identity
            and _publication_stability(before) == _publication_stability(after)
            and _publication_stability(path_before)
            == _publication_stability(path_after)
            and digest == preheld.anchor.sha256
        )
    except OSError:
        return False


def _withdrawn_payload_matches_descriptor(
    preheld: _PreheldPublicationRollback,
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> bool:
    if (
        os.fstat(preheld.withdrawal_descriptor).st_dev,
        os.fstat(preheld.withdrawal_descriptor).st_ino,
    ) != preheld.withdrawal_identity:
        return False
    return _bound_payload_matches_path_core(
        preheld.withdrawal_descriptor,
        _WITHDRAWAL_CHILD,
        descriptor,
        expected_identity,
        expected_sha256,
    )


def _bound_payload_matches_path_core(
    directory_descriptor: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> bool:
    """Path proof rollback calls directly, so no wrapper can weaken it.

    Rollback never routes this through a named indirection: an injectable seam
    in front of it would be exactly the thing a defeated verifier could use to
    stop a withdrawal that has to happen.
    """
    try:
        before = os.fstat(descriptor)
        path_before = _stat_entry(directory_descriptor, name)
        digest = _descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        path_after = _stat_entry(directory_descriptor, name)
        return (
            path_before is not None
            and path_after is not None
            and (before.st_dev, before.st_ino, before.st_uid) == expected_identity[:3]
            and (after.st_dev, after.st_ino, after.st_uid) == expected_identity[:3]
            and (path_before.st_dev, path_before.st_ino, path_before.st_uid)
            == expected_identity[:3]
            and (path_after.st_dev, path_after.st_ino, path_after.st_uid)
            == expected_identity[:3]
            and before.st_nlink >= expected_identity[3]
            and after.st_nlink == before.st_nlink
            and path_before.st_nlink == before.st_nlink
            and path_after.st_nlink == before.st_nlink
            and stat.S_IFMT(before.st_mode) == expected_identity[4]
            and stat.S_IFMT(after.st_mode) == expected_identity[4]
            and stat.S_IFMT(path_before.st_mode) == expected_identity[4]
            and stat.S_IFMT(path_after.st_mode) == expected_identity[4]
            and stat.S_IMODE(before.st_mode) == expected_identity[5]
            and stat.S_IMODE(after.st_mode) == expected_identity[5]
            and stat.S_IMODE(path_before.st_mode) == expected_identity[5]
            and stat.S_IMODE(path_after.st_mode) == expected_identity[5]
            and before.st_size == expected_identity[6]
            and after.st_size == expected_identity[6]
            and path_before.st_size == expected_identity[6]
            and path_after.st_size == expected_identity[6]
            and _publication_stability(before) == _publication_stability(after)
            and _publication_stability(path_before)
            == _publication_stability(path_after)
            and digest == expected_sha256
        )
    except OSError:
        return False


def _restore_quarantined_replacement(
    runtime: _RuntimeRoot | None,
    quarantine_name: str,
    destination_name: str,
    *,
    source_descriptor: int | None = None,
    destination_descriptor: int | None = None,
) -> bool:
    """Best-effort no-replace restore of one stable entry without opening it."""
    if source_descriptor is None:
        if runtime is None:
            return False
        selected_source = runtime.staging_descriptor
    else:
        selected_source = source_descriptor
    if destination_descriptor is None:
        if runtime is None:
            return False
        selected_destination = runtime.inbox_descriptor
    else:
        selected_destination = destination_descriptor
    try:
        before = _stat_entry(selected_source, quarantine_name)
        stable = _stat_entry(selected_source, quarantine_name)
        if (
            before is None
            or stable is None
            or _publication_identity(before) != _publication_identity(stable)
            or _stat_entry(selected_destination, destination_name) is not None
        ):
            return False
        _rename_no_replace(
            quarantine_name,
            destination_name,
            source_descriptor=selected_source,
            destination_descriptor=selected_destination,
        )
        destination = _stat_entry(selected_destination, destination_name)
        return destination is not None and _publication_identity(
            destination
        ) == _publication_identity(before)
    except InvalidArgumentError, OSError:
        return False


def _reserve_private_recovery(
    runtime: _RuntimeRoot,
    *,
    kind: Literal["exact_incomplete", "ordinary_publication"],
    entry_id: str,
    byte_length: int,
    sha256: str,
    expected_identity: tuple[int, ...],
) -> _PrivateRecoveryReservation:
    """Mint one unpredictable candidate private-recovery identity."""
    recovery_id = secrets.token_hex(16)
    reservation = _PrivateRecoveryReservation(
        recovery_id=recovery_id,
        kind=kind,
        payload_name=f".recovery-{recovery_id}.stage",
        entry_id=entry_id,
        byte_length=byte_length,
        sha256=sha256,
        expected_identity=expected_identity,
    )
    return reservation


def _move_to_fresh_private_recovery(
    runtime: _RuntimeRoot,
    *,
    source_name: str,
    source_descriptor: int,
    kind: Literal["exact_incomplete", "ordinary_publication"],
    entry_id: str,
    byte_length: int,
    sha256: str,
    expected_identity: tuple[int, ...],
) -> _PrivateRecoveryReservation | None:
    """Move once to a bounded fresh no-replace recovery payload identity."""
    for _attempt in range(_MAX_PRIVATE_RECOVERY_ATTEMPTS):
        reservation = _reserve_private_recovery(
            runtime,
            kind=kind,
            entry_id=entry_id,
            byte_length=byte_length,
            sha256=sha256,
            expected_identity=expected_identity,
        )
        try:
            _rename_no_replace(
                source_name,
                reservation.payload_name,
                source_descriptor=source_descriptor,
                destination_descriptor=runtime.staging_descriptor,
            )
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                continue
            raise
        return reservation
    return None


def _recovery_payload_matches_descriptor(
    runtime: _RuntimeRoot,
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    """Prove one recovery name and the retained descriptor are the same bytes."""
    try:
        before = os.fstat(descriptor)
        digest = _descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        return (
            _publication_identity(before) == expected_identity
            and _publication_identity(after) == expected_identity
            and _publication_stability(before) == _publication_stability(after)
            and digest == expected_sha256
            and _verified_private_recovery_payload(runtime, reservation)
        )
    except OSError:
        return False


def _unlink_bound_staging_entry(
    runtime: _RuntimeRoot,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, ...],
) -> bool:
    """Remove one staging name only while its exact inode is held open.

    The caller supplies a descriptor it has held continuously across its own
    verification, so nothing is removed by pathname alone. The name must still
    resolve to that identity immediately before the unlink, and the held inode
    must lose its last link afterwards; a replacement created at that name fails
    the post-check instead of being accepted as a successful removal.
    """
    try:
        before = os.fstat(descriptor)
        path_before = _stat_entry(runtime.staging_descriptor, name)
        if (
            path_before is None
            or _publication_identity(before) != expected_identity
            or _publication_identity(path_before) != expected_identity
            or _publication_stability(before) != _publication_stability(path_before)
            or before.st_nlink != 1
        ):
            return False
        os.unlink(name, dir_fd=runtime.staging_descriptor)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_uid) != expected_identity[:3]
            or stat.S_IFMT(after.st_mode) != expected_identity[4]
            or after.st_nlink != 0
        ):
            return False
        os.fsync(runtime.staging_descriptor)
        return True
    except OSError:
        return False


def _reclaim_bound_ordinary_stage_slot(
    runtime: _RuntimeRoot,
    entry_id: str,
    descriptor: int,
) -> bool:
    """Release one aborted ordinary reservation instead of stranding a tombstone.

    Reclamation is authorized by a descriptor its caller holds open across the
    whole of this check, never by pathname, so an occupant of unproven
    provenance is never removed. Two callers hold one: the streaming path,
    whose descriptor created the reservation with `O_CREAT|O_EXCL|O_NOFOLLOW`
    and has held it under its exclusive lock ever since, and the recovery pass
    (`_reclaim_unlocked_ordinary_stage_slot`), which reopens the name no-follow
    and takes that same exclusive lock itself -- which it can only do once no
    live process holds it.

    The checks below are the provenance proof, and both callers need every one
    of them: an owner-owned regular file with one link, mode 0600, no bytes,
    and no `.intent.json` or `.ready.json` sibling naming it. A slot failing
    any of them stays in place and becomes an owner-visible recovery issue
    rather than silently consuming the global staging bound.
    """
    if _ENTRY_ID.fullmatch(entry_id) is None:
        return False
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_size != 0
        ):
            return False
        for suffix in (_EXACT_INTENT_SUFFIX, _EXACT_READY_SUFFIX):
            if _stat_entry(runtime.staging_descriptor, entry_id + suffix) is not None:
                return False
    except OSError:
        return False
    return _unlink_bound_staging_entry(
        runtime,
        entry_id,
        descriptor,
        _publication_identity(current),
    )


def _reclaim_orphaned_ordinary_stage_slots(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    """Free ordinary staging slots whose reserving process died holding them.

    `ent_*.stage` occupancy is the whole global staging bound, and it is
    counted by name. Eight reservations abandoned between `O_CREAT|O_EXCL` and
    the first written byte therefore do not degrade uploads, they end them:
    every later upload fails with the capacity error and nothing in the
    product ever removes the tombstones.

    Only the recovery pass reclaims, never staging itself. Reservation runs on
    every upload and must never delete anything it cannot see the whole
    history of; recovery is the deliberate repair, and it still removes only
    what it can prove is abandoned.

    The pass takes the writer lock for the same reason `_reserve_ordinary_
    stage_slot` does: a reservation is created and locked inside that lock, so
    holding it here is what makes "no live process holds this" a fact rather
    than a race against a slot being born. A busy writer leaves everything for
    the next pass -- an upload is in flight, which is the opposite of the
    condition being repaired.
    """
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            with _writer_lock(paths, root_descriptor=runtime.root_descriptor):
                for name in sorted(os.listdir(runtime.staging_descriptor)):
                    if _ENTRY_ID.fullmatch(name) is not None:
                        _reclaim_unlocked_ordinary_stage_slot(runtime, name)
            _verify_runtime_root(runtime)
    except StoreBusyError:
        return


def _reclaim_unlocked_ordinary_stage_slot(
    runtime: _RuntimeRoot,
    entry_id: str,
) -> bool:
    """Reclaim one ordinary slot no live process is holding, or leave it alone.

    Two facts together are the proof, and neither is sufficient alone. A
    reservation holds `flock(LOCK_EX|LOCK_NB)` on its own descriptor for the
    whole stream and the kernel drops that lock when the holding process dies,
    so a slot this pass can lock is a slot nobody is streaming into and a
    `BlockingIOError` is a live upload to leave exactly where it is. That
    covers streaming and not publication, which reopens the slot without a
    lock -- so the second fact carries the rest: a completed slot always holds
    bytes, because `_stream_reserved_private_slot` refuses an empty one. A
    zero-length slot therefore cannot be an upload waiting to be published.

    The descriptor is opened no-follow and non-blocking and every remaining
    check runs on it, so nothing is judged or removed by pathname. A bounded
    path-side structural check separates proven non-reclaimable entries from
    operational open failures before the descriptor is acquired.
    """
    try:
        path_before = _stat_entry(runtime.staging_descriptor, entry_id)
    except OSError as error:
        raise _StagePayloadLeaseUnavailable(
            "staged payload lease is unavailable"
        ) from error
    if path_before is None:
        return False
    if (
        not stat.S_ISREG(path_before.st_mode)
        or path_before.st_uid != os.geteuid()
        or path_before.st_nlink != 1
        or stat.S_IMODE(path_before.st_mode) != 0o600
        or path_before.st_size != 0
    ):
        return False
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(entry_id, flags, dir_fd=runtime.staging_descriptor)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _StagePayloadLeaseUnavailable(
            "staged payload lease is unavailable"
        ) from error
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                return False
            raise _StagePayloadLeaseUnavailable(
                "staged payload lease failed"
            ) from error
        return _reclaim_bound_ordinary_stage_slot(runtime, entry_id, descriptor)
    finally:
        _close_descriptor_best_effort(descriptor)


#: Ceiling for every durable manifest this module reads back. Manifests hold
#: identifiers, counts, and digests -- never source bytes -- so a megabyte is
#: already far past any legitimate one and exists to bound a corrupted read.
MAX_MANIFEST_BYTES = 1_048_576
#: The recovery marker is the smallest and most rigid of them, and it is read
#: on the crash path, so it gets a tighter ceiling of its own.
MAX_RECOVERY_MANIFEST_BYTES = 16_384


def _read_private_manifest(
    directory_descriptor: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
    verify_stable: bool = False,
) -> bytes:
    """Read one owner-only manifest under a fixed ceiling, or refuse it.

    A manifest is trusted only when it is a regular file this user owns, with
    one link, mode 0600, and a size inside `max_bytes` -- all checked on the
    open descriptor, so the name cannot be swapped between the check and the
    read. `verify_stable` additionally proves that the descriptor and the name
    still denote the same unchanged file once the read is done.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > max_bytes
        ):
            raise InvalidArgumentError(f"{label} is unsafe")
        encoded = bytearray()
        while chunk := os.read(descriptor, 8192):
            encoded.extend(chunk)
            if len(encoded) > max_bytes:
                raise InvalidArgumentError(f"{label} is too large")
        if verify_stable:
            after = os.fstat(descriptor)
            path_after = _stat_entry(directory_descriptor, name)
            if (
                path_after is None
                or _publication_identity(before) != _publication_identity(after)
                or _publication_identity(before) != _publication_identity(path_after)
                or _publication_stability(before) != _publication_stability(after)
                or _publication_stability(before) != _publication_stability(path_after)
            ):
                raise InvalidArgumentError(f"{label} changed")
        return bytes(encoded)
    except OSError as error:
        raise InvalidArgumentError(f"{label} is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _encoded_manifest(payload: Mapping[str, object]) -> bytes:
    """Serialize one manifest payload the single way this module writes them."""
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _publish_manifest_bytes(
    encoded: bytes,
    *,
    directory_descriptor: int,
    temporary_name: str,
    final_name: str,
    checkpoints: tuple[str, str, str],
    write_failure: str,
    replace: bool = False,
) -> None:
    """Land one manifest durably under `final_name`, or raise having published none.

    Every durable manifest in this module lands the same way: create the
    temporary exclusively and never through a symlink, force its mode past the
    umask, write it whole, fsync the file, rename it into place, then fsync the
    directory that now names it. Each boundary carries a checkpoint so a test
    can crash the process between any two of them.

    Cleaning up a temporary a failed write left behind stays with the caller.
    What is safe to unlink differs by call site, and one of them deliberately
    keeps its temporary rather than unlink by name in a directory whose
    identity it can no longer vouch for.
    """
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(errno.EIO, write_failure)
            remaining = remaining[written:]
        os.fsync(descriptor)
        _checkpoint(checkpoints[0])
        os.close(descriptor)
        descriptor = None
        if replace:
            os.replace(
                temporary_name,
                final_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
        else:
            _rename_no_replace(
                temporary_name,
                final_name,
                source_descriptor=directory_descriptor,
                destination_descriptor=directory_descriptor,
            )
        _checkpoint(checkpoints[1])
        os.fsync(directory_descriptor)
        _checkpoint(checkpoints[2])
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_private_recovery_manifest(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    """Best-effort publish one strict recovery marker for a reserved payload."""
    try:
        _publish_manifest_bytes(
            _encoded_manifest(
                {
                    "batch_id": reservation.batch_id,
                    "byte_length": reservation.byte_length,
                    "capture_request_id": reservation.capture_request_id,
                    "entry_id": reservation.entry_id,
                    "expected_identity": list(reservation.expected_identity),
                    "format": _RECOVERY_FORMAT,
                    "kind": reservation.kind,
                    "payload_name": reservation.payload_name,
                    "recovery_id": reservation.recovery_id,
                    "sha256": reservation.sha256,
                }
            ),
            directory_descriptor=runtime.staging_descriptor,
            temporary_name=f".recovery-{secrets.token_hex(16)}.tmp",
            final_name=f".recovery-{reservation.recovery_id}.json",
            checkpoints=(
                "staging.recovery_manifest_file_fsync",
                "staging.recovery_manifest_publish",
                "staging.recovery_manifest_directory_fsync",
            ),
            write_failure="recovery marker write failed",
        )
        _verify_runtime_root(runtime)
        return True
    except BaseException:
        # The unpredictable temporary is intentionally retained when cleanup
        # cannot be made descriptor-bound; recovery reports it content-free.
        return False


def _ensure_preheld_publication_manifest(
    runtime: _RuntimeRoot,
    preheld: _PreheldPublicationRollback,
) -> bool:
    return _ensure_reserved_publication_manifest(
        runtime,
        preheld.anchor,
        preheld.manifest_descriptor,
        preheld.manifest_identity,
    )


def _ensure_reserved_publication_manifest(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
    descriptor: int,
    expected: tuple[int, ...],
) -> bool:
    """Fill and verify the final marker identity reserved before publication."""
    payload = {
        "batch_id": reservation.batch_id,
        "byte_length": reservation.byte_length,
        "capture_request_id": reservation.capture_request_id,
        "entry_id": reservation.entry_id,
        "expected_identity": list(reservation.expected_identity),
        "format": _RECOVERY_FORMAT,
        "kind": reservation.kind,
        "payload_name": reservation.payload_name,
        "recovery_id": reservation.recovery_id,
        "sha256": reservation.sha256,
    }
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    name = f".recovery-{reservation.recovery_id}.json"
    try:
        before = os.fstat(descriptor)
        path_before = _stat_entry(runtime.staging_descriptor, name)
        if (
            path_before is None
            or (before.st_dev, before.st_ino, before.st_uid, before.st_nlink)
            != expected[:4]
            or stat.S_IFMT(before.st_mode) != expected[4]
            or stat.S_IMODE(before.st_mode) != expected[5]
            or _publication_identity(before) != _publication_identity(path_before)
            or before.st_nlink != 1
        ):
            return False
        os.lseek(descriptor, 0, os.SEEK_SET)
        current = bytearray()
        while chunk := os.read(descriptor, _STREAM_BYTES):
            current.extend(chunk)
            if len(current) > len(encoded):
                return False
        if current and bytes(current) != encoded:
            return False
        if not current:
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    return False
                remaining = remaining[written:]
        os.fsync(descriptor)
        try:
            _checkpoint("staging.recovery_manifest_file_fsync")
            _checkpoint("staging.recovery_manifest_publish")
        except BaseException:
            pass
        after = os.fstat(descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, name)
        if (
            path_after is None
            or (after.st_dev, after.st_ino, after.st_uid, after.st_nlink)
            != expected[:4]
            or stat.S_IFMT(after.st_mode) != expected[4]
            or stat.S_IMODE(after.st_mode) != expected[5]
            or _publication_identity(after) != _publication_identity(path_after)
            or after.st_size != len(encoded)
        ):
            return False
        os.fsync(runtime.staging_descriptor)
        _verify_runtime_root(runtime)
        try:
            _checkpoint("staging.recovery_manifest_directory_fsync")
            _checkpoint("staging.recovery_manifest_verified_directory_fsync")
        except BaseException:
            pass
        loaded = _load_private_recovery_manifest(runtime, name)
        return loaded == reservation and _verified_private_recovery_payload(
            runtime,
            reservation,
        )
    except InvalidArgumentError, OSError:
        return False


def _ensure_private_recovery_manifest(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    """Boundedly publish, reload, and independently verify one recovery handoff."""
    final_name = f".recovery-{reservation.recovery_id}.json"
    for _attempt in range(2):
        final_metadata = _stat_entry(runtime.staging_descriptor, final_name)
        try:
            existing = _load_private_recovery_manifest(runtime, final_name)
        except InvalidArgumentError:
            existing = None
        if final_metadata is not None and existing != reservation:
            return False
        existing_matches = existing == reservation and (
            _verified_private_recovery_payload(runtime, reservation)
        )
        if existing_matches:
            try:
                os.fsync(runtime.staging_descriptor)
                _verify_runtime_root(runtime)
            except InvalidArgumentError, OSError:
                continue
            try:
                _checkpoint("staging.recovery_manifest_verified_directory_fsync")
            except BaseException:
                pass
            return True
        temporary_before = {
            name
            for name in os.listdir(runtime.staging_descriptor)
            if _RECOVERY_TEMP.fullmatch(name) is not None
        }
        _write_private_recovery_manifest(runtime, reservation)
        temporary_after = {
            name
            for name in os.listdir(runtime.staging_descriptor)
            if _RECOVERY_TEMP.fullmatch(name) is not None
        }
        if temporary_after - temporary_before:
            return False
    try:
        existing = _load_private_recovery_manifest(runtime, final_name)
        if existing != reservation or not _verified_private_recovery_payload(
            runtime,
            reservation,
        ):
            return False
        os.fsync(runtime.staging_descriptor)
        _verify_runtime_root(runtime)
        try:
            _checkpoint("staging.recovery_manifest_verified_directory_fsync")
        except BaseException:
            pass
        return True
    except InvalidArgumentError, OSError:
        return False


def _sync_rollback_directories(runtime: _RuntimeRoot) -> bool:
    """Attempt both rollback barriers without turning one failure into success."""
    durable = True
    for descriptor, checkpoint in (
        (runtime.inbox_descriptor, "staging.rollback_inbox_directory_fsync"),
        (runtime.staging_descriptor, "staging.rollback_staging_directory_fsync"),
    ):
        try:
            os.fsync(descriptor)
            _checkpoint(checkpoint)
        except BaseException:
            durable = False
    try:
        _verify_runtime_root(runtime)
    except InvalidArgumentError, OSError:
        durable = False
    return durable


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, _STREAM_BYTES):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def capture_exact_staged_entry(
    paths: RuntimePaths,
    entry: PrivateStagedEntry,
    *,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> InboxBatch:
    """Seal exactly one private entry into its reserved isolated batch."""
    _validate_private_entry(entry)
    _validate_exact_metadata(metadata)
    if entry.sha256 != metadata.payload_sha256:
        raise InvalidArgumentError("exact capture digest is mismatched")
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            with _writer_lock(paths, root_descriptor=runtime.root_descriptor):
                _verify_runtime_root(runtime)
                existing = _load_exact_batch(runtime, entry, metadata)
                if existing is not None:
                    _cleanup_committed_exact_claim(runtime, metadata)
                    _cleanup_exact_ready(runtime, entry, metadata)
                    return existing
                claim = _find_exact_claim(runtime, metadata)
                try:
                    loaded_entry, loaded_metadata = _load_exact_ready(
                        runtime,
                        entry.entry_id,
                        require_file=claim is None,
                    )
                except InvalidArgumentError:
                    if claim is None:
                        raise
                else:
                    if loaded_entry != entry or loaded_metadata != metadata:
                        raise InvalidArgumentError("exact ready manifest is mismatched")
                if claim is None:
                    claim = _create_exact_claim(runtime, entry, metadata)
                else:
                    if claim.path.name != claim.batch_id:
                        claim = _publish_created_claim(runtime, claim)
                    _complete_claim(runtime, claim)
                batch = _publish_and_cleanup(runtime, claim)
                try:
                    _cleanup_exact_ready(runtime, entry, metadata)
                except InvalidArgumentError:
                    # The authoritative batch is already committed.  Leave
                    # residual private custody for the next recovery pass
                    # rather than reporting this invocation as a failure and
                    # losing the batch receipt the caller needs.
                    pass
                return batch
    except InvalidArgumentError, StoreBusyError:
        raise
    except OSError as error:
        raise InvalidArgumentError("exact capture filesystem is unavailable") from error


def recover_exact_staged_entries(
    paths: RuntimePaths,
    *,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> tuple[CapturedCorrection, ...]:
    """Inspect recovery state, then resume every valid exact-ready capture."""
    with _recover_exact_staged_entries_session(
        paths,
        directory_authority=directory_authority,
    ) as (recovered, inspection):
        inspection.final_issues()
        return recovered


def recover_exact_staged_entries_with_issues(
    paths: RuntimePaths,
    *,
    limit: int,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> tuple[tuple[CapturedCorrection, ...], Page[CaptureRecoveryIssue]]:
    """Recover and return the first issue page from one retained inspection."""
    _validate_recovery_issue_page_limit(limit)
    with _recover_exact_staged_entries_session(
        paths,
        directory_authority=directory_authority,
    ) as (recovered, inspection):
        return recovered, _recovery_issue_page(
            inspection.final_issues(),
            store_id=inspection.identity.store_id,
            cursor=None,
            limit=limit,
        )


@contextmanager
def _recover_exact_staged_entries_session(
    paths: RuntimePaths,
    *,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> Iterator[tuple[tuple[CapturedCorrection, ...], _ExactRecoveryInspection]]:
    """Retain one preflighted authority through recovery and result assembly."""
    try:
        with _exact_recovery_inspection(
            paths,
            directory_authority=directory_authority,
        ) as inspection:
            candidates = _preflight_exact_recovery(
                paths,
                inspection.directory_authority,
            )
            inspection.inspect_exact_state()
            recovered = _recover_exact_staged_entries(
                paths,
                directory_authority=inspection.directory_authority,
                candidates=candidates,
            )
            yield recovered, inspection
    except OSError as error:
        raise InvalidArgumentError(
            "exact recovery filesystem is unavailable"
        ) from error


def _recover_exact_staged_entries(
    paths: RuntimePaths,
    *,
    directory_authority: RuntimeDirectoryAuthority | None = None,
    candidates: tuple[tuple[PrivateStagedEntry, ExactCaptureMetadata], ...]
    | None = None,
) -> tuple[CapturedCorrection, ...]:
    """Resume every valid private exact-ready manifest without Inbox publication.

    Callers that expose recovery receipts preflight all discovery before this
    loop.  The fallback keeps this internal helper safe for direct callers.
    """
    recovered: list[CapturedCorrection] = []
    try:
        if candidates is None:
            candidates = _preflight_exact_recovery(paths, directory_authority)
        for entry, metadata in candidates:
            try:
                batch = capture_exact_staged_entry(
                    paths,
                    entry,
                    metadata=metadata,
                    directory_authority=directory_authority,
                )
            except _StagePayloadLeaseUnavailable:
                if not recovered:
                    raise
                # A later candidate can lose its lease after an earlier
                # commit. Its next invocation can inspect retained custody;
                # do not erase receipts already produced in this invocation.
                continue
            except InvalidArgumentError:
                # A candidate can become otherwise unrecoverable after
                # preflight. Its next invocation can inspect retained
                # custody; do not erase receipts already produced here.
                continue
            if len(batch.source_ids) != 1:
                continue
            recovered.append(
                CapturedCorrection(
                    capture_request_id=metadata.capture_request_id,
                    batch_id=batch.batch_id,
                    source_id=batch.source_ids[0],
                    lineage_id=metadata.target_lineage_id,
                    expected_head_id=metadata.expected_head_id,
                    captured_at=metadata.captured_at,
                )
            )
        return tuple(recovered)
    except OSError as error:
        raise InvalidArgumentError(
            "exact recovery filesystem is unavailable"
        ) from error


def _preflight_exact_recovery(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None,
) -> tuple[tuple[PrivateStagedEntry, ExactCaptureMetadata], ...]:
    """Normalize and discover every recovery candidate before capture commits."""
    _promote_exact_intent_temps(paths, directory_authority)
    _recover_exact_stage_intents(paths, directory_authority)
    _promote_exact_ready_temps(paths, directory_authority)
    _consume_owner_correction_handoffs(paths, directory_authority)
    _reclaim_orphaned_ordinary_stage_slots(paths, directory_authority)
    return _exact_recovery_candidates(paths, directory_authority)


def list_exact_recovery_issues(
    paths: RuntimePaths,
    *,
    cursor: str | None,
    limit: int,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> Page[CaptureRecoveryIssue]:
    """List bounded content-free issues for quarantined exact-ready artifacts."""
    _validate_recovery_issue_page_limit(limit)
    issues = _exact_recovery_issues(paths, directory_authority)
    return _recovery_issue_page(
        issues,
        store_id=load_runtime_identity(paths).store_id,
        cursor=cursor,
        limit=limit,
    )


def _validate_recovery_issue_page_limit(limit: int) -> None:
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_PAGE_SIZE
    ):
        raise InvalidArgumentError("recovery issue page limit is invalid")


def _recovery_issue_page(
    issues: list[CaptureRecoveryIssue],
    *,
    store_id: str,
    cursor: str | None,
    limit: int,
) -> Page[CaptureRecoveryIssue]:
    """Page one already-inspected, deterministically ordered issue snapshot."""
    snapshot = _recovery_issue_snapshot(issues)
    start = _recovery_issue_offset(
        cursor,
        store_id=store_id,
        snapshot=snapshot,
        total=len(issues),
    )
    visible = tuple(issues[start : start + limit])
    next_offset = start + len(visible)
    has_more = next_offset < len(issues)
    next_cursor = (
        _encode_cursor(
            store_id=store_id,
            operation=_RECOVERY_ISSUE_OPERATION,
            upper=len(issues),
            after=next_offset,
            snapshot=snapshot,
        )
        if has_more
        else None
    )
    return Page(items=visible, next_cursor=next_cursor, has_more=has_more)


def preserve_exact_correction_handoff(
    paths: RuntimePaths,
    *,
    source_bytes: bytes,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> bool:
    """Durably hand irreducibly ambiguous correction bytes to private recovery."""
    _validate_exact_metadata(metadata)
    if (
        not isinstance(source_bytes, bytes)
        or not 1 <= len(source_bytes) <= MAX_FILE_BYTES
        or hashlib.sha256(source_bytes).hexdigest() != metadata.payload_sha256
    ):
        raise InvalidArgumentError("correction recovery payload is invalid")
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            recovery_id = metadata.capture_request_id.removeprefix("cap_")
            payload_name = f".recovery-{recovery_id}.stage"
            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if _RECOVERY_MANIFEST.fullmatch(name) is None:
                    continue
                try:
                    existing = _load_private_recovery_manifest(runtime, name)
                except InvalidArgumentError:
                    continue
                if existing.kind != "owner_correction_handoff" or (
                    existing.capture_request_id != metadata.capture_request_id
                    and existing.batch_id != metadata.batch_id
                ):
                    continue
                if (
                    existing.capture_request_id != metadata.capture_request_id
                    or existing.batch_id != metadata.batch_id
                    or existing.byte_length != len(source_bytes)
                    or existing.sha256 != metadata.payload_sha256
                ):
                    return False
                if not _verified_private_recovery_payload(runtime, existing):
                    return False
                os.fsync(runtime.staging_descriptor)
                _checkpoint("correction.handoff_existing_directory_fsync")
                return True

            existing_payload = _stat_entry(runtime.staging_descriptor, payload_name)
            if existing_payload is not None:
                reservation = _PrivateRecoveryReservation(
                    recovery_id=recovery_id,
                    kind="owner_correction_handoff",
                    payload_name=payload_name,
                    entry_id=f"ent_{recovery_id}.stage",
                    byte_length=len(source_bytes),
                    sha256=metadata.payload_sha256,
                    expected_identity=_publication_identity(existing_payload),
                    capture_request_id=metadata.capture_request_id,
                    batch_id=metadata.batch_id,
                )
                if not _verified_private_recovery_payload(runtime, reservation):
                    return False
                if not _ensure_private_recovery_manifest(runtime, reservation):
                    return False
                return _verified_private_recovery_payload(runtime, reservation)

            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                payload_name,
                flags,
                0o600,
                dir_fd=runtime.staging_descriptor,
            )
            try:
                os.fchmod(descriptor, 0o600)
                remaining = memoryview(source_bytes)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError(errno.EIO, "recovery payload write failed")
                    remaining = remaining[written:]
                os.fsync(descriptor)
                _checkpoint("correction.handoff_payload_file_fsync")
                before = os.fstat(descriptor)
                path_before = _stat_entry(runtime.staging_descriptor, payload_name)
                if (
                    path_before is None
                    or _publication_identity(before)
                    != _publication_identity(path_before)
                    or before.st_size != len(source_bytes)
                    or _descriptor_sha256(descriptor) != metadata.payload_sha256
                ):
                    return False
                after = os.fstat(descriptor)
                path_after = _stat_entry(runtime.staging_descriptor, payload_name)
                if (
                    path_after is None
                    or _publication_identity(after) != _publication_identity(before)
                    or _publication_identity(path_after)
                    != _publication_identity(before)
                    or _publication_stability(after) != _publication_stability(before)
                    or _publication_stability(path_after)
                    != _publication_stability(before)
                ):
                    return False
                reservation = _PrivateRecoveryReservation(
                    recovery_id=recovery_id,
                    kind="owner_correction_handoff",
                    payload_name=payload_name,
                    entry_id=f"ent_{recovery_id}.stage",
                    byte_length=len(source_bytes),
                    sha256=metadata.payload_sha256,
                    expected_identity=_publication_identity(after),
                    capture_request_id=metadata.capture_request_id,
                    batch_id=metadata.batch_id,
                )
            finally:
                os.close(descriptor)
            os.fsync(runtime.staging_descriptor)
            _checkpoint("correction.handoff_payload_directory_fsync")
            if not _ensure_private_recovery_manifest(runtime, reservation):
                return False
            return _verified_private_recovery_payload(runtime, reservation)
    except OSError:
        return False


def owner_correction_display_name(capture_request_id: str) -> str:
    """The fixed display name every owner correction stages under."""
    if _CAPTURE_REQUEST_ID.fullmatch(capture_request_id) is None:
        raise InvalidArgumentError("correction capture request is invalid")
    return f"owner-correction-{capture_request_id.removeprefix('cap_')}.md"


_CORRECTION_ENVELOPE = re.compile(
    rb"\A---\n"
    rb"format: memory\.owner-correction\.v1\n"
    rb"store_id: (?P<store_id>[0-9a-f]{32})\n"
    rb"target_lineage_id: (?P<lineage>[^\n]{1,128})\n"
    rb"expected_head_id: (?P<head>[^\n]{1,128})\n"
    rb"recorded_at: (?P<recorded>[0-9TZ:+-]{20,40})\n"
    rb"---\n"
)


def _consume_owner_correction_handoffs(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    """Replay every provable owner-correction handoff back into custody.

    The handoff pair is the UI's last resort for an irreducibly ambiguous
    correction failure, and on its durability promise the UI drops its only
    retained copy of the owner's text. Replay keeps that promise: each pair
    whose payload verifies against its manifest and whose envelope this
    Store authored becomes an ordinary exact-ready entry -- the recovery
    currency the candidate pass already captures idempotently into the
    correction's own reserved batch -- and the pair is removed only once the
    correction is provably safe. A pair that cannot be proven stays exactly
    where it is, reported as custody debt.
    """
    try:
        for reservation in _owner_correction_handoff_reservations(
            paths,
            directory_authority,
        ):
            _replay_owner_correction_handoff(paths, reservation, directory_authority)
    except OSError as error:
        raise InvalidArgumentError(
            "correction handoff recovery is unavailable"
        ) from error


def _owner_correction_handoff_reservations(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None,
) -> tuple[_PrivateRecoveryReservation, ...]:
    """Load every valid handoff manifest without holding the root afterwards."""
    reservations: list[_PrivateRecoveryReservation] = []
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        _verify_runtime_root(runtime)
        for name in sorted(os.listdir(runtime.staging_descriptor)):
            match = _RECOVERY_MANIFEST.fullmatch(name)
            if match is None:
                continue
            if (
                _stat_entry(
                    runtime.staging_descriptor,
                    f".rollback-slot-{match.group(1)}.json",
                )
                is not None
            ):
                # A recorded rollback bundle owns this manifest name; its
                # members are opened only by the bound bundle inspection,
                # never by handoff discovery.
                continue
            try:
                reservation = _load_private_recovery_manifest(runtime, name)
            except InvalidArgumentError:
                continue
            if reservation.kind != "owner_correction_handoff":
                continue
            reservations.append(reservation)
    return tuple(reservations)


def _replay_owner_correction_handoff(
    paths: RuntimePaths,
    reservation: _PrivateRecoveryReservation,
    directory_authority: RuntimeDirectoryAuthority | None,
) -> None:
    """Stage one handoff as a ready entry, then retire the proven-safe pair.

    Every failure leaves the pair in place for the next pass: staging is
    performed with a fresh entry id through the same intent machinery the
    original submission used, so a crash mid-replay leaves exactly the
    residue ordinary intent recovery already normalizes. The payload is
    removed before the manifest, so a crash between the two leaves a
    remainder that still names the correction and its captured or ready
    proof rather than unaccountable bytes.
    """
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        _verify_runtime_root(runtime)
        payload_bytes = _read_verified_handoff_payload(runtime, reservation)
        metadata = (
            None
            if payload_bytes is None
            else _handoff_metadata(runtime, reservation, payload_bytes)
        )
        payload_present = (
            _stat_entry(runtime.staging_descriptor, reservation.payload_name)
            is not None
        )
        safe = _handoff_capture_exists(
            runtime, reservation
        ) or _matching_handoff_ready_exists(runtime, reservation)
    if not safe and (payload_bytes is None or metadata is None):
        # A payload-less remainder without a captured or ready proof, or a
        # payload this Store cannot prove it authored, is not replayable;
        # it stays reported rather than being guessed at.
        return
    if not safe:
        assert payload_bytes is not None and metadata is not None
        try:
            _stage_exact_entry_unchecked(
                paths,
                display_name=owner_correction_display_name(metadata.capture_request_id),
                exact_chunks=(payload_bytes,),
                payload_byte_length=len(payload_bytes),
                max_bytes=len(payload_bytes),
                metadata=metadata,
                directory_authority=directory_authority,
            )
        except InvalidArgumentError:
            # An ambiguous or refused staging leaves the durable pair for
            # the next pass; nothing has been removed yet.
            return
    if payload_present and payload_bytes is None:
        # The payload exists but cannot be verified against the manifest;
        # even with a safe copy elsewhere, unexplained bytes are never
        # removed.
        return
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        _verify_runtime_root(runtime)
        _remove_consumed_handoff(runtime, reservation)


def _read_verified_handoff_payload(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bytes | None:
    """Read the exact handoff bytes only while they prove the manifest."""
    if not _verified_private_recovery_payload(runtime, reservation):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(
            reservation.payload_name,
            flags,
            dir_fd=runtime.staging_descriptor,
        )
        before = os.fstat(descriptor)
        if before.st_size != reservation.byte_length:
            return None
        payload = bytearray()
        while chunk := os.read(descriptor, _STREAM_BYTES):
            payload.extend(chunk)
            if len(payload) > reservation.byte_length:
                return None
        after = os.fstat(descriptor)
        if (
            len(payload) != reservation.byte_length
            or hashlib.sha256(payload).hexdigest() != reservation.sha256
            or _publication_stability(before) != _publication_stability(after)
        ):
            return None
        return bytes(payload)
    except OSError:
        return None
    finally:
        if descriptor is not None:
            _close_descriptor_best_effort(descriptor)


def _handoff_metadata(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
    payload_bytes: bytes,
) -> ExactCaptureMetadata | None:
    """Rebuild the exact capture metadata the handoff's envelope binds.

    The manifest carries the reservation identity and digest; the lineage,
    expected head, and capture time live nowhere but the payload's own
    envelope. Sensitivity, authorship, origin, and the display name are the
    fixed owner-correction policy. The rebuilt metadata is proven by
    re-rendering the exact envelope prefix against this Store's identity, so
    a forged or foreign envelope reconstructs nothing.
    """
    if reservation.capture_request_id is None or reservation.batch_id is None:
        return None
    match = _CORRECTION_ENVELOPE.match(payload_bytes)
    if match is None:
        return None
    identity = load_runtime_identity(runtime.paths)
    try:
        store_id = match.group("store_id").decode("ascii")
        lineage = match.group("lineage").decode("utf-8")
        head = match.group("head").decode("utf-8")
        recorded = match.group("recorded").decode("ascii")
        captured_at = int(
            datetime.fromisoformat(recorded.replace("Z", "+00:00")).timestamp()
        )
    except UnicodeError, ValueError, OverflowError, OSError:
        return None
    if store_id != identity.store_id:
        return None
    metadata = ExactCaptureMetadata(
        capture_request_id=reservation.capture_request_id,
        batch_id=reservation.batch_id,
        captured_at=captured_at,
        target_lineage_id=lineage,
        expected_head_id=head,
        payload_sha256=reservation.sha256,
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    try:
        _validate_exact_metadata(metadata)
    except InvalidArgumentError:
        return None
    if not _exact_correction_envelope_matches(
        payload_bytes,
        store_id=identity.store_id,
        metadata=metadata,
    ):
        return None
    return metadata


def _handoff_capture_exists(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    """Prove the handoff's exact bytes already live in its reserved batch."""
    identity = load_runtime_identity(runtime.paths)
    connection = open_database(runtime.paths, load_master_key(identity), read_only=True)
    try:
        row = connection.execute(
            "SELECT b.sha256, b.byte_length FROM inbox_batches AS ib "
            "JOIN sources AS s ON s.batch_id = ib.batch_id "
            "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            "WHERE ib.capture_request_id = ? AND ib.batch_id = ?",
            (reservation.capture_request_id, reservation.batch_id),
        ).fetchone()
    finally:
        connection.close()
    return row is not None and (str(row[0]), int(row[1])) == (
        reservation.sha256,
        reservation.byte_length,
    )


def _matching_handoff_ready_exists(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    """Prove a bound ready entry already carries the handoff's exact bytes."""
    for name in sorted(os.listdir(runtime.staging_descriptor)):
        if not name.endswith(_EXACT_READY_SUFFIX):
            continue
        entry_id = name[: -len(_EXACT_READY_SUFFIX)]
        try:
            entry, exact = _load_exact_ready(runtime, entry_id)
        except InvalidArgumentError:
            continue
        if (
            exact.capture_request_id == reservation.capture_request_id
            and exact.batch_id == reservation.batch_id
            and exact.payload_sha256 == reservation.sha256
            and entry.byte_length == reservation.byte_length
        ):
            return True
    return False


def _remove_consumed_handoff(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> None:
    """Retire one proven-safe pair, payload first and manifest last."""
    manifest_name = f".recovery-{reservation.recovery_id}.json"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for name, verify_digest in (
        (reservation.payload_name, True),
        (manifest_name, False),
    ):
        if _stat_entry(runtime.staging_descriptor, name) is None:
            continue
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, dir_fd=runtime.staging_descriptor)
            metadata = os.fstat(descriptor)
            if verify_digest and (
                metadata.st_size != reservation.byte_length
                or _descriptor_sha256(descriptor) != reservation.sha256
            ):
                # Only the exact accounted bytes are ever removed.
                return
            if not _unlink_bound_staging_entry(
                runtime,
                name,
                descriptor,
                _publication_identity(metadata),
            ):
                return
        except OSError:
            return
        finally:
            if descriptor is not None:
                _close_descriptor_best_effort(descriptor)


def _verified_private_recovery_payload(
    runtime: _RuntimeRoot,
    reservation: _PrivateRecoveryReservation,
) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(
            reservation.payload_name,
            flags,
            dir_fd=runtime.staging_descriptor,
        )
        before = os.fstat(descriptor)
        path_before = _stat_entry(
            runtime.staging_descriptor,
            reservation.payload_name,
        )
        digest = _descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        path_after = _stat_entry(
            runtime.staging_descriptor,
            reservation.payload_name,
        )
        staging_device = _staging_device(runtime)
        return (
            path_before is not None
            and path_after is not None
            and _reboot_stable_identity_matches(
                before,
                reservation.expected_identity,
                staging_device,
            )
            and _reboot_stable_identity_matches(
                after,
                reservation.expected_identity,
                staging_device,
            )
            and _reboot_stable_identity_matches(
                path_before,
                reservation.expected_identity,
                staging_device,
            )
            and _reboot_stable_identity_matches(
                path_after,
                reservation.expected_identity,
                staging_device,
            )
            and _publication_stability(before) == _publication_stability(after)
            and _publication_stability(path_before)
            == _publication_stability(path_after)
            and digest == reservation.sha256
        )
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reboot_stable_identity_matches(
    metadata: os.stat_result,
    expected_identity: tuple[int, ...],
    staging_device: int,
) -> bool:
    """Match one persisted publication identity across a reboot.

    The persisted tuple's leading element is the device number the writer's
    boot assigned; the kernel reassigns it at every boot, so comparing it
    made every retained payload unverifiable -- and every retained bundle
    unretirable -- after any reboot. The payload must instead live on the
    staging directory's current device, which preserves the cross-volume
    defense the recorded device provided within its own boot.
    """
    return (
        metadata.st_dev == staging_device
        and _publication_identity(metadata)[1:] == tuple(expected_identity)[1:]
    )


def exact_capture_custody_outcome(
    paths: RuntimePaths,
    *,
    display_name: str,
    byte_length: int,
    metadata: ExactCaptureMetadata,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> Literal["proven_empty", "durable", "ambiguous"]:
    """Classify one failed exact capture without exposing or copying its bytes."""
    probe = PrivateStagedEntry(
        entry_id="ent_00000000000000000000000000000000.stage",
        display_name=display_name,
        byte_length=byte_length,
        sha256=metadata.payload_sha256,
    )
    _validate_private_entry(probe)
    _validate_exact_metadata(metadata)
    try:
        _promote_exact_intent_temps(paths, directory_authority)
        _recover_exact_stage_intents(paths, directory_authority)
        _promote_exact_ready_temps(paths, directory_authority)
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            try:
                committed = _load_exact_batch(runtime, probe, metadata)
            except InvalidArgumentError:
                return "ambiguous"
            if committed is not None:
                return "durable"

            relevant = False
            unresolved_exact_artifact = False
            claims: list[_Claim] = []
            for artifact in _claim_artifacts(runtime):
                try:
                    claim = _load_claim(
                        runtime,
                        artifact.path,
                        batch_id=artifact.batch_id,
                        require_files=False,
                    )
                except InvalidArgumentError:
                    if artifact.batch_id == metadata.batch_id:
                        return "ambiguous"
                    continue
                exact = claim.exact_metadata
                if exact is None or (
                    claim.batch_id != metadata.batch_id
                    and exact.capture_request_id != metadata.capture_request_id
                ):
                    continue
                relevant = True
                if exact != metadata or len(claim.entries) != 1:
                    return "ambiguous"
                claims.append(claim)

            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if not name.endswith(_EXACT_READY_SUFFIX):
                    continue
                entry_id = name[: -len(_EXACT_READY_SUFFIX)]
                try:
                    entry, exact = _load_exact_ready(
                        runtime,
                        entry_id,
                        require_file=False,
                    )
                except InvalidArgumentError:
                    unresolved_exact_artifact = True
                    continue
                if (
                    exact.capture_request_id != metadata.capture_request_id
                    and exact.batch_id != metadata.batch_id
                ):
                    continue
                relevant = True
                if (
                    exact != metadata
                    or entry.display_name != display_name
                    or entry.byte_length != byte_length
                    or entry.sha256 != metadata.payload_sha256
                ):
                    return "ambiguous"
                try:
                    bound_entry, bound_exact = _load_exact_ready(runtime, entry_id)
                except InvalidArgumentError:
                    pass
                else:
                    if bound_entry == entry and bound_exact == metadata:
                        return "durable"
                if _stat_entry(runtime.staging_descriptor, entry.entry_id) is not None:
                    return "ambiguous"
                if _exact_candidate_has_custody(
                    runtime,
                    entry,
                    metadata,
                    tuple(claims),
                ):
                    return "durable"

            for claim in claims:
                visible = claim.entries[0]
                entry = PrivateStagedEntry(
                    entry_id=visible.entry_id,
                    display_name=visible.name,
                    byte_length=visible.size,
                    sha256=visible.sha256,
                )
                if (
                    entry.display_name != display_name
                    or entry.byte_length != byte_length
                    or entry.sha256 != metadata.payload_sha256
                ):
                    return "ambiguous"
                if _exact_candidate_has_custody(
                    runtime,
                    entry,
                    metadata,
                    (claim,),
                ):
                    return "durable"
                return "ambiguous"

            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if not name.endswith(_EXACT_INTENT_SUFFIX):
                    continue
                entry_id = name[: -len(_EXACT_INTENT_SUFFIX)]
                try:
                    intent = _load_exact_intent(runtime, entry_id)
                except InvalidArgumentError:
                    unresolved_exact_artifact = True
                    continue
                exact = intent.metadata
                if (
                    exact.capture_request_id != metadata.capture_request_id
                    and exact.batch_id != metadata.batch_id
                ):
                    continue
                relevant = True
                if (
                    exact != metadata
                    or intent.display_name != display_name
                    or intent.payload_byte_length != byte_length
                ):
                    return "ambiguous"
                try:
                    _read_exact_intent_entry(runtime, intent)
                except InvalidArgumentError:
                    return "ambiguous"
                return "durable"
            if any(
                _EXACT_READY_TEMP.fullmatch(name) is not None
                or _EXACT_INTENT_TEMP.fullmatch(name) is not None
                or _RECOVERY_PAYLOAD.fullmatch(name) is not None
                or _RECOVERY_MANIFEST.fullmatch(name) is not None
                or _RECOVERY_TEMP.fullmatch(name) is not None
                for name in os.listdir(runtime.staging_descriptor)
            ):
                unresolved_exact_artifact = True
            return (
                "ambiguous" if relevant or unresolved_exact_artifact else "proven_empty"
            )
    except _StagePayloadLeaseUnavailable:
        raise
    except InvalidArgumentError, OSError:
        return "ambiguous"


def _validate_stage_arguments(
    display_name: str,
    chunks: Iterable[bytes],
    max_bytes: int,
) -> None:
    if (
        not isinstance(display_name, str)
        or not _safe_entry_name(display_name)
        or display_name.startswith(".")
        or len(display_name.encode("utf-8")) > 255
    ):
        raise InvalidArgumentError("staged Inbox filename is invalid")
    if not isinstance(chunks, Iterable):
        raise InvalidArgumentError("staged Inbox stream is invalid")
    if isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_FILE_BYTES:
        raise InvalidArgumentError("staged Inbox byte limit is invalid")


def _validate_private_entry(entry: PrivateStagedEntry) -> None:
    if (
        not isinstance(entry, PrivateStagedEntry)
        or not isinstance(entry.entry_id, str)
        or _ENTRY_ID.fullmatch(entry.entry_id) is None
        or not isinstance(entry.display_name, str)
        or not _safe_entry_name(entry.display_name)
        or entry.display_name.startswith(".")
        or len(entry.display_name.encode("utf-8")) > 255
        or isinstance(entry.byte_length, bool)
        or not isinstance(entry.byte_length, int)
        or not 0 <= entry.byte_length <= MAX_FILE_BYTES
        or not isinstance(entry.sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", entry.sha256) is None
    ):
        raise InvalidArgumentError("private staged entry is invalid")


def _validate_exact_metadata(metadata: ExactCaptureMetadata) -> None:
    if (
        not isinstance(metadata, ExactCaptureMetadata)
        or not isinstance(metadata.capture_request_id, str)
        or _CAPTURE_REQUEST_ID.fullmatch(metadata.capture_request_id) is None
        or not isinstance(metadata.batch_id, str)
        or _BATCH_ID.fullmatch(metadata.batch_id) is None
        or not isinstance(metadata.captured_at, int)
        or isinstance(metadata.captured_at, bool)
        or metadata.captured_at < 0
        or not isinstance(metadata.target_lineage_id, str)
        or not re.fullmatch(r"lin_[0-9a-f]{32}", metadata.target_lineage_id)
        or not isinstance(metadata.expected_head_id, str)
        or not re.fullmatch(r"mem_[0-9a-f]{32}", metadata.expected_head_id)
        or not isinstance(metadata.payload_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", metadata.payload_sha256) is None
        or metadata.source_origin is not SourceCaptureOrigin.OWNER_CORRECTION
        or metadata.authorship is not Authorship.OWNER
        or metadata.sensitivity is not Sensitivity.RESTRICTED
    ):
        raise InvalidArgumentError("exact capture metadata is invalid")


def _verify_private_file(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
) -> os.stat_result:
    metadata = _stat_entry(runtime.staging_descriptor, entry.entry_id)
    if (
        metadata is None
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != entry.byte_length
    ):
        raise InvalidArgumentError("private staged entry custody is invalid")
    return metadata


def _write_exact_intent(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
    *,
    replace: bool = False,
) -> None:
    """Publish one strict reservation or inode-bound exact-intent state."""
    if replace:
        current = _load_exact_intent(runtime, intent.entry_id)
        if (
            current.phase != "reserved"
            or intent.phase != "payload_bound"
            or not _same_exact_intent_reservation(current, intent)
        ):
            raise InvalidArgumentError("exact staging intent transition is invalid")
    payload = {
        "authorship": intent.metadata.authorship.value,
        "batch_id": intent.metadata.batch_id,
        "byte_length": intent.payload_byte_length,
        "capture_request_id": intent.metadata.capture_request_id,
        "captured_at": intent.metadata.captured_at,
        "display_name": intent.display_name,
        "entry_id": intent.entry_id,
        "expected_head_id": intent.metadata.expected_head_id,
        "format": _EXACT_INTENT_FORMAT,
        "max_bytes": intent.max_bytes,
        "payload_device": intent.payload_device,
        "payload_inode": intent.payload_inode,
        "payload_sha256": intent.metadata.payload_sha256,
        "phase": intent.phase,
        "sensitivity": intent.metadata.sensitivity.value,
        "source_origin": intent.metadata.source_origin.value,
        "target_lineage_id": intent.metadata.target_lineage_id,
    }
    stage = "bound" if replace else "intent"
    temporary = f".intent-{intent.entry_id}-{secrets.token_hex(16)}.tmp"
    try:
        _publish_manifest_bytes(
            _encoded_manifest(payload),
            directory_descriptor=runtime.staging_descriptor,
            temporary_name=temporary,
            final_name=intent.entry_id + _EXACT_INTENT_SUFFIX,
            checkpoints=(
                f"exact.{stage}_manifest_file_fsync",
                f"exact.{stage}_manifest_publish",
                f"exact.{stage}_manifest_directory_fsync",
            ),
            write_failure="exact intent write failed",
            replace=replace,
        )
        _verify_runtime_root(runtime)
    except OSError as error:
        try:
            os.unlink(temporary, dir_fd=runtime.staging_descriptor)
        except FileNotFoundError:
            pass
        raise InvalidArgumentError("exact staging intent is unavailable") from error


def _same_exact_intent_reservation(
    left: _ExactStageIntent,
    right: _ExactStageIntent,
) -> bool:
    return (
        left.entry_id == right.entry_id
        and left.display_name == right.display_name
        and left.max_bytes == right.max_bytes
        and left.payload_byte_length == right.payload_byte_length
        and left.metadata == right.metadata
    )


def _load_exact_intent_manifest(
    runtime: _RuntimeRoot,
    name: str,
    *,
    expected_entry_id: str | None,
) -> _ExactStageIntent:
    encoded = _read_private_manifest(
        runtime.staging_descriptor,
        name,
        max_bytes=MAX_MANIFEST_BYTES,
        label="exact staging intent",
    )
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"))
        required = {
            "authorship",
            "batch_id",
            "byte_length",
            "capture_request_id",
            "captured_at",
            "display_name",
            "entry_id",
            "expected_head_id",
            "format",
            "max_bytes",
            "payload_device",
            "payload_inode",
            "payload_sha256",
            "phase",
            "sensitivity",
            "source_origin",
            "target_lineage_id",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError
        if raw["format"] != _EXACT_INTENT_FORMAT:
            raise ValueError
        if any(
            not isinstance(raw[field], str)
            for field in required
            - {
                "byte_length",
                "captured_at",
                "format",
                "max_bytes",
                "payload_device",
                "payload_inode",
            }
        ):
            raise ValueError
        entry_id = raw["entry_id"]
        if _ENTRY_ID.fullmatch(entry_id) is None or (
            expected_entry_id is not None and entry_id != expected_entry_id
        ):
            raise ValueError
        exact = ExactCaptureMetadata(
            capture_request_id=raw["capture_request_id"],
            batch_id=raw["batch_id"],
            captured_at=raw["captured_at"],
            target_lineage_id=raw["target_lineage_id"],
            expected_head_id=raw["expected_head_id"],
            payload_sha256=raw["payload_sha256"],
            source_origin=SourceCaptureOrigin(raw["source_origin"]),
            authorship=Authorship(raw["authorship"]),
            sensitivity=Sensitivity(raw["sensitivity"]),
        )
        intent = _ExactStageIntent(
            entry_id=entry_id,
            display_name=raw["display_name"],
            max_bytes=raw["max_bytes"],
            payload_byte_length=raw["byte_length"],
            phase=raw["phase"],
            payload_device=raw["payload_device"],
            payload_inode=raw["payload_inode"],
            metadata=exact,
        )
        _validate_stage_arguments(intent.display_name, (), intent.max_bytes)
        _validate_exact_metadata(intent.metadata)
        if (
            not isinstance(intent.payload_byte_length, int)
            or isinstance(intent.payload_byte_length, bool)
            or not 1 <= intent.payload_byte_length <= intent.max_bytes
            or intent.phase not in {"reserved", "payload_bound"}
        ):
            raise ValueError
        if intent.phase == "reserved":
            if intent.payload_device is not None or intent.payload_inode is not None:
                raise ValueError
        elif (
            not isinstance(intent.payload_device, int)
            or isinstance(intent.payload_device, bool)
            or intent.payload_device < 0
            or not isinstance(intent.payload_inode, int)
            or isinstance(intent.payload_inode, bool)
            or intent.payload_inode < 1
        ):
            raise ValueError
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise InvalidArgumentError("exact staging intent is invalid") from error
    return intent


def _load_exact_intent(runtime: _RuntimeRoot, entry_id: str) -> _ExactStageIntent:
    if _ENTRY_ID.fullmatch(entry_id) is None:
        raise InvalidArgumentError("exact staging intent identity is invalid")
    return _load_exact_intent_manifest(
        runtime,
        entry_id + _EXACT_INTENT_SUFFIX,
        expected_entry_id=entry_id,
    )


def _mapped_exact_intent_entry_id(temporary_name: str) -> str | None:
    """Return the payload identity carried by a new-format intent temporary."""
    matched = _EXACT_INTENT_TEMP.fullmatch(temporary_name)
    if matched is None:
        return None
    return matched.group("entry_id")


@contextmanager
def _exact_stage_payload_lease(
    runtime: _RuntimeRoot,
    *,
    entry_id: str,
    max_bytes: int,
    expected_identity: tuple[int, int] | None,
) -> Iterator[int | None]:
    """Lease one exact payload inode, or identify a still-live publisher.

    The advisory lock is attempted before trusting size or timestamps. A live
    publisher may be changing both while this process opens the name, and that
    is precisely the state the lease is meant to distinguish from crash
    residue. A no-follow precheck classifies proven structural invalidity so an
    open failure remains an operational lease failure. Once the lock succeeds,
    descriptor and pathname are identity-bound and stable for the recovery
    action that owns this context.
    """
    if _ENTRY_ID.fullmatch(entry_id) is None or max_bytes < 1:
        raise InvalidArgumentError("exact staged payload identity is invalid")
    try:
        path_before = _stat_entry(runtime.staging_descriptor, entry_id)
    except OSError as error:
        raise _StagePayloadLeaseUnavailable(
            "exact staged payload lease is unavailable"
        ) from error
    if path_before is None:
        yield None
        return
    if (
        not stat.S_ISREG(path_before.st_mode)
        or path_before.st_uid != os.geteuid()
        or path_before.st_nlink != 1
        or stat.S_IMODE(path_before.st_mode) != 0o600
        or (
            expected_identity is not None
            and (path_before.st_dev, path_before.st_ino) != expected_identity
        )
    ):
        raise InvalidArgumentError("exact staged payload custody is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(
            entry_id,
            flags,
            dir_fd=runtime.staging_descriptor,
        )
    except FileNotFoundError:
        yield None
        return
    except OSError as error:
        raise _StagePayloadLeaseUnavailable(
            "exact staged payload lease is unavailable"
        ) from error
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise _ExactStageLeaseBusy from error
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise _ExactStageLeaseBusy from error
            raise _StagePayloadLeaseUnavailable(
                "exact staged payload lease failed"
            ) from error
        try:
            opened = os.fstat(descriptor)
            path = _stat_entry(runtime.staging_descriptor, entry_id)
        except OSError as error:
            raise _StagePayloadLeaseUnavailable(
                "exact staged payload lease is unavailable"
            ) from error
        if (
            path is None
            or _publication_identity(opened) != _publication_identity(path)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 0 <= opened.st_size <= max_bytes
            or (
                expected_identity is not None
                and (opened.st_dev, opened.st_ino) != expected_identity
            )
        ):
            raise InvalidArgumentError("exact staged payload custody is invalid")
        yield descriptor
    finally:
        _close_descriptor_best_effort(descriptor)


@contextmanager
def _exact_intent_payload_lease(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
) -> Iterator[int | None]:
    # The persisted payload_device is the writer's boot-assigned number; the
    # lease binds the inode on the staging directory's current device instead,
    # so a crash-left intent stays resumable across a reboot.
    expected_identity = (
        None
        if intent.payload_device is None or intent.payload_inode is None
        else (_staging_device(runtime), intent.payload_inode)
    )
    with _exact_stage_payload_lease(
        runtime,
        entry_id=intent.entry_id,
        max_bytes=intent.max_bytes,
        expected_identity=expected_identity,
    ) as descriptor:
        yield descriptor


def _read_exact_intent_entry(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
    *,
    descriptor: int | None = None,
    sync_complete: bool = True,
) -> PrivateStagedEntry:
    if (
        intent.phase != "payload_bound"
        or intent.payload_device is None
        or intent.payload_inode is None
    ):
        raise InvalidArgumentError("exact staging intent is not inode-bound")
    path_before = _stat_entry(runtime.staging_descriptor, intent.entry_id)
    if (
        path_before is None
        or stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISREG(path_before.st_mode)
        or path_before.st_uid != os.geteuid()
        or path_before.st_nlink != 1
        or stat.S_IMODE(path_before.st_mode) != 0o600
        or (path_before.st_dev, path_before.st_ino)
        != (_staging_device(runtime), intent.payload_inode)
        or path_before.st_size > intent.max_bytes
    ):
        raise InvalidArgumentError("exact staging intent custody is invalid")
    owns_descriptor = descriptor is None
    if descriptor is None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                intent.entry_id,
                flags,
                dir_fd=runtime.staging_descriptor,
            )
        except OSError as error:
            raise InvalidArgumentError(
                "exact staging intent custody is unavailable"
            ) from error
    try:
        before = os.fstat(descriptor)
        if _publication_identity(before) != _publication_identity(path_before) or (
            before.st_dev,
            before.st_ino,
        ) != (_staging_device(runtime), intent.payload_inode):
            raise InvalidArgumentError("exact staging intent custody is invalid")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, _STREAM_BYTES):
            total += len(chunk)
            if total > intent.max_bytes:
                raise InvalidArgumentError("exact staging intent custody is invalid")
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, intent.entry_id)
        if (
            path_after is None
            or _publication_identity(after) != _publication_identity(before)
            or _publication_identity(path_after) != _publication_identity(before)
            or _publication_stability(after) != _publication_stability(before)
            or _publication_stability(path_after) != _publication_stability(before)
        ):
            raise InvalidArgumentError("exact staging intent custody changed")
        if total < intent.payload_byte_length:
            raise _ExactIncompleteError("exact staging intent payload is incomplete")
        if (
            total != intent.payload_byte_length
            or digest.hexdigest() != intent.metadata.payload_sha256
        ):
            raise InvalidArgumentError("exact staging intent payload is mismatched")
        if sync_complete:
            _checkpoint("exact.recovery_payload_before_file_fsync")
            os.fsync(descriptor)
            _checkpoint("exact.recovery_payload_file_fsync")
            synced = os.fstat(descriptor)
            path_synced = _stat_entry(runtime.staging_descriptor, intent.entry_id)
            if (
                path_synced is None
                or _publication_stability(synced) != _publication_stability(after)
                or _publication_stability(path_synced) != _publication_stability(after)
            ):
                raise InvalidArgumentError("exact staging intent custody changed")
    finally:
        if owns_descriptor:
            os.close(descriptor)
    if sync_complete:
        os.fsync(runtime.staging_descriptor)
        _checkpoint("exact.recovery_payload_directory_fsync")
        _verify_runtime_root(runtime)
    return PrivateStagedEntry(
        entry_id=intent.entry_id,
        display_name=intent.display_name,
        byte_length=intent.payload_byte_length,
        sha256=intent.metadata.payload_sha256,
    )


def _cleanup_exact_intent(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
) -> None:
    loaded = _load_exact_intent(runtime, intent.entry_id)
    if loaded != intent:
        raise InvalidArgumentError("exact staging intent is mismatched")
    os.unlink(
        intent.entry_id + _EXACT_INTENT_SUFFIX,
        dir_fd=runtime.staging_descriptor,
    )
    os.fsync(runtime.staging_descriptor)
    _checkpoint("exact.intent_cleanup_directory_fsync")
    _verify_runtime_root(runtime)


def _rollback_exact_intent(
    paths: RuntimePaths,
    intent: _ExactStageIntent,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    """Remove only a missing or provably bound incomplete exact intention."""
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            loaded = _load_exact_intent(runtime, intent.entry_id)
            if not _same_exact_intent_reservation(loaded, intent):
                return
            metadata = _stat_entry(runtime.staging_descriptor, intent.entry_id)
            if metadata is None:
                _cleanup_exact_intent(runtime, loaded)
                return
            try:
                with _exact_intent_payload_lease(runtime, loaded) as descriptor:
                    if descriptor is None or loaded.phase != "payload_bound":
                        return
                    try:
                        _read_exact_intent_entry(
                            runtime,
                            loaded,
                            descriptor=descriptor,
                        )
                    except _ExactIncompleteError:
                        _quarantine_bound_incomplete_exact_payload(
                            runtime,
                            loaded,
                            descriptor=descriptor,
                        )
            except _StagePayloadLeaseUnavailable:
                raise
            except _ExactStageLeaseBusy, InvalidArgumentError:
                return
    except _StagePayloadLeaseUnavailable:
        raise
    except InvalidArgumentError, OSError:
        return


def _quarantine_bound_incomplete_exact_payload(
    runtime: _RuntimeRoot,
    intent: _ExactStageIntent,
    *,
    descriptor: int,
) -> _PublicationRollbackOutcome:
    """Move a bound prefix aside without any identity-unsafe final unlink."""
    path_before = _stat_entry(runtime.staging_descriptor, intent.entry_id)
    if (
        path_before is None
        or intent.payload_device is None
        or intent.payload_inode is None
        or (path_before.st_dev, path_before.st_ino)
        != (_staging_device(runtime), intent.payload_inode)
        or not stat.S_ISREG(path_before.st_mode)
        or path_before.st_uid != os.geteuid()
        or path_before.st_nlink != 1
        or stat.S_IMODE(path_before.st_mode) != 0o600
        or not 0 <= path_before.st_size < intent.payload_byte_length
    ):
        return _PublicationRollbackOutcome("uncertain", False, False)
    marker_durable = False
    try:
        before = os.fstat(descriptor)
        prefix_sha256 = _descriptor_sha256(descriptor)
        after = os.fstat(descriptor)
        path_after = _stat_entry(runtime.staging_descriptor, intent.entry_id)
        expected_identity = _publication_identity(before)
        if (
            path_after is None
            or expected_identity != _publication_identity(path_before)
            or expected_identity != _publication_identity(after)
            or expected_identity != _publication_identity(path_after)
            or _publication_stability(before) != _publication_stability(after)
            or _publication_stability(before) != _publication_stability(path_after)
        ):
            return _PublicationRollbackOutcome("uncertain", False, False)
        _checkpoint("exact.incomplete_before_quarantine_rename")
        reservation = _move_to_fresh_private_recovery(
            runtime,
            source_name=intent.entry_id,
            source_descriptor=runtime.staging_descriptor,
            kind="exact_incomplete",
            entry_id=intent.entry_id,
            byte_length=before.st_size,
            sha256=prefix_sha256,
            expected_identity=expected_identity,
        )
        if reservation is None:
            barriers_durable = _sync_rollback_directories(runtime)
            return _PublicationRollbackOutcome(
                "uncertain",
                False,
                barriers_durable,
            )
        _checkpoint("exact.incomplete_quarantine_rename")
        captured_expected = _recovery_payload_matches_descriptor(
            runtime,
            descriptor,
            expected_identity,
            prefix_sha256,
            reservation,
        )
        if captured_expected:
            marker_durable = _ensure_private_recovery_manifest(runtime, reservation)
        else:
            _restore_quarantined_replacement(
                runtime,
                reservation.payload_name,
                intent.entry_id,
                destination_descriptor=runtime.staging_descriptor,
            )
        barriers_durable = _sync_rollback_directories(runtime)
        return _PublicationRollbackOutcome(
            "quarantined" if captured_expected else "replacement_preserved",
            marker_durable,
            barriers_durable,
        )
    except InvalidArgumentError, OSError:
        return _PublicationRollbackOutcome("uncertain", marker_durable, False)


def _promote_exact_intent_temps(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            changed = False
            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if _EXACT_INTENT_TEMP.fullmatch(name) is None:
                    continue
                mapped_entry_id = _mapped_exact_intent_entry_id(name)
                if mapped_entry_id is not None:
                    try:
                        with _exact_stage_payload_lease(
                            runtime,
                            entry_id=mapped_entry_id,
                            max_bytes=MAX_FILE_BYTES,
                            expected_identity=None,
                        ):
                            pass
                    except _ExactStageLeaseBusy:
                        continue
                    except _StagePayloadLeaseUnavailable:
                        raise
                    except InvalidArgumentError:
                        continue
                try:
                    intent = _load_exact_intent_manifest(
                        runtime,
                        name,
                        expected_entry_id=None,
                    )
                except InvalidArgumentError:
                    continue
                if mapped_entry_id is not None and intent.entry_id != mapped_entry_id:
                    continue
                try:
                    with _exact_intent_payload_lease(runtime, intent):
                        final_name = intent.entry_id + _EXACT_INTENT_SUFFIX
                        if _stat_entry(runtime.staging_descriptor, final_name) is None:
                            _rename_no_replace(
                                name,
                                final_name,
                                source_descriptor=runtime.staging_descriptor,
                                destination_descriptor=runtime.staging_descriptor,
                            )
                            changed = True
                            continue
                        current = _load_exact_intent(runtime, intent.entry_id)
                        if current == intent:
                            _unlink_staging_name(runtime, name)
                            changed = True
                            continue
                        payload = _stat_entry(
                            runtime.staging_descriptor,
                            intent.entry_id,
                        )
                        if (
                            current.phase == "reserved"
                            and intent.phase == "payload_bound"
                            and _same_exact_intent_reservation(current, intent)
                            and payload is not None
                            and intent.payload_device is not None
                            and (payload.st_dev, payload.st_ino)
                            == (_staging_device(runtime), intent.payload_inode)
                            and stat.S_ISREG(payload.st_mode)
                            and payload.st_uid == os.geteuid()
                            and payload.st_nlink == 1
                            and stat.S_IMODE(payload.st_mode) == 0o600
                        ):
                            os.rename(
                                name,
                                final_name,
                                src_dir_fd=runtime.staging_descriptor,
                                dst_dir_fd=runtime.staging_descriptor,
                            )
                            changed = True
                except _StagePayloadLeaseUnavailable:
                    raise
                except _ExactStageLeaseBusy, InvalidArgumentError:
                    continue
            if changed:
                os.fsync(runtime.staging_descriptor)
                _checkpoint("exact.intent_recovery_directory_fsync")
            _verify_runtime_root(runtime)
    except OSError as error:
        raise InvalidArgumentError("exact staging intent is unavailable") from error


def _recover_exact_stage_intents(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    """Promote complete intended payloads or prove and perform exact rollback."""
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if not name.endswith(_EXACT_INTENT_SUFFIX):
                    continue
                entry_id = name[: -len(_EXACT_INTENT_SUFFIX)]
                try:
                    intent = _load_exact_intent(runtime, entry_id)
                except InvalidArgumentError:
                    continue
                if _stat_entry(runtime.staging_descriptor, entry_id) is None:
                    if intent.phase == "reserved":
                        _cleanup_exact_intent(runtime, intent)
                    continue
                try:
                    with _exact_intent_payload_lease(runtime, intent) as descriptor:
                        if descriptor is None:
                            continue
                        ready_name = entry_id + _EXACT_READY_SUFFIX
                        if (
                            _stat_entry(runtime.staging_descriptor, ready_name)
                            is not None
                        ):
                            ready_entry, ready_exact = _load_exact_ready(
                                runtime,
                                entry_id,
                            )
                            intended_entry = _read_exact_intent_entry(
                                runtime,
                                intent,
                                descriptor=descriptor,
                            )
                            if (
                                ready_entry == intended_entry
                                and ready_exact == intent.metadata
                            ):
                                _cleanup_exact_intent(runtime, intent)
                            continue
                        if intent.phase == "reserved":
                            # The held lease is the abandonment proof: a live
                            # uploader keeps the per-inode flock and the
                            # kernel drops it with a dead process -- the same
                            # proof ordinary-slot reclamation trusts. A
                            # reserved-phase writer has streamed no byte, so
                            # a zero-byte slot carries nothing of the owner's
                            # and leaving the pair turned one crash into a
                            # permanent quarantine of every later owner
                            # correction. A nonempty slot under a reserved
                            # intent is anomalous and stays reported.
                            if os.fstat(descriptor).st_size == 0:
                                _cleanup_exact_intent(runtime, intent)
                                _reclaim_bound_ordinary_stage_slot(
                                    runtime,
                                    entry_id,
                                    descriptor,
                                )
                            continue
                        if intent.phase != "payload_bound":
                            continue
                        try:
                            entry = _read_exact_intent_entry(
                                runtime,
                                intent,
                                descriptor=descriptor,
                            )
                        except _ExactIncompleteError:
                            _quarantine_bound_incomplete_exact_payload(
                                runtime,
                                intent,
                                descriptor=descriptor,
                            )
                            continue
                        _write_exact_ready(runtime, entry, intent.metadata)
                        _cleanup_exact_intent(runtime, intent)
                except _ExactStageLeaseBusy:
                    continue
                except _StagePayloadLeaseUnavailable:
                    raise
                except InvalidArgumentError:
                    continue
            _verify_runtime_root(runtime)
    except OSError as error:
        raise InvalidArgumentError("exact staging intent is unavailable") from error


def _write_exact_ready(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    metadata: ExactCaptureMetadata,
) -> None:
    private_metadata = _verify_private_file(runtime, entry)
    intent = _load_exact_intent(runtime, entry.entry_id)
    if (
        intent.phase != "payload_bound"
        or intent.metadata != metadata
        or intent.display_name != entry.display_name
        or intent.payload_byte_length != entry.byte_length
        or (private_metadata.st_dev, private_metadata.st_ino)
        != (_staging_device(runtime), intent.payload_inode)
    ):
        raise InvalidArgumentError("exact ready payload binding is invalid")
    payload = {
        "authorship": metadata.authorship.value,
        "batch_id": metadata.batch_id,
        "byte_length": entry.byte_length,
        "capture_request_id": metadata.capture_request_id,
        "captured_at": metadata.captured_at,
        "display_name": entry.display_name,
        "entry_id": entry.entry_id,
        "expected_head_id": metadata.expected_head_id,
        "format": _EXACT_READY_FORMAT,
        "payload_device": private_metadata.st_dev,
        "payload_inode": private_metadata.st_ino,
        "payload_sha256": metadata.payload_sha256,
        "sensitivity": metadata.sensitivity.value,
        "source_origin": metadata.source_origin.value,
        "target_lineage_id": metadata.target_lineage_id,
    }
    temporary = f".ready-{secrets.token_hex(16)}.tmp"
    try:
        _publish_manifest_bytes(
            _encoded_manifest(payload),
            directory_descriptor=runtime.staging_descriptor,
            temporary_name=temporary,
            final_name=entry.entry_id + _EXACT_READY_SUFFIX,
            checkpoints=(
                "exact.ready_manifest_file_fsync",
                "exact.ready_manifest_publish",
                "exact.ready_manifest_directory_fsync",
            ),
            write_failure="exact ready manifest write failed",
        )
        _verify_runtime_root(runtime)
    except OSError as error:
        try:
            os.unlink(temporary, dir_fd=runtime.staging_descriptor)
        except FileNotFoundError:
            pass
        raise InvalidArgumentError("exact ready manifest is unavailable") from error


def _load_exact_ready(
    runtime: _RuntimeRoot,
    entry_id: str,
    *,
    require_file: bool = True,
) -> tuple[PrivateStagedEntry, ExactCaptureMetadata]:
    if _ENTRY_ID.fullmatch(entry_id) is None:
        raise InvalidArgumentError("exact ready identity is invalid")
    return _load_exact_ready_manifest(
        runtime,
        entry_id + _EXACT_READY_SUFFIX,
        expected_entry_id=entry_id,
        require_file=require_file,
    )


def _load_exact_ready_temporary(
    runtime: _RuntimeRoot,
    name: str,
    *,
    require_file: bool = True,
) -> tuple[PrivateStagedEntry, ExactCaptureMetadata]:
    if _EXACT_READY_TEMP.fullmatch(name) is None:
        raise InvalidArgumentError("exact ready identity is invalid")
    return _load_exact_ready_manifest(
        runtime,
        name,
        expected_entry_id=None,
        require_file=require_file,
    )


def _load_exact_ready_manifest(
    runtime: _RuntimeRoot,
    name: str,
    *,
    expected_entry_id: str | None,
    require_file: bool,
) -> tuple[PrivateStagedEntry, ExactCaptureMetadata]:
    encoded = _read_private_manifest(
        runtime.staging_descriptor,
        name,
        max_bytes=MAX_MANIFEST_BYTES,
        label="exact ready manifest",
    )
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"))
        required = {
            "authorship",
            "batch_id",
            "byte_length",
            "capture_request_id",
            "captured_at",
            "display_name",
            "entry_id",
            "expected_head_id",
            "format",
            "payload_device",
            "payload_inode",
            "payload_sha256",
            "sensitivity",
            "source_origin",
            "target_lineage_id",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError
        if raw["format"] != _EXACT_READY_FORMAT:
            raise ValueError
        if any(
            not isinstance(raw[field], str)
            for field in (
                "authorship",
                "batch_id",
                "capture_request_id",
                "display_name",
                "expected_head_id",
                "payload_sha256",
                "sensitivity",
                "source_origin",
                "target_lineage_id",
            )
        ):
            raise ValueError
        entry_id = raw["entry_id"]
        if (
            not isinstance(entry_id, str)
            or _ENTRY_ID.fullmatch(entry_id) is None
            or (expected_entry_id is not None and entry_id != expected_entry_id)
        ):
            raise ValueError
        entry = PrivateStagedEntry(
            entry_id=entry_id,
            display_name=raw["display_name"],
            byte_length=raw["byte_length"],
            sha256=raw["payload_sha256"],
        )
        exact = ExactCaptureMetadata(
            capture_request_id=raw["capture_request_id"],
            batch_id=raw["batch_id"],
            captured_at=raw["captured_at"],
            target_lineage_id=raw["target_lineage_id"],
            expected_head_id=raw["expected_head_id"],
            payload_sha256=raw["payload_sha256"],
            source_origin=SourceCaptureOrigin(raw["source_origin"]),
            authorship=Authorship(raw["authorship"]),
            sensitivity=Sensitivity(raw["sensitivity"]),
        )
        _validate_private_entry(entry)
        _validate_exact_metadata(exact)
        payload_device = raw["payload_device"]
        payload_inode = raw["payload_inode"]
        if (
            not isinstance(payload_device, int)
            or isinstance(payload_device, bool)
            or payload_device < 0
            or not isinstance(payload_inode, int)
            or isinstance(payload_inode, bool)
            or payload_inode < 1
        ):
            raise ValueError
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise InvalidArgumentError("exact ready manifest is invalid") from error
    if require_file:
        private_metadata = _verify_private_file(runtime, entry)
        # The persisted payload_device carries the writer's boot-assigned
        # number; binding compares the inode on the staging directory's
        # current device so a durable correction survives a reboot.
        if (private_metadata.st_dev, private_metadata.st_ino) != (
            _staging_device(runtime),
            payload_inode,
        ):
            raise InvalidArgumentError("exact ready payload binding is invalid")
    return entry, exact


def _promote_exact_ready_temps(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> None:
    """Finish a valid fsynced ready-manifest publication after process death."""
    try:
        with _open_runtime_root(paths, authority=directory_authority) as runtime:
            _verify_runtime_root(runtime)
            changed = False
            for name in sorted(os.listdir(runtime.staging_descriptor)):
                if _EXACT_READY_TEMP.fullmatch(name) is None:
                    continue
                try:
                    entry, exact = _load_exact_ready_temporary(
                        runtime,
                        name,
                        require_file=False,
                    )
                except InvalidArgumentError:
                    continue
                try:
                    with _exact_stage_payload_lease(
                        runtime,
                        entry_id=entry.entry_id,
                        max_bytes=entry.byte_length,
                        expected_identity=None,
                    ) as descriptor:
                        if descriptor is None:
                            continue
                        loaded_entry, loaded_exact = _load_exact_ready_temporary(
                            runtime,
                            name,
                        )
                        if loaded_entry != entry or loaded_exact != exact:
                            continue
                        ready_name = entry.entry_id + _EXACT_READY_SUFFIX
                        if _stat_entry(runtime.staging_descriptor, ready_name) is None:
                            _rename_no_replace(
                                name,
                                ready_name,
                                source_descriptor=runtime.staging_descriptor,
                                destination_descriptor=runtime.staging_descriptor,
                            )
                            changed = True
                            continue
                        ready_entry, ready_exact = _load_exact_ready(
                            runtime,
                            entry.entry_id,
                        )
                        if ready_entry != entry or ready_exact != exact:
                            continue
                        _unlink_staging_name(runtime, name)
                        changed = True
                except _StagePayloadLeaseUnavailable:
                    raise
                except _ExactStageLeaseBusy, InvalidArgumentError:
                    continue
            if changed:
                os.fsync(runtime.staging_descriptor)
                _checkpoint("exact.ready_manifest_recovery_directory_fsync")
            _verify_runtime_root(runtime)
    except OSError as error:
        raise InvalidArgumentError("exact staging filesystem is unavailable") from error


def _load_exact_batch(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    metadata: ExactCaptureMetadata,
) -> InboxBatch | None:
    identity = load_runtime_identity(runtime.paths)
    connection = open_database(runtime.paths, load_master_key(identity), read_only=True)
    try:
        connection.execute("BEGIN")
        return _exact_batch_from_connection(
            connection, identity.store_id, entry, metadata
        )
    finally:
        connection.close()


def _exact_batch_from_connection(
    connection: Connection,
    store_id: str,
    entry: PrivateStagedEntry,
    metadata: ExactCaptureMetadata,
) -> InboxBatch | None:
    row = connection.execute(
        "SELECT batch_id, sealed_at, source_count, has_more FROM inbox_batches "
        "WHERE capture_request_id = ?",
        (metadata.capture_request_id,),
    ).fetchone()
    if row is None:
        conflicting = connection.execute(
            "SELECT capture_request_id FROM inbox_batches WHERE batch_id = ?",
            (metadata.batch_id,),
        ).fetchone()
        if conflicting is not None:
            raise InvalidArgumentError("reserved exact batch is already used")
        return None
    source_rows = connection.execute(
        "SELECT s.source_id, s.batch_id, s.origin, s.original_name, s.media_type, "
        "s.authorship, s.sensitivity, s.captured_at, b.sha256, b.byte_length, "
        "b.original_bytes FROM sources AS s "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE s.batch_id = ? ORDER BY s.source_id",
        (str(row[0]),),
    ).fetchall()
    membership_rows = connection.execute(
        "SELECT source_id, ordinal FROM inbox_batch_sources "
        "WHERE batch_id = ? ORDER BY ordinal, source_id",
        (str(row[0]),),
    ).fetchall()
    issue_count = int(
        connection.execute(
            "SELECT count(*) FROM inbox_batch_issues WHERE batch_id = ?",
            (str(row[0]),),
        ).fetchone()[0]
    )
    source_bytes = bytes(source_rows[0][10]) if len(source_rows) == 1 else b""
    if (
        str(row[0]) != metadata.batch_id
        or int(row[1]) != metadata.captured_at
        or row[2:] != (1, 0)
        or len(source_rows) != 1
        or len(membership_rows) != 1
        or issue_count != 0
        or membership_rows[0] != (source_rows[0][0], 0)
        or source_rows[0][1:10]
        != (
            metadata.batch_id,
            metadata.source_origin.value,
            entry.display_name,
            media_type_for_name(entry.display_name),
            metadata.authorship.value,
            metadata.sensitivity.value,
            metadata.captured_at,
            metadata.payload_sha256,
            entry.byte_length,
        )
        or len(source_bytes) != entry.byte_length
        or hashlib.sha256(source_bytes).hexdigest() != entry.sha256
        or not _exact_correction_envelope_matches(
            source_bytes,
            store_id=store_id,
            metadata=metadata,
        )
    ):
        raise InvalidArgumentError("stored exact capture is mismatched")
    return InboxBatch(
        batch_id=metadata.batch_id,
        sealed_at=metadata.captured_at,
        source_count=1,
        source_ids=(str(source_rows[0][0]),),
        duplicates=_duplicate_captures(connection, metadata.batch_id),
    )


def _exact_correction_envelope_matches(
    source_bytes: bytes,
    *,
    store_id: str,
    metadata: ExactCaptureMetadata,
) -> bool:
    try:
        recorded_at = (
            datetime.fromtimestamp(metadata.captured_at, UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        prefix = (
            "---\n"
            "format: memory.owner-correction.v1\n"
            f"store_id: {store_id}\n"
            f"target_lineage_id: {metadata.target_lineage_id}\n"
            f"expected_head_id: {metadata.expected_head_id}\n"
            f"recorded_at: {recorded_at}\n"
            "---\n"
            "# Owner correction\n\n"
        ).encode("utf-8", errors="strict")
    except OverflowError, OSError, UnicodeError, ValueError:
        return False
    return len(source_bytes) > len(prefix) and source_bytes.startswith(prefix)


def _find_exact_claim(
    runtime: _RuntimeRoot,
    metadata: ExactCaptureMetadata,
) -> _Claim | None:
    """Resolve one exact claim without accepting an ordinary/ambiguous claim."""
    matches: list[_Claim] = []
    for artifact in _claim_artifacts(runtime):
        try:
            claim = _load_claim(
                runtime,
                artifact.path,
                batch_id=artifact.batch_id,
                require_files=False,
            )
        except InvalidArgumentError:
            if artifact.batch_id != metadata.batch_id:
                continue
            if artifact.phase == "creating":
                _remove_claim_artifact(runtime, artifact.path)
                continue
            raise InvalidArgumentError("exact capture claim is invalid") from None
        if claim.custody_kind is CustodyKind.INBOX_SCAN:
            if claim.batch_id == metadata.batch_id:
                raise InvalidArgumentError("reserved exact batch is already used")
            continue
        existing = claim.exact_metadata
        if existing is None:
            raise InvalidArgumentError("exact capture claim is invalid")
        if (
            claim.batch_id == metadata.batch_id
            or existing.capture_request_id == metadata.capture_request_id
        ):
            if existing != metadata:
                raise InvalidArgumentError("exact capture reservation is ambiguous")
            matches.append(claim)
    if len(matches) > 1:
        raise InvalidArgumentError("exact capture reservation is ambiguous")
    if matches and matches[0].path.name.startswith(".cleanup-"):
        raise InvalidArgumentError("exact capture publication is incomplete")
    return matches[0] if matches else None


def _cleanup_committed_exact_claim(
    runtime: _RuntimeRoot,
    metadata: ExactCaptureMetadata,
) -> None:
    """Finish only claim artifacts bound to an already verified exact batch."""
    matches = [
        artifact
        for artifact in _claim_artifacts(runtime)
        if artifact.batch_id == metadata.batch_id
    ]
    if len(matches) > 1:
        raise InvalidArgumentError("exact capture reservation is ambiguous")
    if not matches:
        return
    artifact = matches[0]
    try:
        claim = _load_claim(
            runtime,
            artifact.path,
            batch_id=artifact.batch_id,
            require_files=False,
        )
    except InvalidArgumentError:
        if artifact.phase != "cleanup":
            raise InvalidArgumentError("exact capture claim is invalid") from None
        _remove_claim_artifact(runtime, artifact.path)
        return
    if claim.exact_metadata != metadata:
        raise InvalidArgumentError("exact capture reservation is ambiguous")
    published = _load_published_batch(runtime, claim)
    if published is None:
        raise InvalidArgumentError("exact capture publication is incomplete")
    _cleanup_claim(runtime, claim)


def _exact_recovery_candidates(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> tuple[tuple[PrivateStagedEntry, ExactCaptureMetadata], ...]:
    """Enumerate unique valid ready/claim reservations without owner content."""
    candidates: dict[
        str,
        tuple[PrivateStagedEntry, ExactCaptureMetadata],
    ] = {}
    ambiguous: set[str] = set()
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        for name in sorted(os.listdir(runtime.staging_descriptor)):
            if not name.endswith(_EXACT_READY_SUFFIX):
                continue
            entry_id = name[: -len(_EXACT_READY_SUFFIX)]
            try:
                candidate = _load_exact_ready(
                    runtime,
                    entry_id,
                    require_file=False,
                )
            except InvalidArgumentError:
                continue
            try:
                with _exact_stage_payload_lease(
                    runtime,
                    entry_id=candidate[0].entry_id,
                    max_bytes=candidate[0].byte_length,
                    expected_identity=None,
                ):
                    pass
            except _ExactStageLeaseBusy:
                continue
            except _StagePayloadLeaseUnavailable:
                raise
            except InvalidArgumentError:
                try:
                    _load_exact_ready(
                        runtime,
                        entry_id,
                        require_file=True,
                    )
                except InvalidArgumentError:
                    continue
                raise
            request_id = candidate[1].capture_request_id
            previous = candidates.get(request_id)
            if previous is not None and previous != candidate:
                ambiguous.add(request_id)
            else:
                candidates[request_id] = candidate
        for artifact in _claim_artifacts(runtime):
            try:
                claim = _load_claim(
                    runtime,
                    artifact.path,
                    batch_id=artifact.batch_id,
                    require_files=False,
                )
            except InvalidArgumentError:
                continue
            if (
                claim.custody_kind is not CustodyKind.EXACT_STAGED_ENTRY
                or claim.exact_metadata is None
                or len(claim.entries) != 1
            ):
                continue
            visible = claim.entries[0]
            candidate = (
                PrivateStagedEntry(
                    entry_id=visible.entry_id,
                    display_name=visible.name,
                    byte_length=visible.size,
                    sha256=visible.sha256,
                ),
                claim.exact_metadata,
            )
            request_id = claim.exact_metadata.capture_request_id
            previous = candidates.get(request_id)
            if previous is not None and previous != candidate:
                ambiguous.add(request_id)
            else:
                candidates[request_id] = candidate
    return tuple(
        candidates[request_id]
        for request_id in sorted(candidates)
        if request_id not in ambiguous
    )


def _cleanup_exact_ready(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    exact: ExactCaptureMetadata,
) -> None:
    """Retire one committed exact reservation through held descriptor bindings.

    Each artifact is opened before its validation and stays open through it, so
    removal is bound to that exact verified inode instead of to a pathname that
    could have been replaced afterwards. The payload is additionally drained
    through its own descriptor, so its private bytes are unreadable even when
    the final unlink cannot be proven safe; an unreclaimable remainder becomes
    an owner-visible recovery issue rather than a silent leftover.
    """
    _verify_runtime_root(runtime)
    for name in (entry.entry_id, entry.entry_id + _EXACT_READY_SUFFIX):
        metadata = _stat_entry(runtime.staging_descriptor, name)
        if metadata is None:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise InvalidArgumentError("exact cleanup is unsafe")
        payload = name == entry.entry_id
        flags = (os.O_RDWR if payload else os.O_RDONLY) | getattr(os, "O_NONBLOCK", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=runtime.staging_descriptor)
        except OSError as error:
            raise InvalidArgumentError("exact cleanup is unsafe") from error
        try:
            opened = os.fstat(descriptor)
            if _publication_identity(opened) != _publication_identity(metadata):
                raise InvalidArgumentError("exact cleanup is unsafe")
            if payload:
                _verify_private_file(runtime, entry)
                if (
                    opened.st_size != entry.byte_length
                    or not _drain_verified_descriptor(
                        descriptor,
                        _publication_identity(opened),
                        entry.sha256,
                    )
                ):
                    raise InvalidArgumentError("exact cleanup is mismatched")
            else:
                loaded_entry, loaded_metadata = _load_exact_ready(
                    runtime,
                    entry.entry_id,
                    require_file=False,
                )
                if loaded_entry != entry or loaded_metadata != exact:
                    raise InvalidArgumentError("exact cleanup is mismatched")
            if not _unlink_bound_staging_entry(
                runtime,
                name,
                descriptor,
                _publication_identity(os.fstat(descriptor)),
            ):
                raise InvalidArgumentError("exact cleanup is unsafe")
        finally:
            _close_descriptor_best_effort(descriptor)
    os.fsync(runtime.staging_descriptor)
    _checkpoint("exact.cleanup_directory_fsync")


def _unlink_staging_name(runtime: _RuntimeRoot, name: str) -> None:
    if _ENTRY_ID.fullmatch(name) is None and not (
        (name.startswith(".ready-") or name.startswith(".intent-"))
        and name.endswith(".tmp")
    ):
        raise InvalidArgumentError("staging cleanup identity is invalid")
    try:
        metadata = _stat_entry(runtime.staging_descriptor, name)
        if metadata is None:
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise InvalidArgumentError("staging cleanup is unsafe")
        os.unlink(name, dir_fd=runtime.staging_descriptor)
        os.fsync(runtime.staging_descriptor)
    except OSError as error:
        raise InvalidArgumentError("staging cleanup failed") from error


def _encode_staged_cursor(*, store_id: str, upper: str, after: str) -> str:
    encoded = json.dumps(
        {
            "after": after,
            "operation": "inbox.staged.list",
            "store": store_id,
            "upper": upper,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(encoded).decode().rstrip("=")


def _staged_cursor_bounds(
    cursor: str | None,
    *,
    store_id: str,
) -> tuple[str, str | None]:
    if cursor is None:
        return "", None
    try:
        decoded = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4),
            altchars=b"-_",
            validate=True,
        )
        raw = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as error:
        raise StaleCursorError("staged Inbox cursor is invalid") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"after", "operation", "store", "upper", "version"}
        or raw.get("version") != 1
        or raw.get("operation") != "inbox.staged.list"
        or raw.get("store") != store_id
        or not isinstance(raw.get("after"), str)
        or not isinstance(raw.get("upper"), str)
    ):
        raise StaleCursorError("staged Inbox cursor is invalid")
    return str(raw["after"]), str(raw["upper"])


def _load_private_recovery_manifest(
    runtime: _RuntimeRoot,
    name: str,
) -> _PrivateRecoveryReservation:
    """Load one strict content-free private-custody recovery reservation."""
    match = _RECOVERY_MANIFEST.fullmatch(name)
    if match is None:
        raise InvalidArgumentError("private recovery identity is invalid")
    encoded = _read_private_manifest(
        runtime.staging_descriptor,
        name,
        max_bytes=MAX_RECOVERY_MANIFEST_BYTES,
        label="private recovery manifest",
        verify_stable=True,
    )
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"))
        required = {
            "batch_id",
            "byte_length",
            "capture_request_id",
            "entry_id",
            "expected_identity",
            "format",
            "kind",
            "payload_name",
            "recovery_id",
            "sha256",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError
        recovery_id = raw["recovery_id"]
        expected_identity = raw["expected_identity"]
        kind = raw["kind"]
        capture_request_id = raw["capture_request_id"]
        batch_id = raw["batch_id"]
        if (
            raw["format"] != _RECOVERY_FORMAT
            or not isinstance(recovery_id, str)
            or recovery_id != match.group(1)
            or raw["payload_name"] != f".recovery-{recovery_id}.stage"
            or _RECOVERY_PAYLOAD.fullmatch(raw["payload_name"]) is None
            or not isinstance(raw["entry_id"], str)
            or _ENTRY_ID.fullmatch(raw["entry_id"]) is None
            or kind
            not in {
                "exact_incomplete",
                "ordinary_publication",
                "owner_correction_handoff",
            }
            or not isinstance(raw["byte_length"], int)
            or isinstance(raw["byte_length"], bool)
            or not 0 <= raw["byte_length"] <= MAX_FILE_BYTES
            or not isinstance(raw["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) is None
            or not isinstance(expected_identity, list)
            or len(expected_identity) != 7
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in expected_identity
            )
        ):
            raise ValueError
        if kind == "owner_correction_handoff":
            if (
                not isinstance(capture_request_id, str)
                or _CAPTURE_REQUEST_ID.fullmatch(capture_request_id) is None
                or not isinstance(batch_id, str)
                or _BATCH_ID.fullmatch(batch_id) is None
            ):
                raise ValueError
        elif capture_request_id is not None or batch_id is not None:
            raise ValueError
        return _PrivateRecoveryReservation(
            recovery_id=recovery_id,
            kind=kind,
            payload_name=raw["payload_name"],
            entry_id=raw["entry_id"],
            byte_length=raw["byte_length"],
            sha256=raw["sha256"],
            expected_identity=tuple(expected_identity),
            capture_request_id=capture_request_id,
            batch_id=batch_id,
        )
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidArgumentError("private recovery manifest is invalid") from error


def _bound_rollback_slot_members(
    runtime: _RuntimeRoot,
    issues: list[CaptureRecoveryIssue],
    *,
    identity: StoreIdentity | None = None,
) -> tuple[_BoundRollbackSlotMembers, set[str]]:
    """Index bound slot members and identify bundles a live publisher leases."""
    artifact_names = tuple(sorted(os.listdir(runtime.staging_descriptor)))
    names = [
        name
        for name in artifact_names
        if _ROLLBACK_SLOT_RECORD.fullmatch(name) is not None
    ]
    members = _BoundRollbackSlotMembers(artifact_names)
    if not names:
        return members, set()
    selected_identity = (
        load_runtime_identity(runtime.paths) if identity is None else identity
    )
    records = _authenticated_slot_records(
        runtime,
        store_id=selected_identity.store_id,
        master_key=load_master_key(selected_identity),
    )
    live_members: set[str] = set()
    try:
        for name in names:
            match = _ROLLBACK_SLOT_RECORD.fullmatch(name)
            assert match is not None
            metadata = _stat_entry(runtime.staging_descriptor, name)
            detected = 0 if metadata is None else metadata.st_mtime_ns
            record = records.get(match.group(1))
            if record is None:
                issues.append(_recovery_issue(name, "malformed_manifest", detected))
                continue
            bundle = (record.payload, record.manifest, record.withdrawal)
            if not all(
                _rollback_slot_member_matches(runtime, member) for member in bundle
            ):
                issues.append(_recovery_issue(name, "custody_mismatch", detected))
                continue
            lease_state, descriptors = _rollback_slot_bundle_lease_state(
                runtime,
                bundle,
            )
            if lease_state == "mismatched":
                issues.append(_recovery_issue(name, "custody_mismatch", detected))
                continue
            for member in bundle:
                members[member.name] = member
                if lease_state == "busy":
                    live_members.add(member.name)
            members.descriptors.update(descriptors)
        return members, live_members
    except BaseException:
        members.close()
        raise


def _rollback_slot_bundle_lease_state(
    runtime: _RuntimeRoot,
    bundle: tuple[
        StagingArtifactIdentity,
        StagingArtifactIdentity,
        StagingArtifactIdentity,
    ],
) -> tuple[Literal["busy", "idle", "mismatched"], dict[str, int]]:
    """Try to lease an authenticated bundle without trusting-looking names.

    A fully acquired idle group transfers all of its leases to the issue-pass
    owner. That prevents later content inspection from observing a bundle a
    publisher changed after discovery. A busy member means the authenticated
    bundle is one live publication; operational open or flock failure is not
    debt and must abort the report instead of being hidden as malformed.
    """
    descriptors: list[tuple[int, StagingArtifactIdentity]] = []
    retain_descriptors = False
    try:
        for member in bundle:
            flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
            if member.file_type == "directory" and hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(
                    member.name,
                    flags,
                    dir_fd=runtime.staging_descriptor,
                )
            except FileNotFoundError:
                return "mismatched", {}
            except OSError as error:
                raise _StagePayloadLeaseUnavailable(
                    "publication rollback bundle lease is unavailable"
                ) from error
            descriptors.append((descriptor, member))
            try:
                opened = os.fstat(descriptor)
                path = _stat_entry(runtime.staging_descriptor, member.name)
            except OSError as error:
                raise _StagePayloadLeaseUnavailable(
                    "publication rollback bundle lease is unavailable"
                ) from error
            if path is None or not _rollback_slot_descriptor_matches(
                opened,
                path,
                member,
                staging_device=_staging_device(runtime),
            ):
                return "mismatched", {}
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as error:
                if not isinstance(error, BlockingIOError) and error.errno not in {
                    errno.EACCES,
                    errno.EAGAIN,
                }:
                    raise _StagePayloadLeaseUnavailable(
                        "publication rollback bundle lease failed"
                    ) from error
                try:
                    still_bound = _rollback_slot_open_bundle_matches(
                        runtime,
                        bundle,
                        descriptors,
                    )
                except OSError as recheck_error:
                    raise _StagePayloadLeaseUnavailable(
                        "publication rollback bundle lease is unavailable"
                    ) from recheck_error
                return ("busy" if still_bound else "mismatched"), {}
        try:
            still_bound = _rollback_slot_open_bundle_matches(
                runtime,
                bundle,
                descriptors,
            )
        except OSError as error:
            raise _StagePayloadLeaseUnavailable(
                "publication rollback bundle lease is unavailable"
            ) from error
        if not still_bound:
            return "mismatched", {}
        retain_descriptors = True
        return "idle", {member.name: descriptor for descriptor, member in descriptors}
    finally:
        if not retain_descriptors:
            for descriptor, _member in descriptors:
                _close_descriptor_best_effort(descriptor)


def _rollback_slot_open_bundle_matches(
    runtime: _RuntimeRoot,
    bundle: tuple[
        StagingArtifactIdentity,
        StagingArtifactIdentity,
        StagingArtifactIdentity,
    ],
    descriptors: list[tuple[int, StagingArtifactIdentity]],
) -> bool:
    """Rebind every opened descriptor and every recorded path as one bundle."""
    opened_by_name = {member.name: descriptor for descriptor, member in descriptors}
    staging_device = _staging_device(runtime)
    for member in bundle:
        path = _stat_entry(runtime.staging_descriptor, member.name)
        if path is None:
            return False
        descriptor = opened_by_name.get(member.name)
        if descriptor is None:
            if not _rollback_slot_metadata_matches(
                path,
                member,
                staging_device=staging_device,
            ):
                return False
            continue
        opened = os.fstat(descriptor)
        if not _rollback_slot_descriptor_matches(
            opened,
            path,
            member,
            staging_device=staging_device,
        ):
            return False
    return True


def _rollback_slot_descriptor_matches(
    opened: os.stat_result,
    path: os.stat_result,
    member: StagingArtifactIdentity,
    *,
    staging_device: int,
) -> bool:
    """Bind one opened rollback member to its authenticated path identity."""
    if not _rollback_slot_metadata_matches(
        opened,
        member,
        staging_device=staging_device,
    ) or not _rollback_slot_metadata_matches(
        path,
        member,
        staging_device=staging_device,
    ):
        return False
    return (opened.st_dev, opened.st_ino) == (path.st_dev, path.st_ino)


def _rollback_slot_metadata_matches(
    metadata: os.stat_result,
    member: StagingArtifactIdentity,
    *,
    staging_device: int,
) -> bool:
    """Match one path or descriptor to an authenticated rollback member.

    The member's recorded identity carries no device; the caller supplies the
    staging directory's current device instead, so a member substituted from
    another volume still fails while a reboot's renumbering does not.
    """
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    ) != (staging_device, member.inode, member.uid, member.mode):
        return False
    if member.file_type == "regular":
        return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    return stat.S_ISDIR(metadata.st_mode)


def _rollback_slot_member_matches(
    runtime: _RuntimeRoot,
    member: StagingArtifactIdentity,
) -> bool:
    """Prove one authenticated member still binds its recorded runtime identity."""
    metadata = _stat_entry(runtime.staging_descriptor, member.name)
    if metadata is None:
        return False
    return _rollback_slot_metadata_matches(
        metadata,
        member,
        staging_device=_staging_device(runtime),
    )


def _idle_authenticated_slot_member(
    runtime: _RuntimeRoot,
    members: _BoundRollbackSlotMembers,
    live_members: set[str],
    name: str,
) -> bool:
    """Recognize one member of an authenticated idle or live leased bundle."""
    try:
        member = members.get(name)
        if member is None or not _rollback_slot_member_matches(runtime, member):
            return False
        if name in live_members:
            return True
        descriptor = members.descriptors.get(name)
        if descriptor is None:
            return False
        opened = os.fstat(descriptor)
        path = _stat_entry(runtime.staging_descriptor, name)
        if path is None or not _rollback_slot_descriptor_matches(
            opened,
            path,
            member,
            staging_device=_staging_device(runtime),
        ):
            return False
        if member.file_type == "regular":
            return opened.st_size == 0
        return (
            not tuple(os.listdir(descriptor))
            and _stat_entry(descriptor, _WITHDRAWAL_CHILD) is None
        )
    except OSError as error:
        raise _StagePayloadLeaseUnavailable(
            "publication rollback bundle inspection is unavailable"
        ) from error


def _exact_recovery_issues(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> list[CaptureRecoveryIssue]:
    """Report every content-free reason a staging artifact needs attention.

    Five passes, each answering a different question and each feeding the
    next: what recovery custody was left behind, which exact-capture intents
    are inconsistent with their payload, which ready manifests are unbound or
    ambiguous, which claims disagree with the ready manifests about the same
    capture request, and whether more than one ordinary claim is active at
    once.

    Every pass reports rather than repairs. Recovery is the owner's decision,
    and a pass that quietly tidied would destroy the evidence the report is
    made of.
    """
    issues: list[CaptureRecoveryIssue] = []
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        bound_slots, live_slot_members = _bound_rollback_slot_members(runtime, issues)
        try:
            _recovery_artifact_issues(
                runtime,
                bound_slots,
                live_slot_members,
                issues,
            )
            _append_exact_recovery_state_issues(runtime, issues)
        finally:
            bound_slots.close()
    return sorted(issues, key=lambda issue: issue.issue_id)


@contextmanager
def _exact_recovery_inspection(
    paths: RuntimePaths,
    *,
    directory_authority: RuntimeDirectoryAuthority | None,
) -> Iterator[_ExactRecoveryInspection]:
    """Complete fail-honest inspection before mutation and retain its leases."""
    with _open_runtime_root(paths, authority=directory_authority) as runtime:
        artifact_issues: list[CaptureRecoveryIssue] = []
        identity = load_runtime_identity(runtime.paths)
        bound_slots, live_slot_members = _bound_rollback_slot_members(
            runtime,
            artifact_issues,
            identity=identity,
        )
        try:
            _recovery_artifact_issues(
                runtime,
                bound_slots,
                live_slot_members,
                artifact_issues,
            )
            yield _ExactRecoveryInspection(
                runtime=runtime,
                identity=identity,
                directory_authority=_runtime_directory_authority(runtime),
                bound_slots=bound_slots,
                live_slot_members=live_slot_members,
                issues=tuple(sorted(artifact_issues, key=lambda issue: issue.issue_id)),
            )
        finally:
            bound_slots.close()


def _append_exact_recovery_state_issues(
    runtime: _RuntimeRoot,
    issues: list[CaptureRecoveryIssue],
) -> None:
    """Append current intent, ready, claim, and active-claim issue state."""
    intent_entries, busy_exact_entries = _exact_intent_issues(runtime, issues)
    ready_records, unbound_ready_names = _exact_ready_issues(
        runtime,
        intent_entries,
        busy_exact_entries,
        issues,
    )
    _exact_claim_issues(runtime, ready_records, unbound_ready_names, issues)
    _active_ordinary_claim_issues(runtime, issues)


def _active_ordinary_claim_issues(
    runtime: _RuntimeRoot,
    issues: list[CaptureRecoveryIssue],
) -> None:
    """Report a Store holding more than one active ordinary inbox claim.

    One settled scan seals one batch, so one claim is the only number
    `_recover_claim` can resume. Two leave it unable to choose -- picking one
    would be the Store deciding which of the owner's batches was real -- and
    it refuses with `Store has multiple active claims`. That refusal happens
    on the way into *every* later scan, before discovery, so the condition is
    not a scan that failed once: it is capture stopped until someone
    intervenes, with nothing naming it anywhere the owner looks.

    `ambiguous_claim` is the existing code for two records the Store will not
    adjudicate between, which is exactly this, and each claim is named
    separately so the report says how many and which.

    What counts as active mirrors `_recover_claim` exactly, because a report
    that counted differently would name a condition the scanner does not
    have. A published artifact counts even when its manifest will not load; a
    creating one counts only when it will, since recovery discards the rest;
    a cleanup one never counts; and an artifact an exact-ready manifest speaks
    for is not ordinary at all.
    """
    exact_batch_ids = _exact_ready_batch_ids(runtime)
    active: list[_ClaimArtifact] = []
    for artifact in _claim_artifacts(runtime):
        if artifact.phase not in {"published", "creating"}:
            continue
        try:
            claim = _load_claim(
                runtime,
                artifact.path,
                batch_id=artifact.batch_id,
                require_files=False,
            )
        except InvalidArgumentError:
            resumable = (
                artifact.phase == "published"
                and artifact.batch_id not in exact_batch_ids
            )
            if resumable:
                active.append(artifact)
            continue
        if claim.custody_kind is not CustodyKind.EXACT_STAGED_ENTRY:
            active.append(artifact)
    if len(active) < 2:
        return
    for artifact in active:
        issues.append(
            _recovery_issue(
                artifact.path.name,
                "ambiguous_claim",
                _artifact_detected_ns(runtime, artifact),
            )
        )


def _recovery_artifact_issues(
    runtime: _RuntimeRoot,
    bound_slots: _BoundRollbackSlotMembers,
    live_slot_members: set[str],
    issues: list[CaptureRecoveryIssue],
) -> None:
    """Report recovery manifests, temporaries, withdrawals, and orphan payloads.

    A payload whose manifest named it is accounted for; one no manifest names
    is custody nobody is holding.
    """
    recovery_payloads: set[str] = set()
    for name in bound_slots.artifact_names:
        metadata = _stat_entry(runtime.staging_descriptor, name)
        detected = 0 if metadata is None else metadata.st_mtime_ns
        if _RECOVERY_MANIFEST.fullmatch(name) is not None:
            if _idle_authenticated_slot_member(
                runtime,
                bound_slots,
                live_slot_members,
                name,
            ):
                continue
            try:
                reservation = _load_private_recovery_manifest(runtime, name)
            except InvalidArgumentError:
                issues.append(_recovery_issue(name, "malformed_manifest", detected))
            else:
                recovery_payloads.add(reservation.payload_name)
                issues.append(_recovery_issue(name, "custody_mismatch", detected))
        elif _RECOVERY_TEMP.fullmatch(name) is not None:
            issues.append(_recovery_issue(name, "malformed_manifest", detected))
        elif _WITHDRAWAL_DIRECTORY.fullmatch(
            name
        ) is not None and not _idle_authenticated_slot_member(
            runtime,
            bound_slots,
            live_slot_members,
            name,
        ):
            issues.append(_recovery_issue(name, "custody_mismatch", detected))
    for name in bound_slots.artifact_names:
        if (
            _RECOVERY_PAYLOAD.fullmatch(name) is not None
            and name not in recovery_payloads
            and not _idle_authenticated_slot_member(
                runtime,
                bound_slots,
                live_slot_members,
                name,
            )
        ):
            metadata = _stat_entry(runtime.staging_descriptor, name)
            detected = 0 if metadata is None else metadata.st_mtime_ns
            issues.append(_recovery_issue(name, "custody_mismatch", detected))


def _exact_intent_issues(
    runtime: _RuntimeRoot,
    issues: list[CaptureRecoveryIssue],
) -> tuple[set[str], set[str]]:
    """Report intents inconsistent with the payload they reserve or bind.

    Returns the entry ids whose intent loaded cleanly, so the ready pass can
    tell a bare entry with a live intent from one with nothing behind it.
    """
    valid_intent_entries: set[str] = set()
    busy_exact_entries: set[str] = set()
    valid_intents: list[tuple[str, int, _ExactStageIntent]] = []
    for name in sorted(os.listdir(runtime.staging_descriptor)):
        metadata = _stat_entry(runtime.staging_descriptor, name)
        detected = 0 if metadata is None else metadata.st_mtime_ns
        if name.endswith(_EXACT_INTENT_SUFFIX):
            entry_id = name[: -len(_EXACT_INTENT_SUFFIX)]
            try:
                intent = _load_exact_intent(runtime, entry_id)
            except InvalidArgumentError:
                issues.append(_recovery_issue(name, "malformed_manifest", detected))
            else:
                valid_intent_entries.add(entry_id)
                valid_intents.append((name, detected, intent))
        elif _EXACT_INTENT_TEMP.fullmatch(name) is not None:
            mapped_entry_id = _mapped_exact_intent_entry_id(name)
            if mapped_entry_id is not None:
                try:
                    with _exact_stage_payload_lease(
                        runtime,
                        entry_id=mapped_entry_id,
                        max_bytes=MAX_FILE_BYTES,
                        expected_identity=None,
                    ):
                        pass
                except _ExactStageLeaseBusy:
                    valid_intent_entries.add(mapped_entry_id)
                    busy_exact_entries.add(mapped_entry_id)
                    continue
                except _StagePayloadLeaseUnavailable:
                    raise
                except InvalidArgumentError:
                    issues.append(_recovery_issue(name, "malformed_manifest", detected))
                    continue
            try:
                intent = _load_exact_intent_manifest(
                    runtime,
                    name,
                    expected_entry_id=None,
                )
                if mapped_entry_id is not None and intent.entry_id != mapped_entry_id:
                    raise InvalidArgumentError(
                        "exact staging intent temporary is mismatched"
                    )
                with _exact_intent_payload_lease(runtime, intent):
                    pass
            except _ExactStageLeaseBusy:
                valid_intent_entries.add(intent.entry_id)
                busy_exact_entries.add(intent.entry_id)
                continue
            except _StagePayloadLeaseUnavailable:
                raise
            except InvalidArgumentError:
                pass
            issues.append(_recovery_issue(name, "malformed_manifest", detected))
    for name, detected, intent in valid_intents:
        payload = _stat_entry(runtime.staging_descriptor, intent.entry_id)
        mismatched = intent.phase == "payload_bound" and payload is None
        if payload is not None:
            try:
                with _exact_intent_payload_lease(runtime, intent) as descriptor:
                    if descriptor is None:
                        mismatched = True
                    elif intent.phase == "reserved":
                        mismatched = True
                    else:
                        try:
                            _read_exact_intent_entry(
                                runtime,
                                intent,
                                descriptor=descriptor,
                                sync_complete=False,
                            )
                        except _ExactIncompleteError:
                            pass
                        except InvalidArgumentError:
                            mismatched = True
            except _ExactStageLeaseBusy:
                busy_exact_entries.add(intent.entry_id)
                continue
            except _StagePayloadLeaseUnavailable:
                raise
            except InvalidArgumentError:
                mismatched = True
        if mismatched:
            issues.append(_recovery_issue(name, "custody_mismatch", detected))
    return valid_intent_entries, busy_exact_entries


def _exact_ready_issues(
    runtime: _RuntimeRoot,
    valid_intent_entries: set[str],
    busy_exact_entries: set[str],
    issues: list[CaptureRecoveryIssue],
) -> tuple[
    list[tuple[str, int, PrivateStagedEntry, ExactCaptureMetadata]],
    set[str],
]:
    """Report malformed ready manifests and unaccounted staging entries.

    Returns the records that loaded, and the names whose payload is present
    but no longer binds, which only the claim pass can judge.
    """
    ready_records: list[tuple[str, int, PrivateStagedEntry, ExactCaptureMetadata]] = []
    unbound_ready_names: set[str] = set()
    for name in sorted(os.listdir(runtime.staging_descriptor)):
        metadata = _stat_entry(runtime.staging_descriptor, name)
        detected = 0 if metadata is None else metadata.st_mtime_ns
        if name.endswith(_EXACT_READY_SUFFIX):
            entry_id = name[: -len(_EXACT_READY_SUFFIX)]
            try:
                entry, exact = _load_exact_ready(
                    runtime,
                    entry_id,
                    require_file=False,
                )
            except InvalidArgumentError:
                issues.append(_recovery_issue(name, "malformed_manifest", detected))
                continue
            if _stat_entry(runtime.staging_descriptor, entry_id) is not None:
                try:
                    _load_exact_ready(runtime, entry_id)
                except InvalidArgumentError:
                    unbound_ready_names.add(name)
            ready_records.append((name, detected, entry, exact))
        elif _ENTRY_ID.fullmatch(name) is not None:
            ready = name + _EXACT_READY_SUFFIX
            if (
                _stat_entry(runtime.staging_descriptor, ready) is None
                and name not in valid_intent_entries
            ):
                try:
                    with _exact_stage_payload_lease(
                        runtime,
                        entry_id=name,
                        max_bytes=MAX_FILE_BYTES,
                        expected_identity=None,
                    ) as descriptor:
                        if descriptor is None:
                            continue
                except _ExactStageLeaseBusy:
                    busy_exact_entries.add(name)
                    continue
                except _StagePayloadLeaseUnavailable:
                    raise
                except InvalidArgumentError:
                    pass
                issues.append(_recovery_issue(name, "malformed_manifest", detected))
        elif name.startswith(".ready-") and name.endswith(".tmp"):
            try:
                entry, _exact = _load_exact_ready_temporary(
                    runtime,
                    name,
                    require_file=False,
                )
            except InvalidArgumentError:
                pass
            else:
                if entry.entry_id in busy_exact_entries:
                    continue
                try:
                    with _exact_stage_payload_lease(
                        runtime,
                        entry_id=entry.entry_id,
                        max_bytes=entry.byte_length,
                        expected_identity=None,
                    ) as descriptor:
                        if descriptor is not None:
                            _load_exact_ready_temporary(runtime, name)
                except _ExactStageLeaseBusy:
                    valid_intent_entries.add(entry.entry_id)
                    busy_exact_entries.add(entry.entry_id)
                    continue
                except _StagePayloadLeaseUnavailable:
                    raise
                except InvalidArgumentError:
                    pass
            issues.append(_recovery_issue(name, "malformed_manifest", detected))
    return ready_records, unbound_ready_names


def _exact_claim_issues(
    runtime: _RuntimeRoot,
    ready_records: list[tuple[str, int, PrivateStagedEntry, ExactCaptureMetadata]],
    unbound_ready_names: set[str],
    issues: list[CaptureRecoveryIssue],
) -> None:
    """Report claims and ready manifests that disagree about one capture.

    Two records for one capture request that describe different bytes are
    ambiguous, and ambiguity is reported rather than resolved: picking one
    would be the Store deciding which of the owner's captures was real.
    """
    valid_claims: list[tuple[_ClaimArtifact, _Claim]] = []
    invalid_claims: list[_ClaimArtifact] = []
    for artifact in _claim_artifacts(runtime):
        try:
            claim = _load_claim(
                runtime,
                artifact.path,
                batch_id=artifact.batch_id,
                require_files=False,
            )
        except InvalidArgumentError:
            invalid_claims.append(artifact)
            continue
        if claim.custody_kind is CustodyKind.EXACT_STAGED_ENTRY:
            valid_claims.append((artifact, claim))

    ready_by_request: dict[
        str,
        list[tuple[str, int, PrivateStagedEntry, ExactCaptureMetadata]],
    ] = {}
    for ready_record in ready_records:
        ready_by_request.setdefault(
            ready_record[3].capture_request_id,
            [],
        ).append(ready_record)
    claims_by_request: dict[str, list[tuple[_ClaimArtifact, _Claim]]] = {}
    for claim_record in valid_claims:
        claim_exact = claim_record[1].exact_metadata
        if claim_exact is not None:
            claims_by_request.setdefault(
                claim_exact.capture_request_id,
                [],
            ).append(claim_record)

    for request_id, ready_group in ready_by_request.items():
        canonical = (ready_group[0][2], ready_group[0][3])
        related_claims = claims_by_request.get(request_id, [])
        ambiguous = any(
            (ready_record[2], ready_record[3]) != canonical
            for ready_record in ready_group[1:]
        ) or any(
            not _claim_matches_exact_candidate(claim, *canonical)
            for _artifact, claim in related_claims
        )
        if ambiguous:
            for name, detected, _entry, _exact in ready_group:
                issues.append(_recovery_issue(name, "ambiguous_claim", detected))
            continue
        unbound = [
            (name, detected, entry, exact)
            for name, detected, entry, exact in ready_group
            if name in unbound_ready_names
        ]
        if unbound:
            for name, detected, entry, exact in unbound:
                if not _exact_candidate_has_current_custody(runtime, entry, exact):
                    issues.append(_recovery_issue(name, "custody_mismatch", detected))
            continue
        entry, exact = canonical
        if not _exact_candidate_has_custody(
            runtime,
            entry,
            exact,
            tuple(claim for _artifact, claim in related_claims),
        ) and not _exact_candidate_has_current_custody(runtime, entry, exact):
            name, detected, _entry, _exact = ready_group[0]
            issues.append(_recovery_issue(name, "custody_mismatch", detected))

    for request_id, claim_group in claims_by_request.items():
        if request_id in ready_by_request:
            continue
        first_artifact, first_claim = claim_group[0]
        first_exact = first_claim.exact_metadata
        if first_exact is None or len(first_claim.entries) != 1:
            continue
        entry = PrivateStagedEntry(
            entry_id=first_claim.entries[0].entry_id,
            display_name=first_claim.entries[0].name,
            byte_length=first_claim.entries[0].size,
            sha256=first_claim.entries[0].sha256,
        )
        if any(
            not _claim_matches_exact_candidate(claim, entry, first_exact)
            for _artifact, claim in claim_group[1:]
        ):
            issues.append(
                _recovery_issue(
                    first_artifact.path.name,
                    "ambiguous_claim",
                    _artifact_detected_ns(runtime, first_artifact),
                )
            )
        elif not _exact_candidate_has_custody(
            runtime,
            entry,
            first_exact,
            tuple(claim for _artifact, claim in claim_group),
        ) and not _exact_candidate_has_current_custody(
            runtime,
            entry,
            first_exact,
        ):
            issues.append(
                _recovery_issue(
                    first_artifact.path.name,
                    "custody_mismatch",
                    _artifact_detected_ns(runtime, first_artifact),
                )
            )

    ready_batches = {ready_record[3].batch_id for ready_record in ready_records}
    for artifact in invalid_claims:
        if artifact.batch_id in ready_batches:
            issues.append(
                _recovery_issue(
                    artifact.path.name,
                    "malformed_manifest",
                    _artifact_detected_ns(runtime, artifact),
                )
            )


def _claim_matches_exact_candidate(
    claim: _Claim,
    entry: PrivateStagedEntry,
    exact: ExactCaptureMetadata,
) -> bool:
    if claim.exact_metadata != exact or len(claim.entries) != 1:
        return False
    visible = claim.entries[0]
    return (
        visible.entry_id,
        visible.name,
        visible.size,
        visible.sha256,
    ) == (
        entry.entry_id,
        entry.display_name,
        entry.byte_length,
        entry.sha256,
    )


def _exact_candidate_has_custody(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    exact: ExactCaptureMetadata,
    claims: tuple[_Claim, ...],
) -> bool:
    try:
        committed = _load_exact_batch(runtime, entry, exact)
    except InvalidArgumentError:
        return False
    if committed is not None:
        return True
    try:
        _verify_private_file(runtime, entry)
        return True
    except InvalidArgumentError:
        pass
    return _exact_claims_have_custody(runtime, entry, exact, claims)


def _exact_claims_have_custody(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    exact: ExactCaptureMetadata,
    claims: tuple[_Claim, ...],
) -> bool:
    """Verify matching claim bytes without accepting only manifest metadata."""
    for claim in claims:
        if not _claim_matches_exact_candidate(claim, entry, exact):
            continue
        try:
            descriptor = _open_claim_files(runtime, claim)
            try:
                capture = _read_unchanged(descriptor, claim.entries[0])
            finally:
                os.close(descriptor)
        except InvalidArgumentError, NoEligibleSourcesError, OSError:
            continue
        if hashlib.sha256(capture.original_bytes).hexdigest() == exact.payload_sha256:
            return True
    return False


def _exact_candidate_has_current_custody(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    exact: ExactCaptureMetadata,
) -> bool:
    """Recheck current filesystem custody before one remembered issue emits.

    Filesystem evidence is read before the final WAL snapshot. Exact capture
    commits before it removes a claim or ready artifact, so a supported
    transition must leave either matching filesystem custody in the first
    read or a matching committed batch in the later snapshot. A still-present
    malformed or mismatched artifact remains debt even when a batch exists.
    """
    filesystem_custody = False
    ready_name = entry.entry_id + _EXACT_READY_SUFFIX
    ready_before = _stat_entry(runtime.staging_descriptor, ready_name)
    payload_before = _stat_entry(runtime.staging_descriptor, entry.entry_id)
    if ready_before is None:
        if payload_before is not None:
            return False
    else:
        try:
            current_ready = _load_exact_ready(
                runtime,
                entry.entry_id,
                require_file=False,
            )
        except InvalidArgumentError:
            if (
                _stat_entry(runtime.staging_descriptor, ready_name) is not None
                or _stat_entry(runtime.staging_descriptor, entry.entry_id) is not None
            ):
                return False
        else:
            if current_ready != (entry, exact):
                if (
                    _stat_entry(runtime.staging_descriptor, ready_name) is not None
                    or _stat_entry(runtime.staging_descriptor, entry.entry_id)
                    is not None
                ):
                    return False
            elif payload_before is not None:
                try:
                    bound_ready = _load_exact_ready(runtime, entry.entry_id)
                except InvalidArgumentError:
                    if (
                        _stat_entry(runtime.staging_descriptor, entry.entry_id)
                        is not None
                    ):
                        return False
                    if _stat_entry(runtime.staging_descriptor, ready_name) is not None:
                        try:
                            rebound_ready = _load_exact_ready(
                                runtime,
                                entry.entry_id,
                                require_file=False,
                            )
                        except InvalidArgumentError:
                            return False
                        if rebound_ready != (entry, exact):
                            return False
                else:
                    if bound_ready != (entry, exact):
                        return False
                    filesystem_custody = True

    related_claims: list[_Claim] = []
    for artifact in _claim_artifacts(runtime):
        try:
            claim = _load_claim(
                runtime,
                artifact.path,
                batch_id=artifact.batch_id,
                require_files=False,
            )
        except InvalidArgumentError:
            if (
                artifact.batch_id == exact.batch_id
                and _stat_entry(
                    runtime.claims_descriptor,
                    artifact.path.name,
                )
                is not None
                and artifact.phase != "cleanup"
            ):
                return False
            continue
        claim_exact = claim.exact_metadata
        related = artifact.batch_id == exact.batch_id or (
            claim_exact is not None
            and claim_exact.capture_request_id == exact.capture_request_id
        )
        if not related:
            continue
        if (
            claim.custody_kind is not CustodyKind.EXACT_STAGED_ENTRY
            or not _claim_matches_exact_candidate(claim, entry, exact)
        ):
            return False
        related_claims.append(claim)
    if len(related_claims) > 1:
        return False

    claim_custody = _exact_claims_have_custody(
        runtime,
        entry,
        exact,
        tuple(related_claims),
    )
    try:
        committed = _load_exact_batch(runtime, entry, exact)
    except InvalidArgumentError:
        return False
    return committed is not None or filesystem_custody or claim_custody


def _artifact_detected_ns(
    runtime: _RuntimeRoot,
    artifact: _ClaimArtifact,
) -> int:
    metadata = _stat_entry(runtime.claims_descriptor, artifact.path.name)
    return 0 if metadata is None else metadata.st_mtime_ns


def _recovery_issue(
    artifact: str,
    code: str,
    detected_at_ns: int,
) -> CaptureRecoveryIssue:
    issue_id = "cri_" + hashlib.sha256(f"{artifact}\0{code}".encode()).hexdigest()[:32]
    return CaptureRecoveryIssue(
        issue_id=issue_id,
        code=code,  # type: ignore[arg-type]
        detected_at_ns=detected_at_ns,
    )


def _recovery_issue_snapshot(issues: list[CaptureRecoveryIssue]) -> str:
    """Bind one page to the exact content-free issue set that produced it."""
    digest = hashlib.sha256()
    for issue in issues:
        digest.update(issue.issue_id.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def _recovery_issue_offset(
    cursor: str | None,
    *,
    store_id: str,
    snapshot: str,
    total: int,
) -> int:
    """Resolve one page offset from a Store- and snapshot-bound cursor.

    This list is derived from the staging directory rather than a table, so it
    carries no rowid to anchor to. The snapshot digest is the anchor: an issue
    set that changed underneath a cursor fails closed like every other paged
    surface instead of silently skipping or repeating an issue.
    """
    if cursor is None:
        return 0
    raw = _decode_cursor(cursor)
    after = raw.get("after")
    if (
        raw.get("operation") != _RECOVERY_ISSUE_OPERATION
        or raw.get("store") != store_id
        or raw.get("snapshot") != snapshot
        or raw.get("upper") != total
        or isinstance(after, bool)
        or not isinstance(after, int)
        or not 0 <= after <= total
    ):
        raise StaleCursorError("recovery issue cursor is invalid")
    return after


@contextmanager
def _scan_lease(runtime: _RuntimeRoot) -> Iterator[int]:
    """Serialize scanners without blocking unrelated Store writers.

    The empty private lock is only a process lease. All durable scheduling
    authority lives in the encrypted database, never in this lock file.
    """
    _verify_runtime_root(runtime)
    descriptor = os.open(
        _SCAN_LOCK,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
        dir_fd=runtime.root_descriptor,
    )
    locked = False
    try:
        _verify_scan_lease(runtime, descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StoreBusyError("Store Inbox scanner is busy") from error
        locked = True
        _verify_scan_lease(runtime, descriptor)
        yield descriptor
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _verify_scan_lease(runtime: _RuntimeRoot, descriptor: int) -> None:
    _verify_runtime_root(runtime)
    held = os.fstat(descriptor)
    named = _stat_entry(runtime.root_descriptor, _SCAN_LOCK)
    if (
        not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != 0o600
        or held.st_nlink != 1
        or held.st_size != 0
        or named is None
        or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
    ):
        raise InvalidArgumentError("Store Inbox scanner lock changed")


def _scan_token(connection: Connection) -> str | None:
    row = connection.execute(
        "SELECT token FROM inbox_scan_progress WHERE singleton = 1"
    ).fetchone()
    if row is None:
        return None
    token = row[0]
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise InvalidArgumentError("Store Inbox progress is invalid")
    return token


def _read_scan_roster(
    runtime: _RuntimeRoot, token: str | None
) -> list[tuple[int, str]]:
    """Load immutable cohort names outside the Store writer section."""
    if token is None:
        return []
    identity = _database_runtime_identity(runtime.paths)
    connection = open_database(runtime.paths, load_master_key(identity), read_only=True)
    try:
        rows = connection.execute(
            "SELECT ordinal, name FROM inbox_scan_candidates "
            "WHERE token = ? ORDER BY ordinal",
            (token,),
        ).fetchall()
    finally:
        connection.close()
    roster: list[tuple[int, str]] = []
    for ordinal, name in rows:
        if (
            not isinstance(ordinal, int)
            or ordinal < 0
            or not isinstance(name, str)
            or not _safe_entry_name(name)
            or name.startswith(".")
        ):
            raise InvalidArgumentError("Store Inbox progress is invalid")
        roster.append((ordinal, name))
    return roster


def _scan_roster_chunks(
    roster: list[tuple[int, str]],
) -> Iterator[list[tuple[int, str]]]:
    """Bound every scheduler write by rows and encoded metadata bytes."""
    chunk: list[tuple[int, str]] = []
    size = 0
    for item in roster:
        item_size = len(item[1].encode("utf-8")) + 64
        if item_size > _SCAN_METADATA_BYTES:
            raise InvalidArgumentError("Store Inbox progress name is too large")
        if chunk and (
            len(chunk) >= _SCAN_METADATA_ROWS or size + item_size > _SCAN_METADATA_BYTES
        ):
            yield chunk
            chunk = []
            size = 0
        chunk.append(item)
        size += item_size
    if chunk:
        yield chunk


def _cleanup_scan_rosters(
    runtime: _RuntimeRoot,
    lease: int,
    active_token: str | None,
) -> None:
    """Retire crash-left inactive cohorts in bounded indexed transactions."""
    while True:
        # Read and size filename metadata before acquiring the writer, just as
        # for population/consumption. APFS bounds filename characters rather
        # than UTF-8 bytes, so a 64-row-only cleanup is not a byte bound.
        _verify_scan_lease(runtime, lease)
        identity = _database_runtime_identity(runtime.paths)
        reader = open_database(runtime.paths, load_master_key(identity), read_only=True)
        try:
            if active_token is None:
                rows = reader.execute(
                    "SELECT token, ordinal, name FROM inbox_scan_candidates "
                    "ORDER BY token, ordinal LIMIT ?",
                    (_SCAN_METADATA_ROWS,),
                ).fetchall()
            else:
                # Two index ranges avoid walking an arbitrarily large active
                # cohort merely to discover there are no inactive rows.
                rows = reader.execute(
                    "SELECT token, ordinal, name FROM inbox_scan_candidates "
                    "WHERE token < ? ORDER BY token, ordinal LIMIT ?",
                    (active_token, _SCAN_METADATA_ROWS),
                ).fetchall()
                if not rows:
                    rows = reader.execute(
                        "SELECT token, ordinal, name FROM inbox_scan_candidates "
                        "WHERE token > ? ORDER BY token, ordinal LIMIT ?",
                        (active_token, _SCAN_METADATA_ROWS),
                    ).fetchall()
        finally:
            reader.close()
        if not rows:
            return
        names = [(index, str(row[2])) for index, row in enumerate(rows)]
        chunk = next(_scan_roster_chunks(names))
        parameters = [(rows[index][0], rows[index][1]) for index, _name in chunk]
        with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
            _verify_scan_lease(runtime, lease)
            with _writer_transaction(runtime.paths) as connection:
                if _scan_token(connection) != active_token:
                    raise StoreBusyError("Store Inbox progress changed")
                connection.executemany(
                    "DELETE FROM inbox_scan_candidates WHERE token = ? AND ordinal = ?",
                    parameters,
                )
            _checkpoint("scan.roster_cleanup_commit")


def _publish_scan_roster(
    runtime: _RuntimeRoot,
    lease: int,
    previous_token: str | None,
    roster: list[tuple[int, str]],
) -> str:
    """Stage a fixed cohort, releasing the writer between bounded chunks.

    A partial cohort has no active pointer and is safely reclaimed on restart.
    New arrivals never extend an active cohort and cannot delay its tail.
    """
    cohort_id = secrets.token_hex(16)
    for chunk in _scan_roster_chunks(roster):
        parameters = [(cohort_id, ordinal, name) for ordinal, name in chunk]
        with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
            _verify_scan_lease(runtime, lease)
            with _writer_transaction(runtime.paths) as connection:
                if _scan_token(connection) != previous_token:
                    raise StoreBusyError("Store Inbox progress changed")
                connection.executemany(
                    "INSERT INTO inbox_scan_candidates (token, ordinal, name) "
                    "VALUES (?, ?, ?)",
                    parameters,
                )
            _checkpoint("scan.roster_chunk_commit")
    with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
        _verify_scan_lease(runtime, lease)
        with _writer_transaction(runtime.paths) as connection:
            if _scan_token(connection) != previous_token:
                raise StoreBusyError("Store Inbox progress changed")
            connection.execute(
                "INSERT INTO inbox_scan_progress (singleton, token) VALUES (1, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET token = excluded.token",
                (cohort_id,),
            )
        _checkpoint("scan.roster_publish_commit")
    return cohort_id


def _consume_scan_roster(
    runtime: _RuntimeRoot,
    lease: int,
    token: str,
    consumed: list[tuple[int, str]],
) -> None:
    for chunk in _scan_roster_chunks(consumed):
        parameters = [(token, ordinal) for ordinal, _name in chunk]
        with _writer_lock(runtime.paths, root_descriptor=runtime.root_descriptor):
            _verify_scan_lease(runtime, lease)
            with _writer_transaction(runtime.paths) as connection:
                if _scan_token(connection) != token:
                    raise StoreBusyError("Store Inbox progress changed")
                connection.executemany(
                    "DELETE FROM inbox_scan_candidates WHERE token = ? AND ordinal = ?",
                    parameters,
                )
            _checkpoint("scan.roster_consume_commit")


def _scan_inbox(
    paths: RuntimePaths,
    authorship: Authorship,
    sensitivity: Sensitivity,
    *,
    clock: Clock | None,
    policy: ScanPolicy,
) -> InboxBatch:
    active_clock = SystemClock() if clock is None else clock
    with (
        _open_runtime_root(paths) as runtime,
        _scan_lease(runtime) as lease,
        _database_directory_authority(
            paths, runtime.root_descriptor, lambda: _verify_scan_lease(runtime, lease)
        ),
    ):
        with _writer_lock(paths, root_descriptor=runtime.root_descriptor):
            _verify_scan_lease(runtime, lease)
            recovered = _recover_claim(runtime)
            if recovered is not None:
                return recovered
            with _writer_transaction(paths) as connection:
                cohort_id = _scan_token(connection)
        _cleanup_scan_rosters(runtime, lease, cohort_id)
        roster = _read_scan_roster(runtime, cohort_id)
        first, issue_counts = _visible_regular_files(runtime.inbox_descriptor, policy)
        if not roster:
            if not first:
                _raise_all_ineligible(issue_counts)
            roster = [(ordinal, item.name) for ordinal, item in enumerate(first)]
            cohort_id = _publish_scan_roster(runtime, lease, cohort_id, roster)
        assert cohort_id is not None
        by_name = {item.name: item for item in first}
        if any(name in by_name for _ordinal, name in roster):
            active_clock.sleep(policy.settle_seconds)
        _verify_scan_lease(runtime, lease)
        second, _ = _visible_regular_files(runtime.inbox_descriptor, policy)
        second_by_name = {item.name: item for item in second}
        settled: list[_VisibleCandidate] = []
        consumed_names: set[str] = set()
        roster_names = {name for _ordinal, name in roster}
        for _ordinal, name in roster:
            item = by_name.get(name)
            if item is not None and second_by_name.get(name) == item:
                settled.append(item)
            else:
                issue_counts["changed"] += 1
                consumed_names.add(name)
        selected, deferred, attempted = _select_within_limits(
            runtime.inbox_descriptor,
            settled,
            policy,
            issue_counts,
        )
        consumed_names.update(attempted)
        consumed = [item for item in roster if item[1] in consumed_names]
        has_more = deferred > 0 or any(
            name not in roster_names for name in second_by_name
        )
        _checkpoint("scan.observation_complete")
        _verify_scan_lease(runtime, lease)
        _consume_scan_roster(runtime, lease, cohort_id, consumed)
        with _writer_lock(paths, root_descriptor=runtime.root_descriptor):
            _verify_scan_lease(runtime, lease)
            _checkpoint("scan.progress_commit")
            recovered = _recover_claim(runtime)
            if recovered is not None:
                return recovered
            if not selected:
                _raise_all_ineligible(issue_counts)
            claim = _create_claim(
                runtime,
                batch_id=f"bat_{secrets.token_hex(16)}",
                sealed_at=int(active_clock.time()),
                authorship=authorship,
                sensitivity=sensitivity,
                entries=selected,
                issues=issue_counts,
                has_more=has_more,
            )
            return _publish_and_cleanup(runtime, claim)


def _exact_ready_batch_ids(runtime: _RuntimeRoot) -> set[str]:
    """Batch ids a valid private exact-ready manifest already speaks for.

    A claim artifact carrying one of these is an exact capture's, not an
    ordinary scan's, however it happens to load. Both the recovery path and
    the report derive the set the same way so they cannot disagree about which
    claims are ordinary.
    """
    batch_ids: set[str] = set()
    for name in os.listdir(runtime.staging_descriptor):
        if not name.endswith(_EXACT_READY_SUFFIX):
            continue
        try:
            _entry, exact = _load_exact_ready(
                runtime,
                name[: -len(_EXACT_READY_SUFFIX)],
                require_file=False,
            )
        except InvalidArgumentError:
            continue
        batch_ids.add(exact.batch_id)
    return batch_ids


def _recover_claim(runtime: _RuntimeRoot) -> InboxBatch | None:
    artifacts = _claim_artifacts(runtime)
    exact_batch_ids = _exact_ready_batch_ids(runtime)

    ordinary: list[tuple[_ClaimArtifact, _Claim | None]] = []
    for artifact in artifacts:
        try:
            claim = _load_claim(
                runtime,
                artifact.path,
                batch_id=artifact.batch_id,
                require_files=False,
            )
        except InvalidArgumentError:
            if artifact.batch_id in exact_batch_ids:
                continue
            ordinary.append((artifact, None))
            continue
        if claim.custody_kind is CustodyKind.EXACT_STAGED_ENTRY:
            continue
        ordinary.append((artifact, claim))

    claims = [
        artifact for artifact, _claim in ordinary if artifact.phase == "published"
    ]

    for artifact, loaded_claim in (
        item for item in ordinary if item[0].phase == "cleanup"
    ):
        if loaded_claim is None:
            published = _load_published_batch_id(runtime, artifact.batch_id)
            _remove_claim_artifact(runtime, artifact.path)
        else:
            published = _load_published_batch(runtime, loaded_claim)
            _cleanup_claim(runtime, loaded_claim)
        if published is not None:
            return published

    for artifact, loaded_claim in (
        item for item in ordinary if item[0].phase == "creating"
    ):
        if loaded_claim is None:
            _remove_claim_artifact(runtime, artifact.path)
            continue
        claim = loaded_claim
        claim = _publish_created_claim(runtime, claim)
        claims.append(
            _ClaimArtifact(
                path=claim.path,
                batch_id=claim.batch_id,
                phase="published",
            )
        )

    if not claims:
        return None
    if len(claims) != 1:
        raise InvalidArgumentError("Store has multiple active claims")
    claim = _load_claim(
        runtime,
        claims[0].path,
        batch_id=claims[0].batch_id,
    )
    published = _load_published_batch(runtime, claim)
    if published is not None:
        _cleanup_claim(runtime, claim)
        return published
    _complete_claim(runtime, claim)
    return _publish_and_cleanup(runtime, claim)


def _create_claim(
    runtime: _RuntimeRoot,
    *,
    batch_id: str,
    sealed_at: int,
    authorship: Authorship,
    sensitivity: Sensitivity,
    entries: list[_VisibleFile],
    issues: Counter[str],
    has_more: bool,
) -> _Claim:
    _verify_runtime_root(runtime)
    claims_descriptor = runtime.claims_descriptor
    temporary_name = f".create-{batch_id}-{secrets.token_hex(8)}.tmp"
    try:
        os.mkdir(temporary_name, mode=0o700, dir_fd=claims_descriptor)
        _checkpoint("claim.create.temp_mkdir")
        os.fsync(claims_descriptor)
        _checkpoint("claim.create.temp_parent_fsync")
    except OSError as error:
        raise InvalidArgumentError("Store claim path is unavailable") from error
    claim_path = runtime.paths.inbox_claims / temporary_name
    claim_descriptor = _open_directory_at(claims_descriptor, temporary_name)
    try:
        os.mkdir(_CLAIM_FILES, mode=0o700, dir_fd=claim_descriptor)
        _checkpoint("claim.create.files_mkdir")
        os.fsync(claim_descriptor)
        _checkpoint("claim.create.files_parent_fsync")
    except OSError as error:
        raise InvalidArgumentError("Store claim path is unavailable") from error
    finally:
        os.close(claim_descriptor)
    claim = _Claim(
        path=claim_path,
        batch_id=batch_id,
        custody_kind=CustodyKind.INBOX_SCAN,
        source_origin=SourceCaptureOrigin.INBOX,
        capture_request_id=None,
        exact_metadata=None,
        sealed_at=sealed_at,
        authorship=authorship,
        sensitivity=sensitivity,
        entries=list(entries),
        issues=Counter(issues),
        has_more=has_more,
    )
    _write_claim(runtime, claim, phase="claim.create")
    claim = _publish_created_claim(runtime, claim)
    _complete_claim(runtime, claim)
    return claim


def _create_exact_claim(
    runtime: _RuntimeRoot,
    entry: PrivateStagedEntry,
    metadata: ExactCaptureMetadata,
) -> _Claim:
    """Publish a recoverable claim before moving exact private bytes."""
    _verify_runtime_root(runtime)
    staged = _verify_private_file(runtime, entry)
    visible = _VisibleFile(
        entry_id=entry.entry_id,
        name=entry.display_name,
        device=staged.st_dev,
        inode=staged.st_ino,
        size=staged.st_size,
        modified_ns=staged.st_mtime_ns,
        sha256=entry.sha256,
    )
    claims_descriptor = runtime.claims_descriptor
    temporary_name = f".create-{metadata.batch_id}-{secrets.token_hex(8)}.tmp"
    try:
        os.mkdir(temporary_name, mode=0o700, dir_fd=claims_descriptor)
        _checkpoint("exact.claim_temp_mkdir")
        os.fsync(claims_descriptor)
        claim_descriptor = _open_directory_at(claims_descriptor, temporary_name)
        try:
            os.mkdir(_CLAIM_FILES, mode=0o700, dir_fd=claim_descriptor)
            os.fsync(claim_descriptor)
        finally:
            os.close(claim_descriptor)
    except OSError as error:
        raise InvalidArgumentError("exact claim path is unavailable") from error
    claim = _Claim(
        path=runtime.paths.inbox_claims / temporary_name,
        batch_id=metadata.batch_id,
        custody_kind=CustodyKind.EXACT_STAGED_ENTRY,
        source_origin=metadata.source_origin,
        capture_request_id=metadata.capture_request_id,
        exact_metadata=metadata,
        sealed_at=metadata.captured_at,
        authorship=metadata.authorship,
        sensitivity=metadata.sensitivity,
        entries=[visible],
        issues=Counter(),
        has_more=False,
    )
    _write_claim(runtime, claim, phase="exact.claim")
    claim = _publish_created_claim(runtime, claim)
    _checkpoint("exact.claim_manifest_publication")
    _complete_claim(runtime, claim)
    return claim


def _publish_created_claim(runtime: _RuntimeRoot, claim: _Claim) -> _Claim:
    _verify_runtime_root(runtime)
    claims_descriptor = runtime.claims_descriptor
    try:
        if claim.path.name != claim.batch_id:
            os.rename(
                claim.path.name,
                claim.batch_id,
                src_dir_fd=claims_descriptor,
                dst_dir_fd=claims_descriptor,
            )
            _checkpoint("claim.create.publish_rename")
        os.fsync(claims_descriptor)
        _checkpoint("claim.create.publish_dir_fsync")
    except OSError as error:
        raise InvalidArgumentError("Store claim path is unavailable") from error
    claim.path = runtime.paths.inbox_claims / claim.batch_id
    return claim


def _complete_claim(runtime: _RuntimeRoot, claim: _Claim) -> None:
    if claim.custody_kind is CustodyKind.EXACT_STAGED_ENTRY:
        _complete_exact_claim(runtime, claim)
        return
    _verify_runtime_root(runtime)
    inbox_descriptor = runtime.inbox_descriptor
    files_descriptor = _open_claim_files(runtime, claim)
    kept: list[_VisibleFile] = []
    try:
        files_device = os.fstat(files_descriptor).st_dev
        inbox_device = os.fstat(inbox_descriptor).st_dev
        for entry in claim.entries:
            if not _safe_entry_name(entry.name):
                raise InvalidArgumentError("Store claim contains an unsafe name")
            claimed = _stat_entry(files_descriptor, entry.name)
            if claimed is not None:
                if _matches_visible(claimed, entry, containing_device=files_device):
                    kept.append(entry)
                else:
                    _restore_claimed_entry(runtime, claim, entry)
                    claim.issues["changed"] += 1
                continue
            visible = _stat_entry(inbox_descriptor, entry.name)
            if visible is None or not _matches_visible(
                visible,
                entry,
                containing_device=inbox_device,
            ):
                claim.issues["changed"] += 1
                continue
            try:
                _rename_no_replace(
                    entry.name,
                    entry.name,
                    source_descriptor=inbox_descriptor,
                    destination_descriptor=files_descriptor,
                )
                _checkpoint("claim.custody.source_rename")
            except OSError as error:
                raise InvalidArgumentError(
                    "Store could not claim an inbox source"
                ) from error
            moved = _stat_entry(files_descriptor, entry.name)
            if moved is None or not _matches_visible(
                moved,
                entry,
                containing_device=files_device,
            ):
                if moved is not None:
                    _restore_claimed_entry(runtime, claim, entry)
                claim.issues["changed"] += 1
                continue
            kept.append(entry)
        os.fsync(inbox_descriptor)
        _checkpoint("claim.custody.inbox_dir_fsync")
        os.fsync(files_descriptor)
        _checkpoint("claim.custody.files_dir_fsync")
    finally:
        os.close(files_descriptor)
    claim.entries = kept
    _write_claim(runtime, claim, phase="claim.custody")
    if not claim.entries:
        counts = Counter(claim.issues)
        _cleanup_claim(runtime, claim)
        _raise_all_ineligible(counts)


def _complete_exact_claim(runtime: _RuntimeRoot, claim: _Claim) -> None:
    """Move one manifest-bound private entry into exact claim custody."""
    _verify_runtime_root(runtime)
    if claim.exact_metadata is None or len(claim.entries) != 1:
        raise InvalidArgumentError("exact claim metadata is invalid")
    entry = claim.entries[0]
    files_descriptor = _open_claim_files(runtime, claim)
    try:
        files_device = os.fstat(files_descriptor).st_dev
        claimed = _stat_entry(files_descriptor, entry.name)
        if claimed is None:
            staged = _stat_entry(runtime.staging_descriptor, entry.entry_id)
            if staged is None or not _matches_visible(
                staged,
                entry,
                containing_device=_staging_device(runtime),
            ):
                raise InvalidArgumentError("exact staged custody is unavailable")
            _rename_no_replace(
                entry.entry_id,
                entry.name,
                source_descriptor=runtime.staging_descriptor,
                destination_descriptor=files_descriptor,
            )
            _checkpoint("exact.staged_to_claim_move")
            claimed = _stat_entry(files_descriptor, entry.name)
        if claimed is None or not _matches_visible(
            claimed,
            entry,
            containing_device=files_device,
        ):
            raise InvalidArgumentError("exact claim custody is mismatched")
        os.fsync(runtime.staging_descriptor)
        os.fsync(files_descriptor)
        _checkpoint("exact.claim_files_directory_fsync")
    finally:
        os.close(files_descriptor)
    _write_claim(runtime, claim, phase="exact.custody")


def _publish_and_cleanup(runtime: _RuntimeRoot, claim: _Claim) -> InboxBatch:
    captures: list[_Capture] = []
    kept: list[_VisibleFile] = []
    files_descriptor = _open_claim_files(runtime, claim)
    try:
        for entry in claim.entries:
            try:
                capture = _read_unchanged(files_descriptor, entry)
            except (NoEligibleSourcesError, OSError) as error:
                if claim.custody_kind is CustodyKind.EXACT_STAGED_ENTRY:
                    raise InvalidArgumentError(
                        "exact claim custody is mismatched"
                    ) from error
                _restore_claimed_entry(runtime, claim, entry)
                claim.issues["changed"] += 1
                continue
            captures.append(capture)
            kept.append(entry)
    finally:
        os.close(files_descriptor)
    claim.entries = kept
    _write_claim(runtime, claim, phase="claim.capture")
    if not captures:
        counts = Counter(claim.issues)
        _cleanup_claim(runtime, claim)
        _raise_all_ineligible(counts)

    batch = _publish_claim(runtime, claim, captures)
    if claim.custody_kind is CustodyKind.EXACT_STAGED_ENTRY:
        _checkpoint("exact.database_commit")
        try:
            _cleanup_claim(runtime, claim)
        except InvalidArgumentError:
            # Exact recovery has a durable batch at this point.  A cleanup
            # retry is safe, but an error must not hide the committed result.
            pass
    else:
        _cleanup_claim(runtime, claim)
    return batch


def _publish_claim(
    runtime: _RuntimeRoot,
    claim: _Claim,
    captures: list[_Capture],
) -> InboxBatch:
    _verify_runtime_root(runtime)
    source_ids: list[str] = []
    with _writer_transaction(runtime.paths) as connection:
        existing = _batch_from_connection(connection, claim)
        if existing is not None:
            return existing
        connection.execute(
            "INSERT INTO inbox_batches "
            "(batch_id, capture_request_id, sealed_at, source_count, has_more) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                claim.batch_id,
                claim.capture_request_id,
                claim.sealed_at,
                len(captures),
                int(claim.has_more),
            ),
        )
        for issue in _issues(claim.issues):
            connection.execute(
                "INSERT INTO inbox_batch_issues (batch_id, code, count) "
                "VALUES (?, ?, ?)",
                (claim.batch_id, issue.code, issue.count),
            )
        filename_indexed = _filename_is_indexed(connection)
        capture_rowid_indexed = source_projection_uses_capture_rowid(connection)
        for ordinal, capture in enumerate(captures):
            digest = hashlib.sha256(capture.original_bytes).hexdigest()
            row = connection.execute(
                "SELECT blob_id FROM source_blobs WHERE sha256 = ?",
                (digest,),
            ).fetchone()
            if row is None:
                blob_id = f"blb_{secrets.token_hex(16)}"
                connection.execute(
                    "INSERT INTO source_blobs "
                    "(blob_id, sha256, byte_length, original_bytes, utf8_text) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        blob_id,
                        digest,
                        len(capture.original_bytes),
                        capture.original_bytes,
                        retained_utf8_text(capture.original_bytes),
                    ),
                )
            else:
                blob_id = str(row[0])
            source_id = f"src_{secrets.token_hex(16)}"
            source_ids.append(source_id)
            inserted_source = connection.execute(
                "INSERT INTO sources "
                "(source_id, blob_id, batch_id, origin, original_name, media_type, "
                "authorship, sensitivity, captured_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    source_id,
                    blob_id,
                    claim.batch_id,
                    claim.source_origin.value,
                    capture.name,
                    capture.media_type,
                    claim.authorship.value,
                    claim.sensitivity.value,
                    claim.sealed_at,
                ),
            )
            source_rowid = inserted_source.lastrowid
            if not isinstance(source_rowid, int) or source_rowid <= 0:
                raise RuntimeError("source capture rowid is unavailable")
            connection.execute(
                "INSERT INTO inbox_batch_sources (batch_id, source_id, ordinal) "
                "VALUES (?, ?, ?)",
                (claim.batch_id, source_id, ordinal),
            )
            if capture.utf8_text is not None:
                _index_capture(
                    connection,
                    source_id,
                    source_rowid,
                    capture,
                    filename_indexed,
                    capture_rowid_indexed,
                )
        duplicates = _duplicate_captures(connection, claim.batch_id)
    return InboxBatch(
        batch_id=claim.batch_id,
        sealed_at=claim.sealed_at,
        source_count=len(source_ids),
        source_ids=tuple(source_ids),
        issues=_issues(claim.issues),
        has_more=claim.has_more,
        duplicates=duplicates,
    )


def _filename_is_indexed(connection: Connection) -> bool:
    """Report whether this Store's source projection carries the filename.

    FTS5 has no `ALTER TABLE ADD COLUMN`, so the additive healing that repairs
    an ordinary table cannot reach this one: a Store carried forward from
    before the column existed keeps the two-column projection until its owner
    runs `memory reindex`. Capture asks rather than assumes, because a scan
    has already moved the owner's files out of the inbox into claim custody by
    the time it writes here -- so assuming would strand a batch behind an
    untyped driver error after the inbox was already empty.
    """
    return any(
        str(row[1]) == "original_name"
        for row in connection.execute("PRAGMA table_info(source_fts)").fetchall()
    )


def _index_capture(
    connection: Connection,
    source_id: str,
    source_rowid: int,
    capture: _Capture,
    filename_indexed: bool,
    capture_rowid_indexed: bool,
) -> None:
    """Project one capture's searchable text, and its name where that exists."""
    if capture_rowid_indexed:
        connection.execute(
            "INSERT INTO source_fts "
            "(rowid, source_id, capture_rowid, utf8_text, original_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (source_rowid, source_id, source_rowid, capture.utf8_text, capture.name),
        )
        return
    if filename_indexed:
        connection.execute(
            "INSERT INTO source_fts (source_id, utf8_text, original_name) "
            "VALUES (?, ?, ?)",
            (source_id, capture.utf8_text, capture.name),
        )
        return
    connection.execute(
        "INSERT INTO source_fts (source_id, utf8_text) VALUES (?, ?)",
        (source_id, capture.utf8_text),
    )


_DUPLICATE_CAPTURES_SQL = (
    "SELECT capture.source_id, ("
    "SELECT earlier.source_id FROM sources AS earlier "
    "WHERE earlier.blob_id = capture.blob_id AND earlier.rowid < capture.rowid "
    "ORDER BY earlier.rowid LIMIT 1"
    ") FROM sources AS capture "
    "JOIN inbox_batch_sources AS membership "
    "ON membership.source_id = capture.source_id "
    "WHERE membership.batch_id = ? ORDER BY membership.ordinal"
)


def _duplicate_captures(
    connection: Connection,
    batch_id: str,
) -> tuple[DuplicateCapture, ...]:
    """Name the earlier capture of every blob this batch did not introduce.

    This runs inside the publishing transaction because that is the one place
    that already holds both the digest and an open connection; the scan itself
    opens no database at all, and giving it one to answer this would mean a
    second pass over custody outside the transaction that decides it.

    `rowid` ordering is insertion order, which is the only ordering `sources`
    has that answers "which capture came first" -- `captured_at` is one value
    per batch and ties for every capture in it. Two identical files inside one
    batch therefore report the second against the first, correctly: the review
    work is redundant either way.

    Deduplication itself is unchanged and stays a storage fact. Both captures
    keep their own provenance and sensitivity, and this reports only that the
    bytes have been reviewed before.
    """
    rows = connection.execute(_DUPLICATE_CAPTURES_SQL, (batch_id,)).fetchall()
    return tuple(
        DuplicateCapture(source_id=str(row[0]), duplicate_of=str(row[1]))
        for row in rows
        if row[1] is not None
    )


def _load_published_batch(
    runtime: _RuntimeRoot,
    claim: _Claim,
) -> InboxBatch | None:
    _verify_runtime_root(runtime)
    identity = _database_runtime_identity(runtime.paths)
    connection = open_database(
        runtime.paths,
        load_master_key(identity),
        read_only=True,
    )
    try:
        return _batch_from_connection(connection, claim)
    finally:
        connection.close()


def _load_published_batch_id(
    runtime: _RuntimeRoot,
    batch_id: str,
) -> InboxBatch | None:
    _verify_runtime_root(runtime)
    identity = _database_runtime_identity(runtime.paths)
    connection = open_database(
        runtime.paths,
        load_master_key(identity),
        read_only=True,
    )
    try:
        row = connection.execute(
            "SELECT sealed_at, source_count, has_more "
            "FROM inbox_batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            return None
        source_ids = tuple(
            str(source_row[0])
            for source_row in connection.execute(
                "SELECT source_id FROM inbox_batch_sources "
                "WHERE batch_id = ? ORDER BY ordinal",
                (batch_id,),
            ).fetchall()
        )
        if int(row[1]) != len(source_ids):
            raise InvalidArgumentError("Store batch publication is incomplete")
        issues = _issues_from_connection(connection, batch_id)
        has_more = _stored_has_more(row[2])
        return InboxBatch(
            batch_id=batch_id,
            sealed_at=int(row[0]),
            source_count=int(row[1]),
            source_ids=source_ids,
            issues=issues,
            has_more=has_more,
            duplicates=_duplicate_captures(connection, batch_id),
        )
    finally:
        connection.close()


def _batch_from_connection(
    connection: Connection,
    claim: _Claim,
) -> InboxBatch | None:
    row = connection.execute(
        "SELECT capture_request_id, sealed_at, source_count, has_more "
        "FROM inbox_batches WHERE batch_id = ?",
        (claim.batch_id,),
    ).fetchone()
    if row is None:
        return None
    source_ids = tuple(
        str(source_row[0])
        for source_row in connection.execute(
            "SELECT source_id FROM inbox_batch_sources "
            "WHERE batch_id = ? ORDER BY ordinal",
            (claim.batch_id,),
        ).fetchall()
    )
    issues = _issues_from_connection(connection, claim.batch_id)
    has_more = _stored_has_more(row[3])
    source_metadata = connection.execute(
        "SELECT s.origin, s.authorship, s.sensitivity, s.captured_at, b.sha256, "
        "b.byte_length FROM sources AS s "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "JOIN inbox_batch_sources AS membership ON membership.source_id = s.source_id "
        "WHERE membership.batch_id = ? ORDER BY membership.ordinal",
        (claim.batch_id,),
    ).fetchall()
    expected_sources = tuple(
        (
            claim.source_origin.value,
            claim.authorship.value,
            claim.sensitivity.value,
            claim.sealed_at,
            entry.sha256,
            entry.size,
        )
        for entry in claim.entries
    )
    if (
        row[0] != claim.capture_request_id
        or (int(row[1]), int(row[2])) != (claim.sealed_at, len(source_ids))
        or issues != _issues(claim.issues)
        or has_more != claim.has_more
        or tuple(source_metadata) != expected_sources
    ):
        raise InvalidArgumentError("Store claim does not match its publication")
    return InboxBatch(
        batch_id=claim.batch_id,
        sealed_at=int(row[1]),
        source_count=int(row[2]),
        source_ids=source_ids,
        issues=issues,
        has_more=has_more,
        duplicates=_duplicate_captures(connection, claim.batch_id),
    )


def _restore_claimed_entry(
    runtime: _RuntimeRoot,
    claim: _Claim,
    entry: _VisibleFile,
) -> None:
    _verify_runtime_root(runtime)
    inbox_descriptor = runtime.inbox_descriptor
    files_descriptor = _open_claim_files(runtime, claim)
    try:
        if _stat_entry(inbox_descriptor, entry.name) is not None:
            raise StoreBusyError("Store inbox source restore is blocked")
        try:
            _rename_no_replace(
                entry.name,
                entry.name,
                source_descriptor=files_descriptor,
                destination_descriptor=inbox_descriptor,
            )
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                raise StoreBusyError("Store inbox source restore is blocked") from error
            raise
        os.fsync(files_descriptor)
        os.fsync(inbox_descriptor)
    except OSError as error:
        raise InvalidArgumentError("Store cannot safely restore a claim") from error
    finally:
        os.close(files_descriptor)


def _rename_no_replace(
    source_name: str,
    destination_name: str,
    *,
    source_descriptor: int,
    destination_descriptor: int,
) -> None:
    """Atomically move one directory entry without replacing its destination."""
    if not _safe_entry_name(source_name) or not _safe_entry_name(destination_name):
        raise OSError(errno.EINVAL, "unsafe Store source name")
    binding = _BOUND_RENAME.get()
    if binding is not None:
        if (
            source_name != binding.source_name
            or destination_name != binding.destination_name
            or source_descriptor != binding.source_directory_descriptor
            or destination_descriptor != binding.destination_directory_descriptor
            or not _bound_rename_source_matches(binding)
        ):
            raise OSError(errno.ESTALE, "Store source binding changed before rename")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameatx = library.renameatx_np
    except AttributeError as error:  # pragma: no cover - the Store is macOS-only
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
        source_descriptor,
        os.fsencode(source_name),
        destination_descriptor,
        os.fsencode(destination_name),
        _RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _rename_bound_no_replace(
    source_name: str,
    destination_name: str,
    *,
    source_descriptor: int,
    destination_descriptor: int,
    bound_descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
    quarantine_descriptor: int,
) -> None:
    """Rename only while the final source name still denotes the bound inode."""
    binding = _BoundRename(
        source_name=source_name,
        destination_name=destination_name,
        source_directory_descriptor=source_descriptor,
        destination_directory_descriptor=destination_descriptor,
        source_descriptor=bound_descriptor,
        expected_identity=expected_identity,
        expected_sha256=expected_sha256,
    )
    reset_handle = _BOUND_RENAME.set(binding)
    try:
        _rename_no_replace(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )
    finally:
        _BOUND_RENAME.reset(reset_handle)
    if _bound_rename_destination_matches(binding):
        return
    restored = _restore_quarantined_replacement(
        None,
        destination_name,
        source_name,
        source_descriptor=destination_descriptor,
        destination_descriptor=source_descriptor,
    )
    if not restored:
        _restore_quarantined_replacement(
            None,
            destination_name,
            _WITHDRAWAL_CHILD,
            source_descriptor=destination_descriptor,
            destination_descriptor=quarantine_descriptor,
        )
    for descriptor in (
        source_descriptor,
        destination_descriptor,
        quarantine_descriptor,
    ):
        try:
            os.fsync(descriptor)
        except OSError:
            pass
    raise OSError(errno.ESTALE, "Store source changed during exclusive rename")


def _bound_rename_side_matches(
    binding: _BoundRename,
    directory_descriptor: int,
    name: str,
) -> bool:
    """Prove one side of a bound rename still names the retained payload.

    Both directions of the rollback ask the identical question of a different
    pathname: does this name, together with the descriptor held across the
    move, still denote one stable file of the expected identity and digest?
    They share an implementation because a fix applied to one copy and not the
    other would leave the rollback verifying one direction more weakly than
    the other -- and which direction is the weak one would depend on where the
    crash landed.
    """
    try:
        descriptor_before = os.fstat(binding.source_descriptor)
        path_before = _stat_entry(directory_descriptor, name)
        digest = _descriptor_sha256(binding.source_descriptor)
        descriptor_after = os.fstat(binding.source_descriptor)
        path_after = _stat_entry(directory_descriptor, name)
        return (
            path_before is not None
            and path_after is not None
            and _publication_identity(descriptor_before) == binding.expected_identity
            and _publication_identity(descriptor_after) == binding.expected_identity
            and _publication_identity(path_before) == binding.expected_identity
            and _publication_identity(path_after) == binding.expected_identity
            and _publication_stability(descriptor_before)
            == _publication_stability(descriptor_after)
            and _publication_stability(path_before)
            == _publication_stability(path_after)
            and digest == binding.expected_sha256
        )
    except OSError:
        return False


def _bound_rename_source_matches(binding: _BoundRename) -> bool:
    """Prove the final source path and retained descriptor are one stable payload."""
    return _bound_rename_side_matches(
        binding,
        binding.source_directory_descriptor,
        binding.source_name,
    )


def _bound_rename_destination_matches(binding: _BoundRename) -> bool:
    """Prove the kernel moved the retained source rather than a raced pathname."""
    return _bound_rename_side_matches(
        binding,
        binding.destination_directory_descriptor,
        binding.destination_name,
    )


def _cleanup_claim(runtime: _RuntimeRoot, claim: _Claim) -> None:
    _verify_runtime_root(runtime)
    claims_descriptor = runtime.claims_descriptor
    try:
        cleanup_match = _CLEANUP_ARTIFACT.fullmatch(claim.path.name)
        if cleanup_match is None:
            if claim.path.name != claim.batch_id:
                raise InvalidArgumentError("Store claim identity is invalid")
            cleanup_name = f".cleanup-{claim.batch_id}-{secrets.token_hex(8)}.tmp"
            os.rename(
                claim.path.name,
                cleanup_name,
                src_dir_fd=claims_descriptor,
                dst_dir_fd=claims_descriptor,
            )
            claim.path = runtime.paths.inbox_claims / cleanup_name
            _checkpoint("claim.cleanup.hide_rename")
            os.fsync(claims_descriptor)
            _checkpoint("claim.cleanup.claims_dir_fsync")
        _remove_claim_artifact(runtime, claim.path)
    except OSError as error:
        raise InvalidArgumentError("Store claim cleanup failed") from error


def _remove_claim_artifact(
    runtime: _RuntimeRoot,
    path: Path,
) -> None:
    _verify_runtime_root(runtime)
    claims_descriptor = runtime.claims_descriptor
    claim_descriptor: int | None = None
    files_descriptor: int | None = None
    try:
        try:
            claim_descriptor = _open_directory_at(claims_descriptor, path.name)
        except InvalidArgumentError:
            if _stat_entry(claims_descriptor, path.name) is None:
                return
            raise
        try:
            files_descriptor = _open_directory_at(claim_descriptor, _CLAIM_FILES)
        except InvalidArgumentError:
            if _stat_entry(claim_descriptor, _CLAIM_FILES) is not None:
                raise
        if files_descriptor is not None:
            for name in sorted(os.listdir(files_descriptor)):
                if not _safe_entry_name(name):
                    raise InvalidArgumentError("Store claim contains an unsafe name")
                metadata = _stat_entry(files_descriptor, name)
                if metadata is None:
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    raise InvalidArgumentError("Store claim cleanup is unsafe")
                os.unlink(name, dir_fd=files_descriptor)
                _checkpoint("claim.cleanup.source_unlink")
            os.fsync(files_descriptor)
            _checkpoint("claim.cleanup.files_dir_fsync")
            os.close(files_descriptor)
            files_descriptor = None
            os.rmdir(_CLAIM_FILES, dir_fd=claim_descriptor)
            _checkpoint("claim.cleanup.files_rmdir")
            os.fsync(claim_descriptor)
            _checkpoint("claim.cleanup.claim_dir_fsync_after_files")

        for name in sorted(os.listdir(claim_descriptor)):
            if name == _CLAIM_MANIFEST or (
                name.startswith(".manifest-") and name.endswith(".tmp")
            ):
                os.unlink(name, dir_fd=claim_descriptor)
                if name == _CLAIM_MANIFEST:
                    _checkpoint("claim.cleanup.manifest_unlink")
                continue
            raise InvalidArgumentError("Store claim cleanup is unsafe")
        os.fsync(claim_descriptor)
        _checkpoint("claim.cleanup.claim_dir_fsync_after_manifest")
        os.close(claim_descriptor)
        claim_descriptor = None
        os.rmdir(path.name, dir_fd=claims_descriptor)
        os.fsync(claims_descriptor)
    except OSError as error:
        raise InvalidArgumentError("Store claim cleanup failed") from error
    finally:
        if files_descriptor is not None:
            os.close(files_descriptor)
        if claim_descriptor is not None:
            os.close(claim_descriptor)


def _claim_artifacts(runtime: _RuntimeRoot) -> list[_ClaimArtifact]:
    _verify_runtime_root(runtime)
    descriptor = runtime.claims_descriptor
    artifacts: list[_ClaimArtifact] = []
    for name in sorted(os.listdir(descriptor)):
        batch_id: str
        phase: str
        if _BATCH_ID.fullmatch(name) is not None:
            batch_id = name
            phase = "published"
        elif match := _CREATE_ARTIFACT.fullmatch(name):
            batch_id = match.group(1)
            phase = "creating"
        elif match := _CLEANUP_ARTIFACT.fullmatch(name):
            batch_id = match.group(1)
            phase = "cleanup"
        elif name.startswith("."):
            # Every claim artifact this Store mints matches one of the shapes
            # above -- its dot-prefixed temporaries included -- and hidden
            # dot-files never enter custody, so a stray dot-file (Finder's
            # .DS_Store in a browsed directory) is provably not a claim and
            # must not refuse every scan, recovery, and correction.
            continue
        else:
            raise InvalidArgumentError("Store claim identity is invalid")
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise InvalidArgumentError("Store claim path is invalid")
        artifacts.append(
            _ClaimArtifact(
                path=runtime.paths.inbox_claims / name,
                batch_id=batch_id,
                phase=phase,
            )
        )
    return artifacts


def _write_claim(
    runtime: _RuntimeRoot,
    claim: _Claim,
    *,
    phase: str,
) -> None:
    payload = {
        "authorship": claim.authorship.value,
        "batch_id": claim.batch_id,
        "capture_request_id": claim.capture_request_id,
        "captured_at": claim.sealed_at,
        "custody_kind": claim.custody_kind.value,
        "entries": [
            {
                "byte_length": entry.size,
                "device": entry.device,
                "entry_id": entry.entry_id,
                "inode": entry.inode,
                "modified_ns": entry.modified_ns,
                "name": entry.name,
                "sha256": entry.sha256,
            }
            for entry in claim.entries
        ],
        "exact_metadata": (
            {
                "expected_head_id": claim.exact_metadata.expected_head_id,
                "payload_sha256": claim.exact_metadata.payload_sha256,
                "target_lineage_id": claim.exact_metadata.target_lineage_id,
            }
            if claim.exact_metadata is not None
            else None
        ),
        "format": _CLAIM_FORMAT,
        "has_more": claim.has_more,
        "issues": {
            code: count for code, count in sorted(claim.issues.items()) if count > 0
        },
        "sensitivity": claim.sensitivity.value,
        "source_origin": claim.source_origin.value,
    }
    descriptor = _open_claim_directory(runtime, claim)
    try:
        _publish_manifest_bytes(
            _encoded_manifest(payload),
            directory_descriptor=descriptor,
            temporary_name=f".manifest-{secrets.token_hex(8)}.tmp",
            final_name=_CLAIM_MANIFEST,
            checkpoints=(
                f"{phase}.manifest_file_fsync",
                f"{phase}.manifest_replace",
                f"{phase}.manifest_dir_fsync",
            ),
            write_failure="Store claim metadata write failed",
            # A claim manifest is rewritten in place at each phase, so unlike
            # the staging manifests this one lands over its predecessor.
            replace=True,
        )
    except OSError as error:
        raise InvalidArgumentError("Store claim metadata is unavailable") from error
    finally:
        os.close(descriptor)


def _load_claim(
    runtime: _RuntimeRoot,
    path: Path,
    *,
    batch_id: str | None = None,
    require_files: bool = True,
) -> _Claim:
    expected_batch_id = path.name if batch_id is None else batch_id
    if _BATCH_ID.fullmatch(expected_batch_id) is None:
        raise InvalidArgumentError("Store claim identity is invalid")
    descriptor = _open_directory_at(runtime.claims_descriptor, path.name)
    try:
        encoded = _read_private_manifest(
            descriptor,
            _CLAIM_MANIFEST,
            max_bytes=MAX_MANIFEST_BYTES,
            label="Store claim metadata",
        )
    finally:
        os.close(descriptor)
    try:
        raw = json.loads(encoded.decode("utf-8"))
        if not isinstance(raw, dict) or set(raw) != {
            "authorship",
            "batch_id",
            "capture_request_id",
            "captured_at",
            "custody_kind",
            "entries",
            "exact_metadata",
            "format",
            "has_more",
            "issues",
            "sensitivity",
            "source_origin",
        }:
            raise ValueError
        if raw["format"] != _CLAIM_FORMAT or raw["batch_id"] != expected_batch_id:
            raise ValueError
        sealed_at = raw["captured_at"]
        has_more = raw["has_more"]
        raw_entries = raw["entries"]
        raw_issues = raw["issues"]
        if (
            not isinstance(sealed_at, int)
            or isinstance(sealed_at, bool)
            or sealed_at < 0
            or not isinstance(has_more, bool)
            or not isinstance(raw_entries, list)
            or len(raw_entries) > MAX_BATCH_FILES
            or not isinstance(raw_issues, dict)
        ):
            raise ValueError
        entries = [_parse_visible(entry) for entry in raw_entries]
        if (
            sum(entry.size for entry in entries) > MAX_BATCH_BYTES
            or len({entry.name for entry in entries}) != len(entries)
            or len({entry.entry_id for entry in entries}) != len(entries)
        ):
            raise ValueError
        issues: Counter[str] = Counter()
        for code, count in raw_issues.items():
            if (
                not isinstance(code, str)
                or code not in INBOX_ISSUE_CODES
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 1
            ):
                raise ValueError
            issues[code] = count
        authorship = Authorship(raw["authorship"])
        sensitivity = Sensitivity(raw["sensitivity"])
        custody_kind = CustodyKind(raw["custody_kind"])
        source_origin = SourceCaptureOrigin(raw["source_origin"])
        capture_request_id = raw["capture_request_id"]
        raw_exact = raw["exact_metadata"]
        exact_metadata: ExactCaptureMetadata | None
        if custody_kind is CustodyKind.INBOX_SCAN:
            if (
                source_origin is not SourceCaptureOrigin.INBOX
                or capture_request_id is not None
                or raw_exact is not None
                or any(
                    re.fullmatch(r"ise_[0-9a-f]{32}", entry.entry_id) is None
                    for entry in entries
                )
            ):
                raise ValueError
            exact_metadata = None
        else:
            if (
                source_origin is not SourceCaptureOrigin.OWNER_CORRECTION
                or not isinstance(capture_request_id, str)
                or not isinstance(raw_exact, dict)
                or set(raw_exact)
                != {"expected_head_id", "payload_sha256", "target_lineage_id"}
                or any(not isinstance(value, str) for value in raw_exact.values())
                or len(entries) != 1
                or _ENTRY_ID.fullmatch(entries[0].entry_id) is None
                or issues
                or has_more
            ):
                raise ValueError
            exact_metadata = ExactCaptureMetadata(
                capture_request_id=capture_request_id,
                batch_id=expected_batch_id,
                captured_at=sealed_at,
                target_lineage_id=str(raw_exact["target_lineage_id"]),
                expected_head_id=str(raw_exact["expected_head_id"]),
                payload_sha256=str(raw_exact["payload_sha256"]),
                source_origin=source_origin,
                authorship=authorship,
                sensitivity=sensitivity,
            )
            _validate_exact_metadata(exact_metadata)
            if entries[0].sha256 != exact_metadata.payload_sha256:
                raise ValueError
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise InvalidArgumentError("Store claim metadata is invalid") from error
    if require_files:
        claim_descriptor = _open_directory_at(runtime.claims_descriptor, path.name)
        try:
            files_descriptor = _open_directory_at(
                claim_descriptor,
                _CLAIM_FILES,
            )
            os.close(files_descriptor)
        finally:
            os.close(claim_descriptor)
    return _Claim(
        path=path,
        batch_id=expected_batch_id,
        custody_kind=custody_kind,
        source_origin=source_origin,
        capture_request_id=capture_request_id,
        exact_metadata=exact_metadata,
        sealed_at=sealed_at,
        authorship=authorship,
        sensitivity=sensitivity,
        entries=entries,
        issues=issues,
        has_more=has_more,
    )


def _parse_visible(raw: object) -> _VisibleFile:
    if not isinstance(raw, dict) or set(raw) != {
        "byte_length",
        "device",
        "entry_id",
        "inode",
        "modified_ns",
        "name",
        "sha256",
    }:
        raise ValueError
    name = raw["name"]
    entry_id = raw["entry_id"]
    digest = raw["sha256"]
    values = (
        raw["device"],
        raw["inode"],
        raw["byte_length"],
        raw["modified_ns"],
    )
    if (
        not isinstance(name, str)
        or not _safe_entry_name(name)
        or len(name.encode("utf-8")) > 255
        or not isinstance(entry_id, str)
        or (
            re.fullmatch(r"ise_[0-9a-f]{32}", entry_id) is None
            and _ENTRY_ID.fullmatch(entry_id) is None
        )
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or any(
            not isinstance(value, int) or isinstance(value, bool) for value in values
        )
        or any(value < 0 for value in values)
        or values[2] > MAX_FILE_BYTES
    ):
        raise ValueError
    return _VisibleFile(
        entry_id=entry_id,
        name=name,
        device=values[0],
        inode=values[1],
        size=values[2],
        modified_ns=values[3],
        sha256=digest,
    )


def _visible_regular_files(
    descriptor: int,
    policy: ScanPolicy,
) -> tuple[list[_VisibleCandidate], Counter[str]]:
    """List the eligible inbox entries in one deterministic pass, reading none."""
    files: list[_VisibleCandidate] = []
    issues: Counter[str] = Counter()
    for name in sorted(os.listdir(descriptor)):
        if name.startswith("."):
            continue
        if not _safe_entry_name(name):
            issues["path_escape"] += 1
            continue
        metadata = _stat_entry(descriptor, name)
        if metadata is None:
            issues["changed"] += 1
            continue
        if stat.S_ISLNK(metadata.st_mode):
            issues["symlink"] += 1
            continue
        if not stat.S_ISREG(metadata.st_mode):
            issues["not_regular"] += 1
            continue
        if metadata.st_size > policy.file_byte_limit:
            issues["source_too_large"] += 1
            continue
        files.append(
            _VisibleCandidate(
                name=name,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                size=metadata.st_size,
                modified_ns=metadata.st_mtime_ns,
            )
        )
    return files, issues


def _select_within_limits(
    descriptor: int,
    settled: list[_VisibleCandidate],
    policy: ScanPolicy,
    issues: Counter[str],
) -> tuple[list[_VisibleFile], int, set[str]]:
    """Claim a deterministic fitting set within selection and work limits.

    Selection is unchanged: the candidates are walked in their deterministic
    discovery order and each one that still fits both limits is taken, so a
    file too large for the remaining room is deferred without blocking the
    later files that do fit. What changed is where the digest is taken. It is
    taken here, on the at most `batch_file_limit` files this batch will
    actually attempts to claim, rather than on every visible file during
    discovery; the scan reads a bounded amount outside the writer lock
    however large the inbox is. Claimed bytes are revalidated under the writer
    lock before atomic capture. Attempted capacity is distinct from successful
    selection capacity: every digest attempt consumes one file and the
    candidate's settled expected bytes even when that digest reports a change.

    A candidate whose identity moved between the settle comparison and this
    open, or that cannot be read consistently, counts as `changed` and yields
    its place to the next candidate -- exactly what happened when discovery
    hashed and dropped it before selection ever saw it.
    """
    selected: list[_VisibleFile] = []
    selected_bytes = 0
    attempted_names: set[str] = set()
    attempted_files = 0
    attempted_bytes = 0
    deferred = 0
    for item in settled:
        if (
            len(selected) >= policy.batch_file_limit
            or selected_bytes + item.size > policy.batch_byte_limit
        ):
            deferred += 1
            continue
        if (
            attempted_files >= policy.batch_file_limit
            or attempted_bytes + item.size > policy.batch_byte_limit
        ):
            deferred += 1
            continue
        attempted_files += 1
        attempted_bytes += item.size
        attempted_names.add(item.name)
        try:
            digest = _digest_visible_file(descriptor, item.name, item)
        except NoEligibleSourcesError, OSError:
            issues["changed"] += 1
            continue
        selected.append(_claimable_file(item, digest))
        selected_bytes += item.size
    return selected, deferred, attempted_names


def _claimable_file(candidate: _VisibleCandidate, digest: str) -> _VisibleFile:
    """Bind one settled candidate to the digest that proves its bytes.

    The `ise_` derivation still mixes the digest in, unchanged, because an
    entry id is only ever minted for a file this scan has just read whole.
    Nothing downstream needs one for a candidate that was deferred or dropped.
    """
    entry_id = (
        "ise_"
        + hashlib.sha256(
            (
                f"{candidate.name}\0{candidate.device}\0{candidate.inode}\0"
                f"{candidate.size}\0{candidate.modified_ns}\0{digest}"
            ).encode()
        ).hexdigest()[:32]
    )
    return _VisibleFile(
        entry_id=entry_id,
        name=candidate.name,
        device=candidate.device,
        inode=candidate.inode,
        size=candidate.size,
        modified_ns=candidate.modified_ns,
        sha256=digest,
    )


def _digest_visible_file(
    directory_descriptor: int,
    name: str,
    expected: _VisibleCandidate,
) -> str:
    """Digest one settled candidate, proving the bytes read were still its own.

    The identity is the settled candidate's rather than a freshly taken stat:
    the digest is what the claim will hold, so what it has to prove is that
    this open descriptor is the file the settle window observed, not merely
    that it did not move while being read.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, _STREAM_BYTES):
            total += len(chunk)
            if total > expected.size:
                raise NoEligibleSourcesError("an inbox source changed during discovery")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (
        expected.device,
        expected.inode,
        expected.size,
        expected.modified_ns,
    )
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != identity
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity
        or total != expected.size
    ):
        raise NoEligibleSourcesError("an inbox source changed during discovery")
    return digest.hexdigest()


def _read_unchanged(directory_descriptor: int, visible: _VisibleFile) -> _Capture:
    if not _safe_entry_name(visible.name):
        raise InvalidArgumentError("Store source name is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(visible.name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise NoEligibleSourcesError(
            "an inbox source changed during capture"
        ) from error
    try:
        before = os.fstat(descriptor)
        buffer = bytearray()
        remaining = visible.size + 1
        while remaining > 0 and (
            chunk := os.read(descriptor, min(_STREAM_BYTES, remaining))
        ):
            buffer.extend(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    # The claimed identity's device is the writer's boot-assigned number; the
    # source must instead live on its containing directory's current device,
    # so a claim left by a crash still completes after a reboot.
    containing_device = os.fstat(directory_descriptor).st_dev
    identity = (containing_device, visible.inode, visible.size, visible.modified_ns)
    observed_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    observed_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        observed_before != identity
        or observed_after != identity
        or len(buffer) != visible.size
    ):
        raise NoEligibleSourcesError("an inbox source changed during capture")
    original_bytes = bytes(buffer)
    if hashlib.sha256(original_bytes).hexdigest() != visible.sha256:
        raise NoEligibleSourcesError("an inbox source changed during capture")
    media_type = media_type_for_name(visible.name)
    return _Capture(
        name=visible.name,
        media_type=media_type,
        original_bytes=original_bytes,
        utf8_text=searchable_text(media_type, original_bytes),
    )


def _issues(counts: Counter[str]) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    for code, count in sorted(counts.items()):
        if code not in INBOX_ISSUE_CODES or count < 0:
            raise InvalidArgumentError("Store inbox issue metadata is invalid")
        if count > 0:
            issues.append(Issue(code=code, count=count))
    return tuple(issues)


def _issues_from_connection(
    connection: Connection,
    batch_id: str,
) -> tuple[Issue, ...]:
    rows = connection.execute(
        "SELECT code, count FROM inbox_batch_issues WHERE batch_id = ? ORDER BY code",
        (batch_id,),
    ).fetchall()
    issues: list[Issue] = []
    for row in rows:
        code = row[0]
        count = row[1]
        if (
            not isinstance(code, str)
            or code not in INBOX_ISSUE_CODES
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
        ):
            raise InvalidArgumentError("Store batch issue metadata is invalid")
        issues.append(Issue(code=code, count=count))
    return tuple(issues)


def _stored_has_more(raw: object) -> bool:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw not in (0, 1):
        raise InvalidArgumentError("Store batch continuation metadata is invalid")
    return bool(raw)


def _raise_all_ineligible(counts: Counter[str]) -> None:
    if counts and set(counts) == {"source_too_large"}:
        raise SourceTooLargeError("all inbox sources exceed the file limit")
    raise NoEligibleSourcesError("no eligible inbox sources")


def bind_runtime_directory_authority(paths: RuntimePaths) -> RuntimeDirectoryAuthority:
    """Bind the initialized runtime directories for one long-lived owner service."""
    with _open_runtime_root(paths) as runtime:
        return _runtime_directory_authority(runtime)


def _runtime_directory_authority(
    runtime: _RuntimeRoot,
) -> RuntimeDirectoryAuthority:
    """Project one bound runtime root into its reusable directory authority."""
    return RuntimeDirectoryAuthority(
        root_identity=runtime.root_identity,
        inbox_identity=runtime.inbox_identity,
        claims_identity=runtime.claims_identity,
        staging_identity=runtime.staging_identity,
    )


@contextmanager
def _open_runtime_root(
    paths: RuntimePaths,
    *,
    authority: RuntimeDirectoryAuthority | None = None,
) -> Iterator[_RuntimeRoot]:
    _validate_runtime_paths(paths)
    root_descriptor: int | None = None
    inbox_descriptor: int | None = None
    claims_descriptor: int | None = None
    staging_descriptor: int | None = None
    try:
        root_descriptor = _open_path_without_symlinks(paths.root)
        inbox_descriptor = _open_inbox_directory(paths, root_descriptor)
        claims_descriptor = _open_directory_at(root_descriptor, "inbox-claims")
        staging_descriptor = _open_directory_at(root_descriptor, "inbox-staging")
        runtime = _RuntimeRoot(
            paths=paths,
            root_descriptor=root_descriptor,
            inbox_descriptor=inbox_descriptor,
            claims_descriptor=claims_descriptor,
            staging_descriptor=staging_descriptor,
            root_identity=_directory_identity(root_descriptor),
            inbox_identity=_directory_identity(inbox_descriptor),
            claims_identity=_directory_identity(claims_descriptor),
            staging_identity=_directory_identity(staging_descriptor),
        )
        if authority is not None and (
            runtime.root_identity != authority.root_identity
            or runtime.inbox_identity != authority.inbox_identity
            or runtime.claims_identity != authority.claims_identity
            or runtime.staging_identity != authority.staging_identity
        ):
            raise InvalidArgumentError("Store runtime path changed")
        _verify_runtime_root(runtime)
        yield runtime
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if claims_descriptor is not None:
            os.close(claims_descriptor)
        if inbox_descriptor is not None:
            os.close(inbox_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def _validate_runtime_paths(paths: RuntimePaths) -> None:
    expected = {
        "database": paths.root / "store.sqlite3",
        "identity": paths.root / "runtime.json",
        "inbox_claims": paths.root / "inbox-claims",
        "inbox_staging": paths.root / "inbox-staging",
        "writer_lock": paths.root / ".writer.lock",
        "ui_session_lock": paths.root / ".ui-session.lock",
    }
    if any(getattr(paths, field) != path for field, path in expected.items()):
        raise InvalidArgumentError("Store runtime paths are inconsistent")
    if ".." in paths.root.parts or "\x00" in os.fspath(paths.root):
        raise InvalidArgumentError("Store runtime path is unsafe")
    _validate_inbox_location(paths)


def _inbox_is_default(paths: RuntimePaths) -> bool:
    return paths.inbox == paths.root / "inbox"


def _validate_inbox_location(paths: RuntimePaths) -> None:
    """Require the resolved inbox to be the default child or a safe external."""
    inbox = paths.inbox
    if ".." in inbox.parts or "\x00" in os.fspath(inbox):
        raise InvalidArgumentError("Store runtime path is unsafe")
    if _inbox_is_default(paths):
        return
    if not inbox.is_absolute():
        raise InvalidArgumentError("Store runtime path is unsafe")
    root_parts = paths.root.parts
    inbox_parts = inbox.parts
    inside_root = inbox_parts[: len(root_parts)] == root_parts
    contains_root = root_parts[: len(inbox_parts)] == inbox_parts
    if inside_root or contains_root:
        raise InvalidArgumentError("Store runtime paths are inconsistent")


def _open_path_without_symlinks(path: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts or parts[0] != os.path.sep:
        raise InvalidArgumentError("Store runtime path is unsafe")
    descriptor: int | None = None
    try:
        descriptor = os.open(os.path.sep, _directory_open_flags())
        for component in parts[1:]:
            next_descriptor = os.open(
                component,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        assert descriptor is not None
        _directory_identity(descriptor)
        return descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise InvalidArgumentError("Store runtime path is unsafe") from error


def _open_inbox_directory(paths: RuntimePaths, root_descriptor: int) -> int:
    """Open the resolved inbox: the default child or the configured external."""
    if _inbox_is_default(paths):
        return _open_directory_at(root_descriptor, "inbox")
    return _open_path_without_symlinks(paths.inbox)


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    if not _safe_entry_name(name):
        raise InvalidArgumentError("Store runtime path is unsafe")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        _directory_identity(descriptor)
        return descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise InvalidArgumentError("Store runtime path is unsafe") from error


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise OSError("unsafe Store directory")
    return (metadata.st_dev, metadata.st_ino)


def _verify_runtime_root(runtime: _RuntimeRoot) -> None:
    root_descriptor: int | None = None
    inbox_descriptor: int | None = None
    claims_descriptor: int | None = None
    staging_descriptor: int | None = None
    try:
        if _directory_identity(runtime.root_descriptor) != runtime.root_identity:
            raise InvalidArgumentError("Store runtime path changed")
        if _directory_identity(runtime.inbox_descriptor) != runtime.inbox_identity:
            raise InvalidArgumentError("Store runtime path changed")
        if _directory_identity(runtime.claims_descriptor) != runtime.claims_identity:
            raise InvalidArgumentError("Store runtime path changed")
        if _directory_identity(runtime.staging_descriptor) != runtime.staging_identity:
            raise InvalidArgumentError("Store runtime path changed")
        root_descriptor = _open_path_without_symlinks(runtime.paths.root)
        if _directory_identity(root_descriptor) != runtime.root_identity:
            raise InvalidArgumentError("Store runtime path changed")
        inbox_descriptor = _open_inbox_directory(runtime.paths, root_descriptor)
        claims_descriptor = _open_directory_at(root_descriptor, "inbox-claims")
        staging_descriptor = _open_directory_at(root_descriptor, "inbox-staging")
        if _directory_identity(inbox_descriptor) != runtime.inbox_identity:
            raise InvalidArgumentError("Store runtime path changed")
        if _directory_identity(claims_descriptor) != runtime.claims_identity:
            raise InvalidArgumentError("Store runtime path changed")
        if _directory_identity(staging_descriptor) != runtime.staging_identity:
            raise InvalidArgumentError("Store runtime path changed")
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if claims_descriptor is not None:
            os.close(claims_descriptor)
        if inbox_descriptor is not None:
            os.close(inbox_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def _open_claim_directory(runtime: _RuntimeRoot, claim: _Claim) -> int:
    return _open_directory_at(runtime.claims_descriptor, claim.path.name)


def _open_claim_files(runtime: _RuntimeRoot, claim: _Claim) -> int:
    claim_descriptor = _open_claim_directory(runtime, claim)
    try:
        return _open_directory_at(claim_descriptor, _CLAIM_FILES)
    finally:
        os.close(claim_descriptor)


def _safe_entry_name(name: str) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and name not in {".", ".."}
        and "\x00" not in name
        and "/" not in name
        and (os.altsep is None or os.altsep not in name)
        and os.path.basename(name) == name
    )


def _stat_entry(descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _matches_visible(
    metadata: os.stat_result,
    visible: _VisibleFile,
    *,
    containing_device: int,
) -> bool:
    """Match one live stat against a claimed identity across a reboot.

    The claimed device is the writer's boot-assigned number; the caller
    supplies its containing directory's current device instead, which the
    configured-inbox contract keeps equal to the home volume's.
    """
    return stat.S_ISREG(metadata.st_mode) and (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    ) == (
        containing_device,
        visible.inode,
        visible.size,
        visible.modified_ns,
    )
