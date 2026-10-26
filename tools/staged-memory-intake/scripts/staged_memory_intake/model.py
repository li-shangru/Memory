"""Immutable records shared by the staged Memory intake companion."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, Protocol

ErrorCategory = Literal["configuration", "drift", "state", "memory", "trash"]
Sensitivity = Literal["normal", "sensitive", "restricted"]
MemoryKind = Literal["fact", "event", "preference", "relation", "insight"]
CleanupOutcome = Literal["moved", "preserved"]
CleanupFailure = Literal["cleanup_drift", "trash_failed", "cleanup_ambiguous"]
RelocationStatus = Literal["relocated", "recovered", "current"]
LayoutMigrationStatus = Literal["migrated", "recovered", "current"]

# One promotion must fit one public Memory full-detail selection so verification
# is a single complete bijection, never an accumulator over partial responses.
MAX_PROMOTION_CANDIDATES: Final = 50
MAX_PUBLIC_SNAPSHOT_BYTES: Final = 8 * 1024 * 1024


class TransactionState(StrEnum):
    """The receipt's persisted monotone workflow states."""

    OWNER_AUTHORIZED = "owner_authorized"
    PUBLISHING = "publishing"
    PUBLISHED = "published"
    CAPTURED = "captured"
    REVIEW_READY = "review_ready"
    AWAITING_MEMORY_APPROVAL = "awaiting_memory_approval"
    APPLIED = "applied"
    VERIFIED = "verified"
    CLEANUP_PENDING = "cleanup_pending"
    COMPLETE = "complete"


STATE_ORDER: tuple[TransactionState, ...] = tuple(TransactionState)


@dataclass(slots=True)
class IntakeError(Exception):
    """A content-free companion failure safe for operational output."""

    code: str
    category: ErrorCategory
    retryable: bool = False
    state: TransactionState | None = None
    ordinal: int | None = None

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"code", "category", "retryable", "state", "ordinal"}:
            if hasattr(self, name):
                raise AttributeError(name)
        super().__setattr__(name, value)

    def __str__(self) -> str:
        return self.code


def reraise_volume_unidentified(error: IntakeError) -> None:
    """Let the volume-UUID constraint surface under its own name.

    Identity reads fail for two different reasons: the directory moved -- an
    authority question -- and the containing volume reports no UUID at all --
    a filesystem-capability question (the binding effectively requires APFS
    or HFS+). Re-coding the second as the first told owners an unchanged
    root had changed.
    """
    if error.code == "volume_unidentified":
        raise error


def validate_state_transition(
    current: TransactionState,
    requested: TransactionState,
) -> None:
    """Permit only an idempotent write or the immediate next state."""
    current_ordinal = STATE_ORDER.index(current)
    if requested is current:
        return
    if current_ordinal + 1 < len(STATE_ORDER):
        if requested is STATE_ORDER[current_ordinal + 1]:
            return
    raise IntakeError(
        "invalid_state_transition",
        "state",
        state=current,
    )


@dataclass(frozen=True, slots=True)
class CompletedCommand:
    """Bounded subprocess result without decoded content."""

    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    """Argument-array process boundary used by external adapters."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand: ...


class PublicationFault(Protocol):
    """Test seam at publication durability boundaries."""

    def checkpoint(self, name: str) -> None: ...


class RelocationFault(Protocol):
    """Test seam at notes-root relocation durability boundaries."""

    def checkpoint(self, name: str) -> None: ...


class LayoutMigrationFault(Protocol):
    """Test seam at layout-migration durability boundaries."""

    def checkpoint(self, name: str) -> None: ...


@dataclass(frozen=True, slots=True)
class NoPublicationFault:
    """Production publication fault adapter that never interrupts."""

    def checkpoint(self, name: str) -> None:
        del name


@dataclass(frozen=True, slots=True)
class NoRelocationFault:
    """Production relocation fault adapter that never interrupts."""

    def checkpoint(self, name: str) -> None:
        del name


@dataclass(frozen=True, slots=True)
class NoLayoutMigrationFault:
    """Production layout-migration fault adapter that never interrupts."""

    def checkpoint(self, name: str) -> None:
        del name


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    """Filesystem identity bound into configuration and receipts.

    The volume UUID replaces ``st_dev`` because APFS assigns device numbers
    at mount time, so they renumber across reboots while the UUID persists.
    `volume` is None only on an identity parsed from a pre-v2 device-bound
    record, whose device number is meaningless after any reboot; a None
    volume never matches a live identity and is never persisted.
    """

    volume: str | None
    inode: int


VOLUME_UUID_PATTERN: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def require_volume_uuid(value: object) -> str:
    """Return one exact lowercase volume UUID or raise ValueError."""
    if not isinstance(value, str) or VOLUME_UUID_PATTERN.fullmatch(value) is None:
        raise ValueError("volume identity is not a volume UUID")
    return value


def identity_payload(identity: DirectoryIdentity) -> dict[str, object]:
    """Encode the one persisted {volume, inode} identity shape."""
    return {"volume": require_volume_uuid(identity.volume), "inode": identity.inode}


def parse_identity_payload(value: object) -> DirectoryIdentity:
    """Parse the one persisted {volume, inode} shape or raise ValueError."""
    if not isinstance(value, dict) or set(value) != {"volume", "inode"}:
        raise ValueError("directory identity payload is invalid")
    inode = value["inode"]
    if not isinstance(inode, int) or isinstance(inode, bool) or inode < 0:
        raise ValueError("directory identity payload is invalid")
    return DirectoryIdentity(volume=require_volume_uuid(value["volume"]), inode=inode)


@dataclass(frozen=True, slots=True)
class MemoryPaths:
    """Publicly resolved Memory path authorities."""

    home: Path
    inbox: Path
    inbox_identity: DirectoryIdentity


@dataclass(frozen=True, slots=True)
class IntakeConfig:
    """Relocatable notes authority and independent Memory Inbox authority."""

    notes_root: Path
    notes_identity: DirectoryIdentity
    memory_home: Path | None
    memory_inbox: Path
    inbox_identity: DirectoryIdentity
    pending_drop: bool = False


@dataclass(frozen=True, slots=True)
class RelocationResult:
    """Content-free result of one coordinated notes-root relocation."""

    status: RelocationStatus


@dataclass(frozen=True, slots=True)
class LayoutMigrationResult:
    """Content-free result of one numbered-layout migration."""

    status: LayoutMigrationStatus


@dataclass(frozen=True, slots=True)
class MemoryMetadata:
    """Owner-requested or sensitivity-elevated Memory fields."""

    kind: MemoryKind
    sensitivity: Sensitivity
    occurred_on: str | None
    valid_from: str | None
    valid_to: str | None
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParsedPrepared:
    """One exact Prepared candidate with its bound source evidence."""

    prepared_name: str
    source_name: str
    prepared_sha256: str
    source_sha256: str
    statement: str
    statement_sha256: str
    statement_utf8_bytes: int
    verbatim_statement: bool
    evidence_excerpt: str
    evidence_sha256: str
    evidence_char_start: int
    evidence_char_end: int
    requested_metadata: MemoryMetadata


@dataclass(frozen=True, slots=True)
class PreparedCandidate:
    """An ordered proposal; parsed plaintext remains an in-memory value."""

    ordinal: int
    parsed: ParsedPrepared
    final_metadata: MemoryMetadata
    client_item_id: str


@dataclass(frozen=True, slots=True)
class GuardEndpoint:
    """Exactly one selected Prepared candidate or existing lineage."""

    prepared_name: str | None
    lineage_id: str | None


@dataclass(frozen=True, slots=True)
class GuardSpec:
    """A directional guard-to-governed relationship."""

    guard: GuardEndpoint
    governed: GuardEndpoint


@dataclass(frozen=True, slots=True)
class PromotionPreview:
    """The exact ordered owner preview and its body-free manifest digest."""

    candidates: tuple[PreparedCandidate, ...]
    guard_links: tuple[GuardSpec, ...]
    batch_sensitivity: Sensitivity
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class ReceiptCandidate:
    """Body-free persisted form of one exact Prepared candidate."""

    ordinal: int
    prepared_name: str
    source_name: str
    prepared_sha256: str
    source_sha256: str
    statement_sha256: str
    statement_utf8_bytes: int
    evidence_char_start: int
    evidence_char_end: int
    evidence_sha256: str
    client_item_id: str
    metadata: MemoryMetadata


@dataclass(frozen=True, slots=True)
class ReceiptGuardLink:
    """Persisted item-or-lineage endpoints for one approved guard link."""

    guard_item_id: str | None
    guard_lineage_id: str | None
    governed_item_id: str | None
    governed_lineage_id: str | None

    def __post_init__(self) -> None:
        if (self.guard_item_id is None) == (self.guard_lineage_id is None):
            raise ValueError("guard endpoint must name exactly one ID")
        if (self.governed_item_id is None) == (self.governed_lineage_id is None):
            raise ValueError("governed endpoint must name exactly one ID")


@dataclass(frozen=True, slots=True)
class PublishedFile:
    """One exact file durably published to Memory's Inbox."""

    ordinal: int
    prepared_name: str
    inbox_name: str
    sha256: str
    byte_length: int


@dataclass(frozen=True, slots=True)
class SourceBinding:
    """One published file's exact captured-source identity."""

    ordinal: int
    inbox_name: str
    source_id: str
    blob_digest: str


@dataclass(frozen=True, slots=True)
class ScanIssueNotice:
    """Content-free issue retained from the irreversible scan result."""

    code: str
    count: int


@dataclass(frozen=True, slots=True)
class DuplicateNotice:
    """One captured source's duplicate relationship."""

    source_id: str
    duplicate_of: str


@dataclass(frozen=True, slots=True)
class GuardViolationNotice:
    """Content-free standing guard-sensitivity warning."""

    guard_lineage_id: str
    guard_sensitivity: Sensitivity
    governed_lineage_id: str
    governed_sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class GuardViolationChunk:
    """One ordered content-addressed persisted warning chunk."""

    ordinal: int
    count: int
    sha256: str


@dataclass(frozen=True, slots=True)
class CleanupEntry:
    """Body- and name-free durable cleanup journal entry."""

    role: Literal["prepared", "staged"]
    name_sha256: str
    content_sha256: str
    intent_recorded: bool
    failure: CleanupFailure | None
    outcome: CleanupOutcome | None


@dataclass(frozen=True, slots=True)
class TransactionReceipt:
    """Complete body-free state for one monotone intake transaction."""

    transaction_id: str
    state: TransactionState
    manifest_digest: str
    notes_root: str
    notes_identity: DirectoryIdentity
    memory_home: str | None
    memory_inbox: str
    inbox_identity: DirectoryIdentity
    batch_sensitivity: Sensitivity
    candidates: tuple[ReceiptCandidate, ...]
    guard_links: tuple[ReceiptGuardLink, ...]
    published_files: tuple[PublishedFile, ...]
    scan_started: bool
    batch_id: str | None
    scan_source_ids: tuple[str, ...]
    scan_issues: tuple[ScanIssueNotice, ...]
    scan_has_more: bool | None
    scan_page_has_more: bool | None
    source_bindings: tuple[SourceBinding, ...]
    duplicate_notices: tuple[DuplicateNotice, ...]
    change_set_id: str | None
    revision_id: str | None
    review_digest: str | None
    application_id: str | None
    memory_ids: tuple[str, ...]
    standing_guard_violations: tuple[GuardViolationNotice, ...]
    cleanup_entries: tuple[CleanupEntry, ...]
