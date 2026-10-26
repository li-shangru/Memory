"""Store value types shared by domain and protocol boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from memory import __version__ as PRODUCT_VERSION

if TYPE_CHECKING:
    from memory.ui.view_models import AuditSnapshot

type SecretBytes = bytes
type Cursor = str

INBOX_ISSUE_CODES = frozenset(
    {
        "changed",
        "not_regular",
        "path_escape",
        "source_too_large",
        "symlink",
    }
)


class RuntimeMode(StrEnum):
    """Persisted activation class for one Store runtime."""

    PERSONAL = "personal"


class ChangeSetAdapterOrigin(StrEnum):
    """Trusted adapter that authored one immutable review revision."""

    MCP = "mcp"
    OWNER_UI = "owner_ui"
    CLI = "cli"
    SYSTEM = "system"


class SourceCaptureOrigin(StrEnum):
    """Store-assigned custody path for one immutable source capture."""

    INBOX = "inbox"
    OWNER_CORRECTION = "owner_correction"


class CustodyKind(StrEnum):
    """Filesystem custody workflow that owns one durable claim."""

    INBOX_SCAN = "inbox_scan"
    EXACT_STAGED_ENTRY = "exact_staged_entry"


class Sensitivity(StrEnum):
    """Capture sensitivity returned as metadata to the trusted owner."""

    NORMAL = "normal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class Authorship(StrEnum):
    """Declared authorship for all captures in one inbox scan."""

    OWNER = "owner"
    EXTERNAL = "external"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class MemoryKind(StrEnum):
    """Owner-reviewed canonical memory kinds."""

    FACT = "fact"
    EVENT = "event"
    PREFERENCE = "preference"
    RELATION = "relation"
    INSIGHT = "insight"


class MatchStrength(StrEnum):
    """Which ladder rung produced one search hit.

    ``ENUMERATED`` is memory-side only. A `memory.search` call with no query
    walks the filtered current heads in stored order, and every hit it emits
    carries this rung; no query walk can ever emit it, so a reader tells an
    enumeration from a ranked answer by the hit alone. Source search has no
    enumeration mode -- `source.list` already is one -- so its wire enum keeps
    the three ranked values and never advertises this one.
    """

    PHRASE = "phrase"
    ALL_TERMS = "all_terms"
    ANY_TERM = "any_term"
    ENUMERATED = "enumerated"


@dataclass(frozen=True, slots=True)
class Issue:
    """Content-free aggregate warning from inbox custody."""

    code: str
    count: int


@dataclass(frozen=True, slots=True)
class DuplicateCapture:
    """One capture whose bytes were already in custody before it was captured.

    Content-free, like every other batch-level notice: two opaque capture ids
    and nothing about what either one says. Deduplication is a storage fact
    and never a provenance one -- both captures are real, keep their own
    metadata and sensitivity, and stay independently readable. This only
    reports that reviewing the newer one again may be redundant work.
    """

    source_id: str
    duplicate_of: str


@dataclass(frozen=True, slots=True)
class InboxBatch:
    """One atomically sealed inbox batch.

    ``review_state`` is the batch's position in the one review it may ever
    have: ``none`` until a change set exists, then ``draft`` or ``applied``.
    It is derived from the change set at read time rather than stored, because
    the change set is already the authority for its own state.
    """

    batch_id: str
    sealed_at: int
    source_count: int
    source_ids: tuple[str, ...]
    issues: tuple[Issue, ...] = ()
    has_more: bool = False
    duplicates: tuple[DuplicateCapture, ...] = ()
    change_set_id: str | None = None
    review_state: Literal["none", "draft", "applied"] = "none"
    application_id: str | None = None


@dataclass(frozen=True, slots=True)
class StagedInboxEntry:
    """One literal regular file currently visible in the shared Inbox."""

    display_name: str
    byte_length: int
    staged_at_ns: int


@dataclass(frozen=True, slots=True)
class PrivateStagedEntry:
    """Opaque handle for bytes held in the Store-owned staging directory."""

    entry_id: str
    display_name: str
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class CaptureRecoveryIssue:
    """Content-free report for an exact-capture artifact needing attention."""

    issue_id: str
    code: Literal["malformed_manifest", "ambiguous_claim", "custody_mismatch"]
    detected_at_ns: int


@dataclass(frozen=True, slots=True)
class ExactCaptureMetadata:
    """Store-reserved metadata bound to one exact staged capture."""

    capture_request_id: str
    batch_id: str
    captured_at: int
    target_lineage_id: str
    expected_head_id: str
    payload_sha256: str
    source_origin: SourceCaptureOrigin
    authorship: Authorship
    sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class CapturedCorrection:
    """Stable result of one isolated owner-correction capture."""

    capture_request_id: str
    batch_id: str
    source_id: str
    lineage_id: str
    expected_head_id: str
    captured_at: int


@dataclass(frozen=True, slots=True)
class SourceBlob:
    """Deduplicated immutable source bytes."""

    blob_id: str
    sha256: str
    byte_length: int
    original_bytes: bytes
    utf8_text: str | None


@dataclass(frozen=True, slots=True)
class Source:
    """Capture-specific provenance for one retained blob."""

    source_id: str
    blob_id: str
    batch_id: str
    origin: SourceCaptureOrigin
    original_name: str
    media_type: str
    authorship: Authorship
    sensitivity: Sensitivity
    captured_at: int


@dataclass(frozen=True, slots=True)
class SourceSummary:
    """Bounded source provenance returned during enumeration."""

    source_id: str
    origin: SourceCaptureOrigin
    blob_digest: str
    original_name: str
    media_type: str
    byte_length: int
    authorship: Authorship
    declared_sensitivity: Sensitivity
    effective_sensitivity: Sensitivity
    searchable: bool
    captured_at: int


@dataclass(frozen=True, slots=True)
class BatchDetail:
    """One sealed batch and every capture in ordinal order."""

    batch: InboxBatch
    sources: tuple[SourceSummary, ...]


@dataclass(frozen=True, slots=True)
class Page[T]:
    """One high-water keyset page."""

    items: tuple[T, ...]
    next_cursor: Cursor | None
    has_more: bool


@dataclass(frozen=True, slots=True)
class Coverage:
    """Honest source-search coverage for one snapshot."""

    searchable: int
    unsearchable: int
    enumerated: int
    total: int


@dataclass(frozen=True, slots=True)
class SourceSearchHit:
    """One FTS result with a bounded exact source excerpt.

    The excerpt span is canonical source character coordinates -- the same
    system `source.read` chunks and evidence locators use -- so a truncated
    preview converts into an exact locator in one bounded read. The match span
    is the located occurrence inside that source, and is absent when the ladder
    admitted the row through the stemmed projection with no literal occurrence
    to point at, or when case folding did not preserve character positions.
    """

    source: SourceSummary
    exact_excerpt: str
    rank: float
    match_strength: MatchStrength
    excerpt_char_start: int
    excerpt_char_end: int
    match_char_start: int | None
    match_char_end: int | None


@dataclass(frozen=True, slots=True)
class SourceSearchPage:
    """A query-bound source-search page and full snapshot coverage."""

    items: tuple[SourceSearchHit, ...]
    next_cursor: Cursor | None
    has_more: bool
    coverage: Coverage


@dataclass(frozen=True, slots=True)
class SourceChunk:
    """A bounded text or binary slice bound to the full blob digest."""

    source_id: str
    blob_digest: str
    media_type: str
    text: str | None
    binary: bytes | None
    resource_content_index: int | None
    char_start: int | None
    char_end: int | None
    byte_start: int
    byte_end: int
    next_cursor: Cursor | None
    complete: bool


@dataclass(frozen=True, slots=True)
class StoreStatus:
    """Content-free Store identity, counts, coverage, and contract digests.

    ``product_version`` is the running package version. It is the one value
    that lets an agent notice a three-way skew between a packaged Skill copy,
    a long-lived server process, and a repository, which two digests alone
    could only report as "different" without saying which side is behind. It
    defaults to the running package because it is a process fact rather than a
    per-Store one, so every builder reports the same true value.

    ``pending_review_count`` carries no default, deliberately. Zero is a
    meaningful answer here -- "nothing is waiting on you" -- so a builder that
    forgot the field would report it rather than fail, and a backlog the owner
    never sees is the exact condition this count was added to end.
    ``product_version`` keeps its default for the opposite reason: it is a
    process fact, not a per-Store one, so a default guarantees every builder
    reports the same true value where requiring it would only create a chance
    to pass a wrong one.
    """

    product: str
    schema_version: int
    store_id: str
    source_count: int
    memory_count: int
    searchable_count: int
    unsearchable_count: int
    reindex_required: bool
    mcp_contract_digest: str
    skill_digest: str
    pending_review_count: int
    product_version: str = PRODUCT_VERSION


@dataclass(frozen=True, slots=True)
class EvidenceInput:
    """Client proposal for exact text or explicit source-level evidence."""

    source_id: str
    blob_digest: str
    excerpt: str | None = None
    source_level: bool | None = None


@dataclass(frozen=True, slots=True)
class EvidenceLocator:
    """Store-resolved immutable evidence coordinates."""

    ordinal: int
    source_id: str
    blob_digest: str
    mode: str
    char_start: int | None
    char_end: int | None
    excerpt: str | None
    source_level: bool | None


@dataclass(frozen=True, slots=True)
class MemoryFields:
    """The exact owner-reviewable memory fields supplied by an agent."""

    kind: MemoryKind
    statement: str
    occurred_on: str | None
    valid_from: str | None
    valid_to: str | None
    tags: tuple[str, ...]
    sensitivity: Sensitivity
    target_lineage_id: str | None
    expected_head_id: str | None


@dataclass(frozen=True, slots=True)
class AddItem:
    """Add one stable client-named proposal to a draft revision."""

    client_item_id: str
    memory: MemoryFields
    evidence: tuple[EvidenceInput | EvidenceLocator, ...]


@dataclass(frozen=True, slots=True)
class ReplaceItem:
    """Replace one proposal while preserving its review status."""

    item_id: str
    memory: MemoryFields
    evidence: tuple[EvidenceInput | EvidenceLocator, ...]


@dataclass(frozen=True, slots=True)
class RejectItem:
    """Retain one proposal in the diff but remove its source coverage."""

    item_id: str


@dataclass(frozen=True, slots=True)
class RestoreItem:
    """Restore one rejected proposal to active review state."""

    item_id: str


@dataclass(frozen=True, slots=True)
class GuardLinkInput:
    """One guard-link endpoint pair; each side names an item XOR a lineage."""

    guard_item_id: str | None
    guard_lineage_id: str | None
    governed_item_id: str | None
    governed_lineage_id: str | None


@dataclass(frozen=True, slots=True)
class AddGuardLink:
    """Append one guard link to the draft revision."""

    link: GuardLinkInput


@dataclass(frozen=True, slots=True)
class RemoveGuardLink:
    """Remove one exact guard link from the draft revision."""

    link: GuardLinkInput


@dataclass(frozen=True, slots=True)
class RevokeGuardLink:
    """Withdraw one retained canonical guard link when this revision applies.

    The counterpart of `RemoveGuardLink`, which only ever edits the draft: this
    names a link the Store already holds and stops it governing. The row is
    never deleted -- apply stamps it revoked -- so history and the governance
    graph keep it while retrieval and the guard-violation scan stop seeing it.
    """

    link: GuardLinkInput


@dataclass(frozen=True, slots=True)
class SetSourceNoMemory:
    """Record the reviewed decision that one source creates no memory."""

    source_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ClearSourceNoMemory:
    """Remove one explicit no-memory decision from the new revision."""

    source_id: str


type ChangeEdit = (
    AddItem
    | ReplaceItem
    | RejectItem
    | RestoreItem
    | SetSourceNoMemory
    | ClearSourceNoMemory
    | AddGuardLink
    | RemoveGuardLink
    | RevokeGuardLink
)

#: The one roster of edit operations, by the name every surface calls them.
#: Three places enumerate these -- the MCP tool schema parses the name into the
#: type, the owner UI names the form intent, and the applier dispatches on the
#: type -- and none of them can see the others. A tenth operation added to any
#: one of them without the rest fails the binding test in `tests/test_mcp.py`
#: rather than shipping a surface that silently cannot express it.
CHANGE_EDIT_OPERATIONS: dict[str, type] = {
    "add_item": AddItem,
    "replace_item": ReplaceItem,
    "reject_item": RejectItem,
    "restore_item": RestoreItem,
    "set_source_no_memory": SetSourceNoMemory,
    "clear_source_no_memory": ClearSourceNoMemory,
    "add_guard_link": AddGuardLink,
    "remove_guard_link": RemoveGuardLink,
    "revoke_guard_link": RevokeGuardLink,
}


@dataclass(frozen=True, slots=True)
class DraftItem:
    """One complete active or rejected item in an immutable draft revision."""

    ordinal: int
    item_id: str
    status: str
    memory: MemoryFields
    evidence: tuple[EvidenceLocator, ...]


@dataclass(frozen=True, slots=True)
class SourceDecision:
    """One derived used or explicit no-memory batch source decision."""

    ordinal: int
    source_id: str
    blob_digest: str
    state: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class DraftGuardLink:
    """One reviewable guard link with its derived review status."""

    ordinal: int
    guard_item_id: str | None
    guard_lineage_id: str | None
    governed_item_id: str | None
    governed_lineage_id: str | None
    status: str


@dataclass(frozen=True, slots=True)
class ChangeSetView:
    """The complete current owner-visible review revision and canonical digest."""

    change_set_id: str
    batch_id: str
    state: str
    revision_id: str
    digest: str
    adapter_origin: ChangeSetAdapterOrigin
    items: tuple[DraftItem, ...]
    source_decisions: tuple[SourceDecision, ...]
    guard_links: tuple[DraftGuardLink, ...]
    revoked_guard_links: tuple[DraftGuardLink, ...]
    digest_payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class GuardViolation:
    """One guard whose effective sensitivity exceeds a claim it governs."""

    guard_lineage_id: str
    governed_lineage_id: str
    guard_sensitivity: Sensitivity
    governed_sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class ApplicationResult:
    """One atomic apply's stable identity plus an as-of-call guard diagnostic.

    ``application_id``, ``revision_id``, and ``memory_ids`` are the durable
    facts created by the first successful apply. An exact replay does not
    reapply the revision, create a second application, memory, or approval, or
    ask the owner again. It can still commit standard writer-start compatibility
    healing and advance ``audit_generation`` on a carried-forward Store.
    ``idempotent_replay`` describes this particular response, while
    ``standing_guard_violations`` is deliberately recomputed against the whole
    Store for each call; it is not a historical property of the stored
    application.
    """

    application_id: str
    change_set_id: str
    revision_id: str
    memory_ids: tuple[str, ...]
    idempotent_replay: bool
    standing_guard_violations: tuple[GuardViolation, ...]


@dataclass(frozen=True, slots=True)
class MemoryFilters:
    """Optional generic constraints over current canonical memories.

    ``include_undated`` governs only the ``occurred_*`` bounds. It defaults to
    true because the alternative default is the surprising one: an occurred
    bound used to drop every memory carrying no date at all, so "everything
    from 2033" quietly meant "everything from 2033 that happens to be dated".
    Turning it off restores that exclusion deliberately.

    ``recorded_from`` and ``recorded_to`` are inclusive epoch seconds, the same
    units ``MemorySummary.recorded_at`` reports, and are never affected by
    ``include_undated``: every revision has a recorded time.
    """

    kinds: tuple[MemoryKind, ...] = ()
    tags_all: tuple[str, ...] = ()
    tags_any: tuple[str, ...] = ()
    occurred_from: str | None = None
    occurred_to: str | None = None
    recorded_from: int | None = None
    recorded_to: int | None = None
    include_undated: bool = True
    sensitivities: tuple[Sensitivity, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceFilters:
    """Optional generic constraints over the retained source enumeration."""

    searchable: bool | None = None
    origin: SourceCaptureOrigin | None = None


@dataclass(frozen=True, slots=True)
class FacetCount:
    """One distinct facet value and how many current heads carry it."""

    value: str
    count: int


@dataclass(frozen=True, slots=True)
class MemoryFacets:
    """The tag and kind vocabulary current canonical memory actually uses.

    ``total_tags`` is the true distinct-tag count and ``truncated`` says
    whether ``tags`` was cut at the bound, so a bounded answer can never be
    read as a complete one. Values are reported exactly as stored, case
    included: filtering casefolds, and this is the surface that lets an owner
    see that both ``Work`` and ``work`` exist.
    """

    tags: tuple[FacetCount, ...]
    kinds: tuple[FacetCount, ...]
    total_tags: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class MemorySummary:
    """One current or historical canonical memory revision."""

    memory_id: str
    lineage_id: str
    kind: MemoryKind
    statement: str
    occurred_on: str | None
    valid_from: str | None
    valid_to: str | None
    tags: tuple[str, ...]
    stored_sensitivity: Sensitivity
    effective_sensitivity: Sensitivity
    recorded_at: int


@dataclass(frozen=True, slots=True)
class GuardAttachment:
    """Current head of a guard lineage bundled with a governed hit."""

    memory_id: str
    lineage_id: str
    kind: MemoryKind
    statement: str
    effective_sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class MemorySearchHit:
    """One current-head hit, its ladder rung, and its governing guards."""

    memory: MemorySummary
    match_strength: MatchStrength
    guards: tuple[GuardAttachment, ...]


@dataclass(frozen=True, slots=True)
class MemoryDetail:
    """An exact revision, its current-head state, and immutable evidence.

    ``revision_ids`` is the lineage's complete revision history in recorded
    order, oldest first, so one call answers what walking ``predecessor_id``
    one read at a time could only answer backwards -- and successors not at
    all.
    """

    revision: MemorySummary
    is_current: bool
    current_head_id: str
    predecessor_id: str | None
    evidence: tuple[EvidenceLocator, ...]
    guards: tuple[GuardAttachment, ...]
    governs: tuple[GuardAttachment, ...]
    revision_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MemorySearchPage:
    """One bounded current-head memory-search page and its snapshot coverage."""

    items: tuple[MemorySearchHit, ...]
    next_cursor: Cursor | None
    has_more: bool
    coverage: Coverage


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """Resolved paths for one explicitly selected Store runtime."""

    root: Path
    database: Path
    inbox: Path
    inbox_claims: Path
    inbox_staging: Path
    identity: Path
    writer_lock: Path
    ui_session_lock: Path


@dataclass(frozen=True, slots=True)
class UiLaunch:
    """One process-local browser origin and one-shot bootstrap capability."""

    bind_host: str
    public_host: str
    port: int
    bootstrap_capability: str
    url: str


@dataclass(frozen=True, slots=True)
class UiLaunchEnvelope:
    """Versioned launch handoff for a trusted local integration."""

    protocol: Literal["memory.ui-launch.v1"]
    origin: str
    bootstrap_url: str


@dataclass(frozen=True, slots=True)
class UiSession:
    """Opaque process-memory authority for one owner browser session."""

    session_id: str
    csrf_token: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class UiReviewRefusal:
    """One refused owner review edit addressed only by an opaque handle.

    ``fields`` holds the submitted form pairs of whichever edit was refused, so
    one mechanism carries a statement, a reason, an ordered evidence row, or a
    guard-link endpoint back to the form it came from. The owner's typing stays
    in this process for the one redirect that returns it, exactly as a private
    search does: an owner may type anything into those boxes, and nothing they
    type belongs in a URL.
    """

    change_set_id: str
    revision_id: str
    intent: str
    refusal: str
    fields: tuple[tuple[str, str], ...]
    created_at_ns: int


@dataclass(frozen=True, slots=True)
class UiSearchState:
    """Private normalized search state addressed only by an opaque handle."""

    scope: Literal["sources", "memories", "graph"]
    query: str
    filters: tuple[tuple[str, str], ...]
    created_at_ns: int


@dataclass(frozen=True, slots=True)
class UiAuditState:
    """Immutable audit snapshot addressed only by an opaque handle."""

    snapshot: AuditSnapshot
    created_at_ns: int


@dataclass(frozen=True, slots=True)
class StoreIdentity:
    """Identity shared by runtime metadata, Keychain, and the database."""

    product: str
    schema_lineage: str
    schema_version: int
    store_id: str
    runtime_mode: RuntimeMode
    inbox_path: str
