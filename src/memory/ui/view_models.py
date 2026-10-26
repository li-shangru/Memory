"""Immutable bounded records for the trusted local owner surface."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from memory.model import (
    Authorship,
    ChangeSetAdapterOrigin,
    EvidenceLocator,
    GuardViolation,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    MemorySummary,
    RuntimeMode,
    Sensitivity,
    SourceCaptureOrigin,
    StoreStatus,
)

OWNER_REVIEW_ITEM_PAGE_LIMIT = 3

type OwnerApprovalAdapter = Literal[
    "mcp_elicitation", "local_owner_ui", "os_owner_presence_cli"
]

type OwnerReviewFormIntent = Literal[
    "add_item",
    "replace_item",
    "reject_item",
    "restore_item",
    "set_source_no_memory",
    "clear_source_no_memory",
    "add_guard_link",
    "remove_guard_link",
    "revoke_guard_link",
]


@dataclass(frozen=True, slots=True)
class OwnerPage[T]:
    items: tuple[T, ...]
    next_cursor: str | None
    has_more: bool


@dataclass(frozen=True, slots=True)
class SourceProjectionCoverage:
    total_captures: int
    expected_searchable_captures: int
    indexed_expected_captures: int
    missing_expected_rows: int
    inherently_unsearchable_captures: int
    unexpected_or_duplicate_rows: int


@dataclass(frozen=True, slots=True)
class MemoryProjectionCoverage:
    current_heads: int
    indexed_current_heads: int
    missing_current_head_rows: int
    unexpected_or_duplicate_noncurrent_rows: int
    historical_revisions_not_expected: int


@dataclass(frozen=True, slots=True)
class ProjectionCoverage:
    sources: SourceProjectionCoverage
    memories: MemoryProjectionCoverage


@dataclass(frozen=True, slots=True)
class AuditCounts:
    batch_count: int
    batch_issue_row_count: int
    batch_issue_occurrence_count: int
    source_count: int
    change_set_count: int
    change_set_revision_count: int
    approval_count: int
    application_count: int
    lineage_count: int
    memory_revision_count: int


@dataclass(frozen=True, slots=True)
class InboxStatus:
    inbox_display_path: str
    staged_visible_entry_count: int


@dataclass(frozen=True, slots=True)
class OwnerStatus:
    store: StoreStatus
    runtime_mode: RuntimeMode
    availability: Literal["available", "writer_busy", "unavailable"]
    pending_review_count: int
    projections: ProjectionCoverage
    runtime_display_path: str
    inbox: InboxStatus


@dataclass(frozen=True, slots=True)
class OwnerSourceSummary:
    source_id: str
    blob_id: str
    batch_id: str
    batch_ordinal: int
    origin: SourceCaptureOrigin
    blob_digest: str
    original_name: str
    media_type: str
    byte_length: int
    authorship: Authorship
    declared_sensitivity: Sensitivity
    effective_sensitivity: Sensitivity
    expected_searchable: bool
    indexed_for_search: bool
    captured_at: int


@dataclass(frozen=True, slots=True)
class OwnerSourceDetail:
    summary: OwnerSourceSummary
    retained_utf8_text: bool
    blob_capture_count: int
    evidence_backlink_count: int


@dataclass(frozen=True, slots=True)
class OwnerSourceChunk:
    source_id: str
    blob_digest: str
    media_type: str
    text: str | None
    binary: bytes | None
    char_start: int | None
    char_end: int | None
    byte_start: int
    byte_end: int
    next_cursor: str | None
    complete: bool


@dataclass(frozen=True, slots=True)
class OwnerSourceSearchHit:
    source: OwnerSourceSummary
    exact_excerpt: str
    rank: float


@dataclass(frozen=True, slots=True)
class OwnerSourceSearchPage:
    items: tuple[OwnerSourceSearchHit, ...]
    next_cursor: str | None
    has_more: bool
    coverage: SourceProjectionCoverage


@dataclass(frozen=True, slots=True)
class OwnerEvidenceLink:
    memory_revision_id: str
    lineage_id: str
    is_current: bool
    locator: EvidenceLocator


@dataclass(frozen=True, slots=True)
class OwnerMemorySummary:
    revision: MemorySummary
    is_current: bool
    current_head_id: str
    predecessor_id: str | None
    application_id: str
    application_ordinal: int


@dataclass(frozen=True, slots=True)
class OwnerGuardAttachment:
    """One guard-link endpoint rendered beside the claim it relates to."""

    memory_id: str
    kind: MemoryKind
    statement: str
    effective_sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class OwnerMemoryDetail:
    summary: OwnerMemorySummary
    change_set_id: str
    change_set_revision_id: str
    approval_id: str
    evidence: tuple[EvidenceLocator, ...]
    guards: tuple[OwnerGuardAttachment, ...] = ()
    governs: tuple[OwnerGuardAttachment, ...] = ()
    guards_next_cursor: str | None = None
    governs_next_cursor: str | None = None


@dataclass(frozen=True, slots=True)
class OwnerMemorySearchPage:
    items: tuple[OwnerMemorySummary, ...]
    next_cursor: str | None
    has_more: bool
    filters: MemoryFilters
    unfiltered_query_match_count: int
    filtered_match_count: int
    hidden_by_filters_count: int
    projection_coverage: MemoryProjectionCoverage
    kind_counts: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class OwnerBatchIssue:
    code: str
    occurrence_count: int


@dataclass(frozen=True, slots=True)
class OwnerBatchSummary:
    batch_id: str
    sealed_at: int
    source_count: int
    has_more: bool
    issue_row_count: int
    issue_occurrence_count: int
    change_set_id: str | None
    application_id: str | None


@dataclass(frozen=True, slots=True)
class OwnerBatchDetail:
    summary: OwnerBatchSummary
    sources: tuple[OwnerSourceSummary, ...]
    issues: tuple[OwnerBatchIssue, ...]


@dataclass(frozen=True, slots=True)
class AuditSnapshot:
    store_id: str
    generation: int
    high_water_marks: tuple[tuple[str, int], ...]
    counts: AuditCounts
    projection_coverage: ProjectionCoverage


@dataclass(frozen=True, slots=True)
class AuditIndex:
    store: OwnerStatus
    snapshot: AuditSnapshot
    integrity_capability: Literal["unavailable", "available"]


@dataclass(frozen=True, slots=True)
class OwnerLineageSummary:
    lineage_id: str
    current_head_id: str
    revision_count: int
    latest_recorded_at: int


@dataclass(frozen=True, slots=True)
class OwnerChangeSetSummary:
    change_set_id: str
    batch_id: str
    batch_sealed_at: int
    state: Literal["draft", "applied"]
    created_at: int
    current_revision_id: str
    current_digest: str
    current_adapter_origin: ChangeSetAdapterOrigin
    current_lifecycle: Literal["current_draft", "applied"]
    revision_count: int
    item_count: int
    batch_source_count: int
    accounted_source_count: int
    unaccounted_source_count: int
    application_id: str | None


@dataclass(frozen=True, slots=True)
class OwnerReviewRosterItem:
    ordinal: int
    item_id: str
    status: Literal["active", "rejected"]
    change_kind: Literal["new_memory", "correction"]
    target_lineage_id: str | None
    statement_preview: str
    statement_elided: bool


@dataclass(frozen=True, slots=True)
class OwnerReviewRosterSource:
    ordinal: int
    source_id: str
    blob_digest: str
    coverage: Literal["used", "no_memory", "unaccounted"]


@dataclass(frozen=True, slots=True)
class OwnerSourceDecision:
    ordinal: int
    source_id: str
    blob_digest: str
    coverage: Literal["used", "no_memory", "unaccounted"]
    reason: str | None


@dataclass(frozen=True, slots=True)
class OwnerDraftGuardLink:
    """One proposed guard link with both endpoints resolved to their statements.

    ``guard_ref`` and ``governed_ref`` are the exact stored references: a draft
    item identifier or a canonical lineage identifier, whichever the link named.
    The statements and sensitivities beside them are resolved so the owner reads
    the two claims rather than two opaque identifiers, and so an inverted pair
    (a guard more sensitive than the claim it governs) is visible at a glance.
    """

    ordinal: int
    status: Literal["active", "rejected"]
    guard_ref: str
    governed_ref: str
    guard_statement: str
    governed_statement: str
    guard_sensitivity: Sensitivity
    governed_sensitivity: Sensitivity
    # Which kind of reference each side gave. The owner edit form has to post
    # the exact endpoint field the stored link used, and a draft item id and a
    # lineage id are not distinguishable by shape.
    guard_kind: Literal["item", "lineage"]
    governed_kind: Literal["item", "lineage"]
    # Canonical endpoints carry the current head ID so a compact statement can
    # still lead to the complete memory and its evidence. Draft-item endpoints
    # use the exact comparison route and therefore leave this absent.
    guard_memory_id: str | None = None
    governed_memory_id: str | None = None


@dataclass(frozen=True, slots=True)
class OwnerReviewBlocker:
    ordinal: int
    code: Literal[
        "unaccounted_source",
        "ambiguous_evidence",
        "stale_expected_head",
        "duplicate_lineage_target",
        "invalid_review",
    ]
    item_id: str | None
    source_id: str | None
    expected_head_id: str | None
    current_head_id: str | None


@dataclass(frozen=True, slots=True)
class OwnerChangeSetRevisionSummary:
    change_set_id: str
    revision_id: str
    predecessor_revision_id: str | None
    digest: str
    adapter_origin: ChangeSetAdapterOrigin
    recorded_at: int
    lifecycle: Literal["current_draft", "applied", "superseded"]
    item_count: int
    batch_source_count: int
    accounted_source_count: int
    unaccounted_source_count: int


@dataclass(frozen=True, slots=True)
class OwnerReviewManifest:
    batch_id: str
    batch_sealed_at: int
    revision: OwnerChangeSetRevisionSummary
    blocker_count: int
    item_roster: tuple[OwnerReviewRosterItem, ...]
    source_roster: tuple[OwnerReviewRosterSource, ...]
    guard_links: tuple[OwnerDraftGuardLink, ...] = ()
    revoked_guard_links: tuple[OwnerDraftGuardLink, ...] = ()
    """Retained links this revision withdraws when it applies.

    Kept apart from `guard_links` rather than flagged inside it, mirroring the
    two separate draft tables: a proposal and a withdrawal read as opposite
    intents, and one list holding both is one list every reader can misread.
    """

    @property
    def validation_state(self) -> Literal["valid", "blocked"]:
        return "valid" if self.blocker_count == 0 else "blocked"


@dataclass(frozen=True, slots=True)
class OwnerReviewItemComparison:
    ordinal: int
    item_id: str
    status: Literal["active", "rejected"]
    change_kind: Literal["new_memory", "correction"]
    proposal: MemoryFields
    predecessor: OwnerMemorySummary | None
    proposal_evidence: tuple[EvidenceLocator, ...]
    predecessor_evidence: tuple[EvidenceLocator, ...]


@dataclass(frozen=True, slots=True)
class OwnerReviewItemEditTarget:
    item_id: str
    ordinal: int
    status: Literal["active", "rejected"]
    memory: MemoryFields
    evidence: tuple[EvidenceLocator, ...]


@dataclass(frozen=True, slots=True)
class OwnerReviewSourceEditTarget:
    source_id: str
    blob_digest: str
    coverage: Literal["used", "no_memory", "unaccounted"]
    reason: str | None


@dataclass(frozen=True, slots=True)
class OwnerReviewAddEditTarget:
    generated_item_id: str
    generated_item_id_absent: bool
    referenced_sources: tuple[OwnerReviewSourceEditTarget, ...]


@dataclass(frozen=True, slots=True)
class OwnerReviewGuardLinkEditTarget:
    """The exact guard link one link operation names, as it stands now.

    ``present`` is the whole target state: adding a link that already exists and
    removing one that no longer does are both edits whose base changed under the
    owner, so the fingerprint must move when it flips. ``proposal`` names which
    of the revision's two link lists ``present`` was read from, so an add and a
    revocation of the same pair can never share a fingerprint.
    """

    guard_item_id: str | None
    guard_lineage_id: str | None
    governed_item_id: str | None
    governed_lineage_id: str | None
    present: bool
    status: Literal["active", "rejected"] | None
    proposal: Literal["link", "revocation"] = "link"


type ReviewEditTargetState = (
    OwnerReviewItemEditTarget
    | OwnerReviewSourceEditTarget
    | OwnerReviewAddEditTarget
    | OwnerReviewGuardLinkEditTarget
)


@dataclass(frozen=True, slots=True)
class OwnerReviewEditTarget:
    change_set_id: str
    revision_id: str
    digest: str
    lifecycle: Literal["current_draft", "applied", "superseded"]
    state: ReviewEditTargetState
    state_fingerprint: str


@dataclass(frozen=True, slots=True)
class UiPendingReviewForm:
    """One bounded normalized owner edit retained only in process memory."""

    change_set_id: str
    expected_revision_id: str
    expected_digest: str
    operation: OwnerReviewFormIntent
    normalized_fields: tuple[tuple[str, str], ...]
    base_target_fingerprint: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class PendingReviewLease:
    """Exclusive one-use authority to apply a retained pending owner edit."""

    lease_id: str
    form: UiPendingReviewForm
    state: Literal["in_flight"]


@dataclass(frozen=True, slots=True)
class UiPendingReviewConflict:
    """One stale owner edit retained for explicit owner-visible resolution."""

    form: UiPendingReviewForm
    current_revision_id: str
    current_digest: str
    current_target_fingerprint: str


@dataclass(frozen=True, slots=True)
class PendingReviewConflictLease:
    """Exclusive authority bound to one exact server-selected current revision."""

    lease_id: str
    form: UiPendingReviewForm
    selected_revision_id: str
    selected_digest: str
    selected_target_fingerprint: str
    state: Literal["in_flight"]


type UiPendingReviewState = UiPendingReviewForm | UiPendingReviewConflict


@dataclass(frozen=True, slots=True)
class OwnerApplicationSummary:
    application_id: str
    change_set_id: str
    revision_id: str
    applied_at: int
    resulting_memory_count: int


@dataclass(frozen=True, slots=True)
class OwnerApprovalSummary:
    approval_id: str
    change_set_id: str
    revision_id: str
    digest: str
    adapter: OwnerApprovalAdapter
    approved_at: int


@dataclass(frozen=True, slots=True)
class OwnerAppliedReviewDetail:
    application: OwnerApplicationSummary
    approval: OwnerApprovalSummary
    memory_revision_ids: tuple[str, ...]


type OwnerApplicationDetail = OwnerAppliedReviewDetail
type OwnerApprovalDetail = OwnerAppliedReviewDetail


@dataclass(frozen=True, slots=True)
class OwnerGuardCandidate:
    """One heuristic guard-link proposal, ready to read and to act on.

    Statements are clipped for the page and each side links to its memory,
    which is where the untruncated claim lives. The panel is a place to judge
    pairs, not to re-read the corpus, and an unclipped statement is up to
    `MAX_STATEMENT_BYTES` -- two of them on every row of a 256-row report is a
    page no response budget survives.
    """

    guard_lineage_id: str
    governed_lineage_id: str
    guard_revision_id: str
    governed_revision_id: str
    guard_statement: str
    governed_statement: str
    guard_elided: bool
    governed_elided: bool
    rationales: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerGuardRepairTarget:
    """The draft review a proposed link can actually be written into.

    A guard link is an edit to a Memory Review, so the panel can only deep-link
    while one is open. Absent, the panel says so rather than offering a link
    that lands on a page with nothing to edit.

    ``batch_id`` and ``open_draft_count`` exist because "the open review" is
    not always one review. One change set is ever open per batch, but several
    batches can have one at once, and the panel picks the newest -- which may
    belong to a batch that has nothing to do with the pair being repaired. The
    page names the review it will write into, and says how many others are
    open, rather than asserting a singular the Store cannot promise.
    """

    change_set_id: str
    batch_id: str
    open_draft_count: int
    revision_id: str


@dataclass(frozen=True, slots=True)
class OwnerGuardLintPanel:
    """The guard-repair report as one bounded read-only owner page.

    `available` is false on a Store whose guard tables the additive heal has
    not reached: this is a read, and a read cannot heal anything, so it says
    what to run instead of guessing at a report it cannot compute.
    """

    available: bool
    candidates: tuple[OwnerGuardCandidate, ...]
    shown_candidate_count: int
    reported_candidate_count: int
    truncated_candidate_count: int
    standing_violations: tuple[GuardViolation, ...]
    truncated_violation_count: int
    repair_target: OwnerGuardRepairTarget | None


@dataclass(frozen=True, slots=True)
class OwnerGraphNode:
    """One positioned node.

    Enum values are flattened to ``str`` because every one of them lands in a
    class name or a data attribute; a template reaching for ``.value`` on each
    node of a two-thousand-node scene buys nothing.
    """

    key: str
    layer: str
    entity_id: str
    label: str
    kind: str | None
    sensitivity: str
    detail_path: str
    x: float
    y: float
    radius: float
    role: str = ""
    """What this node does in its lens: "guard" on the governance lens.

    A guard and the claim it governs are both memories, so nothing about the
    entity distinguishes them -- only the part they play in this picture does.
    """


@dataclass(frozen=True, slots=True)
class OwnerGraphEdge:
    """One positioned edge, carrying its own SVG path data."""

    kind: str
    from_key: str
    to_key: str
    path: str
    inverted: bool = False
    #: A guard link an owner-approved revocation detached. It stays drawn
    #: because the relationship is part of the audit record, and it is never
    #: drawn as inverted: a link that no longer governs anything cannot be a
    #: sensitivity inversion, and the lens tells the owner an inverted arrow is
    #: a standing violation to repair.
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class OwnerGraphSector:
    """One area's arc, so its name can be written along the wedge it owns.

    A point label competes with its neighbours for the same spot; an arc label
    uses the angular space the sector already has, which is why a sunburst
    names its rings this way.
    """

    name: str
    path_id: str
    path: str


@dataclass(frozen=True, slots=True)
class OwnerGraphScene:
    """One laid-out lens, or an honest refusal with the real node count."""

    lens: str
    nodes: tuple[OwnerGraphNode, ...]
    edges: tuple[OwnerGraphEdge, ...]
    width: float
    height: float
    total_node_count: int
    #: The figure that was actually compared against the ceiling. It differs
    #: from ``total_node_count`` for a filtered lens, which measures its own
    #: selection, and for a refusal triggered after materialisation, where the
    #: scene carries aspect markers that belong to no table.
    measured_node_count: int
    within_ceiling: bool
    guard_links_available: bool
    measured_edge_count: int = 0
    sectors: tuple[OwnerGraphSector, ...] = ()
