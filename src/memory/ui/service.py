"""Bounded query-only application service for the trusted local owner UI."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from collections.abc import Iterable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Literal, cast

from memory.database import Connection, Row
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
    OwnerApprovalRequiredError,
    StaleCursorError,
    StaleRevisionError,
    WrongDigestError,
)
from memory.graph import StoreGraph, read_memory_neighbourhood, read_store_graph
from memory.inbox import (
    Clock,
    RuntimeDirectoryAuthority,
    SystemClock,
    _open_runtime_root,
    _verify_runtime_root,
    bind_runtime_directory_authority,
    capture_exact_staged_entry,
    count_visible_inbox_entries,
    exact_capture_custody_outcome,
    list_exact_recovery_issues,
    list_staged_entries,
    owner_correction_display_name,
    preserve_exact_correction_handoff,
    stage_exact_private_entry,
    stage_inbox_entry,
)
from memory.memories import (
    OWNER_MEMORY_SELECT,
    _normalize_filters,
)
from memory.memories import (
    owner_list_all_memories as _list_all_memories,
)
from memory.memories import (
    owner_list_lineages as _list_lineages,
)
from memory.memories import (
    owner_list_memory_lineage as _list_memory_lineage,
)
from memory.memories import (
    owner_memory_detail as _memory_detail,
)
from memory.memories import (
    owner_memory_projection_coverage as _memory_projection_coverage,
)
from memory.memories import (
    owner_memory_relationship_page as _memory_relationship_page,
)
from memory.memories import (
    owner_memory_search_page as _memory_search_page,
)
from memory.memories import (
    owner_memory_summary_from_row as _memory_summary_from_row,
)
from memory.model import (
    AddGuardLink,
    AddItem,
    ApplicationResult,
    Authorship,
    CapturedCorrection,
    CaptureRecoveryIssue,
    ChangeEdit,
    ChangeSetAdapterOrigin,
    ClearSourceNoMemory,
    Cursor,
    EvidenceInput,
    EvidenceLocator,
    GuardLinkInput,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    RejectItem,
    RemoveGuardLink,
    ReplaceItem,
    RestoreItem,
    RevokeGuardLink,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceCaptureOrigin,
    StagedInboxEntry,
    StoreIdentity,
    StoreStatus,
)
from memory.retrieval import (
    _read_source_from_connection,
)
from memory.retrieval import (
    owner_search_sources as _search_sources,
)
from memory.review_reads import (
    OwnerRevisionAuth as _RevisionAuth,
)
from memory.review_reads import (
    owner_applied_review_detail as _applied_review_detail,
)
from memory.review_reads import (
    owner_list_applications as _list_applications,
)
from memory.review_reads import (
    owner_list_approvals as _list_approvals,
)
from memory.review_reads import (
    owner_list_change_set_revisions as _list_change_set_revisions,
)
from memory.review_reads import (
    owner_list_change_sets as _list_change_sets,
)
from memory.review_reads import (
    owner_review_source_decisions as _review_source_decisions,
)
from memory.review_reads import (
    owner_revision_auth as _revision_auth,
)
from memory.review_reads import (
    owner_revision_summary as _revision_summary,
)
from memory.reviews import (
    MAX_EVIDENCE_PER_ITEM,
    OwnerApproval,
    _batch_sources,
    _load_change_set_revision,
    _load_guard_links,
    _load_guard_revocations,
    _locator_from_row,
    _parse_tags,
    _review_validation_issues,
    render_change_set,
)
from memory.reviews import (
    approve_and_apply as _approve_and_apply,
)
from memory.reviews import (
    edit_change_set as _edit_change_set,
)
from memory.reviews import (
    get_change_set as _get_change_set,
)
from memory.sources import (
    _encode_cursor,
    _read_connection,
    _validate_opaque_id,
    _validate_page_size,
)
from memory.sources import (
    _source_status_membership_sql as _source_status_membership,
)
from memory.sources import (
    owner_batch_detail as _batch_detail,
)
from memory.sources import (
    owner_canonical_hash as _canonical_hash,
)
from memory.sources import (
    owner_current_generation as _current_generation,
)
from memory.sources import (
    owner_cursor_bounds as _cursor_bounds,
)
from memory.sources import (
    owner_filter_binding as _filter_binding,
)
from memory.sources import (
    owner_generation_token as _generation_token,
)
from memory.sources import (
    owner_list_batches as _list_batches,
)
from memory.sources import (
    owner_list_batches_by_origin as _list_batches_by_origin,
)
from memory.sources import (
    owner_list_blob_captures as _list_blob_captures,
)
from memory.sources import (
    owner_list_source_evidence_links as _list_source_evidence_links,
)
from memory.sources import (
    owner_list_sources as _list_sources,
)
from memory.sources import (
    owner_page_from_rows as _page_from_rows,
)
from memory.sources import (
    owner_source_detail as _source_detail,
)
from memory.sources import (
    owner_source_projection_coverage as _source_projection_coverage,
)
from memory.ui.browser_launch import FinderRevealer
from memory.ui.capture import (
    MAX_OWNER_CORRECTION_SOURCE_BYTES,
    CorrectionSubmissionLease,
    ExactCaptureMetadata,
    PreparedOwnerCorrection,
)
from memory.ui.presentation import roster_statement_preview
from memory.ui.request_limits import (
    MAX_GUARD_CANDIDATE_STATEMENT_CHARS,
    UI_GUARD_CANDIDATE_LIMIT,
    UI_GUARD_VIOLATION_LIMIT,
    UI_MEMORY_RELATION_PAGE_LIMIT,
)
from memory.ui.view_models import (
    OWNER_REVIEW_ITEM_PAGE_LIMIT,
    AuditCounts,
    AuditIndex,
    AuditSnapshot,
    InboxStatus,
    OwnerApplicationDetail,
    OwnerApplicationSummary,
    OwnerApprovalDetail,
    OwnerApprovalSummary,
    OwnerBatchDetail,
    OwnerBatchSummary,
    OwnerChangeSetRevisionSummary,
    OwnerChangeSetSummary,
    OwnerDraftGuardLink,
    OwnerEvidenceLink,
    OwnerGuardCandidate,
    OwnerGuardLintPanel,
    OwnerGuardRepairTarget,
    OwnerLineageSummary,
    OwnerMemoryDetail,
    OwnerMemorySearchPage,
    OwnerMemorySummary,
    OwnerPage,
    OwnerReviewAddEditTarget,
    OwnerReviewBlocker,
    OwnerReviewEditTarget,
    OwnerReviewGuardLinkEditTarget,
    OwnerReviewItemComparison,
    OwnerReviewItemEditTarget,
    OwnerReviewManifest,
    OwnerReviewRosterItem,
    OwnerReviewRosterSource,
    OwnerReviewSourceEditTarget,
    OwnerSourceChunk,
    OwnerSourceDecision,
    OwnerSourceDetail,
    OwnerSourceSearchPage,
    OwnerSourceSummary,
    OwnerStatus,
    ProjectionCoverage,
    ReviewEditTargetState,
)


def normalize_owner_memory_filters(filters: MemoryFilters) -> MemoryFilters:
    """Normalize UI filter input through the canonical retrieval contract."""
    return _normalize_filters(filters)


OWNER_EDIT_TARGET_FORMAT = "memory.owner-review-edit-target.v1"
_AUDIT_READER_CONSTRUCTOR = object()
_AUDIT_TABLES = (
    "application_memories",
    "applications",
    "approvals",
    "batch_source_decisions",
    "change_item_evidence",
    "change_items",
    "change_set_revisions",
    "change_sets",
    "current_memory_heads",
    "inbox_batch_issues",
    "inbox_batch_sources",
    "inbox_batches",
    "memory_evidence",
    "memory_fts",
    "memory_lineages",
    "memory_revisions",
    "source_blobs",
    "source_fts",
    "sources",
)


def _source_chunk(
    connection: Connection,
    identity: StoreIdentity,
    source_id: str,
    cursor: Cursor | None,
    max_bytes: int,
    *,
    snapshot_token: str | None,
) -> OwnerSourceChunk:
    chunk = _read_source_from_connection(
        connection,
        identity,
        source_id,
        cursor=cursor,
        max_bytes=max_bytes,
        snapshot=snapshot_token,
    )
    return OwnerSourceChunk(
        source_id=chunk.source_id,
        blob_digest=chunk.blob_digest,
        media_type=chunk.media_type,
        text=chunk.text,
        binary=chunk.binary,
        char_start=chunk.char_start,
        char_end=chunk.char_end,
        byte_start=chunk.byte_start,
        byte_end=chunk.byte_end,
        next_cursor=chunk.next_cursor,
        complete=chunk.complete,
    )


def _item_fields_from_row(row: Row) -> MemoryFields:
    try:
        return MemoryFields(
            kind=MemoryKind(str(row[4])),
            statement=str(row[5]),
            occurred_on=None if row[6] is None else str(row[6]),
            valid_from=None if row[7] is None else str(row[7]),
            valid_to=None if row[8] is None else str(row[8]),
            tags=_parse_tags(row[9]),
            sensitivity=Sensitivity(str(row[10])),
            target_lineage_id=None if row[11] is None else str(row[11]),
            expected_head_id=None if row[12] is None else str(row[12]),
        )
    except ValueError as error:
        raise InvalidArgumentError("stored review item fields are invalid") from error


_REVIEW_ITEM_SELECT = """
SELECT
    item.rowid,
    item.item_id,
    item.ordinal,
    item.status,
    item.kind,
    item.statement,
    item.occurred_on,
    item.valid_from,
    item.valid_to,
    item.tags_json,
    item.sensitivity,
    item.target_lineage_id,
    item.expected_head_id
FROM change_items AS item
"""


def _item_evidence(
    connection: Connection,
    revision_id: str,
    item_id: str,
) -> tuple[EvidenceLocator, ...]:
    rows = connection.execute(
        "SELECT ordinal, source_id, blob_digest, mode, char_start, char_end, "
        "excerpt, source_level FROM change_item_evidence "
        "WHERE revision_id = ? AND item_id = ? ORDER BY ordinal",
        (revision_id, item_id),
    ).fetchall()
    if len(rows) > MAX_EVIDENCE_PER_ITEM:
        raise InvalidArgumentError("review item evidence limit is invalid")
    return tuple(_locator_from_row(row) for row in rows)


def _review_item_comparison(
    connection: Connection,
    auth: _RevisionAuth,
    row: Row,
) -> OwnerReviewItemComparison:
    item_id = str(row[1])
    status = str(row[3])
    if status not in {"active", "rejected"}:
        raise InvalidArgumentError("stored review item status is invalid")
    proposal = _item_fields_from_row(row)
    predecessor: OwnerMemorySummary | None = None
    predecessor_evidence: tuple[EvidenceLocator, ...] = ()
    if proposal.target_lineage_id is not None:
        if proposal.expected_head_id is None:
            raise InvalidArgumentError("stored correction target is invalid")
        predecessor_row = connection.execute(
            OWNER_MEMORY_SELECT + " WHERE revision.revision_id = ?",
            (proposal.expected_head_id,),
        ).fetchone()
        if predecessor_row is not None:
            predecessor = _memory_summary_from_row(predecessor_row)
            predecessor_evidence = _memory_detail(
                connection, proposal.expected_head_id
            ).evidence
    return OwnerReviewItemComparison(
        ordinal=int(row[2]),
        item_id=item_id,
        status=cast(Literal["active", "rejected"], status),
        change_kind="correction"
        if proposal.target_lineage_id is not None
        else "new_memory",
        proposal=proposal,
        predecessor=predecessor,
        proposal_evidence=_item_evidence(connection, auth.revision_id, item_id),
        predecessor_evidence=predecessor_evidence,
    )


def _get_review_item(
    connection: Connection,
    change_set_id: str,
    revision_id: str,
    item_id: str,
) -> OwnerReviewItemComparison:
    """Read one exact comparison without walking its paginated siblings."""
    _validate_opaque_id(item_id)
    auth = _revision_auth(connection, change_set_id, revision_id)
    row = connection.execute(
        _REVIEW_ITEM_SELECT + " WHERE item.revision_id = ? AND item.item_id = ?",
        (revision_id, item_id),
    ).fetchone()
    if row is None:
        raise NotFoundError("review item identifier was not found")
    return _review_item_comparison(connection, auth, row)


def _sequence_page[T](
    connection: Connection,
    identity: StoreIdentity,
    items: tuple[T, ...],
    *,
    cursor: Cursor | None,
    limit: int,
    operation: str,
    binding: str,
    snapshot_token: str,
) -> OwnerPage[T]:
    page_size = _validate_page_size(limit)
    after, upper = _cursor_bounds(
        connection,
        identity,
        operation=operation,
        cursor=cursor,
        upper_table="store_meta",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=len(items),
    )
    visible = items[after : min(upper, after + page_size)]
    has_more = after + len(visible) < upper
    next_cursor = (
        _encode_cursor(
            store_id=identity.store_id,
            operation=operation,
            upper=upper,
            after=after + len(visible),
            binding=binding,
            snapshot=snapshot_token,
        )
        if has_more
        else None
    )
    return OwnerPage(items=visible, next_cursor=next_cursor, has_more=has_more)


def _list_review_items(
    connection: Connection,
    identity: StoreIdentity,
    change_set_id: str,
    revision_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerReviewItemComparison]:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= OWNER_REVIEW_ITEM_PAGE_LIMIT
    ):
        raise InvalidArgumentError(
            f"review item page limit must be between 1 and {OWNER_REVIEW_ITEM_PAGE_LIMIT}"
        )
    auth = _revision_auth(connection, change_set_id, revision_id)
    cursor_guard = (
        _generation_token(connection) if snapshot_token is None else snapshot_token
    )
    binding = _filter_binding(
        {
            "change_set_id": change_set_id,
            "revision_id": revision_id,
            "digest": auth.digest,
        }
    )
    after, upper = _cursor_bounds(
        connection,
        identity,
        operation="owner.review.items",
        cursor=cursor,
        upper_table="change_items",
        binding=binding,
        snapshot_token=cursor_guard,
        upper_override=upper_override,
    )
    rows = connection.execute(
        _REVIEW_ITEM_SELECT
        + " WHERE item.revision_id = ? AND item.rowid > ? AND item.rowid <= ? "
        "ORDER BY item.ordinal LIMIT ?",
        (revision_id, after, upper, limit + 1),
    ).fetchall()
    return _page_from_rows(
        rows,
        page_size=limit,
        identity=identity,
        operation="owner.review.items",
        upper=upper,
        binding=binding,
        snapshot_token=cursor_guard,
        convert=lambda row: _review_item_comparison(connection, auth, row),
    )


def _list_review_source_decisions(
    connection: Connection,
    identity: StoreIdentity,
    change_set_id: str,
    revision_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
) -> OwnerPage[OwnerSourceDecision]:
    auth = _revision_auth(connection, change_set_id, revision_id)
    cursor_guard = (
        _generation_token(connection) if snapshot_token is None else snapshot_token
    )
    binding = _filter_binding(
        {
            "change_set_id": change_set_id,
            "revision_id": revision_id,
            "digest": auth.digest,
        }
    )
    return _sequence_page(
        connection,
        identity,
        _review_source_decisions(connection, auth),
        cursor=cursor,
        limit=limit,
        operation="owner.review.source-decisions",
        binding=binding,
        snapshot_token=cursor_guard,
    )


def _review_blockers(
    connection: Connection,
    auth: _RevisionAuth,
) -> tuple[OwnerReviewBlocker, ...]:
    view = _load_change_set_revision(
        connection,
        auth.change_set_id,
        auth.revision_id,
    )
    issues = _review_validation_issues(
        connection,
        view,
        _batch_sources(connection, auth.batch_id),
    )
    raw = [
        (
            issue.code,
            issue.item_id,
            issue.source_id,
            issue.expected_head_id,
            issue.current_head_id,
        )
        for issue in issues
    ]

    code_order = {
        "unaccounted_source": 0,
        "ambiguous_evidence": 1,
        "stale_expected_head": 2,
        "duplicate_lineage_target": 3,
        "invalid_review": 4,
    }
    unique = sorted(
        set(raw),
        key=lambda item: (
            code_order[item[0]],
            "" if item[1] is None else item[1],
            "" if item[2] is None else item[2],
            "" if item[3] is None else item[3],
            "" if item[4] is None else item[4],
        ),
    )
    return tuple(
        OwnerReviewBlocker(
            ordinal=ordinal,
            code=cast(Any, item[0]),
            item_id=item[1],
            source_id=item[2],
            expected_head_id=item[3],
            current_head_id=item[4],
        )
        for ordinal, item in enumerate(unique)
    )


def _list_review_blockers(
    connection: Connection,
    identity: StoreIdentity,
    change_set_id: str,
    revision_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
) -> OwnerPage[OwnerReviewBlocker]:
    auth = _revision_auth(connection, change_set_id, revision_id)
    cursor_guard = (
        _generation_token(connection) if snapshot_token is None else snapshot_token
    )
    binding = _filter_binding(
        {
            "change_set_id": change_set_id,
            "revision_id": revision_id,
            "digest": auth.digest,
        }
    )
    return _sequence_page(
        connection,
        identity,
        _review_blockers(connection, auth),
        cursor=cursor,
        limit=limit,
        operation="owner.review.blockers",
        binding=binding,
        snapshot_token=cursor_guard,
    )


@dataclass(frozen=True, slots=True)
class _GuardEndpoint:
    """One resolved guard-link side: the stored reference and what it says."""

    reference: str
    kind: Literal["item", "lineage"]
    statement: str
    sensitivity: Sensitivity
    item_status: str | None
    memory_id: str | None


def _draft_item_endpoints(
    connection: Connection,
    revision_id: str,
) -> dict[str, _GuardEndpoint]:
    """Resolve every draft item in one revision to its proposed claim."""
    rows = connection.execute(
        "SELECT item_id, status, statement, sensitivity "
        "FROM change_items WHERE revision_id = ?",
        (revision_id,),
    ).fetchall()
    endpoints: dict[str, _GuardEndpoint] = {}
    for row in rows:
        try:
            sensitivity = Sensitivity(str(row[3]))
        except ValueError as error:
            raise InvalidArgumentError("stored review item fields are invalid") from (
                error
            )
        endpoints[str(row[0])] = _GuardEndpoint(
            reference=str(row[0]),
            kind="item",
            statement=str(row[2]),
            sensitivity=sensitivity,
            item_status=str(row[1]),
            memory_id=None,
        )
    return endpoints


def _lineage_head_endpoint(
    connection: Connection,
    lineage_id: str,
) -> _GuardEndpoint:
    """Resolve one canonical lineage to the claim its current head states."""
    row = connection.execute(
        OWNER_MEMORY_SELECT
        + " WHERE revision.lineage_id = ? AND heads.revision_id = revision.revision_id",
        (lineage_id,),
    ).fetchone()
    if row is None:
        # Unreachable in a consistent Store: every revision write validates that
        # a named lineage has a current head, and heads are never deleted. It
        # stays a raise rather than a placeholder row because a guard link whose
        # governed claim cannot be read is not something to render past.
        raise InvalidArgumentError("guard link names an unresolvable lineage")
    summary = _memory_summary_from_row(row).revision
    return _GuardEndpoint(
        reference=lineage_id,
        kind="lineage",
        statement=summary.statement,
        # The head's effective sensitivity, not its declared one: an inversion
        # the owner must see is an inversion of what the claim actually reads as.
        sensitivity=summary.effective_sensitivity,
        item_status=None,
        memory_id=summary.memory_id,
    )


def _guard_link_endpoint(
    connection: Connection,
    item_ref: str | None,
    lineage_ref: str | None,
    items: dict[str, _GuardEndpoint],
    lineages: dict[str, _GuardEndpoint],
) -> _GuardEndpoint:
    if item_ref is not None:
        resolved = items.get(item_ref)
        if resolved is None:
            raise InvalidArgumentError("guard link names a missing draft item")
        return resolved
    if lineage_ref is None:
        raise InvalidArgumentError("stored guard link endpoint is invalid")
    cached = lineages.get(lineage_ref)
    if cached is None:
        cached = _lineage_head_endpoint(connection, lineage_ref)
        lineages[lineage_ref] = cached
    return cached


def _review_guard_links(
    connection: Connection,
    revision_id: str,
    *,
    revocations: bool = False,
) -> tuple[OwnerDraftGuardLink, ...]:
    """Resolve one revision's guard entries into statement pairs for the owner."""
    stored = (
        _load_guard_revocations(connection, revision_id)
        if revocations
        else _load_guard_links(connection, revision_id)
    )
    if not stored:
        return ()
    items = _draft_item_endpoints(connection, revision_id)
    lineages: dict[str, _GuardEndpoint] = {}
    resolved: list[OwnerDraftGuardLink] = []
    for ordinal, link in stored:
        guard = _guard_link_endpoint(
            connection, link.guard_item_id, link.guard_lineage_id, items, lineages
        )
        governed = _guard_link_endpoint(
            connection, link.governed_item_id, link.governed_lineage_id, items, lineages
        )
        rejected = "rejected" in {guard.item_status, governed.item_status}
        resolved.append(
            OwnerDraftGuardLink(
                ordinal=ordinal,
                status="rejected" if rejected else "active",
                guard_ref=guard.reference,
                governed_ref=governed.reference,
                guard_statement=guard.statement,
                governed_statement=governed.statement,
                guard_sensitivity=guard.sensitivity,
                governed_sensitivity=governed.sensitivity,
                guard_kind=guard.kind,
                governed_kind=governed.kind,
                guard_memory_id=guard.memory_id,
                governed_memory_id=governed.memory_id,
            )
        )
    return tuple(resolved)


def _review_manifest(
    connection: Connection,
    change_set_id: str,
    revision_id: str | None,
) -> OwnerReviewManifest:
    auth = _revision_auth(connection, change_set_id, revision_id)
    item_rows = connection.execute(
        "SELECT ordinal, item_id, status, target_lineage_id, statement "
        "FROM change_items WHERE revision_id = ? ORDER BY ordinal",
        (auth.revision_id,),
    ).fetchall()
    roster_items: list[OwnerReviewRosterItem] = []
    for row in item_rows:
        status = str(row[2])
        if status not in {"active", "rejected"}:
            raise InvalidArgumentError("stored review item status is invalid")
        target = None if row[3] is None else str(row[3])
        statement_preview, statement_elided = roster_statement_preview(str(row[4]))
        roster_items.append(
            OwnerReviewRosterItem(
                ordinal=int(row[0]),
                item_id=str(row[1]),
                status=cast(Literal["active", "rejected"], status),
                change_kind="correction" if target is not None else "new_memory",
                target_lineage_id=target,
                statement_preview=statement_preview,
                statement_elided=statement_elided,
            )
        )
    decisions = _review_source_decisions(connection, auth)
    blockers = _review_blockers(connection, auth)
    return OwnerReviewManifest(
        batch_id=auth.batch_id,
        batch_sealed_at=auth.batch_sealed_at,
        revision=_revision_summary(connection, auth),
        blocker_count=len(blockers),
        item_roster=tuple(roster_items),
        source_roster=tuple(
            OwnerReviewRosterSource(
                ordinal=item.ordinal,
                source_id=item.source_id,
                blob_digest=item.blob_digest,
                coverage=item.coverage,
            )
            for item in decisions
        ),
        guard_links=_review_guard_links(connection, auth.revision_id),
        revoked_guard_links=_review_guard_links(
            connection, auth.revision_id, revocations=True
        ),
    )


def _evidence_payload(
    evidence: Sequence[EvidenceInput | EvidenceLocator],
) -> list[dict[str, object]]:
    return [
        {
            "ordinal": item.ordinal if isinstance(item, EvidenceLocator) else ordinal,
            "source_id": item.source_id,
            "blob_digest": item.blob_digest,
            "mode": item.mode if isinstance(item, EvidenceLocator) else None,
            "char_start": item.char_start
            if isinstance(item, EvidenceLocator)
            else None,
            "char_end": item.char_end if isinstance(item, EvidenceLocator) else None,
            "excerpt": item.excerpt,
            "source_level": item.source_level,
        }
        for ordinal, item in enumerate(evidence)
    ]


def _memory_fields_payload(memory: MemoryFields) -> dict[str, object]:
    return {
        "kind": memory.kind.value,
        "statement": memory.statement,
        "occurred_on": memory.occurred_on,
        "valid_from": memory.valid_from,
        "valid_to": memory.valid_to,
        "tags": list(memory.tags),
        "sensitivity": memory.sensitivity.value,
        "target_lineage_id": memory.target_lineage_id,
        "expected_head_id": memory.expected_head_id,
    }


def _edit_payload(edit: ChangeEdit) -> dict[str, object]:
    if isinstance(edit, AddItem):
        return {
            "operation": "add_item",
            "client_item_id": edit.client_item_id,
            "memory": _memory_fields_payload(edit.memory),
            "evidence": _evidence_payload(edit.evidence),
        }
    if isinstance(edit, ReplaceItem):
        return {
            "operation": "replace_item",
            "item_id": edit.item_id,
            "memory": _memory_fields_payload(edit.memory),
            "evidence": _evidence_payload(edit.evidence),
        }
    if isinstance(edit, RejectItem):
        return {"operation": "reject_item", "item_id": edit.item_id}
    if isinstance(edit, RestoreItem):
        return {"operation": "restore_item", "item_id": edit.item_id}
    if isinstance(edit, SetSourceNoMemory):
        return {
            "operation": "set_source_no_memory",
            "source_id": edit.source_id,
            "reason": edit.reason,
        }
    if isinstance(edit, ClearSourceNoMemory):
        return {"operation": "clear_source_no_memory", "source_id": edit.source_id}
    if isinstance(edit, (AddGuardLink, RemoveGuardLink, RevokeGuardLink)):
        return {
            "operation": _GUARD_LINK_OPERATION_NAMES[type(edit)],
            **_guard_link_payload(edit.link),
        }
    raise InvalidArgumentError("review edit operation is invalid")


#: The wire name each guard-link edit answers to, so one payload builder can
#: serve all three without an isinstance ladder that grows per operation.
_GUARD_LINK_OPERATION_NAMES: dict[type, str] = {
    AddGuardLink: "add_guard_link",
    RemoveGuardLink: "remove_guard_link",
    RevokeGuardLink: "revoke_guard_link",
}


def _guard_link_payload(link: GuardLinkInput) -> dict[str, object]:
    if not isinstance(link, GuardLinkInput):
        raise InvalidArgumentError("guard link is invalid")
    return {
        "guard_item_id": link.guard_item_id,
        "guard_lineage_id": link.guard_lineage_id,
        "governed_item_id": link.governed_item_id,
        "governed_lineage_id": link.governed_lineage_id,
    }


def _state_payload(state: ReviewEditTargetState) -> dict[str, object]:
    if isinstance(state, OwnerReviewItemEditTarget):
        return {
            "type": "item",
            "item_id": state.item_id,
            "ordinal": state.ordinal,
            "status": state.status,
            "memory": _memory_fields_payload(state.memory),
            "evidence": _evidence_payload(state.evidence),
        }
    if isinstance(state, OwnerReviewSourceEditTarget):
        return {
            "type": "source",
            "source_id": state.source_id,
            "blob_digest": state.blob_digest,
            "coverage": state.coverage,
            "reason": state.reason,
        }
    if isinstance(state, OwnerReviewAddEditTarget):
        return {
            "type": "add",
            "generated_item_id": state.generated_item_id,
            "generated_item_id_absent": state.generated_item_id_absent,
            "referenced_sources": [
                _state_payload(source) for source in state.referenced_sources
            ],
        }
    if isinstance(state, OwnerReviewGuardLinkEditTarget):
        return {
            "type": "guard_link",
            "guard_item_id": state.guard_item_id,
            "guard_lineage_id": state.guard_lineage_id,
            "governed_item_id": state.governed_item_id,
            "governed_lineage_id": state.governed_lineage_id,
            "present": state.present,
            "status": state.status,
            "proposal": state.proposal,
        }
    raise InvalidArgumentError("review edit target state is invalid")


def _edit_target_fingerprint(
    store_id: str,
    change_set_id: str,
    edit: ChangeEdit,
    state: ReviewEditTargetState,
) -> str:
    """Hash one exact edit and complete bounded target state canonically."""
    return _canonical_hash(
        {
            "format": OWNER_EDIT_TARGET_FORMAT,
            "store_id": store_id,
            "change_set_id": change_set_id,
            "edit": _edit_payload(edit),
            "state": _state_payload(state),
        }
    )


def _review_source_edit_target(
    connection: Connection,
    auth: _RevisionAuth,
    source_id: str,
) -> OwnerReviewSourceEditTarget:
    _validate_opaque_id(source_id)
    row = connection.execute(
        "SELECT source.source_id, blob.sha256, decision.state, decision.reason "
        "FROM inbox_batch_sources AS membership "
        "JOIN sources AS source ON source.source_id = membership.source_id "
        "JOIN source_blobs AS blob ON blob.blob_id = source.blob_id "
        "LEFT JOIN batch_source_decisions AS decision "
        "ON decision.revision_id = ? AND decision.source_id = source.source_id "
        "WHERE membership.batch_id = ? AND source.source_id = ?",
        (auth.revision_id, auth.batch_id, source_id),
    ).fetchone()
    if row is None:
        raise NotFoundError("review source identifier was not found")
    raw_state = None if row[2] is None else str(row[2])
    if raw_state is None:
        coverage: Literal["used", "no_memory", "unaccounted"] = "unaccounted"
    elif raw_state in {"used", "no_memory"}:
        coverage = cast(Literal["used", "no_memory", "unaccounted"], raw_state)
    else:
        raise InvalidArgumentError("stored source decision is invalid")
    return OwnerReviewSourceEditTarget(
        source_id=str(row[0]),
        blob_digest=str(row[1]),
        coverage=coverage,
        reason=None if row[3] is None else str(row[3]),
    )


def _review_guard_link_edit_target(
    connection: Connection,
    revision_id: str,
    link: GuardLinkInput,
    *,
    proposal: Literal["link", "revocation"] = "link",
) -> OwnerReviewGuardLinkEditTarget:
    """Report whether one exact guard entry already stands in this revision."""
    if not isinstance(link, GuardLinkInput):
        raise InvalidArgumentError("guard link is invalid")
    for item_ref, lineage_ref in (
        (link.guard_item_id, link.guard_lineage_id),
        (link.governed_item_id, link.governed_lineage_id),
    ):
        endpoint = item_ref if item_ref is not None else lineage_ref
        if endpoint is None or (item_ref is not None and lineage_ref is not None):
            raise InvalidArgumentError("guard link endpoint must name item or lineage")
        _validate_opaque_id(endpoint)
    stored_entries = (
        _load_guard_revocations(connection, revision_id)
        if proposal == "revocation"
        else _load_guard_links(connection, revision_id)
    )
    present = any(stored == link for _ordinal, stored in stored_entries)
    status: Literal["active", "rejected"] | None = None
    if present:
        items = _draft_item_endpoints(connection, revision_id)
        endpoints = [
            items[reference]
            for reference in (link.guard_item_id, link.governed_item_id)
            if reference is not None and reference in items
        ]
        status = (
            "rejected"
            if any(endpoint.item_status == "rejected" for endpoint in endpoints)
            else "active"
        )
    return OwnerReviewGuardLinkEditTarget(
        guard_item_id=link.guard_item_id,
        guard_lineage_id=link.guard_lineage_id,
        governed_item_id=link.governed_item_id,
        governed_lineage_id=link.governed_lineage_id,
        present=present,
        status=status,
        proposal=proposal,
    )


def _review_edit_target(
    connection: Connection,
    identity: StoreIdentity,
    change_set_id: str,
    revision_id: str,
    digest: str,
    edit: ChangeEdit,
) -> OwnerReviewEditTarget:
    auth = _revision_auth(connection, change_set_id, revision_id)
    if not isinstance(digest, str) or len(digest) != 64:
        raise InvalidArgumentError("review digest is invalid")
    if digest != auth.digest:
        raise WrongDigestError("review digest does not match")
    if isinstance(edit, (ReplaceItem, RejectItem, RestoreItem)):
        _validate_opaque_id(edit.item_id)
        row = connection.execute(
            _REVIEW_ITEM_SELECT + " WHERE item.revision_id = ? AND item.item_id = ?",
            (revision_id, edit.item_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("review item identifier was not found")
        status = str(row[3])
        if status not in {"active", "rejected"}:
            raise InvalidArgumentError("stored review item status is invalid")
        state: ReviewEditTargetState = OwnerReviewItemEditTarget(
            item_id=str(row[1]),
            ordinal=int(row[2]),
            status=cast(Literal["active", "rejected"], status),
            memory=_item_fields_from_row(row),
            evidence=_item_evidence(connection, revision_id, str(row[1])),
        )
    elif isinstance(edit, (SetSourceNoMemory, ClearSourceNoMemory)):
        state = _review_source_edit_target(connection, auth, edit.source_id)
    elif isinstance(edit, AddItem):
        _validate_opaque_id(edit.client_item_id)
        if (
            isinstance(edit.evidence, (str, bytes))
            or not isinstance(edit.evidence, Sequence)
            or not 1 <= len(edit.evidence) <= MAX_EVIDENCE_PER_ITEM
        ):
            raise InvalidArgumentError("review add evidence count is invalid")
        unique_source_ids: list[str] = []
        for evidence in edit.evidence:
            if not isinstance(evidence, (EvidenceInput, EvidenceLocator)):
                raise InvalidArgumentError("review add evidence is invalid")
            if evidence.source_id not in unique_source_ids:
                unique_source_ids.append(evidence.source_id)
        referenced = tuple(
            _review_source_edit_target(connection, auth, source_id)
            for source_id in unique_source_ids
        )
        present = connection.execute(
            "SELECT 1 FROM change_items WHERE revision_id = ? AND item_id = ?",
            (revision_id, edit.client_item_id),
        ).fetchone()
        state = OwnerReviewAddEditTarget(
            generated_item_id=edit.client_item_id,
            generated_item_id_absent=present is None,
            referenced_sources=referenced,
        )
    elif isinstance(edit, (AddGuardLink, RemoveGuardLink, RevokeGuardLink)):
        state = _review_guard_link_edit_target(
            connection,
            revision_id,
            edit.link,
            proposal="revocation" if isinstance(edit, RevokeGuardLink) else "link",
        )
    else:
        raise InvalidArgumentError("review edit operation is invalid")
    return OwnerReviewEditTarget(
        change_set_id=change_set_id,
        revision_id=revision_id,
        digest=digest,
        lifecycle=auth.lifecycle,
        state=state,
        state_fingerprint=_edit_target_fingerprint(
            identity.store_id, change_set_id, edit, state
        ),
    )


def _projection_coverage(connection: Connection) -> ProjectionCoverage:
    return ProjectionCoverage(
        sources=_source_projection_coverage(connection),
        memories=_memory_projection_coverage(connection),
    )


def _audit_counts(connection: Connection) -> AuditCounts:
    def count(table: str) -> int:
        return int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])

    return AuditCounts(
        batch_count=count("inbox_batches"),
        batch_issue_row_count=count("inbox_batch_issues"),
        batch_issue_occurrence_count=int(
            connection.execute(
                "SELECT COALESCE(sum(count), 0) FROM inbox_batch_issues"
            ).fetchone()[0]
        ),
        source_count=count("sources"),
        change_set_count=count("change_sets"),
        change_set_revision_count=count("change_set_revisions"),
        approval_count=count("approvals"),
        application_count=count("applications"),
        lineage_count=count("memory_lineages"),
        memory_revision_count=count("memory_revisions"),
    )


def _high_water_marks(connection: Connection) -> tuple[tuple[str, int], ...]:
    return tuple(
        (
            table,
            int(
                connection.execute(
                    f"SELECT COALESCE(MAX(rowid), 0) FROM {table}"
                ).fetchone()[0]
            ),
        )
        for table in _AUDIT_TABLES
    )


def _build_snapshot(
    connection: Connection,
    identity: StoreIdentity,
) -> AuditSnapshot:
    return AuditSnapshot(
        store_id=identity.store_id,
        generation=_current_generation(connection),
        high_water_marks=_high_water_marks(connection),
        counts=_audit_counts(connection),
        projection_coverage=_projection_coverage(connection),
    )


def _validate_bound_snapshot(
    connection: Connection,
    identity: StoreIdentity,
    snapshot: AuditSnapshot,
) -> None:
    if (
        not isinstance(snapshot, AuditSnapshot)
        or snapshot.store_id != identity.store_id
    ):
        raise StaleCursorError("audit snapshot belongs to another Store")
    if _current_generation(connection) != snapshot.generation:
        raise StaleCursorError("audit snapshot generation changed")
    if _high_water_marks(connection) != snapshot.high_water_marks:
        raise StaleCursorError("audit snapshot high-water marks changed")


def _audit_token(snapshot: AuditSnapshot) -> str:
    return _canonical_hash(
        {
            "format": "memory.owner-audit-reader.v1",
            "object_identity": id(snapshot),
            "store_id": snapshot.store_id,
            "generation": snapshot.generation,
            "high_water_marks": [list(item) for item in snapshot.high_water_marks],
        }
    )


def _snapshot_upper(snapshot: AuditSnapshot, table: str) -> int:
    values = dict(snapshot.high_water_marks)
    try:
        return values[table]
    except KeyError as error:
        raise StaleCursorError("audit snapshot high-water mark is missing") from error


@contextmanager
def _query_session(
    paths: RuntimePaths,
) -> Iterator[tuple[Connection, StoreIdentity]]:
    with _read_connection(paths) as (connection, identity):
        connection.execute("BEGIN")
        yield connection, identity


def _clipped_statement(statement: str) -> tuple[str, bool]:
    """Collapse one claim to a single clipped line for a candidate row."""
    collapsed = " ".join(statement.split())
    if len(collapsed) <= MAX_GUARD_CANDIDATE_STATEMENT_CHARS:
        return collapsed, False
    return collapsed[: MAX_GUARD_CANDIDATE_STATEMENT_CHARS - 1] + "…", True


def _guard_lint_panel(connection: Connection) -> OwnerGuardLintPanel:
    """Read the guard-repair report for one bounded read-only owner page.

    This runs in a query session, not the writer session `memory lint guards`
    uses, because a GET creates no write-authority state -- it must not take
    the single-writer lock, and it must not run the additive table heal that
    every writer BEGIN performs. So the tables are checked instead of healed,
    and a Store still waiting for that heal gets an honest "run reindex" rather
    than a report computed against columns it does not have.
    """
    from memory.maintenance import guard_lint_report, guard_tables_present

    if not guard_tables_present(connection):
        return OwnerGuardLintPanel(
            available=False,
            candidates=(),
            shown_candidate_count=0,
            reported_candidate_count=0,
            truncated_candidate_count=0,
            standing_violations=(),
            truncated_violation_count=0,
            repair_target=None,
        )
    report = guard_lint_report(connection)
    heads = {
        str(row[0]): str(row[1])
        for row in connection.execute(
            "SELECT lineage_id, revision_id FROM current_memory_heads"
        ).fetchall()
    }
    candidates: list[OwnerGuardCandidate] = []
    for candidate in report.candidates[:UI_GUARD_CANDIDATE_LIMIT]:
        guard_statement, guard_elided = _clipped_statement(candidate.guard_statement)
        governed_statement, governed_elided = _clipped_statement(
            candidate.governed_statement
        )
        candidates.append(
            OwnerGuardCandidate(
                guard_lineage_id=candidate.guard_lineage_id,
                governed_lineage_id=candidate.governed_lineage_id,
                guard_revision_id=heads.get(candidate.guard_lineage_id, ""),
                governed_revision_id=heads.get(candidate.governed_lineage_id, ""),
                guard_statement=guard_statement,
                governed_statement=governed_statement,
                guard_elided=guard_elided,
                governed_elided=governed_elided,
                rationales=candidate.rationales,
            )
        )
    return OwnerGuardLintPanel(
        available=True,
        candidates=tuple(candidates),
        shown_candidate_count=len(candidates),
        reported_candidate_count=len(report.candidates),
        truncated_candidate_count=report.truncated_candidate_count,
        standing_violations=report.standing_violations[:UI_GUARD_VIOLATION_LIMIT],
        truncated_violation_count=max(
            0, len(report.standing_violations) - UI_GUARD_VIOLATION_LIMIT
        ),
        repair_target=_guard_repair_target(connection),
    )


def _guard_repair_target(connection: Connection) -> OwnerGuardRepairTarget | None:
    """Name the open draft a proposed link could be written into, if there is one.

    A guard link is an edit to a Memory Review, so a deep link needs a draft to
    land in, and the newest one is where a repair pass is being assembled. One
    change set is ever open per batch, but several batches can have one at
    once, so the chosen review is reported by name and beside a count of the
    others: a link that silently wrote into whichever draft happened to be
    newest would put a repair in a review curating an unrelated batch.
    """
    row = connection.execute(
        "SELECT change_set.change_set_id, change_set.batch_id, ("
        "    SELECT revision.revision_id FROM change_set_revisions AS revision "
        "    WHERE revision.change_set_id = change_set.change_set_id "
        "    ORDER BY revision.rowid DESC LIMIT 1"
        ") AS current_revision_id "
        "FROM change_sets AS change_set WHERE change_set.state = 'draft' "
        "ORDER BY change_set.rowid DESC LIMIT 1"
    ).fetchone()
    if row is None or row[2] is None:
        return None
    open_drafts = int(
        connection.execute(
            "SELECT count(*) FROM change_sets WHERE state = 'draft'"
        ).fetchone()[0]
    )
    return OwnerGuardRepairTarget(
        change_set_id=str(row[0]),
        batch_id=str(row[1]),
        open_draft_count=open_drafts,
        revision_id=str(row[2]),
    )


def _store_status(connection: Connection, identity: StoreIdentity) -> StoreStatus:
    from memory.maintenance import reindex_required
    from memory.mcp_schemas import contract_digest, skill_digest

    source_count = int(connection.execute("SELECT count(*) FROM sources").fetchone()[0])
    membership = _source_status_membership(connection)
    searchable_count = int(
        connection.execute(
            "SELECT count(*) FROM sources AS s "
            "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            f"WHERE {membership}"
        ).fetchone()[0]
    )
    memory_count = int(
        connection.execute("SELECT count(*) FROM current_memory_heads").fetchone()[0]
    )
    return StoreStatus(
        product=identity.product,
        schema_version=identity.schema_version,
        store_id=identity.store_id,
        source_count=source_count,
        memory_count=memory_count,
        searchable_count=searchable_count,
        unsearchable_count=source_count - searchable_count,
        pending_review_count=_pending_review_count(connection),
        reindex_required=reindex_required(connection),
        mcp_contract_digest=contract_digest(),
        skill_digest=skill_digest(),
    )


def _pending_review_count(connection: Connection) -> int:
    """Count the drafts waiting on an owner decision.

    One reader for both records: the header renders `OwnerStatus`, the status
    page renders the `StoreStatus` inside it, and two queries could drift into
    showing different backlogs on the same screen.
    """
    return int(
        connection.execute(
            "SELECT count(*) FROM change_sets WHERE state = 'draft'"
        ).fetchone()[0]
    )


def _availability(
    paths: RuntimePaths,
) -> Literal["available", "writer_busy", "unavailable"]:
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(paths.writer_lock, flags)
    except FileNotFoundError:
        return "available"
    except OSError:
        return "unavailable"
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "writer_busy"
        except OSError:
            return "unavailable"
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return "available"
    finally:
        os.close(descriptor)


def _inbox_status(
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> InboxStatus:
    return InboxStatus(
        inbox_display_path=os.fspath(paths.inbox.resolve()),
        staged_visible_entry_count=count_visible_inbox_entries(
            paths,
            directory_authority=directory_authority,
        ),
    )


def owner_status(
    connection: Connection,
    identity: StoreIdentity,
    paths: RuntimePaths,
    directory_authority: RuntimeDirectoryAuthority | None = None,
) -> OwnerStatus:
    return OwnerStatus(
        store=_store_status(connection, identity),
        runtime_mode=identity.runtime_mode,
        availability=_availability(paths),
        pending_review_count=_pending_review_count(connection),
        projections=_projection_coverage(connection),
        runtime_display_path=os.fspath(paths.root.resolve()),
        inbox=_inbox_status(paths, directory_authority),
    )


@dataclass(frozen=True, slots=True)
class _ReadBinding:
    """What one read is pinned to: the live Store, or one audit snapshot.

    The owner's live view and the in-app audit ask the Store the same twenty
    questions. The only difference is that the audit pins every answer to one
    snapshot's high-water marks, so it can never show a batch from one
    generation beside an approval from another. Carrying that as a value lets
    both views share one implementation of each read -- which matters more
    here than anywhere else in the product, because two copies drifting apart
    is precisely what the audit surface exists to make impossible.
    """

    snapshot: AuditSnapshot | None

    @property
    def token(self) -> str | None:
        return None if self.snapshot is None else _audit_token(self.snapshot)

    def upper(self, table: str) -> int | None:
        return None if self.snapshot is None else _snapshot_upper(self.snapshot, table)


@contextmanager
def _live_reads(
    paths: RuntimePaths,
) -> Iterator[tuple[Connection, StoreIdentity, _ReadBinding]]:
    with _query_session(paths) as (connection, identity):
        yield connection, identity, _ReadBinding(snapshot=None)


@contextmanager
def _bound_reads(
    paths: RuntimePaths,
    snapshot: AuditSnapshot,
) -> Iterator[tuple[Connection, StoreIdentity, _ReadBinding]]:
    with _query_session(paths) as (connection, identity):
        _validate_bound_snapshot(connection, identity, snapshot)
        yield connection, identity, _ReadBinding(snapshot=snapshot)


class _OwnerReads:
    """Every bounded read the live owner view and the audit view both serve.

    Subclasses supply only where the rows come from. `__slots__` is empty so a
    frozen slotted subclass keeps its own layout instead of gaining a dict.
    """

    __slots__ = ()

    def _reads(
        self,
    ) -> AbstractContextManager[tuple[Connection, StoreIdentity, _ReadBinding]]:
        raise NotImplementedError

    def list_batches(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerBatchSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_batches(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("inbox_batches"),
            )

    def get_batch(self, batch_id: str) -> OwnerBatchDetail:
        with self._reads() as (connection, _identity, _binding):
            return _batch_detail(connection, batch_id)

    def list_sources(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerSourceSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_sources(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("sources"),
            )

    def read_source(
        self,
        source_id: str,
        cursor: str | None,
        max_bytes: int,
    ) -> OwnerSourceChunk:
        with self._reads() as (connection, identity, binding):
            return _source_chunk(
                connection,
                identity,
                source_id,
                cursor,
                max_bytes,
                snapshot_token=binding.token,
            )

    def get_source_detail(self, source_id: str) -> OwnerSourceDetail:
        with self._reads() as (connection, _identity, _binding):
            return _source_detail(connection, source_id)

    def list_blob_captures(
        self,
        blob_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_blob_captures(
                connection,
                identity,
                blob_id,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("sources"),
            )

    def list_source_evidence_links(
        self,
        source_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerEvidenceLink]:
        with self._reads() as (connection, identity, binding):
            return _list_source_evidence_links(
                connection,
                identity,
                source_id,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("memory_evidence"),
            )

    def get_memory_revision(
        self,
        memory_id: str,
        *,
        guards_cursor: str | None = None,
        governs_cursor: str | None = None,
    ) -> OwnerMemoryDetail:
        with self._reads() as (connection, identity, binding):
            detail = _memory_detail(connection, memory_id)
            guards = _memory_relationship_page(
                connection,
                identity,
                detail.summary.revision,
                "guards",
                guards_cursor,
                UI_MEMORY_RELATION_PAGE_LIMIT,
                snapshot_token=binding.token,
            )
            governs = _memory_relationship_page(
                connection,
                identity,
                detail.summary.revision,
                "governs",
                governs_cursor,
                UI_MEMORY_RELATION_PAGE_LIMIT,
                snapshot_token=binding.token,
            )
            return replace(
                detail,
                guards=guards.items,
                governs=governs.items,
                guards_next_cursor=guards.next_cursor,
                governs_next_cursor=governs.next_cursor,
            )

    def list_memory_lineage(
        self,
        lineage_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerMemorySummary]:
        with self._reads() as (connection, identity, binding):
            return _list_memory_lineage(
                connection,
                identity,
                lineage_id,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("memory_revisions"),
            )

    def list_lineages(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerLineageSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_lineages(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("memory_lineages"),
            )

    def list_change_set_revisions(
        self,
        change_set_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerChangeSetRevisionSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_change_set_revisions(
                connection,
                identity,
                change_set_id,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("change_set_revisions"),
            )

    def get_review_manifest(
        self,
        change_set_id: str,
        revision_id: str | None = None,
    ) -> OwnerReviewManifest:
        with self._reads() as (connection, _identity, _binding):
            return _review_manifest(connection, change_set_id, revision_id)

    def list_review_items(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewItemComparison]:
        with self._reads() as (connection, identity, binding):
            return _list_review_items(
                connection,
                identity,
                change_set_id,
                revision_id,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("change_items"),
            )

    def get_review_item(
        self,
        change_set_id: str,
        revision_id: str,
        item_id: str,
    ) -> OwnerReviewItemComparison:
        with self._reads() as (connection, _identity, _binding):
            return _get_review_item(connection, change_set_id, revision_id, item_id)

    def list_review_source_decisions(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceDecision]:
        with self._reads() as (connection, identity, binding):
            return _list_review_source_decisions(
                connection,
                identity,
                change_set_id,
                revision_id,
                cursor,
                limit,
                snapshot_token=binding.token,
            )

    def list_review_blockers(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewBlocker]:
        with self._reads() as (connection, identity, binding):
            return _list_review_blockers(
                connection,
                identity,
                change_set_id,
                revision_id,
                cursor,
                limit,
                snapshot_token=binding.token,
            )

    def list_approvals(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerApprovalSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_approvals(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("approvals"),
            )

    def get_approval(self, approval_id: str) -> OwnerApprovalDetail:
        with self._reads() as (connection, _identity, _binding):
            return _applied_review_detail(connection, approval_id=approval_id)

    def list_applications(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerApplicationSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_applications(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("applications"),
            )

    def get_application(self, application_id: str) -> OwnerApplicationDetail:
        with self._reads() as (connection, _identity, _binding):
            return _applied_review_detail(connection, application_id=application_id)


@dataclass(frozen=True, slots=True)
class OwnerApplicationService(_OwnerReads):
    paths: RuntimePaths
    directory_authority: RuntimeDirectoryAuthority | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _directory_authority: RuntimeDirectoryAuthority = field(
        init=False,
        repr=False,
        compare=False,
    )

    def _reads(
        self,
    ) -> AbstractContextManager[tuple[Connection, StoreIdentity, _ReadBinding]]:
        return _live_reads(self.paths)

    def __post_init__(self) -> None:
        authority = self.directory_authority
        if authority is None:
            authority = bind_runtime_directory_authority(self.paths)
        try:
            with _open_runtime_root(self.paths, authority=authority) as runtime:
                _verify_runtime_root(runtime)
        except (AttributeError, TypeError) as error:
            raise InvalidArgumentError(
                "runtime directory authority is invalid"
            ) from error
        object.__setattr__(
            self,
            "_directory_authority",
            authority,
        )

    def get_status(self) -> OwnerStatus:
        with _query_session(self.paths) as (connection, identity):
            return owner_status(
                connection,
                identity,
                self.paths,
                self._directory_authority,
            )

    def render_approval_review(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str:
        """Render the exact current review that a final approval binding names."""
        view = _get_change_set(self.paths, change_set_id)
        if view.revision_id != revision_id:
            raise StaleRevisionError(
                "review revision is stale",
                details={"expected_revision_id": view.revision_id},
            )
        if view.digest != digest:
            raise WrongDigestError(
                "review digest does not match",
                details={"digest": view.digest},
            )
        return render_change_set(view)

    def list_staged_inbox_entries(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[StagedInboxEntry]:
        page = list_staged_entries(
            self.paths,
            cursor=cursor,
            limit=limit,
            directory_authority=self._directory_authority,
        )
        return OwnerPage(
            items=page.items,
            next_cursor=page.next_cursor,
            has_more=page.has_more,
        )

    def stage_inbox_file(
        self,
        *,
        owner_filename: str,
        chunks: Iterable[bytes],
    ) -> StagedInboxEntry:
        return stage_inbox_entry(
            self.paths,
            owner_filename=owner_filename,
            chunks=chunks,
            directory_authority=self._directory_authority,
        )

    def list_recent_correction_batches(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerBatchSummary]:
        with _query_session(self.paths) as (connection, identity):
            return _list_batches_by_origin(
                connection,
                identity,
                SourceCaptureOrigin.OWNER_CORRECTION,
                cursor,
                limit,
            )

    def list_capture_recovery_issues(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[CaptureRecoveryIssue]:
        page = list_exact_recovery_issues(
            self.paths,
            cursor=cursor,
            limit=limit,
            directory_authority=self._directory_authority,
        )
        return OwnerPage(
            items=page.items,
            next_cursor=page.next_cursor,
            has_more=page.has_more,
        )

    def reveal_inbox_in_finder(self, finder: FinderRevealer) -> None:
        """Resolve the owned Inbox capability and reveal it in process."""
        if not hasattr(finder, "reveal_directory_url"):
            raise InvalidArgumentError("Finder adapter is invalid")
        try:
            from Foundation import NSURL  # type: ignore[import-untyped]

            with _open_runtime_root(
                self.paths,
                authority=self._directory_authority,
            ) as runtime:
                _verify_runtime_root(runtime)
                directory_url = NSURL.fileURLWithPath_isDirectory_(
                    os.fspath(self.paths.inbox), True
                )
                if directory_url is None:
                    raise InvalidArgumentError("Inbox directory URL is invalid")
                reference_url = directory_url.fileReferenceURL()
                if reference_url is None:
                    raise InvalidArgumentError("Inbox file reference is invalid")
                _verify_runtime_root(runtime)
                if not reference_url.isFileReferenceURL():
                    raise InvalidArgumentError("Inbox file reference is invalid")
                try:
                    path_url = reference_url.filePathURL()
                    reference_path = None if path_url is None else path_url.path()
                    if not isinstance(reference_path, str):
                        raise TypeError
                    reference_metadata = os.stat(
                        reference_path,
                        follow_symlinks=False,
                    )
                except (OSError, TypeError) as error:
                    raise InvalidArgumentError(
                        "Inbox file reference is invalid"
                    ) from error
                if (
                    not stat.S_ISDIR(reference_metadata.st_mode)
                    or (reference_metadata.st_dev, reference_metadata.st_ino)
                    != runtime.inbox_identity
                ):
                    raise InvalidArgumentError("Inbox file reference is invalid")
                finder.reveal_directory_url(reference_url)
                _verify_runtime_root(runtime)
        except InvalidArgumentError:
            raise
        except Exception as error:
            raise InvalidArgumentError("Inbox reveal failed") from error

    def prepare_owner_correction(
        self,
        selected_memory_id: str,
        owner_text: str,
        *,
        clock: Clock | None = None,
    ) -> PreparedOwnerCorrection:
        """Serialize exact owner text against the submission-time current head."""
        if not isinstance(owner_text, str) or owner_text == "":
            raise InvalidArgumentError("owner correction text is empty")
        active_clock = SystemClock() if clock is None else clock
        with _query_session(self.paths) as (connection, identity):
            selected = _memory_detail(connection, selected_memory_id)
            current = _memory_detail(connection, selected.summary.current_head_id)
            if (
                current.summary.revision.lineage_id
                != selected.summary.revision.lineage_id
                or not current.summary.is_current
            ):
                raise InvalidArgumentError("memory current head is inconsistent")
            captured_at = int(active_clock.time())
            recorded_at = (
                datetime.fromtimestamp(captured_at, UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
            prefix = (
                "---\n"
                "format: memory.owner-correction.v1\n"
                f"store_id: {identity.store_id}\n"
                f"target_lineage_id: {current.summary.revision.lineage_id}\n"
                f"expected_head_id: {current.summary.current_head_id}\n"
                f"recorded_at: {recorded_at}\n"
                "---\n"
                "# Owner correction\n\n"
            )
            try:
                prefix_bytes = prefix.encode("utf-8", errors="strict")
                owner_bytes = owner_text.encode("utf-8", errors="strict")
            except UnicodeError as error:
                raise InvalidArgumentError(
                    "owner correction text is not UTF-8"
                ) from error
            source_bytes = prefix_bytes + owner_bytes
            if not 1 <= len(source_bytes) <= MAX_OWNER_CORRECTION_SOURCE_BYTES:
                raise InvalidArgumentError("owner correction source is too large")
            return PreparedOwnerCorrection(
                selected_memory_id=selected_memory_id,
                lineage_id=current.summary.revision.lineage_id,
                expected_head_id=current.summary.current_head_id,
                captured_at=captured_at,
                owner_text_offset=len(prefix_bytes),
                owner_text_sha256=hashlib.sha256(owner_bytes).hexdigest(),
                source_bytes=source_bytes,
                source_sha256=hashlib.sha256(source_bytes).hexdigest(),
            )

    def capture_owner_correction(
        self,
        lease: CorrectionSubmissionLease,
    ) -> CapturedCorrection:
        """Capture one exact correction buffer into its isolated reserved batch."""
        if not isinstance(lease, CorrectionSubmissionLease):
            raise InvalidArgumentError("correction lease is invalid")
        prepared = lease.prepared
        if hashlib.sha256(prepared.source_bytes).hexdigest() != prepared.source_sha256:
            raise InvalidArgumentError("correction lease payload is invalid")
        metadata = ExactCaptureMetadata(
            capture_request_id=lease.capture_request_id,
            batch_id=lease.reserved_batch_id,
            captured_at=prepared.captured_at,
            target_lineage_id=prepared.lineage_id,
            expected_head_id=prepared.expected_head_id,
            payload_sha256=prepared.source_sha256,
            source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
            authorship=Authorship.OWNER,
            sensitivity=Sensitivity.RESTRICTED,
        )
        display_name = owner_correction_display_name(lease.capture_request_id)
        entry = stage_exact_private_entry(
            self.paths,
            display_name=display_name,
            chunks=(prepared.source_bytes,),
            max_bytes=MAX_OWNER_CORRECTION_SOURCE_BYTES,
            metadata=metadata,
            directory_authority=self._directory_authority,
        )
        batch = capture_exact_staged_entry(
            self.paths,
            entry,
            metadata=metadata,
            directory_authority=self._directory_authority,
        )
        if len(batch.source_ids) != 1:
            raise InvalidArgumentError("correction batch roster is invalid")
        return CapturedCorrection(
            capture_request_id=lease.capture_request_id,
            batch_id=batch.batch_id,
            source_id=batch.source_ids[0],
            lineage_id=prepared.lineage_id,
            expected_head_id=prepared.expected_head_id,
            captured_at=prepared.captured_at,
        )

    def correction_capture_custody_outcome(
        self,
        lease: CorrectionSubmissionLease,
    ) -> Literal["proven_empty", "durable", "ambiguous"]:
        """Classify failed capture custody for process-buffer reclamation."""
        if not isinstance(lease, CorrectionSubmissionLease):
            raise InvalidArgumentError("correction lease is invalid")
        prepared = lease.prepared
        metadata = ExactCaptureMetadata(
            capture_request_id=lease.capture_request_id,
            batch_id=lease.reserved_batch_id,
            captured_at=prepared.captured_at,
            target_lineage_id=prepared.lineage_id,
            expected_head_id=prepared.expected_head_id,
            payload_sha256=prepared.source_sha256,
            source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
            authorship=Authorship.OWNER,
            sensitivity=Sensitivity.RESTRICTED,
        )
        outcome = exact_capture_custody_outcome(
            self.paths,
            display_name=owner_correction_display_name(lease.capture_request_id),
            byte_length=len(prepared.source_bytes),
            metadata=metadata,
            directory_authority=self._directory_authority,
        )
        if outcome != "ambiguous":
            return outcome
        if preserve_exact_correction_handoff(
            self.paths,
            source_bytes=prepared.source_bytes,
            metadata=metadata,
            directory_authority=self._directory_authority,
        ):
            return "durable"
        return "ambiguous"

    def search_sources(
        self,
        query: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerSourceSearchPage:
        with _query_session(self.paths) as (connection, identity):
            return _search_sources(connection, identity, query, cursor, limit)

    def list_memories(
        self,
        cursor: str | None,
        limit: int,
        filters: MemoryFilters,
    ) -> OwnerMemorySearchPage:
        with _query_session(self.paths) as (connection, identity):
            return _memory_search_page(
                connection,
                identity,
                query=None,
                filters=filters,
                cursor=cursor,
                limit=limit,
            )

    def read_store_graph(self, filters: MemoryFilters = MemoryFilters()) -> StoreGraph:
        with _query_session(self.paths) as (connection, _identity):
            return read_store_graph(connection, normalize_owner_memory_filters(filters))

    def read_memory_neighbourhood(self, memory_id: str) -> StoreGraph:
        with _query_session(self.paths) as (connection, _identity):
            return read_memory_neighbourhood(connection, memory_id)

    def read_guard_lint(self) -> OwnerGuardLintPanel:
        with _query_session(self.paths) as (connection, _identity):
            return _guard_lint_panel(connection)

    def search_memories(
        self,
        query: str,
        filters: MemoryFilters,
        cursor: str | None,
        limit: int,
    ) -> OwnerMemorySearchPage:
        with _query_session(self.paths) as (connection, identity):
            return _memory_search_page(
                connection,
                identity,
                query=query,
                filters=filters,
                cursor=cursor,
                limit=limit,
            )

    def list_change_sets(
        self,
        cursor: str | None,
        limit: int,
        state: str | None,
    ) -> OwnerPage[OwnerChangeSetSummary]:
        with _query_session(self.paths) as (connection, identity):
            return _list_change_sets(connection, identity, cursor, limit, state)

    def edit_review(
        self,
        change_set_id: str,
        expected_revision_id: str,
        edits: Sequence[ChangeEdit],
    ) -> OwnerReviewManifest:
        """Create one immutable owner-UI successor from bounded operations."""
        _edit_change_set(
            self.paths,
            change_set_id,
            expected_revision_id,
            edits,
            adapter_origin=ChangeSetAdapterOrigin.OWNER_UI,
        )
        with _query_session(self.paths) as (connection, _identity):
            return _review_manifest(connection, change_set_id, None)

    def apply_owner_approved_review(
        self,
        approval: OwnerApproval,
        *,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> ApplicationResult:
        """Apply one exact revision through the existing atomic domain operation.

        The caller must already hold a one-use ``OwnerApproval`` minted by a
        production approval adapter after OS-verified owner presence. This
        method never creates, elevates, or substitutes that capability.
        """
        if not isinstance(approval, OwnerApproval):
            raise OwnerApprovalRequiredError("direct owner approval is required")
        return _approve_and_apply(
            self.paths,
            change_set_id,
            revision_id,
            digest,
            approval,
        )

    def get_review_edit_target(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
        edit: ChangeEdit,
    ) -> OwnerReviewEditTarget:
        with _query_session(self.paths) as (connection, identity):
            return _review_edit_target(
                connection,
                identity,
                change_set_id,
                revision_id,
                digest,
                edit,
            )

    def get_review_edit_targets(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
        edits: Sequence[ChangeEdit],
    ) -> tuple[OwnerReviewEditTarget, ...]:
        """Resolve every edit in one submission against one bounded read.

        One session for the whole selection, not one per item: opening this
        Store is expensive by design -- SQLCipher with a deliberately slow key
        derivation -- so a sixty-four item selection resolved one at a time
        would spend a minute deriving the same key.
        """
        with _query_session(self.paths) as (connection, identity):
            return tuple(
                _review_edit_target(
                    connection,
                    identity,
                    change_set_id,
                    revision_id,
                    digest,
                    edit,
                )
                for edit in edits
            )

    def begin_audit_snapshot(self) -> AuditSnapshot:
        with _query_session(self.paths) as (connection, identity):
            return _build_snapshot(connection, identity)

    def bind_audit(self, snapshot: AuditSnapshot) -> BoundAuditReader:
        with _query_session(self.paths) as (connection, identity):
            _validate_bound_snapshot(connection, identity, snapshot)
            if _build_snapshot(connection, identity) != snapshot:
                raise StaleCursorError("audit snapshot is not a full Store snapshot")
        return BoundAuditReader(
            _AUDIT_READER_CONSTRUCTOR,
            paths=self.paths,
            snapshot=snapshot,
        )


@dataclass(frozen=True, slots=True, init=False)
class BoundAuditReader(_OwnerReads):
    _paths: RuntimePaths
    snapshot: AuditSnapshot

    def __init__(
        self,
        constructor: object,
        *,
        paths: RuntimePaths,
        snapshot: AuditSnapshot,
    ) -> None:
        if constructor is not _AUDIT_READER_CONSTRUCTOR:
            raise TypeError("BoundAuditReader is an internal capability")
        object.__setattr__(self, "_paths", paths)
        object.__setattr__(self, "snapshot", snapshot)

    def _reads(
        self,
    ) -> AbstractContextManager[tuple[Connection, StoreIdentity, _ReadBinding]]:
        return _bound_reads(self._paths, self.snapshot)

    def get_index(self) -> AuditIndex:
        with self._reads() as (connection, identity, _binding):
            return AuditIndex(
                store=owner_status(connection, identity, self._paths),
                snapshot=self.snapshot,
                integrity_capability="unavailable",
            )

    # The two reads below are the audit's own. The live view answers each of
    # them differently enough to need its own signature: it lists memories
    # through the filtered search page, and it lists change sets by state.
    def list_memories(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerMemorySummary]:
        with self._reads() as (connection, identity, binding):
            return _list_all_memories(
                connection,
                identity,
                cursor,
                limit,
                snapshot_token=binding.token,
                upper_override=binding.upper("memory_revisions"),
            )

    def list_change_sets(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerChangeSetSummary]:
        with self._reads() as (connection, identity, binding):
            return _list_change_sets(
                connection,
                identity,
                cursor,
                limit,
                None,
                snapshot_token=binding.token,
                upper_override=binding.upper("change_sets"),
            )
