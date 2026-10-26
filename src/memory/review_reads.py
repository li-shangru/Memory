"""The owner view of reviews, approvals, and applications.

Every name here is read by `memory.ui`, and only by `memory.ui`. It used to
live at the bottom of `reviews.py` behind a leading underscore, which said
"module-private" about a set of functions another package imports by name --
the underscore was the misinformation, not the coupling. The dependency runs
one way: this module reads what the review kernel wrote, and the kernel never
calls back into it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

from memory.database import Connection, Row
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
)
from memory.model import (
    ChangeSetAdapterOrigin,
    Cursor,
    StoreIdentity,
)
from memory.sources import (
    _validate_opaque_id,
    _validate_page_size,
    owner_cursor_bounds,
    owner_filter_binding,
    owner_page_from_rows,
)
from memory.ui.view_models import (
    OwnerApplicationSummary,
    OwnerAppliedReviewDetail,
    OwnerApprovalSummary,
    OwnerChangeSetRevisionSummary,
    OwnerChangeSetSummary,
    OwnerPage,
    OwnerSourceDecision,
)

OWNER_APPROVAL_ADAPTERS = frozenset(
    {"mcp_elicitation", "local_owner_ui", "os_owner_presence_cli"}
)


@dataclass(frozen=True, slots=True)
class OwnerRevisionAuth:
    change_set_id: str
    batch_id: str
    batch_sealed_at: int
    change_set_state: Literal["draft", "applied"]
    change_set_created_at: int
    latest_revision_id: str
    revision_id: str
    predecessor_revision_id: str | None
    digest: str
    adapter_origin: ChangeSetAdapterOrigin
    recorded_at: int
    application_id: str | None
    application_revision_id: str | None

    @property
    def lifecycle(self) -> Literal["current_draft", "applied", "superseded"]:
        if self.application_revision_id == self.revision_id:
            return "applied"
        if (
            self.change_set_state == "draft"
            and self.latest_revision_id == self.revision_id
        ):
            return "current_draft"
        return "superseded"


def owner_revision_auth(
    connection: Connection,
    change_set_id: str,
    revision_id: str | None,
) -> OwnerRevisionAuth:
    _validate_opaque_id(change_set_id)
    if revision_id is not None:
        _validate_opaque_id(revision_id)
    change_set = connection.execute(
        "SELECT change_set.batch_id, change_set.state, change_set.created_at, "
        "batch.sealed_at, application.application_id, application.revision_id "
        "FROM change_sets AS change_set "
        "JOIN inbox_batches AS batch ON batch.batch_id = change_set.batch_id "
        "LEFT JOIN applications AS application "
        "ON application.change_set_id = change_set.change_set_id "
        "WHERE change_set.change_set_id = ?",
        (change_set_id,),
    ).fetchone()
    if change_set is None:
        raise NotFoundError("change-set identifier was not found")
    latest = connection.execute(
        "SELECT revision_id FROM change_set_revisions "
        "WHERE change_set_id = ? ORDER BY rowid DESC LIMIT 1",
        (change_set_id,),
    ).fetchone()
    if latest is None:
        raise InvalidArgumentError("change set has no immutable revision")
    selected_revision_id = str(latest[0]) if revision_id is None else revision_id
    revision = connection.execute(
        "SELECT predecessor_id, digest, adapter_origin, created_at "
        "FROM change_set_revisions WHERE change_set_id = ? AND revision_id = ?",
        (change_set_id, selected_revision_id),
    ).fetchone()
    if revision is None:
        raise NotFoundError("change-set revision identifier was not found")
    try:
        state = cast(Literal["draft", "applied"], str(change_set[1]))
        if state not in {"draft", "applied"}:
            raise ValueError
        origin = ChangeSetAdapterOrigin(str(revision[2]))
    except ValueError as error:
        raise InvalidArgumentError("stored review metadata is invalid") from error
    return OwnerRevisionAuth(
        change_set_id=change_set_id,
        batch_id=str(change_set[0]),
        batch_sealed_at=int(change_set[3]),
        change_set_state=state,
        change_set_created_at=int(change_set[2]),
        latest_revision_id=str(latest[0]),
        revision_id=selected_revision_id,
        predecessor_revision_id=None if revision[0] is None else str(revision[0]),
        digest=str(revision[1]),
        adapter_origin=origin,
        recorded_at=int(revision[3]),
        application_id=None if change_set[4] is None else str(change_set[4]),
        application_revision_id=None if change_set[5] is None else str(change_set[5]),
    )


def owner_review_source_decisions(
    connection: Connection,
    auth: OwnerRevisionAuth,
) -> tuple[OwnerSourceDecision, ...]:
    rows = connection.execute(
        "SELECT membership.ordinal, source.source_id, blob.sha256, "
        "decision.state, decision.reason "
        "FROM inbox_batch_sources AS membership "
        "JOIN sources AS source ON source.source_id = membership.source_id "
        "JOIN source_blobs AS blob ON blob.blob_id = source.blob_id "
        "LEFT JOIN batch_source_decisions AS decision "
        "ON decision.revision_id = ? AND decision.source_id = source.source_id "
        "WHERE membership.batch_id = ? ORDER BY membership.ordinal",
        (auth.revision_id, auth.batch_id),
    ).fetchall()
    decisions: list[OwnerSourceDecision] = []
    for row in rows:
        raw_state = None if row[3] is None else str(row[3])
        if raw_state is None:
            coverage: Literal["used", "no_memory", "unaccounted"] = "unaccounted"
        elif raw_state in {"used", "no_memory"}:
            coverage = cast(Literal["used", "no_memory", "unaccounted"], raw_state)
        else:
            raise InvalidArgumentError("stored source decision is invalid")
        decisions.append(
            OwnerSourceDecision(
                ordinal=int(row[0]),
                source_id=str(row[1]),
                blob_digest=str(row[2]),
                coverage=coverage,
                reason=None if row[4] is None else str(row[4]),
            )
        )
    batch_count = connection.execute(
        "SELECT source_count FROM inbox_batches WHERE batch_id = ?",
        (auth.batch_id,),
    ).fetchone()
    if (
        batch_count is None
        or len(decisions) != int(batch_count[0])
        or tuple(item.ordinal for item in decisions) != tuple(range(len(decisions)))
    ):
        raise InvalidArgumentError("sealed batch source roster is invalid")
    return tuple(decisions)


def owner_revision_summary(
    connection: Connection,
    auth: OwnerRevisionAuth,
) -> OwnerChangeSetRevisionSummary:
    item_count = int(
        connection.execute(
            "SELECT count(*) FROM change_items WHERE revision_id = ?",
            (auth.revision_id,),
        ).fetchone()[0]
    )
    decisions = owner_review_source_decisions(connection, auth)
    accounted = sum(item.coverage != "unaccounted" for item in decisions)
    return OwnerChangeSetRevisionSummary(
        change_set_id=auth.change_set_id,
        revision_id=auth.revision_id,
        predecessor_revision_id=auth.predecessor_revision_id,
        digest=auth.digest,
        adapter_origin=auth.adapter_origin,
        recorded_at=auth.recorded_at,
        lifecycle=auth.lifecycle,
        item_count=item_count,
        batch_source_count=len(decisions),
        accounted_source_count=accounted,
        unaccounted_source_count=len(decisions) - accounted,
    )


def owner_change_set_summary(
    connection: Connection,
    change_set_id: str,
) -> OwnerChangeSetSummary:
    auth = owner_revision_auth(connection, change_set_id, None)
    revision = owner_revision_summary(connection, auth)
    revision_count = int(
        connection.execute(
            "SELECT count(*) FROM change_set_revisions WHERE change_set_id = ?",
            (change_set_id,),
        ).fetchone()[0]
    )
    if revision.lifecycle not in {"current_draft", "applied"}:
        raise InvalidArgumentError("current review lifecycle is invalid")
    return OwnerChangeSetSummary(
        change_set_id=change_set_id,
        batch_id=auth.batch_id,
        batch_sealed_at=auth.batch_sealed_at,
        state=auth.change_set_state,
        created_at=auth.change_set_created_at,
        current_revision_id=auth.revision_id,
        current_digest=auth.digest,
        current_adapter_origin=auth.adapter_origin,
        current_lifecycle=revision.lifecycle,
        revision_count=revision_count,
        item_count=revision.item_count,
        batch_source_count=revision.batch_source_count,
        accounted_source_count=revision.accounted_source_count,
        unaccounted_source_count=revision.unaccounted_source_count,
        application_id=auth.application_id,
    )


def owner_list_change_sets(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    state: str | None,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerChangeSetSummary]:
    if state is not None and state not in {"draft", "applied"}:
        raise InvalidArgumentError("change-set state filter is invalid")
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"state": state})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.review.change-sets",
        cursor=cursor,
        upper_table="change_sets",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    if state is None:
        rows = connection.execute(
            "SELECT rowid, change_set_id FROM change_sets "
            "WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT ?",
            (after, upper, page_size + 1),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT rowid, change_set_id FROM change_sets "
            "WHERE state = ? AND rowid > ? AND rowid <= ? "
            "ORDER BY rowid LIMIT ?",
            (state, after, upper, page_size + 1),
        ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.review.change-sets",
        upper=upper,
        binding=binding,
        snapshot_token=snapshot_token,
        convert=lambda row: owner_change_set_summary(connection, str(row[1])),
    )


def owner_list_change_set_revisions(
    connection: Connection,
    identity: StoreIdentity,
    change_set_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerChangeSetRevisionSummary]:
    owner_revision_auth(connection, change_set_id, None)
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"change_set_id": change_set_id})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.review.revisions",
        cursor=cursor,
        upper_table="change_set_revisions",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        "SELECT rowid, revision_id FROM change_set_revisions "
        "WHERE change_set_id = ? AND rowid > ? AND rowid <= ? "
        "ORDER BY rowid LIMIT ?",
        (change_set_id, after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.review.revisions",
        upper=upper,
        binding=binding,
        snapshot_token=snapshot_token,
        convert=lambda row: owner_revision_summary(
            connection,
            owner_revision_auth(connection, change_set_id, str(row[1])),
        ),
    )


def owner_application_summary_from_row(row: Row) -> OwnerApplicationSummary:
    return OwnerApplicationSummary(
        application_id=str(row[1]),
        change_set_id=str(row[2]),
        revision_id=str(row[3]),
        applied_at=int(row[4]),
        resulting_memory_count=int(row[5]),
    )


OWNER_APPLICATION_SELECT = """
SELECT
    application.rowid,
    application.application_id,
    application.change_set_id,
    application.revision_id,
    application.applied_at,
    (SELECT count(*) FROM application_memories AS memory
     WHERE memory.application_id = application.application_id)
FROM applications AS application
"""


def owner_approval_summary_from_row(row: Row) -> OwnerApprovalSummary:
    adapter = str(row[5])
    if adapter not in OWNER_APPROVAL_ADAPTERS:
        raise InvalidArgumentError("stored approval adapter is invalid")
    return OwnerApprovalSummary(
        approval_id=str(row[1]),
        change_set_id=str(row[2]),
        revision_id=str(row[3]),
        digest=str(row[4]),
        adapter=cast(Any, adapter),
        approved_at=int(row[6]),
    )


OWNER_APPROVAL_SELECT = """
SELECT
    approval.rowid,
    approval.approval_id,
    approval.change_set_id,
    approval.revision_id,
    approval.digest,
    approval.adapter,
    approval.approved_at
FROM approvals AS approval
"""


def owner_list_applications(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerApplicationSummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.application.list",
        cursor=cursor,
        upper_table="applications",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_APPLICATION_SELECT
        + " WHERE application.rowid > ? AND application.rowid <= ? "
        "ORDER BY application.rowid LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.application.list",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_application_summary_from_row,
    )


def owner_list_approvals(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerApprovalSummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.approval.list",
        cursor=cursor,
        upper_table="approvals",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_APPROVAL_SELECT + " WHERE approval.rowid > ? AND approval.rowid <= ? "
        "ORDER BY approval.rowid LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.approval.list",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_approval_summary_from_row,
    )


def owner_applied_review_detail(
    connection: Connection,
    *,
    application_id: str | None = None,
    approval_id: str | None = None,
) -> OwnerAppliedReviewDetail:
    if (application_id is None) == (approval_id is None):
        raise InvalidArgumentError("one applied-review identifier is required")
    if application_id is not None:
        _validate_opaque_id(application_id)
        application_row = connection.execute(
            OWNER_APPLICATION_SELECT + " WHERE application.application_id = ?",
            (application_id,),
        ).fetchone()
        if application_row is None:
            raise NotFoundError("application identifier was not found")
        application = owner_application_summary_from_row(application_row)
        approval_row = connection.execute(
            OWNER_APPROVAL_SELECT
            + " WHERE approval.change_set_id = ? AND approval.revision_id = ?",
            (application.change_set_id, application.revision_id),
        ).fetchone()
    else:
        assert approval_id is not None
        _validate_opaque_id(approval_id)
        approval_row = connection.execute(
            OWNER_APPROVAL_SELECT + " WHERE approval.approval_id = ?",
            (approval_id,),
        ).fetchone()
        if approval_row is None:
            raise NotFoundError("approval identifier was not found")
        selected_approval = owner_approval_summary_from_row(approval_row)
        application_row = connection.execute(
            OWNER_APPLICATION_SELECT
            + " WHERE application.change_set_id = ? AND application.revision_id = ?",
            (selected_approval.change_set_id, selected_approval.revision_id),
        ).fetchone()
        if application_row is None:
            raise InvalidArgumentError("approval application provenance is invalid")
        application = owner_application_summary_from_row(application_row)
    if approval_row is None:
        raise InvalidArgumentError("application approval provenance is invalid")
    approval = owner_approval_summary_from_row(approval_row)
    if (
        approval.change_set_id != application.change_set_id
        or approval.revision_id != application.revision_id
    ):
        raise InvalidArgumentError("applied review provenance is inconsistent")
    memory_ids = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT memory_revision_id FROM application_memories "
            "WHERE application_id = ? ORDER BY ordinal",
            (application.application_id,),
        ).fetchall()
    )
    if len(memory_ids) != application.resulting_memory_count:
        raise InvalidArgumentError("application memory roster is invalid")
    return OwnerAppliedReviewDetail(
        application=application,
        approval=approval,
        memory_revision_ids=memory_ids,
    )
