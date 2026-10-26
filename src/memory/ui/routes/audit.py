"""Authenticated in-app Store audit bound to one full-coverage snapshot."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from memory.errors import InvalidArgumentError, StaleCursorError
from memory.inbox import MAX_BATCH_FILES
from memory.model import UiAuditState
from memory.reviews import MAX_CHANGE_ITEMS, MAX_NO_MEMORY_REASON_BYTES
from memory.ui.auth import UiSessionStore
from memory.ui.request_limits import (
    MAX_CONTROL_FORM_BODY_BYTES,
    MAX_CONTROL_FORM_FIELD_BYTES,
    MAX_FORM_FIELDS,
    MAX_STANDARD_HTML_RESPONSE_BYTES,
    MAX_UPLOAD_FILENAME_BYTES,
    STANDARD_PAGE_CHROME_BYTES,
    UI_STANDARD_PAGE_LIMIT,
    parse_bounded_urlencoded,
    read_bounded_body,
)
from memory.ui.routes._support import (
    page_limit,
    render_html,
    session_of,
    singleton_query,
)
from memory.ui.service import BoundAuditReader
from memory.ui.view_models import (
    AuditSnapshot,
    OwnerApplicationDetail,
    OwnerAppliedReviewDetail,
    OwnerApprovalDetail,
    OwnerStatus,
)
from memory.validation import require_invariant

AUDIT_HANDLE_PARAM = "h"

#: Longest opaque identifier the core accepts for any owner-visible row.
MAX_AUDIT_IDENTIFIER_BYTES = 256
#: Worst-case growth factor when escaping stored text into HTML.
AUDIT_ESCAPE_FACTOR = 5
#: Identifiers rendered by the widest audit row (batch, change set, revision,
#: digest, approval, and application).
MAX_AUDIT_IDENTIFIERS_PER_ROW = 6
#: Fixed markup, labels, counts, and timestamps rendered beside those values.
AUDIT_ROW_MARKUP_BYTES = 4_096

MAX_AUDIT_ROW_HTML_BYTES = (
    AUDIT_ESCAPE_FACTOR
    * (
        MAX_AUDIT_IDENTIFIERS_PER_ROW * MAX_AUDIT_IDENTIFIER_BYTES
        + MAX_UPLOAD_FILENAME_BYTES
    )
    + AUDIT_ROW_MARKUP_BYTES
)
MAX_AUDIT_DECISION_ROW_HTML_BYTES = (
    AUDIT_ESCAPE_FACTOR * (MAX_NO_MEMORY_REASON_BYTES + 2 * MAX_AUDIT_IDENTIFIER_BYTES)
    + AUDIT_ROW_MARKUP_BYTES
)
MAX_AUDIT_IDENTIFIER_ROW_HTML_BYTES = (
    AUDIT_ESCAPE_FACTOR * MAX_AUDIT_IDENTIFIER_BYTES + 1_024
)

#: Batches, sources, change sets, approvals, applications, and lineages.
AUDIT_INDEX_SECTIONS = 6
UI_AUDIT_PAGE_LIMIT = min(
    UI_STANDARD_PAGE_LIMIT,
    (MAX_STANDARD_HTML_RESPONSE_BYTES - STANDARD_PAGE_CHROME_BYTES)
    // (AUDIT_INDEX_SECTIONS * MAX_AUDIT_ROW_HTML_BYTES),
)
require_invariant(UI_AUDIT_PAGE_LIMIT >= 1, label="audit page limit")
require_invariant(
    STANDARD_PAGE_CHROME_BYTES
    + AUDIT_INDEX_SECTIONS * UI_AUDIT_PAGE_LIMIT * MAX_AUDIT_ROW_HTML_BYTES
    <= MAX_STANDARD_HTML_RESPONSE_BYTES,
    label="audit index response budget",
)
#: One batch detail renders every capture and issue plus one bounded page of
#: source decisions, one bounded page of immutable revisions, and the complete
#: bounded roster of resulting memory revisions.
MAX_AUDIT_BATCH_ISSUE_ROWS = 5
require_invariant(
    STANDARD_PAGE_CHROME_BYTES
    + (MAX_BATCH_FILES + MAX_AUDIT_BATCH_ISSUE_ROWS) * MAX_AUDIT_ROW_HTML_BYTES
    + UI_AUDIT_PAGE_LIMIT * MAX_AUDIT_DECISION_ROW_HTML_BYTES
    + UI_AUDIT_PAGE_LIMIT * MAX_AUDIT_ROW_HTML_BYTES
    + MAX_CHANGE_ITEMS * MAX_AUDIT_IDENTIFIER_ROW_HTML_BYTES
    <= MAX_STANDARD_HTML_RESPONSE_BYTES,
    label="audit batch detail response budget",
)
#: One approval or application detail renders its bounded resulting-memory
#: roster beside a fixed set of identifier rows.
require_invariant(
    STANDARD_PAGE_CHROME_BYTES
    + MAX_AUDIT_ROW_HTML_BYTES
    + MAX_CHANGE_ITEMS * MAX_AUDIT_IDENTIFIER_ROW_HTML_BYTES
    <= MAX_STANDARD_HTML_RESPONSE_BYTES,
    label="audit detail response budget",
)


class AuditService(Protocol):
    """The exact bounded owner surface consumed by in-app audit routes."""

    def get_status(self) -> OwnerStatus: ...

    def begin_audit_snapshot(self) -> AuditSnapshot: ...

    def bind_audit(self, snapshot: AuditSnapshot) -> BoundAuditReader: ...

    def get_application(self, application_id: str) -> OwnerApplicationDetail: ...

    def get_approval(self, approval_id: str) -> OwnerApprovalDetail: ...


@dataclass(frozen=True, slots=True)
class AuditNavigation:
    """One session-owned handle resolved into its typed snapshot-bound reader."""

    handle: str
    reader: BoundAuditReader


class StaleAuditError(Exception):
    """The bound snapshot no longer covers the current Store generation."""


class UnknownAuditHandleError(Exception):
    """No live snapshot belongs to this session under this opaque handle."""


def audit_suffix(handle: str | None, *, separator: str = "?") -> str:
    """Return the opaque handle query fragment carried by audit navigation."""
    if handle is None:
        return ""
    return f"{separator}{AUDIT_HANDLE_PARAM}={handle}"


def resolve_audit_navigation(
    request: Request,
    sessions: UiSessionStore,
    service: AuditService,
) -> AuditNavigation | None:
    """Resolve one session-owned handle into its bound reader, or nothing."""
    handle = singleton_query(request, AUDIT_HANDLE_PARAM)
    if handle is None:
        return None
    session = session_of(request)
    snapshot = sessions.resolve_audit(
        session.session_id,
        handle,
        now_ns=time.monotonic_ns(),
    )
    if snapshot is None:
        raise UnknownAuditHandleError(AUDIT_HANDLE_PARAM)
    try:
        reader = service.bind_audit(snapshot)
    except StaleCursorError as error:
        raise StaleAuditError(AUDIT_HANDLE_PARAM) from error
    return AuditNavigation(handle=handle, reader=reader)


def stale_audit_response(
    templates: Environment,
    service: AuditService,
    request: Request,
) -> Response:
    """Render the restart action instead of any mixed-generation record."""
    session = session_of(request)
    csrf = session.csrf_token
    return render_html(
        templates,
        "audit/index.html",
        status_code=409,
        status=service.get_status(),
        csrf_token=csrf,
        handle=None,
        index=None,
        stale=True,
        batches=None,
        sources=None,
        change_sets=None,
        approvals=None,
        applications=None,
        lineages=None,
        limit=UI_AUDIT_PAGE_LIMIT,
    )


def audit_routes(
    service: AuditService,
    sessions: UiSessionStore,
    templates: Environment,
) -> tuple[Route, ...]:
    """Build the permanent audit landing plus its snapshot-bound navigation."""

    def index_href(handle: str, cursor_name: str, cursor: str, limit: int) -> str:
        return f"/audit{audit_suffix(handle)}&{cursor_name}={cursor}&limit={limit}"

    def batch_href(
        batch_id: str,
        handle: str,
        cursor_name: str,
        cursor: str,
        limit: int,
    ) -> str:
        return (
            f"/audit/batches/{batch_id}{audit_suffix(handle)}"
            f"&{cursor_name}={cursor}&limit={limit}"
        )

    async def audit_index(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        try:
            navigation = resolve_audit_navigation(request, sessions, service)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        if navigation is None:
            return render_html(
                templates,
                "audit/index.html",
                status=service.get_status(),
                csrf_token=csrf,
                handle=None,
                index=None,
                stale=False,
                batches=None,
                sources=None,
                change_sets=None,
                approvals=None,
                applications=None,
                lineages=None,
                limit=UI_AUDIT_PAGE_LIMIT,
            )
        reader = navigation.reader
        handle = navigation.handle
        limit = page_limit(request, maximum=UI_AUDIT_PAGE_LIMIT)
        try:
            bound_index = reader.get_index()
            batches = reader.list_batches(
                singleton_query(request, "batch_cursor"), limit
            )
            sources = reader.list_sources(
                singleton_query(request, "source_cursor"), limit
            )
            change_sets = reader.list_change_sets(
                singleton_query(request, "change_set_cursor"), limit
            )
            approvals = reader.list_approvals(
                singleton_query(request, "approval_cursor"), limit
            )
            applications = reader.list_applications(
                singleton_query(request, "application_cursor"), limit
            )
            lineages = reader.list_lineages(
                singleton_query(request, "lineage_cursor"), limit
            )
        except StaleCursorError:
            return stale_audit_response(templates, service, request)
        return render_html(
            templates,
            "audit/index.html",
            status=bound_index.store,
            csrf_token=csrf,
            handle=handle,
            index=bound_index,
            stale=False,
            batches=batches,
            sources=sources,
            change_sets=change_sets,
            approvals=approvals,
            applications=applications,
            lineages=lineages,
            limit=limit,
            next_batches_href=(
                index_href(handle, "batch_cursor", batches.next_cursor, limit)
                if batches.next_cursor is not None
                else None
            ),
            next_sources_href=(
                index_href(handle, "source_cursor", sources.next_cursor, limit)
                if sources.next_cursor is not None
                else None
            ),
            next_change_sets_href=(
                index_href(handle, "change_set_cursor", change_sets.next_cursor, limit)
                if change_sets.next_cursor is not None
                else None
            ),
            next_approvals_href=(
                index_href(handle, "approval_cursor", approvals.next_cursor, limit)
                if approvals.next_cursor is not None
                else None
            ),
            next_applications_href=(
                index_href(
                    handle, "application_cursor", applications.next_cursor, limit
                )
                if applications.next_cursor is not None
                else None
            ),
            next_lineages_href=(
                index_href(handle, "lineage_cursor", lineages.next_cursor, limit)
                if lineages.next_cursor is not None
                else None
            ),
        )

    async def begin_audit(request: Request) -> Response:
        session = session_of(request)
        body = await read_bounded_body(
            request.receive,
            headers=request.scope["headers"],
            max_bytes=MAX_CONTROL_FORM_BODY_BYTES,
        )
        fields = parse_bounded_urlencoded(
            body,
            max_fields=MAX_FORM_FIELDS,
            max_field_bytes=MAX_CONTROL_FORM_FIELD_BYTES,
        )
        if fields != (("csrf", session.csrf_token),):
            raise InvalidArgumentError("audit restart form is invalid")
        handle = sessions.remember_audit(
            session.session_id,
            UiAuditState(
                snapshot=service.begin_audit_snapshot(),
                created_at_ns=time.monotonic_ns(),
            ),
        )
        return Response(
            status_code=303,
            headers={"Location": f"/audit{audit_suffix(handle)}"},
        )

    async def audit_batch(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        batch_id = request.path_params["batch_id"]
        try:
            navigation = resolve_audit_navigation(request, sessions, service)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        if navigation is None:
            return PlainTextResponse("Request unavailable", status_code=404)
        reader = navigation.reader
        handle = navigation.handle
        limit = page_limit(request, maximum=UI_AUDIT_PAGE_LIMIT)
        try:
            bound_index = reader.get_index()
            detail = reader.get_batch(batch_id)
            change_set_id = detail.summary.change_set_id
            manifest = (
                None
                if change_set_id is None
                else reader.get_review_manifest(change_set_id)
            )
            decisions = (
                None
                if change_set_id is None or manifest is None
                else reader.list_review_source_decisions(
                    change_set_id,
                    manifest.revision.revision_id,
                    singleton_query(request, "decision_cursor"),
                    limit,
                )
            )
            revisions = (
                None
                if change_set_id is None
                else reader.list_change_set_revisions(
                    change_set_id,
                    singleton_query(request, "revision_cursor"),
                    limit,
                )
            )
            applied = (
                None
                if detail.summary.application_id is None
                else reader.get_application(detail.summary.application_id)
            )
        except StaleCursorError:
            return stale_audit_response(templates, service, request)
        return render_html(
            templates,
            "audit/batch.html",
            status=bound_index.store,
            csrf_token=csrf,
            handle=handle,
            detail=detail,
            manifest=manifest,
            decisions=decisions,
            revisions=revisions,
            applied=applied,
            next_decisions_href=(
                batch_href(
                    batch_id, handle, "decision_cursor", decisions.next_cursor, limit
                )
                if decisions is not None and decisions.next_cursor is not None
                else None
            ),
            next_revisions_href=(
                batch_href(
                    batch_id, handle, "revision_cursor", revisions.next_cursor, limit
                )
                if revisions is not None and revisions.next_cursor is not None
                else None
            ),
        )

    def applied_review_page(
        request: Request,
        template: str,
        resolve_bound: Callable[[BoundAuditReader], OwnerAppliedReviewDetail],
        resolve_current: Callable[[], OwnerAppliedReviewDetail],
    ) -> Response:
        try:
            navigation = resolve_audit_navigation(request, sessions, service)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        try:
            if navigation is None:
                status = service.get_status()
                detail = resolve_current()
            else:
                status = navigation.reader.get_index().store
                detail = resolve_bound(navigation.reader)
        except StaleCursorError:
            return stale_audit_response(templates, service, request)
        return render_html(
            templates,
            template,
            status=status,
            csrf_token=None,
            handle=None if navigation is None else navigation.handle,
            detail=detail,
        )

    async def audit_application(request: Request) -> Response:
        application_id = request.path_params["application_id"]
        return applied_review_page(
            request,
            "audit/application.html",
            lambda reader: reader.get_application(application_id),
            lambda: service.get_application(application_id),
        )

    async def audit_approval(request: Request) -> Response:
        approval_id = request.path_params["approval_id"]
        return applied_review_page(
            request,
            "audit/approval.html",
            lambda reader: reader.get_approval(approval_id),
            lambda: service.get_approval(approval_id),
        )

    return (
        Route("/audit", audit_index, methods=["GET"]),
        Route("/audit", begin_audit, methods=["POST"]),
        Route("/audit/batches/{batch_id}", audit_batch, methods=["GET"]),
        Route(
            "/audit/applications/{application_id}",
            audit_application,
            methods=["GET"],
        ),
        Route("/audit/approvals/{approval_id}", audit_approval, methods=["GET"]),
    )
