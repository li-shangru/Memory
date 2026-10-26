"""Authenticated, bounded current-memory search and historical inspection."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Protocol, TypedDict
from urllib.parse import urlencode

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from memory.errors import (
    InvalidArgumentError,
    StaleCursorError,
    StoreBusyError,
    StoreError,
)
from memory.graph import MAX_GRAPH_NODES, StoreGraph
from memory.inbox import Clock
from memory.model import (
    CapturedCorrection,
    MemoryFilters,
    MemoryKind,
    Sensitivity,
    UiSearchState,
)
from memory.retrieval import MAX_QUERY_BYTES
from memory.reviews import MAX_TAG_BYTES, MAX_TAGS
from memory.ui.auth import UiSessionStore
from memory.ui.capture import (
    CorrectionInProgressView,
    CorrectionRetryView,
    CorrectionSubmissionLease,
    PreparedOwnerCorrection,
)
from memory.ui.graph_layout import radial_neighbourhood
from memory.ui.request_limits import (
    MAX_CONTROL_FORM_BODY_BYTES,
    MAX_CONTROL_FORM_FIELD_BYTES,
    MAX_CORRECTION_FORM_BODY_BYTES,
    MAX_CORRECTION_HTML_RESPONSE_BYTES,
    MAX_CORRECTION_TEXT_BYTES,
    MAX_FORM_FIELDS,
    UI_MEMORY_PAGE_LIMIT,
    parse_bounded_urlencoded,
    read_bounded_body,
)
from memory.ui.routes._support import (
    page_limit,
    render_html,
    session_of,
    singleton_query,
)
from memory.ui.routes.audit import (
    AUDIT_HANDLE_PARAM,
    AuditService,
    StaleAuditError,
    UnknownAuditHandleError,
    resolve_audit_navigation,
    stale_audit_response,
)
from memory.ui.service import normalize_owner_memory_filters
from memory.ui.view_models import (
    OwnerMemoryDetail,
    OwnerMemorySearchPage,
    OwnerMemorySummary,
    OwnerPage,
    OwnerStatus,
)

_ALLOWED_FIELDS = frozenset(
    {"query", "kind", "tag", "occurred_from", "occurred_to", "sensitivity"}
)


class MemoryReadModel(Protocol):
    """The bounded memory reads shared by ordinary and audit navigation."""

    def get_memory_revision(
        self,
        memory_id: str,
        *,
        guards_cursor: str | None = None,
        governs_cursor: str | None = None,
    ) -> OwnerMemoryDetail: ...

    def list_memory_lineage(
        self,
        lineage_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerMemorySummary]: ...


class MemoryService(MemoryReadModel, AuditService, Protocol):
    def get_status(self) -> OwnerStatus: ...

    def read_memory_neighbourhood(self, memory_id: str) -> StoreGraph: ...

    def list_memories(
        self,
        cursor: str | None,
        limit: int,
        filters: MemoryFilters,
    ) -> OwnerMemorySearchPage: ...

    def search_memories(
        self,
        query: str,
        filters: MemoryFilters,
        cursor: str | None,
        limit: int,
    ) -> OwnerMemorySearchPage: ...

    def prepare_owner_correction(
        self,
        selected_memory_id: str,
        owner_text: str,
        *,
        clock: Clock | None = None,
    ) -> PreparedOwnerCorrection: ...

    def capture_owner_correction(
        self, lease: CorrectionSubmissionLease
    ) -> CapturedCorrection: ...

    def correction_capture_custody_outcome(
        self,
        lease: CorrectionSubmissionLease,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class ActiveFilter:
    name: str
    value: str
    remaining: tuple[tuple[str, str], ...]


class _RelationshipHrefs(TypedDict):
    next_guards_href: str | None
    next_governs_href: str | None


def _require_no_query(request: Request) -> None:
    if request.query_params:
        raise InvalidArgumentError("correction query parameter is invalid")


def _memory_detail_href(
    memory_id: str,
    *,
    handle: str | None,
    lineage_cursor: str | None,
    lineage_limit: int,
    guards_cursor: str | None = None,
    governs_cursor: str | None = None,
) -> str:
    parameters: list[tuple[str, str | int]] = [("lineage_limit", lineage_limit)]
    for name, cursor in (
        ("lineage_cursor", lineage_cursor),
        ("guards_cursor", guards_cursor),
        ("governs_cursor", governs_cursor),
    ):
        if cursor is not None:
            parameters.append((name, cursor))
    if handle is not None:
        parameters.append((AUDIT_HANDLE_PARAM, handle))
    return f"/memories/{memory_id}?{urlencode(parameters)}"


def _relationship_hrefs(
    detail: OwnerMemoryDetail,
    *,
    handle: str | None,
    lineage_cursor: str | None = None,
    lineage_limit: int = UI_MEMORY_PAGE_LIMIT,
    guards_cursor: str | None = None,
    governs_cursor: str | None = None,
) -> _RelationshipHrefs:
    """Keep the other panels and any bound audit when advancing one roster."""

    def href(guard_page: str | None, governed_page: str | None) -> str:
        return _memory_detail_href(
            detail.summary.revision.memory_id,
            handle=handle,
            lineage_cursor=lineage_cursor,
            lineage_limit=lineage_limit,
            guards_cursor=guard_page,
            governs_cursor=governed_page,
        )

    return {
        "next_guards_href": (
            href(detail.guards_next_cursor, governs_cursor)
            if detail.guards_next_cursor is not None
            else None
        ),
        "next_governs_href": (
            href(guards_cursor, detail.governs_next_cursor)
            if detail.governs_next_cursor is not None
            else None
        ),
    }


def _one_value(grouped: dict[str, list[str]], name: str) -> str:
    values = grouped.get(name, [])
    if len(values) != 1:
        raise InvalidArgumentError("memory search form is ambiguous")
    return values[0]


def _optional_one_value(grouped: dict[str, list[str]], name: str) -> str | None:
    values = grouped.get(name, [])
    if len(values) > 1:
        raise InvalidArgumentError("memory search form is ambiguous")
    if not values or not values[0]:
        return None
    return values[0]


async def memory_search_form(
    request: Request,
) -> tuple[str, MemoryFilters, tuple[tuple[str, str], ...]]:
    body = await read_bounded_body(
        request.receive,
        headers=request.scope["headers"],
        max_bytes=MAX_CONTROL_FORM_BODY_BYTES,
    )
    pairs = parse_bounded_urlencoded(
        body,
        max_fields=MAX_FORM_FIELDS,
        max_field_bytes=MAX_CONTROL_FORM_FIELD_BYTES,
    )
    if any(name not in _ALLOWED_FIELDS for name, _value in pairs):
        raise InvalidArgumentError("memory search form is invalid")
    grouped: dict[str, list[str]] = {}
    for name, value in pairs:
        grouped.setdefault(name, []).append(value)
    # Absent means empty. The graph filter form has no query box and goes
    # through this exact parser, so the two surfaces cannot validate a
    # filter differently.
    query = _optional_one_value(grouped, "query") or ""
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise InvalidArgumentError("memory search query is invalid")
    raw_tags = [tag for tag in grouped.get("tag", []) if tag.strip()]
    if len(raw_tags) > MAX_TAGS or any(
        not tag.strip() or len(tag.strip().encode("utf-8")) > MAX_TAG_BYTES
        for tag in raw_tags
    ):
        raise InvalidArgumentError("memory tags are invalid")
    try:
        filters = MemoryFilters(
            kinds=tuple(MemoryKind(value) for value in grouped.get("kind", [])),
            tags_all=tuple(raw_tags),
            occurred_from=_optional_one_value(grouped, "occurred_from"),
            occurred_to=_optional_one_value(grouped, "occurred_to"),
            sensitivities=tuple(
                Sensitivity(value) for value in grouped.get("sensitivity", [])
            ),
        )
    except ValueError as error:
        raise InvalidArgumentError("memory filter enum is invalid") from error
    normalized = normalize_owner_memory_filters(filters)
    normalized_pairs = (
        tuple(("kind", value.value) for value in normalized.kinds)
        + tuple(("tag", value) for value in normalized.tags_all)
        + (
            (("occurred_from", normalized.occurred_from),)
            if normalized.occurred_from is not None
            else ()
        )
        + (
            (("occurred_to", normalized.occurred_to),)
            if normalized.occurred_to is not None
            else ()
        )
        + tuple(("sensitivity", value.value) for value in normalized.sensitivities)
    )
    return query, normalized, normalized_pairs


def filters_from_state(state: UiSearchState) -> MemoryFilters:
    # Public because the graph lenses read the same handle-backed filter state.
    # An underscore here would have said "module-private" while two modules
    # imported it.
    grouped: dict[str, list[str]] = {}
    for name, value in state.filters:
        grouped.setdefault(name, []).append(value)
    occurred_from_values = grouped.get("occurred_from", [])
    occurred_to_values = grouped.get("occurred_to", [])
    return normalize_owner_memory_filters(
        MemoryFilters(
            kinds=tuple(MemoryKind(value) for value in grouped.get("kind", [])),
            tags_all=tuple(grouped.get("tag", [])),
            occurred_from=occurred_from_values[0] if occurred_from_values else None,
            occurred_to=occurred_to_values[0] if occurred_to_values else None,
            sensitivities=tuple(
                Sensitivity(value) for value in grouped.get("sensitivity", [])
            ),
        )
    )


def active_filters(state: UiSearchState) -> tuple[ActiveFilter, ...]:
    return tuple(
        ActiveFilter(
            name=name,
            value=value,
            remaining=state.filters[:index] + state.filters[index + 1 :],
        )
        for index, (name, value) in enumerate(state.filters)
    )


def memory_routes(
    service: MemoryService,
    sessions: UiSessionStore,
    templates: Environment,
    *,
    today: Callable[[], date] = date.today,
) -> tuple[Route, ...]:
    """Build current-memory query routes and immutable revision inspection."""

    async def list_memories(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        page = service.list_memories(
            singleton_query(request, "cursor"),
            page_limit(request, maximum=UI_MEMORY_PAGE_LIMIT),
            MemoryFilters(),
        )
        return render_html(
            templates,
            "memories/list.html",
            status=service.get_status(),
            csrf_token=csrf,
            page=page,
            handle=None,
            query="",
            active_filters=(),
            limit=UI_MEMORY_PAGE_LIMIT,
            today=today(),
        )

    async def submit_search(request: Request) -> Response:
        session = session_of(request)
        query, _filters, pairs = await memory_search_form(request)
        handle = sessions.remember_search(
            session.session_id,
            UiSearchState(
                scope="memories",
                query=query,
                filters=pairs,
                created_at_ns=time.monotonic_ns(),
            ),
        )
        return Response(
            status_code=303, headers={"Location": f"/memory/search/{handle}"}
        )

    async def search_results(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        handle = request.path_params["handle"]
        state = sessions.resolve_search(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        if state is None or state.scope != "memories":
            return PlainTextResponse("Request unavailable", status_code=404)
        filters = filters_from_state(state)
        cursor = singleton_query(request, "cursor")
        limit = page_limit(request, maximum=UI_MEMORY_PAGE_LIMIT)
        if state.query.strip():
            page = service.search_memories(
                state.query,
                filters,
                cursor,
                limit,
            )
        else:
            page = service.list_memories(cursor, limit, filters)
        return render_html(
            templates,
            "memories/list.html",
            status=service.get_status(),
            csrf_token=csrf,
            page=page,
            handle=handle,
            query=state.query,
            active_filters=active_filters(state),
            limit=limit,
            today=today(),
        )

    def render_memory_detail(
        request: Request,
        reads: MemoryReadModel,
        handle: str | None,
        status: OwnerStatus,
        graph: StoreGraph | None = None,
    ) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        guards_cursor = singleton_query(request, "guards_cursor")
        governs_cursor = singleton_query(request, "governs_cursor")
        detail = reads.get_memory_revision(
            request.path_params["memory_id"],
            guards_cursor=guards_cursor,
            governs_cursor=governs_cursor,
        )
        raw_limit = singleton_query(request, "lineage_limit")
        lineage_limit = UI_MEMORY_PAGE_LIMIT
        if raw_limit is not None:
            if not raw_limit.isdigit():
                raise InvalidArgumentError("lineage limit is invalid")
            try:
                lineage_limit = int(raw_limit)
            except ValueError as error:
                raise InvalidArgumentError("lineage limit is invalid") from error
            if not 1 <= lineage_limit <= UI_MEMORY_PAGE_LIMIT:
                raise InvalidArgumentError("lineage limit is invalid")
        lineage_cursor = singleton_query(request, "lineage_cursor")
        page = reads.list_memory_lineage(
            detail.summary.revision.lineage_id,
            lineage_cursor,
            lineage_limit,
        )
        if page.has_more and (
            page.next_cursor is None or page.next_cursor == lineage_cursor
        ):
            raise InvalidArgumentError("lineage continuation is invalid")
        return render_html(
            templates,
            "memories/detail.html",
            status=status,
            csrf_token=csrf,
            audit_handle=handle,
            detail=detail,
            revisions=page.items,
            ceiling=MAX_GRAPH_NODES,
            neighbourhood=(
                radial_neighbourhood(
                    graph, f"memory:{detail.summary.revision.lineage_id}"
                )
                if graph is not None
                else None
            ),
            next_lineage_href=(
                _memory_detail_href(
                    detail.summary.revision.memory_id,
                    handle=handle,
                    lineage_cursor=page.next_cursor,
                    lineage_limit=lineage_limit,
                    guards_cursor=guards_cursor,
                    governs_cursor=governs_cursor,
                )
                if page.next_cursor is not None
                else None
            ),
            **_relationship_hrefs(
                detail,
                handle=handle,
                lineage_cursor=lineage_cursor,
                lineage_limit=lineage_limit,
                guards_cursor=guards_cursor,
                governs_cursor=governs_cursor,
            ),
            correction_mode=None,
            correction_binding=None,
            correction_retry=None,
            correction_action=None,
            today=today(),
        )

    async def memory_detail(request: Request) -> Response:
        try:
            navigation = resolve_audit_navigation(request, sessions, service)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        if navigation is None:
            return render_memory_detail(
                request,
                service,
                None,
                service.get_status(),
                service.read_memory_neighbourhood(request.path_params["memory_id"]),
            )
        try:
            # Audit navigation is pinned to one snapshot. The graph is a live
            # read, so drawing it inside that view would put today's edges in a
            # picture the owner is reading as the Store at a fixed generation.
            return render_memory_detail(
                request,
                navigation.reader,
                navigation.handle,
                navigation.reader.get_index().store,
            )
        except StaleCursorError:
            return stale_audit_response(templates, service, request)

    async def open_correction(request: Request) -> Response:
        session = session_of(request)
        _require_no_query(request)
        memory_id = request.path_params["memory_id"]
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
        if fields != (("selected_memory_id", memory_id),):
            raise InvalidArgumentError("correction open form is invalid")
        # Validate the selected immutable revision before issuing authority.
        service.get_memory_revision(memory_id)
        binding = sessions.issue_correction_form(
            session.session_id,
            memory_id,
            now_ns=time.monotonic_ns(),
        )
        return Response(
            status_code=303,
            headers={"Location": f"/memory/corrections/{binding.form_nonce}"},
        )

    def correction_detail_context(
        memory_id: str,
    ) -> tuple[OwnerMemoryDetail, OwnerPage[OwnerMemorySummary]]:
        detail = service.get_memory_revision(memory_id)
        page = service.list_memory_lineage(
            detail.summary.revision.lineage_id,
            None,
            UI_MEMORY_PAGE_LIMIT,
        )
        return detail, page

    async def correction_form(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        _require_no_query(request)
        nonce = request.path_params["nonce"]
        binding = sessions.resolve_correction_form(
            session.session_id,
            nonce,
            now_ns=time.monotonic_ns(),
        )
        if binding is None:
            return PlainTextResponse("Request unavailable", status_code=404)
        detail, page = correction_detail_context(binding.selected_memory_id)
        return render_html(
            templates,
            "memories/detail.html",
            max_bytes=MAX_CORRECTION_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            audit_handle=None,
            detail=detail,
            revisions=page.items,
            ceiling=MAX_GRAPH_NODES,
            neighbourhood=None,
            next_lineage_href=None,
            correction_mode="create",
            correction_binding=binding,
            correction_retry=None,
            correction_action=f"/memory/corrections/{nonce}",
            **_relationship_hrefs(detail, handle=None),
            today=today(),
        )

    async def _correction_submission_fields(
        request: Request,
    ) -> tuple[str, str]:
        body = await read_bounded_body(
            request.receive,
            headers=request.scope["headers"],
            max_bytes=MAX_CORRECTION_FORM_BODY_BYTES,
        )
        fields = parse_bounded_urlencoded(
            body,
            max_fields=2,
            max_field_bytes=MAX_CORRECTION_TEXT_BYTES,
        )
        if tuple(name for name, _value in fields) != (
            "selected_memory_id",
            "owner_text",
        ):
            raise InvalidArgumentError("correction submission form is invalid")
        selected_memory_id = fields[0][1]
        owner_text = fields[1][1]
        if (
            len(selected_memory_id.encode("utf-8")) > MAX_CONTROL_FORM_FIELD_BYTES
            or len(owner_text.encode("utf-8")) > MAX_CORRECTION_TEXT_BYTES
        ):
            raise InvalidArgumentError("correction submission field is too large")
        return selected_memory_id, owner_text

    def _captured_redirect(result: CapturedCorrection) -> Response:
        return Response(
            status_code=303,
            headers={"Location": f"/inbox?captured={result.batch_id}"},
        )

    def _mark_correction_capture_failure(
        lease: CorrectionSubmissionLease,
    ) -> None:
        sessions.mark_correction_retryable(
            lease,
            custody_outcome=service.correction_capture_custody_outcome(lease),
        )

    async def submit_correction(request: Request) -> Response:
        session = session_of(request)
        _require_no_query(request)
        nonce = request.path_params["nonce"]
        binding = sessions.resolve_correction_form(
            session.session_id,
            nonce,
            now_ns=time.monotonic_ns(),
        )
        if binding is None:
            return PlainTextResponse("Request unavailable", status_code=404)
        selected_memory_id, owner_text = await _correction_submission_fields(request)
        if selected_memory_id != binding.selected_memory_id:
            raise InvalidArgumentError("correction target is invalid")
        prepared = service.prepare_owner_correction(selected_memory_id, owner_text)
        try:
            leased = sessions.lease_correction_form(
                session.session_id,
                nonce,
                selected_memory_id,
                prepared,
                now_ns=time.monotonic_ns(),
            )
        except StoreBusyError:
            return Response(
                status_code=303,
                headers={"Location": f"/memory/corrections/{nonce}/retry"},
            )
        if isinstance(leased, CapturedCorrection):
            return _captured_redirect(leased)
        try:
            captured = service.capture_owner_correction(leased)
        except StoreBusyError:
            _mark_correction_capture_failure(leased)
            return Response(
                status_code=303,
                headers={"Location": f"/memory/corrections/{nonce}/retry"},
            )
        except StoreError:
            _mark_correction_capture_failure(leased)
            raise
        except BaseException:
            _mark_correction_capture_failure(leased)
            raise
        sessions.complete_correction_form(
            leased,
            captured,
            now_ns=time.monotonic_ns(),
        )
        return _captured_redirect(captured)

    async def retry_correction(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        _require_no_query(request)
        nonce = request.path_params["nonce"]
        status_view = sessions.resolve_correction_status(
            session.session_id,
            nonce,
            now_ns=time.monotonic_ns(),
        )
        if isinstance(status_view, CapturedCorrection):
            return _captured_redirect(status_view)
        if isinstance(status_view, CorrectionInProgressView):
            return PlainTextResponse(
                "Correction capture is in progress",
                status_code=202,
            )
        if not isinstance(status_view, CorrectionRetryView):
            return PlainTextResponse("Request unavailable", status_code=404)
        detail, page = correction_detail_context(status_view.selected_memory_id)
        return render_html(
            templates,
            "memories/detail.html",
            max_bytes=MAX_CORRECTION_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            audit_handle=None,
            detail=detail,
            revisions=page.items,
            ceiling=MAX_GRAPH_NODES,
            neighbourhood=None,
            next_lineage_href=None,
            correction_mode="retry",
            correction_binding=None,
            correction_retry=status_view,
            correction_action=f"/memory/corrections/{nonce}/retry",
            **_relationship_hrefs(detail, handle=None),
            today=today(),
        )

    async def resubmit_correction(request: Request) -> Response:
        session = session_of(request)
        _require_no_query(request)
        nonce = request.path_params["nonce"]
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
            raise InvalidArgumentError("correction retry form is invalid")
        lease = sessions.lease_retryable_correction(
            session.session_id,
            nonce,
            now_ns=time.monotonic_ns(),
        )
        try:
            captured = service.capture_owner_correction(lease)
        except StoreBusyError:
            _mark_correction_capture_failure(lease)
            return Response(
                status_code=303,
                headers={"Location": f"/memory/corrections/{nonce}/retry"},
            )
        except StoreError:
            _mark_correction_capture_failure(lease)
            raise
        except BaseException:
            _mark_correction_capture_failure(lease)
            raise
        sessions.complete_correction_form(
            lease,
            captured,
            now_ns=time.monotonic_ns(),
        )
        return _captured_redirect(captured)

    return (
        Route("/memory", list_memories, methods=["GET"]),
        Route("/memory/search", submit_search, methods=["POST"]),
        Route("/memory/search/{handle}", search_results, methods=["GET"]),
        Route(
            "/memories/{memory_id}/corrections",
            open_correction,
            methods=["POST"],
        ),
        Route("/memory/corrections/{nonce}", correction_form, methods=["GET"]),
        Route("/memory/corrections/{nonce}", submit_correction, methods=["POST"]),
        Route(
            "/memory/corrections/{nonce}/retry",
            retry_correction,
            methods=["GET"],
        ),
        Route(
            "/memory/corrections/{nonce}/retry",
            resubmit_correction,
            methods=["POST"],
        ),
        Route("/memories/{memory_id}", memory_detail, methods=["GET"]),
    )
