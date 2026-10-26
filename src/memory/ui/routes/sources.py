"""Authenticated, bounded source search, inspection, and inert previews."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlencode

from jinja2 import Environment
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from memory.errors import InvalidArgumentError, StaleCursorError
from memory.model import UiSearchState
from memory.retrieval import MAX_QUERY_BYTES
from memory.ui.auth import UiSessionStore
from memory.ui.media_preview import (
    MAX_BINARY_WINDOW_BYTES,
    MAX_MEDIA_SOURCE_BYTES,
    MAX_PREVIEW_PIXELS,
    MAX_SOURCE_TEXT_CHUNK_BYTES,
    MEDIA_BUSY_RETRY_AFTER_SECONDS,
    MediaPreviewError,
    MediaWorkerBusyError,
    _render_image_preview_with_cancellation,
    render_binary_window,
    run_media_job,
    validate_declared_image_container,
)
from memory.ui.pdf_render import _render_pdf_page_with_cancellation
from memory.ui.request_limits import (
    MAX_CONTROL_FORM_BODY_BYTES,
    MAX_CONTROL_FORM_FIELD_BYTES,
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
from memory.ui.routes.audit import (
    AUDIT_HANDLE_PARAM,
    AuditService,
    StaleAuditError,
    UnknownAuditHandleError,
    resolve_audit_navigation,
    stale_audit_response,
)
from memory.ui.view_models import (
    OwnerEvidenceLink,
    OwnerPage,
    OwnerSourceChunk,
    OwnerSourceDetail,
    OwnerSourceSearchPage,
    OwnerSourceSummary,
    OwnerStatus,
)

_IMAGE_FORMATS = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/webp": "WEBP",
}


class SourceReadModel(Protocol):
    """The bounded source reads shared by ordinary and audit navigation."""

    def get_source_detail(self, source_id: str) -> OwnerSourceDetail: ...

    def read_source(
        self,
        source_id: str,
        cursor: str | None,
        max_bytes: int,
    ) -> OwnerSourceChunk: ...

    def list_blob_captures(
        self,
        blob_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceSummary]: ...

    def list_source_evidence_links(
        self,
        source_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerEvidenceLink]: ...


class SourceService(SourceReadModel, AuditService, Protocol):
    def get_status(self) -> OwnerStatus: ...

    def list_sources(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceSummary]: ...

    def search_sources(
        self,
        query: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerSourceSearchPage: ...


def _source_detail_href(
    source_id: str,
    *,
    handle: str | None = None,
    cursor: str | None = None,
    previous_cursor: str | None = None,
    capture_cursor: str | None = None,
    evidence_cursor: str | None = None,
) -> str:
    parameters = tuple(
        (name, value)
        for name, value in (
            (AUDIT_HANDLE_PARAM, handle),
            ("cursor", cursor),
            ("previous_cursor", previous_cursor),
            ("capture_cursor", capture_cursor),
            ("evidence_cursor", evidence_cursor),
        )
        if value is not None
    )
    path = f"/sources/{source_id}"
    return f"{path}?{urlencode(parameters)}" if parameters else path


async def _source_search_form(request: Request) -> str:
    body = await read_bounded_body(
        request.receive,
        headers=request.scope["headers"],
        max_bytes=MAX_CONTROL_FORM_BODY_BYTES,
    )
    pairs = parse_bounded_urlencoded(
        body,
        max_fields=1,
        max_field_bytes=MAX_CONTROL_FORM_FIELD_BYTES,
    )
    if len(pairs) != 1 or pairs[0][0] != "query":
        raise InvalidArgumentError("source search form is invalid")
    query = pairs[0][1]
    if not query.strip() or len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise InvalidArgumentError("source search query is invalid")
    return query


def _complete_source_bytes(
    service: SourceService,
    detail: OwnerSourceDetail,
    *,
    cancelled: Callable[[], bool],
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    cursor: str | None = None
    expected_start = 0
    while True:
        if cancelled():
            raise MediaPreviewError("cancelled")
        chunk = service.read_source(
            detail.summary.source_id,
            cursor,
            MAX_BINARY_WINDOW_BYTES,
        )
        if (
            chunk.source_id != detail.summary.source_id
            or chunk.blob_digest != detail.summary.blob_digest
            or chunk.media_type != detail.summary.media_type
            or chunk.byte_start != expected_start
        ):
            raise MediaPreviewError("source_changed")
        value = chunk.binary
        if value is None and chunk.text is not None:
            value = chunk.text.encode("utf-8")
        if value is None or len(value) != chunk.byte_end - chunk.byte_start:
            raise MediaPreviewError("invalid_source_chunk")
        total += len(value)
        if total > MAX_MEDIA_SOURCE_BYTES:
            raise MediaPreviewError("source_too_large")
        chunks.append(value)
        expected_start = chunk.byte_end
        if chunk.complete:
            if chunk.next_cursor is not None:
                raise MediaPreviewError("invalid_source_chunk")
            break
        if chunk.next_cursor is None or chunk.byte_end <= chunk.byte_start:
            raise MediaPreviewError("invalid_source_chunk")
        cursor = chunk.next_cursor
    if total != detail.summary.byte_length:
        raise MediaPreviewError("source_changed")
    return b"".join(chunks)


async def _watch_disconnect(
    request: Request,
    cancelled: threading.Event,
) -> None:
    while not cancelled.is_set():
        message = await request.receive()
        if message["type"] == "http.disconnect":
            cancelled.set()
            return


async def _finish_cancelled_job(task: asyncio.Task[object]) -> None:
    """Wait through outer cancellation until the worker permit is safe to release."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    if not task.cancelled():
        task.exception()


async def _run_request_media_job[T, R](
    request: Request,
    loader: Callable[[Callable[[], bool]], T],
    renderer: Callable[[T, Callable[[], bool]], R],
) -> R:
    cancelled = threading.Event()

    def run() -> R:
        return run_media_job(
            lambda: loader(cancelled.is_set),
            lambda value: renderer(value, cancelled.is_set),
        )

    job = asyncio.create_task(run_in_threadpool(run))
    disconnect = asyncio.create_task(_watch_disconnect(request, cancelled))
    try:
        return await asyncio.shield(job)
    except asyncio.CancelledError:
        cancelled.set()
        await _finish_cancelled_job(job)
        raise
    finally:
        disconnect.cancel()
        try:
            await disconnect
        except asyncio.CancelledError:
            pass


def source_routes(
    service: SourceService,
    sessions: UiSessionStore,
    templates: Environment,
) -> tuple[Route, ...]:
    """Build source routes with only query service and process-session authority."""

    async def list_sources(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        page = service.list_sources(
            singleton_query(request, "cursor"),
            page_limit(request, maximum=UI_STANDARD_PAGE_LIMIT),
        )
        return render_html(
            templates,
            "sources/list.html",
            status=service.get_status(),
            csrf_token=csrf,
            page=page,
            search=None,
            handle=None,
        )

    async def submit_search(request: Request) -> Response:
        session = session_of(request)
        query = await _source_search_form(request)
        handle = sessions.remember_search(
            session.session_id,
            UiSearchState(
                scope="sources",
                query=query,
                filters=(),
                created_at_ns=time.monotonic_ns(),
            ),
        )
        return Response(
            status_code=303, headers={"Location": f"/sources/search/{handle}"}
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
        if state is None or state.scope != "sources":
            return PlainTextResponse("Request unavailable", status_code=404)
        limit = page_limit(request, maximum=UI_STANDARD_PAGE_LIMIT)
        page = service.search_sources(
            state.query,
            singleton_query(request, "cursor"),
            limit,
        )
        return render_html(
            templates,
            "sources/list.html",
            status=service.get_status(),
            csrf_token=csrf,
            page=None,
            search=page,
            handle=handle,
            limit=limit,
        )

    def render_source_detail(
        request: Request,
        reads: SourceReadModel,
        handle: str | None,
        status: OwnerStatus,
    ) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        source_id = request.path_params["source_id"]
        detail = reads.get_source_detail(source_id)
        cursor = singleton_query(request, "cursor")
        previous_cursor = singleton_query(request, "previous_cursor")
        capture_cursor = singleton_query(request, "capture_cursor")
        evidence_cursor = singleton_query(request, "evidence_cursor")
        max_bytes = (
            MAX_SOURCE_TEXT_CHUNK_BYTES
            if detail.retained_utf8_text
            else MAX_BINARY_WINDOW_BYTES
        )
        try:
            chunk = reads.read_source(source_id, cursor, max_bytes)
        except StaleCursorError:
            if handle is not None:
                raise
            retry = _source_detail_href(
                source_id,
                cursor=previous_cursor,
                capture_cursor=capture_cursor,
                evidence_cursor=evidence_cursor,
            )
            return render_html(
                templates,
                "sources/stale.html",
                status_code=409,
                status=status,
                csrf_token=csrf,
                retry=retry,
            )
        siblings = reads.list_blob_captures(
            detail.summary.blob_id,
            capture_cursor,
            UI_STANDARD_PAGE_LIMIT,
        )
        evidence = reads.list_source_evidence_links(
            source_id,
            evidence_cursor,
            UI_STANDARD_PAGE_LIMIT,
        )
        binary_rendered = (
            render_binary_window(chunk.binary, offset=chunk.byte_start)
            if chunk.binary is not None
            else None
        )
        return render_html(
            templates,
            "sources/detail.html",
            status=status,
            csrf_token=csrf,
            audit_handle=handle,
            detail=detail,
            chunk=chunk,
            siblings=siblings,
            evidence=evidence,
            binary_rendered=binary_rendered,
            original_hex=chunk.binary.hex() if chunk.binary is not None else None,
            next_content_href=(
                _source_detail_href(
                    source_id,
                    handle=handle,
                    cursor=chunk.next_cursor,
                    previous_cursor=cursor,
                    capture_cursor=capture_cursor,
                    evidence_cursor=evidence_cursor,
                )
                if chunk.next_cursor is not None
                else None
            ),
            next_siblings_href=(
                _source_detail_href(
                    source_id,
                    handle=handle,
                    cursor=cursor,
                    previous_cursor=previous_cursor,
                    capture_cursor=siblings.next_cursor,
                    evidence_cursor=evidence_cursor,
                )
                if siblings.next_cursor is not None
                else None
            ),
            next_evidence_href=(
                _source_detail_href(
                    source_id,
                    handle=handle,
                    cursor=cursor,
                    previous_cursor=previous_cursor,
                    capture_cursor=capture_cursor,
                    evidence_cursor=evidence.next_cursor,
                )
                if evidence.next_cursor is not None
                else None
            ),
            previewable=(
                detail.summary.media_type in _IMAGE_FORMATS
                or detail.summary.media_type == "application/pdf"
            ),
        )

    async def source_detail(request: Request) -> Response:
        try:
            navigation = resolve_audit_navigation(request, sessions, service)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        if navigation is None:
            return render_source_detail(request, service, None, service.get_status())
        try:
            return render_source_detail(
                request,
                navigation.reader,
                navigation.handle,
                navigation.reader.get_index().store,
            )
        except StaleCursorError:
            return stale_audit_response(templates, service, request)

    async def source_preview(request: Request) -> Response:
        source_id = request.path_params["source_id"]
        page_raw = singleton_query(request, "page") or "1"
        try:
            page_number = int(page_raw) if page_raw.isdigit() else 0
        except ValueError:
            page_number = 0
        if page_number < 1:
            return PlainTextResponse("Preview unavailable", status_code=422)

        def load(
            cancelled: Callable[[], bool],
        ) -> tuple[OwnerSourceDetail, bytes]:
            if cancelled():
                raise MediaPreviewError("cancelled")
            detail = service.get_source_detail(source_id)
            return detail, _complete_source_bytes(
                service,
                detail,
                cancelled=cancelled,
            )

        def render(
            loaded: tuple[OwnerSourceDetail, bytes],
            cancelled: Callable[[], bool],
        ) -> bytes:
            if cancelled():
                raise MediaPreviewError("cancelled")
            detail, source = loaded
            media_type = detail.summary.media_type
            if media_type == "application/pdf":
                return _render_pdf_page_with_cancellation(
                    source,
                    page_number=page_number,
                    max_pixels=MAX_PREVIEW_PIXELS,
                    cancelled=cancelled,
                ).png_bytes
            expected = _IMAGE_FORMATS.get(media_type)
            if expected is None:
                raise MediaPreviewError("unsupported_media")
            validate_declared_image_container(source, expected_format=expected)
            return _render_image_preview_with_cancellation(
                source,
                max_pixels=MAX_PREVIEW_PIXELS,
                cancelled=cancelled,
            ).png_bytes

        try:
            body = await _run_request_media_job(request, load, render)
        except MediaWorkerBusyError:
            return PlainTextResponse(
                "Preview busy",
                status_code=429,
                headers={"Retry-After": str(MEDIA_BUSY_RETRY_AFTER_SECONDS)},
            )
        except MediaPreviewError, StaleCursorError:
            return PlainTextResponse("Preview unavailable", status_code=422)
        return Response(body, media_type="image/png")

    return (
        Route("/sources", list_sources, methods=["GET"]),
        Route("/sources/search", submit_search, methods=["POST"]),
        Route("/sources/search/{handle}", search_results, methods=["GET"]),
        Route("/sources/{source_id}/preview", source_preview, methods=["GET"]),
        Route("/sources/{source_id}", source_detail, methods=["GET"]),
    )
