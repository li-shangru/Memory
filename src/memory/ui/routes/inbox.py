"""Authenticated bounded Inbox staging and recovery views."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from queue import Full, Queue
from threading import Thread
from typing import Protocol
from urllib.parse import urlencode

from jinja2 import Environment
from python_multipart.multipart import parse_options_header
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from memory.errors import InvalidArgumentError, RequestLimitError
from memory.model import (
    CaptureRecoveryIssue,
    SourceCaptureOrigin,
    StagedInboxEntry,
)
from memory.ui.browser_launch import FinderRevealer
from memory.ui.request_limits import (
    MAX_CONTROL_FORM_BODY_BYTES,
    MAX_CONTROL_FORM_FIELD_BYTES,
    MAX_FORM_FIELDS,
    MAX_UPLOAD_REQUEST_BYTES,
    UI_STANDARD_PAGE_LIMIT,
    parse_bounded_multipart,
    parse_bounded_urlencoded,
    read_bounded_body,
    validate_content_length,
)
from memory.ui.routes._support import (
    page_limit,
    render_html,
    session_of,
    singleton_query,
)
from memory.ui.view_models import (
    OwnerBatchDetail,
    OwnerBatchSummary,
    OwnerPage,
    OwnerStatus,
)


class InboxService(Protocol):
    def get_status(self) -> OwnerStatus: ...

    def list_staged_inbox_entries(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[StagedInboxEntry]: ...

    def stage_inbox_file(
        self, *, owner_filename: str, chunks: Iterable[bytes]
    ) -> StagedInboxEntry: ...

    def list_recent_correction_batches(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerBatchSummary]: ...

    def list_capture_recovery_issues(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[CaptureRecoveryIssue]: ...

    def reveal_inbox_in_finder(self, finder: FinderRevealer) -> None: ...

    def get_batch(self, batch_id: str) -> OwnerBatchDetail: ...


class _UploadAborted(RuntimeError):
    pass


class _StreamingStageSink:
    """Backpressure multipart bytes into one core-owned staging operation."""

    def __init__(self, service: InboxService) -> None:
        self._service = service
        self._queue: Queue[bytes | _UploadAborted | None] = Queue(maxsize=4)
        self._thread: Thread | None = None
        self._result: StagedInboxEntry | None = None
        self._error: BaseException | None = None
        self._closed = False

    def begin(self, owner_filename: str) -> None:
        if self._thread is not None or self._closed:
            raise InvalidArgumentError("upload stream is invalid")

        def stage() -> None:
            try:
                self._result = self._service.stage_inbox_file(
                    owner_filename=owner_filename,
                    chunks=self._chunks(),
                )
            except BaseException as error:
                self._error = error

        self._thread = Thread(target=stage, name="memory-inbox-staging")
        self._thread.start()

    def write(self, value: bytes) -> int:
        if not value:
            return 0
        if self._thread is None or self._closed:
            raise InvalidArgumentError("upload stream is unavailable")
        self._send(bytes(value))
        self._raise_worker_error()
        return len(value)

    def finish(self) -> StagedInboxEntry:
        if self._thread is None or self._closed:
            raise InvalidArgumentError("upload stream is unavailable")
        self._send(None)
        self._thread.join()
        self._closed = True
        self._raise_worker_error()
        if self._result is None:
            raise InvalidArgumentError("upload staging result is unavailable")
        return self._result

    def abort(self) -> None:
        if self._thread is None or self._closed:
            return
        while self._thread.is_alive():
            try:
                self._queue.put(_UploadAborted(), timeout=0.05)
                break
            except Full:
                continue
        self._thread.join()
        self._closed = True

    def _chunks(self) -> Iterable[bytes]:
        while True:
            item = self._queue.get()
            if item is None:
                return
            if isinstance(item, _UploadAborted):
                raise item
            yield item

    def _send(self, item: bytes | None) -> None:
        assert self._thread is not None
        while True:
            self._raise_worker_error()
            try:
                self._queue.put(item, timeout=0.05)
                return
            except Full:
                if not self._thread.is_alive():
                    self._raise_worker_error()
                    # A full queue is not the failure being reported: the worker
                    # is gone and left no error of its own to chain.
                    raise InvalidArgumentError("upload staging stopped") from None

    def _raise_worker_error(self) -> None:
        if self._error is not None:
            raise self._error


def _require_query_names(request: Request, allowed: frozenset[str]) -> None:
    if any(name not in allowed for name in request.query_params):
        raise InvalidArgumentError("Inbox query parameter is invalid")


async def inbox_page(request: Request) -> Response:
    """Render one bounded Inbox page using only the application service seam."""
    session = session_of(request)
    csrf = session.csrf_token
    service: InboxService = request.app.state.owner_service
    templates: Environment = request.app.state.templates
    _require_query_names(
        request,
        frozenset(
            {
                "captured",
                "correction_cursor",
                "cursor",
                "limit",
                "recovery_cursor",
                "staged",
            }
        ),
    )
    staged_notice = singleton_query(request, "staged")
    if staged_notice not in {None, "1"}:
        raise InvalidArgumentError("Inbox staged state is invalid")
    limit = page_limit(request, maximum=UI_STANDARD_PAGE_LIMIT)
    staged_cursor = singleton_query(request, "cursor")
    correction_cursor = singleton_query(request, "correction_cursor")
    recovery_cursor = singleton_query(request, "recovery_cursor")
    captured_id = singleton_query(request, "captured")
    captured = service.get_batch(captured_id) if captured_id is not None else None
    if captured is not None and (
        len(captured.sources) != 1
        or captured.sources[0].origin is not SourceCaptureOrigin.OWNER_CORRECTION
    ):
        raise InvalidArgumentError("captured correction batch is invalid")
    staged = service.list_staged_inbox_entries(staged_cursor, limit)
    corrections = service.list_recent_correction_batches(correction_cursor, limit)
    recovery = service.list_capture_recovery_issues(recovery_cursor, limit)
    return render_html(
        templates,
        "inbox/index.html",
        status=service.get_status(),
        csrf_token=csrf,
        staged=staged,
        corrections=corrections,
        recovery_issues=recovery,
        captured=captured,
        limit=limit,
        next_staged_href=(
            "/inbox?" + urlencode((("cursor", staged.next_cursor), ("limit", limit)))
            if staged.next_cursor is not None
            else None
        ),
        next_corrections_href=(
            "/inbox?"
            + urlencode(
                (("correction_cursor", corrections.next_cursor), ("limit", limit))
            )
            if corrections.next_cursor is not None
            else None
        ),
        next_recovery_href=(
            "/inbox?"
            + urlencode((("recovery_cursor", recovery.next_cursor), ("limit", limit)))
            if recovery.next_cursor is not None
            else None
        ),
    )


async def _request_chunks(request: Request) -> AsyncIterator[bytes]:
    declared = validate_content_length(
        request.scope["headers"], MAX_UPLOAD_REQUEST_BYTES
    )
    total = 0
    async for chunk in request.stream():
        next_total = total + len(chunk)
        if next_total > MAX_UPLOAD_REQUEST_BYTES or (
            declared is not None and next_total > declared
        ):
            raise RequestLimitError("multipart request exceeds its byte budget")
        total = next_total
        if chunk:
            yield bytes(chunk)
    if declared is not None and total != declared:
        raise InvalidArgumentError("multipart request length is invalid")


async def upload_inbox_file(request: Request) -> Response:
    """Parse one bounded multipart upload and delegate its bytes to the service."""
    session = session_of(request)
    _require_query_names(request, frozenset())
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise InvalidArgumentError("upload content type is ambiguous")
    try:
        raw_content_type = content_types[0].encode("ascii", errors="strict")
    except UnicodeError as error:
        raise InvalidArgumentError("upload content type is invalid") from error
    disposition, options = parse_options_header(raw_content_type)
    boundary = options.get(b"boundary")
    if disposition != b"multipart/form-data" or boundary is None:
        raise InvalidArgumentError("upload content type is invalid")
    service: InboxService = request.app.state.owner_service
    sink = _StreamingStageSink(service)
    try:
        parsed = await parse_bounded_multipart(
            _request_chunks(request),
            boundary=boundary,
            file_sink=sink,
            file_started=sink.begin,
        )
        if (
            parsed.file is None
            or parsed.file.field_name != "file"
            or parsed.fields != (("csrf", session.csrf_token),)
        ):
            raise InvalidArgumentError("upload form is invalid")
        sink.finish()
    except BaseException:
        sink.abort()
        raise
    return Response(status_code=303, headers={"Location": "/inbox?staged=1"})


async def reveal_inbox(request: Request) -> Response:
    """Perform the protected service-owned Finder side effect."""
    session = session_of(request)
    _require_query_names(request, frozenset())
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
        raise InvalidArgumentError("Inbox reveal form is invalid")
    service: InboxService = request.app.state.owner_service
    service.reveal_inbox_in_finder(request.app.state.finder)
    return Response(status_code=303, headers={"Location": "/inbox"})


async def inbox_batch(request: Request) -> Response:
    """Render one bounded authenticated batch reached from the Inbox surface."""
    session_of(request)
    _require_query_names(request, frozenset())
    service: InboxService = request.app.state.owner_service
    templates: Environment = request.app.state.templates
    detail = service.get_batch(request.path_params["batch_id"])
    return render_html(
        templates,
        "inbox/batch.html",
        status=service.get_status(),
        detail=detail,
    )


def inbox_routes() -> tuple[Route, ...]:
    return (
        Route("/inbox", inbox_page, methods=["GET"]),
        Route("/inbox/batches/{batch_id}", inbox_batch, methods=["GET"]),
        Route("/inbox/upload", upload_inbox_file, methods=["POST"]),
        Route("/inbox/reveal", reveal_inbox, methods=["POST"]),
    )
