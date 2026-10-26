"""Secure loopback-only Starlette shell for the local owner UI."""

from __future__ import annotations

import os
import socket
import time
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path
from types import FrameType
from typing import Protocol
from urllib.parse import urlsplit

import uvicorn
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route

from memory.errors import (
    InvalidArgumentError,
    RequestLimitError,
    StoreError,
)
from memory.inbox import (
    bind_runtime_directory_authority,
    recover_exact_staged_entries,
)
from memory.model import RuntimePaths
from memory.runtime import authorize_runtime_use, ui_session_lock
from memory.ui.auth import UiSessionStore
from memory.ui.browser_launch import (
    CocoaFinderRevealer,
    FinderRevealer,
    create_ui_launch,
    open_bootstrap_url_with_launch_services,
    write_ui_launch_envelope,
)
from memory.ui.owner_presence import (
    ApprovalAttemptStore,
    LocalAuthenticationOwnerPresenceVerifier,
    SystemMonotonicClock,
    UiApprovalOrchestrator,
)
from memory.ui.presentation import (
    compare_statements,
    memory_validity,
    review_guard_endpoint_href,
    review_item_edit_href,
    review_item_href,
    roster_statement_preview,
)
from memory.ui.request_limits import (
    MAX_CONTROL_FORM_BODY_BYTES,
    read_bounded_body,
)
from memory.ui.routes.audit import AuditService, audit_routes
from memory.ui.routes.graph import GraphService, graph_routes
from memory.ui.routes.inbox import InboxService, inbox_routes
from memory.ui.routes.memories import MemoryService, memory_routes
from memory.ui.routes.reviews import ReviewService, review_routes
from memory.ui.routes.sources import SourceService, source_routes
from memory.ui.routes.status import status_endpoint

_PACKAGE_ROOT = Path(__file__).resolve().parent
_STATIC_ASSETS = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/bootstrap.js": ("bootstrap.js", "text/javascript; charset=utf-8"),
    "/static/graph.js": ("graph.js", "text/javascript; charset=utf-8"),
    "/static/ui.js": ("ui.js", "text/javascript; charset=utf-8"),
}
_PUBLIC_GETS = frozenset({"/bootstrap", *_STATIC_ASSETS})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_STANDARD_PROXY_HEADERS = frozenset({b"forwarded", b"via"})
_ALLOWED_STANDARD_REQUEST_HEADERS = frozenset(
    {
        b"accept",
        b"accept-encoding",
        b"accept-language",
        b"cache-control",
        b"connection",
        b"content-length",
        b"content-type",
        b"cookie",
        b"dnt",
        b"host",
        b"if-match",
        b"if-modified-since",
        b"if-none-match",
        b"if-range",
        b"if-unmodified-since",
        b"keep-alive",
        b"origin",
        b"pragma",
        b"priority",
        b"purpose",
        b"range",
        b"referer",
        b"save-data",
        b"sec-gpc",
        b"sec-purpose",
        b"te",
        b"upgrade-insecure-requests",
        b"user-agent",
    }
)
_ALLOWED_BROWSER_REQUEST_HEADERS = frozenset(
    {
        b"sec-ch-ua",
        b"sec-ch-ua-mobile",
        b"sec-ch-ua-platform",
        b"sec-fetch-dest",
        b"sec-fetch-mode",
        b"sec-fetch-site",
        b"sec-fetch-user",
    }
)
_ALLOWED_CUSTOM_REQUEST_HEADERS = frozenset({b"x-memory-csrf"})
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; connect-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    ),
}
_BYTE_UNITS = ("KB", "MB", "GB", "TB")
_BOOTSTRAP_HTML = b"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Memory</title></head>
<body><main><h1>Opening Memory</h1><p>This launch link is being exchanged locally.</p></main><script src="/static/bootstrap.js"></script></body></html>
"""


class OwnerUiService(
    SourceService,
    MemoryService,
    InboxService,
    ReviewService,
    AuditService,
    GraphService,
    Protocol,
):
    """Complete bounded owner surface consumed by local UI routes."""


def memory_time(value: object) -> str:
    """Render one stored epoch second as a fixed local ``YYYY-MM-DD HH:MM``.

    Deliberately absolute: a relative rendering would change between two
    identical reads, which no owner page and no acceptance run can pin.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return "not recorded"
    try:
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")
    except OSError, OverflowError, ValueError:
        return "not recorded"


def filesize(value: object) -> str:
    """Render one stored byte length the way the owner reads sizes."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return "unknown size"
    if value == 1:
        return "1 byte"
    if value < 1024:
        return f"{value} bytes"
    scaled = float(value)
    unit = _BYTE_UNITS[0]
    for candidate in _BYTE_UNITS:
        unit = candidate
        scaled /= 1024
        if scaled < 1024:
            break
    rendered = f"{scaled:.1f}".removesuffix(".0")
    return f"{rendered} {unit}"


def _singleton_header(
    headers: list[tuple[bytes, bytes]],
    name: bytes,
) -> bytes | None:
    values = [value for header, value in headers if header.lower() == name]
    return values[0] if len(values) == 1 else None


def _is_allowed_request_header(name: bytes) -> bool:
    normalized = name.lower()
    if normalized in _STANDARD_PROXY_HEADERS or normalized.startswith(b"proxy-"):
        return False
    return (
        normalized in _ALLOWED_STANDARD_REQUEST_HEADERS
        or normalized in _ALLOWED_BROWSER_REQUEST_HEADERS
        or normalized in _ALLOWED_CUSTOM_REQUEST_HEADERS
    )


def create_ui_app(
    service: OwnerUiService,
    sessions: UiSessionStore,
    finder: FinderRevealer,
    approval: UiApprovalOrchestrator,
    *,
    public_origin: str,
    today: Callable[[], date] = date.today,
) -> Starlette:
    """Create one exact-origin app with process-memory authentication."""
    if not isinstance(approval, UiApprovalOrchestrator):
        raise InvalidArgumentError("UI approval orchestrator is required")
    parsed = urlsplit(public_origin)
    if (
        parsed.scheme != "http"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise InvalidArgumentError("UI public origin is invalid")
    exact_host = parsed.netloc
    templates = Environment(
        loader=FileSystemLoader(_PACKAGE_ROOT / "templates"),
        autoescape=select_autoescape(("html", "xml")),
        enable_async=False,
    )
    templates.filters["memory_time"] = memory_time
    templates.filters["filesize"] = filesize
    templates.globals["compare_statements"] = compare_statements
    templates.globals["memory_validity"] = memory_validity
    templates.globals["review_guard_endpoint_href"] = review_guard_endpoint_href
    templates.globals["review_item_edit_href"] = review_item_edit_href
    templates.globals["review_item_href"] = review_item_href
    templates.globals["roster_statement_preview"] = roster_statement_preview
    status = status_endpoint(service, templates)

    async def landing(request: Request) -> Response:
        if service.get_status().pending_review_count > 0:
            return Response(status_code=303, headers={"Location": "/reviews"})
        return await status(request)

    async def bootstrap(_request: Request) -> Response:
        return HTMLResponse(_BOOTSTRAP_HTML)

    async def static_asset(request: Request) -> Response:
        selected = _STATIC_ASSETS.get(request.url.path)
        if selected is None:
            return PlainTextResponse("Request unavailable", status_code=404)
        filename, media_type = selected
        try:
            body = (_PACKAGE_ROOT / "static" / filename).read_bytes()
        except OSError:
            return PlainTextResponse("Request unavailable", status_code=500)
        return Response(body, media_type=media_type)

    async def exchange_session(request: Request) -> Response:
        try:
            body = await read_bounded_body(
                request.receive,
                headers=request.scope["headers"],
                max_bytes=MAX_CONTROL_FORM_BODY_BYTES,
            )
            secret = body.decode("ascii", errors="strict")
        except StoreError, UnicodeError:
            return PlainTextResponse("Request unavailable", status_code=400)
        session = sessions.exchange_bootstrap(
            secret=secret,
            exact_host=exact_host,
            now_ns=time.monotonic_ns(),
        )
        if session is None:
            return PlainTextResponse("Request unavailable", status_code=401)
        response = Response(status_code=303, headers={"Location": "/"})
        response.set_cookie(
            "memory_ui_session",
            session.session_id,
            path="/",
            httponly=True,
            samesite="strict",
        )
        return response

    routes = [
        Route("/bootstrap", bootstrap, methods=["GET"]),
        Route("/session", exchange_session, methods=["POST"]),
        Route("/static/{asset}", static_asset, methods=["GET"]),
        Route("/", landing, methods=["GET"]),
        Route("/status", status, methods=["GET"]),
        *audit_routes(service, sessions, templates),
        *graph_routes(service, sessions, templates),
        *inbox_routes(),
        *memory_routes(service, sessions, templates, today=today),
        *review_routes(service, sessions, templates, approval, today=today),
        *source_routes(service, sessions, templates),
    ]

    async def secure_request(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response: Response
        try:
            raw_headers = request.scope["headers"]
            hosts = [value for name, value in raw_headers if name.lower() == b"host"]
            if len(hosts) != 1 or hosts[0] != exact_host.encode("ascii"):
                response = PlainTextResponse("Request unavailable", status_code=400)
            elif any(
                not _is_allowed_request_header(name) for name, _value in raw_headers
            ):
                response = PlainTextResponse("Request unavailable", status_code=400)
            elif request.url.path == "/session" and request.method == "POST":
                if _singleton_header(raw_headers, b"origin") != public_origin.encode(
                    "ascii"
                ):
                    response = PlainTextResponse("Request unavailable", status_code=403)
                else:
                    response = await call_next(request)
            elif request.method == "GET" and request.url.path in _PUBLIC_GETS:
                response = await call_next(request)
            else:
                cookie = request.cookies.get("memory_ui_session", "")
                session = sessions.resolve_cookie(
                    cookie=cookie,
                    exact_host=exact_host,
                    now_ns=time.monotonic_ns(),
                )
                if session is None:
                    response = PlainTextResponse("Request unavailable", status_code=401)
                elif request.method in _MUTATING_METHODS and (
                    _singleton_header(raw_headers, b"origin")
                    != public_origin.encode("ascii")
                    or _singleton_header(raw_headers, b"x-memory-csrf")
                    != session.csrf_token.encode("ascii")
                ):
                    response = PlainTextResponse("Request unavailable", status_code=403)
                else:
                    request.state.ui_session = session
                    response = await call_next(request)
        except RequestLimitError:
            response = PlainTextResponse("Request unavailable", status_code=413)
        except StoreError:
            response = PlainTextResponse("Request unavailable", status_code=400)
        except Exception:
            response = PlainTextResponse("Request unavailable", status_code=500)
        for name, value in _SECURITY_HEADERS.items():
            response.headers[name] = value
        for cors_header in (
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ):
            if cors_header in response.headers:
                del response.headers[cors_header]
        return response

    application = Starlette(
        routes=routes,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=secure_request)],
    )
    application.state.public_origin = public_origin
    application.state.finder = finder
    application.state.owner_service = service
    application.state.sessions = sessions
    application.state.approval = approval
    application.state.templates = templates
    return application


def _serve_ui(
    application: Starlette,
    bound_socket: socket.socket,
    on_ready: Callable[[], None],
) -> None:
    """Serve an already-bound socket and signal only after Uvicorn startup."""

    class ReadyServer(uvicorn.Server):
        async def startup(self, sockets: list[socket.socket] | None = None) -> None:
            await super().startup(sockets=sockets)
            if self.started:
                on_ready()

        def handle_exit(self, sig: int, frame: FrameType | None) -> None:
            super().handle_exit(sig, frame)
            # Uvicorn normally replays captured signals after graceful shutdown.
            # This process owns additional cleanup in ``run_ui``'s ``finally``.
            self._captured_signals.clear()

    config = uvicorn.Config(
        application,
        host="127.0.0.1",
        port=0,
        access_log=False,
        log_config=None,
        log_level="warning",
        lifespan="off",
    )
    ReadyServer(config).run(sockets=[bound_socket])


def run_ui(
    paths: RuntimePaths,
    *,
    open_browser: bool,
    launch_fd: int | None,
) -> int:
    """Authorize, lock, pre-bind, and serve one foreground owner UI process."""
    if open_browser == (launch_fd is not None):
        raise InvalidArgumentError("UI launch mode is invalid")
    authorize_runtime_use(paths)
    pending_launch_fd = launch_fd
    sessions: UiSessionStore | None = None
    approval: UiApprovalOrchestrator | None = None
    bound_socket: socket.socket | None = None
    try:
        with ui_session_lock(paths):
            directory_authority = bind_runtime_directory_authority(paths)
            recover_exact_staged_entries(
                paths,
                directory_authority=directory_authority,
            )
            bound_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bound_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bound_socket.bind(("127.0.0.1", 0))
            bound_socket.listen(128)
            bound_port = int(bound_socket.getsockname()[1])
            launch = create_ui_launch(paths, bound_port=bound_port)
            exact_host = f"{launch.public_host}:{launch.port}"
            public_origin = f"http://{exact_host}"
            sessions = UiSessionStore(
                bootstrap_capability=launch.bootstrap_capability,
                exact_host=exact_host,
                created_at_ns=time.monotonic_ns(),
            )
            from memory.ui.service import OwnerApplicationService

            service = OwnerApplicationService(
                paths,
                directory_authority=directory_authority,
            )
            approval = UiApprovalOrchestrator(
                service=service,
                sessions=sessions,
                attempts=ApprovalAttemptStore(),
                verifier=LocalAuthenticationOwnerPresenceVerifier(),
                clock=SystemMonotonicClock(),
            )
            application = create_ui_app(
                service,
                sessions,
                CocoaFinderRevealer(),
                approval,
                public_origin=public_origin,
            )

            def on_ready() -> None:
                nonlocal pending_launch_fd
                if open_browser:
                    open_bootstrap_url_with_launch_services(launch.url)
                    return
                descriptor = pending_launch_fd
                pending_launch_fd = None
                if descriptor is None:
                    raise InvalidArgumentError("launch descriptor is unavailable")
                write_ui_launch_envelope(descriptor, launch)
                print("memory-ui-ready", flush=True)

            try:
                _serve_ui(application, bound_socket, on_ready)
            finally:
                # Invalidate pending OS contexts, consume every approval attempt,
                # and erase sessions before this runtime's UI lock is released.
                approval.shutdown()
                sessions.invalidate_all()
            return 0
    except KeyboardInterrupt:
        return 0
    finally:
        if approval is not None:
            approval.shutdown()
        if sessions is not None:
            sessions.invalidate_all()
        if bound_socket is not None:
            try:
                bound_socket.close()
            except OSError:
                pass
        if pending_launch_fd is not None:
            try:
                os.close(pending_launch_fd)
            except OSError:
                pass
