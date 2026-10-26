"""Status and stable shell rendering for the initial owner UI slice."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from memory.ui.request_limits import (
    MAX_STANDARD_HTML_RESPONSE_BYTES,
    render_bounded_chunks,
)
from memory.ui.routes._support import session_of
from memory.ui.view_models import OwnerStatus


class StatusService(Protocol):
    def get_status(self) -> OwnerStatus: ...


def status_endpoint(
    service: StatusService,
    templates: Environment,
) -> Callable[[Request], Awaitable[Response]]:
    """Build a route that receives only query service and session authority."""

    async def render_status(request: Request) -> Response:
        session = session_of(request)
        status = service.get_status()
        csrf = session.csrf_token
        chunks = templates.get_template("status.html").generate(
            status=status,
            csrf_token=csrf,
        )
        encoded = (chunk.encode("utf-8") for chunk in chunks)
        body = render_bounded_chunks(
            encoded,
            max_bytes=MAX_STANDARD_HTML_RESPONSE_BYTES,
        )
        return HTMLResponse(body)

    return render_status
