"""The request helpers every owner-UI route module needs.

Each route module used to carry its own copy of these, and the copies had
drifted: five `_html` variants with mutually incompatible signatures, and one
module answering an unauthenticated request with an HTML body where its
siblings answered the same refusal in plain text. What the owner sees when a
request is refused should not depend on which route refused it.
"""

from __future__ import annotations

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse

from memory.errors import InvalidArgumentError
from memory.model import UiSession
from memory.ui.request_limits import (
    MAX_STANDARD_HTML_RESPONSE_BYTES,
    render_bounded_chunks,
)

#: Every refusal the owner UI renders says exactly this and nothing more, so a
#: refused request never reveals which check refused it.
REFUSAL_TEXT = "Request unavailable"


def session_of(request: Request) -> UiSession:
    """Return the session the authenticating middleware bound to this request."""
    session = request.state.ui_session
    if not isinstance(session, UiSession):
        raise InvalidArgumentError("UI session is unavailable")
    return session


def singleton_query(request: Request, name: str) -> str | None:
    """Read one query parameter, refusing a repeated one rather than picking."""
    values = request.query_params.getlist(name)
    if len(values) > 1:
        raise InvalidArgumentError("query parameter is ambiguous")
    return values[0] if values else None


def page_limit(request: Request, *, maximum: int) -> int:
    """Resolve one owner-supplied page limit inside that page's own ceiling.

    The ceiling differs per page because the rows differ in size, and it is
    what keeps a rendered page inside its response budget. An absent limit
    means the ceiling itself, never something larger.
    """
    raw = singleton_query(request, "limit")
    if raw is None:
        return maximum
    if not raw.isdigit():
        raise InvalidArgumentError("page limit is invalid")
    try:
        value = int(raw)
    except ValueError as error:
        raise InvalidArgumentError("page limit is invalid") from error
    if not 1 <= value <= maximum:
        raise InvalidArgumentError("page limit is invalid")
    return value


def render_html(
    templates: Environment,
    name: str,
    *,
    status_code: int = 200,
    max_bytes: int = MAX_STANDARD_HTML_RESPONSE_BYTES,
    **context: object,
) -> HTMLResponse:
    """Render one template into a response bounded by its own byte budget."""
    chunks = templates.get_template(name).generate(**context)
    body = render_bounded_chunks(
        (chunk.encode("utf-8") for chunk in chunks),
        max_bytes=max_bytes,
    )
    return HTMLResponse(body, status_code=status_code)


def refused(status_code: int) -> PlainTextResponse:
    """Refuse one request in the single wording every route refuses with."""
    return PlainTextResponse(REFUSAL_TEXT, status_code=status_code)
