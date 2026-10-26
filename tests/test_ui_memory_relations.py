from __future__ import annotations

import html
import re
from typing import Literal
from urllib.parse import parse_qs, urlsplit

import pytest
from inspection_support import _authenticated_ui
from synthetic import FakeClock, capture_text, large_guard_star

from memory.errors import StaleCursorError
from memory.memories import get_memories
from memory.model import RuntimePaths, Sensitivity
from memory.ui.service import OwnerApplicationService


@pytest.mark.parametrize("direction", ["guards", "governs"])
@pytest.mark.parametrize("within_audit", [False, True])
def test_large_related_statements_remain_readable_through_bounded_detail_pages(
    synthetic_store: RuntimePaths,
    direction: Literal["guards", "governs"],
    within_audit: bool,
) -> None:
    """Valid escaped statements must not make a memory's whole page return 413."""
    centre, related, complete_statement = large_guard_star(synthetic_store, direction)
    service = OwnerApplicationService(synthetic_store)
    # The real service implements the fake's tested UI surface.
    ui = _authenticated_ui(service)  # type: ignore[arg-type]
    suffix = ""
    if within_audit:
        started = ui.post_form("/audit", [("csrf", ui.session.csrf_token)])
        assert started.status_code == 303
        suffix = "?" + urlsplit(started.headers["location"]).query
        assert "h" in parse_qs(suffix[1:])
    row_attribute = "data-guard-id" if direction == "guards" else "data-governs-id"
    next_attribute = f"data-next-{direction}"
    url: str | None = f"/memories/{centre}{suffix}"
    seen: list[str] = []
    pages = 0
    while url is not None:
        if within_audit:
            assert parse_qs(urlsplit(url).query)["h"] == parse_qs(suffix[1:])["h"]
        response = ui.client.get(url)
        assert response.status_code == 200
        assert len(response.content) <= 4_194_304
        rows = re.findall(rf'{row_attribute}="([^"]+)"', response.text)
        assert 0 < len(rows) <= 50
        seen.extend(rows)
        assert f'href="/memories/{rows[-1]}{suffix}"' in response.text
        next_link = re.search(rf'{next_attribute} href="([^"]+)"', response.text)
        url = None if next_link is None else html.unescape(next_link.group(1))
        pages += 1
        assert pages <= 3
    assert pages > 1
    assert len(seen) == len(set(seen)) == 60
    assert set(seen) == set(related)
    complete = ui.client.get(f"/memories/{related[-1]}{suffix}")
    assert complete.status_code == 200
    assert complete_statement in html.unescape(complete.text)
    assert "Open complete retained source" in complete.text
    assert (
        get_memories(synthetic_store, (related[-1],))[0].revision.statement
        == complete_statement
    )
    ui.client.close()


@pytest.mark.parametrize("direction", ["guards", "governs"])
def test_related_memory_cursors_cannot_cross_contexts_or_store_changes(
    synthetic_store: RuntimePaths,
    direction: Literal["guards", "governs"],
) -> None:
    centre, related, _statement = large_guard_star(synthetic_store, direction)
    service = OwnerApplicationService(synthetic_store)
    first = service.get_memory_revision(centre)
    cursor = (
        first.guards_next_cursor if direction == "guards" else first.governs_next_cursor
    )
    assert cursor is not None
    guards_cursor = cursor if direction == "guards" else None
    governs_cursor = cursor if direction == "governs" else None
    with pytest.raises(StaleCursorError):
        service.get_memory_revision(
            related[0], guards_cursor=guards_cursor, governs_cursor=governs_cursor
        )
    with pytest.raises(StaleCursorError):
        service.get_memory_revision(
            centre, guards_cursor=governs_cursor, governs_cursor=guards_cursor
        )
    audit = service.bind_audit(service.begin_audit_snapshot())
    with pytest.raises(StaleCursorError):
        audit.get_memory_revision(
            centre, guards_cursor=guards_cursor, governs_cursor=governs_cursor
        )
    audit_first = audit.get_memory_revision(centre)
    other_audit = service.bind_audit(service.begin_audit_snapshot())
    with pytest.raises(StaleCursorError):
        other_audit.get_memory_revision(
            centre,
            guards_cursor=audit_first.guards_next_cursor,
            governs_cursor=audit_first.governs_next_cursor,
        )

    capture_text(
        synthetic_store,
        name="synthetic-generation-change.txt",
        body="Synthetic later source: a paper kite arrives at the workshop.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    with pytest.raises(StaleCursorError):
        service.get_memory_revision(
            centre, guards_cursor=guards_cursor, governs_cursor=governs_cursor
        )
    with pytest.raises(StaleCursorError):
        audit.get_memory_revision(
            centre,
            guards_cursor=audit_first.guards_next_cursor,
            governs_cursor=audit_first.governs_next_cursor,
        )
