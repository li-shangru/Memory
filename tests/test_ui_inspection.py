from __future__ import annotations

import asyncio
import base64
import importlib
import inspect
import os
import re
import threading
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any, cast

import httpx2
import keyring
import pytest
from inspection_support import (
    APPLICATION_ID,
    APPROVAL_ID,
    BATCH_ID,
    BINARY_SOURCE_ID,
    CHANGE_REVISION_ID,
    CHANGE_SET_ID,
    CURRENT_MEMORY_ID,
    EVENT_MEMORY_ID,
    EXACT_HOST,
    JPEG_SOURCE_ID,
    LINEAGE_ID,
    MARKUP_TAG,
    NORMAL_SOURCE_ID,
    OLD_MEMORY_ID,
    PDF_SOURCE_ID,
    PNG_SOURCE_ID,
    PUBLIC_ORIGIN,
    TEXT_SOURCE_ID,
    WEBP_SOURCE_ID,
    SyntheticInspectionService,
    _authenticated_ui,
    _hex_from_page,
    _image_bytes,
    _memory_summary,
    _next_content_href,
    _pdf_bytes,
    _source_summary,
    _UnusedFinder,
)
from starlette.routing import Route
from synthetic import (
    FakeClock,
    make_synthetic_store,
    store_synthetic_key_exclusive,
    two_source_linked_apply,
)
from ui_support import build_test_orchestrator

from memory import keys, model
from memory.errors import StaleCursorError
from memory.inbox import ScanPolicy, scan_inbox
from memory.model import (
    AddItem,
    EvidenceLocator,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    MemorySummary,
    RuntimeMode,
    Sensitivity,
)
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.runtime import initialize_runtime, resolve_runtime
from memory.ui.app import OwnerUiService, create_ui_app
from memory.ui.auth import UiSessionStore
from memory.ui.request_limits import (
    MAX_STANDARD_HTML_RESPONSE_BYTES,
    UI_MEMORY_PAGE_LIMIT,
    UI_STANDARD_PAGE_LIMIT,
)
from memory.ui.service import OwnerApplicationService
from memory.ui.view_models import (
    OwnerEvidenceLink,
    OwnerMemoryDetail,
    OwnerMemorySearchPage,
    OwnerMemorySummary,
    OwnerPage,
    OwnerSourceChunk,
    OwnerSourceSummary,
)


class _UnusedOwnerService:
    def get_status(self) -> object:
        raise AssertionError("route inventory must not query the Store")


def _route_inventory() -> set[tuple[str, tuple[str, ...]]]:
    sessions = UiSessionStore(
        bootstrap_capability="synthetic-bootstrap",
        exact_host=EXACT_HOST,
        created_at_ns=100,
    )
    unused = _UnusedOwnerService()
    application = create_ui_app(
        unused,  # type: ignore[arg-type]
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(unused, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    return {
        (route.path, tuple(sorted(route.methods or ())))
        for route in application.routes
        if isinstance(route, Route)
    }


def test_inspection_modules_expose_the_approved_bounded_interfaces() -> None:
    """Catch omission or signature drift at the inspection-service production boundary."""
    media = importlib.import_module("memory.ui.media_preview")
    pdf = importlib.import_module("memory.ui.pdf_render")
    importlib.import_module("memory.ui.routes.sources")
    importlib.import_module("memory.ui.routes.memories")

    assert media.MAX_MEDIA_SOURCE_BYTES == 67_108_864
    assert media.MAX_SOURCE_TEXT_CHUNK_BYTES == 262_144
    assert media.MAX_BINARY_WINDOW_BYTES == 65_536
    assert media.MAX_IMAGE_DECODE_PIXELS == 40_000_000
    assert media.MAX_PREVIEW_PIXELS == 16_000_000
    assert media.MAX_PREVIEW_DIMENSION == 8_192
    assert media.MAX_PREVIEW_PNG_BYTES == 65_048_576
    assert media.MAX_MEDIA_FRAMES == 1
    assert media.MEDIA_WORKER_MEMORY_BYTES == 536_870_912
    assert media.MEDIA_WORKER_TIMEOUT_SECONDS == 10.0
    assert media.MEDIA_WORKER_JOIN_SECONDS == 1.0
    assert media.MAX_CONCURRENT_MEDIA_WORKERS == 2
    assert media.MEDIA_BUSY_RETRY_AFTER_SECONDS == 1
    assert callable(media.render_image_preview)
    assert callable(media.render_binary_window)
    assert pdf.MAX_PDF_PAGES == 500
    assert callable(pdf.render_pdf_page)
    assert tuple(media.ImagePreview.__dataclass_fields__) == (
        "width",
        "height",
        "png_bytes",
    )
    assert tuple(pdf.PdfPageImage.__dataclass_fields__) == (
        "page_number",
        "width",
        "height",
        "png_bytes",
    )
    assert tuple(inspect.signature(media.render_image_preview).parameters) == (
        "source_bytes",
        "max_pixels",
    )
    assert tuple(inspect.signature(pdf.render_pdf_page).parameters) == (
        "source_bytes",
        "page_number",
        "max_pixels",
    )
    assert tuple(inspect.signature(media.render_binary_window).parameters) == (
        "data",
        "offset",
        "width",
    )


def test_app_registers_the_complete_authenticated_inspection_route_inventory() -> None:
    """Catch source or memory inspection falling through to shell placeholders."""
    inventory = _route_inventory()

    assert {
        ("/sources", ("GET", "HEAD")),
        ("/sources/search", ("POST",)),
        ("/sources/search/{handle}", ("GET", "HEAD")),
        ("/sources/{source_id}", ("GET", "HEAD")),
        ("/sources/{source_id}/preview", ("GET", "HEAD")),
        ("/memory", ("GET", "HEAD")),
        ("/memory/search", ("POST",)),
        ("/memory/search/{handle}", ("GET", "HEAD")),
        ("/memories/{memory_id}", ("GET", "HEAD")),
    } <= inventory


def test_binary_window_is_escaped_text_and_reconstructs_exact_bytes() -> None:
    """Catch hex inspection dropping, changing, or activating original bytes."""
    media = importlib.import_module("memory.ui.media_preview")
    source = bytes(range(256)) + b"<script>synthetic()</script>\x00\xff"
    rendered = media.render_binary_window(source, offset=0, width=16)
    recovered = bytes.fromhex(
        "".join(
            line.split("  ", 2)[1].replace(" ", "") for line in rendered.splitlines()
        )
    )

    assert recovered == source
    assert "<script>" not in rendered
    assert "syntheti" in rendered and "c()" in rendered
    assert all(
        len(line.split("  ", 2)[1].split()) <= 16 for line in rendered.splitlines()
    )


@pytest.mark.slow
def test_decoded_pixel_limit_accepts_exact_and_rejects_plus_one() -> None:
    """Catch decompression beyond the 40-million-pixel child bound."""
    media = importlib.import_module("memory.ui.media_preview")
    exact = _image_bytes("PNG", size=(8_000, 5_000), metadata=False)
    over = _image_bytes("PNG", size=(8_000, 5_001), metadata=False)

    preview = media.render_image_preview(exact, max_pixels=media.MAX_PREVIEW_PIXELS)
    with pytest.raises(media.MediaPreviewError) as error:
        media.render_image_preview(over, max_pixels=media.MAX_PREVIEW_PIXELS)

    assert preview.width * preview.height <= media.MAX_PREVIEW_PIXELS
    assert error.value.code == "decoded_pixel_limit"


def test_default_owner_search_includes_every_sensitivity_behind_opaque_handle() -> None:
    """Catch owner search redacting sensitivity or leaking its query into history."""
    ui = _authenticated_ui()
    response = ui.search_sources("synthetic-private-query")

    assert response.status_code == 200
    assert "synthetic-private-query" not in str(response.url)
    assert not response.history
    assert {
        'data-sensitivity="normal"',
        'data-sensitivity="sensitive"',
        'data-sensitivity="restricted"',
    } <= {
        part[: part.index('"', len('data-sensitivity="')) + 1]
        for part in response.text.split()
        if part.startswith("data-sensitivity=")
    }
    assert "Searchable captures" in response.text
    assert "Unsearchable captures" in response.text


def test_memory_tags_carrying_markup_are_escaped_on_every_owner_page() -> None:
    """Catch a stored tag reaching an owner page as live markup."""
    ui = _authenticated_ui()
    detail = ui.client.get(f"/memories/{EVENT_MEMORY_ID}")
    listing = ui.client.get("/memory")

    for response in (detail, listing):
        assert response.status_code == 200
        assert MARKUP_TAG not in response.text
        assert "&lt;script&gt;alert(&#39;synthetic-tag&#39;)&lt;/script&gt;" in (
            response.text
        )


def test_source_detail_escapes_content_and_links_complete_provenance() -> None:
    """Catch inert content becoming HTML or capture/blob relationships disappearing."""
    ui = _authenticated_ui()
    response = ui.client.get(f"/sources/{TEXT_SOURCE_ID}")

    assert response.status_code == 200
    assert "<script>synthetic" not in response.text
    assert "&lt;script&gt;synthetic" in response.text
    assert "合成记录：蓝色纸灯仍然可见" in response.text
    assert f'href="/inbox/batches/{BATCH_ID}"' in response.text
    assert f'href="/memories/{CURRENT_MEMORY_ID}"' in response.text
    assert f'href="/sources/{NORMAL_SOURCE_ID}"' in response.text
    assert "Capture identity" in response.text
    assert "Blob identity" in response.text
    assert "Declared sensitivity" in response.text
    assert "Effective sensitivity" in response.text
    assert "Authorship" in response.text
    assert "Capture origin" in response.text
    assert "Blob digest" in response.text
    assert "Captured at" in response.text
    assert "Indexed for search" in response.text
    assert "Evidence backlinks" in response.text


@pytest.mark.parametrize("source_id", [BINARY_SOURCE_ID, PNG_SOURCE_ID, PDF_SOURCE_ID])
def test_every_binary_original_reconstructs_through_paginated_hex_only(
    source_id: str,
) -> None:
    """Catch valid media or unknown bytes losing complete bounded original access."""
    ui = _authenticated_ui()
    expected = ui.service.media[source_id][1]
    url: str | None = f"/sources/{source_id}"
    reconstructed = bytearray()
    page_count = 0
    while url is not None:
        page = ui.client.get(url)
        assert page.status_code == 200
        reconstructed.extend(_hex_from_page(page.text))
        page_count += 1
        url = _next_content_href(page.text)
    assert bytes(reconstructed) == expected
    assert page_count >= (2 if source_id == BINARY_SOURCE_ID else 1)


def test_failed_source_continuation_exposes_retry_without_discarding_prior_chunk() -> (
    None
):
    """Catch a stale continuation replacing already verified source context."""
    ui = _authenticated_ui()
    first = ui.client.get(f"/sources/{BINARY_SOURCE_ID}")
    failed = ui.client.get(f"/sources/{BINARY_SOURCE_ID}?cursor=stale-cursor")

    assert first.status_code == 200
    assert failed.status_code == 409
    assert "Previously displayed chunks remain valid" in failed.text
    assert f'href="/sources/{BINARY_SOURCE_ID}"' in failed.text
    assert "stale-cursor" not in failed.text


class RecoveringSourceCursorService(SyntheticInspectionService):
    def __init__(self, *, stale_page: str) -> None:
        super().__init__()
        self.stale_page = stale_page
        self.root_reads = 0
        self.middle_reads = 0

    def _binary_chunk(
        self,
        *,
        start: int,
        next_cursor: str | None,
    ) -> OwnerSourceChunk:
        end = min(len(self.binary), start + 65_536)
        return OwnerSourceChunk(
            source_id=BINARY_SOURCE_ID,
            blob_digest=self.sources[BINARY_SOURCE_ID].blob_digest,
            media_type="application/octet-stream",
            text=None,
            binary=self.binary[start:end],
            char_start=None,
            char_end=None,
            byte_start=start,
            byte_end=end,
            next_cursor=next_cursor,
            complete=next_cursor is None,
        )

    def read_source(
        self,
        source_id: str,
        cursor: str | None,
        max_bytes: int,
    ) -> OwnerSourceChunk:
        if source_id != BINARY_SOURCE_ID:
            return super().read_source(source_id, cursor, max_bytes)
        assert max_bytes == 65_536
        if cursor is None:
            self.root_reads += 1
            next_cursor = (
                "stale-first"
                if self.stale_page == "first" and self.root_reads == 1
                else "middle"
            )
            return self._binary_chunk(start=0, next_cursor=next_cursor)
        if cursor == "stale-first":
            raise StaleCursorError("synthetic first continuation expired")
        if cursor == "middle":
            self.middle_reads += 1
            next_cursor = (
                "stale-later"
                if self.stale_page == "later" and self.middle_reads == 1
                else "final"
            )
            return self._binary_chunk(start=65_536, next_cursor=next_cursor)
        if cursor == "stale-later":
            raise StaleCursorError("synthetic later continuation expired")
        if cursor == "final":
            return self._binary_chunk(start=131_072, next_cursor=None)
        raise StaleCursorError("synthetic source cursor is not bound")


def _stale_retry_href(body: str) -> str:
    marker = 'data-retry-content href="'
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)].replace("&amp;", "&")


@pytest.mark.parametrize("stale_page", ["first", "later"])
def test_stale_source_retry_refetches_last_verified_page_then_completes(
    stale_page: str,
) -> None:
    """Catch a stale source retry looping on the cursor that just failed."""
    service = RecoveringSourceCursorService(stale_page=stale_page)
    ui = _authenticated_ui(service)
    first = ui.client.get(f"/sources/{BINARY_SOURCE_ID}")
    first_bytes = _hex_from_page(first.text)
    first_next = _next_content_href(first.text)
    assert first_next is not None

    if stale_page == "first":
        failed = ui.client.get(first_next)
        expected_retry = f"/sources/{BINARY_SOURCE_ID}"
        prior_bytes = first_bytes
    else:
        middle = ui.client.get(first_next)
        middle_bytes = _hex_from_page(middle.text)
        failed_url = _next_content_href(middle.text)
        assert failed_url is not None
        failed = ui.client.get(failed_url)
        expected_retry = first_next
        prior_bytes = first_bytes + middle_bytes

    assert failed.status_code == 409
    retry_url = _stale_retry_href(failed.text)
    assert retry_url == expected_retry
    assert "stale-first" not in retry_url and "stale-later" not in retry_url

    refreshed_previous = ui.client.get(retry_url)
    assert refreshed_previous.status_code == 200
    fresh_next = _next_content_href(refreshed_previous.text)
    assert fresh_next is not None
    if stale_page == "first":
        assert _hex_from_page(refreshed_previous.text) == first_bytes
        middle = ui.client.get(fresh_next)
        reconstructed = prior_bytes + _hex_from_page(middle.text)
        final_url = _next_content_href(middle.text)
    else:
        assert _hex_from_page(refreshed_previous.text) == middle_bytes
        reconstructed = prior_bytes
        final_url = fresh_next
    assert final_url is not None
    final = ui.client.get(final_url)
    assert final.status_code == 200
    reconstructed += _hex_from_page(final.text)
    assert reconstructed == service.binary
    assert _next_content_href(final.text) is None


class PagedRelationshipService(SyntheticInspectionService):
    def __init__(self) -> None:
        super().__init__()
        target = self.sources[BINARY_SOURCE_ID]
        self.sibling_rows = tuple(
            _source_summary(
                f"src_{index + 1000:032x}",
                sensitivity=Sensitivity.RESTRICTED,
                media_type="application/octet-stream",
                name=f"synthetic-sibling-{index:03}.bin",
                blob_id=target.blob_id,
            )
            for index in range(2 * UI_STANDARD_PAGE_LIMIT + 1)
        )
        self.evidence_rows = tuple(
            OwnerEvidenceLink(
                memory_revision_id=f"mem_{index + 2000:032x}",
                lineage_id=f"lin_{index + 3000:032x}",
                is_current=True,
                locator=EvidenceLocator(
                    ordinal=index,
                    source_id=BINARY_SOURCE_ID,
                    blob_digest=target.blob_digest,
                    mode="source",
                    char_start=None,
                    char_end=None,
                    excerpt=None,
                    source_level=True,
                ),
            )
            for index in range(2 * UI_STANDARD_PAGE_LIMIT + 1)
        )

    @staticmethod
    def _bound_offset(cursor: str | None, prefix: str) -> int:
        if cursor is None:
            return 0
        if not cursor.startswith(prefix):
            raise StaleCursorError("synthetic relationship cursor is not bound")
        return int(cursor.removeprefix(prefix))

    def list_blob_captures(
        self,
        blob_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceSummary]:
        expected_blob = self.sources[BINARY_SOURCE_ID].blob_id
        if blob_id != expected_blob:
            raise StaleCursorError("synthetic capture cursor crossed blobs")
        prefix = f"capture:{blob_id}:"
        start = self._bound_offset(cursor, prefix)
        visible = self.sibling_rows[start : start + limit]
        end = start + len(visible)
        more = end < len(self.sibling_rows)
        return OwnerPage(
            items=visible,
            next_cursor=f"{prefix}{end}" if more else None,
            has_more=more,
        )

    def list_source_evidence_links(
        self,
        source_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerEvidenceLink]:
        if source_id != BINARY_SOURCE_ID:
            raise StaleCursorError("synthetic evidence cursor crossed sources")
        prefix = f"evidence:{source_id}:"
        start = self._bound_offset(cursor, prefix)
        visible = self.evidence_rows[start : start + limit]
        end = start + len(visible)
        more = end < len(self.evidence_rows)
        return OwnerPage(
            items=visible,
            next_cursor=f"{prefix}{end}" if more else None,
            has_more=more,
        )


def _marked_href(body: str, marker: str) -> str | None:
    if marker not in body:
        return None
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)].replace("&amp;", "&")


def _marked_ids(body: str, marker: str) -> tuple[str, ...]:
    return tuple(item.split('"', 1)[0] for item in body.split(marker)[1:])


def test_source_relationships_page_independently_and_preserve_content_state() -> None:
    """Catch sibling/evidence relationships truncating or exchanging cursors."""
    service = PagedRelationshipService()
    ui = _authenticated_ui(service)
    content_cursor = "byte-at-65536"
    url: str | None = f"/sources/{BINARY_SOURCE_ID}?cursor={content_cursor}"
    siblings: list[str] = []
    sibling_pages = 0
    while url is not None:
        page = ui.client.get(url)
        assert page.status_code == 200
        assert len(page.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
        assert _hex_from_page(page.text) == service.binary[65_536:131_072]
        siblings.extend(_marked_ids(page.text, 'data-sibling-id="'))
        sibling_pages += 1
        url = _marked_href(page.text, 'data-next-siblings href="')
        if url is not None:
            assert f"cursor={content_cursor}" in url
    assert tuple(siblings) == tuple(row.source_id for row in service.sibling_rows)
    assert sibling_pages == 3

    url = f"/sources/{BINARY_SOURCE_ID}?cursor={content_cursor}"
    evidence: list[str] = []
    evidence_pages = 0
    while url is not None:
        page = ui.client.get(url)
        assert page.status_code == 200
        assert len(page.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
        assert _hex_from_page(page.text) == service.binary[65_536:131_072]
        evidence.extend(_marked_ids(page.text, 'data-evidence-id="'))
        evidence_pages += 1
        url = _marked_href(page.text, 'data-next-evidence href="')
        if url is not None:
            assert f"cursor={content_cursor}" in url
    assert tuple(evidence) == tuple(
        row.memory_revision_id for row in service.evidence_rows
    )
    assert evidence_pages == 3

    first = ui.client.get(f"/sources/{BINARY_SOURCE_ID}?cursor={content_cursor}")
    evidence_url = _marked_href(first.text, 'data-next-evidence href="')
    capture_url = _marked_href(first.text, 'data-next-siblings href="')
    assert evidence_url is not None and capture_url is not None
    evidence_cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(evidence_url).query)[
        "evidence_cursor"
    ][0]
    capture_cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(capture_url).query)[
        "capture_cursor"
    ][0]
    exchanged = ui.client.get(
        f"/sources/{BINARY_SOURCE_ID}?capture_cursor={urllib.parse.quote(evidence_cursor)}"
    )
    crossed_source = ui.client.get(
        f"/sources/{PNG_SOURCE_ID}?capture_cursor={urllib.parse.quote(capture_cursor)}"
    )
    assert exchanged.status_code in {400, 409}
    assert crossed_source.status_code in {400, 409}
    assert evidence_cursor not in exchanged.text
    assert capture_cursor not in crossed_source.text


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ([("kind", "event")], MemoryFilters(kinds=(MemoryKind.EVENT,))),
        (
            [("tag", "synthetic"), ("tag", "event")],
            MemoryFilters(tags_all=("synthetic", "event")),
        ),
        (
            [("occurred_from", "2034-01"), ("occurred_to", "2035-12-31")],
            MemoryFilters(occurred_from="2034-01", occurred_to="2035-12-31"),
        ),
        (
            [("sensitivity", "normal"), ("sensitivity", "restricted")],
            MemoryFilters(sensitivities=(Sensitivity.NORMAL, Sensitivity.RESTRICTED)),
        ),
        (
            [
                ("kind", "preference"),
                ("tag", "synthetic"),
                ("occurred_from", "2034"),
                ("occurred_to", "2034-12"),
                ("sensitivity", "restricted"),
            ],
            MemoryFilters(
                kinds=(MemoryKind.PREFERENCE,),
                tags_all=("synthetic",),
                occurred_from="2034",
                occurred_to="2034-12",
                sensitivities=(Sensitivity.RESTRICTED,),
            ),
        ),
    ],
)
def test_memory_search_normalizes_every_filter_dimension_and_discloses_hidden_count(
    fields: list[tuple[str, str]],
    expected: MemoryFilters,
) -> None:
    """Catch an accepted MemoryFilters dimension being dropped or silently hiding rows."""
    ui = _authenticated_ui()
    submitted = ui.post_form(
        "/memory/search",
        [("query", "synthetic memory"), *fields],
    )
    assert submitted.status_code == 303
    location = submitted.headers["location"]
    assert "synthetic" not in location
    assert all(value not in location for _name, value in fields)

    response = ui.client.get(location)
    assert response.status_code == 200
    assert ui.service.last_memory_query == "synthetic memory"
    assert ui.service.last_memory_filters == expected
    assert "1 result hidden by active filters" in response.text
    for _name, value in fields:
        assert value in response.text
    assert response.text.count("data-remove-filter") == len(fields)


def test_search_handle_is_session_owned_expires_and_survives_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch private filters entering URLs or opaque handles crossing sessions/lifetimes."""
    ui = _authenticated_ui()
    submitted = ui.post_form("/memory/search", [("query", "synthetic")])
    location = submitted.headers["location"]
    handle_path = urllib.parse.urlsplit(location).path
    first = ui.client.get(location + "?limit=1")
    assert first.status_code == 200
    assert handle_path in first.text
    assert "cursor=memory-at-1" in first.text
    assert "synthetic" not in str(first.url)

    other = _authenticated_ui(ui.service)
    assert other.client.get(location).status_code == 404

    routes = importlib.import_module("memory.ui.routes.memories")
    future = time.monotonic_ns() + 600_000_000_001
    monkeypatch.setattr(routes.time, "monotonic_ns", lambda: future)
    assert ui.client.get(location).status_code == 404


def test_historical_memory_shows_complete_lineage_evidence_and_application_navigation() -> (
    None
):
    """Catch historical inspection losing current-head or exact provenance links."""
    ui = _authenticated_ui()
    response = ui.client.get(f"/memories/{OLD_MEMORY_ID}")

    assert response.status_code == 200
    assert "<b>Synthetic" not in response.text
    assert "&lt;b&gt;Synthetic historical interpretation.&lt;/b&gt;" in response.text
    assert OLD_MEMORY_ID in response.text
    assert CURRENT_MEMORY_ID in response.text
    assert "蓝色纸灯" in response.text
    assert f'href="/sources/{TEXT_SOURCE_ID}"' in response.text
    assert f'href="/audit/applications/{APPLICATION_ID}"' in response.text
    assert f'href="/audit/approvals/{APPROVAL_ID}"' in response.text
    assert (
        f'href="/reviews/{CHANGE_SET_ID}/revisions/{CHANGE_REVISION_ID}"'
        in response.text
    )
    assert "Evidence mode" in response.text
    assert "Character range" in response.text
    assert "Evidence blob digest" in response.text
    assert response.text.index(OLD_MEMORY_ID) < response.text.rindex(CURRENT_MEMORY_ID)
    assert "Historical revision" in response.text


def test_memory_pages_use_a_controlled_date_for_applicability_and_open_loops() -> None:
    """Catch revision status being conflated with validity or a revisit horizon."""
    clock_date = date(2034, 6, 15)
    ordinary = SyntheticInspectionService()
    ordinary.current_memory = replace(
        ordinary.current_memory,
        revision=replace(
            ordinary.current_memory.revision,
            valid_from="2035",
            valid_to=None,
        ),
    )
    ordinary_ui = _authenticated_ui(ordinary, today=clock_date)

    listing = ordinary_ui.client.get("/memory")
    detail = ordinary_ui.client.get(f"/memories/{CURRENT_MEMORY_ID}")
    historical = ordinary_ui.client.get(f"/memories/{OLD_MEMORY_ID}")

    assert listing.status_code == detail.status_code == historical.status_code == 200
    assert "Recorded information takes effect in 2035." in listing.text
    assert "No end date recorded" in listing.text
    assert "Current revision" in detail.text
    assert "Revision status and applicability are separate." in detail.text
    assert "The recorded validity period ended 2033-12-31." in historical.text
    technical = detail.text.partition("Technical details")[2]
    assert "No end date recorded" in technical
    assert ">Current<" not in technical

    loop = SyntheticInspectionService()
    loop.current_memory = replace(
        loop.current_memory,
        revision=replace(
            loop.current_memory.revision,
            valid_from="2034-01",
            valid_to="2034-05",
            tags=("synthetic", "loop:open"),
        ),
    )
    loop_ui = _authenticated_ui(loop, today=clock_date)
    loop_detail = loop_ui.client.get(f"/memories/{CURRENT_MEMORY_ID}")

    assert loop_detail.status_code == 200
    assert "Open loop. Revisit is due; its horizon is 2034-05." in loop_detail.text
    assert "Revisit horizon 2034-05" in loop_detail.text
    assert "expired" not in loop_detail.text.lower()


class PagedLineageService(SyntheticInspectionService):
    OTHER_LINEAGE_ID = "lin_22222222222222222222222222222222"

    def __init__(self) -> None:
        super().__init__()
        count = 5 * UI_MEMORY_PAGE_LIMIT
        self.lineage_rows = tuple(
            OwnerMemorySummary(
                revision=MemorySummary(
                    memory_id=f"mem_{index + 4000:032x}",
                    lineage_id=LINEAGE_ID,
                    kind=MemoryKind.INSIGHT,
                    statement="&" * 16_384,
                    occurred_on="9999-12-31",
                    valid_from="9999-12-31",
                    valid_to=None if index == count else "9999-12-31",
                    tags=tuple("&" * 256 for _ in range(64)),
                    stored_sensitivity=Sensitivity.RESTRICTED,
                    effective_sensitivity=Sensitivity.RESTRICTED,
                    recorded_at=1_990_001_000 + index,
                ),
                is_current=index == count,
                current_head_id=f"mem_{count + 4000:032x}",
                predecessor_id=(None if index == 0 else f"mem_{index + 3999:032x}"),
                application_id=APPLICATION_ID,
                application_ordinal=index,
            )
            for index in range(count + 1)
        )

    def get_memory_revision(
        self,
        memory_id: str,
        *,
        guards_cursor: str | None = None,
        governs_cursor: str | None = None,
    ) -> OwnerMemoryDetail:
        detail = super().get_memory_revision(
            memory_id, guards_cursor=guards_cursor, governs_cursor=governs_cursor
        )
        if memory_id != EVENT_MEMORY_ID:
            return detail
        original = detail.summary.revision
        alternate_revision = MemorySummary(
            memory_id=original.memory_id,
            lineage_id=self.OTHER_LINEAGE_ID,
            kind=original.kind,
            statement=original.statement,
            occurred_on=original.occurred_on,
            valid_from=original.valid_from,
            valid_to=original.valid_to,
            tags=original.tags,
            stored_sensitivity=original.stored_sensitivity,
            effective_sensitivity=original.effective_sensitivity,
            recorded_at=original.recorded_at,
        )
        alternate_summary = OwnerMemorySummary(
            revision=alternate_revision,
            is_current=True,
            current_head_id=original.memory_id,
            predecessor_id=None,
            application_id=detail.summary.application_id,
            application_ordinal=detail.summary.application_ordinal,
        )
        return OwnerMemoryDetail(
            summary=alternate_summary,
            change_set_id=detail.change_set_id,
            change_set_revision_id=detail.change_set_revision_id,
            approval_id=detail.approval_id,
            evidence=detail.evidence,
        )

    def list_memory_lineage(
        self,
        lineage_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerMemorySummary]:
        prefix = f"lineage:{lineage_id}:"
        if cursor is None:
            start = 0
        elif not cursor.startswith(prefix):
            raise StaleCursorError("synthetic lineage cursor is not bound")
        else:
            start = int(cursor.removeprefix(prefix))
        rows = self.lineage_rows if lineage_id == LINEAGE_ID else (self.event_memory,)
        visible = rows[start : start + limit]
        end = start + len(visible)
        more = end < len(rows)
        return OwnerPage(
            items=visible,
            next_cursor=f"{prefix}{end}" if more else None,
            has_more=more,
        )


@pytest.mark.parametrize(
    "raw_limit",
    [
        pytest.param("²", id="non-decimal-digit"),
        pytest.param("9" * 5_000, id="oversized-integer"),
    ],
)
def test_memory_lineage_refuses_unconvertible_numeric_limits(raw_limit: str) -> None:
    """Catch malformed lineage pagination becoming an internal server error."""
    ui = _authenticated_ui()

    response = ui.client.get(
        f"/memories/{OLD_MEMORY_ID}", params={"lineage_limit": raw_limit}
    )

    assert response.status_code == 400
    assert response.text == "Request unavailable"
    assert response.headers["cache-control"] == "no-store"


def test_large_memory_lineage_is_one_bounded_cursor_page_per_response() -> None:
    """Catch memory detail accumulating an unbounded lineage before rendering."""
    service = PagedLineageService()
    ui = _authenticated_ui(service)
    url: str | None = f"/memories/{OLD_MEMORY_ID}?lineage_limit={UI_MEMORY_PAGE_LIMIT}"
    recovered: list[str] = []
    response_count = 0
    first_next: str | None = None
    while url is not None:
        page = ui.client.get(url)
        assert page.status_code == 200
        assert len(page.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
        recovered.extend(_marked_ids(page.text, 'data-lineage-id="'))
        response_count += 1
        url = _marked_href(page.text, 'data-next-lineage href="')
        if response_count == 1:
            first_next = url
        if url is not None:
            assert f"lineage_limit={UI_MEMORY_PAGE_LIMIT}" in url
    assert tuple(recovered) == tuple(
        row.revision.memory_id for row in service.lineage_rows
    )
    assert response_count == 6
    assert first_next is not None

    lineage_cursor = urllib.parse.parse_qs(urllib.parse.urlsplit(first_next).query)[
        "lineage_cursor"
    ][0]
    crossed = ui.client.get(
        f"/memories/{EVENT_MEMORY_ID}?lineage_cursor={urllib.parse.quote(lineage_cursor)}"
    )
    stale = ui.client.get(
        f"/memories/{OLD_MEMORY_ID}?lineage_cursor=stale-lineage-cursor"
    )
    assert crossed.status_code in {400, 409}
    assert stale.status_code in {400, 409}
    assert lineage_cursor not in crossed.text
    assert "stale-lineage-cursor" not in stale.text


class MaximumRowService(SyntheticInspectionService):
    def __init__(self) -> None:
        super().__init__()
        maximum_source = _source_summary(
            NORMAL_SOURCE_ID,
            sensitivity=Sensitivity.RESTRICTED,
            name="&" * 255,
        )
        maximum_memory = _memory_summary(
            CURRENT_MEMORY_ID,
            statement="&" * 16_384,
            kind=MemoryKind.INSIGHT,
            sensitivity=Sensitivity.RESTRICTED,
            occurred_on="9999-12-31",
            tags=tuple("&" * 256 for _ in range(64)),
            is_current=True,
            predecessor_id=OLD_MEMORY_ID,
        )
        self.maximum_source = maximum_source
        self.maximum_memory = maximum_memory

    def list_sources(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerSourceSummary]:
        if cursor is None:
            return OwnerPage(
                items=tuple(self.maximum_source for _ in range(limit)),
                next_cursor="source-final-row",
                has_more=True,
            )
        return OwnerPage(items=(self.maximum_source,), next_cursor=None, has_more=False)

    def list_memories(
        self,
        cursor: str | None,
        limit: int,
        filters: MemoryFilters,
    ) -> OwnerMemorySearchPage:
        count = limit if cursor is None else 1
        return OwnerMemorySearchPage(
            items=tuple(self.maximum_memory for _ in range(count)),
            next_cursor="memory-final-row" if cursor is None else None,
            has_more=cursor is None,
            filters=filters,
            unfiltered_query_match_count=limit + 1,
            filtered_match_count=limit + 1,
            hidden_by_filters_count=0,
            projection_coverage=self.status.projections.memories,
        )


def test_real_maximum_rows_fit_derived_html_pages_and_one_more_is_continued() -> None:
    """Catch maximum valid source/memory rows overflowing the standard page cap."""
    service = MaximumRowService()
    ui = _authenticated_ui(service)

    source_page = ui.client.get("/sources")
    source_final = ui.client.get("/sources?cursor=source-final-row")
    memory_page = ui.client.get("/memory")
    memory_final = ui.client.get("/memory?cursor=memory-final-row")

    assert source_page.status_code == 200
    assert len(source_page.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert source_page.text.count("data-source-row") == UI_STANDARD_PAGE_LIMIT
    assert source_final.text.count("data-source-row") == 1
    assert memory_page.status_code == 200
    assert len(memory_page.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert memory_page.text.count("data-memory-row") == UI_MEMORY_PAGE_LIMIT
    assert memory_final.text.count("data-memory-row") == 1


class _SyntheticClock:
    def __init__(self) -> None:
        self.timestamp = 2_010_000_000.0

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


@dataclass(frozen=True, slots=True)
class RealInspectionStore:
    service: OwnerApplicationService
    declared_source_ids: dict[Sensitivity, str]
    duplicate_source_ids: tuple[str, str]
    media_source_ids: tuple[str, ...]
    old_memory_id: str
    current_memory_id: str
    event_memory_id: str
    evidence_excerpt: str


def _capture_real_batch(
    paths: Any,
    clock: _SyntheticClock,
    files: dict[str, bytes],
    sensitivity: Sensitivity,
) -> tuple[str, tuple[OwnerSourceSummary, ...]]:
    for name, value in files.items():
        (paths.inbox / name).write_bytes(value)
    batch = scan_inbox(
        paths,
        sensitivity=sensitivity,
        clock=clock,
        policy=ScanPolicy(settle_seconds=0),
    )
    detail = OwnerApplicationService(paths).get_batch(batch.batch_id)
    return batch.batch_id, detail.sources


def _apply_real_memory(
    paths: Any,
    *,
    batch_id: str,
    source: OwnerSourceSummary,
    item_id: str,
    statement: str,
    excerpt: str,
    kind: MemoryKind,
    occurred_on: str,
    tags: tuple[str, ...],
    sensitivity: Sensitivity,
    target_lineage_id: str | None = None,
    expected_head_id: str | None = None,
) -> str:
    initial = create_change_set(
        paths,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        paths,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id=item_id,
                memory=MemoryFields(
                    kind=kind,
                    statement=statement,
                    occurred_on=occurred_on,
                    valid_from=occurred_on,
                    valid_to=None,
                    tags=tags,
                    sensitivity=sensitivity,
                    target_lineage_id=target_lineage_id,
                    expected_head_id=expected_head_id,
                ),
                evidence=(
                    model.EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt=excerpt,
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    applied = approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval,
    )
    return applied.memory_ids[0]


@pytest.fixture
def real_inspection_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RealInspectionStore]:
    """Build only freshly authored synthetic all-sensitivity inspection state."""
    backend = type("Keyring", (), {})()
    type(backend).__module__ = "keyring.backends.macOS"
    items: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    monkeypatch.setattr(
        keyring,
        "get_password",
        lambda service, account: items.get((service, account)),
    )

    def set_password(service: str, account: str, value: str) -> None:
        base64.b64decode(value, validate=True)
        items[(service, account)] = value

    monkeypatch.setattr(keyring, "set_password", set_password)
    monkeypatch.setattr(
        keys,
        "_store_master_key_exclusive",
        lambda identity, encoded: store_synthetic_key_exclusive(
            items, identity, encoded
        ),
    )
    paths = resolve_runtime(tmp_path / "synthetic-task-four-inspection-store")
    initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    clock = _SyntheticClock()
    declared: dict[Sensitivity, str] = {}
    bodies = {
        Sensitivity.NORMAL: b"synthetic-inspection-marker normal route-visible source\n",
        Sensitivity.SENSITIVE: (
            "synthetic-inspection-marker 敏感的合成来源\n"
        ).encode(),
        Sensitivity.RESTRICTED: b"synthetic-inspection-marker restricted route-visible source\n",
    }
    for sensitivity, body in bodies.items():
        _batch, sources = _capture_real_batch(
            paths,
            clock,
            {f"{sensitivity.value}-inspection.txt": body},
            sensitivity,
        )
        declared[sensitivity] = sources[0].source_id

    duplicate_body = b"Synthetic duplicate capture bytes remain distinct.\n"
    _batch, first_duplicate = _capture_real_batch(
        paths,
        clock,
        {"duplicate-normal.txt": duplicate_body},
        Sensitivity.NORMAL,
    )
    _batch, second_duplicate = _capture_real_batch(
        paths,
        clock,
        {"duplicate-restricted.bin": duplicate_body},
        Sensitivity.RESTRICTED,
    )
    media_files = {
        "canonical.png": _image_bytes("PNG"),
        "canonical.jpeg": _image_bytes("JPEG"),
        "canonical.webp": _image_bytes("WEBP"),
        "external-action.pdf": _pdf_bytes(
            pages=1,
            external_uri="https://synthetic.invalid/external-action",
        ),
        "unknown.bin": bytes(range(256)) * 600,
    }
    _media_batch, media_sources = _capture_real_batch(
        paths,
        clock,
        media_files,
        Sensitivity.RESTRICTED,
    )

    first_memory_batch, first_memory_sources = _capture_real_batch(
        paths,
        clock,
        {"historical-evidence.md": "合成证据：蓝色纸灯原先在周四开放。\n".encode()},
        Sensitivity.SENSITIVE,
    )
    evidence_excerpt = "蓝色纸灯原先在周四开放"
    old_memory_id = _apply_real_memory(
        paths,
        batch_id=first_memory_batch,
        source=first_memory_sources[0],
        item_id="synthetic-historical-item",
        statement="蓝色纸灯原先在周四开放。",
        excerpt=evidence_excerpt,
        kind=MemoryKind.PREFERENCE,
        occurred_on="2036-04",
        tags=("synthetic", "paper-lamp"),
        sensitivity=Sensitivity.SENSITIVE,
    )
    old_detail = OwnerApplicationService(paths).get_memory_revision(old_memory_id)
    correction_batch, correction_sources = _capture_real_batch(
        paths,
        clock,
        {
            "current-evidence.md": b"Synthetic correction: the blue paper lamp opens Friday.\n"
        },
        Sensitivity.RESTRICTED,
    )
    current_memory_id = _apply_real_memory(
        paths,
        batch_id=correction_batch,
        source=correction_sources[0],
        item_id="synthetic-current-item",
        statement="The blue paper lamp opens Friday.",
        excerpt="the blue paper lamp opens Friday",
        kind=MemoryKind.PREFERENCE,
        occurred_on="2037-05-06",
        tags=("synthetic", "paper-lamp", "current"),
        sensitivity=Sensitivity.RESTRICTED,
        target_lineage_id=old_detail.summary.revision.lineage_id,
        expected_head_id=old_memory_id,
    )
    event_batch, event_sources = _capture_real_batch(
        paths,
        clock,
        {"event-evidence.txt": b"Synthetic event happens in the amber studio.\n"},
        Sensitivity.NORMAL,
    )
    event_memory_id = _apply_real_memory(
        paths,
        batch_id=event_batch,
        source=event_sources[0],
        item_id="synthetic-event-item",
        statement="A synthetic event happens in the amber studio.",
        excerpt="Synthetic event happens in the amber studio",
        kind=MemoryKind.EVENT,
        occurred_on="2038-06",
        tags=("synthetic", "event"),
        sensitivity=Sensitivity.NORMAL,
    )

    yield RealInspectionStore(
        service=OwnerApplicationService(paths),
        declared_source_ids=declared,
        duplicate_source_ids=(
            first_duplicate[0].source_id,
            second_duplicate[0].source_id,
        ),
        media_source_ids=tuple(source.source_id for source in media_sources),
        old_memory_id=old_memory_id,
        current_memory_id=current_memory_id,
        event_memory_id=event_memory_id,
        evidence_excerpt=evidence_excerpt,
    )


def test_real_store_search_and_source_detail_preserve_all_sensitivity_and_captures(
    real_inspection_store: RealInspectionStore,
) -> None:
    """Catch route fakes masking Store sensitivity or byte-dedup provenance behavior."""
    ui = _authenticated_ui(real_inspection_store.service)  # type: ignore[arg-type]
    search = ui.search_sources("synthetic-inspection-marker")
    assert search.status_code == 200
    for sensitivity in Sensitivity:
        assert f'data-sensitivity="{sensitivity.value}"' in search.text
        assert real_inspection_store.declared_source_ids[sensitivity] in search.text

    first, second = real_inspection_store.duplicate_source_ids
    detail = ui.client.get(f"/sources/{first}")
    assert detail.status_code == 200
    assert first in detail.text
    assert second in detail.text
    assert "normal" in detail.text
    assert "restricted" in detail.text


def test_real_store_historical_memory_and_filter_paths_are_complete(
    real_inspection_store: RealInspectionStore,
) -> None:
    """Catch template-only lineage/filter tests diverging from owner-service cursors."""
    ui = _authenticated_ui(real_inspection_store.service)  # type: ignore[arg-type]
    historical = ui.client.get(
        f"/memories/{real_inspection_store.old_memory_id}?lineage_limit=1"
    )
    assert historical.status_code == 200
    assert real_inspection_store.evidence_excerpt in historical.text
    lineage_ids = list(_marked_ids(historical.text, 'data-lineage-id="'))
    next_lineage = _marked_href(historical.text, 'data-next-lineage href="')
    assert next_lineage is not None
    current = ui.client.get(next_lineage)
    assert current.status_code == 200
    lineage_ids.extend(_marked_ids(current.text, 'data-lineage-id="'))
    assert lineage_ids == [
        real_inspection_store.old_memory_id,
        real_inspection_store.current_memory_id,
    ]
    assert _marked_href(current.text, 'data-next-lineage href="') is None

    submitted = ui.post_form(
        "/memory/search",
        [
            ("query", "synthetic"),
            ("kind", "event"),
            ("tag", "synthetic"),
            ("occurred_from", "2038"),
            ("occurred_to", "2038-12"),
            ("sensitivity", "normal"),
        ],
    )
    assert submitted.status_code == 303
    result = ui.client.get(submitted.headers["location"])
    assert result.status_code == 200
    assert real_inspection_store.event_memory_id in result.text
    assert real_inspection_store.current_memory_id not in result.text
    assert "1 result hidden by active filters" in result.text


def test_source_search_handle_is_session_owned_expiring_and_pagination_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch source query text leaking or a handle crossing session/expiry boundaries."""
    ui = _authenticated_ui()
    submitted = ui.post_form(
        "/sources/search",
        [("query", "synthetic-private-source")],
    )
    assert submitted.status_code == 303
    location = submitted.headers["location"]
    assert "synthetic-private-source" not in location
    first = ui.client.get(location + "?limit=1")
    assert first.status_code == 200
    assert urllib.parse.urlsplit(location).path in first.text
    assert "cursor=search-page-two" in first.text

    other = _authenticated_ui(ui.service)
    assert other.client.get(location).status_code == 404
    routes = importlib.import_module("memory.ui.routes.sources")
    future = time.monotonic_ns() + 600_000_000_001
    monkeypatch.setattr(
        routes.time,
        "monotonic_ns",
        lambda: future,
    )
    assert ui.client.get(location).status_code == 404


@pytest.mark.parametrize(
    ("path", "fields"),
    [
        ("/sources/search", [("query", "one"), ("query", "two")]),
        ("/sources/search", [("query", "synthetic"), ("unknown", "value")]),
        ("/memory/search", [("query", "synthetic"), ("kind", "not-a-kind")]),
        (
            "/memory/search",
            [("query", "synthetic"), *[("tag", f"tag-{index}") for index in range(65)]],
        ),
    ],
)
def test_search_forms_reject_ambiguous_unknown_or_out_of_bounds_fields(
    path: str,
    fields: list[tuple[str, str]],
) -> None:
    """Catch form structural expansion or duplicate singleton ambiguity."""
    ui = _authenticated_ui()
    response = ui.post_form(path, fields)

    assert response.status_code == 400
    assert "one" not in response.text
    assert "two" not in response.text
    assert "not-a-kind" not in response.text


def test_blank_optional_memory_tag_is_ignored_after_bounded_form_parsing() -> None:
    """Catch the rendered empty optional tag field making normal search unusable."""
    ui = _authenticated_ui()
    response = ui.post_form(
        "/memory/search",
        [("query", "synthetic"), ("tag", "")],
    )

    assert response.status_code == 303


def test_rendered_search_forms_use_real_browser_csrf_post_transport() -> None:
    """Catch forms that only pass tests with a manually injected CSRF header."""
    ui = _authenticated_ui()
    sources = ui.client.get("/sources")
    memories = ui.client.get("/memory")
    script = ui.client.get("/static/ui.js")

    assert "data-authenticated-post" in sources.text
    assert "data-authenticated-post" in memories.text
    assert script.status_code == 200
    assert 'querySelector("meta[name=memory-csrf]")' in script.text
    assert '"X-Memory-CSRF"' in script.text
    assert "new URLSearchParams(new FormData(form))" in script.text
    assert "window.location.assign(response.url)" in script.text
    for kind in MemoryKind:
        assert f'name="kind" value="{kind.value}"' in memories.text
    assert 'name="kind" value="goal"' not in memories.text


def test_preview_work_runs_off_the_single_asgi_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch blocking render work serializing requests before the shared gate."""
    media = importlib.import_module("memory.ui.media_preview")
    source_routes = importlib.import_module("memory.ui.routes.sources")
    service = SyntheticInspectionService()
    bootstrap = "synthetic-async-bootstrap"
    sessions = UiSessionStore(
        bootstrap_capability=bootstrap,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    app = create_ui_app(
        # Deliberately partial, exactly as `_authenticated_ui` casts it: this
        # fake answers only the `OwnerUiService` members the preview route
        # reaches, and this test reaches nothing but that route.
        cast("OwnerUiService", service),
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    entered = threading.Barrier(3)
    release = threading.Event()

    def blocked(_source: bytes, **_options: object) -> Any:
        entered.wait(timeout=2)
        release.wait(timeout=2)
        return media.ImagePreview(
            width=1,
            height=1,
            png_bytes=_image_bytes("PNG", metadata=False),
        )

    monkeypatch.setattr(
        source_routes,
        "_render_image_preview_with_cancellation",
        blocked,
    )

    async def exercise() -> tuple[int, int]:
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url=PUBLIC_ORIGIN,
        ) as client:
            exchanged = await client.post(
                "/session",
                content=bootstrap,
                headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
                follow_redirects=False,
            )
            assert exchanged.status_code == 303
            first = asyncio.create_task(client.get(f"/sources/{PNG_SOURCE_ID}/preview"))
            second = asyncio.create_task(
                client.get(f"/sources/{JPEG_SOURCE_ID}/preview")
            )
            await asyncio.to_thread(entered.wait, 2)
            refused = await client.get(f"/sources/{WEBP_SOURCE_ID}/preview")
            release.set()
            completed = await asyncio.gather(first, second)
            return refused.status_code, sum(item.status_code for item in completed)

    refused_status, completed_statuses = asyncio.run(exercise())
    assert refused_status == 429
    assert completed_statuses == 400


class MaximumChunkService(SyntheticInspectionService):
    def __init__(self) -> None:
        super().__init__()
        self.text = b"&" * (262_144 + 1)
        self.binary = bytes(range(256)) * 257
        self.media[BINARY_SOURCE_ID] = (
            "application/octet-stream",
            self.binary,
            "maximum-window.bin",
        )
        self.sources[TEXT_SOURCE_ID] = _source_summary(
            TEXT_SOURCE_ID,
            sensitivity=Sensitivity.RESTRICTED,
            media_type="text/plain",
            name="maximum-text.txt",
            byte_length=len(self.text),
        )
        self.sources[BINARY_SOURCE_ID] = _source_summary(
            BINARY_SOURCE_ID,
            sensitivity=Sensitivity.RESTRICTED,
            media_type="application/octet-stream",
            name="maximum-window.bin",
            byte_length=len(self.binary),
        )


def test_worst_case_text_and_hex_pages_use_exact_route_chunk_budgets() -> None:
    """Catch worst-case escaping or hex expansion exceeding one bounded HTML page."""
    service = MaximumChunkService()
    ui = _authenticated_ui(service)
    text_first = ui.client.get(f"/sources/{TEXT_SOURCE_ID}")
    text_next = ui.client.get(_next_content_href(text_first.text) or "")
    binary_first = ui.client.get(f"/sources/{BINARY_SOURCE_ID}")
    binary_next = ui.client.get(_next_content_href(binary_first.text) or "")

    assert text_first.status_code == 200
    assert len(text_first.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert text_first.text.count("&amp;") >= 262_144
    assert "&amp;" in text_next.text
    assert binary_first.status_code == 200
    assert len(binary_first.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert _hex_from_page(binary_first.text) + _hex_from_page(binary_next.text) == (
        service.binary
    )
    assert all(
        max_bytes <= 262_144 if source_id == TEXT_SOURCE_ID else max_bytes <= 65_536
        for source_id, _cursor, max_bytes in service.read_calls
    )


def test_inspection_pages_are_semantic_keyboard_friendly_and_local_only() -> None:
    """Catch inspection controls losing labels/headings or introducing remote assets."""
    ui = _authenticated_ui()
    sources = ui.client.get("/sources")
    memories = ui.client.get("/memory")

    for response, heading in ((sources, "Sources"), (memories, "Memory")):
        assert response.status_code == 200
        assert "<h1" in response.text and heading in response.text
        assert "<label" in response.text
        assert "<form" in response.text
        assert "https://" not in response.text
        assert "http://" not in response.text
    assert 'aria-label="Source search"' in sources.text
    assert 'aria-label="Memory search and filters"' in memories.text
    assert "Effective sensitivity" in memories.text


DIGEST_TEXT = re.compile(r"[0-9a-f]{64}")


TECHNICAL_DISCLOSURE = '<details class="technical-details"'


@pytest.fixture
def guarded_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[model.RuntimePaths]:
    """Build one real store holding a claim and the guard that governs it."""
    yield from make_synthetic_store(tmp_path, monkeypatch)


def test_browsing_hides_every_digest_and_detail_discloses_them_once() -> None:
    """Catch identifiers leaking back onto browsing surfaces or out of disclosure."""
    ui = _authenticated_ui()
    listing = ui.client.get("/memory")
    detail = ui.client.get(f"/memories/{CURRENT_MEMORY_ID}")

    assert listing.status_code == 200
    assert DIGEST_TEXT.search(listing.text) is None
    assert detail.status_code == 200
    browsing, marker, disclosed = detail.text.partition(TECHNICAL_DISCLOSURE)
    assert marker == TECHNICAL_DISCLOSURE
    assert DIGEST_TEXT.search(browsing) is None
    assert DIGEST_TEXT.search(disclosed) is not None
    assert "Evidence blob digest" in disclosed


def test_disclosed_identifiers_carry_labelled_copy_actions() -> None:
    """Catch the disclosure losing the copy affordance or its accessible name."""
    ui = _authenticated_ui()
    detail = ui.client.get(f"/memories/{CURRENT_MEMORY_ID}")

    assert detail.status_code == 200
    assert f'data-copy-value="{CURRENT_MEMORY_ID}"' in detail.text
    assert 'aria-label="Copy Memory revision"' in detail.text
    assert 'aria-label="Copy Evidence blob digest"' in detail.text
    assert (
        'class="copy-announce visually-hidden" role="status" aria-live="polite"'
        in detail.text
    )


def test_reindex_requirement_reaches_the_owner_as_a_visible_banner() -> None:
    """Catch this branch's index upgrade staying invisible to the owner."""
    service = SyntheticInspectionService()
    ui = _authenticated_ui(service)

    quiet = ui.client.get("/memory")
    assert quiet.status_code == 200
    assert "Search index upgrade required" not in quiet.text

    service.status = replace(
        service.status,
        store=replace(service.status.store, reindex_required=True),
    )
    upgraded = ui.client.get("/memory")
    assert upgraded.status_code == 200
    assert "Search index upgrade required" in upgraded.text
    assert "memory reindex" in upgraded.text


def test_memory_detail_renders_guards_and_governs_from_the_store(
    guarded_store: model.RuntimePaths,
) -> None:
    """Catch owner detail dropping the guard relation the kernel already applies."""
    applied = two_source_linked_apply(guarded_store, FakeClock())
    claim_id, guard_id = applied.memory_ids[0], applied.memory_ids[1]
    service = OwnerApplicationService(guarded_store)
    guard_statement = "The daily-runs figure is self-reported and not verified."
    claim_statement = "The owner reports daily runs."

    claim = service.get_memory_revision(claim_id)
    guard = service.get_memory_revision(guard_id)
    assert [item.statement for item in claim.guards] == [guard_statement]
    assert [item.memory_id for item in claim.guards] == [guard_id]
    assert claim.governs == ()
    assert [item.statement for item in guard.governs] == [claim_statement]
    assert guard.guards == ()

    ui = _authenticated_ui(service)  # type: ignore[arg-type]
    claim_page = ui.client.get(f"/memories/{claim_id}")
    guard_page = ui.client.get(f"/memories/{guard_id}")

    assert claim_page.status_code == 200
    assert "Owner-approved caveats that govern this memory." in claim_page.text
    assert guard_statement in claim_page.text
    assert f'href="/memories/{guard_id}"' in claim_page.text
    assert "Governs" not in claim_page.text
    assert guard_page.status_code == 200
    assert ">Governs<" in guard_page.text
    assert claim_statement in guard_page.text
    assert "No owner-approved guard governs this memory." in guard_page.text


def test_memory_index_renders_kind_facets_as_filter_shortcuts(
    guarded_store: model.RuntimePaths,
) -> None:
    """Catch the kind facet row losing its counts or its filter submission."""
    two_source_linked_apply(guarded_store, FakeClock())
    service = OwnerApplicationService(guarded_store)
    ui = _authenticated_ui(service)  # type: ignore[arg-type]

    listing = ui.client.get("/memory")
    assert listing.status_code == 200
    assert listing.text.count("data-facet-kind") == 5
    assert 'value="insight"' in listing.text
    assert listing.text.count('action="/memory/search"') == 6

    submitted = ui.post_form("/memory/search", [("query", ""), ("kind", "insight")])
    assert submitted.status_code == 303
    filtered = ui.client.get(submitted.headers["location"])
    assert filtered.status_code == 200
    assert "self-reported and not verified" in filtered.text
    assert "The owner reports daily runs." not in filtered.text


def test_memory_time_filter_renders_one_fixed_local_minute() -> None:
    """Catch a relative or drifting timestamp reaching a rendered owner page."""
    app = importlib.import_module("memory.ui.app")
    previous = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        assert app.memory_time(1_785_969_660) == "2026-08-05 22:41"
        assert app.memory_time(0) == "1970-01-01 00:00"
        assert app.memory_time(None) == "not recorded"
        assert app.memory_time(True) == "not recorded"
        assert app.memory_time("1785969660") == "not recorded"
    finally:
        if previous is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = previous
        time.tzset()
    assert app.filesize(0) == "0 bytes"
    assert app.filesize(1) == "1 byte"
    assert app.filesize(1023) == "1023 bytes"
    assert app.filesize(1536) == "1.5 KB"
    assert app.filesize(5 * 1024 * 1024) == "5 MB"
    assert app.filesize(-1) == "unknown size"
