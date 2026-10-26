"""Scaffolding both owner-inspection suites are built on.

One synthetic service, one authenticated client, and the fixed synthetic
identifiers the assertions name. It exists because the media and PDF tests
moved into their own module and reach the same scaffolding the source and
memory inspection tests do -- so the alternative was a second copy of a
382-line fake, which is how two suites start disagreeing about what the Store
returned.

Not a test module: pytest does not collect it.
"""

import asyncio
import io
import time
import urllib.parse
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, cast

from PIL import Image, PngImagePlugin
from pypdf import PdfWriter
from pypdf.generic import (
    DictionaryObject,
    NameObject,
    TextStringObject,
)
from starlette.testclient import TestClient
from ui_support import build_test_orchestrator

from memory.errors import StaleCursorError
from memory.graph import StoreGraph
from memory.model import (
    Authorship,
    EvidenceLocator,
    MemoryFilters,
    MemoryKind,
    MemorySummary,
    RuntimeMode,
    Sensitivity,
    SourceCaptureOrigin,
    StoreStatus,
    UiSession,
)
from memory.ui.app import OwnerUiService, create_ui_app
from memory.ui.auth import UiSessionStore
from memory.ui.view_models import (
    InboxStatus,
    MemoryProjectionCoverage,
    OwnerEvidenceLink,
    OwnerMemoryDetail,
    OwnerMemorySearchPage,
    OwnerMemorySummary,
    OwnerPage,
    OwnerSourceChunk,
    OwnerSourceDetail,
    OwnerSourceSearchHit,
    OwnerSourceSearchPage,
    OwnerSourceSummary,
    OwnerStatus,
    ProjectionCoverage,
    SourceProjectionCoverage,
)

PUBLIC_ORIGIN = "http://memory-22222222222222222222222222222222.localhost:43210"


EXACT_HOST = "memory-22222222222222222222222222222222.localhost:43210"


CANCELLED_WORKER_TIMEOUT_SECONDS = 10.0


MAX_CANCELLED_RETURN_SECONDS = CANCELLED_WORKER_TIMEOUT_SECONDS / 2


class _UnusedFinder:
    def reveal_directory_url(self, _directory_url: object) -> None:
        raise AssertionError("inspection routes must not reveal a directory")


def _image_bytes(
    image_format: str,
    *,
    size: tuple[int, int] = (37, 23),
    metadata: bool = True,
) -> bytes:
    image = Image.new("RGB", size, (31, 109, 173))
    output = io.BytesIO()
    options: dict[str, object] = {}
    if metadata and image_format == "PNG":
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("SyntheticComment", "strip this synthetic metadata")
        options["pnginfo"] = png_info
        options["icc_profile"] = b"synthetic-icc-profile"
    elif metadata and image_format in {"JPEG", "WEBP"}:
        exif = Image.Exif()
        exif[0x010E] = "strip this synthetic metadata"
        options["exif"] = exif
        options["icc_profile"] = b"synthetic-icc-profile"
        if image_format == "WEBP":
            options["xmp"] = b"<synthetic-xmp>strip</synthetic-xmp>"
    image.save(output, format=image_format, **options)
    return output.getvalue()


def _pdf_bytes(*, pages: int, external_uri: str | None = None) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=96, height=64)
    if external_uri is not None:
        action = DictionaryObject(
            {
                NameObject("/S"): NameObject("/URI"),
                NameObject("/URI"): TextStringObject(external_uri),
            }
        )
        writer.pages[0][NameObject("/AA")] = DictionaryObject(
            {NameObject("/O"): action}
        )
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


async def _wait_for_pid(path: Path) -> int:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if path.exists():
            return int(path.read_text())
        await asyncio.sleep(0.01)
    raise AssertionError("synthetic media child did not report its pid")


TEXT_SOURCE_ID = "src_11111111111111111111111111111111"


NORMAL_SOURCE_ID = "src_22222222222222222222222222222222"


SENSITIVE_SOURCE_ID = "src_33333333333333333333333333333333"


RESTRICTED_SOURCE_ID = "src_44444444444444444444444444444444"


PNG_SOURCE_ID = "src_55555555555555555555555555555555"


JPEG_SOURCE_ID = "src_66666666666666666666666666666666"


WEBP_SOURCE_ID = "src_77777777777777777777777777777777"


PDF_SOURCE_ID = "src_88888888888888888888888888888888"


BINARY_SOURCE_ID = "src_99999999999999999999999999999999"


OLD_MEMORY_ID = "mem_11111111111111111111111111111111"


CURRENT_MEMORY_ID = "mem_22222222222222222222222222222222"


EVENT_MEMORY_ID = "mem_33333333333333333333333333333333"


MARKUP_TAG = "<script>alert('synthetic-tag')</script>"


LINEAGE_ID = "lin_11111111111111111111111111111111"


BATCH_ID = "bat_11111111111111111111111111111111"


APPLICATION_ID = "app_11111111111111111111111111111111"


CHANGE_SET_ID = "chg_11111111111111111111111111111111"


CHANGE_REVISION_ID = "rev_11111111111111111111111111111111"


APPROVAL_ID = "apr_11111111111111111111111111111111"


def _source_summary(
    source_id: str,
    *,
    sensitivity: Sensitivity,
    media_type: str = "text/plain",
    name: str = "synthetic-source.txt",
    blob_id: str | None = None,
    byte_length: int = 64,
) -> OwnerSourceSummary:
    return OwnerSourceSummary(
        source_id=source_id,
        blob_id=blob_id or f"blb_{source_id[4:]}",
        batch_id=BATCH_ID,
        batch_ordinal=0,
        origin=SourceCaptureOrigin.INBOX,
        blob_digest=(source_id[4:6] or "ab") * 32,
        original_name=name,
        media_type=media_type,
        byte_length=byte_length,
        authorship=Authorship.OWNER,
        declared_sensitivity=sensitivity,
        effective_sensitivity=sensitivity,
        expected_searchable=media_type.startswith("text/"),
        indexed_for_search=media_type.startswith("text/"),
        captured_at=1_990_000_000,
    )


def _memory_summary(
    memory_id: str,
    *,
    statement: str,
    kind: MemoryKind,
    sensitivity: Sensitivity,
    occurred_on: str | None,
    tags: tuple[str, ...],
    is_current: bool,
    predecessor_id: str | None,
) -> OwnerMemorySummary:
    return OwnerMemorySummary(
        revision=MemorySummary(
            memory_id=memory_id,
            lineage_id=LINEAGE_ID,
            kind=kind,
            statement=statement,
            occurred_on=occurred_on,
            valid_from="2034-01" if is_current else "2033-01",
            valid_to=None if is_current else "2033-12-31",
            tags=tags,
            stored_sensitivity=sensitivity,
            effective_sensitivity=sensitivity,
            recorded_at=1_990_000_100 if is_current else 1_990_000_000,
        ),
        is_current=is_current,
        current_head_id=CURRENT_MEMORY_ID,
        predecessor_id=predecessor_id,
        application_id=APPLICATION_ID,
        application_ordinal=0,
    )


class SyntheticInspectionService:
    def read_memory_neighbourhood(self, memory_id: str) -> StoreGraph:
        """This stub does not model the relation graph.

        An empty graph means the detail page skips its neighbourhood panel, so
        these tests keep asserting what they are about -- escaping, lineage
        paging, digest disclosure -- rather than the picture. The panel itself
        is covered by the browser journeys against a real Store.
        """
        return StoreGraph(
            nodes=(),
            edges=(),
            total_node_count=0,
            measured_node_count=0,
            within_ceiling=True,
            guard_links_available=True,
        )

    def __init__(self) -> None:
        self.text = (
            "<script>synthetic prompt must stay inert</script>\n"
            "合成记录：蓝色纸灯仍然可见。\n"
        ).encode()
        self.binary = bytes(range(256)) * 600
        self.media: dict[str, tuple[str, bytes, str]] = {
            PNG_SOURCE_ID: ("image/png", _image_bytes("PNG"), "synthetic-preview.png"),
            JPEG_SOURCE_ID: (
                "image/jpeg",
                _image_bytes("JPEG"),
                "synthetic-preview.jpeg",
            ),
            WEBP_SOURCE_ID: (
                "image/webp",
                _image_bytes("WEBP"),
                "synthetic-preview.webp",
            ),
            PDF_SOURCE_ID: (
                "application/pdf",
                _pdf_bytes(pages=1),
                "synthetic-preview.pdf",
            ),
            BINARY_SOURCE_ID: (
                "application/octet-stream",
                self.binary,
                "synthetic-unknown.bin",
            ),
        }
        shared_blob = "blb_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.sources = {
            TEXT_SOURCE_ID: _source_summary(
                TEXT_SOURCE_ID,
                sensitivity=Sensitivity.RESTRICTED,
                name="<script>synthetic-name</script>.md",
                media_type="text/markdown",
                blob_id=shared_blob,
                byte_length=len(self.text),
            ),
            NORMAL_SOURCE_ID: _source_summary(
                NORMAL_SOURCE_ID,
                sensitivity=Sensitivity.NORMAL,
                name="synthetic-normal.txt",
                blob_id=shared_blob,
            ),
            SENSITIVE_SOURCE_ID: _source_summary(
                SENSITIVE_SOURCE_ID,
                sensitivity=Sensitivity.SENSITIVE,
                name="synthetic-sensitive.txt",
            ),
            RESTRICTED_SOURCE_ID: _source_summary(
                RESTRICTED_SOURCE_ID,
                sensitivity=Sensitivity.RESTRICTED,
                name="synthetic-restricted.txt",
            ),
        }
        for source_id, (media_type, body, name) in self.media.items():
            self.sources[source_id] = _source_summary(
                source_id,
                sensitivity=Sensitivity.RESTRICTED,
                media_type=media_type,
                name=name,
                byte_length=len(body),
            )
        self.old_memory = _memory_summary(
            OLD_MEMORY_ID,
            statement="<b>Synthetic historical interpretation.</b>",
            kind=MemoryKind.PREFERENCE,
            sensitivity=Sensitivity.SENSITIVE,
            occurred_on="2033-04",
            tags=("synthetic", "historical"),
            is_current=False,
            predecessor_id=None,
        )
        self.current_memory = _memory_summary(
            CURRENT_MEMORY_ID,
            statement="Synthetic current interpretation with 蓝色纸灯.",
            kind=MemoryKind.PREFERENCE,
            sensitivity=Sensitivity.RESTRICTED,
            occurred_on="2034-05-06",
            tags=("synthetic", "current"),
            is_current=True,
            predecessor_id=OLD_MEMORY_ID,
        )
        self.event_memory = _memory_summary(
            EVENT_MEMORY_ID,
            statement="Synthetic event remains inspectable.",
            kind=MemoryKind.EVENT,
            sensitivity=Sensitivity.NORMAL,
            occurred_on="2035-06",
            tags=("synthetic", "event", MARKUP_TAG),
            is_current=True,
            predecessor_id=None,
        )
        self.last_memory_query: str | None = None
        self.last_memory_filters = MemoryFilters()
        self.read_calls: list[tuple[str, str | None, int]] = []
        source_coverage = SourceProjectionCoverage(
            total_captures=len(self.sources),
            expected_searchable_captures=4,
            indexed_expected_captures=4,
            missing_expected_rows=0,
            inherently_unsearchable_captures=len(self.sources) - 4,
            unexpected_or_duplicate_rows=0,
        )
        memory_coverage = MemoryProjectionCoverage(
            current_heads=2,
            indexed_current_heads=2,
            missing_current_head_rows=0,
            unexpected_or_duplicate_noncurrent_rows=0,
            historical_revisions_not_expected=1,
        )
        self.status = OwnerStatus(
            store=StoreStatus(
                product="memory",
                schema_version=1,
                store_id="a" * 32,
                source_count=len(self.sources),
                memory_count=2,
                searchable_count=4,
                unsearchable_count=len(self.sources) - 4,
                reindex_required=False,
                mcp_contract_digest="b" * 64,
                skill_digest="c" * 64,
                pending_review_count=0,
            ),
            runtime_mode=RuntimeMode.PERSONAL,
            availability="available",
            pending_review_count=0,
            projections=ProjectionCoverage(
                sources=source_coverage,
                memories=memory_coverage,
            ),
            runtime_display_path="Synthetic Store Home",
            inbox=InboxStatus(
                inbox_display_path="Synthetic Inbox",
                staged_visible_entry_count=0,
            ),
        )

    def get_status(self) -> OwnerStatus:
        return self.status

    def list_sources(
        self, cursor: str | None, limit: int
    ) -> OwnerPage[OwnerSourceSummary]:
        ordered = tuple(self.sources.values())
        start = 0 if cursor is None else int(cursor.removeprefix("source-at-"))
        visible = ordered[start : start + limit]
        next_offset = start + len(visible)
        has_more = next_offset < len(ordered)
        return OwnerPage(
            items=visible,
            next_cursor=f"source-at-{next_offset}" if has_more else None,
            has_more=has_more,
        )

    def search_sources(
        self,
        query: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerSourceSearchPage:
        del cursor
        selected = (
            self.sources[NORMAL_SOURCE_ID],
            self.sources[SENSITIVE_SOURCE_ID],
            self.sources[RESTRICTED_SOURCE_ID],
        )[:limit]
        return OwnerSourceSearchPage(
            items=tuple(
                OwnerSourceSearchHit(
                    source=source,
                    exact_excerpt=f"{query} remains synthetic and inert.",
                    rank=-1.0,
                )
                for source in selected
            ),
            next_cursor="search-page-two" if limit < 3 else None,
            has_more=limit < 3,
            coverage=self.status.projections.sources,
        )

    def get_source_detail(self, source_id: str) -> OwnerSourceDetail:
        summary = self.sources[source_id]
        return OwnerSourceDetail(
            summary=summary,
            retained_utf8_text=source_id
            in {
                TEXT_SOURCE_ID,
                NORMAL_SOURCE_ID,
                SENSITIVE_SOURCE_ID,
                RESTRICTED_SOURCE_ID,
            },
            blob_capture_count=2 if summary.blob_id.endswith("a" * 32) else 1,
            evidence_backlink_count=1 if source_id == TEXT_SOURCE_ID else 0,
        )

    def read_source(
        self,
        source_id: str,
        cursor: str | None,
        max_bytes: int,
    ) -> OwnerSourceChunk:
        self.read_calls.append((source_id, cursor, max_bytes))
        if cursor == "stale-cursor":
            raise StaleCursorError("synthetic stale source continuation")
        if source_id == TEXT_SOURCE_ID:
            body = self.text
            is_text = True
            media_type = "text/markdown"
        elif source_id in self.media:
            media_type, body, _name = self.media[source_id]
            is_text = False
        else:
            body = b"synthetic owner search source"
            media_type = "text/plain"
            is_text = True
        start = 0 if cursor is None else int(cursor.removeprefix("byte-at-"))
        end = min(len(body), start + max_bytes)
        complete = end == len(body)
        next_cursor = None if complete else f"byte-at-{end}"
        chunk = body[start:end]
        text = chunk.decode("utf-8") if is_text else None
        return OwnerSourceChunk(
            source_id=source_id,
            blob_digest=self.sources[source_id].blob_digest,
            media_type=media_type,
            text=text,
            binary=None if is_text else chunk,
            char_start=start if is_text else None,
            char_end=end if is_text else None,
            byte_start=start,
            byte_end=end,
            next_cursor=next_cursor,
            complete=complete,
        )

    def list_blob_captures(
        self,
        blob_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceSummary]:
        del cursor
        matches = tuple(
            source for source in self.sources.values() if source.blob_id == blob_id
        )[:limit]
        return OwnerPage(items=matches, next_cursor=None, has_more=False)

    def list_source_evidence_links(
        self,
        source_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerEvidenceLink]:
        del cursor, limit
        if source_id != TEXT_SOURCE_ID:
            return OwnerPage(items=(), next_cursor=None, has_more=False)
        locator = EvidenceLocator(
            ordinal=0,
            source_id=source_id,
            blob_digest=self.sources[source_id].blob_digest,
            mode="text",
            char_start=51,
            char_end=61,
            excerpt="蓝色纸灯",
            source_level=None,
        )
        return OwnerPage(
            items=(
                OwnerEvidenceLink(
                    memory_revision_id=CURRENT_MEMORY_ID,
                    lineage_id=LINEAGE_ID,
                    is_current=True,
                    locator=locator,
                ),
            ),
            next_cursor=None,
            has_more=False,
        )

    def list_memories(
        self,
        cursor: str | None,
        limit: int,
        filters: MemoryFilters,
    ) -> OwnerMemorySearchPage:
        return self._memory_page(None, filters, cursor, limit)

    def search_memories(
        self,
        query: str,
        filters: MemoryFilters,
        cursor: str | None,
        limit: int,
    ) -> OwnerMemorySearchPage:
        return self._memory_page(query, filters, cursor, limit)

    def _memory_page(
        self,
        query: str | None,
        filters: MemoryFilters,
        cursor: str | None,
        limit: int,
    ) -> OwnerMemorySearchPage:
        self.last_memory_query = query
        self.last_memory_filters = filters
        all_items = (self.current_memory, self.event_memory)
        start = 0 if cursor is None else int(cursor.removeprefix("memory-at-"))
        visible = all_items[start : start + limit]
        next_offset = start + len(visible)
        has_more = next_offset < len(all_items)
        hidden = 1 if filters != MemoryFilters() else 0
        return OwnerMemorySearchPage(
            items=visible,
            next_cursor=f"memory-at-{next_offset}" if has_more else None,
            has_more=has_more,
            filters=filters,
            unfiltered_query_match_count=len(all_items),
            filtered_match_count=len(all_items) - hidden,
            hidden_by_filters_count=hidden,
            projection_coverage=self.status.projections.memories,
        )

    def get_memory_revision(
        self,
        memory_id: str,
        *,
        guards_cursor: str | None = None,
        governs_cursor: str | None = None,
    ) -> OwnerMemoryDetail:
        if guards_cursor is not None or governs_cursor is not None:
            raise StaleCursorError("synthetic relationship continuation is unavailable")
        summary = {
            OLD_MEMORY_ID: self.old_memory,
            CURRENT_MEMORY_ID: self.current_memory,
            EVENT_MEMORY_ID: self.event_memory,
        }[memory_id]
        locator = EvidenceLocator(
            ordinal=0,
            source_id=TEXT_SOURCE_ID,
            blob_digest=self.sources[TEXT_SOURCE_ID].blob_digest,
            mode="text",
            char_start=51,
            char_end=61,
            excerpt="蓝色纸灯",
            source_level=None,
        )
        return OwnerMemoryDetail(
            summary=summary,
            change_set_id=CHANGE_SET_ID,
            change_set_revision_id=CHANGE_REVISION_ID,
            approval_id=APPROVAL_ID,
            evidence=(locator,),
        )

    def list_memory_lineage(
        self,
        lineage_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerMemorySummary]:
        assert lineage_id == LINEAGE_ID
        ordered = (self.old_memory, self.current_memory)
        start = 0 if cursor is None else int(cursor.removeprefix("lineage-at-"))
        visible = ordered[start : start + limit]
        next_offset = start + len(visible)
        has_more = next_offset < len(ordered)
        return OwnerPage(
            items=visible,
            next_cursor=f"lineage-at-{next_offset}" if has_more else None,
            has_more=has_more,
        )


@dataclass(slots=True)
class AuthenticatedUi:
    client: TestClient
    sessions: UiSessionStore
    service: SyntheticInspectionService

    @property
    def session(self) -> UiSession:
        cookie = self.client.cookies.get("memory_ui_session")
        assert cookie is not None
        session = self.sessions.resolve_cookie(
            cookie=cookie,
            exact_host=EXACT_HOST,
            now_ns=time.monotonic_ns(),
        )
        assert session is not None
        return session

    def post_form(
        self,
        path: str,
        fields: list[tuple[str, str]],
    ) -> Any:
        encoded = urllib.parse.urlencode(fields).encode("ascii")
        return self.client.post(
            path,
            content=encoded,
            headers={
                "Origin": PUBLIC_ORIGIN,
                "X-Memory-CSRF": self.session.csrf_token,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )

    def search_sources(self, query: str) -> Any:
        submitted = self.post_form("/sources/search", [("query", query)])
        assert submitted.status_code == 303
        location = submitted.headers["location"]
        assert query not in location
        return self.client.get(location)


def _authenticated_ui(
    service: SyntheticInspectionService | None = None,
    *,
    today: date | None = None,
) -> AuthenticatedUi:
    selected = SyntheticInspectionService() if service is None else service
    bootstrap = "synthetic-inspection-bootstrap"
    sessions = UiSessionStore(
        bootstrap_capability=bootstrap,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    application = create_ui_app(
        # Deliberately partial: this fake answers the twelve `OwnerUiService`
        # members the inspection and media routes reach, and none of the
        # twenty-four they do not. Twenty-four stub methods no test exercises
        # would be twenty-four claims about behaviour nobody checked.
        cast("OwnerUiService", selected),
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(selected, sessions),
        public_origin=PUBLIC_ORIGIN,
        today=(date.today if today is None else lambda: today),
    )
    client = TestClient(application, base_url=PUBLIC_ORIGIN)
    response = client.post(
        "/session",
        content=bootstrap,
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return AuthenticatedUi(client=client, sessions=sessions, service=selected)


def _hex_from_page(body: str) -> bytes:
    marker = 'data-original-hex="'
    start = body.index(marker) + len(marker)
    end = body.index('"', start)
    return bytes.fromhex(body[start:end])


def _next_content_href(body: str) -> str | None:
    marker = 'data-next-content href="'
    if marker not in body:
        return None
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)].replace("&amp;", "&")
