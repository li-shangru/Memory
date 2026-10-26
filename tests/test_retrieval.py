from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

from memory.database import Connection, Row
from memory.model import (
    RuntimePaths,
    SourceCaptureOrigin,
    SourceChunk,
    SourceSearchHit,
    SourceSummary,
    StoreIdentity,
)
from memory.sources import _read_connection, owner_source_summary_from_row
from memory.ui.view_models import OwnerSourceSummary

if TYPE_CHECKING:
    from memory.retrieval import _BlobOpeningConnection, _ReadableBlob


class FakeClock:
    def __init__(self) -> None:
        self.timestamp = 1_820_000_000.0

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


def capture_files(
    paths: RuntimePaths, files: dict[str, bytes], clock: FakeClock
) -> None:
    from memory.inbox import scan_inbox

    for name, body in files.items():
        (paths.inbox / name).write_bytes(body)
    scan_inbox(paths, clock=clock)


def _cursor_payload(cursor: str) -> dict[str, object]:
    padding = "=" * (-len(cursor) % 4)
    value = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def _cursor_with(
    cursor: str,
    *,
    remove: tuple[str, ...] = (),
    **changes: object,
) -> str:
    """Return one synthetic cursor with explicit field changes."""
    payload = _cursor_payload(cursor)
    for key in remove:
        payload.pop(key, None)
    payload.update(changes)
    return (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def _capture_source(
    paths: RuntimePaths,
    name: str,
    body: bytes,
) -> SourceSummary:
    from memory.sources import list_sources

    capture_files(paths, {name: body}, FakeClock())
    return list_sources(paths).items[0]


def _replace_retained_text_pair(
    paths: RuntimePaths,
    source_id: str,
    original_bytes: bytes,
    utf8_text_bytes: bytes,
) -> None:
    """Install one synthetic byte/text mismatch or invalid UTF-8 pair."""
    from memory.database import writer_session

    with writer_session(paths) as connection:
        connection.execute(
            "UPDATE source_blobs "
            "SET original_bytes = ?, utf8_text = CAST(? AS TEXT) "
            "WHERE blob_id = (SELECT blob_id FROM sources WHERE source_id = ?)",
            (original_bytes, utf8_text_bytes, source_id),
        )


@dataclass
class _BlobReadStats:
    original_bytes_read: int = 0
    utf8_text_bytes_read: int = 0
    largest_read: int = 0
    opens: int = 0
    selects: int = 0
    utf8_text_column_flags: tuple[int, ...] = ()


def _utf8_text_column_opcode_flags(
    connection: Connection,
    sql: str,
    parameters: tuple[str | bytes | int | float | None, ...],
) -> tuple[int, ...]:
    """Read the real SQLCipher VDBE flags for the retained-text projection."""
    root_page = int(
        connection.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = 'source_blobs'"
        ).fetchone()[0]
    )
    text_column = next(
        int(row[0])
        for row in connection.execute("PRAGMA table_info(source_blobs)").fetchall()
        if str(row[1]) == "utf8_text"
    )
    opcodes = connection.execute("EXPLAIN " + sql, parameters).fetchall()
    blob_cursor = next(
        int(row[2])
        for row in opcodes
        if str(row[1]) == "OpenRead" and int(row[3]) == root_page
    )
    return tuple(
        int(row[6])
        for row in opcodes
        if str(row[1]) == "Column"
        and int(row[2]) == blob_cursor
        and int(row[3]) == text_column
    )


class _CountingBlob:
    def __init__(
        self,
        blob: _ReadableBlob,
        column: str,
        stats: _BlobReadStats,
    ) -> None:
        self._blob = blob
        self._column = column
        self._stats = stats

    def __len__(self) -> int:
        return len(self._blob)

    def read(self, length: int = -1) -> bytes:
        body = self._blob.read(length)
        if self._column == "original_bytes":
            self._stats.original_bytes_read += len(body)
        elif self._column == "utf8_text":
            self._stats.utf8_text_bytes_read += len(body)
        self._stats.largest_read = max(self._stats.largest_read, len(body))
        return body

    def seek(self, offset: int, origin: int = 0) -> int:
        return self._blob.seek(offset, origin)

    def close(self) -> None:
        self._blob.close()


class _CountingConnection:
    """Observe real SQLCipher reads while rejecting a full-BLOB SELECT."""

    def __init__(self, connection: Connection, stats: _BlobReadStats) -> None:
        self._connection = connection
        self._stats = stats

    def execute(
        self,
        sql: str,
        parameters: tuple[str | bytes | int | float | None, ...] = (),
    ) -> object:
        if sql.lstrip().casefold().startswith("select"):
            self._stats.selects += 1
            assert "original_bytes" not in sql.casefold(), (
                "source.read selected the complete retained BLOB"
            )
            self._stats.utf8_text_column_flags += _utf8_text_column_opcode_flags(
                self._connection,
                sql,
                parameters,
            )
        return self._connection.execute(sql, parameters)

    def open_blob(
        self,
        table: str,
        column: str,
        rowid: int,
        read_only: bool = False,
    ) -> _CountingBlob:
        self._stats.opens += 1
        opener = cast("_BlobOpeningConnection", self._connection)
        return _CountingBlob(
            opener.open_blob(table, column, rowid, read_only),
            column,
            self._stats,
        )


def instrumented_read_source(
    paths: RuntimePaths,
    source_id: str,
    *,
    cursor: str | None,
    max_bytes: int,
    stats: _BlobReadStats,
) -> SourceChunk:
    """Read one real page through a connection that counts BLOB window bytes."""
    from memory.retrieval import _read_source_from_connection
    from memory.sources import _read_connection

    with _read_connection(paths) as (connection, identity):
        observed = _CountingConnection(connection, stats)
        return _read_source_from_connection(
            cast("Connection", observed),
            identity,
            source_id,
            cursor=cursor,
            max_bytes=max_bytes,
        )


@dataclass
class _LadderStreamStats:
    id_rows: int = 0
    plaintext_rows: int = 0
    plaintext_bytes: int = 0
    largest_plaintext_row: int = 0


class _StreamingLadderCursor:
    """Audit one real SQLCipher ladder cursor and forbid bulk materialization."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
        kind: str,
        stats: _LadderStreamStats,
    ) -> None:
        self._cursor = cursor
        self._kind = kind
        self._stats = stats

    def __iter__(self) -> Iterator[Row]:
        for raw in self._cursor:
            row = cast("Row", raw)
            if self._kind == "ids":
                self._stats.id_rows += 1
            else:
                size = sum(
                    len(value.encode("utf-8"))
                    for value in row
                    if isinstance(value, str)
                )
                self._stats.plaintext_rows += 1
                self._stats.plaintext_bytes += size
                self._stats.largest_plaintext_row = max(
                    self._stats.largest_plaintext_row,
                    size,
                )
            yield row

    def fetchall(self) -> list[Row]:
        raise AssertionError(f"source ladder {self._kind} cursor used fetchall")


class _StreamingSourceLadderConnection:
    def __init__(self, connection: Connection, stats: _LadderStreamStats) -> None:
        self._connection = connection
        self._stats = stats

    def execute(
        self,
        sql: str,
        parameters: tuple[str | bytes | int | float | None, ...] = (),
    ) -> object:
        cursor = self._connection.execute(sql, parameters)
        normalized = " ".join(sql.casefold().split())
        kind = None
        if "source_fts match ?" in normalized:
            kind = "ids"
        elif normalized.startswith("select s.rowid, s.source_id") and (
            "utf8_text, s.original_name" in normalized
        ):
            kind = "plaintext"
        return (
            cursor
            if kind is None
            else _StreamingLadderCursor(cursor, kind, self._stats)
        )


@dataclass
class _VisibleSourceStreamStats:
    plaintext_rows: int = 0
    outstanding_plaintext_rows: int = 0
    peak_outstanding_plaintext_rows: int = 0
    assembled_rowids: tuple[int, ...] = ()


class _VisibleSourceCursor:
    """Forbid bulk page text and require each row to be bounded immediately."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
        stats: _VisibleSourceStreamStats,
    ) -> None:
        self._cursor = cursor
        self._stats = stats

    def __iter__(self) -> _VisibleSourceCursor:
        return self

    def __next__(self) -> Row:
        assert self._stats.outstanding_plaintext_rows == 0, (
            "source.search retained a full plaintext row while advancing the "
            "visible-page cursor"
        )
        row = cast("Row", next(self._cursor))
        self._stats.plaintext_rows += 1
        self._stats.outstanding_plaintext_rows += 1
        self._stats.peak_outstanding_plaintext_rows = max(
            self._stats.peak_outstanding_plaintext_rows,
            self._stats.outstanding_plaintext_rows,
        )
        return row

    def fetchall(self) -> list[Row]:
        raise AssertionError("source.search visible plaintext cursor used fetchall")


class _VisibleSourceConnection:
    def __init__(
        self,
        connection: Connection,
        stats: _VisibleSourceStreamStats,
    ) -> None:
        self._connection = connection
        self._stats = stats

    def execute(
        self,
        sql: str,
        parameters: tuple[str | bytes | int | float | None, ...] = (),
    ) -> object:
        cursor = self._connection.execute(sql, parameters)
        normalized = " ".join(sql.casefold().split())
        if "s.origin" in normalized and "where s.rowid in (" in normalized:
            return _VisibleSourceCursor(cursor, self._stats)
        return cursor


def test_search_covers_all_utf8_types_and_reports_binary_gap(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch partial FTS coverage being presented as a complete Store search."""
    from memory.retrieval import search_sources

    capture_files(
        synthetic_store,
        {
            "a-english.txt": b"Synthetic orchard lantern schedule.\n",
            "b-chinese.md": "合成远足清单：蓝色雨伞和茶。\n".encode(),
            "c-record.json": b'{"synthetic":"lantern"}\n',
            "d-table.csv": b"item,value\nlantern,2\n",
            "e-image.png": b"\x89PNG\x00\xffsynthetic",
        },
        FakeClock(),
    )

    english = search_sources(synthetic_store, "lantern", limit=100)
    chinese = search_sources(synthetic_store, "蓝色雨伞", limit=100)

    assert [hit.source.original_name for hit in english.items] == [
        "a-english.txt",
        "c-record.json",
        "d-table.csv",
    ]
    assert all("lantern" in hit.exact_excerpt for hit in english.items)
    assert all(hit.source.origin is SourceCaptureOrigin.INBOX for hit in english.items)
    assert [hit.source.original_name for hit in chinese.items] == ["b-chinese.md"]
    assert chinese.items[0].source.origin is SourceCaptureOrigin.INBOX
    assert chinese.items[0].exact_excerpt in "合成远足清单：蓝色雨伞和茶。\n"
    assert english.coverage.searchable == 4
    assert english.coverage.unsearchable == 1
    assert english.coverage.enumerated == 4
    assert english.coverage.total == 5


def test_search_cursor_is_query_bound_and_excludes_later_matches(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a cursor being reusable for another query or admitting later rows."""
    from memory.errors import StaleCursorError
    from memory.retrieval import search_sources

    clock = FakeClock()
    capture_files(
        synthetic_store,
        {
            "a.txt": b"synthetic comet",
            "b.txt": b"synthetic comet",
            "c.txt": b"synthetic comet",
        },
        clock,
    )
    first = search_sources(synthetic_store, "comet", limit=1)
    assert first.next_cursor is not None

    capture_files(
        synthetic_store,
        {"d-later.txt": b"synthetic comet"},
        clock,
    )
    second = search_sources(
        synthetic_store,
        "comet",
        cursor=first.next_cursor,
        limit=1,
    )
    assert second.next_cursor is not None
    third = search_sources(
        synthetic_store,
        "comet",
        cursor=second.next_cursor,
        limit=1,
    )

    assert [page.items[0].source.original_name for page in (first, second, third)] == [
        "a.txt",
        "b.txt",
        "c.txt",
    ]
    assert third.has_more is False
    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "different",
            cursor=first.next_cursor,
            limit=1,
        )


def test_search_cursor_rejects_oversized_rowid_coordinates(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch valid query-bound cursor integers reaching SQLite conversion."""
    from memory.errors import StaleCursorError
    from memory.retrieval import search_sources

    capture_files(
        synthetic_store,
        {
            "synthetic-coordinate-a.txt": b"synthetic coordinate marker",
            "synthetic-coordinate-b.txt": b"synthetic coordinate marker",
        },
        FakeClock(),
    )
    first = search_sources(synthetic_store, "coordinate marker", limit=1)
    assert first.next_cursor is not None
    padding = "=" * (-len(first.next_cursor) % 4)
    payload = json.loads(
        base64.urlsafe_b64decode(first.next_cursor + padding).decode("utf-8")
    )
    payload["after"] = 2**100
    payload["upper"] = 2**100
    oversized = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "coordinate marker",
            cursor=oversized,
            limit=1,
        )


@pytest.mark.parametrize(
    "rank",
    (
        True,
        "1.0",
        float("nan"),
        float("inf"),
        10**2000,
    ),
    ids=("boolean", "wrong-type", "not-a-number", "infinite", "unrepresentable"),
)
def test_search_cursor_rejects_invalid_rank_values_as_stale(
    synthetic_store: RuntimePaths,
    rank: object,
) -> None:
    """Catch malformed rank metadata escaping typed cursor validation."""
    from memory.errors import StaleCursorError
    from memory.retrieval import search_sources

    capture_files(
        synthetic_store,
        {
            "synthetic-rank-a.txt": b"synthetic rank marker",
            "synthetic-rank-b.txt": b"synthetic rank marker",
        },
        FakeClock(),
    )
    first = search_sources(synthetic_store, "rank marker", limit=1)
    assert first.next_cursor is not None
    malformed = _cursor_with(first.next_cursor, rank=rank)
    assert len(malformed) < 4096

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "rank marker",
            cursor=malformed,
            limit=1,
        )


def test_search_orders_by_stable_relevance_across_high_water_pages(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch rank metadata being returned while traversal stays in capture order."""
    from memory.retrieval import search_sources

    clock = FakeClock()
    capture_files(
        synthetic_store,
        {
            "a-one.txt": b"comet",
            "b-three.txt": b"comet meteor orbit",
            "c-two.txt": b"comet meteor",
        },
        clock,
    )
    query = "comet meteor orbit zenith"
    first = search_sources(synthetic_store, query, limit=1)
    assert first.next_cursor is not None

    capture_files(
        synthetic_store,
        {"d-later-full.txt": b"comet meteor orbit zenith"},
        clock,
    )
    second = search_sources(
        synthetic_store,
        query,
        cursor=first.next_cursor,
        limit=1,
    )
    assert second.next_cursor is not None
    third = search_sources(
        synthetic_store,
        query,
        cursor=second.next_cursor,
        limit=1,
    )

    assert [page.items[0].source.original_name for page in (first, second, third)] == [
        "b-three.txt",
        "c-two.txt",
        "a-one.txt",
    ]
    assert first.items[0].rank < second.items[0].rank < third.items[0].rank
    assert third.has_more is False


def test_stem_only_hit_excerpts_the_matching_word_not_the_document_head(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a stemmed hit excerpting filler that never relates to the query."""
    from memory.retrieval import search_sources

    filler = "Synthetic filler sentence about unrelated matters. " * 30
    body = f"{filler}The owner spent Sunday gardening behind the shed.\n"
    assert len(filler.encode("utf-8")) > 1400
    capture_files(synthetic_store, {"stemmed.txt": body.encode("utf-8")}, FakeClock())

    page = search_sources(synthetic_store, "gardens", limit=10)

    assert [hit.source.original_name for hit in page.items] == ["stemmed.txt"]
    excerpt = page.items[0].exact_excerpt
    assert "gardens" not in body
    assert len(excerpt) < len(body)
    assert "gardening" in excerpt


def test_search_hits_report_the_excerpt_span_in_source_coordinates(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a hit excerpt that cannot be turned back into an evidence locator."""
    from memory.retrieval import read_source, search_sources

    filler = "Synthetic filler sentence about unrelated matters. " * 30
    body = f"{filler}The owner spent Sunday gardening behind the shed.\n"
    short = "合成短文：蓝色纸灯挂在门口。\n"
    capture_files(
        synthetic_store,
        {"long.txt": body.encode("utf-8"), "short.md": short.encode("utf-8")},
        FakeClock(),
    )

    truncated = search_sources(synthetic_store, "gardening", limit=10).items[0]
    whole = search_sources(synthetic_store, "纸灯", limit=10).items[0]

    # The excerpt is a window into a source that outgrew the excerpt cap, so its
    # span is the one thing that turns the preview back into an exact locator.
    assert len(truncated.exact_excerpt) < len(body)
    assert truncated.excerpt_char_start > 0
    assert (
        body[truncated.excerpt_char_start : truncated.excerpt_char_end]
        == truncated.exact_excerpt
    )
    assert truncated.match_char_start is not None
    assert truncated.match_char_end is not None
    assert body[truncated.match_char_start : truncated.match_char_end] == "gardening"
    # A source under the cap is returned whole, and its span still has to be the
    # real span rather than an implicit zero nobody checked.
    assert whole.exact_excerpt == short
    assert whole.excerpt_char_start == 0
    assert whole.excerpt_char_end == len(short)
    assert whole.match_char_start is not None
    assert short[whole.match_char_start : whole.match_char_end] == "纸灯"
    # The coordinates are the same system `source.read` reports.
    chunk = read_source(synthetic_store, whole.source.source_id)
    assert chunk.char_start == 0
    assert chunk.char_end == whole.excerpt_char_end


def test_text_chunks_use_canonical_multibyte_character_ranges(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch UTF-8 splitting or byte offsets being mislabeled as character spans."""
    from memory.retrieval import read_source
    from memory.sources import list_sources

    text = "A🙂中Bé"
    body = text.encode()
    capture_files(
        synthetic_store,
        {"synthetic-multibyte.md": body},
        FakeClock(),
    )
    source = list_sources(synthetic_store).items[0]

    first = read_source(synthetic_store, source.source_id, max_bytes=5)
    assert first.next_cursor is not None
    second = read_source(
        synthetic_store,
        source.source_id,
        cursor=first.next_cursor,
        max_bytes=4,
    )
    assert second.next_cursor is not None
    third = read_source(
        synthetic_store,
        source.source_id,
        cursor=second.next_cursor,
        max_bytes=2,
    )

    assert [chunk.text for chunk in (first, second, third)] == ["A🙂", "中B", "é"]
    assert [
        (chunk.char_start, chunk.char_end, chunk.byte_start, chunk.byte_end)
        for chunk in (first, second, third)
    ] == [(0, 2, 0, 5), (2, 4, 5, 9), (4, 5, 9, 11)]
    assert first.complete is False
    assert second.complete is False
    assert third.complete is True
    assert third.next_cursor is None
    assert {chunk.blob_digest for chunk in (first, second, third)} == {
        hashlib.sha256(body).hexdigest()
    }


def test_source_ladder_streams_plaintext_and_fts_id_rows(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch either corpus pass rebuilding a plaintext or ID fetchall list."""
    from memory.retrieval import _source_ladder_matches
    from memory.sources import _read_connection, list_sources

    row_text = "x" * (1024 * 1024)
    capture_files(
        synthetic_store,
        {
            f"synthetic-stream-{index}.txt": (
                f"{row_text} synthetic amber record {index}."
            ).encode()
            for index in range(3)
        },
        FakeClock(),
    )
    expected = {source.source_id for source in list_sources(synthetic_store).items}
    stats = _LadderStreamStats()

    with _read_connection(synthetic_store) as (connection, _identity):
        connection.execute("BEGIN")
        upper = int(connection.execute("SELECT max(rowid) FROM sources").fetchone()[0])
        observed = _StreamingSourceLadderConnection(connection, stats)
        matching = _source_ladder_matches(
            cast("Connection", observed),
            "amber",
            upper,
        )

    assert {entry.source_id for entry in matching} == expected
    assert stats.id_rows == 9
    assert stats.plaintext_rows == 3
    assert stats.largest_plaintext_row >= len(row_text)
    assert stats.plaintext_bytes > 2 * stats.largest_plaintext_row


def test_search_sources_streams_each_visible_plaintext_row_before_advancing(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a public page retaining every selected source's complete text."""
    from memory import retrieval as retrieval_module

    capture_files(
        synthetic_store,
        {
            "a.txt": b"Synthetic studio calendar.",
            "b.txt": b"Synthetic amber lamp near the studio window.",
            "c.txt": b"Synthetic amber studio note.",
            "d.txt": b"Synthetic amber studio and amber studio record.",
        },
        FakeClock(),
    )
    stats = _VisibleSourceStreamStats()
    original_read_connection = _read_connection
    original_search_hit = retrieval_module._search_hit

    @contextmanager
    def observed_read_connection(
        paths: RuntimePaths,
    ) -> Iterator[tuple[Connection, StoreIdentity]]:
        with original_read_connection(paths) as (connection, identity):
            yield (
                cast(
                    "Connection",
                    _VisibleSourceConnection(connection, stats),
                ),
                identity,
            )

    def observed_search_hit(
        entry: retrieval_module._SourceMatchEntry,
        row: Row,
        excerpt: retrieval_module.Excerpt,
    ) -> SourceSearchHit:
        assert stats.outstanding_plaintext_rows == 1
        stats.assembled_rowids += (int(row[0]),)
        stats.outstanding_plaintext_rows -= 1
        return original_search_hit(entry, row, excerpt)

    monkeypatch.setattr(retrieval_module, "_read_connection", observed_read_connection)
    monkeypatch.setattr(retrieval_module, "_search_hit", observed_search_hit)

    page = retrieval_module.search_sources(
        synthetic_store,
        "amber studio",
        limit=4,
    )

    assert [hit.source.original_name for hit in page.items] == [
        "c.txt",
        "d.txt",
        "b.txt",
        "a.txt",
    ]
    assert stats.plaintext_rows == 4
    assert stats.peak_outstanding_plaintext_rows == 1
    assert stats.outstanding_plaintext_rows == 0
    assert len(set(stats.assembled_rowids)) == 4

    owner_stats = _VisibleSourceStreamStats()
    original_owner_summary = owner_source_summary_from_row

    def observed_owner_summary(row: Row) -> OwnerSourceSummary:
        assert owner_stats.outstanding_plaintext_rows == 1
        owner_stats.assembled_rowids += (int(row[0]),)
        owner_stats.outstanding_plaintext_rows -= 1
        return original_owner_summary(row)

    monkeypatch.setattr(
        retrieval_module,
        "owner_source_summary_from_row",
        observed_owner_summary,
    )
    with original_read_connection(synthetic_store) as (connection, identity):
        connection.execute("BEGIN")
        owner_page = retrieval_module.owner_search_sources(
            cast("Connection", _VisibleSourceConnection(connection, owner_stats)),
            identity,
            "amber studio",
            None,
            4,
        )

    assert [hit.source.original_name for hit in owner_page.items] == [
        hit.source.original_name for hit in page.items
    ]
    assert [hit.rank for hit in owner_page.items] == [hit.rank for hit in page.items]
    assert [hit.exact_excerpt for hit in owner_page.items] == [
        hit.exact_excerpt for hit in page.items
    ]
    assert owner_stats.plaintext_rows == 4
    assert owner_stats.peak_outstanding_plaintext_rows == 1
    assert owner_stats.outstanding_plaintext_rows == 0
    assert len(set(owner_stats.assembled_rowids)) == 4


@pytest.mark.slow
@pytest.mark.parametrize("size", (16 * 1024 * 1024, 64 * 1024 * 1024))
@pytest.mark.parametrize(
    ("suffix", "unit", "is_text"),
    ((".txt", b"T", True), (".pdf", b"\x00", False)),
    ids=("text", "binary"),
)
def test_source_walks_use_incremental_blob_windows_with_linear_work(
    synthetic_store: RuntimePaths,
    size: int,
    suffix: str,
    unit: bytes,
    is_text: bool,
) -> None:
    """Catch every page SELECTing the full BLOB or re-reading prior pages."""
    body = unit * size
    source = _capture_source(
        synthetic_store,
        f"synthetic-large{suffix}",
        body,
    )
    stats = _BlobReadStats()
    digest = hashlib.sha256()
    cursor: str | None = None
    byte_start = 0
    char_start = 0
    page_count = 0
    max_bytes = 4 * 1024 * 1024

    while True:
        chunk = instrumented_read_source(
            synthetic_store,
            source.source_id,
            cursor=cursor,
            max_bytes=max_bytes,
            stats=stats,
        )
        page_count += 1
        assert chunk.byte_start == byte_start
        if is_text:
            assert chunk.text is not None
            piece = chunk.text.encode("utf-8")
            assert chunk.char_start == char_start
            assert chunk.char_end == char_start + len(chunk.text)
            char_start = chunk.char_end
        else:
            assert chunk.binary is not None
            piece = chunk.binary
            assert chunk.char_start is None
            assert chunk.char_end is None
        digest.update(piece)
        byte_start = chunk.byte_end
        if chunk.complete:
            assert chunk.next_cursor is None
            break
        assert chunk.next_cursor is not None
        cursor = chunk.next_cursor

    assert byte_start == size
    assert digest.hexdigest() == hashlib.sha256(body).hexdigest()
    assert page_count == size // max_bytes
    assert stats.opens == page_count * (2 if is_text else 1)
    assert stats.selects == page_count
    # OPFLAG_TYPEOFARG tells SQLite's Column opcode to inspect the record type
    # without materializing an overflow TEXT value merely to report presence.
    assert stats.utf8_text_column_flags == (0x80,) * page_count
    assert stats.original_bytes_read == size
    assert stats.utf8_text_bytes_read == (size if is_text else 0)
    assert stats.original_bytes_read + stats.utf8_text_bytes_read == size * (
        2 if is_text else 1
    )
    # Text decoding uses fixed windows rather than one page-sized allocation;
    # binary retains the existing raw page contract.
    assert stats.largest_read <= (64 * 1024 if is_text else max_bytes)


def test_new_and_legacy_source_read_cursors_preserve_character_coordinates(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a new character coordinate being omitted or an old cursor rejected."""
    from memory.retrieval import read_source

    body = "A🙂中Bé尾".encode()
    source = _capture_source(synthetic_store, "synthetic-cursor.md", body)
    first = read_source(synthetic_store, source.source_id, max_bytes=5)
    assert first.next_cursor is not None
    new_payload = _cursor_payload(first.next_cursor)

    assert new_payload["after"] == 5
    assert new_payload["character"] == 2

    new_stats = _BlobReadStats()
    resumed = instrumented_read_source(
        synthetic_store,
        source.source_id,
        cursor=first.next_cursor,
        max_bytes=4,
        stats=new_stats,
    )
    legacy = _cursor_with(first.next_cursor, remove=("character",))
    legacy_stats = _BlobReadStats()
    resumed_legacy = instrumented_read_source(
        synthetic_store,
        source.source_id,
        cursor=legacy,
        max_bytes=4,
        stats=legacy_stats,
    )

    assert resumed.text == resumed_legacy.text == "中B"
    assert (resumed.char_start, resumed.char_end) == (2, 4)
    assert (resumed_legacy.char_start, resumed_legacy.char_end) == (2, 4)
    assert new_stats.original_bytes_read == 4
    assert new_stats.utf8_text_bytes_read == 4
    # The one compatibility read streams the five-byte prefix and the page,
    # then its continuation is new-form and needs no further prefix walk.
    assert legacy_stats.original_bytes_read == 9
    assert legacy_stats.utf8_text_bytes_read == 9
    assert resumed_legacy.next_cursor is not None
    assert _cursor_payload(resumed_legacy.next_cursor)["character"] == 4


@pytest.mark.parametrize(
    ("after", "character"),
    (
        (None, True),
        (None, -1),
        (None, 6),
        (None, "2"),
        (2, 1),
    ),
    ids=(
        "boolean",
        "negative",
        "past-byte-coordinate",
        "wrong-type",
        "mid-codepoint",
    ),
)
def test_source_read_cursor_rejects_malformed_character_coordinates(
    synthetic_store: RuntimePaths,
    after: int | None,
    character: object,
) -> None:
    """Catch malformed coordinates and byte seeks inside a UTF-8 code point."""
    from memory.errors import StaleCursorError
    from memory.retrieval import read_source

    source = _capture_source(
        synthetic_store, "synthetic-malformed.md", "A🙂中".encode()
    )
    first = read_source(synthetic_store, source.source_id, max_bytes=5)
    assert first.next_cursor is not None
    malformed = (
        _cursor_with(first.next_cursor, character=character)
        if after is None
        else _cursor_with(first.next_cursor, after=after, character=character)
    )

    with pytest.raises(StaleCursorError):
        read_source(
            synthetic_store,
            source.source_id,
            cursor=malformed,
            max_bytes=4,
        )


def test_character_coordinate_is_confined_to_text_source_read_cursors(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the compatible cursor extension leaking to lists or binary reads."""
    from memory.errors import StaleCursorError
    from memory.retrieval import read_source
    from memory.sources import list_sources

    capture_files(
        synthetic_store,
        {
            "a-list.txt": b"Synthetic first list source.",
            "b-list.txt": b"Synthetic second list source.",
            "c-binary.pdf": b"%PDF-synthetic-binary-cursor",
        },
        FakeClock(),
    )
    sources = list_sources(synthetic_store, limit=3).items
    first_list_page = list_sources(synthetic_store, limit=1)
    assert first_list_page.next_cursor is not None
    list_cursor = _cursor_with(first_list_page.next_cursor, character=0)
    with pytest.raises(StaleCursorError):
        list_sources(synthetic_store, cursor=list_cursor, limit=1)

    binary = next(
        source for source in sources if source.media_type == "application/pdf"
    )
    first_binary = read_source(
        synthetic_store,
        binary.source_id,
        max_bytes=4,
    )
    assert first_binary.next_cursor is not None
    binary_cursor = _cursor_with(first_binary.next_cursor, character=0)
    with pytest.raises(StaleCursorError):
        read_source(
            synthetic_store,
            binary.source_id,
            cursor=binary_cursor,
            max_bytes=4,
        )


def test_binary_chunks_are_bounded_and_reconstruct_exact_bytes(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch binary omission, base64-oriented mutation, or cursor byte gaps."""
    from memory.retrieval import read_source
    from memory.sources import list_sources

    body = b"%PDF-\x00\xffsynthetic-binary"
    capture_files(synthetic_store, {"synthetic-paper.pdf": body}, FakeClock())
    source = list_sources(synthetic_store).items[0]
    chunks = []
    cursor = None
    while True:
        chunk = read_source(
            synthetic_store,
            source.source_id,
            cursor=cursor,
            max_bytes=4,
        )
        chunks.append(chunk)
        if chunk.complete:
            break
        cursor = chunk.next_cursor

    assert (
        b"".join(chunk.binary for chunk in chunks if chunk.binary is not None) == body
    )
    assert all(chunk.text is None for chunk in chunks)
    assert all(chunk.resource_content_index == 0 for chunk in chunks)
    assert [(chunk.byte_start, chunk.byte_end) for chunk in chunks] == [
        (0, 4),
        (4, 8),
        (8, 12),
        (12, 16),
        (16, 20),
        (20, len(body)),
    ]
    assert {chunk.blob_digest for chunk in chunks} == {hashlib.sha256(body).hexdigest()}


def test_capture_media_type_controls_text_vs_binary_for_one_shared_blob(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch blob dedup overriding a capture's declared read/search mode."""
    from memory.inbox import scan_inbox
    from memory.retrieval import read_source, search_sources
    from memory.sources import list_sources

    clock = FakeClock()
    body = b"synthetic reversible text"
    (synthetic_store.inbox / "first.bin").write_bytes(body)
    scan_inbox(synthetic_store, clock=clock)
    (synthetic_store.inbox / "second.txt").write_bytes(body)
    scan_inbox(synthetic_store, clock=clock)
    sources = list_sources(synthetic_store).items

    binary = read_source(synthetic_store, sources[0].source_id)
    text = read_source(synthetic_store, sources[1].source_id)
    hits = search_sources(synthetic_store, "reversible")

    assert binary.binary == body
    assert binary.text is None
    assert text.text == body.decode()
    assert text.binary is None
    assert [hit.source.source_id for hit in hits.items] == [sources[1].source_id]


def test_read_source_uses_authoritative_blob_text_not_disposable_fts(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch disposable search rows replacing complete retained source truth."""
    from memory.database import writer_session
    from memory.retrieval import read_source
    from memory.sources import list_sources

    body = "合成权威文本：青色风筝。\n".encode()
    capture_files(
        synthetic_store,
        {"synthetic-authoritative.md": body},
        FakeClock(),
    )
    source = list_sources(synthetic_store).items[0]
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "UPDATE source_fts SET utf8_text = ? WHERE source_id = ?",
            ("Synthetic corrupt projection.", source.source_id),
        )

    chunk = read_source(synthetic_store, source.source_id)

    assert chunk.text == body.decode()
    assert chunk.binary is None
    assert chunk.complete is True


@pytest.mark.parametrize("drift", ("same-length", "shorter"))
def test_text_reads_reject_incremental_duplicate_text_drift(
    synthetic_store: RuntimePaths,
    drift: str,
) -> None:
    """Catch bounded byte reads silently dropping retained-text fidelity."""
    from memory.errors import InvalidArgumentError
    from memory.retrieval import read_source

    body = ("A" * (70 * 1024)).encode()
    source = _capture_source(synthetic_store, "synthetic-fidelity.txt", body)
    replacement = b"B" * (len(body) if drift == "same-length" else len(body) - 1)
    _replace_retained_text_pair(synthetic_store, source.source_id, body, replacement)

    with pytest.raises(InvalidArgumentError):
        read_source(
            synthetic_store,
            source.source_id,
            max_bytes=len(body),
        )


def test_text_read_strictly_decodes_equal_invalid_blob_windows(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch byte/text equality being mistaken for valid retained UTF-8."""
    from memory.errors import InvalidArgumentError
    from memory.retrieval import read_source

    body = b"A" * (128 * 1024)
    source = _capture_source(synthetic_store, "synthetic-invalid.txt", body)
    invalid = body[: 64 * 1024] + b"\xff" + body[64 * 1024 + 1 :]
    assert len(invalid) == len(body)
    _replace_retained_text_pair(synthetic_store, source.source_id, invalid, invalid)

    with pytest.raises(InvalidArgumentError):
        read_source(
            synthetic_store,
            source.source_id,
            max_bytes=len(body),
        )


def test_text_presence_and_capture_media_type_jointly_select_the_read_arm(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch text presence alone overriding one capture's declared media type."""
    from memory.database import writer_session
    from memory.retrieval import read_source
    from memory.sources import list_sources

    text_body = b"Synthetic text-presence fixture."
    binary_body = b"Synthetic bytes with a binary media declaration."
    capture_files(
        synthetic_store,
        {"a-text.txt": text_body, "b-binary.pdf": binary_body},
        FakeClock(),
    )
    text_source, binary_source = list_sources(synthetic_store).items
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "UPDATE source_blobs SET utf8_text = NULL "
            "WHERE blob_id = (SELECT blob_id FROM sources WHERE source_id = ?)",
            (text_source.source_id,),
        )
        connection.execute(
            "UPDATE source_blobs SET utf8_text = ? "
            "WHERE blob_id = (SELECT blob_id FROM sources WHERE source_id = ?)",
            (binary_body.decode(), binary_source.source_id),
        )

    absent_text = read_source(synthetic_store, text_source.source_id)
    binary_media = read_source(synthetic_store, binary_source.source_id)

    assert absent_text.text is None
    assert absent_text.binary == text_body
    assert binary_media.text is None
    assert binary_media.binary == binary_body


def test_exhaustive_listing_and_chunk_reads_reproduce_every_capture(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch any retained source becoming unreachable through bounded APIs."""
    from memory.retrieval import read_source
    from memory.sources import list_sources

    expected = {
        "a.txt": b"synthetic alpha",
        "b.md": "合成乙项".encode(),
        "c.webp": b"RIFF\x00\xffWEBP",
    }
    capture_files(synthetic_store, expected, FakeClock())
    reconstructed: dict[str, bytes] = {}
    list_cursor = None
    while True:
        page = list_sources(synthetic_store, cursor=list_cursor, limit=1)
        for source in page.items:
            pieces: list[bytes] = []
            read_cursor = None
            while True:
                chunk = read_source(
                    synthetic_store,
                    source.source_id,
                    cursor=read_cursor,
                    max_bytes=4,
                )
                if chunk.text is not None:
                    pieces.append(chunk.text.encode())
                else:
                    assert chunk.binary is not None
                    pieces.append(chunk.binary)
                if chunk.complete:
                    break
                read_cursor = chunk.next_cursor
            reconstructed[source.original_name] = b"".join(pieces)
        if not page.has_more:
            break
        list_cursor = page.next_cursor

    assert reconstructed == expected


def test_read_and_search_bounds_fail_with_typed_arguments(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch unbounded query/chunk requests or a non-progressing UTF-8 cursor."""
    from memory.errors import InvalidArgumentError
    from memory.retrieval import read_source, search_sources
    from memory.sources import list_sources

    capture_files(
        synthetic_store,
        {"synthetic-bound.md": "A🙂".encode()},
        FakeClock(),
    )
    source = list_sources(synthetic_store).items[0]
    first = read_source(synthetic_store, source.source_id, max_bytes=1)
    assert first.next_cursor is not None
    symbol_search = search_sources(synthetic_store, "🙂")
    # FTS cannot tokenize a lone symbol, so this query is answered only by the
    # literal substring rung; the page and its coverage stay well formed.
    assert [hit.source.original_name for hit in symbol_search.items] == [
        "synthetic-bound.md"
    ]
    assert symbol_search.coverage.searchable == 1

    with pytest.raises(InvalidArgumentError):
        read_source(
            synthetic_store,
            source.source_id,
            cursor=first.next_cursor,
            max_bytes=1,
        )
    with pytest.raises(InvalidArgumentError):
        read_source(synthetic_store, source.source_id, max_bytes=4 * 1024 * 1024 + 1)
    for invalid_query in ("", "synthetic\x00query", "x" * (16 * 1024 + 1)):
        with pytest.raises(InvalidArgumentError):
            search_sources(synthetic_store, invalid_query)


def test_an_excerpt_span_stays_in_source_coordinates_when_folding_grows(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a window sliced from the source with an index into its folding.

    Full case folding never shortens a string but often lengthens it -- `ss`
    for one `ss`, `fi` for one ligature -- so a located index is a source index
    only when the two lengths agree. Slicing the source with it anyway
    displaces the window by the difference, and for a long enough document
    slides it off the end entirely: an empty preview for a source that plainly
    holds the term, published under a half-open span whose start exceeds its
    end.
    """
    from synthetic import FakeClock, capture_text

    from memory.model import Sensitivity
    from memory.retrieval import search_sources

    body = "\u00df" * 1500 + " the amber lamp sits here " + "x" * 200
    capture_text(
        synthetic_store,
        name="folded.txt",
        body=body,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )

    hit = search_sources(synthetic_store, "amber").items[0]

    assert len(body.casefold()) != len(body)
    assert 0 <= hit.excerpt_char_start < hit.excerpt_char_end <= len(body)
    # The span is the excerpt's own coordinates, so it must slice back to it.
    assert body[hit.excerpt_char_start : hit.excerpt_char_end] == hit.exact_excerpt
    # And the preview is worth showing: a direct scan recovers the position
    # the folded index could not name.
    assert "amber" in hit.exact_excerpt
    # The match span stays withheld -- folding is not index-preserving here.
    assert hit.match_char_start is None
    assert hit.match_char_end is None


def test_a_fold_misaligned_window_centres_on_the_match_the_ladder_found(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a window that gives up on a document folding did not preserve.

    Falling back to a direct scan of the source recovers only the two spellings
    that scan probes -- the query verbatim and its casefold. It recovers
    neither of the two commonest anchors: an occurrence differing from the
    query only in capitalization, and a hit the stemmed pass admitted with no
    literal occurrence at all. Both land on the fallback's own fallback and
    window the head of the document, so a `phrase`-strength hit arrives with a
    preview holding nothing the caller searched for.

    One `ß` anywhere in a document is enough to reach this, and the
    document does not have to be contrived: a German note, a ligature pasted
    out of a PDF, a Turkish dotted capital.
    """
    from synthetic import FakeClock, capture_text

    from memory.model import Sensitivity
    from memory.retrieval import search_sources

    filler = "\n".join(f"filler line {index} carrying nothing" for index in range(40))
    body = (
        "Die Straße war ruhig.\n"
        + filler
        + "\nThe Amber Lamp sits on the desk.\n"
        + filler
    )
    capture_text(
        synthetic_store,
        name="misaligned.txt",
        body=body,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    assert len(body.casefold()) != len(body)

    # Capitalized in the source, lower case in the query: the folded pass
    # locates it exactly, and only the source scan cannot spell it.
    capitalized = search_sources(synthetic_store, "amber lamp").items[0]
    assert body[capitalized.excerpt_char_start : capitalized.excerpt_char_end] == (
        capitalized.exact_excerpt
    )
    assert "Amber Lamp" in capitalized.exact_excerpt

    # Admitted by the stemmed pass with no literal occurrence to scan for, so
    # the anchor is a prefix and the window has nothing else to centre on.
    stemmed = search_sources(synthetic_store, "lamps").items[0]
    assert body[stemmed.excerpt_char_start : stemmed.excerpt_char_end] == (
        stemmed.exact_excerpt
    )
    assert "Amber Lamp" in stemmed.exact_excerpt


def test_the_folded_index_map_agrees_with_its_own_definition_everywhere() -> None:
    """Pin the bounded walk to the definition it is an optimization of.

    `_source_index` is specified by one unbounded walk: step through the source
    accumulating each character's folded width, and stop at the character whose
    width covers the folded index. It does not run that walk -- an aligned
    document returns immediately, and a misaligned one starts as far back as
    the document's total expansion allows rather than at zero. Both shortcuts
    are provable, and this is what proves them: the fast function must equal
    the definition at every index of every input, not only at the ones a
    fixture happens to hold.
    """
    import random

    from memory.retrieval import _source_index

    def definition(text: str, folded_index: int) -> int:
        consumed = 0
        for position, character in enumerate(text):
            width = len(character.casefold())
            if consumed + width > folded_index:
                return position
            consumed += width
        return len(text)

    # Characters whose fold expands, one that folds to itself, CJK, and one
    # astral character, so the sample carries every shape the walk can meet.
    alphabet = (
        "".join(
            chr(code) for code in (0xDF, 0xFB01, 0x130, 0x1E9E, 0x390, 0x3B0, 0x149)
        )
        + "abXY 安静\n\U0001d518"
    )
    random_source = random.Random(20260810)

    for _ in range(400):
        text = "".join(
            random_source.choice(alphabet) for _ in range(random_source.randint(0, 40))
        )
        folded = text.casefold()
        for index in range(len(folded) + 3):
            assert _source_index(text, folded, index) == definition(text, index), (
                text,
                index,
            )


@pytest.mark.slow
def test_windowing_a_large_source_stays_near_the_cost_of_folding_it() -> None:
    """Catch the window mapping scanning the whole source once per hit.

    `_exact_excerpt` folds the whole text before it maps, so that fold is the
    natural unit to measure against: it is the same work over the same
    string, on the same loaded machine, which is what makes this bound a
    ratio rather than a wall-clock figure a busy CI can miss. A Python-level
    walk of the source costs roughly 180 folds and runs once per hit, so a
    page of 500 hits over multi-megabyte sources is minutes rather than
    milliseconds. The compiled locate that anchors production excerpts has
    its own, larger cost profile and is deliberately not this bound's
    subject; this guards the mapping step alone, as it always has.
    """
    import time

    from memory.retrieval import _source_index

    body = "x" * (4 * 1024 * 1024) + " the amber lamp sits here "
    folded = body.casefold()
    match = folded.find("amber")

    start = time.perf_counter()
    body.casefold()
    fold_seconds = time.perf_counter() - start

    start = time.perf_counter()
    mapped = _source_index(body, folded, match)
    map_seconds = time.perf_counter() - start

    assert mapped == match
    # Measured at ~1.4x with the bound in place and ~180x without it.
    assert map_seconds < 20 * fold_seconds, (map_seconds, fold_seconds)
