from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING, cast

import pytest
from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]  # no stubs

from memory.model import (
    Authorship,
    RuntimePaths,
    Sensitivity,
    SourceCaptureOrigin,
)

if TYPE_CHECKING:
    from memory.database import Connection


def _decoded_cursor(cursor: str) -> dict[str, object]:
    padding = "=" * (-len(cursor) % 4)
    raw = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
    assert isinstance(raw, dict)
    return cast("dict[str, object]", raw)


def _encoded_cursor(payload: dict[str, object]) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )


class _SnapshotCompositionCounter:
    def __init__(self, original: Callable[..., str]) -> None:
        self.calls = 0
        self._original = original

    def __call__(
        self,
        connection: Connection,
        *,
        upper: int,
        clause: str,
        filter_parameters: tuple[object, ...],
    ) -> str:
        self.calls += 1
        return self._original(
            connection,
            upper=upper,
            clause=clause,
            filter_parameters=filter_parameters,
        )


def _membership_connection(source_count: int) -> Connection:
    """Build one fresh synthetic projection on the shipped SQLCipher driver."""
    connection = cast("Connection", sqlcipher.connect(":memory:"))
    connection.executescript(
        """
        CREATE TABLE source_blobs (
            blob_id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            utf8_text TEXT
        );
        CREATE TABLE sources (
            source_id TEXT PRIMARY KEY,
            blob_id TEXT NOT NULL,
            origin TEXT NOT NULL,
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            authorship TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            captured_at INTEGER NOT NULL
        );
        CREATE INDEX idx_sources_blob_id ON sources(blob_id);
        CREATE VIRTUAL TABLE source_fts USING fts5(
            source_id UNINDEXED,
            capture_rowid UNINDEXED,
            utf8_text,
            original_name,
            tokenize = 'porter unicode61'
        );
        """
    )
    rowids = range(1, source_count + 1)
    connection.executemany(
        "INSERT INTO source_blobs VALUES (?, ?, ?, ?)",
        (
            (
                f"blb_synthetic_{rowid:06d}",
                f"{rowid:064x}",
                len(f"Synthetic retained row {rowid}.".encode()),
                f"Synthetic retained row {rowid}.",
            )
            for rowid in rowids
        ),
    )
    connection.executemany(
        "INSERT INTO sources "
        "(rowid, source_id, blob_id, origin, original_name, media_type, "
        "authorship, sensitivity, captured_at) "
        "VALUES (?, ?, ?, 'inbox', ?, 'text/plain', "
        "'owner', 'normal', ?)",
        (
            (
                rowid,
                f"src_synthetic_{rowid:06d}",
                f"blb_synthetic_{rowid:06d}",
                f"synthetic-{rowid:06d}.txt",
                rowid,
            )
            for rowid in rowids
        ),
    )
    connection.executemany(
        "INSERT INTO source_fts "
        "(rowid, source_id, capture_rowid, utf8_text, original_name) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            (
                rowid,
                f"src_synthetic_{rowid:06d}",
                rowid,
                f"Synthetic retained row {rowid}.",
                f"synthetic-{rowid:06d}.txt",
            )
            for rowid in rowids
            if rowid % 2
        ),
    )
    return connection


def _replace_with_legacy_projection(
    connection: Connection,
    source_count: int,
) -> None:
    connection.execute("DROP TABLE source_fts")
    connection.execute(
        "CREATE VIRTUAL TABLE source_fts USING fts5("
        "source_id UNINDEXED, utf8_text, original_name, "
        "tokenize = 'porter unicode61')"
    )
    connection.executemany(
        "INSERT INTO source_fts VALUES (?, ?, ?)",
        (
            (
                f"src_synthetic_{rowid:06d}",
                f"Synthetic legacy row {rowid}.",
                f"synthetic-{rowid:06d}.txt",
            )
            for rowid in range(1, source_count + 1, 2)
        ),
    )
    connection.execute(
        "INSERT INTO source_fts VALUES (NULL, 'Synthetic NULL row.', 'null.txt')"
    )


def _vm_work[T](
    connection: Connection,
    operation: Callable[[], T],
) -> tuple[T, int]:
    """Count deterministic SQLite VM progress callbacks for one operation."""
    steps = 0

    def count_step() -> int:
        nonlocal steps
        steps += 1
        return 0

    connection.set_progress_handler(count_step, 1)
    try:
        return operation(), steps
    finally:
        connection.set_progress_handler(None, 0)


def _fetchall(
    connection: Connection,
    query: str,
    parameters: tuple[object, ...],
) -> list[tuple[object, ...]]:
    return cast(
        "list[tuple[object, ...]]",
        connection.execute(query, parameters).fetchall(),
    )


def _limit_one_walk_work(
    connection: Connection,
    searchable: bool | None,
) -> tuple[int, int]:
    """Walk the production summary/filter query one emitted row at a time."""
    from memory.model import SourceFilters
    from memory.sources import _source_filter_clause, _source_select

    filters = SourceFilters(searchable=searchable)
    clause, parameters = _source_filter_clause(connection, filters)
    select = _source_select(connection)
    upper = int(connection.execute("SELECT max(rowid) FROM sources").fetchone()[0])
    after = 0
    emitted = 0
    work = 0
    while True:
        query = (
            select
            + " WHERE s.rowid > ? AND s.rowid <= ?"
            + clause
            + " ORDER BY s.rowid LIMIT 2"
        )
        rows, page_work = _vm_work(
            connection,
            partial(
                _fetchall,
                connection,
                query,
                (after, upper, *parameters),
            ),
        )
        work += page_work
        if not rows:
            break
        emitted += 1
        rowid = rows[0][0]
        assert isinstance(rowid, int) and not isinstance(rowid, bool)
        after = rowid
        if len(rows) == 1:
            break
    return emitted, work


class FakeClock:
    def __init__(self) -> None:
        self.timestamp = 1_810_000_000.0

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("synthetic-note.TXT", "text/plain"),
        ("synthetic-plan.md", "text/markdown"),
        ("synthetic-record.json", "application/json"),
        ("synthetic-table.csv", "text/csv"),
        ("synthetic-paper.pdf", "application/pdf"),
        ("synthetic-image.png", "image/png"),
        ("synthetic-photo.jpeg", "image/jpeg"),
        ("synthetic-photo.jpg", "image/jpeg"),
        ("synthetic-picture.webp", "image/webp"),
        ("synthetic-unknown.bin", "application/octet-stream"),
    ],
)
def test_media_type_uses_only_the_fixed_extension_allowlist(
    name: str,
    expected: str,
) -> None:
    """Catch extension drift or content sniffing changing declared custody."""
    from memory.sources import media_type_for_name

    assert media_type_for_name(name) == expected


def test_searchable_text_requires_allowlisted_text_and_strict_utf8() -> None:
    """Catch binary or malformed text being silently claimed as searchable."""
    from memory.sources import searchable_text

    chinese = "合成记录：周三散步。".encode()

    assert searchable_text("text/markdown", chinese) == "合成记录：周三散步。"
    assert searchable_text("text/plain", b"synthetic garden note") == (
        "synthetic garden note"
    )
    assert searchable_text("image/png", chinese) is None
    assert searchable_text("text/plain", b"synthetic\xffnote") is None


def test_source_and_batch_pages_keep_their_first_page_high_water_mark(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch later captures entering or reshuffling an in-flight traversal."""
    from memory.inbox import scan_inbox
    from memory.sources import list_batches, list_sources, read_batch

    clock = FakeClock()
    for name in ("a.txt", "b.txt", "c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"synthetic source {name}\n",
            encoding="utf-8",
        )
    first_batch = scan_inbox(synthetic_store, clock=clock)
    (synthetic_store.inbox / "d-before.txt").write_text(
        "synthetic second batch source\n",
        encoding="utf-8",
    )
    second_batch = scan_inbox(synthetic_store, clock=clock)

    first_sources = list_sources(synthetic_store, limit=2)
    first_batches = list_batches(synthetic_store, limit=1)
    assert first_sources.has_more is True
    assert first_sources.next_cursor is not None
    assert first_batches.has_more is True
    assert first_batches.next_cursor is not None

    (synthetic_store.inbox / "e-later.txt").write_text(
        "synthetic later source\n",
        encoding="utf-8",
    )
    later_batch = scan_inbox(synthetic_store, clock=clock)

    second_sources = list_sources(
        synthetic_store,
        cursor=first_sources.next_cursor,
        limit=2,
    )
    fresh_sources = list_sources(synthetic_store, limit=100)
    fresh_batches = list_batches(synthetic_store, limit=100)
    second_batches = list_batches(
        synthetic_store,
        cursor=first_batches.next_cursor,
        limit=1,
    )
    detail = read_batch(synthetic_store, first_batch.batch_id)

    assert [source.original_name for source in first_sources.items] == [
        "a.txt",
        "b.txt",
    ]
    assert [source.original_name for source in second_sources.items] == [
        "c.txt",
        "d-before.txt",
    ]
    assert second_sources.has_more is False
    assert [source.original_name for source in fresh_sources.items] == [
        "a.txt",
        "b.txt",
        "c.txt",
        "d-before.txt",
        "e-later.txt",
    ]
    assert [batch.batch_id for batch in fresh_batches.items] == [
        first_batch.batch_id,
        second_batch.batch_id,
        later_batch.batch_id,
    ]
    assert [batch.batch_id for batch in second_batches.items] == [second_batch.batch_id]
    assert second_batches.has_more is False
    assert detail.batch.batch_id == first_batch.batch_id
    assert [source.original_name for source in detail.sources] == [
        "a.txt",
        "b.txt",
        "c.txt",
    ]


def test_source_and_batch_pages_reject_oversized_rowid_coordinates(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch model-controlled cursor integers reaching either SQLite pager."""
    from memory.errors import StaleCursorError
    from memory.inbox import scan_inbox
    from memory.sources import list_batches, list_sources

    clock = FakeClock()
    for name in ("synthetic-coordinate-a.txt", "synthetic-coordinate-b.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic cursor coordinates for {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=clock)
    (synthetic_store.inbox / "synthetic-coordinate-c.txt").write_text(
        "Synthetic second-batch cursor coordinate.\n",
        encoding="utf-8",
    )
    scan_inbox(synthetic_store, clock=clock)

    source_cursor = list_sources(synthetic_store, limit=1).next_cursor
    batch_cursor = list_batches(synthetic_store, limit=1).next_cursor
    assert source_cursor is not None
    assert batch_cursor is not None

    for cursor, list_page in (
        (source_cursor, list_sources),
        (batch_cursor, list_batches),
    ):
        padding = "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
        payload["after"] = 2**100
        payload["upper"] = 2**100
        oversized = (
            base64.urlsafe_b64encode(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        with pytest.raises(StaleCursorError):
            list_page(synthetic_store, cursor=oversized, limit=1)


def test_duplicate_capture_raises_effective_but_not_declared_sensitivity(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch dedup lowering sensitivity or rewriting earlier provenance."""
    from memory.inbox import scan_inbox
    from memory.sources import list_sources

    body = b"synthetic shared custody bytes"
    (synthetic_store.inbox / "first.txt").write_bytes(body)
    scan_inbox(
        synthetic_store,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    (synthetic_store.inbox / "second.bin").write_bytes(body)
    scan_inbox(
        synthetic_store,
        authorship=Authorship.UNKNOWN,
        sensitivity=Sensitivity.RESTRICTED,
        clock=FakeClock(),
    )

    page = list_sources(synthetic_store, limit=100)

    assert [source.declared_sensitivity for source in page.items] == [
        Sensitivity.NORMAL,
        Sensitivity.RESTRICTED,
    ]
    assert [source.effective_sensitivity for source in page.items] == [
        Sensitivity.RESTRICTED,
        Sensitivity.RESTRICTED,
    ]
    assert [source.authorship for source in page.items] == [
        Authorship.OWNER,
        Authorship.UNKNOWN,
    ]
    assert [source.searchable for source in page.items] == [True, False]
    assert {source.origin for source in page.items} == {SourceCaptureOrigin.INBOX}


def test_store_status_searchable_count_ignores_an_orphaned_projection_row(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a searchable count that trusts the projection instead of custody.

    `source_fts` carries `source_id UNINDEXED`, so the obvious cheap rewrite of
    this count -- `count(DISTINCT source_id)` over the projection -- reads the
    disposable side of the Store as if it were the authoritative one. A row
    naming a capture the Store does not hold then inflates the number the Skill
    uses to decide whether coverage is thin. The count must stay a count of
    captures.
    """
    from memory.database import writer_session
    from memory.inbox import scan_inbox
    from memory.sources import get_store_status

    (synthetic_store.inbox / "searchable.md").write_text(
        "A synthetic note about the copper gallery.\n",
        encoding="utf-8",
    )
    scan_inbox(synthetic_store, clock=FakeClock())

    with writer_session(synthetic_store) as connection:
        connection.execute(
            "INSERT INTO source_fts (source_id, utf8_text) VALUES (?, ?)",
            ("src_synthetic_orphan", "an orphaned projection row"),
        )

    status = get_store_status(synthetic_store)

    assert status.source_count == 1
    assert status.searchable_count == 1
    assert status.unsearchable_count == 0


def test_page_bound_is_five_hundred_and_the_refusal_names_it(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the raised page ceiling, or a refusal that still hides the bound."""
    from memory.errors import InvalidArgumentError
    from memory.sources import MAX_PAGE_SIZE, list_sources

    assert MAX_PAGE_SIZE == 500
    assert list_sources(synthetic_store, limit=MAX_PAGE_SIZE).items == ()
    with pytest.raises(InvalidArgumentError) as refused:
        list_sources(synthetic_store, limit=MAX_PAGE_SIZE + 1)

    # The one declared detail key the envelope had never emitted. Without it a
    # caller binary-searches for a ceiling the Store already knows.
    assert refused.value.details == {"limit": MAX_PAGE_SIZE}


def test_source_enumeration_filters_narrow_origin_and_projection_membership(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the coverage gap being enumerable only by reading every capture."""
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import list_sources

    (synthetic_store.inbox / "note.txt").write_text("A searchable note.\n", "utf-8")
    (synthetic_store.inbox / "figure.png").write_bytes(b"\x89PNG\x00\xff")
    scan_inbox(synthetic_store, clock=FakeClock())

    everything = list_sources(synthetic_store)
    searchable = list_sources(synthetic_store, filters=SourceFilters(searchable=True))
    unsearchable = list_sources(
        synthetic_store, filters=SourceFilters(searchable=False)
    )
    from_inbox = list_sources(
        synthetic_store, filters=SourceFilters(origin=SourceCaptureOrigin.INBOX)
    )
    corrections = list_sources(
        synthetic_store,
        filters=SourceFilters(origin=SourceCaptureOrigin.OWNER_CORRECTION),
    )

    assert len(everything.items) == 2
    # A filtered page can never hold a row whose own flag contradicts it: both
    # sides read the same projection-membership expression.
    assert [source.original_name for source in searchable.items] == ["note.txt"]
    assert all(source.searchable for source in searchable.items)
    assert [source.original_name for source in unsearchable.items] == ["figure.png"]
    assert not any(source.searchable for source in unsearchable.items)
    assert len(from_inbox.items) == 2
    assert corrections.items == ()


def test_canonical_membership_queries_constrain_fts_by_integer_rowid() -> None:
    """Catch any production membership surface scanning an UNINDEXED source ID."""
    from memory.model import SourceFilters
    from memory.sources import (
        _source_filter_clause,
        _source_list_snapshot_select,
        _source_select,
    )

    connection = _membership_connection(8)
    try:
        clause, parameters = _source_filter_clause(
            connection, SourceFilters(searchable=True)
        )
        production_queries = (
            _source_list_snapshot_select(clause),
            _source_select(connection)
            + " WHERE s.rowid > ? AND s.rowid <= ?"
            + clause
            + " ORDER BY s.rowid LIMIT ?",
        )
        query_parameters = (
            (8, *parameters),
            (0, 8, *parameters, 2),
        )
        for query, bound in zip(production_queries, query_parameters, strict=True):
            details = [
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN " + query,
                    bound,
                ).fetchall()
                if "VIRTUAL TABLE" in str(row[3])
            ]
            assert details
            assert all(":=" in detail for detail in details), details
    finally:
        connection.close()


def test_canonical_visible_search_fetch_is_page_sized_and_fts_free() -> None:
    """Catch one visible page rescanning the whole disposable projection."""
    from memory.retrieval import _search_select_sql

    work: list[int] = []
    for size in (64, 256):
        connection = _membership_connection(size)
        try:
            query = _search_select_sql(connection, "?, ?, ?")
            plan = tuple(
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN " + query,
                    (1, 3, 5),
                ).fetchall()
            )
            assert not any("source_fts" in detail for detail in plan), plan
            rows, steps = _vm_work(
                connection,
                partial(_fetchall, connection, query, (1, 3, 5)),
            )
            assert [row[0] for row in rows] == [1, 3, 5]
            work.append(steps)
        finally:
            connection.close()

    assert work[1] <= work[0] * 3 // 2, work


@pytest.mark.parametrize("searchable", [True, False])
def test_first_membership_composition_has_bounded_linear_vm_work(
    searchable: bool,
) -> None:
    """Catch the first filtered cursor composition returning to quadratic work."""
    from memory.model import SourceFilters
    from memory.sources import _source_filter_clause, _source_list_snapshot_digest

    work: list[int] = []
    for size in (48, 96):
        connection = _membership_connection(size)
        try:
            clause, parameters = _source_filter_clause(
                connection, SourceFilters(searchable=searchable)
            )
            _digest, steps = _vm_work(
                connection,
                partial(
                    _source_list_snapshot_digest,
                    connection,
                    upper=size,
                    clause=clause,
                    filter_parameters=parameters,
                ),
            )
            work.append(steps)
        finally:
            connection.close()

    assert work[1] <= work[0] * 5 // 2, work


@pytest.mark.parametrize("searchable", [True, False, None])
def test_limit_one_summary_walk_has_bounded_linear_vm_work(
    searchable: bool | None,
) -> None:
    """Catch each small keyset page doing Store-size membership work."""
    observations: list[tuple[int, int]] = []
    for size in (32, 64):
        connection = _membership_connection(size)
        try:
            observations.append(_limit_one_walk_work(connection, searchable))
        finally:
            connection.close()

    expected_emitted = (16, 32) if searchable is not None else (32, 64)
    assert tuple(value[0] for value in observations) == expected_emitted
    assert observations[1][1] <= observations[0][1] * 5 // 2, observations


def test_legacy_status_membership_composes_once_and_scales_linearly() -> None:
    """Catch pre-reindex status correlating one UNINDEXED scan per source."""
    from memory.sources import _source_status_membership_sql

    work: list[int] = []
    for size in (48, 96):
        connection = _membership_connection(size)
        try:
            _replace_with_legacy_projection(connection, size)
            query = (
                "SELECT count(*) FROM sources AS s WHERE "
                + _source_status_membership_sql(connection)
            )
            plan = tuple(
                str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN " + query)
            )
            result, steps = _vm_work(
                connection,
                partial(_fetchall, connection, query, ()),
            )
            assert result == [(size // 2,)]
            assert any("LIST SUBQUERY" in detail for detail in plan), plan
            assert not any("CORRELATED" in detail for detail in plan), plan
            work.append(steps)
        finally:
            connection.close()

    assert work[1] <= work[0] * 5 // 2, work


def test_pre_reindex_projection_keeps_legacy_source_id_membership(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the rowid predicate being forced onto an old divergent projection."""
    from memory.database import writer_session
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import get_store_status, list_sources

    (synthetic_store.inbox / "a-synthetic-note.txt").write_text(
        "Synthetic legacy first row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "b-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (synthetic_store.inbox / "c-synthetic-note.txt").write_text(
        "Synthetic legacy divergent row.\n", encoding="utf-8"
    )
    scan_inbox(synthetic_store, clock=FakeClock())
    captured = list_sources(synthetic_store, limit=10).items
    text_sources = [source for source in captured if source.media_type == "text/plain"]

    with writer_session(synthetic_store) as connection:
        rows = connection.execute(
            "SELECT source_id, utf8_text, original_name FROM source_fts ORDER BY rowid"
        ).fetchall()
        connection.execute("DROP TABLE source_fts")
        connection.execute(
            "CREATE VIRTUAL TABLE source_fts USING fts5("
            "source_id UNINDEXED, utf8_text, original_name, "
            "tokenize = 'porter unicode61')"
        )
        for row in rows:
            connection.execute(
                "INSERT INTO source_fts (source_id, utf8_text, original_name) "
                "VALUES (?, ?, ?)",
                row,
            )

    searchable = list_sources(
        synthetic_store,
        limit=10,
        filters=SourceFilters(searchable=True),
    ).items
    unsearchable = list_sources(
        synthetic_store,
        limit=10,
        filters=SourceFilters(searchable=False),
    ).items

    assert [source.source_id for source in searchable] == [
        source.source_id for source in text_sources
    ]
    assert [source.original_name for source in unsearchable] == [
        "b-synthetic-image.png"
    ]
    assert get_store_status(synthetic_store).searchable_count == 2
    assert get_store_status(synthetic_store).reindex_required is True


@pytest.mark.parametrize(
    ("searchable", "suffix"),
    [(True, "txt"), (False, "png")],
)
def test_quiescent_projection_filtered_continuation_skips_membership_composition(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    searchable: bool,
    suffix: str,
) -> None:
    """Catch one whole-Store membership hash being rebuilt for every page."""
    import memory.sources as source_module
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters

    for name in ("a", "b", "c"):
        path = synthetic_store.inbox / f"{name}.{suffix}"
        if searchable:
            path.write_text(f"Synthetic retained source {name}.\n", encoding="utf-8")
        else:
            path.write_bytes(b"\x89PNG\x00\xff" + name.encode("ascii"))
    scan_inbox(synthetic_store, clock=FakeClock())

    compositions = _SnapshotCompositionCounter(
        source_module._source_list_snapshot_digest
    )
    monkeypatch.setattr(
        source_module,
        "_source_list_snapshot_digest",
        compositions,
    )
    filters = SourceFilters(searchable=searchable)
    first = source_module.list_sources(synthetic_store, limit=1, filters=filters)
    assert first.next_cursor is not None
    assert compositions.calls == 1

    second = source_module.list_sources(
        synthetic_store,
        cursor=first.next_cursor,
        limit=1,
        filters=filters,
    )

    assert [source.original_name for source in second.items] == [f"b.{suffix}"]
    assert compositions.calls == 1


def test_projection_filtered_cursor_streams_the_existing_canonical_membership(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the streamed digest changing the snapshot's byte definition."""
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import _read_connection, list_sources

    for name in ("合成-a.txt", "synthetic-b.txt", "synthetic-c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())

    first = list_sources(
        synthetic_store,
        limit=1,
        filters=SourceFilters(searchable=True),
    )
    assert first.next_cursor is not None
    payload = _decoded_cursor(first.next_cursor)
    upper = payload["upper"]
    assert isinstance(upper, int) and not isinstance(upper, bool)
    with _read_connection(synthetic_store) as (connection, _identity):
        rows = connection.execute(
            "SELECT s.rowid, s.source_id FROM sources AS s "
            "WHERE s.rowid <= ? AND EXISTS("
            "SELECT 1 FROM source_fts AS admitted "
            "WHERE admitted.source_id = s.source_id) = 1 ORDER BY s.rowid",
            (upper,),
        ).fetchall()
    canonical = json.dumps(
        {
            "entries": [[int(row[0]), str(row[1])] for row in rows],
            "upper": upper,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert payload["snapshot"] == hashlib.sha256(canonical).hexdigest()


def test_changed_generation_with_same_membership_rechecks_once_and_refreshes_cursor(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch generation-only staleness or a stale generation carried forward."""
    import memory.sources as source_module
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters

    for name in ("a.txt", "b.txt", "c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())
    filters = SourceFilters(searchable=True)
    first = source_module.list_sources(synthetic_store, limit=1, filters=filters)
    assert first.next_cursor is not None
    first_payload = _decoded_cursor(first.next_cursor)
    first_generation = first_payload["generation"]
    assert isinstance(first_generation, int) and not isinstance(first_generation, bool)

    # This capture advances the Store generation but lands above the cursor's
    # high-water mark, so exact membership under `upper` is unchanged.
    (synthetic_store.inbox / "z-later.txt").write_text(
        "Synthetic later source outside the in-flight walk.\n",
        encoding="utf-8",
    )
    scan_inbox(synthetic_store, clock=FakeClock())

    compositions = _SnapshotCompositionCounter(
        source_module._source_list_snapshot_digest
    )
    monkeypatch.setattr(
        source_module,
        "_source_list_snapshot_digest",
        compositions,
    )
    second = source_module.list_sources(
        synthetic_store,
        cursor=first.next_cursor,
        limit=1,
        filters=filters,
    )
    assert second.next_cursor is not None
    second_payload = _decoded_cursor(second.next_cursor)
    second_generation = second_payload["generation"]
    assert isinstance(second_generation, int) and not isinstance(
        second_generation, bool
    )

    assert compositions.calls == 1
    assert [source.original_name for source in second.items] == ["b.txt"]
    assert second_payload["snapshot"] == first_payload["snapshot"]
    assert second_generation > first_generation


def test_projection_filtered_source_cursor_stales_when_reindex_adds_earlier_member(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a rebuilt projection adding an eligible source behind `after`."""
    from memory.database import writer_session
    from memory.errors import StaleCursorError
    from memory.inbox import scan_inbox
    from memory.maintenance import rebuild_search_projections
    from memory.model import SourceFilters
    from memory.sources import list_sources

    for name in ("a.txt", "b.txt", "c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())
    sources = list_sources(synthetic_store, limit=100).items
    assert [source.original_name for source in sources] == [
        "a.txt",
        "b.txt",
        "c.txt",
    ]
    source_a = next(source for source in sources if source.original_name == "a.txt")
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "DELETE FROM source_fts WHERE source_id = ?",
            (source_a.source_id,),
        )

    filters = SourceFilters(searchable=True)
    first = list_sources(synthetic_store, limit=1, filters=filters)
    assert [source.original_name for source in first.items] == ["b.txt"]
    assert first.next_cursor is not None

    rebuild_search_projections(synthetic_store)

    import memory.sources as source_module

    compositions = _SnapshotCompositionCounter(
        source_module._source_list_snapshot_digest
    )
    monkeypatch.setattr(
        source_module,
        "_source_list_snapshot_digest",
        compositions,
    )

    try:
        list_sources(
            synthetic_store,
            cursor=first.next_cursor,
            limit=1,
            filters=filters,
        )
    except StaleCursorError:
        pass
    else:
        pytest.fail("cursor silently skipped reindexed source a.txt and returned c.txt")
    assert compositions.calls == 1


def test_projection_filtered_source_cursor_continues_across_idempotent_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch projection-write identity replacing eligible membership identity."""
    from memory.inbox import scan_inbox
    from memory.maintenance import rebuild_search_projections
    from memory.model import SourceFilters
    from memory.sources import list_sources

    for name in ("a.txt", "b.txt", "c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())
    filters = SourceFilters(searchable=True)
    first = list_sources(synthetic_store, limit=1, filters=filters)
    assert [source.original_name for source in first.items] == ["a.txt"]
    assert first.next_cursor is not None

    report = rebuild_search_projections(synthetic_store)
    second = list_sources(
        synthetic_store,
        cursor=first.next_cursor,
        limit=1,
        filters=filters,
    )

    assert report.source_rows == 3
    assert [source.original_name for source in second.items] == ["b.txt"]
    assert second.has_more is True


def test_only_projection_filtered_source_cursor_requires_membership_snapshot(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch legacy searchable cursors resuming, or unfiltered cursors changing."""
    from memory.errors import StaleCursorError
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import list_sources, owner_filter_binding

    for name in ("a.txt", "b.txt", "c.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())

    filters = SourceFilters(searchable=True)
    filtered = list_sources(synthetic_store, limit=1, filters=filters)
    unfiltered = list_sources(synthetic_store, limit=1)
    origin_only = list_sources(
        synthetic_store,
        limit=1,
        filters=SourceFilters(origin=SourceCaptureOrigin.INBOX),
    )
    assert filtered.next_cursor is not None
    assert unfiltered.next_cursor is not None
    assert origin_only.next_cursor is not None

    filtered_payload = _decoded_cursor(filtered.next_cursor)
    filtered_payload.pop("snapshot", None)
    legacy_filtered = _encoded_cursor(filtered_payload)

    with pytest.raises(StaleCursorError):
        list_sources(
            synthetic_store,
            cursor=legacy_filtered,
            limit=1,
            filters=filters,
        )

    unfiltered_payload = _decoded_cursor(unfiltered.next_cursor)
    origin_payload = _decoded_cursor(origin_only.next_cursor)
    resumed = list_sources(
        synthetic_store,
        cursor=unfiltered.next_cursor,
        limit=1,
    )
    resumed_origin = list_sources(
        synthetic_store,
        cursor=origin_only.next_cursor,
        limit=1,
        filters=SourceFilters(origin=SourceCaptureOrigin.INBOX),
    )

    assert "snapshot" not in unfiltered_payload
    assert "generation" not in unfiltered_payload
    assert "snapshot" not in origin_payload
    assert "generation" not in origin_payload
    assert unfiltered_payload["binding"] == owner_filter_binding(
        {"origin": None, "searchable": None}
    )
    assert origin_payload["binding"] == owner_filter_binding(
        {"origin": "inbox", "searchable": None}
    )
    assert [source.original_name for source in resumed.items] == ["b.txt"]
    assert [source.original_name for source in resumed_origin.items] == ["b.txt"]


def test_projection_filtered_cursor_rejects_coordinate_only_membership_binding(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the stronger membership rule reusing a pre-fidelity cursor."""
    from memory.errors import StaleCursorError
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import list_sources, owner_filter_binding

    for name in ("a.txt", "b.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())
    filters = SourceFilters(searchable=True)
    first = list_sources(synthetic_store, limit=1, filters=filters)
    assert first.next_cursor is not None
    payload = _decoded_cursor(first.next_cursor)
    payload["binding"] = owner_filter_binding({"origin": None, "searchable": True})

    with pytest.raises(StaleCursorError):
        list_sources(
            synthetic_store,
            cursor=_encoded_cursor(payload),
            limit=1,
            filters=filters,
        )


def test_projection_filtered_source_cursor_rejects_invalid_snapshot_state(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch malformed generation or digest state bypassing recomposition."""
    from memory.errors import StaleCursorError
    from memory.inbox import scan_inbox
    from memory.model import SourceFilters
    from memory.sources import list_sources

    for name in ("a.txt", "b.txt"):
        (synthetic_store.inbox / name).write_text(
            f"Synthetic retained source {name}.\n",
            encoding="utf-8",
        )
    scan_inbox(synthetic_store, clock=FakeClock())
    filters = SourceFilters(searchable=True)
    first = list_sources(synthetic_store, limit=1, filters=filters)
    assert first.next_cursor is not None
    valid = _decoded_cursor(first.next_cursor)

    invalid_payloads: list[dict[str, object]] = []
    missing_generation = dict(valid)
    missing_generation.pop("generation", None)
    invalid_payloads.append(missing_generation)
    for generation in (True, -1, "0", None, 1.5):
        malformed_generation = dict(valid)
        malformed_generation["generation"] = generation
        invalid_payloads.append(malformed_generation)
    for snapshot in (None, 7, "", "a" * 63, "A" * 64, "g" * 64):
        malformed_snapshot = dict(valid)
        malformed_snapshot["snapshot"] = snapshot
        invalid_payloads.append(malformed_snapshot)

    for payload in invalid_payloads:
        with pytest.raises(StaleCursorError):
            list_sources(
                synthetic_store,
                cursor=_encoded_cursor(payload),
                limit=1,
                filters=filters,
            )


def test_a_reread_batch_keeps_what_its_own_scan_reported(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch duplicates, issues, and continuation surviving only the scan itself."""
    from memory.inbox import scan_inbox
    from memory.sources import list_batches, read_batch

    body = "The same synthetic bytes twice over.\n"
    for name in ("first.txt", "second.txt"):
        (synthetic_store.inbox / name).write_text(body, encoding="utf-8")
    scanned = scan_inbox(synthetic_store, clock=FakeClock())

    listed = list_batches(synthetic_store).items[0]
    read = read_batch(synthetic_store, scanned.batch_id).batch

    assert len(scanned.duplicates) == 1
    assert listed.duplicates == scanned.duplicates
    assert read.duplicates == scanned.duplicates
    assert listed.has_more is scanned.has_more
    assert listed.issues == scanned.issues
    # Review state is derived at read time from the change set, so a batch with
    # none reads as unreviewed rather than as an absent field.
    assert listed.review_state == "none"
    assert listed.change_set_id is None
    assert listed.application_id is None
