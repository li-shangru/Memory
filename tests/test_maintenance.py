"""Owner maintenance: search projection rebuild and reindex detection."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import cast

import pytest
from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]  # no stubs
from synthetic import (
    HEDGE_BODY,
    FakeClock,
    apply_ready,
    capture_batch,
    capture_text,
    ready_items,
    single_item_edit,
    store_one_memory,
    two_source_linked_apply,
)

from memory import maintenance, reviews
from memory.database import Connection, writer_session
from memory.inbox import scan_inbox
from memory.maintenance import GuardCandidate, lint_guards, rebuild_search_projections
from memory.memories import get_memory, search_memories
from memory.model import (
    AddGuardLink,
    ChangeSetAdapterOrigin,
    ChangeSetView,
    GuardLinkInput,
    MemoryKind,
    RevokeGuardLink,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceFilters,
)
from memory.retrieval import read_source, search_sources
from memory.reviews import edit_change_set
from memory.sources import (
    _read_connection,
    get_store_status,
    list_sources,
    owner_source_detail,
    owner_source_projection_coverage,
)

_LEGACY_SOURCE_FTS_SQL = (
    "CREATE VIRTUAL TABLE source_fts USING fts5("
    "source_id UNINDEXED, utf8_text, tokenize = 'unicode61')"
)
_LEGACY_MEMORY_FTS_SQL = (
    "CREATE VIRTUAL TABLE memory_fts USING fts5("
    "revision_id UNINDEXED, statement, tags, tokenize = 'unicode61')"
)


def _memory_projection_connection(memory_count: int) -> Connection:
    """Build a synthetic memory projection on the shipped SQLCipher driver."""
    connection = cast("Connection", sqlcipher.connect(":memory:"))
    connection.executescript(
        """
        CREATE TABLE memory_revisions (
            revision_id TEXT PRIMARY KEY,
            statement TEXT NOT NULL,
            tags_json TEXT NOT NULL
        );
        CREATE TABLE current_memory_heads (
            lineage_id TEXT PRIMARY KEY,
            revision_id TEXT NOT NULL UNIQUE
        );
        CREATE VIRTUAL TABLE memory_fts USING fts5(
            revision_id UNINDEXED,
            statement,
            tags,
            tokenize = 'porter unicode61'
        );
        """
    )
    rowids = range(1, memory_count + 1)
    connection.executemany(
        "INSERT INTO memory_revisions "
        "(rowid, revision_id, statement, tags_json) VALUES (?, ?, ?, ?)",
        (
            (
                rowid,
                f"mem_synthetic_{rowid:06d}",
                f"Synthetic retained memory {rowid}.",
                '["synthetic","retained"]',
            )
            for rowid in rowids
        ),
    )
    connection.executemany(
        "INSERT INTO current_memory_heads (lineage_id, revision_id) VALUES (?, ?)",
        (
            (
                f"lin_synthetic_{rowid:06d}",
                f"mem_synthetic_{rowid:06d}",
            )
            for rowid in rowids
        ),
    )
    connection.executemany(
        "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
        (
            (
                f"mem_synthetic_{rowid:06d}",
                f"Synthetic retained memory {rowid}.",
                "synthetic retained",
            )
            for rowid in rowids
        ),
    )
    return connection


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


def _downgrade_fts_tokenizer(connection: Connection) -> None:
    """Swap both FTS tables to the pre-porter tokenizer, preserving their rows."""
    source_rows = connection.execute(
        "SELECT source_id, utf8_text FROM source_fts"
    ).fetchall()
    memory_rows = connection.execute(
        "SELECT revision_id, statement, tags FROM memory_fts"
    ).fetchall()
    connection.execute("DROP TABLE source_fts")
    connection.execute("DROP TABLE memory_fts")
    connection.execute(_LEGACY_SOURCE_FTS_SQL)
    connection.execute(_LEGACY_MEMORY_FTS_SQL)
    for source_id, text in source_rows:
        connection.execute(
            "INSERT INTO source_fts (source_id, utf8_text) VALUES (?, ?)",
            (source_id, text),
        )
    for revision_id, statement, tags in memory_rows:
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            (revision_id, statement, tags),
        )


def test_memory_projection_coverage_composes_unindexed_rows_once() -> None:
    """Keep public and owner coverage linear in Store size.

    `memory_fts.revision_id` is UNINDEXED.  A correlated exact-row EXISTS is
    correct but scans the whole FTS table once per current head, making an
    audit or every search page quadratic.  The canonical ID composition must
    instead scan the projection once and materialize one reusable set.
    """
    from memory.memories import (
        _CANONICAL_MEMORY_PROJECTION_IDS_SQL,
        _memory_coverage,
        owner_memory_projection_coverage,
    )

    work: list[tuple[int, int]] = []
    for size in (64, 128):
        connection = _memory_projection_connection(size)
        try:
            plan = tuple(
                str(row[3])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN " + _CANONICAL_MEMORY_PROJECTION_IDS_SQL
                ).fetchall()
            )
            fts_steps = tuple(
                detail for detail in plan if "indexed VIRTUAL TABLE" in detail
            )
            assert len(fts_steps) == 1, plan
            assert "SCAN indexed VIRTUAL TABLE" in fts_steps[0], plan
            assert "EXISTS" not in fts_steps[0], plan
            public, public_steps = _vm_work(
                connection, partial(_memory_coverage, connection, size)
            )
            owner, owner_steps = _vm_work(
                connection, partial(owner_memory_projection_coverage, connection)
            )
            assert public.searchable == size
            assert public.unsearchable == 0
            assert owner.indexed_current_heads == size
            assert owner.missing_current_head_rows == 0
            work.append((public_steps, owner_steps))
        finally:
            connection.close()

    assert work[1][0] <= work[0][0] * 5 // 2, work
    assert work[1][1] <= work[0][1] * 5 // 2, work


def _downgrade_to_legacy_fts(paths: RuntimePaths) -> None:
    """Recreate a faithful pre-porter v1.0 store: legacy FTS, no guard tables."""
    with writer_session(paths) as connection:
        _downgrade_fts_tokenizer(connection)
        connection.execute("DROP TABLE memory_guard_links")
        connection.execute("DROP TABLE change_revision_guard_links")
        connection.execute("DROP TABLE change_revision_guard_revocations")


def test_fresh_store_needs_no_reindex_and_stems(
    synthetic_store: RuntimePaths,
) -> None:
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="stemming.txt",
        body="The owner loved the walled garden.\n",
        statement="The owner loved the walled garden.",
        excerpt="loved the walled garden",
    )
    status = get_store_status(synthetic_store)
    assert status.reindex_required is False
    assert [
        hit.memory.statement for hit in search_memories(synthetic_store, "loving").items
    ] == ["The owner loved the walled garden."]


def test_legacy_store_reports_reindex_and_rebuild_restores_stemming(
    synthetic_store: RuntimePaths,
) -> None:
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="legacy.txt",
        body="She was loving the amber studio.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    _downgrade_to_legacy_fts(synthetic_store)
    assert get_store_status(synthetic_store).reindex_required is True
    assert search_sources(synthetic_store, "love").items == ()

    report = rebuild_search_projections(synthetic_store)
    assert report.source_rows == 1
    # `rebuild_search_projections` runs inside a writer session, and the
    # writer transaction's BEGIN-time ensure recreates the missing guard-link
    # tables before the rebuild's own work runs, so the store is fully
    # healed by the time this rebuild commits.
    assert get_store_status(synthetic_store).reindex_required is False
    hits = search_sources(synthetic_store, "love").items
    assert [hit.source.original_name for hit in hits] == ["legacy.txt"]


def test_fts_only_downgrade_clears_reindex_after_rebuild(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch reindex_required staying stuck when guard tables are already present."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="tokenizer-only.txt",
        body="She was loving the amber studio.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    with writer_session(synthetic_store) as connection:
        _downgrade_fts_tokenizer(connection)
    assert get_store_status(synthetic_store).reindex_required is True

    rebuild_search_projections(synthetic_store)

    assert get_store_status(synthetic_store).reindex_required is False


def test_rebuild_indexes_the_capture_filename(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the search projection leaving every retained filename unsearchable."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        # The body deliberately shares no word with the name: only the indexed
        # filename can answer this query.
        name="orchard-lantern-schedule.md",
        body="Two rows were pruned before the frost.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )

    rebuild_search_projections(synthetic_store)

    hits = search_sources(synthetic_store, "orchard").items
    assert [hit.source.original_name for hit in hits] == ["orchard-lantern-schedule.md"]


def test_capture_indexes_the_filename_without_a_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a freshly captured filename reaching only the literal pass.

    The query has to be one only the projection can answer. A literal
    substring of the name is not: the ladder folds `sources.original_name`
    into its own haystack and never reads the projection for it, so `orchard`
    against `orchard-lantern-schedule.md` passed with capture-time filename
    indexing removed entirely -- and so did the whole suite. What the new
    `source_fts.original_name` column adds is the *stemmed* pass, so a stemmed
    query is what tests it: `schedules` stems to the `schedule` in the name and
    occurs nowhere as a substring.
    """
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="orchard-lantern-schedule.md",
        body="Two rows were pruned before the frost.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )

    literal = search_sources(synthetic_store, "orchard").items
    stemmed = search_sources(synthetic_store, "schedules").items

    assert [hit.source.original_name for hit in literal] == [
        "orchard-lantern-schedule.md"
    ]
    assert "schedules" not in "orchard-lantern-schedule.md"
    assert [hit.source.original_name for hit in stemmed] == [
        "orchard-lantern-schedule.md"
    ]


def test_rebuild_is_idempotent(synthetic_store: RuntimePaths) -> None:
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="idem.txt",
        body="Idempotent rebuild keeps one row.\n",
        statement="Idempotent rebuild keeps one row.",
        excerpt="rebuild keeps one row",
    )

    first = rebuild_search_projections(synthetic_store)
    with writer_session(synthetic_store) as connection:
        assert connection.execute("SELECT count(*) FROM memory_fts").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM source_fts").fetchone() == (1,)

    second = rebuild_search_projections(synthetic_store)
    with writer_session(synthetic_store) as connection:
        assert connection.execute("SELECT count(*) FROM memory_fts").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM source_fts").fetchone() == (1,)

    assert first.memory_rows == second.memory_rows == 1
    assert first.source_rows == second.source_rows == 1


def test_rebuild_reproduces_ingestion_membership_on_a_mixed_store(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a rebuild admitting or dropping rows relative to ingestion's gate."""
    (synthetic_store.inbox / "mixed-text.txt").write_text(
        "Synthetic mixed-store coverage text.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "mixed-binary.png").write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\xff"
    )
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())

    rebuild_search_projections(synthetic_store)

    with _read_connection(synthetic_store) as (connection, _identity):
        coverage = owner_source_projection_coverage(connection)
    assert coverage.missing_expected_rows == 0
    assert coverage.unexpected_or_duplicate_rows == 0


def test_utf8_binary_cannot_become_searchable_through_exact_projection_row(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch coordinate-and-content fidelity admitting an ineligible capture."""
    from memory.ui.service import OwnerApplicationService

    body = b"Synthetic PNG amber studio payload.\n"
    (synthetic_store.inbox / "synthetic-utf8-image.png").write_bytes(body)
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())
    natural = list_sources(synthetic_store, limit=10).items
    assert len(natural) == 1
    assert natural[0].media_type == "image/png"
    assert natural[0].searchable is False

    target = natural[0]
    with writer_session(synthetic_store) as connection:
        row = connection.execute(
            "SELECT s.rowid, s.source_id, b.utf8_text, s.original_name "
            "FROM sources AS s "
            "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            "WHERE s.source_id = ?",
            (target.source_id,),
        ).fetchone()
        assert row is not None
        assert row[2] == body.decode("utf-8")
        connection.execute(
            "INSERT INTO source_fts "
            "(rowid, source_id, capture_rowid, utf8_text, original_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (int(row[0]), str(row[1]), int(row[0]), str(row[2]), str(row[3])),
        )

    all_sources = list_sources(synthetic_store, limit=10).items
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
    kernel_status = get_store_status(synthetic_store)
    kernel_search = search_sources(synthetic_store, "amber studio", limit=10)
    retained = read_source(synthetic_store, target.source_id)
    service = OwnerApplicationService(synthetic_store)
    owner_status = service.get_status()
    owner_search = service.search_sources("amber studio", None, 10)
    with _read_connection(synthetic_store) as (connection, _identity):
        owner_detail = owner_source_detail(connection, target.source_id)
        audit = owner_source_projection_coverage(connection)

    assert {
        "public_searchable": all_sources[0].searchable,
        "searchable_filter": [source.source_id for source in searchable],
        "unsearchable_filter": [source.source_id for source in unsearchable],
        "kernel_status": (
            kernel_status.searchable_count,
            kernel_status.unsearchable_count,
        ),
        "owner_status": (
            owner_status.store.searchable_count,
            owner_status.store.unsearchable_count,
        ),
        "owner_status_coverage": (
            owner_status.projections.sources.expected_searchable_captures,
            owner_status.projections.sources.indexed_expected_captures,
            owner_status.projections.sources.inherently_unsearchable_captures,
            owner_status.projections.sources.unexpected_or_duplicate_rows,
        ),
        "kernel_hits": [hit.source.source_id for hit in kernel_search.items],
        "owner_hits": [hit.source.source_id for hit in owner_search.items],
        "kernel_coverage": (
            kernel_search.coverage.searchable,
            kernel_search.coverage.unsearchable,
        ),
        "owner_expected_indexed": (
            owner_detail.summary.expected_searchable,
            owner_detail.summary.indexed_for_search,
        ),
        "owner_coverage": (
            owner_search.coverage.expected_searchable_captures,
            owner_search.coverage.indexed_expected_captures,
            owner_search.coverage.inherently_unsearchable_captures,
            owner_search.coverage.unexpected_or_duplicate_rows,
        ),
        "audit": (
            audit.expected_searchable_captures,
            audit.indexed_expected_captures,
            audit.inherently_unsearchable_captures,
            audit.unexpected_or_duplicate_rows,
        ),
        "read": (retained.media_type, retained.text, retained.binary),
    } == {
        "public_searchable": False,
        "searchable_filter": [],
        "unsearchable_filter": [target.source_id],
        "kernel_status": (0, 1),
        "owner_status": (0, 1),
        "owner_status_coverage": (0, 0, 1, 1),
        "kernel_hits": [],
        "owner_hits": [],
        "kernel_coverage": (0, 1),
        "owner_expected_indexed": (False, False),
        "owner_coverage": (0, 0, 1, 1),
        "audit": (0, 0, 1, 1),
        "read": ("image/png", None, body),
    }


@pytest.mark.parametrize(
    ("malformation", "target_searchable", "missing", "unexpected"),
    [
        ("duplicate", True, 0, 1),
        ("orphan", True, 0, 1),
        ("null_source", False, 1, 1),
        ("null_marker", False, 1, 1),
        ("wrong_marker", False, 1, 1),
        ("rowid_collision", False, 1, 1),
        ("text_drift", False, 1, 1),
        ("name_drift", False, 1, 1),
        ("missing_canonical", False, 1, 0),
        ("stranded_duplicate", False, 1, 1),
    ],
)
def test_canonical_membership_honesty_matrix_keeps_flags_filters_and_audit_aligned(
    synthetic_store: RuntimePaths,
    malformation: str,
    target_searchable: bool,
    missing: int,
    unexpected: int,
) -> None:
    """Catch malformed projection extras masquerading as canonical membership."""
    from memory.ui.service import OwnerApplicationService

    (synthetic_store.inbox / "a-synthetic-note.txt").write_text(
        "Synthetic alpha membership row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "b-synthetic-note.txt").write_text(
        "Synthetic beta membership row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "c-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())
    original = list_sources(synthetic_store, limit=10).items
    target = original[0]

    with writer_session(synthetic_store) as connection:
        target_rowid = int(
            connection.execute(
                "SELECT rowid FROM sources WHERE source_id = ?", (target.source_id,)
            ).fetchone()[0]
        )
        second_rowid = target_rowid + 1
        if malformation in {"missing_canonical", "stranded_duplicate"}:
            connection.execute(
                "DELETE FROM source_fts WHERE rowid = ?", (target_rowid,)
            )
        values: tuple[int, object, object] | None
        if malformation == "null_source":
            connection.execute(
                "UPDATE source_fts SET source_id = NULL WHERE rowid = ?",
                (target_rowid,),
            )
            values = None
        elif malformation == "null_marker":
            connection.execute(
                "UPDATE source_fts SET capture_rowid = NULL WHERE rowid = ?",
                (target_rowid,),
            )
            values = None
        elif malformation == "wrong_marker":
            connection.execute(
                "UPDATE source_fts SET capture_rowid = ? WHERE rowid = ?",
                (second_rowid, target_rowid),
            )
            values = None
        elif malformation == "rowid_collision":
            connection.execute(
                "UPDATE source_fts SET source_id = ?, capture_rowid = ? "
                "WHERE rowid = ?",
                (original[1].source_id, second_rowid, target_rowid),
            )
            values = None
        elif malformation == "text_drift":
            connection.execute(
                "UPDATE source_fts SET utf8_text = ? WHERE rowid = ?",
                ("Synthetic amber studio fabricated row.", target_rowid),
            )
            values = None
        elif malformation == "name_drift":
            connection.execute(
                "UPDATE source_fts SET original_name = ? WHERE rowid = ?",
                ("synthetic-orchards.txt", target_rowid),
            )
            values = None
        elif malformation == "duplicate":
            values = (1001, target.source_id, target_rowid)
        elif malformation == "orphan":
            values = (1001, "src_synthetic_orphan", 1001)
        elif malformation == "stranded_duplicate":
            values = (1001, target.source_id, target_rowid)
        else:
            values = None
        if values is not None:
            connection.execute(
                "INSERT INTO source_fts "
                "(rowid, source_id, capture_rowid, utf8_text, original_name) "
                "VALUES (?, ?, ?, 'Synthetic alpha membership malformed row.', "
                "'synthetic-malformed.txt')",
                values,
            )

    all_sources = list_sources(synthetic_store, limit=10).items
    searchable_ids = {
        source.source_id
        for source in list_sources(
            synthetic_store,
            limit=10,
            filters=SourceFilters(searchable=True),
        ).items
    }
    unsearchable_ids = {
        source.source_id
        for source in list_sources(
            synthetic_store,
            limit=10,
            filters=SourceFilters(searchable=False),
        ).items
    }
    with _read_connection(synthetic_store) as (connection, _identity):
        owner_target = owner_source_detail(connection, target.source_id)
        coverage = owner_source_projection_coverage(connection)
    search_query = {
        "text_drift": "amber studio",
        "name_drift": "orchards",
    }.get(malformation, "alpha membership")
    kernel_search = search_sources(synthetic_store, search_query, limit=10)
    service = OwnerApplicationService(synthetic_store)
    owner_search = service.search_sources(search_query, None, 10)
    kernel_search_ids = {hit.source.source_id for hit in kernel_search.items}
    owner_search_ids = {hit.source.source_id for hit in owner_search.items}
    wire_status = get_store_status(synthetic_store)
    owner_status = service.get_status().store

    assert searchable_ids | unsearchable_ids == {
        source.source_id for source in all_sources
    }
    assert searchable_ids.isdisjoint(unsearchable_ids)
    assert all(
        source.searchable == (source.source_id in searchable_ids)
        for source in all_sources
    )
    assert (target.source_id in searchable_ids) is target_searchable
    assert kernel_search_ids == owner_search_ids
    assert (target.source_id in kernel_search_ids) is target_searchable
    assert kernel_search.coverage.searchable == len(searchable_ids)
    assert kernel_search.coverage.unsearchable == len(unsearchable_ids)
    assert owner_target.summary.indexed_for_search is target_searchable
    assert coverage.expected_searchable_captures == 2
    assert coverage.indexed_expected_captures == 2 - missing
    assert coverage.missing_expected_rows == missing
    assert coverage.unexpected_or_duplicate_rows == unexpected
    assert (
        owner_status.searchable_count
        == wire_status.searchable_count
        == len(searchable_ids)
    )
    assert (
        owner_status.unsearchable_count
        == wire_status.unsearchable_count
        == len(unsearchable_ids)
    )


def test_rebuild_writes_the_canonical_source_projection_shape_and_rowids(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch rebuild DDL drift or auto-assigned FTS rowids across a binary gap."""
    (synthetic_store.inbox / "a-synthetic-note.md").write_text(
        "Synthetic first rebuild row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "b-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (synthetic_store.inbox / "c-synthetic-note.md").write_text(
        "Synthetic third rebuild row.\n", encoding="utf-8"
    )
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())

    rebuild_search_projections(synthetic_store)

    with _read_connection(synthetic_store) as (connection, _identity):
        live_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type = 'table' AND name = 'source_fts'"
            ).fetchone()[0]
        )
        rows = connection.execute(
            "SELECT f.rowid, f.capture_rowid, f.source_id, s.rowid "
            "FROM source_fts AS f "
            "JOIN sources AS s ON s.source_id = f.source_id "
            "ORDER BY s.rowid"
        ).fetchall()

    assert " ".join(live_sql.split()) == " ".join(maintenance._SOURCE_FTS_SQL.split())
    assert [(int(row[0]), int(row[1]), int(row[3])) for row in rows] == [
        (1, 1, 1),
        (3, 3, 3),
    ]


def test_pre_reindex_capture_keeps_legacy_auto_rowids_until_rebuild(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a new-shape insert colliding with a legacy projection after custody."""
    with writer_session(synthetic_store) as connection:
        connection.execute("DROP TABLE source_fts")
        connection.execute(
            "CREATE VIRTUAL TABLE source_fts USING fts5(\n"
            "    source_id UNINDEXED,\n"
            "    utf8_text,\n"
            "    original_name,\n"
            "    tokenize = 'porter unicode61'\n"
            ")"
        )

    (synthetic_store.inbox / "a-synthetic-note.md").write_text(
        "Synthetic first legacy row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "b-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (synthetic_store.inbox / "c-synthetic-note.md").write_text(
        "Synthetic third legacy row.\n", encoding="utf-8"
    )
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())
    (synthetic_store.inbox / "d-synthetic-note.md").write_text(
        "Synthetic fourth legacy row.\n", encoding="utf-8"
    )
    last_batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock()
    )

    assert get_store_status(synthetic_store).reindex_required is True
    with _read_connection(synthetic_store) as (connection, _identity):
        legacy_row = connection.execute(
            "SELECT f.rowid, s.rowid FROM source_fts AS f "
            "JOIN sources AS s ON s.source_id = f.source_id "
            "WHERE s.source_id = ?",
            (last_batch.source_ids[0],),
        ).fetchone()
    assert legacy_row == (3, 4)
    legacy_search = search_sources(synthetic_store, "legacy row", limit=10)
    assert [hit.source.original_name for hit in legacy_search.items] == [
        "a-synthetic-note.md",
        "c-synthetic-note.md",
        "d-synthetic-note.md",
    ]
    assert legacy_search.coverage.searchable == 3
    assert legacy_search.coverage.unsearchable == 1
    assert legacy_search.coverage.enumerated == 3
    assert legacy_search.coverage.total == 4

    rebuild_search_projections(synthetic_store)

    assert get_store_status(synthetic_store).reindex_required is False
    with _read_connection(synthetic_store) as (connection, _identity):
        rebuilt_rows = connection.execute(
            "SELECT f.rowid, f.capture_rowid, s.rowid "
            "FROM source_fts AS f "
            "JOIN sources AS s ON s.source_id = f.source_id "
            "ORDER BY s.rowid"
        ).fetchall()
    assert [tuple(int(value) for value in row) for row in rebuilt_rows] == [
        (1, 1, 1),
        (3, 3, 3),
        (4, 4, 4),
    ]


def test_rebuild_keeps_only_the_current_head_after_a_correction(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a rebuild resurrecting a superseded revision into memory_fts."""
    clock = FakeClock()
    memory_id, lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="original.txt",
        body="The original claim about the walled garden.\n",
        statement="The original claim about the walled garden.",
        excerpt="original claim about the walled garden",
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="correction.txt",
        body="The corrected claim about the walled garden.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_correction",
                    source=source,
                    statement="The corrected claim about the walled garden.",
                    excerpt="corrected claim about the walled garden",
                    target_lineage_id=lineage_id,
                    expected_head_id=memory_id,
                ),
            ),
        ),
    )

    rebuild_search_projections(synthetic_store)

    with writer_session(synthetic_store) as connection:
        assert connection.execute("SELECT count(*) FROM memory_fts").fetchone() == (1,)
    assert [
        hit.memory.statement
        for hit in search_memories(synthetic_store, "corrected").items
    ] == ["The corrected claim about the walled garden."]
    assert search_memories(synthetic_store, "original").items == ()


def test_lint_proposes_vocabulary_and_shared_source_candidates(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin the exact candidate the heuristic proposes from one applied batch."""
    clock = FakeClock()
    batch_id, source = capture_text(
        synthetic_store,
        name="claim-and-hedge.txt",
        body="The owner reports daily runs.\n" + HEDGE_BODY,
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    applied = apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_claim",
                    source=source,
                    statement="The owner reports daily runs.",
                    excerpt="The owner reports daily runs.",
                ),
                single_item_edit(
                    item_id="itm_hedge",
                    source=source,
                    statement="The daily-runs figure is self-reported and not verified.",
                    excerpt="self-reported and not verified",
                    kind=MemoryKind.INSIGHT,
                ),
            ),
        ),
    )
    claim_lineage_id = get_memory(
        synthetic_store, applied.memory_ids[0]
    ).revision.lineage_id
    hedge_lineage_id = get_memory(
        synthetic_store, applied.memory_ids[1]
    ).revision.lineage_id

    report = lint_guards(synthetic_store)

    assert report.standing_violations == ()
    assert report.truncated_candidate_count == 0
    assert report.candidates == (
        GuardCandidate(
            guard_lineage_id=hedge_lineage_id,
            governed_lineage_id=claim_lineage_id,
            guard_statement="The daily-runs figure is self-reported and not verified.",
            governed_statement="The owner reports daily runs.",
            rationales=(
                "guard_vocabulary",
                "same_application",
                "shared_evidence_source",
            ),
        ),
    )


def test_lint_requires_shared_evidence_not_just_same_application(
    synthetic_store: RuntimePaths,
) -> None:
    """`same_application` alone must not manufacture a candidate pair.

    Two items from two different sources in one batch: `same_application`
    holds for the pair, but `shared_evidence_source` does not, since the
    claim and its hedge each cite their own distinct source. Without the
    shared-evidence gate this would still propose a two-rationale candidate;
    with it, `same_application` alone must yield nothing.
    """
    clock = FakeClock()
    batch_id, captured = capture_batch(
        synthetic_store,
        {
            "claim.txt": "The owner reports daily runs.\n",
            "hedge.txt": HEDGE_BODY,
        },
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_claim",
                    source=captured["claim.txt"],
                    statement="The owner reports daily runs.",
                    excerpt="The owner reports daily runs.",
                ),
                single_item_edit(
                    item_id="itm_hedge",
                    source=captured["hedge.txt"],
                    statement="The daily-runs figure is self-reported and not verified.",
                    excerpt="self-reported and not verified",
                    kind=MemoryKind.INSIGHT,
                ),
            ),
        ),
    )

    report = lint_guards(synthetic_store)

    assert report.candidates == ()
    assert report.standing_violations == ()
    assert report.truncated_candidate_count == 0


def _linked_claim_and_hedge(
    synthetic_store: RuntimePaths,
    clock: FakeClock,
) -> ChangeSetView:
    """Draft one claim, its hedge, and the link between them from one source.

    One shared source, so the pair qualifies on all three lint rationales; the
    only reason it must not be proposed is the link itself, not a missing
    structural rationale (see test_lint_requires_shared_evidence_... for that).
    """
    batch_id, source = capture_text(
        synthetic_store,
        name="claim-and-hedge.txt",
        body="The owner reports daily runs.\n" + HEDGE_BODY,
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_claim",
                source=source,
                statement="The owner reports daily runs.",
                excerpt="The owner reports daily runs.",
            ),
            single_item_edit(
                item_id="itm_hedge",
                source=source,
                statement="The daily-runs figure is self-reported and not verified.",
                excerpt="self-reported and not verified",
                kind=MemoryKind.INSIGHT,
            ),
        ),
    )
    linked = edit_change_set(
        synthetic_store,
        draft.change_set_id,
        draft.revision_id,
        (
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id="itm_hedge",
                    guard_lineage_id=None,
                    governed_item_id="itm_claim",
                    governed_lineage_id=None,
                )
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    assert isinstance(linked, ChangeSetView)
    return linked


def test_lint_skips_already_linked_pairs(synthetic_store: RuntimePaths) -> None:
    """A pair the Store already links is not re-proposed as a repair candidate."""
    apply_ready(synthetic_store, _linked_claim_and_hedge(synthetic_store, FakeClock()))

    report = lint_guards(synthetic_store)

    assert report.candidates == ()
    assert report.standing_violations == ()
    assert report.truncated_candidate_count == 0


def test_lint_does_not_re_propose_a_revoked_pair(
    synthetic_store: RuntimePaths,
) -> None:
    """A revoked pair cannot be re-added, so proposing it again would be noise."""
    clock = FakeClock()
    linked = _linked_claim_and_hedge(synthetic_store, clock)
    apply_ready(synthetic_store, linked)
    with _read_connection(synthetic_store) as (connection, _identity):
        row = connection.execute(
            "SELECT guard_lineage_id, governed_lineage_id FROM memory_guard_links"
        ).fetchone()
    repair_batch, repair_source = capture_text(
        synthetic_store,
        name="repair.txt",
        body="The hedge was attached to the wrong claim.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            repair_batch,
            (
                SetSourceNoMemory(
                    source_id=repair_source.source_id,
                    reason="Synthetic reviewed decision: this note only fixes a link.",
                ),
                RevokeGuardLink(
                    link=GuardLinkInput(
                        guard_item_id=None,
                        guard_lineage_id=str(row[0]),
                        governed_item_id=None,
                        governed_lineage_id=str(row[1]),
                    )
                ),
            ),
        ),
    )

    report = lint_guards(synthetic_store)

    assert report.candidates == ()
    assert report.standing_violations == ()


def test_lint_reports_standing_violations(synthetic_store: RuntimePaths) -> None:
    """A standing sensitivity inversion the Store already allowed surfaces here too."""
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    claim_lineage_id = get_memory(
        synthetic_store, applied.memory_ids[0]
    ).revision.lineage_id
    guard_lineage_id = get_memory(
        synthetic_store, applied.memory_ids[1]
    ).revision.lineage_id
    # Same bytes as the guard's own evidence source, recaptured RESTRICTED:
    # this raises the guard's effective sensitivity above its claim's without
    # repointing any head, so the violation is standing rather than blocked.
    capture_text(
        synthetic_store,
        name="hedge-copy.txt",
        body=HEDGE_BODY,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )

    report = lint_guards(synthetic_store)

    assert len(report.standing_violations) == 1
    violation = report.standing_violations[0]
    assert violation.guard_lineage_id == guard_lineage_id
    assert violation.governed_lineage_id == claim_lineage_id
    assert violation.guard_sensitivity is Sensitivity.RESTRICTED
    assert violation.governed_sensitivity is Sensitivity.NORMAL


def test_lint_truncates_candidates_at_the_guard_link_cap(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A report with more qualifying pairs than one change set can hold truncates."""
    monkeypatch.setattr(reviews, "MAX_GUARD_LINKS", 1)
    clock = FakeClock()
    for index in range(2):
        batch_id, source = capture_text(
            synthetic_store,
            name=f"claim-and-hedge-{index}.txt",
            body=f"The owner reports run {index}.\n{HEDGE_BODY}",
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        apply_ready(
            synthetic_store,
            ready_items(
                synthetic_store,
                batch_id,
                (
                    single_item_edit(
                        item_id=f"itm_claim_{index}",
                        source=source,
                        statement=f"The owner reports run {index}.",
                        excerpt=f"The owner reports run {index}.",
                    ),
                    single_item_edit(
                        item_id=f"itm_hedge_{index}",
                        source=source,
                        statement=f"Run {index} is self-reported and not verified.",
                        excerpt="self-reported and not verified",
                        kind=MemoryKind.INSIGHT,
                    ),
                ),
            ),
        )

    report = lint_guards(synthetic_store)

    assert len(report.candidates) == 1
    assert report.truncated_candidate_count == 1


def test_capture_survives_a_projection_that_predates_the_filename_column(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch capture requiring a projection shape an existing Store cannot have.

    `source_fts` gained `original_name` in this release, and FTS5 has no
    `ALTER TABLE ADD COLUMN`, so a Store carried forward from an earlier
    release keeps the two-column projection until its owner runs
    `memory reindex`. A capture that assumes the new column does not merely
    fail: the scan has already moved the owner's files out of the inbox into
    claim custody by the time it writes the projection, so the failure lands
    after the inbox is empty and escapes as an untyped driver error rather
    than one of the Store's own codes.
    """
    from memory.database import writer_session
    from memory.inbox import scan_inbox
    from memory.retrieval import search_sources
    from memory.sources import list_sources

    with writer_session(synthetic_store) as connection:
        connection.execute("DROP TABLE source_fts")
        connection.execute(
            "CREATE VIRTUAL TABLE source_fts USING fts5(\n"
            "    source_id UNINDEXED,\n"
            "    utf8_text,\n"
            "    tokenize = 'porter unicode61'\n"
            ")"
        )

    (synthetic_store.inbox / "orchard-gardening.md").write_text(
        "The orchard lantern schedule moved to Tuesday.\n",
        encoding="utf-8",
    )
    batch = scan_inbox(synthetic_store, clock=FakeClock())

    assert batch.source_count == 1
    assert list(synthetic_store.inbox.iterdir()) == []
    assert len(list_sources(synthetic_store).items) == 1
    # The capture is retained and its text is searchable on the old projection.
    assert [
        hit.source.original_name
        for hit in search_sources(synthetic_store, "orchard lantern").items
    ] == ["orchard-gardening.md"]
    # A literal filename query works before any reindex, because the ladder
    # folds `sources.original_name` into its own haystack rather than reading
    # the projection for it.
    assert [
        hit.source.original_name
        for hit in search_sources(synthetic_store, "gardening").items
    ] == ["orchard-gardening.md"]
    # What the projection column adds is the stemmed pass over the filename,
    # and that is the part an existing Store gains only by reindexing.
    assert search_sources(synthetic_store, "gardens").items == ()

    rebuild_search_projections(synthetic_store)

    assert [
        hit.source.original_name
        for hit in search_sources(synthetic_store, "gardens").items
    ] == ["orchard-gardening.md"]
