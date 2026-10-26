from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import cast

import pytest

from memory import memories as memories_module
from memory import model
from memory.database import Connection, Row
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
    StaleCursorError,
    StaleHeadError,
)
from memory.inbox import scan_inbox
from memory.memories import get_memories, get_memory, get_memory_head, search_memories
from memory.model import (
    AddItem,
    ApplicationResult,
    ChangeSetView,
    EvidenceInput,
    MemoryDetail,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    RuntimePaths,
    Sensitivity,
    SourceSummary,
    StoreIdentity,
)
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.sources import get_store_status, list_sources


class FakeClock:
    def __init__(self, timestamp: float = 1_850_000_000.0) -> None:
        self.timestamp = timestamp

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


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
        raise AssertionError(f"memory ladder {self._kind} cursor used fetchall")


class _StreamingMemoryLadderConnection:
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
        if "memory_fts match ?" in normalized:
            kind = "ids"
        elif normalized.startswith("select mr.rowid, mr.revision_id") and (
            "mr.statement" in normalized and "current_memory_heads" in normalized
        ):
            kind = "plaintext"
        return (
            cursor
            if kind is None
            else _StreamingLadderCursor(cursor, kind, self._stats)
        )


@dataclass
class _FacetMaterializationStats:
    list_queries: int = 0
    list_rows: int = 0


class _ObservedFacetListCursor:
    """Count the rows one real bounded tag-list query materializes."""

    def __init__(
        self,
        cursor: sqlite3.Cursor,
        stats: _FacetMaterializationStats,
    ) -> None:
        self._cursor = cursor
        self._stats = stats

    def fetchall(self) -> list[Row]:
        rows = cast("list[Row]", self._cursor.fetchall())
        self._stats.list_queries += 1
        self._stats.list_rows += len(rows)
        return rows


class _ObservedFacetConnection:
    def __init__(
        self,
        connection: Connection,
        stats: _FacetMaterializationStats,
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
        if normalized.startswith(
            "select tag.value, count(*) from current_memory_heads"
        ):
            return _ObservedFacetListCursor(cursor, self._stats)
        return cursor


def capture_text(
    paths: RuntimePaths,
    *,
    name: str,
    body: str,
    sensitivity: Sensitivity,
    clock: FakeClock,
) -> tuple[str, SourceSummary]:
    before = {source.source_id for source in list_sources(paths).items}
    (paths.inbox / name).write_text(body, encoding="utf-8")
    batch = scan_inbox(paths, sensitivity=sensitivity, clock=clock)
    source = next(
        source
        for source in list_sources(paths, limit=100).items
        if source.source_id not in before
    )
    return batch.batch_id, source


def ready_single_item(
    paths: RuntimePaths,
    *,
    batch_id: str,
    source: SourceSummary,
    item_id: str,
    statement: str,
    excerpt: str,
    kind: MemoryKind = MemoryKind.FACT,
    occurred_on: str | None = None,
    tags: tuple[str, ...] = ("synthetic",),
    sensitivity: Sensitivity = Sensitivity.NORMAL,
    target_lineage_id: str | None = None,
    expected_head_id: str | None = None,
) -> ChangeSetView:
    initial = create_change_set(
        paths,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    return edit_change_set(
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
                    valid_from=None,
                    valid_to=None,
                    tags=tags,
                    sensitivity=sensitivity,
                    target_lineage_id=target_lineage_id,
                    expected_head_id=expected_head_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt=excerpt,
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )


def apply_ready(paths: RuntimePaths, ready: ChangeSetView) -> ApplicationResult:
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )


def create_search_snapshot(
    paths: RuntimePaths,
    *,
    clock: FakeClock,
) -> tuple[list[SourceSummary], list[str], list[str]]:
    sources: list[SourceSummary] = []
    memory_ids: list[str] = []
    bodies: list[str] = []
    for index in range(3):
        body = f"Synthetic snapshot record {index} keeps the amber studio open.\n"
        batch_id, source = capture_text(
            paths,
            name=f"snapshot-{index}.txt",
            body=body,
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        applied = apply_ready(
            paths,
            ready_single_item(
                paths,
                batch_id=batch_id,
                source=source,
                item_id=f"itm_snapshot_{index}",
                statement=f"Snapshot record {index} keeps the amber studio open.",
                excerpt=f"snapshot record {index} keeps the amber studio open",
            ),
        )
        sources.append(source)
        memory_ids.extend(applied.memory_ids)
        bodies.append(body)
    return sources, memory_ids, bodies


def test_only_applied_current_memory_is_searchable_and_detail_resolves_evidence(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch draft interpretation entering search or detail losing source locators."""
    clock = FakeClock()
    batch_id, source = capture_text(
        synthetic_store,
        name="synthetic-tea.md",
        body="合成事实：蓝色茶室在星期三开放。\n",
        sensitivity=Sensitivity.SENSITIVE,
        clock=clock,
    )
    ready = ready_single_item(
        synthetic_store,
        batch_id=batch_id,
        source=source,
        item_id="itm_tea",
        statement="蓝色茶室在星期三开放。",
        excerpt="蓝色茶室在星期三开放",
        tags=("休闲", " synthetic "),
        sensitivity=Sensitivity.SENSITIVE,
    )

    assert search_memories(synthetic_store, "茶室").items == ()
    assert get_store_status(synthetic_store).memory_count == 0

    applied = apply_ready(synthetic_store, ready)
    page = search_memories(
        synthetic_store,
        "茶室",
        filters=MemoryFilters(
            kinds=(MemoryKind.FACT,),
            tags_all=("休闲",),
            sensitivities=(Sensitivity.SENSITIVE,),
        ),
    )
    detail = get_memory(synthetic_store, applied.memory_ids[0])

    assert [hit.memory.memory_id for hit in page.items] == list(applied.memory_ids)
    assert page.items[0].memory.lineage_id == detail.revision.lineage_id
    assert page.items[0].memory.stored_sensitivity is Sensitivity.SENSITIVE
    assert page.items[0].memory.effective_sensitivity is Sensitivity.SENSITIVE
    assert detail.is_current is True
    assert detail.current_head_id == applied.memory_ids[0]
    assert detail.predecessor_id is None
    assert len(detail.evidence) == 1
    assert detail.evidence[0].source_id == source.source_id
    assert detail.evidence[0].blob_digest == source.blob_digest
    assert detail.evidence[0].excerpt == "蓝色茶室在星期三开放"
    assert detail.evidence[0].char_start is not None
    assert detail.evidence[0].char_end is not None
    assert detail.evidence[0].char_end > detail.evidence[0].char_start
    assert get_store_status(synthetic_store).memory_count == 1


def test_memory_ladder_streams_plaintext_and_fts_id_rows(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch either corpus pass rebuilding a plaintext or ID fetchall list."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import store_one_memory

    from memory.memories import _ladder_matches
    from memory.sources import _read_connection

    row_text = "x" * (12 * 1024)
    expected = {
        store_one_memory(
            synthetic_store,
            clock=SyntheticClock(),
            name=f"synthetic-memory-stream-{index}.txt",
            body=f"{row_text} Synthetic amber memory record {index}.\n",
            statement=f"{row_text} Synthetic amber memory record {index}.",
            excerpt=f"Synthetic amber memory record {index}",
        )[0]
        for index in range(3)
    }
    stats = _LadderStreamStats()

    with _read_connection(synthetic_store) as (connection, _identity):
        connection.execute("BEGIN")
        upper = int(
            connection.execute("SELECT max(rowid) FROM memory_revisions").fetchone()[0]
        )
        observed = _StreamingMemoryLadderConnection(connection, stats)
        matching = _ladder_matches(
            cast("Connection", observed),
            "amber",
            MemoryFilters(),
            upper,
        )

    assert {entry.revision_id for entry in matching} == expected
    assert stats.id_rows == 9
    assert stats.plaintext_rows == 3
    assert stats.largest_plaintext_row >= len(row_text)
    assert stats.plaintext_bytes > 2 * stats.largest_plaintext_row


def test_correction_appends_history_updates_head_and_stale_competitor_writes_nothing(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch in-place correction or application order selecting a stale successor."""
    clock = FakeClock()
    first_batch, first_source = capture_text(
        synthetic_store,
        name="first-observation.txt",
        body="Synthetic observation: the studio opens on Thursday.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    first_ready = ready_single_item(
        synthetic_store,
        batch_id=first_batch,
        source=first_source,
        item_id="itm_first",
        statement="The studio opens on Thursday.",
        excerpt="the studio opens on Thursday",
    )
    first_applied = apply_ready(synthetic_store, first_ready)
    original = get_memory(synthetic_store, first_applied.memory_ids[0])

    winner_batch, winner_source = capture_text(
        synthetic_store,
        name="winner-correction.txt",
        body="Synthetic correction: the studio opens on Friday.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    loser_batch, loser_source = capture_text(
        synthetic_store,
        name="loser-correction.txt",
        body="Synthetic correction draft: the studio opens on Saturday.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    winner = ready_single_item(
        synthetic_store,
        batch_id=winner_batch,
        source=winner_source,
        item_id="itm_winner",
        statement="The studio opens on Friday.",
        excerpt="the studio opens on Friday",
        target_lineage_id=original.revision.lineage_id,
        expected_head_id=original.current_head_id,
    )
    loser = ready_single_item(
        synthetic_store,
        batch_id=loser_batch,
        source=loser_source,
        item_id="itm_loser",
        statement="The studio opens on Saturday.",
        excerpt="the studio opens on Saturday",
        target_lineage_id=original.revision.lineage_id,
        expected_head_id=original.current_head_id,
    )
    winner_applied = apply_ready(synthetic_store, winner)
    loser_approval = _mint_owner_approval(
        synthetic_store,
        loser.change_set_id,
        loser.revision_id,
        loser.digest,
        adapter="mcp_elicitation",
    )

    with pytest.raises(StaleHeadError):
        approve_and_apply(
            synthetic_store,
            loser.change_set_id,
            loser.revision_id,
            loser.digest,
            approval=loser_approval,
        )

    historical = get_memory(synthetic_store, original.revision.memory_id)
    current = get_memory(synthetic_store, winner_applied.memory_ids[0])
    results = search_memories(synthetic_store, "studio opens")

    assert historical.is_current is False
    assert historical.current_head_id == winner_applied.memory_ids[0]
    assert historical.revision.statement == "The studio opens on Thursday."
    assert current.is_current is True
    assert current.predecessor_id == original.revision.memory_id
    assert current.revision.statement == "The studio opens on Friday."
    assert [hit.memory.memory_id for hit in results.items] == [
        winner_applied.memory_ids[0]
    ]


def test_one_draft_cannot_propose_two_successors_for_the_same_lineage(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch ambiguous correction order inside one atomic application."""
    clock = FakeClock()
    initial_batch, initial_source = capture_text(
        synthetic_store,
        name="base.txt",
        body="Synthetic base: the club meets monthly.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    base = apply_ready(
        synthetic_store,
        ready_single_item(
            synthetic_store,
            batch_id=initial_batch,
            source=initial_source,
            item_id="itm_base",
            statement="The club meets monthly.",
            excerpt="the club meets monthly",
        ),
    )
    detail = get_memory(synthetic_store, base.memory_ids[0])
    correction_batch, source = capture_text(
        synthetic_store,
        name="two-options.txt",
        body="Option one is weekly. Option two is quarterly.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    initial = create_change_set(
        synthetic_store,
        correction_batch,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    target = {
        "target_lineage_id": detail.revision.lineage_id,
        "expected_head_id": detail.current_head_id,
    }

    with pytest.raises(InvalidArgumentError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (
                AddItem(
                    client_item_id="itm_option_one",
                    memory=MemoryFields(
                        kind=MemoryKind.FACT,
                        statement="The club meets weekly.",
                        occurred_on=None,
                        valid_from=None,
                        valid_to=None,
                        tags=(),
                        sensitivity=Sensitivity.NORMAL,
                        **target,
                    ),
                    evidence=(
                        EvidenceInput(
                            source_id=source.source_id,
                            blob_digest=source.blob_digest,
                            excerpt="Option one is weekly",
                        ),
                    ),
                ),
                AddItem(
                    client_item_id="itm_option_two",
                    memory=MemoryFields(
                        kind=MemoryKind.FACT,
                        statement="The club meets quarterly.",
                        occurred_on=None,
                        valid_from=None,
                        valid_to=None,
                        tags=(),
                        sensitivity=Sensitivity.NORMAL,
                        **target,
                    ),
                    evidence=(
                        EvidenceInput(
                            source_id=source.source_id,
                            blob_digest=source.blob_digest,
                            excerpt="Option two is quarterly",
                        ),
                    ),
                ),
            ),
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )


def test_later_restricted_duplicate_raises_effective_sensitivity_without_mutation(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch byte dedup lowering memory metadata or rewriting accepted revisions."""
    clock = FakeClock()
    body = "Synthetic preference: quiet reading rooms are preferred.\n"
    batch_id, source = capture_text(
        synthetic_store,
        name="preference.txt",
        body=body,
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    applied = apply_ready(
        synthetic_store,
        ready_single_item(
            synthetic_store,
            batch_id=batch_id,
            source=source,
            item_id="itm_preference",
            statement="Quiet reading rooms are preferred.",
            excerpt="quiet reading rooms are preferred",
            kind=MemoryKind.PREFERENCE,
        ),
    )
    before = get_memory(synthetic_store, applied.memory_ids[0])

    capture_text(
        synthetic_store,
        name="restricted-copy.md",
        body=body,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    after = get_memory(synthetic_store, applied.memory_ids[0])

    assert before.revision.memory_id == after.revision.memory_id
    assert before.revision.lineage_id == after.revision.lineage_id
    assert before.revision.statement == after.revision.statement
    assert before.revision.recorded_at == after.revision.recorded_at
    assert before.revision.stored_sensitivity is Sensitivity.NORMAL
    assert before.revision.effective_sensitivity is Sensitivity.NORMAL
    assert after.revision.stored_sensitivity is Sensitivity.NORMAL
    assert after.revision.effective_sensitivity is Sensitivity.RESTRICTED


def test_memory_search_filters_dates_and_uses_stable_bounded_pagination(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch ignored filters, unbounded pages, or cursor/query cross-use."""
    from memory.errors import StaleCursorError

    clock = FakeClock()
    created: list[str] = []
    for index, day in enumerate(("2032-01-04", "2032-02-05", "2032-03-06")):
        phrase = f"Synthetic festival entry {index} occurs on {day}."
        batch_id, source = capture_text(
            synthetic_store,
            name=f"festival-{index}.txt",
            body=phrase + "\n",
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        applied = apply_ready(
            synthetic_store,
            ready_single_item(
                synthetic_store,
                batch_id=batch_id,
                source=source,
                item_id=f"itm_festival_{index}",
                statement=phrase,
                excerpt=phrase[:-1],
                kind=MemoryKind.EVENT,
                occurred_on=day,
                tags=("festival",),
            ),
        )
        created.extend(applied.memory_ids)

    first = search_memories(
        synthetic_store,
        "Synthetic festival",
        filters=MemoryFilters(
            kinds=(MemoryKind.EVENT,),
            tags_all=("festival",),
            occurred_from="2032-02",
            occurred_to="2032-03-31",
        ),
        limit=1,
    )
    second = search_memories(
        synthetic_store,
        "Synthetic festival",
        filters=MemoryFilters(
            kinds=(MemoryKind.EVENT,),
            tags_all=("festival",),
            occurred_from="2032-02",
            occurred_to="2032-03-31",
        ),
        cursor=first.next_cursor,
        limit=1,
    )

    assert first.has_more is True
    assert second.has_more is False
    assert [
        first.items[0].memory.occurred_on,
        second.items[0].memory.occurred_on,
    ] == [
        "2032-02-05",
        "2032-03-06",
    ]
    assert {
        first.items[0].memory.memory_id,
        second.items[0].memory.memory_id,
    } < set(created)
    open_ended = search_memories(
        synthetic_store,
        "Synthetic festival",
        filters=MemoryFilters(occurred_to="9999-12"),
    )
    assert len(open_ended.items) == 3
    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "different query",
            cursor=first.next_cursor,
            limit=1,
        )


def test_memory_search_cursor_stales_when_a_matched_head_is_corrected(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a corrected head changing page composition without staling."""
    clock = FakeClock()
    _sources, memory_ids, _bodies = create_search_snapshot(
        synthetic_store,
        clock=clock,
    )
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    target = get_memory(synthetic_store, memory_ids[1])
    correction_batch, correction_source = capture_text(
        synthetic_store,
        name="snapshot-correction.txt",
        body="Synthetic correction: the amber studio now opens at noon.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_single_item(
            synthetic_store,
            batch_id=correction_batch,
            source=correction_source,
            item_id="itm_snapshot_correction",
            statement="The amber studio now opens at noon.",
            excerpt="the amber studio now opens at noon",
            target_lineage_id=target.revision.lineage_id,
            expected_head_id=target.current_head_id,
        ),
    )

    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=first.next_cursor,
            limit=1,
        )


def test_memory_search_cursor_stales_when_effective_sensitivity_changes(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a duplicate capture silently changing snapshot filter membership."""
    clock = FakeClock()
    _sources, _memory_ids, bodies = create_search_snapshot(
        synthetic_store,
        clock=clock,
    )
    filters = MemoryFilters(sensitivities=(Sensitivity.NORMAL,))
    first = search_memories(
        synthetic_store,
        "amber studio",
        filters=filters,
        limit=1,
    )
    assert first.next_cursor is not None
    capture_text(
        synthetic_store,
        name="restricted-snapshot-copy.md",
        body=bodies[1],
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )

    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            filters=filters,
            cursor=first.next_cursor,
            limit=1,
        )


def test_memory_search_cursor_requires_its_snapshot_coordinate(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch continuation accepting a cursor with its snapshot binding removed."""
    clock = FakeClock()
    create_search_snapshot(synthetic_store, clock=clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    padding = "=" * (-len(first.next_cursor) % 4)
    payload = json.loads(
        base64.urlsafe_b64decode(first.next_cursor + padding).decode("utf-8")
    )
    payload.pop("snapshot", None)
    unbound_cursor = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )

    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=unbound_cursor,
            limit=1,
        )


def test_memory_search_cursor_rejects_oversized_rowid_coordinates(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a valid snapshot/query cursor integer reaching SQLite conversion."""
    create_search_snapshot(synthetic_store, clock=FakeClock())
    first = search_memories(synthetic_store, "amber studio", limit=1)
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
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=oversized,
            limit=1,
        )


def test_memory_search_cursor_excludes_unrelated_later_insertions(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a snapshot guard treating an unrelated later lineage as mutation."""
    clock = FakeClock()
    _sources, memory_ids, _bodies = create_search_snapshot(
        synthetic_store,
        clock=clock,
    )
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    later_batch, later_source = capture_text(
        synthetic_store,
        name="later-snapshot.txt",
        body="Synthetic later record keeps the amber studio open.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    later = apply_ready(
        synthetic_store,
        ready_single_item(
            synthetic_store,
            batch_id=later_batch,
            source=later_source,
            item_id="itm_later_snapshot",
            statement="A later record keeps the amber studio open.",
            excerpt="later record keeps the amber studio open",
        ),
    )

    returned = [hit.memory.memory_id for hit in first.items]
    cursor: str | None = first.next_cursor
    while cursor is not None:
        page = search_memories(
            synthetic_store,
            "amber studio",
            cursor=cursor,
            limit=1,
        )
        returned.extend(hit.memory.memory_id for hit in page.items)
        cursor = page.next_cursor

    assert returned == memory_ids
    assert later.memory_ids[0] not in returned


def test_memory_search_private_wire_budget_walks_without_skip_or_repeat(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a byte stop losing the excluded hit or weakening cursor bindings."""
    clock = FakeClock()
    _sources, memory_ids, _bodies = create_search_snapshot(
        synthetic_store,
        clock=clock,
    )

    def fixed_wire_cost(_hit: model.MemorySearchHit, first_on_page: bool) -> int:
        return 6 if first_on_page else 8

    def budgeted_page(
        cursor: str | None = None,
        *,
        query: str = "amber studio",
        filters: MemoryFilters = MemoryFilters(),
        limit: int = 3,
        oversized: bool = False,
    ) -> model.MemorySearchPage:
        return search_memories(
            synthetic_store,
            query,
            filters=filters,
            cursor=cursor,
            limit=limit,
            _wire_item_budget=1 if oversized else 14,
            _wire_item_cost=(
                (lambda _hit, _first: 2) if oversized else fixed_wire_cost
            ),
        )

    first = budgeted_page()
    assert [hit.memory.memory_id for hit in first.items] == memory_ids[:2]
    assert first.has_more is True
    assert first.next_cursor is not None

    second = budgeted_page(first.next_cursor)
    assert [hit.memory.memory_id for hit in second.items] == memory_ids[2:]
    assert second.has_more is False
    assert second.next_cursor is None

    with pytest.raises(StaleCursorError):
        budgeted_page(first.next_cursor, query="different query")
    with pytest.raises(StaleCursorError):
        budgeted_page(
            first.next_cursor,
            filters=MemoryFilters(kinds=(MemoryKind.FACT,)),
        )

    item_limited = budgeted_page(limit=1)
    assert [hit.memory.memory_id for hit in item_limited.items] == memory_ids[:1]
    assert item_limited.has_more is True

    oversized_walk: list[str] = []
    cursor = None
    while True:
        oversized = budgeted_page(cursor, oversized=True)
        assert len(oversized.items) == 1
        oversized_walk.append(oversized.items[0].memory.memory_id)
        if oversized.next_cursor is None:
            assert oversized.has_more is False
            break
        assert oversized.has_more is True
        cursor = oversized.next_cursor
    assert oversized_walk == memory_ids

    fresh_first = budgeted_page(limit=2)
    assert fresh_first.next_cursor is not None
    target = get_memory(synthetic_store, memory_ids[2])
    correction = _ready_snapshot_correction(
        synthetic_store,
        clock=clock,
        original_memory_id=target.current_head_id,
        lineage_id=target.revision.lineage_id,
        label="amber",
    )
    apply_ready(synthetic_store, correction)
    with pytest.raises(StaleCursorError):
        budgeted_page(fresh_first.next_cursor, limit=2)


def test_memory_search_loads_guards_only_for_considered_lineages(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch byte paging restoring one bulk 500-lineage guard materialization."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import store_one_memory, two_source_linked_apply

    linked = two_source_linked_apply(synthetic_store, SyntheticClock())
    claim = get_memory(synthetic_store, linked.memory_ids[0])
    guard = get_memory(synthetic_store, linked.memory_ids[1])
    _extra_id, extra_lineage = store_one_memory(
        synthetic_store,
        clock=SyntheticClock(),
        name="later-budget-candidate.txt",
        body="A later synthetic candidate remains outside the first byte page.\n",
        statement="A later synthetic candidate remains outside the first byte page.",
        excerpt="later synthetic candidate remains outside the first byte page",
    )

    original = memories_module._guards_for_lineages
    queried: list[tuple[str, ...]] = []

    def tracked_guards(
        connection: Connection,
        lineage_ids: tuple[str, ...],
        *,
        tables_ready: bool,
    ) -> dict[str, tuple[model.GuardAttachment, ...]]:
        queried.append(lineage_ids)
        return original(connection, lineage_ids, tables_ready=tables_ready)

    monkeypatch.setattr(memories_module, "_guards_for_lineages", tracked_guards)

    page = search_memories(
        synthetic_store,
        limit=3,
        _wire_item_budget=1,
        _wire_item_cost=lambda _hit, first: 1 if first else 2,
    )

    assert [hit.memory.memory_id for hit in page.items] == [linked.memory_ids[0]]
    assert page.items[0].guards != ()
    assert page.has_more is True
    assert queried == [
        (claim.revision.lineage_id,),
        (guard.revision.lineage_id,),
    ]
    assert (extra_lineage,) not in queried


def test_memory_search_keeps_a_compact_five_hundred_hit_page(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the byte guard turning an ordinary compact maximum page short."""
    from memory.mcp_server import (
        _MEMORY_SEARCH_ITEM_BUDGET_BYTES,
        _memory_search_hit_wire_cost,
    )
    from memory.retrieval import _STRENGTH_ORDER

    count = 500
    strength = _STRENGTH_ORDER[model.MatchStrength.ENUMERATED]
    entries = [
        memories_module._MatchEntry(
            strength,
            0.0,
            index,
            f"mem_compact_{index:04d}",
            0,
        )
        for index in range(1, count + 1)
    ]
    rows = {
        entry.rowid: (
            entry.rowid,
            entry.revision_id,
            f"lin_compact_{entry.rowid:04d}",
            "fact",
            f"Synthetic compact record {entry.rowid:04d}.",
            None,
            None,
            None,
            '["synthetic"]',
            "normal",
            0,
            1_850_000_000,
        )
        for entry in entries
    }
    monkeypatch.setattr(
        memories_module,
        "_ladder_matches",
        lambda _connection, _query, _filters, _upper: entries,
    )
    monkeypatch.setattr(
        memories_module,
        "_visible_memory_rows",
        lambda _connection, rowids: {rowid: rows[rowid] for rowid in rowids},
    )
    monkeypatch.setattr(
        memories_module, "_guard_tables_ready", lambda _connection: False
    )
    monkeypatch.setattr(
        memories_module,
        "_memory_coverage",
        lambda _connection, _upper: model.Coverage(
            searchable=count,
            unsearchable=0,
            enumerated=count,
            total=count,
        ),
    )

    page = search_memories(
        synthetic_store,
        limit=count,
        _wire_item_budget=_MEMORY_SEARCH_ITEM_BUDGET_BYTES,
        _wire_item_cost=_memory_search_hit_wire_cost,
    )

    assert len(page.items) == count
    assert page.has_more is False
    assert page.next_cursor is None


def test_memory_search_rejects_a_lone_surrogate_as_invalid_argument(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch strict UTF-8 query validation escaping as a codec exception."""
    with pytest.raises(InvalidArgumentError):
        search_memories(synthetic_store, "\ud800")


def test_memory_lookup_rejects_a_lone_surrogate_opaque_id(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an invalid opaque ID reaching the SQLite UTF-8 binder."""
    with pytest.raises(InvalidArgumentError):
        get_memory(synthetic_store, "mem_\ud800")


def _ready_snapshot_correction(
    paths: RuntimePaths,
    *,
    clock: FakeClock,
    original_memory_id: str,
    lineage_id: str,
    label: str,
) -> ChangeSetView:
    batch_id, source = capture_text(
        paths,
        name=f"{label}-correction.txt",
        body=f"Synthetic correction: the {label} room now opens on Friday.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    return ready_single_item(
        paths,
        batch_id=batch_id,
        source=source,
        item_id=f"itm_{label}_correction",
        statement=f"The {label} room now opens on Friday.",
        excerpt=f"the {label} room now opens on Friday",
        target_lineage_id=lineage_id,
        expected_head_id=original_memory_id,
    )


def _store_snapshot_memory(
    paths: RuntimePaths,
    *,
    clock: FakeClock,
    label: str,
) -> tuple[str, str]:
    batch_id, source = capture_text(
        paths,
        name=f"{label}-room.txt",
        body=f"The {label} room opens on Thursday.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    applied = apply_ready(
        paths,
        ready_single_item(
            paths,
            batch_id=batch_id,
            source=source,
            item_id=f"itm_{label}",
            statement=f"The {label} room opens on Thursday.",
            excerpt=f"The {label} room opens on Thursday.",
        ),
    )
    memory_id = applied.memory_ids[0]
    return memory_id, get_memory(paths, memory_id).revision.lineage_id


def test_memory_head_detail_uses_the_snapshot_that_selected_the_head(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a correction tearing lineage selection from detail assembly."""
    clock = FakeClock()
    memory_id, lineage_id = _store_snapshot_memory(
        synthetic_store,
        clock=clock,
        label="lineage",
    )
    correction = _ready_snapshot_correction(
        synthetic_store,
        clock=clock,
        original_memory_id=memory_id,
        lineage_id=lineage_id,
        label="lineage",
    )
    original_detail = memories_module._memory_detail
    corrected_memory_id: str | None = None

    def apply_between_head_selection_and_detail(
        connection: Connection,
        selected_memory_id: str,
    ) -> MemoryDetail:
        nonlocal corrected_memory_id
        corrected_memory_id = apply_ready(synthetic_store, correction).memory_ids[0]
        return original_detail(connection, selected_memory_id)

    monkeypatch.setattr(
        memories_module,
        "_memory_detail",
        apply_between_head_selection_and_detail,
    )

    detail = get_memory_head(synthetic_store, lineage_id)

    assert corrected_memory_id is not None
    assert detail.revision.memory_id == memory_id
    assert detail.current_head_id == memory_id
    assert detail.is_current is True
    assert detail.revision_ids == (memory_id,)
    monkeypatch.setattr(memories_module, "_memory_detail", original_detail)
    fresh = get_memory_head(synthetic_store, lineage_id)
    assert fresh.revision.memory_id == corrected_memory_id
    assert fresh.current_head_id == corrected_memory_id


def test_exact_memory_detail_cannot_mix_head_and_history_snapshots(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch history advancing after an exact detail already read its head."""
    clock = FakeClock()
    memory_id, lineage_id = _store_snapshot_memory(
        synthetic_store,
        clock=clock,
        label="exact",
    )
    correction = _ready_snapshot_correction(
        synthetic_store,
        clock=clock,
        original_memory_id=memory_id,
        lineage_id=lineage_id,
        label="exact",
    )
    original_tables_ready = memories_module._guard_tables_ready
    corrected_memory_id: str | None = None

    def apply_after_head_read(connection: Connection) -> bool:
        nonlocal corrected_memory_id
        corrected_memory_id = apply_ready(synthetic_store, correction).memory_ids[0]
        return original_tables_ready(connection)

    monkeypatch.setattr(
        memories_module,
        "_guard_tables_ready",
        apply_after_head_read,
    )

    detail = get_memory(synthetic_store, memory_id)

    assert corrected_memory_id is not None
    assert detail.current_head_id == memory_id
    assert detail.is_current is True
    assert detail.revision_ids == (memory_id,)
    monkeypatch.setattr(
        memories_module,
        "_guard_tables_ready",
        original_tables_ready,
    )
    fresh = get_memory(synthetic_store, memory_id)
    assert fresh.current_head_id == corrected_memory_id
    assert fresh.is_current is False
    assert fresh.revision_ids == (memory_id, corrected_memory_id)


def test_bulk_memory_details_share_one_snapshot_across_requested_items(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch bulk assembly opening a fresh snapshot for each requested item."""
    clock = FakeClock()
    first_memory_id, _first_lineage_id = _store_snapshot_memory(
        synthetic_store,
        clock=clock,
        label="bulk-first",
    )
    second_memory_id, second_lineage_id = _store_snapshot_memory(
        synthetic_store,
        clock=clock,
        label="bulk-second",
    )
    correction = _ready_snapshot_correction(
        synthetic_store,
        clock=clock,
        original_memory_id=second_memory_id,
        lineage_id=second_lineage_id,
        label="bulk-second",
    )
    original_detail = memories_module._memory_detail
    detail_count = 0
    corrected_memory_id: str | None = None

    def apply_between_requested_items(
        connection: Connection,
        selected_memory_id: str,
    ) -> MemoryDetail:
        nonlocal corrected_memory_id, detail_count
        detail = original_detail(connection, selected_memory_id)
        detail_count += 1
        if detail_count == 1:
            corrected_memory_id = apply_ready(synthetic_store, correction).memory_ids[0]
        return detail

    monkeypatch.setattr(
        memories_module,
        "_memory_detail",
        apply_between_requested_items,
    )

    first, second = get_memories(
        synthetic_store,
        (first_memory_id, second_memory_id),
    )

    assert corrected_memory_id is not None
    assert first.current_head_id == first_memory_id
    assert first.revision_ids == (first_memory_id,)
    assert second.current_head_id == second_memory_id
    assert second.is_current is True
    assert second.revision_ids == (second_memory_id,)
    monkeypatch.setattr(memories_module, "_memory_detail", original_detail)
    fresh = get_memory(synthetic_store, second_memory_id)
    assert fresh.current_head_id == corrected_memory_id
    assert fresh.is_current is False
    assert fresh.revision_ids == (second_memory_id, corrected_memory_id)


def test_memory_selection_refuses_an_unbounded_or_repeated_request(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a bulk read that is unbounded, partial, or silently deduplicated."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import store_one_memory

    from memory.memories import MAX_MEMORY_SELECTION, get_memories, get_memory_head

    memory_id, lineage_id = store_one_memory(
        synthetic_store,
        clock=SyntheticClock(),
        name="quarry.txt",
        body="The quarry road floods in spring.\n",
        statement="The quarry road floods in spring.",
        excerpt="The quarry road floods in spring.",
    )

    assert MAX_MEMORY_SELECTION == 50
    assert [
        detail.revision.memory_id
        for detail in get_memories(synthetic_store, (memory_id,))
    ] == [memory_id]
    assert get_memory_head(synthetic_store, lineage_id).revision.memory_id == memory_id
    with pytest.raises(InvalidArgumentError):
        get_memories(synthetic_store, ())
    with pytest.raises(InvalidArgumentError):
        get_memories(synthetic_store, (memory_id,) * (MAX_MEMORY_SELECTION + 1))
    with pytest.raises(InvalidArgumentError):
        get_memories(synthetic_store, (memory_id, memory_id))
    # Every named id must resolve: a partial answer to a verification read is
    # indistinguishable from a Store that lost a revision.
    with pytest.raises(NotFoundError):
        get_memories(synthetic_store, (memory_id, "mem_synthetic_absent"))
    with pytest.raises(NotFoundError):
        get_memory_head(synthetic_store, "lin_synthetic_absent")


def test_memory_facets_truncate_loudly_at_the_declared_tag_bound(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the exact vocabulary count while materializing only its wire bound."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import apply_ready, capture_batch, ready_items, single_item_edit

    from memory import memories as memories_module
    from memory.memories import MAX_FACET_TAGS, get_memory_facets
    from memory.sources import _read_connection

    files = {
        f"facet-{index:02d}.txt": f"Synthetic facet record {index:02d}.\n"
        for index in range(8)
    }
    batch_id, sources = capture_batch(
        synthetic_store,
        files,
        sensitivity=Sensitivity.NORMAL,
        clock=SyntheticClock(),
    )
    unique_tags = tuple(
        f"aspect:facet-{index:02d}-{tag_index:02d}"
        for index in range(8)
        for tag_index in range(63)
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            tuple(
                single_item_edit(
                    item_id=f"itm_facet_{index:02d}",
                    source=sources[name],
                    statement=files[name].strip(),
                    excerpt=files[name].strip(),
                    tags=(
                        "aspect:shared",
                        *(
                            f"aspect:facet-{index:02d}-{tag_index:02d}"
                            for tag_index in range(63)
                        ),
                    ),
                )
                for index, name in enumerate(files)
            ),
        ),
    )

    stats = _FacetMaterializationStats()

    @contextmanager
    def observed_read_connection(
        paths: RuntimePaths,
    ) -> Iterator[tuple[Connection, StoreIdentity]]:
        with _read_connection(paths) as (connection, identity):
            observed = _ObservedFacetConnection(connection, stats)
            yield cast("Connection", observed), identity

    monkeypatch.setattr(
        memories_module,
        "_read_connection",
        observed_read_connection,
    )
    bounded = get_memory_facets(synthetic_store)

    assert MAX_FACET_TAGS == 500
    assert bounded.total_tags == 505
    assert len(bounded.tags) == 500
    assert bounded.truncated is True
    assert [facet.value for facet in bounded.tags] == [
        "aspect:shared",
        *sorted(unique_tags)[:499],
    ]
    assert bounded.tags[0].count == 8
    assert all(facet.count == 1 for facet in bounded.tags[1:])
    assert [(facet.value, facet.count) for facet in bounded.kinds] == [("fact", 8)]
    assert stats.list_queries == 1
    assert stats.list_rows == MAX_FACET_TAGS


def test_memory_facets_report_only_current_heads(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a superseded revision's tag being offered as a usable filter."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import (
        apply_ready,
        capture_text,
        ready_items,
        single_item_edit,
        store_one_memory,
    )

    from memory.memories import get_memory_facets

    clock = SyntheticClock()
    first_id, lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="ferry.txt",
        body="The ferry leaves at seven.\n",
        statement="The ferry leaves at seven.",
        excerpt="The ferry leaves at seven.",
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="ferry-correction.txt",
        body="The ferry leaves at eight, not seven.\n",
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
                    item_id="itm_ferry",
                    source=source,
                    statement="The ferry leaves at eight.",
                    excerpt="The ferry leaves at eight",
                    tags=("aspect:transit",),
                    target_lineage_id=lineage_id,
                    expected_head_id=first_id,
                ),
            ),
        ),
    )

    facets = get_memory_facets(synthetic_store)

    assert [facet.value for facet in facets.tags] == ["aspect:transit"]
    assert facets.total_tags == 1


def test_memory_facets_hold_one_wal_snapshot_across_an_approved_correction(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch tag and kind aggregates coming from two committed snapshots."""
    from memory.memories import get_memory_facets

    clock = FakeClock()
    first_batch_id, first_source = capture_text(
        synthetic_store,
        name="lantern-schedule.txt",
        body="The synthetic lantern is lit at dawn.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    first_application = apply_ready(
        synthetic_store,
        ready_single_item(
            synthetic_store,
            batch_id=first_batch_id,
            source=first_source,
            item_id="itm_lantern_schedule",
            statement="The synthetic lantern is lit at dawn.",
            excerpt="The synthetic lantern is lit at dawn.",
            kind=MemoryKind.FACT,
        ),
    )
    first_memory_id = first_application.memory_ids[0]
    lineage_id = get_memory(synthetic_store, first_memory_id).revision.lineage_id
    correction_batch_id, correction_source = capture_text(
        synthetic_store,
        name="lantern-correction.txt",
        body="The synthetic lantern is instead lit at dusk.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    correction = ready_single_item(
        synthetic_store,
        batch_id=correction_batch_id,
        source=correction_source,
        item_id="itm_lantern_correction",
        statement="The synthetic lantern is lit at dusk.",
        excerpt="synthetic lantern is instead lit at dusk",
        kind=MemoryKind.INSIGHT,
        tags=("aspect:evening",),
        target_lineage_id=lineage_id,
        expected_head_id=first_memory_id,
    )
    before = get_memory_facets(synthetic_store)
    original_kind_counts = memories_module.owner_kind_counts
    writer_committed = False

    def publish_after_tag_query(
        connection: Connection,
    ) -> tuple[tuple[str, int], ...]:
        nonlocal writer_committed
        if not writer_committed:
            apply_ready(synthetic_store, correction)
            writer_committed = True
        return original_kind_counts(connection)

    monkeypatch.setattr(
        memories_module,
        "owner_kind_counts",
        publish_after_tag_query,
    )

    in_flight = get_memory_facets(synthetic_store)

    assert writer_committed is True
    assert in_flight == before
    monkeypatch.setattr(memories_module, "owner_kind_counts", original_kind_counts)
    after = get_memory_facets(synthetic_store)
    assert after != before
    assert [facet.value for facet in after.tags] == ["aspect:evening"]
    assert [(facet.value, facet.count) for facet in after.kinds] == [("insight", 1)]
