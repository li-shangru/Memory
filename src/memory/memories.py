"""Canonical current-head memory retrieval with immutable historical detail."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Literal, NamedTuple

from memory.database import Connection, Row, guard_revocations_recorded
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
    StaleCursorError,
)
from memory.model import (
    Coverage,
    Cursor,
    FacetCount,
    GuardAttachment,
    MatchStrength,
    MemoryDetail,
    MemoryFacets,
    MemoryFilters,
    MemoryKind,
    MemorySearchHit,
    MemorySearchPage,
    MemorySummary,
    RuntimePaths,
    Sensitivity,
    StoreIdentity,
)
from memory.retrieval import (
    _HAYSTACK_JOIN,
    _STRENGTH_FROM_ORDER,
    _STRENGTH_ORDER,
    LADDER_VERSION,
    _compile_literal_query,
    _cursor_rank,
    _cursor_snapshot,
    _cursor_strength,
    _rung_expressions,
    _strongest,
    _validate_query,
    ladder_resume,
    ladder_start_index,
    owner_binding,
)
from memory.reviews import (
    MAX_EVIDENCE_PER_ITEM,
    _locator_from_row,
    _normalize_tags,
    _parse_tags,
    _validate_partial_date,
    partial_date_bounds,
)
from memory.sources import (
    DEFAULT_PAGE_SIZE,
    _canonical_json,
    _cursor_rowid_bounds,
    _decode_cursor,
    _effective_rank_sql,
    _encode_cursor,
    _read_connection,
    _require_cursor_scope,
    _validate_opaque_id,
    _validate_page_size,
    owner_cursor_bounds,
    owner_filter_binding,
    owner_generation_token,
    owner_page_from_rows,
)
from memory.ui.view_models import (
    MemoryProjectionCoverage,
    OwnerGuardAttachment,
    OwnerLineageSummary,
    OwnerMemoryDetail,
    OwnerMemorySearchPage,
    OwnerMemorySummary,
    OwnerPage,
)
from memory.validation import require_invariant, sensitivity_from_rank

_MEMORY_SELECT = f"""
SELECT
    mr.rowid,
    mr.revision_id,
    mr.lineage_id,
    mr.kind,
    mr.statement,
    mr.occurred_on,
    mr.valid_from,
    mr.valid_to,
    mr.tags_json,
    mr.sensitivity,
    {_effective_rank_sql("mr")},
    mr.recorded_at
FROM memory_revisions AS mr
"""

_GUARD_ATTACHMENT_COLUMNS = f"""
    mr.revision_id,
    mr.lineage_id,
    mr.kind,
    mr.statement,
    {_effective_rank_sql("mr")}
"""


# The lean scan the ladder scores. It selects what a filter, a rung, a rank and
# the snapshot digest need, and leaves the rest of the summary to the visible
# page. Unlike the source side it cannot drop the correlated
# effective-sensitivity subquery: that rank is both a filter input and part of
# the digested composition, so every candidate needs it. What the split buys
# here is that the ladder no longer returns one reader's row shape, which is
# what lets the owner reader page over the same rungs (5.3).
_LADDER_SCAN = f"""
SELECT
    mr.rowid,
    mr.revision_id,
    mr.kind,
    mr.statement,
    mr.occurred_on,
    mr.tags_json,
    {_effective_rank_sql("mr")},
    mr.recorded_at
FROM memory_revisions AS mr
JOIN current_memory_heads AS heads ON heads.revision_id = mr.revision_id
WHERE mr.rowid <= ?
ORDER BY mr.rowid
"""

# One disposable memory projection row is canonical only when it restates all
# indexed content of its authoritative revision exactly.  Keep these aliases
# fixed so the stemmed MATCH query, public coverage, and owner audit all use
# one definition rather than three mirrored interpretations.  In particular,
# the MATCHing `indexed` row itself must satisfy this predicate: a separate
# exact-row EXISTS would let a divergent duplicate supply the score.
_CANONICAL_MEMORY_PROJECTION_PREDICATE = (
    "indexed.revision_id = revision.revision_id "
    "AND indexed.statement = revision.statement "
    "AND indexed.tags = ("
    "SELECT COALESCE(group_concat(value, ' '), '') "
    "FROM json_each(revision.tags_json))"
)

# `memory_fts.revision_id` is deliberately UNINDEXED.  Materialize the exact
# canonical IDs once from an FTS-outer CROSS JOIN, then let callers probe that
# bounded set through `IN`.  Correlating one FTS scan per current head would
# turn public coverage and owner audit into quadratic Store-size work.
_CANONICAL_MEMORY_PROJECTION_IDS_SQL = (
    "SELECT revision.revision_id FROM memory_fts AS indexed "
    "CROSS JOIN memory_revisions AS revision ON "
    + _CANONICAL_MEMORY_PROJECTION_PREDICATE
    + " GROUP BY revision.revision_id"
)


class _MatchEntry(NamedTuple):
    """One current head admitted by the ladder, at its resolved rung and rank."""

    strength: int
    rank: float
    rowid: int
    revision_id: str
    sensitivity_rank: int


def _guard_tables_ready(connection: Connection) -> bool:
    # Read connections never heal, matching the tolerance _load_guard_links takes:
    # a store captured before the guard tables existed still answers reads, with
    # no attachments, until any writer session adds them back.
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'memory_guard_links'"
        ).fetchone()
        is not None
    )


def _live_link_predicate(connection: Connection) -> str:
    """Return the clause that keeps a revoked link out of co-retrieval.

    Empty on a store the revocation heal has not reached: it holds no revoked
    link, so filtering on a column it does not have would fail a read whose
    answer is already known.
    """
    return (
        "AND link.revoked_at IS NULL " if guard_revocations_recorded(connection) else ""
    )


def _attachment_from_row(row: Row, offset: int = 0) -> GuardAttachment:
    return GuardAttachment(
        memory_id=str(row[offset]),
        lineage_id=str(row[offset + 1]),
        kind=MemoryKind(str(row[offset + 2])),
        statement=str(row[offset + 3]),
        effective_sensitivity=sensitivity_from_rank(int(row[offset + 4])),
    )


def _guards_for_lineages(
    connection: Connection,
    lineage_ids: tuple[str, ...],
    *,
    tables_ready: bool,
) -> dict[str, tuple[GuardAttachment, ...]]:
    """Return current guards for the bounded governed-lineage selection.

    MCP search deliberately calls this with one considered lineage at a time:
    one bulk selection could materialize every maximum-width attachment before
    the MCP result-body budget had a chance to stop the page. Exact-detail reads
    continue to use the same helper for their one lineage.
    """
    if not lineage_ids or not tables_ready:
        return {}
    placeholders = ", ".join("?" for _ in lineage_ids)
    rows = connection.execute(
        "SELECT link.governed_lineage_id, "
        + _GUARD_ATTACHMENT_COLUMNS
        + "FROM memory_guard_links AS link "
        "JOIN current_memory_heads AS heads "
        "ON heads.lineage_id = link.guard_lineage_id "
        "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
        f"WHERE link.governed_lineage_id IN ({placeholders}) "
        + _live_link_predicate(connection)
        + "ORDER BY link.governed_lineage_id, mr.lineage_id",
        lineage_ids,
    ).fetchall()
    grouped: dict[str, list[GuardAttachment]] = {}
    for row in rows:
        grouped.setdefault(str(row[0]), []).append(_attachment_from_row(row, 1))
    return {governed: tuple(attachments) for governed, attachments in grouped.items()}


def _governs_for_lineage(
    connection: Connection,
    lineage_id: str,
    *,
    tables_ready: bool,
) -> tuple[GuardAttachment, ...]:
    """Return the current head of every claim this lineage guards."""
    if not tables_ready:
        return ()
    rows = connection.execute(
        "SELECT " + _GUARD_ATTACHMENT_COLUMNS + "FROM memory_guard_links AS link "
        "JOIN current_memory_heads AS heads "
        "ON heads.lineage_id = link.governed_lineage_id "
        "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
        "WHERE link.guard_lineage_id = ? "
        + _live_link_predicate(connection)
        + "ORDER BY mr.lineage_id",
        (lineage_id,),
    ).fetchall()
    return tuple(_attachment_from_row(row) for row in rows)


def search_memories(
    paths: RuntimePaths,
    query: str | None = None,
    filters: MemoryFilters = MemoryFilters(),
    cursor: Cursor | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    *,
    _wire_item_budget: int | None = None,
    _wire_item_cost: Callable[[MemorySearchHit, bool], int] | None = None,
) -> MemorySearchPage:
    """Search or enumerate current canonical heads with generic bounded filters.

    An absent query is an enumeration walk over the filtered current heads in
    stored order. It is not a degenerate search: every hit it emits carries
    `enumerated`, a rung no ranked walk can produce, so a reader can tell the
    two apart from one hit. `None` and any present query are distinguished in
    the cursor binding, so neither traversal can resume into the other.
    """
    normalized_query = None if query is None else _validate_query(query)
    normalized_filters = _normalize_filters(filters)
    page_size = _validate_page_size(limit)
    if (_wire_item_budget is None) != (_wire_item_cost is None):
        raise InvalidArgumentError("memory search result budget is invalid")
    if _wire_item_budget is not None and (
        isinstance(_wire_item_budget, bool)
        or not isinstance(_wire_item_budget, int)
        or _wire_item_budget < 0
    ):
        raise InvalidArgumentError("memory search result budget is invalid")
    binding_payload: dict[str, object] = {
        "ladder": LADDER_VERSION,
        "query": normalized_query,
        "filters": owner_filters_payload(normalized_filters),
    }
    binding = hashlib.sha256(_canonical_json(binding_payload)).hexdigest()
    with _read_connection(paths) as (connection, identity):
        connection.execute("BEGIN")
        if cursor is None:
            resume: tuple[int, float, int] | None = None
            snapshot: str | None = None
            upper = int(
                connection.execute(
                    "SELECT COALESCE(MAX(rowid), 0) FROM memory_revisions"
                ).fetchone()[0]
            )
        else:
            payload = _decode_cursor(cursor)
            _require_cursor_scope(
                payload,
                store_id=identity.store_id,
                operation="memory.search",
                binding=binding,
                label="memory search",
            )
            after, upper = _cursor_rowid_bounds(payload)
            resume = (_cursor_strength(payload), _cursor_rank(payload), after)
            snapshot = _cursor_snapshot(payload)

        matching = _ladder_matches(
            connection,
            normalized_query,
            normalized_filters,
            upper,
        )
        digest = _ladder_snapshot_digest(matching, upper)
        if snapshot is not None and digest != snapshot:
            raise StaleCursorError("memory search snapshot changed")
        start_index = (
            0
            if resume is None
            else next(
                (
                    index
                    for index, entry in enumerate(matching)
                    if (entry.strength, entry.rank, entry.rowid) > resume
                ),
                len(matching),
            )
        )
        candidates = matching[start_index : start_index + page_size]
        # Guards are attachments, never hits: they bypass the filters by never
        # reaching _matches_filters, and they consume no page slot. The snapshot
        # digest above deliberately excludes them -- they do not affect page
        # composition or order, so a guard edited mid-walk shows its fresh
        # attachment on the next page rather than staling the cursor. An added
        # link is the same trade seen from the other side: pages already emitted
        # carry no attachment for it, a refetch of those pages does. Accepted
        # because guard applies are owner-approved and rare, and staling the
        # cursor would not un-emit the pages the caller has already read.
        page_rows = _visible_memory_rows(
            connection, tuple(entry.rowid for entry in candidates)
        )
        tables_ready = bool(candidates) and _guard_tables_ready(connection)
        visible: list[_MatchEntry] = []
        items: list[MemorySearchHit] = []
        wire_cost = 0
        for entry in candidates:
            row = page_rows[entry.rowid]
            lineage_id = str(row[2])
            guard_map = _guards_for_lineages(
                connection,
                (lineage_id,),
                tables_ready=tables_ready,
            )
            item = MemorySearchHit(
                memory=_summary_from_row(row),
                match_strength=_STRENGTH_FROM_ORDER[entry.strength],
                guards=guard_map.get(lineage_id, ()),
            )
            item_cost = (
                0 if _wire_item_cost is None else _wire_item_cost(item, not items)
            )
            require_invariant(
                not isinstance(item_cost, bool)
                and isinstance(item_cost, int)
                and item_cost >= 0,
                label="memory search result item cost",
            )
            # The first candidate always advances the opaque cursor, even when
            # its bounded guard roster makes it larger than the ordinary MCP
            # page budget. Every later candidate is left for the next page if
            # it would cross that budget.
            if (
                items
                and _wire_item_budget is not None
                and wire_cost + item_cost > _wire_item_budget
            ):
                break
            visible.append(entry)
            items.append(item)
            wire_cost += item_cost
        has_more = start_index + len(visible) < len(matching)
        next_cursor = (
            _encode_cursor(
                store_id=identity.store_id,
                operation="memory.search",
                upper=upper,
                after=visible[-1].rowid,
                binding=binding,
                rank=visible[-1].rank,
                snapshot=digest,
                strength=visible[-1].strength,
            )
            if has_more
            else None
        )
        return MemorySearchPage(
            items=tuple(items),
            next_cursor=next_cursor,
            has_more=has_more,
            coverage=_memory_coverage(connection, upper),
        )


def _memory_coverage(connection: Connection, upper: int) -> Coverage:
    """Report how much of the snapshot's canonical memory the walk could reach.

    A current head missing an exact canonical `memory_fts` row -- including a
    row whose statement or tags drifted -- is unsearchable in per-query
    coverage and is missing/unexpected in the owner projection audit.
    `store.status.reindex_required` is deliberately narrower: it reports FTS
    DDL and guard-table shape readiness, not row fidelity, so it may remain
    false while this coverage exposes a gap. Reporting that gap per query turns
    a thin answer from "nothing matched" into "part of the corpus could not be
    searched at all".

    Queryless enumeration deliberately continues to walk canonical heads, so
    it can return a current head even when that head's disposable projection
    row is missing. Coverage remains projection membership in every mode:
    otherwise a queryless response would conceal a search gap that a ranked
    response correctly exposes.
    """
    total = int(
        connection.execute(
            "SELECT count(*) FROM current_memory_heads AS heads "
            "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
            "WHERE mr.rowid <= ?",
            (upper,),
        ).fetchone()[0]
    )
    searchable = int(
        connection.execute(
            "SELECT count(*) FROM current_memory_heads AS heads "
            "JOIN memory_revisions AS current_revision "
            "ON current_revision.revision_id = heads.revision_id "
            "WHERE current_revision.rowid <= ? "
            "AND current_revision.revision_id IN ("
            + _CANONICAL_MEMORY_PROJECTION_IDS_SQL
            + ")",
            (upper,),
        ).fetchone()[0]
    )
    return Coverage(
        searchable=searchable,
        unsearchable=total - searchable,
        # Mirrors `searchable`, exactly as source-search coverage does: the
        # number reports how much of the snapshot this walk could enumerate
        # through the projection, not how many hits it returned.
        enumerated=searchable,
        total=total,
    )


#: The most exact revisions one `memory.get` may name. Bounded well below the
#: 256 memory ids an `ApplicationResult` can return, because each detail here
#: carries evidence, both guard directions, and a full revision list.
MAX_MEMORY_SELECTION = 50
#: The most distinct tags `memory.facets` reports. The count it reports beside
#: them is the true one, so the bound truncates the list and never the answer.
MAX_FACET_TAGS = 500


def get_memory(paths: RuntimePaths, memory_id: str) -> MemoryDetail:
    """Return one exact current or historical revision and its current head."""
    _validate_opaque_id(memory_id)
    with _read_connection(paths) as (connection, _identity):
        connection.execute("BEGIN")
        return _memory_detail(connection, memory_id)


def get_memory_head(paths: RuntimePaths, lineage_id: str) -> MemoryDetail:
    """Return the current head of one lineage without first reading a revision.

    The lineage id is the stable name a correction already carries; resolving
    it here removes the read-then-read an agent otherwise performs to turn a
    lineage back into the revision that currently speaks for it.
    """
    _validate_opaque_id(lineage_id)
    with _read_connection(paths) as (connection, _identity):
        connection.execute("BEGIN")
        head_row = connection.execute(
            "SELECT revision_id FROM current_memory_heads WHERE lineage_id = ?",
            (lineage_id,),
        ).fetchone()
        if head_row is None:
            raise NotFoundError("memory lineage identifier was not found")
        return _memory_detail(connection, str(head_row[0]))


def get_memories(
    paths: RuntimePaths,
    memory_ids: tuple[str, ...],
) -> tuple[MemoryDetail, ...]:
    """Return each named exact revision, in the order the caller named them.

    Bounded, and every id must resolve: a partial answer to a verification read
    would be indistinguishable from a Store that lost a revision.
    """
    if not 1 <= len(memory_ids) <= MAX_MEMORY_SELECTION:
        raise InvalidArgumentError("memory selection is invalid")
    if len(set(memory_ids)) != len(memory_ids):
        raise InvalidArgumentError("memory selection is duplicated")
    for memory_id in memory_ids:
        _validate_opaque_id(memory_id)
    with _read_connection(paths) as (connection, _identity):
        connection.execute("BEGIN")
        return tuple(_memory_detail(connection, memory_id) for memory_id in memory_ids)


def _memory_detail(connection: Connection, memory_id: str) -> MemoryDetail:
    """Assemble one exact revision's detail inside an open read connection."""
    row = connection.execute(
        _MEMORY_SELECT + " WHERE mr.revision_id = ?",
        (memory_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("memory revision identifier was not found")
    revision = _summary_from_row(row)
    head_row = connection.execute(
        "SELECT revision_id FROM current_memory_heads WHERE lineage_id = ?",
        (revision.lineage_id,),
    ).fetchone()
    if head_row is None:
        raise InvalidArgumentError("memory lineage has no current head")
    predecessor_row = connection.execute(
        "SELECT predecessor_id FROM memory_revisions WHERE revision_id = ?",
        (memory_id,),
    ).fetchone()
    require_invariant(predecessor_row is not None, label="memory revision row")
    evidence_rows = connection.execute(
        "SELECT ordinal, source_id, blob_digest, mode, char_start, char_end, "
        "excerpt, source_level FROM memory_evidence "
        "WHERE memory_revision_id = ? ORDER BY ordinal",
        (memory_id,),
    ).fetchall()
    evidence = tuple(_locator_from_row(item) for item in evidence_rows)
    if not evidence:
        raise InvalidArgumentError("memory revision has no retained evidence")
    current_head_id = str(head_row[0])
    # Links are lineage-level, so a historical revision reports the same
    # attachments its current head does -- the guard governs the claim, not
    # one wording of it. Both directions read one table, so the presence
    # check is made once here rather than once per direction.
    tables_ready = _guard_tables_ready(connection)
    guards = _guards_for_lineages(
        connection,
        (revision.lineage_id,),
        tables_ready=tables_ready,
    )
    return MemoryDetail(
        revision=revision,
        is_current=current_head_id == memory_id,
        current_head_id=current_head_id,
        predecessor_id=None if predecessor_row[0] is None else str(predecessor_row[0]),
        evidence=evidence,
        guards=guards.get(revision.lineage_id, ()),
        governs=_governs_for_lineage(
            connection,
            revision.lineage_id,
            tables_ready=tables_ready,
        ),
        revision_ids=_lineage_revision_ids(connection, revision.lineage_id),
    )


def _lineage_revision_ids(connection: Connection, lineage_id: str) -> tuple[str, ...]:
    """List one lineage's revisions oldest first, in recorded then stored order.

    `recorded_at` alone ties for two revisions written by the same application,
    so `rowid` breaks the tie: it is insertion order, which is the only order
    the table has that answers "which was written first".
    """
    return tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT revision_id FROM memory_revisions WHERE lineage_id = ? "
            "ORDER BY recorded_at, rowid",
            (lineage_id,),
        ).fetchall()
    )


def get_memory_facets(paths: RuntimePaths) -> MemoryFacets:
    """Report the tag and kind vocabulary the current heads actually carry.

    Counts are over current heads only, matching what `memory.search` can
    return: reporting a tag that only a superseded revision still carries would
    send a caller after a filter that answers nothing.
    """
    with _read_connection(paths) as (connection, _identity):
        connection.execute("BEGIN")
        total_tags = int(
            connection.execute(
                "SELECT count(DISTINCT tag.value) "
                "FROM current_memory_heads AS heads "
                "JOIN memory_revisions AS mr "
                "ON mr.revision_id = heads.revision_id "
                "JOIN json_each(mr.tags_json) AS tag"
            ).fetchone()[0]
        )
        tag_rows = connection.execute(
            "SELECT tag.value, count(*) FROM current_memory_heads AS heads "
            "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
            "JOIN json_each(mr.tags_json) AS tag "
            "GROUP BY tag.value ORDER BY count(*) DESC, tag.value ASC LIMIT ?",
            (MAX_FACET_TAGS,),
        ).fetchall()
        tags = tuple(
            FacetCount(value=str(row[0]), count=int(row[1])) for row in tag_rows
        )
        counted = dict(owner_kind_counts(connection))
        return MemoryFacets(
            tags=tags,
            kinds=tuple(
                FacetCount(value=kind.value, count=counted[kind.value])
                for kind in MemoryKind
                if counted[kind.value] > 0
            ),
            total_tags=total_tags,
            truncated=total_tags > len(tags),
        )


def _summary_from_row(row: Row) -> MemorySummary:
    return MemorySummary(
        memory_id=str(row[1]),
        lineage_id=str(row[2]),
        kind=MemoryKind(str(row[3])),
        statement=str(row[4]),
        occurred_on=None if row[5] is None else str(row[5]),
        valid_from=None if row[6] is None else str(row[6]),
        valid_to=None if row[7] is None else str(row[7]),
        tags=_parse_tags(row[8]),
        stored_sensitivity=Sensitivity(str(row[9])),
        effective_sensitivity=sensitivity_from_rank(int(row[10])),
        recorded_at=int(row[11]),
    )


def _validate_recorded_bound(value: object, label: str) -> int | None:
    """Bound one inclusive recorded-time filter as the integer epoch it is.

    `recorded_at` is an integer epoch on the wire, so the range bounds are
    integers too. A partial date here would need a timezone the Store does not
    have and has never been asked to guess.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgumentError(f"memory {label} filter is invalid")
    return value


def _casefolded(tags: tuple[str, ...]) -> frozenset[str]:
    return frozenset(tag.casefold() for tag in tags)


def _normalize_filters(raw: MemoryFilters) -> MemoryFilters:
    if not isinstance(raw, MemoryFilters):
        raise InvalidArgumentError("memory filters are invalid")
    try:
        kinds = tuple(MemoryKind(kind) for kind in raw.kinds)
        sensitivities = tuple(
            Sensitivity(sensitivity) for sensitivity in raw.sensitivities
        )
    except (TypeError, ValueError) as error:
        raise InvalidArgumentError("memory filter enum is invalid") from error
    if len(set(kinds)) != len(kinds) or len(set(sensitivities)) != len(sensitivities):
        raise InvalidArgumentError("memory filter enum is duplicated")
    tags_all = _normalize_tags(raw.tags_all)
    tags_any = _normalize_tags(raw.tags_any)
    occurred_from = _validate_partial_date(raw.occurred_from, "occurred_from")
    occurred_to = _validate_partial_date(raw.occurred_to, "occurred_to")
    if occurred_from is not None and occurred_to is not None:
        if partial_date_bounds(occurred_from)[0] > partial_date_bounds(occurred_to)[1]:
            raise InvalidArgumentError("memory date filter is invalid")
    recorded_from = _validate_recorded_bound(raw.recorded_from, "recorded_from")
    recorded_to = _validate_recorded_bound(raw.recorded_to, "recorded_to")
    if (
        recorded_from is not None
        and recorded_to is not None
        and recorded_from > recorded_to
    ):
        raise InvalidArgumentError("memory recorded filter is invalid")
    if not isinstance(raw.include_undated, bool):
        raise InvalidArgumentError("memory include_undated filter is invalid")
    return MemoryFilters(
        kinds=kinds,
        tags_all=tags_all,
        tags_any=tags_any,
        occurred_from=occurred_from,
        occurred_to=occurred_to,
        recorded_from=recorded_from,
        recorded_to=recorded_to,
        include_undated=raw.include_undated,
        sensitivities=sensitivities,
    )


def _matches_filters(
    *,
    kind: MemoryKind,
    occurred_on: str | None,
    recorded_at: int,
    tags: tuple[str, ...],
    sensitivity_rank: int,
    filters: MemoryFilters,
) -> bool:
    """Apply the generic bounded filters to one candidate head.

    Takes the values it reads rather than a row, so the ladder can hand it a
    lean scan row and the readers can hand it their own summary shapes without
    positional indexes having to agree across three queries.

    Tags compare case-folded on both sides. Nothing stored is rewritten: a
    revision's `tags` array is part of `memory.change-set-digest.v1`, so
    folding at write time would store something other than what the owner
    approved. Folding at read time only widens recall, so no caller loses a
    result it used to get.
    """
    sensitivity = sensitivity_from_rank(sensitivity_rank)
    folded_tags = _casefolded(tags)
    if filters.kinds and kind not in filters.kinds:
        return False
    if filters.tags_all and not _casefolded(filters.tags_all) <= folded_tags:
        return False
    if filters.tags_any and not (_casefolded(filters.tags_any) & folded_tags):
        return False
    if filters.sensitivities and sensitivity not in filters.sensitivities:
        return False
    if filters.recorded_from is not None and recorded_at < filters.recorded_from:
        return False
    if filters.recorded_to is not None and recorded_at > filters.recorded_to:
        return False
    if filters.occurred_from is not None or filters.occurred_to is not None:
        if occurred_on is None:
            # The undated case is the one an occurred bound used to drop in
            # silence. It is now a stated choice, and it defaults to keeping.
            return filters.include_undated
        occurred_start, occurred_end = partial_date_bounds(occurred_on)
        if filters.occurred_from is not None:
            filter_start = partial_date_bounds(filters.occurred_from)[0]
            if occurred_end < filter_start:
                return False
        if filters.occurred_to is not None:
            filter_end = partial_date_bounds(filters.occurred_to)[1]
            if occurred_start > filter_end:
                return False
    return True


def _fts_strengths(
    connection: Connection, query: str, upper: int
) -> dict[str, MatchStrength]:
    """Assign every exact canonical projection row its strongest ladder rung."""
    strengths: dict[str, MatchStrength] = {}
    # `memory_fts` stores every tag in one column, so an unconfined phrase
    # expression matches two adjacent tags as a phrase neither of them is.
    for strength, expression in _rung_expressions(query, phrase_column="statement"):
        for row in connection.execute(
            "SELECT revision.revision_id FROM memory_fts AS indexed "
            "JOIN memory_revisions AS revision ON "
            + _CANONICAL_MEMORY_PROJECTION_PREDICATE
            + " WHERE memory_fts MATCH ? AND revision.rowid <= ? "
            "GROUP BY revision.rowid",
            (expression, upper),
        ):
            strengths.setdefault(str(row[0]), strength)
    return strengths


def _ladder_matches(
    connection: Connection,
    query: str | None,
    filters: MemoryFilters,
    upper: int,
) -> list[_MatchEntry]:
    """Rank every filtered current head in the snapshot by its ladder rung.

    The lean half of a two-pass read: this scans and scores, and the caller
    fetches full summary rows for the visible page only. Both readers page over
    what this returns, so the rungs, the ranks and the order an owner sees in
    the browser are the ones an agent sees over MCP, by construction.

    With no query it enumerates instead of ranking. Every admitted head takes
    the `enumerated` rung at rank zero, so the sort below degenerates to stored
    order, and one snapshot digest, one resume rule and one page shape serve
    both walks rather than an enumeration path that could drift from them.
    """
    matching, _match_count = _ladder_match_set(
        connection,
        query,
        filters,
        upper,
        include_filtered_out=False,
    )
    return matching


def _ladder_matches_with_unfiltered_count(
    connection: Connection,
    query: str,
    filters: MemoryFilters,
    upper: int,
) -> tuple[list[_MatchEntry], int]:
    """Rank one owner query once and count every match before filtering."""
    return _ladder_match_set(
        connection,
        query,
        filters,
        upper,
        include_filtered_out=True,
    )


def _ladder_match_set(
    connection: Connection,
    query: str | None,
    filters: MemoryFilters,
    upper: int,
    *,
    include_filtered_out: bool,
) -> tuple[list[_MatchEntry], int]:
    """Score one corpus, retaining filtered hits and counting scored matches.

    Kernel search can reject filtered rows before scoring. Owner search also
    needs the unfiltered query-match count for its banner, so it scores those
    rows once and excludes them only from the returned filtered composition.
    """
    fts_strength = {} if query is None else _fts_strengths(connection, query, upper)
    literal_query = None if query is None else _compile_literal_query(query)
    matching: list[_MatchEntry] = []
    scored_match_count = 0
    for row in connection.execute(_LADDER_SCAN, (upper,)):
        tags = _parse_tags(row[5])
        sensitivity_rank = int(row[6])
        passes_filters = _matches_filters(
            kind=MemoryKind(str(row[2])),
            occurred_on=None if row[4] is None else str(row[4]),
            recorded_at=int(row[7]),
            tags=tags,
            sensitivity_rank=sensitivity_rank,
            filters=filters,
        )
        if not passes_filters and not include_filtered_out:
            continue
        # Joined on NUL for the reason `_HAYSTACK_JOIN` documents: a phrase
        # must not be able to straddle statement-into-tag or tag-into-tag and
        # be reported as literally present in neither.
        haystack = _HAYSTACK_JOIN.join((str(row[3]), *tags)).casefold()
        if query is None:
            scored_match_count += 1
            if not passes_filters:
                continue
            matching.append(
                _MatchEntry(
                    _STRENGTH_ORDER[MatchStrength.ENUMERATED],
                    0.0,
                    int(row[0]),
                    str(row[1]),
                    sensitivity_rank,
                )
            )
            continue
        assert literal_query is not None
        literal = literal_query.evaluate(haystack)
        strength = _strongest(
            fts_strength.get(str(row[1])),
            literal.strength,
        )
        if strength is not None:
            scored_match_count += 1
            if not passes_filters:
                continue
            # Ranked through the same function the source ladder ranks with, over
            # the same haystack the rungs were resolved against, so a rung holds
            # its hits in relevance order rather than the order they were applied.
            matching.append(
                _MatchEntry(
                    _STRENGTH_ORDER[strength],
                    literal.rank,
                    int(row[0]),
                    str(row[1]),
                    sensitivity_rank,
                )
            )
    matching.sort(key=lambda entry: (entry.strength, entry.rank, entry.rowid))
    return matching, scored_match_count


def _visible_memory_rows(
    connection: Connection, rowids: tuple[int, ...]
) -> dict[int, Row]:
    """Fetch the full summary row for one page's heads, and no others."""
    if not rowids:
        return {}
    placeholders = ", ".join("?" for _ in rowids)
    rows = connection.execute(
        _MEMORY_SELECT + f" WHERE mr.rowid IN ({placeholders})",
        rowids,
    ).fetchall()
    return {int(row[0]): row for row in rows}


def _ladder_snapshot_digest(matching: list[_MatchEntry], upper: int) -> str:
    """Bind a cursor to the exact page composition the ladder just produced."""
    payload = {
        # Ranks are bounded negative integer scores normalized to a single zero, so
        # every serialized value round-trips through JSON exactly.
        "entries": [
            [
                entry.strength,
                entry.rank + 0.0,
                entry.rowid,
                entry.revision_id,
                entry.sensitivity_rank,
            ]
            for entry in matching
        ],
        "ladder": LADDER_VERSION,
        "upper": upper,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


OWNER_MEMORY_SELECT = f"""
SELECT
    revision.rowid AS sort_id,
    revision.revision_id,
    revision.lineage_id,
    revision.kind,
    revision.statement,
    revision.occurred_on,
    revision.valid_from,
    revision.valid_to,
    revision.tags_json,
    revision.sensitivity,
    {_effective_rank_sql("revision")} AS effective_sensitivity_rank,
    revision.recorded_at,
    CASE WHEN heads.revision_id = revision.revision_id THEN 1 ELSE 0 END
        AS is_current,
    heads.revision_id AS current_head_id,
    revision.predecessor_id,
    revision.application_id,
    application_memory.ordinal AS application_ordinal
FROM memory_revisions AS revision
JOIN current_memory_heads AS heads ON heads.lineage_id = revision.lineage_id
JOIN application_memories AS application_memory
    ON application_memory.memory_revision_id = revision.revision_id
"""

OWNER_LINEAGE_SELECT = """
SELECT
    lineage.rowid,
    lineage.lineage_id,
    heads.revision_id,
    (SELECT count(*) FROM memory_revisions AS revision
     WHERE revision.lineage_id = lineage.lineage_id),
    (SELECT MAX(revision.recorded_at) FROM memory_revisions AS revision
     WHERE revision.lineage_id = lineage.lineage_id)
FROM memory_lineages AS lineage
LEFT JOIN current_memory_heads AS heads ON heads.lineage_id = lineage.lineage_id
"""


def owner_memory_summary_from_row(row: Row) -> OwnerMemorySummary:
    try:
        stored = Sensitivity(str(row[9]))
        effective = (
            Sensitivity.NORMAL,
            Sensitivity.SENSITIVE,
            Sensitivity.RESTRICTED,
        )[int(row[10])]
        kind = MemoryKind(str(row[3]))
        tags = _parse_tags(row[8])
    except (IndexError, TypeError, ValueError) as error:
        raise InvalidArgumentError("stored memory metadata is invalid") from error
    current_head_id = str(row[13])
    revision = MemorySummary(
        memory_id=str(row[1]),
        lineage_id=str(row[2]),
        kind=kind,
        statement=str(row[4]),
        occurred_on=None if row[5] is None else str(row[5]),
        valid_from=None if row[6] is None else str(row[6]),
        valid_to=None if row[7] is None else str(row[7]),
        tags=tags,
        stored_sensitivity=stored,
        effective_sensitivity=effective,
        recorded_at=int(row[11]),
    )
    return OwnerMemorySummary(
        revision=revision,
        is_current=bool(row[12]),
        current_head_id=current_head_id,
        predecessor_id=None if row[14] is None else str(row[14]),
        application_id=str(row[15]),
        application_ordinal=int(row[16]),
    )


def owner_memory_projection_coverage(
    connection: Connection,
) -> MemoryProjectionCoverage:
    current_heads = int(
        connection.execute("SELECT count(*) FROM current_memory_heads").fetchone()[0]
    )
    indexed = int(
        connection.execute(
            "SELECT count(*) FROM current_memory_heads AS heads "
            "JOIN memory_revisions AS current_revision "
            "ON current_revision.revision_id = heads.revision_id "
            "WHERE current_revision.revision_id IN ("
            + _CANONICAL_MEMORY_PROJECTION_IDS_SQL
            + ")"
        ).fetchone()[0]
    )
    projection_rows = int(
        connection.execute("SELECT count(*) FROM memory_fts").fetchone()[0]
    )
    total_revisions = int(
        connection.execute("SELECT count(*) FROM memory_revisions").fetchone()[0]
    )
    return MemoryProjectionCoverage(
        current_heads=current_heads,
        indexed_current_heads=indexed,
        missing_current_head_rows=current_heads - indexed,
        unexpected_or_duplicate_noncurrent_rows=max(0, projection_rows - indexed),
        historical_revisions_not_expected=total_revisions - current_heads,
    )


def owner_memory_matches_filters(
    kind: object,
    occurred_on: object,
    tags_json: object,
    effective_rank: object,
    filters: MemoryFilters,
    recorded_at: object = None,
) -> int:
    """Answer the same filter question `_matches_filters` answers, from SQL.

    Two surfaces answering one question differently would be worse than one
    surface that cannot answer it, so both fold tags identically and both treat
    an undated memory under an occurred bound the same way. `recorded_at` is
    optional only because the governance graph's node select does not carry it
    and its caller cannot set a recorded bound; an absent value with a bound
    set is reported as no match rather than quietly ignored.
    """
    if isinstance(effective_rank, bool) or not isinstance(effective_rank, int):
        return 0
    try:
        memory_kind = MemoryKind(str(kind))
        tags = _parse_tags(tags_json)
        sensitivity = (
            Sensitivity.NORMAL,
            Sensitivity.SENSITIVE,
            Sensitivity.RESTRICTED,
        )[effective_rank]
    except IndexError, TypeError, ValueError, InvalidArgumentError:
        return 0
    folded_tags = _casefolded(tags)
    if filters.kinds and memory_kind not in filters.kinds:
        return 0
    if filters.tags_all and not _casefolded(filters.tags_all) <= folded_tags:
        return 0
    if filters.tags_any and not (_casefolded(filters.tags_any) & folded_tags):
        return 0
    if filters.sensitivities and sensitivity not in filters.sensitivities:
        return 0
    if filters.recorded_from is not None or filters.recorded_to is not None:
        if isinstance(recorded_at, bool) or not isinstance(recorded_at, int):
            return 0
        if filters.recorded_from is not None and recorded_at < filters.recorded_from:
            return 0
        if filters.recorded_to is not None and recorded_at > filters.recorded_to:
            return 0
    if filters.occurred_from is not None or filters.occurred_to is not None:
        if occurred_on is None:
            return 1 if filters.include_undated else 0
        try:
            occurred_start, occurred_end = partial_date_bounds(str(occurred_on))
            if filters.occurred_from is not None:
                if occurred_end < partial_date_bounds(filters.occurred_from)[0]:
                    return 0
            if filters.occurred_to is not None:
                if occurred_start > partial_date_bounds(filters.occurred_to)[1]:
                    return 0
        except AssertionError, ValueError:
            return 0
    return 1


def owner_filters_payload(filters: MemoryFilters) -> dict[str, object]:
    """Render one normalized filter set as the value a cursor binds.

    Every filter the composition depends on appears here, so adding one that
    changes which rows a page holds without adding it here would let a cursor
    resume into a traversal it was never part of.
    """
    return {
        "include_undated": filters.include_undated,
        "kinds": [kind.value for kind in filters.kinds],
        "occurred_from": filters.occurred_from,
        "occurred_to": filters.occurred_to,
        "recorded_from": filters.recorded_from,
        "recorded_to": filters.recorded_to,
        "sensitivities": [item.value for item in filters.sensitivities],
        "tags_all": list(filters.tags_all),
        "tags_any": list(filters.tags_any),
    }


class _OwnerMemoryPage(NamedTuple):
    """One owner memory page plus the two counts its filter banner reports."""

    items: tuple[OwnerMemorySummary, ...]
    next_cursor: Cursor | None
    has_more: bool
    unfiltered: int
    filtered: int


def _visible_owner_memory_rows(
    connection: Connection, rowids: tuple[int, ...]
) -> dict[int, Row]:
    """Fetch the owner's fuller summary row for one page's heads."""
    if not rowids:
        return {}
    placeholders = ", ".join("?" for _ in rowids)
    rows = connection.execute(
        OWNER_MEMORY_SELECT + f" WHERE revision.rowid IN ({placeholders})",
        rowids,
    ).fetchall()
    fetched = {int(row[0]): row for row in rows}
    if len(fetched) != len(set(rowids)):
        # The ladder scans current heads directly; this select joins each head
        # to the application that wrote it. A head with no application row is a
        # broken provenance chain, reported rather than silently short-paged.
        raise InvalidArgumentError("memory application provenance is invalid")
    return fetched


def _owner_memory_enumeration(
    connection: Connection,
    identity: StoreIdentity,
    *,
    filters: MemoryFilters,
    after: int,
    upper: int,
    binding: str,
    guard: str,
    page_size: int,
) -> _OwnerMemoryPage:
    """Enumerate the filtered current heads in stored order, with no query."""
    connection.create_function(
        "pms_owner_memory_filters",
        5,
        lambda kind, occurred, tags, rank, recorded: owner_memory_matches_filters(
            kind, occurred, tags, rank, filters, recorded
        ),
        deterministic=True,
    )
    rows = connection.execute(
        "WITH owner_memories AS ("
        + OWNER_MEMORY_SELECT
        + ") SELECT * FROM owner_memories WHERE is_current = 1 "
        "AND sort_id > ? AND sort_id <= ? "
        "AND pms_owner_memory_filters(kind, occurred_on, tags_json, "
        "effective_sensitivity_rank, recorded_at) = 1 ORDER BY sort_id LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    page: OwnerPage[OwnerMemorySummary] = owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.memory.list",
        upper=upper,
        binding=binding,
        snapshot_token=guard,
        convert=owner_memory_summary_from_row,
    )
    count_prefix = "WITH owner_memories AS (" + OWNER_MEMORY_SELECT + ") "
    unfiltered = int(
        connection.execute(
            count_prefix + "SELECT count(*) FROM owner_memories WHERE is_current = 1 "
            "AND sort_id <= ?",
            (upper,),
        ).fetchone()[0]
    )
    filtered = int(
        connection.execute(
            count_prefix + "SELECT count(*) FROM owner_memories WHERE is_current = 1 "
            "AND sort_id <= ? "
            "AND pms_owner_memory_filters(kind, occurred_on, tags_json, "
            "effective_sensitivity_rank, recorded_at) = 1",
            (upper,),
        ).fetchone()[0]
    )
    return _OwnerMemoryPage(
        items=page.items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        unfiltered=unfiltered,
        filtered=filtered,
    )


def _owner_memory_ladder(
    connection: Connection,
    identity: StoreIdentity,
    *,
    query: str,
    filters: MemoryFilters,
    cursor: Cursor | None,
    after: int,
    upper: int,
    binding: str,
    guard: str,
    page_size: int,
) -> _OwnerMemoryPage:
    """Answer the owner's browser memory search with the kernel ladder itself.

    This reader used to compare case-folded substrings against statement and
    tag text with no FTS at all: no stemming, so `loving` never reached
    `loved`, and no any-term rung, so a two-word query silently required both
    words. It now pages over exactly what `search_memories` pages over.

    The two banner counts come from one ladder pass. Each current head is
    scored once, and the generic filters decide only whether a matching head
    joins the visible composition.
    """
    resume = None if cursor is None else ladder_resume(_decode_cursor(cursor), after)
    matching, unfiltered_count = _ladder_matches_with_unfiltered_count(
        connection, query, filters, upper
    )
    start_index = ladder_start_index(matching, resume)
    window = matching[start_index : start_index + page_size + 1]
    has_more = len(window) > page_size
    visible = window[:page_size]
    rows = _visible_owner_memory_rows(
        connection, tuple(entry.rowid for entry in visible)
    )
    next_cursor = (
        _encode_cursor(
            store_id=identity.store_id,
            operation="owner.memory.search",
            upper=upper,
            after=visible[-1].rowid,
            binding=binding,
            rank=visible[-1].rank,
            snapshot=guard,
            strength=visible[-1].strength,
        )
        if has_more
        else None
    )
    return _OwnerMemoryPage(
        items=tuple(
            owner_memory_summary_from_row(rows[entry.rowid]) for entry in visible
        ),
        next_cursor=next_cursor,
        has_more=has_more,
        unfiltered=unfiltered_count,
        filtered=len(matching),
    )


def owner_memory_search_page(
    connection: Connection,
    identity: StoreIdentity,
    *,
    query: str | None,
    filters: MemoryFilters,
    cursor: Cursor | None,
    limit: int,
) -> OwnerMemorySearchPage:
    """Page the owner's memories, by ladder when a query is present."""
    normalized_query = None if query is None else _validate_query(query)
    normalized_filters = _normalize_filters(filters)
    page_size = _validate_page_size(limit)
    binding_payload: dict[str, object] = {
        "query": normalized_query,
        "filters": owner_filters_payload(normalized_filters),
    }
    # Queryless owner lists have no ranked composition. Retain their version-six
    # binding bytes, including the legacy key, across the ranking-only upgrade.
    binding = (
        owner_filter_binding({**binding_payload, "ladder": 6})
        if normalized_query is None
        else owner_binding(binding_payload)
    )
    guard = owner_generation_token(connection)
    operation = (
        "owner.memory.search" if normalized_query is not None else "owner.memory.list"
    )
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation=operation,
        cursor=cursor,
        upper_table="memory_revisions",
        binding=binding,
        snapshot_token=guard,
    )
    page = (
        _owner_memory_enumeration(
            connection,
            identity,
            filters=normalized_filters,
            after=after,
            upper=upper,
            binding=binding,
            guard=guard,
            page_size=page_size,
        )
        if normalized_query is None
        else _owner_memory_ladder(
            connection,
            identity,
            query=normalized_query,
            filters=normalized_filters,
            cursor=cursor,
            after=after,
            upper=upper,
            binding=binding,
            guard=guard,
            page_size=page_size,
        )
    )
    return OwnerMemorySearchPage(
        items=page.items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        filters=normalized_filters,
        unfiltered_query_match_count=page.unfiltered,
        filtered_match_count=page.filtered,
        hidden_by_filters_count=page.unfiltered - page.filtered,
        projection_coverage=owner_memory_projection_coverage(connection),
        kind_counts=owner_kind_counts(connection),
    )


def owner_kind_counts(connection: Connection) -> tuple[tuple[str, int], ...]:
    """Count current heads per kind in one pass, including the empty kinds."""
    rows = connection.execute(
        "SELECT revision.kind, count(*) FROM current_memory_heads AS heads "
        "JOIN memory_revisions AS revision "
        "ON revision.revision_id = heads.revision_id "
        "GROUP BY revision.kind"
    ).fetchall()
    counted = {str(row[0]): int(row[1]) for row in rows}
    return tuple((kind.value, counted.get(kind.value, 0)) for kind in MemoryKind)


def owner_guard_attachment(attachment: GuardAttachment) -> OwnerGuardAttachment:
    return OwnerGuardAttachment(
        memory_id=attachment.memory_id,
        kind=attachment.kind,
        statement=attachment.statement,
        effective_sensitivity=attachment.effective_sensitivity,
    )


def owner_memory_detail(connection: Connection, memory_id: str) -> OwnerMemoryDetail:
    """Read exact revision content; the owner service pages relationships separately."""
    _validate_opaque_id(memory_id)
    row = connection.execute(
        OWNER_MEMORY_SELECT + " WHERE revision.revision_id = ?",
        (memory_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("memory revision identifier was not found")
    summary = owner_memory_summary_from_row(row)
    provenance = connection.execute(
        "SELECT application.change_set_id, application.revision_id, "
        "approval.approval_id "
        "FROM applications AS application "
        "JOIN approvals AS approval "
        "ON approval.change_set_id = application.change_set_id "
        "AND approval.revision_id = application.revision_id "
        "WHERE application.application_id = ?",
        (summary.application_id,),
    ).fetchone()
    if provenance is None:
        raise InvalidArgumentError("memory application provenance is invalid")
    evidence_rows = connection.execute(
        "SELECT ordinal, source_id, blob_digest, mode, char_start, char_end, "
        "excerpt, source_level FROM memory_evidence "
        "WHERE memory_revision_id = ? ORDER BY ordinal",
        (memory_id,),
    ).fetchall()
    evidence = tuple(_locator_from_row(item) for item in evidence_rows)
    if not evidence or len(evidence) > MAX_EVIDENCE_PER_ITEM:
        raise InvalidArgumentError("memory evidence roster is invalid")
    return OwnerMemoryDetail(
        summary=summary,
        change_set_id=str(provenance[0]),
        change_set_revision_id=str(provenance[1]),
        approval_id=str(provenance[2]),
        evidence=evidence,
    )


def owner_memory_relationship_page(
    connection: Connection,
    identity: StoreIdentity,
    memory: MemorySummary,
    direction: Literal["guards", "governs"],
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None,
) -> OwnerPage[OwnerGuardAttachment]:
    """Page live lineage links under the same generation as their owner view.

    Only the visible window and one continuation sentinel enter Python. The
    selected memory, direction, Store and generation bind each continuation;
    a revoked link or corrected endpoint therefore cannot silently shift a walk.
    """
    page_size = _validate_page_size(limit)
    if not _guard_tables_ready(connection):
        if cursor is not None:
            raise StaleCursorError("memory relationship traversal is unavailable")
        return OwnerPage(items=(), next_cursor=None, has_more=False)
    endpoint, subject = (
        ("guard_lineage_id", "governed_lineage_id")
        if direction == "guards"
        else ("governed_lineage_id", "guard_lineage_id")
    )
    operation = "owner.memory.relationships"
    binding = owner_filter_binding(
        {"memory_id": memory.memory_id, "direction": direction}
    )
    snapshot = snapshot_token or owner_generation_token(connection)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation=operation,
        cursor=cursor,
        upper_table="memory_guard_links",
        binding=binding,
        snapshot_token=snapshot,
    )
    rows = connection.execute(
        "SELECT link.rowid, "
        + _GUARD_ATTACHMENT_COLUMNS
        + "FROM memory_guard_links AS link "
        f"JOIN current_memory_heads AS heads ON heads.lineage_id = link.{endpoint} "
        "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
        f"WHERE link.{subject} = ? AND link.rowid > ? AND link.rowid <= ? "
        + _live_link_predicate(connection)
        + "ORDER BY link.rowid LIMIT ?",
        (memory.lineage_id, after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation=operation,
        upper=upper,
        binding=binding,
        snapshot_token=snapshot,
        convert=lambda row: owner_guard_attachment(_attachment_from_row(row, 1)),
    )


def owner_list_all_memories(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None,
    upper_override: int | None,
) -> OwnerPage[OwnerMemorySummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.audit.memory.list",
        cursor=cursor,
        upper_table="memory_revisions",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_MEMORY_SELECT + " WHERE revision.rowid > ? AND revision.rowid <= ? "
        "ORDER BY revision.rowid LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.audit.memory.list",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_memory_summary_from_row,
    )


def owner_lineage_summary_from_row(row: Row) -> OwnerLineageSummary:
    if row[2] is None or int(row[3]) < 1:
        raise InvalidArgumentError("memory lineage metadata is invalid")
    return OwnerLineageSummary(
        lineage_id=str(row[1]),
        current_head_id=str(row[2]),
        revision_count=int(row[3]),
        latest_recorded_at=int(row[4]),
    )


def owner_list_lineages(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerLineageSummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.memory.lineages",
        cursor=cursor,
        upper_table="memory_lineages",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_LINEAGE_SELECT + " WHERE lineage.rowid > ? AND lineage.rowid <= ? "
        "ORDER BY lineage.rowid LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.memory.lineages",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_lineage_summary_from_row,
    )


def owner_list_memory_lineage(
    connection: Connection,
    identity: StoreIdentity,
    lineage_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerMemorySummary]:
    _validate_opaque_id(lineage_id)
    if (
        connection.execute(
            "SELECT 1 FROM memory_lineages WHERE lineage_id = ?", (lineage_id,)
        ).fetchone()
        is None
    ):
        raise NotFoundError("memory lineage identifier was not found")
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"lineage_id": lineage_id})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.memory.lineage",
        cursor=cursor,
        upper_table="memory_revisions",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_MEMORY_SELECT + " WHERE revision.lineage_id = ? AND revision.rowid > ? "
        "AND revision.rowid <= ? ORDER BY revision.rowid LIMIT ?",
        (lineage_id, after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.memory.lineage",
        upper=upper,
        binding=binding,
        snapshot_token=snapshot_token,
        convert=owner_memory_summary_from_row,
    )
