"""Bounded read of the Store's approved relation graph for owner-UI lenses.

The Store holds exactly three approved relations -- batch custody, source
evidence, and guard links -- and this module reads all three at once into one
value. It infers nothing: there is no similarity, no scoring, and no derived
edge here, because a picture that draws unapproved relationships in the same
ink as approved ones teaches the owner something the Store never asserted.

The projection is disposable in the sense of AGENTS.md's ninth invariant: it
is computed on
read and persisted nowhere. Row order is fixed by rowid throughout, because the
layout downstream is a pure function of this value and must not shift between
two reads of an unchanged Store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from memory.database import Connection, Row, guard_revocations_recorded
from memory.errors import InvalidArgumentError
from memory.maintenance import guard_links_readable
from memory.memories import owner_memory_matches_filters
from memory.model import MemoryFilters, MemoryKind, Sensitivity
from memory.reviews import _parse_tags
from memory.sources import _effective_rank_sql
from memory.validation import sensitivity_from_rank

MAX_GRAPH_NODES = 2_500
"""Ceiling on drawable nodes. Above it the view refuses rather than truncates."""

MAX_GRAPH_EDGES = 6_000
MAX_GRAPH_RENDER_BYTES = 3 * 1024 * 1024
MAX_GRAPH_LAYOUT_WORK = 1_400_000
# Conservative costs include escaped labels, SVG attributes and layout work.
GRAPH_NODE_BYTES = 2_048
GRAPH_EDGE_BYTES = 512


def graph_fits_budget(nodes: int, edges: int) -> bool:
    return (
        nodes <= MAX_GRAPH_NODES
        and edges <= MAX_GRAPH_EDGES
        and nodes * GRAPH_NODE_BYTES + edges * GRAPH_EDGE_BYTES
        <= MAX_GRAPH_RENDER_BYTES
        and nodes * nodes + edges * 128 <= MAX_GRAPH_LAYOUT_WORK
    )


MAX_GRAPH_LABEL_CHARS = 120


ASPECT_TAG_PREFIX = "aspect:"


class GraphLayer(StrEnum):
    """Which node population one graph node belongs to."""

    ASPECT = "aspect"
    BATCH = "batch"
    SOURCE = "source"
    MEMORY = "memory"


class GraphEdgeKind(StrEnum):
    """Which approved relation one graph edge records."""

    CONTAINS = "contains"
    EVIDENCE = "evidence"
    GUARD = "guard"


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One drawable entity, addressed by a layer-qualified key."""

    key: str
    layer: GraphLayer
    entity_id: str
    label: str
    kind: MemoryKind | None
    sensitivity: Sensitivity
    detail_path: str
    aspect: str | None = None
    """The owner's own area tag, present on memories that carry one.

    Read straight off the approved `aspect:` tag rather than inferred from
    wording. An area the owner never declared is an area this view does not
    invent.
    """


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """One approved relation, directed from ``from_key`` to ``to_key``."""

    kind: GraphEdgeKind
    from_key: str
    to_key: str
    revoked: bool = False
    """Whether an owner-approved apply withdrew this guard relation.

    A revoked link stops governing and stops riding along on retrieval, but it
    is never deleted, so the graph keeps drawing it: the audit record of what
    once governed a claim is exactly what a governance picture is for.
    """


@dataclass(frozen=True, slots=True)
class StoreGraph:
    """The whole approved relation graph, or an honest refusal to draw it."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    total_node_count: int
    measured_node_count: int
    within_ceiling: bool
    guard_links_available: bool
    measured_edge_count: int = 0


#: The registered name of the owner's filter predicate on this connection.
#: `memories.py` registers the same predicate under its own name for the owner
#: memory list; a distinct name here keeps one read from rebinding the other's
#: closure while both are live on one connection.
_GRAPH_FILTER_SQL_FUNCTION = "pms_graph_memory_filters"

#: The filtered selection, named once and used three times: to count it before
#: anything is allocated, to read its nodes, and to trim its edges.
#:
#: A filter is a question about memories, and sources and batches are not
#: memories -- they cannot match a question about kind or tag. So they are kept
#: for what they still explain and dropped otherwise. One consequence worth
#: naming: a barren source appears only in the unfiltered graph, because it
#: evidences no memory and so answers no question about one. Its absence under
#: a filter is not its absence from the Store.
#:
#: It lives in SQL rather than in Python because the ceiling has to be measured
#: before the selection is materialised. Counting in one language and keeping
#: in another is two rules that must agree forever; this is one rule read three
#: times.
_SELECTION_CTE = f"""
WITH selected_memories AS (
    SELECT heads.lineage_id AS lineage_id
    FROM current_memory_heads AS heads
    JOIN memory_revisions AS revision ON revision.revision_id = heads.revision_id
    WHERE {_GRAPH_FILTER_SQL_FUNCTION}(
        revision.kind,
        revision.occurred_on,
        revision.tags_json,
        {_effective_rank_sql("revision")}
    ) = 1
),
selected_sources AS (
    SELECT DISTINCT evidence.source_id AS source_id
    FROM memory_evidence AS evidence
    JOIN current_memory_heads AS heads
        ON heads.revision_id = evidence.memory_revision_id
    WHERE heads.lineage_id IN (SELECT lineage_id FROM selected_memories)
),
selected_batches AS (
    SELECT DISTINCT membership.batch_id AS batch_id
    FROM inbox_batch_sources AS membership
    WHERE membership.source_id IN (SELECT source_id FROM selected_sources)
)
"""

_SELECTION_COUNT_SQL = (
    _SELECTION_CTE + "SELECT (SELECT count(*) FROM selected_memories) "
    "+ (SELECT count(*) FROM selected_sources) "
    "+ (SELECT count(*) FROM selected_batches)"
)

_MEMORY_NODE_COLUMNS = f"""
SELECT
    heads.lineage_id,
    revision.revision_id,
    revision.kind,
    revision.statement,
    {_effective_rank_sql("revision")} AS effective_rank,
    revision.occurred_on,
    revision.tags_json
FROM current_memory_heads AS heads
JOIN memory_revisions AS revision ON revision.revision_id = heads.revision_id
"""
_MEMORY_NODE_SELECT = _MEMORY_NODE_COLUMNS + "ORDER BY revision.rowid"
_SELECTED_MEMORY_NODE_SELECT = (
    _SELECTION_CTE
    + _MEMORY_NODE_COLUMNS
    + "WHERE heads.lineage_id IN (SELECT lineage_id FROM selected_memories) "
    "ORDER BY revision.rowid"
)

_SOURCE_NODE_COLUMNS = """
SELECT
    s.source_id,
    s.original_name,
    (
        SELECT MAX(
            CASE effective.sensitivity
                WHEN 'normal' THEN 0
                WHEN 'sensitive' THEN 1
                WHEN 'restricted' THEN 2
            END
        )
        FROM sources AS effective
        WHERE effective.blob_id = s.blob_id
    ) AS effective_rank
FROM sources AS s
"""
_SOURCE_NODE_SELECT = _SOURCE_NODE_COLUMNS + "ORDER BY s.rowid"
_SELECTED_SOURCE_NODE_SELECT = (
    _SELECTION_CTE
    + _SOURCE_NODE_COLUMNS
    + "WHERE s.source_id IN (SELECT source_id FROM selected_sources) "
    "ORDER BY s.rowid"
)

_BATCH_NODE_COLUMNS = "SELECT batch_id, source_count, sealed_at FROM inbox_batches "
_BATCH_NODE_SELECT = _BATCH_NODE_COLUMNS + "ORDER BY rowid"
_SELECTED_BATCH_NODE_SELECT = (
    _SELECTION_CTE
    + _BATCH_NODE_COLUMNS
    + "WHERE batch_id IN (SELECT batch_id FROM selected_batches) "
    "ORDER BY rowid"
)

_CONTAINS_EDGE_COLUMNS = "SELECT batch_id, source_id FROM inbox_batch_sources "
_CONTAINS_EDGE_SELECT = _CONTAINS_EDGE_COLUMNS + "ORDER BY batch_id, ordinal"
_SELECTED_CONTAINS_EDGE_SELECT = (
    _SELECTION_CTE
    + _CONTAINS_EDGE_COLUMNS
    + "WHERE source_id IN (SELECT source_id FROM selected_sources) "
    "ORDER BY batch_id, ordinal"
)

_EVIDENCE_EDGE_COLUMNS = """
SELECT DISTINCT evidence.source_id, heads.lineage_id
FROM memory_evidence AS evidence
JOIN current_memory_heads AS heads
    ON heads.revision_id = evidence.memory_revision_id
"""
_EVIDENCE_EDGE_SELECT = (
    _EVIDENCE_EDGE_COLUMNS + "ORDER BY evidence.source_id, heads.lineage_id"
)
_SELECTED_EVIDENCE_EDGE_SELECT = (
    _SELECTION_CTE
    + _EVIDENCE_EDGE_COLUMNS
    + "WHERE heads.lineage_id IN (SELECT lineage_id FROM selected_memories) "
    "ORDER BY evidence.source_id, heads.lineage_id"
)

#: `{revoked}` is filled with a column name this package chose, never with
#: caller input: a store the revocation heal has not reached has no such
#: column and reads a literal NULL instead.
_GUARD_EDGE_COLUMNS = (
    "SELECT guard_lineage_id, governed_lineage_id, {revoked} FROM memory_guard_links "
)
_GUARD_EDGE_SELECT = (
    _GUARD_EDGE_COLUMNS + "ORDER BY guard_lineage_id, governed_lineage_id"
)
_SELECTED_GUARD_EDGE_SELECT = (
    _SELECTION_CTE
    + _GUARD_EDGE_COLUMNS
    + "WHERE guard_lineage_id IN (SELECT lineage_id FROM selected_memories) "
    "AND governed_lineage_id IN (SELECT lineage_id FROM selected_memories) "
    "ORDER BY guard_lineage_id, governed_lineage_id"
)


def _aspect_of(tags_json: Any) -> str | None:
    """Return the one `aspect:` tag on a memory, or None.

    Exactly one is the shape the owner writes. Two would be a memory that
    genuinely spans areas, and the layout places those between their sectors
    rather than picking a winner, so this reports None instead of guessing.
    """
    try:
        tags = _parse_tags(tags_json)
    except InvalidArgumentError, TypeError, ValueError:
        return None
    found = [
        tag[len(ASPECT_TAG_PREFIX) :].strip()
        for tag in tags
        if tag.startswith(ASPECT_TAG_PREFIX) and tag[len(ASPECT_TAG_PREFIX) :].strip()
    ]
    return found[0] if len(found) == 1 else None


def _bounded_label(raw: str) -> str:
    """Collapse to one line and clip, so a label never becomes a payload."""
    collapsed = " ".join(str(raw).split())
    if len(collapsed) <= MAX_GRAPH_LABEL_CHARS:
        return collapsed
    return collapsed[: MAX_GRAPH_LABEL_CHARS - 1] + "…"


def _batch_label(sealed_at: Any, source_count: int) -> str:
    """Name a batch the way the owner thinks of it: the day it was sealed.

    Date only, not the shared `memory_time` filter: that lives in the UI shell
    and renders a minute-precision timestamp, which is noise on a node label
    and would drag a template filter into a domain read for no gain.
    """
    plural = "" if source_count == 1 else "s"
    try:
        day = datetime.fromtimestamp(int(sealed_at)).strftime("%Y-%m-%d")
    except OSError, OverflowError, TypeError, ValueError:
        return f"{source_count} source{plural}"
    return f"Sealed {day} · {source_count} source{plural}"


def _node_count(connection: Connection) -> int:
    row: Row = connection.execute(
        "SELECT (SELECT count(*) FROM inbox_batches) "
        "+ (SELECT count(*) FROM sources) "
        "+ (SELECT count(*) FROM current_memory_heads)"
    ).fetchone()
    return int(row[0])


def _register_filter(connection: Connection, filters: MemoryFilters) -> None:
    """Bind the owner's filter as one deterministic SQL predicate.

    The same `owner_memory_matches_filters` the owner memory list registers.
    Two surfaces that answer one question differently would be worse than one
    surface that cannot answer it at all, so there is exactly one predicate and
    both call it.
    """
    connection.create_function(
        _GRAPH_FILTER_SQL_FUNCTION,
        4,
        lambda kind, occurred, tags, rank: owner_memory_matches_filters(
            kind, occurred, tags, rank, filters
        ),
        deterministic=True,
    )


def _selected_node_count(connection: Connection) -> int:
    """Count the drawable entities one registered filter selects.

    One integer, read before any row is materialised: the ceiling has to be a
    bound on allocation, not a report on it.
    """
    row: Row = connection.execute(_SELECTION_COUNT_SQL).fetchone()
    return int(row[0])


def _batch_nodes(connection: Connection, *, selected: bool) -> list[GraphNode]:
    nodes: list[GraphNode] = []
    rows: list[Any] = connection.execute(
        _SELECTED_BATCH_NODE_SELECT if selected else _BATCH_NODE_SELECT
    ).fetchall()
    for row in rows:
        batch_id = str(row[0])
        count = int(row[1])
        nodes.append(
            GraphNode(
                key=f"batch:{batch_id}",
                layer=GraphLayer.BATCH,
                entity_id=batch_id,
                label=_batch_label(row[2], count),
                kind=None,
                sensitivity=Sensitivity.NORMAL,
                detail_path=f"/inbox/batches/{batch_id}",
            )
        )
    return nodes


def _source_nodes(
    connection: Connection,
    *,
    selected: bool,
    query: str | None = None,
    parameters: tuple[str, ...] = (),
) -> list[GraphNode]:
    nodes: list[GraphNode] = []
    rows: list[Any] = connection.execute(
        query or (_SELECTED_SOURCE_NODE_SELECT if selected else _SOURCE_NODE_SELECT),
        parameters,
    ).fetchall()
    for row in rows:
        source_id = str(row[0])
        nodes.append(
            GraphNode(
                key=f"source:{source_id}",
                layer=GraphLayer.SOURCE,
                entity_id=source_id,
                label=_bounded_label(str(row[1])),
                kind=None,
                sensitivity=sensitivity_from_rank(int(row[2])),
                detail_path=f"/sources/{source_id}",
            )
        )
    return nodes


def _memory_nodes(
    connection: Connection,
    *,
    selected: bool,
    query: str | None = None,
    parameters: tuple[str, ...] = (),
) -> list[GraphNode]:
    """Read the current heads this lens draws, filtered in SQL when it is."""
    nodes: list[GraphNode] = []
    rows: list[Any] = connection.execute(
        query or (_SELECTED_MEMORY_NODE_SELECT if selected else _MEMORY_NODE_SELECT),
        parameters,
    ).fetchall()
    for row in rows:
        lineage_id = str(row[0])
        revision_id = str(row[1])
        nodes.append(
            GraphNode(
                key=f"memory:{lineage_id}",
                layer=GraphLayer.MEMORY,
                entity_id=revision_id,
                label=_bounded_label(str(row[3])),
                kind=MemoryKind(str(row[2])),
                sensitivity=sensitivity_from_rank(int(row[4])),
                detail_path=f"/memories/{revision_id}",
                aspect=_aspect_of(row[6]),
            )
        )
    return nodes


def _aspect_nodes(memories: list[GraphNode]) -> list[GraphNode]:
    """One region marker per area the owner actually used.

    These are not entities and carry no detail page: an area is a tag, and the
    place to read every memory in one is the filtered list. They exist so the
    picture can be organised by what the owner said things are about.
    """
    names = sorted({node.aspect for node in memories if node.aspect is not None})
    return [
        GraphNode(
            key=f"aspect:{name}",
            layer=GraphLayer.ASPECT,
            entity_id=name,
            label=name,
            kind=None,
            sensitivity=Sensitivity.NORMAL,
            detail_path="",
            aspect=name,
        )
        for name in names
    ]


def _edges(
    connection: Connection,
    *,
    guards_ready: bool,
    selected: bool,
) -> list[GraphEdge]:
    """Read the approved relations, trimmed in SQL to the selection when filtered.

    An edge survives exactly when both of its endpoints do, which the selection
    already answers: an evidence edge follows its memory, a custody edge follows
    its source, and a guard edge needs both lineages.
    """
    edges: list[GraphEdge] = []
    contains: list[Any] = connection.execute(
        _SELECTED_CONTAINS_EDGE_SELECT if selected else _CONTAINS_EDGE_SELECT
    ).fetchall()
    for row in contains:
        edges.append(
            GraphEdge(
                kind=GraphEdgeKind.CONTAINS,
                from_key=f"batch:{row[0]}",
                to_key=f"source:{row[1]}",
            )
        )
    evidence: list[Any] = connection.execute(
        _SELECTED_EVIDENCE_EDGE_SELECT if selected else _EVIDENCE_EDGE_SELECT
    ).fetchall()
    for row in evidence:
        edges.append(
            GraphEdge(
                kind=GraphEdgeKind.EVIDENCE,
                from_key=f"source:{row[0]}",
                to_key=f"memory:{row[1]}",
            )
        )
    if guards_ready:
        # A store the revocation heal has not reached holds no revoked link, so
        # naming the column it does not have would fail a read that is already
        # answerable: every link it holds is live.
        revoked_column = (
            "revoked_at" if guard_revocations_recorded(connection) else "NULL"
        )
        template = _SELECTED_GUARD_EDGE_SELECT if selected else _GUARD_EDGE_SELECT
        guards: list[Any] = connection.execute(
            template.format(revoked=revoked_column)
        ).fetchall()
        for row in guards:
            edges.append(
                GraphEdge(
                    kind=GraphEdgeKind.GUARD,
                    from_key=f"memory:{row[0]}",
                    to_key=f"memory:{row[1]}",
                    revoked=row[2] is not None,
                )
            )
    return edges


def _edge_count(connection: Connection, *, selected: bool, guards_ready: bool) -> int:
    queries = [
        _SELECTED_CONTAINS_EDGE_SELECT if selected else _CONTAINS_EDGE_SELECT,
        _SELECTED_EVIDENCE_EDGE_SELECT if selected else _EVIDENCE_EDGE_SELECT,
    ]
    if guards_ready:
        queries.append(
            (_SELECTED_GUARD_EDGE_SELECT if selected else _GUARD_EDGE_SELECT).format(
                revoked="NULL"
            )
        )
    return sum(
        int(
            connection.execute(
                f"SELECT count(*) FROM ({query.rsplit('ORDER BY', 1)[0]})"
            ).fetchone()[0]
        )
        for query in queries
    )


def read_store_graph(
    connection: Connection,
    filters: MemoryFilters | None = None,
) -> StoreGraph:
    """Read every node and approved edge, or refuse above the drawing budget.

    `total_node_count` always reports the whole Store, filtered or not: the
    ceiling is a fact about how much there is to draw, not about how much one
    question happened to select.

    The ceiling itself measures the selection, not the Store. Measured on the
    Store, one growing corpus takes every lens away at once -- including the
    narrowed lens the refusal tells the owner to try, which is the only move it
    offers. Measured on the selection, a Store too large to draw whole still
    answers "show me this one aspect", and the refusal keeps its meaning for
    the questions that really are too big.

    SQL counts entities and relations before labels or edges are loaded.
    Node, edge, conservative rendered-byte and layout-work limits are combined.
    A second gate counts aspect markers generated from the bounded memories
    before any edge is loaded or layout runs. It refuses rather than truncates:
    a silently truncated picture lies about what the Store holds.
    """
    guards_ready = guard_links_readable(connection)
    total = _node_count(connection)
    selecting = filters is not None and filters != MemoryFilters()
    if selecting and filters is not None:
        _register_filter(connection, filters)

    edge_count = _edge_count(connection, selected=selecting, guards_ready=guards_ready)

    def refusal(measured: int) -> StoreGraph:
        # `measured` is the figure that actually crossed the ceiling, which is
        # not always the whole-Store total: a filtered read measures its own
        # selection, and the post-materialisation gate measures the scene
        # including aspect markers, which belong to no table. Reporting the
        # total there would name a number at or below the ceiling it says was
        # exceeded.
        return StoreGraph(
            nodes=(),
            edges=(),
            total_node_count=total,
            measured_node_count=measured,
            measured_edge_count=edge_count,
            within_ceiling=False,
            guard_links_available=guards_ready,
        )

    drawable = _selected_node_count(connection) if selecting else total
    if not graph_fits_budget(drawable, edge_count):
        return refusal(drawable)

    memories = _memory_nodes(connection, selected=selecting)
    nodes = [
        *_aspect_nodes(memories),
        *_batch_nodes(connection, selected=selecting),
        *_source_nodes(connection, selected=selecting),
        *memories,
    ]
    if not graph_fits_budget(len(nodes), edge_count):
        return refusal(len(nodes))
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(_edges(connection, guards_ready=guards_ready, selected=selecting)),
        total_node_count=total,
        measured_node_count=len(nodes),
        measured_edge_count=edge_count,
        within_ceiling=True,
        guard_links_available=guards_ready,
    )


def read_memory_neighbourhood(connection: Connection, memory_id: str) -> StoreGraph:
    """Read current evidence and guard neighbours for one selected lineage.

    Selection and admission happen in SQL before any node label or edge is
    materialised. Unrelated Store growth therefore cannot hide a local scene.
    A historical revision selects its lineage; the scene consistently draws
    current heads and their evidence, as the whole-Store graph does.
    """
    guards_ready = guard_links_readable(connection)
    guard_selection = (
        "SELECT guard_lineage_id, governed_lineage_id, "
        + ("revoked_at" if guard_revocations_recorded(connection) else "NULL")
        + " AS revoked_at FROM memory_guard_links "
        "WHERE guard_lineage_id IN (SELECT lineage_id FROM centre) "
        "OR governed_lineage_id IN (SELECT lineage_id FROM centre)"
        if guards_ready
        else "SELECT NULL AS guard_lineage_id, NULL AS governed_lineage_id, "
        "NULL AS revoked_at WHERE 0"
    )
    cte = f"""
WITH centre AS (
    SELECT heads.lineage_id, heads.revision_id
    FROM current_memory_heads AS heads
    JOIN memory_revisions AS selected ON selected.lineage_id = heads.lineage_id
    WHERE selected.revision_id = ?
), local_guards AS ({guard_selection}),
selected_heads AS (
    SELECT lineage_id, revision_id FROM centre
    UNION ALL
    SELECT lineage_id, revision_id FROM current_memory_heads
    WHERE lineage_id NOT IN (SELECT lineage_id FROM centre)
    AND lineage_id IN (
        SELECT guard_lineage_id FROM local_guards
        UNION SELECT governed_lineage_id FROM local_guards
    )
), local_sources AS (
    SELECT DISTINCT source_id FROM memory_evidence
    WHERE memory_revision_id IN (SELECT revision_id FROM centre)
)
"""
    parameters = (memory_id,)
    measured = connection.execute(
        cte + "SELECT (SELECT count(*) FROM selected_heads) + "
        "(SELECT count(*) FROM local_sources), "
        "(SELECT count(*) FROM local_guards) + (SELECT count(*) FROM local_sources)",
        parameters,
    ).fetchone()
    node_count, edge_count = int(measured[0]), int(measured[1])
    fits = graph_fits_budget(node_count, edge_count)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    if fits:
        nodes = [
            *_source_nodes(
                connection,
                selected=False,
                query=cte
                + _SOURCE_NODE_COLUMNS
                + "WHERE s.source_id IN (SELECT source_id FROM local_sources) ORDER BY s.rowid",
                parameters=parameters,
            ),
            *_memory_nodes(
                connection,
                selected=False,
                query=cte
                + _MEMORY_NODE_COLUMNS.replace(
                    "current_memory_heads AS heads", "selected_heads AS heads"
                )
                + "ORDER BY revision.rowid",
                parameters=parameters,
            ),
        ]
        evidence_rows: list[Any] = connection.execute(
            cte
            + "SELECT source_id, lineage_id FROM local_sources CROSS JOIN centre ORDER BY source_id",
            parameters,
        ).fetchall()
        edges = [
            GraphEdge(GraphEdgeKind.EVIDENCE, f"source:{row[0]}", f"memory:{row[1]}")
            for row in evidence_rows
        ]
        guard_rows: list[Any] = connection.execute(
            cte
            + "SELECT * FROM local_guards ORDER BY guard_lineage_id, governed_lineage_id",
            parameters,
        ).fetchall()
        edges.extend(
            GraphEdge(
                GraphEdgeKind.GUARD,
                f"memory:{row[0]}",
                f"memory:{row[1]}",
                revoked=row[2] is not None,
            )
            for row in guard_rows
        )
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=_node_count(connection),
        measured_node_count=node_count,
        measured_edge_count=edge_count,
        within_ceiling=fits,
        guard_links_available=guards_ready,
    )
