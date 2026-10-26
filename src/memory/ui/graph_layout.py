"""Pure geometry turning one `StoreGraph` into one positioned scene.

Every function here is a pure transform: same graph in, same coordinates out.
There is deliberately no random number generator in this module -- a seeded one
would still be a promise about a standard-library implementation detail, and
the layouts do not need one. Determinism is what lets the test suite pin the
picture and what stops an unchanged Store from redrawing itself differently on
every request.

The sunburst exists because generic physics failed the job. Measured on a
634-node fixture, Fruchterman-Reingold over the whole graph took 4.4 seconds
and produced an unreadable blob; this layout takes half a millisecond because
it knows that custody flows outward from a batch to a source to a claim.
"""

from __future__ import annotations

import math
from dataclasses import replace

from memory.graph import GraphEdgeKind, GraphLayer, GraphNode, StoreGraph
from memory.ui.view_models import (
    OwnerGraphEdge,
    OwnerGraphNode,
    OwnerGraphScene,
    OwnerGraphSector,
)

ASPECT_RADIUS = 9.0
BATCH_RADIUS = 8.0
SOURCE_RADIUS = 6.5
MEMORY_RADIUS = 5.0
MAX_NODE_RADIUS = 13.0
"""Ceiling on any mark, so one prolific source cannot become a dinner plate."""

# Area, not radius, carries the count -- a mark twice as wide reads as four
# times as much, so the square root is what keeps the encoding honest.
_MEMORY_GROWTH = 1.6
_SOURCE_GROWTH = 1.1

_GAP_BUDGET = 0.12
"""Share of the circle spent separating slices, however many there are.

A fixed gap per source does not survive growth: at 63 sources a 0.012-turn gap
consumed three quarters of the circle and left the content fighting over the
rest. The budget is shared instead, so the separation stays visible and the
arcs stay proportional whether the Store holds six sources or six hundred.
"""
_SOURCE_RING = 0.40
_MEMORY_RING = 0.56
_ASPECT_RING = 0.26
_SECTOR_LABEL_RING = 0.47
# Rough advance width of the sector label face at its rendered size.
_SECTOR_LABEL_EM = 6.4

_SECTOR_SHARED = "across areas"
_SECTOR_NO_MEMORY = "no memory retained"
_SECTOR_UNTAGGED = "no area recorded"
_CATCH_ALL_SECTORS = (_SECTOR_SHARED, _SECTOR_UNTAGGED, _SECTOR_NO_MEMORY)
_RING_SPACING = 17.0
_ARC_SPACING = 16.0

_SENSITIVITY_ORDER = {"normal": 0, "sensitive": 1, "restricted": 2}

_ITERATIONS = 500
_GOLDEN_ANGLE = math.pi * (3.0 - math.sqrt(5.0))


def _radius_for(layer: GraphLayer, degree: int = 0) -> float:
    """Size a mark by how much it carries.

    A memory grows with the evidence beneath it and a source with the memories
    it produced, so "what is this claim resting on" and "which document is
    load-bearing" become things the owner can see rather than click into. A
    barren source stays at the floor, which is exactly the signal wanted: it
    produced nothing, and it should look like it.
    """
    if layer is GraphLayer.ASPECT:
        return ASPECT_RADIUS
    if layer is GraphLayer.BATCH:
        return BATCH_RADIUS
    if layer is GraphLayer.SOURCE:
        return min(MAX_NODE_RADIUS, SOURCE_RADIUS + _SOURCE_GROWTH * math.sqrt(degree))
    return min(
        MAX_NODE_RADIUS,
        MEMORY_RADIUS + _MEMORY_GROWTH * math.sqrt(max(0, degree - 1)),
    )


def _positioned(
    node: GraphNode, x: float, y: float, degree: int = 0, role: str = ""
) -> OwnerGraphNode:
    return OwnerGraphNode(
        key=node.key,
        layer=node.layer.value,
        entity_id=node.entity_id,
        label=node.label,
        kind=node.kind.value if node.kind is not None else None,
        sensitivity=node.sensitivity.value,
        detail_path=node.detail_path,
        x=round(x, 1),
        y=round(y, 1),
        radius=_radius_for(node.layer, degree),
        role=role,
    )


def _straight(a: OwnerGraphNode, b: OwnerGraphNode) -> str:
    return f"M{a.x} {a.y}L{b.x} {b.y}"


def _trimmed(a: OwnerGraphNode, b: OwnerGraphNode) -> str:
    """Stop the line at the target's edge rather than its centre.

    A guard link carries an arrowhead, and an arrowhead buried inside the claim
    it points at says nothing. Trimming by the target radius puts the head where
    a reader looks for it.
    """
    dx, dy = b.x - a.x, b.y - a.y
    span = math.hypot(dx, dy)
    if span <= b.radius + 3.0:
        return _straight(a, b)
    stop = (span - b.radius - 3.0) / span
    return f"M{a.x} {a.y}L{round(a.x + dx * stop, 1)} {round(a.y + dy * stop, 1)}"


def _empty_scene(
    lens: str,
    graph: StoreGraph,
    width: float,
    height: float,
    *,
    within_ceiling: bool,
) -> OwnerGraphScene:
    return OwnerGraphScene(
        lens=lens,
        nodes=(),
        edges=(),
        width=width,
        height=height,
        total_node_count=graph.total_node_count,
        measured_node_count=graph.measured_node_count,
        measured_edge_count=graph.measured_edge_count,
        within_ceiling=within_ceiling,
        guard_links_available=graph.guard_links_available,
    )


def _edges_for(
    graph: StoreGraph,
    placed: dict[str, OwnerGraphNode],
    kinds: frozenset[GraphEdgeKind],
) -> tuple[OwnerGraphEdge, ...]:
    drawn: list[OwnerGraphEdge] = []
    for edge in graph.edges:
        if edge.kind not in kinds:
            continue
        origin = placed.get(edge.from_key)
        target = placed.get(edge.to_key)
        if origin is None or target is None:
            continue
        drawn.append(
            OwnerGraphEdge(
                kind=edge.kind.value,
                from_key=edge.from_key,
                to_key=edge.to_key,
                path=_straight(origin, target),
                # Carried even though this builder's callers ask only for
                # evidence edges: the invariant belongs to the field, not to
                # whichever filter a caller happened to pass.
                revoked=edge.revoked,
            )
        )
    return tuple(drawn)


_MAX_EXPANSION = 3.0


def _expand_to_rim(
    placed: dict[str, OwnerGraphNode],
    cx: float,
    cy: float,
    rim: float,
) -> dict[str, OwnerGraphNode]:
    """Scale the whole sunburst about its centre until it reaches the rim.

    The rings sit at fixed fractions of the canvas, which is right for a Store
    with hundreds of sources and leaves a nearly-empty canvas for one with
    three. Scaling radially about the centre keeps the centre the centre and
    preserves every ordering the layers depend on -- it only decides how much
    of the picture is picture. Capped, so a two-node Store does not become two
    dinner plates.
    """
    extent = max(
        (math.hypot(node.x - cx, node.y - cy) for node in placed.values()),
        default=0.0,
    )
    if extent <= 1.0:
        return placed
    factor = min(_MAX_EXPANSION, rim / extent)
    if factor <= 1.0:
        return placed
    return {
        key: replace(
            node,
            x=round(cx + (node.x - cx) * factor, 1),
            y=round(cy + (node.y - cy) * factor, 1),
        )
        for key, node in placed.items()
    }


def _sector_arc(
    index: int,
    name: str,
    start: float,
    end: float,
    cx: float,
    cy: float,
    radius: float,
) -> OwnerGraphSector | None:
    """Build the arc an area's name is written along, if the arc can hold it.

    Arcs whose midpoint falls in the lower half are drawn the other way round,
    because text follows its path and would otherwise hang upside down. An arc
    too short for its own name gets no label at all rather than one that spills
    across its neighbours -- a narrow area is still reachable by hovering its
    nodes and by the filters, and neither of those is made worse by silence.
    """
    if radius * abs(end - start) < len(name) * _SECTOR_LABEL_EM:
        return None
    upright = math.sin((start + end) / 2) <= 0
    first, second = (start, end) if upright else (end, start)
    sweep = 1 if upright else 0
    large = 1 if abs(end - start) > math.pi else 0
    x0 = cx + radius * math.cos(first)
    y0 = cy + radius * math.sin(first)
    x1 = cx + radius * math.cos(second)
    y1 = cy + radius * math.sin(second)
    return OwnerGraphSector(
        name=name,
        path_id=f"graph-sector-{index}",
        path=(
            f"M{x0:.1f} {y0:.1f}"
            f"A{radius:.1f} {radius:.1f} 0 {large} {sweep} {x1:.1f} {y1:.1f}"
        ),
    )


def _sector_of(
    source_key: str,
    source_memories: dict[str, list[str]],
    by_key: dict[str, GraphNode],
) -> str:
    """Name the sector a source belongs in, from its memories' own area tags.

    The owner tagged every memory with one area. A source inherits the area its
    memories agree on -- a mechanical roll-up over approved tags, the same shape
    as sensitivity propagation, not a guess about what a document is about.
    Disagreement and silence both get their own sector rather than a coin flip:
    a source whose memories span areas is genuinely cross-cutting, and one that
    produced nothing has no area to inherit.
    """
    members = source_memories.get(source_key, ())
    if not members:
        return _SECTOR_NO_MEMORY
    aspects = sorted(
        {aspect for key in members if (aspect := by_key[key].aspect) is not None}
    )
    if not aspects:
        return _SECTOR_UNTAGGED
    return aspects[0] if len(aspects) == 1 else _SECTOR_SHARED


def custody_sunburst(
    graph: StoreGraph,
    *,
    width: float = 1200.0,
    height: float = 820.0,
) -> OwnerGraphScene:
    """Lay custody out as a sunburst, grouped by the owner's own areas.

    The centre used to be inbox batches. A batch is a custody artifact -- these
    files were sealed together at one moment -- and it was the layout's primary
    spatial axis, so proximity on the rim meant "arrived the same day" while
    reading as relatedness. Batches also accumulate forever and never merge. The
    areas the owner already tags every memory with are a small, slow vocabulary
    that means something, so they organise the picture instead. Batch custody
    stays in the Inbox, the audit, and every source's detail page.

    Guard edges are excluded on purpose. In the prototype, 66 guard chords
    across the middle drowned 728 evidence lines; governance is its own lens.
    """
    if not graph.within_ceiling:
        return _empty_scene("provenance", graph, width, height, within_ceiling=False)

    cx, cy = width / 2, height / 2
    max_r = min(width, height) / 2 - 24

    by_key = {node.key: node for node in graph.nodes}
    sources = [n for n in graph.nodes if n.layer is GraphLayer.SOURCE]
    aspects = [n for n in graph.nodes if n.layer is GraphLayer.ASPECT]

    source_memories: dict[str, list[str]] = {n.key: [] for n in sources}
    memory_sources: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind is GraphEdgeKind.EVIDENCE:
            source_memories.setdefault(edge.from_key, []).append(edge.to_key)
            memory_sources.setdefault(edge.to_key, []).append(edge.from_key)

    sector_of = {
        source.key: _sector_of(source.key, source_memories, by_key)
        for source in sources
    }
    # Named areas first and alphabetical, then the two catch-alls last, so the
    # ring reads as the owner's own vocabulary with the leftovers at the end.
    named = sorted({s for s in sector_of.values() if s not in _CATCH_ALL_SECTORS})
    sector_order = named + [s for s in _CATCH_ALL_SECTORS if s in sector_of.values()]

    ordered = sorted(
        sources, key=lambda n: (sector_order.index(sector_of[n.key]), n.key)
    )
    weights = [max(1.0, len(source_memories[n.key]) ** 0.72) for n in ordered]
    total_weight = sum(weights) or 1.0
    gap = math.tau * _GAP_BUDGET / max(1, len(ordered))
    usable = math.tau * (1.0 - _GAP_BUDGET)

    # Every area is guaranteed enough arc to carry its own name, and the rest of
    # the circle is shared out by weight. Proportion still reads -- a large area
    # is still visibly larger -- but an area is the thing this picture is
    # organised by, and an area nobody can name is one nobody can find. If the
    # floors alone would fill the circle there is nothing to guarantee, so the
    # split falls back to pure proportion and short names drop as before.
    label_radius = max_r * _SECTOR_LABEL_RING
    floors = {
        sector: (len(sector) + 2) * _SECTOR_LABEL_EM / label_radius
        for sector in sector_order
    }
    scaled: dict[str, float] = {}
    if label_radius > 0 and sum(floors.values()) < usable * 0.75:
        sector_weight = dict.fromkeys(sector_order, 0.0)
        for source, weight in zip(ordered, weights, strict=True):
            sector_weight[sector_of[source.key]] += weight
        spare = usable - sum(floors.values())
        for sector in sector_order:
            share = sector_weight[sector] / total_weight
            scaled[sector] = floors[sector] + spare * share

    slice_start: dict[str, float] = {}
    slice_width: dict[str, float] = {}
    cursor = -math.pi / 2
    for source, weight in zip(ordered, weights, strict=True):
        if scaled:
            sector = sector_of[source.key]
            sector_total = sum(
                w
                for s, w in zip(ordered, weights, strict=True)
                if sector_of[s.key] == sector
            )
            span = scaled[sector] * (weight / (sector_total or 1.0))
        else:
            span = usable * (weight / total_weight)
        slice_start[source.key] = cursor
        slice_width[source.key] = span
        cursor += span + gap

    placed: dict[str, OwnerGraphNode] = {}
    for source in ordered:
        angle = slice_start[source.key] + slice_width[source.key] / 2
        placed[source.key] = _positioned(
            source,
            cx + max_r * _SOURCE_RING * math.cos(angle),
            cy + max_r * _SOURCE_RING * math.sin(angle),
            len(source_memories[source.key]),
        )

    # One region marker per area, at the centre of the arc its sources occupy.
    sector_bounds: dict[str, tuple[float, float]] = {}
    for source in ordered:
        sector = sector_of[source.key]
        low = slice_start[source.key]
        high = low + slice_width[source.key]
        if sector in sector_bounds:
            first, _last = sector_bounds[sector]
            sector_bounds[sector] = (first, high)
        else:
            sector_bounds[sector] = (low, high)
    for aspect in aspects:
        bounds = sector_bounds.get(aspect.entity_id)
        if bounds is None:
            continue
        angle = (bounds[0] + bounds[1]) / 2
        placed[aspect.key] = _positioned(
            aspect,
            cx + max_r * _ASPECT_RING * math.cos(angle),
            cy + max_r * _ASPECT_RING * math.sin(angle),
        )
    sectors = tuple(
        arc
        for index, (name, (low, high)) in enumerate(
            sorted(sector_bounds.items(), key=lambda entry: entry[1][0])
        )
        if (
            arc := _sector_arc(
                index, name, low, high, cx, cy, max_r * _SECTOR_LABEL_RING
            )
        )
        is not None
    )

    rim = max_r - MAX_NODE_RADIUS
    for source in ordered:
        members = [
            key
            for key in sorted(source_memories[source.key])
            if len(memory_sources.get(key, ())) == 1
        ]
        if not members:
            continue
        start = slice_start[source.key]
        span = slice_width[source.key]
        radius = max_r * _MEMORY_RING
        capacity = max(1, int(radius * span / _ARC_SPACING))
        seat = 0
        for key in members:
            if seat >= capacity:
                # Clamp at the rim. A source with hundreds of memories in a
                # narrow slice would otherwise walk its outer rings off the
                # canvas, and a node the owner cannot see is a node they
                # cannot fix. At the rim, seats tighten instead of moving out.
                radius = min(rim, radius + _RING_SPACING)
                capacity = max(1, int(radius * span / _ARC_SPACING))
                if radius >= rim:
                    capacity = max(capacity, len(members))
                seat = 0
            angle = start + span * ((seat + 0.5) / capacity)
            placed[key] = _positioned(
                by_key[key],
                cx + radius * math.cos(angle),
                cy + radius * math.sin(angle),
                len(memory_sources.get(key, ())),
            )
            seat += 1

    for key, owners in sorted(memory_sources.items()):
        if key in placed or not owners:
            continue
        angles = [
            slice_start[owner] + slice_width[owner] / 2
            for owner in owners
            if owner in slice_start
        ]
        if not angles:
            continue
        mean_x = sum(math.cos(a) for a in angles) / len(angles)
        mean_y = sum(math.sin(a) for a in angles) / len(angles)
        angle = math.atan2(mean_y, mean_x)
        spread = math.hypot(mean_x, mean_y)
        distance = max_r * _SOURCE_RING * 0.52 * spread + 18.0
        placed[key] = _positioned(
            by_key[key],
            cx + distance * math.cos(angle),
            cy + distance * math.sin(angle),
            len(owners),
        )

    # A memory with no evidence edge cannot exist in a valid Store, but an
    # un-upgraded projection could still hand us one. Park it on the rim rather
    # than dropping it: a node the owner cannot see is a node they cannot fix.
    orphan_angle = -math.pi / 2
    for node in graph.nodes:
        if node.key in placed or node.layer is GraphLayer.BATCH:
            continue
        placed[node.key] = _positioned(
            node,
            cx + rim * math.cos(orphan_angle),
            cy + rim * math.sin(orphan_angle),
        )
        orphan_angle += 0.08

    placed = _expand_to_rim(placed, cx, cy, rim)

    drawn = [node for node in graph.nodes if node.key in placed]
    return OwnerGraphScene(
        lens="provenance",
        nodes=tuple(placed[node.key] for node in drawn),
        edges=_edges_for(graph, placed, frozenset({GraphEdgeKind.EVIDENCE})),
        width=width,
        height=height,
        total_node_count=graph.total_node_count,
        measured_node_count=graph.measured_node_count,
        measured_edge_count=graph.measured_edge_count,
        within_ceiling=True,
        guard_links_available=graph.guard_links_available,
        sectors=sectors,
    )


def _fit(
    points: list[list[float]],
    radii: list[float],
    width: float,
    height: float,
) -> None:
    """Scale and centre a settled layout into the viewport, radii included."""
    pad = 24.0 + (max(radii) if radii else 0.0)
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    span_x = (max(xs) - min(xs)) or 1.0
    span_y = (max(ys) - min(ys)) or 1.0
    scale = min((width - 2 * pad) / span_x, (height - 2 * pad) / span_y)
    offset_x = (width - span_x * scale) / 2
    offset_y = (height - span_y * scale) / 2
    low_x, low_y = min(xs), min(ys)
    for point in points:
        point[0] = (point[0] - low_x) * scale + offset_x
        point[1] = (point[1] - low_y) * scale + offset_y


def _settle(
    count: int,
    pairs: list[tuple[int, int]],
    width: float,
    height: float,
) -> list[list[float]]:
    """Run seeded Fruchterman-Reingold with grid-approximated repulsion.

    Phyllotaxis seeding rather than random placement: it spreads evenly, needs
    no generator, and roughly halves the iterations required to settle.
    """
    area = width * height
    k = math.sqrt(area / count)
    points = [[0.0, 0.0] for _ in range(count)]
    for index in range(count):
        distance = k * math.sqrt(index) * 0.9
        angle = index * _GOLDEN_ANGLE
        points[index][0] = distance * math.cos(angle)
        points[index][1] = distance * math.sin(angle)

    temperature = width / 8.0
    cooling = temperature / (_ITERATIONS + 1)
    cell = k * 2.0

    for _ in range(_ITERATIONS):
        forces = [[0.0, 0.0] for _ in range(count)]
        buckets: dict[tuple[int, int], list[int]] = {}
        for index, point in enumerate(points):
            buckets.setdefault(
                (int(point[0] // cell), int(point[1] // cell)), []
            ).append(index)
        for (bucket_x, bucket_y), occupants in buckets.items():
            near: list[int] = []
            for offset_x in (-1, 0, 1):
                for offset_y in (-1, 0, 1):
                    near.extend(
                        buckets.get((bucket_x + offset_x, bucket_y + offset_y), ())
                    )
            for i in occupants:
                for j in near:
                    if i == j:
                        continue
                    dx = points[i][0] - points[j][0]
                    dy = points[i][1] - points[j][1]
                    squared = dx * dx + dy * dy
                    if squared < 1e-6:
                        dx, dy, squared = 0.01 * (i - j), 0.01, 1e-4
                    distance = math.sqrt(squared)
                    push = (k * k / distance) * 0.5
                    forces[i][0] += dx / distance * push
                    forces[i][1] += dy / distance * push
        for i, j in pairs:
            dx = points[i][0] - points[j][0]
            dy = points[i][1] - points[j][1]
            distance = math.sqrt(dx * dx + dy * dy) or 0.01
            pull = (distance * distance / k) * 1.6
            forces[i][0] -= dx / distance * pull
            forces[i][1] -= dy / distance * pull
            forces[j][0] += dx / distance * pull
            forces[j][1] += dy / distance * pull
        for index, force in enumerate(forces):
            magnitude = math.hypot(force[0], force[1]) or 1.0
            step = min(magnitude, temperature)
            points[index][0] += force[0] / magnitude * step
            points[index][1] += force[1] / magnitude * step
        temperature -= cooling
    return points


def guard_constellation(
    graph: StoreGraph,
    *,
    width: float = 1160.0,
    height: float = 560.0,
) -> OwnerGraphScene:
    """Lay out only the guarded subgraph, then settle it with seeded forces.

    The subgraph is built *before* the simulation, never filtered after it. A
    layout run over the whole Store and rendered down to the guarded nodes lets
    every unrelated memory contribute repulsion, which collapses the result
    into a line -- the prototype did exactly that, and
    ``test_unguarded_memories_do_not_influence_the_layout`` is the pin that
    stops it coming back.
    """
    if not graph.within_ceiling:
        return _empty_scene("governance", graph, width, height, within_ceiling=False)

    guard_edges = [edge for edge in graph.edges if edge.kind is GraphEdgeKind.GUARD]
    involved = {edge.from_key for edge in guard_edges}
    involved |= {edge.to_key for edge in guard_edges}
    members = [node for node in graph.nodes if node.key in involved]
    if not members:
        return _empty_scene("governance", graph, width, height, within_ceiling=True)

    seat = {node.key: index for index, node in enumerate(members)}
    points = _settle(
        len(members),
        [(seat[edge.from_key], seat[edge.to_key]) for edge in guard_edges],
        width,
        height,
    )
    _fit(points, [_radius_for(node.layer) for node in members], width, height)

    # A guard and the claim it governs are both memories. Nothing about either
    # entity says which is which, so the lens has to mark the part they play.
    guarding = {edge.from_key for edge in guard_edges}
    placed = {
        node.key: _positioned(
            node,
            points[seat[node.key]][0],
            points[seat[node.key]][1],
            role="guard" if node.key in guarding else "",
        )
        for node in members
    }
    ranks = {node.key: _SENSITIVITY_ORDER[node.sensitivity.value] for node in members}
    edges = tuple(
        OwnerGraphEdge(
            kind=edge.kind.value,
            from_key=edge.from_key,
            to_key=edge.to_key,
            path=_trimmed(placed[edge.from_key], placed[edge.to_key]),
            # A revoked link governs nothing, so it cannot be an inversion.
            # Leaving it inverted would draw a repaired mis-attachment in the
            # same red the lens calls a standing violation, and revocation is
            # final for that pair -- the arrow would never clear.
            inverted=not edge.revoked and ranks[edge.from_key] > ranks[edge.to_key],
            revoked=edge.revoked,
        )
        for edge in guard_edges
    )
    return OwnerGraphScene(
        lens="governance",
        nodes=tuple(placed[node.key] for node in members),
        edges=edges,
        width=width,
        height=height,
        total_node_count=graph.total_node_count,
        measured_node_count=graph.measured_node_count,
        measured_edge_count=graph.measured_edge_count,
        within_ceiling=True,
        guard_links_available=graph.guard_links_available,
    )


def radial_neighbourhood(
    graph: StoreGraph,
    centre_key: str,
    *,
    width: float = 520.0,
    height: float = 360.0,
) -> OwnerGraphScene:
    """Place one entity at the centre with its one-hop neighbours on a ring.

    Neighbour order follows the key, not the edge order, so the panel does not
    reshuffle itself when an unrelated batch is applied.
    """
    by_key = {node.key: node for node in graph.nodes}
    centre = by_key.get(centre_key)
    if centre is None or not graph.within_ceiling:
        return _empty_scene(
            "neighbourhood",
            graph,
            width,
            height,
            within_ceiling=graph.within_ceiling,
        )

    touching = [
        edge for edge in graph.edges if centre_key in (edge.from_key, edge.to_key)
    ]
    neighbours = sorted(
        {
            edge.to_key if edge.from_key == centre_key else edge.from_key
            for edge in touching
        }
        & set(by_key)
    )

    cx, cy = width / 2, height / 2
    ring = min(width, height) / 2 - 34.0
    placed = {centre_key: _positioned(centre, cx, cy)}
    for index, key in enumerate(neighbours):
        angle = -math.pi / 2 + math.tau * (index / max(1, len(neighbours)))
        placed[key] = _positioned(
            by_key[key], cx + ring * math.cos(angle), cy + ring * math.sin(angle)
        )

    ranks = {key: _SENSITIVITY_ORDER[by_key[key].sensitivity.value] for key in placed}
    edges = tuple(
        OwnerGraphEdge(
            kind=edge.kind.value,
            from_key=edge.from_key,
            to_key=edge.to_key,
            path=_straight(placed[edge.from_key], placed[edge.to_key]),
            inverted=(
                edge.kind is GraphEdgeKind.GUARD
                and not edge.revoked
                and ranks[edge.from_key] > ranks[edge.to_key]
            ),
            revoked=edge.revoked,
        )
        for edge in touching
        if edge.from_key in placed and edge.to_key in placed
    )
    return OwnerGraphScene(
        lens="neighbourhood",
        nodes=tuple(placed[key] for key in [centre_key, *neighbours]),
        edges=edges,
        width=width,
        height=height,
        total_node_count=graph.total_node_count,
        measured_node_count=graph.measured_node_count,
        measured_edge_count=graph.measured_edge_count,
        within_ceiling=True,
        guard_links_available=graph.guard_links_available,
    )
