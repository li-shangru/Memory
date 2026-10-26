"""Pure geometry for the owner-UI graph lenses."""

from __future__ import annotations

import inspect
import math
from dataclasses import replace
from pathlib import Path
from typing import cast

from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.runtime import Macro

from memory.graph import (
    MAX_GRAPH_LABEL_CHARS,
    MAX_GRAPH_NODES,
    GraphEdge,
    GraphEdgeKind,
    GraphLayer,
    GraphNode,
    StoreGraph,
)
from memory.model import MemoryKind, Sensitivity
from memory.ui import graph_layout
from memory.ui.graph_layout import (
    MAX_NODE_RADIUS,
    custody_sunburst,
    guard_constellation,
    radial_neighbourhood,
)
from memory.ui.request_limits import MAX_STANDARD_HTML_RESPONSE_BYTES
from memory.ui.view_models import OwnerGraphEdge, OwnerGraphNode, OwnerGraphScene

WIDTH = 1200.0
HEIGHT = 820.0


def node(key: str, layer: GraphLayer, aspect: str | None = None) -> GraphNode:
    return GraphNode(
        key=key,
        layer=layer,
        entity_id=key.split(":", 1)[1],
        label=key,
        kind=MemoryKind.FACT if layer is GraphLayer.MEMORY else None,
        sensitivity=Sensitivity.NORMAL,
        detail_path="" if layer is GraphLayer.ASPECT else f"/{layer.value}/{key}",
        aspect=aspect if layer is GraphLayer.MEMORY else None,
    )


def fixture() -> StoreGraph:
    """One batch, three sources -- one of them barren -- and four memories."""
    nodes = [
        node("batch:bat_1", GraphLayer.BATCH),
        node("source:src_1", GraphLayer.SOURCE),
        node("source:src_2", GraphLayer.SOURCE),
        node("source:src_barren", GraphLayer.SOURCE),
        node("memory:lin_1", GraphLayer.MEMORY),
        node("memory:lin_2", GraphLayer.MEMORY),
        node("memory:lin_3", GraphLayer.MEMORY),
        node("memory:lin_bridge", GraphLayer.MEMORY),
    ]
    edges = [
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_1"),
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_2"),
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_barren"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_1", "memory:lin_1"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_1", "memory:lin_2"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_2", "memory:lin_3"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_1", "memory:lin_bridge"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_2", "memory:lin_bridge"),
        GraphEdge(GraphEdgeKind.GUARD, "memory:lin_1", "memory:lin_3"),
    ]
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )


def placed(scene: OwnerGraphScene, key: str) -> OwnerGraphNode:
    return next(item for item in scene.nodes if item.key == key)


def radius_of(scene: OwnerGraphScene, key: str) -> float:
    item = placed(scene, key)
    return math.hypot(item.x - scene.width / 2, item.y - scene.height / 2)


def test_sunburst_is_deterministic() -> None:
    first = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    second = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    assert [(n.key, n.x, n.y) for n in first.nodes] == [
        (n.key, n.x, n.y) for n in second.nodes
    ]


def test_every_node_lands_inside_the_viewport() -> None:
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    for item in scene.nodes:
        assert item.radius <= item.x <= scene.width - item.radius
        assert item.radius <= item.y <= scene.height - item.radius


def test_layers_are_ordered_outward_from_the_centre() -> None:
    scene = custody_sunburst(aspect_fixture(), width=WIDTH, height=HEIGHT)
    assert radius_of(scene, "aspect:finance") < radius_of(scene, "source:src_money")
    assert radius_of(scene, "source:src_money") < radius_of(scene, "memory:lin_money")


def test_the_provenance_lens_draws_no_batch() -> None:
    """Custody by day was the old organising axis and is deliberately gone.

    A batch is "these files were sealed together at one moment" -- an audit
    unit that accumulates forever and never merges. It stays in the Inbox, the
    audit, and every source's detail page; it is no longer what the picture is
    organised by.
    """
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    assert [item for item in scene.nodes if item.layer == "batch"] == []
    assert [edge for edge in scene.edges if edge.kind == "contains"] == []


def test_a_multi_source_memory_bridges_inside_the_source_ring() -> None:
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    assert radius_of(scene, "memory:lin_bridge") < radius_of(scene, "source:src_1")


def test_a_barren_source_is_placed_but_fans_nothing() -> None:
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    assert placed(scene, "source:src_barren") is not None
    fanned = [edge for edge in scene.edges if edge.from_key == "source:src_barren"]
    assert fanned == []


def test_guard_edges_are_absent_from_the_provenance_lens() -> None:
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    assert [edge for edge in scene.edges if edge.kind == "guard"] == []


def test_a_crowded_slice_stays_inside_the_rim() -> None:
    """A source with hundreds of memories must not walk its rings off-canvas."""
    nodes = [node("source:src_dense", GraphLayer.SOURCE)]
    edges = []
    for index in range(400):
        key = f"memory:lin_{index:03d}"
        nodes.append(node(key, GraphLayer.MEMORY))
        edges.append(GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_dense", key))
    graph = StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )
    scene = custody_sunburst(graph, width=WIDTH, height=HEIGHT)
    for item in scene.nodes:
        assert item.radius <= item.x <= scene.width - item.radius
        assert item.radius <= item.y <= scene.height - item.radius


def guarded_fixture(extra_unguarded: int) -> StoreGraph:
    """Two guard links plus however many memories touch no guard at all."""
    nodes = [
        node("memory:lin_guard", GraphLayer.MEMORY),
        node("memory:lin_claim_a", GraphLayer.MEMORY),
        node("memory:lin_claim_b", GraphLayer.MEMORY),
    ]
    for index in range(extra_unguarded):
        nodes.append(node(f"memory:lin_free_{index:03d}", GraphLayer.MEMORY))
    edges = [
        GraphEdge(GraphEdgeKind.GUARD, "memory:lin_guard", "memory:lin_claim_a"),
        GraphEdge(GraphEdgeKind.GUARD, "memory:lin_guard", "memory:lin_claim_b"),
    ]
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )


def test_a_revoked_link_is_drawn_apart_and_never_as_an_inversion() -> None:
    """Catch a repaired mis-attachment still drawn as a violation to repair.

    The owner guide tells the owner the governance lens keeps a revoked link
    "marked revoked", and the lens's own lede tells them an inverted arrow is a
    standing violation to fix. A revoked link governs nothing, so it cannot be
    an inversion -- and revocation is final for that pair, so an arrow left red
    would never clear and would send the owner to repair a repair.
    """
    guard = node("memory:lin_guard", GraphLayer.MEMORY)
    claim = node("memory:lin_claim_a", GraphLayer.MEMORY)
    restricted_guard = replace(guard, sensitivity=Sensitivity.RESTRICTED)
    graph = StoreGraph(
        nodes=(restricted_guard, claim),
        edges=(
            GraphEdge(
                GraphEdgeKind.GUARD,
                "memory:lin_guard",
                "memory:lin_claim_a",
                revoked=True,
            ),
        ),
        total_node_count=2,
        measured_node_count=2,
        within_ceiling=True,
        guard_links_available=True,
    )

    scene = guard_constellation(graph, width=1160.0, height=560.0)

    assert len(scene.edges) == 1
    edge = scene.edges[0]
    # The guard outranks the claim, so an unrevoked link here would invert.
    assert edge.revoked is True
    assert edge.inverted is False


def test_every_lens_that_draws_an_edge_preserves_its_revoked_state() -> None:
    """Catch one lens learning about revocation while another does not.

    Three producers build `OwnerGraphEdge`, and the revoked state was added to
    one of them. A lens that drops it draws a revoked link exactly like a live
    one -- and, when the guard outranks the claim, in the red the governance
    lede calls a standing violation to repair. Revocation is final for a pair,
    so such an arrow never clears. Reading the source is the only check that
    covers a producer no fixture happens to exercise.
    """
    source = inspect.getsource(graph_layout)
    constructions = source.count("OwnerGraphEdge(")
    assert constructions == source.count("revoked=edge.revoked"), (
        "every OwnerGraphEdge construction must carry the edge's revoked state"
    )
    # And no producer may call a revoked link an inversion.
    assert source.count("inverted=") == source.count("not edge.revoked")


def test_the_neighbourhood_lens_marks_a_revoked_link_too() -> None:
    """The behavioural half of the guard above, on the second guard lens."""
    guard = replace(
        node("memory:lin_guard", GraphLayer.MEMORY),
        sensitivity=Sensitivity.RESTRICTED,
    )
    claim = node("memory:lin_claim_a", GraphLayer.MEMORY)
    graph = StoreGraph(
        nodes=(guard, claim),
        edges=(
            GraphEdge(
                GraphEdgeKind.GUARD,
                "memory:lin_guard",
                "memory:lin_claim_a",
                revoked=True,
            ),
        ),
        total_node_count=2,
        measured_node_count=2,
        within_ceiling=True,
        guard_links_available=True,
    )

    scene = radial_neighbourhood(graph, "memory:lin_claim_a", width=800.0, height=520.0)

    assert [(edge.revoked, edge.inverted) for edge in scene.edges] == [(True, False)]


def test_constellation_holds_only_the_guarded_subgraph() -> None:
    scene = guard_constellation(guarded_fixture(40), width=1160.0, height=560.0)
    assert {item.key for item in scene.nodes} == {
        "memory:lin_guard",
        "memory:lin_claim_a",
        "memory:lin_claim_b",
    }
    assert len(scene.edges) == 2


def test_unguarded_memories_do_not_influence_the_layout() -> None:
    """The regression pin: ungoverned nodes must not contribute repulsion."""
    few = guard_constellation(guarded_fixture(0), width=1160.0, height=560.0)
    many = guard_constellation(guarded_fixture(400), width=1160.0, height=560.0)
    assert [(n.key, n.x, n.y) for n in few.nodes] == [
        (n.key, n.x, n.y) for n in many.nodes
    ]


def test_constellation_is_deterministic_and_inside_the_viewport() -> None:
    first = guard_constellation(guarded_fixture(12), width=1160.0, height=560.0)
    second = guard_constellation(guarded_fixture(12), width=1160.0, height=560.0)
    assert [(n.key, n.x, n.y) for n in first.nodes] == [
        (n.key, n.x, n.y) for n in second.nodes
    ]
    for item in first.nodes:
        assert item.radius <= item.x <= first.width - item.radius
        assert item.radius <= item.y <= first.height - item.radius


def test_a_guard_above_its_claim_is_marked_inverted() -> None:
    base = guarded_fixture(0)
    raised = tuple(
        GraphNode(
            key=item.key,
            layer=item.layer,
            entity_id=item.entity_id,
            label=item.label,
            kind=item.kind,
            sensitivity=(
                Sensitivity.RESTRICTED
                if item.key == "memory:lin_guard"
                else Sensitivity.NORMAL
            ),
            detail_path=item.detail_path,
        )
        for item in base.nodes
    )
    graph = StoreGraph(
        nodes=raised,
        edges=base.edges,
        total_node_count=len(raised),
        measured_node_count=len(raised),
        within_ceiling=True,
        guard_links_available=True,
    )
    scene = guard_constellation(graph, width=1160.0, height=560.0)
    assert scene.edges
    assert all(edge.inverted for edge in scene.edges)


def test_a_guard_at_or_below_its_claim_is_not_marked_inverted() -> None:
    scene = guard_constellation(guarded_fixture(0), width=1160.0, height=560.0)
    assert scene.edges
    assert not any(edge.inverted for edge in scene.edges)


def test_a_store_with_no_guard_links_draws_no_constellation() -> None:
    base = fixture()
    unguarded = StoreGraph(
        nodes=base.nodes,
        edges=tuple(e for e in base.edges if e.kind is not GraphEdgeKind.GUARD),
        total_node_count=base.total_node_count,
        measured_node_count=base.total_node_count,
        within_ceiling=True,
        guard_links_available=True,
    )
    scene = guard_constellation(unguarded, width=1160.0, height=560.0)
    assert scene.nodes == ()
    assert scene.within_ceiling is True


def test_a_refused_graph_lays_out_as_an_empty_scene() -> None:
    refused = StoreGraph(
        nodes=(),
        edges=(),
        total_node_count=9_000,
        measured_node_count=9_000,
        within_ceiling=False,
        guard_links_available=True,
    )
    scene = custody_sunburst(refused, width=WIDTH, height=HEIGHT)
    assert scene.nodes == ()
    assert scene.within_ceiling is False
    assert scene.total_node_count == 9_000


def test_neighbourhood_centres_the_subject_and_rings_its_neighbours() -> None:
    scene = radial_neighbourhood(fixture(), "memory:lin_1", width=520.0, height=360.0)
    centre = placed(scene, "memory:lin_1")
    assert centre.x == round(scene.width / 2, 1)
    assert centre.y == round(scene.height / 2, 1)
    assert {item.key for item in scene.nodes} == {
        "memory:lin_1",
        "source:src_1",
        "memory:lin_3",
    }


def test_neighbourhood_is_deterministic() -> None:
    first = radial_neighbourhood(fixture(), "memory:lin_1", width=520.0, height=360.0)
    second = radial_neighbourhood(fixture(), "memory:lin_1", width=520.0, height=360.0)
    assert [(n.key, n.x, n.y) for n in first.nodes] == [
        (n.key, n.x, n.y) for n in second.nodes
    ]


def test_neighbourhood_of_an_unknown_key_is_empty() -> None:
    scene = radial_neighbourhood(fixture(), "memory:absent", width=520.0, height=360.0)
    assert scene.nodes == ()
    assert scene.edges == ()


def test_neighbourhood_keeps_every_node_inside_the_viewport() -> None:
    scene = radial_neighbourhood(fixture(), "source:src_1", width=520.0, height=360.0)
    for item in scene.nodes:
        assert item.radius <= item.x <= scene.width - item.radius
        assert item.radius <= item.y <= scene.height - item.radius


def test_a_ceiling_sized_scene_fits_the_standard_response_bound() -> None:
    """A full-ceiling scene must not be able to blow the page bound.

    If this ever fails the fix is a smaller ceiling or a shorter label bound,
    never a larger response ceiling.
    """
    label = "x" * MAX_GRAPH_LABEL_CHARS
    nodes = tuple(
        OwnerGraphNode(
            key=f"memory:lin_{index}",
            layer="memory",
            entity_id=f"mem_{index}",
            label=label,
            kind="fact",
            sensitivity="restricted",
            detail_path=f"/memories/mem_{index}",
            x=100.0 + index % 900,
            y=100.0 + index % 700,
            radius=3.4,
        )
        for index in range(MAX_GRAPH_NODES)
    )
    edges = tuple(
        OwnerGraphEdge(
            kind="evidence",
            from_key=nodes[index].key,
            to_key=nodes[(index + 1) % len(nodes)].key,
            path=f"M{nodes[index].x} {nodes[index].y}L1.0 1.0",
        )
        for index in range(MAX_GRAPH_NODES)
    )
    scene = OwnerGraphScene(
        lens="provenance",
        nodes=nodes,
        edges=edges,
        width=1200.0,
        height=820.0,
        total_node_count=MAX_GRAPH_NODES,
        measured_node_count=MAX_GRAPH_NODES,
        within_ceiling=True,
        guard_links_available=True,
    )
    environment = Environment(
        loader=FileSystemLoader(
            Path(__file__).resolve().parents[1] / "src/memory/ui/templates"
        ),
        autoescape=select_autoescape(("html", "xml")),
    )
    # A template's macros only enter its module namespace once the module has
    # been rendered, so the name cannot be reached as a declared attribute.
    module = environment.get_template("graph/_scene.html").module
    macro = cast(Macro, vars(module)["scene"])
    rendered = str(macro(scene, "Provenance graph", MAX_GRAPH_NODES)).encode("utf-8")

    assert len(rendered) < MAX_STANDARD_HTML_RESPONSE_BYTES
    # The realistic figure too, so a regression reads as a number rather than
    # as "still under four megabytes".
    assert len(rendered) < 2_000_000


def test_a_small_graph_still_fills_the_canvas() -> None:
    """A three-source Store must not render as a speck in an empty frame."""
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)
    rim = min(WIDTH, HEIGHT) / 2 - 24 - 3.4
    extent = max(radius_of(scene, item.key) for item in scene.nodes)

    assert extent > rim * 0.7


def test_expansion_preserves_the_layer_ordering() -> None:
    """Scaling about the centre must not reorder what the layers mean."""
    scene = custody_sunburst(fixture(), width=WIDTH, height=HEIGHT)

    assert radius_of(scene, "memory:lin_bridge") < radius_of(scene, "source:src_1")
    assert radius_of(scene, "source:src_1") < radius_of(scene, "memory:lin_1")


def sized_fixture() -> StoreGraph:
    """One source producing many memories, one producing one, one barren."""
    nodes = [
        node("batch:bat_1", GraphLayer.BATCH),
        node("source:src_busy", GraphLayer.SOURCE),
        node("source:src_quiet", GraphLayer.SOURCE),
        node("source:src_barren", GraphLayer.SOURCE),
        node("memory:lin_thin", GraphLayer.MEMORY),
        node("memory:lin_thick", GraphLayer.MEMORY),
    ]
    edges = [
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_busy"),
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_quiet"),
        GraphEdge(GraphEdgeKind.CONTAINS, "batch:bat_1", "source:src_barren"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_busy", "memory:lin_thin"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_busy", "memory:lin_thick"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_quiet", "memory:lin_thick"),
    ]
    for index in range(12):
        key = f"memory:lin_bulk_{index:02d}"
        nodes.append(node(key, GraphLayer.MEMORY))
        edges.append(GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_busy", key))
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )


def test_a_memory_on_more_evidence_draws_larger() -> None:
    """Size answers the question the lens exists for: what is this resting on?"""
    scene = custody_sunburst(sized_fixture(), width=WIDTH, height=HEIGHT)

    thin = placed(scene, "memory:lin_thin").radius
    thick = placed(scene, "memory:lin_thick").radius
    assert thick > thin


def test_a_source_that_produced_more_draws_larger_and_a_barren_one_smallest() -> None:
    scene = custody_sunburst(sized_fixture(), width=WIDTH, height=HEIGHT)

    busy = placed(scene, "source:src_busy").radius
    quiet = placed(scene, "source:src_quiet").radius
    barren = placed(scene, "source:src_barren").radius
    assert busy > quiet > barren


def test_node_sizes_stay_bounded() -> None:
    """A prolific source must not become a dinner plate."""
    nodes = [node("source:src_huge", GraphLayer.SOURCE)]
    edges = []
    for index in range(500):
        key = f"memory:lin_{index:03d}"
        nodes.append(node(key, GraphLayer.MEMORY))
        edges.append(GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_huge", key))
    graph = StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )
    scene = custody_sunburst(graph, width=WIDTH, height=HEIGHT)

    assert max(item.radius for item in scene.nodes) <= MAX_NODE_RADIUS
    for item in scene.nodes:
        assert item.radius <= item.x <= scene.width - item.radius
        assert item.radius <= item.y <= scene.height - item.radius


def aspect_fixture() -> StoreGraph:
    """Two named areas, one cross-cutting source, and one that produced nothing."""
    nodes = [
        node("aspect:finance", GraphLayer.ASPECT),
        node("aspect:health", GraphLayer.ASPECT),
        node("source:src_money", GraphLayer.SOURCE),
        node("source:src_body", GraphLayer.SOURCE),
        node("source:src_both", GraphLayer.SOURCE),
        node("source:src_barren", GraphLayer.SOURCE),
        node("memory:lin_money", GraphLayer.MEMORY, "finance"),
        node("memory:lin_money_two", GraphLayer.MEMORY, "finance"),
        node("memory:lin_body", GraphLayer.MEMORY, "health"),
        node("memory:lin_cross_a", GraphLayer.MEMORY, "finance"),
        node("memory:lin_cross_b", GraphLayer.MEMORY, "health"),
    ]
    edges = [
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_money", "memory:lin_money"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_money", "memory:lin_money_two"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_body", "memory:lin_body"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_both", "memory:lin_cross_a"),
        GraphEdge(GraphEdgeKind.EVIDENCE, "source:src_both", "memory:lin_cross_b"),
    ]
    return StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )


def sector_angles(scene: OwnerGraphScene, key: str) -> float:
    item = placed(scene, key)
    return math.atan2(item.y - scene.height / 2, item.x - scene.width / 2)


def test_sources_are_grouped_by_the_area_their_memories_declare() -> None:
    """The owner's own aspect tag organises the ring, nothing inferred."""
    scene = custody_sunburst(aspect_fixture(), width=WIDTH, height=HEIGHT)

    finance = sector_angles(scene, "source:src_money")
    health = sector_angles(scene, "source:src_body")
    marker_finance = sector_angles(scene, "aspect:finance")
    marker_health = sector_angles(scene, "aspect:health")
    # Each area marker sits on the arc its own sources occupy.
    assert abs(marker_finance - finance) < abs(marker_finance - health)
    assert abs(marker_health - health) < abs(marker_health - finance)


def test_a_cross_cutting_source_and_a_barren_one_get_their_own_sectors() -> None:
    """Neither gets a coin flip: one spans areas, the other has none to inherit."""
    graph = aspect_fixture()
    scene = custody_sunburst(graph, width=WIDTH, height=HEIGHT)

    # Every source is still drawn, including the one that produced nothing.
    drawn = {item.key for item in scene.nodes if item.layer == "source"}
    assert drawn == {
        "source:src_money",
        "source:src_body",
        "source:src_both",
        "source:src_barren",
    }


def test_an_area_marker_is_not_navigable() -> None:
    """An area is a tag, not an entity, so it has no detail page to open."""
    scene = custody_sunburst(aspect_fixture(), width=WIDTH, height=HEIGHT)
    for item in scene.nodes:
        if item.layer == "aspect":
            assert item.detail_path == ""


def test_every_area_gets_enough_arc_to_be_named() -> None:
    """Every area in an invented crowded graph must retain a visible label.

    The independently authored stress fixture uses ten generic areas and
    eighty sources so per-source spacing cannot consume the label arcs.
    """
    names = [f"area-{index:02d}" for index in range(10)]
    nodes = [node(f"aspect:{name}", GraphLayer.ASPECT) for name in names]
    edges = []
    for index in range(80):
        area = names[index % len(names)]
        source = f"source:src_{index:02d}"
        nodes.append(node(source, GraphLayer.SOURCE))
        for step in range(1 + index % 7):
            key = f"memory:lin_{index:02d}_{step}"
            nodes.append(node(key, GraphLayer.MEMORY, area))
            edges.append(GraphEdge(GraphEdgeKind.EVIDENCE, source, key))
    graph = StoreGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        total_node_count=len(nodes),
        measured_node_count=len(nodes),
        within_ceiling=True,
        guard_links_available=True,
    )

    scene = custody_sunburst(graph, width=WIDTH, height=HEIGHT)

    assert {sector.name for sector in scene.sectors} == set(names)


def test_slice_separation_does_not_grow_with_the_source_count() -> None:
    """The gap budget is shared, so it cannot crowd out the content."""

    def ring_span(count: int) -> float:
        nodes = [node("aspect:one", GraphLayer.ASPECT)]
        edges = []
        for index in range(count):
            source = f"source:src_{index:03d}"
            nodes.append(node(source, GraphLayer.SOURCE))
            key = f"memory:lin_{index:03d}"
            nodes.append(node(key, GraphLayer.MEMORY, "one"))
            edges.append(GraphEdge(GraphEdgeKind.EVIDENCE, source, key))
        graph = StoreGraph(
            nodes=tuple(nodes),
            edges=tuple(edges),
            total_node_count=len(nodes),
            measured_node_count=len(nodes),
            within_ceiling=True,
            guard_links_available=True,
        )
        scene = custody_sunburst(graph, width=WIDTH, height=HEIGHT)
        return max(radius_of(scene, item.key) for item in scene.nodes)

    # Whatever the source count, the picture still fills its canvas rather than
    # collapsing into the fraction of the circle the gaps left behind.
    assert ring_span(8) > 0
    assert ring_span(200) > 0


def test_the_constellation_marks_which_end_is_the_guard() -> None:
    """Catch a lens that draws guards and claims as indistinguishable dots.

    Both ends of a guard link are memories, so nothing about the entities says
    which governs which. Without a role the picture is anonymous circles joined
    by undirected lines.
    """
    scene = guard_constellation(guarded_fixture(0), width=1160.0, height=560.0)

    roles = {item.key: item.role for item in scene.nodes}
    assert roles["memory:lin_guard"] == "guard"
    assert roles["memory:lin_claim_a"] == ""
    assert roles["memory:lin_claim_b"] == ""


def test_guard_edges_stop_short_of_the_claim_they_point_at() -> None:
    """An arrowhead buried inside the claim it points at says nothing."""
    scene = guard_constellation(guarded_fixture(0), width=1160.0, height=560.0)
    targets = {item.key: item for item in scene.nodes}

    for edge in scene.edges:
        end = edge.path.split("L")[1].split(" ")
        target = targets[edge.to_key]
        gap = math.hypot(float(end[0]) - target.x, float(end[1]) - target.y)
        assert gap >= target.radius, (edge.to_key, gap, target.radius)


def test_combined_budget_covers_dense_escaped_svg_response() -> None:
    """Escaped source labels and revoked guard attributes fit the admitted budget."""
    from memory.graph import graph_fits_budget

    nodes = tuple(
        OwnerGraphNode(
            key=f"source:src_{index:032x}",
            layer="source",
            entity_id=f"src_{index:032x}",
            label="'" * 120,
            kind=None,
            sensitivity="restricted",
            detail_path=f"/sources/src_{index:032x}",
            x=1196.6,
            y=816.6,
            radius=3.4,
        )
        for index in range(1024)
    )
    edges = tuple(
        OwnerGraphEdge(
            kind="guard",
            from_key=nodes[index % 1024].key,
            to_key=nodes[(index + 1) % 1024].key,
            path="M1196.6 816.6Q1196.6 816.6 1196.6 816.6",
            revoked=True,
        )
        for index in range(2048)
    )
    assert graph_fits_budget(len(nodes), len(edges))
    scene = OwnerGraphScene(
        lens="provenance",
        nodes=nodes,
        edges=edges,
        width=1200.0,
        height=820.0,
        total_node_count=1024,
        measured_node_count=1024,
        measured_edge_count=2048,
        within_ceiling=True,
        guard_links_available=True,
    )
    environment = Environment(
        loader=FileSystemLoader(
            Path(__file__).resolve().parents[1] / "src/memory/ui/templates"
        ),
        autoescape=select_autoescape(("html", "xml")),
    )
    macro = cast(
        Macro, vars(environment.get_template("graph/_scene.html").module)["scene"]
    )
    rendered = str(macro(scene, "Synthetic dense graph", MAX_GRAPH_NODES)).encode()
    # Keep a full MiB for authenticated page chrome and maximum-size filters.
    assert len(rendered) < MAX_STANDARD_HTML_RESPONSE_BYTES - 1024 * 1024
