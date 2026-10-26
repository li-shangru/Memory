"""Bounded projection of the Store's approved relation graph."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from synthetic import (
    FakeClock,
    apply_ready,
    capture_batch,
    capture_text,
    make_synthetic_store,
    ready_items,
    single_item_edit,
    store_one_memory,
    two_source_linked_apply,
)

from memory.graph import GraphEdgeKind, GraphLayer, StoreGraph, read_store_graph
from memory.model import (
    MemoryFilters,
    MemoryKind,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
)
from memory.sources import _read_connection
from memory.ui.service import OwnerApplicationService


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[RuntimePaths]:
    yield from make_synthetic_store(tmp_path, monkeypatch)


def read(paths: RuntimePaths) -> StoreGraph:
    with _read_connection(paths) as (connection, _identity):
        return read_store_graph(connection)


def test_projection_covers_batches_sources_and_current_heads(
    paths: RuntimePaths,
) -> None:
    clock = FakeClock()
    store_one_memory(
        paths,
        clock=clock,
        name="ledger.txt",
        body="The kettle was descaled in March.\n",
        statement="The kettle was descaled in March.",
        excerpt="descaled in March",
    )
    graph = read(paths)

    layers = [node.layer for node in graph.nodes]
    assert layers.count(GraphLayer.BATCH) == 1
    assert layers.count(GraphLayer.SOURCE) == 1
    assert layers.count(GraphLayer.MEMORY) == 1
    assert graph.total_node_count == 3
    assert graph.within_ceiling is True

    kinds = [edge.kind for edge in graph.edges]
    assert kinds.count(GraphEdgeKind.CONTAINS) == 1
    assert kinds.count(GraphEdgeKind.EVIDENCE) == 1

    memory = next(n for n in graph.nodes if n.layer is GraphLayer.MEMORY)
    assert memory.label == "The kettle was descaled in March."
    assert memory.detail_path.startswith("/memories/")
    assert memory.sensitivity is Sensitivity.NORMAL


def test_guard_links_become_directed_edges(paths: RuntimePaths) -> None:
    two_source_linked_apply(paths, FakeClock())
    graph = read(paths)

    guards = [e for e in graph.edges if e.kind is GraphEdgeKind.GUARD]
    assert len(guards) == 1
    assert guards[0].from_key != guards[0].to_key
    assert guards[0].from_key.startswith("memory:")
    assert guards[0].revoked is False
    assert graph.guard_links_available is True


def test_a_revoked_guard_link_is_still_drawn_as_a_revoked_edge(
    paths: RuntimePaths,
) -> None:
    """Revocation stops a link governing; the audit picture keeps it visible."""
    clock = FakeClock()
    two_source_linked_apply(paths, clock)
    live = [e for e in read(paths).edges if e.kind is GraphEdgeKind.GUARD]
    guard_key, governed_key = live[0].from_key, live[0].to_key

    _revoke_the_only_guard_link(paths, clock)

    guards = [e for e in read(paths).edges if e.kind is GraphEdgeKind.GUARD]
    assert len(guards) == 1
    assert (guards[0].from_key, guards[0].to_key) == (guard_key, governed_key)
    assert guards[0].revoked is True


def _revoke_the_only_guard_link(paths: RuntimePaths, clock: FakeClock) -> None:
    """Apply one revision whose sole effect is revoking the store's one link."""
    from memory.model import GuardLinkInput, RevokeGuardLink

    with _read_connection(paths) as (connection, _identity):
        row = connection.execute(
            "SELECT guard_lineage_id, governed_lineage_id FROM memory_guard_links"
        ).fetchone()
    batch_id, captured = capture_batch(
        paths,
        {"repair.txt": "The hedge was attached to the wrong claim.\n"},
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch_id,
            (
                SetSourceNoMemory(
                    source_id=captured["repair.txt"].source_id,
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


def _batch_with_a_barren_source(paths: RuntimePaths, clock: FakeClock) -> None:
    """Capture two sources and retain a memory from only one of them.

    The unused source needs an explicit no-memory decision: a revision that
    leaves a batch source unaccounted for is refused, which is the review
    contract working, not a fixture problem.
    """
    batch_id, captured = capture_batch(
        paths,
        {
            "used.txt": "The kettle was descaled in March.\n",
            "unused.txt": "A packing list with nothing worth retaining.\n",
        },
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_used",
                    source=captured["used.txt"],
                    statement="The kettle was descaled in March.",
                    excerpt="descaled in March",
                ),
                SetSourceNoMemory(
                    source_id=captured["unused.txt"].source_id,
                    reason="A packing list with nothing worth retaining.",
                ),
            ),
        ),
    )


def test_a_barren_source_is_a_node_with_no_evidence_edge(
    paths: RuntimePaths,
) -> None:
    """A source that produced no memory must still appear -- that is the point."""
    _batch_with_a_barren_source(paths, FakeClock())
    graph = read(paths)

    sources = [n for n in graph.nodes if n.layer is GraphLayer.SOURCE]
    assert len(sources) == 2
    evidenced = {e.from_key for e in graph.edges if e.kind is GraphEdgeKind.EVIDENCE}
    barren = [s for s in sources if s.key not in evidenced]
    assert len(barren) == 1
    assert barren[0].label == "unused.txt"


def test_a_memory_resting_on_two_sources_gets_two_evidence_edges(
    paths: RuntimePaths,
) -> None:
    two_source_linked_apply(paths, FakeClock())
    graph = read(paths)

    per_memory: dict[str, int] = {}
    for edge in graph.edges:
        if edge.kind is GraphEdgeKind.EVIDENCE:
            per_memory[edge.to_key] = per_memory.get(edge.to_key, 0) + 1
    assert per_memory
    assert sum(per_memory.values()) == len(
        [e for e in graph.edges if e.kind is GraphEdgeKind.EVIDENCE]
    )


def test_evidence_edges_are_deduplicated_per_source_and_memory(
    paths: RuntimePaths,
) -> None:
    """Two locators into one source are one edge, not two overlapping lines."""
    clock = FakeClock()
    store_one_memory(
        paths,
        clock=clock,
        name="ledger.txt",
        body="The kettle was descaled in March. The filter was replaced too.\n",
        statement="The kettle was descaled in March.",
        excerpt="descaled in March",
    )
    graph = read(paths)
    pairs = [
        (e.from_key, e.to_key) for e in graph.edges if e.kind is GraphEdgeKind.EVIDENCE
    ]
    assert len(pairs) == len(set(pairs))


def test_node_ceiling_refuses_and_reports_the_real_total(
    paths: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    store_one_memory(
        paths,
        clock=clock,
        name="ledger.txt",
        body="The kettle was descaled in March.\n",
        statement="The kettle was descaled in March.",
        excerpt="descaled in March",
    )
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 2)
    graph = read(paths)

    assert graph.within_ceiling is False
    assert graph.total_node_count == 3
    assert graph.nodes == ()
    assert graph.edges == ()


def test_the_ceiling_measures_the_filtered_selection_not_the_whole_store(
    paths: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a growing Store making every lens unreachable at once.

    The ceiling exists so a picture never lies by truncation. Measured on the
    unfiltered Store it refuses answers it could have drawn: one aspect, or
    one kind, is exactly the narrowing the refusal itself tells the owner to
    try.
    """
    clock = FakeClock()
    for name, statement, kind in (
        ("fact.txt", "The kettle was descaled in March.", MemoryKind.FACT),
        ("pref.txt", "Loose-leaf tea is preferred over bags.", MemoryKind.PREFERENCE),
        ("event.txt", "The blue lamp arrived on a Tuesday.", MemoryKind.EVENT),
    ):
        store_one_memory(
            paths,
            clock=clock,
            name=name,
            body=f"{statement}\n",
            statement=statement,
            excerpt=statement[:20],
            kind=kind,
        )
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 4)

    with _read_connection(paths) as (connection, _identity):
        unfiltered = read_store_graph(connection)
        filtered = read_store_graph(
            connection, filters=MemoryFilters(kinds=(MemoryKind.FACT,))
        )

    assert unfiltered.within_ceiling is False
    assert unfiltered.total_node_count == 9
    assert filtered.within_ceiling is True
    # One memory, the source that evidences it, and that source's batch.
    assert len(filtered.nodes) == 3
    assert len([n for n in filtered.nodes if n.layer is GraphLayer.MEMORY]) == 1
    # The whole Store, filtered or not: the ceiling is a fact about how much
    # there is to draw, not about how much this question selected.
    assert filtered.total_node_count == 9


def test_a_filtered_selection_above_the_ceiling_still_refuses(
    paths: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the filtered gate becoming a way to truncate rather than refuse."""
    clock = FakeClock()
    for name, statement in (
        ("one.txt", "The kettle was descaled in March."),
        ("two.txt", "The kettle was descaled in April."),
    ):
        store_one_memory(
            paths,
            clock=clock,
            name=name,
            body=f"{statement}\n",
            statement=statement,
            excerpt=statement[:20],
            kind=MemoryKind.FACT,
        )
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 5)

    with _read_connection(paths) as (connection, _identity):
        graph = read_store_graph(
            connection, filters=MemoryFilters(kinds=(MemoryKind.FACT,))
        )

    assert graph.within_ceiling is False
    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.total_node_count == 6


def test_aspect_markers_count_against_the_ceiling_they_are_drawn_under(
    paths: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch generated region markers pushing a scene past the bound it promised.

    Aspect nodes are read off approved tags after the entity gate, so they are
    absent from the Store's own node count. They are still drawn, and the
    ceiling is a promise about what a lens renders.
    """
    clock = FakeClock()
    batch_id, source = capture_text(
        paths,
        name="fact.txt",
        body="The kettle was descaled in March.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_aspect",
                    source=source,
                    statement="The kettle was descaled in March.",
                    excerpt="descaled in March",
                    tags=("aspect:kitchen",),
                ),
            ),
        ),
    )
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 3)

    with_marker = read(paths)
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 4)
    with_room = read(paths)

    # Three entities exactly fill a ceiling of three, and the marker the tag
    # earns is the fourth thing drawn.
    assert with_marker.total_node_count == 3
    assert with_marker.within_ceiling is False
    assert with_marker.nodes == ()
    assert with_room.within_ceiling is True
    assert len(with_room.nodes) == 4
    assert [n.entity_id for n in with_room.nodes if n.layer is GraphLayer.ASPECT] == [
        "kitchen"
    ]


def test_filters_select_memories_and_carry_their_provenance(
    paths: RuntimePaths,
) -> None:
    """A filter is a question about memories; provenance comes along."""
    clock = FakeClock()
    store_one_memory(
        paths,
        clock=clock,
        name="fact.txt",
        body="The kettle was descaled in March.\n",
        statement="The kettle was descaled in March.",
        excerpt="descaled in March",
        kind=MemoryKind.FACT,
    )
    store_one_memory(
        paths,
        clock=clock,
        name="preference.txt",
        body="Loose-leaf tea is preferred over bags.\n",
        statement="Loose-leaf tea is preferred over bags.",
        excerpt="Loose-leaf tea is preferred",
        kind=MemoryKind.PREFERENCE,
    )

    with _read_connection(paths) as (connection, _identity):
        graph = read_store_graph(
            connection, filters=MemoryFilters(kinds=(MemoryKind.FACT,))
        )

    memories = [n for n in graph.nodes if n.layer is GraphLayer.MEMORY]
    assert len(memories) == 1
    assert memories[0].kind is MemoryKind.FACT
    assert [n.label for n in graph.nodes if n.layer is GraphLayer.SOURCE] == [
        "fact.txt"
    ]
    assert len([n for n in graph.nodes if n.layer is GraphLayer.BATCH]) == 1
    # The unfiltered total stays honest: the ceiling is about the Store, not
    # about the answer to one question.
    assert graph.total_node_count == 6


def test_a_filter_hides_barren_sources_and_an_unfiltered_read_keeps_them(
    paths: RuntimePaths,
) -> None:
    """A source that produced nothing cannot answer a question about memories."""
    _batch_with_a_barren_source(paths, FakeClock())

    with _read_connection(paths) as (connection, _identity):
        unfiltered = read_store_graph(connection)
        filtered = read_store_graph(
            connection, filters=MemoryFilters(kinds=(MemoryKind.FACT,))
        )

    assert len([n for n in unfiltered.nodes if n.layer is GraphLayer.SOURCE]) == 2
    assert len([n for n in filtered.nodes if n.layer is GraphLayer.SOURCE]) == 1


def test_an_empty_filter_changes_nothing(paths: RuntimePaths) -> None:
    clock = FakeClock()
    store_one_memory(
        paths,
        clock=clock,
        name="ledger.txt",
        body="The kettle was descaled in March.\n",
        statement="The kettle was descaled in March.",
        excerpt="descaled in March",
    )
    with _read_connection(paths) as (connection, _identity):
        plain = read_store_graph(connection)
        empty = read_store_graph(connection, filters=MemoryFilters())

    assert plain.nodes == empty.nodes
    assert plain.edges == empty.edges


def test_a_guard_edge_survives_only_when_both_endpoints_do(
    paths: RuntimePaths,
) -> None:
    two_source_linked_apply(paths, FakeClock())

    with _read_connection(paths) as (connection, _identity):
        everything = read_store_graph(connection)
        facts_only = read_store_graph(
            connection, filters=MemoryFilters(kinds=(MemoryKind.FACT,))
        )

    assert [e for e in everything.edges if e.kind is GraphEdgeKind.GUARD]
    # The guard in this fixture is an insight, so filtering to facts drops the
    # guard end of the link and the edge with it.
    assert [e for e in facts_only.edges if e.kind is GraphEdgeKind.GUARD] == []


def test_the_graph_and_the_memory_list_answer_a_filter_identically(
    paths: RuntimePaths,
) -> None:
    """Catch the graph and the list disagreeing about the same question.

    Two surfaces that filter differently are worse than one surface that does
    not filter at all, so both go through `owner_memory_matches_filters`.
    """
    clock = FakeClock()
    for name, statement, kind, sensitivity in (
        ("a.txt", "The kettle was descaled in March.", MemoryKind.FACT, "normal"),
        ("b.txt", "Loose-leaf tea is preferred.", MemoryKind.PREFERENCE, "normal"),
        ("c.txt", "The blue lamp arrived on a Tuesday.", MemoryKind.EVENT, "normal"),
        ("d.txt", "The green notebook is upstairs.", MemoryKind.FACT, "sensitive"),
    ):
        store_one_memory(
            paths,
            clock=clock,
            name=name,
            body=f"{statement}\n",
            statement=statement,
            excerpt=statement[:20],
            kind=kind,
            sensitivity=Sensitivity(sensitivity),
        )

    service = OwnerApplicationService(paths=paths)
    for filters in (
        MemoryFilters(kinds=(MemoryKind.FACT,)),
        MemoryFilters(kinds=(MemoryKind.FACT, MemoryKind.EVENT)),
        MemoryFilters(sensitivities=(Sensitivity.SENSITIVE,)),
        MemoryFilters(tags_all=("synthetic",)),
        MemoryFilters(kinds=(MemoryKind.FACT,), sensitivities=(Sensitivity.NORMAL,)),
    ):
        listed = {
            item.revision.memory_id
            for item in service.list_memories(None, 50, filters).items
        }
        with _read_connection(paths) as (connection, _identity):
            graphed = {
                node.entity_id
                for node in read_store_graph(connection, filters=filters).nodes
                if node.layer is GraphLayer.MEMORY
            }
        assert graphed == listed, filters


def test_edge_budget_counts_revoked_relations_before_loading_edges(
    paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    two_source_linked_apply(paths, clock)
    _revoke_the_only_guard_link(paths, clock)
    baseline = read(paths)
    monkeypatch.setattr(
        "memory.graph.MAX_GRAPH_EDGES", len(baseline.edges), raising=False
    )
    assert read(paths).within_ceiling
    monkeypatch.setattr("memory.graph.MAX_GRAPH_EDGES", len(baseline.edges) - 1)
    refused = read(paths)
    assert not refused.within_ceiling
    assert refused.nodes == ()
    assert refused.edges == ()
    assert refused.measured_edge_count == len(baseline.edges)


def test_detail_neighbourhood_survives_unrelated_store_growth(
    paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_ui_audit import _authenticated_client

    clock = FakeClock()
    centre, _lineage = store_one_memory(
        paths,
        clock=clock,
        name="centre.txt",
        body="Synthetic copper dial. 合成铜盘。\n",
        statement="Synthetic copper dial.",
        excerpt="Synthetic copper dial.",
    )
    service = OwnerApplicationService(paths)
    ui = _authenticated_client(service)
    before = ui.client.get(f"/memories/{centre}")
    assert 'aria-label="Neighbourhood graph: 2 nodes and 1 links"' in before.text
    store_one_memory(
        paths,
        clock=clock,
        name="unrelated.txt",
        body="Synthetic violet dial.\n",
        statement="Synthetic violet dial.",
        excerpt="Synthetic violet dial.",
    )
    monkeypatch.setattr("memory.graph.MAX_GRAPH_NODES", 3)
    assert not service.read_store_graph().within_ceiling
    after = ui.client.get(f"/memories/{centre}")
    assert after.status_code == 200
    assert 'aria-label="Neighbourhood graph: 2 nodes and 1 links"' in after.text
    ui.client.close()


def test_valid_dense_store_refuses_with_counts_instead_of_late_http_413(
    paths: RuntimePaths,
) -> None:
    """A valid dense graph below the node ceiling must refuse before layout."""
    from test_ui_audit import _authenticated_client

    from memory.model import AddGuardLink, GuardLinkInput

    clock = FakeClock()
    batch, source = capture_text(
        paths,
        name="dense.txt",
        body="Synthetic dense copper grid. 合成铜网。\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch,
            tuple(
                single_item_edit(
                    item_id=f"itm_dense_{index}",
                    source=source,
                    statement=f"Synthetic copper grid cell {index}.",
                    excerpt="Synthetic dense copper grid.",
                )
                for index in range(160)
            ),
        ),
    )
    nodes = [node for node in read(paths).nodes if node.layer is GraphLayer.MEMORY]
    for offset in range(0, 64, 2):
        batch, source = capture_text(
            paths,
            name=f"relations-{offset}.txt",
            body=f"Synthetic grid decisions {offset}. 合成关系。\n",
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        apply_ready(
            paths,
            ready_items(
                paths,
                batch,
                (
                    SetSourceNoMemory(
                        source_id=source.source_id,
                        reason="Synthetic relation-only decision.",
                    ),
                    *(
                        AddGuardLink(
                            link=GuardLinkInput(
                                guard_item_id=None,
                                guard_lineage_id=guard.key.removeprefix("memory:"),
                                governed_item_id=None,
                                governed_lineage_id=claim.key.removeprefix("memory:"),
                            )
                        )
                        for guard in nodes[offset : offset + 2]
                        for claim in nodes[64:]
                    ),
                ),
            ),
        )
    graph = read(paths)
    assert not graph.within_ceiling
    assert graph.measured_node_count == 226
    assert graph.measured_edge_count == 6337  # 6,144 guards, 160 evidence, 33 custody.
    assert graph.nodes == ()
    assert graph.edges == ()
    ui = _authenticated_client(OwnerApplicationService(paths))
    response = ui.client.get("/graph/governance")
    assert response.status_code == 200
    assert "226 nodes and 6337 links" in response.text
    assert "Narrow the filters" in response.text and 'href="/memory"' in response.text
    assert "Synthetic copper grid cell" not in response.text
    ui.client.close()


def test_local_neighbourhood_refusal_is_visible_without_hiding_memory(
    paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_ui_audit import _authenticated_client

    two_source_linked_apply(paths, FakeClock())
    graph = read(paths)
    subject = next(node for node in graph.nodes if node.layer is GraphLayer.MEMORY)
    monkeypatch.setattr("memory.graph.MAX_GRAPH_EDGES", 0)
    ui = _authenticated_client(OwnerApplicationService(paths))
    response = ui.client.get(subject.detail_path)
    assert response.status_code == 200
    assert 'class="graph-refusal"' in response.text
    assert subject.label in response.text
    assert "paginated guard lists" in response.text
    ui.client.close()


def test_historical_neighbourhood_keeps_current_head_and_current_evidence(
    paths: RuntimePaths,
) -> None:
    from memory.graph import read_memory_neighbourhood

    clock = FakeClock()
    historical, lineage = store_one_memory(
        paths,
        clock=clock,
        name="old-dial.txt",
        body="Synthetic dial was copper. 合成旧铜盘。\n",
        statement="Synthetic dial was copper.",
        excerpt="Synthetic dial was copper.",
    )
    batch, source = capture_text(
        paths,
        name="new-dial.txt",
        body="Synthetic dial is silver. 合成新银盘。\n",
        sensitivity=Sensitivity.SENSITIVE,
        clock=clock,
    )
    applied = apply_ready(
        paths,
        ready_items(
            paths,
            batch,
            (
                single_item_edit(
                    item_id="itm_silver",
                    sensitivity=Sensitivity.SENSITIVE,
                    source=source,
                    statement="Synthetic dial is silver.",
                    excerpt="Synthetic dial is silver.",
                    target_lineage_id=lineage,
                    expected_head_id=historical,
                ),
            ),
        ),
    )
    with _read_connection(paths) as (connection, _identity):
        graph = read_memory_neighbourhood(connection, historical)
    memory = next(n for n in graph.nodes if n.layer is GraphLayer.MEMORY)
    assert memory.entity_id == applied.memory_ids[0]
    assert memory.sensitivity is Sensitivity.SENSITIVE
    assert memory.label == "Synthetic dial is silver."
    assert memory.detail_path == f"/memories/{applied.memory_ids[0]}"
    assert [n.label for n in graph.nodes if n.layer is GraphLayer.SOURCE] == [
        "new-dial.txt"
    ]


@pytest.mark.parametrize(
    "budget,at_limit",
    [("MAX_GRAPH_RENDER_BYTES", 7168), ("MAX_GRAPH_LAYOUT_WORK", 265)],
)
def test_combined_budget_boundary_is_inclusive_and_refuses_without_nodes(
    paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch, budget: str, at_limit: int
) -> None:
    store_one_memory(
        paths,
        clock=FakeClock(),
        name="budget.txt",
        body="Synthetic budget dial.\n",
        statement="Synthetic budget dial.",
        excerpt="Synthetic budget dial.",
    )
    monkeypatch.setattr(f"memory.graph.{budget}", at_limit)
    admitted = read(paths)
    assert len(admitted.nodes) == 3 and len(admitted.edges) == 2
    monkeypatch.setattr(f"memory.graph.{budget}", at_limit - 1)
    refusal = read(paths)
    assert not refusal.within_ceiling
    assert refusal.measured_node_count == 3 and refusal.measured_edge_count == 2
    assert refusal.nodes == () and refusal.edges == ()


def test_neighbourhood_has_same_incoming_outgoing_and_revoked_edges_as_local_slice(
    paths: RuntimePaths,
) -> None:
    from memory.graph import read_memory_neighbourhood

    clock = FakeClock()
    two_source_linked_apply(paths, clock)
    _revoke_the_only_guard_link(paths, clock)
    whole = read(paths)
    for centre in [n for n in whole.nodes if n.layer is GraphLayer.MEMORY]:
        touching = tuple(e for e in whole.edges if centre.key in (e.from_key, e.to_key))
        keys = {
            centre.key,
            *(e.from_key for e in touching),
            *(e.to_key for e in touching),
        }
        with _read_connection(paths) as (connection, _identity):
            local = read_memory_neighbourhood(connection, centre.entity_id)
            repeated = read_memory_neighbourhood(connection, centre.entity_id)
        assert local == repeated
        assert set(local.nodes) == {n for n in whole.nodes if n.key in keys}
        assert local.edges == touching
        assert local.measured_node_count == len(keys)
        assert local.measured_edge_count == len(touching)


def test_admitted_render_boundary_fits_both_complete_lens_pages(
    paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_ui_audit import _authenticated_client

    from memory.graph import GraphEdge, GraphNode, graph_fits_budget
    from memory.ui.request_limits import MAX_STANDARD_HTML_RESPONSE_BYTES

    aspects = tuple("'" * 116 + f"{index:04d}" for index in range(128))
    nodes = (
        tuple(
            GraphNode(
                key=f"aspect:{aspect}",
                layer=GraphLayer.ASPECT,
                entity_id=aspect,
                label=aspect,
                kind=None,
                sensitivity=Sensitivity.NORMAL,
                detail_path="",
                aspect=aspect,
            )
            for aspect in aspects
        )
        + tuple(
            GraphNode(
                key=f"source:src_{index:032x}",
                layer=GraphLayer.SOURCE,
                entity_id=f"src_{index:032x}",
                label="'" * 120,
                kind=None,
                sensitivity=Sensitivity.RESTRICTED,
                detail_path=f"/sources/src_{index:032x}",
            )
            for index in range(256)
        )
        + tuple(
            GraphNode(
                key=f"memory:lin_{index:032x}",
                layer=GraphLayer.MEMORY,
                entity_id=f"mem_{index:032x}",
                label="'" * 120,
                kind=MemoryKind.FACT,
                sensitivity=Sensitivity.RESTRICTED,
                detail_path=f"/memories/mem_{index:032x}",
                aspect=aspects[index % 128],
            )
            for index in range(512)
        )
    )
    edges = tuple(
        GraphEdge(
            GraphEdgeKind.EVIDENCE,
            f"source:src_{index % 256:032x}",
            f"memory:lin_{index:032x}",
        )
        for index in range(512)
    ) + tuple(
        GraphEdge(
            GraphEdgeKind.GUARD,
            f"memory:lin_{guard:032x}",
            f"memory:lin_{claim:032x}",
            revoked=True,
        )
        for guard in range(128)
        for claim in range(128, 144)
    )
    assert graph_fits_budget(896, 2560)
    assert not graph_fits_budget(896, 2561)
    graph = StoreGraph(
        nodes=nodes,
        edges=edges,
        total_node_count=768,
        measured_node_count=896,
        measured_edge_count=2560,
        within_ceiling=True,
        guard_links_available=True,
    )
    service = OwnerApplicationService(paths)

    def selected_graph(
        self: OwnerApplicationService, filters: MemoryFilters = MemoryFilters()
    ) -> StoreGraph:
        return graph

    monkeypatch.setattr(OwnerApplicationService, "read_store_graph", selected_graph)
    ui = _authenticated_client(service)
    for route in ("/graph", "/graph/governance"):
        response = ui.client.get(route)
        assert response.status_code == 200
        assert 'svg class="graph-scene"' in response.text
        assert len(response.content) < MAX_STANDARD_HTML_RESPONSE_BYTES
    ui.client.close()


@pytest.mark.parametrize("legacy", ["missing", "pre_revocation"])
def test_local_read_keeps_unhealed_guard_table_compatibility(
    paths: RuntimePaths, legacy: str
) -> None:
    from memory.database import writer_session
    from memory.graph import read_memory_neighbourhood

    two_source_linked_apply(paths, FakeClock())
    whole = read(paths)
    subject = next(n for n in whole.nodes if n.layer is GraphLayer.MEMORY)
    with writer_session(paths) as connection:
        if legacy == "missing":
            connection.execute("DROP TABLE memory_guard_links")
            connection.execute("DROP TABLE change_revision_guard_links")
            connection.execute("DROP TABLE change_revision_guard_revocations")
        else:
            # This fixture predates revocation and the v1.12 active-link indexes.
            connection.execute("DROP INDEX idx_memory_guard_governed")
            connection.execute("DROP INDEX idx_memory_guard_active")
            connection.execute("ALTER TABLE memory_guard_links DROP COLUMN revoked_at")
    with _read_connection(paths) as (connection, _identity):
        local = read_memory_neighbourhood(connection, subject.entity_id)
    assert local.within_ceiling
    assert any(e.kind is GraphEdgeKind.EVIDENCE for e in local.edges)
    guards = [e for e in local.edges if e.kind is GraphEdgeKind.GUARD]
    assert local.guard_links_available is (legacy != "missing")
    if legacy == "missing":
        assert guards == []
    else:
        assert len(guards) == 1 and not guards[0].revoked


def test_two_node_neighbourhood_survives_more_than_2500_unrelated_nodes(
    paths: RuntimePaths,
) -> None:
    clock = FakeClock()
    centre, _lineage = store_one_memory(
        paths,
        clock=clock,
        name="local.txt",
        body="Synthetic local jade dial. 合成本地玉盘。\n",
        statement="Synthetic local jade dial.",
        excerpt="Synthetic local jade dial.",
    )
    service = OwnerApplicationService(paths)
    before = service.read_memory_neighbourhood(centre)
    for offset in range(10):
        batch, source = capture_text(
            paths,
            name=f"remote-{offset}.txt",
            body=f"Synthetic unrelated grid {offset}. 合成无关网格。\n",
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        apply_ready(
            paths,
            ready_items(
                paths,
                batch,
                tuple(
                    single_item_edit(
                        item_id=f"itm_remote_{offset}_{index}",
                        source=source,
                        statement=f"Synthetic unrelated cell {offset}-{index}.",
                        excerpt=f"Synthetic unrelated grid {offset}.",
                    )
                    for index in range(250)
                ),
            ),
        )
    after = service.read_memory_neighbourhood(centre)
    assert after.total_node_count == 2523
    assert after.within_ceiling and after.measured_node_count == 2
    assert after.nodes == before.nodes and after.edges == before.edges
