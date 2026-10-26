"""Reserved orientation contracts, using fresh synthetic kernel evidence only.

Fixture approval is the unit-test adapter. These checks attest neither real
owner presence nor the behavior of an installed reasoning client.
"""

from __future__ import annotations

import pytest
from synthetic import (
    FakeClock,
    apply_ready,
    capture_batch,
    ready_items,
    single_item_edit,
)

from memory.mcp_prompts import skill_prompts
from memory.memories import MAX_FACET_TAGS, get_memory_facets, search_memories
from memory.model import (
    AddGuardLink,
    ChangeEdit,
    Cursor,
    GuardLinkInput,
    MatchStrength,
    MemoryFilters,
    MemoryKind,
    MemorySearchHit,
    RuntimePaths,
    Sensitivity,
)


def test_served_advice_never_gates_reserved_walks_on_facets() -> None:
    """Catch bounded vocabulary suppressing either required orientation walk."""
    prompt = next(
        prompt for prompt in skill_prompts() if prompt.name == "advise_the_owner"
    )
    orientation = " ".join(
        prompt.workflow.split("Orient first, before any ranked query:", 1)[1]
        .split("Then follow `## Answer a question`", 1)[0]
        .split()
    )

    assert "then always run one queryless `memory.search`" in orientation
    assert '`tags_all: ["standing"]`' in orientation
    assert "Always enumerate `loop:open` the same way" in orientation
    assert '`tags_all: ["loop:open"]` and no aspect filter' in orientation
    assert (
        "Facets may be truncated; omissions never suppress either walk" in orientation
    )
    assert "follow `has_more` to completion" in orientation
    assert "Never add an `aspect:` filter to this first walk" in orientation
    assert "guards attached, sensitivity as metadata" in orientation
    assert "When the live vocabulary contains" not in orientation
    assert "When the vocabulary contains" not in orientation
    assert "normal, sensitive, and restricted captures participate" in " ".join(
        prompt.preamble.split()
    )


@pytest.mark.parametrize(
    "unrelated_memory", (False, True), ids=("empty-store", "unrelated-memory")
)
def test_absent_reserved_tags_have_terminal_empty_walks(
    synthetic_store: RuntimePaths,
    unrelated_memory: bool,
) -> None:
    """Unconditional orientation must finish cleanly when neither set exists."""
    if unrelated_memory:
        statement = "Synthetic inventory entry records a blue stool in the workshop."
        batch_id, sources = capture_batch(
            synthetic_store,
            {"unrelated.txt": statement},
            sensitivity=Sensitivity.NORMAL,
            clock=FakeClock(),
        )
        apply_ready(
            synthetic_store,
            ready_items(
                synthetic_store,
                batch_id,
                (
                    single_item_edit(
                        item_id="itm_unrelated_orientation",
                        source=sources["unrelated.txt"],
                        statement=statement,
                        excerpt=statement,
                        tags=("aspect:inventory",),
                    ),
                ),
            ),
        )

    facets = get_memory_facets(synthetic_store)
    assert facets.total_tags == len(facets.tags) == int(unrelated_memory)
    assert facets.truncated is False
    assert {"standing", "loop:open"}.isdisjoint(facet.value for facet in facets.tags)
    for reserved_tag in ("standing", "loop:open"):
        page = search_memories(
            synthetic_store,
            filters=MemoryFilters(tags_all=(reserved_tag,)),
            limit=1,
        )
        assert page.items == ()
        assert page.has_more is False
        assert page.next_cursor is None
        assert page.coverage.total == page.coverage.enumerated == int(unrelated_memory)


def test_reserved_walks_recover_every_head_omitted_by_truncated_facets(
    synthetic_store: RuntimePaths,
) -> None:
    """Exercise the paginated queryless path that the served Skill must require."""
    guard_statement = (
        "Synthetic caveat: the workshop plan is optional and may be reconsidered."
    )
    files = {
        f"clutter-{index:02d}.txt": f"Synthetic catalog record {index:02d}.\n"
        for index in range(24)
    }
    files["clutter-00.txt"] = guard_statement + "\n"
    statements = (
        "Synthetic keeper prefers quiet workshop sessions and plans a lantern check.",
        "合成记录：档案员一直偏好安静的工坊时段，并计划检查灯笼。",
        "Synthetic curator values unhurried studio work and plans a lantern inspection.",
    )
    for index, statement in enumerate(statements):
        files[f"reserved-{index}.txt"] = statement + "\n"
    batch_id, sources = capture_batch(
        synthetic_store,
        files,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    # Each of 504 lexically early tags occurs three times. Both reserved tags
    # also occur three times, leaving them outside the unchanged top-500 bound.
    edits: list[ChangeEdit] = [
        single_item_edit(
            item_id=f"itm_clutter_{index:02d}",
            source=sources[f"clutter-{index:02d}.txt"],
            statement=files[f"clutter-{index:02d}.txt"].strip(),
            excerpt=files[f"clutter-{index:02d}.txt"].strip(),
            tags=tuple(
                f"aspect:orientation-{index // 3:02d}-{tag_index:02d}"
                for tag_index in range(63)
            ),
        )
        for index in range(24)
    ]
    for index, sensitivity in enumerate(Sensitivity):
        edits.append(
            single_item_edit(
                item_id=f"itm_reserved_{index}",
                source=sources[f"reserved-{index}.txt"],
                statement=statements[index],
                excerpt=statements[index],
                kind=MemoryKind.PREFERENCE,
                tags=(
                    "standing",
                    "loop:open",
                    f"aspect:orientation-00-{index:02d}",
                ),
                sensitivity=sensitivity,
            )
        )
    for index in range(3):
        edits.append(
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id="itm_clutter_00",
                    guard_lineage_id=None,
                    governed_item_id=f"itm_reserved_{index}",
                    governed_lineage_id=None,
                )
            )
        )
    applied = apply_ready(
        synthetic_store, ready_items(synthetic_store, batch_id, edits)
    )
    expected_ids = set(applied.memory_ids[-3:])
    guard_id = applied.memory_ids[0]

    facets = get_memory_facets(synthetic_store)
    assert MAX_FACET_TAGS == 500
    assert facets.total_tags == 506
    assert len(facets.tags) == MAX_FACET_TAGS
    assert facets.truncated is True
    assert {"standing", "loop:open"}.isdisjoint(facet.value for facet in facets.tags)

    for reserved_tag in ("standing", "loop:open"):
        hits: list[MemorySearchHit] = []
        cursor: Cursor | None = None
        for page_index in range(3):
            page = search_memories(
                synthetic_store,
                filters=MemoryFilters(tags_all=(reserved_tag,)),
                cursor=cursor,
                limit=1,
            )
            assert len(page.items) == 1
            assert page.has_more is (page_index < 2)
            assert page.has_more is (page.next_cursor is not None)
            assert (
                page.coverage.total
                == page.coverage.enumerated
                == len(applied.memory_ids)
            )
            hits.extend(page.items)
            cursor = page.next_cursor

        assert {hit.memory.memory_id for hit in hits} == expected_ids
        assert {hit.memory.effective_sensitivity for hit in hits} == set(Sensitivity)
        assert all(hit.match_strength is MatchStrength.ENUMERATED for hit in hits)
        for hit in hits:
            assert len(hit.guards) == 1
            assert hit.guards[0].memory_id == guard_id
            assert hit.guards[0].statement == guard_statement
            assert hit.guards[0].effective_sensitivity is Sensitivity.NORMAL

        # A plausible topical filter would drop two required orientation hits.
        narrowed = search_memories(
            synthetic_store,
            filters=MemoryFilters(tags_all=(reserved_tag, "aspect:orientation-00-00")),
        )
        assert len(narrowed.items) == 1
        assert narrowed.items[0].memory.memory_id in expected_ids
