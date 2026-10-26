"""Distinct lexical coverage ranks evidence ahead of repeated query fragments."""

from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from synthetic import FakeClock, store_one_memory

from memory import retrieval
from memory.memories import (
    owner_filters_payload,
    owner_memory_search_page,
    search_memories,
)
from memory.model import MatchStrength, MemoryFilters, RuntimePaths
from memory.sources import (
    _canonical_json,
    _decode_cursor,
    _read_connection,
    owner_filter_binding,
)


@pytest.mark.parametrize(
    ("query", "relevant", "repeated"),
    (
        (
            "signal kiln launch readiness",
            "Readiness for the kiln called Signal requires an independent seal check.",
            "Signal is repeated here solely to test the lettering press. ",
        ),
        (
            "苔光 窑炉 启动 验收",
            "苔光窑炉的验收条件是先完成独立的密封检查。",
            "苔光二字在这里重复，只用于测试字模。",
        ),
    ),
    ids=("english", "chinese"),
)
def test_distinct_query_terms_outrank_repetition_in_all_four_readers(
    synthetic_store: RuntimePaths,
    query: str,
    relevant: str,
    repeated: str,
) -> None:
    """A richer partial match must precede an earlier one-term distraction."""
    for name, statement in (
        ("synthetic-practice.txt", repeated * 48),
        ("synthetic-condition.txt", relevant),
    ):
        store_one_memory(
            synthetic_store,
            clock=FakeClock(),
            name=name,
            body=statement,
            statement=statement,
            excerpt=statement,
        )

    sources = retrieval.search_sources(synthetic_store, query, limit=1)
    memories = search_memories(synthetic_store, query, limit=1)
    assert sources.items[0].source.original_name == "synthetic-condition.txt"
    assert sources.items[0].rank == -3.0
    assert sources.items[0].match_strength is MatchStrength.ANY_TERM
    assert memories.items[0].memory.statement == relevant
    assert memories.items[0].match_strength is MatchStrength.ANY_TERM
    assert sources.next_cursor is not None
    assert memories.next_cursor is not None
    source_next = retrieval.search_sources(
        synthetic_store, query, cursor=sources.next_cursor, limit=1
    )
    memory_next = search_memories(
        synthetic_store, query, cursor=memories.next_cursor, limit=1
    )
    assert source_next.items[0].source.original_name == "synthetic-practice.txt"
    assert source_next.items[0].rank == -1.0
    assert memory_next.items[0].memory.statement == (repeated * 48).strip()
    assert not source_next.has_more
    assert not memory_next.has_more

    with _read_connection(synthetic_store) as (connection, identity):
        owner_sources = retrieval.owner_search_sources(
            connection, identity, query, None, 2
        )
        owner_memories = owner_memory_search_page(
            connection,
            identity,
            query=query,
            filters=MemoryFilters(),
            cursor=None,
            limit=2,
        )
    assert [hit.source.original_name for hit in owner_sources.items] == [
        "synthetic-condition.txt",
        "synthetic-practice.txt",
    ]
    assert [hit.revision.statement for hit in owner_memories.items] == [
        relevant,
        (repeated * 48).strip(),
    ]


@pytest.mark.parametrize(
    ("query", "body", "expected_rank"),
    (
        ("amber copper lead", "amber copper " * 100, -2.0),
        ("amber amber copper copper lead", "amber copper " * 100, -2.0),
        ("amber copper", "amber copper " * 100, -3.0),
        ("art", "party " * 100, -1.0),
        ("art", "party " * 100 + "art", -2.0),
        ("ai", "ai " * 100, -1.0),
        ("ai art", "chair party " * 100, -1.0),
        ("開門 開門 閉館", "開門" * 100, -1.0),
        ("Straße STRASSE other", "STRASSE " * 100, -1.0),
    ),
    ids=(
        "occurrences",
        "query-duplicates",
        "phrase-bonus",
        "midword",
        "bounded-after-midword",
        "short-token",
        "short-fragment",
        "cjk-duplicates",
        "casefold-duplicates",
    ),
)
def test_distinct_score_saturates_occurrences_and_query_duplicate_weights(
    query: str, body: str, expected_rank: float
) -> None:
    """Literal repetition never contributes another unit of query coverage."""
    compiled = retrieval._compile_literal_query(query)
    assert compiled.native is not None
    folded = body.casefold()
    native = compiled.evaluate(folded)
    automaton = replace(compiled, native=None).evaluate(folded)
    phrase, terms = retrieval._folded_query(query)
    assert native == automaton
    assert native.rank == expected_rank
    assert retrieval._score_folded(folded, phrase, terms) == expected_rank
    assert native.strength == retrieval._substring_strength(folded, phrase, terms)
    assert native.rank.is_integer()
    assert -(len(set(terms)) + 1) <= native.rank <= 0


def test_version_six_queryless_owner_list_cursor_survives_ranking_upgrade(
    synthetic_store: RuntimePaths,
) -> None:
    """The unchanged owner list keeps its prior cursor binding and page order."""
    for index in range(2):
        statement = f"Synthetic unchanged enumeration entry {index}."
        store_one_memory(
            synthetic_store,
            clock=FakeClock(),
            name=f"synthetic-enumeration-{index}.txt",
            body=statement,
            statement=statement,
            excerpt=statement,
        )
    filters = MemoryFilters(tags_all=("synthetic",))
    with _read_connection(synthetic_store) as (connection, identity):
        first = owner_memory_search_page(
            connection, identity, query=None, filters=filters, cursor=None, limit=1
        )
        assert first.next_cursor is not None
        payload = _decode_cursor(first.next_cursor)
        prior_binding = owner_filter_binding(
            {"query": None, "filters": owner_filters_payload(filters), "ladder": 6}
        )
        payload["binding"] = prior_binding
        previous_cursor = (
            base64.urlsafe_b64encode(_canonical_json(payload)).rstrip(b"=").decode()
        )
        second = owner_memory_search_page(
            connection,
            identity,
            query=None,
            filters=filters,
            cursor=previous_cursor,
            limit=1,
        )
        assert _decode_cursor(first.next_cursor)["binding"] == prior_binding
    assert first.items[0].revision.statement.endswith("entry 0.")
    assert second.items[0].revision.statement.endswith("entry 1.")
    assert not second.has_more
