"""Exact short-query retrieval with a bound on Python per-character work."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import replace
from types import FrameType
from typing import TYPE_CHECKING

import pytest
from synthetic import FakeClock, store_one_memory

from memory import memories, retrieval
from memory.model import MatchStrength, RuntimePaths

if TYPE_CHECKING:
    from _typeshed import TraceFunction


def _python_retrieval_work(operation: Callable[[], None]) -> int:
    events = 0

    def trace(frame: FrameType, event: str, argument: object) -> TraceFunction:
        nonlocal events
        if event == "line" and frame.f_code.co_filename == retrieval.__file__:
            events += 1
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        operation()
    finally:
        sys.settrace(previous)
    return events


def test_short_query_avoids_python_work_per_source_character() -> None:
    """Restoring the Python automaton for ordinary queries exceeds this budget."""
    compiled = retrieval._compile_literal_query("amber arch")
    observations: list[int] = []
    for repeats in (256, 4096):
        haystack = "plain synthetic filler. " * repeats + "amber arch"

        def run(haystack: str = haystack) -> None:
            result = compiled.evaluate(haystack)
            assert result.rank == -3.0
            assert result.strength is MatchStrength.PHRASE
            assert compiled.locate(haystack) == (len(haystack) - 10, 10)

        observations.append(_python_retrieval_work(run))
    assert max(observations) <= 1000, observations
    assert observations[1] <= observations[0] + 20, observations


@pytest.mark.parametrize(
    "query",
    (
        "amber arch",
        "art art",
        "ai art",
        "Straße",
        "café",
        "開放計畫",
        "開a開",
        "ｶﾅ",
        "\uffa1\uffa2",
        "art_arch",
        '"art"',
        "!!!",
        "a" * 48,
        "amber architecture",
    ),
)
def test_short_queries_keep_exact_rungs_scores_and_excerpt_anchors(query: str) -> None:
    """Unicode, overlap, duplicates, and prefix priority use the existing oracle."""
    bodies = (
        "",
        "a" * 8192,
        "party " * 200 + " art arch and amber arch.",
        "修訂開放計畫只在取得許可後實施。開a開。",
        "Straße CAFÉ e\u0301 ｶﾅ \uffa1\uffa2",
        'smart\x00art_arch !!! "art"',
        "archival notes. The amber architect marked an arch.",
        "a開a開a開a開a",
    )
    compiled = retrieval._compile_literal_query(query)
    phrase, terms = retrieval._folded_query(query)
    for body in bodies:
        folded = body.casefold()
        result = compiled.evaluate(folded)
        assert result.strength == retrieval._substring_strength(folded, phrase, terms)
        assert result.rank == retrieval._score_folded(folded, phrase, terms)
        assert result.phrase_index == retrieval._bounded_occurrence(folded, phrase)
        assert compiled.locate(folded) == retrieval._locate_match(folded, query)


def test_native_scan_resumes_cursors_minted_by_the_automaton(
    synthetic_store: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A performance change must retain the composition bound into old cursors."""
    for index in range(2):
        statement = f"Synthetic amber arch record {index}."
        store_one_memory(
            synthetic_store,
            clock=FakeClock(),
            name=f"synthetic-native-cursor-{index}.txt",
            body=statement,
            statement=statement,
            excerpt=statement,
        )
    compile_query = retrieval._compile_literal_query

    def automaton_only(query: str) -> retrieval._CompiledLiteralQuery:
        return replace(compile_query(query), native=None)

    with monkeypatch.context() as patch:
        patch.setattr(retrieval, "_compile_literal_query", automaton_only)
        patch.setattr(memories, "_compile_literal_query", automaton_only)
        old_source = retrieval.search_sources(synthetic_store, "amber arch", limit=1)
        old_memory = memories.search_memories(synthetic_store, "amber arch", limit=1)
        expected_source = retrieval.search_sources(
            synthetic_store, "amber arch", cursor=old_source.next_cursor, limit=1
        )
        expected_memory = memories.search_memories(
            synthetic_store, "amber arch", cursor=old_memory.next_cursor, limit=1
        )
    assert old_source.next_cursor is not None
    assert old_memory.next_cursor is not None
    assert (
        retrieval.search_sources(
            synthetic_store, "amber arch", cursor=old_source.next_cursor, limit=1
        )
        == expected_source
    )
    assert (
        memories.search_memories(
            synthetic_store, "amber arch", cursor=old_memory.next_cursor, limit=1
        )
        == expected_memory
    )
