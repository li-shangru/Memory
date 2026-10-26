"""Deterministic query-ladder semantics and rung-aware pagination."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from functools import partial
from types import CodeType, FrameType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from _typeshed import TraceFunction

import pytest
from synthetic import (
    FakeClock,
    apply_ready,
    capture_batch,
    capture_text,
    ready_items,
    single_item_edit,
    store_one_memory,
)

from memory import memories as memories_module
from memory import retrieval as retrieval_module
from memory.database import Connection, writer_session
from memory.errors import StaleCursorError
from memory.maintenance import rebuild_search_projections
from memory.memories import (
    _ladder_matches,
    get_memory,
    owner_filters_payload,
    owner_memory_projection_coverage,
    owner_memory_search_page,
    search_memories,
)
from memory.model import (
    MatchStrength,
    MemoryFilters,
    MemoryKind,
    RuntimePaths,
    Sensitivity,
)
from memory.retrieval import (
    _source_ladder_matches,
    owner_search_sources,
    search_sources,
)
from memory.sources import _canonical_json, _read_connection, owner_filter_binding

_MISSING = object()


@dataclass
class _LiteralScanStats:
    character_visits: int = 0
    full_string_operations: int = 0


@dataclass
class _LiteralDormantStats:
    wide_operations: int = 0
    boundary_classifications: int = 0
    boundary_transition_lookups: int = 0


@dataclass
class _LiteralMatchedBlockStats:
    scan_calls: int = 0
    line_events: int = 0
    query_width_bit_work: int = 0
    maximum_runtime_int_bits: int = 0


class _MeasuredWideInt:
    """Count packed work while otherwise behaving as one compiled mask."""

    def __init__(self, value: int, stats: _LiteralDormantStats) -> None:
        self._value = value
        self._stats = stats

    def __ror__(self, other: object) -> int:
        assert isinstance(other, int)
        self._stats.wide_operations += 1
        return other | self._value

    def __rand__(self, other: object) -> int:
        assert isinstance(other, int)
        self._stats.wide_operations += 1
        return other & self._value


class _MeasuredBoundaryTransitions(Mapping[retrieval_module._BoundaryToken, int]):
    """Count actual deterministic boundary-automaton transitions."""

    def __init__(
        self,
        values: Mapping[retrieval_module._BoundaryToken, int],
        stats: _LiteralDormantStats,
    ) -> None:
        self._values = values
        self._stats = stats

    def __getitem__(self, key: retrieval_module._BoundaryToken) -> int:
        self._stats.boundary_transition_lookups += 1
        return self._values[key]

    def __iter__(self) -> Iterator[retrieval_module._BoundaryToken]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


class _MeasuredText:
    """Count literal passes while retaining the string operations under test."""

    def __init__(self, value: str, stats: _LiteralScanStats) -> None:
        self._value = value
        self._stats = stats

    def casefold(self) -> _MeasuredText:
        return _MeasuredText(self._value.casefold(), self._stats)

    def __contains__(self, value: object) -> bool:
        assert isinstance(value, str)
        self._stats.full_string_operations += 1
        return value in self._value

    def find(self, value: str, start: int = 0, end: int | None = None) -> int:
        self._stats.full_string_operations += 1
        if end is None:
            return self._value.find(value, start)
        return self._value.find(value, start, end)

    def count(self, value: str, start: int = 0, end: int | None = None) -> int:
        self._stats.full_string_operations += 1
        if end is None:
            return self._value.count(value, start)
        return self._value.count(value, start, end)

    def __iter__(self) -> Iterator[str]:
        for character in self._value:
            self._stats.character_visits += 1
            yield character

    def __len__(self) -> int:
        return len(self._value)

    def __getitem__(self, index: int | slice) -> str:
        return self._value[index]


class _MeasuredJoin:
    def __init__(self, separator: str, stats: _LiteralScanStats) -> None:
        self._separator = separator
        self._stats = stats

    def join(self, values: Iterable[str]) -> str:
        measured = _MeasuredText(self._separator.join(values), self._stats)
        return cast("str", measured)


def _four_thousand_term_query() -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

    def term(index: int) -> str:
        return "".join(
            (
                alphabet[(index // (36 * 36)) % 36],
                alphabet[(index // 36) % 36],
                alphabet[index % 36],
            )
        )

    return " ".join(term(index) for index in range(4_000))


def _last_distinct_terms_query(term_count: int) -> str:
    """Keep only the tail whose final legal three-byte term is ``333``."""
    terms = _four_thousand_term_query().split()
    return " ".join(terms[-term_count:])


def _nested_prefix_query(last_length: int) -> str:
    return " ".join("a" * length for length in range(3, last_length + 1))


def _nested_mixed_boundary_query(term_count: int) -> str:
    return " ".join("a" + ("開a" * length) for length in range(1, term_count + 1))


def _count_line_events(code: CodeType, operation: Callable[[], None]) -> int:
    """Count deterministic Python work inside one selected implementation."""
    line_events = 0

    def trace(frame: FrameType, event: str, _argument: object) -> TraceFunction:
        nonlocal line_events
        if frame.f_code is code and event == "line":
            line_events += 1
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        operation()
    finally:
        sys.settrace(previous)
    return line_events


def _measure_matched_block_work[ResultT](
    operation: Callable[[], ResultT],
) -> tuple[ResultT, _LiteralMatchedBlockStats]:
    """Measure query-wide integer work while an actual term is matching.

    The fixture's eventual fixed block holds at most 64 three-character term
    lanes, so a runtime integer wider than 256 bits is query-width state rather
    than work for the one block containing ``333``. This measures the real
    matcher without a clock threshold or a test-only production callback.
    """
    stats = _LiteralMatchedBlockStats()
    scan_code = retrieval_module._CompiledLiteralQuery._scan.__code__
    locate_code = retrieval_module._CompiledLiteralQuery.locate.__code__

    def trace(frame: FrameType, event: str, _argument: object) -> TraceFunction | None:
        if frame.f_code not in (scan_code, locate_code):
            return None
        if frame.f_code is scan_code and event == "call":
            stats.scan_calls += 1
        elif event == "line":
            stats.line_events += 1
            widths = tuple(
                value.bit_length()
                for value in frame.f_locals.values()
                if isinstance(value, int) and not isinstance(value, bool)
            )
            if widths:
                stats.maximum_runtime_int_bits = max(
                    stats.maximum_runtime_int_bits,
                    max(widths),
                )
                stats.query_width_bit_work += sum(
                    width for width in widths if width > 256
                )
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        result = operation()
    finally:
        sys.settrace(previous)
    return result, stats


def _no_source_fts(
    _connection: Connection, _query: str, _upper: int
) -> dict[int, MatchStrength]:
    return {}


def _no_memory_fts(
    _connection: Connection, _query: str, _upper: int
) -> dict[str, MatchStrength]:
    return {}


def _literal_ladder_results(
    paths: RuntimePaths, query: str
) -> tuple[list[tuple[int, float]], list[tuple[int, float]]]:
    with _read_connection(paths) as (connection, _identity):
        connection.execute("BEGIN")
        source_upper = int(
            connection.execute("SELECT max(rowid) FROM sources").fetchone()[0]
        )
        memory_upper = int(
            connection.execute("SELECT max(rowid) FROM memory_revisions").fetchone()[0]
        )
        source_entries = _source_ladder_matches(connection, query, source_upper)
        memory_entries = _ladder_matches(
            connection,
            query,
            MemoryFilters(),
            memory_upper,
        )
    return (
        [(entry.strength, entry.rank) for entry in source_entries],
        [(entry.strength, entry.rank) for entry in memory_entries],
    )


def _instrument_dormant_literal_query(
    compiled: retrieval_module._CompiledLiteralQuery,
    stats: _LiteralDormantStats,
) -> retrieval_module._CompiledLiteralQuery:
    return replace(
        compiled,
        term_blocks=tuple(
            replace(
                block,
                counter_high_mask=cast(
                    "int", _MeasuredWideInt(block.counter_high_mask, stats)
                ),
            )
            for block in compiled.term_blocks
        ),
    )


def _instrument_active_boundary_query(
    compiled: retrieval_module._CompiledLiteralQuery,
    stats: _LiteralDormantStats,
    *,
    measure_query_width: bool = False,
) -> retrieval_module._CompiledLiteralQuery:
    transitions = tuple(
        _MeasuredBoundaryTransitions(state, stats)
        for state in compiled.boundary_transitions
    )
    if measure_query_width:
        return replace(
            compiled,
            term_blocks=tuple(
                replace(
                    block,
                    admissible_mask=cast(
                        "int", _MeasuredWideInt(block.admissible_mask, stats)
                    ),
                )
                for block in compiled.term_blocks
            ),
            boundary_transitions=transitions,
        )
    return replace(
        compiled,
        boundary_transitions=transitions,
    )


def _count_boundary_classifications(
    monkeypatch: pytest.MonkeyPatch, stats: _LiteralDormantStats
) -> None:
    original = retrieval_module._boundary_between

    def measured(outer: str, inner: str) -> bool:
        stats.boundary_classifications += 1
        return original(outer, inner)

    monkeypatch.setattr(retrieval_module, "_boundary_between", measured)


def _decode_payload(cursor: str) -> dict[str, object]:
    padding = "=" * (-len(cursor) % 4)
    decoded = base64.urlsafe_b64decode(cursor + padding).decode("utf-8")
    payload: dict[str, object] = json.loads(decoded)
    return payload


def _encode_payload(payload: dict[str, object]) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def _seed(paths: RuntimePaths, clock: FakeClock) -> None:
    store_one_memory(
        paths,
        clock=clock,
        name="phrase.txt",
        body="The owner keeps the amber studio door open.\n",
        statement="The owner keeps the amber studio door open.",
        excerpt="keeps the amber studio door open",
    )
    store_one_memory(
        paths,
        clock=clock,
        name="allterms.txt",
        body="An amber lamp sits beside the studio window.\n",
        statement="An amber lamp sits beside the studio window.",
        excerpt="amber lamp sits beside the studio",
    )
    store_one_memory(
        paths,
        clock=clock,
        name="anyterm.txt",
        body="The studio calendar hangs by the door.\n",
        statement="The studio calendar hangs by the door.",
        excerpt="studio calendar hangs",
    )


def test_literal_matching_compiles_once_for_source_and_memory_ladders(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch membership and rank each scanning one haystack per query term."""
    query = _four_thousand_term_query()
    terms = query.split()
    assert len(query.encode("utf-8")) == 15_999
    assert len(terms) == len(set(terms)) == 4_000
    assert {len(term) for term in terms} == {3}

    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="literal-scale.txt",
        body="Synthetic literal record 000.\n",
        statement="Synthetic literal record 000.",
        excerpt="Synthetic literal record 000.",
    )

    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)
    source_stats = _LiteralScanStats()
    memory_stats = _LiteralScanStats()
    monkeypatch.setattr(
        retrieval_module,
        "_HAYSTACK_JOIN",
        _MeasuredJoin("\x00", source_stats),
    )
    monkeypatch.setattr(
        memories_module,
        "_HAYSTACK_JOIN",
        _MeasuredJoin("\x00", memory_stats),
    )

    source_results, memory_results = _literal_ladder_results(synthetic_store, query)

    assert source_results == [(2, -1.0)]
    assert memory_results == [(2, -1.0)]
    # One compiled traversal supplies membership, rank, and phrase coordinates.
    # Doubling a haystack therefore doubles character visits instead of
    # multiplying either membership or rank by 4,000 terms.
    assert source_stats.character_visits == len(
        "Synthetic literal record 000.\n\x00literal-scale.txt".casefold()
    )
    assert memory_stats.character_visits == len(
        "Synthetic literal record 000.\x00synthetic".casefold()
    )
    assert source_stats.full_string_operations == 0
    assert memory_stats.full_string_operations == 0


def test_public_source_excerpt_reuses_compiled_literal_matcher(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch visible excerpts restoring one full-text probe per query term."""
    query = _four_thousand_term_query()
    assert len(query.encode("utf-8")) == 15_999
    assert len(query.split()) == 4_000
    body = ("x" * 600) + " 333 " + ("y" * 1_000)
    capture_text(
        synthetic_store,
        name="literal-excerpt-scale.txt",
        body=body,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    original_admits = retrieval_module._substring_admits
    term_probes = 0

    def measured_admits(term: str, haystack_folded: str) -> bool:
        nonlocal term_probes
        term_probes += 1
        return original_admits(term, haystack_folded)

    monkeypatch.setattr(retrieval_module, "_substring_admits", measured_admits)

    page = search_sources(synthetic_store, query)

    assert len(page.items) == 1
    hit = page.items[0]
    assert hit.source.original_name == "literal-excerpt-scale.txt"
    assert hit.match_strength is MatchStrength.ANY_TERM
    assert hit.rank == -1.0
    assert hit.exact_excerpt == ("x" * 255) + " 333 " + ("y" * 764)
    assert (hit.excerpt_char_start, hit.excerpt_char_end) == (345, 1_369)
    assert (hit.match_char_start, hit.match_char_end) == (601, 604)
    assert term_probes == 0


def test_compiled_literal_matcher_equals_the_reference_oracle_exhaustively() -> None:
    """Catch any exact membership, boundary, or occurrence semantic drift."""
    from memory.retrieval import (
        _bounded_occurrence,
        _compile_literal_query,
        _folded_query,
        _locate_match,
        _score_folded,
        _substring_strength,
    )

    queries = (
        "amber",
        "amber amber",
        "aaa",
        "aaa aaa aaa",
        "aba bab",
        "aba aba",
        "art artist",
        "cat catalog log",
        "catalog cat",
        "gardens",
        "ar studio",
        "开放 时间",
        "かな 案内",
        "한글 안내",
        "strasse",
        "amber studio",
        "amber\x00studio",
        "amber\U0010ffffstudio",
        "a開a",
        "---",
    )
    haystacks = (
        "",
        "amber",
        "amber amber amber",
        "xamber",
        "xamber amber",
        "aaaaa",
        "ababa",
        "xxabaxx aba",
        "artist art",
        "catalog cat log",
        "the gardening catalog",
        "a smart studio",
        "研究所的开放时间",
        "かな案内かな",
        "한글안내한글",
        "Straße STRASSE",
        "amber\x00studio",
        "amber\U0010ffffstudio",
        "a開a",
        "xa開a",
        "a開ax",
        "x開開x",
        "a party in the art room",
        "art,studio;catalog!",
        "--- ---",
    )

    for query in queries:
        phrase, terms = _folded_query(query)
        compiled = _compile_literal_query(query)
        for haystack in haystacks:
            folded = haystack.casefold()
            evaluated = compiled.evaluate(folded)
            assert (
                evaluated.strength,
                evaluated.rank,
                evaluated.phrase_index,
            ) == (
                _substring_strength(folded, phrase, terms),
                _score_folded(folded, phrase, terms),
                _bounded_occurrence(folded, phrase),
            ), (query, haystack)
            assert compiled.locate(folded) == _locate_match(folded, query), (
                query,
                haystack,
            )


def test_compiled_literal_matcher_equals_deterministic_random_reference_oracle() -> (
    None
):
    """Exercise mixed duplicate, overlap, boundary, and folding combinations."""
    from memory.retrieval import (
        _bounded_occurrence,
        _compile_literal_query,
        _folded_query,
        _locate_match,
        _score_folded,
        _substring_strength,
    )

    generator = random.Random(0xB10C)
    term_pool = (
        "a",
        "ab",
        "aba",
        "aaa",
        "amber",
        "開",
        "開a",
        "a開a",
        "かな",
        "한글",
        "strasse",
        "---",
    )
    haystack_chunks = (
        "a",
        "b",
        " ",
        "-",
        ",",
        "開",
        "かな",
        "한글",
        "Straße",
        "\x00",
        "\U0010ffff",
    )

    for _case in range(256):
        query = " ".join(
            generator.choice(term_pool) for _ in range(generator.randint(1, 6))
        )
        haystack = "".join(
            generator.choice(haystack_chunks) for _ in range(generator.randint(0, 24))
        )
        phrase, terms = _folded_query(query)
        folded = haystack.casefold()
        compiled = _compile_literal_query(query)
        evaluated = compiled.evaluate(folded)
        assert (
            evaluated.strength,
            evaluated.rank,
            evaluated.phrase_index,
        ) == (
            _substring_strength(folded, phrase, terms),
            _score_folded(folded, phrase, terms),
            _bounded_occurrence(folded, phrase),
        ), (query, haystack)
        assert compiled.locate(folded) == _locate_match(folded, query), (
            query,
            haystack,
        )


@pytest.mark.parametrize(
    ("query", "haystack", "evaluation", "location"),
    (
        (
            "a開a",
            "a開a",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -2.0, 0),
            (0, 3),
        ),
        (
            "a開a",
            "xa開a",
            retrieval_module._LiteralEvaluation(MatchStrength.ANY_TERM, -1.0, -1),
            (1, 0),
        ),
        (
            "a開a",
            "a開ax",
            retrieval_module._LiteralEvaluation(MatchStrength.ANY_TERM, -1.0, -1),
            (0, 0),
        ),
        (
            "---",
            "x---x",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -1.0, 1),
            (1, 3),
        ),
        (
            "開開",
            "x開開x",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -2.0, 1),
            (1, 2),
        ),
        (
            "amber",
            "xamberx",
            retrieval_module._LiteralEvaluation(MatchStrength.ANY_TERM, -1.0, -1),
            (1, 0),
        ),
        (
            "amber",
            " amber ",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -2.0, 1),
            (1, 5),
        ),
        (
            "amber\x00studio",
            "amber\x00studio",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -3.0, 0),
            (0, 12),
        ),
        (
            "amber\U0010ffffstudio",
            "amber\U0010ffffstudio",
            retrieval_module._LiteralEvaluation(MatchStrength.PHRASE, -3.0, 0),
            (0, 12),
        ),
    ),
)
def test_boundary_automaton_preserves_exact_edge_semantics(
    query: str,
    haystack: str,
    evaluation: retrieval_module._LiteralEvaluation,
    location: tuple[int, int],
) -> None:
    """Keep the private marker distinct from text and every edge exact."""
    compiled = retrieval_module._compile_literal_query(query)

    assert compiled.evaluate(haystack.casefold()) == evaluation
    assert compiled.locate(haystack.casefold()) == location


def test_compiled_literal_matcher_traversal_doubles_from_n_to_two_n() -> None:
    """Catch multi-pattern work growing with term count instead of text length."""
    from memory.retrieval import _compile_literal_query

    compiled = _compile_literal_query(_four_thousand_term_query())
    observed: list[int] = []
    for size in (2_048, 4_096):
        stats = _LiteralScanStats()
        measured = _MeasuredText("x" * (size - 3) + "000", stats)
        evaluated = compiled.evaluate(cast("str", measured))
        assert evaluated.strength is MatchStrength.ANY_TERM
        assert evaluated.rank == -1.0
        assert stats.full_string_operations == 0
        observed.append(stats.character_visits)

    assert observed == [2_048, 4_096]


def test_actual_high_index_match_touches_only_its_fixed_term_block() -> None:
    """Catch an actual match restoring query-wide packed integer state."""
    queries = {
        10: _last_distinct_terms_query(10),
        4_000: _last_distinct_terms_query(4_000),
    }
    assert len(queries[4_000].encode("utf-8")) == 15_999
    observed: dict[tuple[int, int], _LiteralMatchedBlockStats] = {}

    for term_count, query in queries.items():
        compiled = retrieval_module._compile_literal_query(query)
        for repeats in (64, 128):
            evaluation, stats = _measure_matched_block_work(
                partial(compiled.evaluate, "333 " * repeats)
            )
            assert evaluation == retrieval_module._LiteralEvaluation(
                MatchStrength.ANY_TERM,
                -1.0,
                -1,
            )
            assert stats.scan_calls == 1
            assert stats.query_width_bit_work == 0
            assert stats.maximum_runtime_int_bits <= 256
            observed[(term_count, repeats)] = stats

    for term_count in queries:
        assert (
            observed[(term_count, 128)].line_events
            <= observed[(term_count, 64)].line_events * 3
        )
    for repeats in (64, 128):
        assert (
            observed[(4_000, repeats)].line_events
            <= observed[(10, repeats)].line_events * 2
        )


def test_actual_match_block_work_is_bounded_on_all_public_ladders(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep source, memory, owner, and visible-locate scans block-sparse."""
    repeats = 64
    statement = ("333 " * repeats).strip()
    body = statement + "\nSynthetic evidence tail.\n"
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="matched-block.txt",
        body=body,
        statement=statement,
        excerpt="Synthetic evidence tail.",
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)

    public_work: dict[tuple[int, str], _LiteralMatchedBlockStats] = {}
    for term_count in (10, 4_000):
        query = _last_distinct_terms_query(term_count)

        source_page, public_work[(term_count, "source")] = _measure_matched_block_work(
            partial(search_sources, synthetic_store, query)
        )
        assert [
            (
                hit.source.original_name,
                hit.match_strength,
                hit.rank,
                hit.exact_excerpt,
                hit.excerpt_char_start,
                hit.excerpt_char_end,
                hit.match_char_start,
                hit.match_char_end,
            )
            for hit in source_page.items
        ] == [
            (
                "matched-block.txt",
                MatchStrength.ANY_TERM,
                -1.0,
                body,
                0,
                len(body),
                0,
                3,
            )
        ]

        memory_page, public_work[(term_count, "memory")] = _measure_matched_block_work(
            partial(search_memories, synthetic_store, query)
        )
        assert [
            (hit.memory.statement, hit.match_strength) for hit in memory_page.items
        ] == [(statement, MatchStrength.ANY_TERM)]

        with _read_connection(synthetic_store) as (connection, identity):
            connection.execute("BEGIN")
            owner_source_page, public_work[(term_count, "owner_source")] = (
                _measure_matched_block_work(
                    partial(
                        owner_search_sources,
                        connection,
                        identity,
                        query,
                        None,
                        20,
                    )
                )
            )
            assert [
                (hit.source.original_name, hit.rank) for hit in owner_source_page.items
            ] == [("matched-block.txt", -1.0)]

            owner_memory_page, public_work[(term_count, "owner_memory")] = (
                _measure_matched_block_work(
                    partial(
                        owner_memory_search_page,
                        connection,
                        identity,
                        query=query,
                        filters=MemoryFilters(),
                        cursor=None,
                        limit=20,
                    )
                )
            )
            assert [hit.revision.statement for hit in owner_memory_page.items] == [
                statement
            ]

    expected_scans = {
        "source": 2,
        "memory": 1,
        "owner_source": 2,
        "owner_memory": 1,
    }
    for (term_count, path), stats in public_work.items():
        assert stats.scan_calls == expected_scans[path], (term_count, path)
        assert stats.query_width_bit_work == 0, (term_count, path)
        assert stats.maximum_runtime_int_bits <= 256, (term_count, path)
    for path in expected_scans:
        assert (
            public_work[(4_000, path)].line_events
            <= public_work[(10, path)].line_events * 2
        )


def test_public_source_and_memory_dense_phrase_scan_is_linear(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch one phrase find per overlapping, rejected mid-word coordinate."""
    phrase = "a" * 64
    run = "a" * 4_096
    statement = f"x{run}x"
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="dense-overlap.txt",
        body=statement,
        statement=statement,
        excerpt=statement[:80],
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)
    source_stats = _LiteralScanStats()
    memory_stats = _LiteralScanStats()
    monkeypatch.setattr(
        retrieval_module,
        "_HAYSTACK_JOIN",
        _MeasuredJoin("\x00", source_stats),
    )
    monkeypatch.setattr(
        memories_module,
        "_HAYSTACK_JOIN",
        _MeasuredJoin("\x00", memory_stats),
    )

    source_page = search_sources(synthetic_store, phrase)
    memory_page = search_memories(synthetic_store, phrase)

    assert [
        (hit.source.original_name, hit.match_strength, hit.rank)
        for hit in source_page.items
    ] == [("dense-overlap.txt", MatchStrength.ANY_TERM, -1.0)]
    assert [
        (hit.memory.statement, hit.match_strength) for hit in memory_page.items
    ] == [(statement, MatchStrength.ANY_TERM)]
    assert (
        source_stats.full_string_operations,
        memory_stats.full_string_operations,
    ) == (0, 0)


def test_compiled_literal_matcher_keeps_no_match_coordinates_dormant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch full-query packed work on text that cannot advance any term."""
    from memory.retrieval import _compile_literal_query

    query = _four_thousand_term_query()
    compiled = _compile_literal_query(query)
    assert len(query.encode("utf-8")) == 15_999
    assert (
        sum(block.all_terms_mask.bit_count() for block in compiled.term_blocks) == 4_000
    )
    assert (
        max(block.all_terms_mask.bit_length() for block in compiled.term_blocks) <= 192
    )

    stats = _LiteralDormantStats()
    _count_boundary_classifications(monkeypatch, stats)
    measured = _instrument_dormant_literal_query(compiled, stats)
    haystack = "x" * 8_192
    evaluation = measured.evaluate(haystack)

    assert evaluation == retrieval_module._LiteralEvaluation(None, -0.0, -1)
    assert stats.wide_operations == 0
    assert stats.boundary_classifications == len(haystack) - 1
    assert stats.boundary_transition_lookups == 0


def test_no_match_coordinates_stay_dormant_through_both_ladders(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the no-output fast path on source and memory Store callers."""
    from memory.retrieval import _compile_literal_query

    query = _four_thousand_term_query()
    body = "Synthetic unmatched " + ("x" * 8_192) + ".\n"
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="unmatched-scale.txt",
        body=body,
        statement=body.rstrip(),
        excerpt="Synthetic unmatched ",
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)
    boundary_stats = _LiteralDormantStats()
    _count_boundary_classifications(monkeypatch, boundary_stats)

    original_compile = _compile_literal_query
    stats: list[_LiteralDormantStats] = []

    def measured_compile(raw_query: str) -> retrieval_module._CompiledLiteralQuery:
        compiled = original_compile(raw_query)
        dormant = _LiteralDormantStats()
        stats.append(dormant)
        return _instrument_dormant_literal_query(compiled, dormant)

    monkeypatch.setattr(retrieval_module, "_compile_literal_query", measured_compile)
    monkeypatch.setattr(memories_module, "_compile_literal_query", measured_compile)

    source_results, memory_results = _literal_ladder_results(synthetic_store, query)

    assert source_results == []
    assert memory_results == []
    assert stats == [_LiteralDormantStats(), _LiteralDormantStats()]
    source_haystack = f"{body}\x00unmatched-scale.txt".casefold()
    memory_haystack = f"{body.rstrip()}\x00synthetic".casefold()
    compile_classifications = 2 * sum(
        len(term) - 1 for term in dict.fromkeys(query.split())
    )
    expected_edge_classifications = (
        compile_classifications + len(source_haystack) - 1 + len(memory_haystack) - 1
    )
    assert boundary_stats.boundary_classifications == expected_edge_classifications


def test_active_boundary_seeds_do_not_touch_query_width_masks(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch repeated valid seeds doing 4,000-term big-int work per position."""
    query = _four_thousand_term_query()
    assert len(query.encode("utf-8")) == 15_999
    compiled = retrieval_module._compile_literal_query(query)
    direct_work: list[tuple[int, int]] = []
    for size in (2_048, 4_096):
        stats = _LiteralDormantStats()
        measured = _instrument_active_boundary_query(
            compiled,
            stats,
            measure_query_width=True,
        )
        evaluation = measured.evaluate("0 " * (size // 2))
        assert evaluation == retrieval_module._LiteralEvaluation(None, -0.0, -1)
        direct_work.append((stats.boundary_transition_lookups, stats.wide_operations))

    body = "Synthetic active seeds: " + ("0 " * 2_048)
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="active-boundary-seeds.txt",
        body=body,
        statement=body,
        excerpt="Synthetic active seeds: ",
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)
    original_compile = retrieval_module._compile_literal_query
    public_stats: list[_LiteralDormantStats] = []

    def measured_compile(raw_query: str) -> retrieval_module._CompiledLiteralQuery:
        stats = _LiteralDormantStats()
        public_stats.append(stats)
        return _instrument_active_boundary_query(
            original_compile(raw_query),
            stats,
            measure_query_width=True,
        )

    monkeypatch.setattr(retrieval_module, "_compile_literal_query", measured_compile)
    monkeypatch.setattr(memories_module, "_compile_literal_query", measured_compile)

    assert search_sources(synthetic_store, query).items == ()
    assert search_memories(synthetic_store, query).items == ()
    public_work = [
        (stats.boundary_transition_lookups, stats.wide_operations)
        for stats in public_stats
    ]
    assert all(
        0 < transitions <= ((2 * size) + 1) * 4
        for transitions, size in zip(
            (direct_work[0][0], direct_work[1][0]),
            (2_048, 4_096),
            strict=True,
        )
    )
    assert all(wide == 0 for _transitions, wide in direct_work)
    assert len(public_work) == 2
    public_haystacks = (
        f"{body}\x00active-boundary-seeds.txt".casefold(),
        f"{body}\x00synthetic".casefold(),
    )
    assert all(
        0 < transitions <= ((2 * len(haystack)) + 1) * 4
        for (transitions, _wide), haystack in zip(
            public_work, public_haystacks, strict=True
        )
    )
    assert all(wide == 0 for _transitions, wide in public_work)


def test_compiled_literal_matcher_does_not_enumerate_nested_prefix_outputs() -> None:
    """Catch one inherited suffix output per term and haystack character."""
    from memory.retrieval import _compile_literal_query, _CompiledLiteralQuery

    small_query = _nested_prefix_query(18)
    adversarial_query = _nested_prefix_query(179)
    assert len(small_query.split()) == 16
    assert len(adversarial_query.split()) == 177
    assert len(adversarial_query.encode("utf-8")) == 16_283
    haystack = "a" * 2_048

    def measure(query: str) -> tuple[object, int]:
        compiled = _compile_literal_query(query)
        evaluated: list[object] = []

        def evaluate_once() -> None:
            evaluated.append(compiled.evaluate(haystack))

        events = _count_line_events(
            _CompiledLiteralQuery.evaluate.__code__, evaluate_once
        )
        assert len(evaluated) == 1
        return evaluated[0], events

    observed: list[int] = []
    for query in (small_query, adversarial_query):
        evaluated, events = measure(query)
        expected_score = len(set(query.split()))
        assert evaluated == retrieval_module._LiteralEvaluation(
            MatchStrength.ANY_TERM,
            -float(expected_score),
            -1,
        )
        observed.append(events)

    # Width groups, unlike inherited output lists, grow logarithmically across
    # these nested terms. The 11x term-count increase must not multiply work.
    assert observed[1] <= observed[0] * 3


def test_nested_prefix_work_is_bounded_through_source_and_memory_ladders(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the aggregate matcher on both real ladder call paths."""
    run = "a" * 2_048
    body = f"prefix\n{run}\nsuffix\n"
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="nested-prefix.txt",
        body=body,
        statement=f"prefix {run} suffix",
        excerpt=f"prefix\n{run[:80]}",
    )

    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)

    queries = (_nested_prefix_query(18), _nested_prefix_query(179))
    evaluate_code = retrieval_module._CompiledLiteralQuery.evaluate.__code__

    def measure_ladders(
        query: str,
    ) -> tuple[int, list[tuple[int, float]], list[tuple[int, float]]]:
        results: list[tuple[list[tuple[int, float]], list[tuple[int, float]]]] = []

        def run_ladders() -> None:
            results.append(_literal_ladder_results(synthetic_store, query))

        events = _count_line_events(evaluate_code, run_ladders)
        assert len(results) == 1
        source_results, memory_results = results[0]
        return events, source_results, memory_results

    observed: list[int] = []
    for query in queries:
        events, source_results, memory_results = measure_ladders(query)
        observed.append(events)
        expected_rank = -float(len(set(query.split())))
        assert source_results == [(2, expected_rank)]
        assert memory_results == [(2, expected_rank)]

    assert observed[1] <= observed[0] * 3


def test_nested_cjk_boundaries_use_one_deterministic_state() -> None:
    """Catch nested CJK terms restoring one active state per query term."""
    queries = (
        " ".join("開" * length for length in range(3, 11)),
        " ".join("開" * length for length in range(3, 101)),
    )
    observed: dict[tuple[int, int], int] = {}
    for query_index, query in enumerate(queries):
        compiled = retrieval_module._compile_literal_query(query)
        for length in (1_024, 2_048):
            haystack = "開" * length
            stats = _LiteralDormantStats()
            measured = _instrument_active_boundary_query(compiled, stats)
            expected = len(set(query.split()))
            assert measured.evaluate(haystack) == retrieval_module._LiteralEvaluation(
                MatchStrength.ALL_TERMS,
                -float(expected),
                -1,
            )
            assert stats.boundary_transition_lookups <= (2 * length + 1) * 4
            observed[(query_index, length)] = stats.boundary_transition_lookups

    for length in (1_024, 2_048):
        assert observed[(1, length)] <= observed[(0, length)] * 2


def test_nested_mixed_boundaries_use_one_state_through_both_ladders(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch one active boundary state per nested mixed-script term."""
    queries = {
        8: _nested_mixed_boundary_query(8),
        89: _nested_mixed_boundary_query(89),
    }
    assert len(queries[89].encode("utf-8")) == 16_197
    expected_ranks = {
        (8, 256): -8.0,
        (8, 512): -8.0,
        (89, 256): -89.0,
        (89, 512): -89.0,
    }

    direct_work: dict[tuple[int, int], int] = {}
    for term_count, query in queries.items():
        compiled = retrieval_module._compile_literal_query(query)
        for repeats in (256, 512):
            haystack = "a開" * repeats
            stats = _LiteralDormantStats()
            measured = _instrument_active_boundary_query(compiled, stats)
            assert measured.evaluate(haystack) == retrieval_module._LiteralEvaluation(
                MatchStrength.ALL_TERMS,
                expected_ranks[(term_count, repeats)],
                -1,
            )
            assert measured.locate(haystack) == (0, 3)
            transformed_token_ceiling = (2 * len(haystack)) + 1
            # `evaluate` and `locate` each scan once. Per scan, mapping
            # membership/get plus failure fallback is amortized to at most
            # four lookups for each transformed token.
            assert (
                stats.boundary_transition_lookups <= transformed_token_ceiling * 2 * 4
            )
            direct_work[(term_count, repeats)] = stats.boundary_transition_lookups

    for repeats in (256, 512):
        assert direct_work[(89, repeats)] <= direct_work[(8, repeats)] * 2

    run = "a開" * 512
    body = run + "\nSynthetic terminal evidence.\n"
    store_one_memory(
        synthetic_store,
        clock=FakeClock(),
        name="nested-mixed-boundaries.txt",
        body=body,
        statement=run,
        excerpt="Synthetic terminal evidence.",
    )
    monkeypatch.setattr(retrieval_module, "_source_fts_strengths", _no_source_fts)
    monkeypatch.setattr(memories_module, "_fts_strengths", _no_memory_fts)
    original_compile = retrieval_module._compile_literal_query
    public_stats: list[tuple[int, _LiteralDormantStats]] = []

    def measured_compile(raw_query: str) -> retrieval_module._CompiledLiteralQuery:
        term_count = len(raw_query.split())
        stats = _LiteralDormantStats()
        public_stats.append((term_count, stats))
        return _instrument_active_boundary_query(original_compile(raw_query), stats)

    monkeypatch.setattr(retrieval_module, "_compile_literal_query", measured_compile)
    monkeypatch.setattr(memories_module, "_compile_literal_query", measured_compile)

    for term_count, query in queries.items():
        source_page = search_sources(synthetic_store, query)
        memory_page = search_memories(synthetic_store, query)
        assert [
            (
                hit.source.original_name,
                hit.match_strength,
                hit.rank,
                hit.exact_excerpt,
                hit.excerpt_char_start,
                hit.excerpt_char_end,
                hit.match_char_start,
                hit.match_char_end,
            )
            for hit in source_page.items
        ] == [
            (
                "nested-mixed-boundaries.txt",
                MatchStrength.ALL_TERMS,
                expected_ranks[(term_count, 512)],
                run[:512],
                0,
                512,
                0,
                3,
            )
        ]
        assert [
            (hit.memory.statement, hit.match_strength) for hit in memory_page.items
        ] == [(run, MatchStrength.ALL_TERMS)]

    source_work = {
        term_count: public_stats[index][1].boundary_transition_lookups
        for index, term_count in ((0, 8), (2, 89))
    }
    memory_work = {
        term_count: public_stats[index][1].boundary_transition_lookups
        for index, term_count in ((1, 8), (3, 89))
    }
    assert [term_count for term_count, _stats in public_stats] == [8, 8, 89, 89]
    source_ladder_haystack = f"{body}\x00nested-mixed-boundaries.txt".casefold()
    memory_haystack = f"{run}\x00synthetic".casefold()
    source_token_ceiling = (
        (2 * len(source_ladder_haystack)) + 1 + (2 * len(body.casefold())) + 1
    )
    memory_token_ceiling = (2 * len(memory_haystack)) + 1
    assert all(work <= source_token_ceiling * 4 for work in source_work.values())
    assert all(work <= memory_token_ceiling * 4 for work in memory_work.values())
    assert source_work[89] <= source_work[8] * 2
    assert memory_work[89] <= memory_work[8] * 2


def test_two_word_query_no_longer_misses_single_word_records(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an AND-only query builder hiding every single-term record."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    page = search_memories(synthetic_store, "amber studio")
    strengths = {hit.memory.statement: hit.match_strength for hit in page.items}
    assert strengths == {
        "The owner keeps the amber studio door open.": MatchStrength.PHRASE,
        "An amber lamp sits beside the studio window.": MatchStrength.ALL_TERMS,
        "The studio calendar hangs by the door.": MatchStrength.ANY_TERM,
    }
    ordered = [hit.match_strength for hit in page.items]
    assert ordered == sorted(
        ordered,
        key=[
            MatchStrength.PHRASE,
            MatchStrength.ALL_TERMS,
            MatchStrength.ANY_TERM,
        ].index,
    )


def test_stemming_unifies_inflections(synthetic_store: RuntimePaths) -> None:
    """Catch a ladder rung that drops the stemmed projection."""
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="loving.txt",
        body="The owner loved gardening on weekends.\n",
        statement="The owner loved gardening on weekends.",
        excerpt="loved gardening on weekends",
    )
    for query in ("love", "loving", "gardens"):
        page = search_memories(synthetic_store, query)
        assert [hit.memory.statement for hit in page.items] == [
            "The owner loved gardening on weekends."
        ], query


def test_ladder_pagination_is_stable_across_rungs(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a cursor that repeats or skips records at a rung boundary."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert len(first.items) == 1 and first.has_more
    second = search_memories(
        synthetic_store, "amber studio", cursor=first.next_cursor, limit=1
    )
    third = search_memories(
        synthetic_store, "amber studio", cursor=second.next_cursor, limit=1
    )
    statements = [page.items[0].memory.statement for page in (first, second, third)]
    assert statements == [
        "The owner keeps the amber studio door open.",
        "An amber lamp sits beside the studio window.",
        "The studio calendar hangs by the door.",
    ]
    assert third.has_more is False


def test_surrounding_whitespace_shares_one_walk(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a trailing space minting a second traversal of the same query."""
    # The kernel enforces its query bound in bytes and then binds the cursor to
    # the query text, so an untrimmed query would carry its own binding, its own
    # folded phrase, and its own page composition for the identical search.
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    resumed = search_memories(
        synthetic_store, " amber studio ", cursor=first.next_cursor, limit=1
    )
    assert [hit.memory.statement for hit in resumed.items] == [
        "An amber lamp sits beside the studio window."
    ]

    first_source = search_sources(synthetic_store, "amber studio", limit=1)
    assert first_source.next_cursor is not None
    exact = search_sources(
        synthetic_store, "amber studio", cursor=first_source.next_cursor, limit=1
    )
    padded = search_sources(
        synthetic_store, "\tamber studio\n", cursor=first_source.next_cursor, limit=1
    )
    assert [hit.source.original_name for hit in padded.items] == [
        hit.source.original_name for hit in exact.items
    ]
    assert padded.items[0].rank == exact.items[0].rank


def test_cursor_from_other_query_is_stale(synthetic_store: RuntimePaths) -> None:
    """Catch a ladder cursor being honoured across two different queries."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    with pytest.raises(StaleCursorError):
        search_memories(synthetic_store, "door", cursor=first.next_cursor)


def test_same_rung_pagination_returns_every_record_exactly_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a resume comparison repeating or skipping inside one rung."""
    clock = FakeClock()
    expected = [
        store_one_memory(
            synthetic_store,
            clock=clock,
            name=f"rung-{index}.txt",
            body=f"Record {index} keeps the amber studio open.\n",
            statement=f"Record {index} keeps the amber studio open.",
            excerpt=f"Record {index} keeps the amber studio open",
        )[0]
        for index in range(5)
    ]
    returned: list[str] = []
    strengths: set[MatchStrength] = set()
    cursor: str | None = None
    pages = 0
    while True:
        page = search_memories(synthetic_store, "amber studio", cursor=cursor, limit=2)
        returned.extend(hit.memory.memory_id for hit in page.items)
        strengths.update(hit.match_strength for hit in page.items)
        pages += 1
        cursor = page.next_cursor
        if not page.has_more:
            break
    assert pages == 3
    assert returned == expected
    assert strengths == {MatchStrength.PHRASE}


@pytest.mark.parametrize(
    ("key", "forged"),
    [
        # 3 is the enumeration rung the shared validator now accepts, so
        # the first out-of-range value moved up by one with it.
        ("strength", 4),
        ("strength", -1),
        ("strength", True),
        ("strength", "1"),
        ("strength", 1.0),
        ("strength", None),
        ("strength", _MISSING),
        ("rank", True),
        ("rank", "1.0"),
        ("rank", float("nan")),
        ("rank", float("inf")),
        ("rank", None),
        ("rank", _MISSING),
    ],
)
def test_forged_cursor_strength_is_rejected(
    synthetic_store: RuntimePaths, key: str, forged: object
) -> None:
    """Catch a tampered rung or rank coordinate steering the resume comparison."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    payload = _decode_payload(first.next_cursor)
    if forged is _MISSING:
        payload.pop(key, None)
    else:
        payload[key] = forged

    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(payload),
            limit=1,
        )


def test_correction_between_pages_stales_the_ladder_cursor(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a superseded head leaving the ladder without staling the cursor."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    head = get_memory(synthetic_store, first.items[0].memory.memory_id)
    batch_id, source = capture_text(
        synthetic_store,
        name="ladder-correction.txt",
        body="The owner now keeps the amber studio door shut.\n",
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
                    item_id="itm_ladder_correction",
                    source=source,
                    statement="The owner now keeps the amber studio door shut.",
                    excerpt="keeps the amber studio door shut",
                    target_lineage_id=head.revision.lineage_id,
                    expected_head_id=head.current_head_id,
                ),
            ),
        ),
    )

    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=first.next_cursor,
            limit=1,
        )


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ('"', 0),
        ('""', 0),
        ("*", 0),
        ("(", 0),
        ("col:amber", 1),
        ("NEAR(a b)", 1),
        ("a NOT b", 1),
        ("\\", 0),
        ("---", 0),
        ("a" * 4000, 0),
    ],
)
def test_fts_syntax_never_escapes_a_rung_expression(
    synthetic_store: RuntimePaths, query: str, expected: int
) -> None:
    """Catch an owner query reaching FTS5 as operator syntax instead of text."""
    # Operator characters must be quoted into literal text, so a query is only
    # ever answered by the words it contains: bare punctuation matches nothing,
    # while a query carrying a real word still reaches the record through it.
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="literal.txt",
        body="The owner keeps the amber studio door open.\n",
        statement="The owner keeps the amber studio door open.",
        excerpt="keeps the amber studio door open",
    )
    assert len(search_memories(synthetic_store, query).items) == expected


def test_chinese_recall_survives_the_phrase_boundary_cap(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the token-boundary cap dropping recall that only substrings carry."""
    # unicode61 keeps one Han run as a single token, so CJK recall rides on the
    # substring rung: the boundary cap may demote that label, never the hit.
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="institute.txt",
        body="研究所的开放时间是周二。\n",
        statement="研究所的开放时间是周二。",
        excerpt="研究所的开放时间是周二",
    )
    # 研究 opens the Han run, so an FTS prefix term still reaches it; 开放 sits
    # mid-token and is reachable only through the substring rung.
    for query in ("研究", "开放"):
        page = search_memories(synthetic_store, query)
        assert [hit.memory.statement for hit in page.items] == [
            "研究所的开放时间是周二。"
        ], query


def test_exact_chinese_phrase_earns_the_phrase_rung(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a Han run capping an exact CJK phrase below the phrase rung."""
    # Every character around a Han match is itself wordish, so a Latin-shaped
    # boundary test can never be satisfied inside a Han run: the label would be
    # capped at all_terms for every CJK query the Store can be asked.
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="hours.txt",
        body="研究所的开放时间是周二。\n",
        statement="研究所的开放时间是周二。",
        excerpt="研究所的开放时间是周二",
    )
    capture_text(
        synthetic_store,
        name="hours-source.txt",
        body="研究所的开放时间是周二。\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    for query in ("开放", "开放时间"):
        assert [
            hit.match_strength for hit in search_memories(synthetic_store, query).items
        ] == [MatchStrength.PHRASE], query
        assert MatchStrength.PHRASE in {
            hit.match_strength for hit in search_sources(synthetic_store, query).items
        }, query


def test_latin_midword_substring_still_cannot_earn_the_phrase_rung(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the CJK boundary exemption leaking into Latin token boundaries."""
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="smart.txt",
        body="A smart studio setup helps.\n",
        statement="A smart studio setup helps.",
        excerpt="A smart studio setup helps",
    )
    page = search_memories(synthetic_store, "art")
    assert [hit.memory.statement for hit in page.items] == [
        "A smart studio setup helps."
    ]
    assert page.items[0].match_strength is not MatchStrength.PHRASE


def test_phrase_label_stops_at_token_boundaries(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a mid-word substring being promoted to the phrase rung."""
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="aligned.txt",
        body="The art studio has north light.\n",
        statement="The art studio has north light.",
        excerpt="The art studio has north light",
    )
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="embedded.txt",
        body="A smart studio setup helps.\n",
        statement="A smart studio setup helps.",
        excerpt="A smart studio setup helps",
    )
    page = search_memories(synthetic_store, "art studio")
    # "smart" contains "art" only inside a longer word, which is weak evidence
    # and must not read as an all-terms match; it lands at any_term, the rung
    # the Skill treats as a lead to verify.
    assert {hit.memory.statement: hit.match_strength for hit in page.items} == {
        "The art studio has north light.": MatchStrength.PHRASE,
        "A smart studio setup helps.": MatchStrength.ANY_TERM,
    }


def test_memory_hits_are_ranked_within_their_rung(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch memory search returning one rung in insertion order."""
    clock = FakeClock()
    for name, statement in (
        ("one.txt", "Record one notes amber."),
        ("three.txt", "Record three notes amber, copper and nickel."),
        ("two.txt", "Record two notes amber beside copper."),
    ):
        store_one_memory(
            synthetic_store,
            clock=clock,
            name=name,
            body=f"{statement}\n",
            statement=statement,
            excerpt=statement,
        )
    page = search_memories(synthetic_store, "amber copper nickel cobalt", limit=10)
    assert {hit.match_strength for hit in page.items} == {MatchStrength.ANY_TERM}
    assert [hit.memory.statement for hit in page.items] == [
        "Record three notes amber, copper and nickel.",
        "Record two notes amber beside copper.",
        "Record one notes amber.",
    ]


def test_memory_rank_order_survives_a_paginated_walk(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a memory cursor resuming on rowid alone under a ranked order."""
    clock = FakeClock()
    terms = ("amber", "copper", "nickel", "cobalt", "zinc")
    query = " ".join(terms)
    for index, count in enumerate((1, 4, 2, 3)):
        statement = f"Record {index} notes " + " ".join(terms[:count]) + "."
        store_one_memory(
            synthetic_store,
            clock=clock,
            name=f"ranked-{index}.txt",
            body=f"{statement}\n",
            statement=statement,
            excerpt=statement,
        )
    single = search_memories(synthetic_store, query, limit=10)
    walked: list[str] = []
    cursor: str | None = None
    while True:
        page = search_memories(synthetic_store, query, cursor=cursor, limit=1)
        walked.extend(hit.memory.memory_id for hit in page.items)
        if not page.has_more:
            break
        cursor = page.next_cursor
    assert walked == [hit.memory.memory_id for hit in single.items]
    assert [hit.memory.statement for hit in single.items] == [
        "Record 1 notes amber copper nickel cobalt.",
        "Record 3 notes amber copper nickel.",
        "Record 2 notes amber copper.",
        "Record 0 notes amber.",
    ]


def test_short_latin_substring_no_longer_admits_a_row(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a two-character Latin fragment admitting a row it is no evidence of."""
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="short.txt",
        body="A smart studio setup helps.\n",
        statement="A smart studio setup helps.",
        excerpt="A smart studio setup helps",
    )
    capture_text(
        synthetic_store,
        name="short-source.txt",
        body="A smart studio setup helps.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    # No token starts with "ar", so the stemmed pass answers nothing and the
    # substring pass was the only thing admitting the row.
    assert search_memories(synthetic_store, "ar").items == ()
    assert search_sources(synthetic_store, "ar").items == ()
    # Three characters clears the length threshold, so `art` still admits the
    # row -- but only inside "smart", so the rung demotion catches what the
    # length rule cannot. Recall is kept and the strength stops overstating it.
    # Raising the threshold instead would have deleted `cat`, `tax`, and `API`
    # as substring terms, which are exactly the short distinctive nouns the
    # Skill tells an agent to search with.
    surviving = search_memories(synthetic_store, "art").items
    assert [hit.match_strength for hit in surviving] == [MatchStrength.ANY_TERM]


def test_short_chinese_terms_stay_exempt_from_the_substring_threshold(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the Latin length threshold deleting real two-character CJK recall."""
    clock = FakeClock()
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="exempt.txt",
        body="研究所的开放时间是周二。\n",
        statement="研究所的开放时间是周二。",
        excerpt="研究所的开放时间是周二",
    )
    # Two terms, only one present, so the hit rides the any-term rung rather
    # than the phrase rung: a two-character Han term is a word, not a fragment.
    page = search_memories(synthetic_store, "开放 缺席")
    assert [hit.match_strength for hit in page.items] == [MatchStrength.ANY_TERM]


def _four_reader_hits(
    paths: RuntimePaths,
    query: str,
) -> tuple[
    list[tuple[str, MatchStrength]],
    list[tuple[str, MatchStrength]],
    list[str],
    list[str],
]:
    """Return the visible hit identity from kernel and owner readers."""
    source_page = search_sources(paths, query)
    memory_page = search_memories(paths, query)
    with _read_connection(paths) as (connection, identity):
        owner_source_page = owner_search_sources(connection, identity, query, None, 10)
        owner_memory_page = owner_memory_search_page(
            connection,
            identity,
            query=query,
            filters=MemoryFilters(),
            cursor=None,
            limit=10,
        )
    return (
        [(hit.source.original_name, hit.match_strength) for hit in source_page.items],
        [(hit.memory.statement, hit.match_strength) for hit in memory_page.items],
        [hit.source.original_name for hit in owner_source_page.items],
        [hit.revision.statement for hit in owner_memory_page.items],
    )


def test_halfwidth_katakana_short_term_reaches_all_four_readers(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch standard halfwidth Katakana taking the Latin short-term branch."""
    from memory.retrieval import _compile_literal_query

    clock = FakeClock()
    statement = (
        "合成記録ではｽﾏﾎﾒﾓﾁｮｳとスマホメモ帳を確認する。"
        "A smart studio note remains synthetic."
    )
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="katakana.txt",
        body=f"{statement}\n",
        statement=statement,
        excerpt=statement,
    )

    # Deleting the halfwidth range makes this compiled literal result disappear
    # before any Store-specific reader can recover it.
    evaluation = _compile_literal_query("ﾒﾓ").evaluate(statement.casefold())
    assert evaluation.strength is MatchStrength.PHRASE
    assert evaluation.phrase_index == 9

    for query in ("ﾒﾓ", "メモ"):
        assert _four_reader_hits(synthetic_store, query) == (
            [("katakana.txt", MatchStrength.PHRASE)],
            [(statement, MatchStrength.PHRASE)],
            ["katakana.txt"],
            [statement],
        )

    for query in ("ar", "art"):
        strength = None if query == "ar" else MatchStrength.ANY_TERM
        expected = (
            ([], [], [], [])
            if strength is None
            else (
                [("katakana.txt", strength)],
                [(statement, strength)],
                ["katakana.txt"],
                [statement],
            )
        )
        assert _four_reader_hits(synthetic_store, query) == expected


def test_halfwidth_hangul_short_term_reaches_all_four_readers(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch standard halfwidth Hangul taking the Latin short-term branch."""
    clock = FakeClock()
    statement = "합성 기록에서 ﾠﾡﾤﾧ과 ㅇㄱㄴㄷ을 확인한다."
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="hangul.txt",
        body=f"{statement}\n",
        statement=statement,
        excerpt=statement,
    )

    for query in ("ﾡﾤ", "ㄱㄴ"):
        assert _four_reader_hits(synthetic_store, query) == (
            [("hangul.txt", MatchStrength.PHRASE)],
            [(statement, MatchStrength.PHRASE)],
            ["hangul.txt"],
            [statement],
        )


def _seed_sources(paths: RuntimePaths, clock: FakeClock) -> None:
    for name, body in (
        ("s-phrase.txt", "Notes: the amber studio stays warm in winter.\n"),
        ("s-all.txt", "The studio uses an amber bulb after dusk.\n"),
        ("s-any.txt", "Winter studio bookings run late.\n"),
    ):
        capture_text(
            paths, name=name, body=body, sensitivity=Sensitivity.NORMAL, clock=clock
        )


def test_source_search_or_rung_catches_single_word_documents(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch source search keeping AND-only recall while memories climb rungs."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    page = search_sources(synthetic_store, "amber studio")
    by_name = {hit.source.original_name: hit.match_strength for hit in page.items}
    assert by_name == {
        "s-phrase.txt": MatchStrength.PHRASE,
        "s-all.txt": MatchStrength.ALL_TERMS,
        "s-any.txt": MatchStrength.ANY_TERM,
    }
    assert page.coverage.searchable == 3


def test_source_search_pagination_walks_rungs_deterministically(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a source cursor repeating or skipping across a rung boundary."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    names: list[str] = []
    cursor = None
    while True:
        page = search_sources(synthetic_store, "amber studio", cursor=cursor, limit=1)
        names.extend(hit.source.original_name for hit in page.items)
        if not page.has_more:
            break
        cursor = page.next_cursor
    assert names == ["s-phrase.txt", "s-all.txt", "s-any.txt"]


def test_source_search_substring_rung_matches_partial_words(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch source search losing the literal substring rung memories carry."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="runner.txt",
        body="Marathon runner logs, spring block.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    page = search_sources(synthetic_store, "runn")
    assert [hit.source.original_name for hit in page.items] == ["runner.txt"]


def test_source_search_cursor_stales_when_the_projection_changes(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a reindex reshaping rung membership under a paginated walk."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    first = search_sources(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "DELETE FROM source_fts WHERE source_id IN "
            "(SELECT source_id FROM sources WHERE original_name = ?)",
            ("s-any.txt",),
        )

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "amber studio",
            cursor=first.next_cursor,
            limit=1,
        )


def test_previous_source_ladder_binding_is_stale(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a version-three source cursor resuming under fidelity-only search."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    first = search_sources(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    payload = _decode_payload(first.next_cursor)
    payload["binding"] = hashlib.sha256(
        _canonical_json({"ladder": 3, "query": "amber studio"})
    ).hexdigest()

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(payload),
            limit=1,
        )


@pytest.mark.parametrize("older_version", (5, 6))
def test_all_older_search_bindings_fail_closed(
    synthetic_store: RuntimePaths,
    older_version: int,
) -> None:
    """Require the single ladder move to reach all four cursor bindings."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    _seed(synthetic_store, clock)

    source_first = search_sources(synthetic_store, "amber studio", limit=1)
    memory_first = search_memories(synthetic_store, "amber studio", limit=1)
    assert source_first.next_cursor is not None
    assert memory_first.next_cursor is not None
    source_payload = _decode_payload(source_first.next_cursor)
    memory_payload = _decode_payload(memory_first.next_cursor)
    source_payload["binding"] = hashlib.sha256(
        _canonical_json({"ladder": older_version, "query": "amber studio"})
    ).hexdigest()
    memory_payload["binding"] = hashlib.sha256(
        _canonical_json(
            {
                "ladder": older_version,
                "query": "amber studio",
                "filters": owner_filters_payload(MemoryFilters()),
            }
        )
    ).hexdigest()
    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(source_payload),
            limit=1,
        )
    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(memory_payload),
            limit=1,
        )

    with _read_connection(synthetic_store) as (connection, identity):
        source_owner = owner_search_sources(
            connection, identity, "amber studio", None, 1
        )
        memory_owner = owner_memory_search_page(
            connection,
            identity,
            query="amber studio",
            filters=MemoryFilters(),
            cursor=None,
            limit=1,
        )
        assert source_owner.next_cursor is not None
        assert memory_owner.next_cursor is not None
        source_owner_payload = _decode_payload(source_owner.next_cursor)
        memory_owner_payload = _decode_payload(memory_owner.next_cursor)
        source_owner_payload["binding"] = owner_filter_binding(
            {"query": "amber studio", "ladder": older_version}
        )
        memory_owner_payload["binding"] = owner_filter_binding(
            {
                "query": "amber studio",
                "filters": owner_filters_payload(MemoryFilters()),
                "ladder": older_version,
            }
        )
        with pytest.raises(StaleCursorError):
            owner_search_sources(
                connection,
                identity,
                "amber studio",
                _encode_payload(source_owner_payload),
                1,
            )
        with pytest.raises(StaleCursorError):
            owner_memory_search_page(
                connection,
                identity,
                query="amber studio",
                filters=MemoryFilters(),
                cursor=_encode_payload(memory_owner_payload),
                limit=1,
            )


@pytest.mark.parametrize("older_version", (5, 6))
def test_both_older_kernel_snapshot_digests_fail_closed(
    synthetic_store: RuntimePaths,
    older_version: int,
) -> None:
    """Require source and memory snapshots to carry the shared ladder move."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    _seed(synthetic_store, clock)
    source_first = search_sources(synthetic_store, "amber studio", limit=1)
    memory_first = search_memories(synthetic_store, "amber studio", limit=1)
    assert source_first.next_cursor is not None
    assert memory_first.next_cursor is not None
    source_payload = _decode_payload(source_first.next_cursor)
    memory_payload = _decode_payload(memory_first.next_cursor)
    source_upper_value = source_payload["upper"]
    memory_upper_value = memory_payload["upper"]
    assert isinstance(source_upper_value, int) and not isinstance(
        source_upper_value, bool
    )
    assert isinstance(memory_upper_value, int) and not isinstance(
        memory_upper_value, bool
    )

    with _read_connection(synthetic_store) as (connection, _identity):
        connection.execute("BEGIN")
        source_entries = _source_ladder_matches(
            connection, "amber studio", source_upper_value
        )
        memory_entries = _ladder_matches(
            connection,
            "amber studio",
            MemoryFilters(),
            memory_upper_value,
        )
    source_payload["snapshot"] = hashlib.sha256(
        _canonical_json(
            {
                "entries": [
                    [
                        entry.strength,
                        entry.rank + 0.0,
                        entry.rowid,
                        entry.source_id,
                    ]
                    for entry in source_entries
                ],
                "ladder": older_version,
                "upper": source_upper_value,
            }
        )
    ).hexdigest()
    memory_payload["snapshot"] = hashlib.sha256(
        _canonical_json(
            {
                "entries": [
                    [
                        entry.strength,
                        entry.rank + 0.0,
                        entry.rowid,
                        entry.revision_id,
                        entry.sensitivity_rank,
                    ]
                    for entry in memory_entries
                ],
                "ladder": older_version,
                "upper": memory_upper_value,
            }
        )
    ).hexdigest()

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(source_payload),
            limit=1,
        )
    with pytest.raises(StaleCursorError):
        search_memories(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(memory_payload),
            limit=1,
        )


@pytest.mark.parametrize(
    ("key", "forged"),
    [
        # 3 is the enumeration rung the shared validator now accepts, so
        # the first out-of-range value moved up by one with it.
        ("strength", 4),
        ("strength", -1),
        ("strength", True),
        ("strength", "1"),
        ("strength", 1.0),
        ("strength", None),
        ("strength", _MISSING),
        ("rank", True),
        ("rank", "1.0"),
        ("rank", float("nan")),
        ("rank", float("inf")),
        ("rank", None),
        ("rank", _MISSING),
        ("snapshot", "0" * 63),
        ("snapshot", "z" * 64),
        ("snapshot", 0),
        ("snapshot", None),
        ("snapshot", _MISSING),
    ],
)
def test_forged_source_cursor_coordinates_are_rejected(
    synthetic_store: RuntimePaths, key: str, forged: object
) -> None:
    """Catch a tampered rung, rank, or digest steering the source resume."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    first = search_sources(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    payload = _decode_payload(first.next_cursor)
    if forged is _MISSING:
        payload.pop(key, None)
    else:
        payload[key] = forged

    with pytest.raises(StaleCursorError):
        search_sources(
            synthetic_store,
            "amber studio",
            cursor=_encode_payload(payload),
            limit=1,
        )


def test_source_chinese_recall_survives_the_phrase_boundary_cap(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch source search losing CJK recall the FTS projection cannot reach."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="institute.txt",
        body="研究所的开放时间是周二。\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    # 研究 opens the Han run, so an FTS prefix term still reaches it; 开放 sits
    # mid-token and is reachable only through the substring rung.
    for query in ("研究", "开放"):
        page = search_sources(synthetic_store, query)
        names = [hit.source.original_name for hit in page.items]
        assert names == ["institute.txt"], query
    # A Han run is boundary-exempt, so the mid-run match is an exact phrase
    # rather than a hit the boundary test had to demote.
    strongest = search_sources(synthetic_store, "开放").items[0].match_strength
    assert strongest is MatchStrength.PHRASE


def _walk_sources(paths: RuntimePaths, query: str) -> list[str]:
    """Page one source search a hit at a time and collect the order it yields."""
    walked: list[str] = []
    cursor = None
    while True:
        page = search_sources(paths, query, cursor=cursor, limit=1)
        walked.extend(hit.source.original_name for hit in page.items)
        if not page.has_more:
            break
        cursor = page.next_cursor
    return walked


def test_memory_search_cursor_survives_an_idempotent_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch projection identity or DDL leaking into the memory ladder digest."""
    # `memory reindex` drops and repopulates both FTS tables. It changes no
    # canonical row, so a walk in flight must continue rather than fail closed.
    clock = FakeClock()
    _seed(synthetic_store, clock)
    first = search_memories(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    rebuild_search_projections(synthetic_store)

    second = search_memories(
        synthetic_store, "amber studio", cursor=first.next_cursor, limit=1
    )
    assert [hit.memory.statement for hit in second.items] == [
        "An amber lamp sits beside the studio window."
    ]
    assert second.items[0].match_strength is MatchStrength.ALL_TERMS


def test_source_search_cursor_survives_an_idempotent_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch projection identity or DDL leaking into the source ladder digest."""
    clock = FakeClock()
    _seed_sources(synthetic_store, clock)
    first = search_sources(synthetic_store, "amber studio", limit=1)
    assert first.next_cursor is not None
    rebuild_search_projections(synthetic_store)

    second = search_sources(
        synthetic_store, "amber studio", cursor=first.next_cursor, limit=1
    )
    assert [hit.source.original_name for hit in second.items] == ["s-all.txt"]
    assert second.items[0].match_strength is MatchStrength.ALL_TERMS


def test_source_search_walks_one_tied_rung_without_drift(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a resume comparison repeating or skipping inside one tied rung."""
    clock = FakeClock()
    for index in range(4):
        capture_text(
            synthetic_store,
            name=f"tie-{index}.txt",
            body="An amber studio note.\n",
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
    single = search_sources(synthetic_store, "amber studio", limit=20)
    assert {hit.rank for hit in single.items} == {-3.0}
    assert {hit.match_strength for hit in single.items} == {MatchStrength.PHRASE}

    walked = _walk_sources(synthetic_store, "amber studio")
    assert walked == [hit.source.original_name for hit in single.items]
    assert walked == [f"tie-{index}.txt" for index in range(4)]


def test_projection_duplicates_cannot_promote_or_hide_canonical_source_text(
    synthetic_store: RuntimePaths,
) -> None:
    """Keep duplicate corruption out of hit, rung, rank, and excerpt fidelity."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="a-winter.txt",
        body="Winter studio bookings run late.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    (synthetic_store.inbox / "b-gap.png").write_bytes(b"\x89PNG\x00\xffsynthetic")
    (synthetic_store.inbox / "c-canonical.txt").write_text(
        "Canonical xxneedlexx retained body.\n",
        encoding="utf-8",
    )
    from memory.inbox import scan_inbox

    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=clock)
    baseline = search_sources(synthetic_store, "xxneedlexx", limit=20)
    assert [hit.source.original_name for hit in baseline.items] == ["c-canonical.txt"]
    with writer_session(synthetic_store) as connection:
        winter = connection.execute(
            "SELECT s.rowid, s.source_id FROM sources AS s WHERE s.original_name = ?",
            ("a-winter.txt",),
        ).fetchone()
        canonical = connection.execute(
            "SELECT s.rowid, s.source_id FROM sources AS s WHERE s.original_name = ?",
            ("c-canonical.txt",),
        ).fetchone()
        assert winter is not None
        assert canonical is not None
        connection.execute(
            "INSERT INTO source_fts "
            "(rowid, source_id, capture_rowid, utf8_text, original_name) "
            "VALUES (1001, ?, ?, ?, ?)",
            (
                str(winter[1]),
                int(winter[0]),
                "The amber studio repeats amber studio.",
                "a-winter.txt",
            ),
        )
        connection.execute(
            "INSERT INTO source_fts "
            "(rowid, source_id, capture_rowid, utf8_text, original_name) "
            "VALUES (2, ?, ?, ?, ?)",
            (
                str(canonical[1]),
                int(canonical[0]),
                "Synthetic unrelated lower-rowid duplicate.",
                "c-canonical.txt",
            ),
        )

    retained = search_sources(synthetic_store, "xxneedlexx", limit=20)
    duplicate_query = search_sources(synthetic_store, "amber studio", limit=20)
    assert [
        (hit.source.source_id, hit.match_strength, hit.rank) for hit in retained.items
    ] == [
        (
            baseline.items[0].source.source_id,
            baseline.items[0].match_strength,
            baseline.items[0].rank,
        )
    ]
    assert [
        (hit.source.original_name, hit.match_strength, hit.rank)
        for hit in duplicate_query.items
    ] == [("a-winter.txt", MatchStrength.ANY_TERM, -1.0)]
    assert "amber" not in duplicate_query.items[0].exact_excerpt.casefold()

    from memory.retrieval import read_source
    from memory.sources import _read_connection

    source_id = retained.items[0].source.source_id
    authoritative = read_source(synthetic_store, source_id).text
    with _read_connection(synthetic_store) as (connection, identity):
        owner = owner_search_sources(connection, identity, "xxneedlexx", None, 20)
    assert authoritative is not None
    assert retained.items[0].exact_excerpt == owner.items[0].exact_excerpt
    assert retained.items[0].exact_excerpt in authoritative


def test_memory_projection_rows_must_match_the_same_canonical_revision(
    synthetic_store: RuntimePaths,
) -> None:
    """Keep malformed memory projection rows out of every retrieval surface.

    The matrix deliberately combines an exact duplicate with a divergent row
    for the same revision.  An implementation that merely asks whether *some*
    exact row exists will still let the divergent row supply MATCH and
    fabricate the hit.  A second current head has only a tag-drifted row, so
    statement and tag fidelity are independently load-bearing.
    """
    clock = FakeClock()
    first_id, _first_lineage = store_one_memory(
        synthetic_store,
        clock=clock,
        name="cedar.txt",
        body="The cedar gardener loved spring planning.\n",
        statement="The cedar gardener loved spring planning.",
        excerpt="cedar gardener loved spring planning",
    )
    drifted_id, _drifted_lineage = store_one_memory(
        synthetic_store,
        clock=clock,
        name="orchard.txt",
        body="The orchard gardener loved summer planning.\n",
        statement="The orchard gardener loved summer planning.",
        excerpt="orchard gardener loved summer planning",
    )
    historical_id, historical_lineage = store_one_memory(
        synthetic_store,
        clock=clock,
        name="historical.txt",
        body="The historicalneedle note described an old route.\n",
        statement="The historicalneedle note described an old route.",
        excerpt="historicalneedle note described an old route",
    )
    correction_batch, correction_source = capture_text(
        synthetic_store,
        name="current.txt",
        body="The current route follows the harbor path.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    corrected = apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            correction_batch,
            (
                single_item_edit(
                    item_id="itm_current_route",
                    source=correction_source,
                    statement="The current route follows the harbor path.",
                    excerpt="current route follows the harbor path",
                    target_lineage_id=historical_lineage,
                    expected_head_id=historical_id,
                ),
            ),
        ),
    )
    current_id = corrected.memory_ids[0]
    final_id, _final_lineage = store_one_memory(
        synthetic_store,
        clock=clock,
        name="terrace.txt",
        body="The terrace gardener loved autumn planning.\n",
        statement="The terrace gardener loved autumn planning.",
        excerpt="terrace gardener loved autumn planning",
    )

    with writer_session(synthetic_store) as connection:
        canonical = connection.execute(
            "SELECT statement, tags FROM memory_fts WHERE revision_id = ?",
            (first_id,),
        ).fetchone()
        historical = connection.execute(
            "SELECT statement, (SELECT COALESCE(group_concat(value, ' '), '') "
            "FROM json_each(revision.tags_json)) "
            "FROM memory_revisions AS revision WHERE revision.revision_id = ?",
            (historical_id,),
        ).fetchone()
        assert canonical is not None
        assert historical is not None
        # Same revision, exact row still present: only same-row MATCH fidelity
        # prevents this divergent duplicate from fabricating a result.
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            (first_id, "Projected phantomstatement only.", str(canonical[1])),
        )
        # An exact duplicate remains harmless to ranking, but the audit must
        # retain it as unexpected projection debt.
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            (first_id, str(canonical[0]), str(canonical[1])),
        )
        # Statement stays exact while tags drift.  The row is no longer a
        # canonical projection, even for a statement-only query.
        connection.execute(
            "UPDATE memory_fts SET tags = ? WHERE revision_id = ?",
            ("phantomtag", drifted_id),
        )
        # Historical and orphan rows are audit evidence only.
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            (historical_id, str(historical[0]), str(historical[1])),
        )
        connection.execute(
            "INSERT INTO memory_fts (revision_id, statement, tags) VALUES (?, ?, ?)",
            ("mem_synthetic_orphan", "Projected orphanneedle only.", "synthetic"),
        )

    assert search_memories(synthetic_store, "phantomstatement").items == ()
    assert search_memories(synthetic_store, "phantomtag").items == ()
    assert search_memories(synthetic_store, "historicalneedle").items == ()
    assert search_memories(synthetic_store, "orphanneedle").items == ()

    kernel_ids: list[str] = []
    cursor = None
    while True:
        page = search_memories(synthetic_store, "loving", cursor=cursor, limit=1)
        kernel_ids.extend(hit.memory.memory_id for hit in page.items)
        if not page.has_more:
            coverage = page.coverage
            break
        cursor = page.next_cursor
    assert kernel_ids == [first_id, final_id]
    assert coverage.searchable == 3
    assert coverage.unsearchable == 1
    assert coverage.enumerated == 3
    assert coverage.total == 4

    with _read_connection(synthetic_store) as (connection, identity):
        owner_ids: list[str] = []
        owner_cursor = None
        while True:
            owner_page = owner_memory_search_page(
                connection,
                identity,
                query="loving",
                filters=MemoryFilters(),
                cursor=owner_cursor,
                limit=1,
            )
            owner_ids.extend(item.revision.memory_id for item in owner_page.items)
            if not owner_page.has_more:
                break
            owner_cursor = owner_page.next_cursor
        audit = owner_memory_projection_coverage(connection)
        for query in ("phantomstatement", "phantomtag", "historicalneedle"):
            assert (
                owner_memory_search_page(
                    connection,
                    identity,
                    query=query,
                    filters=MemoryFilters(),
                    cursor=None,
                    limit=10,
                ).items
                == ()
            )
    assert owner_ids == kernel_ids
    assert audit.current_heads == 4
    assert audit.indexed_current_heads == 3
    assert audit.missing_current_head_rows == 1
    assert audit.unexpected_or_duplicate_noncurrent_rows == 5
    assert audit.historical_revisions_not_expected == 1

    # Disposable projection corruption never restates authoritative history.
    assert get_memory(synthetic_store, drifted_id).revision.statement == (
        "The orchard gardener loved summer planning."
    )
    historical_detail = get_memory(synthetic_store, historical_id)
    assert historical_detail.is_current is False
    assert historical_detail.current_head_id == current_id


# One fixed synthetic corpus, English and Chinese, exercising every rung the
# ladder can assign plus a stem-only hit, a tie, and a filename-only match. The
# golden sequences below were recorded from the single-pass ladder before the
# two-pass restructure and must survive it unchanged.
_DIFFERENTIAL_SOURCES: tuple[tuple[str, str], ...] = (
    (
        "amber-notes.txt",
        "The amber studio stays warm in winter. The amber lamp glows.\n",
    ),
    ("studio-log.md", "The studio uses an amber bulb after dusk.\n"),
    ("winter-bookings.txt", "Winter bookings for the studio run late.\n"),
    ("gardening.txt", "The owner spent Sunday gardening behind the shed.\n"),
    ("institute.md", "研究所的开放时间是周二。摄影棚在二楼。\n"),
    ("photo-studio.md", "摄影棚的琥珀色灯光很暖，开放给所有住户。\n"),
    ("tie-a.txt", "An amber studio note.\n"),
    ("tie-b.txt", "An amber studio note.\n"),
)
_DIFFERENTIAL_QUERIES = ("amber studio", "开放", "摄影棚", "gardens", "amber")
_DIFFERENTIAL_PAGE_SIZES = (1, 2, 3, 5, 100)
#: Filename membership remains part of the haystack; version seven scores each
#: admitted literal term once across that complete haystack. A repeated filename
#: or body term no longer multiplies rank. This recording preserves membership,
#: rung, order and page-size parity under the intentional new scores.
_GOLDEN_SOURCE_SEQUENCES: dict[str, list[tuple[str, str, float]]] = {
    "amber studio": [
        ("amber-notes.txt", "phrase", -3.0),
        ("tie-a.txt", "phrase", -3.0),
        ("tie-b.txt", "phrase", -3.0),
        ("studio-log.md", "all_terms", -2.0),
        ("winter-bookings.txt", "any_term", -1.0),
        ("photo-studio.md", "any_term", -1.0),
    ],
    "开放": [
        ("institute.md", "phrase", -2.0),
        ("photo-studio.md", "phrase", -2.0),
    ],
    "摄影棚": [
        ("institute.md", "phrase", -2.0),
        ("photo-studio.md", "phrase", -2.0),
    ],
    # A stem-only hit: "gardens" occurs nowhere literally, so the projection
    # admits it at the phrase rung and the literal score stays at zero.
    "gardens": [("gardening.txt", "phrase", -0.0)],
    "amber": [
        ("amber-notes.txt", "phrase", -2.0),
        ("studio-log.md", "phrase", -2.0),
        ("tie-a.txt", "phrase", -2.0),
        ("tie-b.txt", "phrase", -2.0),
    ],
}
_GOLDEN_MEMORY_SEQUENCES: dict[str, list[tuple[str, str]]] = {
    "amber studio": [
        ("The amber studio stays warm in winter. The amber lamp glows.", "phrase"),
        ("An amber studio note.", "phrase"),
        ("An amber studio note.", "phrase"),
        ("The studio uses an amber bulb after dusk.", "all_terms"),
        ("Winter bookings for the studio run late.", "any_term"),
    ],
    "开放": [
        ("研究所的开放时间是周二。摄影棚在二楼。", "phrase"),
        ("摄影棚的琥珀色灯光很暖，开放给所有住户。", "phrase"),
    ],
    "摄影棚": [
        ("研究所的开放时间是周二。摄影棚在二楼。", "phrase"),
        ("摄影棚的琥珀色灯光很暖，开放给所有住户。", "phrase"),
    ],
    "gardens": [("The owner spent Sunday gardening behind the shed.", "phrase")],
    "amber": [
        ("The amber studio stays warm in winter. The amber lamp glows.", "phrase"),
        ("The studio uses an amber bulb after dusk.", "phrase"),
        ("An amber studio note.", "phrase"),
        ("An amber studio note.", "phrase"),
    ],
}


def test_a_cjk_filename_is_findable_mid_run_without_a_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a filename only the stemmed pass can see.

    `unicode61` keeps one Han run as a single token, so a query inside that run
    is answered by the literal substring pass alone. A ladder that indexes the
    filename for FTS but folds only the body text therefore leaves a Chinese
    filename findable only by its whole run -- which is the same gap indexing
    the filename was meant to close.
    """
    capture_text(
        synthetic_store,
        name="摄影棚-年度日志.md",
        body="Unrelated English body with no Chinese at all.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )

    whole_run = search_sources(synthetic_store, "摄影棚-年度日志").items
    mid_run = search_sources(synthetic_store, "年度").items

    assert [hit.source.original_name for hit in whole_run] == ["摄影棚-年度日志.md"]
    assert [hit.source.original_name for hit in mid_run] == ["摄影棚-年度日志.md"]


def test_no_phrase_can_straddle_two_fields_of_one_haystack(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a rung and a rank asserting text that exists in no field.

    Both ladders fold several fields into one haystack -- a source's text and
    filename, a memory's statement and tags. Joined on a space, a query whose
    first half ends one field and whose second half begins the next reads as
    an exact occurrence with a token boundary on both sides, so it earns the
    top rung and a rank counting occurrences of something the capture does not
    contain. The Skill treats `phrase` as an established hit rather than a
    lead, so the fabricated match outranks the real ones.
    """
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="studio-notes.txt",
        body="The lamp is amber",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    batch, sources = capture_batch(
        synthetic_store,
        {"tagged.txt": "The lamp is amber in winter.\n"},
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch,
            (
                single_item_edit(
                    item_id="itm_junction",
                    source=sources["tagged.txt"],
                    statement="The lamp is amber",
                    excerpt="The lamp is amber in winter.",
                    tags=("studio", "lighting"),
                ),
            ),
        ),
    )

    source_hits = {
        hit.source.original_name: hit
        for hit in search_sources(synthetic_store, "amber studio").items
    }
    memory_hits = {
        hit.memory.statement: hit
        for hit in search_memories(synthetic_store, "amber studio").items
    }

    # Both terms really are present -- one in the body, one in the filename --
    # so the row is admitted, but at all_terms rather than as an exact phrase.
    straddling = source_hits["studio-notes.txt"]
    assert straddling.match_strength is MatchStrength.ALL_TERMS
    # And the rank counts only occurrences that exist: one "amber", one
    # "studio", and no phrase.
    assert straddling.rank == -2.0
    # The same junction exists between a memory's statement and its tags.
    assert memory_hits["The lamp is amber"].match_strength is MatchStrength.ALL_TERMS


def test_two_adjacent_tags_are_not_one_phrase(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the stemmed pass forming a phrase across two separate tags.

    `memory_fts` stores every tag in one column, and FTS5 gives a row's tokens
    one position sequence, so `copper` and `lantern` stored as two tags are
    adjacent tokens and an unconfined phrase expression matches "copper
    lantern" at the top rung. The Skill treats `phrase` as an established hit
    rather than a lead, so the overstatement is acted on. Recall is not the
    issue -- both terms really are present -- the rung is.
    """
    clock = FakeClock()
    batch, sources = capture_batch(
        synthetic_store,
        {"tags.txt": "A note about gardening in winter.\n"},
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch,
            (
                single_item_edit(
                    item_id="itm_adjacent_tags",
                    source=sources["tags.txt"],
                    statement="A note about gardening in winter.",
                    excerpt="A note about gardening in winter.",
                    tags=("copper", "lantern", "amber studio"),
                ),
            ),
        ),
    )

    def strengths(query: str) -> list[MatchStrength]:
        return [
            hit.match_strength for hit in search_memories(synthetic_store, query).items
        ]

    # Two separate tags: still found, no longer called a phrase, and the
    # answer no longer depends on which order the tags happen to be stored in.
    assert strengths("copper lantern") == [MatchStrength.ALL_TERMS]
    assert strengths("lantern copper") == [MatchStrength.ALL_TERMS]
    # A phrase that really does sit inside one field keeps its rung: the
    # literal pass awards it whether it is one tag or the statement.
    assert strengths("amber studio") == [MatchStrength.PHRASE]
    assert strengths("gardening in winter") == [MatchStrength.PHRASE]
    # And the stemmed pass still answers over the statement.
    assert strengths("gardens") == [MatchStrength.PHRASE]


def test_a_match_span_points_at_the_occurrence_it_validated(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a span validated on one occurrence and reported from another.

    A document can hold a mid-word occurrence before a real one -- "art" sits
    inside "party" before the "art" in "A party in the art room". A check that
    asks "is any occurrence at a boundary" and a report that takes `find`'s
    first hit disagree exactly there, and the Skill converts a span into an
    evidence locator without a second search, so the citation validates
    against the source and points at the wrong word.
    """
    clock = FakeClock()
    for name, body in (
        ("mid-first.txt", "A party in the art room."),
        ("prefix.txt", "Smartly, the art room opened."),
        ("none.txt", "The party started at dawn."),
        ("chinese.txt", "研究所的开放时间是周二。"),
    ):
        capture_text(
            synthetic_store,
            name=name,
            body=body,
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )

    def span(query: str, name: str) -> str | None:
        hit = next(
            item
            for item in search_sources(synthetic_store, query).items
            if item.source.original_name == name
        )
        if hit.match_char_start is None:
            return None
        return hit.exact_excerpt[hit.match_char_start : hit.match_char_end]

    # Both documents hold an earlier mid-word occurrence; the span names the
    # standalone one that satisfied the boundary rule.
    assert span("art", "mid-first.txt") == "art"
    assert span("art", "prefix.txt") == "art"
    # A document whose only occurrence is inside a longer word reports none.
    assert span("art", "none.txt") is None
    # The unspaced-script exemption still yields a span.
    assert span("开放", "chinese.txt") == "开放"


def test_both_owner_walks_fail_closed_across_a_reindex(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an owner walk resuming across a rebuild that reordered it.

    A reindex changes which rung a capture reaches -- filename stemming
    arrives with it -- so a walk resumed across one skips every entry the
    rebuild promoted above the boundary it left off at, and terminates looking
    complete. The owner memory reader binds the audit generation for exactly
    this reason; the source reader is the walk the owner is most likely to
    have open, because `memory reindex` is what the upgrade tells them to run.
    """
    clock = FakeClock()
    for name, body in (
        ("gardens-orchards.md", "A note that mentions neither term directly.\n"),
        ("a.txt", "gardens orchards\n"),
        ("c.txt", "gardens only\n"),
    ):
        capture_text(
            synthetic_store,
            name=name,
            body=body,
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
    # Two memories, both matching, so a limit-1 page actually mints a cursor.
    # With one, the memory half of this test never ran: its `next_cursor` was
    # None and the arm sat behind a conditional that was never true.
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="m.txt",
        body="The orchard gardens open on Tuesday.\n",
        statement="The orchard gardens open on Tuesday.",
        excerpt="The orchard gardens open on Tuesday.",
    )
    store_one_memory(
        synthetic_store,
        clock=clock,
        name="n.txt",
        body="The gardens close for winter in November.\n",
        statement="The gardens close for winter in November.",
        excerpt="The gardens close for winter in November.",
    )

    with _read_connection(synthetic_store) as (connection, identity):
        connection.execute("BEGIN")
        sources = owner_search_sources(
            connection, identity, "gardens orchards", None, 1
        )
        memories = owner_memory_search_page(
            connection,
            identity,
            query="gardens",
            filters=MemoryFilters(),
            cursor=None,
            limit=1,
        )
    assert sources.next_cursor is not None
    assert memories.next_cursor is not None

    rebuild_search_projections(synthetic_store)

    with _read_connection(synthetic_store) as (connection, identity):
        connection.execute("BEGIN")
        with pytest.raises(StaleCursorError):
            owner_search_sources(
                connection, identity, "gardens orchards", sources.next_cursor, 1
            )
        with pytest.raises(StaleCursorError):
            owner_memory_search_page(
                connection,
                identity,
                query="gardens",
                filters=MemoryFilters(),
                cursor=memories.next_cursor,
                limit=1,
            )


def _seed_differential_sources(paths: RuntimePaths, clock: FakeClock) -> None:
    for name, body in _DIFFERENTIAL_SOURCES:
        capture_text(
            paths, name=name, body=body, sensitivity=Sensitivity.NORMAL, clock=clock
        )


def _seed_differential_memories(paths: RuntimePaths, clock: FakeClock) -> None:
    for name, body in _DIFFERENTIAL_SOURCES:
        statement = body.strip()
        store_one_memory(
            paths,
            clock=clock,
            name=f"m-{name}",
            body=body,
            statement=statement,
            excerpt=statement,
        )


def _source_sequence(
    paths: RuntimePaths, query: str, page_size: int
) -> list[tuple[str, str, float]]:
    """Walk one source search to exhaustion and record every scored hit."""
    walked: list[tuple[str, str, float]] = []
    cursor: str | None = None
    while True:
        page = search_sources(paths, query, cursor=cursor, limit=page_size)
        walked.extend(
            (hit.source.original_name, hit.match_strength.value, hit.rank)
            for hit in page.items
        )
        if not page.has_more:
            return walked
        cursor = page.next_cursor


def _memory_sequence(
    paths: RuntimePaths, query: str, page_size: int
) -> list[tuple[str, str]]:
    """Walk one memory search to exhaustion and record every rung it assigned."""
    walked: list[tuple[str, str]] = []
    cursor: str | None = None
    while True:
        page = search_memories(paths, query, cursor=cursor, limit=page_size)
        walked.extend(
            (hit.memory.statement, hit.match_strength.value) for hit in page.items
        )
        if not page.has_more:
            return walked
        cursor = page.next_cursor


def test_source_ladder_sequence_is_identical_across_every_page_size(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a ladder restructure changing membership, rung, rank, or order."""
    clock = FakeClock()
    _seed_differential_sources(synthetic_store, clock)
    recorded = {
        query: _source_sequence(synthetic_store, query, 100)
        for query in _DIFFERENTIAL_QUERIES
    }
    for query in _DIFFERENTIAL_QUERIES:
        for page_size in _DIFFERENTIAL_PAGE_SIZES:
            assert (
                _source_sequence(synthetic_store, query, page_size) == recorded[query]
            ), (query, page_size)
    assert recorded == _GOLDEN_SOURCE_SEQUENCES


def test_memory_ladder_sequence_is_identical_across_every_page_size(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a ladder restructure changing membership, rung, or order."""
    clock = FakeClock()
    _seed_differential_memories(synthetic_store, clock)
    recorded = {
        query: _memory_sequence(synthetic_store, query, 100)
        for query in _DIFFERENTIAL_QUERIES
    }
    for query in _DIFFERENTIAL_QUERIES:
        for page_size in _DIFFERENTIAL_PAGE_SIZES:
            assert (
                _memory_sequence(synthetic_store, query, page_size) == recorded[query]
            ), (query, page_size)
    assert recorded == _GOLDEN_MEMORY_SEQUENCES


def _owner_source_hits(paths: RuntimePaths, query: str) -> set[str]:
    """Page the owner's browser search to exhaustion and collect its hits."""
    found: set[str] = set()
    with _read_connection(paths) as (connection, identity):
        cursor: str | None = None
        while True:
            page = owner_search_sources(connection, identity, query, cursor, 2)
            found.update(hit.source.source_id for hit in page.items)
            if not page.has_more:
                return found
            cursor = page.next_cursor


def _owner_memory_hits(paths: RuntimePaths, query: str) -> set[str]:
    """Page the owner's browser memory search to exhaustion and collect its hits."""
    found: set[str] = set()
    with _read_connection(paths) as (connection, identity):
        cursor: str | None = None
        while True:
            page = owner_memory_search_page(
                connection,
                identity,
                query=query,
                filters=MemoryFilters(),
                cursor=cursor,
                limit=2,
            )
            found.update(item.revision.memory_id for item in page.items)
            if not page.has_more:
                return found
            cursor = page.next_cursor


def test_both_source_readers_answer_one_query_with_one_hit_set(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the owner's browser search answering less than the MCP ladder."""
    # Sets, not sequences: the two readers page through differently and may
    # order a rank tie differently. What may not differ is what they can find.
    clock = FakeClock()
    _seed_differential_sources(synthetic_store, clock)
    for query in _DIFFERENTIAL_QUERIES:
        kernel = {
            hit.source.source_id
            for hit in search_sources(synthetic_store, query, limit=100).items
        }
        assert kernel, query
        assert _owner_source_hits(synthetic_store, query) == kernel, query


def test_both_memory_readers_answer_one_query_with_one_hit_set(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the owner's browser memory search answering less than the ladder."""
    clock = FakeClock()
    _seed_differential_memories(synthetic_store, clock)
    for query in _DIFFERENTIAL_QUERIES:
        kernel = {
            hit.memory.memory_id
            for hit in search_memories(synthetic_store, query, limit=100).items
        }
        assert kernel, query
        assert _owner_memory_hits(synthetic_store, query) == kernel, query


def test_owner_memory_search_scores_each_head_once_per_filtered_and_unfiltered_page(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch either owner banner count repeating matcher setup or corpus scoring."""
    statements = (
        "Amber studio opens on Tuesday.",
        "Amber workshop closes on Wednesday.",
        "琥珀工作室周四开放。",
        "Cobalt gallery remains quiet.",
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="owner-search-scoring.txt",
        body="\n".join(statements) + "\n",
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    apply_ready(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            tuple(
                single_item_edit(
                    item_id=f"itm_owner_search_scoring_{index}",
                    source=source,
                    statement=statement,
                    excerpt=statement,
                    kind=MemoryKind.EVENT if index == 1 else MemoryKind.FACT,
                    tags=("synthetic", "visible" if index != 1 else "private"),
                    sensitivity=(
                        Sensitivity.RESTRICTED if index == 1 else Sensitivity.NORMAL
                    ),
                )
                for index, statement in enumerate(statements)
            ),
        ),
    )
    query = "amber 开放"
    assert [
        (hit.memory.statement, hit.match_strength)
        for hit in search_memories(synthetic_store, query, limit=10).items
    ] == [
        (statements[0], MatchStrength.ANY_TERM),
        (statements[1], MatchStrength.ANY_TERM),
        (statements[2], MatchStrength.ANY_TERM),
    ]

    original_compile = retrieval_module._compile_literal_query
    compile_calls = 0

    def measured_compile(
        raw_query: str,
    ) -> retrieval_module._CompiledLiteralQuery:
        nonlocal compile_calls
        compile_calls += 1
        return original_compile(raw_query)

    monkeypatch.setattr(memories_module, "_compile_literal_query", measured_compile)
    filters = MemoryFilters(sensitivities=(Sensitivity.NORMAL,))
    observed_scans: list[int] = []
    with _read_connection(synthetic_store) as (connection, identity):
        connection.execute("BEGIN")

        filtered_first, work = _measure_matched_block_work(
            partial(
                owner_memory_search_page,
                connection,
                identity,
                query=query,
                filters=filters,
                cursor=None,
                limit=1,
            )
        )
        observed_scans.append(work.scan_calls)
        assert filtered_first.next_cursor is not None
        filtered_next, work = _measure_matched_block_work(
            partial(
                owner_memory_search_page,
                connection,
                identity,
                query=query,
                filters=filters,
                cursor=filtered_first.next_cursor,
                limit=1,
            )
        )
        observed_scans.append(work.scan_calls)

        unfiltered_first, work = _measure_matched_block_work(
            partial(
                owner_memory_search_page,
                connection,
                identity,
                query=query,
                filters=MemoryFilters(),
                cursor=None,
                limit=2,
            )
        )
        observed_scans.append(work.scan_calls)
        assert unfiltered_first.next_cursor is not None
        unfiltered_next, work = _measure_matched_block_work(
            partial(
                owner_memory_search_page,
                connection,
                identity,
                query=query,
                filters=MemoryFilters(),
                cursor=unfiltered_first.next_cursor,
                limit=2,
            )
        )
        observed_scans.append(work.scan_calls)

    assert [item.revision.statement for item in filtered_first.items] == [statements[0]]
    assert [item.revision.statement for item in filtered_next.items] == [statements[2]]
    assert filtered_next.next_cursor is None
    for page in (filtered_first, filtered_next):
        assert page.unfiltered_query_match_count == 3
        assert page.filtered_match_count == 2
        assert page.hidden_by_filters_count == 1
    assert [item.revision.statement for item in unfiltered_first.items] == list(
        statements[:2]
    )
    assert [item.revision.statement for item in unfiltered_next.items] == [
        statements[2]
    ]
    assert unfiltered_next.next_cursor is None
    for page in (unfiltered_first, unfiltered_next):
        assert page.unfiltered_query_match_count == 3
        assert page.filtered_match_count == 3
        assert page.hidden_by_filters_count == 0
    assert compile_calls == 4
    assert observed_scans == [4, 4, 4, 4]


def test_owner_source_search_reaches_a_chinese_mid_run_query(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the reported case: a query MCP answers returning nothing in browser."""
    clock = FakeClock()
    capture_text(
        synthetic_store,
        name="institute.md",
        body="研究所的开放时间是周二。\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    with _read_connection(synthetic_store) as (connection, identity):
        page = owner_search_sources(connection, identity, "开放", None, 10)
    assert [hit.source.original_name for hit in page.items] == ["institute.md"]
    assert "开放" in page.items[0].exact_excerpt


def test_owner_memory_search_reaches_the_any_term_rung(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the owner's memory search keeping AND-only recall the ladder dropped."""
    clock = FakeClock()
    _seed(synthetic_store, clock)
    assert _owner_memory_hits(synthetic_store, "amber studio") == {
        hit.memory.memory_id
        for hit in search_memories(synthetic_store, "amber studio", limit=100).items
    }


def test_owner_search_cursors_from_ladder_three_fail_closed(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch owner cursors resuming after projection fidelity changed search."""
    # The owner cursors bind `owner_filter_binding`, not the ladder snapshot, so
    # nothing else would notice that the order underneath them changed. The
    # ladder version joins that binding for exactly this reason.
    clock = FakeClock()
    _seed_differential_sources(synthetic_store, clock)
    _seed_differential_memories(synthetic_store, clock)
    with _read_connection(synthetic_store) as (connection, identity):
        sources = owner_search_sources(connection, identity, "amber studio", None, 1)
        memories = owner_memory_search_page(
            connection,
            identity,
            query="amber studio",
            filters=MemoryFilters(),
            cursor=None,
            limit=1,
        )
        assert sources.next_cursor is not None
        assert memories.next_cursor is not None
        source_payload = _decode_payload(sources.next_cursor)
        memory_payload = _decode_payload(memories.next_cursor)
        source_payload["binding"] = owner_filter_binding(
            {"query": "amber studio", "ladder": 3}
        )
        memory_payload["binding"] = owner_filter_binding(
            {
                "query": "amber studio",
                "filters": owner_filters_payload(MemoryFilters()),
                "ladder": 3,
            }
        )

        with pytest.raises(StaleCursorError):
            owner_search_sources(
                connection,
                identity,
                "amber studio",
                _encode_payload(source_payload),
                1,
            )
        with pytest.raises(StaleCursorError):
            owner_memory_search_page(
                connection,
                identity,
                query="amber studio",
                filters=MemoryFilters(),
                cursor=_encode_payload(memory_payload),
                limit=1,
            )
