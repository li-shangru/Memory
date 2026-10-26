"""Fresh synthetic timing and evidence reach, with no client acceptance claim.

This development harness uses the suite's in-memory keyring and internal test
approval helper solely to prepare canonical synthetic fixtures. It never calls
an installed client, a completion provider, or the OS approval adapters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field
from synthetic import (
    FakeClock,
    apply_ready,
    capture_batch,
    capture_text,
    make_synthetic_store,
    ready_items,
    single_item_edit,
)

import memory
from memory.errors import InvalidArgumentError
from memory.memories import get_memory, get_memory_facets, search_memories
from memory.model import (
    AddGuardLink,
    ChangeEdit,
    MemoryDetail,
    MemoryFilters,
    MemorySearchHit,
    MemorySearchPage,
    Page,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceSearchHit,
    SourceSearchPage,
    SourceSummary,
)
from memory.retrieval import LADDER_VERSION, read_source, search_sources
from memory.sources import get_store_status, list_sources

type JSON = str | int | float | bool | list[JSON] | dict[str, JSON] | None
type Stats = dict[str, int | bool | str]
type Language = Literal["en", "zh"]
type Profile = Literal["smoke", "baseline", "matrix", "quality"]

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "tests" / "fixtures" / "synthetic_retrieval" / "manifest.json"


class FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Template(FixtureModel):
    query: str
    no_hit_query: str
    heading: str
    statement: str
    filler: str = Field(min_length=1)


class TimingCase(FixtureModel):
    label: str = Field(pattern=r"^SYN-[A-Z0-9-]{1,64}$")
    profiles: list[Profile]
    language: Language
    source_count: int = Field(ge=2, le=64)
    bytes_per_source: int = Field(ge=1024, le=524288)
    memory_count: int = Field(ge=0, le=2400)
    statement_bytes: int = Field(ge=64, le=1024)


class SourceFixture(FixtureModel):
    label: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    phase: int = Field(default=0, ge=0, le=1)
    prefix: str
    repeat: str = ""
    repeat_count: int = Field(default=0, ge=0, le=256)
    filler: str = " "
    target_bytes: int | None = Field(default=None, ge=1024, le=524288)
    tail: str = ""


class MemoryFixture(FixtureModel):
    label: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    phase: int = Field(default=0, ge=0, le=1)
    source: str
    statement: str
    excerpt: str
    tags: tuple[str, ...]
    corrects: str | None = None


class GuardFixture(FixtureModel):
    guard: str
    governed: str


class Requirement(FixtureModel):
    source: str
    excerpt: str


class QualityCase(FixtureModel):
    label: str = Field(pattern=r"^SYN-[A-Z0-9-]{1,64}$")
    language: Language
    conditions: list[str]
    query: str
    sources: list[SourceFixture] = Field(min_length=1, max_length=8)
    memories: list[MemoryFixture] = Field(max_length=16)
    guards: list[GuardFixture] = Field(default_factory=list, max_length=8)
    required_guards: list[str] = Field(default_factory=list)
    required_current_memories: list[str] = Field(default_factory=list)
    requirements: list[Requirement] = Field(min_length=1, max_length=16)


class Manifest(FixtureModel):
    format: Literal["memory.synthetic-retrieval-benchmark.v1"]
    authored_on: str
    templates: dict[Language, Template]
    timing: list[TimingCase] = Field(max_length=16)
    quality: list[QualityCase] = Field(max_length=8)


@dataclass
class AdviceRead:
    stats: Stats
    source_texts: dict[str, str]
    memory_hits: tuple[MemorySearchHit, ...]
    source_hits: tuple[SourceSearchHit, ...]
    details: tuple[MemoryDetail, ...]


@contextmanager
def synthetic_store() -> Iterator[RuntimePaths]:
    with tempfile.TemporaryDirectory(prefix="memory-synthetic-retrieval-") as root:
        # Resolve macOS's /var symlink before the runtime's no-symlinks check.
        private_root = Path(root).resolve()
        private_root.chmod(0o700)
        with pytest.MonkeyPatch.context() as patch:
            yield from make_synthetic_store(private_root, patch)


def padded_text(prefix: str, size: int, filler: str) -> str:
    """Author an exact UTF-8 byte count without splitting a code point."""
    remaining = size - len(prefix.encode("utf-8"))
    if remaining < 0 or not filler:
        raise ValueError("synthetic fixture does not fit its declared size")
    encoded = filler.encode("utf-8")
    repeated, remainder = divmod(remaining, len(encoded))
    partial = encoded[:remainder].decode("utf-8", errors="ignore")
    padding = " " * (remainder - len(partial.encode("utf-8")))
    return prefix + filler * repeated + partial + padding


def source_body(source: SourceFixture) -> str:
    body = source.prefix + source.repeat * source.repeat_count
    if source.target_bytes is not None:
        body = padded_text(
            body,
            source.target_bytes - len(source.tail.encode("utf-8")),
            source.filler,
        )
    body += source.tail
    if len(body.encode("utf-8")) > 524288:
        raise ValueError("synthetic quality source exceeds its work bound")
    return body


def seed_timing(paths: RuntimePaths, case: TimingCase, template: Template) -> None:
    clock = FakeClock()
    per_source = (case.memory_count + case.source_count - 1) // case.source_count
    if per_source > 240:
        raise ValueError("synthetic memory batch exceeds its work bound")
    for source_index in range(case.source_count):
        statements: list[tuple[int, str]] = []
        for index in range(
            source_index * per_source,
            min((source_index + 1) * per_source, case.memory_count),
        ):
            topic = template.query if index < 2 else template.heading
            prefix = f"{template.statement} {index:05d}: {topic}. "
            statements.append(
                (index, padded_text(prefix, case.statement_bytes, template.filler))
            )
        prefix = f"{template.heading} {source_index:03d}: {template.query}.\n"
        prefix += "\n".join(statement for _, statement in statements) + "\n"
        body = padded_text(prefix, case.bytes_per_source, template.filler)
        batch_id, source = capture_text(
            paths,
            name=f"synthetic-scale-{source_index:03d}.txt",
            body=body,
            sensitivity=Sensitivity.NORMAL,
            clock=clock,
        )
        if not statements:
            continue
        edits: list[ChangeEdit] = []
        for index, statement in statements:
            tags: tuple[str, ...] = ("synthetic",)
            if index < 2:
                tags += ("standing",)
            elif index < 4:
                tags += ("loop:open",)
            edits.append(
                single_item_edit(
                    item_id=f"synthetic_scale_{index:05d}",
                    source=source,
                    statement=statement,
                    excerpt=statement,
                    tags=tags,
                )
            )
        # Automated test setup only, never owner presence or acceptance evidence.
        apply_ready(paths, ready_items(paths, batch_id, edits))


def seed_quality(
    paths: RuntimePaths, case: QualityCase
) -> tuple[dict[str, SourceSummary], dict[str, str], set[str]]:
    from memory.model import GuardLinkInput

    clock = FakeClock()
    sources: dict[str, SourceSummary] = {}
    memories: dict[str, str] = {}
    superseded: set[str] = set()
    for phase in sorted({source.phase for source in case.sources}):
        source_specs = [source for source in case.sources if source.phase == phase]
        files = {
            f"synthetic-{source.label}.txt": source_body(source)
            for source in source_specs
        }
        batch_id, captured = capture_batch(
            paths, files, sensitivity=Sensitivity.NORMAL, clock=clock
        )
        for source in source_specs:
            sources[source.label] = captured[f"synthetic-{source.label}.txt"]
        current = [item for item in case.memories if item.phase == phase]
        edits: list[ChangeEdit] = []
        for item in current:
            lineage = head = None
            if item.corrects is not None:
                predecessor = get_memory(paths, memories[item.corrects])
                lineage = predecessor.revision.lineage_id
                head = predecessor.current_head_id
                superseded.add(head)
            edits.append(
                single_item_edit(
                    item_id=item.label,
                    source=sources[item.source],
                    statement=item.statement,
                    excerpt=item.excerpt,
                    tags=item.tags,
                    target_lineage_id=lineage,
                    expected_head_id=head,
                )
            )
        used = {item.source for item in current}
        for source in source_specs:
            if source.label not in used:
                edits.append(
                    SetSourceNoMemory(
                        source_id=sources[source.label].source_id,
                        reason="Synthetic source retained for retrieval evaluation only.",
                    )
                )
        current_labels = {item.label for item in current}
        for guard in case.guards:
            if {guard.guard, guard.governed} <= current_labels:
                edits.append(
                    AddGuardLink(
                        link=GuardLinkInput(
                            guard_item_id=guard.guard,
                            guard_lineage_id=None,
                            governed_item_id=guard.governed,
                            governed_lineage_id=None,
                        )
                    )
                )
        applied = apply_ready(paths, ready_items(paths, batch_id, edits))
        if len(applied.memory_ids) != len(current):
            raise AssertionError("synthetic seed did not create every memory")
        memories.update(
            (item.label, memory_id)
            for item, memory_id in zip(current, applied.memory_ids, strict=True)
        )
    return sources, memories, superseded


def memory_walk(
    paths: RuntimePaths,
    query: str | None = None,
    filters: MemoryFilters = MemoryFilters(),
) -> tuple[tuple[MemorySearchHit, ...], int]:
    hits: list[MemorySearchHit] = []
    cursor = None
    calls = 0
    while True:
        page = search_memories(paths, query, filters, cursor, limit=50)
        calls += 1
        hits.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return tuple(hits), calls


def advice_read(paths: RuntimePaths, query: str) -> AdviceRead:
    """Execute one conservative complete retrieval sequence; perform no advice."""
    status = get_store_status(paths)
    get_memory_facets(paths)
    calls = 2
    standing, used = memory_walk(paths, filters=MemoryFilters(tags_all=("standing",)))
    calls += used
    loops, used = memory_walk(paths, filters=MemoryFilters(tags_all=("loop:open",)))
    calls += used
    memories, used = memory_walk(paths, query)
    calls += used
    source_hits: list[SourceSearchHit] = []
    cursor = None
    while True:
        source_page = search_sources(paths, query, cursor, limit=50)
        calls += 1
        source_hits.extend(source_page.items)
        cursor = source_page.next_cursor
        if cursor is None:
            break
    all_memories = standing + loops + memories
    detail_ids = dict.fromkeys(
        memory_id
        for hit in all_memories
        for memory_id in (
            hit.memory.memory_id,
            *(guard.memory_id for guard in hit.guards),
        )
    )
    details = tuple(get_memory(paths, memory_id) for memory_id in detail_ids)
    calls += len(details)
    sources: list[SourceSummary] = []
    cursor = None
    while True:
        listing = list_sources(paths, cursor, limit=50)
        calls += 1
        sources.extend(listing.items)
        cursor = listing.next_cursor
        if cursor is None:
            break
    texts: dict[str, str] = {}
    bytes_read = chunks = 0
    for source in sources:
        cursor = None
        parts: list[str] = []
        source_bytes = 0
        while True:
            chunk = read_source(paths, source.source_id, cursor, max_bytes=262144)
            calls += 1
            chunks += 1
            if chunk.text is None or chunk.byte_start != source_bytes:
                raise AssertionError("synthetic full-source walk is incomplete")
            parts.append(chunk.text)
            source_bytes = chunk.byte_end
            cursor = chunk.next_cursor
            if cursor is None:
                if not chunk.complete or source_bytes != source.byte_length:
                    raise AssertionError("synthetic source walk ended early")
                break
        text = "".join(parts)
        if len(text.encode("utf-8")) != source.byte_length:
            raise AssertionError("synthetic UTF-8 reconstruction differs in length")
        texts[source.source_id] = text
        bytes_read += source_bytes
    if len(sources) != status.source_count:
        raise AssertionError("synthetic source enumeration omitted a capture")
    return AdviceRead(
        stats={
            "calls": calls,
            "standing_heads": len(standing),
            "open_loop_heads": len(loops),
            "query_memory_heads": len(memories),
            "query_source_hits": len(source_hits),
            "memory_details_read": len(details),
            "sources_read": len(sources),
            "source_read_chunks": chunks,
            "source_bytes_read": bytes_read,
        },
        source_texts=texts,
        memory_hits=memories,
        source_hits=tuple(source_hits),
        details=details,
    )


def measure[T](
    operation: str,
    callback: Callable[[], T],
    summarize: Callable[[T], Stats],
    repetitions: int,
) -> tuple[T, dict[str, JSON]]:
    walls: list[float] = []
    cpus: list[float] = []
    expected: Stats | None = None
    for _ in range(repetitions):
        wall = time.perf_counter()
        cpu = time.process_time()
        result = callback()
        cpus.append((time.process_time() - cpu) * 1000)
        walls.append((time.perf_counter() - wall) * 1000)
        summary = summarize(result)
        if expected is not None and expected != summary:
            raise AssertionError("synthetic repeated retrieval changed its counts")
        expected = summary
    record: dict[str, JSON] = {
        "operation": operation,
        "samples": repetitions,
        "wall_ms": round(statistics.median(walls), 3),
        "cpu_ms": round(statistics.median(cpus), 3),
        "wall_samples_ms": [round(value, 3) for value in walls],
        "cpu_samples_ms": [round(value, 3) for value in cpus],
    }
    if expected is None:
        raise ValueError("repetitions must be positive")
    record.update(expected)
    return result, record


def page_stats(
    page: SourceSearchPage | MemorySearchPage | Page[SourceSummary],
) -> Stats:
    return {"items": len(page.items), "has_more": page.has_more}


def run_timing(
    case: TimingCase, template: Template, repetitions: int
) -> dict[str, JSON]:
    with synthetic_store() as paths:
        seed_timing(paths, case, template)
        operations: list[JSON] = []

        def record[T](
            operation: str, callback: Callable[[], T], summarize: Callable[[T], Stats]
        ) -> T:
            result, observation = measure(operation, callback, summarize, repetitions)
            operations.append(observation)
            return result

        first_source = record(
            "source.match.first",
            lambda: search_sources(paths, template.query, limit=1),
            page_stats,
        )
        if first_source.next_cursor is not None:
            record(
                "source.match.continued",
                lambda: search_sources(
                    paths, template.query, first_source.next_cursor, 1
                ),
                page_stats,
            )
        record(
            "source.no_hits.first",
            lambda: search_sources(paths, template.no_hit_query, limit=1),
            page_stats,
        )
        listing = record(
            "source.enumerate.first", lambda: list_sources(paths, limit=1), page_stats
        )
        record(
            "source.enumerate.continued",
            lambda: list_sources(paths, listing.next_cursor, limit=1),
            page_stats,
        )
        first_memory = record(
            "memory.match.first",
            lambda: search_memories(paths, template.query, limit=1),
            page_stats,
        )
        if first_memory.next_cursor is not None:
            record(
                "memory.match.continued",
                lambda: search_memories(
                    paths, template.query, cursor=first_memory.next_cursor, limit=1
                ),
                page_stats,
            )
        record(
            "memory.no_hits.first",
            lambda: search_memories(paths, template.no_hit_query, limit=1),
            page_stats,
        )
        enumeration = record(
            "memory.enumerate.first",
            lambda: search_memories(paths, limit=1),
            page_stats,
        )
        if enumeration.next_cursor is not None:
            record(
                "memory.enumerate.continued",
                lambda: search_memories(paths, cursor=enumeration.next_cursor, limit=1),
                page_stats,
            )
        for tag, label in (("standing", "standing"), ("loop:open", "open_loops")):
            record(
                f"memory.{label}.complete",
                partial(memory_walk, paths, filters=MemoryFilters(tags_all=(tag,))),
                lambda result: {"items": len(result[0]), "calls": result[1]},
            )
        record(
            "advice.complete",
            lambda: advice_read(paths, template.query),
            lambda x: x.stats,
        )

        def empty_query() -> str:
            try:
                search_sources(paths, "", limit=1)
            except InvalidArgumentError:
                return "invalid_argument"
            raise AssertionError("source search accepted an empty string")

        record("source.empty_string", empty_query, lambda outcome: {"outcome": outcome})
        status = get_store_status(paths)
        return {
            "label": case.label,
            "language": case.language,
            "source_count": status.source_count,
            "source_bytes": case.source_count * case.bytes_per_source,
            "bytes_per_source": case.bytes_per_source,
            "current_memory_count": status.memory_count,
            "statement_bytes": case.statement_bytes if case.memory_count else 0,
            "operations": operations,
        }


def run_quality(case: QualityCase) -> dict[str, JSON]:
    with synthetic_store() as paths:
        sources, memories, superseded = seed_quality(paths, case)
        first_source = search_sources(paths, case.query, limit=1)
        first_memory = search_memories(paths, case.query, limit=1)
        wall = time.perf_counter()
        cpu = time.process_time()
        read = advice_read(paths, case.query)
        cpu_ms = (time.process_time() - cpu) * 1000
        wall_ms = (time.perf_counter() - wall) * 1000
        source_names = {source.source_id: label for label, source in sources.items()}
        required_sources = {requirement.source for requirement in case.requirements}
        query_memory_ids = {hit.memory.memory_id for hit in read.memory_hits}
        delivered_guards = {
            guard.memory_id for hit in first_memory.items for guard in hit.guards
        }
        statements = [
            statement
            for hit in first_memory.items
            for statement in (
                hit.memory.statement,
                *(guard.statement for guard in hit.guards),
            )
        ]
        return {
            "label": case.label,
            "language": case.language,
            "conditions": list(case.conditions),
            "source_count": len(sources),
            "requirement_count": len(case.requirements),
            "first_source_excerpt_requirement_hits": sum(
                requirement.excerpt in hit.exact_excerpt
                and sources[requirement.source].source_id == hit.source.source_id
                for requirement in case.requirements
                for hit in first_source.items
            ),
            "first_memory_statement_requirement_hits": sum(
                any(requirement.excerpt in statement for statement in statements)
                for requirement in case.requirements
            ),
            "ranked_source_hits": len(read.source_hits),
            "ranked_memory_hits": len(read.memory_hits),
            "required_source_ranks": [
                {"label": source_names[hit.source.source_id], "rank": rank}
                for rank, hit in enumerate(read.source_hits, 1)
                if source_names[hit.source.source_id] in required_sources
            ],
            "full_read_requirement_hits": sum(
                requirement.excerpt
                in read.source_texts[sources[requirement.source].source_id]
                for requirement in case.requirements
            ),
            "full_read_sources": len(read.source_texts),
            "required_guard_count": len(case.required_guards),
            "required_guards_delivered": sum(
                memories[label] in delivered_guards for label in case.required_guards
            ),
            "required_current_heads_delivered": sum(
                memories[label] in query_memory_ids
                for label in case.required_current_memories
            ),
            "search_returned_only_current_heads": all(
                detail.is_current for detail in read.details
            ),
            "superseded_heads_returned": len(query_memory_ids & superseded),
            "advice_sequence": dict(read.stats),
            "wall_ms": round(wall_ms, 3),
            "cpu_ms": round(cpu_ms, 3),
        }


def implementation_digest() -> str:
    root = Path(memory.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def repetition_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "repetitions must be between 1 and 7"
        ) from error
    if not 1 <= count <= 7:
        raise argparse.ArgumentTypeError("repetitions must be between 1 and 7")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=("smoke", "baseline", "matrix", "quality"),
        default="matrix",
    )
    parser.add_argument("--repetitions", type=repetition_count, default=3)
    parser.add_argument(
        "--label", choices=("before", "after", "recheck"), default="recheck"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw_manifest = MANIFEST.read_bytes()
    manifest = Manifest.model_validate_json(raw_manifest)
    timing: list[JSON] = []
    quality: list[JSON] = []
    for case in manifest.timing:
        if args.profile in case.profiles:
            print(f"Measuring {case.label}", file=sys.stderr, flush=True)
            timing.append(
                run_timing(case, manifest.templates[case.language], args.repetitions)
            )
    if args.profile in ("matrix", "quality"):
        for quality_case in manifest.quality:
            print(f"Reading {quality_case.label}", file=sys.stderr, flush=True)
            quality.append(run_quality(quality_case))
    result: dict[str, JSON] = {
        "format": "memory.synthetic-retrieval-report.v1",
        "label": args.label,
        "profile": args.profile,
        "acceptance_claim": "automated_synthetic_retrieval_only",
        "method": "Fresh disposable Stores; in-memory keyring; automated canonical fixture setup; direct kernel calls; capture excluded; repeated sequential calls without separate warmup; no MCP serialization or model inference.",
        "repository_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip(),
        "implementation_digest": implementation_digest(),
        "harness_digest": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "manifest_digest": hashlib.sha256(raw_manifest).hexdigest(),
        "ladder_version": LADDER_VERSION,
        "python": platform.python_version(),
        "system": platform.system(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count(),
        "repetitions": args.repetitions,
        "page_limit": 1,
        "advice_page_limit": 50,
        "read_chunk_bytes": 262144,
        "timing": timing,
        "quality": quality,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(
        f"Completed {len(timing)} timing scenarios and {len(quality)} evidence cases."
    )
    return 0
