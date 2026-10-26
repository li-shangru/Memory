"""Fresh synthetic evidence discovery, separate from client reasoning acceptance.

The experiment never invokes an installed client or completion provider. Its
canonical fixtures use the test suite's disposable SQLCipher runtime and internal
approval fake; no OS approval or owner-presence claim follows from this setup.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import statistics
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import Literal, Self, cast

import keyring
import pytest
from pydantic import BaseModel, ConfigDict, Field, model_validator
from retrieval_benchmark import QualityCase, padded_text, seed_quality, source_body
from synthetic import FakeClock, capture_batch, capture_text, make_synthetic_store

import memory
from memory import retrieval
from memory.memories import get_memories, search_memories
from memory.model import (
    MemorySearchHit,
    RuntimePaths,
    Sensitivity,
    SourceSearchHit,
    SourceSummary,
)
from memory.retrieval import read_source, search_sources
from memory.sources import get_store_status, list_sources

type JSON = str | int | float | bool | list[JSON] | dict[str, JSON] | None

REPO = Path(__file__).resolve().parents[1]
MANIFEST = (
    REPO / "tests" / "fixtures" / "synthetic_retrieval_discovery" / "manifest.json"
)


class AdditionalCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    copy_of: str | None = None
    text: str | None = Field(default=None, max_length=65536)
    suffix: Literal["txt", "bin"]
    sensitivity: Sensitivity

    @model_validator(mode="after")
    def one_body(self) -> Self:
        if (self.copy_of is None) == (self.text is None):
            raise ValueError("synthetic capture must name exactly one body")
        return self


class DiscoveryCase(QualityCase):
    additional_captures: list[AdditionalCapture] = Field(
        default_factory=list, max_length=8
    )
    expected_answerability: Literal["answerable", "unanswerable"]

    @model_validator(mode="after")
    def known_unique_captures(self) -> Self:
        original = {source.label for source in self.sources}
        additional = {source.label for source in self.additional_captures}
        if len(original) != len(self.sources) or len(additional) != len(
            self.additional_captures
        ):
            raise ValueError("synthetic capture labels must be unique")
        if original & additional:
            raise ValueError("additional capture must have a fresh label")
        if any(
            source.copy_of is not None and source.copy_of not in original
            for source in self.additional_captures
        ):
            raise ValueError("synthetic duplicate must name an original source")
        return self


class CorpusShape(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: Literal["compact", "short_noise", "long_sources"]
    minimum_source_bytes: int = Field(ge=0, le=196608)
    noise_source_count: int = Field(ge=0, le=16)
    noise_source_bytes: int = Field(ge=64, le=1024)
    neutral_filler: dict[Literal["en", "zh"], str]


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["memory.synthetic-discovery-fixtures.v1"]
    authored_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    cases: list[DiscoveryCase] = Field(min_length=1, max_length=16)
    shapes: list[CorpusShape] = Field(min_length=1, max_length=3)


def shaped_case(case: DiscoveryCase, shape: CorpusShape) -> DiscoveryCase:
    if not shape.minimum_source_bytes:
        return case
    return case.model_copy(
        update={
            "sources": [
                source.model_copy(
                    update={
                        "target_bytes": max(
                            len(source_body(source).encode("utf-8")),
                            shape.minimum_source_bytes,
                        ),
                        "filler": shape.neutral_filler[case.language],
                    }
                )
                for source in case.sources
            ]
        }
    )


@contextmanager
def fresh_store() -> Iterator[RuntimePaths]:
    with tempfile.TemporaryDirectory(prefix="memory-v111-discovery-synthetic-") as root:
        disposable = Path(root).resolve()
        disposable.chmod(0o700)
        with pytest.MonkeyPatch.context() as patch:
            # The shared fixture stubs get/set. Complete the boundary even though
            # this experiment never requests key deletion.
            patch.setattr(keyring, "delete_password", lambda *_arguments: None)
            yield from make_synthetic_store(disposable, patch)


def json_default(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(type(value).__name__)


@dataclasses.dataclass
class Measurement:
    calls: int = 0
    returned_kernel_json_bytes: int = 0
    kernel_wall_ms: float = 0.0
    kernel_cpu_ms: float = 0.0

    def call[T](self, operation: Callable[[], T]) -> T:
        started_wall = time.perf_counter()
        started_cpu = time.process_time()
        result = operation()
        self.kernel_cpu_ms += (time.process_time() - started_cpu) * 1000
        self.kernel_wall_ms += (time.perf_counter() - started_wall) * 1000
        self.calls += 1
        self.returned_kernel_json_bytes += len(
            json.dumps(
                result,
                default=json_default,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        return result

    def summary(self) -> dict[str, JSON]:
        return {
            "calls": self.calls,
            "returned_kernel_json_bytes": self.returned_kernel_json_bytes,
            "kernel_wall_ms": round(self.kernel_wall_ms, 3),
            "kernel_cpu_ms": round(self.kernel_cpu_ms, 3),
        }


def walk_memories(
    paths: RuntimePaths, measurement: Measurement, query: str | None
) -> tuple[MemorySearchHit, ...]:
    hits: list[MemorySearchHit] = []
    cursor = None
    while True:
        page = measurement.call(
            partial(search_memories, paths, query, cursor=cursor, limit=2)
        )
        hits.extend(page.items)
        if page.next_cursor is None:
            return tuple(hits)
        cursor = page.next_cursor


def walk_sources(
    paths: RuntimePaths, measurement: Measurement, query: str
) -> tuple[SourceSearchHit, ...]:
    hits: list[SourceSearchHit] = []
    cursor = None
    while True:
        page = measurement.call(partial(search_sources, paths, query, cursor, limit=2))
        hits.extend(page.items)
        if page.next_cursor is None:
            return tuple(hits)
        cursor = page.next_cursor


def requirement_hits(case: QualityCase, returned: list[str]) -> int:
    return sum(
        any(item.excerpt in text for text in returned) for item in case.requirements
    )


def hit_texts(hits: tuple[MemorySearchHit, ...]) -> list[str]:
    return [
        statement
        for hit in hits
        for statement in (
            hit.memory.statement,
            *(guard.statement for guard in hit.guards),
        )
    ]


def read_complete(
    paths: RuntimePaths,
    source: SourceSummary,
    measurement: Measurement,
) -> tuple[str | None, int, int]:
    cursor = None
    parts: list[str] = []
    binary_parts: list[bytes] = []
    byte_end = 0
    chunks = 0
    while True:
        chunk = measurement.call(
            partial(read_source, paths, source.source_id, cursor, max_bytes=4096)
        )
        assert chunk.byte_start == byte_end
        byte_end = chunk.byte_end
        chunks += 1
        if chunk.text is not None:
            parts.append(chunk.text)
        else:
            assert chunk.binary is not None
            binary_parts.append(chunk.binary)
        if chunk.next_cursor is None:
            assert chunk.complete
            break
        cursor = chunk.next_cursor
    reconstructed = "".join(parts).encode("utf-8") if parts else b"".join(binary_parts)
    assert byte_end == source.byte_length == len(reconstructed)
    assert hashlib.sha256(reconstructed).hexdigest() == source.blob_digest
    return ("".join(parts) if parts else None), byte_end, chunks


def ranking_summary(
    case: QualityCase,
    sources: dict[str, SourceSummary],
    memories: dict[str, str],
    source_hits: tuple[SourceSearchHit, ...],
    memory_hits: tuple[MemorySearchHit, ...],
) -> dict[str, JSON]:
    source_labels = {source.source_id: label for label, source in sources.items()}
    memory_labels = {identifier: label for label, identifier in memories.items()}
    return {
        "source_order": [source_labels[hit.source.source_id] for hit in source_hits],
        "source_rungs": [hit.match_strength.value for hit in source_hits],
        "source_scores": [hit.rank for hit in source_hits],
        "memory_order": [memory_labels[hit.memory.memory_id] for hit in memory_hits],
        "memory_rungs": [hit.match_strength.value for hit in memory_hits],
        "first_source_preview_requirement_hits": requirement_hits(
            case, [hit.exact_excerpt for hit in source_hits[:1]]
        ),
        "first_memory_plus_guards_requirement_hits": requirement_hits(
            case, hit_texts(memory_hits[:1])
        ),
    }


def run_case(original: DiscoveryCase, shape: CorpusShape) -> dict[str, JSON]:
    case = shaped_case(original, shape)
    with fresh_store() as paths:
        sources, memories, superseded = seed_quality(paths, case)
        originals = {source.label: source_body(source) for source in case.sources}
        for extra in case.additional_captures:
            text = originals[extra.copy_of] if extra.copy_of is not None else extra.text
            assert text is not None
            _, captured = capture_text(
                paths,
                name=f"synthetic-{extra.label}.{extra.suffix}",
                body=text,
                sensitivity=extra.sensitivity,
                clock=FakeClock(),
            )
            sources[extra.label] = captured
        if shape.noise_source_count:
            noise_files = {
                f"synthetic-noise-{index:02d}.txt": padded_text(
                    f"{index:02d}\n",
                    shape.noise_source_bytes,
                    shape.neutral_filler[case.language],
                )
                for index in range(shape.noise_source_count)
            }
            _, noise = capture_batch(
                paths, noise_files, sensitivity=Sensitivity.NORMAL, clock=FakeClock()
            )
            sources.update(
                (f"noise_{index:02d}", noise[f"synthetic-noise-{index:02d}.txt"])
                for index in range(shape.noise_source_count)
            )

        status = get_store_status(paths)
        literal_measurement = Measurement()
        source_hits = walk_sources(paths, literal_measurement, case.query)
        memory_hits = walk_memories(paths, literal_measurement, case.query)
        ranked = ranking_summary(case, sources, memories, source_hits, memory_hits)

        # This is a real current-head enumeration and bounded batched get using
        # existing kernel operations. Its selection is exhaustive, not an oracle
        # that knows which fixture statement is required.
        discovery_measurement = Measurement()
        all_heads = walk_memories(paths, discovery_measurement, None)
        detail_ids = tuple(
            dict.fromkeys(
                identifier
                for hit in all_heads
                for identifier in (
                    hit.memory.memory_id,
                    *(guard.memory_id for guard in hit.guards),
                )
            )
        )
        details = (
            discovery_measurement.call(lambda: get_memories(paths, detail_ids))
            if detail_ids
            else ()
        )
        details_text = [
            excerpt
            for detail in details
            for excerpt in (
                detail.revision.statement,
                *(evidence.excerpt or "" for evidence in detail.evidence),
                *(guard.statement for guard in detail.guards),
            )
        ]
        compact = {
            **discovery_measurement.summary(),
            "requirement_hits": requirement_hits(case, details_text),
            "current_heads": len(all_heads),
            "all_details_current": all(detail.is_current for detail in details),
        }

        # Full fallback follows every list/read cursor, including the binary
        # source. Byte reconstruction attests custody, not binary interpretation.
        listing: list[SourceSummary] = []
        cursor = None
        while True:
            page = discovery_measurement.call(
                partial(list_sources, paths, cursor, limit=2)
            )
            listing.extend(page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        evidence_ids = list(
            dict.fromkeys(
                evidence.source_id for detail in details for evidence in detail.evidence
            )
        )
        priority = {identifier: index for index, identifier in enumerate(evidence_ids)}
        listing.sort(key=lambda source: priority.get(source.source_id, len(priority)))
        returned_text: list[str] = []
        source_bytes = binary_bytes = chunks = 0
        for source in listing:
            text, used_bytes, used_chunks = read_complete(
                paths, source, discovery_measurement
            )
            source_bytes += used_bytes
            chunks += used_chunks
            if text is not None:
                returned_text.append(text)
            else:
                binary_bytes += used_bytes
        complete = {
            **discovery_measurement.summary(),
            "requirement_hits": requirement_hits(case, returned_text),
            "sources_read": len(listing),
            "source_bytes": source_bytes,
            "binary_bytes_read_without_interpretation": binary_bytes,
            "read_chunks": chunks,
            "all_custody_bytes_reconstructed": True,
            "unresolved_binary_sources": sum(
                not source.searchable for source in listing
            ),
        }

        ranked_ids = {hit.memory.memory_id for hit in memory_hits}
        guards = {guard.memory_id for hit in memory_hits for guard in hit.guards}
        return {
            "label": case.label,
            "language": case.language,
            "condition": case.conditions[0],
            "shape": shape.label,
            "required_fragment_count": len(case.requirements),
            "source_count": status.source_count,
            "searchable_sources": status.searchable_count,
            "unsearchable_sources": status.unsearchable_count,
            "literal_search": {**literal_measurement.summary(), **ranked},
            "queryless_current_head_discovery": compact,
            "complete_evidence_discovery": complete,
            "superseded_heads_returned": len(ranked_ids & superseded),
            "required_guards_delivered": sum(
                memories[label] in guards for label in case.required_guards
            ),
            "restricted_claim_returned": any(
                hit.memory.effective_sensitivity is Sensitivity.RESTRICTED
                for hit in memory_hits
            ),
            "expected_answerability": case.expected_answerability,
            "model_answer_evaluated": False,
        }


def source_digest() -> str:
    digest = hashlib.sha256()
    for name in ("retrieval.py", "memories.py", "sources.py", "model.py"):
        digest.update(name.encode())
        digest.update((Path(memory.__file__).resolve().parent / name).read_bytes())
    return digest.hexdigest()


def _record(value: JSON) -> dict[str, JSON]:
    if not isinstance(value, dict):
        raise AssertionError("synthetic measurement is not a record")
    return value


def aggregate(samples: list[dict[str, JSON]]) -> dict[str, JSON]:
    """Keep paired outcome/cost identity and summarize only noisy clock samples."""
    result = dict(samples[0])
    operations = (
        "literal_search",
        "queryless_current_head_discovery",
        "complete_evidence_discovery",
    )
    for sample in samples[1:]:
        if {key: value for key, value in sample.items() if key not in operations} != {
            key: value for key, value in result.items() if key not in operations
        }:
            raise AssertionError("synthetic repetitions changed their outcomes")
    for operation in operations:
        measurements = [_record(sample[operation]) for sample in samples]
        first = measurements[0]
        clocks = ("kernel_wall_ms", "kernel_cpu_ms")
        stable = {key: value for key, value in first.items() if key not in clocks}
        if any(
            {key: value for key, value in measured.items() if key not in clocks}
            != stable
            for measured in measurements[1:]
        ):
            raise AssertionError("synthetic repetitions changed their costs or reach")
        merged = dict(first)
        for clock in clocks:
            values: list[float] = []
            for measured in measurements:
                value = measured[clock]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise AssertionError("synthetic clock sample is not numeric")
                values.append(float(value))
            merged[clock] = round(statistics.median(values), 3)
            merged[clock.replace("_ms", "_samples_ms")] = cast(list[JSON], values)
        result[operation] = merged
    return result


def repetitions(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 3:
        raise argparse.ArgumentTypeError("repetitions must be between 1 and 3")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=repetitions, default=3)
    arguments = parser.parse_args()
    manifest_bytes = MANIFEST.read_bytes()
    if len(manifest_bytes) > 1024 * 1024:
        raise ValueError("synthetic manifest exceeds its byte bound")
    manifest = Manifest.model_validate_json(manifest_bytes)
    before_digest = source_digest()
    rows: list[JSON] = []
    for shape in manifest.shapes:
        for item in manifest.cases:
            rows.append(
                aggregate([run_case(item, shape) for _ in range(arguments.repetitions)])
            )
    if before_digest != source_digest():
        raise RuntimeError("retrieval source changed during benchmark")
    report: dict[str, JSON] = {
        "format": "memory.synthetic-discovery-benchmark.v1",
        "repository_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip(),
        "source_digest": before_digest,
        "fixture_digest": hashlib.sha256(manifest_bytes).hexdigest(),
        "ladder_version": retrieval.LADDER_VERSION,
        "claims": {
            "scope": "fresh disposable synthetic kernel retrieval only",
            "approval_setup": "internal test fake; no OS approval or owner-presence claim",
            "provider_or_model_calls": 0,
            "model_answer_quality": "not measured",
            "client_visible_latency": "not measured",
            "samples_per_case": arguments.repetitions,
            "fresh_disposable_runtime_count": len(rows) * arguments.repetitions,
            "time_boundary": "kernel operations only; excludes fixture setup, serialization, model and transport",
            "volume_boundary": "one compact dataclass JSON representation; not MCP wire or token count",
            "fragment_boundary": "exact required-text reach only; does not grade an answer or binary meaning",
            "clock_summary": "median of fresh-runtime samples; individual samples retained",
            "environment_limit": "concurrent machine load is uncontrolled; transport and model latency are excluded",
        },
        "strategies": {
            "literal_search": "complete source.search and memory.search walks for the original query, limit 2; first-hit metrics inspect only the first result",
            "queryless_current_head_discovery": "complete unfiltered queryless memory.search walk, limit 2, then one batched memory.get for every head and attached guard",
            "complete_evidence_discovery": "queryless current-head discovery plus complete source.list and source.read walks; evidence-linked sources first, limit 2, read chunks 4096 bytes",
            "cost_accounting": "each strategy is measured separately from the original-query search; complete discovery includes its compact discovery prefix",
        },
        "cases": rows,
    }
    output = cast(Path, arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Measured {len(rows)} fresh synthetic discovery cases.")
    return 0
