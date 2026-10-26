"""Development benchmark checks: real synthetic retrieval, never timing gates."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from retrieval_benchmark import JSON

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "run-retrieval-benchmark.py"


def _run(output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), "--output", str(output), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _records(value: JSON) -> list[dict[str, JSON]]:
    assert isinstance(value, list)
    assert all(isinstance(item, dict) for item in value)
    return cast(list[dict[str, JSON]], value)


def test_benchmark_bounds_work_before_creating_a_report(tmp_path: Path) -> None:
    output = tmp_path / "synthetic-report.json"

    result = _run(output, "--repetitions", "0")

    assert result.returncode == 2
    assert "between 1 and 7" in result.stderr
    assert not output.exists()


def test_smoke_measures_bilingual_real_pages_and_only_emits_aggregates(
    tmp_path: Path,
) -> None:
    output = tmp_path / "synthetic-report.json"

    result = _run(output, "--profile", "smoke", "--repetitions", "1")

    assert result.returncode == 0, result.stderr
    report = cast(dict[str, JSON], json.loads(output.read_text()))
    assert report["acceptance_claim"] == "automated_synthetic_retrieval_only"
    rows = _records(report["timing"])
    assert {row["language"] for row in rows} == {"en", "zh"}
    for row in rows:
        assert row["source_count"] == 2
        assert row["source_bytes"] == 32768
        assert row["current_memory_count"] == 4
        operations = _records(row["operations"])
        measurements = {str(entry["operation"]): entry for entry in operations}
        assert measurements["source.match.first"]["items"] == 1
        assert measurements["source.match.continued"]["items"] == 1
        assert measurements["source.no_hits.first"]["items"] == 0
        assert measurements["memory.match.first"]["items"] == 1
        assert measurements["memory.match.continued"]["items"] == 1
        assert measurements["memory.no_hits.first"]["items"] == 0
        assert measurements["advice.complete"]["source_bytes_read"] == 32768
        assert measurements["advice.complete"]["sources_read"] == 2
        assert measurements["advice.complete"]["standing_heads"] == 2
        assert measurements["advice.complete"]["open_loop_heads"] == 2
        assert all(entry["samples"] == 1 for entry in operations)
    serialized = output.read_text()
    for forbidden in (
        "source_id",
        "store_id",
        "lineage_id",
        "blob_digest",
        "exact_excerpt",
        "runtime_path",
        str(tmp_path),
        "glimmer pathway",
        "晨光通道",
    ):
        assert forbidden not in serialized


def test_quality_walk_reaches_manifest_evidence_and_current_guards(
    tmp_path: Path,
) -> None:
    output = tmp_path / "synthetic-quality.json"

    result = _run(output, "--profile", "quality", "--repetitions", "1")

    assert result.returncode == 0, result.stderr
    report = cast(dict[str, JSON], json.loads(output.read_text()))
    assert report["timing"] == []
    cases = _records(report["quality"])
    assert len(cases) == 6
    assert {case["language"] for case in cases} == {"en", "zh"}
    for case in cases:
        assert case["full_read_requirement_hits"] == case["requirement_count"]
        assert case["full_read_sources"] == case["source_count"]
        assert case["search_returned_only_current_heads"] is True
    paraphrases = [case for case in cases if "paraphrase" in str(case["conditions"])]
    assert len(paraphrases) == 2
    assert all(case["ranked_source_hits"] == 0 for case in paraphrases)
    assert all(
        case["first_source_excerpt_requirement_hits"] == 0 for case in paraphrases
    )
    guards = [case for case in cases if "guard_attachment" in str(case["conditions"])]
    assert len(guards) == 1
    assert guards[0]["required_guards_delivered"] == 1
    assert guards[0]["required_guard_count"] == 1
    corrections = [case for case in cases if "supersession" in str(case["conditions"])]
    assert len(corrections) == 1
    assert corrections[0]["superseded_heads_returned"] == 0
    assert corrections[0]["required_current_heads_delivered"] == 1
