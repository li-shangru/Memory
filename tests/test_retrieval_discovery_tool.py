"""Synthetic evidence-discovery metrics retain the distinction from model answers."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "run-retrieval-discovery.py"


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _run(output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--output",
            str(output),
            "--repetitions",
            "1",
            *arguments,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.mark.parametrize("value", ("0", "4"))
def test_discovery_runner_refuses_unbounded_repetition_counts(
    tmp_path: Path, value: str
) -> None:
    output = tmp_path / "synthetic-discovery.json"
    result = _run(output, "--repetitions", value)
    assert result.returncode == 2
    assert "between 1 and 3" in result.stderr
    assert not output.exists()


def test_discovery_runner_measures_reach_and_preserves_lexical_limits(
    tmp_path: Path,
) -> None:
    output = tmp_path / "synthetic-discovery.json"
    result = _run(output)
    assert result.returncode == 0, result.stderr
    report = _mapping(json.loads(output.read_text()))
    assert report["format"] == "memory.synthetic-discovery-benchmark.v1"
    assert report["ladder_version"] == 7
    claims = _mapping(report["claims"])
    assert claims["provider_or_model_calls"] == 0
    assert claims["model_answer_quality"] == "not measured"
    assert claims["client_visible_latency"] == "not measured"
    cases = report["cases"]
    assert isinstance(cases, list)
    rows = [_mapping(row) for row in cases]
    assert len(rows) == 36
    assert {row["language"] for row in rows} == {"en", "zh"}
    assert {row["shape"] for row in rows} == {"compact", "short_noise", "long_sources"}
    required = compact = complete = 0
    for row in rows:
        requirement_count = row["required_fragment_count"]
        assert isinstance(requirement_count, int)
        required += requirement_count
        canonical = _mapping(row["queryless_current_head_discovery"])
        canonical_hits = canonical["requirement_hits"]
        assert isinstance(canonical_hits, int)
        compact += canonical_hits
        assert canonical["all_details_current"] is True
        assert row["superseded_heads_returned"] == 0
        full = _mapping(row["complete_evidence_discovery"])
        full_hits = full["requirement_hits"]
        assert isinstance(full_hits, int)
        complete += full_hits
        assert full_hits == requirement_count
        assert full["all_custody_bytes_reconstructed"] is True
        assert full["sources_read"] == row["source_count"]
        assert row["model_answer_evaluated"] is False
        literal = _mapping(row["literal_search"])
        match row["condition"]:
            case "partial_repetition":
                assert literal["source_order"] == ["record", "distractor"]
                assert literal["memory_order"] == ["condition", "practice"]
            case "exact_repetition_late_caveat":
                assert literal["source_order"] == ["distractor", "record"]
                assert literal["first_source_preview_requirement_hits"] == 0
                assert canonical_hits == 1
            case "paraphrase":
                assert literal["source_order"] == []
                assert literal["memory_order"] == []
                assert canonical_hits == 1
            case "guard":
                assert row["required_guards_delivered"] == 1
                assert row["restricted_claim_returned"] is True
            case "unanswerable_binary":
                assert row["expected_answerability"] == "unanswerable"
                assert row["unsearchable_sources"] == 1
                assert full["unresolved_binary_sources"] == 1
            case "correction":
                assert literal["memory_order"] == ["latest"]
            case _:
                raise AssertionError("unexpected synthetic discovery condition")
    assert (required, compact, complete) == (48, 42, 48)

    serialized = output.read_text()
    for private_field in (
        "source_id",
        "store_id",
        "memory_id",
        "lineage_id",
        "blob_digest",
        "exact_excerpt",
        "runtime_path",
        str(tmp_path),
        "signal kiln launch readiness",
        "如何防止运输损坏",
    ):
        assert private_field not in serialized
