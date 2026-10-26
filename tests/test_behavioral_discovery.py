"""The separate discovery cohort keeps its fixed denominator and provenance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import _provenance, _tool

ROOT = Path(__file__).resolve().parents[1]
DISCOVERY = ROOT / "tests/fixtures/synthetic_behavioral_discovery/manifest.json"
HISTORICAL = ROOT / "tests/fixtures/synthetic_behavioral/manifest.json"
CASES = (
    "SYN-BEHAVIOR-DISCOVERY-REPEAT-LATE-EN-027",
    "SYN-BEHAVIOR-DISCOVERY-REPEAT-LATE-ZH-028",
)
CONDITIONS = (
    "repeated_distractors_and_late_caveat_en",
    "repeated_distractors_and_late_caveat_zh",
)


def test_discovery_manifest_has_a_separate_fixed_six_slot_client_cohort() -> None:
    tool = _tool()
    manifest = tool.load_manifest(DISCOVERY)
    state = tool.create_run_state(manifest, trials=None, provenance=_provenance())

    assert manifest.schema == "memory.synthetic-behavioral-discovery.v1"
    assert manifest.rubric_version == "behavioral-discovery-rubric-2026-09-05"
    assert tuple(manifest.cases) == CASES
    assert state["requested_trial_count"] == 3
    assert [(slot["case_id"], slot["trial"]) for slot in state["slots"]] == [
        (case, trial) for case in CASES for trial in (1, 2, 3)
    ]
    assert manifest.digest != tool.load_manifest(HISTORICAL).digest
    assert manifest.rubric_digest != tool.load_manifest(HISTORICAL).rubric_digest


@pytest.mark.parametrize("trials", [1, 2, 4, 10])
def test_discovery_rejects_trial_count_changes(trials: int) -> None:
    tool = _tool()
    with pytest.raises(tool.AcceptanceError, match=r"fixed.*three"):
        tool.create_run_state(
            tool.load_manifest(DISCOVERY), trials=trials, provenance=_provenance()
        )


@pytest.mark.parametrize("count", [True, 1, 2, 3.0, "3", None])
def test_discovery_manifest_rejects_changed_declared_count(
    tmp_path: Path, count: object
) -> None:
    tool = _tool()
    payload = json.loads(DISCOVERY.read_text(encoding="utf-8"))
    payload["trials_per_case_per_client"] = count
    changed = tmp_path / "manifest.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(tool.AcceptanceError, match=r"fixed.*three"):
        tool.load_manifest(changed)


def test_discovery_report_retains_blocked_and_pending_denominators() -> None:
    tool = _tool()
    state = tool.create_run_state(
        tool.load_manifest(DISCOVERY), trials=3, provenance=_provenance()
    )
    state["slots"][0].update(
        attempted=True,
        execution_outcome="blocked",
        outcome_label="synthetic_prerequisite_unavailable",
        inference_started=False,
        client_launch_attempted=False,
    )
    report = tool.build_report(state)

    assert report["counts"] == {
        "requested": 6,
        "attempted": 1,
        "completed": 0,
        "passed": 0,
    }
    assert report["pass_rate"] == {"numerator": 0, "denominator": 6}
    assert tuple(row["condition"] for row in report["conditions"]) == CONDITIONS
    assert [row["counts"]["requested"] for row in report["conditions"]] == [3, 3]
    assert all(row["pass_rate"]["denominator"] == 3 for row in report["conditions"])
    assert len(report["trials"]) == 6
    assert "question_variant" not in json.dumps(report)


@pytest.mark.parametrize("mutation", ["schema", "roster", "rubric", "root_key"])
def test_manifest_policies_cannot_be_mixed(tmp_path: Path, mutation: str) -> None:
    tool = _tool()
    payload = json.loads(DISCOVERY.read_text(encoding="utf-8"))
    if mutation == "schema":
        payload["schema"] = tool.MANIFEST_SCHEMA
    elif mutation == "roster":
        payload["cases"] = json.loads(HISTORICAL.read_text(encoding="utf-8"))["cases"]
    elif mutation == "rubric":
        payload["rubric_version"] = "behavioral-rubric-2026-09-03"
    else:
        del payload["trials_per_case_per_client"]
    changed = tmp_path / "manifest.json"
    changed.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(tool.AcceptanceError):
        tool.load_manifest(changed)


def test_discovery_cannot_resume_or_grade_a_historical_state(tmp_path: Path) -> None:
    tool = _tool()
    manifest = tool.load_manifest(DISCOVERY)
    state = cast(
        dict[str, Any],
        tool.create_run_state(
            tool.load_manifest(HISTORICAL), trials=3, provenance=_provenance()
        ),
    )

    def forbidden(*_args: object) -> dict[str, Any]:
        pytest.fail("cross-manifest state reached the executor")

    with pytest.raises(tool.AcceptanceError, match="another manifest"):
        tool.execute_trials(state, manifest, tmp_path, execute=forbidden)
    with pytest.raises(tool.AcceptanceError, match="provenance changed"):
        tool.grade_trials(state, manifest, [])
    assert not any(state["slots"][i]["attempted"] for i in range(18))


@pytest.mark.parametrize(
    "mutation", ["drop", "duplicate", "count", "condition", "trial"]
)
@pytest.mark.parametrize("boundary", ["report", "resume", "grade", "read", "write"])
def test_discovery_revalidates_the_fixed_roster_before_using_state(
    tmp_path: Path, mutation: str, boundary: str
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(DISCOVERY)
    state = tool.create_run_state(manifest, trials=3, provenance=_provenance())
    if mutation == "drop":
        state["slots"].pop()
    elif mutation == "duplicate":
        state["slots"][1] = dict(state["slots"][0])
    elif mutation == "count":
        state["requested_trial_count"] = 2
    elif mutation == "condition":
        state["slots"][0]["condition"] = tool.EXPECTED_CONDITIONS[0]
    else:
        state["slots"][0]["trial"] = True

    def forbidden(*_args: object) -> dict[str, Any]:
        pytest.fail("changed fixed roster reached the executor")

    with pytest.raises(tool.AcceptanceError, match=r"fixed.*roster"):
        if boundary == "report":
            tool.build_report(state)
        elif boundary == "resume":
            tool.execute_trials(state, manifest, tmp_path, execute=forbidden)
        elif boundary == "grade":
            tool.grade_trials(state, manifest, [])
        elif boundary == "write":
            tool._write_state(tmp_path, state)
        else:
            path = tmp_path / tool.STATE_FILENAME
            path.write_text(json.dumps(state), encoding="utf-8")
            path.chmod(0o600)
            tool._read_state(tmp_path)
