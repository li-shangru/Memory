"""A narrow infrastructure continuation cannot rewrite a consumed trial."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import (
    MANIFEST_PATH,
    REPO_ROOT,
    _complete_attempt,
    _passing_grades,
    _provenance,
    _tool,
)
from test_behavioral_subscription_binding import _authentication, _isolation

CONTINUATION_SCHEMA = "memory.behavioral-subscription-continuation.v1"
NEW_PROFILE = "ca" * 32
NEW_ADAPTER = "da" * 32
CLEANUP_DIGEST = "ea" * 32


def _serialized(state: dict[str, Any]) -> bytes:
    return (json.dumps(state, ensure_ascii=False, sort_keys=True) + "\n").encode()


def _state(tool: ModuleType, root: Path, *, discovery: bool = False) -> dict[str, Any]:
    manifest_path = (
        REPO_ROOT / "tests/fixtures/synthetic_behavioral_discovery/manifest.json"
        if discovery
        else MANIFEST_PATH
    )
    state = cast(
        dict[str, Any],
        tool.create_run_state(
            tool.load_manifest(manifest_path),
            trials=3,
            provenance={
                **_provenance(),
                **_isolation(),
                "reasoning_effort": "max",
                "seed_mode": "owner_review",
            },
        ),
    )
    state["private"] = {
        "manifest_path": str(manifest_path),
        "client_executable": "/synthetic/codex",
        "memory_executable": "/synthetic/memory",
        "build_artifact": "/synthetic/memory.whl",
        "seed_executable": "/synthetic/seed",
        "fixture_run_id": "SYN-CONTINUATION-RUN",
    }
    for ordinal, slot in enumerate(state["slots"], start=1):
        slot.update(
            client_launch_attempted=False,
            inference_started=False,
            fixture_preparation="ready",
            fixture_store_id="SYN-CONTINUATION-STORE-" + slot["slot_id"],
            fixture_phases=[{"digest": "ad" * 32, "fixture_id": "SYN-SOURCE"}],
            private_trial_directory=str(
                root / "private-trials" / f"trial-{ordinal:03d}"
            ),
        )
    state = cast(
        dict[str, Any],
        tool.bind_subscription_authentication(
            state,
            auth_root=root / "old-interrupted-auth-scope",
            authentication_digest=_authentication()["authentication_adapter_digest"],
            isolation_binding=_isolation(),
        ),
    )
    if not discovery:
        state["slots"][0].update(
            attempted=True,
            client_launch_attempted=True,
            inference_started=None,
            execution_outcome="failed",
            outcome_label="client_transport_failed",
            mutation_outcome="unchanged",
        )
    return state


def _snapshot(root: Path, state: dict[str, Any]) -> tuple[Path, str]:
    raw = _serialized(state)
    digest = hashlib.sha256(raw).hexdigest()
    path = root / f"continuation-before-{digest}.private.json"
    path.write_bytes(raw)
    path.chmod(0o400)
    return path, digest


def _continue(tool: ModuleType, root: Path, state: dict[str, Any]) -> dict[str, Any]:
    snapshot, digest = _snapshot(root, state)
    return cast(
        dict[str, Any],
        tool.continue_subscription_authentication(
            state,
            auth_root=root / "fresh-auth-scope",
            authentication_digest=NEW_ADAPTER,
            isolation_binding={**_isolation(), "isolation_profile_digest": NEW_PROFILE},
            snapshot_path=snapshot,
            snapshot_digest=digest,
            cleanup_evidence=root / "cleanup.private.json",
            cleanup_digest=CLEANUP_DIGEST,
        ),
    )


@pytest.mark.parametrize(
    "discovery,pending,denominator", [(False, 17, 18), (True, 6, 6)]
)
def test_continuation_preserves_original_state_slots_approvals_and_denominators(
    tmp_path: Path, discovery: bool, pending: int, denominator: int
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path, discovery=discovery)
    before = copy.deepcopy(state)
    slots = state["slots"]
    changed = _continue(tool, tmp_path, state)

    assert state == before
    assert changed["schema"] == tool.STATE_SCHEMA
    assert changed["provenance"] == before["provenance"]
    assert changed["slots"] is slots
    assert all(
        left is right for left, right in zip(changed["slots"], slots, strict=True)
    )
    assert changed["slots"] == before["slots"]
    assert (
        changed["private"]["subscription_auth_root"]
        == before["private"]["subscription_auth_root"]
    )
    assert (
        changed["private"]["authentication_transitions"]
        == before["private"]["authentication_transitions"]
    )
    assert changed["continuation"]["schema"] == CONTINUATION_SCHEMA
    assert len(changed["continuation"]["pending_slot_ids"]) == pending
    report = tool.build_report(changed)
    assert report["schema"] == "memory.behavioral-acceptance-report.v2"
    assert report["counts"]["requested"] == denominator
    assert report["pass_rate"]["denominator"] == denominator
    assert report["provenance"] == tool.build_report(before)["provenance"]
    assert (
        report["execution_bindings"]["original"]["isolation_profile_digest"]
        == (_isolation()["isolation_profile_digest"])
    )
    assert (
        report["execution_bindings"]["continued"]["isolation_profile_digest"]
        == NEW_PROFILE
    )
    assert (
        sum(trial["execution_binding"] == "continued" for trial in report["trials"])
        == pending
    )
    if not discovery:
        assert report["trials"][0]["execution_binding"] == "original"
        assert report["trials"][0]["outcome_label"] == "client_transport_failed"
        assert report["trials"][0]["inference_started"] is None
    serialized = json.dumps(report)
    for private_value in (
        str(tmp_path),
        "SYN-CONTINUATION-RUN",
        "SYN-CONTINUATION-STORE",
        "cleanup.private",
        "snapshot",
    ):
        assert private_value not in serialized


@pytest.mark.parametrize(
    "changes",
    [
        {"completed": True},
        {"client_launch_attempted": False},
        {"inference_started": False},
        {"inference_started": True},
        {"execution_outcome": "interrupted"},
        {"outcome_label": "client_teardown_unverified"},
        {"mutation_outcome": "changed"},
        {"grade_outcome": "passed"},
        {"outcomes": {"final_answer": {"result": "passed"}}},
    ],
)
def test_only_the_exact_ungraded_transport_failure_can_be_preserved(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    state["slots"][0].update(changes)
    before = copy.deepcopy(state)
    with pytest.raises(tool.AcceptanceError):
        _continue(tool, tmp_path, state)
    assert state == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempted", 0),
        ("inference_started", None),
        ("outcome_label", "awaiting_grade"),
        ("mutation_outcome", "unchanged"),
        ("grade_outcome", "failed"),
        ("fixture_preparation", "owner_presence_prerequisite"),
    ],
)
def test_continuation_refuses_ambiguous_or_unready_pending_slots(
    tmp_path: Path, field: str, value: object
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    state["slots"][3][field] = value
    with pytest.raises(tool.AcceptanceError):
        _continue(tool, tmp_path, state)


def test_effective_view_shares_slots_but_never_changes_original_provenance(
    tmp_path: Path,
) -> None:
    tool = _tool()
    state = _continue(tool, tmp_path, _state(tool, tmp_path))
    original = copy.deepcopy(state)
    pending = state["continuation"]["pending_slot_ids"][0]
    effective = tool.effective_execution_state(state, slot_id=pending)
    assert effective["slots"] is state["slots"]
    assert effective["provenance"]["isolation_profile_digest"] == NEW_PROFILE
    assert effective["provenance"]["authentication_adapter_digest"] == NEW_ADAPTER
    assert effective["private"]["subscription_auth_root"] == str(
        tmp_path / "fresh-auth-scope"
    )
    assert "continuation" not in effective
    assert state == original
    with pytest.raises(tool.AcceptanceError):
        tool.effective_execution_state(state, slot_id=state["slots"][0]["slot_id"])


@pytest.mark.parametrize("field", ["client_executable_digest", "code_mode_host_digest"])
def test_continuation_refuses_changed_client_or_host(
    tmp_path: Path, field: str
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    snapshot, digest = _snapshot(tmp_path, state)
    with pytest.raises(tool.AcceptanceError):
        tool.continue_subscription_authentication(
            state,
            auth_root=tmp_path / "fresh-auth-scope",
            authentication_digest=NEW_ADAPTER,
            isolation_binding={
                **_isolation(),
                "isolation_profile_digest": NEW_PROFILE,
                field: "fa" * 32,
            },
            snapshot_path=snapshot,
            snapshot_digest=digest,
            cleanup_evidence=tmp_path / "cleanup.private.json",
            cleanup_digest=CLEANUP_DIGEST,
        )


@pytest.mark.parametrize(
    "field",
    [
        "model",
        "reasoning_effort",
        "skill_digest",
        "build_digest",
        "installed_distribution_digest",
        "manifest_digest",
        "rubric_digest",
    ],
)
def test_later_provenance_tampering_refuses_report_and_execution(
    tmp_path: Path, field: str
) -> None:
    tool = _tool()
    state = _continue(tool, tmp_path, _state(tool, tmp_path))
    state["provenance"][field] = "fa" * 32
    with pytest.raises(tool.AcceptanceError):
        tool.build_report(state)
    with pytest.raises(tool.AcceptanceError):
        tool.effective_execution_state(state)


def test_snapshot_and_failed_slot_are_checked_on_every_view(tmp_path: Path) -> None:
    tool = _tool()
    state = _continue(tool, tmp_path, _state(tool, tmp_path))
    first = copy.deepcopy(state["slots"][0])
    state["slots"][0]["execution_outcome"] = "pending"
    with pytest.raises(tool.AcceptanceError):
        tool.effective_execution_state(state)
    state["slots"][0] = first
    snapshot = Path(state["private"]["continuation"]["snapshot_path"])
    snapshot.chmod(0o600)
    snapshot.write_text("{}\n", encoding="utf-8")
    snapshot.chmod(0o400)
    with pytest.raises(tool.AcceptanceError):
        tool.build_report(state)


@pytest.mark.parametrize("discovery,pending", [(False, 17), (True, 6)])
def test_execution_and_grading_preserve_original_slots_through_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, discovery: bool, pending: int
) -> None:
    tool = _tool()
    original = _state(tool, tmp_path, discovery=discovery)
    tool._write_state(tmp_path, original)
    raw = (tmp_path / tool.STATE_FILENAME).read_bytes()
    state = _continue(tool, tmp_path, original)
    tool._write_state(
        tmp_path, state, expected_state_digest=hashlib.sha256(raw).hexdigest()
    )
    failed = None if discovery else copy.deepcopy(state["slots"][0])
    observed: list[str] = []
    for ordinal, _slot in enumerate(state["slots"], start=1):
        directory = tmp_path / "private-trials" / f"trial-{ordinal:03d}"
        directory.mkdir(parents=True)
        (directory / "store").mkdir()
        (directory / "client-session").mkdir()
        (directory / "client-response.private").touch(mode=0o600)
        for path in (directory, directory / "store", directory / "client-session"):
            path.chmod(0o700)

    def bound(
        view: dict[str, Any],
        _manifest: object,
        *,
        persist: Callable[[], None] | None = None,
    ) -> Callable[[dict[str, Any], int, Path, Path, Path], dict[str, Any]]:
        assert view["slots"] is state["slots"]
        assert view["provenance"]["isolation_profile_digest"] == NEW_PROFILE
        assert view["private"]["subscription_auth_root"] == str(
            tmp_path / "fresh-auth-scope"
        )
        assert persist is not None

        def execute(case: dict[str, Any], trial: int, *_paths: Path) -> dict[str, Any]:
            slot_id = f"{case['case_id']}:{trial}"
            slot = next(slot for slot in view["slots"] if slot["slot_id"] == slot_id)
            slot.update(client_launch_attempted=True, inference_started=None)
            assert persist is not None
            persist()
            saved = tool._read_state(tmp_path)
            assert saved["provenance"] == original["provenance"]
            assert (
                saved["private"]["subscription_auth_root"]
                == original["private"]["subscription_auth_root"]
            )
            observed.append(slot_id)
            return _complete_attempt()

        return execute

    monkeypatch.setattr(tool, "_actual_executor_bound", bound)
    manifest = tool.load_manifest(Path(state["private"]["manifest_path"]))
    executor = tool._actual_executor(
        state, manifest, persist=lambda: tool._write_state(tmp_path, state)
    )

    def run() -> None:
        tool.execute_trials(
            state,
            manifest,
            tmp_path / "private-trials",
            execute=executor,
            persist=lambda current: tool._write_state(tmp_path, current),
        )

    run()
    assert observed == state["continuation"]["pending_slot_ids"]
    assert tool.build_report(state)["counts"]["completed"] == pending
    if failed is not None:
        assert state["slots"][0] == failed
    assert tool._read_state(tmp_path) == state
    run()
    assert len(observed) == pending

    ungraded = copy.deepcopy(state)
    grades = _passing_grades(state, manifest)
    for grade in grades:
        grade["inference_observed"] = True
    tool.grade_trials(state, manifest, grades)
    tool._write_state(tmp_path, state)
    saved = (tmp_path / tool.STATE_FILENAME).read_bytes()
    with pytest.raises(tool.AcceptanceError):
        tool.grade_trials(state, manifest, grades)
    with pytest.raises(tool.AcceptanceError):
        tool._write_state(tmp_path, ungraded)
    assert (tmp_path / tool.STATE_FILENAME).read_bytes() == saved
    assert tool.build_report(state)["counts"]["passed"] == pending
    assert tool.build_report(state)["inference_counts"]["started"] == pending


def _terminal_state(tool: ModuleType, root: Path, outcome: str) -> dict[str, Any]:
    state = _continue(tool, root, _state(tool, root))
    state["slots"][1].update(
        attempted=True,
        completed=outcome == "completed",
        execution_outcome=outcome,
        outcome_label={
            "failed": "client_transport_failed",
            "blocked": "owner_presence_prerequisite",
            "completed": "awaiting_grade",
        }[outcome],
        mutation_outcome="unchanged",
        client_launch_attempted=False,
        inference_started=False,
        capability_probe={"schema": "synthetic-proof", "capabilities_confirmed": True},
    )
    tool._write_state(root, state)
    return state


@pytest.mark.parametrize("outcome", ["failed", "blocked", "completed"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("attempted", False),
        ("completed", None),
        ("execution_outcome", "interrupted"),
        ("outcome_label", "executor_failed"),
        ("mutation_outcome", "changed"),
        ("grade_outcome", "passed"),
        ("outcomes", {"synthetic": {"result": "passed"}}),
        ("client_launch_attempted", True),
        ("inference_started", None),
        ("capability_probe", {"schema": "synthetic-replacement"}),
    ],
)
def test_terminal_execution_evidence_cannot_be_rewritten(
    tmp_path: Path, outcome: str, field: str, value: object
) -> None:
    tool = _tool()
    state = _terminal_state(tool, tmp_path, outcome)
    state_path = tmp_path / tool.STATE_FILENAME
    original = state_path.read_bytes()
    snapshot = Path(state["private"]["continuation"]["snapshot_path"])
    snapshot_bytes = snapshot.read_bytes()
    changed = copy.deepcopy(state)
    changed["slots"][1][field] = value

    with pytest.raises(tool.AcceptanceError):
        tool._write_state(tmp_path, changed)

    assert state_path.read_bytes() == original
    assert tool._read_state(tmp_path) == state
    assert snapshot.read_bytes() == snapshot_bytes


@pytest.mark.parametrize(
    "field,value",
    [
        ("outcome_label", "executor_failed"),
        ("mutation_outcome", "changed"),
        ("client_launch_attempted", True),
        ("inference_started", None),
        ("capability_probe", {"schema": "synthetic-replacement"}),
    ],
)
def test_grading_cannot_also_replace_completed_execution_evidence(
    tmp_path: Path, field: str, value: object
) -> None:
    tool = _tool()
    state = _terminal_state(tool, tmp_path, "completed")
    original = (tmp_path / tool.STATE_FILENAME).read_bytes()
    manifest = tool.load_manifest(MANIFEST_PATH)
    changed = copy.deepcopy(state)
    tool.grade_trials(changed, manifest, _passing_grades(changed, manifest))
    changed["slots"][1][field] = value

    with pytest.raises(tool.AcceptanceError):
        tool._write_state(tmp_path, changed)

    assert (tmp_path / tool.STATE_FILENAME).read_bytes() == original


@pytest.mark.parametrize("result", ["passed", "failed"])
@pytest.mark.parametrize("inference_observed", [False, True])
def test_completed_slot_accepts_only_its_once_only_grading_transition(
    tmp_path: Path, result: str, inference_observed: bool
) -> None:
    tool = _tool()
    state = _terminal_state(tool, tmp_path, "completed")
    manifest = tool.load_manifest(MANIFEST_PATH)
    tool._write_state(tmp_path, state)
    before = copy.deepcopy(state["slots"][1])
    grades = _passing_grades(state, manifest)
    if result == "failed":
        outcome = next(
            value
            for value in grades[0]["outcomes"].values()
            if value["result"] == "passed"
        )
        outcome.update(result="failed", label="synthetic_dimension_failed")
    if inference_observed:
        grades[0]["inference_observed"] = True
    tool.grade_trials(state, manifest, grades)
    tool._write_state(tmp_path, state)
    saved = (tmp_path / tool.STATE_FILENAME).read_bytes()
    tool._write_state(tmp_path, state)
    assert (tmp_path / tool.STATE_FILENAME).read_bytes() == saved
    after = tool._read_state(tmp_path)["slots"][1]
    assert after["grade_outcome"] == result
    assert after["inference_started"] is inference_observed
    for field in before.keys() - {
        "grade_outcome",
        "outcome_label",
        "outcomes",
        "inference_started",
    }:
        assert after[field] == before[field]


def _command_state(tool: ModuleType, root: Path) -> dict[str, Any]:
    state = _state(tool, root)
    client = root / "synthetic-codex"
    client.write_text("Synthetic executable fixture.\n", encoding="utf-8")
    client.chmod(0o700)
    state["private"]["client_executable"] = str(client)
    tool._write_state(root, state)
    return state


def _command_arguments(root: Path) -> list[str]:
    return [
        "continue-subscription",
        "--state-root",
        str(root),
        "--auth-root",
        str(root / "fresh-auth-scope"),
        "--cleanup-evidence",
        str(root / "cleanup.private.json"),
    ]


def _stub_prerequisites(
    tool: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    observed: list[str],
    failure: str | None = None,
) -> None:
    def prerequisite(name: str) -> None:
        observed.append(name)
        if failure == name:
            raise tool.AcceptanceError("Synthetic prerequisite unavailable.")

    def cleanup(_state: object, _path: Path, *, state_digest: str) -> str:
        assert len(state_digest) == 64
        prerequisite("cleanup")
        return CLEANUP_DIGEST

    monkeypatch.setattr(tool, "_require_continuation_cleanup", cleanup)
    monkeypatch.setattr(
        tool, "_subscription_implementation_digest", lambda: NEW_ADAPTER
    )
    monkeypatch.setattr(
        tool,
        "_codex_artifact_binding",
        lambda *_args, **_kwargs: {
            **_isolation(),
            "isolation_profile_digest": NEW_PROFILE,
        },
    )
    monkeypatch.setattr(
        tool, "_revalidate_prepared_artifacts", lambda _state: prerequisite("artifacts")
    )
    monkeypatch.setattr(
        tool, "_validated_subscription_session", lambda *_args: prerequisite("auth")
    )
    monkeypatch.setattr(
        tool, "_require_codex_capabilities", lambda _state: prerequisite("capabilities")
    )
    monkeypatch.setattr(
        tool,
        "_require_memory_transport_readiness",
        lambda _state: prerequisite("readiness"),
    )


@pytest.mark.parametrize(
    "failure", [None, "cleanup", "artifacts", "auth", "capabilities", "readiness"]
)
def test_command_saves_only_after_every_prerequisite_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    tool = _tool()
    state = _command_state(tool, tmp_path)
    original = (tmp_path / tool.STATE_FILENAME).read_bytes()
    observed: list[str] = []
    _stub_prerequisites(tool, monkeypatch, observed, failure)
    result = tool.main(_command_arguments(tmp_path), stderr=io.StringIO())
    assert result == (0 if failure is None else 1)
    if failure is None:
        saved = tool._read_state(tmp_path)
        assert saved["slots"] == state["slots"]
        assert saved["provenance"] == state["provenance"]
        assert observed == ["cleanup", "artifacts", "auth", "capabilities", "readiness"]
        snapshot = Path(saved["private"]["continuation"]["snapshot_path"])
        assert snapshot.read_bytes() == original
        assert snapshot.stat().st_mode & 0o777 == 0o400
    else:
        assert (tmp_path / tool.STATE_FILENAME).read_bytes() == original
        assert not list(tmp_path.glob("continuation-before-*.private.json"))


def test_identical_command_replay_is_a_noop_only_before_continuation_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    _command_state(tool, tmp_path)
    observed: list[str] = []
    _stub_prerequisites(tool, monkeypatch, observed)
    arguments = _command_arguments(tmp_path)
    assert tool.main(arguments, stderr=io.StringIO()) == 0
    saved_path = tmp_path / tool.STATE_FILENAME
    first = saved_path.read_bytes()
    observed.clear()
    assert tool.main(arguments, stderr=io.StringIO()) == 0
    assert saved_path.read_bytes() == first
    assert observed == ["cleanup"]
    state = tool._read_state(tmp_path)
    state["slots"][1].update(
        attempted=True,
        execution_outcome="interrupted",
        outcome_label="execution_interrupted",
    )
    tool._write_state(tmp_path, state)
    attempted = saved_path.read_bytes()
    assert tool.main(arguments, stderr=io.StringIO()) == 1
    assert saved_path.read_bytes() == attempted


def test_concurrent_state_change_refuses_the_final_continuation_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _command_state(tool, tmp_path)
    observed: list[str] = []
    _stub_prerequisites(tool, monkeypatch, observed)

    def concurrent_change(_candidate: object) -> None:
        state["slots"][2].update(
            attempted=True,
            execution_outcome="interrupted",
            outcome_label="execution_interrupted",
        )
        tool._write_state(tmp_path, state)

    monkeypatch.setattr(tool, "_require_memory_transport_readiness", concurrent_change)
    assert tool.main(_command_arguments(tmp_path), stderr=io.StringIO()) == 1
    assert tool._read_state(tmp_path) == state
    assert "continuation" not in state


def test_cleanup_is_closed_until_an_authoritative_validator_is_installed(
    tmp_path: Path,
) -> None:
    tool = _tool()
    _command_state(tool, tmp_path)
    (tmp_path / "cleanup.private.json").write_text(
        '{"cleanup_confirmed":true}\n', encoding="utf-8"
    )
    original = (tmp_path / tool.STATE_FILENAME).read_bytes()
    assert tool.main(_command_arguments(tmp_path), stderr=io.StringIO()) == 1
    assert (tmp_path / tool.STATE_FILENAME).read_bytes() == original


def test_legacy_absence_keeps_reports_identical(tmp_path: Path) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    before = json.dumps(tool.build_report(state), sort_keys=True)
    view = tool.effective_execution_state(state)
    assert view["slots"] is state["slots"]
    assert json.dumps(tool.build_report(state), sort_keys=True) == before
    assert json.dumps(tool.build_report(view), sort_keys=True) == before


def _cleanup_receipt(root: Path, state: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    evidence = root / "synthetic-census.json"
    evidence.write_text('{"synthetic_numeric_evidence":true}\n', encoding="utf-8")
    evidence.chmod(0o400)
    provenance = state["provenance"]
    provenance_digest = hashlib.sha256(
        json.dumps(
            provenance,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    artifacts = {
        key: value for key, value in provenance.items() if key.endswith("_digest")
    }
    boot = datetime(2026, 1, 1, tzinfo=UTC)
    payload: dict[str, Any] = {
        "schema": "memory.behavioral-prior-cleanup.v1",
        "outcome": "verified",
        "verification_method": "current_uid_birth_time_census_with_exact_startup_source",
        "previous_state_digest": {
            "codex-base": hashlib.sha256(_serialized(state)).hexdigest(),
            "codex-discovery": "bc" * 32,
        },
        "old_provenance": {
            "codex-base": provenance_digest,
            "codex-discovery": "dc" * 32,
        },
        "old_provenance_serialization": "json-sort-keys-compact-ascii-utf8-no-newline.v1",
        "old_artifact_binding": {"codex-base": artifacts, "codex-discovery": artifacts},
        "lower_bound_utc": "2026-01-01T01:00:00Z",
        "upper_bound_utc": "2026-01-01T01:01:00Z",
        "observed_at_utc": "2026-01-01T01:02:00Z",
        "recorded_at_utc": "2026-01-01T01:03:00Z",
        "observed_uid": os.getuid(),
        "current_boot": {
            "boot_session_uuid": "00000000-0000-4000-8000-000000000001",
            "boot_time_utc": boot.isoformat(),
            "seconds": int(boot.timestamp()),
            "microseconds": 0,
        },
        "queried_pid_count": 682,
        "in_window_survivor_count": 0,
        "unknown_query_count": 0,
        "stable_selection": True,
        "source_commit": "1" * 40,
        "evidence": [
            {
                "path": evidence.name,
                "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "bytes": evidence.stat().st_size,
            }
        ],
        "limitations": [
            "Synthetic evidence exercises validation only; it attests no real process cleanup."
        ],
    }
    path = root / "cleanup.private.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path, payload


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_cleanup_receipt_binds_original_raw_bytes_full_provenance_and_evidence(
    tmp_path: Path, mode: int
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    path, _payload = _cleanup_receipt(tmp_path, state)
    path.chmod(mode)
    digest = tool._require_continuation_cleanup(
        state, path, state_digest=hashlib.sha256(_serialized(state)).hexdigest()
    )
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_cleanup_receipt_mode_must_remain_exact_through_final_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    tool = _tool()
    tool._behavioral_helper_path()
    import behavioral_continuation

    state = _state(tool, tmp_path)
    receipt, _payload = _cleanup_receipt(tmp_path, state)
    receipt.chmod(mode)
    read_private_bytes = behavioral_continuation.read_private_bytes

    def read(path: Path, *, mode: int = 0o600) -> bytes:
        raw = read_private_bytes(path, mode=mode)
        if path.name == "synthetic-census.json":
            receipt.chmod(0o600 if receipt.stat().st_mode & 0o777 == 0o400 else 0o400)
        return raw

    monkeypatch.setattr(behavioral_continuation, "read_private_bytes", read)
    with pytest.raises(tool.AcceptanceError):
        tool._require_continuation_cleanup(
            state,
            receipt,
            state_digest=hashlib.sha256(_serialized(state)).hexdigest(),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_state",
        "wrong_provenance",
        "wrong_artifact",
        "foreign_uid",
        "survivor",
        "unknown",
        "unstable",
        "time_order",
        "path_escape",
        "changed_evidence",
        "symlink_evidence",
        "world_readable",
        "bool_count",
    ],
)
def test_cleanup_receipt_refuses_unbound_ambiguous_or_changed_evidence(
    tmp_path: Path, mutation: str
) -> None:
    tool = _tool()
    state = _state(tool, tmp_path)
    path, payload = _cleanup_receipt(tmp_path, state)
    if mutation == "wrong_state":
        payload["previous_state_digest"]["codex-base"] = "ac" * 32
    elif mutation == "wrong_provenance":
        payload["old_provenance"]["codex-base"] = "ac" * 32
    elif mutation == "wrong_artifact":
        payload["old_artifact_binding"]["codex-base"]["client_executable_digest"] = (
            "ac" * 32
        )
    elif mutation == "foreign_uid":
        payload["observed_uid"] = os.getuid() + 1
    elif mutation == "survivor":
        payload["in_window_survivor_count"] = 1
    elif mutation == "unknown":
        payload["unknown_query_count"] = 1
    elif mutation == "unstable":
        payload["stable_selection"] = False
    elif mutation == "time_order":
        payload["upper_bound_utc"] = "2026-01-01T00:59:00Z"
    elif mutation == "path_escape":
        payload["evidence"][0]["path"] = "../synthetic-census.json"
    elif mutation == "changed_evidence":
        evidence = tmp_path / "synthetic-census.json"
        evidence.chmod(0o600)
        evidence.write_text("{}\n", encoding="utf-8")
        evidence.chmod(0o400)
    elif mutation == "symlink_evidence":
        evidence = tmp_path / "synthetic-census.json"
        replacement = tmp_path / "synthetic-target.json"
        evidence.rename(replacement)
        evidence.symlink_to(replacement)
    elif mutation == "bool_count":
        payload["unknown_query_count"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    if mutation == "world_readable":
        path.chmod(0o644)
    with pytest.raises(tool.AcceptanceError):
        tool._require_continuation_cleanup(
            state, path, state_digest=hashlib.sha256(_serialized(state)).hexdigest()
        )


@pytest.mark.parametrize(
    "failure,symlinked_interpreter",
    [
        pytest.param(None, False, id="regular-interpreter"),
        pytest.param(None, True, id="symlinked-venv-interpreter"),
        ("bindings_changed", False),
        ("cleanup_unknown", False),
        ("bridge_cleanup_unknown", False),
        ("client_binding_changed", False),
        ("missing_checkpoint", False),
        ("changed_checkpoint", False),
        ("checkpoint_permissions", False),
        ("helper_failed", False),
    ],
)
def test_readiness_requires_bound_evidence_and_retains_an_unverified_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
    symlinked_interpreter: bool,
) -> None:
    tool = _tool()
    tool._behavioral_helper_path()
    import behavioral_mcp_bridge
    import behavioral_memory_endpoint

    state = _state(tool, tmp_path)
    binaries = tmp_path / "synthetic-bin"
    binaries.mkdir()
    for filename in ("memory", "python", "codex"):
        path = binaries / filename
        path.write_text(
            "Synthetic executable bytes; never launched.\n", encoding="utf-8"
        )
        path.chmod(0o700)
    (binaries / "memory").write_text(
        f"#!{binaries / 'python'}\n# Synthetic console entry point; never launched.\n",
        encoding="utf-8",
    )
    if symlinked_interpreter:
        target = tmp_path / "synthetic-python-runtime"
        (binaries / "python").rename(target)
        (binaries / "python").symlink_to(target)
    state["private"]["memory_executable"] = str(binaries / "memory")
    state["private"]["client_executable"] = str(binaries / "codex")
    workspace = tmp_path / "readiness-workspace"
    workspace.mkdir(mode=0o700)
    monkeypatch.setattr(tool.tempfile, "mkdtemp", lambda **_kwargs: str(workspace))
    monkeypatch.setattr(
        behavioral_memory_endpoint, "implementation_digest", lambda: "b1" * 32
    )
    monkeypatch.setattr(behavioral_mcp_bridge, "transport_digest", lambda: "b2" * 32)

    def verify(memory: Path, client: Path, fresh_workspace: Path) -> dict[str, object]:
        assert memory == binaries / "memory"
        assert client == binaries / "codex"
        assert fresh_workspace == workspace
        assert state["private"]["subscription_auth_root"] not in (
            str(memory),
            str(client),
            str(fresh_workspace),
        )
        checkpoint = workspace / "readiness-checkpoint.private.json"
        checkpoint.write_text(
            '{"synthetic_readiness_evidence":true}\n', encoding="utf-8"
        )
        checkpoint.chmod(0o600)
        checkpoint_digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        provenance = state["provenance"]
        result: dict[str, object] = {
            "schema": "memory.behavioral-memory-endpoint-readiness.v1",
            "outcome_label": "memory_endpoint_readiness_confirmed",
            "memory_executable_digest": provenance["memory_executable_digest"],
            "memory_interpreter_digest": hashlib.sha256(
                (binaries / "python").read_bytes()
            ).hexdigest(),
            "client_executable_digest": provenance["client_executable_digest"],
            "code_mode_host_digest": provenance["code_mode_host_digest"],
            "isolation_profile_digest": provenance["isolation_profile_digest"],
            "endpoint_helper_digest": "b1" * 32,
            "bridge_transport_digest": "b2" * 32,
            "checkpoint_digest": checkpoint_digest,
            "ready": True,
            "memory_initialized": True,
            "mcp_initialized": True,
            "proxy_auth_environment_absent": True,
            "proxy_environment_isolated": True,
            "proxy_auth_home_denied": True,
            "endpoint_auth_home_denied": True,
            "endpoint_auth_environment_absent": True,
            "client_endpoint_environment_read_denied": True,
            "client_endpoint_environment_write_denied": True,
            "processes_reaped": True,
            "key_cleanup_confirmed": True,
            "runtime_removed": True,
            "cleanup_confirmed": True,
            "bridge_cleanup_confirmed": True,
            "bindings_unchanged": True,
        }
        if failure == "bindings_changed":
            result["bindings_unchanged"] = False
        elif failure == "cleanup_unknown":
            result["key_cleanup_confirmed"] = None
        elif failure == "bridge_cleanup_unknown":
            result["bridge_cleanup_confirmed"] = None
        elif failure == "client_binding_changed":
            result["client_executable_digest"] = "b3" * 32
        elif failure == "missing_checkpoint":
            checkpoint.unlink()
        elif failure == "changed_checkpoint":
            checkpoint.write_text("{}\n", encoding="utf-8")
        elif failure == "checkpoint_permissions":
            checkpoint.chmod(0o644)
        elif failure == "helper_failed":
            raise RuntimeError("Synthetic helper failure after evidence creation.")
        return result

    monkeypatch.setattr(behavioral_memory_endpoint, "verify_endpoint_readiness", verify)
    if failure is None:
        tool._require_memory_transport_readiness(state)
        assert not workspace.exists()
    else:
        with pytest.raises(tool.AcceptanceError):
            tool._require_memory_transport_readiness(state)
        assert workspace.is_dir()
        assert workspace.stat().st_mode & 0o777 == 0o700
