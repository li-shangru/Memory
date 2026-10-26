"""Fresh executor proof must match the exact prepared client, host and profile."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import MANIFEST_PATH, _provenance, _tool


def _binding() -> dict[str, str]:
    return {
        "client_executable_digest": "55" * 32,
        "code_mode_host_digest": "88" * 32,
        "isolation_profile_digest": "99" * 32,
    }


def _state(tool: ModuleType, *, bound: bool = True) -> dict[str, Any]:
    provenance = {**_provenance(), "reasoning_effort": "max"}
    if bound:
        provenance.update(_binding())
    state = cast(
        dict[str, Any],
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH), trials=3, provenance=provenance
        ),
    )
    state["private"] = {"client_executable": "/synthetic/codex"}
    return state


def _result() -> dict[str, object]:
    return {
        **_binding(),
        "schema": "memory.behavioral-capability-probe.v1",
        "client_kind": "codex",
        "model": "synthetic-model",
        "reasoning_effort": "max",
        "capabilities_confirmed": True,
        "outcome_label": "client_executor_capabilities_confirmed",
    }


def test_new_provenance_binds_profile_and_host_without_relabeling_legacy() -> None:
    tool = _tool()
    current = tool.build_report(_state(tool))
    old = tool.build_report(_state(tool, bound=False))

    for field in ("isolation_profile_digest", "code_mode_host_digest"):
        assert current["provenance"][field] == _binding()[field]
        assert field not in old["provenance"]


@pytest.mark.parametrize(
    "changes",
    [
        {"isolation_profile_digest": "99" * 32},
        {"code_mode_host_digest": "88" * 32},
        {"isolation_profile_digest": "bad", "code_mode_host_digest": "88" * 32},
        {
            "client_kind": "claude",
            "isolation_profile_digest": "99" * 32,
            "code_mode_host_digest": "88" * 32,
        },
    ],
)
def test_profile_binding_is_complete_codex_only_and_digest_bounded(
    changes: dict[str, str],
) -> None:
    tool = _tool()
    with pytest.raises(tool.AcceptanceError):
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH),
            trials=3,
            provenance={**_provenance(), **changes},
        )


def test_each_check_runs_a_fresh_proof_for_bound_model_and_effort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    state = _state(tool)
    observed: list[tuple[Path, str, str | None]] = []

    def probe(client: Path, model: str, effort: str | None) -> dict[str, object]:
        observed.append((client, model, effort))
        return _result()

    monkeypatch.setattr(tool, "_codex_capability_probe", probe)
    assert tool._require_codex_capabilities(state) == _result()
    assert tool._require_codex_capabilities(state) == _result()
    assert observed == [(Path("/synthetic/codex"), "synthetic-model", "max")] * 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "unknown"),
        ("client_executable_digest", "aa" * 32),
        ("code_mode_host_digest", "aa" * 32),
        ("isolation_profile_digest", "aa" * 32),
        ("model", "different-model"),
        ("reasoning_effort", "low"),
        ("capabilities_confirmed", False),
        ("outcome_label", "probe_failed"),
    ],
)
def test_capability_mismatch_cannot_authorize_actual_execution(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    tool = _tool()
    state = _state(tool)
    result = {**_result(), field: value}
    monkeypatch.setattr(tool, "_codex_capability_probe", lambda *_args: result)

    with pytest.raises(tool.TrialBlocked) as captured:
        tool._require_codex_capabilities(state)
    assert captured.value.label == "client_isolation_controls_unavailable"


def test_old_unbound_state_blocks_without_retroactively_choosing_a_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    state = _state(tool, bound=False)

    def forbidden(*_args: object) -> None:
        pytest.fail("unbound historical state reached a client probe")

    monkeypatch.setattr(tool, "_codex_capability_probe", forbidden)
    with pytest.raises(tool.TrialBlocked) as captured:
        tool._require_codex_capabilities(state)
    assert captured.value.label == "client_isolation_profile_unbound"


def test_host_or_profile_drift_refuses_prepared_artifacts_before_client_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    state = _state(tool)
    state["private"].update(
        memory_executable="/synthetic/memory",
        build_artifact="/synthetic/memory.whl",
        seed_executable="/synthetic/seed",
    )
    digests = {"codex": "55", "memory": "44", "memory.whl": "11", "seed": "66"}
    monkeypatch.setattr(tool, "_sha256_file", lambda path: digests[path.name] * 32)
    monkeypatch.setattr(
        tool, "_installed_distribution_digest", lambda *_args: "77" * 32
    )
    monkeypatch.setattr(
        tool,
        "_codex_artifact_binding",
        lambda _client: {**_binding(), "code_mode_host_digest": "aa" * 32},
    )

    with pytest.raises(tool.AcceptanceError, match="prepared artifact changed"):
        tool._revalidate_prepared_artifacts(state)


@pytest.mark.parametrize("confirmed", [True, False])
def test_capability_probe_phase_exports_separate_evidence_without_trial_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, confirmed: bool
) -> None:
    tool = _tool()
    client = tmp_path / "codex"
    client.write_text("synthetic executable metadata only", encoding="utf-8")
    client.chmod(0o700)
    output = tmp_path / "capability.json"
    result = {**_result(), "capabilities_confirmed": confirmed}
    observed: list[tuple[Path, str, str | None]] = []

    def probe(command: Path, model: str, effort: str | None) -> dict[str, object]:
        observed.append((command, model, effort))
        return result

    monkeypatch.setattr(tool, "_codex_capability_probe", probe)
    exit_status = tool.main(
        [
            "probe-capabilities",
            "--client-executable",
            str(client),
            "--model",
            "synthetic-model",
            "--reasoning-effort",
            "max",
            "--output",
            str(output),
        ]
    )

    assert exit_status == (0 if confirmed else 2)
    assert observed == [(client, "synthetic-model", "max")]
    assert json.loads(output.read_text(encoding="utf-8")) == result
    assert not (tmp_path / tool.STATE_FILENAME).exists()
