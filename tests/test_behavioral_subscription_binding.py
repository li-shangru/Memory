"""Subscription setup cannot reset trials or silently rewrite prior evidence."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import MANIFEST_PATH, _provenance, _tool
from test_behavioral_capability_binding import _result


def _isolation() -> dict[str, str]:
    return {
        "client_executable_digest": "55" * 32,
        "code_mode_host_digest": "88" * 32,
        "isolation_profile_digest": "99" * 32,
    }


def _authentication() -> dict[str, str]:
    return {
        "authentication_mode": "chatgpt_subscription",
        "authentication_adapter_digest": "ab" * 32,
    }


def _state(tool: ModuleType) -> dict[str, Any]:
    state = cast(
        dict[str, Any],
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH),
            trials=3,
            provenance={**_provenance(), **_isolation(), "reasoning_effort": "max"},
        ),
    )
    state["private"] = {
        "client_executable": "/synthetic/codex",
        "fixture_run_id": "SYN-SUBSCRIPTION-RUN",
    }
    for slot in state["slots"]:
        slot.update(
            client_launch_attempted=False,
            inference_started=False,
            fixture_preparation="ready",
            fixture_store_id="SYN-SUBSCRIPTION-STORE-" + slot["slot_id"],
            fixture_phases=[{"digest": "cd" * 32, "fixture_id": "SYN-SOURCE"}],
        )
    return state


def _bind(tool: ModuleType, state: dict[str, Any], root: Path) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        tool.bind_subscription_authentication(
            state,
            auth_root=root,
            authentication_digest=_authentication()["authentication_adapter_digest"],
            isolation_binding={**_isolation(), "isolation_profile_digest": "ef" * 32},
        ),
    )


def test_subscription_provenance_is_explicit_without_relabeling_old_reports() -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    prior = tool.create_run_state(manifest, trials=3, provenance=_provenance())
    old_report = json.dumps(tool.build_report(prior), sort_keys=True)
    subscribed = tool.create_run_state(
        manifest,
        trials=3,
        provenance={**_provenance(), **_isolation(), **_authentication()},
    )

    current = tool.build_report(subscribed)["provenance"]
    assert all(current[key] == value for key, value in _authentication().items())
    assert not set(_authentication()).intersection(
        tool.build_report(prior)["provenance"]
    )
    assert json.dumps(tool.build_report(prior), sort_keys=True) == old_report


@pytest.mark.parametrize(
    "changes",
    [
        {"authentication_mode": "chatgpt_subscription"},
        {"authentication_adapter_digest": "ab" * 32},
        {**_authentication(), "authentication_mode": "api_key"},
        {**_authentication(), "authentication_adapter_digest": "invalid"},
        {**_authentication(), "authentication_adapter_digest": ""},
        {**_authentication(), "client_kind": "claude"},
    ],
)
def test_authentication_binding_refuses_partial_or_unsupported_metadata(
    changes: dict[str, str],
) -> None:
    tool = _tool()
    with pytest.raises(tool.AcceptanceError):
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH),
            trials=3,
            provenance={**_provenance(), **_isolation(), **changes},
        )


def test_subscription_requires_a_bound_executor_profile() -> None:
    tool = _tool()
    with pytest.raises(tool.AcceptanceError):
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH),
            trials=3,
            provenance={**_provenance(), **_authentication()},
        )


def test_binding_preserves_every_slot_and_records_prior_provenance(
    tmp_path: Path,
) -> None:
    tool = _tool()
    state = _state(tool)
    before = copy.deepcopy(state)
    auth_root = tmp_path / "synthetic-auth-session"

    changed = _bind(tool, state, auth_root)

    assert state == before
    assert changed["slots"] == before["slots"]
    assert changed["requested_trial_count"] == before["requested_trial_count"]
    assert changed["private"]["fixture_run_id"] == before["private"]["fixture_run_id"]
    assert changed["private"]["subscription_auth_root"] == str(auth_root)
    assert (
        changed["private"]["authentication_transitions"][0]["previous_provenance"]
        == before["provenance"]
    )
    for key, value in before["provenance"].items():
        if key != "isolation_profile_digest":
            assert changed["provenance"][key] == value
    assert changed["provenance"]["isolation_profile_digest"] == "ef" * 32
    assert all(changed["provenance"][k] == v for k, v in _authentication().items())
    report = json.dumps(tool.build_report(changed), sort_keys=True)
    assert str(auth_root) not in report
    assert "SYN-SUBSCRIPTION-RUN" not in report
    assert "authentication_transitions" not in report


@pytest.mark.parametrize(
    "changes",
    [
        {"attempted": True},
        {"attempted": 0},
        {"completed": True},
        {"client_launch_attempted": True},
        {"client_launch_attempted": None},
        {"inference_started": True},
        {"inference_started": None},
        {"execution_outcome": "blocked"},
        {"execution_outcome": "failed"},
        {"execution_outcome": "interrupted"},
        {"grade_outcome": "passed"},
        {"outcome_label": "execution_interrupted"},
        {"mutation_outcome": "unchanged"},
        {"outcomes": {"retrieval": {"result": "passed"}}},
    ],
)
def test_binding_never_resets_or_relabels_a_consumed_or_ambiguous_slot(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    tool = _tool()
    state = _state(tool)
    state["slots"][7].update(changes)
    before = copy.deepcopy(state)

    with pytest.raises(tool.AcceptanceError):
        _bind(tool, state, tmp_path / "synthetic-auth-session")
    assert state == before


@pytest.mark.parametrize("field", ["client_executable_digest", "code_mode_host_digest"])
def test_authentication_transition_cannot_replace_the_client_or_host(
    tmp_path: Path, field: str
) -> None:
    tool = _tool()
    state = _state(tool)
    before = copy.deepcopy(state)
    with pytest.raises(tool.AcceptanceError):
        tool.bind_subscription_authentication(
            state,
            auth_root=tmp_path / "synthetic-auth-session",
            authentication_digest="ab" * 32,
            isolation_binding={**_isolation(), field: "ef" * 32},
        )
    assert state == before


def test_repeating_the_exact_prelaunch_binding_adds_no_new_history(
    tmp_path: Path,
) -> None:
    tool = _tool()
    root = tmp_path / "synthetic-auth-session"
    first = _bind(tool, _state(tool), root)
    assert _bind(tool, first, root) == first


def test_subscription_state_read_and_report_refuse_partial_authentication_metadata(
    tmp_path: Path,
) -> None:
    tool = _tool()
    state = _state(tool)
    state["provenance"].update(authentication_mode="chatgpt_subscription")
    with pytest.raises(tool.AcceptanceError):
        tool.build_report(state)
    path = tmp_path / tool.STATE_FILENAME
    path.write_text(json.dumps(state), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(tool.AcceptanceError):
        tool._read_state(tmp_path)


@pytest.mark.parametrize("wrong_adapter", [False, True])
def test_fresh_capability_proof_binds_the_authentication_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrong_adapter: bool
) -> None:
    tool = _tool()
    state = _bind(tool, _state(tool), tmp_path / "synthetic-auth-session")
    observed: list[object] = []
    result = {
        **_result(),
        **_authentication(),
        "isolation_profile_digest": "ef" * 32,
    }
    if wrong_adapter:
        result["authentication_adapter_digest"] = "cd" * 32

    def probe(
        client: Path,
        model: str,
        effort: str | None,
        *,
        authentication_mode: str | None = None,
    ) -> dict[str, object]:
        observed.append((client, model, effort, authentication_mode))
        return result

    monkeypatch.setattr(tool, "_codex_capability_probe", probe)
    if wrong_adapter:
        with pytest.raises(tool.TrialBlocked):
            tool._require_codex_capabilities(state)
    else:
        assert tool._require_codex_capabilities(state) == result
    assert observed == [
        (Path("/synthetic/codex"), "synthetic-model", "max", "chatgpt_subscription")
    ]


def test_subscription_artifact_revalidation_uses_the_bound_authentication_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _bind(tool, _state(tool), tmp_path / "synthetic-auth-session")
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
    observed: list[str | None] = []

    def binding(
        client: Path, *, authentication_mode: str | None = None
    ) -> dict[str, str]:
        assert client == Path("/synthetic/codex")
        observed.append(authentication_mode)
        return {**_isolation(), "isolation_profile_digest": "ef" * 32}

    monkeypatch.setattr(tool, "_codex_artifact_binding", binding)
    monkeypatch.setattr(
        tool, "_subscription_implementation_digest", lambda: "ab" * 32, raising=False
    )
    tool._revalidate_prepared_artifacts(state)
    assert observed == ["chatgpt_subscription"]


@pytest.mark.parametrize("failure", [None, "auth", "artifacts", "capabilities"])
def test_binding_command_preserves_prepared_state_until_all_prerequisites_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    tool = _tool()
    state = _state(tool)
    client = tmp_path / "codex"
    client.write_text("Synthetic executable fixture.", encoding="utf-8")
    client.chmod(0o700)
    state["private"].update(
        client_executable=str(client), manifest_path=str(MANIFEST_PATH)
    )
    tool._write_state(tmp_path, state)
    previous = (tmp_path / tool.STATE_FILENAME).read_bytes()
    observed: list[str] = []
    monkeypatch.setattr(tool, "_subscription_implementation_digest", lambda: "ab" * 32)
    monkeypatch.setattr(
        tool,
        "_codex_artifact_binding",
        lambda *_args, **_kwargs: {
            **_isolation(),
            "isolation_profile_digest": "ef" * 32,
        },
    )

    def prerequisite(name: str) -> None:
        observed.append(name)
        if failure == name:
            raise tool.AcceptanceError("Synthetic prerequisite unavailable.")

    monkeypatch.setattr(
        tool, "_validated_subscription_session", lambda *_args: prerequisite("auth")
    )
    monkeypatch.setattr(
        tool, "_revalidate_prepared_artifacts", lambda _state: prerequisite("artifacts")
    )
    monkeypatch.setattr(
        tool, "_require_codex_capabilities", lambda _state: prerequisite("capabilities")
    )
    result = tool.main(
        [
            "bind-subscription",
            "--state-root",
            str(tmp_path),
            "--auth-root",
            str(tmp_path / "synthetic-auth-session"),
        ],
        stderr=io.StringIO(),
    )
    if failure is None:
        assert result == 0
        current = tool._read_state(tmp_path)
        assert current["slots"] == state["slots"]
        assert current["provenance"]["authentication_mode"] == "chatgpt_subscription"
        assert observed == ["auth", "artifacts", "capabilities"]
    else:
        assert result == 1
        assert (tmp_path / tool.STATE_FILENAME).read_bytes() == previous


def test_missing_subscription_before_run_does_not_consume_the_fixed_roster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _bind(tool, _state(tool), tmp_path / "synthetic-auth-session")
    state["private"]["manifest_path"] = str(MANIFEST_PATH)
    state["private"].update(memory_executable="/synthetic/memory", seed_executable=None)
    tool._write_state(tmp_path, state)
    before = (tmp_path / tool.STATE_FILENAME).read_bytes()
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)

    def unavailable(_state: object) -> None:
        raise tool.TrialBlocked("subscription_authentication_unavailable")

    monkeypatch.setattr(tool, "_subscription_session", unavailable)
    errors = io.StringIO()
    assert tool.main(["run", "--state-root", str(tmp_path)], stderr=errors) == 2
    assert errors.getvalue() == "subscription_authentication_unavailable\n"
    assert (tmp_path / tool.STATE_FILENAME).read_bytes() == before


def test_lost_shared_subscription_keeps_remaining_trials_pending(
    tmp_path: Path,
) -> None:
    tool = _tool()
    state = _state(tool)
    manifest = tool.load_manifest(MANIFEST_PATH)
    attempts: list[str] = []

    def prerequisite() -> None:
        if attempts:
            raise tool.TrialBlocked("subscription_authentication_unavailable")

    def execute(*_args: object) -> object:
        attempts.append("attempt")
        raise tool.AcceptanceError("Synthetic transport failure interrupts auth lease.")

    with pytest.raises(tool.TrialBlocked):
        tool.execute_trials(
            state,
            manifest,
            tmp_path / "trials",
            execute=execute,
            before_attempt=prerequisite,
        )
    assert len(attempts) == 1
    assert state["slots"][0]["attempted"] is True
    assert state["slots"][0]["execution_outcome"] == "failed"
    assert all(
        slot["attempted"] is False and slot["execution_outcome"] == "pending"
        for slot in state["slots"][1:]
    )
