"""Optional effort provenance remains exact without rewriting old campaigns."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from argparse import Namespace
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import _stub_synthetic_codex_transport

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "synthetic_behavioral" / "manifest.json"
)


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "behavioral_effort", REPO_ROOT / "tools" / "run-behavioral-acceptance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _provenance() -> dict[str, str]:
    return {
        "client_kind": "codex",
        "client_version": "codex-cli 9.8.7",
        "model": "synthetic-model",
        "product_version": "memory 9.8.7",
        "build_digest": "11" * 32,
        "memory_executable_digest": "44" * 32,
        "client_executable_digest": "55" * 32,
        "seed_executable_digest": "66" * 32,
        "installed_distribution_digest": "77" * 32,
        "mcp_contract_digest": "22" * 32,
        "skill_digest": "33" * 32,
        "seed_mode": "synthetic_adapter",
    }


def _state(tool: ModuleType, effort: str | None = None) -> dict[str, Any]:
    provenance = _provenance()
    if effort is not None:
        provenance["reasoning_effort"] = effort
    return cast(
        dict[str, Any],
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH), trials=1, provenance=provenance
        ),
    )


def test_absent_effort_preserves_exact_legacy_state_and_report() -> None:
    tool = _tool()
    state = _state(tool)

    assert tool._canonical_digest(state) == (
        "7ff7d294d06a3eab900c8c67ecbf8a56343cf646d3a8afd32f3cadad837e6345"
    )
    assert tool._canonical_digest(tool.build_report(state)) == (
        "b95cd2d6d45e10204cd093c63212f034f43deb18a903ea066776975bb82aba53"
    )
    assert "reasoning_effort" not in json.dumps(state)
    assert "reasoning_effort" not in json.dumps(tool.build_report(state))


def test_explicit_effort_survives_private_state_and_content_free_report(
    tmp_path: Path,
) -> None:
    tool = _tool()
    state = _state(tool, "max")
    state["private"] = {"synthetic_private_content": "must-remain-private"}
    tool._write_state(tmp_path, state)

    restored = tool._read_state(tmp_path)
    assert restored["provenance"]["reasoning_effort"] == "max"
    report = tool.build_report(restored)
    assert report["provenance"]["reasoning_effort"] == "max"
    assert "must-remain-private" not in json.dumps(report)
    assert report["counts"] == tool.build_report(_state(tool))["counts"]


@pytest.mark.parametrize("value", ["", "MAX", "max\nprivate", "x" * 33, None, 7])
def test_effort_provenance_rejects_unbounded_or_nonlabel_values(value: object) -> None:
    tool = _tool()
    provenance: dict[str, object] = {**_provenance(), "reasoning_effort": value}

    with pytest.raises(tool.AcceptanceError):
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH), trials=1, provenance=provenance
        )


def test_effort_provenance_refuses_a_client_without_effort_binding() -> None:
    tool = _tool()
    provenance = {**_provenance(), "client_kind": "claude", "reasoning_effort": "max"}

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool.create_run_state(
            tool.load_manifest(MANIFEST_PATH), trials=1, provenance=provenance
        )


def _prepare_arguments(tmp_path: Path, effort: str | None) -> Namespace:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return Namespace(
        state_root=root,
        manifest=MANIFEST_PATH,
        memory=tmp_path / "memory",
        client_executable=tmp_path / "codex",
        client_kind="codex",
        seed_executable=None,
        fixture_mode="owner_review",
        build_artifact=tmp_path / "memory.whl",
        model="synthetic-model",
        reasoning_effort=effort,
        trials=1,
    )


def _stub_preparation_metadata(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tool, "_validate_executable", lambda path: path)
    monkeypatch.setattr(tool, "_probe_version", lambda *_args: "9.8.7")
    monkeypatch.setattr(
        tool, "_installed_digests", lambda _memory: ("22" * 32, "33" * 32)
    )
    monkeypatch.setattr(tool, "_sha256_file", lambda _path: "44" * 32)
    monkeypatch.setattr(
        tool,
        "_codex_artifact_binding",
        lambda _client: {
            "client_executable_digest": "44" * 32,
            "code_mode_host_digest": "88" * 32,
            "isolation_profile_digest": "99" * 32,
        },
    )
    monkeypatch.setattr(
        tool, "_installed_distribution_digest", lambda *_args: "77" * 32
    )


def test_prepare_accepts_cli_effort_and_binds_advertised_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    arguments = _prepare_arguments(tmp_path, "max")
    _stub_preparation_metadata(tool, monkeypatch)
    observed: list[tuple[Path, str]] = []

    def support(client: Path, model: str) -> frozenset[str]:
        observed.append((client, model))
        return frozenset({"low", "max"})

    monkeypatch.setattr(tool, "_codex_reasoning_efforts", support)
    parsed = tool._build_parser().parse_args(
        [
            "prepare",
            "--manifest",
            str(MANIFEST_PATH),
            "--state-root",
            str(arguments.state_root),
            "--memory",
            str(arguments.memory),
            "--build-artifact",
            str(arguments.build_artifact),
            "--client-kind",
            "codex",
            "--client-executable",
            str(arguments.client_executable),
            "--model",
            "synthetic-model",
            "--reasoning-effort",
            "max",
        ]
    )

    assert parsed.reasoning_effort == "max"
    assert tool._prepare(arguments) == 0
    assert observed == [(arguments.client_executable, "synthetic-model")]
    prepared = tool._read_state(arguments.state_root)
    assert prepared["provenance"]["reasoning_effort"] == "max"
    assert prepared["provenance"]["code_mode_host_digest"] == "88" * 32
    assert prepared["provenance"]["isolation_profile_digest"] == "99" * 32
    assert all(slot["inference_started"] is False for slot in prepared["slots"])
    assert all(slot["client_launch_attempted"] is False for slot in prepared["slots"])


@pytest.mark.parametrize("kind,effort", [("claude", "max"), ("codex", "unsupported")])
def test_unsupported_prepare_refuses_before_campaign_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, effort: str
) -> None:
    tool = _tool()
    arguments = _prepare_arguments(tmp_path, effort)
    arguments.client_kind = kind
    _stub_preparation_metadata(tool, monkeypatch)
    monkeypatch.setattr(
        tool, "_codex_reasoning_efforts", lambda *_args: frozenset({"low", "max"})
    )

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._prepare(arguments)
    assert list(arguments.state_root.iterdir()) == []


@pytest.mark.parametrize("effort", [None, "max", "low"])
def test_codex_launch_passes_exact_bound_effort_only_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, effort: str | None
) -> None:
    tool = _tool()
    _stub_synthetic_codex_transport(tool, monkeypatch)
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-codex-token")
    state = _state(tool, effort)
    state["private"] = {
        "memory_executable": str(tmp_path / "memory"),
        "client_executable": str(tmp_path / "codex"),
        "seed_executable": str(tmp_path / "seed"),
    }
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(tool, "_require_codex_capabilities", lambda _state: {})
    support_calls: list[tuple[Path, str]] = []

    def support(client: Path, model: str) -> frozenset[str]:
        support_calls.append((client, model))
        return frozenset({"low", "max"})

    monkeypatch.setattr(tool, "_codex_reasoning_efforts", support)
    monkeypatch.setattr(
        tool,
        "_store_snapshot",
        lambda *_args: {"mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32},
    )

    def fixture_command(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["skill", "install"]:
            Path(command[-1]).write_text("Synthetic checked Skill.", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(tool, "_run_text", fixture_command)
    launches: list[list[str]] = []

    def launch(command: Sequence[str], **_kwargs: object) -> tuple[int, str | None]:
        launches.append(list(command))
        return 0, None

    monkeypatch.setattr(tool, "_run_client_to_private_files", launch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = tool.load_manifest(MANIFEST_PATH)
    tool._actual_executor(state, manifest)(
        manifest.cases["SYN-BEHAVIOR-PARAPHRASE-021"],
        1,
        tmp_path / "store",
        workspace,
        tmp_path / "response.private",
    )

    assert len(launches) == 1
    command = launches[0]
    overrides = [
        value for value in command if value.startswith("model_reasoning_effort=")
    ]
    assert overrides == (
        [] if effort is None else [f'model_reasoning_effort="{effort}"']
    )
    if effort is None:
        assert support_calls == []
    else:
        assert support_calls == [(tmp_path / "codex", "synthetic-model")]
        assert command[command.index(overrides[0]) - 1] == "-c"


def test_changed_effort_support_blocks_before_fixture_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _state(tool, "max")
    state["private"] = {
        "memory_executable": str(tmp_path / "memory"),
        "client_executable": str(tmp_path / "codex"),
        "seed_executable": str(tmp_path / "seed"),
    }
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(
        tool, "_codex_reasoning_efforts", lambda *_args: frozenset({"low"})
    )
    monkeypatch.setattr(
        tool, "_run_text", lambda *_args, **_kwargs: pytest.fail("fixture command ran")
    )
    manifest = tool.load_manifest(MANIFEST_PATH)

    with pytest.raises(tool.TrialBlocked) as captured:
        tool._actual_executor(state, manifest)(
            manifest.cases["SYN-BEHAVIOR-PARAPHRASE-021"],
            1,
            tmp_path / "store",
            tmp_path / "workspace",
            tmp_path / "response.private",
        )
    assert captured.value.label == "client_reasoning_effort_unavailable"
    assert state["slots"][0]["client_launch_attempted"] is False


def test_fixture_phase_refuses_unsupported_effort_before_any_store_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _state(tool, "max")
    state["provenance"]["seed_mode"] = "owner_review"
    state["private"] = {
        "client_executable": str(tmp_path / "codex"),
        "memory_executable": str(tmp_path / "memory"),
        "manifest_path": str(MANIFEST_PATH),
    }
    monkeypatch.setattr(tool, "_private_root", lambda root: root)
    monkeypatch.setattr(tool, "_read_state", lambda _root: state)
    monkeypatch.setattr(
        tool, "_codex_reasoning_efforts", lambda *_args: frozenset({"low"})
    )
    monkeypatch.setattr(
        tool,
        "_revalidate_prepared_artifacts",
        lambda _state: None,
    )
    monkeypatch.setattr(
        tool,
        "_run_text",
        lambda *_args, **_kwargs: pytest.fail("fixture command ran"),
    )

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._fixtures(Namespace(state_root=tmp_path, slot_id=None))


def test_fixture_phase_rejects_changed_client_before_effort_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    state = _state(tool, "max")
    state["provenance"]["seed_mode"] = "owner_review"
    monkeypatch.setattr(tool, "_private_root", lambda root: root)
    monkeypatch.setattr(tool, "_read_state", lambda _root: state)

    def changed_artifact(_state: Mapping[str, Any]) -> None:
        raise tool.AcceptanceError("prepared artifact changed")

    monkeypatch.setattr(tool, "_revalidate_prepared_artifacts", changed_artifact)
    monkeypatch.setattr(
        tool,
        "_codex_reasoning_efforts",
        lambda *_args: pytest.fail("changed client executed"),
    )

    with pytest.raises(tool.AcceptanceError, match="prepared artifact changed"):
        tool._fixtures(Namespace(state_root=tmp_path, slot_id=None))


def _metadata_policy_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(REPO_ROOT / "tools"))
    return importlib.import_module("behavioral_codex_isolation")


def _permit_synthetic_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    # Script fakes exercise the protocol; shared policy tests exercise native isolation.
    module = _metadata_policy_module(monkeypatch)
    monkeypatch.setattr(
        module, "protected_command", lambda command, **_kwargs: list(command)
    )


def test_metadata_startup_policy_wraps_command_before_process_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    module = _metadata_policy_module(monkeypatch)
    client = tmp_path / "synthetic-client"
    policies: list[tuple[list[str], Path, tuple[Path, ...], int | None]] = []
    launches: list[list[str]] = []

    def protect(
        command: Sequence[str],
        *,
        policy_path: Path,
        executable_paths: Sequence[Path],
        loopback_port: int | None = None,
    ) -> list[str]:
        policies.append(
            (list(command), policy_path, tuple(executable_paths), loopback_port)
        )
        return ["synthetic-protected-launch", *command]

    def launch(command: Sequence[str], **_kwargs: object) -> subprocess.Popen[bytes]:
        assert len(policies) == 1
        assert command[0] == "synthetic-protected-launch"
        launches.append(list(command))
        raise OSError("synthetic stop before launch")

    monkeypatch.setattr(module, "protected_command", protect)
    monkeypatch.setattr(tool.subprocess, "Popen", launch)

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._codex_reasoning_efforts(client, "synthetic-model")

    assert len(launches) == 1
    command, policy, executables, network_port = policies[0]
    assert command[:2] == [str(client), "app-server"]
    assert policy.name == "startup.sb"
    assert not policy.parent.exists()
    assert executables == (client,)
    assert network_port is None


def test_metadata_policy_unavailable_refuses_before_any_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    module = _metadata_policy_module(monkeypatch)

    def unavailable(_command: Sequence[str], **_kwargs: object) -> list[str]:
        raise module.CapabilityProbeError("synthetic_policy_unavailable")

    monkeypatch.setattr(module, "protected_command", unavailable)
    monkeypatch.setattr(
        tool.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("unprotected metadata process launched"),
    )

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._codex_reasoning_efforts(tmp_path / "synthetic-client", "synthetic-model")


def _metadata_client(
    tmp_path: Path,
    pages: list[dict[str, object]],
    *,
    error_method: str | None = None,
) -> Path:
    client = tmp_path / "codex"
    client.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        f"pages = {pages!r}\n"
        f"record = pathlib.Path({str(tmp_path / 'metadata-requests.json')!r})\n"
        "calls = []\n"
        "for line in sys.stdin:\n"
        "    message = json.loads(line)\n"
        "    calls.append(message)\n"
        "    record.write_text(json.dumps({'calls':calls, 'environment':dict(os.environ), 'cwd':os.getcwd(), 'argv':sys.argv[1:]}))\n"
        "    if message['method'] == 'initialize':\n"
        "        result = {}\n"
        "    elif message['method'] == 'model/list':\n"
        "        result = pages.pop(0)\n"
        "    elif message['method'] == 'initialized':\n"
        "        continue\n"
        "    else:\n"
        "        raise SystemExit(99)\n"
        "    response = {'id':message['id'], 'result':result}\n"
        f"    if message['method'] == {error_method!r}:\n"
        "        response['error'] = {'code':-1, 'message':'synthetic metadata error'}\n"
        "    print(json.dumps(response), flush=True)\n",
        encoding="utf-8",
    )
    client.chmod(0o700)
    return client


def test_live_model_metadata_matches_exact_model_and_follows_pages_without_inference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    _permit_synthetic_metadata(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-do-not-inherit")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "unread-saved-config"))
    client = _metadata_client(
        tmp_path,
        [
            {
                "data": [
                    {
                        "model": "unrelated-model",
                        "supportedReasoningEfforts": [{"reasoningEffort": "ultra"}],
                    }
                ],
                "nextCursor": "synthetic-page-2",
            },
            {
                "data": [
                    {
                        "model": "synthetic-model",
                        "supportedReasoningEfforts": [
                            {"reasoningEffort": "low"},
                            {"reasoningEffort": "max"},
                        ],
                    }
                ],
                "nextCursor": None,
            },
        ],
    )

    assert tool._codex_reasoning_efforts(client, "synthetic-model") == frozenset(
        {"low", "max"}
    )
    record = json.loads((tmp_path / "metadata-requests.json").read_text())
    assert [row["method"] for row in record["calls"]] == [
        "initialize",
        "initialized",
        "model/list",
        "model/list",
    ]
    assert record["calls"][-1]["params"]["cursor"] == "synthetic-page-2"
    assert "OPENAI_API_KEY" not in record["environment"]
    assert "ANTHROPIC_API_KEY" not in record["environment"]
    assert record["environment"]["CODEX_HOME"] == record["environment"]["HOME"]
    assert record["environment"]["HOME"] != os.environ["CODEX_HOME"]
    assert not Path(record["environment"]["HOME"]).exists()
    assert 'cli_auth_credentials_store="file"' in record["argv"]
    assert "app-server" in record["argv"]


@pytest.mark.parametrize(
    "row",
    [
        {
            "model": "unrelated-model",
            "supportedReasoningEfforts": [{"reasoningEffort": "max"}],
        },
        {"model": "synthetic-model", "supportedReasoningEfforts": []},
        {
            "model": "synthetic-model",
            "supportedReasoningEfforts": [{"reasoningEffort": "max\nprivate"}],
        },
        {
            "model": "synthetic-model",
            "supportedReasoningEfforts": [
                {"reasoningEffort": "max"},
                {"reasoningEffort": "max"},
            ],
        },
    ],
)
def test_model_metadata_cannot_validate_wrong_or_malformed_effort_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: Mapping[str, object]
) -> None:
    tool = _tool()
    _permit_synthetic_metadata(monkeypatch)
    client = _metadata_client(tmp_path, [{"data": [dict(row)], "nextCursor": None}])

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._codex_reasoning_efforts(client, "synthetic-model")


@pytest.mark.parametrize("method", ["initialize", "model/list"])
def test_model_metadata_refuses_an_error_even_when_a_result_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    tool = _tool()
    _permit_synthetic_metadata(monkeypatch)
    client = _metadata_client(
        tmp_path,
        [
            {
                "data": [
                    {
                        "model": "synthetic-model",
                        "supportedReasoningEfforts": [{"reasoningEffort": "max"}],
                    }
                ],
                "nextCursor": None,
            }
        ],
        error_method=method,
    )

    with pytest.raises(tool.AcceptanceError, match="reasoning effort"):
        tool._codex_reasoning_efforts(client, "synthetic-model")
