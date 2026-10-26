"""Tests for repeated installed-client behavioral acceptance tooling."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from argparse import Namespace
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Protocol, cast

import pytest

from memory.model import RuntimePaths

if TYPE_CHECKING:
    from behavioral_client_lifecycle import ClientLifecycle

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "run-behavioral-acceptance.py"
MANIFEST_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "synthetic_behavioral" / "manifest.json"
)
DIMENSIONS = ("retrieval", "caveat", "freshness", "uncertainty", "final_answer")
CLIENT_SETUP_PATH = REPO_ROOT / "docs" / "client-setup.md"
CEREMONY_PATH = REPO_ROOT / "docs" / "smoke-ceremony.md"
RECORD_PATH = REPO_ROOT / "docs" / "acceptance" / "client-smoke.md"


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "run_behavioral_acceptance", TOOL_PATH
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


class _TestClientLaunch(Protocol):
    command: list[str]
    before_cleanup: Callable[[], None] | None
    lifecycle: ClientLifecycle | None


def _stub_synthetic_codex_transport(
    tool: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run inert client scripts; the real guarded transport has separate tests."""

    @contextmanager
    def command(
        client: Path,
        _memory: Path,
        _home: Path,
        workspace: Path,
        model: str,
        effort: str | None,
        *,
        events_path: Path | None = None,
        observe_lifecycle: Callable[[ClientLifecycle], None] | None = None,
    ) -> Iterator[_TestClientLaunch]:
        arguments = cast(
            list[str], tool._codex_launch_arguments(client, workspace, model, effort)
        )
        yield cast(_TestClientLaunch, tool.ClientLaunch([*arguments, "-"]))

    monkeypatch.setattr(tool, "_codex_execution_command", command)


def _complete_attempt() -> dict[str, Any]:
    status = {
        "product": "memory",
        "product_version": "9.8.7",
        "schema_version": 1,
        "store_id": "aa" * 16,
        "source_count": 2,
        "memory_count": 2,
        "searchable_count": 2,
        "unsearchable_count": 0,
        "pending_review_count": 0,
        "reindex_required": False,
        "mcp_contract_digest": "22" * 32,
        "skill_digest": "33" * 32,
        "audit_generation": 7,
    }
    return {"exit_status": 0, "before_status": status, "after_status": dict(status)}


def _passing_grades(state: dict[str, Any], manifest: Any) -> list[dict[str, Any]]:
    grades = []
    for slot in state["slots"]:
        if slot["execution_outcome"] != "completed":
            continue
        case = manifest.cases[slot["case_id"]]
        outcomes = {}
        for dimension in DIMENSIONS:
            rule = case["rubric"][dimension]
            outcomes[dimension] = {
                "result": "passed" if rule["applicable"] else "not_applicable",
                "label": rule["pass_label"],
            }
        grades.append({"slot_id": slot["slot_id"], "outcomes": outcomes})
    return grades


def test_trial_count_is_fixed_before_run_and_bounded() -> None:
    tool = _tool()

    assert tool.validate_trial_count(None) == 3
    assert tool.validate_trial_count(1) == 1
    assert tool.validate_trial_count(10) == 10
    with pytest.raises(tool.AcceptanceError, match="between 1 and 10"):
        tool.validate_trial_count(0)
    with pytest.raises(tool.AcceptanceError, match="between 1 and 10"):
        tool.validate_trial_count(11)


def test_manifest_fixes_fresh_bilingual_conditions_and_rubric_provenance() -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)

    assert tuple(manifest.cases) == (
        "SYN-BEHAVIOR-PARAPHRASE-021",
        "SYN-BEHAVIOR-BILINGUAL-ZH-022",
        "SYN-BEHAVIOR-GUARD-ZH-023",
        "SYN-BEHAVIOR-PRIORITY-024",
        "SYN-BEHAVIOR-CORRECTION-ZH-025",
        "SYN-BEHAVIOR-READONLY-026",
    )
    assert manifest.rubric_version == "behavioral-rubric-2026-09-03"
    assert len(manifest.digest) == 64
    assert len(manifest.rubric_digest) == 64
    assert {case["language"] for case in manifest.cases.values()} == {"en", "zh"}
    for case in manifest.cases.values():
        for rule in case["rubric"].values():
            assert isinstance(rule["criterion"], str)
            assert rule["criterion"].strip() == rule["criterion"]
            assert len(rule["criterion"]) >= 24
    assert {case["condition"] for case in manifest.cases.values()} == {
        "non_obvious_paraphrase",
        "bilingual_retrieval",
        "governing_caveat",
        "explicit_priority",
        "conflicting_stale_predecessor_and_approved_correction",
        "read_only_advice",
    }
    assert all(
        case["seed_profile"]["mode"] == "synthetic_adapter"
        for case in manifest.cases.values()
    )


def test_manifest_time_sensitive_language_uses_absolute_dates() -> None:
    manifest = _tool().load_manifest(MANIFEST_PATH)
    serialized = json.dumps(manifest.cases, ensure_ascii=False).casefold()

    for relative in (
        "next week",
        "tomorrow",
        "this tuesday",
        "this season",
        "下周",
        "明早",
        "这周二",
    ):
        assert relative not in serialized
    for absolute in ("2026-09-04", "2026-09-07", "2026-09-08", "2026-09-11"):
        assert absolute in serialized


def test_manifest_rejects_a_rubric_rule_without_a_human_criterion(
    tmp_path: Path,
) -> None:
    tool = _tool()
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    del payload["cases"][0]["rubric"]["retrieval"]["criterion"]
    invalid = tmp_path / "manifest.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(tool.AcceptanceError, match="rubric rule structure"):
        tool.load_manifest(invalid)


def test_plan_preserves_every_fixed_slot_and_complete_provenance() -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)

    state = tool.create_run_state(manifest, trials=2, provenance=_provenance())

    assert state["requested_trial_count"] == 2
    assert len(state["slots"]) == len(manifest.cases) * 2
    assert [slot["trial"] for slot in state["slots"][:2]] == [1, 2]
    assert all(slot["execution_outcome"] == "pending" for slot in state["slots"])
    assert state["provenance"] == {
        **_provenance(),
        "manifest_schema": manifest.schema,
        "manifest_version": manifest.version,
        "manifest_digest": manifest.digest,
        "rubric_version": manifest.rubric_version,
        "rubric_digest": manifest.rubric_digest,
    }


def test_execution_uses_unique_private_runtime_and_session_for_every_slot(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=2, provenance=_provenance())
    observed: list[tuple[Path, Path, Path]] = []

    def execute(
        _case: dict[str, Any],
        _trial: int,
        home: Path,
        workspace: Path,
        response_path: Path,
    ) -> dict[str, Any]:
        observed.append((home, workspace, response_path))
        response_path.write_text("private synthetic response", encoding="utf-8")
        return _complete_attempt()

    tool.execute_trials(state, manifest, tmp_path, execute=execute)

    assert len(observed) == len(state["slots"])
    assert len({home for home, _workspace, _response in observed}) == len(observed)
    assert len({workspace for _home, workspace, _response in observed}) == len(observed)
    assert len({response for _home, _workspace, response in observed}) == len(observed)
    assert all(home.parent == workspace.parent for home, workspace, _ in observed)
    assert all(path.stat().st_mode & 0o077 == 0 for paths in observed for path in paths)
    assert all(slot["execution_outcome"] == "completed" for slot in state["slots"])


def test_execution_preserves_blocked_and_failed_slots_without_retry(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    attempts: list[str] = []

    def execute(
        case: dict[str, Any],
        _trial: int,
        _home: Path,
        _workspace: Path,
        _response_path: Path,
    ) -> dict[str, Any]:
        attempts.append(case["case_id"])
        if len(attempts) == 1:
            raise tool.TrialBlocked("client_authentication_unavailable")
        if len(attempts) == 2:
            result = _complete_attempt()
            result["exit_status"] = 7
            return result
        return _complete_attempt()

    tool.execute_trials(state, manifest, tmp_path, execute=execute)

    assert len(attempts) == len(manifest.cases)
    assert state["slots"][0]["execution_outcome"] == "blocked"
    assert state["slots"][0]["outcome_label"] == "client_authentication_unavailable"
    assert state["slots"][1]["execution_outcome"] == "failed"
    assert state["slots"][1]["outcome_label"] == "client_exit_nonzero"
    assert all(slot["execution_outcome"] != "pending" for slot in state["slots"])


def test_execution_persists_interrupted_before_creating_or_invoking(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    snapshots: list[dict[str, Any]] = []
    invoked = False

    def persist(current: dict[str, Any]) -> None:
        snapshots.append(json.loads(json.dumps(current)))
        raise KeyboardInterrupt

    def execute(*_args: object) -> dict[str, Any]:
        nonlocal invoked
        invoked = True
        return _complete_attempt()

    with pytest.raises(KeyboardInterrupt):
        tool.execute_trials(
            state,
            manifest,
            tmp_path / "private-trials",
            execute=execute,
            persist=persist,
        )

    first = snapshots[0]["slots"][0]
    assert first["attempted"] is True
    assert first["execution_outcome"] == "interrupted"
    assert first["outcome_label"] == "execution_interrupted"
    assert invoked is False
    assert not (tmp_path / "private-trials").exists()


def test_changed_store_state_fails_the_read_only_trial(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())

    def execute(
        _case: dict[str, Any],
        _trial: int,
        _home: Path,
        _workspace: Path,
        _response_path: Path,
    ) -> dict[str, Any]:
        result = _complete_attempt()
        result["after_status"]["pending_review_count"] = 1
        return result

    tool.execute_trials(state, manifest, tmp_path, execute=execute)

    assert all(slot["mutation_outcome"] == "changed" for slot in state["slots"])
    assert all(slot["execution_outcome"] == "failed" for slot in state["slots"])
    assert all(slot["outcome_label"] == "store_mutated" for slot in state["slots"])


def test_audit_generation_change_fails_when_all_status_counts_match(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())

    def execute(*_args: object) -> dict[str, Any]:
        result = _complete_attempt()
        result["after_status"]["audit_generation"] = 8
        return result

    tool.execute_trials(state, manifest, tmp_path, execute=execute)

    assert all(slot["mutation_outcome"] == "changed" for slot in state["slots"])
    assert all(slot["execution_outcome"] == "failed" for slot in state["slots"])
    assert all(slot["outcome_label"] == "store_mutated" for slot in state["slots"])


def test_store_identity_change_fails_when_all_status_counts_match(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())

    def execute(*_args: object) -> dict[str, Any]:
        result = _complete_attempt()
        result["after_status"]["store_id"] = "bb" * 16
        return result

    tool.execute_trials(state, manifest, tmp_path, execute=execute)

    assert all(slot["mutation_outcome"] == "changed" for slot in state["slots"])
    assert all(slot["execution_outcome"] == "failed" for slot in state["slots"])
    assert all(slot["outcome_label"] == "store_mutated" for slot in state["slots"])


def _write_executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _bind_test_artifacts(
    tool: Any,
    state: dict[str, Any],
    tmp_path: Path,
    *,
    memory: Path,
    client: Path,
    seed: Path,
) -> None:
    build = tmp_path / "memory.whl"
    build.write_bytes(b"synthetic exact build")
    state["provenance"].update(
        {
            "build_digest": tool._sha256_file(build),
            "memory_executable_digest": tool._sha256_file(memory),
            "client_executable_digest": tool._sha256_file(client),
            "seed_executable_digest": tool._sha256_file(seed),
            "installed_distribution_digest": "44" * 32,
        }
    )
    state["private"] = {
        "manifest_path": str(MANIFEST_PATH),
        "memory_executable": str(memory),
        "client_executable": str(client),
        "seed_executable": str(seed),
        "build_artifact": str(build),
    }
    if state["provenance"]["client_kind"] == "codex":
        _write_executable(
            client.parent / "codex-code-mode-host", "raise SystemExit(0)\n"
        )
        state["provenance"].update(tool._codex_artifact_binding(client))


def test_actual_codex_executor_runs_exact_isolated_command_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    _stub_synthetic_codex_transport(tool, monkeypatch)
    manifest = tool.load_manifest(MANIFEST_PATH)
    command_log = tmp_path / "commands.jsonl"
    monkeypatch.setenv("MEMORY_BEHAVIOR_COMMAND_LOG", str(command_log))
    monkeypatch.setenv("MEMORY_BEHAVIOR_UNRELATED", "must-not-reach-client")
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-codex-token")
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    memory = _write_executable(
        bin_dir / "memory",
        """
import json, os, pathlib, sys
with open(os.environ["MEMORY_BEHAVIOR_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"program": "memory", "argv": sys.argv[1:]}) + "\\n")
if sys.argv[1] == "status":
    print(json.dumps({
        "product": "memory", "product_version": "9.8.7", "schema_version": 1,
        "store_id": "aa" * 16, "source_count": 2, "memory_count": 2,
        "searchable_count": 2, "unsearchable_count": 0,
        "pending_review_count": 0, "reindex_required": False,
        "mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32,
    }))
elif sys.argv[1:3] == ["skill", "install"]:
    target = pathlib.Path(sys.argv[sys.argv.index("--target") + 1])
    target.write_text("synthetic exact skill\\n", encoding="utf-8")
raise SystemExit(0)
""",
    )
    _write_executable(
        bin_dir / "python",
        f"log_path = {str(command_log)!r}\n"
        + """
import json, os, sys
with open(log_path, "a", encoding="utf-8") as log:
    program = "distribution-probe" if sys.argv[-1].endswith(".whl") else "owner-snapshot"
    log.write(json.dumps({"program": program, "argv": sys.argv[1:]}) + "\\n")
if sys.argv[-1].endswith(".whl"):
    print(json.dumps({"matched": True, "distribution_digest": "44" * 32}))
else:
    print(json.dumps({"audit_generation": 7}))
""",
    )
    seed = _write_executable(
        tmp_path / "seed",
        """
import json, os, sys
with open(os.environ["MEMORY_BEHAVIOR_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"program": "seed", "argv": sys.argv[1:]}) + "\\n")
""",
    )
    client = _write_executable(
        tmp_path / "codex",
        f"""
import json, os, pathlib, sys
features = {list(tool.CODEX_DISABLED_FEATURES)!r}
is_feature_probe = sys.argv[-2:] == ["features", "list"]
prompt = "" if is_feature_probe else sys.stdin.read()
with pathlib.Path({str(command_log)!r}).open("a", encoding="utf-8") as log:
    log.write(json.dumps({{"program": "codex-features" if is_feature_probe else "codex", "argv": sys.argv[1:], "unrelated": os.environ.get("MEMORY_BEHAVIOR_UNRELATED"), "authentication": os.environ.get("CODEX_API_KEY"), "prompt": prompt}}) + "\\n")
if is_feature_probe:
    pathlib.Path(os.environ["CODEX_HOME"], "probe-state").write_text("synthetic", encoding="utf-8")
    print("\\n".join(f"{{feature}} stable false" for feature in features))
else:
    print("private synthetic answer")
""",
    )
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    _bind_test_artifacts(tool, state, tmp_path, memory=memory, client=client, seed=seed)

    def capability_probe(
        command: Path, model: str, effort: str | None
    ) -> dict[str, object]:
        with command_log.open("a", encoding="utf-8") as log:
            log.write(json.dumps({"program": "codex-capabilities"}) + "\n")
        assert command == client and model == "synthetic-model" and effort is None
        return {
            **tool._codex_artifact_binding(client),
            "schema": "memory.behavioral-capability-probe.v1",
            "client_kind": "codex",
            "model": model,
            "capabilities_confirmed": True,
            "outcome_label": "client_executor_capabilities_confirmed",
        }

    monkeypatch.setattr(tool, "_codex_capability_probe", capability_probe)
    trial_root = tmp_path / "trial"
    home = trial_root / "store"
    workspace = trial_root / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    response_path = trial_root / "response.private"
    response_path.touch(mode=0o600)

    result = tool._actual_executor(state, manifest)(
        manifest.cases["SYN-BEHAVIOR-PARAPHRASE-021"],
        1,
        home,
        workspace,
        response_path,
    )
    calls = [json.loads(line) for line in command_log.read_text().splitlines()]

    assert result["before_status"]["audit_generation"] == 7
    assert result["after_status"]["audit_generation"] == 7
    assert [call["program"] for call in calls] == [
        "distribution-probe",
        "codex-capabilities",
        "memory",
        "seed",
        "memory",
        "owner-snapshot",
        "memory",
        "memory",
        "codex",
        "memory",
        "owner-snapshot",
    ]
    assert calls[2]["argv"] == ["init", "--home", str(home)]
    assert calls[3]["argv"][-2:] == ["--home", str(home)]
    assert calls[4]["argv"] == ["status", "--home", str(home), "--json"]
    assert calls[5]["argv"][-1] == str(home)
    skill = workspace / ".agents" / "skills" / "using-memory" / "SKILL.md"
    assert calls[6]["argv"] == ["skill", "install", "--target", str(skill)]
    assert calls[7]["argv"] == ["skill", "check", "--target", str(skill)]
    codex = calls[8]
    assert "--ephemeral" in codex["argv"]
    assert "--ignore-user-config" in codex["argv"]
    assert "--ignore-rules" in codex["argv"]
    assert "--strict-config" in codex["argv"]
    assert codex["argv"][codex["argv"].index("--sandbox") + 1] == "read-only"
    assert not any(value.startswith("sandbox_permissions=") for value in codex["argv"])
    assert 'shell_environment_policy.inherit="none"' in codex["argv"]
    assert "features.code_mode.enabled=true" in codex["argv"]
    assert (
        'features.code_mode.excluded_tool_namespaces=["functions","web","clock","collaboration"]'
        in codex["argv"]
    )
    assert "agents.enabled=false" in codex["argv"]
    assert 'web_search="disabled"' in codex["argv"]
    disabled_features = {
        codex["argv"][index + 1]
        for index, argument in enumerate(codex["argv"])
        if argument == "--disable"
    }
    assert {
        "shell_tool",
        "unified_exec",
        "view_image",
        "shell_snapshot",
        "shell_snapshot_v2",
        "workspace_dependencies",
        "skill_search",
    } <= disabled_features
    assert not {"code_mode", "code_mode_host"}.intersection(disabled_features)
    assert calls[1]["program"] == "codex-capabilities"
    assert codex["unrelated"] is None
    assert codex["authentication"] == "synthetic-codex-token"
    assert "synthetic exact skill" in codex["prompt"]
    assert calls[9]["argv"] == ["status", "--home", str(home), "--json"]
    assert response_path.read_text(encoding="utf-8") == "private synthetic answer\n"
    assert os.stat(skill).st_mode & stat.S_IRUSR
    assert state["slots"][0]["inference_started"] is None
    assert state["slots"][0]["client_launch_attempted"] is True


def test_codex_isolation_probe_rejects_a_disabled_feature_that_remains_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    enabled_feature = tool.CODEX_DISABLED_FEATURES[0]
    client = _write_executable(
        tmp_path / "codex",
        f"""
import sys
features = {list(tool.CODEX_DISABLED_FEATURES)!r}
if sys.argv[-2:] == ["features", "list"]:
    for feature in features:
        enabled = "true" if feature == {enabled_feature!r} else "false"
        print(f"{{feature}} stable {{enabled}}")
    raise SystemExit(0)
raise SystemExit(99)
""",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    assert tool._codex_isolation_controls_supported(client, workspace) is False
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    state = {
        "private": {
            "memory_executable": str(tmp_path / "memory"),
            "client_executable": str(client),
            "seed_executable": str(tmp_path / "seed"),
        },
        "provenance": {
            "client_kind": "codex",
            "model": "synthetic-model",
            "client_executable_digest": "55" * 32,
            "code_mode_host_digest": "88" * 32,
            "isolation_profile_digest": "99" * 32,
        },
    }
    monkeypatch.setattr(
        tool,
        "_codex_capability_probe",
        lambda *_args: {"capabilities_confirmed": False},
    )
    manifest = tool.load_manifest(MANIFEST_PATH)
    with pytest.raises(tool.TrialBlocked) as captured:
        tool._actual_executor(state, manifest)(
            manifest.cases["SYN-BEHAVIOR-PARAPHRASE-021"],
            1,
            tmp_path / "store",
            workspace,
            tmp_path / "response.private",
        )
    assert captured.value.label == "client_isolation_controls_unavailable"


def test_codex_isolation_probe_accepts_multiword_lifecycle_labels(
    tmp_path: Path,
) -> None:
    tool = _tool()
    multiword_feature = tool.CODEX_DISABLED_FEATURES[0]
    client = _write_executable(
        tmp_path / "codex",
        f"""
import sys
features = {list(tool.CODEX_DISABLED_FEATURES)!r}
if sys.argv[-2:] == ["features", "list"]:
    for feature in features:
        lifecycle = "under development" if feature == {multiword_feature!r} else "stable"
        print(f"{{feature}} {{lifecycle}} false")
    raise SystemExit(0)
raise SystemExit(99)
""",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    assert tool._codex_isolation_controls_supported(client, workspace) is True


def test_client_output_is_streamed_to_private_files_with_a_strict_utf8_byte_cap(
    tmp_path: Path,
) -> None:
    tool = _tool()
    response_path = tmp_path / "client-response.private"
    stderr_path = tmp_path / "client-stderr.private"
    program = (
        "import sys;"
        f"text='界'*{tool.PRIVATE_OUTPUT_LIMIT};"
        "sys.stdout.write(text);sys.stdout.flush();"
        "sys.stderr.write(text);sys.stderr.flush()"
    )

    exit_status, failure_label = tool._run_client_to_private_files(
        [sys.executable, "-c", program],
        environment=os.environ,
        cwd=tmp_path,
        input_text=None,
        stdout_path=response_path,
        stderr_path=stderr_path,
        timeout=5,
    )

    assert exit_status == 0
    assert failure_label is None
    assert 0 < response_path.stat().st_size <= tool.PRIVATE_OUTPUT_LIMIT
    assert 0 < stderr_path.stat().st_size <= tool.PRIVATE_OUTPUT_LIMIT
    response_path.read_text(encoding="utf-8")
    stderr_path.read_text(encoding="utf-8")


def test_client_interrupt_always_kills_reaps_and_drains_the_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    response_path = tmp_path / "client-response.private"
    stderr_path = tmp_path / "client-stderr.private"
    original_wait = tool.subprocess.Popen.wait
    observed: dict[str, Any] = {}

    def interrupt_once(process: Any, timeout: float | None = None) -> int:
        observed["process"] = process
        if not observed.get("interrupted"):
            observed["interrupted"] = True
            raise KeyboardInterrupt
        return int(original_wait(process, timeout=timeout))

    monkeypatch.setattr(tool.subprocess.Popen, "wait", interrupt_once)
    orphaned = False
    try:
        with pytest.raises(KeyboardInterrupt):
            tool._run_client_to_private_files(
                [
                    sys.executable,
                    "-c",
                    "import os,time;os.write(1,b'partial');time.sleep(10)",
                ],
                environment=os.environ,
                cwd=tmp_path,
                input_text=None,
                stdout_path=response_path,
                stderr_path=stderr_path,
                timeout=5,
            )
    finally:
        process = observed.get("process")
        if process is not None and process.poll() is None:
            orphaned = True
            tool._kill_client_process(process)
            original_wait(process)

    process = observed["process"]
    assert orphaned is False
    assert process.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)
    response_path.read_text(encoding="utf-8")
    stderr_path.read_text(encoding="utf-8")


def test_actual_claude_executor_disables_builtin_tools_and_sanitizes_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    command_log = tmp_path / "commands.jsonl"
    monkeypatch.setenv("MEMORY_BEHAVIOR_COMMAND_LOG", str(command_log))
    monkeypatch.setenv("MEMORY_BEHAVIOR_UNRELATED", "must-not-reach-client")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-auth-token")
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    memory = _write_executable(
        bin_dir / "memory",
        """
import json, os, pathlib, sys
with open(os.environ["MEMORY_BEHAVIOR_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"program": "memory", "argv": sys.argv[1:]}) + "\\n")
if sys.argv[1] == "status":
    print(json.dumps({
        "product": "memory", "product_version": "9.8.7", "schema_version": 1,
        "store_id": "aa" * 16, "source_count": 2, "memory_count": 2,
        "searchable_count": 2, "unsearchable_count": 0,
        "pending_review_count": 0, "reindex_required": False,
        "mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32,
    }))
elif sys.argv[1:3] == ["skill", "install"]:
    target = pathlib.Path(sys.argv[sys.argv.index("--target") + 1])
    target.write_text("synthetic exact skill\\n", encoding="utf-8")
raise SystemExit(0)
""",
    )
    _write_executable(
        bin_dir / "python",
        f"log_path = {str(command_log)!r}\n"
        + """
import json, os, sys
with open(log_path, "a", encoding="utf-8") as log:
    program = "distribution-probe" if sys.argv[-1].endswith(".whl") else "owner-snapshot"
    log.write(json.dumps({"program": program, "argv": sys.argv[1:]}) + "\\n")
if sys.argv[-1].endswith(".whl"):
    print(json.dumps({"matched": True, "distribution_digest": "44" * 32}))
else:
    print(json.dumps({"audit_generation": 7}))
""",
    )
    seed = _write_executable(
        tmp_path / "seed",
        """
import json, os, sys
with open(os.environ["MEMORY_BEHAVIOR_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"program": "seed", "argv": sys.argv[1:]}) + "\\n")
""",
    )
    client = _write_executable(
        tmp_path / "claude",
        f"""
import json, os, pathlib, sys
configuration = pathlib.Path(sys.argv[sys.argv.index("--mcp-config") + 1])
with pathlib.Path({str(command_log)!r}).open("a", encoding="utf-8") as log:
    log.write(json.dumps({{
        "program": "claude",
        "argv": sys.argv[1:],
        "mcp_config": configuration.read_text(encoding="utf-8"),
        "unrelated": os.environ.get("MEMORY_BEHAVIOR_UNRELATED"),
        "oauth": os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"),
        "skip_history": os.environ.get("CLAUDE_CODE_SKIP_PROMPT_HISTORY"),
    }}) + "\\n")
print("private synthetic answer")
""",
    )
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["provenance"]["client_kind"] = "claude"
    state["provenance"]["client_version"] = "9.8.7 (Claude Code)"
    _bind_test_artifacts(tool, state, tmp_path, memory=memory, client=client, seed=seed)
    trial_root = tmp_path / "trial"
    home = trial_root / "store"
    workspace = trial_root / "workspace"
    home.mkdir(parents=True)
    workspace.mkdir()
    response_path = trial_root / "response.private"
    response_path.touch(mode=0o600)

    result = tool._actual_executor(state, manifest)(
        manifest.cases["SYN-BEHAVIOR-PARAPHRASE-021"],
        1,
        home,
        workspace,
        response_path,
    )
    calls = [json.loads(line) for line in command_log.read_text().splitlines()]
    claude = calls[7]

    assert result["before_status"]["audit_generation"] == 7
    assert result["after_status"]["audit_generation"] == 7
    assert [call["program"] for call in calls] == [
        "distribution-probe",
        "memory",
        "seed",
        "memory",
        "owner-snapshot",
        "memory",
        "memory",
        "claude",
        "memory",
        "owner-snapshot",
    ]
    assert "--restricted" in claude["argv"]
    assert "--no-session-persistence" in claude["argv"]
    assert claude["argv"][claude["argv"].index("--tools") + 1] == ""
    assert claude["argv"][claude["argv"].index("--permission-mode") + 1] == ("dontAsk")
    assert claude["argv"][claude["argv"].index("--permission-prompts") + 1] == ("none")
    assert claude["argv"][claude["argv"].index("--allowedTools") + 1] == (
        "mcp__memory_behavioral_acceptance"
    )
    assert "--strict-mcp-config" in claude["argv"]
    assert claude["unrelated"] is None
    assert claude["oauth"] == "synthetic-auth-token"
    assert claude["skip_history"] == "1"
    assert "synthetic exact skill" in " ".join(claude["argv"])
    assert str(home) in claude["mcp_config"]
    assert not (workspace / "claude-mcp.private.json").exists()


def test_timed_out_client_still_checks_mutation_and_store_mutated_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    _stub_synthetic_codex_transport(tool, monkeypatch)
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-codex-token")
    monkeypatch.setattr(tool, "_require_codex_capabilities", lambda _state: {})
    manifest = tool.load_manifest(MANIFEST_PATH)
    generation = tmp_path / "generation"
    generation.write_text("7", encoding="utf-8")
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    memory = _write_executable(
        bin_dir / "memory",
        """
import json, pathlib, sys
if sys.argv[1] == "status":
    print(json.dumps({
        "product": "memory", "product_version": "9.8.7", "schema_version": 1,
        "store_id": "aa" * 16, "source_count": 2, "memory_count": 2,
        "searchable_count": 2, "unsearchable_count": 0,
        "pending_review_count": 0, "reindex_required": False,
        "mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32,
    }))
elif sys.argv[1:3] == ["skill", "install"]:
    target = pathlib.Path(sys.argv[sys.argv.index("--target") + 1])
    target.write_text("synthetic exact skill\\n", encoding="utf-8")
""",
    )
    _write_executable(
        bin_dir / "python",
        f"""
import json, pathlib, sys
if sys.argv[-1].endswith(".whl"):
    print(json.dumps({{"matched": True, "distribution_digest": "44" * 32}}))
else:
    print(json.dumps({{"audit_generation": int(pathlib.Path({str(generation)!r}).read_text())}}))
""",
    )
    seed = _write_executable(tmp_path / "seed", "")
    client = _write_executable(
        tmp_path / "codex",
        f"""
import os, pathlib, sys, time
features = {list(tool.CODEX_DISABLED_FEATURES)!r}
if sys.argv[-2:] == ["features", "list"]:
    print("\\n".join(f"{{feature}} stable false" for feature in features))
    raise SystemExit(0)
pathlib.Path({str(generation)!r}).write_text("8", encoding="utf-8")
os.write(1, b"private partial stdout")
os.write(2, b"private partial stderr")
time.sleep(10)
""",
    )
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    for prior_slot in state["slots"][1:]:
        prior_slot.update(
            attempted=True,
            execution_outcome="blocked",
            outcome_label="synthetic_prior_block",
        )
    _bind_test_artifacts(tool, state, tmp_path, memory=memory, client=client, seed=seed)
    # Let the synthetic interpreter reach its writes before timing out in its
    # ten-second sleep, including while other verification uses the machine.
    monkeypatch.setattr(tool, "CLIENT_TIMEOUT_SECONDS", 1)
    trial_root = tmp_path / "trials"
    tool.execute_trials(
        state,
        manifest,
        trial_root,
        execute=tool._actual_executor(state, manifest),
    )

    slot = state["slots"][0]
    assert slot["mutation_outcome"] == "changed"
    assert slot["execution_outcome"] == "failed"
    assert slot["outcome_label"] == "store_mutated"
    private_trial = trial_root / "trial-001"
    assert (private_trial / "client-response.private").read_text(
        encoding="utf-8"
    ) == "private partial stdout"
    assert (private_trial / "client-stderr.private").read_text(
        encoding="utf-8"
    ) == "private partial stderr"


def test_replaced_prepared_client_is_blocked_before_any_client_launch(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    memory = _write_executable(bin_dir / "memory", "raise SystemExit(0)\n")
    _write_executable(bin_dir / "python", "raise SystemExit(0)\n")
    seed = _write_executable(tmp_path / "seed", "raise SystemExit(0)\n")
    launched = tmp_path / "client-launched"
    client = _write_executable(tmp_path / "codex", "raise SystemExit(0)\n")
    build = tmp_path / "memory.whl"
    build.write_bytes(b"synthetic exact build")
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["provenance"].update(
        {
            "build_digest": tool._sha256_file(build),
            "memory_executable_digest": tool._sha256_file(memory),
            "client_executable_digest": tool._sha256_file(client),
            "seed_executable_digest": tool._sha256_file(seed),
            "installed_distribution_digest": "44" * 32,
        }
    )
    state["private"] = {
        "manifest_path": str(MANIFEST_PATH),
        "memory_executable": str(memory),
        "client_executable": str(client),
        "seed_executable": str(seed),
        "build_artifact": str(build),
    }
    _write_executable(
        client,
        f"""
import pathlib
pathlib.Path({str(launched)!r}).write_text("launched", encoding="utf-8")
""",
    )

    tool.execute_trials(
        state,
        manifest,
        tmp_path / "trials",
        execute=tool._actual_executor(state, manifest),
    )

    assert state["slots"][0]["execution_outcome"] == "blocked"
    assert state["slots"][0]["outcome_label"] == "prepared_artifact_changed"
    assert not launched.exists()


def test_installed_distribution_probe_binds_the_exact_build_artifact(
    tmp_path: Path,
) -> None:
    tool = _tool()
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    memory = _write_executable(bin_dir / "memory", "raise SystemExit(0)\n")
    observed = tmp_path / "observed-artifact"
    _write_executable(
        bin_dir / "python",
        f"""
import json, pathlib, sys
pathlib.Path({str(observed)!r}).write_text(sys.argv[-1], encoding="utf-8")
print(json.dumps({{"matched": True, "distribution_digest": "44" * 32}}))
""",
    )
    build = tmp_path / "memory.whl"
    build.write_bytes(b"synthetic exact build")

    digest = tool._installed_distribution_digest(memory, build)

    assert digest == "44" * 32
    assert observed.read_text(encoding="utf-8") == str(build)


def test_grading_requires_every_completed_slot_and_every_dimension(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    tool.execute_trials(
        state,
        manifest,
        tmp_path,
        execute=lambda *_args: _complete_attempt(),
    )
    grades = _passing_grades(state, manifest)

    with pytest.raises(tool.AcceptanceError, match="every completed slot"):
        tool.grade_trials(state, manifest, grades[:-1])
    incomplete = json.loads(json.dumps(grades))
    del incomplete[0]["outcomes"]["freshness"]
    with pytest.raises(tool.AcceptanceError, match="all rubric dimensions"):
        tool.grade_trials(state, manifest, incomplete)

    tool.grade_trials(state, manifest, grades)
    assert all(slot["grade_outcome"] == "passed" for slot in state["slots"])


def test_grading_refuses_manifest_or_rubric_drift_from_the_executed_run(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    tool.execute_trials(
        state,
        manifest,
        tmp_path / "trials",
        execute=lambda *_args: _complete_attempt(),
    )
    changed_document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    changed_document["cases"][0]["rubric"]["retrieval"]["criterion"] += (
        " This changed criterion belongs to a different reviewed rubric."
    )
    changed_path = tmp_path / "changed-manifest.json"
    changed_path.write_text(json.dumps(changed_document), encoding="utf-8")
    changed_manifest = tool.load_manifest(changed_path)

    with pytest.raises(tool.AcceptanceError, match="prepared manifest"):
        tool.grade_trials(
            state,
            changed_manifest,
            _passing_grades(state, changed_manifest),
        )

    assert all(slot["grade_outcome"] == "ungraded" for slot in state["slots"])


def test_grade_command_checks_and_applies_one_exact_grade_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    tool.execute_trials(
        state,
        manifest,
        tmp_path / "trials",
        execute=lambda *_args: _complete_attempt(),
    )
    state["private"] = {"manifest_path": str(MANIFEST_PATH)}
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    tool._write_state(state_root, state)
    passing = {
        "schema": "memory.behavioral-acceptance-grades.v1",
        "manifest_digest": manifest.digest,
        "rubric_digest": manifest.rubric_digest,
        "grades": _passing_grades(state, manifest),
    }
    changed = json.loads(json.dumps(passing))
    changed["grades"][0]["outcomes"]["retrieval"] = {
        "result": "failed",
        "label": "replacement_document_was_not_verified",
    }
    grades_path = tmp_path / "grades.json"
    grades_path.write_text(json.dumps(passing), encoding="utf-8")
    changed_bytes = json.dumps(changed).encode("utf-8")
    original_read_bytes = Path.read_bytes
    grade_reads = 0

    def replace_after_read(path: Path) -> bytes:
        nonlocal grade_reads
        raw = original_read_bytes(path)
        if path == grades_path:
            grade_reads += 1
            if grade_reads == 1:
                path.write_bytes(changed_bytes)
        return raw

    monkeypatch.setattr(Path, "read_bytes", replace_after_read)

    result = tool._grade(Namespace(state_root=state_root, grades=grades_path))
    persisted = tool._read_state(state_root)

    assert result == 0
    assert grade_reads == 1
    assert all(slot["grade_outcome"] == "passed" for slot in persisted["slots"])


def test_failed_grade_is_immutable_and_cannot_be_regraded_as_passed(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    tool.execute_trials(
        state,
        manifest,
        tmp_path,
        execute=lambda *_args: _complete_attempt(),
    )
    failed = _passing_grades(state, manifest)
    failed[0]["outcomes"]["retrieval"] = {
        "result": "failed",
        "label": "required_evidence_not_applied",
    }
    tool.grade_trials(state, manifest, failed)
    frozen = json.loads(json.dumps(state["slots"]))

    with pytest.raises(tool.AcceptanceError, match="already graded"):
        tool.grade_trials(state, manifest, _passing_grades(state, manifest))

    assert state["slots"] == frozen
    assert state["slots"][0]["grade_outcome"] == "failed"


def test_report_has_explicit_denominators_and_no_private_material(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=2, provenance=_provenance())
    counter = 0

    def execute(*_args: object) -> dict[str, Any]:
        nonlocal counter
        counter += 1
        if counter == 1:
            raise tool.TrialBlocked("client_authentication_unavailable")
        return _complete_attempt()

    tool.execute_trials(state, manifest, tmp_path, execute=execute)
    grades = _passing_grades(state, manifest)
    grades[0]["outcomes"]["final_answer"] = {
        "result": "failed",
        "label": "final_answer_did_not_apply_evidence",
    }
    tool.grade_trials(state, manifest, grades)

    report = tool.build_report(state)
    serialized = json.dumps(report, sort_keys=True)

    assert report["counts"] == {
        "requested": 12,
        "attempted": 12,
        "completed": 11,
        "passed": 10,
    }
    assert report["pass_rate"] == {"numerator": 10, "denominator": 12}
    assert all(row["pass_rate"]["denominator"] == 2 for row in report["conditions"])
    assert report["provenance"]["rubric_digest"] == manifest.rubric_digest
    for forbidden in (
        "private synthetic response",
        str(tmp_path),
        "response_path",
        "runtime_path",
        "workspace_path",
        "question_variant",
        "criterion",
        "prompt",
        "raw_answer",
        "transcript",
        "store_id",
    ):
        assert forbidden not in serialized


def test_write_report_refuses_to_overwrite_and_emits_content_free_json(
    tmp_path: Path,
) -> None:
    tool = _tool()
    target = tmp_path / "report.json"
    report = {"schema": "memory.behavioral-acceptance-report.v1", "counts": {}}

    tool.write_report(target, report)

    assert target.stat().st_mode & 0o077 == 0
    assert json.loads(target.read_text(encoding="utf-8")) == report
    with pytest.raises(tool.AcceptanceError, match="already exists"):
        tool.write_report(target, report)


def test_documented_repeated_run_keeps_trials_private_fixed_and_honest() -> None:
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    ceremony = CEREMONY_PATH.read_text(encoding="utf-8")
    record = RECORD_PATH.read_text(encoding="utf-8")
    combined = setup + ceremony + record
    normalized_ceremony = " ".join(ceremony.split())

    assert "run-behavioral-acceptance.py" in setup
    assert "default is three" in ceremony
    assert "maximum is ten" in ceremony
    assert "one fresh disposable Store and one independent client session" in ceremony
    assert "no retry-until-green" in ceremony
    assert "`execution_interrupted`" in ceremony
    assert "`criterion`" in ceremony
    assert "not keywords to match" in normalized_ceremony
    assert "`audit_generation`" in ceremony
    assert "one-use and immutable" in normalized_ceremony
    assert "`client_transport_failed`" in ceremony
    assert "after-snapshot" in ceremony
    assert "`--restricted`" in ceremony
    assert '`--tools ""`' in ceremony
    assert "read-only sandbox" in ceremony
    assert "excluding native executor namespaces" in normalized_ceremony
    assert "repeats the capability proof" in normalized_ceremony
    assert "never launches inference" in normalized_ceremony
    assert "`client_isolation_controls_unavailable`" in ceremony
    assert "installed distribution digest" in normalized_ceremony
    assert "revalidated before every slot" in normalized_ceremony
    assert "synthetic adapter-seeded" in combined.casefold()
    assert "does not attest capture, review, approval, or apply" in normalized_ceremony
    assert "Raw prompts, answers, transcripts, runtime IDs, and paths" in ceremony
    assert "explicit denominator" in record
    for document in (setup, ceremony, record):
        normalized = " ".join(document.split())
        assert "private location outside the checkout" in normalized
        assert "template unexecuted" in normalized


def _connect_synthetic_mcp(
    tool: ModuleType, paths: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    """Exercise real MCP dispatch; only replace the installed-process boundary."""
    from memory.mcp_server import call_tool

    operations: list[str] = []

    def call(
        _memory: Path, home: Path, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        assert home == paths.root
        operations.append(name)
        envelope = cast(
            "dict[str, Any]", call_tool(paths, name, arguments)["structuredContent"]
        )
        assert "error" not in envelope, envelope
        return envelope

    monkeypatch.setattr(tool, "_fixture_call", call, raising=False)
    return operations


def test_owner_review_preparation_seals_exact_guard_review_without_approving(
    synthetic_store: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    case = tool.load_manifest(MANIFEST_PATH).cases["SYN-BEHAVIOR-GUARD-ZH-023"]
    operations = _connect_synthetic_mcp(tool, synthetic_store, monkeypatch)
    phases: list[dict[str, Any]] = []

    assert hasattr(tool, "advance_fixture_preparation"), "review preparation is missing"
    outcome = tool.advance_fixture_preparation(
        Path("/synthetic/bin/memory"), synthetic_store.root, case, phases
    )

    from memory.reviews import get_change_set
    from memory.sources import get_store_status

    status = get_store_status(synthetic_store)
    assert outcome == "owner_presence_prerequisite"
    assert status.source_count == 3
    assert status.memory_count == 0
    assert status.pending_review_count == 1
    assert len(phases) == 1
    view = get_change_set(synthetic_store, phases[0]["change_set_id"])
    assert view.digest == phases[0]["digest"]
    assert len(view.items) == 3
    assert len(view.guard_links) == 1
    assert view.guard_links[0].guard_item_id == "SYN-BEHAVIOR-MEM-GUARD-AIR-026"
    assert view.guard_links[0].governed_item_id == "SYN-BEHAVIOR-MEM-GUARD-PLAN-025"
    assert "change_set.approve_and_apply" not in operations
    assert not any(synthetic_store.inbox.iterdir())
    frozen = json.dumps(phases, sort_keys=True)
    assert (
        tool.advance_fixture_preparation(
            Path("/synthetic/bin/memory"), synthetic_store.root, case, phases
        )
        == "owner_presence_prerequisite"
    )
    assert json.dumps(phases, sort_keys=True) == frozen
    assert operations.count("inbox.scan") == 1


def test_owner_review_preparation_refuses_unaccounted_sources_before_staging(
    synthetic_store: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from synthetic import FakeClock

    from memory.inbox import scan_inbox

    (synthetic_store.inbox / "unrelated.txt").write_text(
        "A fresh unrelated synthetic source.", encoding="utf-8"
    )
    scan_inbox(synthetic_store, clock=FakeClock())
    tool = _tool()
    case = tool.load_manifest(MANIFEST_PATH).cases["SYN-BEHAVIOR-PARAPHRASE-021"]
    operations = _connect_synthetic_mcp(tool, synthetic_store, monkeypatch)

    assert hasattr(tool, "advance_fixture_preparation"), "review preparation is missing"
    with pytest.raises(tool.AcceptanceError, match="fixture Store"):
        tool.advance_fixture_preparation(
            Path("/synthetic/bin/memory"), synthetic_store.root, case, []
        )
    assert "inbox.scan" not in operations
    assert not any(synthetic_store.inbox.iterdir())


def test_correction_preparation_waits_for_each_exact_review_and_verifies_history(
    synthetic_store: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from synthetic import apply_ready

    from memory.reviews import get_change_set

    tool = _tool()
    case = tool.load_manifest(MANIFEST_PATH).cases["SYN-BEHAVIOR-CORRECTION-ZH-025"]
    operations = _connect_synthetic_mcp(tool, synthetic_store, monkeypatch)
    phases: list[dict[str, Any]] = []
    memory = Path("/synthetic/bin/memory")

    assert hasattr(tool, "advance_fixture_preparation"), "review preparation is missing"
    assert (
        tool.advance_fixture_preparation(memory, synthetic_store.root, case, phases)
        == "owner_presence_prerequisite"
    )
    assert len(phases) == 1
    predecessor = get_change_set(synthetic_store, phases[0]["change_set_id"])
    assert len(predecessor.items) == 1
    # Kernel test fixture only; this is not OS-presence or installed-client evidence.
    apply_ready(synthetic_store, predecessor)
    assert (
        tool.advance_fixture_preparation(memory, synthetic_store.root, case, phases)
        == "owner_presence_prerequisite"
    )
    assert len(phases) == 2
    successor = get_change_set(synthetic_store, phases[1]["change_set_id"])
    assert successor.items[0].memory.target_lineage_id is not None
    assert successor.items[0].memory.expected_head_id is not None
    apply_ready(synthetic_store, successor)
    assert (
        tool.advance_fixture_preparation(memory, synthetic_store.root, case, phases)
        == "ready"
    )
    assert operations.count("inbox.scan") == 2
    assert "change_set.approve_and_apply" not in operations


def test_isolation_probe_has_no_ambient_home_or_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    for variable in (
        "HOME",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ):
        monkeypatch.setenv(variable, "synthetic-ambient-value")
    record = tmp_path / "probe.json"
    client = _write_executable(
        tmp_path / "codex",
        f"""
import json, os, pathlib
variables = ["HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
pathlib.Path({str(record)!r}).write_text(json.dumps({{key: os.environ.get(key) for key in variables}}))
for feature in {list(tool.CODEX_DISABLED_FEATURES)!r}:
    print(f"{{feature}} stable false")
""",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    assert tool._codex_isolation_controls_supported(client, workspace) is True

    observed = json.loads(record.read_text())
    assert observed["HOME"] != "synthetic-ambient-value"
    assert Path(observed["HOME"]).is_relative_to(workspace)
    assert Path(observed["CODEX_HOME"]).is_relative_to(workspace)
    assert all(
        observed[name] is None
        for name in (
            "CLAUDE_CONFIG_DIR",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
        )
    )


def test_fixture_command_leaves_reviewable_handoff_without_attempting_a_trial(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from memory.mcp_server import call_tool
    from memory.model import RuntimeMode
    from memory.runtime import initialize_runtime, resolve_runtime

    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["provenance"]["seed_mode"] = "owner_review"
    state["private"] = {
        "manifest_path": str(MANIFEST_PATH),
        "memory_executable": "/synthetic/bin/memory",
    }
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    tool._write_state(root, state)
    calls: list[str] = []

    def installed_call(
        _memory: Path, home: Path, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        assert home.is_relative_to(root)
        calls.append(name)
        envelope = cast(
            "dict[str, Any]",
            call_tool(resolve_runtime(home), name, arguments)["structuredContent"],
        )
        assert "error" not in envelope, envelope
        return envelope

    def initialize(
        command: list[str], **_options: object
    ) -> subprocess.CompletedProcess[str]:
        assert command[:3] == ["/synthetic/bin/memory", "init", "--home"]
        initialize_runtime(resolve_runtime(Path(command[3])), mode=RuntimeMode.PERSONAL)
        return subprocess.CompletedProcess(command, 0, "", "")

    def forbidden_client_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("owner-review preparation reached authentication or inference")

    monkeypatch.setattr(tool, "_fixture_call", installed_call, raising=False)
    monkeypatch.setattr(tool, "_run_text", initialize)
    monkeypatch.setattr(tool, "_revalidate_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(tool, "_client_authentication", forbidden_client_work)
    monkeypatch.setattr(tool, "_run_client_to_private_files", forbidden_client_work)

    assert hasattr(tool, "_fixtures"), "fixture command is missing"
    arguments = Namespace(state_root=root, slot_id=state["slots"][0]["slot_id"])
    assert tool._fixtures(arguments) == 0
    prepared = tool._read_state(root)
    assert prepared["slots"][0]["fixture_preparation"] == "owner_presence_prerequisite"
    assert prepared["slots"][0]["attempted"] is False
    assert tool.build_report(prepared)["counts"] == {
        "requested": 6,
        "attempted": 0,
        "completed": 0,
        "passed": 0,
    }
    handoff = root / "owner-review.private.sh"
    assert handoff.stat().st_mode & 0o077 == 0
    assert "/synthetic/bin/memory approve " in handoff.read_text()
    assert "--revision" in handoff.read_text() and "--digest" in handoff.read_text()
    assert tool._fixtures(arguments) == 0
    assert calls.count("inbox.scan") == 1
    assert "change_set.approve_and_apply" not in calls
    trial = Path(prepared["slots"][0]["private_trial_directory"])
    marker = trial / "fixture-owner.private.json"
    assert marker.is_file(), "fresh runtime ownership is not bound"
    assert marker.stat().st_mode & 0o077 == 0
    old_sources = calls.count("source.read")
    marker.write_text("{}", encoding="utf-8")
    assert tool._fixtures(arguments) == 0
    assert (
        tool._read_state(root)["slots"][0]["fixture_preparation"]
        == "fixture_preparation_failed"
    )
    assert calls.count("source.read") == old_sources


def test_owner_review_execution_uses_the_original_prepared_runtime(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["provenance"]["seed_mode"] = "owner_review"
    private = tmp_path / "private-trials"
    private.mkdir(mode=0o700)
    prepared = private / "trial-001"
    prepared.mkdir(mode=0o700)
    home = prepared / "store"
    home.mkdir(mode=0o700)
    (prepared / "client-session").mkdir(mode=0o700)
    (prepared / "client-response.private").touch(mode=0o600)
    state["slots"][0]["private_trial_directory"] = str(prepared)
    seen: list[Path] = []

    def execute(
        _case: dict[str, Any],
        _trial: int,
        selected_home: Path,
        _workspace: Path,
        _response: Path,
    ) -> dict[str, Any]:
        seen.append(selected_home)
        return _complete_attempt()

    tool.execute_trials(state, manifest, private, execute=execute)
    assert seen[0] == home
    assert len(seen) == 6


def test_probe_command_records_unhonored_controls_without_creating_trials(
    tmp_path: Path,
) -> None:
    tool = _tool()
    client = _write_executable(
        tmp_path / "codex",
        f"""
import sys
if sys.argv[-1] == "--version":
    print("codex-cli 9.8.7")
else:
    for feature in {list(tool.CODEX_DISABLED_FEATURES)!r}:
        enabled = "true" if feature == "unified_exec" else "false"
        print(f"{{feature}} stable {{enabled}}")
""",
    )
    root = tmp_path / "probe"
    root.mkdir(mode=0o700)

    assert hasattr(tool, "probe_client_isolation"), "metadata-only probe is missing"
    report = tool.probe_client_isolation(client, "codex", root)

    assert report["outcome_label"] == "client_isolation_controls_unavailable"
    assert report["required_controls"] == 27
    assert report["confirmed_disabled_controls"] == 26
    assert report["unhonored_controls"] == ["unified_exec"]
    assert report["inference_launched"] is False
    assert report["behavioral_slots_created"] == 0
    assert not (root / "private-trials").exists()
    assert not (root / "runtime.json").exists()
    assert str(tmp_path) not in json.dumps(report)


def test_version_probe_uses_a_fresh_home_without_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    record = tmp_path / "version.json"
    monkeypatch.setenv("HOME", "synthetic-ambient-home")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-ambient-token")
    client = _write_executable(
        tmp_path / "codex",
        f"""
import json, os, pathlib
pathlib.Path({str(record)!r}).write_text(json.dumps({{"home": os.environ.get("HOME"), "auth": os.environ.get("OPENAI_API_KEY")}}))
print("codex-cli 9.8.7")
""",
    )

    assert tool._probe_version(client, "codex") == "codex-cli 9.8.7"
    observed = json.loads(record.read_text())
    assert observed["home"] != "synthetic-ambient-home"
    assert observed["auth"] is None


def test_explicit_prerequisite_block_records_all_slots_before_inference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=3, provenance=_provenance())
    state["private"] = {
        "manifest_path": str(MANIFEST_PATH),
        "memory_executable": "/synthetic/bin/memory",
        "client_executable": "/synthetic/bin/codex",
    }
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    tool._write_state(root, state)
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)

    assert (
        tool._run(
            Namespace(state_root=root, blocked_reason="owner_presence_prerequisite")
        )
        == 0
    )
    recorded = tool._read_state(root)
    report = tool.build_report(recorded)
    assert {slot["outcome_label"] for slot in recorded["slots"]} == {
        "owner_presence_prerequisite"
    }
    assert report["counts"] == {
        "requested": 18,
        "attempted": 18,
        "completed": 0,
        "passed": 0,
    }
    assert report["inference_counts"] == {
        "started": 0,
        "not_started": 18,
        "unavailable": 0,
    }
    assert report["pass_rate"] == {"numerator": 0, "denominator": 18}


def test_historical_report_does_not_infer_whether_a_client_was_started() -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    for slot in state["slots"]:
        slot.pop("inference_started", None)
    report = tool.build_report(state)
    assert "inference_counts" in report, "inference observation is missing"
    assert report["inference_counts"] == {
        "started": 0,
        "not_started": 0,
        "unavailable": 6,
    }
    assert "client_launch_counts" in report, "client launches are not separated"
    assert report["client_launch_counts"] == {
        "attempted": 0,
        "not_attempted": 0,
        "unavailable": 6,
    }


def test_grading_records_inference_only_from_explicit_private_operator_observation(
    tmp_path: Path,
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    tool.execute_trials(
        state, manifest, tmp_path, execute=lambda *_args: _complete_attempt()
    )
    grades = _passing_grades(state, manifest)
    grades[0]["inference_observed"] = True
    tool.grade_trials(state, manifest, grades)
    assert tool.build_report(state)["inference_counts"] == {
        "started": 1,
        "not_started": 0,
        "unavailable": 5,
    }


@pytest.mark.parametrize(
    "invalid_id", ["../../outside", "/outside", "SYN-BEHAVIOR-MEM-X/../Y"]
)
def test_fixture_manifest_refuses_path_shaped_fixture_ids_before_staging(
    tmp_path: Path,
    invalid_id: str,
) -> None:
    tool = _tool()
    payload = json.loads(MANIFEST_PATH.read_text())
    payload["cases"][0]["seed_profile"]["memories"][0]["fixture_id"] = invalid_id
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(tool.AcceptanceError, match="fixture identifier"):
        tool.load_manifest(path)


def test_unapproved_owner_fixtures_block_before_initialization_or_client_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["provenance"]["seed_mode"] = "owner_review"
    state["slots"][0]["fixture_preparation"] = "owner_presence_prerequisite"
    state["private"] = {
        "memory_executable": "/synthetic/bin/memory",
        "client_executable": "/synthetic/bin/codex",
    }
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(
        tool, "_codex_isolation_controls_supported", lambda *_args: True
    )
    with pytest.raises(tool.TrialBlocked) as captured:
        tool._actual_executor(state, manifest)(
            manifest.cases[state["slots"][0]["case_id"]],
            1,
            tmp_path / "store",
            tmp_path / "workspace",
            tmp_path / "response",
        )
    assert captured.value.label == "owner_presence_prerequisite"
