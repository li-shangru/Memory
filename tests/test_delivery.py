"""Freshness and failure regressions use synthetic metadata and private tmp paths."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from mcp.types import CallToolResult

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))

import delivery as d  # noqa: E402
import delivery_probe as dp  # noqa: E402


def test_delivery_command_exists_and_missing_profile_cannot_pass(
    tmp_path: Path,
) -> None:
    """A source gate must not quietly substitute for a missing delivery profile."""
    script = TOOLS / "delivery.py"
    assert script.is_file(), "Memory has no executable local-delivery completion gate"
    result = subprocess.run(
        [sys.executable, str(script), "check", "--profile", str(tmp_path / "absent")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "profile_missing" in result.stdout
    assert "configure" in result.stdout
    assert (
        json.loads((tmp_path / "memory-delivery-last.json").read_text())["status"]
        == "failed"
    )


def snapshot(tmp_path: Path) -> dict[str, object]:
    return {
        "metadata_version": "1.2.3",
        "module_version": "1.2.3",
        "prefix": str(tmp_path / "installed"),
        "origin": str(tmp_path / "installed/lib/python3.14/site-packages/memory"),
        "editable": False,
        "direct_url": (tmp_path / "memory.whl").as_uri(),
        "metadata": "Name: memory\nVersion: 1.2.3\nRequires-Python: >=3.14,<3.15\n",
        "entry_points": "[console_scripts]\nmemory = memory.cli:main\n",
        "files": {"cli.py": "111", "skill/SKILL.md": "222"},
        "python_version": [3, 14],
    }


def verify_snapshot(payload: dict[str, object], tmp_path: Path) -> None:
    d.verify_snapshot(
        payload,
        source_version="1.2.3",
        source_files={"cli.py": "111", "skill/SKILL.md": "222"},
        wheel_metadata="Name: memory\nVersion: 1.2.3\nRequires-Python: >=3.14,<3.15\n",
        wheel_entry_points="[console_scripts]\nmemory = memory.cli:main\n",
        expected_prefix=tmp_path / "installed",
        expected_wheel=tmp_path / "memory.whl",
    )


def test_matching_version_cannot_hide_changed_package_bytes(tmp_path: Path) -> None:
    payload = snapshot(tmp_path)
    payload["files"] = {"cli.py": "changed", "skill/SKILL.md": "222"}
    with pytest.raises(d.DeliveryError, match="package_bytes_drift"):
        verify_snapshot(payload, tmp_path)


@pytest.mark.parametrize("member", ["skill/SKILL.md", "ui/template.html"])
def test_packaged_instruction_and_extra_file_drift_fail(
    tmp_path: Path, member: str
) -> None:
    payload = snapshot(tmp_path)
    payload["files"] = {"cli.py": "111", "skill/SKILL.md": "222", member: "drift"}
    with pytest.raises(d.DeliveryError, match="package_bytes_drift"):
        verify_snapshot(payload, tmp_path)


def test_correct_complete_snapshot_passes(tmp_path: Path) -> None:
    verify_snapshot(snapshot(tmp_path), tmp_path)


def test_editable_metadata_drift_is_distinguished_from_origin(tmp_path: Path) -> None:
    payload = snapshot(tmp_path)
    payload.update(editable=True, metadata_version="1.2.2", module_version="1.2.2")
    with pytest.raises(d.DeliveryError, match="editable_metadata_drift"):
        verify_snapshot(payload, tmp_path)


def test_current_editable_install_is_explicitly_wrong_memory_delivery_mode(
    tmp_path: Path,
) -> None:
    payload = snapshot(tmp_path)
    payload["editable"] = True
    with pytest.raises(d.DeliveryError, match="editable_installation"):
        verify_snapshot(payload, tmp_path)


@pytest.mark.parametrize("field", ["prefix", "origin", "direct_url"])
def test_same_bytes_from_the_wrong_installation_fail(
    tmp_path: Path, field: str
) -> None:
    payload = snapshot(tmp_path)
    payload[field] = str(tmp_path / "another-checkout")
    with pytest.raises(d.DeliveryError, match="installation_origin_drift"):
        verify_snapshot(payload, tmp_path)


def test_same_version_stale_dependency_metadata_fails(tmp_path: Path) -> None:
    payload = snapshot(tmp_path)
    payload["metadata"] = str(payload["metadata"]) + "Requires-Dist: stale-package\n"
    with pytest.raises(d.DeliveryError, match="package_metadata_drift"):
        verify_snapshot(payload, tmp_path)


def test_source_input_drift_invalidates_a_prior_release() -> None:
    with pytest.raises(d.DeliveryError, match="source_not_released"):
        d.verify_release_inputs({"cli.py": "old"}, {"cli.py": "new"})


def write_command(tmp_path: Path, python: Path) -> Path:
    command = tmp_path / "memory"
    command.write_text(
        f"#!{python}\nimport sys\nfrom memory.cli import main\n"
        "if __name__ == '__main__':\n    sys.exit(main())\n"
    )
    command.chmod(0o700)
    return command


def test_wrong_shebang_fails_even_when_interpreters_resolve_to_same_binary(
    tmp_path: Path,
) -> None:
    for name in ("expected", "other"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "python").symlink_to(sys.executable)
    command = write_command(tmp_path, tmp_path / "other/python")
    with pytest.raises(d.DeliveryError, match="executable_interpreter_drift"):
        d.verify_launcher(command, tmp_path / "expected/python")


def test_modified_console_wrapper_is_refused(tmp_path: Path) -> None:
    python = tmp_path / "python"
    command = write_command(tmp_path, python)
    command.write_text(command.read_text() + "print('wrapper changed')\n")
    with pytest.raises(d.DeliveryError, match="unsupported_launcher"):
        d.verify_launcher(command, python)


def test_configured_wrong_command_is_refused_before_launch(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[mcp_servers.memory]\ncommand = "/synthetic/wrong/memory"\nargs = ["mcp"]\n'
    )
    with pytest.raises(d.DeliveryError, match="configured_entrypoint_drift"):
        d.verify_configuration(config, "codex", tmp_path / "memory")


@pytest.mark.parametrize("kind", ["codex", "claude"])
def test_configuration_runtime_argument_is_never_opened(
    tmp_path: Path, kind: str
) -> None:
    command = write_command(tmp_path, Path(sys.executable))
    runtime = tmp_path / "forbidden-runtime"
    runtime.symlink_to(tmp_path / "missing")
    config = tmp_path / "config"
    entry = {"command": str(command), "args": ["mcp", "--home", str(runtime)]}
    if kind == "codex":
        config.write_text(
            f"[mcp_servers.memory]\ncommand = {json.dumps(str(command))}\n"
            f"args = {json.dumps(entry['args'])}\n"
        )
    else:
        config.write_text(json.dumps({"mcpServers": {"memory": entry}}))
    before = runtime.lstat()
    d.verify_configuration(config, kind, command)
    assert runtime.lstat() == before
    assert not (tmp_path / "missing").exists()


def test_ambient_python_injection_does_not_reach_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/synthetic/wrong-checkout")
    monkeypatch.setenv("MEMORY_HOME", "/synthetic/forbidden")
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", "/synthetic/wrong-env")
    cleaned = d.safe_environment()
    assert "PYTHONPATH" not in cleaned
    assert "MEMORY_HOME" not in cleaned
    assert "UV_PROJECT_ENVIRONMENT" not in cleaned
    assert cleaned["PYTHONDONTWRITEBYTECODE"] == "1"


def test_changed_skill_is_reported_without_overwriting_it(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.write_bytes(b"canonical\n")
    target.write_bytes(b"stale\n")
    with pytest.raises(d.DeliveryError, match="copied_skill_drift"):
        d.verify_skill_file(source, target)
    assert target.read_bytes() == b"stale\n"


@pytest.mark.parametrize("stage", ["installation", "fresh_process"])
def test_failed_delivery_subprocess_cannot_be_reported_as_success(
    tmp_path: Path, stage: str
) -> None:
    with pytest.raises(d.DeliveryError, match=f"{stage}_failed"):
        d.run_command(
            stage,
            [sys.executable, "-c", "raise SystemExit(7)"],
            cwd=tmp_path,
            log=tmp_path / "command.log",
        )


def test_fingerprint_covers_all_shipped_files_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    (tmp_path / "skill").mkdir()
    (tmp_path / "skill/SKILL.md").write_bytes(b"instruction\n")
    (tmp_path / "__init__.py").write_bytes(b"VERSION = 'synthetic'\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__/cached.pyc").write_bytes(b"cache")
    assert set(d.fingerprint(tmp_path)) == {"skill/SKILL.md", "__init__.py"}
    (tmp_path / "linked.py").symlink_to(tmp_path / "__init__.py")
    with pytest.raises(d.DeliveryError, match="package_symlink"):
        d.fingerprint(tmp_path)


def test_profile_is_private_and_rerunnable_without_changing_bytes(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile.json"
    payload = {"schema": "memory.delivery-profile.v1", "synthetic": True}
    d.write_json(profile, payload)
    before = profile.stat().st_mtime_ns
    d.write_json(profile, payload)
    assert profile.stat().st_mtime_ns == before
    assert os.stat(profile).st_mode & 0o777 == 0o600


def test_finishing_gate_requires_delivery_unless_source_only_is_explicit(
    tmp_path: Path,
) -> None:
    """Exercise the actual gate shell flow without starting product processes."""
    tools = tmp_path / "tools"
    tools.mkdir()
    shutil.copyfile(TOOLS / "check.sh", tools / "check.sh")
    (tools / "check.sh").chmod(0o700)
    for name, body in (
        ("setup-browser-tests.sh", "exit 0"),
        ("deliver.sh", 'echo "delivery required"; exit 7'),
        ("uv", "exit 0"),
    ):
        (tools / name).write_text(f"#!/bin/sh\n{body}\n")
        (tools / name).chmod(0o700)
    environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}
    completed = subprocess.run(
        [str(tools / "check.sh")],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 7
    assert "delivery required" in completed.stdout
    source = subprocess.run(
        [str(tools / "check.sh"), "--source-only"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert source.returncode == 0
    assert "delivery is not verified" in source.stdout
    assert "delivery required" not in source.stdout


def test_failed_fresh_init_uses_a_new_home_and_cleans_only_that_home(
    tmp_path: Path,
) -> None:
    """A broken installed command cannot fall back to any configured/default home."""
    call_log = tmp_path / "invocation.json"
    command = tmp_path / "synthetic-memory"
    command.write_text(
        f"#!{sys.executable}\nimport json, pathlib, sys\n"
        f"pathlib.Path({str(call_log)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "raise SystemExit(7)\n"
    )
    command.chmod(0o700)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(TOOLS / "delivery_probe.py"),
            "fresh",
            "--source",
            str(tmp_path),
            "--executable",
            str(command),
            "--version",
            "1.2.3",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "MEMORY_HOME": str(tmp_path / "forbidden")},
    )
    assert result.returncode == 1
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "failed"
    assert receipt["errors"] == ["synthetic_init_failed"]
    assert receipt["synthetic_runtime_removed"] is True
    arguments = json.loads(call_log.read_text())
    assert arguments[:2] == ["init", "--home"]
    root = Path(arguments[2])
    assert root.parent == Path("/tmp").resolve()
    assert root.name.startswith("memory-delivery.")
    assert not root.exists()
    assert not (tmp_path / "forbidden").exists()


@pytest.mark.parametrize("kind", ["codex", "claude", "claude_project"])
def test_project_mcp_overrides_cannot_hide_behind_global_parity(
    tmp_path: Path,
    kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
    config = tmp_path / "client.json"
    config.write_text("{}")
    if kind == "codex":
        (workspace / ".codex").mkdir()
        (workspace / ".codex/config.toml").write_text(
            '[mcp_servers.memory]\ncommand = "/synthetic/wrong/memory"\n'
        )
    elif kind == "claude":
        (workspace / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"memory": {"command": "/synthetic/wrong/memory"}}}
            )
        )
    else:
        config.write_text(
            json.dumps(
                {
                    "projects": {
                        str(workspace): {
                            "mcpServers": {
                                "memory": {"command": "/synthetic/wrong/memory"}
                            }
                        }
                    }
                }
            )
        )
    with pytest.raises(d.DeliveryError, match="project_configuration_override"):
        d.verify_project_overrides((workspace,), (("claude", config),))


def test_overlapping_delivery_attempts_refuse_without_replacing_receipt(
    tmp_path: Path,
) -> None:
    first = d.acquire_lock(tmp_path / "profile.json")
    try:
        with pytest.raises(d.DeliveryError, match="delivery_in_progress"):
            d.acquire_lock(tmp_path / "profile.json")
    finally:
        os.close(first)
    second = d.acquire_lock(tmp_path / "profile.json")
    os.close(second)


def test_claude_scope_alias_uses_directory_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
    alias = tmp_path / "alias"
    alias.symlink_to(workspace, target_is_directory=True)
    config = tmp_path / "client.json"
    config.write_text(
        json.dumps(
            {
                "projects": {
                    str(alias): {
                        "mcpServers": {"memory": {"command": "/synthetic/wrong/memory"}}
                    }
                }
            }
        )
    )
    with pytest.raises(d.DeliveryError, match="project_configuration_override"):
        d.verify_project_overrides((workspace,), (("claude", config),))


class SyntheticEvidenceClient:
    def __init__(self, *, corrupt: bool = False, failed: bool = False) -> None:
        self.corrupt = corrupt
        self.failed = failed
        self.calls: list[str] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, object] | None = None,
    ) -> CallToolResult:
        self.calls.append(name)
        data: object
        if name == "inbox.scan":
            data = {"batch_id": "synthetic-batch", "source_count": 1}
        elif name == "source.list":
            data = [{"source_id": "synthetic-source"}]
        else:
            assert arguments is not None
            start = int(str(arguments.get("cursor", "0")))
            text = dp.FIXTURE_TEXT
            end = start + 1
            while end < len(text) and len(text[start : end + 1].encode()) <= 64:
                end += 1
            piece = text[start:end]
            if self.corrupt and start == 0:
                piece = "?" + piece[1:]
            data = {
                "source_id": "synthetic-source",
                "text": piece,
                "byte_start": len(text[:start].encode()),
                "byte_end": len(text[:end].encode()),
                "char_start": start,
                "char_end": end,
                "complete": end == len(text),
                "blob_digest": hashlib.sha256(text.encode()).hexdigest(),
            }
            if end != len(text):
                data["next_cursor"] = str(end)
        return CallToolResult(
            content=[],
            is_error=self.failed,
            structured_content={
                "schema": "memory.mcp.v1",
                "instruction_trust": "inert",
                "data": data,
                "page": {"has_more": False},
            },
        )


def test_fresh_evidence_probe_reconstructs_bilingual_chunks() -> None:
    client = SyntheticEvidenceClient()
    result = anyio.run(dp.verify_evidence, client, True)
    assert result["source_count"] == 1
    assert result["chunks"] > 1
    assert client.calls.count("inbox.scan") == 1
    assert "change_set.approve_and_apply" not in client.calls
    legacy = SyntheticEvidenceClient()
    anyio.run(dp.verify_evidence, legacy, False)
    assert "inbox.scan" not in legacy.calls


@pytest.mark.parametrize("failure", ["corrupt", "failed"])
def test_fresh_evidence_readback_failure_cannot_pass(failure: str) -> None:
    client = SyntheticEvidenceClient(
        corrupt=failure == "corrupt", failed=failure == "failed"
    )
    with pytest.raises(ValueError, match="evidence_"):
        anyio.run(dp.verify_evidence, client, False)


@pytest.mark.parametrize(
    "setting", ['env_vars = ["PYTHONPATH"]', 'experimental_environment = "remote"']
)
def test_unverified_configured_environment_cannot_pass(
    tmp_path: Path, setting: str
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[mcp_servers.memory]\ncommand = "/synthetic/memory"\nargs = ["mcp"]\n'
        + setting
        + "\n"
    )
    with pytest.raises(d.DeliveryError, match="unsupported_configuration"):
        d.verify_configuration(config, "codex", Path("/synthetic/memory"))


def test_inherited_project_override_is_checked_for_selected_child(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    child = project / "child"
    child.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(project)], check=True)
    (project / ".codex").mkdir()
    (project / ".codex/config.toml").write_text(
        '[mcp_servers.memory]\ncommand = "/synthetic/other/memory"\n'
    )
    with pytest.raises(d.DeliveryError, match="project_configuration_override"):
        d.verify_project_overrides((child,), ())


@pytest.mark.parametrize("failure", ["package", "launcher"])
def test_failed_post_install_validation_prevents_skill_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    profile = d.Profile(
        tmp_path / "memory", tmp_path / "installed/bin/python", (), (), (tmp_path,)
    )
    calls: list[bool] = []
    command_checks = 0
    snapshots = 0

    def commands(_profile: d.Profile) -> None:
        nonlocal command_checks
        command_checks += 1
        if failure == "launcher" and command_checks > 1:
            raise d.DeliveryError("executable_interpreter_drift")

    def inspect(_profile: d.Profile, _logs: Path) -> dict[str, object]:
        nonlocal snapshots
        snapshots += 1
        value = snapshot(tmp_path)
        value["dependencies"] = {
            "synthetic": "1",
            "memory-sqlcipher3": d.PREVIOUS_COMPANION_VERSION,
        }
        value["dependency_files"] = {
            "synthetic": {"module.py": "1" * 64},
            "memory-sqlcipher3": {"native.so": "2" * 64},
        }
        if failure == "package" and snapshots > 1:
            value["files"] = {"cli.py": "wrong"}
        return value

    def skills(_profile: d.Profile, _logs: Path, *, install: bool) -> None:
        calls.append(install)

    monkeypatch.setattr(d, "git", lambda *args: "")
    monkeypatch.setattr(d, "verify_profile_commands", commands)
    monkeypatch.setattr(d, "inspect_install", inspect)
    monkeypatch.setattr(d, "run_command", lambda *args, **kwargs: "")
    monkeypatch.setattr(
        d, "freeze_release", lambda *args: (tmp_path, tmp_path / "memory.whl")
    )
    monkeypatch.setattr(d, "sha256", lambda *args: "synthetic-digest")
    monkeypatch.setattr(
        d, "fingerprint", lambda *args: {"cli.py": "111", "skill/SKILL.md": "222"}
    )
    monkeypatch.setattr(
        d,
        "verify_release",
        lambda *args: (
            {},
            str(snapshot(tmp_path)["metadata"]),
            str(snapshot(tmp_path)["entry_points"]),
        ),
    )
    monkeypatch.setattr(d, "install_release", lambda *args: None)
    monkeypatch.setattr(d, "verify_skills", skills)
    with pytest.raises(
        d.DeliveryError, match=r"package_bytes_drift|executable_interpreter_drift"
    ):
        d.deliver(profile, "1.2.3", tmp_path)
    assert calls == [], (
        "Unqualified installed code reached Skill mutation before verification"
    )


def test_only_reviewed_companion_dependency_transition_is_allowed() -> None:
    baseline = {"synthetic": "1.7", "memory-sqlcipher3": "0.6.2+sqlcipher4.17.0"}
    expected = {**baseline, "memory-sqlcipher3": "0.6.2+sqlcipher4.17.0.memory1"}
    assert d.expected_dependency_versions(baseline) == expected
    assert d.expected_dependency_versions(expected) == expected
    assert baseline["memory-sqlcipher3"] == "0.6.2+sqlcipher4.17.0"


@pytest.mark.parametrize("version", [None, "0.6.1", "0.6.2+sqlcipher4.17.0.memory2"])
def test_unknown_companion_baseline_cannot_authorize_upgrade(
    version: str | None,
) -> None:
    baseline = {"synthetic": "1.7"}
    if version is not None:
        baseline["memory-sqlcipher3"] = version
    with pytest.raises(d.DeliveryError, match="dependency_transition_unapproved"):
        d.expected_dependency_versions(baseline)


def test_dependency_byte_drift_is_rejected_even_with_unchanged_versions() -> None:
    before: dict[str, object] = {
        "synthetic": {"synthetic/module.py": "1" * 64},
        "memory-sqlcipher3": {"sqlcipher3/native.so": "3" * 64},
    }
    after: dict[str, object] = {
        "synthetic": {"synthetic/module.py": "2" * 64},
        "memory-sqlcipher3": {"sqlcipher3/native.so": "4" * 64},
    }
    with pytest.raises(d.DeliveryError, match="dependency_bytes_changed"):
        d.verify_preserved_dependency_bytes(before, after)
    after["synthetic"] = before["synthetic"]
    d.verify_preserved_dependency_bytes(before, after)


@pytest.mark.parametrize(
    "drift", ["native", "extra", "metadata", "origin", "distribution"]
)
def test_companion_snapshot_must_match_frozen_wheel_bytes(
    tmp_path: Path, drift: str
) -> None:
    import zipfile

    wheel = tmp_path / "companion.whl"
    metadata = "Name: memory-sqlcipher3\nVersion: 0.6.2+sqlcipher4.17.0.memory1\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("sqlcipher3/native.so", b"synthetic-native")
        archive.writestr("memory_sqlcipher3.dist-info/METADATA", metadata)
    files = {"native.so": hashlib.sha256(b"synthetic-native").hexdigest()}
    value: dict[str, object] = {
        "version": "0.6.2+sqlcipher4.17.0.memory1",
        "origin": str(tmp_path / "installed/lib/python3.14/site-packages/sqlcipher3"),
        "metadata": metadata,
        "files": files,
        "distribution_files": {
            "sqlcipher3/native.so": files["native.so"],
            "memory_sqlcipher3.dist-info/METADATA": hashlib.sha256(
                metadata.encode()
            ).hexdigest(),
        },
    }
    d.verify_companion(value, wheel, tmp_path / "installed")
    if drift == "native":
        files["native.so"] = "tampered"
    elif drift == "extra":
        files["unexpected.py"] = "injected"
    elif drift == "metadata":
        value["metadata"] = metadata + "extra"
    elif drift == "distribution":
        value["distribution_files"] = {}
    else:
        value["origin"] = str(tmp_path / "unrelated/sqlcipher3")
    with pytest.raises(d.DeliveryError, match=r"companion_.*_drift"):
        d.verify_companion(value, wheel, tmp_path / "installed")


@pytest.mark.parametrize("script", ["smoke-wheel.sh", "smoke-ui.sh"])
def test_smokes_refuse_supplied_companion_byte_drift_before_install(
    tmp_path: Path, script: str
) -> None:
    wheel = tmp_path / "memory-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"synthetic wheel never installed")
    companion = tmp_path / d.COMPANION_NAME
    companion.write_bytes(b"changed synthetic native artifact")
    environment = {
        **d.safe_environment(),
        "TMPDIR": str(tmp_path),
        "MEMORY_SMOKE_WHEEL": str(wheel),
        "MEMORY_SMOKE_WHEEL_SHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "MEMORY_SMOKE_COMPANION": str(companion),
        "MEMORY_SMOKE_COMPANION_SHA256": "0" * 64,
    }
    result = subprocess.run(
        [str(TOOLS / script)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "refused an unverified supplied companion" in result.stderr
    assert not list(tmp_path.glob("memory-*-home.*"))
    assert not list(tmp_path.glob("memory-*-venv.*"))


@pytest.mark.parametrize("digest", ["", "x" * 64, "1" * 63])
def test_malformed_dependency_byte_snapshot_fails(digest: str) -> None:
    with pytest.raises(d.DeliveryError, match="dependency_snapshot_failed"):
        d.dependency_file_maps({"synthetic": {"module.py": digest}})


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {"synthetic": {"module.py": "1" * 64}},
        {
            "memory-sqlcipher3": {"native.so": "bad"},
            "synthetic": {"module.py": "1" * 64},
        },
    ],
)
def test_incomplete_dependency_baseline_refuses_before_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformed: object
) -> None:
    wheel = tmp_path / "memory.whl"
    wheel.write_bytes(b"synthetic artifact")
    (tmp_path / d.COMPANION_NAME).write_bytes(b"synthetic companion")
    profile = d.Profile(tmp_path / "bin/memory", tmp_path / "bin/python", (), (), ())
    baseline = {
        "dependencies": {
            "memory-sqlcipher3": d.PREVIOUS_COMPANION_VERSION,
            "synthetic": "1",
        },
        "dependency_files": malformed,
    }
    mutations: list[str] = []
    monkeypatch.setattr(d, "git", lambda *args: "")
    monkeypatch.setattr(d, "verify_profile_commands", lambda *args: None)
    monkeypatch.setattr(d, "run_command", lambda *args, **kwargs: "")
    monkeypatch.setattr(d, "freeze_release", lambda *args: (tmp_path, wheel))
    monkeypatch.setattr(d, "inspect_install", lambda *args: baseline)
    monkeypatch.setattr(d, "verify_release", lambda *args: None)
    monkeypatch.setattr(d, "install_release", lambda *args: mutations.append("install"))
    monkeypatch.setattr(
        d,
        "qualify_install",
        lambda *args: (
            {
                "dependencies": {
                    "memory-sqlcipher3": d.COMPANION_VERSION,
                    "synthetic": "1",
                },
                "dependency_files": malformed,
            },
            {},
            "",
            "",
        ),
    )
    with pytest.raises(d.DeliveryError, match="dependency_snapshot_failed"):
        d.deliver(profile, "1.2.3", tmp_path)
    assert mutations == []


def test_frozen_companion_manifest_cannot_replace_reviewed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    version = "1.2.3"
    artifacts = {}
    for name in (
        f"memory-{version}-py3-none-any.whl",
        f"memory-{version}.tar.gz",
        d.COMPANION_NAME,
    ):
        path = tmp_path / name
        path.write_bytes(b"synthetic unreviewed artifact")
        artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (tmp_path / "release.json").write_text(
        json.dumps(
            {
                "schema": d.RELEASE_SCHEMA,
                "version": version,
                "inputs": {},
                "artifacts": artifacts,
            }
        )
    )
    monkeypatch.setattr(d, "source_inputs", lambda: {})
    monkeypatch.setattr(d, "fingerprint", lambda *args: {})
    monkeypatch.setattr(
        d, "wheel_contents", lambda *args: ({}, "Name: memory\nVersion: 1.2.3\n", "")
    )
    with pytest.raises(d.DeliveryError, match="release_artifact_drift"):
        d.verify_release(tmp_path, version)


def test_public_release_requires_its_exact_reviewed_dependency_upgrades() -> None:
    baseline = {
        "memory-sqlcipher3": d.COMPANION_VERSION,
        "httpx2": "2.12.0",
        "httpcore2": "2.12.0",
        "mcp": "2.1.1",
        "mcp-types": "2.1.1",
        "opentelemetry-api": "1.44.0",
        "pillow": "12.3.0",
        "pydantic": "2.13.5",
        "pydantic_core": "2.46.5",
        "pypdfium2": "5.13.0",
        "PyJWT": "2.13.0",
        "starlette": "1.6.0",
        "uvicorn": "0.52.4",
        "synthetic-unchanged": "7.1",
    }
    expected = d.expected_dependency_versions(baseline, public_release=True)
    assert expected["httpx2"] == expected["httpcore2"] == "2.16.0"
    assert expected["mcp"] == expected["mcp-types"] == "2.3.0"
    assert expected["pydantic_core"] == "2.50.1"
    assert expected["synthetic-unchanged"] == "7.1"
    assert baseline["httpx2"] == "2.12.0"
