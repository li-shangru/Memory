"""Endpoint bootstrap tests never use an owner home, real key or model call."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import ModuleType, SimpleNamespace, TracebackType
from typing import Protocol, cast

import pytest

HELPER = Path(__file__).resolve().parents[1] / "tools/behavioral_memory_endpoint.py"


def _module() -> ModuleType:
    name = "behavioral_memory_endpoint_test_module"
    spec = importlib.util.spec_from_file_location(name, HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _os_account(module: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    current = os.getuid()
    monkeypatch.setattr(module.os, "getuid", lambda: current)
    monkeypatch.setattr(module.os, "geteuid", lambda: current)

    def account(uid: int) -> SimpleNamespace:
        assert uid == current
        return SimpleNamespace(pw_dir="/Users/synthetic-os-account")

    monkeypatch.setattr(module.pwd, "getpwuid", account)


def test_environment_uses_os_metadata_and_fresh_private_application_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    monkeypatch.setenv("HOME", "/synthetic/inherited-home-must-not-win")
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-never-valid")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-never-valid")
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    environment = module.endpoint_environment(tmp_path)
    private = tmp_path.resolve() / ".mcp-endpoint-home"
    assert environment == {
        "HOME": "/Users/synthetic-os-account",
        "TMPDIR": str(private / "tmp"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.macOS.Keyring",
        "PYTHONNOUSERSITE": "1",
        "XDG_CONFIG_HOME": str(private / "config"),
        "XDG_CACHE_HOME": str(private / "cache"),
    }
    for path in (private, *(private / name for name in ("config", "cache", "tmp"))):
        assert path.is_dir() and not path.is_symlink()
        assert path.stat().st_mode & 0o077 == 0
    assert all(
        not tuple((private / name).iterdir()) for name in ("config", "cache", "tmp")
    )
    module.validate_endpoint_environment(environment, tmp_path)


def test_mismatched_effective_user_refuses_before_creating_bootstrap_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    monkeypatch.setattr(module.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(module.EndpointError, match="endpoint_environment_invalid"):
        module.endpoint_environment(tmp_path)
    assert not (tmp_path / ".mcp-endpoint-home").exists()


def test_environment_helper_digest_binds_exact_source() -> None:
    import hashlib

    module = _module()
    assert (
        module.implementation_digest()
        == hashlib.sha256(HELPER.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("HOME", "/synthetic/unrelated-account"),
        ("TMPDIR", "/synthetic/unrelated-tmp"),
        ("PATH", "/synthetic/untrusted-bin"),
        ("LANG", "en_US.UTF-8"),
        ("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring"),
        ("PYTHONNOUSERSITE", "0"),
        ("XDG_CONFIG_HOME", "/synthetic/unrelated-config"),
        ("XDG_CACHE_HOME", "/synthetic/unrelated-cache"),
        ("OPENAI_API_KEY", "synthetic-never-valid"),
    ],
)
def test_environment_validator_rejects_changed_or_added_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    environment = module.endpoint_environment(tmp_path)
    environment[key] = value
    with pytest.raises(module.EndpointError, match="endpoint_environment_invalid"):
        module.validate_endpoint_environment(environment, tmp_path)


@pytest.mark.parametrize("name", ["config", "cache", "tmp"])
@pytest.mark.parametrize("change", ["symlink", "public", "nonempty"])
def test_application_directories_must_stay_private_empty_and_real(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, change: str
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    environment = module.endpoint_environment(tmp_path)
    directory = tmp_path / ".mcp-endpoint-home" / name
    if change == "symlink":
        directory.rmdir()
        target = tmp_path / "unrelated-synthetic-directory"
        target.mkdir(mode=0o700)
        directory.symlink_to(target, target_is_directory=True)
    elif change == "public":
        directory.chmod(0o755)
    else:
        (directory / "untrusted-input").write_bytes(b"synthetic")
    with pytest.raises(module.EndpointError, match="endpoint_environment_invalid"):
        module.validate_endpoint_environment(environment, tmp_path)


def test_existing_environment_is_never_reused_or_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    module.endpoint_environment(tmp_path)
    marker = tmp_path / ".mcp-endpoint-home" / "existing-marker"
    marker.write_bytes(b"preserve synthetic preexisting material")
    with pytest.raises(module.EndpointError, match="endpoint_environment_invalid"):
        module.endpoint_environment(tmp_path)
    assert marker.read_bytes() == b"preserve synthetic preexisting material"


def test_post_creation_validation_failure_cleans_only_new_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    marker = tmp_path / "preexisting-workspace-marker"
    marker.write_bytes(b"preserve")

    def refuse(environment: object, workspace: Path) -> None:
        raise module.EndpointError("endpoint_environment_invalid")

    monkeypatch.setattr(module, "validate_endpoint_environment", refuse)
    with pytest.raises(module.EndpointError, match="endpoint_environment_invalid"):
        module.endpoint_environment(tmp_path)
    assert not (tmp_path / ".mcp-endpoint-home").exists()
    assert marker.read_bytes() == b"preserve"


class ReadinessContext(Protocol):
    root: Path
    runtime: Path
    store_id: str | None
    processes: list[dict[str, object]]


def _fake_readiness(
    module: ModuleType, monkeypatch: pytest.MonkeyPatch, root: Path
) -> tuple[list[str], list[Path]]:
    events: list[str] = []
    allocated: list[Path] = []
    bindings = dict.fromkeys(
        (
            "memory_executable_digest",
            "memory_interpreter_digest",
            "client_executable_digest",
            "code_mode_host_digest",
            "endpoint_helper_digest",
            "isolation_profile_digest",
            "bridge_transport_digest",
        ),
        "ab" * 32,
    )
    monkeypatch.setattr(
        module, "_artifact_bindings", lambda _memory, _client: dict(bindings)
    )
    monkeypatch.setattr(
        module, "_memory_interpreter", lambda _memory: Path(sys.executable)
    )
    monkeypatch.setattr(module, "_file_digest", lambda _path: "ab" * 32)
    monkeypatch.setattr(module, "FRESH_ROOT_PARENT", root)

    def initialize(context: ReadinessContext, memory: Path) -> None:
        assert memory == Path("/synthetic/candidate/bin/memory")
        assert not context.runtime.exists()
        events.append("initialize")
        allocated.append(context.root)
        context.runtime.mkdir(mode=0o700)
        identity = {
            "product": "memory",
            "schema_lineage": "memory-store-v1",
            "schema_version": 1,
            "runtime_mode": "personal",
            "store_id": "73" * 16,
            "inbox_path": str(context.runtime / "inbox"),
        }
        path = context.runtime / "runtime.json"
        path.write_text(json.dumps(identity), encoding="utf-8")
        path.chmod(0o600)
        context.processes.append(
            {
                "phase": "memory_init",
                "pid": 987,
                "pgid": 987,
                "reaped": True,
                "process_group_stopped": True,
            }
        )

    def bridge_check(
        context: ReadinessContext, memory: Path, client: Path, interpreter: Path
    ) -> dict[str, bool]:
        assert context.runtime.is_dir()
        assert client == Path("/synthetic/codex")
        assert interpreter == Path(sys.executable)
        events.append("bridge")
        return dict.fromkeys(
            (
                "mcp_initialized",
                "proxy_auth_environment_absent",
                "proxy_environment_isolated",
                "proxy_auth_home_denied",
                "endpoint_auth_home_denied",
                "endpoint_auth_environment_absent",
                "client_endpoint_environment_read_denied",
                "client_endpoint_environment_write_denied",
            ),
            True,
        )

    def cleanup(context: ReadinessContext, interpreter: Path) -> bool:
        assert context.store_id == "73" * 16
        assert interpreter == Path(sys.executable)
        assert context.runtime.is_dir()
        events.append("key_cleanup")
        return True

    monkeypatch.setattr(module, "_native_initialize", initialize)
    monkeypatch.setattr(module, "_native_bridge_check", bridge_check)
    monkeypatch.setattr(module, "_cleanup_native_key", cleanup)
    return events, allocated


def _verify(module: ModuleType, workspace: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        module.verify_endpoint_readiness(
            Path("/synthetic/candidate/bin/memory"), Path("/synthetic/codex"), workspace
        ),
    )


def test_readiness_uses_one_new_runtime_and_cleans_it_after_key_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    workspace = tmp_path / "receipt-workspace"
    workspace.mkdir(mode=0o700)
    events, allocated = _fake_readiness(module, monkeypatch, tmp_path)
    result = _verify(module, workspace)
    assert events == ["initialize", "bridge", "key_cleanup"]
    assert result["schema"] == "memory.behavioral-memory-endpoint-readiness.v1"
    assert result["outcome_label"] == "memory_endpoint_readiness_confirmed"
    assert result["ready"] is True and result["cleanup_confirmed"] is True
    assert result["key_cleanup_confirmed"] is True and result["runtime_removed"] is True
    assert len(allocated) == 1 and not allocated[0].exists()
    checkpoint = workspace / "readiness-checkpoint.private.json"
    assert checkpoint.stat().st_mode & 0o077 == 0
    assert result["checkpoint_digest"] == "ab" * 32
    with pytest.raises(module.EndpointError, match="readiness_workspace_consumed"):
        _verify(module, workspace)
    assert events == ["initialize", "bridge", "key_cleanup"]


@pytest.mark.parametrize("failed_step", ["bridge", "key_cleanup", "unknown_identity"])
def test_readiness_failures_never_claim_success_or_discard_uncertain_key_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_step: str
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    workspace = tmp_path / "receipt-workspace"
    workspace.mkdir(mode=0o700)
    events, allocated = _fake_readiness(module, monkeypatch, tmp_path)
    if failed_step == "key_cleanup":
        monkeypatch.setattr(
            module, "_cleanup_native_key", lambda _ctx, _interpreter: False
        )
    else:

        def failed_bridge(context: ReadinessContext, *args: object) -> dict[str, bool]:
            events.append("bridge_failed")
            if failed_step == "unknown_identity":
                (context.runtime / "runtime.json").write_bytes(
                    b"invalid synthetic identity"
                )
            raise module.EndpointError("memory_endpoint_transport_failed")

        monkeypatch.setattr(module, "_native_bridge_check", failed_bridge)
    result = _verify(module, workspace)
    assert result["ready"] is False
    clean = failed_step == "bridge"
    assert result["cleanup_confirmed"] is clean
    assert result["runtime_removed"] is clean
    assert allocated[0].exists() is not clean
    if failed_step == "unknown_identity":
        assert "key_cleanup" not in events
    checkpoint = json.loads(
        (workspace / "readiness-checkpoint.private.json").read_bytes()
    )
    assert checkpoint["cleanup_confirmed"] is clean


def test_bounded_native_process_timeout_reaps_only_its_own_group(
    tmp_path: Path,
) -> None:
    module = _module()
    records: list[dict[str, object]] = []
    checkpoints: list[int] = []
    with pytest.raises(module.EndpointError, match="readiness_process_timeout"):
        module._run_owned(
            [sys.executable, "-I", "-S", "-c", "import time;time.sleep(10)"],
            environment={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
            cwd=tmp_path,
            phase="synthetic_timeout",
            processes=records,
            checkpoint=lambda: checkpoints.append(len(records)),
            timeout=0.05,
        )
    assert len(records) == 1 and records[0]["reaped"] is True
    assert records[0]["process_group_stopped"] is True
    assert checkpoints and all(value == 1 for value in checkpoints)


def test_artifact_change_during_cleanup_refuses_completed_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    workspace = tmp_path / "receipt-workspace"
    workspace.mkdir(mode=0o700)
    _fake_readiness(module, monkeypatch, tmp_path)
    original = module._artifact_bindings
    changed = False

    def bindings(memory: Path, client: Path) -> dict[str, str]:
        values = cast(dict[str, str], original(memory, client))
        return {**values, "bridge_transport_digest": "cd" * 32} if changed else values

    def cleanup(context: ReadinessContext, interpreter: Path) -> bool:
        nonlocal changed
        changed = True
        return True

    monkeypatch.setattr(module, "_artifact_bindings", bindings)
    monkeypatch.setattr(module, "_cleanup_native_key", cleanup)
    result = _verify(module, workspace)
    assert result["ready"] is False and result["bindings_unchanged"] is False
    assert result["cleanup_confirmed"] is True


def test_unconfirmed_owned_group_preserves_key_and_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    workspace = tmp_path / "receipt-workspace"
    workspace.mkdir(mode=0o700)
    events, allocated = _fake_readiness(module, monkeypatch, tmp_path)

    def failed_bridge(context: ReadinessContext, *args: object) -> dict[str, bool]:
        context.processes.append(
            {
                "phase": "synthetic_unreaped",
                "pid": 988,
                "pgid": 988,
                "reaped": False,
                "process_group_stopped": False,
            }
        )
        raise module.EndpointError("readiness_process_cleanup_unconfirmed")

    monkeypatch.setattr(module, "_native_bridge_check", failed_bridge)
    result = _verify(module, workspace)
    assert "key_cleanup" not in events
    assert result["processes_reaped"] is False and result["cleanup_confirmed"] is False
    assert allocated[0].is_dir()


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_native_output_limit_terminates_and_reaps_owned_group(
    tmp_path: Path, stream: str
) -> None:
    module = _module()
    records: list[dict[str, object]] = []
    with pytest.raises(module.EndpointError, match="readiness_process_output_limit"):
        module._run_owned(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                "import sys,time;sys."
                + stream
                + ".buffer.write(b'x'*70000);sys."
                + stream
                + ".flush();time.sleep(10)",
            ],
            environment={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
            cwd=tmp_path,
            phase="synthetic_output",
            processes=records,
            checkpoint=lambda: None,
            timeout=2,
        )
    assert records[0]["reaped"] is True


def test_installed_interpreter_keeps_venv_link_and_rejects_ambiguous_shebang(
    tmp_path: Path,
) -> None:
    module = _module()
    interpreter = tmp_path / "python"
    interpreter.symlink_to(sys.executable)
    memory = tmp_path / "memory"
    memory.write_text("#!" + str(interpreter) + "\n", encoding="utf-8")
    memory.chmod(0o700)
    assert module._memory_interpreter(memory) == interpreter
    memory.write_text("#!/usr/bin/env python\n", encoding="utf-8")
    with pytest.raises(module.EndpointError, match="readiness_artifact_unavailable"):
        module._memory_interpreter(memory)


@pytest.mark.parametrize(
    "broken", [None, "endpoint", "read", "write", "mcp", "transport"]
)
def test_native_phase_wiring_uses_separate_os_bootstrap_boundary_without_model_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broken: str | None
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    module._tools_on_path()
    import behavioral_codex_isolation as isolation
    import behavioral_mcp_bridge as transport

    allocation = tmp_path / "fresh-allocation"
    allocation.mkdir(mode=0o700)
    context = module._ReadinessContext(tmp_path, allocation, {})
    context.runtime.mkdir(mode=0o700)
    memory, client, python = (
        Path("/synthetic/memory"),
        Path("/synthetic/codex"),
        Path(sys.executable).resolve(),
    )
    commands: list[tuple[str, ...]] = []
    phases: list[str] = []
    expected_bootstrap = allocation / "endpoint" / ".mcp-endpoint-home"

    def endpoint_policy(
        command: Sequence[str], *, policy_path: Path, credential_homes: Sequence[Path]
    ) -> list[str]:
        assert tuple(command) == (str(memory), "mcp", "--home", str(context.runtime))
        assert all(path.is_relative_to(allocation) for path in credential_homes)
        policy_path.write_text("synthetic policy", encoding="utf-8")
        policy_path.chmod(0o600)
        return ["/usr/bin/sandbox-exec", "-f", str(policy_path), *command]

    def client_policy(
        command: Sequence[str],
        *,
        policy_path: Path,
        executable_paths: Sequence[Path],
        bridge_socket: Path,
        readable_proxy_files: Sequence[Path],
        memory_home: Path,
        credential_homes: Sequence[Path],
        credential_client: Path,
        endpoint_environment_root: Path,
    ) -> list[str]:
        assert command[0] == str(client) and credential_client == client
        assert client in executable_paths and python in executable_paths
        assert memory_home == context.runtime
        assert endpoint_environment_root == expected_bootstrap
        assert not endpoint_environment_root.is_relative_to(memory_home)
        assert not memory_home.is_relative_to(endpoint_environment_root)
        assert all(path.is_relative_to(allocation) for path in credential_homes)
        assert readable_proxy_files and bridge_socket.is_absolute()
        policy_path.write_text("synthetic policy", encoding="utf-8")
        policy_path.chmod(0o600)
        return ["/usr/bin/sandbox-exec", "-f", str(policy_path), *command]

    class SyntheticBridge:
        endpoint_started = True
        proxy_auth_environment_absent = True
        proxy_environment_isolated = True
        proxy_auth_home_denied = True
        failure_label = "synthetic_transport_failure" if broken == "transport" else None
        endpoint_process_metadata: Mapping[str, object] = {
            "phase": "memory_mcp_endpoint",
            "pid": 444,
            "pgid": 444,
            "reaped": True,
            "process_group_stopped": True,
        }
        process_cleanup_confirmed = False
        resources_cleanup_confirmed = False

        def __init__(
            self,
            *,
            root: Path,
            endpoint_command: Sequence[str],
            endpoint_environment: Mapping[str, str],
            endpoint_cwd: Path,
            proxy_python: Path,
            credential_homes: Sequence[Path],
            credential_canary: Path,
            limits: object,
        ) -> None:
            module.validate_endpoint_environment(endpoint_environment, endpoint_cwd)
            assert endpoint_environment["HOME"] == "/Users/synthetic-os-account"
            assert endpoint_environment["PYTHONNOUSERSITE"] == "1"
            assert "CODEX_API_KEY" not in endpoint_environment
            assert str(context.runtime) in endpoint_command
            assert proxy_python == python
            assert any(
                credential_canary.is_relative_to(home) for home in credential_homes
            )
            self.proxy_command = (
                "/usr/bin/env",
                "-i",
                "HOME=/synthetic/proxy",
                str(python),
                "-I",
                "-S",
                str(root / "proxy.py"),
            )
            self.proxy_executable_paths = (Path("/usr/bin/env"), python)
            self.proxy_read_paths = (root / "proxy.py", root / "proxy-session.private")
            self.socket_path = root / "synthetic.sock"
            self.cleanup_paths = (
                root / "synthetic-material",
                root / "synthetic-socket",
            )

        def __enter__(self) -> SyntheticBridge:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            self.close()

        def close(self) -> None:
            self.process_cleanup_confirmed = True
            self.resources_cleanup_confirmed = True

    def run_owned(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        phase: str,
        processes: list[dict[str, object]],
        checkpoint: Callable[[], None],
        timeout: float = 30,
        request: bytes | None = None,
        first_line: bool = False,
        before_stop: Callable[[], None] | None = None,
        observer: Callable[[], None] | None = None,
    ) -> object:
        commands.append(tuple(command))
        phases.append(phase)
        assert command[3] != str(client)
        if phase == "endpoint_credential_boundary":
            assert set(environment) == module.ENDPOINT_ENVIRONMENT_KEYS
            assert environment["HOME"] == "/Users/synthetic-os-account"
            payload: dict[str, object] = {
                "auth_denied": broken != "endpoint",
                "auth_environment_absent": True,
            }
        elif phase == "client_endpoint_boundary":
            assert command[-1] == str(expected_bootstrap)
            payload = {
                "auth_denied": True,
                "auth_environment_absent": True,
                "environment_read_denied": broken != "read",
                "environment_write_denied": broken != "write",
            }
        else:
            assert phase == "memory_stdio_proxy" and request is not None and first_line
            assert command[3] == "/usr/bin/env" and "CODEX_API_KEY" in environment
            sent = json.loads(request)
            assert sent["method"] == "initialize"
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "Memory"},
                },
            }
            if broken == "mcp":
                payload["error"] = {"code": -32603}
        if before_stop is not None:
            before_stop()
        if observer is not None:
            observer()
        return module._ProcessResult(0, json.dumps(payload).encode(), b"")

    monkeypatch.setattr(isolation, "endpoint_command", endpoint_policy)
    monkeypatch.setattr(isolation, "execution_command", client_policy)
    monkeypatch.setattr(isolation, "system_python", lambda: python)
    monkeypatch.setattr(transport, "MCPBridge", SyntheticBridge)
    monkeypatch.setattr(module, "_run_owned", run_owned)
    if broken is None:
        result = module._native_bridge_check(context, memory, client, python)
        assert result and all(result.values())
        assert phases == [
            "endpoint_credential_boundary",
            "client_endpoint_boundary",
            "memory_stdio_proxy",
        ]
    else:
        with pytest.raises(module.EndpointError):
            module._native_bridge_check(context, memory, client, python)
        if broken in {"endpoint", "read", "write"}:
            assert "memory_stdio_proxy" not in phases
    assert commands and all(command[3] != str(client) for command in commands)


def test_key_cleanup_requires_an_actual_boolean_absence_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    root = tmp_path / "fresh-allocation"
    root.mkdir(mode=0o700)
    context = module._ReadinessContext(
        tmp_path, root, {"memory_interpreter_digest": "ab" * 32}
    )
    context.store_id = "73" * 16
    monkeypatch.setattr(module, "_file_digest", lambda _path: "ab" * 32)

    def forged_receipt(command: object, **kwargs: object) -> object:
        return module._ProcessResult(0, b'{"absent":1}', b"")

    monkeypatch.setattr(module, "_run_owned", forged_receipt)
    assert module._cleanup_native_key(context, Path(sys.executable)) is False


@pytest.mark.parametrize("enter_fails", [False, True])
def test_bridge_resource_failure_keeps_every_recovery_root_in_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enter_fails: bool
) -> None:
    module = _module()
    _os_account(module, monkeypatch)
    native_bridge_check = module._native_bridge_check
    workspace = tmp_path / "receipt-workspace"
    workspace.mkdir(mode=0o700)
    events, allocated = _fake_readiness(module, monkeypatch, tmp_path)
    module._tools_on_path()
    import behavioral_codex_isolation as isolation
    import behavioral_mcp_bridge as transport

    external = tmp_path / "synthetic-external-bridge-root"
    external.mkdir(mode=0o700)
    bridge_paths: list[Path] = []
    real_rmtree = shutil.rmtree

    def endpoint_policy(
        command: Sequence[str], *, policy_path: Path, credential_homes: Sequence[Path]
    ) -> list[str]:
        policy_path.write_text("synthetic policy", encoding="utf-8")
        policy_path.chmod(0o600)
        return ["/usr/bin/sandbox-exec", "-f", str(policy_path), *command]

    def refuse_client_policy(*args: object, **kwargs: object) -> list[str]:
        raise module.EndpointError("synthetic_client_policy_failure")

    def no_native_process(command: object, **kwargs: object) -> object:
        return module._ProcessResult(
            0, b'{"auth_denied":true,"auth_environment_absent":true}', b""
        )

    def enter(bridge: transport.MCPBridge) -> transport.MCPBridge:
        bridge._entered = True
        bridge._material = Path(
            tempfile.mkdtemp(prefix="synthetic-bridge-", dir=bridge._root)
        )
        bridge._socket_root = external
        bridge.socket_path = external / "s"
        bridge_paths.extend((bridge._material, external))
        if enter_fails:
            bridge.close()
            raise module.EndpointError("synthetic_enter_failure")
        return bridge

    def fail_external(path: Path | str, *args: object, **kwargs: object) -> None:
        if Path(path) == external:
            raise OSError("synthetic exact-root removal failure")
        real_rmtree(path)

    monkeypatch.setattr(isolation, "endpoint_command", endpoint_policy)
    monkeypatch.setattr(isolation, "execution_command", refuse_client_policy)
    monkeypatch.setattr(
        isolation, "system_python", lambda: Path(sys.executable).resolve()
    )
    monkeypatch.setattr(module, "_run_owned", no_native_process)
    monkeypatch.setattr(module, "_native_bridge_check", native_bridge_check)
    monkeypatch.setattr(transport.MCPBridge, "__enter__", enter)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(shutil, "rmtree", fail_external)
            result = _verify(module, workspace)
        assert result["ready"] is False
        assert result["outcome_label"] == "memory_endpoint_cleanup_unconfirmed"
        assert result["cleanup_confirmed"] is False
        assert result["bridge_cleanup_confirmed"] is False
        assert (
            result["processes_reaped"] is True
            and result["key_cleanup_confirmed"] is True
        )
        assert "key_cleanup" in events
        assert result["runtime_removed"] is False
        assert allocated[0].is_dir() and external.is_dir()
        checkpoint = json.loads(
            (workspace / "readiness-checkpoint.private.json").read_bytes()
        )
        assert checkpoint["bridge_allocation_started"] is True
        assert checkpoint["bridge_cleanup_confirmed"] is False
        assert set(checkpoint["bridge_resource_paths"]) == {
            str(path) for path in bridge_paths
        }
        assert checkpoint["fresh_root"] == str(allocated[0])
    finally:
        real_rmtree(external)
        for root in allocated:
            if root.exists():
                real_rmtree(root)
