"""Actual client execution must retain the startup boundary used by its proof."""

from __future__ import annotations

import json
import os
import pwd
import signal
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from test_behavioral_acceptance_tool import (
    MANIFEST_PATH,
    _provenance,
    _TestClientLaunch,
    _tool,
)
from test_behavioral_mcp_bridge import _module as _bridge_module


def _execution_state(
    tool: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = cast(
        dict[str, Any],
        tool.create_run_state(manifest, trials=1, provenance=_provenance()),
    )
    state["private"] = {
        "memory_executable": str(tmp_path / "memory"),
        "client_executable": str(tmp_path / "codex"),
        "seed_executable": str(tmp_path / "seed"),
    }
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-scoped-client-key")
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(tool, "_require_codex_capabilities", lambda _state: {})

    def fixture_command(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["skill", "install"]:
            Path(command[-1]).write_text("Synthetic checked Skill.", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(tool, "_run_text", fixture_command)
    (tmp_path / "workspace").mkdir()
    return state


@pytest.mark.parametrize("failure", [None, "cleanup", "transport", "interruption"])
def test_subscription_credentials_return_only_after_verified_client_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    tool = _tool()
    state = _execution_state(tool, tmp_path, monkeypatch)
    state["provenance"].update(
        authentication_mode="chatgpt_subscription",
        authentication_adapter_digest="ab" * 32,
        code_mode_host_digest="88" * 32,
        isolation_profile_digest="99" * 32,
    )
    events: list[str] = []
    session = object()
    monkeypatch.setattr(
        tool, "_subscription_session", lambda _state: session, raising=False
    )

    def forbidden_auth(_kind: str) -> None:
        pytest.fail("subscription execution reached API credentials")

    monkeypatch.setattr(tool, "_client_authentication", forbidden_auth)
    monkeypatch.setattr(
        tool,
        "_store_snapshot",
        lambda *_args: {"mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32},
    )

    class Lease:
        credential_homes = (
            tmp_path / "fresh-auth",
            tmp_path / "workspace" / ".client-home",
        )
        credential_canary = credential_homes[1] / "synthetic-canary"
        public_ca_bundle = tmp_path / "pinned-public-ca.pem"

        def complete(self) -> None:
            events.append("credentials_complete")

    @contextmanager
    def credentials(actual_session: object, client_home: Path) -> Iterator[Lease]:
        assert actual_session is session
        assert client_home == Lease.credential_homes[1]
        assert client_home.is_dir()
        events.append("credentials_enter")
        try:
            yield Lease()
        finally:
            events.append("credentials_exit")

    monkeypatch.setattr(tool, "_subscription_lease", credentials, raising=False)

    @contextmanager
    def protected(*_args: object, **options: object) -> Iterator[_TestClientLaunch]:
        assert callable(options.pop("observe_lifecycle"))
        assert options == {
            "authentication_mode": "chatgpt_subscription",
            "credential_homes": Lease.credential_homes,
            "credential_canary": Lease.credential_canary,
            "public_ca_bundle": Lease.public_ca_bundle,
            "events_path": tmp_path / "client-events.private",
        }
        events.append("protection_enter")
        try:
            yield cast(_TestClientLaunch, tool.ClientLaunch(["/synthetic/client"]))
            if failure == "cleanup":
                raise tool.AcceptanceError("synthetic cleanup failure")
        finally:
            events.append("protection_exit")

    monkeypatch.setattr(tool, "_codex_execution_command", protected)

    def launch(_command: Sequence[str], **options: Any) -> tuple[int, str | None]:
        assert "CODEX_API_KEY" not in options["environment"]
        assert "OPENAI_API_KEY" not in options["environment"]
        assert options["environment"]["CODEX_CA_CERTIFICATE"] == str(
            Lease.public_ca_bundle
        )
        events.append("client_finished")
        if failure == "interruption":
            raise KeyboardInterrupt
        return (1, "client_transport_failed") if failure == "transport" else (0, None)

    monkeypatch.setattr(tool, "_run_client_to_private_files", launch)
    manifest = tool.load_manifest(MANIFEST_PATH)
    slot = state["slots"][0]

    def execute() -> object:
        return tool._actual_executor(state, manifest)(
            manifest.cases[slot["case_id"]],
            1,
            tmp_path / "store",
            tmp_path / "workspace",
            tmp_path / "response.private",
        )

    if failure == "interruption":
        with pytest.raises(KeyboardInterrupt):
            execute()
    else:
        execute()
    assert events == [
        "credentials_enter",
        "protection_enter",
        "client_finished",
        "protection_exit",
        *(["credentials_complete"] if failure is None else []),
        "credentials_exit",
    ]


@pytest.mark.parametrize(
    "failure", [None, "before_launch", "after_launch", "persistence", "interruption"]
)
def test_actual_executor_keeps_protection_and_bridge_alive_through_client_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    tool = _tool()
    state = _execution_state(tool, tmp_path, monkeypatch)
    slot = state["slots"][0]
    events: list[str] = []

    def snapshot(*_args: object) -> dict[str, object]:
        events.append("snapshot")
        return {"mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32}

    monkeypatch.setattr(tool, "_store_snapshot", snapshot)

    @contextmanager
    def protected(*_args: object, **_kwargs: object) -> Iterator[_TestClientLaunch]:
        events.append("protection_enter")
        assert slot["client_launch_attempted"] is False
        if failure == "before_launch":
            raise tool.AcceptanceError("synthetic protection unavailable")
        try:
            yield cast(
                _TestClientLaunch, tool.ClientLaunch(["/synthetic/protected-client"])
            )
            if failure == "after_launch":
                raise tool.AcceptanceError("synthetic bridge transport failed")
        finally:
            events.append("protection_exit")

    monkeypatch.setattr(tool, "_codex_execution_command", protected, raising=False)

    def persist() -> None:
        if slot["client_launch_attempted"]:
            events.append("persist_launch")
            if failure == "persistence":
                raise OSError("synthetic state persistence unavailable")
            if failure == "interruption":
                raise KeyboardInterrupt

    def launch(command: Sequence[str], **_kwargs: object) -> tuple[int, str | None]:
        assert command == ["/synthetic/protected-client"]
        assert events[-1] == "persist_launch"
        assert slot["client_launch_attempted"] is True
        assert slot["inference_started"] is None
        events.append("client_launch")
        return 0, None

    monkeypatch.setattr(tool, "_run_client_to_private_files", launch)
    manifest = tool.load_manifest(MANIFEST_PATH)

    def execute() -> dict[str, Any]:
        return cast(
            dict[str, Any],
            tool._actual_executor(state, manifest, persist=persist)(
                manifest.cases[slot["case_id"]],
                1,
                tmp_path / "store",
                tmp_path / "workspace",
                tmp_path / "response.private",
            ),
        )

    if failure in {"before_launch", "persistence", "interruption"}:
        if failure == "interruption":
            with pytest.raises(KeyboardInterrupt):
                execute()
        else:
            with pytest.raises(tool.TrialBlocked) as captured:
                execute()
            assert captured.value.label == (
                "client_launch_state_unavailable"
                if failure == "persistence"
                else "client_isolation_controls_unavailable"
            )
        assert slot["client_launch_attempted"] is False
        assert slot["inference_started"] is False
        assert events == (
            ["snapshot", "protection_enter", "snapshot"]
            if failure == "before_launch"
            else [
                "snapshot",
                "protection_enter",
                "persist_launch",
                "protection_exit",
                "snapshot",
            ]
        )
    else:
        result = execute()
        assert events == [
            "snapshot",
            "protection_enter",
            "persist_launch",
            "client_launch",
            "protection_exit",
            "snapshot",
        ]
        assert result["before_status"] == result["after_status"]
        assert result["failure_label"] == (
            "client_transport_failed" if failure else None
        )


@pytest.mark.parametrize(
    "failure", [None, "policy", "transport", "timeout", "unstarted", "proxy_auth"]
)
@pytest.mark.parametrize("subscription", [False, True])
def test_guarded_command_binds_only_the_exact_endpoint_and_private_proxy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
    subscription: bool,
) -> None:
    tool = _tool()
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    memory, home = tmp_path / "memory", tmp_path / "synthetic-store"
    client, python = tmp_path / "codex", tmp_path / "framework-python"
    proxy = [str(python), "-I", "-S", str(workspace / "proxy.py")]
    events: list[str] = []
    observed: dict[str, object] = {}
    credential_homes = (workspace / "fresh-auth", workspace / ".client-home")
    credential_canary = credential_homes[1] / "synthetic-canary"
    public_ca_bundle = workspace / "pinned-public-ca.pem"

    class BoundaryError(Exception):
        pass

    class SyntheticLifecycle:
        def __init__(self, events_path: Path) -> None:
            assert events_path == workspace / "client-events.private"

        natural_exit_zero = True
        client_completion_confirmed = True

        def completion_probe(self) -> bool:
            return True

        def record_transport(self, _metadata: Mapping[str, object]) -> None:
            pass

    class SyntheticBridge:
        def __init__(
            self,
            *,
            root: Path,
            endpoint_command: Sequence[str],
            endpoint_environment: Mapping[str, str],
            endpoint_cwd: Path,
            proxy_python: Path,
            **options: object,
        ) -> None:
            assert root == workspace and endpoint_cwd == workspace
            assert proxy_python == python
            assert list(endpoint_command) == [
                *(["/synthetic/endpoint-guard"] if subscription else []),
                str(memory),
                "mcp",
                "--home",
                str(home),
            ]
            assert callable(options.pop("completion_probe"))
            assert options == (
                {
                    "credential_homes": credential_homes,
                    "credential_canary": credential_canary,
                }
                if subscription
                else {}
            )
            assert set(endpoint_environment) == {
                "HOME",
                "TMPDIR",
                "PATH",
                "LANG",
                "LC_ALL",
                "PYTHON_KEYRING_BACKEND",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "PYTHONNOUSERSITE",
            }
            assert endpoint_environment["HOME"] == pwd.getpwuid(os.getuid()).pw_dir
            assert endpoint_environment["PYTHON_KEYRING_BACKEND"] == (
                "keyring.backends.macOS.Keyring"
            )
            assert endpoint_environment["PYTHONNOUSERSITE"] == "1"
            for variable, child in (
                ("TMPDIR", "tmp"),
                ("XDG_CONFIG_HOME", "config"),
                ("XDG_CACHE_HOME", "cache"),
            ):
                path = Path(endpoint_environment[variable])
                assert path == workspace / ".mcp-endpoint-home" / child
                assert path.stat().st_mode & 0o077 == 0
            self.proxy_command = proxy
            self.unix_socket_path = workspace / "synthetic.sock"
            self.proxy_read_paths = (workspace / "proxy.py", workspace / "credential")
            self.failure_label: str | None = None
            self.endpoint_started = failure != "unstarted"
            self.proxy_auth_environment_absent = subscription or failure != "proxy_auth"
            self.proxy_auth_home_denied = failure != "proxy_auth"
            self.proxy_environment_isolated = True
            self.proxy_executable_paths = (python, Path("/synthetic/env"))
            self.client_completion_confirmed = True
            self.process_cleanup_confirmed = True
            self.resources_cleanup_confirmed = True
            self.lifecycle_metadata: Mapping[str, object] = {}
            self.endpoint_process_metadata: Mapping[str, object] | None = None
            self.cleanup_paths: tuple[Path, ...] = ()

        def __enter__(self) -> SyntheticBridge:
            events.append("bridge_enter")
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("bridge_closed")
            if failure == "transport":
                self.failure_label = "synthetic_transport_failure"

        def close(self) -> None:
            events.append("bridge_shutdown_callback")

        def finish_client(self) -> None:
            self.close()

        def wait(self, timeout: float) -> bool:
            assert timeout == 5
            events.append("bridge_wait")
            return failure != "timeout"

    def protect(command: Sequence[str], **options: object) -> list[str]:
        events.append("policy")
        observed.update(options)
        observed["command"] = list(command)
        if failure == "policy":
            raise BoundaryError("synthetic policy unavailable")
        return ["/synthetic/OS-guard", *command]

    def endpoint_protection(command: Sequence[str], **options: object) -> list[str]:
        assert options["credential_homes"] == credential_homes
        return ["/synthetic/endpoint-guard", *command]

    isolation = ModuleType("behavioral_codex_isolation")
    monkeypatch.setattr(isolation, "CapabilityProbeError", BoundaryError, raising=False)
    monkeypatch.setattr(isolation, "execution_command", protect, raising=False)
    monkeypatch.setattr(isolation, "system_python", lambda: python, raising=False)
    monkeypatch.setattr(
        isolation, "endpoint_command", endpoint_protection, raising=False
    )
    bridge_module = ModuleType("behavioral_mcp_bridge")
    monkeypatch.setattr(bridge_module, "BridgeError", BoundaryError, raising=False)
    monkeypatch.setattr(bridge_module, "MCPBridge", SyntheticBridge, raising=False)
    monkeypatch.setitem(sys.modules, "behavioral_codex_isolation", isolation)
    monkeypatch.setitem(sys.modules, "behavioral_mcp_bridge", bridge_module)
    lifecycle_module = ModuleType("behavioral_client_lifecycle")
    monkeypatch.setattr(
        lifecycle_module, "ClientLifecycle", SyntheticLifecycle, raising=False
    )
    monkeypatch.setattr(
        lifecycle_module, "LifecycleError", BoundaryError, raising=False
    )
    monkeypatch.setitem(sys.modules, "behavioral_client_lifecycle", lifecycle_module)
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-must-not-reach-endpoint")
    monkeypatch.setattr(
        tool,
        "_codex_launch_arguments",
        lambda *_args, **_kwargs: [str(client), "--bound-profile"],
    )

    def run() -> None:
        options = (
            {
                "authentication_mode": "chatgpt_subscription",
                "credential_homes": credential_homes,
                "credential_canary": credential_canary,
                "public_ca_bundle": public_ca_bundle,
            }
            if subscription
            else {}
        )
        with tool._codex_execution_command(
            client, memory, home, workspace, "synthetic-model", "max", **options
        ) as raw_launch:
            launch = cast(_TestClientLaunch, raw_launch)
            command = launch.command
            assert command[:3] == [
                "/synthetic/OS-guard",
                str(client),
                "--bound-profile",
            ]
            assert str(memory) not in " ".join(command)
            assert str(home) not in " ".join(command)
            assert (
                "mcp_servers.memory_behavioral_acceptance.command="
                + json.dumps(proxy[0])
                in command
            )
            assert (
                "mcp_servers.memory_behavioral_acceptance.args=" + json.dumps(proxy[1:])
                in command
            )
            events.append("client_body")
            assert launch.before_cleanup is not None
            launch.before_cleanup()

    if failure is None:
        run()
    else:
        with pytest.raises(tool.AcceptanceError):
            run()
    assert events[-1] == "bridge_closed"
    assert observed["memory_home"] == home
    assert observed["endpoint_environment_root"] == (workspace / ".mcp-endpoint-home")
    assert observed["credential_homes"] == (credential_homes if subscription else ())
    assert observed["credential_client"] == (client if subscription else None)
    assert observed["executable_paths"] == (
        client,
        client.parent / "codex-code-mode-host",
        python,
        Path("/synthetic/env"),
    )
    assert observed["readable_proxy_files"] == (
        workspace / "proxy.py",
        workspace / "credential",
        *((workspace / "endpoint-policy.private.sb",) if subscription else ()),
        *((public_ca_bundle,) if subscription else ()),
    )
    assert observed["bridge_socket"] == workspace / "synthetic.sock"
    assert ("client_body" in events) is (failure != "policy")


@pytest.mark.parametrize("mode", ["normal", "early_disconnect", "cleanup_error"])
def test_client_shutdown_coordinates_bridge_before_killing_waiting_proxy(
    tmp_path: Path, mode: str
) -> None:
    tool, module = _tool(), _bridge_module()
    python = str(Path(sys.executable).resolve())
    endpoint = tmp_path / "inert-endpoint.py"
    endpoint.write_text(
        "import sys,time\n"
        "for line in sys.stdin.buffer:\n"
        " sys.stdout.buffer.write(line)\n"
        " sys.stdout.buffer.flush()\n"
        "time.sleep(0.2)\n",
        encoding="utf-8",
    )
    home = tmp_path / "synthetic-home"
    home.mkdir(mode=0o700)
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C"}
    bridge = module.MCPBridge(
        tmp_path,
        [python, "-I", "-S", str(endpoint)],
        environment,
        tmp_path,
        Path(python),
    )
    callbacks: list[str] = []
    with bridge:
        materials = tuple(bridge.proxy_read_paths)
        client = tmp_path / "inert-client.py"
        client.write_text(
            "import os,subprocess,time\n"
            f"proxy=subprocess.Popen({list(bridge.proxy_command)!r},"
            "stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)\n"
            "assert proxy.stdin and proxy.stdout\n"
            'proxy.stdin.write(b\'{"jsonrpc":"2.0","id":1,"result":"synthetic"}\\n\')\n'
            "proxy.stdin.flush()\n"
            "assert proxy.stdout.readline().endswith(b'\\n')\n"
            + (
                "proxy.kill()\nproxy.wait()\ntime.sleep(0.2)\n"
                if mode == "early_disconnect"
                else ""
            )
            + "print('synthetic completed client output',flush=True)\nos._exit(0)\n",
            encoding="utf-8",
        )

        def close_bridge() -> None:
            callbacks.append("close")
            bridge.close()
            if mode == "cleanup_error":
                raise OSError("synthetic cleanup callback failure")

        exit_status, failure = tool._run_client_to_private_files(
            [python, "-I", "-S", str(client)],
            environment=environment,
            cwd=tmp_path,
            input_text=None,
            stdout_path=tmp_path / "stdout.private",
            stderr_path=tmp_path / "stderr.private",
            timeout=5,
            before_cleanup=close_bridge,
        )
        assert callbacks == ["close"]
        assert exit_status == 0
        assert failure == (
            "client_transport_failed" if mode == "cleanup_error" else None
        )
        assert bridge.wait(timeout=2)
        assert bridge.failure_label == (
            "bridge_disconnected" if mode == "early_disconnect" else None
        )
        assert all(not path.exists() for path in materials)


def test_refused_group_shutdown_never_reports_verified_client_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    marker = tmp_path / "owned-processes.json"
    python = str(Path(sys.executable).resolve())
    script = (
        "import json,os,subprocess,sys\n"
        "child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        f"open({str(marker)!r},'w').write(json.dumps([os.getpid(),child.pid]))\n"
    )
    actual_killpg = os.killpg

    def refused(_group: int, _signal: int) -> None:
        raise PermissionError("Synthetic process-group signal refusal.")

    monkeypatch.setattr(tool.os, "killpg", refused)
    try:
        status, failure = tool._run_client_to_private_files(
            [python, "-I", "-S", "-c", script],
            environment={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
            cwd=tmp_path,
            input_text=None,
            stdout_path=tmp_path / "output.private",
            stderr_path=tmp_path / "error.private",
            timeout=5,
        )
        assert status == 0
        assert failure == "client_teardown_unverified"
    finally:
        if marker.exists():
            group, _child = json.loads(marker.read_text(encoding="utf-8"))
            actual_killpg(group, signal.SIGKILL)
