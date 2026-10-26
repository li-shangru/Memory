"""The development bridge uses fresh inert endpoints, never a real Store."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import NoReturn

import pytest

BRIDGE = Path(__file__).resolve().parents[1] / "tools/behavioral_mcp_bridge.py"


def _module() -> ModuleType:
    name = "behavioral_mcp_bridge_test_module"
    spec = importlib.util.spec_from_file_location(name, BRIDGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _isolation_module() -> ModuleType:
    name = "behavioral_codex_isolation_bridge_test_module"
    spec = importlib.util.spec_from_file_location(
        name, BRIDGE.with_name("behavioral_codex_isolation.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _endpoint_environment(root: Path) -> dict[str, str]:
    directory = str(BRIDGE.parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import behavioral_memory_endpoint

    return behavioral_memory_endpoint.endpoint_environment(root)


def test_complete_native_endpoint_environment_is_admitted(root: Path) -> None:
    module = _module()
    command, _ = _endpoint(root, "pass\n")
    environment = _endpoint_environment(root)
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    bridge.close()


def test_native_os_home_is_not_resolved_or_inspected(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    command, _ = _endpoint(root, "pass\n")
    environment = _endpoint_environment(root)
    credential_home = root / "synthetic-auth-home"
    credential_home.mkdir(mode=0o700)
    canary = credential_home / "synthetic-canary"
    canary.write_bytes(b"synthetic")
    canary.chmod(0o600)
    original = Path.resolve

    def resolve(path: Path, strict: bool = False) -> Path:
        assert str(path) != environment["HOME"], (
            "OS account HOME must remain metadata only"
        )
        return original(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve)
    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        credential_homes=(credential_home,),
        credential_canary=canary,
    )
    bridge.close()


@pytest.mark.parametrize(
    "change", ["partial", "backend", "config", "cache", "temporary", "credential"]
)
def test_native_endpoint_environment_rejects_partial_or_untrusted_tuple(
    root: Path, change: str
) -> None:
    module = _module()
    command, _ = _endpoint(root, "pass\n")
    environment = _endpoint_environment(root)
    if change == "partial":
        environment.pop("XDG_CACHE_HOME")
    elif change == "backend":
        environment["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"
    elif change == "credential":
        environment["CODEX_API_KEY"] = "synthetic-never-valid"
    else:
        key = {
            "config": "XDG_CONFIG_HOME",
            "cache": "XDG_CACHE_HOME",
            "temporary": "TMPDIR",
        }[change]
        environment[key] = str(root / "unrelated")
    with pytest.raises(module.BridgeError, match="bridge_invalid_configuration"):
        module.MCPBridge(
            root, command, environment, root, Path(sys.executable).resolve()
        )


@pytest.fixture
def root() -> Iterator[Path]:
    # AF_UNIX paths have a small OS limit; an explicit disposable root keeps
    # these fixtures independent of pytest's longer nested directory names.
    with tempfile.TemporaryDirectory(prefix="memory-bridge-", dir="/tmp") as value:
        yield Path(value)


def _endpoint(root: Path, source: str) -> tuple[list[str], dict[str, str]]:
    path = root / "inert-endpoint.py"
    path.write_text(source, encoding="utf-8")
    home = root / "endpoint-home"
    home.mkdir()
    return [str(Path(sys.executable).resolve()), "-I", "-S", str(path)], {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LANG": "en_US.UTF-8",
    }


@contextmanager
def _endpoint_with_surviving_child(root: Path) -> Iterator[subprocess.Popen[bytes]]:
    command, environment = _endpoint(
        root,
        "import subprocess,sys\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-I','-S','-c',"
        "'import time;time.sleep(60)'],stdin=subprocess.DEVNULL,"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "Path('child-pid').write_text(str(child.pid))\n",
    )
    process = subprocess.Popen(
        command,
        env=environment,
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    kill_group = os.killpg
    try:
        assert process.wait(timeout=2) == 0
        child_pid = int((root / "child-pid").read_text(encoding="utf-8"))
        os.kill(child_pid, 0)
        yield process
    finally:
        try:
            kill_group(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def test_exited_endpoint_leader_does_not_hide_live_child_when_group_signal_denied(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    with _endpoint_with_surviving_child(root) as process:
        with monkeypatch.context() as patch:

            def deny_group(group: int, number: int) -> NoReturn:
                assert group == process.pid
                assert number in {signal.SIGTERM, signal.SIGKILL}
                raise PermissionError("synthetic owned-group denial")

            patch.setattr(module.os, "killpg", deny_group)
            with pytest.raises(PermissionError):
                module._stop_endpoint(process, 0.05)


def test_successful_group_signal_still_requires_no_live_members(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    with _endpoint_with_surviving_child(root) as process:
        with monkeypatch.context() as patch:

            def dropped_group_signal(group: int, number: int) -> None:
                assert group == process.pid
                assert number in {signal.SIGTERM, signal.SIGKILL}

            patch.setattr(module.os, "killpg", dropped_group_signal)
            with pytest.raises(module.BridgeError, match=r"^bridge_shutdown_failed$"):
                module._stop_endpoint(process, 0.05)


@contextmanager
def _proxy(
    command: tuple[str, ...],
    root: Path,
    extra_environment: dict[str, str] | None = None,
) -> Iterator[subprocess.Popen[bytes]]:
    environment = {"HOME": str(root), "PATH": "/usr/bin:/bin", "LANG": "C"}
    environment.update(extra_environment or {})
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=root,
        env=environment,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)


def _credential(read_paths: tuple[Path, ...]) -> dict[str, object]:
    value = json.loads(read_paths[1].read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _connect(socket_path: Path, read_paths: tuple[Path, ...]) -> socket.socket:
    credentials = _credential(read_paths)
    assert isinstance(credentials["secret"], str)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(2)
    peer.connect(str(socket_path))
    peer.sendall(
        b"MEMORY-MCP-BRIDGE\x02"
        + bytes.fromhex(credentials["secret"])
        + b"\x00\x01\x02"
    )
    assert peer.recv(1) == b"\x01"
    return peer


def _send_rpc(peer: socket.socket, message: dict[str, object]) -> bytes:
    line = json.dumps(message, separators=(",", ":")).encode() + b"\n"
    peer.sendall(struct.pack("!BI", 1, len(line)) + line)
    return line


def _receive_rpc(peer: socket.socket) -> dict[str, object]:
    def receive(size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = peer.recv(size - len(result))
            assert chunk
            result.extend(chunk)
        return bytes(result)

    kind, size = struct.unpack("!BI", receive(5))
    assert kind == 1
    result = json.loads(receive(size))
    assert isinstance(result, dict)
    return result


def _rpc_endpoint(
    root: Path, after_eof: str = "", response: str = "{'result': {}}"
) -> tuple[list[str], dict[str, str]]:
    return _endpoint(
        root,
        "import json,sys,time\n"
        "for raw in sys.stdin.buffer:\n"
        "    request=json.loads(raw)\n"
        "    if request.get('method')=='synthetic.pending':continue\n"
        "    if 'id' in request and 'method' in request:\n"
        "        body={'result': {}} if request['method']=='initialize' else "
        + response
        + "\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':request['id'],**body}),flush=True)\n"
        + after_eof,
    )


def _initialize_rpc(peer: socket.socket) -> None:
    _send_rpc(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert _receive_rpc(peer) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    _send_rpc(peer, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    _send_rpc(
        peer,
        {
            "jsonrpc": "2.0",
            "id": "synthetic-call",
            "method": "tools/call",
            "params": {
                "name": "synthetic.lookup",
                "arguments": {"query": "private synthetic text never in metadata"},
            },
        },
    )
    assert _receive_rpc(peer)["id"] == "synthetic-call"


@pytest.mark.parametrize("finish", ["peer_eof", "controller"])
def test_opt_in_completion_requires_natural_endpoint_exit_and_empty_rpc(
    root: Path, finish: str
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    )
    with bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            if finish == "peer_eof":
                peer.shutdown(socket.SHUT_WR)
                assert bridge.wait(2)
            else:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    finished = executor.submit(bridge.finish_client)
                    assert peer.recv(5) == struct.pack("!BI", 2, 0)
                    peer.shutdown(socket.SHUT_WR)
                    finished.result(timeout=2)
            assert bridge.client_completion_confirmed is True
            assert bridge.failure_label is None
    metadata = bridge.lifecycle_metadata
    assert metadata["completion_trigger"] == finish
    assert metadata["endpoint_natural_exit_confirmed"] is True
    assert metadata["endpoint_returncode"] == 0
    assert metadata["endpoint_forced_cleanup"] is False
    assert metadata["client_to_endpoint_requests"] == 2
    assert metadata["client_to_endpoint_notifications"] == 1
    assert metadata["endpoint_to_client_responses"] == 2
    assert metadata["client_to_endpoint_pending_requests"] == 0
    assert metadata["endpoint_to_client_pending_requests"] == 0
    assert metadata["queued_to_peer_bytes"] == 0
    assert metadata["queued_to_endpoint_bytes"] == 0
    assert metadata["client_to_endpoint_methods"] == {
        "initialize": 1,
        "notifications/initialized": 1,
        "tools/call": 1,
    }
    assert metadata["client_to_endpoint_tools"] == {"synthetic.lookup": 1}
    assert (
        metadata["peer_to_bridge_wire_bytes"]
        > metadata["client_to_endpoint_json_bytes"]
    )
    assert metadata["endpoint_stdout_bytes"] > metadata["endpoint_to_client_json_bytes"]
    assert metadata["relay_elapsed_seconds"] >= 0
    assert metadata["endpoint_elapsed_seconds"] >= 0
    assert metadata["process_cleanup_confirmed"] is True
    assert metadata["resources_cleanup_confirmed"] is True
    assert metadata["primary_failure_reason"] is None
    rendered = json.dumps(dict(metadata))
    assert "private synthetic text" not in rendered
    assert "synthetic-call" not in rendered
    assert str(root) not in rendered


def test_opt_in_early_peer_eof_cannot_be_reclassified_after_terminal_flag(
    root: Path,
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    terminal = False
    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: terminal,
    )
    with bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        first_failure = bridge.failure_label
        assert first_failure == "bridge_completion_unconfirmed"
        terminal = True
        with pytest.raises(module.BridgeError, match=first_failure):
            bridge.finish_client()
        assert bridge.failure_label == first_failure
        assert bridge.client_completion_confirmed is False
        assert bridge.lifecycle_metadata["primary_failure_reason"] == first_failure


@pytest.mark.parametrize(
    ("after_eof", "label"),
    [
        ("raise SystemExit(7)\n", "bridge_endpoint_failed"),
        ("time.sleep(60)\n", "bridge_shutdown_timeout"),
        (
            "print(json.dumps({'jsonrpc':'2.0','method':'synthetic.late'}),flush=True)\n",
            "bridge_output_after_completion",
        ),
        (
            "sys.stderr.write('synthetic late stderr');sys.stderr.flush()\n",
            "bridge_output_after_completion",
        ),
    ],
)
def test_opt_in_endpoint_drain_failures_never_confirm_completion(
    root: Path, after_eof: str, label: str
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root, after_eof)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
        limits=module.BridgeLimits(shutdown_timeout_seconds=0.1),
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label == label
        assert bridge.lifecycle_metadata["primary_failure_reason"] == label
        assert bridge.client_completion_confirmed is False


@pytest.mark.parametrize(
    ("condition", "label"),
    [
        ("frame", "bridge_incomplete_frame"),
        ("pending", "bridge_completion_pending_requests"),
        ("queued", "bridge_completion_pending_data"),
        ("no_startup", "bridge_completion_startup_unconfirmed"),
    ],
)
def test_opt_in_completion_refuses_incomplete_protocol_state(
    root: Path, monkeypatch: pytest.MonkeyPatch, condition: str, label: str
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            if condition != "no_startup":
                _initialize_rpc(peer)
            if condition == "frame":
                peer.sendall(b"\x01\x00")
            elif condition in {"pending", "queued"}:
                if condition == "queued":

                    def blocked_write(descriptor: int, data: bytes) -> NoReturn:
                        raise BlockingIOError("synthetic send queue remains blocked")

                    monkeypatch.setattr(module.os, "write", blocked_write)
                    message: dict[str, object] = {
                        "jsonrpc": "2.0",
                        "method": "synthetic.notification",
                    }
                else:
                    message = {
                        "jsonrpc": "2.0",
                        "id": 99,
                        "method": "synthetic.pending",
                    }
                _send_rpc(peer, message)
                if condition == "pending":
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        metadata = bridge.lifecycle_metadata
                        if (
                            metadata["client_to_endpoint_pending_requests"] == 1
                            and metadata["queued_to_endpoint_bytes"] == 0
                        ):
                            break
                        time.sleep(0.005)
                    else:
                        pytest.fail("synthetic pending request did not reach endpoint")
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label == label
        assert bridge.client_completion_confirmed is False


@pytest.mark.parametrize(
    ("response", "label"),
    [
        (
            "{'result': {}, 'error': {'code': -1, 'message': 'synthetic'}}",
            "bridge_invalid_json_rpc",
        ),
        ("{'result': {}, 'id': 'unmatched'}", "bridge_unmatched_rpc_response"),
        ("{'result': {}, 'id': True}", "bridge_invalid_json_rpc"),
    ],
)
def test_opt_in_rejects_malformed_or_unmatched_responses(
    root: Path, response: str, label: str
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root, response=response)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _send_rpc(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            _receive_rpc(peer)
            _send_rpc(peer, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
            assert bridge.wait(2)
        assert bridge.failure_label == label
        assert bridge.client_completion_confirmed is False


def test_opt_in_counts_valid_correlated_error_responses_without_transport_failure(
    root: Path,
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(
        root, response="{'error': {'code': -32601, 'message': 'synthetic unavailable'}}"
    )
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label is None
        assert bridge.client_completion_confirmed is True
        assert bridge.lifecycle_metadata["endpoint_to_client_error_responses"] == 1


def test_opt_in_duplicate_response_fails_with_original_reason_after_cleanup_failure(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import json,sys\n"
        "request=json.loads(sys.stdin.buffer.readline())\n"
        "reply=json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{}})\n"
        "print(reply,flush=True);print(reply,flush=True)\n"
        "sys.stdin.buffer.read()\n",
    )
    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    )
    with bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _send_rpc(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_duplicate_rpc_response"
        with monkeypatch.context() as patch:
            patch.setattr(module.shutil, "rmtree", lambda path: None)
            with pytest.raises(module.BridgeError, match="bridge_cleanup_failed"):
                bridge.close()
            assert bridge.failure_label == "bridge_cleanup_failed"
            assert bridge.lifecycle_metadata["primary_failure_reason"] == (
                "bridge_duplicate_rpc_response"
            )
            assert bridge.client_completion_confirmed is False


def test_opt_in_controller_finishes_live_standalone_proxy_without_signalling_endpoint(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    )
    with bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            assert proxy.stdin is not None and proxy.stdout is not None
            proxy.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n')
            proxy.stdin.flush()
            assert json.loads(proxy.stdout.readline())["id"] == 1

            def no_signal(process: subprocess.Popen[bytes], number: int) -> NoReturn:
                raise AssertionError("natural completion must not signal the endpoint")

            monkeypatch.setattr(module, "_signal_endpoint_group", no_signal)
            bridge.finish_client()
            assert proxy.wait(timeout=2) == 0
            assert bridge.client_completion_confirmed is True
            assert bridge.failure_label is None


@pytest.mark.parametrize("reply", [False, True])
def test_opt_in_accounts_for_endpoint_requests_and_client_responses(
    root: Path, reply: bool
) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import json,sys\n"
        "for raw in sys.stdin.buffer:\n"
        "    message=json.loads(raw)\n"
        "    if 'method' in message and 'id' in message:\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':{}}),flush=True)\n"
        "        if message['method']=='initialize':\n"
        "            print(json.dumps({'jsonrpc':'2.0','id':'endpoint-id','method':'ping'}),flush=True)\n"
        "    elif message.get('id')=='endpoint-id':\n"
        "        print(json.dumps({'jsonrpc':'2.0','method':'synthetic.ack'}),flush=True)\n",
    )
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _send_rpc(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            _receive_rpc(peer)
            assert _receive_rpc(peer)["method"] == "ping"
            if reply:
                _send_rpc(peer, {"jsonrpc": "2.0", "id": "endpoint-id", "result": {}})
                assert _receive_rpc(peer)["method"] == "synthetic.ack"
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.client_completion_confirmed is reply
        metadata = bridge.lifecycle_metadata
        assert metadata["endpoint_to_client_requests"] == 1
        assert metadata["client_to_endpoint_responses"] == int(reply)
        assert metadata["endpoint_to_client_pending_requests"] == int(not reply)
        assert bridge.failure_label == (
            None if reply else "bridge_completion_pending_requests"
        )


@pytest.mark.parametrize(
    "line",
    [
        b"{}\n",
        b"[]\n",
        b'{"jsonrpc":"2.0","id":2,"id":3,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":null,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}\n',
        b'{"jsonrpc":"2.0","id":2,"method":"ping","result":{}}\n',
        b'{"jsonrpc":"2.0","id":2,"method":"ping","params":NaN}\n',
    ],
)
def test_opt_in_rejects_invalid_inbound_json_rpc(root: Path, line: bytes) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            peer.sendall(struct.pack("!BI", 1, len(line)) + line)
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_invalid_json_rpc"
        assert bridge.client_completion_confirmed is False


@pytest.mark.parametrize(
    ("limit", "message", "label"),
    [
        (
            "MAX_RPC_MESSAGES",
            {"jsonrpc": "2.0", "method": "synthetic.extra"},
            "bridge_rpc_accounting_limit",
        ),
        (
            "MAX_RPC_IDENTIFIERS",
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            "bridge_rpc_accounting_limit",
        ),
        (
            "MAX_RPC_NAMES",
            {"jsonrpc": "2.0", "method": "synthetic.extra"},
            "bridge_rpc_accounting_limit",
        ),
        (
            "MAX_RPC_NAMES",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "synthetic.extra"},
            },
            "bridge_rpc_accounting_limit",
        ),
        (
            "MAX_RPC_IDENTIFIER_BYTES",
            {"jsonrpc": "2.0", "id": "synthetic-oversize-id", "method": "p"},
            "bridge_invalid_json_rpc",
        ),
    ],
)
def test_opt_in_rpc_metadata_and_identifiers_remain_bounded(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    message: dict[str, object],
    label: str,
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            monkeypatch.setattr(module, limit, 1)
            _send_rpc(peer, message)
            assert bridge.wait(2)
        assert bridge.failure_label == label


def test_opt_in_incomplete_endpoint_line_prevents_eof_completion(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import json,sys\n"
        "request=json.loads(sys.stdin.buffer.readline())\n"
        "print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{}}),flush=True)\n"
        "sys.stdout.write('{');sys.stdout.flush()\n"
        "sys.stdin.buffer.read()\n",
    )
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _send_rpc(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            _receive_rpc(peer)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                metadata = bridge.lifecycle_metadata
                if (
                    metadata["endpoint_stdout_bytes"]
                    > metadata["endpoint_to_client_json_bytes"] + 1
                ):
                    break
                time.sleep(0.005)
            else:
                pytest.fail("synthetic partial endpoint line was not observed")
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_incomplete_frame"
        assert bridge.client_completion_confirmed is False


def test_opt_in_late_client_data_after_controller_completion_is_rejected(
    root: Path,
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(root)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            with ThreadPoolExecutor(max_workers=1) as executor:
                finished = executor.submit(bridge.finish_client)
                assert peer.recv(5) == struct.pack("!BI", 2, 0)
                _send_rpc(peer, {"jsonrpc": "2.0", "method": "synthetic.late"})
                with pytest.raises(
                    module.BridgeError, match="bridge_output_after_completion"
                ):
                    finished.result(timeout=2)
        assert bridge.client_completion_confirmed is False


def test_opt_in_natural_exit_with_surviving_endpoint_child_is_not_success(
    root: Path,
) -> None:
    module = _module()
    command, environment = _rpc_endpoint(
        root,
        "import subprocess\n"
        "subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n",
    )
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        completion_probe=lambda: True,
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            _initialize_rpc(peer)
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_shutdown_failed"
        assert bridge.client_completion_confirmed is False
        assert bridge.lifecycle_metadata["endpoint_forced_cleanup"] is True
    assert bridge.process_cleanup_confirmed is True


def test_endpoint_owned_process_receipt_records_start_and_group_cleanup(
    root: Path,
) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import sys\nfor line in sys.stdin.buffer: sys.stdout.buffer.write(line);sys.stdout.buffer.flush()\n",
    )
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    assert bridge.endpoint_process_metadata is None
    with bridge:
        with _proxy(bridge.proxy_command, root) as process:
            stdout, stderr = process.communicate(b"{}\n", timeout=2)
            assert stdout == b"{}\n" and stderr == b""
        assert bridge.wait(2)
    receipt = bridge.endpoint_process_metadata
    assert receipt is not None
    assert receipt["pid"] == receipt["pgid"]
    assert receipt["phase"] == "memory_mcp_endpoint"
    assert receipt["reaped"] is True and receipt["process_group_stopped"] is True
    assert receipt["finished_monotonic"] >= receipt["started_monotonic"]
    assert not {"argv", "environment", "stdout", "stderr", "home"} & set(receipt)


def test_bridge_cleanup_records_allocated_paths_and_positive_removal(
    root: Path,
) -> None:
    module = _module()
    command, environment = _endpoint(root, "pass\n")
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    assert bridge.cleanup_paths == ()
    assert bridge.resources_cleanup_confirmed is False
    with bridge:
        paths = bridge.cleanup_paths
        assert len(paths) == 2 and all(path.is_dir() for path in paths)
        assert bridge.resources_cleanup_confirmed is False
    assert bridge.cleanup_paths == paths
    assert bridge.resources_cleanup_confirmed is True
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("retained_index", [0, 1])
def test_bridge_cleanup_requires_observed_absence_of_each_allocated_root(
    root: Path, monkeypatch: pytest.MonkeyPatch, retained_index: int
) -> None:
    module = _module()
    command, environment = _endpoint(root, "pass\n")
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    bridge.__enter__()
    paths = bridge.cleanup_paths
    original = module.shutil.rmtree

    def leave_one(path: Path) -> None:
        if path != paths[retained_index]:
            original(path)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.shutil, "rmtree", leave_one)
            with pytest.raises(module.BridgeError, match="bridge_cleanup_failed"):
                bridge.close()
            assert bridge.process_cleanup_confirmed is True
            assert bridge.resources_cleanup_confirmed is False
            assert paths[retained_index].is_dir()
            assert bridge.cleanup_paths == paths
    finally:
        bridge.close()
    assert bridge.resources_cleanup_confirmed is True
    assert all(not path.exists() for path in paths)


def test_successful_roundtrip_uses_exact_environment_and_cleans_material(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import json,os,sys\n"
        "for raw in sys.stdin.buffer:\n"
        "    request=json.loads(raw)\n"
        "    reply={'jsonrpc':'2.0','id':request['id'],'result':dict(os.environ)}\n"
        "    print(json.dumps(reply),flush=True)\n",
    )
    monkeypatch.setenv("SYNTHETIC_PARENT_SECRET", "must-not-be-inherited")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-never-valid")
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-never-valid")
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    with bridge:
        materials = (bridge.unix_socket_path, *bridge.proxy_read_paths)
        credentials = _credential(bridge.proxy_read_paths)
        assert isinstance(credentials["secret"], str)
        assert credentials["secret"] not in " ".join(bridge.proxy_command)
        assert all(path.stat().st_mode & 0o077 == 0 for path in materials)
        assert bridge.proxy_command[:2] == ("/usr/bin/env", "-i")
        python_index = bridge.proxy_command.index(str(Path(sys.executable).resolve()))
        assert bridge.proxy_command[python_index + 1 : python_index + 3] == ("-I", "-S")
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(
                b'{"jsonrpc":"2.0","id":1,"method":"synthetic/echo"}\n',
                timeout=5,
            )
            assert proxy.returncode == 0
        response = json.loads(output)
        assert response["id"] == 1
        assert all(
            response["result"][key] == value for key, value in environment.items()
        )
        # Python/CoreFoundation may synthesize their own locale marker at
        # startup; the injected parent secret and every other key stay absent.
        assert set(response["result"]) - set(environment) <= {"__CF_USER_TEXT_ENCODING"}
        assert errors == b""
        assert bridge.wait(2)
        assert bridge.failure_label is None
        assert bridge.endpoint_started
        assert bridge.proxy_auth_environment_absent is True
    assert all(not path.exists() for path in materials)


def test_wrong_token_starts_no_endpoint_and_consumes_only_session(root: Path) -> None:
    module = _module()
    marker = root / "endpoint-started"
    command, environment = _endpoint(
        root, "from pathlib import Path\nPath('endpoint-started').touch()\n"
    )
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(str(bridge.unix_socket_path))
            peer.sendall(b"MEMORY-MCP-BRIDGE\x02" + bytes(35))
            assert peer.recv(1) == b""
        assert bridge.wait(2)
        assert bridge.failure_label == "bridge_authentication_failed"
        assert not bridge.endpoint_started
        assert not marker.exists()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second:
            with pytest.raises(OSError):
                second.connect(str(bridge.unix_socket_path))


def test_oversized_wire_frame_fails_closed(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "import time\ntime.sleep(60)\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(max_frame_bytes=64, max_stream_bytes=1024),
    ) as bridge:
        credentials = _credential(bridge.proxy_read_paths)
        assert isinstance(credentials["secret"], str)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(str(bridge.unix_socket_path))
            peer.sendall(
                b"MEMORY-MCP-BRIDGE\x02"
                + bytes.fromhex(credentials["secret"])
                + b"\x00\x01\x02"
            )
            assert peer.recv(1) == b"\x01"
            peer.sendall(struct.pack("!BI", 1, 65))
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_frame_limit"
        assert bridge.endpoint_started


def test_authentication_timeout_starts_no_endpoint(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(auth_timeout_seconds=0.05),
    ) as bridge:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect(str(bridge.unix_socket_path))
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_authentication_timeout"
        assert not bridge.endpoint_started


def test_transport_digest_is_stable_and_excludes_session_secret(root: Path) -> None:
    module = _module()
    before = module.transport_digest()
    command, environment = _endpoint(root, "pass\n")
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        assert bridge.transport_digest() == before
        assert len(before) == 64
    assert module.transport_digest() == before


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin framework interpreter")
def test_proxy_uses_actual_system_framework_python(root: Path) -> None:
    module = _module()
    launcher = Path("/var/db/xcode_select_link/usr/bin/python3").resolve()
    python = launcher.parent.parent / "Resources/Python.app/Contents/MacOS/Python"
    if not python.is_file():
        pytest.skip("the actual system framework Python is unavailable")
    command, environment = _endpoint(
        root,
        "import sys\nfor line in sys.stdin.buffer:\n    print(line.decode().strip(),flush=True)\n",
    )
    with module.MCPBridge(root, command, environment, root, python) as bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(
                b'{"jsonrpc":"2.0","id":1,"result":"synthetic"}\n', timeout=5
            )
            assert proxy.returncode == 0, errors.decode()
        assert json.loads(output)["result"] == "synthetic"
        assert bridge.wait(2)
        assert bridge.failure_label is None


def test_long_caller_root_uses_short_private_socket(root: Path) -> None:
    module = _module()
    long_root = root / ("synthetic-private-trial-" * 8)
    long_root.mkdir()
    command, environment = _endpoint(long_root, "pass\n")
    with module.MCPBridge(
        long_root, command, environment, long_root, Path(sys.executable).resolve()
    ) as bridge:
        socket_root = bridge.socket_path.parent
        material_root = bridge.readable_proxy_files[0].parent
        assert len(str(bridge.socket_path).encode()) < 104
        assert all(
            path.is_relative_to(long_root) for path in bridge.readable_proxy_files
        )
        assert socket_root.stat().st_mode & 0o077 == 0
        assert material_root.stat().st_mode & 0o077 == 0
    assert not socket_root.exists()
    assert not material_root.exists()


@pytest.mark.parametrize(
    "key",
    ["CODEX_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"],
)
def test_bypassed_clean_launcher_rejects_auth_environment_before_endpoint_launch(
    root: Path, key: str
) -> None:
    module = _module()
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        unclean_command = (
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            str(bridge.readable_proxy_files[0]),
            "--proxy",
            str(bridge.readable_proxy_files[1]),
        )
        with _proxy(unclean_command, root, {key: "synthetic-never-valid"}) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 1
        assert output == errors == b""
        assert bridge.wait(2)
        assert bridge.failure_label == "bridge_proxy_credentials_present"
        assert bridge.proxy_auth_environment_absent is False
        assert not bridge.endpoint_started


@pytest.mark.parametrize(
    ("wire", "label"),
    [
        (struct.pack("!BI", 1, 4) + b"x\nx\n", "bridge_invalid_frame"),
        (struct.pack("!BI", 1, 2) + b"{}", "bridge_invalid_frame"),
        (struct.pack("!BI", 99, 0), "bridge_invalid_frame"),
        (struct.pack("!BI", 2, 1), "bridge_invalid_frame"),
        (struct.pack("!BI", 1, 0), "bridge_frame_limit"),
        (b"\x01\x00", "bridge_incomplete_frame"),
        (struct.pack("!BI", 1, 8) + b"{}", "bridge_incomplete_frame"),
        (struct.pack("!BI", 3, 0), "bridge_peer_failed"),
        (struct.pack("!BI", 2, 0) + struct.pack("!BI", 1, 1), "bridge_invalid_frame"),
        (b"", "bridge_disconnected"),
    ],
)
def test_invalid_or_disconnected_peer_fails_closed(
    root: Path, wire: bytes, label: str
) -> None:
    module = _module()
    command, environment = _endpoint(root, "import time\ntime.sleep(60)\n")
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            if wire:
                peer.sendall(wire)
            peer.shutdown(socket.SHUT_WR)
            assert bridge.wait(2)
        assert bridge.failure_label == label


@pytest.mark.parametrize(
    ("source", "label"),
    [
        ("import sys\nsys.stdout.write('x'*65)\n", "bridge_frame_limit"),
        ("import sys\nsys.stdout.write('{}')\n", "bridge_incomplete_frame"),
        ("import sys\nsys.stderr.write('x'*65)\n", "bridge_stderr_limit"),
        ("raise SystemExit(7)\n", "bridge_endpoint_failed"),
        ("import time\ntime.sleep(60)\n", "bridge_shutdown_timeout"),
    ],
)
def test_endpoint_failures_are_content_free_and_bounded(
    root: Path, source: str, label: str
) -> None:
    module = _module()
    command, environment = _endpoint(root, source)
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(
            max_frame_bytes=64,
            max_stream_bytes=1024,
            max_stderr_bytes=64,
            shutdown_timeout_seconds=0.1,
        ),
    ) as bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 1
        assert output == errors == b""
        assert bridge.wait(2)
        assert bridge.failure_label == label


def test_cumulative_wire_volume_is_bounded(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "import time\ntime.sleep(60)\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(max_frame_bytes=64, max_stream_bytes=128),
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files) as peer:
            peer.sendall((struct.pack("!BI", 1, 3) + b"{}\n") * 17)
            assert bridge.wait(2)
        assert bridge.failure_label == "bridge_stream_limit"


@pytest.mark.parametrize(
    ("limit", "label"),
    [
        ("idle_timeout_seconds", "bridge_idle_timeout"),
        ("session_timeout_seconds", "bridge_session_timeout"),
    ],
)
def test_authenticated_stalls_obey_deadlines(
    root: Path, limit: str, label: str
) -> None:
    module = _module()
    command, environment = _endpoint(root, "import time\ntime.sleep(60)\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(**{limit: 0.05}),
    ) as bridge:
        with _connect(bridge.socket_path, bridge.readable_proxy_files):
            assert bridge.wait(2)
        assert bridge.failure_label == label


def test_no_connection_has_bounded_wait_and_no_endpoint(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        limits=module.BridgeLimits(connect_timeout_seconds=0.05),
    ) as bridge:
        assert bridge.wait(2)
        assert bridge.failure_label == "bridge_connection_timeout"
        assert not bridge.endpoint_started


@pytest.mark.parametrize("close_context", [False, True])
def test_disconnect_or_context_exit_kills_endpoint_and_child(
    root: Path, close_context: bool
) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import json,os,subprocess,sys,time\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-I','-S','-c',"
        '"import os,signal,time;from pathlib import Path;'
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        "Path('child-ready').write_text(str(os.getpid()));time.sleep(60)\"])\n"
        "while not Path('child-ready').exists():time.sleep(0.005)\n"
        "Path('processes').write_text(json.dumps([os.getpid(),child.pid]))\n"
        "time.sleep(60)\n",
    )
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    with bridge:
        peer = _connect(bridge.socket_path, bridge.readable_proxy_files)
        try:
            deadline = time.monotonic() + 2
            while not (root / "processes").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            pids = json.loads((root / "processes").read_text())
            assert isinstance(pids, list) and len(pids) == 2
            if close_context:
                bridge.close()
            else:
                peer.close()
                assert bridge.wait(2)
                assert bridge.failure_label == "bridge_disconnected"
        finally:
            peer.close()
    for pid in pids:
        assert isinstance(pid, int)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            pytest.fail("synthetic endpoint process survived bridge cleanup")


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"PATH": "/usr/bin:/bin"},
        {"HOME": "/synthetic", "OPENAI_API_KEY": "synthetic"},
    ],
)
def test_endpoint_environment_must_be_explicit_and_credential_free(
    root: Path, environment: dict[str, str]
) -> None:
    module = _module()
    with pytest.raises(module.BridgeError, match=r"^bridge_invalid_configuration$"):
        module.MCPBridge(
            root,
            [str(Path(sys.executable).resolve())],
            environment,
            root,
            Path(sys.executable).resolve(),
        )


def test_unexpected_endpoint_launch_error_is_content_free(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    command, environment = _endpoint(root, "pass\n")

    def fail_launch(*args: object, **kwargs: object) -> NoReturn:
        raise RuntimeError("synthetic private failure detail must not escape")

    monkeypatch.setattr(module.subprocess, "Popen", fail_launch)
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        credentials = _credential(bridge.readable_proxy_files)
        assert isinstance(credentials["secret"], str)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(str(bridge.socket_path))
            peer.sendall(
                b"MEMORY-MCP-BRIDGE\x02"
                + bytes.fromhex(credentials["secret"])
                + b"\x00\x01\x02"
            )
            assert peer.recv(1) == b""
        assert bridge.wait(2)
        assert not bridge.endpoint_started
        assert bridge.failure_label == "bridge_internal_failure"


def test_closed_bridge_cannot_be_started(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "pass\n")
    bridge = module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    )
    bridge.close()
    with pytest.raises(module.BridgeError, match=r"^bridge_session_consumed$"):
        with bridge:
            pass


def test_large_unicode_json_rpc_lines_roundtrip_byte_exactly(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(
        root,
        "import sys\n"
        "for raw in sys.stdin.buffer:\n"
        "    sys.stdout.buffer.write(raw)\n"
        "    sys.stdout.buffer.flush()\n",
    )
    request = (
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": "合成测试来源。" * 5000},
            ensure_ascii=False,
        ).encode()
        + b"\n"
    )
    payload = request + b'{"jsonrpc":"2.0","id":2,"result":"synthetic"}\n'
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(payload, timeout=5)
            assert proxy.returncode == 0
        assert output == payload
        assert errors == b""
        assert bridge.wait(2)
        assert bridge.failure_label is None


def _auth_home(root: Path) -> tuple[Path, Path]:
    home = root / "synthetic-client-auth"
    home.mkdir(mode=0o700)
    canary = home / "synthetic-credential-canary"
    canary.write_text("Fresh synthetic credential boundary canary.\n", encoding="utf-8")
    canary.chmod(0o600)
    return home, canary


def _proxy_policy(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    bridge_socket: Path,
    readable_proxy_files: Sequence[Path],
    credential_homes: Sequence[Path],
) -> Sequence[str]:
    # This synthetic factory tests the bridge's policy contract. The installed
    # client proof separately supplies the full shared process policy.
    policies = ["(version 1)", "(allow default)"]
    policies.extend(
        "(deny file-read* file-write* (subpath " + json.dumps(str(home)) + "))"
        for home in credential_homes
    )
    policies.extend(
        "(deny file-write* file-link (literal " + json.dumps(str(path)) + "))"
        for path in (*readable_proxy_files, policy_path)
    )
    policy_path.write_text("\n".join(policies) + "\n", encoding="utf-8")
    policy_path.chmod(0o600)
    return ["/usr/bin/sandbox-exec", "-f", str(policy_path), *command]


def test_proxy_has_separate_empty_home_and_clears_inherited_environment(
    root: Path,
) -> None:
    module = _module()
    auth_home, _ = _auth_home(root)
    command, environment = _endpoint(root, "pass\n")
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        assert bridge.proxy_home != auth_home
        assert list(bridge.proxy_home.iterdir()) == []
        with _proxy(
            bridge.proxy_command,
            root,
            {
                "HOME": str(auth_home),
                "SYNTHETIC_PARENT_SECRET": "never-inherit",
                "CODEX_API_KEY": "synthetic-never-valid",
                "OPENAI_API_KEY": "synthetic-never-valid",
                "ANTHROPIC_API_KEY": "synthetic-never-valid",
                "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-never-valid",
            },
        ) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 0
        assert output == errors == b""
        assert bridge.wait(2)
        assert bridge.proxy_environment_isolated is True
        assert bridge.proxy_auth_environment_absent is True
        assert list(bridge.proxy_home.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin nested process policy")
@pytest.mark.parametrize("policy_kind", ["minimal", "framework", "shared"])
def test_proxy_must_prove_auth_home_file_denial_before_endpoint_launch(
    root: Path,
    policy_kind: str,
) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "pass\n")
    python = Path(sys.executable).resolve()
    policy = _proxy_policy
    if policy_kind != "minimal":
        launcher = Path("/var/db/xcode_select_link/usr/bin/python3").resolve()
        python = launcher.parent.parent / "Resources/Python.app/Contents/MacOS/Python"
        if not python.is_file():
            pytest.skip("the actual system framework Python is unavailable")
    if policy_kind == "shared":
        isolation = _isolation_module()
        policy = isolation.proxy_command
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        python,
        credential_homes=(auth_home,),
        credential_canary=canary,
        proxy_policy_factory=policy,
    ) as bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 0
        assert output == errors == b""
        assert bridge.wait(2)
        assert bridge.endpoint_started
        assert bridge.proxy_auth_home_denied is True
        assert bridge.proxy_environment_isolated is True
        assert bridge.failure_label is None


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin nested process policy")
def test_policy_without_file_denial_cannot_launch_endpoint(root: Path) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")

    def ineffective_policy(
        command: Sequence[str],
        *,
        policy_path: Path,
        executable_paths: Sequence[Path],
        bridge_socket: Path,
        readable_proxy_files: Sequence[Path],
        credential_homes: Sequence[Path],
    ) -> Sequence[str]:
        return _proxy_policy(
            command,
            policy_path=policy_path,
            executable_paths=executable_paths,
            bridge_socket=bridge_socket,
            readable_proxy_files=readable_proxy_files,
            credential_homes=(),
        )

    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        credential_homes=(auth_home,),
        credential_canary=canary,
        proxy_policy_factory=ineffective_policy,
    ) as bridge:
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 1
        assert output == errors == b""
        assert bridge.wait(2)
        assert not bridge.endpoint_started
        assert bridge.proxy_auth_home_denied is False
        assert bridge.failure_label == "bridge_proxy_credential_readable"


@pytest.mark.parametrize("change", ["remove", "replace"])
@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin nested process policy")
def test_changed_canary_cannot_attest_file_denial(root: Path, change: str) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        credential_homes=(auth_home,),
        credential_canary=canary,
        proxy_policy_factory=_proxy_policy,
    ) as bridge:
        canary.unlink()
        if change == "replace":
            canary.write_text("A different synthetic canary.\n", encoding="utf-8")
            canary.chmod(0o600)
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 1
        assert output == errors == b""
        assert bridge.wait(2)
        assert not bridge.endpoint_started
        assert bridge.proxy_auth_home_denied is False
        assert bridge.failure_label == "bridge_proxy_credential_boundary_unconfirmed"


@pytest.mark.parametrize("part", ["homes", "canary", "factory", "no_canary"])
def test_boundary_requires_home_canary_pair_and_factory_requires_boundary(
    root: Path, part: str
) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "pass\n")
    configuration: dict[str, object] = {}
    if part in {"homes", "no_canary"}:
        configuration["credential_homes"] = (auth_home,)
    if part == "canary":
        configuration["credential_canary"] = canary
    if part in {"factory", "no_canary"}:
        configuration["proxy_policy_factory"] = _proxy_policy
    with pytest.raises(module.BridgeError, match=r"^bridge_invalid_configuration$"):
        module.MCPBridge(
            root,
            command,
            environment,
            root,
            Path(sys.executable).resolve(),
            **configuration,
        )


def test_proxy_home_contamination_refuses_endpoint(root: Path) -> None:
    module = _module()
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")
    with module.MCPBridge(
        root, command, environment, root, Path(sys.executable).resolve()
    ) as bridge:
        (bridge.proxy_home / "unexpected-synthetic-file").touch()
        with _proxy(bridge.proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == 1
        assert output == errors == b""
        assert bridge.wait(2)
        assert not bridge.endpoint_started
        assert bridge.proxy_environment_isolated is False
        assert bridge.failure_label == "bridge_proxy_environment_unconfirmed"


@pytest.mark.parametrize("location", ["home", "temporary", "working_directory"])
def test_endpoint_cannot_receive_credential_home_as_environment_or_cwd(
    root: Path, location: str
) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "pass\n")
    cwd = root
    if location == "home":
        environment["HOME"] = str(auth_home)
    elif location == "temporary":
        environment["TMPDIR"] = str(auth_home)
    else:
        cwd = auth_home
    with pytest.raises(module.BridgeError, match=r"^bridge_invalid_configuration$"):
        module.MCPBridge(
            root,
            command,
            environment,
            cwd,
            Path(sys.executable).resolve(),
            credential_homes=(auth_home,),
            credential_canary=canary,
            proxy_policy_factory=_proxy_policy,
        )


@pytest.mark.parametrize("change", ["command", "mode", "symlink"])
@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin nested process policy")
def test_policy_cannot_change_proxy_launch_or_use_mutable_material(
    root: Path, change: str
) -> None:
    module = _module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "raise AssertionError('must not start')\n")

    def invalid_policy(
        command: Sequence[str],
        *,
        policy_path: Path,
        executable_paths: Sequence[Path],
        bridge_socket: Path,
        readable_proxy_files: Sequence[Path],
        credential_homes: Sequence[Path],
    ) -> Sequence[str]:
        wrapped = _proxy_policy(
            command,
            policy_path=policy_path,
            executable_paths=executable_paths,
            bridge_socket=bridge_socket,
            readable_proxy_files=readable_proxy_files,
            credential_homes=credential_homes,
        )
        if change == "command":
            return [*wrapped, "--unexpected-synthetic-argument"]
        if change == "mode":
            policy_path.chmod(0o644)
        else:
            target = root / "synthetic-policy"
            policy_path.rename(target)
            policy_path.symlink_to(target)
        return wrapped

    bridge = module.MCPBridge(
        root,
        command,
        environment,
        root,
        Path(sys.executable).resolve(),
        credential_homes=(auth_home,),
        credential_canary=canary,
        proxy_policy_factory=invalid_policy,
    )
    with pytest.raises(module.BridgeError, match=r"^bridge_proxy_policy_unavailable$"):
        with bridge:
            pass
    assert not bridge.endpoint_started
    assert not bridge.socket_path.parent.exists()
    assert list(root.glob("mcp-bridge-*")) == []


@pytest.mark.parametrize("inherited_denial", [False, True])
@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin inherited process policy")
def test_canary_without_callback_requires_real_inherited_file_denial(
    root: Path, inherited_denial: bool
) -> None:
    module = _module()
    isolation = _isolation_module()
    auth_home, canary = _auth_home(root)
    command, environment = _endpoint(root, "pass\n")
    with module.MCPBridge(
        root,
        command,
        environment,
        root,
        isolation.system_python(),
        credential_homes=(auth_home,),
        credential_canary=canary,
    ) as bridge:
        assert "/usr/bin/sandbox-exec" not in bridge.proxy_command
        proxy_command = bridge.proxy_command
        if inherited_denial:
            # The exact env launcher is admitted; after it execs Python the
            # inherited policy denies credential reads for Python's identity.
            proxy_command = tuple(
                isolation.protected_command(
                    proxy_command,
                    policy_path=root / "inherited-policy.sb",
                    executable_paths=bridge.proxy_executable_paths,
                    bridge_socket=bridge.socket_path,
                    readable_proxy_files=bridge.readable_proxy_files,
                    credential_homes=(auth_home,),
                    credential_client=Path(bridge.proxy_command[0]),
                )
            )
        with _proxy(proxy_command, root) as proxy:
            output, errors = proxy.communicate(timeout=5)
            assert proxy.returncode == (0 if inherited_denial else 1)
        assert output == errors == b""
        assert bridge.wait(2)
        assert bridge.proxy_environment_isolated is True
        assert bridge.proxy_auth_environment_absent is True
        assert bridge.proxy_auth_home_denied is inherited_denial
        assert bridge.endpoint_started is inherited_denial
        assert bridge.failure_label == (
            None if inherited_denial else "bridge_proxy_credential_readable"
        )
