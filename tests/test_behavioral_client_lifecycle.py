"""Synthetic client completion must survive the real context and lease path."""

from __future__ import annotations

import importlib
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from test_behavioral_acceptance_tool import MANIFEST_PATH, _tool
from test_behavioral_execution_isolation import _execution_state

if TYPE_CHECKING:
    from behavioral_client_lifecycle import ClientLifecycle


def _lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, max_bytes: int = 1024 * 1024
) -> ClientLifecycle:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    module = importlib.import_module("behavioral_client_lifecycle")
    return cast(
        "ClientLifecycle",
        module.ClientLifecycle(tmp_path / "events.private", max_bytes=max_bytes),
    )


def _events(*events: dict[str, object]) -> bytes:
    return b"".join(json.dumps(event).encode() + b"\n" for event in events)


PREFIX = _events(
    {"type": "thread.started", "thread_id": "synthetic-thread"},
    {"type": "turn.started"},
)
TERMINAL = _events(
    {
        "type": "item.completed",
        "item": {
            "id": "synthetic-final",
            "type": "agent_message",
            "text": "Synthetic answer.",
        },
    },
    {"type": "turn.completed", "usage": {}},
)


def _run_bytes(
    lifecycle: ClientLifecycle, tmp_path: Path, stdout: bytes, stderr: bytes = b""
) -> tuple[int, str | None]:
    script = tmp_path / "inert-output.py"
    script.write_text(
        f"import sys\nsys.stdout.buffer.write({stdout!r})\n"
        f"sys.stderr.buffer.write({stderr!r})\n",
        encoding="utf-8",
    )
    return lifecycle.run(
        [str(Path(sys.executable).resolve()), "-I", "-S", str(script)],
        environment={"PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        input_text=None,
        response_path=tmp_path / "answer.private",
        stderr_path=tmp_path / "stderr.private",
        timeout=3,
    )


@pytest.mark.parametrize("failed_start", [1, 2, 3])
def test_reader_start_failure_reaps_process_and_closes_all_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_start: int
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    module = importlib.import_module("behavioral_client_lifecycle")
    original_start = module.threading.Thread.start
    original_cleanup = module._kill_and_reap
    started = 0
    cleaned: list[subprocess.Popen[bytes]] = []

    def start(thread: object) -> None:
        nonlocal started
        started += 1
        if started == failed_start:
            raise OSError("Synthetic thread start failure.")
        original_start(thread)

    def cleanup(process: subprocess.Popen[bytes]) -> bool:
        cleaned.append(process)
        return bool(original_cleanup(process))

    monkeypatch.setattr(module.threading.Thread, "start", start)
    monkeypatch.setattr(module, "_kill_and_reap", cleanup)
    with pytest.raises(OSError, match="Synthetic thread start failure"):
        lifecycle.run(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-c",
                "import time; time.sleep(60)",
            ],
            environment={"PATH": "/usr/bin:/bin"},
            cwd=tmp_path,
            input_text="Synthetic input.",
            response_path=tmp_path / "answer.private",
            stderr_path=tmp_path / "stderr.private",
            timeout=3,
        )
    assert len(cleaned) == 1
    process = cleaned[0]
    assert process.poll() is not None
    assert all(
        stream is not None and stream.closed
        for stream in (process.stdin, process.stdout, process.stderr)
    )
    assert lifecycle.metadata()["process_cleanup_confirmed"] is True
    assert lifecycle.client_completion_confirmed is False


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b'{"type":"thread.started","type":"turn.started"}\n', "client_malformed_json"),
        (b'{"type":NaN}\n', "client_malformed_json"),
        (b"\xff\n", "client_malformed_json"),
        (b"[]\n", "client_malformed_event"),
        (b'{"type":{}}\n', "client_malformed_event"),
        (
            b'{"type":"thread.started","thread_id":"\\ud800"}\n',
            "client_malformed_event",
        ),
        (
            PREFIX
            + _events(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "bad-text",
                        "type": "agent_message",
                        "text": "\ud800",
                    },
                }
            )
            + b'{"type":"turn.completed"}\n',
            "client_malformed_event",
        ),
        (
            b"\n".join(
                line.decode("utf-8").encode("utf-16le")
                for line in (PREFIX + TERMINAL).splitlines()
            )
            + b"\n",
            "client_malformed_json",
        ),
        (b'{"type":"turn.started"}\n', "client_event_order"),
        (PREFIX + PREFIX, "client_event_order"),
        (PREFIX + b'{"type":"turn.failed"}\n', "client_reported_error"),
        (
            PREFIX + b'{"type":"item.completed","item":{"type":"error"}}\n',
            "client_reported_error",
        ),
        (PREFIX + b'{"type":"turn.completed"}\n', "client_final_answer_unconfirmed"),
        (
            PREFIX + TERMINAL + b'{"type":"turn.started"}\n',
            "client_event_after_completion",
        ),
        (PREFIX + TERMINAL[:-1], "client_incomplete_json"),
        (
            PREFIX
            + _events(
                {
                    "type": "item.started",
                    "item": {"id": "pending", "type": "mcp_tool_call"},
                }
            )
            + TERMINAL,
            "client_final_answer_unconfirmed",
        ),
        (
            PREFIX
            + _events(
                {
                    "type": "item.updated",
                    "item": {"id": "missing", "type": "mcp_tool_call"},
                }
            ),
            "client_event_order",
        ),
        (
            PREFIX
            + _events(
                {
                    "type": "item.started",
                    "item": {"id": "changed", "type": "mcp_tool_call"},
                },
                {
                    "type": "item.completed",
                    "item": {"id": "changed", "type": "reasoning"},
                },
            ),
            "client_event_order",
        ),
    ],
)
def test_malformed_or_incomplete_events_fail_after_natural_process_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: bytes, expected: str
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    status, failure = _run_bytes(lifecycle, tmp_path, data)
    assert status == 0
    assert failure == expected
    metadata = lifecycle.metadata()
    assert metadata["process_cleanup_confirmed"] is True
    assert metadata["stdout_fully_drained"] is True
    assert metadata["stderr_fully_drained"] is True
    assert lifecycle.client_completion_confirmed is False


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_capture_limit_drains_but_never_accepts_truncated_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch, max_bytes=1024)
    stdout, stderr = PREFIX + TERMINAL, b""
    if stream == "stdout":
        stdout += b"x" * 2048
    else:
        stderr = b"x" * 2048
    status, failure = _run_bytes(lifecycle, tmp_path, stdout, stderr)
    assert status == 0
    assert failure == "client_output_limit"
    metadata = lifecycle.metadata()
    assert metadata[f"{stream}_truncated"] is True
    assert metadata[f"{stream}_fully_drained"] is True
    assert metadata[f"{stream}_raw_bytes"] == len(
        stdout if stream == "stdout" else stderr
    )
    capture = tmp_path / ("events.private" if stream == "stdout" else "stderr.private")
    assert capture.stat().st_size == 1024
    assert lifecycle.client_completion_confirmed is False


def test_bounded_event_count_refuses_a_nonterminal_event_flood(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    item = {"id": "synthetic", "type": "reasoning"}
    data = PREFIX + _events({"type": "item.started", "item": item})
    data += _events({"type": "item.updated", "item": item}) * 8190
    status, failure = _run_bytes(lifecycle, tmp_path, data)
    assert status == 0
    assert failure == "client_event_limit"
    assert lifecycle.metadata()["event_count"] == 8193
    assert lifecycle.client_completion_confirmed is False


def test_unverified_process_group_cleanup_rejects_otherwise_complete_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    module = importlib.import_module("behavioral_client_lifecycle")
    cleanup = module._kill_and_reap

    def unverified(process: subprocess.Popen[bytes]) -> bool:
        assert cleanup(process)
        return False

    monkeypatch.setattr(module, "_kill_and_reap", unverified)
    status, failure = _run_bytes(lifecycle, tmp_path, PREFIX + TERMINAL)
    assert status == 0
    assert failure == "client_teardown_unverified"
    assert lifecycle.metadata()["process_cleanup_confirmed"] is False
    assert lifecycle.client_completion_confirmed is False


def test_durable_ingestion_failure_never_confirms_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    original_sync = os.fsync

    def sync(descriptor: int) -> None:
        status = os.fstat(descriptor)
        if stat.S_ISREG(status.st_mode) and status.st_size > 0:
            raise OSError("Synthetic durable-write failure.")
        original_sync(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    status, failure = _run_bytes(lifecycle, tmp_path, PREFIX + TERMINAL)
    assert status == 0
    assert failure == "client_output_capture_failed"
    assert lifecycle.metadata()["process_cleanup_confirmed"] is True
    assert lifecycle.client_completion_confirmed is False


def test_capture_directory_sync_failure_prevents_launch_and_closes_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    original_sync = os.fsync
    attempted: list[int] = []

    def sync(descriptor: int) -> None:
        attempted.append(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("Synthetic directory-sync failure.")
        original_sync(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(OSError, match="Synthetic directory-sync failure"):
        _run_bytes(lifecycle, tmp_path, PREFIX + TERMINAL)
    assert len(attempted) == 2
    for descriptor in attempted:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert lifecycle.metadata()["process"] == {}
    assert lifecycle.client_completion_confirmed is False


def test_eof_snapshot_reads_completion_already_in_the_kernel_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    reader, writer = os.pipe()
    try:
        os.set_blocking(reader, False)
        with (tmp_path / "snapshot.private").open("wb") as target:
            lifecycle._fd, lifecycle._target = reader, target
            data = PREFIX + TERMINAL
            assert os.write(writer, data) == len(data)
            assert lifecycle.completion_probe() is True
            snapshot = lifecycle.metadata()["completion_at_peer_eof"]
            assert isinstance(snapshot, dict)
            assert snapshot["already_available_bytes"] == len(data)
            assert snapshot["synchronously_read_bytes"] == len(data)
            assert snapshot["event_count"] == 4
            assert snapshot["partial_json_bytes"] == 0
            lifecycle._append_stdout(b'{"type":"error"}\n')
            assert lifecycle.failure_label == "client_reported_error"
            assert lifecycle.completion_probe() is True
            assert lifecycle.metadata()["completion_at_peer_eof"] == snapshot
            assert lifecycle.client_completion_confirmed is False
    finally:
        os.close(reader)
        os.close(writer)


def test_eof_cutoff_cannot_read_a_terminal_event_written_after_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    reader, writer = os.pipe()
    original_read = os.read
    late_written = False

    def read(descriptor: int, size: int) -> bytes:
        nonlocal late_written
        result = original_read(descriptor, size)
        if descriptor == reader and not late_written:
            late_written = True
            assert os.write(writer, TERMINAL) == len(TERMINAL)
        return result

    monkeypatch.setattr(os, "read", read)
    try:
        os.set_blocking(reader, False)
        with (tmp_path / "snapshot.private").open("wb") as target:
            lifecycle._fd, lifecycle._target = reader, target
            assert os.write(writer, PREFIX) == len(PREFIX)
            assert lifecycle.completion_probe() is False
            snapshot = lifecycle.metadata()["completion_at_peer_eof"]
            assert isinstance(snapshot, dict)
            assert snapshot["already_available_bytes"] == len(PREFIX)
            assert snapshot["synchronously_read_bytes"] == len(PREFIX)
            assert snapshot["event_count"] == 2
            lifecycle._append_stdout(PREFIX + original_read(reader, 65536))
            assert lifecycle.metadata()["turn_completed"] is True
            assert lifecycle.completion_probe() is False
            assert lifecycle.metadata()["completion_at_peer_eof"] == snapshot
    finally:
        os.close(reader)
        os.close(writer)


def test_slow_parser_never_forgives_terminal_bytes_observed_after_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    reader, writer = os.pipe()
    observed: list[bool] = []
    observer = threading.Thread(
        target=lambda: observed.append(lifecycle.completion_probe())
    )
    try:
        os.set_blocking(reader, False)
        with (tmp_path / "snapshot.private").open("wb") as target:
            lifecycle._fd, lifecycle._target = reader, target
            with lifecycle._lock:
                observer.start()
                observer.join(timeout=0.2)
                did_not_wait = not observer.is_alive()
                lifecycle._append_stdout(PREFIX + TERMINAL)
            observer.join(timeout=1)
            assert did_not_wait
            assert observed == [False]
            snapshot = lifecycle.metadata()["completion_at_peer_eof"]
            assert isinstance(snapshot, dict)
            assert snapshot["failure_label"] == "client_completion_unconfirmed"
            assert lifecycle.completion_probe() is False
            assert lifecycle.metadata()["completion_at_peer_eof"] == snapshot
    finally:
        observer.join(timeout=1)
        os.close(reader)
        os.close(writer)


@pytest.mark.parametrize("terminal_precedes_eof", [True, False])
def test_in_flight_read_uses_only_its_pre_eof_reserved_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal_precedes_eof: bool
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    reader, writer = os.pipe()
    original_read = os.read
    read_started, release_read, cutoff_frozen = (threading.Event() for _ in range(3))
    results: list[bool] = []
    errors: list[BaseException] = []

    def paused_read(descriptor: int, size: int) -> bytes:
        if descriptor == reader and not read_started.is_set():
            read_started.set()
            assert release_read.wait(timeout=3)
        return original_read(descriptor, size)

    def read_once() -> None:
        try:
            with lifecycle._observation_lock:
                lifecycle._observe_stdout()
        except BaseException as error:
            errors.append(error)

    drainer = threading.Thread(target=read_once)
    observer = threading.Thread(
        target=lambda: results.append(lifecycle.completion_probe())
    )
    monkeypatch.setattr(os, "read", paused_read)
    try:
        os.set_blocking(reader, False)
        with (tmp_path / "snapshot.private").open("wb") as target:
            lifecycle._fd, lifecycle._target = reader, target
            initial = PREFIX + TERMINAL if terminal_precedes_eof else PREFIX
            assert os.write(writer, initial) == len(initial)
            drainer.start()
            assert read_started.wait(timeout=1)
            reservation = lifecycle._read_reservation
            assert reservation is not None
            original_result = reservation.completed.result

            def reserved_result(timeout: float | None = None) -> bytes:
                cutoff_frozen.set()
                return original_result(timeout=timeout)

            monkeypatch.setattr(reservation.completed, "result", reserved_result)
            observer.start()
            assert cutoff_frozen.wait(timeout=1)
            if not terminal_precedes_eof:
                assert os.write(writer, TERMINAL) == len(TERMINAL)
            release_read.set()
            drainer.join(timeout=2)
            observer.join(timeout=2)
            assert not errors
            assert not drainer.is_alive() and not observer.is_alive()
            assert results == [terminal_precedes_eof]
            snapshot = lifecycle.metadata()["completion_at_peer_eof"]
            assert isinstance(snapshot, dict)
            assert snapshot["cutoff_source"] == "pre_eof_read_reservation"
            assert snapshot["stdout_bytes"] == len(initial)
            assert snapshot["already_available_bytes"] == len(initial)
            assert snapshot["synchronously_read_bytes"] == 0
            if not terminal_precedes_eof:
                with lifecycle._observation_lock:
                    lifecycle._observe_stdout()
                while lifecycle._pending_stdout:
                    lifecycle._append_stdout(lifecycle._pending_stdout.popleft())
                assert lifecycle.metadata()["turn_completed"] is True
            assert lifecycle.completion_probe() is terminal_precedes_eof
            assert lifecycle.metadata()["completion_at_peer_eof"] == snapshot
    finally:
        release_read.set()
        if drainer.ident is not None:
            drainer.join(timeout=2)
        if observer.ident is not None:
            observer.join(timeout=6)
        os.close(reader)
        os.close(writer)


def test_recovery_metadata_is_bounded_private_and_not_shared_by_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = _lifecycle(tmp_path, monkeypatch)
    module = importlib.import_module("behavioral_client_lifecycle")
    assert lifecycle.private_recovery_metadata() is None
    payload: dict[str, object] = {"cleanup_paths": [str(tmp_path / "synthetic-root")]}
    lifecycle.record_recovery(payload)
    payload["cleanup_paths"] = []
    retained = lifecycle.private_recovery_metadata()
    assert retained == {"cleanup_paths": [str(tmp_path / "synthetic-root")]}
    assert str(tmp_path) not in json.dumps(lifecycle.metadata())
    assert isinstance(retained, dict)
    retained["cleanup_paths"] = []
    assert lifecycle.private_recovery_metadata() != retained
    with pytest.raises(module.LifecycleError, match="client_recovery_metadata_invalid"):
        lifecycle.record_recovery({"oversize": "x" * 65536})


def test_abrupt_controller_termination_preserves_ingested_small_streams(
    tmp_path: Path,
) -> None:
    controller_source = tmp_path / "inert-controller.py"
    tools_path = Path(__file__).resolve().parents[1] / "tools"
    controller_source.write_text(
        "import pathlib,sys\n"
        f"sys.path.insert(0,{str(tools_path)!r})\n"
        "from behavioral_client_lifecycle import ClientLifecycle\n"
        f"root=pathlib.Path({str(tmp_path)!r})\n"
        "lifecycle=ClientLifecycle(root/'events.private')\n"
        "original=lifecycle._append_stdout\n"
        "def appended(data):\n"
        " original(data)\n"
        " (root/'ingested').write_text(str(lifecycle._process['pid']))\n"
        "lifecycle._append_stdout=appended\n"
        "lifecycle.run([sys.executable,'-I','-S','-c',"
        f"{('import os,time;os.write(1,' + repr(PREFIX) + ');os.write(2,b"Synthetic stderr.");time.sleep(60)')!r}],"
        "environment={'PATH':'/usr/bin:/bin'},cwd=root,input_text=None,"
        "response_path=root/'answer.private',stderr_path=root/'stderr.private',timeout=60)\n",
        encoding="utf-8",
    )
    controller = subprocess.Popen(
        [str(Path(sys.executable).resolve()), "-I", "-S", str(controller_source)],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    native_pid: int | None = None
    try:
        deadline = time.monotonic() + 3
        while not (tmp_path / "ingested").exists():
            assert time.monotonic() < deadline, (
                "synthetic controller did not ingest output"
            )
            time.sleep(0.01)
        native_pid = int((tmp_path / "ingested").read_text())
        while (
            tmp_path / "stderr.private"
        ).stat().st_size == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        os.killpg(controller.pid, signal.SIGKILL)
        controller.wait(timeout=3)
        assert (tmp_path / "events.private").read_bytes() == PREFIX
        assert (tmp_path / "stderr.private").read_bytes() == b"Synthetic stderr."
    finally:
        if controller.poll() is None:
            os.killpg(controller.pid, signal.SIGKILL)
        controller.wait(timeout=3)
        if native_pid is not None:
            os.killpg(native_pid, signal.SIGKILL)


def _run_actual_synthetic_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str = "normal"
) -> tuple[dict[str, Any], list[str], Path]:
    """Use real runner/context/bridge/process code with inert identity adapters."""
    tool = _tool()
    state = _execution_state(tool, tmp_path, monkeypatch)
    (tmp_path / "workspace").chmod(0o700)
    state["provenance"].update(
        authentication_mode="chatgpt_subscription",
        authentication_adapter_digest="ab" * 32,
        code_mode_host_digest="88" * 32,
        isolation_profile_digest="99" * 32,
    )
    python = Path(sys.executable).resolve()
    memory = tmp_path / "memory"
    pending_request_observed = tmp_path / "pending-request-observed"
    memory.write_text(
        f"#!{python}\n"
        "import json,pathlib,sys\n"
        f"pending=pathlib.Path({str(pending_request_observed)!r})\n"
        "for line in sys.stdin.buffer:\n"
        " request=json.loads(line)\n"
        " if request.get('method')=='synthetic/hold':\n"
        "  pending.touch();continue\n"
        " if 'id' in request:\n"
        "  print(json.dumps({'jsonrpc':'2.0','id':request['id'],"
        "'result':{'synthetic':'ok'}}),flush=True)\n",
        encoding="utf-8",
    )
    memory.chmod(0o700)
    client = tmp_path / "inert-client.py"
    client.write_text(
        "import json,os,pathlib,subprocess,sys,time\n"
        f"MODE={mode!r}\n"
        "settings=dict(item.split('=',1) for item in sys.argv[1:] if '=' in item)\n"
        "prefix='mcp_servers.memory_behavioral_acceptance.'\n"
        "command=[json.loads(settings[prefix+'command']),"
        "*json.loads(settings[prefix+'args'])]\n"
        "def emit(value):print(json.dumps(value),flush=True)\n"
        "emit({'type':'thread.started','thread_id':'synthetic-thread'})\n"
        "emit({'type':'turn.started'})\n"
        "pathlib.Path('client-started').write_text('synthetic')\n"
        "if MODE=='interruption':time.sleep(60)\n"
        "proxy=subprocess.Popen(command,stdin=subprocess.PIPE,"
        "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)\n"
        "assert proxy.stdin and proxy.stdout\n"
        "request={'jsonrpc':'2.0','id':1,'method':'initialize','params':{}}\n"
        "proxy.stdin.write((json.dumps(request)+'\\n').encode());proxy.stdin.flush()\n"
        "assert json.loads(proxy.stdout.readline())['id']==1\n"
        "if MODE=='early_disconnect':proxy.kill();proxy.wait();time.sleep(0.2)\n"
        "if MODE=='partial':\n"
        ' os.write(1,b\'{"type":"item.completed"\');proxy.kill();proxy.wait();'
        "raise SystemExit(0)\n"
        "if MODE=='malformed':os.write(1,b'not-json\\n')\n"
        "if MODE=='client_error':emit({'type':'error','message':'Synthetic failure.'})\n"
        "if MODE=='pending_rpc':\n"
        " request.update(id=2,method='synthetic/hold');"
        "proxy.stdin.write((json.dumps(request)+'\\n').encode());proxy.stdin.flush()\n"
        # A flushed pipe is not proof that the bridge observed the request.
        # Confirm the endpoint received it before terminating the proxy.
        f" pending=pathlib.Path({str(pending_request_observed)!r})\n"
        " deadline=time.monotonic()+5\n"
        " while not pending.exists():\n"
        "  if time.monotonic()>=deadline:raise RuntimeError('Synthetic pending request was not observed.')\n"
        "  time.sleep(0.01)\n"
        "emit({'type':'item.completed','item':{'id':'synthetic-final',"
        "'type':'agent_message','text':'' if MODE=='empty' else 'Synthetic completed answer.'}})\n"
        "emit({'type':'turn.completed','usage':{}})\n"
        "if MODE!='early_disconnect':proxy.kill();proxy.wait()\n"
        "if MODE=='terminal_nonzero':raise SystemExit(7)\n"
        "if MODE=='terminal_timeout':time.sleep(60)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    isolation = importlib.import_module("behavioral_codex_isolation")
    bridge_module = importlib.import_module("behavioral_mcp_bridge")
    actual_bridge = bridge_module.MCPBridge

    def inert_bridge(**options: object) -> object:
        # The credential authority is deliberately a test adapter. Transport,
        # process custody, execution context and the lease completion are real.
        options.pop("credential_homes", None)
        options.pop("credential_canary", None)
        bridge = actual_bridge(**options)
        bridge._proxy_auth_home_denied = True
        if mode == "cleanup_error":
            finish = bridge.finish_client

            def failed_finish() -> None:
                finish()
                raise OSError("Synthetic bridge cleanup failure.")

            bridge.finish_client = failed_finish
        return cast(object, bridge)

    def passthrough(command: Sequence[str], **_options: object) -> list[str]:
        return list(command)

    monkeypatch.setattr(bridge_module, "MCPBridge", inert_bridge)
    monkeypatch.setattr(isolation, "system_python", lambda: python)
    monkeypatch.setattr(isolation, "execution_command", passthrough)
    monkeypatch.setattr(isolation, "endpoint_command", passthrough)
    monkeypatch.setattr(
        tool,
        "_codex_launch_arguments",
        lambda *_args, **_options: [str(python), "-I", "-S", str(client)],
    )
    monkeypatch.setattr(
        tool,
        "_store_snapshot",
        lambda *_args: {"mcp_contract_digest": "22" * 32, "skill_digest": "33" * 32},
    )
    session = object()
    events: list[str] = []
    monkeypatch.setattr(tool, "_subscription_session", lambda _state: session)

    def forbidden_auth(_kind: str) -> None:
        pytest.fail("synthetic subscription execution reached API credentials")

    monkeypatch.setattr(tool, "_client_authentication", forbidden_auth)

    class Lease:
        credential_homes = (
            tmp_path / "fresh-auth",
            tmp_path / "workspace" / ".client-home",
        )
        credential_canary = credential_homes[1] / "synthetic-canary"
        public_ca_bundle = tmp_path / "synthetic-public-ca.pem"

        def complete(self) -> None:
            events.append("credentials_complete")

    @contextmanager
    def credentials(_session: object, _client_home: Path) -> Iterator[Lease]:
        assert _session is session
        events.append("credentials_enter")
        try:
            yield Lease()
        finally:
            events.append("credentials_exit")

    monkeypatch.setattr(tool, "_subscription_lease", credentials)
    if mode == "terminal_timeout":
        monkeypatch.setattr(tool, "CLIENT_TIMEOUT_SECONDS", 0.3)
    if mode == "interruption":
        original_wait = subprocess.Popen[bytes].wait
        interrupted = False

        def interrupt_wait(
            process: subprocess.Popen[bytes], timeout: float | None = None
        ) -> int:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                deadline = time.monotonic() + 2
                while not (tmp_path / "workspace" / "client-started").exists():
                    if time.monotonic() >= deadline:
                        pytest.fail("synthetic client did not start")
                    time.sleep(0.01)
                raise KeyboardInterrupt
            return original_wait(process, timeout=timeout)

        monkeypatch.setattr(subprocess.Popen, "wait", interrupt_wait)
    manifest = tool.load_manifest(MANIFEST_PATH)
    case_id = state["slots"][0]["case_id"]
    response = tmp_path / "response.private"
    result = tool._actual_executor(state, manifest)(
        manifest.cases[case_id],
        1,
        tmp_path / "store",
        tmp_path / "workspace",
        response,
    )
    if mode == "pending_rpc":
        assert pending_request_observed.is_file()
    return cast(dict[str, Any], result), events, response


def test_completed_native_shutdown_finishes_actual_context_and_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, events, response = _run_actual_synthetic_client(tmp_path, monkeypatch)
    assert result["exit_status"] == 0
    assert result["failure_label"] is None
    assert events == ["credentials_enter", "credentials_complete", "credentials_exit"]
    assert response.read_text(encoding="utf-8") == "Synthetic completed answer.\n"
    raw = tmp_path / "client-events.private"
    assert raw.stat().st_mode & 0o077 == 0
    assert b'"type": "turn.completed"' in raw.read_bytes()
    assert not (tmp_path / "workspace" / "client-events.private").exists()
    receipts = {
        value["schema"]: (path, value)
        for path in (tmp_path / "receipts").glob("*.private.json")
        if isinstance(value := json.loads(path.read_text()), dict)
    }
    _, attempt = receipts["memory.behavioral-client-attempt.v1"]
    _, recovery = receipts["memory.behavioral-client-recovery.v1"]
    endpoint = recovery["recovery"]["endpoint_process"]
    assert isinstance(endpoint["pid"], int)
    assert endpoint["pgid"] == endpoint["pid"]
    assert endpoint["reaped"] is True and endpoint["process_group_stopped"] is True
    assert endpoint["returncode"] == 0
    paths = recovery["recovery"]["cleanup_paths"]
    assert len(paths) == 2
    assert all(not Path(path).exists() for path in paths)
    assert all(path not in json.dumps(attempt) for path in paths)


def test_durable_terminal_bytes_survive_slow_ingestion_at_peer_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "tools"))
    module = importlib.import_module("behavioral_client_lifecycle")
    capture = module._capture

    def slow_capture(target: object, data: bytes) -> None:
        capture(target, data)
        if b"turn.completed" in data:
            time.sleep(0.1)

    monkeypatch.setattr(module, "_capture", slow_capture)
    result, events, response = _run_actual_synthetic_client(tmp_path, monkeypatch)
    assert result["exit_status"] == 0
    assert result["failure_label"] is None
    assert events == ["credentials_enter", "credentials_complete", "credentials_exit"]
    assert response.read_text() == "Synthetic completed answer.\n"


@pytest.mark.parametrize(
    "mode",
    [
        "early_disconnect",
        "partial",
        "malformed",
        "client_error",
        "pending_rpc",
        "empty",
        "terminal_nonzero",
        "terminal_timeout",
        "cleanup_error",
    ],
)
def test_incomplete_native_lifecycle_never_completes_the_actual_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    result, events, _response = _run_actual_synthetic_client(
        tmp_path, monkeypatch, mode
    )
    assert result["failure_label"] is not None
    assert events == ["credentials_enter", "credentials_exit"]
    assert (tmp_path / "client-events.private").read_bytes().startswith(b"{")
    assert not (tmp_path / "workspace" / "client-events.private").exists()


def test_interruption_keeps_partial_json_in_the_durable_capture_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(KeyboardInterrupt):
        _run_actual_synthetic_client(tmp_path, monkeypatch, "interruption")
    raw = tmp_path / "client-events.private"
    assert raw.stat().st_mode & 0o077 == 0
    assert b'"type": "turn.started"' in raw.read_bytes()
    assert not (tmp_path / "workspace" / "client-events.private").exists()
