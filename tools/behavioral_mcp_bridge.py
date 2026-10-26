"""One authenticated development-only stdio bridge to one explicit endpoint.

The parent owns the endpoint process outside the client's OS sandbox. The client
executes an isolated copy of this file with only a one-use socket credential.
No endpoint command, runtime path, client credential, or transcript is copied
into the proxy's material. The caller owns synthetic-runtime authorization.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import json
import math
import os
import secrets
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Protocol

AUTH_MAGIC = b"MEMORY-MCP-BRIDGE\x02"
SECRET_BYTES = 32
HEADER = struct.Struct("!BI")
DATA, END, ERROR = 1, 2, 3
CHUNK_BYTES = 64 * 1024
PROXY_CLOSE_GRACE_SECONDS = 0.25
ENVIRONMENT_KEYS = frozenset({"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "LC_CTYPE"})
ENDPOINT_EXTENSION_KEYS = frozenset(
    {"PYTHON_KEYRING_BACKEND", "PYTHONNOUSERSITE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}
)
AUTH_ENVIRONMENT_KEYS = (
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
CANARY_READABLE, CANARY_DENIED, CANARY_NOT_REQUESTED, CANARY_UNCONFIRMED = range(4)
MAX_RPC_MESSAGES = 65536
MAX_RPC_IDENTIFIERS = 8192
MAX_RPC_NAMES = 128
MAX_RPC_IDENTIFIER_BYTES = 128


class ProxyPolicyFactory(Protocol):
    """Supply the same nested process policy used by proof and execution."""

    def __call__(
        self,
        command: Sequence[str],
        *,
        policy_path: Path,
        executable_paths: Sequence[Path],
        bridge_socket: Path,
        readable_proxy_files: Sequence[Path],
        credential_homes: Sequence[Path],
    ) -> Sequence[str]: ...


class BridgeError(Exception):
    """A fixed failure label containing no endpoint or transported content."""


@dataclass(frozen=True)
class BridgeLimits:
    max_frame_bytes: int = 8 * 1024 * 1024
    max_stream_bytes: int = 64 * 1024 * 1024
    max_stderr_bytes: int = 1024 * 1024
    connect_timeout_seconds: float = 30.0
    auth_timeout_seconds: float = 5.0
    idle_timeout_seconds: float = 180.0
    session_timeout_seconds: float = 900.0
    shutdown_timeout_seconds: float = 2.0

    def validate(self) -> None:
        if (
            type(self.max_frame_bytes) is not int
            or not 1 <= self.max_frame_bytes <= 16 * 1024 * 1024
            or type(self.max_stream_bytes) is not int
            or not self.max_frame_bytes <= self.max_stream_bytes <= 1024**3
            or type(self.max_stderr_bytes) is not int
            or not 1 <= self.max_stderr_bytes <= 64 * 1024 * 1024
        ):
            raise BridgeError("bridge_invalid_configuration")
        for value in (
            self.connect_timeout_seconds,
            self.auth_timeout_seconds,
            self.idle_timeout_seconds,
            self.session_timeout_seconds,
            self.shutdown_timeout_seconds,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not math.isfinite(value)
                or not 0.01 <= value <= 1800
            ):
                raise BridgeError("bridge_invalid_configuration")


def transport_digest() -> str:
    """Bind the exact shared transport implementation, independent of a run."""
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        raise BridgeError("bridge_material_unavailable") from None


def _private_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _executable(path: Path) -> Path:
    if not path.is_absolute():
        raise BridgeError("bridge_invalid_configuration")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BridgeError("bridge_invalid_configuration")
    return resolved


def _canary_identity(path: Path) -> tuple[int, ...]:
    """Verify a caller-authored canary is readable without reading its bytes."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_mode & 0o077
            or not value.st_mode & stat.S_IRUSR
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
        ):
            raise BridgeError("bridge_invalid_configuration")
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
        )
    finally:
        os.close(descriptor)


class _Lines:
    def __init__(self, limits: BridgeLimits) -> None:
        self.limits = limits
        self.buffer = bytearray()
        self.total = 0

    def feed(self, data: bytes) -> list[bytes]:
        self.total += len(data)
        if self.total > self.limits.max_stream_bytes:
            raise BridgeError("bridge_stream_limit")
        self.buffer.extend(data)
        result: list[bytes] = []
        while (index := self.buffer.find(b"\n")) >= 0:
            if index + 1 > self.limits.max_frame_bytes:
                raise BridgeError("bridge_frame_limit")
            result.append(bytes(self.buffer[: index + 1]))
            del self.buffer[: index + 1]
        if len(self.buffer) >= self.limits.max_frame_bytes:
            raise BridgeError("bridge_frame_limit")
        return result

    def finish(self) -> None:
        if self.buffer:
            raise BridgeError("bridge_incomplete_frame")


class _Frames:
    def __init__(self, limits: BridgeLimits) -> None:
        self.limits = limits
        self.buffer = bytearray()
        self.total = 0
        self.ended = False

    def feed(self, data: bytes) -> list[bytes | None]:
        self.total += len(data)
        if self.total > self.limits.max_stream_bytes:
            raise BridgeError("bridge_stream_limit")
        self.buffer.extend(data)
        result: list[bytes | None] = []
        while len(self.buffer) >= HEADER.size:
            kind, length = HEADER.unpack_from(self.buffer)
            if self.ended or kind not in (DATA, END, ERROR):
                raise BridgeError("bridge_invalid_frame")
            if kind != DATA:
                if length:
                    raise BridgeError("bridge_invalid_frame")
                del self.buffer[: HEADER.size]
                if kind == ERROR:
                    raise BridgeError("bridge_peer_failed")
                self.ended = True
                result.append(None)
                continue
            if not 1 <= length <= self.limits.max_frame_bytes:
                raise BridgeError("bridge_frame_limit")
            if len(self.buffer) < HEADER.size + length:
                break
            payload = bytes(self.buffer[HEADER.size : HEADER.size + length])
            del self.buffer[: HEADER.size + length]
            if not payload.endswith(b"\n") or b"\n" in payload[:-1]:
                raise BridgeError("bridge_invalid_frame")
            result.append(payload)
        return result

    def finish(self) -> None:
        if self.buffer:
            raise BridgeError("bridge_incomplete_frame")


class _LifecycleMetrics:
    """Only fixed labels, bounded counters, and monotonic timing cross this API."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, object] = {
            "peer_to_bridge_wire_bytes": 0,
            "bridge_to_peer_wire_bytes": 0,
            "wire_byte_scope": "relay_io_excluding_handshake_and_failure_status",
            "json_byte_scope": "accepted_envelopes_excluding_newline",
            "endpoint_stdin_bytes": 0,
            "endpoint_stdout_bytes": 0,
            "endpoint_stderr_bytes": 0,
            "queued_to_peer_bytes": 0,
            "queued_to_endpoint_bytes": 0,
            "completion_trigger": None,
            "completion_probe_confirmed_at_observation": None,
            "eligible_completion": False,
            "endpoint_natural_exit_confirmed": False,
            "endpoint_forced_cleanup": False,
            "endpoint_returncode": None,
            "endpoint_stdout_eof": False,
            "endpoint_stderr_eof": False,
            "peer_eof": False,
            "peer_end_received": False,
            "relay_elapsed_seconds": None,
            "endpoint_elapsed_seconds": None,
            "endpoint_cleanup_elapsed_seconds": None,
        }

    def update(self, **values: object) -> None:
        with self._lock:
            self._values.update(values)

    def add(self, key: str, count: int) -> None:
        with self._lock:
            previous = self._values[key]
            assert isinstance(previous, int)
            self._values[key] = previous + count

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return dict(self._values)


def _rpc_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BridgeError("bridge_invalid_json_rpc")
        result[key] = value
    return result


def _invalid_json_constant(value: str) -> None:
    raise BridgeError("bridge_invalid_json_rpc")


def _rpc_identifier(value: object) -> int | str:
    if type(value) is int and -(2**63) <= value < 2**63:
        return value
    if isinstance(value, str):
        try:
            if 0 < len(value.encode()) <= MAX_RPC_IDENTIFIER_BYTES:
                return value
        except UnicodeError:
            pass
    raise BridgeError("bridge_invalid_json_rpc")


def _rpc_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_RPC_IDENTIFIER_BYTES
        or any(
            not (character.isascii() and (character.isalnum() or character in "_./:-"))
            for character in value
        )
    ):
        raise BridgeError("bridge_invalid_json_rpc")
    return value


def _count_name(counts: dict[str, int], name: str) -> None:
    if name not in counts and len(counts) >= MAX_RPC_NAMES:
        raise BridgeError("bridge_rpc_accounting_limit")
    counts[name] = counts.get(name, 0) + 1


@dataclass
class _RPCDirection:
    pending: dict[int | str, str] = field(default_factory=dict)
    completed: set[int | str] = field(default_factory=set)
    requests: int = 0
    responses: int = 0
    error_responses: int = 0
    notifications: int = 0
    json_bytes: int = 0
    methods: dict[str, int] = field(default_factory=dict)
    tools: dict[str, int] = field(default_factory=dict)

    def snapshot(self, prefix: str) -> dict[str, object]:
        return {
            prefix + "_requests": self.requests,
            prefix + "_responses": self.responses,
            prefix + "_error_responses": self.error_responses,
            prefix + "_notifications": self.notifications,
            # Count the transported JSON bytes, excluding its newline delimiter.
            prefix + "_json_bytes": self.json_bytes,
            prefix + "_pending_requests": len(self.pending),
            prefix + "_methods": dict(self.methods),
            prefix + "_tools": dict(self.tools),
        }


class _RPCState:
    """Parent-only correlation; IDs and payloads never enter public metadata."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._client, self._endpoint = _RPCDirection(), _RPCDirection()
        self._messages = 0
        self._initialized = False

    def observe(self, line: bytes, *, from_peer: bool) -> None:
        try:
            message: object = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_rpc_object,
                parse_constant=_invalid_json_constant,
            )
        except (ValueError, UnicodeError, RecursionError) as _error:
            raise BridgeError("bridge_invalid_json_rpc") from None
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise BridgeError("bridge_invalid_json_rpc")
        with self._lock:
            if self._messages >= MAX_RPC_MESSAGES:
                raise BridgeError("bridge_rpc_accounting_limit")
            sent, received = (
                (self._client, self._endpoint)
                if from_peer
                else (self._endpoint, self._client)
            )
            if "method" in message:
                if not set(message) <= {"jsonrpc", "id", "method", "params"}:
                    raise BridgeError("bridge_invalid_json_rpc")
                method = _rpc_name(message["method"])
                params = message.get("params", {})
                if not isinstance(params, (dict, list)):
                    raise BridgeError("bridge_invalid_json_rpc")
                if "id" in message:
                    identifier = _rpc_identifier(message["id"])
                    if identifier in sent.pending or identifier in sent.completed:
                        raise BridgeError("bridge_duplicate_rpc_request")
                    if len(sent.pending) + len(sent.completed) >= MAX_RPC_IDENTIFIERS:
                        raise BridgeError("bridge_rpc_accounting_limit")
                    sent.pending[identifier] = method
                    sent.requests += 1
                else:
                    sent.notifications += 1
                _count_name(sent.methods, method)
                if method == "tools/call":
                    if not isinstance(params, dict):
                        raise BridgeError("bridge_invalid_json_rpc")
                    _count_name(sent.tools, _rpc_name(params.get("name")))
            else:
                if (
                    "id" not in message
                    or ("result" in message) == ("error" in message)
                    or not set(message) <= {"jsonrpc", "id", "result", "error"}
                ):
                    raise BridgeError("bridge_invalid_json_rpc")
                identifier = _rpc_identifier(message["id"])
                if "error" in message:
                    error = message["error"]
                    if (
                        not isinstance(error, dict)
                        or type(error.get("code")) is not int
                        or not isinstance(error.get("message"), str)
                        or not set(error) <= {"code", "message", "data"}
                    ):
                        raise BridgeError("bridge_invalid_json_rpc")
                if identifier not in received.pending:
                    raise BridgeError(
                        "bridge_duplicate_rpc_response"
                        if identifier in received.completed
                        else "bridge_unmatched_rpc_response"
                    )
                method = received.pending.pop(identifier)
                received.completed.add(identifier)
                sent.responses += 1
                if "error" in message:
                    sent.error_responses += 1
                elif not from_peer and method == "initialize":
                    self._initialized = True
            sent.json_bytes += len(line) - 1
            self._messages += 1

    def finish(self) -> None:
        with self._lock:
            if self._client.pending or self._endpoint.pending:
                raise BridgeError("bridge_completion_pending_requests")
            if not self._initialized:
                raise BridgeError("bridge_completion_startup_unconfirmed")

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                **self._client.snapshot("client_to_endpoint"),
                **self._endpoint.snapshot("endpoint_to_client"),
                "startup_response_confirmed": self._initialized,
            }


def _send_status(peer: socket.socket, kind: int) -> None:
    with contextlib.suppress(OSError):
        peer.settimeout(0.1)
        peer.sendall(HEADER.pack(kind, 0))


def _receive_exact(
    peer: socket.socket,
    size: int,
    timeout: float,
    stop: threading.Event,
) -> bytes:
    end = time.monotonic() + timeout
    received = bytearray()
    peer.settimeout(min(timeout, 0.05))
    while len(received) < size:
        if stop.is_set():
            raise BridgeError("bridge_cancelled")
        if time.monotonic() >= end:
            raise BridgeError("bridge_authentication_timeout")
        try:
            chunk = peer.recv(size - len(received))
        except TimeoutError:
            continue
        if not chunk:
            raise BridgeError("bridge_authentication_failed")
        received.extend(chunk)
    return bytes(received)


def _validate_endpoint_environment(environment: Mapping[str, str], cwd: Path) -> None:
    if not set(environment) & ENDPOINT_EXTENSION_KEYS:
        if not set(environment) <= ENVIRONMENT_KEYS:
            raise BridgeError("bridge_invalid_configuration")
        return
    # The parent alone loads this helper. The copied standalone proxy never
    # constructs a bridge and does not need to read development source files.
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_memory_endpoint import EndpointError, validate_endpoint_environment

    try:
        validate_endpoint_environment(environment, cwd)
    except EndpointError:
        raise BridgeError("bridge_invalid_configuration") from None


def _endpoint_group_has_no_live_members(group: int) -> bool:
    # Only the parent performs endpoint cleanup. The standalone proxy copy
    # needs no access to the development helper or its source directory.
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_process_cleanup import group_has_no_live_members

    return group_has_no_live_members(group)


def _signal_endpoint_group(process: subprocess.Popen[bytes], number: int) -> None:
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin can report EPERM for an already-exited group. A stopped
        # leader alone cannot prove that its children have also stopped.
        if process.poll() is None or not _endpoint_group_has_no_live_members(
            process.pid
        ):
            raise


def _stop_endpoint(process: subprocess.Popen[bytes], timeout: float) -> None:
    # Kill the group even after its leader exits: MCP descendants can retain a
    # pipe or survive their parent. The leader is always waited/reaped here.
    try:
        _signal_endpoint_group(process, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=timeout)
    finally:
        try:
            _signal_endpoint_group(process, signal.SIGKILL)
        finally:
            try:
                process.wait(timeout=timeout)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
    deadline = time.monotonic() + timeout
    while not _endpoint_group_has_no_live_members(process.pid):
        if time.monotonic() >= deadline:
            raise BridgeError("bridge_shutdown_failed")
        time.sleep(0.02)


def _relay(
    peer: socket.socket,
    source: int,
    destination: int,
    limits: BridgeLimits,
    stop: threading.Event,
    endpoint: subprocess.Popen[bytes] | None = None,
) -> None:
    """Move bounded newline frames; the endpoint side drains EOF before exit."""
    for descriptor in (peer.fileno(), source, destination):
        os.set_blocking(descriptor, False)
    stderr = endpoint.stderr.fileno() if endpoint and endpoint.stderr else None
    if stderr is not None:
        os.set_blocking(stderr, False)
    lines, frames = _Lines(limits), _Frames(limits)
    to_peer, to_local = bytearray(), bytearray()
    local_ended = remote_ended = end_sent = destination_closed = False
    shutdown_deadline: float | None = None
    began = last_activity = time.monotonic()
    stderr_bytes = 0
    buffer_limit = 2 * limits.max_frame_bytes + CHUNK_BYTES + HEADER.size
    while not stop.is_set():
        now = time.monotonic()
        if now - began >= limits.session_timeout_seconds:
            raise BridgeError("bridge_session_timeout")
        if now - last_activity >= limits.idle_timeout_seconds:
            raise BridgeError("bridge_idle_timeout")
        if shutdown_deadline is not None and now >= shutdown_deadline:
            raise BridgeError("bridge_shutdown_timeout")
        if endpoint is not None and endpoint.poll() not in (None, 0):
            raise BridgeError("bridge_endpoint_failed")
        if endpoint is None and remote_ended and not to_local:
            return
        if endpoint is not None and remote_ended and not to_local:
            if not destination_closed:
                assert endpoint.stdin is not None
                endpoint.stdin.close()
                destination_closed = True
        if local_ended and not end_sent:
            if endpoint is None or endpoint.poll() is not None:
                to_peer.extend(HEADER.pack(END, 0))
                end_sent = True
        if endpoint is not None and end_sent and not to_peer:
            return
        if max(len(to_peer), len(to_local)) > buffer_limit:
            raise BridgeError("bridge_buffer_limit")
        readable = [peer.fileno()]
        if not local_ended:
            readable.append(source)
        if stderr is not None:
            readable.append(stderr)
        writable = [peer.fileno()] if to_peer else []
        if to_local and not destination_closed:
            writable.append(destination)
        ready_read, ready_write, _ = select.select(readable, writable, [], 0.02)
        if ready_read or ready_write:
            last_activity = time.monotonic()
        for descriptor in ready_write:
            pending = to_peer if descriptor == peer.fileno() else to_local
            try:
                count = os.write(descriptor, pending)
            except BlockingIOError:
                continue
            if count <= 0:
                raise BridgeError("bridge_transport_failed")
            del pending[:count]
        for descriptor in ready_read:
            try:
                data = os.read(descriptor, CHUNK_BYTES)
            except BlockingIOError:
                continue
            if descriptor == peer.fileno():
                if not data:
                    frames.finish()
                    if not remote_ended:
                        raise BridgeError("bridge_disconnected")
                    if endpoint is None and to_local:
                        continue
                    raise BridgeError("bridge_disconnected")
                for payload in frames.feed(data):
                    if payload is None:
                        remote_ended = True
                        shutdown_deadline = now + limits.shutdown_timeout_seconds
                    else:
                        if destination_closed:
                            raise BridgeError("bridge_invalid_frame")
                        to_local.extend(payload)
            elif descriptor == stderr:
                if not data:
                    stderr = None
                stderr_bytes += len(data)
                if stderr_bytes > limits.max_stderr_bytes:
                    raise BridgeError("bridge_stderr_limit")
            elif data:
                for line in lines.feed(data):
                    to_peer.extend(HEADER.pack(DATA, len(line)))
                    to_peer.extend(line)
            else:
                lines.finish()
                local_ended = True
                shutdown_deadline = now + limits.shutdown_timeout_seconds
                if endpoint is None:
                    # Let the endpoint-owning side report its bounded shutdown
                    # failure before the proxy independently times out.
                    shutdown_deadline += PROXY_CLOSE_GRACE_SECONDS


def _tracked_endpoint_relay(
    peer: socket.socket,
    endpoint: subprocess.Popen[bytes],
    limits: BridgeLimits,
    stop: threading.Event,
    finish_requested: threading.Event,
    completion_probe: Callable[[], bool],
    protocol: _RPCState,
    metrics: _LifecycleMetrics,
) -> None:
    """Opt-in parent lifecycle; completion is a witnessed state, never cleanup."""
    assert endpoint.stdout is not None and endpoint.stdin is not None
    assert endpoint.stderr is not None
    source, destination, stderr = (
        endpoint.stdout.fileno(),
        endpoint.stdin.fileno(),
        endpoint.stderr.fileno(),
    )
    for descriptor in (peer.fileno(), source, destination, stderr):
        os.set_blocking(descriptor, False)
    lines, frames = _Lines(limits), _Frames(limits)
    to_peer, to_endpoint = bytearray(), bytearray()
    peer_eof = stdout_eof = stderr_eof = eligible = end_sent = False
    shutdown_deadline: float | None = None
    began = last_activity = time.monotonic()
    stderr_bytes = 0
    buffer_limit = 2 * limits.max_frame_bytes + CHUNK_BYTES + HEADER.size

    def begin_completion(trigger: str) -> None:
        nonlocal eligible, shutdown_deadline
        # The parent freezes terminal capture before this callback. Never retry
        # it after a false observation or after another transport failure.
        try:
            confirmed = completion_probe() is True
        except Exception:
            confirmed = False
        metrics.update(
            completion_trigger=trigger,
            completion_probe_confirmed_at_observation=confirmed,
            queued_to_peer_bytes=len(to_peer),
            queued_to_endpoint_bytes=len(to_endpoint),
        )
        if not confirmed:
            raise BridgeError("bridge_completion_unconfirmed")
        frames.finish()
        lines.finish()
        if to_peer or to_endpoint:
            raise BridgeError("bridge_completion_pending_data")
        protocol.finish()
        if endpoint.poll() not in (None, 0):
            raise BridgeError("bridge_endpoint_failed")
        eligible = True
        metrics.update(eligible_completion=True)
        shutdown_deadline = time.monotonic() + limits.shutdown_timeout_seconds
        assert endpoint.stdin is not None
        endpoint.stdin.close()

    while not stop.is_set():
        now = time.monotonic()
        if now - began >= limits.session_timeout_seconds:
            raise BridgeError("bridge_session_timeout")
        if now - last_activity >= limits.idle_timeout_seconds:
            raise BridgeError("bridge_idle_timeout")
        if shutdown_deadline is not None and now >= shutdown_deadline:
            raise BridgeError("bridge_shutdown_timeout")
        returncode = endpoint.poll()
        if returncode not in (None, 0):
            raise BridgeError("bridge_endpoint_failed")
        if finish_requested.is_set() and not eligible:
            begin_completion("controller")
        if eligible and stdout_eof and stderr_eof and returncode == 0:
            if not end_sent and not peer_eof:
                to_peer.extend(HEADER.pack(END, 0))
                end_sent = True
            if peer_eof and not to_peer:
                frames.finish()
                lines.finish()
                protocol.finish()
                metrics.update(
                    endpoint_natural_exit_confirmed=True,
                    endpoint_returncode=0,
                    queued_to_peer_bytes=0,
                    queued_to_endpoint_bytes=0,
                )
                return
        if max(len(to_peer), len(to_endpoint)) > buffer_limit:
            raise BridgeError("bridge_buffer_limit")
        metrics.update(
            queued_to_peer_bytes=len(to_peer),
            queued_to_endpoint_bytes=len(to_endpoint),
        )
        readable = [] if peer_eof else [peer.fileno()]
        if not stdout_eof:
            readable.append(source)
        if not stderr_eof:
            readable.append(stderr)
        writable = [peer.fileno()] if to_peer else []
        if to_endpoint and not eligible:
            writable.append(destination)
        ready_read, ready_write, _ = select.select(readable, writable, [], 0.02)
        if ready_read or ready_write:
            last_activity = time.monotonic()
        for descriptor in ready_write:
            pending = to_peer if descriptor == peer.fileno() else to_endpoint
            try:
                count = os.write(descriptor, pending)
            except BlockingIOError:
                continue
            if count <= 0:
                raise BridgeError("bridge_transport_failed")
            metrics.add(
                "bridge_to_peer_wire_bytes"
                if descriptor == peer.fileno()
                else "endpoint_stdin_bytes",
                count,
            )
            del pending[:count]
            metrics.update(
                queued_to_peer_bytes=len(to_peer),
                queued_to_endpoint_bytes=len(to_endpoint),
            )
        for descriptor in ready_read:
            try:
                data = os.read(descriptor, CHUNK_BYTES)
            except BlockingIOError:
                continue
            if descriptor == peer.fileno():
                if not data:
                    peer_eof = True
                    metrics.update(peer_eof=True)
                    frames.finish()
                    if not eligible:
                        begin_completion("peer_eof")
                    continue
                metrics.add("peer_to_bridge_wire_bytes", len(data))
                for payload in frames.feed(data):
                    if payload is None:
                        metrics.update(peer_end_received=True)
                        if not eligible:
                            begin_completion("peer_end")
                    else:
                        if eligible:
                            raise BridgeError("bridge_output_after_completion")
                        protocol.observe(payload, from_peer=True)
                        to_endpoint.extend(payload)
                        metrics.update(queued_to_endpoint_bytes=len(to_endpoint))
            elif descriptor == stderr:
                metrics.add("endpoint_stderr_bytes", len(data))
                if not data:
                    stderr_eof = True
                    metrics.update(endpoint_stderr_eof=True)
                elif eligible:
                    raise BridgeError("bridge_output_after_completion")
                stderr_bytes += len(data)
                if stderr_bytes > limits.max_stderr_bytes:
                    raise BridgeError("bridge_stderr_limit")
            else:
                metrics.add("endpoint_stdout_bytes", len(data))
                if not data:
                    lines.finish()
                    stdout_eof = True
                    metrics.update(endpoint_stdout_eof=True)
                elif eligible:
                    raise BridgeError("bridge_output_after_completion")
                else:
                    for line in lines.feed(data):
                        protocol.observe(line, from_peer=False)
                        to_peer.extend(HEADER.pack(DATA, len(line)))
                        to_peer.extend(line)
                        metrics.update(queued_to_peer_bytes=len(to_peer))
    raise BridgeError("bridge_cancelled")


class MCPBridge:
    """Create private one-session material; close before inspecting the Store.

    `wait` observes completion without cleanup. `close`/context exit always
    completes endpoint cleanup and removes the socket and proxy material. The
    content-free `failure_label` and `endpoint_started` remain available.

    An optional `completion_probe` enables parent-only JSON-RPC accounting and
    graceful client completion. It must inspect already captured terminal
    evidence at the observation, never collect later output to revise an EOF.
    """

    def __init__(
        self,
        root: Path,
        endpoint_command: Sequence[str],
        endpoint_environment: Mapping[str, str],
        endpoint_cwd: Path,
        proxy_python: Path,
        *,
        limits: BridgeLimits | None = None,
        credential_homes: Sequence[Path] = (),
        credential_canary: Path | None = None,
        proxy_policy_factory: ProxyPolicyFactory | None = None,
        completion_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.limits = limits if limits is not None else BridgeLimits()
        if not isinstance(self.limits, BridgeLimits):
            raise BridgeError("bridge_invalid_configuration")
        self.limits.validate()
        try:
            if (
                not root.is_absolute()
                or not root.is_dir()
                or not endpoint_cwd.is_absolute()
                or not endpoint_cwd.is_dir()
                or not endpoint_command
                or any(
                    not isinstance(arg, str) or "\x00" in arg
                    for arg in endpoint_command
                )
                or "HOME" not in endpoint_environment
                or any(
                    not isinstance(value, str) or "\x00" in value
                    for value in endpoint_environment.values()
                )
                or not Path(endpoint_environment["HOME"]).is_absolute()
            ):
                raise BridgeError("bridge_invalid_configuration")
            _validate_endpoint_environment(endpoint_environment, endpoint_cwd)
            _executable(Path(endpoint_command[0]))
            self._proxy_python = _executable(proxy_python)
            self._env_executable = _executable(Path("/usr/bin/env"))
            boundary_supplied = (bool(credential_homes), credential_canary is not None)
            if (any(boundary_supplied) and not all(boundary_supplied)) or (
                proxy_policy_factory is not None and not all(boundary_supplied)
            ):
                raise BridgeError("bridge_invalid_configuration")
            if proxy_policy_factory is not None and not callable(proxy_policy_factory):
                raise BridgeError("bridge_invalid_configuration")
            if completion_probe is not None and not callable(completion_probe):
                raise BridgeError("bridge_invalid_configuration")
            self._credential_homes = tuple(
                path.resolve(strict=True) for path in credential_homes
            )
            if any(
                not path.is_absolute()
                or path.is_symlink()
                or not resolved.is_dir()
                or resolved.stat().st_mode & 0o077
                or resolved.stat().st_uid != os.geteuid()
                for path, resolved in zip(
                    credential_homes, self._credential_homes, strict=True
                )
            ):
                raise BridgeError("bridge_invalid_configuration")
            self._credential_canary: Path | None = None
            self._canary_identity: tuple[int, ...] | None = None
            if credential_canary is not None:
                if (
                    not credential_canary.is_absolute()
                    or credential_canary.is_symlink()
                ):
                    raise BridgeError("bridge_invalid_configuration")
                self._credential_canary = credential_canary.resolve(strict=True)
                if not any(
                    self._credential_canary.is_relative_to(path)
                    for path in self._credential_homes
                ):
                    raise BridgeError("bridge_invalid_configuration")
                self._canary_identity = _canary_identity(self._credential_canary)
                if any(
                    (
                        candidate
                        if set(endpoint_environment) & ENDPOINT_EXTENSION_KEYS
                        and candidate == Path(endpoint_environment["HOME"])
                        else candidate.resolve()
                    ).is_relative_to(home)
                    for home in self._credential_homes
                    for candidate in (
                        root,
                        endpoint_cwd,
                        Path(endpoint_environment["HOME"]),
                        *(
                            [Path(endpoint_environment["TMPDIR"])]
                            if "TMPDIR" in endpoint_environment
                            else []
                        ),
                    )
                ):
                    raise BridgeError("bridge_invalid_configuration")
            self._sandbox_executable: Path | None = None
            if proxy_policy_factory is not None:
                if sys.platform != "darwin":
                    raise BridgeError("bridge_proxy_policy_unavailable")
                self._sandbox_executable = _executable(Path("/usr/bin/sandbox-exec"))
        except (OSError, RuntimeError, TypeError, ValueError) as _error:
            raise BridgeError("bridge_invalid_configuration") from None
        self._root, self._cwd = root, endpoint_cwd
        self._command = tuple(endpoint_command)
        self._environment = dict(endpoint_environment)
        self._proxy_policy_factory = proxy_policy_factory
        self._completion_probe = completion_probe
        self._protocol = _RPCState() if completion_probe is not None else None
        self._metrics = _LifecycleMetrics()
        self._material: Path | None = None
        self._socket_root: Path | None = None
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop, self._done = threading.Event(), threading.Event()
        self._finish_requested = threading.Event()
        self._failure_label: str | None = None
        self._primary_failure_reason: str | None = None
        self._failure_lock = threading.Lock()
        self._client_completion_confirmed = False
        self._endpoint_started = False
        self._endpoint_process_metadata: dict[str, object] | None = None
        self._process_cleanup_confirmed = False
        self._resources_cleanup_confirmed = False
        self._proxy_auth_environment_absent: bool | None = None
        self._proxy_environment_isolated: bool | None = None
        self._proxy_auth_home_denied: bool | None = None
        self._proxy_home = Path()
        self._proxy_tmp = Path()
        self._proxy_environment: Mapping[str, str] = MappingProxyType({})
        self._entered = False
        self._secret = secrets.token_bytes(SECRET_BYTES)
        self.proxy_command: tuple[str, ...] = ()
        self.readable_proxy_files: tuple[Path, ...] = ()
        self.socket_path = Path()

    @property
    def cleanup_paths(self) -> tuple[Path, ...]:
        """Retain every allocated root so callers can checkpoint failed cleanup."""
        return tuple(
            path for path in (self._material, self._socket_root) if path is not None
        )

    @property
    def process_cleanup_confirmed(self) -> bool:
        return self._process_cleanup_confirmed

    @property
    def resources_cleanup_confirmed(self) -> bool:
        return self._resources_cleanup_confirmed

    @property
    def endpoint_process_metadata(self) -> Mapping[str, object] | None:
        if self._endpoint_process_metadata is None:
            return None
        return MappingProxyType(dict(self._endpoint_process_metadata))

    @property
    def failure_label(self) -> str | None:
        return self._failure_label

    def _record_failure(self, label: str) -> None:
        with self._failure_lock:
            self._failure_label = label
            if self._primary_failure_reason is None:
                self._primary_failure_reason = label
            self._client_completion_confirmed = False

    @property
    def client_completion_confirmed(self) -> bool:
        return (
            self._client_completion_confirmed and self._primary_failure_reason is None
        )

    @property
    def lifecycle_metadata(self) -> Mapping[str, object]:
        result: dict[str, object] = {
            "schema": "memory.behavioral-bridge-lifecycle.v1",
            "json_rpc_tracking": self._protocol is not None,
            "relay_byte_tracking": self._protocol is not None,
            **self._metrics.snapshot(),
            "client_completion_confirmed": self.client_completion_confirmed,
            "primary_failure_reason": self._primary_failure_reason,
            "failure_label": self._failure_label,
            "process_cleanup_confirmed": self._process_cleanup_confirmed,
            "resources_cleanup_confirmed": self._resources_cleanup_confirmed,
        }
        if self._protocol is not None:
            result.update(self._protocol.snapshot())
        return MappingProxyType(result)

    @property
    def endpoint_started(self) -> bool:
        return self._endpoint_started

    @property
    def proxy_auth_environment_absent(self) -> bool | None:
        return self._proxy_auth_environment_absent

    @property
    def proxy_environment_isolated(self) -> bool | None:
        return self._proxy_environment_isolated

    @property
    def proxy_auth_home_denied(self) -> bool | None:
        return self._proxy_auth_home_denied

    @property
    def proxy_home(self) -> Path:
        return self._proxy_home

    @property
    def proxy_environment(self) -> Mapping[str, str]:
        return self._proxy_environment

    @property
    def proxy_executable_paths(self) -> tuple[Path, ...]:
        return (
            self._env_executable,
            *(
                [self._sandbox_executable]
                if self._sandbox_executable is not None
                else []
            ),
            self._proxy_python,
        )

    @property
    def unix_socket_path(self) -> Path:
        return self.socket_path

    @property
    def proxy_read_paths(self) -> tuple[Path, ...]:
        return self.readable_proxy_files

    def transport_digest(self) -> str:
        return transport_digest()

    def __enter__(self) -> MCPBridge:
        if self._entered or self._stop.is_set():
            raise BridgeError("bridge_session_consumed")
        self._entered = True
        try:
            self._material = Path(
                tempfile.mkdtemp(prefix="mcp-bridge-", dir=self._root)
            )
            # Darwin AF_UNIX sun_path is short. IPC metadata is always transient,
            # in an explicit private directory, independent of campaign depth.
            socket_parent = "/private/tmp" if sys.platform == "darwin" else "/tmp"
            self._socket_root = Path(tempfile.mkdtemp(prefix="mb-", dir=socket_parent))
            self.socket_path = self._socket_root / "s"
            self._proxy_home, self._proxy_tmp = (
                self._socket_root / "h",
                self._socket_root / "t",
            )
            for directory in (self._proxy_home, self._proxy_tmp):
                directory.mkdir(mode=0o700)
                if any(
                    directory.is_relative_to(home) for home in self._credential_homes
                ):
                    raise BridgeError("bridge_invalid_configuration")
            self._proxy_environment = MappingProxyType(
                {
                    "HOME": str(self._proxy_home),
                    "TMPDIR": str(self._proxy_tmp),
                    "PATH": "/usr/bin:/bin",
                    "LANG": "en_US.UTF-8",
                    "LC_ALL": "en_US.UTF-8",
                }
            )
            script, credential = self._material / "proxy.py", self._material / "session"
            _private_file(script, Path(__file__).read_bytes())
            _private_file(
                credential,
                json.dumps(
                    {
                        "secret": self._secret.hex(),
                        "socket": str(self.socket_path),
                        "limits": asdict(self.limits),
                        "proxy_home": str(self._proxy_home),
                        "proxy_tmp": str(self._proxy_tmp),
                        "credential_canary": (
                            str(self._credential_canary)
                            if self._credential_canary is not None
                            else None
                        ),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
            )
            command: tuple[str, ...] = (
                str(self._proxy_python),
                "-I",
                "-S",
                str(script),
                "--proxy",
                str(credential),
            )
            self.readable_proxy_files = (script, credential)
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            self._listener.listen(1)
            self._listener.settimeout(0.05)
            if self._proxy_policy_factory is not None:
                policy = self._material / "proxy.sb"
                try:
                    wrapped = tuple(
                        self._proxy_policy_factory(
                            command,
                            policy_path=policy,
                            executable_paths=self.proxy_executable_paths,
                            bridge_socket=self.socket_path,
                            readable_proxy_files=self.readable_proxy_files,
                            credential_homes=self._credential_homes,
                        )
                    )
                    metadata = policy.lstat()
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_mode & 0o077
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_nlink != 1
                        or wrapped
                        != (str(self._sandbox_executable), "-f", str(policy), *command)
                    ):
                        raise BridgeError("bridge_proxy_policy_unavailable")
                except Exception:
                    raise BridgeError("bridge_proxy_policy_unavailable") from None
                self.readable_proxy_files = (*self.readable_proxy_files, policy)
                command = wrapped
            self.proxy_command = (
                str(self._env_executable),
                "-i",
                *(key + "=" + value for key, value in self._proxy_environment.items()),
                *command,
            )
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            return self
        except BridgeError:
            self.close()
            raise
        except (OSError, RuntimeError) as _error:
            self.close()
            raise BridgeError("bridge_material_unavailable") from None

    def _serve(self) -> None:
        peer: socket.socket | None = None
        endpoint: subprocess.Popen[bytes] | None = None
        relay_started: float | None = None
        graceful = False
        try:
            assert self._listener is not None
            deadline = time.monotonic() + self.limits.connect_timeout_seconds
            while not self._stop.is_set():
                if self._finish_requested.is_set():
                    raise BridgeError("bridge_completion_startup_unconfirmed")
                if time.monotonic() >= deadline:
                    raise BridgeError("bridge_connection_timeout")
                try:
                    peer, _ = self._listener.accept()
                    break
                except TimeoutError:
                    continue
            self._listener.close()  # The first connection consumes this session.
            if peer is None:
                return
            presented = _receive_exact(
                peer,
                len(AUTH_MAGIC) + SECRET_BYTES + 3,
                self.limits.auth_timeout_seconds,
                self._stop,
            )
            if not hmac.compare_digest(presented[:-3], AUTH_MAGIC + self._secret):
                raise BridgeError("bridge_authentication_failed")
            self._proxy_auth_environment_absent = presented[-3] == 0
            if not self._proxy_auth_environment_absent:
                raise BridgeError("bridge_proxy_credentials_present")
            self._proxy_environment_isolated = presented[-2] == 1
            if not self._proxy_environment_isolated:
                raise BridgeError("bridge_proxy_environment_unconfirmed")
            canary_state = presented[-1]
            if self._credential_canary is None:
                if canary_state != CANARY_NOT_REQUESTED:
                    raise BridgeError("bridge_proxy_credential_boundary_unconfirmed")
            else:
                self._proxy_auth_home_denied = False
                if canary_state == CANARY_READABLE:
                    raise BridgeError("bridge_proxy_credential_readable")
                if canary_state != CANARY_DENIED:
                    raise BridgeError("bridge_proxy_credential_boundary_unconfirmed")
                try:
                    identity = _canary_identity(self._credential_canary)
                except Exception:
                    raise BridgeError(
                        "bridge_proxy_credential_boundary_unconfirmed"
                    ) from None
                if identity != self._canary_identity:
                    raise BridgeError("bridge_proxy_credential_boundary_unconfirmed")
                self._proxy_auth_home_denied = True
            if self._stop.is_set():
                return
            try:
                started_utc, started_monotonic = time.time(), time.monotonic()
                endpoint = subprocess.Popen(
                    self._command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=self._cwd,
                    env=self._environment,
                    start_new_session=True,
                    close_fds=True,
                )
            except (OSError, ValueError) as _error:
                raise BridgeError("bridge_endpoint_unavailable") from None
            self._endpoint_started = True
            self._endpoint_process_metadata = {
                "phase": "memory_mcp_endpoint",
                "pid": endpoint.pid,
                "pgid": endpoint.pid,
                "started_at_utc": started_utc,
                "started_monotonic": started_monotonic,
                "reaped": False,
                "process_group_stopped": False,
            }
            peer.sendall(b"\x01")
            assert endpoint.stdout is not None and endpoint.stdin is not None
            relay_started = time.monotonic()
            if self._completion_probe is None:
                _relay(
                    peer,
                    endpoint.stdout.fileno(),
                    endpoint.stdin.fileno(),
                    self.limits,
                    self._stop,
                    endpoint,
                )
            else:
                assert self._protocol is not None
                _tracked_endpoint_relay(
                    peer,
                    endpoint,
                    self.limits,
                    self._stop,
                    self._finish_requested,
                    self._completion_probe,
                    self._protocol,
                    self._metrics,
                )
                graceful = True
        except BridgeError as error:
            if not self._stop.is_set() or self._completion_probe is not None:
                self._record_failure(str(error))
                if peer is not None and self._endpoint_started:
                    _send_status(peer, ERROR)
        except (OSError, ValueError) as _error:
            if not self._stop.is_set() or self._completion_probe is not None:
                self._record_failure("bridge_transport_failed")
                if peer is not None and self._endpoint_started:
                    _send_status(peer, ERROR)
        except Exception:
            # Unexpected failures are still failed transport, never a silently
            # successful thread or a traceback containing private arguments.
            self._record_failure("bridge_internal_failure")
            if peer is not None and self._endpoint_started:
                _send_status(peer, ERROR)
        finally:
            if relay_started is not None:
                self._metrics.update(
                    relay_elapsed_seconds=time.monotonic() - relay_started
                )
            if self._listener is not None:
                self._listener.close()
            if endpoint is not None:
                cleanup_started = time.monotonic()
                try:
                    if graceful:
                        try:
                            group_stopped = _endpoint_group_has_no_live_members(
                                endpoint.pid
                            )
                        except Exception:
                            group_stopped = False
                        if not group_stopped:
                            self._record_failure("bridge_shutdown_failed")
                            graceful = False
                    if not graceful:
                        self._metrics.update(endpoint_forced_cleanup=True)
                        _stop_endpoint(endpoint, self.limits.shutdown_timeout_seconds)
                    else:
                        # The relay already observed EOF on both pipes and reaped
                        # a natural exit0. Signalling cleanup is not that proof.
                        for stream in (
                            endpoint.stdin,
                            endpoint.stdout,
                            endpoint.stderr,
                        ):
                            if stream is not None:
                                stream.close()
                        self._client_completion_confirmed = True
                    if self._endpoint_process_metadata is not None:
                        self._endpoint_process_metadata.update(
                            reaped=True,
                            process_group_stopped=True,
                            finished_at_utc=time.time(),
                            finished_monotonic=time.monotonic(),
                            returncode=endpoint.returncode,
                            natural_exit_confirmed=graceful,
                        )
                except Exception:
                    self._record_failure("bridge_shutdown_failed")
                finally:
                    self._metrics.update(
                        endpoint_returncode=endpoint.poll(),
                        endpoint_cleanup_elapsed_seconds=time.monotonic()
                        - cleanup_started,
                    )
                    if self._endpoint_process_metadata is not None:
                        started = self._endpoint_process_metadata["started_monotonic"]
                        assert isinstance(started, float)
                        self._metrics.update(
                            endpoint_elapsed_seconds=time.monotonic() - started
                        )
            if peer is not None:
                peer.close()
            self._done.set()

    def wait(self, timeout: float | None = None) -> bool:
        if timeout is None:
            timeout = (
                self.limits.connect_timeout_seconds
                + self.limits.auth_timeout_seconds
                + self.limits.session_timeout_seconds
                + 3 * self.limits.shutdown_timeout_seconds
                + 3
            )
        return self._done.wait(timeout)

    def finish_client(self) -> None:
        """Request bounded graceful drain before the caller cleans client children."""
        if self._completion_probe is None:
            self._record_failure("bridge_completion_unavailable")
        elif not self._done.is_set():
            self._finish_requested.set()
            if not self._done.wait(self.limits.shutdown_timeout_seconds + 3):
                self._record_failure("bridge_shutdown_timeout")
        self.close()
        if self._failure_label is not None:
            raise BridgeError(self._failure_label)
        if not self.client_completion_confirmed:
            self._record_failure("bridge_completion_unconfirmed")
            raise BridgeError("bridge_completion_unconfirmed")

    def close(self) -> None:
        self._stop.set()
        self._process_cleanup_confirmed = False
        self._resources_cleanup_confirmed = False
        failure: str | None = None
        if self._thread is not None:
            # Endpoint waits and its final group confirmation are bounded
            # separately; leave room for the helper's two-second query.
            self._thread.join(3 * self.limits.shutdown_timeout_seconds + 3)
            if self._thread.is_alive():
                self._record_failure("bridge_shutdown_failed")
                failure = "bridge_shutdown_failed"
        else:
            self._done.set()
        self._process_cleanup_confirmed = (
            self._thread is None or not self._thread.is_alive()
        ) and (
            self._endpoint_process_metadata is None
            or (
                self._endpoint_process_metadata.get("reaped") is True
                and self._endpoint_process_metadata.get("process_group_stopped") is True
            )
        )
        if self._listener is not None:
            self._listener.close()
        resources_removed = True
        for path in self.cleanup_paths:
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass
            except OSError:
                resources_removed = False
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                resources_removed = False
            else:
                resources_removed = False
        self._resources_cleanup_confirmed = resources_removed and (
            self._listener is None or self._listener.fileno() == -1
        )
        if not self._resources_cleanup_confirmed:
            self._record_failure("bridge_cleanup_failed")
            failure = "bridge_cleanup_failed"
        self._secret = b""
        if failure is not None:
            raise BridgeError(failure)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _proxy_credentials(
    path: Path,
) -> tuple[str, bytes, BridgeLimits, Path, Path, Path | None]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size > 4096
        ):
            raise BridgeError("bridge_invalid_credential")
        payload = json.loads(stream.read(4097))
    if not isinstance(payload, dict) or set(payload) != {
        "secret",
        "socket",
        "limits",
        "proxy_home",
        "proxy_tmp",
        "credential_canary",
    }:
        raise BridgeError("bridge_invalid_credential")
    secret, address, raw_limits = (
        payload["secret"],
        payload["socket"],
        payload["limits"],
    )
    if (
        not isinstance(secret, str)
        or len(secret) != 2 * SECRET_BYTES
        or not isinstance(address, str)
        or not Path(address).is_absolute()
        or not isinstance(raw_limits, dict)
        or set(raw_limits) != {field.name for field in fields(BridgeLimits)}
    ):
        raise BridgeError("bridge_invalid_credential")
    limits = BridgeLimits(**raw_limits)
    limits.validate()
    home, temporary, canary = (
        payload["proxy_home"],
        payload["proxy_tmp"],
        payload["credential_canary"],
    )
    if (
        not isinstance(home, str)
        or not Path(home).is_absolute()
        or not isinstance(temporary, str)
        or not Path(temporary).is_absolute()
        or (
            canary is not None
            and (not isinstance(canary, str) or not Path(canary).is_absolute())
        )
    ):
        raise BridgeError("bridge_invalid_credential")
    return (
        address,
        bytes.fromhex(secret),
        limits,
        Path(home),
        Path(temporary),
        Path(canary) if canary is not None else None,
    )


def _isolated_proxy_environment(home: Path, temporary: Path) -> bool:
    expected = {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "PATH": "/usr/bin:/bin",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    }
    # The native runtime can add its own text-encoding marker. No inherited
    # application environment, account credential, or client home is accepted.
    if set(os.environ) - set(expected) - {"__CF_USER_TEXT_ENCODING"}:
        return False
    if any(os.environ.get(key) != value for key, value in expected.items()):
        return False
    try:
        for directory in (home, temporary):
            metadata = directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()
                or any(directory.iterdir())
            ):
                return False
        os.chdir(home)
    except OSError:
        return False
    return True


def _canary_read_status(path: Path | None) -> int:
    if path is None:
        return CANARY_NOT_REQUESTED
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            return CANARY_DENIED
        return CANARY_UNCONFIRMED
    os.close(descriptor)
    return CANARY_READABLE


def _proxy_main(credential: Path) -> int:
    peer: socket.socket | None = None
    try:
        address, secret, limits, home, temporary, canary = _proxy_credentials(
            credential
        )
        stop = threading.Event()
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(limits.connect_timeout_seconds)
        peer.connect(address)  # Exactly one attempt; never reconnect or fall back.
        auth_presence = sum(
            1 << index
            for index, key in enumerate(AUTH_ENVIRONMENT_KEYS)
            if key in os.environ
        )
        environment_isolated = _isolated_proxy_environment(home, temporary)
        canary_status = _canary_read_status(canary)
        peer.sendall(
            AUTH_MAGIC
            + secret
            + bytes([auth_presence, int(environment_isolated), canary_status])
        )
        if _receive_exact(peer, 1, limits.auth_timeout_seconds, stop) != b"\x01":
            raise BridgeError("bridge_authentication_failed")
        _relay(peer, sys.stdin.fileno(), sys.stdout.fileno(), limits, stop)
        return 0
    except Exception:
        if peer is not None:
            _send_status(peer, ERROR)
        # The parent retains a fixed label. Client stderr never receives paths,
        # subprocess errors, endpoint stderr, or transported message content.
        return 1
    finally:
        if peer is not None:
            peer.close()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--proxy":
        raise SystemExit(2)
    raise SystemExit(_proxy_main(Path(sys.argv[2])))
