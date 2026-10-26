"""Bounded native completion evidence shared by proof and trial execution.

Only the controller reads these client events. Transcripts and final text stay
in its private files; public metadata contains counters and fixed labels only.
"""

from __future__ import annotations

import array
import contextlib
import fcntl
import hashlib
import json
import os
import select
import signal
import subprocess
import termios
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, cast


class LifecycleError(Exception):
    """One fixed label without client output or process arguments."""


def implementation_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise LifecycleError("client_malformed_json")
        result[name] = value
    return result


def _constant(_value: str) -> object:
    raise LifecycleError("client_malformed_json")


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise LifecycleError("client_malformed_event")
    return cast(dict[str, object], value)


def _identity(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise LifecycleError("client_malformed_event")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise LifecycleError("client_malformed_event") from None
    return value


def _capture(target: BinaryIO, data: bytes) -> None:
    if not data:
        return
    try:
        if target.write(data) != len(data):
            raise LifecycleError("client_output_capture_failed")
        target.flush()
        os.fsync(target.fileno())
    except OSError, ValueError:
        raise LifecycleError("client_output_capture_failed") from None


def _sync_created_capture(descriptor: int, path: Path) -> None:
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class CompletionSnapshot:
    """One immutable observation; later output can never improve this result."""

    confirmed: bool
    observed_monotonic: float
    terminal_observed_monotonic: float | None
    event_count: int | None
    stdout_bytes: int | None
    partial_json_bytes: int | None
    already_available_bytes: int | None
    synchronously_read_bytes: int | None
    failure_label: str | None
    cutoff_source: str
    validated_monotonic: float


@dataclass(frozen=True)
class _ReadReservation:
    prefix: bytes
    prefix_available_monotonic: float | None
    count: int
    available_monotonic: float
    completed: Future[bytes]


@dataclass(frozen=True)
class _FrozenStdout:
    data: bytes
    available_monotonic: float | None
    already_available_bytes: int
    synchronously_read_bytes: int
    source: str
    failure_label: str | None = None


class ClientLifecycle:
    """Own one private JSON stream, completion snapshot and native process."""

    def __init__(self, events_path: Path, *, max_bytes: int = 1024 * 1024) -> None:
        if (
            not events_path.is_absolute()
            or type(max_bytes) is not int
            or not 1024 <= max_bytes <= 64 * 1024 * 1024
        ):
            raise LifecycleError("client_lifecycle_invalid")
        self.events_path = events_path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._snapshot_lock = threading.Lock()
        self._observation_lock = threading.Lock()
        self._observed_stdout = b""
        self._observed_stdout_bytes = 0
        self._observed_available_monotonic: float | None = None
        self._observed_stdout_eof = False
        self._observation_failure: str | None = None
        self._read_reservation: _ReadReservation | None = None
        self._pending_stdout: deque[bytes] = deque()
        self._fd: int | None = None
        self._target: BinaryIO | None = None
        self._stdout_closed = False
        self._stderr_closed = False
        self._stdout_bytes = 0
        self._stderr_bytes = 0
        self._buffer = bytearray()
        self._failure: str | None = None
        self._event_count = 0
        self._thread_seen = False
        self._turn_started = False
        self._turn_completed = False
        self._active_items: dict[str, str] = {}
        self._completed_items: set[str] = set()
        self._final_text: str | None = None
        self._last_completed_kind: str | None = None
        self._terminal_monotonic: float | None = None
        self._snapshot: CompletionSnapshot | None = None
        self._used = False
        self._native_exit: int | None = None
        self._natural_exit = False
        self._process_cleanup = False
        self._client_completed = False
        self._process: dict[str, object] = {}
        self._transport: Mapping[str, object] | None = None
        self._recovery_json: bytes | None = None

    def _fail(self, label: str) -> None:
        self._failure = self._failure or label

    @property
    def failure_label(self) -> str | None:
        with self._lock:
            return self._failure

    @property
    def natural_exit_zero(self) -> bool:
        with self._lock:
            return self._natural_exit and self._native_exit == 0

    @property
    def client_completion_confirmed(self) -> bool:
        with self._lock:
            return self._client_completed

    def record_transport(self, value: Mapping[str, object]) -> None:
        with self._lock:
            self._transport = dict(value)

    def record_recovery(self, value: Mapping[str, object]) -> None:
        """Retain only caller-owned recovery context, never in public metadata."""
        try:
            encoded = json.dumps(
                dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True
            ).encode("utf-8")
        except TypeError, ValueError, UnicodeError:
            raise LifecycleError("client_recovery_metadata_invalid") from None
        if len(encoded) > 65536:
            raise LifecycleError("client_recovery_metadata_invalid")
        with self._lock:
            self._recovery_json = encoded

    def private_recovery_metadata(self) -> Mapping[str, object] | None:
        with self._lock:
            if self._recovery_json is None:
                return None
            return cast(dict[str, object], json.loads(self._recovery_json))

    def metadata(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema": "memory.behavioral-client-lifecycle.v1",
                "failure_label": self._failure,
                "client_completion_confirmed": self._client_completed,
                "natural_exit": self._natural_exit,
                "native_exit_status": self._native_exit,
                "process_cleanup_confirmed": self._process_cleanup,
                "stdout_fully_drained": self._stdout_closed,
                "stderr_fully_drained": self._stderr_closed,
                "stdout_raw_bytes": self._stdout_bytes,
                "stderr_raw_bytes": self._stderr_bytes,
                "stdout_truncated": self._stdout_bytes > self.max_bytes,
                "stderr_truncated": self._stderr_bytes > self.max_bytes,
                "event_count": self._event_count,
                "thread_started": self._thread_seen,
                "turn_started": self._turn_started,
                "turn_completed": self._turn_completed,
                "pending_items": len(self._active_items),
                "partial_json_bytes": len(self._buffer),
                "final_answer_bytes": (
                    len(self._final_text.encode("utf-8"))
                    if self._final_text is not None
                    else 0
                ),
                "completion_at_peer_eof": (
                    asdict(self._snapshot) if self._snapshot is not None else None
                ),
                "process": dict(self._process),
                "transport": dict(self._transport)
                if self._transport is not None
                else None,
            }

    def _event(self, value: Mapping[str, object]) -> None:
        kind = value.get("type")
        if not isinstance(kind, str):
            raise LifecycleError("client_malformed_event")
        self._event_count += 1
        if self._event_count > 8192:
            raise LifecycleError("client_event_limit")
        if kind in {"error", "turn.failed"}:
            raise LifecycleError("client_reported_error")
        if kind in {"item.started", "item.updated", "item.completed"}:
            item = _mapping(value.get("item"))
            if item.get("type") == "error":
                raise LifecycleError("client_reported_error")
        if self._turn_completed:
            raise LifecycleError("client_event_after_completion")
        if kind == "thread.started":
            _identity(value.get("thread_id"))
            if self._thread_seen or self._turn_started:
                raise LifecycleError("client_event_order")
            self._thread_seen = True
            return
        if not self._thread_seen:
            raise LifecycleError("client_event_order")
        if kind == "turn.started":
            if self._turn_started:
                raise LifecycleError("client_event_order")
            self._turn_started = True
            return
        if not self._turn_started:
            raise LifecycleError("client_event_order")
        if kind == "turn.completed":
            if (
                self._active_items
                or self._last_completed_kind != "agent_message"
                or self._final_text is None
                or not self._final_text.strip()
            ):
                raise LifecycleError("client_final_answer_unconfirmed")
            self._turn_completed = True
            self._terminal_monotonic = time.monotonic()
            return
        if kind not in {"item.started", "item.updated", "item.completed"}:
            raise LifecycleError("client_unexpected_event")
        item = _mapping(value.get("item"))
        identity, item_kind = _identity(item.get("id")), _identity(item.get("type"))
        if identity in self._completed_items:
            raise LifecycleError("client_event_order")
        if kind == "item.started":
            if identity in self._active_items:
                raise LifecycleError("client_event_order")
            self._active_items[identity] = item_kind
            self._last_completed_kind = None
            return
        active_kind = self._active_items.get(identity)
        if active_kind is not None and active_kind != item_kind:
            raise LifecycleError("client_event_order")
        if kind == "item.updated":
            if active_kind is None:
                raise LifecycleError("client_event_order")
            return
        self._active_items.pop(identity, None)
        self._completed_items.add(identity)
        self._last_completed_kind = item_kind
        if item_kind == "agent_message":
            text = item.get("text")
            if not isinstance(text, str):
                raise LifecycleError("client_malformed_event")
            try:
                text.encode("utf-8")
            except UnicodeError:
                raise LifecycleError("client_malformed_event") from None
            self._final_text = text

    def _append_stdout(self, data: bytes) -> None:
        before = self._stdout_bytes
        self._stdout_bytes += len(data)
        assert self._target is not None
        if before < self.max_bytes:
            _capture(self._target, data[: self.max_bytes - before])
        if self._stdout_bytes > self.max_bytes:
            self._fail("client_output_limit")
        self._parse_stdout(data)

    def _parse_stdout(self, data: bytes) -> None:
        if self._failure is not None:
            return
        self._buffer.extend(data)
        while (index := self._buffer.find(b"\n")) >= 0:
            line = bytes(self._buffer[:index])
            del self._buffer[: index + 1]
            try:
                parsed: object = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=_object,
                    parse_constant=_constant,
                )
                self._event(_mapping(parsed))
            except LifecycleError as error:
                self._fail(str(error))
                break
            except ValueError, UnicodeError, RecursionError:
                self._fail("client_malformed_json")
                break

    def _available_stdout(self) -> int:
        assert self._fd is not None
        count = array.array("i", [0])
        fcntl.ioctl(self._fd, termios.FIONREAD, count, True)
        if count[0] < 0:
            raise LifecycleError("client_completion_snapshot_failed")
        return count[0]

    def _observe_stdout(
        self, available: int | None = None, *, observed: float | None = None
    ) -> int:
        """Reserve only bytes already present, then publish them before ingestion.

        The observation lock protects this bounded nonblocking pipe operation,
        never disk writes or parsing. A contending EOF observer can retain this
        immutable reservation and wait for only its already-present bytes.
        """
        assert self._fd is not None
        if available is None:
            available = min(65536, self._available_stdout())
        timestamp = time.monotonic() if observed is None else observed
        reservation = _ReadReservation(
            self._observed_stdout,
            self._observed_available_monotonic,
            available,
            timestamp,
            Future(),
        )
        self._read_reservation = reservation
        try:
            data = os.read(self._fd, available or 65536)
        except BlockingIOError:
            reservation.completed.set_result(b"")
            return 0
        except OSError, ValueError:
            self._observation_failure = "client_output_capture_failed"
            reservation.completed.set_exception(
                LifecycleError("client_output_capture_failed")
            )
            raise
        if data:
            self._observed_stdout_bytes += len(data)
            self._observed_stdout = (self._observed_stdout + data)[: self.max_bytes]
            self._observed_available_monotonic = (
                timestamp if available else time.monotonic()
            )
            self._pending_stdout.append(data)
            if self._observed_stdout_bytes > self.max_bytes:
                self._observation_failure = "client_output_limit"
        else:
            self._observed_stdout_eof = True
        reservation.completed.set_result(data)
        return len(data)

    def _drain_stdout(self, source: BinaryIO, target: BinaryIO) -> None:
        descriptor = source.fileno()
        os.set_blocking(descriptor, False)
        with self._observation_lock:
            self._fd, self._target = descriptor, target
        try:
            while True:
                with self._observation_lock:
                    if not self._pending_stdout and not self._observed_stdout_eof:
                        self._observe_stdout()
                    data = (
                        self._pending_stdout.popleft() if self._pending_stdout else None
                    )
                    ended = self._observed_stdout_eof
                if data is not None:
                    with self._lock:
                        self._append_stdout(data)
                elif ended:
                    with self._lock:
                        if self._buffer:
                            self._fail("client_incomplete_json")
                        self._stdout_closed = True
                        target.flush()
                        os.fsync(target.fileno())
                        return
                else:
                    select.select([descriptor], [], [], 0.02)
        except Exception:
            with self._lock:
                self._fail("client_output_capture_failed")
            raise
        finally:
            source.close()

    def _drain_stderr(self, source: BinaryIO, target: BinaryIO) -> None:
        try:
            while data := os.read(source.fileno(), 65536):
                with self._lock:
                    before = self._stderr_bytes
                    self._stderr_bytes += len(data)
                    if self._stderr_bytes > self.max_bytes:
                        self._fail("client_output_limit")
                if before < self.max_bytes:
                    _capture(target, data[: self.max_bytes - before])
            target.flush()
            os.fsync(target.fileno())
            with self._lock:
                self._stderr_closed = True
        except Exception:
            with self._lock:
                self._fail("client_output_capture_failed")
            raise
        finally:
            source.close()

    def completion_probe(self) -> bool:
        """Validate one immutable pre-EOF byte cutoff independently of ingestion."""
        observed = time.monotonic()
        with self._snapshot_lock:
            if self._snapshot is not None:
                return self._snapshot.confirmed
            frozen = self._freeze_stdout(observed)
            # This parser instance never opens a file or launches a process.
            # Reusing the same parser prevents proof/trial acceptance drift.
            parser = ClientLifecycle(self.events_path, max_bytes=self.max_bytes)
            parser._parse_stdout(frozen.data)
            failure = frozen.failure_label or parser._failure
            confirmed = (
                failure is None
                and parser._turn_completed
                and not parser._buffer
                and not parser._active_items
                and parser._final_text is not None
                and bool(parser._final_text.strip())
            )
            self._snapshot = CompletionSnapshot(
                confirmed,
                observed,
                frozen.available_monotonic if parser._turn_completed else None,
                parser._event_count,
                len(frozen.data),
                len(parser._buffer),
                frozen.already_available_bytes,
                frozen.synchronously_read_bytes,
                failure
                if failure is not None or confirmed
                else "client_completion_unconfirmed",
                frozen.source,
                time.monotonic(),
            )
            return confirmed

    def _freeze_stdout(self, observed: float) -> _FrozenStdout:
        if self._observation_lock.acquire(blocking=False):
            try:
                return self._freeze_available_stdout()
            finally:
                self._observation_lock.release()
        reservation = self._read_reservation
        source = "pre_eof_read_reservation"
        if reservation is None or reservation.available_monotonic > observed:
            return _FrozenStdout(
                b"", None, 0, 0, source, "client_completion_snapshot_raced"
            )
        if len(reservation.prefix) + reservation.count > self.max_bytes:
            return _FrozenStdout(b"", None, 0, 0, source, "client_output_limit")
        if reservation.count == 0:
            return _FrozenStdout(
                reservation.prefix,
                reservation.prefix_available_monotonic,
                0,
                0,
                source,
            )
        try:
            # Waiting cannot extend this already-present, fixed-length prefix.
            # A timeout only rejects it; later reads are never consulted.
            data = reservation.completed.result(timeout=5)
            if len(data) != reservation.count:
                raise LifecycleError("client_completion_snapshot_failed")
            return _FrozenStdout(
                reservation.prefix + data,
                reservation.available_monotonic,
                reservation.count,
                0,
                source,
            )
        except LifecycleError, TimeoutError:
            return _FrozenStdout(
                b"", None, 0, 0, source, "client_completion_snapshot_failed"
            )

    def _freeze_available_stdout(self) -> _FrozenStdout:
        source = "observed_prefix_and_kernel_bytes"
        available = received = 0
        failure = self._observation_failure
        try:
            if self._fd is None:
                raise LifecycleError("client_completion_snapshot_failed")
            if failure is None and not self._observed_stdout_eof:
                available = self._available_stdout()
                if available > self.max_bytes - self._observed_stdout_bytes:
                    raise LifecycleError("client_output_limit")
                cutoff = time.monotonic()
                while received < available:
                    count = self._observe_stdout(
                        min(65536, available - received), observed=cutoff
                    )
                    if not count:
                        break
                    received += count
                if received != available:
                    raise LifecycleError("client_completion_snapshot_failed")
        except LifecycleError as error:
            failure = str(error)
        except OSError, ValueError:
            failure = "client_completion_snapshot_failed"
        return _FrozenStdout(
            self._observed_stdout,
            self._observed_available_monotonic,
            available,
            received,
            source,
            failure,
        )

    def _write_answer(self, path: Path) -> None:
        with self._lock:
            text = self._final_text if self._turn_completed else None
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            if text is not None:
                stream.write((text + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())

    def run(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        input_text: str | None,
        response_path: Path,
        stderr_path: Path,
        timeout: float,
        before_cleanup: Callable[[], None] | None = None,
    ) -> tuple[int, str | None]:
        """Execute one native client and retain complete teardown evidence."""
        with self._lock:
            if self._used:
                raise LifecycleError("client_lifecycle_consumed")
            self._used = True
        stdout_descriptor = os.open(
            self.events_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        stderr_descriptor: int | None = None
        try:
            _sync_created_capture(stdout_descriptor, self.events_path)
            stderr_descriptor = os.open(
                stderr_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            _sync_created_capture(stderr_descriptor, stderr_path)
        except BaseException:
            os.close(stdout_descriptor)
            if stderr_descriptor is not None:
                os.close(stderr_descriptor)
            raise
        with (
            os.fdopen(stdout_descriptor, "wb", buffering=0) as stdout_file,
            os.fdopen(stderr_descriptor, "wb", buffering=0) as stderr_file,
        ):
            try:
                started_utc, started = time.time(), time.monotonic()
                process = subprocess.Popen(
                    list(command),
                    close_fds=True,
                    cwd=cwd,
                    env=dict(environment),
                    stdin=subprocess.PIPE
                    if input_text is not None
                    else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError:
                with self._lock:
                    self._fail("client_launch_failed")
                return 1, self.failure_label
            with self._lock:
                self._process = {
                    "pid": process.pid,
                    "pgid": process.pid,
                    "started_at_utc": started_utc,
                    "started_monotonic": started,
                    "reaped": False,
                    "process_group_stopped": False,
                }
            errors: list[Exception] = []
            threads: list[threading.Thread] = []
            status = 1

            def drain(
                function: Callable[[BinaryIO, BinaryIO], None],
                source: BinaryIO,
                target: BinaryIO,
            ) -> None:
                try:
                    function(source, target)
                except Exception as error:
                    errors.append(error)

            try:
                assert process.stdout is not None and process.stderr is not None
                for function, source, target in (
                    (self._drain_stdout, process.stdout, stdout_file),
                    (self._drain_stderr, process.stderr, stderr_file),
                ):
                    thread = threading.Thread(
                        target=drain, args=(function, source, target), daemon=True
                    )
                    threads.append(thread)
                    thread.start()
                if input_text is not None:
                    assert process.stdin is not None
                    client_input = process.stdin

                    def write_input() -> None:
                        try:
                            client_input.write(input_text.encode("utf-8"))
                            client_input.flush()
                        except BrokenPipeError:
                            pass
                        except OSError as error:
                            errors.append(error)
                        finally:
                            client_input.close()

                    thread = threading.Thread(target=write_input, daemon=True)
                    threads.append(thread)
                    thread.start()
                try:
                    status = process.wait(timeout=timeout)
                    with self._lock:
                        self._natural_exit = True
                        self._native_exit = status
                        self._process.update(
                            natural_exit_monotonic=time.monotonic(),
                            natural_exit_status=status,
                        )
                        if status != 0:
                            self._fail("client_exit_nonzero")
                except subprocess.TimeoutExpired:
                    with self._lock:
                        self._fail("client_timeout")
                except OSError, subprocess.SubprocessError:
                    with self._lock:
                        self._fail("client_wait_failed")
            except BaseException:
                with self._lock:
                    self._fail("client_interrupted")
                raise
            finally:
                try:
                    if before_cleanup is not None:
                        before_cleanup()
                except Exception:
                    with self._lock:
                        self._fail("client_transport_failed")
                finally:
                    stopped = _kill_and_reap(process)
                    for thread in threads:
                        if thread.ident is not None:
                            thread.join(timeout=5)
                    drained = all(not thread.is_alive() for thread in threads)
                    streams = (process.stdin, process.stdout, process.stderr)
                    if drained:
                        for stream in streams:
                            if stream is not None:
                                with contextlib.suppress(OSError):
                                    stream.close()
                    streams_closed = all(
                        stream is None or stream.closed for stream in streams
                    )
                    with self._lock:
                        self._process_cleanup = stopped and drained and streams_closed
                        self._process.update(
                            reaped=process.poll() is not None,
                            process_group_stopped=stopped,
                            capture_threads_stopped=drained,
                            process_streams_closed=streams_closed,
                            cleanup_finished_monotonic=time.monotonic(),
                            cleanup_exit_status=process.returncode,
                        )
                        if not self._process_cleanup:
                            self._fail("client_teardown_unverified")
            with self._lock:
                if errors:
                    self._fail("client_output_capture_failed")
                if not (
                    self._natural_exit
                    and status == 0
                    and self._process_cleanup
                    and self._stdout_closed
                    and self._stderr_closed
                    and self._turn_completed
                    and self._final_text is not None
                    and bool(self._final_text.strip())
                    and not self._buffer
                    and (self._snapshot is None or self._snapshot.confirmed)
                ):
                    self._fail(
                        self._snapshot.failure_label
                        if self._snapshot is not None
                        and self._snapshot.failure_label is not None
                        else "client_completion_unconfirmed"
                    )
                self._client_completed = self._failure is None
        try:
            self._write_answer(response_path)
        except OSError:
            with self._lock:
                self._fail("client_answer_capture_failed")
                self._client_completed = False
        return status, self.failure_label


def _kill_and_reap(process: subprocess.Popen[bytes]) -> bool:
    from behavioral_process_cleanup import group_has_no_live_members

    signalled = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        signalled = group_has_no_live_members(process.pid)
    except OSError:
        signalled = False
    if not signalled:
        with contextlib.suppress(OSError):
            process.kill()
    try:
        process.wait(timeout=5)
    except OSError, subprocess.SubprocessError:
        return False
    if not signalled:
        return False
    deadline = time.monotonic() + 5
    while not group_has_no_live_members(process.pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True
