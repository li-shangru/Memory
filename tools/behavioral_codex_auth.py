"""A fresh, serialized ChatGPT login with opaque file-credential custody.

Only a newly allocated task scope is accepted. The controller checks metadata and
the installed client's ordinary login status; it never parses credential bytes.
An interrupted login or lease cannot recover, borrow a cache, or replay a trial.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal, cast

AUTHENTICATION_MODE = "chatgpt_subscription"
SESSION_FILENAME = "session.private.json"
SESSION_SCHEMA = "memory.behavioral-subscription-session.v1"
SCOPE_PREFIX = "memory-subscription-auth-"
MAX_MARKER_BYTES = 8192
MAX_CREDENTIAL_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 65536
STATUS_TIMEOUT_SECONDS = 8
PUBLIC_CA_FILENAME = "public-ca.pem"
MAX_PUBLIC_CA_BYTES = 2 * 1024 * 1024


class AuthError(Exception):
    """A fixed public failure label without private paths or credential bytes."""


def _validate_public_ca(content: bytes) -> None:
    boundary = b"-" * 5
    begin = boundary + b"BEGIN CERTIFICATE" + boundary
    end = boundary + b"END CERTIFICATE" + boundary
    fragments = content.split(begin)
    count = len(fragments) - 1
    if (
        count == 0
        or content.count(boundary + b"BEGIN") != count
        or content.count(boundary + b"END") != count
    ):
        raise AuthError("subscription_public_ca_invalid")
    try:
        # This starts with an empty certificate store. Validate each supplied
        # block without loading default roots or silently skipping a bad block.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for fragment in fragments[1:]:
            encoded, closing, _ = fragment.partition(end)
            if not closing:
                raise AuthError("subscription_public_ca_invalid")
            context.load_verify_locations(
                cadata=(begin + encoded + end).decode("ascii")
            )
    except OSError, ValueError, UnicodeError:
        raise AuthError("subscription_public_ca_invalid") from None


def _ca_bytes(path: Path, *, system: bool) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != (0 if system else os.getuid())
                or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_PUBLIC_CA_BYTES
                or (
                    info.st_mode & 0o022
                    if system
                    else stat.S_IMODE(info.st_mode) != 0o600
                )
            ):
                raise AuthError("subscription_public_ca_invalid")
            content = stream.read(MAX_PUBLIC_CA_BYTES + 1)
            after = os.fstat(stream.fileno())
            # A permitted read can update atime. Identity, permissions, links,
            # size and modification/change timestamps must remain unchanged.
            if (
                len(content) != info.st_size
                or info[:7] != after[:7]
                or info.st_mtime_ns != after.st_mtime_ns
                or info.st_ctime_ns != after.st_ctime_ns
            ):
                raise AuthError("subscription_public_ca_changed")
            _validate_public_ca(content)
            return content, info
    except OSError:
        raise AuthError("subscription_public_ca_unavailable") from None


def _system_public_ca() -> bytes:
    # This public OS file is the only source. Never select a caller's CA path,
    # a saved client configuration, or a filesystem/daemon Keychain store.
    content, _ = _ca_bytes(Path("/private/etc/ssl/cert.pem"), system=True)
    return content


def public_ca_digest() -> str:
    """Bind only the explicitly selected, validated public system PEM bytes."""
    return hashlib.sha256(_system_public_ca()).hexdigest()


def _write_public_ca(root: Path, content: bytes) -> Path:
    path = root / PUBLIC_CA_FILENAME
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _sync_directory(root)
        return path
    except OSError:
        raise AuthError("subscription_public_ca_unavailable") from None


def pin_public_ca_bundle(root: Path) -> Path:
    """Pin the same public PEM in a fresh private synthetic proof directory."""
    root = _safe_path(root)
    _private_directory(root)
    return _write_public_ca(root, _system_public_ca())


def _check_public_ca(root: Path, record: Mapping[str, object]) -> None:
    content, info = _ca_bytes(root / PUBLIC_CA_FILENAME, system=False)
    if (
        record.get("public_ca_bundle_digest") != hashlib.sha256(content).hexdigest()
        or record.get("public_ca_bundle_digest") != public_ca_digest()
        or record.get("public_ca_device") != info.st_dev
        or record.get("public_ca_inode") != info.st_ino
    ):
        raise AuthError("subscription_public_ca_changed")


def implementation_digest() -> str:
    tools_root = Path(__file__).resolve().parent
    if str(tools_root) not in sys.path:
        sys.path.insert(0, str(tools_root))
    from behavioral_process_cleanup import implementation_digest as cleanup_digest

    try:
        binding = {
            "authentication_source": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "process_policy_source": hashlib.sha256(
                (tools_root / "behavioral_codex_isolation.py").read_bytes()
            ).hexdigest(),
            "process_cleanup": cleanup_digest(),
        }
    except OSError:
        raise AuthError("subscription_adapter_unavailable") from None
    return hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _client_digest(client: Path) -> str:
    try:
        digest = hashlib.sha256()
        with client.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        raise AuthError("subscription_client_unavailable") from None


def _safe_path(path: Path) -> Path:
    # Reject owner/default paths before resolving or looking up their metadata.
    roots = (
        Path("/private/tmp"),
        Path("/tmp"),
        Path("/private/var/folders"),
        Path("/var/folders"),
    )
    if (
        not path.is_absolute()
        or ".." in path.parts
        or not any(path.is_relative_to(root) for root in roots)
    ):
        raise AuthError("subscription_session_invalid")
    try:
        resolved = path.resolve(strict=True)
        if not any(resolved.is_relative_to(root) for root in roots):
            raise AuthError("subscription_session_invalid")
        return resolved
    except OSError, RuntimeError:
        raise AuthError("subscription_session_invalid") from None


def _private_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise AuthError("subscription_session_invalid")
        return info
    except OSError:
        raise AuthError("subscription_session_invalid") from None


def _private_file(path: Path, *, maximum: int, label: str) -> os.stat_result:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or not 0 < info.st_size <= maximum
        ):
            raise AuthError(label)
        return info
    except OSError:
        raise AuthError(label) from None


def _credential(home: Path) -> Path:
    path = home / "auth.json"
    _private_file(
        path, maximum=MAX_CREDENTIAL_BYTES, label="subscription_credential_invalid"
    )
    return path


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_record(root: Path, record: Mapping[str, object]) -> None:
    target = root / SESSION_FILENAME
    temporary = root / (".session-" + secrets.token_hex(16))
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _sync_directory(root)
    except OSError:
        raise AuthError("subscription_session_unavailable") from None
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _record(root: Path, client: Path) -> dict[str, object]:
    info = _private_directory(root)
    marker = root / SESSION_FILENAME
    _private_file(
        marker, maximum=MAX_MARKER_BYTES, label="subscription_session_invalid"
    )

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value: object = json.loads(
            marker.read_text(encoding="utf-8"), object_pairs_hook=pairs
        )
        if not isinstance(value, dict):
            raise ValueError
        record = cast(dict[str, object], value)
    except OSError, ValueError, UnicodeError:
        raise AuthError("subscription_session_invalid") from None
    if (
        record.get("schema") != SESSION_SCHEMA
        or record.get("authentication_mode") != AUTHENTICATION_MODE
        or record.get("root_device") != info.st_dev
        or record.get("root_inode") != info.st_ino
        or not isinstance(record.get("session_id"), str)
        or len(cast(str, record.get("session_id"))) != 64
        or record.get("phase")
        not in ("created", "logging_in", "ready", "validating", "leased", "interrupted")
    ):
        raise AuthError("subscription_session_invalid")
    if record.get(
        "authentication_adapter_digest"
    ) != implementation_digest() or record.get(
        "client_executable_digest"
    ) != _client_digest(client):
        raise AuthError("subscription_session_changed")
    _private_directory(root / "home")
    _check_public_ca(root, record)
    return record


@dataclass(frozen=True)
class ScopedSession:
    root: Path
    home: Path
    client: Path
    session_id: str
    client_digest: str


def create_session(parent: Path, client: Path) -> ScopedSession:
    """Allocate a new empty task scope; never discover or import saved login."""
    parent = _safe_path(parent)
    public_ca = _system_public_ca()
    try:
        client = client.resolve(strict=True)
        if not client.is_file() or not os.access(client, os.X_OK):
            raise AuthError("subscription_client_unavailable")
        root = Path(tempfile.mkdtemp(prefix=SCOPE_PREFIX, dir=parent))
        public_ca_info = _write_public_ca(root, public_ca).lstat()
        for name in ("home", "workspace", "logs"):
            (root / name).mkdir(mode=0o700)
        (root / "session.lock").touch(mode=0o600, exist_ok=False)
        info = _private_directory(root)
        _write_record(
            root,
            {
                "schema": SESSION_SCHEMA,
                "authentication_mode": AUTHENTICATION_MODE,
                "session_id": secrets.token_hex(32),
                "root_device": info.st_dev,
                "root_inode": info.st_ino,
                "client_executable_digest": _client_digest(client),
                "authentication_adapter_digest": implementation_digest(),
                "public_ca_bundle_digest": hashlib.sha256(public_ca).hexdigest(),
                "public_ca_device": public_ca_info.st_dev,
                "public_ca_inode": public_ca_info.st_ino,
                "phase": "created",
            },
        )
        return load_session(root, client)
    except OSError, RuntimeError:
        raise AuthError("subscription_session_unavailable") from None


def load_session(root: Path, client: Path) -> ScopedSession:
    """Open only a caller-named fresh task scope with matching identity bytes."""
    if not root.name.startswith(SCOPE_PREFIX):
        raise AuthError("subscription_session_invalid")
    root = _safe_path(root)
    try:
        client = client.resolve(strict=True)
    except OSError, RuntimeError:
        raise AuthError("subscription_client_unavailable") from None
    record = _record(root, client)
    return ScopedSession(
        root,
        root / "home",
        client,
        cast(str, record["session_id"]),
        cast(str, record["client_executable_digest"]),
    )


class _SessionLock:
    def __init__(self, session: ScopedSession) -> None:
        self.descriptor: int | None = None
        if (
            not session.root.name.startswith(SCOPE_PREFIX)
            or _safe_path(session.root) != session.root
        ):
            raise AuthError("subscription_session_invalid")
        _private_directory(session.root)
        try:
            path = session.root / "session.lock"
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.descriptor = descriptor
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise AuthError("subscription_session_invalid")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.close()
            raise AuthError("subscription_auth_busy") from None
        except OSError:
            self.close()
            raise AuthError("subscription_session_unavailable") from None
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


def _checked(session: ScopedSession) -> dict[str, object]:
    if load_session(session.root, session.client) != session:
        raise AuthError("subscription_session_changed")
    return _record(session.root, session.client)


def _require_phase(record: Mapping[str, object], expected: str) -> None:
    phase = record.get("phase")
    if phase in ("logging_in", "validating", "leased", "interrupted"):
        raise AuthError("subscription_auth_interrupted")
    if phase != expected:
        raise AuthError("subscription_auth_not_ready")


def _environment(session: ScopedSession) -> dict[str, str]:
    return {
        "HOME": str(session.home),
        "CODEX_HOME": str(session.home),
        "TMPDIR": str(session.root),
        "PATH": "/usr/bin:/bin",
        "LANG": "en_US.UTF-8",
        "CODEX_CA_CERTIFICATE": str(session.root / PUBLIC_CA_FILENAME),
    }


def _arguments(session: ScopedSession) -> list[str]:
    return [
        str(session.client),
        "-c",
        'cli_auth_credentials_store="file"',
        "-c",
        'forced_login_method="chatgpt"',
        "-c",
        "analytics.enabled=false",
    ]


def _client_executables(client: Path, *, browser: bool) -> tuple[Path, ...]:
    return (client, Path("/usr/bin/open")) if browser else (client,)


def _status(session: ScopedSession) -> bool:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_codex_isolation import CapabilityProbeError, protected_command

    _checked(session)
    label = secrets.token_hex(16)
    output = session.root / "logs" / ("status-" + label + ".private.log")
    stopped = True
    try:
        command = protected_command(
            [*_arguments(session), "login", "status"],
            policy_path=session.root / ("status-" + label + ".sb"),
            executable_paths=_client_executables(session.client, browser=False),
            readable_proxy_files=(session.root / PUBLIC_CA_FILENAME,),
        )
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            process = subprocess.Popen(
                command,
                cwd=session.root / "workspace",
                env=_environment(session),
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=stream,
                start_new_session=True,
                umask=0o077,
            )
            stopped = False
            try:
                returncode = process.wait(timeout=STATUS_TIMEOUT_SECONDS)
            finally:
                _stop_login_process(process)
                stopped = True
        if returncode != 0 or output.stat().st_size > MAX_STATUS_BYTES:
            return False
        lines = output.read_text(encoding="utf-8").splitlines()
        return lines.count("Logged in using ChatGPT") == 1 and not any(
            "API key" in line for line in lines
        )
    except OSError, UnicodeError, subprocess.SubprocessError, CapabilityProbeError:
        return False
    finally:
        if stopped:
            with contextlib.suppress(OSError):
                output.unlink()


def validate_session(session: ScopedSession) -> None:
    lock = _SessionLock(session)
    validating = False
    try:
        record = _checked(session)
        _require_phase(record, "ready")
        _credential(session.home)
        record["phase"] = "validating"
        _write_record(session.root, record)
        validating = True
        if not _status(session):
            raise AuthError("subscription_login_unconfirmed")
        record = _checked(session)
        if record["phase"] != "validating":
            raise AuthError("subscription_auth_interrupted")
        _credential(session.home)
        record["phase"] = "ready"
        _write_record(session.root, record)
        validating = False
    except BaseException:
        if validating:
            record = _checked(session)
            record["phase"] = "interrupted"
            _write_record(session.root, record)
        raise
    finally:
        lock.close()


def _stop_login_process(process: subprocess.Popen[bytes]) -> None:
    from behavioral_codex_isolation import CapabilityProbeError, _stop_process

    try:
        _stop_process(process)
    except OSError, subprocess.SubprocessError, CapabilityProbeError:
        raise AuthError("subscription_login_cleanup_unconfirmed") from None


class LoginAttempt:
    def __init__(
        self,
        session: ScopedSession,
        lock: _SessionLock,
        process: subprocess.Popen[bytes],
        output_path: Path,
        deadline: float,
    ) -> None:
        self.session = session
        self.output_path = output_path
        self._lock = lock
        self._process = process
        self._deadline = deadline
        self._finished = False
        self._closed = False
        self._process_stopped = False

    def __enter__(self) -> LoginAttempt:
        return self

    def wait(self, timeout: float | None = None) -> bool:
        remaining = max(0.0, self._deadline - time.monotonic())
        if remaining == 0:
            raise AuthError("subscription_login_timeout")
        if timeout is not None:
            if not math.isfinite(timeout) or timeout < 0:
                raise AuthError("subscription_login_invalid")
            remaining = min(remaining, timeout)
        try:
            self._process.wait(timeout=remaining)
            return True
        except subprocess.TimeoutExpired:
            if time.monotonic() >= self._deadline:
                raise AuthError("subscription_login_timeout") from None
            return False

    def finish(self) -> None:
        if self._closed or self._finished or self._process.poll() != 0:
            raise AuthError("subscription_login_unconfirmed")
        _stop_login_process(self._process)
        self._process_stopped = True
        _credential(self.session.home)
        if not _status(self.session):
            raise AuthError("subscription_login_unconfirmed")
        record = _checked(self.session)
        if record["phase"] != "logging_in":
            raise AuthError("subscription_auth_interrupted")
        record["phase"] = "ready"
        _write_record(self.session.root, record)
        self._finished = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        tools_root = str(Path(__file__).resolve().parent)
        if tools_root not in sys.path:
            sys.path.insert(0, tools_root)
        try:
            if not self._process_stopped:
                _stop_login_process(self._process)
                self._process_stopped = True
            if not self._finished:
                record = _checked(self.session)
                record["phase"] = "interrupted"
                _write_record(self.session.root, record)
        except AuthError:
            record = _checked(self.session)
            record["phase"] = "interrupted"
            _write_record(self.session.root, record)
            raise
        finally:
            self._lock.close()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def start_login(
    session: ScopedSession,
    *,
    method: Literal["browser", "device"] = "browser",
    timeout_seconds: float = 300,
) -> LoginAttempt:
    """Run the installed client's normal sign-in into this new private scope."""
    if (
        method not in ("browser", "device")
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 600
    ):
        raise AuthError("subscription_login_invalid")
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_codex_isolation import CapabilityProbeError, login_command

    lock = _SessionLock(session)
    try:
        record = _checked(session)
        _require_phase(record, "created")
        record["phase"] = "logging_in"
        _write_record(session.root, record)
        command = [*_arguments(session), "login"]
        if method == "device":
            command.append("--device-auth")
        wrapped = login_command(
            command,
            policy_path=session.root / "login.sb",
            executable_paths=_client_executables(
                session.client, browser=method == "browser"
            ),
            callback_port=1455 if method == "browser" else None,
            public_ca_bundle=session.root / PUBLIC_CA_FILENAME,
        )
        output = session.root / "logs" / "login.private.log"
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            process = subprocess.Popen(
                wrapped,
                cwd=session.root / "workspace",
                env=_environment(session),
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=stream,
                start_new_session=True,
                umask=0o077,
            )
        return LoginAttempt(
            session, lock, process, output, time.monotonic() + timeout_seconds
        )
    except OSError, CapabilityProbeError:
        lock.close()
        raise AuthError("subscription_login_unavailable") from None
    except BaseException:
        lock.close()
        raise


class CredentialLease:
    def __init__(self, session: ScopedSession, client_home: Path) -> None:
        self.session = session
        self.client_home = client_home
        self.credential_homes = (session.root, client_home)
        self.credential_canary = client_home / "subscription-denial-canary"
        self.public_ca_bundle = session.root / PUBLIC_CA_FILENAME
        self._lock: _SessionLock | None = None
        self._completed = False

    def __enter__(self) -> CredentialLease:
        lock = _SessionLock(self.session)
        try:
            record = _checked(self.session)
            _require_phase(record, "ready")
            original = _credential(self.session.home)
            client_home = _safe_path(self.client_home)
            info = _private_directory(client_home)
            if (
                client_home != self.client_home
                or client_home.is_relative_to(self.session.root)
                or self.session.root.is_relative_to(client_home)
                or info.st_dev != original.stat().st_dev
                or next(client_home.iterdir(), None) is not None
            ):
                raise AuthError("subscription_client_home_invalid")
            descriptor = os.open(
                self.credential_canary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"fresh synthetic subscription denial canary")
            record.update(
                phase="leased",
                active_client_home=str(client_home),
                lease_id=secrets.token_hex(32),
            )
            _write_record(self.session.root, record)
            os.replace(original, client_home / "auth.json")
            _sync_directory(self.session.home)
            _sync_directory(client_home)
            self._lock = lock
            return self
        except OSError:
            lock.close()
            raise AuthError("subscription_credential_handoff_failed") from None
        except BaseException:
            lock.close()
            raise

    def complete(self) -> None:
        """The caller confirms every client, proxy and endpoint child has stopped."""
        if self._lock is None:
            raise AuthError("subscription_teardown_unconfirmed")
        self._completed = True

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        lock = self._lock
        if lock is None:
            return
        self._lock = None
        try:
            record = _checked(self.session)
            if record.get("phase") != "leased" or record.get(
                "active_client_home"
            ) != str(self.client_home):
                raise AuthError("subscription_auth_interrupted")
            if not self._completed:
                record["phase"] = "interrupted"
                _write_record(self.session.root, record)
                if exc is None:
                    raise AuthError("subscription_teardown_unconfirmed")
                return
            refreshed = _credential(self.client_home)
            original = self.session.home / "auth.json"
            if original.exists() or original.is_symlink():
                raise AuthError("subscription_credential_handoff_failed")
            os.replace(refreshed, original)
            _sync_directory(self.client_home)
            _sync_directory(self.session.home)
            record["phase"] = "ready"
            record.pop("active_client_home", None)
            record.pop("lease_id", None)
            _write_record(self.session.root, record)
        except OSError:
            raise AuthError("subscription_credential_handoff_failed") from None
        finally:
            lock.close()


def stage_credentials(session: ScopedSession, client_home: Path) -> CredentialLease:
    return CredentialLease(session, client_home)
