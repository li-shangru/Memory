"""Development-only Memory endpoint bootstrap and fresh native readiness."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from behavioral_mcp_bridge import MCPBridge

KEYRING_BACKEND = "keyring.backends.macOS.Keyring"
ENDPOINT_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "TMPDIR",
        "PATH",
        "LANG",
        "LC_ALL",
        "PYTHON_KEYRING_BACKEND",
        "PYTHONNOUSERSITE",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
    }
)
ENDPOINT_EXTENSION_KEYS = frozenset(
    {"PYTHON_KEYRING_BACKEND", "PYTHONNOUSERSITE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}
)
FRESH_ROOT_PARENT = Path("/private/tmp")
READINESS_SCHEMA = "memory.behavioral-memory-endpoint-readiness.v1"
MAX_OUTPUT_BYTES = 64 * 1024
PROCESS_TIMEOUT_SECONDS = 30.0
SUCCESS_FLAGS = (
    "memory_initialized",
    "mcp_initialized",
    "proxy_auth_environment_absent",
    "proxy_environment_isolated",
    "proxy_auth_home_denied",
    "endpoint_auth_home_denied",
    "endpoint_auth_environment_absent",
    "client_endpoint_environment_read_denied",
    "client_endpoint_environment_write_denied",
    "processes_reaped",
    "key_cleanup_confirmed",
    "runtime_removed",
    "cleanup_confirmed",
    "bridge_cleanup_confirmed",
    "bindings_unchanged",
)


class EndpointError(Exception):
    """A fixed diagnostic label without credentials or runtime content."""


def implementation_digest() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        raise EndpointError("endpoint_helper_unavailable") from None


def _os_home() -> str:
    try:
        uid = os.getuid()
        if uid != os.geteuid():
            raise EndpointError("endpoint_environment_invalid")
        home = pwd.getpwuid(uid).pw_dir
        if (
            not isinstance(home, str)
            or "\x00" in home
            or not Path(home).is_absolute()
            or Path(home) == Path("/")
            or any(part in {".", ".."} for part in home.split("/"))
        ):
            raise EndpointError("endpoint_environment_invalid")
        return home
    except KeyError, OSError:
        raise EndpointError("endpoint_environment_invalid") from None


def _private_directory(path: Path) -> None:
    value = path.lstat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_mode & 0o077
        or value.st_uid != os.geteuid()
    ):
        raise EndpointError("endpoint_environment_invalid")


def _workspace(path: Path) -> Path:
    if not path.is_absolute():
        raise EndpointError("endpoint_environment_invalid")
    _private_directory(path)
    return path.resolve(strict=True)


def _environment(workspace: Path, home: str) -> dict[str, str]:
    private = workspace / ".mcp-endpoint-home"
    return {
        "HOME": home,
        "TMPDIR": str(private / "tmp"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHON_KEYRING_BACKEND": KEYRING_BACKEND,
        "PYTHONNOUSERSITE": "1",
        "XDG_CONFIG_HOME": str(private / "config"),
        "XDG_CACHE_HOME": str(private / "cache"),
    }


def validate_endpoint_environment(
    environment: Mapping[str, str], workspace: Path
) -> None:
    """Validate the complete fixed tuple without opening the OS account home."""
    try:
        workspace = _workspace(workspace)
        expected = _environment(workspace, _os_home())
        if dict(environment) != expected:
            raise EndpointError("endpoint_environment_invalid")
        private = workspace / ".mcp-endpoint-home"
        _private_directory(private)
        if {path.name for path in private.iterdir()} != {"config", "cache", "tmp"}:
            raise EndpointError("endpoint_environment_invalid")
        for name in ("config", "cache", "tmp"):
            directory = private / name
            _private_directory(directory)
            if any(directory.iterdir()):
                raise EndpointError("endpoint_environment_invalid")
    except OSError, RuntimeError, TypeError, ValueError:
        raise EndpointError("endpoint_environment_invalid") from None


def endpoint_environment(workspace: Path) -> dict[str, str]:
    """Use OS HOME for Keychain and fresh private application directories."""
    created: Path | None = None
    try:
        home = _os_home()
        workspace = _workspace(workspace)
        private = workspace / ".mcp-endpoint-home"
        private.mkdir(mode=0o700)
        created = private
        for name in ("config", "cache", "tmp"):
            (private / name).mkdir(mode=0o700)
        environment = _environment(workspace, home)
        validate_endpoint_environment(environment, workspace)
        return environment
    except EndpointError, OSError, RuntimeError, TypeError, ValueError:
        if created is not None:
            try:
                shutil.rmtree(created)
            except OSError:
                raise EndpointError("endpoint_environment_cleanup_failed") from None
        raise EndpointError("endpoint_environment_invalid") from None


def _tools_on_path() -> None:
    directory = str(Path(__file__).resolve().parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _memory_interpreter(memory: Path) -> Path:
    """Keep the venv's lexical interpreter path while checking its target."""
    try:
        if not memory.is_absolute() or not os.access(memory, os.X_OK):
            raise EndpointError("readiness_artifact_unavailable")
        with memory.open("rb") as stream:
            first = stream.readline(4097)
        if len(first) > 4096 or not first.startswith(b"#!/"):
            raise EndpointError("readiness_artifact_unavailable")
        value = first[2:].decode("utf-8").strip()
        interpreter = Path(value)
        if (
            not value
            or any(character.isspace() for character in value)
            or "\x00" in value
            or not interpreter.is_absolute()
            or not interpreter.name.startswith("python")
            or not interpreter.resolve(strict=True).is_file()
            or not os.access(interpreter, os.X_OK)
        ):
            raise EndpointError("readiness_artifact_unavailable")
        return interpreter
    except OSError, RuntimeError, UnicodeError:
        raise EndpointError("readiness_artifact_unavailable") from None


def _artifact_bindings(memory: Path, client: Path) -> dict[str, str]:
    _tools_on_path()
    from behavioral_codex_isolation import artifact_binding
    from behavioral_mcp_bridge import transport_digest

    try:
        binding = artifact_binding(client, authentication_mode="chatgpt_subscription")
        return {
            "memory_executable_digest": _file_digest(memory),
            "memory_interpreter_digest": _file_digest(_memory_interpreter(memory)),
            "client_executable_digest": binding.client_executable_digest,
            "code_mode_host_digest": binding.code_mode_host_digest,
            "isolation_profile_digest": binding.isolation_profile_digest,
            "endpoint_helper_digest": implementation_digest(),
            "bridge_transport_digest": transport_digest(),
        }
    except Exception:
        raise EndpointError("readiness_artifact_unavailable") from None


def _write_checkpoint(path: Path, payload: Mapping[str, object]) -> str:
    temporary: Path | None = None
    try:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise EndpointError("readiness_checkpoint_failed")
        descriptor, value = tempfile.mkstemp(
            prefix=".readiness-checkpoint-", dir=path.parent
        )
        temporary = Path(value)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(payload, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        return _file_digest(path)
    except OSError, TypeError, ValueError:
        raise EndpointError("readiness_checkpoint_failed") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass
class _ReadinessContext:
    workspace: Path
    root: Path
    bindings: dict[str, str]
    processes: list[dict[str, object]] = field(default_factory=list)
    flags: dict[str, bool] = field(
        default_factory=lambda: dict.fromkeys(SUCCESS_FLAGS, False)
    )
    initialization_attempted: bool = False
    bridge_allocation_started: bool = False
    bridge_resource_paths: list[str] = field(default_factory=list)
    bridge_process_cleanup_confirmed: bool = True
    store_id: str | None = None
    checkpoint_digest: str = ""

    def __post_init__(self) -> None:
        # No bridge resources exist until allocation begins. From that point
        # only the bridge's explicit cleanup evidence can restore this flag.
        self.flags["bridge_cleanup_confirmed"] = True

    @property
    def runtime(self) -> Path:
        return self.root / "fresh-empty-store"

    def checkpoint(self) -> None:
        self.checkpoint_digest = _write_checkpoint(
            self.workspace / "readiness-checkpoint.private.json",
            {
                "schema": READINESS_SCHEMA,
                "fresh_root": str(self.root),
                "runtime": str(self.runtime),
                "store_id": self.store_id,
                "initialization_attempted": self.initialization_attempted,
                "bridge_allocation_started": self.bridge_allocation_started,
                "bridge_resource_paths": self.bridge_resource_paths,
                "bridge_process_cleanup_confirmed": self.bridge_process_cleanup_confirmed,
                "owned_processes": self.processes,
                **self.bindings,
                **self.flags,
            },
        )


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes


def _run_owned(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    phase: str,
    processes: list[dict[str, object]],
    checkpoint: Callable[[], None],
    timeout: float = PROCESS_TIMEOUT_SECONDS,
    request: bytes | None = None,
    first_line: bool = False,
    before_stop: Callable[[], None] | None = None,
    observer: Callable[[], None] | None = None,
) -> _ProcessResult:
    """Bound stdout, stderr and time; record and stop only the newly owned group."""
    _tools_on_path()
    from behavioral_mcp_bridge import _stop_endpoint

    started_utc, started_monotonic = time.time(), time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if request is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(environment),
            start_new_session=True,
            close_fds=True,
        )
    except OSError, ValueError:
        raise EndpointError("readiness_process_unavailable") from None
    record: dict[str, object] = {
        "phase": phase,
        "pid": process.pid,
        "pgid": process.pid,
        "started_at_utc": started_utc,
        "started_monotonic": started_monotonic,
        "reaped": False,
        "process_group_stopped": False,
    }
    processes.append(record)
    try:
        checkpoint()
        if request is not None:
            if len(request) > 4096:
                raise EndpointError("readiness_process_input_invalid")
            assert process.stdin is not None
            process.stdin.write(request)
            process.stdin.flush()
        assert process.stdout is not None and process.stderr is not None
        output, errors = bytearray(), bytearray()
        descriptors = {process.stdout.fileno(): output, process.stderr.fileno(): errors}
        for descriptor in descriptors:
            os.set_blocking(descriptor, False)
        deadline = time.monotonic() + timeout
        while descriptors:
            if observer is not None:
                observer()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EndpointError("readiness_process_timeout")
            readable, _, _ = select.select(
                tuple(descriptors), (), (), min(remaining, 0.1)
            )
            for descriptor in readable:
                chunk = os.read(descriptor, min(8192, MAX_OUTPUT_BYTES + 1))
                if not chunk:
                    del descriptors[descriptor]
                    continue
                target = descriptors[descriptor]
                if len(target) + len(chunk) > MAX_OUTPUT_BYTES:
                    raise EndpointError("readiness_process_output_limit")
                target.extend(chunk)
            if first_line and b"\n" in output:
                return _ProcessResult(
                    process.poll(), bytes(output).split(b"\n", 1)[0], bytes(errors)
                )
        return _ProcessResult(
            process.wait(timeout=max(0.01, deadline - time.monotonic())),
            bytes(output),
            bytes(errors),
        )
    except subprocess.TimeoutExpired:
        raise EndpointError("readiness_process_timeout") from None
    except OSError, ValueError:
        raise EndpointError("readiness_process_failed") from None
    finally:
        try:
            if before_stop is not None:
                before_stop()
        finally:
            try:
                _stop_endpoint(process, 1.0)
                record.update(reaped=True, process_group_stopped=True)
            except Exception:
                raise EndpointError("readiness_process_cleanup_unconfirmed") from None
            finally:
                record.update(
                    finished_at_utc=time.time(), finished_monotonic=time.monotonic()
                )
                if observer is not None:
                    observer()
                checkpoint()


def _new_workspace(context: _ReadinessContext, name: str) -> Path:
    path = context.root / name
    path.mkdir(mode=0o700)
    return path


def _native_initialize(context: _ReadinessContext, memory: Path) -> None:
    workspace = _new_workspace(context, "preparation")
    environment = endpoint_environment(workspace)
    result = _run_owned(
        [str(memory), "init", "--home", str(context.runtime)],
        environment=environment,
        cwd=workspace,
        phase="memory_init",
        processes=context.processes,
        checkpoint=context.checkpoint,
    )
    if result.returncode != 0:
        raise EndpointError("memory_endpoint_initialization_failed")


def _capture_store_id(context: _ReadinessContext) -> None:
    try:
        path = context.runtime / "runtime.json"
        if not context.runtime.exists() and context.store_id is None:
            return
        _private_directory(context.runtime)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if context.store_id is None:
                return
            raise EndpointError("readiness_identity_unconfirmed") from None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                raise EndpointError("readiness_identity_unconfirmed")
            value = json.loads(stream.read(4097))
        if not isinstance(value, dict):
            raise EndpointError("readiness_identity_unconfirmed")
        store_id = value.get("store_id")
        if (
            not isinstance(store_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", store_id) is None
            or type(value.get("schema_version")) is not int
            or value
            != {
                "product": "memory",
                "schema_lineage": "memory-store-v1",
                "schema_version": 1,
                "runtime_mode": "personal",
                "store_id": store_id,
                "inbox_path": str(context.runtime / "inbox"),
            }
            or (context.store_id is not None and context.store_id != store_id)
        ):
            raise EndpointError("readiness_identity_unconfirmed")
        context.store_id = store_id
        context.checkpoint()
    except OSError, ValueError, TypeError:
        raise EndpointError("readiness_identity_unconfirmed") from None


_KEY_CLEANUP = """import json,sys
import keyring
backend=keyring.get_keyring()
assert type(backend).__module__+'.'+type(backend).__qualname__=='keyring.backends.macOS.Keyring'
account=sys.argv[1]
assert len(account)==32 and all(c in '0123456789abcdef' for c in account)
present=backend.get_password('memory',account) is not None
if present: backend.delete_password('memory',account)
print(json.dumps({'absent':backend.get_password('memory',account) is None}))
"""


def _cleanup_native_key(context: _ReadinessContext, interpreter: Path) -> bool:
    # No identity means initialization never reached key creation: the installed
    # runtime contract persists its fresh identity before creating its key.
    if context.store_id is None:
        return not context.flags["memory_initialized"]
    if _file_digest(interpreter) != context.bindings["memory_interpreter_digest"]:
        return False
    workspace = _new_workspace(context, "key-cleanup")
    environment = endpoint_environment(workspace)
    result = _run_owned(
        [str(interpreter), "-I", "-c", _KEY_CLEANUP, context.store_id],
        environment=environment,
        cwd=workspace,
        phase="synthetic_key_cleanup",
        processes=context.processes,
        checkpoint=context.checkpoint,
    )
    receipt = _json_mapping(result.stdout)
    return (
        result.returncode == 0
        and not result.stderr
        and set(receipt) == {"absent"}
        and receipt["absent"] is True
    )


def _json_mapping(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except UnicodeError, ValueError:
        raise EndpointError("readiness_response_invalid") from None
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise EndpointError("readiness_response_invalid")
    return cast(dict[str, object], value)


_BOUNDARY_CHECK = """import errno,json,os,sys
def denied(path,flags):
 try:
  descriptor=os.open(path,flags,0o600)
 except OSError as error:
  return error.errno in (errno.EACCES,errno.EPERM)
 else:
  os.close(descriptor)
  if flags & os.O_CREAT: os.unlink(path)
  return False
result={'auth_denied':denied(sys.argv[1],os.O_RDONLY)}
if len(sys.argv)>2:
 result['environment_read_denied']=denied(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
 result['environment_write_denied']=denied(sys.argv[2]+'/config/synthetic-write-canary',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
result['auth_environment_absent']=not any(name in os.environ for name in ('CODEX_API_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY','CLAUDE_CODE_OAUTH_TOKEN'))
print(json.dumps(result))
"""


def _remember_bridge_state(context: _ReadinessContext, bridge: MCPBridge) -> None:
    paths = list(
        dict.fromkeys(
            (
                *context.bridge_resource_paths,
                *(str(path) for path in bridge.cleanup_paths),
            )
        )
    )
    resources_removed = bridge.resources_cleanup_confirmed
    processes_stopped = bridge.process_cleanup_confirmed
    changed = (
        paths != context.bridge_resource_paths
        or resources_removed != context.flags["bridge_cleanup_confirmed"]
        or processes_stopped != context.bridge_process_cleanup_confirmed
    )
    context.bridge_resource_paths = paths
    context.flags["bridge_cleanup_confirmed"] = resources_removed
    context.bridge_process_cleanup_confirmed = processes_stopped
    metadata = bridge.endpoint_process_metadata
    if metadata is not None:
        for record in context.processes:
            if record.get("phase") == "memory_mcp_endpoint":
                if record != metadata:
                    record.update(metadata)
                    changed = True
                break
        else:
            context.processes.append(dict(metadata))
            changed = True
    if changed:
        context.checkpoint()


def _native_bridge_check(
    context: _ReadinessContext, memory: Path, client: Path, interpreter: Path
) -> dict[str, bool]:
    _tools_on_path()
    from behavioral_codex_isolation import (
        endpoint_command,
        execution_command,
        system_python,
    )
    from behavioral_mcp_bridge import BridgeLimits, MCPBridge

    workspace = _new_workspace(context, "endpoint")
    environment = endpoint_environment(workspace)
    environment_root = workspace / ".mcp-endpoint-home"
    homes = (
        _new_workspace(context, "synthetic-auth-scope"),
        _new_workspace(context, "synthetic-client-home"),
    )
    canary = homes[1] / "synthetic-denial-canary"
    with canary.open("xb") as stream:
        stream.write(b"fresh synthetic noncredential canary")
    canary.chmod(0o600)
    endpoint_policy = workspace / "endpoint-policy.private.sb"
    endpoint = endpoint_command(
        [str(memory), "mcp", "--home", str(context.runtime)],
        policy_path=endpoint_policy,
        credential_homes=homes,
    )
    endpoint_control = _run_owned(
        [
            *endpoint[:3],
            str(interpreter),
            "-I",
            "-S",
            "-c",
            _BOUNDARY_CHECK,
            str(canary),
        ],
        environment=environment,
        cwd=workspace,
        phase="endpoint_credential_boundary",
        processes=context.processes,
        checkpoint=context.checkpoint,
    )
    endpoint_result = _json_mapping(endpoint_control.stdout)
    flags = {
        "endpoint_auth_home_denied": endpoint_result.get("auth_denied") is True,
        "endpoint_auth_environment_absent": endpoint_result.get(
            "auth_environment_absent"
        )
        is True,
    }
    context.flags.update(flags)
    if (
        endpoint_control.returncode != 0
        or endpoint_control.stderr
        or not all(flags.values())
    ):
        raise EndpointError("readiness_endpoint_boundary_unconfirmed")
    python = system_python()
    bridge = MCPBridge(
        root=workspace,
        endpoint_command=endpoint,
        endpoint_environment=environment,
        endpoint_cwd=workspace,
        proxy_python=python,
        credential_homes=homes,
        credential_canary=canary,
        limits=BridgeLimits(
            connect_timeout_seconds=60,
            session_timeout_seconds=60,
            idle_timeout_seconds=40,
        ),
    )
    context.bridge_allocation_started = True
    context.flags["bridge_cleanup_confirmed"] = False
    context.bridge_process_cleanup_confirmed = False
    context.checkpoint()
    try:
        with bridge:
            _remember_bridge_state(context, bridge)
            # Construct the real native-client policy, then launch only its
            # unchanged stdio proxy beneath that inherited policy. No client,
            # login operation or completion provider is invoked by readiness.
            policy = execution_command(
                [str(client), "--help"],
                policy_path=workspace / "client-policy.private.sb",
                executable_paths=tuple(
                    dict.fromkeys(
                        (
                            client,
                            client.parent / "codex-code-mode-host",
                            python,
                            *bridge.proxy_executable_paths,
                        )
                    )
                ),
                bridge_socket=bridge.socket_path,
                readable_proxy_files=(*bridge.proxy_read_paths, endpoint_policy),
                memory_home=context.runtime,
                credential_homes=homes,
                credential_client=client,
                endpoint_environment_root=environment_root,
            )
            client_environment = {
                "HOME": str(homes[1]),
                "CODEX_HOME": str(homes[1]),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            client_control = _run_owned(
                [
                    *policy[:3],
                    str(python),
                    "-I",
                    "-S",
                    "-c",
                    _BOUNDARY_CHECK,
                    str(canary),
                    str(environment_root),
                ],
                environment=client_environment,
                cwd=workspace,
                phase="client_endpoint_boundary",
                processes=context.processes,
                checkpoint=context.checkpoint,
            )
            client_result = _json_mapping(client_control.stdout)
            context.flags.update(
                client_endpoint_environment_read_denied=client_result.get(
                    "environment_read_denied"
                )
                is True,
                client_endpoint_environment_write_denied=client_result.get(
                    "environment_write_denied"
                )
                is True,
            )
            if (
                client_control.returncode != 0
                or client_control.stderr
                or client_result
                != {
                    "auth_denied": True,
                    "auth_environment_absent": True,
                    "environment_read_denied": True,
                    "environment_write_denied": True,
                }
            ):
                raise EndpointError("readiness_client_boundary_unconfirmed")
            request = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "synthetic-memory-readiness",
                                "version": "1",
                            },
                        },
                    }
                )
                + "\n"
            ).encode()
            result = _run_owned(
                [*policy[:3], *bridge.proxy_command],
                environment={
                    **client_environment,
                    "CODEX_API_KEY": "synthetic-never-valid",
                },
                cwd=workspace,
                phase="memory_stdio_proxy",
                processes=context.processes,
                checkpoint=context.checkpoint,
                request=request,
                first_line=True,
                before_stop=bridge.close,
                observer=lambda: _remember_bridge_state(context, bridge),
            )
            value = _json_mapping(result.stdout)
            response = value.get("result")
            if (
                value.get("jsonrpc") != "2.0"
                or type(value.get("id")) is not int
                or value.get("id") != 1
                or "error" in value
                or not isinstance(response, dict)
                or response.get("protocolVersion") != "2025-03-26"
                or not isinstance(response.get("capabilities"), dict)
                or not isinstance(response.get("serverInfo"), dict)
                or response["serverInfo"].get("name") != "Memory"
            ):
                raise EndpointError("readiness_response_invalid")
            context.flags["mcp_initialized"] = True
    finally:
        _remember_bridge_state(context, bridge)
        context.flags.update(
            proxy_auth_environment_absent=bridge.proxy_auth_environment_absent is True,
            proxy_environment_isolated=bridge.proxy_environment_isolated is True,
            proxy_auth_home_denied=bridge.proxy_auth_home_denied is True,
        )
    if bridge.failure_label is not None or not bridge.endpoint_started:
        raise EndpointError("memory_endpoint_transport_failed")
    return {
        key: context.flags[key]
        for key in (
            "mcp_initialized",
            "proxy_auth_environment_absent",
            "proxy_environment_isolated",
            "proxy_auth_home_denied",
            "endpoint_auth_home_denied",
            "endpoint_auth_environment_absent",
            "client_endpoint_environment_read_denied",
            "client_endpoint_environment_write_denied",
        )
    }


def _processes_reaped(context: _ReadinessContext) -> bool:
    return context.bridge_process_cleanup_confirmed and all(
        record.get("reaped") is True and record.get("process_group_stopped") is True
        for record in context.processes
    )


def verify_endpoint_readiness(
    memory_executable: Path, client_executable: Path, workspace: Path
) -> dict[str, object]:
    """Check a new empty Store through the installed endpoint and exact bridge.

    No existing runtime or auth path is accepted. The caller retains the private
    checkpoint workspace when cleanup cannot be confirmed; a consumed workspace
    is never retried. This function launches no native model client or provider.
    """
    workspace = _workspace(workspace)
    checkpoint_path = workspace / "readiness-checkpoint.private.json"
    if checkpoint_path.exists() or checkpoint_path.is_symlink():
        raise EndpointError("readiness_workspace_consumed")
    try:
        marker = os.open(
            workspace / ".readiness-consumed",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(marker)
    except OSError:
        raise EndpointError("readiness_workspace_consumed") from None
    bindings = _artifact_bindings(memory_executable, client_executable)
    interpreter = _memory_interpreter(memory_executable)
    root = Path(
        tempfile.mkdtemp(prefix="memory-endpoint-readiness-", dir=FRESH_ROOT_PARENT)
    ).resolve()
    context = _ReadinessContext(workspace, root, bindings)
    label = "memory_endpoint_readiness_failed"
    try:
        context.checkpoint()
        context.initialization_attempted = True
        context.checkpoint()
        _native_initialize(context, memory_executable)
        context.flags["memory_initialized"] = True
        _capture_store_id(context)
        if context.store_id is None:
            raise EndpointError("readiness_identity_unconfirmed")
        context.flags.update(
            _native_bridge_check(
                context, memory_executable, client_executable, interpreter
            )
        )
        context.flags["bindings_unchanged"] = (
            _artifact_bindings(memory_executable, client_executable) == bindings
        )
        if not context.flags["bindings_unchanged"]:
            raise EndpointError("readiness_artifact_changed")
    except EndpointError as error:
        label = str(error)
    except Exception:
        label = "memory_endpoint_readiness_failed"
    finally:
        context.flags["processes_reaped"] = _processes_reaped(context)
        if context.flags["processes_reaped"]:
            try:
                _capture_store_id(context)
                context.flags["key_cleanup_confirmed"] = _cleanup_native_key(
                    context, interpreter
                )
            except Exception:
                context.flags["key_cleanup_confirmed"] = False
        context.flags["processes_reaped"] = _processes_reaped(context)
        if all(
            context.flags[key]
            for key in (
                "key_cleanup_confirmed",
                "processes_reaped",
                "bridge_cleanup_confirmed",
            )
        ):
            try:
                shutil.rmtree(root)
                context.flags["runtime_removed"] = not root.exists()
            except OSError:
                context.flags["runtime_removed"] = False
        context.flags["cleanup_confirmed"] = all(
            context.flags[key]
            for key in (
                "key_cleanup_confirmed",
                "processes_reaped",
                "runtime_removed",
                "bridge_cleanup_confirmed",
            )
        )
        try:
            final_bindings_match = (
                _artifact_bindings(memory_executable, client_executable) == bindings
            )
        except Exception:
            final_bindings_match = False
        context.flags["bindings_unchanged"] = (
            context.flags["bindings_unchanged"] and final_bindings_match
        )
        if not final_bindings_match:
            label = "readiness_artifact_changed"
        context.checkpoint()
    ready = all(context.flags.values())
    if ready:
        label = "memory_endpoint_readiness_confirmed"
    elif not context.flags["cleanup_confirmed"]:
        label = "memory_endpoint_cleanup_unconfirmed"
    return {
        "schema": READINESS_SCHEMA,
        "ready": ready,
        "outcome_label": label,
        **bindings,
        **context.flags,
        "owned_processes": context.processes,
        "checkpoint_digest": context.checkpoint_digest,
    }
