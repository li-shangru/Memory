"""Prove an installed client's MCP-only executor using no real model or Store.

The loopback provider returns fixed harness-authored Code Mode calls. Their only
nested operation is an inert synthetic MCP stub. Receipts contain capability
names, digests, counts, and fixed labels, never captured prompts or transcripts.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BufferedIOBase
from pathlib import Path
from typing import cast

PROFILE_SCHEMA = "memory.behavioral-codex-isolation-profile.v1"
PROBE_SCHEMA = "memory.behavioral-capability-probe.v1"
MCP_SERVER_NAME = "memory_behavioral_acceptance"
STUB_TOOL_NAME = f"mcp__{MCP_SERVER_NAME}__probe_status"
EXCLUDED_NAMESPACES = ("functions", "web", "clock", "collaboration")
KEYCHAIN_FILESYSTEM_ROOTS = (
    "/Library/Keychains",
    "/System/Library/Keychains",
    "/Network/Library/Keychains",
    "/private/var/root/Library/Keychains",
    "/private/var/Keychains",
    "/private/var/db/SystemKeys",
    "/private/var/db/SystemKey",
    "/System/Volumes/Data/Library/Keychains",
    "/System/Volumes/Data/private/var/root/Library/Keychains",
    "/System/Volumes/Data/private/var/Keychains",
    "/System/Volumes/Data/private/var/db/SystemKeys",
    "/System/Volumes/Data/private/var/db/SystemKey",
)
DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "view_image",
    "shell_snapshot",
    "shell_snapshot_v2",
    "workspace_dependencies",
    "skill_search",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "in_app_browser",
    "image_generation",
    "hooks",
    "plugins",
    "apps",
    "tool_suggest",
    "deferred_executor",
    "executor_capability_discovery",
    "multi_agent",
    "multi_agent_v2",
    "goals",
    "artifact",
    "sleep_tool",
    "request_permissions_tool",
    "enable_request_compression",
)
DIRECT_TOOLS = frozenset(
    ("functions.exec", "functions.wait", "functions.request_user_input_async")
)
ORDINARY_PROTOTYPE_NAMES = tuple(
    sorted(
        (
            "constructor",
            "__defineGetter__",
            "__defineSetter__",
            "hasOwnProperty",
            "__lookupGetter__",
            "__lookupSetter__",
            "isPrototypeOf",
            "propertyIsEnumerable",
            "toString",
            "valueOf",
            "__proto__",
            "toLocaleString",
        )
    )
)
STUB_RESULT: dict[str, object] = {
    "content": [{"type": "text", "text": '{"synthetic_capability":"ok"}'}],
    "isError": False,
}
MAX_BODY = 2 * 1024 * 1024
MAX_REQUESTS = 8
MAX_CONNECTIONS = 8
MAX_STUB_EVENTS = 32
FINAL_PROBE_MESSAGE = "Synthetic capability completed."
RUN_TIMEOUT_SECONDS = 20
GUARD_TIMEOUT_SECONDS = 8
MODEL_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
EFFORT_LABEL = re.compile(r"[a-z][a-z0-9_]{0,31}")


class CapabilityProbeError(Exception):
    """A fixed, content-free capability failure label."""


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _executable(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
        if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
            raise CapabilityProbeError("executable_unavailable")
        return resolved
    except OSError, RuntimeError:
        raise CapabilityProbeError("executable_unavailable") from None


def _authentication_binding(authentication_mode: str | None) -> dict[str, str]:
    if authentication_mode is None:
        return {}
    if authentication_mode != "chatgpt_subscription":
        raise CapabilityProbeError("invalid_authentication_mode")
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_codex_auth import AuthError, implementation_digest, public_ca_digest

    try:
        return {
            "authentication_mode": authentication_mode,
            "authentication_adapter_digest": implementation_digest(),
            "public_ca_bundle_digest": public_ca_digest(),
        }
    except AuthError as error:
        raise CapabilityProbeError(str(error)) from None


def _settings(authentication_mode: str | None = None) -> tuple[str, ...]:
    settings = (
        "features.code_mode.enabled=true",
        "features.code_mode.excluded_tool_namespaces="
        + json.dumps(EXCLUDED_NAMESPACES, separators=(",", ":")),
        "agents.enabled=false",
        'web_search="disabled"',
        "tools.experimental_request_user_input.enabled=false",
        "tools.update_plan.enabled=false",
        'shell_environment_policy.inherit="none"',
        'cli_auth_credentials_store="file"',
        "analytics.enabled=false",
        "suppress_unstable_features_warning=true",
    )
    return settings + (
        ('forced_login_method="chatgpt"',)
        if _authentication_binding(authentication_mode)
        else ()
    )


def _bridge_transport_digest() -> str:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_mcp_bridge import BridgeError, transport_digest

    try:
        return transport_digest()
    except BridgeError:
        raise CapabilityProbeError("bridge_material_unavailable") from None


def _cleanup_implementation_digest() -> str:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_process_cleanup import implementation_digest

    return implementation_digest()


def _endpoint_implementation_digest() -> str:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_memory_endpoint import EndpointError, implementation_digest

    try:
        return implementation_digest()
    except EndpointError:
        raise CapabilityProbeError("endpoint_environment_unavailable") from None


def _lifecycle_implementation_digest() -> str:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_client_lifecycle import implementation_digest

    return implementation_digest()


def profile_digest(*, authentication_mode: str | None = None) -> str:
    """Bind the settings and exact shared policy/proof/bridge implementation."""
    return _digest(
        {
            "schema": PROFILE_SCHEMA,
            "settings": _settings(authentication_mode),
            "disabled_features": DISABLED_FEATURES,
            "enabled_features": ["code_mode_host"],
            "direct_tools": sorted(DIRECT_TOOLS),
            "mcp_server_name": MCP_SERVER_NAME,
            "launch_flags": _launch_flags(),
            "policy_and_proof_digest": _file_digest(Path(__file__)),
            "bridge_transport_digest": _bridge_transport_digest(),
            "client_lifecycle_digest": _lifecycle_implementation_digest(),
            "process_cleanup_digest": _cleanup_implementation_digest(),
            "endpoint_environment_digest": _endpoint_implementation_digest(),
            **_authentication_binding(authentication_mode),
        }
    )


def _launch_flags() -> tuple[str, ...]:
    return (
        "--ask-for-approval",
        "never",
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--json",
    )


def _validate_labels(model: str, reasoning_effort: str | None) -> None:
    if MODEL_LABEL.fullmatch(model) is None:
        raise CapabilityProbeError("invalid_probe_model")
    if (
        reasoning_effort is not None
        and EFFORT_LABEL.fullmatch(reasoning_effort) is None
    ):
        raise CapabilityProbeError("invalid_probe_effort")


def launch_arguments(
    client: Path,
    workspace: Path,
    *,
    model: str,
    reasoning_effort: str | None = None,
    authentication_mode: str | None = None,
) -> list[str]:
    """Build the shared launch; append exactly one explicit MCP server and `-`."""
    _validate_labels(model, reasoning_effort)
    command = [str(client), *_launch_flags(), "-C", str(workspace), "--model", model]
    for setting in _settings(authentication_mode):
        command.extend(("-c", setting))
    for feature in DISABLED_FEATURES:
        command.extend(("--disable", feature))
    command.extend(("--enable", "code_mode_host"))
    if reasoning_effort is not None:
        command.extend(("-c", "model_reasoning_effort=" + json.dumps(reasoning_effort)))
    return command


@dataclass(frozen=True)
class ArtifactBinding:
    client_executable_digest: str
    code_mode_host_digest: str
    isolation_profile_digest: str


def artifact_binding(
    client: Path, *, authentication_mode: str | None = None
) -> ArtifactBinding:
    """Resolve/hash only the installed client and host files; launch nothing."""
    client = _executable(client)
    host = _executable(client.parent / "codex-code-mode-host")
    try:
        return ArtifactBinding(
            _file_digest(client),
            _file_digest(host),
            profile_digest(authentication_mode=authentication_mode),
        )
    except OSError:
        raise CapabilityProbeError("executable_unavailable") from None


def protected_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    loopback_port: int | None = None,
    denied_fixture: Path | None = None,
    bridge_socket: Path | None = None,
    readable_proxy_files: Sequence[Path] = (),
    memory_home: Path | None = None,
    credential_homes: Sequence[Path] = (),
    credential_client: Path | None = None,
    endpoint_environment_root: Path | None = None,
) -> list[str]:
    """Write one new policy in a caller-owned private root and wrap the launch.

    The caller supplies a fresh HOME and minimal environment. No default home,
    credential, managed configuration, Keychain, or preference daemon is read to
    construct this policy. An offline metadata caller omits `loopback_port` and
    supplies only its client executable, prohibiting MCP/hook child processes.
    """
    return _process_command(
        command,
        policy_path=policy_path,
        executable_paths=executable_paths,
        loopback_port=loopback_port,
        denied_fixture=denied_fixture,
        bridge_socket=bridge_socket,
        readable_proxy_files=readable_proxy_files,
        memory_home=memory_home,
        provider_egress=False,
        credential_homes=credential_homes,
        credential_client=credential_client,
        endpoint_environment_root=endpoint_environment_root,
    )


def execution_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    bridge_socket: Path,
    readable_proxy_files: Sequence[Path],
    memory_home: Path,
    credential_homes: Sequence[Path] = (),
    credential_client: Path | None = None,
    endpoint_environment_root: Path | None = None,
) -> list[str]:
    """Use the shared policy with provider TLS and one parent-owned MCP proxy.

    The client cannot read the explicit Store or contact Keychain services.
    The caller owns the separate MCP endpoint and passes only proxy material.
    This constructs the policy; it does not establish provider authentication
    or TLS connectivity, which the offline capability proof does not measure.
    """
    if not readable_proxy_files:
        raise CapabilityProbeError("invalid_process_policy")
    return _process_command(
        command,
        policy_path=policy_path,
        executable_paths=executable_paths,
        loopback_port=None,
        denied_fixture=None,
        bridge_socket=bridge_socket,
        readable_proxy_files=readable_proxy_files,
        memory_home=memory_home,
        provider_egress=True,
        credential_homes=credential_homes,
        credential_client=credential_client,
        endpoint_environment_root=endpoint_environment_root,
    )


def login_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    callback_port: int | None,
    public_ca_bundle: Path | None = None,
) -> list[str]:
    """Admit normal subscription TLS and only its selected loopback callback."""
    return _process_command(
        command,
        policy_path=policy_path,
        executable_paths=executable_paths,
        loopback_port=None,
        denied_fixture=None,
        bridge_socket=None,
        readable_proxy_files=() if public_ca_bundle is None else (public_ca_bundle,),
        memory_home=None,
        provider_egress=True,
        callback_port=callback_port,
    )


def _immutable_rules(paths: Sequence[Path]) -> list[str]:
    if not paths:
        return []
    literals = " ".join("(literal " + json.dumps(str(path)) + ")" for path in paths)
    ancestors = " ".join(
        "(literal " + json.dumps(str(path)) + ")"
        for path in sorted({parent for path in paths for parent in path.parents})
    )
    return [
        "(deny file-write* file-link (require-any " + literals + "))",
        "(deny file-write-unlink (require-any " + ancestors + "))",
    ]


def _signing_identifier(client: Path) -> str:
    """Read only the admitted executable's signing metadata, never a key store."""
    with tempfile.TemporaryDirectory(
        prefix="memory-signing-metadata-", dir="/private/tmp"
    ) as temporary:
        root = Path(temporary)
        codesign = Path("/usr/bin/codesign")
        # SecStaticCode otherwise probes enclosing bundle directories. Display
        # an exact disposable copy of these public executable bytes so it has
        # no reason or permission to inspect an existing client-home directory.
        copied_code = root / "admitted-executable.bytes"
        try:
            descriptor = os.open(
                copied_code, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with (
                os.fdopen(descriptor, "wb") as destination,
                client.open("rb") as source,
            ):
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)
            if _file_digest(copied_code) != _file_digest(client):
                raise CapabilityProbeError("credential_client_identity_unconfirmed")
        except OSError:
            raise CapabilityProbeError(
                "credential_client_identity_unconfirmed"
            ) from None
        command = protected_command(
            [str(codesign), "-dv", "--verbose=2", str(copied_code)],
            policy_path=root / "metadata.sb",
            executable_paths=(codesign,),
        )
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                env={"HOME": str(root), "PATH": "/usr/bin:/bin", "TMPDIR": str(root)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=GUARD_TIMEOUT_SECONDS,
            )
            if (
                completed.returncode != 0
                or len(completed.stdout) + len(completed.stderr) > 16384
            ):
                raise CapabilityProbeError("credential_client_identity_unconfirmed")
            identifiers = [
                line.removeprefix("Identifier=")
                for line in completed.stderr.decode("utf-8").splitlines()
                if line.startswith("Identifier=")
            ]
            if (
                len(identifiers) != 1
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identifiers[0])
                is None
            ):
                raise CapabilityProbeError("credential_client_identity_unconfirmed")
            return identifiers[0]
        except OSError, UnicodeError, subprocess.SubprocessError:
            raise CapabilityProbeError(
                "credential_client_identity_unconfirmed"
            ) from None


def _credential_rules(
    credential_homes: Sequence[Path], *, reader_identifier: str | None = None
) -> list[str]:
    try:
        if any(not path.is_absolute() for path in credential_homes):
            raise CapabilityProbeError("invalid_process_policy")
        roots = tuple(path.resolve(strict=True) for path in credential_homes)
        if any(not path.is_dir() or path == Path("/") for path in roots):
            raise CapabilityProbeError("invalid_process_policy")
    except OSError, RuntimeError:
        raise CapabilityProbeError("invalid_process_policy") from None
    rules = []
    for root in roots:
        location = "(subpath " + json.dumps(str(root)) + ")"
        if reader_identifier is not None:
            location = (
                "(require-all "
                + location
                + " (require-not (signing-identifier "
                + json.dumps(reader_identifier)
                + ")))"
            )
        rules.append("(deny file-read* file-write* file-link " + location + ")")
    return rules + _immutable_rules(roots)


def _write_policy(command: Sequence[str], policy_path: Path, source: str) -> list[str]:
    try:
        descriptor = os.open(policy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(source)
    except OSError:
        raise CapabilityProbeError("process_policy_unavailable") from None
    return ["/usr/bin/sandbox-exec", "-f", str(policy_path), *command]


def proxy_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    bridge_socket: Path,
    readable_proxy_files: Sequence[Path],
    credential_homes: Sequence[Path],
) -> list[str]:
    """Further restrict the child proxy after its environment has been cleared."""
    if not credential_homes or not readable_proxy_files:
        raise CapabilityProbeError("invalid_process_policy")
    return _process_command(
        command,
        policy_path=policy_path,
        executable_paths=executable_paths,
        loopback_port=None,
        denied_fixture=None,
        bridge_socket=bridge_socket,
        readable_proxy_files=readable_proxy_files,
        memory_home=None,
        provider_egress=False,
        credential_homes=credential_homes,
        protect_policy=True,
    )


def endpoint_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    credential_homes: Sequence[Path],
) -> list[str]:
    """Deny task credentials to the parent-owned endpoint while retaining Keychain.

    The real endpoint needs its explicit synthetic Store and OS key boundary;
    the client/child-proxy policy must therefore not be reused wholesale here.
    """
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise CapabilityProbeError("platform_unavailable")
    if not command or not policy_path.is_absolute() or not credential_homes:
        raise CapabilityProbeError("invalid_process_policy")
    source = (
        "\n".join(
            [
                "(version 1)",
                "(allow default)",
                *_credential_rules(credential_homes),
                *_immutable_rules((policy_path.resolve(),)),
            ]
        )
        + "\n"
    )
    return _write_policy(command, policy_path, source)


def _process_command(
    command: Sequence[str],
    *,
    policy_path: Path,
    executable_paths: Sequence[Path],
    loopback_port: int | None,
    denied_fixture: Path | None,
    bridge_socket: Path | None,
    readable_proxy_files: Sequence[Path],
    memory_home: Path | None,
    provider_egress: bool,
    credential_homes: Sequence[Path] = (),
    credential_client: Path | None = None,
    callback_port: int | None = None,
    protect_policy: bool = False,
    endpoint_environment_root: Path | None = None,
) -> list[str]:
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise CapabilityProbeError("platform_unavailable")
    if (
        not command
        or not executable_paths
        or not policy_path.is_absolute()
        or (loopback_port is not None and not 1 <= loopback_port <= 65535)
        or (callback_port is not None and not 1 <= callback_port <= 65535)
        or (memory_home is not None and not memory_home.is_absolute())
        or (bridge_socket is not None and not bridge_socket.is_absolute())
        or any(not path.is_absolute() for path in readable_proxy_files)
    ):
        raise CapabilityProbeError("invalid_process_policy")
    executables = tuple(_executable(path) for path in executable_paths)
    if _executable(Path(command[0])) not in executables:
        raise CapabilityProbeError("invalid_process_policy")
    reader_identifier: str | None = None
    if credential_client is not None:
        if not credential_homes or _executable(credential_client) != _executable(
            Path(command[0])
        ):
            raise CapabilityProbeError("invalid_process_policy")
        reader_identifier = _signing_identifier(_executable(credential_client))
    executable_literals = " ".join(
        "(literal " + json.dumps(str(path)) + ")" for path in executables
    )
    try:
        proxy_files = tuple(path.resolve(strict=True) for path in readable_proxy_files)
        memory_home = memory_home.resolve() if memory_home is not None else None
        if endpoint_environment_root is not None:
            if (
                not endpoint_environment_root.is_absolute()
                or endpoint_environment_root.is_symlink()
            ):
                raise CapabilityProbeError("invalid_process_policy")
            endpoint_environment_root = endpoint_environment_root.resolve(strict=True)
            endpoint_info = endpoint_environment_root.stat()
            if (
                not stat.S_ISDIR(endpoint_info.st_mode)
                or endpoint_info.st_mode & 0o077
                or endpoint_info.st_uid != os.geteuid()
                or endpoint_environment_root == Path("/")
            ):
                raise CapabilityProbeError("invalid_process_policy")
        if any(
            not path.is_file()
            or (memory_home is not None and path.is_relative_to(memory_home))
            for path in proxy_files
        ):
            raise CapabilityProbeError("invalid_process_policy")
        if bridge_socket is not None:
            bridge_socket = bridge_socket.resolve(strict=True)
            if not stat.S_ISSOCK(bridge_socket.stat().st_mode) or (
                memory_home is not None and bridge_socket.is_relative_to(memory_home)
            ):
                raise CapabilityProbeError("invalid_process_policy")
    except OSError, RuntimeError:
        raise CapabilityProbeError("invalid_process_policy") from None
    readable_literals = " ".join(
        "(literal " + json.dumps(str(path)) + ")"
        for path in (*executables, *proxy_files)
    )
    immutable_proxy_rules = _immutable_rules(
        (*proxy_files, policy_path.resolve()) if protect_policy else proxy_files
    )
    protected_roots = '(subpath "/Users")'
    if denied_fixture is not None:
        if not denied_fixture.is_absolute():
            raise CapabilityProbeError("invalid_process_policy")
        protected_roots += " (subpath " + json.dumps(str(denied_fixture)) + ")"
    destinations: list[str] = []
    if loopback_port is not None:
        destinations.append('(remote ip "localhost:' + str(loopback_port) + '")')
    if bridge_socket is not None:
        destinations.append("(literal " + json.dumps(str(bridge_socket)) + ")")
    if provider_egress:
        destinations.extend(
            ('(remote tcp "*:443")', '(literal "/private/var/run/mDNSResponder")')
        )
    callback = '(local tcp "localhost:' + str(callback_port) + '")'
    network = (
        [
            "(deny network-outbound (require-not (require-any "
            + " ".join(destinations)
            + ")))",
            "(deny network-inbound)"
            if callback_port is None
            else "(deny network-inbound (require-not " + callback + "))",
            "(deny network-bind)"
            if callback_port is None
            else "(deny network-bind (require-not " + callback + "))",
        ]
        if destinations
        else ["(deny network*)"]
    )
    source = (
        "\n".join(
            [
                "(version 1)",
                "(allow default)",
                *network,
                "(deny process-exec (require-not (require-any "
                + executable_literals
                + ")))",
                "(deny file-read* (require-all (require-any "
                + protected_roots
                + ") (require-not (require-any "
                + readable_literals
                + "))))",
                "(deny file-write* (require-any " + protected_roots + "))",
                *immutable_proxy_rules,
                *_credential_rules(
                    credential_homes, reader_identifier=reader_identifier
                ),
                *(
                    _credential_rules((endpoint_environment_root,))
                    if endpoint_environment_root is not None
                    else []
                ),
                *(
                    [
                        "(deny file-read* file-write* (subpath "
                        + json.dumps(str(memory_home))
                        + "))"
                    ]
                    if memory_home is not None
                    else []
                ),
                '(deny file-read* (subpath "/private/etc/codex"))',
                '(deny file-read* (subpath "/Library/Managed Preferences"))',
                '(deny file-read* (subpath "/Library/Preferences"))',
                *(
                    "(deny file-read* file-write* (subpath " + json.dumps(root) + "))"
                    for root in KEYCHAIN_FILESYSTEM_ROOTS
                ),
                '(deny mach-lookup (global-name "com.apple.securityd")'
                ' (global-name "com.apple.securityd.xpc")'
                ' (global-name "com.apple.cfprefsd.daemon")'
                ' (global-name "com.apple.cfprefsd.agent"))',
            ]
        )
        + "\n"
    )
    return _write_policy(command, policy_path, source)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CapabilityProbeError("malformed_probe_response")
    return cast(Mapping[str, object], value)


def _json(raw: bytes | str) -> object:
    def reject_constant(_value: str) -> object:
        raise CapabilityProbeError("malformed_probe_response")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise CapabilityProbeError("malformed_probe_response")
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        return json.loads(
            text, object_pairs_hook=unique, parse_constant=reject_constant
        )
    except ValueError, UnicodeError:
        raise CapabilityProbeError("malformed_probe_response") from None


def _direct_tool_specs(payload: Mapping[str, object]) -> dict[str, str] | None:
    groups: list[object] = []
    if "tools" in payload:
        groups.append(payload["tools"])
    inputs = payload.get("input", [])
    if not isinstance(inputs, list):
        raise CapabilityProbeError("malformed_probe_response")
    for item in inputs:
        item = _mapping(item)
        if item.get("type") == "additional_tools":
            groups.append(item.get("tools"))
    if not groups:
        return None
    specifications: dict[str, str] = {}
    for group in groups:
        if not isinstance(group, list):
            raise CapabilityProbeError("malformed_probe_response")
        for raw_namespace in group:
            namespace = _mapping(raw_namespace)
            nested = namespace.get("tools")
            if (
                namespace.get("type") != "namespace"
                or namespace.get("name") != "functions"
                or not isinstance(nested, list)
                or not nested
            ):
                raise CapabilityProbeError("unexpected_direct_tool")
            for raw_tool in nested:
                tool = _mapping(raw_tool)
                name = tool.get("name")
                if not isinstance(name, str) or "functions." + name not in DIRECT_TOOLS:
                    raise CapabilityProbeError("unexpected_direct_tool")
                if tool.get("type") != ("custom" if name == "exec" else "function"):
                    raise CapabilityProbeError("unexpected_direct_tool")
                qualified = "functions." + name
                if qualified in specifications:
                    raise CapabilityProbeError("missing_or_duplicate_direct_tool")
                specifications[qualified] = _digest(tool)
    return specifications


def _direct_tools(payload: Mapping[str, object]) -> tuple[str, ...]:
    specifications = _direct_tool_specs(payload)
    if specifications is None or not {"functions.exec", "functions.wait"} <= set(
        specifications
    ):
        raise CapabilityProbeError("missing_or_duplicate_direct_tool")
    return tuple(sorted(specifications))


def _validate_wrapper(output: Mapping[str, object], *, excluded: bool) -> None:
    if set(output) != {
        "probe_nonce",
        "names",
        "tool_object_names",
        "tool_symbol_count",
        "prototype_kind",
        "prototype_names",
        "prototype_symbol_count",
        "callable",
        "caught",
        "stub_result",
    }:
        raise CapabilityProbeError("malformed_wrapper_output")
    expected_names = [] if excluded else [STUB_TOOL_NAME]
    if (
        output["names"] != expected_names
        or output["tool_object_names"] != expected_names
    ):
        raise CapabilityProbeError("unexpected_executor_tool")
    for field_name in ("tool_symbol_count", "prototype_symbol_count"):
        if type(output[field_name]) is not int or output[field_name] != 0:
            raise CapabilityProbeError("unexpected_executor_property")
    prototype_kind = output["prototype_kind"]
    if (
        not isinstance(prototype_kind, str)
        or prototype_kind not in {"ordinary", "null"}
        or output["prototype_names"]
        != (list(ORDINARY_PROTOTYPE_NAMES) if prototype_kind == "ordinary" else [])
    ):
        raise CapabilityProbeError("unexpected_executor_prototype")
    if (
        output["callable"] != ("undefined" if excluded else "function")
        or output["caught"] is not excluded
        or output["stub_result"] != (None if excluded else STUB_RESULT)
    ):
        raise CapabilityProbeError("executor_dispatch_unconfirmed")


def _wrapper_output(payload: Mapping[str, object], nonce: str) -> Mapping[str, object]:
    inputs = payload.get("input")
    if not isinstance(inputs, list):
        raise CapabilityProbeError("malformed_probe_response")
    outputs = [
        _mapping(item)
        for item in inputs
        if _mapping(item).get("type")
        in {"custom_tool_call_output", "function_call_output"}
    ]
    if (
        len(outputs) != 1
        or outputs[0].get("type") != "custom_tool_call_output"
        or outputs[0].get("call_id") != "call_" + nonce
    ):
        raise CapabilityProbeError("unexpected_wrapper_output")
    blocks = outputs[0].get("output")
    if not isinstance(blocks, list):
        raise CapabilityProbeError("malformed_wrapper_output")
    candidates: list[Mapping[str, object]] = []
    for block in blocks:
        block = _mapping(block)
        if block.get("type") != "input_text" or not isinstance(block.get("text"), str):
            raise CapabilityProbeError("malformed_wrapper_output")
        text = cast(str, block["text"])
        if text.startswith("{"):
            candidates.append(_mapping(_json(text)))
    if len(candidates) != 1 or candidates[0].get("probe_nonce") != nonce:
        raise CapabilityProbeError("wrapper_execution_unavailable")
    return candidates[0]


def _wrapper_code(nonce: str) -> str:
    return (
        "const names = ALL_TOOLS.map(tool => tool.name).sort(); "
        "const own_keys = Reflect.ownKeys(tools); "
        "const tool_object_names = own_keys.filter(key => typeof key === 'string').sort(); "
        "const tool_symbol_count = own_keys.length - tool_object_names.length; "
        "const prototype = Object.getPrototypeOf(tools); "
        "const prototype_kind = prototype === null ? 'null' : "
        "prototype === Object.prototype && Object.getPrototypeOf(prototype) === null ? 'ordinary' : 'unexpected'; "
        "const prototype_keys = prototype === null ? [] : Reflect.ownKeys(prototype); "
        "const prototype_names = prototype_keys.filter(key => typeof key === 'string').sort(); "
        "const prototype_symbol_count = prototype_keys.length - prototype_names.length; "
        f"const callable = typeof tools.{STUB_TOOL_NAME}; "
        "let caught = false; let stub_result = null; "
        f"try {{ stub_result = await tools.{STUB_TOOL_NAME}({{}}); }} "
        "catch { caught = true; } "
        "text({probe_nonce: "
        + json.dumps(nonce)
        + ", names, tool_object_names, tool_symbol_count, prototype_kind, prototype_names, "
        "prototype_symbol_count, callable, caught, stub_result});"
    )


def _response_events(nonce: str, model: str) -> list[dict[str, object]]:
    code = _wrapper_code(nonce)
    item: dict[str, object] = {
        "type": "custom_tool_call",
        "id": "item_" + nonce,
        "call_id": "call_" + nonce,
        "namespace": "functions",
        "name": "exec",
        "input": code,
        "status": "completed",
    }
    response = {
        "id": "response_" + nonce,
        "object": "response",
        "status": "completed",
        "model": model,
        "output": [item],
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }
    return [
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress", "output": []},
        },
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {**item, "status": "in_progress", "input": ""},
        },
        {
            "type": "response.custom_tool_call_input.delta",
            "output_index": 0,
            "item_id": item["id"],
            "delta": code,
        },
        {
            "type": "response.custom_tool_call_input.done",
            "output_index": 0,
            "item_id": item["id"],
            "input": code,
        },
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]


def _final_response_events(nonce: str, model: str) -> list[dict[str, object]]:
    part = {"type": "output_text", "text": FINAL_PROBE_MESSAGE, "annotations": []}
    item: dict[str, object] = {
        "type": "message",
        "id": "final_" + nonce,
        "role": "assistant",
        "status": "completed",
        "content": [part],
    }
    response = {
        "id": "final_response_" + nonce,
        "object": "response",
        "status": "completed",
        "model": model,
        "output": [item],
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }
    return [
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress", "output": []},
        },
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {**item, "status": "in_progress", "content": []},
        },
        {
            "type": "response.content_part.added",
            "output_index": 0,
            "content_index": 0,
            "item_id": item["id"],
            "part": {**part, "text": ""},
        },
        {
            "type": "response.output_text.delta",
            "output_index": 0,
            "content_index": 0,
            "item_id": item["id"],
            "delta": FINAL_PROBE_MESSAGE,
        },
        {
            "type": "response.output_text.done",
            "output_index": 0,
            "content_index": 0,
            "item_id": item["id"],
            "text": FINAL_PROBE_MESSAGE,
        },
        {
            "type": "response.content_part.done",
            "output_index": 0,
            "content_index": 0,
            "item_id": item["id"],
            "part": part,
        },
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]


@dataclass
class _Capture:
    model: str
    effort: str | None
    excluded: bool
    authentication_mode: str | None = None
    metadata_requests: int = 0
    nonce: str = field(default_factory=lambda: secrets.token_hex(24))
    token: str = field(default_factory=lambda: "synthetic_" + secrets.token_hex(32))
    done: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    failure: str | None = None
    direct: tuple[str, ...] = ()
    direct_specs: dict[str, str] = field(default_factory=dict)
    request_count: int = 0
    mock_calls: int = 0
    executor_names: tuple[str, ...] = ()
    final_response_sent: bool = False

    def fail(self, label: str) -> None:
        with self.lock:
            self.failure = self.failure or label
            self.done.set()

    def accept(self, raw: bytes, authorization: str) -> str:
        with self.lock:
            self.request_count += 1
            if len(raw) > MAX_BODY or self.request_count > MAX_REQUESTS:
                raise CapabilityProbeError("probe_request_limit")
            if authorization != "Bearer " + self.token:
                raise CapabilityProbeError("synthetic_auth_unconfirmed")
            payload = _mapping(_json(raw))
            if "response" in payload:
                payload = _mapping(payload["response"])
            if payload.get("model") != self.model:
                raise CapabilityProbeError("probe_model_mismatch")
            if (
                self.effort is not None
                and _mapping(payload.get("reasoning")).get("effort") != self.effort
            ):
                raise CapabilityProbeError("probe_effort_mismatch")
            supplied = _direct_tool_specs(payload)
            if (
                self.direct
                and supplied is not None
                and any(
                    self.direct_specs.get(name) != digest
                    for name, digest in supplied.items()
                )
            ):
                raise CapabilityProbeError("probe_direct_schema_changed")
            if payload.get("generate") is False:
                return "prewarm"
            if not self.direct:
                self.direct = _direct_tools(payload)
                self.direct_specs = supplied or {}
                if self.nonce not in json.dumps(payload.get("input")):
                    raise CapabilityProbeError("synthetic_prompt_unconfirmed")
                self.mock_calls += 1
                return "respond"
            _validate_wrapper(
                _wrapper_output(payload, self.nonce), excluded=self.excluded
            )
            self.executor_names = () if self.excluded else (STUB_TOOL_NAME,)
            self.done.set()
            return "complete"


def _read_exact(stream: BufferedIOBase, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part:
            raise CapabilityProbeError("probe_transport_closed")
        chunks.extend(part)
    return bytes(chunks)


def _read_websocket(stream: BufferedIOBase) -> bytes | None:
    chunks = bytearray()
    for index in range(32):
        first, second = _read_exact(stream, 2)
        opcode = first & 15
        if opcode == 8:
            return None
        if first & 112 or not second & 128 or opcode != (1 if index == 0 else 0):
            raise CapabilityProbeError("unsupported_probe_frame")
        length = second & 127
        if length == 126:
            length = struct.unpack("!H", _read_exact(stream, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _read_exact(stream, 8))[0]
        if len(chunks) + length > MAX_BODY:
            raise CapabilityProbeError("probe_request_limit")
        mask = _read_exact(stream, 4)
        body = _read_exact(stream, length)
        chunks.extend(value ^ mask[position % 4] for position, value in enumerate(body))
        if first & 128:
            return bytes(chunks)
    raise CapabilityProbeError("probe_request_limit")


def _websocket_message(event: Mapping[str, object]) -> bytes:
    data = json.dumps(event, separators=(",", ":")).encode()
    if len(data) < 126:
        header = bytes((129, len(data)))
    elif len(data) < 65536:
        header = bytes((129, 126)) + struct.pack("!H", len(data))
    else:
        header = bytes((129, 127)) + struct.pack("!Q", len(data))
    return header + data


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(
        self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]
    ) -> None:
        self._connections: set[socket.socket] = set()
        self._connection_count = 0
        self._connection_lock = threading.Lock()
        super().__init__(address, handler)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        with self._connection_lock:
            self._connection_count += 1
            if self._connection_count > MAX_CONNECTIONS:
                connection.close()
                raise OSError("synthetic connection limit")
            self._connections.add(connection)
        connection.settimeout(RUN_TIMEOUT_SECONDS)
        return connection, address

    def shutdown_request(
        self, request: socket.socket | tuple[bytes, socket.socket]
    ) -> None:
        if isinstance(request, socket.socket):
            with self._connection_lock:
                self._connections.discard(request)
        super().shutdown_request(request)

    def server_close(self) -> None:
        with self._connection_lock:
            connections = list(self._connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        super().server_close()

    def handle_error(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        # No request, prompt, private path, or session identifier is logged.
        pass


def _handler(capture: _Capture) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            pass

        def _empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def do_GET(self) -> None:
            if self.path == "/guard":
                self._empty(200)
                return
            if (
                capture.authentication_mode == "chatgpt_subscription"
                and self.path.split("?", 1)[0]
                in ("/v1/models", "/v1/api/codex/settings/user")
            ):
                with capture.lock:
                    capture.metadata_requests += 1
                    valid = (
                        capture.metadata_requests <= MAX_REQUESTS
                        and self.headers.get("Authorization")
                        == "Bearer " + capture.token
                    )
                if not valid:
                    capture.fail("unexpected_probe_metadata_request")
                # Retain the installed client's own built-in model catalogue.
                # A mock catalogue must not invent model/tool capabilities.
                self._empty(404)
                return
            if (
                self.path != "/v1/responses"
                or self.headers.get("Upgrade", "").lower() != "websocket"
            ):
                capture.fail("unexpected_probe_request")
                self._empty(400)
                return
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            ).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.connection.settimeout(RUN_TIMEOUT_SECONDS)
            try:
                for _ in range(MAX_REQUESTS):
                    raw = _read_websocket(self.rfile)
                    if raw is None:
                        return
                    action = capture.accept(raw, self.headers.get("Authorization", ""))
                    if action not in {"respond", "complete"}:
                        return
                    events = (
                        _response_events(capture.nonce, capture.model)
                        if action == "respond"
                        else _final_response_events(capture.nonce, capture.model)
                    )
                    for event in events:
                        self.wfile.write(_websocket_message(event))
                    self.wfile.flush()
                    if action == "complete":
                        with capture.lock:
                            capture.final_response_sent = True
                        return
            except CapabilityProbeError as error:
                capture.fail(str(error))
            except OSError, ValueError:
                capture.fail("probe_transport_failed")
            finally:
                self.close_connection = True

        def do_POST(self) -> None:
            if (
                self.path != "/v1/responses"
                or self.headers.get("Content-Encoding")
                or self.headers.get("Transfer-Encoding")
            ):
                capture.fail("unexpected_probe_request")
                self._empty(400)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= MAX_BODY:
                    raise CapabilityProbeError("probe_request_limit")
                self.connection.settimeout(RUN_TIMEOUT_SECONDS)
                action = capture.accept(
                    _read_exact(self.rfile, length),
                    self.headers.get("Authorization", ""),
                )
                if action not in {"respond", "complete"}:
                    self._empty(400)
                    return
                events = (
                    _response_events(capture.nonce, capture.model)
                    if action == "respond"
                    else _final_response_events(capture.nonce, capture.model)
                )
                stream = "".join(
                    "data: " + json.dumps(event, separators=(",", ":")) + "\n\n"
                    for event in events
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(stream)))
                self.end_headers()
                self.wfile.write(stream)
                self.wfile.flush()
                if action == "complete":
                    with capture.lock:
                        capture.final_response_sent = True
            except CapabilityProbeError as error:
                capture.fail(str(error))
            except OSError, ValueError:
                capture.fail("probe_transport_failed")
            finally:
                self.close_connection = True

    return Handler


def _probe_environment(
    root: Path,
    token: str,
    *,
    authentication_mode: str | None = None,
    public_ca_bundle: Path | None = None,
) -> dict[str, str]:
    result = {
        "HOME": str(root / "home"),
        "CODEX_HOME": str(root / "home"),
        "PATH": "/usr/bin:/bin",
        "LANG": "en_US.UTF-8",
        "TMPDIR": str(root),
    }
    if not _authentication_binding(authentication_mode):
        result["CODEX_API_KEY"] = token
    else:
        if public_ca_bundle is None:
            raise CapabilityProbeError("subscription_public_ca_unavailable")
        result["CODEX_CA_CERTIFICATE"] = str(public_ca_bundle)
    return result


def _synthetic_subscription_cache(home: Path, token: str) -> None:
    """Fresh dummy ChatGPT cache only; never copy or inspect a real credential."""

    def segment(value: object) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

    identity = (
        segment({"alg": "none", "typ": "JWT"})
        + "."
        + segment(
            {
                "sub": "synthetic-capability-subject",
                "email": "synthetic@example.invalid",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "synthetic-capability-account",
                    "chatgpt_plan_type": "pro",
                },
            }
        )
        + "."
        + base64.urlsafe_b64encode(b"synthetic-signature-only").rstrip(b"=").decode()
    )
    cache = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "access_token": token,
            "id_token": identity,
            "refresh_token": "synthetic-unused-refresh-token",
            "account_id": "synthetic-capability-account",
        },
        "last_refresh": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    descriptor = os.open(
        home / "auth.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(cache, stream, separators=(",", ":"))


def _system_python() -> Path:
    # Resolve system developer-tool metadata, avoiding the /usr/bin launcher
    # which execs a separately selected interpreter after policy admission.
    for candidate in (
        Path("/var/db/xcode_select_link/usr/bin/python3"),
        Path("/Library/Developer/CommandLineTools/usr/bin/python3"),
    ):
        try:
            launcher = _executable(candidate)
            framework_binary = (
                launcher.parent.parent / "Resources/Python.app/Contents/MacOS/Python"
            )
            if framework_binary.is_file():
                return _executable(framework_binary)
            return launcher
        except CapabilityProbeError:
            continue
    raise CapabilityProbeError("system_python_unavailable")


def system_python() -> Path:
    """Resolve the actual system interpreter from developer-tool metadata."""
    return _system_python()


def _write_stub(
    path: Path,
    journal: Path,
    *,
    credential_canary: Path | None = None,
    denial_receipt: Path | None = None,
) -> None:
    # The child runs -I -S. It imports only the system standard library and
    # never receives a Memory executable, home, configuration, or credential.
    source = """import json,sys
BOUNDARY_CHECK
events=0
while events<32:
    raw=sys.stdin.buffer.readline(65537)
    if not raw or len(raw)>65536:break
    request=json.loads(raw)
    method=request.get("method")
    entry={"method":method}
    if method=="tools/call":
        entry["valid_call"]=request.get("params",{}).get("name")=="probe_status" and request.get("params",{}).get("arguments")=={}
    with open(sys.argv[1],"a") as stream:stream.write(json.dumps(entry)+"\\n")
    events+=1
    if "id" not in request:continue
    if method=="initialize":result={"protocolVersion":request["params"]["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"synthetic_capability_probe","version":"1.0.0"}}
    elif method=="tools/list":result={"tools":[{"name":"probe_status","description":"Return a fixed inert synthetic status.","inputSchema":{"type":"object","properties":{},"additionalProperties":False},"annotations":{"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False}}]}
    elif method=="tools/call" and entry.get("valid_call"):result=STUB_RESULT
    elif method=="resources/list":result={"resources":[]}
    elif method=="resources/templates/list":result={"resourceTemplates":[]}
    elif method=="prompts/list":result={"prompts":[]}
    elif method=="ping":result={}
    else:
        print(json.dumps({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"Unknown synthetic operation"}}),flush=True)
        continue
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result}),flush=True)
""".replace("STUB_RESULT", repr(STUB_RESULT))
    boundary = ""
    if credential_canary is not None and denial_receipt is not None:
        boundary = """try:
    with open(CANARY,'rb'):pass
    denied=False
except PermissionError:denied=True
with open(RECEIPT,'w') as stream:json.dump({'endpoint_auth_home_denied':denied},stream)
if not denied:raise SystemExit(1)
""".replace("CANARY", repr(str(credential_canary))).replace(
            "RECEIPT", repr(str(denial_receipt))
        )
    source = source.replace("BOUNDARY_CHECK", boundary)
    path.write_text(source, encoding="utf-8")
    path.chmod(0o600)
    journal.touch(mode=0o600, exist_ok=False)


def _stub_calls(journal: Path, *, excluded: bool) -> int:
    if journal.stat().st_size > 8192:
        raise CapabilityProbeError("stub_event_limit")
    events = [_mapping(_json(line)) for line in journal.read_bytes().splitlines()]
    allowed = {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "ping",
    }
    if not 1 <= len(events) <= MAX_STUB_EVENTS or any(
        event.get("method") not in allowed for event in events
    ):
        raise CapabilityProbeError("unexpected_stub_operation")
    if not {"initialize", "tools/list"} <= {event.get("method") for event in events}:
        raise CapabilityProbeError("stub_startup_unconfirmed")
    calls = [event for event in events if event.get("method") == "tools/call"]
    if len(calls) != (0 if excluded else 1) or any(
        event.get("valid_call") is not True for event in calls
    ):
        raise CapabilityProbeError("unexpected_stub_dispatch")
    return len(calls)


def _guard(
    python: Path,
    policy_path: Path,
    root: Path,
    port: int,
    denied_port: int,
) -> bool:
    source = """import json,socket,sys
def connect(port):
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=2):return True
    except OSError:return False
try:
    with open(sys.argv[3],"rb") as stream:stream.read(1)
    blocked=False
except PermissionError:blocked=True
print(json.dumps({"allowed":connect(int(sys.argv[1])),"denied":not connect(int(sys.argv[2])),"owner_rule_canary":blocked}))
"""
    # Both endpoints are alive before the protected check; no external probe
    # is needed or permitted to show that a different port is denied.
    for target in (port, denied_port):
        with socket.create_connection(("127.0.0.1", target), timeout=2):
            pass
    completed = subprocess.run(
        [
            "/usr/bin/sandbox-exec",
            "-f",
            str(policy_path),
            str(python),
            "-I",
            "-S",
            "-c",
            source,
            str(port),
            str(denied_port),
            str(root / "denied-fixture" / "canary"),
        ],
        cwd=root,
        env=_probe_environment(root, "synthetic_guard_only"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=GUARD_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0 or len(completed.stdout) > 1024:
        return False
    return _json(completed.stdout) == {
        "allowed": True,
        "denied": True,
        "owner_rule_canary": True,
    }


def _process_group_empty(group_id: int) -> bool:
    """Inspect only this owned process group; unknown state never proves cleanup."""
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_process_cleanup import group_has_no_live_members

    return group_has_no_live_members(group_id)


def _signal_process_group(
    process: subprocess.Popen[bytes], signum: signal.Signals
) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin may report EPERM after exit. The leader alone cannot prove
        # descendants stopped; require an owned-group query with no live rows.
        if process.poll() is None or not _process_group_empty(process.pid):
            raise


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        _signal_process_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _signal_process_group(process, signal.SIGKILL)
            process.wait(timeout=2)
    finally:
        # Reap the leader and its private group even if its first wait was
        # immediate or signaling raised; Code Mode children can outlive it.
        try:
            _signal_process_group(process, signal.SIGKILL)
        finally:
            process.wait(timeout=2)
    deadline = time.monotonic() + 2
    while not _process_group_empty(process.pid):
        if time.monotonic() >= deadline:
            raise CapabilityProbeError("client_process_cleanup_unconfirmed")
        time.sleep(0.02)


@dataclass(frozen=True)
class _RunResult:
    direct: tuple[str, ...]
    executor: tuple[str, ...]
    stub_calls: int
    mock_calls: int
    guards_confirmed: bool
    bridge_confirmed: bool = False
    proxy_auth_environment_absent: bool = False
    proxy_environment_isolated: bool = False
    proxy_auth_home_denied: bool | None = None
    endpoint_auth_home_denied: bool | None = None
    client_completion_confirmed: bool = False
    endpoint_completion_confirmed: bool = False
    final_response_sent: bool = False


def _run_probe(
    client: Path,
    host: Path,
    python: Path,
    *,
    model: str,
    effort: str | None,
    excluded: bool,
    authentication_mode: str | None = None,
) -> _RunResult:
    tools_root = str(Path(__file__).resolve().parent)
    if tools_root not in sys.path:
        sys.path.insert(0, tools_root)
    from behavioral_client_lifecycle import ClientLifecycle, LifecycleError
    from behavioral_codex_auth import AuthError, pin_public_ca_bundle, public_ca_digest
    from behavioral_mcp_bridge import BridgeError, BridgeLimits, MCPBridge

    capture = _Capture(model, effort, excluded, authentication_mode=authentication_mode)
    servers: list[_Server] = []
    threads: list[threading.Thread] = []
    try:
        for _ in range(2):
            server = _Server(("127.0.0.1", 0), _handler(capture))
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            thread.start()
            servers.append(server)
            threads.append(thread)
        with tempfile.TemporaryDirectory(
            prefix="memory-capability-", dir="/private/tmp"
        ) as temporary:
            root = Path(temporary)
            for name in ("home", "workspace", "denied-fixture", "endpoint"):
                (root / name).mkdir(mode=0o700)
            (root / "denied-fixture" / "canary").write_bytes(
                b"fresh synthetic denial canary"
            )
            endpoint_root = root / "endpoint"
            endpoint_home = endpoint_root / "home"
            endpoint_home.mkdir(mode=0o700)
            stub = endpoint_root / "stub.py"
            journal = endpoint_root / "stub-events.jsonl"
            credential_homes: tuple[Path, ...] = ()
            credential_canary: Path | None = None
            denial_receipt: Path | None = None
            public_ca_bundle: Path | None = None
            if authentication_mode is not None:
                auth_scope = root / "fresh-auth-scope"
                auth_scope.mkdir(mode=0o700)
                public_ca_bundle = pin_public_ca_bundle(auth_scope)
                credential_homes = (auth_scope, root / "home")
                credential_canary = root / "home" / "synthetic-denial-canary"
                credential_canary.write_bytes(
                    b"fresh synthetic subscription denial canary"
                )
                credential_canary.chmod(0o600)
                _synthetic_subscription_cache(root / "home", capture.token)
                denial_receipt = endpoint_root / "endpoint-denial.json"
            _write_stub(
                stub,
                journal,
                credential_canary=credential_canary,
                denial_receipt=denial_receipt,
            )
            endpoint = protected_command(
                [str(python), "-I", "-S", str(stub), str(journal)],
                policy_path=endpoint_root / "endpoint-policy.sb",
                executable_paths=(python,),
                credential_homes=credential_homes,
            )
            lifecycle = ClientLifecycle(root / "workspace" / "client-events.private")
            bridge = MCPBridge(
                root=root / "workspace",
                endpoint_command=endpoint,
                endpoint_environment={
                    "HOME": str(endpoint_home),
                    "TMPDIR": str(endpoint_home),
                    "PATH": "/usr/bin:/bin",
                    "LANG": "en_US.UTF-8",
                },
                endpoint_cwd=endpoint_root,
                proxy_python=python,
                credential_homes=credential_homes,
                credential_canary=credential_canary,
                completion_probe=lifecycle.completion_probe,
                limits=BridgeLimits(
                    max_frame_bytes=MAX_BODY,
                    max_stream_bytes=8 * MAX_BODY,
                    max_stderr_bytes=65536,
                    connect_timeout_seconds=RUN_TIMEOUT_SECONDS + 5,
                    session_timeout_seconds=RUN_TIMEOUT_SECONDS + 5,
                    idle_timeout_seconds=RUN_TIMEOUT_SECONDS + 5,
                ),
            )
            with bridge:
                command = launch_arguments(
                    client,
                    root / "workspace",
                    model=model,
                    reasoning_effort=effort,
                    authentication_mode=authentication_mode,
                )
                command.extend(
                    (
                        "-c",
                        (
                            "openai_base_url"
                            if authentication_mode is None
                            else "chatgpt_base_url"
                        )
                        + '="http://127.0.0.1:'
                        + str(servers[0].server_port)
                        + '/v1"',
                        "-c",
                        f"mcp_servers.{MCP_SERVER_NAME}.command="
                        + json.dumps(bridge.proxy_command[0]),
                        "-c",
                        f"mcp_servers.{MCP_SERVER_NAME}.args="
                        + json.dumps(bridge.proxy_command[1:]),
                        "-c",
                        f"mcp_servers.{MCP_SERVER_NAME}.required=true",
                        "-c",
                        f'mcp_servers.{MCP_SERVER_NAME}.default_tools_approval_mode="auto"',
                    )
                )
                if authentication_mode is not None:
                    command.extend(
                        (
                            "-c",
                            'openai_base_url="http://127.0.0.1:'
                            + str(servers[0].server_port)
                            + '/v1"',
                        )
                    )
                if excluded:
                    command.extend(
                        (
                            "-c",
                            "features.code_mode.excluded_tool_namespaces="
                            + json.dumps(
                                [*EXCLUDED_NAMESPACES, "mcp__" + MCP_SERVER_NAME]
                            ),
                        )
                    )
                command.append("-")
                policy = root / "policy.sb"
                command = protected_command(
                    command,
                    policy_path=policy,
                    executable_paths=(client, host, *bridge.proxy_executable_paths),
                    loopback_port=servers[0].server_port,
                    denied_fixture=root / "denied-fixture",
                    bridge_socket=bridge.socket_path,
                    readable_proxy_files=(
                        *bridge.readable_proxy_files,
                        *((public_ca_bundle,) if public_ca_bundle is not None else ()),
                    ),
                    memory_home=endpoint_root,
                    endpoint_environment_root=endpoint_home,
                    credential_homes=credential_homes,
                    credential_client=client
                    if authentication_mode is not None
                    else None,
                )
                if not _guard(
                    python, policy, root, servers[0].server_port, servers[1].server_port
                ):
                    raise CapabilityProbeError("process_restrictions_unconfirmed")

                def finish_client() -> None:
                    try:
                        if lifecycle.natural_exit_zero:
                            bridge.finish_client()
                        else:
                            bridge.close()
                    finally:
                        lifecycle.record_transport(bridge.lifecycle_metadata)

                response_path = root / "workspace" / "client-response.private"
                status, failure = lifecycle.run(
                    command,
                    cwd=root / "workspace",
                    environment=_probe_environment(
                        root,
                        capture.token,
                        authentication_mode=authentication_mode,
                        public_ca_bundle=public_ca_bundle,
                    ),
                    input_text="SYNTHETIC_CAPABILITY_ONLY " + capture.nonce + "\n",
                    response_path=response_path,
                    stderr_path=root / "workspace" / "client-stderr.private",
                    timeout=RUN_TIMEOUT_SECONDS,
                    before_cleanup=finish_client,
                )
                if capture.failure is not None:
                    raise CapabilityProbeError(capture.failure)
                if bridge.failure_label is not None:
                    raise CapabilityProbeError(bridge.failure_label)
                if failure is not None or status != 0:
                    raise CapabilityProbeError(
                        "client_probe_timeout"
                        if failure == "client_timeout"
                        else failure or "client_probe_unavailable"
                    )
                if (
                    not capture.final_response_sent
                    or not lifecycle.client_completion_confirmed
                    or not bridge.client_completion_confirmed
                    or response_path.read_text(encoding="utf-8")
                    != FINAL_PROBE_MESSAGE + "\n"
                ):
                    raise CapabilityProbeError("client_completion_unconfirmed")
            if bridge.failure_label is not None:
                raise CapabilityProbeError(bridge.failure_label)
            if (
                not bridge.endpoint_started
                or bridge.proxy_auth_environment_absent is not True
                or bridge.proxy_environment_isolated is not True
            ):
                raise CapabilityProbeError("mcp_bridge_unconfirmed")
            endpoint_denied: bool | None = None
            if authentication_mode is not None:
                if (
                    public_ca_bundle is None
                    or _file_digest(public_ca_bundle) != public_ca_digest()
                ):
                    raise CapabilityProbeError("subscription_public_ca_changed")
                if bridge.proxy_auth_home_denied is not True or denial_receipt is None:
                    raise CapabilityProbeError(
                        "subscription_child_boundary_unconfirmed"
                    )
                if _json(denial_receipt.read_bytes()) != {
                    "endpoint_auth_home_denied": True
                }:
                    raise CapabilityProbeError(
                        "subscription_child_boundary_unconfirmed"
                    )
                endpoint_denied = True
            calls = _stub_calls(journal, excluded=excluded)
            if capture.mock_calls != 1:
                raise CapabilityProbeError("unexpected_mock_call_count")
            return _RunResult(
                direct=capture.direct,
                executor=capture.executor_names,
                stub_calls=calls,
                mock_calls=capture.mock_calls,
                guards_confirmed=True,
                bridge_confirmed=True,
                proxy_auth_environment_absent=True,
                proxy_environment_isolated=True,
                proxy_auth_home_denied=bridge.proxy_auth_home_denied,
                endpoint_auth_home_denied=endpoint_denied,
                client_completion_confirmed=True,
                endpoint_completion_confirmed=True,
                final_response_sent=True,
            )
    except (BridgeError, AuthError, LifecycleError) as error:
        raise CapabilityProbeError(str(error)) from None
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=1)


@dataclass(frozen=True)
class CapabilityResult:
    model: str
    reasoning_effort: str | None
    outcome_label: str
    binding: ArtifactBinding | None = None
    allowed: _RunResult | None = None
    excluded: _RunResult | None = None
    authentication_mode: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.outcome_label == "client_executor_capabilities_confirmed"

    def to_public_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": PROBE_SCHEMA,
            "client_kind": "codex",
            "model": self.model,
            "isolation_profile_digest": profile_digest(
                authentication_mode=self.authentication_mode
            ),
            "outcome_label": self.outcome_label,
            "capabilities_confirmed": self.confirmed,
            "real_provider_requests": 0,
            "model_inference_calls": 0,
            "memory_processes_launched": 0,
            "behavioral_slots_created": 0,
            "mock_assistant_answers": sum(
                run.final_response_sent
                for run in (self.allowed, self.excluded)
                if run is not None
            ),
            **_authentication_binding(self.authentication_mode),
        }
        if self.reasoning_effort is not None:
            result["reasoning_effort"] = self.reasoning_effort
        if self.binding is not None:
            result.update(
                client_executable_digest=self.binding.client_executable_digest,
                code_mode_host_digest=self.binding.code_mode_host_digest,
                isolation_profile_digest=self.binding.isolation_profile_digest,
            )
        for label, run in (("allowed", self.allowed), ("excluded", self.excluded)):
            if run is not None:
                result[label] = {
                    "direct_tool_names": list(run.direct),
                    "executor_tool_names": list(run.executor),
                    "stub_call_count": run.stub_calls,
                    "mock_custom_tool_requests": run.mock_calls,
                    "process_restrictions_confirmed": run.guards_confirmed,
                    "mcp_bridge_confirmed": run.bridge_confirmed,
                    "proxy_auth_environment_absent": run.proxy_auth_environment_absent,
                    "proxy_environment_isolated": run.proxy_environment_isolated,
                    "client_completion_confirmed": run.client_completion_confirmed,
                    "endpoint_completion_confirmed": run.endpoint_completion_confirmed,
                    "final_response_sent": run.final_response_sent,
                }
                if self.authentication_mode is not None:
                    details = cast(dict[str, object], result[label])
                    details["proxy_auth_home_denied"] = run.proxy_auth_home_denied
                    details["endpoint_auth_home_denied"] = run.endpoint_auth_home_denied
        return result


def verify_capabilities(
    client: Path,
    *,
    model: str,
    reasoning_effort: str | None = None,
    authentication_mode: str | None = None,
) -> CapabilityResult:
    """Run fresh allowed/excluded proofs, or return a fixed failure receipt."""
    _validate_labels(model, reasoning_effort)
    binding: ArtifactBinding | None = None
    allowed: _RunResult | None = None
    excluded: _RunResult | None = None
    try:
        binding = artifact_binding(client, authentication_mode=authentication_mode)
        client = _executable(client)
        host = _executable(client.parent / "codex-code-mode-host")
        python = _system_python()
        for deny in (False, True):
            run = _run_probe(
                client,
                host,
                python,
                model=model,
                effort=reasoning_effort,
                excluded=deny,
                authentication_mode=authentication_mode,
            )
            if deny:
                excluded = run
            else:
                allowed = run
            if (
                artifact_binding(client, authentication_mode=authentication_mode)
                != binding
            ):
                raise CapabilityProbeError("client_artifact_changed")
        if allowed is None or excluded is None or allowed.direct != excluded.direct:
            raise CapabilityProbeError("probe_profile_mismatch")
        return CapabilityResult(
            model,
            reasoning_effort,
            "client_executor_capabilities_confirmed",
            binding,
            allowed,
            excluded,
            authentication_mode,
        )
    except CapabilityProbeError as error:
        label = str(error)
    except OSError, ValueError, subprocess.SubprocessError:
        label = "capability_probe_unavailable"
    return CapabilityResult(
        model, reasoning_effort, label, binding, allowed, excluded, authentication_mode
    )
