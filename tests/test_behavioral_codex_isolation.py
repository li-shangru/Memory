"""Fresh synthetic capability proof must precede real client execution."""

from __future__ import annotations

import http.client
import importlib.util
import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import ModuleType

import pytest
from playwright._impl._driver import compute_driver_executable

HELPER = Path(__file__).resolve().parents[1] / "tools/behavioral_codex_isolation.py"


@pytest.mark.skipif(
    sys.platform != "darwin", reason="Seatbelt policy is macOS-specific"
)
def test_login_policy_binds_only_the_selected_loopback_callback(tmp_path: Path) -> None:
    module = _module()
    python = module.system_python()
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    source = """import json,socket,sys
def bind(port):
    try:
        with socket.socket() as connection:connection.bind(('127.0.0.1',port));return True
    except PermissionError:return False
print(json.dumps([bind(int(sys.argv[1])),bind(0)]))
"""
    command = module.login_command(
        [str(python), "-I", "-S", "-c", source, str(port)],
        policy_path=tmp_path / "login.sb",
        executable_paths=(python,),
        callback_port=port,
    )
    result = subprocess.run(
        command,
        capture_output=True,
        timeout=5,
        cwd=tmp_path,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == [True, False]


@pytest.mark.skipif(
    sys.platform != "darwin", reason="Seatbelt policy is macOS-specific"
)
@pytest.mark.parametrize("kind", ["proxy", "endpoint"])
def test_subscription_children_cannot_open_credential_homes(
    tmp_path: Path, kind: str
) -> None:
    module = _module()
    python = module.system_python()
    credential_home = tmp_path / "fresh-credential-home"
    credential_home.mkdir(mode=0o700)
    canary = credential_home / "synthetic-canary"
    canary.write_bytes(b"fresh harmless denial fixture")
    public = tmp_path / "public-synthetic-data"
    public.write_bytes(b"allowed")
    source = """import json,sys
try:
    with open(sys.argv[1],'rb'):pass
    denied=False
except PermissionError:denied=True
with open(sys.argv[2],'rb') as stream:allowed=stream.read()==b'allowed'
print(json.dumps([denied,allowed]))
"""
    command = [str(python), "-I", "-S", "-c", source, str(canary), str(public)]
    with (
        tempfile.TemporaryDirectory(
            prefix="m-sub-policy-", dir="/private/tmp"
        ) as temporary,
        socket.socket(socket.AF_UNIX) as server,
    ):
        path = Path(temporary) / "bridge.socket"
        server.bind(str(path))
        if kind == "proxy":
            wrapped = module.proxy_command(
                command,
                policy_path=tmp_path / "proxy.sb",
                executable_paths=(python,),
                bridge_socket=path,
                readable_proxy_files=(public,),
                credential_homes=(credential_home,),
            )
        else:
            wrapped = module.endpoint_command(
                command,
                policy_path=tmp_path / "endpoint.sb",
                credential_homes=(credential_home,),
            )
        result = subprocess.run(
            wrapped,
            capture_output=True,
            timeout=5,
            cwd=tmp_path,
            env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        )
    assert result.returncode == 0
    assert json.loads(result.stdout) == [True, True]


def _module() -> ModuleType:
    name = "behavioral_codex_isolation_test_module"
    spec = importlib.util.spec_from_file_location(name, HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _tools(*extra: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "type": "namespace",
            "name": "functions",
            "tools": [
                {"type": "custom", "name": "exec"},
                {"type": "function", "name": "wait"},
                *extra,
            ],
        }
    ]


def _output(module: ModuleType, *, excluded: bool) -> dict[str, object]:
    return {
        "probe_nonce": "synthetic_nonce",
        "names": [] if excluded else [module.STUB_TOOL_NAME],
        "tool_object_names": [] if excluded else [module.STUB_TOOL_NAME],
        "tool_symbol_count": 0,
        "prototype_kind": "null",
        "prototype_names": [],
        "prototype_symbol_count": 0,
        "callable": "undefined" if excluded else "function",
        "caught": excluded,
        "stub_result": None if excluded else module.STUB_RESULT,
    }


def test_profile_enables_transport_without_replacing_structured_exclusions() -> None:
    module = _module()
    command = module.launch_arguments(
        Path("/synthetic/codex"),
        Path("/synthetic/workspace"),
        model="gpt-6-astra",
        reasoning_effort="max",
    )

    assert "features.code_mode.enabled=true" in command
    assert "suppress_unstable_features_warning=true" in command
    assert "--json" in command
    assert "--enable" not in command or "code_mode" not in [
        command[index + 1]
        for index, argument in enumerate(command[:-1])
        if argument == "--enable"
    ]
    assert "code_mode_host" in command
    assert 'model_reasoning_effort="max"' in command
    assert "sandbox_permissions=[]" not in command
    assert 'shell_environment_policy.inherit="none"' in command
    assert 'cli_auth_credentials_store="file"' in command
    assert "--ignore-user-config" in command
    assert "--ignore-rules" in command
    assert "--strict-config" in command
    assert not any("mcp_servers." in value for value in command)
    exclusions = next(
        value for value in command if "excluded_tool_namespaces=" in value
    )
    assert json.loads(exclusions.split("=", 1)[1]) == [
        "functions",
        "web",
        "clock",
        "collaboration",
    ]


def test_tool_declarations_include_additional_input_items() -> None:
    module = _module()
    assert module._direct_tools(
        {"input": [{"type": "additional_tools", "tools": _tools()}]}
    ) == ("functions.exec", "functions.wait")


@pytest.mark.parametrize(
    "payload",
    [
        {"tools": []},
        {"tools": "invalid"},
        {"tools": _tools(), "input": [{"type": "additional_tools", "tools": _tools()}]},
        {"tools": _tools({"type": "function", "name": "exec_command"})},
        {"tools": [{"type": "function", "name": "web_search"}]},
        {"tools": [{"type": "namespace", "name": "other", "tools": []}]},
        {"tools": _tools({"type": "namespace", "name": "nested", "tools": []})},
        {"tools": _tools({"type": "function", "name": "request_user_input"})},
    ],
)
def test_missing_duplicate_or_extra_direct_tools_fail_closed(
    payload: dict[str, object],
) -> None:
    module = _module()
    with pytest.raises(module.CapabilityProbeError):
        module._direct_tools(payload)


def test_only_named_nonexecutor_input_utility_is_accepted() -> None:
    module = _module()
    assert module._direct_tools(
        {"tools": _tools({"type": "function", "name": "request_user_input_async"})}
    ) == (
        "functions.exec",
        "functions.request_user_input_async",
        "functions.wait",
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"duplicate":1,"duplicate":2}',
        b'{"value":NaN}',
        '{"value":1}'.encode("utf-16"),
    ],
)
def test_transport_requires_unique_utf8_strict_json(raw: bytes) -> None:
    module = _module()
    with pytest.raises(module.CapabilityProbeError):
        module._json(raw)


def _request(nonce: str) -> dict[str, object]:
    return {
        "model": "synthetic-model",
        "reasoning": {"effort": "max"},
        "input": [
            {"type": "additional_tools", "tools": _tools()},
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": nonce}],
            },
        ],
    }


@pytest.mark.parametrize("wrong", ["model", "effort", "auth", "marker"])
def test_request_binding_rejects_other_model_effort_auth_or_prompt(wrong: str) -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    payload = _request(capture.nonce)
    auth = "Bearer " + capture.token
    if wrong == "model":
        payload["model"] = "other-model"
    elif wrong == "effort":
        payload["reasoning"] = {"effort": "low"}
    elif wrong == "auth":
        auth = "Bearer unrelated_synthetic_token"
    else:
        payload["input"] = [{"type": "additional_tools", "tools": _tools()}]
    with pytest.raises(module.CapabilityProbeError):
        capture.accept(json.dumps(payload).encode(), auth)


def test_second_request_requires_the_exact_mock_call_and_output_nonce() -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    payload = _request(capture.nonce)
    assert (
        capture.accept(json.dumps(payload).encode(), "Bearer " + capture.token)
        == "respond"
    )
    payload["input"] = [
        {
            "type": "custom_tool_call_output",
            "call_id": "call_other_synthetic_nonce",
            "output": [
                {
                    "type": "input_text",
                    "text": json.dumps(_output(module, excluded=False)),
                }
            ],
        }
    ]
    with pytest.raises(module.CapabilityProbeError, match="unexpected_wrapper_output"):
        capture.accept(json.dumps(payload).encode(), "Bearer " + capture.token)


@pytest.mark.parametrize("location", ["tools", "additional_tools", "prewarm"])
def test_every_supplied_tool_declaration_rejects_later_native_admission(
    location: str,
) -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    auth = "Bearer " + capture.token
    payload = _request(capture.nonce)
    if location != "prewarm":
        assert capture.accept(json.dumps(payload).encode(), auth) == "respond"
        output = {**_output(module, excluded=False), "probe_nonce": capture.nonce}
        payload["input"] = [
            {
                "type": "custom_tool_call_output",
                "call_id": "call_" + capture.nonce,
                "output": [{"type": "input_text", "text": json.dumps(output)}],
            }
        ]
    else:
        payload["generate"] = False
    forbidden = _tools({"type": "function", "name": "exec_command"})
    if location == "tools":
        payload["tools"] = forbidden
    else:
        inputs = payload["input"]
        assert isinstance(inputs, list)
        inputs.append({"type": "additional_tools", "tools": forbidden})
    with pytest.raises(module.CapabilityProbeError):
        capture.accept(json.dumps(payload).encode(), auth)
    assert not capture.done.is_set()


@pytest.mark.parametrize("repeat", [False, True])
def test_followup_preserves_or_repeats_the_proven_tool_schema(repeat: bool) -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    auth = "Bearer " + capture.token
    payload = _request(capture.nonce)
    assert capture.accept(json.dumps(payload).encode(), auth) == "respond"
    output = {**_output(module, excluded=False), "probe_nonce": capture.nonce}
    payload["input"] = [
        {
            "type": "custom_tool_call_output",
            "call_id": "call_" + capture.nonce,
            "output": [{"type": "input_text", "text": json.dumps(output)}],
        }
    ]
    if repeat:
        payload["tools"] = _tools()
    assert capture.accept(json.dumps(payload).encode(), auth) == "complete"


@pytest.mark.parametrize("change", ["new_allowed_name", "changed_schema", "unchanged"])
def test_late_prewarm_preserves_the_established_direct_schema(change: str) -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    auth = "Bearer " + capture.token
    payload = _request(capture.nonce)
    assert capture.accept(json.dumps(payload).encode(), auth) == "respond"
    tools = _tools()
    if change == "new_allowed_name":
        tools = _tools({"type": "function", "name": "request_user_input_async"})
    elif change == "changed_schema":
        tools = [
            {
                "type": "namespace",
                "name": "functions",
                "tools": [
                    {"type": "custom", "name": "exec", "description": "changed schema"},
                    {"type": "function", "name": "wait"},
                ],
            }
        ]
    payload["input"] = [{"type": "additional_tools", "tools": tools}]
    payload["generate"] = False
    if change == "unchanged":
        assert capture.accept(json.dumps(payload).encode(), auth) == "prewarm"
    else:
        with pytest.raises(
            module.CapabilityProbeError, match="probe_direct_schema_changed"
        ):
            capture.accept(json.dumps(payload).encode(), auth)
    assert not capture.done.is_set()


def _masked_frame(body: bytes) -> bytes:
    mask = b"abcd"
    header = (
        bytes((129, 128 | len(body)))
        if len(body) < 126
        else bytes((129, 254)) + struct.pack("!H", len(body))
    )
    return (
        header
        + mask
        + bytes(value ^ mask[index % 4] for index, value in enumerate(body))
    )


def test_websocket_accepts_only_bounded_masked_text_frames() -> None:
    module = _module()
    body = b'{"synthetic":"request"}'
    assert module._read_websocket(io.BytesIO(_masked_frame(body))) == body
    for frame in (
        bytes((129, 2)) + b"{}",  # Missing client mask.
        bytes((130, 128)) + b"abcd",  # Binary frame.
        bytes((129, 255)) + struct.pack("!Q", module.MAX_BODY + 1),
        _masked_frame(body)[:-1],
    ):
        with pytest.raises(module.CapabilityProbeError):
            module._read_websocket(io.BytesIO(frame))


def test_request_count_and_body_size_are_bounded() -> None:
    module = _module()
    capture = module._Capture("synthetic-model", "max", False)
    capture.request_count = module.MAX_REQUESTS
    with pytest.raises(module.CapabilityProbeError, match="probe_request_limit"):
        capture.accept(b"{}", "Bearer " + capture.token)
    capture.request_count = 0
    with pytest.raises(module.CapabilityProbeError, match="probe_request_limit"):
        capture.accept(b"x" * (module.MAX_BODY + 1), "Bearer " + capture.token)


@pytest.mark.parametrize("excluded", [False, True])
def test_exact_executor_and_dispatch_results_are_required(excluded: bool) -> None:
    module = _module()
    module._validate_wrapper(_output(module, excluded=excluded), excluded=excluded)


@pytest.mark.parametrize(
    "mutation",
    [
        {"names": ["exec_command"]},
        {"names": []},
        {"tool_object_names": ["exec_command"]},
        {"callable": "undefined"},
        {"caught": True},
        {"stub_result": {"isError": True}},
        {"unexpected": "private output must not be reflected"},
    ],
)
def test_allowed_wrapper_rejects_native_tools_and_incomplete_dispatch(
    mutation: dict[str, object],
) -> None:
    module = _module()
    output = {**_output(module, excluded=False), **mutation}
    with pytest.raises(module.CapabilityProbeError):
        module._validate_wrapper(output, excluded=False)


@pytest.mark.parametrize(
    "mutation",
    [
        {"names": ["mcp__memory_behavioral_acceptance__probe_status"]},
        {"tool_object_names": ["mcp__memory_behavioral_acceptance__probe_status"]},
        {"callable": "function"},
        {"caught": False},
        {"stub_result": {}},
    ],
)
def test_excluded_wrapper_must_have_no_executor_or_dispatch(
    mutation: dict[str, object],
) -> None:
    module = _module()
    with pytest.raises(module.CapabilityProbeError):
        module._validate_wrapper(
            {**_output(module, excluded=True), **mutation}, excluded=True
        )


def _evaluate_wrapper(
    module: ModuleType,
    tmp_path: Path,
    mode: str,
) -> dict[str, object]:
    node, _driver = compute_driver_executable()
    script = (
        "let native_calls = 0; let captured; "
        "const native = async () => { native_calls++; }; "
        "const tools = " + ("Object.create(null)" if mode == "null" else "{}") + "; "
        "tools["
        + json.dumps(module.STUB_TOOL_NAME)
        + "] = async () => ("
        + json.dumps(module.STUB_RESULT)
        + "); "
        "const ALL_TOOLS = [{name:" + json.dumps(module.STUB_TOOL_NAME) + "}]; "
        "const text = value => { captured = value; }; "
    )
    if mode == "non_enumerable":
        script += "Object.defineProperty(tools, 'exec_command', {value:native, enumerable:false}); "
    elif mode == "inherited":
        script += "Object.setPrototypeOf(tools, {exec_command:native}); "
    elif mode == "ordinary_pollution":
        script += "Object.defineProperty(Object.prototype, 'exec_command', {value:native, enumerable:false}); "
    elif mode == "symbol":
        script += "tools[Symbol('synthetic_hidden_tool')] = native; "
    script += module._wrapper_code("synthetic_nonce")
    script += "process.stdout.write(JSON.stringify({captured, native_calls}));"
    completed = subprocess.run(
        [node, "--input-type=module", "-"],
        input=script,
        text=True,
        cwd=tmp_path,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["native_calls"] == 0
    output = result["captured"]
    assert isinstance(output, dict)
    return output


@pytest.mark.parametrize(
    "mode", ["non_enumerable", "inherited", "ordinary_pollution", "symbol"]
)
def test_wrapper_rejects_hidden_executor_properties_without_invoking_them(
    tmp_path: Path,
    mode: str,
) -> None:
    module = _module()
    output = _evaluate_wrapper(module, tmp_path, mode)
    with pytest.raises(module.CapabilityProbeError):
        module._validate_wrapper(output, excluded=False)


@pytest.mark.parametrize("mode", ["ordinary", "null"])
def test_wrapper_accepts_plain_or_null_prototype_tool_objects(
    tmp_path: Path,
    mode: str,
) -> None:
    module = _module()
    output = _evaluate_wrapper(module, tmp_path, mode)
    module._validate_wrapper(output, excluded=False)


def test_probe_environment_never_inherits_auth_or_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    for key in (
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "HTTPS_PROXY",
        "CODEX_HOME",
    ):
        monkeypatch.setenv(key, "SYNTHETIC_DO_NOT_INHERIT")
    environment = module._probe_environment(tmp_path, "synthetic_fresh_token")

    assert environment["CODEX_API_KEY"] == "synthetic_fresh_token"
    assert "SYNTHETIC_DO_NOT_INHERIT" not in json.dumps(environment)
    assert set(environment) == {
        "HOME",
        "CODEX_HOME",
        "PATH",
        "LANG",
        "TMPDIR",
        "CODEX_API_KEY",
    }


def test_subscription_profile_requires_chatgpt_cache_and_no_auth_environment(
    tmp_path: Path,
) -> None:
    module = _module()
    command = module.launch_arguments(
        Path("/synthetic/codex"),
        tmp_path,
        model="synthetic-model",
        authentication_mode="chatgpt_subscription",
    )
    assert 'forced_login_method="chatgpt"' in command
    from behavioral_codex_auth import pin_public_ca_bundle

    public_ca_bundle = pin_public_ca_bundle(tmp_path)
    environment = module._probe_environment(
        tmp_path,
        "synthetic_unused_api_token",
        authentication_mode="chatgpt_subscription",
        public_ca_bundle=public_ca_bundle,
    )
    assert environment["CODEX_CA_CERTIFICATE"] == str(public_ca_bundle)
    assert (
        not {"CODEX_API_KEY", "OPENAI_API_KEY", "CODEX_ACCESS_TOKEN"}
        & environment.keys()
    )
    assert (
        module.profile_digest(authentication_mode="chatgpt_subscription")
        != module.profile_digest()
    )


def test_subscription_profile_binds_public_ca_bytes_only_for_subscription(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    subscription = module.profile_digest(authentication_mode="chatgpt_subscription")
    legacy = module.profile_digest()
    import behavioral_codex_auth

    monkeypatch.setattr(behavioral_codex_auth, "public_ca_digest", lambda: "f" * 64)
    assert (
        module.profile_digest(authentication_mode="chatgpt_subscription")
        != subscription
    )
    assert module.profile_digest() == legacy
    assert "public_ca_bundle_digest" not in module._authentication_binding(None)


@pytest.mark.parametrize(
    "action", ["overwrite", "unlink", "replace", "parent_replace", "hardlink"]
)
def test_login_public_ca_bytes_and_parent_identity_cannot_be_changed(
    tmp_path: Path, action: str
) -> None:
    module = _module()
    python = module.system_python()
    scope = tmp_path / "fresh-auth-scope"
    scope.mkdir(mode=0o700)
    pinned = scope / "public-ca.pem"
    pinned.write_bytes(b"fresh synthetic public certificate fixture")
    pinned.chmod(0o600)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"synthetic changed material")
    source = """import json,os,pathlib,sys
bundle=pathlib.Path(os.environ['CODEX_CA_CERTIFICATE'])
readable=bundle.read_bytes()==b'fresh synthetic public certificate fixture'
try:
    if sys.argv[1]=='overwrite':bundle.write_bytes(b'synthetic changed bytes')
    elif sys.argv[1]=='unlink':bundle.unlink()
    elif sys.argv[1]=='replace':os.replace(sys.argv[2],bundle)
    elif sys.argv[1]=='parent_replace':os.rename(bundle.parent,str(bundle.parent)+'-moved')
    elif sys.argv[1]=='hardlink':os.link(bundle,str(bundle)+'-alias')
    denied=False
except PermissionError:denied=True
print(json.dumps([readable,denied]))
"""
    command = module.login_command(
        [str(python), "-I", "-S", "-c", source, action, str(replacement)],
        policy_path=tmp_path / "pinned-ca.sb",
        executable_paths=(python,),
        callback_port=None,
        public_ca_bundle=pinned,
    )
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        env={
            "HOME": str(tmp_path),
            "PATH": "/usr/bin:/bin",
            "CODEX_CA_CERTIFICATE": str(pinned),
        },
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == [True, True]
    assert pinned.read_bytes() == b"fresh synthetic public certificate fixture"


@pytest.mark.parametrize(
    "path", ["/v1/models?client_version=synthetic", "/v1/api/codex/settings/user"]
)
@pytest.mark.parametrize("authenticated", [True, False])
def test_subscription_metadata_requests_are_bounded_and_do_not_invent_models(
    path: str, authenticated: bool
) -> None:
    module = _module()
    capture = module._Capture(
        "synthetic-model", "max", False, authentication_mode="chatgpt_subscription"
    )
    server = module._Server(("127.0.0.1", 0), module._handler(capture))
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=2
        )
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Authorization": "Bearer "
                    + (capture.token if authenticated else "synthetic_wrong_token")
                },
            )
            response = connection.getresponse()
            assert response.status == 404
            assert response.read() == b""
        finally:
            connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    assert capture.metadata_requests == 1
    assert capture.mock_calls == 0
    assert capture.direct == ()
    assert capture.failure == (
        None if authenticated else "unexpected_probe_metadata_request"
    )


def test_binding_rehashes_the_exact_executable_and_neighboring_host(
    tmp_path: Path,
) -> None:
    module = _module()
    client = tmp_path / "codex"
    host = tmp_path / "codex-code-mode-host"
    client.write_text("synthetic client", encoding="utf-8")
    host.write_text("synthetic host", encoding="utf-8")
    client.chmod(0o700)
    host.chmod(0o700)
    first = module.artifact_binding(client)
    host.write_text("changed synthetic host", encoding="utf-8")
    second = module.artifact_binding(client)

    assert first.client_executable_digest == second.client_executable_digest
    assert first.code_mode_host_digest != second.code_mode_host_digest
    assert first.isolation_profile_digest == module.profile_digest()


def test_system_python_admits_the_actual_framework_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    framework = tmp_path / "Python3.framework/Versions/3.9"
    launcher = framework / "bin/python3.9"
    executable = framework / "Resources/Python.app/Contents/MacOS/Python"
    executable.parent.mkdir(parents=True)
    executable.write_text("synthetic interpreter", encoding="utf-8")

    def resolve(path: Path) -> Path:
        return executable if path == executable else launcher

    monkeypatch.setattr(module, "_executable", resolve)
    assert module._system_python() == executable
    assert module.system_python() == executable


def test_profile_binds_shared_policy_and_bridge_transport_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    original = module.profile_digest()
    monkeypatch.setattr(module, "_file_digest", lambda _path: "a" * 64)
    changed_policy = module.profile_digest()
    assert changed_policy != original
    monkeypatch.setattr(module, "_bridge_transport_digest", lambda: "b" * 64)
    assert module.profile_digest() != changed_policy


def test_profile_binds_endpoint_environment_implementation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    original = module.profile_digest()
    monkeypatch.setattr(
        module, "_endpoint_implementation_digest", lambda: "e" * 64, raising=False
    )
    assert module.profile_digest() != original


def test_execution_policy_allows_exact_proxy_and_denies_synthetic_store_and_peers(
    tmp_path: Path,
) -> None:
    module = _module()
    python = module._system_python()
    memory_home = tmp_path / "synthetic-store"
    memory_home.mkdir()
    canary = memory_home / "synthetic-state"
    canary.write_bytes(b"fresh synthetic Store denial canary")
    proxy = tmp_path / "synthetic-proxy"
    proxy.write_bytes(b"fresh synthetic proxy material")
    endpoint_root = tmp_path / "fresh-endpoint"
    endpoint_root.mkdir(mode=0o700)
    endpoint_canary = endpoint_root / "synthetic-bootstrap"
    endpoint_canary.write_bytes(b"fresh synthetic bootstrap marker")
    with tempfile.TemporaryDirectory(
        prefix="memory-policy-", dir="/private/tmp"
    ) as raw:
        socket_root = Path(raw)
        allowed_socket, denied_socket = socket_root / "a", socket_root / "b"
        with (
            socket.socket(socket.AF_UNIX) as allowed,
            socket.socket(socket.AF_UNIX) as denied,
        ):
            for listener, path in ((allowed, allowed_socket), (denied, denied_socket)):
                listener.bind(str(path))
                listener.listen(4)
                with socket.socket(socket.AF_UNIX) as control:
                    control.connect(str(path))
            script = """import json,socket,subprocess,sys
def readable(path):
    try:
        with open(path,"rb") as stream:stream.read(1)
        return True
    except PermissionError:return False
def connect(path):
    try:
        with socket.socket(socket.AF_UNIX) as stream:stream.connect(path)
        return True
    except PermissionError:return False
def writable(path):
    try:
        with open(path,"wb") as stream:stream.write(b"fresh synthetic mutation")
        return True
    except PermissionError:return False
try:
    subprocess.run(["/usr/bin/true"],check=True)
    exec_denied=False
except PermissionError:exec_denied=True
print(json.dumps({"proxy":readable(sys.argv[1]),"store_denied":not readable(sys.argv[2]),"socket":connect(sys.argv[3]),"peer_denied":not connect(sys.argv[4]),"exec_denied":exec_denied,"endpoint_read_denied":not readable(sys.argv[5]),"endpoint_write_denied":not writable(sys.argv[6])}))
"""
            policy = tmp_path / "execution.sb"
            command = module.execution_command(
                [
                    str(python),
                    "-I",
                    "-S",
                    "-c",
                    script,
                    str(proxy),
                    str(canary),
                    str(allowed_socket),
                    str(denied_socket),
                    str(endpoint_canary),
                    str(endpoint_root / "unexpected-file"),
                ],
                policy_path=policy,
                executable_paths=(python,),
                bridge_socket=allowed_socket,
                readable_proxy_files=(proxy,),
                memory_home=memory_home,
                endpoint_environment_root=endpoint_root,
            )
            completed = subprocess.run(
                command,
                cwd=tmp_path,
                env=module._probe_environment(tmp_path, "synthetic_only"),
                capture_output=True,
                timeout=5,
            )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "proxy": True,
        "store_denied": True,
        "socket": True,
        "peer_denied": True,
        "exec_denied": True,
        "endpoint_read_denied": True,
        "endpoint_write_denied": True,
    }
    source = policy.read_text(encoding="utf-8")
    assert '(remote tcp "*:443")' in source
    assert '(literal "/private/var/run/mDNSResponder")' in source
    assert '(subpath "/Users")' in source
    assert '(subpath "/private/etc/codex")' in source
    assert '(subpath "/Library/Managed Preferences")' in source
    assert "com.apple.securityd" in source
    for root in module.KEYCHAIN_FILESYSTEM_ROOTS:
        assert f'(deny file-read* file-write* (subpath "{root}"))' in source


def test_protected_proxy_read_exception_is_exact_inside_synthetic_owner_rule(
    tmp_path: Path,
) -> None:
    module = _module()
    python = module._system_python()
    fixture = tmp_path / "synthetic-owner-mirror"
    fixture.mkdir()
    proxy, peer = fixture / "proxy", fixture / "peer"
    for path in (proxy, peer):
        path.write_bytes(b"fresh synthetic bytes")
    script = """import json,sys
results=[]
for path in sys.argv[1:]:
    try:
        with open(path,"rb") as stream:stream.read(1)
        results.append(True)
    except PermissionError:results.append(False)
print(json.dumps(results))
"""
    command = module.protected_command(
        [str(python), "-I", "-S", "-c", script, str(proxy), str(peer)],
        policy_path=tmp_path / "proxy-read.sb",
        executable_paths=(python,),
        readable_proxy_files=(proxy,),
        denied_fixture=fixture,
    )
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        env=module._probe_environment(tmp_path, "synthetic_only"),
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == [True, False]


def test_proxy_material_cannot_bypass_the_explicit_store_denial(tmp_path: Path) -> None:
    module = _module()
    memory_home = tmp_path / "synthetic-store"
    memory_home.mkdir()
    proxy = memory_home / "misplaced-proxy"
    proxy.write_bytes(b"fresh synthetic bytes")
    with pytest.raises(module.CapabilityProbeError, match="invalid_process_policy"):
        module.execution_command(
            ["/usr/bin/true"],
            policy_path=tmp_path / "refused.sb",
            executable_paths=(Path("/usr/bin/true"),),
            bridge_socket=tmp_path / "socket",
            readable_proxy_files=(proxy,),
            memory_home=memory_home,
        )
    assert not (tmp_path / "refused.sb").exists()


@pytest.mark.parametrize("launch", ["probe", "execution"])
@pytest.mark.parametrize(
    "action",
    [
        "overwrite",
        "unlink",
        "replace",
        "parent_replace",
        "ancestor_replace",
        "hardlink_write",
    ],
)
def test_proxy_material_stays_readable_and_immutable_in_both_launch_paths(
    tmp_path: Path,
    launch: str,
    action: str,
) -> None:
    module = _module()
    python = module.system_python()
    workspace = tmp_path / "synthetic-workspace"
    material = workspace / "synthetic-proxy-material"
    material.mkdir(parents=True)
    proxy, credential = material / "proxy.py", material / "session"
    expected = b"fresh synthetic immutable material"
    for path in (proxy, credential):
        path.write_bytes(expected)
    memory_home = tmp_path / "synthetic-store"
    memory_home.mkdir()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"fresh synthetic replacement bytes")
    new_material = tmp_path / "new-material"
    new_material.mkdir()
    (new_material / "proxy.py").write_bytes(b"fresh synthetic replaced material")
    new_workspace = tmp_path / "new-workspace"
    (new_workspace / material.name).mkdir(parents=True)
    (new_workspace / material.name / "proxy.py").write_bytes(
        b"fresh synthetic replaced ancestor"
    )
    script = """import json,os,pathlib,sys
root=pathlib.Path(sys.argv[1])
workspace=root/"synthetic-workspace"
material=workspace/"synthetic-proxy-material"
proxy=material/"proxy.py"
action=sys.argv[2]
readable=proxy.read_bytes()==b"fresh synthetic immutable material"
try:
    if action=="overwrite":proxy.write_bytes(b"unexpected changed bytes")
    elif action=="unlink":proxy.unlink()
    elif action=="replace":os.replace(root/"replacement",proxy)
    elif action=="parent_replace":
        os.rename(material,root/"old-material")
        os.rename(root/"new-material",material)
    elif action=="ancestor_replace":
        os.rename(workspace,root/"old-workspace")
        os.rename(root/"new-workspace",workspace)
    elif action=="hardlink_write":
        alias=root/"linked-proxy"
        os.link(proxy,alias)
        alias.write_bytes(b"unexpected changed inode bytes")
    blocked=False
except PermissionError:blocked=True
print(json.dumps({"readable":readable,"blocked":blocked}))
"""
    with tempfile.TemporaryDirectory(
        prefix="memory-policy-", dir="/private/tmp"
    ) as raw:
        bridge_socket = Path(raw) / "s"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(bridge_socket))
            listener.listen(1)
            wrap = (
                module.protected_command
                if launch == "probe"
                else module.execution_command
            )
            command = wrap(
                [str(python), "-I", "-S", "-c", script, str(tmp_path), action],
                policy_path=tmp_path / "immutable.sb",
                executable_paths=(python,),
                bridge_socket=bridge_socket,
                readable_proxy_files=(proxy, credential),
                memory_home=memory_home,
            )
            completed = subprocess.run(
                command,
                cwd=tmp_path,
                env=module._probe_environment(tmp_path, "synthetic_only"),
                capture_output=True,
                timeout=5,
            )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {"readable": True, "blocked": True}
    assert proxy.read_bytes() == expected
    assert credential.read_bytes() == expected


def test_offline_policy_is_shared_and_refuses_overwriting_existing_file(
    tmp_path: Path,
) -> None:
    module = _module()
    policy = tmp_path / "policy.sb"
    command = module.protected_command(
        ["/usr/bin/true"],
        policy_path=policy,
        executable_paths=[Path("/usr/bin/true")],
    )
    assert command[:3] == ["/usr/bin/sandbox-exec", "-f", str(policy)]
    source = policy.read_text(encoding="utf-8")
    assert "(deny network*)" in source
    assert '(subpath "/Users")' in source
    assert '(subpath "/private/etc/codex")' in source
    assert '(subpath "/Library/Managed Preferences")' in source
    assert "com.apple.securityd" in source
    assert policy.stat().st_mode & 0o777 == 0o600
    with pytest.raises(module.CapabilityProbeError):
        module.protected_command(
            ["/usr/bin/true"],
            policy_path=policy,
            executable_paths=[Path("/usr/bin/true")],
        )


def test_keychain_roots_are_denied_as_files_without_inspecting_them(
    tmp_path: Path,
) -> None:
    module = _module()
    policy = tmp_path / "keychain-denial.sb"
    module.protected_command(
        ["/usr/bin/true"],
        policy_path=policy,
        executable_paths=[Path("/usr/bin/true")],
    )
    source = policy.read_text(encoding="utf-8")
    for root in (
        "/Library/Keychains",
        "/System/Library/Keychains",
        "/Network/Library/Keychains",
        "/private/var/root/Library/Keychains",
        "/private/var/Keychains",
        "/private/var/db/SystemKeys",
        "/private/var/db/SystemKey",
    ):
        assert f'(deny file-read* file-write* (subpath "{root}"))' in source


def test_keychain_rule_blocks_only_fresh_synthetic_mirrors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    mirrors = (
        tmp_path / "synthetic-library-keychains",
        tmp_path / "synthetic-system-keys",
    )
    for mirror in mirrors:
        mirror.mkdir()
        (mirror / "synthetic-keychain").write_bytes(b"fresh synthetic test bytes")
    monkeypatch.setattr(module, "KEYCHAIN_FILESYSTEM_ROOTS", tuple(map(str, mirrors)))
    python = module._system_python()
    script = """import json,sys
denied=[]
for path in sys.argv[1:]:
    try:
        with open(path,"rb") as stream:stream.read(1)
        denied.append(False)
    except PermissionError:denied.append(True)
print(json.dumps(denied))
"""
    command = module.protected_command(
        [
            str(python),
            "-I",
            "-S",
            "-c",
            script,
            *[str(mirror / "synthetic-keychain") for mirror in mirrors],
        ],
        policy_path=tmp_path / "synthetic-keychain-policy.sb",
        executable_paths=[python],
    )
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        env=module._probe_environment(tmp_path, "synthetic_only"),
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == [True, True]


def test_unsupported_platform_fails_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.sys, "platform", "unsupported_synthetic_platform")
    with pytest.raises(module.CapabilityProbeError, match="platform_unavailable"):
        module.protected_command(
            ["/usr/bin/true"],
            policy_path=tmp_path / "policy.sb",
            executable_paths=[Path("/usr/bin/true")],
        )


def test_public_failure_is_content_free(tmp_path: Path) -> None:
    module = _module()
    result = module.verify_capabilities(
        tmp_path / "synthetic_private_path_no_executable", model="synthetic-model"
    )
    public: dict[str, object] = result.to_public_dict()
    encoded = json.dumps(public)
    assert result.confirmed is False
    assert public["schema"] == "memory.behavioral-capability-probe.v1"
    assert public["model_inference_calls"] == 0
    assert public["memory_processes_launched"] == 0
    assert public["behavioral_slots_created"] == 0
    assert str(tmp_path) not in encoded
    assert "synthetic_private_path" not in encoded
    assert os.environ.get("CODEX_API_KEY", "unavailable_secret") not in encoded


def test_cleanup_tolerates_darwin_permission_denial_only_after_leader_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    process = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
    assert process.wait(timeout=5) == 0

    def denied(_pid: int, _signal: int) -> None:
        raise PermissionError("synthetic already-exited process group")

    monkeypatch.setattr(module.os, "killpg", denied)
    module._stop_process(process)
    monkeypatch.setattr(process, "poll", lambda: None)
    with pytest.raises(PermissionError):
        module._stop_process(process)


def test_cleanup_refuses_exited_leader_with_a_surviving_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    python = module.system_python()
    source = "import subprocess,sys;subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
    process = subprocess.Popen(
        [str(python), "-I", "-S", "-c", source], start_new_session=True
    )
    assert process.wait(timeout=5) == 0
    actual_killpg = os.killpg

    def denied(_pid: int, _signal: int) -> None:
        raise PermissionError("synthetic signaling failure with surviving child")

    try:
        monkeypatch.setattr(module.os, "killpg", denied)
        with pytest.raises(PermissionError):
            module._stop_process(process)
    finally:
        actual_killpg(process.pid, 9)


@pytest.mark.skipif(
    sys.platform != "darwin", reason="Seatbelt policy is macOS-specific"
)
def test_one_policy_rechecks_signing_identity_after_child_exec(tmp_path: Path) -> None:
    module = _module()
    python = module.system_python()
    home = tmp_path / "credential-home"
    home.mkdir(mode=0o700)
    canary = home / "fresh-canary"
    canary.write_bytes(b"fresh harmless fixture")
    source = """import subprocess,sys
with open(sys.argv[1],'rb'):pass
child=subprocess.run(['/bin/cat',sys.argv[1]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(child.returncode)
"""
    command = module.protected_command(
        [str(python), "-I", "-S", "-c", source, str(canary)],
        policy_path=tmp_path / "credential-policy.sb",
        executable_paths=(python, Path("/bin/cat")),
        credential_homes=(home,),
        credential_client=python,
    )
    result = subprocess.run(
        command,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == b"1"


def _fake_client(tmp_path: Path, module: ModuleType, *, mode: str) -> Path:
    """A protocol fixture, not a substitute for the installed Code Mode smoke."""
    executable = tmp_path / "synthetic-client"
    source = """import json,os,pathlib,subprocess,sys,time,urllib.request
MODE=FIXTURE_MODE
def emit(value):print(json.dumps(value),flush=True)
emit({'type':'thread.started','thread_id':'synthetic-thread'})
emit({'type':'turn.started'})
settings={}
for index,value in enumerate(sys.argv[:-1]):
    if value=="-c":
        key,raw=sys.argv[index+1].split("=",1)
        settings[key]=json.loads(raw)
if MODE=="timeout":time.sleep(60)
model=sys.argv[sys.argv.index("--model")+1]
nonce=sys.stdin.read().strip().split()[-1]
if settings.get("forced_login_method")=="chatgpt":
    assert not any(name in os.environ for name in ("CODEX_API_KEY","OPENAI_API_KEY","CODEX_ACCESS_TOKEN"))
    cache=json.loads((pathlib.Path(os.environ["CODEX_HOME"])/"auth.json").read_bytes())
    assert cache['auth_mode']=='chatgpt'
    token=cache['tokens']['access_token']
    base_url=settings['chatgpt_base_url']
else:
    token=os.environ['CODEX_API_KEY']
    base_url=settings['openai_base_url']
assert token.startswith("synthetic_")
assert "OPENAI_API_KEY" not in os.environ
assert "HTTPS_PROXY" not in os.environ
namespace="memory_behavioral_acceptance"
tool_name="mcp__memory_behavioral_acceptance__probe_status"
excluded="mcp__memory_behavioral_acceptance" in settings["features.code_mode.excluded_tool_namespaces"]
proxy_environment={key:value for key,value in os.environ.items() if key not in {"CODEX_API_KEY","OPENAI_API_KEY","ANTHROPIC_API_KEY","CLAUDE_CODE_OAUTH_TOKEN"}}
proxy_command=[settings["mcp_servers."+namespace+".command"],*settings["mcp_servers."+namespace+".args"]]
if MODE=="proxy_auth_leak":
    proxy_environment["CODEX_API_KEY"]="synthetic_prohibited_proxy_credential"
    proxy_command=proxy_command[proxy_command.index('-I')-1:]
stub=subprocess.Popen(proxy_command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,env=proxy_environment)
def rpc(method,params,rid):
    stub.stdin.write((json.dumps({"jsonrpc":"2.0","id":rid,"method":method,"params":params})+"\\n").encode())
    stub.stdin.flush()
    return json.loads(stub.stdout.readline())["result"]
rpc("initialize",{"protocolVersion":"2025-06-18"},1)
rpc("tools/list",{},2)
tools=[{"type":"namespace","name":"functions","tools":[{"type":"custom","name":"exec"},{"type":"function","name":"wait"}]}]
payload={"model":model,"reasoning":{"effort":settings["model_reasoning_effort"]},"input":[{"type":"additional_tools","tools":tools},{"type":"message","role":"user","content":[{"type":"input_text","text":nonce}]}]}
def post(payload):
    request=urllib.request.Request(base_url+"/responses",data=json.dumps(payload).encode(),headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
    with urllib.request.urlopen(request,timeout=5) as response:return response.read()
response=post(payload)
assert b"custom_tool_call" in response
stub_result=None if excluded else rpc("tools/call",{"name":"probe_status","arguments":{}},3)
names=[] if excluded else [tool_name]
if MODE=="native_inventory":names.append("exec_command")
output={"probe_nonce":nonce,"names":names,"tool_object_names":names,"tool_symbol_count":0,"prototype_kind":"null","prototype_names":[],"prototype_symbol_count":0,"callable":"undefined" if excluded else "function","caught":excluded,"stub_result":stub_result}
payload["input"]=[{"type":"custom_tool_call_output","call_id":"call_"+nonce,"output":[{"type":"input_text","text":json.dumps(output)}]}]
try:response=post(payload)
except Exception:time.sleep(60);raise
events=[json.loads(line[6:]) for line in response.decode().splitlines() if line.startswith('data: ')]
final=events[-1]['response']['output'][0]['content'][0]['text']
emit({'type':'item.completed','item':{'type':'agent_message','id':'synthetic-final','text':final}})
emit({'type':'turn.completed','usage':{}})
stub.kill();stub.wait()
""".replace("FIXTURE_MODE", repr(mode))
    executable.write_text(
        "#!" + str(module._system_python()) + "\n" + source, encoding="utf-8"
    )
    executable.chmod(0o700)
    host = tmp_path / "codex-code-mode-host"
    host.write_text("synthetic unused host artifact", encoding="utf-8")
    host.chmod(0o700)
    return executable


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("success", "client_executor_capabilities_confirmed"),
        ("native_inventory", "unexpected_executor_tool"),
        ("timeout", "client_probe_timeout"),
        ("proxy_auth_leak", "bridge_proxy_credentials_present"),
    ],
)
def test_synthetic_protocol_runs_are_bounded_and_remove_disposable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: str,
) -> None:
    module = _module()
    client = _fake_client(tmp_path, module, mode=mode)
    original = tempfile.TemporaryDirectory
    roots: list[Path] = []

    def temporary(*, prefix: str, dir: str) -> tempfile.TemporaryDirectory[str]:
        context = original(prefix=prefix, dir=dir)
        roots.append(Path(context.name))
        return context

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", temporary)
    monkeypatch.setattr(module, "RUN_TIMEOUT_SECONDS", 1)
    monkeypatch.setenv("OPENAI_API_KEY", "SYNTHETIC_REAL_AUTH_MUST_NOT_PROPAGATE")
    monkeypatch.setenv("HTTPS_PROXY", "SYNTHETIC_PROXY_MUST_NOT_PROPAGATE")
    result = module.verify_capabilities(
        client, model="synthetic-model", reasoning_effort="max"
    )
    assert result.outcome_label == expected
    assert result.confirmed is (mode == "success")
    assert len(roots) == (2 if mode == "success" else 1)
    assert all(not root.exists() for root in roots)
    public = result.to_public_dict()
    assert public["model_inference_calls"] == 0
    assert public["memory_processes_launched"] == 0
    if mode == "success":
        assert public["allowed"]["stub_call_count"] == 1
        assert public["excluded"]["stub_call_count"] == 0
        for run in ("allowed", "excluded"):
            assert public[run]["mcp_bridge_confirmed"] is True
            assert public[run]["proxy_auth_environment_absent"] is True
            assert public[run]["client_completion_confirmed"] is True
            assert public[run]["endpoint_completion_confirmed"] is True
            assert public[run]["final_response_sent"] is True
        assert public["mock_assistant_answers"] == 2


def test_fresh_verification_rejects_host_changes_between_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    client = _fake_client(tmp_path, module, mode="success")
    run_count = 0

    def changed(*_args: object, **_kwargs: object) -> object:
        nonlocal run_count
        run_count += 1
        (tmp_path / "codex-code-mode-host").write_text(
            "changed synthetic host", encoding="utf-8"
        )
        return module._RunResult(
            ("functions.exec", "functions.wait"), (module.STUB_TOOL_NAME,), 1, 1, True
        )

    monkeypatch.setattr(module, "_run_probe", changed)
    result = module.verify_capabilities(
        client, model="synthetic-model", reasoning_effort="max"
    )
    assert result.outcome_label == "client_artifact_changed"
    assert result.confirmed is False
    assert run_count == 1


def test_subscription_protocol_refuses_a_client_without_distinct_signing_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    client = _fake_client(tmp_path, module, mode="success")
    monkeypatch.setenv("CODEX_API_KEY", "SYNTHETIC_AUTH_MUST_NOT_PROPAGATE")
    result = module.verify_capabilities(
        client,
        model="synthetic-model",
        reasoning_effort="max",
        authentication_mode="chatgpt_subscription",
    )
    assert not result.confirmed
    assert result.outcome_label == "credential_client_identity_unconfirmed"
    receipt = result.to_public_dict()
    assert receipt["authentication_mode"] == "chatgpt_subscription"
    assert len(receipt["authentication_adapter_digest"]) == 64
    assert "allowed" not in receipt
