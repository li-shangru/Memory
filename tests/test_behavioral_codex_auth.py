"""Opaque fresh subscription credentials never become campaign evidence."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from behavioral_codex_auth import ScopedSession

HELPER = Path(__file__).resolve().parents[1] / "tools/behavioral_codex_auth.py"
ISOLATION = HELPER.with_name("behavioral_codex_isolation.py")


def _module() -> ModuleType:
    name = "behavioral_codex_auth_test_module"
    spec = importlib.util.spec_from_file_location(name, HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _python() -> Path:
    name = "behavioral_codex_auth_test_isolation"
    spec = importlib.util.spec_from_file_location(name, ISOLATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return cast(Path, module.system_python())


def _client(tmp_path: Path, *, mode: str = "success") -> Path:
    client = tmp_path / "synthetic-codex"
    source = """import json,os,pathlib,subprocess,sys,time
MODE=FIXTURE_MODE
assert not any(key in os.environ for key in ("CODEX_API_KEY","OPENAI_API_KEY","CODEX_ACCESS_TOKEN","ANTHROPIC_API_KEY","CLAUDE_CODE_OAUTH_TOKEN","HTTPS_PROXY"))
home=pathlib.Path(os.environ["CODEX_HOME"])
assert str(home)==os.environ["HOME"]
public_ca=pathlib.Path(os.environ["CODEX_CA_CERTIFICATE"])
assert public_ca.parent==home.parent
assert b'BEGIN CERTIFICATE' in public_ca.read_bytes()
try:
    public_ca.open('ab')
    raise AssertionError('pinned public CA bytes were writable')
except PermissionError:pass
try:
    public_ca.parent.rename(str(public_ca.parent)+'-moved')
    raise AssertionError('pinned public CA parent was replaceable')
except PermissionError:pass
assert 'forced_login_method="chatgpt"' in sys.argv
assert 'cli_auth_credentials_store="file"' in sys.argv
if "status" in sys.argv:
    if not (home/"auth.json").is_file():raise SystemExit(1)
    if MODE=="status_child":
        child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (home/'synthetic-status-child.pid').write_text(str(child.pid))
    print("Logged in using an API key" if MODE=="api_status" else "Logged in using ChatGPT")
elif MODE=="wait":time.sleep(60)
else:
    (home/"auth.json").write_bytes(b"opaque fresh synthetic credential bytes")
    (home/"auth.json").chmod(0o600)
    print("Synthetic owner sign-in completed.")
""".replace("FIXTURE_MODE", repr(mode))
    client.write_text("#!" + str(_python()) + "\n" + source, encoding="utf-8")
    client.chmod(0o700)
    return client


def _allow_fixture_interpreter(
    module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    python = _python()

    def executables(client: Path, *, browser: bool) -> tuple[Path, ...]:
        del browser
        return client, python

    monkeypatch.setattr(module, "_client_executables", executables)


def _ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, ScopedSession]:
    module = _module()
    _allow_fixture_interpreter(module, monkeypatch)
    session = cast("ScopedSession", module.create_session(tmp_path, _client(tmp_path)))
    with module.start_login(session) as attempt:
        assert attempt.wait(timeout=5)
        attempt.finish()
    module.validate_session(session)
    return module, session


def test_create_allocates_exclusive_private_roots_without_authentication(
    tmp_path: Path,
) -> None:
    module = _module()
    client = _client(tmp_path)
    first = module.create_session(tmp_path, client)
    second = module.create_session(tmp_path, client)
    assert first.root != second.root
    assert first.session_id != second.session_id
    assert first.root.stat().st_mode & 0o777 == 0o700
    assert first.home.stat().st_mode & 0o777 == 0o700
    assert not (first.home / "auth.json").exists()
    assert module.load_session(first.root, client) == first
    with pytest.raises(module.AuthError, match="subscription_auth_not_ready"):
        module.validate_session(first)


def test_foreign_and_saved_home_paths_are_rejected_before_file_access(
    tmp_path: Path,
) -> None:
    module = _module()
    client = _client(tmp_path)
    for root in (Path("/Users") / "synthetic-owner" / ".codex", tmp_path):
        with pytest.raises(module.AuthError, match="subscription_session_invalid"):
            module.load_session(root, client)


def test_login_uses_only_new_scope_and_exposes_no_provider_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "HTTPS_PROXY",
    ):
        monkeypatch.setenv(name, "SYNTHETIC_MUST_NOT_INHERIT")
    module, session = _ready(tmp_path, monkeypatch)
    assert session.root == module.load_session(session.root, session.client).root
    assert (session.home / "auth.json").stat().st_mode & 0o777 == 0o600


def test_api_status_does_not_qualify_subscription_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _allow_fixture_interpreter(module, monkeypatch)
    session = module.create_session(tmp_path, _client(tmp_path, mode="api_status"))
    with module.start_login(session) as attempt:
        assert attempt.wait(timeout=5)
        with pytest.raises(module.AuthError, match="subscription_login_unconfirmed"):
            attempt.finish()
    with pytest.raises(module.AuthError):
        module.validate_session(session)


def test_cancelled_login_cannot_resume_or_stage_the_same_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _allow_fixture_interpreter(module, monkeypatch)
    session = module.create_session(tmp_path, _client(tmp_path, mode="wait"))
    with module.start_login(session) as attempt:
        assert not attempt.wait(timeout=0.05)
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.start_login(session)


def test_login_deadline_fails_and_reaps_instead_of_polling_forever(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _allow_fixture_interpreter(module, monkeypatch)
    session = module.create_session(tmp_path, _client(tmp_path, mode="wait"))
    with pytest.raises(module.AuthError, match="subscription_login_timeout"):
        with module.start_login(session, timeout_seconds=0.05) as attempt:
            attempt.wait(timeout=1)
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.validate_session(session)


def test_status_cannot_leave_a_live_descendant_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _allow_fixture_interpreter(module, monkeypatch)
    session = module.create_session(tmp_path, _client(tmp_path, mode="status_child"))
    pid: int | None = None
    try:
        with module.start_login(session) as attempt:
            assert attempt.wait(timeout=5)
            attempt.finish()
        pid = int((session.home / "synthetic-status-child.pid").read_text())
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "stat="], capture_output=True, timeout=5
        )
        assert result.returncode == 1 or result.stdout.strip().startswith(b"Z")
    finally:
        if pid is not None:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass


def test_unconfirmed_status_cleanup_interrupts_scope_before_lock_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    stop = module._stop_login_process

    def unconfirmed(process: subprocess.Popen[bytes]) -> None:
        stop(process)
        raise module.AuthError("subscription_login_cleanup_unconfirmed")

    monkeypatch.setattr(module, "_stop_login_process", unconfirmed)
    with pytest.raises(
        module.AuthError, match="subscription_login_cleanup_unconfirmed"
    ):
        module.validate_session(session)
    record = json.loads((session.root / module.SESSION_FILENAME).read_text())
    assert record["phase"] == "interrupted"
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.validate_session(session)


def test_crash_during_ready_session_validation_cannot_reuse_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    program = """import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('synthetic_validation_crash',sys.argv[1])
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
session=module.load_session(Path(sys.argv[2]),Path(sys.argv[3]))
def crash(_session):os._exit(17)
module._status=crash
module.validate_session(session)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(HELPER),
            str(session.root),
            str(session.client),
        ],
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 17
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.validate_session(session)


def test_cleanup_implementation_drift_invalidates_existing_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    import behavioral_process_cleanup

    monkeypatch.setattr(
        behavioral_process_cleanup, "implementation_digest", lambda: "f" * 64
    )
    with pytest.raises(module.AuthError, match="subscription_session_changed"):
        module.validate_session(session)


def test_opaque_refresh_returns_only_after_explicit_child_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    client_home = tmp_path / "fresh-client-home"
    client_home.mkdir(mode=0o700)
    original_read_bytes = Path.read_bytes

    def no_credential_reads(path: Path) -> bytes:
        if path.name == "auth.json":
            raise AssertionError("the controller must not read credential bytes")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", no_credential_reads)
    with module.stage_credentials(session, client_home) as lease:
        assert not (session.home / "auth.json").exists()
        assert (client_home / "auth.json").is_file()
        assert lease.credential_homes == (session.root, client_home)
        assert lease.credential_canary.parent == client_home
        (client_home / "auth.json").write_bytes(b"opaque refreshed synthetic bytes")
        lease.complete()
    assert (
        original_read_bytes(session.home / "auth.json")
        == b"opaque refreshed synthetic bytes"
    )
    assert not (client_home / "auth.json").exists()
    module.validate_session(session)


def test_same_session_cannot_be_used_concurrently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    first, second = tmp_path / "first-client", tmp_path / "second-client"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    with module.stage_credentials(session, first) as lease:
        with pytest.raises(module.AuthError, match="subscription_auth_busy"):
            with module.stage_credentials(session, second):
                pytest.fail("a second credential user must never enter")
        lease.complete()


def test_unconfirmed_teardown_preserves_cache_and_blocks_session_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    client_home = tmp_path / "fresh-client-home"
    client_home.mkdir(mode=0o700)
    with pytest.raises(module.AuthError, match="subscription_teardown_unconfirmed"):
        with module.stage_credentials(session, client_home):
            pass
    assert (client_home / "auth.json").is_file()
    assert not (session.home / "auth.json").exists()
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.validate_session(session)


def test_process_death_preserves_consumed_custody_without_automatic_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    client_home = tmp_path / "fresh-client-home"
    client_home.mkdir(mode=0o700)
    program = """import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('synthetic_auth_crash',sys.argv[1])
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
session=module.load_session(Path(sys.argv[2]),Path(sys.argv[3]))
with module.stage_credentials(session,Path(sys.argv[4])):
    os._exit(17)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(HELPER),
            str(session.root),
            str(session.client),
            str(client_home),
        ],
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        cwd=tmp_path,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 17
    assert (client_home / "auth.json").is_file()
    with pytest.raises(module.AuthError, match="subscription_auth_interrupted"):
        module.validate_session(session)


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public_mode"])
def test_unsafe_fresh_cache_metadata_is_rejected_without_reading_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    credential = session.home / "auth.json"
    if unsafe == "symlink":
        replacement = tmp_path / "synthetic-other-credential"
        credential.rename(replacement)
        credential.symlink_to(replacement)
    elif unsafe == "hardlink":
        os.link(credential, tmp_path / "synthetic-alias")
    else:
        credential.chmod(0o644)
    with pytest.raises(module.AuthError, match="subscription_credential_invalid"):
        module.validate_session(session)


def test_session_marker_and_code_binding_cannot_be_transplanted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, session = _ready(tmp_path, monkeypatch)
    transplanted = tmp_path / ("memory-subscription-auth-" + "f" * 16)
    transplanted.mkdir(mode=0o700)
    for item in session.root.iterdir():
        if item.name == module.SESSION_FILENAME:
            (transplanted / item.name).write_bytes(item.read_bytes())
            (transplanted / item.name).chmod(0o600)
    with pytest.raises(module.AuthError, match="subscription_session_invalid"):
        module.load_session(transplanted, session.client)
    monkeypatch.setattr(module, "implementation_digest", lambda: "f" * 64)
    with pytest.raises(module.AuthError, match="subscription_session_changed"):
        module.validate_session(session)


def test_public_failures_never_include_private_paths_or_cache_bytes(
    tmp_path: Path,
) -> None:
    module = _module()
    with pytest.raises(module.AuthError) as result:
        module.load_session(tmp_path / "synthetic-private-location", _client(tmp_path))
    assert str(tmp_path) not in str(result.value)
    assert "synthetic-private-location" not in str(result.value)
    assert json.dumps(str(result.value)).startswith('"subscription_')


def test_scope_pins_only_the_public_system_ca_and_lease_exposes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.setenv(
            name, str(Path("/Users") / "synthetic-owner" / "private-ca.pem")
        )
    module, session = _ready(tmp_path, monkeypatch)
    pinned = session.root / "public-ca.pem"
    assert pinned.read_bytes() == Path("/private/etc/ssl/cert.pem").read_bytes()
    assert pinned.stat().st_mode & 0o777 == 0o600
    record = json.loads((session.root / module.SESSION_FILENAME).read_text())
    assert (
        record["public_ca_bundle_digest"]
        == hashlib.sha256(pinned.read_bytes()).hexdigest()
    )
    environment = module._environment(session)
    assert environment["CODEX_CA_CERTIFICATE"] == str(pinned)
    assert "SSL_CERT_FILE" not in environment and "SSL_CERT_DIR" not in environment
    client_home = tmp_path / "fresh-client-home"
    client_home.mkdir(mode=0o700)
    with module.stage_credentials(session, client_home) as lease:
        assert lease.public_ca_bundle == pinned
        lease.complete()


@pytest.mark.parametrize(
    "drift", ["bytes", "replacement", "mode", "missing", "symlink", "hardlink"]
)
def test_pinned_public_ca_drift_blocks_session_before_any_client_launch(
    tmp_path: Path, drift: str
) -> None:
    module = _module()
    session = module.create_session(tmp_path, _client(tmp_path))
    pinned = session.root / "public-ca.pem"
    original = pinned.read_bytes()
    if drift == "bytes":
        pinned.write_bytes(original + b"\n# synthetic changed public bytes\n")
    elif drift == "replacement":
        pinned.unlink()
        pinned.write_bytes(original)
        pinned.chmod(0o600)
    elif drift == "mode":
        pinned.chmod(0o644)
    elif drift == "missing":
        pinned.unlink()
    elif drift == "symlink":
        target = session.root / "synthetic-public-ca-alias.pem"
        pinned.rename(target)
        pinned.symlink_to(target)
    else:
        os.link(pinned, session.root / "synthetic-public-ca-alias.pem")
    with pytest.raises(module.AuthError, match="subscription_public_ca_"):
        module.start_login(session)
    assert not (session.root / "login.sb").exists()
    assert not (session.home / "auth.json").exists()


@pytest.mark.parametrize("failure", ["missing", "symlink"])
def test_missing_or_symlinked_public_system_ca_fails_before_scope_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    module = _module()
    client = _client(tmp_path)
    real_open = os.open

    def unavailable(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == Path("/private/etc/ssl/cert.pem"):
            assert flags & os.O_NOFOLLOW
            if failure == "missing":
                raise FileNotFoundError
            raise OSError("synthetic no-follow refusal")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(module.os, "open", unavailable)
    with pytest.raises(module.AuthError, match="subscription_public_ca_"):
        module.create_session(tmp_path, client)
    assert not list(tmp_path.glob("memory-subscription-auth-*"))


@pytest.mark.parametrize(
    "corrupt", ["empty", "non_pem", "base64", "der", "truncated", "mixed"]
)
def test_public_ca_rejects_corrupt_certificates_before_pinning(
    tmp_path: Path, corrupt: str
) -> None:
    module = _module()
    boundary = b"-" * 5
    begin = boundary + b"BEGIN CERTIFICATE" + boundary + b"\n"
    end = boundary + b"END CERTIFICATE" + boundary + b"\n"
    broken_der = (
        begin + base64.b64encode(b"synthetic-not-an-x509-certificate") + b"\n" + end
    )
    if corrupt == "empty":
        content = b""
    elif corrupt == "non_pem":
        content = b"fresh synthetic text, not a public certificate"
    elif corrupt == "base64":
        content = begin + b"!synthetic-invalid-base64!\n" + end
    elif corrupt == "der":
        content = broken_der
    elif corrupt == "truncated":
        content = begin + base64.b64encode(b"synthetic") + b"\n"
    else:
        public = Path("/private/etc/ssl/cert.pem").read_bytes()
        first = public.split(begin, 1)[1].split(end, 1)[0]
        content = begin + first + end + broken_der
    path = tmp_path / "fresh-synthetic-public-ca.pem"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(module.AuthError, match="subscription_public_ca_invalid"):
        module._ca_bytes(path, system=False)


def test_reading_public_ca_may_change_access_time_without_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    content = Path("/private/etc/ssl/cert.pem").read_bytes()
    pinned = tmp_path / "fresh-public-ca.pem"
    pinned.write_bytes(content)
    pinned.chmod(0o600)
    original = os.fstat
    reads = 0

    def changed_access_time(descriptor: int) -> os.stat_result:
        nonlocal reads
        values = list(original(descriptor))
        reads += 1
        values[7] += reads
        return os.stat_result(values)

    monkeypatch.setattr(module.os, "fstat", changed_access_time)
    assert module._ca_bytes(pinned, system=False)[0] == content


@pytest.mark.parametrize(
    "field,value",
    [(0, 0o100666), (0, 0o040644), (4, 501), (3, 0), (6, 0), (6, 2**22)],
)
def test_unsafe_public_system_ca_metadata_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: int,
    value: int,
) -> None:
    module = _module()
    client = _client(tmp_path)
    real_stat = os.fstat

    def unsafe(descriptor: int) -> os.stat_result:
        values = list(real_stat(descriptor))
        values[field] = value
        return os.stat_result(values)

    monkeypatch.setattr(module.os, "fstat", unsafe)
    with pytest.raises(module.AuthError, match="subscription_public_ca_"):
        module.create_session(tmp_path, client)
    assert not list(tmp_path.glob("memory-subscription-auth-*"))
