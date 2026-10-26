"""Opening the owner's browser, and the one-shot capability handed to it.

These are the tests for `memory.ui.browser_launch`: that each launch mints an
independent random host and secret, that the envelope reaches exactly one
writable pipe or socketpair and closes its descriptor, that it refuses a
terminal, a regular file, a read-only or inet descriptor, and a standard
stream, and that the capability and hostname are never retained or emitted
anywhere afterwards. Plus the Finder reveal, which must use only the URL it
was handed.

They lived inside the 2,800-line session-and-CSRF suite, where the module they
cover had no test file of its own to notice was missing.
"""

import importlib
import json
import os
import pty
import socket
import subprocess
import sys
import webbrowser
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ui_support import load_ui_module

from memory.errors import StoreError
from memory.model import (
    RuntimeMode,
)
from memory.runtime import resolve_runtime

PUBLIC_HOST = "memory-11111111111111111111111111111111.localhost"
PUBLIC_PORT = 43123
EXACT_HOST = f"{PUBLIC_HOST}:{PUBLIC_PORT}"
PUBLIC_ORIGIN = f"http://{EXACT_HOST}"
BOOTSTRAP = "synthetic-bootstrap-capability"
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_random_launches_use_independent_128_bit_hosts_and_256_bit_secrets() -> None:
    """Catch fixed/reused origin and bootstrap capability generation."""
    browser_launch = load_ui_module("browser_launch")
    paths = resolve_runtime(Path("synthetic-ui-home"))

    first = browser_launch.create_ui_launch(paths, bound_port=PUBLIC_PORT)
    second = browser_launch.create_ui_launch(paths, bound_port=PUBLIC_PORT)

    assert first != second
    assert first.bind_host == second.bind_host == "127.0.0.1"
    assert (
        len(first.public_host.removeprefix("memory-").removesuffix(".localhost")) == 32
    )
    assert len(first.bootstrap_capability) >= 43
    assert first.public_host != second.public_host
    assert first.bootstrap_capability != second.bootstrap_capability
    assert first.bootstrap_capability not in first.public_host
    assert first.public_host not in first.bootstrap_capability


def test_launch_envelope_writes_once_to_pipe_and_closes_descriptor() -> None:
    """Catch descriptor retention or non-versioned integration launch output."""
    browser_launch = load_ui_module("browser_launch")
    launch = browser_launch.create_ui_launch(
        resolve_runtime(Path("synthetic-ui-home")),
        bound_port=PUBLIC_PORT,
    )
    read_fd, write_fd = os.pipe()
    try:
        browser_launch.write_ui_launch_envelope(write_fd, launch)
        payload = os.read(read_fd, 16_384)
        assert os.read(read_fd, 1) == b""
    finally:
        os.close(read_fd)

    with pytest.raises(OSError):
        os.fstat(write_fd)
    assert json.loads(payload) == {
        "bootstrap_url": launch.url,
        "origin": f"http://{launch.public_host}:{launch.port}",
        "protocol": "memory.ui-launch.v1",
    }
    assert payload.endswith(b"\n")
    assert payload.count(b"\n") == 1


def test_launch_envelope_accepts_connected_unix_socketpair_and_closes_fd() -> None:
    """Catch integration mode rejecting its only non-pipe transport."""
    browser_launch = load_ui_module("browser_launch")
    launch = browser_launch.create_ui_launch(
        resolve_runtime(Path("synthetic-ui-home")),
        bound_port=PUBLIC_PORT,
    )
    writer, reader = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    write_fd = writer.detach()
    try:
        browser_launch.write_ui_launch_envelope(write_fd, launch)
        payload = reader.recv(16_384)
        assert reader.recv(1) == b""
    finally:
        reader.close()

    assert json.loads(payload)["bootstrap_url"] == launch.url
    with pytest.raises(OSError):
        os.fstat(write_fd)


def invalid_launch_descriptors(tmp_path: Path) -> Iterator[tuple[str, int, Any]]:
    regular_fd = os.open(
        tmp_path / "synthetic-regular", os.O_WRONLY | os.O_CREAT, 0o600
    )
    yield "regular", regular_fd, None

    master_fd, terminal_fd = pty.openpty()
    yield "terminal", terminal_fd, lambda: os.close(master_fd)

    read_fd, write_fd = os.pipe()
    yield "readonly_pipe", read_fd, lambda: os.close(write_fd)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(listener.getsockname())
    accepted, _address = listener.accept()
    inet_fd = client.detach()

    def close_inet() -> None:
        accepted.close()
        listener.close()

    yield "inet", inet_fd, close_inet


def test_launch_envelope_rejects_terminal_regular_readonly_and_inet_fds(
    tmp_path: Path,
) -> None:
    """Catch bootstrap URLs entering retained files, terminals, or TCP streams."""
    browser_launch = load_ui_module("browser_launch")
    launch = browser_launch.create_ui_launch(
        resolve_runtime(Path("synthetic-ui-home")),
        bound_port=PUBLIC_PORT,
    )

    for _name, descriptor, cleanup in invalid_launch_descriptors(tmp_path):
        try:
            with pytest.raises(StoreError):
                browser_launch.write_ui_launch_envelope(descriptor, launch)
            with pytest.raises(OSError):
                os.fstat(descriptor)
        finally:
            if cleanup is not None:
                cleanup()
    assert (tmp_path / "synthetic-regular").read_bytes() == b""


def run_standard_stream_launch_probe(
    target: str,
) -> tuple[int, bytes, bytes, dict[str, object]]:
    """Run launch validation where all three standard streams are real pipes."""
    report_read, report_write = os.pipe()
    script = r"""
import json
import os
import sys
from pathlib import Path

from memory.errors import StoreError
from memory.runtime import resolve_runtime
from memory.ui.browser_launch import (
    create_ui_launch,
    write_ui_launch_envelope,
)

selected = sys.argv[1]
report_fd = int(sys.argv[2])
target_fd = os.dup(1) if selected == "alias" else int(selected)
launch = create_ui_launch(resolve_runtime(Path("synthetic-ui-home")), bound_port=43123)
rejected = False
try:
    write_ui_launch_envelope(target_fd, launch)
except StoreError:
    rejected = True
try:
    os.fstat(target_fd)
except OSError:
    still_open = False
else:
    still_open = True
payload = json.dumps(
    {"rejected": rejected, "still_open": still_open},
    sort_keys=True,
    separators=(",", ":"),
).encode() + b"\n"
os.write(report_fd, payload)
os.close(report_fd)
if selected == "alias" and still_open:
    os.close(target_fd)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, target, str(report_write)],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(report_write,),
    )
    os.close(report_write)
    try:
        stdout, stderr = process.communicate(input=b"", timeout=10)
        report = os.read(report_read, 4_096)
        assert os.read(report_read, 1) == b""
    finally:
        os.close(report_read)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return process.returncode, stdout, stderr, json.loads(report)


@pytest.mark.parametrize("target", ["0", "1", "2", "alias"])
def test_launch_envelope_rejects_standard_streams_and_aliases_without_closing(
    target: str,
) -> None:
    """Catch secrets written through standard streams or their duplicate pipes."""
    returncode, stdout, stderr, report = run_standard_stream_launch_probe(target)

    assert returncode == 0
    if stdout or stderr:
        pytest.fail("launch material reached a standard stream")
    assert report == {"rejected": True, "still_open": True}


def test_browser_open_uses_only_in_process_launch_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch secret-bearing URL launch through argv, shell, or webbrowser."""
    import subprocess
    import sys
    from types import SimpleNamespace

    browser_launch = load_ui_module("browser_launch")
    opened: list[object] = []

    class SyntheticURL:
        @classmethod
        def URLWithString_(cls, value: str) -> object:
            return ("synthetic-url", value)

    def open_url(value: object) -> bool:
        opened.append(value)
        return True

    workspace = SimpleNamespace(openURL_=open_url)

    class SyntheticWorkspace:
        @classmethod
        def sharedWorkspace(cls) -> object:
            return workspace

    monkeypatch.setitem(sys.modules, "Foundation", SimpleNamespace(NSURL=SyntheticURL))
    monkeypatch.setitem(
        sys.modules, "AppKit", SimpleNamespace(NSWorkspace=SyntheticWorkspace)
    )
    monkeypatch.setattr(
        webbrowser,
        "open",
        lambda *_args, **_kwargs: pytest.fail("webbrowser received bootstrap URL"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess received bootstrap URL"),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Popen received bootstrap URL"),
    )
    url = f"{PUBLIC_ORIGIN}/bootstrap#{BOOTSTRAP}"

    browser_launch.open_bootstrap_url_with_launch_services(url)

    assert opened == [("synthetic-url", url)]


@pytest.mark.parametrize("outcome", ["false", "exception"])
def test_browser_open_requires_explicit_content_free_launch_services_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    outcome: str,
) -> None:
    """Catch false/exception Cocoa launch results being treated as readiness."""
    from types import SimpleNamespace

    browser_launch = load_ui_module("browser_launch")
    url = f"{PUBLIC_ORIGIN}/bootstrap#{BOOTSTRAP}"

    class SyntheticURL:
        @classmethod
        def URLWithString_(cls, value: str) -> object:
            return ("synthetic-url", value)

    def open_url(_value: object) -> bool:
        if outcome == "false":
            return False
        raise RuntimeError(url)

    workspace = SimpleNamespace(openURL_=open_url)

    class SyntheticWorkspace:
        @classmethod
        def sharedWorkspace(cls) -> object:
            return workspace

    monkeypatch.setitem(sys.modules, "Foundation", SimpleNamespace(NSURL=SyntheticURL))
    monkeypatch.setitem(
        sys.modules, "AppKit", SimpleNamespace(NSWorkspace=SyntheticWorkspace)
    )

    with pytest.raises(StoreError) as captured:
        browser_launch.open_bootstrap_url_with_launch_services(url)

    output = capsys.readouterr()
    combined = str(captured.value) + output.out + output.err + caplog.text
    assert url not in combined
    assert BOOTSTRAP not in combined


def test_cocoa_finder_revealer_uses_only_supplied_directory_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the narrow Finder seam accepting paths or constructing URLs."""
    import sys
    from types import SimpleNamespace

    browser_launch = load_ui_module("browser_launch")
    revealed: list[object] = []
    workspace = SimpleNamespace(
        activateFileViewerSelectingURLs_=lambda urls: revealed.extend(urls)
    )

    class SyntheticWorkspace:
        @classmethod
        def sharedWorkspace(cls) -> object:
            return workspace

    monkeypatch.setitem(
        sys.modules, "AppKit", SimpleNamespace(NSWorkspace=SyntheticWorkspace)
    )
    directory_url = object()

    browser_launch.CocoaFinderRevealer().reveal_directory_url(directory_url)

    assert revealed == [directory_url]


def test_launch_capability_and_hostname_are_not_retained_or_emitted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catch launch material entering process metadata, output, logs, or files."""
    import sys

    browser_launch = load_ui_module("browser_launch")
    paths = resolve_runtime(tmp_path / "synthetic-runtime")
    paths.root.mkdir(mode=0o700)
    launch = browser_launch.create_ui_launch(paths, bound_port=PUBLIC_PORT)

    emitted = capsys.readouterr()
    process_metadata = repr(sys.argv) + repr(dict(os.environ))
    retained = b"".join(
        path.read_bytes() for path in paths.root.iterdir() if path.is_file()
    )
    for value in (launch.public_host, launch.bootstrap_capability):
        assert value not in emitted.out
        assert value not in emitted.err
        assert value not in caplog.text
        assert value not in process_metadata
        assert value.encode("utf-8") not in retained


def test_cli_ui_passes_only_validated_launch_mode_to_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch CLI option normalization changing the runner's authority inputs."""
    cli = importlib.import_module("memory.cli")
    app = load_ui_module("app")
    calls: list[tuple[object, bool, int | None]] = []

    def fake_run_ui(
        paths: object,
        *,
        open_browser: bool,
        launch_fd: int | None,
    ) -> int:
        calls.append((paths, open_browser, launch_fd))
        return 37

    monkeypatch.setattr(app, "run_ui", fake_run_ui)
    home = tmp_path / "synthetic-home"

    assert cli.main(["ui", "--home", str(home)]) == 37
    assert cli.main(["ui", "--home", str(home), "--no-open", "--launch-fd", "11"]) == 37
    assert [(opened, descriptor) for _, opened, descriptor in calls] == [
        (True, None),
        (False, 11),
    ]


@pytest.mark.parametrize("outcome", ["false", "exception"])
def test_run_ui_unwinds_when_launch_services_fails_browser_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
    outcome: str,
) -> None:
    """Catch failed Cocoa launch readiness retaining the socket or UI lock."""
    from types import SimpleNamespace

    app = load_ui_module("app")
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-browser-refusal")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    sockets: list[socket.socket] = []

    class SyntheticURL:
        @classmethod
        def URLWithString_(cls, value: str) -> object:
            return ("synthetic-url", value)

    def open_url(value: object) -> bool:
        if outcome == "false":
            return False
        raise RuntimeError(value)

    workspace = SimpleNamespace(openURL_=open_url)

    class SyntheticWorkspace:
        @classmethod
        def sharedWorkspace(cls) -> object:
            return workspace

    def serve_until_ready(
        _application: Any,
        bound_socket: socket.socket,
        on_ready: Any,
    ) -> None:
        sockets.append(bound_socket)
        on_ready()

    monkeypatch.setitem(sys.modules, "Foundation", SimpleNamespace(NSURL=SyntheticURL))
    monkeypatch.setitem(
        sys.modules, "AppKit", SimpleNamespace(NSWorkspace=SyntheticWorkspace)
    )
    monkeypatch.setattr(app, "_serve_ui", serve_until_ready)

    with pytest.raises(StoreError):
        app.run_ui(
            paths,
            open_browser=True,
            launch_fd=None,
        )

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""
    assert len(sockets) == 1
    assert sockets[0].fileno() == -1
    with runtime.ui_session_lock(paths):
        pass


def test_random_launch_uses_fragment_capability() -> None:
    """Catch bootstrap material entering a query string or fixed origin."""
    browser_launch = importlib.import_module("memory.ui.browser_launch")
    runtime = importlib.import_module("memory.runtime")

    launch = browser_launch.create_ui_launch(
        runtime.resolve_runtime(Path("synthetic-ui-home")),
        bound_port=43123,
    )

    assert launch.bind_host == "127.0.0.1"
    assert launch.public_host.startswith("memory-")
    assert launch.public_host.endswith(".localhost")
    assert launch.url == (
        f"http://{launch.public_host}:43123/bootstrap#{launch.bootstrap_capability}"
    )
    assert "?" not in launch.url
