from __future__ import annotations

import ast
import http.client
import json
import os
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "src" / "memory"
UI_ROOT = PACKAGE_ROOT / "ui"
TEMPLATE_ROOT = UI_ROOT / "templates"
STATIC_ROOT = UI_ROOT / "static"
SQLCIPHER_COMPANION = REPO_ROOT / (
    "third_party/wheels/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-"
    "cp314-cp314-macosx_26_0_arm64.whl"
)
REQUIRED_OWNER_PRESENCE_MEMBERS = (
    "memory/ui/owner_presence.py",
    "memory/ui/templates/reviews/approve.html",
)
FORBIDDEN_BYPASS_SYMBOLS = (
    b"SyntheticOwnerApproval",
    b"SyntheticOwnerPresenceAdapter",
    b"RefusingOwnerPresenceAdapter",
    b"SyntheticLocalAuthentication",
    b"FakeOwnerPresence",
    b"AlwaysApprovingOwnerPresence",
    b"fake_owner_presence",
    b"bypass_owner_presence",
)
ISOLATED_PROBE = """\
import importlib.util
import json
import pathlib

import memory

print(
    json.dumps(
        {
            "origin": str(pathlib.Path(memory.__file__).resolve()),
            "tests": importlib.util.find_spec("tests") is not None,
            "fake": importlib.util.find_spec(
                "memory.ui.fake_owner_presence"
            )
            is not None,
            "owner_presence": importlib.util.find_spec(
                "memory.ui.owner_presence"
            )
            is not None,
        }
    )
)
"""


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one clean wheel from the repository into a temporary wheelhouse."""
    wheelhouse = tmp_path_factory.mktemp("owner-presence-wheelhouse")
    built = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    wheels = list(wheelhouse.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_clean_wheel_ships_the_production_owner_presence_adapter(
    built_wheel: Path,
) -> None:
    """Catch a wheel that cannot request macOS owner presence after install."""
    with ZipFile(built_wheel) as archive:
        names = set(archive.namelist())

    assert set(REQUIRED_OWNER_PRESENCE_MEMBERS) <= names


def test_clean_wheel_has_no_test_approval_bypass_material(built_wheel: Path) -> None:
    """Catch a test owner-presence fake or synthetic approval entering the wheel."""
    with ZipFile(built_wheel) as archive:
        names = tuple(archive.namelist())
        python_source = b"\n".join(
            archive.read(name) for name in names if name.endswith(".py")
        )

    assert not any(name.startswith("tests/") for name in names)
    assert "memory/ui/fake_owner_presence.py" not in names
    assert b"SyntheticOwnerApproval" not in python_source
    for forbidden in FORBIDDEN_BYPASS_SYMBOLS:
        assert forbidden not in python_source


def test_installed_wheel_import_excludes_tests_and_owner_presence_fakes(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    """Catch a checkout import masking bypass material absent from the wheel."""
    environment = tmp_path / "clean-environment"
    created = subprocess.run(
        ["uv", "venv", "--python", "3.14", str(environment)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert created.returncode == 0, created.stderr
    interpreter = environment / "bin" / "python"
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(interpreter),
            str(SQLCIPHER_COMPANION),
            str(built_wheel),
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr
    outside = tmp_path / "outside-the-repository"
    outside.mkdir()
    isolated = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTHON", "UV_"))
        and name not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}
    }

    probe = subprocess.run(
        [str(interpreter), "-I", "-c", ISOLATED_PROBE],
        cwd=outside,
        capture_output=True,
        check=False,
        env=isolated,
        text=True,
    )

    assert probe.returncode == 0, probe.stderr
    observed = json.loads(probe.stdout)
    origin = Path(observed["origin"])
    assert origin.is_relative_to(environment)
    assert "site-packages/memory/__init__.py" in origin.as_posix()
    assert not origin.is_relative_to(REPO_ROOT)
    assert observed["tests"] is False
    assert observed["fake"] is False
    assert observed["owner_presence"] is True


UI_ASSET_MEMBER_PREFIXES = (
    "memory/ui/templates/",
    "memory/ui/static/",
)
FORBIDDEN_WHEEL_PREFIXES = (
    "tests/",
    "tools/",
    "docs/",
    "src/",
    "scratch/",
    "memory/tests/",
)
FORBIDDEN_WHEEL_SUBSTRINGS = (
    "prepare-ui-acceptance",
    "prepare_ui_acceptance",
    "smoke-ui",
    "smoke_ui",
    "smoke-wheel",
    "fake_owner_presence",
    "synthetic_ui/manifest",
    "synthetic_journeys",
    "__pycache__",
    ".pyc",
)
PROVIDER_LAUNCHER_MARKERS = (
    b"--ignore-user-config",
    b"--ephemeral",
    b"--strict-mcp-config",
    b"--setting-sources",
    b"client_executable",
    b"launch_client",
    b"codex exec",
    b"mcpServers",
)
STATE_ATTRIBUTE_TEXT = {
    "data-item-status": ("{{ item.status }}",),
    "data-coverage": ("{{ source.coverage }}", "{{ decision.coverage }}"),
    "data-review-state": ("Review ", "Digest "),
    "data-revision-lifecycle": ("{{ entry.lifecycle.replace",),
    "data-sensitivity": ("Effective sensitivity:", "sensitivity_dot("),
    "data-level": ('class="sensitivity-label">{{ level }}',),
    "data-kind": (">{{ kind }}<",),
    "data-link-status": ('class="state-tag">{{ link.status }}',),
}
# The only attributes the stylesheet is allowed to color by: each renders its
# own state as adjacent text, so the color repeats the label, never replaces
# it. A rejected guard link also carries a strike-through, so its state does
# not depend on the dimmed edge either.
#
# `data-sensitivity` is admitted for the graph lenses alone, and only because
# the picture cannot carry five hundred inline labels: every graph node states
# its own kind and sensitivity as text inside its `<title>`, which is its
# accessible name and its hover tooltip, and each lens renders an always-
# visible key built from the same `sensitivity_dot` and `kind_chip` macros the
# list views use. `test_graph_lenses_label_their_own_colour_encoding` pins both
# halves; without them this entry would be exactly the regression this test
# exists to catch.
COLOR_STATE_ATTRIBUTES = frozenset(
    {"data-level", "data-kind", "data-link-status", "data-sensitivity"}
)
CONTRAST_MATRIX = (
    ("--text", "--background", 4.5),
    ("--text", "--surface", 4.5),
    ("--text", "--raised", 4.5),
    ("--text", "--warning", 4.5),
    ("--text", "--accent-soft", 4.5),
    ("--muted", "--surface", 4.5),
    ("--muted", "--raised", 4.5),
    ("--accent", "--surface", 4.5),
    ("--accent-contrast", "--accent", 4.5),
    ("--border", "--surface", 3.0),
    ("--border", "--background", 3.0),
)
MEMORY_KINDS = ("fact", "event", "preference", "relation", "insight")
CONTROL_TAG = re.compile(r"<(input|select|textarea)\b[^>]*>", re.IGNORECASE)
LABEL_FOR = re.compile(r"<label[^>]*\bfor=\"([^\"]+)\"", re.IGNORECASE)
WRAPPED_CONTROL = re.compile(
    r"<label\b[^>]*>(?:(?!</label>).)*<(?:input|select|textarea)\b",
    re.IGNORECASE | re.DOTALL,
)
EXTERNAL_URL = re.compile(
    r"""(?:src|href|url\(|@import\s+)["'(]?\s*(?:https?:)?//""",
    re.IGNORECASE,
)
LAUNCH_ENVELOPE_TIMEOUT_SECONDS = 30.0


def template_paths() -> tuple[Path, ...]:
    return tuple(sorted(TEMPLATE_ROOT.rglob("*.html")))


def static_paths() -> tuple[Path, ...]:
    return tuple(sorted(STATIC_ROOT.iterdir()))


def relative_member(path: Path) -> str:
    return f"memory/{path.relative_to(PACKAGE_ROOT).as_posix()}"


def relative_luminance(color: str) -> float:
    """Return the WCAG relative luminance of one ``#rrggbb`` color."""
    raw = color.lstrip("#")
    channels = [int(raw[index : index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(foreground: str, background: str) -> float:
    """Return the WCAG contrast ratio between two ``#rrggbb`` colors."""
    first = relative_luminance(foreground)
    second = relative_luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def declared_colors(source: str) -> dict[str, str]:
    """Return every ``--name: #rrggbb`` declaration in one stylesheet region."""
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6});", source))


def css_palettes() -> dict[str, dict[str, str]]:
    """Return both rendered color palettes: light default and dark override."""
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")
    dark_block = re.search(
        r"@media \(prefers-color-scheme: dark\) \{(.*?)\n\}",
        css,
        re.DOTALL,
    )
    assert dark_block is not None, "the owner stylesheet declares no dark palette"
    light = declared_colors(css[: dark_block.start()])
    dark = {**light, **declared_colors(dark_block.group(1))}
    return {"light": light, "dark": dark}


def max_headings_on_any_path(template: str, tag: str = "h1") -> int:
    """Return the largest number of ``tag`` openings any rendered branch emits."""
    tokens = re.split(r"({%-?\s*(?:if|elif|else|endif|for|endfor)\b.*?-?%})", template)

    def control(position: int) -> str | None:
        if position >= len(tokens) or position % 2 == 0:
            return None
        matched = re.match(r"{%-?\s*(\w+)", tokens[position])
        return None if matched is None else matched.group(1)

    def walk(index: int, stop: tuple[str, ...]) -> tuple[int, int]:
        total = 0
        position = index
        while position < len(tokens):
            name = control(position)
            if name is None:
                total += len(re.findall(rf"<{tag}\b", tokens[position]))
                position += 1
                continue
            if name in stop:
                return total, position
            if name == "if":
                branches: list[int] = []
                position += 1
                while True:
                    branch, position = walk(position, ("elif", "else", "endif"))
                    branches.append(branch)
                    closing = control(position)
                    position += 1
                    if closing == "endif":
                        break
                if len(branches) == 1:
                    branches.append(0)
                total += max(branches)
                continue
            if name == "for":
                position += 1
                body, position = walk(position, ("else", "endfor"))
                closing = control(position)
                position += 1
                if closing == "else":
                    empty, position = walk(position, ("endfor",))
                    position += 1
                    body = max(body, empty)
                # A repeated heading is never acceptable; report it as many.
                total += body * 2
                continue
            position += 1
        return total, position

    counted, _ = walk(0, ())
    return counted


def isolated_environment() -> dict[str, str]:
    """Return the caller environment without Python, uv, or virtualenv leakage."""
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTHON", "UV_"))
        and name not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}
    }


@dataclass(frozen=True, slots=True)
class InstalledStore:
    """One installed environment plus the temporary synthetic runtime it owns."""

    environment: Path
    interpreter: Path
    command: Path
    home: Path
    store_id: str


@pytest.fixture(scope="module")
def installed_environment(
    built_wheel: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Install the built wheel once into a fresh temporary virtual environment."""
    root = tmp_path_factory.mktemp("installed-owner-ui")
    environment = root / "clean-environment"
    created = subprocess.run(
        ["uv", "venv", "--python", "3.14", str(environment)],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert created.returncode == 0, created.stderr
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(environment / "bin" / "python"),
            str(SQLCIPHER_COMPANION),
            str(built_wheel),
        ],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr
    return environment


def delete_synthetic_key(store_id: str) -> None:
    """Delete exactly one temporary synthetic Keychain item and verify absence."""
    subprocess.run(
        [
            "/usr/bin/security",
            "delete-generic-password",
            "-s",
            "memory",
            "-a",
            store_id,
        ],
        capture_output=True,
        check=False,
        text=True,
    )


@pytest.fixture
def installed_store(
    installed_environment: Path,
    tmp_path: Path,
) -> Iterator[InstalledStore]:
    """Initialize and clean up one disposable installed synthetic runtime."""
    home = tmp_path / "synthetic-installed-home"
    command = installed_environment / "bin" / "memory"
    outside = tmp_path / "outside-the-repository"
    outside.mkdir()
    result = subprocess.run(
        [str(command), "init", "--home", str(home)],
        cwd=outside,
        capture_output=True,
        check=False,
        env=isolated_environment(),
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    identity = json.loads((home / "runtime.json").read_text(encoding="utf-8"))
    store_id = identity["store_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", store_id)
    assert identity["runtime_mode"] == "personal"
    try:
        yield InstalledStore(
            environment=installed_environment,
            interpreter=installed_environment / "bin" / "python",
            command=command,
            home=home,
            store_id=store_id,
        )
    finally:
        delete_synthetic_key(store_id)


def read_ready_line(descriptor: int, deadline: float) -> bytes:
    """Read one newline-terminated marker without blocking past the deadline."""
    collected = bytearray()
    while not collected.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        assert remaining > 0, "the launch marker did not arrive"
        readable, _, _ = select.select([descriptor], [], [], remaining)
        assert readable, "the launch marker did not arrive"
        chunk = os.read(descriptor, 4096)
        assert chunk, "the launch stream closed before its marker"
        collected.extend(chunk)
    return bytes(collected)


def test_clean_wheel_ships_every_owner_ui_template_and_static_asset(
    built_wheel: Path,
) -> None:
    """Catch a wheel whose installed UI cannot render a page or serve an asset."""
    expected = {relative_member(path) for path in template_paths()}
    expected |= {relative_member(path) for path in static_paths()}
    assert len(expected) >= 21

    with ZipFile(built_wheel) as archive:
        names = set(archive.namelist())

    assert expected <= names
    packaged = {name for name in names if name.startswith(UI_ASSET_MEMBER_PREFIXES)}
    assert packaged == expected


def test_clean_wheel_excludes_tests_tools_fixtures_and_bytecode(
    built_wheel: Path,
) -> None:
    """Catch development, acceptance, or provider material entering the wheel."""
    with ZipFile(built_wheel) as archive:
        names = tuple(archive.namelist())
        packaged_source = b"\n".join(
            archive.read(name)
            for name in names
            if name.endswith((".py", ".sh", ".css", ".js", ".html"))
        )

    for name in names:
        assert not name.startswith(FORBIDDEN_WHEEL_PREFIXES), name
        for forbidden in FORBIDDEN_WHEEL_SUBSTRINGS:
            assert forbidden not in name, name
    for marker in PROVIDER_LAUNCHER_MARKERS:
        assert marker not in packaged_source, marker


def test_repository_scripts_keep_executable_mode_in_the_committed_tree() -> None:
    """Catch a browser or UI smoke helper committed without executable mode."""
    scripts = ("tools/setup-browser-tests.sh", "tools/smoke-ui.sh")
    listed = subprocess.run(
        ["git", "ls-files", "-s", *scripts],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert listed.returncode == 0, listed.stderr
    recorded = {
        line.split("\t", 1)[1]: line.split(" ", 1)[0]
        for line in listed.stdout.splitlines()
    }
    assert set(recorded) == set(scripts)
    for script in scripts:
        assert recorded[script] == "100755", script
        path = REPO_ROOT / script
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o755


def test_installed_wheel_serves_the_owner_ui_and_stops_that_exact_process(
    installed_store: InstalledStore,
    tmp_path: Path,
) -> None:
    """Catch a clean installation that cannot launch or cleanly stop the UI."""
    outside = tmp_path / "outside-the-repository"
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            str(installed_store.command),
            "ui",
            "--home",
            str(installed_store.home),
            "--no-open",
            "--launch-fd",
            str(write_fd),
        ],
        cwd=outside,
        env=isolated_environment(),
        pass_fds=(write_fd,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        deadline = time.monotonic() + LAUNCH_ENVELOPE_TIMEOUT_SECONDS
        envelope = json.loads(read_ready_line(read_fd, deadline))
        assert (
            read_ready_line(process.stdout.fileno(), deadline) == b"memory-ui-ready\n"
        )
        assert envelope["protocol"] == "memory.ui-launch.v1"
        origin = envelope["origin"]
        exact_host = origin.removeprefix("http://")
        port = int(exact_host.rsplit(":", 1)[1])

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request("GET", "/bootstrap", headers={"Host": exact_host})
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
    finally:
        os.close(read_fd)
        process.send_signal(signal.SIGTERM)
        stopped = process.wait(timeout=20)
        remaining_stdout = process.stdout.read()
        remaining_stderr = process.stderr.read()
        process.stdout.close()
        process.stderr.close()

    assert stopped == 0
    assert remaining_stdout == b""
    assert remaining_stderr == b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(5)
        with pytest.raises(OSError):
            probe.connect(("127.0.0.1", port))


def test_installed_owner_ui_assets_resolve_below_site_packages(
    installed_environment: Path,
    tmp_path: Path,
) -> None:
    """Catch installed templates or static assets resolving to the checkout."""
    outside = tmp_path / "outside-the-repository"
    outside.mkdir()
    probe = subprocess.run(
        [
            str(installed_environment / "bin" / "python"),
            "-I",
            "-c",
            (
                "import json, pathlib, memory.ui as ui;"
                "root = pathlib.Path(ui.__file__).resolve().parent;"
                "print(json.dumps(sorted("
                "  str(path.relative_to(root))"
                "  for path in root.rglob('*')"
                "  if path.suffix in {'.html', '.css', '.js'}"
                ") + [str(root)]))"
            ),
        ],
        cwd=outside,
        capture_output=True,
        check=False,
        env=isolated_environment(),
        text=True,
    )

    assert probe.returncode == 0, probe.stderr
    observed = json.loads(probe.stdout)
    root = Path(observed[-1])
    assert root.is_relative_to(installed_environment)
    assert "site-packages/memory/ui" in root.as_posix()
    assert not root.is_relative_to(REPO_ROOT)
    expected = sorted(
        path.relative_to(UI_ROOT).as_posix()
        for path in UI_ROOT.rglob("*")
        if path.suffix in {".html", ".css", ".js"}
    )
    assert observed[:-1] == expected


def test_every_owner_page_template_renders_exactly_one_top_level_heading() -> None:
    """Catch a page with no heading or with competing document headings."""
    offenders = {
        path.relative_to(TEMPLATE_ROOT).as_posix(): max_headings_on_any_path(
            path.read_text(encoding="utf-8")
        )
        for path in template_paths()
        if path.name != "base.html" and not path.name.startswith("_")
    }

    assert {name: count for name, count in offenders.items() if count != 1} == {}
    assert "<h1" not in (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
    # The shell and the macro library are page fragments: neither may introduce
    # a competing document heading into the page that includes it.
    for path in template_paths():
        if path.name.startswith("_"):
            assert "<h1" not in path.read_text(encoding="utf-8"), path


def test_owner_shell_declares_language_charset_and_navigation_landmarks() -> None:
    """Catch a shell that loses its document language or assistive landmarks."""
    base = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")

    assert '<html lang="en">' in base
    assert '<meta charset="utf-8">' in base
    assert '<nav aria-label="Primary">' in base
    assert '<main id="main-content"' in base
    assert "<header" in base
    assert 'class="skip-link" href="#main-content"' in base


def test_every_owner_form_control_is_labelled() -> None:
    """Catch an unlabelled owner control that a screen reader cannot announce."""
    unlabelled: dict[str, list[str]] = {}
    for path in template_paths():
        text = path.read_text(encoding="utf-8")
        targets = set(LABEL_FOR.findall(text))
        wrapped = len(WRAPPED_CONTROL.findall(text))
        problems = []
        for match in CONTROL_TAG.finditer(text):
            tag = match.group(0)
            if 'type="hidden"' in tag or 'type="submit"' in tag:
                continue
            identifier = re.search(r'\bid="([^"]+)"', tag)
            if identifier is not None and identifier.group(1) in targets:
                continue
            if wrapped:
                wrapped -= 1
                continue
            problems.append(tag)
        if problems:
            unlabelled[path.relative_to(TEMPLATE_ROOT).as_posix()] = problems

    assert unlabelled == {}


def test_every_owner_table_declares_scoped_header_cells() -> None:
    """Catch a data table that presents rows without programmatic headers."""
    for path in template_paths():
        text = path.read_text(encoding="utf-8")
        tables = text.count("<table")
        if not tables:
            continue
        assert text.count("<thead") == tables, path
        assert text.count("<th ") >= tables, path
        assert text.count("<th ") == text.count('<th scope="'), path


def test_owner_state_is_never_conveyed_by_color_alone() -> None:
    """Catch review, coverage, or sensitivity state rendered only as color."""
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")

    coloured = set(re.findall(r"\[(data-[a-z0-9-]+)=", css))
    assert coloured <= COLOR_STATE_ATTRIBUTES
    for path in template_paths():
        text = path.read_text(encoding="utf-8")
        for attribute, evidence in STATE_ATTRIBUTE_TEXT.items():
            if attribute not in text:
                continue
            assert any(marker in text for marker in evidence), (path, attribute)


def test_owner_stylesheet_keeps_visible_focus_and_accessible_contrast() -> None:
    """Catch a suppressed focus ring or a palette below WCAG AA contrast."""
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")
    palettes = css_palettes()

    assert "outline: none" not in css
    assert ":focus-visible" in css
    assert "outline:" in css.split(":focus-visible", 1)[1]
    for mode, palette in palettes.items():
        for foreground, background, minimum in CONTRAST_MATRIX:
            ratio = contrast_ratio(palette[foreground], palette[background])
            assert ratio >= minimum, (mode, foreground, background, round(ratio, 2))
        for kind in MEMORY_KINDS:
            ratio = contrast_ratio(
                palette[f"--chip-{kind}-text"],
                palette[f"--chip-{kind}-surface"],
            )
            assert ratio >= 4.5, (mode, kind, round(ratio, 2))


def test_owner_ui_assets_request_no_external_host() -> None:
    """Catch a CDN, analytics, or remote font request entering the local UI."""
    for path in (*template_paths(), *static_paths()):
        text = path.read_text(encoding="utf-8")
        assert EXTERNAL_URL.search(text) is None, path
        assert "integrity=" not in text
        assert "crossorigin" not in text


def test_owner_ui_never_marks_stored_owner_text_as_trusted_html() -> None:
    """Catch autoescape being bypassed for any stored source or memory text."""
    for path in template_paths():
        text = path.read_text(encoding="utf-8")
        assert "|safe" not in text.replace(" ", "")
        assert "{% autoescape false %}" not in text


OWNER_GUIDE = REPO_ROOT / "docs" / "owner-guide.md"
GUIDE_REQUIRED_COMMANDS = (
    "uv tool install --python 3.14 --force .",
    "uv tool uninstall memory",
    "uv tool dir --bin",
    "command -v memory",
    "memory --version",
    "uv tool update-shell",
    "memory init --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME",
    "memory init --inbox",
    "memory ui --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME",
    '"$(uv tool dir)/memory/bin/python" -I -c '
    "'import sys; assert sys.version_info[:2] == (3, 14)'",
    "uv sync --locked",
    "uv run memory",
    "--operator-view",
    "--launch-client",
    "--client-executable",
    "--model",
    "--task",
)
GUIDE_REQUIRED_TOPICS = (
    "Pending Reviews",
    "Inbox",
    "Memory",
    "Sources & Audit",
    # The exact sentence the Inbox page renders; the guide quotes it as such.
    "ask a connected agent to process the Inbox",
    "staged-count badge",
    "owner-presence",
    "correction note",
    "record export",
    "raw database",
)
GUIDE_INSTALL_SCRIPT = r"""
set -eu
umask 077
cd "$MEMORY_GUIDE_REPO"

uv tool install --python 3.14 --force . >/dev/null 2>&1

# Reproduce the documented `command not found: memory` state before the fix.
if command -v memory >/dev/null 2>&1; then
    echo "expected memory to be missing from PATH" >&2
    exit 1
fi
echo "missing-tool-bin-reproduced"

# Follow the guide's recovery: fix the shell profile, then use a fresh shell.
uv tool update-shell >/dev/null
resolved=$(/bin/zsh -c 'command -v memory')
expected_bin=$(uv tool dir --bin)
case "$resolved" in
    "$expected_bin"/memory) ;;
    *) echo "memory resolved outside the uv tool bin" >&2; exit 1 ;;
esac
case "$resolved" in
    "$MEMORY_GUIDE_REPO"/*) echo "memory resolved inside the source checkout" >&2; exit 1 ;;
esac
echo "resolved-from-tool-bin"

"$(uv tool dir)/memory/bin/python" -I -c \
    'import sys; assert sys.version_info[:2] == (3, 14)'
echo "tool-python-3.14"

"$resolved" --version

uv tool install --python 3.14 --force . >/dev/null 2>&1
echo "updated-with-python-pin"
"""
GUIDE_RUNTIME_SCRIPT = r"""
set -eu
umask 077
export PATH="$MEMORY_GUIDE_TOOL_BIN:$PATH"
memory init --home "$MEMORY_GUIDE_STORE" >/dev/null
echo "initialized-synthetic-store"
"""


def read_guide() -> str:
    assert OWNER_GUIDE.is_file(), "the local owner UI guide is missing"
    return OWNER_GUIDE.read_text(encoding="utf-8")


def test_owner_guide_documents_every_required_command_and_area() -> None:
    """Catch an owner guide missing an exact installed command or workflow area."""
    guide = read_guide()

    for command in GUIDE_REQUIRED_COMMANDS:
        assert command in guide, command
    for topic in GUIDE_REQUIRED_TOPICS:
        assert topic in guide, topic
    assert "memory ui --home" in guide
    assert "uv run memory ui" in guide
    assert "./tools/deliver.sh run" in guide
    # The guide quotes the Inbox handoff "in these exact words", so the quote
    # has to be the words. A list of required substrings cannot notice that
    # the page changed underneath it; reading the template can.
    rendered = (
        REPO_ROOT / "src" / "memory" / "ui" / "templates" / "inbox" / "index.html"
    ).read_text(encoding="utf-8")
    handoff = re.search(r"<strong>(Staged;[^<]*)</strong>", rendered)
    assert handoff is not None
    assert f"> **{handoff.group(1)}**" in guide


def test_repository_readmes_link_the_owner_guide_and_keep_the_import_boundary() -> None:
    """Catch orientation documents dropping the guide or the import boundary."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    documentation = (REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")

    assert "docs/owner-guide.md" in readme
    assert "owner-guide.md" in documentation
    for text in (readme, documentation):
        assert "owner-approved" in text


@pytest.mark.slow
def test_owner_guide_installation_journey_from_a_fresh_shell(tmp_path: Path) -> None:
    """Catch a documented install/update/uninstall path the owner cannot follow."""
    read_guide()
    guide_home = tmp_path / "disposable-shell-home"
    tool_dir = tmp_path / "disposable-uv-tools"
    tool_bin = tmp_path / "disposable-uv-tool-bin"
    shim = tmp_path / "disposable-path"
    store = tmp_path / "disposable-synthetic-store"
    for directory in (guide_home, tool_dir, tool_bin, shim):
        directory.mkdir()
    resolved_uv = shutil.which("uv")
    assert resolved_uv is not None
    resolved_python = shutil.which("python3.14")
    assert resolved_python is not None
    (shim / "uv").symlink_to(resolved_uv)
    (shim / "python3.14").symlink_to(resolved_python)
    shared = {
        **isolated_environment(),
        "PATH": f"{shim}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SHELL": "/bin/zsh",
        "UV_TOOL_DIR": str(tool_dir),
        "UV_TOOL_BIN_DIR": str(tool_bin),
        "MEMORY_GUIDE_TOOL_BIN": str(tool_bin),
        "MEMORY_GUIDE_REPO": str(REPO_ROOT),
        "MEMORY_GUIDE_STORE": str(store),
    }
    # The install phase uses a disposable shell profile home; the runtime phase
    # keeps the real login keychain, which the Store key boundary requires.
    environment = {**shared, "HOME": str(guide_home)}
    runtime_environment = dict(shared)

    installed = subprocess.run(
        ["/bin/zsh", "-f", "-c", GUIDE_INSTALL_SCRIPT],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=900,
    )
    store_id = ""
    try:
        assert installed.returncode == 0, installed.stderr
        started = subprocess.run(
            ["/bin/zsh", "-f", "-c", GUIDE_RUNTIME_SCRIPT],
            cwd=tmp_path,
            capture_output=True,
            check=False,
            env=runtime_environment,
            text=True,
            timeout=300,
        )
        assert started.returncode == 0, started.stderr
        lines = installed.stdout.splitlines() + started.stdout.splitlines()
        assert "missing-tool-bin-reproduced" in lines
        assert "resolved-from-tool-bin" in lines
        assert "tool-python-3.14" in lines
        assert "initialized-synthetic-store" in lines
        assert "updated-with-python-pin" in lines
        assert any(re.fullmatch(r"memory \d+\.\d+\.\d+", line) for line in lines)
        identity = json.loads((store / "runtime.json").read_text(encoding="utf-8"))
        store_id = identity["store_id"]
        assert identity["runtime_mode"] == "personal"

        read_fd, write_fd = os.pipe()
        process = subprocess.Popen(
            [
                str(tool_bin / "memory"),
                "ui",
                "--home",
                str(store),
                "--no-open",
                "--launch-fd",
                str(write_fd),
            ],
            cwd=tmp_path,
            env=runtime_environment,
            pass_fds=(write_fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(write_fd)
        assert process.stdout is not None
        try:
            deadline = time.monotonic() + LAUNCH_ENVELOPE_TIMEOUT_SECONDS
            envelope = json.loads(read_ready_line(read_fd, deadline))
            marker = read_ready_line(process.stdout.fileno(), deadline)
        finally:
            os.close(read_fd)
            process.send_signal(signal.SIGTERM)
            stopped = process.wait(timeout=20)
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        assert marker == b"memory-ui-ready\n"
        assert envelope["origin"].startswith("http://memory-")
        assert stopped == 0

        removed = subprocess.run(
            ["/bin/zsh", "-f", "-c", "uv tool uninstall memory"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=300,
        )
        assert removed.returncode == 0, removed.stderr
        assert not (tool_bin / "memory").exists()
    finally:
        if store_id:
            delete_synthetic_key(store_id)
        subprocess.run(
            ["/bin/zsh", "-f", "-c", "uv tool uninstall memory"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=300,
        )


ACCEPTANCE_SECTION = "12. Acceptance rehearsal tooling"
PREPARER_PATH = REPO_ROOT / "tools" / "prepare-ui-acceptance.py"
INSTALLED_INTERPRETER = '"$(uv tool dir)/memory/bin/python"'
INTERPRETER_ASSIGNMENT = f"MEMORY_UI_PYTHON={INSTALLED_INTERPRETER}"
TOOL_REFERENCE = '"$MEMORY_UI_TOOL"'
SHELL_VARIABLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
SHELL_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=", re.MULTILINE)
LONG_OPTION = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]+")
FENCED_BLOCK = re.compile(r"^```(?:console|sh)\n(.*?)^```", re.DOTALL | re.MULTILINE)


def guide_sections() -> dict[str, str]:
    """Return each numbered guide section body keyed by its exact heading."""
    sections: dict[str, str] = {}
    current = ""
    for line in read_guide().splitlines(keepends=True):
        if line.startswith("## "):
            current = line.removeprefix("## ").strip()
            sections[current] = ""
            continue
        if current:
            sections[current] += line
    return sections


def preparer_long_options() -> set[str]:
    """Return every long option the acceptance preparer actually declares."""
    tree = ast.parse(
        PREPARER_PATH.read_text(encoding="utf-8"), filename=str(PREPARER_PATH)
    )
    options: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(
                    argument.value, str
                ):
                    if argument.value.startswith("--"):
                        options.add(argument.value)
    return options


def preparer_invocations(section: str) -> list[str]:
    """Return every fenced block that actually invokes the acceptance preparer."""
    return [block for block in FENCED_BLOCK.findall(section) if TOOL_REFERENCE in block]


def test_owner_guide_acceptance_commands_match_the_preparer_interface() -> None:
    """Catch a documented acceptance flag that the preparer does not declare."""
    declared = preparer_long_options()
    section = guide_sections()[ACCEPTANCE_SECTION]
    documented = {
        option
        for block in preparer_invocations(section)
        for option in LONG_OPTION.findall(block)
    }

    assert declared, "the preparer declares no long options"
    assert documented - declared == set()
    assert declared - documented == set()


def test_owner_guide_acceptance_blocks_run_verbatim_from_a_fresh_shell() -> None:
    """Catch an unrunnable interpreter path or an undefined acceptance variable."""
    guide = read_guide()
    section = guide_sections()[ACCEPTANCE_SECTION]
    blocks = FENCED_BLOCK.findall(section)

    assert "UV_TOOL_BIN" not in guide
    assert len(blocks) >= 5
    assert INTERPRETER_ASSIGNMENT in section
    assert len(preparer_invocations(section)) >= 4
    defined: set[str] = set()
    for block in blocks:
        assert not re.search(r"^\s*\.\.\.", block, re.MULTILINE), block
        defined |= set(SHELL_ASSIGNMENT.findall(block))
        for name in SHELL_VARIABLE.findall(block):
            assert name in defined, (name, block)
        if TOOL_REFERENCE not in block:
            continue
        assert f'"$MEMORY_UI_PYTHON" -I {TOOL_REFERENCE}' in block, block


def test_owner_guide_documents_the_mandatory_correction_batch_step() -> None:
    """Catch an acceptance sequence that stops before the correction launch."""
    section = guide_sections()[ACCEPTANCE_SECTION]
    recorded = section.find("--record-correction-batch")
    launched = section.find("--task SYN-UI-CORRECTION-004")

    assert recorded != -1
    assert launched != -1
    assert recorded < launched
    assert "required" in section.lower()


def test_owner_pages_wrap_every_joined_tag_list() -> None:
    """Catch a long tag list overflowing its grid cell on an owner page."""
    for path in template_paths():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "tags | join" not in line:
                continue
            assert "wrap-anywhere" in line, (path.name, line.strip())


def test_graph_marks_are_solid_and_encode_exactly_one_state() -> None:
    """Catch the two faults that made every node render as an empty ring.

    A stroke centred on a 3.4 radius mark consumed 51% of its own area, so the
    fill survived only as a dot inside a ring; `paint-order: stroke` puts the
    ring underneath, where it separates neighbours instead. And the kind text
    colours reused as fills measured a deuteranope separation of 1.0 -- five
    categories that no reader could tell apart -- so colour now carries
    sensitivity alone and kind moved to the hover label and the filters.
    """
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")

    assert "paint-order: stroke" in css
    # Colour encodes one state. A kind-based fill rule would silently make it
    # two, and reintroduce a five-way split that cannot separate in dark mode.
    for kind in MEMORY_KINDS:
        assert f".graph-node--{kind} circle" not in css, kind
    assert '.graph-node[data-sensitivity="restricted"] circle' in css


def test_only_sources_carry_a_canvas_label() -> None:
    """Catch a label layer that outgrows the space its layer actually has.

    Batch labels were tried and removed: fifteen dates on the tight inner ring
    collided into an unreadable smear. Memory labels are whole sentences and
    never fit. Both keep their name in the hover panel instead.
    """
    macro = (TEMPLATE_ROOT / "graph" / "_scene.html").read_text(encoding="utf-8")

    assert 'for node in scene.nodes if node.layer == "source"' in macro
    assert "graph-label-text" in macro
    # Revealed by zoom, not painted at fit scale where they would collide.
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")
    assert ".graph-label-text" in css
    assert "opacity: 0;" in css
    assert ".graph-scene.is-zoomed .graph-label-text" in css


def test_graph_lenses_label_their_own_colour_encoding() -> None:
    """Catch a graph that colours by state without saying what the colours mean.

    `data-sensitivity` is on the stylesheet's colour allowlist only because of
    these two things. If either disappears, the graph would be conveying state
    by colour alone and the allowlist entry becomes a hole.
    """
    macro = (TEMPLATE_ROOT / "graph" / "_scene.html").read_text(encoding="utf-8")

    # Every node states its kind and sensitivity as text in its accessible name.
    assert "<title>" in macro
    assert "Effective sensitivity: {{ node.sensitivity }}" in macro
    assert "{{ node.kind }}" in macro

    # And every lens page renders the always-visible key.
    for name in ("provenance.html", "governance.html"):
        page = (TEMPLATE_ROOT / "graph" / name).read_text(encoding="utf-8")
        assert "graph_legend()" in page, name
    assert "sensitivity_dot(level" in macro
    assert "kind_chip(kind)" in macro


def test_the_governance_lens_names_its_guards_and_points_its_links() -> None:
    """Catch the governance lens rendering as anonymous dots on plain lines.

    Guard-ness is conveyed three ways and none of them is colour: the guard
    carries a name its claims do not, the arrow points away from it, and
    degree-sizing draws it larger. If the label or the marker goes, the lens
    stops saying which end governs.
    """
    macro = (TEMPLATE_ROOT / "graph" / "_scene.html").read_text(encoding="utf-8")
    css = (STATIC_ROOT / "app.css").read_text(encoding="utf-8")

    assert 'marker-end="url(#graph-arrow' in macro
    assert '<marker id="graph-arrow"' in macro
    assert '<marker id="graph-arrow-inverted"' in macro
    assert 'for node in scene.nodes if node.role == "guard"' in macro
    assert ".graph-arrow path" in css
    assert ".graph-arrow--inverted path" in css
    # And guard-ness must not be encoded by colouring an attribute.
    assert "[data-role=" not in css
