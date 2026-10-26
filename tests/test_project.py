from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import jwt
import pytest
from jwt.types import Options

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("complete", [False, True])
def test_jwt_unverified_peek_cannot_disable_later_expiry_check(complete: bool) -> None:
    """A shared options mapping must not retain relaxed verification defaults."""
    key = "synthetic-regression-key-for-expired-token-checks-" * 2
    token = jwt.encode({"sub": "synthetic-subject", "exp": 1}, key, algorithm="HS256")
    options: Options = {"verify_signature": False}
    decode = jwt.decode_complete if complete else jwt.decode

    decode(token, key, algorithms=["HS256"], options=options)

    assert options == {"verify_signature": False}
    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        decode(token, key, algorithms=["HS256"], options=options)


def write_executable(path: Path, body: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def synthetic_smoke_environment(tmp_path: Path) -> dict[str, str]:
    fake_pms = write_executable(
        tmp_path / "synthetic-memory",
        """\
import json
import os
import pathlib
import sys

command = sys.argv[1]
home = pathlib.Path(sys.argv[sys.argv.index("--home") + 1])
store_id = os.environ["MEMORY_SMOKE_SYNTHETIC_STORE_ID"]
if command == "init":
    home.mkdir(mode=0o700, exist_ok=True)
    (home / "inbox").mkdir(mode=0o700)
    (home / "inbox-claims").mkdir(mode=0o700)
    (home / "inbox-staging").mkdir(mode=0o700)
    (home / "store.sqlite3").write_bytes(b"synthetic wheel smoke database\\n")
    identity = {
        "product": "memory",
        "schema_lineage": os.environ.get(
            "MEMORY_SMOKE_SYNTHETIC_LINEAGE", "memory-store-v1"
        ),
        "schema_version": 1,
        "store_id": store_id,
        "runtime_mode": "personal",
        "inbox_path": str(home / "inbox"),
    }
    (home / "runtime.json").write_text(
        json.dumps(identity, sort_keys=True) + "\\n",
        encoding="utf-8",
    )
    pathlib.Path(os.environ["MEMORY_SMOKE_HOME_LOG"]).write_text(
        str(home),
        encoding="utf-8",
    )
    print(f"Inbox: {home / 'inbox'}")
elif command == "paths":
    print(json.dumps({
        "database": str(home / "store.sqlite3"),
        "home": str(home),
        "identity": str(home / "runtime.json"),
        "inbox": str(home / "inbox"),
        "inbox_claims": str(home / "inbox-claims"),
    }, sort_keys=True))
else:
    raise SystemExit(2)
""",
    )
    fake_security = write_executable(
        tmp_path / "synthetic-security",
        """\
import os
import pathlib
import sys

command = sys.argv[1]
state = pathlib.Path(os.environ["MEMORY_SMOKE_SECURITY_STATE"])
calls = pathlib.Path(os.environ["MEMORY_SMOKE_SECURITY_CALLS"])
with calls.open("a", encoding="utf-8") as output:
    output.write(command + "\\n")
if command == "delete-generic-password":
    if os.environ.get("MEMORY_SMOKE_DELETE_FAILURE") == "1":
        raise SystemExit(7)
    state.write_text("absent\\n", encoding="utf-8")
    raise SystemExit(0)
if command == "find-generic-password":
    if os.environ.get("MEMORY_SMOKE_FIND_FAILURE") == "1":
        raise SystemExit(3)
    raise SystemExit(44 if state.read_text(encoding="utf-8") == "absent\\n" else 0)
raise SystemExit(2)
""",
    )
    state = tmp_path / "synthetic-key-state"
    state.write_text("present\n", encoding="utf-8")
    return {
        **os.environ,
        "TMPDIR": str(tmp_path),
        "PYTHONPATH": str(REPO_ROOT / "src"),
        "MEMORY_SMOKE_CLI_COMMAND": str(fake_pms),
        "MEMORY_SMOKE_SECURITY_COMMAND": str(fake_security),
        "MEMORY_SMOKE_SECURITY_STATE": str(state),
        "MEMORY_SMOKE_SECURITY_CALLS": str(tmp_path / "security-calls"),
        "MEMORY_SMOKE_HOME_LOG": str(tmp_path / "store-home-log"),
        "MEMORY_SMOKE_SYNTHETIC_STORE_ID": "a1" * 16,
    }


def run_wheel_smoke(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [REPO_ROOT / "tools" / "smoke-wheel.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=120,
    )


def test_project_metadata_names_the_memory_distribution() -> None:
    """Catch build metadata drifting from the memory package and entry point."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "memory"
    assert project["project"]["scripts"] == {"memory": "memory.cli:main"}
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/memory"
    ]
    assert project["tool"]["hatch"]["build"]["artifacts"] == [
        "src/memory/skill/**/*",
        "src/memory/ui/static/**/*",
        "src/memory/ui/templates/**/*",
    ]
    assert project["tool"]["hatch"]["build"]["targets"]["sdist"]["only-include"] == [
        "src/memory"
    ]


def test_project_requires_and_statically_targets_python_314() -> None:
    """Catch any active package or static-analysis surface retaining 3.13."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert (REPO_ROOT / ".python-version").read_text(encoding="utf-8") == "3.14\n"
    assert project["project"]["requires-python"] == ">=3.14,<3.15"
    assert project["tool"]["ruff"]["target-version"] == "py314"
    assert project["tool"]["mypy"]["python_version"] == "3.14"
    assert project["tool"]["uv"]["prerelease"] == "disallow"
    assert project["tool"]["uv"]["resolution"] == "highest"
    assert project["build-system"]["requires"] == ["hatchling>=1.32.4"]


def test_package_is_importable() -> None:
    """Catch a build configuration that names a package absent from the tree."""
    assert importlib.util.find_spec("memory") is not None


def test_current_modules_ship_under_the_memory_package() -> None:
    """Catch a wheel skeleton that omits a Store kernel or source module."""
    modules = (
        "cli",
        "database",
        "errors",
        "inbox",
        "keys",
        "mcp_prompts",
        "mcp_server",
        "memories",
        "model",
        "retrieval",
        "reviews",
        "runtime",
        "skill_sync",
        "sources",
    )

    missing = [
        name for name in modules if importlib.util.find_spec(f"memory.{name}") is None
    ]

    assert missing == []


def test_active_tree_contains_only_the_provider_free_store_distribution() -> None:
    """Catch unapproved dependencies entering the product."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["dependencies"] == [
        "httpx2>=2.16.0",
        "jinja2>=3.1.6",
        "keyring>=25.7.0",
        "mcp>=2.3.0,<3",
        "opentelemetry-api>=1.45.1",
        "pillow>=13.0.0",
        "pydantic>=2.14.1",
        "pypdfium2>=5.14.0",
        "pyjwt[crypto]>=2.15.1",
        "pyobjc-framework-Cocoa>=12.2.2",
        "pyobjc-framework-LocalAuthentication>=12.2.2",
        "python-multipart>=0.0.32",
        "memory-sqlcipher3==0.6.2+sqlcipher4.17.0.memory1",
        "starlette>=1.9.0",
        "uvicorn>=0.54.0",
    ]
    assert project["dependency-groups"]["dev"] == [
        "httpx2>=2.16.0",
        "hypothesis>=6.170.8",
        "jsonschema>=4.26.0",
        "mypy>=2.4.0",
        "playwright==1.62.0+memory.1",
        "pyee==14.0.0",
        "pypdf>=6.21.2",
        "pytest-cov>=7.1.0",
        "pytest>=9.1.1",
        "ruff>=0.17.2",
    ]
    assert project["tool"]["uv"]["sources"] == {
        "memory-sqlcipher3": {
            "path": (
                "third_party/wheels/"
                "memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-"
                "cp314-cp314-macosx_26_0_arm64.whl"
            )
        },
        "playwright": {
            "path": (
                "third_party/wheels/"
                "playwright-1.62.0+memory.1-py3-none-macosx_26_0_arm64.whl"
            )
        },
    }
    assert {path.name for path in (REPO_ROOT / "tests").glob("test_*.py")} == {
        "test_agent_factory.py",
        "test_agent_factory_context.py",
        "test_agent_factory_workflow.py",
        "test_behavioral_acceptance_tool.py",
        "test_behavioral_auth.py",
        "test_behavioral_campaign.py",
        "test_behavioral_campaign_execution.py",
        "test_behavioral_capability_binding.py",
        "test_behavioral_client_lifecycle.py",
        "test_behavioral_codex_auth.py",
        "test_behavioral_codex_isolation.py",
        "test_behavioral_continuation.py",
        "test_behavioral_discovery.py",
        "test_behavioral_effort.py",
        "test_behavioral_execution_isolation.py",
        "test_behavioral_mcp_bridge.py",
        "test_behavioral_memory_endpoint.py",
        "test_behavioral_process_cleanup.py",
        "test_behavioral_subscription_binding.py",
        "test_cli.py",
        "test_database.py",
        "test_delivery.py",
        "test_delivery_dependencies.py",
        "test_detail_indexes.py",
        "test_graph.py",
        "test_graph_layout.py",
        "test_export.py",
        "test_guard_links.py",
        "test_inbox.py",
        "test_inbox_observation.py",
        "test_inbox_relocation.py",
        "test_inbox_seam.py",
        "test_initialization.py",
        "test_keys.py",
        "test_ladder.py",
        "test_maintenance.py",
        "test_mcp.py",
        "test_mcp_detail_pages.py",
        "test_mcp_teaching.py",
        "test_memories.py",
        "test_owner_presence.py",
        "test_owner_service.py",
        "test_precommit.py",
        "test_prepush.py",
        "test_project.py",
        "test_public_distribution.py",
        "test_retrieval.py",
        "test_retrieval_benchmark_tool.py",
        "test_retrieval_discovery_tool.py",
        "test_retrieval_native.py",
        "test_retrieval_ranking.py",
        "test_reviews.py",
        "test_runtime_mode.py",
        "test_skill.py",
        "test_skill_discovery.py",
        "test_skill_orientation.py",
        "test_skill_sync.py",
        "test_sources.py",
        "test_staged_memory_intake_cancellation.py",
        "test_staged_memory_intake_checks.py",
        "test_staged_memory_intake_cleanup.py",
        "test_staged_memory_intake_cli.py",
        "test_staged_memory_intake_config.py",
        "test_staged_memory_intake_layout_migration.py",
        "test_staged_memory_intake_prepared.py",
        "test_staged_memory_intake_publish.py",
        "test_staged_memory_intake_relocation.py",
        "test_staged_memory_intake_skill.py",
        "test_staged_memory_intake_state.py",
        "test_staged_memory_intake_sync.py",
        "test_staging_provenance.py",
        "test_synthetic_workflow.py",
        "test_ui_acceptance_tool.py",
        "test_ui_audit.py",
        "test_ui_auth.py",
        "test_ui_browser_launch.py",
        "test_ui_inbox.py",
        "test_ui_inspection.py",
        "test_ui_media.py",
        "test_ui_memory_relations.py",
        "test_ui_packaging.py",
        "test_ui_presentation.py",
        "test_ui_reviews.py",
        "test_wheel_fetch.py",
    }


def test_tracked_text_omits_absolute_macos_user_home_paths() -> None:
    """Keep developer and owner home paths out of every committed text file."""
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    private_home = re.compile("/" + "Users/" + r"[A-Za-z0-9._-]+/")
    violations: list[str] = []
    for encoded in tracked:
        if not encoded:
            continue
        relative = encoded.decode("utf-8")
        if relative.startswith("third_party/wheels/"):
            continue
        path = REPO_ROOT / relative
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in private_home.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{relative}:{line}")
    assert violations == []


def test_sqlcipher_companion_is_pinned_self_contained_and_licensed() -> None:
    """Catch fallback to PyPI's stale kernel or an unauditable native wheel."""
    wheel = REPO_ROOT / (
        "third_party/wheels/"
        "memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-"
        "cp314-cp314-macosx_26_0_arm64.whl"
    )
    provenance = REPO_ROOT / "third_party" / "memory-sqlcipher3"
    assert wheel.is_file()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert f"{digest}  third_party/wheels/{wheel.name}" in (
        (provenance / "wheel-hash.txt").read_text(encoding="utf-8").splitlines()
    )
    native_checksums = (
        (provenance / "native-hashes.txt").read_text(encoding="utf-8").splitlines()
    )
    assert len(native_checksums) == 3
    assert all(
        re.fullmatch(r"[0-9a-f]{64}  lib(?:crypto|sqlite3)\.a \(.+\)", line)
        for line in native_checksums[:2]
    )
    assert re.fullmatch(
        r"[0-9a-f]{64}  sqlcipher3/_sqlite3\.cpython-314-darwin\.so",
        native_checksums[2],
    )
    recipe = (provenance / "build-wheel.sh").read_text(encoding="utf-8")
    downstream_project = (provenance / "downstream-pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert 'requires-python = ">=3.14,<3.15"' in downstream_project
    for pinned_hash in (
        "a2b675289ba8889f389625a21f3a01f1ff159a551b5b88fba8fd92da0e02380a",
        "79c0e164b9c059e7487bf8f29272f601cca5f3312cc267461f81e349962a5058",
        "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09",
    ):
        assert pinned_hash in recipe
    for compile_option in (
        "SQLITE_ENABLE_FTS5",
        "SQLITE_ENABLE_RTREE",
        "SQLITE_ENABLE_STAT4",
        "SQLITE_USE_URI",
        "SQLITE_MAX_VARIABLE_NUMBER=250000",
        "SQLITE_DEFAULT_CACHE_SIZE=-8000",
    ):
        assert compile_option in recipe
    assert "MACOSX_DEPLOYMENT_TARGET=26.0" in recipe
    assert "rewrite-openssl-buildinfo.py" in recipe
    assert "otool -L" in recipe
    assert {path.name for path in (provenance / "licenses").iterdir()} == {
        "OpenSSL.txt",
        "SQLCipher-BSD.txt",
        "SQLCipher-Community.md",
        "SQLite-Public-Domain.md",
        "sqlcipher3.txt",
    }
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
        native_name = "sqlcipher3/_sqlite3.cpython-314-darwin.so"
        assert (
            hashlib.sha256(archive.read(native_name)).hexdigest()
            == native_checksums[2].split()[0]
        )
        assert "Name: memory-sqlcipher3\n" in metadata
        assert "Version: 0.6.2+sqlcipher4.17.0.memory1\n" in metadata
        assert "Requires-Python: <3.15,>=3.14\n" in metadata
        license_names = {
            Path(name).name
            for name in archive.namelist()
            if ".dist-info/licenses/" in name
        }
        assert license_names == {
            "LICENSE",
            "LICENSE.OpenSSL.txt",
            "LICENSE.SQLCipher-BSD.txt",
            "LICENSE.SQLCipher-Community.md",
            "LICENSE.SQLite-Public-Domain.md",
        }

    lock = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    assert 'name = "memory-sqlcipher3"' in lock
    assert 'name = "sqlcipher3"' not in lock
    assert "files.pythonhosted.org" not in "\n".join(
        line for line in lock.splitlines() if "sqlcipher3" in line.lower()
    )


def test_openssl_buildinfo_rewrite_is_exact_and_fail_closed(tmp_path: Path) -> None:
    """Reject upstream drift instead of silently leaving a private build path."""
    source = tmp_path / "mkbuildinf.pl"
    source.write_text(
        "my $platform = pop @ARGV;\n"
        "my $cflags = join(' ', @ARGV);\n"
        "$cflags =~ s(\\\\)(\\\\\\\\)g;\n"
        '$cflags = "compiler: $cflags";\n',
        encoding="utf-8",
    )
    rewrite = (
        REPO_ROOT / "third_party" / "memory-sqlcipher3" / "rewrite-openssl-buildinfo.py"
    )

    first = subprocess.run(
        [sys.executable, "-I", str(rewrite), str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    assert source.read_text(encoding="utf-8").endswith(
        "# Memory records the exact compiler and flags in its committed provenance.\n"
        "# Do not embed the disposable source-build path carried by prefix-map flags.\n"
        '$cflags = "compiler: see Memory companion provenance";\n'
    )

    second = subprocess.run(
        [sys.executable, "-I", str(rewrite), str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode != 0
    assert "expected exactly one OpenSSL compiler-description assignment" in (
        second.stderr
    )


def test_playwright_companion_relaxes_only_pyee_and_never_falls_back(
    tmp_path: Path,
) -> None:
    """Catch current pyee being hidden behind stale Playwright metadata."""
    wheel = REPO_ROOT / (
        "third_party/wheels/playwright-1.62.0+memory.1-py3-none-macosx_26_0_arm64.whl"
    )
    provenance = REPO_ROOT / "third_party" / "playwright"
    assert wheel.is_file()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert (provenance / "wheel-hash.txt").read_text(encoding="utf-8") == (
        f"{digest}  third_party/wheels/{wheel.name}\n"
    )
    recipe = (provenance / "build-wheel.sh").read_text(encoding="utf-8")
    assert "db755ab27db21a04186f1fe8169888e42356086e439b1059b923ef417f0b6034" in recipe
    assert "30cc72a0c00a22c3d287539233d3d6abd579becbfe7d02aef80bd3e75c951455" in (
        provenance / "PROVENANCE.md"
    ).read_text(encoding="utf-8")
    assert hashlib.sha256((provenance / "LICENSE").read_bytes()).hexdigest() == (
        "7fab1461b41970ff376f1c9303a637076bfaaeb71cd12dd3a1c44aaf59a1a2b9"
    )
    assert 'declared_macos_floor="26.0"' in recipe
    assert 'expected_node_minos="13.5"' in recipe

    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        assert metadata_name.startswith("playwright-1.62.0+memory.1.dist-info/")
        metadata_text = archive.read(metadata_name).decode("utf-8")
        assert "Name: playwright\n" in metadata_text
        assert "Version: 1.62.0+memory.1\n" in metadata_text
        assert "Requires-Dist: pyee<15,>=14\n" in metadata_text
        assert "Requires-Dist: pyee<14,>=13\n" not in metadata_text
        assert "Requires-Dist: greenlet<4.0.0,>=3.1.1\n" in metadata_text
        wheel_text = archive.read("playwright-1.62.0+memory.1.dist-info/WHEEL").decode(
            "utf-8"
        )
        assert "Tag: py3-none-macosx_26_0_arm64\n" in wheel_text
        assert archive.read(
            "playwright-1.62.0+memory.1.dist-info/entry_points.txt"
        ) == (
            b"[console_scripts]\n"
            b"playwright = playwright.__main__:main\n\n"
            b"[pyinstaller40]\n"
            b"hook-dirs = playwright._impl.__pyinstaller:get_hook_dirs\n"
        )
        members = {info.filename: info for info in archive.infolist()}
        assert members["playwright/driver/node"].external_attr >> 16 == 0o100755
        assert {
            "playwright/driver/LICENSE",
            "playwright/driver/package/LICENSE",
            "playwright/driver/package/NOTICE",
            "playwright/driver/package/ThirdPartyNotices.txt",
        } <= members.keys()
        code_digest = hashlib.sha256()
        code_names = sorted(
            name
            for name in archive.namelist()
            if ".dist-info/" not in name and not name.endswith("/")
        )
        assert len(code_names) == 181
        for name in code_names:
            code_digest.update(name.encode())
            code_digest.update(b"\0")
            code_digest.update(hashlib.sha256(archive.read(name)).digest())
        assert code_digest.hexdigest() == (
            "82149c494b20c20937efb9f5bdcb7a3367aeb701346b3b944a72dd2b012bafca"
        )
        node = tmp_path / "node"
        node.write_bytes(archive.read("playwright/driver/node"))

    load_commands = subprocess.run(
        ["otool", "-l", str(node)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    node_minos = re.findall(r"^\s*minos ([0-9.]+)$", load_commands, re.MULTILINE)
    assert node_minos == ["13.5"]
    assert tuple(int(part) for part in node_minos[0].split(".")) <= (26, 0)

    lock = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    assert 'name = "playwright"\nversion = "1.62.0+memory.1"' in lock
    assert 'name = "pyee"\nversion = "14.0.0"' in lock
    playwright_lock = lock.split('name = "playwright"', maxsplit=1)[1].split(
        "[[package]]", maxsplit=1
    )[0]
    assert "files.pythonhosted.org" not in playwright_lock


def test_v1_13_0_release_metadata_moves_together() -> None:
    """Catch a local release whose package, lock, Skill, and docs disagree."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    locked = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    memory_packages = [
        package for package in locked["package"] if package["name"] == "memory"
    ]

    assert project["project"]["version"] == "1.13.0"
    assert [package["version"] for package in memory_packages] == ["1.13.0"]
    assert '__version__ = "1.13.0"' in (
        REPO_ROOT / "src" / "memory" / "__init__.py"
    ).read_text(encoding="utf-8")
    assert "product version `1.13.0`" in (
        REPO_ROOT / "src" / "memory" / "skill" / "SKILL.md"
    ).read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    technical_design = (REPO_ROOT / "docs" / "technical-design.md").read_text(
        encoding="utf-8"
    )
    assert "Version 1.13.0" in readme
    assert "Python 3.14" in readme
    assert "MCP Python SDK 2" in readme
    assert "SQLCipher 4.17.0" in readme
    assert "SQLite 3.53.3" in readme
    assert "Playwright 1.62.0+memory.1" in readme
    assert "v1.13.0," in technical_design
    assert "Python 3.14" in technical_design
    assert "MCP Python SDK 2" in technical_design
    assert "SQLCipher 4.17.0" in technical_design
    assert "SQLite 3.53.3" in technical_design
    assert "v1.13.0" in (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    acceptance = (
        REPO_ROOT / "docs" / "acceptance" / "v1.13.0-acceptance.md"
    ).read_text(encoding="utf-8")
    assert "# Memory v1.13.0 release acceptance" in acceptance


ACCEPTANCE_PARITY_FLOOR = (1, 5, 1)


@pytest.mark.parametrize(
    ("status", "accepted"),
    [
        ("accepted and locally deployed", True),
        ("accepted local release; not installed", True),
        ("accepted public source release; not installed", True),
        ("pending", False),
        ("unverified local release", False),
    ],
)
def test_release_acceptance_status_keeps_installation_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, accepted: bool
) -> None:
    """A release tag needs acceptance, while installation has its own authority."""
    records = tmp_path / "docs" / "acceptance"
    records.mkdir(parents=True)
    (records / "v1.6.2-acceptance.md").write_text(
        "# Memory v1.6.2 release acceptance\n"
        "- Status: **accepted and locally deployed**\n",
        encoding="utf-8",
    )
    (records / "v9.9.9-acceptance.md").write_text(
        f"# Memory v9.9.9 release acceptance\n- Status: **{status}**\n",
        encoding="utf-8",
    )

    def list_synthetic_tags(
        args: list[str], *, cwd: Path, capture_output: bool, check: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        assert args == ["git", "tag", "--list", "v*"]
        assert cwd == tmp_path and capture_output and check and text
        return subprocess.CompletedProcess(args, 0, "v1.6.2\nv9.9.9\n", "")

    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(subprocess, "run", list_synthetic_tags)
    if accepted:
        test_every_release_tag_since_v1_5_1_has_an_acceptance_record()
    else:
        with pytest.raises(AssertionError):
            test_every_release_tag_since_v1_5_1_has_an_acceptance_record()


def test_every_release_tag_since_v1_5_1_has_an_acceptance_record() -> None:
    """Catch a release tag cut without recording its owner acceptance."""
    listed = subprocess.run(
        ["git", "tag", "--list", "v*"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        text=True,
    )
    versions: list[tuple[int, ...]] = []
    for line in listed.stdout.split():
        parts = line.removeprefix("v").split(".")
        if len(parts) == 3 and all(part.isdigit() for part in parts):
            versions.append(tuple(int(part) for part in parts))
    for version in sorted(versions):
        if version < ACCEPTANCE_PARITY_FLOOR:
            continue
        label = ".".join(str(part) for part in version)
        record = REPO_ROOT / "docs" / "acceptance" / f"v{label}-acceptance.md"
        assert record.is_file(), f"tag v{label} has no acceptance record"
        acceptance = record.read_text(encoding="utf-8")
        assert f"# Memory v{label} release acceptance" in acceptance
        assert any(
            f"Status: **{status}**" in acceptance
            for status in (
                "accepted and locally deployed",
                "accepted local release; not installed",
                "accepted public source release; not installed",
            )
        ), f"tag v{label} has no accepted release status"


def test_browser_setup_script_is_executable() -> None:
    """Catch a packaged browser-test setup helper that cannot be invoked."""
    script = REPO_ROOT / "tools" / "setup-browser-tests.sh"

    assert script.is_file()
    assert stat.S_IMODE(script.stat().st_mode) == 0o755


def test_owner_ui_smoke_scripts_are_executable_and_committed_executable() -> None:
    """Catch an installed-UI smoke helper the owner or gate cannot invoke."""
    scripts = ("tools/setup-browser-tests.sh", "tools/smoke-ui.sh")
    for name in scripts:
        script = REPO_ROOT / name
        assert script.is_file(), name
        assert stat.S_IMODE(script.stat().st_mode) == 0o755, name

    listed = subprocess.run(
        ["git", "ls-files", "-s", *scripts],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert listed.returncode == 0, listed.stderr
    assert sorted(line.split(" ", 1)[0] for line in listed.stdout.splitlines()) == [
        "100755",
        "100755",
    ]


def test_project_gate_runs_the_browser_journey_suite() -> None:
    """Catch a repository gate that silently skips the real-browser journeys."""
    gate = (REPO_ROOT / "tools" / "check.sh").read_text(encoding="utf-8")

    assert "./tools/setup-browser-tests.sh" in gate
    assert "uv run pytest" in gate
    assert (REPO_ROOT / "tests" / "browser" / "test_local_owner_ui.py").is_file()


def test_acceptance_tooling_is_excluded_from_the_installed_distribution() -> None:
    """Catch acceptance or client-launcher code moving under the wheel package."""
    preparers = (
        REPO_ROOT / "tools" / "prepare-ui-acceptance.py",
        REPO_ROOT / "tools" / "run-behavioral-acceptance.py",
    )

    assert all(preparer.is_file() for preparer in preparers)
    package = REPO_ROOT / "src" / "memory"
    for path in package.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "codex" not in text.lower(), path
        assert "claude" not in text.lower(), path


def test_check_loc_counts_the_source_tests_and_tools() -> None:
    """Catch project checks silently omitting the new src-layout package."""
    roots = (
        REPO_ROOT / "src" / "memory",
        REPO_ROOT / "tests",
        REPO_ROOT / "tools",
    )
    expected = sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for root in roots
        for path in root.rglob("*")
        if path.suffix in {".py", ".sh", ".sql"}
    )

    result = subprocess.run(
        [REPO_ROOT / "tools" / "check.sh", "--loc"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    match = re.fullmatch(r"Authored LOC \(source \+ tests\): (\d+)\n", result.stdout)
    assert match is not None
    assert int(match.group(1)) == expected
    assert result.stderr == ""


def test_import_time_invariants_survive_optimised_python() -> None:
    """Catch a shipped budget stated as an assert that ``python -O`` discards.

    Module-level asserts are the response-size and label-set budgets the routes
    promise. An optimised interpreter drops them, so the ceiling would go
    unenforced in exactly the build the owner runs. Narrowing asserts inside a
    function are not this: they document a type, they do not enforce a bound.
    """
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{node.lineno}"
        for path in sorted((REPO_ROOT / "src" / "memory").rglob("*.py"))
        for node in ast.parse(
            path.read_text(encoding="utf-8"),
            filename=str(path),
        ).body
        if isinstance(node, ast.Assert)
    ]

    assert offenders == []


def test_source_imports_no_model_provider_packages() -> None:
    """Catch provider reasoning entering the Store kernel."""
    forbidden = {
        "anthropic",
        "google.generativeai",
        "httpx",
        "httpx2",
        "openai",
    }
    imported: set[str] = set()
    for path in (REPO_ROOT / "src" / "memory").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)

    violations = {
        name
        for name in imported
        for blocked in forbidden
        if name == blocked or name.startswith(f"{blocked}.")
    }
    assert violations == set()


def test_package_source_names_no_client_vendors() -> None:
    """AGENTS.md: package source under src/memory/ must not name client vendors."""
    text_suffixes = {".py", ".md", ".sql", ".html", ".css", ".js"}
    vendor_names = ("anthropic", "claude", "codex", "openai")
    violations: list[str] = []
    for path in sorted((REPO_ROOT / "src" / "memory").rglob("*")):
        if not path.is_file() or path.suffix not in text_suffixes:
            continue
        folded = path.read_text(encoding="utf-8").casefold()
        violations.extend(
            f"{path.relative_to(REPO_ROOT)}: {vendor}"
            for vendor in vendor_names
            if vendor in folded
        )
    assert violations == []


def test_wheel_contains_only_the_store_package_schema_and_console_entrypoint(
    tmp_path: Path,
) -> None:
    """Catch a wheel that omits runtime assets or accidentally ships old code."""
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as wheel:
        names = set(wheel.namelist())
        entry_points_name = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points = wheel.read(entry_points_name).decode("utf-8")

    assert {
        "memory/__init__.py",
        "memory/cli.py",
        "memory/database.py",
        "memory/errors.py",
        "memory/inbox.py",
        "memory/keys.py",
        "memory/mcp_prompts.py",
        "memory/mcp_server.py",
        "memory/model.py",
        "memory/retrieval.py",
        "memory/runtime.py",
        "memory/schema.sql",
        "memory/py.typed",
        "memory/skill/SKILL.md",
        # The wheel is the only artifact an installed client has; a copied
        # Skill cannot be verified from a repository helper it never received.
        "memory/skill_sync.py",
        "memory/sources.py",
        "memory/staging_provenance.py",
        "memory/ui/capture.py",
        "memory/ui/owner_presence.py",
        "memory/ui/routes/inbox.py",
        "memory/ui/routes/reviews.py",
        "memory/ui/static/app.css",
        "memory/ui/static/bootstrap.js",
        "memory/ui/static/ui.js",
        "memory/ui/templates/base.html",
        "memory/ui/templates/inbox/index.html",
        "memory/ui/templates/reviews/approve.html",
        "memory/ui/templates/reviews/detail.html",
        "memory/ui/templates/reviews/edit.html",
        "memory/ui/templates/reviews/list.html",
        "memory/ui/templates/status.html",
    } <= names
    assert entry_points == "[console_scripts]\nmemory = memory.cli:main\n"


def test_sdist_excludes_internal_paths_and_reproduces_across_builds(
    tmp_path: Path,
) -> None:
    """Catch internal planning, cache, or test material shipping in the sdist."""
    digests: list[str] = []
    members: list[set[str]] = []
    for attempt in ("first", "second"):
        out_dir = tmp_path / attempt
        result = subprocess.run(
            ["uv", "build", "--sdist", "--out-dir", str(out_dir)],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        archives = list(out_dir.glob("*.tar.gz"))
        assert len(archives) == 1
        digests.append(hashlib.sha256(archives[0].read_bytes()).hexdigest())
        with tarfile.open(archives[0]) as archive:
            members.append(
                {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
            )

    assert digests[0] == digests[1]
    assert members[0] == members[1]
    shipped = members[0]
    forbidden_prefixes = (
        ".claude/",
        ".github/",
        ".hypothesis/",
        ".pytest_cache/",
        "scratch/",
        ".venv/",
        ".worktrees/",
        "dist/",
        "docs/",
        "tests/",
        "tools/",
    )
    for name in shipped:
        assert not name.startswith(forbidden_prefixes), name
    assert {
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src/memory/__init__.py",
        "src/memory/cli.py",
        "src/memory/schema.sql",
        "src/memory/skill/SKILL.md",
        "src/memory/ui/static/app.css",
        "src/memory/ui/templates/base.html",
    } <= shipped


def test_wheel_smoke_ignores_stale_dist_and_imports_only_from_its_venv(
    tmp_path: Path,
) -> None:
    """Catch stale-wheel selection or checkout imports masking a broken wheel."""
    environment = synthetic_smoke_environment(tmp_path)
    dist = REPO_ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stale = dist / "memory-zzzz-py3-none-any.whl"
    stale.write_bytes(b"synthetic invalid stale wheel\n")
    try:
        result = run_wheel_smoke(environment)
    finally:
        stale.unlink(missing_ok=True)

    assert result.returncode == 0, result.stderr
    module_lines = [
        line for line in result.stdout.splitlines() if line.startswith("Wheel module: ")
    ]
    assert len(module_lines) == 1
    module_path = Path(module_lines[0].removeprefix("Wheel module: "))
    assert module_path.is_relative_to(tmp_path)
    assert "site-packages/memory/__init__.py" in module_path.as_posix()
    assert not module_path.is_relative_to(REPO_ROOT / "src")
    skill_lines = [
        line for line in result.stdout.splitlines() if line.startswith("Wheel skill: ")
    ]
    assert len(skill_lines) == 1
    skill_path = Path(skill_lines[0].removeprefix("Wheel skill: "))
    assert skill_path.is_relative_to(tmp_path)
    assert "site-packages/memory/skill/SKILL.md" in (skill_path.as_posix())
    digest_lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("Wheel skill digest: ")
    ]
    skill_bytes = (REPO_ROOT / "src" / "memory" / "skill" / "SKILL.md").read_bytes()
    normalized_skill = skill_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    expected_skill_digest = hashlib.sha256(normalized_skill).hexdigest()
    assert digest_lines == [f"Wheel skill digest: {expected_skill_digest}"]
    calls = (tmp_path / "security-calls").read_text(encoding="utf-8").splitlines()
    assert calls == ["delete-generic-password", "find-generic-password"]
    assert (tmp_path / "synthetic-key-state").read_text(encoding="utf-8") == (
        "absent\n"
    )
    store_home = Path((tmp_path / "store-home-log").read_text(encoding="utf-8"))
    assert not store_home.exists()


def test_wheel_smoke_probes_installed_legacy_stdio_server() -> None:
    """Catch exact-wheel packaging omitting MCP discovery and call coverage."""
    smoke = (REPO_ROOT / "tools" / "smoke-wheel.sh").read_text(encoding="utf-8")

    assert "PRAGMA cipher_version" in smoke
    assert "PRAGMA cipher_status" in smoke
    assert "PRAGMA cipher_provider" in smoke
    assert "PRAGMA compile_options" in smoke
    assert "SELECT sqlite_version()" in smoke
    assert 'version("memory-sqlcipher3")' in smoke
    assert 'cipher_row == ("4.17.0 community",)' in smoke
    assert 'sqlite_row == ("3.53.3",)' in smoke
    assert "otool -L" in smoke
    assert "Wheel SQLCipher engine:" in smoke
    assert "Wheel SQLite engine:" in smoke
    assert "StdioServerParameters" in smoke
    assert "StdioTransport" in smoke
    assert "mode=mode" in smoke
    assert "client.list_tools()" in smoke
    assert 'client.call_tool("store.status", {})' in smoke
    assert 'assert modern_protocol == "2026-07-28"' in smoke
    assert 'assert legacy_protocol == "2025-11-25"' in smoke
    assert 'args=["mcp", "--home", sys.argv[2]]' in smoke
    assert "mcp==1.29.0" in smoke
    assert "initialized.protocolVersion" in smoke
    assert 'assert protocol == "2025-11-25"' in smoke


def test_wheel_smoke_ignores_an_inherited_alternate_uv_project(
    tmp_path: Path,
) -> None:
    """Catch UV_PROJECT redirecting the smoke build to another checkout."""
    environment = synthetic_smoke_environment(tmp_path)
    alternate = tmp_path / "synthetic-alternate-project"
    package = alternate / "memory"
    package.mkdir(parents=True)
    (alternate / "pyproject.toml").write_text(
        """\
[project]
name = "memory"
version = "9.9.9"
requires-python = ">=3.14"

[build-system]
requires = ["hatchling>=1.32.0"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["memory"]
""",
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(
        """\
import os
from pathlib import Path

marker = os.environ.get("MEMORY_SMOKE_ALTERNATE_IMPORT_MARKER")
if marker is not None:
    Path(marker).write_text("alternate wheel imported\\n", encoding="utf-8")
""",
        encoding="utf-8",
    )
    marker = tmp_path / "alternate-imported"
    environment["UV_PROJECT"] = str(alternate)
    environment["MEMORY_SMOKE_ALTERNATE_IMPORT_MARKER"] = str(marker)

    result = run_wheel_smoke(environment)

    assert result.returncode == 0, result.stderr
    assert not marker.exists()


def test_wheel_smoke_refuses_multiple_wheels_in_its_unique_wheelhouse(
    tmp_path: Path,
) -> None:
    """Catch ambiguous artifact selection even inside an isolated build directory."""
    environment = synthetic_smoke_environment(tmp_path)
    real_uv = shutil.which("uv")
    assert real_uv is not None
    fake_uv = write_executable(
        tmp_path / "synthetic-uv",
        """\
import os
import pathlib
import shutil
import subprocess
import sys

arguments = sys.argv[1:]
completed = subprocess.run([os.environ["MEMORY_SMOKE_REAL_UV"], *arguments], check=False)
if completed.returncode != 0:
    raise SystemExit(completed.returncode)
if arguments and arguments[0] == "build":
    out_dir = pathlib.Path(arguments[arguments.index("--out-dir") + 1])
    wheel = next(out_dir.glob("*.whl"))
    shutil.copyfile(wheel, out_dir / "synthetic_duplicate.whl")
""",
    )
    environment["MEMORY_SMOKE_UV_COMMAND"] = str(fake_uv)
    environment["MEMORY_SMOKE_REAL_UV"] = real_uv
    dist = REPO_ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stale = dist / "memory-zzzz-py3-none-any.whl"
    stale.write_bytes(b"synthetic invalid stale wheel\n")
    try:
        result = run_wheel_smoke(environment)
    finally:
        stale.unlink(missing_ok=True)

    assert result.returncode != 0
    assert "exactly one Store wheel" in result.stderr
    assert not (tmp_path / "store-home-log").exists()
    assert not (tmp_path / "security-calls").exists()


@pytest.mark.parametrize(
    ("failure_variable", "expected_calls"),
    [
        ("MEMORY_SMOKE_DELETE_FAILURE", ["delete-generic-password"]),
        (
            "MEMORY_SMOKE_FIND_FAILURE",
            ["delete-generic-password", "find-generic-password"],
        ),
    ],
)
def test_wheel_smoke_propagates_key_cleanup_failure_and_retains_runtime(
    tmp_path: Path,
    failure_variable: str,
    expected_calls: list[str],
) -> None:
    """Catch cleanup failures being swallowed after deleting recovery state."""
    environment = synthetic_smoke_environment(tmp_path)
    environment[failure_variable] = "1"

    result = run_wheel_smoke(environment)

    assert result.returncode != 0
    store_home = Path((tmp_path / "store-home-log").read_text(encoding="utf-8"))
    assert store_home.is_dir()
    identity = json.loads((store_home / "runtime.json").read_text(encoding="utf-8"))
    assert identity == {
        "product": "memory",
        "schema_lineage": "memory-store-v1",
        "schema_version": 1,
        "store_id": "a1" * 16,
        "runtime_mode": "personal",
        "inbox_path": str(store_home / "inbox"),
    }
    assert (store_home / "store.sqlite3").is_file()
    assert (store_home / "inbox").is_dir()
    assert (store_home / "inbox-claims").is_dir()
    assert (store_home / "inbox-staging").is_dir()
    assert str(store_home) in result.stderr
    calls = (tmp_path / "security-calls").read_text(encoding="utf-8").splitlines()
    assert calls == expected_calls


def test_wheel_smoke_refuses_cleanup_for_an_incomplete_store_identity(
    tmp_path: Path,
) -> None:
    """Catch cleanup deleting a key selected from only a partial identity check."""
    environment = synthetic_smoke_environment(tmp_path)
    environment["MEMORY_SMOKE_SYNTHETIC_LINEAGE"] = "synthetic-foreign-lineage"

    result = run_wheel_smoke(environment)

    assert result.returncode != 0
    store_home = Path((tmp_path / "store-home-log").read_text(encoding="utf-8"))
    assert store_home.is_dir()
    assert (store_home / "runtime.json").is_file()
    assert str(store_home) in result.stderr
    assert not (tmp_path / "security-calls").exists()


def test_synced_environment_exposes_store_console_command() -> None:
    command = shutil.which("memory")

    assert command is not None
    result = subprocess.run(
        [command, "--version"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert re.fullmatch(r"memory \d+\.\d+\.\d+\n", result.stdout)
    assert result.stderr == ""


def test_owner_presence_module_is_the_only_production_approval_minting_path() -> None:
    """Catch a second production path minting an internal owner approval."""
    package = REPO_ROOT / "src" / "memory"
    minting = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if "_APPROVAL_CONSTRUCTOR" in path.read_text(encoding="utf-8")
        or "_mint_bound_owner_approval" in path.read_text(encoding="utf-8")
        or "_PRESENCE_CONSTRUCTOR" in path.read_text(encoding="utf-8")
    }

    assert minting == {"reviews.py", "ui/owner_presence.py"}


def test_owner_presence_never_reads_the_environment_argv_or_a_terminal() -> None:
    """Catch an environment variable, argv, or TTY check standing in for the OS."""
    path = REPO_ROOT / "src" / "memory" / "ui" / "owner_presence.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}

    assert attributes.isdisjoint(
        {"environ", "getenv", "argv", "isatty", "stdin", "stdout", "ttyname"}
    )
    assert names.isdisjoint({"input", "getpass", "os", "sys"})
