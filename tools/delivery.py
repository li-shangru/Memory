#!/usr/bin/env python3
"""Enforce an exact local Memory release, installation, Skills and fresh MCP proof."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import email.parser
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import dependency_transition as transition
import staged_memory_intake_sync as bundle

REPO = Path(__file__).resolve().parents[1]
PROFILE_SCHEMA = "memory.delivery-profile.v1"
RELEASE_SCHEMA = "memory.local-release.v1"
COMPANION_VERSION = "0.6.2+sqlcipher4.17.0.memory1"
PREVIOUS_COMPANION_VERSION = "0.6.2+sqlcipher4.17.0"
COMPANION_NAME = (
    "memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"
)
COMPANION_SHA256 = "3436966d149f0e498f69aa78612bc8be2b9c8340fa44c5fb3f4cc50c5ddf2106"
HELP = {
    "profile_missing": "Run ./tools/deliver.sh configure with the intended installation, configuration files and Skill roots; see docs/local-delivery.md.",
    "profile_invalid": "Repair the private profile with ./tools/deliver.sh configure; no runtime paths are accepted.",
    "source_not_released": "Source inputs differ from this version's frozen release. Bump the coupled version, commit, and run ./tools/deliver.sh run.",
    "release_missing": "Run ./tools/deliver.sh run to qualify, build, install, synchronize and verify this source version.",
    "release_artifact_drift": "A frozen artifact differs from its manifest. Restore the verified artifact or make a new local version; do not overwrite the receipt.",
    "package_bytes_drift": "The installed package differs from source despite any matching version. Run ./tools/deliver.sh run.",
    "package_version_drift": "The source version has not reached the installed package. Run ./tools/deliver.sh run.",
    "package_metadata_drift": "Installed metadata differs from the exact wheel. Reinstall through ./tools/deliver.sh run.",
    "editable_metadata_drift": "This editable installation has stale version or dependency metadata. Memory delivery requires reinstalling the exact wheel through ./tools/deliver.sh run.",
    "editable_installation": "Memory's everyday command must use an installed wheel. Keep editable environments for source work and configure the uv tool installation.",
    "installation_origin_drift": "The interpreter/package/wheel origin is not the configured installation. Fix the local profile or entry point; see docs/local-delivery.md.",
    "configured_entrypoint_drift": "A selected client points to another command. Correct its Memory entry, then rerun; this workflow never edits or executes saved runtime arguments.",
    "unsupported_configuration": "The selected Memory entry uses unsupported arguments, environment overrides, or transport. Configure a direct memory mcp command; runtime --home and --trust-elicitation are permitted but never replayed by verification.",
    "project_configuration_override": "A selected workspace has a project-specific Memory MCP override. Review that metadata and remove the obsolete override or extend this verifier for its effective configuration before claiming freshness. No override is launched or edited.",
    "executable_interpreter_drift": "The CLI shebang selects another environment. Reinstall the intended uv tool and check the configured command path.",
    "unsupported_launcher": "The CLI is not a recognized generated memory.cli:main launcher. Reinstall through the documented uv tool command; wrappers are not certified.",
    "shell_entrypoint_drift": "The launching shell resolves memory to another installation. Correct PATH and rerun ./tools/deliver.sh.",
    "copied_skill_drift": "A copied Skill is missing or differs from canonical bytes. Run ./tools/deliver.sh run; locally modified staged bundles refuse replacement until reviewed.",
    "wrong_install_target": "The profile does not name uv's current Memory tool environment/bin directory. Correct the profile before installation.",
    "dirty_release_source": "Commit the reviewed candidate before local release. Read-only check remains available; no unrelated work is committed automatically.",
    "tag_drift": "The local version tag differs from the frozen release commit. Inspect and resolve locally; this workflow never moves an existing tag.",
    "delivery_in_progress": "Another delivery attempt owns this local profile. Wait for it to finish, then rerun; its current receipt was preserved.",
}


class DeliveryError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise DeliveryError(code)


def safe_environment() -> dict[str, str]:
    allowed = {"HOME", "USER", "LOGNAME", "PATH", "SHELL", "LANG", "LC_CTYPE", "TMPDIR"}
    result = {key: value for key, value in os.environ.items() if key in allowed}
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    return result


def fingerprint(root: Path) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), "package_missing")
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        require(not path.is_symlink(), "package_symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256(path)
        else:
            require(path.is_dir(), "package_special_file")
    require(bool(result), "package_missing")
    return result


def sha256(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "release_artifact_drift")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(not path.is_symlink(), "unsafe_receipt")
    if path.is_file() and path.read_bytes() == encoded:
        path.chmod(0o600)
        return
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def json_object(path: Path, code: str) -> dict[str, object]:
    try:
        require(path.is_file() and not path.is_symlink(), code)
        result: object = json.loads(path.read_text())
        require(isinstance(result, dict), code)
        return cast(dict[str, object], result)
    except (OSError, ValueError) as error:
        raise DeliveryError(code) from error


def acquire_lock(profile: Path) -> int:
    profile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        profile.with_name("memory-delivery.lock"),
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise DeliveryError("delivery_in_progress") from error


def string_map(value: object, code: str) -> dict[str, str]:
    require(isinstance(value, dict), code)
    assert isinstance(value, dict)
    require(
        all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()), code
    )
    return cast(dict[str, str], value)


@dataclass(frozen=True)
class Profile:
    executable: Path
    python: Path
    configurations: tuple[tuple[str, Path], ...]
    skill_roots: tuple[Path, ...]
    workspaces: tuple[Path, ...]

    def payload(self) -> dict[str, object]:
        return {
            "schema": PROFILE_SCHEMA,
            "executable": str(self.executable),
            "python": str(self.python),
            "configurations": [
                {"kind": kind, "path": str(path)} for kind, path in self.configurations
            ],
            "skill_roots": [str(path) for path in self.skill_roots],
            "workspaces": [str(path) for path in self.workspaces],
        }


def read_profile(path: Path) -> Profile:
    require(path.exists(), "profile_missing")
    value = json_object(path, "profile_invalid")
    require(
        set(value)
        == {
            "schema",
            "executable",
            "python",
            "configurations",
            "skill_roots",
            "workspaces",
        }
        and value["schema"] == PROFILE_SCHEMA,
        "profile_invalid",
    )
    executable, python = value["executable"], value["python"]
    configs, roots = value["configurations"], value["skill_roots"]
    workspaces = value["workspaces"]
    require(
        isinstance(executable, str)
        and isinstance(python, str)
        and isinstance(configs, list)
        and isinstance(roots, list),
        "profile_invalid",
    )
    assert isinstance(executable, str) and isinstance(python, str)
    assert isinstance(configs, list) and isinstance(roots, list)
    configurations: list[tuple[str, Path]] = []
    for item in configs:
        require(
            isinstance(item, dict) and set(item) == {"kind", "path"}, "profile_invalid"
        )
        require(
            item["kind"] in {"codex", "claude"} and isinstance(item["path"], str),
            "profile_invalid",
        )
        configurations.append((item["kind"], Path(item["path"])))
    require(all(isinstance(item, str) for item in roots), "profile_invalid")
    require(
        isinstance(workspaces, list)
        and all(isinstance(item, str) for item in workspaces),
        "profile_invalid",
    )
    assert isinstance(workspaces, list)
    profile = Profile(
        Path(executable),
        Path(python),
        tuple(configurations),
        tuple(Path(item) for item in roots),
        tuple(Path(item) for item in workspaces),
    )
    require(
        bool(profile.configurations)
        and bool(profile.skill_roots)
        and any(same_workspace(workspace, REPO) for workspace in profile.workspaces),
        "profile_invalid",
    )
    paths = [
        profile.executable,
        profile.python,
        *profile.skill_roots,
        *profile.workspaces,
        *(path for _, path in profile.configurations),
    ]
    require(all(path.is_absolute() for path in paths), "profile_invalid")
    require(
        len(set(profile.skill_roots)) == len(profile.skill_roots), "profile_invalid"
    )
    return profile


def verify_launcher(
    executable: Path, python: Path, entry_point: str = "memory.cli:main"
) -> None:
    require(
        executable.is_file() and os.access(executable, os.X_OK), "executable_missing"
    )
    module, separator, function = entry_point.partition(":")
    require(
        separator == ":"
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", module) is not None
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", function) is not None,
        "unsupported_launcher",
    )
    text = executable.read_text()
    require(text.splitlines()[0] == f"#!{python}", "executable_interpreter_drift")
    templates: tuple[str, ...] = (
        "import sys\nfrom memory.cli import main\nif __name__ == '__main__':\n    sys.exit(main())\n",
        "import sys\nfrom memory.cli import main\nif __name__ == '__main__':\n    if sys.argv[0].endswith('-script.pyw'):\n        sys.argv[0] = sys.argv[0][:-11]\n    elif sys.argv[0].endswith('.exe'):\n        sys.argv[0] = sys.argv[0][:-4]\n    sys.exit(main())\n",
        "import re\nimport sys\nfrom memory.cli import main\nif __name__ == '__main__':\n    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n    sys.exit(main())\n",
    )
    templates = tuple(
        template.replace(
            "from memory.cli import main",
            f"from {module} import {function.split('.')[0]}",
        ).replace("main()", f"{function}()")
        for template in templates
    )
    try:
        require(
            ast.dump(ast.parse(text))
            in {ast.dump(ast.parse(template)) for template in templates},
            "unsupported_launcher",
        )
    except SyntaxError as error:
        raise DeliveryError("unsupported_launcher") from error


def verify_configuration(path: Path, kind: str, executable: Path) -> None:
    try:
        if kind == "codex":
            configuration = tomllib.loads(path.read_text())
            require(
                "project_root_markers" not in configuration,
                "unsupported_configuration",
            )
            selected = configuration["mcp_servers"]["memory"]
        elif kind == "claude":
            selected = json.loads(path.read_text())["mcpServers"]["memory"]
        else:
            raise DeliveryError("profile_invalid")
        require(
            isinstance(selected, dict)
            and set(selected) <= {"command", "args", "enabled", "env", "type"},
            "unsupported_configuration",
        )
        command = selected.get("command")
        arguments = selected.get("args", [])
        require(isinstance(command, str), "configured_entrypoint_drift")
        resolved = command if Path(command).is_absolute() else shutil.which(command)
        require(
            resolved is not None and Path(resolved).absolute() == executable.absolute(),
            "configured_entrypoint_drift",
        )
        require(
            selected.get("enabled", True) is True
            and selected.get("env", {}) == {}
            and selected.get("type", "stdio") == "stdio",
            "unsupported_configuration",
        )
        require(
            isinstance(arguments, list)
            and all(isinstance(item, str) for item in arguments),
            "unsupported_configuration",
        )
        require(bool(arguments) and arguments[0] == "mcp", "unsupported_configuration")
        # Validate only the invocation shape. Never resolve, stat, print, or replay
        # saved runtime arguments; fresh verification creates its own --home.
        remaining = list(arguments[1:])
        while remaining:
            option = remaining.pop(0)
            if option == "--home":
                require(bool(remaining), "unsupported_configuration")
                remaining.pop(0)
            else:
                require(option == "--trust-elicitation", "unsupported_configuration")
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise DeliveryError("configured_entrypoint_drift") from error


def verify_project_overrides(
    workspaces: tuple[Path, ...], configurations: tuple[tuple[str, Path], ...]
) -> None:
    try:
        layers = tuple(
            layer for workspace in workspaces for layer in project_layers(workspace)
        )
        for workspace in layers:
            for relative, section in (
                (".codex/config.toml", "mcp_servers"),
                (".mcp.json", "mcpServers"),
            ):
                path = workspace / relative
                if not path.exists():
                    continue
                value = (
                    tomllib.loads(path.read_text())
                    if path.suffix == ".toml"
                    else json.loads(path.read_text())
                )
                require(
                    "memory" not in value.get(section, {})
                    and "project_root_markers" not in value,
                    "project_configuration_override",
                )
        for kind, path in configurations:
            if kind != "claude":
                continue
            projects = json.loads(path.read_text()).get("projects", {})
            for name, project in projects.items():
                require(isinstance(name, str), "project_configuration_override")
                if not any(
                    same_workspace(Path(name), workspace) for workspace in layers
                ):
                    continue
                require(
                    "memory" not in project.get("mcpServers", {}),
                    "project_configuration_override",
                )
                require(
                    "memory" not in project.get("disabledMcpServers", []),
                    "project_configuration_override",
                )
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise DeliveryError("project_configuration_override") from error


def project_layers(workspace: Path) -> tuple[Path, ...]:
    """Bound inherited configuration to the selected workspace's Git project."""
    try:
        current = workspace.resolve(strict=True)
        require(current.is_dir(), "project_configuration_override")
        result = subprocess.run(
            ["git", "-C", str(current), "rev-parse", "--show-toplevel"],
            env=safe_environment(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        require(result.returncode == 0, "project_configuration_override")
        root = Path(result.stdout.strip()).resolve(strict=True)
        require(current.is_relative_to(root), "project_configuration_override")
        layers = [current]
        while layers[-1] != root:
            layers.append(layers[-1].parent)
        return tuple(reversed(layers))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise DeliveryError("project_configuration_override") from error


def same_workspace(candidate: Path, workspace: Path) -> bool:
    """Compare configured project directory identities, never runtime arguments."""
    if not candidate.is_absolute():
        return False
    try:
        return candidate.samefile(workspace)
    except OSError:
        require(
            str(candidate).casefold() != str(workspace).casefold(),
            "project_configuration_override",
        )
        return False


def verify_snapshot(
    value: dict[str, object],
    *,
    source_version: str,
    source_files: dict[str, str],
    wheel_metadata: str,
    wheel_entry_points: str,
    expected_prefix: Path,
    expected_wheel: Path,
) -> None:
    version_ok = (
        value.get("metadata_version") == value.get("module_version") == source_version
    )
    metadata_ok = (
        value.get("metadata") == wheel_metadata
        and value.get("entry_points") == wheel_entry_points
    )
    if value.get("editable") is True:
        require(version_ok and metadata_ok, "editable_metadata_drift")
        raise DeliveryError("editable_installation")
    require(version_ok, "package_version_drift")
    require(metadata_ok, "package_metadata_drift")
    require(value.get("python_version") == [3, 14], "python_version_drift")
    origin = value.get("origin")
    require(isinstance(origin, str), "installation_origin_drift")
    assert isinstance(origin, str)
    require(
        value.get("prefix") == str(expected_prefix)
        and Path(origin).is_relative_to(expected_prefix)
        and "site-packages" in Path(origin).parts
        and value.get("direct_url") == expected_wheel.as_uri(),
        "installation_origin_drift",
    )
    require(value.get("files") == source_files, "package_bytes_drift")


def expected_dependency_versions(
    before: dict[str, str], *, public_release: bool = False
) -> dict[str, str]:
    """Preserve the baseline except exact, artifact-bound reviewed transitions."""
    require(
        before.get("memory-sqlcipher3")
        in {PREVIOUS_COMPANION_VERSION, COMPANION_VERSION},
        "dependency_transition_unapproved",
    )
    expected = transition.expected_versions(before) if public_release else dict(before)
    return {**expected, "memory-sqlcipher3": COMPANION_VERSION}


def dependency_file_maps(value: object) -> dict[str, dict[str, str]]:
    require(isinstance(value, dict) and bool(value), "dependency_snapshot_failed")
    assert isinstance(value, dict)
    result: dict[str, dict[str, str]] = {}
    for name, files in value.items():
        require(isinstance(name, str), "dependency_snapshot_failed")
        assert isinstance(name, str)
        result[name] = string_map(files, "dependency_snapshot_failed")
        require(
            bool(result[name])
            and all(
                re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                for digest in result[name].values()
            ),
            "dependency_snapshot_failed",
        )
    return result


def verify_preserved_dependency_bytes(
    before: object,
    after: object,
    *,
    version_changes: dict[str, tuple[str, str]] | None = None,
) -> None:
    changes = version_changes or {}
    approved = transition.policy()[2]
    require(
        all(
            name in approved and pair == (approved[name].before, approved[name].after)
            for name, pair in changes.items()
        ),
        "dependency_transition_unapproved",
    )
    original, installed = dependency_file_maps(before), dependency_file_maps(after)
    require(set(original) == set(installed), "dependency_bytes_changed")
    require(
        all(
            installed[name] == files
            for name, files in original.items()
            if name != "memory-sqlcipher3" and name not in changes
        ),
        "dependency_bytes_changed",
    )


def verify_companion(value: object, wheel: Path, expected_prefix: Path) -> None:
    """Bind installed native code and package inventory to the frozen wheel."""
    require(isinstance(value, dict), "companion_bytes_drift")
    assert isinstance(value, dict)
    origin = value.get("origin")
    require(
        isinstance(origin, str)
        and Path(origin).is_relative_to(expected_prefix)
        and "site-packages" in Path(origin).parts
        and Path(origin).name == "sqlcipher3",
        "companion_origin_drift",
    )
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "release_artifact_drift")
        files = {
            name.removeprefix("sqlcipher3/"): hashlib.sha256(
                archive.read(name)
            ).hexdigest()
            for name in names
            if name.startswith("sqlcipher3/") and not name.endswith("/")
        }
        require(bool(files) and value.get("files") == files, "companion_bytes_drift")
        distribution_files = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in names
            if not name.endswith("/")
            and name != metadata[0].removesuffix("METADATA") + "RECORD"
        }
        require(
            value.get("distribution_files") == distribution_files,
            "companion_bytes_drift",
        )
        require(
            value.get("version") == COMPANION_VERSION
            and value.get("metadata") == archive.read(metadata[0]).decode(),
            "companion_metadata_drift",
        )


def verify_release_inputs(recorded: object, current: dict[str, str]) -> None:
    require(recorded == current, "source_not_released")


def verify_skill_file(source: Path, target: Path) -> None:
    require(
        target.is_file()
        and not target.is_symlink()
        and target.read_bytes() == source.read_bytes(),
        "copied_skill_drift",
    )


def run_command(
    stage: str,
    command: list[str],
    *,
    cwd: Path,
    log: Path,
    environment: dict[str, str] | None = None,
    timeout: int = 1800,
) -> str:
    print(f"delivery: {stage}", flush=True)
    log.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with log.open("w") as output:
            os.chmod(log, 0o600)
            result = subprocess.run(
                command,
                cwd=cwd,
                env=environment or safe_environment(),
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
        require(result.returncode == 0, f"{stage}_failed")
        return log.read_text()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeliveryError(f"{stage}_failed") from error


def git(*arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), *arguments], text=True
    ).strip()


def default_profile() -> Path:
    directory = Path(git("rev-parse", "--git-common-dir"))
    return (
        directory if directory.is_absolute() else REPO / directory
    ) / "memory-delivery.json"


def source_version() -> str:
    version: object = tomllib.loads((REPO / "pyproject.toml").read_text())["project"][
        "version"
    ]
    require(
        isinstance(version, str)
        and re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
        "source_version_invalid",
    )
    assert isinstance(version, str)
    return version


def source_inputs() -> dict[str, str]:
    try:
        bundle.check_source(REPO / "tools/staged-memory-intake")
    except bundle.BundleError as error:
        raise DeliveryError(f"staged_source_{error.code}") from error
    result = {
        f"src/memory/{name}": digest
        for name, digest in fingerprint(REPO / "src/memory").items()
    }
    result.update(
        {
            f"tools/staged-memory-intake/{name}": digest
            for name, digest in fingerprint(REPO / "tools/staged-memory-intake").items()
        }
    )
    result.update(
        {
            name: sha256(REPO / name)
            for name in ("pyproject.toml", "uv.lock", "README.md")
        }
    )
    return result


def wheel_contents(wheel: Path) -> tuple[dict[str, str], str, str]:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "release_artifact_drift")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "release_artifact_drift")
        prefix = metadata[0].removesuffix("METADATA")
        for name, digest, size in csv.reader(
            io.StringIO(archive.read(prefix + "RECORD").decode())
        ):
            if name == prefix + "RECORD":
                continue
            content = archive.read(name)
            expected = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(content).digest()
            ).decode().rstrip("=")
            require(
                digest == expected and size == str(len(content)),
                "release_artifact_drift",
            )
        files = {
            name.removeprefix("memory/"): hashlib.sha256(archive.read(name)).hexdigest()
            for name in names
            if name.startswith("memory/") and not name.endswith("/")
        }
        return (
            files,
            archive.read(metadata[0]).decode(),
            archive.read(prefix + "entry_points.txt").decode(),
        )


def release_paths(version: str) -> tuple[Path, Path]:
    root = REPO / "dist" / f"v{version}"
    return root, root / f"memory-{version}-py3-none-any.whl"


def verify_release(root: Path, version: str) -> tuple[dict[str, object], str, str]:
    manifest = json_object(root / "release.json", "release_missing")
    require(
        manifest.get("schema") == RELEASE_SCHEMA and manifest.get("version") == version,
        "release_artifact_drift",
    )
    verify_release_inputs(manifest.get("inputs"), source_inputs())
    artifacts = string_map(manifest.get("artifacts"), "release_artifact_drift")
    names = {
        f"memory-{version}-py3-none-any.whl",
        f"memory-{version}.tar.gz",
        COMPANION_NAME,
    }
    require(set(artifacts) == names, "release_artifact_drift")
    require(artifacts[COMPANION_NAME] == COMPANION_SHA256, "release_artifact_drift")
    for name, digest in artifacts.items():
        require(sha256(root / name) == digest, "release_artifact_drift")
    files, metadata, entry_points = wheel_contents(
        root / f"memory-{version}-py3-none-any.whl"
    )
    require(files == fingerprint(REPO / "src/memory"), "release_artifact_drift")
    parsed = email.parser.Parser().parsestr(metadata)
    require(
        parsed["Name"] == "memory" and parsed["Version"] == version,
        "release_artifact_drift",
    )
    return manifest, metadata, entry_points


def freeze_release(version: str, logs: Path) -> tuple[Path, Path]:
    root, wheel = release_paths(version)
    if root.exists():
        verify_release(root, version)
        return root, wheel
    root.parent.mkdir(exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".v{version}.", dir=root.parent))
    try:
        run_command(
            "build",
            ["uv", "build", "--out-dir", str(temporary)],
            cwd=REPO,
            log=logs / "build.log",
        )
        copied = temporary / COMPANION_NAME
        require(
            sha256(REPO / "third_party/wheels" / COMPANION_NAME) == COMPANION_SHA256,
            "companion_drift",
        )
        shutil.copyfile(REPO / "third_party/wheels" / COMPANION_NAME, copied)
        files, _, _ = wheel_contents(temporary / wheel.name)
        require(files == fingerprint(REPO / "src/memory"), "release_artifact_drift")
        with tarfile.open(temporary / f"memory-{version}.tar.gz") as archive:
            source_files: dict[str, str] = {}
            for member in archive.getmembers():
                prefix = f"memory-{version}/src/memory/"
                if member.name.startswith(prefix) and member.isfile():
                    content = archive.extractfile(member)
                    require(content is not None, "release_artifact_drift")
                    assert content is not None
                    source_files[member.name.removeprefix(prefix)] = hashlib.sha256(
                        content.read()
                    ).hexdigest()
            require(source_files == files, "release_artifact_drift")
        names = (wheel.name, f"memory-{version}.tar.gz", COMPANION_NAME)
        manifest: dict[str, object] = {
            "schema": RELEASE_SCHEMA,
            "version": version,
            "source_commit": git("rev-parse", "HEAD"),
            "inputs": source_inputs(),
            "artifacts": {name: sha256(temporary / name) for name in names},
        }
        write_json(temporary / "release.json", manifest)
        os.rename(temporary, root)
        verify_release(root, version)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return root, wheel


def inspect_install(profile: Profile, logs: Path) -> dict[str, object]:
    output = run_command(
        "installed_metadata",
        [str(profile.python), "-I", str(REPO / "tools/delivery_probe.py"), "snapshot"],
        cwd=logs,
        log=logs / "installed-metadata.json",
        timeout=30,
    )
    value: object = json.loads(output)
    require(
        isinstance(value, dict) and value.get("status") == "passed",
        "installed_metadata_failed",
    )
    return cast(dict[str, object], value)


def verify_profile_commands(profile: Profile) -> None:
    verify_launcher(profile.executable, profile.python)
    shell_cli = os.environ.get("MEMORY_DELIVERY_SHELL_CLI") or shutil.which("memory")
    require(
        shell_cli is not None
        and Path(shell_cli).absolute() == profile.executable.absolute(),
        "shell_entrypoint_drift",
    )
    for kind, path in profile.configurations:
        verify_configuration(path, kind, profile.executable)
    verify_project_overrides(profile.workspaces, profile.configurations)


def verify_skills(profile: Profile, logs: Path, *, install: bool) -> None:
    canonical = REPO / "src/memory/skill/SKILL.md"
    staged = REPO / "tools/staged-memory-intake"
    for index, root in enumerate(profile.skill_roots):
        target = root / "using-memory/SKILL.md"
        for selected in (root, target.parent):
            require(
                not any(
                    parent.is_symlink() for parent in (selected, *selected.parents)
                ),
                "copied_skill_drift",
            )
        if install:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            run_command(
                "skill_install",
                [str(profile.executable), "skill", "install", "--target", str(target)],
                cwd=logs,
                log=logs / f"skill-{index}-install.json",
            )
        verify_skill_file(canonical, target)
        output = run_command(
            "skill_check",
            [str(profile.executable), "skill", "check", "--target", str(target)],
            cwd=logs,
            log=logs / f"skill-{index}-check.json",
        )
        result = json.loads(output)
        require(
            result.get("status") == "current" and result.get("byte_exact") is True,
            "copied_skill_drift",
        )
        try:
            if install:
                bundle.install_bundle(staged, root / "staged-memory-intake")
            bundle.check_install(staged, root / "staged-memory-intake")
        except bundle.BundleError as error:
            raise DeliveryError(f"copied_skill_drift:{error.code}") from error


def qualify_install(
    profile: Profile, version: str, logs: Path
) -> tuple[dict[str, object], dict[str, object], str, str]:
    """Qualify the new installation before its first CLI command or Skill write."""
    verify_profile_commands(profile)
    root, wheel = release_paths(version)
    snapshot = inspect_install(profile, logs)
    files = fingerprint(REPO / "src/memory")
    require(
        snapshot.get("metadata_version") == snapshot.get("module_version") == version,
        "editable_metadata_drift"
        if snapshot.get("editable") is True
        else "package_version_drift",
    )
    require(snapshot.get("files") == files, "package_bytes_drift")
    manifest, metadata, entry_points = verify_release(root, version)
    verify_snapshot(
        snapshot,
        source_version=version,
        source_files=files,
        wheel_metadata=metadata,
        wheel_entry_points=entry_points,
        expected_prefix=profile.python.parent.parent,
        expected_wheel=wheel,
    )
    verify_companion(
        snapshot.get("companion"), root / COMPANION_NAME, profile.python.parent.parent
    )
    dependency_files = dependency_file_maps(snapshot.get("dependency_files"))
    require(
        set(dependency_files)
        == set(string_map(snapshot.get("dependencies"), "dependency_snapshot_failed")),
        "dependency_snapshot_failed",
    )
    if transition.applies(manifest):
        transition.verify_installed(snapshot, root, verify_launcher)
    run_command(
        "dependency_check",
        ["uv", "pip", "check", "--python", str(profile.python)],
        cwd=logs,
        log=logs / "dependency-check.log",
    )
    return snapshot, manifest, metadata, entry_points


def check_delivery(profile: Profile, version: str, logs: Path) -> dict[str, object]:
    snapshot, manifest, metadata, entry_points = qualify_install(profile, version, logs)
    root, wheel = release_paths(version)
    files = fingerprint(REPO / "src/memory")
    version_text = run_command(
        "cli_version",
        [str(profile.executable), "--version"],
        cwd=logs,
        log=logs / "cli-version.log",
    )
    require(version_text.strip() == f"memory {version}", "package_version_drift")
    verify_skills(profile, logs, install=False)
    output = run_command(
        "fresh_process",
        [
            str(profile.python),
            "-I",
            str(REPO / "tools/delivery_probe.py"),
            "fresh",
            "--source",
            str(REPO),
            "--executable",
            str(profile.executable),
            "--version",
            version,
        ],
        cwd=logs,
        log=logs / "fresh-process.json",
        timeout=150,
    )
    fresh: object = json.loads(output)
    require(
        isinstance(fresh, dict) and fresh.get("status") == "passed",
        "fresh_process_failed",
    )
    # Verify again after subprocesses: source/configuration changes during a probe
    # cannot leave a completion receipt for a different candidate.
    verify_release(root, version)
    verify_profile_commands(profile)
    final_snapshot = inspect_install(profile, logs)
    verify_snapshot(
        final_snapshot,
        source_version=version,
        source_files=files,
        wheel_metadata=metadata,
        wheel_entry_points=entry_points,
        expected_prefix=profile.python.parent.parent,
        expected_wheel=wheel,
    )
    verify_companion(
        final_snapshot.get("companion"),
        root / COMPANION_NAME,
        profile.python.parent.parent,
    )
    require(
        final_snapshot.get("dependencies") == snapshot.get("dependencies")
        and final_snapshot.get("dependency_files") == snapshot.get("dependency_files"),
        "dependency_bytes_changed",
    )
    dependency_files = dependency_file_maps(snapshot.get("dependency_files"))
    return {
        "dependency_count": len(dependency_files),
        "dependency_file_count": sum(len(files) for files in dependency_files.values()),
        "dependency_files_sha256": hashlib.sha256(
            json.dumps(dependency_files, sort_keys=True).encode()
        ).hexdigest(),
        "companion_sha256": COMPANION_SHA256,
        "version": version,
        "source_commit": git("rev-parse", "HEAD"),
        "release_commit": manifest["source_commit"],
        "package_file_count": len(files),
        "package_sha256": hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()
        ).hexdigest(),
        "executable": str(profile.executable),
        "resolved_executable": str(profile.executable.resolve()),
        "python": str(profile.python),
        "package_origin": snapshot["origin"],
        "configurations_checked": len(profile.configurations),
        "skill_roots_checked": len(profile.skill_roots),
        "fresh_process": fresh,
        "existing_connections_verified": False,
    }


def install_release(
    profile: Profile, root: Path, wheel: Path, constraints: Path, logs: Path
) -> None:
    uv_root = run_command(
        "uv_tool_directory",
        ["uv", "tool", "dir"],
        cwd=logs,
        log=logs / "uv-tool-dir.log",
    ).strip()
    uv_bin = run_command(
        "uv_tool_bin",
        ["uv", "tool", "dir", "--bin"],
        cwd=logs,
        log=logs / "uv-tool-bin.log",
    ).strip()
    require(
        profile.python == Path(uv_root) / "memory/bin/python"
        and profile.executable == Path(uv_bin) / "memory",
        "wrong_install_target",
    )
    run_command(
        "installation",
        [
            "uv",
            "tool",
            "install",
            "--python",
            "3.14",
            "--force",
            "--constraints",
            str(constraints),
            "--with",
            str(root / COMPANION_NAME),
            str(wheel),
        ],
        cwd=logs,
        log=logs / "installation.log",
    )


def deliver(profile: Profile, version: str, logs: Path) -> dict[str, object]:
    require(not git("status", "--porcelain"), "dirty_release_source")
    verify_profile_commands(profile)
    run_command(
        "source_gate",
        [str(REPO / "tools/check.sh"), "--source-only"],
        cwd=REPO,
        log=logs / "source-gate.log",
    )
    root, wheel = freeze_release(version, logs)
    baseline = inspect_install(profile, logs)
    before = string_map(baseline.get("dependencies"), "dependency_snapshot_failed")
    require(
        all(
            re.fullmatch(r"[A-Za-z0-9_.-]+", name)
            and re.fullmatch(r"[A-Za-z0-9_.+!-]+", version)
            for name, version in before.items()
        ),
        "dependency_snapshot_failed",
    )
    baseline_files = dependency_file_maps(baseline.get("dependency_files"))
    require(set(baseline_files) == set(before), "dependency_snapshot_failed")
    public_release = version == "1.13.0" and transition.applies(
        json_object(root / "release.json", "release_missing")
    )
    expected = expected_dependency_versions(before, public_release=public_release)
    artifacts = transition.prepare_artifacts(root) if public_release else {}
    constraints = logs / "runtime-constraints.txt"
    constraints.write_text(
        "".join(
            f"{name} @ {artifacts[name].as_uri()}\n"
            if name in artifacts
            else f"{name}=={pin}\n"
            for name, pin in sorted(expected.items())
        )
    )
    constraints.chmod(0o600)
    environment = safe_environment()
    environment.update(
        MEMORY_SMOKE_WHEEL=str(wheel),
        MEMORY_SMOKE_WHEEL_SHA256=sha256(wheel),
        MEMORY_SMOKE_COMPANION=str(root / COMPANION_NAME),
        MEMORY_SMOKE_COMPANION_SHA256=COMPANION_SHA256,
        MEMORY_SMOKE_CONSTRAINTS=str(constraints),
    )
    for script in ("smoke-wheel", "smoke-ui"):
        run_command(
            script.replace("-", "_"),
            [str(REPO / "tools" / f"{script}.sh")],
            cwd=REPO,
            log=logs / f"{script}.log",
            environment=environment,
        )
    verify_release(root, version)
    install_release(profile, root, wheel, constraints, logs)
    installed, _, _, _ = qualify_install(profile, version, logs)
    require(
        installed.get("dependencies") == expected,
        "dependency_versions_changed",
    )
    verify_preserved_dependency_bytes(
        baseline.get("dependency_files"),
        installed.get("dependency_files"),
        version_changes={
            name: (before[name], pin)
            for name, pin in expected.items()
            if before[name] != pin and name != "memory-sqlcipher3"
        },
    )
    verify_skills(profile, logs, install=True)
    report = check_delivery(profile, version, logs)
    tag = f"v{version}"
    existing = git("tag", "--list", tag)
    if existing:
        require(
            git("rev-parse", f"{tag}^{{commit}}") == report["release_commit"],
            "tag_drift",
        )
    else:
        git(
            "tag",
            "-a",
            tag,
            str(report["release_commit"]),
            "-m",
            f"Memory {version}: verified local release and installation",
        )
    report["local_tag"] = tag
    transitions = {
        name: {"before": before[name], "after": pin}
        for name, pin in expected.items()
        if before[name] != pin
    }
    report["dependency_transitions"] = transitions
    report["dependency_versions_preserved"] = len(before) - len(transitions)
    if public_release:
        report["public_dependency_policy_sha256"] = sha256(transition.POLICY)
        report["public_dependency_artifacts"] = {
            name: {"filename": path.name, "sha256": sha256(path)}
            for name, path in artifacts.items()
        }
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("run", "check", "configure"):
        command = commands.add_parser(name)
        command.add_argument("--profile", type=Path)
        if name == "configure":
            command.add_argument("--executable", type=Path, required=True)
            command.add_argument("--python", type=Path, required=True)
            command.add_argument("--codex-config", type=Path)
            command.add_argument("--claude-config", type=Path)
            command.add_argument(
                "--skill-root", action="append", type=Path, required=True
            )
            command.add_argument(
                "--workspace", action="append", type=Path, required=True
            )
    return result


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    profile_path: Path = args.profile or default_profile()
    receipt = profile_path.with_name("memory-delivery-last.json")
    report: dict[str, object] = {
        "status": "failed",
        "command": args.command,
        "recorded_at": datetime.now(UTC).isoformat(),
        "existing_connections_verified": False,
    }
    logs: Path | None = None
    try:
        lock_descriptor = acquire_lock(profile_path)
    except DeliveryError as error:
        report.update(error=error.code, action=HELP[error.code])
        print(json.dumps(report, sort_keys=True, indent=2))
        return 1
    try:
        if args.command == "configure":
            selected = tuple(
                (kind, path)
                for kind, path in (
                    ("codex", args.codex_config),
                    ("claude", args.claude_config),
                )
                if path is not None
            )
            profile = Profile(
                args.executable,
                args.python,
                selected,
                tuple(args.skill_root),
                tuple(args.workspace),
            )
            require(bool(selected), "profile_invalid")
            # Validate serialization and invocation metadata before retaining it.
            with tempfile.TemporaryDirectory(
                prefix="memory-delivery-profile."
            ) as temporary:
                provisional = Path(temporary) / "profile.json"
                write_json(provisional, profile.payload())
                read_profile(provisional)
            verify_profile_commands(profile)
            write_json(profile_path, profile.payload())
            report["profile"] = str(profile_path)
        else:
            profile = read_profile(profile_path)
            version = source_version()
            logs = (
                profile_path.parent
                / "memory-delivery-logs"
                / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
            )
            logs.mkdir(mode=0o700, parents=True)
            write_json(receipt, report | {"status": "running", "logs": str(logs)})
            report.update(
                deliver(profile, version, logs)
                if args.command == "run"
                else check_delivery(profile, version, logs)
            )
            report["logs"] = str(logs)
            if args.command == "check":
                tag = f"v{version}"
                require(
                    git("tag", "--list", tag) == tag
                    and git("rev-parse", f"{tag}^{{commit}}")
                    == report["release_commit"],
                    "tag_drift",
                )
                report["local_tag"] = tag
        report["status"] = "passed"
    except Exception as error:
        code = (
            error.code
            if isinstance(error, (DeliveryError, transition.TransitionError))
            else type(error).__name__
        )
        report["error"] = code
        report["action"] = HELP.get(
            code.split(":")[0],
            "Inspect this run's private stage log, fix the reported failure, then rerun ./tools/deliver.sh. No successful delivery or existing-process update is claimed.",
        )
        if logs is not None:
            report["logs"] = str(logs)
    write_json(receipt, report)
    os.close(lock_descriptor)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
