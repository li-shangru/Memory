"""One reviewed public-release dependency transition; no general upgrade resolver."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import delivery_probe as probe

POLICY = Path(__file__).with_name("public-dependency-transition.json")


class EntryPointParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


class TransitionError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise TransitionError(code)


@dataclass(frozen=True)
class Target:
    before: str
    after: str
    filename: str
    url: str
    sha256: str


def policy() -> tuple[str, str, dict[str, Target]]:
    require(POLICY.is_file() and not POLICY.is_symlink(), "dependency_policy_invalid")
    value = json.loads(POLICY.read_text())
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "release_commit", "version", "dependencies"}
        and value["schema"] == "memory.public-dependency-transition.v1"
        and isinstance(value["release_commit"], str)
        and re.fullmatch(r"[0-9a-f]{40}", value["release_commit"]) is not None
        and isinstance(value["version"], str)
        and isinstance(value["dependencies"], dict),
        "dependency_policy_invalid",
    )
    targets: dict[str, Target] = {}
    for name, item in value["dependencies"].items():
        require(
            isinstance(name, str)
            and isinstance(item, dict)
            and set(item) == {"before", "after", "filename", "url", "sha256"}
            and all(isinstance(v, str) and bool(v) for v in item.values()),
            "dependency_policy_invalid",
        )
        target = Target(**item)
        require(
            Path(target.filename).name == target.filename
            and target.filename.endswith(".whl")
            and target.url.startswith("https://files.pythonhosted.org/")
            and re.fullmatch(r"[0-9a-f]{64}", target.sha256) is not None,
            "dependency_policy_invalid",
        )
        targets[name] = target
    require(bool(targets), "dependency_policy_invalid")
    return value["release_commit"], value["version"], targets


def applies(manifest: dict[str, object]) -> bool:
    commit, version, _ = policy()
    return (
        manifest.get("source_commit") == commit and manifest.get("version") == version
    )


def expected_versions(before: dict[str, str]) -> dict[str, str]:
    result = dict(before)
    targets = policy()[2]
    require(targets.keys() <= before.keys(), "dependency_transition_unapproved")
    for name, target in targets.items():
        require(
            before[name] in {target.before, target.after},
            "dependency_transition_unapproved",
        )
        result[name] = target.after
    return result


def artifact_paths(release: Path) -> dict[str, Path]:
    _, version, targets = policy()
    root = release.parent / f"v{version}-public-dependencies"
    return {name: root / target.filename for name, target in targets.items()}


def verify_artifact(path: Path, target: Target) -> None:
    require(
        path.is_file()
        and not path.is_symlink()
        and hashlib.sha256(path.read_bytes()).hexdigest() == target.sha256,
        "dependency_artifact_drift",
    )


def prepare_artifacts(release: Path) -> dict[str, Path]:
    paths = artifact_paths(release)
    for name, target in policy()[2].items():
        path = paths[name]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not path.parent.is_symlink(), "dependency_artifact_drift")
        if not path.exists():
            descriptor, temporary = tempfile.mkstemp(
                dir=path.parent, prefix=".download-"
            )
            try:
                with os.fdopen(descriptor, "wb") as output:
                    with urllib.request.urlopen(target.url, timeout=60) as source:
                        while chunk := source.read(1024 * 1024):
                            output.write(chunk)
                verify_artifact(Path(temporary), target)
                os.rename(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        verify_artifact(path, target)
    return paths


def verify_distribution(
    files: dict[str, str],
    wheel: Path,
    target: Target,
    prefix: Path,
    launcher: Callable[[Path, Path, str], None],
    shared_files: dict[str, str] | None = None,
) -> None:
    verify_artifact(wheel, target)
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        require(
            len(names) == len(set(names))
            and all(
                not Path(name).is_absolute()
                and ".." not in Path(name).parts
                and not any(part.endswith(".data") for part in Path(name).parts)
                for name in names
            ),
            "dependency_artifact_layout",
        )
        expected = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in names
            if not (
                Path(name).parent.name.endswith(".dist-info")
                and Path(name).name == "RECORD"
            )
        }
        entries = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        require(len(entries) <= 1, "dependency_artifact_layout")
        scripts: dict[str, str] = {}
        if entries:
            parser = EntryPointParser(interpolation=None)
            parser.read_string(archive.read(entries[0]).decode())
            if parser.has_section("console_scripts"):
                scripts = dict(parser.items("console_scripts"))
        generated = {f"../../../bin/{name}" for name in scripts}
        require(
            {name: digest for name, digest in files.items() if name not in generated}
            == expected
            and generated <= files.keys(),
            "dependency_artifact_bytes_changed",
        )
        # RECORD cannot reveal unrecorded code. Enumerate each actual package and
        # metadata root through the same descriptor-bound reader as the probe.
        roots = {Path(name).parts[0] for name in expected}
        actual: dict[str, str] = {}
        for root in roots:
            path = prefix / "lib/python3.14/site-packages" / root
            if path.is_dir():
                actual.update(
                    {
                        f"{root}/{name}": digest
                        for name, digest in probe._installed_fingerprint(
                            prefix, path
                        ).items()
                    }
                )
            else:
                actual[root] = probe._installed_hash(prefix, path)
        installer_files = {
            "RECORD",
            "direct_url.json",
            "INSTALLER",
            "REQUESTED",
            "uv_cache.json",
        }
        actual = {
            name: digest
            for name, digest in actual.items()
            if not (
                Path(name).parent.name.endswith(".dist-info")
                and Path(name).name in installer_files
            )
        }
        # Other recorded distributions may own part of a namespace package.
        # They cannot claim extra files inside this distribution's metadata.
        shared = {
            name: digest
            for name, digest in (shared_files or {}).items()
            if Path(name).parts[0] in roots
            and not Path(name).parts[0].endswith(".dist-info")
        }
        require(
            all(
                name not in expected or expected[name] == digest
                for name, digest in shared.items()
            )
            and actual == {**shared, **expected},
            "dependency_artifact_bytes_changed",
        )
        for name, entry in scripts.items():
            require(
                re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None,
                "dependency_artifact_layout",
            )
            launcher(
                prefix / "bin" / name,
                prefix / "bin/python",
                entry.split("[", 1)[0].strip(),
            )


def verify_installed(
    snapshot: dict[str, object],
    release: Path,
    launcher: Callable[[Path, Path, str], None],
) -> None:
    versions, inventories, prefix = (
        snapshot.get("dependencies"),
        snapshot.get("dependency_files"),
        snapshot.get("prefix"),
    )
    require(
        isinstance(versions, dict)
        and isinstance(inventories, dict)
        and isinstance(prefix, str),
        "dependency_snapshot_failed",
    )
    assert (
        isinstance(versions, dict)
        and isinstance(inventories, dict)
        and isinstance(prefix, str)
    )
    paths = artifact_paths(release)
    for name, target in policy()[2].items():
        require(
            versions.get(name) == target.after
            and isinstance(inventories.get(name), dict),
            "dependency_transition_unapproved",
        )
        shared: dict[str, str] = {}
        for other, members in inventories.items():
            if other != name:
                require(isinstance(members, dict), "dependency_snapshot_failed")
                shared.update(cast("dict[str, str]", members))
        verify_distribution(
            cast("dict[str, str]", inventories[name]),
            paths[name],
            target,
            Path(prefix),
            launcher,
            shared,
        )
