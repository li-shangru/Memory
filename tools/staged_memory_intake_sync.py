#!/usr/bin/env python3
"""Freeze and synchronize the repository-owned companion Skill bundle."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Never

SCHEMA: Final = "staged-memory-intake.bundle.v1"
MANIFEST_NAME: Final = "bundle-manifest.json"
BUFFER_SIZE: Final = 1024 * 1024
replace_file = os.replace


class BundleError(Exception):
    """A content-free bundle synchronization failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BundleArgumentParser(argparse.ArgumentParser):
    """An argument parser whose failures never echo caller-controlled text."""

    def error(self, message: str) -> Never:
        del message
        raise BundleError("invalid_argument")

    def exit(self, status: int = 0, message: str | None = None) -> Never:
        if status:
            raise BundleError("invalid_argument")
        super().exit(status, message)


@dataclass(frozen=True, slots=True)
class BundleFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BundleManifest:
    schema: str
    files: tuple[BundleFile, ...]
    bundle_digest: str


def _bundle_digest(files: tuple[BundleFile, ...]) -> str:
    payload = [asdict(item) for item in files]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.name.endswith(".pyc")
        or "__pycache__" in path.parts
    ):
        raise BundleError("unsafe_entry")


def _validate_bundle_path(value: str) -> None:
    _validate_relative_path(value)
    path = PurePosixPath(value)
    allowed = (
        value == "SKILL.md"
        or value == "agents/openai.yaml"
        or (
            len(path.parts) == 2
            and path.parts[0] == "references"
            and path.suffix == ".md"
        )
        or (len(path.parts) >= 2 and path.parts[0] == "scripts")
    )
    if not allowed:
        raise BundleError("source_extra")


def _root_kind(root: Path, *, missing_code: str) -> None:
    _assert_no_symlink_components(root, allow_missing=False, missing_code=missing_code)
    try:
        mode = root.lstat().st_mode
    except FileNotFoundError as error:
        raise BundleError(missing_code) from error
    except OSError as error:
        raise BundleError(missing_code) from error
    if stat.S_ISLNK(mode):
        raise BundleError("unsafe_entry")
    if not stat.S_ISDIR(mode):
        raise BundleError(missing_code)


def _assert_no_symlink_components(
    path: Path,
    *,
    allow_missing: bool,
    missing_code: str,
) -> None:
    expanded = Path(os.path.expanduser(path))
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    current = Path(absolute.anchor)
    missing_seen = False
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as error:
            missing_seen = True
            if not allow_missing:
                raise BundleError(missing_code) from error
            continue
        except OSError as error:
            raise BundleError(missing_code) from error
        if missing_seen:
            raise BundleError(missing_code)
        if stat.S_ISLNK(mode):
            raise BundleError("unsafe_entry")


def _walk_regular_files(root: Path, *, extra_code: str) -> tuple[str, ...]:
    _root_kind(root, missing_code="source_invalid")
    files: list[str] = []
    directories: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise BundleError("unsafe_entry") from error
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            _validate_relative_path(relative)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as error:
                raise BundleError("unsafe_entry") from error
            if stat.S_ISLNK(mode):
                raise BundleError("unsafe_entry")
            if stat.S_ISDIR(mode):
                relative_path = PurePosixPath(relative)
                allowed_directory = relative in {"agents", "references", "scripts"} or (
                    len(relative_path.parts) > 1 and relative_path.parts[0] == "scripts"
                )
                if not allowed_directory:
                    raise BundleError(extra_code)
                directories.append(relative)
                pending.append(Path(entry.path))
            elif stat.S_ISREG(mode):
                files.append(relative)
            else:
                raise BundleError("unsafe_entry")
    if any(
        path.startswith("__pycache__/") or "/__pycache__/" in path for path in files
    ):
        raise BundleError("unsafe_entry")
    if any(path.endswith(".pyc") for path in files):
        raise BundleError("unsafe_entry")
    for relative_directory in directories:
        if relative_directory not in {"agents", "scripts"} and not any(
            path.startswith(f"{relative_directory}/") for path in files
        ):
            raise BundleError(extra_code)
    if extra_code == "source_extra":
        for path in files:
            if path != MANIFEST_NAME:
                _validate_bundle_path(path)
    return tuple(sorted(files))


def _read_regular(path: Path, *, code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BundleError(code) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BundleError("unsafe_entry")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, BUFFER_SIZE)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    except OSError as error:
        raise BundleError(code) from error
    finally:
        os.close(descriptor)


def _describe_file(root: Path, relative: str, *, code: str) -> BundleFile:
    content = _read_regular(root / relative, code=code)
    return BundleFile(
        path=relative,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_manifest(source: Path) -> BundleManifest:
    files = tuple(
        _describe_file(source, relative, code="source_invalid")
        for relative in _walk_regular_files(source, extra_code="source_extra")
        if relative != MANIFEST_NAME
    )
    if not files:
        raise BundleError("source_invalid")
    return BundleManifest(
        schema=SCHEMA,
        files=files,
        bundle_digest=_bundle_digest(files),
    )


def _manifest_bytes(manifest: BundleManifest) -> bytes:
    payload = {
        "schema": manifest.schema,
        "files": [asdict(item) for item in manifest.files],
        "bundle_digest": manifest.bundle_digest,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError as error:
        raise BundleError("install_failed") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise BundleError("install_failed") from error
    finally:
        os.close(descriptor)


def _replace_bytes(destination: Path, content: bytes, *, failure_code: str) -> None:
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        staged = Path(temporary_name)
        if (
            hashlib.sha256(_read_regular(staged, code=failure_code)).digest()
            != hashlib.sha256(content).digest()
        ):
            raise BundleError(failure_code)
        replace_file(staged, destination)
        temporary_name = None
        _fsync_directory(destination.parent)
    except BundleError:
        raise
    except OSError as error:
        raise BundleError(failure_code) from error
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass


def freeze_manifest(source: Path) -> BundleManifest:
    manifest = build_manifest(source)
    destination = source / MANIFEST_NAME
    try:
        _replace_bytes(
            destination, _manifest_bytes(manifest), failure_code="freeze_failed"
        )
        os.chmod(destination, 0o600, follow_symlinks=False)
    except BundleError:
        raise
    except OSError as error:
        raise BundleError("freeze_failed") from error
    return manifest


def _parse_manifest(content: bytes, *, code: str) -> BundleManifest:
    try:
        payload = json.loads(content)
        if not isinstance(payload, dict) or set(payload) != {
            "schema",
            "files",
            "bundle_digest",
        }:
            raise ValueError
        schema = payload["schema"]
        digest = payload["bundle_digest"]
        raw_files = payload["files"]
        if (
            schema != SCHEMA
            or not isinstance(digest, str)
            or not isinstance(raw_files, list)
        ):
            raise ValueError
        files: list[BundleFile] = []
        for raw in raw_files:
            if not isinstance(raw, dict) or set(raw) != {"path", "size", "sha256"}:
                raise ValueError
            path = raw["path"]
            size = raw["size"]
            sha256 = raw["sha256"]
            if (
                not isinstance(path, str)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(sha256, str)
                or len(sha256) != 64
                or any(character not in "0123456789abcdef" for character in sha256)
            ):
                raise ValueError
            _validate_bundle_path(path)
            files.append(BundleFile(path=path, size=size, sha256=sha256))
        frozen_files = tuple(files)
        if list(frozen_files) != sorted(frozen_files, key=lambda item: item.path):
            raise ValueError
        if len({item.path for item in frozen_files}) != len(frozen_files):
            raise ValueError
        manifest = BundleManifest(
            schema=schema, files=frozen_files, bundle_digest=digest
        )
        if (
            _bundle_digest(frozen_files) != digest
            or _manifest_bytes(manifest) != content
        ):
            raise ValueError
        return manifest
    except (
        BundleError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
    ) as error:
        raise BundleError(code) from error


def check_source(source: Path) -> BundleManifest:
    inventory = _walk_regular_files(source, extra_code="source_extra")
    if MANIFEST_NAME not in inventory:
        raise BundleError("source_manifest")
    content = _read_regular(source / MANIFEST_NAME, code="source_manifest")
    manifest = _parse_manifest(content, code="source_manifest")
    if _manifest_bytes(build_manifest(source)) != content:
        raise BundleError("source_manifest")
    try:
        manifest_mode = (
            source.joinpath(MANIFEST_NAME).stat(follow_symlinks=False).st_mode & 0o777
        )
        if manifest_mode not in {0o600, 0o644}:
            raise BundleError("source_manifest")
    except OSError as error:
        raise BundleError("source_manifest") from error
    return manifest


def _target_inventory(target: Path) -> tuple[str, ...]:
    try:
        return _walk_regular_files(target, extra_code="target_extra")
    except BundleError as error:
        if error.code == "source_invalid":
            raise BundleError("target_invalid") from error
        raise


def _assert_target_allowlist(target: Path, expected: set[str]) -> tuple[str, ...]:
    inventory = _target_inventory(target)
    extras = set(inventory) - expected
    if extras:
        raise BundleError("target_extra")
    return inventory


def _file_matches(root: Path, item: BundleFile) -> bool:
    try:
        return _describe_file(root, item.path, code="target_drift") == item
    except BundleError:
        return False


def _preflight_existing_target(
    target: Path,
    source_manifest: BundleManifest,
) -> None:
    inventory = _target_inventory(target)
    if not inventory:
        return
    new_by_path = {item.path: item for item in source_manifest.files}
    expected = set(new_by_path) | {MANIFEST_NAME}
    _assert_target_allowlist(target, expected)
    if MANIFEST_NAME not in inventory:
        for relative in inventory:
            if relative not in new_by_path:
                raise BundleError("target_extra")
            if not _file_matches(target, new_by_path[relative]):
                raise BundleError("target_drift")
        return
    installed_bytes = _read_regular(target / MANIFEST_NAME, code="target_drift")
    installed = _parse_manifest(installed_bytes, code="target_drift")
    old_by_path = {item.path: item for item in installed.files}
    for relative in inventory:
        if relative == MANIFEST_NAME:
            continue
        new = new_by_path[relative]
        old = old_by_path.get(relative)
        if not _file_matches(target, new) and (
            old is None or not _file_matches(target, old)
        ):
            raise BundleError("target_drift")
    for relative in set(old_by_path) & set(new_by_path):
        if relative not in inventory:
            raise BundleError("target_drift")


def _prepare_target(target: Path) -> None:
    _assert_no_symlink_components(
        target,
        allow_missing=True,
        missing_code="target_invalid",
    )
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            mode = target.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise BundleError("unsafe_entry")
            if not stat.S_ISDIR(mode):
                raise BundleError("target_invalid")
        else:
            target.mkdir(mode=0o700)
    except BundleError:
        raise
    except OSError as error:
        raise BundleError("target_invalid") from error


def _open_lock(target: Path) -> int:
    lock = target.with_name(f".{target.name}.lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except OSError as error:
        try:
            os.close(descriptor)
        except NameError, OSError:
            pass
        raise BundleError("lock_failed") from error


def install_bundle(source: Path, target: Path) -> BundleManifest:
    source_manifest = check_source(source)
    _prepare_target(target)
    lock_descriptor = _open_lock(target)
    try:
        _preflight_existing_target(target, source_manifest)
        for item in source_manifest.files:
            destination = target / item.path
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            content = _read_regular(source / item.path, code="source_invalid")
            if (
                len(content) != item.size
                or hashlib.sha256(content).hexdigest() != item.sha256
            ):
                raise BundleError("source_drift")
            _replace_bytes(destination, content, failure_code="install_failed")
        manifest_content = _read_regular(source / MANIFEST_NAME, code="source_manifest")
        _replace_bytes(
            target / MANIFEST_NAME,
            manifest_content,
            failure_code="install_failed",
        )
        return check_install(source, target)
    except BundleError:
        raise
    except OSError as error:
        raise BundleError("install_failed") from error
    finally:
        os.close(lock_descriptor)


def check_install(source: Path, target: Path) -> BundleManifest:
    source_manifest = check_source(source)
    _root_kind(target, missing_code="target_invalid")
    expected = {item.path for item in source_manifest.files} | {MANIFEST_NAME}
    inventory = _assert_target_allowlist(target, expected)
    if set(inventory) != expected:
        raise BundleError("target_drift")
    source_bytes = _read_regular(source / MANIFEST_NAME, code="source_manifest")
    target_bytes = _read_regular(target / MANIFEST_NAME, code="target_drift")
    if target_bytes != source_bytes:
        raise BundleError("target_drift")
    for item in source_manifest.files:
        if not _file_matches(target, item):
            raise BundleError("target_drift")
    return source_manifest


def _parser() -> argparse.ArgumentParser:
    parser = BundleArgumentParser(prog="staged-memory-intake-sync")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("freeze", "check-source"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--source", type=Path, required=True)
    for command in ("install", "check"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--source", type=Path, required=True)
        command_parser.add_argument("--target", type=Path, required=True)
    return parser


def _run(arguments: list[str]) -> BundleManifest:
    parsed = _parser().parse_args(arguments)
    source: Path = parsed.source
    if parsed.command == "freeze":
        return freeze_manifest(source)
    if parsed.command == "check-source":
        return check_source(source)
    target: Path = parsed.target
    if parsed.command == "install":
        return install_bundle(source, target)
    return check_install(source, target)


def main(arguments: list[str] | None = None) -> int:
    try:
        manifest = _run(sys.argv[1:] if arguments is None else arguments)
    except BundleError as error:
        print(f"bundle_error:{error.code}", file=sys.stderr)
        return 1
    print(_manifest_bytes(manifest).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
