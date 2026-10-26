"""Check or explicitly install one copied client Skill.

Memory cannot discover a client home, and never tries: every call names one
absolute target, and every result stays content- and path-free so a refusal is
safe to print into a shared transcript. The Store supplies the source itself —
the exact Skill bytes shipped inside this installed package — so a copy is
compared against the contract the running server actually implements rather
than against a checkout that may have moved on.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal

MAX_SKILL_BYTES = 1024 * 1024
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
_PARENT_FLAGS = _READ_FLAGS | os.O_DIRECTORY
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

SkillSyncStatusName = Literal["current", "missing", "stale", "synced"]


class SkillSyncError(Exception):
    """One bounded refusal whose code is safe to print."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class SkillSyncStatus:
    """One content-free comparison of a copied Skill with the packaged Skill."""

    byte_exact: bool
    source_digest: str
    status: SkillSyncStatusName
    target_digest: str | None


def normalize_lf(raw: bytes) -> bytes:
    """Normalize line endings exactly as `store.status.skill_digest`."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def digest(raw: bytes) -> str:
    """Return the canonical copied-Skill contract digest."""
    return hashlib.sha256(normalize_lf(raw)).hexdigest()


def packaged_skill_path() -> Path:
    """Locate the exact Skill file shipped inside this installed package."""
    return Path(str(files("memory").joinpath("skill", "SKILL.md")))


def check_skill(*, source: Path, target: Path) -> SkillSyncStatus:
    """Compare one copied Skill with a source, creating and changing nothing."""
    with _bounded_filesystem():
        source_bytes = _read_regular(_absolute(source), unsafe_code="unsafe_source")
        target_path = _absolute(target)
        parent_descriptor = _open_target_parent(target_path)
        try:
            return _status(
                source_bytes,
                _read_target(parent_descriptor, target_path.name),
            )
        finally:
            os.close(parent_descriptor)


def install_skill(*, source: Path, target: Path) -> SkillSyncStatus:
    """Replace exactly one named copied Skill with the source bytes."""
    with _bounded_filesystem():
        source_bytes = _read_regular(_absolute(source), unsafe_code="unsafe_source")
        target_path = _absolute(target)
        parent_descriptor = _open_target_parent(target_path)
        try:
            current = _read_target(parent_descriptor, target_path.name)
            if current == source_bytes:
                return _status(source_bytes, current)
            verified = _install(parent_descriptor, target_path.name, source_bytes)
            installed = _status(source_bytes, verified)
            return SkillSyncStatus(
                byte_exact=installed.byte_exact,
                source_digest=installed.source_digest,
                status="synced",
                target_digest=installed.target_digest,
            )
        finally:
            os.close(parent_descriptor)


@contextmanager
def _bounded_filesystem() -> Iterator[None]:
    """Translate any unclassified filesystem failure into one bounded code.

    Every deliberate refusal below raises `SkillSyncError` with its own code
    first; this catches only what is left -- a failed replace, a short write, a
    failed fsync -- so an operating-system message never reaches the caller.
    """
    try:
        yield
    except OSError:
        raise SkillSyncError("filesystem_error") from None


def _absolute(path: Path) -> Path:
    if not path.is_absolute():
        raise SkillSyncError("path_not_absolute")
    return path


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, MAX_SKILL_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_SKILL_BYTES:
            raise SkillSyncError("skill_too_large")
    return b"".join(chunks)


def _read_regular(path: Path, *, unsafe_code: str) -> bytes:
    try:
        before = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise SkillSyncError("source_missing") from None
    except OSError:
        raise SkillSyncError(unsafe_code) from None
    if not stat.S_ISREG(before.st_mode):
        raise SkillSyncError(unsafe_code)
    if before.st_size > MAX_SKILL_BYTES:
        raise SkillSyncError("skill_too_large")

    try:
        descriptor = os.open(path, _READ_FLAGS)
    except OSError:
        raise SkillSyncError(unsafe_code) from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SkillSyncError(unsafe_code)
        if opened.st_size > MAX_SKILL_BYTES:
            raise SkillSyncError("skill_too_large")
        return _read_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _open_target_parent(target: Path) -> int:
    if not target.name:
        raise SkillSyncError("unsafe_target")
    try:
        before = os.stat(target.parent, follow_symlinks=False)
    except OSError:
        raise SkillSyncError("unsafe_parent") from None
    if not stat.S_ISDIR(before.st_mode):
        raise SkillSyncError("unsafe_parent")
    try:
        descriptor = os.open(target.parent, _PARENT_FLAGS)
    except OSError:
        raise SkillSyncError("unsafe_parent") from None
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        raise SkillSyncError("unsafe_parent")
    return descriptor


def _read_target(parent_descriptor: int, name: str) -> bytes | None:
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise SkillSyncError("unsafe_target") from None
    if not stat.S_ISREG(before.st_mode):
        raise SkillSyncError("unsafe_target")
    if before.st_size > MAX_SKILL_BYTES:
        raise SkillSyncError("skill_too_large")
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_descriptor)
    except OSError:
        raise SkillSyncError("unsafe_target") from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SkillSyncError("unsafe_target")
        if opened.st_size > MAX_SKILL_BYTES:
            raise SkillSyncError("skill_too_large")
        return _read_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _write_descriptor(descriptor: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short Skill write")
        remaining = remaining[written:]


def _create_temporary(parent_descriptor: int, raw: bytes) -> str:
    for _attempt in range(32):
        name = f".memory-skill-sync-{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        try:
            _write_descriptor(descriptor, raw)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        except BaseException:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        return name
    raise SkillSyncError("temporary_unavailable")


def _install(parent_descriptor: int, name: str, source: bytes) -> bytes:
    temporary = _create_temporary(parent_descriptor, source)
    replaced = False
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        os.fsync(parent_descriptor)
    finally:
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=parent_descriptor)
            except OSError:
                pass
    verified = _read_target(parent_descriptor, name)
    if verified is None or verified != source:
        raise SkillSyncError("verification_failed")
    return verified


def _status(source: bytes, target: bytes | None) -> SkillSyncStatus:
    source_digest = digest(source)
    if target is None:
        return SkillSyncStatus(
            byte_exact=False,
            source_digest=source_digest,
            status="missing",
            target_digest=None,
        )
    target_digest = digest(target)
    return SkillSyncStatus(
        byte_exact=source == target,
        source_digest=source_digest,
        status="current" if source_digest == target_digest else "stale",
        target_digest=target_digest,
    )
