"""Typed synthetic doubles for the staged Memory intake companion."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from staged_memory_intake.cleanup import TrashReference
from staged_memory_intake.model import CompletedCommand, IntakeError

if TYPE_CHECKING:
    from staged_memory_intake.cleanup import TrashSource


@dataclass(frozen=True)
class _FakeTrashReference:
    """Test-only stable referent returned by the fake reference boundary."""

    path: Path


def memory_success_envelope(
    data: object,
    *,
    page: Mapping[str, object] | None = None,
    issues: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Build one complete synthetic Memory success envelope."""
    envelope: dict[str, object] = {
        "schema": "memory.mcp.v1",
        "instruction_trust": "inert",
        "data": data,
    }
    if page is not None:
        envelope["page"] = dict(page)
    if issues is not None:
        envelope["issues"] = [dict(issue) for issue in issues]
    return envelope


@dataclass
class FakeMemoryPathsRunner:
    """Return one complete synthetic response for the public paths command."""

    home: Path
    inbox: Path
    returncode: int = 0
    stderr: bytes = b""
    extra: dict[str, object] = field(default_factory=dict)
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        self.calls.append((tuple(argv), timeout_seconds))
        payload: dict[str, object] = {
            "database": str(self.home / "synthetic-database"),
            "home": str(self.home),
            "identity": str(self.home / "synthetic-identity"),
            "inbox": str(self.inbox),
            "inbox_claims": str(self.home / "synthetic-claims"),
        }
        payload.update(self.extra)
        return CompletedCommand(
            returncode=self.returncode,
            stdout=json.dumps(payload).encode(),
            stderr=self.stderr,
        )


@dataclass
class NeverRunner:
    """Fail if an unconfigured operation tries to invoke Memory."""

    calls: int = 0

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        del argv, timeout_seconds
        self.calls += 1
        raise AssertionError("unexpected synthetic Memory invocation")


@dataclass
class FakeTrash:
    """Move synthetic files into a disposable recoverable sink."""

    destination: Path
    fail_before_calls: set[int] = field(default_factory=set)
    before_reference: Callable[[TrashSource], None] | None = None
    after_reference: Callable[[TrashSource], Path | None] | None = None
    observer: Callable[[TrashSource], None] | None = None
    attempts: list[Path] = field(default_factory=list)
    moves: list[Path] = field(default_factory=list)
    descriptors: list[int] = field(default_factory=list)
    reference_descriptors: list[int] = field(default_factory=list)

    def create_reference(self, source: TrashSource) -> TrashReference:
        """Bind one synthetic stable referent without moving it."""
        self.reference_descriptors.append(source.descriptor)
        if self.before_reference is not None:
            self.before_reference(source)
        referent = source.path
        if self.after_reference is not None:
            replacement = self.after_reference(source)
            if replacement is not None:
                referent = replacement
        return TrashReference(_FakeTrashReference(referent))

    def trash_reference(
        self,
        source: TrashSource,
        reference: TrashReference,
    ) -> None:
        """Move only the referent bound by ``create_reference``."""
        if not isinstance(reference.token, _FakeTrashReference):
            raise IntakeError("trash_failed", "trash", retryable=True)
        call = len(self.attempts)
        path = source.path
        self.attempts.append(path)
        self.descriptors.append(source.descriptor)
        if call in self.fail_before_calls:
            raise IntakeError("trash_failed", "trash", retryable=True)
        if self.observer is not None:
            self.observer(source)
        descriptor_metadata = os.fstat(source.descriptor)
        path_metadata = reference.token.path.stat(follow_symlinks=False)
        descriptor_identity = (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
            descriptor_metadata.st_mode,
        )
        if (
            descriptor_identity != (source.device, source.inode, source.mode)
            or descriptor_identity
            != (path_metadata.st_dev, path_metadata.st_ino, path_metadata.st_mode)
            or not stat.S_ISREG(descriptor_metadata.st_mode)
        ):
            raise IntakeError("trash_failed", "trash", retryable=True)
        reference.token.path.rename(
            self.destination / f"synthetic-trash-item-{call:02d}"
        )
        self.moves.append(path)

    def move(self, source: TrashSource) -> None:
        reference = self.create_reference(source)
        self.trash_reference(source, reference)
