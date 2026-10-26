"""Crash-safe notes-root relocation tests for staged Memory intake."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from staged_memory_intake.config import configure, load_config, load_config_record
from staged_memory_intake.model import (
    CompletedCommand,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    MemoryPaths,
    NoPublicationFault,
)
from staged_memory_intake.securefs import (
    atomic_private_json,
    descriptor_volume,
    directory_identity,
)
from staged_memory_intake_fakes import FakeTrash, NeverRunner


@dataclass
class RelocatingMemoryRunner:
    """Synthetic public Memory CLI that moves one real disposable directory."""

    home: Path
    inbox: Path
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        command = tuple(argv)
        self.calls.append((command, timeout_seconds))
        if command[:2] == ("memory", "paths"):
            payload = {
                "database": str(self.home / "synthetic-database"),
                "home": str(self.home),
                "identity": str(self.home / "synthetic-identity"),
                "inbox": str(self.inbox),
                "inbox_claims": str(self.home / "synthetic-claims"),
            }
            return CompletedCommand(0, json.dumps(payload).encode(), b"")
        if command[:2] == ("memory", "relocate-inbox"):
            destination = Path(command[command.index("--to") + 1])
            if self.inbox == destination:
                status_value = "current"
            else:
                self.inbox.rename(destination)
                self.inbox = destination
                status_value = "relocated"
            return CompletedCommand(
                0,
                json.dumps(
                    {"status": status_value},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n",
                b"",
            )
        raise AssertionError(command)


@dataclass
class ChangingPathsMemoryRunner:
    """Return a different synthetic Memory Inbox after one authoritative read."""

    delegate: RelocatingMemoryRunner
    replacement_inbox: Path
    paths_responses: int = 0
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        command = tuple(argv)
        self.calls.append((command, timeout_seconds))
        if command[:2] == ("memory", "paths"):
            self.paths_responses += 1
            inbox = (
                self.delegate.inbox
                if self.paths_responses == 1
                else self.replacement_inbox
            )
            payload = {
                "database": str(self.delegate.home / "synthetic-database"),
                "home": str(self.delegate.home),
                "identity": str(self.delegate.home / "synthetic-identity"),
                "inbox": str(inbox),
                "inbox_claims": str(self.delegate.home / "synthetic-claims"),
            }
            return CompletedCommand(0, json.dumps(payload).encode(), b"")
        raise AssertionError(command)


@dataclass
class InterruptingMemoryRunner:
    """Model Memory refusing ordinary commands until exact relocation retry."""

    delegate: RelocatingMemoryRunner
    interrupted: bool = False
    pending_destination: Path | None = None
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        command = tuple(argv)
        self.calls.append((command, timeout_seconds))
        if command[:2] == ("memory", "paths") and self.pending_destination is not None:
            return CompletedCommand(4, b"", b'{"code":"relocation_pending"}\n')
        if command[:2] == ("memory", "relocate-inbox"):
            destination = Path(command[command.index("--to") + 1])
            if not self.interrupted:
                completed = self.delegate.run(argv, timeout_seconds=timeout_seconds)
                assert completed.returncode == 0
                self.interrupted = True
                self.pending_destination = destination
                return CompletedCommand(4, b"", b'{"code":"synthetic_crash"}\n')
            if destination == self.pending_destination:
                self.pending_destination = None
                return CompletedCommand(0, b'{"status":"recovered"}\n', b"")
        return self.delegate.run(argv, timeout_seconds=timeout_seconds)


def _configured_root(
    tmp_path: Path,
) -> tuple[Path, Path, Path, RelocatingMemoryRunner]:
    notes = tmp_path / "synthetic-old-root"
    home = tmp_path / "synthetic-memory-home"
    state_root = tmp_path / "synthetic-helper-state"
    for path in (
        notes,
        notes / "01_Pending",
        notes / "02_Staged",
        notes / "03_Prepared",
        notes / "04_Inbox",
        home,
    ):
        path.mkdir(mode=0o700)
    runner = RelocatingMemoryRunner(home=home, inbox=notes / "04_Inbox")
    configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
    )
    return state_root, notes, home, runner


def _replace_configured_root(
    tmp_path: Path,
    source: Path,
    runner: RelocatingMemoryRunner,
) -> tuple[Path, dict[str, DirectoryIdentity]]:
    """Replace one configured synthetic root without examining child contents."""
    displaced = tmp_path / "synthetic-displaced-root"
    source.rename(displaced)
    for path in (
        source,
        source / "01_Pending",
        source / "02_Staged",
        source / "03_Prepared",
        source / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    runner.inbox = source / "04_Inbox"
    return (
        displaced,
        {
            name: directory_identity(source if name == "." else source / name)
            for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
        },
    )


def test_relocate_notes_root_preserves_all_directory_identities(
    tmp_path: Path,
) -> None:
    """Catch a coordinated rename that copies or recreates any owner directory."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    before = {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "relocated"
    assert not source.exists()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert {
        name: directory_identity(destination if name == "." else destination / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == before
    assert runner.inbox == destination / "04_Inbox"
    configured = load_config(state_root)
    assert configured is not None
    assert configured.notes_root == destination
    assert configured.notes_identity == before["."]
    assert configured.memory_inbox == destination / "04_Inbox"
    assert configured.inbox_identity == before["04_Inbox"]
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not (state_root / ".notes-root-relocation-inbox").exists()
    assert set(os.listdir(destination)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }


def test_relocation_carries_the_enabled_pending_drop_flag(
    tmp_path: Path,
) -> None:
    """Catch the preflight snapshot losing pending_drop across a relocation."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    payload = json.loads((state_root / "config.json").read_text(encoding="utf-8"))
    payload["pending_drop"] = True
    atomic_private_json(state_root / "config.json", payload)
    destination = tmp_path / "synthetic-captures"
    before = {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "relocated"
    assert not source.exists()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert {
        name: directory_identity(destination if name == "." else destination / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == before
    assert runner.inbox == destination / "04_Inbox"
    configured = load_config(state_root)
    assert configured is not None
    assert configured.notes_root == destination
    assert configured.notes_identity == before["."]
    assert configured.memory_inbox == destination / "04_Inbox"
    assert configured.inbox_identity == before["04_Inbox"]
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not (state_root / ".notes-root-relocation-inbox").exists()
    assert set(os.listdir(destination)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }
    assert load_config_record(state_root).pending_drop is True


def test_explicit_adoption_rebinds_current_authority_then_relocates(
    tmp_path: Path,
) -> None:
    """Require an explicit owner-confirmation flag for stale inode bindings."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    displaced = tmp_path / "synthetic-displaced-root"
    source.rename(displaced)
    for path in (
        source,
        source / "01_Pending",
        source / "02_Staged",
        source / "03_Prepared",
        source / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    runner.inbox = source / "04_Inbox"
    destination = tmp_path / "synthetic-captures"
    before = {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }

    with pytest.raises(IntakeError) as refused:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )
    assert refused.value.code == "relocation_authority_changed"
    assert source.is_dir()
    assert not destination.exists()

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
        adopt_current_authority=True,
    )

    assert result.status == "relocated"
    assert {
        name: directory_identity(destination if name == "." else destination / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == before
    configured = load_config(state_root)
    assert configured is not None
    assert configured.notes_identity == before["."]
    assert configured.inbox_identity == before["04_Inbox"]


def _rewrite_config_device_bound(state_root: Path, *, device_shift: int) -> None:
    """Rewrite the persisted config exactly as a pre-upgrade helper left it."""
    config = load_config_record(state_root)
    atomic_private_json(
        state_root / "config.json",
        {
            "schema": "staged-memory-intake.config.v1",
            "notes_root": str(config.notes_root),
            "notes_identity": {
                "device": config.notes_root.lstat().st_dev + device_shift,
                "inode": config.notes_identity.inode,
            },
            "memory_home": (
                None if config.memory_home is None else str(config.memory_home)
            ),
            "memory_inbox": str(config.memory_inbox),
            "inbox_identity": {
                "device": config.memory_inbox.lstat().st_dev + device_shift,
                "inode": config.inbox_identity.inode,
            },
        },
    )


def test_relocate_adopts_a_device_bound_config_before_judging_authority(
    tmp_path: Path,
) -> None:
    """Catch relocate refusing a v1 config a reboot renumbered.

    `relocate` reads the exact config record, so a device-bound v1 config's
    first post-upgrade command being `relocate` compared the legacy device
    sentinel against live volume UUIDs and falsely refused as
    relocation_authority_changed. The same in-place adoption the ordinary
    load path performs must run first.
    """
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    _rewrite_config_device_bound(state_root, device_shift=1)

    result = relocate_notes_root(state_root, source, runner, NoRelocationFault())

    assert result.status == "current"
    configured = load_config_record(state_root)
    assert configured.notes_identity == directory_identity(source)
    assert configured.inbox_identity == directory_identity(source / "04_Inbox")
    assert load_config(state_root) == configured


def test_abandon_unsupported_relocation_intent_unwedges_pending(
    tmp_path: Path,
) -> None:
    """Catch a pre-v2 relocation intent refusing every command forever.

    A device-bound pending intent is refused, never reinterpreted -- but
    every command's pending gate raised on it and nothing could remove it.
    The hatch quarantines exactly the unsupported intent, keeps its bytes,
    and never touches a current-schema intent.
    """
    from staged_memory_intake.relocation import (
        abandon_unsupported_intent,
        relocation_pending,
    )

    state_root = tmp_path / "synthetic-wedged-state"
    state_root.mkdir(mode=0o700)
    intent_path = state_root / ".notes-root-relocation.intent.json"
    atomic_private_json(
        intent_path,
        {"schema": "staged-memory-intake.root-relocation.v1", "phase": "prepared"},
    )
    with pytest.raises(IntakeError) as wedged:
        relocation_pending(state_root)
    assert wedged.value.code == "relocation_intent_invalid"

    assert abandon_unsupported_intent(state_root) is True

    assert relocation_pending(state_root) is False
    quarantined = sorted(
        state_root.glob("abandoned-.notes-root-relocation.intent.json.*")
    )
    assert len(quarantined) == 1
    assert json.loads(quarantined[0].read_text(encoding="utf-8"))["schema"] == (
        "staged-memory-intake.root-relocation.v1"
    )
    assert abandon_unsupported_intent(state_root) is False

    atomic_private_json(
        intent_path,
        {"schema": "staged-memory-intake.root-relocation.v2", "phase": "prepared"},
    )
    assert abandon_unsupported_intent(state_root) is False
    assert intent_path.exists()


def test_relocation_surfaces_volume_unidentified_unrecoded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch relocation re-coding the volume-UUID constraint as drift."""
    import staged_memory_intake.relocation as relocation
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root
    from staged_memory_intake.securefs import descriptor_volume

    state_root, source, _, runner = _configured_root(tmp_path)
    calls = {"count": 0}

    def unidentified_on_reproof(descriptor: int) -> str:
        calls["count"] += 1
        if calls["count"] >= 2:
            raise IntakeError("volume_unidentified", "configuration")
        return descriptor_volume(descriptor)

    monkeypatch.setattr(relocation, "descriptor_volume", unidentified_on_reproof)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(state_root, source, runner, NoRelocationFault())

    assert calls["count"] >= 2
    assert caught.value.code == "volume_unidentified"


def test_explicit_adoption_rebinds_a_device_bound_config_with_changed_inode(
    tmp_path: Path,
) -> None:
    """Catch auto-adoption cutting off the explicit rebind for v1 configs.

    A device-bound config whose root was replaced fails the inode match, so
    automatic adoption correctly refuses it -- but that refusal must not run
    ahead of `--adopt-current-authority`, which is exactly the owner's escape
    for that state and rebound such configs before the automatic path
    existed.
    """
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    _rewrite_config_device_bound(state_root, device_shift=1)
    _displaced, rebound = _replace_configured_root(tmp_path, source, runner)

    with pytest.raises(IntakeError) as refused:
        relocate_notes_root(state_root, source, runner, NoRelocationFault())
    assert refused.value.code == "notes_root_changed"

    result = relocate_notes_root(
        state_root,
        source,
        runner,
        NoRelocationFault(),
        adopt_current_authority=True,
    )

    assert result.status == "current"
    configured = load_config_record(state_root)
    assert configured.notes_identity == rebound["."]
    assert configured.inbox_identity == rebound["04_Inbox"]


def test_explicit_adoption_rebinds_current_authority_in_place(
    tmp_path: Path,
) -> None:
    """Catch same-path adoption entering the move-only relocation protocol."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    old_config = load_config_record(state_root)
    displaced, rebound = _replace_configured_root(tmp_path, source, runner)
    displaced_identity = directory_identity(displaced)
    displaced_entries = tuple(sorted(os.listdir(displaced)))

    with pytest.raises(IntakeError) as refused:
        relocate_notes_root(state_root, source, runner, NoRelocationFault())
    assert refused.value.code == "relocation_authority_changed"
    assert load_config_record(state_root) == old_config

    result = relocate_notes_root(
        state_root,
        source,
        runner,
        NoRelocationFault(),
        adopt_current_authority=True,
    )

    assert result.status == "current"
    configured = load_config_record(state_root)
    assert configured.notes_root == old_config.notes_root
    assert configured.memory_inbox == old_config.memory_inbox
    assert configured.notes_identity == rebound["."]
    assert configured.inbox_identity == rebound["04_Inbox"]
    assert {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == rebound
    assert all(call[:2] == ("memory", "paths") for call, _ in runner.calls)
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not (state_root / ".notes-root-relocation-inbox").exists()
    assert directory_identity(displaced) == displaced_identity
    assert tuple(sorted(os.listdir(displaced))) == displaced_entries


def test_same_path_adoption_does_not_require_parent_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch in-place adoption inheriting the different-target parent gate."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    real_open = cast(
        "Callable[..., int]",
        relocation.__dict__["_open_bound_directory"],
    )

    def parent_not_owner(path: Path, *, require_owner: bool = True) -> int:
        if path == source.parent and require_owner:
            raise IntakeError("relocation_destination_invalid", "configuration")
        return real_open(path, require_owner=require_owner)

    monkeypatch.setattr(relocation, "_open_bound_directory", parent_not_owner)

    result = relocation.relocate_notes_root(
        state_root,
        source,
        runner,
        relocation.NoRelocationFault(),
        adopt_current_authority=True,
    )

    assert result.status == "current"
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_same_path_adoption_exact_replay_does_not_replace_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a replay that rewrites already rebound same-path authority."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    first = relocation.relocate_notes_root(
        state_root,
        source,
        runner,
        relocation.NoRelocationFault(),
        adopt_current_authority=True,
    )

    def forbid_replace(*args: object, **kwargs: object) -> IntakeConfig:
        del args, kwargs
        raise AssertionError("exact replay must not rewrite configuration")

    monkeypatch.setattr(relocation, "replace_config_paths", forbid_replace)
    replay = relocation.relocate_notes_root(
        state_root,
        source,
        runner,
        relocation.NoRelocationFault(),
        adopt_current_authority=True,
    )

    assert first.status == "current"
    assert replay.status == "current"


def test_same_path_adoption_refuses_different_memory_inbox_without_writing(
    tmp_path: Path,
) -> None:
    """Catch path confirmation accepting Memory authority at another inbox."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    different_inbox = tmp_path / "synthetic-different-inbox"
    different_inbox.mkdir(mode=0o700)
    runner.inbox = different_inbox
    config_path = state_root / "config.json"
    before = config_path.read_bytes()

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            source,
            runner,
            NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert config_path.read_bytes() == before


def test_same_path_adoption_refuses_substituted_memory_inbox_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a Memory paths response whose identity no longer matches the inbox."""
    import staged_memory_intake.relocation as relocation

    state_root, source, home, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    substitute = tmp_path / "synthetic-substitute-inbox"
    substitute.mkdir(mode=0o700)

    def substituted_paths(
        memory_home: Path | None,
        runner_arg: object,
    ) -> MemoryPaths:
        del memory_home, runner_arg
        return MemoryPaths(
            home=home,
            inbox=source / "04_Inbox",
            inbox_identity=directory_identity(substitute),
        )

    monkeypatch.setattr(relocation, "resolve_memory_paths", substituted_paths)
    config_path = state_root / "config.json"
    before = config_path.read_bytes()

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            source,
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert config_path.read_bytes() == before


def test_same_path_adoption_refuses_unexpected_root_entry_without_writing(
    tmp_path: Path,
) -> None:
    """Catch authority adoption accepting an unbound root entry."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    (source / "synthetic-unexpected").mkdir(mode=0o700)
    config_path = state_root / "config.json"
    before = config_path.read_bytes()

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            source,
            runner,
            NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_layout_invalid"
    assert config_path.read_bytes() == before


def test_same_path_adoption_rechecks_child_identities_after_config_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a child substitution after config CAS but before returning current."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _, rebound = _replace_configured_root(tmp_path, source, runner)
    real_replace = cast(
        "Callable[[Path, IntakeConfig, Path, DirectoryIdentity, Path, DirectoryIdentity], IntakeConfig]",
        relocation.__dict__["replace_config_paths"],
    )

    def replace_then_substitute(
        state_root_arg: Path,
        old: IntakeConfig,
        notes_root: Path,
        notes_identity: DirectoryIdentity,
        memory_inbox: Path,
        inbox_identity: DirectoryIdentity,
    ) -> IntakeConfig:
        updated = real_replace(
            state_root_arg,
            old,
            notes_root,
            notes_identity,
            memory_inbox,
            inbox_identity,
        )
        (source / "02_Staged").rename(tmp_path / "synthetic-displaced-staged")
        (source / "02_Staged").mkdir(mode=0o700)
        return updated

    monkeypatch.setattr(relocation, "replace_config_paths", replace_then_substitute)

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            source,
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code in {
        "relocation_authority_changed",
        "relocation_layout_changed",
    }
    assert load_config_record(state_root).notes_identity == rebound["."]
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_same_path_adoption_rechecks_persisted_config_after_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch config replacement after authority CAS but before current returns."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _, rebound = _replace_configured_root(tmp_path, source, runner)
    real_replace = cast(
        "Callable[[Path, IntakeConfig, Path, DirectoryIdentity, Path, DirectoryIdentity], IntakeConfig]",
        relocation.__dict__["replace_config_paths"],
    )

    def replace_then_substitute_config(
        state_root_arg: Path,
        old: IntakeConfig,
        notes_root: Path,
        notes_identity: DirectoryIdentity,
        memory_inbox: Path,
        inbox_identity: DirectoryIdentity,
    ) -> IntakeConfig:
        updated = real_replace(
            state_root_arg,
            old,
            notes_root,
            notes_identity,
            memory_inbox,
            inbox_identity,
        )
        atomic_private_json(
            state_root_arg / "config.json",
            {
                "schema": "staged-memory-intake.config.v2",
                "notes_root": str(notes_root),
                "notes_identity": {
                    "volume": notes_identity.volume,
                    "inode": notes_identity.inode,
                },
                "memory_home": None,
                "memory_inbox": str(memory_inbox),
                "inbox_identity": {
                    "volume": inbox_identity.volume,
                    "inode": inbox_identity.inode,
                },
            },
        )
        return updated

    monkeypatch.setattr(
        relocation,
        "replace_config_paths",
        replace_then_substitute_config,
    )

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            source,
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert load_config_record(state_root).notes_identity == rebound["."]
    assert load_config_record(state_root).memory_home is None
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_same_path_adoption_rechecks_memory_paths_after_config_cas(
    tmp_path: Path,
) -> None:
    """Catch Memory changing its named Inbox after same-path authority CAS."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, delegate = _configured_root(tmp_path)
    _, rebound = _replace_configured_root(tmp_path, source, delegate)
    replacement_inbox = tmp_path / "synthetic-replacement-inbox"
    replacement_inbox.mkdir(mode=0o700)
    runner = ChangingPathsMemoryRunner(delegate, replacement_inbox)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            source,
            runner,
            NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert runner.paths_responses == 2
    assert load_config_record(state_root).inbox_identity == rebound["04_Inbox"]
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_same_path_adoption_reuses_bound_child_after_post_cas_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch caller validation resampling a child after adoption validated it."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    real_adopt = cast(
        "Callable[[Path, IntakeConfig, Path, RelocatingMemoryRunner], object]",
        relocation.__dict__["_adopt_current_authority"],
    )

    def adopt_then_substitute_child(
        state_root_arg: Path,
        config: IntakeConfig,
        destination: Path,
        runner_arg: RelocatingMemoryRunner,
    ) -> object:
        adopted = real_adopt(state_root_arg, config, destination, runner_arg)
        (source / "02_Staged").rename(tmp_path / "synthetic-post-validation-staged")
        (source / "02_Staged").mkdir(mode=0o700)
        return adopted

    monkeypatch.setattr(
        relocation,
        "_adopt_current_authority",
        adopt_then_substitute_child,
    )

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            source,
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code in {
        "relocation_authority_changed",
        "relocation_layout_changed",
    }
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_same_path_adoption_reloads_config_after_post_cas_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch caller success ignoring config replacement after adoption validation."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    _replace_configured_root(tmp_path, source, runner)
    real_adopt = cast(
        "Callable[[Path, IntakeConfig, Path, RelocatingMemoryRunner], object]",
        relocation.__dict__["_adopt_current_authority"],
    )

    def adopt_then_substitute_config(
        state_root_arg: Path,
        config: IntakeConfig,
        destination: Path,
        runner_arg: RelocatingMemoryRunner,
    ) -> object:
        adopted = real_adopt(state_root_arg, config, destination, runner_arg)
        rebound = load_config_record(state_root_arg)
        atomic_private_json(
            state_root_arg / "config.json",
            {
                "schema": "staged-memory-intake.config.v2",
                "notes_root": str(rebound.notes_root),
                "notes_identity": {
                    "volume": rebound.notes_identity.volume,
                    "inode": rebound.notes_identity.inode,
                },
                "memory_home": None,
                "memory_inbox": str(rebound.memory_inbox),
                "inbox_identity": {
                    "volume": rebound.inbox_identity.volume,
                    "inode": rebound.inbox_identity.inode,
                },
            },
        )
        return adopted

    monkeypatch.setattr(
        relocation,
        "_adopt_current_authority",
        adopt_then_substitute_config,
    )

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            source,
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert load_config_record(state_root).memory_home is None
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


def test_explicit_adoption_refuses_a_different_memory_inbox(
    tmp_path: Path,
) -> None:
    """Do not let path confirmation override Memory's current authority."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    source.rename(tmp_path / "synthetic-displaced-root")
    for path in (
        source,
        source / "01_Pending",
        source / "02_Staged",
        source / "03_Prepared",
        source / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    different_inbox = tmp_path / "synthetic-different-inbox"
    different_inbox.mkdir(mode=0o700)
    runner.inbox = different_inbox
    destination = tmp_path / "synthetic-captures"

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert source.is_dir()
    assert not destination.exists()
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_adoption_substitution_never_persists_the_substitute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an adoption CAS that re-authorizes by statting at commit time."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    source.rename(tmp_path / "synthetic-displaced-root")
    for path in (
        source,
        source / "01_Pending",
        source / "02_Staged",
        source / "03_Prepared",
        source / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    runner.inbox = source / "04_Inbox"
    old_config = load_config_record(state_root)
    real_replace = cast(
        "Callable[[Path, IntakeConfig, Path, DirectoryIdentity, Path, DirectoryIdentity], IntakeConfig]",
        relocation.__dict__["replace_config_paths"],
    )

    def substitute_then_replace(
        state_root_arg: Path,
        old: IntakeConfig,
        notes_root: Path,
        notes_identity: DirectoryIdentity,
        memory_inbox: Path,
        inbox_identity: DirectoryIdentity,
    ) -> IntakeConfig:
        source.rename(tmp_path / "synthetic-confirmed-root")
        for path in (
            source,
            source / "01_Pending",
            source / "02_Staged",
            source / "03_Prepared",
            source / "04_Inbox",
        ):
            path.mkdir(mode=0o700)
        runner.inbox = source / "04_Inbox"
        return real_replace(
            state_root_arg,
            old,
            notes_root,
            notes_identity,
            memory_inbox,
            inbox_identity,
        )

    monkeypatch.setattr(relocation, "replace_config_paths", substitute_then_replace)

    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            tmp_path / "synthetic-captures",
            runner,
            relocation.NoRelocationFault(),
            adopt_current_authority=True,
        )

    assert caught.value.code == "relocation_authority_changed"
    assert load_config_record(state_root) == old_config


def test_relocation_carries_optional_obsidian_metadata_opaquely(
    tmp_path: Path,
) -> None:
    """Preserve a vault metadata directory without inspecting its contents."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    metadata = source / ".obsidian"
    metadata.mkdir(mode=0o755)
    metadata.chmod(0o755)
    (metadata / "synthetic-config.json").write_text("{}", encoding="utf-8")
    before = directory_identity(metadata)
    destination = tmp_path / "synthetic-captures"

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "relocated"
    moved = destination / ".obsidian"
    assert directory_identity(moved) == before
    assert stat.S_IMODE(moved.stat().st_mode) == 0o755
    assert (moved / "synthetic-config.json").read_text(encoding="utf-8") == "{}"


def test_optional_obsidian_metadata_recovers_from_durable_intent(
    tmp_path: Path,
) -> None:
    """Bind optional metadata in the journal so exact retry stays fail-closed."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    metadata = source / ".obsidian"
    metadata.mkdir(mode=0o755)
    metadata.chmod(0o755)
    before = directory_identity(metadata)
    destination = tmp_path / "synthetic-captures"

    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("intent_published"),
        )
    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "recovered"
    assert directory_identity(destination / ".obsidian") == before


def test_optional_metadata_drift_refuses_before_parking_inbox(
    tmp_path: Path,
) -> None:
    """Catch recovery mutating a phase before validating its bound root layout."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    metadata = source / ".obsidian"
    metadata.mkdir(mode=0o755)
    metadata.chmod(0o755)
    destination = tmp_path / "synthetic-captures"
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("intent_published"),
        )
    metadata.chmod(0o700)
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_authority_changed"
    assert runner.inbox == source / "04_Inbox"
    assert (source / "04_Inbox").is_dir()
    assert not (state_root / ".notes-root-relocation-inbox").exists()
    assert tuple(runner.calls) == calls_before


def test_exact_retry_recovers_interrupted_nested_memory_relocation(
    tmp_path: Path,
) -> None:
    """Catch `memory paths` deadlocking recovery of Memory's own intent."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, _, _, delegate = _configured_root(tmp_path)
    runner = InterruptingMemoryRunner(delegate)
    destination = tmp_path / "synthetic-captures"

    with pytest.raises(IntakeError) as first:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )
    assert first.value.code == "memory_relocation_failed"
    assert runner.pending_destination == (state_root / ".notes-root-relocation-inbox")

    recovered = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert recovered.status == "recovered"
    assert runner.pending_destination is None
    assert delegate.inbox == destination / "04_Inbox"
    relocation_calls = [
        call for call, _ in runner.calls if call[:2] == ("memory", "relocate-inbox")
    ]
    assert relocation_calls[:2] == [relocation_calls[0], relocation_calls[0]]


class SyntheticCrash(BaseException):
    """Simulate process loss without converting it to an operational error."""


@dataclass
class CrashOnce:
    checkpoint_name: str
    crashed: bool = False

    def checkpoint(self, name: str) -> None:
        if name == self.checkpoint_name and not self.crashed:
            self.crashed = True
            raise SyntheticCrash


def test_exact_replay_is_current_and_does_not_move_again(tmp_path: Path) -> None:
    """Catch an exact replay that starts a second transition or changes identity."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    (source / ".obsidian").mkdir(mode=0o755)
    destination = tmp_path / "synthetic-captures"
    first = relocate_notes_root(state_root, destination, runner, NoRelocationFault())
    calls_after_first = tuple(runner.calls)
    before = directory_identity(destination)

    replay = relocate_notes_root(state_root, destination, runner, NoRelocationFault())

    assert first.status == "relocated"
    assert replay.status == "current"
    assert directory_identity(destination) == before
    assert tuple(runner.calls[:-1]) == calls_after_first
    assert runner.calls[-1][0][:2] == ("memory", "paths")
    assert not source.exists()


@pytest.mark.parametrize(
    "checkpoint",
    [
        "intent_published",
        "inbox_staged",
        "root_moved",
        "inbox_final",
        "config_replaced",
    ],
)
def test_each_durable_interruption_recovers_on_exact_retry(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    """Catch a persisted phase that cannot converge after process interruption."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    before = {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }

    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce(checkpoint),
        )

    recovered = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert recovered.status == "recovered"
    assert not source.exists()
    assert {
        name: directory_identity(destination if name == "." else destination / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == before
    assert load_config(state_root) is not None
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not (state_root / ".notes-root-relocation-inbox").exists()


@pytest.mark.parametrize(
    "checkpoint",
    [
        "intent_published",
        "inbox_staged",
        "root_moved",
        "inbox_final",
        "config_replaced",
    ],
)
def test_relocation_recovery_carries_the_enabled_pending_drop_flag(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    """Catch a resumed relocation losing pending_drop across a process crash."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    payload = json.loads((state_root / "config.json").read_text(encoding="utf-8"))
    payload["pending_drop"] = True
    atomic_private_json(state_root / "config.json", payload)
    destination = tmp_path / "synthetic-captures"
    before = {
        name: directory_identity(source if name == "." else source / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }

    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce(checkpoint),
        )

    recovered = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert recovered.status == "recovered"
    assert not source.exists()
    assert {
        name: directory_identity(destination if name == "." else destination / name)
        for name in (".", "01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    } == before
    assert load_config(state_root) is not None
    assert not (state_root / ".notes-root-relocation.intent.json").exists()
    assert not (state_root / ".notes-root-relocation-inbox").exists()
    assert load_config_record(state_root).pending_drop is True


def test_relocation_intent_without_pending_drop_key_parses_as_false(
    tmp_path: Path,
) -> None:
    """Catch a pre-upgrade intent (no pending_drop key) failing to resume."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, _, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("intent_published"),
        )
    intent_path = state_root / ".notes-root-relocation.intent.json"
    payload = json.loads(intent_path.read_bytes())
    assert "pending_drop" not in payload

    recovered = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert recovered.status == "recovered"
    assert load_config_record(state_root).pending_drop is False


def test_relocation_intent_pending_drop_key_must_be_a_boolean(
    tmp_path: Path,
) -> None:
    """Reject a tampered intent whose pending_drop key is not a boolean."""
    from staged_memory_intake.relocation import relocate_notes_root

    state_root, _, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("intent_published"),
        )
    intent_path = state_root / ".notes-root-relocation.intent.json"
    payload = json.loads(intent_path.read_bytes())
    payload["pending_drop"] = "on"
    atomic_private_json(intent_path, payload)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(state_root, destination, runner)

    assert caught.value.code == "relocation_intent_invalid"


@pytest.mark.parametrize(
    "checkpoint",
    [
        "inbox_staged_uncommitted",
        "root_moved_uncommitted",
        "inbox_final_uncommitted",
        "config_replaced_uncommitted",
    ],
)
def test_interruption_between_side_effect_and_phase_commit_recovers(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    """Catch recovery that assumes every completed side effect advanced its phase."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    root_identity = directory_identity(source)
    inbox_identity = directory_identity(source / "04_Inbox")

    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce(checkpoint),
        )

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "recovered"
    assert directory_identity(destination) == root_identity
    assert directory_identity(destination / "04_Inbox") == inbox_identity
    assert load_config(state_root) is not None


def test_destination_through_symlink_is_refused_before_intent(
    tmp_path: Path,
) -> None:
    """Catch a destination traversal that follows an intermediate symlink."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    real_parent = tmp_path / "synthetic-real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "synthetic-linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    destination = linked_parent / "synthetic-captures"
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_destination_invalid"
    assert source.is_dir()
    assert not destination.exists()
    assert tuple(runner.calls) == calls_before
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_destination_inside_source_is_refused_before_inbox_moves(
    tmp_path: Path,
) -> None:
    """Catch a self-containing root rename that strands the parked Inbox."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = source / "01_Pending" / "synthetic-captures"
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_destination_invalid"
    assert (source / "04_Inbox").is_dir()
    assert tuple(runner.calls) == calls_before
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_non_private_destination_parent_is_refused_before_intent(
    tmp_path: Path,
) -> None:
    """Catch publication into a parent other local processes can traverse."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination_parent = tmp_path / "synthetic-shared-parent"
    destination_parent.mkdir(mode=0o755)
    destination_parent.chmod(0o755)
    destination = destination_parent / "synthetic-captures"
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_destination_invalid"
    assert source.is_dir()
    assert tuple(runner.calls) == calls_before
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_same_parent_rename_preserves_existing_parent_boundary(
    tmp_path: Path,
) -> None:
    """Allow a rename within one exact owner-bound parent without widening access."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    tmp_path.chmod(0o750)
    destination = tmp_path / "synthetic-captures"

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "relocated"
    assert not source.exists()
    assert destination.is_dir()


@pytest.mark.parametrize("unsafe_mode", [0o770, 0o777])
def test_same_parent_rename_refuses_writable_shared_boundary(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    """Reject a shared parent where another local actor can substitute names."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    tmp_path.chmod(unsafe_mode)
    destination = tmp_path / "synthetic-captures"

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_destination_invalid"
    assert source.is_dir()
    assert not destination.exists()
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_recovery_refuses_replaced_destination_parent(tmp_path: Path) -> None:
    """Catch recovery that trusts a parent pathname instead of its authority."""
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination_parent = tmp_path / "synthetic-private-parent"
    destination_parent.mkdir(mode=0o700)
    destination = destination_parent / "synthetic-captures"
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("inbox_staged"),
        )
    displaced_parent = tmp_path / "synthetic-displaced-parent"
    destination_parent.rename(displaced_parent)
    destination_parent.mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "relocation_authority_changed"
    assert source.is_dir()
    assert not destination.exists()
    assert (state_root / ".notes-root-relocation.intent.json").is_file()
    assert (state_root / ".notes-root-relocation-inbox").is_dir()


def test_retry_resyncs_both_parents_after_root_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch recovery that clears its intent around an undurable root rename."""
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    destination_parent = tmp_path / "synthetic-private-parent"
    destination_parent.mkdir(mode=0o700)
    destination = destination_parent / "synthetic-captures"
    source_parent_identity = directory_identity(source.parent)
    destination_parent_identity = directory_identity(destination.parent)
    real_fsync = os.fsync
    failed = False

    def fail_after_root_move(descriptor: int) -> None:
        nonlocal failed
        if not failed and not source.exists() and destination.is_dir():
            failed = True
            raise OSError("synthetic parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_after_root_move)
    with pytest.raises(IntakeError) as caught:
        relocation.relocate_notes_root(
            state_root,
            destination,
            runner,
            relocation.NoRelocationFault(),
        )
    assert caught.value.code == "root_relocation_failed"
    assert failed
    assert not source.exists()
    assert destination.is_dir()

    synced: set[DirectoryIdentity] = set()

    def record_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced.add(
                DirectoryIdentity(descriptor_volume(descriptor), metadata.st_ino)
            )
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    result = relocation.relocate_notes_root(
        state_root,
        destination,
        runner,
        relocation.NoRelocationFault(),
    )

    assert result.status == "recovered"
    assert {source_parent_identity, destination_parent_identity} <= synced
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


@dataclass
class DestinationWinner:
    destination: Path

    def checkpoint(self, name: str) -> None:
        if name == "before_root_move":
            self.destination.mkdir(mode=0o700)


def test_destination_race_preserves_the_winner_and_source(
    tmp_path: Path,
) -> None:
    """Catch a root rename that replaces a destination winner."""
    from staged_memory_intake.relocation import relocate_notes_root

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    source_identity = directory_identity(source)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            destination,
            runner,
            DestinationWinner(destination),
        )

    assert caught.value.code == "relocation_layout_changed"
    assert directory_identity(source) == source_identity
    assert destination.is_dir()
    assert directory_identity(destination) != source_identity
    assert (state_root / ".notes-root-relocation-inbox").is_dir()
    assert (state_root / ".notes-root-relocation.intent.json").is_file()


def test_relocation_never_inventories_any_child_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the coordinator enumerating content below the four root entries."""
    import staged_memory_intake.config as config_module
    import staged_memory_intake.relocation as relocation

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    original_inventory = cast(
        "Callable[[Path, DirectoryIdentity], tuple[str, ...]]",
        relocation.__dict__["_root_inventory"],
    )
    inventoried: list[Path] = []

    def guarded_inventory(
        path: Path,
        expected: DirectoryIdentity,
    ) -> tuple[str, ...]:
        assert path.name not in {"01_Pending", "04_Inbox", ".obsidian"}
        inventoried.append(path)
        return original_inventory(path, expected)

    def forbid_child_inventory(root: Path, folder: str) -> None:
        del root, folder
        raise AssertionError("relocation must not inventory child content")

    monkeypatch.setattr(relocation, "_root_inventory", guarded_inventory)
    monkeypatch.setattr(
        config_module,
        "_validate_regular_inventory",
        forbid_child_inventory,
    )

    result = relocation.relocate_notes_root(
        state_root,
        destination,
        runner,
        relocation.NoRelocationFault(),
    )

    assert result.status == "relocated"
    assert set(inventoried) == {source, destination}


def test_cli_relocate_emits_one_content_free_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch a helper CLI that omits the coordinated command or leaks paths."""
    from staged_memory_intake.cli import Dependencies, main

    state_root, source, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    trash_root = tmp_path / "synthetic-trash"
    trash_root.mkdir(mode=0o700)
    dependencies = Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash_root),
        publication_fault=NoPublicationFault(),
    )

    exit_code = main(
        [
            "--state-root",
            str(state_root),
            "relocate",
            "--to",
            str(destination),
        ],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.out == (
        '{"schema":"staged-memory-intake.relocation.v1","status":"relocated"}\n'
    )
    assert output.err == ""
    assert not source.exists()


def test_cli_routes_explicit_current_authority_adoption(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch a documented adoption flag that is not wired to relocation."""
    from staged_memory_intake.cli import Dependencies, main

    state_root, source, _, runner = _configured_root(tmp_path)
    source.rename(tmp_path / "synthetic-displaced-root")
    for path in (
        source,
        source / "01_Pending",
        source / "02_Staged",
        source / "03_Prepared",
        source / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    runner.inbox = source / "04_Inbox"
    destination = tmp_path / "synthetic-captures"
    trash_root = tmp_path / "synthetic-trash"
    trash_root.mkdir(mode=0o700)
    dependencies = Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash_root),
        publication_fault=NoPublicationFault(),
    )

    exit_code = main(
        [
            "--state-root",
            str(state_root),
            "relocate",
            "--to",
            str(destination),
            "--adopt-current-authority",
        ],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.out == (
        '{"schema":"staged-memory-intake.relocation.v1","status":"relocated"}\n'
    )
    assert output.err == ""


def test_cli_adopts_current_authority_in_place(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch CLI same-path adoption entering a move instead of returning current."""
    from staged_memory_intake.cli import Dependencies, main

    state_root, source, _, runner = _configured_root(tmp_path)
    _, rebound = _replace_configured_root(tmp_path, source, runner)
    trash_root = tmp_path / "synthetic-trash"
    trash_root.mkdir(mode=0o700)
    dependencies = Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash_root),
        publication_fault=NoPublicationFault(),
    )

    exit_code = main(
        [
            "--state-root",
            str(state_root),
            "relocate",
            "--to",
            str(source),
            "--adopt-current-authority",
        ],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.out == (
        '{"schema":"staged-memory-intake.relocation.v1","status":"current"}\n'
    )
    assert output.err == ""
    configured = load_config_record(state_root)
    assert configured.notes_root == source
    assert configured.notes_identity == rebound["."]
    assert configured.inbox_identity == rebound["04_Inbox"]
    assert not any(call[:2] == ("memory", "relocate-inbox") for call, _ in runner.calls)


@dataclass
class InProcessMemoryRunner:
    """Run the real Memory CLI against one disposable synthetic runtime."""

    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        from memory import cli

        self.calls.append((tuple(argv), timeout_seconds))
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = cli.main(list(argv[1:]))
        return CompletedCommand(
            returncode=returncode,
            stdout=stdout.getvalue().encode(),
            stderr=stderr.getvalue().encode(),
        )


def test_coordinator_uses_real_memory_relocation_twice(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch disagreement between helper orchestration and the released Memory CLI."""
    del synthetic_keychain
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root

    from memory import model as memory_model
    from memory import runtime

    notes = tmp_path / "synthetic-old-root"
    home = tmp_path / "synthetic-memory-home"
    state_root = tmp_path / "synthetic-helper-state"
    for path in (
        notes,
        notes / "01_Pending",
        notes / "02_Staged",
        notes / "03_Prepared",
        notes / "04_Inbox",
    ):
        path.mkdir(mode=0o700)
    runtime.initialize_runtime(
        runtime.resolve_runtime(home),
        mode=memory_model.RuntimeMode.PERSONAL,
        inbox=notes / "04_Inbox",
    )
    runner = InProcessMemoryRunner()
    configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
    )
    destination = tmp_path / "synthetic-captures"

    result = relocate_notes_root(
        state_root,
        destination,
        runner,
        NoRelocationFault(),
    )

    assert result.status == "relocated"
    assert runtime.resolve_runtime(home).inbox == destination / "04_Inbox"
    relocation_calls = [
        call for call, _ in runner.calls if call[:2] == ("memory", "relocate-inbox")
    ]
    assert relocation_calls == [
        (
            "memory",
            "relocate-inbox",
            "--home",
            str(home),
            "--to",
            str(state_root / ".notes-root-relocation-inbox"),
        ),
        (
            "memory",
            "relocate-inbox",
            "--home",
            str(home),
            "--to",
            str(destination / "04_Inbox"),
        ),
    ]


def test_active_transaction_refuses_before_any_relocation_artifact(
    tmp_path: Path,
) -> None:
    """Catch a root move that invalidates an authorization-bound transaction."""
    from staged_memory_intake.prepared import build_preview
    from staged_memory_intake.relocation import NoRelocationFault, relocate_notes_root
    from staged_memory_intake.state import TransactionStore

    state_root, source, _, runner = _configured_root(tmp_path)
    source_bytes = b"fresh synthetic source"
    source_name = "synthetic-source.md"
    prepared_name = "synthetic-prepared.md"
    (source / "02_Staged" / source_name).write_bytes(source_bytes)
    (source / "03_Prepared" / prepared_name).write_bytes(
        (
            "---\n"
            "memory_intake_version: 1\n"
            f"source_note: {source_name}\n"
            f"source_sha256: {hashlib.sha256(source_bytes).hexdigest()}\n"
            "kind: fact\n"
            "sensitivity: restricted\n"
            "occurred_on: \n"
            "valid_from: \n"
            "valid_to: \n"
            "tags: []\n"
            "---\n"
            "Fresh synthetic statement.\n"
        ).encode()
    )
    configured = load_config(state_root)
    assert configured is not None
    preview = build_preview(configured, [prepared_name], [])
    TransactionStore(state_root).authorize(preview, preview.manifest_digest)
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            tmp_path / "synthetic-captures",
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "transaction_active"
    assert directory_identity(source) == configured.notes_identity
    assert tuple(runner.calls) == calls_before
    assert not (state_root / ".notes-root-relocation.intent.json").exists()


def test_other_cli_commands_fail_closed_while_relocation_is_pending(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch an ordinary helper command running against a half-moved authority."""
    from staged_memory_intake.cli import Dependencies, main
    from staged_memory_intake.relocation import relocate_notes_root

    state_root, _, _, runner = _configured_root(tmp_path)
    destination = tmp_path / "synthetic-captures"
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            destination,
            runner,
            CrashOnce("intent_published"),
        )
    trash_root = tmp_path / "synthetic-trash"
    trash_root.mkdir(mode=0o700)
    dependencies = Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash_root),
        publication_fault=NoPublicationFault(),
    )

    exit_code = main(
        ["--state-root", str(state_root), "status"],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 4
    assert output.out == ""
    assert json.loads(output.err) == {
        "schema": "staged-memory-intake.error.v1",
        "code": "relocation_pending",
        "state": None,
        "ordinal": None,
        "retryable": True,
    }
