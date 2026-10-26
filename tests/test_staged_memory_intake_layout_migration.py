"""Crash-safe legacy-to-numbered staged-intake layout migration tests."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast

import pytest
from staged_memory_intake.config import CONFIG_SCHEMA, load_config, load_config_record
from staged_memory_intake.layout_migration import (
    NoLayoutMigrationFault,
    migrate_layout,
)
from staged_memory_intake.model import (
    CompletedCommand,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    NoRelocationFault,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.relocation import relocate_notes_root
from staged_memory_intake.securefs import atomic_private_json, directory_identity
from staged_memory_intake.state import TransactionStore


@dataclass
class RelocatingMemoryRunner:
    """Synthetic public Memory CLI over one disposable Inbox directory."""

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
                status = "current"
            else:
                self.inbox.rename(destination)
                self.inbox = destination
                status = "relocated"
            return CompletedCommand(
                0,
                json.dumps(
                    {"status": status},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n",
                b"",
            )
        raise AssertionError(command)


@dataclass
class InterruptingMemoryRunner:
    """Model Memory requiring exact retry after its move committed."""

    delegate: RelocatingMemoryRunner
    interrupted: bool = False
    pending_destination: Path | None = None

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        command = tuple(argv)
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


class SyntheticCrash(BaseException):
    """Simulate process loss without operational exception handling."""


@dataclass
class CrashOnce:
    """Interrupt one exact durability checkpoint once."""

    checkpoint_name: str
    crashed: bool = False

    def checkpoint(self, name: str) -> None:
        if name == self.checkpoint_name and not self.crashed:
            self.crashed = True
            raise SyntheticCrash


@dataclass(frozen=True)
class _SyntheticActive:
    state: TransactionState = TransactionState.OWNER_AUTHORIZED


def _write_config(state_root: Path, config: IntakeConfig) -> None:
    atomic_private_json(
        state_root / "config.json",
        {
            "schema": CONFIG_SCHEMA,
            "notes_root": str(config.notes_root),
            "notes_identity": {
                "volume": config.notes_identity.volume,
                "inode": config.notes_identity.inode,
            },
            "memory_home": (
                None if config.memory_home is None else str(config.memory_home)
            ),
            "memory_inbox": str(config.memory_inbox),
            "inbox_identity": {
                "volume": config.inbox_identity.volume,
                "inode": config.inbox_identity.inode,
            },
        },
    )


def _legacy_configured_root(
    tmp_path: Path,
) -> tuple[Path, Path, RelocatingMemoryRunner]:
    notes = tmp_path / "synthetic-captures"
    home = tmp_path / "synthetic-memory-home"
    state_root = tmp_path / "synthetic-helper-state"
    for path in (
        notes,
        notes / "Pending",
        notes / "Staged",
        notes / "Prepared",
        notes / "Inbox",
        home,
        state_root,
    ):
        path.mkdir(mode=0o700)
    inbox = notes / "Inbox"
    atomic_private_json(
        state_root / "config.json",
        {
            "schema": CONFIG_SCHEMA,
            "notes_root": str(notes),
            "notes_identity": {
                "volume": directory_identity(notes).volume,
                "inode": directory_identity(notes).inode,
            },
            "memory_home": str(home),
            "memory_inbox": str(inbox),
            "inbox_identity": {
                "volume": directory_identity(inbox).volume,
                "inode": directory_identity(inbox).inode,
            },
        },
    )
    return state_root, notes, RelocatingMemoryRunner(home=home, inbox=inbox)


def _numbered_configured_root(
    tmp_path: Path,
) -> tuple[Path, Path, RelocatingMemoryRunner]:
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    for legacy, numbered in (
        ("Pending", "01_Pending"),
        ("Staged", "02_Staged"),
        ("Prepared", "03_Prepared"),
        ("Inbox", "04_Inbox"),
    ):
        (notes / legacy).rename(notes / numbered)
    runner.inbox = notes / "04_Inbox"
    configured = load_config_record(state_root)
    _write_config(
        state_root,
        replace(configured, memory_inbox=runner.inbox),
    )
    return state_root, notes, runner


def _workflow_identities(notes: Path) -> dict[str, DirectoryIdentity]:
    return {
        name: directory_identity(notes / name)
        for name in ("01_Pending", "02_Staged", "03_Prepared", "04_Inbox")
    }


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


def test_migrate_layout_adopts_a_device_bound_config(tmp_path: Path) -> None:
    """Catch the legacy layout having no adoption path at all.

    A device-bound v1 config on the legacy folder layout could not be adopted
    anywhere: the ordinary load path requires the numbered layout, and
    `migrate-layout` -- the only command that could fix the layout -- read the
    exact record and falsely refused its legacy device sentinel as
    layout_migration_authority_changed.
    """
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    _rewrite_config_device_bound(state_root, device_shift=1)

    result = migrate_layout(state_root, runner)

    assert result.status == "migrated"
    assert set(os.listdir(notes)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }
    configured = load_config(state_root)
    assert configured is not None
    assert configured.notes_identity == directory_identity(notes)
    assert configured.inbox_identity == directory_identity(notes / "04_Inbox")


def test_abandon_unsupported_layout_intent_unwedges_pending(
    tmp_path: Path,
) -> None:
    """Catch a pre-v2 layout-migration intent refusing every command forever."""
    from staged_memory_intake.layout_migration import (
        abandon_unsupported_intent,
        layout_migration_pending,
    )

    state_root = tmp_path / "synthetic-wedged-state"
    state_root.mkdir(mode=0o700)
    intent_path = state_root / ".layout-migration.intent.json"
    atomic_private_json(
        intent_path,
        {
            "schema": "staged-memory-intake.layout-migration-intent.v1",
            "phase": "prepared",
        },
    )
    with pytest.raises(IntakeError) as wedged:
        layout_migration_pending(state_root)
    assert wedged.value.code == "layout_migration_intent_invalid"

    assert abandon_unsupported_intent(state_root) is True

    assert layout_migration_pending(state_root) is False
    quarantined = sorted(state_root.glob("abandoned-.layout-migration.intent.json.*"))
    assert len(quarantined) == 1
    assert abandon_unsupported_intent(state_root) is False


def test_layout_migration_surfaces_volume_unidentified_unrecoded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch layout migration re-coding the volume-UUID constraint as drift."""
    import staged_memory_intake.layout_migration as layout_migration

    state_root, _notes, runner = _numbered_configured_root(tmp_path)

    def unidentified(path: Path) -> DirectoryIdentity:
        raise IntakeError("volume_unidentified", "configuration")

    monkeypatch.setattr(layout_migration, "directory_identity", unidentified)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "volume_unidentified"


def test_migrate_layout_preserves_all_directory_identities(tmp_path: Path) -> None:
    """Catch a migration that copies, recreates, omits, or mislabels a role."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    before = {
        legacy: directory_identity(notes / legacy)
        for legacy in ("Pending", "Staged", "Prepared", "Inbox")
    }

    result = migrate_layout(state_root, runner)

    assert result.status == "migrated"
    assert set(os.listdir(notes)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }
    assert directory_identity(notes / "01_Pending") == before["Pending"]
    assert directory_identity(notes / "02_Staged") == before["Staged"]
    assert directory_identity(notes / "03_Prepared") == before["Prepared"]
    assert directory_identity(notes / "04_Inbox") == before["Inbox"]
    assert runner.inbox == notes / "04_Inbox"
    configured = load_config(state_root)
    assert configured is not None
    assert configured.memory_inbox == notes / "04_Inbox"
    assert configured.inbox_identity == before["Inbox"]
    assert not (state_root / ".layout-migration.intent.json").exists()


def test_layout_migration_carries_the_enabled_pending_drop_flag(
    tmp_path: Path,
) -> None:
    """Catch the preflight snapshot losing pending_drop across a migration."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    payload = json.loads((state_root / "config.json").read_text(encoding="utf-8"))
    payload["pending_drop"] = True
    atomic_private_json(state_root / "config.json", payload)
    before = {
        legacy: directory_identity(notes / legacy)
        for legacy in ("Pending", "Staged", "Prepared", "Inbox")
    }

    result = migrate_layout(state_root, runner)

    assert result.status == "migrated"
    assert set(os.listdir(notes)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }
    assert directory_identity(notes / "01_Pending") == before["Pending"]
    assert directory_identity(notes / "02_Staged") == before["Staged"]
    assert directory_identity(notes / "03_Prepared") == before["Prepared"]
    assert directory_identity(notes / "04_Inbox") == before["Inbox"]
    assert runner.inbox == notes / "04_Inbox"
    configured = load_config(state_root)
    assert configured is not None
    assert configured.memory_inbox == notes / "04_Inbox"
    assert configured.inbox_identity == before["Inbox"]
    assert not (state_root / ".layout-migration.intent.json").exists()
    assert load_config_record(state_root).pending_drop is True


def test_migrate_layout_exact_replay_is_current(tmp_path: Path) -> None:
    """Catch replay starting another transition after exact completion."""
    state_root, _, runner = _legacy_configured_root(tmp_path)
    migrate_layout(state_root, runner)
    calls_before = tuple(runner.calls)

    result = migrate_layout(state_root, runner)

    assert result.status == "current"
    assert tuple(runner.calls) == (
        *calls_before,
        (("memory", "paths", "--home", str(runner.home), "--json"), 30.0),
    )


def test_interrupted_memory_relocation_recovers_by_exact_retry(
    tmp_path: Path,
) -> None:
    """Recover when Memory moved the Inbox but reported process failure."""
    state_root, notes, delegate = _legacy_configured_root(tmp_path)
    runner = InterruptingMemoryRunner(delegate)

    with pytest.raises(IntakeError) as interrupted:
        migrate_layout(state_root, runner)
    assert interrupted.value.code == "memory_relocation_failed"
    assert delegate.inbox == notes / "04_Inbox"
    assert runner.pending_destination == notes / "04_Inbox"

    recovered = migrate_layout(state_root, runner)

    assert recovered.status == "recovered"
    assert runner.pending_destination is None
    assert set(os.listdir(notes)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }
    assert not (state_root / ".layout-migration.intent.json").exists()


@pytest.mark.parametrize(
    "checkpoint",
    [
        "intent_published",
        "inbox_numbered_uncommitted",
        "inbox_numbered",
        "pending_numbered_uncommitted",
        "pending_numbered",
        "staged_numbered_uncommitted",
        "staged_numbered",
        "prepared_numbered_uncommitted",
        "prepared_numbered",
        "config_replaced_uncommitted",
        "config_replaced",
        "intent_removed",
    ],
)
def test_every_layout_migration_interruption_converges_on_exact_retry(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    """Catch any side effect or phase write that cannot recover exactly."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    before = {
        legacy: directory_identity(notes / legacy)
        for legacy in ("Pending", "Staged", "Prepared", "Inbox")
    }

    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce(checkpoint))

    result = migrate_layout(state_root, runner, NoLayoutMigrationFault())

    assert result.status == (
        "current" if checkpoint == "intent_removed" else "recovered"
    )
    assert _workflow_identities(notes) == {
        "01_Pending": before["Pending"],
        "02_Staged": before["Staged"],
        "03_Prepared": before["Prepared"],
        "04_Inbox": before["Inbox"],
    }
    assert runner.inbox == notes / "04_Inbox"
    assert not (state_root / ".layout-migration.intent.json").exists()


@pytest.mark.parametrize(
    "checkpoint",
    [
        "intent_published",
        "inbox_numbered_uncommitted",
        "inbox_numbered",
        "pending_numbered_uncommitted",
        "pending_numbered",
        "staged_numbered_uncommitted",
        "staged_numbered",
        "prepared_numbered_uncommitted",
        "prepared_numbered",
        "config_replaced_uncommitted",
        "config_replaced",
        "intent_removed",
    ],
)
def test_layout_migration_recovery_carries_the_enabled_pending_drop_flag(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    """Catch a resumed migration losing pending_drop across a process crash."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    payload = json.loads((state_root / "config.json").read_text(encoding="utf-8"))
    payload["pending_drop"] = True
    atomic_private_json(state_root / "config.json", payload)
    before = {
        legacy: directory_identity(notes / legacy)
        for legacy in ("Pending", "Staged", "Prepared", "Inbox")
    }

    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce(checkpoint))

    result = migrate_layout(state_root, runner, NoLayoutMigrationFault())

    assert result.status == (
        "current" if checkpoint == "intent_removed" else "recovered"
    )
    assert _workflow_identities(notes) == {
        "01_Pending": before["Pending"],
        "02_Staged": before["Staged"],
        "03_Prepared": before["Prepared"],
        "04_Inbox": before["Inbox"],
    }
    assert runner.inbox == notes / "04_Inbox"
    assert not (state_root / ".layout-migration.intent.json").exists()
    assert load_config_record(state_root).pending_drop is True


def test_layout_migration_intent_without_pending_drop_key_parses_as_false(
    tmp_path: Path,
) -> None:
    """Catch a pre-upgrade migration intent (no pending_drop key) failing to resume."""
    state_root, _notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    intent_path = state_root / ".layout-migration.intent.json"
    payload = json.loads(intent_path.read_bytes())
    assert "pending_drop" not in payload

    result = migrate_layout(state_root, runner, NoLayoutMigrationFault())

    assert result.status == "recovered"
    assert load_config_record(state_root).pending_drop is False


def test_layout_migration_intent_pending_drop_key_must_be_a_boolean(
    tmp_path: Path,
) -> None:
    """Reject a tampered migration intent whose pending_drop key is not a boolean."""
    state_root, _notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    intent_path = state_root / ".layout-migration.intent.json"
    payload = json.loads(intent_path.read_bytes())
    payload["pending_drop"] = "on"
    atomic_private_json(intent_path, payload)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_intent_invalid"


def test_active_transaction_refuses_before_migration_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not invalidate paths bound into an active owner authorization."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)

    def active(_store: TransactionStore) -> TransactionReceipt | None:
        return cast("TransactionReceipt", _SyntheticActive())

    monkeypatch.setattr(TransactionStore, "active", active)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "transaction_active"
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}
    assert not (state_root / ".layout-migration.intent.json").exists()
    assert runner.calls == []


def test_root_relocation_intent_excludes_layout_migration(tmp_path: Path) -> None:
    """Never run two topology journals against the same configured root."""
    state_root, _, runner = _numbered_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        relocate_notes_root(
            state_root,
            tmp_path / "synthetic-relocated-root",
            runner,
            CrashOnce("intent_published"),
        )

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "relocation_pending"
    assert not (state_root / ".layout-migration.intent.json").exists()


def test_layout_migration_intent_excludes_root_relocation(tmp_path: Path) -> None:
    """A root move must not begin while folder labels are half migrated."""
    state_root, _, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))

    with pytest.raises(IntakeError) as caught:
        relocate_notes_root(
            state_root,
            tmp_path / "synthetic-relocated-root",
            runner,
            NoRelocationFault(),
        )

    assert caught.value.code == "layout_migration_pending"


def test_config_substitution_after_intent_refuses_before_side_effects(
    tmp_path: Path,
) -> None:
    """Bind recovery to the exact config that authorized its intent."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    calls_before = tuple(runner.calls)
    different_home = tmp_path / "synthetic-different-home"
    different_home.mkdir(mode=0o700)
    configured = load_config_record(state_root)
    _write_config(state_root, replace(configured, memory_home=different_home))

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_config_changed"
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}
    assert tuple(runner.calls) == calls_before


def test_wrong_memory_inbox_refuses_before_publishing_intent(tmp_path: Path) -> None:
    """Do not rename a directory Memory does not identify as its Inbox."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    different_inbox = tmp_path / "synthetic-different-inbox"
    different_inbox.mkdir(mode=0o700)
    runner.inbox = different_inbox

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_authority_changed"
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}
    assert not (state_root / ".layout-migration.intent.json").exists()


def test_child_identity_substitution_refuses_before_next_side_effect(
    tmp_path: Path,
) -> None:
    """Recovery must not transfer an intent to a replacement directory."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    calls_before = tuple(runner.calls)
    (notes / "Pending").rename(tmp_path / "synthetic-displaced-pending")
    (notes / "Pending").mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_layout_changed"
    assert runner.inbox == notes / "Inbox"
    assert tuple(runner.calls) == calls_before


@pytest.mark.parametrize(
    ("checkpoint", "substituted_role", "next_legacy_role"),
    [
        ("inbox_numbered", "Staged", "Pending"),
        ("pending_numbered", "Prepared", "Staged"),
        ("staged_numbered", "Prepared", "Prepared"),
    ],
)
def test_each_durable_phase_revalidates_all_children_before_next_rename(
    tmp_path: Path,
    checkpoint: str,
    substituted_role: str,
    next_legacy_role: str,
) -> None:
    """Do not mutate another label after any bound sibling is substituted."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce(checkpoint))
    calls_before = tuple(runner.calls)
    source = notes / substituted_role
    source.rename(tmp_path / f"synthetic-displaced-{substituted_role.lower()}")
    source.mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_layout_changed"
    assert (notes / next_legacy_role).is_dir()
    assert tuple(runner.calls) == calls_before


@pytest.mark.parametrize(
    "case",
    ["collision", "mixed", "unexpected", "unsafe_mode", "symlink"],
)
def test_ambiguous_or_unsafe_legacy_layout_is_never_migrated(
    tmp_path: Path,
    case: str,
) -> None:
    """Refuse topology ambiguity without deleting, merging, or guessing."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    if case == "collision":
        (notes / "01_Pending").mkdir(mode=0o700)
    elif case == "mixed":
        (notes / "Pending").rename(notes / "01_Pending")
    elif case == "unexpected":
        (notes / "synthetic-unexpected.txt").write_text("synthetic", encoding="utf-8")
    elif case == "unsafe_mode":
        (notes / "Staged").chmod(0o750)
    else:
        displaced = tmp_path / "synthetic-displaced-prepared"
        (notes / "Prepared").rename(displaced)
        (notes / "Prepared").symlink_to(displaced, target_is_directory=True)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_layout_changed"
    assert not (state_root / ".layout-migration.intent.json").exists()
    assert not any(
        command[:2] == ("memory", "relocate-inbox")
        for command, _timeout in runner.calls
    )


def test_optional_obsidian_authority_change_refuses_before_side_effects(
    tmp_path: Path,
) -> None:
    """Treat optional root metadata as opaque but bind its exact authority."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    metadata = notes / ".obsidian"
    metadata.mkdir(mode=0o755)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    calls_before = tuple(runner.calls)
    metadata.chmod(0o700)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_authority_changed"
    assert runner.inbox == notes / "Inbox"
    assert tuple(runner.calls) == calls_before


@pytest.mark.parametrize("mutation", ["malformed", "wrong_schema", "wrong_mode"])
def test_invalid_migration_intent_never_recovers(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Reject any journal that is not the exact private canonical record."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    with pytest.raises(SyntheticCrash):
        migrate_layout(state_root, runner, CrashOnce("intent_published"))
    intent_path = state_root / ".layout-migration.intent.json"
    if mutation == "malformed":
        intent_path.write_bytes(b"{\n")
        intent_path.chmod(0o600)
    elif mutation == "wrong_schema":
        payload = json.loads(intent_path.read_bytes())
        assert isinstance(payload, dict)
        payload["schema"] = "staged-memory-intake.layout-migration-intent.v3"
        atomic_private_json(intent_path, payload)
    else:
        intent_path.chmod(0o644)
    calls_before = tuple(runner.calls)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_intent_invalid"
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}
    assert tuple(runner.calls) == calls_before


def test_migration_never_inventories_a_workflow_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove migration observes only root labels, never nested names."""
    state_root, notes, runner = _legacy_configured_root(tmp_path)
    for index, name in enumerate(("Pending", "Staged", "Prepared", "Inbox")):
        child = notes / name
        (child / f"synthetic-private-{index}.txt").write_text(
            "fresh synthetic content",
            encoding="utf-8",
        )
        (child / f"synthetic-nested-{index}").mkdir(mode=0o700)
    metadata = notes / ".obsidian"
    metadata.mkdir(mode=0o755)
    (metadata / "synthetic-settings.json").write_text(
        "{}",
        encoding="utf-8",
    )
    notes_identity = directory_identity(notes)
    real_listdir = os.listdir

    def root_only_listdir(descriptor: int) -> list[str]:
        metadata = os.fstat(descriptor)
        if metadata.st_ino != notes_identity.inode:
            raise AssertionError("workflow child was enumerated")
        return real_listdir(descriptor)

    monkeypatch.setattr(os, "listdir", root_only_listdir)

    result = migrate_layout(state_root, runner)

    assert result.status == "migrated"


def test_exclusive_rename_preserves_a_destination_race_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a rename implementation that overwrites a concurrent collision."""
    import staged_memory_intake.layout_migration as layout_migration

    state_root, notes, runner = _legacy_configured_root(tmp_path)
    source_identity = directory_identity(notes / "Pending")
    real_rename = layout_migration._rename_no_replace
    winner_identity: object | None = None

    def race_once(
        parent_descriptor: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal winner_identity
        if destination_name == "01_Pending" and winner_identity is None:
            os.mkdir(destination_name, mode=0o700, dir_fd=parent_descriptor)
            winner_identity = directory_identity(notes / destination_name)
        real_rename(parent_descriptor, source_name, destination_name)

    monkeypatch.setattr(layout_migration, "_rename_no_replace", race_once)

    with pytest.raises(IntakeError) as caught:
        migrate_layout(state_root, runner)

    assert caught.value.code == "layout_migration_rename_failed"
    assert directory_identity(notes / "Pending") == source_identity
    assert directory_identity(notes / "01_Pending") == winner_identity
    assert source_identity != winner_identity
    assert stat.S_IMODE((notes / "01_Pending").stat().st_mode) == 0o700
