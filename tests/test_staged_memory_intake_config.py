"""Secure-path and relocatable configuration tests for staged intake."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from staged_memory_intake.config import (
    CONFIG_SCHEMA,
    configure,
    load_config,
    load_config_record,
    replace_config_paths,
    require_config,
    resolve_memory_paths,
)
from staged_memory_intake.model import (
    STATE_ORDER,
    CommandRunner,
    CompletedCommand,
    IntakeError,
    TransactionState,
    validate_state_transition,
)
from staged_memory_intake.relocation import relocate_notes_root
from staged_memory_intake.securefs import (
    atomic_private_json,
    directory_identity,
    inventory,
    read_regular,
    sha256_regular,
)
from staged_memory_intake_fakes import FakeMemoryPathsRunner, NeverRunner


@dataclass
class InterleavingMemoryPathsRunner:
    """Commit a competing initial configuration during path resolution."""

    winner: Callable[[], None]
    delegate: CommandRunner
    invoked: bool = False

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        if not self.invoked:
            self.invoked = True
            self.winner()
        return self.delegate.run(argv, timeout_seconds=timeout_seconds)


def _notes_root(tmp_path: Path, *, prepared: bool = True) -> Path:
    root = tmp_path / "synthetic-notes"
    root.mkdir(mode=0o700)
    (root / "01_Pending").mkdir(mode=0o700)
    (root / "02_Staged").mkdir(mode=0o700)
    if prepared:
        (root / "03_Prepared").mkdir(mode=0o700)
    return root


def _memory_paths(tmp_path: Path) -> tuple[Path, Path, FakeMemoryPathsRunner]:
    home = tmp_path / "synthetic-memory-home"
    inbox = tmp_path / "synthetic-memory-inbox"
    home.mkdir(mode=0o700)
    inbox.mkdir(mode=0o700)
    return home, inbox, FakeMemoryPathsRunner(home, inbox)


def _configured(tmp_path: Path) -> tuple[Path, Path, FakeMemoryPathsRunner]:
    notes = _notes_root(tmp_path)
    _, _, runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"
    configure(
        state_root,
        notes,
        None,
        create_prepared=False,
        runner=runner,
    )
    return state_root, notes, runner


def test_absent_configuration_is_valid_and_creates_nothing(tmp_path: Path) -> None:
    state_root = tmp_path / "absent-state"
    notes_root = tmp_path / "absent-notes"
    runner = NeverRunner()

    assert load_config(state_root) is None
    with pytest.raises(IntakeError) as caught:
        require_config(state_root)

    assert caught.value.code == "not_configured"
    assert caught.value.category == "configuration"
    assert caught.value.retryable is False
    assert caught.value.state is None
    assert caught.value.ordinal is None
    assert str(caught.value) == "not_configured"
    assert not state_root.exists()
    assert not notes_root.exists()
    assert runner.calls == 0


def test_configure_binds_real_roots_and_private_modes(tmp_path: Path) -> None:
    notes = _notes_root(tmp_path)
    home, inbox, runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"

    configured = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
    )

    assert configured.notes_root == notes
    assert configured.notes_identity == directory_identity(notes)
    assert configured.memory_home == home
    assert configured.memory_inbox == inbox
    assert configured.inbox_identity == directory_identity(inbox)
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
    assert stat.S_IMODE((state_root / "config.json").stat().st_mode) == 0o600
    assert runner.calls == [(("memory", "paths", "--home", str(home), "--json"), 30.0)]
    assert load_config(state_root) == configured


def test_configure_accepts_only_the_numbered_workflow_layout(
    tmp_path: Path,
) -> None:
    notes = tmp_path / "numbered-synthetic-notes"
    notes.mkdir(mode=0o700)
    for name in ("01_Pending", "02_Staged", "03_Prepared", "04_Inbox"):
        (notes / name).mkdir(mode=0o700)
    home = tmp_path / "synthetic-memory-home"
    home.mkdir(mode=0o700)
    inbox = notes / "04_Inbox"
    runner = FakeMemoryPathsRunner(home, inbox)

    configured = configure(
        tmp_path / "synthetic-state",
        notes,
        home,
        create_prepared=False,
        runner=runner,
    )

    assert configured.memory_inbox == inbox


def test_stale_initial_configuration_cannot_repoint_the_committed_winner(
    tmp_path: Path,
) -> None:
    winner_root = tmp_path / "winner"
    loser_root = tmp_path / "loser"
    winner_root.mkdir(mode=0o700)
    loser_root.mkdir(mode=0o700)
    winner_notes = _notes_root(winner_root)
    loser_notes = _notes_root(loser_root)
    home, inbox, winner_runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"
    winner_bytes: list[bytes] = []

    def commit_winner() -> None:
        configure(
            state_root,
            winner_notes,
            home,
            create_prepared=False,
            runner=winner_runner,
        )
        winner_bytes.append((state_root / "config.json").read_bytes())

    loser_runner = InterleavingMemoryPathsRunner(
        commit_winner,
        FakeMemoryPathsRunner(home, inbox),
    )
    loser_inventory = tuple((loser_notes / "03_Prepared").iterdir())
    loser_identity = directory_identity(loser_notes / "03_Prepared")

    with pytest.raises(IntakeError) as caught:
        configure(
            state_root,
            loser_notes,
            home,
            create_prepared=False,
            runner=loser_runner,
        )

    assert caught.value.code == "stale_configuration"
    assert len(winner_bytes) == 1
    assert (state_root / "config.json").read_bytes() == winner_bytes[0]
    configured = load_config(state_root)
    assert configured is not None
    assert configured.notes_root == winner_notes
    assert tuple((loser_notes / "03_Prepared").iterdir()) == loser_inventory
    assert directory_identity(loser_notes / "03_Prepared") == loser_identity


def test_default_memory_paths_uses_only_public_command(tmp_path: Path) -> None:
    home, inbox, runner = _memory_paths(tmp_path)

    paths = resolve_memory_paths(None, runner)

    assert paths.home == home
    assert paths.inbox == inbox
    assert runner.calls == [(("memory", "paths", "--json"), 30.0)]


def test_prepared_is_created_only_when_explicitly_requested(tmp_path: Path) -> None:
    notes = _notes_root(tmp_path, prepared=False)
    _, _, runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"

    with pytest.raises(IntakeError) as caught:
        configure(
            state_root,
            notes,
            None,
            create_prepared=False,
            runner=runner,
        )
    assert caught.value.code == "prepared_missing"
    assert not (notes / "03_Prepared").exists()
    assert not state_root.exists()

    configured = configure(
        state_root,
        notes,
        None,
        create_prepared=True,
        runner=runner,
    )
    assert configured.notes_root == notes
    assert stat.S_IMODE((notes / "03_Prepared").stat().st_mode) == 0o700


@pytest.mark.parametrize("folder", [None, "01_Pending", "02_Staged", "03_Prepared"])
def test_symlink_roots_and_required_folders_are_rejected(
    tmp_path: Path,
    folder: str | None,
) -> None:
    real_notes = _notes_root(tmp_path)
    _, _, runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"
    if folder is None:
        notes = tmp_path / "linked-notes"
        notes.symlink_to(real_notes, target_is_directory=True)
    else:
        notes = real_notes
        original = notes / folder
        moved = notes / f"{folder}-real"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)

    with pytest.raises((IntakeError, OSError)):
        configure(
            state_root,
            notes,
            None,
            create_prepared=False,
            runner=runner,
        )
    assert not state_root.exists()


def test_nested_staged_directory_is_rejected_without_reading_pending(
    tmp_path: Path,
) -> None:
    notes = _notes_root(tmp_path)
    (notes / "01_Pending" / "do-not-inventory").mkdir()
    (notes / "02_Staged" / "nested").mkdir()
    _, _, runner = _memory_paths(tmp_path)

    with pytest.raises(IntakeError) as caught:
        configure(
            tmp_path / "synthetic-state",
            notes,
            None,
            create_prepared=False,
            runner=runner,
        )

    assert caught.value.code == "staged_entry_not_regular"


def test_pending_is_neither_opened_nor_inventoried(tmp_path: Path) -> None:
    notes = _notes_root(tmp_path)
    pending = notes / "01_Pending"
    (pending / "unrestricted-owner-tree").mkdir()
    pending.chmod(0)
    _, _, runner = _memory_paths(tmp_path)
    try:
        configured = configure(
            tmp_path / "synthetic-state",
            notes,
            None,
            create_prepared=False,
            runner=runner,
        )
    finally:
        pending.chmod(0o700)

    assert configured.notes_root == notes


@pytest.mark.parametrize(
    "name",
    ["../escape.md", "nested/file.md", ".", "..", "nul\0name.md"],
)
def test_root_relative_reads_reject_path_escape(tmp_path: Path, name: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "escape.md").write_bytes(b"outside")

    with pytest.raises(IntakeError) as caught:
        read_regular(root, name, limit=64)

    assert caught.value.code == "invalid_relative_name"


def test_regular_reads_are_bounded_hashed_and_do_not_follow_symlinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "note.md").write_bytes(b"synthetic note")
    (root / "linked.md").symlink_to(root / "note.md")

    assert read_regular(root, "note.md", limit=14) == b"synthetic note"
    assert sha256_regular(root, "note.md", limit=14) == (
        "4168793f97486029e468a3cf60ae6f2296086f7476ffd616437af72799ec4939"
    )
    with pytest.raises(IntakeError) as overflow:
        read_regular(root, "note.md", limit=13)
    assert overflow.value.code == "file_too_large"
    with pytest.raises((IntakeError, OSError)):
        read_regular(root, "linked.md", limit=64)


def test_inventory_includes_dot_entries_without_following_them(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / ".marker").write_bytes(b"hidden")
    (root / "ordinary.md").write_bytes(b"ordinary")
    (root / "linked").symlink_to(tmp_path)

    assert inventory(root) == (".marker", "linked", "ordinary.md")


_LEGACY_CONFIG_SCHEMA = "staged-memory-intake.config.v1"
_CONFIG_LIMIT = 64 * 1024
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def _write_legacy_config(
    state_root: Path,
    notes: Path,
    inbox: Path,
    *,
    device_shift: int,
) -> None:
    notes_metadata = notes.lstat()
    inbox_metadata = inbox.lstat()
    atomic_private_json(
        state_root / "config.json",
        {
            "schema": _LEGACY_CONFIG_SCHEMA,
            "notes_root": str(notes),
            "notes_identity": {
                "device": notes_metadata.st_dev + device_shift,
                "inode": notes_metadata.st_ino,
            },
            "memory_home": None,
            "memory_inbox": str(inbox),
            "inbox_identity": {
                "device": inbox_metadata.st_dev + device_shift,
                "inode": inbox_metadata.st_ino,
            },
        },
    )


@pytest.mark.parametrize("device_shift", [0, 1])
def test_legacy_config_adopts_reboot_renumbered_device(
    tmp_path: Path,
    device_shift: int,
) -> None:
    state_root, notes, runner = _configured(tmp_path)
    _write_legacy_config(state_root, notes, runner.inbox, device_shift=device_shift)

    adopted = load_config(state_root)

    assert adopted is not None
    assert adopted.notes_root == notes
    assert adopted.notes_identity == directory_identity(notes)
    assert adopted.inbox_identity == directory_identity(runner.inbox)
    persisted = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    assert persisted["schema"] == CONFIG_SCHEMA
    assert persisted["notes_identity"] == {
        "volume": adopted.notes_identity.volume,
        "inode": notes.lstat().st_ino,
    }
    assert load_config(state_root) == adopted


def test_legacy_adoption_refuses_an_interleaved_reconfiguration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the one-shot upgrade silently reverting a concurrent write.

    The adoption write runs outside the transaction lock, so a locked
    reconfiguration landing between the adoption's record read and its write
    used to be clobbered by the rebind. The pre-write compare must refuse
    instead, leaving the interleaved configuration in place.
    """
    import staged_memory_intake.config as config_module

    state_root, notes, runner = _configured(tmp_path)
    (tmp_path / "interleaved").mkdir(mode=0o700)
    interleaved_notes = _notes_root(tmp_path / "interleaved")
    competing = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    competing["notes_root"] = str(interleaved_notes)
    competing["notes_identity"] = {
        "volume": directory_identity(interleaved_notes).volume,
        "inode": interleaved_notes.lstat().st_ino,
    }
    _write_legacy_config(state_root, notes, runner.inbox, device_shift=1)
    original_validate = config_module._validate_notes_root
    interleaved = False

    def interleave_then_validate(
        notes_root: Path,
        *,
        require_prepared: bool,
    ) -> None:
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            atomic_private_json(state_root / "config.json", competing)
        original_validate(notes_root, require_prepared=require_prepared)

    monkeypatch.setattr(
        config_module,
        "_validate_notes_root",
        interleave_then_validate,
    )

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "configured_root_changed"
    persisted = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    assert persisted["notes_root"] == str(interleaved_notes)


def test_legacy_adoption_refuses_a_mount_point_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch auto-adoption degenerating on a volume-root notes root.

    Volume roots share inode 2, so for a mount-point root the stored inode
    distinguishes nothing: any volume mounted at the configured path would
    self-adopt. The one-shot upgrade must refuse and leave the explicit
    `relocate --adopt-current-authority` rebind to the owner.
    """
    import staged_memory_intake.config as config_module
    from staged_memory_intake.model import DirectoryIdentity

    state_root, notes, runner = _configured(tmp_path)
    _write_legacy_config(state_root, notes, runner.inbox, device_shift=1)
    foreign = "00000000-0000-4000-8000-00000000000f"

    def mounted_notes_identity(path: Path) -> DirectoryIdentity:
        identity = directory_identity(path)
        if path == notes.parent:
            return DirectoryIdentity(volume=foreign, inode=identity.inode)
        return identity

    monkeypatch.setattr(
        config_module,
        "directory_identity",
        mounted_notes_identity,
    )

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "notes_root_unverifiable"
    persisted = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    assert persisted["schema"] == _LEGACY_CONFIG_SCHEMA


def test_legacy_config_with_changed_inode_still_fails_closed(
    tmp_path: Path,
) -> None:
    state_root, notes, runner = _configured(tmp_path)
    _write_legacy_config(state_root, notes, runner.inbox, device_shift=1)
    replacement = tmp_path / "replacement-notes"
    notes.rename(replacement)
    notes.mkdir(mode=0o700)
    for folder in ("01_Pending", "02_Staged", "03_Prepared"):
        (notes / folder).mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "notes_root_changed"
    persisted = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    assert persisted["schema"] == _LEGACY_CONFIG_SCHEMA


def test_missing_volume_uuid_is_reported_as_volume_unidentified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the volume-UUID constraint hiding behind a changed-root code.

    A volume without a readable UUID (FAT, exFAT, some network filesystems)
    cannot be identity-bound at all. Re-coding that as configured_root_changed
    told the owner their unchanged root moved; the real constraint must
    surface under its own name.
    """
    import staged_memory_intake.config as config_module
    from staged_memory_intake.model import DirectoryIdentity

    state_root, notes, _runner = _configured(tmp_path)

    def unidentified_notes(path: Path) -> DirectoryIdentity:
        if path == notes:
            raise IntakeError("volume_unidentified", "configuration")
        return directory_identity(path)

    monkeypatch.setattr(config_module, "directory_identity", unidentified_notes)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "volume_unidentified"


def test_child_deleted_between_lookups_is_reported_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a mid-race deletion surfacing as a mangled directory.

    The by-name child check assembles inode and volume from two lookups. A
    child deleted between them used to surface as {role}_not_directory --
    an authority-changed shape -- when the truth is simply that the child is
    gone.
    """
    import staged_memory_intake.config as config_module
    from staged_memory_intake.securefs import entry_volume

    state_root, _notes, _runner = _configured(tmp_path)

    def deleted_after_stat(parent_descriptor: int, name: str) -> str:
        if name == "01_Pending":
            raise FileNotFoundError(2, "synthetic mid-race deletion")
        return entry_volume(parent_descriptor, name)

    monkeypatch.setattr(config_module, "entry_volume", deleted_after_stat)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "pending_missing"


def test_entry_volume_reports_an_absent_name_like_stat(tmp_path: Path) -> None:
    """Catch getattrlistat's ENOENT vanishing into volume_unidentified.

    The kernel sets errno on failure and the reader never looked at it, so a
    plainly absent name was indistinguishable from a volume with no UUID.
    Absence must raise the same FileNotFoundError a stat would.
    """
    from staged_memory_intake.securefs import entry_volume

    root = tmp_path / "synthetic-parent"
    root.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(FileNotFoundError):
            entry_volume(descriptor, "synthetic-absent-child")
    finally:
        os.close(descriptor)


def test_changed_volume_binding_fails_closed(tmp_path: Path) -> None:
    state_root, _notes, _ = _configured(tmp_path)
    payload = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    payload["notes_identity"]["volume"] = "00000000-0000-4000-8000-000000000001"
    atomic_private_json(state_root / "config.json", payload)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "notes_root_changed"


def test_config_volume_must_be_a_canonical_uuid(tmp_path: Path) -> None:
    state_root, _notes, _ = _configured(tmp_path)
    payload = json.loads(read_regular(state_root, "config.json", limit=_CONFIG_LIMIT))
    payload["inbox_identity"]["volume"] = "not-a-volume-uuid"
    atomic_private_json(state_root / "config.json", payload)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "invalid_config"


def test_directory_identity_binds_reboot_stable_volume(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)

    first_identity = directory_identity(first)
    second_identity = directory_identity(second)

    assert first_identity.volume is not None
    assert _UUID_PATTERN.fullmatch(first_identity.volume) is not None
    assert first_identity.volume == second_identity.volume
    assert first_identity != second_identity
    assert directory_identity(first) == first_identity


def test_changed_notes_directory_identity_fails_closed(tmp_path: Path) -> None:
    state_root, notes, _ = _configured(tmp_path)
    old_notes = tmp_path / "old-notes"
    notes.rename(old_notes)
    notes.mkdir(mode=0o700)
    for folder in ("01_Pending", "02_Staged", "03_Prepared"):
        (notes / folder).mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "notes_root_changed"


def test_changed_memory_inbox_identity_fails_closed(tmp_path: Path) -> None:
    state_root, _, runner = _configured(tmp_path)
    old_inbox = tmp_path / "old-inbox"
    runner.inbox.rename(old_inbox)
    runner.inbox.mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "memory_inbox_changed"


def test_non_private_state_root_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "synthetic-state"
    state_root.mkdir(mode=0o755)
    state_root.chmod(0o755)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "state_root_not_private"


def test_insecure_state_root_blocks_prepared_and_config_creation(
    tmp_path: Path,
) -> None:
    notes = _notes_root(tmp_path, prepared=False)
    _, _, runner = _memory_paths(tmp_path)
    state_root = tmp_path / "synthetic-state"
    state_root.mkdir(mode=0o755)
    state_root.chmod(0o755)

    with pytest.raises(IntakeError) as caught:
        configure(
            state_root,
            notes,
            None,
            create_prepared=True,
            runner=runner,
        )

    assert caught.value.code == "state_root_not_private"
    assert not (notes / "03_Prepared").exists()
    assert not (state_root / "config.json").exists()


def test_missing_or_non_private_config_file_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "synthetic-state"
    state_root.mkdir(mode=0o700)

    with pytest.raises(IntakeError) as missing:
        load_config(state_root)
    assert missing.value.code == "invalid_config"

    config_path = state_root / "config.json"
    config_path.write_bytes(b"{}")
    config_path.chmod(0o644)
    with pytest.raises(IntakeError) as public:
        load_config(state_root)
    assert public.value.code == "config_not_private"


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"[]",
        json.dumps({"schema": CONFIG_SCHEMA}).encode(),
    ],
)
def test_malformed_configuration_is_content_free(
    tmp_path: Path,
    payload: bytes,
) -> None:
    state_root = tmp_path / "synthetic-state"
    state_root.mkdir(mode=0o700)
    config_path = state_root / "config.json"
    config_path.write_bytes(payload)
    config_path.chmod(0o600)

    with pytest.raises(IntakeError) as caught:
        load_config(state_root)

    assert caught.value.code == "invalid_config"
    assert str(caught.value) == "invalid_config"


@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": "value"},
        {"home": 7},
        {"inbox": "relative/inbox"},
    ],
)
def test_memory_paths_requires_exact_complete_string_shape(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    _, _, runner = _memory_paths(tmp_path)
    runner.extra = mutation

    with pytest.raises(IntakeError) as caught:
        resolve_memory_paths(None, runner)

    assert caught.value.code == "invalid_memory_paths"
    assert caught.value.category == "memory"


def test_memory_paths_rejects_failure_and_symlink_directory(tmp_path: Path) -> None:
    home, inbox, runner = _memory_paths(tmp_path)
    runner.returncode = 1
    runner.stderr = b"synthetic private subprocess detail"
    with pytest.raises(IntakeError) as failed:
        resolve_memory_paths(None, runner)
    assert failed.value.code == "memory_paths_failed"
    assert "private" not in str(failed.value)

    runner.returncode = 0
    runner.stderr = b""
    inbox.rmdir()
    real_inbox = tmp_path / "real-inbox"
    real_inbox.mkdir()
    inbox.symlink_to(real_inbox, target_is_directory=True)
    with pytest.raises((IntakeError, OSError)):
        resolve_memory_paths(home, runner)


def test_atomic_private_json_replaces_with_canonical_private_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    path = root / "record.json"

    atomic_private_json(path, {"z": 2, "a": "synthetic"})

    assert path.read_bytes() == b'{"a":"synthetic","z":2}\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not [name for name in os.listdir(root) if name != "record.json"]


def test_transaction_states_only_allow_idempotence_or_next_state() -> None:
    assert tuple(state.value for state in STATE_ORDER) == (
        "owner_authorized",
        "publishing",
        "published",
        "captured",
        "review_ready",
        "awaiting_memory_approval",
        "applied",
        "verified",
        "cleanup_pending",
        "complete",
    )
    for ordinal, current in enumerate(STATE_ORDER):
        validate_state_transition(current, current)
        if ordinal + 1 < len(STATE_ORDER):
            validate_state_transition(current, STATE_ORDER[ordinal + 1])

    with pytest.raises(IntakeError) as skipped:
        validate_state_transition(
            TransactionState.OWNER_AUTHORIZED,
            TransactionState.PUBLISHED,
        )
    assert skipped.value.code == "invalid_state_transition"
    assert skipped.value.state is TransactionState.OWNER_AUTHORIZED

    with pytest.raises(IntakeError):
        validate_state_transition(
            TransactionState.VERIFIED,
            TransactionState.APPLIED,
        )


def _flag_environment(tmp_path: Path) -> tuple[Path, Path, Path, FakeMemoryPathsRunner]:
    notes = tmp_path / "synthetic-flag-notes"
    home = tmp_path / "synthetic-flag-home"
    # The inbox is nested at the numbered layout's own name so this
    # environment is also relocatable: relocate_notes_root's preflight
    # refuses relocation_layout_invalid for any config whose memory_inbox is
    # not exactly notes_root / "04_Inbox", which the same-path adoption test
    # below exercises.
    inbox = notes / "04_Inbox"
    # state_root is deliberately left absent: configure() creates it itself,
    # and pre-creating an empty directory here makes configure() take its
    # already-configured branch, which then fails closed with invalid_config
    # because no config.json exists yet.
    state_root = tmp_path / "synthetic-flag-state"
    for path in (
        notes,
        notes / "01_Pending",
        notes / "02_Staged",
        notes / "03_Prepared",
        inbox,
        home,
    ):
        path.mkdir(mode=0o700)
    return state_root, notes, home, FakeMemoryPathsRunner(home=home, inbox=inbox)


def _raw_config(state_root: Path) -> dict[str, object]:
    payload = json.loads((state_root / "config.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_pending_drop_defaults_off_and_stays_out_of_the_payload(
    tmp_path: Path,
) -> None:
    state_root, notes, home, runner = _flag_environment(tmp_path)
    config = configure(state_root, notes, home, create_prepared=False, runner=runner)
    assert config.pending_drop is False
    assert "pending_drop" not in _raw_config(state_root)


def test_pending_drop_enables_persists_and_survives_reconfigure(
    tmp_path: Path,
) -> None:
    state_root, notes, home, runner = _flag_environment(tmp_path)
    configure(state_root, notes, home, create_prepared=False, runner=runner)
    enabled = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
        pending_drop=True,
    )
    assert enabled.pending_drop is True
    assert _raw_config(state_root)["pending_drop"] is True
    kept = configure(state_root, notes, home, create_prepared=False, runner=runner)
    assert kept.pending_drop is True
    disabled = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
        pending_drop=False,
    )
    assert disabled.pending_drop is False
    assert "pending_drop" not in _raw_config(state_root)


def test_pending_drop_key_must_be_a_boolean(tmp_path: Path) -> None:
    state_root, notes, home, runner = _flag_environment(tmp_path)
    configure(state_root, notes, home, create_prepared=False, runner=runner)
    payload = _raw_config(state_root)
    payload["pending_drop"] = "on"
    atomic_private_json(state_root / "config.json", payload)
    with pytest.raises(IntakeError, match="invalid_config"):
        load_config(state_root)


def test_replace_config_paths_carries_the_enabled_flag(tmp_path: Path) -> None:
    state_root, notes, home, runner = _flag_environment(tmp_path)
    configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
        pending_drop=True,
    )
    old = require_config(state_root)
    updated = replace_config_paths(
        state_root,
        old,
        old.notes_root,
        old.notes_identity,
        old.memory_inbox,
        old.inbox_identity,
    )
    assert updated.pending_drop is True


def test_same_path_adoption_carries_the_enabled_flag(tmp_path: Path) -> None:
    state_root, notes, home, runner = _flag_environment(tmp_path)
    configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
        pending_drop=True,
    )
    relocate_notes_root(state_root, notes, runner, adopt_current_authority=True)
    assert load_config_record(state_root).pending_drop is True


def test_intake_error_fields_are_immutable() -> None:
    error = IntakeError(
        "synthetic_error",
        "state",
        retryable=True,
        state=TransactionState.PUBLISHED,
        ordinal=3,
    )

    for field, replacement in (
        ("code", "replacement"),
        ("category", "trash"),
        ("retryable", False),
        ("state", TransactionState.COMPLETE),
        ("ordinal", 7),
    ):
        with pytest.raises(AttributeError):
            setattr(error, field, replacement)
