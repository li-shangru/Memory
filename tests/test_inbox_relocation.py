"""Crash-safe relocation of one exact configured external Inbox."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from memory import inbox_relocation as relocation_module
from memory.errors import InvalidArgumentError, InvalidRuntimeError, StoreBusyError
from memory.inbox_relocation import (
    DestinationParent,
    DirectoryMoveReference,
    DirectoryMoveSource,
    relocate_inbox,
)
from memory.model import RuntimeMode
from memory.runtime import (
    authorize_runtime_use,
    initialize_runtime,
    load_runtime_identity,
    resolve_runtime,
)


class SyntheticRelocationCrash(BaseException):
    """Deterministic simulated process death at one durable checkpoint."""


@dataclass(frozen=True, slots=True)
class SyntheticDirectoryMover:
    """No-subprocess exact-enough mover for ordinary crash/recovery tests."""

    def create_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
    ) -> DirectoryMoveReference:
        assert os.fstat(source.descriptor).st_ino == source.inode
        assert (
            os.fstat(destination_parent.descriptor).st_ino == destination_parent.inode
        )
        return DirectoryMoveReference(object())

    def move_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
        destination_name: str,
        reference: DirectoryMoveReference,
    ) -> None:
        del reference
        if os.path.lexists(destination_parent.path / destination_name):
            raise InvalidArgumentError("synthetic destination exists")
        os.rename(source.path, destination_parent.path / destination_name)


_SYNTHETIC_MOVER = SyntheticDirectoryMover()
_RELOCATION_ARTIFACTS = (
    ".inbox-relocation.intent.json",
    ".inbox-relocation.intent.tmp",
    ".inbox-relocation.runtime.tmp",
)


def _initialized_external_runtime(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "store"
    source = tmp_path / "old" / "Inbox"
    destination = tmp_path / "new" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    (source / "synthetic-waiting.md").write_bytes(b"synthetic waiting bytes\n")
    return home, source, destination


def _assert_no_relocation_artifacts(home: Path) -> None:
    for name in _RELOCATION_ARTIFACTS:
        path = home / name
        assert not path.exists()
        assert not path.is_symlink()


def _audit_generation(home: Path) -> int:
    from memory.database import open_database
    from memory.keys import load_master_key

    paths = resolve_runtime(home)
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        row = connection.execute(
            "SELECT audit_generation FROM store_meta WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    value = row[0]
    assert isinstance(value, int)
    return value


def test_relocate_external_inbox_preserves_exact_directory_and_store(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "old" / "Inbox"
    destination = tmp_path / "new" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    waiting = source / "synthetic-waiting.md"
    waiting.write_bytes(b"synthetic waiting bytes\n")
    before = source.lstat()
    database_before = (home / "store.sqlite3").read_bytes()
    runtime_before = load_runtime_identity(resolve_runtime(home))
    audit_before = _audit_generation(home)
    keychain_before = dict(synthetic_keychain)

    result = relocate_inbox(resolve_runtime(home), destination)

    assert result.status == "relocated"
    assert not source.exists()
    assert not source.is_symlink()
    moved = destination.lstat()
    assert (moved.st_dev, moved.st_ino) == (before.st_dev, before.st_ino)
    assert (destination / waiting.name).read_bytes() == b"synthetic waiting bytes\n"
    relocated_paths = resolve_runtime(home)
    assert relocated_paths.inbox == destination
    runtime_after = load_runtime_identity(relocated_paths)
    assert runtime_after.store_id == runtime_before.store_id
    assert runtime_after.runtime_mode is runtime_before.runtime_mode
    assert runtime_after.inbox_path == str(destination)
    assert (home / "store.sqlite3").read_bytes() == database_before
    assert _audit_generation(home) == audit_before
    assert synthetic_keychain == keychain_before
    payload = json.loads((home / "runtime.json").read_text(encoding="utf-8"))
    assert payload["inbox_path"] == str(destination)


def test_relocate_exact_current_inbox_is_idempotent(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "external" / "Inbox"
    source.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    source_before = source.lstat()
    identity_before = (home / "runtime.json").read_bytes()

    result = relocate_inbox(resolve_runtime(home), source)

    assert result.status == "current"
    source_after = source.lstat()
    assert (source_after.st_dev, source_after.st_ino) == (
        source_before.st_dev,
        source_before.st_ino,
    )
    assert (home / "runtime.json").read_bytes() == identity_before


def test_relocate_external_inbox_twice_preserves_one_inode(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "first" / "Inbox"
    second = tmp_path / "second" / "Inbox"
    third = tmp_path / "third" / "Inbox"
    for parent in (source.parent, second.parent, third.parent):
        parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    source_identity = source.lstat()

    first_result = relocate_inbox(resolve_runtime(home), second)
    second_result = relocate_inbox(resolve_runtime(home), third)

    assert first_result.status == "relocated"
    assert second_result.status == "relocated"
    assert not source.exists()
    assert not second.exists()
    final_identity = third.lstat()
    assert (final_identity.st_dev, final_identity.st_ino) == (
        source_identity.st_dev,
        source_identity.st_ino,
    )
    assert resolve_runtime(home).inbox == third


def test_relocate_refuses_a_destination_winner_before_reference_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "source" / "Inbox"
    destination = tmp_path / "destination" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    source_before = source.lstat()
    winner_identity: tuple[int, int] | None = None

    def install_winner(name: str) -> None:
        nonlocal winner_identity
        if name == "before_reference_move":
            destination.mkdir(mode=0o700)
            metadata = destination.lstat()
            winner_identity = (metadata.st_dev, metadata.st_ino)

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        install_winner,
    )

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), destination)

    assert winner_identity is not None
    source_after = source.lstat()
    destination_after = destination.lstat()
    assert (source_after.st_dev, source_after.st_ino) == (
        source_before.st_dev,
        source_before.st_ino,
    )
    assert (destination_after.st_dev, destination_after.st_ino) == winner_identity
    assert resolve_runtime(home).inbox == source


def test_relocate_refuses_a_source_replacement_before_reference_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "source" / "Inbox"
    destination = tmp_path / "destination" / "Inbox"
    parked = tmp_path / "parked-original"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    original_identity = source.lstat()
    replacement_identity: tuple[int, int] | None = None

    def replace_source(name: str) -> None:
        nonlocal replacement_identity
        if name == "before_reference_creation":
            os.rename(source, parked)
            source.mkdir(mode=0o700)
            metadata = source.lstat()
            replacement_identity = (metadata.st_dev, metadata.st_ino)

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        replace_source,
    )

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), destination)

    assert replacement_identity is not None
    parked_after = parked.lstat()
    replacement_after = source.lstat()
    assert (parked_after.st_dev, parked_after.st_ino) == (
        original_identity.st_dev,
        original_identity.st_ino,
    )
    assert (replacement_after.st_dev, replacement_after.st_ino) == (
        replacement_identity
    )
    assert not destination.exists()
    assert resolve_runtime(home).inbox == source


def test_relocate_moves_the_exact_reference_after_source_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    source = tmp_path / "source" / "Inbox"
    destination = tmp_path / "destination" / "Inbox"
    parked = tmp_path / "parked-original"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(
        resolve_runtime(home),
        mode=RuntimeMode.PERSONAL,
        inbox=source,
    )
    original_identity = source.lstat()
    replacement_identity: tuple[int, int] | None = None

    def replace_after_reference(name: str) -> None:
        nonlocal replacement_identity
        if name == "after_reference_creation":
            os.rename(source, parked)
            source.mkdir(mode=0o700)
            metadata = source.lstat()
            replacement_identity = (metadata.st_dev, metadata.st_ino)

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        replace_after_reference,
    )

    result = relocate_inbox(resolve_runtime(home), destination)

    assert result.status == "relocated"
    assert replacement_identity is not None
    destination_after = destination.lstat()
    replacement_after = source.lstat()
    assert not parked.exists()
    assert (destination_after.st_dev, destination_after.st_ino) == (
        original_identity.st_dev,
        original_identity.st_ino,
    )
    assert (replacement_after.st_dev, replacement_after.st_ino) == (
        replacement_identity
    )
    assert resolve_runtime(home).inbox == destination


@pytest.mark.parametrize(
    "checkpoint",
    [
        "after_intent_temp_fsync",
        "after_intent_publish",
        "after_intent_root_fsync",
        "after_directory_move",
        "after_source_parent_fsync",
        "after_destination_parent_fsync",
        "after_runtime_temp_fsync",
        "after_runtime_replace",
        "after_runtime_root_fsync",
        "after_intent_unlink",
    ],
)
def test_every_durable_interruption_recovers_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    checkpoint: str,
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    original = source.lstat()

    def interrupt(name: str) -> None:
        if name == checkpoint:
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )
    result = relocate_inbox(
        resolve_runtime(home),
        destination,
        mover=_SYNTHETIC_MOVER,
    )

    assert result.status == (
        "current" if checkpoint == "after_intent_unlink" else "recovered"
    )
    moved = destination.lstat()
    assert (moved.st_dev, moved.st_ino) == (original.st_dev, original.st_ino)
    assert (destination / "synthetic-waiting.md").read_bytes() == (
        b"synthetic waiting bytes\n"
    )
    assert resolve_runtime(home).inbox == destination
    _assert_no_relocation_artifacts(home)


def test_ordinary_runtime_refuses_a_pending_relocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, _source, destination = _initialized_external_runtime(tmp_path)

    def interrupt(name: str) -> None:
        if name == "after_intent_publish":
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    with pytest.raises(InvalidRuntimeError):
        authorize_runtime_use(resolve_runtime(home))


def test_recovery_preserves_a_post_move_source_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    original = source.lstat()
    replacement_identity: tuple[int, int] | None = None

    def replace_and_interrupt(name: str) -> None:
        nonlocal replacement_identity
        if name == "after_directory_move":
            source.mkdir(mode=0o700)
            replacement = source.lstat()
            replacement_identity = (replacement.st_dev, replacement.st_ino)
            raise SyntheticRelocationCrash

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        replace_and_interrupt,
    )
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    result = relocate_inbox(
        resolve_runtime(home),
        destination,
        mover=_SYNTHETIC_MOVER,
    )

    assert result.status == "recovered"
    assert replacement_identity is not None
    replacement = source.lstat()
    moved = destination.lstat()
    assert (replacement.st_dev, replacement.st_ino) == replacement_identity
    assert (moved.st_dev, moved.st_ino) == (original.st_dev, original.st_ino)
    assert resolve_runtime(home).inbox == destination


def test_recovery_refuses_a_replaced_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, _source, destination = _initialized_external_runtime(tmp_path)
    parked = tmp_path / "parked-moved-inbox"

    def replace_and_interrupt(name: str) -> None:
        if name == "after_directory_move":
            os.rename(destination, parked)
            destination.mkdir(mode=0o700)
            raise SyntheticRelocationCrash

    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        replace_and_interrupt,
    )
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    with pytest.raises(InvalidRuntimeError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert parked.is_dir()
    assert destination.is_dir()


def test_recovery_refuses_noncanonical_or_tampered_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)

    def interrupt(name: str) -> None:
        if name == "after_intent_root_fsync":
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    intent = home / ".inbox-relocation.intent.json"
    payload = json.loads(intent.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    intent.write_text(json.dumps(payload), encoding="utf-8")
    intent.chmod(0o600)
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    with pytest.raises(InvalidRuntimeError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert source.is_dir()
    assert not destination.exists()


def test_recovery_refuses_a_different_requested_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    other = tmp_path / "other" / "Inbox"
    other.parent.mkdir(mode=0o700)

    def interrupt(name: str) -> None:
        if name == "after_intent_root_fsync":
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    with pytest.raises(InvalidRuntimeError):
        relocate_inbox(resolve_runtime(home), other, mover=_SYNTHETIC_MOVER)

    assert source.is_dir()
    assert not destination.exists()
    assert not other.exists()


@pytest.mark.parametrize(
    "artifact_name",
    _RELOCATION_ARTIFACTS,
)
def test_ordinary_runtime_refuses_every_relocation_artifact(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    artifact_name: str,
) -> None:
    home, _source, _destination = _initialized_external_runtime(tmp_path)
    artifact = home / artifact_name
    artifact.write_bytes(b"synthetic artifact\n")
    artifact.chmod(0o600)

    with pytest.raises(InvalidRuntimeError):
        authorize_runtime_use(resolve_runtime(home))


@pytest.mark.parametrize(
    "destination_factory",
    [
        lambda tmp_path, home: Path("relative/Inbox"),
        lambda tmp_path, home: tmp_path / "new" / ".." / "new" / "Inbox",
        lambda tmp_path, home: home / "nested" / "Inbox",
        lambda tmp_path, home: home.parent,
    ],
)
def test_relocate_refuses_unsafe_destination_shapes(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    destination_factory: object,
) -> None:
    home, source, _destination = _initialized_external_runtime(tmp_path)
    factory = destination_factory
    assert callable(factory)
    destination = factory(tmp_path, home)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), destination, mover=_SYNTHETIC_MOVER)

    assert source.is_dir()
    _assert_no_relocation_artifacts(home)


def test_relocate_refuses_the_internal_inbox(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    destination = tmp_path / "new" / "Inbox"
    destination.parent.mkdir(mode=0o700)
    initialize_runtime(resolve_runtime(home), mode=RuntimeMode.PERSONAL)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )


def test_relocate_refuses_an_exact_current_internal_inbox(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    initialize_runtime(resolve_runtime(home), mode=RuntimeMode.PERSONAL)
    paths = resolve_runtime(home)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(paths, paths.inbox, mover=_SYNTHETIC_MOVER)


def test_relocate_refuses_an_overlong_destination_name_before_intent(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    overlong = destination.parent / ("x" * 256)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), overlong, mover=_SYNTHETIC_MOVER)

    assert source.is_dir()
    _assert_no_relocation_artifacts(home)


def test_relocate_refuses_a_destination_inside_the_current_inbox(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, _destination = _initialized_external_runtime(tmp_path)
    destination = source / "private-child" / "Inbox"
    destination.parent.mkdir(mode=0o700)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), destination, mover=_SYNTHETIC_MOVER)

    assert source.is_dir()
    assert not destination.exists()
    _assert_no_relocation_artifacts(home)


def test_relocate_refuses_an_intermediate_destination_parent_symlink(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, _destination = _initialized_external_runtime(tmp_path)
    actual_root = tmp_path / "actual-root"
    actual_parent = actual_root / "private-parent"
    actual_root.mkdir(mode=0o700)
    actual_parent.mkdir(mode=0o700)
    alias = tmp_path / "alias-root"
    alias.symlink_to(actual_root, target_is_directory=True)
    destination = alias / actual_parent.name / "Inbox"

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(resolve_runtime(home), destination, mover=_SYNTHETIC_MOVER)

    assert source.is_dir()
    assert not (actual_parent / "Inbox").exists()
    _assert_no_relocation_artifacts(home)


def test_parent_fsync_error_is_typed_and_exact_retry_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    real_fsync = os.fsync
    fail_next_fsync = False

    def arm_failure(name: str) -> None:
        nonlocal fail_next_fsync
        if name == "after_directory_move":
            fail_next_fsync = True

    def synthetic_fsync(descriptor: int) -> None:
        nonlocal fail_next_fsync
        if fail_next_fsync:
            fail_next_fsync = False
            raise OSError("synthetic-private-filesystem-marker")
        real_fsync(descriptor)

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", arm_failure)
    monkeypatch.setattr("memory.inbox_relocation.os.fsync", synthetic_fsync)

    with pytest.raises(InvalidRuntimeError) as raised:
        relocate_inbox(resolve_runtime(home), destination, mover=_SYNTHETIC_MOVER)

    assert "synthetic-private-filesystem-marker" not in str(raised.value)
    assert not source.exists()
    assert destination.is_dir()

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", lambda name: None)
    monkeypatch.setattr("memory.inbox_relocation.os.fsync", real_fsync)
    assert (
        relocate_inbox(
            resolve_runtime(home), destination, mover=_SYNTHETIC_MOVER
        ).status
        == "recovered"
    )
    _assert_no_relocation_artifacts(home)


@pytest.mark.parametrize("private_name", ["inbox-claims", "inbox-staging"])
def test_relocate_refuses_active_private_custody(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    private_name: str,
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    (home / private_name / "synthetic-entry").write_bytes(b"opaque")

    with pytest.raises(StoreBusyError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert source.is_dir()
    assert not destination.exists()
    _assert_no_relocation_artifacts(home)


@pytest.mark.parametrize("entry_kind", ["directory", "file", "symlink"])
def test_relocate_refuses_any_existing_destination_entry(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    entry_kind: str,
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    if entry_kind == "directory":
        destination.mkdir(mode=0o700)
    elif entry_kind == "file":
        destination.write_bytes(b"synthetic winner")
    else:
        destination.symlink_to(tmp_path / "missing")

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert source.is_dir()
    assert os.path.lexists(destination)
    _assert_no_relocation_artifacts(home)


def test_relocate_refuses_loose_source_or_destination_parent_mode(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)
    source.chmod(0o755)

    with pytest.raises(InvalidArgumentError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    source.chmod(0o700)
    destination.parent.chmod(0o755)
    with pytest.raises(InvalidArgumentError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert stat.S_IMODE(source.lstat().st_mode) == 0o700
    _assert_no_relocation_artifacts(home)


def test_stale_pre_relocation_paths_refuse_after_success(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, _source, destination = _initialized_external_runtime(tmp_path)
    stale = resolve_runtime(home)

    relocate_inbox(stale, destination, mover=_SYNTHETIC_MOVER)

    with pytest.raises(InvalidRuntimeError):
        authorize_runtime_use(stale)


def test_recovery_refuses_a_tampered_runtime_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home, _source, destination = _initialized_external_runtime(tmp_path)

    def interrupt(name: str) -> None:
        if name == "after_runtime_temp_fsync":
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    temporary = home / ".inbox-relocation.runtime.tmp"
    temporary.write_bytes(b"{}\n")
    temporary.chmod(0o600)
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    with pytest.raises(InvalidRuntimeError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert destination.is_dir()


@pytest.mark.parametrize("unsafe_kind", ["mode", "symlink"])
def test_recovery_refuses_an_unsafe_persisted_intent_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    unsafe_kind: str,
) -> None:
    home, source, destination = _initialized_external_runtime(tmp_path)

    def interrupt(name: str) -> None:
        if name == "after_intent_root_fsync":
            raise SyntheticRelocationCrash

    monkeypatch.setattr(relocation_module, "_relocation_checkpoint", interrupt)
    with pytest.raises(SyntheticRelocationCrash):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )
    intent = home / ".inbox-relocation.intent.json"
    if unsafe_kind == "mode":
        intent.chmod(0o644)
    else:
        encoded = intent.read_bytes()
        intent.unlink()
        target = home / "synthetic-intent-target"
        target.write_bytes(encoded)
        target.chmod(0o600)
        intent.symlink_to(target)
    monkeypatch.setattr(
        relocation_module,
        "_relocation_checkpoint",
        lambda name: None,
    )

    with pytest.raises(InvalidRuntimeError):
        relocate_inbox(
            resolve_runtime(home),
            destination,
            mover=_SYNTHETIC_MOVER,
        )

    assert source.is_dir()
    assert not destination.exists()
