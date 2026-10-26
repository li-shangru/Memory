"""Durable exact publication and interruption-recovery tests."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import stat
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
import staged_memory_intake.publish as publication
from staged_memory_intake.config import configure
from staged_memory_intake.model import (
    IntakeConfig,
    IntakeError,
    NoPublicationFault,
    ParsedPrepared,
    PublicationFault,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import build_preview, parse_prepared
from staged_memory_intake.publish import (
    publish,
    published_name,
    recover_publication,
)
from staged_memory_intake.securefs import (
    atomic_private_json,
    directory_identity,
    inventory,
)
from staged_memory_intake.state import TransactionStore
from staged_memory_intake_fakes import FakeMemoryPathsRunner


class SyntheticPublicationCrash(RuntimeError):
    """One test-only interruption at an explicitly durable checkpoint."""


class SyntheticBlockingOpen(RuntimeError):
    """Prevent a regression test from entering a real blocking FIFO open."""


@dataclass
class CrashAt:
    """Raise once at one named publication checkpoint."""

    target: str
    observed: list[str]
    crashed: bool = False

    def checkpoint(self, name: str) -> None:
        self.observed.append(name)
        if name == self.target and not self.crashed:
            self.crashed = True
            raise SyntheticPublicationCrash(name)


@dataclass
class InstallHiddenAtPublishing:
    """Install one exact hidden winner after the literal empty preflight."""

    path: Path
    payload: bytes
    installed: bool = False

    def checkpoint(self, name: str) -> None:
        if name != "publishing_receipt" or self.installed:
            return
        self.path.write_bytes(self.payload)
        self.path.chmod(0o600)
        self.installed = True


@dataclass
class ReplaceExactHiddenAt:
    """Replace one exact hidden path at a deterministic lifetime boundary."""

    target: str
    hidden: Path
    displaced: Path
    payload: bytes
    installed: bool = False
    replacement_identity: tuple[int, int] | None = None

    def checkpoint(self, name: str) -> None:
        if name != self.target or self.installed:
            return
        self.hidden.rename(self.displaced)
        self.hidden.write_bytes(self.payload)
        self.hidden.chmod(0o600)
        metadata = self.hidden.stat()
        self.replacement_identity = (metadata.st_dev, metadata.st_ino)
        self.installed = True


@dataclass
class FakeRenameAtX:
    """A narrow fake C symbol that records flags and performs the rename."""

    calls: list[tuple[int, bytes, int, bytes, int]]
    argtypes: object = None
    restype: object = None

    def __call__(
        self,
        source_descriptor: int,
        source_name: bytes,
        destination_descriptor: int,
        destination_name: bytes,
        flags: int,
    ) -> int:
        self.calls.append(
            (
                source_descriptor,
                source_name,
                destination_descriptor,
                destination_name,
                flags,
            )
        )
        os.rename(
            os.fsdecode(source_name),
            os.fsdecode(destination_name),
            src_dir_fd=source_descriptor,
            dst_dir_fd=destination_descriptor,
        )
        return 0


@dataclass(frozen=True)
class FakeCLibrary:
    """One fake process library exposing only ``renameatx_np``."""

    renameatx_np: FakeRenameAtX


@dataclass(frozen=True)
class PublicationSetup:
    """One entirely disposable two-candidate authorized publication."""

    config: IntakeConfig
    store: TransactionStore
    receipt: TransactionReceipt
    runner: FakeMemoryPathsRunner
    prepared_bytes: tuple[bytes, bytes]


@dataclass
class HiddenDescriptorEvents:
    """Track every exact hidden open and close without owning the descriptor."""

    opened: list[tuple[str, int]]
    closed: list[int]


def _prepared_bytes(
    source_name: str,
    source: bytes,
    statement: str,
    *,
    sensitivity: str = "sensitive",
) -> bytes:
    return (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
        "kind: insight\n"
        f"sensitivity: {sensitivity}\n"
        "occurred_on: 2026-08\n"
        "valid_from: \n"
        "valid_to: \n"
        'tags: ["synthetic","publication"]\n'
        "---\n"
        f"{statement}\n"
    ).encode()


def _setup(tmp_path: Path) -> PublicationSetup:
    notes = tmp_path / "synthetic-notes"
    notes.mkdir(mode=0o700)
    for folder in ("01_Pending", "02_Staged", "03_Prepared"):
        (notes / folder).mkdir(mode=0o700)
    home = tmp_path / "synthetic-memory-home"
    inbox = tmp_path / "synthetic-memory-inbox"
    home.mkdir(mode=0o700)
    inbox.mkdir(mode=0o700)
    runner = FakeMemoryPathsRunner(home, inbox)

    first_source = b"Synthetic first staged evidence."
    second_source = b"Synthetic second staged evidence."
    first_prepared = _prepared_bytes(
        "first-source.md",
        first_source,
        "Synthetic first approved statement.",
        sensitivity="normal",
    )
    second_prepared = _prepared_bytes(
        "second-source.md",
        second_source,
        "Synthetic second approved statement.",
    )
    (notes / "02_Staged" / "first-source.md").write_bytes(first_source)
    (notes / "02_Staged" / "second-source.md").write_bytes(second_source)
    (notes / "03_Prepared" / "first.md").write_bytes(first_prepared)
    (notes / "03_Prepared" / "second.md").write_bytes(second_prepared)
    (notes / "03_Prepared" / "unselected.md").write_bytes(
        _prepared_bytes(
            "first-source.md",
            first_source,
            "Synthetic unselected statement.",
        )
    )
    state_root = tmp_path / "synthetic-state"
    config = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=runner,
    )
    store = TransactionStore(state_root)
    preview = build_preview(config, ["first.md", "second.md"], [])
    receipt = store.authorize(preview, preview.manifest_digest)
    return PublicationSetup(
        config=config,
        store=store,
        receipt=receipt,
        runner=runner,
        prepared_bytes=(first_prepared, second_prepared),
    )


@pytest.fixture
def setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> PublicationSetup:
    value = _setup(tmp_path)
    monkeypatch.setattr(publication, "_MEMORY_PATHS_RUNNER", value.runner)
    return value


def _assert_no_publication(setup: PublicationSetup) -> None:
    assert inventory(setup.config.memory_inbox) == ()
    assert setup.store.load(setup.receipt.transaction_id) == setup.receipt


def _assert_published(setup: PublicationSetup, receipt: TransactionReceipt) -> None:
    expected_names = tuple(
        published_name(receipt.transaction_id, value) for value in receipt.candidates
    )
    assert receipt.state is TransactionState.PUBLISHED
    assert (
        tuple(value.inbox_name for value in receipt.published_files) == expected_names
    )
    assert inventory(setup.config.memory_inbox) == tuple(sorted(expected_names))
    for name, expected in zip(expected_names, setup.prepared_bytes, strict=True):
        path = setup.config.memory_inbox / name
        assert path.read_bytes() == expected
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    hidden_names = {
        publication.staged_name(receipt.transaction_id, candidate)
        for candidate in receipt.candidates
    }
    assert hidden_names.isdisjoint(inventory(setup.config.memory_inbox))
    assert (setup.config.notes_root / "03_Prepared" / "first.md").exists()
    assert (setup.config.notes_root / "03_Prepared" / "second.md").exists()
    assert (setup.config.notes_root / "03_Prepared" / "unselected.md").exists()
    assert all("scan" not in argv for argv, _timeout in setup.runner.calls)


def _hidden_name(setup: PublicationSetup, ordinal: int) -> str:
    candidate = setup.receipt.candidates[ordinal]
    return (
        f".staged-memory-intake-{setup.receipt.transaction_id}-"
        f"{candidate.ordinal:02d}-{candidate.prepared_sha256[:12]}.tmp"
    )


def _hidden_path(setup: PublicationSetup, ordinal: int) -> Path:
    return setup.config.memory_inbox / _hidden_name(setup, ordinal)


def _track_hidden_descriptors(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> list[int]:
    hidden_names = {_hidden_name(setup, ordinal) for ordinal in range(2)}
    real_open = os.open
    opened: list[int] = []

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path in hidden_names:
            opened.append(descriptor)
        return descriptor

    monkeypatch.setattr("staged_memory_intake.publish.os.open", tracked_open)
    return opened


def _track_hidden_open_events(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> HiddenDescriptorEvents:
    hidden_names = {_hidden_name(setup, ordinal) for ordinal in range(2)}
    real_open = os.open
    real_close = os.close
    events = HiddenDescriptorEvents([], [])
    hidden_descriptors: set[int] = set()

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if isinstance(path, str) and path in hidden_names:
            events.opened.append((path, descriptor))
            hidden_descriptors.add(descriptor)
        return descriptor

    def tracked_close(descriptor: int) -> None:
        if descriptor in hidden_descriptors:
            events.closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr("staged_memory_intake.publish.os.open", tracked_open)
    monkeypatch.setattr("staged_memory_intake.publish.os.close", tracked_close)
    return events


def _assert_open_events_closed(events: HiddenDescriptorEvents) -> None:
    assert events.opened
    opened_descriptors = [descriptor for _name, descriptor in events.opened]
    assert Counter(events.closed) == Counter(opened_descriptors)
    for descriptor in set(opened_descriptors):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_published_names_are_deterministic_bounded_and_collision_specific(
    setup: PublicationSetup,
) -> None:
    first, second = setup.receipt.candidates

    assert publication.staged_name(setup.receipt.transaction_id, first) == (
        f".staged-memory-intake-{setup.receipt.transaction_id}-"
        f"00-{first.prepared_sha256[:12]}.tmp"
    )
    assert first.prepared_name not in publication.staged_name(
        setup.receipt.transaction_id,
        first,
    )
    assert published_name(setup.receipt.transaction_id, first) == (
        f"{setup.receipt.transaction_id}-00-{first.prepared_sha256[:12]}-first.md"
    )
    assert published_name(setup.receipt.transaction_id, second) == (
        f"{setup.receipt.transaction_id}-01-{second.prepared_sha256[:12]}-second.md"
    )
    with pytest.raises(IntakeError) as caught:
        published_name(
            setup.receipt.transaction_id,
            replace(first, prepared_name=f"{'x' * 240}.md"),
        )
    assert caught.value.code == "published_name_too_long"


def test_published_names_bind_the_full_transaction_id(
    setup: PublicationSetup,
) -> None:
    candidate = setup.receipt.candidates[0]
    first_transaction = "tx_" + "1" * 32
    second_transaction = "tx_" + "2" * 32

    first = published_name(first_transaction, candidate)
    second = published_name(second_transaction, candidate)

    assert first != second
    assert first.startswith(f"{first_transaction}-")
    assert second.startswith(f"{second_transaction}-")
    assert len(first.encode("utf-8")) <= 255


def test_publication_requires_the_exact_active_authorization(
    setup: PublicationSetup,
) -> None:
    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            "tx_00000000000000000000000000000000",
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_not_authorized"
    _assert_no_publication(setup)


def test_memory_cli_failure_during_publication_keeps_its_own_name(
    setup: PublicationSetup,
) -> None:
    """Catch a failing memory CLI being reported as authority drift.

    Memory's own CLI failing to answer -- a missing binary, a timeout,
    stderr noise -- says nothing about directory authority. Re-coding it as
    terminal publication_authority_changed inverted retryability and sent
    the owner to audit directories that never moved, at the one workflow
    stage where the skill treats drift as unrecoverable.
    """
    from collections.abc import Sequence
    from dataclasses import dataclass, field

    from staged_memory_intake.model import CompletedCommand

    @dataclass
    class FailingRunner:
        calls: list[tuple[str, ...]] = field(default_factory=list)

        def run(
            self,
            argv: Sequence[str],
            *,
            timeout_seconds: float,
        ) -> CompletedCommand:
            self.calls.append(tuple(argv))
            return CompletedCommand(1, b"", b"synthetic memory failure\n")

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
            memory_paths_runner=FailingRunner(),
        )

    assert caught.value.code == "memory_paths_failed"
    assert caught.value.category == "memory"
    assert caught.value.retryable is True
    assert inventory(setup.config.memory_inbox) == ()
    assert setup.store.load(setup.receipt.transaction_id) == setup.receipt


@pytest.mark.parametrize(
    "drift", ["notes_path", "notes_identity", "inbox_path", "inbox_identity"]
)
def test_publication_refuses_path_or_identity_drift_before_writing(
    setup: PublicationSetup,
    tmp_path: Path,
    drift: str,
) -> None:
    config = setup.config
    if drift == "notes_path":
        other = tmp_path / "other-notes"
        other.mkdir(mode=0o700)
        config = replace(
            config,
            notes_root=other,
            notes_identity=directory_identity(other),
        )
    elif drift == "notes_identity":
        old = tmp_path / "old-notes"
        config.notes_root.rename(old)
        config.notes_root.mkdir(mode=0o700)
    elif drift == "inbox_path":
        other = tmp_path / "other-inbox"
        other.mkdir(mode=0o700)
        setup.runner.inbox = other
    else:
        old = tmp_path / "old-inbox"
        config.memory_inbox.rename(old)
        config.memory_inbox.mkdir(mode=0o700)

    with pytest.raises(IntakeError) as caught:
        publish(
            config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_authority_changed"
    assert caught.value.category == "drift"
    assert inventory(config.memory_inbox) == ()
    assert setup.store.load(setup.receipt.transaction_id) == setup.receipt


@pytest.mark.parametrize("drift", ["staged", "prepared", "prepared_symlink"])
def test_publication_refuses_selected_file_drift_before_writing(
    setup: PublicationSetup,
    drift: str,
) -> None:
    if drift == "staged":
        (setup.config.notes_root / "02_Staged" / "first-source.md").write_bytes(
            b"Changed synthetic staged evidence."
        )
    else:
        selected = setup.config.notes_root / "03_Prepared" / "first.md"
        if drift == "prepared":
            selected.write_bytes(b"Changed synthetic Prepared artifact.")
        else:
            selected.rename(setup.config.notes_root / "03_Prepared" / "displaced.md")
            selected.symlink_to(setup.config.notes_root / "03_Prepared" / "second.md")

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_drift"
    assert caught.value.category == "drift"
    _assert_no_publication(setup)


def test_publication_reparses_prepared_and_refuses_semantic_drift(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def changed_parse(
        prepared_name: str,
        prepared_bytes: bytes,
        staged_bytes: bytes,
    ) -> ParsedPrepared:
        parsed = parse_prepared(prepared_name, prepared_bytes, staged_bytes)
        return replace(parsed, statement_sha256="f" * 64)

    monkeypatch.setattr(publication, "parse_prepared", changed_parse)
    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_drift"
    assert caught.value.category == "drift"
    _assert_no_publication(setup)


def test_publication_rebuilds_manifest_before_accepting_requested_sensitivity(
    setup: PublicationSetup,
) -> None:
    prepared = setup.config.notes_root / "03_Prepared" / "first.md"
    changed = prepared.read_bytes().replace(
        b"sensitivity: normal\n",
        b"sensitivity: sensitive\n",
    )
    prepared.write_bytes(changed)
    reparsed = parse_prepared(
        "first.md",
        changed,
        (setup.config.notes_root / "02_Staged" / "first-source.md").read_bytes(),
    )
    receipt_path = setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    payload = json.loads(receipt_path.read_bytes())
    prepared_sha256 = hashlib.sha256(changed).hexdigest()
    payload["candidates"][0]["prepared_sha256"] = prepared_sha256
    item_digest = hashlib.sha256(f"0:{prepared_sha256}".encode("ascii")).hexdigest()
    payload["candidates"][0]["client_item_id"] = f"itm_{item_digest[:40]}"
    payload["candidates"][0]["evidence_char_start"] = reparsed.evidence_char_start
    payload["candidates"][0]["evidence_char_end"] = reparsed.evidence_char_end
    atomic_private_json(receipt_path, payload)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_drift"
    assert caught.value.category == "drift"
    assert inventory(setup.config.memory_inbox) == ()
    assert (
        setup.store.load(setup.receipt.transaction_id).state
        is TransactionState.OWNER_AUTHORIZED
    )


@pytest.mark.parametrize("entry_kind", ["visible", "dotfile", "symlink", "directory"])
def test_initial_publication_requires_literal_empty_inbox(
    setup: PublicationSetup,
    entry_kind: str,
) -> None:
    entry = setup.config.memory_inbox / (
        ".synthetic-entry" if entry_kind == "dotfile" else "synthetic-entry"
    )
    if entry_kind in {"visible", "dotfile"}:
        entry.write_bytes(b"Synthetic unrelated bytes.")
    elif entry_kind == "symlink":
        entry.symlink_to(setup.config.notes_root / "03_Prepared" / "first.md")
    else:
        entry.mkdir(mode=0o700)
    before = inventory(setup.config.memory_inbox)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "inbox_not_empty"
    assert inventory(setup.config.memory_inbox) == before
    assert setup.store.load(setup.receipt.transaction_id) == setup.receipt


PUBLICATION_CHECKPOINTS = (
    "publishing_receipt",
    "staged_file_0_fsynced",
    "staging_files_fsynced",
    "visible_file_0_renamed",
    "visible_directory_fsynced",
    "published_receipt",
)


@pytest.mark.parametrize("checkpoint", PUBLICATION_CHECKPOINTS)
def test_every_durable_checkpoint_recovers_one_exact_publication(
    setup: PublicationSetup,
    checkpoint: str,
) -> None:
    fault: PublicationFault = CrashAt(checkpoint, [])

    with pytest.raises(SyntheticPublicationCrash, match=checkpoint):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            fault,
        )

    if checkpoint == "staged_file_0_fsynced":
        hidden = _hidden_path(setup, 0)
        assert hidden.is_file()
        assert stat.S_IMODE(hidden.stat().st_mode) == 0o600
    recovered = recover_publication(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        NoPublicationFault(),
    )

    _assert_published(setup, recovered)
    assert setup.store.active() == recovered


def test_publication_emits_only_the_amended_checkpoints(
    setup: PublicationSetup,
) -> None:
    observed: list[str] = []

    receipt = publish(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        CrashAt("never", observed),
    )

    _assert_published(setup, receipt)
    assert observed == list(PUBLICATION_CHECKPOINTS)


@pytest.mark.parametrize(
    "checkpoint",
    [
        "staged_file_0_fsynced",
        "staging_files_fsynced",
        "visible_file_0_renamed",
        "visible_directory_fsynced",
        "published_receipt",
    ],
)
def test_publication_checkpoint_closes_each_created_descriptor_once(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    opened = _track_hidden_open_events(setup, monkeypatch)

    with pytest.raises(SyntheticPublicationCrash, match=checkpoint):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt(checkpoint, []),
        )

    _assert_open_events_closed(opened)


@pytest.mark.parametrize("entry_kind", ["hidden", "visible"])
def test_recovery_refuses_unrelated_entry_without_moving_anything(
    setup: PublicationSetup,
    entry_kind: str,
) -> None:
    fault = CrashAt("staged_file_0_fsynced", [])
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            fault,
        )
    unrelated = setup.config.memory_inbox / (
        ".synthetic-unrelated" if entry_kind == "hidden" else "synthetic-unrelated"
    )
    unrelated.write_bytes(b"Synthetic unrelated recovery bytes.")
    before = {
        name: (setup.config.memory_inbox / name).lstat()
        for name in inventory(setup.config.memory_inbox)
    }

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert inventory(setup.config.memory_inbox) == tuple(sorted(before))
    for name, metadata in before.items():
        current = (setup.config.memory_inbox / name).lstat()
        assert (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino)
    assert (
        setup.store.load(setup.receipt.transaction_id).state
        is TransactionState.PUBLISHING
    )


@pytest.mark.parametrize("location", ["staged", "visible"])
def test_recovery_refuses_changed_expected_bytes_without_moving_entries(
    setup: PublicationSetup,
    location: str,
) -> None:
    checkpoint = (
        "staged_file_0_fsynced" if location == "staged" else "visible_file_0_renamed"
    )
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt(checkpoint, []),
        )
    first = setup.receipt.candidates[0]
    if location == "staged":
        changed = _hidden_path(setup, 0)
    else:
        changed = setup.config.memory_inbox / published_name(
            setup.receipt.transaction_id,
            first,
        )
    changed.write_bytes(b"Changed synthetic recovery bytes.")
    before = inventory(setup.config.memory_inbox)

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert inventory(setup.config.memory_inbox) == before
    assert changed.read_bytes() == b"Changed synthetic recovery bytes."


def test_recovery_refuses_hidden_wrong_mode_without_moving_entries(
    setup: PublicationSetup,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staged_file_0_fsynced", []),
        )
    hidden = _hidden_path(setup, 0)
    hidden.chmod(0o640)
    before = hidden.lstat()

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    current = hidden.lstat()
    assert (current.st_dev, current.st_ino, current.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


def test_recovery_refuses_one_candidate_in_visible_and_hidden_forms(
    setup: PublicationSetup,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("visible_file_0_renamed", []),
        )
    first_name = published_name(
        setup.receipt.transaction_id,
        setup.receipt.candidates[0],
    )
    visible = setup.config.memory_inbox / first_name
    duplicate = _hidden_path(setup, 0)
    duplicate.write_bytes(visible.read_bytes())
    duplicate.chmod(0o600)
    before = inventory(setup.config.memory_inbox)

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert inventory(setup.config.memory_inbox) == before
    assert visible.exists() and duplicate.exists()


def test_recovery_closes_bound_hidden_file_on_byte_mismatch(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staged_file_0_fsynced", []),
        )
    _hidden_path(setup, 0).write_bytes(b"x" * len(setup.prepared_bytes[0]))
    opened = _track_hidden_descriptors(setup, monkeypatch)

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert opened
    with pytest.raises(OSError):
        os.fstat(opened[-1])


def test_initial_publication_refuses_exclusive_hidden_name_winner(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden_name = _hidden_name(setup, 0)
    hidden_path = _hidden_path(setup, 0)
    payload = setup.prepared_bytes[0]
    real_open = os.open
    winner_identity: list[tuple[int, int]] = []

    def install_winner(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == hidden_name and flags & os.O_CREAT and not winner_identity:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            try:
                assert os.write(descriptor, payload) == len(payload)
                metadata = os.fstat(descriptor)
                winner_identity.append((metadata.st_dev, metadata.st_ino))
            finally:
                os.close(descriptor)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("staged_memory_intake.publish.os.open", install_winner)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert winner_identity
    current = hidden_path.stat()
    assert (current.st_dev, current.st_ino) == winner_identity[0]
    assert hidden_path.read_bytes() == payload
    assert inventory(setup.config.memory_inbox) == (hidden_name,)
    assert (
        setup.store.load(setup.receipt.transaction_id).state
        is TransactionState.PUBLISHING
    )


def test_initial_publication_never_adopts_post_preflight_hidden_winner(
    setup: PublicationSetup,
) -> None:
    hidden = _hidden_path(setup, 0)
    fault = InstallHiddenAtPublishing(hidden, setup.prepared_bytes[0])

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            fault,
        )

    assert caught.value.code == "publication_ambiguous"
    assert fault.installed is True
    assert hidden.read_bytes() == setup.prepared_bytes[0]
    assert inventory(setup.config.memory_inbox) == (_hidden_name(setup, 0),)
    assert (
        setup.store.load(setup.receipt.transaction_id).state
        is TransactionState.PUBLISHING
    )


def test_initial_publication_retains_created_identity_after_file_fsync(
    setup: PublicationSetup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden = _hidden_path(setup, 0)
    displaced = tmp_path / "synthetic-created-hidden.tmp"
    opened = _track_hidden_open_events(setup, monkeypatch)
    real_fsync = publication._fsync
    replacement_identity: list[tuple[int, int]] = []

    def replace_after_file_fsync(descriptor: int, role: str) -> None:
        real_fsync(descriptor, role)
        if role != "staged_file" or replacement_identity:
            return
        hidden.rename(displaced)
        hidden.write_bytes(setup.prepared_bytes[0])
        hidden.chmod(0o600)
        metadata = hidden.stat()
        replacement_identity.append((metadata.st_dev, metadata.st_ino))

    monkeypatch.setattr(publication, "_fsync", replace_after_file_fsync)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert replacement_identity
    replacement = hidden.stat()
    assert (replacement.st_dev, replacement.st_ino) == replacement_identity[0]
    assert hidden.read_bytes() == setup.prepared_bytes[0]
    assert displaced.read_bytes() == setup.prepared_bytes[0]
    assert all(
        not (
            setup.config.memory_inbox
            / published_name(setup.receipt.transaction_id, candidate)
        ).exists()
        for candidate in setup.receipt.candidates
    )
    assert all("scan" not in argv for argv, _timeout in setup.runner.calls)
    assert [name for name, _descriptor in opened.opened] == [_hidden_name(setup, 0)]
    _assert_open_events_closed(opened)


def test_initial_publication_retains_all_created_identities_until_first_rename(
    setup: PublicationSetup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden = _hidden_path(setup, 0)
    displaced = tmp_path / "synthetic-prepared-hidden.tmp"
    fault = ReplaceExactHiddenAt(
        "staging_files_fsynced",
        hidden,
        displaced,
        setup.prepared_bytes[0],
    )
    opened = _track_hidden_open_events(setup, monkeypatch)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            fault,
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert fault.installed is True
    assert fault.replacement_identity is not None
    replacement = hidden.stat()
    assert (replacement.st_dev, replacement.st_ino) == fault.replacement_identity
    assert hidden.read_bytes() == setup.prepared_bytes[0]
    assert displaced.read_bytes() == setup.prepared_bytes[0]
    assert inventory(setup.config.memory_inbox) == tuple(
        sorted(_hidden_name(setup, ordinal) for ordinal in range(2))
    )
    assert all(
        not (
            setup.config.memory_inbox
            / published_name(setup.receipt.transaction_id, candidate)
        ).exists()
        for candidate in setup.receipt.candidates
    )
    assert all("scan" not in argv for argv, _timeout in setup.runner.calls)
    assert [name for name, _descriptor in opened.opened] == [
        _hidden_name(setup, ordinal) for ordinal in range(2)
    ]
    _assert_open_events_closed(opened)


@pytest.mark.parametrize("entry_kind", ["symlink", "directory"])
def test_recovery_refuses_hidden_non_regular_entry_without_mutation(
    setup: PublicationSetup,
    entry_kind: str,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("publishing_receipt", []),
        )
    hidden = _hidden_path(setup, 0)
    if entry_kind == "symlink":
        hidden.symlink_to(setup.config.notes_root / "03_Prepared" / "first.md")
    else:
        hidden.mkdir(mode=0o700)
    before = hidden.lstat()

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    current = hidden.lstat()
    assert (current.st_dev, current.st_ino, current.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )
    assert inventory(setup.config.memory_inbox) == (_hidden_name(setup, 0),)


def test_recovery_refuses_source_identity_drift_between_observation_and_open(
    setup: PublicationSetup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staging_files_fsynced", []),
        )
    hidden_name = _hidden_name(setup, 0)
    hidden = _hidden_path(setup, 0)
    displaced = tmp_path / "synthetic-observed-hidden.tmp"
    real_open = os.open
    replacement_identity: list[tuple[int, int]] = []

    def replace_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == hidden_name and not replacement_identity:
            hidden.rename(displaced)
            hidden.write_bytes(setup.prepared_bytes[0])
            hidden.chmod(0o600)
            metadata = hidden.stat()
            replacement_identity.append((metadata.st_dev, metadata.st_ino))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("staged_memory_intake.publish.os.open", replace_before_open)

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert replacement_identity
    current = hidden.stat()
    assert (current.st_dev, current.st_ino) == replacement_identity[0]
    assert hidden.read_bytes() == setup.prepared_bytes[0]
    assert displaced.read_bytes() == setup.prepared_bytes[0]


def test_recovery_nonblocking_open_refuses_fifo_replacement(
    setup: PublicationSetup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staging_files_fsynced", []),
        )
    hidden_name = _hidden_name(setup, 0)
    hidden = _hidden_path(setup, 0)
    displaced = tmp_path / "synthetic-fifo-displaced-hidden.tmp"
    opened = _track_hidden_open_events(setup, monkeypatch)
    real_open = os.open
    replaced = False

    def replace_with_fifo_before_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == hidden_name and not replaced:
            hidden.rename(displaced)
            os.mkfifo(hidden, mode=0o600)
            replaced = True
            if not flags & os.O_NONBLOCK:
                raise SyntheticBlockingOpen("synthetic FIFO open would block")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(
        "staged_memory_intake.publish.os.open", replace_with_fifo_before_open
    )

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert replaced is True
    assert stat.S_ISFIFO(hidden.lstat().st_mode)
    assert displaced.read_bytes() == setup.prepared_bytes[0]
    assert all(
        not (
            setup.config.memory_inbox
            / published_name(setup.receipt.transaction_id, candidate)
        ).exists()
        for candidate in setup.receipt.candidates
    )
    assert all("scan" not in argv for argv, _timeout in setup.runner.calls)
    _assert_open_events_closed(opened)


def test_recovery_refuses_hidden_source_replacement_immediately_before_rename(
    setup: PublicationSetup,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staging_files_fsynced", []),
        )
    hidden_name = _hidden_name(setup, 0)
    hidden = _hidden_path(setup, 0)
    displaced = tmp_path / "synthetic-displaced-hidden.tmp"
    real_rename = publication._rename_bound_exclusive
    replacement_identity: list[tuple[int, int]] = []
    opened = _track_hidden_open_events(setup, monkeypatch)

    def replace_before_rename(
        source_name: str,
        destination_name: str,
        *,
        inbox_descriptor: int,
        source: publication._BoundHiddenFile,
    ) -> None:
        if source_name == hidden_name and not replacement_identity:
            hidden.rename(displaced)
            hidden.write_bytes(setup.prepared_bytes[0])
            hidden.chmod(0o600)
            metadata = hidden.stat()
            replacement_identity.append((metadata.st_dev, metadata.st_ino))
        real_rename(
            source_name,
            destination_name,
            inbox_descriptor=inbox_descriptor,
            source=source,
        )

    monkeypatch.setattr(publication, "_rename_bound_exclusive", replace_before_rename)

    with pytest.raises(IntakeError) as caught:
        recover_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert str(caught.value) == "publication_ambiguous"
    assert replacement_identity
    current = hidden.stat()
    assert (current.st_dev, current.st_ino) == replacement_identity[0]
    assert hidden.read_bytes() == setup.prepared_bytes[0]
    assert displaced.read_bytes() == setup.prepared_bytes[0]
    assert not (
        setup.config.memory_inbox
        / published_name(
            setup.receipt.transaction_id,
            setup.receipt.candidates[0],
        )
    ).exists()
    _assert_open_events_closed(opened)


def test_recovery_opens_each_hidden_once_and_retains_it_through_rename(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SyntheticPublicationCrash):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            CrashAt("staging_files_fsynced", []),
        )
    opened = _track_hidden_open_events(setup, monkeypatch)
    real_rename = publication._rename_bound_exclusive
    observed_at_rename: list[tuple[str, int, int, int]] = []

    def observe_retained_rename(
        source_name: str,
        destination_name: str,
        *,
        inbox_descriptor: int,
        source: publication._BoundHiddenFile,
    ) -> None:
        metadata = os.fstat(source.descriptor)
        assert (metadata.st_dev, metadata.st_ino, metadata.st_mode) == (
            source.device,
            source.inode,
            source.mode,
        )
        observed_at_rename.append(
            (source_name, source.descriptor, metadata.st_dev, metadata.st_ino)
        )
        real_rename(
            source_name,
            destination_name,
            inbox_descriptor=inbox_descriptor,
            source=source,
        )

    monkeypatch.setattr(publication, "_rename_bound_exclusive", observe_retained_rename)

    recovered = recover_publication(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        NoPublicationFault(),
    )

    _assert_published(setup, recovered)
    assert [name for name, _descriptor in opened.opened] == [
        _hidden_name(setup, ordinal) for ordinal in range(2)
    ]
    assert [name for name, _descriptor, _device, _inode in observed_at_rename] == [
        _hidden_name(setup, ordinal) for ordinal in range(2)
    ]
    assert [descriptor for _name, descriptor in opened.opened] == [
        descriptor for _name, descriptor, _device, _inode in observed_at_rename
    ]
    _assert_open_events_closed(opened)


def test_publication_refuses_visible_target_race_without_clobber(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = setup.receipt.candidates[0]
    visible = setup.config.memory_inbox / published_name(
        setup.receipt.transaction_id,
        first,
    )
    real_rename = publication._rename_bound_exclusive
    winner = b"Synthetic visible race winner."
    opened = _track_hidden_open_events(setup, monkeypatch)

    def install_visible_winner(
        source_name: str,
        destination_name: str,
        *,
        inbox_descriptor: int,
        source: publication._BoundHiddenFile,
    ) -> None:
        if not visible.exists():
            visible.write_bytes(winner)
            visible.chmod(0o600)
        real_rename(
            source_name,
            destination_name,
            inbox_descriptor=inbox_descriptor,
            source=source,
        )

    monkeypatch.setattr(publication, "_rename_bound_exclusive", install_visible_winner)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert visible.read_bytes() == winner
    assert _hidden_path(setup, 0).read_bytes() == setup.prepared_bytes[0]
    _assert_open_events_closed(opened)


def test_publication_refuses_unavailable_exclusive_rename_and_preserves_hidden(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = _track_hidden_open_events(setup, monkeypatch)

    def unavailable(
        source_name: str,
        destination_name: str,
        *,
        directory_descriptor: int,
    ) -> None:
        del source_name, destination_name, directory_descriptor
        raise OSError(errno.ENOTSUP, "synthetic unavailable primitive")

    monkeypatch.setattr(publication, "_rename_no_replace", unavailable)

    with pytest.raises(IntakeError) as caught:
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert caught.value.code == "publication_ambiguous"
    assert _hidden_path(setup, 0).read_bytes() == setup.prepared_bytes[0]
    assert not (
        setup.config.memory_inbox
        / published_name(
            setup.receipt.transaction_id,
            setup.receipt.candidates[0],
        )
    ).exists()
    _assert_open_events_closed(opened)


def test_visible_publication_passes_rename_excl_to_macos_primitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / ".synthetic-hidden.tmp"
    destination = tmp_path / "synthetic-visible.md"
    source.write_bytes(b"Synthetic exclusive rename bytes.")
    symbol = FakeRenameAtX([])

    def fake_cdll(name: str | None, *, use_errno: bool) -> FakeCLibrary:
        assert name is None
        assert use_errno is True
        return FakeCLibrary(symbol)

    monkeypatch.setattr(ctypes, "CDLL", fake_cdll)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        publication._rename_no_replace(
            source.name,
            destination.name,
            directory_descriptor=descriptor,
        )
    finally:
        os.close(descriptor)

    assert destination.read_bytes() == b"Synthetic exclusive rename bytes."
    assert not source.exists()
    assert len(symbol.calls) == 1
    assert symbol.calls[0][-1] == 0x00000004


def test_initial_hidden_creation_is_exclusive_no_follow_and_descriptor_relative(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden_names = {_hidden_name(setup, ordinal) for ordinal in range(2)}
    real_open = os.open
    observed: list[tuple[str, int, int, int | None]] = []

    def observed_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if isinstance(path, str) and path in hidden_names and flags & os.O_CREAT:
            observed.append((path, flags, mode, dir_fd))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("staged_memory_intake.publish.os.open", observed_open)

    receipt = publish(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        NoPublicationFault(),
    )

    _assert_published(setup, receipt)
    assert [item[0] for item in observed] == sorted(hidden_names)
    for _name, flags, mode, dir_fd in observed:
        assert flags & os.O_WRONLY
        assert flags & os.O_CREAT
        assert flags & os.O_EXCL
        assert flags & os.O_NOFOLLOW
        assert not flags & os.O_TRUNC
        assert mode == 0o600
        assert dir_fd is not None


def test_publication_performs_every_required_durability_fsync(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []
    real_fsync = publication._fsync

    def observed_fsync(descriptor: int, role: str) -> None:
        observed.append(role)
        real_fsync(descriptor, role)

    monkeypatch.setattr(publication, "_fsync", observed_fsync)
    receipt = publish(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        NoPublicationFault(),
    )

    _assert_published(setup, receipt)
    assert observed == [
        "staged_file",
        "staged_file",
        "inbox_staging",
        "inbox_visible",
        "inbox_visible",
    ]


def test_publication_fsync_seam_calls_the_operating_system(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[int] = []
    monkeypatch.setattr("staged_memory_intake.publish.os.fsync", observed.append)

    publication._fsync(17, "synthetic_role")

    assert observed == [17]


def test_failed_hidden_file_fsync_closes_the_open_descriptor(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden_name = _hidden_name(setup, 0)
    real_open = os.open
    opened_hidden: list[int] = []

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == hidden_name:
            opened_hidden.append(descriptor)
        return descriptor

    def fail_hidden_fsync(descriptor: int, role: str) -> None:
        del descriptor
        if role == "staged_file":
            raise OSError("synthetic hidden fsync failure")

    monkeypatch.setattr("staged_memory_intake.publish.os.open", tracked_open)
    monkeypatch.setattr(publication, "_fsync", fail_hidden_fsync)

    with pytest.raises(OSError, match="synthetic hidden fsync failure"):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert len(opened_hidden) == 1
    with pytest.raises(OSError):
        os.fstat(opened_hidden[0])


def test_late_inbox_identity_failure_closes_the_open_descriptor(
    setup: PublicationSetup,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open = os.open
    opened_inbox: list[int] = []

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == setup.config.memory_inbox:
            opened_inbox.append(descriptor)
        return descriptor

    def fail_identity(descriptor: int, receipt: TransactionReceipt) -> None:
        del descriptor, receipt
        raise IntakeError("synthetic_late_identity_drift", "drift")

    monkeypatch.setattr("staged_memory_intake.publish.os.open", tracked_open)
    monkeypatch.setattr(publication, "_require_directory_identity", fail_identity)

    with pytest.raises(IntakeError, match="synthetic_late_identity_drift"):
        publish(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            NoPublicationFault(),
        )

    assert opened_inbox
    with pytest.raises(OSError):
        os.fstat(opened_inbox[-1])
