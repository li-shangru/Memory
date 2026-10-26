"""Verified-only recoverable cleanup tests with synthetic filesystem roots."""

from __future__ import annotations

import ast
import errno
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, cast

import pytest
import staged_memory_intake.cleanup as cleanup_module
from staged_memory_intake.cleanup import (
    CREATE_FILE_REFERENCE_SCRIPT,
    TRASH_FILE_REFERENCE_SCRIPT,
    MacOSTrash,
    TrashReference,
    TrashSource,
    cleanup,
    reconcile_cleanup,
)
from staged_memory_intake.config import configure
from staged_memory_intake.model import (
    STATE_ORDER,
    CommandRunner,
    CompletedCommand,
    IntakeConfig,
    IntakeError,
    PublishedFile,
    SourceBinding,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import build_preview
from staged_memory_intake.state import TransactionStore
from staged_memory_intake_fakes import FakeMemoryPathsRunner, FakeTrash

_REVIEW_DIGEST = "a" * 64
_CLEANUP_ENTRY_COUNT = 5


class SyntheticInterruption(RuntimeError):
    """Test-only process interruption at one cleanup durability boundary."""


@dataclass(frozen=True)
class CleanupSetup:
    config: IntakeConfig
    store: TransactionStore
    receipt: TransactionReceipt
    prepared_paths: tuple[Path, ...]
    staged_paths: tuple[Path, ...]
    unselected_paths: tuple[Path, ...]
    trash: FakeTrash

    @property
    def ordered_paths(self) -> tuple[Path, ...]:
        return (*self.prepared_paths, *self.staged_paths)


@dataclass
class TwoStageOnlyTrash:
    """Expose only the new reference protocol, never the legacy move shortcut."""

    inner: FakeTrash

    def create_reference(self, source: TrashSource) -> TrashReference:
        return self.inner.create_reference(source)

    def trash_reference(
        self,
        source: TrashSource,
        reference: TrashReference,
    ) -> None:
        self.inner.trash_reference(source, reference)


@dataclass
class RecordingRunner(CommandRunner):
    """Record one argument-array command without invoking a process."""

    results: tuple[CompletedCommand, ...]
    failure_at: int | None = None
    failure: OSError | subprocess.SubprocessError | None = None
    calls: list[tuple[tuple[str, ...], float]] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        assert self.calls is not None
        self.calls.append((tuple(argv), timeout_seconds))
        call = len(self.calls) - 1
        if self.failure_at == call:
            raise self.failure or OSError("synthetic failure")
        if call >= len(self.results):
            raise AssertionError("unexpected synthetic command")
        return self.results[call]


@contextmanager
def _trash_source(path: Path) -> Iterator[TrashSource]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        yield TrashSource(
            path=path,
            descriptor=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
        )
    finally:
        os.close(descriptor)


def _reference_result(
    source: TrashSource,
    *,
    reference: str = "file:///.file/id=synthetic-reference",
    device: int | None = None,
    inode: int | None = None,
    mode: int | None = None,
) -> CompletedCommand:
    return CompletedCommand(
        0,
        json.dumps(
            {
                "device": str(source.device if device is None else device),
                "inode": str(source.inode if inode is None else inode),
                "mode": str(stat.S_IMODE(source.mode) if mode is None else mode),
                "reference": reference,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        b"",
    )


def _prepared_bytes(
    source_name: str,
    source: bytes,
    statement: str,
) -> bytes:
    return (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
        "kind: fact\n"
        "sensitivity: sensitive\n"
        "occurred_on: 2026-08\n"
        "valid_from: \n"
        "valid_to: \n"
        'tags: ["synthetic","cleanup"]\n'
        "---\n"
        f"{statement}\n"
    ).encode()


def _advance_to(
    store: TransactionStore,
    authorized: TransactionReceipt,
    target: TransactionState,
    *,
    memory_ids: tuple[str, ...] | None,
) -> TransactionReceipt:
    if target is TransactionState.OWNER_AUTHORIZED:
        return authorized
    current = store.advance(authorized, TransactionState.PUBLISHING)
    if target is TransactionState.PUBLISHING:
        return current
    published_files = tuple(
        PublishedFile(
            ordinal=candidate.ordinal,
            prepared_name=candidate.prepared_name,
            inbox_name=f"synthetic-inbox-{candidate.ordinal}.md",
            sha256=candidate.prepared_sha256,
            byte_length=(
                Path(authorized.notes_root) / "03_Prepared" / candidate.prepared_name
            )
            .stat()
            .st_size,
        )
        for candidate in authorized.candidates
    )
    current = store.advance(
        current,
        TransactionState.PUBLISHED,
        published_files=published_files,
    )
    if target is TransactionState.PUBLISHED:
        return current
    current = store.advance(
        current,
        TransactionState.PUBLISHED,
        scan_started=True,
    )
    source_bindings = tuple(
        SourceBinding(
            ordinal=candidate.ordinal,
            inbox_name=published_files[candidate.ordinal].inbox_name,
            source_id=f"src_synthetic_{candidate.ordinal}",
            blob_digest=candidate.prepared_sha256,
        )
        for candidate in authorized.candidates
    )
    current = store.advance(
        current,
        TransactionState.CAPTURED,
        batch_id="bat_synthetic_cleanup",
        scan_source_ids=tuple(value.source_id for value in source_bindings),
        scan_issues=(),
        scan_has_more=False,
        scan_page_has_more=False,
        source_bindings=source_bindings,
        duplicate_notices=(),
    )
    if target is TransactionState.CAPTURED:
        return current
    current = store.advance(
        current,
        TransactionState.REVIEW_READY,
        change_set_id="chg_synthetic_cleanup",
        revision_id="rev_synthetic_cleanup",
        review_digest=_REVIEW_DIGEST,
    )
    if target is TransactionState.REVIEW_READY:
        return current
    current = store.advance(current, TransactionState.AWAITING_MEMORY_APPROVAL)
    if target is TransactionState.AWAITING_MEMORY_APPROVAL:
        return current
    exact_memory_ids = memory_ids or tuple(
        f"mem_synthetic_{candidate.ordinal}" for candidate in authorized.candidates
    )
    current = store.advance(
        current,
        TransactionState.APPLIED,
        application_id="app_synthetic_cleanup",
        memory_ids=exact_memory_ids,
        standing_guard_violations=(),
    )
    if target is TransactionState.APPLIED:
        return current
    if target is not TransactionState.VERIFIED:
        raise AssertionError("unsupported synthetic target state")
    return store.advance(current, TransactionState.VERIFIED)


def _setup(
    tmp_path: Path,
    *,
    state: TransactionState = TransactionState.VERIFIED,
    memory_ids: tuple[str, ...] | None = None,
) -> CleanupSetup:
    notes = tmp_path / "synthetic-notes"
    home = tmp_path / "synthetic-memory-home"
    inbox = tmp_path / "synthetic-memory-inbox"
    for path in (notes, home, inbox):
        path.mkdir(mode=0o700)
    for folder in ("01_Pending", "02_Staged", "03_Prepared"):
        (notes / folder).mkdir(mode=0o700)

    shared_source = b"Synthetic shared staged source for two exact candidates."
    solo_source = "Synthetic distinct staged source with Unicode 界.".encode()
    unselected_source = b"Synthetic unselected staged source."
    source_values = {
        "shared-source.md": shared_source,
        "solo-source.md": solo_source,
        "unselected-source.md": unselected_source,
    }
    for name, value in source_values.items():
        (notes / "02_Staged" / name).write_bytes(value)

    prepared_values = {
        "alpha.md": _prepared_bytes(
            "shared-source.md",
            shared_source,
            "Synthetic exact statement alpha.",
        ),
        "beta.md": _prepared_bytes(
            "shared-source.md",
            shared_source,
            "Synthetic exact statement beta.",
        ),
        "gamma.md": _prepared_bytes(
            "solo-source.md",
            solo_source,
            "Synthetic exact statement gamma with Unicode 界.",
        ),
        "unselected.md": _prepared_bytes(
            "unselected-source.md",
            unselected_source,
            "Synthetic unselected Prepared statement.",
        ),
    }
    for name, value in prepared_values.items():
        (notes / "03_Prepared" / name).write_bytes(value)

    state_root = tmp_path / "synthetic-state"
    config = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=FakeMemoryPathsRunner(home, inbox),
    )
    preview = build_preview(config, ["alpha.md", "beta.md", "gamma.md"], [])
    store = TransactionStore(state_root)
    authorized = store.authorize(preview, preview.manifest_digest)
    receipt = _advance_to(
        store,
        authorized,
        state,
        memory_ids=memory_ids,
    )
    destination = tmp_path / "synthetic-trash"
    destination.mkdir(mode=0o700)
    return CleanupSetup(
        config=config,
        store=store,
        receipt=receipt,
        prepared_paths=tuple(
            notes / "03_Prepared" / name for name in ("alpha.md", "beta.md", "gamma.md")
        ),
        staged_paths=tuple(
            notes / "02_Staged" / name
            for name in ("shared-source.md", "solo-source.md")
        ),
        unselected_paths=(
            notes / "03_Prepared" / "unselected.md",
            notes / "02_Staged" / "unselected-source.md",
        ),
        trash=FakeTrash(destination),
    )


def _error(
    operation: Callable[[], object],
    code: str,
    *,
    ordinal: int | None = None,
) -> IntakeError:
    with pytest.raises(IntakeError) as caught:
        operation()
    assert caught.value.code == code
    assert caught.value.ordinal == ordinal
    return caught.value


_PRE_VERIFIED_STATES = tuple(
    state
    for state in STATE_ORDER
    if STATE_ORDER.index(state) < STATE_ORDER.index(TransactionState.VERIFIED)
)


@pytest.mark.parametrize("state", _PRE_VERIFIED_STATES)
def test_cleanup_never_calls_trash_before_complete_memory_verification(
    tmp_path: Path,
    state: TransactionState,
) -> None:
    setup = _setup(tmp_path, state=state)

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_not_verified",
    )

    assert setup.trash.attempts == []
    assert all(path.exists() for path in setup.ordered_paths)


def test_verified_label_without_every_shared_source_candidate_is_not_authority(
    tmp_path: Path,
) -> None:
    setup = _setup(
        tmp_path,
        memory_ids=("mem_synthetic_0", "mem_synthetic_2"),
    )

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_not_verified",
    )

    assert setup.trash.attempts == []
    assert setup.staged_paths[0].exists()


@pytest.mark.parametrize("mutation", ["missing", "changed", "symlink"])
def test_every_remaining_file_is_preflighted_before_the_first_trash_call(
    tmp_path: Path,
    mutation: Literal["missing", "changed", "symlink"],
) -> None:
    setup = _setup(tmp_path)
    target = setup.staged_paths[-1]
    if mutation == "missing":
        target.unlink()
    elif mutation == "changed":
        target.write_bytes(b"Synthetic changed replacement.")
    else:
        target.unlink()
        target.symlink_to(setup.unselected_paths[-1])

    error = _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=4,
    )

    assert str(error) == "cleanup_drift"
    assert setup.trash.attempts == []
    assert all(path.exists() for path in setup.ordered_paths[:-1])
    current = setup.store.load(setup.receipt.transaction_id)
    assert current.state is TransactionState.CLEANUP_PENDING
    assert current.cleanup_entries[4].failure == "cleanup_drift"


def test_pre_intent_cleanup_drift_reconciles_only_as_preserved(
    tmp_path: Path,
) -> None:
    """Catch permanent cleanup_drift wedging the whole helper.

    The applied memories are safe in the Store; only a staged original's
    bytes changed after verification -- an editor auto-save, a sync pass,
    the owner tidying a note whose content is already captured. Refusing
    every reconciliation for that state left the receipt permanently in
    CLEANUP_PENDING and the helper blocked behind transaction_active, with
    manual state-root surgery the only exit. `preserved` is the honest
    owner resolution: nothing was moved, the changed bytes stay. `moved`
    still refuses -- it would claim bytes reached the Trash that never did.
    """
    setup = _setup(tmp_path)
    setup.staged_paths[-1].write_bytes(b"Synthetic changed replacement.")
    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=4,
    )

    _error(
        lambda: reconcile_cleanup(
            setup.store,
            setup.receipt.transaction_id,
            4,
            "moved",
        ),
        "cleanup_reconciliation_not_required",
        ordinal=4,
    )

    reconciled = reconcile_cleanup(
        setup.store,
        setup.receipt.transaction_id,
        4,
        "preserved",
    )
    assert reconciled.cleanup_entries[4].outcome == "preserved"

    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert complete.cleanup_entries[4].outcome == "preserved"
    assert setup.staged_paths[-1].read_bytes() == b"Synthetic changed replacement."
    assert setup.staged_paths[-1] not in setup.trash.moves
    assert setup.store.active() is None


def test_cleanup_moves_prepared_then_deduplicated_staged_and_nothing_else(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)

    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert setup.trash.moves == list(setup.ordered_paths)
    assert setup.trash.moves.count(setup.staged_paths[0]) == 1
    assert all(not path.exists() for path in setup.ordered_paths)
    assert all(path.exists() for path in setup.unselected_paths)
    assert all(entry.outcome == "moved" for entry in complete.cleanup_entries)
    assert setup.store.active() is None

    payload = json.loads(
        (setup.store.state_root / f"{complete.transaction_id}.json").read_bytes()
    )
    entries = cast(list[dict[str, object]], payload["cleanup_entries"])
    assert len(entries) == _CLEANUP_ENTRY_COUNT
    assert set(entries[0]) == {
        "content_sha256",
        "failure",
        "intent_recorded",
        "name_sha256",
        "outcome",
        "role",
    }
    expected_name_hash = hmac.new(
        bytes.fromhex(complete.manifest_digest),
        b"prepared\0alpha.md",
        hashlib.sha256,
    ).hexdigest()
    assert entries[0]["name_sha256"] == expected_name_hash
    assert entries[0]["name_sha256"] != hashlib.sha256(b"alpha.md").hexdigest()
    for entry in entries:
        encoded = json.dumps(entry, sort_keys=True)
        assert "alpha.md" not in encoded
        assert "shared-source.md" not in encoded
        assert str(setup.config.notes_root) not in encoded


def test_complete_cleanup_and_exact_reconciliation_are_idempotent(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert (
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
        == complete
    )
    assert (
        reconcile_cleanup(
            setup.store,
            complete.transaction_id,
            4,
            "moved",
        )
        == complete
    )
    assert len(setup.trash.attempts) == _CLEANUP_ENTRY_COUNT


def test_receipt_only_complete_replay_needs_no_config_or_trash(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )
    moved_notes = tmp_path / "synthetic-relocated-notes"
    setup.config.notes_root.rename(moved_notes)
    before = (
        tuple(setup.trash.attempts),
        tuple(setup.trash.moves),
        tuple(setup.trash.descriptors),
        tuple(setup.trash.reference_descriptors),
    )

    replayed = cleanup_module.replay_complete_cleanup(
        setup.store,
        complete.transaction_id,
    )

    assert replayed == complete
    assert (
        tuple(setup.trash.attempts),
        tuple(setup.trash.moves),
        tuple(setup.trash.descriptors),
        tuple(setup.trash.reference_descriptors),
    ) == before


def test_complete_receipt_precedes_active_pointer_clear_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    real_unlink = os.unlink

    def interrupt_active_pointer(
        path: str | bytes,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if path == "active.json":
            raise OSError("synthetic active-pointer interruption")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", interrupt_active_pointer)
    with pytest.raises(OSError, match="synthetic active-pointer interruption"):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )

    complete = setup.store.load(setup.receipt.transaction_id)
    assert complete.state is TransactionState.COMPLETE
    assert all(entry.outcome == "moved" for entry in complete.cleanup_entries)
    assert (setup.store.state_root / "active.json").exists()

    monkeypatch.setattr(os, "unlink", real_unlink)
    assert setup.store.active() is None
    assert not (setup.store.state_root / "active.json").exists()


def test_intent_is_durable_before_each_trash_adapter_call(tmp_path: Path) -> None:
    setup = _setup(tmp_path)

    def observe(source: TrashSource) -> None:
        ordinal = setup.ordered_paths.index(source.path)
        current = setup.store.load(setup.receipt.transaction_id)
        entry = current.cleanup_entries[ordinal]
        assert current.state is TransactionState.CLEANUP_PENDING
        assert entry.intent_recorded is True
        assert entry.outcome is None
        metadata = os.fstat(source.descriptor)
        assert (metadata.st_dev, metadata.st_ino, metadata.st_mode) == (
            source.device,
            source.inode,
            source.mode,
        )

    setup.trash.observer = observe

    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert len(setup.trash.moves) == _CLEANUP_ENTRY_COUNT


def test_swap_after_complete_preflight_preserves_replacement_and_records_failure(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    original = setup.prepared_paths[0]
    parked_original = tmp_path / "synthetic-parked-original"
    replacement_bytes = b"Synthetic replacement after complete preflight."

    def swap(source: TrashSource) -> None:
        if source.path != original:
            return
        original.rename(parked_original)
        original.write_bytes(replacement_bytes)

    setup.trash.observer = swap

    error = _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_ambiguous",
        ordinal=0,
    )

    assert str(original) not in str(error)
    assert original.read_bytes() == replacement_bytes
    assert parked_original.exists()
    assert setup.trash.moves == []
    failed = setup.store.load(setup.receipt.transaction_id)
    assert failed.cleanup_entries[0].intent_recorded is True
    assert failed.cleanup_entries[0].failure == "cleanup_ambiguous"
    assert failed.cleanup_entries[0].outcome is None
    for descriptor in setup.trash.descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF


def test_swap_before_cleanup_parent_binding_is_pre_intent_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    original = setup.prepared_paths[0]
    parked_original = tmp_path / "synthetic-parked-original"
    replacement = b"Synthetic replacement before parent binding."
    real_open_all = cleanup_module._open_all_remaining

    def open_then_swap(
        store: TransactionStore,
        receipt: TransactionReceipt,
        targets: tuple[cleanup_module._CleanupTarget, ...],
    ) -> tuple[cleanup_module._OpenedTarget | None, ...]:
        opened = real_open_all(store, receipt, targets)
        original.rename(parked_original)
        original.write_bytes(replacement)
        return opened

    monkeypatch.setattr(cleanup_module, "_open_all_remaining", open_then_swap)

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=0,
    )

    assert original.read_bytes() == replacement
    assert parked_original.exists()
    assert setup.trash.attempts == []
    failed = setup.store.load(setup.receipt.transaction_id)
    assert failed.cleanup_entries[0].intent_recorded is False
    assert failed.cleanup_entries[0].failure == "cleanup_drift"


def test_same_inode_drift_in_later_file_during_first_trash_action_stops_before_it(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    first = setup.prepared_paths[0]
    later = setup.prepared_paths[1]
    later_inode = later.stat().st_ino
    changed = b"Synthetic same-inode drift created during an earlier Trash action."

    def mutate_later(source: TrashSource) -> None:
        if source.path == first:
            later.write_bytes(changed)

    setup.trash.observer = mutate_later

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=1,
    )

    assert later.stat().st_ino == later_inode
    assert later.read_bytes() == changed
    assert later not in setup.trash.moves
    assert setup.trash.attempts == [first]
    assert len(setup.trash.reference_descriptors) == 1
    blocked = setup.store.load(setup.receipt.transaction_id)
    assert blocked.cleanup_entries[1].intent_recorded is False
    assert blocked.cleanup_entries[1].failure == "cleanup_drift"


@pytest.mark.parametrize("mutation_point", ["before_reference", "after_reference"])
def test_same_inode_drift_around_reference_creation_stops_and_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_point: Literal["before_reference", "after_reference"],
) -> None:
    setup = _setup(tmp_path)
    retained: list[int] = []
    close_counts: dict[int, int] = {}
    target = setup.prepared_paths[0]
    target_inode = target.stat().st_ino
    changed = f"Synthetic {mutation_point} same-inode drift.".encode()
    real_open_all = cleanup_module._open_all_remaining
    real_close = os.close

    def capture_opened(
        store: TransactionStore,
        receipt: TransactionReceipt,
        targets: tuple[cleanup_module._CleanupTarget, ...],
    ) -> tuple[cleanup_module._OpenedTarget | None, ...]:
        opened = real_open_all(store, receipt, targets)
        retained.extend(value.descriptor for value in opened if value is not None)
        return opened

    def tracked_close(descriptor: int) -> None:
        if descriptor in retained:
            close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
        real_close(descriptor)

    def mutate(_source: TrashSource) -> None:
        target.write_bytes(changed)

    def mutate_after(_source: TrashSource) -> Path | None:
        target.write_bytes(changed)
        return None

    monkeypatch.setattr(cleanup_module, "_open_all_remaining", capture_opened)
    monkeypatch.setattr(os, "close", tracked_close)
    if mutation_point == "before_reference":
        setup.trash.before_reference = mutate
    else:
        setup.trash.after_reference = mutate_after

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=0,
    )

    assert target.stat().st_ino == target_inode
    assert target.read_bytes() == changed
    assert setup.trash.attempts == []
    assert len(retained) == _CLEANUP_ENTRY_COUNT
    assert close_counts == dict.fromkeys(retained, 1)
    for descriptor in retained:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF


def test_same_inode_drift_after_intent_stops_before_reference_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    target = setup.prepared_paths[0]
    target_inode = target.stat().st_ino
    changed = b"Synthetic same-inode drift after durable cleanup intent."

    def mutate_after_intent(name: str, ordinal: int) -> None:
        if name == "after_intent" and ordinal == 0:
            target.write_bytes(changed)

    monkeypatch.setattr(cleanup_module, "_checkpoint", mutate_after_intent)

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_ambiguous",
        ordinal=0,
    )

    assert target.stat().st_ino == target_inode
    assert target.read_bytes() == changed
    assert setup.trash.attempts == []
    blocked = setup.store.load(setup.receipt.transaction_id)
    assert blocked.cleanup_entries[0].intent_recorded is True
    assert blocked.cleanup_entries[0].failure == "cleanup_ambiguous"


def test_path_replacement_after_reference_preserves_replacement_and_trashes_referent(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    original = setup.prepared_paths[0]
    parked_original = tmp_path / "synthetic-reference-bound-original"
    replacement = b"Synthetic replacement after exact reference creation."

    def replace_path(source: TrashSource) -> Path | None:
        if source.path != original:
            return None
        original.rename(parked_original)
        original.write_bytes(replacement)
        return parked_original

    setup.trash.after_reference = replace_path

    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        TwoStageOnlyTrash(setup.trash),
    )

    assert complete.state is TransactionState.COMPLETE
    assert original.read_bytes() == replacement
    assert not parked_original.exists()
    assert setup.trash.moves == list(setup.ordered_paths)


def test_all_remaining_preflight_descriptors_stay_open_through_first_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    target_names = {path.name for path in setup.ordered_paths}
    target_inodes = {path.stat().st_ino for path in setup.ordered_paths}
    active_opened: set[int] = set()
    retained: list[int] = []
    closed_descriptors: list[int] = []
    real_open = os.open
    real_close = os.close

    def tracked_open(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path) in target_names:
            metadata = os.fstat(descriptor)
            if metadata.st_ino in target_inodes:
                active_opened.add(descriptor)
        return descriptor

    def tracked_close(descriptor: int) -> None:
        if descriptor in active_opened:
            active_opened.remove(descriptor)
            closed_descriptors.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "close", tracked_close)

    def observe(_source: TrashSource) -> None:
        if not retained:
            retained.extend(sorted(active_opened))
        assert len(retained) == _CLEANUP_ENTRY_COUNT
        for descriptor in retained:
            os.fstat(descriptor)

    setup.trash.observer = observe

    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert len(retained) == _CLEANUP_ENTRY_COUNT
    assert sorted(closed_descriptors[-_CLEANUP_ENTRY_COUNT:]) == retained
    for descriptor in retained:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF


def test_retained_descriptors_close_once_when_interrupted_before_first_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    retained: list[int] = []
    real_open_all = cleanup_module._open_all_remaining

    def observe_opened(
        store: TransactionStore,
        receipt: TransactionReceipt,
        targets: tuple[cleanup_module._CleanupTarget, ...],
    ) -> tuple[cleanup_module._OpenedTarget | None, ...]:
        opened = real_open_all(store, receipt, targets)
        retained.extend(value.descriptor for value in opened if value is not None)
        return opened

    def interrupt(name: str, ordinal: int) -> None:
        if name == "before_move" and ordinal == 0:
            raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_open_all_remaining", observe_opened)
    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt)

    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )

    assert len(retained) == _CLEANUP_ENTRY_COUNT
    for descriptor in retained:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF
    assert setup.trash.attempts == []


def test_descriptor_opened_before_preflight_interruption_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    interrupted_descriptor: int | None = None
    real_hash_descriptor = cleanup_module._hash_descriptor

    def interrupt_hash(descriptor: int, *, limit: int) -> str:
        nonlocal interrupted_descriptor
        interrupted_descriptor = descriptor
        del limit
        raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_hash_descriptor", interrupt_hash)

    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )

    monkeypatch.setattr(cleanup_module, "_hash_descriptor", real_hash_descriptor)
    assert interrupted_descriptor is not None
    with pytest.raises(OSError) as caught:
        os.fstat(interrupted_descriptor)
    assert caught.value.errno == errno.EBADF
    assert setup.trash.attempts == []


def test_preflight_hash_oserror_records_content_free_drift_and_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    failed_descriptor: int | None = None

    def fail_hash(descriptor: int, *, limit: int) -> str:
        nonlocal failed_descriptor
        failed_descriptor = descriptor
        del limit
        raise OSError("synthetic content must stay private")

    monkeypatch.setattr(cleanup_module, "_hash_descriptor", fail_hash)

    error = _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=0,
    )

    assert str(error) == "cleanup_drift"
    assert failed_descriptor is not None
    with pytest.raises(OSError) as caught:
        os.fstat(failed_descriptor)
    assert caught.value.errno == errno.EBADF
    assert setup.trash.attempts == []


@pytest.mark.parametrize("target_ordinal", range(_CLEANUP_ENTRY_COUNT))
def test_interruption_before_each_move_resumes_without_skipping_or_repeating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_ordinal: int,
) -> None:
    setup = _setup(tmp_path)

    def interrupt(name: str, ordinal: int) -> None:
        if name == "before_move" and ordinal == target_ordinal:
            raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt)
    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
    interrupted = setup.store.load(setup.receipt.transaction_id)
    assert len(setup.trash.moves) == target_ordinal
    assert interrupted.cleanup_entries[target_ordinal].intent_recorded is False
    assert interrupted.cleanup_entries[target_ordinal].failure is None

    monkeypatch.setattr(cleanup_module, "_checkpoint", lambda _name, _ordinal: None)
    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert setup.trash.moves == list(setup.ordered_paths)


@pytest.mark.parametrize("target_ordinal", range(_CLEANUP_ENTRY_COUNT))
def test_interruption_after_intent_retries_only_while_exact_source_remains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_ordinal: int,
) -> None:
    setup = _setup(tmp_path)

    def interrupt(name: str, ordinal: int) -> None:
        if name == "after_intent" and ordinal == target_ordinal:
            raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt)
    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
    interrupted = setup.store.load(setup.receipt.transaction_id)
    entry = interrupted.cleanup_entries[target_ordinal]
    assert len(setup.trash.moves) == target_ordinal
    assert entry.intent_recorded is True
    assert entry.outcome is None
    assert entry.failure is None
    _error(
        lambda: reconcile_cleanup(
            setup.store,
            interrupted.transaction_id,
            target_ordinal,
            "preserved",
        ),
        "cleanup_reconciliation_not_required",
        ordinal=target_ordinal,
    )

    monkeypatch.setattr(cleanup_module, "_checkpoint", lambda _name, _ordinal: None)
    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert setup.trash.moves == list(setup.ordered_paths)


@pytest.mark.parametrize("target_ordinal", range(_CLEANUP_ENTRY_COUNT))
def test_interruption_after_trash_return_requires_exact_owner_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_ordinal: int,
) -> None:
    setup = _setup(tmp_path)

    def interrupt(name: str, ordinal: int) -> None:
        if name == "after_move" and ordinal == target_ordinal:
            raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt)
    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
    assert len(setup.trash.moves) == target_ordinal + 1

    monkeypatch.setattr(cleanup_module, "_checkpoint", lambda _name, _ordinal: None)
    error = _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_ambiguous",
        ordinal=target_ordinal,
    )
    assert str(setup.ordered_paths[target_ordinal]) not in str(error)
    assert len(setup.trash.attempts) == target_ordinal + 1
    ambiguous = setup.store.load(setup.receipt.transaction_id)
    assert ambiguous.cleanup_entries[target_ordinal].failure == "cleanup_ambiguous"
    wrong_ordinal = (
        target_ordinal + 1
        if target_ordinal + 1 < _CLEANUP_ENTRY_COUNT
        else target_ordinal - 1
    )
    wrong_outcome: Literal["moved", "preserved"] = (
        "moved" if target_ordinal + 1 < _CLEANUP_ENTRY_COUNT else "preserved"
    )
    wrong_code = (
        "cleanup_reconciliation_not_required"
        if target_ordinal + 1 < _CLEANUP_ENTRY_COUNT
        else "cleanup_reconciliation_conflict"
    )
    _error(
        lambda: reconcile_cleanup(
            setup.store,
            ambiguous.transaction_id,
            wrong_ordinal,
            wrong_outcome,
        ),
        wrong_code,
        ordinal=wrong_ordinal,
    )

    reconciled = reconcile_cleanup(
        setup.store,
        ambiguous.transaction_id,
        target_ordinal,
        "moved",
    )
    assert reconciled.cleanup_entries[target_ordinal].outcome == "moved"
    if reconciled.state is TransactionState.CLEANUP_PENDING:
        reconciled = cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
    assert reconciled.state is TransactionState.COMPLETE
    assert setup.trash.moves == list(setup.ordered_paths)


def test_ordinary_trash_failure_is_recorded_before_owner_preserves_one_entry(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    setup.trash.fail_before_calls.add(0)

    error = _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "trash_failed",
        ordinal=0,
    )
    assert error.state is None
    failed = setup.store.load(setup.receipt.transaction_id)
    assert failed.cleanup_entries[0].failure == "trash_failed"
    assert setup.prepared_paths[0].exists()
    _error(
        lambda: reconcile_cleanup(
            setup.store,
            failed.transaction_id,
            1,
            "preserved",
        ),
        "cleanup_reconciliation_not_required",
        ordinal=1,
    )

    reconciled = reconcile_cleanup(
        setup.store,
        failed.transaction_id,
        0,
        "preserved",
    )
    setup.trash.fail_before_calls.clear()
    complete = cleanup(
        setup.config,
        setup.store,
        reconciled.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert complete.cleanup_entries[0].outcome == "preserved"
    assert setup.prepared_paths[0].exists()
    assert setup.trash.moves == list(setup.ordered_paths[1:])


def test_recorded_trash_failure_can_retry_the_same_exact_present_source(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    setup.trash.fail_before_calls.add(0)
    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "trash_failed",
        ordinal=0,
    )

    setup.trash.fail_before_calls.clear()
    complete = cleanup(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.trash,
    )

    assert complete.state is TransactionState.COMPLETE
    assert setup.trash.moves == list(setup.ordered_paths)


def test_resume_preflights_every_later_file_before_any_new_trash_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)

    def interrupt(name: str, ordinal: int) -> None:
        if name == "before_move" and ordinal == 1:
            raise SyntheticInterruption

    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt)
    with pytest.raises(SyntheticInterruption):
        cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        )
    assert len(setup.trash.attempts) == 1
    setup.staged_paths[-1].write_bytes(b"Synthetic later-file drift.")
    monkeypatch.setattr(cleanup_module, "_checkpoint", lambda _name, _ordinal: None)

    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "cleanup_drift",
        ordinal=4,
    )

    assert len(setup.trash.attempts) == 1


@pytest.mark.parametrize("mutation", ["missing", "invalid"])
def test_cleanup_journal_parser_requires_exact_failure_field(
    tmp_path: Path,
    mutation: Literal["missing", "invalid"],
) -> None:
    setup = _setup(tmp_path)
    setup.trash.fail_before_calls.add(0)
    _error(
        lambda: cleanup(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            setup.trash,
        ),
        "trash_failed",
        ordinal=0,
    )
    path = setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    payload = cast(dict[str, object], json.loads(path.read_bytes()))
    entries = cast(list[dict[str, object]], payload["cleanup_entries"])
    if mutation == "missing":
        del entries[0]["failure"]
    else:
        entries[0]["failure"] = "synthetic-private-filename.md"
    path.write_text(json.dumps(payload), encoding="utf-8")

    _error(
        lambda: setup.store.load(setup.receipt.transaction_id),
        "invalid_transaction_receipt",
    )


def test_macos_trash_uses_validated_same_file_reference_and_exact_arguments(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic note.md"
    path.write_bytes(b"Synthetic adapter source.")
    with _trash_source(path) as source:
        reference = "file:///.file/id=synthetic-reference"
        runner = RecordingRunner(
            (
                _reference_result(source, reference=reference),
                CompletedCommand(0, b"", b""),
            )
        )

        MacOSTrash(runner).move(source)

        assert runner.calls == [
            (
                (
                    "/usr/bin/osascript",
                    "-l",
                    "JavaScript",
                    "-e",
                    CREATE_FILE_REFERENCE_SCRIPT,
                    str(path),
                ),
                60.0,
            ),
            (
                (
                    "/usr/bin/osascript",
                    "-l",
                    "JavaScript",
                    "-e",
                    TRASH_FILE_REFERENCE_SCRIPT,
                    reference,
                    str(source.device),
                    str(source.inode),
                    str(stat.S_IMODE(source.mode)),
                ),
                60.0,
            ),
        ]


@pytest.mark.parametrize("field", ["device", "inode", "mode"])
def test_macos_trash_refuses_reference_identity_mismatch_content_free(
    tmp_path: Path,
    field: Literal["device", "inode", "mode"],
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    with _trash_source(path) as source:
        overrides = {
            "device": source.device,
            "inode": source.inode,
            "mode": stat.S_IMODE(source.mode),
        }
        overrides[field] += 1
        runner = RecordingRunner(
            (
                _reference_result(
                    source,
                    device=overrides["device"],
                    inode=overrides["inode"],
                    mode=overrides["mode"],
                ),
            )
        )

        error = _error(lambda: MacOSTrash(runner).move(source), "trash_failed")

    assert str(path) not in str(error)
    assert runner.calls is not None
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"{}",
        b'{"device":"1","inode":"2","mode":"420","reference":"https://invalid"}',
    ],
)
def test_macos_trash_refuses_malformed_or_non_file_reference_content_free(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    runner = RecordingRunner((CompletedCommand(0, payload, b""),))
    with _trash_source(path) as source:
        error = _error(lambda: MacOSTrash(runner).move(source), "trash_failed")

    assert str(path) not in str(error)
    assert runner.calls is not None
    assert len(runner.calls) == 1


def test_macos_trash_binds_cached_source_identity_to_live_descriptor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    with _trash_source(path) as source:
        forged = replace(source, inode=source.inode + 1)
        runner = RecordingRunner(
            (
                _reference_result(forged),
                CompletedCommand(0, b"", b""),
            )
        )

        error = _error(lambda: MacOSTrash(runner).move(forged), "trash_failed")

    assert str(path) not in str(error)
    assert runner.calls == []


def test_swap_immediately_before_reference_creation_never_reaches_trash_action(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    parked_original = tmp_path / "synthetic-parked-original"
    replacement = b"Synthetic replacement before reference creation."
    path.write_bytes(b"Synthetic adapter original.")
    with _trash_source(path) as source:
        path.rename(parked_original)
        path.write_bytes(replacement)
        replacement_metadata = path.stat(follow_symlinks=False)
        runner = RecordingRunner(
            (
                _reference_result(
                    source,
                    device=replacement_metadata.st_dev,
                    inode=replacement_metadata.st_ino,
                    mode=replacement_metadata.st_mode,
                ),
            )
        )

        error = _error(lambda: MacOSTrash(runner).move(source), "trash_failed")

    assert str(path) not in str(error)
    assert path.read_bytes() == replacement
    assert parked_original.exists()
    assert runner.calls is not None
    assert len(runner.calls) == 1


def test_swap_after_reference_creation_uses_same_reference_not_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    parked_original = tmp_path / "synthetic-parked-original"
    replacement = b"Synthetic replacement after reference creation."
    path.write_bytes(b"Synthetic adapter original.")
    with _trash_source(path) as source:
        reference = "file:///.file/id=synthetic-reference"
        runner = RecordingRunner(
            (
                _reference_result(source, reference=reference),
                CompletedCommand(0, b"", b""),
            )
        )
        adapter = MacOSTrash(runner)
        bound_reference = adapter.create_reference(source)
        path.rename(parked_original)
        path.write_bytes(replacement)

        adapter.trash_reference(source, bound_reference)

    assert path.read_bytes() == replacement
    assert parked_original.exists()
    assert runner.calls is not None
    assert runner.calls[-1][0][-4:] == (
        reference,
        str(source.device),
        str(source.inode),
        str(stat.S_IMODE(source.mode)),
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS Foundation")
def test_real_macos_same_reference_trashes_original_and_preserves_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "synthetic-reference-original"
    parked_original = tmp_path / "synthetic-parked-original"
    replacement = b"Synthetic replacement after reference creation."
    path.write_bytes(b"Synthetic adapter original.")

    with _trash_source(path) as source:
        adapter = MacOSTrash()
        reference = adapter.create_reference(source)
        path.rename(parked_original)
        path.write_bytes(replacement)

        adapter.trash_reference(source, reference)

    assert path.read_bytes() == replacement
    assert not parked_original.exists()


@pytest.mark.parametrize(
    "result",
    [
        CompletedCommand(1, b"", b""),
        CompletedCommand(0, b"", b"synthetic stderr must stay private"),
    ],
)
def test_macos_trash_failure_exposes_no_path_or_stderr(
    tmp_path: Path,
    result: CompletedCommand,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    runner = RecordingRunner((result,))

    with _trash_source(path) as source:
        error = _error(lambda: MacOSTrash(runner).move(source), "trash_failed")

    assert str(path) not in str(error)
    assert "stderr" not in str(error)


@pytest.mark.parametrize(
    "result",
    [
        CompletedCommand(1, b"", b"synthetic action stderr"),
        CompletedCommand(0, b"synthetic malformed action output", b""),
    ],
)
def test_macos_trash_action_failure_is_content_free(
    tmp_path: Path,
    result: CompletedCommand,
) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    with _trash_source(path) as source:
        runner = RecordingRunner(
            (
                _reference_result(source),
                result,
            )
        )

        error = _error(lambda: MacOSTrash(runner).move(source), "trash_failed")

    assert str(path) not in str(error)
    assert "stderr" not in str(error)


def test_macos_trash_timeout_is_content_free(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-private-filename.md"
    path.write_bytes(b"Synthetic adapter source.")
    runner = RecordingRunner(
        (),
        failure_at=0,
        failure=subprocess.TimeoutExpired(["synthetic"], 60.0),
    )

    with _trash_source(path) as source:
        _error(lambda: MacOSTrash(runner).move(source), "trash_failed")


def test_default_macos_runner_uses_no_shell_and_text_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[tuple[str, ...], dict[str, object]]] = []
    path = tmp_path / "synthetic note.md"
    path.write_bytes(b"Synthetic adapter source.")
    with _trash_source(path) as source:
        reference_payload = _reference_result(source)
        responses = iter(
            (
                subprocess.CompletedProcess(
                    (),
                    reference_payload.returncode,
                    reference_payload.stdout.decode(),
                    reference_payload.stderr.decode(),
                ),
                subprocess.CompletedProcess((), 0, "", ""),
            )
        )

        def run(
            argv: Sequence[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            observed.append((tuple(argv), dict(kwargs)))
            return next(responses)

        monkeypatch.setattr(subprocess, "run", run)
        MacOSTrash().move(source)

    assert len(observed) == 2
    for _argv, kwargs in observed:
        assert kwargs == {
            "capture_output": True,
            "check": False,
            "shell": False,
            "text": True,
            "timeout": 60.0,
        }


def test_cleanup_module_has_no_irrecoverable_deletion_api() -> None:
    path = Path(cleanup_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"unlink", "remove", "rmtree", "system"}
    }

    assert forbidden_calls == set()
