"""Synthetic publication withdrawal and interruption recovery contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import staged_memory_intake.cancellation as cancellation
import staged_memory_intake.cli as cli
from staged_memory_intake.cli import Dependencies, main
from staged_memory_intake.config import configure
from staged_memory_intake.model import (
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    NoPublicationFault,
    PublicationFault,
    TransactionReceipt,
)
from staged_memory_intake.prepared import build_preview
from staged_memory_intake.publish import publish
from staged_memory_intake.securefs import (
    atomic_private_json,
    canonical_json_bytes,
    directory_identity,
)
from staged_memory_intake.state import TransactionStore
from staged_memory_intake_fakes import FakeMemoryPathsRunner, FakeTrash, NeverRunner


@dataclass(frozen=True)
class CancellationSetup:
    config: IntakeConfig
    store: TransactionStore
    receipt: TransactionReceipt
    runner: FakeMemoryPathsRunner
    dependencies: Dependencies


@pytest.fixture
def setup(tmp_path: Path) -> CancellationSetup:
    notes = tmp_path / "synthetic-notes"
    home = tmp_path / "synthetic-home"
    inbox = notes / "04_Inbox"
    trash = tmp_path / "synthetic-trash"
    for directory in (notes, home, trash):
        directory.mkdir(mode=0o700)
    for name in ("01_Pending", "02_Staged", "03_Prepared", "04_Inbox"):
        (notes / name).mkdir(mode=0o700)
    for ordinal in range(2):
        source = f"Synthetic source {ordinal}. 中文证据。\n".encode()
        source_name = f"synthetic-source-{ordinal}.md"
        (notes / "02_Staged" / source_name).write_bytes(source)
        (notes / "03_Prepared" / f"synthetic-prepared-{ordinal}.md").write_text(
            "---\n"
            "memory_intake_version: 1\n"
            f"source_note: {source_name}\n"
            f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
            "kind: fact\n"
            "sensitivity: restricted\n"
            "occurred_on: \n"
            "valid_from: \n"
            "valid_to: \n"
            "tags: []\n"
            "---\n"
            f"Synthetic approved statement {ordinal}.\n"
        )
    runner = FakeMemoryPathsRunner(home, inbox)
    store = TransactionStore(tmp_path / "synthetic-state")
    config = configure(
        store.state_root, notes, home, create_prepared=False, runner=runner
    )
    preview = build_preview(
        config, [f"synthetic-prepared-{n}.md" for n in range(2)], []
    )
    receipt = store.authorize(preview, preview.manifest_digest)
    receipt = publish(
        config,
        store,
        receipt.transaction_id,
        NoPublicationFault(),
        memory_paths_runner=runner,
    )
    dependencies = Dependencies(
        runner, NeverRunner(), FakeTrash(trash), NoPublicationFault(), True
    )
    return CancellationSetup(config, store, receipt, runner, dependencies)


def _cancel(setup: CancellationSetup) -> int:
    return main(
        [
            "--state-root",
            str(setup.store.state_root),
            "cancel-publication",
            "--transaction",
            setup.receipt.transaction_id,
            "--digest",
            setup.receipt.manifest_digest,
        ],
        dependencies=setup.dependencies,
    )


def test_cancel_withdraws_only_published_copies_even_after_prepared_deleted(
    setup: CancellationSetup, capsys: pytest.CaptureFixture[str]
) -> None:
    for candidate in setup.receipt.candidates:
        (setup.config.notes_root / "03_Prepared" / candidate.prepared_name).unlink()
    staged = {
        entry.name: entry.read_bytes()
        for entry in (setup.config.notes_root / "02_Staged").iterdir()
    }
    receipt_bytes = (
        setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    ).read_bytes()
    published = {
        entry.name: entry.read_bytes() for entry in setup.config.memory_inbox.iterdir()
    }
    assert _cancel(setup) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "cancelled"
    assert result["archived_count"] == 2
    assert setup.store.active() is None
    assert list(setup.config.memory_inbox.iterdir()) == []
    archive = (
        setup.store.state_root / f"cancelled-publication-{setup.receipt.transaction_id}"
    )
    assert {entry.name: entry.read_bytes() for entry in archive.iterdir()} == published
    assert (
        setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    ).read_bytes() == receipt_bytes
    assert {
        entry.name: entry.read_bytes()
        for entry in (setup.config.notes_root / "02_Staged").iterdir()
    } == staged
    assert list((setup.config.notes_root / "03_Prepared").iterdir()) == []


class SyntheticCancellationCrash(BaseException):
    """Loss of a helper process at one durable protocol boundary."""


@dataclass(frozen=True)
class CrashAt:
    target: str

    def checkpoint(self, name: str) -> None:
        if name == self.target:
            raise SyntheticCancellationCrash


def _direct_cancel(
    setup: CancellationSetup, fault: PublicationFault | None = None
) -> dict[str, object]:
    return cancellation.cancel_publication(
        setup.config,
        setup.store,
        setup.receipt.transaction_id,
        setup.receipt.manifest_digest,
        setup.runner,
        fault,
    )


def _archive(setup: CancellationSetup) -> Path:
    return (
        setup.store.state_root / f"cancelled-publication-{setup.receipt.transaction_id}"
    )


def _pending(setup: CancellationSetup, target: str = "cancellation_intent") -> None:
    with pytest.raises(SyntheticCancellationCrash):
        _direct_cancel(setup, CrashAt(target))


@pytest.mark.parametrize(
    "checkpoint",
    [
        "cancellation_intent",
        "before_archive_0",
        "archive_0_renamed",
        "archive_0_durable",
        "archive_1_renamed",
        "archive_1_durable",
        "cancellation_verified",
        "cancelled_marker",
        "active_detached",
    ],
)
def test_exact_retry_recovers_every_boundary(
    setup: CancellationSetup, checkpoint: str
) -> None:
    _pending(setup, checkpoint)
    result = _direct_cancel(setup)
    assert result["status"] == "cancelled"
    assert setup.store.active() is None
    assert list(setup.config.memory_inbox.iterdir()) == []
    assert len(list(_archive(setup).iterdir())) == 2


@pytest.mark.parametrize(
    "drift", ["hidden", "visible", "modified", "symlink", "fifo", "mode", "missing"]
)
def test_initial_drift_refuses_without_moving_or_detaching(
    setup: CancellationSetup, drift: str
) -> None:
    inbox = setup.config.memory_inbox
    first = inbox / setup.receipt.published_files[0].inbox_name
    if drift in {"hidden", "visible"}:
        (
            inbox / (".synthetic-extra" if drift == "hidden" else "synthetic-extra.md")
        ).write_bytes(b"synthetic extra")
    elif drift == "modified":
        first.write_bytes(b"synthetic modified")
    elif drift == "mode":
        first.chmod(0o644)
    else:
        first.unlink()
        if drift == "symlink":
            first.symlink_to(inbox / setup.receipt.published_files[1].inbox_name)
        elif drift == "fifo":
            os.mkfifo(first, 0o600)
    before = {entry.name for entry in inbox.iterdir()}
    with pytest.raises(IntakeError, match="cancellation_ambiguous"):
        _direct_cancel(setup)
    assert {entry.name for entry in inbox.iterdir()} == before
    assert setup.store.active() == setup.receipt
    assert not (
        setup.store.state_root / f"{setup.receipt.transaction_id}.cancellation.json"
    ).exists()


@pytest.mark.parametrize(
    "drift",
    [
        "same_bytes_replaced",
        "modified",
        "mode",
        "symlink",
        "fifo",
        "missing_both",
        "both_present",
        "archive_extra",
        "inbox_hidden",
        "archive_replaced",
    ],
)
def test_pending_recovery_refuses_unproven_copy_state(
    setup: CancellationSetup, drift: str
) -> None:
    _pending(setup, "archive_0_durable")
    first = _archive(setup) / setup.receipt.published_files[0].inbox_name
    if drift == "same_bytes_replaced":
        raw = first.read_bytes()
        first.rename(setup.store.state_root / "synthetic-displaced-copy")
        first.write_bytes(raw)
        first.chmod(0o600)
    elif drift == "modified":
        first.write_bytes(b"synthetic replaced archive")
    elif drift == "mode":
        first.chmod(0o644)
    elif drift in {"symlink", "fifo", "missing_both"}:
        first.unlink()
        if drift == "symlink":
            first.symlink_to(
                setup.config.memory_inbox / setup.receipt.published_files[1].inbox_name
            )
        elif drift == "fifo":
            os.mkfifo(first, 0o600)
    elif drift == "both_present":
        extra = setup.config.memory_inbox / first.name
        extra.write_bytes(first.read_bytes())
        extra.chmod(0o600)
    elif drift == "archive_extra":
        (_archive(setup) / ".synthetic-extra").write_bytes(b"synthetic extra")
    elif drift == "inbox_hidden":
        (setup.config.memory_inbox / ".synthetic-extra").write_bytes(b"synthetic extra")
    else:
        _archive(setup).rename(setup.store.state_root / "synthetic-displaced-archive")
        _archive(setup).mkdir(mode=0o700)
    with pytest.raises(IntakeError):
        _direct_cancel(setup)
    assert setup.store.active() == setup.receipt
    assert not (
        setup.store.state_root / f"{setup.receipt.transaction_id}.cancelled.json"
    ).exists()


@pytest.mark.parametrize(
    "field",
    ["scan_started", "batch_id", "change_set_id", "revision_id", "application_id"],
)
def test_cancellation_refuses_irreversible_state(
    setup: CancellationSetup, field: str
) -> None:
    receipt_path = setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    raw = json.loads(receipt_path.read_bytes())
    raw[field] = True if field == "scan_started" else "synthetic_recorded_id"
    atomic_private_json(receipt_path, raw)
    with pytest.raises(IntakeError, match="cancellation_not_allowed"):
        _direct_cancel(setup)
    assert len(list(setup.config.memory_inbox.iterdir())) == 2
    assert setup.store.active() is not None


@pytest.mark.parametrize("argument", ["transaction", "digest"])
def test_requires_complete_current_exact_authority(
    setup: CancellationSetup, argument: str
) -> None:
    transaction = setup.receipt.transaction_id
    digest = setup.receipt.manifest_digest
    if argument == "transaction":
        transaction = transaction[:15]
    else:
        digest = digest[:12]
    with pytest.raises(IntakeError, match="invalid_arguments"):
        cancellation.cancel_publication(
            setup.config, setup.store, transaction, digest, setup.runner
        )
    assert setup.store.active() == setup.receipt


def test_wrong_digest_and_changed_memory_inbox_refuse(setup: CancellationSetup) -> None:
    with pytest.raises(IntakeError, match="wrong_manifest_digest"):
        cancellation.cancel_publication(
            setup.config,
            setup.store,
            setup.receipt.transaction_id,
            "a" * 64,
            setup.runner,
        )
    setup.runner.inbox = setup.runner.home
    with pytest.raises(IntakeError, match="cancellation_authority_changed"):
        _direct_cancel(setup)
    assert setup.store.active() == setup.receipt


@pytest.mark.parametrize(
    "command",
    [
        ["begin-scan"],
        ["publish"],
        ["cleanup"],
        ["record-scan", "--input", "-"],
        ["check-batch", "--input", "-"],
        ["check-review", "--input", "-"],
        ["record-application", "--input", "-"],
        ["check-memories", "--input", "-"],
        ["await-approval", "--revision", "synthetic-revision", "--digest", "a" * 64],
        ["reconcile-cleanup", "--ordinal", "0", "--outcome", "moved"],
        ["preview", "review"],
    ],
)
@pytest.mark.parametrize("checkpoint", ["cancellation_intent", "cancelled_marker"])
def test_pending_fences_every_transaction_command_without_stdin_read(
    setup: CancellationSetup,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
    checkpoint: str,
) -> None:
    _pending(setup, checkpoint)
    result = main(
        [
            "--state-root",
            str(setup.store.state_root),
            *command,
            "--transaction",
            setup.receipt.transaction_id,
        ],
        dependencies=setup.dependencies,
    )
    assert result == 4
    assert json.loads(capsys.readouterr().err)["code"] == "cancellation_pending"
    assert setup.store.active() == setup.receipt


@pytest.mark.parametrize(
    "command",
    [
        ["abandon-unsupported"],
        ["migrate-layout"],
        ["relocate", "--to", "/synthetic-absent-root"],
        ["configure", "--notes-root", "/synthetic-absent-root"],
        ["pending-drop", "--name", "synthetic-new.md", "--input", "-"],
        ["preview", "prepared", "--prepared", "synthetic-prepared-0.md"],
        ["authorize", "--prepared", "synthetic-prepared-0.md", "--digest", "a" * 64],
    ],
)
def test_pending_fences_other_commands(
    setup: CancellationSetup, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    _pending(setup)
    assert (
        main(
            ["--state-root", str(setup.store.state_root), *command],
            dependencies=setup.dependencies,
        )
        == 4
    )
    assert json.loads(capsys.readouterr().err)["code"] == "cancellation_pending"


def test_status_is_content_free_pending_then_cancelled(
    setup: CancellationSetup, capsys: pytest.CaptureFixture[str]
) -> None:
    _pending(setup, "archive_0_durable")
    assert (
        main(
            ["--state-root", str(setup.store.state_root), "status"],
            dependencies=setup.dependencies,
        )
        == 0
    )
    pending = json.loads(capsys.readouterr().out)
    assert pending == {
        "schema": "staged-memory-intake.status.v1",
        "status": "cancellation_pending",
        "transaction_id": setup.receipt.transaction_id,
        "manifest_digest": setup.receipt.manifest_digest,
        "scan_started": False,
        "published_count": 2,
        "archived_count": 1,
        "recovery_command": "cancel-publication",
    }
    _direct_cancel(setup)
    assert (
        main(
            [
                "--state-root",
                str(setup.store.state_root),
                "status",
                "--transaction",
                setup.receipt.transaction_id,
            ],
            dependencies=setup.dependencies,
        )
        == 0
    )
    completed = json.loads(capsys.readouterr().out)
    assert completed["status"] == "cancelled"
    assert "recovery_command" not in completed
    serialized = json.dumps(completed)
    for private in (
        str(setup.config.notes_root),
        "Synthetic approved statement",
        setup.receipt.candidates[0].prepared_name,
    ):
        assert private not in serialized


def test_cancelled_replay_preserves_new_active_transaction_and_inbox(
    setup: CancellationSetup, capsys: pytest.CaptureFixture[str]
) -> None:
    _direct_cancel(setup)
    candidate = (
        setup.config.notes_root
        / "03_Prepared"
        / setup.receipt.candidates[0].prepared_name
    )
    candidate.write_bytes(
        candidate.read_bytes().replace(
            b"Synthetic approved statement 0", b"Synthetic later statement"
        )
    )
    preview = build_preview(setup.config, [candidate.name], [])
    later = setup.store.authorize(preview, preview.manifest_digest)
    later = publish(
        setup.config,
        setup.store,
        later.transaction_id,
        NoPublicationFault(),
        memory_paths_runner=setup.runner,
    )
    before = {
        entry.name: entry.read_bytes() for entry in setup.config.memory_inbox.iterdir()
    }
    assert _direct_cancel(setup)["status"] == "cancelled"
    assert setup.store.active() == later
    assert {
        entry.name: entry.read_bytes() for entry in setup.config.memory_inbox.iterdir()
    } == before
    assert (
        main(
            [
                "--state-root",
                str(setup.store.state_root),
                "status",
                "--transaction",
                setup.receipt.transaction_id,
            ],
            dependencies=setup.dependencies,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "cancelled"


def test_receipt_drift_after_intent_is_terminal(setup: CancellationSetup) -> None:
    _pending(setup)
    receipt_path = setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(IntakeError, match="cancellation_receipt_changed"):
        _direct_cancel(setup)
    assert len(list(setup.config.memory_inbox.iterdir())) == 2


def test_destination_winner_is_never_replaced(
    setup: CancellationSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = cancellation._move_bound_file
    payload = b"synthetic destination winner"
    first_name = setup.receipt.published_files[0].inbox_name

    def install_winner(source: int, destination: int, name: str) -> None:
        (_archive(setup) / name).write_bytes(payload)
        original(source, destination, name)

    monkeypatch.setattr(cancellation, "_move_bound_file", install_winner)
    with pytest.raises(IntakeError, match="cancellation_ambiguous"):
        _direct_cancel(setup)
    assert (_archive(setup) / first_name).read_bytes() == payload
    assert (setup.config.memory_inbox / first_name).exists()
    assert setup.store.active() == setup.receipt


def test_dispatcher_lock_prevents_cancellation_between_scan_fence_and_action(
    setup: CancellationSetup,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real_status = cancellation.cancellation_status
    calls = 0

    def start_cancellation_after_outer_gate(
        store: TransactionStore, transaction_id: str | None = None
    ) -> dict[str, object] | None:
        nonlocal calls
        calls += 1
        if calls == 1:
            _pending(setup)
            return None
        return real_status(store, transaction_id)

    monkeypatch.setattr(cli, "cancellation_status", start_cancellation_after_outer_gate)
    assert (
        main(
            [
                "--state-root",
                str(setup.store.state_root),
                "begin-scan",
                "--transaction",
                setup.receipt.transaction_id,
            ],
            dependencies=setup.dependencies,
        )
        == 4
    )
    assert json.loads(capsys.readouterr().err)["code"] == "transaction_busy"
    assert setup.store.load(setup.receipt.transaction_id).scan_started is False


@pytest.mark.parametrize(
    "checkpoint",
    [
        "intent_temporary",
        "intent_partial",
        "intent_fsynced",
        "intent_renamed",
        "marker_temporary",
        "marker_partial",
        "marker_fsynced",
        "marker_renamed",
        "cancellation_intent",
        "archive_0_renamed",
        "archive_0_durable",
        "archive_1_renamed",
        "archive_1_durable",
        "cancelled_marker",
        "active_detached",
    ],
)
def test_real_process_death_and_fresh_recovery(
    setup: CancellationSetup, checkpoint: str
) -> None:
    script = """
import json, os, sys
from pathlib import Path
from staged_memory_intake.cancellation import cancel_publication
from staged_memory_intake.config import require_config
from staged_memory_intake.model import CompletedCommand
from staged_memory_intake.state import TransactionStore
state, transaction, digest, checkpoint = sys.argv[1:]
store = TransactionStore(Path(state))
config = require_config(Path(state))
class Runner:
    def run(self, argv, *, timeout_seconds):
        return CompletedCommand(0, json.dumps({"home": str(config.memory_home), "database": str(config.memory_home / "synthetic-database"), "identity": str(config.memory_home / "synthetic-identity"), "inbox": str(config.memory_inbox), "inbox_claims": str(config.memory_home / "synthetic-claims")}).encode(), b"")
class Fault:
    def checkpoint(self, name):
        if name == checkpoint:
            os._exit(86)
result = cancel_publication(config, store, transaction, digest, Runner(), Fault())
print(json.dumps(result))
"""
    helper = Path(cancellation.__file__).parent.parent
    environment = dict(os.environ, PYTHONPATH=str(helper))
    arguments = [
        sys.executable,
        "-B",
        "-c",
        script,
        str(setup.store.state_root),
        setup.receipt.transaction_id,
        setup.receipt.manifest_digest,
    ]
    first = subprocess.run(
        [*arguments, checkpoint], capture_output=True, env=environment, timeout=10
    )
    assert first.returncode == 86, first.stderr
    resumed = subprocess.run(
        [*arguments, "no-crash"], capture_output=True, env=environment, timeout=10
    )
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(resumed.stdout)["status"] == "cancelled"
    assert setup.store.active() is None


@pytest.mark.parametrize("checkpoint", ["cancellation_verified", "cancelled_marker"])
@pytest.mark.parametrize("authority", ["state", "inbox", "archive"])
def test_final_boundary_substitution_preserves_active_authority(
    setup: CancellationSetup, checkpoint: str, authority: str
) -> None:
    root = setup.store.state_root
    pointer = (root / "active.json").read_bytes()
    displaced = root.parent / f"synthetic-displaced-{authority}"

    class Substitute:
        def checkpoint(self, name: str) -> None:
            if name != checkpoint:
                return
            path = (
                root
                if authority == "state"
                else setup.config.memory_inbox
                if authority == "inbox"
                else _archive(setup)
            )
            path.rename(displaced)
            shutil.copytree(displaced, path)

    with pytest.raises(IntakeError):
        _direct_cancel(setup, Substitute())
    if authority == "state":
        assert (displaced / "active.json").read_bytes() == pointer
        assert (root / "active.json").read_bytes() == pointer
    else:
        assert (root / "active.json").read_bytes() == pointer


def test_replacement_at_actual_move_boundary_never_moves_foreign_source(
    setup: CancellationSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_move = cancellation._move_bound_file
    published = setup.config.memory_inbox / setup.receipt.published_files[0].inbox_name
    displaced = setup.store.state_root / "synthetic-displaced-owned-copy"
    payload = b"synthetic foreign replacement"
    owned = published.read_bytes()
    replaced = False

    def replace_then_move(descriptor: int, destination: int, name: str) -> None:
        nonlocal replaced
        if not replaced:
            published.rename(displaced)
            published.write_bytes(payload)
            published.chmod(0o600)
            replaced = True
        original_move(descriptor, destination, name)

    monkeypatch.setattr(cancellation, "_move_bound_file", replace_then_move)
    with pytest.raises(IntakeError):
        _direct_cancel(setup)
    assert published.read_bytes() == payload
    assert (_archive(setup) / published.name).read_bytes() == owned
    assert setup.store.active() == setup.receipt


def test_fifo_receipt_refuses_without_blocking(setup: CancellationSetup) -> None:
    path = setup.store.state_root / f"{setup.receipt.transaction_id}.json"
    path.rename(setup.store.state_root / "synthetic-receipt-backup")
    os.mkfifo(path, 0o600)
    with pytest.raises(IntakeError, match="unsafe_regular_file"):
        _direct_cancel(setup)
    assert len(list(setup.config.memory_inbox.iterdir())) == 2


def test_failed_lock_identity_does_not_leave_reentrant_authority(
    setup: CancellationSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    import staged_memory_intake.state as state_module

    original_identity = directory_identity
    calls = 0

    def fail_second_identity(path: Path) -> DirectoryIdentity:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise IntakeError("synthetic_identity_failure", "drift")
        return original_identity(path)

    monkeypatch.setattr(state_module, "directory_identity", fail_second_identity)
    with pytest.raises(IntakeError, match="synthetic_identity_failure"):
        with setup.store.lock():
            pytest.fail("setup must fail before lock authority is exposed")
    monkeypatch.setattr(state_module, "directory_identity", original_identity)
    contender = TransactionStore(setup.store.state_root)
    with contender.lock():
        with pytest.raises(IntakeError, match="transaction_busy"):
            with setup.store.lock():
                pytest.fail("failed setup must not authorize reentrant bypass")


def test_process_contender_cannot_begin_scan_during_cancellation(
    setup: CancellationSetup,
) -> None:
    helper = Path(cancellation.__file__).parent.parent
    environment = dict(os.environ, PYTHONPATH=str(helper))
    observed: list[str] = []

    class Contender:
        def checkpoint(self, name: str) -> None:
            if name != "cancellation_intent":
                return
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "staged_memory_intake",
                    "--state-root",
                    str(setup.store.state_root),
                    "begin-scan",
                    "--transaction",
                    setup.receipt.transaction_id,
                ],
                capture_output=True,
                env=environment,
                timeout=10,
            )
            assert result.returncode == 4
            observed.append(json.loads(result.stderr)["code"])

    assert _direct_cancel(setup, Contender())["status"] == "cancelled"
    assert observed == ["transaction_busy"]
    assert setup.store.load(setup.receipt.transaction_id).scan_started is False


def test_notes_root_symlink_substitution_before_move_refuses(
    setup: CancellationSetup,
) -> None:
    root = setup.config.notes_root
    displaced = root.parent / "synthetic-displaced-notes"

    class Substitute:
        def checkpoint(self, name: str) -> None:
            if name == "before_archive_0":
                root.rename(displaced)
                root.symlink_to(displaced, target_is_directory=True)

    with pytest.raises(IntakeError, match="cancellation_authority_changed"):
        _direct_cancel(setup, Substitute())
    assert setup.store.active() == setup.receipt
    assert len(list((displaced / "04_Inbox").iterdir())) == 2
    assert list(_archive(setup).iterdir()) == []


def test_cli_cancellation_does_not_inventory_or_open_any_original(
    setup: CancellationSetup,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    forbidden = [
        (setup.config.notes_root / folder).stat().st_ino
        for folder in ("02_Staged", "03_Prepared")
    ]
    real_listdir = os.listdir
    real_open = os.open

    def reject_original_inventory(
        path: str | bytes | int | os.PathLike[str] | os.PathLike[bytes] = ".",
    ) -> list[str]:
        metadata = os.fstat(path) if isinstance(path, int) else os.stat(path)
        assert metadata.st_ino not in forbidden, (
            "cancellation must not inventory originals"
        )
        return real_listdir(path)  # type: ignore[return-value]

    def reject_original_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is not None:
            assert os.fstat(dir_fd).st_ino not in forbidden, (
                "cancellation must not open originals"
            )
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "listdir", reject_original_inventory)
    monkeypatch.setattr(os, "open", reject_original_open)
    assert _cancel(setup) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "cancelled"


@pytest.mark.parametrize("checkpoint", ["intent_partial", "marker_partial"])
def test_retry_preserves_unpromoted_temporary_bytes(
    setup: CancellationSetup, checkpoint: str
) -> None:
    _pending(setup, checkpoint)
    temporaries = {
        entry.name: entry.read_bytes()
        for entry in setup.store.state_root.iterdir()
        if entry.name.endswith(".tmp")
    }
    assert temporaries
    assert _direct_cancel(setup)["status"] == "cancelled"
    assert {
        name: (setup.store.state_root / name).read_bytes() for name in temporaries
    } == temporaries


@pytest.mark.parametrize("malformation", ["extra_key", "schema", "duplicate_key"])
def test_malformed_cancellation_sidecar_fences_and_preserves_publication(
    setup: CancellationSetup, capsys: pytest.CaptureFixture[str], malformation: str
) -> None:
    _pending(setup)
    path = setup.store.state_root / f"{setup.receipt.transaction_id}.cancellation.json"
    payload = json.loads(path.read_bytes())
    if malformation == "extra_key":
        payload["synthetic_extra"] = True
        atomic_private_json(path, payload)
    elif malformation == "schema":
        payload["schema"] = "staged-memory-intake.publication-cancellation.v999"
        atomic_private_json(path, payload)
    else:
        raw = path.read_bytes()
        path.write_bytes(b'{"phase":"pending",' + raw[1:])
    before = path.read_bytes()
    assert _cancel(setup) == 4
    assert json.loads(capsys.readouterr().err)["code"] == "invalid_cancellation"
    assert path.read_bytes() == before
    assert setup.store.active() == setup.receipt
    assert len(list(setup.config.memory_inbox.iterdir())) == 2


@pytest.mark.parametrize("winner", ["existing", "concurrent"])
def test_authority_replay_fsyncs_parent_before_return(
    setup: CancellationSetup, monkeypatch: pytest.MonkeyPatch, winner: str
) -> None:
    state = setup.store.state_root
    name = "synthetic-authority.json"
    payload: dict[str, object] = {"synthetic": "authority"}
    raw = canonical_json_bytes(payload)
    if winner == "existing":
        (state / name).write_bytes(raw)
        (state / name).chmod(0o600)
    syncs: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def record_sync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        syncs.append((metadata.st_dev, metadata.st_ino))
        real_fsync(descriptor)

    def install_exact_winner(
        source: int, destination: int, source_name: str, destination_name: str
    ) -> None:
        descriptor = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination,
        )
        try:
            os.write(descriptor, raw)
        finally:
            os.close(descriptor)
        raise FileExistsError("synthetic concurrent authority winner")

    monkeypatch.setattr(os, "fsync", record_sync)
    if winner == "concurrent":
        monkeypatch.setattr(
            cancellation, "_rename_entries_no_replace", install_exact_winner
        )
    descriptor = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        cancellation._write_exclusive(
            descriptor, name, payload, NoPublicationFault(), "synthetic"
        )
    finally:
        os.close(descriptor)
    metadata = state.stat()
    assert (metadata.st_dev, metadata.st_ino) in syncs


def test_resumed_intent_is_fsynced_before_any_archive_move(
    setup: CancellationSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pending(setup, "intent_renamed")
    state_metadata = setup.store.state_root.stat()
    durable = False
    original_fsync = os.fsync
    original_move = cancellation._move_bound_file

    def track_durability(descriptor: int) -> None:
        nonlocal durable
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            state_metadata.st_dev,
            state_metadata.st_ino,
        ):
            durable = True
        original_fsync(descriptor)

    def require_durable_intent(descriptor: int, destination: int, name: str) -> None:
        assert durable, "intent directory must be durable before withdrawing a copy"
        original_move(descriptor, destination, name)

    monkeypatch.setattr(os, "fsync", track_durability)
    monkeypatch.setattr(cancellation, "_move_bound_file", require_durable_intent)
    assert _direct_cancel(setup)["status"] == "cancelled"
