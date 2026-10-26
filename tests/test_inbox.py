from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from synthetic import make_synthetic_store

from memory import model
from memory.database import Connection, open_database, writer_session
from memory.keys import KEYCHAIN_SERVICE, load_master_key
from memory.model import Authorship, RuntimePaths, Sensitivity
from memory.runtime import (
    initialize_runtime,
    load_runtime_identity,
    resolve_runtime,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_KEYCHAIN_ITEM = "SYNTHETIC_INBOX_KEYCHAIN_ITEM"
_RECOVERY_PAYLOAD_NAME = re.compile(r"\.recovery-([0-9a-f]{32})\.stage")
_RECOVERY_MANIFEST_NAME = re.compile(r"\.recovery-([0-9a-f]{32})\.json")


class FakeClock:
    def __init__(
        self,
        timestamp: float = 1_800_000_000.0,
        on_sleep: Callable[[], None] | None = None,
    ) -> None:
        self.timestamp = timestamp
        self.on_sleep = on_sleep
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.on_sleep is not None:
            self.on_sleep()
        self.timestamp += seconds


def test_empty_inbox_scan_returns_typed_no_eligible_sources(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch empty discovery publishing an empty or partial batch."""
    from memory.errors import NoEligibleSourcesError
    from memory.inbox import scan_inbox

    clock = FakeClock()
    with pytest.raises(NoEligibleSourcesError) as raised:
        scan_inbox(synthetic_store, clock=clock)

    assert raised.value.code == "no_eligible_sources"
    assert clock.sleeps == []


def test_settled_mixed_files_form_one_private_atomic_batch(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch split batches, metadata loss, false indexing, or early deletion."""
    from memory.inbox import scan_inbox
    from memory.runtime import load_runtime_identity

    paths = synthetic_store
    (paths.inbox / "b-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    note_bytes = "合成花园记录：周五浇水。\n".encode()
    (paths.inbox / "a-synthetic-note.md").write_bytes(note_bytes)
    clock = FakeClock()

    batch = scan_inbox(paths, clock=clock)

    assert clock.sleeps == [5.0]
    assert batch.source_count == 2
    assert len(batch.source_ids) == 2
    assert batch.issues == ()
    assert batch.has_more is False
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []

    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        batches = connection.execute(
            "SELECT batch_id, sealed_at, source_count FROM inbox_batches"
        ).fetchall()
        captures = connection.execute(
            "SELECT source_id, original_name, media_type, authorship, sensitivity "
            "FROM sources ORDER BY original_name"
        ).fetchall()
        blobs = connection.execute(
            "SELECT byte_length, original_bytes, utf8_text "
            "FROM source_blobs ORDER BY byte_length DESC"
        ).fetchall()
        indexed = connection.execute(
            "SELECT source_id, utf8_text FROM source_fts"
        ).fetchall()
    finally:
        connection.close()

    assert batches == [(batch.batch_id, 1_800_000_005, 2)]
    assert [row[0] for row in captures] == list(batch.source_ids)
    assert captures == [
        (
            batch.source_ids[0],
            "a-synthetic-note.md",
            "text/markdown",
            "owner",
            "restricted",
        ),
        (
            batch.source_ids[1],
            "b-synthetic-image.png",
            "image/png",
            "owner",
            "restricted",
        ),
    ]
    assert blobs == [
        (len(note_bytes), note_bytes, "合成花园记录：周五浇水。\n"),
        (8, b"\x89PNG\r\n\x1a\n", None),
    ]
    assert indexed == [(batch.source_ids[0], "合成花园记录：周五浇水。\n")]

    with writer_session(paths):
        pass


def test_fresh_capture_binds_search_rows_to_authoritative_source_rowids(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch capture auto-assigning FTS rowids across an unsearchable gap."""
    from memory.inbox import scan_inbox
    from memory.keys import load_master_key
    from memory.runtime import load_runtime_identity

    (synthetic_store.inbox / "a-synthetic-note.md").write_text(
        "Synthetic first row.\n", encoding="utf-8"
    )
    (synthetic_store.inbox / "b-synthetic-image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (synthetic_store.inbox / "c-synthetic-note.md").write_text(
        "Synthetic third row.\n", encoding="utf-8"
    )

    scan_inbox(synthetic_store, clock=FakeClock())

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        rows = connection.execute(
            "SELECT f.rowid, f.capture_rowid, f.source_id, s.rowid "
            "FROM source_fts AS f "
            "JOIN sources AS s ON s.source_id = f.source_id "
            "ORDER BY s.rowid"
        ).fetchall()
    finally:
        connection.close()

    assert [(int(row[0]), int(row[1]), int(row[3])) for row in rows] == [
        (1, 1, 1),
        (3, 3, 3),
    ]


def test_mixed_scan_skips_changing_symlink_and_oversize_files(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch one ineligible file blocking a later safe capture or being deleted."""
    from memory.inbox import ScanPolicy, scan_inbox
    from memory.model import Issue

    changing = synthetic_store.inbox / "a-changing.txt"
    changing.write_bytes(b"old")
    (synthetic_store.inbox / "b-valid.txt").write_bytes(b"garden")
    outside = tmp_path / "synthetic-outside.txt"
    outside.write_bytes(b"outside")
    (synthetic_store.inbox / "c-link.txt").symlink_to(outside)
    (synthetic_store.inbox / "d-large.txt").write_bytes(b"123456789")

    def rewrite_changing() -> None:
        changing.write_bytes(b"newer")

    clock = FakeClock(on_sleep=rewrite_changing)
    policy = ScanPolicy(file_byte_limit=8, batch_byte_limit=32, batch_file_limit=4)

    batch = scan_inbox(synthetic_store, clock=clock, policy=policy)

    assert batch.source_count == 1
    assert batch.issues == (
        Issue(code="changed", count=1),
        Issue(code="source_too_large", count=1),
        Issue(code="symlink", count=1),
    )
    assert batch.has_more is False
    assert {path.name for path in synthetic_store.inbox.iterdir()} == {
        "a-changing.txt",
        "c-link.txt",
        "d-large.txt",
    }
    assert outside.read_bytes() == b"outside"


def test_all_oversize_scan_returns_source_too_large_without_mutation(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an all-ineligible pass publishing a batch or deleting the input."""
    from memory.errors import SourceTooLargeError
    from memory.inbox import ScanPolicy, scan_inbox

    oversized = synthetic_store.inbox / "synthetic-large.txt"
    oversized.write_bytes(b"123456789")
    policy = ScanPolicy(file_byte_limit=8, batch_byte_limit=32, batch_file_limit=4)

    with pytest.raises(SourceTooLargeError) as raised:
        scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    assert raised.value.code == "source_too_large"
    assert oversized.read_bytes() == b"123456789"


def test_batch_limits_choose_a_deterministic_maximal_set_and_continue(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch nondeterministic or prefix-only selection wasting batch capacity."""
    from memory.inbox import ScanPolicy, scan_inbox

    for name, body in (
        ("a-six.txt", b"aaaaaa"),
        ("b-six.txt", b"bbbbbb"),
        ("c-four.txt", b"cccc"),
        ("d-two.txt", b"dd"),
    ):
        (synthetic_store.inbox / name).write_bytes(body)
    policy = ScanPolicy(file_byte_limit=8, batch_byte_limit=10, batch_file_limit=2)
    clock = FakeClock()

    first = scan_inbox(synthetic_store, clock=clock, policy=policy)
    second = scan_inbox(synthetic_store, clock=clock, policy=policy)

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        names = connection.execute(
            "SELECT b.batch_id, s.original_name "
            "FROM inbox_batch_sources AS m "
            "JOIN inbox_batches AS b ON b.batch_id = m.batch_id "
            "JOIN sources AS s ON s.source_id = m.source_id "
            "ORDER BY b.rowid, m.ordinal"
        ).fetchall()
    finally:
        connection.close()

    assert first.has_more is True
    assert second.has_more is False
    assert names == [
        (first.batch_id, "a-six.txt"),
        (first.batch_id, "c-four.txt"),
        (second.batch_id, "b-six.txt"),
        (second.batch_id, "d-two.txt"),
    ]
    assert list(synthetic_store.inbox.iterdir()) == []


def test_scan_digests_only_the_files_one_batch_can_claim(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the scan reading every visible file while it holds the writer lock.

    The lock is the Store's single writer, and a scan of a large inbox held it
    for two full SHA-256 passes over files the batch cap could never take. The
    bound that matters is the batch cap, not the inbox size.
    """
    from memory import inbox

    for index in range(12):
        (synthetic_store.inbox / f"synthetic-note-{index:02d}.md").write_bytes(
            f"合成笔记 {index}\n".encode()
        )
    policy = inbox.ScanPolicy(batch_file_limit=3)
    original = inbox._digest_visible_file
    digested: list[str] = []

    def counting(
        directory_descriptor: int,
        name: str,
        expected: inbox._VisibleCandidate,
    ) -> str:
        digested.append(name)
        return original(directory_descriptor, name, expected)

    monkeypatch.setattr(inbox, "_digest_visible_file", counting)

    batch = inbox.scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    assert batch.source_count == 3
    assert batch.has_more is True
    assert digested == [f"synthetic-note-{index:02d}.md" for index in range(3)]


def test_changed_digest_attempts_consume_the_batch_file_budget(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch changed candidates yielding unbounded extra digest attempts."""
    from memory import inbox
    from memory.model import Issue

    names = [f"synthetic-attempt-{index}.txt" for index in range(6)]
    for name in names:
        (synthetic_store.inbox / name).write_bytes(b"settled")
    policy = inbox.ScanPolicy(batch_file_limit=3)
    original = inbox._digest_visible_file
    attempted: list[str] = []

    def change_early_candidates(
        directory_descriptor: int,
        name: str,
        expected: inbox._VisibleCandidate,
    ) -> str:
        attempted.append(name)
        if name in names[:2]:
            (synthetic_store.inbox / name).write_bytes(b"changed-after-snapshot")
        return original(directory_descriptor, name, expected)

    monkeypatch.setattr(inbox, "_digest_visible_file", change_early_candidates)

    batch = inbox.scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    assert attempted == names[:3]
    assert batch.source_count == 1
    assert batch.issues == (Issue(code="changed", count=2),)
    assert batch.has_more is True
    assert {path.name for path in synthetic_store.inbox.iterdir()} == {
        names[0],
        names[1],
        names[3],
        names[4],
        names[5],
    }


def test_changed_digest_attempts_charge_the_settled_expected_bytes(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch changed candidates escaping the attempted-byte work budget."""
    from memory import inbox
    from memory.model import Issue

    changed = synthetic_store.inbox / "a-changed.txt"
    selected = synthetic_store.inbox / "b-selected.txt"
    deferred = synthetic_store.inbox / "c-deferred.txt"
    changed.write_bytes(b"aaaaaa")
    selected.write_bytes(b"bbbb")
    deferred.write_bytes(b"c")
    policy = inbox.ScanPolicy(
        file_byte_limit=6,
        batch_byte_limit=10,
        batch_file_limit=4,
    )
    original = inbox._digest_visible_file
    attempted: list[str] = []

    def change_first_candidate(
        directory_descriptor: int,
        name: str,
        expected: inbox._VisibleCandidate,
    ) -> str:
        attempted.append(name)
        if name == changed.name:
            changed.write_bytes(b"changed-after-snapshot")
        return original(directory_descriptor, name, expected)

    monkeypatch.setattr(inbox, "_digest_visible_file", change_first_candidate)

    batch = inbox.scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    assert attempted == [changed.name, selected.name]
    assert batch.source_count == 1
    assert batch.issues == (Issue(code="changed", count=1),)
    assert batch.has_more is True
    assert {path.name for path in synthetic_store.inbox.iterdir()} == {
        changed.name,
        deferred.name,
    }
    assert deferred.read_bytes() == b"c"


def test_equal_bytes_deduplicate_blob_but_not_capture_metadata(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch byte dedup collapsing provenance or lowering prior sensitivity."""
    from memory.inbox import scan_inbox

    body = b"synthetic duplicate bytes"
    (synthetic_store.inbox / "first.txt").write_bytes(body)
    first = scan_inbox(
        synthetic_store,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    (synthetic_store.inbox / "second.bin").write_bytes(body)
    second = scan_inbox(
        synthetic_store,
        authorship=Authorship.EXTERNAL,
        sensitivity=Sensitivity.RESTRICTED,
        clock=FakeClock(),
    )

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        blob_count = connection.execute("SELECT count(*) FROM source_blobs").fetchone()
        rows = connection.execute(
            "SELECT source_id, original_name, media_type, authorship, sensitivity, "
            "blob_id FROM sources ORDER BY rowid"
        ).fetchall()
    finally:
        connection.close()

    assert blob_count == (1,)
    assert rows == [
        (
            first.source_ids[0],
            "first.txt",
            "text/plain",
            "owner",
            "normal",
            rows[0][5],
        ),
        (
            second.source_ids[0],
            "second.bin",
            "application/octet-stream",
            "external",
            "restricted",
            rows[0][5],
        ),
    ]


def test_crash_before_database_commit_recovers_the_same_batch_id(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch pre-commit recovery minting a new batch or losing claimed bytes."""
    import memory.inbox as inbox
    from memory.database import _writer_transaction as original_writer_transaction

    class SyntheticCrash(RuntimeError):
        pass

    @contextmanager
    def crash_before_publish(_paths: RuntimePaths) -> Iterator[Connection]:
        # Scheduling now has its own bounded encrypted transactions before
        # custody. Inject only at the original publication seam: a complete
        # claimed source exists, but no source transaction has begun.
        if any(synthetic_store.inbox_claims.iterdir()):
            raise SyntheticCrash("synthetic crash before database commit")
        with original_writer_transaction(_paths) as connection:
            yield connection

    source = synthetic_store.inbox / "synthetic-recovery.txt"
    source.write_bytes(b"recoverable synthetic bytes")
    monkeypatch.setattr(inbox, "_writer_transaction", crash_before_publish)

    with pytest.raises(SyntheticCrash):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    claim_directories = list(synthetic_store.inbox_claims.iterdir())
    assert len(claim_directories) == 1
    claimed_batch_id = claim_directories[0].name
    assert not source.exists()

    monkeypatch.setattr(inbox, "_writer_transaction", original_writer_transaction)
    recovery_clock = FakeClock()
    recovered = inbox.scan_inbox(synthetic_store, clock=recovery_clock)

    assert recovered.batch_id == claimed_batch_id
    assert recovery_clock.sleeps == []
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_crash_after_database_commit_reuses_publication_and_cleans_claim(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch post-commit cleanup failure producing duplicate captures."""
    import memory.inbox as inbox

    class SyntheticCrash(RuntimeError):
        pass

    crashed = False

    def crash_first_source_cleanup(checkpoint: str) -> None:
        nonlocal crashed
        if checkpoint == "claim.cleanup.source_unlink" and not crashed:
            crashed = True
            raise SyntheticCrash("synthetic crash after database commit")

    source = synthetic_store.inbox / "synthetic-after-commit.txt"
    source.write_bytes(b"published once")
    monkeypatch.setattr(inbox, "_checkpoint", crash_first_source_cleanup)

    with pytest.raises(SyntheticCrash):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        committed = connection.execute(
            "SELECT batch_id, source_count FROM inbox_batches"
        ).fetchall()
    finally:
        connection.close()
    assert len(committed) == 1
    assert list(synthetic_store.inbox_claims.iterdir())

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovery_clock = FakeClock()
    recovered = inbox.scan_inbox(synthetic_store, clock=recovery_clock)

    assert (recovered.batch_id, recovered.source_count) == committed[0]
    assert recovery_clock.sleeps == []
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources)"
        ).fetchone()
    finally:
        connection.close()
    assert counts == (1, 1)
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_manifest_loss_after_commit_preserves_exact_scan_response_metadata(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch late cleanup recovery dropping warnings or deferred-work state."""
    import memory.inbox as inbox
    from memory.model import Issue
    from memory.sources import list_batches, read_batch

    class SyntheticCrash(RuntimeError):
        pass

    outside = tmp_path / "synthetic-warning-target.txt"
    outside.write_bytes(b"warning target")
    (synthetic_store.inbox / "a-selected.txt").write_bytes(b"selected")
    deferred = synthetic_store.inbox / "b-deferred.txt"
    deferred.write_bytes(b"deferred")
    warning = synthetic_store.inbox / "c-warning-link.txt"
    warning.symlink_to(outside)
    policy = inbox.ScanPolicy(batch_file_limit=1)
    crashed = False

    def crash_after_manifest_unlink(checkpoint: str) -> None:
        nonlocal crashed
        if checkpoint == "claim.cleanup.manifest_unlink" and not crashed:
            crashed = True
            raise SyntheticCrash("late synthetic cleanup crash")

    monkeypatch.setattr(inbox, "_checkpoint", crash_after_manifest_unlink)
    with pytest.raises(SyntheticCrash, match="late synthetic cleanup crash"):
        inbox.scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        committed = connection.execute(
            "SELECT batch_id, sealed_at, source_count FROM inbox_batches"
        ).fetchone()
        assert committed is not None
        source_ids = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT source_id FROM inbox_batch_sources "
                "WHERE batch_id = ? ORDER BY ordinal",
                (str(committed[0]),),
            ).fetchall()
        )
    finally:
        connection.close()

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock(), policy=policy)

    assert (
        recovered.batch_id,
        recovered.sealed_at,
        recovered.source_count,
        recovered.source_ids,
    ) == (str(committed[0]), int(committed[1]), int(committed[2]), source_ids)
    assert recovered.has_more is True
    assert recovered.issues == (Issue(code="symlink", count=1),)
    assert read_batch(synthetic_store, recovered.batch_id).batch == recovered
    assert list_batches(synthetic_store).items == (recovered,)
    assert deferred.read_bytes() == b"deferred"
    assert warning.is_symlink()


def test_custody_replacement_crash_restores_the_producer_object(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a checked source replacement being dropped and cleanup-deleted."""
    import memory.inbox as inbox
    from memory.errors import NoEligibleSourcesError

    class SyntheticCrash(RuntimeError):
        pass

    source_name = "synthetic-custody-race.txt"
    source = synthetic_store.inbox / source_name
    source.write_bytes(b"settled original")
    replacement = synthetic_store.root / "synthetic-producer-replacement.tmp"
    replacement.write_bytes(b"producer replacement")
    replacement_identity = (replacement.stat().st_dev, replacement.stat().st_ino)
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )
    original_stat_entry = inbox._stat_entry
    inbox_observations = 0
    replaced = False

    def replace_after_identity_check(descriptor: int, name: str) -> object:
        nonlocal inbox_observations, replaced
        metadata = original_stat_entry(descriptor, name)
        descriptor_metadata = os.fstat(descriptor)
        if (
            name == source_name
            and (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
            == inbox_identity
            and metadata is not None
        ):
            inbox_observations += 1
            if inbox_observations == 3:
                replacement.replace(source)
                replaced = True
        return metadata

    crashed = False

    def crash_after_source_move(checkpoint: str) -> None:
        nonlocal crashed
        if checkpoint == "claim.custody.source_rename" and not crashed:
            crashed = True
            raise SyntheticCrash("synthetic custody crash")

    monkeypatch.setattr(inbox, "_stat_entry", replace_after_identity_check)
    monkeypatch.setattr(inbox, "_checkpoint", crash_after_source_move)
    with pytest.raises(SyntheticCrash, match="synthetic custody crash"):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert replaced is True
    claim_paths = list(synthetic_store.inbox_claims.iterdir())
    assert len(claim_paths) == 1
    claimed_replacement = claim_paths[0] / "files" / source_name
    assert claimed_replacement.read_bytes() == b"producer replacement"
    assert (
        claimed_replacement.stat().st_dev,
        claimed_replacement.stat().st_ino,
    ) == replacement_identity

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    with pytest.raises(NoEligibleSourcesError):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert source.read_bytes() == b"producer replacement"
    assert (source.stat().st_dev, source.stat().st_ino) == replacement_identity
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_restore_collision_preserves_both_objects_and_retries_safely(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch check-then-rename restore overwriting a new inbox object."""
    import memory.inbox as inbox
    from memory.errors import NoEligibleSourcesError, StoreBusyError
    from memory.inbox import _Capture, _VisibleFile

    source_name = "synthetic-restore-race.txt"
    source = synthetic_store.inbox / source_name
    source.write_bytes(b"claimed original")
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )
    original_read_unchanged = inbox._read_unchanged
    original_stat_entry = inbox._stat_entry
    mutated = False
    collided = False
    collision_identity: tuple[int, int] | None = None

    def mutate_before_capture(
        descriptor: int,
        visible: _VisibleFile,
    ) -> _Capture:
        nonlocal mutated
        if visible.name == source_name and not mutated:
            write_descriptor = os.open(
                source_name,
                os.O_WRONLY | os.O_APPEND,
                dir_fd=descriptor,
            )
            try:
                os.write(write_descriptor, b" changed")
                os.fsync(write_descriptor)
            finally:
                os.close(write_descriptor)
            mutated = True
        return original_read_unchanged(descriptor, visible)

    def collide_after_destination_check(
        descriptor: int, name: str
    ) -> os.stat_result | None:
        nonlocal collided, collision_identity
        metadata = original_stat_entry(descriptor, name)
        descriptor_metadata = os.fstat(descriptor)
        if (
            mutated
            and not collided
            and name == source_name
            and metadata is None
            and (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
            == inbox_identity
        ):
            collision_descriptor = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=descriptor,
            )
            try:
                os.write(collision_descriptor, b"producer collision")
                os.fsync(collision_descriptor)
                collision_metadata = os.fstat(collision_descriptor)
                collision_identity = (
                    collision_metadata.st_dev,
                    collision_metadata.st_ino,
                )
            finally:
                os.close(collision_descriptor)
            collided = True
        return metadata

    monkeypatch.setattr(inbox, "_read_unchanged", mutate_before_capture)
    monkeypatch.setattr(inbox, "_stat_entry", collide_after_destination_check)
    with pytest.raises(StoreBusyError):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert collided is True
    assert source.read_bytes() == b"producer collision"
    assert (source.stat().st_dev, source.stat().st_ino) == collision_identity
    claim_paths = list(synthetic_store.inbox_claims.iterdir())
    assert len(claim_paths) == 1
    claimed_source = claim_paths[0] / "files" / source_name
    assert claimed_source.read_bytes() == b"claimed original changed"
    assert (claimed_source.stat().st_dev, claimed_source.stat().st_ino) == (
        source_identity
    )

    source.unlink()
    monkeypatch.setattr(inbox, "_read_unchanged", original_read_unchanged)
    monkeypatch.setattr(inbox, "_stat_entry", original_stat_entry)
    with pytest.raises(NoEligibleSourcesError):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert source.read_bytes() == b"claimed original changed"
    assert (source.stat().st_dev, source.stat().st_ino) == source_identity
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_scan_writer_lock_covers_claim_recovery_through_cleanup(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch concurrent scans mutating custody before either owns the writer lock."""
    import memory.inbox as inbox
    from memory.errors import StoreBusyError

    class SyntheticCrash(RuntimeError):
        pass

    (synthetic_store.inbox / "synthetic-concurrent.txt").write_bytes(
        b"one recoverable source"
    )
    ready = threading.Event()
    release = threading.Event()
    worker_ident: list[int] = []
    worker_errors: list[BaseException] = []

    def pause_then_crash_before_commit(checkpoint: str) -> None:
        if (
            checkpoint == "claim.capture.manifest_dir_fsync"
            and worker_ident
            and threading.get_ident() == worker_ident[0]
        ):
            ready.set()
            if not release.wait(timeout=10):
                raise AssertionError("synthetic concurrent scan was not released")
            raise SyntheticCrash("synthetic pre-commit crash")

    def run_first_scan() -> None:
        worker_ident.append(threading.get_ident())
        try:
            inbox.scan_inbox(synthetic_store, clock=FakeClock())
        except BaseException as error:
            worker_errors.append(error)

    monkeypatch.setattr(inbox, "_checkpoint", pause_then_crash_before_commit)
    worker = threading.Thread(target=run_first_scan)
    worker.start()
    assert ready.wait(timeout=10)
    artifacts_before = tuple(
        sorted(path.name for path in synthetic_store.inbox_claims.iterdir())
    )
    assert len(artifacts_before) == 1
    try:
        with pytest.raises(StoreBusyError) as raised:
            inbox.scan_inbox(synthetic_store, clock=FakeClock())
        assert raised.value.code == "busy"
        assert (
            tuple(sorted(path.name for path in synthetic_store.inbox_claims.iterdir()))
            == artifacts_before
        )
    finally:
        release.set()
        worker.join(timeout=10)

    assert not worker.is_alive()
    assert len(worker_errors) == 1
    assert isinstance(worker_errors[0], SyntheticCrash)
    assert (
        tuple(sorted(path.name for path in synthetic_store.inbox_claims.iterdir()))
        == artifacts_before
    )

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock())
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources)"
        ).fetchone()
    finally:
        connection.close()
    assert recovered.source_count == 1
    assert counts == (1, 1)
    assert list(synthetic_store.inbox_claims.iterdir()) == []


@pytest.mark.parametrize(
    "checkpoint",
    [
        "claim.create.temp_mkdir",
        "claim.create.temp_parent_fsync",
        "claim.create.files_mkdir",
        "claim.create.files_parent_fsync",
        "claim.create.manifest_file_fsync",
        "claim.create.manifest_replace",
        "claim.create.manifest_dir_fsync",
        "claim.create.publish_rename",
        "claim.create.publish_dir_fsync",
        "claim.custody.source_rename",
        "claim.custody.inbox_dir_fsync",
        "claim.custody.files_dir_fsync",
        "claim.custody.manifest_file_fsync",
        "claim.custody.manifest_replace",
        "claim.custody.manifest_dir_fsync",
        "claim.capture.manifest_file_fsync",
        "claim.capture.manifest_replace",
        "claim.capture.manifest_dir_fsync",
    ],
)
def test_each_claim_publication_boundary_is_crash_recoverable(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    """Catch a durable partial claim permanently blocking the inbox."""
    import memory.inbox as inbox

    class SyntheticCrash(RuntimeError):
        pass

    crashed = False

    def crash_once(observed: str) -> None:
        nonlocal crashed
        if observed == checkpoint and not crashed:
            crashed = True
            raise SyntheticCrash(checkpoint)

    source = synthetic_store.inbox / "synthetic-boundary.txt"
    source.write_bytes(b"recover exactly once")
    monkeypatch.setattr(inbox, "_checkpoint", crash_once)

    with pytest.raises(SyntheticCrash, match=checkpoint):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert crashed is True

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock())

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources)"
        ).fetchone()
    finally:
        connection.close()
    assert recovered.source_count == 1
    assert counts == (1, 1)
    assert not source.exists()
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_ordinary_scan_claim_uses_strict_v2_custody_and_origin_manifest(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch legacy claim serialization dropping identity or origin metadata."""
    import memory.inbox as inbox

    class SyntheticCrash(RuntimeError):
        pass

    body = b"Synthetic ordinary v2 claim bytes.\n"
    source = synthetic_store.inbox / "synthetic-v2-claim.md"
    source.write_bytes(body)

    def stop_after_capture_manifest(checkpoint: str) -> None:
        if checkpoint == "claim.capture.manifest_dir_fsync":
            raise SyntheticCrash(checkpoint)

    monkeypatch.setattr(inbox, "_checkpoint", stop_after_capture_manifest)
    with pytest.raises(
        SyntheticCrash, match=re.escape("claim.capture.manifest_dir_fsync")
    ):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    claims = tuple(synthetic_store.inbox_claims.iterdir())
    assert len(claims) == 1
    manifest = json.loads((claims[0] / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest) == {
        "authorship",
        "batch_id",
        "capture_request_id",
        "captured_at",
        "custody_kind",
        "entries",
        "exact_metadata",
        "format",
        "has_more",
        "issues",
        "sensitivity",
        "source_origin",
    }
    assert manifest["format"] == "memory.inbox-claim.v2"
    assert manifest["custody_kind"] == "inbox_scan"
    assert manifest["source_origin"] == "inbox"
    assert manifest["capture_request_id"] is None
    assert manifest["exact_metadata"] is None
    assert manifest["captured_at"] == 1_800_000_005
    assert manifest["authorship"] == "owner"
    assert manifest["sensitivity"] == "restricted"
    assert len(manifest["entries"]) == 1
    entry = manifest["entries"][0]
    assert set(entry) == {
        "byte_length",
        "device",
        "entry_id",
        "inode",
        "modified_ns",
        "name",
        "sha256",
    }
    assert entry["entry_id"].startswith("ise_")
    assert entry["name"] == source.name
    assert entry["byte_length"] == len(body)
    assert entry["sha256"] == hashlib.sha256(body).hexdigest()

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert recovered.batch_id == manifest["batch_id"]
    assert list(synthetic_store.inbox_claims.iterdir()) == []


@pytest.mark.parametrize(
    "checkpoint",
    [
        "claim.cleanup.hide_rename",
        "claim.cleanup.claims_dir_fsync",
        "claim.cleanup.source_unlink",
        "claim.cleanup.files_dir_fsync",
        "claim.cleanup.files_rmdir",
        "claim.cleanup.claim_dir_fsync_after_files",
        "claim.cleanup.manifest_unlink",
        "claim.cleanup.claim_dir_fsync_after_manifest",
    ],
)
def test_each_claim_cleanup_boundary_is_crash_recoverable(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    """Catch partial cleanup hiding or corrupting an already committed batch."""
    import memory.inbox as inbox

    class SyntheticCrash(RuntimeError):
        pass

    crashed = False

    def crash_once(observed: str) -> None:
        nonlocal crashed
        if observed == checkpoint and not crashed:
            crashed = True
            raise SyntheticCrash(checkpoint)

    (synthetic_store.inbox / "synthetic-cleanup.txt").write_bytes(b"one commit")
    monkeypatch.setattr(inbox, "_checkpoint", crash_once)

    with pytest.raises(SyntheticCrash, match=checkpoint):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert crashed is True

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock())

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources)"
        ).fetchone()
    finally:
        connection.close()
    assert recovered.source_count == 1
    assert counts == (1, 1)
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_inbox_directory_path_escape_is_typed_and_never_followed(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch the scanner following a replaced inbox directory outside runtime."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    original_inbox = synthetic_store.root / "detached-synthetic-inbox"
    synthetic_store.inbox.rename(original_inbox)
    outside = tmp_path / "synthetic-outside-directory"
    outside.mkdir()
    outside_source = outside / "synthetic-outside.txt"
    outside_source.write_bytes(b"must remain outside")
    synthetic_store.inbox.symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidArgumentError) as raised:
        scan_inbox(synthetic_store, clock=FakeClock())

    assert raised.value.code == "invalid_argument"
    assert "synthetic-outside" not in str(raised.value)
    assert outside_source.read_bytes() == b"must remain outside"


def test_symlinked_runtime_root_is_rejected_without_outside_mutation(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch leaf-only O_NOFOLLOW checks traversing a symlinked Store root."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    source_name = "synthetic-root-link.txt"
    (synthetic_store.inbox / source_name).write_bytes(b"outside stays intact")
    detached_root = tmp_path / "detached-synthetic-root"
    synthetic_store.root.rename(detached_root)
    synthetic_store.root.symlink_to(detached_root, target_is_directory=True)

    with pytest.raises(InvalidArgumentError) as raised:
        scan_inbox(synthetic_store, clock=FakeClock())

    assert raised.value.code == "invalid_argument"
    assert (detached_root / "inbox" / source_name).read_bytes() == (
        b"outside stays intact"
    )
    assert list((detached_root / "inbox-claims").iterdir()) == []


def test_symlinked_runtime_ancestor_is_rejected_without_outside_mutation(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch a safe leaf reached through an unsafe ancestor component."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    selected_parent = tmp_path / "selected-synthetic-parent"
    paths = resolve_runtime(selected_parent / "store")
    initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    source_name = "synthetic-ancestor-link.txt"
    (paths.inbox / source_name).write_bytes(b"ancestor target stays intact")
    detached_parent = tmp_path / "detached-synthetic-parent"
    selected_parent.rename(detached_parent)
    selected_parent.symlink_to(detached_parent, target_is_directory=True)

    with pytest.raises(InvalidArgumentError) as raised:
        scan_inbox(paths, clock=FakeClock())

    assert raised.value.code == "invalid_argument"
    assert (detached_parent / "store" / "inbox" / source_name).read_bytes() == (
        b"ancestor target stays intact"
    )
    assert list((detached_parent / "store" / "inbox-claims").iterdir()) == []


def test_replaced_runtime_root_during_settle_is_rejected_before_mutation(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch a post-open root replacement redirecting claim or database writes."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    source_name = "synthetic-replaced-root.txt"
    (synthetic_store.inbox / source_name).write_bytes(b"detached root stays intact")
    detached_root = tmp_path / "settle-detached-synthetic-root"

    def replace_root() -> None:
        synthetic_store.root.rename(detached_root)
        synthetic_store.root.symlink_to(detached_root, target_is_directory=True)

    with pytest.raises(InvalidArgumentError) as raised:
        scan_inbox(synthetic_store, clock=FakeClock(on_sleep=replace_root))

    assert raised.value.code == "invalid_argument"
    assert (detached_root / "inbox" / source_name).read_bytes() == (
        b"detached root stays intact"
    )
    assert list((detached_root / "inbox-claims").iterdir()) == []


def test_replaced_runtime_ancestor_during_settle_is_rejected_before_mutation(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch ancestor replacement after discovery but before source custody."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    selected_parent = tmp_path / "settle-selected-synthetic-parent"
    paths = resolve_runtime(selected_parent / "store")
    initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    source_name = "synthetic-replaced-ancestor.txt"
    (paths.inbox / source_name).write_bytes(b"detached ancestor stays intact")
    detached_parent = tmp_path / "settle-detached-synthetic-parent"

    def replace_ancestor() -> None:
        selected_parent.rename(detached_parent)
        selected_parent.symlink_to(detached_parent, target_is_directory=True)

    with pytest.raises(InvalidArgumentError) as raised:
        scan_inbox(paths, clock=FakeClock(on_sleep=replace_ancestor))

    assert raised.value.code == "invalid_argument"
    assert (detached_parent / "store" / "inbox" / source_name).read_bytes() == (
        b"detached ancestor stays intact"
    )
    assert list((detached_parent / "store" / "inbox-claims").iterdir()) == []


def test_file_changed_while_streaming_is_restored_and_does_not_block_later_file(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch custody trusting only the pre-read stat or aborting later files."""
    import memory.inbox as inbox
    from memory.model import Issue

    changing = synthetic_store.inbox / "a-stream-changing.txt"
    changing.write_bytes(b"a" * (1024 * 1024 + 1))
    changing_inode = changing.stat().st_ino
    write_descriptor = os.open(changing, os.O_WRONLY | os.O_APPEND)
    (synthetic_store.inbox / "b-stable.txt").write_bytes(b"stable")
    original_read = os.read
    changed = False

    def mutate_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed and os.fstat(descriptor).st_ino == changing_inode:
            os.write(write_descriptor, b"x")
            os.fsync(write_descriptor)
            changed = True
        return chunk

    monkeypatch.setattr(os, "read", mutate_after_first_chunk)
    try:
        batch = inbox.scan_inbox(synthetic_store, clock=FakeClock())
    finally:
        os.close(write_descriptor)

    assert changed is True
    assert batch.source_count == 1
    assert batch.issues == (Issue(code="changed", count=1),)
    assert changing.is_file()
    assert changing.stat().st_size == 1024 * 1024 + 2


def test_external_inbox_scan_claims_and_removes_originals(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch external-inbox custody diverging from the default child inbox."""
    from memory.inbox import scan_inbox
    from memory.runtime import initialize_runtime, resolve_runtime

    external = tmp_path / "Documents" / "Inbox"
    external.parent.mkdir()
    home = tmp_path / "external-store"
    initialize_runtime(
        resolve_runtime(home),
        mode=model.RuntimeMode.PERSONAL,
        inbox=external,
    )
    paths = resolve_runtime(home)
    assert paths.inbox == external
    (external / "phone-note.md").write_text(
        "# Synthetic phone note\n", encoding="utf-8"
    )
    (external / "second-note.txt").write_text("synthetic body\n", encoding="utf-8")

    batch = scan_inbox(paths, clock=FakeClock())

    assert batch.source_count == 2
    assert batch.issues == ()
    assert list(external.iterdir()) == []
    assert not (paths.root / "inbox").exists()


def test_hidden_files_are_silently_ignored_by_scan_and_counting(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch OS metadata like .DS_Store entering permanent Store custody."""
    from memory.inbox import count_visible_inbox_entries, scan_inbox

    (synthetic_store.inbox / ".DS_Store").write_bytes(b"synthetic finder noise")
    (synthetic_store.inbox / ".note.md.icloud").write_bytes(b"synthetic placeholder")
    (synthetic_store.inbox / "visible.md").write_text(
        "synthetic visible note\n", encoding="utf-8"
    )

    assert count_visible_inbox_entries(synthetic_store) == 1
    batch = scan_inbox(synthetic_store, clock=FakeClock())

    assert batch.source_count == 1
    assert batch.issues == ()
    assert {path.name for path in synthetic_store.inbox.iterdir()} == {
        ".DS_Store",
        ".note.md.icloud",
    }


def test_staged_entry_names_may_not_be_hidden(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a staged upload that scanning would silently never capture."""
    from memory.errors import InvalidArgumentError
    from memory.inbox import stage_inbox_entry

    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename=".hidden-note.md",
            chunks=(b"synthetic body\n",),
        )
    assert list(synthetic_store.inbox.iterdir()) == []


def _abandoned_stage_slot(paths: RuntimePaths, index: int) -> Path:
    """Write one zero-length `ent_*.stage` tombstone of the shape a crash leaves."""
    slot = paths.inbox_staging / f"ent_{index:032x}.stage"
    slot.write_bytes(b"")
    slot.chmod(0o600)
    return slot


def test_recovery_reclaims_crash_orphaned_staging_slots(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch abandoned reservations disabling owner uploads permanently.

    Eight is the whole global staging bound, so eight tombstones left by
    processes that died between reserving a slot and writing to it are not a
    degraded state the owner can wait out -- every future upload fails until
    something removes them.
    """
    from memory.errors import InvalidArgumentError
    from memory.inbox import recover_exact_staged_entries, stage_inbox_entry

    orphans = [_abandoned_stage_slot(synthetic_store, index) for index in range(8)]

    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename="synthetic-blocked.md",
            chunks=(b"blocked owner bytes\n",),
        )

    recover_exact_staged_entries(synthetic_store)

    assert [orphan.name for orphan in orphans if orphan.exists()] == []
    published = stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-unblocked.md",
        chunks=("再次可以上传。\n".encode(),),
    )

    assert published.display_name == "synthetic-unblocked.md"
    assert (synthetic_store.inbox / "synthetic-unblocked.md").read_bytes() == (
        "再次可以上传。\n".encode()
    )


def test_recovery_leaves_every_unproven_staging_slot_in_place(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch reclamation removing a slot it has not proved is abandoned.

    A slot an upload still holds, one that already has bytes in it, and one a
    ready manifest names are three different live states. Removing any of
    them is destroying owner custody to free a reservation.
    """
    import fcntl

    from memory.inbox import recover_exact_staged_entries

    held = _abandoned_stage_slot(synthetic_store, 1)
    occupied = _abandoned_stage_slot(synthetic_store, 2)
    occupied.write_bytes(b"partial owner bytes")
    announced = _abandoned_stage_slot(synthetic_store, 3)
    (synthetic_store.inbox_staging / (announced.name + ".ready.json")).write_bytes(
        b"{}\n"
    )
    descriptor = os.open(held, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

        recover_exact_staged_entries(synthetic_store)
    finally:
        os.close(descriptor)

    assert held.read_bytes() == b""
    assert occupied.read_bytes() == b"partial owner bytes"
    assert announced.read_bytes() == b""


def test_two_active_claims_are_reported_and_not_only_raised(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a permanently wedged scanner the owner report says nothing about.

    A second published claim directory makes every later scan refuse with one
    opaque error, forever. Resolving it is the owner's decision -- choosing a
    claim would be the Store deciding which of two batches was real -- but the
    report the owner actually reads has to name the condition.
    """
    from memory import inbox as inbox_module
    from memory.errors import InvalidArgumentError

    class SyntheticCrash(RuntimeError):
        pass

    (synthetic_store.inbox / "synthetic-claimed.md").write_bytes(b"claimed bytes\n")
    crashed = False

    def crash_once(checkpoint: str) -> None:
        nonlocal crashed
        if checkpoint == "claim.capture.manifest_replace" and not crashed:
            crashed = True
            raise SyntheticCrash("synthetic claim crash")

    monkeypatch.setattr(inbox_module, "_checkpoint", crash_once)
    with pytest.raises(SyntheticCrash, match="synthetic claim crash"):
        inbox_module.scan_inbox(synthetic_store, clock=FakeClock())
    monkeypatch.setattr(inbox_module, "_checkpoint", lambda name: None)

    assert len(list(synthetic_store.inbox_claims.iterdir())) == 1
    stranded = synthetic_store.inbox_claims / f"bat_{'0e' * 16}"
    stranded.mkdir()

    with pytest.raises(InvalidArgumentError, match="multiple active claims"):
        inbox_module.scan_inbox(synthetic_store, clock=FakeClock())

    issues = inbox_module.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )

    assert [issue.code for issue in issues.items] == ["ambiguous_claim"] * 2
    assert len({issue.issue_id for issue in issues.items}) == 2
    assert len(list(synthetic_store.inbox_claims.iterdir())) == 2


def test_scan_names_the_earlier_capture_of_bytes_already_in_custody(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a re-dropped file silently generating redundant review work.

    An inbox synchronized across devices re-delivers the same note routinely.
    Byte deduplication already keeps one blob, but the review workflow only
    sees a new capture, so the agent drafts the same memory a second time
    unless the scan says whose bytes these already were.
    """
    from memory.inbox import scan_inbox
    from memory.model import DuplicateCapture

    body = "合成重复笔记：同样的字节。\n".encode()
    (synthetic_store.inbox / "first.md").write_bytes(body)
    first = scan_inbox(synthetic_store, clock=FakeClock())

    (synthetic_store.inbox / "b-distinct.md").write_bytes("另一段文字。\n".encode())
    (synthetic_store.inbox / "c-second.md").write_bytes(body)
    second = scan_inbox(synthetic_store, clock=FakeClock())

    assert first.duplicates == ()
    assert second.source_count == 2
    assert second.duplicates == (
        DuplicateCapture(
            source_id=second.source_ids[1],
            duplicate_of=first.source_ids[0],
        ),
    )


@pytest.fixture
def crashable_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RuntimePaths]:
    """A disposable Store a child interpreter can reopen after killing itself.

    The correction-handoff barriers are fsyncs, and an exception raised at one
    only proves the interpreter can unwind. Proving durability means killing
    the process outright, which means a child -- and a child inherits neither
    this fixture's in-memory Keychain nor its runtime. Both are handed over
    explicitly, so the child can never resolve the owner's real Store.
    """
    yield from make_synthetic_store(
        tmp_path,
        monkeypatch,
        export_keychain_item=SYNTHETIC_KEYCHAIN_ITEM,
    )


def _synthetic_keyring_prelude(paths: RuntimePaths) -> str:
    """Rebuild this fixture's synthetic Keychain inside a child interpreter.

    The item travels through the environment rather than the command line so
    that no key material is ever placed in a process argument list.
    """
    identity = load_runtime_identity(paths)
    return f"""
import os as _os

import keyring as _keyring

_items = {{
    ({KEYCHAIN_SERVICE!r}, {identity.store_id!r}): _os.environ[
        {SYNTHETIC_KEYCHAIN_ITEM!r}
    ]
}}
_backend = type("Keyring", (), {{}})()
type(_backend).__module__ = "keyring.backends.macOS"
_keyring.get_keyring = lambda: _backend
_keyring.get_password = lambda service, account: _items.get((service, account))
_keyring.set_password = lambda service, account, value: _items.__setitem__(
    (service, account), value
)
_keyring.delete_password = lambda service, account: _items.pop((service, account))

from memory import keys as _keys

def _unexpected_synthetic_key_creation(identity, encoded):
    raise AssertionError("a scan must never create a Store key")

_keys._store_master_key_exclusive = _unexpected_synthetic_key_creation
"""


def _owner_correction_payload(
    paths: RuntimePaths,
    *,
    marker: str,
    captured_at: int = 1_900_000_000,
) -> tuple[bytes, model.ExactCaptureMetadata]:
    """Author one synthetic owner correction and the metadata that binds it.

    The lineage the correction targets and the head it expects live nowhere
    but these bytes once the handoff owns them, which is why the crash tests
    below read them back out of the payload rather than out of the manifest.
    """
    identity = load_runtime_identity(paths)
    lineage_id = "lin_" + marker * 32
    expected_head_id = "mem_" + marker * 32
    recorded_at = (
        datetime.fromtimestamp(captured_at, UTC).isoformat().replace("+00:00", "Z")
    )
    body = (
        "---\n"
        "format: memory.owner-correction.v1\n"
        f"store_id: {identity.store_id}\n"
        f"target_lineage_id: {lineage_id}\n"
        f"expected_head_id: {expected_head_id}\n"
        f"recorded_at: {recorded_at}\n"
        "---\n"
        "# Owner correction\n\n"
        f"合成纠正 {marker}：手记应改为周六浇水。\n"
    ).encode()
    return body, model.ExactCaptureMetadata(
        capture_request_id="cap_" + marker * 32,
        batch_id="bat_" + marker * 32,
        captured_at=captured_at,
        target_lineage_id=lineage_id,
        expected_head_id=expected_head_id,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=model.SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )


def _crash_correction_handoff(
    paths: RuntimePaths,
    *,
    body: bytes,
    metadata: model.ExactCaptureMetadata,
    checkpoint: str,
) -> subprocess.CompletedProcess[str]:
    """Hand one ambiguous correction to private recovery in a child that dies.

    Exit 86 is the kill at `checkpoint`, 0 is a handoff that reported durable
    without reaching it, and 70 is one that refused. Distinguishing them is
    the difference between a crash test and a test that only proves the
    process is mortal.
    """
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
import os
from pathlib import Path

import memory.inbox as inbox
from memory.model import (
    Authorship,
    ExactCaptureMetadata,
    Sensitivity,
    SourceCaptureOrigin,
)
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
metadata = ExactCaptureMetadata(
    capture_request_id={metadata.capture_request_id!r},
    batch_id={metadata.batch_id!r},
    captured_at={metadata.captured_at!r},
    target_lineage_id={metadata.target_lineage_id!r},
    expected_head_id={metadata.expected_head_id!r},
    payload_sha256={metadata.payload_sha256!r},
    source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
    authorship=Authorship.OWNER,
    sensitivity=Sensitivity.RESTRICTED,
)
inbox._checkpoint = lambda name: os._exit(86) if name == {checkpoint!r} else None
preserved = inbox.preserve_exact_correction_handoff(
    paths,
    source_bytes=base64.b64decode({encoded!r}),
    metadata=metadata,
)
os._exit(0 if preserved else 70)
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _crash_exact_staging(
    paths: RuntimePaths,
    *,
    body: bytes,
    metadata: model.ExactCaptureMetadata,
    checkpoint: str,
) -> subprocess.CompletedProcess[str]:
    """Stage one exact correction in a child that dies at `checkpoint`.

    Exit 86 is the kill; 0 means staging finished without ever reaching the
    barrier, which would make everything asserted afterwards meaningless.
    """
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
import os
from pathlib import Path

import memory.inbox as inbox
from memory.model import (
    Authorship,
    ExactCaptureMetadata,
    Sensitivity,
    SourceCaptureOrigin,
)
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
metadata = ExactCaptureMetadata(
    capture_request_id={metadata.capture_request_id!r},
    batch_id={metadata.batch_id!r},
    captured_at={metadata.captured_at!r},
    target_lineage_id={metadata.target_lineage_id!r},
    expected_head_id={metadata.expected_head_id!r},
    payload_sha256={metadata.payload_sha256!r},
    source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
    authorship=Authorship.OWNER,
    sensitivity=Sensitivity.RESTRICTED,
)
inbox._checkpoint = lambda name: os._exit(86) if name == {checkpoint!r} else None
inbox.stage_exact_private_entry(
    paths,
    display_name="synthetic-crashed-correction.md",
    chunks=(base64.b64decode({encoded!r}),),
    max_bytes={len(body)},
    metadata=metadata,
)
os._exit(0)
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _pause_exact_staging(
    paths: RuntimePaths,
    *,
    body: bytes,
    metadata: model.ExactCaptureMetadata,
    checkpoint: str,
    coordination: Path,
) -> subprocess.Popen[str]:
    """Pause a real exact publisher at one visible durability boundary."""
    ready = coordination / "publisher-ready"
    release = coordination / "publisher-release"
    encoded = base64.b64encode(body).decode("ascii")
    if checkpoint == "synthetic.exact_before_first_intent":
        instrumentation = """
_original_write_exact_intent = inbox._write_exact_intent
_paused_before_first_intent = False

def write_exact_intent_with_initial_pause(runtime, intent, *, replace=False):
    global _paused_before_first_intent
    if not replace and not _paused_before_first_intent:
        _paused_before_first_intent = True
        pause_live_publisher()
    return _original_write_exact_intent(runtime, intent, replace=replace)

inbox._write_exact_intent = write_exact_intent_with_initial_pause
"""
    elif checkpoint == "synthetic.exact_partial_intent_temporary":
        instrumentation = """
_original_os_write = inbox.os.write
_paused_partial_intent = False

def write_partial_first_intent(descriptor, data):
    global _paused_partial_intent
    if not _paused_partial_intent:
        encoded_data = bytes(data)
        prefix_length = min(24, len(encoded_data) - 1)
        assert prefix_length > 0
        written = _original_os_write(descriptor, encoded_data[:prefix_length])
        _paused_partial_intent = True
        pause_live_publisher()
        return written
    return _original_os_write(descriptor, data)

inbox.os.write = write_partial_first_intent
"""
    else:
        instrumentation = f"""
def pause_at_boundary(name):
    if name == {checkpoint!r}:
        pause_live_publisher()

inbox._checkpoint = pause_at_boundary
"""
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
import os
import time
from pathlib import Path

import memory.inbox as inbox
from memory.model import (
    Authorship,
    ExactCaptureMetadata,
    Sensitivity,
    SourceCaptureOrigin,
)
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
ready = Path({os.fspath(ready)!r})
release = Path({os.fspath(release)!r})
metadata = ExactCaptureMetadata(
    capture_request_id={metadata.capture_request_id!r},
    batch_id={metadata.batch_id!r},
    captured_at={metadata.captured_at!r},
    target_lineage_id={metadata.target_lineage_id!r},
    expected_head_id={metadata.expected_head_id!r},
    payload_sha256={metadata.payload_sha256!r},
    source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
    authorship=Authorship.OWNER,
    sensitivity=Sensitivity.RESTRICTED,
)

def pause_live_publisher():
    ready.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 20.0
    while not release.exists():
        if time.monotonic() >= deadline:
            os._exit(75)
        time.sleep(0.01)

{instrumentation}
inbox.stage_exact_private_entry(
    paths,
    display_name="synthetic-live-correction.md",
    chunks=(base64.b64decode({encoded!r}),),
    max_bytes={len(body)},
    metadata=metadata,
)
os._exit(0)
"""
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10.0
    while not ready.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "exact publisher exited before the requested boundary: "
                f"{process.returncode}; stdout={stdout!r}; stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(
                "exact publisher did not reach the requested boundary: "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        time.sleep(0.01)
    return process


def _pause_ordinary_staging(
    paths: RuntimePaths,
    *,
    body: bytes,
    coordination: Path,
) -> subprocess.Popen[str]:
    """Pause one real ordinary publisher while its leased slot is still bare."""
    ready = coordination / "publisher-ready"
    release = coordination / "publisher-release"
    encoded = base64.b64encode(body).decode("ascii")
    split = max(1, len(body) // 2)
    script = f"""
import base64
import json
import os
import time
from pathlib import Path

import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
ready = Path({os.fspath(ready)!r})
release = Path({os.fspath(release)!r})
body = base64.b64decode({encoded!r})

def chunks():
    yield body[:{split}]
    ready.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 20.0
    while not release.exists():
        if time.monotonic() >= deadline:
            os._exit(75)
        time.sleep(0.01)
    yield body[{split}:]

entry = inbox.stage_private_entry(
    paths,
    display_name="synthetic-live-ordinary.md",
    chunks=chunks(),
    max_bytes=len(body),
)
print(json.dumps({{
    "byte_length": entry.byte_length,
    "display_name": entry.display_name,
    "entry_id": entry.entry_id,
    "sha256": entry.sha256,
}}, sort_keys=True))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10.0
    while not ready.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "ordinary publisher exited before its live-stream pause: "
                f"{process.returncode}; stdout={stdout!r}; stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(
                "ordinary publisher did not reach its live-stream pause: "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        time.sleep(0.01)
    return process


def _pause_ordinary_publication(
    paths: RuntimePaths,
    *,
    body: bytes,
    pause_after_prepare: bool,
    coordination: Path,
) -> subprocess.Popen[str]:
    """Pause one integrated ordinary publisher around rollback preparation."""
    ready = coordination / "publisher-ready"
    release = coordination / "publisher-release"
    encoded = base64.b64encode(body).decode("ascii")
    instrumentation = (
        """
original_rename = inbox._rename_bound_no_replace

def rename_with_pause(*args, **kwargs):
    pause_live_publisher()
    return original_rename(*args, **kwargs)

inbox._rename_bound_no_replace = rename_with_pause
"""
        if pause_after_prepare
        else """
original_prepare = inbox._prepare_publication_rollback

def prepare_with_pause(runtime, source_descriptor, source_identity, entry):
    pause_live_publisher()
    return original_prepare(
        runtime,
        source_descriptor,
        source_identity,
        entry,
    )

inbox._prepare_publication_rollback = prepare_with_pause
"""
    )
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
import json
import os
import time
from pathlib import Path

import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
ready = Path({os.fspath(ready)!r})
release = Path({os.fspath(release)!r})
body = base64.b64decode({encoded!r})

def pause_live_publisher():
    ready.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 20.0
    while not release.exists():
        if time.monotonic() >= deadline:
            os._exit(75)
        time.sleep(0.01)

{instrumentation}
published = inbox.stage_inbox_entry(
    paths,
    owner_filename="synthetic-integrated-publication.md",
    chunks=(body,),
    max_bytes=len(body),
)
print(json.dumps({{
    "byte_length": published.byte_length,
    "display_name": published.display_name,
}}, sort_keys=True))
"""
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10.0
    while not ready.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "ordinary publisher exited before rollback preparation pause: "
                f"{process.returncode}; stdout={stdout!r}; stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(
                "ordinary publisher did not reach rollback preparation pause: "
                f"stdout={stdout!r}; stderr={stderr!r}"
            )
        time.sleep(0.01)
    return process


def _run_public_recovery(
    paths: RuntimePaths,
    *,
    flock_eio_identity: tuple[int, int] | None = None,
    open_eio_name: str | None = None,
    listdir_eio_identity: tuple[int, int] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the public recovery command with only this disposable Store bound."""
    flock_fault = (
        f"""
import errno as _errno
import memory.inbox as _inbox

_original_flock = _inbox.fcntl.flock
_fault_identity = {flock_eio_identity!r}

def _fail_flock(_descriptor, _operation):
    _metadata = _os.fstat(_descriptor)
    if (_metadata.st_dev, _metadata.st_ino) == _fault_identity:
        raise OSError(_errno.EIO, "synthetic exact lease I/O failure")
    return _original_flock(_descriptor, _operation)

_inbox.fcntl.flock = _fail_flock
"""
        if flock_eio_identity is not None
        else ""
    )
    open_fault = (
        f"""
import errno as _errno
import memory.inbox as _inbox

_original_open = _inbox.os.open
_fault_name = {open_eio_name!r}

def _fail_open(_path, *args, **kwargs):
    if _path == _fault_name:
        raise OSError(_errno.EIO, "synthetic exact open I/O failure")
    return _original_open(_path, *args, **kwargs)

_inbox.os.open = _fail_open
"""
        if open_eio_name is not None
        else ""
    )
    listdir_fault = (
        f"""
import errno as _errno
import memory.inbox as _inbox

_original_listdir = _inbox.os.listdir
_fault_listdir_identity = {listdir_eio_identity!r}

def _fail_listdir(_path):
    if isinstance(_path, int):
        _metadata = _os.fstat(_path)
        if (_metadata.st_dev, _metadata.st_ino) == _fault_listdir_identity:
            raise OSError(_errno.EIO, "synthetic withdrawal listing I/O failure")
    return _original_listdir(_path)

_inbox.os.listdir = _fail_listdir
"""
        if listdir_eio_identity is not None
        else ""
    )
    script = (
        _synthetic_keyring_prelude(paths)
        + flock_fault
        + open_fault
        + listdir_fault
        + f"""
from memory.cli import main

raise SystemExit(main(["recover", "--home", {os.fspath(paths.root)!r}]))
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _staging_snapshot(paths: RuntimePaths) -> dict[str, tuple[object, ...]]:
    """Identity, shape, timing, and bytes of every private staging occupant."""
    snapshot: dict[str, tuple[object, ...]] = {}
    for entry in sorted(paths.inbox_staging.iterdir()):
        metadata = entry.lstat()
        snapshot[entry.name] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_nlink,
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            entry.read_bytes() if stat.S_ISREG(metadata.st_mode) else b"",
        )
    return snapshot


def _staging_names(paths: RuntimePaths, pattern: re.Pattern[str]) -> list[str]:
    return sorted(
        entry.name
        for entry in paths.inbox_staging.iterdir()
        if pattern.fullmatch(entry.name) is not None
    )


def _capture_counts(paths: RuntimePaths) -> tuple[int, int]:
    """Committed batch and source counts, to prove no canonical side effect."""
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        counts = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources)"
        ).fetchone()
    finally:
        connection.close()
    assert counts is not None
    return int(counts[0]), int(counts[1])


def _audit_generation(paths: RuntimePaths) -> int:
    """Read the transaction-bound generation without mutating the Store."""
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        row = connection.execute(
            "SELECT audit_generation FROM store_meta WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return int(row[0])


def _assert_one_idle_publication_rollback_bundle(paths: RuntimePaths) -> None:
    """Require one authenticated rollback bundle in its reusable idle shape."""
    from memory.staging_provenance import decode_publication_rollback_slot

    records = sorted(paths.inbox_staging.glob(".rollback-slot-*.json"))
    assert len(records) == 1
    identity = load_runtime_identity(paths)
    record = decode_publication_rollback_slot(
        records[0].read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    assert record.format_version == 2
    staging_device = paths.inbox_staging.lstat().st_dev
    for member in (record.payload, record.manifest):
        path = paths.inbox_staging / member.name
        metadata = path.lstat()
        assert member.device is None
        assert metadata.st_dev == staging_device
        assert (
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            path.read_bytes(),
        ) == (member.inode, member.uid, member.mode, b"")
    withdrawal = paths.inbox_staging / record.withdrawal.name
    metadata = withdrawal.lstat()
    assert record.withdrawal.device is None
    assert metadata.st_dev == staging_device
    assert (
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        tuple(withdrawal.iterdir()),
    ) == (
        record.withdrawal.inode,
        record.withdrawal.uid,
        record.withdrawal.mode,
        (),
    )


def _forge_stale_device_v1_slot(
    paths: RuntimePaths,
    *,
    retained_payload: bytes = b"",
) -> str:
    """Author one authentic pre-v2 slot record with a reboot-stale device axis.

    The members are real idle artifacts in the live staging directory; only
    the recorded device numbers are shifted, which is exactly the state every
    reboot left every genuine v1 record in. A nonempty `retained_payload`
    additionally publishes the durable recovery manifest a retained bundle
    carries, with the same stale device inside its persisted identity.
    """
    from memory.staging_provenance import PUBLICATION_ROLLBACK_SLOT_KEY_CONTEXT

    identity = load_runtime_identity(paths)
    master_key = load_master_key(identity)
    slot_id = secrets.token_hex(16)
    payload = paths.inbox_staging / f".recovery-{slot_id}.stage"
    manifest = paths.inbox_staging / f".recovery-{slot_id}.json"
    withdrawal = paths.inbox_staging / f".withdrawal-{slot_id}"
    payload.write_bytes(retained_payload)
    os.chmod(payload, 0o600)
    manifest.write_bytes(b"")
    os.chmod(manifest, 0o600)
    withdrawal.mkdir()
    os.chmod(withdrawal, 0o700)
    if retained_payload:
        payload_metadata = payload.lstat()
        manifest.write_bytes(
            json.dumps(
                {
                    "batch_id": None,
                    "byte_length": len(retained_payload),
                    "capture_request_id": None,
                    "entry_id": f"ent_{'0' * 32}.stage",
                    "expected_identity": [
                        payload_metadata.st_dev + 1,
                        payload_metadata.st_ino,
                        payload_metadata.st_uid,
                        1,
                        stat.S_IFREG,
                        0o600,
                        len(retained_payload),
                    ],
                    "format": "memory.private-custody-recovery.v1",
                    "kind": "ordinary_publication",
                    "payload_name": payload.name,
                    "recovery_id": slot_id,
                    "sha256": hashlib.sha256(retained_payload).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        os.chmod(manifest, 0o600)

    def encoded_member(path: Path, file_type: str, mode: int) -> dict[str, object]:
        metadata = path.lstat()
        return {
            "device": metadata.st_dev + 1,
            "file_type": file_type,
            "inode": metadata.st_ino,
            "mode": mode,
            "name": path.name,
            "uid": metadata.st_uid,
        }

    document: dict[str, object] = {
        "format": "memory.publication-rollback-slot.v1",
        "manifest": encoded_member(manifest, "regular", 0o600),
        "payload": encoded_member(payload, "regular", 0o600),
        "slot_id": slot_id,
        "store_id": identity.store_id,
        "withdrawal": encoded_member(withdrawal, "directory", 0o700),
    }
    subkey = hmac.digest(
        bytes(master_key),
        PUBLICATION_ROLLBACK_SLOT_KEY_CONTEXT + identity.store_id.encode("ascii"),
        "sha256",
    )
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    document["mac"] = hmac.digest(subkey, canonical.encode("utf-8"), "sha256").hex()
    record_path = paths.inbox_staging / f".rollback-slot-{slot_id}.json"
    record_path.write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    os.chmod(record_path, 0o600)
    return slot_id


def test_stale_device_v1_slot_records_do_not_burn_the_publication_budget(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch reboot-invalidated pre-v2 bundles wedging all inbox publication.

    A v1 record bound each member to a boot-assigned device number, so every
    reboot invalidated every stored slot: reuse failed, retirement failed, and
    each publication burned one entry of the bounded slot budget until the
    rollback anchor was refused outright. Eight stale records is exactly that
    terminal state, and publication must retire them instead of dying on them.
    """
    from memory.inbox import stage_inbox_entry

    paths = synthetic_store
    for _ in range(8):
        _forge_stale_device_v1_slot(paths)

    body = "合成便签：雨后修剪盆栽。\n".encode()
    entry = stage_inbox_entry(
        paths,
        owner_filename="synthetic-after-reboot.md",
        chunks=(body,),
    )

    assert entry.display_name == "synthetic-after-reboot.md"
    assert (paths.inbox / "synthetic-after-reboot.md").read_bytes() == body
    _assert_one_idle_publication_rollback_bundle(paths)
    occupants = sorted(entry.name for entry in paths.inbox_staging.iterdir())
    assert len(occupants) == 4
    from memory.inbox import list_exact_recovery_issues

    issues = list_exact_recovery_issues(paths, cursor=None, limit=64)
    assert issues.items == ()


def test_retained_stale_device_v1_bundle_retires_to_visible_recovery_debt(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a crash-retained pre-v2 bundle staying unretirable after reboot.

    A retained bundle holds real recovery bytes, so its members must survive
    retirement and stay reported; only the record may go, and only after the
    durable manifest is proven to bind the payload on its own -- a proof that
    used to compare the persisted boot-assigned device and therefore failed
    forever after any reboot.
    """
    from memory.inbox import list_exact_recovery_issues, stage_inbox_entry

    paths = synthetic_store
    for _ in range(7):
        _forge_stale_device_v1_slot(paths)
    retained_slot_id = _forge_stale_device_v1_slot(
        paths,
        retained_payload=b"synthetic retained recovery bytes\n",
    )

    entry = stage_inbox_entry(
        paths,
        owner_filename="synthetic-second-life.md",
        chunks=(b"synthetic body\n",),
    )

    assert entry.display_name == "synthetic-second-life.md"
    assert sorted(paths.inbox_staging.glob(".rollback-slot-*.json")) != []
    _assert_one_idle_publication_rollback_bundle(paths)
    retained_payload = paths.inbox_staging / f".recovery-{retained_slot_id}.stage"
    retained_manifest = paths.inbox_staging / f".recovery-{retained_slot_id}.json"
    retained_withdrawal = paths.inbox_staging / f".withdrawal-{retained_slot_id}"
    assert retained_payload.read_bytes() == b"synthetic retained recovery bytes\n"
    assert retained_manifest.exists()
    assert retained_withdrawal.is_dir()
    issues = list_exact_recovery_issues(paths, cursor=None, limit=64)
    assert sorted(issue.code for issue in issues.items) == [
        "custody_mismatch",
        "custody_mismatch",
    ]


def test_legacy_slot_retirement_is_idempotent_across_a_crash_window(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a half-retired v1 bundle becoming permanently unreclaimable.

    Members are removed before the record so a crash between the two leaves
    an authenticated record whose members are gone. The next acquisition must
    tolerate the absent members and finish retiring the record, not report it
    as custody debt forever.
    """
    import memory.inbox as inbox
    from memory.inbox import stage_inbox_entry

    paths = synthetic_store
    slot_id = _forge_stale_device_v1_slot(paths)
    record_name = f".rollback-slot-{slot_id}.json"
    original_unlink = inbox._unlink_bound_staging_entry

    def refuse_record_unlink(
        runtime: inbox._RuntimeRoot,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, ...],
    ) -> bool:
        if name == record_name:
            return False
        return original_unlink(runtime, name, descriptor, expected_identity)

    monkeypatch.setattr(inbox, "_unlink_bound_staging_entry", refuse_record_unlink)
    stage_inbox_entry(
        paths,
        owner_filename="synthetic-first.md",
        chunks=(b"synthetic first body\n",),
    )
    assert (paths.inbox_staging / record_name).exists()
    assert not (paths.inbox_staging / f".recovery-{slot_id}.stage").exists()
    assert not (paths.inbox_staging / f".recovery-{slot_id}.json").exists()
    assert not (paths.inbox_staging / f".withdrawal-{slot_id}").exists()

    monkeypatch.setattr(inbox, "_unlink_bound_staging_entry", original_unlink)
    stage_inbox_entry(
        paths,
        owner_filename="synthetic-second.md",
        chunks=(b"synthetic second body\n",),
    )

    assert not (paths.inbox_staging / record_name).exists()
    _assert_one_idle_publication_rollback_bundle(paths)


def _rewrite_manifest_device(path: Path, *keys: str) -> None:
    """Shift the persisted device axes of one manifest, as every reboot did."""
    document = json.loads(path.read_text(encoding="utf-8"))
    for key in keys:
        document[key] += 1
    path.write_bytes(
        (
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    )


def test_bound_exact_intent_custody_survives_a_reboot(
    crashable_store: RuntimePaths,
) -> None:
    """Catch a reboot stranding a durable correction recovery would complete.

    The intent persists the payload's boot-assigned device number. Comparing
    it against the live inode after a reboot misreported a complete, durable,
    bound correction as custody_mismatch: recovery refused to touch it, the
    issue quarantined every later owner correction, and the owner's bytes sat
    in staging with no path forward. A rebooted Store must complete the same
    correction an unrebooted one completes.
    """
    import memory.inbox as inbox
    from memory.retrieval import read_source

    paths = crashable_store
    body, metadata = _owner_correction_payload(paths, marker="d")
    completed = _crash_exact_staging(
        paths,
        body=body,
        metadata=metadata,
        checkpoint="exact.payload_directory_fsync",
    )
    assert completed.returncode == 86, completed.stderr
    intents = sorted(paths.inbox_staging.glob("ent_*.stage.intent.json"))
    assert len(intents) == 1
    assert json.loads(intents[0].read_text(encoding="utf-8"))["phase"] == (
        "payload_bound"
    )
    _rewrite_manifest_device(intents[0], "payload_device")

    recovered = inbox.recover_exact_staged_entries(paths)

    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    chunk = read_source(paths, recovered[0].source_id)
    assert chunk.complete is True
    assert chunk.text == body.decode("utf-8")
    assert list(paths.inbox_staging.iterdir()) == []
    assert inbox.list_exact_recovery_issues(paths, cursor=None, limit=10).items == ()


def test_exact_ready_entry_survives_a_reboot(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a complete staged correction becoming unbound custody on reboot.

    A ready manifest binds its payload by persisted device plus inode, so a
    reboot stranded a complete, durable owner correction as custody_mismatch
    while its bytes sat intact in staging.
    """
    from memory.inbox import list_exact_recovery_issues

    paths = synthetic_store
    entry_path = _prepare_lease_fault_artifact(
        paths,
        artifact_kind="final_ready",
        marker="f",
    )
    ready = entry_path.parent / (entry_path.name + ".ready.json")
    assert ready.is_file()
    _rewrite_manifest_device(ready, "payload_device")

    issues = list_exact_recovery_issues(paths, cursor=None, limit=64)

    assert issues.items == ()


def test_a_finder_dotfile_in_claims_does_not_refuse_every_scan(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch one .DS_Store wedging scans behind a claim-identity error.

    Any unrecognized inbox-claims entry refused every scan, recovery, and
    correction as 'Store claim identity is invalid' -- an error naming claim
    custody when the cause was Finder writing metadata into a browsed
    directory. A dot-file matches no claim-artifact shape, and hidden
    dot-files never enter custody, so it is provably not a claim; a non-dot
    stranger still fails closed.
    """
    from memory.errors import InvalidArgumentError
    from memory.inbox import scan_inbox

    paths = synthetic_store
    (paths.inbox_claims / ".DS_Store").write_bytes(b"\x00synthetic finder bytes")
    (paths.inbox / "synthetic-browsed.md").write_bytes(b"synthetic body\n")

    batch = scan_inbox(paths, clock=FakeClock())

    assert batch.source_count == 1
    assert (paths.inbox_claims / ".DS_Store").exists()

    (paths.inbox_claims / "stranger").mkdir(mode=0o700)
    (paths.inbox / "synthetic-second.md").write_bytes(b"synthetic body two\n")
    with pytest.raises(InvalidArgumentError, match="claim identity"):
        scan_inbox(paths, clock=FakeClock())


def test_published_ordinary_claim_completes_after_a_reboot(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a crash-left claim rejecting every claimed source after reboot.

    The claim manifest persists each entry's boot-assigned device. Comparing
    it against the live files after a reboot restored every claimed source as
    `changed`, failed the recovering scan, and abandoned the sealed batch
    identity -- for files whose bytes never moved.
    """
    from memory.inbox import scan_inbox

    paths = synthetic_store
    batch_id = f"bat_{'d' * 32}"
    claim_path = paths.inbox_claims / batch_id
    files = claim_path / "files"
    claim_path.mkdir(mode=0o700)
    files.mkdir(mode=0o700)
    bodies = {
        "synthetic-claimed-a.md": "合成清单甲：整理书桌。\n".encode(),
        "synthetic-claimed-b.md": b"synthetic claimed body b\n",
    }
    entries: list[dict[str, object]] = []
    for index, (name, body) in enumerate(sorted(bodies.items())):
        source = files / name
        source.write_bytes(body)
        os.chmod(source, 0o600)
        metadata = source.lstat()
        entries.append(
            {
                "byte_length": len(body),
                "device": metadata.st_dev + 1,
                "entry_id": f"ise_{format(index, 'x') * 32}",
                "inode": metadata.st_ino,
                "modified_ns": metadata.st_mtime_ns,
                "name": name,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    manifest: dict[str, object] = {
        "authorship": "owner",
        "batch_id": batch_id,
        "capture_request_id": None,
        "captured_at": 1_800_000_005,
        "custody_kind": "inbox_scan",
        "entries": entries,
        "exact_metadata": None,
        "format": "memory.inbox-claim.v2",
        "has_more": False,
        "issues": {},
        "sensitivity": "restricted",
        "source_origin": "inbox",
    }
    (claim_path / "manifest.json").write_bytes(
        (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    )
    os.chmod(claim_path / "manifest.json", 0o600)

    batch = scan_inbox(paths, clock=FakeClock())

    assert batch.batch_id == batch_id
    assert batch.source_count == 2
    assert batch.issues == ()
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []


def _prepare_lease_fault_artifact(
    paths: RuntimePaths,
    *,
    artifact_kind: str,
    marker: str,
) -> Path:
    """Create one structurally valid artifact whose payload lease can fault."""
    import memory.inbox as inbox

    if artifact_kind == "bare_ordinary":
        return _abandoned_stage_slot(paths, int(marker, 16))
    body, metadata = _owner_correction_payload(paths, marker=marker)
    if artifact_kind == "final_ready":
        entry = inbox.stage_exact_private_entry(
            paths,
            display_name="synthetic-valid-ready.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
        return paths.inbox_staging / entry.entry_id
    checkpoint = {
        "intent_temporary": "exact.intent_manifest_file_fsync",
        "final_intent": "exact.intent_manifest_directory_fsync",
        "ready_temporary": "exact.ready_manifest_file_fsync",
    }[artifact_kind]
    crashed = _crash_exact_staging(
        paths,
        body=body,
        metadata=metadata,
        checkpoint=checkpoint,
    )
    assert crashed.returncode == 86, crashed.stderr
    payloads = sorted(paths.inbox_staging.glob("ent_*.stage"))
    assert len(payloads) == 1
    if artifact_kind == "ready_temporary":
        intents = sorted(paths.inbox_staging.glob("ent_*.stage.intent.json"))
        assert len(intents) == 1
        intents[0].unlink()
        ready_temporaries = sorted(paths.inbox_staging.glob(".ready-*.tmp"))
        assert len(ready_temporaries) == 1
    return payloads[0]


def _assert_handoff_is_complete(
    paths: RuntimePaths,
    *,
    body: bytes,
    metadata: model.ExactCaptureMetadata,
) -> None:
    """Require exactly one durable handoff binding these exact correction bytes."""
    from memory.inbox import _RECOVERY_FORMAT

    recovery_id = metadata.capture_request_id.removeprefix("cap_")
    payload = paths.inbox_staging / f".recovery-{recovery_id}.stage"
    manifest = paths.inbox_staging / f".recovery-{recovery_id}.json"
    assert _staging_names(paths, _RECOVERY_PAYLOAD_NAME) == [payload.name]
    assert _staging_names(paths, _RECOVERY_MANIFEST_NAME) == [manifest.name]

    stored = payload.read_bytes()
    assert stored == body
    assert hashlib.sha256(stored).hexdigest() == metadata.payload_sha256
    text = stored.decode("utf-8")
    assert f"target_lineage_id: {metadata.target_lineage_id}\n" in text
    assert f"expected_head_id: {metadata.expected_head_id}\n" in text

    payload_metadata = payload.lstat()
    assert stat.S_IMODE(payload_metadata.st_mode) == 0o600
    assert payload_metadata.st_nlink == 1
    assert payload_metadata.st_uid == os.geteuid()

    record = json.loads(manifest.read_text(encoding="utf-8"))
    assert record["format"] == _RECOVERY_FORMAT
    assert record["kind"] == "owner_correction_handoff"
    assert record["recovery_id"] == recovery_id
    assert record["payload_name"] == payload.name
    assert record["capture_request_id"] == metadata.capture_request_id
    assert record["batch_id"] == metadata.batch_id
    assert record["byte_length"] == len(body)
    assert record["sha256"] == metadata.payload_sha256
    assert record["expected_identity"][:2] == [
        payload_metadata.st_dev,
        payload_metadata.st_ino,
    ]


@pytest.mark.parametrize(
    "checkpoint",
    [
        "correction.handoff_payload_file_fsync",
        "correction.handoff_payload_directory_fsync",
    ],
)
def test_correction_handoff_payload_barrier_crash_keeps_the_exact_bytes(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Catch a killed correction handoff losing or tearing the owner's only copy.

    An owner correction typed into the local UI is one of two routes by which
    canonical memory can ever be corrected, and the handoff is what happens
    when its capture cannot say whether it took. Dying between writing those
    bytes and marking them means the Store is holding the only copy of text
    the owner has already been told to stop retyping.
    """
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="1")
    recovery_id = metadata.capture_request_id.removeprefix("cap_")

    completed = _crash_correction_handoff(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint=checkpoint,
    )

    assert completed.returncode == 86, completed.stderr
    payload = crashable_store.inbox_staging / f".recovery-{recovery_id}.stage"
    assert _staging_names(crashable_store, _RECOVERY_PAYLOAD_NAME) == [payload.name]
    assert _staging_names(crashable_store, _RECOVERY_MANIFEST_NAME) == []
    assert payload.read_bytes() == body
    torn = (payload.lstat().st_dev, payload.lstat().st_ino)

    assert list(crashable_store.inbox.iterdir()) == []
    assert list(crashable_store.inbox_claims.iterdir()) == []
    assert _capture_counts(crashable_store) == (0, 0)
    unmarked = inbox.list_exact_recovery_issues(
        crashable_store,
        cursor=None,
        limit=10,
    )
    assert [issue.code for issue in unmarked.items] == ["custody_mismatch"]
    assert "合成纠正" not in repr(unmarked.items)

    assert inbox.recover_exact_staged_entries(crashable_store) == ()
    assert payload.read_bytes() == body
    assert (payload.lstat().st_dev, payload.lstat().st_ino) == torn

    assert (
        inbox.preserve_exact_correction_handoff(
            crashable_store,
            source_bytes=body,
            metadata=metadata,
        )
        is True
    )

    _assert_handoff_is_complete(crashable_store, body=body, metadata=metadata)
    assert (payload.lstat().st_dev, payload.lstat().st_ino) == torn
    assert _capture_counts(crashable_store) == (0, 0)


def test_correction_handoff_existing_barrier_crash_changes_nothing(
    crashable_store: RuntimePaths,
) -> None:
    """Catch a repeated handoff damaging or duplicating the durable one it finds.

    Reaching `correction.handoff_existing_directory_fsync` means the bytes and
    their marker are already durable, so the only correct outcome of dying
    there is the completed state, unaltered. A retry that rewrote the payload,
    minted a second one, or dropped the marker would still return true.
    """
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="2")

    assert (
        inbox.preserve_exact_correction_handoff(
            crashable_store,
            source_bytes=body,
            metadata=metadata,
        )
        is True
    )
    _assert_handoff_is_complete(crashable_store, body=body, metadata=metadata)
    durable = _staging_snapshot(crashable_store)

    completed = _crash_correction_handoff(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint="correction.handoff_existing_directory_fsync",
    )

    assert completed.returncode == 86, completed.stderr
    assert _staging_snapshot(crashable_store) == durable
    _assert_handoff_is_complete(crashable_store, body=body, metadata=metadata)

    assert (
        inbox.preserve_exact_correction_handoff(
            crashable_store,
            source_bytes=body,
            metadata=metadata,
        )
        is True
    )
    assert _staging_snapshot(crashable_store) == durable
    assert list(crashable_store.inbox.iterdir()) == []
    assert _capture_counts(crashable_store) == (0, 0)


@pytest.mark.parametrize(
    "checkpoint",
    ["exact.payload_file_fsync", "exact.payload_directory_fsync"],
)
def test_exact_payload_barrier_crash_recovers_the_whole_correction(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Catch a killed exact staging losing a correction whose bytes are complete.

    Past these two barriers the payload is written, synced, and named by a
    bound intent, so the only correct outcome is the completed one: the same
    reserved batch, the same capture request, and the same lineage and head
    the owner's text was bound to -- once, never twice, and never through the
    Inbox.
    """
    import memory.inbox as inbox
    from memory.retrieval import read_source

    body, metadata = _owner_correction_payload(crashable_store, marker="3")

    completed = _crash_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint=checkpoint,
    )

    assert completed.returncode == 86, completed.stderr
    staged = {path.name: path for path in crashable_store.inbox_staging.iterdir()}
    slots = sorted(name for name in staged if name.endswith(".stage"))
    assert len(slots) == 1
    assert sorted(staged) == [slots[0], slots[0] + ".intent.json"]
    assert staged[slots[0]].read_bytes() == body
    intent = json.loads(staged[slots[0] + ".intent.json"].read_text(encoding="utf-8"))
    assert intent["phase"] == "payload_bound"
    assert _capture_counts(crashable_store) == (0, 0)

    recovered = inbox.recover_exact_staged_entries(crashable_store)

    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    assert recovered[0].lineage_id == metadata.target_lineage_id
    assert recovered[0].expected_head_id == metadata.expected_head_id
    assert recovered[0].captured_at == metadata.captured_at
    chunk = read_source(crashable_store, recovered[0].source_id)
    assert chunk.complete is True
    assert chunk.text == body.decode("utf-8")
    assert _capture_counts(crashable_store) == (1, 1)
    assert list(crashable_store.inbox.iterdir()) == []
    assert list(crashable_store.inbox_staging.iterdir()) == []
    assert (
        inbox.list_exact_recovery_issues(crashable_store, cursor=None, limit=10).items
        == ()
    )

    assert inbox.recover_exact_staged_entries(crashable_store) == ()
    assert _capture_counts(crashable_store) == (1, 1)


def test_recovery_captures_a_preserved_owner_correction_handoff(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a durable handoff that nothing can ever consume.

    The UI's last resort for an irreducibly ambiguous correction failure is
    the durable handoff pair, and on that durability promise it drops its
    only retained copy of the owner's text. A handoff nothing consumes is a
    promise the product cannot keep: the bytes sit in private staging
    forever, reported as custody debt, quarantining every later correction.
    Recovery must replay the pair into the correction's own reserved batch
    and remove it, exactly as if the original submission had completed.
    """
    import memory.inbox as inbox
    from memory.retrieval import read_source

    body, metadata = _owner_correction_payload(synthetic_store, marker="6")
    assert inbox.preserve_exact_correction_handoff(
        synthetic_store,
        source_bytes=body,
        metadata=metadata,
    )
    _assert_handoff_is_complete(synthetic_store, body=body, metadata=metadata)

    recovered = inbox.recover_exact_staged_entries(synthetic_store)

    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    assert recovered[0].lineage_id == metadata.target_lineage_id
    assert recovered[0].expected_head_id == metadata.expected_head_id
    assert recovered[0].captured_at == metadata.captured_at
    chunk = read_source(synthetic_store, recovered[0].source_id)
    assert chunk.complete is True
    assert chunk.text == body.decode("utf-8")
    assert list(synthetic_store.inbox_staging.iterdir()) == []
    assert (
        inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=10).items
        == ()
    )
    assert _capture_counts(synthetic_store) == (1, 1)
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()


def test_a_preserved_handoff_no_longer_quarantines_new_corrections(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch one stranded handoff refusing every later owner correction."""
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(synthetic_store, marker="7")
    assert inbox.preserve_exact_correction_handoff(
        synthetic_store,
        source_bytes=body,
        metadata=metadata,
    )
    fresh_body, fresh = _owner_correction_payload(synthetic_store, marker="8")

    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-after-handoff.md",
        chunks=(fresh_body,),
        max_bytes=len(fresh_body),
        metadata=fresh,
    )

    assert entry.sha256 == fresh.payload_sha256
    assert _staging_names(synthetic_store, _RECOVERY_PAYLOAD_NAME) == []
    assert _staging_names(synthetic_store, _RECOVERY_MANIFEST_NAME) == []
    assert (
        inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=10).items
        == ()
    )

    recovered = inbox.recover_exact_staged_entries(synthetic_store)

    assert {value.capture_request_id for value in recovered} == {
        metadata.capture_request_id,
        fresh.capture_request_id,
    }
    assert _capture_counts(synthetic_store) == (2, 2)


def test_handoff_replay_is_idempotent_after_capture(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a replay double-capturing a correction the Store already holds."""
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(synthetic_store, marker="9")
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name=f"owner-correction-{metadata.capture_request_id[4:]}.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    batch = inbox.capture_exact_staged_entry(
        synthetic_store,
        entry,
        metadata=metadata,
    )
    assert batch.batch_id == metadata.batch_id
    assert _capture_counts(synthetic_store) == (1, 1)
    assert inbox.preserve_exact_correction_handoff(
        synthetic_store,
        source_bytes=body,
        metadata=metadata,
    )

    recovered = inbox.recover_exact_staged_entries(synthetic_store)

    assert recovered == ()
    assert _capture_counts(synthetic_store) == (1, 1)
    assert _staging_names(synthetic_store, _RECOVERY_PAYLOAD_NAME) == []
    assert _staging_names(synthetic_store, _RECOVERY_MANIFEST_NAME) == []
    assert (
        inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=10).items
        == ()
    )


def test_half_removed_handoff_finishes_on_the_next_pass(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a crash between the pair's two removals stranding the remainder.

    The payload is removed first and the manifest last, so the remainder
    still names the correction and its captured proof; the next pass must
    recognize the safe state and finish, not report it as debt forever.
    """
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(synthetic_store, marker="a")
    assert inbox.preserve_exact_correction_handoff(
        synthetic_store,
        source_bytes=body,
        metadata=metadata,
    )
    recovery_id = metadata.capture_request_id.removeprefix("cap_")
    manifest_name = f".recovery-{recovery_id}.json"
    original_unlink = inbox._unlink_bound_staging_entry

    def refuse_manifest_unlink(
        runtime: inbox._RuntimeRoot,
        name: str,
        descriptor: int,
        expected_identity: tuple[int, ...],
    ) -> bool:
        if name == manifest_name:
            return False
        return original_unlink(runtime, name, descriptor, expected_identity)

    monkeypatch.setattr(inbox, "_unlink_bound_staging_entry", refuse_manifest_unlink)
    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert len(recovered) == 1
    assert (synthetic_store.inbox_staging / manifest_name).exists()
    assert not (
        synthetic_store.inbox_staging / f".recovery-{recovery_id}.stage"
    ).exists()

    monkeypatch.setattr(inbox, "_unlink_bound_staging_entry", original_unlink)
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()

    assert _staging_names(synthetic_store, _RECOVERY_MANIFEST_NAME) == []
    assert _capture_counts(synthetic_store) == (1, 1)
    assert (
        inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=10).items
        == ()
    )


def test_a_foreign_store_handoff_stays_reported_and_untouched(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch replay trusting an envelope another Store authored."""
    import dataclasses

    import memory.inbox as inbox

    identity = load_runtime_identity(synthetic_store)
    body, metadata = _owner_correction_payload(synthetic_store, marker="b")
    foreign_body = body.replace(
        identity.store_id.encode("ascii"),
        b"f" * 32,
    )
    foreign = dataclasses.replace(
        metadata,
        payload_sha256=hashlib.sha256(foreign_body).hexdigest(),
    )
    assert inbox.preserve_exact_correction_handoff(
        synthetic_store,
        source_bytes=foreign_body,
        metadata=foreign,
    )

    recovered = inbox.recover_exact_staged_entries(synthetic_store)

    assert recovered == ()
    recovery_id = foreign.capture_request_id.removeprefix("cap_")
    assert (
        synthetic_store.inbox_staging / f".recovery-{recovery_id}.stage"
    ).read_bytes() == foreign_body
    assert (synthetic_store.inbox_staging / f".recovery-{recovery_id}.json").exists()
    issues = inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=10)
    assert [issue.code for issue in issues.items] == ["custody_mismatch"]
    assert _capture_counts(synthetic_store) == (0, 0)


def test_recovery_issue_list_rechecks_an_exact_capture_committed_mid_pass(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a remembered ready artifact becoming false recovery debt."""
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="d")
    entry = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-concurrent-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    original_load = inbox._load_exact_batch
    interleaved = False

    def commit_after_precommit_read(
        runtime: inbox._RuntimeRoot,
        remembered_entry: model.PrivateStagedEntry,
        remembered_metadata: model.ExactCaptureMetadata,
    ) -> model.InboxBatch | None:
        nonlocal interleaved
        existing = original_load(runtime, remembered_entry, remembered_metadata)
        if interleaved:
            return existing
        assert existing is None
        assert remembered_entry == entry
        assert remembered_metadata == metadata
        interleaved = True
        committed = inbox.capture_exact_staged_entry(
            crashable_store,
            entry,
            metadata=metadata,
        )
        assert committed.batch_id == metadata.batch_id
        assert list(crashable_store.inbox_staging.iterdir()) == []
        return existing

    monkeypatch.setattr(inbox, "_load_exact_batch", commit_after_precommit_read)

    issues = inbox.list_exact_recovery_issues(
        crashable_store,
        cursor=None,
        limit=10,
    )

    assert interleaved
    assert issues.items == ()
    assert issues.has_more is False
    assert issues.next_cursor is None
    assert _capture_counts(crashable_store) == (1, 1)


def test_recovery_issue_list_caches_claim_custody_before_final_wal_read(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch claim custody being consumed only after its precommit snapshot."""
    import memory.inbox as inbox

    class SyntheticMovePause(RuntimeError):
        pass

    body, metadata = _owner_correction_payload(crashable_store, marker="f")
    entry = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-claim-snapshot-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    original_load = inbox._load_exact_batch
    original_verify = inbox._verify_private_file
    moved_to_claim = False
    committed_after_snapshot = False
    completing = False

    def move_before_initial_payload_check(
        runtime: inbox._RuntimeRoot,
        remembered_entry: model.PrivateStagedEntry,
    ) -> os.stat_result:
        nonlocal moved_to_claim
        if moved_to_claim:
            return original_verify(runtime, remembered_entry)
        moved_to_claim = True

        def pause_after_move(checkpoint: str) -> None:
            if checkpoint == "exact.staged_to_claim_move":
                raise SyntheticMovePause(checkpoint)

        monkeypatch.setattr(inbox, "_checkpoint", pause_after_move)
        with pytest.raises(
            SyntheticMovePause,
            match=re.escape("exact.staged_to_claim_move"),
        ):
            inbox.capture_exact_staged_entry(
                crashable_store,
                entry,
                metadata=metadata,
            )
        monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
        assert len(list(crashable_store.inbox_claims.iterdir())) == 1
        return original_verify(runtime, remembered_entry)

    def commit_after_final_precommit_read(
        runtime: inbox._RuntimeRoot,
        remembered_entry: model.PrivateStagedEntry,
        remembered_metadata: model.ExactCaptureMetadata,
    ) -> model.InboxBatch | None:
        nonlocal committed_after_snapshot, completing
        existing = original_load(runtime, remembered_entry, remembered_metadata)
        claim_exists = bool(list(crashable_store.inbox_claims.iterdir()))
        if moved_to_claim and claim_exists and not completing:
            assert existing is None
            completing = True
            committed = inbox.capture_exact_staged_entry(
                crashable_store,
                entry,
                metadata=metadata,
            )
            assert committed.batch_id == metadata.batch_id
            committed_after_snapshot = True
        return existing

    monkeypatch.setattr(
        inbox, "_verify_private_file", move_before_initial_payload_check
    )
    monkeypatch.setattr(inbox, "_load_exact_batch", commit_after_final_precommit_read)

    in_flight = inbox.list_exact_recovery_issues(
        crashable_store,
        cursor=None,
        limit=10,
    )
    fresh = inbox.list_exact_recovery_issues(
        crashable_store,
        cursor=None,
        limit=10,
    )

    assert moved_to_claim
    assert committed_after_snapshot
    assert in_flight.items == ()
    assert fresh.items == ()
    assert list(crashable_store.inbox_staging.iterdir()) == []
    assert list(crashable_store.inbox_claims.iterdir()) == []
    assert _capture_counts(crashable_store) == (1, 1)


def test_public_recover_defers_exact_state_arriving_after_snapshot(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A post-snapshot correction is for the next recovery invocation."""
    import memory.cli as cli
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="e")
    original_recover = inbox._recover_exact_staged_entries
    original_load = inbox._load_exact_batch
    staged_entry: model.PrivateStagedEntry | None = None
    interleaved = False

    def stage_after_recovery(
        paths: RuntimePaths,
        *,
        directory_authority: inbox.RuntimeDirectoryAuthority | None = None,
        candidates: tuple[
            tuple[model.PrivateStagedEntry, model.ExactCaptureMetadata], ...
        ]
        | None = None,
    ) -> tuple[model.CapturedCorrection, ...]:
        nonlocal staged_entry
        recovered = original_recover(
            paths,
            directory_authority=directory_authority,
            candidates=candidates,
        )
        assert recovered == ()
        staged_entry = inbox.stage_exact_private_entry(
            paths,
            display_name="synthetic-public-concurrent-correction.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
            directory_authority=directory_authority,
        )
        return recovered

    def commit_after_precommit_read(
        runtime: inbox._RuntimeRoot,
        remembered_entry: model.PrivateStagedEntry,
        remembered_metadata: model.ExactCaptureMetadata,
    ) -> model.InboxBatch | None:
        nonlocal interleaved
        existing = original_load(runtime, remembered_entry, remembered_metadata)
        if interleaved:
            return existing
        assert existing is None
        assert staged_entry is not None
        assert remembered_entry == staged_entry
        assert remembered_metadata == metadata
        interleaved = True
        inbox.capture_exact_staged_entry(
            crashable_store,
            staged_entry,
            metadata=metadata,
        )
        return existing

    monkeypatch.setattr(inbox, "_recover_exact_staged_entries", stage_after_recovery)
    monkeypatch.setattr(inbox, "_load_exact_batch", commit_after_precommit_read)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert not interleaved
    assert report == {
        "issues": [],
        "issues_truncated": False,
        "recovered": [],
    }
    assert output.err == ""
    assert staged_entry is not None
    assert (crashable_store.inbox_staging / staged_entry.entry_id).exists()
    assert _capture_counts(crashable_store) == (0, 0)


@pytest.mark.parametrize(
    ("pause_kind", "marker"),
    [
        ("synthetic.exact_before_first_intent", "1"),
        ("synthetic.exact_partial_intent_temporary", "2"),
    ],
)
def test_public_recovery_skips_live_unannounced_exact_publishers(
    crashable_store: RuntimePaths,
    tmp_path: Path,
    pause_kind: str,
    marker: str,
) -> None:
    """Catch a live bare or partially announced exact slot becoming false debt."""
    from memory.retrieval import read_source

    body, metadata = _owner_correction_payload(crashable_store, marker=marker)
    coordination = tmp_path / f"coordination-unannounced-{marker}"
    coordination.mkdir()
    release = coordination / "publisher-release"
    publisher = _pause_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint=pause_kind,
        coordination=coordination,
    )
    publisher_stdout = ""
    publisher_stderr = ""
    try:
        before_staging = _staging_snapshot(crashable_store)
        before_counts = _capture_counts(crashable_store)
        before_generation = _audit_generation(crashable_store)
        bare = [name for name in before_staging if name.endswith(".stage")]
        assert len(bare) == 1
        if pause_kind == "synthetic.exact_before_first_intent":
            assert sorted(before_staging) == bare
        else:
            partials = [
                name
                for name in before_staging
                if name.startswith(".intent-") and name.endswith(".tmp")
            ]
            assert len(partials) == 1
            partial_bytes = before_staging[partials[0]][-1]
            assert isinstance(partial_bytes, bytes)
            with pytest.raises(json.JSONDecodeError):
                json.loads(partial_bytes.decode("utf-8"))

        concurrent = _run_public_recovery(crashable_store)
        concurrent_report = json.loads(concurrent.stdout)

        assert concurrent.returncode == 0, concurrent.stderr
        assert concurrent_report == {
            "issues": [],
            "issues_truncated": False,
            "recovered": [],
        }
        assert _staging_snapshot(crashable_store) == before_staging
        assert _capture_counts(crashable_store) == before_counts
        assert _audit_generation(crashable_store) == before_generation
    finally:
        release.write_text("release", encoding="utf-8")
        publisher_stdout, publisher_stderr = publisher.communicate(timeout=10)

    assert publisher.returncode == 0, (
        f"stdout={publisher_stdout!r}; stderr={publisher_stderr!r}"
    )

    recovered = _run_public_recovery(crashable_store)
    assert recovered.returncode == 0, recovered.stderr
    report = json.loads(recovered.stdout)
    assert len(report["recovered"]) == 1
    correction = report["recovered"][0]
    assert correction["batch_id"] == metadata.batch_id
    assert report["issues"] == []
    assert read_source(crashable_store, correction["source_id"]).text == body.decode()
    assert _capture_counts(crashable_store) == (1, 1)
    assert list(crashable_store.inbox_staging.iterdir()) == []

    idempotent = _run_public_recovery(crashable_store)
    assert idempotent.returncode == 0, idempotent.stderr
    assert json.loads(idempotent.stdout)["recovered"] == []
    assert _capture_counts(crashable_store) == (1, 1)


def test_public_recovery_skips_a_live_bare_ordinary_stream(
    crashable_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch ordinary streaming custody being reported as malformed exact debt."""
    from memory.inbox import publish_staged_inbox_entry

    body = "合成普通上传：发布者仍在写入。\n".encode()
    coordination = tmp_path / "coordination-live-ordinary"
    coordination.mkdir()
    release = coordination / "publisher-release"
    publisher = _pause_ordinary_staging(
        crashable_store,
        body=body,
        coordination=coordination,
    )
    publisher_stdout = ""
    publisher_stderr = ""
    try:
        before_staging = _staging_snapshot(crashable_store)
        before_counts = _capture_counts(crashable_store)
        before_generation = _audit_generation(crashable_store)
        bare = [name for name in before_staging if name.endswith(".stage")]
        assert len(bare) == 1
        partial_bytes = before_staging[bare[0]][-1]
        assert isinstance(partial_bytes, bytes)
        assert 0 < len(partial_bytes) < len(body)

        concurrent = _run_public_recovery(crashable_store)
        concurrent_report = json.loads(concurrent.stdout)

        assert concurrent.returncode == 0, concurrent.stderr
        assert concurrent_report == {
            "issues": [],
            "issues_truncated": False,
            "recovered": [],
        }
        assert _staging_snapshot(crashable_store) == before_staging
        assert _capture_counts(crashable_store) == before_counts
        assert _audit_generation(crashable_store) == before_generation
    finally:
        release.write_text("release", encoding="utf-8")
        publisher_stdout, publisher_stderr = publisher.communicate(timeout=10)

    assert publisher.returncode == 0, (
        f"stdout={publisher_stdout!r}; stderr={publisher_stderr!r}"
    )
    raw_entry = json.loads(publisher_stdout)
    entry = model.PrivateStagedEntry(
        entry_id=raw_entry["entry_id"],
        display_name=raw_entry["display_name"],
        byte_length=raw_entry["byte_length"],
        sha256=raw_entry["sha256"],
    )
    retained = crashable_store.inbox_staging / entry.entry_id
    assert retained.read_bytes() == body
    assert hashlib.sha256(body).hexdigest() == entry.sha256

    before_unlocked_recovery = _staging_snapshot(crashable_store)
    unlocked = _run_public_recovery(crashable_store)

    assert unlocked.returncode == 0, unlocked.stderr
    unlocked_report = json.loads(unlocked.stdout)
    assert [issue["code"] for issue in unlocked_report["issues"]] == [
        "malformed_manifest"
    ]
    assert unlocked_report["recovered"] == []
    assert _staging_snapshot(crashable_store) == before_unlocked_recovery
    assert _capture_counts(crashable_store) == (0, 0)

    published = publish_staged_inbox_entry(crashable_store, entry)

    assert published.display_name == entry.display_name
    assert (crashable_store.inbox / entry.display_name).read_bytes() == body
    assert _capture_counts(crashable_store) == (0, 0)

    clean = _run_public_recovery(crashable_store)
    assert clean.returncode == 0, clean.stderr
    assert json.loads(clean.stdout) == {
        "issues": [],
        "issues_truncated": False,
        "recovered": [],
    }
    assert _capture_counts(crashable_store) == (0, 0)


@pytest.mark.parametrize(
    ("pause_after_prepare", "marker"),
    [(False, "before"), (True, "after")],
)
def test_public_recovery_skips_a_live_integrated_ordinary_publication(
    crashable_store: RuntimePaths,
    tmp_path: Path,
    pause_after_prepare: bool,
    marker: str,
) -> None:
    """Catch rollback preparation making a live ordinary publish false debt."""
    body = f"Synthetic integrated publication at {marker} rollback prep.\n".encode()
    coordination = tmp_path / f"coordination-publication-{marker}"
    coordination.mkdir()
    release = coordination / "publisher-release"
    publisher = _pause_ordinary_publication(
        crashable_store,
        body=body,
        pause_after_prepare=pause_after_prepare,
        coordination=coordination,
    )
    publisher_stdout = ""
    publisher_stderr = ""
    try:
        before_staging = _staging_snapshot(crashable_store)
        before_counts = _capture_counts(crashable_store)
        before_generation = _audit_generation(crashable_store)
        sources = [name for name in before_staging if name.endswith(".stage")]
        assert len(sources) == 1 + int(pause_after_prepare)
        ordinary_sources = [name for name in sources if name.startswith("ent_")]
        assert len(ordinary_sources) == 1
        assert before_staging[ordinary_sources[0]][-1] == body
        records = [
            name
            for name in before_staging
            if name.startswith(".rollback-slot-") and name.endswith(".json")
        ]
        assert len(records) == int(pause_after_prepare)

        concurrent = _run_public_recovery(crashable_store)

        assert concurrent.returncode == 0, concurrent.stderr
        assert json.loads(concurrent.stdout) == {
            "issues": [],
            "issues_truncated": False,
            "recovered": [],
        }
        assert _staging_snapshot(crashable_store) == before_staging
        assert _capture_counts(crashable_store) == before_counts
        assert _audit_generation(crashable_store) == before_generation
    finally:
        release.write_text("release", encoding="utf-8")
        publisher_stdout, publisher_stderr = publisher.communicate(timeout=10)

    assert publisher.returncode == 0, (
        f"stdout={publisher_stdout!r}; stderr={publisher_stderr!r}"
    )
    assert json.loads(publisher_stdout) == {
        "byte_length": len(body),
        "display_name": "synthetic-integrated-publication.md",
    }
    assert (
        crashable_store.inbox / "synthetic-integrated-publication.md"
    ).read_bytes() == body
    assert _capture_counts(crashable_store) == (0, 0)
    assert _audit_generation(crashable_store) == before_generation
    _assert_one_idle_publication_rollback_bundle(crashable_store)

    idle = _staging_snapshot(crashable_store)
    clean = _run_public_recovery(crashable_store)

    assert clean.returncode == 0, clean.stderr
    assert json.loads(clean.stdout) == {
        "issues": [],
        "issues_truncated": False,
        "recovered": [],
    }
    assert _staging_snapshot(crashable_store) == idle
    assert _capture_counts(crashable_store) == (0, 0)
    assert _audit_generation(crashable_store) == before_generation


def test_standalone_ordinary_publication_propagates_source_flock_io_failure(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a source-lease I/O failure without touching staged custody."""
    import memory.inbox as inbox
    from memory.errors import InvalidArgumentError

    body = b"Synthetic standalone source lease failure.\n"
    entry = inbox.stage_private_entry(
        crashable_store,
        display_name="synthetic-source-lease-failure.md",
        chunks=(body,),
        max_bytes=len(body),
    )
    source = (crashable_store.inbox_staging / entry.entry_id).lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)
    original_flock = fcntl.flock

    def fail_source_flock(descriptor: int, operation: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (source.st_dev, source.st_ino):
            raise OSError(5, "synthetic publication source lease I/O failure")
        original_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_source_flock)

    with pytest.raises(InvalidArgumentError, match="publication failed"):
        inbox.publish_staged_inbox_entry(crashable_store, entry)

    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


@pytest.mark.parametrize(
    ("checkpoint", "marker", "expected_phase", "inspect_temporary"),
    [
        ("exact.intent_manifest_file_fsync", "a", "reserved", True),
        ("exact.bound_manifest_file_fsync", "b", "payload_bound", True),
        ("exact.intent_manifest_directory_fsync", "5", "reserved", False),
        ("exact.bound_manifest_directory_fsync", "6", "payload_bound", False),
        ("exact.payload_file_fsync", "7", "payload_bound", False),
    ],
)
def test_public_recovery_skips_a_live_exact_publisher_until_its_lease_drops(
    crashable_store: RuntimePaths,
    tmp_path: Path,
    checkpoint: str,
    marker: str,
    expected_phase: str,
    inspect_temporary: bool,
) -> None:
    """Catch recovery rolling back or capturing bytes a live process still owns.

    The temporary and final reserved pauses prove the lease precedes intent
    visibility and that recovery ignores a valid temporary a live publisher is
    still publishing. The bound pauses cover a payload before its first byte,
    and the final pause covers fully fsynced bytes before `ready`. The public
    command must see the live inode lease, report no issue, and leave every byte
    and manifest untouched.
    """
    from memory.retrieval import read_source

    body, metadata = _owner_correction_payload(crashable_store, marker=marker)
    coordination = tmp_path / f"coordination-{marker}"
    coordination.mkdir()
    release = coordination / "publisher-release"
    publisher = _pause_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint=checkpoint,
        coordination=coordination,
    )
    publisher_stdout = ""
    publisher_stderr = ""
    try:
        before = _staging_snapshot(crashable_store)
        intent_names = [
            name
            for name in before
            if (
                name.startswith(".intent-") and name.endswith(".tmp")
                if inspect_temporary
                else name.endswith(".intent.json")
            )
        ]
        assert len(intent_names) == 1
        intent = json.loads(
            (crashable_store.inbox_staging / intent_names[0]).read_text(
                encoding="utf-8"
            )
        )
        assert intent["phase"] == expected_phase

        concurrent = _run_public_recovery(crashable_store)

        assert concurrent.returncode == 0, concurrent.stderr
        concurrent_report = json.loads(concurrent.stdout)
        assert concurrent_report["recovered"] == []
        assert concurrent_report["issues"] == []
        assert _staging_snapshot(crashable_store) == before
        assert _capture_counts(crashable_store) == (0, 0)
    finally:
        release.write_text("release", encoding="utf-8")
        publisher_stdout, publisher_stderr = publisher.communicate(timeout=10)

    assert publisher.returncode == 0, (
        f"stdout={publisher_stdout!r}; stderr={publisher_stderr!r}"
    )

    recovered = _run_public_recovery(crashable_store)

    assert recovered.returncode == 0, recovered.stderr
    recovered_report = json.loads(recovered.stdout)
    assert len(recovered_report["recovered"]) == 1
    correction = recovered_report["recovered"][0]
    assert correction["batch_id"] == metadata.batch_id
    assert correction["lineage_id"] == metadata.target_lineage_id
    assert correction["expected_head_id"] == metadata.expected_head_id
    assert recovered_report["issues"] == []
    assert read_source(crashable_store, correction["source_id"]).text == body.decode()
    assert _capture_counts(crashable_store) == (1, 1)
    assert list(crashable_store.inbox_staging.iterdir()) == []

    idempotent = _run_public_recovery(crashable_store)
    assert idempotent.returncode == 0, idempotent.stderr
    assert json.loads(idempotent.stdout)["recovered"] == []
    assert _capture_counts(crashable_store) == (1, 1)


def test_public_recovery_preserves_legacy_parseable_intent_temporaries(
    crashable_store: RuntimePaths,
) -> None:
    """Keep pre-fix parseable intent temporaries recoverable after the rename."""
    body, metadata = _owner_correction_payload(crashable_store, marker="f")
    crashed = _crash_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint="exact.intent_manifest_file_fsync",
    )
    assert crashed.returncode == 86, crashed.stderr
    temporaries = sorted(crashable_store.inbox_staging.glob(".intent-*.tmp"))
    assert len(temporaries) == 1
    temporary = temporaries[0]
    assert temporary.name.startswith(".intent-ent_")
    legacy_name = f".intent-{temporary.name.rsplit('-', maxsplit=1)[1]}"
    legacy = temporary.with_name(legacy_name)
    temporary.rename(legacy)

    recovered = _run_public_recovery(crashable_store)

    # The temporary is promoted through the intent machinery rather than
    # treated as garbage; the promoted reserved pair is then provably
    # abandoned (lease acquirable, zero bytes) and reclaimed in the same
    # pass, so nothing is stranded and nothing is reported.
    assert recovered.returncode == 0, recovered.stderr
    report = json.loads(recovered.stdout)
    assert report["issues"] == []
    assert report["recovered"] == []
    assert not legacy.exists()
    assert list(crashable_store.inbox_staging.iterdir()) == []
    assert _capture_counts(crashable_store) == (0, 0)

    idempotent = _run_public_recovery(crashable_store)
    assert idempotent.returncode == 0, idempotent.stderr
    idempotent_report = json.loads(idempotent.stdout)
    assert idempotent_report["issues"] == []
    assert idempotent_report["recovered"] == []
    assert list(crashable_store.inbox_staging.iterdir()) == []
    assert _capture_counts(crashable_store) == (0, 0)


def test_public_recovery_skips_bad_ready_custody_and_captures_healthy_work(
    crashable_store: RuntimePaths,
) -> None:
    """Catch one malformed candidate aborting recovery before unrelated work."""
    import memory.inbox as inbox

    bad_body, bad_metadata = _owner_correction_payload(crashable_store, marker="8")
    good_body, good_metadata = _owner_correction_payload(crashable_store, marker="9")
    bad = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-bad-custody.md",
        chunks=(bad_body,),
        max_bytes=len(bad_body),
        metadata=bad_metadata,
    )
    good = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-healthy-correction.md",
        chunks=(good_body,),
        max_bytes=len(good_body),
        metadata=good_metadata,
    )
    bad_path = crashable_store.inbox_staging / bad.entry_id
    bad_path.chmod(0o644)
    bad_snapshot = _staging_snapshot(crashable_store)[bad.entry_id]

    completed = _run_public_recovery(crashable_store)

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert [item["batch_id"] for item in report["recovered"]] == [
        good_metadata.batch_id
    ]
    assert [item["code"] for item in report["issues"]] == ["custody_mismatch"]
    assert bad_metadata.capture_request_id not in repr(report["issues"])
    assert _staging_snapshot(crashable_store)[bad.entry_id] == bad_snapshot
    assert not (crashable_store.inbox_staging / good.entry_id).exists()
    assert _capture_counts(crashable_store) == (1, 1)

    idempotent = _run_public_recovery(crashable_store)
    assert idempotent.returncode == 0, idempotent.stderr
    assert json.loads(idempotent.stdout)["recovered"] == []
    assert _capture_counts(crashable_store) == (1, 1)


@pytest.mark.parametrize(
    ("artifact_kind", "marker"),
    [
        ("intent_temporary", "a"),
        ("final_intent", "b"),
        ("ready_temporary", "c"),
        ("bare_ordinary", "d"),
        ("final_ready", "e"),
    ],
)
@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_public_recovery_propagates_every_valid_artifact_lease_io_failure(
    crashable_store: RuntimePaths,
    artifact_kind: str,
    marker: str,
    fault_operation: str,
) -> None:
    """Catch fail-honest lease I/O being swallowed or changed into debt."""
    payload_path = _prepare_lease_fault_artifact(
        crashable_store,
        artifact_kind=artifact_kind,
        marker=marker,
    )
    payload = payload_path.lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)

    completed = _run_public_recovery(
        crashable_store,
        flock_eio_identity=(
            (payload.st_dev, payload.st_ino) if fault_operation == "flock" else None
        ),
        open_eio_name=(payload_path.name if fault_operation == "open" else None),
    )

    assert (
        completed.returncode,
        completed.stdout,
        completed.stderr,
    ) == (1, "", "memory: invalid_argument\n")
    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_public_recovery_propagates_rollback_bundle_lease_io_failure(
    crashable_store: RuntimePaths,
    fault_operation: str,
) -> None:
    """Keep operational bundle lease failures distinct from recovery debt."""
    from memory.inbox import stage_inbox_entry

    stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-idle-rollback-bundle.md",
        chunks=(b"Synthetic bytes that mint one idle rollback bundle.\n",),
    )
    payloads = sorted(crashable_store.inbox_staging.glob(".recovery-*.stage"))
    assert len(payloads) == 1
    payload = payloads[0].lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)

    completed = _run_public_recovery(
        crashable_store,
        flock_eio_identity=(
            (payload.st_dev, payload.st_ino) if fault_operation == "flock" else None
        ),
        open_eio_name=(payloads[0].name if fault_operation == "open" else None),
    )

    assert (
        completed.returncode,
        completed.stdout,
        completed.stderr,
    ) == (1, "", "memory: invalid_argument\n")
    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_public_recovery_inspects_idle_bundle_before_exact_capture(
    crashable_store: RuntimePaths,
    fault_operation: str,
) -> None:
    """A later bundle failure cannot hide an already-committed correction."""
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="b")
    entry = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-preflight-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    inbox.stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-preflight-bundle.md",
        chunks=("Synthetic rollback bundle / 合成回滚束。\n".encode(),),
    )
    payloads = sorted(crashable_store.inbox_staging.glob(".recovery-*.stage"))
    assert len(payloads) == 1
    payload = payloads[0].lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)
    assert entry.entry_id in before_staging

    completed = _run_public_recovery(
        crashable_store,
        flock_eio_identity=(
            (payload.st_dev, payload.st_ino) if fault_operation == "flock" else None
        ),
        open_eio_name=(payloads[0].name if fault_operation == "open" else None),
    )

    assert (
        completed.returncode,
        completed.stdout,
        completed.stderr,
    ) == (1, "", "memory: invalid_argument\n")
    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


def test_public_recovery_inspects_idle_bundle_before_exact_intent_normalization(
    crashable_store: RuntimePaths,
) -> None:
    """Bundle I/O must fail before recovery rewrites a crashed exact intent."""
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="9")
    crashed = _crash_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint="exact.payload_file_fsync",
    )
    assert crashed.returncode == 86, crashed.stderr
    inbox.stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-intent-preflight-bundle.md",
        chunks=("Synthetic intent preflight bundle / 合成意图预检束。\n".encode(),),
    )
    payloads = sorted(crashable_store.inbox_staging.glob(".recovery-*.stage"))
    assert len(payloads) == 1
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)

    completed = _run_public_recovery(
        crashable_store,
        open_eio_name=payloads[0].name,
    )

    assert (
        completed.returncode,
        completed.stdout,
        completed.stderr,
    ) == (1, "", "memory: invalid_argument\n")
    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


def test_public_recovery_constructs_result_without_post_commit_identity_reload(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch a fallible runtime read after exact capture already committed."""
    import memory.cli as cli
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="e")
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-pure-recovery-result.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    original_capture = inbox.capture_exact_staged_entry
    hidden_identity = crashable_store.root / ".synthetic-hidden-runtime.json"
    identity_was_hidden = False

    def capture(
        paths: RuntimePaths,
        staged_entry: model.PrivateStagedEntry,
        *,
        metadata: model.ExactCaptureMetadata,
        directory_authority: inbox.RuntimeDirectoryAuthority | None = None,
    ) -> model.InboxBatch:
        nonlocal identity_was_hidden
        batch = original_capture(
            paths,
            staged_entry,
            metadata=metadata,
            directory_authority=directory_authority,
        )
        paths.identity.rename(hidden_identity)
        identity_was_hidden = True
        return batch

    monkeypatch.setattr(inbox, "capture_exact_staged_entry", capture)

    try:
        result = cli.main(["recover", "--home", str(crashable_store.root)])
        output = capsys.readouterr()
    finally:
        if hidden_identity.exists():
            hidden_identity.rename(crashable_store.identity)

    assert identity_was_hidden
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1
    assert list(crashable_store.inbox_staging.iterdir()) == []
    assert (result, output.err) == (0, "")
    report = json.loads(output.out)
    assert report["issues"] == []
    assert report["issues_truncated"] is False
    assert len(report["recovered"]) == 1
    assert report["recovered"][0]["batch_id"] == metadata.batch_id


@pytest.mark.parametrize(
    "inspection_name",
    [
        "_exact_intent_issues",
        "_exact_ready_issues",
        "_exact_claim_issues",
        "_active_ordinary_claim_issues",
    ],
)
def test_public_recovery_never_reenters_exact_state_inspection_after_commit(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    inspection_name: str,
) -> None:
    """A late intent/ready/claim read cannot erase a committed receipt."""
    import memory.cli as cli
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="4")
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-postcommit-inspection.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    malformed_name = f"ent_{'5' * 32}.stage.ready.json"
    malformed = crashable_store.inbox_staging / malformed_name
    malformed.write_text("{synthetic malformed", encoding="utf-8")
    malformed.chmod(0o600)
    original_capture = inbox.capture_exact_staged_entry
    original_inspection: Callable[..., object] = getattr(inbox, inspection_name)
    capture_returned = False

    def capture(
        paths: RuntimePaths,
        staged_entry: model.PrivateStagedEntry,
        *,
        metadata: model.ExactCaptureMetadata,
        directory_authority: inbox.RuntimeDirectoryAuthority | None = None,
    ) -> model.InboxBatch:
        nonlocal capture_returned
        batch = original_capture(
            paths,
            staged_entry,
            metadata=metadata,
            directory_authority=directory_authority,
        )
        capture_returned = True
        return batch

    def inspect(*args: object, **kwargs: object) -> object:
        if capture_returned:
            raise OSError(5, "synthetic post-commit exact-state inspection failure")
        return original_inspection(*args, **kwargs)

    monkeypatch.setattr(inbox, "capture_exact_staged_entry", capture)
    monkeypatch.setattr(inbox, inspection_name, inspect)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert capture_returned
    assert output.err == ""
    assert len(report["recovered"]) == 1
    assert report["recovered"][0]["batch_id"] == metadata.batch_id
    assert [issue["code"] for issue in report["issues"]] == ["malformed_manifest"]
    assert report["issues_truncated"] is False
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1


def test_public_recovery_keeps_receipt_when_committed_exact_cleanup_fails(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A committed batch remains a successful recovery even with cleanup debt."""
    import memory.cli as cli
    import memory.inbox as inbox
    from memory.errors import InvalidArgumentError

    body, metadata = _owner_correction_payload(crashable_store, marker="6")
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-postcommit-cleanup.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def fail_cleanup(
        _runtime: inbox._RuntimeRoot,
        _claim: inbox._Claim,
    ) -> None:
        raise InvalidArgumentError("synthetic committed exact cleanup failure")

    monkeypatch.setattr(inbox, "_cleanup_claim", fail_cleanup)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert output.err == ""
    assert [recovery["batch_id"] for recovery in report["recovered"]] == [
        metadata.batch_id
    ]
    assert report["issues"] == []
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1


def test_public_recovery_keeps_earlier_receipt_when_later_candidate_fails(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A later candidate failure must not replace an earlier recovery receipt."""
    import memory.cli as cli
    import memory.inbox as inbox

    first_body, first_metadata = _owner_correction_payload(crashable_store, marker="7")
    second_body, second_metadata = _owner_correction_payload(
        crashable_store,
        marker="8",
    )
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-first-recovery.md",
        chunks=(first_body,),
        max_bytes=len(first_body),
        metadata=first_metadata,
    )
    second_entry = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-second-recovery.md",
        chunks=(second_body,),
        max_bytes=len(second_body),
        metadata=second_metadata,
    )
    original_capture = inbox.capture_exact_staged_entry

    def capture(
        paths: RuntimePaths,
        entry: model.PrivateStagedEntry,
        *,
        metadata: model.ExactCaptureMetadata,
        directory_authority: inbox.RuntimeDirectoryAuthority | None = None,
    ) -> model.InboxBatch:
        if entry == second_entry:
            raise inbox._StagePayloadLeaseUnavailable(
                "synthetic later candidate lease failure"
            )
        return original_capture(
            paths,
            entry,
            metadata=metadata,
            directory_authority=directory_authority,
        )

    monkeypatch.setattr(inbox, "capture_exact_staged_entry", capture)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert output.err == ""
    assert [recovery["batch_id"] for recovery in report["recovered"]] == [
        first_metadata.batch_id
    ]
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1


def test_public_recovery_refuses_first_candidate_lease_failure(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An operational lease failure before every receipt remains fail-honest."""
    import memory.cli as cli
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="9")
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-first-lease-failure.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def fail_capture(*_args: object, **_kwargs: object) -> model.InboxBatch:
        raise inbox._StagePayloadLeaseUnavailable(
            "synthetic first candidate lease failure"
        )

    monkeypatch.setattr(inbox, "capture_exact_staged_entry", fail_capture)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 1
    output = capsys.readouterr()

    assert output.out == ""
    assert output.err == "memory: invalid_argument\n"
    assert _capture_counts(crashable_store) == (0, 0)
    assert _audit_generation(crashable_store) == 0


def test_public_recovery_retains_one_bundle_inspection_through_result(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One retained bundle authority spans exact capture and result assembly."""
    import memory.cli as cli
    import memory.inbox as inbox
    from memory.staging_provenance import decode_publication_rollback_slot

    body, metadata = _owner_correction_payload(crashable_store, marker="c")
    inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-retained-authority-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    inbox.stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-retained-authority-bundle.md",
        chunks=("Synthetic retained bundle / 合成保留束。\n".encode(),),
    )
    records = sorted(crashable_store.inbox_staging.glob(".rollback-slot-*.json"))
    assert len(records) == 1
    identity = load_runtime_identity(crashable_store)
    record = decode_publication_rollback_slot(
        records[0].read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    target_names = {
        record.payload.name,
        record.manifest.name,
        record.withdrawal.name,
    }
    target_opens: list[str] = []
    target_closes: list[str] = []
    target_descriptors: dict[int, str] = {}
    original_open = os.open
    original_close = inbox._close_descriptor_best_effort
    original_inspection = inbox._exact_recovery_inspection
    original_capture = inbox.capture_exact_staged_entry
    original_issue_snapshot = inbox._recovery_issue_snapshot
    active_inspection: inbox._ExactRecoveryInspection | None = None
    capture_authority: inbox.RuntimeDirectoryAuthority | None = None

    @contextmanager
    def observe_inspection(
        paths: RuntimePaths,
        *,
        directory_authority: inbox.RuntimeDirectoryAuthority | None,
    ) -> Iterator[inbox._ExactRecoveryInspection]:
        nonlocal active_inspection
        with original_inspection(
            paths,
            directory_authority=directory_authority,
        ) as inspection:
            active_inspection = inspection
            try:
                yield inspection
            finally:
                active_inspection = None

    def track_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if isinstance(path, str) and path in target_names:
            target_opens.append(path)
            target_descriptors[descriptor] = path
        return descriptor

    def track_close(descriptor: int) -> None:
        target = target_descriptors.pop(descriptor, None)
        if target is not None:
            target_closes.append(target)
        original_close(descriptor)

    def capture(
        paths: RuntimePaths,
        staged_entry: model.PrivateStagedEntry,
        *,
        metadata: model.ExactCaptureMetadata,
        directory_authority: inbox.RuntimeDirectoryAuthority | None = None,
    ) -> model.InboxBatch:
        nonlocal capture_authority
        assert sorted(target_opens) == sorted(target_names)
        assert target_closes == []
        assert directory_authority is not None
        capture_authority = directory_authority
        batch = original_capture(
            paths,
            staged_entry,
            metadata=metadata,
            directory_authority=directory_authority,
        )
        assert target_closes == []
        return batch

    def issue_snapshot(issues: list[model.CaptureRecoveryIssue]) -> str:
        inspection = active_inspection
        assert inspection is not None
        assert inspection.directory_authority == capture_authority
        runtime = inspection.runtime
        assert [
            (metadata.st_dev, metadata.st_ino)
            for metadata in (
                os.fstat(runtime.root_descriptor),
                os.fstat(runtime.inbox_descriptor),
                os.fstat(runtime.claims_descriptor),
                os.fstat(runtime.staging_descriptor),
            )
        ] == [
            runtime.root_identity,
            runtime.inbox_identity,
            runtime.claims_identity,
            runtime.staging_identity,
        ]
        assert sorted(target_opens) == sorted(target_names)
        assert target_closes == []
        assert sorted(target_descriptors.values()) == sorted(target_names)
        return original_issue_snapshot(issues)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(inbox, "_close_descriptor_best_effort", track_close)
    monkeypatch.setattr(inbox, "_exact_recovery_inspection", observe_inspection)
    monkeypatch.setattr(inbox, "capture_exact_staged_entry", capture)
    monkeypatch.setattr(inbox, "_recovery_issue_snapshot", issue_snapshot)

    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    first_output = capsys.readouterr()
    first = json.loads(first_output.out)

    assert first_output.err == ""
    assert first["issues"] == []
    assert first["issues_truncated"] is False
    assert len(first["recovered"]) == 1
    assert first["recovered"][0]["batch_id"] == metadata.batch_id
    assert first["recovered"][0]["lineage_id"] == metadata.target_lineage_id
    assert first["recovered"][0]["expected_head_id"] == metadata.expected_head_id
    assert sorted(target_opens) == sorted(target_names)
    assert sorted(target_closes) == sorted(target_names)
    assert target_descriptors == {}
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1

    target_opens.clear()
    target_closes.clear()
    assert cli.main(["recover", "--home", str(crashable_store.root)]) == 0
    second_output = capsys.readouterr()

    assert json.loads(second_output.out) == {
        "issues": [],
        "issues_truncated": False,
        "recovered": [],
    }
    assert second_output.err == ""
    assert sorted(target_opens) == sorted(target_names)
    assert sorted(target_closes) == sorted(target_names)
    assert target_descriptors == {}
    assert _capture_counts(crashable_store) == (1, 1)
    assert _audit_generation(crashable_store) == 1


def test_busy_rollback_bundle_with_a_replaced_member_is_not_suppressed(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A busy member cannot hide structural mismatch elsewhere in its bundle."""
    import memory.inbox as inbox

    inbox.stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-bundle-mismatch.md",
        chunks=(b"Synthetic bytes that mint a bundle for mismatch control.\n",),
    )
    records = sorted(crashable_store.inbox_staging.glob(".rollback-slot-*.json"))
    assert len(records) == 1
    from memory.staging_provenance import (
        StagingArtifactIdentity,
        decode_publication_rollback_slot,
    )

    identity = load_runtime_identity(crashable_store)
    record = decode_publication_rollback_slot(
        records[0].read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    payload = crashable_store.inbox_staging / record.payload.name
    manifest = crashable_store.inbox_staging / record.manifest.name
    original_matches = inbox._rollback_slot_member_matches
    prechecks = 0

    def replace_after_precheck(
        runtime: inbox._RuntimeRoot,
        member: StagingArtifactIdentity,
    ) -> bool:
        nonlocal prechecks
        matched = original_matches(runtime, member)
        prechecks += 1
        if prechecks == 3:
            manifest.unlink()
            manifest.write_bytes(b"")
            manifest.chmod(0o600)
        return matched

    monkeypatch.setattr(inbox, "_rollback_slot_member_matches", replace_after_precheck)
    descriptor = os.open(payload, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        issues = inbox.list_exact_recovery_issues(
            crashable_store,
            cursor=None,
            limit=100,
        )
    finally:
        os.close(descriptor)

    assert prechecks >= 3
    assert "custody_mismatch" in [issue.code for issue in issues.items]


def test_issue_pass_holds_idle_bundle_leases_through_artifact_inspection(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A publisher cannot turn a proved-idle bundle into false live debt."""
    import memory.inbox as inbox

    inbox.stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-seed-idle-bundle.md",
        chunks=(b"Synthetic seed bytes for an idle rollback bundle.\n",),
    )
    body = b"Synthetic interleaved ordinary publication bytes.\n"
    entry = inbox.stage_private_entry(
        crashable_store,
        display_name="synthetic-interleaved-publication.md",
        chunks=(body,),
        max_bytes=len(body),
    )
    original_artifact_issues = inbox._recovery_artifact_issues
    preheld: inbox._PreheldPublicationRollback | None = None
    source_descriptor: int | None = None
    source_identity: tuple[int, ...] | None = None

    def publish_between_passes(
        runtime: inbox._RuntimeRoot,
        bound_slots: inbox._BoundRollbackSlotMembers,
        live_slot_members: set[str],
        issues: list[model.CaptureRecoveryIssue],
    ) -> None:
        nonlocal preheld
        assert source_descriptor is not None
        assert source_identity is not None
        preheld = inbox._prepare_publication_rollback(
            runtime,
            source_descriptor,
            source_identity,
            entry,
        )
        original_artifact_issues(
            runtime,
            bound_slots,
            live_slot_members,
            issues,
        )

    try:
        with inbox._open_runtime_root(crashable_store) as runtime:
            source_descriptor, source_identity = inbox._open_bound_private_entry(
                runtime,
                entry,
            )
            monkeypatch.setattr(
                inbox,
                "_recovery_artifact_issues",
                publish_between_passes,
            )
            in_flight = inbox.list_exact_recovery_issues(
                crashable_store,
                cursor=None,
                limit=100,
            )

        assert preheld is not None
        assert in_flight.items == ()
    finally:
        monkeypatch.setattr(
            inbox, "_recovery_artifact_issues", original_artifact_issues
        )
        if preheld is not None:
            for descriptor in (
                preheld.anchor_descriptor,
                preheld.manifest_descriptor,
                preheld.withdrawal_descriptor,
            ):
                os.close(descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)

    unlocked = inbox.list_exact_recovery_issues(
        crashable_store,
        cursor=None,
        limit=100,
    )
    assert "custody_mismatch" in [issue.code for issue in unlocked.items]


def test_public_recovery_propagates_withdrawal_content_listing_io_failure(
    crashable_store: RuntimePaths,
) -> None:
    """A proved bundle's content-inspection I/O failure is not custody debt."""
    from memory.inbox import stage_inbox_entry
    from memory.staging_provenance import decode_publication_rollback_slot

    stage_inbox_entry(
        crashable_store,
        owner_filename="synthetic-withdrawal-listing-failure.md",
        chunks=(b"Synthetic bytes that mint a withdrawal listing control.\n",),
    )
    records = sorted(crashable_store.inbox_staging.glob(".rollback-slot-*.json"))
    assert len(records) == 1
    identity = load_runtime_identity(crashable_store)
    record = decode_publication_rollback_slot(
        records[0].read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    withdrawal = (crashable_store.inbox_staging / record.withdrawal.name).lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)

    completed = _run_public_recovery(
        crashable_store,
        listdir_eio_identity=(withdrawal.st_dev, withdrawal.st_ino),
    )

    assert (
        completed.returncode,
        completed.stdout,
        completed.stderr,
    ) == (1, "", "memory: invalid_argument\n")
    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


@pytest.mark.parametrize(
    ("artifact_kind", "marker"),
    [
        ("intent_temporary", "6"),
        ("final_intent", "7"),
        ("ready_temporary", "8"),
        ("bare_ordinary", "9"),
    ],
)
@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_recovery_issue_listing_propagates_payload_lease_io_failure(
    crashable_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
    marker: str,
    fault_operation: str,
) -> None:
    """Catch issue classification converting a lease I/O failure into debt."""
    import memory.inbox as inbox
    from memory.errors import InvalidArgumentError

    payload_path = _prepare_lease_fault_artifact(
        crashable_store,
        artifact_kind=artifact_kind,
        marker=marker,
    )
    payload = payload_path.lstat()
    before_staging = _staging_snapshot(crashable_store)
    before_counts = _capture_counts(crashable_store)
    before_generation = _audit_generation(crashable_store)
    original_flock = fcntl.flock
    original_open = os.open

    def fail_payload_flock(descriptor: int, operation: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (payload.st_dev, payload.st_ino):
            raise OSError(5, "synthetic issue lease I/O failure")
        original_flock(descriptor, operation)

    def fail_payload_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == payload_path.name:
            raise OSError(5, "synthetic issue open I/O failure")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    if fault_operation == "flock":
        monkeypatch.setattr(fcntl, "flock", fail_payload_flock)
    else:
        monkeypatch.setattr(os, "open", fail_payload_open)

    with pytest.raises(InvalidArgumentError, match="lease"):
        inbox.list_exact_recovery_issues(
            crashable_store,
            cursor=None,
            limit=10,
        )

    assert _staging_snapshot(crashable_store) == before_staging
    assert _capture_counts(crashable_store) == before_counts
    assert _audit_generation(crashable_store) == before_generation


@pytest.mark.parametrize(
    "checkpoint",
    ["exact.payload_empty_file_fsync", "exact.payload_empty_directory_fsync"],
)
def test_exact_empty_payload_barrier_crash_strands_no_owner_bytes(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Catch a reservation crash wedging every later owner correction.

    Both barriers precede the first written byte, so nothing of the owner's
    can be lost here. The residue used to be left in place on the theory that
    an empty slot an intent still names is indistinguishable from an upload
    mid-flight -- but it is distinguishable: a live uploader holds the
    per-inode flock, and the kernel drops it with the dead process, which is
    the same abandonment proof ordinary-slot reclamation already trusts.
    Leaving the pair turned one crash into a permanent quarantine of every
    later owner correction, re-reported by recovery but never repaired.
    """
    import memory.inbox as inbox

    body, metadata = _owner_correction_payload(crashable_store, marker="4")

    completed = _crash_exact_staging(
        crashable_store,
        body=body,
        metadata=metadata,
        checkpoint=checkpoint,
    )

    assert completed.returncode == 86, completed.stderr
    reserved = {path.name: path for path in crashable_store.inbox_staging.iterdir()}
    slots = sorted(name for name in reserved if name.endswith(".stage"))
    assert len(slots) == 1
    assert sorted(reserved) == [slots[0], slots[0] + ".intent.json"]
    assert reserved[slots[0]].read_bytes() == b""
    assert stat.S_IMODE(reserved[slots[0]].lstat().st_mode) == 0o600
    intent = json.loads(reserved[slots[0] + ".intent.json"].read_text(encoding="utf-8"))
    assert intent["phase"] == "reserved"
    assert "合成纠正" not in reserved[slots[0] + ".intent.json"].read_text(
        encoding="utf-8"
    )
    assert _capture_counts(crashable_store) == (0, 0)
    assert list(crashable_store.inbox.iterdir()) == []

    assert inbox.recover_exact_staged_entries(crashable_store) == ()

    assert list(crashable_store.inbox_staging.iterdir()) == []
    issues = inbox.list_exact_recovery_issues(crashable_store, cursor=None, limit=10)
    assert issues.items == ()

    retry_body, retry_metadata = _owner_correction_payload(crashable_store, marker="5")
    retried = inbox.stage_exact_private_entry(
        crashable_store,
        display_name="synthetic-unblocked-correction.md",
        chunks=(retry_body,),
        max_bytes=len(retry_body),
        metadata=retry_metadata,
    )

    assert retried.sha256 == retry_metadata.payload_sha256
    assert _capture_counts(crashable_store) == (0, 0)


def test_recovery_cannot_reclaim_a_slot_a_publication_still_owns(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the reclamation pass deleting a slot out from under an upload.

    `_reclaim_unlocked_ordinary_stage_slot` treats a zero-length slot nobody
    holds a lock on as an abandoned reservation. Publication drops the
    reservation's lock before it reopens the slot, so the lock alone does not
    cover the window between staging and publishing -- which means a completed
    slot must never be zero-length, or the pass cannot tell a live upload from
    a dead reservation and deletes it.
    """
    from memory.errors import InvalidArgumentError
    from memory.inbox import (
        publish_staged_inbox_entry,
        recover_exact_staged_entries,
        stage_private_entry,
    )

    with pytest.raises(InvalidArgumentError):
        stage_private_entry(
            synthetic_store,
            display_name="empty-upload.txt",
            chunks=[b""],
            max_bytes=64 * 1024,
        )
    # The refused slot is drained, so it consumes none of the staging bound.
    assert [
        name
        for name in sorted(
            path.name for path in synthetic_store.inbox_staging.iterdir()
        )
        if name.startswith("ent_")
    ] == []

    entry = stage_private_entry(
        synthetic_store,
        display_name="real-upload.txt",
        chunks=[b"A synthetic note.\n"],
        max_bytes=64 * 1024,
    )
    recover_exact_staged_entries(synthetic_store)
    published = publish_staged_inbox_entry(synthetic_store, entry)

    assert entry.byte_length > 0
    assert published.display_name == "real-upload.txt"
    assert (synthetic_store.inbox / "real-upload.txt").is_file()


def _crash_public_recovery(
    paths: RuntimePaths, checkpoint: str
) -> subprocess.CompletedProcess[str]:
    """Kill public recovery without running unwinding or cleanup handlers."""
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
inbox._checkpoint = lambda name: _os._exit(86) if name == {checkpoint!r} else None
inbox.recover_exact_staged_entries(paths)
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    ("seed_checkpoint", "checkpoint"),
    [
        ("exact.payload_directory_fsync", "exact.recovery_payload_before_file_fsync"),
        ("exact.payload_directory_fsync", "exact.recovery_payload_file_fsync"),
        ("exact.payload_directory_fsync", "exact.recovery_payload_directory_fsync"),
        (
            "exact.ready_manifest_file_fsync",
            "exact.ready_manifest_recovery_directory_fsync",
        ),
    ],
)
def test_recovery_process_death_preserves_complete_exact_custody(
    crashable_store: RuntimePaths,
    seed_checkpoint: str,
    checkpoint: str,
) -> None:
    """A second crash during normalization must neither lose nor duplicate a correction."""
    import memory.inbox as inbox
    from memory.retrieval import read_source

    paths = crashable_store
    body, metadata = _owner_correction_payload(paths, marker="6")
    seeded = _crash_exact_staging(
        paths, body=body, metadata=metadata, checkpoint=seed_checkpoint
    )
    assert seeded.returncode == 86, seeded.stderr
    killed = _crash_public_recovery(paths, checkpoint)
    assert killed.returncode == 86, killed.stderr
    assert _capture_counts(paths) == (0, 0)
    assert any(
        path.read_bytes() == body for path in paths.inbox_staging.glob("*.stage")
    )
    assert list(paths.inbox.iterdir()) == []

    recovered = inbox.recover_exact_staged_entries(paths)
    assert len(recovered) == 1
    receipt = recovered[0]
    assert receipt.batch_id == metadata.batch_id
    assert receipt.capture_request_id == metadata.capture_request_id
    assert receipt.lineage_id == metadata.target_lineage_id
    assert receipt.expected_head_id == metadata.expected_head_id
    assert read_source(paths, receipt.source_id).text == body.decode()
    assert _capture_counts(paths) == (1, 1)
    assert list(paths.inbox_staging.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []
    assert list(paths.inbox.iterdir()) == []
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _capture_counts(paths) == (1, 1)
    _assert_no_canonical_interpretation(paths)


def test_intent_promotion_process_death_reclaims_only_abandoned_empty_custody(
    crashable_store: RuntimePaths,
) -> None:
    """A crash after promoting an unbound intent cannot strand an empty upload forever."""
    import memory.inbox as inbox

    paths = crashable_store
    body, metadata = _owner_correction_payload(paths, marker="7")
    seeded = _crash_exact_staging(
        paths,
        body=body,
        metadata=metadata,
        checkpoint="exact.intent_manifest_file_fsync",
    )
    assert seeded.returncode == 86, seeded.stderr
    killed = _crash_public_recovery(paths, "exact.intent_recovery_directory_fsync")
    assert killed.returncode == 86, killed.stderr
    assert len(list(paths.inbox_staging.glob("*.intent.json"))) == 1
    assert _capture_counts(paths) == (0, 0)
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert list(paths.inbox_staging.iterdir()) == []
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _capture_counts(paths) == (0, 0)
    assert list(paths.inbox.iterdir()) == []
    _assert_no_canonical_interpretation(paths)


@pytest.mark.parametrize(
    "checkpoint",
    [
        "exact.bound_manifest_publish",
        "exact.incomplete_before_quarantine_rename",
        "exact.incomplete_quarantine_rename",
    ],
)
def test_incomplete_exact_process_death_never_captures_a_prefix(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """A bound empty upload or torn prefix stays private and cannot become a source."""
    import memory.inbox as inbox

    paths = crashable_store
    body, metadata = _owner_correction_payload(paths, marker="8")
    seeded = _crash_exact_staging(
        paths, body=body, metadata=metadata, checkpoint="exact.bound_manifest_publish"
    )
    assert seeded.returncode == 86, seeded.stderr
    staged = list(paths.inbox_staging.glob("ent_*.stage"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b""
    prefix = b"" if checkpoint == "exact.bound_manifest_publish" else body[:37]
    if prefix:
        # A torn streaming write preserves the already bound inode.
        staged[0].write_bytes(prefix)
        killed = _crash_public_recovery(paths, checkpoint)
        assert killed.returncode == 86, killed.stderr
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _capture_counts(paths) == (0, 0)
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []
    quarantined = list(paths.inbox_staging.glob(".recovery-*.stage"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == prefix
    assert not staged[0].exists()
    issues = inbox.list_exact_recovery_issues(paths, cursor=None, limit=10)
    assert issues.items
    snapshot = _staging_snapshot(paths)
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _staging_snapshot(paths) == snapshot
    assert _capture_counts(paths) == (0, 0)
    _assert_no_canonical_interpretation(paths)


def _crash_ordinary_publication(
    paths: RuntimePaths,
    *,
    body: bytes,
    checkpoint: str,
    rollback: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Publish with real filesystem effects, optionally fail the Inbox durability barrier."""
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
real_fsync = _os.fsync
inbox_identity = (paths.inbox.stat().st_dev, paths.inbox.stat().st_ino)
published = False

def crash_checkpoint(name):
    global published
    if name == "staging.publish_rename":
        published = True
    if name == {checkpoint!r}:
        _os._exit(86)

def fail_publication_fsync(descriptor):
    metadata = _os.fstat(descriptor)
    if {rollback!r} and published and (metadata.st_dev, metadata.st_ino) == inbox_identity:
        raise OSError(5, "synthetic publication durability failure")
    real_fsync(descriptor)

inbox._checkpoint = crash_checkpoint
inbox.os.fsync = fail_publication_fsync
inbox.stage_inbox_entry(
    paths,
    owner_filename="synthetic-crash-publication.md",
    chunks=(base64.b64decode({base64.b64encode(body).decode("ascii")!r}),),
)
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _assert_no_canonical_interpretation(paths: RuntimePaths) -> None:
    """Neither custody recovery nor upload retry is approval to create memory."""
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        row = connection.execute(
            "SELECT (SELECT count(*) FROM memory_revisions), "
            "(SELECT count(*) FROM change_sets)"
        ).fetchone()
        assert row is not None
        assert tuple(row) == (0, 0)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "checkpoint",
    [
        "staging.publication_anchor_directory_fsync",
        "staging.publication_slot_record_file_fsync",
        "staging.publication_slot_record_publish",
        "staging.withdrawal_directory_fsync",
    ],
)
def test_publication_preparation_process_death_keeps_original_upload_retryable(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """A dead rollback-capability preparation cannot consume or publish staged bytes."""
    import memory.inbox as inbox
    from memory.retrieval import read_source

    paths = crashable_store
    body = "Synthetic crash preparation: 合成上传仍需完整保管。\n".encode()
    killed = _crash_ordinary_publication(paths, body=body, checkpoint=checkpoint)
    assert killed.returncode == 86, killed.stderr
    staged = list(paths.inbox_staging.glob("ent_*.stage"))
    assert len(staged) == 1
    payload_identity = (staged[0].stat().st_dev, staged[0].stat().st_ino)
    assert staged[0].read_bytes() == body
    assert list(paths.inbox.iterdir()) == []
    assert _capture_counts(paths) == (0, 0)

    assert inbox.recover_exact_staged_entries(paths) == ()
    assert staged[0].read_bytes() == body
    assert (staged[0].stat().st_dev, staged[0].stat().st_ino) == payload_identity
    assert inbox.recover_exact_staged_entries(paths) == ()
    entry = model.PrivateStagedEntry(
        entry_id=staged[0].name,
        display_name="synthetic-crash-publication.md",
        byte_length=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    inbox.publish_staged_inbox_entry(paths, entry)
    assert [path.name for path in paths.inbox.iterdir()] == [entry.display_name]
    assert (paths.inbox / entry.display_name).read_bytes() == body
    assert not staged[0].exists()
    batch = inbox.scan_inbox(paths, clock=FakeClock())
    assert batch.source_count == 1
    assert read_source(paths, batch.source_ids[0]).text == body.decode()
    assert _capture_counts(paths) == (1, 1)
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _capture_counts(paths) == (1, 1)
    _assert_no_canonical_interpretation(paths)


@pytest.mark.parametrize(
    "checkpoint",
    [
        "staging.publish_directories_fsync",
        "staging.publish_inbox_directory_fsync",
        "staging.publish_staging_directory_fsync",
    ],
)
def test_publication_barrier_process_death_scans_exactly_one_complete_upload(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """A dead publisher leaves one complete Inbox entry; recovery cannot publish its anchor."""
    import memory.inbox as inbox
    from memory.errors import NoEligibleSourcesError
    from memory.retrieval import read_source

    paths = crashable_store
    body = "Synthetic published bytes: 合成笔记只有一个可扫描副本。\n".encode()
    killed = _crash_ordinary_publication(paths, body=body, checkpoint=checkpoint)
    assert killed.returncode == 86, killed.stderr
    destination = paths.inbox / "synthetic-crash-publication.md"
    assert list(paths.inbox.iterdir()) == [destination]
    assert destination.read_bytes() == body
    assert _capture_counts(paths) == (0, 0)
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert list(paths.inbox.iterdir()) == [destination]
    assert destination.read_bytes() == body
    batch = inbox.scan_inbox(paths, clock=FakeClock())
    assert batch.source_count == 1
    assert read_source(paths, batch.source_ids[0]).text == body.decode()
    assert _capture_counts(paths) == (1, 1)
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []
    assert inbox.recover_exact_staged_entries(paths) == ()
    with pytest.raises(NoEligibleSourcesError):
        inbox.scan_inbox(paths, clock=FakeClock())
    assert _capture_counts(paths) == (1, 1)
    _assert_no_canonical_interpretation(paths)


@pytest.mark.parametrize(
    "checkpoint",
    [
        "staging.recovery_manifest_directory_fsync",
        "staging.recovery_manifest_publish",
        "staging.recovery_manifest_verified_directory_fsync",
        "staging.withdrawal_child_recycled",
        "staging.withdrawal_directory_rollback_fsync",
    ],
)
def test_rollback_process_death_retains_private_manifest_custody_without_republication(
    crashable_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """A crash in rollback must preserve a verifiable copy and never requeue withdrawn bytes."""
    import memory.inbox as inbox
    from memory.errors import NoEligibleSourcesError

    paths = crashable_store
    body = "Synthetic rollback custody: 合成撤回内容必须保留在私有区。\n".encode()
    killed = _crash_ordinary_publication(
        paths, body=body, checkpoint=checkpoint, rollback=True
    )
    assert killed.returncode == 86, killed.stderr
    assert list(paths.inbox.iterdir()) == []
    manifests = list(paths.inbox_staging.glob(".recovery-*.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text())
    assert manifest["kind"] == "ordinary_publication"
    assert manifest["byte_length"] == len(body)
    assert manifest["sha256"] == hashlib.sha256(body).hexdigest()
    retained = paths.inbox_staging / manifest["payload_name"]
    assert retained.read_bytes() == body
    durable_pair = (retained.read_bytes(), manifests[0].read_bytes())
    assert _capture_counts(paths) == (0, 0)

    assert inbox.recover_exact_staged_entries(paths) == ()
    assert (retained.read_bytes(), manifests[0].read_bytes()) == durable_pair
    assert not list(paths.inbox_staging.glob("ent_*.stage"))
    issues = inbox.list_exact_recovery_issues(paths, cursor=None, limit=10)
    assert issues.items
    assert body.decode().strip() not in repr(issues.items)
    snapshot = _staging_snapshot(paths)
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _staging_snapshot(paths) == snapshot
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []
    with pytest.raises(NoEligibleSourcesError):
        inbox.scan_inbox(paths, clock=FakeClock())
    assert _capture_counts(paths) == (0, 0)
    _assert_no_canonical_interpretation(paths)


def test_prepublication_cleanup_process_death_preserves_existing_destination(
    crashable_store: RuntimePaths,
) -> None:
    """A collision cleanup crash cannot delete the old Inbox entry or publish rejected bytes."""
    import memory.inbox as inbox
    from memory.errors import InvalidArgumentError
    from memory.retrieval import read_source

    paths = crashable_store
    destination = paths.inbox / "synthetic-crash-publication.md"
    old_body = "Synthetic existing upload: 合成旧文件不可覆盖。\n".encode()
    rejected_body = b"Synthetic rejected collision bytes.\n"
    destination.write_bytes(old_body)
    original = (destination.stat().st_dev, destination.stat().st_ino)
    killed = _crash_ordinary_publication(
        paths,
        body=rejected_body,
        checkpoint="staging.prepublication_cleanup_directory_fsync",
    )
    assert killed.returncode == 86, killed.stderr
    assert not list(paths.inbox_staging.glob("ent_*.stage"))
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert destination.read_bytes() == old_body
    assert (destination.stat().st_dev, destination.stat().st_ino) == original
    assert list(paths.inbox.iterdir()) == [destination]
    with pytest.raises(InvalidArgumentError):
        inbox.stage_inbox_entry(
            paths, owner_filename=destination.name, chunks=(rejected_body,)
        )
    assert not list(paths.inbox_staging.glob("ent_*.stage"))
    assert destination.read_bytes() == old_body
    batch = inbox.scan_inbox(paths, clock=FakeClock())
    assert batch.source_count == 1
    assert read_source(paths, batch.source_ids[0]).text == old_body.decode()
    assert inbox.recover_exact_staged_entries(paths) == ()
    assert _capture_counts(paths) == (1, 1)
    assert list(paths.inbox.iterdir()) == []
    _assert_no_canonical_interpretation(paths)


@pytest.mark.parametrize(
    "change", ["replace", "remove", "append", "rewrite", "symlink"]
)
def test_claim_revalidates_every_observed_source_after_unlocked_observation(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    """A stale observation cannot capture replacement or changed producer bytes."""
    from memory import inbox
    from memory.model import Issue
    from memory.sources import list_sources

    changed = synthetic_store.inbox / "a-synthetic-change.txt"
    stable = synthetic_store.inbox / "b-synthetic-stable.txt"
    changed.write_bytes(b"synthetic first version")
    stable.write_bytes(b"synthetic stable version")
    before = changed.stat()
    replacement = synthetic_store.root / "synthetic-replacement.txt"
    replacement.write_bytes(b"synthetic other version")
    reached = False

    def change_after_observation(checkpoint: str) -> None:
        nonlocal reached
        if checkpoint != "scan.observation_complete":
            return
        reached = True
        if change == "replace":
            replacement.replace(changed)
        elif change == "remove":
            changed.unlink()
        elif change == "append":
            with changed.open("ab") as stream:
                stream.write(b" appended")
        elif change == "rewrite":
            # Preserve inode, size and mtime: only revalidating the observed
            # digest after custody can reject this replacement of the bytes.
            changed.write_bytes(b"synthetic other version")
            os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns))
        else:
            changed.unlink()
            changed.symlink_to(replacement)

    monkeypatch.setattr(inbox, "_checkpoint", change_after_observation)
    batch = inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert reached
    assert batch.source_count == 1
    assert batch.issues == (Issue(code="changed", count=1),)
    sources = list_sources(synthetic_store, None, limit=10).items
    assert [source.original_name for source in sources] == [stable.name]
    assert list(synthetic_store.inbox_claims.iterdir()) == []
    if change == "remove":
        assert not changed.exists()
    elif change == "symlink":
        assert changed.is_symlink()
        assert replacement.read_bytes() == b"synthetic other version"
    elif change == "append":
        assert changed.read_bytes() == b"synthetic first version appended"
    else:
        assert changed.read_bytes() == b"synthetic other version"


@pytest.mark.parametrize("directory", ["inbox", "inbox_claims", "inbox_staging"])
def test_observation_cannot_transfer_custody_through_replaced_directory_authority(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    directory: str,
) -> None:
    from memory import inbox
    from memory.errors import InvalidArgumentError
    from memory.sources import list_sources

    source = synthetic_store.inbox / "synthetic-authority.txt"
    source.write_bytes(b"synthetic authority is held")
    selected = getattr(synthetic_store, directory)
    assert isinstance(selected, Path)
    detached = synthetic_store.root / "synthetic-detached-directory"
    reached = False

    def replace_after_observation(checkpoint: str) -> None:
        nonlocal reached
        if checkpoint == "scan.observation_complete":
            reached = True
            selected.rename(detached)
            selected.mkdir(mode=0o700)
            (selected / "synthetic-foreign.txt").write_bytes(b"must remain untouched")

    monkeypatch.setattr(inbox, "_checkpoint", replace_after_observation)
    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())

    assert reached
    assert (selected / "synthetic-foreign.txt").read_bytes() == b"must remain untouched"
    original = detached / source.name if directory == "inbox" else source
    assert original.read_bytes() == b"synthetic authority is held"
    assert list_sources(synthetic_store, None, limit=10).items == ()


def test_scan_heals_legacy_progress_tables_and_rolls_back_failed_cohort_publication(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from memory import inbox
    from memory.database import _writer_transaction as original_transaction
    from memory.sources import list_sources

    identity = load_runtime_identity(synthetic_store)
    key = load_master_key(identity)
    connection = open_database(synthetic_store, key, read_only=False)
    try:
        connection.execute("DROP TABLE inbox_scan_candidates")
        connection.execute("DROP TABLE inbox_scan_progress")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    source = synthetic_store.inbox / "synthetic-legacy-scan.txt"
    source.write_bytes(b"synthetic legacy progress adoption")
    armed = False

    class SyntheticRollback(RuntimeError):
        pass

    @contextmanager
    def fail_pointer_commit(paths: RuntimePaths) -> Iterator[Connection]:
        nonlocal armed
        with original_transaction(paths) as opened:
            yield opened
            pointer = opened.execute(
                "SELECT token FROM inbox_scan_progress WHERE singleton = 1"
            ).fetchone()
            if pointer is not None and not armed:
                armed = True
                raise SyntheticRollback("synthetic pointer publication rollback")

    monkeypatch.setattr(inbox, "_writer_transaction", fail_pointer_commit)
    with pytest.raises(SyntheticRollback):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert armed
    connection = open_database(synthetic_store, key, read_only=True)
    try:
        assert connection.execute(
            "SELECT count(*) FROM inbox_scan_progress"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM inbox_scan_candidates"
        ).fetchone() == (1,)
    finally:
        connection.close()
    assert source.read_bytes() == b"synthetic legacy progress adoption"
    assert list_sources(synthetic_store, None, limit=10).items == ()

    monkeypatch.setattr(inbox, "_writer_transaction", original_transaction)
    batch = inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert batch.source_count == 1
    connection = open_database(synthetic_store, key, read_only=True)
    try:
        assert connection.execute(
            "SELECT count(*) FROM inbox_scan_candidates"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM inbox_scan_progress"
        ).fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize("boundary", ["connect", "transaction"])
def test_scan_database_and_wal_stay_bound_when_lexical_root_is_replaced(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    """SQLite must retain its inode path and never write the replacement root."""
    from typing import cast

    from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]

    from memory import inbox
    from memory.database import _writer_transaction as original_transaction
    from memory.errors import InvalidArgumentError
    from memory.sources import list_sources

    source = synthetic_store.inbox / "synthetic-database-authority.txt"
    source.write_bytes(b"synthetic source for a directory-bound transaction")
    root_metadata = synthetic_store.root.stat()
    anchor = f"/.vol/{root_metadata.st_dev}/{root_metadata.st_ino}/store.sqlite3"
    detached = tmp_path / "synthetic-detached-database-root"
    reached = False
    observed_names: list[str] = []
    original_connect = sqlcipher.connect

    def replace_root() -> None:
        nonlocal reached
        reached = True
        synthetic_store.root.rename(detached)
        synthetic_store.root.mkdir(mode=0o700)
        (synthetic_store.root / "synthetic-foreign-marker").write_bytes(b"unchanged")

    def connect_with_replacement(name: str, **kwargs: object) -> Connection:
        if (
            boundary == "connect"
            and not reached
            and name.endswith("?mode=rw")
            and any(synthetic_store.inbox_claims.iterdir())
        ):
            assert name == Path(anchor).as_uri() + "?mode=rw"
            replace_root()
        return cast(Connection, original_connect(name, **kwargs))

    @contextmanager
    def transaction_with_replacement(paths: RuntimePaths) -> Iterator[Connection]:
        with original_transaction(paths) as connection:
            if (
                boundary == "transaction"
                and not reached
                and any(synthetic_store.inbox_claims.iterdir())
            ):
                observed_names.append(
                    str(connection.execute("PRAGMA database_list").fetchone()[2])
                )
                replace_root()
            yield connection

    monkeypatch.setattr(sqlcipher, "connect", connect_with_replacement)
    monkeypatch.setattr(inbox, "_writer_transaction", transaction_with_replacement)
    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert reached
    if boundary == "transaction":
        assert observed_names == [anchor]
    assert sorted(path.name for path in synthetic_store.root.iterdir()) == [
        "synthetic-foreign-marker"
    ]
    assert (
        synthetic_store.root / "synthetic-foreign-marker"
    ).read_bytes() == b"unchanged"
    assert len(list((detached / "inbox-claims").iterdir())) == 1

    monkeypatch.setattr(sqlcipher, "connect", original_connect)
    monkeypatch.setattr(inbox, "_writer_transaction", original_transaction)
    (synthetic_store.root / "synthetic-foreign-marker").unlink()
    synthetic_store.root.rmdir()
    detached.rename(synthetic_store.root)
    assert list_sources(synthetic_store, None, limit=10).items == ()
    recovered = inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert recovered.source_count == 1
    assert len(list_sources(synthetic_store, None, limit=10).items) == 1
    assert list(synthetic_store.inbox_claims.iterdir()) == []


def test_scan_scope_preserves_another_connections_native_sqlite_read_lock(
    synthetic_store: RuntimePaths,
) -> None:
    """Closing the scan's identity pin must not release another SQLite lock."""
    from memory.errors import NoEligibleSourcesError
    from memory.inbox import scan_inbox

    identity = load_runtime_identity(synthetic_store)
    reader = open_database(synthetic_store, load_master_key(identity), read_only=True)
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 510, 0x40000002, os.SEEK_SET)
    except BlockingIOError:
        raise SystemExit(42)
finally:
    os.close(fd)
"""

    def reader_lock_is_held() -> bool:
        result = subprocess.run(
            [sys.executable, "-c", script, str(synthetic_store.database)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode in (0, 42), result.stderr
        return result.returncode == 42

    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT product FROM store_meta").fetchone() == (
            "memory",
        )
        assert reader.in_transaction
        assert reader_lock_is_held()
        with pytest.raises(NoEligibleSourcesError):
            scan_inbox(synthetic_store, clock=FakeClock())
        assert reader.in_transaction
        assert reader_lock_is_held()
    finally:
        reader.close()


@pytest.mark.parametrize("read_only", [True, False])
def test_rejected_database_open_preserves_another_connections_native_sqlite_lock(
    synthetic_store: RuntimePaths,
    read_only: bool,
) -> None:
    """Wrong-key classification must not release any live SQLite reader lock."""
    from memory import inbox
    from memory.database import _database_directory_authority
    from memory.errors import KeyMismatchError

    identity = load_runtime_identity(synthetic_store)
    reader = open_database(synthetic_store, load_master_key(identity), read_only=True)
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 510, 0x40000002, os.SEEK_SET)
    except BlockingIOError:
        raise SystemExit(42)
finally:
    os.close(fd)
"""

    def reader_lock_is_held() -> bool:
        result = subprocess.run(
            [sys.executable, "-c", script, str(synthetic_store.database)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode in (0, 42), result.stderr
        return result.returncode == 42

    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT product FROM store_meta").fetchone() == (
            "memory",
        )
        assert reader_lock_is_held()
        with inbox._open_runtime_root(synthetic_store) as runtime:
            with _database_directory_authority(
                synthetic_store,
                runtime.root_descriptor,
                lambda: inbox._verify_runtime_root(runtime),
            ):
                assert reader_lock_is_held()
                with pytest.raises(KeyMismatchError):
                    open_database(synthetic_store, b"z" * 32, read_only=read_only)
                assert reader.in_transaction
                assert reader_lock_is_held()
        assert reader.in_transaction
        assert reader_lock_is_held()
    finally:
        reader.close()


def test_inactive_roster_cleanup_respects_encoded_filename_metadata_limit(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """APFS accepts Unicode names whose UTF-8 length exceeds its character count."""
    from memory import inbox
    from memory.database import _writer_transaction as original_transaction

    names = [f"{index:03d}-" + "中" * 240 for index in range(64)]
    for name in names:
        (synthetic_store.inbox / name).write_bytes(b"synthetic unicode filename")
    with writer_session(synthetic_store) as connection:
        connection.executemany(
            "INSERT INTO inbox_scan_candidates (token, ordinal, name) VALUES (?, ?, ?)",
            [("a" * 32, ordinal, name) for ordinal, name in enumerate(names)],
        )
    deleted_payloads: list[int] = []

    @contextmanager
    def observe_cleanup(paths: RuntimePaths) -> Iterator[Connection]:
        with original_transaction(paths) as connection:
            before = set(
                connection.execute("SELECT name FROM inbox_scan_candidates").fetchall()
            )
            yield connection
            after = set(
                connection.execute("SELECT name FROM inbox_scan_candidates").fetchall()
            )
            if before != after:
                deleted_payloads.append(
                    sum(len(name.encode("utf-8")) + 64 for (name,) in before - after)
                )

    class SyntheticStop(RuntimeError):
        pass

    def stop_after_cleanup(checkpoint: str) -> None:
        if checkpoint == "scan.roster_cleanup_commit":
            raise SyntheticStop

    monkeypatch.setattr(inbox, "_writer_transaction", observe_cleanup)
    monkeypatch.setattr(inbox, "_checkpoint", stop_after_cleanup)
    with pytest.raises(SyntheticStop):
        inbox.scan_inbox(synthetic_store, clock=FakeClock())
    assert len(deleted_payloads) == 1
    assert 0 < deleted_payloads[0] <= 16 * 1024
    assert sorted(path.name for path in synthetic_store.inbox.iterdir()) == names


def test_scan_database_connection_rejects_replacement_restored_after_native_open(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Named-path checks must also bind the actual SQLite connection inode."""
    import shutil
    from dataclasses import replace
    from typing import cast

    from sqlcipher3 import dbapi2 as sqlcipher

    from memory import inbox
    from memory.database import (
        _apply_cipher_settings,
        _database_directory_authority,
    )
    from memory.errors import InvalidArgumentError, StoreOpenError

    identity = load_runtime_identity(synthetic_store)
    key = load_master_key(identity)
    replacement = tmp_path / "synthetic-connection-replacement.sqlite3"
    original_slot = tmp_path / "synthetic-held-original.sqlite3"
    original = open_database(synthetic_store, key, read_only=False)
    try:
        original.execute("CREATE TABLE synthetic_connection_marker (value TEXT)")
        original.execute("INSERT INTO synthetic_connection_marker VALUES ('original')")
        original.commit()
    finally:
        original.close()
    shutil.copyfile(synthetic_store.database, replacement)
    replacement.chmod(0o600)
    copied = sqlcipher.connect(str(replacement))
    try:
        _apply_cipher_settings(copied, key)
        copied.execute("UPDATE synthetic_connection_marker SET value='replacement'")
        copied.commit()
        copied.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        copied.close()
    original_connect = sqlcipher.connect
    swapped = False
    read_from_replacement: list[str] = []

    def transient_replacement(name: str, **kwargs: object) -> Connection:
        nonlocal swapped
        if not name.endswith("?mode=rw") or swapped:
            return cast(Connection, original_connect(name, **kwargs))
        swapped = True
        synthetic_store.database.rename(original_slot)
        replacement.rename(synthetic_store.database)
        try:
            connection = cast(Connection, original_connect(name, **kwargs))
        finally:
            synthetic_store.database.rename(replacement)
            original_slot.rename(synthetic_store.database)
        return connection

    monkeypatch.setattr(sqlcipher, "connect", transient_replacement)
    with inbox._open_runtime_root(synthetic_store) as runtime:
        with _database_directory_authority(
            synthetic_store,
            runtime.root_descriptor,
            lambda: inbox._verify_runtime_root(runtime),
        ):
            with pytest.raises(
                (InvalidArgumentError, StoreOpenError),
                match=r"identity|moved|changed",
            ):
                with writer_session(synthetic_store) as connection:
                    row = connection.execute(
                        "SELECT value FROM synthetic_connection_marker"
                    ).fetchone()
                    assert row is not None
                    read_from_replacement.append(str(row[0]))
                    connection.execute(
                        "UPDATE synthetic_connection_marker SET value='writer-used-' || value"
                    )
    assert swapped
    assert read_from_replacement == []

    for paths, expected in (
        (synthetic_store, "original"),
        (replace(synthetic_store, database=replacement), "replacement"),
    ):
        checked = open_database(paths, key, read_only=True)
        try:
            assert checked.execute(
                "SELECT value FROM synthetic_connection_marker"
            ).fetchone() == (expected,)
            assert checked.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            checked.close()


@pytest.mark.parametrize("failure", ["missing", "unsupported", "malformed", "mismatch"])
def test_scan_fails_closed_before_sql_when_native_connection_identity_is_unavailable(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from typing import cast

    from sqlcipher3 import dbapi2 as sqlcipher

    from memory.errors import InvalidArgumentError, StoreOpenError
    from memory.inbox import scan_inbox

    metadata = synthetic_store.database.stat()
    original_connect = sqlcipher.connect
    closed: list[bool] = []

    class UnverifiedConnection:
        def __init__(self, connection: Connection) -> None:
            self.connection = connection

        def file_identity(self) -> object:
            if failure == "missing":
                raise AttributeError("synthetic missing native method")
            if failure == "unsupported":
                raise sqlcipher.OperationalError("synthetic unsupported VFS")
            if failure == "malformed":
                return (True, metadata.st_ino)
            return (metadata.st_dev, metadata.st_ino + 1)

        def execute(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("unverified native connection executed SQL")

        def close(self) -> None:
            self.connection.close()
            closed.append(True)

    def unverified_connect(name: str, **kwargs: object) -> Connection:
        connection = cast(Connection, original_connect(name, **kwargs))
        return cast(Connection, UnverifiedConnection(connection))

    monkeypatch.setattr(sqlcipher, "connect", unverified_connect)
    with pytest.raises(
        (InvalidArgumentError, StoreOpenError), match=r"native.*identity"
    ):
        scan_inbox(synthetic_store, clock=FakeClock())
    assert closed == [True]
    assert synthetic_store.database.stat().st_ino == metadata.st_ino
    assert list(synthetic_store.inbox_claims.iterdir()) == []
