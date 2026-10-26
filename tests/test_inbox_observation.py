"""Synthetic proofs that Inbox observation stays responsive and makes progress."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

import keyring
import pytest
from synthetic import make_synthetic_store

from memory import inbox
from memory.database import open_database, writer_session
from memory.errors import StoreBusyError
from memory.keys import KEYCHAIN_SERVICE, load_master_key
from memory.model import InboxBatch, RuntimePaths
from memory.runtime import load_runtime_identity
from memory.sources import list_sources

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_KEYCHAIN_ITEM = "SYNTHETIC_INBOX_OBSERVATION_KEYCHAIN_ITEM"


class ObservationClock:
    def __init__(self, on_sleep: Callable[[], None] | None = None) -> None:
        self.timestamp = 1_900_000_000.0
        self.on_sleep = on_sleep

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        if self.on_sleep is not None:
            self.on_sleep()
        self.timestamp += seconds


@pytest.mark.parametrize("phase", ["discovery", "settling", "digest"])
def test_scan_observation_allows_an_unrelated_writer(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    """A paused filesystem observation must not occupy the Store writer lock.

    Events put the writer attempt inside each observation phase, rather than
    relying on a short sleep to guess when a worker reached the expensive work.
    The complete scan after release also proves the pause reached a real path.
    """
    (synthetic_store.inbox / "synthetic-observation.txt").write_text(
        "合成观察：稳定的收件箱来源。\n", encoding="utf-8"
    )
    reached = threading.Event()
    release = threading.Event()
    batches: list[InboxBatch] = []
    failures: list[BaseException] = []

    def pause() -> None:
        if not reached.is_set():
            reached.set()
            if not release.wait(timeout=15):
                raise AssertionError("synthetic observation was not released")

    original_discovery = inbox._visible_regular_files
    original_digest = inbox._digest_visible_file

    def paused_discovery(
        descriptor: int,
        policy: inbox.ScanPolicy,
    ) -> tuple[list[inbox._VisibleCandidate], Counter[str]]:
        pause()
        return original_discovery(descriptor, policy)

    def paused_digest(
        descriptor: int,
        name: str,
        expected: inbox._VisibleCandidate,
    ) -> str:
        pause()
        return original_digest(descriptor, name, expected)

    if phase == "discovery":
        monkeypatch.setattr(inbox, "_visible_regular_files", paused_discovery)
    elif phase == "digest":
        monkeypatch.setattr(inbox, "_digest_visible_file", paused_digest)
    clock = ObservationClock(pause if phase == "settling" else None)

    def run_scan() -> None:
        try:
            batches.append(inbox.scan_inbox(synthetic_store, clock=clock))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=run_scan)
    worker.start()
    try:
        assert reached.wait(timeout=15), "scan did not reach observation phase"
        with writer_session(synthetic_store) as connection:
            assert connection.execute("SELECT 1").fetchone() == (1,)
        with pytest.raises(StoreBusyError):
            inbox.scan_inbox(synthetic_store, clock=ObservationClock())
        assert list_sources(synthetic_store, limit=100).items == ()
    finally:
        release.set()
        worker.join(timeout=15)

    assert not worker.is_alive()
    assert failures == []
    assert len(batches) == 1
    assert batches[0].source_count == 1
    assert len(list_sources(synthetic_store, limit=100).items) == 1
    assert list(synthetic_store.inbox.iterdir()) == []


@pytest.fixture
def observation_process_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RuntimePaths]:
    """Export only a fresh disposable fixture's synthetic key to child scans."""
    monkeypatch.setattr(keyring, "delete_password", lambda _service, _account: None)
    yield from make_synthetic_store(
        tmp_path,
        monkeypatch,
        export_keychain_item=SYNTHETIC_KEYCHAIN_ITEM,
    )


def _scan_in_fresh_process(
    paths: RuntimePaths,
    *,
    checkpoint: str | None = None,
) -> subprocess.CompletedProcess[str]:
    identity = load_runtime_identity(paths)
    script = f"""
import json
import os
from pathlib import Path

import keyring

items = {{
    ({KEYCHAIN_SERVICE!r}, {identity.store_id!r}): os.environ[
        {SYNTHETIC_KEYCHAIN_ITEM!r}
    ]
}}
backend = type("Keyring", (), {{}})()
type(backend).__module__ = "keyring.backends.macOS"
keyring.get_keyring = lambda: backend
keyring.get_password = lambda service, account: items.get((service, account))
keyring.set_password = lambda service, account, value: items.__setitem__(
    (service, account), value
)
keyring.delete_password = lambda service, account: items.pop((service, account))

from memory import keys

def unexpected_synthetic_key_creation(identity, encoded):
    raise AssertionError("a scan must never create a Store key")

keys._store_master_key_exclusive = unexpected_synthetic_key_creation

from memory import inbox
from memory.errors import NoEligibleSourcesError
from memory.runtime import resolve_runtime
from memory.sources import list_sources

paths = resolve_runtime(Path({os.fspath(paths.root)!r}))
original_digest = inbox._digest_visible_file
attempted = []

class Clock:
    def time(self):
        return 1_900_000_000.0
    def sleep(self, seconds):
        pass

def change_prefix_after_snapshot(descriptor, name, expected):
    attempted.append(name)
    if name.startswith("a-synthetic-changing-"):
        path = paths.inbox / name
        body = path.read_bytes()
        path.write_bytes(bytes([body[0] ^ 1]) + body[1:])
        os.utime(path, ns=(expected.modified_ns + 1, expected.modified_ns + 1))
    return original_digest(descriptor, name, expected)

inbox._digest_visible_file = change_prefix_after_snapshot
inbox._checkpoint = lambda name: os._exit(73) if name == {checkpoint!r} else None
try:
    inbox.scan_inbox(paths, clock=Clock())
except NoEligibleSourcesError:
    pass
sources = list_sources(paths, limit=100)
print(json.dumps({{
    "attempted": len(attempted),
    "stable_captured": any(
        source.original_name == "z-synthetic-stable.txt" for source in sources.items
    ),
}}))
"""
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_changing_prefix_cannot_starve_a_stable_file_across_fresh_processes(
    observation_process_store: RuntimePaths,
) -> None:
    """A stable 66th entry progresses within three default-budget scan calls.

    Every digest of the preceding 65 entries changes that file after both
    snapshots. Their failures consume the real 64-file attempt cap on every
    call, so progress requires persisted scheduling rather than process memory
    or raising the work budget. A typed no-eligible result is valid meanwhile.
    """
    paths = observation_process_store
    file_budget = inbox.ScanPolicy().batch_file_limit
    assert file_budget == 64
    for index in range(file_budget + 1):
        (paths.inbox / f"a-synthetic-changing-{index:03d}.txt").write_bytes(
            b"Synthetic changing prefix.\n"
        )
    (paths.inbox / "z-synthetic-stable.txt").write_text(
        "合成稳定来源：应当最终捕获。\n", encoding="utf-8"
    )

    captured = False
    for _ in range(3):
        result = _scan_in_fresh_process(paths)
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert 1 <= summary["attempted"] <= file_budget
        if summary["stable_captured"]:
            captured = True
            break

    assert captured, "stable source starved behind a repeatedly changing prefix"
    sources = list_sources(paths, limit=100)
    assert [source.original_name for source in sources.items] == [
        "z-synthetic-stable.txt"
    ]
    assert len(list(paths.inbox.iterdir())) == file_budget + 1


@pytest.mark.parametrize(
    "checkpoint",
    [
        "scan.progress_commit",
        "scan.observation_complete",
        "scan.roster_chunk_commit",
        "scan.roster_publish_commit",
        "scan.roster_consume_commit",
    ],
)
def test_process_death_before_claim_preserves_all_sources_for_later_scans(
    observation_process_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Progress is scheduling metadata, never evidence of completed custody.

    A process dies without unwinding at both the unlocked observation boundary
    and the committed-progress boundary. Every original must still be visible,
    and fresh scans must retain each exactly once within the finite next epoch.
    """
    paths = observation_process_store
    originals = {
        "synthetic-before-claim-a.txt": b"Synthetic first original.\n",
        "synthetic-before-claim-b.txt": "合成第二份原件。\n".encode(),
    }
    for name, body in originals.items():
        (paths.inbox / name).write_bytes(body)

    killed = _scan_in_fresh_process(paths, checkpoint=checkpoint)

    assert killed.returncode == 73, killed.stderr
    assert list_sources(paths, limit=100).items == ()
    assert list(paths.inbox_claims.iterdir()) == []
    assert {path.name: path.read_bytes() for path in paths.inbox.iterdir()} == originals

    _assert_fresh_scans_capture_exactly_once(paths, originals)


def _assert_fresh_scans_capture_exactly_once(
    paths: RuntimePaths, originals: dict[str, bytes]
) -> None:
    """Finish a crash rehearsal, verifying custody and retired scheduler rows."""

    for _ in range(len(originals) + 2):
        resumed = _scan_in_fresh_process(paths)
        assert resumed.returncode == 0, resumed.stderr
        if len(list_sources(paths, limit=100).items) == len(originals):
            break

    # One final fresh no-eligible scan must not duplicate a completed capture.
    final = _scan_in_fresh_process(paths)
    assert final.returncode == 0, final.stderr
    sources = list_sources(paths, limit=100).items
    assert len(sources) == len(originals)
    assert {source.original_name: source.blob_digest for source in sources} == {
        name: hashlib.sha256(body).hexdigest() for name, body in originals.items()
    }
    assert list(paths.inbox.iterdir()) == []
    assert list(paths.inbox_claims.iterdir()) == []
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM inbox_scan_candidates"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_process_death_during_inactive_roster_cleanup_preserves_originals(
    observation_process_store: RuntimePaths,
) -> None:
    """Unpublished scheduling chunks stay discardable across a second crash."""
    paths = observation_process_store
    originals = {
        f"synthetic-interrupted-roster-{index:03d}.txt": (
            f"Synthetic recoverable roster source {index}.\n".encode()
        )
        for index in range(inbox.ScanPolicy().batch_file_limit + 2)
    }
    for name, body in originals.items():
        (paths.inbox / name).write_bytes(body)
    unpublished = _scan_in_fresh_process(paths, checkpoint="scan.roster_chunk_commit")
    assert unpublished.returncode == 73, unpublished.stderr

    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM inbox_scan_progress"
        ).fetchone() == (0,)
        unpublished_count = connection.execute(
            "SELECT COUNT(*) FROM inbox_scan_candidates"
        ).fetchone()
        assert unpublished_count is not None
        assert 1 <= unpublished_count[0] <= 64
    finally:
        connection.close()

    cleanup = _scan_in_fresh_process(paths, checkpoint="scan.roster_cleanup_commit")

    assert cleanup.returncode == 73, cleanup.stderr
    assert list_sources(paths, limit=100).items == ()
    assert list(paths.inbox_claims.iterdir()) == []
    assert {path.name: path.read_bytes() for path in paths.inbox.iterdir()} == originals
    _assert_fresh_scans_capture_exactly_once(paths, originals)


def test_new_and_renamed_entries_cannot_preempt_the_active_roster_tail(
    observation_process_store: RuntimePaths,
) -> None:
    """A fixed cohort finishes despite new early names and disappearing members."""
    paths = observation_process_store
    file_budget = inbox.ScanPolicy().batch_file_limit
    for index in range(file_budget + 2):
        (paths.inbox / f"a-synthetic-changing-{index:03d}.txt").write_bytes(
            b"Synthetic changing cohort member.\n"
        )
    stable = "z-synthetic-stable.txt"
    stable_body = "合成稳定队尾：新文件不能抢先。\n".encode()
    (paths.inbox / stable).write_bytes(stable_body)

    first = _scan_in_fresh_process(paths)
    assert first.returncode == 0, first.stderr
    first_summary = json.loads(first.stdout)
    assert first_summary == {"attempted": file_budget, "stable_captured": False}

    # Both unattempted prefix members disappear under their captured names.
    (paths.inbox / f"a-synthetic-changing-{file_budget:03d}.txt").unlink()
    renamed = "a-synthetic-changing-000-renamed.txt"
    (paths.inbox / f"a-synthetic-changing-{file_budget + 1:03d}.txt").rename(
        paths.inbox / renamed
    )
    for index in range(file_budget + 1):
        (paths.inbox / f"a-synthetic-changing-000-new-{index:03d}.txt").write_bytes(
            b"Synthetic early arrival.\n"
        )

    second = _scan_in_fresh_process(paths)

    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout) == {"attempted": 1, "stable_captured": True}
    sources = list_sources(paths, limit=100).items
    assert len(sources) == 1
    assert sources[0].original_name == stable
    assert sources[0].blob_digest == hashlib.sha256(stable_body).hexdigest()
    assert (paths.inbox / renamed).is_file()


def test_roster_population_releases_writer_between_metadata_chunks(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Large cohort population cannot hold one writer section for every name."""
    paths = synthetic_store
    for index in range(130):
        (paths.inbox / f"synthetic-chunked-roster-{index:03d}.txt").write_bytes(
            b"Synthetic bounded roster population.\n"
        )
    reached = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []
    batches: list[InboxBatch] = []
    original_chunks = inbox._scan_roster_chunks
    chunks_seen: list[int] = []

    def paused_between_chunks(
        roster: list[tuple[int, str]],
    ) -> Iterator[list[tuple[int, str]]]:
        for chunk in original_chunks(roster):
            chunks_seen.append(len(chunk))
            yield chunk
            if not reached.is_set():
                reached.set()
                if not release.wait(timeout=15):
                    raise AssertionError("synthetic roster writer was not released")

    def run_scan() -> None:
        try:
            batches.append(inbox.scan_inbox(paths, clock=ObservationClock()))
        except BaseException as error:
            failures.append(error)

    monkeypatch.setattr(inbox, "_scan_roster_chunks", paused_between_chunks)
    worker = threading.Thread(target=run_scan)
    worker.start()
    try:
        assert reached.wait(timeout=15), "scan did not populate its first roster chunk"
        with writer_session(paths) as connection:
            assert connection.execute("SELECT 1").fetchone() == (1,)
    finally:
        release.set()
        worker.join(timeout=15)

    assert not worker.is_alive()
    assert failures == []
    assert len(chunks_seen) >= 3
    assert all(1 <= size <= 64 for size in chunks_seen)
    assert len(batches) == 1
    assert batches[0].source_count == 64
    assert batches[0].has_more is True
