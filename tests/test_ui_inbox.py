from __future__ import annotations

import base64
import fcntl
import hashlib
import importlib
import inspect
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import httpx2
import pytest
from starlette.applications import Starlette
from starlette.datastructures import State
from starlette.testclient import TestClient
from synthetic import make_synthetic_store
from ui_support import build_test_orchestrator

from memory import model
from memory.errors import (
    InvalidArgumentError,
    RequestLimitError,
    StaleHeadError,
    StoreBusyError,
)
from memory.keys import KEYCHAIN_SERVICE
from memory.model import (
    AddItem,
    Authorship,
    EvidenceInput,
    MemoryFields,
    MemoryKind,
    RuntimeMode,
    RuntimePaths,
    Sensitivity,
    SourceCaptureOrigin,
    UiSession,
)
from memory.retrieval import read_source
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.runtime import (
    initialize_runtime,
    load_runtime_identity,
    resolve_runtime,
)
from memory.sources import read_batch

if TYPE_CHECKING:
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import PreparedOwnerCorrection

PUBLIC_ORIGIN = "http://memory-55555555555555555555555555555555.localhost:43210"
EXACT_HOST = "memory-55555555555555555555555555555555.localhost:43210"
SYNTHETIC_KEYCHAIN_ITEM = "SYNTHETIC_STORE_KEYCHAIN_ITEM"
_ORDINARY_STAGE_NAME = re.compile(r"ent_[0-9a-f]{32}\.stage")
_SLOT_RECORD_NAME = re.compile(r"\.rollback-slot-[0-9a-f]{32}\.json")


def _custody_snapshot(path: Path) -> tuple[int, ...]:
    """Capture identity, shape, and timestamps of one unrelated occupant."""
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class FrozenClock:
    def __init__(self, timestamp: float = 2_020_000_000.0) -> None:
        self.timestamp = timestamp
        self.calls = 0

    def time(self) -> float:
        self.calls += 1
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


@pytest.fixture
def synthetic_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RuntimePaths]:
    """The shared disposable Store, plus the Keychain entry a subprocess needs.

    This suite crashes the process on purpose at durability checkpoints, so its
    subprocesses have to rebuild the same synthetic Keychain from outside.
    """
    yield from make_synthetic_store(
        tmp_path,
        monkeypatch,
        export_keychain_item=SYNTHETIC_KEYCHAIN_ITEM,
    )


def _synthetic_keyring_prelude(paths: RuntimePaths) -> str:
    """Rebuild the fixture's synthetic in-memory Keychain inside a subprocess.

    The synthetic item is inherited through the environment so that no key
    material is placed in a subprocess command line.
    """
    identity = load_runtime_identity(paths)
    return f"""
import os as _os

import keyring as _keyring
from memory import keys as _keys
from memory.errors import KeyAlreadyExistsError as _KeyAlreadyExistsError

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
def _store_exclusive(identity, encoded):
    account = (_keys.KEYCHAIN_SERVICE, identity.store_id)
    if account in _items:
        raise _KeyAlreadyExistsError("synthetic Keychain item already exists")
    _items[account] = encoded
_keys._store_master_key_exclusive = _store_exclusive
"""


def _is_writer_lock_descriptor(paths: RuntimePaths, descriptor: int) -> bool:
    """Keep a staging fault injection from disabling the Store writer lock."""
    try:
        metadata = os.fstat(descriptor)
        lock = paths.writer_lock.stat()
    except OSError:
        return False
    return (metadata.st_dev, metadata.st_ino) == (lock.st_dev, lock.st_ino)


def _assert_authenticated_rollback_slot(paths: RuntimePaths, record: Path) -> None:
    """Require every published slot record to authenticate and bind its members."""
    from memory.keys import load_master_key
    from memory.staging_provenance import (
        decode_publication_rollback_slot,
    )

    metadata = record.stat()
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    identity = load_runtime_identity(paths)
    decoded = decode_publication_rollback_slot(
        record.read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    assert record.name == f".rollback-slot-{decoded.slot_id}.json"
    assert decoded.format_version == 2
    staging_device = paths.inbox_staging.lstat().st_dev
    for member in (decoded.payload, decoded.manifest, decoded.withdrawal):
        bound = (paths.inbox_staging / member.name).stat()
        assert member.device is None
        assert bound.st_dev == staging_device
        assert (bound.st_ino, bound.st_uid) == (member.inode, member.uid)
        assert stat.S_IMODE(bound.st_mode) == member.mode


def _assert_drained_recovery_residue(
    paths: RuntimePaths,
    *,
    count: int,
    withdrawal_count: int,
    ordinary_count: int = 0,
) -> None:
    """Accept only bounded, owner-only zero tombstones from failed publication.

    `ordinary_count` pins how many reclaimable `ent_*.stage` reservations the
    Store left behind. A failed ordinary staging or publication reclaims its own
    descriptor-bound reservation, so this is zero unless a test deliberately
    prevents that reclamation.
    """
    from memory.inbox import list_exact_recovery_issues

    entries = tuple(paths.inbox_staging.iterdir())
    records = tuple(
        entry for entry in entries if _SLOT_RECORD_NAME.fullmatch(entry.name)
    )
    manifests = tuple(
        entry
        for entry in entries
        if entry.is_file()
        and entry.name.endswith(".json")
        and _SLOT_RECORD_NAME.fullmatch(entry.name) is None
    )
    residues = tuple(
        entry
        for entry in entries
        if entry.is_file() and not entry.name.endswith(".json")
    )
    withdrawals = tuple(entry for entry in entries if entry.is_dir())
    ordinary = tuple(
        entry for entry in residues if _ORDINARY_STAGE_NAME.fullmatch(entry.name)
    )
    assert len(residues) == count
    assert len(ordinary) == ordinary_count
    assert len(withdrawals) == withdrawal_count
    assert len(records) == withdrawal_count
    for record in records:
        _assert_authenticated_rollback_slot(paths, record)
    for residue in residues:
        metadata = residue.stat()
        assert residue.name.startswith(".recovery-") or residue.name.startswith("ent_")
        assert residue.name.endswith(".stage")
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_nlink == 1
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert residue.read_bytes() == b""
    for manifest in manifests:
        metadata = manifest.stat()
        assert manifest.name.startswith(".recovery-")
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_nlink == 1
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert manifest.read_bytes() == b""
    for withdrawal in withdrawals:
        metadata = withdrawal.stat()
        assert withdrawal.name.startswith(".withdrawal-")
        assert metadata.st_uid == os.geteuid()
        assert stat.S_ISDIR(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o700
        assert tuple(withdrawal.iterdir()) == ()
    assert list_exact_recovery_issues(paths, cursor=None, limit=100).items == ()


def _session_store() -> tuple[UiSessionStore, str]:
    from memory.ui.auth import UiSessionStore

    sessions = UiSessionStore(
        bootstrap_capability="test-boot",
        exact_host="memory-synthetic.localhost:43210",
        created_at_ns=100,
    )
    session = sessions.exchange_bootstrap(
        secret="test-boot",
        exact_host="memory-synthetic.localhost:43210",
        now_ns=101,
    )
    assert session is not None
    return sessions, session.session_id


def _prepared_correction(
    owner_text: bytes = b"text",
    *,
    selected_memory_id: str = "mem_" + "1" * 32,
    lineage_id: str = "lin_" + "2" * 32,
    expected_head_id: str = "mem_" + "3" * 32,
    captured_at: int = 2_020_000_000,
    prefix: bytes = b"head\n",
) -> PreparedOwnerCorrection:
    from memory.ui.capture import PreparedOwnerCorrection

    source_bytes = prefix + owner_text
    return PreparedOwnerCorrection(
        selected_memory_id=selected_memory_id,
        lineage_id=lineage_id,
        expected_head_id=expected_head_id,
        captured_at=captured_at,
        owner_text_offset=len(prefix),
        owner_text_sha256=hashlib.sha256(owner_text).hexdigest(),
        source_bytes=source_bytes,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
    )


def _exact_owner_payload(
    paths: RuntimePaths,
    *,
    marker: str,
    captured_at: int = 2_020_000_000,
) -> tuple[bytes, model.ExactCaptureMetadata]:
    identity = load_runtime_identity(paths)
    lineage_id = "lin_" + marker * 32
    expected_head_id = "mem_" + marker * 32
    capture_request_id = "cap_" + marker * 32
    batch_id = "bat_" + marker * 32
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
        f"Synthetic exact owner correction {marker}.\n"
    ).encode()
    return body, model.ExactCaptureMetadata(
        capture_request_id=capture_request_id,
        batch_id=batch_id,
        captured_at=captured_at,
        target_lineage_id=lineage_id,
        expected_head_id=expected_head_id,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )


def _crash_exact_staging_subprocess(
    paths: RuntimePaths,
    *,
    body: bytes,
    metadata: model.ExactCaptureMetadata,
    checkpoint: str,
    display_name: str,
) -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(paths)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.model import Authorship, ExactCaptureMetadata, Sensitivity, SourceCaptureOrigin
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
    display_name={display_name!r},
    chunks=(base64.b64decode({encoded!r}),),
    max_bytes={len(body)},
    metadata=metadata,
)
"""
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )


def _exact_intent_payload_path(paths: RuntimePaths) -> Path:
    intents = tuple(paths.inbox_staging.glob("*.intent.json"))
    assert len(intents) == 1
    suffix = ".intent.json"
    assert intents[0].name.endswith(suffix)
    return paths.inbox_staging / intents[0].name.removesuffix(suffix)


def _applied_memory(paths: RuntimePaths) -> str:
    from memory.inbox import ScanPolicy, scan_inbox

    source_body = b"Synthetic source says the paper lantern is blue.\n"
    (paths.inbox / "synthetic-memory-source.md").write_bytes(source_body)
    batch = scan_inbox(
        paths,
        clock=FrozenClock(2_010_000_000.0),
        policy=ScanPolicy(settle_seconds=0),
    )
    source = read_batch(paths, batch.batch_id).sources[0]
    draft = create_change_set(
        paths,
        batch.batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        (
            AddItem(
                client_item_id="synthetic-owner-inbox-memory",
                memory=MemoryFields(
                    kind=MemoryKind.PREFERENCE,
                    statement="The synthetic paper lantern is blue.",
                    occurred_on="2033-04",
                    valid_from="2033-04",
                    valid_to=None,
                    tags=("synthetic", "lantern"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt="the paper lantern is blue",
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval,
    ).memory_ids[0]


def _apply_successor(
    paths: RuntimePaths,
    predecessor_id: str,
    *,
    marker: str,
) -> str:
    from memory.inbox import ScanPolicy, scan_inbox
    from memory.ui.service import OwnerApplicationService

    predecessor = OwnerApplicationService(paths).get_memory_revision(predecessor_id)
    sentence = f"Synthetic successor {marker} says the paper lantern is green."
    filename = f"synthetic-successor-{marker}.md"
    (paths.inbox / filename).write_text(sentence + "\n", encoding="utf-8")
    batch = scan_inbox(
        paths,
        clock=FrozenClock(2_011_000_000.0),
        policy=ScanPolicy(settle_seconds=0),
    )
    source = read_batch(paths, batch.batch_id).sources[0]
    draft = create_change_set(
        paths,
        batch.batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        (
            AddItem(
                client_item_id=f"synthetic-successor-{marker}",
                memory=MemoryFields(
                    kind=MemoryKind.PREFERENCE,
                    statement=sentence,
                    occurred_on="2033-05",
                    valid_from="2033-05",
                    valid_to=None,
                    tags=("synthetic", "lantern", marker),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=predecessor.summary.revision.lineage_id,
                    expected_head_id=predecessor.summary.current_head_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt=sentence,
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval,
    ).memory_ids[0]


class RecordingFinder:
    def __init__(self) -> None:
        self.urls: list[object] = []

    def reveal_directory_url(self, directory_url: object) -> None:
        self.urls.append(directory_url)


def _authenticated_client(
    paths: RuntimePaths,
    finder: RecordingFinder | None = None,
) -> tuple[TestClient, UiSession, RecordingFinder]:
    from memory.ui.app import create_ui_app
    from memory.ui.auth import UiSessionStore
    from memory.ui.service import OwnerApplicationService

    selected_finder = RecordingFinder() if finder is None else finder
    sessions = UiSessionStore(
        bootstrap_capability="synthetic-ui-bootstrap",
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    service = OwnerApplicationService(paths)
    app = create_ui_app(
        service,
        sessions,
        selected_finder,
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    client = TestClient(app, base_url=PUBLIC_ORIGIN)
    exchanged = client.post(
        "/session",
        content="synthetic-ui-bootstrap",
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )
    assert exchanged.status_code == 303
    cookie = client.cookies.get("memory_ui_session")
    assert cookie is not None
    session = sessions.resolve_cookie(
        cookie=cookie,
        exact_host=EXACT_HOST,
        now_ns=time.monotonic_ns(),
    )
    assert session is not None
    return client, session, selected_finder


def _app_state(client: TestClient) -> State:
    """Reach the app's own state through the client's bare-ASGI handle."""
    app = client.app
    assert isinstance(app, Starlette)
    return app.state


def _redirect_location(response: httpx2.Response | BaseException) -> str:
    """Read the redirect a worker thread recorded, or fail with what it raised."""
    assert isinstance(response, httpx2.Response), response
    return response.headers["location"]


def test_task_five_modules_expose_the_approved_capture_interfaces() -> None:
    """Catch omission or signature drift at the owner-capture boundary."""
    capture = importlib.import_module("memory.ui.capture")
    routes = importlib.import_module("memory.ui.routes.inbox")

    assert capture.MAX_OWNER_CORRECTION_SOURCE_BYTES == 1_048_576
    assert capture.CORRECTION_FORM_TTL_NS == 600_000_000_000
    assert capture.MAX_CORRECTION_INTENTS == 8
    assert capture.MAX_CORRECTION_SESSION_RETAINED_BYTES == 8 * 1_048_576
    assert callable(routes.inbox_page)
    assert tuple(inspect.signature(routes.inbox_page).parameters) == ("request",)


def test_safe_staging_rejects_unsafe_names_and_cleans_interrupted_streams(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.inbox import list_staged_entries, stage_inbox_entry

    for name in ("", ".", "..", "../escape.txt", "nested/file.txt", "bad\x00.txt"):
        with pytest.raises(InvalidArgumentError):
            stage_inbox_entry(
                synthetic_store,
                owner_filename=name,
                chunks=(b"synthetic",),
            )

    def interrupted() -> Iterator[bytes]:
        yield b"synthetic partial bytes"
        raise RuntimeError("synthetic interrupted upload")

    with pytest.raises(RuntimeError, match="synthetic interrupted"):
        stage_inbox_entry(
            synthetic_store,
            owner_filename="interrupted.txt",
            chunks=interrupted(),
        )
    assert list(synthetic_store.inbox.iterdir()) == []
    _assert_drained_recovery_residue(
        synthetic_store,
        count=0,
        withdrawal_count=0,
    )
    assert list_staged_entries(synthetic_store, cursor=None, limit=10).items == ()


def test_staging_is_exclusive_mode_0600_bounded_and_stably_paginated(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.inbox import list_staged_entries, stage_inbox_entry

    first = stage_inbox_entry(
        synthetic_store,
        owner_filename="a-synthetic.txt",
        chunks=(b"one", b"-two"),
    )
    second = stage_inbox_entry(
        synthetic_store,
        owner_filename="b-synthetic.md",
        chunks=("合成".encode(),),
    )
    assert first.display_name == "a-synthetic.txt"
    assert first.byte_length == 7
    assert stat.S_IMODE(
        (synthetic_store.inbox / first.display_name).stat().st_mode
    ) == (0o600)
    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename=first.display_name,
            chunks=(b"must not replace",),
        )
    assert (synthetic_store.inbox / first.display_name).read_bytes() == b"one-two"
    with pytest.raises(RequestLimitError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename="too-large.txt",
            chunks=(b"1234",),
            max_bytes=3,
        )
    page_one = list_staged_entries(synthetic_store, cursor=None, limit=1)
    assert page_one.items == (first,)
    assert page_one.has_more is True and page_one.next_cursor is not None
    page_two = list_staged_entries(
        synthetic_store,
        cursor=page_one.next_cursor,
        limit=1,
    )
    assert page_two.items == (second,)
    assert page_two.has_more is False
    _assert_drained_recovery_residue(
        synthetic_store,
        count=1,
        withdrawal_count=1,
    )


def test_staging_symlink_and_concurrent_name_collision_never_overwrite(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Catch publication following a link or replacing a concurrent owner file."""
    from memory.inbox import stage_inbox_entry

    outside = tmp_path / "synthetic-outside.txt"
    outside.write_bytes(b"outside remains unchanged")
    linked = synthetic_store.inbox / "linked-owner-file.txt"
    linked.symlink_to(outside)
    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename=linked.name,
            chunks=(b"must not follow",),
        )
    assert outside.read_bytes() == b"outside remains unchanged"
    assert linked.is_symlink()

    barrier = threading.Barrier(2)
    results: list[object] = []

    def stage(body: bytes) -> None:
        for _attempt in range(200):

            def chunks() -> Iterator[bytes]:
                barrier.wait(timeout=10)
                yield body

            try:
                results.append(
                    stage_inbox_entry(
                        synthetic_store,
                        owner_filename="same-synthetic-name.txt",
                        chunks=chunks(),
                    )
                )
                return
            except StoreBusyError:
                # The short reservation section holds the nonblocking Store
                # writer lock; a concurrent caller retries before streaming.
                time.sleep(0.001)
            except BaseException as error:
                results.append(error)
                return

    first = threading.Thread(target=stage, args=(b"first synthetic body",))
    second = threading.Thread(target=stage, args=(b"second synthetic body",))
    first.start()
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()
    assert (
        len([item for item in results if isinstance(item, model.StagedInboxEntry)]) == 1
    )
    assert (
        len([item for item in results if isinstance(item, InvalidArgumentError)]) == 1
    )
    assert (synthetic_store.inbox / "same-synthetic-name.txt").read_bytes() in {
        b"first synthetic body",
        b"second synthetic body",
    }
    _assert_drained_recovery_residue(
        synthetic_store,
        count=2,
        withdrawal_count=2,
    )


def test_repeated_publication_outcomes_bound_fresh_cleanup_slots(
    synthetic_store: RuntimePaths,
) -> None:
    """Fresh-only failed staging remains bounded without reusing zero occupants."""
    from memory.inbox import (
        list_exact_recovery_issues,
        stage_inbox_entry,
    )

    for index in range(4):
        body = f"Synthetic reusable publication {index}.\n".encode()
        staged = stage_inbox_entry(
            synthetic_store,
            owner_filename=f"synthetic-reusable-{index}.md",
            chunks=(body,),
        )
        assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    success_residue = tuple(
        sorted(candidate.name for candidate in synthetic_store.inbox_staging.iterdir())
    )
    # One reused authenticated bundle: payload, marker, withdrawal, and record.
    assert len(success_residue) == 4
    assert (
        len([name for name in success_residue if _SLOT_RECORD_NAME.fullmatch(name)])
        == 1
    )

    destination = synthetic_store.inbox / "synthetic-repeated-collision.md"
    destination.write_bytes(b"Synthetic existing destination.\n")
    destination.chmod(0o600)
    for index in range(4):
        body = f"Synthetic rejected publication {index}.\n".encode()
        with pytest.raises(InvalidArgumentError, match="publication"):
            stage_inbox_entry(
                synthetic_store,
                owner_filename=destination.name,
                chunks=(body,),
            )
        assert destination.read_bytes() == b"Synthetic existing destination.\n"
        current = tuple(
            sorted(
                (
                    candidate.name,
                    candidate.stat().st_size,
                    stat.S_IFMT(candidate.stat().st_mode),
                )
                for candidate in synthetic_store.inbox_staging.iterdir()
            )
        )
        # Each refused publication reclaims the reservation it created through
        # its own continuously held descriptor, so repeated collisions never
        # consume the global ordinary-staging bound.
        assert len(current) == len(success_residue)
        assert sum(name.startswith("ent_") for name, _size, _kind in current) == 0
        assert body not in tuple(
            candidate.read_bytes()
            for candidate in synthetic_store.inbox_staging.iterdir()
            if candidate.is_file()
        )
        assert (
            list_exact_recovery_issues(
                synthetic_store,
                cursor=None,
                limit=100,
            ).items
            == ()
        )

    assert len(current) <= len(success_residue) + 8


def test_success_never_escapes_when_anchor_release_cannot_be_proven_clean(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed anchor drain must withdraw publication before reporting failure."""
    import memory.inbox as inbox

    body = b"Synthetic anchor-release failure payload.\n"
    destination = synthetic_store.inbox / "synthetic-anchor-release.md"
    original_drain = inbox._drain_verified_descriptor
    drain_calls = 0

    def fail_first_drain(
        descriptor: int,
        expected_identity: tuple[int, ...],
        expected_sha256: str,
    ) -> bool:
        nonlocal drain_calls
        drain_calls += 1
        if drain_calls == 1:
            return False
        return original_drain(descriptor, expected_identity, expected_sha256)

    monkeypatch.setattr(inbox, "_drain_verified_descriptor", fail_first_drain)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert drain_calls >= 2
    assert not destination.exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert retained.count(body) == 1
    assert inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    ).items


def test_prepublication_drain_failure_classifies_one_readable_private_copy(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A collision cleanup failure must not leave two anonymous readable copies."""
    import memory.inbox as inbox

    body = b"Synthetic prepublication drain failure payload.\n"
    destination = synthetic_store.inbox / "synthetic-prepublication-drain.md"
    destination.write_bytes(b"Synthetic existing destination.\n")
    destination.chmod(0o600)
    original_drain = inbox._drain_verified_descriptor
    original_ftruncate = os.ftruncate
    source_identity: tuple[int, int] | None = None

    def fail_source_drain(
        descriptor: int,
        expected_identity: tuple[int, ...],
        expected_sha256: str,
    ) -> bool:
        nonlocal source_identity
        if source_identity is None:
            source_identity = (expected_identity[0], expected_identity[1])
            return False
        return original_drain(descriptor, expected_identity, expected_sha256)

    def fail_sealed_source_truncate(descriptor: int, length: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            source_identity == (metadata.st_dev, metadata.st_ino)
            and stat.S_IMODE(metadata.st_mode) == 0
        ):
            raise OSError(5, "synthetic sealed source truncate EIO")
        original_ftruncate(descriptor, length)

    monkeypatch.setattr(inbox, "_drain_verified_descriptor", fail_source_drain)
    monkeypatch.setattr(os, "ftruncate", fail_sealed_source_truncate)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert destination.read_bytes() == b"Synthetic existing destination.\n"
    copies = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and candidate.stat().st_size == len(body)
    ]
    assert len(copies) == 2
    sealed = [
        candidate for candidate in copies if stat.S_IMODE(candidate.stat().st_mode) == 0
    ]
    readable = [
        candidate
        for candidate in copies
        if stat.S_IMODE(candidate.stat().st_mode) == 0o600
    ]
    assert len(sealed) == 1
    assert len(readable) == 1
    assert readable[0].read_bytes() == body
    assert len(tuple(synthetic_store.inbox_staging.glob(".recovery-*.json"))) == 1
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert issues.items
    assert body.decode().strip() not in repr(issues.items)


def test_unproven_zero_stage_candidate_is_never_reused(
    synthetic_store: RuntimePaths,
) -> None:
    """A matching owner-only zero file is occupied, not Store provenance."""
    import memory.inbox as inbox

    occupied = synthetic_store.inbox_staging / f"ent_{'a' * 32}.stage"
    occupied.write_bytes(b"")
    occupied.chmod(0o600)
    before = occupied.stat()
    body = b"Synthetic successful source after slot race.\n"
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-after-slot-race.md",
        chunks=(body,),
    )

    after = occupied.stat()
    assert occupied.read_bytes() == b""
    assert (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        after.st_nlink,
        stat.S_IFMT(after.st_mode),
        stat.S_IMODE(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) == (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_nlink,
        stat.S_IFMT(before.st_mode),
        stat.S_IMODE(before.st_mode),
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body


def test_unproven_zero_recovery_pair_is_never_reused_or_mutated(
    synthetic_store: RuntimePaths,
) -> None:
    """A same-owner zero recovery pair without Store provenance stays untouched."""
    from memory.inbox import stage_inbox_entry

    slot_id = "b" * 32
    payload = synthetic_store.inbox_staging / f".recovery-{slot_id}.stage"
    marker = synthetic_store.inbox_staging / f".recovery-{slot_id}.json"
    for occupant in (payload, marker):
        occupant.write_bytes(b"")
        occupant.chmod(0o600)
    before = {occupant: _custody_snapshot(occupant) for occupant in (payload, marker)}

    body = b"Synthetic publication beside an unproven zero recovery pair.\n"
    staged = stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-unproven-zero.txt",
        chunks=(body,),
    )

    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    for occupant in (payload, marker):
        assert occupant.is_file()
        assert occupant.read_bytes() == b""
        assert _custody_snapshot(occupant) == before[occupant]


def test_unproven_withdrawal_child_is_never_relocated_or_mutated(
    synthetic_store: RuntimePaths,
) -> None:
    """A shape-only withdrawal child is never vacated into a staging identity."""
    from memory.inbox import stage_inbox_entry

    slot_id = "c" * 32
    withdrawal = synthetic_store.inbox_staging / f".withdrawal-{slot_id}"
    withdrawal.mkdir(mode=0o700)
    child = withdrawal / "withdrawn"
    child.write_bytes(b"")
    child.chmod(0o600)
    relocated = synthetic_store.inbox_staging / f"ent_{slot_id}.stage"
    before = _custody_snapshot(child)

    body = b"Synthetic publication beside an unproven withdrawal child.\n"
    staged = stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-unproven-withdrawal.txt",
        chunks=(body,),
    )

    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    assert not relocated.exists()
    assert child.is_file()
    assert child.read_bytes() == b""
    assert _custody_snapshot(child) == before


@pytest.mark.parametrize(
    "damage",
    [
        "missing_record",
        "malformed_record",
        "tampered_mac",
        "wrong_store_record",
        "wrong_key_record",
        "payload_replaced",
        "manifest_replaced",
        "withdrawal_replaced",
    ],
)
def test_unauthenticated_rollback_slot_is_never_reused_or_mutated(
    synthetic_store: RuntimePaths,
    damage: str,
) -> None:
    """Invalid provenance or a replaced member retires a bundle without mutation."""
    import memory.inbox as inbox
    from memory.keys import load_master_key
    from memory.staging_provenance import (
        decode_publication_rollback_slot,
        encode_publication_rollback_slot,
    )

    first = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-authenticated-first.md",
        chunks=(b"Synthetic first authenticated publication.\n",),
    )
    assert (synthetic_store.inbox / first.display_name).is_file()
    record_path = next(
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if _SLOT_RECORD_NAME.fullmatch(candidate.name)
    )
    slot_id = record_path.name.removeprefix(".rollback-slot-").removesuffix(".json")
    identity = load_runtime_identity(synthetic_store)
    decoded = decode_publication_rollback_slot(
        record_path.read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )

    if damage == "missing_record":
        record_path.unlink()
    elif damage == "malformed_record":
        record_path.write_bytes(b"{}\n")
    elif damage == "tampered_mac":
        document = json.loads(record_path.read_bytes().decode("utf-8"))
        document["mac"] = ("0" if document["mac"][0] != "0" else "1") + document["mac"][
            1:
        ]
        record_path.write_bytes(
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        )
    elif damage == "wrong_store_record":
        record_path.write_bytes(
            encode_publication_rollback_slot(
                decoded,
                store_id="f" * 32,
                master_key=load_master_key(identity),
            )
        )
    elif damage == "wrong_key_record":
        record_path.write_bytes(
            encode_publication_rollback_slot(
                decoded,
                store_id=identity.store_id,
                master_key=b"\x33" * 32,
            )
        )
    else:
        replaced = (
            synthetic_store.inbox_staging
            / {
                "payload_replaced": f".recovery-{slot_id}.stage",
                "manifest_replaced": f".recovery-{slot_id}.json",
                "withdrawal_replaced": f".withdrawal-{slot_id}",
            }[damage]
        )
        if damage == "withdrawal_replaced":
            shutil.rmtree(replaced)
            replaced.mkdir(mode=0o700)
        else:
            replaced.unlink()
            replaced.write_bytes(b"")
            replaced.chmod(0o600)

    members = tuple(
        synthetic_store.inbox_staging / name
        for name in (
            f".recovery-{slot_id}.stage",
            f".recovery-{slot_id}.json",
            f".withdrawal-{slot_id}",
        )
    )
    before = {member: _custody_snapshot(member) for member in members}

    body = b"Synthetic publication beside a retired bundle.\n"
    second = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-authenticated-second.md",
        chunks=(body,),
    )

    assert (synthetic_store.inbox / second.display_name).read_bytes() == body
    for member in members:
        assert _custody_snapshot(member) == before[member]
        if member.is_file():
            assert member.read_bytes() == b""
        else:
            assert tuple(member.iterdir()) == ()
    records = tuple(
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if _SLOT_RECORD_NAME.fullmatch(candidate.name)
    )
    fresh = [candidate for candidate in records if candidate.name != record_path.name]
    assert len(fresh) == 1
    _assert_authenticated_rollback_slot(synthetic_store, fresh[0])
    issues = inbox.list_exact_recovery_issues(synthetic_store, cursor=None, limit=100)
    assert issues.items
    assert slot_id not in repr(issues.items)
    assert body.decode().strip() not in repr(issues.items)


@pytest.mark.parametrize(
    "occupied_member", ["payload", "manifest", "withdrawal", "record"]
)
def test_rollback_slot_creation_preserves_every_member_collision(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    occupied_member: str,
) -> None:
    """A collided bundle name never displaces or reuses its existing occupant."""
    import memory.inbox as inbox

    collided = "9" * 32
    occupant = (
        synthetic_store.inbox_staging
        / {
            "payload": f".recovery-{collided}.stage",
            "manifest": f".recovery-{collided}.json",
            "withdrawal": f".withdrawal-{collided}",
            "record": f".rollback-slot-{collided}.json",
        }[occupied_member]
    )
    unrelated = b"Synthetic unrelated bundle-name occupant.\n"
    if occupied_member == "withdrawal":
        occupant.mkdir(mode=0o700)
        child = occupant / "unrelated-synthetic-child.txt"
        child.write_bytes(unrelated)
        child.chmod(0o600)
        child_before = _custody_snapshot(child)
    else:
        occupant.write_bytes(unrelated)
        occupant.chmod(0o600)
        child_before = None
    before = _custody_snapshot(occupant)

    original_token_hex = secrets.token_hex
    calls = 0

    def selected_token_hex(byte_count: int) -> str:
        nonlocal calls
        if byte_count != 16:
            return original_token_hex(byte_count)
        calls += 1
        if calls == 2:
            return collided
        return original_token_hex(byte_count)

    monkeypatch.setattr(secrets, "token_hex", selected_token_hex)

    body = b"Synthetic publication after a bundle-name collision.\n"
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-bundle-collision.md",
        chunks=(body,),
    )

    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    assert _custody_snapshot(occupant) == before
    if occupied_member == "withdrawal":
        assert _custody_snapshot(occupant / "unrelated-synthetic-child.txt") == (
            child_before
        )
        assert (occupant / "unrelated-synthetic-child.txt").read_bytes() == unrelated
    else:
        assert occupant.read_bytes() == unrelated
    records = tuple(
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if _SLOT_RECORD_NAME.fullmatch(candidate.name)
        and candidate.name != f".rollback-slot-{collided}.json"
    )
    assert len(records) == 1
    _assert_authenticated_rollback_slot(synthetic_store, records[0])
    assert not (
        synthetic_store.inbox_staging / f".rollback-slot-{collided}.tmp"
    ).exists()


def test_authenticated_rollback_slot_survives_restart_and_is_reused(
    synthetic_store: RuntimePaths,
) -> None:
    """A bundle minted by an earlier process authenticates for a later one."""
    import memory.inbox as inbox

    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
inbox.stage_inbox_entry(
    paths,
    owner_filename="synthetic-restart-first.md",
    chunks=(b"Synthetic restart publication.\\n",),
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    before = tuple(
        sorted(candidate.name for candidate in synthetic_store.inbox_staging.iterdir())
    )
    assert len([name for name in before if _SLOT_RECORD_NAME.fullmatch(name)]) == 1

    body = b"Synthetic restart reuse publication.\n"
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-restart-second.md",
        chunks=(body,),
    )

    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    assert (
        tuple(
            sorted(
                candidate.name for candidate in synthetic_store.inbox_staging.iterdir()
            )
        )
        == before
    )
    _assert_drained_recovery_residue(synthetic_store, count=1, withdrawal_count=1)


def test_paused_upload_never_holds_the_store_writer_lock(
    synthetic_store: RuntimePaths,
) -> None:
    """Only the short reservation section may own the Store writer boundary."""
    from memory.inbox import _open_runtime_root, stage_inbox_entry
    from memory.runtime import _writer_lock

    private_ready = threading.Event()
    release = threading.Event()
    staged: list[object] = []
    acquired = False

    def chunks() -> Iterator[bytes]:
        yield b"first synthetic paused chunk"
        private_ready.set()
        assert release.wait(timeout=10)
        yield b"second synthetic paused chunk"

    def upload() -> None:
        try:
            staged.append(
                stage_inbox_entry(
                    synthetic_store,
                    owner_filename="synthetic-paused-writer-lock.txt",
                    chunks=chunks(),
                )
            )
        except BaseException as error:
            staged.append(error)

    worker = threading.Thread(target=upload)
    worker.start()
    try:
        assert private_ready.wait(timeout=10)
        with _open_runtime_root(synthetic_store) as runtime:
            with _writer_lock(
                synthetic_store,
                root_descriptor=runtime.root_descriptor,
            ):
                acquired = True
    finally:
        release.set()
        worker.join(timeout=10)

    assert not worker.is_alive()
    assert acquired
    assert len(staged) == 1 and isinstance(staged[0], model.StagedInboxEntry)
    assert (
        synthetic_store.inbox / "synthetic-paused-writer-lock.txt"
    ).read_bytes() == b"first synthetic paused chunksecond synthetic paused chunk"


def test_retained_publication_anchors_never_disable_inbox_staging(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch retained rollback anchors permanently exhausting the slot budget."""
    import memory.inbox as inbox

    destination = synthetic_store.inbox / "synthetic-retained-anchor.md"
    destination.write_bytes(b"Synthetic existing destination.\n")
    destination.chmod(0o600)

    original_remove = inbox._remove_bound_private_before_publication
    retaining = [True]

    def retain_every_anchor(
        runtime: inbox._RuntimeRoot,
        descriptor: int,
        expected_identity: tuple[int, ...],
        entry: model.PrivateStagedEntry,
    ) -> bool:
        if retaining[0]:
            return False
        return original_remove(
            runtime,
            descriptor,
            expected_identity,
            entry,
        )

    monkeypatch.setattr(
        inbox,
        "_remove_bound_private_before_publication",
        retain_every_anchor,
    )
    retained_bodies = []
    for index in range(8):
        body = f"Synthetic retained anchor {index}.\n".encode()
        retained_bodies.append(body)
        with pytest.raises(InvalidArgumentError, match="publication"):
            inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=destination.name,
                chunks=(body,),
            )
    retaining[0] = False

    body = b"Synthetic staging after eight retained anchors.\n"
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename="synthetic-after-retained-anchors.md",
        chunks=(body,),
    )
    assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
    assert destination.read_bytes() == b"Synthetic existing destination.\n"
    # Every retained copy stays privately readable for owner recovery.
    retained = tuple(
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
    )
    for retained_body in retained_bodies:
        assert retained_body in retained
    assert (
        inbox.list_exact_recovery_issues(
            synthetic_store,
            cursor=None,
            limit=100,
        ).items
        != ()
    )


def test_authenticated_rollback_slot_is_reused_without_growth(
    synthetic_store: RuntimePaths,
) -> None:
    """Repeated clean publication reuses one authenticated provenance bundle."""
    from memory.inbox import stage_inbox_entry

    slot_id: str | None = None
    for index in range(4):
        body = f"Synthetic authenticated rollback slot {index}.\n".encode()
        staged = stage_inbox_entry(
            synthetic_store,
            owner_filename=f"synthetic-authenticated-slot-{index}.md",
            chunks=(body,),
        )
        assert (synthetic_store.inbox / staged.display_name).read_bytes() == body
        names = sorted(
            candidate.name for candidate in synthetic_store.inbox_staging.iterdir()
        )
        records = [name for name in names if _SLOT_RECORD_NAME.fullmatch(name)]
        assert len(records) == 1
        current = records[0].removeprefix(".rollback-slot-").removesuffix(".json")
        if slot_id is None:
            slot_id = current
        assert current == slot_id
        assert names == sorted(
            (
                f".recovery-{slot_id}.json",
                f".recovery-{slot_id}.stage",
                f".rollback-slot-{slot_id}.json",
                f".withdrawal-{slot_id}",
            )
        )

    assert slot_id is not None
    from memory.keys import load_master_key
    from memory.staging_provenance import (
        decode_publication_rollback_slot,
    )

    identity = load_runtime_identity(synthetic_store)
    record = decode_publication_rollback_slot(
        (synthetic_store.inbox_staging / f".rollback-slot-{slot_id}.json").read_bytes(),
        expected_store_id=identity.store_id,
        master_key=load_master_key(identity),
    )
    assert record.slot_id == slot_id
    members = (
        (record.payload, synthetic_store.inbox_staging / f".recovery-{slot_id}.stage"),
        (record.manifest, synthetic_store.inbox_staging / f".recovery-{slot_id}.json"),
        (record.withdrawal, synthetic_store.inbox_staging / f".withdrawal-{slot_id}"),
    )
    for bound, path in members:
        metadata = path.stat()
        assert bound.name == path.name
        assert bound.device is None
        assert metadata.st_dev == synthetic_store.inbox_staging.lstat().st_dev
        assert (bound.inode, bound.uid) == (metadata.st_ino, metadata.st_uid)
        assert bound.mode == stat.S_IMODE(metadata.st_mode)
    assert record.payload.file_type == "regular"
    assert record.manifest.file_type == "regular"
    assert record.withdrawal.file_type == "directory"


def test_concurrent_failed_private_stage_reservations_leave_at_most_eight_entries(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Four synchronized failing callers must not exceed the global stage bound."""
    import memory.inbox as inbox

    original_stat_entry = inbox._stat_entry
    faulted = threading.Semaphore(0)
    synchronized = threading.Event()
    local = threading.local()

    def unbind_fresh_stage_path(descriptor: int, name: str) -> os.stat_result | None:
        if _ORDINARY_STAGE_NAME.fullmatch(name) is None:
            return original_stat_entry(descriptor, name)
        if not getattr(local, "faulted", False):
            local.faulted = True
            faulted.release()
            synchronized.wait(timeout=10)
        return None

    def watch() -> None:
        for _index in range(4):
            if not faulted.acquire(timeout=10):
                break
        synchronized.set()

    monkeypatch.setattr(inbox, "_stat_entry", unbind_fresh_stage_path)

    start = threading.Barrier(4, timeout=10)
    outcomes: list[object] = []
    guard = threading.Lock()

    def stage(index: int) -> None:
        outcome: object
        try:
            start.wait()
            outcome = inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=f"synthetic-concurrent-reservation-{index}.txt",
                chunks=(f"Synthetic concurrent reservation {index}.\n".encode(),),
            )
        except BaseException as error:
            outcome = error
        with guard:
            outcomes.append(outcome)

    observer = threading.Thread(target=watch)
    observer.start()
    workers = [threading.Thread(target=stage, args=(index,)) for index in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)
    synchronized.set()
    observer.join(timeout=10)
    assert not any(worker.is_alive() for worker in workers)

    assert len(outcomes) == 4
    assert all(
        isinstance(outcome, InvalidArgumentError | StoreBusyError)
        for outcome in outcomes
    )
    assert list(synthetic_store.inbox.iterdir()) == []
    residues = tuple(
        path
        for path in synthetic_store.inbox_staging.iterdir()
        if _ORDINARY_STAGE_NAME.fullmatch(path.name)
    )
    assert len(residues) <= 8
    assert all(path.read_bytes() == b"" for path in residues)


def test_stage_slot_flock_error_closes_the_just_opened_descriptor(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lock syscall failure must not leak its newly owned file descriptor."""
    import memory.inbox as inbox

    original_flock = fcntl.flock
    opened: list[int] = []

    def fail_flock(descriptor: int, operation: int) -> None:
        if _is_writer_lock_descriptor(synthetic_store, descriptor):
            original_flock(descriptor, operation)
            return
        opened.append(descriptor)
        raise OSError(5, "synthetic stage-slot flock EIO")

    monkeypatch.setattr(fcntl, "flock", fail_flock)

    with pytest.raises(InvalidArgumentError, match="filesystem"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename="synthetic-flock-error.md",
            chunks=(b"Synthetic flock-error payload.\n",),
        )

    assert len(opened) == 1
    with pytest.raises(OSError) as captured:
        os.fstat(opened[0])
    assert captured.value.errno == 9


def test_repeated_stage_slot_contention_is_bounded_and_closes_descriptors(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh-only contention stops at eight occupied names without leaking FDs."""
    import memory.inbox as inbox

    original_flock = fcntl.flock
    rejected: list[int] = []

    def contend(descriptor: int, operation: int) -> None:
        if _is_writer_lock_descriptor(synthetic_store, descriptor):
            original_flock(descriptor, operation)
            return
        rejected.append(descriptor)
        raise BlockingIOError(11, "synthetic persistent stage contention")

    monkeypatch.setattr(fcntl, "flock", contend)

    stable_names: tuple[str, ...] | None = None
    for index in range(2):
        with pytest.raises(InvalidArgumentError, match="staging capacity"):
            inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=f"synthetic-stage-contention-{index}.md",
                chunks=(b"Synthetic stage contention payload.\n",),
            )
        names = tuple(
            sorted(
                candidate.name
                for candidate in synthetic_store.inbox_staging.glob("ent_*.stage")
            )
        )
        assert len(names) == 8
        if stable_names is None:
            stable_names = names
        else:
            assert names == stable_names

    assert len(rejected) == 8
    for descriptor in set(rejected):
        with pytest.raises(OSError) as captured:
            os.fstat(descriptor)
        assert captured.value.errno == 9


def test_repeated_anchor_flock_failures_are_bounded_and_close_descriptors(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persistent anchor contention must reuse eight names without leaking FDs."""
    import memory.inbox as inbox

    original_flock = fcntl.flock
    rejected_descriptors: list[int] = []

    def fail_recovery_anchor_flock(descriptor: int, operation: int) -> None:
        metadata = os.fstat(descriptor)
        for candidate in synthetic_store.inbox_staging.iterdir():
            candidate_metadata = candidate.lstat()
            if (
                candidate.name.startswith(".recovery-")
                and candidate.name.endswith(".stage")
                and (candidate_metadata.st_dev, candidate_metadata.st_ino)
                == (metadata.st_dev, metadata.st_ino)
            ):
                rejected_descriptors.append(descriptor)
                raise BlockingIOError(11, "synthetic persistent anchor contention")
        original_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", fail_recovery_anchor_flock)

    stable_names: tuple[str, ...] | None = None
    for index in range(3):
        with pytest.raises(InvalidArgumentError, match="publication"):
            inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=f"synthetic-anchor-contention-{index}.md",
                chunks=(f"Synthetic anchor contention {index}.\n".encode(),),
            )
        names = tuple(
            sorted(
                candidate.name
                for candidate in synthetic_store.inbox_staging.iterdir()
                if candidate.name.startswith(".recovery-")
                and candidate.name.endswith(".stage")
            )
        )
        assert len(names) == 8
        if stable_names is None:
            stable_names = names
        else:
            assert names == stable_names
        with pytest.raises(OSError) as captured:
            os.fstat(rejected_descriptors[-1])
        assert captured.value.errno == 9

    # Eight bounded reuse probes plus eight bounded retirement probes per
    # acquisition: 8 mints in the first pass, then 16 probes in each later pass.
    assert len(rejected_descriptors) == 40


def test_repeated_withdrawal_fsync_failures_reuse_one_closed_capability(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A persistent withdrawal barrier failure must not mint unbounded directories."""
    import memory.inbox as inbox

    original_fsync = os.fsync
    rejected_descriptors: list[int] = []

    def fail_withdrawal_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        for candidate in synthetic_store.inbox_staging.iterdir():
            candidate_metadata = candidate.lstat()
            if (
                candidate.name.startswith(".withdrawal-")
                and stat.S_ISDIR(candidate_metadata.st_mode)
                and (candidate_metadata.st_dev, candidate_metadata.st_ino)
                == (metadata.st_dev, metadata.st_ino)
            ):
                rejected_descriptors.append(descriptor)
                raise OSError(5, "synthetic persistent withdrawal fsync EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_withdrawal_fsync)

    stable_names: tuple[str, ...] | None = None
    for index in range(3):
        with pytest.raises(InvalidArgumentError, match="publication"):
            inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=f"synthetic-withdrawal-fsync-{index}.md",
                chunks=(f"Synthetic withdrawal fsync {index}.\n".encode(),),
            )
        names = tuple(
            sorted(
                candidate.name
                for candidate in synthetic_store.inbox_staging.iterdir()
                if candidate.name.startswith(".withdrawal-")
            )
        )
        assert len(names) == 1
        if stable_names is None:
            stable_names = names
        else:
            assert names == stable_names
        with pytest.raises(OSError) as captured:
            os.fstat(rejected_descriptors[-1])
        assert captured.value.errno == 9

    assert len(rejected_descriptors) == 3


@pytest.mark.parametrize("replacement_kind", ["regular", "symlink", "fifo"])
def test_publication_rechecks_bound_source_name_at_exclusive_rename(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Never publish a final-boundary replacement under the owner's name."""
    import memory.inbox as inbox

    body = b"Synthetic final-boundary source payload.\n"
    replacement = b"Synthetic unrelated final-boundary occupant.\n"
    display_name = f"synthetic-final-boundary-{replacement_kind}.md"
    destination = synthetic_store.inbox / display_name
    original_match = inbox._bound_rename_source_matches
    swapped_entry: Path | None = None

    def swap_after_final_proof(binding: inbox._BoundRename) -> bool:
        nonlocal swapped_entry
        matched = original_match(binding)
        if matched and binding.destination_name == display_name:
            swapped_entry = synthetic_store.inbox_staging / binding.source_name
            swapped_entry.unlink()
            if replacement_kind == "regular":
                swapped_entry.write_bytes(replacement)
                swapped_entry.chmod(0o600)
            elif replacement_kind == "symlink":
                swapped_entry.symlink_to("synthetic-foreign-target")
            else:
                os.mkfifo(swapped_entry, 0o600)
        return matched

    monkeypatch.setattr(inbox, "_bound_rename_source_matches", swap_after_final_proof)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=display_name,
            chunks=(body,),
        )

    assert swapped_entry is not None
    assert not destination.exists() and not destination.is_symlink()
    if replacement_kind == "regular":
        assert swapped_entry.read_bytes() == replacement
    elif replacement_kind == "symlink":
        assert swapped_entry.is_symlink()
        assert os.readlink(swapped_entry) == "synthetic-foreign-target"
    else:
        assert stat.S_ISFIFO(swapped_entry.lstat().st_mode)


@pytest.mark.parametrize(
    "descriptor_kind", ["source", "anchor", "manifest", "withdrawal"]
)
def test_close_failure_after_publication_commit_does_not_reverse_success(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    descriptor_kind: str,
) -> None:
    """A close error cannot turn a proven committed publication into failure."""
    import memory.inbox as inbox

    real_close = os.close
    original_stage = inbox._stage_private_entry_in_runtime
    original_prepare = inbox._prepare_publication_rollback
    descriptors: dict[str, int] = {}
    close_failed = False

    def capture_source(
        runtime: inbox._RuntimeRoot,
        *,
        display_name: str,
        chunks: Iterable[bytes],
        max_bytes: int,
    ) -> tuple[model.PrivateStagedEntry, int, tuple[int, ...]]:
        entry, descriptor, identity = original_stage(
            runtime,
            display_name=display_name,
            chunks=chunks,
            max_bytes=max_bytes,
        )
        descriptors["source"] = descriptor
        return entry, descriptor, identity

    def capture_rollback(
        runtime: inbox._RuntimeRoot,
        source_descriptor: int,
        source_identity: tuple[int, ...],
        entry: model.PrivateStagedEntry,
    ) -> inbox._PreheldPublicationRollback:
        preheld = original_prepare(
            runtime,
            source_descriptor,
            source_identity,
            entry,
        )
        descriptors.update(
            anchor=preheld.anchor_descriptor,
            manifest=preheld.manifest_descriptor,
            withdrawal=preheld.withdrawal_descriptor,
        )
        return preheld

    def close_then_fail(descriptor: int) -> None:
        nonlocal close_failed
        if (
            not close_failed
            and descriptor_kind in descriptors
            and descriptor == descriptors[descriptor_kind]
        ):
            close_failed = True
            real_close(descriptor)
            raise OSError(5, "synthetic post-commit close EIO")
        real_close(descriptor)

    monkeypatch.setattr(inbox, "_stage_private_entry_in_runtime", capture_source)
    monkeypatch.setattr(inbox, "_prepare_publication_rollback", capture_rollback)
    monkeypatch.setattr(os, "close", close_then_fail)

    body = f"Synthetic {descriptor_kind} close-after-commit payload.\n".encode()
    display_name = f"synthetic-{descriptor_kind}-close-after-commit.md"
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename=display_name,
        chunks=(body,),
    )

    assert close_failed
    assert staged.display_name == display_name
    assert (synthetic_store.inbox / display_name).read_bytes() == body
    with pytest.raises(OSError) as captured:
        os.fstat(descriptors[descriptor_kind])
    assert captured.value.errno == 9
    assert (
        inbox.list_exact_recovery_issues(
            synthetic_store,
            cursor=None,
            limit=10,
        ).items
        == ()
    )


def test_nonempty_withdrawal_residue_is_reported_content_free(
    synthetic_store: RuntimePaths,
) -> None:
    """Never silently ignore source bytes left inside a withdrawal capability."""
    from memory.inbox import list_exact_recovery_issues

    withdrawal = synthetic_store.inbox_staging / f".withdrawal-{'d' * 32}"
    withdrawal.mkdir(mode=0o700)
    child = withdrawal / "withdrawn"
    body = b"Synthetic unexpected withdrawal payload.\n"
    child.write_bytes(body)
    child.chmod(0o600)

    issues = list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )
    assert len(issues.items) == 1
    assert issues.items[0].code == "custody_mismatch"
    assert body.decode().strip() not in repr(issues.items)


def test_recovery_issue_cursor_is_bound_to_its_own_store_and_issue_set(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Refuse a recovery-issue cursor from another Store or another issue set."""
    from memory.errors import StaleCursorError
    from memory.inbox import list_exact_recovery_issues

    for index in range(3):
        (synthetic_store.inbox_staging / f".recovery-{index:032x}.tmp").write_bytes(b"")

    first = list_exact_recovery_issues(synthetic_store, cursor=None, limit=1)
    assert first.has_more
    assert first.next_cursor is not None
    assert (
        list_exact_recovery_issues(
            synthetic_store,
            cursor=first.next_cursor,
            limit=1,
        ).items[0]
        != first.items[0]
    )

    # A bare offset is not a cursor this Store ever minted.
    with pytest.raises(StaleCursorError):
        list_exact_recovery_issues(
            synthetic_store,
            cursor=base64.urlsafe_b64encode(b"1").decode().rstrip("="),
            limit=1,
        )

    # Neither is one minted by a different Store.
    other = resolve_runtime(tmp_path / "synthetic-second-store")
    initialize_runtime(other, mode=RuntimeMode.PERSONAL)
    for index in range(3):
        (other.inbox_staging / f".recovery-{index:032x}.tmp").write_bytes(b"")
    with pytest.raises(StaleCursorError):
        list_exact_recovery_issues(other, cursor=first.next_cursor, limit=1)

    # Nor one minted before the issue set itself changed.
    (synthetic_store.inbox_staging / f".recovery-{9:032x}.tmp").write_bytes(b"")
    with pytest.raises(StaleCursorError):
        list_exact_recovery_issues(
            synthetic_store,
            cursor=first.next_cursor,
            limit=1,
        )


def test_recovery_manifest_fifo_is_rejected_without_blocking(
    synthetic_store: RuntimePaths,
) -> None:
    """A manifest-shaped nonregular entry must never block issue enumeration."""
    fifo = synthetic_store.inbox_staging / f".recovery-{'f' * 32}.json"
    os.mkfifo(fifo, 0o600)
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
from pathlib import Path
from memory.inbox import list_exact_recovery_issues
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
issues = list_exact_recovery_issues(paths, cursor=None, limit=10)
print(tuple(item.code for item in issues.items))
"""
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0, completed.stderr
    assert "malformed_manifest" in completed.stdout
    assert stat.S_ISFIFO(fifo.lstat().st_mode)


@pytest.mark.parametrize("metadata_kind", ["intent", "ready", "claim"])
def test_exact_recovery_metadata_fifo_is_rejected_without_blocking(
    synthetic_store: RuntimePaths,
    metadata_kind: str,
) -> None:
    """A metadata-shaped FIFO must never block recovery issue enumeration."""
    entry_id = f"ent_{'e' * 32}.stage"
    if metadata_kind == "claim":
        claim = synthetic_store.inbox_claims / f"bat_{'e' * 32}"
        claim.mkdir(mode=0o700)
        fifo = claim / "manifest.json"
    else:
        fifo = synthetic_store.inbox_staging / f"{entry_id}.{metadata_kind}.json"
    os.mkfifo(fifo, 0o600)
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
from pathlib import Path
from memory.inbox import list_exact_recovery_issues
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
issues = list_exact_recovery_issues(paths, cursor=None, limit=10)
print(tuple(item.code for item in issues.items))
"""
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0, completed.stderr
    if metadata_kind != "claim":
        assert "malformed_manifest" in completed.stdout
    assert stat.S_ISFIFO(fifo.lstat().st_mode)


@pytest.mark.parametrize("replacement_kind", ["regular", "symlink", "fifo"])
def test_replaced_recovery_marker_consolidates_one_private_source_copy(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Preserve a marker occupant while consolidating to one private source."""
    import memory.inbox as inbox

    body = b"Synthetic replaced-marker source payload.\n"
    unrelated = b"Synthetic unrelated marker occupant.\n"
    destination = synthetic_store.inbox / f"synthetic-marker-{replacement_kind}.md"
    detached_marker = synthetic_store.root / f"detached-marker-{replacement_kind}"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )
    swapped_marker: Path | None = None

    def replace_marker(name: str) -> None:
        nonlocal swapped_marker
        if name == "staging.publish_rename":
            swapped_marker = next(
                synthetic_store.inbox_staging.glob(".recovery-*.json")
            )
            swapped_marker.rename(detached_marker)
            if replacement_kind == "regular":
                swapped_marker.write_bytes(unrelated)
                swapped_marker.chmod(0o600)
            elif replacement_kind == "symlink":
                swapped_marker.symlink_to("synthetic-unrelated-marker-target")
            else:
                os.mkfifo(swapped_marker, 0o600)
        original_checkpoint(name)

    def fail_initial_inbox_fsync(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if destination.exists() and identity == inbox_identity:
            raise OSError(5, "synthetic replaced-marker publication EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", replace_marker)
    monkeypatch.setattr(os, "fsync", fail_initial_inbox_fsync)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert swapped_marker is not None
    assert not destination.exists()
    assert detached_marker.read_bytes() == b""
    if replacement_kind == "regular":
        assert swapped_marker.read_bytes() == unrelated
    elif replacement_kind == "symlink":
        assert swapped_marker.is_symlink()
        assert os.readlink(swapped_marker) == "synthetic-unrelated-marker-target"
    else:
        assert stat.S_ISFIFO(swapped_marker.lstat().st_mode)
    readable_copies = [
        candidate
        for candidate in synthetic_store.inbox_staging.rglob("*")
        if candidate.is_file()
        and not candidate.is_symlink()
        and candidate.read_bytes() == body
    ]
    assert len(readable_copies) == 1
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert issues.items
    assert body.decode().strip() not in repr(issues.items)


@pytest.mark.parametrize(
    "replacement_kind",
    ["same_digest", "wrong_digest", "partial_content"],
)
def test_prepublication_cleanup_never_unlinks_a_final_boundary_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """A local replacement after the last stat must never be name-unlinked."""
    import memory.inbox as inbox

    body = b"Synthetic descriptor-bound prepublication payload.\n"
    existing_destination = b"Synthetic existing visible destination.\n"
    replacement = {
        "same_digest": body,
        "wrong_digest": b"W" * len(body),
        "partial_content": b"P" * (len(body) // 2),
    }[replacement_kind]
    destination = synthetic_store.inbox / "synthetic-prepublication-race.md"
    destination.write_bytes(existing_destination)
    destination.chmod(0o600)
    detached = (
        synthetic_store.inbox_staging
        / f".recovery-{ {'same_digest': '1', 'wrong_digest': '2', 'partial_content': '3'}[replacement_kind] * 32 }.stage"
    )

    original_rename = inbox._rename_no_replace
    original_checkpoint = inbox._checkpoint
    original_unlink = os.unlink
    entry_id: str | None = None
    swapped = False
    name_unlinks: list[str] = []

    def track_publication(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal entry_id
        if destination_name == destination.name:
            entry_id = source_name
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    def replace_before_cleanup(name: str) -> None:
        nonlocal swapped
        if name == "staging.prepublication_before_cleanup":
            assert entry_id is not None
            source = synthetic_store.inbox_staging / entry_id
            source.rename(detached)
            source.write_bytes(replacement)
            source.chmod(0o600)
            swapped = True
        original_checkpoint(name)

    def track_unlink(
        path: str,
        *args: object,
        dir_fd: int | None = None,
        **kwargs: object,
    ) -> None:
        if isinstance(path, str) and path.startswith("ent_"):
            name_unlinks.append(path)
        original_unlink(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(inbox, "_rename_no_replace", track_publication)
    monkeypatch.setattr(inbox, "_checkpoint", replace_before_cleanup)
    monkeypatch.setattr(os, "unlink", track_unlink)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert swapped
    assert name_unlinks == []
    assert entry_id is not None
    assert destination.read_bytes() == existing_destination
    assert detached.read_bytes() == b""
    assert (synthetic_store.inbox_staging / entry_id).read_bytes() == replacement
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert issues.items
    assert body.decode().strip() not in repr(issues.items)
    assert replacement.decode(errors="ignore").strip() not in repr(issues.items)


@pytest.mark.parametrize(
    "replacement_kind",
    ["same_digest", "wrong_digest", "partial_content"],
)
def test_prepublication_fresh_quarantine_boundary_never_unlinks_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Drain the bound inode if its private name is swapped at the final boundary."""
    import memory.inbox as inbox

    body = b"Synthetic fresh-quarantine descriptor payload.\n"
    existing_destination = b"Synthetic destination that must remain unchanged.\n"
    replacement = {
        "same_digest": body,
        "wrong_digest": b"W" * len(body),
        "partial_content": b"P" * (len(body) // 2),
    }[replacement_kind]
    destination = synthetic_store.inbox / "synthetic-fresh-quarantine-race.md"
    destination.write_bytes(existing_destination)
    destination.chmod(0o600)
    detached = synthetic_store.inbox_staging / (
        f"detached-fresh-quarantine-{replacement_kind}.stage"
    )

    original_rename = inbox._rename_no_replace
    original_checkpoint = inbox._checkpoint
    original_unlink = os.unlink
    entry_id: str | None = None
    swapped = False
    recovery_name_unlinks: list[str] = []

    def track_publication(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal entry_id
        if destination_name == destination.name:
            entry_id = source_name
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    def swap_before_descriptor_drain(name: str) -> None:
        nonlocal swapped
        if name == "staging.prepublication_before_descriptor_drain":
            assert entry_id is not None
            private = synthetic_store.inbox_staging / entry_id
            private.rename(detached)
            private.write_bytes(replacement)
            private.chmod(0o600)
            swapped = True
        original_checkpoint(name)

    def record_unlink(
        path: str,
        *args: object,
        dir_fd: int | None = None,
        **kwargs: object,
    ) -> None:
        if isinstance(path, str) and (
            inbox._RECOVERY_PAYLOAD.fullmatch(path) or inbox._ENTRY_ID.fullmatch(path)
        ):
            recovery_name_unlinks.append(path)
        original_unlink(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(inbox, "_rename_no_replace", track_publication)
    monkeypatch.setattr(inbox, "_checkpoint", swap_before_descriptor_drain)
    monkeypatch.setattr(os, "unlink", record_unlink)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert swapped
    assert destination.read_bytes() == existing_destination
    assert recovery_name_unlinks == []
    assert detached.read_bytes() == b""
    quarantine_replacements = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and candidate.read_bytes() == replacement
    ]
    assert len(quarantine_replacements) == 1
    retained_store_payloads = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
        and candidate not in quarantine_replacements
        and candidate.read_bytes() == body
    ]
    assert retained_store_payloads == []


def test_staging_ancestor_replacement_fails_closed_and_cleans_pinned_temporary(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a mid-stream path swap stranding or publishing private upload bytes."""
    from memory.inbox import stage_inbox_entry

    detached = synthetic_store.root / "detached-synthetic-staging"

    def replace_staging() -> Iterator[bytes]:
        yield b"first private chunk"
        synthetic_store.inbox_staging.rename(detached)
        synthetic_store.inbox_staging.mkdir(mode=0o700)
        yield b"second private chunk"

    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename="must-not-publish.txt",
            chunks=replace_staging(),
        )

    assert list(synthetic_store.inbox.iterdir()) == []
    assert list(synthetic_store.inbox_staging.iterdir()) == []
    # The reservation reclaims its own descriptor-bound tombstone, so the
    # detached original staging directory retains nothing at all.
    assert tuple(detached.iterdir()) == ()


@pytest.mark.parametrize("failure", ["rename", "staging_fsync", "inbox_fsync"])
def test_ordinary_publication_reconciles_every_postrename_failure(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """Catch a visible exact destination being reported as a failed upload."""
    import memory.inbox as inbox

    class SyntheticCrash(RuntimeError):
        pass

    renamed = False
    failure_raised = False
    postrename_fsyncs: list[tuple[int, int]] = []
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    staging_identity = (
        synthetic_store.inbox_staging.stat().st_dev,
        synthetic_store.inbox_staging.stat().st_ino,
    )
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal failure_raised, renamed
        if name == "staging.publish_rename":
            renamed = True
            if failure == "rename" and not failure_raised:
                failure_raised = True
                raise SyntheticCrash(name)
        original_checkpoint(name)

    def fsync(descriptor: int) -> None:
        nonlocal failure_raised
        original_fsync(descriptor)
        if not renamed:
            return
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        postrename_fsyncs.append(identity)
        if (
            failure == "staging_fsync"
            and identity == staging_identity
            and not failure_raised
        ):
            failure_raised = True
            raise SyntheticCrash(failure)
        if (
            failure == "inbox_fsync"
            and identity == inbox_identity
            and not failure_raised
        ):
            failure_raised = True
            raise SyntheticCrash(failure)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fsync)
    staged = inbox.stage_inbox_entry(
        synthetic_store,
        owner_filename=f"synthetic-postrename-{failure}.md",
        chunks=(b"Synthetic publication bytes.\n",),
    )
    assert staged.display_name == f"synthetic-postrename-{failure}.md"
    assert (synthetic_store.inbox / staged.display_name).read_bytes() == (
        b"Synthetic publication bytes.\n"
    )
    assert staging_identity in postrename_fsyncs
    assert inbox_identity in postrename_fsyncs
    _assert_drained_recovery_residue(
        synthetic_store,
        count=1,
        withdrawal_count=1,
    )


@pytest.mark.parametrize(
    "failed_barriers",
    [frozenset({"staging"}), frozenset({"inbox"}), frozenset({"staging", "inbox"})],
)
def test_ordinary_publication_never_reports_success_on_persistent_directory_eio(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    failed_barriers: frozenset[str],
) -> None:
    """Catch real post-rename durability failures being treated as checkpoints."""
    import memory.inbox as inbox

    renamed = False
    attempts = {"staging": 0, "inbox": 0}
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    identities = {
        "staging": (
            synthetic_store.inbox_staging.stat().st_dev,
            synthetic_store.inbox_staging.stat().st_ino,
        ),
        "inbox": (
            synthetic_store.inbox.stat().st_dev,
            synthetic_store.inbox.stat().st_ino,
        ),
    }

    def checkpoint(name: str) -> None:
        nonlocal renamed
        if name == "staging.publish_rename":
            renamed = True
        original_checkpoint(name)

    def persistent_eio(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        for barrier, expected in identities.items():
            if renamed and identity == expected:
                attempts[barrier] += 1
                if barrier in failed_barriers:
                    raise OSError(5, "synthetic persistent directory EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", persistent_eio)
    destination = synthetic_store.inbox / "synthetic-persistent-eio.md"
    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(b"Synthetic persistent durability failure.\n",),
        )

    assert not destination.exists()
    assert all(attempts[barrier] >= 2 for barrier in failed_barriers)


def test_ordinary_publication_eio_never_withdraws_a_destination_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch rollback touching a replacement instead of the retained inode."""
    import memory.inbox as inbox

    destination = synthetic_store.inbox / "synthetic-eio-replacement.md"
    detached = synthetic_store.root / "detached-eio-original"
    replacement = b"Synthetic unrelated EIO replacement.\n"
    renamed = False
    swapped = False
    rollback_checkpoints = 0
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    original_rename = inbox._rename_no_replace
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal renamed, rollback_checkpoints
        if name == "staging.publish_rename":
            renamed = True
        if name == "staging.publish_before_rollback":
            rollback_checkpoints += 1
        original_checkpoint(name)

    def swap_at_rollback_move(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal swapped
        if (
            not swapped
            and source_name == destination.name
            and destination_name == "withdrawn"
        ):
            destination.rename(detached)
            destination.write_bytes(replacement)
            destination.chmod(0o600)
            swapped = True
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    def fail_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if renamed and identity == inbox_identity:
            raise OSError(5, "synthetic persistent Inbox EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_inbox_barrier)
    monkeypatch.setattr(inbox, "_rename_no_replace", swap_at_rollback_move)
    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(b"Synthetic retained publication bytes.\n",),
        )

    assert swapped
    assert rollback_checkpoints == 1
    assert destination.read_bytes() == replacement
    assert detached.read_bytes() == b""
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
    ]
    assert retained.count(b"Synthetic retained publication bytes.\n") == 1


@pytest.mark.parametrize("same_digest_collision", [False, True])
def test_ordinary_publication_rollback_preserves_staging_collision_and_hides_payload(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    same_digest_collision: bool,
) -> None:
    """Catch failed rollback plus outer cleanup deleting a staging collision."""
    import memory.inbox as inbox

    body = b"Synthetic rollback payload that must leave the visible Inbox.\n"
    collision = body if same_digest_collision else b"Synthetic unrelated collision.\n"
    destination = synthetic_store.inbox / "synthetic-rollback-collision.md"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    original_rename = inbox._rename_no_replace
    published = False
    entry_id: str | None = None
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def track_rename(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal entry_id
        if destination_name == destination.name:
            entry_id = source_name
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    def collide_before_rollback(name: str) -> None:
        nonlocal published
        if name == "staging.publish_rename":
            published = True
        if name == "staging.publish_before_rollback":
            assert entry_id is not None
            collision_path = synthetic_store.inbox_staging / entry_id
            collision_path.write_bytes(collision)
            collision_path.chmod(0o600)
        original_checkpoint(name)

    def fail_inbox_barriers(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and identity == inbox_identity:
            raise OSError(5, "synthetic persistent Inbox EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_rename_no_replace", track_rename)
    monkeypatch.setattr(inbox, "_checkpoint", collide_before_rollback)
    monkeypatch.setattr(os, "fsync", fail_inbox_barriers)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert not destination.exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert body in retained
    assert collision in retained
    assert inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    ).items


def test_ordinary_publication_rollback_skips_an_occupied_fresh_recovery_name(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the Store payload private when the first recovery identity is occupied."""
    import memory.inbox as inbox

    body = b"Synthetic publication requiring a second recovery identity.\n"
    unrelated = b"Synthetic unrelated occupied recovery payload.\n"
    destination = synthetic_store.inbox / "synthetic-occupied-recovery.md"
    occupied_recovery_id = "f" * 32
    occupied = synthetic_store.inbox_staging / f".recovery-{occupied_recovery_id}.stage"
    occupied.write_bytes(unrelated)
    occupied.chmod(0o600)

    original_token_hex = secrets.token_hex
    token_calls = 0

    def selected_token_hex(byte_count: int) -> str:
        nonlocal token_calls
        if byte_count != 16:
            return original_token_hex(byte_count)
        token_calls += 1
        if token_calls == 1:
            return "e" * 32  # ordinary private entry identity
        if token_calls == 2:
            return occupied_recovery_id
        return original_token_hex(byte_count)

    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    original_sync_rollback = inbox._sync_rollback_directories
    published = False
    rollback_barrier_attempts: list[str] = []
    observing_rollback = False
    identities = {
        "inbox": (
            synthetic_store.inbox.stat().st_dev,
            synthetic_store.inbox.stat().st_ino,
        ),
        "staging": (
            synthetic_store.inbox_staging.stat().st_dev,
            synthetic_store.inbox_staging.stat().st_ino,
        ),
    }

    def checkpoint(name: str) -> None:
        nonlocal published
        if name == "staging.publish_rename":
            published = True
        original_checkpoint(name)

    def fsync(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if observing_rollback:
            for name, expected in identities.items():
                if identity == expected:
                    rollback_barrier_attempts.append(name)
        if published and not observing_rollback and identity == identities["inbox"]:
            raise OSError(5, "synthetic persistent publication Inbox EIO")
        original_fsync(descriptor)

    def observe_rollback(runtime: inbox._RuntimeRoot) -> bool:
        nonlocal observing_rollback
        observing_rollback = True
        try:
            return original_sync_rollback(runtime)
        finally:
            observing_rollback = False

    monkeypatch.setattr(secrets, "token_hex", selected_token_hex)
    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(inbox, "_sync_rollback_directories", observe_rollback)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert rollback_barrier_attempts.count("inbox") >= 1
    assert rollback_barrier_attempts.count("staging") >= 1
    assert not destination.exists()
    assert occupied.read_bytes() == unrelated
    private_payloads = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and candidate.name.endswith(".stage")
    ]
    assert private_payloads.count(body) == 1
    assert private_payloads.count(unrelated) == 1

    first = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    names_before = tuple(
        sorted(candidate.name for candidate in synthetic_store.inbox_staging.iterdir())
    )
    second = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert first == second
    assert first.items
    assert (
        tuple(
            sorted(
                candidate.name for candidate in synthetic_store.inbox_staging.iterdir()
            )
        )
        == names_before
    )
    assert body.decode().strip() not in repr(first.items)
    assert unrelated.decode().strip() not in repr(first.items)


def test_ordinary_publication_exhaustion_uses_one_preheld_private_anchor(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback must not allocate its only private custody after publication."""
    import memory.inbox as inbox

    body = b"Synthetic bounded recovery-exhaustion payload.\n"
    destination = synthetic_store.inbox / "synthetic-exhausted-recovery.md"
    occupied_ids = tuple(f"{index:032x}" for index in range(1, 9))
    occupied: dict[str, tuple[bytes, tuple[int, ...]]] = {}
    for index, recovery_id in enumerate(occupied_ids, start=1):
        candidate = synthetic_store.inbox_staging / f".recovery-{recovery_id}.stage"
        candidate.write_bytes(f"Synthetic unrelated occupant {index}.\n".encode())
        candidate.chmod(0o600)
        metadata = candidate.stat()
        occupied[candidate.name] = (
            candidate.read_bytes(),
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_nlink,
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_size,
            ),
        )
    baseline_issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )

    original_token_hex = secrets.token_hex
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    original_sync_rollback = inbox._sync_rollback_directories
    rollback_active = False
    rollback_candidate_index = 0
    published = False
    observing_rollback = False
    barrier_attempts: list[str] = []
    identities = {
        "inbox": (
            synthetic_store.inbox.stat().st_dev,
            synthetic_store.inbox.stat().st_ino,
        ),
        "staging": (
            synthetic_store.inbox_staging.stat().st_dev,
            synthetic_store.inbox_staging.stat().st_ino,
        ),
    }

    def selected_token_hex(byte_count: int) -> str:
        nonlocal rollback_candidate_index
        if byte_count == 16 and rollback_active:
            if rollback_candidate_index >= len(occupied_ids):
                raise AssertionError("rollback exceeded its bounded candidate set")
            selected = occupied_ids[rollback_candidate_index]
            rollback_candidate_index += 1
            return selected
        return original_token_hex(byte_count)

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_active
        if name == "staging.publish_rename":
            published = True
        elif name == "staging.publish_before_rollback":
            rollback_active = True
        original_checkpoint(name)

    def fsync(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if observing_rollback:
            for name, expected in identities.items():
                if identity == expected:
                    barrier_attempts.append(name)
        if published and not observing_rollback and identity == identities["inbox"]:
            raise OSError(5, "synthetic persistent publication Inbox EIO")
        original_fsync(descriptor)

    def observe_rollback(runtime: inbox._RuntimeRoot) -> bool:
        nonlocal observing_rollback
        observing_rollback = True
        try:
            return original_sync_rollback(runtime)
        finally:
            observing_rollback = False

    monkeypatch.setattr(secrets, "token_hex", selected_token_hex)
    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(inbox, "_sync_rollback_directories", observe_rollback)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    # Payload and final marker namespaces are both preheld before publication;
    # rollback performs no fresh recovery allocation.
    assert rollback_candidate_index == 0
    assert barrier_attempts.count("inbox") >= 1
    assert barrier_attempts.count("staging") >= 1
    assert not destination.exists()
    for name, expected in occupied.items():
        candidate = synthetic_store.inbox_staging / name
        metadata = candidate.stat()
        assert candidate.read_bytes() == expected[0]
        assert (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_nlink,
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
        ) == expected[1]

    store_payloads = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and candidate.read_bytes() == body
    ]
    assert len(store_payloads) == 1
    with inbox._open_runtime_root(synthetic_store) as runtime:
        manifests = [
            inbox._load_private_recovery_manifest(runtime, name)
            for name in os.listdir(runtime.staging_descriptor)
            if inbox._RECOVERY_MANIFEST.fullmatch(name)
        ]
        anchors = [
            reservation
            for reservation in manifests
            if reservation.kind == "ordinary_publication"
            and reservation.sha256 == hashlib.sha256(body).hexdigest()
        ]
        assert len(anchors) == 1
        assert inbox._verified_private_recovery_payload(runtime, anchors[0])

    first = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )
    filesystem_before = tuple(
        sorted(
            (candidate.name, candidate.stat().st_size)
            for candidate in synthetic_store.inbox_staging.iterdir()
        )
    )
    second = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )
    assert first == second
    assert len(first.items) == len(baseline_issues.items) + 1
    assert (
        tuple(
            sorted(
                (candidate.name, candidate.stat().st_size)
                for candidate in synthetic_store.inbox_staging.iterdir()
            )
        )
        == filesystem_before
    )
    assert body.decode().strip() not in repr(first.items)
    for occupant_bytes, _identity in occupied.values():
        assert occupant_bytes.decode().strip() not in repr(first.items)


def test_repeated_rollbacks_retire_each_authenticated_withdrawal_capability(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each consumed rollback retires its bundle instead of reusing a shape."""
    import memory.inbox as inbox

    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )
    published = False
    rollback_moved = False

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_moved
        if name == "staging.publish_rename":
            published = True
            rollback_moved = False
        elif name == "staging.publish_rollback_quarantine":
            rollback_moved = True
        original_checkpoint(name)

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_moved and identity == inbox_identity:
            raise OSError(5, "synthetic repeated publication Inbox EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)

    retired: set[str] = set()
    for index in range(3):
        destination = synthetic_store.inbox / f"synthetic-repeat-rollback-{index}.md"
        body = f"Synthetic repeated rollback payload {index}.\n".encode()
        with pytest.raises(InvalidArgumentError, match="publication"):
            inbox.stage_inbox_entry(
                synthetic_store,
                owner_filename=destination.name,
                chunks=(body,),
            )
        assert not destination.exists()
        withdrawals = tuple(
            sorted(
                candidate.name
                for candidate in synthetic_store.inbox_staging.iterdir()
                if candidate.is_dir()
            )
        )
        records = tuple(
            sorted(
                candidate
                for candidate in synthetic_store.inbox_staging.iterdir()
                if _SLOT_RECORD_NAME.fullmatch(candidate.name)
            )
        )
        # Each consumed rollback retires exactly one authenticated bundle; the
        # next publication reclaims that retired slot capability and mints one
        # fresh bundle instead of reusing a shape. The retained payload,
        # manifest, and withdrawal directory all stay in place.
        assert len(withdrawals) == index + 1
        assert len(records) == 1
        retired |= set(withdrawals)
        assert retired == set(withdrawals)
        for record in records:
            _assert_authenticated_rollback_slot(synthetic_store, record)
        assert all(
            tuple(candidate.iterdir()) == ()
            for candidate in synthetic_store.inbox_staging.iterdir()
            if candidate.is_dir()
        )


def test_anchor_mismatch_cannot_short_circuit_publication_withdrawal(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even an untrusted anchor must not leave the Store source scan-visible."""
    import memory.inbox as inbox

    body = b"Synthetic mismatched-anchor rollback payload.\n"
    destination = synthetic_store.inbox / "synthetic-mismatched-anchor.md"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    published = False
    rollback_moved = False
    barriers: list[str] = []
    identities = {
        "inbox": (
            synthetic_store.inbox.stat().st_dev,
            synthetic_store.inbox.stat().st_ino,
        ),
        "staging": (
            synthetic_store.inbox_staging.stat().st_dev,
            synthetic_store.inbox_staging.stat().st_ino,
        ),
    }

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_moved
        if name == "staging.publish_rename":
            published = True
        elif name == "staging.publish_rollback_quarantine":
            rollback_moved = True
        if name.startswith("staging.rollback_"):
            barriers.append(name)
        original_checkpoint(name)

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_moved and identity == identities["inbox"]:
            raise OSError(5, "synthetic mismatched-anchor publication EIO")
        original_fsync(descriptor)

    # Counted, not just replaced. Every assertion below holds equally if the
    # real anchor happened to match, so a stub that is never consulted would
    # leave this test green while proving nothing about the mismatch path.
    anchor_checks = 0

    def anchor_never_matches(*_args: object) -> bool:
        nonlocal anchor_checks
        anchor_checks += 1
        return False

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)
    monkeypatch.setattr(inbox, "_preheld_anchor_matches", anchor_never_matches)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert anchor_checks > 0
    assert rollback_moved
    assert not destination.exists()
    assert "staging.rollback_inbox_directory_fsync" in barriers
    assert "staging.rollback_staging_directory_fsync" in barriers
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
    ]
    retained.extend(
        child.read_bytes()
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
        for child in directory.iterdir()
        if child.is_file()
    )
    assert retained.count(body) >= 1
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert issues.items
    assert body.decode().strip() not in repr(issues.items)


def test_transient_anchor_mismatch_reproves_then_drains_withdrawn_duplicate(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Release must finish a withdrawal once its anchor becomes trustworthy."""
    import memory.inbox as inbox

    body = b"Synthetic transient anchor mismatch payload.\n"
    destination = synthetic_store.inbox / "synthetic-transient-anchor.md"
    original_match = inbox._preheld_anchor_matches
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    match_calls = 0
    published = False
    rollback_moved = False
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def transient_match(
        runtime: inbox._RuntimeRoot,
        preheld: inbox._PreheldPublicationRollback,
    ) -> bool:
        nonlocal match_calls
        match_calls += 1
        if match_calls == 1:
            return False
        return original_match(runtime, preheld)

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_moved
        if name == "staging.publish_rename":
            published = True
        elif name == "staging.publish_rollback_quarantine":
            rollback_moved = True
        original_checkpoint(name)

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_moved and identity == inbox_identity:
            raise OSError(5, "synthetic transient-anchor publication EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_preheld_anchor_matches", transient_match)
    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert match_calls >= 2
    assert not destination.exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    retained.extend(
        child.read_bytes()
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
        for child in directory.iterdir()
        if child.is_file()
    )
    assert retained.count(body) == 1
    assert all(
        tuple(directory.iterdir()) == ()
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
    )


def test_rollback_checkpoint_failure_cannot_skip_unconditional_withdrawal(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Instrumentation failure before rollback must not leave source bytes visible."""
    import memory.inbox as inbox

    body = b"Synthetic rollback-checkpoint failure payload.\n"
    destination = synthetic_store.inbox / "synthetic-rollback-checkpoint.md"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    published = False
    rollback_moved = False
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_moved
        if name == "staging.publish_rename":
            published = True
        elif name == "staging.publish_before_rollback":
            raise RuntimeError("synthetic rollback entry checkpoint failure")
        elif name == "staging.publish_rollback_quarantine":
            rollback_moved = True
        original_checkpoint(name)

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_moved and identity == inbox_identity:
            raise OSError(5, "synthetic checkpoint publication EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert rollback_moved
    assert not destination.exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert retained.count(body) == 1


@pytest.mark.parametrize(
    "checkpoint",
    [
        "staging.publish_before_rollback",
        "staging.recovery_manifest_file_fsync",
        "staging.publish_before_rollback_quarantine",
    ],
)
def test_rollback_process_death_checkpoints_leave_no_source_visible(
    synthetic_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Every rollback crash hook runs only after descriptor-proven withdrawal."""
    body = b"Synthetic rollback process-death payload.\n"
    display_name = "synthetic-rollback-process-death.md"
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
real_fsync = os.fsync
inbox_identity = (paths.inbox.stat().st_dev, paths.inbox.stat().st_ino)
published = False

def crash_checkpoint(name):
    global published
    if name == "staging.publish_rename":
        published = True
    if name == {checkpoint!r}:
        os._exit(86)

def fail_publication_inbox_fsync(descriptor):
    identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
    if published and identity == inbox_identity:
        raise OSError(5, "synthetic persistent publication Inbox EIO")
    real_fsync(descriptor)

inbox._checkpoint = crash_checkpoint
inbox.os.fsync = fail_publication_inbox_fsync
inbox.stage_inbox_entry(
    paths,
    owner_filename={display_name!r},
    chunks=(base64.b64decode({encoded!r}),),
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 86, completed.stderr
    assert not (synthetic_store.inbox / display_name).exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
    ]
    retained.extend(
        child.read_bytes()
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
        for child in directory.iterdir()
        if child.is_file()
    )
    assert body in retained


def test_transient_withdrawn_verifier_crash_keeps_moved_source_private(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """Verifier uncertainty must never restore Store bytes before a crash hook."""
    # The stub leaves a witness. Everything asserted below is equally true if
    # the real verifier answered, so without one this proves nothing about
    # what happens when the verifier is uncertain.
    witness = tmp_path / "withdrawn-verifier-was-consulted"
    body = b"Synthetic transient verifier process-death payload.\n"
    display_name = "synthetic-transient-verifier-process-death.md"
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
real_fsync = os.fsync
inbox_identity = (paths.inbox.stat().st_dev, paths.inbox.stat().st_ino)
published = False

def crash_checkpoint(name):
    global published
    if name == "staging.publish_rename":
        published = True
    if name == "staging.publish_before_rollback":
        os._exit(86)

def fail_publication_inbox_fsync(descriptor):
    identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
    if published and identity == inbox_identity:
        raise OSError(5, "synthetic transient-verifier Inbox EIO")
    real_fsync(descriptor)

inbox._checkpoint = crash_checkpoint
def never_matches(*_args):
    Path({os.fspath(witness)!r}).write_bytes(b"consulted")
    return False

inbox._withdrawn_payload_matches_descriptor = never_matches
inbox.os.fsync = fail_publication_inbox_fsync
inbox.stage_inbox_entry(
    paths,
    owner_filename={display_name!r},
    chunks=(base64.b64decode({encoded!r}),),
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 86, completed.stderr
    assert witness.exists(), "the withdrawn-payload verifier was never consulted"
    assert not (synthetic_store.inbox / display_name).exists()
    private_children = [
        child.read_bytes()
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
        for child in directory.iterdir()
        if child.is_file()
    ]
    assert body in private_children


def test_transient_publication_verifiers_cannot_precede_private_rollback_checkpoint(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    """A process-exit hook is reachable only after Inbox-wide source withdrawal."""
    # The stub leaves a witness. Nothing asserted below distinguishes a
    # defeated reconciler from a reconciler that happened to agree, so an
    # injection nobody consults would read as proof and be none.
    witness = tmp_path / "reconciler-was-consulted"
    body = b"Synthetic transient publication-verifier payload.\n"
    display_name = "synthetic-transient-publication-verifier.md"
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
real_fsync = os.fsync
inbox_identity = (paths.inbox.stat().st_dev, paths.inbox.stat().st_ino)
published = False

def crash_checkpoint(name):
    global published
    if name == "staging.publish_rename":
        published = True
    if name == "staging.publish_before_rollback":
        os._exit(86)

def fail_publication_inbox_fsync(descriptor):
    identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
    if published and identity == inbox_identity:
        raise OSError(5, "synthetic persistent publication Inbox EIO")
    real_fsync(descriptor)

inbox._checkpoint = crash_checkpoint
inbox.os.fsync = fail_publication_inbox_fsync
# Only verifiers rollback actually consults are defeated here. The path proof
# itself is deliberately called without an injectable wrapper in front of it,
# so there is nothing further to patch -- patching a name rollback never reads
# would look like coverage and prove nothing.
def no_reconciliation(*_args, **_kwargs):
    Path({os.fspath(witness)!r}).write_bytes(b"consulted")
    return None

inbox._reconcile_published_entry = no_reconciliation
inbox.stage_inbox_entry(
    paths,
    owner_filename={display_name!r},
    chunks=(base64.b64decode({encoded!r}),),
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 86, completed.stderr
    assert witness.exists(), "the publication reconciler was never consulted"
    destination = synthetic_store.inbox / display_name
    assert not destination.exists()
    assert body not in tuple(
        candidate.read_bytes()
        for candidate in synthetic_store.inbox.iterdir()
        if candidate.is_file()
    )


def test_alternate_inbox_source_is_withdrawn_before_rollback_process_exit(
    synthetic_store: RuntimePaths,
) -> None:
    """Rollback locates the bound source across Inbox and preserves its replacement."""
    body = b"Synthetic alternate Inbox source payload.\n"
    replacement = b"Synthetic alternate Inbox replacement.\n"
    display_name = "synthetic-alternate-inbox-source.md"
    alternate_name = "synthetic-alternate-inbox-bound-source.md"
    encoded_body = base64.b64encode(body).decode("ascii")
    encoded_replacement = base64.b64encode(replacement).decode("ascii")
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
real_fsync = os.fsync
real_rename = inbox._rename_no_replace
inbox_identity = (paths.inbox.stat().st_dev, paths.inbox.stat().st_ino)
published = False
swapped = False

def crash_checkpoint(name):
    global published
    if name == "staging.publish_rename":
        published = True
    if name == "staging.publish_before_rollback":
        os._exit(86)

def fail_publication_inbox_fsync(descriptor):
    identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
    if published and identity == inbox_identity:
        raise OSError(5, "synthetic persistent publication Inbox EIO")
    real_fsync(descriptor)

def relocate_before_rollback_move(
    source_name,
    destination_name,
    *,
    source_descriptor,
    destination_descriptor,
):
    global swapped
    if not swapped and source_name == {display_name!r} and destination_name == "withdrawn":
        swapped = True
        (paths.inbox / source_name).rename(paths.inbox / {alternate_name!r})
        replacement = paths.inbox / source_name
        replacement.write_bytes(base64.b64decode({encoded_replacement!r}))
        replacement.chmod(0o600)
    real_rename(
        source_name,
        destination_name,
        source_descriptor=source_descriptor,
        destination_descriptor=destination_descriptor,
    )

inbox._checkpoint = crash_checkpoint
inbox.os.fsync = fail_publication_inbox_fsync
inbox._rename_no_replace = relocate_before_rollback_move
inbox.stage_inbox_entry(
    paths,
    owner_filename={display_name!r},
    chunks=(base64.b64decode({encoded_body!r}),),
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 86, completed.stderr
    assert (synthetic_store.inbox / display_name).read_bytes() == replacement
    assert not (synthetic_store.inbox / alternate_name).exists()
    assert body not in tuple(
        candidate.read_bytes()
        for candidate in synthetic_store.inbox.iterdir()
        if candidate.is_file()
    )


def test_occupied_withdrawal_and_drain_failure_seals_visible_source(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An occupied fixed child must be preserved without leaving readable source."""
    import memory.inbox as inbox

    body = b"Synthetic occupied-withdrawal source payload.\n"
    unrelated = b"Synthetic unrelated fixed-child occupant.\n"
    destination = synthetic_store.inbox / "synthetic-occupied-withdrawal.md"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    original_rename = inbox._rename_no_replace
    original_drain = inbox._drain_verified_descriptor
    original_ftruncate = os.ftruncate
    published = False
    rollback_started = False
    source_identity: tuple[int, int] | None = None
    barriers: list[str] = []
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal published
        if name == "staging.publish_rename":
            published = True
        elif name.startswith("staging.rollback_"):
            barriers.append(name)
        original_checkpoint(name)

    def occupy_fixed_child_before_move(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal rollback_started, source_identity
        if destination_name == "withdrawn":
            rollback_started = True
            metadata = destination.stat()
            source_identity = (metadata.st_dev, metadata.st_ino)
            withdrawal = next(
                candidate
                for candidate in synthetic_store.inbox_staging.iterdir()
                if candidate.is_dir()
            )
            child = withdrawal / "withdrawn"
            child.write_bytes(unrelated)
            child.chmod(0o600)
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_started and identity == inbox_identity:
            raise OSError(5, "synthetic occupied-withdrawal publication EIO")
        original_fsync(descriptor)

    def fail_source_drain(
        descriptor: int,
        expected_identity: tuple[int, ...],
        expected_sha256: str,
    ) -> bool:
        metadata = os.fstat(descriptor)
        if source_identity == (metadata.st_dev, metadata.st_ino):
            return False
        return original_drain(descriptor, expected_identity, expected_sha256)

    def fail_sealed_source_truncate(descriptor: int, length: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            source_identity == (metadata.st_dev, metadata.st_ino)
            and stat.S_IMODE(metadata.st_mode) == 0
        ):
            raise OSError(5, "synthetic sealed visible-source truncate EIO")
        original_ftruncate(descriptor, length)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)
    monkeypatch.setattr(inbox, "_rename_no_replace", occupy_fixed_child_before_move)
    monkeypatch.setattr(inbox, "_drain_verified_descriptor", fail_source_drain)
    monkeypatch.setattr(os, "ftruncate", fail_sealed_source_truncate)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    withdrawal = next(
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_dir()
    )
    assert (withdrawal / "withdrawn").read_bytes() == unrelated
    assert destination.stat().st_size == len(body)
    assert stat.S_IMODE(destination.stat().st_mode) == 0
    assert barriers == []


def test_publication_hardlink_race_withdraws_without_truncating_external_link(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Link-count drift may permit private move, never descriptor truncation."""
    import memory.inbox as inbox

    body = b"Synthetic hardlink-withdrawal payload.\n"
    destination = synthetic_store.inbox / "synthetic-hardlink-withdrawal.md"
    outside = synthetic_store.root / "synthetic-outside-hardlink"
    original_checkpoint = inbox._checkpoint
    original_fsync = os.fsync
    published = False
    rollback_started = False
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_started
        if name == "staging.publish_rename":
            published = True
            os.link(destination, outside)
        elif name == "staging.publish_rollback_quarantine":
            rollback_started = True
        original_checkpoint(name)

    def fail_publication_inbox_barrier(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_started and identity == inbox_identity:
            raise OSError(5, "synthetic hardlink publication EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barrier)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert not destination.exists()
    assert outside.read_bytes() == body
    private_children = [
        child
        for directory in synthetic_store.inbox_staging.iterdir()
        if directory.is_dir()
        for child in directory.iterdir()
    ]
    assert len(private_children) == 1
    assert private_children[0].read_bytes() == body
    assert inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    ).items


@pytest.mark.parametrize(
    "failed_rollback_barriers",
    [frozenset({"inbox"}), frozenset({"staging"}), frozenset({"inbox", "staging"})],
)
def test_ordinary_publication_rollback_barrier_failure_keeps_private_handoff(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    failed_rollback_barriers: frozenset[str],
) -> None:
    """Catch rollback barrier uncertainty erasing its only recovery handoff."""
    import memory.inbox as inbox

    body = b"Synthetic rollback barrier payload.\n"
    destination = synthetic_store.inbox / "synthetic-rollback-barriers.md"
    identities = {
        "staging": (
            synthetic_store.inbox_staging.stat().st_dev,
            synthetic_store.inbox_staging.stat().st_ino,
        ),
        "inbox": (
            synthetic_store.inbox.stat().st_dev,
            synthetic_store.inbox.stat().st_ino,
        ),
    }
    original_fsync = os.fsync
    original_checkpoint = inbox._checkpoint
    published = False
    rollback_moved = False

    def checkpoint(name: str) -> None:
        nonlocal published, rollback_moved
        if name == "staging.publish_rename":
            published = True
        elif name == "staging.publish_rollback_quarantine":
            rollback_moved = True
        original_checkpoint(name)

    def fail_selected_barriers(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not rollback_moved and identity == identities["inbox"]:
            raise OSError(5, "synthetic publication Inbox EIO")
        if rollback_moved:
            for name in failed_rollback_barriers:
                if identity == identities[name]:
                    raise OSError(5, f"synthetic rollback {name} EIO")
        original_fsync(descriptor)

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_selected_barriers)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert rollback_moved
    assert not destination.exists()
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert retained.count(body) == 1
    assert all(candidate in {b"", body} for candidate in retained)
    assert inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    ).items


def test_ordinary_publication_rollback_move_preserves_destination_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a rollback quarantine move accepting or deleting a raced inode."""
    import memory.inbox as inbox

    body = b"Synthetic rollback move original.\n"
    replacement = b"Synthetic rollback move replacement.\n"
    destination = synthetic_store.inbox / "synthetic-rollback-move-race.md"
    detached = synthetic_store.root / "detached-rollback-move-original"
    original_rename = inbox._rename_no_replace
    original_fsync = os.fsync
    original_checkpoint = inbox._checkpoint
    published = False
    swapped = False
    inbox_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )

    def checkpoint(name: str) -> None:
        nonlocal published
        if name == "staging.publish_rename":
            published = True
        original_checkpoint(name)

    def fail_publication_inbox_barriers(descriptor: int) -> None:
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if published and not swapped and identity == inbox_identity:
            raise OSError(5, "synthetic publication Inbox EIO")
        original_fsync(descriptor)

    def swap_at_rollback_move(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal swapped
        if source_name == destination.name and destination_name == "withdrawn":
            swapped = True
            destination.rename(detached)
            destination.write_bytes(replacement)
            destination.chmod(0o600)
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    monkeypatch.setattr(inbox, "_checkpoint", checkpoint)
    monkeypatch.setattr(os, "fsync", fail_publication_inbox_barriers)
    monkeypatch.setattr(inbox, "_rename_no_replace", swap_at_rollback_move)

    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename=destination.name,
            chunks=(body,),
        )

    assert swapped
    assert destination.read_bytes() == replacement
    assert detached.read_bytes() == b""
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert retained.count(body) == 1
    assert replacement not in retained
    assert inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    ).items


def test_ordinary_publication_rejects_destination_replacement_without_deleting_it(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch postrename validation accepting a same-name unrelated inode."""
    import memory.inbox as inbox

    replacement = b"Synthetic unrelated replacement.\n"
    detached = synthetic_store.root / "detached-published-entry"

    def replace_after_rename(checkpoint: str) -> None:
        if checkpoint != "staging.publish_rename":
            return
        published = synthetic_store.inbox / "synthetic-replaced-after-rename.md"
        published.rename(detached)
        published.write_bytes(replacement)
        published.chmod(0o600)

    monkeypatch.setattr(inbox, "_checkpoint", replace_after_rename)
    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename="synthetic-replaced-after-rename.md",
            chunks=(b"Synthetic original publication.\n",),
        )
    assert (
        synthetic_store.inbox / "synthetic-replaced-after-rename.md"
    ).read_bytes() == replacement
    assert detached.read_bytes() == b""
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
    ]
    assert retained.count(b"Synthetic original publication.\n") == 1


def test_ordinary_publication_rechecks_destination_after_digest_race(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a replacement racing between destination identity and digest checks."""
    import memory.inbox as inbox

    original_digest = inbox._descriptor_sha256
    publication_visible = False
    published_digest_calls = 0
    detached = synthetic_store.root / "detached-digest-race-entry"
    replacement = b"Synthetic digest-race replacement.\n"

    def replace_during_reconciliation(descriptor: int) -> str:
        nonlocal published_digest_calls
        digest = original_digest(descriptor)
        if publication_visible:
            published_digest_calls += 1
        if published_digest_calls == 1:
            visible = synthetic_store.inbox / "synthetic-digest-race.md"
            visible.rename(detached)
            visible.write_bytes(replacement)
            visible.chmod(0o600)
        return digest

    def mark_published(name: str) -> None:
        nonlocal publication_visible
        if name == "staging.publish_rename":
            publication_visible = True

    monkeypatch.setattr(inbox, "_descriptor_sha256", replace_during_reconciliation)
    monkeypatch.setattr(inbox, "_checkpoint", mark_published)
    with pytest.raises(InvalidArgumentError, match="publication"):
        inbox.stage_inbox_entry(
            synthetic_store,
            owner_filename="synthetic-digest-race.md",
            chunks=(b"Synthetic original digest-race bytes.\n",),
        )
    assert published_digest_calls >= 1
    assert (synthetic_store.inbox / "synthetic-digest-race.md").read_bytes() == (
        replacement
    )
    assert detached.read_bytes() == b""


@pytest.mark.parametrize("ancestor", ["runtime", "inbox"])
def test_staging_runtime_or_inbox_replacement_never_publishes(
    synthetic_store: RuntimePaths,
    ancestor: str,
) -> None:
    """Catch path-based validation after pinned runtime capabilities are opened."""
    from memory.inbox import stage_inbox_entry

    selected = synthetic_store.root if ancestor == "runtime" else synthetic_store.inbox
    detached = selected.parent / f"detached-synthetic-{ancestor}"

    def replace_ancestor() -> Iterator[bytes]:
        yield b"first private chunk"
        selected.rename(detached)
        selected.mkdir(mode=0o700)
        yield b"second private chunk"

    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename=f"must-not-publish-{ancestor}.txt",
            chunks=replace_ancestor(),
        )

    assert list(selected.iterdir()) == []
    if ancestor == "runtime":
        # The reservation reclaims its own descriptor-bound tombstone, so no
        # private artifact survives in the detached original runtime.
        assert tuple((detached / "inbox-staging").iterdir()) == ()
        assert list((detached / "Inbox").iterdir()) == []
    else:
        assert list(detached.iterdir()) == []


def test_scanner_cannot_observe_an_upload_before_exclusive_publication(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch private multipart bytes becoming scan-visible before completion."""
    from memory.errors import NoEligibleSourcesError
    from memory.inbox import ScanPolicy, scan_inbox, stage_inbox_entry

    private_ready = threading.Event()
    release = threading.Event()
    staged: list[object] = []

    def chunks() -> Iterator[bytes]:
        yield b"first synthetic upload chunk"
        private_ready.set()
        assert release.wait(timeout=10)
        yield b"second synthetic upload chunk"

    def upload() -> None:
        try:
            staged.append(
                stage_inbox_entry(
                    synthetic_store,
                    owner_filename="paused-synthetic-upload.txt",
                    chunks=chunks(),
                )
            )
        except BaseException as error:
            staged.append(error)

    worker = threading.Thread(target=upload)
    worker.start()
    assert private_ready.wait(timeout=10)
    try:
        with pytest.raises(NoEligibleSourcesError):
            scan_inbox(
                synthetic_store,
                clock=FrozenClock(),
                policy=ScanPolicy(settle_seconds=0),
            )
    finally:
        release.set()
        worker.join(timeout=10)
    assert not worker.is_alive()
    assert len(staged) == 1 and isinstance(staged[0], model.StagedInboxEntry)
    assert (synthetic_store.inbox / "paused-synthetic-upload.txt").is_file()


def test_exact_staging_shares_the_global_ordinary_stage_bound(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch exact capture minting ent_* names outside the global staging bound."""
    from memory.inbox import stage_exact_private_entry

    def ordinary_names() -> tuple[str, ...]:
        return tuple(
            sorted(
                entry.name
                for entry in synthetic_store.inbox_staging.iterdir()
                if _ORDINARY_STAGE_NAME.fullmatch(entry.name)
            )
        )

    for index in range(8):
        body, metadata = _exact_owner_payload(synthetic_store, marker=f"{index:x}")
        stage_exact_private_entry(
            synthetic_store,
            display_name=f"synthetic-bound-{index}.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
    assert len(ordinary_names()) == 8

    body, metadata = _exact_owner_payload(synthetic_store, marker="8")
    with pytest.raises(InvalidArgumentError, match="capacity"):
        stage_exact_private_entry(
            synthetic_store,
            display_name="synthetic-bound-overflow.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
    assert len(ordinary_names()) == 8


def test_exact_staging_reserves_its_identity_under_the_store_writer_lock(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch exact staging creating a reservation while another writer holds it."""
    import fcntl

    from memory.inbox import stage_exact_private_entry

    body, metadata = _exact_owner_payload(synthetic_store, marker="b")
    descriptor = os.open(synthetic_store.writer_lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(StoreBusyError):
            stage_exact_private_entry(
                synthetic_store,
                display_name="synthetic-locked-correction.md",
                chunks=(body,),
                max_bytes=len(body),
                metadata=metadata,
            )
    finally:
        os.close(descriptor)
    assert (
        tuple(
            entry.name
            for entry in synthetic_store.inbox_staging.iterdir()
            if _ORDINARY_STAGE_NAME.fullmatch(entry.name)
        )
        == ()
    )


def test_exact_private_capture_is_isolated_idempotent_and_preserves_origin(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.inbox import (
        capture_exact_staged_entry,
        stage_exact_private_entry,
    )

    body, metadata = _exact_owner_payload(synthetic_store, marker="1")
    entry = stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    batch = capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)
    replay = capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)

    assert replay == batch
    assert batch.batch_id == metadata.batch_id
    assert batch.source_count == 1
    assert list(synthetic_store.inbox.iterdir()) == []
    detail = read_batch(synthetic_store, batch.batch_id)
    assert detail.sources[0].origin is SourceCaptureOrigin.OWNER_CORRECTION
    assert detail.sources[0].authorship is Authorship.OWNER
    assert detail.sources[0].declared_sensitivity is Sensitivity.RESTRICTED
    assert detail.sources[0].captured_at == metadata.captured_at


@pytest.mark.parametrize("target", ["payload", "manifest"])
def test_exact_cleanup_never_unlinks_a_postverification_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    """Catch exact cleanup deleting an inode swapped in after its own checks."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="d")
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-cleanup-race.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    selected = entry.entry_id if target == "payload" else entry.entry_id + ".ready.json"
    replacement_bytes = b"unrelated synthetic occupant"
    swapped: list[str] = []

    def swap() -> None:
        if swapped:
            return
        swapped.append(selected)
        occupant = synthetic_store.inbox_staging / selected
        occupant.unlink()
        occupant.write_bytes(replacement_bytes)
        occupant.chmod(0o600)

    original_verify = inbox._verify_private_file
    original_load = inbox._load_exact_ready

    def verify(
        runtime: inbox._RuntimeRoot,
        staged: model.PrivateStagedEntry,
    ) -> os.stat_result:
        result = original_verify(runtime, staged)
        if target == "payload":
            swap()
        return result

    def load(
        runtime: inbox._RuntimeRoot,
        entry_id: str,
        *,
        require_file: bool = True,
    ) -> tuple[model.PrivateStagedEntry, model.ExactCaptureMetadata]:
        result = original_load(
            runtime,
            entry_id,
            require_file=require_file,
        )
        if target == "manifest":
            swap()
        return result

    monkeypatch.setattr(inbox, "_verify_private_file", verify)
    monkeypatch.setattr(inbox, "_load_exact_ready", load)
    with inbox._open_runtime_root(synthetic_store) as runtime:
        with pytest.raises(InvalidArgumentError, match="cleanup"):
            inbox._cleanup_exact_ready(runtime, entry, metadata)
    assert swapped == [selected]
    assert (synthetic_store.inbox_staging / selected).read_bytes() == (
        replacement_bytes
    )


def test_exact_cleanup_drains_its_payload_before_any_unlink(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a verified exact payload staying readable when its unlink fails."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="e")
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-cleanup-unlink-failure.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    original_unlink = os.unlink

    def refusing_unlink(
        name: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        if name == entry.entry_id:
            raise OSError(13, "synthetic staging unlink refusal")
        original_unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", refusing_unlink)
    with inbox._open_runtime_root(synthetic_store) as runtime:
        with pytest.raises(InvalidArgumentError, match="cleanup"):
            inbox._cleanup_exact_ready(runtime, entry, metadata)
    monkeypatch.undo()
    payload = synthetic_store.inbox_staging / entry.entry_id
    assert payload.read_bytes() == b""
    assert (
        inbox.list_exact_recovery_issues(
            synthetic_store,
            cursor=None,
            limit=100,
        ).items
        != ()
    )


@pytest.mark.parametrize("damage", ["length", "name", "media", "membership"])
def test_exact_postcommit_replay_quarantines_every_ready_binding_mismatch(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    """Catch a committed row being accepted on digest-only exact replay."""
    import memory.inbox as inbox
    from memory.database import open_database
    from memory.keys import load_master_key

    class SyntheticCrash(RuntimeError):
        pass

    marker = {"length": "1", "name": "2", "media": "3", "membership": "4"}[damage]
    body, metadata = _exact_owner_payload(synthetic_store, marker=marker)
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name=f"synthetic-postcommit-{damage}.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def crash_after_commit(checkpoint: str) -> None:
        if checkpoint == "exact.database_commit":
            raise SyntheticCrash(checkpoint)

    monkeypatch.setattr(inbox, "_checkpoint", crash_after_commit)
    with pytest.raises(SyntheticCrash, match=re.escape("exact.database_commit")):
        inbox.capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)
    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=False,
    )
    try:
        source_id = connection.execute(
            "SELECT source_id FROM sources WHERE batch_id = ?",
            (metadata.batch_id,),
        ).fetchone()[0]
        if damage == "length":
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE source_blobs SET byte_length = byte_length + 1 "
                "WHERE blob_id = (SELECT blob_id FROM sources WHERE source_id = ?)",
                (source_id,),
            )
        elif damage == "name":
            connection.execute(
                "UPDATE sources SET original_name = ? WHERE source_id = ?",
                ("synthetic-wrong-name.md", source_id),
            )
        elif damage == "media":
            connection.execute(
                "UPDATE sources SET media_type = ? WHERE source_id = ?",
                ("application/octet-stream", source_id),
            )
        else:
            connection.execute(
                "DELETE FROM inbox_batch_sources WHERE batch_id = ?",
                (metadata.batch_id,),
            )
        connection.commit()
    finally:
        connection.close()

    ready = synthetic_store.inbox_staging / f"{entry.entry_id}.ready.json"
    assert ready.is_file()
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}
    assert ready.is_file()


@pytest.mark.parametrize("field", ["target_lineage_id", "expected_head_id"])
def test_exact_postcommit_replay_validates_retained_correction_envelope(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    """Catch ready metadata being trusted without its retained envelope binding."""
    import memory.inbox as inbox
    from memory.database import open_database
    from memory.keys import load_master_key

    class SyntheticCrash(RuntimeError):
        pass

    marker = "5" if field == "target_lineage_id" else "6"
    body, metadata = _exact_owner_payload(synthetic_store, marker=marker)
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name=f"synthetic-envelope-{field}.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def crash_after_commit(checkpoint: str) -> None:
        if checkpoint == "exact.database_commit":
            raise SyntheticCrash(checkpoint)

    monkeypatch.setattr(inbox, "_checkpoint", crash_after_commit)
    with pytest.raises(SyntheticCrash, match=re.escape("exact.database_commit")):
        inbox.capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)
    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)

    old_value = getattr(metadata, field)
    prefix = "lin_" if field == "target_lineage_id" else "mem_"
    replacement = prefix + ("a" if marker != "a" else "b") * 32
    mutated = body.replace(
        f"{field}: {old_value}\n".encode(),
        f"{field}: {replacement}\n".encode(),
    )
    assert mutated != body and len(mutated) == len(body)
    mutated_digest = hashlib.sha256(mutated).hexdigest()

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=False,
    )
    try:
        connection.execute(
            "UPDATE source_blobs SET sha256 = ?, original_bytes = ?, "
            "byte_length = ? WHERE sha256 = ?",
            (mutated_digest, mutated, len(mutated), metadata.payload_sha256),
        )
        connection.commit()
    finally:
        connection.close()

    for claim in synthetic_store.inbox_claims.iterdir():
        shutil.rmtree(claim)
    private = synthetic_store.inbox_staging / entry.entry_id
    private.write_bytes(mutated)
    private.chmod(0o600)
    ready = synthetic_store.inbox_staging / f"{entry.entry_id}.ready.json"
    ready_payload = json.loads(ready.read_text(encoding="utf-8"))
    ready_payload["payload_sha256"] = mutated_digest
    ready.write_text(
        json.dumps(ready_payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    ready.chmod(0o600)

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}
    assert ready.is_file()


@pytest.mark.parametrize(
    "checkpoint", ["staging.file_fsync", "staging.directory_fsync"]
)
def test_exact_staging_process_death_before_ready_manifest_is_recoverable(
    synthetic_store: RuntimePaths,
    checkpoint: str,
) -> None:
    """Catch process death stranding private exact bytes without their identity."""
    body, metadata = _exact_owner_payload(synthetic_store, marker="7")
    encoded = base64.b64encode(body).decode("ascii")
    script = (
        _synthetic_keyring_prelude(synthetic_store)
        + f"""
import base64
import os
from pathlib import Path
import memory.inbox as inbox
from memory.model import Authorship, ExactCaptureMetadata, Sensitivity, SourceCaptureOrigin
from memory.runtime import resolve_runtime

paths = resolve_runtime(Path({os.fspath(synthetic_store.root)!r}))
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
    display_name="synthetic-process-death.md",
    chunks=(base64.b64decode({encoded!r}),),
    max_bytes={len(body)},
    metadata=metadata,
)
"""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 86, completed.stderr

    import memory.inbox as inbox

    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    assert (
        inbox.list_exact_recovery_issues(
            synthetic_store,
            cursor=None,
            limit=10,
        ).items
        == ()
    )


def test_exact_process_death_immediately_before_payload_fsync_recovers_reserved_bytes(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch recovery publishing complete bytes that were never durably synced."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="8")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="exact.payload_before_file_fsync",
        display_name="synthetic-before-payload-fsync.md",
    )
    assert completed.returncode == 86, completed.stderr

    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    assert tuple(synthetic_store.inbox_staging.iterdir()) == ()


def test_exact_recovery_fsyncs_bound_complete_payload_before_ready_publication(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch recovery trusting complete bytes without a payload-inode barrier."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="9")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-recovery-payload-fsync.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    payload_identity = (payload_path.stat().st_dev, payload_path.stat().st_ino)

    original_fsync = os.fsync
    synced_identities: list[tuple[int, int]] = []

    def record_fsync(descriptor: int) -> None:
        metadata_before = os.fstat(descriptor)
        synced_identities.append((metadata_before.st_dev, metadata_before.st_ino))
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert len(recovered) == 1
    assert payload_identity in synced_identities


def test_exact_intent_recovery_quarantines_same_digest_inode_replacement(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a digest-equivalent pathname replacement escaping inode custody."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="a")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-same-digest-replacement.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    original_identity = (payload_path.stat().st_dev, payload_path.stat().st_ino)
    detached = synthetic_store.root / "detached-synthetic-exact-payload"
    payload_path.rename(detached)
    payload_path.write_bytes(body)
    payload_path.chmod(0o600)
    assert (payload_path.stat().st_dev, payload_path.stat().st_ino) != original_identity

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}
    assert payload_path.read_bytes() == body
    assert detached.read_bytes() == body


def test_exact_intent_recovery_never_deletes_wrong_digest_inode_replacement(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch tamper being conflated with a provably incomplete exact artifact."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="b")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-wrong-digest-replacement.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    detached = synthetic_store.root / "detached-wrong-digest-exact-payload"
    payload_path.rename(detached)
    replacement = b"X" * len(body)
    payload_path.write_bytes(replacement)
    payload_path.chmod(0o600)

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}
    assert payload_path.read_bytes() == replacement
    assert detached.read_bytes() == body


def test_exact_intent_recovery_quarantines_in_place_full_length_mutation(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a stable bound inode with unexpected complete bytes being erased."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="c")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-in-place-mutation.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    original_identity = (payload_path.stat().st_dev, payload_path.stat().st_ino)
    replacement = b"Y" * len(body)
    with payload_path.open("r+b", buffering=0) as stream:
        stream.write(replacement)
        os.fsync(stream.fileno())
    assert (payload_path.stat().st_dev, payload_path.stat().st_ino) == original_identity

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}
    assert payload_path.read_bytes() == replacement


@pytest.mark.parametrize(
    "replacement_kind",
    ["same_digest", "wrong_digest", "proper_prefix"],
)
def test_exact_incomplete_rollback_never_unlinks_a_final_path_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Catch the final pathname unlink deleting a same-owner replacement."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="e")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-final-unlink-race.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    prefix = body[: len(body) // 2]
    with payload_path.open("r+b", buffering=0) as stream:
        stream.truncate(len(prefix))
        os.fsync(stream.fileno())
    detached = synthetic_store.root / f"detached-{replacement_kind}-prefix"
    replacement = {
        "same_digest": body,
        "wrong_digest": b"X" * len(body),
        "proper_prefix": b"Y" * len(prefix),
    }[replacement_kind]
    original_unlink = os.unlink
    swapped = False

    def swap_at_final_unlink(
        path: str,
        *args: object,
        dir_fd: int | None = None,
        **kwargs: object,
    ) -> None:
        nonlocal swapped
        if path == payload_path.name and dir_fd is not None:
            swapped = True
            payload_path.rename(detached)
            payload_path.write_bytes(replacement)
            payload_path.chmod(0o600)
        original_unlink(path, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "unlink", swap_at_final_unlink)

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    retained_payloads = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    if swapped:
        assert detached.read_bytes() == prefix
        assert replacement in retained_payloads
    else:
        assert prefix in retained_payloads
    assert tuple(synthetic_store.inbox_staging.glob("*.intent.json"))
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"custody_mismatch"}


@pytest.mark.parametrize(
    "replacement_kind",
    ["same_digest", "wrong_digest", "proper_prefix"],
)
def test_exact_incomplete_quarantine_rename_preserves_a_racing_replacement(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Catch quarantine moving and later deleting an unrelated pathname swap."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="f")
    completed = _crash_exact_staging_subprocess(
        synthetic_store,
        body=body,
        metadata=metadata,
        checkpoint="staging.file_fsync",
        display_name="synthetic-quarantine-rename-race.md",
    )
    assert completed.returncode == 86, completed.stderr
    payload_path = _exact_intent_payload_path(synthetic_store)
    prefix = body[: len(body) // 2]
    with payload_path.open("r+b", buffering=0) as stream:
        stream.truncate(len(prefix))
        os.fsync(stream.fileno())
    detached = synthetic_store.root / f"detached-rename-{replacement_kind}"
    replacement = {
        "same_digest": body,
        "wrong_digest": b"R" * len(body),
        "proper_prefix": b"P" * len(prefix),
    }[replacement_kind]
    original_rename = inbox._rename_no_replace
    swapped = False

    def swap_at_quarantine_rename(
        source_name: str,
        destination_name: str,
        *,
        source_descriptor: int,
        destination_descriptor: int,
    ) -> None:
        nonlocal swapped
        if source_name == payload_path.name and destination_name.startswith(
            ".recovery-"
        ):
            swapped = True
            payload_path.rename(detached)
            payload_path.write_bytes(replacement)
            payload_path.chmod(0o600)
        original_rename(
            source_name,
            destination_name,
            source_descriptor=source_descriptor,
            destination_descriptor=destination_descriptor,
        )

    monkeypatch.setattr(inbox, "_rename_no_replace", swap_at_quarantine_rename)

    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    assert swapped
    assert detached.read_bytes() == prefix
    retained_payloads = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file() and not candidate.name.endswith(".json")
    ]
    assert replacement in retained_payloads
    assert tuple(synthetic_store.inbox_staging.glob("*.intent.json"))
    assert {
        issue.code
        for issue in inbox.list_exact_recovery_issues(
            synthetic_store,
            cursor=None,
            limit=10,
        ).items
    } == {"custody_mismatch"}


def test_exact_custody_classifier_retains_bytes_beside_unresolved_manifest(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch malformed exact state being mistaken for a proven-empty capture."""
    import memory.inbox as inbox

    body, metadata = _exact_owner_payload(synthetic_store, marker="d")
    malformed = synthetic_store.inbox_staging / (f"ent_{'e' * 32}.stage.ready.json")
    malformed.write_text("{synthetic malformed", encoding="utf-8")
    malformed.chmod(0o600)

    assert (
        inbox.exact_capture_custody_outcome(
            synthetic_store,
            display_name="synthetic-unresolved-custody.md",
            byte_length=len(body),
            metadata=metadata,
        )
        == "ambiguous"
    )


@pytest.mark.parametrize(
    "checkpoint",
    [
        "exact.claim_manifest_publication",
        "exact.staged_to_claim_move",
        "exact.database_commit",
        "claim.cleanup.source_unlink",
    ],
)
def test_exact_claim_checkpoint_recovery_returns_the_reserved_result_once(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    """Catch an exact correction being lost, duplicated, or Inbox-published."""
    import memory.inbox as inbox
    from memory.database import open_database
    from memory.keys import load_master_key

    class SyntheticCrash(RuntimeError):
        pass

    body, metadata = _exact_owner_payload(
        synthetic_store,
        marker="5",
        captured_at=2_020_000_001,
    )
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-recoverable-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    unrelated = synthetic_store.inbox / "unrelated-visible-after-crash.txt"
    unrelated.write_bytes(b"Unrelated synthetic queue entry.\n")
    crashed = False

    def crash_once(observed: str) -> None:
        nonlocal crashed
        if observed == checkpoint and not crashed:
            crashed = True
            raise SyntheticCrash(checkpoint)

    monkeypatch.setattr(inbox, "_checkpoint", crash_once)
    with pytest.raises(SyntheticCrash, match=checkpoint):
        inbox.capture_exact_staged_entry(
            synthetic_store,
            entry,
            metadata=metadata,
        )
    assert crashed is True

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert recovered == (
        model.CapturedCorrection(
            capture_request_id=metadata.capture_request_id,
            batch_id=metadata.batch_id,
            source_id=recovered[0].source_id,
            lineage_id=metadata.target_lineage_id,
            expected_head_id=metadata.expected_head_id,
            captured_at=metadata.captured_at,
        ),
    )
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    assert unrelated.read_bytes() == b"Unrelated synthetic queue entry.\n"
    assert list(synthetic_store.inbox_claims.iterdir()) == []
    assert list(synthetic_store.inbox_staging.iterdir()) == []

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        assert connection.execute(
            "SELECT count(*), count(DISTINCT capture_request_id) FROM inbox_batches"
        ).fetchone() == (1, 1)
        assert connection.execute("SELECT count(*) FROM sources").fetchone() == (1,)
    finally:
        connection.close()


def test_generic_scan_never_recovers_an_exact_correction_claim(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch generic Inbox recovery crossing the exact-custody branch."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    class SyntheticCrash(RuntimeError):
        pass

    body = b"Synthetic exact branch remains isolated.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "9" * 32,
        batch_id="bat_" + "a" * 32,
        captured_at=2_020_000_002,
        target_lineage_id="lin_" + "b" * 32,
        expected_head_id="mem_" + "c" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-isolated-claim.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def crash_after_move(observed: str) -> None:
        if observed == "exact.staged_to_claim_move":
            raise SyntheticCrash(observed)

    monkeypatch.setattr(inbox, "_checkpoint", crash_after_move)
    with pytest.raises(SyntheticCrash):
        inbox.capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)

    ordinary = synthetic_store.inbox / "ordinary-synthetic.txt"
    ordinary.write_bytes(b"Ordinary synthetic queue entry.\n")
    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    ordinary_batch = inbox.scan_inbox(
        synthetic_store,
        clock=FrozenClock(),
        policy=inbox.ScanPolicy(settle_seconds=0),
    )
    ordinary_detail = read_batch(synthetic_store, ordinary_batch.batch_id)
    assert ordinary_detail.sources[0].origin is SourceCaptureOrigin.INBOX
    assert ordinary_detail.sources[0].original_name == ordinary.name

    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert len(recovered) == 1
    exact_detail = read_batch(synthetic_store, recovered[0].batch_id)
    assert exact_detail.sources[0].origin is SourceCaptureOrigin.OWNER_CORRECTION


@pytest.mark.parametrize(
    "checkpoint",
    [
        "exact.ready_manifest_file_fsync",
        "exact.ready_manifest_publish",
        "exact.ready_manifest_directory_fsync",
    ],
)
def test_exact_ready_publication_crash_is_recovered_at_startup(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: str,
) -> None:
    """Catch a durable ready manifest being detached from its exact bytes."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    class SyntheticCrash(RuntimeError):
        pass

    body = b"Synthetic ready manifest retry bytes.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "d" * 32,
        batch_id="bat_" + "e" * 32,
        captured_at=2_020_000_003,
        target_lineage_id="lin_" + "1" * 32,
        expected_head_id="mem_" + "2" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    crashed = False

    def crash_once(observed: str) -> None:
        nonlocal crashed
        if observed == checkpoint and not crashed:
            crashed = True
            raise SyntheticCrash(checkpoint)

    monkeypatch.setattr(inbox, "_checkpoint", crash_once)
    with pytest.raises(SyntheticCrash, match=checkpoint):
        inbox.stage_exact_private_entry(
            synthetic_store,
            display_name="synthetic-ready-retry.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
    assert crashed is True

    monkeypatch.setattr(inbox, "_checkpoint", lambda _name: None)
    recovered = inbox.recover_exact_staged_entries(synthetic_store)
    assert recovered == (
        model.CapturedCorrection(
            capture_request_id=metadata.capture_request_id,
            batch_id=metadata.batch_id,
            source_id=recovered[0].source_id,
            lineage_id=metadata.target_lineage_id,
            expected_head_id=metadata.expected_head_id,
            captured_at=metadata.captured_at,
        ),
    )
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()
    assert list(synthetic_store.inbox_staging.iterdir()) == []


def test_recovery_issue_listing_treats_valid_claim_custody_as_recoverable(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report only content-free quarantine state, not a healthy moved claim."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    class SyntheticCrash(RuntimeError):
        pass

    body = b"Synthetic custody issue fixture.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "3" * 32,
        batch_id="bat_" + "4" * 32,
        captured_at=2_020_000_004,
        target_lineage_id="lin_" + "5" * 32,
        expected_head_id="mem_" + "6" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-healthy-claim.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    def crash_after_move(observed: str) -> None:
        if observed == "exact.staged_to_claim_move":
            raise SyntheticCrash(observed)

    monkeypatch.setattr(inbox, "_checkpoint", crash_after_move)
    with pytest.raises(SyntheticCrash):
        inbox.capture_exact_staged_entry(synthetic_store, entry, metadata=metadata)

    healthy = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert healthy.items == ()

    malformed_name = "private-owner-words.ready.json"
    malformed = synthetic_store.inbox_staging / malformed_name
    malformed.write_text(
        "private owner contents must not be surfaced", encoding="utf-8"
    )
    malformed.chmod(0o600)
    page = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert len(page.items) == 1
    issue = page.items[0]
    assert issue.code == "malformed_manifest"
    assert issue.issue_id.startswith("cri_")
    assert malformed_name not in repr(issue)
    assert "private owner contents" not in repr(issue)


def test_malformed_exact_manifest_is_quarantined_without_replacement(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch malformed reserved custody being ignored by a new exact capture."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    malformed_entry_id = "ent_" + "1" * 32 + ".stage"
    malformed = synthetic_store.inbox_staging / (malformed_entry_id + ".ready.json")
    malformed.write_text("{synthetic malformed", encoding="utf-8")
    malformed.chmod(0o600)
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert len(issues.items) == 1
    assert issues.items[0].code == "malformed_manifest"

    body = b"Synthetic replacement must remain blocked.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "2" * 32,
        batch_id="bat_" + "3" * 32,
        captured_at=2_020_000_007,
        target_lineage_id="lin_" + "4" * 32,
        expected_head_id="mem_" + "5" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    with pytest.raises(InvalidArgumentError, match="quarantined"):
        inbox.stage_exact_private_entry(
            synthetic_store,
            display_name="synthetic-blocked-replacement.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
    assert {path.name for path in synthetic_store.inbox_staging.iterdir()} == {
        malformed.name
    }


def test_duplicate_exact_ready_reservations_are_quarantined_as_ambiguous(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch one duplicate reservation being selected and silently published."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    body = b"Synthetic ambiguous exact reservation.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "7" * 32,
        batch_id="bat_" + "8" * 32,
        captured_at=2_020_000_005,
        target_lineage_id="lin_" + "9" * 32,
        expected_head_id="mem_" + "a" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    original = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-ambiguous.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    duplicate_id = "ent_" + "f" * 32 + ".stage"
    duplicate = synthetic_store.inbox_staging / duplicate_id
    duplicate.write_bytes(body)
    duplicate.chmod(0o600)
    ready = json.loads(
        (synthetic_store.inbox_staging / f"{original.entry_id}.ready.json").read_text(
            encoding="utf-8"
        )
    )
    ready["entry_id"] = duplicate_id
    duplicate_ready = synthetic_store.inbox_staging / f"{duplicate_id}.ready.json"
    duplicate_ready.write_text(
        json.dumps(ready, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    duplicate_ready.chmod(0o600)

    with pytest.raises(InvalidArgumentError, match="ambiguous"):
        inbox.stage_exact_private_entry(
            synthetic_store,
            display_name="synthetic-ambiguous.md",
            chunks=(body,),
            max_bytes=len(body),
            metadata=metadata,
        )
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert {issue.code for issue in issues.items} == {"ambiguous_claim"}
    assert inbox.recover_exact_staged_entries(synthetic_store) == ()


def test_launch_recovery_propagates_writer_contention_instead_of_skipping_ready(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch UI startup proceeding while a valid exact reservation stays pending."""
    import memory.inbox as inbox
    from memory.ui.capture import ExactCaptureMetadata

    body = b"Synthetic busy launch recovery.\n"
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "b" * 32,
        batch_id="bat_" + "c" * 32,
        captured_at=2_020_000_006,
        target_lineage_id="lin_" + "d" * 32,
        expected_head_id="mem_" + "e" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    inbox.stage_exact_private_entry(
        synthetic_store,
        display_name="synthetic-busy-recovery.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    monkeypatch.setattr(
        inbox,
        "capture_exact_staged_entry",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            StoreBusyError("synthetic writer contention")
        ),
    )

    with pytest.raises(StoreBusyError):
        inbox.recover_exact_staged_entries(synthetic_store)


def test_session_correction_intents_are_target_bound_replayable_and_bounded() -> None:
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionSubmissionLease,
        PreparedOwnerCorrection,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = PreparedOwnerCorrection(
        selected_memory_id="mem_" + "1" * 32,
        lineage_id="lin_" + "2" * 32,
        expected_head_id="mem_" + "3" * 32,
        captured_at=2_020_000_000,
        owner_text_offset=5,
        owner_text_sha256=hashlib.sha256(b"text").hexdigest(),
        source_bytes=b"head\ntext",
        source_sha256=hashlib.sha256(b"head\ntext").hexdigest(),
    )
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    assert len(base64.urlsafe_b64decode(binding.form_nonce + "==")) >= 16
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    result = CapturedCorrection(
        capture_request_id=lease.capture_request_id,
        batch_id=lease.reserved_batch_id,
        source_id="src_" + "4" * 32,
        lineage_id=prepared.lineage_id,
        expected_head_id=prepared.expected_head_id,
        captured_at=prepared.captured_at,
    )
    sessions.complete_correction_form(lease, result, now_ns=202)
    replay = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=202,
    )
    assert replay == result

    for index in range(7):
        sessions.issue_correction_form(
            session_id,
            f"mem_{index + 10:032x}",
            now_ns=203 + index,
        )
    with pytest.raises(InvalidArgumentError):
        sessions.issue_correction_form(
            session_id,
            "mem_" + "f" * 32,
            now_ns=220,
        )


@pytest.mark.parametrize("status_requested", [False, True])
def test_completed_correction_retains_only_a_requested_content_free_status(
    status_requested: bool,
) -> None:
    """Keep global terminal capacity for a follower that can still read it."""
    from memory.ui.auth import (
        CORRECTION_STATUS_TTL_NS,
        UiSessionStore,
    )
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionInProgressView,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    if status_requested:
        assert isinstance(
            sessions.resolve_correction_status(
                session_id,
                binding.form_nonce,
                now_ns=202,
            ),
            CorrectionInProgressView,
        )
    result = CapturedCorrection(
        capture_request_id=lease.capture_request_id,
        batch_id=lease.reserved_batch_id,
        source_id="src_" + "4" * 32,
        lineage_id=prepared.lineage_id,
        expected_head_id=prepared.expected_head_id,
        captured_at=prepared.captured_at,
    )
    sessions.complete_correction_form(lease, result, now_ns=203)

    assert len(sessions._orphaned_corrections) == int(status_requested)
    resolved = sessions.resolve_correction_status(
        session_id,
        binding.form_nonce,
        now_ns=203,
    )
    assert resolved == (result if status_requested else None)
    # Reading is idempotent and releases no capacity; only the status lifetime,
    # session invalidation, or shutdown may retire a retained result.
    assert sessions.resolve_correction_status(
        session_id,
        binding.form_nonce,
        now_ns=204,
    ) == (result if status_requested else None)
    assert len(sessions._orphaned_corrections) == int(status_requested)
    assert (
        sessions.resolve_correction_status(
            session_id,
            binding.form_nonce,
            now_ns=203 + CORRECTION_STATUS_TTL_NS,
        )
        is None
    )
    assert sessions._orphaned_corrections == {}


def test_correction_lease_rejects_cross_session_target_payload_and_expiry() -> None:
    """Catch a nonce becoming transferable, retargetable, mutable, or refreshable."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CORRECTION_FORM_TTL_NS, CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )

    other_sessions, other_session_id = _session_store()
    assert isinstance(other_sessions, UiSessionStore)
    with pytest.raises(InvalidArgumentError, match="unavailable"):
        other_sessions.lease_correction_form(
            other_session_id,
            binding.form_nonce,
            prepared.selected_memory_id,
            prepared,
            now_ns=201,
        )
    with pytest.raises(InvalidArgumentError, match="unavailable"):
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            "mem_" + "4" * 32,
            prepared,
            now_ns=201,
        )
    altered = _prepared_correction(b"altered")
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    with pytest.raises(InvalidArgumentError, match="already leased"):
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            prepared.selected_memory_id,
            altered,
            now_ns=202,
        )
    assert isinstance(lease, CorrectionSubmissionLease)
    assert lease.prepared.source_bytes == prepared.source_bytes

    expired = sessions.issue_correction_form(
        session_id,
        "mem_" + "5" * 32,
        now_ns=300,
    )
    assert (
        sessions.resolve_correction_form(
            session_id,
            expired.form_nonce,
            now_ns=300 + CORRECTION_FORM_TTL_NS,
        )
        is None
    )


def test_simultaneous_duplicate_correction_submit_has_one_exact_lease() -> None:
    """Catch a follower receiving custody instead of the owner's terminal result."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    owner = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(owner, CorrectionSubmissionLease)
    entered = threading.Event()
    results: list[object] = []

    def follow() -> None:
        entered.set()
        try:
            results.append(
                sessions.lease_correction_form(
                    session_id,
                    binding.form_nonce,
                    prepared.selected_memory_id,
                    prepared,
                    now_ns=201,
                )
            )
        except BaseException as error:
            results.append(error)

    follower = threading.Thread(target=follow)
    follower.start()
    assert entered.wait(timeout=10)
    assert follower.is_alive()
    captured = CapturedCorrection(
        capture_request_id=owner.capture_request_id,
        batch_id=owner.reserved_batch_id,
        source_id="src_" + "4" * 32,
        lineage_id=prepared.lineage_id,
        expected_head_id=prepared.expected_head_id,
        captured_at=prepared.captured_at,
    )
    sessions.complete_correction_form(owner, captured, now_ns=202)
    follower.join(timeout=10)
    assert not follower.is_alive()
    assert results == [captured]


@pytest.mark.parametrize("transition", ["retryable", "shutdown"])
def test_duplicate_correction_follower_wakes_on_non_success_terminal_transition(
    transition: str,
) -> None:
    """Catch retry or shutdown leaving a duplicate submit worker blocked forever."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    owner = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(owner, CorrectionSubmissionLease)
    entered = threading.Event()
    results: list[object] = []

    def follow() -> None:
        entered.set()
        try:
            results.append(
                sessions.lease_correction_form(
                    session_id,
                    binding.form_nonce,
                    prepared.selected_memory_id,
                    prepared,
                    now_ns=202,
                )
            )
        except BaseException as error:
            results.append(error)

    follower = threading.Thread(target=follow)
    follower.start()
    assert entered.wait(timeout=10)
    assert follower.is_alive()
    if transition == "retryable":
        sessions.mark_correction_retryable(owner)
        expected_error: type[BaseException] = StoreBusyError
    else:
        sessions.invalidate_all()
        expected_error = InvalidArgumentError
    follower.join(timeout=10)
    assert not follower.is_alive()
    assert len(results) == 1 and isinstance(results[0], expected_error)


def test_proven_empty_correction_failure_wakes_a_real_duplicate_waiter() -> None:
    """A removed lease must change phase before its waiting follower is notified."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    # The follower's own deadline is the thing the wake has to beat, so it is
    # set wide and the bound is drawn against it with real headroom rather than
    # against a literal a loaded machine can miss.
    follower_deadline_seconds = 10.0
    sessions._correction_wait_timeout_seconds = follower_deadline_seconds
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    owner = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(owner, CorrectionSubmissionLease)
    entered = threading.Event()
    results: list[object] = []

    def follow() -> None:
        entered.set()
        try:
            results.append(
                sessions.lease_correction_form(
                    session_id,
                    binding.form_nonce,
                    prepared.selected_memory_id,
                    prepared,
                    now_ns=202,
                )
            )
        except BaseException as error:
            results.append(error)

    follower = threading.Thread(target=follow)
    follower.start()
    assert entered.wait(timeout=10)
    assert follower.is_alive()
    # Woken by the owner's failure, not released by its own deadline.
    started = time.monotonic()
    sessions.consume_proven_empty_correction_failure(owner)
    follower.join(timeout=follower_deadline_seconds)

    assert not follower.is_alive()
    assert time.monotonic() - started < follower_deadline_seconds / 2
    assert len(results) == 1 and isinstance(results[0], InvalidArgumentError)


def test_duplicate_correction_follower_has_a_bounded_spurious_wakeup_safe_deadline() -> (
    None
):
    """Catch an owner that never returns blocking every matching follower forever."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    sessions._correction_wait_timeout_seconds = 0.05
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    owner = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(owner, CorrectionSubmissionLease)
    results: list[object] = []

    def follow() -> None:
        try:
            results.append(
                sessions.lease_correction_form(
                    session_id,
                    binding.form_nonce,
                    prepared.selected_memory_id,
                    prepared,
                    now_ns=202,
                )
            )
        except BaseException as error:
            results.append(error)

    follower = threading.Thread(target=follow)
    follower.start()
    follower.join(timeout=0.5)
    returned_before_cleanup = not follower.is_alive()
    if follower.is_alive():
        sessions.mark_correction_retryable(owner)
        follower.join(timeout=10)
    assert returned_before_cleanup
    assert len(results) == 1 and isinstance(results[0], StoreBusyError)


@pytest.mark.parametrize("transition", ["expiry", "logout", "shutdown"])
@pytest.mark.parametrize("custody_outcome", ["proven_empty", "durable"])
def test_revoked_correction_terminal_failure_reclaims_bytes_and_notifies_followers(
    transition: str,
    custody_outcome: str,
) -> None:
    """Catch revoked source bytes becoming inaccessible permanent orphans."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)

    if transition == "expiry":
        assert (
            sessions.resolve_correction_form(
                session_id,
                binding.form_nonce,
                now_ns=200 + CORRECTION_FORM_TTL_NS,
            )
            is None
        )
    elif transition == "logout":
        sessions.invalidate_session(session_id)
    else:
        sessions.invalidate_all()

    sessions.mark_correction_retryable(
        lease,
        custody_outcome=custody_outcome,
    )
    # A terminal record keeps only the size of the buffer it released, so a
    # surviving orphan still has to show up in the retained total.
    retained = sum(
        record.byte_length for record in sessions._orphaned_corrections.values()
    ) + sum(
        len(record.prepared.source_bytes)
        for session in sessions._sessions.values()
        for record in session.corrections.values()
        if record.prepared is not None
    )
    assert retained == 0
    assert sessions._orphaned_corrections == {}


def test_correction_capacity_reclaims_only_terminal_expired_intents() -> None:
    """Catch capacity eviction of live custody or retention after safe expiry."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CapturedCorrection,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    bindings = tuple(
        sessions.issue_correction_form(
            session_id,
            f"mem_{index + 1:032x}",
            now_ns=200,
        )
        for index in range(8)
    )
    in_flight = sessions.lease_correction_form(
        session_id,
        bindings[0].form_nonce,
        bindings[0].selected_memory_id,
        _prepared_correction(selected_memory_id=bindings[0].selected_memory_id),
        now_ns=201,
    )
    assert isinstance(in_flight, CorrectionSubmissionLease)
    completed_lease = sessions.lease_correction_form(
        session_id,
        bindings[1].form_nonce,
        bindings[1].selected_memory_id,
        _prepared_correction(selected_memory_id=bindings[1].selected_memory_id),
        now_ns=201,
    )
    assert isinstance(completed_lease, CorrectionSubmissionLease)
    sessions.complete_correction_form(
        completed_lease,
        CapturedCorrection(
            capture_request_id=completed_lease.capture_request_id,
            batch_id=completed_lease.reserved_batch_id,
            source_id="src_" + "4" * 32,
            lineage_id=completed_lease.prepared.lineage_id,
            expected_head_id=completed_lease.prepared.expected_head_id,
            captured_at=completed_lease.prepared.captured_at,
        ),
        now_ns=202,
    )

    with pytest.raises(InvalidArgumentError, match="capacity"):
        sessions.issue_correction_form(
            session_id,
            "mem_" + "f" * 32,
            now_ns=202,
        )

    replacement = sessions.issue_correction_form(
        session_id,
        "mem_" + "f" * 32,
        now_ns=200 + CORRECTION_FORM_TTL_NS,
    )
    assert replacement.selected_memory_id == "mem_" + "f" * 32
    assert (
        sessions.resolve_correction_form(
            session_id,
            bindings[0].form_nonce,
            now_ns=200 + CORRECTION_FORM_TTL_NS,
        )
        is None
    )
    sessions.complete_correction_form(
        in_flight,
        CapturedCorrection(
            capture_request_id=in_flight.capture_request_id,
            batch_id=in_flight.reserved_batch_id,
            source_id="src_" + "5" * 32,
            lineage_id=in_flight.prepared.lineage_id,
            expected_head_id=in_flight.prepared.expected_head_id,
            captured_at=in_flight.prepared.captured_at,
        ),
        now_ns=201 + CORRECTION_FORM_TTL_NS,
    )


def test_expired_unrequested_successes_release_global_terminal_capacity() -> None:
    """Do not retain completed status nobody requested after active expiry."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CapturedCorrection,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    leases: list[CorrectionSubmissionLease] = []
    for index in range(8):
        selected_memory_id = f"mem_{index + 1:032x}"
        issued_at = 200 + index * 2
        binding = sessions.issue_correction_form(
            session_id,
            selected_memory_id,
            now_ns=issued_at,
        )
        lease = sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            selected_memory_id,
            _prepared_correction(selected_memory_id=selected_memory_id),
            now_ns=issued_at + 1,
        )
        assert isinstance(lease, CorrectionSubmissionLease)
        leases.append(lease)

    ninth_binding = sessions.issue_correction_form(
        session_id,
        "mem_" + "f" * 32,
        now_ns=216 + CORRECTION_FORM_TTL_NS,
    )
    for index, lease in enumerate(leases):
        sessions.complete_correction_form(
            lease,
            CapturedCorrection(
                capture_request_id=lease.capture_request_id,
                batch_id=lease.reserved_batch_id,
                source_id=f"src_{index + 1:032x}",
                lineage_id=lease.prepared.lineage_id,
                expected_head_id=lease.prepared.expected_head_id,
                captured_at=lease.prepared.captured_at,
            ),
            now_ns=216 + CORRECTION_FORM_TTL_NS,
        )

    assert sessions._orphaned_corrections == {}
    ninth = sessions.lease_correction_form(
        session_id,
        ninth_binding.form_nonce,
        ninth_binding.selected_memory_id,
        _prepared_correction(selected_memory_id=ninth_binding.selected_memory_id),
        now_ns=217 + CORRECTION_FORM_TTL_NS,
    )
    assert isinstance(ninth, CorrectionSubmissionLease)


def test_abandoned_requested_successes_expire_and_release_terminal_capacity() -> None:
    """Completed one-shot status results have a completion-relative lifetime."""
    from memory.ui.auth import (
        CORRECTION_STATUS_TTL_NS,
        UiSessionStore,
    )
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CapturedCorrection,
        CorrectionInProgressView,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    completed_at_ns = 300
    bindings = tuple(
        sessions.issue_correction_form(
            session_id,
            f"mem_{index + 1:032x}",
            now_ns=200,
        )
        for index in range(8)
    )
    leases = tuple(
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            binding.selected_memory_id,
            _prepared_correction(selected_memory_id=binding.selected_memory_id),
            now_ns=201,
        )
        for binding in bindings
    )
    assert all(isinstance(lease, CorrectionSubmissionLease) for lease in leases)
    for index, (binding, lease) in enumerate(zip(bindings, leases, strict=True)):
        assert isinstance(lease, CorrectionSubmissionLease)
        assert isinstance(
            sessions.resolve_correction_status(
                session_id,
                binding.form_nonce,
                now_ns=202,
            ),
            CorrectionInProgressView,
        )
        sessions.complete_correction_form(
            lease,
            CapturedCorrection(
                capture_request_id=lease.capture_request_id,
                batch_id=lease.reserved_batch_id,
                source_id=f"src_{index + 1:032x}",
                lineage_id=lease.prepared.lineage_id,
                expected_head_id=lease.prepared.expected_head_id,
                captured_at=lease.prepared.captured_at,
            ),
            now_ns=completed_at_ns,
        )

    ninth_binding = sessions.issue_correction_form(
        session_id,
        "mem_" + "f" * 32,
        now_ns=200 + CORRECTION_FORM_TTL_NS,
    )
    ninth_prepared = _prepared_correction(
        selected_memory_id=ninth_binding.selected_memory_id,
    )
    with pytest.raises(InvalidArgumentError, match="capacity"):
        sessions.lease_correction_form(
            session_id,
            ninth_binding.form_nonce,
            ninth_binding.selected_memory_id,
            ninth_prepared,
            now_ns=completed_at_ns + CORRECTION_STATUS_TTL_NS - 1,
        )

    ninth = sessions.lease_correction_form(
        session_id,
        ninth_binding.form_nonce,
        ninth_binding.selected_memory_id,
        ninth_prepared,
        now_ns=completed_at_ns + CORRECTION_STATUS_TTL_NS,
    )
    assert isinstance(ninth, CorrectionSubmissionLease)
    assert sessions._orphaned_corrections == {}


def test_correction_status_read_never_frees_write_authority_capacity() -> None:
    """A read-only status resolve must not unblock a capacity-refused lease."""
    from memory.ui.auth import (
        CORRECTION_STATUS_TTL_NS,
        UiSessionStore,
    )
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CapturedCorrection,
        CorrectionInProgressView,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    completed_at_ns = 300
    bindings = tuple(
        sessions.issue_correction_form(
            session_id,
            f"mem_{index + 1:032x}",
            now_ns=200,
        )
        for index in range(8)
    )
    leases = tuple(
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            binding.selected_memory_id,
            _prepared_correction(selected_memory_id=binding.selected_memory_id),
            now_ns=201,
        )
        for binding in bindings
    )
    for index, (binding, lease) in enumerate(zip(bindings, leases, strict=True)):
        assert isinstance(lease, CorrectionSubmissionLease)
        assert isinstance(
            sessions.resolve_correction_status(
                session_id,
                binding.form_nonce,
                now_ns=202,
            ),
            CorrectionInProgressView,
        )
        sessions.complete_correction_form(
            lease,
            CapturedCorrection(
                capture_request_id=lease.capture_request_id,
                batch_id=lease.reserved_batch_id,
                source_id=f"src_{index + 1:032x}",
                lineage_id=lease.prepared.lineage_id,
                expected_head_id=lease.prepared.expected_head_id,
                captured_at=lease.prepared.captured_at,
            ),
            now_ns=completed_at_ns,
        )
    assert len(sessions._orphaned_corrections) == 8

    first = sessions.resolve_correction_status(
        session_id,
        bindings[0].form_nonce,
        now_ns=completed_at_ns + 1,
    )
    second = sessions.resolve_correction_status(
        session_id,
        bindings[0].form_nonce,
        now_ns=completed_at_ns + 2,
    )
    assert isinstance(first, CapturedCorrection)
    assert second == first
    assert len(sessions._orphaned_corrections) == 8

    ninth_binding = sessions.issue_correction_form(
        session_id,
        "mem_" + "f" * 32,
        now_ns=200 + CORRECTION_FORM_TTL_NS,
    )
    with pytest.raises(InvalidArgumentError, match="capacity"):
        sessions.lease_correction_form(
            session_id,
            ninth_binding.form_nonce,
            ninth_binding.selected_memory_id,
            _prepared_correction(
                selected_memory_id=ninth_binding.selected_memory_id,
            ),
            now_ns=completed_at_ns + CORRECTION_STATUS_TTL_NS - 1,
        )
    released = sessions.lease_correction_form(
        session_id,
        ninth_binding.form_nonce,
        ninth_binding.selected_memory_id,
        _prepared_correction(selected_memory_id=ninth_binding.selected_memory_id),
        now_ns=completed_at_ns + CORRECTION_STATUS_TTL_NS,
    )
    assert isinstance(released, CorrectionSubmissionLease)


@pytest.mark.parametrize("ordering", ["completion_first", "expiry_first"])
def test_revoke_reconciles_a_completed_status_terminal_and_active_mirror(
    ordering: str,
) -> None:
    """A completed capture cannot retain status authority after explicit revoke."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        CapturedCorrection,
        CorrectionInProgressView,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    assert isinstance(
        sessions.resolve_correction_status(
            session_id,
            binding.form_nonce,
            now_ns=202,
        ),
        CorrectionInProgressView,
    )
    if ordering == "expiry_first":
        assert (
            sessions.resolve_correction_form(
                session_id,
                binding.form_nonce,
                now_ns=200 + CORRECTION_FORM_TTL_NS,
            )
            is None
        )
    captured = CapturedCorrection(
        capture_request_id=lease.capture_request_id,
        batch_id=lease.reserved_batch_id,
        source_id="src_" + "4" * 32,
        lineage_id=lease.prepared.lineage_id,
        expected_head_id=lease.prepared.expected_head_id,
        captured_at=lease.prepared.captured_at,
    )
    sessions.complete_correction_form(
        lease,
        captured,
        now_ns=203 + (CORRECTION_FORM_TTL_NS if ordering == "expiry_first" else 0),
    )

    revoked = sessions.revoke_in_flight_correction(lease)

    assert revoked.state == "revoked"
    assert sessions._orphaned_corrections == {}
    assert (
        sessions.resolve_correction_status(
            session_id,
            binding.form_nonce,
            now_ns=204 + (CORRECTION_FORM_TTL_NS if ordering == "expiry_first" else 0),
        )
        is None
    )
    with pytest.raises(InvalidArgumentError, match="unavailable"):
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            prepared.selected_memory_id,
            prepared,
            now_ns=205 + (CORRECTION_FORM_TTL_NS if ordering == "expiry_first" else 0),
        )


def test_correction_session_retains_exact_eight_mib_and_rejects_cap_plus_one() -> None:
    """Pin aggregate canonical-buffer accounting without duplicate owner strings."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        MAX_CORRECTION_SESSION_RETAINED_BYTES,
        MAX_OWNER_CORRECTION_SOURCE_BYTES,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    bindings = tuple(
        sessions.issue_correction_form(
            session_id,
            f"mem_{index + 1:032x}",
            now_ns=200,
        )
        for index in range(8)
    )
    for index, binding in enumerate(bindings):
        selected = f"mem_{index + 1:032x}"
        prepared = _prepared_correction(
            b"x" * (MAX_OWNER_CORRECTION_SOURCE_BYTES - 1),
            selected_memory_id=selected,
            prefix=b"h",
        )
        sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            selected,
            prepared,
            now_ns=201,
        )
    record = sessions._sessions[session_id]
    assert sessions._retained_correction_bytes(record) == (
        MAX_CORRECTION_SESSION_RETAINED_BYTES
    )

    oversized_sessions, oversized_session_id = _session_store()
    assert isinstance(oversized_sessions, UiSessionStore)
    selected = "mem_" + "e" * 32
    oversized = _prepared_correction(
        b"x" * MAX_OWNER_CORRECTION_SOURCE_BYTES,
        selected_memory_id=selected,
        prefix=b"h",
    )
    binding = oversized_sessions.issue_correction_form(
        oversized_session_id,
        selected,
        now_ns=200,
    )
    with pytest.raises(InvalidArgumentError, match="size"):
        oversized_sessions.lease_correction_form(
            oversized_session_id,
            binding.form_nonce,
            selected,
            oversized,
            now_ns=201,
        )


@pytest.mark.parametrize("invalidate_all", [False, True])
def test_session_invalidation_erases_terminal_state_but_orphans_in_flight(
    invalidate_all: bool,
) -> None:
    """Keep a bounded terminal identity while the active lease owns its bytes."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    pending = sessions.issue_correction_form(
        session_id,
        "mem_" + "4" * 32,
        now_ns=200,
    )
    retry_binding = sessions.issue_correction_form(
        session_id,
        "mem_" + "5" * 32,
        now_ns=200,
    )
    flight_binding = sessions.issue_correction_form(
        session_id,
        "mem_" + "6" * 32,
        now_ns=200,
    )
    retry_lease = sessions.lease_correction_form(
        session_id,
        retry_binding.form_nonce,
        retry_binding.selected_memory_id,
        _prepared_correction(selected_memory_id=retry_binding.selected_memory_id),
        now_ns=201,
    )
    assert isinstance(retry_lease, CorrectionSubmissionLease)
    sessions.mark_correction_retryable(retry_lease)
    flight_lease = sessions.lease_correction_form(
        session_id,
        flight_binding.form_nonce,
        flight_binding.selected_memory_id,
        _prepared_correction(selected_memory_id=flight_binding.selected_memory_id),
        now_ns=201,
    )
    assert isinstance(flight_lease, CorrectionSubmissionLease)

    if invalidate_all:
        sessions.invalidate_all()
    else:
        sessions.invalidate_session(session_id)

    assert sessions.active_session_count == 0
    assert sessions._sessions == {}
    assert len(sessions._orphaned_corrections) == 1
    orphan = sessions._orphaned_corrections[flight_lease.lease_id]
    assert orphan.phase == "revoked"
    assert not hasattr(orphan, "prepared")
    assert not hasattr(orphan, "lease")
    assert orphan.capture_request_id == flight_lease.capture_request_id
    assert orphan.reserved_batch_id == flight_lease.reserved_batch_id
    assert flight_lease.prepared.source_bytes
    assert pending.form_nonce not in repr(sessions._orphaned_corrections)
    assert retry_lease.lease_id not in sessions._orphaned_corrections


@pytest.mark.parametrize("transition", ["expiry", "logout", "shutdown"])
def test_revoked_correction_handoff_is_globally_bounded_and_content_free(
    transition: str,
) -> None:
    """Catch eight revoked maximum buffers becoming an unbounded byte orphanage."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CORRECTION_FORM_TTL_NS,
        MAX_OWNER_CORRECTION_SOURCE_BYTES,
        CorrectionSubmissionLease,
    )

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    leases: list[CorrectionSubmissionLease] = []
    for index in range(8):
        selected = f"mem_{index + 1:032x}"
        issued_at = 200 + (index * 2)
        binding = sessions.issue_correction_form(
            session_id,
            selected,
            now_ns=issued_at,
        )
        prepared = _prepared_correction(
            b"z" * (MAX_OWNER_CORRECTION_SOURCE_BYTES - 1),
            selected_memory_id=selected,
            prefix=b"h",
        )
        lease = sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            selected,
            prepared,
            now_ns=issued_at + 1,
        )
        assert isinstance(lease, CorrectionSubmissionLease)
        leases.append(lease)

    if transition == "expiry":
        assert (
            sessions.resolve_correction_form(
                session_id,
                leases[0].binding.form_nonce,
                now_ns=220 + CORRECTION_FORM_TTL_NS,
            )
            is None
        )
    elif transition == "logout":
        sessions.invalidate_session(session_id)
    else:
        sessions.invalidate_all()

    assert len(sessions._orphaned_corrections) == 8
    assert all(
        getattr(record, "prepared", None) is None
        and getattr(record, "lease", None) is None
        for record in sessions._orphaned_corrections.values()
    )
    assert (
        sum(
            len(record.prepared.source_bytes)
            for session_record in sessions._sessions.values()
            for record in session_record.corrections.values()
            if record.prepared is not None
        )
        == 0
    )

    for lease in leases:
        sessions.mark_correction_retryable(lease, custody_outcome="ambiguous")
    assert len(sessions._orphaned_corrections) == 8
    for index, lease in enumerate(leases):
        sessions.mark_correction_retryable(
            lease,
            custody_outcome="durable" if index % 2 else "proven_empty",
        )
    assert sessions._orphaned_corrections == {}

    sessions.invalidate_all()
    assert sessions._sessions == {}
    assert sessions._orphaned_corrections == {}


def test_proven_empty_failure_erases_the_only_in_flight_buffer() -> None:
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease

    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    prepared = _prepared_correction()
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    sessions.consume_proven_empty_correction_failure(lease)
    assert (
        sessions.resolve_correction_form(
            session_id,
            binding.form_nonce,
            now_ns=202,
        )
        is None
    )


@pytest.mark.parametrize("shutdown", [False, True])
def test_in_flight_correction_survives_invalidation_at_every_custody_checkpoint(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    shutdown: bool,
) -> None:
    """Pin active-lease custody through every durable exact-capture boundary."""
    import memory.inbox as inbox
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    checkpoints = (
        "exact.intent_manifest_file_fsync",
        "exact.intent_manifest_publish",
        "exact.intent_manifest_directory_fsync",
        "staging.file_fsync",
        "staging.directory_fsync",
        "exact.ready_manifest_file_fsync",
        "exact.ready_manifest_publish",
        "exact.ready_manifest_directory_fsync",
        "exact.intent_cleanup_directory_fsync",
        "exact.claim_temp_mkdir",
        "exact.claim.manifest_file_fsync",
        "exact.claim.manifest_replace",
        "exact.claim.manifest_dir_fsync",
        "claim.create.publish_rename",
        "claim.create.publish_dir_fsync",
        "exact.claim_manifest_publication",
        "exact.staged_to_claim_move",
        "exact.claim_files_directory_fsync",
        "exact.custody.manifest_file_fsync",
        "exact.custody.manifest_replace",
        "exact.custody.manifest_dir_fsync",
        "exact.database_commit",
        "claim.cleanup.hide_rename",
        "claim.cleanup.claims_dir_fsync",
        "claim.cleanup.source_unlink",
        "claim.cleanup.files_dir_fsync",
        "claim.cleanup.files_rmdir",
        "claim.cleanup.claim_dir_fsync_after_files",
        "claim.cleanup.manifest_unlink",
        "claim.cleanup.claim_dir_fsync_after_manifest",
        "exact.cleanup_directory_fsync",
    )
    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)

    # One checkpoint per call: the invalidating hook closes over that
    # iteration's session and lease, and a closure built in the loop body would
    # be reading whichever iteration happened to run last.
    def invalidate_one_checkpoint(index: int, target: str) -> None:
        sessions, session_id = _session_store()
        assert isinstance(sessions, UiSessionStore)
        prepared = service.prepare_owner_correction(
            memory_id,
            f"Synthetic checkpoint correction {index}.",
            clock=FrozenClock(2_020_001_000.0 + index),
        )
        binding = sessions.issue_correction_form(
            session_id,
            memory_id,
            now_ns=200,
        )
        lease = sessions.lease_correction_form(
            session_id,
            binding.form_nonce,
            memory_id,
            prepared,
            now_ns=201,
        )
        assert isinstance(lease, CorrectionSubmissionLease)
        observed_target = False

        def invalidate_at_checkpoint(observed: str) -> None:
            nonlocal observed_target
            if observed != target or observed_target:
                return
            observed_target = True
            if shutdown:
                sessions.invalidate_all()
            else:
                sessions.invalidate_session(session_id)
            orphan = sessions._orphaned_corrections[lease.lease_id]
            assert not hasattr(orphan, "prepared")
            assert not hasattr(orphan, "lease")
            assert orphan.capture_request_id == lease.capture_request_id
            assert orphan.reserved_batch_id == lease.reserved_batch_id
            assert lease.prepared.source_bytes == prepared.source_bytes

        monkeypatch.setattr(inbox, "_checkpoint", invalidate_at_checkpoint)
        captured = service.capture_owner_correction(lease)
        assert observed_target is True, target
        sessions.complete_correction_form(lease, captured, now_ns=202)
        assert sessions._orphaned_corrections == {}
        assert (
            read_source(
                synthetic_store,
                captured.source_id,
                max_bytes=1_048_576,
            ).text
            == prepared.source_bytes.decode()
        )

    for index, target in enumerate(checkpoints):
        invalidate_one_checkpoint(index, target)


def test_prepared_owner_correction_uses_submission_head_and_one_clock_sample(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)
    selected = service.get_memory_revision(memory_id)
    clock = FrozenClock()
    owner_text = "合成更正：纸灯现在是绿色。\n"
    prepared = service.prepare_owner_correction(
        memory_id,
        owner_text,
        clock=clock,
    )
    identity = load_runtime_identity(synthetic_store)
    expected_prefix = (
        "---\n"
        "format: memory.owner-correction.v1\n"
        f"store_id: {identity.store_id}\n"
        f"target_lineage_id: {selected.summary.revision.lineage_id}\n"
        f"expected_head_id: {selected.summary.current_head_id}\n"
        "recorded_at: 2034-01-04T15:06:40Z\n"
        "---\n"
        "# Owner correction\n\n"
    ).encode()
    assert prepared.source_bytes == expected_prefix + owner_text.encode()
    assert prepared.owner_text_offset == len(expected_prefix)
    assert prepared.owner_text_sha256 == hashlib.sha256(owner_text.encode()).hexdigest()
    assert prepared.source_sha256 == hashlib.sha256(prepared.source_bytes).hexdigest()
    assert clock.calls == 1

    with pytest.raises(InvalidArgumentError):
        service.prepare_owner_correction(memory_id, "", clock=clock)
    with pytest.raises(InvalidArgumentError):
        service.prepare_owner_correction(memory_id, "\ud800", clock=clock)


def test_owner_correction_preflight_enforces_exact_envelope_utf8_boundary(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch owner-text estimates replacing the serialized-source byte cap."""
    from memory.ui.capture import MAX_OWNER_CORRECTION_SOURCE_BYTES
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)
    clock = FrozenClock()
    probe = service.prepare_owner_correction(memory_id, "x", clock=clock)
    available = MAX_OWNER_CORRECTION_SOURCE_BYTES - probe.owner_text_offset
    assert available > 3
    exact_text = "x" * (available - len("界".encode())) + "界"
    before = (
        tuple(synthetic_store.inbox_staging.iterdir()),
        tuple(synthetic_store.inbox_claims.iterdir()),
    )

    exact = service.prepare_owner_correction(
        memory_id,
        exact_text,
        clock=FrozenClock(),
    )
    assert len(exact.source_bytes) == MAX_OWNER_CORRECTION_SOURCE_BYTES
    with pytest.raises(InvalidArgumentError, match="too large"):
        service.prepare_owner_correction(
            memory_id,
            exact_text + "x",
            clock=FrozenClock(),
        )
    assert (
        tuple(synthetic_store.inbox_staging.iterdir()),
        tuple(synthetic_store.inbox_claims.iterdir()),
    ) == before


def test_historical_correction_preflight_resolves_the_submission_time_head(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.ui.service import OwnerApplicationService

    historical_id = _applied_memory(synthetic_store)
    current_id = _apply_successor(
        synthetic_store,
        historical_id,
        marker="current",
    )
    service = OwnerApplicationService(synthetic_store)
    historical = service.get_memory_revision(historical_id)
    assert historical.summary.is_current is False
    assert historical.summary.current_head_id == current_id

    prepared = service.prepare_owner_correction(
        historical_id,
        "Synthetic correction opened from the historical revision.",
        clock=FrozenClock(),
    )
    assert prepared.selected_memory_id == historical_id
    assert prepared.lineage_id == historical.summary.revision.lineage_id
    assert prepared.expected_head_id == current_id
    assert f"expected_head_id: {current_id}\n".encode() in prepared.source_bytes


def test_later_head_advance_makes_the_captured_correction_review_stale(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch capture-time head metadata bypassing normal atomic apply checks."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)
    owner_text = "Synthetic stale proposal says the paper lantern is amber."
    prepared = service.prepare_owner_correction(
        memory_id,
        owner_text,
        clock=FrozenClock(),
    )
    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    binding = sessions.issue_correction_form(session_id, memory_id, now_ns=200)
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    captured = service.capture_owner_correction(lease)
    response_loss_replay = service.capture_owner_correction(lease)
    assert response_loss_replay == captured
    sessions.complete_correction_form(lease, captured, now_ns=202)
    captured_source = read_batch(synthetic_store, captured.batch_id).sources[0]
    draft = create_change_set(
        synthetic_store,
        captured.batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        draft.change_set_id,
        draft.revision_id,
        (
            AddItem(
                client_item_id="synthetic-stale-owner-correction",
                memory=MemoryFields(
                    kind=MemoryKind.PREFERENCE,
                    statement="The synthetic paper lantern is amber.",
                    occurred_on="2033-06",
                    valid_from="2033-06",
                    valid_to=None,
                    tags=("synthetic", "lantern", "stale"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=prepared.lineage_id,
                    expected_head_id=prepared.expected_head_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=captured_source.source_id,
                        blob_digest=captured_source.blob_digest,
                        excerpt=owner_text,
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    successor_id = _apply_successor(
        synthetic_store,
        memory_id,
        marker="winner",
    )
    assert successor_id != prepared.expected_head_id
    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    with pytest.raises(StaleHeadError):
        approve_and_apply(
            synthetic_store,
            ready.change_set_id,
            ready.revision_id,
            ready.digest,
            approval,
        )


def test_owner_correction_capture_creates_only_one_sealed_source_and_no_review(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.database import open_database
    from memory.keys import load_master_key
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    unrelated = synthetic_store.inbox / "unrelated-settled.txt"
    unrelated.write_bytes(b"Synthetic unrelated Inbox entry.\n")
    service = OwnerApplicationService(synthetic_store)
    prepared = service.prepare_owner_correction(
        memory_id,
        "Synthetic corrected owner text.",
        clock=FrozenClock(),
    )
    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    binding = sessions.issue_correction_form(session_id, memory_id, now_ns=200)
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    captured = service.capture_owner_correction(lease)
    sessions.complete_correction_form(lease, captured, now_ns=202)

    assert unrelated.read_bytes() == b"Synthetic unrelated Inbox entry.\n"
    detail = read_batch(synthetic_store, captured.batch_id)
    assert len(detail.sources) == 1
    assert detail.sources[0].source_id == captured.source_id
    assert detail.sources[0].origin is SourceCaptureOrigin.OWNER_CORRECTION
    owner_detail = service.get_batch(captured.batch_id)
    assert owner_detail.sources[0].origin is SourceCaptureOrigin.OWNER_CORRECTION
    audit_detail = service.bind_audit(service.begin_audit_snapshot()).get_batch(
        captured.batch_id
    )
    assert audit_detail.sources[0].origin is SourceCaptureOrigin.OWNER_CORRECTION
    chunk = read_source(synthetic_store, captured.source_id, max_bytes=1_048_576)
    assert chunk.complete is True
    assert chunk.text == prepared.source_bytes.decode()
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        assert connection.execute(
            "SELECT count(*) FROM change_sets WHERE batch_id = ?",
            (captured.batch_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_inbox_page_upload_and_finder_reveal_are_protected_and_do_not_scan(
    synthetic_store: RuntimePaths,
) -> None:
    client, session, finder = _authenticated_client(synthetic_store)
    page = client.get("/inbox")
    assert page.status_code == 200
    assert "Staged; ask a connected agent to process the Inbox." in page.text
    assert "inbox.scan" in page.text
    assert "/inbox/scan" not in page.text
    assert "Scan Inbox" not in page.text
    assert "Choose or drop a complete file" in page.text
    assert "data-drop-zone" in page.text
    script = client.get("/static/ui.js")
    assert script.status_code == 200
    assert 'addEventListener("dragover"' in script.text
    assert 'addEventListener("drop"' in script.text

    uploaded = client.post(
        "/inbox/upload",
        data={"csrf": session.csrf_token},
        files={
            "file": ("合成-owner-note.md", "Synthetic staged bytes.\n", "text/markdown")
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    assert uploaded.headers["location"] == "/inbox?staged=1"
    staged = client.get(uploaded.headers["location"])
    assert "合成-owner-note.md" in staged.text
    assert "Synthetic staged bytes" not in staged.text

    assert client.get("/inbox/reveal").status_code == 405
    revealed = client.post(
        "/inbox/reveal",
        data={"csrf": session.csrf_token},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert revealed.status_code == 303
    assert len(finder.urls) == 1
    injected_reveal = client.post(
        "/inbox/reveal?path=/tmp/synthetic-injected",
        data={"csrf": session.csrf_token},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert injected_reveal.status_code == 400
    assert len(finder.urls) == 1

    unauthenticated = TestClient(client.app, base_url=PUBLIC_ORIGIN)
    assert unauthenticated.get("/inbox").status_code == 401
    assert unauthenticated.post("/inbox/reveal").status_code == 401


def test_upload_streams_a_single_pass_iterator_into_core_staging(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a route-level whole-file chunk collection before core staging."""
    from memory.ui.service import OwnerApplicationService

    original_stage = OwnerApplicationService.stage_inbox_file
    stream_shapes: list[tuple[bool, bool]] = []

    def inspect_stream(
        service: OwnerApplicationService,
        *,
        owner_filename: str,
        chunks: Iterable[bytes],
    ) -> model.StagedInboxEntry:
        iterator = iter(chunks)
        stream_shapes.append((iterator is chunks, isinstance(chunks, (list, tuple))))
        return original_stage(
            service,
            owner_filename=owner_filename,
            chunks=iterator,
        )

    monkeypatch.setattr(OwnerApplicationService, "stage_inbox_file", inspect_stream)
    client, session, _finder = _authenticated_client(synthetic_store)
    response = client.post(
        "/inbox/upload",
        data={"csrf": session.csrf_token},
        files={"file": ("synthetic-stream.md", b"streamed body", "text/markdown")},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert stream_shapes == [(True, False)]
    assert (synthetic_store.inbox / "synthetic-stream.md").read_bytes() == (
        b"streamed body"
    )


def test_upload_parser_abort_and_publication_failure_leave_no_private_artifact(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch streamed bytes surviving invalid trailing parts or a name collision."""
    client, session, _finder = _authenticated_client(synthetic_store)
    boundary = "synthetic-owner-upload-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; '
        'filename="synthetic-aborted.md"\r\n'
        "Content-Type: text/markdown\r\n\r\n"
        "private synthetic bytes\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="csrf"\r\n\r\n'
        f"{session.csrf_token}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="extra"\r\n\r\n'
        "invalid\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    aborted = client.post(
        "/inbox/upload",
        content=body,
        headers={
            "Origin": PUBLIC_ORIGIN,
            "X-Memory-CSRF": session.csrf_token,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        follow_redirects=False,
    )
    assert aborted.status_code == 413
    assert list(synthetic_store.inbox.iterdir()) == []
    _assert_drained_recovery_residue(
        synthetic_store,
        count=0,
        withdrawal_count=0,
    )

    collision = synthetic_store.inbox / "synthetic-collision.md"
    collision.write_bytes(b"existing owner bytes")
    rejected = client.post(
        "/inbox/upload",
        data={"csrf": session.csrf_token},
        files={"file": (collision.name, b"must not replace", "text/markdown")},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert rejected.status_code == 400
    assert collision.read_bytes() == b"existing owner bytes"
    _assert_drained_recovery_residue(
        synthetic_store,
        count=1,
        withdrawal_count=1,
    )


def _malformed_upload_body(*, boundary: str, csrf: str, index: int) -> bytes:
    """Build one multipart whose file part starts before its field name fails."""
    return (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="wrong"; '
        f'filename="synthetic-aborted-{index}.md"\r\n'
        "Content-Type: text/markdown\r\n\r\n"
        "private synthetic bytes\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="csrf"\r\n\r\n'
        f"{csrf}\r\n"
        f"--{boundary}--\r\n"
    ).encode()


def test_repeated_aborted_uploads_never_disable_inbox_upload(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch aborted uploads permanently consuming the global staging bound."""
    from memory.inbox import list_exact_recovery_issues

    client, session, _finder = _authenticated_client(synthetic_store)
    boundary = "synthetic-owner-abort-boundary"
    for index in range(8):
        aborted = client.post(
            "/inbox/upload",
            content=_malformed_upload_body(
                boundary=boundary,
                csrf=session.csrf_token,
                index=index,
            ),
            headers={
                "Origin": PUBLIC_ORIGIN,
                "X-Memory-CSRF": session.csrf_token,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            follow_redirects=False,
        )
        assert aborted.status_code == 400
    assert list(synthetic_store.inbox.iterdir()) == []
    assert (
        tuple(
            entry.name
            for entry in synthetic_store.inbox_staging.iterdir()
            if _ORDINARY_STAGE_NAME.fullmatch(entry.name)
        )
        == ()
    )

    accepted = client.post(
        "/inbox/upload",
        data={"csrf": session.csrf_token},
        files={"file": ("synthetic-after-aborts.md", b"owner bytes", "text/markdown")},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
    assert (synthetic_store.inbox / "synthetic-after-aborts.md").read_bytes() == (
        b"owner bytes"
    )
    assert (
        list_exact_recovery_issues(synthetic_store, cursor=None, limit=100).items == ()
    )


def test_unreclaimable_drained_stage_residue_is_owner_visible(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a stranded ordinary tombstone being hidden from the owner."""
    from memory import inbox as inbox_module

    monkeypatch.setattr(
        inbox_module,
        "_reclaim_bound_ordinary_stage_slot",
        lambda runtime, entry_id, descriptor: False,
    )

    def interrupted() -> Iterator[bytes]:
        yield b"synthetic partial bytes"
        raise RuntimeError("synthetic interrupted upload")

    with pytest.raises(RuntimeError, match="synthetic interrupted"):
        inbox_module.stage_inbox_entry(
            synthetic_store,
            owner_filename="stranded.txt",
            chunks=interrupted(),
        )
    residues = tuple(
        entry.name
        for entry in synthetic_store.inbox_staging.iterdir()
        if _ORDINARY_STAGE_NAME.fullmatch(entry.name)
    )
    assert len(residues) == 1
    issues = inbox_module.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=100,
    )
    assert [issue.code for issue in issues.items] == ["malformed_manifest"]


def test_unproven_zero_stage_occupants_are_surfaced_and_never_reused(
    synthetic_store: RuntimePaths,
) -> None:
    """Exhaustion the Store cannot prove it owns is reported, never recycled."""
    from memory.inbox import (
        list_exact_recovery_issues,
        stage_inbox_entry,
    )

    occupants = []
    for index in range(8):
        occupant = synthetic_store.inbox_staging / f"ent_{index:032x}.stage"
        occupant.write_bytes(b"")
        occupant.chmod(0o600)
        occupants.append(occupant)
    before = {occupant: _custody_snapshot(occupant) for occupant in occupants}

    issues = list_exact_recovery_issues(synthetic_store, cursor=None, limit=100)
    assert [issue.code for issue in issues.items] == ["malformed_manifest"] * 8

    with pytest.raises(InvalidArgumentError):
        stage_inbox_entry(
            synthetic_store,
            owner_filename="synthetic-refused.txt",
            chunks=(b"owner bytes",),
        )
    for occupant in occupants:
        assert occupant.read_bytes() == b""
        assert _custody_snapshot(occupant) == before[occupant]
    assert list(synthetic_store.inbox.iterdir()) == []


def test_reveal_refuses_replaced_inbox_before_calling_finder(
    synthetic_store: RuntimePaths,
) -> None:
    client, session, finder = _authenticated_client(synthetic_store)
    detached = synthetic_store.root / "detached-synthetic-inbox"
    synthetic_store.inbox.rename(detached)
    synthetic_store.inbox.mkdir(mode=0o700)

    response = client.post(
        "/inbox/reveal",
        data={"csrf": session.csrf_token},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert finder.urls == []
    assert list(synthetic_store.inbox.iterdir()) == []


def test_reveal_passes_an_inode_reference_when_inbox_swaps_inside_adapter(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch Finder resolving a replacement pathname at its side-effect boundary."""
    from memory.ui.service import OwnerApplicationService

    original_identity = (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    )
    detached = synthetic_store.root / "detached-finder-bound-inbox"
    received: list[object] = []

    class SwappingFinder:
        def reveal_directory_url(self, directory_url: object) -> None:
            synthetic_store.inbox.rename(detached)
            synthetic_store.inbox.mkdir(mode=0o700)
            received.append(directory_url)

    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        OwnerApplicationService(synthetic_store).reveal_inbox_in_finder(
            SwappingFinder()
        )

    assert len(received) == 1
    directory_url = received[0]
    # Whatever the adapter handed Finder is a PyObjC NSURL, and PyObjC ships no
    # stubs, so only the framework can answer what this reference resolves to.
    assert directory_url.isFileReferenceURL() is True  # type: ignore[attr-defined]
    resolved = directory_url.filePathURL()  # type: ignore[attr-defined]
    assert resolved is not None
    resolved_path = Path(str(resolved.path()))
    assert (
        resolved_path.stat().st_dev,
        resolved_path.stat().st_ino,
    ) == original_identity
    assert (
        synthetic_store.inbox.stat().st_dev,
        synthetic_store.inbox.stat().st_ino,
    ) != original_identity


def test_reveal_swap_during_file_reference_creation_never_reaches_finder(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch URL conversion binding Finder authority to a replacement inode."""
    from types import SimpleNamespace

    from memory.ui.service import OwnerApplicationService

    detached = synthetic_store.root / "detached-during-reference-creation"
    received: list[object] = []

    class SyntheticPathURL:
        def fileReferenceURL(self) -> object:
            synthetic_store.inbox.rename(detached)
            synthetic_store.inbox.mkdir(mode=0o700)
            return object()

    class SyntheticNSURL:
        @classmethod
        def fileURLWithPath_isDirectory_(
            cls,
            _path: str,
            _is_directory: bool,
        ) -> SyntheticPathURL:
            return SyntheticPathURL()

    class RecordingSwapFinder:
        def reveal_directory_url(self, directory_url: object) -> None:
            received.append(directory_url)

    monkeypatch.setitem(
        sys.modules, "Foundation", SimpleNamespace(NSURL=SyntheticNSURL)
    )
    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        OwnerApplicationService(synthetic_store).reveal_inbox_in_finder(
            RecordingSwapFinder()
        )
    assert received == []


def test_reveal_rejects_a_reference_to_a_swap_that_restores_the_runtime_path(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch pathname revalidation accepting a reference bound to another inode."""
    from types import SimpleNamespace

    from memory.ui.service import OwnerApplicationService

    detached_original = synthetic_store.root / "detached-restored-inbox"
    detached_replacement = synthetic_store.root / "detached-reference-replacement"
    received: list[object] = []

    class SyntheticReferenceURL:
        def isFileReferenceURL(self) -> bool:
            return True

        def filePathURL(self) -> object:
            return SimpleNamespace(path=lambda: os.fspath(detached_replacement))

    class SyntheticPathURL:
        def fileReferenceURL(self) -> SyntheticReferenceURL:
            synthetic_store.inbox.rename(detached_original)
            synthetic_store.inbox.mkdir(mode=0o700)
            synthetic_store.inbox.rename(detached_replacement)
            detached_original.rename(synthetic_store.inbox)
            return SyntheticReferenceURL()

    class SyntheticNSURL:
        @classmethod
        def fileURLWithPath_isDirectory_(
            cls,
            _path: str,
            _is_directory: bool,
        ) -> SyntheticPathURL:
            return SyntheticPathURL()

    class RecordingFinder:
        def reveal_directory_url(self, directory_url: object) -> None:
            received.append(directory_url)

    monkeypatch.setitem(
        sys.modules, "Foundation", SimpleNamespace(NSURL=SyntheticNSURL)
    )
    with pytest.raises(InvalidArgumentError, match="file reference"):
        OwnerApplicationService(synthetic_store).reveal_inbox_in_finder(
            RecordingFinder()
        )
    assert received == []


def test_owner_service_binds_startup_directory_authority_for_inbox_operations(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch each service call treating a replaced directory as a fresh baseline."""
    from memory.ui.service import OwnerApplicationService

    service = OwnerApplicationService(synthetic_store)
    detached = synthetic_store.root / "detached-service-inbox"
    synthetic_store.inbox.rename(detached)
    synthetic_store.inbox.mkdir(mode=0o700)
    finder = RecordingFinder()

    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        service.list_staged_inbox_entries(None, 10)
    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        service.stage_inbox_file(
            owner_filename="must-not-stage-after-replacement.md",
            chunks=(b"Synthetic private bytes.\n",),
        )
    with pytest.raises(InvalidArgumentError, match="runtime path changed"):
        service.reveal_inbox_in_finder(finder)
    assert finder.urls == []
    assert tuple(synthetic_store.inbox.iterdir()) == ()


def test_maximum_staged_rows_fit_the_derived_page_and_continue_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch literal maximum filenames overflowing or bypassing page bounds."""
    from memory.ui.request_limits import (
        MAX_STANDARD_HTML_RESPONSE_BYTES,
        MAX_STANDARD_LIST_ROW_HTML_BYTES,
        UI_STANDARD_PAGE_LIMIT,
    )

    for index in range(UI_STANDARD_PAGE_LIMIT + 1):
        prefix = f"{index:03d}-"
        name = prefix + "x" * (255 - len(prefix))
        assert len(name.encode("utf-8")) == 255
        (synthetic_store.inbox / name).write_bytes(b"")
    client, _session, _finder = _authenticated_client(synthetic_store)

    first = client.get(f"/inbox?limit={UI_STANDARD_PAGE_LIMIT}")
    assert first.status_code == 200
    assert len(first.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert first.text.count("data-staged-row") == UI_STANDARD_PAGE_LIMIT
    assert 'data-next-staged href="' in first.text
    one_row = next(
        line for line in first.text.splitlines() if "data-staged-row" in line
    )
    assert len(one_row.encode("utf-8")) <= MAX_STANDARD_LIST_ROW_HTML_BYTES

    next_href = first.text.split('data-next-staged href="', 1)[1].split('"', 1)[0]
    second = client.get(next_href.replace("&amp;", "&"))
    assert second.status_code == 200
    assert second.text.count("data-staged-row") == 1
    assert "data-next-staged" not in second.text


def test_memory_correction_routes_issue_by_post_and_capture_exact_batch(
    synthetic_store: RuntimePaths,
) -> None:
    memory_id = _applied_memory(synthetic_store)
    unrelated = synthetic_store.inbox / "unrelated-visible.txt"
    unrelated.write_bytes(b"Unrelated synthetic Inbox bytes.\n")
    client, session, _finder = _authenticated_client(synthetic_store)
    detail = client.get(f"/memories/{memory_id}")
    assert detail.status_code == 200
    assert "Create correction" in detail.text

    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert opened.status_code == 303
    location = opened.headers["location"]
    assert memory_id not in location
    nonce = urllib.parse.urlsplit(location).path.rsplit("/", 1)[-1]
    assert nonce
    form = client.get(location)
    assert form.status_code == 200
    assert "Owner correction" in form.text
    assert client.get(location + "?owner_text=private-synthetic").status_code == 400
    assert (
        client.post(
            location + "?target=synthetic-injected",
            data={
                "selected_memory_id": memory_id,
                "owner_text": "Synthetic route correction with 绿色纸灯.",
            },
            headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
            follow_redirects=False,
        ).status_code
        == 400
    )

    submitted = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic route correction with 绿色纸灯.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    assert submitted.headers["location"].startswith("/inbox?captured=bat_")
    captured = client.get(submitted.headers["location"])
    assert captured.status_code == 200
    assert "Captured; awaiting Memory Review" in captured.text
    assert "Open captured correction source" in captured.text
    batch_id = urllib.parse.parse_qs(
        urllib.parse.urlsplit(submitted.headers["location"]).query
    )["captured"][0]
    batch_href = f"/inbox/batches/{batch_id}"
    assert f'href="{batch_href}"' in captured.text
    batch_page = client.get(batch_href)
    assert batch_page.status_code == 200
    captured_source_href = captured.text.split('href="/sources/', 1)[1].split('"', 1)[0]
    assert f'href="/sources/{captured_source_href}"' in batch_page.text
    assert client.get(f"/sources/{captured_source_href}").status_code == 200
    recent = client.get("/inbox")
    assert recent.status_code == 200
    assert f'href="{batch_href}"' in recent.text
    assert unrelated.read_bytes() == b"Unrelated synthetic Inbox bytes.\n"
    replayed = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic route correction with 绿色纸灯.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert replayed.status_code == 303
    assert replayed.headers["location"] == submitted.headers["location"]
    altered = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Altered synthetic duplicate.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert altered.status_code == 400
    artifacts = tuple(synthetic_store.inbox_staging.glob("*.json")) + tuple(
        synthetic_store.inbox_claims.rglob("manifest.json")
    )
    assert all(nonce.encode() not in path.read_bytes() for path in artifacts)


def test_duplicate_correction_posts_are_single_flight_and_share_one_redirect(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch two duplicate HTTP workers both entering exact-capture custody."""
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionSubmissionLease,
    )
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    client, session, _finder = _authenticated_client(synthetic_store)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    service = _app_state(client).owner_service
    assert isinstance(service, OwnerApplicationService)
    prepared = service.prepare_owner_correction(
        memory_id,
        "Synthetic concurrent correction.",
        clock=FrozenClock(),
    )

    capture_calls: list[CorrectionSubmissionLease] = []
    capture_lock = threading.Lock()
    capture_started = threading.Event()
    duplicate_capture_started = threading.Event()
    release_capture = threading.Event()

    def capture_once(
        _selected_service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> CapturedCorrection:
        with capture_lock:
            capture_calls.append(lease)
            capture_started.set()
            if len(capture_calls) == 2:
                duplicate_capture_started.set()
        assert release_capture.wait(timeout=10)
        return CapturedCorrection(
            capture_request_id=lease.capture_request_id,
            batch_id=lease.reserved_batch_id,
            source_id="src_" + "9" * 32,
            lineage_id=lease.prepared.lineage_id,
            expected_head_id=lease.prepared.expected_head_id,
            captured_at=lease.prepared.captured_at,
        )

    monkeypatch.setattr(
        OwnerApplicationService,
        "prepare_owner_correction",
        lambda *_args, **_kwargs: prepared,
    )
    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        capture_once,
    )
    responses: list[httpx2.Response | BaseException] = []

    def submit() -> None:
        try:
            responses.append(
                client.post(
                    location,
                    data={
                        "selected_memory_id": memory_id,
                        "owner_text": "Synthetic concurrent correction.",
                    },
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "X-Memory-CSRF": session.csrf_token,
                    },
                    follow_redirects=False,
                )
            )
        except BaseException as error:
            responses.append(error)

    first = threading.Thread(target=submit)
    second = threading.Thread(target=submit)
    workers = [first, second]
    first.start()
    assert capture_started.wait(timeout=10)
    second.start()
    duplicate_capture_started.wait(timeout=0.2)
    release_capture.set()
    for worker in workers:
        worker.join(timeout=10)
    assert all(not worker.is_alive() for worker in workers)
    assert len(capture_calls) == 1
    assert len(responses) == 2
    assert all(
        getattr(response, "status_code", None) == 303 for response in responses
    ), responses
    assert {_redirect_location(response) for response in responses} == {
        f"/inbox?captured={capture_calls[0].reserved_batch_id}"
    }


def test_duplicate_correction_http_follower_times_out_then_replays_original_result(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an indefinitely blocked duplicate HTTP worker or second capture."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionSubmissionLease,
    )
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    client, session, _finder = _authenticated_client(synthetic_store)
    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    sessions._correction_wait_timeout_seconds = 0.05
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    capture_started = threading.Event()
    release_capture = threading.Event()
    capture_calls: list[CorrectionSubmissionLease] = []

    def capture_once(
        _service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> CapturedCorrection:
        capture_calls.append(lease)
        capture_started.set()
        assert release_capture.wait(timeout=10)
        return CapturedCorrection(
            capture_request_id=lease.capture_request_id,
            batch_id=lease.reserved_batch_id,
            source_id="src_" + "8" * 32,
            lineage_id=lease.prepared.lineage_id,
            expected_head_id=lease.prepared.expected_head_id,
            captured_at=lease.prepared.captured_at,
        )

    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        capture_once,
    )
    responses: dict[str, httpx2.Response | BaseException] = {}

    def submit(label: str) -> None:
        try:
            responses[label] = client.post(
                location,
                data={
                    "selected_memory_id": memory_id,
                    "owner_text": "Synthetic bounded HTTP follower.",
                },
                headers={
                    "Origin": PUBLIC_ORIGIN,
                    "X-Memory-CSRF": session.csrf_token,
                },
                follow_redirects=False,
            )
        except BaseException as error:
            responses[label] = error

    owner = threading.Thread(target=submit, args=("owner",))
    follower = threading.Thread(target=submit, args=("follower",))
    owner.start()
    assert capture_started.wait(timeout=10)
    follower.start()
    follower.join(timeout=0.5)
    follower_returned_before_owner = not follower.is_alive()
    assert follower_returned_before_owner
    retry_location = f"{location}/retry"
    immediate = client.get(retry_location, follow_redirects=False)
    assert immediate.status_code == 202
    assert "in progress" in immediate.text.lower()
    assert "Synthetic bounded HTTP follower." not in immediate.text
    assert "Synthetic bounded HTTP follower." not in retry_location
    release_capture.set()
    owner.join(timeout=10)
    follower.join(timeout=10)
    assert not owner.is_alive() and not follower.is_alive()
    assert len(capture_calls) == 1
    assert getattr(responses["follower"], "status_code", None) == 303
    assert _redirect_location(responses["follower"]) == retry_location
    original_location = f"/inbox?captured={capture_calls[0].reserved_batch_id}"
    assert _redirect_location(responses["owner"]) == original_location

    replay_before_status = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic bounded HTTP follower.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert replay_before_status.status_code == 303
    assert replay_before_status.headers["location"] == original_location

    completed_status = client.get(retry_location, follow_redirects=False)
    assert completed_status.status_code == 303
    assert completed_status.headers["location"] == original_location

    replay = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic bounded HTTP follower.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert replay.status_code == 303
    assert replay.headers["location"] == original_location
    assert len(capture_calls) == 1


def test_expired_in_flight_correction_status_replays_the_original_batch(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep content-free status while the sole active call owns correction bytes."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        CapturedCorrection,
        CorrectionSubmissionLease,
    )
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    client, session, _finder = _authenticated_client(synthetic_store)
    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    nonce = location.rsplit("/", maxsplit=1)[-1]
    binding = sessions._sessions[session.session_id].corrections[nonce].binding
    capture_started = threading.Event()
    release_capture = threading.Event()
    capture_calls: list[CorrectionSubmissionLease] = []

    def capture_once(
        _service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> CapturedCorrection:
        capture_calls.append(lease)
        capture_started.set()
        assert release_capture.wait(timeout=10)
        return CapturedCorrection(
            capture_request_id=lease.capture_request_id,
            batch_id=lease.reserved_batch_id,
            source_id="src_" + "7" * 32,
            lineage_id=lease.prepared.lineage_id,
            expected_head_id=lease.prepared.expected_head_id,
            captured_at=lease.prepared.captured_at,
        )

    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        capture_once,
    )
    responses: list[httpx2.Response | BaseException] = []

    def submit() -> None:
        try:
            responses.append(
                client.post(
                    location,
                    data={
                        "selected_memory_id": memory_id,
                        "owner_text": "Synthetic expiry-owned correction.",
                    },
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "X-Memory-CSRF": session.csrf_token,
                    },
                    follow_redirects=False,
                )
            )
        except BaseException as error:
            responses.append(error)

    owner = threading.Thread(target=submit)
    owner.start()
    assert capture_started.wait(timeout=10)
    object.__setattr__(binding, "expires_at_ns", time.monotonic_ns())
    try:
        in_progress = client.get(f"{location}/retry", follow_redirects=False)
        terminal = sessions._orphaned_corrections[capture_calls[0].lease_id]
        retained_session_bytes = sum(
            len(record.prepared.source_bytes)
            for active in sessions._sessions.values()
            for record in active.corrections.values()
            if record.prepared is not None
        )
        terminal_repr = repr(terminal)
    finally:
        release_capture.set()
        owner.join(timeout=10)

    assert not owner.is_alive()
    assert in_progress.status_code == 202
    assert retained_session_bytes == 0
    assert "Synthetic expiry-owned correction." not in terminal_repr
    assert capture_calls[0].prepared.source_bytes.endswith(
        b"Synthetic expiry-owned correction."
    )
    assert len(capture_calls) == 1
    assert len(responses) == 1
    original_location = f"/inbox?captured={capture_calls[0].reserved_batch_id}"
    assert getattr(responses[0], "status_code", None) == 303
    assert _redirect_location(responses[0]) == original_location

    # Design section 10.3 forbids a GET from consuming write-authority state, so
    # the status read is idempotent for the ten-minute tombstone lifetime and
    # never frees the retained terminal capacity. Release happens only through
    # that lifetime, session invalidation, or shutdown.
    from memory.ui.auth import CORRECTION_STATUS_TTL_NS

    for _repeat in range(3):
        completed = client.get(f"{location}/retry", follow_redirects=False)
        assert completed.status_code == 303
        assert completed.headers["location"] == original_location
        assert len(sessions._orphaned_corrections) == 1
    assert (
        sessions.resolve_correction_status(
            session.session_id,
            nonce,
            now_ns=time.monotonic_ns() + CORRECTION_STATUS_TTL_NS,
        )
        is None
    )
    assert sessions._orphaned_corrections == {}


@pytest.mark.parametrize("transition", ["logout", "shutdown"])
@pytest.mark.parametrize("durable_staging", [False, True])
def test_revoked_http_capture_failure_releases_only_terminal_custody(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
    durable_staging: bool,
) -> None:
    """Pin real route wiring from core custody outcome to revoked-byte erasure."""
    import memory.inbox as inbox
    from memory.errors import StoreBusyError
    from memory.model import ExactCaptureMetadata
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        MAX_OWNER_CORRECTION_SOURCE_BYTES,
        CorrectionSubmissionLease,
    )
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    client, session, _finder = _authenticated_client(synthetic_store)
    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    outcomes: list[str] = []
    original_mark = sessions.mark_correction_retryable

    def record_outcome(
        lease: CorrectionSubmissionLease,
        *,
        custody_outcome: str = "ambiguous",
    ) -> None:
        outcomes.append(custody_outcome)
        original_mark(lease, custody_outcome=custody_outcome)

    def fail_after_transition(
        service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> model.CapturedCorrection:
        if durable_staging:
            metadata = ExactCaptureMetadata(
                capture_request_id=lease.capture_request_id,
                batch_id=lease.reserved_batch_id,
                captured_at=lease.prepared.captured_at,
                target_lineage_id=lease.prepared.lineage_id,
                expected_head_id=lease.prepared.expected_head_id,
                payload_sha256=lease.prepared.source_sha256,
                source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
                authorship=Authorship.OWNER,
                sensitivity=Sensitivity.RESTRICTED,
            )
            inbox.stage_exact_private_entry(
                service.paths,
                display_name=(
                    "owner-correction-"
                    f"{lease.capture_request_id.removeprefix('cap_')}.md"
                ),
                chunks=(lease.prepared.source_bytes,),
                max_bytes=MAX_OWNER_CORRECTION_SOURCE_BYTES,
                metadata=metadata,
                directory_authority=service._directory_authority,
            )
        if transition == "logout":
            sessions.invalidate_session(session.session_id)
        else:
            sessions.invalidate_all()
        raise StoreBusyError("synthetic capture contention")

    monkeypatch.setattr(sessions, "mark_correction_retryable", record_outcome)
    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        fail_after_transition,
    )
    response = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic terminal custody classification.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert outcomes == ["durable" if durable_staging else "proven_empty"]
    assert sessions._orphaned_corrections == {}


def test_expired_http_failure_finishes_ambiguous_handoff_in_one_invocation(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve an ambiguous active failure before returning from its route call."""
    import memory.inbox as inbox
    from memory.errors import StoreBusyError
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    client, session, _finder = _authenticated_client(synthetic_store)
    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    malformed = synthetic_store.inbox_staging / f"ent_{'b' * 32}.stage.ready.json"
    malformed.write_text("{synthetic unrelated", encoding="utf-8")
    malformed.chmod(0o600)
    outcomes: list[str] = []
    capture_calls: list[str] = []
    original_mark = sessions.mark_correction_retryable
    original_write = inbox._write_private_recovery_manifest
    marker_calls = 0

    def fail_first_marker(
        runtime: inbox._RuntimeRoot,
        reservation: inbox._PrivateRecoveryReservation,
    ) -> bool:
        nonlocal marker_calls
        marker_calls += 1
        if marker_calls == 1:
            return False
        return original_write(runtime, reservation)

    def record_outcome(
        lease: CorrectionSubmissionLease,
        *,
        custody_outcome: str = "ambiguous",
    ) -> None:
        outcomes.append(custody_outcome)
        original_mark(lease, custody_outcome=custody_outcome)

    def expire_then_fail(
        _service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> model.CapturedCorrection:
        capture_calls.append(lease.capture_request_id)
        assert (
            sessions.resolve_correction_form(
                session.session_id,
                lease.binding.form_nonce,
                now_ns=lease.binding.expires_at_ns,
            )
            is None
        )
        raise StoreBusyError("synthetic ambiguous capture failure")

    monkeypatch.setattr(inbox, "_write_private_recovery_manifest", fail_first_marker)
    monkeypatch.setattr(sessions, "mark_correction_retryable", record_outcome)
    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        expire_then_fail,
    )
    response = client.post(
        location,
        data={
            "selected_memory_id": memory_id,
            "owner_text": "Synthetic one-call custody resolution.",
        },
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert capture_calls and len(capture_calls) == 1
    assert outcomes == ["durable"]
    assert marker_calls == 2
    assert sessions._orphaned_corrections == {}
    payloads = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.name.startswith(".recovery-") and candidate.name.endswith(".stage")
    ]
    assert len(payloads) == 1
    assert payloads[0].read_bytes().endswith(b"Synthetic one-call custody resolution.")


def test_correction_custody_classifier_uses_a_distinct_handoff_for_replaced_ready(
    synthetic_store: RuntimePaths,
) -> None:
    """Never trust a replacement inode; durable means a separate exact handoff."""
    import memory.inbox as inbox
    from memory.model import ExactCaptureMetadata
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        MAX_OWNER_CORRECTION_SOURCE_BYTES,
        CorrectionSubmissionLease,
    )
    from memory.ui.service import OwnerApplicationService

    service = OwnerApplicationService(synthetic_store)
    prepared = service.prepare_owner_correction(
        _applied_memory(synthetic_store),
        "Synthetic classifier inode replacement.",
        clock=FrozenClock(),
    )
    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    metadata = ExactCaptureMetadata(
        capture_request_id=lease.capture_request_id,
        batch_id=lease.reserved_batch_id,
        captured_at=prepared.captured_at,
        target_lineage_id=prepared.lineage_id,
        expected_head_id=prepared.expected_head_id,
        payload_sha256=prepared.source_sha256,
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    entry = inbox.stage_exact_private_entry(
        synthetic_store,
        display_name=(
            f"owner-correction-{lease.capture_request_id.removeprefix('cap_')}.md"
        ),
        chunks=(prepared.source_bytes,),
        max_bytes=MAX_OWNER_CORRECTION_SOURCE_BYTES,
        metadata=metadata,
        directory_authority=service._directory_authority,
    )
    payload = synthetic_store.inbox_staging / entry.entry_id
    detached = synthetic_store.root / "detached-classifier-ready-inode"
    payload.rename(detached)
    payload.write_bytes(prepared.source_bytes)
    payload.chmod(0o600)

    assert service.correction_capture_custody_outcome(lease) == "durable"
    assert payload.read_bytes() == prepared.source_bytes
    assert detached.read_bytes() == prepared.source_bytes
    handoffs = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.name.startswith(".recovery-") and candidate.name.endswith(".stage")
    ]
    assert handoffs == [prepared.source_bytes]


def test_revoked_ambiguous_correction_gets_a_durable_content_free_handoff(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an unrelated malformed artifact pinning the sole source buffer."""
    import memory.inbox as inbox
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    service = OwnerApplicationService(synthetic_store)
    prepared = service.prepare_owner_correction(
        _applied_memory(synthetic_store),
        "Synthetic terminal recovery handoff.",
        clock=FrozenClock(),
    )
    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    malformed = synthetic_store.inbox_staging / f"ent_{'d' * 32}.stage.ready.json"
    malformed.write_text("{synthetic unrelated", encoding="utf-8")
    malformed.chmod(0o600)

    sessions.invalidate_all()
    outcome = service.correction_capture_custody_outcome(lease)
    assert outcome == "durable"
    sessions.mark_correction_retryable(lease, custody_outcome=outcome)
    assert sessions._sessions == {}
    assert sessions._orphaned_corrections == {}
    retained = [
        candidate.read_bytes()
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.is_file()
        and candidate.name.startswith(".recovery-")
        and candidate.name.endswith(".stage")
    ]
    assert retained == [prepared.source_bytes]
    issues = inbox.list_exact_recovery_issues(
        synthetic_store,
        cursor=None,
        limit=10,
    )
    assert issues.items
    assert "Synthetic terminal recovery handoff." not in repr(issues.items)


def test_ambiguous_correction_handoff_retry_reuses_one_bounded_payload(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a failed marker barrier duplicating maximum-size recovery bytes."""
    import memory.inbox as inbox
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    service = OwnerApplicationService(synthetic_store)
    prepared = service.prepare_owner_correction(
        _applied_memory(synthetic_store),
        "Synthetic idempotent recovery handoff.",
        clock=FrozenClock(),
    )
    sessions, session_id = _session_store()
    assert isinstance(sessions, UiSessionStore)
    binding = sessions.issue_correction_form(
        session_id,
        prepared.selected_memory_id,
        now_ns=200,
    )
    lease = sessions.lease_correction_form(
        session_id,
        binding.form_nonce,
        prepared.selected_memory_id,
        prepared,
        now_ns=201,
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    malformed = synthetic_store.inbox_staging / f"ent_{'c' * 32}.stage.ready.json"
    malformed.write_text("{synthetic unrelated", encoding="utf-8")
    malformed.chmod(0o600)
    original_write = inbox._write_private_recovery_manifest
    calls = 0

    def fail_first_marker(
        runtime: inbox._RuntimeRoot,
        reservation: inbox._PrivateRecoveryReservation,
    ) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return False
        return original_write(runtime, reservation)

    monkeypatch.setattr(inbox, "_write_private_recovery_manifest", fail_first_marker)

    assert service.correction_capture_custody_outcome(lease) == "durable"
    assert service.correction_capture_custody_outcome(lease) == "durable"
    payloads = [
        candidate
        for candidate in synthetic_store.inbox_staging.iterdir()
        if candidate.name.startswith(".recovery-") and candidate.name.endswith(".stage")
    ]
    assert len(payloads) == 1
    assert payloads[0].read_bytes() == prepared.source_bytes


def test_captured_notice_refuses_an_ordinary_inbox_batch(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.inbox import ScanPolicy, scan_inbox

    ordinary = synthetic_store.inbox / "synthetic-ordinary-not-correction.md"
    ordinary.write_bytes(b"Synthetic ordinary batch.\n")
    batch = scan_inbox(
        synthetic_store,
        clock=FrozenClock(),
        policy=ScanPolicy(settle_seconds=0),
    )
    client, _session, _finder = _authenticated_client(synthetic_store)

    response = client.get(f"/inbox?captured={batch.batch_id}")
    assert response.status_code == 400
    assert "Captured; awaiting Memory Review" not in response.text


def test_busy_correction_retry_preserves_exact_maximum_payload_without_retyping(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch busy handling leaking, duplicating, truncating, or re-reserving text."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import (
        MAX_OWNER_CORRECTION_SOURCE_BYTES,
        CapturedCorrection,
        CorrectionSubmissionLease,
    )
    from memory.ui.request_limits import (
        MAX_CORRECTION_HTML_RESPONSE_BYTES,
    )
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)
    probe = service.prepare_owner_correction(
        memory_id,
        "x",
        clock=FrozenClock(),
    )
    owner_text = "&" * (MAX_OWNER_CORRECTION_SOURCE_BYTES - probe.owner_text_offset)
    assert (
        len(
            service.prepare_owner_correction(
                memory_id,
                owner_text,
                clock=FrozenClock(),
            ).source_bytes
        )
        == MAX_OWNER_CORRECTION_SOURCE_BYTES
    )

    original_capture = OwnerApplicationService.capture_owner_correction
    capture_calls: list[CorrectionSubmissionLease] = []

    def busy_once(
        selected_service: OwnerApplicationService,
        lease: CorrectionSubmissionLease,
    ) -> CapturedCorrection:
        capture_calls.append(lease)
        if len(capture_calls) == 1:
            raise StoreBusyError("synthetic busy before staging")
        return original_capture(selected_service, lease)

    monkeypatch.setattr(
        OwnerApplicationService,
        "capture_owner_correction",
        busy_once,
    )
    client, session, _finder = _authenticated_client(synthetic_store)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    nonce = location.rsplit("/", 1)[-1]
    busy = client.post(
        location,
        data={"selected_memory_id": memory_id, "owner_text": owner_text},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert busy.status_code == 303
    assert busy.headers["location"] == f"{location}/retry"
    assert owner_text not in busy.headers["location"]
    assert tuple(synthetic_store.inbox_staging.iterdir()) == ()
    assert tuple(synthetic_store.inbox_claims.iterdir()) == ()

    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    record = sessions._sessions[session.session_id].corrections[nonce]
    assert record.phase == "retryable"
    assert record.prepared is not None
    assert len(record.prepared.source_bytes) == MAX_OWNER_CORRECTION_SOURCE_BYTES
    assert record.lease is not None
    capture_request_id = record.lease.capture_request_id
    reserved_batch_id = record.lease.reserved_batch_id

    retry_page = client.get(busy.headers["location"])
    assert retry_page.status_code == 200
    assert len(retry_page.content) <= MAX_CORRECTION_HTML_RESPONSE_BYTES
    rendered_owner_text = retry_page.text.split(
        '<pre class="owner-correction-retry">', 1
    )[1].split("</pre>", 1)[0]
    assert rendered_owner_text == "&amp;" * len(owner_text)
    assert retry_page.url.query == b""
    retried = client.post(
        busy.headers["location"],
        data={"csrf": session.csrf_token},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert retried.status_code == 303
    assert retried.headers["location"] == f"/inbox?captured={reserved_batch_id}"
    assert len(capture_calls) == 2
    assert capture_calls[0].capture_request_id == capture_request_id
    assert capture_calls[1].capture_request_id == capture_request_id
    assert capture_calls[0].reserved_batch_id == capture_calls[1].reserved_batch_id
    assert record.phase == "completed"
    assert record.prepared is None and record.lease is None

    restarted, _new_session_id = _session_store()
    assert isinstance(restarted, UiSessionStore)
    assert (
        restarted.resolve_retryable_correction(
            session.session_id,
            nonce,
            now_ns=202,
        )
        is None
    )


def test_correction_route_rejects_envelope_and_declared_body_overflow_prelease(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch body or envelope caps reserving IDs or leaving custody artifacts."""
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import MAX_OWNER_CORRECTION_SOURCE_BYTES
    from memory.ui.request_limits import MAX_CORRECTION_FORM_BODY_BYTES
    from memory.ui.service import OwnerApplicationService

    memory_id = _applied_memory(synthetic_store)
    service = OwnerApplicationService(synthetic_store)
    probe = service.prepare_owner_correction(
        memory_id,
        "x",
        clock=FrozenClock(),
    )
    owner_text = "x" * (MAX_OWNER_CORRECTION_SOURCE_BYTES - probe.owner_text_offset + 1)
    client, session, _finder = _authenticated_client(synthetic_store)
    opened = client.post(
        f"/memories/{memory_id}/corrections",
        data={"selected_memory_id": memory_id},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    location = opened.headers["location"]
    nonce = location.rsplit("/", 1)[-1]
    before = (
        tuple(synthetic_store.inbox_staging.iterdir()),
        tuple(synthetic_store.inbox_claims.iterdir()),
    )

    rejected = client.post(
        location,
        data={"selected_memory_id": memory_id, "owner_text": owner_text},
        headers={"Origin": PUBLIC_ORIGIN, "X-Memory-CSRF": session.csrf_token},
        follow_redirects=False,
    )
    assert rejected.status_code == 400
    sessions = _app_state(client).sessions
    assert isinstance(sessions, UiSessionStore)
    record = sessions._sessions[session.session_id].corrections[nonce]
    assert record.phase == "pending"
    assert record.prepared is None and record.lease is None
    assert (
        tuple(synthetic_store.inbox_staging.iterdir()),
        tuple(synthetic_store.inbox_claims.iterdir()),
    ) == before

    declared = client.post(
        location,
        content=b"",
        headers={
            "Origin": PUBLIC_ORIGIN,
            "X-Memory-CSRF": session.csrf_token,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(MAX_CORRECTION_FORM_BODY_BYTES + 1),
        },
        follow_redirects=False,
    )
    assert declared.status_code == 413
    assert record.phase == "pending"
    assert record.prepared is None and record.lease is None
    assert (
        tuple(synthetic_store.inbox_staging.iterdir()),
        tuple(synthetic_store.inbox_claims.iterdir()),
    ) == before
