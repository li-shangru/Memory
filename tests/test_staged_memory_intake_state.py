"""Body-free authorization receipts and monotone transaction-state tests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path

import pytest
import staged_memory_intake.state as state_module
from staged_memory_intake.config import configure, load_config
from staged_memory_intake.model import (
    STATE_ORDER,
    GuardViolationNotice,
    IntakeError,
    PromotionPreview,
    PublishedFile,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import build_preview
from staged_memory_intake.state import (
    TRANSACTION_SCHEMA,
    TransactionStore,
    abandon_unsupported_transaction,
    validate_reconfiguration,
)
from staged_memory_intake_fakes import FakeMemoryPathsRunner

PRIVATE_BODY_MARKER = "SYNTHETIC-CONSPICUOUS-PRIVATE-BODY-MARKER"


def _prepared_bytes(source_name: str, source: bytes, statement: str) -> bytes:
    return (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
        "kind: insight\n"
        "sensitivity: sensitive\n"
        "occurred_on: 2026-08\n"
        "valid_from: \n"
        "valid_to: \n"
        'tags: ["synthetic","authorization"]\n' + "---\n" + statement + "\n"
    ).encode()


def _roots(tmp_path: Path, name: str = "notes") -> tuple[Path, Path, Path]:
    notes = tmp_path / name
    notes.mkdir(mode=0o700)
    for folder in ("01_Pending", "02_Staged", "03_Prepared"):
        (notes / folder).mkdir(mode=0o700)
    home = tmp_path / f"{name}-memory-home"
    inbox = tmp_path / f"{name}-memory-inbox"
    home.mkdir(mode=0o700)
    inbox.mkdir(mode=0o700)
    return notes, home, inbox


def _configured_preview(
    tmp_path: Path,
    *,
    statement: str = PRIVATE_BODY_MARKER,
) -> tuple[Path, TransactionStore, PromotionPreview]:
    notes, home, inbox = _roots(tmp_path)
    source = b"Synthetic staged source for exact binding."
    (notes / "02_Staged" / "source.md").write_bytes(source)
    (notes / "03_Prepared" / "candidate.md").write_bytes(
        _prepared_bytes("source.md", source, statement)
    )
    state_root = tmp_path / "state"
    config = configure(
        state_root,
        notes,
        home,
        create_prepared=False,
        runner=FakeMemoryPathsRunner(home, inbox),
    )
    return (
        state_root,
        TransactionStore(state_root),
        build_preview(
            config,
            ["candidate.md"],
            [
                json.dumps(
                    {
                        "guard": {"prepared_name": "candidate.md"},
                        "governed": {"lineage_id": "lin_synthetic"},
                    }
                )
            ],
        ),
    )


def _authorize(
    tmp_path: Path,
) -> tuple[Path, TransactionStore, PromotionPreview, TransactionReceipt]:
    state_root, store, preview = _configured_preview(tmp_path)
    receipt = store.authorize(preview, preview.manifest_digest)
    return state_root, store, preview, receipt


def _warning(index: int, *, width: int = 0) -> GuardViolationNotice:
    suffix = f"_{index:02d}" + ("x" * width)
    return GuardViolationNotice(
        guard_lineage_id=f"lin_guard{suffix}",
        guard_sensitivity="restricted",
        governed_lineage_id=f"lin_governed{suffix}",
        governed_sensitivity="normal",
    )


def _persist_warnings(
    tmp_path: Path,
    warnings: tuple[GuardViolationNotice, ...],
) -> tuple[Path, TransactionStore, TransactionReceipt, TransactionReceipt]:
    state_root, store, _, receipt = _authorize(tmp_path)
    current = store.advance(receipt, TransactionState.PUBLISHING)
    current = store.advance(current, TransactionState.PUBLISHED)
    current = store.advance(current, TransactionState.CAPTURED)
    current = store.advance(current, TransactionState.REVIEW_READY)
    awaiting = store.advance(current, TransactionState.AWAITING_MEMORY_APPROVAL)
    applied = store.advance(
        awaiting,
        TransactionState.APPLIED,
        application_id="app_synthetic_warnings",
        memory_ids=("mem_synthetic_warning",),
        standing_guard_violations=warnings,
    )
    return state_root, store, awaiting, applied


def _receipt_payload_at(
    state_root: Path, receipt: TransactionReceipt
) -> dict[str, object]:
    raw = json.loads(
        (state_root / f"{receipt.transaction_id}.json").read_text(encoding="utf-8")
    )
    assert isinstance(raw, dict)
    return raw


def _write_receipt_payload(
    state_root: Path,
    receipt: TransactionReceipt,
    payload: dict[str, object],
) -> None:
    path = state_root / f"{receipt.transaction_id}.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _warning_chunk_paths(
    state_root: Path,
    receipt: TransactionReceipt,
    payload: dict[str, object],
) -> tuple[Path, ...]:
    binding = payload["standing_guard_violations"]
    assert isinstance(binding, dict)
    chunks = binding["chunks"]
    assert isinstance(chunks, list)
    paths: list[Path] = []
    for raw in chunks:
        assert isinstance(raw, dict)
        paths.append(
            state_root
            / (
                f"{receipt.transaction_id}.standing-guard-violations-"
                f"{raw['ordinal']:04d}-{raw['sha256']}.jsonl"
            )
        )
    return tuple(paths)


def test_authorization_receipt_is_body_free_private_and_canonical(
    tmp_path: Path,
) -> None:
    state_root, store, preview, receipt = _authorize(tmp_path)

    assert re.fullmatch(r"tx_[0-9a-f]{32}", receipt.transaction_id) is not None
    assert receipt.state is TransactionState.OWNER_AUTHORIZED
    assert receipt.scan_started is False
    assert receipt.manifest_digest == preview.manifest_digest
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
    all_bytes = b"".join(
        path.read_bytes() for path in state_root.iterdir() if path.is_file()
    )
    assert PRIVATE_BODY_MARKER.encode() not in all_bytes
    assert preview.candidates[0].parsed.evidence_excerpt.encode() not in all_bytes
    for path in state_root.iterdir():
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        if path.suffix == ".json":
            raw = path.read_bytes()
            assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
            assert raw == (
                json.dumps(
                    json.loads(raw),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )

    payload = json.loads((state_root / f"{receipt.transaction_id}.json").read_bytes())
    assert payload["schema"] == TRANSACTION_SCHEMA
    assert set(payload["candidates"][0]) == {
        "ordinal",
        "prepared_name",
        "source_name",
        "prepared_sha256",
        "source_sha256",
        "statement_sha256",
        "statement_utf8_bytes",
        "evidence_char_start",
        "evidence_char_end",
        "evidence_sha256",
        "client_item_id",
        "metadata",
    }
    assert payload["guard_links"] == [
        {
            "governed_item_id": None,
            "governed_lineage_id": "lin_synthetic",
            "guard_item_id": receipt.candidates[0].client_item_id,
            "guard_lineage_id": None,
        }
    ]
    assert json.loads((state_root / "active.json").read_bytes()) == {
        "transaction_id": receipt.transaction_id
    }
    assert store.load(receipt.transaction_id) == receipt


def test_authorization_is_same_digest_idempotent_and_refuses_a_second_active_set(
    tmp_path: Path,
) -> None:
    _, store, preview, first = _authorize(tmp_path)

    assert store.authorize(preview, preview.manifest_digest) == first
    config = load_config(store.state_root)
    assert config is not None
    source = b"Second synthetic staged source."
    (config.notes_root / "02_Staged" / "second.md").write_bytes(source)
    (config.notes_root / "03_Prepared" / "second.md").write_bytes(
        _prepared_bytes("second.md", source, "Second synthetic body")
    )
    changed = build_preview(config, ["second.md"], [])
    with pytest.raises(IntakeError) as caught:
        store.authorize(changed, changed.manifest_digest)
    assert caught.value.code == "transaction_active"


def test_exact_owner_authorized_supersede_retains_transaction_id(
    tmp_path: Path,
) -> None:
    state_root, store, _, first = _authorize(tmp_path)
    config = load_config(state_root)
    assert config is not None
    new_source = b"Fresh synthetic staged source for supersede."
    (config.notes_root / "02_Staged" / "source.md").write_bytes(new_source)
    (config.notes_root / "03_Prepared" / "candidate.md").write_bytes(
        _prepared_bytes("source.md", new_source, "Fresh synthetic statement")
    )
    fresh = build_preview(config, ["candidate.md"], [])

    superseded = store.authorize(
        fresh,
        fresh.manifest_digest,
        supersede_transaction_id=first.transaction_id,
        supersede_manifest_digest=first.manifest_digest,
    )

    assert superseded.transaction_id == first.transaction_id
    assert superseded.manifest_digest == fresh.manifest_digest
    assert superseded.state is TransactionState.OWNER_AUTHORIZED
    assert superseded != first
    assert store.active() == superseded


@pytest.mark.parametrize(
    ("transaction", "digest"),
    [
        (None, "old"),
        ("old", None),
        ("tx_ffffffffffffffffffffffffffffffff", "old"),
        ("old", "f" * 64),
    ],
    ids=["missing-transaction", "missing-digest", "wrong-id", "wrong-digest"],
)
def test_invalid_supersede_pair_preserves_old_receipt_bytes(
    tmp_path: Path,
    transaction: str | None,
    digest: str | None,
) -> None:
    state_root, store, _, first = _authorize(tmp_path)
    config = load_config(state_root)
    assert config is not None
    source = b"Fresh synthetic supersede bytes."
    (config.notes_root / "02_Staged" / "source.md").write_bytes(source)
    (config.notes_root / "03_Prepared" / "candidate.md").write_bytes(
        _prepared_bytes("source.md", source, "Fresh synthetic body")
    )
    fresh = build_preview(config, ["candidate.md"], [])
    receipt_path = state_root / f"{first.transaction_id}.json"
    before = receipt_path.read_bytes()
    supplied_transaction = first.transaction_id if transaction == "old" else transaction
    supplied_digest = first.manifest_digest if digest == "old" else digest

    with pytest.raises(IntakeError) as caught:
        store.authorize(
            fresh,
            fresh.manifest_digest,
            supersede_transaction_id=supplied_transaction,
            supersede_manifest_digest=supplied_digest,
        )

    assert caught.value.code == "invalid_supersede"
    assert receipt_path.read_bytes() == before
    assert store.active() == first


def test_stale_supersede_pair_and_later_state_are_forbidden(
    tmp_path: Path,
) -> None:
    state_root, store, _, first = _authorize(tmp_path)
    config = load_config(state_root)
    assert config is not None
    source = b"First fresh synthetic source."
    (config.notes_root / "02_Staged" / "source.md").write_bytes(source)
    (config.notes_root / "03_Prepared" / "candidate.md").write_bytes(
        _prepared_bytes("source.md", source, "First fresh body")
    )
    fresh = build_preview(config, ["candidate.md"], [])
    superseded = store.authorize(
        fresh,
        fresh.manifest_digest,
        supersede_transaction_id=first.transaction_id,
        supersede_manifest_digest=first.manifest_digest,
    )
    second_source = b"Second fresh synthetic source."
    (config.notes_root / "02_Staged" / "source.md").write_bytes(second_source)
    (config.notes_root / "03_Prepared" / "candidate.md").write_bytes(
        _prepared_bytes("source.md", second_source, "Second fresh body")
    )
    second = build_preview(config, ["candidate.md"], [])
    path = state_root / f"{first.transaction_id}.json"
    before = path.read_bytes()

    with pytest.raises(IntakeError) as stale:
        store.authorize(
            second,
            second.manifest_digest,
            supersede_transaction_id=first.transaction_id,
            supersede_manifest_digest=first.manifest_digest,
        )
    assert stale.value.code == "invalid_supersede"
    assert path.read_bytes() == before

    publishing = store.advance(superseded, TransactionState.PUBLISHING)
    before = path.read_bytes()
    with pytest.raises(IntakeError) as later:
        store.authorize(
            second,
            second.manifest_digest,
            supersede_transaction_id=publishing.transaction_id,
            supersede_manifest_digest=publishing.manifest_digest,
        )
    assert later.value.code == "invalid_supersede"
    assert path.read_bytes() == before


def test_authorization_revalidates_preview_and_exact_approved_digest(
    tmp_path: Path,
) -> None:
    state_root, store, preview = _configured_preview(tmp_path)
    with pytest.raises(IntakeError) as wrong:
        store.authorize(preview, "f" * 64)
    assert wrong.value.code == "wrong_manifest_digest"
    assert not (state_root / "active.json").exists()

    config = load_config(state_root)
    assert config is not None
    prepared = config.notes_root / "03_Prepared" / "candidate.md"
    prepared.write_bytes(
        prepared.read_bytes().replace(PRIVATE_BODY_MARKER.encode(), b"changed")
    )
    with pytest.raises(IntakeError) as stale:
        store.authorize(preview, preview.manifest_digest)
    assert stale.value.code == "stale_preview"
    assert not (state_root / "active.json").exists()


def test_receipt_load_rejects_truncation_schema_and_transaction_name(
    tmp_path: Path,
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    path = state_root / f"{receipt.transaction_id}.json"
    original = path.read_bytes()
    path.write_bytes(original[: len(original) // 2])
    with pytest.raises(IntakeError) as truncated:
        store.load(receipt.transaction_id)
    assert truncated.value.code == "invalid_transaction_receipt"

    payload = json.loads(original)
    payload["schema"] = "staged-memory-intake.transaction.v4"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntakeError) as unsupported:
        store.load(receipt.transaction_id)
    assert unsupported.value.code == "unsupported_transaction_schema"

    with pytest.raises(IntakeError) as invalid_name:
        store.load("../escape")
    assert invalid_name.value.code == "invalid_transaction_id"


def test_guard_warnings_round_trip_through_ordered_content_addressed_chunks(
    tmp_path: Path,
) -> None:
    warnings = tuple(_warning(index, width=70_000) for index in range(3))
    state_root, store, _, applied = _persist_warnings(tmp_path, warnings)
    payload = _receipt_payload_at(state_root, applied)
    binding = payload["standing_guard_violations"]

    assert payload["schema"] == "staged-memory-intake.transaction.v3"
    assert isinstance(binding, dict)
    assert set(binding) == {"count", "sha256", "chunks"}
    assert binding["count"] == len(warnings)
    chunks = binding["chunks"]
    assert isinstance(chunks, list)
    assert len(chunks) >= 2
    assert store.load(applied.transaction_id) == applied
    for path in _warning_chunk_paths(state_root, applied, payload):
        assert stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) == 0o600
        assert path.stat(follow_symlinks=False).st_size > 0


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "tampered",
        "symlink",
        "loose_mode",
        "wrong_order",
        "wrong_count",
        "wrong_chunk_digest",
        "wrong_total_digest",
        "duplicate_ordinal",
        "extra_binding_key",
        "extra_chunk_key",
        "noncanonical_trailing_bytes",
    ],
)
def test_guard_warning_chunk_corruption_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    warnings = tuple(_warning(index, width=70_000) for index in range(3))
    state_root, store, _, applied = _persist_warnings(tmp_path, warnings)
    payload = _receipt_payload_at(state_root, applied)
    binding = payload["standing_guard_violations"]
    assert isinstance(binding, dict)
    chunks = binding["chunks"]
    assert isinstance(chunks, list) and len(chunks) >= 2
    paths = _warning_chunk_paths(state_root, applied, payload)

    if mutation == "missing":
        paths[0].unlink()
    elif mutation == "tampered":
        paths[0].write_bytes(
            paths[0].read_bytes().replace(b"lin_guard", b"lin_guarf", 1)
        )
        binding["sha256"] = hashlib.sha256(
            b"".join(path.read_bytes() for path in paths)
        ).hexdigest()
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "symlink":
        target = state_root / "synthetic-warning-target"
        paths[0].rename(target)
        paths[0].symlink_to(target)
    elif mutation == "loose_mode":
        paths[0].chmod(0o644)
    elif mutation == "wrong_order":
        chunks.reverse()
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "wrong_count":
        first = chunks[0]
        assert isinstance(first, dict)
        first["count"] = int(first["count"]) + 1
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "wrong_chunk_digest":
        first = chunks[0]
        assert isinstance(first, dict)
        first["sha256"] = "f" * 64
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "wrong_total_digest":
        binding["sha256"] = "f" * 64
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "duplicate_ordinal":
        second = chunks[1]
        assert isinstance(second, dict)
        second["ordinal"] = 0
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "extra_binding_key":
        binding["path"] = "synthetic-not-accepted"
        _write_receipt_payload(state_root, applied, payload)
    elif mutation == "extra_chunk_key":
        first = chunks[0]
        assert isinstance(first, dict)
        first["path"] = "synthetic-not-accepted"
        _write_receipt_payload(state_root, applied, payload)
    else:
        paths[0].write_bytes(paths[0].read_bytes() + b"\n")

    with pytest.raises(IntakeError) as caught:
        store.load(applied.transaction_id)
    assert caught.value.code == "invalid_transaction_receipt"


def test_chunk_failure_before_receipt_replace_preserves_prior_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    current = store.advance(receipt, TransactionState.PUBLISHING)
    current = store.advance(current, TransactionState.PUBLISHED)
    current = store.advance(current, TransactionState.CAPTURED)
    current = store.advance(current, TransactionState.REVIEW_READY)
    awaiting = store.advance(current, TransactionState.AWAITING_MEMORY_APPROVAL)
    receipt_path = state_root / f"{receipt.transaction_id}.json"
    before = receipt_path.read_bytes()

    def fail_receipt_replace(path: Path, payload: object) -> None:
        del path, payload
        raise OSError("synthetic receipt replacement failure")

    monkeypatch.setattr(state_module, "atomic_private_json", fail_receipt_replace)
    with pytest.raises(OSError):
        store.advance(
            awaiting,
            TransactionState.APPLIED,
            application_id="app_synthetic_warning_failure",
            memory_ids=("mem_synthetic_warning",),
            standing_guard_violations=(_warning(0, width=300_000),),
        )

    assert tuple(state_root.glob("*.standing-guard-violations-*.jsonl"))
    assert receipt_path.read_bytes() == before
    assert store.load(receipt.transaction_id) == awaiting


def test_receipt_size_is_preflighted_before_writing_warning_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    current = store.advance(receipt, TransactionState.PUBLISHING)
    current = store.advance(current, TransactionState.PUBLISHED)
    current = store.advance(current, TransactionState.CAPTURED)
    current = store.advance(current, TransactionState.REVIEW_READY)
    awaiting = store.advance(current, TransactionState.AWAITING_MEMORY_APPROVAL)
    path = state_root / f"{receipt.transaction_id}.json"
    before = path.read_bytes()
    monkeypatch.setattr(state_module, "_RECEIPT_WRITE_LIMIT", 1, raising=False)

    with pytest.raises(IntakeError) as caught:
        store.advance(
            awaiting,
            TransactionState.APPLIED,
            application_id="app_synthetic_warning_limit",
            memory_ids=("mem_synthetic_warning",),
            standing_guard_violations=(_warning(0),),
        )

    assert caught.value.code == "invalid_transaction_update"
    assert path.read_bytes() == before
    assert tuple(state_root.glob("*.standing-guard-violations-*.jsonl")) == ()


def test_device_bound_legacy_schemas_are_refused_not_reinterpreted(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "synthetic-legacy-state"
    state_root.mkdir(mode=0o700)
    transaction_id = "tx_11111111111111111111111111111111"
    warning = _warning(0)
    payload: dict[str, object] = {
        "application_id": None,
        "batch_id": None,
        "batch_sensitivity": "restricted",
        "candidates": [
            {
                "client_item_id": "itm_synthetic_legacy",
                "evidence_char_end": 8,
                "evidence_char_start": 0,
                "evidence_sha256": "d" * 64,
                "metadata": {
                    "kind": "fact",
                    "occurred_on": None,
                    "sensitivity": "restricted",
                    "tags": ["synthetic", "legacy"],
                    "valid_from": None,
                    "valid_to": None,
                },
                "ordinal": 0,
                "prepared_name": "candidate.md",
                "prepared_sha256": "a" * 64,
                "source_name": "source.md",
                "source_sha256": "b" * 64,
                "statement_sha256": "c" * 64,
                "statement_utf8_bytes": 24,
            }
        ],
        "change_set_id": None,
        "cleanup_entries": [],
        "duplicate_notices": [],
        "guard_links": [],
        "inbox_identity": {"device": 31, "inode": 32},
        "manifest_digest": "e" * 64,
        "memory_home": None,
        "memory_ids": [],
        "memory_inbox": "/synthetic/legacy-inbox",
        "notes_identity": {"device": 21, "inode": 22},
        "notes_root": "/synthetic/legacy-notes",
        "published_files": [],
        "review_digest": None,
        "revision_id": None,
        "scan_has_more": None,
        "scan_issues": [],
        "scan_page_has_more": None,
        "scan_source_ids": [],
        "scan_started": False,
        "schema": "staged-memory-intake.transaction.v1",
        "source_bindings": [],
        "standing_guard_violations": [
            {
                "governed_lineage_id": warning.governed_lineage_id,
                "governed_sensitivity": warning.governed_sensitivity,
                "guard_lineage_id": warning.guard_lineage_id,
                "guard_sensitivity": warning.guard_sensitivity,
            }
        ],
        "state": "owner_authorized",
        "transaction_id": transaction_id,
    }
    receipt_path = state_root / f"{transaction_id}.json"
    receipt_path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    active_path = state_root / "active.json"
    active_path.write_text(
        json.dumps({"transaction_id": transaction_id}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    active_path.chmod(0o600)
    store = TransactionStore(state_root)

    with pytest.raises(IntakeError) as caught:
        store.load(transaction_id)

    assert caught.value.code == "unsupported_transaction_schema"
    assert receipt_path.read_bytes() != b""


def _write_legacy_receipt_pointer(state_root: Path, transaction_id: str) -> Path:
    """Persist one pre-v3 receipt and the active pointer naming it."""
    payload = {
        "schema": "staged-memory-intake.transaction.v2",
        "transaction_id": transaction_id,
        "state": "publishing",
    }
    receipt_path = state_root / f"{transaction_id}.json"
    receipt_path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    active_path = state_root / "active.json"
    active_path.write_text(
        json.dumps({"transaction_id": transaction_id}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    active_path.chmod(0o600)
    return receipt_path


def test_abandon_unsupported_transaction_unwedges_the_store(tmp_path: Path) -> None:
    """Catch a pre-v3 receipt refusing every command with no escape.

    Device-bound receipts are refused, never reinterpreted -- but the refusal
    used to be terminal: the active pointer kept naming the unsupported
    receipt and no command could remove it. The explicit hatch quarantines
    exactly that receipt, keeps its bytes for the owner, and releases the
    pointer.
    """
    state_root = tmp_path / "synthetic-wedged-state"
    state_root.mkdir(mode=0o700)
    transaction_id = "tx_" + "2" * 32
    _write_legacy_receipt_pointer(state_root, transaction_id)
    store = TransactionStore(state_root)
    with pytest.raises(IntakeError) as wedged:
        store.active()
    assert wedged.value.code == "unsupported_transaction_schema"

    abandoned = abandon_unsupported_transaction(state_root)

    assert abandoned == (transaction_id,)
    assert store.active() is None
    assert not (state_root / "active.json").exists()
    quarantined = sorted(state_root.glob(f"abandoned-{transaction_id}.json.*"))
    assert len(quarantined) == 1
    preserved = json.loads(quarantined[0].read_text(encoding="utf-8"))
    assert preserved["schema"] == "staged-memory-intake.transaction.v2"
    assert abandon_unsupported_transaction(state_root) == ()


def test_abandon_never_touches_a_current_schema_transaction(tmp_path: Path) -> None:
    """Catch the escape hatch reaching a live, recoverable transaction."""
    state_root, store, _, receipt = _authorize(tmp_path)

    assert abandon_unsupported_transaction(state_root) == ()

    active = store.active()
    assert active is not None
    assert active.transaction_id == receipt.transaction_id
    assert sorted(state_root.glob("abandoned-*")) == []


def test_dangling_active_pointer_is_corruption_not_absence(tmp_path: Path) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    pointer = state_root / "active.json"
    pointer.unlink()
    pointer.symlink_to(state_root / "synthetic-missing-target")

    with pytest.raises(IntakeError) as caught:
        store.active()

    assert caught.value.code == "invalid_active_transaction"
    assert pointer.is_symlink()
    assert store.load(receipt.transaction_id) == receipt


def test_store_lock_is_nonblocking_and_private(tmp_path: Path) -> None:
    state_root, store, _ = _configured_preview(tmp_path)
    with store.lock():
        contender = TransactionStore(state_root)
        with pytest.raises(IntakeError) as caught:
            with contender.lock():
                raise AssertionError("unreachable")
        assert caught.value.code == "transaction_busy"
        assert caught.value.retryable is True
    lock_path = state_root / ".transaction.lock"
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_lock_is_acquired_before_active_pointer_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, store, preview = _configured_preview(tmp_path)
    lock_fd = os.open(state_root / ".transaction.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    called = False
    original = Path.read_bytes

    def observed(path: Path) -> bytes:
        nonlocal called
        if path.name == "active.json":
            called = True
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", observed)
    try:
        with pytest.raises(IntakeError) as caught:
            store.authorize(preview, preview.manifest_digest)
        assert caught.value.code == "transaction_busy"
        assert called is False
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def test_receipt_replace_failures_never_publish_a_partial_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    path = state_root / f"{receipt.transaction_id}.json"
    original = path.read_bytes()
    publishing = replace(receipt, state=TransactionState.PUBLISHING)
    real_replace = os.replace

    def fail_before(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("synthetic before replace")

    monkeypatch.setattr(os, "replace", fail_before)
    with pytest.raises(OSError):
        store.advance(receipt, TransactionState.PUBLISHING)
    assert path.read_bytes() == original
    assert store.load(receipt.transaction_id) == receipt

    monkeypatch.setattr(os, "replace", real_replace)
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic directory fsync")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError):
        store.advance(receipt, TransactionState.PUBLISHING)
    assert store.load(receipt.transaction_id) == publishing
    assert path.read_bytes().endswith(b"\n")


def test_all_state_edges_are_exact_and_complete_clears_only_active_pointer(
    tmp_path: Path,
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    current = receipt
    for index, state in enumerate(STATE_ORDER):
        assert current.state is state
        assert store.advance(current, state) == current
        for disallowed in STATE_ORDER:
            if disallowed not in {state} and (
                index + 1 >= len(STATE_ORDER)
                or disallowed is not STATE_ORDER[index + 1]
            ):
                with pytest.raises(IntakeError) as caught:
                    store.advance(current, disallowed)
                assert caught.value.code == "invalid_state_transition"
        if index + 1 < len(STATE_ORDER):
            current = store.advance(current, STATE_ORDER[index + 1])

    assert current.state is TransactionState.COMPLETE
    assert store.active() is None
    assert not (state_root / "active.json").exists()
    assert store.load(current.transaction_id) == current


def test_complete_receipt_recovers_pointer_clear_after_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, store, _, current = _authorize(tmp_path)
    for next_state in STATE_ORDER[1:-1]:
        current = store.advance(current, next_state)
    real_unlink = os.unlink

    def interrupted_unlink(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("synthetic pointer-clear interruption")

    monkeypatch.setattr(os, "unlink", interrupted_unlink)
    with pytest.raises(OSError):
        store.advance(current, TransactionState.COMPLETE)
    monkeypatch.setattr(os, "unlink", real_unlink)

    complete = store.load(current.transaction_id)
    assert complete.state is TransactionState.COMPLETE
    assert store.active() is None
    assert not (state_root / "active.json").exists()


def test_advance_rejects_stale_receipt_and_unknown_update(tmp_path: Path) -> None:
    _, store, _, receipt = _authorize(tmp_path)
    current = store.advance(receipt, TransactionState.PUBLISHING)
    with pytest.raises(IntakeError) as stale:
        store.advance(receipt, TransactionState.PUBLISHING)
    assert stale.value.code == "stale_transaction_receipt"
    with pytest.raises(IntakeError) as unknown:
        store.advance(current, TransactionState.PUBLISHED, not_a_field=True)
    assert unknown.value.code == "invalid_transaction_update"


def test_advance_rejects_invalid_runtime_update_type_without_mutation(
    tmp_path: Path,
) -> None:
    _, store, _, receipt = _authorize(tmp_path)
    publishing = store.advance(receipt, TransactionState.PUBLISHING)
    published = store.advance(publishing, TransactionState.PUBLISHED)

    with pytest.raises(IntakeError) as caught:
        store.advance(published, TransactionState.CAPTURED, batch_id=7)

    assert caught.value.code == "invalid_transaction_update"
    assert store.active() == published


def test_published_scan_marker_round_trips_as_one_body_free_same_state_update(
    tmp_path: Path,
) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    publishing = store.advance(receipt, TransactionState.PUBLISHING)
    with pytest.raises(IntakeError) as premature_marker:
        store.advance(
            publishing,
            TransactionState.PUBLISHED,
            scan_started=True,
        )
    assert premature_marker.value.code == "invalid_transaction_update"
    published = store.advance(publishing, TransactionState.PUBLISHED)

    assert published.scan_started is False
    started = store.advance(
        published,
        TransactionState.PUBLISHED,
        scan_started=True,
    )

    assert started.scan_started is True
    assert store.load(started.transaction_id) == started
    assert (
        store.advance(
            started,
            TransactionState.PUBLISHED,
            scan_started=True,
        )
        == started
    )
    payload = json.loads((state_root / f"{started.transaction_id}.json").read_bytes())
    assert payload["scan_started"] is True
    with pytest.raises(IntakeError) as reversed_marker:
        store.advance(
            started,
            TransactionState.PUBLISHED,
            scan_started=False,
        )
    assert reversed_marker.value.code == "invalid_transaction_update"
    assert store.active() == started


def test_receipt_requires_one_strict_boolean_scan_marker(tmp_path: Path) -> None:
    state_root, store, _, receipt = _authorize(tmp_path)
    path = state_root / f"{receipt.transaction_id}.json"
    payload = json.loads(path.read_bytes())
    del payload["scan_started"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IntakeError) as missing:
        store.load(receipt.transaction_id)

    assert missing.value.code == "invalid_transaction_receipt"


def test_advance_rejects_immutable_authorization_field_update(
    tmp_path: Path,
) -> None:
    _, store, _, receipt = _authorize(tmp_path)

    with pytest.raises(IntakeError) as caught:
        store.advance(
            receipt,
            TransactionState.PUBLISHING,
            notes_root="/synthetic/changed-authority",
        )

    assert caught.value.code == "invalid_transaction_update"
    assert store.active() == receipt


def test_replace_rejects_stale_receipt_overwriting_newer_facts(
    tmp_path: Path,
) -> None:
    _, store, _, receipt = _authorize(tmp_path)
    publishing = store.advance(receipt, TransactionState.PUBLISHING)
    published_file = PublishedFile(
        ordinal=0,
        prepared_name="candidate.md",
        inbox_name="00-synthetic-candidate.md",
        sha256=receipt.candidates[0].prepared_sha256,
        byte_length=57,
    )
    current = store.advance(
        publishing,
        TransactionState.PUBLISHED,
        published_files=(published_file,),
    )
    stale_overwrite = replace(
        publishing,
        state=TransactionState.PUBLISHED,
        published_files=(),
    )

    with pytest.raises(IntakeError) as caught:
        store.replace(stale_overwrite)

    assert caught.value.code == "stale_transaction_receipt"
    assert store.active() == current


def test_reconfiguration_rejects_active_transaction(tmp_path: Path) -> None:
    state_root, store, _, _ = _authorize(tmp_path)
    old = load_config(state_root)
    assert old is not None
    proposed, _, _ = _roots(tmp_path, "proposed")

    with pytest.raises(IntakeError) as caught:
        validate_reconfiguration(store, old, proposed)
    assert caught.value.code == "transaction_active"


def test_unconfigured_reconfiguration_validates_only_proposed_root(
    tmp_path: Path,
) -> None:
    proposed, _, _ = _roots(tmp_path, "proposed")
    state_root = tmp_path / "new-state"

    validate_reconfiguration(TransactionStore(state_root), None, proposed)

    assert state_root.exists()
    assert not (state_root / "config.json").exists()
    assert not (tmp_path / "old-notes").exists()


def test_reconfiguration_requires_every_old_prepared_binding_in_new_staged(
    tmp_path: Path,
) -> None:
    state_root, _, preview = _configured_preview(tmp_path, statement="Synthetic body")
    old = load_config(state_root)
    assert old is not None
    proposed, _, _ = _roots(tmp_path, "proposed")
    old_source = (old.notes_root / "02_Staged" / "source.md").read_bytes()
    (proposed / "02_Staged" / "source.md").write_bytes(old_source)
    (proposed / "03_Prepared" / "candidate.md").write_bytes(
        (old.notes_root / "03_Prepared" / "candidate.md").read_bytes()
    )
    store = TransactionStore(state_root)

    validate_reconfiguration(store, old, proposed)
    (proposed / "02_Staged" / "source.md").write_bytes(b"changed synthetic source")
    with pytest.raises(IntakeError) as changed:
        validate_reconfiguration(store, old, proposed)
    assert changed.value.code == "relocation_binding_changed"

    (proposed / "02_Staged" / "source.md").unlink()
    with pytest.raises(IntakeError) as missing:
        validate_reconfiguration(store, old, proposed)
    assert missing.value.code == "relocation_binding_changed"
    assert preview is not None


@pytest.mark.parametrize("proposed_prepared", [None, b"changed prepared bytes"])
def test_reconfiguration_requires_same_prepared_artifact_in_proposed_root(
    tmp_path: Path,
    proposed_prepared: bytes | None,
) -> None:
    state_root, _, _ = _configured_preview(tmp_path, statement="Synthetic body")
    old = load_config(state_root)
    assert old is not None
    proposed, _, _ = _roots(tmp_path, "proposed")
    (proposed / "02_Staged" / "source.md").write_bytes(
        (old.notes_root / "02_Staged" / "source.md").read_bytes()
    )
    if proposed_prepared is not None:
        (proposed / "03_Prepared" / "candidate.md").write_bytes(proposed_prepared)

    with pytest.raises(IntakeError) as caught:
        validate_reconfiguration(TransactionStore(state_root), old, proposed)

    assert caught.value.code == "relocation_binding_changed"


def test_reconfiguration_accepts_exact_prepared_and_staged_binding(
    tmp_path: Path,
) -> None:
    state_root, _, _ = _configured_preview(tmp_path, statement="Synthetic body")
    old = load_config(state_root)
    assert old is not None
    proposed, _, _ = _roots(tmp_path, "proposed")
    for folder, name in (("03_Prepared", "candidate.md"), ("02_Staged", "source.md")):
        (proposed / folder / name).write_bytes(
            (old.notes_root / folder / name).read_bytes()
        )

    validate_reconfiguration(TransactionStore(state_root), old, proposed)


def test_failed_configure_relocation_preserves_old_config_bytes(
    tmp_path: Path,
) -> None:
    state_root, _, _ = _configured_preview(tmp_path, statement="Synthetic body")
    old = load_config(state_root)
    assert old is not None
    before = (state_root / "config.json").read_bytes()
    proposed, _, _ = _roots(tmp_path, "proposed")
    (proposed / "02_Staged" / "source.md").write_bytes(b"wrong")

    with pytest.raises(IntakeError) as caught:
        configure(
            state_root,
            proposed,
            old.memory_home,
            create_prepared=False,
            runner=FakeMemoryPathsRunner(
                Path(old.memory_home) if old.memory_home is not None else tmp_path,
                old.memory_inbox,
            ),
        )
    assert caught.value.code == "relocation_binding_changed"
    assert (state_root / "config.json").read_bytes() == before


def test_configure_relocation_cannot_repoint_memory_inbox(tmp_path: Path) -> None:
    state_root, _, _ = _configured_preview(tmp_path, statement="Synthetic body")
    old = load_config(state_root)
    assert old is not None
    before = (state_root / "config.json").read_bytes()
    proposed, home, different_inbox = _roots(tmp_path, "proposed")
    (proposed / "02_Staged" / "source.md").write_bytes(
        (old.notes_root / "02_Staged" / "source.md").read_bytes()
    )

    with pytest.raises(IntakeError) as caught:
        configure(
            state_root,
            proposed,
            home,
            create_prepared=False,
            runner=FakeMemoryPathsRunner(home, different_inbox),
        )

    assert caught.value.code == "memory_inbox_reconfiguration_required"
    assert (state_root / "config.json").read_bytes() == before
