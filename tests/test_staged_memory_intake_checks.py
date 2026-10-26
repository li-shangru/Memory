"""Strict synthetic Memory snapshot planning and equality tests."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from staged_memory_intake.checks import (
    begin_scan,
    build_review_edits,
    check_batch,
    check_memories,
    check_review,
    mark_awaiting_approval,
    parse_success_envelope,
    record_application,
    record_scan,
)
from staged_memory_intake.model import (
    IntakeConfig,
    IntakeError,
    PublishedFile,
    ReceiptGuardLink,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import build_preview
from staged_memory_intake.publish import published_name
from staged_memory_intake.securefs import directory_identity
from staged_memory_intake.state import TransactionStore
from staged_memory_intake_fakes import memory_success_envelope
from synthetic import apply_ready

from memory.mcp_server import call_tool
from memory.model import RuntimePaths
from memory.reviews import get_change_set

HASH_A = "a" * 64
HASH_B = "b" * 64


def _prepared_bytes(
    source_name: str,
    source: bytes,
    statement: str,
    *,
    kind: str,
    sensitivity: str,
    occurred_on: str = "",
    valid_from: str = "",
    valid_to: str = "",
    tags: str,
) -> bytes:
    return (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
        f"kind: {kind}\n"
        f"sensitivity: {sensitivity}\n"
        f"occurred_on: {occurred_on}\n"
        f"valid_from: {valid_from}\n"
        f"valid_to: {valid_to}\n"
        f"tags: {tags}\n"
        "---\n"
        f"{statement}\n"
    ).encode()


@dataclass(frozen=True)
class SnapshotSetup:
    config: IntakeConfig
    receipt: TransactionReceipt
    scan: dict[str, object]
    batch: dict[str, object]
    review: dict[str, object]
    application: dict[str, object]
    memories: dict[str, object]


def _source_summary(
    source_id: str,
    name: str,
    digest: str,
    length: int,
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "origin": "inbox",
        "blob_digest": digest,
        "original_name": name,
        "media_type": "text/markdown",
        "byte_length": length,
        "authorship": "mixed",
        "declared_sensitivity": "sensitive",
        "effective_sensitivity": "sensitive",
        "searchable": True,
        "captured_at": 1_775_000_000,
    }


def _memory_fields(
    receipt: TransactionReceipt,
    ordinal: int,
    statement: str,
) -> dict[str, object]:
    metadata = receipt.candidates[ordinal].metadata
    return {
        "kind": metadata.kind,
        "statement": statement,
        "occurred_on": metadata.occurred_on,
        "valid_from": metadata.valid_from,
        "valid_to": metadata.valid_to,
        "tags": list(metadata.tags),
        "sensitivity": receipt.batch_sensitivity,
        "target_lineage_id": None,
        "expected_head_id": None,
    }


def _summary(
    receipt: TransactionReceipt,
    ordinal: int,
    statement: str,
) -> dict[str, object]:
    metadata = receipt.candidates[ordinal].metadata
    summary: dict[str, object] = {
        "memory_id": f"mem_{ordinal}",
        "lineage_id": f"lin_new_{ordinal}",
        "kind": metadata.kind,
        "statement": statement,
        "tags": list(metadata.tags),
        "stored_sensitivity": receipt.batch_sensitivity,
        "effective_sensitivity": receipt.batch_sensitivity,
        "recorded_at": 1_775_000_100 + ordinal,
    }
    if metadata.occurred_on is not None:
        summary["occurred_on"] = metadata.occurred_on
    if metadata.valid_from is not None:
        summary["valid_from"] = metadata.valid_from
    if metadata.valid_to is not None:
        summary["valid_to"] = metadata.valid_to
    return summary


def _attachment(summary: dict[str, object]) -> dict[str, object]:
    return {
        "memory_id": summary["memory_id"],
        "lineage_id": summary["lineage_id"],
        "kind": summary["kind"],
        "statement": summary["statement"],
        "effective_sensitivity": summary["effective_sensitivity"],
    }


def _setup(
    tmp_path: Path,
    *,
    statement_values: tuple[str, str] | None = None,
) -> SnapshotSetup:
    notes = tmp_path / "synthetic-notes"
    pending_root = notes / "01_Pending"
    prepared_root = notes / "03_Prepared"
    staged_root = notes / "02_Staged"
    inbox = tmp_path / "synthetic-inbox"
    home = tmp_path / "synthetic-memory-home"
    for path in (notes, pending_root, prepared_root, staged_root, inbox, home):
        path.mkdir(mode=0o700)
    source_values = (
        b"Synthetic retained source alpha.",
        "Synthetic retained source beta with Unicode 界.".encode(),
    )
    statements = statement_values or (
        "Synthetic exact statement alpha.",
        "Synthetic exact statement beta with Unicode 界.",
    )
    prepared_values = (
        _prepared_bytes(
            "alpha-source.md",
            source_values[0],
            statements[0],
            kind="fact",
            sensitivity="normal",
            tags='["synthetic","alpha"]',
        ),
        _prepared_bytes(
            "beta-source.md",
            source_values[1],
            statements[1],
            kind="preference",
            sensitivity="sensitive",
            occurred_on="2026-08",
            valid_from="2026-08-01",
            tags='["synthetic","beta"]',
        ),
    )
    for name, value in zip(
        ("alpha-source.md", "beta-source.md"), source_values, strict=True
    ):
        (staged_root / name).write_bytes(value)
    for name, value in zip(("alpha.md", "beta.md"), prepared_values, strict=True):
        (prepared_root / name).write_bytes(value)
    config = IntakeConfig(
        notes_root=notes,
        notes_identity=directory_identity(notes),
        memory_home=home,
        memory_inbox=inbox,
        inbox_identity=directory_identity(inbox),
    )
    guards = (
        '{"guard":{"prepared_name":"alpha.md"},"governed":{"prepared_name":"beta.md"}}',
        '{"guard":{"prepared_name":"beta.md"},'
        '"governed":{"lineage_id":"lin_existing"}}',
    )
    preview = build_preview(config, ["alpha.md", "beta.md"], guards)
    state_root = tmp_path / "synthetic-state"
    state_root.mkdir(mode=0o700)
    # Authorize uses the same public-filesystem-only preview rebuild as production.
    config_path = state_root / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema": "staged-memory-intake.config.v2",
                "notes_root": str(notes),
                "notes_identity": {
                    "volume": config.notes_identity.volume,
                    "inode": config.notes_identity.inode,
                },
                "memory_home": str(home),
                "memory_inbox": str(inbox),
                "inbox_identity": {
                    "volume": config.inbox_identity.volume,
                    "inode": config.inbox_identity.inode,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    receipt = TransactionStore(state_root).authorize(preview, preview.manifest_digest)
    published_files = tuple(
        PublishedFile(
            ordinal=candidate.ordinal,
            prepared_name=candidate.parsed.prepared_name,
            inbox_name=published_name(
                receipt.transaction_id,
                receipt.candidates[candidate.ordinal],
            ),
            sha256=candidate.parsed.prepared_sha256,
            byte_length=len(prepared_values[candidate.ordinal]),
        )
        for candidate in preview.candidates
    )
    receipt = replace(
        receipt,
        state=TransactionState.PUBLISHED,
        published_files=published_files,
    )
    receipt = begin_scan(receipt)
    source_ids = ["src_alpha", "src_beta"]
    batch_data: dict[str, object] = {
        "batch_id": "bat_exact",
        "sealed_at": 1_775_000_000,
        "source_count": 2,
        "source_ids": source_ids,
        "batch_has_more": False,
        "issues": [],
        "duplicates": [],
        "review_state": "none",
    }
    scan = memory_success_envelope(batch_data, page={"has_more": False})
    sources = [
        _source_summary(
            source_ids[index],
            published.inbox_name,
            published.sha256,
            published.byte_length,
        )
        for index, published in enumerate(published_files)
    ]
    batch = memory_success_envelope({"batch": batch_data, "sources": sources})

    captured = check_batch(record_scan(receipt, scan), batch)
    parsed = preview.candidates
    items: list[dict[str, object]] = []
    decisions: list[dict[str, object]] = []
    for ordinal, candidate in enumerate(parsed):
        binding = captured.source_bindings[ordinal]
        items.append(
            {
                "ordinal": ordinal,
                "item_id": candidate.client_item_id,
                "status": "active",
                "memory": _memory_fields(captured, ordinal, candidate.parsed.statement),
                "evidence": [
                    {
                        "ordinal": 0,
                        "source_id": binding.source_id,
                        "blob_digest": binding.blob_digest,
                        "mode": "text",
                        "char_start": candidate.parsed.evidence_char_start,
                        "char_end": candidate.parsed.evidence_char_end,
                        "excerpt": candidate.parsed.evidence_excerpt,
                    }
                ],
            }
        )
        decisions.append(
            {
                "ordinal": ordinal,
                "source_id": binding.source_id,
                "blob_digest": binding.blob_digest,
                "state": "used",
                "reason": None,
            }
        )
    review_data: dict[str, object] = {
        "change_set_id": "chg_exact",
        "batch_id": "bat_exact",
        "state": "draft",
        "revision_id": "rev_exact",
        "digest": HASH_A,
        "adapter_origin": "mcp",
        "items": items,
        "source_decisions": decisions,
        "guard_links": [
            {
                "ordinal": 0,
                "guard_item_id": receipt.candidates[0].client_item_id,
                "guard_lineage_id": None,
                "governed_item_id": receipt.candidates[1].client_item_id,
                "governed_lineage_id": None,
                "status": "active",
            },
            {
                "ordinal": 1,
                "guard_item_id": receipt.candidates[1].client_item_id,
                "guard_lineage_id": None,
                "governed_item_id": None,
                "governed_lineage_id": "lin_existing",
                "status": "active",
            },
        ],
        "revoked_guard_links": [],
    }
    review = memory_success_envelope(review_data)
    application = memory_success_envelope(
        {
            "application_id": "app_exact",
            "change_set_id": "chg_exact",
            "revision_id": "rev_exact",
            "memory_ids": ["mem_0", "mem_1"],
            "idempotent_replay": False,
            "standing_guard_violations": [
                {
                    "guard_lineage_id": "lin_warning_guard",
                    "guard_sensitivity": "restricted",
                    "governed_lineage_id": "lin_warning_claim",
                    "governed_sensitivity": "normal",
                }
            ],
        }
    )

    summaries = [
        _summary(captured, ordinal, statements[ordinal]) for ordinal in range(2)
    ]
    existing = {
        "memory_id": "mem_existing",
        "lineage_id": "lin_existing",
        "kind": "fact",
        "statement": "Synthetic existing governed statement.",
        "effective_sensitivity": "sensitive",
    }
    details: list[dict[str, object]] = []
    for ordinal, candidate in enumerate(parsed):
        binding = captured.source_bindings[ordinal]
        details.append(
            {
                "revision": summaries[ordinal],
                "is_current": True,
                "current_head_id": f"mem_{ordinal}",
                "revision_ids": [f"mem_{ordinal}"],
                "evidence": [
                    {
                        "ordinal": 0,
                        "source_id": binding.source_id,
                        "blob_digest": binding.blob_digest,
                        "mode": "text",
                        "char_start": candidate.parsed.evidence_char_start,
                        "char_end": candidate.parsed.evidence_char_end,
                        "excerpt": candidate.parsed.evidence_excerpt,
                    }
                ],
                "guards": [] if ordinal == 0 else [_attachment(summaries[0])],
                "governs": (
                    [_attachment(summaries[1])] if ordinal == 0 else [existing]
                ),
            }
        )
    memories = memory_success_envelope(details)
    return SnapshotSetup(
        config=config,
        receipt=receipt,
        scan=scan,
        batch=batch,
        review=review,
        application=application,
        memories=memories,
    )


def _error_code(action: Callable[[], object], expected: str) -> None:
    with pytest.raises(IntakeError) as caught:
        action()
    assert caught.value.code == expected
    assert str(caught.value) == expected


def test_snapshot_errors_preserve_state_drift_and_memory_categories(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    with pytest.raises(IntakeError) as wrong_state:
        build_review_edits(setup.receipt, setup.config)
    assert wrong_state.value.category == "state"

    changed_path = setup.config.notes_root / "03_Prepared" / "alpha.md"
    changed_path.write_bytes(changed_path.read_bytes().replace(b"alpha.", b"changed."))
    with pytest.raises(IntakeError) as drift:
        build_review_edits(captured, setup.config)
    assert drift.value.category == "drift"

    with pytest.raises(IntakeError) as memory:
        check_batch(captured, memory_success_envelope({}))
    assert memory.value.category == "memory"


def test_scan_must_be_durably_started_before_call_or_recovery(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    unstarted = replace(setup.receipt, scan_started=False)

    _error_code(
        lambda: record_scan(unstarted, setup.scan),
        "scan_not_started",
    )
    _error_code(
        lambda: check_batch(unstarted, setup.batch),
        "scan_not_started",
    )
    started = begin_scan(unstarted)
    assert started.state is TransactionState.PUBLISHED
    assert started.scan_started is True
    assert begin_scan(started) == started
    malformed = copy.deepcopy(setup.scan)
    del cast(dict[str, object], malformed["data"])["batch_id"]
    _error_code(lambda: record_scan(started, malformed), "invalid_scan_snapshot")
    assert started.scan_started is True
    assert started.batch_id is None
    assert check_batch(started, setup.batch).state is TransactionState.CAPTURED


def test_scan_started_marker_is_body_free_and_has_no_content_channel(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    started = begin_scan(replace(setup.receipt, scan_started=False))

    assert started.scan_started is True
    assert started.batch_id is None
    assert started.scan_source_ids == ()
    assert started.scan_issues == ()
    assert started.duplicate_notices == ()


def test_begin_scan_matches_the_only_persistable_marker_update(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    unstarted = replace(setup.receipt, scan_started=False)

    assert begin_scan(unstarted) == replace(unstarted, scan_started=True)


def test_scan_start_rejects_every_other_state(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    started = begin_scan(setup.receipt)
    captured = check_batch(started, setup.batch)

    _error_code(lambda: begin_scan(captured), "invalid_snapshot_state")


def test_parse_success_envelope_is_bounded_strict_and_duplicate_safe() -> None:
    valid = b'{"schema":"memory.mcp.v1","instruction_trust":"inert","data":[]}'
    assert parse_success_envelope(valid) == {
        "schema": "memory.mcp.v1",
        "instruction_trust": "inert",
        "data": [],
    }
    exactly_bounded = valid + b" " * (8 * 1024 * 1024 - len(valid))
    assert parse_success_envelope(exactly_bounded) == parse_success_envelope(valid)
    invalid = (
        b'{"schema":"memory.mcp.v1","instruction_trust":"inert","data":[],"data":{}}'
    )
    error = b'{"schema":"memory.mcp.v1","instruction_trust":"inert","error":{}}'
    invalid_constant = (
        b'{"schema":"memory.mcp.v1","instruction_trust":"inert","data":NaN}'
    )
    utf16 = '{"schema":"memory.mcp.v1","instruction_trust":"inert","data":[]}'.encode(
        "utf-16"
    )
    for raw in (
        b"[]",
        b"\xff",
        invalid,
        error,
        invalid_constant,
        utf16,
        valid + b" " * (8 * 1024 * 1024),
    ):
        _error_code(partial(parse_success_envelope, raw), "invalid_memory_envelope")


def test_record_scan_records_irreversible_success_before_manifest_checks(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    wrong = copy.deepcopy(setup.scan)
    data = cast(dict[str, object], wrong["data"])
    data["source_count"] = 1
    data["source_ids"] = ["src_unexpected"]
    data["batch_has_more"] = True
    data["issues"] = [{"code": "changed", "count": 2}]
    data["duplicates"] = [{"source_id": "src_unexpected", "duplicate_of": "src_prior"}]
    wrong["issues"] = [{"code": "changed", "count": 2}]

    captured = record_scan(setup.receipt, wrong)

    assert captured.state is TransactionState.CAPTURED
    assert captured.batch_id == "bat_exact"
    assert captured.scan_source_ids == ("src_unexpected",)
    assert captured.scan_issues[0].code == "changed"
    assert captured.scan_has_more is True
    assert captured.scan_page_has_more is False
    assert captured.duplicate_notices[0].duplicate_of == "src_prior"
    assert record_scan(captured, wrong) == captured
    another = copy.deepcopy(wrong)
    cast(dict[str, object], another["data"])["batch_id"] = "bat_second"
    _error_code(lambda: record_scan(captured, another), "scan_result_changed")


def test_scan_page_deferment_is_recorded_then_rejected_by_batch_check(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.scan)
    cast(dict[str, object], changed["page"])["has_more"] = True

    captured = record_scan(setup.receipt, changed)

    assert captured.scan_page_has_more is True
    _error_code(
        lambda: check_batch(captured, setup.batch),
        "batch_snapshot_mismatch",
    )


def test_valid_duplicate_notice_is_bound_from_scan_through_batch(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    scan = copy.deepcopy(setup.scan)
    batch = copy.deepcopy(setup.batch)
    notice = {"source_id": "src_beta", "duplicate_of": "src_prior"}
    cast(dict[str, object], scan["data"])["duplicates"] = [notice]
    _batch_value(batch)["duplicates"] = [notice]

    captured = check_batch(record_scan(setup.receipt, scan), batch)

    assert captured.duplicate_notices[0].source_id == "src_beta"
    assert captured.duplicate_notices[0].duplicate_of == "src_prior"


def test_scan_rejects_error_or_malformed_success_without_authorizing_rescan(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    malformed = copy.deepcopy(setup.scan)
    del cast(dict[str, object], malformed["data"])["batch_id"]
    _error_code(lambda: record_scan(setup.receipt, malformed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED


_PUBLIC_SCAN_ISSUE_CODES = (
    "changed",
    "not_regular",
    "path_escape",
    "source_too_large",
    "symlink",
)


def _scan_at_public_nested_maxima(setup: SnapshotSetup) -> dict[str, object]:
    source_ids = [f"src_boundary_{ordinal:02}" for ordinal in range(64)]
    issues = [{"code": code, "count": 1} for code in _PUBLIC_SCAN_ISSUE_CODES]
    return memory_success_envelope(
        {
            "batch_id": "bat_boundary",
            "sealed_at": 1_775_000_200,
            "source_count": 64,
            "source_ids": source_ids,
            "batch_has_more": True,
            "issues": issues,
            "duplicates": [
                {
                    "source_id": source_id,
                    "duplicate_of": f"src_prior_{ordinal:02}",
                }
                for ordinal, source_id in enumerate(source_ids)
            ],
            "review_state": "none",
        },
        page={"has_more": True},
        issues=issues,
    )


def test_scan_records_exact_public_nested_maxima_before_manifest_mismatch(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)

    captured = record_scan(setup.receipt, _scan_at_public_nested_maxima(setup))

    assert captured.state is TransactionState.CAPTURED
    assert len(captured.scan_source_ids) == 64
    assert len(captured.scan_issues) == 5
    assert len(captured.duplicate_notices) == 64
    assert captured.scan_has_more is True
    assert captured.scan_page_has_more is True


def test_scan_rejects_nonwire_issue_code_before_irreversible_recording(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.scan)
    issue = {"code": "synthetic_unknown", "count": 1}
    cast(dict[str, object], changed["data"])["issues"] = [issue]
    changed["issues"] = [issue]

    _error_code(lambda: record_scan(setup.receipt, changed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED
    assert setup.receipt.scan_started is True


def test_scan_rejects_more_than_five_wire_issues_before_recording(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = _scan_at_public_nested_maxima(setup)
    issues = cast(list[dict[str, object]], changed["issues"])
    issues.append({"code": "synthetic_sixth", "count": 1})
    cast(list[dict[str, object]], cast(dict[str, object], changed["data"])["issues"])[
        :
    ] = issues

    _error_code(lambda: record_scan(setup.receipt, changed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED


def test_scan_rejects_more_than_sixty_four_sources_before_recording(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = _scan_at_public_nested_maxima(setup)
    data = cast(dict[str, object], changed["data"])
    source_ids = cast(list[str], data["source_ids"])
    source_ids.append("src_boundary_64")
    data["source_count"] = 65

    _error_code(lambda: record_scan(setup.receipt, changed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED


def test_scan_rejects_more_than_sixty_four_duplicates_before_recording(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = _scan_at_public_nested_maxima(setup)
    data = cast(dict[str, object], changed["data"])
    cast(list[dict[str, object]], data["duplicates"]).append(
        {"source_id": "src_boundary_00", "duplicate_of": "src_prior_extra"}
    )

    _error_code(lambda: record_scan(setup.receipt, changed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED


@pytest.mark.parametrize("count", [0, True])
def test_scan_rejects_nonwire_issue_count_before_recording(
    tmp_path: Path,
    count: object,
) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.scan)
    issue = {"code": "changed", "count": count}
    cast(dict[str, object], changed["data"])["issues"] = [issue]
    changed["issues"] = [issue]

    _error_code(lambda: record_scan(setup.receipt, changed), "invalid_scan_snapshot")
    assert setup.receipt.state is TransactionState.PUBLISHED


def test_scan_rejects_nonwire_empty_top_level_issues(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.scan)
    changed["issues"] = []

    _error_code(
        lambda: record_scan(setup.receipt, changed),
        "invalid_scan_snapshot",
    )


def test_check_batch_validates_bijection_and_can_recover_exact_published_batch(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    captured = record_scan(setup.receipt, setup.scan)

    checked = check_batch(captured, setup.batch)
    recovered = check_batch(setup.receipt, setup.batch)

    assert checked.state is TransactionState.CAPTURED
    assert checked.source_bindings == recovered.source_bindings
    assert tuple(binding.source_id for binding in checked.source_bindings) == (
        "src_alpha",
        "src_beta",
    )
    assert recovered.batch_id == "bat_exact"
    assert recovered.scan_page_has_more is False
    another = copy.deepcopy(setup.batch)
    cast(dict[str, object], cast(dict[str, object], another["data"])["batch"])[
        "batch_id"
    ] = "bat_second"
    _error_code(lambda: check_batch(checked, another), "batch_snapshot_mismatch")


def test_batch_from_another_transaction_visible_name_is_not_a_match(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.batch)
    source = _source_value(changed, 0)
    original_name = cast(str, source["original_name"])
    other_transaction = "tx_" + "f" * 32
    source["original_name"] = original_name.replace(
        setup.receipt.transaction_id,
        other_transaction,
        1,
    )
    assert source["original_name"] != original_name

    _error_code(
        lambda: check_batch(setup.receipt, changed),
        "batch_snapshot_mismatch",
    )


def test_batch_rejects_nonwire_null_optional_review_id(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    changed = copy.deepcopy(setup.batch)
    _batch_value(changed)["change_set_id"] = None

    _error_code(
        lambda: check_batch(setup.receipt, changed),
        "batch_snapshot_mismatch",
    )


def test_batch_recheck_cannot_rebind_a_captured_source(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    changed = copy.deepcopy(setup.batch)
    first = _source_value(changed, 0)
    second = _source_value(changed, 1)
    first["original_name"], second["original_name"] = (
        second["original_name"],
        first["original_name"],
    )
    first["blob_digest"], second["blob_digest"] = (
        second["blob_digest"],
        first["blob_digest"],
    )
    first["byte_length"], second["byte_length"] = (
        second["byte_length"],
        first["byte_length"],
    )

    _error_code(
        lambda: check_batch(captured, changed),
        "batch_snapshot_mismatch",
    )
    assert captured.source_bindings[0].source_id == "src_alpha"


BatchMutation = Callable[[dict[str, object]], None]


def _batch_value(envelope: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], cast(dict[str, object], envelope["data"])["batch"])


def _source_value(envelope: dict[str, object], ordinal: int = 0) -> dict[str, object]:
    sources = cast(
        list[dict[str, object]], cast(dict[str, object], envelope["data"])["sources"]
    )
    return sources[ordinal]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: _batch_value(value).__setitem__("source_count", 1),
        lambda value: _batch_value(value).__setitem__(
            "source_ids", ["src_beta", "src_alpha"]
        ),
        lambda value: _batch_value(value).__setitem__("batch_has_more", True),
        lambda value: _batch_value(value).__setitem__(
            "issues", [{"code": "changed", "count": 1}]
        ),
        lambda value: _batch_value(value).__setitem__("review_state", "draft"),
        lambda value: _batch_value(value).__setitem__(
            "change_set_id", "chg_unexpected"
        ),
        lambda value: _batch_value(value).__setitem__(
            "duplicates", [{"source_id": "src_alpha", "duplicate_of": "src_alpha"}]
        ),
        lambda value: _source_value(value).__setitem__("original_name", "wrong.md"),
        lambda value: _source_value(value).__setitem__("source_id", "src_other"),
        lambda value: _source_value(value).__setitem__("blob_digest", HASH_B),
        lambda value: _source_value(value).__setitem__("origin", "owner_correction"),
        lambda value: _source_value(value).__setitem__("authorship", "owner"),
        lambda value: _source_value(value).__setitem__(
            "declared_sensitivity", "normal"
        ),
        lambda value: _source_value(value).__setitem__(
            "effective_sensitivity", "restricted"
        ),
        lambda value: _source_value(value).__setitem__("media_type", "text/plain"),
        lambda value: _source_value(value).__setitem__("searchable", False),
        lambda value: _source_value(value).__setitem__("byte_length", 0),
        lambda value: cast(
            list[object], cast(dict[str, object], value["data"])["sources"]
        ).append(copy.deepcopy(_source_value(value))),
    ],
    ids=[
        "count",
        "source-order",
        "deferred",
        "issue",
        "review-state",
        "review-id",
        "duplicate",
        "filename",
        "source-id",
        "digest",
        "origin",
        "authorship",
        "declared",
        "effective",
        "media",
        "searchable",
        "length",
        "extra-source",
    ],
)
def test_batch_mismatch_preserves_captured_state(
    tmp_path: Path,
    mutate: BatchMutation,
) -> None:
    setup = _setup(tmp_path)
    captured = record_scan(setup.receipt, setup.scan)
    changed = copy.deepcopy(setup.batch)
    mutate(changed)

    _error_code(lambda: check_batch(captured, changed), "batch_snapshot_mismatch")
    assert captured.state is TransactionState.CAPTURED
    assert captured.source_bindings == ()


def test_review_edits_are_exact_contentful_items_then_directional_guards(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)

    edits = build_review_edits(captured, setup.config)

    assert [edit["op"] for edit in edits] == [
        "add_item",
        "add_item",
        "add_guard_link",
        "add_guard_link",
    ]
    first = edits[0]
    assert first["client_item_id"] == captured.candidates[0].client_item_id
    assert cast(dict[str, object], first["memory"]) == {
        "kind": "fact",
        "statement": "Synthetic exact statement alpha.",
        "occurred_on": None,
        "valid_from": None,
        "valid_to": None,
        "tags": ["synthetic", "alpha"],
        "sensitivity": "sensitive",
        "target_lineage_id": None,
        "expected_head_id": None,
    }
    assert cast(list[object], first["evidence"]) == [
        {
            "source_id": "src_alpha",
            "blob_digest": captured.published_files[0].sha256,
            "excerpt": "Synthetic exact statement alpha.",
        }
    ]
    assert edits[2] == {
        "op": "add_guard_link",
        "guard_item_id": captured.candidates[0].client_item_id,
        "governed_item_id": captured.candidates[1].client_item_id,
    }
    assert edits[3] == {
        "op": "add_guard_link",
        "guard_item_id": captured.candidates[1].client_item_id,
        "governed_lineage_id": "lin_existing",
    }


def test_review_plan_reopens_exact_prepared_bytes(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    path = setup.config.notes_root / "03_Prepared" / "alpha.md"
    path.write_bytes(path.read_bytes().replace(b"alpha.", b"changed."))

    _error_code(
        lambda: build_review_edits(captured, setup.config),
        "prepared_snapshot_changed",
    )


ReviewMutation = Callable[[dict[str, object]], None]


def _review_value(envelope: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], envelope["data"])


def _review_item(envelope: dict[str, object], ordinal: int = 0) -> dict[str, object]:
    return cast(list[dict[str, object]], _review_value(envelope)["items"])[ordinal]


def _review_memory(envelope: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], _review_item(envelope)["memory"])


def _review_evidence_value(envelope: dict[str, object]) -> dict[str, object]:
    return cast(list[dict[str, object]], _review_item(envelope)["evidence"])[0]


def _review_source_decision(envelope: dict[str, object]) -> dict[str, object]:
    return cast(list[dict[str, object]], _review_value(envelope)["source_decisions"])[0]


def _review_guard_value(envelope: dict[str, object]) -> dict[str, object]:
    return cast(list[dict[str, object]], _review_value(envelope)["guard_links"])[0]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: _review_value(value).__setitem__("batch_id", "bat_other"),
        lambda value: _review_value(value).__setitem__("adapter_origin", "owner_ui"),
        lambda value: _review_value(value).__setitem__("state", "applied"),
        lambda value: _review_item(value).__setitem__("ordinal", 1),
        lambda value: _review_item(value).__setitem__("item_id", "itm_other"),
        lambda value: _review_item(value).__setitem__("status", "rejected"),
        lambda value: _review_memory(value).__setitem__("statement", "changed"),
        lambda value: _review_memory(value).__setitem__("kind", "event"),
        lambda value: _review_memory(value).__setitem__("occurred_on", "2025"),
        lambda value: _review_memory(value).__setitem__("valid_from", "2025"),
        lambda value: _review_memory(value).__setitem__("valid_to", "2025"),
        lambda value: _review_memory(value).__setitem__("tags", ["changed"]),
        lambda value: _review_memory(value).__setitem__("sensitivity", "normal"),
        lambda value: _review_memory(value).__setitem__("target_lineage_id", "lin_x"),
        lambda value: _review_memory(value).__setitem__("expected_head_id", "mem_x"),
        lambda value: _review_evidence_value(value).__setitem__("ordinal", 1),
        lambda value: _review_evidence_value(value).__setitem__("source_id", "src_x"),
        lambda value: _review_evidence_value(value).__setitem__("blob_digest", HASH_B),
        lambda value: _review_evidence_value(value).__setitem__("char_start", 1),
        lambda value: _review_evidence_value(value).__setitem__("char_end", 1),
        lambda value: _review_evidence_value(value).__setitem__("excerpt", "changed"),
        lambda value: _review_source_decision(value).__setitem__("ordinal", 1),
        lambda value: _review_source_decision(value).__setitem__("source_id", "src_x"),
        lambda value: _review_source_decision(value).__setitem__("blob_digest", HASH_B),
        lambda value: _review_source_decision(value).__setitem__("state", "no_memory"),
        lambda value: _review_source_decision(value).__setitem__("reason", "changed"),
        lambda value: _review_guard_value(value).__setitem__("ordinal", 1),
        lambda value: _review_guard_value(value).__setitem__("status", "rejected"),
        lambda value: _review_guard_value(value).__setitem__(
            "guard_item_id", _review_guard_value(value)["governed_item_id"]
        ),
        lambda value: cast(
            list[object], _review_value(value)["revoked_guard_links"]
        ).append(
            copy.deepcopy(cast(list[object], _review_value(value)["guard_links"])[0])
        ),
    ],
    ids=[
        "batch",
        "origin",
        "state",
        "item-order",
        "item-id",
        "rejected",
        "statement",
        "kind",
        "occurred-on",
        "valid-from",
        "valid-to",
        "tags",
        "sensitivity",
        "target-lineage",
        "expected-head",
        "evidence-ordinal",
        "evidence-source",
        "evidence-digest",
        "evidence-start",
        "evidence-end",
        "evidence-excerpt",
        "decision-ordinal",
        "decision-source",
        "decision-digest",
        "decision-state",
        "decision-reason",
        "guard-ordinal",
        "guard-status",
        "guard-direction",
        "revoked",
    ],
)
def test_review_mismatch_is_never_corrected(
    tmp_path: Path,
    mutate: ReviewMutation,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    changed = copy.deepcopy(setup.review)
    mutate(changed)

    _error_code(lambda: check_review(captured, changed), "review_snapshot_mismatch")
    assert captured.state is TransactionState.CAPTURED
    assert captured.change_set_id is None


@pytest.mark.parametrize("collection", ["items", "source_decisions", "guard_links"])
def test_review_requires_every_exact_ordered_collection_member(
    tmp_path: Path,
    collection: str,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    changed = copy.deepcopy(setup.review)
    cast(list[object], _review_value(changed)[collection]).pop()

    _error_code(lambda: check_review(captured, changed), "review_snapshot_mismatch")


def test_review_and_approval_bind_one_exact_revision(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    ready = check_review(captured, setup.review)

    assert ready.state is TransactionState.REVIEW_READY
    assert ready.change_set_id == "chg_exact"
    assert ready.revision_id == "rev_exact"
    assert ready.review_digest == HASH_A
    assert check_review(ready, setup.review) == ready
    awaiting = mark_awaiting_approval(ready, "rev_exact", HASH_A)
    assert awaiting.state is TransactionState.AWAITING_MEMORY_APPROVAL
    assert mark_awaiting_approval(awaiting, "rev_exact", HASH_A) == awaiting
    _error_code(
        lambda: mark_awaiting_approval(ready, "rev_other", HASH_A),
        "review_binding_mismatch",
    )
    _error_code(
        lambda: mark_awaiting_approval(ready, "rev_exact", HASH_B),
        "review_binding_mismatch",
    )


def test_batch_recovery_accepts_only_receipt_recorded_review_state(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    ready = check_review(captured, setup.review)
    draft_batch = copy.deepcopy(setup.batch)
    batch = _batch_value(draft_batch)
    batch["review_state"] = "draft"
    batch["change_set_id"] = "chg_exact"

    assert check_batch(ready, draft_batch) == ready
    changed = copy.deepcopy(draft_batch)
    _batch_value(changed)["change_set_id"] = "chg_other"
    _error_code(
        lambda: check_batch(ready, changed),
        "batch_snapshot_mismatch",
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("change_set_id", "chg_other"),
        ("revision_id", "rev_other"),
        ("digest", HASH_B),
    ],
)
def test_ready_review_rejects_a_different_review_binding(
    tmp_path: Path,
    key: str,
    value: object,
) -> None:
    setup = _setup(tmp_path)
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    ready = check_review(captured, setup.review)
    changed = copy.deepcopy(setup.review)
    cast(dict[str, object], changed["data"])[key] = value

    _error_code(lambda: check_review(ready, changed), "review_snapshot_mismatch")
    assert ready.state is TransactionState.REVIEW_READY


def _awaiting(setup: SnapshotSetup) -> TransactionReceipt:
    captured = check_batch(record_scan(setup.receipt, setup.scan), setup.batch)
    ready = check_review(captured, setup.review)
    return mark_awaiting_approval(ready, "rev_exact", HASH_A)


def test_application_records_exact_ids_replay_and_standing_warnings(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    awaiting = _awaiting(setup)

    applied = record_application(awaiting, setup.application)

    assert applied.state is TransactionState.APPLIED
    assert applied.application_id == "app_exact"
    assert applied.memory_ids == ("mem_0", "mem_1")
    assert applied.standing_guard_violations[0].guard_lineage_id == "lin_warning_guard"
    replay = copy.deepcopy(setup.application)
    replay_data = cast(dict[str, object], replay["data"])
    replay_data["idempotent_replay"] = True
    replay_data["standing_guard_violations"] = []
    replayed = record_application(applied, replay)
    assert replayed.application_id == applied.application_id
    assert replayed.memory_ids == applied.memory_ids
    assert replayed.standing_guard_violations == ()


def test_application_preserves_every_ordered_standing_warning(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    awaiting = _awaiting(setup)
    application = copy.deepcopy(setup.application)
    warnings = [
        {
            "guard_lineage_id": f"lin_guard_{index:03d}",
            "guard_sensitivity": "restricted",
            "governed_lineage_id": f"lin_governed_{index:03d}",
            "governed_sensitivity": "normal",
        }
        for index in range(257)
    ]
    cast(dict[str, object], application["data"])["standing_guard_violations"] = warnings

    applied = record_application(awaiting, application)

    assert len(applied.standing_guard_violations) == len(warnings)
    assert tuple(
        warning.guard_lineage_id for warning in applied.standing_guard_violations
    ) == tuple(f"lin_guard_{index:03d}" for index in range(257))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("change_set_id", "chg_other"),
        ("revision_id", "rev_other"),
        ("application_id", ""),
        ("memory_ids", ["mem_0", "mem_0"]),
        ("memory_ids", ["mem_0"]),
        ("standing_guard_violations", [{"guard_lineage_id": "lin_only"}]),
    ],
)
def test_application_mismatch_stays_awaiting(
    tmp_path: Path,
    key: str,
    value: object,
) -> None:
    setup = _setup(tmp_path)
    awaiting = _awaiting(setup)
    changed = copy.deepcopy(setup.application)
    cast(dict[str, object], changed["data"])[key] = value

    _error_code(
        lambda: record_application(awaiting, changed),
        "application_snapshot_mismatch",
    )
    assert awaiting.state is TransactionState.AWAITING_MEMORY_APPROVAL
    assert awaiting.application_id is None


def _applied(setup: SnapshotSetup) -> TransactionReceipt:
    return record_application(_awaiting(setup), setup.application)


MemoryMutation = Callable[[dict[str, object]], None]


def _details(envelope: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], envelope["data"])


def _detail(envelope: dict[str, object], ordinal: int = 0) -> dict[str, object]:
    return _details(envelope)[ordinal]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: _details(value).pop(),
        lambda value: _details(value).append(copy.deepcopy(_detail(value))),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "memory_id", "mem_other"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "lineage_id", "lin_existing"
        ),
        lambda value: _detail(value).__setitem__("is_current", False),
        lambda value: _detail(value).__setitem__("current_head_id", "mem_other"),
        lambda value: _detail(value).__setitem__("revision_ids", ["mem_old", "mem_0"]),
        lambda value: _detail(value).__setitem__("predecessor_id", "mem_old"),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "statement", "changed"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "kind", "event"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "occurred_on", "2025"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "tags", ["changed"]
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "valid_from", "2025"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "valid_to", "2025"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "stored_sensitivity", "normal"
        ),
        lambda value: cast(dict[str, object], _detail(value)["revision"]).__setitem__(
            "effective_sensitivity", "normal"
        ),
        lambda value: cast(list[dict[str, object]], _detail(value)["evidence"])[
            0
        ].__setitem__("source_id", "src_other"),
        lambda value: cast(list[dict[str, object]], _detail(value)["evidence"])[
            0
        ].__setitem__("blob_digest", HASH_B),
        lambda value: cast(list[dict[str, object]], _detail(value)["evidence"])[
            0
        ].__setitem__("excerpt", "changed"),
        lambda value: cast(list[dict[str, object]], _detail(value)["evidence"])[
            0
        ].__setitem__("char_end", 1),
        lambda value: cast(list[dict[str, object]], _detail(value)["evidence"])[
            0
        ].__setitem__("ordinal", 1),
        lambda value: _detail(value).__setitem__(
            "guards", copy.deepcopy(cast(list[object], _detail(value, 1)["guards"]))
        ),
        lambda value: _detail(value).__setitem__("governs", []),
    ],
    ids=[
        "missing",
        "extra",
        "id",
        "existing-lineage",
        "historical",
        "head",
        "history",
        "predecessor",
        "statement",
        "kind",
        "date",
        "tags",
        "valid-from",
        "valid-to",
        "stored-sensitivity",
        "effective-sensitivity",
        "evidence-source",
        "evidence-digest",
        "evidence-excerpt",
        "evidence-coordinate",
        "evidence-ordinal",
        "guard-direction",
        "governs",
    ],
)
@pytest.mark.parametrize("with_page", [False, True], ids=["legacy", "current"])
def test_memory_mismatch_stays_applied(
    tmp_path: Path,
    mutate: MemoryMutation,
    with_page: bool,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    changed = copy.deepcopy(setup.memories)
    if with_page:
        changed["page"] = {"has_more": False}
    mutate(changed)

    _error_code(
        lambda: check_memories(applied, setup.config, changed),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


@pytest.mark.parametrize("with_page", [False, True], ids=["legacy", "current"])
def test_memory_bijection_and_guard_directions_advance_only_after_full_check(
    tmp_path: Path,
    with_page: bool,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)

    if with_page:
        setup.memories["page"] = {"has_more": False}
    verified = check_memories(applied, setup.config, setup.memories)

    assert verified.state is TransactionState.VERIFIED
    assert check_memories(verified, setup.config, setup.memories) == verified
    assert verified.application_id == "app_exact"
    assert verified.memory_ids == ("mem_0", "mem_1")
    assert verified.standing_guard_violations == applied.standing_guard_violations


def test_new_noncorrection_lineage_cannot_alias_an_approved_existing_lineage(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    changed = copy.deepcopy(setup.memories)
    revision = cast(dict[str, object], _detail(changed)["revision"])
    revision["lineage_id"] = "lin_existing"
    cast(list[dict[str, object]], _detail(changed, 1)["guards"])[0] = _attachment(
        revision
    )

    _error_code(
        lambda: check_memories(applied, setup.config, changed),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


def test_existing_lineage_attachment_cannot_alias_a_selected_memory_id(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    changed = copy.deepcopy(setup.memories)
    existing = cast(list[dict[str, object]], _detail(changed, 1)["governs"])[0]
    existing["memory_id"] = "mem_0"

    _error_code(
        lambda: check_memories(applied, setup.config, changed),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("memory_id", "mem_existing_other"),
        ("kind", "event"),
        ("statement", "Synthetic inconsistent existing statement."),
        ("effective_sensitivity", "restricted"),
    ],
)
def test_repeated_existing_lineage_attachments_must_be_identical(
    tmp_path: Path,
    key: str,
    value: object,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    repeated = ReceiptGuardLink(
        guard_item_id=applied.candidates[0].client_item_id,
        guard_lineage_id=None,
        governed_item_id=None,
        governed_lineage_id="lin_existing",
    )
    applied = replace(applied, guard_links=(*applied.guard_links, repeated))
    changed = copy.deepcopy(setup.memories)
    beta_governs = cast(list[dict[str, object]], _detail(changed, 1)["governs"])
    inconsistent = copy.deepcopy(beta_governs[0])
    inconsistent[key] = value
    alpha_governs = cast(list[dict[str, object]], _detail(changed)["governs"])
    alpha_governs.append(inconsistent)
    alpha_governs.sort(key=lambda item: cast(str, item["lineage_id"]))

    _error_code(
        lambda: check_memories(applied, setup.config, changed),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


@pytest.mark.parametrize("direction", ["selected_to_existing", "existing_to_selected"])
def test_guard_effective_sensitivity_cannot_exceed_governed_in_either_direction(
    tmp_path: Path,
    direction: str,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    changed = copy.deepcopy(setup.memories)
    beta = _detail(changed, 1)
    existing = cast(list[dict[str, object]], beta["governs"])[0]
    if direction == "selected_to_existing":
        existing["effective_sensitivity"] = "normal"
    else:
        second = applied.guard_links[1]
        applied = replace(
            applied,
            guard_links=(
                applied.guard_links[0],
                replace(
                    second,
                    guard_item_id=None,
                    guard_lineage_id="lin_existing",
                    governed_item_id=applied.candidates[1].client_item_id,
                    governed_lineage_id=None,
                ),
            ),
        )
        cast(list[dict[str, object]], beta["governs"]).remove(existing)
        existing["effective_sensitivity"] = "restricted"
        guards = cast(list[dict[str, object]], beta["guards"])
        guards.append(existing)
        guards.sort(key=lambda item: cast(str, item["lineage_id"]))

    _error_code(
        lambda: check_memories(applied, setup.config, changed),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


def test_memory_guard_bijection_preserves_existing_to_selected_direction(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    second = applied.guard_links[1]
    reversed_link = replace(
        second,
        guard_item_id=None,
        guard_lineage_id="lin_existing",
        governed_item_id=applied.candidates[1].client_item_id,
        governed_lineage_id=None,
    )
    applied = replace(applied, guard_links=(applied.guard_links[0], reversed_link))
    memories = copy.deepcopy(setup.memories)
    beta = _detail(memories, 1)
    existing = cast(list[dict[str, object]], beta["governs"]).pop()
    guards = cast(list[dict[str, object]], beta["guards"])
    guards.append(existing)
    guards.sort(key=lambda value: cast(str, value["lineage_id"]))

    verified = check_memories(applied, setup.config, memories)

    assert verified.state is TransactionState.VERIFIED


def test_memory_check_reopens_exact_prepared_bytes(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    path = setup.config.notes_root / "03_Prepared" / "beta.md"
    path.write_bytes(path.read_bytes().replace(b"beta", b"changed", 1))

    _error_code(
        lambda: check_memories(applied, setup.config, setup.memories),
        "prepared_snapshot_changed",
    )
    assert applied.state is TransactionState.APPLIED


def test_long_evidence_excerpt_may_end_in_significant_whitespace(
    tmp_path: Path,
) -> None:
    long_statement = "A" * 4096 + " " + "A" * 4096
    setup = _setup(
        tmp_path,
        statement_values=(
            long_statement,
            "Synthetic exact statement beta with Unicode 界.",
        ),
    )
    evidence = cast(list[dict[str, object]], _detail(setup.memories)["evidence"])[0]
    assert cast(str, evidence["excerpt"]).endswith(" ")
    applied = _applied(setup)

    verified = check_memories(applied, setup.config, setup.memories)

    assert verified.state is TransactionState.VERIFIED


@pytest.mark.parametrize(
    "page",
    [
        None,
        False,
        [],
        {},
        {"has_more": True},
        {"has_more": 0},
        {"has_more": 1},
        {"has_more": "false"},
        {"has_more": None},
        {"has_more": False, "next_cursor": "synthetic-cursor"},
        {"has_more": False, "next_cursor": None},
        {"has_more": True, "next_cursor": "synthetic-cursor"},
        {"has_more": False, "cursor": "synthetic-cursor"},
        {"has_more": False, "unexpected": False},
    ],
)
def test_memory_page_metadata_refuses_incomplete_or_malformed_snapshots(
    tmp_path: Path, page: object
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    setup.memories["page"] = page

    _error_code(
        lambda: check_memories(applied, setup.config, setup.memories),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


@pytest.mark.parametrize("has_more", [False, True])
def test_memory_detail_fragments_never_authorize_cleanup(
    tmp_path: Path, has_more: bool
) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    setup.memories["page"] = {"has_more": has_more}
    setup.memories["data"] = {"detail_fragments": setup.memories["data"]}

    _error_code(
        lambda: check_memories(applied, setup.config, setup.memories),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


@pytest.mark.parametrize("field", ["cursor", "next_cursor", "unexpected"])
def test_memory_envelope_rejects_unknown_fields(tmp_path: Path, field: str) -> None:
    setup = _setup(tmp_path)
    applied = _applied(setup)
    setup.memories["page"] = {"has_more": False}
    setup.memories[field] = "synthetic-value"

    _error_code(
        lambda: check_memories(applied, setup.config, setup.memories),
        "memory_snapshot_mismatch",
    )
    assert applied.state is TransactionState.APPLIED


def test_current_public_mcp_details_verify_exact_synthetic_intake(
    tmp_path: Path, synthetic_store: RuntimePaths
) -> None:
    """Exercise the producer and verifier together without a hand-built envelope."""
    setup = _setup(tmp_path)
    config = replace(
        setup.config,
        memory_home=synthetic_store.root,
        memory_inbox=synthetic_store.inbox,
        inbox_identity=directory_identity(synthetic_store.inbox),
    )
    receipt = replace(
        setup.receipt,
        memory_home=str(config.memory_home),
        memory_inbox=str(config.memory_inbox),
        inbox_identity=config.inbox_identity,
        guard_links=setup.receipt.guard_links[:1],
    )
    for published in receipt.published_files:
        source = config.notes_root / "03_Prepared" / published.prepared_name
        (config.memory_inbox / published.inbox_name).write_bytes(source.read_bytes())

    def public(name: str, arguments: dict[str, object]) -> dict[str, object]:
        result = call_tool(synthetic_store, name, arguments)
        envelope = cast(dict[str, object], result["structuredContent"])
        assert "error" not in envelope
        # The helper receives the unchanged structured envelope through JSON stdin.
        return cast(
            dict[str, object],
            parse_success_envelope(json.dumps(envelope).encode()),
        )

    scanned = record_scan(
        receipt,
        public("inbox.scan", {"authorship": "mixed", "sensitivity": "sensitive"}),
    )
    captured = check_batch(
        scanned, public("inbox.read", {"batch_id": scanned.batch_id})
    )
    draft = cast(
        dict[str, object],
        public("change_set.create", {"batch_id": captured.batch_id})["data"],
    )
    edited = public(
        "change_set.edit",
        {
            "change_set_id": draft["change_set_id"],
            "expected_revision_id": draft["revision_id"],
            "edits": list(build_review_edits(captured, config)),
        },
    )
    ready = check_review(captured, edited)
    assert ready.change_set_id is not None
    assert ready.revision_id is not None
    assert ready.review_digest is not None
    awaiting = mark_awaiting_approval(ready, ready.revision_id, ready.review_digest)
    # The shared synthetic approval adapter never invokes an owner UI or Keychain.
    apply_ready(synthetic_store, get_change_set(synthetic_store, ready.change_set_id))
    applied = record_application(
        awaiting,
        public(
            "change_set.approve_and_apply",
            {
                "change_set_id": ready.change_set_id,
                "revision_id": ready.revision_id,
                "digest": ready.review_digest,
            },
        ),
    )
    envelope = public("memory.get", {"memory_ids": list(applied.memory_ids)})
    assert envelope["page"] == {"has_more": False}
    assert isinstance(envelope["data"], list)

    verified = check_memories(applied, config, envelope)

    assert verified.state is TransactionState.VERIFIED
    assert verified.memory_ids == applied.memory_ids
    assert verified.guard_links == receipt.guard_links
    assert check_memories(verified, config, envelope) == verified
