"""Body-free authorization receipts and monotone transaction persistence."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    MAX_PUBLIC_SNAPSHOT_BYTES,
    STATE_ORDER,
    CleanupEntry,
    CleanupFailure,
    CleanupOutcome,
    DirectoryIdentity,
    DuplicateNotice,
    GuardEndpoint,
    GuardSpec,
    GuardViolationChunk,
    GuardViolationNotice,
    IntakeConfig,
    IntakeError,
    MemoryKind,
    MemoryMetadata,
    PreparedCandidate,
    PromotionPreview,
    PublishedFile,
    ReceiptCandidate,
    ReceiptGuardLink,
    ScanIssueNotice,
    Sensitivity,
    SourceBinding,
    TransactionReceipt,
    TransactionState,
    identity_payload,
    parse_identity_payload,
    validate_state_transition,
)
from staged_memory_intake.prepared import build_preview, parse_prepared
from staged_memory_intake.securefs import (
    atomic_private_json,
    canonical_json_bytes,
    directory_identity,
    ensure_private_bytes,
    inventory,
    quarantine_state_entry,
    read_private_regular,
    read_regular,
)

TRANSACTION_SCHEMA = "staged-memory-intake.transaction.v3"
_LEGACY_TRANSACTION_PREFIX = "staged-memory-intake.transaction."
_ACTIVE_NAME = "active.json"
_LOCK_NAME = ".transaction.lock"
# A headroom multiple of the public envelope bounds the receipt metadata
# overhead above its chunked warning payloads.
_RECEIPT_LIMIT = MAX_PUBLIC_SNAPSHOT_BYTES * 2
_RECEIPT_WRITE_LIMIT = 4 * 1024 * 1024
_WARNING_CHUNK_LIMIT = 256 * 1024
_PREPARED_LIMIT = 256 * 1024
_SOURCE_LIMIT = 64 * 1024 * 1024
_THREAD_LOCKS = threading.local()
_TX_PATTERN = re.compile(r"tx_[0-9a-f]{32}")
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_SENSITIVITIES: frozenset[str] = frozenset({"normal", "sensitive", "restricted"})
_KINDS: frozenset[str] = frozenset(
    {"fact", "event", "preference", "relation", "insight"}
)
_MUTABLE_FIELDS_BY_STATE: Mapping[TransactionState, frozenset[str]] = {
    TransactionState.OWNER_AUTHORIZED: frozenset(),
    TransactionState.PUBLISHING: frozenset(),
    TransactionState.PUBLISHED: frozenset({"published_files", "scan_started"}),
    TransactionState.CAPTURED: frozenset(
        {
            "batch_id",
            "scan_source_ids",
            "scan_issues",
            "scan_has_more",
            "scan_page_has_more",
            "source_bindings",
            "duplicate_notices",
        }
    ),
    TransactionState.REVIEW_READY: frozenset(
        {"change_set_id", "revision_id", "review_digest"}
    ),
    TransactionState.AWAITING_MEMORY_APPROVAL: frozenset(
        {"revision_id", "review_digest"}
    ),
    TransactionState.APPLIED: frozenset(
        {"application_id", "memory_ids", "standing_guard_violations"}
    ),
    TransactionState.VERIFIED: frozenset(),
    TransactionState.CLEANUP_PENDING: frozenset({"cleanup_entries"}),
    TransactionState.COMPLETE: frozenset({"cleanup_entries"}),
}


def _error(code: str, *, retryable: bool = False) -> IntakeError:
    return IntakeError(code, "state", retryable=retryable)


def _private_root(state_root: Path) -> None:
    try:
        state_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    identity = directory_identity(state_root)
    del identity
    try:
        mode = stat.S_IMODE(state_root.lstat().st_mode)
    except OSError as error:
        raise _error("invalid_state_root") from error
    if mode != 0o700:
        raise _error("state_root_not_private")


def _direct_name(value: str) -> bool:
    return bool(value) and "\0" not in value and PurePosixPath(value).parts == (value,)


def _identity_json(identity: DirectoryIdentity) -> dict[str, object]:
    return identity_payload(identity)


def _metadata_json(metadata: MemoryMetadata) -> dict[str, object]:
    return {
        "kind": metadata.kind,
        "occurred_on": metadata.occurred_on,
        "sensitivity": metadata.sensitivity,
        "tags": list(metadata.tags),
        "valid_from": metadata.valid_from,
        "valid_to": metadata.valid_to,
    }


def _candidate_json(candidate: ReceiptCandidate) -> dict[str, object]:
    return {
        "client_item_id": candidate.client_item_id,
        "evidence_char_end": candidate.evidence_char_end,
        "evidence_char_start": candidate.evidence_char_start,
        "evidence_sha256": candidate.evidence_sha256,
        "metadata": _metadata_json(candidate.metadata),
        "ordinal": candidate.ordinal,
        "prepared_name": candidate.prepared_name,
        "prepared_sha256": candidate.prepared_sha256,
        "source_name": candidate.source_name,
        "source_sha256": candidate.source_sha256,
        "statement_sha256": candidate.statement_sha256,
        "statement_utf8_bytes": candidate.statement_utf8_bytes,
    }


def _guard_json(guard: ReceiptGuardLink) -> dict[str, object]:
    return {
        "governed_item_id": guard.governed_item_id,
        "governed_lineage_id": guard.governed_lineage_id,
        "guard_item_id": guard.guard_item_id,
        "guard_lineage_id": guard.guard_lineage_id,
    }


def _violation_json(value: GuardViolationNotice) -> dict[str, object]:
    return {
        "governed_lineage_id": value.governed_lineage_id,
        "governed_sensitivity": value.governed_sensitivity,
        "guard_lineage_id": value.guard_lineage_id,
        "guard_sensitivity": value.guard_sensitivity,
    }


def _violation_line(value: GuardViolationNotice) -> bytes:
    return canonical_json_bytes(_violation_json(value))


def _chunk_name(transaction_id: str, chunk: GuardViolationChunk) -> str:
    return (
        f"{transaction_id}.standing-guard-violations-"
        f"{chunk.ordinal:04d}-{chunk.sha256}.jsonl"
    )


@dataclass(frozen=True, slots=True)
class _WarningPersistence:
    binding: dict[str, object]
    chunks: tuple[tuple[GuardViolationChunk, bytes], ...]


def _warning_persistence(receipt: TransactionReceipt) -> _WarningPersistence:
    lines = tuple(_violation_line(value) for value in receipt.standing_guard_violations)
    total_bytes = sum(len(line) for line in lines)
    if total_bytes > MAX_PUBLIC_SNAPSHOT_BYTES:
        raise _error("standing_guard_violations_too_large")
    chunk_payloads: list[bytes] = []
    chunk_counts: list[int] = []
    current: list[bytes] = []
    current_bytes = 0
    for line in lines:
        if current and current_bytes + len(line) > _WARNING_CHUNK_LIMIT:
            chunk_payloads.append(b"".join(current))
            chunk_counts.append(len(current))
            current = []
            current_bytes = 0
        current.append(line)
        current_bytes += len(line)
        if len(line) > _WARNING_CHUNK_LIMIT:
            chunk_payloads.append(b"".join(current))
            chunk_counts.append(len(current))
            current = []
            current_bytes = 0
    if current:
        chunk_payloads.append(b"".join(current))
        chunk_counts.append(len(current))
    chunks = tuple(
        (
            GuardViolationChunk(
                ordinal=ordinal,
                count=chunk_counts[ordinal],
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        )
        for ordinal, payload in enumerate(chunk_payloads)
    )
    concatenated = b"".join(chunk_payloads)
    return _WarningPersistence(
        binding={
            "count": len(lines),
            "sha256": hashlib.sha256(concatenated).hexdigest(),
            "chunks": [
                {
                    "ordinal": chunk.ordinal,
                    "count": chunk.count,
                    "sha256": chunk.sha256,
                }
                for chunk, _payload in chunks
            ],
        },
        chunks=chunks,
    )


def _receipt_payload(
    receipt: TransactionReceipt,
    warning_binding: Mapping[str, object],
) -> dict[str, object]:
    return {
        "application_id": receipt.application_id,
        "batch_id": receipt.batch_id,
        "batch_sensitivity": receipt.batch_sensitivity,
        "candidates": [_candidate_json(value) for value in receipt.candidates],
        "change_set_id": receipt.change_set_id,
        "cleanup_entries": [
            {
                "content_sha256": value.content_sha256,
                "failure": value.failure,
                "intent_recorded": value.intent_recorded,
                "name_sha256": value.name_sha256,
                "outcome": value.outcome,
                "role": value.role,
            }
            for value in receipt.cleanup_entries
        ],
        "duplicate_notices": [
            {"duplicate_of": value.duplicate_of, "source_id": value.source_id}
            for value in receipt.duplicate_notices
        ],
        "guard_links": [_guard_json(value) for value in receipt.guard_links],
        "inbox_identity": _identity_json(receipt.inbox_identity),
        "manifest_digest": receipt.manifest_digest,
        "memory_home": receipt.memory_home,
        "memory_ids": list(receipt.memory_ids),
        "memory_inbox": receipt.memory_inbox,
        "notes_identity": _identity_json(receipt.notes_identity),
        "notes_root": receipt.notes_root,
        "published_files": [
            {
                "byte_length": value.byte_length,
                "inbox_name": value.inbox_name,
                "ordinal": value.ordinal,
                "prepared_name": value.prepared_name,
                "sha256": value.sha256,
            }
            for value in receipt.published_files
        ],
        "review_digest": receipt.review_digest,
        "revision_id": receipt.revision_id,
        "scan_started": receipt.scan_started,
        "scan_has_more": receipt.scan_has_more,
        "scan_issues": [
            {"code": value.code, "count": value.count} for value in receipt.scan_issues
        ],
        "scan_page_has_more": receipt.scan_page_has_more,
        "scan_source_ids": list(receipt.scan_source_ids),
        "schema": TRANSACTION_SCHEMA,
        "source_bindings": [
            {
                "blob_digest": value.blob_digest,
                "inbox_name": value.inbox_name,
                "ordinal": value.ordinal,
                "source_id": value.source_id,
            }
            for value in receipt.source_bindings
        ],
        "standing_guard_violations": dict(warning_binding),
        "state": receipt.state.value,
        "transaction_id": receipt.transaction_id,
    }


def receipt_candidate(candidate: PreparedCandidate) -> ReceiptCandidate:
    """Drop statement and excerpt bodies from an approved candidate."""
    parsed = candidate.parsed
    return ReceiptCandidate(
        ordinal=candidate.ordinal,
        prepared_name=parsed.prepared_name,
        source_name=parsed.source_name,
        prepared_sha256=parsed.prepared_sha256,
        source_sha256=parsed.source_sha256,
        statement_sha256=parsed.statement_sha256,
        statement_utf8_bytes=parsed.statement_utf8_bytes,
        evidence_char_start=parsed.evidence_char_start,
        evidence_char_end=parsed.evidence_char_end,
        evidence_sha256=parsed.evidence_sha256,
        client_item_id=candidate.client_item_id,
        metadata=candidate.final_metadata,
    )


def _guard_endpoint(
    endpoint: GuardEndpoint,
    item_ids: Mapping[str, str],
) -> tuple[str | None, str | None]:
    if endpoint.prepared_name is not None:
        try:
            return item_ids[endpoint.prepared_name], None
        except KeyError as error:
            raise _error("invalid_guard_spec") from error
    if endpoint.lineage_id is None:
        raise _error("invalid_guard_spec")
    return None, endpoint.lineage_id


def _receipt_guard(
    guard: GuardSpec,
    item_ids: Mapping[str, str],
) -> ReceiptGuardLink:
    guard_item, guard_lineage = _guard_endpoint(guard.guard, item_ids)
    governed_item, governed_lineage = _guard_endpoint(guard.governed, item_ids)
    return ReceiptGuardLink(
        guard_item_id=guard_item,
        guard_lineage_id=guard_lineage,
        governed_item_id=governed_item,
        governed_lineage_id=governed_lineage,
    )


def _endpoint_raw(endpoint: GuardEndpoint) -> dict[str, str]:
    if endpoint.prepared_name is not None:
        return {"prepared_name": endpoint.prepared_name}
    if endpoint.lineage_id is None:
        raise _error("invalid_guard_spec")
    return {"lineage_id": endpoint.lineage_id}


def _guard_raw(guard: GuardSpec) -> str:
    return json.dumps(
        {
            "guard": _endpoint_raw(guard.guard),
            "governed": _endpoint_raw(guard.governed),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _require_dict(value: object, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise _error("invalid_transaction_receipt")
    return value


def _string(value: object, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\0" in value
    ):
        raise _error("invalid_transaction_receipt")
    return value


def _integer(value: object, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _error("invalid_transaction_receipt")
    return value


def _boolean(value: object, *, nullable: bool = False) -> bool | None:
    if nullable and value is None:
        return None
    if not isinstance(value, bool):
        raise _error("invalid_transaction_receipt")
    return value


def _hash(value: object) -> str:
    parsed = _string(value)
    if parsed is None or _HASH_PATTERN.fullmatch(parsed) is None:
        raise _error("invalid_transaction_receipt")
    return parsed


def _identity(value: object) -> DirectoryIdentity:
    try:
        return parse_identity_payload(value)
    except ValueError as error:
        raise _error("invalid_transaction_receipt") from error


def _metadata(value: object) -> MemoryMetadata:
    raw = _require_dict(
        value,
        {"kind", "occurred_on", "sensitivity", "tags", "valid_from", "valid_to"},
    )
    kind = _string(raw["kind"])
    sensitivity = _string(raw["sensitivity"])
    tags_raw = raw["tags"]
    if kind not in _KINDS or sensitivity not in _SENSITIVITIES:
        raise _error("invalid_transaction_receipt")
    if not isinstance(tags_raw, list):
        raise _error("invalid_transaction_receipt")
    tags: list[str] = []
    for tag_raw in tags_raw:
        tag = _string(tag_raw)
        if tag is None or tag in tags:
            raise _error("invalid_transaction_receipt")
        tags.append(tag)
    return MemoryMetadata(
        kind=cast(MemoryKind, kind),
        sensitivity=cast(Sensitivity, sensitivity),
        occurred_on=_string(raw["occurred_on"], nullable=True),
        valid_from=_string(raw["valid_from"], nullable=True),
        valid_to=_string(raw["valid_to"], nullable=True),
        tags=tuple(tags),
    )


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, list):
        raise _error("invalid_transaction_receipt")
    return value


def _candidate(value: object) -> ReceiptCandidate:
    expected = {
        "client_item_id",
        "evidence_char_end",
        "evidence_char_start",
        "evidence_sha256",
        "metadata",
        "ordinal",
        "prepared_name",
        "prepared_sha256",
        "source_name",
        "source_sha256",
        "statement_sha256",
        "statement_utf8_bytes",
    }
    raw = _require_dict(value, expected)
    prepared_name = _string(raw["prepared_name"])
    source_name = _string(raw["source_name"])
    if (
        prepared_name is None
        or source_name is None
        or not _direct_name(prepared_name)
        or not _direct_name(source_name)
    ):
        raise _error("invalid_transaction_receipt")
    start = _integer(raw["evidence_char_start"])
    end = _integer(raw["evidence_char_end"])
    if end <= start:
        raise _error("invalid_transaction_receipt")
    client_item_id = _string(raw["client_item_id"])
    if client_item_id is None:
        raise _error("invalid_transaction_receipt")
    return ReceiptCandidate(
        ordinal=_integer(raw["ordinal"]),
        prepared_name=prepared_name,
        source_name=source_name,
        prepared_sha256=_hash(raw["prepared_sha256"]),
        source_sha256=_hash(raw["source_sha256"]),
        statement_sha256=_hash(raw["statement_sha256"]),
        statement_utf8_bytes=_integer(raw["statement_utf8_bytes"], minimum=1),
        evidence_char_start=start,
        evidence_char_end=end,
        evidence_sha256=_hash(raw["evidence_sha256"]),
        client_item_id=client_item_id,
        metadata=_metadata(raw["metadata"]),
    )


def _guard(value: object) -> ReceiptGuardLink:
    raw = _require_dict(
        value,
        {
            "governed_item_id",
            "governed_lineage_id",
            "guard_item_id",
            "guard_lineage_id",
        },
    )
    try:
        return ReceiptGuardLink(
            guard_item_id=_string(raw["guard_item_id"], nullable=True),
            guard_lineage_id=_string(raw["guard_lineage_id"], nullable=True),
            governed_item_id=_string(raw["governed_item_id"], nullable=True),
            governed_lineage_id=_string(raw["governed_lineage_id"], nullable=True),
        )
    except ValueError as error:
        raise _error("invalid_transaction_receipt") from error


def _published(value: object) -> PublishedFile:
    raw = _require_dict(
        value,
        {"byte_length", "inbox_name", "ordinal", "prepared_name", "sha256"},
    )
    prepared_name = _string(raw["prepared_name"])
    inbox_name = _string(raw["inbox_name"])
    if (
        prepared_name is None
        or inbox_name is None
        or not _direct_name(prepared_name)
        or not _direct_name(inbox_name)
    ):
        raise _error("invalid_transaction_receipt")
    return PublishedFile(
        ordinal=_integer(raw["ordinal"]),
        prepared_name=prepared_name,
        inbox_name=inbox_name,
        sha256=_hash(raw["sha256"]),
        byte_length=_integer(raw["byte_length"]),
    )


def _source_binding(value: object) -> SourceBinding:
    raw = _require_dict(value, {"blob_digest", "inbox_name", "ordinal", "source_id"})
    inbox_name = _string(raw["inbox_name"])
    source_id = _string(raw["source_id"])
    if inbox_name is None or source_id is None or not _direct_name(inbox_name):
        raise _error("invalid_transaction_receipt")
    return SourceBinding(
        ordinal=_integer(raw["ordinal"]),
        inbox_name=inbox_name,
        source_id=source_id,
        blob_digest=_hash(raw["blob_digest"]),
    )


def _scan_issue(value: object) -> ScanIssueNotice:
    raw = _require_dict(value, {"code", "count"})
    code = _string(raw["code"])
    if code is None:
        raise _error("invalid_transaction_receipt")
    return ScanIssueNotice(code=code, count=_integer(raw["count"], minimum=1))


def _duplicate(value: object) -> DuplicateNotice:
    raw = _require_dict(value, {"duplicate_of", "source_id"})
    source_id = _string(raw["source_id"])
    duplicate_of = _string(raw["duplicate_of"])
    if source_id is None or duplicate_of is None:
        raise _error("invalid_transaction_receipt")
    return DuplicateNotice(source_id=source_id, duplicate_of=duplicate_of)


def _violation(value: object) -> GuardViolationNotice:
    raw = _require_dict(
        value,
        {
            "governed_lineage_id",
            "governed_sensitivity",
            "guard_lineage_id",
            "guard_sensitivity",
        },
    )
    guard_id = _string(raw["guard_lineage_id"])
    governed_id = _string(raw["governed_lineage_id"])
    guard_sensitivity = _string(raw["guard_sensitivity"])
    governed_sensitivity = _string(raw["governed_sensitivity"])
    if (
        guard_id is None
        or governed_id is None
        or guard_sensitivity not in _SENSITIVITIES
        or governed_sensitivity not in _SENSITIVITIES
    ):
        raise _error("invalid_transaction_receipt")
    return GuardViolationNotice(
        guard_lineage_id=guard_id,
        guard_sensitivity=cast(Sensitivity, guard_sensitivity),
        governed_lineage_id=governed_id,
        governed_sensitivity=cast(Sensitivity, governed_sensitivity),
    )


def _warning_binding(
    value: object,
) -> tuple[int, str, tuple[GuardViolationChunk, ...]]:
    raw = _require_dict(value, {"chunks", "count", "sha256"})
    count = _integer(raw["count"], minimum=0)
    digest = _hash(raw["sha256"])
    chunks: list[GuardViolationChunk] = []
    for value in _sequence(raw["chunks"]):
        chunk = _require_dict(value, {"count", "ordinal", "sha256"})
        chunks.append(
            GuardViolationChunk(
                ordinal=_integer(chunk["ordinal"], minimum=0),
                count=_integer(chunk["count"], minimum=1),
                sha256=_hash(chunk["sha256"]),
            )
        )
    ordered = tuple(chunks)
    if tuple(chunk.ordinal for chunk in ordered) != tuple(range(len(ordered))):
        raise _error("invalid_transaction_receipt")
    if count == 0 and ordered:
        raise _error("invalid_transaction_receipt")
    if count > 0 and not ordered:
        raise _error("invalid_transaction_receipt")
    return count, digest, ordered


def _cleanup(value: object) -> CleanupEntry:
    raw = _require_dict(
        value,
        {
            "content_sha256",
            "failure",
            "intent_recorded",
            "name_sha256",
            "outcome",
            "role",
        },
    )
    role = _string(raw["role"])
    failure = _string(raw["failure"], nullable=True)
    outcome = _string(raw["outcome"], nullable=True)
    if (
        role not in {"prepared", "staged"}
        or failure
        not in {
            None,
            "cleanup_drift",
            "trash_failed",
            "cleanup_ambiguous",
        }
        or outcome not in {None, "moved", "preserved"}
    ):
        raise _error("invalid_transaction_receipt")
    return CleanupEntry(
        role=cast(Literal["prepared", "staged"], role),
        name_sha256=_hash(raw["name_sha256"]),
        content_sha256=_hash(raw["content_sha256"]),
        intent_recorded=cast(bool, _boolean(raw["intent_recorded"])),
        failure=cast(CleanupFailure | None, failure),
        outcome=cast(CleanupOutcome | None, outcome),
    )


_RECEIPT_KEYS = {
    "application_id",
    "batch_id",
    "batch_sensitivity",
    "candidates",
    "change_set_id",
    "cleanup_entries",
    "duplicate_notices",
    "guard_links",
    "inbox_identity",
    "manifest_digest",
    "memory_home",
    "memory_ids",
    "memory_inbox",
    "notes_identity",
    "notes_root",
    "published_files",
    "review_digest",
    "revision_id",
    "scan_started",
    "scan_has_more",
    "scan_issues",
    "scan_page_has_more",
    "scan_source_ids",
    "schema",
    "source_bindings",
    "standing_guard_violations",
    "state",
    "transaction_id",
}


def _string_tuple(value: object) -> tuple[str, ...]:
    result: list[str] = []
    for raw in _sequence(value):
        parsed = _string(raw)
        if parsed is None:
            raise _error("invalid_transaction_receipt")
        result.append(parsed)
    return tuple(result)


def _parse_receipt(
    value: object,
    *,
    chunked_warnings: tuple[GuardViolationNotice, ...] | None = None,
) -> TransactionReceipt:
    # Recognize an older transaction schema before requiring the current key
    # shape: a pre-v3 receipt whose keys differ would otherwise misreport as
    # invalid rather than as unsupported.
    if isinstance(value, dict):
        schema = value.get("schema")
        if (
            isinstance(schema, str)
            and schema.startswith(_LEGACY_TRANSACTION_PREFIX)
            and schema != TRANSACTION_SCHEMA
        ):
            raise _error("unsupported_transaction_schema")
    raw = _require_dict(value, _RECEIPT_KEYS)
    if raw["schema"] != TRANSACTION_SCHEMA:
        raise _error("unsupported_transaction_schema")
    count, digest, chunks = _warning_binding(raw["standing_guard_violations"])
    del chunks
    if chunked_warnings is None or len(chunked_warnings) != count:
        raise _error("invalid_transaction_receipt")
    encoded = b"".join(_violation_line(value) for value in chunked_warnings)
    if not hmac.compare_digest(hashlib.sha256(encoded).hexdigest(), digest):
        raise _error("invalid_transaction_receipt")
    warnings = chunked_warnings
    transaction_id = _string(raw["transaction_id"])
    state_raw = _string(raw["state"])
    manifest_digest = _hash(raw["manifest_digest"])
    notes_root = _string(raw["notes_root"])
    memory_home = _string(raw["memory_home"], nullable=True)
    memory_inbox = _string(raw["memory_inbox"])
    sensitivity = _string(raw["batch_sensitivity"])
    if (
        transaction_id is None
        or _TX_PATTERN.fullmatch(transaction_id) is None
        or state_raw not in {state.value for state in STATE_ORDER}
        or notes_root is None
        or not Path(notes_root).is_absolute()
        or (memory_home is not None and not Path(memory_home).is_absolute())
        or memory_inbox is None
        or not Path(memory_inbox).is_absolute()
        or sensitivity not in _SENSITIVITIES
    ):
        raise _error("invalid_transaction_receipt")
    return TransactionReceipt(
        transaction_id=transaction_id,
        state=TransactionState(state_raw),
        manifest_digest=manifest_digest,
        notes_root=notes_root,
        notes_identity=_identity(raw["notes_identity"]),
        memory_home=memory_home,
        memory_inbox=memory_inbox,
        inbox_identity=_identity(raw["inbox_identity"]),
        batch_sensitivity=cast(Sensitivity, sensitivity),
        candidates=tuple(_candidate(value) for value in _sequence(raw["candidates"])),
        guard_links=tuple(_guard(value) for value in _sequence(raw["guard_links"])),
        published_files=tuple(
            _published(value) for value in _sequence(raw["published_files"])
        ),
        scan_started=cast(bool, _boolean(raw["scan_started"])),
        batch_id=_string(raw["batch_id"], nullable=True),
        scan_source_ids=_string_tuple(raw["scan_source_ids"]),
        scan_issues=tuple(
            _scan_issue(value) for value in _sequence(raw["scan_issues"])
        ),
        scan_has_more=_boolean(raw["scan_has_more"], nullable=True),
        scan_page_has_more=_boolean(raw["scan_page_has_more"], nullable=True),
        source_bindings=tuple(
            _source_binding(value) for value in _sequence(raw["source_bindings"])
        ),
        duplicate_notices=tuple(
            _duplicate(value) for value in _sequence(raw["duplicate_notices"])
        ),
        change_set_id=_string(raw["change_set_id"], nullable=True),
        revision_id=_string(raw["revision_id"], nullable=True),
        review_digest=(
            None if raw["review_digest"] is None else _hash(raw["review_digest"])
        ),
        application_id=_string(raw["application_id"], nullable=True),
        memory_ids=_string_tuple(raw["memory_ids"]),
        standing_guard_violations=warnings,
        cleanup_entries=tuple(
            _cleanup(value) for value in _sequence(raw["cleanup_entries"])
        ),
    )


def _validated_receipt_persistence(
    receipt: TransactionReceipt,
    *,
    code: str,
) -> tuple[dict[str, object], tuple[tuple[GuardViolationChunk, bytes], ...]]:
    """Round-trip one body-free receipt through its strict persisted decoder."""
    try:
        warnings = _warning_persistence(receipt)
        payload = _receipt_payload(receipt, warnings.binding)
        parsed = _parse_receipt(
            payload,
            chunked_warnings=receipt.standing_guard_violations,
        )
    except (AttributeError, IntakeError, TypeError, ValueError) as error:
        raise _error(code) from error
    if parsed != receipt or len(canonical_json_bytes(payload)) > _RECEIPT_WRITE_LIMIT:
        raise _error(code)
    return payload, warnings.chunks


def _persist_receipt(
    state_root: Path,
    receipt: TransactionReceipt,
    *,
    code: str,
) -> None:
    payload, chunks = _validated_receipt_persistence(receipt, code=code)
    for chunk, chunk_bytes in chunks:
        ensure_private_bytes(
            state_root / _chunk_name(receipt.transaction_id, chunk),
            chunk_bytes,
        )
    atomic_private_json(
        state_root / f"{receipt.transaction_id}.json",
        payload,
    )


def _load_chunked_warnings(
    state_root: Path,
    transaction_id: str,
    binding_value: object,
) -> tuple[GuardViolationNotice, ...]:
    try:
        expected_count, expected_digest, chunks = _warning_binding(binding_value)
        warnings: list[GuardViolationNotice] = []
        concatenated: list[bytes] = []
        total_bytes = 0
        for chunk in chunks:
            raw = read_private_regular(
                state_root,
                _chunk_name(transaction_id, chunk),
                limit=MAX_PUBLIC_SNAPSHOT_BYTES,
            )
            total_bytes += len(raw)
            if total_bytes > MAX_PUBLIC_SNAPSHOT_BYTES:
                raise _error("invalid_transaction_receipt")
            if len(raw) > _WARNING_CHUNK_LIMIT and chunk.count != 1:
                raise _error("invalid_transaction_receipt")
            if not hmac.compare_digest(
                hashlib.sha256(raw).hexdigest(),
                chunk.sha256,
            ):
                raise _error("invalid_transaction_receipt")
            lines = raw.splitlines(keepends=True)
            if len(lines) != chunk.count or any(
                not line.endswith(b"\n") for line in lines
            ):
                raise _error("invalid_transaction_receipt")
            for line in lines:
                parsed = _violation(json.loads(line[:-1]))
                if _violation_line(parsed) != line:
                    raise _error("invalid_transaction_receipt")
                warnings.append(parsed)
            concatenated.append(raw)
        all_bytes = b"".join(concatenated)
        if len(warnings) != expected_count or not hmac.compare_digest(
            hashlib.sha256(all_bytes).hexdigest(),
            expected_digest,
        ):
            raise _error("invalid_transaction_receipt")
        return tuple(warnings)
    except (
        IntakeError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise _error("invalid_transaction_receipt") from error


class TransactionStore:
    """Locked, atomic persistence for one active monotone transaction."""

    def __init__(self, state_root: Path) -> None:
        self.state_root = state_root
        self._lock_descriptor: int | None = None
        self._lock_depth = 0

    @classmethod
    def for_operation(cls, state_root: Path) -> TransactionStore:
        """Reuse an explicitly held adapter lock, preserving contender semantics."""
        held = cast(
            dict[Path, tuple[TransactionStore, DirectoryIdentity]] | None,
            getattr(_THREAD_LOCKS, "held", None),
        )
        if held is not None and state_root in held:
            owner, identity = held[state_root]
            if directory_identity(state_root) != identity:
                raise _error("invalid_state_root")
            return owner
        return cls(state_root)

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Hold the private process lock, refusing concurrent acquisition."""
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        _private_root(self.state_root)
        held = cast(
            dict[Path, tuple[TransactionStore, DirectoryIdentity]] | None,
            getattr(_THREAD_LOCKS, "held", None),
        )
        if held is None:
            held = {}
            _THREAD_LOCKS.held = held
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        try:
            descriptor = os.open(self.state_root / _LOCK_NAME, flags, 0o600)
        except OSError as error:
            raise _error("transaction_lock_failed") from error
        try:
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise _error("transaction_busy", retryable=True) from error
            root_identity = directory_identity(self.state_root)
            self._lock_descriptor = descriptor
            self._lock_depth = 1
            held[self.state_root] = (self, root_identity)
            try:
                yield
            finally:
                del held[self.state_root]
                self._lock_depth = 0
                self._lock_descriptor = None
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _active_locked(self) -> TransactionReceipt | None:
        try:
            raw = read_regular(self.state_root, _ACTIVE_NAME, limit=1024)
        except IntakeError as error:
            try:
                (self.state_root / _ACTIVE_NAME).lstat()
            except FileNotFoundError:
                return None
            except OSError as stat_error:
                raise _error("invalid_active_transaction") from stat_error
            raise _error("invalid_active_transaction") from error
        try:
            payload = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise _error("invalid_active_transaction") from error
        pointer = _require_dict(payload, {"transaction_id"})
        transaction_id = pointer["transaction_id"]
        if (
            not isinstance(transaction_id, str)
            or _TX_PATTERN.fullmatch(transaction_id) is None
        ):
            raise _error("invalid_active_transaction")
        receipt = self.load(transaction_id)
        if receipt.state is TransactionState.COMPLETE:
            self._unlink_active_pointer_locked()
            return None
        return receipt

    def _unlink_active_pointer_locked(self) -> None:
        descriptor = os.open(
            self.state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.unlink(_ACTIVE_NAME, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def active(self) -> TransactionReceipt | None:
        """Return only the transaction named by the active pointer."""
        with self.lock():
            return self._active_locked()

    def detach_cancelled_publication(
        self,
        receipt: TransactionReceipt,
        *,
        state_descriptor: int,
        receipt_sha256: str,
    ) -> None:
        """Detach only the unchanged active receipt after owned archival.

        Cancellation's separate final marker must already be durable. The
        receipt remains unchanged, preserving existing schemas and digests.
        Exact completed replay leaves a newer active transaction untouched.
        """
        with self.lock():
            root = os.fstat(state_descriptor)
            current_root = self.state_root.lstat()
            if not stat.S_ISDIR(current_root.st_mode) or (root.st_dev, root.st_ino) != (
                current_root.st_dev,
                current_root.st_ino,
            ):
                raise _error("stale_transaction_receipt")
            if self.load(receipt.transaction_id) != receipt or (
                receipt.state is not TransactionState.PUBLISHED
                or receipt.scan_started
                or receipt.batch_id is not None
                or receipt.change_set_id is not None
                or receipt.application_id is not None
            ):
                raise _error("stale_transaction_receipt")
            raw = read_private_regular(
                self.state_root, f"{receipt.transaction_id}.json", limit=_RECEIPT_LIMIT
            )
            if hashlib.sha256(raw).hexdigest() != receipt_sha256:
                raise _error("stale_transaction_receipt")
            try:
                descriptor = os.open(
                    _ACTIVE_NAME,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=state_descriptor,
                )
            except FileNotFoundError:
                return
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_size > 1024
                ):
                    raise _error("invalid_active_transaction")
                raw_pointer = os.read(descriptor, 1025)
                try:
                    pointer = _require_dict(json.loads(raw_pointer), {"transaction_id"})
                except (UnicodeError, json.JSONDecodeError) as error:
                    raise _error("invalid_active_transaction") from error
                if pointer["transaction_id"] != receipt.transaction_id:
                    return
                after = os.fstat(descriptor)
                current = os.stat(
                    _ACTIVE_NAME, dir_fd=state_descriptor, follow_symlinks=False
                )

                def attributes(value: os.stat_result) -> tuple[int, ...]:
                    return (
                        value.st_dev,
                        value.st_ino,
                        value.st_mode,
                        value.st_size,
                        value.st_mtime_ns,
                        value.st_ctime_ns,
                    )

                if attributes(before) != attributes(after) or attributes(
                    after
                ) != attributes(current):
                    raise _error("stale_transaction_receipt")
                current_root = self.state_root.lstat()
                if (root.st_dev, root.st_ino) != (
                    current_root.st_dev,
                    current_root.st_ino,
                ):
                    raise _error("stale_transaction_receipt")
                # Always mutate the originally held directory, never a reopened
                # pathname that an external actor may have replaced.
                os.unlink(_ACTIVE_NAME, dir_fd=state_descriptor)
                os.fsync(state_descriptor)
            finally:
                os.close(descriptor)

    def load(self, transaction_id: str) -> TransactionReceipt:
        """Read one exact receipt; transaction folders are never inferred."""
        if _TX_PATTERN.fullmatch(transaction_id) is None:
            raise _error("invalid_transaction_id")
        try:
            raw = read_regular(
                self.state_root,
                f"{transaction_id}.json",
                limit=_RECEIPT_LIMIT,
            )
            payload = json.loads(raw)
        except IntakeError:
            raise
        except (UnicodeError, json.JSONDecodeError) as error:
            raise _error("invalid_transaction_receipt") from error
        chunked_warnings: tuple[GuardViolationNotice, ...] | None = None
        if isinstance(payload, dict) and payload.get("schema") == TRANSACTION_SCHEMA:
            persisted_transaction_id = _string(payload.get("transaction_id"))
            if (
                persisted_transaction_id is None
                or _TX_PATTERN.fullmatch(persisted_transaction_id) is None
                or persisted_transaction_id != transaction_id
            ):
                raise _error("invalid_transaction_receipt")
            chunked_warnings = _load_chunked_warnings(
                self.state_root,
                persisted_transaction_id,
                payload.get("standing_guard_violations"),
            )
        receipt = _parse_receipt(payload, chunked_warnings=chunked_warnings)
        if receipt.transaction_id != transaction_id:
            raise _error("invalid_transaction_receipt")
        return receipt

    def authorize(
        self,
        preview: PromotionPreview,
        approved_digest: str,
        *,
        supersede_transaction_id: str | None = None,
        supersede_manifest_digest: str | None = None,
    ) -> TransactionReceipt:
        """Rebuild and persist one exact body-free owner authorization."""
        with self.lock():
            if (supersede_transaction_id is None) != (
                supersede_manifest_digest is None
            ):
                raise _error("invalid_supersede")
            if not hmac.compare_digest(approved_digest, preview.manifest_digest):
                raise _error("wrong_manifest_digest")
            active = self._active_locked()
            superseding = supersede_transaction_id is not None
            if active is None:
                if superseding:
                    raise _error("invalid_supersede")
            elif superseding:
                assert supersede_manifest_digest is not None
                if (
                    active.state is not TransactionState.OWNER_AUTHORIZED
                    or active.transaction_id != supersede_transaction_id
                    or not hmac.compare_digest(
                        active.manifest_digest,
                        supersede_manifest_digest,
                    )
                ):
                    raise _error("invalid_supersede")
                if hmac.compare_digest(
                    active.manifest_digest,
                    preview.manifest_digest,
                ):
                    return active
            elif hmac.compare_digest(
                active.manifest_digest,
                preview.manifest_digest,
            ):
                return active
            else:
                raise _error("transaction_active")

            from staged_memory_intake.config import require_config

            config = require_config(self.state_root)
            try:
                rebuilt = build_preview(
                    config,
                    [value.parsed.prepared_name for value in preview.candidates],
                    [_guard_raw(value) for value in preview.guard_links],
                )
            except IntakeError as error:
                raise _error("stale_preview") from error
            if not hmac.compare_digest(
                rebuilt.manifest_digest, preview.manifest_digest
            ):
                raise _error("stale_preview")
            item_ids = {
                value.parsed.prepared_name: value.client_item_id
                for value in rebuilt.candidates
            }
            transaction_id = (
                active.transaction_id
                if active is not None
                else f"tx_{secrets.token_hex(16)}"
            )
            receipt = TransactionReceipt(
                transaction_id=transaction_id,
                state=TransactionState.OWNER_AUTHORIZED,
                manifest_digest=rebuilt.manifest_digest,
                notes_root=str(config.notes_root),
                notes_identity=config.notes_identity,
                memory_home=(
                    None if config.memory_home is None else str(config.memory_home)
                ),
                memory_inbox=str(config.memory_inbox),
                inbox_identity=config.inbox_identity,
                batch_sensitivity=rebuilt.batch_sensitivity,
                candidates=tuple(
                    receipt_candidate(value) for value in rebuilt.candidates
                ),
                guard_links=tuple(
                    _receipt_guard(value, item_ids) for value in rebuilt.guard_links
                ),
                published_files=(),
                scan_started=False,
                batch_id=None,
                scan_source_ids=(),
                scan_issues=(),
                scan_has_more=None,
                scan_page_has_more=None,
                source_bindings=(),
                duplicate_notices=(),
                change_set_id=None,
                revision_id=None,
                review_digest=None,
                application_id=None,
                memory_ids=(),
                standing_guard_violations=(),
                cleanup_entries=(),
            )
            _persist_receipt(
                self.state_root,
                receipt,
                code="invalid_transaction_receipt",
            )
            if active is None:
                atomic_private_json(
                    self.state_root / _ACTIVE_NAME,
                    {"transaction_id": transaction_id},
                )
            return receipt

    def _clear_active_locked(self, transaction_id: str) -> None:
        try:
            raw = read_regular(self.state_root, _ACTIVE_NAME, limit=1024)
            pointer = _require_dict(json.loads(raw), {"transaction_id"})
        except (IntakeError, UnicodeError, json.JSONDecodeError) as error:
            raise _error("invalid_active_transaction") from error
        if pointer["transaction_id"] != transaction_id:
            raise _error("stale_transaction_receipt")
        self._unlink_active_pointer_locked()

    def _replace_locked(
        self,
        expected: TransactionReceipt,
        replacement: TransactionReceipt,
    ) -> TransactionReceipt:
        active = self._active_locked()
        if active != expected:
            raise _error("stale_transaction_receipt")
        validate_state_transition(expected.state, replacement.state)
        _persist_receipt(
            self.state_root,
            replacement,
            code="invalid_transaction_update",
        )
        if replacement.state is TransactionState.COMPLETE:
            self._clear_active_locked(replacement.transaction_id)
        return replacement

    def replace(self, receipt: TransactionReceipt) -> TransactionReceipt:
        """Idempotently re-persist only the exact currently active receipt."""
        with self.lock():
            return self._replace_locked(receipt, receipt)

    def advance(
        self,
        receipt: TransactionReceipt,
        next_state: TransactionState,
        **updates: object,
    ) -> TransactionReceipt:
        """Apply one immediate state edge or idempotent field update."""
        if not set(updates) <= _MUTABLE_FIELDS_BY_STATE[next_state]:
            raise _error("invalid_transaction_update")
        if "scan_started" in updates and (
            updates["scan_started"] is not True
            or receipt.state is not TransactionState.PUBLISHED
            or next_state is not TransactionState.PUBLISHED
        ):
            raise _error("invalid_transaction_update")
        validate_state_transition(receipt.state, next_state)
        with self.lock():
            current = self._active_locked()
            if (
                current is None
                and receipt.state is TransactionState.COMPLETE
                and next_state is TransactionState.COMPLETE
                and not updates
                and self.load(receipt.transaction_id) == receipt
            ):
                return receipt
            if current != receipt:
                raise _error("stale_transaction_receipt")
            try:
                updated = replace(
                    receipt,
                    state=next_state,
                    **updates,  # type: ignore[arg-type]  # Runtime field allowlist validates this dynamic update API.
                )
            except TypeError as error:
                raise _error("invalid_transaction_update") from error
            return self._replace_locked(receipt, updated)


def _validate_proposed_root(new_notes_root: Path) -> None:
    if not new_notes_root.is_absolute():
        raise _error("notes_root_not_absolute")
    directory_identity(new_notes_root)
    root_descriptor = os.open(
        new_notes_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        for folder in NUMBERED_LAYOUT.parked_children:
            metadata = os.stat(
                folder,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(metadata.st_mode):
                raise _error("relocation_root_invalid")
    except OSError as error:
        raise _error("relocation_root_invalid") from error
    finally:
        os.close(root_descriptor)
    for folder in (NUMBERED_LAYOUT.staged, NUMBERED_LAYOUT.prepared):
        root = new_notes_root / folder
        for name in inventory(root):
            try:
                read_regular(root, name, limit=max(_PREPARED_LIMIT, _SOURCE_LIMIT))
            except IntakeError as error:
                raise _error("relocation_root_invalid") from error


def _validate_reconfiguration_locked(
    store: TransactionStore,
    old: IntakeConfig | None,
    new_notes_root: Path,
) -> None:
    if store._active_locked() is not None:
        raise _error("transaction_active")
    _validate_proposed_root(new_notes_root)
    if old is None:
        return
    old_prepared = old.notes_root / NUMBERED_LAYOUT.prepared
    old_staged = old.notes_root / NUMBERED_LAYOUT.staged
    proposed_prepared = new_notes_root / NUMBERED_LAYOUT.prepared
    proposed_staged = new_notes_root / NUMBERED_LAYOUT.staged
    for prepared_name in inventory(old_prepared):
        try:
            prepared_bytes = read_regular(
                old_prepared,
                prepared_name,
                limit=_PREPARED_LIMIT,
            )
            source_names = inventory(old_staged)
            matched = None
            for source_name in source_names:
                try:
                    parsed = parse_prepared(
                        prepared_name,
                        prepared_bytes,
                        read_regular(old_staged, source_name, limit=_SOURCE_LIMIT),
                    )
                except IntakeError:
                    continue
                if parsed.source_name == source_name:
                    matched = parsed
                    break
            if matched is None:
                raise _error("relocation_binding_changed")
            proposed_prepared_bytes = read_regular(
                proposed_prepared,
                prepared_name,
                limit=_PREPARED_LIMIT,
            )
            if not hmac.compare_digest(
                matched.prepared_sha256,
                hashlib.sha256(proposed_prepared_bytes).hexdigest(),
            ):
                raise _error("relocation_binding_changed")
            proposed_staged_bytes = read_regular(
                proposed_staged,
                matched.source_name,
                limit=_SOURCE_LIMIT,
            )
            proposed_binding = parse_prepared(
                prepared_name,
                proposed_prepared_bytes,
                proposed_staged_bytes,
            )
            if proposed_binding != matched:
                raise _error("relocation_binding_changed")
        except IntakeError as error:
            if error.code == "transaction_active":
                raise
            raise _error("relocation_binding_changed") from error


def _legacy_receipt_names(state_root: Path) -> tuple[str, ...]:
    """Names of receipts whose schema is a recognized pre-v3 transaction.

    Only a readable JSON object whose schema names an older transaction
    format qualifies. A current-schema receipt is live recoverable state, and
    a malformed one is evidence of something else entirely; neither is ever
    touched.
    """
    names: list[str] = []
    for name in sorted(inventory(state_root)):
        if not name.endswith(".json"):
            continue
        if _TX_PATTERN.fullmatch(name.removesuffix(".json")) is None:
            continue
        try:
            payload = json.loads(read_regular(state_root, name, limit=_RECEIPT_LIMIT))
        except IntakeError, UnicodeError, json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        schema = payload.get("schema")
        if (
            isinstance(schema, str)
            and schema.startswith(_LEGACY_TRANSACTION_PREFIX)
            and schema != TRANSACTION_SCHEMA
        ):
            names.append(name)
    return tuple(names)


def _pointer_transaction_name(state_root: Path) -> str | None:
    try:
        payload = json.loads(read_regular(state_root, _ACTIVE_NAME, limit=1024))
    except IntakeError, UnicodeError, json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    transaction_id = payload.get("transaction_id")
    if not isinstance(transaction_id, str):
        return None
    if _TX_PATTERN.fullmatch(transaction_id) is None:
        return None
    return f"{transaction_id}.json"


def abandon_unsupported_transaction(state_root: Path) -> tuple[str, ...]:
    """Quarantine pre-v3 receipts so an upgraded helper can run again.

    A device-bound receipt is refused, never reinterpreted -- but before this
    hatch the refusal was terminal: the active pointer kept naming the
    unsupported receipt and no command could remove it. The pointer is
    released first, so a crash between the two steps leaves no wedge, only an
    orphaned legacy receipt the next run sweeps; each receipt is then renamed
    to an `abandoned-` name no code path reads, preserving its bytes for the
    owner. Current-schema and unreadable receipts are never touched.
    """
    store = TransactionStore.for_operation(state_root)
    with store.lock():
        legacy_names = _legacy_receipt_names(state_root)
        if not legacy_names:
            return ()
        if _pointer_transaction_name(state_root) in legacy_names:
            store._unlink_active_pointer_locked()
        for name in legacy_names:
            quarantine_state_entry(state_root, name)
        return tuple(name.removesuffix(".json") for name in legacy_names)


def validate_reconfiguration(
    store: TransactionStore,
    old: IntakeConfig | None,
    new_notes_root: Path,
) -> None:
    """Refuse active work and validate every relocation binding under lock."""
    with store.lock():
        _validate_reconfiguration_locked(store, old, new_notes_root)
