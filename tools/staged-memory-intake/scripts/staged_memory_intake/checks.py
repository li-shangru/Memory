"""Strict planning and equality checks over agent-supplied Memory snapshots."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    MAX_PROMOTION_CANDIDATES,
    MAX_PUBLIC_SNAPSHOT_BYTES,
    DuplicateNotice,
    GuardViolationNotice,
    IntakeConfig,
    IntakeError,
    ParsedPrepared,
    ReceiptCandidate,
    ReceiptGuardLink,
    ScanIssueNotice,
    Sensitivity,
    SourceBinding,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.names import visible_inbox_name
from staged_memory_intake.prepared import parse_prepared
from staged_memory_intake.securefs import directory_identity, read_regular

_ENVELOPE_LIMIT = MAX_PUBLIC_SNAPSHOT_BYTES
_PREPARED_LIMIT = 256 * 1024
_SOURCE_LIMIT = 64 * 1024 * 1024
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_SENSITIVITY_RANK: Mapping[str, int] = {
    "normal": 0,
    "sensitive": 1,
    "restricted": 2,
}
_SCAN_ISSUE_CODES = frozenset(
    {"changed", "not_regular", "path_escape", "source_too_large", "symlink"}
)
_MAX_SCAN_ISSUES = 5
_MAX_BATCH_SOURCES = 64
_MAX_BATCH_DUPLICATES = 64


class _DuplicateJsonKey(ValueError):
    pass


def _memory_error(code: str) -> IntakeError:
    return IntakeError(code, "memory")


def _state_error(code: str) -> IntakeError:
    return IntakeError(code, "state")


def _drift_error(code: str) -> IntakeError:
    return IntakeError(code, "drift")


def _error(code: str) -> IntakeError:
    return _memory_error(code)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    del value
    raise ValueError


def parse_success_envelope(raw: bytes) -> object:
    """Parse one bounded duplicate-safe Memory success envelope."""
    if len(raw) > _ENVELOPE_LIMIT:
        raise _error("invalid_memory_envelope")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise _error("invalid_memory_envelope") from error
    if (
        not isinstance(decoded, dict)
        or decoded.get("schema") != "memory.mcp.v1"
        or decoded.get("instruction_trust") != "inert"
        or "data" not in decoded
        or "error" in decoded
    ):
        raise _error("invalid_memory_envelope")
    return decoded


def _mapping(value: object, keys: set[str], code: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _error(code)
    return value


def _mapping_optional(
    value: object,
    required: set[str],
    optional: set[str],
    code: str,
) -> Mapping[str, object]:
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or not set(value) <= required | optional
    ):
        raise _error(code)
    return value


def _envelope(
    value: Mapping[str, object],
    keys: set[str],
    code: str,
) -> Mapping[str, object]:
    raw = _mapping(value, keys, code)
    if raw["schema"] != "memory.mcp.v1" or raw["instruction_trust"] != "inert":
        raise _error(code)
    return raw


def _sequence(value: object, code: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise _error(code)
    return value


def _string(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\0" in value
    ):
        raise _error(code)
    return value


def _evidence_text(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\0" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise _error(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _error(code)
    return value


def _boolean(value: object, code: str) -> bool:
    if not isinstance(value, bool):
        raise _error(code)
    return value


def _hash(value: object, code: str) -> str:
    parsed = _string(value, code)
    if _HASH_PATTERN.fullmatch(parsed) is None:
        raise _error(code)
    return parsed


def _string_tuple(value: object, code: str) -> tuple[str, ...]:
    parsed = tuple(_string(item, code) for item in _sequence(value, code))
    if len(set(parsed)) != len(parsed):
        raise _error(code)
    return parsed


_BATCH_REQUIRED = {
    "batch_has_more",
    "batch_id",
    "duplicates",
    "issues",
    "review_state",
    "sealed_at",
    "source_count",
    "source_ids",
}
_BATCH_OPTIONAL = {"application_id", "change_set_id"}


def _scan_issue(value: object, code: str) -> ScanIssueNotice:
    raw = _mapping(value, {"code", "count"}, code)
    issue_code = _string(raw["code"], code)
    if issue_code not in _SCAN_ISSUE_CODES:
        raise _error(code)
    return ScanIssueNotice(
        code=issue_code,
        count=_integer(raw["count"], code, minimum=1),
    )


def _issues(value: object, code: str) -> tuple[ScanIssueNotice, ...]:
    values = _sequence(value, code)
    if len(values) > _MAX_SCAN_ISSUES:
        raise _error(code)
    result = tuple(_scan_issue(item, code) for item in values)
    if len({item.code for item in result}) != len(result):
        raise _error(code)
    return result


def _duplicate(value: object, code: str) -> DuplicateNotice:
    raw = _mapping(value, {"duplicate_of", "source_id"}, code)
    source_id = _string(raw["source_id"], code)
    duplicate_of = _string(raw["duplicate_of"], code)
    if source_id == duplicate_of:
        raise _error(code)
    return DuplicateNotice(source_id=source_id, duplicate_of=duplicate_of)


def _duplicates(value: object, code: str) -> tuple[DuplicateNotice, ...]:
    values = _sequence(value, code)
    if len(values) > _MAX_BATCH_DUPLICATES:
        raise _error(code)
    result = tuple(_duplicate(item, code) for item in values)
    if len({item.source_id for item in result}) != len(result):
        raise _error(code)
    return result


def _batch(value: object, code: str) -> Mapping[str, object]:
    raw = _mapping_optional(value, _BATCH_REQUIRED, _BATCH_OPTIONAL, code)
    batch_id = _string(raw["batch_id"], code)
    del batch_id
    _integer(raw["sealed_at"], code)
    source_count = _integer(raw["source_count"], code, minimum=1)
    source_ids = _string_tuple(raw["source_ids"], code)
    if (
        source_count > _MAX_BATCH_SOURCES
        or len(source_ids) > _MAX_BATCH_SOURCES
        or source_count != len(source_ids)
    ):
        raise _error(code)
    _boolean(raw["batch_has_more"], code)
    _issues(raw["issues"], code)
    duplicates = _duplicates(raw["duplicates"], code)
    if any(item.source_id not in source_ids for item in duplicates):
        raise _error(code)
    review_state = _string(raw["review_state"], code)
    change_set_id = (
        _string(raw["change_set_id"], code) if "change_set_id" in raw else None
    )
    application_id = (
        _string(raw["application_id"], code) if "application_id" in raw else None
    )
    if (
        review_state not in {"none", "draft", "applied"}
        or (
            review_state == "none"
            and (change_set_id is not None or application_id is not None)
        )
        or (
            review_state == "draft"
            and (change_set_id is None or application_id is not None)
        )
        or (
            review_state == "applied"
            and (change_set_id is None or application_id is None)
        )
    ):
        raise _error(code)
    return raw


def _scan_snapshot(
    envelope: Mapping[str, object],
) -> tuple[
    Mapping[str, object],
    tuple[str, ...],
    tuple[ScanIssueNotice, ...],
    tuple[DuplicateNotice, ...],
    bool,
    bool,
]:
    code = "invalid_scan_snapshot"
    if set(envelope) not in (
        {"data", "instruction_trust", "page", "schema"},
        {"data", "instruction_trust", "issues", "page", "schema"},
    ):
        raise _error(code)
    raw = _envelope(envelope, set(envelope), code)
    batch = _batch(raw["data"], code)
    page = _mapping(raw["page"], {"has_more"}, code)
    page_has_more = _boolean(page["has_more"], code)
    batch_issues = _issues(batch["issues"], code)
    issues = _issues(raw["issues"], code) if "issues" in raw else ()
    if "issues" in raw and not issues:
        raise _error(code)
    if issues != batch_issues or (batch_issues and "issues" not in raw):
        raise _error(code)
    source_ids = _string_tuple(batch["source_ids"], code)
    return (
        batch,
        source_ids,
        issues,
        _duplicates(batch["duplicates"], code),
        _boolean(batch["batch_has_more"], code),
        page_has_more,
    )


def record_scan(
    receipt: TransactionReceipt,
    scan_envelope: Mapping[str, object],
) -> TransactionReceipt:
    """Durably represent one structurally successful irreversible scan result."""
    if receipt.state not in {TransactionState.PUBLISHED, TransactionState.CAPTURED}:
        raise _state_error("invalid_snapshot_state")
    if not receipt.scan_started:
        raise _state_error("scan_not_started")
    batch, source_ids, issues, duplicates, has_more, page_has_more = _scan_snapshot(
        scan_envelope
    )
    batch_id = _string(batch["batch_id"], "invalid_scan_snapshot")
    recorded = replace(
        receipt,
        state=TransactionState.CAPTURED,
        batch_id=batch_id,
        scan_source_ids=source_ids,
        scan_issues=issues,
        scan_has_more=has_more,
        scan_page_has_more=page_has_more,
        duplicate_notices=duplicates,
    )
    if receipt.state is TransactionState.PUBLISHED:
        return recorded
    if receipt.batch_id != batch_id:
        raise _error("scan_result_changed")
    if recorded != receipt:
        raise _error("scan_result_changed")
    return receipt


_SOURCE_KEYS = {
    "authorship",
    "blob_digest",
    "byte_length",
    "captured_at",
    "declared_sensitivity",
    "effective_sensitivity",
    "media_type",
    "original_name",
    "origin",
    "searchable",
    "source_id",
}


def _source(value: object, code: str) -> Mapping[str, object]:
    raw = _mapping(value, _SOURCE_KEYS, code)
    _string(raw["source_id"], code)
    _string(raw["origin"], code)
    _hash(raw["blob_digest"], code)
    _string(raw["original_name"], code)
    _string(raw["media_type"], code)
    _integer(raw["byte_length"], code)
    _string(raw["authorship"], code)
    _string(raw["declared_sensitivity"], code)
    _string(raw["effective_sensitivity"], code)
    _boolean(raw["searchable"], code)
    _integer(raw["captured_at"], code)
    return raw


def _expected_review_state(
    receipt: TransactionReceipt,
) -> tuple[str, str | None, str | None]:
    if receipt.change_set_id is None:
        if receipt.application_id is not None:
            raise _error("batch_snapshot_mismatch")
        return "none", None, None
    if receipt.application_id is None:
        return "draft", receipt.change_set_id, None
    return "applied", receipt.change_set_id, receipt.application_id


def _validated_batch_bindings(
    receipt: TransactionReceipt,
    detail_envelope: Mapping[str, object],
) -> tuple[
    str,
    tuple[str, ...],
    tuple[ScanIssueNotice, ...],
    bool,
    tuple[SourceBinding, ...],
    tuple[DuplicateNotice, ...],
]:
    code = "batch_snapshot_mismatch"
    raw = _envelope(
        detail_envelope,
        {"data", "instruction_trust", "schema"},
        code,
    )
    detail = _mapping(raw["data"], {"batch", "sources"}, code)
    batch = _batch(detail["batch"], code)
    batch_id = _string(batch["batch_id"], code)
    if receipt.batch_id is not None and receipt.batch_id != batch_id:
        raise _error(code)
    source_ids = _string_tuple(batch["source_ids"], code)
    issues = _issues(batch["issues"], code)
    duplicates = _duplicates(batch["duplicates"], code)
    batch_has_more = _boolean(batch["batch_has_more"], code)
    expected_review_state, change_set_id, application_id = _expected_review_state(
        receipt
    )
    if (
        batch["review_state"] != expected_review_state
        or batch.get("change_set_id") != change_set_id
        or batch.get("application_id") != application_id
    ):
        raise _error(code)
    if len(receipt.published_files) != len(receipt.candidates):
        raise _error(code)
    try:
        expected_names = tuple(
            visible_inbox_name(
                receipt.transaction_id,
                candidate.ordinal,
                candidate.prepared_sha256,
                candidate.prepared_name,
            )
            for candidate in receipt.candidates
        )
    except IntakeError as error:
        raise _error(code) from error
    if tuple(item.inbox_name for item in receipt.published_files) != expected_names:
        raise _error(code)
    expected_by_name = {item.inbox_name: item for item in receipt.published_files}
    if len(expected_by_name) != len(receipt.published_files):
        raise _error(code)
    sources = tuple(
        _source(value, code) for value in _sequence(detail["sources"], code)
    )
    if len(sources) != len(expected_by_name) or len(source_ids) != len(
        expected_by_name
    ):
        raise _error(code)
    bindings: list[SourceBinding] = []
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    for source in sources:
        source_id = _string(source["source_id"], code)
        name = _string(source["original_name"], code)
        if source_id in seen_ids or name in seen_names:
            raise _error(code)
        seen_ids.add(source_id)
        seen_names.add(name)
        expected = expected_by_name.get(name)
        if expected is None or (
            source["blob_digest"] != expected.sha256
            or source["byte_length"] != expected.byte_length
            or source["origin"] != "inbox"
            or source["authorship"] != "mixed"
            or source["declared_sensitivity"] != receipt.batch_sensitivity
            or source["effective_sensitivity"] != receipt.batch_sensitivity
            or source["media_type"] != "text/markdown"
            or source["searchable"] is not True
        ):
            raise _error(code)
        bindings.append(
            SourceBinding(
                ordinal=expected.ordinal,
                inbox_name=name,
                source_id=source_id,
                blob_digest=_hash(source["blob_digest"], code),
            )
        )
    if (
        seen_names != set(expected_by_name)
        or tuple(source["source_id"] for source in sources) != source_ids
        or tuple(sorted(binding.ordinal for binding in bindings))
        != tuple(range(len(bindings)))
    ):
        raise _error(code)
    ordered = tuple(sorted(bindings, key=lambda value: value.ordinal))
    duplicate_sources = {item.source_id for item in duplicates}
    if (
        issues
        or (duplicates and (not duplicate_sources <= set(source_ids)))
        or batch_has_more
    ):
        raise _error(code)
    return batch_id, source_ids, issues, batch_has_more, ordered, duplicates


def check_batch(
    receipt: TransactionReceipt,
    batch_envelope: Mapping[str, object],
) -> TransactionReceipt:
    """Bind one exact sealed batch or recover it after an ambiguous scan call."""
    if receipt.state not in {
        TransactionState.PUBLISHED,
        TransactionState.CAPTURED,
        TransactionState.REVIEW_READY,
        TransactionState.AWAITING_MEMORY_APPROVAL,
        TransactionState.APPLIED,
        TransactionState.VERIFIED,
    }:
        raise _state_error("invalid_snapshot_state")
    if not receipt.scan_started:
        raise _state_error("scan_not_started")
    batch_id, source_ids, issues, has_more, bindings, duplicates = (
        _validated_batch_bindings(receipt, batch_envelope)
    )
    if receipt.state is not TransactionState.PUBLISHED:
        if (
            receipt.batch_id != batch_id
            or receipt.scan_source_ids != source_ids
            or receipt.scan_issues != issues
            or receipt.scan_has_more != has_more
            or receipt.scan_page_has_more is not False
            or receipt.duplicate_notices != duplicates
            or (receipt.source_bindings and receipt.source_bindings != bindings)
        ):
            raise _error("batch_snapshot_mismatch")
    next_state = (
        TransactionState.CAPTURED
        if receipt.state is TransactionState.PUBLISHED
        else receipt.state
    )
    return replace(
        receipt,
        state=next_state,
        batch_id=batch_id,
        scan_source_ids=source_ids,
        scan_issues=issues,
        scan_has_more=has_more,
        scan_page_has_more=False,
        source_bindings=bindings,
        duplicate_notices=duplicates,
    )


def begin_scan(receipt: TransactionReceipt) -> TransactionReceipt:
    """Irreversibly mark the one scan call as started before MCP invocation."""
    if receipt.state is not TransactionState.PUBLISHED:
        raise _state_error("invalid_snapshot_state")
    if receipt.scan_started:
        return receipt
    return replace(receipt, scan_started=True)


def _same_candidate(candidate: ReceiptCandidate, parsed: ParsedPrepared) -> bool:
    return (
        candidate.prepared_name == parsed.prepared_name
        and candidate.source_name == parsed.source_name
        and candidate.prepared_sha256 == parsed.prepared_sha256
        and candidate.source_sha256 == parsed.source_sha256
        and candidate.statement_sha256 == parsed.statement_sha256
        and candidate.statement_utf8_bytes == parsed.statement_utf8_bytes
        and candidate.evidence_char_start == parsed.evidence_char_start
        and candidate.evidence_char_end == parsed.evidence_char_end
        and candidate.evidence_sha256 == parsed.evidence_sha256
        and candidate.metadata.kind == parsed.requested_metadata.kind
        and candidate.metadata.occurred_on == parsed.requested_metadata.occurred_on
        and candidate.metadata.valid_from == parsed.requested_metadata.valid_from
        and candidate.metadata.valid_to == parsed.requested_metadata.valid_to
        and candidate.metadata.tags == parsed.requested_metadata.tags
    )


def _prepared_values(
    receipt: TransactionReceipt,
    config: IntakeConfig,
) -> tuple[ParsedPrepared, ...]:
    try:
        identities_match = (
            directory_identity(config.notes_root) == config.notes_identity
            and directory_identity(config.memory_inbox) == config.inbox_identity
        )
    except IntakeError as error:
        raise _drift_error("prepared_snapshot_changed") from error
    if (
        not identities_match
        or Path(receipt.notes_root) != config.notes_root
        or receipt.notes_identity != config.notes_identity
        or receipt.memory_home
        != (None if config.memory_home is None else str(config.memory_home))
        or Path(receipt.memory_inbox) != config.memory_inbox
        or receipt.inbox_identity != config.inbox_identity
        or len(receipt.candidates) > MAX_PROMOTION_CANDIDATES
    ):
        raise _drift_error("prepared_snapshot_changed")
    result: list[ParsedPrepared] = []
    for candidate in receipt.candidates:
        try:
            prepared_bytes = read_regular(
                config.notes_root / NUMBERED_LAYOUT.prepared,
                candidate.prepared_name,
                limit=_PREPARED_LIMIT,
            )
            staged_bytes = read_regular(
                config.notes_root / NUMBERED_LAYOUT.staged,
                candidate.source_name,
                limit=_SOURCE_LIMIT,
            )
            parsed = parse_prepared(
                candidate.prepared_name,
                prepared_bytes,
                staged_bytes,
            )
        except IntakeError as error:
            raise _drift_error("prepared_snapshot_changed") from error
        if not _same_candidate(candidate, parsed):
            raise _drift_error("prepared_snapshot_changed")
        if candidate.metadata.sensitivity != receipt.batch_sensitivity:
            raise _drift_error("prepared_snapshot_changed")
        result.append(parsed)
    return tuple(result)


def _memory_input(
    receipt: TransactionReceipt,
    candidate: ReceiptCandidate,
    parsed: ParsedPrepared,
) -> dict[str, object]:
    metadata = candidate.metadata
    return {
        "kind": metadata.kind,
        "statement": parsed.statement,
        "occurred_on": metadata.occurred_on,
        "valid_from": metadata.valid_from,
        "valid_to": metadata.valid_to,
        "tags": list(metadata.tags),
        "sensitivity": receipt.batch_sensitivity,
        "target_lineage_id": None,
        "expected_head_id": None,
    }


def _guard_edit(link: ReceiptGuardLink) -> dict[str, object]:
    result: dict[str, object] = {"op": "add_guard_link"}
    if link.guard_item_id is not None:
        result["guard_item_id"] = link.guard_item_id
    elif link.guard_lineage_id is not None:
        result["guard_lineage_id"] = link.guard_lineage_id
    else:
        raise _state_error("review_plan_mismatch")
    if link.governed_item_id is not None:
        result["governed_item_id"] = link.governed_item_id
    elif link.governed_lineage_id is not None:
        result["governed_lineage_id"] = link.governed_lineage_id
    else:
        raise _state_error("review_plan_mismatch")
    if link.guard_item_id is None and link.governed_item_id is None:
        raise _state_error("review_plan_mismatch")
    return result


def build_review_edits(
    receipt: TransactionReceipt,
    config: IntakeConfig,
) -> tuple[dict[str, object], ...]:
    """Reopen exact Prepared bodies and construct one exact edit sequence."""
    if (
        receipt.state is not TransactionState.CAPTURED
        or len(receipt.source_bindings) != len(receipt.candidates)
        or tuple(value.ordinal for value in receipt.source_bindings)
        != tuple(range(len(receipt.candidates)))
    ):
        raise _state_error("invalid_snapshot_state")
    parsed_values = _prepared_values(receipt, config)
    edits: list[dict[str, object]] = []
    for candidate, parsed, binding in zip(
        receipt.candidates,
        parsed_values,
        receipt.source_bindings,
        strict=True,
    ):
        edits.append(
            {
                "op": "add_item",
                "client_item_id": candidate.client_item_id,
                "memory": _memory_input(receipt, candidate, parsed),
                "evidence": [
                    {
                        "source_id": binding.source_id,
                        "blob_digest": binding.blob_digest,
                        "excerpt": parsed.evidence_excerpt,
                    }
                ],
            }
        )
    edits.extend(_guard_edit(link) for link in receipt.guard_links)
    return tuple(edits)


def _exact_json(actual: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int equality shortcut."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict) or set(actual) != set(expected):
            return False
        return all(_exact_json(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return False
        return all(
            _exact_json(actual_value, expected_value)
            for actual_value, expected_value in zip(actual, expected, strict=True)
        )
    return actual == expected


_REVIEW_KEYS = {
    "adapter_origin",
    "batch_id",
    "change_set_id",
    "digest",
    "guard_links",
    "items",
    "revision_id",
    "revoked_guard_links",
    "source_decisions",
    "state",
}


def _review_evidence(
    binding: SourceBinding,
    parsed: ParsedPrepared,
) -> dict[str, object]:
    return {
        "ordinal": 0,
        "source_id": binding.source_id,
        "blob_digest": binding.blob_digest,
        "mode": "text",
        "char_start": parsed.evidence_char_start,
        "char_end": parsed.evidence_char_end,
        "excerpt": parsed.evidence_excerpt,
    }


def _review_guard(link: ReceiptGuardLink, ordinal: int) -> dict[str, object]:
    return {
        "ordinal": ordinal,
        "guard_item_id": link.guard_item_id,
        "guard_lineage_id": link.guard_lineage_id,
        "governed_item_id": link.governed_item_id,
        "governed_lineage_id": link.governed_lineage_id,
        "status": "active",
    }


def _expected_review_collections(
    receipt: TransactionReceipt,
    parsed_values: tuple[ParsedPrepared, ...],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    items: list[dict[str, object]] = []
    decisions: list[dict[str, object]] = []
    for ordinal, (candidate, parsed, binding) in enumerate(
        zip(
            receipt.candidates,
            parsed_values,
            receipt.source_bindings,
            strict=True,
        )
    ):
        items.append(
            {
                "ordinal": ordinal,
                "item_id": candidate.client_item_id,
                "status": "active",
                "memory": _memory_input(receipt, candidate, parsed),
                "evidence": [_review_evidence(binding, parsed)],
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
    guards = [
        _review_guard(link, ordinal) for ordinal, link in enumerate(receipt.guard_links)
    ]
    return items, decisions, guards


def check_review(
    receipt: TransactionReceipt,
    view_envelope: Mapping[str, object],
) -> TransactionReceipt:
    """Bind one exact unedited MCP review revision and digest."""
    if receipt.state not in {
        TransactionState.CAPTURED,
        TransactionState.REVIEW_READY,
        TransactionState.AWAITING_MEMORY_APPROVAL,
    }:
        raise _state_error("invalid_snapshot_state")
    if len(receipt.source_bindings) != len(receipt.candidates):
        raise _state_error("invalid_snapshot_state")
    config = IntakeConfig(
        notes_root=Path(receipt.notes_root),
        notes_identity=receipt.notes_identity,
        memory_home=(
            None if receipt.memory_home is None else Path(receipt.memory_home)
        ),
        memory_inbox=Path(receipt.memory_inbox),
        inbox_identity=receipt.inbox_identity,
        # pending_drop stays default: receipt-derived configs resolve paths only.
    )
    parsed_values = _prepared_values(receipt, config)
    code = "review_snapshot_mismatch"
    envelope = _envelope(
        view_envelope,
        {"data", "instruction_trust", "schema"},
        code,
    )
    view = _mapping(envelope["data"], _REVIEW_KEYS, code)
    change_set_id = _string(view["change_set_id"], code)
    revision_id = _string(view["revision_id"], code)
    digest = _hash(view["digest"], code)
    items, decisions, guards = _expected_review_collections(receipt, parsed_values)
    if (
        view["batch_id"] != receipt.batch_id
        or view["adapter_origin"] != "mcp"
        or view["state"] != "draft"
        or not _exact_json(view["items"], items)
        or not _exact_json(view["source_decisions"], decisions)
        or not _exact_json(view["guard_links"], guards)
        or not _exact_json(view["revoked_guard_links"], [])
    ):
        raise _error(code)
    if receipt.state is TransactionState.CAPTURED:
        if (
            receipt.change_set_id is not None
            or receipt.revision_id is not None
            or receipt.review_digest is not None
        ):
            raise _error(code)
        return replace(
            receipt,
            state=TransactionState.REVIEW_READY,
            change_set_id=change_set_id,
            revision_id=revision_id,
            review_digest=digest,
        )
    if (
        receipt.change_set_id != change_set_id
        or receipt.revision_id != revision_id
        or receipt.review_digest != digest
    ):
        raise _error(code)
    return receipt


def mark_awaiting_approval(
    receipt: TransactionReceipt,
    revision_id: str,
    digest: str,
) -> TransactionReceipt:
    """Record that the owner was shown the same complete review revision."""
    if receipt.state not in {
        TransactionState.REVIEW_READY,
        TransactionState.AWAITING_MEMORY_APPROVAL,
    }:
        raise _state_error("invalid_snapshot_state")
    try:
        checked_revision = _string(revision_id, "review_binding_mismatch")
        checked_digest = _hash(digest, "review_binding_mismatch")
    except IntakeError as error:
        raise _state_error("review_binding_mismatch") from error
    if (
        receipt.revision_id != checked_revision
        or receipt.review_digest != checked_digest
        or receipt.change_set_id is None
    ):
        raise _state_error("review_binding_mismatch")
    if receipt.state is TransactionState.AWAITING_MEMORY_APPROVAL:
        return receipt
    return replace(receipt, state=TransactionState.AWAITING_MEMORY_APPROVAL)


_APPLICATION_KEYS = {
    "application_id",
    "change_set_id",
    "idempotent_replay",
    "memory_ids",
    "revision_id",
    "standing_guard_violations",
}
_VIOLATION_KEYS = {
    "guard_lineage_id",
    "guard_sensitivity",
    "governed_lineage_id",
    "governed_sensitivity",
}


def _sensitivity(value: object, code: str) -> Sensitivity:
    parsed = _string(value, code)
    if parsed not in _SENSITIVITY_RANK:
        raise _error(code)
    return cast(Sensitivity, parsed)


def _guard_violations(
    value: object,
    code: str,
) -> tuple[GuardViolationNotice, ...]:
    result: list[GuardViolationNotice] = []
    pairs: set[tuple[str, str]] = set()
    for item in _sequence(value, code):
        raw = _mapping(item, _VIOLATION_KEYS, code)
        guard_lineage_id = _string(raw["guard_lineage_id"], code)
        governed_lineage_id = _string(raw["governed_lineage_id"], code)
        pair = (guard_lineage_id, governed_lineage_id)
        if pair in pairs or guard_lineage_id == governed_lineage_id:
            raise _error(code)
        pairs.add(pair)
        result.append(
            GuardViolationNotice(
                guard_lineage_id=guard_lineage_id,
                guard_sensitivity=_sensitivity(raw["guard_sensitivity"], code),
                governed_lineage_id=governed_lineage_id,
                governed_sensitivity=_sensitivity(
                    raw["governed_sensitivity"],
                    code,
                ),
            )
        )
    return tuple(result)


def record_application(
    receipt: TransactionReceipt,
    application_envelope: Mapping[str, object],
) -> TransactionReceipt:
    """Bind one application result without dropping standing violations."""
    if receipt.state not in {
        TransactionState.AWAITING_MEMORY_APPROVAL,
        TransactionState.APPLIED,
    }:
        raise _state_error("invalid_snapshot_state")
    code = "application_snapshot_mismatch"
    envelope = _envelope(
        application_envelope,
        {"data", "instruction_trust", "schema"},
        code,
    )
    application = _mapping(envelope["data"], _APPLICATION_KEYS, code)
    application_id = _string(application["application_id"], code)
    change_set_id = _string(application["change_set_id"], code)
    revision_id = _string(application["revision_id"], code)
    memory_ids = _string_tuple(application["memory_ids"], code)
    _boolean(application["idempotent_replay"], code)
    warnings = _guard_violations(application["standing_guard_violations"], code)
    if (
        change_set_id != receipt.change_set_id
        or revision_id != receipt.revision_id
        or len(memory_ids) != len(receipt.candidates)
        or not memory_ids
    ):
        raise _error(code)
    if receipt.state is TransactionState.APPLIED:
        if application_id != receipt.application_id or set(memory_ids) != set(
            receipt.memory_ids
        ):
            raise _error(code)
        return replace(receipt, standing_guard_violations=warnings)
    if receipt.application_id is not None or receipt.memory_ids:
        raise _error(code)
    return replace(
        receipt,
        state=TransactionState.APPLIED,
        application_id=application_id,
        memory_ids=memory_ids,
        standing_guard_violations=warnings,
    )


_DETAIL_KEYS = {
    "current_head_id",
    "evidence",
    "governs",
    "guards",
    "is_current",
    "revision",
    "revision_ids",
}
_SUMMARY_REQUIRED = {
    "effective_sensitivity",
    "kind",
    "lineage_id",
    "memory_id",
    "recorded_at",
    "statement",
    "stored_sensitivity",
    "tags",
}
_TEXT_EVIDENCE_KEYS = {
    "blob_digest",
    "char_end",
    "char_start",
    "excerpt",
    "mode",
    "ordinal",
    "source_id",
}
_ATTACHMENT_KEYS = {
    "effective_sensitivity",
    "kind",
    "lineage_id",
    "memory_id",
    "statement",
}
_KINDS = {"fact", "event", "preference", "relation", "insight"}


def _kind(value: object, code: str) -> str:
    parsed = _string(value, code)
    if parsed not in _KINDS:
        raise _error(code)
    return parsed


def _expected_summary_keys(candidate: ReceiptCandidate) -> set[str]:
    keys = set(_SUMMARY_REQUIRED)
    metadata = candidate.metadata
    if metadata.occurred_on is not None:
        keys.add("occurred_on")
    if metadata.valid_from is not None:
        keys.add("valid_from")
    if metadata.valid_to is not None:
        keys.add("valid_to")
    return keys


def _validated_summary(
    value: object,
    receipt: TransactionReceipt,
    candidate: ReceiptCandidate,
    parsed: ParsedPrepared,
    code: str,
) -> Mapping[str, object]:
    summary = _mapping(value, _expected_summary_keys(candidate), code)
    memory_id = _string(summary["memory_id"], code)
    del memory_id
    _string(summary["lineage_id"], code)
    _integer(summary["recorded_at"], code)
    effective = _sensitivity(summary["effective_sensitivity"], code)
    metadata = candidate.metadata
    if (
        _kind(summary["kind"], code) != metadata.kind
        or summary["statement"] != parsed.statement
        or not _exact_json(summary["tags"], list(metadata.tags))
        or summary["stored_sensitivity"] != receipt.batch_sensitivity
        or _SENSITIVITY_RANK[effective] < _SENSITIVITY_RANK[receipt.batch_sensitivity]
        or summary.get("occurred_on") != metadata.occurred_on
        or summary.get("valid_from") != metadata.valid_from
        or summary.get("valid_to") != metadata.valid_to
    ):
        raise _error(code)
    _sensitivity(summary["stored_sensitivity"], code)
    return summary


def _validated_attachment(value: object, code: str) -> Mapping[str, object]:
    attachment = _mapping(value, _ATTACHMENT_KEYS, code)
    _string(attachment["memory_id"], code)
    _string(attachment["lineage_id"], code)
    _kind(attachment["kind"], code)
    _string(attachment["statement"], code)
    _sensitivity(attachment["effective_sensitivity"], code)
    return attachment


def _attachment_from_summary(summary: Mapping[str, object]) -> dict[str, object]:
    return {
        "memory_id": summary["memory_id"],
        "lineage_id": summary["lineage_id"],
        "kind": summary["kind"],
        "statement": summary["statement"],
        "effective_sensitivity": summary["effective_sensitivity"],
    }


def _validated_detail_evidence(
    value: object,
    code: str,
) -> Mapping[str, object]:
    evidence = _sequence(value, code)
    if len(evidence) != 1:
        raise _error(code)
    raw = _mapping(evidence[0], _TEXT_EVIDENCE_KEYS, code)
    _integer(raw["ordinal"], code)
    _string(raw["source_id"], code)
    _hash(raw["blob_digest"], code)
    _integer(raw["char_start"], code)
    _integer(raw["char_end"], code)
    _evidence_text(raw["excerpt"], code)
    if raw["mode"] != "text":
        raise _error(code)
    return raw


def _expected_relationships(
    receipt: TransactionReceipt,
    summaries: Mapping[int, Mapping[str, object]],
    code: str,
) -> tuple[
    dict[int, list[tuple[str, Mapping[str, object] | None]]],
    dict[int, list[tuple[str, Mapping[str, object] | None]]],
]:
    item_ordinals = {
        candidate.client_item_id: candidate.ordinal for candidate in receipt.candidates
    }
    if len(item_ordinals) != len(receipt.candidates):
        raise _error(code)
    guards: dict[int, list[tuple[str, Mapping[str, object] | None]]] = {
        ordinal: [] for ordinal in range(len(receipt.candidates))
    }
    governs: dict[int, list[tuple[str, Mapping[str, object] | None]]] = {
        ordinal: [] for ordinal in range(len(receipt.candidates))
    }
    for link in receipt.guard_links:
        guard_ordinal = (
            None
            if link.guard_item_id is None
            else item_ordinals.get(link.guard_item_id)
        )
        governed_ordinal = (
            None
            if link.governed_item_id is None
            else item_ordinals.get(link.governed_item_id)
        )
        if (
            (link.guard_item_id is not None and guard_ordinal is None)
            or (link.governed_item_id is not None and governed_ordinal is None)
            or (guard_ordinal is None and governed_ordinal is None)
        ):
            raise _error(code)
        guard_lineage = (
            _string(link.guard_lineage_id, code)
            if guard_ordinal is None
            else _string(summaries[guard_ordinal]["lineage_id"], code)
        )
        governed_lineage = (
            _string(link.governed_lineage_id, code)
            if governed_ordinal is None
            else _string(summaries[governed_ordinal]["lineage_id"], code)
        )
        if guard_lineage == governed_lineage:
            raise _error(code)
        if guard_ordinal is not None:
            expected = (
                None
                if governed_ordinal is None
                else _attachment_from_summary(summaries[governed_ordinal])
            )
            governs[guard_ordinal].append((governed_lineage, expected))
        if governed_ordinal is not None:
            expected = (
                None
                if guard_ordinal is None
                else _attachment_from_summary(summaries[guard_ordinal])
            )
            guards[governed_ordinal].append((guard_lineage, expected))
    for values in (*guards.values(), *governs.values()):
        values.sort(key=lambda value: value[0])
        if len({lineage for lineage, _ in values}) != len(values):
            raise _error(code)
    return guards, governs


def _check_attachments(
    value: object,
    expected: list[tuple[str, Mapping[str, object] | None]],
    code: str,
) -> tuple[Mapping[str, object], ...]:
    actual = tuple(_validated_attachment(item, code) for item in _sequence(value, code))
    if len(actual) != len(expected):
        raise _error(code)
    for attachment, (lineage_id, exact) in zip(actual, expected, strict=True):
        if attachment["lineage_id"] != lineage_id:
            raise _error(code)
        if exact is not None and not _exact_json(attachment, dict(exact)):
            raise _error(code)
    return actual


def _register_attachment_identity(
    attachment: Mapping[str, object],
    by_lineage: dict[str, Mapping[str, object]],
    lineage_by_memory_id: dict[str, str],
    code: str,
) -> None:
    lineage_id = _string(attachment["lineage_id"], code)
    memory_id = _string(attachment["memory_id"], code)
    prior_lineage = lineage_by_memory_id.get(memory_id)
    prior_attachment = by_lineage.get(lineage_id)
    if (prior_lineage is not None and prior_lineage != lineage_id) or (
        prior_attachment is not None
        and not _exact_json(attachment, dict(prior_attachment))
    ):
        raise _error(code)
    lineage_by_memory_id[memory_id] = lineage_id
    by_lineage[lineage_id] = attachment


def _validate_relationship_snapshot(
    receipt: TransactionReceipt,
    summaries: Mapping[int, Mapping[str, object]],
    guards: Mapping[int, tuple[Mapping[str, object], ...]],
    governs: Mapping[int, tuple[Mapping[str, object], ...]],
    code: str,
) -> None:
    item_ordinals = {
        candidate.client_item_id: candidate.ordinal for candidate in receipt.candidates
    }
    if len(item_ordinals) != len(receipt.candidates):
        raise _error(code)
    selected = {
        ordinal: _attachment_from_summary(summary)
        for ordinal, summary in summaries.items()
    }
    by_lineage: dict[str, Mapping[str, object]] = {}
    lineage_by_memory_id: dict[str, str] = {}
    for selected_attachment in selected.values():
        _register_attachment_identity(
            selected_attachment,
            by_lineage,
            lineage_by_memory_id,
            code,
        )
    for attachments in (*guards.values(), *governs.values()):
        for attachment in attachments:
            _register_attachment_identity(
                attachment,
                by_lineage,
                lineage_by_memory_id,
                code,
            )

    def resolved(
        item_id: str | None,
        lineage_id: str | None,
    ) -> Mapping[str, object]:
        if item_id is not None:
            ordinal = item_ordinals.get(item_id)
            if ordinal is None:
                raise _error(code)
            return selected[ordinal]
        if lineage_id is None:
            raise _error(code)
        attachment = by_lineage.get(lineage_id)
        if attachment is None:
            raise _error(code)
        return attachment

    for link in receipt.guard_links:
        guard = resolved(link.guard_item_id, link.guard_lineage_id)
        governed = resolved(link.governed_item_id, link.governed_lineage_id)
        guard_sensitivity = _sensitivity(guard["effective_sensitivity"], code)
        governed_sensitivity = _sensitivity(governed["effective_sensitivity"], code)
        if (
            _SENSITIVITY_RANK[guard_sensitivity]
            > _SENSITIVITY_RANK[governed_sensitivity]
        ):
            raise _error(code)


def check_memories(
    receipt: TransactionReceipt,
    config: IntakeConfig,
    detail_envelope: Mapping[str, object],
) -> TransactionReceipt:
    """Verify one bounded full-detail bijection before authorizing cleanup."""
    if receipt.state not in {TransactionState.APPLIED, TransactionState.VERIFIED}:
        raise _state_error("invalid_snapshot_state")
    if (
        receipt.application_id is None
        or len(receipt.memory_ids) != len(receipt.candidates)
        or not receipt.memory_ids
        or len(receipt.memory_ids) > MAX_PROMOTION_CANDIDATES
        or len(set(receipt.memory_ids)) != len(receipt.memory_ids)
        or len(receipt.source_bindings) != len(receipt.candidates)
    ):
        raise _error("memory_snapshot_mismatch")
    parsed_values = _prepared_values(receipt, config)
    code = "memory_snapshot_mismatch"
    envelope = _envelope(
        detail_envelope,
        {"data", "instruction_trust", "schema"}
        | ({"page"} if "page" in detail_envelope else set()),
        code,
    )
    # Older complete snapshots omit page; current MCP always includes it.
    # Only a complete, cursor-free page can authorize cleanup. Fragment data
    # remains invalid even on its final page because details must be a list.
    if "page" in envelope:
        page = _mapping(envelope["page"], {"has_more"}, code)
        if page["has_more"] is not False:
            raise _error(code)
    details = _sequence(envelope["data"], code)
    if len(details) != len(receipt.candidates):
        raise _error(code)
    source_ordinals = {
        binding.source_id: binding.ordinal for binding in receipt.source_bindings
    }
    if len(source_ordinals) != len(receipt.source_bindings):
        raise _error(code)
    by_ordinal: dict[int, tuple[Mapping[str, object], Mapping[str, object]]] = {}
    seen_memory_ids: set[str] = set()
    seen_lineages: set[str] = set()
    existing_lineages = {
        lineage_id
        for link in receipt.guard_links
        for lineage_id in (link.guard_lineage_id, link.governed_lineage_id)
        if lineage_id is not None
    }
    for value in details:
        detail = _mapping(value, _DETAIL_KEYS, code)
        evidence = _validated_detail_evidence(detail["evidence"], code)
        source_id = _string(evidence["source_id"], code)
        ordinal = source_ordinals.get(source_id)
        if ordinal is None or ordinal in by_ordinal:
            raise _error(code)
        candidate = receipt.candidates[ordinal]
        parsed = parsed_values[ordinal]
        binding = receipt.source_bindings[ordinal]
        summary = _validated_summary(
            detail["revision"],
            receipt,
            candidate,
            parsed,
            code,
        )
        memory_id = _string(summary["memory_id"], code)
        lineage_id = _string(summary["lineage_id"], code)
        if (
            memory_id not in receipt.memory_ids
            or memory_id in seen_memory_ids
            or lineage_id in seen_lineages
            or lineage_id in existing_lineages
            or detail["is_current"] is not True
            or detail["current_head_id"] != memory_id
            or not _exact_json(detail["revision_ids"], [memory_id])
            or not _exact_json(evidence, _review_evidence(binding, parsed))
        ):
            raise _error(code)
        seen_memory_ids.add(memory_id)
        seen_lineages.add(lineage_id)
        by_ordinal[ordinal] = (detail, summary)
    if set(by_ordinal) != set(range(len(receipt.candidates))) or seen_memory_ids != set(
        receipt.memory_ids
    ):
        raise _error(code)
    summaries = {ordinal: value[1] for ordinal, value in by_ordinal.items()}
    expected_guards, expected_governs = _expected_relationships(
        receipt,
        summaries,
        code,
    )
    actual_guards: dict[int, tuple[Mapping[str, object], ...]] = {}
    actual_governs: dict[int, tuple[Mapping[str, object], ...]] = {}
    for ordinal, (detail, _) in by_ordinal.items():
        actual_guards[ordinal] = _check_attachments(
            detail["guards"], expected_guards[ordinal], code
        )
        actual_governs[ordinal] = _check_attachments(
            detail["governs"], expected_governs[ordinal], code
        )
    _validate_relationship_snapshot(
        receipt,
        summaries,
        actual_guards,
        actual_governs,
        code,
    )
    if receipt.state is TransactionState.VERIFIED:
        return receipt
    return replace(receipt, state=TransactionState.VERIFIED)
