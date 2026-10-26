"""Exact Prepared parsing, deterministic evidence, and promotion previews."""

from __future__ import annotations

import calendar
import hashlib
import json
import re
from bisect import bisect_right
from collections.abc import Collection, Mapping, Sequence
from dataclasses import replace
from datetime import date
from pathlib import PurePosixPath
from typing import cast

from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    MAX_PROMOTION_CANDIDATES,
    DirectoryIdentity,
    GuardEndpoint,
    GuardSpec,
    IntakeConfig,
    IntakeError,
    MemoryKind,
    MemoryMetadata,
    ParsedPrepared,
    PreparedCandidate,
    PromotionPreview,
    Sensitivity,
    identity_payload,
)
from staged_memory_intake.names import (
    PLACEHOLDER_TRANSACTION_ID,
    visible_inbox_name,
)
from staged_memory_intake.securefs import directory_identity, read_regular

MANIFEST_SCHEMA = "staged-memory-intake.promotion-manifest.v2"
_PREPARED_LIMIT = 256 * 1024
_SOURCE_LIMIT = 64 * 1024 * 1024
_STATEMENT_LIMIT = 16_384
_EVIDENCE_LIMIT = 4_096
_TAG_LIMIT = 256
_TAG_COUNT_LIMIT = 64
_EDIT_LIMIT = 256
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_DATE_PATTERN = re.compile(r"([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?")
_KINDS: frozenset[str] = frozenset(
    {"fact", "event", "preference", "relation", "insight"}
)
_SENSITIVITIES: tuple[Sensitivity, ...] = (
    "normal",
    "sensitive",
    "restricted",
)
_HEADER_PREFIXES = (
    "memory_intake_version: ",
    "source_note: ",
    "source_sha256: ",
    "kind: ",
    "sensitivity: ",
    "occurred_on: ",
    "valid_from: ",
    "valid_to: ",
    "tags: ",
)


def _error(code: str) -> IntakeError:
    return IntakeError(code, "state")


def _decode_prepared(prepared_bytes: bytes) -> str:
    try:
        text = prepared_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _error("invalid_prepared") from error
    if text.startswith("\ufeff") or "\r" in text or "\0" in text:
        raise _error("invalid_prepared")
    return text


def _header_values(text: str) -> tuple[tuple[str, ...], str]:
    lines = text.split("\n")
    if len(lines) < 12 or lines[0] != "---" or lines[10] != "---":
        raise _error("invalid_prepared")
    values: list[str] = []
    for line, prefix in zip(lines[1:10], _HEADER_PREFIXES, strict=True):
        if not line.startswith(prefix):
            raise _error("invalid_prepared")
        values.append(line.removeprefix(prefix))
    body = "\n".join(lines[11:])
    if body.endswith("\n"):
        body = body[:-1]
    if not body or body != body.strip():
        raise _error("invalid_prepared")
    return tuple(values), body


def _is_markdown_name(name: str) -> bool:
    return (
        bool(name)
        and "\0" not in name
        and PurePosixPath(name).parts == (name,)
        and name.endswith(".md")
    )


def _partial_date_bounds(raw: str) -> tuple[date, date] | None:
    if not raw:
        return None
    matched = _DATE_PATTERN.fullmatch(raw)
    if matched is None:
        raise _error("invalid_prepared")
    year = int(matched.group(1))
    month_text = matched.group(2)
    day_text = matched.group(3)
    try:
        if month_text is None:
            return date(year, 1, 1), date(year, 12, 31)
        month = int(month_text)
        if day_text is None:
            return (
                date(year, month, 1),
                date(year, month, calendar.monthrange(year, month)[1]),
            )
        exact = date(year, month, int(day_text))
        return exact, exact
    except (ValueError, calendar.IllegalMonthError) as error:
        raise _error("invalid_prepared") from error


def _parse_tags(raw: str) -> tuple[str, ...]:
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character.isspace():
            raise _error("invalid_prepared")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise _error("invalid_prepared") from error
    if not isinstance(decoded, list) or len(decoded) > _TAG_COUNT_LIMIT:
        raise _error("invalid_prepared")
    tags: list[str] = []
    seen: set[str] = set()
    for value in decoded:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\0" in value
            or len(value.encode("utf-8")) > _TAG_LIMIT
            or value in seen
        ):
            raise _error("invalid_prepared")
        seen.add(value)
        tags.append(value)
    return tuple(tags)


def _metadata(values: tuple[str, ...]) -> tuple[str, str, MemoryMetadata]:
    (
        version,
        source_name,
        source_sha256,
        kind_raw,
        sensitivity_raw,
        occurred_on,
        valid_from,
        valid_to,
        tags_raw,
    ) = values
    if (
        version != "1"
        or not _is_markdown_name(source_name)
        or _HASH_PATTERN.fullmatch(source_sha256) is None
        or kind_raw not in _KINDS
        or sensitivity_raw not in _SENSITIVITIES
    ):
        raise _error("invalid_prepared")
    occurred_bounds = _partial_date_bounds(occurred_on)
    valid_from_bounds = _partial_date_bounds(valid_from)
    valid_to_bounds = _partial_date_bounds(valid_to)
    del occurred_bounds
    if (
        valid_from_bounds is not None
        and valid_to_bounds is not None
        and valid_from_bounds[0] > valid_to_bounds[1]
    ):
        raise _error("invalid_prepared")
    metadata = MemoryMetadata(
        kind=cast(MemoryKind, kind_raw),
        sensitivity=sensitivity_raw,
        occurred_on=occurred_on or None,
        valid_from=valid_from or None,
        valid_to=valid_to or None,
        tags=_parse_tags(tags_raw),
    )
    return source_name, source_sha256, metadata


def _source_name(prepared_bytes: bytes) -> str:
    values, _ = _header_values(_decode_prepared(prepared_bytes))
    source_name, _, _ = _metadata(values)
    return source_name


def _unique_location(haystack: str, needle: str) -> int | None:
    first = haystack.find(needle)
    if first < 0 or haystack.find(needle, first + 1) >= 0:
        return None
    return first


def _select_evidence(statement: str, source_text: str) -> tuple[str, int, int]:
    if len(statement.encode("utf-8")) <= _EVIDENCE_LIMIT:
        location = _unique_location(source_text, statement)
        if location is None:
            raise _error("evidence_not_unique")
        return statement, location, location + len(statement)

    byte_offsets = [0]
    for character in statement:
        byte_offsets.append(byte_offsets[-1] + len(character.encode("utf-8")))
    for start in range(len(statement)):
        end = (
            bisect_right(
                byte_offsets,
                byte_offsets[start] + _EVIDENCE_LIMIT,
                lo=start + 1,
            )
            - 1
        )
        excerpt = statement[start:end]
        location = _unique_location(source_text, excerpt)
        if location is not None:
            return excerpt, location, location + len(excerpt)
    raise _error("evidence_not_unique")


def parse_prepared(
    prepared_name: str,
    prepared_bytes: bytes,
    staged_bytes: bytes,
) -> ParsedPrepared:
    """Parse one exact Prepared Markdown candidate and bind its source bytes."""
    if not _is_markdown_name(prepared_name):
        raise _error("invalid_prepared")
    prepared_text = _decode_prepared(prepared_bytes)
    values, statement = _header_values(prepared_text)
    source_name, declared_source_sha256, metadata = _metadata(values)
    source_sha256 = hashlib.sha256(staged_bytes).hexdigest()
    if source_sha256 != declared_source_sha256:
        raise _error("source_hash_mismatch")
    statement_bytes = statement.encode("utf-8")
    if len(statement_bytes) > _STATEMENT_LIMIT:
        raise _error("statement_too_large")
    try:
        staged_text = staged_bytes.decode("utf-8")
    except UnicodeDecodeError:
        staged_text = ""
    evidence, evidence_start, evidence_end = _select_evidence(
        statement,
        prepared_text,
    )
    return ParsedPrepared(
        prepared_name=prepared_name,
        source_name=source_name,
        prepared_sha256=hashlib.sha256(prepared_bytes).hexdigest(),
        source_sha256=source_sha256,
        statement=statement,
        statement_sha256=hashlib.sha256(statement_bytes).hexdigest(),
        statement_utf8_bytes=len(statement_bytes),
        verbatim_statement=staged_text.strip() == statement,
        evidence_excerpt=evidence,
        evidence_sha256=hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        evidence_char_start=evidence_start,
        evidence_char_end=evidence_end,
        requested_metadata=metadata,
    )


class _DuplicateJsonKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _parse_endpoint(raw: object, selected_names: Collection[str]) -> GuardEndpoint:
    if not isinstance(raw, dict) or len(raw) != 1:
        raise _error("invalid_guard_spec")
    key, value = next(iter(raw.items()))
    if (
        key not in {"prepared_name", "lineage_id"}
        or not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\0" in value
    ):
        raise _error("invalid_guard_spec")
    if key == "prepared_name":
        if value not in selected_names:
            raise _error("invalid_guard_spec")
        return GuardEndpoint(prepared_name=value, lineage_id=None)
    return GuardEndpoint(prepared_name=None, lineage_id=value)


def parse_guard_spec(raw: str, selected_names: Collection[str]) -> GuardSpec:
    """Parse one strict JSON guard relationship into typed endpoints."""
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, _DuplicateJsonKey) as error:
        raise _error("invalid_guard_spec") from error
    if not isinstance(decoded, dict) or set(decoded) != {"guard", "governed"}:
        raise _error("invalid_guard_spec")
    guard = _parse_endpoint(decoded["guard"], selected_names)
    governed = _parse_endpoint(decoded["governed"], selected_names)
    if guard == governed or (
        guard.prepared_name is None and governed.prepared_name is None
    ):
        raise _error("invalid_guard_spec")
    return GuardSpec(guard=guard, governed=governed)


def _identity_json(identity: DirectoryIdentity) -> dict[str, object]:
    return identity_payload(identity)


def _metadata_json(metadata: MemoryMetadata) -> dict[str, object]:
    return {
        "kind": metadata.kind,
        "sensitivity": metadata.sensitivity,
        "occurred_on": metadata.occurred_on,
        "valid_from": metadata.valid_from,
        "valid_to": metadata.valid_to,
        "tags": list(metadata.tags),
    }


def _endpoint_json(endpoint: GuardEndpoint) -> dict[str, object]:
    if endpoint.prepared_name is not None:
        return {"prepared_name": endpoint.prepared_name}
    if endpoint.lineage_id is None:
        raise _error("invalid_guard_spec")
    return {"lineage_id": endpoint.lineage_id}


def _manifest_payload(
    config: IntakeConfig,
    candidates: Sequence[PreparedCandidate],
    guards: Sequence[GuardSpec],
    batch_sensitivity: Sensitivity,
) -> dict[str, object]:
    candidate_payloads: list[object] = []
    for candidate in candidates:
        parsed = candidate.parsed
        # verbatim_statement stays out of this payload: it derives entirely
        # from the digest-bound prepared and staged bytes, and adding it
        # would shift every in-flight manifest digest for nothing.
        candidate_payloads.append(
            {
                "ordinal": candidate.ordinal,
                "prepared_name": parsed.prepared_name,
                "source_name": parsed.source_name,
                "prepared_sha256": parsed.prepared_sha256,
                "source_sha256": parsed.source_sha256,
                "statement_sha256": parsed.statement_sha256,
                "statement_utf8_bytes": parsed.statement_utf8_bytes,
                "evidence_sha256": parsed.evidence_sha256,
                "evidence_char_start": parsed.evidence_char_start,
                "evidence_char_end": parsed.evidence_char_end,
                "requested_metadata": _metadata_json(parsed.requested_metadata),
                "final_metadata": _metadata_json(candidate.final_metadata),
                "client_item_id": candidate.client_item_id,
            }
        )
    guard_payloads: list[object] = []
    for guard in guards:
        guard_payloads.append(
            {
                "guard": _endpoint_json(guard.guard),
                "governed": _endpoint_json(guard.governed),
            }
        )
    return {
        "schema": MANIFEST_SCHEMA,
        "notes_identity": _identity_json(config.notes_identity),
        "inbox_identity": _identity_json(config.inbox_identity),
        "candidates": candidate_payloads,
        "guard_links": guard_payloads,
        "batch_sensitivity": batch_sensitivity,
    }


def _manifest_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_preview(
    config: IntakeConfig,
    prepared_names: Sequence[str],
    guard_specs: Sequence[str],
) -> PromotionPreview:
    """Read an explicit ordered selection and bind its exact promotion plan."""
    if len(prepared_names) > MAX_PROMOTION_CANDIDATES:
        raise _error("too_many_candidates")
    if len(prepared_names) + len(guard_specs) > _EDIT_LIMIT:
        raise _error("too_many_edits")
    if len(set(prepared_names)) != len(prepared_names):
        raise _error("duplicate_candidate")
    if (
        directory_identity(config.notes_root) != config.notes_identity
        or directory_identity(config.memory_inbox) != config.inbox_identity
    ):
        raise _error("configured_root_changed")
    prepared_root = config.notes_root / NUMBERED_LAYOUT.prepared
    staged_root = config.notes_root / NUMBERED_LAYOUT.staged
    directory_identity(prepared_root)
    directory_identity(staged_root)
    parsed_values: list[ParsedPrepared] = []
    for prepared_name in prepared_names:
        prepared_bytes = read_regular(
            prepared_root,
            prepared_name,
            limit=_PREPARED_LIMIT,
        )
        source_name = _source_name(prepared_bytes)
        staged_bytes = read_regular(staged_root, source_name, limit=_SOURCE_LIMIT)
        parsed_values.append(
            parse_prepared(prepared_name, prepared_bytes, staged_bytes)
        )
    selected_names = set(prepared_names)
    guards: list[GuardSpec] = []
    seen_guards: set[GuardSpec] = set()
    for raw_guard in guard_specs:
        guard = parse_guard_spec(raw_guard, selected_names)
        if guard in seen_guards:
            raise _error("duplicate_guard_link")
        seen_guards.add(guard)
        guards.append(guard)
    batch_sensitivity: Sensitivity = "normal"
    for parsed in parsed_values:
        requested_sensitivity = parsed.requested_metadata.sensitivity
        if _SENSITIVITIES.index(requested_sensitivity) > _SENSITIVITIES.index(
            batch_sensitivity
        ):
            batch_sensitivity = requested_sensitivity
    candidates: list[PreparedCandidate] = []
    for ordinal, parsed in enumerate(parsed_values):
        client_digest = hashlib.sha256(
            f"{ordinal}:{parsed.prepared_sha256}".encode("ascii")
        ).hexdigest()
        candidates.append(
            PreparedCandidate(
                ordinal=ordinal,
                parsed=parsed,
                final_metadata=replace(
                    parsed.requested_metadata,
                    sensitivity=batch_sensitivity,
                ),
                client_item_id=f"itm_{client_digest[:40]}",
            )
        )
    visible_names = tuple(
        visible_inbox_name(
            PLACEHOLDER_TRANSACTION_ID,
            candidate.ordinal,
            candidate.parsed.prepared_sha256,
            candidate.parsed.prepared_name,
        )
        for candidate in candidates
    )
    if len(set(visible_names)) != len(visible_names):
        raise _error("published_name_collision")
    payload = _manifest_payload(config, candidates, guards, batch_sensitivity)
    return PromotionPreview(
        candidates=tuple(candidates),
        guard_links=tuple(guards),
        batch_sensitivity=batch_sensitivity,
        manifest_digest=_manifest_digest(payload),
    )


def preview_json(preview: PromotionPreview) -> dict[str, object]:
    """Render the content-free owner manifest; complete content stays in files."""
    candidates: list[object] = []
    for candidate in preview.candidates:
        parsed = candidate.parsed
        candidates.append(
            {
                "ordinal": candidate.ordinal,
                "prepared_name": parsed.prepared_name,
                "source_name": parsed.source_name,
                "prepared_sha256": parsed.prepared_sha256,
                "source_sha256": parsed.source_sha256,
                "requested_sensitivity": parsed.requested_metadata.sensitivity,
                "verbatim_statement": parsed.verbatim_statement,
            }
        )
    return {
        "schema": "staged-memory-intake.promotion-preview.v1",
        "candidates": candidates,
        "candidate_count": len(candidates),
        "guard_links": [
            {
                "guard": _endpoint_json(guard.guard),
                "governed": _endpoint_json(guard.governed),
            }
            for guard in preview.guard_links
        ],
        "guard_link_count": len(preview.guard_links),
        "batch_sensitivity": preview.batch_sensitivity,
        "manifest_digest": preview.manifest_digest,
    }
