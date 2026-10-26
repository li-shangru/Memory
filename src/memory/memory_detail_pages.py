"""Bounded MCP detail walks; kernel/CLI full-detail calls retain their contract.

Every record is an indivisible bounded scalar or canonical row. A cursor resumes
strictly after the last emitted record, never after a priced-but-excluded row.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal, cast

from memory.database import Connection, Row
from memory.errors import InvalidArgumentError, NotFoundError, StaleCursorError
from memory.memories import (
    _MEMORY_SELECT,
    MAX_MEMORY_SELECTION,
    _attachment_from_row,
    _guard_tables_ready,
    _live_link_predicate,
    _summary_from_row,
)
from memory.model import EvidenceLocator, GuardAttachment, MemoryDetail, RuntimePaths
from memory.reviews import _locator_from_row
from memory.sources import (
    _effective_rank_sql,
    _read_connection,
    _validate_opaque_id,
    owner_current_generation,
)

MAX_DETAIL_RECORDS = 256
DETAIL_BODY_LIMIT = 8 * 1024 * 1024
# At most 4096 cursor characters, copied twice, plus the fixed envelope/schema,
# fragment discriminator and 50 bounded revision IDs when legacy reconstruction
# moves header fields. This reserve exceeds that fixed overhead by over 3x.
DETAIL_RESERVE = 64 * 1024
_SECTIONS = ("header", "evidence", "guards", "governs", "revision_ids")
Section = Literal["header", "evidence", "guards", "governs", "revision_ids"]


@dataclass(frozen=True)
class DetailRecord:
    selection_index: int
    memory_id: str
    section: Section
    value: MemoryDetail | EvidenceLocator | GuardAttachment | str
    after: int | str | tuple[int, int] | None


@dataclass(frozen=True)
class DetailPage:
    records: tuple[DetailRecord, ...]
    next_cursor: str | None


def read_detail_page(
    paths: RuntimePaths,
    selector: str,
    selection: tuple[str, ...],
    cursor: str | None,
    cost: Callable[[DetailRecord], int],
    *,
    budget: int = DETAIL_BODY_LIMIT - DETAIL_RESERVE,
) -> DetailPage:
    """Read at most 256 records plus one bounded sentinel in one snapshot."""
    if selector not in {"memory_id", "lineage_id", "memory_ids"}:
        raise InvalidArgumentError("memory selection is invalid")
    if not 1 <= len(selection) <= MAX_MEMORY_SELECTION or len(set(selection)) != len(
        selection
    ):
        raise InvalidArgumentError("memory selection is invalid or duplicated")
    for value in selection:
        _validate_opaque_id(value)
    with _read_connection(paths) as (connection, identity):
        connection.execute("BEGIN")
        generation = owner_current_generation(connection)
        payload = None if cursor is None else _cursor_payload(cursor)
        if payload is not None and (
            payload["store"] != identity.store_id or payload["generation"] != generation
        ):
            raise StaleCursorError(
                "memory detail cursor is stale or belongs to another Store"
            )
        ids = _resolve_selection(connection, selector, selection)
        binding = hashlib.sha256(
            json.dumps(
                [selector, selection, ids], ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        index, section, after = (
            (0, "header", None)
            if payload is None
            else _resume(
                payload,
                store=identity.store_id,
                binding=binding,
                generation=generation,
                ids=ids,
            )
        )
        if cursor is not None:
            _validate_anchor(connection, ids[index], section, after)
        records: list[DetailRecord] = []
        used = 0
        more = False
        for record in _records(
            connection, ids, index, section, after, resumed=cursor is not None
        ):
            item_cost = cost(record) + (2 if records else 0)
            if item_cost > budget and not records:
                # Canonical bounds guarantee one record fits. Invalid persisted
                # data must not create an oversized-first-record exception.
                raise InvalidArgumentError(
                    "memory detail record exceeds the response budget"
                )
            if len(records) == MAX_DETAIL_RECORDS or used + item_cost > budget:
                more = True
                break
            records.append(record)
            used += item_cost
        if cursor is not None and not records:
            raise StaleCursorError("memory detail cursor is exhausted")
        if more:
            last = records[-1]
            payload = {
                "version": 1,
                "operation": "memory.get",
                "store": identity.store_id,
                "binding": binding,
                "generation": generation,
                "index": last.selection_index,
                "section": last.section,
                "after": last.after,
            }
            next_cursor = (
                base64.urlsafe_b64encode(
                    json.dumps(payload, separators=(",", ":")).encode("utf-8")
                )
                .decode("ascii")
                .rstrip("=")
            )
        else:
            next_cursor = None
        return DetailPage(tuple(records), next_cursor)


def _resolve_selection(
    connection: Connection, selector: str, selection: tuple[str, ...]
) -> tuple[str, ...]:
    if selector == "lineage_id":
        row = connection.execute(
            "SELECT CASE WHEN length(CAST(revision_id AS BLOB)) <= 256 THEN revision_id END FROM current_memory_heads WHERE lineage_id = ?",
            selection,
        ).fetchone()
        if row is None:
            raise NotFoundError("memory lineage identifier was not found")
        if row[0] is None:
            raise InvalidArgumentError(
                "memory head identifier exceeds canonical bounds"
            )
        _validate_opaque_id(str(row[0]))
        return (str(row[0]),)
    for memory_id in selection:
        if (
            connection.execute(
                "SELECT 1 FROM memory_revisions WHERE revision_id = ?", (memory_id,)
            ).fetchone()
            is None
        ):
            raise NotFoundError("memory revision identifier was not found")
    return selection


def _cursor_payload(cursor: str) -> dict[str, Any]:
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
        raise StaleCursorError("memory detail cursor is invalid")
    try:
        raw = json.loads(
            base64.b64decode(
                cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
            )
        )
    except (ValueError, binascii.Error, UnicodeError, RecursionError) as error:
        raise StaleCursorError("memory detail cursor is invalid") from error
    if not isinstance(raw, dict) or set(raw) != {
        "version",
        "operation",
        "store",
        "binding",
        "generation",
        "index",
        "section",
        "after",
    }:
        raise StaleCursorError("memory detail cursor is invalid")
    return cast("dict[str, Any]", raw)


def _resume(
    raw: dict[str, Any],
    *,
    store: str,
    binding: str,
    generation: int,
    ids: tuple[str, ...],
) -> tuple[int, str, Any]:
    if (
        type(raw["version"]) is not int
        or raw["version"] != 1
        or raw["operation"] != "memory.get"
        or raw["store"] != store
        or raw["binding"] != binding
        or type(raw["generation"]) is not int
        or raw["generation"] != generation
    ):
        raise StaleCursorError(
            "memory detail cursor is stale or belongs to another selection"
        )
    index = raw["index"]
    section = raw["section"]
    after = raw["after"]
    if type(index) is not int or not 0 <= index < len(ids) or section not in _SECTIONS:
        raise StaleCursorError("memory detail cursor position is invalid")
    if isinstance(after, str):
        try:
            after.encode("utf-8")
        except UnicodeError as error:
            raise StaleCursorError(
                "memory detail cursor coordinate is invalid"
            ) from error
    valid = (
        (section == "header" and after is None)
        or (section == "evidence" and type(after) is int and 0 <= after < 16)
        or (
            section in {"guards", "governs"}
            and isinstance(after, str)
            and 1 <= len(after.encode("utf-8")) <= 256
            and "\x00" not in after
        )
        or (
            section == "revision_ids"
            and isinstance(after, list)
            and len(after) == 2
            and all(type(value) is int and -(2**63) <= value < 2**63 for value in after)
            and after[1] > 0
        )
    )
    if not valid:
        raise StaleCursorError("memory detail cursor coordinate is invalid")
    return index, section, after


def _validate_anchor(
    connection: Connection, memory_id: str, section: str, after: Any
) -> None:
    """Coordinates must name an actual preceding record in this detail."""
    lineage = connection.execute(
        "SELECT CASE WHEN length(CAST(lineage_id AS BLOB)) <= 256 THEN lineage_id END FROM memory_revisions WHERE revision_id = ?",
        (memory_id,),
    ).fetchone()
    if lineage is None or lineage[0] is None:
        raise StaleCursorError("memory detail cursor lineage is invalid")
    if section == "header":
        return
    if section == "evidence":
        row = connection.execute(
            "SELECT 1 FROM memory_evidence WHERE memory_revision_id = ? AND ordinal = ?",
            (memory_id, after),
        ).fetchone()
    elif section == "revision_ids":
        row = connection.execute(
            "SELECT 1 FROM memory_revisions WHERE lineage_id = ? AND recorded_at = ? AND rowid = ?",
            (lineage[0], after[0], after[1]),
        ).fetchone()
    else:
        subject, endpoint = (
            ("governed_lineage_id", "guard_lineage_id")
            if section == "guards"
            else ("guard_lineage_id", "governed_lineage_id")
        )
        row = connection.execute(
            f"SELECT 1 FROM memory_guard_links AS link WHERE link.{subject} = ? AND link.{endpoint} = ? "
            + _live_link_predicate(connection),
            (lineage[0], after),
        ).fetchone()
    if row is None:
        raise StaleCursorError("memory detail cursor anchor is invalid")


def _header(connection: Connection, memory_id: str) -> MemoryDetail:
    # Check scalar byte sizes inside SQLite before returning text to Python.
    # Invalid persisted data must not bypass the bounded record materialization.
    sizes = connection.execute(
        "SELECT length(CAST(statement AS BLOB)), length(CAST(tags_json AS BLOB)), length(CAST(lineage_id AS BLOB)), COALESCE(length(CAST(occurred_on AS BLOB)), 0), COALESCE(length(CAST(valid_from AS BLOB)), 0), COALESCE(length(CAST(valid_to AS BLOB)), 0) FROM memory_revisions WHERE revision_id = ?",
        (memory_id,),
    ).fetchone()
    assert sizes is not None
    if (
        int(sizes[0]) > 16384
        or int(sizes[1]) > 100000
        or int(sizes[2]) > 256
        or any(int(value) > 10 for value in sizes[3:])
    ):
        raise InvalidArgumentError("memory detail scalar exceeds canonical bounds")
    row = connection.execute(
        _MEMORY_SELECT + " WHERE mr.revision_id = ?", (memory_id,)
    ).fetchone()
    assert row is not None
    revision = _summary_from_row(row)
    state = connection.execute(
        "SELECT CASE WHEN length(CAST(heads.revision_id AS BLOB)) <= 256 THEN heads.revision_id END, CASE WHEN length(CAST(mr.predecessor_id AS BLOB)) <= 256 THEN mr.predecessor_id END, COALESCE(length(CAST(mr.predecessor_id AS BLOB)), 0) FROM memory_revisions AS mr JOIN current_memory_heads AS heads ON heads.lineage_id = mr.lineage_id WHERE mr.revision_id = ?",
        (memory_id,),
    ).fetchone()
    if state is None or state[0] is None or int(state[2]) > 256:
        raise InvalidArgumentError("memory lineage head or predecessor is invalid")
    return MemoryDetail(
        revision,
        str(state[0]) == memory_id,
        str(state[0]),
        None if state[1] is None else str(state[1]),
        (),
        (),
        (),
        (),
    )


def _records(
    connection: Connection,
    ids: tuple[str, ...],
    start: int,
    section: str,
    after: Any,
    *,
    resumed: bool,
) -> Iterator[DetailRecord]:
    ready = _guard_tables_ready(connection)
    for index in range(start, len(ids)):
        memory_id = ids[index]
        header = _header(connection, memory_id)
        lineage = header.revision.lineage_id
        first_section = _SECTIONS.index(section) if index == start else 0
        for order in range(first_section, len(_SECTIONS)):
            current = _SECTIONS[order]
            anchor = after if index == start and current == section else None
            if current == "header":
                if not (resumed and index == start and section == "header"):
                    yield DetailRecord(index, memory_id, "header", header, None)
            elif current == "evidence":
                rows = connection.execute(
                    "SELECT ordinal, CASE WHEN length(CAST(source_id AS BLOB)) <= 256 THEN source_id END, blob_digest, mode, char_start, char_end, CASE WHEN length(CAST(excerpt AS BLOB)) <= 4096 THEN excerpt END, source_level FROM memory_evidence WHERE memory_revision_id = ? AND ordinal > ? ORDER BY ordinal LIMIT 17",
                    (memory_id, -1 if anchor is None else anchor),
                )
                found = False
                for row in rows:
                    found = True
                    if (
                        int(row[0]) >= 16
                        or row[1] is None
                        or (row[3] == "text" and row[6] is None)
                    ):
                        raise InvalidArgumentError(
                            "memory evidence exceeds canonical bounds"
                        )
                    yield DetailRecord(
                        index,
                        memory_id,
                        "evidence",
                        _locator_from_row(row),
                        int(row[0]),
                    )
                if anchor is None and not found:
                    raise InvalidArgumentError(
                        "memory revision has no retained evidence"
                    )
            elif current in {"guards", "governs"} and ready:
                subject, endpoint = (
                    ("governed_lineage_id", "guard_lineage_id")
                    if current == "guards"
                    else ("guard_lineage_id", "governed_lineage_id")
                )
                # Predicate/order match the additive active-relationship indexes.
                rows = connection.execute(
                    "SELECT CASE WHEN length(CAST(mr.revision_id AS BLOB)) <= 256 THEN mr.revision_id END, CASE WHEN length(CAST(mr.lineage_id AS BLOB)) <= 256 THEN mr.lineage_id END, mr.kind, CASE WHEN length(CAST(mr.statement AS BLOB)) <= 16384 THEN mr.statement END, "
                    + _effective_rank_sql("mr")
                    + " FROM memory_guard_links AS link JOIN current_memory_heads AS heads ON heads.lineage_id = link."
                    + endpoint
                    + " JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id WHERE link."
                    + subject
                    + " = ? AND link."
                    + endpoint
                    + " > ? "
                    + _live_link_predicate(connection)
                    + "ORDER BY link."
                    + endpoint
                    + " LIMIT ?",
                    (lineage, "" if anchor is None else anchor, MAX_DETAIL_RECORDS + 1),
                )
                for row in rows:
                    if row[0] is None or row[1] is None or row[3] is None:
                        raise InvalidArgumentError(
                            "memory guard exceeds canonical bounds"
                        )
                    yield DetailRecord(
                        index,
                        memory_id,
                        cast("Section", current),
                        _attachment_from_row(row),
                        str(row[1]),
                    )
            elif current == "revision_ids":
                for row in _history_rows(connection, lineage, anchor):
                    if row[0] is None:
                        raise InvalidArgumentError(
                            "memory history identifier exceeds canonical bounds"
                        )
                    yield DetailRecord(
                        index,
                        memory_id,
                        "revision_ids",
                        str(row[0]),
                        (int(row[1]), int(row[2])),
                    )


def _history_rows(connection: Connection, lineage: str, anchor: Any) -> Iterator[Row]:
    # A tuple comparison only seeks recorded_at on SQLite: a dense tied date
    # would re-scan the previous prefix on every page. Two disjoint index seeks
    # use the index's implicit rowid key and preserve recorded_at,rowid order.
    prefix = (
        "SELECT CASE WHEN length(CAST(revision_id AS BLOB)) <= 256 "
        "THEN revision_id END, recorded_at, rowid FROM memory_revisions "
        "WHERE lineage_id = ? "
    )
    suffix = "ORDER BY recorded_at, rowid LIMIT ?"
    if anchor is None:
        yield from connection.execute(
            prefix + suffix, (lineage, MAX_DETAIL_RECORDS + 1)
        )
    else:
        yield from connection.execute(
            prefix + "AND recorded_at = ? AND rowid > ? " + suffix,
            (lineage, anchor[0], anchor[1], MAX_DETAIL_RECORDS + 1),
        )
        yield from connection.execute(
            prefix + "AND recorded_at > ? " + suffix,
            (lineage, anchor[0], MAX_DETAIL_RECORDS + 1),
        )
