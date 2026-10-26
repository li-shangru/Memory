"""Source byte classification and custody helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import PurePath
from typing import Any, Literal

from memory.database import Connection, Row, open_database
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
    StaleCursorError,
)
from memory.keys import load_master_key
from memory.model import (
    INBOX_ISSUE_CODES,
    Authorship,
    BatchDetail,
    Cursor,
    DuplicateCapture,
    InboxBatch,
    Issue,
    Page,
    RuntimePaths,
    Sensitivity,
    SourceCaptureOrigin,
    SourceFilters,
    SourceSummary,
    StoreIdentity,
    StoreStatus,
)
from memory.runtime import load_runtime_identity
from memory.ui.view_models import (
    OwnerBatchDetail,
    OwnerBatchIssue,
    OwnerBatchSummary,
    OwnerEvidenceLink,
    OwnerPage,
    OwnerSourceDetail,
    OwnerSourceSummary,
    SourceProjectionCoverage,
)
from memory.validation import sensitivity_from_rank, strict_utf8_bytes

MEDIA_TYPES = {
    ".csv": "text/csv",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".json": "application/json",
    ".markdown": "text/markdown",
    ".md": "text/markdown",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".txt": "text/plain",
    ".webp": "image/webp",
}
SEARCHABLE_MEDIA_TYPES = {
    "application/json",
    "text/csv",
    "text/markdown",
    "text/plain",
}


def source_projection_uses_capture_rowid(connection: Connection) -> bool:
    """Report whether the disposable source projection uses rowid binding."""
    return any(
        str(row[1]) == "capture_rowid"
        for row in connection.execute("PRAGMA table_info(source_fts)").fetchall()
    )


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
MAX_SQLITE_ROWID = (1 << 63) - 1
_CURSOR_VERSION = 1
_SOURCE_PROJECTION_FILTER_BINDING_VERSION = 2
_SEARCHABLE_MEDIA_TYPE_SQL = ", ".join(
    f"'{media_type}'" for media_type in sorted(SEARCHABLE_MEDIA_TYPES)
)
_CANONICAL_SOURCE_ELIGIBILITY = (
    f"s.media_type IN ({_SEARCHABLE_MEDIA_TYPE_SQL}) AND b.utf8_text IS NOT NULL"
)
_CANONICAL_SOURCE_PROJECTION_CONDITIONS = (
    "rowid = s.rowid",
    "capture_rowid = s.rowid",
    "source_id = s.source_id",
    "utf8_text = b.utf8_text",
    "original_name = s.original_name",
)


def _canonical_source_projection_predicate(
    alias: Literal["projected", "source_fts"],
) -> str:
    """Bind an eligible capture's fixed projection alias to custody and content."""
    fidelity = " AND ".join(
        f"{alias}.{condition}" for condition in _CANONICAL_SOURCE_PROJECTION_CONDITIONS
    )
    return f"{_CANONICAL_SOURCE_ELIGIBILITY} AND {fidelity}"


def _source_projection_membership_sql(
    connection: Connection,
    *,
    match_authoritative_text: bool = False,
) -> str:
    """Return the one shape-aware membership predicate for fixed aliases.

    Every caller aliases the authoritative capture as ``s``, its blob as ``b``,
    and the projection probe as ``projected``. Those names are package literals,
    never caller input. Canonical membership first requires an authoritatively
    eligible text capture, then includes both indexed fields, so every flag,
    filter, status, coverage, and audit surface rejects binary captures and
    projection text or a filename that differs from authoritative custody. The
    optional text equality preserves the legacy owner-audit behavior before
    reindex.
    """
    conditions = ["projected.source_id = s.source_id"]
    if source_projection_uses_capture_rowid(connection):
        conditions = [_canonical_source_projection_predicate("projected")]
    elif match_authoritative_text:
        conditions.append("projected.utf8_text = b.utf8_text")
    joined = " AND ".join(conditions)
    return f"EXISTS(SELECT 1 FROM source_fts AS projected WHERE {joined})"


def _source_status_membership_sql(connection: Connection) -> str:
    """Return a shape-aware, linear status-count membership predicate.

    Canonical projections use the exact indexed rowid predicate shared by every
    flag. A legacy projection has no indexed coordinate, so status composes its
    UNINDEXED source IDs once instead of correlating one FTS scan per source.
    `COALESCE` keeps an injected NULL projection ID from turning a nonmember's
    predicate into SQL NULL.
    """
    if source_projection_uses_capture_rowid(connection):
        return _source_projection_membership_sql(connection)
    return (
        "COALESCE(s.source_id IN ("
        "SELECT projected.source_id FROM source_fts AS projected"
        "), 0)"
    )


def _source_select(connection: Connection) -> str:
    """Build the public source summary select for the live projection shape."""
    membership = _source_projection_membership_sql(connection)
    return f"""
    SELECT
        s.rowid,
        s.source_id,
        s.origin,
        b.sha256,
        s.original_name,
        s.media_type,
        b.byte_length,
        s.authorship,
        s.sensitivity,
        (
            SELECT MAX(
                CASE effective.sensitivity
                    WHEN 'normal' THEN 0
                    WHEN 'sensitive' THEN 1
                    WHEN 'restricted' THEN 2
                END
            )
            FROM sources AS effective
            WHERE effective.blob_id = s.blob_id
        ),
        {membership},
        s.captured_at
    FROM sources AS s
    JOIN source_blobs AS b ON b.blob_id = s.blob_id
    """


def _effective_rank_sql(alias: str) -> str:
    """Return the one canonical memory-side effective-sensitivity rank expression.

    A memory revision is read at the highest of its own declared sensitivity and
    the sensitivity of every source sharing a blob with one it cites. Three
    readers need that number and all three must agree: memory-search cursors
    digest the rank, so a drift between copies would silently restate a page.
    The source-side expression is deliberately not folded in here -- it ranks a
    blob's sibling sources with no revision or evidence join, a different rule
    over different tables that only looks similar. The interpolated alias must
    be a SQL identifier literal from this package, never caller input.
    """
    return f"""MAX(
    CASE {alias}.sensitivity
        WHEN 'normal' THEN 0
        WHEN 'sensitive' THEN 1
        WHEN 'restricted' THEN 2
    END,
    COALESCE(
        (
            SELECT MAX(
                CASE effective.sensitivity
                    WHEN 'normal' THEN 0
                    WHEN 'sensitive' THEN 1
                    WHEN 'restricted' THEN 2
                END
            )
            FROM memory_evidence AS evidence
            JOIN sources AS cited ON cited.source_id = evidence.source_id
            JOIN sources AS effective ON effective.blob_id = cited.blob_id
            WHERE evidence.memory_revision_id = {alias}.revision_id
        ),
        0
    )
)"""


def media_type_for_name(original_name: str) -> str:
    """Return the fixed declared media type for a capture name."""
    extension = PurePath(original_name).suffix.lower()
    return MEDIA_TYPES.get(extension, "application/octet-stream")


def searchable_text(media_type: str, original_bytes: bytes) -> str | None:
    """Decode only allowlisted text bytes using strict UTF-8."""
    if media_type not in SEARCHABLE_MEDIA_TYPES:
        return None
    try:
        return original_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def retained_utf8_text(original_bytes: bytes) -> str | None:
    """Return immutable byte-derived UTF-8 text independent of capture metadata."""
    try:
        return original_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _source_filter_clause(
    connection: Connection,
    filters: SourceFilters,
) -> tuple[str, tuple[object, ...]]:
    """Render the enumeration filters as one SQL fragment and its parameters.

    `searchable` is answered against the same projection-membership expression
    `SourceSummary.searchable` reports, so a filtered page can never contain a
    row whose own flag contradicts the filter that admitted it.
    """
    clauses: list[str] = []
    parameters: list[object] = []
    if filters.origin is not None:
        clauses.append(" AND s.origin = ?")
        parameters.append(filters.origin.value)
    if filters.searchable is not None:
        clauses.append(f" AND {_source_projection_membership_sql(connection)} = ?")
        parameters.append(1 if filters.searchable else 0)
    return "".join(clauses), tuple(parameters)


def _normalize_source_filters(filters: SourceFilters) -> SourceFilters:
    if not isinstance(filters, SourceFilters):
        raise InvalidArgumentError("source filters are invalid")
    if filters.searchable is not None and not isinstance(filters.searchable, bool):
        raise InvalidArgumentError("source searchable filter is invalid")
    if filters.origin is not None and not isinstance(
        filters.origin, SourceCaptureOrigin
    ):
        raise InvalidArgumentError("source origin filter is invalid")
    return filters


def list_sources(
    paths: RuntimePaths,
    cursor: Cursor | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    filters: SourceFilters = SourceFilters(),
) -> Page[SourceSummary]:
    """Enumerate every capture using a stable source-row high-water mark.

    Filters join the cursor binding, so changing one mid-walk stales the cursor
    rather than resuming a traversal it was never part of. A projection filter
    additionally binds the exact eligible membership under that high-water
    mark, because reindex can change it without changing an authoritative row.
    Generation says when that membership must be recomposed; only its exact
    digest decides whether the cursor is stale.
    """
    page_size = _validate_page_size(limit)
    normalized = _normalize_source_filters(filters)
    binding_payload: dict[str, object] = {
        "origin": None if normalized.origin is None else normalized.origin.value,
        "searchable": normalized.searchable,
    }
    if normalized.searchable is not None:
        binding_payload["projection_membership"] = (
            _SOURCE_PROJECTION_FILTER_BINDING_VERSION
        )
    binding = owner_filter_binding(binding_payload)
    with _read_connection(paths) as (connection, identity):
        clause, filter_parameters = _source_filter_clause(connection, normalized)
        projection_filtered = normalized.searchable is not None
        if projection_filtered:
            # Generation, digest when needed, summary flags, and visible page
            # must describe one projection state even if reindex commits.
            connection.execute("BEGIN")
        after, upper = _page_bounds(
            connection,
            identity,
            operation="source.list",
            cursor=cursor,
            upper_table="sources",
            binding=binding,
        )
        snapshot: str | None = None
        generation: int | None = None
        if projection_filtered:
            generation = owner_current_generation(connection)
            if cursor is None:
                snapshot = _source_list_snapshot_digest(
                    connection,
                    upper=upper,
                    clause=clause,
                    filter_parameters=filter_parameters,
                )
            else:
                cursor_generation, cursor_snapshot = _source_list_cursor_state(
                    _decode_cursor(cursor)
                )
                if generation == cursor_generation:
                    snapshot = cursor_snapshot
                else:
                    snapshot = _source_list_snapshot_digest(
                        connection,
                        upper=upper,
                        clause=clause,
                        filter_parameters=filter_parameters,
                    )
                    if snapshot != cursor_snapshot:
                        raise StaleCursorError("source list snapshot changed")
        rows = connection.execute(
            _source_select(connection)
            + " WHERE s.rowid > ? AND s.rowid <= ?"
            + clause
            + " ORDER BY s.rowid LIMIT ?",
            (after, upper, *filter_parameters, page_size + 1),
        ).fetchall()
        return _source_page(
            rows,
            identity=identity,
            operation="source.list",
            upper=upper,
            page_size=page_size,
            binding=binding,
            snapshot=snapshot,
            generation=generation,
        )


def _source_list_snapshot_digest(
    connection: Connection,
    *,
    upper: int,
    clause: str,
    filter_parameters: tuple[object, ...],
) -> str:
    """Stream the ordered eligible identities into their canonical digest."""
    digest = hashlib.sha256()
    digest.update(b'{"entries":[')
    first = True
    for row in connection.execute(
        _source_list_snapshot_select(clause),
        (upper, *filter_parameters),
    ):
        if first:
            first = False
        else:
            digest.update(b",")
        digest.update(
            json.dumps(
                [int(row[0]), str(row[1])],
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
    digest.update(b'],"upper":')
    digest.update(str(upper).encode("ascii"))
    digest.update(b"}")
    return digest.hexdigest()


def _source_list_snapshot_select(clause: str) -> str:
    """Build the streamed membership query from the production filter clause."""
    # `clause` was produced by `_source_filter_clause` from fixed package SQL
    # and contains no caller-authored identifier.
    return (
        "SELECT s.rowid, s.source_id FROM sources AS s "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE s.rowid <= ?" + clause + " ORDER BY s.rowid"
    )


def _source_list_cursor_state(payload: Mapping[str, object]) -> tuple[int, str]:
    """Validate the composition state required by a projection-filtered cursor."""
    generation = payload.get("generation")
    snapshot = payload.get("snapshot")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
        or not isinstance(snapshot, str)
        or len(snapshot) != 64
        or any(character not in "0123456789abcdef" for character in snapshot)
    ):
        raise StaleCursorError("source list snapshot state is invalid")
    return generation, snapshot


#: Every sealed batch with the one review it may ever have. The two LEFT JOINs
#: are what makes a review backlog visible from the batch side: a batch with no
#: change set reads `none`, and neither join can multiply a row because
#: `change_sets.batch_id` and `applications.change_set_id` are both UNIQUE.
_BATCH_SELECT = """
SELECT
    batch.rowid,
    batch.batch_id,
    batch.sealed_at,
    batch.source_count,
    batch.has_more,
    change_set.change_set_id,
    change_set.state,
    application.application_id
FROM inbox_batches AS batch
LEFT JOIN change_sets AS change_set ON change_set.batch_id = batch.batch_id
LEFT JOIN applications AS application
    ON application.change_set_id = change_set.change_set_id
"""


def list_batches(
    paths: RuntimePaths,
    cursor: Cursor | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> Page[InboxBatch]:
    """Enumerate sealed batches using a stable batch-row high-water mark."""
    page_size = _validate_page_size(limit)
    with _read_connection(paths) as (connection, identity):
        after, upper = _page_bounds(
            connection,
            identity,
            operation="inbox.list",
            cursor=cursor,
            upper_table="inbox_batches",
        )
        rows = connection.execute(
            _BATCH_SELECT + " WHERE batch.rowid > ? AND batch.rowid <= ? "
            "ORDER BY batch.rowid LIMIT ?",
            (after, upper, page_size + 1),
        ).fetchall()
        has_more = len(rows) > page_size
        visible_rows = rows[:page_size]
        items = tuple(_batch_from_row(connection, row) for row in visible_rows)
        next_cursor = (
            _encode_cursor(
                store_id=identity.store_id,
                operation="inbox.list",
                upper=upper,
                after=int(visible_rows[-1][0]),
            )
            if has_more
            else None
        )
        return Page(items=items, next_cursor=next_cursor, has_more=has_more)


def read_batch(paths: RuntimePaths, batch_id: str) -> BatchDetail:
    """Return one sealed batch and all capture summaries."""
    _validate_opaque_id(batch_id)
    with _read_connection(paths) as (connection, _identity):
        row = connection.execute(
            _BATCH_SELECT + " WHERE batch.batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("batch identifier was not found")
        batch = _batch_from_row(connection, row)
        source_rows = connection.execute(
            _source_select(connection)
            + " JOIN inbox_batch_sources AS membership"
            + " ON membership.source_id = s.source_id"
            + " WHERE membership.batch_id = ?"
            + " ORDER BY membership.ordinal",
            (batch_id,),
        ).fetchall()
        sources = tuple(_summary_from_row(source_row) for source_row in source_rows)
        if len(sources) != batch.source_count:
            raise InvalidArgumentError("sealed batch membership is inconsistent")
        return BatchDetail(batch=batch, sources=sources)


def get_store_status(paths: RuntimePaths) -> StoreStatus:
    """Return only aggregate Store identity, coverage, and contract metadata."""
    from memory.maintenance import reindex_required
    from memory.mcp_schemas import contract_digest, skill_digest

    with _read_connection(paths) as (connection, identity):
        # One status is one WAL snapshot: source and memory counts, review
        # backlog, and projection readiness must all describe the same Store.
        # The read transaction does not block a concurrent writer from committing.
        connection.execute("BEGIN")
        source_count = int(
            connection.execute("SELECT count(*) FROM sources").fetchone()[0]
        )
        membership = _source_status_membership_sql(connection)
        searchable_count = int(
            connection.execute(
                "SELECT count(*) FROM sources AS s "
                "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
                f"WHERE {membership}"
            ).fetchone()[0]
        )
        memory_count = int(
            connection.execute("SELECT count(*) FROM current_memory_heads").fetchone()[
                0
            ]
        )
        # A draft change set is a review the owner has not decided yet, and it
        # is the one backlog nothing else on this wire reports: an agent that
        # creates one and loses its client session leaves work no later call
        # would surface.
        pending_review_count = int(
            connection.execute(
                "SELECT count(*) FROM change_sets WHERE state = 'draft'"
            ).fetchone()[0]
        )
        return StoreStatus(
            product=identity.product,
            schema_version=identity.schema_version,
            store_id=identity.store_id,
            source_count=source_count,
            memory_count=memory_count,
            searchable_count=searchable_count,
            unsearchable_count=source_count - searchable_count,
            pending_review_count=pending_review_count,
            reindex_required=reindex_required(connection),
            mcp_contract_digest=contract_digest(),
            skill_digest=skill_digest(),
        )


@contextmanager
def _read_connection(
    paths: RuntimePaths,
) -> Iterator[tuple[Connection, StoreIdentity]]:
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        yield connection, identity
    finally:
        connection.close()


def _source_page(
    rows: list[Row],
    *,
    identity: StoreIdentity,
    operation: str,
    upper: int,
    page_size: int,
    binding: str | None = None,
    snapshot: str | None = None,
    generation: int | None = None,
) -> Page[SourceSummary]:
    has_more = len(rows) > page_size
    visible_rows = rows[:page_size]
    items = tuple(_summary_from_row(row) for row in visible_rows)
    next_cursor = (
        _encode_cursor(
            store_id=identity.store_id,
            operation=operation,
            upper=upper,
            after=int(visible_rows[-1][0]),
            binding=binding,
            snapshot=snapshot,
            generation=generation,
        )
        if has_more
        else None
    )
    return Page(items=items, next_cursor=next_cursor, has_more=has_more)


def _summary_from_row(row: Row) -> SourceSummary:
    return SourceSummary(
        source_id=str(row[1]),
        origin=SourceCaptureOrigin(str(row[2])),
        blob_digest=str(row[3]),
        original_name=str(row[4]),
        media_type=str(row[5]),
        byte_length=int(row[6]),
        authorship=Authorship(str(row[7])),
        declared_sensitivity=Sensitivity(str(row[8])),
        effective_sensitivity=sensitivity_from_rank(int(row[9])),
        searchable=bool(row[10]),
        captured_at=int(row[11]),
    )


def _batch_from_row(connection: Connection, row: Row) -> InboxBatch:
    batch_id = str(row[1])
    source_ids = tuple(
        str(source_row[0])
        for source_row in connection.execute(
            "SELECT source_id FROM inbox_batch_sources "
            "WHERE batch_id = ? ORDER BY ordinal",
            (batch_id,),
        ).fetchall()
    )
    if len(source_ids) != int(row[3]):
        raise InvalidArgumentError("sealed batch membership is inconsistent")
    raw_has_more = row[4]
    if (
        not isinstance(raw_has_more, int)
        or isinstance(raw_has_more, bool)
        or raw_has_more not in (0, 1)
    ):
        raise InvalidArgumentError("sealed batch continuation state is inconsistent")
    issue_rows = connection.execute(
        "SELECT code, count FROM inbox_batch_issues WHERE batch_id = ? ORDER BY code",
        (batch_id,),
    ).fetchall()
    issues: list[Issue] = []
    for issue_row in issue_rows:
        code = issue_row[0]
        count = issue_row[1]
        if (
            not isinstance(code, str)
            or code not in INBOX_ISSUE_CODES
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
        ):
            raise InvalidArgumentError("sealed batch issue metadata is inconsistent")
        issues.append(Issue(code=code, count=count))
    change_set_id = None if row[5] is None else str(row[5])
    review_state: Literal["none", "draft", "applied"] = "none"
    if change_set_id is not None:
        stored_state = str(row[6])
        if stored_state not in ("draft", "applied"):
            raise InvalidArgumentError("sealed batch review state is inconsistent")
        review_state = "draft" if stored_state == "draft" else "applied"
    return InboxBatch(
        batch_id=batch_id,
        sealed_at=int(row[2]),
        source_count=int(row[3]),
        source_ids=source_ids,
        issues=tuple(issues),
        has_more=bool(raw_has_more),
        duplicates=_retained_duplicate_captures(connection, batch_id),
        change_set_id=change_set_id,
        review_state=review_state,
        application_id=None if row[7] is None else str(row[7]),
    )


def _retained_duplicate_captures(
    connection: Connection,
    batch_id: str,
) -> tuple[DuplicateCapture, ...]:
    """Name the earlier capture of every blob this batch did not introduce.

    The scan reports this once, inside the transaction that publishes the
    batch, and then never again: rereading a sealed batch used to lose it. The
    answer is a pure function of insertion order over retained rows, so
    recomputing it here reproduces exactly what the scan reported rather than
    approximating it -- and `sources` is append-only, so the earliest capture
    of a blob cannot change after the fact.
    """
    rows = connection.execute(
        "SELECT capture.source_id, ("
        "SELECT earlier.source_id FROM sources AS earlier "
        "WHERE earlier.blob_id = capture.blob_id AND earlier.rowid < capture.rowid "
        "ORDER BY earlier.rowid LIMIT 1"
        ") FROM sources AS capture "
        "JOIN inbox_batch_sources AS membership "
        "ON membership.source_id = capture.source_id "
        "WHERE membership.batch_id = ? ORDER BY membership.ordinal",
        (batch_id,),
    ).fetchall()
    return tuple(
        DuplicateCapture(source_id=str(row[0]), duplicate_of=str(row[1]))
        for row in rows
        if row[1] is not None
    )


def _validate_page_size(limit: int) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PAGE_SIZE
    ):
        # `limit` is the one declared detail key the envelope had never carried.
        # A refusal that names the ceiling is the difference between one
        # corrected retry and a binary search for the bound.
        raise InvalidArgumentError(
            f"page limit must be between 1 and {MAX_PAGE_SIZE}",
            details={"limit": MAX_PAGE_SIZE},
        )
    return limit


def _validate_opaque_id(value: str) -> None:
    strict_utf8_bytes(value, label="opaque identifier")
    if not value or len(value) > 256:
        raise InvalidArgumentError("opaque identifier is invalid")


def _page_bounds(
    connection: Connection,
    identity: StoreIdentity,
    *,
    operation: str,
    cursor: Cursor | None,
    upper_table: str,
    binding: str | None = None,
) -> tuple[int, int]:
    if cursor is None:
        upper = int(
            connection.execute(
                f"SELECT COALESCE(MAX(rowid), 0) FROM {upper_table}"
            ).fetchone()[0]
        )
        return 0, upper
    payload = _decode_cursor(cursor)
    if (
        payload.get("store") != identity.store_id
        or payload.get("operation") != operation
        or payload.get("binding") != binding
    ):
        raise StaleCursorError("cursor belongs to another Store operation")
    return _cursor_rowid_bounds(payload)


def _cursor_rowid_bounds(payload: dict[str, object]) -> tuple[int, int]:
    """Validate model-controlled cursor coordinates for SQLite rowid binding."""
    after = payload.get("after")
    upper = payload.get("upper")
    if (
        isinstance(after, bool)
        or not isinstance(after, int)
        or isinstance(upper, bool)
        or not isinstance(upper, int)
        or after < 0
        or upper < after
        or upper > MAX_SQLITE_ROWID
    ):
        raise StaleCursorError("cursor coordinates are invalid")
    return after, upper


def _canonical_json(payload: dict[str, object]) -> bytes:
    """Serialize one payload so equal content always encodes to equal bytes."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _encode_cursor(
    *,
    store_id: str,
    operation: str,
    upper: int,
    after: int,
    binding: str | None = None,
    rank: float | None = None,
    snapshot: str | None = None,
    generation: int | None = None,
    strength: int | None = None,
    character: int | None = None,
) -> Cursor:
    payload: dict[str, object] = {
        "after": after,
        "operation": operation,
        "store": store_id,
        "upper": upper,
        "version": _CURSOR_VERSION,
    }
    if binding is not None:
        payload["binding"] = binding
    if rank is not None:
        payload["rank"] = rank
    if snapshot is not None:
        payload["snapshot"] = snapshot
    if generation is not None:
        payload["generation"] = generation
    if strength is not None:
        payload["strength"] = strength
    if character is not None:
        payload["character"] = character
    try:
        encoded = _canonical_json(payload)
    except (TypeError, ValueError, UnicodeError) as error:
        raise InvalidArgumentError("cursor payload is invalid") from error
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _require_cursor_scope(
    payload: Mapping[str, object],
    *,
    store_id: str,
    operation: str,
    binding: str,
    label: str,
) -> None:
    """Refuse a cursor minted for another Store, operation, or query.

    The binding is a digest of everything the page order depends on -- the
    query, the filters, and the ladder version -- so a cursor cannot be
    replayed against an ordering it was not built for. What each traversal
    then does about `snapshot` differs and stays at its own call site: one
    requires the same snapshot, one requires none, and the paged searches
    compare it against a freshly computed digest instead.
    """
    if (
        payload.get("store") != store_id
        or payload.get("operation") != operation
        or payload.get("binding") != binding
    ):
        raise StaleCursorError(f"cursor belongs to another {label}")


def _decode_cursor(
    cursor: Cursor,
    *,
    allow_character: bool = False,
) -> dict[str, object]:
    if (
        not isinstance(cursor, str)
        or not cursor
        or len(cursor) > 4096
        or "\x00" in cursor
    ):
        raise StaleCursorError("cursor is invalid")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(
            cursor + padding,
            altchars=b"-_",
            validate=True,
        )
        raw: Any = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as error:
        raise StaleCursorError("cursor is invalid") from error
    required = {"after", "operation", "store", "upper", "version"}
    optional = {"binding", "generation", "rank", "snapshot", "strength"}
    if allow_character:
        optional.add("character")
    if (
        not isinstance(raw, dict)
        or raw.get("version") != _CURSOR_VERSION
        or not required <= set(raw)
        or not set(raw) <= required | optional
    ):
        raise StaleCursorError("cursor is invalid")
    return raw


OWNER_SOURCE_MEDIA_PARAMETERS = tuple(sorted(SEARCHABLE_MEDIA_TYPES))
OWNER_SOURCE_MEDIA_PLACEHOLDERS = ", ".join("?" for _ in OWNER_SOURCE_MEDIA_PARAMETERS)


def _owner_source_select(
    connection: Connection,
    *,
    include_authoritative_text: bool,
) -> str:
    """Build one owner source select for the live projection shape."""
    indexed = _source_projection_membership_sql(
        connection,
        match_authoritative_text=True,
    )
    authoritative_text = (
        ",\n        b.utf8_text AS authoritative_utf8_text"
        if include_authoritative_text
        else ""
    )
    return f"""
    SELECT
        s.rowid AS sort_id,
        s.source_id,
        s.blob_id,
        s.batch_id,
        membership.ordinal AS batch_ordinal,
        s.origin,
        b.sha256,
        s.original_name,
        s.media_type,
        b.byte_length,
        s.authorship,
        s.sensitivity,
        (
            SELECT MAX(
                CASE effective.sensitivity
                    WHEN 'normal' THEN 0
                    WHEN 'sensitive' THEN 1
                    WHEN 'restricted' THEN 2
                END
            )
            FROM sources AS effective
            WHERE effective.blob_id = s.blob_id
        ) AS effective_sensitivity_rank,
        CASE
            WHEN s.media_type IN ({OWNER_SOURCE_MEDIA_PLACEHOLDERS})
                 AND b.utf8_text IS NOT NULL
            THEN 1 ELSE 0
        END AS expected_searchable,
        {indexed} AS indexed_for_search,
        s.captured_at,
        typeof(b.utf8_text) != 'null' AS retained_utf8_text{authoritative_text}
    FROM sources AS s
    JOIN source_blobs AS b ON b.blob_id = s.blob_id
    JOIN inbox_batch_sources AS membership ON membership.source_id = s.source_id
    """


def owner_source_select(connection: Connection) -> str:
    """Build the bounded owner source summary select."""
    return _owner_source_select(connection, include_authoritative_text=False)


def owner_source_search_select(connection: Connection) -> str:
    """Build the text-bearing select used only by streamed owner search."""
    return _owner_source_select(connection, include_authoritative_text=True)


OWNER_BATCH_SELECT = """
SELECT
    batch.rowid,
    batch.batch_id,
    batch.sealed_at,
    batch.source_count,
    batch.has_more,
    (SELECT count(*) FROM inbox_batch_issues AS issue
     WHERE issue.batch_id = batch.batch_id),
    (SELECT COALESCE(sum(issue.count), 0) FROM inbox_batch_issues AS issue
     WHERE issue.batch_id = batch.batch_id),
    change_set.change_set_id,
    application.application_id
FROM inbox_batches AS batch
LEFT JOIN change_sets AS change_set ON change_set.batch_id = batch.batch_id
LEFT JOIN applications AS application
    ON application.change_set_id = change_set.change_set_id
"""


def owner_canonical_hash(payload: dict[str, object]) -> str:
    """Hash a JSON-safe owner-view binding canonically."""
    try:
        encoded = _canonical_json(payload)
    except (TypeError, ValueError, UnicodeError) as error:
        raise InvalidArgumentError("owner view binding is invalid") from error
    return hashlib.sha256(encoded).hexdigest()


def owner_current_generation(connection: Connection) -> int:
    row = connection.execute(
        "SELECT audit_generation FROM store_meta WHERE singleton = 1"
    ).fetchone()
    if (
        row is None
        or not isinstance(row[0], int)
        or isinstance(row[0], bool)
        or row[0] < 0
    ):
        raise InvalidArgumentError("Store audit generation is invalid")
    return int(row[0])


def owner_generation_token(connection: Connection) -> str:
    return owner_canonical_hash(
        {
            "format": "memory.owner-generation.v1",
            "generation": owner_current_generation(connection),
        }
    )


def owner_filter_binding(payload: object) -> str:
    return owner_canonical_hash(
        {"format": "memory.owner-cursor-binding.v1", "value": payload}
    )


def owner_cursor_bounds(
    connection: Connection,
    identity: StoreIdentity,
    *,
    operation: str,
    cursor: Cursor | None,
    upper_table: str,
    binding: str | None = None,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> tuple[int, int]:
    if cursor is None:
        upper = (
            int(
                connection.execute(
                    f"SELECT COALESCE(MAX(rowid), 0) FROM {upper_table}"
                ).fetchone()[0]
            )
            if upper_override is None
            else upper_override
        )
        return 0, upper
    payload = _decode_cursor(cursor)
    if (
        payload.get("store") != identity.store_id
        or payload.get("operation") != operation
        or payload.get("binding") != binding
        or payload.get("snapshot") != snapshot_token
    ):
        raise StaleCursorError("cursor belongs to another owner traversal")
    after, upper = _cursor_rowid_bounds(payload)
    if upper_override is not None and upper != upper_override:
        raise StaleCursorError("owner traversal high-water mark changed")
    return after, upper


def owner_page_from_rows[T](
    rows: Sequence[Row],
    *,
    page_size: int,
    identity: StoreIdentity,
    operation: str,
    upper: int,
    binding: str | None,
    snapshot_token: str | None,
    convert: Callable[[Row], T],
    cursor_coordinate: Callable[[Row], int] = lambda row: int(row[0]),
) -> OwnerPage[T]:
    has_more = len(rows) > page_size
    visible = rows[:page_size]
    items = tuple(convert(row) for row in visible)
    next_cursor = (
        _encode_cursor(
            store_id=identity.store_id,
            operation=operation,
            upper=upper,
            after=cursor_coordinate(visible[-1]),
            binding=binding,
            snapshot=snapshot_token,
        )
        if has_more
        else None
    )
    return OwnerPage(items=items, next_cursor=next_cursor, has_more=has_more)


def owner_source_parameters(*extra: object) -> tuple[object, ...]:
    return (*OWNER_SOURCE_MEDIA_PARAMETERS, *extra)


def owner_source_summary_from_row(row: Row) -> OwnerSourceSummary:
    try:
        origin = SourceCaptureOrigin(str(row[5]))
        authorship = Authorship(str(row[10]))
        declared = Sensitivity(str(row[11]))
        effective = (
            Sensitivity.NORMAL,
            Sensitivity.SENSITIVE,
            Sensitivity.RESTRICTED,
        )[int(row[12])]
    except (IndexError, TypeError, ValueError) as error:
        raise InvalidArgumentError("stored source metadata is invalid") from error
    return OwnerSourceSummary(
        source_id=str(row[1]),
        blob_id=str(row[2]),
        batch_id=str(row[3]),
        batch_ordinal=int(row[4]),
        origin=origin,
        blob_digest=str(row[6]),
        original_name=str(row[7]),
        media_type=str(row[8]),
        byte_length=int(row[9]),
        authorship=authorship,
        declared_sensitivity=declared,
        effective_sensitivity=effective,
        expected_searchable=bool(row[13]),
        indexed_for_search=bool(row[14]),
        captured_at=int(row[15]),
    )


def owner_source_projection_coverage(
    connection: Connection,
) -> SourceProjectionCoverage:
    total = int(connection.execute("SELECT count(*) FROM sources").fetchone()[0])
    expected = int(
        connection.execute(
            f"SELECT count(*) FROM sources AS s "
            "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            f"WHERE s.media_type IN ({OWNER_SOURCE_MEDIA_PLACEHOLDERS}) "
            "AND b.utf8_text IS NOT NULL",
            OWNER_SOURCE_MEDIA_PARAMETERS,
        ).fetchone()[0]
    )
    indexed_membership = _source_projection_membership_sql(
        connection,
        match_authoritative_text=True,
    )
    indexed = int(
        connection.execute(
            f"SELECT count(*) FROM sources AS s "
            "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            f"WHERE s.media_type IN ({OWNER_SOURCE_MEDIA_PLACEHOLDERS}) "
            f"AND b.utf8_text IS NOT NULL AND {indexed_membership}",
            OWNER_SOURCE_MEDIA_PARAMETERS,
        ).fetchone()[0]
    )
    projection_rows = int(
        connection.execute("SELECT count(*) FROM source_fts").fetchone()[0]
    )
    return SourceProjectionCoverage(
        total_captures=total,
        expected_searchable_captures=expected,
        indexed_expected_captures=indexed,
        missing_expected_rows=expected - indexed,
        inherently_unsearchable_captures=total - expected,
        unexpected_or_duplicate_rows=max(0, projection_rows - indexed),
    )


def owner_list_sources(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerSourceSummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.source.list",
        cursor=cursor,
        upper_table="sources",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        owner_source_select(connection)
        + " WHERE s.rowid > ? AND s.rowid <= ? ORDER BY s.rowid LIMIT ?",
        owner_source_parameters(after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.source.list",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_source_summary_from_row,
    )


def owner_source_detail(connection: Connection, source_id: str) -> OwnerSourceDetail:
    _validate_opaque_id(source_id)
    row = connection.execute(
        owner_source_select(connection) + " WHERE s.source_id = ?",
        owner_source_parameters(source_id),
    ).fetchone()
    if row is None:
        raise NotFoundError("source identifier was not found")
    summary = owner_source_summary_from_row(row)
    blob_capture_count = int(
        connection.execute(
            "SELECT count(*) FROM sources WHERE blob_id = ?",
            (summary.blob_id,),
        ).fetchone()[0]
    )
    evidence_count = int(
        connection.execute(
            "SELECT count(*) FROM memory_evidence WHERE source_id = ?",
            (source_id,),
        ).fetchone()[0]
    )
    return OwnerSourceDetail(
        summary=summary,
        retained_utf8_text=bool(row[16]),
        blob_capture_count=blob_capture_count,
        evidence_backlink_count=evidence_count,
    )


def owner_list_blob_captures(
    connection: Connection,
    identity: StoreIdentity,
    blob_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerSourceSummary]:
    _validate_opaque_id(blob_id)
    if (
        connection.execute(
            "SELECT 1 FROM source_blobs WHERE blob_id = ?", (blob_id,)
        ).fetchone()
        is None
    ):
        raise NotFoundError("source blob identifier was not found")
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"blob_id": blob_id})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.source.blob-captures",
        cursor=cursor,
        upper_table="sources",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        owner_source_select(connection)
        + " WHERE s.blob_id = ? AND s.rowid > ? AND s.rowid <= ? "
        "ORDER BY s.rowid LIMIT ?",
        owner_source_parameters(blob_id, after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.source.blob-captures",
        upper=upper,
        binding=binding,
        snapshot_token=snapshot_token,
        convert=owner_source_summary_from_row,
    )


def owner_list_source_evidence_links(
    connection: Connection,
    identity: StoreIdentity,
    source_id: str,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerEvidenceLink]:
    from memory.reviews import _locator_from_row

    _validate_opaque_id(source_id)
    if (
        connection.execute(
            "SELECT 1 FROM sources WHERE source_id = ?", (source_id,)
        ).fetchone()
        is None
    ):
        raise NotFoundError("source identifier was not found")
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"source_id": source_id})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.source.evidence-links",
        cursor=cursor,
        upper_table="memory_evidence",
        binding=binding,
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        "SELECT evidence.rowid, evidence.memory_revision_id, revision.lineage_id, "
        "CASE WHEN heads.revision_id = revision.revision_id THEN 1 ELSE 0 END, "
        "evidence.ordinal, evidence.source_id, evidence.blob_digest, evidence.mode, "
        "evidence.char_start, evidence.char_end, evidence.excerpt, "
        "evidence.source_level "
        "FROM memory_evidence AS evidence "
        "JOIN memory_revisions AS revision "
        "ON revision.revision_id = evidence.memory_revision_id "
        "JOIN current_memory_heads AS heads ON heads.lineage_id = revision.lineage_id "
        "WHERE evidence.source_id = ? AND evidence.rowid > ? "
        "AND evidence.rowid <= ? ORDER BY evidence.rowid LIMIT ?",
        (source_id, after, upper, page_size + 1),
    ).fetchall()

    def convert(row: Row) -> OwnerEvidenceLink:
        return OwnerEvidenceLink(
            memory_revision_id=str(row[1]),
            lineage_id=str(row[2]),
            is_current=bool(row[3]),
            locator=_locator_from_row(row[4:]),
        )

    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.source.evidence-links",
        upper=upper,
        binding=binding,
        snapshot_token=snapshot_token,
        convert=convert,
    )


def owner_batch_summary_from_row(row: Row) -> OwnerBatchSummary:
    raw_has_more = row[4]
    if raw_has_more not in (0, 1):
        raise InvalidArgumentError("stored batch continuation is invalid")
    return OwnerBatchSummary(
        batch_id=str(row[1]),
        sealed_at=int(row[2]),
        source_count=int(row[3]),
        has_more=bool(raw_has_more),
        issue_row_count=int(row[5]),
        issue_occurrence_count=int(row[6]),
        change_set_id=None if row[7] is None else str(row[7]),
        application_id=None if row[8] is None else str(row[8]),
    )


def owner_list_batches(
    connection: Connection,
    identity: StoreIdentity,
    cursor: Cursor | None,
    limit: int,
    *,
    snapshot_token: str | None = None,
    upper_override: int | None = None,
) -> OwnerPage[OwnerBatchSummary]:
    page_size = _validate_page_size(limit)
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.batch.list",
        cursor=cursor,
        upper_table="inbox_batches",
        snapshot_token=snapshot_token,
        upper_override=upper_override,
    )
    rows = connection.execute(
        OWNER_BATCH_SELECT + " WHERE batch.rowid > ? AND batch.rowid <= ? "
        "ORDER BY batch.rowid LIMIT ?",
        (after, upper, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.batch.list",
        upper=upper,
        binding=None,
        snapshot_token=snapshot_token,
        convert=owner_batch_summary_from_row,
    )


def owner_list_batches_by_origin(
    connection: Connection,
    identity: StoreIdentity,
    origin: SourceCaptureOrigin,
    cursor: Cursor | None,
    limit: int,
) -> OwnerPage[OwnerBatchSummary]:
    """List only batches whose complete roster has one selected origin."""
    if not isinstance(origin, SourceCaptureOrigin):
        raise InvalidArgumentError("batch origin is invalid")
    page_size = _validate_page_size(limit)
    binding = owner_filter_binding({"origin": origin.value})
    after, upper = owner_cursor_bounds(
        connection,
        identity,
        operation="owner.batch.list-by-origin",
        cursor=cursor,
        upper_table="inbox_batches",
        binding=binding,
    )
    rows = connection.execute(
        OWNER_BATCH_SELECT + " WHERE batch.rowid > ? AND batch.rowid <= ? "
        "AND EXISTS (SELECT 1 FROM sources AS selected "
        "WHERE selected.batch_id = batch.batch_id AND selected.origin = ?) "
        "AND NOT EXISTS (SELECT 1 FROM sources AS other "
        "WHERE other.batch_id = batch.batch_id AND other.origin != ?) "
        "ORDER BY batch.rowid LIMIT ?",
        (after, upper, origin.value, origin.value, page_size + 1),
    ).fetchall()
    return owner_page_from_rows(
        rows,
        page_size=page_size,
        identity=identity,
        operation="owner.batch.list-by-origin",
        upper=upper,
        binding=binding,
        snapshot_token=None,
        convert=owner_batch_summary_from_row,
    )


def owner_batch_detail(connection: Connection, batch_id: str) -> OwnerBatchDetail:
    _validate_opaque_id(batch_id)
    row = connection.execute(
        OWNER_BATCH_SELECT + " WHERE batch.batch_id = ?",
        (batch_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("batch identifier was not found")
    summary = owner_batch_summary_from_row(row)
    source_rows = connection.execute(
        owner_source_select(connection)
        + " WHERE s.batch_id = ? ORDER BY membership.ordinal",
        owner_source_parameters(batch_id),
    ).fetchall()
    sources = tuple(owner_source_summary_from_row(source) for source in source_rows)
    if len(sources) != summary.source_count:
        raise InvalidArgumentError("sealed batch source roster is invalid")
    issue_rows = connection.execute(
        "SELECT code, count FROM inbox_batch_issues WHERE batch_id = ? ORDER BY code",
        (batch_id,),
    ).fetchall()
    issues = tuple(
        OwnerBatchIssue(code=str(issue[0]), occurrence_count=int(issue[1]))
        for issue in issue_rows
    )
    if (
        len(issues) != summary.issue_row_count
        or sum(issue.occurrence_count for issue in issues)
        != summary.issue_occurrence_count
    ):
        raise InvalidArgumentError("sealed batch issue counts are invalid")
    return OwnerBatchDetail(summary=summary, sources=sources, issues=issues)
