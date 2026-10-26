"""Bounded FTS and complete retained-source reading."""

from __future__ import annotations

import codecs
import hashlib
import math
import re
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NamedTuple, Protocol, cast

from memory.database import Connection, Row
from memory.errors import (
    InvalidArgumentError,
    NotFoundError,
    StaleCursorError,
)
from memory.model import (
    Coverage,
    Cursor,
    MatchStrength,
    RuntimePaths,
    SourceChunk,
    SourceSearchHit,
    SourceSearchPage,
    StoreIdentity,
)
from memory.sources import (
    DEFAULT_PAGE_SIZE,
    SEARCHABLE_MEDIA_TYPES,
    _canonical_json,
    _canonical_source_projection_predicate,
    _cursor_rowid_bounds,
    _decode_cursor,
    _encode_cursor,
    _read_connection,
    _require_cursor_scope,
    _source_projection_membership_sql,
    _summary_from_row,
    _validate_opaque_id,
    _validate_page_size,
    owner_filter_binding,
    owner_generation_token,
    owner_source_parameters,
    owner_source_projection_coverage,
    owner_source_search_select,
    owner_source_summary_from_row,
    source_projection_uses_capture_rowid,
)
from memory.ui.view_models import (
    OwnerSourceSearchHit,
    OwnerSourceSearchPage,
)
from memory.validation import strict_utf8_bytes

MAX_QUERY_BYTES = 16 * 1024
MAX_EXCERPT_BYTES = 1024
DEFAULT_READ_BYTES = 256 * 1024
# 4 MiB, not 8: a binary chunk rides the wire as base64 in an MCP embedded
# resource, so 4 MiB of source is roughly 5.6 MiB of JSON in one stdio message
# and 8 MiB would be roughly 11.2. This reads the largest practical text source
# in a couple of chunks while one message stays inside what stdio handles
# comfortably, and the 64 MiB capture ceiling still bounds the walk.
MAX_READ_BYTES = 4 * 1024 * 1024
# Text pages use fixed incremental BLOB reads. The returned page may still be
# as large as MAX_READ_BYTES; this window bounds decoder working memory and the
# one compatibility pass for a cursor minted before character coordinates.
_BLOB_READ_WINDOW_BYTES = 64 * 1024
# Bump whenever rung membership, ordering, or cursor payload semantics change.
LADDER_VERSION = 7


class _BoundaryMarker:
    """An automaton token no stored or queried character can equal."""

    __slots__ = ()


_BOUNDARY_MARKER = _BoundaryMarker()
type _BoundaryToken = str | _BoundaryMarker


class _ReadableBlob(Protocol):
    """The read-only subset of sqlcipher3's incremental BLOB object."""

    def __len__(self) -> int: ...

    def read(self, length: int = -1) -> bytes: ...

    def seek(self, offset: int, origin: int = 0) -> int: ...

    def close(self) -> None: ...


class _BlobOpeningConnection(Protocol):
    """The sqlcipher3 extension absent from sqlite3's typing surface."""

    def open_blob(
        self,
        table: str,
        column: str,
        rowid: int,
        read_only: bool = False,
    ) -> _ReadableBlob: ...


_WORDISH = re.compile(r"[^\W_]")
# Fixed admission limits for the native short-query scan. The number and width
# of its C-level passes never grow with an arbitrary public query. Larger
# queries keep the sparse automata below, including their adversarial bounds.
_NATIVE_QUERY_CHARACTERS = 48
_NATIVE_QUERY_TERMS = 8
# Scripts `unicode61` keeps as one unbroken token because they are written with
# no inter-word space: Han (including the compatibility and extension blocks),
# Hiragana, Katakana, and Hangul. Every character of such a run is wordish, so a
# Latin-shaped boundary test can never be satisfied inside one -- which would
# cap an exact CJK phrase below the phrase rung forever. A boundary test that
# involves one of these characters therefore succeeds.
_UNSPACED_SCRIPT = re.compile(
    "["
    "ᄀ-ᇿ"  # Hangul Jamo
    "⺀-⻿"  # CJK radicals supplement
    "぀-ヿ"  # Hiragana and fullwidth Katakana
    "㄰-㆏"  # Hangul compatibility Jamo
    "ㇰ-ㇿ"  # Katakana phonetic extensions
    "㐀-䶿"  # CJK unified ideographs extension A
    "一-鿿"  # CJK unified ideographs
    "ꥠ-꥿"  # Hangul Jamo extended-A
    "가-퟿"  # Hangul syllables and Jamo extended-B
    "豈-﫿"  # CJK compatibility ideographs
    "ｦ-ﾟ"  # Halfwidth Katakana
    "ﾠ-ￜ"  # Halfwidth Hangul
    "\U00020000-\U0003ffff"  # CJK unified ideographs extensions B and later
    "]"
)
# Separates the fields of one haystack. A query can never contain NUL --
# `strict_utf8_bytes` rejects it -- so no phrase, term, or counted occurrence
# can straddle the junction between two fields and claim to be literally
# present in a capture that holds it in neither. A space would: a body ending
# "the lamp is amber" beside a file named "studio-notes.txt" reads as an exact
# occurrence of "amber studio", at the top rung, with a rank asserting literal
# occurrences of something nothing contains.
_HAYSTACK_JOIN = "\x00"
_SNAPSHOT_DIGEST = re.compile(r"[0-9a-f]{64}")
# Prefix lengths an excerpt anchor probes after the whole term, when only the
# stemmed projection matched. Two fixed probes bound the work per term, and
# below three characters a prefix stops being evidence of the match at all.
_MIN_EXCERPT_PREFIX = 3
_EXCERPT_PREFIX_PROBES = (4, _MIN_EXCERPT_PREFIX)
# Shortest spaced-script term the literal substring pass will admit a row on.
_MIN_SUBSTRING_TERM = 3
# Query aggregation stays sparse in fixed-size blocks. The block is small
# enough that packed cooldown lanes remain machine-sized for ordinary terms,
# while an automaton output can name only the blocks it actually matched.
_LITERAL_TERM_BLOCK_SIZE = 64
# Enumeration sits below every ranked rung rather than beside them: a walk with
# no query emits only this rung, and a walk with a query never emits it, so the
# fourth entry orders a set the other three can never share.
_STRENGTH_ORDER: dict[MatchStrength, int] = {
    MatchStrength.PHRASE: 0,
    MatchStrength.ALL_TERMS: 1,
    MatchStrength.ANY_TERM: 2,
    MatchStrength.ENUMERATED: 3,
}
_STRENGTH_FROM_ORDER = {order: strength for strength, order in _STRENGTH_ORDER.items()}

_SEARCH_SELECT = """
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
    1,
    s.captured_at,
    source_fts.utf8_text
FROM source_fts
JOIN sources AS s ON s.source_id = source_fts.source_id
JOIN source_blobs AS b ON b.blob_id = s.blob_id
"""

_CANONICAL_SEARCH_SELECT = """
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
    1,
    s.captured_at,
    b.utf8_text
FROM sources AS s
JOIN source_blobs AS b ON b.blob_id = s.blob_id
"""


# The legacy lean scan the ladder scores before a Store has the rowid marker.
# Canonical search builds its own authoritative-content arm below.
_LADDER_SCAN = """
SELECT s.rowid, s.source_id, source_fts.utf8_text, s.original_name
FROM source_fts
JOIN sources AS s ON s.source_id = source_fts.source_id
WHERE s.rowid <= ?
GROUP BY s.rowid
ORDER BY s.rowid
"""


def _shape_aware_search_sql(
    connection: Connection,
    legacy_sql: str,
    canonical_sql: str,
) -> str:
    """Select canonical search SQL without changing a legacy projection query."""
    return (
        canonical_sql
        if source_projection_uses_capture_rowid(connection)
        else legacy_sql
    )


def _search_select_sql(connection: Connection, placeholders: str) -> str:
    """Build the visible-page fetch for the live source projection shape."""
    legacy = _SEARCH_SELECT + f" WHERE s.rowid IN ({placeholders}) GROUP BY s.rowid"
    canonical = _CANONICAL_SEARCH_SELECT + f" WHERE s.rowid IN ({placeholders})"
    return _shape_aware_search_sql(connection, legacy, canonical)


def _ladder_scan_sql(connection: Connection) -> str:
    """Build the literal ladder scan for the live source projection shape."""
    membership = _canonical_source_projection_predicate("source_fts")
    canonical = f"""
SELECT s.rowid, s.source_id, b.utf8_text, s.original_name
FROM source_fts
JOIN sources AS s ON s.rowid = source_fts.rowid
JOIN source_blobs AS b ON b.blob_id = s.blob_id
WHERE s.rowid <= ? AND {membership}
ORDER BY s.rowid
"""
    return _shape_aware_search_sql(connection, _LADDER_SCAN, canonical)


def _fts_strength_sql(connection: Connection) -> str:
    """Build one stemmed-rung query for the live source projection shape."""
    legacy = (
        "SELECT s.rowid FROM source_fts "
        "JOIN sources AS s ON s.source_id = source_fts.source_id "
        "WHERE source_fts MATCH ? AND s.rowid <= ? "
        "GROUP BY s.rowid"
    )
    membership = _canonical_source_projection_predicate("source_fts")
    canonical = (
        "SELECT s.rowid FROM source_fts "
        "JOIN sources AS s ON s.rowid = source_fts.rowid "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE source_fts MATCH ? AND s.rowid <= ? AND " + membership + " "
        "GROUP BY s.rowid"
    )
    return _shape_aware_search_sql(connection, legacy, canonical)


def _source_search_coverage_membership_sql(connection: Connection) -> str:
    """Keep legacy coverage SQL intact and share canonical rowid membership."""
    if not source_projection_uses_capture_rowid(connection):
        return (
            "EXISTS (SELECT 1 FROM source_fts WHERE source_fts.source_id = s.source_id)"
        )
    return _source_projection_membership_sql(connection)


class _SourceMatchEntry(NamedTuple):
    """One searchable capture admitted by the ladder, at its resolved rung."""

    strength: int
    rank: float
    rowid: int
    source_id: str


def search_sources(
    paths: RuntimePaths,
    query: str,
    cursor: Cursor | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
) -> SourceSearchPage:
    """Search every searchable capture and report the binary coverage gap."""
    normalized_query = _validate_query(query)
    page_size = _validate_page_size(limit)
    binding = hashlib.sha256(
        _canonical_json({"ladder": LADDER_VERSION, "query": normalized_query})
    ).hexdigest()
    with _read_connection(paths) as (connection, identity):
        connection.execute("BEGIN")
        if cursor is None:
            resume: tuple[int, float, int] | None = None
            snapshot: str | None = None
            upper = int(
                connection.execute(
                    "SELECT COALESCE(MAX(rowid), 0) FROM sources"
                ).fetchone()[0]
            )
        else:
            payload = _decode_cursor(cursor)
            _require_cursor_scope(
                payload,
                store_id=identity.store_id,
                operation="source.search",
                binding=binding,
                label="source search",
            )
            after, upper = _cursor_rowid_bounds(payload)
            resume = (_cursor_strength(payload), _cursor_rank(payload), after)
            snapshot = _cursor_snapshot(payload)

        literal_query = _compile_literal_query(normalized_query)
        matching = _source_ladder_matches(
            connection,
            normalized_query,
            upper,
            literal_query=literal_query,
        )
        digest = _source_snapshot_digest(matching, upper)
        if snapshot is not None and digest != snapshot:
            raise StaleCursorError("source search snapshot changed")
        start_index = (
            0
            if resume is None
            else next(
                (
                    index
                    for index, entry in enumerate(matching)
                    if (entry.strength, entry.rank, entry.rowid) > resume
                ),
                len(matching),
            )
        )
        window = matching[start_index : start_index + page_size + 1]
        has_more = len(window) > page_size
        visible = window[:page_size]
        items = _visible_source_hits(
            connection,
            visible,
            literal_query,
        )
        next_cursor = (
            _encode_cursor(
                store_id=identity.store_id,
                operation="source.search",
                upper=upper,
                after=visible[-1].rowid,
                binding=binding,
                rank=visible[-1].rank,
                snapshot=digest,
                strength=visible[-1].strength,
            )
            if has_more
            else None
        )
        total = int(
            connection.execute(
                "SELECT count(*) FROM sources WHERE rowid <= ?",
                (upper,),
            ).fetchone()[0]
        )
        membership = _source_search_coverage_membership_sql(connection)
        searchable = int(
            connection.execute(
                "SELECT count(*) FROM sources AS s "
                "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
                f"WHERE s.rowid <= ? AND {membership}",
                (upper,),
            ).fetchone()[0]
        )
        coverage = Coverage(
            searchable=searchable,
            unsearchable=total - searchable,
            enumerated=searchable,
            total=total,
        )
        return SourceSearchPage(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            coverage=coverage,
        )


def _search_hit(
    entry: _SourceMatchEntry, row: Row, excerpt: Excerpt
) -> SourceSearchHit:
    """Assemble one wire hit from a scored ladder entry and its preview."""
    return SourceSearchHit(
        source=_summary_from_row(row),
        exact_excerpt=excerpt.text,
        rank=entry.rank,
        match_strength=_STRENGTH_FROM_ORDER[entry.strength],
        excerpt_char_start=excerpt.char_start,
        excerpt_char_end=excerpt.char_end,
        match_char_start=excerpt.match_char_start,
        match_char_end=excerpt.match_char_end,
    )


def _source_fts_strengths(
    connection: Connection, query: str, upper: int
) -> dict[int, MatchStrength]:
    """Assign every projected capture in the snapshot its strongest rung."""
    strengths: dict[int, MatchStrength] = {}
    sql = _fts_strength_sql(connection)
    for strength, expression in _rung_expressions(query):
        for row in connection.execute(
            sql,
            (expression, upper),
        ):
            strengths.setdefault(int(row[0]), strength)
    return strengths


def _source_ladder_matches(
    connection: Connection,
    query: str,
    upper: int,
    *,
    literal_query: _CompiledLiteralQuery | None = None,
) -> list[_SourceMatchEntry]:
    """Rank every searchable capture in the snapshot by its ladder rung.

    Two passes, and this is the lean one. Every page of a paginated walk
    re-scans and re-folds the whole corpus -- that is what the per-page
    snapshot digest is for and a cache cannot replace it -- so the scan carries
    only what a rung and a rank need. The summary join and the correlated
    effective-sensitivity subquery move to the visible page, dropping them from
    O(corpus) to O(page). Nothing about the answer moves: the same strings
    reach the same functions in the same order.
    """
    fts_strength = _source_fts_strengths(connection, query, upper)
    compiled = _compile_literal_query(query) if literal_query is None else literal_query
    matching: list[_SourceMatchEntry] = []
    for row in connection.execute(_ladder_scan_sql(connection), (upper,)):
        rowid = int(row[0])
        # The filename joins the haystack because the projection now indexes
        # it, and a literal pass blind to what the stemmed pass can see is the
        # gap that keeps a CJK filename unfindable: `unicode61` holds one Han
        # run as a single token, so only the substring pass reaches inside it.
        # The memory ladder folds statement-plus-tags for the same reason.
        folded = _HAYSTACK_JOIN.join((str(row[2]), str(row[3]))).casefold()
        literal = compiled.evaluate(folded)
        projected = fts_strength.get(rowid)
        if projected is MatchStrength.PHRASE:
            strength: MatchStrength | None = MatchStrength.PHRASE
        else:
            strength = _strongest(projected, literal.strength)
        if strength is None:
            continue
        # Scored here rather than in SQL so each capture is folded exactly once.
        # The owner path ranks through this same function, so rung-for-rung rank
        # parity between the two readers is structural rather than mirrored.
        rank = literal.rank
        matching.append(
            _SourceMatchEntry(_STRENGTH_ORDER[strength], rank, rowid, str(row[1]))
        )
    matching.sort(key=lambda entry: (entry.strength, entry.rank, entry.rowid))
    return matching


def _visible_source_hits(
    connection: Connection,
    visible: Sequence[_SourceMatchEntry],
    literal_query: _CompiledLiteralQuery,
) -> tuple[SourceSearchHit, ...]:
    """Stream selected plaintext rows into bounded hits in ranked order."""
    if not visible:
        return ()
    by_rowid = {entry.rowid: entry for entry in visible}
    hits: dict[int, SourceSearchHit] = {}
    placeholders = ", ".join("?" for _ in visible)
    rows = connection.execute(
        _search_select_sql(connection, placeholders),
        tuple(entry.rowid for entry in visible),
    )
    for row in rows:
        rowid = int(row[0])
        entry = by_rowid[rowid]
        excerpt = _exact_excerpt(str(row[12]), literal_query=literal_query)
        hits[rowid] = _search_hit(entry, row, excerpt)
    return tuple(hits[entry.rowid] for entry in visible)


def _source_snapshot_digest(matching: list[_SourceMatchEntry], upper: int) -> str:
    """Bind a cursor to the exact page composition the ladder just produced."""
    payload = {
        # Ranks are bounded negative integer scores normalized to a single zero, so
        # every serialized value round-trips through JSON exactly.
        "entries": [
            [entry.strength, entry.rank + 0.0, entry.rowid, entry.source_id]
            for entry in matching
        ],
        "ladder": LADDER_VERSION,
        "upper": upper,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def read_source(
    paths: RuntimePaths,
    source_id: str,
    cursor: Cursor | None = None,
    max_bytes: int = DEFAULT_READ_BYTES,
    *,
    _text_result_budget: int | None = None,
    _text_character_cost: Callable[[str], int] | None = None,
) -> SourceChunk:
    """Read one retained capture without splitting UTF-8 code points.

    ``max_bytes`` remains a source-byte bound for every direct caller. The two
    private text arguments let a serialization adapter stop earlier on an
    encoded-result budget without teaching this storage layer any wire format.
    """
    if (_text_result_budget is None) != (_text_character_cost is None):
        raise ValueError("text result budget and character cost must be paired")
    if _text_result_budget is not None and (
        isinstance(_text_result_budget, bool)
        or not isinstance(_text_result_budget, int)
        or _text_result_budget <= 0
    ):
        raise ValueError("text result budget must be a positive integer")
    with _read_connection(paths) as (connection, identity):
        return _read_source_from_connection(
            connection,
            identity,
            source_id,
            cursor=cursor,
            max_bytes=max_bytes,
            text_result_budget=_text_result_budget,
            text_character_cost=_text_character_cost,
        )


def _read_source_from_connection(
    connection: Connection,
    identity: StoreIdentity,
    source_id: str,
    *,
    cursor: Cursor | None,
    max_bytes: int,
    snapshot: str | None = None,
    text_result_budget: int | None = None,
    text_character_cost: Callable[[str], int] | None = None,
) -> SourceChunk:
    """Read authoritative retained bytes inside an existing query transaction."""
    _validate_opaque_id(source_id)
    byte_limit = _validate_read_size(max_bytes)
    # `typeof` is load-bearing: SQLite marks its Column operand
    # OPFLAG_TYPEOFARG and reads only the serial type. `IS NOT NULL` would
    # materialize the complete overflow TEXT merely to compute this boolean.
    row = connection.execute(
        "SELECT b.rowid, b.sha256, b.byte_length, s.media_type, "
        "       typeof(b.utf8_text) != 'null' "
        "FROM sources AS s "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE s.source_id = ?",
        (source_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("source identifier was not found")
    blob_rowid = int(row[0])
    digest = str(row[1])
    byte_length = int(row[2])
    media_type = str(row[3])
    is_text = media_type in SEARCHABLE_MEDIA_TYPES and int(row[4]) == 1
    binding = hashlib.sha256(f"{source_id}\x00{digest}".encode()).hexdigest()
    start, character_start = _read_start(
        cursor,
        store_id=identity.store_id,
        binding=binding,
        byte_length=byte_length,
        snapshot=snapshot,
    )
    opener = cast(_BlobOpeningConnection, connection)
    blob = opener.open_blob("source_blobs", "original_bytes", blob_rowid, True)
    text_blob: _ReadableBlob | None = None
    try:
        if len(blob) != byte_length:
            raise InvalidArgumentError("retained source length does not match metadata")
        if not is_text:
            if character_start is not None:
                raise StaleCursorError("binary read cursor has text coordinates")
            return _binary_chunk(
                source_id=source_id,
                digest=digest,
                media_type=media_type,
                blob=blob,
                byte_length=byte_length,
                start=start,
                max_bytes=byte_limit,
                store_id=identity.store_id,
                binding=binding,
                snapshot=snapshot,
            )
        text_blob = opener.open_blob("source_blobs", "utf8_text", blob_rowid, True)
        if len(text_blob) != byte_length:
            raise InvalidArgumentError(
                "retained UTF-8 text does not match source bytes"
            )
        return _text_chunk(
            source_id=source_id,
            digest=digest,
            media_type=media_type,
            blob=blob,
            text_blob=text_blob,
            byte_length=byte_length,
            start=start,
            character_start=character_start,
            max_bytes=byte_limit,
            store_id=identity.store_id,
            binding=binding,
            snapshot=snapshot,
            text_result_budget=text_result_budget,
            text_character_cost=text_character_cost,
        )
    finally:
        if text_blob is not None:
            text_blob.close()
        blob.close()


def _text_chunk(
    *,
    source_id: str,
    digest: str,
    media_type: str,
    blob: _ReadableBlob,
    text_blob: _ReadableBlob,
    byte_length: int,
    start: int,
    character_start: int | None,
    max_bytes: int,
    store_id: str,
    binding: str,
    snapshot: str | None,
    text_result_budget: int | None,
    text_character_cost: Callable[[str], int] | None,
) -> SourceChunk:
    char_start = (
        _stream_prefix_character_count(blob, text_blob, start)
        if character_start is None
        else character_start
    )
    text, emitted_bytes = _read_text_blob_window(
        blob,
        text_blob,
        start=start,
        byte_length=byte_length,
        max_bytes=max_bytes,
        text_result_budget=text_result_budget,
        text_character_cost=text_character_cost,
    )
    end = start + emitted_bytes
    if end == start and start < byte_length:
        raise InvalidArgumentError("max_bytes cannot contain the next UTF-8 character")
    char_end = char_start + len(text)
    complete = end == byte_length
    next_cursor = (
        None
        if complete
        else _encode_cursor(
            store_id=store_id,
            operation="source.read",
            upper=byte_length,
            after=end,
            binding=binding,
            snapshot=snapshot,
            character=char_end,
        )
    )
    return SourceChunk(
        source_id=source_id,
        blob_digest=digest,
        media_type=media_type,
        text=text,
        binary=None,
        resource_content_index=None,
        char_start=char_start,
        char_end=char_end,
        byte_start=start,
        byte_end=end,
        next_cursor=next_cursor,
        complete=complete,
    )


def _binary_chunk(
    *,
    source_id: str,
    digest: str,
    media_type: str,
    blob: _ReadableBlob,
    byte_length: int,
    start: int,
    max_bytes: int,
    store_id: str,
    binding: str,
    snapshot: str | None,
) -> SourceChunk:
    end = min(byte_length, start + max_bytes)
    blob.seek(start)
    body = blob.read(end - start)
    if len(body) != end - start:
        raise InvalidArgumentError("retained source ended before its metadata length")
    complete = end == byte_length
    next_cursor = (
        None
        if complete
        else _encode_cursor(
            store_id=store_id,
            operation="source.read",
            upper=byte_length,
            after=end,
            binding=binding,
            snapshot=snapshot,
        )
    )
    return SourceChunk(
        source_id=source_id,
        blob_digest=digest,
        media_type=media_type,
        text=None,
        binary=body,
        resource_content_index=0,
        char_start=None,
        char_end=None,
        byte_start=start,
        byte_end=end,
        next_cursor=next_cursor,
        complete=complete,
    )


def _read_start(
    cursor: Cursor | None,
    *,
    store_id: str,
    binding: str,
    byte_length: int,
    snapshot: str | None,
) -> tuple[int, int | None]:
    if cursor is None:
        return 0, None
    payload = _decode_cursor(cursor, allow_character=True)
    _require_cursor_scope(
        payload,
        store_id=store_id,
        operation="source.read",
        binding=binding,
        label="source read",
    )
    if payload.get("snapshot") != snapshot:
        raise StaleCursorError("cursor belongs to another source read")
    start, upper = _cursor_rowid_bounds(payload)
    if upper != byte_length:
        raise StaleCursorError("source length changed during traversal")
    if "character" not in payload:
        return start, None
    character = payload.get("character")
    if (
        isinstance(character, bool)
        or not isinstance(character, int)
        or character < 0
        or character > start
    ):
        raise StaleCursorError("source read character coordinate is invalid")
    return start, character


def _new_utf8_decoder() -> codecs.IncrementalDecoder:
    decoder_type = codecs.getincrementaldecoder("utf-8")
    if decoder_type is None:  # pragma: no cover - UTF-8 is a built-in codec
        raise RuntimeError("UTF-8 incremental decoder is unavailable")
    return decoder_type(errors="strict")


def _read_exact_blob_window(blob: _ReadableBlob, length: int) -> bytes:
    body = blob.read(length)
    if len(body) != length:
        raise InvalidArgumentError("retained source ended before its metadata length")
    return body


def _read_matching_text_window(
    blob: _ReadableBlob,
    text_blob: _ReadableBlob,
    length: int,
) -> bytes:
    """Read equal byte/text windows before decoding the byte authority."""
    body = _read_exact_blob_window(blob, length)
    retained_text = _read_exact_blob_window(text_blob, length)
    if body != retained_text:
        raise InvalidArgumentError("retained UTF-8 text does not match source bytes")
    return body


def _stream_prefix_character_count(
    blob: _ReadableBlob,
    text_blob: _ReadableBlob,
    end: int,
) -> int:
    """Count one legacy cursor prefix with fixed memory and no retained copy."""
    if end == 0:
        return 0
    decoder = _new_utf8_decoder()
    remaining = end
    characters = 0
    blob.seek(0)
    text_blob.seek(0)
    try:
        while remaining:
            length = min(_BLOB_READ_WINDOW_BYTES, remaining)
            body = _read_matching_text_window(blob, text_blob, length)
            characters += len(decoder.decode(body, final=False))
            remaining -= length
        characters += len(decoder.decode(b"", final=True))
    except UnicodeDecodeError as error:
        raise StaleCursorError("read cursor is not at a UTF-8 boundary") from error
    return characters


def _read_text_blob_window(
    blob: _ReadableBlob,
    text_blob: _ReadableBlob,
    *,
    start: int,
    byte_length: int,
    max_bytes: int,
    text_result_budget: int | None,
    text_character_cost: Callable[[str], int] | None,
) -> tuple[str, int]:
    """Decode one bounded BLOB interval and optionally stop on encoded cost."""
    target = min(max_bytes, byte_length - start)
    if target == 0:
        return "", 0
    decoder = _new_utf8_decoder()
    pieces: list[str] = []
    emitted_bytes = 0
    bytes_read = 0
    spent = 0
    blob.seek(start)
    text_blob.seek(start)

    while bytes_read < target:
        length = min(_BLOB_READ_WINDOW_BYTES, target - bytes_read)
        body = _read_matching_text_window(blob, text_blob, length)
        before = bytes_read
        bytes_read += length
        try:
            decoded = decoder.decode(body, final=False)
        except UnicodeDecodeError as error:
            if start > 0 and before == 0 and error.start == 0:
                raise StaleCursorError(
                    "read cursor is not at a UTF-8 boundary"
                ) from error
            raise InvalidArgumentError("retained source is not valid UTF-8") from error

        if text_result_budget is None:
            pieces.append(decoded)
            emitted_bytes += len(decoded.encode("utf-8"))
            continue

        assert text_character_cost is not None
        accepted = 0
        for character in decoded:
            cost = text_character_cost(character)
            if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
                raise ValueError("text character cost must be a positive integer")
            if spent + cost > text_result_budget:
                if accepted:
                    accepted_text = decoded[:accepted]
                    pieces.append(accepted_text)
                    emitted_bytes += len(accepted_text.encode("utf-8"))
                return "".join(pieces), emitted_bytes
            spent += cost
            accepted += 1
        pieces.append(decoded)
        emitted_bytes += len(decoded.encode("utf-8"))

    if start + bytes_read == byte_length:
        try:
            tail = decoder.decode(b"", final=True)
        except UnicodeDecodeError as error:
            raise InvalidArgumentError("retained source is not valid UTF-8") from error
        if tail:
            if text_result_budget is None:
                pieces.append(tail)
                emitted_bytes += len(tail.encode("utf-8"))
            else:
                assert text_character_cost is not None
                for character in tail:
                    cost = text_character_cost(character)
                    if spent + cost > text_result_budget:
                        return "".join(pieces), emitted_bytes
                    spent += cost
                    pieces.append(character)
                    emitted_bytes += len(character.encode("utf-8"))
    return "".join(pieces), emitted_bytes


def _cursor_rank(payload: dict[str, object]) -> float:
    raw_rank = payload.get("rank")
    if isinstance(raw_rank, bool) or not isinstance(raw_rank, (int, float)):
        raise StaleCursorError("source search cursor rank is invalid")
    try:
        rank = float(raw_rank)
    except OverflowError as error:
        raise StaleCursorError("source search cursor rank is invalid") from error
    if not math.isfinite(rank):
        raise StaleCursorError("source search cursor rank is invalid")
    return rank


def _cursor_snapshot(payload: dict[str, object]) -> str:
    """Read the ladder composition digest a paginated search cursor carries."""
    snapshot = payload.get("snapshot")
    if not isinstance(snapshot, str) or _SNAPSHOT_DIGEST.fullmatch(snapshot) is None:
        raise StaleCursorError("search cursor snapshot is invalid")
    return snapshot


def _validate_query(query: str) -> str:
    """Bound one query in bytes and return the single canonical form of it.

    The bound is measured on exactly what the caller sent, so no amount of
    padding buys extra query. What every downstream reader then sees is the
    stripped form: the cursor binding, the folded phrase, and the excerpt anchor
    all derive from this return value, so `"cat"` and `"cat "` are one walk
    rather than two traversals of the same corpus with incompatible cursors.
    """
    encoded = strict_utf8_bytes(query, label="search query")
    stripped = query.strip()
    if not stripped or len(encoded) > MAX_QUERY_BYTES:
        raise InvalidArgumentError("search query is invalid")
    return stripped


def _validate_read_size(max_bytes: int) -> int:
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= MAX_READ_BYTES
    ):
        raise InvalidArgumentError(
            f"max_bytes must be between 1 and {MAX_READ_BYTES}",
            details={"limit": MAX_READ_BYTES},
        )
    return max_bytes


def _fts_expression(query: str) -> str:
    terms = _query_terms(query)
    if not terms:
        terms = [query.strip()]
    return " AND ".join(f'"{term.replace(chr(34), chr(34) * 2)}"*' for term in terms)


def _phrase_expression(query: str) -> str:
    terms = _query_terms(query)
    if not terms:
        terms = [query.strip()]
    joined = " ".join(terms)
    return '"' + joined.replace('"', '""') + '"'


def _any_term_expression(query: str) -> str:
    terms = _query_terms(query)
    if not terms:
        terms = [query.strip()]
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"*' for term in terms)


def _rung_expressions(
    query: str, *, phrase_column: str | None = None
) -> tuple[tuple[MatchStrength, str], ...]:
    """Return every ladder rung with the FTS expression that answers it.

    `phrase_column` confines the phrase rung to one indexed column. FTS5 gives
    every token in a row one position sequence, so two values stored in the
    same column are adjacent tokens and a phrase can form across the boundary
    between them -- a memory tagged `copper` and `lantern` answers the phrase
    "copper lantern" at the top rung although neither tag is that phrase.

    The literal pass still awards the phrase rung for a phrase that really does
    sit inside one field, so the true positive survives the confinement in the
    ordinary case. It does not survive it when the phrase is reachable only by
    stemming: a tag `copper lantern` queried as `copper lanterns` matches
    neither pass and lands at all-terms. That is the accepted cost. It moves a
    label on a real hit; the alternative leaves a fabricated phrase outranking
    real ones, and the Skill acts on `phrase` without verifying it.
    """
    phrase = _phrase_expression(query)
    if phrase_column is not None:
        phrase = f"{{{phrase_column}}} : {phrase}"
    return (
        (MatchStrength.PHRASE, phrase),
        (MatchStrength.ALL_TERMS, _fts_expression(query)),
        (MatchStrength.ANY_TERM, _any_term_expression(query)),
    )


def _folded_query(query: str) -> tuple[str, tuple[str, ...]]:
    """Fold one query once for repeated per-row substring scoring."""
    phrase = query.casefold().strip()
    terms = tuple(term.casefold() for term in _query_terms(query))
    return phrase, terms


@dataclass(frozen=True, slots=True)
class _LiteralEvaluation:
    strength: MatchStrength | None
    rank: float
    phrase_index: int


@dataclass(frozen=True, slots=True)
class _LiteralScanResult:
    """Exact coordinates and counts collected during one haystack traversal."""

    present_term_count: int
    bounded_term_count: int
    term_score: int
    phrase_count: int
    phrase_index: int
    bounded_term_index: int | None
    bounded_term_start: int
    bounded_term_length: int
    prefix_index: int


@dataclass(frozen=True, slots=True)
class _LiteralTermBlock:
    """Fixed-width term state touched only by its outputs or live cooldowns."""

    all_terms_mask: int
    admissible_mask: int
    counter_high_mask: int
    cooldown_resets: int
    multiplicity_planes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _NativeLiteralTerm:
    text: str
    multiplicity: int
    boundary: re.Pattern[str] | None


def _native_boundary_pattern(text: str) -> re.Pattern[str]:
    """Compile exact structural boundaries without a Python occurrence walk.

    There are no repetitions or variable-width assertions in this pattern.
    Its literal is at most 48 characters and each boundary has two fixed
    alternatives. Wordish and unspaced ranges are the automaton's own rules.
    """
    left = right = ""
    if _WORDISH.match(text[0]) and not _UNSPACED_SCRIPT.match(text[0]):
        left = rf"(?:(?<![^\W_])|(?<={_UNSPACED_SCRIPT.pattern}))"
    if _WORDISH.match(text[-1]) and not _UNSPACED_SCRIPT.match(text[-1]):
        right = rf"(?:(?![^\W_])|(?={_UNSPACED_SCRIPT.pattern}))"
    return re.compile(left + re.escape(text) + right)


def _native_match_index(pattern: re.Pattern[str], text: str) -> int:
    found = pattern.search(text)
    return -1 if found is None else found.start()


@dataclass(frozen=True, slots=True)
class _NativeLiteralQuery:
    """At most 42 fixed C scans, with no Python work per source coordinate.

    One phrase count/search, eight term counts/searches, and at most three
    prefix searches per term. Counts retain non-overlap and duplicate weights;
    boundary searches may find overlapping occurrences without enumerating
    them in Python. The sparse automaton remains the arbitrary-query path.
    """

    phrase: str
    boundary: re.Pattern[str]
    terms: tuple[_NativeLiteralTerm, ...]
    prefixes: tuple[re.Pattern[str], ...]

    def scan(self, haystack: str) -> _LiteralScanResult:
        phrase_count = haystack.count(self.phrase)
        phrase_index = (
            _native_match_index(self.boundary, haystack) if phrase_count else -1
        )
        present = bounded = score = 0
        term_index: int | None = None
        term_start = -1
        term_length = 0
        for index, term in enumerate(self.terms):
            count = haystack.count(term.text)
            score += count * term.multiplicity
            if not count or term.boundary is None:
                continue
            present += 1
            position = _native_match_index(term.boundary, haystack)
            if position >= 0:
                bounded += 1
                if term_index is None:
                    term_index = index
                    term_start = position
                    term_length = len(term.text)
        prefix_index = -1
        if phrase_index < 0 and term_index is None:
            for prefix in self.prefixes:
                prefix_index = _native_match_index(prefix, haystack)
                if prefix_index >= 0:
                    break
        return _LiteralScanResult(
            present_term_count=present,
            bounded_term_count=bounded,
            term_score=score,
            phrase_count=phrase_count,
            phrase_index=phrase_index,
            bounded_term_index=term_index,
            bounded_term_start=term_start,
            bounded_term_length=term_length,
            prefix_index=prefix_index,
        )


@dataclass(frozen=True, slots=True)
class _CompiledLiteralQuery:
    """One immutable exact multi-pattern matcher shared by every corpus row."""

    phrase: str
    transitions: tuple[Mapping[str, int], ...]
    failures: tuple[int, ...]
    output_blocks: tuple[tuple[tuple[int, int], ...], ...]
    term_blocks: tuple[_LiteralTermBlock, ...]
    term_count: int
    admissible_term_count: int
    counter_shift: int
    counter_lane_fill: int
    boundary_transitions: tuple[Mapping[_BoundaryToken, int], ...]
    boundary_failures: tuple[int, ...]
    boundary_output_blocks: tuple[tuple[tuple[int, int], ...], ...]
    term_lengths: tuple[int, ...]
    phrase_failures: tuple[int, ...]
    prefix_priorities: tuple[int | None, ...]
    prefix_lengths: tuple[int, ...]
    native: _NativeLiteralQuery | None

    def evaluate(self, haystack_folded: str) -> _LiteralEvaluation:
        """Resolve literal rung and rank without enumerating matched terms."""
        scan = self._scan(haystack_folded)
        # Each admitted term contributes once, regardless of its occurrences or
        # query multiplicity. A bounded exact phrase earns one further unit.
        # The query byte ceiling bounds this integer well below 2**53, preserving
        # exact JSON ranks while repetition cannot outweigh broader coverage.
        score = scan.present_term_count + int(scan.phrase_index >= 0)
        if scan.phrase_index >= 0:
            strength: MatchStrength | None = MatchStrength.PHRASE
        elif not self.term_count or not scan.present_term_count:
            strength = None
        elif (
            scan.bounded_term_count == self.admissible_term_count
            and scan.present_term_count == self.term_count
        ):
            strength = MatchStrength.ALL_TERMS
        else:
            strength = MatchStrength.ANY_TERM
        return _LiteralEvaluation(strength, -float(score), scan.phrase_index)

    def locate(self, haystack_folded: str) -> tuple[int, int]:
        """Return the legacy excerpt anchor from the compiled exact scan."""
        scan = self._scan(haystack_folded)
        if scan.phrase_index >= 0:
            return scan.phrase_index, len(self.phrase)
        if scan.bounded_term_index is not None:
            return scan.bounded_term_start, scan.bounded_term_length
        return scan.prefix_index, 0

    def _scan(self, haystack_folded: str) -> _LiteralScanResult:
        """Use fixed native passes or traverse once with sparse exact state."""
        if self.native is not None:
            return self.native.scan(haystack_folded)
        cooldowns: dict[int, int] = {}
        present_masks: dict[int, int] = {}
        bounded_masks: dict[int, int] = {}
        present_term_count = 0
        bounded_term_count = 0
        term_score = 0
        state = 0
        phrase_state = 0
        phrase_count = 0
        phrase_next_count_start = 0
        phrase_index = -1
        bounded_term_index: int | None = None
        bounded_term_start = -1
        bounded_term_length = 0
        prefix_priority: int | None = None
        prefix_index = -1
        final_index = len(haystack_folded) - 1
        boundary_state = 0

        def record_boundary_output(
            outputs: tuple[tuple[int, int], ...], boundary_index: int
        ) -> None:
            nonlocal bounded_term_count
            nonlocal bounded_term_index
            nonlocal bounded_term_length
            nonlocal bounded_term_start
            for block_index, output in outputs:
                previous = bounded_masks.get(block_index, 0)
                newly_bounded = output & ~previous
                if newly_bounded:
                    bounded_masks[block_index] = previous | output
                    bounded_term_count += newly_bounded.bit_count()
                lowest_bit = output & -output
                local_index = (lowest_bit.bit_length() - 1) // (self.counter_shift + 1)
                term_index = block_index * _LITERAL_TERM_BLOCK_SIZE + local_index
                if bounded_term_index is None or term_index < bounded_term_index:
                    bounded_term_index = term_index
                    bounded_term_length = self.term_lengths[term_index]
                    bounded_term_start = boundary_index - bounded_term_length

        if self.admissible_term_count:
            boundary_state = _advance_automaton(
                boundary_state,
                _BOUNDARY_MARKER,
                self.boundary_transitions,
                self.boundary_failures,
            )
        previous_character: str | None = None
        for index, character in enumerate(haystack_folded):
            # Each live block packs only its own non-overlap cooldown lanes.
            # Blocks without a current output or live cooldown stay dormant.
            blocked_by_block: dict[int, int] = {}
            for block_index, block_cooldowns in tuple(cooldowns.items()):
                block = self.term_blocks[block_index]
                guarded = (
                    block_cooldowns | block.counter_high_mask
                ) - block.all_terms_mask
                blocked = (guarded & block.counter_high_mask) >> self.counter_shift
                next_cooldowns = block_cooldowns - blocked
                blocked_by_block[block_index] = blocked
                if next_cooldowns:
                    cooldowns[block_index] = next_cooldowns
                else:
                    del cooldowns[block_index]

            state = _advance_automaton(
                state,
                character,
                self.transitions,
                self.failures,
            )
            candidate_priority = self.prefix_priorities[state]
            if candidate_priority is not None and (
                prefix_priority is None or candidate_priority < prefix_priority
            ):
                prefix_priority = candidate_priority
                prefix_index = index - self.prefix_lengths[state] + 1
            for block_index, matched in self.output_blocks[state]:
                block = self.term_blocks[block_index]
                previous_present = present_masks.get(block_index, 0)
                admitted = matched & block.admissible_mask
                newly_present = admitted & ~previous_present
                if newly_present:
                    present_masks[block_index] = previous_present | admitted
                    present_term_count += newly_present.bit_count()
                accepted = matched & (
                    block.all_terms_mask ^ blocked_by_block.get(block_index, 0)
                )
                if accepted:
                    for weight_bit, plane in enumerate(block.multiplicity_planes):
                        term_score += (accepted & plane).bit_count() << weight_bit
                    accepted_lanes = accepted * self.counter_lane_fill
                    next_cooldowns = (
                        cooldowns.get(block_index, 0) & ~accepted_lanes
                    ) | (block.cooldown_resets & accepted_lanes)
                    if next_cooldowns:
                        cooldowns[block_index] = next_cooldowns
                    else:
                        cooldowns.pop(block_index, None)

            if self.admissible_term_count:
                if previous_character is not None and _boundary_between(
                    previous_character, character
                ):
                    boundary_state = _advance_automaton(
                        boundary_state,
                        _BOUNDARY_MARKER,
                        self.boundary_transitions,
                        self.boundary_failures,
                    )
                    record_boundary_output(
                        self.boundary_output_blocks[boundary_state], index
                    )
                boundary_state = _advance_automaton(
                    boundary_state,
                    character,
                    self.boundary_transitions,
                    self.boundary_failures,
                )
                previous_character = character

            if self.phrase:
                while phrase_state and character != self.phrase[phrase_state]:
                    phrase_state = self.phrase_failures[phrase_state - 1]
                if character == self.phrase[phrase_state]:
                    phrase_state += 1
                if phrase_state == len(self.phrase):
                    start = index - len(self.phrase) + 1
                    if start >= phrase_next_count_start:
                        phrase_count += 1
                        phrase_next_count_start = index + 1
                    if phrase_index < 0:
                        before = start == 0 or _boundary_between(
                            haystack_folded[start - 1], self.phrase[0]
                        )
                        after = index == final_index or _boundary_between(
                            haystack_folded[index + 1], self.phrase[-1]
                        )
                        if before and after:
                            phrase_index = start
                    phrase_state = self.phrase_failures[phrase_state - 1]

        if self.admissible_term_count:
            boundary_state = _advance_automaton(
                boundary_state,
                _BOUNDARY_MARKER,
                self.boundary_transitions,
                self.boundary_failures,
            )
            record_boundary_output(
                self.boundary_output_blocks[boundary_state], len(haystack_folded)
            )

        return _LiteralScanResult(
            present_term_count=present_term_count,
            bounded_term_count=bounded_term_count,
            term_score=term_score,
            phrase_count=phrase_count,
            phrase_index=phrase_index,
            bounded_term_index=bounded_term_index,
            bounded_term_start=bounded_term_start,
            bounded_term_length=bounded_term_length,
            prefix_index=prefix_index,
        )


def _compile_literal_query(query: str) -> _CompiledLiteralQuery:
    """Compile folded terms once without changing their duplicate weights."""
    phrase, terms = _folded_query(query)
    multiplicities: dict[str, int] = {}
    for term in terms:
        multiplicities[term] = multiplicities.get(term, 0) + 1

    transitions: list[dict[str, int]] = [{}]
    failures = [0]
    output_blocks: list[dict[int, int]] = [{}]
    boundary_transitions: list[dict[_BoundaryToken, int]] = [{}]
    boundary_failures = [0]
    boundary_output_blocks: list[dict[int, int]] = [{}]
    term_lengths: list[int] = []
    maximum_term_length = max((len(term) for term in multiplicities), default=0)
    counter_width = max(1, maximum_term_length.bit_length() + 1)
    counter_lane_fill = (1 << counter_width) - 1
    block_count = (
        len(multiplicities) + _LITERAL_TERM_BLOCK_SIZE - 1
    ) // _LITERAL_TERM_BLOCK_SIZE
    all_terms_masks = [0] * block_count
    admissible_masks = [0] * block_count
    cooldown_resets = [0] * block_count
    multiplicity_planes: list[list[int]] = [[] for _ in range(block_count)]
    admissible_term_count = 0
    for term_index, (term, multiplicity) in enumerate(multiplicities.items()):
        term_lengths.append(len(term))
        block_index = term_index // _LITERAL_TERM_BLOCK_SIZE
        local_index = term_index % _LITERAL_TERM_BLOCK_SIZE
        lane_start = local_index * counter_width
        term_bit = 1 << lane_start
        all_terms_masks[block_index] |= term_bit
        cooldown_resets[block_index] |= (len(term) - 1) << lane_start
        state = 0
        for character in term:
            target = transitions[state].get(character)
            if target is None:
                target = len(transitions)
                transitions[state][character] = target
                transitions.append({})
                failures.append(0)
                output_blocks.append({})
            state = target
        output_blocks[state][block_index] = (
            output_blocks[state].get(block_index, 0) | term_bit
        )
        while len(multiplicity_planes[block_index]) < multiplicity.bit_length():
            multiplicity_planes[block_index].append(0)
        for weight_bit in range(multiplicity.bit_length()):
            if multiplicity & (1 << weight_bit):
                multiplicity_planes[block_index][weight_bit] |= term_bit
        admissible = not (
            len(term) < _MIN_SUBSTRING_TERM and _UNSPACED_SCRIPT.search(term) is None
        )
        if admissible:
            admissible_term_count += 1
            admissible_masks[block_index] |= term_bit
            boundary_tokens: list[_BoundaryToken] = [_BOUNDARY_MARKER]
            previous_term_character: str | None = None
            for character in term:
                if previous_term_character is not None and _boundary_between(
                    previous_term_character, character
                ):
                    boundary_tokens.append(_BOUNDARY_MARKER)
                boundary_tokens.append(character)
                previous_term_character = character
            boundary_tokens.append(_BOUNDARY_MARKER)
            boundary_state = 0
            for token in boundary_tokens:
                boundary_target = boundary_transitions[boundary_state].get(token)
                if boundary_target is None:
                    boundary_target = len(boundary_transitions)
                    boundary_transitions[boundary_state][token] = boundary_target
                    boundary_transitions.append({})
                    boundary_failures.append(0)
                    boundary_output_blocks.append({})
                boundary_state = boundary_target
            boundary_output_blocks[boundary_state][block_index] = (
                boundary_output_blocks[boundary_state].get(block_index, 0) | term_bit
            )

    prefix_candidates: dict[str, int] = {}
    prefix_priority = 0
    for term in sorted(terms, key=len, reverse=True):
        for end in dict.fromkeys(
            length
            for length in (len(term), *_EXCERPT_PREFIX_PROBES)
            if _MIN_EXCERPT_PREFIX <= length <= len(term)
        ):
            prefix_candidates.setdefault(term[:end], prefix_priority)
            prefix_priority += 1
    prefix_priorities: list[int | None] = [None] * len(transitions)
    prefix_lengths = [0] * len(transitions)
    for prefix, priority in prefix_candidates.items():
        state = 0
        for character in prefix:
            state = transitions[state][character]
        current = prefix_priorities[state]
        if current is None or priority < current:
            prefix_priorities[state] = priority
            prefix_lengths[state] = len(prefix)

    pending: deque[int] = deque(transitions[0].values())
    while pending:
        state = pending.popleft()
        for character, target in transitions[state].items():
            pending.append(target)
            fallback = failures[state]
            while fallback and character not in transitions[fallback]:
                fallback = failures[fallback]
            failures[target] = transitions[fallback].get(character, 0)
            # Inherited suffixes stay grouped by fixed block. Evaluation
            # visits one local mask per block that really produced output,
            # never one event per matching term or one query-wide integer.
            for block_index, inherited in output_blocks[failures[target]].items():
                output_blocks[target][block_index] = (
                    output_blocks[target].get(block_index, 0) | inherited
                )
            inherited_priority = prefix_priorities[failures[target]]
            current_priority = prefix_priorities[target]
            if inherited_priority is not None and (
                current_priority is None or inherited_priority < current_priority
            ):
                prefix_priorities[target] = inherited_priority
                prefix_lengths[target] = prefix_lengths[failures[target]]

    boundary_pending: deque[int] = deque(boundary_transitions[0].values())
    while boundary_pending:
        boundary_state = boundary_pending.popleft()
        for token, boundary_target in boundary_transitions[boundary_state].items():
            boundary_pending.append(boundary_target)
            boundary_fallback = boundary_failures[boundary_state]
            while (
                boundary_fallback
                and token not in boundary_transitions[boundary_fallback]
            ):
                boundary_fallback = boundary_failures[boundary_fallback]
            boundary_failures[boundary_target] = boundary_transitions[
                boundary_fallback
            ].get(token, 0)
            for block_index, inherited in boundary_output_blocks[
                boundary_failures[boundary_target]
            ].items():
                boundary_output_blocks[boundary_target][block_index] = (
                    boundary_output_blocks[boundary_target].get(block_index, 0)
                    | inherited
                )

    phrase_failures: list[int] = []
    phrase_fallback = 0
    for index, character in enumerate(phrase):
        if index == 0:
            phrase_failures.append(0)
            continue
        while phrase_fallback and character != phrase[phrase_fallback]:
            phrase_fallback = phrase_failures[phrase_fallback - 1]
        if character == phrase[phrase_fallback]:
            phrase_fallback += 1
        phrase_failures.append(phrase_fallback)

    frozen_transitions = tuple(
        MappingProxyType(dict(state_transitions)) for state_transitions in transitions
    )
    frozen_boundary_transitions = tuple(
        MappingProxyType(dict(state_transitions))
        for state_transitions in boundary_transitions
    )
    frozen_output_blocks = tuple(
        tuple(sorted(state_outputs.items())) for state_outputs in output_blocks
    )
    frozen_boundary_output_blocks = tuple(
        tuple(sorted(state_outputs.items())) for state_outputs in boundary_output_blocks
    )
    term_blocks = tuple(
        _LiteralTermBlock(
            all_terms_mask=all_terms_masks[block_index],
            admissible_mask=admissible_masks[block_index],
            counter_high_mask=all_terms_masks[block_index] << (counter_width - 1),
            cooldown_resets=cooldown_resets[block_index],
            multiplicity_planes=tuple(multiplicity_planes[block_index]),
        )
        for block_index in range(block_count)
    )
    native = None
    if (
        0 < len(phrase) <= _NATIVE_QUERY_CHARACTERS
        and len(multiplicities) <= _NATIVE_QUERY_TERMS
    ):
        native = _NativeLiteralQuery(
            phrase=phrase,
            boundary=_native_boundary_pattern(phrase),
            terms=tuple(
                _NativeLiteralTerm(
                    text=term,
                    multiplicity=weight,
                    boundary=_native_boundary_pattern(term)
                    if len(term) >= _MIN_SUBSTRING_TERM
                    or _UNSPACED_SCRIPT.search(term) is not None
                    else None,
                )
                for term, weight in multiplicities.items()
            ),
            prefixes=tuple(
                re.compile(re.escape(prefix)) for prefix in prefix_candidates
            ),
        )
    return _CompiledLiteralQuery(
        phrase=phrase,
        transitions=frozen_transitions,
        failures=tuple(failures),
        output_blocks=frozen_output_blocks,
        term_blocks=term_blocks,
        term_count=len(multiplicities),
        admissible_term_count=admissible_term_count,
        counter_shift=counter_width - 1,
        counter_lane_fill=counter_lane_fill,
        boundary_transitions=frozen_boundary_transitions,
        boundary_failures=tuple(boundary_failures),
        boundary_output_blocks=frozen_boundary_output_blocks,
        term_lengths=tuple(term_lengths),
        phrase_failures=tuple(phrase_failures),
        prefix_priorities=tuple(prefix_priorities),
        prefix_lengths=tuple(prefix_lengths),
        native=native,
    )


def _advance_automaton[TokenT](
    state: int,
    token: TokenT,
    transitions: tuple[Mapping[TokenT, int], ...],
    failures: tuple[int, ...],
) -> int:
    """Advance one deterministic Aho-Corasick state by one token."""
    while state and token not in transitions[state]:
        state = failures[state]
    return transitions[state].get(token, 0)


def _boundary_between(outer: str, inner: str) -> bool:
    """Report whether two adjacent characters may sit on a token boundary."""
    if _UNSPACED_SCRIPT.match(outer) or _UNSPACED_SCRIPT.match(inner):
        return True
    return not (_WORDISH.match(outer) and _WORDISH.match(inner))


def _bounded_occurrence(haystack_folded: str, phrase: str) -> int:
    """Index the first occurrence sitting at a token boundary, or -1.

    Callers need the position, not just the fact: a haystack can hold a
    mid-word occurrence before a real one -- "art" inside "party" precedes the
    "art" in "A party in the art room" -- and answering "yes, somewhere" while
    the caller reports `find`'s first hit points a match span inside an
    unrelated word.
    """
    if not phrase:
        return -1
    start = 0
    while (index := haystack_folded.find(phrase, start)) >= 0:
        end = index + len(phrase)
        before = index == 0 or _boundary_between(haystack_folded[index - 1], phrase[0])
        after = end == len(haystack_folded) or _boundary_between(
            haystack_folded[end], phrase[-1]
        )
        if before and after:
            return index
        start = index + 1
    return -1


def _at_token_boundary(haystack_folded: str, phrase: str) -> bool:
    return _bounded_occurrence(haystack_folded, phrase) >= 0


def _substring_admits(term: str, haystack_folded: str) -> bool:
    """Report whether one folded term is literal evidence of a match.

    A short spaced-script fragment is not. Two Latin characters occur inside
    unrelated words constantly, so admitting a row on one says nothing about
    the query. An unspaced script is exempt: a two-character Han term is a
    word, and the same threshold applied to it would delete real recall rather
    than noise. The stemmed pass is untouched either way, so a short term that
    genuinely tokenizes still reaches its proper rung through FTS.
    """
    if len(term) < _MIN_SUBSTRING_TERM and _UNSPACED_SCRIPT.search(term) is None:
        return False
    return term in haystack_folded


def _substring_strength(
    haystack_folded: str, phrase: str, terms: tuple[str, ...]
) -> MatchStrength | None:
    """Report the strongest rung one folded haystack satisfies literally.

    No production path calls this: it is the reference rung engine the ladder
    suite verifies the compiled evaluation against.

    A term found only inside a longer word is weak evidence, so it cannot lift
    a hit to all-terms: `art` occurs in "party" and a reader told all-terms
    would take that for a real match. It still reaches any-term, which the
    Skill treats as a lead to verify rather than an established hit -- demoting
    the rung keeps the recall and stops overstating it. The minimum term length
    (`_substring_admits`) removes fragments too short to be evidence at all;
    this handles the ones long enough to look convincing and still not be.
    """
    if (
        phrase
        and phrase in haystack_folded
        and _at_token_boundary(haystack_folded, phrase)
    ):
        return MatchStrength.PHRASE
    if not terms:
        return None
    present = [_substring_admits(term, haystack_folded) for term in terms]
    if not any(present):
        return None
    if all(present) and all(
        _at_token_boundary(haystack_folded, term) for term in terms
    ):
        return MatchStrength.ALL_TERMS
    return MatchStrength.ANY_TERM


def _strongest(
    first: MatchStrength | None, second: MatchStrength | None
) -> MatchStrength | None:
    """Return whichever rung of two candidates sits highest on the ladder."""
    if first is None:
        return second
    if second is None:
        return first
    return first if _STRENGTH_ORDER[first] <= _STRENGTH_ORDER[second] else second


def _cursor_strength(payload: dict[str, object]) -> int:
    raw = payload.get("strength")
    if isinstance(raw, bool) or not isinstance(raw, int) or raw not in (0, 1, 2, 3):
        raise StaleCursorError("search cursor strength is invalid")
    return raw


def _term_prefix_match(folded_text: str, query: str) -> tuple[int, int]:
    """Locate a term or one bounded prefix of it, longest term first.

    The ladder admits stemmed matches, so a hit can carry no literal occurrence
    of the query at all. Probing the whole term and then two short prefixes
    keeps the excerpt near the word that actually matched ("gardens" finds
    "gardening") instead of falling back to the head of the document, which
    shows the reader nothing.
    """
    for term in sorted(
        (term.casefold() for term in _query_terms(query)),
        key=len,
        reverse=True,
    ):
        for end in dict.fromkeys(
            length
            for length in (len(term), *_EXCERPT_PREFIX_PROBES)
            if _MIN_EXCERPT_PREFIX <= length <= len(term)
        ):
            match = folded_text.find(term[:end])
            if match >= 0:
                return match, end
    return -1, 0


def _locate_match(folded_text: str, query: str) -> tuple[int, int]:
    """Return the strongest literal anchor for one query, as (index, length).

    No production path calls this: it is the reference locator the ladder
    suite verifies the compiled locate against.

    A length of zero means the anchor positions the excerpt but is not a
    literal occurrence: the last fallback probes a three- or four-character
    prefix of a term, which is enough to window the preview near whatever the
    stemmed projection matched and is not enough to report as a match span.
    Reporting it would hand an agent an evidence locator covering `stud` for a
    query about "studio" -- an excerpt that validates against the source and
    points at the wrong word.
    """
    # Every arm reports the occurrence it validated, never `find`'s first: a
    # mid-word occurrence can precede a real one, and a span over "art" inside
    # "party" converts into an evidence locator that validates against the
    # source and points at the wrong word.
    folded_query = query.casefold()
    match = _bounded_occurrence(folded_text, folded_query)
    if match >= 0:
        return match, len(folded_query)
    for term in _query_terms(query):
        folded_term = term.casefold()
        # The same discipline the literal pass uses to admit a row: a term too
        # short to be evidence, or found only inside a longer word, is not an
        # occurrence to point at.
        if not _substring_admits(folded_term, folded_text):
            continue
        match = _bounded_occurrence(folded_text, folded_term)
        if match >= 0:
            return match, len(folded_term)
    prefix, _length = _term_prefix_match(folded_text, query)
    return prefix, 0


class Excerpt(NamedTuple):
    """One bounded preview and its span in canonical source coordinates."""

    text: str
    char_start: int
    char_end: int
    match_char_start: int | None
    match_char_end: int | None


def _exact_excerpt(
    text: str,
    *,
    literal_query: _CompiledLiteralQuery,
) -> Excerpt:
    """Window one source around its match and report where the window sits.

    The span is in the source's own character coordinates, the same system
    `source.read` and evidence locators use, so a truncated preview converts
    into an exact locator with one bounded read instead of a re-scan.

    The located index belongs to the folding, not to the source, so it is
    mapped back before it windows anything. Match coordinates are a stricter
    case and are reported only when folding preserved character positions:
    folding never shortens a string and maps each character to one or more, so
    equal folded and unfolded lengths prove every character mapped one to one.
    Where it does not -- `ß` folding to `ss` earlier in the same document --
    a mapped span can still cover a character the match only half spans, and
    an evidence locator pointing at more than it matched is the failure the
    compiled locate already refuses. The window has no such requirement: it is
    a preview, and showing the passage is what it is for.
    """
    folded_text = text.casefold()
    match, match_length = literal_query.locate(folded_text)
    aligned = len(folded_text) == len(text)
    # A zero length is a prefix anchor: good enough to centre the window, not
    # a literal occurrence to point at.
    located = match >= 0 and match_length > 0 and aligned
    match_start = match if located else None
    match_end = None if match_start is None else match_start + match_length
    if len(text.encode("utf-8")) <= MAX_EXCERPT_BYTES:
        return Excerpt(text, 0, len(text), match_start, match_end)
    center = _source_index(text, folded_text, match) if match >= 0 else 0
    start = max(0, center - 256)
    end = min(len(text), center + 768)
    excerpt = text[start:end]
    while len(excerpt.encode("utf-8")) > MAX_EXCERPT_BYTES:
        if end - center > center - start:
            end -= 1
        else:
            start += 1
        excerpt = text[start:end]
    return Excerpt(excerpt, start, end, match_start, match_end)


def _source_index(text: str, folded_text: str, folded_index: int) -> int:
    """Map one index into the case-folded text back to the source it folded from.

    Full case folding is a per-character mapping with no context dependence, so
    the folded text is exactly the concatenation of each source character's own
    fold. That is what makes this total where scanning the source for the query
    was not: a scan can only probe spellings it can name, and it named two --
    the query verbatim and its casefold. It found neither an occurrence
    differing from the query only in capitalization nor a hit the stemmed pass
    admitted with no literal occurrence at all, and both then windowed the head
    of the document instead of the passage that matched.

    Folding never shortens, so equal lengths prove every character mapped one
    to one and the folded index is already a source index. That guard lives
    here rather than at the call site because it is the path almost every
    document takes and no caller should be able to reach the search without it.

    The rest walks, but not from the beginning. Folding only ever adds, so a
    source position trails its folded one by at most the whole document's
    expansion, and no earlier position can be the answer: the walk starts that
    far back and steps at most as many times. A Python-level walk of a whole
    multi-megabyte source is not affordable once per hit -- it cost 200 ms on a
    4 MiB source, against 1 ms to fold the whole of it -- and this is the same
    walk with a bound rather than a different computation.
    """
    if len(folded_text) == len(text):
        return min(folded_index, len(text))
    expansion = len(folded_text) - len(text)
    start = max(0, folded_index - expansion)
    consumed = len(text[:start].casefold())
    for position in range(start, len(text)):
        width = len(text[position].casefold())
        if consumed + width > folded_index:
            return position
        consumed += width
    return len(text)


def _query_terms(query: str) -> list[str]:
    return re.findall(r"[^\W_]+", query, flags=re.UNICODE)


def _score_folded(folded: str, phrase: str, terms: tuple[str, ...]) -> float:
    """Rank one folded haystack by distinct admitted terms and an exact phrase.

    Production ranks through `_CompiledLiteralQuery.evaluate`; this is the
    reference scorer the ladder suite verifies that engine against, so the
    two cannot drift apart silently.
    """
    score = sum(_substring_admits(term, folded) for term in set(terms))
    score += int(_bounded_occurrence(folded, phrase) >= 0)
    return -float(score)


def owner_binding(payload: dict[str, object]) -> str:
    """Bind one owner search cursor to the ladder that produced its order.

    Owner cursors bind `owner_filter_binding` and the audit generation, never
    the ladder snapshot digest, so nothing else about them would notice that
    the order underneath them changed. Carrying the ladder version in the
    binding is what makes a cursor minted against the previous order fail
    closed rather than resume into a page it was never part of.
    """
    return owner_filter_binding({**payload, "ladder": LADDER_VERSION})


def ladder_resume(payload: dict[str, object], after: int) -> tuple[int, float, int]:
    """Read the rung, rank, and rowid a ladder cursor resumes after."""
    return _cursor_strength(payload), _cursor_rank(payload), after


class LadderEntry(Protocol):
    """The three coordinates every ladder resume compares, in sort order."""

    @property
    def strength(self) -> int: ...

    @property
    def rank(self) -> float: ...

    @property
    def rowid(self) -> int: ...


def ladder_start_index(
    matching: Sequence[LadderEntry], resume: tuple[int, float, int] | None
) -> int:
    """Find the first entry a resumed ladder walk has not already emitted."""
    if resume is None:
        return 0
    return next(
        (
            index
            for index, entry in enumerate(matching)
            if (entry.strength, entry.rank, entry.rowid) > resume
        ),
        len(matching),
    )


def _visible_owner_source_hits(
    connection: Connection,
    visible: Sequence[_SourceMatchEntry],
    literal_query: _CompiledLiteralQuery,
) -> tuple[OwnerSourceSearchHit, ...]:
    """Stream the owner's selected plaintext rows into bounded ranked hits."""
    if not visible:
        return ()
    by_rowid = {entry.rowid: entry for entry in visible}
    hits: dict[int, OwnerSourceSearchHit] = {}
    placeholders = ", ".join("?" for _ in visible)
    rows = connection.execute(
        owner_source_search_select(connection) + f" WHERE s.rowid IN ({placeholders})",
        owner_source_parameters(*(entry.rowid for entry in visible)),
    )
    for row in rows:
        rowid = int(row[0])
        entry = by_rowid[rowid]
        excerpt = _exact_excerpt(
            _authoritative_text(row),
            literal_query=literal_query,
        )
        hits[rowid] = OwnerSourceSearchHit(
            source=owner_source_summary_from_row(row),
            exact_excerpt=excerpt.text,
            rank=entry.rank,
        )
    return tuple(hits[entry.rowid] for entry in visible)


def owner_search_sources(
    connection: Connection,
    identity: StoreIdentity,
    query: str,
    cursor: Cursor | None,
    limit: int,
) -> OwnerSourceSearchPage:
    """Answer the owner's browser search with the kernel ladder itself.

    This reader used to issue one all-terms FTS expression -- no phrase rung,
    no any-term rung, no literal substring pass -- so a Han mid-run query that
    an agent could answer over MCP returned nothing in the owner's own
    browser. It now pages over exactly what `search_sources` pages over, and
    ranks through the same compiled literal query the kernel ladder uses
    rather than a mirror of it.
    The one deliberate difference is the excerpt, which is still cut from
    authoritative blob text rather than the disposable projection row.
    """
    normalized = _validate_query(query)
    page_size = _validate_page_size(limit)
    binding = owner_binding({"query": normalized})
    guard = owner_generation_token(connection)
    if cursor is None:
        resume: tuple[int, float, int] | None = None
        upper = int(
            connection.execute(
                "SELECT COALESCE(MAX(rowid), 0) FROM sources"
            ).fetchone()[0]
        )
    else:
        payload = _decode_cursor(cursor)
        _require_cursor_scope(
            payload,
            store_id=identity.store_id,
            operation="owner.source.search",
            binding=binding,
            label="owner source search",
        )
        # Owner cursors bind the audit generation, never the ladder snapshot.
        # This reader needs that guard as much as its memory sibling does: a
        # reindex changes which rung a capture reaches -- filename stemming
        # arrives with it -- so a walk resumed across one silently skips every
        # entry the rebuild promoted above the page boundary it left off at.
        if payload.get("snapshot") != guard:
            raise StaleCursorError("cursor belongs to another owner source search")
        after, upper = _cursor_rowid_bounds(payload)
        resume = ladder_resume(payload, after)
    literal_query = _compile_literal_query(normalized)
    matching = _source_ladder_matches(
        connection,
        normalized,
        upper,
        literal_query=literal_query,
    )
    start_index = ladder_start_index(matching, resume)
    window = matching[start_index : start_index + page_size + 1]
    has_more = len(window) > page_size
    visible = window[:page_size]
    items = _visible_owner_source_hits(
        connection,
        visible,
        literal_query,
    )
    next_cursor = (
        _encode_cursor(
            store_id=identity.store_id,
            operation="owner.source.search",
            upper=upper,
            after=visible[-1].rowid,
            binding=binding,
            rank=visible[-1].rank,
            snapshot=guard,
            strength=visible[-1].strength,
        )
        if has_more
        else None
    )
    return OwnerSourceSearchPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
        coverage=owner_source_projection_coverage(connection),
    )


def _authoritative_text(row: Row) -> str:
    """Read the retained blob text an owner excerpt is cut from.

    A capture the ladder admitted has a projection row, which implies retained
    text at capture time. It does not prove the blob still carries it, and an
    excerpt is a preview: an empty one is a worse answer than a hit, not a
    reason to withhold the hit.
    """
    return "" if row[17] is None else str(row[17])
