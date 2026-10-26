"""Owner-invoked maintenance: search projection rebuild and upgrade detection."""

from __future__ import annotations

import json
from dataclasses import dataclass

from memory.database import Connection, guard_revocations_recorded, writer_session
from memory.model import GuardViolation, RuntimePaths
from memory.sources import SEARCHABLE_MEDIA_TYPES

# Casefolded substring markers a claim's own wording uses when it is hedging,
# conditioning, superseding, or otherwise qualifying another claim. Matching
# is deliberately substring-based, not word-bounded, so it happily hits
# plurals and other inflections ("supersedes"/"superseded", "permission"/
# "permissions") and tolerates the occasional mid-word collision. That
# looseness is fine: a marker hit alone never proposes a candidate in
# `lint_guards` -- the shared-evidence-source gate is the real filter that
# keeps the report meaningful.
GUARD_VOCABULARY = (
    "self-reported",
    "not verified",
    "unverified",
    "unless",
    "only if",
    "except when",
    "supersedes",
    "superseded",
    "asked not to",
    "do not",
    "permission",
    "with consent",
    "counterbalance",
    "however",
)

_GUARD_LINK_TABLE = "memory_guard_links"
_GUARD_TABLES = (
    _GUARD_LINK_TABLE,
    "change_revision_guard_links",
    "change_revision_guard_revocations",
)
_SEARCHABLE_MEDIA_PARAMETERS = tuple(sorted(SEARCHABLE_MEDIA_TYPES))
_SEARCHABLE_MEDIA_PLACEHOLDERS = ", ".join("?" for _ in _SEARCHABLE_MEDIA_PARAMETERS)
# Mirrors `source_fts` in schema.sql byte for byte, modulo whitespace. A drift
# here is not a cosmetic one: `search_projection_current` compares live DDL
# against this string, so a mirror that lags reports `reindex_required` on every
# store forever and `memory reindex` writes the shape it just called stale.
_SOURCE_FTS_SQL = (
    "CREATE VIRTUAL TABLE source_fts USING fts5(\n"
    "    source_id UNINDEXED,\n"
    "    capture_rowid UNINDEXED,\n"
    "    utf8_text,\n"
    "    original_name,\n"
    "    tokenize = 'porter unicode61'\n"
    ")"
)
_MEMORY_FTS_SQL = (
    "CREATE VIRTUAL TABLE memory_fts USING fts5(\n"
    "    revision_id UNINDEXED,\n"
    "    statement,\n"
    "    tags,\n"
    "    tokenize = 'porter unicode61'\n"
    ")"
)


def _normalized_sql(sql: str) -> str:
    return " ".join(sql.split())


_FTS_CANONICAL_SQL = {
    "source_fts": _normalized_sql(_SOURCE_FTS_SQL),
    "memory_fts": _normalized_sql(_MEMORY_FTS_SQL),
}


@dataclass(frozen=True, slots=True)
class ReindexReport:
    """Row counts written into the rebuilt search projections."""

    source_rows: int
    memory_rows: int


@dataclass(frozen=True, slots=True)
class GuardCandidate:
    """One heuristic guard-link proposal for the owner's repair review."""

    guard_lineage_id: str
    governed_lineage_id: str
    guard_statement: str
    governed_statement: str
    rationales: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GuardLintReport:
    """Candidates plus every standing invariant violation.

    `candidates` is sorted strongest-rationale-first and capped at
    MAX_GUARD_LINKS, since the report exists to become `add_guard_link` edits
    in one change set, which can hold no more than that many links.
    `truncated_candidate_count` is how many qualifying pairs the cap left out
    (0 when the cap left nothing out).
    """

    candidates: tuple[GuardCandidate, ...]
    standing_violations: tuple[GuardViolation, ...]
    truncated_candidate_count: int


def search_projection_current(connection: Connection) -> bool:
    """Report whether both FTS projections match the canonical porter DDL."""
    for table, canonical in _FTS_CANONICAL_SQL.items():
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if row is None or _normalized_sql(str(row[0])) != canonical:
            return False
    return True


def guard_links_readable(connection: Connection) -> bool:
    """Report whether the canonical link table exists at all on this store.

    The narrow question a read path has: a store predating guard links answers
    every read with no links rather than failing, and that tolerance must not
    widen into "a store whose draft tables are one release behind draws no
    guard edges", which would hide links the store really holds.
    """
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (_GUARD_LINK_TABLE,),
        ).fetchone()
        is not None
    )


def guard_tables_present(connection: Connection) -> bool:
    """Report whether every canonical guard table and column is in place.

    This learns the revocation columns, where it used to be name-only. The old
    comment reserved exactly this revisit for the day a guard table's shape
    changed, and the reason it gave for staying name-only does not survive the
    change: a DDL-equality check reports a mismatch `memory reindex` cannot
    repair, but a *missing nullable column* is repaired by the additive
    ALTER heal that every writer BEGIN runs -- including the BEGIN that
    `memory reindex` itself opens. So this can report an unhealed store
    without stranding its owner, while a name-only check would call a store
    green whose links cannot yet record a revocation.
    """
    for table in _GUARD_TABLES:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if row is None:
            return False
    return guard_revocations_recorded(connection)


def reindex_required(connection: Connection) -> bool:
    """Report whether the owner must run `memory reindex` before search is current."""
    return not (
        search_projection_current(connection) and guard_tables_present(connection)
    )


def rebuild_search_projections(paths: RuntimePaths) -> ReindexReport:
    """Atomically drop and repopulate both FTS projections from canonical rows."""
    with writer_session(paths) as connection:
        connection.execute("DROP TABLE IF EXISTS source_fts")
        connection.execute("DROP TABLE IF EXISTS memory_fts")
        connection.execute(_SOURCE_FTS_SQL)
        connection.execute(_MEMORY_FTS_SQL)
        source_rows = 0
        for source_rowid, source_id, text, original_name in connection.execute(
            "SELECT s.rowid, s.source_id, b.utf8_text, s.original_name "
            "FROM sources AS s JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            f"WHERE s.media_type IN ({_SEARCHABLE_MEDIA_PLACEHOLDERS}) "
            "AND b.utf8_text IS NOT NULL ORDER BY s.rowid",
            _SEARCHABLE_MEDIA_PARAMETERS,
        ):
            authoritative_rowid = int(source_rowid)
            connection.execute(
                "INSERT INTO source_fts "
                "(rowid, source_id, capture_rowid, utf8_text, original_name) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    authoritative_rowid,
                    str(source_id),
                    authoritative_rowid,
                    str(text),
                    str(original_name),
                ),
            )
            source_rows += 1
        memory_rows = 0
        for revision_id, statement, tags_json in connection.execute(
            "SELECT heads.revision_id, mr.statement, mr.tags_json "
            "FROM current_memory_heads AS heads "
            "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
            "ORDER BY mr.rowid"
        ):
            tags = " ".join(json.loads(str(tags_json)))
            connection.execute(
                "INSERT INTO memory_fts (revision_id, statement, tags) "
                "VALUES (?, ?, ?)",
                (str(revision_id), str(statement), tags),
            )
            memory_rows += 1
        return ReindexReport(source_rows=source_rows, memory_rows=memory_rows)


def lint_guards(paths: RuntimePaths) -> GuardLintReport:
    """Propose heuristic guard-link candidates and report standing violations.

    Runs inside one `writer_session`, deliberately: a writer transaction's
    BEGIN-time ensure heals the guard-link tables additively before any of this
    runs, so `reviews._guard_violations` -- itself writer-session-only -- is
    safe to call here even against a legacy store that predates those tables.
    """
    with writer_session(paths) as connection:
        return guard_lint_report(connection)


def guard_lint_report(connection: Connection) -> GuardLintReport:
    """Build the guard-repair report from one already-open connection.

    Split out so a read can have it too. `lint_guards` supplies a writer
    session, whose BEGIN-time ensure heals the guard tables first; a reader
    cannot heal anything, so it must satisfy itself with `guard_tables_present`
    before calling this -- `_guard_violations` names `revoked_at` unguarded,
    and a store one release behind does not have that column yet.

    Nothing here writes. The transaction it runs in is the caller's choice, not
    this function's requirement.
    """
    # Lazy import: reviews.py is a large module with no other reason to be a
    # standing module-level dependency of maintenance.py, and this reaches
    # into one of its internals. Not needed to break an import cycle --
    # reviews.py never imports memory.maintenance, at module level or
    # otherwise -- but kept local to the one function that needs it, matching
    # how cli.py and sources.py already treat cross-references to reviews.py.
    from memory.reviews import MAX_GUARD_LINKS, _guard_violations

    heads = connection.execute(
        "SELECT heads.lineage_id, mr.statement, mr.application_id, mr.revision_id "
        "FROM current_memory_heads AS heads "
        "JOIN memory_revisions AS mr ON mr.revision_id = heads.revision_id "
        "ORDER BY mr.rowid"
    ).fetchall()
    # One evidence-source-id-set query per head: acceptable at owner-lint
    # cadence (an explicit, infrequent maintenance command), unlike the
    # per-request paths elsewhere in this module.
    evidence_sources = {
        str(revision_id): {
            str(row[0])
            for row in connection.execute(
                "SELECT source_id FROM memory_evidence WHERE memory_revision_id = ?",
                (str(revision_id),),
            ).fetchall()
        }
        for _lineage_id, _statement, _application_id, revision_id in heads
    }
    # Revoked pairs stay in this set, unlike everywhere else a revoked link
    # is skipped. The set exists to keep the report from proposing an edit
    # the owner cannot apply, and re-adding a revoked pair is refused: a
    # candidate that can only ever be rejected is noise, not a repair.
    existing_links = {
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "SELECT guard_lineage_id, governed_lineage_id FROM memory_guard_links"
        ).fetchall()
    }
    candidates: list[GuardCandidate] = []
    for (
        guard_lineage_id,
        guard_statement,
        guard_application_id,
        guard_revision_id,
    ) in heads:
        # Candidate rule: a head whose statement contains a guard-vocabulary
        # marker (hedges, conditionals, supersession language, consent or
        # permission language, counterarguments) is a *potential* guard.
        # shared_evidence_source is a NECESSARY rationale for every
        # proposed pair, not merely a sufficient one: at realistic corpus
        # scale, same_application alone would pair every marker-bearing
        # head with every other head from the same batch, which swamps
        # the owner with a mostly-meaningless report. same_application
        # only ever strengthens an already-qualifying pair to a third
        # rationale; it can never qualify one by itself.
        guard_statement_folded = str(guard_statement).casefold()
        if not any(marker in guard_statement_folded for marker in GUARD_VOCABULARY):
            continue
        for (
            governed_lineage_id,
            governed_statement,
            governed_application_id,
            governed_revision_id,
        ) in heads:
            if governed_lineage_id == guard_lineage_id:
                continue
            if (str(guard_lineage_id), str(governed_lineage_id)) in existing_links:
                continue
            rationales = {"guard_vocabulary"}
            if (
                evidence_sources[str(guard_revision_id)]
                & evidence_sources[str(governed_revision_id)]
            ):
                rationales.add("shared_evidence_source")
            if guard_application_id == governed_application_id:
                rationales.add("same_application")
            if "shared_evidence_source" not in rationales:
                continue
            candidates.append(
                GuardCandidate(
                    guard_lineage_id=str(guard_lineage_id),
                    governed_lineage_id=str(governed_lineage_id),
                    guard_statement=str(guard_statement),
                    governed_statement=str(governed_statement),
                    rationales=tuple(sorted(rationales)),
                )
            )
    # Stable sort on rationale count only: ties keep their prior relative
    # order, which is already (guard head rowid, governed head rowid)
    # ascending, because `heads` is rowid-ordered and both loops above
    # walk it in that order.
    candidates.sort(key=lambda candidate: -len(candidate.rationales))
    # Bounded like every other owner-facing operation in this Store: the
    # report exists to become `add_guard_link` edits in one change set,
    # and a change set cannot hold more than MAX_GUARD_LINKS of those, so
    # a longer report could never be fully actioned regardless.
    truncated_candidate_count = max(0, len(candidates) - MAX_GUARD_LINKS)
    return GuardLintReport(
        candidates=tuple(candidates[:MAX_GUARD_LINKS]),
        standing_violations=_guard_violations(connection),
        truncated_candidate_count=truncated_candidate_count,
    )
