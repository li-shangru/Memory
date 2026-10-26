"""Guard links: schema presence, writer-side ensure, and draft authoring."""

from __future__ import annotations

import pytest
from synthetic import (
    HEDGE_BODY,
    FakeClock,
    apply_ready,
    capture_batch,
    capture_text,
    ready_items,
    single_item_edit,
    store_one_memory,
    two_source_linked_apply,
)

from memory import reviews
from memory.database import (
    CHANGE_REVISION_GUARD_LINKS_SQL,
    CHANGE_REVISION_GUARD_REVOCATIONS_SQL,
    MEMORY_GUARD_LINKS_SQL,
    writer_session,
)
from memory.errors import InvalidArgumentError
from memory.maintenance import _normalized_sql, lint_guards
from memory.memories import get_memory, search_memories
from memory.model import (
    AddGuardLink,
    ApplicationResult,
    ChangeEdit,
    ChangeSetAdapterOrigin,
    ChangeSetView,
    DraftItem,
    EvidenceLocator,
    GuardLinkInput,
    MatchStrength,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    RejectItem,
    RemoveGuardLink,
    RestoreItem,
    RevokeGuardLink,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceDecision,
    SourceSummary,
)
from memory.reviews import MAX_GUARD_LINKS, edit_change_set, get_change_set
from memory.sources import _read_connection, get_store_status

_GUARD_TABLES = {
    "memory_guard_links",
    "change_revision_guard_links",
    "change_revision_guard_revocations",
}
#: The canonical link table exactly as v1.1.x created it, for the one test that
#: has to stand a current store back down onto a pre-revocation shape.
_LEGACY_MEMORY_GUARD_LINKS_SQL = """CREATE TABLE memory_guard_links (
    guard_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    governed_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    PRIMARY KEY (guard_lineage_id, governed_lineage_id),
    CHECK (guard_lineage_id <> governed_lineage_id)
) STRICT"""
_APPLIED_TABLES = (
    "application_memories",
    "applications",
    "approvals",
    "current_memory_heads",
    "memory_evidence",
    "memory_fts",
    "memory_guard_links",
    "memory_lineages",
    "memory_revisions",
)


def _committed_table_names(paths: RuntimePaths) -> set[str]:
    """Read table names over a read-only session that can never heal them."""
    with _read_connection(paths) as (connection, _identity):
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }


def _audit_generation(paths: RuntimePaths) -> int:
    """Read the committed generation without entering the writer heal path."""
    with _read_connection(paths) as (connection, _identity):
        row = connection.execute(
            "SELECT audit_generation FROM store_meta WHERE singleton = 1"
        ).fetchone()
    assert row is not None
    return int(row[0])


def _drop_guard_tables(paths: RuntimePaths) -> None:
    with writer_session(paths) as connection:
        for table in sorted(_GUARD_TABLES):
            connection.execute(f"DROP TABLE {table}")


def _downgrade_to_pre_revocation_shape(paths: RuntimePaths) -> None:
    """Stand the link table back down onto its released three-column shape.

    Runs inside the writer session that already healed it at BEGIN, so the
    downgrade is what commits -- the same trick the FTS downgrade uses.
    """
    with writer_session(paths) as connection:
        retained = connection.execute(
            "SELECT guard_lineage_id, governed_lineage_id, application_id "
            "FROM memory_guard_links"
        ).fetchall()
        connection.execute("DROP TABLE memory_guard_links")
        connection.execute("DROP TABLE change_revision_guard_revocations")
        connection.execute(_LEGACY_MEMORY_GUARD_LINKS_SQL)
        for row in retained:
            connection.execute(
                "INSERT INTO memory_guard_links "
                "(guard_lineage_id, governed_lineage_id, application_id) "
                "VALUES (?, ?, ?)",
                (str(row[0]), str(row[1]), str(row[2])),
            )


def _guard_link_columns(paths: RuntimePaths) -> set[str]:
    with _read_connection(paths) as (connection, _identity):
        return {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(memory_guard_links)"
            ).fetchall()
        }


def _revocation_rows(paths: RuntimePaths) -> list[tuple[str, str, bool, str | None]]:
    """Read every link with whether it is revoked and by which application."""
    with _read_connection(paths) as (connection, _identity):
        return [
            (
                str(row[0]),
                str(row[1]),
                row[2] is not None,
                None if row[3] is None else str(row[3]),
            )
            for row in connection.execute(
                "SELECT guard_lineage_id, governed_lineage_id, revoked_at, "
                "revoking_application_id FROM memory_guard_links "
                "ORDER BY guard_lineage_id, governed_lineage_id"
            ).fetchall()
        ]


def _governed_link_counts(paths: RuntimePaths, lineage_id: str) -> tuple[int, int]:
    """Count one claim's live links and its retained rows, live or revoked."""
    with _read_connection(paths) as (connection, _identity):
        live = int(
            connection.execute(
                "SELECT count(*) FROM memory_guard_links "
                "WHERE governed_lineage_id = ? AND revoked_at IS NULL",
                (lineage_id,),
            ).fetchone()[0]
        )
        retained = int(
            connection.execute(
                "SELECT count(*) FROM memory_guard_links WHERE governed_lineage_id = ?",
                (lineage_id,),
            ).fetchone()[0]
        )
    return live, retained


def _revoking_draft(
    paths: RuntimePaths,
    clock: FakeClock,
    *revocations: GuardLinkInput,
    name: str = "revocation-note.txt",
) -> ChangeSetView:
    """Seal a one-source batch whose only effect is revoking retained links.

    The source is accounted for as no-memory, so the revision proposes no claim
    at all: what applies is exactly the revocation, and nothing else.
    """
    batch_id, source = capture_text(
        paths,
        name=name,
        body="The hedge was attached to the wrong claim.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch_id,
        (
            SetSourceNoMemory(
                source_id=source.source_id,
                reason="Synthetic reviewed decision: this note only corrects a link.",
            ),
            *(RevokeGuardLink(link=link) for link in revocations),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    return draft


def _two_item_draft(
    paths: RuntimePaths,
    clock: FakeClock,
    *,
    guard_sensitivity: Sensitivity = Sensitivity.NORMAL,
) -> tuple[SourceSummary, ChangeSetView]:
    """Draft one guard claim and the claim it governs from a single source."""
    batch_id, source = capture_text(
        paths,
        name="pair.txt",
        body="The owner reports daily runs.\n" + HEDGE_BODY,
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch_id,
        (
            single_item_edit(
                item_id="itm_claim",
                source=source,
                statement="The owner reports daily runs.",
                excerpt="The owner reports daily runs.",
            ),
            single_item_edit(
                item_id="itm_guard",
                source=source,
                statement="The daily-runs figure is self-reported and not verified.",
                excerpt="self-reported and not verified",
                kind=MemoryKind.INSIGHT,
                sensitivity=guard_sensitivity,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    return source, draft


def _guard_link_rows(paths: RuntimePaths) -> list[tuple[str, str, str]]:
    """Read every materialized lineage-level link in a deterministic order."""
    with _read_connection(paths) as (connection, _identity):
        return [
            (str(row[0]), str(row[1]), str(row[2]))
            for row in connection.execute(
                "SELECT guard_lineage_id, governed_lineage_id, application_id "
                "FROM memory_guard_links "
                "ORDER BY guard_lineage_id, governed_lineage_id"
            ).fetchall()
        ]


def _draft_guard_link_rows(
    paths: RuntimePaths,
) -> list[tuple[str, int, str | None, str | None, str | None, str | None]]:
    """Read retained draft-link rows without entering a writer repair path."""
    with _read_connection(paths) as (connection, _identity):
        return [
            (
                str(row[0]),
                int(row[1]),
                None if row[2] is None else str(row[2]),
                None if row[3] is None else str(row[3]),
                None if row[4] is None else str(row[4]),
                None if row[5] is None else str(row[5]),
            )
            for row in connection.execute(
                "SELECT revision_id, ordinal, guard_item_id, guard_lineage_id, "
                "governed_item_id, governed_lineage_id "
                "FROM change_revision_guard_links ORDER BY revision_id, ordinal"
            ).fetchall()
        ]


def _row_counts(paths: RuntimePaths) -> dict[str, int]:
    """Count every table one application writes, for rollback completeness."""
    with _read_connection(paths) as (connection, _identity):
        return {
            table: int(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
            for table in _APPLIED_TABLES
        }


def _lineage_of(paths: RuntimePaths, memory_id: str) -> str:
    return get_memory(paths, memory_id).revision.lineage_id


def _lineage_link(guard: str, governed: str) -> GuardLinkInput:
    return GuardLinkInput(
        guard_item_id=None,
        guard_lineage_id=guard,
        governed_item_id=None,
        governed_lineage_id=governed,
    )


def _edit(
    paths: RuntimePaths, current: ChangeSetView, *edits: ChangeEdit
) -> ChangeSetView:
    return edit_change_set(
        paths,
        current.change_set_id,
        current.revision_id,
        edits,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )


def _item_link(guard: str, governed: str) -> GuardLinkInput:
    return GuardLinkInput(
        guard_item_id=guard,
        guard_lineage_id=None,
        governed_item_id=governed,
        governed_lineage_id=None,
    )


def test_guard_table_ddl_matches_schema_sql() -> None:
    from importlib import resources

    schema = (
        resources.files("memory").joinpath("schema.sql").read_text(encoding="utf-8")
    )
    for ddl in (
        MEMORY_GUARD_LINKS_SQL,
        CHANGE_REVISION_GUARD_LINKS_SQL,
        CHANGE_REVISION_GUARD_REVOCATIONS_SQL,
    ):
        canonical = ddl.replace("IF NOT EXISTS ", "")
        assert _normalized_sql(canonical) in _normalized_sql(schema)


def test_noop_writer_heals_missing_guard_tables_and_advances_generation_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch committed table DDL escaping the writer generation boundary."""
    _drop_guard_tables(synthetic_store)
    assert not (_GUARD_TABLES & _committed_table_names(synthetic_store))
    generation_before = _audit_generation(synthetic_store)

    with writer_session(synthetic_store) as connection:
        connection.execute("SELECT 1")

    assert _GUARD_TABLES <= _committed_table_names(synthetic_store)
    assert _audit_generation(synthetic_store) == generation_before + 1

    with writer_session(synthetic_store):
        pass

    assert _audit_generation(synthetic_store) == generation_before + 1


def test_exact_replay_heals_carried_forward_guard_tables_without_reapplying(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin released-table repair before the exact stable replay result."""
    applied = two_source_linked_apply(synthetic_store, FakeClock())
    ready = get_change_set(synthetic_store, applied.change_set_id)
    with _read_connection(synthetic_store) as (connection, _identity):
        counts_before = tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "applications",
                "approvals",
                "application_memories",
                "change_revision_guard_links",
            )
        )
    links_before = _guard_link_rows(synthetic_store)
    draft_links_before = _draft_guard_link_rows(synthetic_store)

    _downgrade_to_pre_revocation_shape(synthetic_store)
    generation_before = _audit_generation(synthetic_store)
    assert {"revoked_at", "revoking_application_id"}.isdisjoint(
        _guard_link_columns(synthetic_store)
    )
    assert "change_revision_guard_revocations" not in _committed_table_names(
        synthetic_store
    )
    assert _guard_link_rows(synthetic_store) == links_before
    assert _draft_guard_link_rows(synthetic_store) == draft_links_before

    replayed = reviews.approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=None,
    )

    assert replayed.idempotent_replay is True
    assert replayed.application_id == applied.application_id
    assert replayed.revision_id == applied.revision_id
    assert replayed.memory_ids == applied.memory_ids
    assert _GUARD_TABLES <= _committed_table_names(synthetic_store)
    assert {"revoked_at", "revoking_application_id"} <= _guard_link_columns(
        synthetic_store
    )
    assert _guard_link_rows(synthetic_store) == links_before
    assert _draft_guard_link_rows(synthetic_store) == draft_links_before
    assert _audit_generation(synthetic_store) == generation_before + 1
    with _read_connection(synthetic_store) as (connection, _identity):
        counts_after = tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "applications",
                "approvals",
                "application_memories",
                "change_revision_guard_links",
            )
        )
    assert counts_after == counts_before

    replayed_again = reviews.approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=None,
    )

    assert replayed_again.idempotent_replay is True
    assert replayed_again.application_id == applied.application_id
    assert replayed_again.revision_id == applied.revision_id
    assert replayed_again.memory_ids == applied.memory_ids
    assert _guard_link_rows(synthetic_store) == links_before
    assert _draft_guard_link_rows(synthetic_store) == draft_links_before
    assert _audit_generation(synthetic_store) == generation_before + 1


def test_guard_table_healing_and_generation_roll_back_together(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch healing DDL or its generation escaping a failed transaction."""
    _drop_guard_tables(synthetic_store)
    generation_before = _audit_generation(synthetic_store)

    with pytest.raises(RuntimeError, match="synthetic healing rollback"):
        with writer_session(synthetic_store):
            raise RuntimeError("synthetic healing rollback")

    assert not (_GUARD_TABLES & _committed_table_names(synthetic_store))
    assert _audit_generation(synthetic_store) == generation_before


def test_guard_table_healing_plus_dml_advances_generation_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch DDL and DML in one commit double-advancing the generation."""
    _drop_guard_tables(synthetic_store)
    generation_before = _audit_generation(synthetic_store)

    with writer_session(synthetic_store) as connection:
        connection.execute(
            "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
            ("lin_synthetic_healing", 1),
        )

    assert _GUARD_TABLES <= _committed_table_names(synthetic_store)
    assert _audit_generation(synthetic_store) == generation_before + 1
    with _read_connection(synthetic_store) as (connection, _identity):
        row = connection.execute(
            "SELECT created_at FROM memory_lineages WHERE lineage_id = ?",
            ("lin_synthetic_healing",),
        ).fetchone()
    assert row == (1,)


def test_any_writer_operation_heals_missing_guard_tables(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a heal reachable only through the owner's explicit reindex."""
    _drop_guard_tables(synthetic_store)
    assert get_store_status(synthetic_store).reindex_required is True

    capture_text(
        synthetic_store,
        name="ordinary.txt",
        body="An ordinary synthetic capture heals the additive guard tables.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )

    assert _GUARD_TABLES <= _committed_table_names(synthetic_store)
    assert get_store_status(synthetic_store).reindex_required is False


def test_add_guard_link_between_draft_items_and_digest_gains_key(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin that a link is reviewable and that only a linked revision digests one."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    assert draft.guard_links == ()
    assert "guard_links" not in draft.digest_payload

    linked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_item_link("itm_guard", "itm_claim")),
    )

    assert len(linked.guard_links) == 1
    link = linked.guard_links[0]
    assert link.ordinal == 0
    assert link.guard_item_id == "itm_guard"
    assert link.governed_item_id == "itm_claim"
    assert link.guard_lineage_id is None
    assert link.governed_lineage_id is None
    assert link.status == "active"
    assert "guard_links" in linked.digest_payload
    assert linked.digest != draft.digest
    assert get_change_set(synthetic_store, draft.change_set_id) == linked


def test_linkless_revision_digest_payload_has_no_guard_key(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch guard support changing the digest of every pre-guard revision."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())

    reloaded = get_change_set(synthetic_store, draft.change_set_id)

    assert reloaded.digest == draft.digest
    assert reloaded.guard_links == ()
    assert "guard_links" not in reloaded.digest_payload


#: The exact lowercase SHA-256 the released digest payload produced for these
#: two synthetic revisions before `revoked_guard_links` existed, recorded from
#: v1.1.4's own `_digest_payload`. Every stored revision in every existing
#: Store is verified by recomputing this payload on load, so these two bytes
#: strings are the compatibility contract: the linkless one stands for every
#: revision a pre-guard Store holds, the linked one for every revision a
#: v1.1.x Store holds. A key added unconditionally moves both and makes each
#: such revision fail closed as `wrong_digest` forever.
_PRE_REVOCATION_LINKLESS_DIGEST = (
    "21eeb40a908190930ef7fc44554e58053693c9dbb16e9b56bd5609d90ed37d27"
)
_PRE_REVOCATION_LINKED_DIGEST = (
    "c72e811144c50b06d120d50bc8ecb279178563a6f79dbbd7aac305c33eec29ca"
)


def _fixed_payload_parts() -> tuple[DraftItem, SourceDecision, GuardLinkInput]:
    """One frozen synthetic item, decision, and link with no generated ids.

    Every identifier here is literal so the recorded digests above stay
    reproducible; a Store-generated id would make them change every run.
    """
    blob_digest = "0" * 64
    item = DraftItem(
        ordinal=0,
        item_id="itm_alpha",
        status="active",
        memory=MemoryFields(
            kind=MemoryKind.FACT,
            statement="Synthetic claim.",
            occurred_on=None,
            valid_from=None,
            valid_to=None,
            tags=("synthetic",),
            sensitivity=Sensitivity.NORMAL,
            target_lineage_id=None,
            expected_head_id=None,
        ),
        evidence=(
            EvidenceLocator(
                ordinal=0,
                source_id="src_a",
                blob_digest=blob_digest,
                mode="text",
                char_start=0,
                char_end=16,
                excerpt="Synthetic claim.",
                source_level=None,
            ),
        ),
    )
    decision = SourceDecision(
        ordinal=0,
        source_id="src_a",
        blob_digest=blob_digest,
        state="used",
        reason=None,
    )
    return item, decision, _item_link("itm_guard", "itm_alpha")


def _fixed_digest(
    *,
    guard_links: tuple[tuple[int, GuardLinkInput], ...],
    revoked_guard_links: tuple[tuple[int, GuardLinkInput], ...],
) -> tuple[dict[str, object], str]:
    item, decision, _link = _fixed_payload_parts()
    payload = reviews._digest_payload(
        store_id="sto_synthetic",
        change_set_id="chg_synthetic",
        batch_id="bat_synthetic",
        revision_id="csr_synthetic",
        items=(item,),
        decisions=(decision,),
        guard_links=guard_links,
        revoked_guard_links=revoked_guard_links,
    )
    _encoded, digest = reviews.canonical_digest(payload)
    return payload, digest


def test_revocation_key_leaves_every_pre_revocation_digest_byte_identical() -> None:
    """Catch a payload key that retroactively invalidates every stored revision."""
    _item, _decision, link = _fixed_payload_parts()

    linkless, linkless_digest = _fixed_digest(guard_links=(), revoked_guard_links=())
    linked, linked_digest = _fixed_digest(
        guard_links=((0, link),), revoked_guard_links=()
    )

    assert "guard_links" not in linkless
    assert "revoked_guard_links" not in linkless
    assert "revoked_guard_links" not in linked
    assert linkless_digest == _PRE_REVOCATION_LINKLESS_DIGEST
    assert linked_digest == _PRE_REVOCATION_LINKED_DIGEST


def test_revocation_key_appears_only_when_a_revision_carries_one() -> None:
    """Pin the new key's exact shape and its separation from `guard_links`."""
    _item, _decision, link = _fixed_payload_parts()

    revoking, revoking_digest = _fixed_digest(
        guard_links=(), revoked_guard_links=((0, link),)
    )

    assert "guard_links" not in revoking
    assert revoking["revoked_guard_links"] == [
        {
            "ordinal": 0,
            "guard_item_id": "itm_guard",
            "guard_lineage_id": None,
            "governed_item_id": "itm_alpha",
            "governed_lineage_id": None,
        }
    ]
    assert revoking_digest not in {
        _PRE_REVOCATION_LINKLESS_DIGEST,
        _PRE_REVOCATION_LINKED_DIGEST,
    }


def test_every_stored_revision_still_verifies_after_the_key_exists(
    synthetic_store: RuntimePaths,
) -> None:
    """Load every revision a pre-change Store could hold through the new loader.

    The Store recomputes and re-verifies a revision's digest on every load, so
    reading each stored revision back is the whole compatibility check: a
    payload that gained an unconditional key raises `WrongDigestError` here.
    """
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    linked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_item_link("itm_guard", "itm_claim")),
    )
    unlinked = _edit(
        synthetic_store, linked, RemoveGuardLink(link=linked_input(linked))
    )
    stored = _stored_revision_ids(synthetic_store, draft.change_set_id)
    assert len(stored) == 4

    with _read_connection(synthetic_store) as (connection, _identity):
        loaded = [
            reviews._load_change_set_revision(
                connection, draft.change_set_id, revision_id
            )
            for revision_id in stored
        ]

    assert [view.revision_id for view in loaded] == list(stored)
    assert {view.digest for view in loaded} >= {
        draft.digest,
        linked.digest,
        unlinked.digest,
    }
    assert all("revoked_guard_links" not in view.digest_payload for view in loaded)


def linked_input(view: ChangeSetView) -> GuardLinkInput:
    """Read one stored draft link back as the input that would recreate it."""
    link = view.guard_links[0]
    return GuardLinkInput(
        guard_item_id=link.guard_item_id,
        guard_lineage_id=link.guard_lineage_id,
        governed_item_id=link.governed_item_id,
        governed_lineage_id=link.governed_lineage_id,
    )


def _stored_revision_ids(paths: RuntimePaths, change_set_id: str) -> tuple[str, ...]:
    with _read_connection(paths) as (connection, _identity):
        return tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT revision_id FROM change_set_revisions "
                "WHERE change_set_id = ? ORDER BY created_at, rowid",
                (change_set_id,),
            ).fetchall()
        )


def test_guard_link_refs_are_validated(synthetic_store: RuntimePaths) -> None:
    """Pin refusal of unnamed, doubly named, absent, self, and unknown endpoints."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    invalid = (
        GuardLinkInput(
            guard_item_id=None,
            guard_lineage_id=None,
            governed_item_id="itm_claim",
            governed_lineage_id=None,
        ),
        GuardLinkInput(
            guard_item_id="itm_guard",
            guard_lineage_id="lin_also_named",
            governed_item_id="itm_claim",
            governed_lineage_id=None,
        ),
        _item_link("itm_absent", "itm_claim"),
        _item_link("itm_claim", "itm_claim"),
        GuardLinkInput(
            guard_item_id=None,
            guard_lineage_id="lin_does_not_exist",
            governed_item_id="itm_claim",
            governed_lineage_id=None,
        ),
    )

    for link in invalid:
        with pytest.raises(InvalidArgumentError):
            _edit(synthetic_store, draft, AddGuardLink(link=link))

    assert get_change_set(synthetic_store, draft.change_set_id) == draft


def test_remove_guard_link_and_duplicate_rejection(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin exact-link removal and refusal of a duplicate or absent link."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    link = _item_link("itm_guard", "itm_claim")
    linked = _edit(synthetic_store, draft, AddGuardLink(link=link))

    with pytest.raises(InvalidArgumentError):
        _edit(synthetic_store, linked, AddGuardLink(link=link))
    with pytest.raises(InvalidArgumentError):
        _edit(
            synthetic_store,
            linked,
            RemoveGuardLink(link=_item_link("itm_claim", "itm_guard")),
        )

    unlinked = _edit(synthetic_store, linked, RemoveGuardLink(link=link))

    assert unlinked.guard_links == ()
    assert "guard_links" not in unlinked.digest_payload
    assert unlinked.digest != linked.digest
    assert get_change_set(synthetic_store, draft.change_set_id) == unlinked


def test_rejected_item_marks_its_links_rejected(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin link status deriving from its endpoints rather than being stored."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    link = _item_link("itm_guard", "itm_claim")

    rejected = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=link),
        RejectItem(item_id="itm_guard"),
    )

    assert rejected.guard_links[0].status == "rejected"
    assert get_change_set(synthetic_store, draft.change_set_id) == rejected

    restored = _edit(synthetic_store, rejected, RestoreItem(item_id="itm_guard"))

    assert restored.guard_links[0].status == "active"
    assert get_change_set(synthetic_store, draft.change_set_id) == restored


def test_apply_materializes_lineage_level_links(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin that an item-referenced draft link becomes one lineage-level row."""
    applied = two_source_linked_apply(synthetic_store, FakeClock())

    assert applied.standing_guard_violations == ()
    claim_lineage_id = _lineage_of(synthetic_store, applied.memory_ids[0])
    guard_lineage_id = _lineage_of(synthetic_store, applied.memory_ids[1])
    assert _guard_link_rows(synthetic_store) == [
        (guard_lineage_id, claim_lineage_id, applied.application_id)
    ]


def test_apply_blocks_guard_above_touched_claim(
    synthetic_store: RuntimePaths,
) -> None:
    """A guard more sensitive than its claim blocks, leaving nothing applied."""
    _source, draft = _two_item_draft(
        synthetic_store, FakeClock(), guard_sensitivity=Sensitivity.RESTRICTED
    )
    linked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_item_link("itm_guard", "itm_claim")),
    )

    with pytest.raises(InvalidArgumentError) as raised:
        apply_ready(synthetic_store, linked)

    details = raised.value.details
    assert details is not None
    assert details["guard_sensitivity"] == "restricted"
    assert details["governed_sensitivity"] == "normal"
    assert _row_counts(synthetic_store) == dict.fromkeys(_APPLIED_TABLES, 0)
    assert get_change_set(synthetic_store, draft.change_set_id) == linked
    assert linked.state == "draft"


def test_rejected_endpoint_drops_link_at_apply(
    synthetic_store: RuntimePaths,
) -> None:
    """A rejected item creates no memory, so its links die with it."""
    _source, draft = _two_item_draft(synthetic_store, FakeClock())
    rejected = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_item_link("itm_guard", "itm_claim")),
        RejectItem(item_id="itm_guard"),
    )
    assert rejected.guard_links[0].status == "rejected"

    applied = apply_ready(synthetic_store, rejected)

    assert len(applied.memory_ids) == 1
    assert applied.standing_guard_violations == ()
    assert _guard_link_rows(synthetic_store) == []


def test_standing_violation_reports_without_blocking_unrelated_apply(
    synthetic_store: RuntimePaths,
) -> None:
    """A later capture can raise a guard above its claim without freezing writes."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, governed_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    capture_text(
        synthetic_store,
        name="hedge-copy.txt",
        body=HEDGE_BODY,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    unrelated_batch, unrelated_source = capture_text(
        synthetic_store,
        name="unrelated.txt",
        body="The owner keeps a paper notebook.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )

    ready = ready_items(
        synthetic_store,
        unrelated_batch,
        (
            single_item_edit(
                item_id="itm_unrelated",
                source=unrelated_source,
                statement="The owner keeps a paper notebook.",
                excerpt="The owner keeps a paper notebook.",
            ),
        ),
    )

    applied = apply_ready(synthetic_store, ready)

    assert len(applied.memory_ids) == 1
    assert len(applied.standing_guard_violations) == 1
    violation = applied.standing_guard_violations[0]
    assert violation.guard_lineage_id == guard_lineage_id
    assert violation.governed_lineage_id == governed_lineage_id
    assert violation.guard_sensitivity is Sensitivity.RESTRICTED
    assert violation.governed_sensitivity is Sensitivity.NORMAL

    replayed = apply_ready(synthetic_store, ready)

    assert replayed.idempotent_replay is True
    assert replayed.standing_guard_violations == applied.standing_guard_violations


def test_cross_form_self_link_is_rejected_at_edit(
    synthetic_store: RuntimePaths,
) -> None:
    """An item correcting lineage L is lineage L, however the link names it."""
    clock = FakeClock()
    head_id, lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="claim.txt",
        body="The owner reports daily runs.\n",
        statement="The owner reports daily runs.",
        excerpt="The owner reports daily runs.",
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="correction.txt",
        body="The owner reports runs on weekdays only.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_correction",
                source=source,
                statement="The owner reports runs on weekdays only.",
                excerpt="The owner reports runs on weekdays only.",
                target_lineage_id=lineage_id,
                expected_head_id=head_id,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)

    with pytest.raises(InvalidArgumentError) as raised:
        _edit(
            synthetic_store,
            draft,
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id="itm_correction",
                    guard_lineage_id=None,
                    governed_item_id=None,
                    governed_lineage_id=lineage_id,
                )
            ),
        )

    assert raised.value.details == {
        "guard_lineage_id": lineage_id,
        "governed_lineage_id": lineage_id,
    }
    assert get_change_set(synthetic_store, draft.change_set_id) == draft


def test_cross_form_duplicate_is_rejected(synthetic_store: RuntimePaths) -> None:
    """Two links naming one lineage in different forms are still one pair."""
    clock = FakeClock()
    guard_head_id, guard_lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="hedge.txt",
        body=HEDGE_BODY,
        statement="The daily-runs figure is self-reported and not verified.",
        excerpt="self-reported and not verified",
        kind=MemoryKind.INSIGHT,
    )
    _claim_head_id, claim_lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="claim.txt",
        body="The owner reports daily runs.\n",
        statement="The owner reports daily runs.",
        excerpt="The owner reports daily runs.",
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="sharper-hedge.txt",
        body="No independent record confirms that figure.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_guard",
                source=source,
                statement="No independent record confirms the daily-runs figure.",
                excerpt="No independent record confirms that figure.",
                kind=MemoryKind.INSIGHT,
                target_lineage_id=guard_lineage_id,
                expected_head_id=guard_head_id,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    item_form = GuardLinkInput(
        guard_item_id="itm_guard",
        guard_lineage_id=None,
        governed_item_id=None,
        governed_lineage_id=claim_lineage_id,
    )

    with pytest.raises(InvalidArgumentError) as raised:
        _edit(
            synthetic_store,
            draft,
            AddGuardLink(link=item_form),
            AddGuardLink(link=_lineage_link(guard_lineage_id, claim_lineage_id)),
        )

    assert raised.value.details == {
        "guard_lineage_id": guard_lineage_id,
        "governed_lineage_id": claim_lineage_id,
    }
    linked = _edit(synthetic_store, draft, AddGuardLink(link=item_form))
    assert len(linked.guard_links) == 1


def test_reproposing_an_existing_link_is_idempotent(
    synthetic_store: RuntimePaths,
) -> None:
    """Re-proposing a materialized pair is add-only, not an error."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    existing = _guard_link_rows(synthetic_store)
    guard_lineage_id, governed_lineage_id, first_application_id = existing[0]
    batch_id, source = capture_text(
        synthetic_store,
        name="restated.txt",
        body="The owner still reports daily runs.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_restated",
                source=source,
                statement="The owner still reports daily runs.",
                excerpt="The owner still reports daily runs.",
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    relinked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_lineage_link(guard_lineage_id, governed_lineage_id)),
    )

    applied = apply_ready(synthetic_store, relinked)

    assert applied.standing_guard_violations == ()
    assert applied.application_id != first_application_id
    assert _guard_link_rows(synthetic_store) == existing


def test_max_guard_links_boundary(synthetic_store: RuntimePaths) -> None:
    """Pin the link ceiling on item pairs, which cost no extra stored lineages."""
    lines = tuple(f"Synthetic fact {index:02d} stands alone.\n" for index in range(17))
    batch_id, source = capture_text(
        synthetic_store,
        name="many.txt",
        body="".join(lines),
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        tuple(
            single_item_edit(
                item_id=f"itm_{index:02d}",
                source=source,
                statement=line.strip(),
                excerpt=line.strip(),
            )
            for index, line in enumerate(lines)
        ),
    )
    assert isinstance(draft, ChangeSetView)
    pairs = [
        (f"itm_{guard:02d}", f"itm_{governed:02d}")
        for guard in range(len(lines))
        for governed in range(len(lines))
        if guard != governed
    ]
    assert len(pairs) > MAX_GUARD_LINKS

    filled = _edit(
        synthetic_store,
        draft,
        *(
            AddGuardLink(link=_item_link(guard, governed))
            for guard, governed in pairs[:MAX_GUARD_LINKS]
        ),
    )

    assert len(filled.guard_links) == MAX_GUARD_LINKS
    with pytest.raises(InvalidArgumentError):
        _edit(
            synthetic_store,
            filled,
            AddGuardLink(link=_item_link(*pairs[MAX_GUARD_LINKS])),
        )


def _apply_one_more_guard(
    paths: RuntimePaths,
    clock: FakeClock,
    *,
    index: int,
    governed_lineage_id: str,
) -> ApplicationResult:
    """Capture, draft, link, and apply one further guard for an existing claim."""
    excerpt = f"Hedge {index}: no independent record confirms that figure."
    batch_id, source = capture_text(
        paths,
        name=f"hedge-{index}.txt",
        body=f"{excerpt}\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch_id,
        (
            single_item_edit(
                item_id="itm_guard",
                source=source,
                statement=f"Hedge {index} qualifies the daily-runs figure.",
                excerpt=excerpt,
                kind=MemoryKind.INSIGHT,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    linked = _edit(
        paths,
        draft,
        AddGuardLink(
            link=GuardLinkInput(
                guard_item_id="itm_guard",
                guard_lineage_id=None,
                governed_item_id=None,
                governed_lineage_id=governed_lineage_id,
            )
        ),
    )
    return apply_ready(paths, linked)


def test_per_lineage_guard_cap_refuses_the_link_past_the_wire_bound(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every guard rides along on the claim, so the retained roster is capped."""
    # Lowered to keep the fixture small; the real ceiling is the guards
    # maxItems the MCP schemas declare, pinned by the test_mcp mirror equality.
    monkeypatch.setattr(reviews, "MAX_GUARDS_PER_LINEAGE", 3)
    clock = FakeClock()
    first = two_source_linked_apply(synthetic_store, clock)
    claim_lineage_id = _lineage_of(synthetic_store, first.memory_ids[0])
    _apply_one_more_guard(
        synthetic_store,
        clock,
        index=2,
        governed_lineage_id=claim_lineage_id,
    )
    _apply_one_more_guard(
        synthetic_store,
        clock,
        index=3,
        governed_lineage_id=claim_lineage_id,
    )
    filled_links = _guard_link_rows(synthetic_store)
    filled_counts = _row_counts(synthetic_store)
    assert len(filled_links) == 3

    with pytest.raises(InvalidArgumentError) as raised:
        _apply_one_more_guard(
            synthetic_store,
            clock,
            index=4,
            governed_lineage_id=claim_lineage_id,
        )

    assert raised.value.details == {"governed_lineage_id": claim_lineage_id}
    assert _guard_link_rows(synthetic_store) == filled_links
    assert _row_counts(synthetic_store) == filled_counts
    assert len(get_memory(synthetic_store, first.memory_ids[0]).guards) == 3


def _apply_one_more_claim_under_guard(
    paths: RuntimePaths,
    clock: FakeClock,
    *,
    index: int,
    guard_lineage_id: str,
) -> ApplicationResult:
    """Capture, draft, link, and apply one further claim under an existing guard."""
    statement = f"The owner logs a {index}-mile bike ride."
    batch_id, source = capture_text(
        paths,
        name=f"claim-{index}.txt",
        body=f"{statement}\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch_id,
        (
            single_item_edit(
                item_id="itm_claim",
                source=source,
                statement=statement,
                excerpt=statement,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    linked = _edit(
        paths,
        draft,
        AddGuardLink(
            link=GuardLinkInput(
                guard_item_id=None,
                guard_lineage_id=guard_lineage_id,
                governed_item_id="itm_claim",
                governed_lineage_id=None,
            )
        ),
    )
    return apply_ready(paths, linked)


def test_guard_direction_is_uncapped_across_lineages(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MAX_GUARDS_PER_LINEAGE bounds a claim's guards, never a guard's claims."""
    monkeypatch.setattr(reviews, "MAX_GUARDS_PER_LINEAGE", 2)
    clock = FakeClock()
    first = two_source_linked_apply(synthetic_store, clock)
    guard_id = first.memory_ids[1]
    guard_lineage_id = _lineage_of(synthetic_store, guard_id)

    second = _apply_one_more_claim_under_guard(
        synthetic_store, clock, index=2, guard_lineage_id=guard_lineage_id
    )
    third = _apply_one_more_claim_under_guard(
        synthetic_store, clock, index=3, guard_lineage_id=guard_lineage_id
    )

    # Each claim carries only this one guard, so the per-governed-lineage cap
    # (patched well below 3) never sees more than one link per claim and all
    # three applies succeed -- the cap tracks the governed side, not this one.
    governed_lineages = {
        _lineage_of(synthetic_store, memory_id)
        for memory_id in (
            first.memory_ids[0],
            second.memory_ids[0],
            third.memory_ids[0],
        )
    }
    assert len(_guard_link_rows(synthetic_store)) == 3
    guard = get_memory(synthetic_store, guard_id)
    assert len(guard.governs) == 3
    assert {attachment.lineage_id for attachment in guard.governs} == governed_lineages


def test_reproposing_a_retained_link_does_not_consume_cap_headroom(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Add-only re-proposal must not count as a new guard against the cap."""
    monkeypatch.setattr(reviews, "MAX_GUARDS_PER_LINEAGE", 1)
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, governed_lineage_id, _application = _guard_link_rows(
        synthetic_store
    )[0]
    batch_id, source = capture_text(
        synthetic_store,
        name="restated.txt",
        body="The owner still reports daily runs.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_restated",
                source=source,
                statement="The owner still reports daily runs.",
                excerpt="The owner still reports daily runs.",
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    relinked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_lineage_link(guard_lineage_id, governed_lineage_id)),
    )

    replayed = apply_ready(synthetic_store, relinked)

    assert replayed.standing_guard_violations == ()
    assert len(_guard_link_rows(synthetic_store)) == 1
    assert len(get_memory(synthetic_store, applied.memory_ids[0]).guards) == 1


def test_blocked_apply_rolls_back_onto_a_populated_store(
    synthetic_store: RuntimePaths,
) -> None:
    """Roll back over a real baseline: the repointed head must come back too."""
    clock = FakeClock()
    head_id, lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="claim.txt",
        body="The owner reports daily runs.\n",
        statement="The owner reports daily runs.",
        excerpt="The owner reports daily runs.",
    )
    before_counts = _row_counts(synthetic_store)
    before_search = search_memories(synthetic_store, "daily runs")
    assert [hit.memory.statement for hit in before_search.items] == [
        "The owner reports daily runs."
    ]
    batch_id, captured = capture_batch(
        synthetic_store,
        {
            "correction.txt": "The owner reports runs on weekdays only.\n",
            "notebook.txt": "The owner keeps a paper notebook.\n",
            "notebook-hedge.txt": HEDGE_BODY,
        },
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_correction",
                source=captured["correction.txt"],
                statement="The owner reports runs on weekdays only.",
                excerpt="The owner reports runs on weekdays only.",
                target_lineage_id=lineage_id,
                expected_head_id=head_id,
            ),
            single_item_edit(
                item_id="itm_claim",
                source=captured["notebook.txt"],
                statement="The owner keeps a paper notebook.",
                excerpt="The owner keeps a paper notebook.",
            ),
            single_item_edit(
                item_id="itm_guard",
                source=captured["notebook-hedge.txt"],
                statement="The notebook habit is self-reported and not verified.",
                excerpt="self-reported and not verified",
                kind=MemoryKind.INSIGHT,
                sensitivity=Sensitivity.RESTRICTED,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    linked = _edit(
        synthetic_store,
        draft,
        AddGuardLink(link=_item_link("itm_guard", "itm_claim")),
    )

    with pytest.raises(InvalidArgumentError):
        apply_ready(synthetic_store, linked)

    assert _row_counts(synthetic_store) == before_counts
    assert get_memory(synthetic_store, head_id).current_head_id == head_id
    assert search_memories(synthetic_store, "daily runs") == before_search


def test_raising_a_guard_lineage_blocks_on_its_new_head(
    synthetic_store: RuntimePaths,
) -> None:
    """A correction that raises only the guard still trips the invariant."""
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    guard_head_id = applied.memory_ids[1]
    guard_lineage_id = _lineage_of(synthetic_store, guard_head_id)
    batch_id, source = capture_text(
        synthetic_store,
        name="sharper-hedge.txt",
        body="No independent record confirms that figure.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_guard",
                source=source,
                statement="No independent record confirms the daily-runs figure.",
                excerpt="No independent record confirms that figure.",
                kind=MemoryKind.INSIGHT,
                sensitivity=Sensitivity.RESTRICTED,
                target_lineage_id=guard_lineage_id,
                expected_head_id=guard_head_id,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)

    # The batch names only the guard, and the guard was NORMAL until this very
    # apply repointed its head. Read the lineage ranks before the item phase and
    # the raise reads NORMAL, no violation is seen, and this apply lands silently.
    with pytest.raises(InvalidArgumentError) as raised:
        apply_ready(synthetic_store, draft)

    details = raised.value.details
    assert details is not None
    assert details["guard_lineage_id"] == guard_lineage_id
    assert details["guard_sensitivity"] == "restricted"
    assert details["governed_sensitivity"] == "normal"
    assert get_memory(synthetic_store, guard_head_id).current_head_id == guard_head_id


def test_search_bundles_guards_bypassing_filters(
    synthetic_store: RuntimePaths,
) -> None:
    """A guard the filters exclude as a hit still rides along with its claim."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)

    page = search_memories(
        synthetic_store,
        "daily runs",
        filters=MemoryFilters(kinds=(MemoryKind.FACT,)),
    )

    claim_hits = [
        hit
        for hit in page.items
        if hit.memory.statement == "The owner reports daily runs."
    ]
    assert len(claim_hits) == 1
    guards = claim_hits[0].guards
    assert [guard.statement for guard in guards] == [
        "The daily-runs figure is self-reported and not verified."
    ]
    assert guards[0].kind == MemoryKind.INSIGHT
    assert all(hit.memory.kind == MemoryKind.FACT for hit in page.items)


def test_guard_matching_the_query_is_a_hit_and_an_attachment_at_once(
    synthetic_store: RuntimePaths,
) -> None:
    """A guard that answers the query keeps its own hit and its escort role."""
    applied = two_source_linked_apply(synthetic_store, FakeClock())
    claim_id, guard_id = applied.memory_ids
    guard_lineage_id = _lineage_of(synthetic_store, guard_id)

    page = search_memories(synthetic_store, "daily runs")

    assert [hit.memory.memory_id for hit in page.items] == [claim_id, guard_id]
    # Both statements answer the phrase rung, so the guard is ordered by the
    # ladder like any other head rather than demoted for also being a guard.
    assert [hit.match_strength for hit in page.items] == [
        MatchStrength.PHRASE,
        MatchStrength.PHRASE,
    ]
    claim_hit, guard_hit = page.items
    assert [attachment.lineage_id for attachment in claim_hit.guards] == [
        guard_lineage_id
    ]
    assert claim_hit.guards[0].memory_id == guard_id
    assert guard_hit.guards == ()


def test_three_guards_attach_in_one_lineage_order_on_both_read_paths(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the two read paths ordering one claim's guards differently."""
    hedges = (
        (
            "The daily-runs figure is self-reported and not verified.",
            "That figure is self-reported and not verified.",
        ),
        (
            "No independent record confirms the daily-runs figure.",
            "No independent record confirms that figure.",
        ),
        (
            "The daily-runs figure predates the current tracker.",
            "That figure predates the current tracker.",
        ),
    )
    batch_id, source = capture_text(
        synthetic_store,
        name="hedged.txt",
        body="The owner reports daily runs.\n"
        + "".join(f"{excerpt}\n" for _statement, excerpt in hedges),
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_claim",
                source=source,
                statement="The owner reports daily runs.",
                excerpt="The owner reports daily runs.",
            ),
            *(
                single_item_edit(
                    item_id=f"itm_guard_{index}",
                    source=source,
                    statement=statement,
                    excerpt=excerpt,
                    kind=MemoryKind.INSIGHT,
                )
                for index, (statement, excerpt) in enumerate(hedges)
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    linked = _edit(
        synthetic_store,
        draft,
        *(
            AddGuardLink(link=_item_link(f"itm_guard_{index}", "itm_claim"))
            for index in range(len(hedges))
        ),
    )

    applied = apply_ready(synthetic_store, linked)

    claim_id, *guard_ids = applied.memory_ids
    page = search_memories(synthetic_store, "daily runs")
    claim_hits = [hit for hit in page.items if hit.memory.memory_id == claim_id]
    assert len(claim_hits) == 1
    attached = claim_hits[0].guards

    assert len(attached) == len(hedges)
    assert attached == get_memory(synthetic_store, claim_id).guards
    assert [guard.lineage_id for guard in attached] == sorted(
        _lineage_of(synthetic_store, memory_id) for memory_id in guard_ids
    )
    assert {guard.statement for guard in attached} == {
        statement for statement, _excerpt in hedges
    }


def test_get_memory_reports_guards_and_governs(
    synthetic_store: RuntimePaths,
) -> None:
    """Both ends of one link read their own side of it and nothing more."""
    applied = two_source_linked_apply(synthetic_store, FakeClock())
    claim = get_memory(synthetic_store, applied.memory_ids[0])
    guard = get_memory(synthetic_store, applied.memory_ids[1])

    assert [attachment.lineage_id for attachment in claim.guards] == [
        guard.revision.lineage_id
    ]
    assert claim.guards[0].memory_id == guard.revision.memory_id
    assert claim.governs == ()
    assert guard.guards == ()
    assert [attachment.lineage_id for attachment in guard.governs] == [
        claim.revision.lineage_id
    ]
    assert guard.governs[0].memory_id == claim.revision.memory_id


def test_guard_supersession_keeps_the_link(synthetic_store: RuntimePaths) -> None:
    """The link is lineage-level, so a reworded guard keeps governing the claim."""
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    guard_head_id = applied.memory_ids[1]
    guard_lineage_id = _lineage_of(synthetic_store, guard_head_id)
    reworded = "No independent record confirms the daily-runs figure."
    batch_id, source = capture_text(
        synthetic_store,
        name="sharper-hedge.txt",
        body="No independent record confirms that figure.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    ready = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_guard",
                source=source,
                statement=reworded,
                excerpt="No independent record confirms that figure.",
                kind=MemoryKind.INSIGHT,
                target_lineage_id=guard_lineage_id,
                expected_head_id=guard_head_id,
            ),
        ),
    )

    superseded = apply_ready(synthetic_store, ready)

    page = search_memories(synthetic_store, "daily runs")
    claim_hits = [
        hit
        for hit in page.items
        if hit.memory.statement == "The owner reports daily runs."
    ]
    assert len(claim_hits) == 1
    guards = claim_hits[0].guards
    assert [guard.statement for guard in guards] == [reworded]
    assert guards[0].memory_id == superseded.memory_ids[0]
    assert guards[0].lineage_id == guard_lineage_id


def test_sensitivity_filtered_search_still_attaches_lower_guards(
    synthetic_store: RuntimePaths,
) -> None:
    """Set filters must not silence a guard the owner is entitled to read."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    capture_text(
        synthetic_store,
        name="claim-copy.txt",
        body="The owner reports daily runs.\n",
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )

    page = search_memories(
        synthetic_store,
        "daily runs",
        filters=MemoryFilters(sensitivities=(Sensitivity.RESTRICTED,)),
    )

    assert [hit.memory.statement for hit in page.items] == [
        "The owner reports daily runs."
    ]
    hit = page.items[0]
    assert hit.memory.effective_sensitivity is Sensitivity.RESTRICTED
    assert [guard.statement for guard in hit.guards] == [
        "The daily-runs figure is self-reported and not verified."
    ]
    assert hit.guards[0].effective_sensitivity is Sensitivity.NORMAL


def test_guards_absent_on_pre_guard_read_path(
    synthetic_store: RuntimePaths,
) -> None:
    """A store predating the guard tables reads its memories, minus attachments."""
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    _drop_guard_tables(synthetic_store)
    assert not (_GUARD_TABLES & _committed_table_names(synthetic_store))

    page = search_memories(synthetic_store, "daily runs")
    claim = get_memory(synthetic_store, applied.memory_ids[0])

    assert [hit.memory.statement for hit in page.items] == [
        "The owner reports daily runs.",
        "The daily-runs figure is self-reported and not verified.",
    ]
    assert all(hit.guards == () for hit in page.items)
    assert claim.revision.statement == "The owner reports daily runs."
    assert claim.guards == ()
    assert claim.governs == ()


def test_noop_writer_heals_revocation_columns_and_advances_generation_once(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch committed column DDL escaping the writer generation boundary."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    _downgrade_to_pre_revocation_shape(synthetic_store)
    assert "revoked_at" not in _guard_link_columns(synthetic_store)
    assert "change_revision_guard_revocations" not in _committed_table_names(
        synthetic_store
    )
    generation_before = _audit_generation(synthetic_store)
    # Honest while unhealed: the shape is behind, and every retained link still
    # reads as the live link it is rather than vanishing from co-retrieval.
    assert get_store_status(synthetic_store).reindex_required is True
    page = search_memories(synthetic_store, "daily runs")
    assert [guard.statement for hit in page.items for guard in hit.guards] == [
        "The daily-runs figure is self-reported and not verified."
    ]

    with writer_session(synthetic_store) as connection:
        connection.execute("SELECT 1")

    assert {"revoked_at", "revoking_application_id"} <= _guard_link_columns(
        synthetic_store
    )
    assert _GUARD_TABLES <= _committed_table_names(synthetic_store)
    assert get_store_status(synthetic_store).reindex_required is False
    assert len(_guard_link_rows(synthetic_store)) == 1
    assert _audit_generation(synthetic_store) == generation_before + 1

    with writer_session(synthetic_store):
        pass

    assert _audit_generation(synthetic_store) == generation_before + 1


def test_revoking_a_link_stops_co_retrieval_and_keeps_the_row(
    synthetic_store: RuntimePaths,
) -> None:
    """The whole point: a mis-attached guard stops riding along, and stays visible."""
    clock = FakeClock()
    applied = two_source_linked_apply(synthetic_store, clock)
    claim_id, guard_id = applied.memory_ids
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    draft = _revoking_draft(
        synthetic_store, clock, _lineage_link(guard_lineage_id, claim_lineage_id)
    )
    assert len(draft.revoked_guard_links) == 1
    assert draft.revoked_guard_links[0].status == "active"
    assert "revoked_guard_links" in draft.digest_payload
    assert "guard_links" not in draft.digest_payload

    revoked = apply_ready(synthetic_store, draft)

    assert revoked.memory_ids == ()
    assert revoked.standing_guard_violations == ()
    assert _revocation_rows(synthetic_store) == [
        (guard_lineage_id, claim_lineage_id, True, revoked.application_id)
    ]
    claim = get_memory(synthetic_store, claim_id)
    guard = get_memory(synthetic_store, guard_id)
    assert claim.guards == ()
    assert guard.governs == ()
    page = search_memories(synthetic_store, "daily runs")
    assert len(page.items) == 2
    assert all(hit.guards == () for hit in page.items)


def test_revocation_clears_a_standing_violation(
    synthetic_store: RuntimePaths,
) -> None:
    """A mis-attached guard that is a standing violation is cleared by revoking it."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    capture_text(
        synthetic_store,
        name="hedge-copy.txt",
        body=HEDGE_BODY,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    standing = _revoking_draft(synthetic_store, clock, name="unrelated-note.txt")
    assert standing.revoked_guard_links == ()
    reported = apply_ready(synthetic_store, standing)
    assert len(reported.standing_guard_violations) == 1

    revoked = apply_ready(
        synthetic_store,
        _revoking_draft(
            synthetic_store,
            clock,
            _lineage_link(guard_lineage_id, claim_lineage_id),
            name="repair-note.txt",
        ),
    )

    assert revoked.standing_guard_violations == ()
    assert lint_guards(synthetic_store).standing_violations == ()


def test_carried_revocation_of_an_already_revoked_pair_stays_workable(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a parallel revocation permanently wedging a whole draft.

    A revocation that was valid when added stops naming a live link the
    moment any other applied revision revokes the same pair -- and one batch
    gets exactly one change set, so refusing the carried list on every edit
    made that batch's review permanently uneditable and unapplyable, with no
    operation able to remove the stale entry. A pair the Store already holds
    as revoked is a satisfied intent, not a mistake: edits proceed, apply
    proceeds, and the first revocation's stamp stays final.
    """
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    carried = _revoking_draft(
        synthetic_store,
        clock,
        _lineage_link(guard_lineage_id, claim_lineage_id),
        name="parallel-carried.txt",
    )

    first = apply_ready(
        synthetic_store,
        _revoking_draft(
            synthetic_store,
            clock,
            _lineage_link(guard_lineage_id, claim_lineage_id),
            name="parallel-winner.txt",
        ),
    )
    assert first.standing_guard_violations == ()

    def _revocation_stamp() -> tuple[object, object]:
        with _read_connection(synthetic_store) as (connection, _identity):
            row = connection.execute(
                "SELECT revoked_at, revoking_application_id FROM memory_guard_links "
                "WHERE guard_lineage_id = ? AND governed_lineage_id = ?",
                (guard_lineage_id, claim_lineage_id),
            ).fetchone()
        assert row is not None
        assert row[0] is not None
        return (row[0], row[1])

    stamped = _revocation_stamp()

    edited = edit_change_set(
        synthetic_store,
        carried.change_set_id,
        carried.revision_id,
        [
            SetSourceNoMemory(
                source_id=carried.source_decisions[0].source_id,
                reason="Synthetic reviewed decision: the link is already revoked.",
            )
        ],
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    assert edited.revoked_guard_links != ()

    applied = apply_ready(synthetic_store, edited)

    assert applied.standing_guard_violations == ()
    assert _revocation_stamp() == stamped
    assert lint_guards(synthetic_store).standing_violations == ()


def test_revocation_refuses_a_link_the_store_does_not_retain(
    synthetic_store: RuntimePaths,
) -> None:
    """Revoking a link that was never applied is a mistake worth reporting."""
    clock = FakeClock()
    _claim_id, claim_lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="claim.txt",
        body="The owner reports daily runs.\n",
        statement="The owner reports daily runs.",
        excerpt="The owner reports daily runs.",
    )
    _hedge_id, hedge_lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="hedge.txt",
        body=HEDGE_BODY,
        statement="The daily-runs figure is self-reported and not verified.",
        excerpt="self-reported and not verified",
        kind=MemoryKind.INSIGHT,
    )

    with pytest.raises(InvalidArgumentError) as raised:
        _revoking_draft(
            synthetic_store, clock, _lineage_link(hedge_lineage_id, claim_lineage_id)
        )

    details = raised.value.details
    assert details is not None
    assert details["guard_lineage_id"] == hedge_lineage_id
    assert details["governed_lineage_id"] == claim_lineage_id


def test_revocation_endpoint_and_duplicate_rules(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin unknown lineages, self-pairs, repeats, and add-and-revoke in one revision."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    link = _lineage_link(guard_lineage_id, claim_lineage_id)
    draft = _revoking_draft(synthetic_store, clock, link)

    with pytest.raises(InvalidArgumentError):
        _edit(synthetic_store, draft, RevokeGuardLink(link=link))
    with pytest.raises(InvalidArgumentError):
        _revoking_draft(
            synthetic_store,
            clock,
            _lineage_link(guard_lineage_id, "lin_does_not_exist"),
            name="unknown.txt",
        )
    with pytest.raises(InvalidArgumentError):
        _revoking_draft(
            synthetic_store,
            clock,
            _lineage_link(guard_lineage_id, guard_lineage_id),
            name="self.txt",
        )

    with pytest.raises(InvalidArgumentError) as raised:
        _edit(
            synthetic_store,
            draft,
            AddGuardLink(link=_lineage_link(guard_lineage_id, claim_lineage_id)),
        )

    details = raised.value.details
    assert details is not None
    assert details["guard_lineage_id"] == guard_lineage_id


def test_a_revoked_pair_cannot_be_re_added(synthetic_store: RuntimePaths) -> None:
    """Re-adding is refused loudly rather than ignored into a silent no-op."""
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    apply_ready(
        synthetic_store,
        _revoking_draft(
            synthetic_store, clock, _lineage_link(guard_lineage_id, claim_lineage_id)
        ),
    )
    relink_batch, relink_source = capture_text(
        synthetic_store,
        name="relink.txt",
        body="The hedge belongs on the daily-runs claim after all.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    relinked = ready_items(
        synthetic_store,
        relink_batch,
        (
            SetSourceNoMemory(
                source_id=relink_source.source_id,
                reason="Synthetic reviewed decision: this note only restores a link.",
            ),
            AddGuardLink(link=_lineage_link(guard_lineage_id, claim_lineage_id)),
        ),
    )

    with pytest.raises(InvalidArgumentError) as raised:
        apply_ready(synthetic_store, relinked)

    details = raised.value.details
    assert details is not None
    assert details["guard_lineage_id"] == guard_lineage_id
    assert details["governed_lineage_id"] == claim_lineage_id
    assert _revocation_rows(synthetic_store)[0][2] is True


def _second_guard_on(
    paths: RuntimePaths,
    clock: FakeClock,
    *,
    claim_lineage_id: str,
    name: str,
) -> ChangeSetView:
    """Draft one further guard attached to an existing claim, ready to apply."""
    statement = "The owner counts a rest day as a run day."
    batch_id, source = capture_text(
        paths,
        name=name,
        body=f"{statement}\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch_id,
        (
            single_item_edit(
                item_id="itm_second_guard",
                source=source,
                statement=statement,
                excerpt=statement,
            ),
        ),
    )
    assert isinstance(draft, ChangeSetView)
    return _edit(
        paths,
        draft,
        AddGuardLink(
            link=GuardLinkInput(
                guard_item_id="itm_second_guard",
                guard_lineage_id=None,
                governed_item_id=None,
                governed_lineage_id=claim_lineage_id,
            )
        ),
    )


def test_a_revoked_link_frees_its_per_lineage_cap_slot(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a revoked row still consuming the slot the cap counts.

    The name promises the cap, so the cap is what this drives. Counting rows
    either side of a revocation proves only that the row was stamped: the
    query it asserts on is the test's own, not the one `_reject_guard_link_
    overflow` runs, so a cap that counted revoked rows would leave it green
    while a claim stayed permanently full because of one mis-attachment.
    """
    monkeypatch.setattr(reviews, "MAX_GUARDS_PER_LINEAGE", 1)
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    assert _governed_link_counts(synthetic_store, claim_lineage_id) == (1, 1)

    # At the cap: one more guard on this claim is refused.
    with pytest.raises(InvalidArgumentError) as raised:
        apply_ready(
            synthetic_store,
            _second_guard_on(
                synthetic_store,
                clock,
                claim_lineage_id=claim_lineage_id,
                name="crowding.txt",
            ),
        )
    assert (raised.value.details or {})["governed_lineage_id"] == claim_lineage_id

    apply_ready(
        synthetic_store,
        _revoking_draft(
            synthetic_store, clock, _lineage_link(guard_lineage_id, claim_lineage_id)
        ),
    )
    assert _governed_link_counts(synthetic_store, claim_lineage_id) == (0, 1)

    # The revoked row is retained and no longer counted, so the slot is free.
    applied = apply_ready(
        synthetic_store,
        _second_guard_on(
            synthetic_store,
            clock,
            claim_lineage_id=claim_lineage_id,
            name="after-revocation.txt",
        ),
    )

    assert applied.standing_guard_violations == ()
    assert _governed_link_counts(synthetic_store, claim_lineage_id) == (1, 2)


def test_every_revocation_refusal_names_the_endpoint_it_could_not_resolve(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch one arm of the revocation family refusing without a locator.

    These validate after the per-edit dispatch loop, so none of them carries
    the ordinal that names which operation failed, and a revocation batch may
    hold up to `MAX_GUARD_LINKS` entries. Every other refusal in the family
    names an endpoint instead -- an opaque identifier the caller itself
    supplied. The arm reached when an endpoint resolves to no lineage at all --
    a draft item that opens a new one rather than correcting an existing one --
    named nothing, so an agent had to bisect the batch to find it.
    """
    clock = FakeClock()
    two_source_linked_apply(synthetic_store, clock)
    _guard_lineage_id, claim_lineage_id, _application_id = _guard_link_rows(
        synthetic_store
    )[0]
    batch_id, source = capture_text(
        synthetic_store,
        name="new-lineage-note.txt",
        body="A fresh claim that opens its own lineage.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    draft = ready_items(
        synthetic_store,
        batch_id,
        (
            single_item_edit(
                item_id="itm_new_lineage",
                source=source,
                statement="A fresh claim that opens its own lineage.",
                excerpt="A fresh claim that opens its own lineage.",
            ),
        ),
    )

    with pytest.raises(InvalidArgumentError) as unresolvable:
        _edit(
            synthetic_store,
            draft,
            RevokeGuardLink(
                link=GuardLinkInput(
                    guard_item_id="itm_new_lineage",
                    guard_lineage_id=None,
                    governed_item_id=None,
                    governed_lineage_id=claim_lineage_id,
                )
            ),
        )

    # The item exists in the draft, so this is not the missing-item arm: it is
    # the one where a real endpoint resolves to no lineage yet.
    assert "already holds" in str(unresolvable.value)
    assert (unresolvable.value.details or {}).get("client_item_id") == (
        "itm_new_lineage"
    )
