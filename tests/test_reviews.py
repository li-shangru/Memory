from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from typing import cast

import pytest
from sqlcipher3 import dbapi2 as sqlcipher  # type: ignore[import-untyped]  # no stubs

from memory import model
from memory.database import open_database
from memory.errors import (
    AmbiguousEvidenceError,
    IncompleteBatchError,
    InvalidArgumentError,
    InvalidEvidenceError,
    OwnerApprovalRequiredError,
    StaleRevisionError,
    WrongDigestError,
)
from memory.inbox import scan_inbox
from memory.keys import load_master_key
from memory.memories import get_memory
from memory.model import (
    AddItem,
    ChangeEdit,
    ChangeSetView,
    ClearSourceNoMemory,
    EvidenceInput,
    MemoryFields,
    MemoryKind,
    RejectItem,
    ReplaceItem,
    RestoreItem,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceSummary,
)
from memory.reviews import (
    OwnerApproval,
    _mint_owner_approval,
    approve_and_apply,
    canonical_digest,
    get_change_set,
)
from memory.reviews import (
    create_change_set as _create_change_set,
)
from memory.reviews import (
    edit_change_set as _edit_change_set,
)
from memory.runtime import (
    load_runtime_identity,
)
from memory.sources import list_sources


class FakeClock:
    def __init__(self, timestamp: float = 1_840_000_000.0) -> None:
        self.timestamp = timestamp

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


def create_change_set(
    paths: RuntimePaths,
    batch_id: str,
    *,
    adapter_origin: model.ChangeSetAdapterOrigin | None = None,
) -> ChangeSetView:
    """Exercise the production adapter boundary as an internal test workflow."""
    return _create_change_set(
        paths,
        batch_id,
        adapter_origin=(
            model.ChangeSetAdapterOrigin.SYSTEM
            if adapter_origin is None
            else adapter_origin
        ),
    )


def edit_change_set(
    paths: RuntimePaths,
    change_set_id: str,
    expected_revision_id: str,
    edits: Sequence[ChangeEdit],
    *,
    adapter_origin: model.ChangeSetAdapterOrigin | None = None,
) -> ChangeSetView:
    """Exercise the production adapter boundary as an internal test workflow."""
    return _edit_change_set(
        paths,
        change_set_id,
        expected_revision_id,
        edits,
        adapter_origin=(
            model.ChangeSetAdapterOrigin.SYSTEM
            if adapter_origin is None
            else adapter_origin
        ),
    )


def capture_mixed_batch(paths: RuntimePaths) -> tuple[str, tuple[SourceSummary, ...]]:
    (paths.inbox / "a-note.md").write_text(
        "Synthetic schedule: the lantern workshop meets on 2031-04-08.\n"
        "synthetic marker; synthetic marker.\n"
        "合成偏好：周末喜欢安静的陶艺课。\n",
        encoding="utf-8",
    )
    (paths.inbox / "b-image.png").write_bytes(b"\x89PNG synthetic mosaic")
    batch = scan_inbox(paths, sensitivity=Sensitivity.SENSITIVE, clock=FakeClock())
    return batch.batch_id, list_sources(paths).items


def delete_text_projection(paths: RuntimePaths, source: SourceSummary) -> None:
    """Delete only one disposable FTS row while retaining immutable text custody."""
    identity = load_runtime_identity(paths)
    connection = open_database(
        paths,
        load_master_key(identity),
        read_only=False,
    )
    try:
        retained = connection.execute(
            "SELECT s.media_type, b.utf8_text, b.sha256, b.original_bytes "
            "FROM sources AS s JOIN source_blobs AS b ON b.blob_id = s.blob_id "
            "WHERE s.source_id = ?",
            (source.source_id,),
        ).fetchone()
        assert retained is not None
        assert retained[0] == "text/markdown"
        assert retained[1] is not None
        assert retained[2] == source.blob_digest
        assert bytes(retained[3]).decode("utf-8") == retained[1]
        connection.execute(
            "DELETE FROM source_fts WHERE source_id = ?",
            (source.source_id,),
        )
        connection.commit()
        assert connection.execute(
            "SELECT count(*) FROM source_fts WHERE source_id = ?",
            (source.source_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def text_fields(
    statement: str = "The lantern workshop meets on 2031-04-08.",
) -> MemoryFields:
    return MemoryFields(
        kind=MemoryKind.EVENT,
        statement=statement,
        occurred_on="2031-04-08",
        valid_from=None,
        valid_to=None,
        tags=(" synthetic ", "calendar", "synthetic"),
        sensitivity=Sensitivity.SENSITIVE,
        target_lineage_id=None,
        expected_head_id=None,
    )


def test_canonical_digest_vector_preserves_nulls_unicode_and_ordinals() -> None:
    """Catch default JSON formatting, Unicode normalization, or reordered arrays."""
    payload = {
        "revision_id": "csr_vector",
        "batch_id": "bat_vector",
        "change_set_id": "chg_vector",
        "store_id": "0" * 32,
        "format": "memory.change-set-digest.v1",
        "items": [
            {
                "status": "active",
                "ordinal": 1,
                "item_id": "itm_beta",
                "target_lineage_id": None,
                "expected_head_id": None,
                "memory": {
                    "statement": "合成偏好 café",
                    "kind": "preference",
                    "occurred_on": None,
                    "valid_from": "2031-04",
                    "valid_to": None,
                    "tags": ["β", "alpha"],
                    "sensitivity": "sensitive",
                },
                "evidence": [
                    {
                        "source_level": None,
                        "excerpt": "合成偏好",
                        "char_end": 4,
                        "char_start": 0,
                        "mode": "text",
                        "blob_digest": "2" * 64,
                        "source_id": "src_b",
                        "ordinal": 0,
                    }
                ],
            }
        ],
        "source_decisions": [
            {
                "reason": "保留原文，不创建记忆",
                "state": "no_memory",
                "blob_digest": "1" * 64,
                "source_id": "src_a",
                "ordinal": 0,
            }
        ],
    }
    expected_bytes = (
        b'{"batch_id":"bat_vector","change_set_id":"chg_vector",'
        b'"format":"memory.change-set-digest.v1","items":[{"evidence":'
        b'[{"blob_digest":"2222222222222222222222222222222222222222222222222222222222222222",'
        b'"char_end":4,"char_start":0,"excerpt":"\xe5\x90\x88\xe6\x88\x90\xe5\x81\x8f\xe5\xa5\xbd",'
        b'"mode":"text","ordinal":0,"source_id":"src_b","source_level":null}],'
        b'"expected_head_id":null,"item_id":"itm_beta","memory":{"kind":"preference",'
        b'"occurred_on":null,"sensitivity":"sensitive","statement":"\xe5\x90\x88\xe6\x88\x90'
        b'\xe5\x81\x8f\xe5\xa5\xbd caf\xc3\xa9","tags":["\xce\xb2","alpha"],'
        b'"valid_from":"2031-04","valid_to":null},"ordinal":1,"status":"active",'
        b'"target_lineage_id":null}],"revision_id":"csr_vector","source_decisions":'
        b'[{"blob_digest":"1111111111111111111111111111111111111111111111111111111111111111",'
        b'"ordinal":0,"reason":"\xe4\xbf\x9d\xe7\x95\x99\xe5\x8e\x9f\xe6\x96\x87\xef\xbc\x8c'
        b'\xe4\xb8\x8d\xe5\x88\x9b\xe5\xbb\xba\xe8\xae\xb0\xe5\xbf\x86",'
        b'"source_id":"src_a","state":"no_memory"}],'
        b'"store_id":"00000000000000000000000000000000"}'
    )

    encoded, digest = canonical_digest(payload)

    assert encoded == expected_bytes
    assert digest == "bea63cf500ff7e6fb30093ce6110a9e8d59e30e559ea461a6dbde558b8893aab"


def test_one_change_set_is_idempotent_and_every_edit_changes_the_digest(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch multiple reviews per batch or mutable draft revisions."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources

    initial = create_change_set(synthetic_store, batch_id)
    repeated = create_change_set(synthetic_store, batch_id)
    added = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_lantern",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=binary_source.source_id,
                reason="Synthetic image contains no additional durable statement.",
            ),
        ),
    )
    replaced = edit_change_set(
        synthetic_store,
        added.change_set_id,
        added.revision_id,
        (
            ReplaceItem(
                item_id="itm_lantern",
                memory=text_fields("The lantern workshop is scheduled for 2031-04-08."),
                evidence=added.items[0].evidence,
            ),
        ),
    )
    rejected = edit_change_set(
        synthetic_store,
        replaced.change_set_id,
        replaced.revision_id,
        (RejectItem(item_id="itm_lantern"),),
    )
    restored = edit_change_set(
        synthetic_store,
        rejected.change_set_id,
        rejected.revision_id,
        (RestoreItem(item_id="itm_lantern"),),
    )

    assert initial == repeated
    assert initial.items == ()
    assert initial.source_decisions == ()
    assert (
        len(
            {
                initial.digest,
                added.digest,
                replaced.digest,
                rejected.digest,
                restored.digest,
            }
        )
        == 5
    )
    assert added.items[0].memory.tags == ("synthetic", "calendar")
    assert replaced.items[0].status == "active"
    assert rejected.items[0].status == "rejected"
    assert all(
        decision.source_id != text_source.source_id
        for decision in rejected.source_decisions
    )
    assert {decision.state for decision in restored.source_decisions} == {
        "used",
        "no_memory",
    }
    assert get_change_set(synthetic_store, initial.change_set_id) == restored

    with pytest.raises(StaleRevisionError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (ClearSourceNoMemory(source_id=binary_source.source_id),),
        )


def test_evidence_is_exact_unique_batch_bound_and_content_bounded(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch guessed excerpts, cross-batch evidence, or oversized model text."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)

    with pytest.raises(AmbiguousEvidenceError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (
                AddItem(
                    client_item_id="itm_ambiguous",
                    memory=text_fields(),
                    evidence=(
                        EvidenceInput(
                            source_id=text_source.source_id,
                            blob_digest=text_source.blob_digest,
                            excerpt="synthetic marker",
                        ),
                    ),
                ),
            ),
        )

    for evidence in (
        EvidenceInput(
            source_id=text_source.source_id,
            blob_digest="0" * 64,
            excerpt="the lantern workshop meets on 2031-04-08",
        ),
        EvidenceInput(
            source_id=text_source.source_id,
            blob_digest=text_source.blob_digest,
            excerpt="a statement absent from the source",
        ),
        EvidenceInput(
            source_id=binary_source.source_id,
            blob_digest=binary_source.blob_digest,
            excerpt="synthetic mosaic",
        ),
    ):
        with pytest.raises(InvalidEvidenceError):
            edit_change_set(
                synthetic_store,
                initial.change_set_id,
                initial.revision_id,
                (
                    AddItem(
                        client_item_id="itm_invalid",
                        memory=text_fields(),
                        evidence=(evidence,),
                    ),
                ),
            )

    with pytest.raises(InvalidArgumentError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (
                AddItem(
                    client_item_id="itm_large",
                    memory=text_fields("x" * (16 * 1024 + 1)),
                    evidence=(
                        EvidenceInput(
                            source_id=text_source.source_id,
                            blob_digest=text_source.blob_digest,
                            excerpt="the lantern workshop meets on 2031-04-08",
                        ),
                    ),
                ),
            ),
        )


def test_text_evidence_classification_survives_deleted_fts_projection(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch disposable FTS loss changing retained text into binary evidence."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    delete_text_projection(synthetic_store, text_source)

    with pytest.raises(InvalidEvidenceError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (
                AddItem(
                    client_item_id="itm_projection_source_level",
                    memory=text_fields(),
                    evidence=(
                        EvidenceInput(
                            source_id=text_source.source_id,
                            blob_digest=text_source.blob_digest,
                            source_level=True,
                        ),
                    ),
                ),
            ),
        )

    excerpt = "the lantern workshop meets on 2031-04-08"
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_projection_text",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt=excerpt,
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=binary_source.source_id,
                reason="Synthetic image has no separate durable statement.",
            ),
        ),
    )
    locator = ready.items[0].evidence[0]
    assert locator.mode == "text"
    assert locator.excerpt == excerpt
    assert locator.char_start is not None
    assert locator.char_end == locator.char_start + len(excerpt)

    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    applied = approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )
    detail = get_memory(synthetic_store, applied.memory_ids[0])
    assert detail.evidence == (locator,)


def test_projection_loss_preserves_genuine_binary_source_level_evidence(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch text projection state controlling genuine binary evidence behavior."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    delete_text_projection(synthetic_store, text_source)

    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_projection_text",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
            AddItem(
                client_item_id="itm_projection_binary",
                memory=MemoryFields(
                    kind=MemoryKind.INSIGHT,
                    statement="A synthetic mosaic artifact was retained.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("synthetic", "artifact"),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=binary_source.source_id,
                        blob_digest=binary_source.blob_digest,
                        source_level=True,
                    ),
                ),
            ),
        ),
    )
    assert [item.evidence[0].mode for item in ready.items] == [
        "text",
        "source_level",
    ]

    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    applied = approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )
    details = [
        get_memory(synthetic_store, memory_id) for memory_id in applied.memory_ids
    ]
    assert [detail.evidence[0].mode for detail in details] == [
        "text",
        "source_level",
    ]
    assert details[1].evidence[0].source_level is True


@pytest.mark.parametrize("field", ("statement", "tag", "excerpt", "reason"))
def test_review_text_fields_reject_lone_surrogates_as_invalid_argument(
    synthetic_store: RuntimePaths,
    field: str,
) -> None:
    """Catch model-writable review text escaping strict UTF-8 validation."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, _binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    invalid = "\ud800"
    edits: tuple[ChangeEdit, ...]
    if field == "reason":
        edits = (
            SetSourceNoMemory(
                source_id=text_source.source_id,
                reason=invalid,
            ),
        )
    else:
        memory = text_fields(
            invalid if field == "statement" else text_fields().statement
        )
        if field == "tag":
            memory = replace(memory, tags=(invalid,))
        edits = (
            AddItem(
                client_item_id="itm_invalid_utf8",
                memory=memory,
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt=(
                            invalid
                            if field == "excerpt"
                            else "the lantern workshop meets on 2031-04-08"
                        ),
                    ),
                ),
            ),
        )

    with pytest.raises(InvalidArgumentError):
        edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            edits,
        )


def test_incomplete_draft_is_viewable_but_not_approvable_and_mapping_is_not_approval(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch incomplete application or model-shaped approval capability injection."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, _binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    incomplete = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_incomplete",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(TypeError):
        OwnerApproval(  # type: ignore[call-arg]
            adapter="mcp_elicitation",
            approved=True,
        )
    with pytest.raises(OwnerApprovalRequiredError):
        approve_and_apply(
            synthetic_store,
            incomplete.change_set_id,
            incomplete.revision_id,
            incomplete.digest,
            approval={"approved": True},  # type: ignore[arg-type]
        )

    approval = _mint_owner_approval(
        synthetic_store,
        incomplete.change_set_id,
        incomplete.revision_id,
        incomplete.digest,
        adapter="mcp_elicitation",
    )
    with pytest.raises(IncompleteBatchError):
        approve_and_apply(
            synthetic_store,
            incomplete.change_set_id,
            incomplete.revision_id,
            incomplete.digest,
            approval=approval,
        )

    # The rollback restores the Store but never un-spends the capability, so a
    # retry must ask the owner again rather than reuse the consumed approval.
    with pytest.raises(OwnerApprovalRequiredError) as spent:
        approve_and_apply(
            synthetic_store,
            incomplete.change_set_id,
            incomplete.revision_id,
            incomplete.digest,
            approval=approval,
        )
    assert "already used" in str(spent.value)


def test_atomic_apply_revalidates_digest_and_evidence_and_exact_retry_is_idempotent(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch partial writes, stale evidence acceptance, or repeated approval prompts."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_event",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
            AddItem(
                client_item_id="itm_binary",
                memory=MemoryFields(
                    kind=MemoryKind.INSIGHT,
                    statement="A synthetic mosaic source was retained.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("artifact",),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=binary_source.source_id,
                        blob_digest=binary_source.blob_digest,
                        source_level=True,
                    ),
                ),
            ),
        ),
    )

    wrong = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    with pytest.raises(WrongDigestError):
        approve_and_apply(
            synthetic_store,
            ready.change_set_id,
            ready.revision_id,
            "0" * 64,
            approval=wrong,
        )

    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    applied = approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )
    replayed = approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=None,
    )

    assert len(applied.memory_ids) == 2
    assert applied.idempotent_replay is False
    assert replayed == applied.__class__(
        application_id=applied.application_id,
        change_set_id=applied.change_set_id,
        revision_id=applied.revision_id,
        memory_ids=applied.memory_ids,
        idempotent_replay=True,
        standing_guard_violations=applied.standing_guard_violations,
    )
    assert create_change_set(synthetic_store, batch_id).state == "applied"

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        assert connection.execute("SELECT count(*) FROM applications").fetchone() == (
            1,
        )
        assert connection.execute("SELECT count(*) FROM approvals").fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM memory_revisions"
        ).fetchone() == (2,)
    finally:
        connection.close()


def test_apply_refuses_changed_source_bytes_without_any_semantic_rows(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch apply trusting draft locators instead of revalidating immutable evidence."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_tamper",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=binary_source.source_id,
                reason="Synthetic image has no additional durable statement.",
            ),
        ),
    )
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=False,
    )
    try:
        connection.execute(
            "UPDATE source_blobs SET original_bytes = zeroblob(byte_length) "
            "WHERE sha256 = ?",
            (text_source.blob_digest,),
        )
        connection.commit()
    finally:
        connection.close()
    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )

    with pytest.raises(InvalidEvidenceError):
        approve_and_apply(
            synthetic_store,
            ready.change_set_id,
            ready.revision_id,
            ready.digest,
            approval=approval,
        )

    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT (SELECT count(*) FROM approvals), "
            "(SELECT count(*) FROM applications), "
            "(SELECT count(*) FROM memory_revisions)"
        ).fetchone()
        assert counts == (0, 0, 0)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "damage",
    ("sealed_count", "source_binding", "membership_count", "membership_ordinal"),
)
def test_apply_refuses_a_damaged_sealed_roster_without_semantic_rows(
    synthetic_store: RuntimePaths,
    damage: str,
) -> None:
    """Catch approval trusting a truncated or structurally inconsistent roster."""
    (synthetic_store.inbox / "synthetic-roster.txt").write_text(
        "Synthetic roster source has no proposed durable memory.\n",
        encoding="utf-8",
    )
    batch = scan_inbox(
        synthetic_store,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    source = list_sources(synthetic_store).items[0]
    initial = create_change_set(synthetic_store, batch.batch_id)
    ready = (
        initial
        if damage == "membership_count"
        else edit_change_set(
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (
                SetSourceNoMemory(
                    source_id=source.source_id,
                    reason="The synthetic source has no durable memory proposal.",
                ),
            ),
        )
    )
    other_batch_id: str | None = None
    if damage == "source_binding":
        (synthetic_store.inbox / "synthetic-other-roster.txt").write_text(
            "Synthetic unrelated roster source.\n",
            encoding="utf-8",
        )
        other_batch_id = scan_inbox(
            synthetic_store,
            sensitivity=Sensitivity.NORMAL,
            clock=FakeClock(),
        ).batch_id

    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=False,
    )
    try:
        if damage == "sealed_count":
            connection.execute(
                "UPDATE inbox_batches SET source_count = 2 WHERE batch_id = ?",
                (batch.batch_id,),
            )
        elif damage == "source_binding":
            assert other_batch_id is not None
            connection.execute(
                "UPDATE sources SET batch_id = ? WHERE source_id = ?",
                (other_batch_id, source.source_id),
            )
        elif damage == "membership_count":
            connection.execute(
                "DELETE FROM inbox_batch_sources WHERE batch_id = ?",
                (batch.batch_id,),
            )
        else:
            connection.execute(
                "UPDATE inbox_batch_sources SET ordinal = 1 WHERE batch_id = ?",
                (batch.batch_id,),
            )
        connection.commit()
    finally:
        connection.close()

    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    with pytest.raises(IncompleteBatchError):
        approve_and_apply(
            synthetic_store,
            ready.change_set_id,
            ready.revision_id,
            ready.digest,
            approval=approval,
        )

    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=True,
    )
    try:
        counts = connection.execute(
            "SELECT (SELECT count(*) FROM approvals), "
            "(SELECT count(*) FROM applications), "
            "(SELECT count(*) FROM memory_revisions), "
            "(SELECT count(*) FROM current_memory_heads), "
            "(SELECT count(*) FROM memory_fts)"
        ).fetchone()
        assert counts == (0, 0, 0, 0, 0)
    finally:
        connection.close()


def test_change_set_json_payload_is_exactly_the_stored_revision(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch digesting a projection that differs from the owner-visible diff."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_unicode",
                memory=text_fields("合成偏好：周末喜欢安静的陶艺课。"),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="合成偏好：周末喜欢安静的陶艺课。",
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=binary_source.source_id,
                reason="No durable textual interpretation is proposed.",
            ),
        ),
    )

    encoded = json.dumps(
        ready.digest_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    # The digest payload is shape-free JSON by design, so reaching into it has
    # to restate the shape the digest vector above already pins.
    digested_items = cast("list[dict[str, object]]", ready.digest_payload["items"])
    digested_memory = cast("dict[str, object]", digested_items[0]["memory"])

    assert ready.digest_payload["format"] == "memory.change-set-digest.v1"
    assert canonical_digest(ready.digest_payload) == (encoded, ready.digest)
    assert digested_memory["statement"] == "合成偏好：周末喜欢安静的陶艺课。"


def test_pre_guard_revision_digests_are_unchanged_by_guard_support(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch guard-link support making every pre-guard stored revision unloadable."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, _binary_source = sources
    initial = create_change_set(synthetic_store, batch_id)
    draft = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_linkless",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
        ),
    )

    reloaded = get_change_set(synthetic_store, draft.change_set_id)

    assert reloaded.digest == draft.digest
    assert reloaded.digest_payload == draft.digest_payload
    assert "guard_links" not in reloaded.digest_payload
    assert reloaded.guard_links == ()


def test_change_set_adapter_origin_is_required_valid_immutable_and_not_digested(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin trusted-adapter assignment, idempotency, and digest exclusion."""
    batch_id, sources = capture_mixed_batch(synthetic_store)
    text_source, _binary_source = sources

    with pytest.raises(TypeError):
        _create_change_set(synthetic_store, batch_id)  # type: ignore[call-arg]
    with pytest.raises(InvalidArgumentError):
        _create_change_set(
            synthetic_store,
            batch_id,
            adapter_origin="mcp",  # type: ignore[arg-type]
        )

    initial = _create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.MCP,
    )
    repeated = _create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    assert repeated == initial
    assert initial.adapter_origin is model.ChangeSetAdapterOrigin.MCP
    assert "adapter_origin" not in initial.digest_payload
    assert canonical_digest(initial.digest_payload)[1] == initial.digest

    with pytest.raises(TypeError):
        _edit_change_set(  # type: ignore[call-arg]
            synthetic_store,
            initial.change_set_id,
            initial.revision_id,
            (SetSourceNoMemory(text_source.source_id, "synthetic exclusion"),),
        )
    edited = _edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (SetSourceNoMemory(text_source.source_id, "synthetic exclusion"),),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    assert edited.adapter_origin is model.ChangeSetAdapterOrigin.OWNER_UI
    assert get_change_set(synthetic_store, initial.change_set_id) == edited
    assert "adapter_origin" not in edited.digest_payload
    assert canonical_digest(edited.digest_payload)[1] == edited.digest


def test_unknown_stored_change_set_adapter_origin_fails_closed(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch corrupted provenance being converted to untrusted free-form text."""
    batch_id, _sources = capture_mixed_batch(synthetic_store)
    created = _create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store,
        load_master_key(identity),
        read_only=False,
    )
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE change_set_revisions SET adapter_origin = 'unknown' "
            "WHERE revision_id = ?",
            (created.revision_id,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(InvalidArgumentError):
        get_change_set(synthetic_store, created.change_set_id)


def test_removed_interactive_cli_adapter_cannot_mint_owner_approval(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the superseded textual capability adapter returning to production."""
    batch_id, _sources = capture_mixed_batch(synthetic_store)
    created = create_change_set(synthetic_store, batch_id)

    with pytest.raises(InvalidArgumentError):
        _mint_owner_approval(
            synthetic_store,
            created.change_set_id,
            created.revision_id,
            created.digest,
            adapter="interactive_cli",
        )


def complete_review(paths: RuntimePaths) -> ChangeSetView:
    """Seal one complete synthetic revision that accounts for every source."""
    batch_id, sources = capture_mixed_batch(paths)
    text_source, binary_source = sources
    created = create_change_set(paths, batch_id)
    return edit_change_set(
        paths,
        created.change_set_id,
        created.revision_id,
        (
            AddItem(
                client_item_id="itm_adapter_case",
                memory=text_fields(),
                evidence=(
                    EvidenceInput(
                        source_id=text_source.source_id,
                        blob_digest=text_source.blob_digest,
                        excerpt="the lantern workshop meets on 2031-04-08",
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=binary_source.source_id,
                reason="Synthetic binary capture records no canonical memory.",
            ),
        ),
    )


@pytest.mark.parametrize(
    "adapter",
    ["mcp_elicitation", "local_owner_ui", "os_owner_presence_cli"],
)
def test_every_direct_owner_adapter_applies_and_records_exact_provenance(
    synthetic_store: RuntimePaths,
    adapter: str,
) -> None:
    """Catch the OS-backed UI and CLI adapters being unable to apply a review."""
    ready = complete_review(synthetic_store)
    approval = _mint_owner_approval(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter=adapter,
    )

    application = approve_and_apply(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval,
    )

    assert application.idempotent_replay is False
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store, load_master_key(identity), read_only=True
    )
    try:
        stored = connection.execute(
            "SELECT adapter FROM approvals WHERE change_set_id = ?",
            (ready.change_set_id,),
        ).fetchone()
    finally:
        connection.close()
    assert stored == (adapter,)


def test_approvals_schema_refuses_every_unapproved_adapter_value(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the schema accepting an approval adapter outside the exact set."""
    ready = complete_review(synthetic_store)
    identity = load_runtime_identity(synthetic_store)
    connection = open_database(
        synthetic_store, load_master_key(identity), read_only=False
    )

    try:
        for adapter in ("interactive_cli", "browser_form", ""):
            # The schema's CHECK constraint is what refuses the adapter, so a
            # blind `Exception` here would also pass on a typo in the SQL.
            with pytest.raises(sqlcipher.IntegrityError):
                connection.execute(
                    "INSERT INTO approvals (approval_id, change_set_id, revision_id, "
                    "digest, approved_at, adapter) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        f"apr_synthetic_{adapter}",
                        ready.change_set_id,
                        ready.revision_id,
                        ready.digest,
                        1,
                        adapter,
                    ),
                )
    finally:
        connection.close()


def test_a_failed_edit_names_itself_inside_a_long_batch(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a batch refusal an agent can only resolve by bisecting.

    One `change_set.edit` carries up to 256 operations. A refusal that names
    only its code leaves the caller no way to find which one failed except to
    resubmit smaller batches, which is both slow and a second chance to get the
    review wrong. The ordinal and the caller's own identifier are content-free
    and already bounded, so there is no reason to withhold them.
    """
    from synthetic import FakeClock, capture_batch, single_item_edit

    from memory.errors import AmbiguousEvidenceError

    batch_id, sources = capture_batch(
        synthetic_store,
        {"repeat.md": "The lantern repeats. The lantern repeats.\n"},
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    source = sources["repeat.md"]
    view = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    good = [
        single_item_edit(
            item_id=f"itm_ok_{index}",
            source=source,
            statement=f"Synthetic claim {index}.",
            excerpt="The lantern repeats. The lantern repeats.",
        )
        for index in range(4)
    ]
    ambiguous = single_item_edit(
        item_id="itm_ambiguous",
        source=source,
        statement="A claim whose excerpt occurs twice.",
        excerpt="The lantern repeats.",
    )

    with pytest.raises(AmbiguousEvidenceError) as refusal:
        edit_change_set(
            synthetic_store,
            view.change_set_id,
            view.revision_id,
            (*good, ambiguous),
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )

    details = refusal.value.details or {}
    assert details.get("ordinal") == 4
    assert details.get("client_item_id") == "itm_ambiguous"


def test_no_post_dispatch_refusal_leaves_the_caller_without_a_locator() -> None:
    """Catch a refusal outside the ordinal wrapper that names nothing.

    `edit_change_set` attaches an ordinal and the caller's own identifier to
    anything raised inside its dispatch loop. The validators that run after the
    loop are outside that wrapper, so each has to name its own subject or the
    caller is told only that something in a 256-operation edit was wrong.

    Reading the source is what covers a member no fixture happens to exercise,
    which is how this family shipped three bare arms across three separate
    fixes. `_validate_active_targets` keeps one exemption: a stored status
    outside active/rejected is an internal invariant no caller input reaches.
    """
    import ast
    import inspect

    from memory import reviews

    post_dispatch = (
        "_validate_active_targets",
        "_validate_endpoints",
        "_validate_guard_links",
        "_validate_guard_revocations",
        "_reject_resolved_conflict",
        "_reject_guard_link_overflow",
    )
    exempt = {"draft item status is invalid"}

    def bare_refusals(name: str, tree: ast.AST, after: int = 0) -> list[str]:
        found: list[str] = []
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or (call.lineno or 0) <= after:
                continue
            callee = call.func.id if isinstance(call.func, ast.Name) else None
            if callee is None or not callee.endswith("Error"):
                continue
            if any(keyword.arg == "details" for keyword in call.keywords):
                continue
            if call.args and isinstance(call.args[0], ast.Constant):
                message = call.args[0].value
                if isinstance(message, str) and message not in exempt:
                    found.append(f"{name}: {message}")
        return found

    bare: list[str] = []
    for name in post_dispatch:
        function = getattr(reviews, name)
        bare.extend(
            bare_refusals(name, ast.parse(inspect.getsource(function).lstrip()))
        )

    # `edit_change_set` raises after its own dispatch loop as well, and those
    # refusals are outside the wrapper for the same reason the helpers are.
    # Scoping this to helpers alone let the contested-source locator be
    # stripped with the whole suite still green. The boundary is the dispatch
    # loop itself: everything above it is either pre-flight or inside the
    # wrapper, and only what follows it needs to name its own subject.
    caller = ast.parse(inspect.getsource(reviews.edit_change_set).lstrip())
    dispatch = min(
        (node for node in ast.walk(caller) if isinstance(node, ast.For)),
        key=lambda node: node.lineno,
    )
    bare.extend(
        bare_refusals("edit_change_set", caller, after=dispatch.end_lineno or 0)
    )

    # Add to `exempt` deliberately, with the reason, never in passing.
    assert bare == [], bare


def test_a_date_is_accepted_only_in_the_digits_the_wire_declares() -> None:
    """Catch a date admitted in digits the envelope's own pattern rejects.

    `occurred_on`, `valid_from`, and `valid_to` are the only wire fields
    carrying a `pattern` whose value the caller chooses rather than the Store.
    JSON Schema fixes `pattern` to ECMA-262, where `\\d` is exactly `[0-9]`;
    Python's `re` reads `\\d` as the whole Nd category and `int()` parses it,
    so an Arabic-Indic or mathematical-digit date passed every domain check and
    was stored and re-emitted verbatim, under a declaration that rejects it.

    Every other bound in this contract is declared in characters and enforced
    in UTF-8 bytes, which can only round the safe way. This one rounded the
    other way.
    """
    import pytest

    from memory.errors import InvalidArgumentError
    from memory.reviews import _date_bounds, _validate_partial_date

    assert _validate_partial_date("2031-04-08", "occurred_on") == "2031-04-08"
    assert _validate_partial_date("2031-04", "valid_from") == "2031-04"
    assert _validate_partial_date("2031", "valid_to") == "2031"

    for rejected in ("٢٠٢٥-٠١-٠٩", "𝟚𝟘𝟚𝟝", "٢٠٢٥", "２０３１-０４"):
        with pytest.raises(InvalidArgumentError):
            _validate_partial_date(rejected, "occurred_on")

    # A revision an older release accepted still reads. `_date_bounds` runs
    # against values already stored and asserts its own match, so narrowing it
    # too would turn such a revision into a crash on an ordinary search rather
    # than a value the owner can supersede.
    assert _date_bounds("٢٠٢٥-٠١-٠٩") == _date_bounds("2025-01-09")
