from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from synthetic import FakeClock as SharedFakeClock
from synthetic import store_one_memory, two_source_linked_apply

from memory import model
from memory.database import Connection, writer_session
from memory.errors import (
    InvalidArgumentError,
    InvalidEvidenceError,
    NotFoundError,
    StaleCursorError,
    WrongDigestError,
)
from memory.inbox import ScanPolicy, scan_inbox
from memory.model import (
    AddItem,
    ApplicationResult,
    ChangeSetView,
    ClearSourceNoMemory,
    EvidenceInput,
    EvidenceLocator,
    MemoryFields,
    MemoryFilters,
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
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.runtime import initialize_runtime, resolve_runtime
from memory.sources import list_sources
from memory.ui.service import (
    BoundAuditReader,
    OwnerApplicationService,
    _edit_target_fingerprint,
)
from memory.ui.view_models import (
    OWNER_REVIEW_ITEM_PAGE_LIMIT,
    OwnerPage,
    OwnerReviewAddEditTarget,
    OwnerReviewItemEditTarget,
    OwnerReviewSourceEditTarget,
)


class FakeClock(SharedFakeClock):
    """The shared clock, started at the epoch this suite's captures assume."""

    def __init__(self, timestamp: float = 1_930_000_000.0) -> None:
        super().__init__(timestamp)


@dataclass(frozen=True, slots=True)
class SyntheticAppliedStore:
    paths: RuntimePaths
    batch_id: str
    source_ids: tuple[str, ...]
    change_set_id: str
    revision_ids: tuple[str, ...]
    digest: str
    application_id: str
    memory_ids: tuple[str, ...]


@dataclass
class _OwnerSourceSelectStats:
    queries: list[str]


class _ObservedOwnerSourceConnection:
    """Record the real owner-source result shape without changing the query."""

    def __init__(
        self,
        connection: Connection,
        stats: _OwnerSourceSelectStats,
    ) -> None:
        self._connection = connection
        self._stats = stats

    def execute(
        self,
        sql: str,
        parameters: tuple[str | bytes | int | float | None, ...] = (),
    ) -> object:
        normalized = " ".join(sql.casefold().split())
        if normalized.startswith("select s.rowid as sort_id") and (
            "join inbox_batch_sources as membership" in normalized
        ):
            self._stats.queries.append(normalized)
        return self._connection.execute(sql, parameters)


def _capture(
    paths: RuntimePaths,
    files: dict[str, bytes],
    *,
    sensitivity: Sensitivity = Sensitivity.RESTRICTED,
    clock: FakeClock | None = None,
) -> tuple[str, tuple[SourceSummary, ...]]:
    before = {source.source_id for source in list_sources(paths, limit=100).items}
    for name, body in files.items():
        (paths.inbox / name).write_bytes(body)
    batch = scan_inbox(
        paths,
        sensitivity=sensitivity,
        clock=FakeClock() if clock is None else clock,
        policy=ScanPolicy(settle_seconds=0),
    )
    captured = tuple(
        source
        for source in list_sources(paths, limit=100).items
        if source.source_id not in before
    )
    return batch.batch_id, captured


def _fields(
    statement: str,
    *,
    target_lineage_id: str | None = None,
    expected_head_id: str | None = None,
    sensitivity: Sensitivity = Sensitivity.RESTRICTED,
) -> MemoryFields:
    return MemoryFields(
        kind=MemoryKind.FACT,
        statement=statement,
        occurred_on=None,
        valid_from=None,
        valid_to=None,
        tags=("synthetic",),
        sensitivity=sensitivity,
        target_lineage_id=target_lineage_id,
        expected_head_id=expected_head_id,
    )


def _apply(paths: RuntimePaths, review: ChangeSetView) -> ApplicationResult:
    approval = _mint_owner_approval(
        paths,
        review.change_set_id,
        review.revision_id,
        review.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        review.change_set_id,
        review.revision_id,
        review.digest,
        approval,
    )


def _make_applied_store(
    paths: RuntimePaths,
    *,
    no_memory_only: bool,
) -> SyntheticAppliedStore:
    batch_id, sources = _capture(
        paths,
        {
            "a-synthetic-note.md": "合成记录：琥珀灯在周六点亮。\n".encode(),
            "b-synthetic-image.png": b"\x89PNG\x00synthetic-owner-service",
        },
    )
    initial = create_change_set(
        paths,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    if no_memory_only:
        ready = edit_change_set(
            paths,
            initial.change_set_id,
            initial.revision_id,
            tuple(
                SetSourceNoMemory(
                    source_id=source.source_id,
                    reason="Synthetic source retained without canonical memory.",
                )
                for source in sources
            ),
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )
        revision_ids: tuple[str, ...] = (initial.revision_id, ready.revision_id)
    else:
        text_source, binary_source = sources
        proposed = edit_change_set(
            paths,
            initial.change_set_id,
            initial.revision_id,
            (
                AddItem(
                    client_item_id="synthetic-item",
                    memory=_fields("The synthetic amber lamp is lit on Saturday."),
                    evidence=(
                        EvidenceInput(
                            source_id=text_source.source_id,
                            blob_digest=text_source.blob_digest,
                            excerpt="琥珀灯在周六点亮",
                        ),
                    ),
                ),
                SetSourceNoMemory(
                    source_id=binary_source.source_id,
                    reason="Synthetic image adds no separate memory.",
                ),
            ),
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )
        ready = edit_change_set(
            paths,
            proposed.change_set_id,
            proposed.revision_id,
            (
                ReplaceItem(
                    item_id="synthetic-item",
                    memory=_fields("The synthetic amber lamp is lit each Saturday."),
                    evidence=proposed.items[0].evidence,
                ),
            ),
            adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
        )
        revision_ids = (
            initial.revision_id,
            proposed.revision_id,
            ready.revision_id,
        )
    applied = _apply(paths, ready)
    return SyntheticAppliedStore(
        paths=paths,
        batch_id=batch_id,
        source_ids=tuple(source.source_id for source in sources),
        change_set_id=ready.change_set_id,
        revision_ids=revision_ids,
        digest=ready.digest,
        application_id=applied.application_id,
        memory_ids=applied.memory_ids,
    )


def _collect_pages[T](
    fetch: Callable[[str | None, int], OwnerPage[T]],
    *,
    limit: int,
) -> list[T]:
    items: list[T] = []
    cursor: str | None = None
    while True:
        page = fetch(cursor, limit)
        items.extend(page.items)
        if not page.has_more:
            return items
        assert page.next_cursor is not None
        cursor = page.next_cursor


@pytest.mark.parametrize(
    "reader_name",
    ("source_list", "blob_captures", "source_detail", "batch_detail", "audit"),
)
def test_owner_metadata_source_selects_do_not_return_authoritative_text(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    reader_name: str,
) -> None:
    """Catch any metadata reader materializing retained text it cannot return."""
    from memory.ui import service as service_module

    body = "Synthetic bounded owner summary. 合成的有界来源摘要。".encode()
    batch_id, sources = _capture(
        synthetic_store,
        {
            "a-synthetic-bounded.txt": body,
            "b-synthetic-bounded.txt": body,
        },
    )
    service = OwnerApplicationService(synthetic_store)
    blob_id = service.list_sources(None, 1).items[0].blob_id
    audit_reader = service.bind_audit(service.begin_audit_snapshot())
    stats = _OwnerSourceSelectStats(queries=[])
    original_query_session = service_module._query_session

    @contextmanager
    def observed_query_session(
        paths: RuntimePaths,
    ) -> Iterator[tuple[Connection, model.StoreIdentity]]:
        with original_query_session(paths) as (connection, identity):
            yield (
                cast(
                    "Connection",
                    _ObservedOwnerSourceConnection(connection, stats),
                ),
                identity,
            )

    monkeypatch.setattr(service_module, "_query_session", observed_query_session)
    if reader_name == "source_list":
        service.list_sources(None, 2)
    elif reader_name == "blob_captures":
        service.list_blob_captures(blob_id, None, 2)
    elif reader_name == "source_detail":
        service.get_source_detail(sources[0].source_id)
    elif reader_name == "batch_detail":
        service.get_batch(batch_id)
    else:
        audit_reader.list_sources(None, 2)

    assert len(stats.queries) == 1
    query = stats.queries[0]
    assert "b.utf8_text as authoritative_utf8_text" not in query
    assert "typeof(b.utf8_text) != 'null' as retained_utf8_text" in query


def test_owner_service_reaches_no_memory_only_application(
    synthetic_store: RuntimePaths,
) -> None:
    synthetic_applied_store = _make_applied_store(
        synthetic_store,
        no_memory_only=True,
    )
    service = OwnerApplicationService(synthetic_applied_store.paths)
    batch = service.get_batch(synthetic_applied_store.batch_id)
    assert batch.summary.application_id is not None
    application = service.get_application(batch.summary.application_id)
    assert application.memory_revision_ids == ()
    assert (
        application.application.change_set_id == synthetic_applied_store.change_set_id
    )
    assert service.get_approval(application.approval.approval_id) == application
    assert application.approval.digest == synthetic_applied_store.digest


def test_owner_service_traverses_complete_applied_provenance(
    synthetic_store: RuntimePaths,
) -> None:
    applied = _make_applied_store(synthetic_store, no_memory_only=False)
    service = OwnerApplicationService(applied.paths)

    status = service.get_status()
    batch = service.get_batch(applied.batch_id)
    source = service.get_source_detail(applied.source_ids[0])
    chunk = service.read_source(source.summary.source_id, None, 8)
    revisions = _collect_pages(
        lambda cursor, limit: service.list_change_set_revisions(
            applied.change_set_id,
            cursor,
            limit,
        ),
        limit=1,
    )
    application = service.get_application(applied.application_id)
    memory = service.get_memory_revision(applied.memory_ids[0])
    lineage = service.list_memory_lineage(
        memory.summary.revision.lineage_id,
        None,
        1,
    )
    backlinks = service.list_source_evidence_links(
        source.summary.source_id,
        None,
        1,
    )

    assert status.runtime_mode is model.RuntimeMode.PERSONAL
    assert status.store.source_count == 2
    assert batch.summary.change_set_id == applied.change_set_id
    assert batch.summary.application_id == applied.application_id
    assert len(batch.sources) == 2
    assert source.summary.origin is model.SourceCaptureOrigin.INBOX
    assert source.summary.batch_id == applied.batch_id
    assert source.retained_utf8_text is True
    assert chunk.text is not None
    assert [revision.lifecycle for revision in revisions] == [
        "superseded",
        "superseded",
        "applied",
    ]
    assert revisions[-1].adapter_origin is model.ChangeSetAdapterOrigin.OWNER_UI
    assert application.memory_revision_ids == applied.memory_ids
    assert memory.change_set_id == applied.change_set_id
    assert memory.change_set_revision_id == applied.revision_ids[-1]
    assert memory.approval_id == application.approval.approval_id
    assert lineage.items == (memory.summary,)
    assert backlinks.items[0].memory_revision_id == applied.memory_ids[0]
    assert backlinks.items[0].locator == memory.evidence[0]
    assert service.get_approval(application.approval.approval_id) == application


def test_owner_pages_bind_limits_filters_store_and_high_water(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    body = b"Synthetic shared blob page marker."
    for index in range(101):
        (synthetic_store.inbox / f"capture-{index:03}.txt").write_bytes(body)
    clock = FakeClock()
    scan_inbox(
        synthetic_store,
        clock=clock,
        policy=ScanPolicy(settle_seconds=0),
    )
    scan_inbox(
        synthetic_store,
        clock=clock,
        policy=ScanPolicy(settle_seconds=0),
    )
    service = OwnerApplicationService(synthetic_store)

    one = service.list_sources(None, 1)
    fifty = service.list_sources(None, 50)
    hundred = service.list_sources(None, 100)
    assert len(one.items) == 1 and one.has_more
    assert len(fifty.items) == 50 and fifty.has_more
    assert len(hundred.items) == 100 and hundred.has_more
    assert hundred.next_cursor is not None
    assert len(service.list_sources(hundred.next_cursor, 100).items) == 1

    blob_id = one.items[0].blob_id
    captures = _collect_pages(
        lambda cursor, limit: service.list_blob_captures(blob_id, cursor, limit),
        limit=100,
    )
    assert len(captures) == 101
    assert {capture.blob_id for capture in captures} == {blob_id}

    search = service.search_sources("shared blob", None, 1)
    assert search.next_cursor is not None
    with pytest.raises(StaleCursorError):
        service.search_sources("different query", search.next_cursor, 1)
    with pytest.raises(StaleCursorError):
        service.list_sources("opaque-but-invalid", 1)
    # The owner reads share the kernel's one page validator, so the ceiling
    # moved with it when the wire bound went from 100 to 500.
    for invalid_limit in (0, 501):
        with pytest.raises(InvalidArgumentError):
            service.list_sources(None, invalid_limit)

    foreign_paths = resolve_runtime(tmp_path / "synthetic-foreign-owner-store")
    initialize_runtime(foreign_paths, mode=model.RuntimeMode.PERSONAL)
    foreign_service = OwnerApplicationService(foreign_paths)
    assert one.next_cursor is not None
    with pytest.raises(StaleCursorError):
        foreign_service.list_sources(one.next_cursor, 1)

    for lookup in (
        lambda: service.get_batch("bat_ffffffffffffffffffffffffffffffff"),
        lambda: service.get_source_detail("src_ffffffffffffffffffffffffffffffff"),
        lambda: service.get_memory_revision("mem_ffffffffffffffffffffffffffffffff"),
        lambda: service.get_application("app_ffffffffffffffffffffffffffffffff"),
        lambda: service.get_approval("apr_ffffffffffffffffffffffffffffffff"),
    ):
        with pytest.raises(NotFoundError):
            lookup()


def test_review_manifest_is_compact_and_every_large_section_is_paged(
    synthetic_store: RuntimePaths,
) -> None:
    for index in range(64):
        (synthetic_store.inbox / f"binary-{index:02}.bin").write_bytes(
            b"\xffsynthetic-bounded-review"
        )
    batch = scan_inbox(
        synthetic_store,
        clock=FakeClock(),
        policy=ScanPolicy(settle_seconds=0),
    )
    sources = list_sources(synthetic_store, limit=100).items
    initial = create_change_set(
        synthetic_store,
        batch.batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    edits = []
    for index in range(256):
        source = sources[index if index < len(sources) else 0]
        edits.append(
            AddItem(
                client_item_id=f"synthetic-item-{index:03}",
                memory=_fields(f"Synthetic bounded proposal {index}."),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        source_level=True,
                    ),
                ),
            )
        )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        tuple(edits),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    service = OwnerApplicationService(synthetic_store)
    manifest = service.get_review_manifest(ready.change_set_id)

    assert len(manifest.item_roster) == 256
    assert len(manifest.source_roster) == 64
    assert manifest.validation_state == "valid"
    assert manifest.item_roster[0].statement_preview == "Synthetic bounded proposal 0."
    assert manifest.item_roster[0].statement_elided is False
    items = _collect_pages(
        lambda cursor, limit: service.list_review_items(
            ready.change_set_id,
            ready.revision_id,
            cursor,
            limit,
        ),
        limit=OWNER_REVIEW_ITEM_PAGE_LIMIT,
    )
    decisions = _collect_pages(
        lambda cursor, limit: service.list_review_source_decisions(
            ready.change_set_id,
            ready.revision_id,
            cursor,
            limit,
        ),
        limit=100,
    )
    assert len(items) == 256
    assert len(decisions) == 64
    assert all(decision.coverage == "used" for decision in decisions)
    assert (
        service.get_review_item(
            ready.change_set_id,
            ready.revision_id,
            ready.items[0].item_id,
        )
        == items[0]
    )
    with pytest.raises(NotFoundError):
        service.get_review_item(
            ready.change_set_id,
            ready.revision_id,
            "synthetic-item-missing",
        )
    with pytest.raises(InvalidArgumentError):
        service.list_review_items(
            ready.change_set_id,
            ready.revision_id,
            None,
            OWNER_REVIEW_ITEM_PAGE_LIMIT + 1,
        )

    first = service.list_review_items(
        ready.change_set_id,
        ready.revision_id,
        None,
        1,
    )
    assert first.next_cursor is not None
    edit_change_set(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        (
            ReplaceItem(
                item_id=ready.items[-1].item_id,
                memory=_fields("Synthetic unrelated successor revision."),
                evidence=ready.items[-1].evidence,
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    with pytest.raises(StaleCursorError):
        service.list_review_items(
            ready.change_set_id,
            ready.revision_id,
            first.next_cursor,
            1,
        )


def test_review_validation_lifecycle_and_blockers_reconcile(
    synthetic_store: RuntimePaths,
) -> None:
    batch_id, sources = _capture(
        synthetic_store,
        {
            "a-review.bin": b"\xffsynthetic-a",
            "b-review.bin": b"\xffsynthetic-b",
        },
    )
    initial = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    service = OwnerApplicationService(synthetic_store)
    blocked = service.get_review_manifest(initial.change_set_id)
    first_blockers = service.list_review_blockers(
        initial.change_set_id,
        initial.revision_id,
        None,
        1,
    )
    assert blocked.validation_state == "blocked"
    assert blocked.blocker_count == 2
    assert first_blockers.items[0].code == "unaccounted_source"
    assert first_blockers.next_cursor is not None

    partial = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            SetSourceNoMemory(
                source_id=sources[0].source_id,
                reason="Synthetic first source decision.",
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    with pytest.raises(StaleCursorError):
        service.list_review_blockers(
            initial.change_set_id,
            initial.revision_id,
            first_blockers.next_cursor,
            1,
        )
    complete = edit_change_set(
        synthetic_store,
        partial.change_set_id,
        partial.revision_id,
        (
            SetSourceNoMemory(
                source_id=sources[1].source_id,
                reason="Synthetic second source decision.",
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    successor = edit_change_set(
        synthetic_store,
        complete.change_set_id,
        complete.revision_id,
        (
            SetSourceNoMemory(
                source_id=sources[1].source_id,
                reason="Synthetic reviewed second source decision.",
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    applied = _apply(synthetic_store, successor)

    manifests = {
        revision_id: service.get_review_manifest(
            initial.change_set_id,
            revision_id,
        )
        for revision_id in (
            initial.revision_id,
            partial.revision_id,
            complete.revision_id,
            successor.revision_id,
        )
    }
    assert manifests[initial.revision_id].revision.lifecycle == "superseded"
    assert manifests[initial.revision_id].validation_state == "blocked"
    assert manifests[partial.revision_id].validation_state == "blocked"
    assert manifests[complete.revision_id].revision.lifecycle == "superseded"
    assert manifests[complete.revision_id].validation_state == "valid"
    assert manifests[successor.revision_id].revision.lifecycle == "applied"
    assert manifests[successor.revision_id].validation_state == "valid"
    assert applied.memory_ids == ()
    assert not any(
        manifest.revision.lifecycle == "current_draft"
        and manifest.validation_state == "valid"
        for manifest in manifests.values()
    )


def test_review_blockers_share_apply_sensitivity_validation(
    synthetic_store: RuntimePaths,
) -> None:
    body = b"Synthetic sensitivity propagation evidence."
    batch_id, sources = _capture(
        synthetic_store,
        {"normal-source.txt": body},
        sensitivity=Sensitivity.NORMAL,
    )
    source = sources[0]
    initial = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="synthetic-sensitivity-item",
                memory=_fields(
                    "Synthetic sensitivity propagation statement.",
                    sensitivity=Sensitivity.NORMAL,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt=body.decode(),
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    _capture(
        synthetic_store,
        {"restricted-recapture.txt": body},
        sensitivity=Sensitivity.RESTRICTED,
    )

    service = OwnerApplicationService(synthetic_store)
    manifest = service.get_review_manifest(ready.change_set_id, ready.revision_id)
    blockers = service.list_review_blockers(
        ready.change_set_id,
        ready.revision_id,
        None,
        10,
    )

    assert manifest.validation_state == "blocked"
    assert manifest.blocker_count == 1
    assert len(blockers.items) == 1
    assert blockers.items[0].code == "invalid_review"
    assert blockers.items[0].item_id == "synthetic-sensitivity-item"
    with pytest.raises(InvalidEvidenceError):
        _apply(synthetic_store, ready)


def test_review_edit_target_is_bounded_in_maximum_review(
    synthetic_store: RuntimePaths,
) -> None:
    for index in range(64):
        (synthetic_store.inbox / f"target-{index:02}.bin").write_bytes(
            b"\xffsynthetic-maximum-target"
        )
    batch = scan_inbox(
        synthetic_store,
        clock=FakeClock(),
        policy=ScanPolicy(settle_seconds=0),
    )
    sources = list_sources(synthetic_store, limit=100).items
    initial = create_change_set(
        synthetic_store,
        batch.batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        tuple(
            AddItem(
                client_item_id=f"synthetic-target-item-{index:03}",
                memory=_fields(f"Synthetic target proposal {index}."),
                evidence=(
                    EvidenceInput(
                        source_id=sources[
                            index if index < len(sources) else 0
                        ].source_id,
                        blob_digest=sources[
                            index if index < len(sources) else 0
                        ].blob_digest,
                        source_level=True,
                    ),
                ),
            )
            for index in range(256)
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    with writer_session(synthetic_store) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE change_items SET kind = 'synthetic-invalid-kind' "
            "WHERE revision_id = ? AND item_id = ?",
            (ready.revision_id, ready.items[-1].item_id),
        )
        connection.execute(
            "UPDATE batch_source_decisions SET state = 'synthetic-invalid-state' "
            "WHERE revision_id = ? AND source_id = ?",
            (ready.revision_id, sources[-1].source_id),
        )

    service = OwnerApplicationService(synthetic_store)
    item_edit = ReplaceItem(
        item_id=ready.items[0].item_id,
        memory=_fields("Synthetic bounded replacement."),
        evidence=ready.items[0].evidence,
    )
    source_edit = ClearSourceNoMemory(source_id=sources[0].source_id)
    add_edit = AddItem(
        client_item_id="synthetic-bounded-add",
        memory=_fields("Synthetic bounded addition."),
        evidence=(
            EvidenceInput(
                source_id=sources[0].source_id,
                blob_digest=sources[0].blob_digest,
                source_level=True,
            ),
            EvidenceInput(
                source_id=sources[1].source_id,
                blob_digest=sources[1].blob_digest,
                source_level=True,
            ),
        ),
    )

    item_target = service.get_review_edit_target(
        ready.change_set_id, ready.revision_id, ready.digest, item_edit
    )
    source_target = service.get_review_edit_target(
        ready.change_set_id, ready.revision_id, ready.digest, source_edit
    )
    add_target = service.get_review_edit_target(
        ready.change_set_id, ready.revision_id, ready.digest, add_edit
    )

    assert isinstance(item_target.state, OwnerReviewItemEditTarget)
    assert item_target.state.item_id == ready.items[0].item_id
    assert isinstance(source_target.state, OwnerReviewSourceEditTarget)
    assert source_target.state.source_id == sources[0].source_id
    assert isinstance(add_target.state, OwnerReviewAddEditTarget)
    assert tuple(
        source.source_id for source in add_target.state.referenced_sources
    ) == (sources[0].source_id, sources[1].source_id)


def test_review_edit_target_reads_only_exact_typed_state(
    synthetic_store: RuntimePaths,
) -> None:
    batch_id, sources = _capture(
        synthetic_store,
        {
            "a-target.bin": b"\xffsynthetic-target-a",
            "b-target.bin": b"\xffsynthetic-target-b",
            "c-target.bin": b"\xffsynthetic-target-c",
        },
    )
    initial = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="synthetic-existing-item",
                memory=_fields("Synthetic existing proposal."),
                evidence=(
                    EvidenceInput(
                        source_id=sources[0].source_id,
                        blob_digest=sources[0].blob_digest,
                        source_level=True,
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=sources[1].source_id,
                reason="Synthetic reviewed no-memory decision.",
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    service = OwnerApplicationService(synthetic_store)
    replace_edit = ReplaceItem(
        item_id="synthetic-existing-item",
        memory=_fields("Synthetic replacement proposal."),
        evidence=ready.items[0].evidence,
    )
    item_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        replace_edit,
    )
    rejected_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        RejectItem(item_id="synthetic-existing-item"),
    )
    restored_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        RestoreItem(item_id="synthetic-existing-item"),
    )
    no_memory_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        ClearSourceNoMemory(source_id=sources[1].source_id),
    )
    unaccounted_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        ClearSourceNoMemory(source_id=sources[2].source_id),
    )
    set_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        SetSourceNoMemory(
            source_id=sources[2].source_id,
            reason="Synthetic proposed source decision.",
        ),
    )
    add_edit = AddItem(
        client_item_id="synthetic-new-item",
        memory=_fields("Synthetic new proposal."),
        evidence=(
            EvidenceInput(
                source_id=sources[2].source_id,
                blob_digest=sources[2].blob_digest,
                source_level=True,
            ),
            EvidenceInput(
                source_id=sources[0].source_id,
                blob_digest=sources[0].blob_digest,
                source_level=True,
            ),
            EvidenceInput(
                source_id=sources[2].source_id,
                blob_digest=sources[2].blob_digest,
                source_level=True,
            ),
        ),
    )
    add_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        add_edit,
    )
    present_target = service.get_review_edit_target(
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        AddItem(
            client_item_id="synthetic-existing-item",
            memory=_fields("Synthetic duplicate proposal."),
            evidence=add_edit.evidence,
        ),
    )

    assert isinstance(item_target.state, OwnerReviewItemEditTarget)
    assert item_target.state.memory == ready.items[0].memory
    assert item_target.state.evidence == ready.items[0].evidence
    assert isinstance(rejected_target.state, OwnerReviewItemEditTarget)
    assert isinstance(restored_target.state, OwnerReviewItemEditTarget)
    assert isinstance(no_memory_target.state, OwnerReviewSourceEditTarget)
    assert no_memory_target.state.coverage == "no_memory"
    assert no_memory_target.state.reason == "Synthetic reviewed no-memory decision."
    assert isinstance(unaccounted_target.state, OwnerReviewSourceEditTarget)
    assert unaccounted_target.state.coverage == "unaccounted"
    assert isinstance(set_target.state, OwnerReviewSourceEditTarget)
    assert isinstance(add_target.state, OwnerReviewAddEditTarget)
    assert add_target.state.generated_item_id_absent is True
    assert [item.source_id for item in add_target.state.referenced_sources] == [
        sources[2].source_id,
        sources[0].source_id,
    ]
    assert isinstance(present_target.state, OwnerReviewAddEditTarget)
    assert present_target.state.generated_item_id_absent is False
    assert (
        len(
            {
                item_target.state_fingerprint,
                rejected_target.state_fingerprint,
                restored_target.state_fingerprint,
                no_memory_target.state_fingerprint,
                unaccounted_target.state_fingerprint,
                set_target.state_fingerprint,
                add_target.state_fingerprint,
                present_target.state_fingerprint,
            }
        )
        == 8
    )

    unrelated = edit_change_set(
        synthetic_store,
        ready.change_set_id,
        ready.revision_id,
        (
            SetSourceNoMemory(
                source_id=sources[2].source_id,
                reason="Synthetic unrelated source decision.",
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    unchanged_item_target = service.get_review_edit_target(
        unrelated.change_set_id,
        unrelated.revision_id,
        unrelated.digest,
        replace_edit,
    )
    assert unchanged_item_target.state_fingerprint == item_target.state_fingerprint
    changed = edit_change_set(
        synthetic_store,
        unrelated.change_set_id,
        unrelated.revision_id,
        (RejectItem(item_id="synthetic-existing-item"),),
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    changed_item_target = service.get_review_edit_target(
        changed.change_set_id,
        changed.revision_id,
        changed.digest,
        replace_edit,
    )
    assert changed_item_target.state_fingerprint != item_target.state_fingerprint

    with pytest.raises(WrongDigestError) as mismatch:
        service.get_review_edit_target(
            ready.change_set_id,
            ready.revision_id,
            "0" * 64,
            replace_edit,
        )
    assert mismatch.value.details is None
    assert ready.digest not in str(mismatch.value)
    with pytest.raises(NotFoundError):
        service.get_review_edit_target(
            ready.change_set_id,
            ready.revision_id,
            ready.digest,
            RejectItem(item_id="synthetic-missing-item"),
        )


def _fingerprint_item_state() -> OwnerReviewItemEditTarget:
    return OwnerReviewItemEditTarget(
        item_id="synthetic-item-a",
        ordinal=7,
        status="active",
        memory=MemoryFields(
            kind=MemoryKind.EVENT,
            statement="Synthetic fingerprint statement.",
            occurred_on="2026-01-02",
            valid_from="2026-01-03",
            valid_to="2026-01-04",
            tags=("synthetic", "fingerprint"),
            sensitivity=Sensitivity.SENSITIVE,
            target_lineage_id="synthetic-lineage-a",
            expected_head_id="synthetic-head-a",
        ),
        evidence=(
            EvidenceLocator(
                ordinal=0,
                source_id="synthetic-source-a",
                blob_digest="ab" * 32,
                mode="text",
                char_start=0,
                char_end=10,
                excerpt="Synthetic.",
                source_level=None,
            ),
            EvidenceLocator(
                ordinal=1,
                source_id="synthetic-source-b",
                blob_digest="cd" * 32,
                mode="text",
                char_start=11,
                char_end=21,
                excerpt="Fingerprint.",
                source_level=None,
            ),
        ),
    )


def _mutate_item_state(
    state: OwnerReviewItemEditTarget,
    dimension: str,
) -> OwnerReviewItemEditTarget:
    if dimension == "item_id":
        return replace(state, item_id="synthetic-item-b")
    if dimension == "ordinal":
        return replace(state, ordinal=8)
    if dimension == "status":
        return replace(state, status="rejected")
    # Each dimension names one field at runtime, so the replacement values span
    # every field type these dataclasses declare.
    memory_changes: dict[str, Any] = {
        "memory_kind": MemoryKind.FACT,
        "memory_statement": "Changed synthetic fingerprint statement.",
        "memory_occurred_on": "2026-02-02",
        "memory_valid_from": "2026-02-03",
        "memory_valid_to": "2026-02-04",
        "memory_tags": ("fingerprint", "synthetic"),
        "memory_sensitivity": Sensitivity.RESTRICTED,
        "memory_target_lineage_id": "synthetic-lineage-b",
        "memory_expected_head_id": "synthetic-head-b",
    }
    if dimension in memory_changes:
        field_name = dimension.removeprefix("memory_")
        return replace(
            state,
            memory=replace(state.memory, **{field_name: memory_changes[dimension]}),
        )
    if dimension == "evidence_order":
        return replace(state, evidence=tuple(reversed(state.evidence)))
    if dimension == "evidence_count":
        return replace(state, evidence=state.evidence[:1])
    evidence_changes: dict[str, Any] = {
        "evidence_ordinal": 2,
        "evidence_source_id": "synthetic-source-c",
        "evidence_blob_digest": "ef" * 32,
        "evidence_mode": "source_level",
        "evidence_char_start": 1,
        "evidence_char_end": 9,
        "evidence_excerpt": "Changed.",
        "evidence_source_level": True,
    }
    if dimension in evidence_changes:
        field_name = dimension.removeprefix("evidence_")
        changed = replace(
            state.evidence[0], **{field_name: evidence_changes[dimension]}
        )
        return replace(state, evidence=(changed, state.evidence[1]))
    raise AssertionError(f"unknown item fingerprint dimension: {dimension}")


@pytest.mark.parametrize(
    "dimension",
    (
        "item_id",
        "ordinal",
        "status",
        "memory_kind",
        "memory_statement",
        "memory_occurred_on",
        "memory_valid_from",
        "memory_valid_to",
        "memory_tags",
        "memory_sensitivity",
        "memory_target_lineage_id",
        "memory_expected_head_id",
        "evidence_order",
        "evidence_count",
        "evidence_ordinal",
        "evidence_source_id",
        "evidence_blob_digest",
        "evidence_mode",
        "evidence_char_start",
        "evidence_char_end",
        "evidence_excerpt",
        "evidence_source_level",
    ),
)
def test_item_edit_target_fingerprint_covers_each_state_dimension(
    dimension: str,
) -> None:
    state = _fingerprint_item_state()
    edit = ReplaceItem(
        item_id=state.item_id,
        memory=state.memory,
        evidence=state.evidence,
    )

    assert _edit_target_fingerprint(
        "synthetic-store", "synthetic-change-set", edit, state
    ) != _edit_target_fingerprint(
        "synthetic-store",
        "synthetic-change-set",
        edit,
        _mutate_item_state(state, dimension),
    )


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    (
        ("source_id", "synthetic-source-b"),
        ("blob_digest", "cd" * 32),
        ("coverage", "unaccounted"),
        ("reason", "Changed synthetic reason."),
    ),
)
def test_source_edit_target_fingerprint_covers_each_state_dimension(
    field_name: str,
    changed_value: str,
) -> None:
    state = OwnerReviewSourceEditTarget(
        source_id="synthetic-source-a",
        blob_digest="ab" * 32,
        coverage="no_memory",
        reason="Synthetic reason.",
    )
    edit = ClearSourceNoMemory(source_id=state.source_id)
    # The field is chosen by name at runtime, so `replace` cannot be checked.
    change: dict[str, Any] = {field_name: changed_value}

    assert _edit_target_fingerprint(
        "synthetic-store", "synthetic-change-set", edit, state
    ) != _edit_target_fingerprint(
        "synthetic-store",
        "synthetic-change-set",
        edit,
        replace(state, **change),
    )


def _fingerprint_add_state() -> OwnerReviewAddEditTarget:
    return OwnerReviewAddEditTarget(
        generated_item_id="synthetic-generated-a",
        generated_item_id_absent=True,
        referenced_sources=(
            OwnerReviewSourceEditTarget(
                source_id="synthetic-source-a",
                blob_digest="ab" * 32,
                coverage="used",
                reason=None,
            ),
            OwnerReviewSourceEditTarget(
                source_id="synthetic-source-b",
                blob_digest="cd" * 32,
                coverage="no_memory",
                reason="Synthetic reference reason.",
            ),
        ),
    )


def _mutate_add_state(
    state: OwnerReviewAddEditTarget,
    dimension: str,
) -> OwnerReviewAddEditTarget:
    if dimension == "generated_item_id":
        return replace(state, generated_item_id="synthetic-generated-b")
    if dimension == "generated_item_id_absent":
        return replace(state, generated_item_id_absent=False)
    if dimension == "reference_order":
        return replace(
            state, referenced_sources=tuple(reversed(state.referenced_sources))
        )
    if dimension == "reference_count":
        return replace(state, referenced_sources=state.referenced_sources[:1])
    # As above: the field is chosen by name, so `replace` cannot be checked here.
    reference_changes: dict[str, Any] = {
        "reference_source_id": "synthetic-source-c",
        "reference_blob_digest": "ef" * 32,
        "reference_coverage": "unaccounted",
        "reference_reason": "Changed synthetic reference reason.",
    }
    if dimension in reference_changes:
        field_name = dimension.removeprefix("reference_")
        changed = replace(
            state.referenced_sources[0],
            **{field_name: reference_changes[dimension]},
        )
        return replace(
            state,
            referenced_sources=(changed, state.referenced_sources[1]),
        )
    raise AssertionError(f"unknown add fingerprint dimension: {dimension}")


@pytest.mark.parametrize(
    "dimension",
    (
        "generated_item_id",
        "generated_item_id_absent",
        "reference_order",
        "reference_count",
        "reference_source_id",
        "reference_blob_digest",
        "reference_coverage",
        "reference_reason",
    ),
)
def test_add_edit_target_fingerprint_covers_each_state_dimension(
    dimension: str,
) -> None:
    state = _fingerprint_add_state()
    edit = AddItem(
        client_item_id=state.generated_item_id,
        memory=_fields("Synthetic add fingerprint statement."),
        evidence=tuple(
            EvidenceInput(
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                source_level=True,
            )
            for source in state.referenced_sources
        ),
    )

    assert _edit_target_fingerprint(
        "synthetic-store", "synthetic-change-set", edit, state
    ) != _edit_target_fingerprint(
        "synthetic-store",
        "synthetic-change-set",
        edit,
        _mutate_add_state(state, dimension),
    )


def test_evidence_item_edit_target_has_canonical_fingerprint_vector() -> None:
    state = OwnerReviewItemEditTarget(
        item_id="itm_22222222222222222222222222222222",
        ordinal=5,
        status="active",
        memory=MemoryFields(
            kind=MemoryKind.PREFERENCE,
            statement="Synthetic preference with retained evidence.",
            occurred_on="2032-05",
            valid_from="2032-05-01",
            valid_to="2032-12",
            tags=("synthetic", "ordered"),
            sensitivity=Sensitivity.SENSITIVE,
            target_lineage_id="lin_33333333333333333333333333333333",
            expected_head_id="mem_44444444444444444444444444444444",
        ),
        evidence=(
            EvidenceLocator(
                ordinal=7,
                source_id="src_55555555555555555555555555555555",
                blob_digest="ab" * 32,
                mode="text",
                char_start=4,
                char_end=21,
                excerpt="retained evidence",
                source_level=None,
            ),
        ),
    )
    edit = RejectItem(item_id=state.item_id)

    assert (
        _edit_target_fingerprint(
            "0123456789abcdef0123456789abcdef",
            "chg_11111111111111111111111111111111",
            edit,
            state,
        )
        == "7913f5dee03f0f4b1e0577e8ec5049abfa3bb8bc33b32451a191302a26ca9172"
    )


def test_review_edit_target_fingerprint_has_canonical_golden_vector() -> None:
    state = OwnerReviewSourceEditTarget(
        source_id="src_22222222222222222222222222222222",
        blob_digest="ab" * 32,
        coverage="no_memory",
        reason="Prior synthetic reason.",
    )
    edit = SetSourceNoMemory(
        source_id="src_22222222222222222222222222222222",
        reason="Synthetic reason.",
    )

    assert (
        _edit_target_fingerprint(
            "0123456789abcdef0123456789abcdef",
            "chg_11111111111111111111111111111111",
            edit,
            state,
        )
        == "08a0c43b80aa45faabe2ab61b112d688d5abbf558c46d3975ce45543f3a1fa63"
    )


def test_owner_source_read_uses_authoritative_blob_and_reports_projection_gap(
    synthetic_store: RuntimePaths,
) -> None:
    body = "合成权威来源：蓝色纸灯。\n".encode()
    _batch_id, sources = _capture(
        synthetic_store,
        {"synthetic-authoritative.md": body},
    )
    source = sources[0]
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "UPDATE source_fts SET utf8_text = ? WHERE source_id = ?",
            ("Synthetic corrupt projection.", source.source_id),
        )

    service = OwnerApplicationService(synthetic_store)
    detail = service.get_source_detail(source.source_id)
    chunks = []
    cursor = None
    while True:
        chunk = service.read_source(source.source_id, cursor, 5)
        chunks.append(chunk)
        if chunk.complete:
            break
        cursor = chunk.next_cursor
    coverage = service.search_sources("纸灯", None, 10).coverage

    assert "".join(chunk.text or "" for chunk in chunks).encode() == body
    assert detail.summary.expected_searchable is True
    assert detail.summary.indexed_for_search is False
    assert coverage.expected_searchable_captures == 1
    assert coverage.indexed_expected_captures == 0
    assert coverage.missing_expected_rows == 1
    assert coverage.unexpected_or_duplicate_rows == 1


def test_inbox_status_counts_only_descriptor_safe_visible_regular_entries(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (synthetic_store.inbox / "synthetic-visible.txt").write_text(
        "Synthetic staged entry.\n",
        encoding="utf-8",
    )
    (synthetic_store.inbox / "synthetic-directory").mkdir()
    (synthetic_store.inbox / "synthetic-symlink").symlink_to(
        synthetic_store.inbox / "synthetic-visible.txt"
    )
    service = OwnerApplicationService(synthetic_store)
    assert service.get_status().inbox.staged_visible_entry_count == 1

    # The scan lists the staged directory through the os module, so patching it
    # here is the same patch memory.inbox sees.
    real_listdir = os.listdir
    replaced = False

    def replace_after_list(descriptor: int) -> list[str]:
        nonlocal replaced
        entries = real_listdir(descriptor)
        if not replaced:
            replaced = True
            old_inbox = synthetic_store.root / "synthetic-replaced-inbox"
            synthetic_store.inbox.rename(old_inbox)
            synthetic_store.inbox.mkdir(mode=0o700)
        return entries

    monkeypatch.setattr(os, "listdir", replace_after_list)
    with pytest.raises(InvalidArgumentError):
        service.get_status()


def test_audit_snapshot_reconciles_counts_and_stales_on_every_mutation(
    synthetic_store: RuntimePaths,
) -> None:
    for index in range(3):
        (synthetic_store.inbox / f"synthetic-link-{index}").symlink_to(
            synthetic_store.inbox / "missing-synthetic-target"
        )
    for index in range(2):
        (synthetic_store.inbox / f"synthetic-dir-{index}").mkdir()
    applied = _make_applied_store(synthetic_store, no_memory_only=True)
    service = OwnerApplicationService(synthetic_store)
    detail = service.get_batch(applied.batch_id)
    snapshot_one = service.begin_audit_snapshot()
    snapshot_two = service.begin_audit_snapshot()
    reader_one = service.bind_audit(snapshot_one)
    reader_two = service.bind_audit(snapshot_two)

    assert isinstance(reader_one, BoundAuditReader)
    assert snapshot_one.counts.batch_issue_row_count == 2
    assert snapshot_one.counts.batch_issue_occurrence_count == 5
    assert detail.summary.issue_row_count == 2
    assert detail.summary.issue_occurrence_count == 5
    assert sorted(issue.occurrence_count for issue in detail.issues) == [2, 3]
    audit_index = reader_one.get_index()
    assert audit_index.snapshot is snapshot_one
    assert audit_index.integrity_capability == "unavailable"

    page = reader_one.list_sources(None, 1)
    assert page.next_cursor is not None
    with pytest.raises(StaleCursorError):
        reader_two.list_sources(page.next_cursor, 1)

    with writer_session(synthetic_store) as connection:
        connection.execute(
            "DELETE FROM source_fts WHERE source_id = ?",
            (applied.source_ids[0],),
        )
    for stale_call in (
        lambda: reader_one.list_sources(page.next_cursor, 1),
        lambda: reader_one.get_batch(applied.batch_id),
        lambda: reader_one.get_application(applied.application_id),
        reader_two.get_index,
    ):
        with pytest.raises(StaleCursorError):
            stale_call()

    fresh = service.bind_audit(service.begin_audit_snapshot())
    _capture(
        synthetic_store,
        {"synthetic-later.txt": b"Synthetic later authoritative mutation."},
    )
    with pytest.raises(StaleCursorError):
        fresh.list_batches(None, 1)


def test_audit_bind_rejects_foreign_or_forged_snapshot(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    service = OwnerApplicationService(synthetic_store)
    snapshot = service.begin_audit_snapshot()
    with pytest.raises(TypeError):
        # The private field name is not a constructor keyword, which is the
        # point: the reader cannot be built outside service.bind_audit.
        BoundAuditReader(  # type: ignore[call-arg]
            _paths=synthetic_store,
            snapshot=snapshot,
        )
    foreign_paths = resolve_runtime(tmp_path / "synthetic-audit-foreign")
    initialize_runtime(foreign_paths, mode=model.RuntimeMode.PERSONAL)
    foreign_service = OwnerApplicationService(foreign_paths)

    with pytest.raises(StaleCursorError):
        foreign_service.bind_audit(snapshot)
    forged = type(snapshot)(
        store_id=snapshot.store_id,
        generation=snapshot.generation,
        high_water_marks=tuple(
            (name, value + 1 if name == "sources" else value)
            for name, value in snapshot.high_water_marks
        ),
        counts=snapshot.counts,
        projection_coverage=snapshot.projection_coverage,
    )
    with pytest.raises(StaleCursorError):
        service.bind_audit(forged)


def test_owner_memory_page_counts_current_heads_by_kind(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the kind facet counting historical revisions or dropping a kind."""
    clock = FakeClock()
    service = OwnerApplicationService(synthetic_store)
    assert service.list_memories(None, 10, MemoryFilters()).kind_counts == (
        ("fact", 0),
        ("event", 0),
        ("preference", 0),
        ("relation", 0),
        ("insight", 0),
    )

    for index, kind in enumerate((MemoryKind.FACT, MemoryKind.FACT, MemoryKind.EVENT)):
        store_one_memory(
            synthetic_store,
            clock=clock,
            name=f"facet-{index}.md",
            body=f"Synthetic facet body {index}.\n",
            statement=f"Synthetic facet statement {index}.",
            excerpt=f"Synthetic facet body {index}.",
            kind=kind,
        )
    correction_target, lineage_id = store_one_memory(
        synthetic_store,
        clock=clock,
        name="facet-superseded.md",
        body="Synthetic facet body superseded.\n",
        statement="Synthetic facet statement superseded.",
        excerpt="Synthetic facet body superseded.",
        kind=MemoryKind.INSIGHT,
    )
    _batch_id, sources = _capture(
        synthetic_store,
        {"facet-correction.md": b"Synthetic facet correction body.\n"},
        clock=clock,
    )
    initial = create_change_set(
        synthetic_store,
        _batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="facet-correction-item",
                memory=MemoryFields(
                    kind=MemoryKind.RELATION,
                    statement="Synthetic facet statement corrected.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("synthetic",),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=lineage_id,
                    expected_head_id=correction_target,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=sources[0].source_id,
                        blob_digest=sources[0].blob_digest,
                        excerpt="Synthetic facet correction body.",
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    _apply(synthetic_store, ready)

    # The superseded insight is history, so only its relation head is counted.
    assert service.list_memories(None, 10, MemoryFilters()).kind_counts == (
        ("fact", 2),
        ("event", 1),
        ("preference", 0),
        ("relation", 1),
        ("insight", 0),
    )
    filtered = service.search_memories(
        "facet",
        MemoryFilters(kinds=(MemoryKind.EVENT,)),
        None,
        10,
    )
    assert len(filtered.items) == 1
    assert filtered.kind_counts == (
        ("fact", 2),
        ("event", 1),
        ("preference", 0),
        ("relation", 1),
        ("insight", 0),
    )


def test_memory_filter_cursor_cannot_change_filters(
    synthetic_store: RuntimePaths,
) -> None:
    first = _make_applied_store(synthetic_store, no_memory_only=False)
    _batch_id, sources = _capture(
        synthetic_store,
        {"second-memory.md": b"Synthetic violet marker is retained."},
    )
    initial = create_change_set(
        synthetic_store,
        _batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    ready = edit_change_set(
        synthetic_store,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="second-memory-item",
                memory=_fields("Synthetic violet marker is retained."),
                evidence=(
                    EvidenceInput(
                        source_id=sources[0].source_id,
                        blob_digest=sources[0].blob_digest,
                        excerpt="Synthetic violet marker is retained.",
                    ),
                ),
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    _apply(synthetic_store, ready)
    service = OwnerApplicationService(synthetic_store)
    page = service.list_memories(None, 1, MemoryFilters())
    assert page.next_cursor is not None
    with pytest.raises(StaleCursorError):
        service.list_memories(
            page.next_cursor,
            1,
            MemoryFilters(kinds=(MemoryKind.EVENT,)),
        )
    assert service.get_application(first.application_id).memory_revision_ids


def test_memory_lineage_over_one_hundred_revisions_is_cursor_bounded(
    synthetic_store: RuntimePaths,
) -> None:
    initial_store = _make_applied_store(synthetic_store, no_memory_only=False)
    service = OwnerApplicationService(synthetic_store)
    current_memory_id = initial_store.memory_ids[0]
    lineage_id = service.get_memory_revision(
        current_memory_id
    ).summary.revision.lineage_id

    for index in range(100):
        body = f"Synthetic lineage correction evidence {index:03}.".encode()
        (synthetic_store.inbox / f"lineage-{index:03}.txt").write_bytes(body)
        batch = scan_inbox(
            synthetic_store,
            clock=FakeClock(1_930_001_000.0 + index),
            policy=ScanPolicy(settle_seconds=0),
        )
        source = service.get_batch(batch.batch_id).sources[0]
        draft = create_change_set(
            synthetic_store,
            batch.batch_id,
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )
        ready = edit_change_set(
            synthetic_store,
            draft.change_set_id,
            draft.revision_id,
            (
                AddItem(
                    client_item_id=f"lineage-item-{index:03}",
                    memory=_fields(
                        f"Synthetic lineage statement {index:03}.",
                        target_lineage_id=lineage_id,
                        expected_head_id=current_memory_id,
                    ),
                    evidence=(
                        EvidenceInput(
                            source_id=source.source_id,
                            blob_digest=source.blob_digest,
                            excerpt=body.decode(),
                        ),
                    ),
                ),
            ),
            adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
        )
        current_memory_id = _apply(synthetic_store, ready).memory_ids[0]

    first = service.list_memory_lineage(lineage_id, None, 100)
    assert len(first.items) == 100
    assert first.has_more and first.next_cursor is not None
    second = service.list_memory_lineage(lineage_id, first.next_cursor, 100)
    assert len(second.items) == 1
    assert second.items[-1].revision.memory_id == current_memory_id
    assert not second.has_more and second.next_cursor is None
    lineage = service.list_lineages(None, 1).items[0]
    assert lineage.lineage_id == lineage_id
    assert lineage.revision_count == 101
    assert lineage.current_head_id == current_memory_id


def test_owner_service_reads_the_store_graph(synthetic_store: RuntimePaths) -> None:
    """The graph lenses read through the same bounded query session as the rest."""
    two_source_linked_apply(synthetic_store, FakeClock())
    service = OwnerApplicationService(paths=synthetic_store)

    graph = service.read_store_graph()

    assert graph.within_ceiling is True
    assert graph.guard_links_available is True
    assert any(edge.kind.value == "guard" for edge in graph.edges)
    assert any(node.layer.value == "source" for node in graph.nodes)


def _one_guard_candidate(paths: RuntimePaths) -> None:
    """Store one hedge and one claim on a single source, and link neither."""
    from synthetic import HEDGE_BODY, capture_text, ready_items, single_item_edit

    clock = SharedFakeClock()
    batch_id, source = capture_text(
        paths,
        name="claim-and-hedge.txt",
        body="The owner reports daily runs.\n" + HEDGE_BODY,
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    _apply(
        paths,
        ready_items(
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
                    item_id="itm_hedge",
                    source=source,
                    statement=(
                        "The daily-runs figure is self-reported and not verified."
                    ),
                    excerpt="self-reported and not verified",
                    kind=MemoryKind.INSIGHT,
                ),
            ),
        ),
    )


def test_guard_lint_panel_reads_without_taking_the_writer(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the governance panel turning a GET into a writer session.

    `memory lint guards` runs inside a writer session so its BEGIN heals the
    guard tables. A page must not: the writer lock is nonblocking and process
    level, so a panel that took it would refuse whenever a review was being
    written, and the heal itself is a schema change a GET must never make.
    """
    _one_guard_candidate(synthetic_store)
    service = OwnerApplicationService(paths=synthetic_store)

    with writer_session(synthetic_store):
        panel = service.read_guard_lint()

    assert panel.available is True
    assert panel.reported_candidate_count == 1
    assert panel.truncated_candidate_count == 0
    assert panel.standing_violations == ()
    candidate = panel.candidates[0]
    assert candidate.guard_statement == (
        "The daily-runs figure is self-reported and not verified."
    )
    assert candidate.governed_statement == "The owner reports daily runs."
    assert candidate.rationales == (
        "guard_vocabulary",
        "same_application",
        "shared_evidence_source",
    )
    # Every side resolves to the memory page holding the whole claim.
    assert candidate.guard_revision_id.startswith("mem_")
    assert candidate.governed_revision_id.startswith("mem_")
    assert (candidate.guard_elided, candidate.governed_elided) == (False, False)


def test_guard_lint_panel_clips_a_long_claim_and_says_it_did(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a statement being silently shortened, or not shortened at all."""
    from synthetic import capture_text, ready_items, single_item_edit

    from memory.ui.request_limits import MAX_GUARD_CANDIDATE_STATEMENT_CHARS

    long_claim = "The kettle was descaled in March " + "and again later " * 40
    clock = SharedFakeClock()
    batch_id, source = capture_text(
        paths=synthetic_store,
        name="long.txt",
        body=long_claim + "\nThe descaling date is self-reported.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    _apply(
        synthetic_store,
        ready_items(
            synthetic_store,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_long",
                    source=source,
                    statement=long_claim,
                    excerpt="The kettle was descaled in March",
                ),
                single_item_edit(
                    item_id="itm_hedge",
                    source=source,
                    statement="The descaling date is self-reported.",
                    excerpt="The descaling date is self-reported.",
                    kind=MemoryKind.INSIGHT,
                ),
            ),
        ),
    )

    candidate = (
        OwnerApplicationService(paths=synthetic_store).read_guard_lint().candidates[0]
    )

    assert candidate.governed_elided is True
    assert candidate.guard_elided is False
    assert len(candidate.governed_statement) == MAX_GUARD_CANDIDATE_STATEMENT_CHARS
    assert candidate.governed_statement.endswith("…")


def test_guard_lint_panel_names_the_draft_a_link_can_be_written_into(
    synthetic_store: RuntimePaths,
) -> None:
    """A proposed link needs an open review to land in, or it needs saying."""
    from synthetic import capture_text

    _one_guard_candidate(synthetic_store)
    service = OwnerApplicationService(paths=synthetic_store)

    assert service.read_guard_lint().repair_target is None

    # The runbook's own step: a one-line note gives the repair a batch.
    note_batch, _source = capture_text(
        paths=synthetic_store,
        name="guard-repair-note.txt",
        body="Linking the guards already in the Store.\n",
        sensitivity=Sensitivity.NORMAL,
        clock=SharedFakeClock(),
    )
    draft = create_change_set(
        synthetic_store,
        note_batch,
        adapter_origin=model.ChangeSetAdapterOrigin.OWNER_UI,
    )
    target = service.read_guard_lint().repair_target

    assert target is not None
    assert target.change_set_id == draft.change_set_id
    assert target.revision_id == draft.revision_id


def test_owner_status_reports_the_same_review_backlog_as_the_wire(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the owner header and `store.status` disagreeing about the backlog.

    `pending_review_count` reached the wire before it reached the record the
    owner UI builds, and the field carries a zero default. A builder that skips
    it therefore does not fail; it reports "no reviews waiting", which is the
    one wrong answer this count exists to prevent.
    """
    from memory.model import ChangeSetAdapterOrigin
    from memory.sources import get_store_status

    (synthetic_store.inbox / "backlog.md").write_text(
        "A synthetic note awaiting review.\n", encoding="utf-8"
    )
    batch = scan_inbox(synthetic_store, clock=FakeClock())
    create_change_set(
        synthetic_store,
        batch.batch_id,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )

    owner = OwnerApplicationService(synthetic_store).get_status()
    wire = get_store_status(synthetic_store)

    assert wire.pending_review_count == 1
    assert owner.store.pending_review_count == wire.pending_review_count
    assert owner.pending_review_count == wire.pending_review_count
