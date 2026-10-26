from __future__ import annotations

import importlib
import inspect
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx2
import pytest
from starlette.routing import Route
from starlette.testclient import TestClient
from ui_support import RefusingOwnerPresenceAdapter

from memory.database import writer_session
from memory.errors import StaleCursorError
from memory.inbox import ScanPolicy, scan_inbox
from memory.model import (
    AddItem,
    Authorship,
    ChangeSetAdapterOrigin,
    EvidenceInput,
    EvidenceLocator,
    MemoryFields,
    MemoryKind,
    MemorySummary,
    RejectItem,
    ReplaceItem,
    RuntimeMode,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceCaptureOrigin,
    StoreStatus,
    UiSession,
)
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.sources import list_sources
from memory.ui.app import create_ui_app
from memory.ui.auth import UiSessionStore
from memory.ui.owner_presence import (
    ApprovalAttemptStore,
    SystemMonotonicClock,
    UiApprovalOrchestrator,
)
from memory.ui.request_limits import (
    MAX_STANDARD_HTML_RESPONSE_BYTES,
    STANDARD_PAGE_CHROME_BYTES,
    UI_MEMORY_PAGE_LIMIT,
    UI_STANDARD_PAGE_LIMIT,
)
from memory.ui.routes.audit import (
    AUDIT_HANDLE_PARAM,
    AUDIT_INDEX_SECTIONS,
    MAX_AUDIT_DECISION_ROW_HTML_BYTES,
    MAX_AUDIT_IDENTIFIER_BYTES,
    MAX_AUDIT_IDENTIFIER_ROW_HTML_BYTES,
    MAX_AUDIT_ROW_HTML_BYTES,
    UI_AUDIT_PAGE_LIMIT,
    audit_routes,
)
from memory.ui.service import OwnerApplicationService
from memory.ui.view_models import (
    AuditCounts,
    AuditIndex,
    AuditSnapshot,
    InboxStatus,
    MemoryProjectionCoverage,
    OwnerApplicationSummary,
    OwnerApprovalSummary,
    OwnerBatchSummary,
    OwnerChangeSetSummary,
    OwnerLineageSummary,
    OwnerMemoryDetail,
    OwnerMemorySummary,
    OwnerPage,
    OwnerSourceSummary,
    OwnerStatus,
    ProjectionCoverage,
    SourceProjectionCoverage,
)

PUBLIC_ORIGIN = "http://memory-55555555555555555555555555555555.localhost:41777"
EXACT_HOST = "memory-55555555555555555555555555555555.localhost:41777"
BOOTSTRAP = "synthetic-audit-bootstrap"

ORIGIN_TEXT = "Synthetic origin note: the amber lamp is lit on Saturday.\n"
DUPLICATE_TEXT = "合成重复来源：青玉钟在黎明鸣响。\n"
CORRECTION_TEXT = "合成修订：琥珀灯改在周日点亮。\n"
NO_MEMORY_TEXT = "Synthetic entry that records no canonical memory at all.\n"
DRAFT_TEXT = "Synthetic draft-only entry awaiting an owner Memory Review.\n"
IMAGE_BYTES = b"\x89PNG\x00synthetic-owner-audit-image"

ORIGIN_EXCERPT = "the amber lamp is lit on Saturday"
CORRECTION_EXCERPT = "琥珀灯改在周日点亮"


class FrozenClock:
    def __init__(self, timestamp: float = 2_140_000_000.0) -> None:
        self.timestamp = timestamp

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


class UnusedFinder:
    def reveal_directory_url(self, _directory_url: object) -> None:
        raise AssertionError("audit routes must not reveal a directory")


def _capture(
    paths: RuntimePaths,
    files: dict[str, bytes],
    *,
    sensitivity: Sensitivity = Sensitivity.NORMAL,
) -> tuple[str, dict[str, Any]]:
    before = {source.source_id for source in list_sources(paths, limit=100).items}
    for name, body in files.items():
        (paths.inbox / name).write_bytes(body)
    batch = scan_inbox(
        paths,
        sensitivity=sensitivity,
        clock=FrozenClock(),
        policy=ScanPolicy(settle_seconds=0),
    )
    captured = {
        source.original_name: source
        for source in list_sources(paths, limit=100).items
        if source.source_id not in before
    }
    return batch.batch_id, captured


def _apply(paths: RuntimePaths, review: Any) -> Any:
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


@dataclass(frozen=True, slots=True)
class SyntheticAuditStore:
    """One synthetic Store covering every authoritative audit schema area."""

    paths: RuntimePaths
    origin_batch_id: str
    origin_source_id: str
    duplicate_blob_id: str
    duplicate_source_ids: tuple[str, str]
    image_source_id: str
    origin_change_set_id: str
    origin_revision_ids: tuple[str, ...]
    origin_applied_revision_id: str
    origin_application_id: str
    origin_approval_id: str
    origin_memory_id: str
    lineage_id: str
    correction_batch_id: str
    correction_source_id: str
    correction_change_set_id: str
    correction_applied_revision_id: str
    correction_application_id: str
    correction_approval_id: str
    correction_memory_id: str
    correction_item_id: str
    rejected_item_id: str
    no_memory_batch_id: str
    no_memory_source_id: str
    no_memory_change_set_id: str
    no_memory_application_id: str
    no_memory_approval_id: str
    draft_batch_id: str
    draft_change_set_id: str


def _unscannable_inbox_entries(paths: RuntimePaths) -> None:
    """Leave exactly two synthetic issue codes with five total occurrences."""
    for index in range(3):
        (paths.inbox / f"synthetic-link-{index}").symlink_to(
            paths.inbox / "missing-synthetic-target"
        )
    for index in range(2):
        (paths.inbox / f"synthetic-directory-{index}").mkdir()


def _build_audit_store(paths: RuntimePaths) -> SyntheticAuditStore:
    """Seal duplicate blobs, applied lineages, a zero-memory apply, and a draft."""
    _unscannable_inbox_entries(paths)
    origin_batch_id, origin_sources = _capture(
        paths,
        {
            "a-origin-note.md": ORIGIN_TEXT.encode(),
            "b-duplicate-one.md": DUPLICATE_TEXT.encode(),
            "c-duplicate-two.md": DUPLICATE_TEXT.encode(),
            "d-synthetic-image.png": IMAGE_BYTES,
        },
        sensitivity=Sensitivity.RESTRICTED,
    )
    origin_source = origin_sources["a-origin-note.md"]
    duplicate_one = origin_sources["b-duplicate-one.md"]
    duplicate_two = origin_sources["c-duplicate-two.md"]
    image_source = origin_sources["d-synthetic-image.png"]
    assert duplicate_one.blob_digest == duplicate_two.blob_digest
    duplicate_blob_id = (
        OwnerApplicationService(paths)
        .get_source_detail(duplicate_one.source_id)
        .summary.blob_id
    )

    origin_draft = create_change_set(
        paths,
        origin_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    origin_proposed = edit_change_set(
        paths,
        origin_draft.change_set_id,
        origin_draft.revision_id,
        (
            AddItem(
                client_item_id="synthetic-origin",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement="The synthetic amber lamp is lit on Saturday.",
                    occurred_on="2031-02-03",
                    valid_from="2031-02-03",
                    valid_to=None,
                    tags=("lamp", "origin"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=origin_source.source_id,
                        blob_digest=origin_source.blob_digest,
                        excerpt=ORIGIN_EXCERPT,
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=duplicate_one.source_id,
                reason="Synthetic duplicate capture adds no separate memory.",
            ),
            SetSourceNoMemory(
                source_id=duplicate_two.source_id,
                reason="Synthetic duplicate capture adds no separate memory.",
            ),
            SetSourceNoMemory(
                source_id=image_source.source_id,
                reason="Synthetic binary capture is inherently unsearchable.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    origin_ready = edit_change_set(
        paths,
        origin_proposed.change_set_id,
        origin_proposed.revision_id,
        (
            ReplaceItem(
                item_id="synthetic-origin",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement="The synthetic amber lamp is lit each Saturday.",
                    occurred_on="2031-02-03",
                    valid_from="2031-02-03",
                    valid_to=None,
                    tags=("lamp", "origin"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=origin_proposed.items[0].evidence,
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.OWNER_UI,
    )
    origin_applied = _apply(paths, origin_ready)
    origin_memory_id = origin_applied.memory_ids[0]
    service = OwnerApplicationService(paths)
    lineage_id = service.get_memory_revision(
        origin_memory_id
    ).summary.revision.lineage_id
    origin_approval_id = service.get_application(
        origin_applied.application_id
    ).approval.approval_id

    correction_batch_id, correction_sources = _capture(
        paths,
        {"e-correction.md": CORRECTION_TEXT.encode()},
        sensitivity=Sensitivity.SENSITIVE,
    )
    correction_source = correction_sources["e-correction.md"]
    correction_draft = create_change_set(
        paths,
        correction_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    correction_ready = edit_change_set(
        paths,
        correction_draft.change_set_id,
        correction_draft.revision_id,
        (
            AddItem(
                client_item_id="synthetic-correction",
                memory=MemoryFields(
                    kind=MemoryKind.EVENT,
                    statement="The synthetic amber lamp is lit on Sunday.",
                    occurred_on="2032-04-05",
                    valid_from="2032-04-05",
                    valid_to=None,
                    tags=("lamp", "sunday"),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=lineage_id,
                    expected_head_id=origin_memory_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=correction_source.source_id,
                        blob_digest=correction_source.blob_digest,
                        excerpt=CORRECTION_EXCERPT,
                    ),
                ),
            ),
            AddItem(
                client_item_id="synthetic-rejected",
                memory=MemoryFields(
                    kind=MemoryKind.INSIGHT,
                    statement="A synthetic rejected reading of the same correction.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("rejected",),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=correction_source.source_id,
                        blob_digest=correction_source.blob_digest,
                        excerpt=CORRECTION_EXCERPT,
                    ),
                ),
            ),
            RejectItem(item_id="synthetic-rejected"),
        ),
        adapter_origin=ChangeSetAdapterOrigin.OWNER_UI,
    )
    correction_applied = _apply(paths, correction_ready)
    correction_approval_id = service.get_application(
        correction_applied.application_id
    ).approval.approval_id

    no_memory_batch_id, no_memory_sources = _capture(
        paths,
        {"f-no-memory.md": NO_MEMORY_TEXT.encode()},
    )
    no_memory_source = no_memory_sources["f-no-memory.md"]
    no_memory_draft = create_change_set(
        paths,
        no_memory_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    no_memory_ready = edit_change_set(
        paths,
        no_memory_draft.change_set_id,
        no_memory_draft.revision_id,
        (
            SetSourceNoMemory(
                source_id=no_memory_source.source_id,
                reason="Synthetic source records no canonical memory.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    no_memory_applied = _apply(paths, no_memory_ready)
    assert no_memory_applied.memory_ids == ()
    no_memory_approval_id = service.get_application(
        no_memory_applied.application_id
    ).approval.approval_id

    draft_batch_id, _draft_sources = _capture(
        paths,
        {"g-draft.md": DRAFT_TEXT.encode()},
    )
    draft_change_set = create_change_set(
        paths,
        draft_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )

    return SyntheticAuditStore(
        paths=paths,
        origin_batch_id=origin_batch_id,
        origin_source_id=origin_source.source_id,
        duplicate_blob_id=duplicate_blob_id,
        duplicate_source_ids=(duplicate_one.source_id, duplicate_two.source_id),
        image_source_id=image_source.source_id,
        origin_change_set_id=origin_ready.change_set_id,
        origin_revision_ids=(
            origin_draft.revision_id,
            origin_proposed.revision_id,
            origin_ready.revision_id,
        ),
        origin_applied_revision_id=origin_ready.revision_id,
        origin_application_id=origin_applied.application_id,
        origin_approval_id=origin_approval_id,
        origin_memory_id=origin_memory_id,
        lineage_id=lineage_id,
        correction_batch_id=correction_batch_id,
        correction_source_id=correction_source.source_id,
        correction_change_set_id=correction_ready.change_set_id,
        correction_applied_revision_id=correction_ready.revision_id,
        correction_application_id=correction_applied.application_id,
        correction_approval_id=correction_approval_id,
        correction_memory_id=correction_applied.memory_ids[0],
        correction_item_id="synthetic-correction",
        rejected_item_id="synthetic-rejected",
        no_memory_batch_id=no_memory_batch_id,
        no_memory_source_id=no_memory_source.source_id,
        no_memory_change_set_id=no_memory_ready.change_set_id,
        no_memory_application_id=no_memory_applied.application_id,
        no_memory_approval_id=no_memory_approval_id,
        draft_batch_id=draft_batch_id,
        draft_change_set_id=draft_change_set.change_set_id,
    )


@dataclass(slots=True)
class AuditUi:
    client: TestClient
    sessions: UiSessionStore
    service: Any
    store: SyntheticAuditStore | None = None

    @property
    def session(self) -> UiSession:
        cookie = self.client.cookies.get("memory_ui_session")
        assert cookie is not None
        session = self.sessions.resolve_cookie(
            cookie=cookie,
            exact_host=EXACT_HOST,
            now_ns=time.monotonic_ns(),
        )
        assert session is not None
        return session

    def post(
        self, path: str, fields: tuple[tuple[str, str], ...] = ()
    ) -> httpx2.Response:
        return self.client.post(
            path,
            content=urllib.parse.urlencode(fields).encode("ascii"),
            headers={
                "Origin": PUBLIC_ORIGIN,
                "X-Memory-CSRF": self.session.csrf_token,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )

    def begin_audit(self) -> str:
        response = self.post("/audit", (("csrf", self.session.csrf_token),))
        assert response.status_code == 303, response.text
        location = response.headers["location"]
        assert location.startswith(f"/audit?{AUDIT_HANDLE_PARAM}=")
        return location.split("=", 1)[1]

    def audit_handle_count(self) -> int:
        record = self.sessions._sessions[self.session.session_id]
        return len(record.audits)


def _authenticated_client(service: Any) -> AuditUi:
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    application = create_ui_app(
        service,
        sessions,
        UnusedFinder(),
        UiApprovalOrchestrator(
            service=service,
            sessions=sessions,
            attempts=ApprovalAttemptStore(),
            verifier=RefusingOwnerPresenceAdapter(),
            clock=SystemMonotonicClock(),
        ),
        public_origin=PUBLIC_ORIGIN,
    )
    client = TestClient(application, base_url=PUBLIC_ORIGIN)
    exchanged = client.post(
        "/session",
        content=BOOTSTRAP,
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )
    assert exchanged.status_code == 303
    return AuditUi(client=client, sessions=sessions, service=service)


@pytest.fixture
def audit_ui(synthetic_store: RuntimePaths) -> AuditUi:
    store = _build_audit_store(synthetic_store)
    ui = _authenticated_client(OwnerApplicationService(synthetic_store))
    ui.store = store
    return ui


def _marked(body: str, marker: str) -> tuple[str, ...]:
    return tuple(item.split('"', 1)[0] for item in body.split(marker)[1:])


def _href(body: str, marker: str) -> str | None:
    if marker not in body:
        return None
    start = body.index(marker) + len(marker)
    return body[start : body.index('"', start)].replace("&amp;", "&")


def _exhaust(ui: AuditUi, url: str, row: str, following: str) -> tuple[str, ...]:
    """Walk every continuation page, collecting one marker across the traversal."""
    collected: list[str] = []
    pages = 0
    current: str | None = url
    while current is not None:
        response = ui.client.get(current)
        assert response.status_code == 200, response.text
        collected.extend(_marked(response.text, row))
        current = _href(response.text, following)
        pages += 1
        assert pages <= 64
    return tuple(collected)


# --------------------------------------------------------------------------
# Contract and route inventory
# --------------------------------------------------------------------------


def test_task_eight_modules_expose_the_approved_audit_interfaces() -> None:
    """Catch omission or signature drift at the in-app audit boundary."""
    routes = importlib.import_module("memory.ui.routes.audit")
    service = importlib.import_module("memory.ui.service")

    assert tuple(inspect.signature(audit_routes).parameters) == (
        "service",
        "sessions",
        "templates",
    )
    assert routes.AUDIT_HANDLE_PARAM == "h"
    assert MAX_AUDIT_IDENTIFIER_BYTES == 256
    assert 1 <= UI_AUDIT_PAGE_LIMIT <= UI_STANDARD_PAGE_LIMIT
    assert (
        STANDARD_PAGE_CHROME_BYTES
        + AUDIT_INDEX_SECTIONS * UI_AUDIT_PAGE_LIMIT * MAX_AUDIT_ROW_HTML_BYTES
        <= MAX_STANDARD_HTML_RESPONSE_BYTES
    )
    assert tuple(AuditIndex.__dataclass_fields__) == (
        "store",
        "snapshot",
        "integrity_capability",
    )
    assert tuple(AuditCounts.__dataclass_fields__) == (
        "batch_count",
        "batch_issue_row_count",
        "batch_issue_occurrence_count",
        "source_count",
        "change_set_count",
        "change_set_revision_count",
        "approval_count",
        "application_count",
        "lineage_count",
        "memory_revision_count",
    )
    for name in (
        "get_index",
        "list_batches",
        "get_batch",
        "list_sources",
        "get_source_detail",
        "list_blob_captures",
        "list_source_evidence_links",
        "list_lineages",
        "list_memory_lineage",
        "get_memory_revision",
        "list_change_sets",
        "list_change_set_revisions",
        "get_review_manifest",
        "list_review_items",
        "list_review_source_decisions",
        "list_applications",
        "get_application",
        "list_approvals",
        "get_approval",
    ):
        assert callable(getattr(service.BoundAuditReader, name))


def test_app_registers_the_complete_authenticated_audit_route_inventory(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an audit surface still falling through to the shell placeholder."""
    ui = _authenticated_client(OwnerApplicationService(synthetic_store))
    inventory = {
        (route.path, tuple(sorted(route.methods or ())))
        for route in ui.client.app.routes  # type: ignore[attr-defined]
        if isinstance(route, Route)
    }

    assert {
        ("/audit", ("GET", "HEAD")),
        ("/audit", ("POST",)),
        ("/audit/batches/{batch_id}", ("GET", "HEAD")),
        ("/audit/approvals/{approval_id}", ("GET", "HEAD")),
        ("/audit/applications/{application_id}", ("GET", "HEAD")),
    } <= inventory
    assert not any(
        segment in path
        for path, _methods in inventory
        for segment in ("export", "download", "dump", "backup", ".zip", ".jsonl")
    )


# --------------------------------------------------------------------------
# Read-only landing and protected snapshot lifecycle
# --------------------------------------------------------------------------


def test_audit_landing_is_read_only_and_creates_no_snapshot_handle(
    audit_ui: AuditUi,
) -> None:
    """Catch a GET that mints audit snapshot authority or session handles."""
    store = audit_ui.store
    assert store is not None
    before = audit_ui.service.begin_audit_snapshot().generation

    first = audit_ui.client.get("/audit")
    refreshed = audit_ui.client.get("/audit")
    unknown = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}=synthetic-unknown")

    assert first.status_code == 200
    assert refreshed.status_code == 200
    assert unknown.status_code == 404
    assert audit_ui.audit_handle_count() == 0
    assert audit_ui.service.begin_audit_snapshot().generation == before
    assert "Integrity verification unavailable" in first.text
    assert 'data-audit-generation="' not in first.text
    assert "data-audit-begin" in first.text


def test_protected_post_begins_one_session_owned_snapshot_and_redirects(
    audit_ui: AuditUi,
) -> None:
    """Catch snapshot creation outside an exact-Origin/CSRF-protected POST."""
    handle = audit_ui.begin_audit()
    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    generation = audit_ui.service.begin_audit_snapshot().generation

    unprotected = audit_ui.client.post(
        "/audit",
        content=b"csrf=synthetic",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    foreign_origin = audit_ui.client.post(
        "/audit",
        content=b"csrf=synthetic",
        headers={
            "Origin": "http://evil.invalid",
            "X-Memory-CSRF": audit_ui.session.csrf_token,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )

    assert index.status_code == 200
    assert f'data-audit-generation="{generation}"' in index.text
    assert audit_ui.audit_handle_count() == 1
    assert unprotected.status_code == 403
    assert foreign_origin.status_code == 403
    assert audit_ui.audit_handle_count() == 1

    restarted = audit_ui.begin_audit()
    assert restarted != handle
    assert audit_ui.audit_handle_count() == 2
    assert (
        audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}").status_code == 200
    )


def test_audit_gets_never_mutate_state_or_replace_the_session_handle(
    audit_ui: AuditUi,
) -> None:
    """Catch a GET that restarts the snapshot or advances the Store generation."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()
    before = audit_ui.service.begin_audit_snapshot()

    for path in (
        "/audit",
        f"/audit?{AUDIT_HANDLE_PARAM}={handle}",
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}",
        f"/audit/approvals/{store.origin_approval_id}?{AUDIT_HANDLE_PARAM}={handle}",
        (
            f"/audit/applications/{store.origin_application_id}"
            f"?{AUDIT_HANDLE_PARAM}={handle}"
        ),
        f"/sources/{store.origin_source_id}?{AUDIT_HANDLE_PARAM}={handle}",
        f"/memories/{store.correction_memory_id}?{AUDIT_HANDLE_PARAM}={handle}",
        f"/reviews/{store.origin_change_set_id}?{AUDIT_HANDLE_PARAM}={handle}",
        (
            f"/reviews/{store.correction_change_set_id}/revisions/"
            f"{store.correction_applied_revision_id}/items/"
            f"{store.correction_item_id}?{AUDIT_HANDLE_PARAM}={handle}"
        ),
    ):
        assert audit_ui.client.get(path).status_code == 200, path

    after = audit_ui.service.begin_audit_snapshot()
    assert after.generation == before.generation
    assert after.counts == before.counts
    assert audit_ui.audit_handle_count() == 1


# --------------------------------------------------------------------------
# Authoritative schema-area coverage
# --------------------------------------------------------------------------

AUTHORITATIVE_ROUTES = (
    ("store_meta", "/audit"),
    ("source_fts", "/audit?h={handle}"),
    ("memory_fts", "/audit?h={handle}"),
    ("source_blobs", "/sources/{source_id}?h={handle}"),
    ("sources", "/sources/{source_id}?h={handle}"),
    ("inbox_batches", "/audit/batches/{batch_id}?h={handle}"),
    ("inbox_batch_sources", "/audit/batches/{batch_id}?h={handle}"),
    ("inbox_batch_issues", "/audit/batches/{batch_id}?h={handle}"),
    ("change_sets", "/reviews/{change_set_id}?h={handle}"),
    ("change_set_revisions", "/reviews/{change_set_id}/revisions?h={handle}"),
    (
        "change_items",
        "/reviews/{change_set_id}/revisions/{revision_id}/items?h={handle}",
    ),
    (
        "change_item_evidence",
        "/reviews/{change_set_id}/revisions/{revision_id}/items?h={handle}",
    ),
    (
        "batch_source_decisions",
        "/reviews/{change_set_id}/revisions/{revision_id}/sources?h={handle}",
    ),
    ("approvals", "/audit/approvals/{approval_id}?h={handle}"),
    ("applications", "/audit/applications/{application_id}?h={handle}"),
    ("application_memories", "/audit/applications/{application_id}?h={handle}"),
    ("memory_lineages", "/memories/{memory_id}?h={handle}"),
    ("memory_revisions", "/memories/{memory_id}?h={handle}"),
    ("current_memory_heads", "/memories/{memory_id}?h={handle}"),
    ("memory_evidence", "/memories/{memory_id}?h={handle}"),
)


@pytest.mark.parametrize(("entity", "route"), AUTHORITATIVE_ROUTES)
def test_authoritative_entity_is_reachable(
    entity: str,
    route: str,
    audit_ui: AuditUi,
) -> None:
    """Catch an authoritative schema area with no bounded owner audit surface."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()
    identifiers = {
        "handle": handle,
        "source_id": store.origin_source_id,
        "batch_id": store.origin_batch_id,
        "change_set_id": store.origin_change_set_id,
        "revision_id": store.origin_applied_revision_id,
        "approval_id": store.correction_approval_id,
        "application_id": store.correction_application_id,
        "memory_id": store.correction_memory_id,
    }
    markers = {
        "store_meta": audit_ui.service.get_status().store.store_id,
        "source_fts": "Inherently unsearchable captures",
        "memory_fts": "Historical revisions not expected in projection",
        "source_blobs": store.duplicate_blob_id,
        "sources": store.origin_source_id,
        "inbox_batches": store.origin_batch_id,
        "inbox_batch_sources": f'data-audit-batch-source="{store.image_source_id}"',
        "inbox_batch_issues": 'data-audit-issue="symlink"',
        "change_sets": store.origin_change_set_id,
        "change_set_revisions": store.origin_revision_ids[0],
        "change_items": "synthetic-origin",
        "change_item_evidence": ORIGIN_EXCERPT,
        "batch_source_decisions": 'data-coverage="no_memory"',
        "approvals": store.correction_approval_id,
        "applications": store.correction_application_id,
        "application_memories": store.correction_memory_id,
        "memory_lineages": store.lineage_id,
        "memory_revisions": store.origin_memory_id,
        "current_memory_heads": store.correction_memory_id,
        "memory_evidence": CORRECTION_EXCERPT,
    }
    if entity == "source_blobs":
        identifiers["source_id"] = store.duplicate_source_ids[0]

    response = audit_ui.client.get(route.format(**identifiers))

    assert response.status_code == 200, response.text
    assert markers[entity] in response.text


# --------------------------------------------------------------------------
# Reconciled counts, issue meanings, and revision lifecycle
# --------------------------------------------------------------------------


def test_audit_index_counts_reconcile_with_exhaustive_pagination(
    audit_ui: AuditUi,
) -> None:
    """Catch a summary count that disagrees with its own bounded traversal."""
    handle = audit_ui.begin_audit()
    index_url = f"/audit?{AUDIT_HANDLE_PARAM}={handle}"
    snapshot = audit_ui.service.begin_audit_snapshot()

    batches = _exhaust(
        audit_ui, index_url, 'data-audit-batch="', 'data-next-batches href="'
    )
    sources = _exhaust(
        audit_ui, index_url, 'data-audit-source="', 'data-next-sources href="'
    )
    change_sets = _exhaust(
        audit_ui, index_url, 'data-audit-change-set="', 'data-next-change-sets href="'
    )
    approvals = _exhaust(
        audit_ui, index_url, 'data-audit-approval="', 'data-next-approvals href="'
    )
    applications = _exhaust(
        audit_ui, index_url, 'data-audit-application="', 'data-next-applications href="'
    )
    lineages = _exhaust(
        audit_ui, index_url, 'data-audit-lineage="', 'data-next-lineages href="'
    )

    assert len(batches) == snapshot.counts.batch_count == 4
    assert len(sources) == snapshot.counts.source_count == 7
    assert len(change_sets) == snapshot.counts.change_set_count == 4
    assert len(approvals) == snapshot.counts.approval_count == 3
    assert len(applications) == snapshot.counts.application_count == 3
    assert len(lineages) == snapshot.counts.lineage_count == 1

    revisions: list[str] = []
    for change_set_id in change_sets:
        revisions.extend(
            _exhaust(
                audit_ui,
                f"/reviews/{change_set_id}/revisions?{AUDIT_HANDLE_PARAM}={handle}",
                'data-audit-revision="',
                'data-next-revisions href="',
            )
        )
    assert len(revisions) == snapshot.counts.change_set_revision_count

    heads = {
        summary.lineage_id: summary.current_head_id
        for summary in audit_ui.service.list_lineages(None, 100).items
    }
    memory_revisions: list[str] = []
    for lineage in lineages:
        memory_revisions.extend(
            _exhaust(
                audit_ui,
                f"/memories/{heads[lineage]}?{AUDIT_HANDLE_PARAM}={handle}",
                'data-lineage-id="',
                'data-next-lineage href="',
            )
        )
    assert len(memory_revisions) == snapshot.counts.memory_revision_count == 2

    issue_rows = 0
    issue_occurrences = 0
    for batch_id in batches:
        page = audit_ui.client.get(
            f"/audit/batches/{batch_id}?{AUDIT_HANDLE_PARAM}={handle}"
        )
        assert page.status_code == 200
        codes = _marked(page.text, 'data-audit-issue="')
        counts = _marked(page.text, 'data-audit-issue-occurrences="')
        issue_rows += len(codes)
        issue_occurrences += sum(int(value) for value in counts)
    assert issue_rows == snapshot.counts.batch_issue_row_count == 8
    assert issue_occurrences == snapshot.counts.batch_issue_occurrence_count == 20
    assert issue_rows != issue_occurrences


def test_audit_index_labels_both_issue_meanings_and_zero_occurrence_sums(
    audit_ui: AuditUi,
) -> None:
    """Catch an issue summary conflating aggregate rows with occurrence counts."""
    handle = audit_ui.begin_audit()

    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    snapshot = audit_ui.service.begin_audit_snapshot()

    assert index.status_code == 200
    assert (
        f'data-audit-count-issue-rows="{snapshot.counts.batch_issue_row_count}"'
        in index.text
    )
    assert (
        "data-audit-count-issue-occurrences="
        f'"{snapshot.counts.batch_issue_occurrence_count}"' in index.text
    )
    assert "Inbox issue rows" in index.text
    assert "Recorded issue occurrences" in index.text


def test_batch_detail_links_every_child_and_labels_both_issue_meanings(
    audit_ui: AuditUi,
) -> None:
    """Catch a batch page hiding a capture, decision, issue, or resulting memory."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    page = audit_ui.client.get(
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )

    assert page.status_code == 200
    assert set(_marked(page.text, 'data-audit-batch-source="')) == {
        store.origin_source_id,
        store.image_source_id,
        *store.duplicate_source_ids,
    }
    assert set(_marked(page.text, 'data-audit-issue="')) == {"symlink", "not_regular"}
    assert 'data-audit-issue-row-count="2"' in page.text
    assert 'data-audit-issue-occurrence-count="5"' in page.text
    assert "Inbox issue rows" in page.text
    assert "Recorded issue occurrences" in page.text
    decisions = _exhaust(
        audit_ui,
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}",
        'data-audit-decision="',
        'data-next-decisions href="',
    )
    assert set(decisions) == {
        store.origin_source_id,
        store.image_source_id,
        *store.duplicate_source_ids,
    }
    assert f'href="/audit/applications/{store.origin_application_id}' in page.text
    assert f'href="/audit/approvals/{store.origin_approval_id}' in page.text
    assert f'data-audit-memory="{store.origin_memory_id}"' in page.text
    assert f'href="/reviews/{store.origin_change_set_id}' in page.text
    revisions = _exhaust(
        audit_ui,
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}",
        'data-audit-revision="',
        'data-next-batch-revisions href="',
    )
    assert set(revisions) == set(store.origin_revision_ids)


def test_exactly_one_revision_is_applied_and_predecessors_are_superseded(
    audit_ui: AuditUi,
) -> None:
    """Catch an applied change set marking its immutable predecessors applied."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    applied_history = audit_ui.client.get(
        f"/reviews/{store.origin_change_set_id}/revisions?{AUDIT_HANDLE_PARAM}={handle}"
    )
    draft_history = audit_ui.client.get(
        f"/reviews/{store.draft_change_set_id}/revisions?{AUDIT_HANDLE_PARAM}={handle}"
    )

    lifecycles = _marked(applied_history.text, 'data-revision-lifecycle="')
    assert applied_history.status_code == 200
    assert lifecycles == ("superseded", "superseded", "applied")
    assert _marked(draft_history.text, 'data-revision-lifecycle="') == (
        "current_draft",
    )


def test_applied_no_memory_only_review_and_zero_memory_application_stay_reachable(
    audit_ui: AuditUi,
) -> None:
    """Catch a zero-memory apply disappearing from batch and application views."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    batch = audit_ui.client.get(
        f"/audit/batches/{store.no_memory_batch_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    application = audit_ui.client.get(
        f"/audit/applications/{store.no_memory_application_id}"
        f"?{AUDIT_HANDLE_PARAM}={handle}"
    )
    listed = _exhaust(
        audit_ui,
        f"/audit?{AUDIT_HANDLE_PARAM}={handle}",
        'data-audit-application="',
        'data-next-applications href="',
    )

    assert batch.status_code == 200
    assert application.status_code == 200
    assert store.no_memory_application_id in listed
    assert 'data-audit-memory-count="0"' in application.text
    assert 'data-audit-memory="' not in application.text
    assert "no canonical memory" in application.text.lower()
    assert f'href="/audit/applications/{store.no_memory_application_id}' in batch.text


# --------------------------------------------------------------------------
# Projection honesty and integrity capability
# --------------------------------------------------------------------------


def test_projection_reporting_uses_distinct_source_and_memory_models(
    audit_ui: AuditUi,
) -> None:
    """Catch a projection report described as missing authoritative records."""
    handle = audit_ui.begin_audit()

    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    coverage = audit_ui.service.begin_audit_snapshot().projection_coverage

    assert index.status_code == 200
    for marker, value in (
        ("total-captures", coverage.sources.total_captures),
        ("expected-searchable", coverage.sources.expected_searchable_captures),
        ("indexed-expected", coverage.sources.indexed_expected_captures),
        ("missing-expected", coverage.sources.missing_expected_rows),
        ("inherently-unsearchable", coverage.sources.inherently_unsearchable_captures),
        ("unexpected-or-duplicate", coverage.sources.unexpected_or_duplicate_rows),
    ):
        assert f'data-source-projection-{marker}="{value}"' in index.text
    for marker, value in (
        ("current-heads", coverage.memories.current_heads),
        ("indexed-current-heads", coverage.memories.indexed_current_heads),
        ("missing-current-heads", coverage.memories.missing_current_head_rows),
        (
            "unexpected-or-duplicate",
            coverage.memories.unexpected_or_duplicate_noncurrent_rows,
        ),
        ("historical-revisions", coverage.memories.historical_revisions_not_expected),
    ):
        assert f'data-memory-projection-{marker}="{value}"' in index.text
    assert coverage.sources.inherently_unsearchable_captures == 1
    assert coverage.memories.historical_revisions_not_expected == 1
    assert "Historical revisions not expected in projection" in index.text
    assert "disposable" in index.text.lower()
    lowered = index.text.lower()
    assert "missing authoritative" not in lowered
    assert "cannot be retrieved" not in lowered


def test_integrity_verification_is_reported_unavailable_everywhere(
    audit_ui: AuditUi,
) -> None:
    """Catch ordinary bounded reads presented as an integrity pass."""
    handle = audit_ui.begin_audit()

    landing = audit_ui.client.get("/audit")
    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")

    for response in (landing, index):
        assert response.status_code == 200
        assert "Integrity verification unavailable" in response.text
        lowered = response.text.lower()
        assert "integrity passed" not in lowered
        assert "all clear" not in lowered
        assert "verified" not in lowered


# --------------------------------------------------------------------------
# Stale snapshots, interleaving, and handle isolation
# --------------------------------------------------------------------------


def _stale_page(response: httpx2.Response) -> bool:
    return (
        response.status_code == 409
        and "data-audit-stale" in response.text
        and "data-audit-begin" in response.text
    )


def _mutate_authoritatively(store: SyntheticAuditStore) -> None:
    _capture(store.paths, {"z-interleaved.md": b"Synthetic interleaved capture.\n"})


def _mutate_projection_only(store: SyntheticAuditStore) -> None:
    with writer_session(store.paths) as connection:
        connection.execute(
            "DELETE FROM source_fts WHERE source_id = ?",
            (store.origin_source_id,),
        )


def test_interleaved_application_between_pages_requires_a_stale_restart(
    audit_ui: AuditUi,
) -> None:
    """Catch an audit traversal mixing generations across continuation pages."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()
    first = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}&limit=1")
    assert first.status_code == 200
    following = _href(first.text, 'data-next-sources href="')
    assert following is not None

    _mutate_authoritatively(store)
    stale = audit_ui.client.get(following)

    assert _stale_page(stale)
    assert store.origin_source_id not in stale.text
    restarted = audit_ui.begin_audit()
    assert (
        audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={restarted}").status_code
        == 200
    )


@pytest.mark.parametrize("mutation", ("authoritative", "projection"))
def test_shared_details_render_the_stale_restart_before_record_content(
    mutation: str,
    audit_ui: AuditUi,
) -> None:
    """Catch a shared detail page falling back to a point-in-time read."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()
    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    assert index.status_code == 200

    if mutation == "authoritative":
        _mutate_authoritatively(store)
    else:
        _mutate_projection_only(store)

    shared = (
        (f"/sources/{store.origin_source_id}", ORIGIN_EXCERPT),
        (f"/memories/{store.correction_memory_id}", CORRECTION_EXCERPT),
        (f"/reviews/{store.origin_change_set_id}", store.origin_applied_revision_id),
        (
            f"/reviews/{store.correction_change_set_id}/revisions/"
            f"{store.correction_applied_revision_id}/items/"
            f"{store.correction_item_id}",
            CORRECTION_EXCERPT,
        ),
    )
    audit_owned = (
        (f"/audit/batches/{store.origin_batch_id}", store.origin_source_id),
        (f"/audit/approvals/{store.origin_approval_id}", store.origin_application_id),
        (
            f"/audit/applications/{store.origin_application_id}",
            store.origin_memory_id,
        ),
    )
    for path, forbidden in shared + audit_owned:
        response = audit_ui.client.get(f"{path}?{AUDIT_HANDLE_PARAM}={handle}")
        assert _stale_page(response), path
        assert forbidden not in response.text, path
    for path, _forbidden in shared:
        assert audit_ui.client.get(path).status_code == 200, path


def test_audit_handles_and_cursors_stay_session_and_snapshot_bound(
    audit_ui: AuditUi,
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an audit handle or cursor crossing sessions or snapshots."""
    store = audit_ui.store
    assert store is not None
    first = audit_ui.begin_audit()
    second = audit_ui.begin_audit()
    page = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={first}&limit=1")
    assert page.status_code == 200
    following = _href(page.text, 'data-next-sources href="')
    assert following is not None
    borrowed = following.replace(
        f"{AUDIT_HANDLE_PARAM}={first}", f"{AUDIT_HANDLE_PARAM}={second}"
    )

    stranger = TestClient(audit_ui.client.app, base_url=PUBLIC_ORIGIN)
    replayed_bootstrap = stranger.post(
        "/session",
        content=BOOTSTRAP,
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )
    foreign = _authenticated_client(OwnerApplicationService(synthetic_store))

    assert replayed_bootstrap.status_code == 401
    assert stranger.get(f"/audit?{AUDIT_HANDLE_PARAM}={first}").status_code == 401
    assert foreign.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={first}").status_code == 404
    assert _stale_page(audit_ui.client.get(borrowed))
    assert (
        audit_ui.sessions.resolve_audit(
            "synthetic-other-session",
            first,
            now_ns=time.monotonic_ns(),
        )
        is None
    )


# --------------------------------------------------------------------------
# Bounded relationships beyond one hundred records
# --------------------------------------------------------------------------


def test_captures_sharing_a_blob_stay_bounded_beyond_one_hundred(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an audit source page materializing every capture of one blob."""
    shared = b"Synthetic duplicated capture body for blob identity.\n"
    for batch in range(2):
        for index in range(51):
            (synthetic_store.inbox / f"dup-{batch}-{index:03}.md").write_bytes(shared)
        scan_inbox(
            synthetic_store,
            sensitivity=Sensitivity.NORMAL,
            clock=FrozenClock(),
            policy=ScanPolicy(settle_seconds=0),
        )
    ui = _authenticated_client(OwnerApplicationService(synthetic_store))
    handle = ui.begin_audit()
    first_source = ui.service.list_sources(None, 1).items[0]

    collected: list[str] = []
    pages = 0
    url: str | None = f"/sources/{first_source.source_id}?{AUDIT_HANDLE_PARAM}={handle}"
    while url is not None:
        response = ui.client.get(url)
        assert response.status_code == 200, response.text
        assert len(response.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
        assert f"{AUDIT_HANDLE_PARAM}={handle}" in response.text
        collected.extend(_marked(response.text, 'data-sibling-id="'))
        assert len(collected) <= 102
        url = _href(response.text, 'data-next-siblings href="')
        pages += 1

    assert len(collected) == 102
    assert len(set(collected)) == 102
    assert pages == 3


# --------------------------------------------------------------------------
# Render-only bounded page budgets
# --------------------------------------------------------------------------


def _wide(prefix: str, index: int, width: int) -> str:
    body = f"{prefix}{index:06d}"
    return body + "&" * (width - len(body))


def _wide_identifier(prefix: str, index: int) -> str:
    return _wide(prefix, index, MAX_AUDIT_IDENTIFIER_BYTES)


def _synthetic_status() -> OwnerStatus:
    return OwnerStatus(
        store=StoreStatus(
            product="memory",
            schema_version=1,
            store_id="store_synthetic_audit_budget",
            source_count=1,
            memory_count=1,
            searchable_count=1,
            unsearchable_count=0,
            reindex_required=False,
            mcp_contract_digest="0" * 64,
            skill_digest="1" * 64,
            pending_review_count=0,
        ),
        runtime_mode=RuntimeMode.PERSONAL,
        availability="available",
        pending_review_count=0,
        projections=ProjectionCoverage(
            sources=SourceProjectionCoverage(
                total_captures=1,
                expected_searchable_captures=1,
                indexed_expected_captures=1,
                missing_expected_rows=0,
                inherently_unsearchable_captures=0,
                unexpected_or_duplicate_rows=0,
            ),
            memories=MemoryProjectionCoverage(
                current_heads=1,
                indexed_current_heads=1,
                missing_current_head_rows=0,
                unexpected_or_duplicate_noncurrent_rows=0,
                historical_revisions_not_expected=0,
            ),
        ),
        runtime_display_path="/synthetic/store/home",
        inbox=InboxStatus(
            inbox_display_path="/synthetic/store/home/Inbox",
            staged_visible_entry_count=0,
        ),
    )


def _synthetic_snapshot() -> AuditSnapshot:
    return AuditSnapshot(
        store_id="store_synthetic_audit_budget",
        generation=7,
        high_water_marks=(("sources", 1),),
        counts=AuditCounts(
            batch_count=1,
            batch_issue_row_count=0,
            batch_issue_occurrence_count=0,
            source_count=1,
            change_set_count=1,
            change_set_revision_count=1,
            approval_count=1,
            application_count=1,
            lineage_count=1,
            memory_revision_count=1,
        ),
        projection_coverage=_synthetic_status().projections,
    )


def _page[T](rows: tuple[T, ...], cursor: str | None, limit: int) -> OwnerPage[T]:
    start = 0 if cursor is None else int(cursor.removeprefix("row:"))
    visible = rows[start : start + limit]
    end = start + len(visible)
    more = end < len(rows)
    return OwnerPage(
        items=visible,
        next_cursor=f"row:{end}" if more else None,
        has_more=more,
    )


class RenderOnlyAuditReader:
    """One worst-case-valid bounded audit reader for page-budget proofs."""

    def __init__(self, rows: int) -> None:
        self.rows = rows

    def get_index(self) -> AuditIndex:
        return AuditIndex(
            store=_synthetic_status(),
            snapshot=_synthetic_snapshot(),
            integrity_capability="unavailable",
        )

    def _source(self, index: int) -> OwnerSourceSummary:
        return OwnerSourceSummary(
            source_id=_wide_identifier("src", index),
            blob_id=_wide_identifier("blb", index),
            batch_id=_wide_identifier("bat", index),
            batch_ordinal=index,
            origin=SourceCaptureOrigin.INBOX,
            blob_digest="e" * 64,
            original_name=_wide("name", index, 255),
            media_type="text/markdown",
            byte_length=4096,
            authorship=Authorship.EXTERNAL,
            declared_sensitivity=Sensitivity.RESTRICTED,
            effective_sensitivity=Sensitivity.RESTRICTED,
            expected_searchable=True,
            indexed_for_search=True,
            captured_at=2_140_000_000,
        )

    def list_sources(self, cursor: str | None, limit: int) -> Any:
        return _page(
            tuple(self._source(index) for index in range(self.rows)), cursor, limit
        )

    def list_batches(self, cursor: str | None, limit: int) -> Any:
        rows = tuple(
            OwnerBatchSummary(
                batch_id=_wide_identifier("bat", index),
                sealed_at=2_140_000_000,
                source_count=64,
                has_more=False,
                issue_row_count=5,
                issue_occurrence_count=41,
                change_set_id=_wide_identifier("chs", index),
                application_id=_wide_identifier("app", index),
            )
            for index in range(self.rows)
        )
        return _page(rows, cursor, limit)

    def list_change_sets(self, cursor: str | None, limit: int) -> Any:
        rows = tuple(
            OwnerChangeSetSummary(
                change_set_id=_wide_identifier("chs", index),
                batch_id=_wide_identifier("bat", index),
                batch_sealed_at=2_140_000_000,
                state="applied",
                created_at=2_140_000_000,
                current_revision_id=_wide_identifier("rev", index),
                current_digest="f" * 64,
                current_adapter_origin=ChangeSetAdapterOrigin.OWNER_UI,
                current_lifecycle="applied",
                revision_count=3,
                item_count=256,
                batch_source_count=64,
                accounted_source_count=64,
                unaccounted_source_count=0,
                application_id=_wide_identifier("app", index),
            )
            for index in range(self.rows)
        )
        return _page(rows, cursor, limit)

    def list_approvals(self, cursor: str | None, limit: int) -> Any:
        rows = tuple(
            OwnerApprovalSummary(
                approval_id=_wide_identifier("apr", index),
                change_set_id=_wide_identifier("chs", index),
                revision_id=_wide_identifier("rev", index),
                digest="a" * 64,
                adapter="local_owner_ui",
                approved_at=2_140_000_000,
            )
            for index in range(self.rows)
        )
        return _page(rows, cursor, limit)

    def list_applications(self, cursor: str | None, limit: int) -> Any:
        rows = tuple(
            OwnerApplicationSummary(
                application_id=_wide_identifier("app", index),
                change_set_id=_wide_identifier("chs", index),
                revision_id=_wide_identifier("rev", index),
                applied_at=2_140_000_000,
                resulting_memory_count=256,
            )
            for index in range(self.rows)
        )
        return _page(rows, cursor, limit)

    def list_lineages(self, cursor: str | None, limit: int) -> Any:
        rows = tuple(
            OwnerLineageSummary(
                lineage_id=_wide_identifier("lin", index),
                current_head_id=_wide_identifier("mem", index),
                revision_count=101,
                latest_recorded_at=2_140_000_000,
            )
            for index in range(self.rows)
        )
        return _page(rows, cursor, limit)

    def _memory(self, index: int) -> OwnerMemorySummary:
        return OwnerMemorySummary(
            revision=MemorySummary(
                memory_id=_wide_identifier("mem", index),
                lineage_id=_wide_identifier("lin", 0),
                kind=MemoryKind.FACT,
                statement=f"Synthetic bounded lineage revision {index}.",
                occurred_on=None,
                valid_from=None,
                valid_to=None,
                recorded_at=2_140_000_000,
                tags=(),
                stored_sensitivity=Sensitivity.RESTRICTED,
                effective_sensitivity=Sensitivity.RESTRICTED,
            ),
            is_current=index == 0,
            current_head_id=_wide_identifier("mem", 0),
            predecessor_id=None,
            application_id=_wide_identifier("app", 0),
            application_ordinal=0,
        )

    def get_memory_revision(
        self,
        memory_id: str,
        *,
        guards_cursor: str | None = None,
        governs_cursor: str | None = None,
    ) -> OwnerMemoryDetail:
        if guards_cursor is not None or governs_cursor is not None:
            raise StaleCursorError("synthetic relationship continuation is unavailable")
        index = int(memory_id.removeprefix("mem")[:6])
        return OwnerMemoryDetail(
            summary=self._memory(index),
            change_set_id=_wide_identifier("chs", 0),
            change_set_revision_id=_wide_identifier("rev", 0),
            approval_id=_wide_identifier("apr", 0),
            evidence=(
                EvidenceLocator(
                    ordinal=0,
                    source_id=_wide_identifier("src", 0),
                    blob_digest="e" * 64,
                    mode="source",
                    char_start=None,
                    char_end=None,
                    excerpt=None,
                    source_level=True,
                ),
            ),
        )

    def list_memory_lineage(
        self,
        lineage_id: str,
        cursor: str | None,
        limit: int,
    ) -> Any:
        rows = tuple(self._memory(index) for index in range(self.rows))
        return _page(rows, cursor, limit)


class RenderOnlyAuditService:
    """One owner service exposing only the audit seam under test."""

    def __init__(self, rows: int) -> None:
        self.rows = rows
        self.reader = RenderOnlyAuditReader(rows)

    def get_status(self) -> OwnerStatus:
        return _synthetic_status()

    def begin_audit_snapshot(self) -> AuditSnapshot:
        return _synthetic_snapshot()

    def bind_audit(self, snapshot: AuditSnapshot) -> Any:
        assert isinstance(snapshot, AuditSnapshot)
        return self.reader


def _row_html_sizes(body: str) -> tuple[int, ...]:
    return tuple(
        len(segment.split("</li>", 1)[0].encode("utf-8")) + len("<li</li>")
        for segment in body.split("<li")[1:]
    )


def test_maximum_valid_audit_index_page_fits_its_derived_response_bound() -> None:
    """Catch an audit index page allocated beyond its declared byte budget."""
    ui = _authenticated_client(RenderOnlyAuditService(UI_AUDIT_PAGE_LIMIT + 1))
    handle = ui.begin_audit()

    first = ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    assert first.status_code == 200, first.text
    following = _href(first.text, 'data-next-sources href="')
    assert following is not None
    second = ui.client.get(following)

    assert len(first.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
    assert len(_marked(first.text, 'data-audit-source="')) == UI_AUDIT_PAGE_LIMIT
    assert len(_marked(first.text, 'data-audit-batch="')) == UI_AUDIT_PAGE_LIMIT
    assert len(_marked(first.text, 'data-audit-change-set="')) == UI_AUDIT_PAGE_LIMIT
    assert len(_marked(first.text, 'data-audit-approval="')) == UI_AUDIT_PAGE_LIMIT
    assert len(_marked(first.text, 'data-audit-application="')) == UI_AUDIT_PAGE_LIMIT
    assert len(_marked(first.text, 'data-audit-lineage="')) == UI_AUDIT_PAGE_LIMIT
    assert second.status_code == 200
    assert len(_marked(second.text, 'data-audit-source="')) == 1
    assert max(_row_html_sizes(first.text)) <= MAX_AUDIT_ROW_HTML_BYTES
    assert MAX_AUDIT_DECISION_ROW_HTML_BYTES >= MAX_AUDIT_ROW_HTML_BYTES
    assert MAX_AUDIT_IDENTIFIER_ROW_HTML_BYTES <= MAX_AUDIT_ROW_HTML_BYTES


def test_lineage_revisions_stay_bounded_beyond_one_hundred() -> None:
    """Catch an audit lineage view materializing every revision at once."""
    rows = 101
    expected_pages = -(-rows // UI_MEMORY_PAGE_LIMIT)
    ui = _authenticated_client(RenderOnlyAuditService(rows))
    handle = ui.begin_audit()

    collected: list[str] = []
    pages = 0
    url: str | None = (
        f"/memories/{_wide_identifier('mem', 0)}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    while url is not None:
        response = ui.client.get(url)
        assert response.status_code == 200, response.text
        assert len(response.content) <= MAX_STANDARD_HTML_RESPONSE_BYTES
        collected.extend(_marked(response.text, 'data-lineage-id="'))
        assert len(collected) <= rows
        url = _href(response.text, 'data-next-lineage href="')
        pages += 1

    assert len(collected) == rows
    assert len(set(collected)) == rows
    assert pages == expected_pages
    assert expected_pages >= 3


# --------------------------------------------------------------------------
# Capability, export, and content hygiene
# --------------------------------------------------------------------------


def test_approval_detail_is_read_only_and_exposes_no_reusable_capability(
    audit_ui: AuditUi,
) -> None:
    """Catch approval detail leaking session, Keychain, or capability material."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    approval = audit_ui.client.get(
        f"/audit/approvals/{store.correction_approval_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    application = audit_ui.client.get(
        f"/audit/applications/{store.correction_application_id}"
        f"?{AUDIT_HANDLE_PARAM}={handle}"
    )

    for response in (approval, application):
        assert response.status_code == 200
        assert "<form" not in response.text
        lowered = response.text.lower()
        for forbidden in (
            "keychain",
            "ownerapproval",
            "capability",
            "challenge",
            "sqlcipher",
            ".sqlite",
            "-wal",
            "-shm",
            "csrf",
            "select ",
            audit_ui.session.session_id,
            audit_ui.session.csrf_token,
            str(store.paths.database),
            str(store.paths.writer_lock),
        ):
            assert forbidden.lower() not in lowered
    assert "mcp_elicitation" in approval.text
    assert store.correction_memory_id in application.text
    assert f'href="/reviews/{store.correction_change_set_id}' in approval.text


def test_audit_pages_offer_no_record_export_or_bulk_download(
    audit_ui: AuditUi,
) -> None:
    """Catch a ZIP, JSONL, Markdown, or database export path in the audit view."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    for path in (
        "/audit",
        f"/audit?{AUDIT_HANDLE_PARAM}={handle}",
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}",
        f"/audit/approvals/{store.origin_approval_id}?{AUDIT_HANDLE_PARAM}={handle}",
        (
            f"/audit/applications/{store.origin_application_id}"
            f"?{AUDIT_HANDLE_PARAM}={handle}"
        ),
    ):
        response = audit_ui.client.get(path)
        assert response.status_code == 200, path
        lowered = response.text.lower()
        for forbidden in (
            "download",
            "export",
            ".zip",
            ".jsonl",
            "dump",
            "http://",
            "https://",
        ):
            assert forbidden not in lowered, path
        assert "download" not in response.headers.get("content-disposition", "")


def test_audit_bound_review_sections_keep_every_link_inside_the_snapshot(
    audit_ui: AuditUi,
) -> None:
    """Catch an audit review section dropping the handle into a live read."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()
    base = (
        f"/reviews/{store.origin_change_set_id}"
        f"/revisions/{store.origin_applied_revision_id}"
    )

    for path in (
        f"/reviews/{store.origin_change_set_id}",
        base,
        f"{base}/items",
        f"{base}/sources",
        f"{base}/blockers",
        f"/reviews/{store.origin_change_set_id}/revisions",
    ):
        response = audit_ui.client.get(f"{path}?{AUDIT_HANDLE_PARAM}={handle}")
        assert response.status_code == 200, path
        assert "/edits/" not in response.text, path
        for link in _marked(response.text, 'href="'):
            if link.startswith(("/sources/", "/memories/", "/reviews/", "/audit/")):
                assert f"{AUDIT_HANDLE_PARAM}={handle}" in link, (path, link)


def test_audit_navigation_carries_only_the_opaque_handle_in_links(
    audit_ui: AuditUi,
) -> None:
    """Catch owner content, filters, or filenames entering audit URLs."""
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    index = audit_ui.client.get(f"/audit?{AUDIT_HANDLE_PARAM}={handle}")
    source = audit_ui.client.get(
        f"/sources/{store.origin_source_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    memory = audit_ui.client.get(
        f"/memories/{store.correction_memory_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )

    batch = audit_ui.client.get(
        f"/audit/batches/{store.origin_batch_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    approval = audit_ui.client.get(
        f"/audit/approvals/{store.origin_approval_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )
    application = audit_ui.client.get(
        f"/audit/applications/{store.origin_application_id}"
        f"?{AUDIT_HANDLE_PARAM}={handle}"
    )

    for response in (index, source, memory, batch, approval, application):
        assert response.status_code == 200
        for link in _marked(response.text, 'href="'):
            assert "a-origin-note" not in link
            assert ORIGIN_EXCERPT not in link
            assert CORRECTION_EXCERPT not in link
            if link.endswith("/preview"):
                continue
            if link.startswith(("/sources/", "/memories/", "/reviews/", "/audit/")):
                assert f"{AUDIT_HANDLE_PARAM}={handle}" in link, link
    assert "Create correction" not in memory.text
    assert "data-authenticated-post" not in memory.text


def test_a_pinned_audit_snapshot_draws_no_live_neighbourhood(
    audit_ui: AuditUi,
) -> None:
    """Catch a live graph read leaking into a view pinned to one generation.

    The neighbourhood panel reads today's edges. Drawing it inside an audit
    snapshot would put current relationships in a picture the owner is reading
    as the Store at a fixed generation, which is the one thing audit
    navigation exists to prevent.
    """
    store = audit_ui.store
    assert store is not None
    handle = audit_ui.begin_audit()

    ordinary = audit_ui.client.get(f"/memories/{store.correction_memory_id}")
    pinned = audit_ui.client.get(
        f"/memories/{store.correction_memory_id}?{AUDIT_HANDLE_PARAM}={handle}"
    )

    assert ordinary.status_code == 200
    assert pinned.status_code == 200
    assert 'class="graph-neighbourhood"' in ordinary.text
    assert 'class="graph-neighbourhood"' not in pinned.text
    assert "/static/graph.js" not in pinned.text
