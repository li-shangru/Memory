from __future__ import annotations

import hashlib
import importlib
import inspect
import re
import time
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Protocol, cast

import pytest
from starlette.datastructures import FormData, Headers, UploadFile
from starlette.routing import Route
from starlette.testclient import TestClient
from test_owner_presence import (
    SyntheticOwnerPresenceAdapter,
)
from ui_support import build_test_orchestrator

from memory.errors import InvalidArgumentError
from memory.inbox import ScanPolicy, scan_inbox
from memory.model import (
    AddGuardLink,
    AddItem,
    ChangeSetAdapterOrigin,
    EvidenceInput,
    GuardLinkInput,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    RejectItem,
    ReplaceItem,
    RevokeGuardLink,
    RuntimeMode,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    StoreStatus,
    UiSession,
)
from memory.reviews import (
    MAX_DIFF_BYTES,
    MAX_EVIDENCE_EXCERPT_BYTES,
    MAX_EVIDENCE_PER_ITEM,
    MAX_GUARD_LINKS,
    MAX_NO_MEMORY_REASON_BYTES,
    MAX_STATEMENT_BYTES,
    MAX_TAG_BYTES,
    MAX_TAGS,
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
    get_change_set,
    render_change_set,
)
from memory.runtime import (
    _writer_lock,
)
from memory.sources import list_sources
from memory.ui.app import OwnerUiService, create_ui_app
from memory.ui.auth import (
    _MAX_REVIEW_REFUSALS,
    MAX_PENDING_REVIEW_FORMS,
    UI_PENDING_REVIEW_TTL_NS,
    UI_REVIEW_REFUSAL_TTL_NS,
    UiSessionStore,
)
from memory.ui.owner_presence import (
    APPROVAL_BINDING_TTL_NS,
    UiApprovalOrchestrator,
)
from memory.ui.request_limits import (
    MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES,
    MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES,
    MAX_FORM_FIELDS,
    MAX_RETAINED_REFUSAL_BYTES,
    MAX_REVIEW_EDIT_BODY_BYTES,
    MAX_REVIEW_FORM_FIELD_BYTES,
    MAX_REVIEW_GUARD_CHANGES_PER_ITEM,
    MAX_REVIEW_ROSTER_ROW_HTML_BYTES,
    MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
    STANDARD_PAGE_CHROME_BYTES,
    UI_REVIEW_ITEM_PAGE_LIMIT,
    UI_STANDARD_PAGE_LIMIT,
)
from memory.ui.review_forms import parse_change_edit_form
from memory.ui.service import OwnerApplicationService
from memory.ui.view_models import (
    InboxStatus,
    MemoryProjectionCoverage,
    OwnerApplicationSummary,
    OwnerApprovalSummary,
    OwnerChangeSetRevisionSummary,
    OwnerChangeSetSummary,
    OwnerDraftGuardLink,
    OwnerPage,
    OwnerReviewBlocker,
    OwnerReviewItemComparison,
    OwnerReviewManifest,
    OwnerReviewRosterItem,
    OwnerReviewRosterSource,
    OwnerSourceDecision,
    OwnerStatus,
    PendingReviewConflictLease,
    PendingReviewLease,
    ProjectionCoverage,
    SourceProjectionCoverage,
    UiPendingReviewConflict,
    UiPendingReviewForm,
)

PUBLIC_ORIGIN = "http://memory-44444444444444444444444444444444.localhost:41999"
EXACT_HOST = "memory-44444444444444444444444444444444.localhost:41999"
BOOTSTRAP = "synthetic-review-bootstrap"
OPERATIONS = (
    "add_item",
    "replace_item",
    "reject_item",
    "restore_item",
    "set_source_no_memory",
    "clear_source_no_memory",
)
GUARD_LINK_OPERATIONS = ("add_guard_link", "remove_guard_link", "revoke_guard_link")
ALL_OPERATIONS = OPERATIONS + GUARD_LINK_OPERATIONS


class FrozenClock:
    def __init__(self, timestamp: float = 2_130_000_000.0) -> None:
        self.timestamp = timestamp

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


class UnusedFinder:
    def reveal_directory_url(self, _directory_url: object) -> None:
        raise AssertionError("review routes must not reveal a directory")


def _capture(
    paths: RuntimePaths,
    files: dict[str, bytes],
    *,
    sensitivity: Sensitivity = Sensitivity.RESTRICTED,
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
class SyntheticReview:
    paths: RuntimePaths
    batch_id: str
    change_set_id: str
    revision_id: str
    digest: str
    lineage_id: str
    predecessor_id: str
    correction_item_id: str
    rejected_item_id: str
    correction_source_id: str
    unaccounted_source_id: str
    no_memory_source_id: str
    unaccounted_excerpt: str


ORIGIN_TEXT = "合成起源记录：琥珀灯在周六点亮。\n"
CORRECTION_TEXT = "合成修订记录：琥珀灯改在周日点亮。\n"
UNACCOUNTED_TEXT = "Synthetic omitted-proposal evidence line for owner repair.\n"
NO_MEMORY_TEXT = "Synthetic source that records no canonical memory at all.\n"


def _build_synthetic_review(paths: RuntimePaths) -> SyntheticReview:
    """Seal one applied predecessor plus one draft with every review state."""
    origin_batch, origin_sources = _capture(
        paths,
        {"a-origin-note.md": ORIGIN_TEXT.encode()},
    )
    origin_source = origin_sources["a-origin-note.md"]
    origin_draft = create_change_set(
        paths,
        origin_batch,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    origin_ready = edit_change_set(
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
                    valid_to="2031-12-31",
                    tags=("origin", "lamp"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=origin_source.source_id,
                        blob_digest=origin_source.blob_digest,
                        excerpt="琥珀灯在周六点亮",
                    ),
                ),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    applied = _apply(paths, origin_ready)
    predecessor_id = applied.memory_ids[0]
    lineage_id = (
        OwnerApplicationService(paths)
        .get_memory_revision(predecessor_id)
        .summary.revision.lineage_id
    )

    batch_id, sources = _capture(
        paths,
        {
            "a-correction.md": CORRECTION_TEXT.encode(),
            "b-unaccounted.md": UNACCOUNTED_TEXT.encode(),
            "c-no-memory.md": NO_MEMORY_TEXT.encode(),
        },
        sensitivity=Sensitivity.NORMAL,
    )
    correction_source = sources["a-correction.md"]
    unaccounted_source = sources["b-unaccounted.md"]
    no_memory_source = sources["c-no-memory.md"]
    draft = create_change_set(
        paths,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    ready = edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        (
            AddItem(
                client_item_id="synthetic-correction",
                memory=MemoryFields(
                    kind=MemoryKind.EVENT,
                    statement="The synthetic amber lamp is lit on Sunday.",
                    occurred_on="2032-04-05",
                    valid_from="2032-04-05",
                    valid_to="2032-09-09",
                    tags=("sunday", "lantern", "revised"),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=lineage_id,
                    expected_head_id=predecessor_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=correction_source.source_id,
                        blob_digest=correction_source.blob_digest,
                        excerpt="琥珀灯改在周日点亮",
                    ),
                ),
            ),
            AddItem(
                client_item_id="synthetic-rejected",
                memory=MemoryFields(
                    kind=MemoryKind.INSIGHT,
                    statement="A synthetic rejected interpretation of the omission.",
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
                        source_id=unaccounted_source.source_id,
                        blob_digest=unaccounted_source.blob_digest,
                        excerpt="Synthetic omitted-proposal evidence line",
                    ),
                ),
            ),
            RejectItem(item_id="synthetic-rejected"),
            SetSourceNoMemory(
                source_id=no_memory_source.source_id,
                reason="Synthetic source records no canonical memory.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    return SyntheticReview(
        paths=paths,
        batch_id=batch_id,
        change_set_id=ready.change_set_id,
        revision_id=ready.revision_id,
        digest=ready.digest,
        lineage_id=lineage_id,
        predecessor_id=predecessor_id,
        correction_item_id="synthetic-correction",
        rejected_item_id="synthetic-rejected",
        correction_source_id=correction_source.source_id,
        unaccounted_source_id=unaccounted_source.source_id,
        no_memory_source_id=no_memory_source.source_id,
        unaccounted_excerpt="Synthetic omitted-proposal evidence line",
    )


class ReviewUiService(OwnerUiService, Protocol):
    """The owner surface this suite reads: the UI's own, plus applied history.

    The approval assertions read the recorded approval and application rows
    back out of the Store to prove exactly one of each was minted. No owner UI
    route lists them, so `OwnerUiService` does not declare them.
    """

    def list_approvals(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerApprovalSummary]: ...

    def list_applications(
        self,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerApplicationSummary]: ...


@dataclass(slots=True)
class ReviewUi:
    client: TestClient
    sessions: UiSessionStore
    service: ReviewUiService
    review: SyntheticReview
    approval: UiApprovalOrchestrator

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

    def post_body(self, path: str, body: bytes, **extra: str) -> Any:
        headers = {
            "Origin": PUBLIC_ORIGIN,
            "X-Memory-CSRF": self.session.csrf_token,
            "Content-Type": "application/x-www-form-urlencoded",
            **extra,
        }
        return self.client.post(
            path,
            content=body,
            headers=headers,
            follow_redirects=False,
        )

    def post_form(self, path: str, fields: Sequence[tuple[str, str]]) -> Any:
        return self.post_body(path, urllib.parse.urlencode(fields).encode("ascii"))

    def current_revision(self) -> OwnerReviewManifest:
        return self.service.get_review_manifest(self.review.change_set_id)

    def edit_path(self, operation: str, revision_id: str | None = None) -> str:
        selected = revision_id or self.current_revision().revision.revision_id
        return (
            f"/reviews/{self.review.change_set_id}"
            f"/revisions/{selected}/edits/{operation}"
        )

    def edit_fields(self, operation: str) -> list[tuple[str, str]]:
        return operation_fields(operation, self.review, self.current_revision())

    def submit(self, operation: str) -> OwnerReviewManifest:
        response = self.post_form(
            self.edit_path(operation),
            self.edit_fields(operation),
        )
        assert response.status_code == 303, response.text
        assert response.headers["location"] == f"/reviews/{self.review.change_set_id}"
        return self.current_revision()


def operation_fields(
    operation: str,
    review: SyntheticReview,
    manifest: OwnerReviewManifest,
) -> list[tuple[str, str]]:
    """Return exactly one bounded browser-writable operation form."""
    digest = [("expected_digest", manifest.revision.digest)]
    if operation == "add_item":
        return [
            *digest,
            ("kind", "insight"),
            ("statement", "A synthetic owner-added interpretation of the omission."),
            ("occurred_on", "2032-05-06"),
            ("valid_from", ""),
            ("valid_to", ""),
            ("sensitivity", "sensitive"),
            ("tag.0", "owner-added"),
            ("tag.1", "repair"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", review.unaccounted_excerpt),
        ]
    if operation == "replace_item":
        return [
            *digest,
            ("item_id", review.correction_item_id),
            ("kind", "event"),
            ("statement", "The synthetic amber lamp is now lit on Sunday evening."),
            ("occurred_on", "2032-04-05"),
            ("valid_from", "2032-04-05"),
            ("valid_to", ""),
            ("sensitivity", "sensitive"),
            ("target_lineage_id", review.lineage_id),
            ("expected_head_id", review.predecessor_id),
            ("tag.0", "sunday"),
            ("tag.1", "evening"),
            ("evidence.0.source_id", review.correction_source_id),
            ("evidence.0.excerpt", "琥珀灯改在周日点亮"),
        ]
    if operation == "reject_item":
        return [*digest, ("item_id", review.correction_item_id)]
    if operation == "restore_item":
        return [*digest, ("item_id", review.rejected_item_id)]
    if operation == "set_source_no_memory":
        return [
            *digest,
            ("source_id", review.no_memory_source_id),
            ("reason", "Synthetic reviewed decision: no canonical memory."),
        ]
    if operation == "clear_source_no_memory":
        return [*digest, ("source_id", review.no_memory_source_id)]
    if operation in GUARD_LINK_OPERATIONS:
        return [
            *digest,
            ("guard_item_id", review.rejected_item_id),
            ("governed_item_id", review.correction_item_id),
        ]
    raise AssertionError("unknown synthetic review operation")


def _authenticated_review_ui(
    paths: RuntimePaths,
    review: SyntheticReview,
    service: ReviewUiService | None = None,
    verifier: Any | None = None,
) -> ReviewUi:
    selected = OwnerApplicationService(paths) if service is None else service
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    approval = build_test_orchestrator(selected, sessions, verifier)
    application = create_ui_app(
        selected,
        sessions,
        UnusedFinder(),
        approval,
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
    return ReviewUi(
        client=client,
        sessions=sessions,
        service=selected,
        review=review,
        approval=approval,
    )


@pytest.fixture
def review_ui(synthetic_store: RuntimePaths) -> ReviewUi:
    review = _build_synthetic_review(synthetic_store)
    return _authenticated_review_ui(synthetic_store, review)


def test_task_six_modules_expose_the_approved_review_interfaces() -> None:
    """Catch omission or signature drift at the owner Memory Review boundary."""
    forms = importlib.import_module("memory.ui.review_forms")
    auth = importlib.import_module("memory.ui.auth")

    assert tuple(inspect.signature(parse_change_edit_form).parameters) == (
        "form",
        "intent",
        "current",
    )
    assert forms.OWNER_REVIEW_FORM_INTENTS == ALL_OPERATIONS
    assert MAX_PENDING_REVIEW_FORMS == 8
    assert UI_PENDING_REVIEW_TTL_NS == 600_000_000_000
    assert tuple(UiPendingReviewForm.__dataclass_fields__) == (
        "change_set_id",
        "expected_revision_id",
        "expected_digest",
        "operation",
        "normalized_fields",
        "base_target_fingerprint",
        "expires_at_ns",
    )
    assert tuple(PendingReviewLease.__dataclass_fields__) == (
        "lease_id",
        "form",
        "state",
    )
    assert tuple(UiPendingReviewConflict.__dataclass_fields__) == (
        "form",
        "current_revision_id",
        "current_digest",
        "current_target_fingerprint",
    )
    assert tuple(PendingReviewConflictLease.__dataclass_fields__) == (
        "lease_id",
        "form",
        "selected_revision_id",
        "selected_digest",
        "selected_target_fingerprint",
        "state",
    )
    for name in (
        "remember_pending_review",
        "resolve_pending_review",
        "lease_pending_review",
        "lease_pending_review_conflict",
        "complete_pending_review",
        "mark_pending_review_retryable",
        "mark_pending_review_conflict",
    ):
        assert callable(getattr(auth.UiSessionStore, name))
    assert tuple(inspect.signature(OwnerApplicationService.edit_review).parameters) == (
        "self",
        "change_set_id",
        "expected_revision_id",
        "edits",
    )


def _route_inventory(service: Any) -> set[tuple[str, tuple[str, ...]]]:
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=100,
    )
    application = create_ui_app(
        service,
        sessions,
        UnusedFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    return {
        (route.path, tuple(sorted(route.methods or ())))
        for route in application.routes
        if isinstance(route, Route)
    }


def test_app_registers_the_complete_authenticated_review_route_inventory() -> None:
    """Catch a review surface still falling through to the shell placeholder."""
    inventory = _route_inventory(RenderOnlyReviewService())

    assert {
        ("/reviews", ("GET", "HEAD")),
        ("/reviews/{change_set_id}", ("GET", "HEAD")),
        ("/reviews/{change_set_id}/revisions/{revision_id}", ("GET", "HEAD")),
        ("/reviews/{change_set_id}/revisions/{revision_id}/items", ("GET", "HEAD")),
        (
            "/reviews/{change_set_id}/revisions/{revision_id}/items/{item_id}",
            ("GET", "HEAD"),
        ),
        ("/reviews/{change_set_id}/revisions/{revision_id}/sources", ("GET", "HEAD")),
        ("/reviews/{change_set_id}/revisions/{revision_id}/blockers", ("GET", "HEAD")),
        (
            "/reviews/{change_set_id}/revisions/{revision_id}/edits/{intent}",
            ("GET", "HEAD"),
        ),
        ("/reviews/{change_set_id}/revisions/{revision_id}/edits/{intent}", ("POST",)),
        ("/reviews/{change_set_id}/pending/{handle}", ("GET", "HEAD")),
        ("/reviews/{change_set_id}/pending/{handle}", ("POST",)),
        ("/reviews/{change_set_id}/pending/{handle}/current", ("POST",)),
    } <= inventory


def test_landing_prefers_pending_reviews_only_while_a_draft_exists(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a landing page that hides or invents an owner Memory Review."""
    review = _build_synthetic_review(synthetic_store)
    ui = _authenticated_review_ui(synthetic_store, review)

    drafted = ui.client.get("/", follow_redirects=False)
    listed = ui.client.get("/reviews")
    _apply_current_draft(ui)
    settled = ui.client.get("/", follow_redirects=False)

    assert drafted.status_code == 303
    assert drafted.headers["location"] == "/reviews"
    assert listed.status_code == 200
    assert f'href="/reviews/{review.change_set_id}"' in listed.text
    assert settled.status_code == 200
    assert "Store status" in settled.text


def _apply_current_draft(ui: ReviewUi) -> Any:
    """Apply the exact current draft revision out of band through the core."""
    manifest = ui.current_revision()
    review = ui.review
    ready = edit_change_set(
        review.paths,
        review.change_set_id,
        manifest.revision.revision_id,
        (
            SetSourceNoMemory(
                source_id=review.unaccounted_source_id,
                reason="Synthetic out-of-band accounting completion.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    return _apply(review.paths, ready)


def test_review_list_separates_draft_and_applied_change_sets(
    review_ui: ReviewUi,
) -> None:
    """Catch applied history disappearing from the owner review inventory."""
    review = review_ui.review
    drafted = review_ui.client.get("/reviews")
    _apply_current_draft(review_ui)
    applied = review_ui.client.get("/reviews")

    draft_row = f'data-review-state="draft" data-change-set="{review.change_set_id}"'
    applied_row = (
        f'data-review-state="applied" data-change-set="{review.change_set_id}"'
    )
    assert draft_row in drafted.text
    assert applied_row not in drafted.text
    assert f'href="/inbox/batches/{review.batch_id}"' in drafted.text
    assert applied_row in applied.text
    assert draft_row not in applied.text
    assert "No draft Memory Review is pending." in applied.text


def test_applied_reviews_name_the_adapter_that_wrote_them(
    review_ui: ReviewUi,
) -> None:
    """Catch the applied list dropping the origin the draft list shows.

    Which surface authored a revision is exactly the question an owner asks
    about a review they no longer remember, and applying it does not make the
    answer less interesting.
    """
    drafted = review_ui.client.get("/reviews")
    _apply_current_draft(review_ui)
    applied = review_ui.client.get("/reviews")
    applied_section = applied.text.split('id="applied-reviews-heading"', 1)[1]

    assert "Origin mcp" in drafted.text
    assert "Origin system" in applied_section


def test_correction_review_shows_every_predecessor_and_proposal_field(
    review_ui: ReviewUi,
) -> None:
    """Catch a partial correction diff hiding a changed field or evidence set."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    revision_id = manifest.revision.revision_id
    base = f"/reviews/{review.change_set_id}/revisions/{revision_id}"
    roster = review_ui.client.get(base)
    items = review_ui.client.get(f"{base}/items")
    sources = review_ui.client.get(f"{base}/sources")

    assert roster.status_code == 200
    assert manifest.revision.digest in roster.text
    assert revision_id in roster.text
    assert f'data-roster-item="{review.correction_item_id}"' in roster.text
    assert f'data-roster-item="{review.rejected_item_id}"' in roster.text
    assert f'data-roster-source="{review.unaccounted_source_id}"' in roster.text
    assert "no canonical memory" not in roster.text

    assert items.status_code == 200
    assert 'data-change-kind="correction"' in items.text
    assert 'data-change-kind="new_memory"' in items.text
    assert 'data-item-status="rejected"' in items.text
    for predecessor_value in (
        "fact",
        "The synthetic amber lamp is lit on Saturday.",
        "2031-02-03",
        "2031-12-31",
        "origin",
        "restricted",
        "琥珀灯在周六点亮",
    ):
        assert predecessor_value in items.text
    for proposal_value in (
        "event",
        "The synthetic amber lamp is lit on Sunday.",
        "2032-04-05",
        "2032-09-09",
        "revised",
        "sensitive",
        "琥珀灯改在周日点亮",
    ):
        assert proposal_value in items.text
    assert f'href="/sources/{review.correction_source_id}"' in items.text
    assert f'href="/memories/{review.predecessor_id}"' in items.text

    assert sources.status_code == 200
    assert 'data-coverage="unaccounted"' in sources.text
    assert 'data-coverage="no_memory"' in sources.text
    assert 'data-coverage="used"' in sources.text
    assert "Synthetic source records no canonical memory." in sources.text
    assert f'href="/inbox/batches/{review.batch_id}"' in sources.text
    assert "Accounted 2 of 3" in sources.text
    assert "Unaccounted 1" in sources.text


@pytest.mark.parametrize("operation", (*OPERATIONS, "add_guard_link"))
def test_owner_edit_creates_new_revision_with_new_digest(
    operation: str,
    review_ui: ReviewUi,
) -> None:
    """Catch any bounded owner operation mutating history or losing provenance."""
    before = review_ui.current_revision().revision
    after = review_ui.submit(operation).revision

    landed = review_ui.client.get(f"/reviews/{review_ui.review.change_set_id}")

    assert after.predecessor_revision_id == before.revision_id
    assert after.revision_id != before.revision_id
    assert after.digest != before.digest
    assert after.adapter_origin == "owner_ui"
    assert landed.status_code == 200
    assert after.digest in landed.text
    assert before.digest not in landed.text


def test_owner_edits_never_autosave_and_get_creates_no_revision(
    review_ui: ReviewUi,
) -> None:
    """Catch a GET that mutates, leases, or silently accepts a partial page."""
    review = review_ui.review
    before = review_ui.current_revision().revision
    revision_id = before.revision_id
    base = f"/reviews/{review.change_set_id}/revisions/{revision_id}"

    for path in (
        "/reviews",
        base,
        f"{base}/items",
        f"{base}/sources",
        f"{base}/blockers",
        f"{base}/edits/reject_item?item_id={review.correction_item_id}",
        f"{base}/edits/set_source_no_memory?source_id={review.no_memory_source_id}",
    ):
        assert review_ui.client.get(path).status_code == 200
    after = review_ui.current_revision().revision

    assert after == before


def test_source_accounting_repair_restores_complete_coverage(
    review_ui: ReviewUi,
) -> None:
    """Catch an unaccounted source that cannot be repaired inside the UI."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    unaccounted = [
        source for source in manifest.source_roster if source.coverage == "unaccounted"
    ]

    assert [source.source_id for source in unaccounted] == [
        review.unaccounted_source_id
    ]
    assert manifest.validation_state == "blocked"
    assert manifest.blocker_count == 1

    added = review_ui.submit("add_item")
    assert added.validation_state == "valid"
    assert all(source.coverage != "unaccounted" for source in added.source_roster)

    cleared = review_ui.submit("clear_source_no_memory")
    assert cleared.validation_state == "blocked"
    assert {source.source_id: source.coverage for source in cleared.source_roster}[
        review.no_memory_source_id
    ] == "unaccounted"

    explicit = review_ui.submit("set_source_no_memory")
    coverage = {source.source_id: source.coverage for source in explicit.source_roster}
    assert explicit.validation_state == "valid"
    assert coverage[review.no_memory_source_id] == "no_memory"


def test_blocker_section_reconciles_with_the_compact_manifest(
    review_ui: ReviewUi,
) -> None:
    """Catch a blocker count that does not survive exhaustive traversal."""
    review = review_ui.review
    review_ui.submit("reject_item")
    manifest = review_ui.current_revision()
    revision_id = manifest.revision.revision_id
    blockers = review_ui.client.get(
        f"/reviews/{review.change_set_id}/revisions/{revision_id}/blockers"
    )

    assert manifest.blocker_count == 2
    assert manifest.validation_state == "blocked"
    assert blockers.text.count("data-blocker-row") == 2
    assert 'data-blocker-code="unaccounted_source"' in blockers.text
    assert "cannot be approved" in blockers.text


def test_all_rejected_review_keeps_every_item_and_reason_visible(
    review_ui: ReviewUi,
) -> None:
    """Catch rejected items or no-memory reasons vanishing from the review."""
    review = review_ui.review
    review_ui.submit("reject_item")
    review_ui.submit("set_source_no_memory")
    manifest = review_ui.current_revision()
    revision_id = manifest.revision.revision_id
    base = f"/reviews/{review.change_set_id}/revisions/{revision_id}"
    roster = review_ui.client.get(base)
    items = review_ui.client.get(f"{base}/items")
    sources = review_ui.client.get(f"{base}/sources")

    assert all(item.status == "rejected" for item in manifest.item_roster)
    assert len(manifest.item_roster) == 2
    assert roster.text.count("data-roster-item=") == 2
    assert items.text.count('data-item-status="rejected"') == 2
    assert "Synthetic reviewed decision: no canonical memory." in sources.text
    assert sources.text.count('data-coverage="unaccounted"') == 2
    assert sources.text.count('data-coverage="no_memory"') == 1


def test_ambiguous_or_duplicate_evidence_creates_no_revision(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an ambiguous excerpt silently becoming an immutable revision."""
    batch_id, sources = _capture(
        synthetic_store,
        {"ambiguous.md": b"repeat marker line\nrepeat marker line\n"},
        sensitivity=Sensitivity.NORMAL,
    )
    source = sources["ambiguous.md"]
    draft = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    review = SyntheticReview(
        paths=synthetic_store,
        batch_id=batch_id,
        change_set_id=draft.change_set_id,
        revision_id=draft.revision_id,
        digest=draft.digest,
        lineage_id="lin_" + "0" * 32,
        predecessor_id="mem_" + "0" * 32,
        correction_item_id="synthetic-absent",
        rejected_item_id="synthetic-absent",
        correction_source_id=source.source_id,
        unaccounted_source_id=source.source_id,
        no_memory_source_id=source.source_id,
        unaccounted_excerpt="repeat marker line",
    )
    ui = _authenticated_review_ui(synthetic_store, review)
    before = ui.current_revision().revision
    posted = ui.post_form(
        ui.edit_path("add_item"),
        [
            ("expected_digest", before.digest),
            ("kind", "insight"),
            ("statement", "Synthetic ambiguous evidence proposal."),
            ("sensitivity", "normal"),
            ("tag.0", "ambiguous"),
            ("evidence.0.source_id", source.source_id),
            ("evidence.0.excerpt", "repeat marker line"),
        ],
    )
    location = posted.headers["location"]
    response = ui.client.get(location)

    assert posted.status_code == 303, posted.text
    assert "repeat marker line" not in location
    assert response.status_code == 200
    assert "evidence excerpt is ambiguous" in response.text
    assert ui.current_revision().revision == before


def test_duplicate_lineage_successor_is_blocked_and_visible(
    review_ui: ReviewUi,
) -> None:
    """Catch two successors for one lineage passing owner-visible validation."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    response = _refuse_edit(
        review_ui,
        "add_item",
        [
            ("kind", "event"),
            ("statement", "A second synthetic successor for one lineage."),
            ("sensitivity", "sensitive"),
            ("target_lineage_id", review.lineage_id),
            ("expected_head_id", review.predecessor_id),
            ("tag.0", "duplicate"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", review.unaccounted_excerpt),
        ],
    )

    assert response.status_code == 200
    assert "draft has multiple successors for one lineage" in response.text
    assert review_ui.current_revision().revision == manifest.revision


def _manifest_for_parser(review: SyntheticReview) -> OwnerReviewManifest:
    return OwnerApplicationService(review.paths).get_review_manifest(
        review.change_set_id
    )


def _upload_file() -> UploadFile:
    return UploadFile(
        filename="synthetic-upload.md",
        file=None,  # type: ignore[arg-type]
        headers=Headers({"content-type": "text/markdown"}),
    )


@pytest.mark.parametrize(
    ("intent", "fields"),
    [
        ("reject_item", [("item_id", "synthetic-correction"), ("unknown", "x")]),
        # Two distinct items is a selection; the same item twice is a
        # malformed form whose second operation nobody asked for.
        (
            "reject_item",
            [
                ("item_id", "synthetic-correction"),
                ("item_id", "synthetic-correction"),
            ],
        ),
        ("reject_item", [("item_id", "synthetic-absent")]),
        (
            "reject_item",
            [("item_id", "synthetic-correction"), ("item_id", "synthetic-absent")],
        ),
        ("restore_item", []),
        ("clear_source_no_memory", [("source_id", "src_" + "0" * 32)]),
        ("set_source_no_memory", [("source_id", "src_" + "0" * 32), ("reason", "x")]),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic gapped tag proposal."),
                ("sensitivity", "sensitive"),
                ("tag.1", "gapped"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic duplicate tag index proposal."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("tag.0", "two"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic gapped evidence proposal."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("evidence.1.source_id", "PLACEHOLDER"),
                ("evidence.1.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic evidence intent conflict."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
                ("evidence.0.source_level", "true"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "not-a-kind"),
                ("statement", "Synthetic invalid enum proposal."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "x" * (MAX_STATEMENT_BYTES + 1)),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic oversized tag proposal."),
                ("sensitivity", "sensitive"),
                ("tag.0", "t" * (MAX_TAG_BYTES + 1)),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic Store-assigned field injection."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("client_item_id", "browser-chosen-identity"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic adapter origin injection."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("adapter_origin", "mcp"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic recorded-time injection."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("recorded_at", "0"),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
        (
            "add_item",
            [
                ("kind", "insight"),
                ("statement", "Synthetic application identity injection."),
                ("sensitivity", "sensitive"),
                ("tag.0", "one"),
                ("application_id", "app_" + "0" * 32),
                ("evidence.0.source_id", "PLACEHOLDER"),
                ("evidence.0.excerpt", "PLACEHOLDER"),
            ],
        ),
    ],
)
def test_change_edit_form_rejects_invalid_or_privileged_input(
    intent: str,
    fields: list[tuple[str, str]],
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a parser accepting unknown, duplicate, gapped, or Store-owned keys."""
    review = _build_synthetic_review(synthetic_store)
    manifest = _manifest_for_parser(review)
    resolved: list[tuple[str, str | UploadFile]] = [
        (
            name,
            review.unaccounted_source_id
            if name.endswith("source_id") and value == "PLACEHOLDER"
            else review.unaccounted_excerpt
            if value == "PLACEHOLDER"
            else value,
        )
        for name, value in fields
    ]

    with pytest.raises(InvalidArgumentError):
        parse_change_edit_form(
            FormData(resolved),
            intent=intent,  # type: ignore[arg-type]
            current=manifest,
        )


def test_change_edit_form_rejects_every_uploaded_value(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a multipart file value reaching a bounded review edit operation."""
    review = _build_synthetic_review(synthetic_store)
    manifest = _manifest_for_parser(review)

    with pytest.raises(InvalidArgumentError):
        parse_change_edit_form(
            FormData([("item_id", _upload_file())]),
            intent="reject_item",
            current=manifest,
        )


@pytest.mark.parametrize("field", ["tag", "evidence"])
@pytest.mark.parametrize(
    "raw_index",
    [
        pytest.param("²", id="non-decimal-digit"),
        pytest.param("9" * 5_000, id="oversized-integer"),
    ],
)
def test_change_edit_form_refuses_unconvertible_numeric_indices(
    field: str,
    raw_index: str,
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an invalid index escaping the typed refusal before draft editing."""
    review = _build_synthetic_review(synthetic_store)
    manifest = _manifest_for_parser(review)
    name = f"tag.{raw_index}" if field == "tag" else f"evidence.{raw_index}.excerpt"

    with pytest.raises(InvalidArgumentError):
        parse_change_edit_form(
            FormData([(name, "Synthetic numeric-index refusal.")]),
            intent="add_item",
            current=manifest,
        )


def test_change_edit_form_preserves_ordered_tags_and_evidence(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch reordered or collapsed indexed tag and evidence fields."""
    review = _build_synthetic_review(synthetic_store)
    manifest = _manifest_for_parser(review)
    parsed = parse_change_edit_form(
        FormData(
            [
                ("kind", "insight"),
                ("statement", "Synthetic ordered round-trip proposal."),
                ("sensitivity", "sensitive"),
                ("tag.0", "gamma"),
                ("tag.1", "alpha"),
                ("tag.2", "beta"),
                ("evidence.0.source_id", review.unaccounted_source_id),
                ("evidence.0.excerpt", "Synthetic omitted-proposal"),
                ("evidence.1.source_id", review.unaccounted_source_id),
                ("evidence.1.excerpt", "for owner repair"),
            ]
        ),
        intent="add_item",
        current=manifest,
    )

    assert len(parsed) == 1
    edit = parsed[0]
    assert isinstance(edit, AddItem)
    assert edit.memory.tags == ("gamma", "alpha", "beta")
    assert [item.excerpt for item in edit.evidence] == [
        "Synthetic omitted-proposal",
        "for owner repair",
    ]
    assert edit.client_item_id.startswith("itm_")
    assert edit.evidence[0].blob_digest == next(
        source.blob_digest
        for source in manifest.source_roster
        if source.source_id == review.unaccounted_source_id
    )


@pytest.mark.parametrize("characters", (256, 257))
def test_review_reference_uses_the_kernel_unicode_character_bound(
    review_ui: ReviewUi, characters: int
) -> None:
    """Catch valid multibyte identifiers being refused by a narrower byte limit."""
    item_id = "合" * characters
    form = FormData(
        [
            ("guard_item_id", item_id),
            ("governed_item_id", review_ui.review.correction_item_id),
        ]
    )
    if characters > 256:
        with pytest.raises(InvalidArgumentError):
            parse_change_edit_form(
                form, intent="add_guard_link", current=review_ui.current_revision()
            )
    else:
        edits = parse_change_edit_form(
            form, intent="add_guard_link", current=review_ui.current_revision()
        )
        assert len(edits) == 1
        assert isinstance(edits[0], AddGuardLink)
        assert edits[0].link.guard_item_id == item_id


def test_ordered_tags_and_evidence_round_trip_through_the_edit_route(
    review_ui: ReviewUi,
) -> None:
    """Catch ordered owner input losing its order inside the immutable revision."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    response = review_ui.post_form(
        review_ui.edit_path("add_item"),
        [
            ("expected_digest", manifest.revision.digest),
            ("kind", "insight"),
            ("statement", "Synthetic ordered evidence proposal."),
            ("sensitivity", "sensitive"),
            ("tag.0", "gamma"),
            ("tag.1", "alpha"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", "Synthetic omitted-proposal"),
            ("evidence.1.source_id", review.unaccounted_source_id),
            ("evidence.1.excerpt", "for owner repair"),
        ],
    )
    updated = review_ui.current_revision()
    items = review_ui.client.get(
        f"/reviews/{review.change_set_id}"
        f"/revisions/{updated.revision.revision_id}/items"
    )

    assert response.status_code == 303
    assert "Synthetic ordered evidence proposal." in items.text
    assert items.text.index("Synthetic omitted-proposal") < items.text.index(
        "for owner repair"
    )
    assert items.text.index("gamma") < items.text.index("alpha")


def _padding_fields(*, count: int, size: int) -> list[tuple[str, str]]:
    return [(f"pad.{index}", "x" * size) for index in range(count)]


def _sized_body(fields: Sequence[tuple[str, str]], *, total: int) -> bytes:
    body = urllib.parse.urlencode(list(fields)).encode("ascii")
    assert len(body) <= total
    index = 0
    while len(body) < total:
        remaining = total - len(body)
        name = f"pad.{index}".encode("ascii")
        overhead = len(name) + 2
        if remaining <= overhead:
            body += b"x" * remaining
            break
        body += b"&" + name + b"=" + b"x" * min(remaining - overhead, 60_000)
        index += 1
    assert len(body) == total
    return body


def test_review_edit_body_bound_is_enforced_before_form_construction(
    review_ui: ReviewUi,
) -> None:
    """Catch an oversized edit body allocating a FormData or a pending form."""
    review = review_ui.review
    before = review_ui.current_revision().revision
    path = review_ui.edit_path("reject_item")
    valid_prefix = review_ui.edit_fields("reject_item")
    at_limit = review_ui.post_body(
        path,
        _sized_body(valid_prefix, total=MAX_REVIEW_EDIT_BODY_BYTES),
    )
    above_limit = review_ui.post_body(
        path,
        _sized_body(valid_prefix, total=MAX_REVIEW_EDIT_BODY_BYTES) + b"x",
    )

    # A body exactly at the bound is read and then refused on its content, so
    # it reaches the owner as the explaining redirect; one byte past is never
    # read at all.
    assert at_limit.status_code == 303
    assert "refused=" in at_limit.headers["location"]
    assert above_limit.status_code == 413
    assert review_ui.current_revision().revision == before
    assert review_ui.sessions.pending_review_count(review_ui.session.session_id) == 0
    assert review.change_set_id not in above_limit.text


def test_review_form_field_and_count_bounds_reject_before_any_revision(
    review_ui: ReviewUi,
) -> None:
    """Catch field-count or field-byte expansion past the declared review caps."""
    before = review_ui.current_revision().revision
    path = review_ui.edit_path("reject_item")
    digest = [("expected_digest", before.digest)]

    at_field_bytes = review_ui.post_form(
        path,
        [*digest, ("item_id", "i" * MAX_REVIEW_FORM_FIELD_BYTES)],
    )
    above_field_bytes = review_ui.post_form(
        path,
        [*digest, ("item_id", "i" * (MAX_REVIEW_FORM_FIELD_BYTES + 1))],
    )
    at_field_count = review_ui.post_form(
        path,
        digest + _padding_fields(count=MAX_FORM_FIELDS - 1, size=4),
    )
    above_field_count = review_ui.post_form(
        path,
        digest + _padding_fields(count=MAX_FORM_FIELDS, size=4),
    )
    percent_encoded = review_ui.post_body(
        path,
        b"item_id=" + b"%41" * ((MAX_REVIEW_EDIT_BODY_BYTES - 8) // 3),
    )
    percent_at_field_bytes = review_ui.post_form(
        path,
        [*digest, ("item_id", "é" * (MAX_REVIEW_FORM_FIELD_BYTES // 2))],
    )

    # Fields exactly at a bound are parsed and then refused on their content;
    # anything past a bound is rejected before the form is ever constructed.
    assert at_field_bytes.status_code == 303
    assert above_field_bytes.status_code == 413
    assert at_field_count.status_code == 303
    assert above_field_count.status_code in {400, 413}
    assert percent_encoded.status_code == 413
    assert percent_at_field_bytes.status_code == 303
    assert review_ui.current_revision().revision == before
    assert review_ui.sessions.pending_review_count(review_ui.session.session_id) == 0


def test_pending_review_state_machine_is_session_bound_and_one_use() -> None:
    """Catch replay, cross-session reuse, or unbounded retained edit forms."""
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=100,
    )
    session = sessions.exchange_bootstrap(
        secret=BOOTSTRAP,
        exact_host=EXACT_HOST,
        now_ns=100,
    )
    assert session is not None

    def form(marker: str, now_ns: int = 200) -> UiPendingReviewForm:
        return UiPendingReviewForm(
            change_set_id="chg_" + "0" * 32,
            expected_revision_id="csr_" + "0" * 32,
            expected_digest="a" * 64,
            operation="reject_item",
            normalized_fields=(("item_id", marker),),
            base_target_fingerprint="b" * 64,
            expires_at_ns=now_ns + UI_PENDING_REVIEW_TTL_NS,
        )

    handles = [
        sessions.remember_pending_review(session.session_id, form(f"item-{index}"))
        for index in range(MAX_PENDING_REVIEW_FORMS + 1)
    ]
    assert len(set(handles)) == len(handles)
    assert sessions.pending_review_count(session.session_id) == MAX_PENDING_REVIEW_FORMS
    assert (
        sessions.resolve_pending_review(session.session_id, handles[0], now_ns=200)
        is None
    )

    handle = handles[-1]
    assert (
        sessions.resolve_pending_review(session.session_id, handle, now_ns=200)
        is not None
    )
    assert (
        sessions.resolve_pending_review(session.session_id, handle, now_ns=201)
        is not None
    )
    assert sessions.resolve_pending_review("other-session", handle, now_ns=201) is None

    lease = sessions.lease_pending_review(session.session_id, handle, now_ns=202)
    assert isinstance(lease, PendingReviewLease)
    assert lease.state == "in_flight"
    with pytest.raises(InvalidArgumentError):
        sessions.lease_pending_review(session.session_id, handle, now_ns=203)
    sessions.mark_pending_review_retryable(lease)
    released = sessions.lease_pending_review(
        session.session_id,
        handle,
        now_ns=204,
    )
    sessions.mark_pending_review_conflict(
        released,
        current_revision_id="csr_" + "1" * 32,
        current_digest="c" * 64,
        current_target_fingerprint="d" * 64,
    )
    conflict = sessions.resolve_pending_review(
        session.session_id,
        handle,
        now_ns=205,
    )
    assert isinstance(conflict, UiPendingReviewConflict)
    assert conflict.current_revision_id == "csr_" + "1" * 32
    with pytest.raises(InvalidArgumentError):
        sessions.lease_pending_review(session.session_id, handle, now_ns=206)

    conflict_lease = sessions.lease_pending_review_conflict(
        session.session_id,
        handle,
        selected_revision_id="csr_" + "1" * 32,
        selected_digest="c" * 64,
        selected_target_fingerprint="d" * 64,
        now_ns=207,
    )
    assert isinstance(conflict_lease, PendingReviewConflictLease)
    sessions.complete_pending_review(conflict_lease)
    assert (
        sessions.resolve_pending_review(session.session_id, handle, now_ns=208) is None
    )

    expiring = sessions.remember_pending_review(session.session_id, form("expiring"))
    assert (
        sessions.resolve_pending_review(
            session.session_id,
            expiring,
            now_ns=200 + UI_PENDING_REVIEW_TTL_NS,
        )
        is None
    )
    survivor = sessions.remember_pending_review(session.session_id, form("survivor"))
    sessions.invalidate_session(session.session_id)
    assert (
        sessions.resolve_pending_review(session.session_id, survivor, now_ns=300)
        is None
    )


def test_busy_writer_redirects_to_a_get_only_one_use_retry_view(
    review_ui: ReviewUi,
) -> None:
    """Catch a repeated mutation, a leaked value in a URL, or a lost owner edit."""
    review = review_ui.review
    before = review_ui.current_revision().revision
    path = review_ui.edit_path("reject_item")
    fields = review_ui.edit_fields("reject_item")
    with _writer_lock(review.paths):
        busy = review_ui.post_form(path, fields)
    location = busy.headers["location"]

    assert busy.status_code == 303
    assert location.startswith(f"/reviews/{review.change_set_id}/pending/")
    assert review.correction_item_id not in location
    assert review_ui.current_revision().revision == before

    first = review_ui.client.get(location)
    second = review_ui.client.get(location)
    assert first.status_code == 200
    assert second.status_code == 200
    assert "Retry the owner edit" in first.text
    assert review_ui.current_revision().revision == before

    unauthenticated = review_ui.client.post(
        location,
        content=b"csrf=x",
        headers={
            "Origin": PUBLIC_ORIGIN,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    assert unauthenticated.status_code == 403
    assert review_ui.current_revision().revision == before

    retried = review_ui.post_form(
        location,
        [("csrf", review_ui.session.csrf_token)],
    )
    after = review_ui.current_revision().revision
    assert retried.status_code == 303
    assert after.predecessor_revision_id == before.revision_id
    assert after.adapter_origin == "owner_ui"

    replayed = review_ui.post_form(
        location,
        [("csrf", review_ui.session.csrf_token)],
    )
    assert replayed.status_code == 404
    assert review_ui.current_revision().revision == after


def test_repeated_busy_result_returns_the_same_retryable_form(
    review_ui: ReviewUi,
) -> None:
    """Catch a leased retry form stranded in flight after a second busy writer."""
    review = review_ui.review
    before = review_ui.current_revision().revision
    path = review_ui.edit_path("reject_item")
    fields = review_ui.edit_fields("reject_item")
    with _writer_lock(review.paths):
        busy = review_ui.post_form(path, fields)
        location = busy.headers["location"]
        again = review_ui.post_form(
            location,
            [("csrf", review_ui.session.csrf_token)],
        )

    assert again.status_code == 303
    assert again.headers["location"] == location
    assert review_ui.client.get(location).status_code == 200
    assert review_ui.current_revision().revision == before

    retried = review_ui.post_form(
        location,
        [("csrf", review_ui.session.csrf_token)],
    )
    assert retried.status_code == 303
    assert (
        review_ui.current_revision().revision.predecessor_revision_id
        == before.revision_id
    )


class RacingReviewService:
    """Wrap the real owner service and land one concurrent core edit."""

    def __init__(
        self,
        service: OwnerApplicationService,
        race: Any,
        *,
        race_on: int = 1,
    ) -> None:
        self._service = service
        self._race = race
        self._race_on = race_on
        self.calls = 0
        self.races = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._service, name)

    def edit_review(
        self,
        change_set_id: str,
        expected_revision_id: str,
        edits: Sequence[Any],
    ) -> OwnerReviewManifest:
        self.calls += 1
        if self.calls == self._race_on:
            self.races += 1
            self._race()
        return self._service.edit_review(change_set_id, expected_revision_id, edits)


def _concurrent_unrelated_edit(review: SyntheticReview, reason: str) -> None:
    manifest = OwnerApplicationService(review.paths).get_review_manifest(
        review.change_set_id
    )
    edit_change_set(
        review.paths,
        review.change_set_id,
        manifest.revision.revision_id,
        (SetSourceNoMemory(source_id=review.unaccounted_source_id, reason=reason),),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )


def _concurrent_same_target_edit(review: SyntheticReview) -> None:
    manifest = OwnerApplicationService(review.paths).get_review_manifest(
        review.change_set_id
    )
    edit_change_set(
        review.paths,
        review.change_set_id,
        manifest.revision.revision_id,
        (
            ReplaceItem(
                item_id=review.correction_item_id,
                memory=MemoryFields(
                    kind=MemoryKind.EVENT,
                    statement="A synthetic concurrent same-target rewrite.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("concurrent",),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=review.lineage_id,
                    expected_head_id=review.predecessor_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=review.correction_source_id,
                        blob_digest=next(
                            item.blob_digest
                            for item in OwnerApplicationService(review.paths)
                            .get_review_manifest(review.change_set_id)
                            .source_roster
                            if item.source_id == review.correction_source_id
                        ),
                        excerpt="琥珀灯改在周日点亮",
                    ),
                ),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )


def test_stale_edit_applies_nothing_and_shows_both_typed_targets(
    review_ui: ReviewUi,
) -> None:
    """Catch a silent rebase or a conflict view missing the compared states."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("reject_item", displayed.revision.revision_id)
    fields = review_ui.edit_fields("reject_item")
    _concurrent_unrelated_edit(review, "Synthetic concurrent unrelated decision.")
    current = review_ui.current_revision()

    stale = review_ui.post_form(path, fields)
    location = stale.headers["location"]
    view = review_ui.client.get(location)

    assert stale.status_code == 303
    assert location.startswith(f"/reviews/{review.change_set_id}/pending/")
    assert view.status_code == 200
    assert displayed.revision.revision_id in view.text
    assert displayed.revision.digest in view.text
    assert current.revision.revision_id in view.text
    assert current.revision.digest in view.text
    assert "Retry against current revision" in view.text
    assert "data-conflict-old-target" in view.text
    assert "data-conflict-current-target" in view.text
    assert 'data-conflict-proposed-change="reject_item"' in view.text
    assert review_ui.current_revision().revision == current.revision
    assert review_ui.client.get(location).status_code == 200
    assert review_ui.current_revision().revision == current.revision


def test_compatible_unrelated_successor_is_retried_exactly_once(
    review_ui: ReviewUi,
) -> None:
    """Catch a retry that rebases silently, applies twice, or never applies."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("reject_item", displayed.revision.revision_id)
    fields = review_ui.edit_fields("reject_item")
    _concurrent_unrelated_edit(review, "Synthetic concurrent unrelated decision.")
    current = review_ui.current_revision()
    location = review_ui.post_form(path, fields).headers["location"]

    retried = review_ui.post_form(
        f"{location}/current",
        [("csrf", review_ui.session.csrf_token)],
    )
    after = review_ui.current_revision()
    replayed = review_ui.post_form(
        f"{location}/current",
        [("csrf", review_ui.session.csrf_token)],
    )

    assert retried.status_code == 303
    assert after.revision.predecessor_revision_id == current.revision.revision_id
    assert after.revision.adapter_origin == "owner_ui"
    assert {item.item_id: item.status for item in after.item_roster}[
        review.correction_item_id
    ] == "rejected"
    assert replayed.status_code == 404
    assert review_ui.current_revision().revision == after.revision


def test_same_target_change_stays_conflicted_and_creates_nothing(
    review_ui: ReviewUi,
) -> None:
    """Catch a retry that ignores an exact same-target concurrent rewrite."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("replace_item", displayed.revision.revision_id)
    fields = review_ui.edit_fields("replace_item")
    _concurrent_same_target_edit(review)
    current = review_ui.current_revision()
    location = review_ui.post_form(path, fields).headers["location"]

    refused = review_ui.post_form(
        f"{location}/current",
        [("csrf", review_ui.session.csrf_token)],
    )
    view = review_ui.client.get(location)

    assert refused.status_code == 303
    assert refused.headers["location"] == location
    assert view.status_code == 200
    assert "Retry against current revision" in view.text
    assert review_ui.current_revision().revision == current.revision


def test_second_race_during_retry_returns_a_refreshed_conflict(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a leased retry applying against a revision that already moved."""
    review = _build_synthetic_review(synthetic_store)
    service = RacingReviewService(
        OwnerApplicationService(synthetic_store),
        lambda: _concurrent_unrelated_edit(review, "Synthetic second race."),
        race_on=2,
    )
    ui = _authenticated_review_ui(synthetic_store, review, service)
    displayed = ui.current_revision()
    path = ui.edit_path("reject_item", displayed.revision.revision_id)
    fields = ui.edit_fields("reject_item")
    _concurrent_unrelated_edit(review, "Synthetic first race.")
    location = ui.post_form(path, fields).headers["location"]
    raced = ui.current_revision()

    retried = ui.post_form(f"{location}/current", [("csrf", ui.session.csrf_token)])
    view = ui.client.get(location)
    settled = ui.current_revision()

    assert service.races == 1
    assert retried.status_code == 303
    assert retried.headers["location"] == location
    assert view.status_code == 200
    assert settled.revision.revision_id != raced.revision.revision_id
    assert settled.revision.adapter_origin == "mcp"
    assert settled.revision.revision_id in view.text
    assert {item.item_id: item.status for item in settled.item_roster}[
        review.correction_item_id
    ] == "active"


def test_add_item_retry_requires_every_referenced_source_to_match(
    review_ui: ReviewUi,
) -> None:
    """Catch an add retry landing after its referenced source accounting changed."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("add_item", displayed.revision.revision_id)
    fields = review_ui.edit_fields("add_item")
    _concurrent_unrelated_edit(review, "Synthetic concurrent source decision.")
    current = review_ui.current_revision()
    location = review_ui.post_form(path, fields).headers["location"]

    refused = review_ui.post_form(
        f"{location}/current",
        [("csrf", review_ui.session.csrf_token)],
    )

    assert refused.status_code == 303
    assert refused.headers["location"] == location
    assert review_ui.current_revision().revision == current.revision


def _synthetic_status() -> OwnerStatus:
    return OwnerStatus(
        store=StoreStatus(
            product="memory",
            schema_version=1,
            store_id="0" * 32,
            source_count=64,
            memory_count=0,
            searchable_count=64,
            unsearchable_count=0,
            reindex_required=False,
            mcp_contract_digest="1" * 64,
            skill_digest="2" * 64,
            pending_review_count=1,
        ),
        runtime_mode=RuntimeMode.PERSONAL,
        availability="available",
        pending_review_count=1,
        projections=ProjectionCoverage(
            sources=SourceProjectionCoverage(
                total_captures=64,
                expected_searchable_captures=64,
                indexed_expected_captures=64,
                missing_expected_rows=0,
                inherently_unsearchable_captures=0,
                unexpected_or_duplicate_rows=0,
            ),
            memories=MemoryProjectionCoverage(
                current_heads=0,
                indexed_current_heads=0,
                missing_current_head_rows=0,
                unexpected_or_duplicate_noncurrent_rows=0,
                historical_revisions_not_expected=0,
            ),
        ),
        runtime_display_path="Synthetic Store Home",
        inbox=InboxStatus(
            inbox_display_path="Synthetic Inbox",
            staged_visible_entry_count=0,
        ),
    )


RENDER_CHANGE_SET_ID = "chg_" + "b" * 32
RENDER_REVISION_ID = "csr_" + "b" * 32
RENDER_BATCH_ID = "bat_" + "b" * 32
RENDER_DIGEST = "c" * 64


def _render_revision(
    *,
    item_count: int,
    source_count: int,
    blocker_count: int,
    digest: str = RENDER_DIGEST,
) -> OwnerChangeSetRevisionSummary:
    return OwnerChangeSetRevisionSummary(
        change_set_id=RENDER_CHANGE_SET_ID,
        revision_id=RENDER_REVISION_ID,
        predecessor_revision_id=None,
        digest=digest,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
        recorded_at=2_130_000_000,
        lifecycle="current_draft",
        item_count=item_count,
        batch_source_count=source_count,
        accounted_source_count=source_count - blocker_count,
        unaccounted_source_count=blocker_count,
    )


@dataclass(slots=True)
class RenderOnlyReviewService:
    """Serve exact bounded owner read models without opening any Store."""

    roster_items: int = 0
    roster_sources: int = 0
    decisions: tuple[OwnerSourceDecision, ...] = ()
    blockers: tuple[OwnerReviewBlocker, ...] = ()
    canonical_review: str | None = None
    digest: str = RENDER_DIGEST
    comparisons: tuple[OwnerReviewItemComparison, ...] = ()
    guard_links: tuple[OwnerDraftGuardLink, ...] = ()
    revoked_guard_links: tuple[OwnerDraftGuardLink, ...] = ()
    roster_item_ids: tuple[str, ...] = ()

    def render_approval_review(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str:
        assert (change_set_id, revision_id, digest) == (
            RENDER_CHANGE_SET_ID,
            RENDER_REVISION_ID,
            self.digest,
        )
        return (
            "Digest: " + self.digest + "\nPayload:\n{}\n"
            if self.canonical_review is None
            else self.canonical_review
        )

    def get_status(self) -> OwnerStatus:
        return _synthetic_status()

    def get_review_manifest(
        self,
        change_set_id: str,
        revision_id: str | None = None,
    ) -> OwnerReviewManifest:
        assert change_set_id == RENDER_CHANGE_SET_ID
        item_ids = self.roster_item_ids or tuple(
            f"itm_{index:032d}" for index in range(self.roster_items)
        )
        return OwnerReviewManifest(
            batch_id=RENDER_BATCH_ID,
            batch_sealed_at=2_130_000_000,
            revision=_render_revision(
                item_count=len(item_ids),
                source_count=self.roster_sources,
                blocker_count=len(self.blockers),
                digest=self.digest,
            ),
            blocker_count=len(self.blockers),
            item_roster=tuple(
                OwnerReviewRosterItem(
                    ordinal=index,
                    item_id=item_id,
                    status="active",
                    change_kind="new_memory",
                    target_lineage_id=None,
                    statement_preview=(
                        "<script>synthetic-review-preview</script>"
                        if index == 0
                        else '"' * 160
                    ),
                    statement_elided=index != 0,
                )
                for index, item_id in enumerate(item_ids)
            ),
            source_roster=tuple(
                OwnerReviewRosterSource(
                    ordinal=index,
                    source_id=f"src_{index:032d}",
                    blob_digest=f"{index:064d}",
                    coverage="used",
                )
                for index in range(self.roster_sources)
            ),
            guard_links=self.guard_links,
            revoked_guard_links=self.revoked_guard_links,
        )

    def list_change_sets(
        self,
        cursor: str | None,
        limit: int,
        state: str | None,
    ) -> OwnerPage[OwnerChangeSetSummary]:
        assert cursor is None
        assert limit >= 1
        assert state in {"draft", "applied"}
        return OwnerPage(items=(), next_cursor=None, has_more=False)

    def list_change_set_revisions(
        self,
        change_set_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerChangeSetRevisionSummary]:
        assert change_set_id == RENDER_CHANGE_SET_ID
        assert limit >= 1
        return _offset_page(
            (
                _render_revision(
                    item_count=self.roster_items,
                    source_count=self.roster_sources,
                    blocker_count=len(self.blockers),
                    digest=self.digest,
                ),
            ),
            cursor,
            limit,
        )

    def list_review_items(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewItemComparison]:
        assert change_set_id == RENDER_CHANGE_SET_ID
        assert revision_id == RENDER_REVISION_ID
        assert 1 <= limit <= UI_REVIEW_ITEM_PAGE_LIMIT
        return _offset_page(self.comparisons, cursor, limit)

    def get_review_item(
        self,
        change_set_id: str,
        revision_id: str,
        item_id: str,
    ) -> OwnerReviewItemComparison:
        assert change_set_id == RENDER_CHANGE_SET_ID
        assert revision_id == RENDER_REVISION_ID
        return next(item for item in self.comparisons if item.item_id == item_id)

    def list_review_source_decisions(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceDecision]:
        assert change_set_id == RENDER_CHANGE_SET_ID
        assert revision_id == RENDER_REVISION_ID
        return _offset_page(self.decisions, cursor, limit)

    def list_review_blockers(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewBlocker]:
        assert change_set_id == RENDER_CHANGE_SET_ID
        assert revision_id == RENDER_REVISION_ID
        return _offset_page(self.blockers, cursor, limit)

    def get_review_edit_target(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
        edit: Any,
    ) -> Any:
        raise AssertionError("render-only review service must not resolve targets")

    def edit_review(
        self,
        change_set_id: str,
        expected_revision_id: str,
        edits: Sequence[Any],
    ) -> OwnerReviewManifest:
        raise AssertionError("render-only review service must not mutate")


def _offset_page[T](
    items: tuple[T, ...],
    cursor: str | None,
    limit: int,
) -> OwnerPage[T]:
    start = 0 if cursor is None else int(cursor.removeprefix("at-"))
    visible = items[start : start + limit]
    end = start + len(visible)
    has_more = end < len(items)
    return OwnerPage(
        items=visible,
        next_cursor=f"at-{end}" if has_more else None,
        has_more=has_more,
    )


def _render_ui(service: RenderOnlyReviewService) -> TestClient:
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    application = create_ui_app(
        # Deliberately partial: this fake answers the nine `OwnerUiService`
        # members the review render paths reach, and none of the twenty-four
        # they do not. Stubbing the rest would claim behaviour no assertion
        # here ever reads.
        cast("OwnerUiService", service),
        sessions,
        UnusedFinder(),
        build_test_orchestrator(service, sessions),
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
    return client


def _roster_path() -> str:
    return f"/reviews/{RENDER_CHANGE_SET_ID}/revisions/{RENDER_REVISION_ID}"


def test_maximum_compact_roster_renders_and_cap_plus_one_fails_closed() -> None:
    """Catch an unbounded roster response or a partial approval-bearing page."""
    at_cap = _render_ui(RenderOnlyReviewService(roster_items=256, roster_sources=64))
    above_items = _render_ui(
        RenderOnlyReviewService(roster_items=257, roster_sources=64)
    )
    above_sources = _render_ui(
        RenderOnlyReviewService(roster_items=256, roster_sources=65)
    )

    rendered = at_cap.get(_roster_path())
    overflow_items = above_items.get(_roster_path())
    overflow_sources = above_sources.get(_roster_path())

    assert rendered.status_code == 200
    assert rendered.text.count("data-roster-item=") == 256
    assert rendered.text.count("data-roster-source=") == 64
    assert len(rendered.content) <= MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES
    for overflow in (overflow_items, overflow_sources):
        assert overflow.status_code == 413
        assert "data-roster-item=" not in overflow.text
        assert RENDER_DIGEST not in overflow.text


def test_compact_roster_escapes_preview_and_links_one_exact_item() -> None:
    marker = "<script>synthetic-review-preview</script>"
    service = RenderOnlyReviewService(roster_items=1, roster_sources=1)
    client = _render_ui(service)
    item_id = "itm_00000000000000000000000000000000"

    roster = client.get(_roster_path())

    assert roster.status_code == 200
    assert marker not in roster.text
    assert "&lt;script&gt;synthetic-review-preview&lt;/script&gt;" in roster.text
    assert (
        f'href="{_roster_path()}/items/lookup/exact?item_id={item_id}"' in roster.text
    )


def test_roster_item_link_round_trips_opaque_url_characters() -> None:
    item_id = "synthetic/item?branch=1#owner%view"
    comparison = OwnerReviewItemComparison(
        ordinal=0,
        item_id=item_id,
        status="active",
        change_kind="new_memory",
        proposal=MemoryFields(
            kind=MemoryKind.FACT,
            statement="Synthetic opaque identifier proposal.",
            occurred_on=None,
            valid_from=None,
            valid_to=None,
            tags=("synthetic",),
            sensitivity=Sensitivity.NORMAL,
            target_lineage_id=None,
            expected_head_id=None,
        ),
        predecessor=None,
        proposal_evidence=(),
        predecessor_evidence=(),
    )
    client = _render_ui(
        RenderOnlyReviewService(
            roster_item_ids=(item_id,),
            roster_sources=1,
            comparisons=(comparison,),
        )
    )

    roster = client.get(_roster_path())

    assert roster.status_code == 200
    expected = urllib.parse.urlencode({"item_id": item_id})
    href = f"{_roster_path()}/items/lookup/exact?{expected}"
    assert f'href="{href.replace("&", "&amp;")}"' in roster.text
    direct = client.get(href)
    assert direct.status_code == 200
    assert f'data-review-item="{item_id}"' in direct.text
    for intent in ("replace_item", "reject_item"):
        edit_href = (
            f"{_roster_path()}/edits/{intent}?"
            f"{urllib.parse.urlencode({'item_id': item_id})}"
        )
        assert f'href="{edit_href}"' in direct.text


def test_direct_lookup_does_not_shadow_legacy_item_identifier_path() -> None:
    item_id = "item"
    comparison = OwnerReviewItemComparison(
        ordinal=0,
        item_id=item_id,
        status="active",
        change_kind="new_memory",
        proposal=MemoryFields(
            kind=MemoryKind.FACT,
            statement="Synthetic proposal whose opaque identifier is item.",
            occurred_on=None,
            valid_from=None,
            valid_to=None,
            tags=("synthetic",),
            sensitivity=Sensitivity.NORMAL,
            target_lineage_id=None,
            expected_head_id=None,
        ),
        predecessor=None,
        proposal_evidence=(),
        predecessor_evidence=(),
    )
    client = _render_ui(
        RenderOnlyReviewService(
            roster_item_ids=(item_id,),
            roster_sources=1,
            comparisons=(comparison,),
        )
    )

    legacy = client.get(f"{_roster_path()}/items/{item_id}")

    assert legacy.status_code == 200
    assert f'data-review-item="{item_id}"' in legacy.text


def test_maximum_guard_roster_uses_bounded_previews_inside_response_cap() -> None:
    statement = "&" * MAX_STATEMENT_BYTES
    guard_links = tuple(
        OwnerDraftGuardLink(
            ordinal=index,
            status="active",
            guard_ref=f"lin_guard_{index:04d}",
            governed_ref=f"lin_claim_{index:04d}",
            guard_statement=statement,
            governed_statement=statement,
            guard_sensitivity=Sensitivity.NORMAL,
            governed_sensitivity=Sensitivity.NORMAL,
            guard_kind="lineage",
            governed_kind="lineage",
        )
        for index in range(MAX_GUARD_LINKS)
    )
    client = _render_ui(RenderOnlyReviewService(guard_links=guard_links))
    overflow_client = _render_ui(
        RenderOnlyReviewService(guard_links=(*guard_links, guard_links[0]))
    )

    roster = client.get(_roster_path())
    overflow = overflow_client.get(_roster_path())

    assert roster.status_code == 200
    assert roster.text.count("data-guard-link=") == MAX_GUARD_LINKS
    assert roster.text.count("statement preview ends here") == 2 * MAX_GUARD_LINKS
    assert len(roster.content) <= MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES
    assert overflow.status_code == 413
    assert "data-guard-link=" not in overflow.text
    assert RENDER_DIGEST not in overflow.text


def test_item_comparison_caps_guard_changes_and_links_complete_roster() -> None:
    item_id = "itm_00000000000000000000000000000000"
    statement = "Synthetic statement governed by several proposed caveats."
    comparison = OwnerReviewItemComparison(
        ordinal=0,
        item_id=item_id,
        status="active",
        change_kind="new_memory",
        proposal=MemoryFields(
            kind=MemoryKind.FACT,
            statement=statement,
            occurred_on=None,
            valid_from=None,
            valid_to=None,
            tags=("synthetic",),
            sensitivity=Sensitivity.NORMAL,
            target_lineage_id=None,
            expected_head_id=None,
        ),
        predecessor=None,
        proposal_evidence=(),
        predecessor_evidence=(),
    )
    guard_links = tuple(
        OwnerDraftGuardLink(
            ordinal=index,
            status="active",
            guard_ref=item_id,
            governed_ref=f"lin_{index:032d}",
            guard_statement=statement,
            governed_statement=f"Synthetic governed statement {index}.",
            guard_sensitivity=Sensitivity.NORMAL,
            governed_sensitivity=Sensitivity.NORMAL,
            guard_kind="item",
            governed_kind="lineage",
        )
        for index in range(MAX_REVIEW_GUARD_CHANGES_PER_ITEM + 1)
    )
    client = _render_ui(
        RenderOnlyReviewService(
            roster_items=1,
            roster_sources=1,
            comparisons=(comparison,),
            guard_links=guard_links,
        )
    )

    comparison_page = client.get(f"{_roster_path()}/items")
    roster = client.get(_roster_path())

    assert comparison_page.status_code == roster.status_code == 200
    assert (
        comparison_page.text.count("data-guard-change=")
        == MAX_REVIEW_GUARD_CHANGES_PER_ITEM
    )
    assert (
        f"Showing {MAX_REVIEW_GUARD_CHANGES_PER_ITEM} of {len(guard_links)} "
        "relevant relationship changes." in comparison_page.text
    )
    assert 'href="' + _roster_path() + '"' in comparison_page.text
    assert roster.text.count("data-guard-link=") == len(guard_links)


def test_compact_roster_never_renders_a_no_memory_reason() -> None:
    """Catch owner reason text leaking into the compact approval roster."""
    reason = "&" * MAX_NO_MEMORY_REASON_BYTES
    service = RenderOnlyReviewService(
        roster_items=4,
        roster_sources=UI_STANDARD_PAGE_LIMIT + 1,
        decisions=tuple(
            OwnerSourceDecision(
                ordinal=index,
                source_id=f"src_{index:032d}",
                blob_digest=f"{index:064d}",
                coverage="no_memory",
                reason=reason,
            )
            for index in range(UI_STANDARD_PAGE_LIMIT + 1)
        ),
    )
    client = _render_ui(service)

    roster = client.get(_roster_path())
    decisions = client.get(f"{_roster_path()}/sources")

    assert roster.status_code == 200
    assert "&amp;" * 8 not in roster.text
    assert decisions.status_code == 200
    assert decisions.text.count("data-source-decision=") == UI_STANDARD_PAGE_LIMIT
    assert "&amp;" * 8 in decisions.text
    assert len(decisions.content) <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES
    assert "data-next-sources" in decisions.text


def _maximum_blocker(index: int) -> OwnerReviewBlocker:
    return OwnerReviewBlocker(
        ordinal=index,
        code="stale_expected_head",
        item_id=f"itm{index:0253d}",
        source_id=f"src{index:0253d}",
        expected_head_id=f"mem{index:0253d}",
        current_head_id=f"cur{index:0253d}",
    )


def test_blocker_section_rows_and_pages_stay_inside_their_declared_caps() -> None:
    """Catch a blocker page exceeding its row budget or hiding a blocker."""
    empty = _render_ui(RenderOnlyReviewService(roster_items=1, roster_sources=1))
    one = _render_ui(
        RenderOnlyReviewService(
            roster_items=1,
            roster_sources=1,
            blockers=(_maximum_blocker(0),),
        )
    )
    full = _render_ui(
        RenderOnlyReviewService(
            roster_items=1,
            roster_sources=1,
            blockers=tuple(
                _maximum_blocker(index) for index in range(UI_STANDARD_PAGE_LIMIT + 1)
            ),
        )
    )

    chrome = empty.get(f"{_roster_path()}/blockers")
    single = one.get(f"{_roster_path()}/blockers")
    page = full.get(f"{_roster_path()}/blockers")
    continuation = full.get(
        f"{_roster_path()}/blockers?cursor=at-{UI_STANDARD_PAGE_LIMIT}"
    )

    assert chrome.status_code == 200
    assert single.status_code == 200
    assert len(single.content) - len(chrome.content) <= MAX_REVIEW_ROSTER_ROW_HTML_BYTES
    assert page.status_code == 200
    assert page.text.count("data-blocker-row") == UI_STANDARD_PAGE_LIMIT
    assert len(page.content) <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES
    assert continuation.text.count("data-blocker-row") == 1


MAX_ITEMS_UNDER_TEST = UI_REVIEW_ITEM_PAGE_LIMIT + 1


def _filled(marker: str, size: int) -> str:
    assert len(marker) < size
    return marker + "&" * (size - len(marker))


def _maximum_source_text(prefix: str) -> tuple[str, tuple[str, ...]]:
    excerpts = tuple(
        _filled(f"{prefix}{index:04d}", MAX_EVIDENCE_EXCERPT_BYTES)
        for index in range(MAX_ITEMS_UNDER_TEST * MAX_EVIDENCE_PER_ITEM)
    )
    return "".join(excerpts), excerpts


def _maximum_fields(
    marker: str,
    *,
    target_lineage_id: str | None = None,
    expected_head_id: str | None = None,
) -> MemoryFields:
    return MemoryFields(
        kind=MemoryKind.FACT,
        statement=_filled(f"S{marker}", MAX_STATEMENT_BYTES),
        occurred_on="2033-01-02",
        valid_from="2033-01-02",
        valid_to="2033-12-31",
        tags=tuple(
            _filled(f"T{marker}{index:03d}", MAX_TAG_BYTES) for index in range(MAX_TAGS)
        ),
        sensitivity=Sensitivity.NORMAL,
        target_lineage_id=target_lineage_id,
        expected_head_id=expected_head_id,
    )


@pytest.mark.slow
def test_worst_case_comparison_sections_stay_inside_their_declared_caps(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch one monolithic maximum review or a lost maximum comparison row."""
    predecessor_text, predecessor_excerpts = _maximum_source_text("P")
    proposal_text, proposal_excerpts = _maximum_source_text("Q")
    origin_batch, origin_sources = _capture(
        synthetic_store,
        {"maximum-predecessor.md": predecessor_text.encode()},
        sensitivity=Sensitivity.NORMAL,
    )
    origin_source = origin_sources["maximum-predecessor.md"]
    origin_draft = create_change_set(
        synthetic_store,
        origin_batch,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    origin_ready = edit_change_set(
        synthetic_store,
        origin_draft.change_set_id,
        origin_draft.revision_id,
        tuple(
            AddItem(
                client_item_id=f"synthetic-maximum-predecessor-{item:02d}",
                memory=_maximum_fields(f"P{item:02d}"),
                evidence=tuple(
                    EvidenceInput(
                        source_id=origin_source.source_id,
                        blob_digest=origin_source.blob_digest,
                        excerpt=predecessor_excerpts[
                            item * MAX_EVIDENCE_PER_ITEM + slot
                        ],
                    )
                    for slot in range(MAX_EVIDENCE_PER_ITEM)
                ),
            )
            for item in range(MAX_ITEMS_UNDER_TEST)
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    applied = _apply(synthetic_store, origin_ready)
    service = OwnerApplicationService(synthetic_store)
    lineages = tuple(
        service.get_memory_revision(memory_id).summary.revision.lineage_id
        for memory_id in applied.memory_ids
    )

    batch_id, sources = _capture(
        synthetic_store,
        {"maximum-proposal.md": proposal_text.encode()},
        sensitivity=Sensitivity.NORMAL,
    )
    proposal_source = sources["maximum-proposal.md"]
    draft = create_change_set(
        synthetic_store,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    ready = edit_change_set(
        synthetic_store,
        draft.change_set_id,
        draft.revision_id,
        tuple(
            AddItem(
                client_item_id=f"synthetic-maximum-correction-{item:02d}",
                memory=_maximum_fields(
                    f"Q{item:02d}",
                    target_lineage_id=lineages[item],
                    expected_head_id=applied.memory_ids[item],
                ),
                evidence=tuple(
                    EvidenceInput(
                        source_id=proposal_source.source_id,
                        blob_digest=proposal_source.blob_digest,
                        excerpt=proposal_excerpts[item * MAX_EVIDENCE_PER_ITEM + slot],
                    )
                    for slot in range(MAX_EVIDENCE_PER_ITEM)
                ),
            )
            for item in range(MAX_ITEMS_UNDER_TEST)
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    review = SyntheticReview(
        paths=synthetic_store,
        batch_id=batch_id,
        change_set_id=ready.change_set_id,
        revision_id=ready.revision_id,
        digest=ready.digest,
        lineage_id=lineages[0],
        predecessor_id=applied.memory_ids[0],
        correction_item_id="synthetic-maximum-correction-00",
        rejected_item_id="synthetic-maximum-correction-01",
        correction_source_id=proposal_source.source_id,
        unaccounted_source_id=proposal_source.source_id,
        no_memory_source_id=proposal_source.source_id,
        unaccounted_excerpt=proposal_excerpts[0],
    )
    ui = _authenticated_review_ui(synthetic_store, review)
    base = f"/reviews/{review.change_set_id}/revisions/{review.revision_id}"

    single = ui.client.get(f"{base}/items?limit=1")
    page = ui.client.get(f"{base}/items")
    assert single.status_code == 200
    assert page.status_code == 200
    assert single.text.count("data-review-item=") == 1
    assert page.text.count("data-review-item=") == UI_REVIEW_ITEM_PAGE_LIMIT
    assert len(single.content) > MAX_STATEMENT_BYTES
    assert (
        len(single.content)
        <= STANDARD_PAGE_CHROME_BYTES + MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES
    )
    assert (
        len(page.content)
        <= STANDARD_PAGE_CHROME_BYTES
        + UI_REVIEW_ITEM_PAGE_LIMIT * MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES
    )
    assert len(page.content) <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES

    seen: list[str] = []
    href: str | None = f"{base}/items"
    while href is not None:
        response = ui.client.get(href)
        assert response.status_code == 200
        assert len(response.content) <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES
        seen.extend(_rendered_item_ids(response.text))
        href = _next_href(response.text, "data-next-items")
    manifest = ui.current_revision()

    assert len(seen) == MAX_ITEMS_UNDER_TEST
    assert seen == [item.item_id for item in manifest.item_roster]

    last_item = manifest.item_roster[-1]
    roster = ui.client.get(base)
    direct_path = (
        f"{base}/items/lookup/exact?"
        f"{urllib.parse.urlencode({'item_id': last_item.item_id})}"
    )
    assert f'href="{direct_path}"' in roster.text
    direct = ui.client.get(direct_path)
    assert direct.status_code == 200
    assert _rendered_item_ids(direct.text) == [last_item.item_id]
    assert len(direct.content) <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES


def test_correction_comparison_marks_fields_and_relevant_guard_change(
    review_ui: ReviewUi,
) -> None:
    """Catch a comparison that makes the owner infer what changed."""
    review_ui.submit("restore_item")
    manifest = review_ui.submit("add_guard_link")
    item = next(
        value
        for value in manifest.item_roster
        if value.item_id == review_ui.review.correction_item_id
    )
    path = (
        f"/reviews/{review_ui.review.change_set_id}/revisions/"
        f"{manifest.revision.revision_id}/items/{item.item_id}"
    )

    page = review_ui.client.get(path)

    assert page.status_code == 200
    assert 'data-statement-change="changed"' in page.text
    assert "Saturday</del>" in page.text
    assert "Sunday</ins>" in page.text
    for field in (
        "occurred-on",
        "valid-from",
        "valid-to-or-revisit-horizon",
        "tags",
        "stored-sensitivity",
    ):
        assert f'data-review-field="{field}" data-field-change="changed"' in page.text
    assert 'data-guard-change="proposed"' in page.text
    assert "is governed by" in page.text
    assert "A synthetic rejected interpretation of the omission." in page.text


def test_tag_comparison_uses_tuple_structure_instead_of_joined_display_text(
    review_ui: ReviewUi,
) -> None:
    """Catch one comma-bearing tag colliding with two distinct tags."""
    fields = [
        (name, value)
        for name, value in review_ui.edit_fields("replace_item")
        if not name.startswith("tag.")
    ]
    fields.append(("tag.0", "origin, lamp"))
    response = review_ui.post_form(review_ui.edit_path("replace_item"), fields)
    assert response.status_code == 303
    manifest = review_ui.current_revision()
    item_id = review_ui.review.correction_item_id
    href = urllib.parse.urlencode({"item_id": item_id})

    page = review_ui.client.get(
        f"/reviews/{review_ui.review.change_set_id}/revisions/"
        f"{manifest.revision.revision_id}/items/lookup/exact?{href}"
    )

    assert page.status_code == 200
    assert 'data-review-field="tags" data-field-change="changed"' in page.text
    start = page.text.index('data-review-field="tags"')
    end = page.text.index("</div>", start)
    tags = page.text[start:end]
    assert tags.count('data-comparison-tag="predecessor"') == 2
    assert tags.count('data-comparison-tag="proposal"') == 1


def _rendered_item_ids(body: str) -> list[str]:
    marker = 'data-review-item="'
    found: list[str] = []
    position = body.find(marker)
    while position >= 0:
        start = position + len(marker)
        end = body.index('"', start)
        found.append(body[start:end])
        position = body.find(marker, end)
    return found


def _next_href(body: str, marker: str) -> str | None:
    needle = f'{marker} href="'
    if needle not in body:
        return None
    start = body.index(needle) + len(needle)
    return body[start : body.index('"', start)].replace("&amp;", "&")


class CountingReviewService:
    """Count exactly which bounded owner operations one route path uses."""

    def __init__(self, service: OwnerApplicationService) -> None:
        self._service = service
        self.calls: dict[str, int] = {}

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._service, name)
        if not callable(attribute):
            return attribute

        def counted(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] = self.calls.get(name, 0) + 1
            return attribute(*args, **kwargs)

        return counted


def test_edit_submission_never_scans_review_pages(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a route rebuilding an edit target from paginated review pages."""
    review = _build_synthetic_review(synthetic_store)
    service = CountingReviewService(OwnerApplicationService(synthetic_store))
    ui = _authenticated_review_ui(synthetic_store, review, service)
    path = ui.edit_path("reject_item")
    fields = ui.edit_fields("reject_item")
    service.calls.clear()

    response = ui.post_form(path, fields)

    assert response.status_code == 303
    assert service.calls.get("list_review_items", 0) == 0
    assert service.calls.get("list_review_source_decisions", 0) == 0
    assert service.calls.get("list_review_blockers", 0) == 0
    assert service.calls.get("list_change_set_revisions", 0) == 0
    assert service.calls["get_review_edit_targets"] == 1
    assert service.calls["get_review_manifest"] == 1
    assert service.calls["edit_review"] == 1


def test_busy_retry_that_finds_a_stale_revision_becomes_a_conflict(
    review_ui: ReviewUi,
) -> None:
    """Catch a retained busy retry applying against a superseded revision."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("reject_item", displayed.revision.revision_id)
    fields = review_ui.edit_fields("reject_item")
    with _writer_lock(review.paths):
        location = review_ui.post_form(path, fields).headers["location"]
    _concurrent_unrelated_edit(review, "Synthetic decision during the retry wait.")
    current = review_ui.current_revision()

    retried = review_ui.post_form(
        location,
        [("csrf", review_ui.session.csrf_token)],
    )
    view = review_ui.client.get(location)

    assert retried.status_code == 303
    assert retried.headers["location"] == location
    assert view.status_code == 200
    assert "Retry against current revision" in view.text
    assert current.revision.revision_id in view.text
    assert review_ui.current_revision().revision == current.revision


def test_source_decision_retry_requires_the_exact_base_coverage_and_reason(
    review_ui: ReviewUi,
) -> None:
    """Catch a source-decision retry ignoring a changed coverage or reason."""
    review = review_ui.review
    displayed = review_ui.current_revision()
    path = review_ui.edit_path("clear_source_no_memory", displayed.revision.revision_id)
    fields = review_ui.edit_fields("clear_source_no_memory")
    edit_change_set(
        review.paths,
        review.change_set_id,
        displayed.revision.revision_id,
        (
            SetSourceNoMemory(
                source_id=review.no_memory_source_id,
                reason="Synthetic concurrent replacement reason.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    current = review_ui.current_revision()
    location = review_ui.post_form(path, fields).headers["location"]

    refused = review_ui.post_form(
        f"{location}/current",
        [("csrf", review_ui.session.csrf_token)],
    )
    view = review_ui.client.get(location)

    assert refused.status_code == 303
    assert refused.headers["location"] == location
    assert "Synthetic concurrent replacement reason." in view.text
    assert review_ui.current_revision().revision == current.revision


def test_review_routes_never_touch_paths_sql_or_the_database() -> None:
    """Catch a review route reaching around the bounded owner service."""
    module_file = importlib.import_module("memory.ui.routes.reviews").__file__
    assert module_file is not None
    source = Path(module_file).read_text(encoding="utf-8")

    for forbidden in (
        "RuntimePaths",
        "writer_session",
        "open_database",
        "sqlite",
        "SELECT ",
        "INSERT ",
        "memory.database",
        "memory.runtime",
    ):
        assert forbidden not in source


def test_review_edit_form_declares_its_progressive_enhancement_hooks(
    review_ui: ReviewUi,
) -> None:
    """Catch a review form losing its unsaved warning or double-submit guard."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    form = review_ui.client.get(
        f"/reviews/{review.change_set_id}"
        f"/revisions/{manifest.revision.revision_id}/edits/replace_item"
    )
    styles = review_ui.client.get("/static/app.css")

    assert form.status_code == 200
    assert "data-unsaved-warning" in form.text
    assert "data-review-edit" in form.text
    assert "data-authenticated-post" in form.text
    assert ".review-comparison" in styles.text


@pytest.mark.parametrize("explicit_item", (False, True))
def test_replacement_form_prefills_the_complete_selected_proposal(
    review_ui: ReviewUi, explicit_item: bool
) -> None:
    """Catch a wording edit starting from defaults that erase retained fields."""
    review = review_ui.review
    path = review_ui.edit_path("replace_item")
    if explicit_item:
        path += "?" + urllib.parse.urlencode({"item_id": review.correction_item_id})

    response = review_ui.client.get(path)

    assert response.status_code == 200
    assert '<option value="event" selected>' in response.text
    assert '<option value="sensitive" selected>' in response.text
    assert "The synthetic amber lamp is lit on Sunday.</textarea>" in response.text
    for name, value in (
        ("occurred_on", "2032-04-05"),
        ("valid_from", "2032-04-05"),
        ("valid_to", "2032-09-09"),
        ("target_lineage_id", review.lineage_id),
        ("expected_head_id", review.predecessor_id),
    ):
        assert re.search(
            rf'name="{re.escape(name)}"[^>]*value="{re.escape(escape(value))}"',
            response.text,
        )
    for index, tag in enumerate(("sunday", "lantern", "revised")):
        assert re.search(rf'name="tag\.{index}"[^>]*>{tag}</textarea>', response.text)
    assert f'<option value="{review.correction_source_id}" selected>' in response.text
    assert "琥珀灯改在周日点亮</textarea>" in response.text


def test_replacement_form_exposes_every_supported_tag_and_evidence_slot(
    review_ui: ReviewUi,
) -> None:
    """Catch a valid full-capacity proposal becoming impossible to retain."""
    response = review_ui.client.get(review_ui.edit_path("replace_item"))

    assert response.status_code == 200
    assert 'name="tag.63"' in response.text
    assert 'name="evidence.15.source_id"' in response.text
    assert 'name="evidence.15.excerpt"' in response.text
    assert 'name="evidence.15.source_level"' in response.text


def test_replacement_of_an_empty_draft_has_no_editable_target(
    review_ui: ReviewUi,
) -> None:
    """Catch an empty roster presenting a blank replacement as an existing item."""
    batch_id, sources = _capture(
        review_ui.review.paths,
        {"syn-empty-edit.txt": b"Synthetic source awaiting its first proposal."},
    )
    draft = create_change_set(
        review_ui.review.paths, batch_id, adapter_origin=ChangeSetAdapterOrigin.MCP
    )
    path = (
        f"/reviews/{draft.change_set_id}/revisions/{draft.revision_id}"
        "/edits/replace_item"
    )

    response = review_ui.client.get(path)

    assert response.status_code == 200
    assert "This revision has no draft item to edit." in response.text
    assert "data-review-edit" not in response.text
    assert "/edits/add_item" in response.text
    source = sources["syn-empty-edit.txt"]
    refused = review_ui.post_form(
        path,
        [
            ("expected_digest", draft.digest),
            ("item_id", ""),
            ("kind", "fact"),
            ("statement", "Synthetic replacement has no target."),
            ("sensitivity", "restricted"),
            ("evidence.0.source_id", source.source_id),
            ("evidence.0.excerpt", "Synthetic source awaiting its first proposal."),
        ],
    )
    assert refused.status_code == 303
    assert "refused=" in refused.headers["location"]
    assert get_change_set(review_ui.review.paths, draft.change_set_id) == draft


def _guard_link_fields(review_ui: ReviewUi) -> list[tuple[str, str]]:
    review = review_ui.review
    return [
        ("expected_digest", review_ui.current_revision().revision.digest),
        ("guard_item_id", review.rejected_item_id),
        ("governed_item_id", review.correction_item_id),
    ]


def test_one_submission_rejects_every_selected_item_in_one_revision(
    review_ui: ReviewUi,
) -> None:
    """Catch a selection becoming one round trip and one revision per item.

    Clearing a sealed sixty-four-file batch used to be sixty-four submissions
    and sixty-four immutable revisions. The revisions are the real cost: the
    owner then approves a history nobody can read.
    """
    review = review_ui.review
    review_ui.submit("restore_item")
    before = review_ui.current_revision()

    response = review_ui.post_form(
        review_ui.edit_path("reject_item"),
        [
            ("expected_digest", before.revision.digest),
            ("item_id", review.correction_item_id),
            ("item_id", review.rejected_item_id),
        ],
    )
    after = review_ui.current_revision()

    assert response.status_code == 303
    assert response.headers["location"] == f"/reviews/{review.change_set_id}"
    assert {item.status for item in after.item_roster} == {"rejected"}
    assert len(after.item_roster) == 2
    # Exactly one revision later, not two.
    assert after.revision.predecessor_revision_id == before.revision.revision_id


def test_restoring_a_selection_is_the_same_one_submission_in_reverse(
    review_ui: ReviewUi,
) -> None:
    """Catch restore being left behind as the single-item operation."""
    review = review_ui.review
    review_ui.submit("restore_item")
    review_ui.post_form(
        review_ui.edit_path("reject_item"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("item_id", review.correction_item_id),
            ("item_id", review.rejected_item_id),
        ],
    )
    before = review_ui.current_revision()

    response = review_ui.post_form(
        review_ui.edit_path("restore_item"),
        [
            ("expected_digest", before.revision.digest),
            ("item_id", review.correction_item_id),
            ("item_id", review.rejected_item_id),
        ],
    )
    after = review_ui.current_revision()

    assert response.status_code == 303
    assert {item.status for item in after.item_roster} == {"active"}
    assert after.revision.predecessor_revision_id == before.revision.revision_id


def test_only_reject_and_restore_accept_a_repeated_reference(
    review_ui: ReviewUi,
) -> None:
    """Catch bulk leaking onto an operation that writes owner-authored content.

    Reject and restore name a draft item and nothing else, and each undoes the
    other. Everything else carries a statement, an excerpt, a reason, or a
    link -- an owner submitting forty of those at once has read none of them.
    """
    review = review_ui.review
    digest = review_ui.current_revision().revision.digest

    refused = review_ui.post_form(
        review_ui.edit_path("set_source_no_memory"),
        [
            ("expected_digest", digest),
            ("source_id", review.unaccounted_source_id),
            ("source_id", review.no_memory_source_id),
            ("reason", "Synthetic bulk no-memory attempt."),
        ],
    )

    assert refused.status_code == 303
    assert "/edits/set_source_no_memory?refused=" in refused.headers["location"]
    explained = review_ui.client.get(refused.headers["location"])
    assert "review edit field is duplicated" in explained.text


def test_a_selection_past_its_ceiling_is_refused_before_anything_is_written(
    review_ui: ReviewUi,
) -> None:
    """Catch one POST asking for more items than a single revision may carry.

    Two ceilings, deliberately. The field budget refuses the oversized body
    before it is decoded, which is where a browser hits the wall. The codec's
    own ceiling guards the path that never sees a body at all: a retained
    submission rebuilt from process memory after a busy writer.
    """
    from memory.ui.request_limits import MAX_BULK_REVIEW_ITEM_IDS

    review = review_ui.review
    before = review_ui.current_revision()
    oversized = [("expected_digest", before.revision.digest)] + [
        ("item_id", f"{review.correction_item_id}-{index}")
        for index in range(MAX_BULK_REVIEW_ITEM_IDS + 1)
    ]

    response = review_ui.post_form(review_ui.edit_path("reject_item"), oversized)

    assert response.status_code == 400
    after = review_ui.current_revision()
    assert after.revision.revision_id == before.revision.revision_id

    with pytest.raises(InvalidArgumentError, match="too many draft items"):
        parse_change_edit_form(
            FormData(
                [
                    ("item_id", f"{review.correction_item_id}-{index}")
                    for index in range(MAX_BULK_REVIEW_ITEM_IDS + 1)
                ]
            ),
            intent="reject_item",
            current=before,
        )


def test_the_roster_offers_the_selection_forms_only_where_editing_is_allowed(
    review_ui: ReviewUi,
) -> None:
    """Catch the bulk controls appearing on a read-only bound audit view."""
    review = review_ui.review
    roster = review_ui.client.get(f"/reviews/{review.change_set_id}")

    assert roster.status_code == 200
    assert 'data-bulk-edit="reject_item"' in roster.text
    assert 'data-bulk-edit="restore_item"' in roster.text
    assert "Reject or restore several items at once" in roster.text
    assert f'name="item_id" value="{review.correction_item_id}"' in roster.text
    assert f'name="item_id" value="{review.rejected_item_id}"' in roster.text


def test_guard_link_form_opens_with_the_lineages_a_candidate_named(
    review_ui: ReviewUi,
) -> None:
    """Catch the candidates panel's deep link arriving at an empty form.

    Only opaque Store identifiers ride in that URL. The statements the owner
    read stay on the panel: nothing they typed, and nothing they were shown,
    belongs in an address bar.
    """
    path = review_ui.edit_path("add_guard_link")
    prefilled = review_ui.client.get(
        f"{path}?guard_lineage_id=lin_synthetic_guard"
        "&governed_lineage_id=lin_synthetic_governed"
    )
    plain = review_ui.client.get(path)

    assert prefilled.status_code == 200
    assert (
        'name="guard_lineage_id" class="wrap-anywhere" maxlength="256" '
        'value="lin_synthetic_guard"'
    ) in prefilled.text
    assert (
        'name="governed_lineage_id" class="wrap-anywhere" maxlength="256" '
        'value="lin_synthetic_governed"'
    ) in prefilled.text
    # Only the two lineages are carried; the draft-item selection stays empty.
    assert re.search(
        r'name="guard_item_id"[^>]*>\s*<option value=""></option>', prefilled.text
    )
    assert plain.status_code == 200
    assert "lin_synthetic_guard" not in plain.text


def test_guard_links_render_as_statement_pairs_and_follow_item_status(
    review_ui: ReviewUi,
) -> None:
    """Catch a guard link the owner cannot read, judge, or take back."""
    review = review_ui.review
    guard_statement = "A synthetic rejected interpretation of the omission."
    governed_statement = "The synthetic amber lamp is lit on Sunday."
    roster = f"/reviews/{review.change_set_id}"

    review_ui.submit("restore_item")
    linked = review_ui.post_form(
        review_ui.edit_path("add_guard_link"),
        _guard_link_fields(review_ui),
    )
    active = review_ui.client.get(roster)
    review_ui.post_form(
        review_ui.edit_path("reject_item"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("item_id", review.rejected_item_id),
        ],
    )
    rejected = review_ui.client.get(roster)
    removed = review_ui.post_form(
        review_ui.edit_path("remove_guard_link"),
        _guard_link_fields(review_ui),
    )
    gone = review_ui.client.get(roster)

    assert linked.status_code == 303
    assert active.status_code == 200
    assert 'data-guard-link="0" data-link-status="active"' in active.text
    assert guard_statement in active.text
    assert governed_statement in active.text
    # The dots are the inversion cue, so both endpoints must resolve one each.
    assert active.text.count('class="sensitivity-dot" data-level="sensitive"') >= 2
    assert rejected.status_code == 200
    assert 'data-guard-link="0" data-link-status="rejected"' in rejected.text
    assert removed.status_code == 303
    assert gone.status_code == 200
    assert "data-guard-link" not in gone.text
    assert review_ui.current_revision().guard_links == ()


def test_guard_link_rows_render_a_hostile_statement_inert(
    review_ui: ReviewUi,
) -> None:
    """Catch a guard-link row treating a proposed statement as markup."""
    review = review_ui.review
    hostile = "</span><script>alert('synthetic-guard')</script>"
    review_ui.post_form(
        review_ui.edit_path("replace_item"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("item_id", review.rejected_item_id),
            ("kind", "insight"),
            ("statement", hostile),
            ("sensitivity", "normal"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", review.unaccounted_excerpt),
        ],
    )
    review_ui.post_form(
        review_ui.edit_path("add_guard_link"),
        _guard_link_fields(review_ui),
    )

    roster = review_ui.client.get(f"/reviews/{review.change_set_id}")

    assert roster.status_code == 200
    assert "data-guard-link" in roster.text
    assert "<script>alert" not in roster.text
    assert "&lt;/span&gt;&lt;script&gt;" in roster.text


UNKNOWN_ITEM = "itm_synthetic_unknown_guard_endpoint"
UNKNOWN_LINEAGE = "lin_" + "0" * 32
ENDPOINT_REFUSAL = "guard link endpoint must name one item or one lineage"
GUARD_LINK_REFUSALS = (
    ("both_endpoints", ENDPOINT_REFUSAL),
    ("neither_endpoint", ENDPOINT_REFUSAL),
    ("unknown_item", "guard link names a missing draft item"),
    ("unknown_lineage", "guard link names an unknown lineage"),
    ("self_link", "guard link cannot be a self-link"),
)


def _refused_guard_link_fields(
    cause: str,
    review: SyntheticReview,
) -> list[tuple[str, str]]:
    """Return the endpoint boxes one refusal cause needs the owner to have typed."""
    if cause == "both_endpoints":
        return [
            ("guard_item_id", review.rejected_item_id),
            ("guard_lineage_id", review.lineage_id),
            ("governed_item_id", review.correction_item_id),
        ]
    if cause == "neither_endpoint":
        return [("governed_item_id", review.correction_item_id)]
    if cause == "unknown_item":
        return [
            ("guard_item_id", UNKNOWN_ITEM),
            ("governed_item_id", review.correction_item_id),
        ]
    if cause == "unknown_lineage":
        return [
            ("guard_lineage_id", UNKNOWN_LINEAGE),
            ("governed_item_id", review.correction_item_id),
        ]
    return [
        ("guard_item_id", review.correction_item_id),
        ("governed_item_id", review.correction_item_id),
    ]


def _refuse_edit(
    review_ui: ReviewUi,
    intent: str,
    fields: list[tuple[str, str]],
) -> Any:
    """Post one refused review edit and follow it to the rendered page.

    The owner's browser posts through ``ui.js``, which discards any response
    that is not a followed redirect, so a refusal only reaches the owner as
    post/redirect/get -- the same shape the busy and conflict paths already use.
    """
    posted = review_ui.post_form(
        review_ui.edit_path(intent),
        [("expected_digest", review_ui.current_revision().revision.digest), *fields],
    )
    assert posted.status_code == 303, posted.text
    location = posted.headers["location"]
    assert "refused=" in location
    return review_ui.client.get(location)


@pytest.mark.parametrize(("cause", "message"), GUARD_LINK_REFUSALS)
def test_guard_link_refusal_explains_itself_and_keeps_the_owner_input(
    cause: str,
    message: str,
    review_ui: ReviewUi,
) -> None:
    """Catch a refused guard link reaching the owner as a bare shell error."""
    review = review_ui.review
    before = review_ui.current_revision().revision.revision_id
    fields = _refused_guard_link_fields(cause, review)

    refused = _refuse_edit(review_ui, "add_guard_link", fields)

    assert refused.status_code == 200
    assert "Request unavailable" not in refused.text
    assert "data-review-refusal" in refused.text
    assert message in refused.text
    for _name, value in fields:
        assert value in refused.text
        assert f'value="{value}"' in refused.text
    assert review_ui.current_revision().revision.revision_id == before
    assert review_ui.sessions.pending_review_count(review_ui.session.session_id) == 0


def test_refused_guard_link_endpoints_never_enter_the_url(
    review_ui: ReviewUi,
) -> None:
    """Catch owner-typed endpoints travelling back through the address bar."""
    review = review_ui.review
    typed = "itm_synthetic_endpoint_the_owner_typed"

    posted = review_ui.post_form(
        review_ui.edit_path("add_guard_link"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("guard_item_id", typed),
            ("governed_item_id", review.correction_item_id),
        ],
    )
    location = posted.headers["location"]
    stale = review_ui.client.get(location.split("?", 1)[0] + "?refused=synthetic-stale")

    assert typed not in location
    assert review.correction_item_id not in location
    assert stale.status_code == 200
    assert "data-review-refusal" not in stale.text


def test_refused_guard_link_endpoints_come_back_inert(
    review_ui: ReviewUi,
) -> None:
    """Catch a rejected endpoint reopening the form as markup instead of text."""
    review = review_ui.review
    hostile = "\"><script>alert('synthetic-endpoint')</script>"

    refused = _refuse_edit(
        review_ui,
        "add_guard_link",
        [
            ("guard_item_id", hostile),
            ("governed_item_id", review.correction_item_id),
        ],
    )

    assert refused.status_code == 200
    assert "guard link names a missing draft item" in refused.text
    assert "<script>alert" not in refused.text
    assert 'value="&#34;&gt;&lt;script&gt;' in refused.text


def test_guard_link_present_state_refusals_name_the_exact_collision(
    review_ui: ReviewUi,
) -> None:
    """Catch 'already there' and 'already gone' hiding behind the catch-all."""
    review = review_ui.review
    endpoints = [
        ("guard_item_id", review.rejected_item_id),
        ("governed_item_id", review.correction_item_id),
    ]
    absent = _refuse_edit(review_ui, "remove_guard_link", endpoints)
    review_ui.post_form(
        review_ui.edit_path("add_guard_link"),
        _guard_link_fields(review_ui),
    )
    linked = review_ui.current_revision().revision.revision_id
    duplicate = _refuse_edit(review_ui, "add_guard_link", endpoints)

    assert absent.status_code == 200
    assert "guard link was not found" in absent.text
    assert review.rejected_item_id in absent.text
    assert duplicate.status_code == 200
    assert "guard link already exists" in duplicate.text
    assert f'value="{review.rejected_item_id}"' in duplicate.text
    assert review_ui.current_revision().revision.revision_id == linked
    assert review_ui.sessions.pending_review_count(review_ui.session.session_id) == 0


UNKNOWN_SOURCE = "src_synthetic_unknown_batch_source"
UNKNOWN_LINEAGE = "lin_synthetic_unknown_guard_endpoint"
ABSENT_EXCERPT = "Synthetic excerpt no captured source contains at all."


def _refused_edit_fields(
    intent: str,
    review: SyntheticReview,
) -> list[tuple[str, str]]:
    """Return one submission each browser-writable intent genuinely refuses."""
    if intent == "add_item":
        return [
            ("kind", "insight"),
            ("statement", "A synthetic proposal whose excerpt is not in a source."),
            ("sensitivity", "sensitive"),
            ("tag.0", "owner-added"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", ABSENT_EXCERPT),
        ]
    if intent == "replace_item":
        return [
            ("item_id", UNKNOWN_ITEM),
            ("kind", "event"),
            ("statement", "A synthetic replacement for an item the draft lost."),
            ("occurred_on", "2032-04-05"),
            ("sensitivity", "sensitive"),
            ("tag.0", "replaced"),
            ("evidence.0.source_id", review.correction_source_id),
            ("evidence.0.excerpt", "琥珀灯改在周日点亮"),
        ]
    if intent == "reject_item":
        return [("item_id", UNKNOWN_ITEM)]
    if intent == "restore_item":
        # The one submission that names no box at all: the page still explains
        # itself, and the receipt list simply has nothing to hold.
        return []
    if intent == "set_source_no_memory":
        return [
            ("source_id", review.correction_source_id),
            ("reason", "Synthetic reviewed decision on a source already used."),
        ]
    if intent == "clear_source_no_memory":
        return [("source_id", UNKNOWN_SOURCE)]
    if intent == "add_guard_link":
        return [
            ("guard_item_id", UNKNOWN_ITEM),
            ("governed_item_id", review.correction_item_id),
        ]
    if intent == "revoke_guard_link":
        return [
            ("guard_lineage_id", UNKNOWN_LINEAGE),
            ("governed_item_id", review.correction_item_id),
        ]
    return [
        ("guard_item_id", review.rejected_item_id),
        ("governed_item_id", review.correction_item_id),
    ]


EVERY_INTENT_REFUSAL = (
    ("add_item", "evidence excerpt was not found"),
    ("replace_item", "review item reference is unknown"),
    ("reject_item", "review item reference is unknown"),
    ("restore_item", "review edit field is missing"),
    ("set_source_no_memory", "a source cannot be used and no-memory"),
    ("clear_source_no_memory", "review source reference is unknown"),
    ("add_guard_link", "guard link names a missing draft item"),
    ("remove_guard_link", "guard link was not found"),
    ("revoke_guard_link", "guard link names an unknown lineage"),
)


@pytest.mark.parametrize(("intent", "message"), EVERY_INTENT_REFUSAL)
def test_every_review_edit_intent_explains_its_refusal_and_keeps_the_input(
    intent: str,
    message: str,
    review_ui: ReviewUi,
) -> None:
    """Catch any refused edit intent reaching the owner as a bare shell error."""
    before = review_ui.current_revision().revision.revision_id
    fields = _refused_edit_fields(intent, review_ui.review)

    posted = review_ui.post_form(
        review_ui.edit_path(intent),
        [("expected_digest", review_ui.current_revision().revision.digest), *fields],
    )
    location = posted.headers["location"]
    refused = review_ui.client.get(location)

    assert posted.status_code == 303, posted.text
    assert "refused=" in location
    assert refused.status_code == 200
    assert "Request unavailable" not in refused.text
    assert "data-review-refusal" in refused.text
    assert "This edit was not applied" in refused.text
    assert message in refused.text
    for _name, value in fields:
        assert value not in location
        assert value in refused.text
    assert review_ui.current_revision().revision.revision_id == before
    assert review_ui.sessions.pending_review_count(review_ui.session.session_id) == 0


def test_the_revoke_form_offers_both_endpoints_and_names_what_revoking_does(
    review_ui: ReviewUi,
) -> None:
    """Catch the ninth operation having a route but no form the owner can use."""
    rendered = review_ui.client.get(review_ui.edit_path("revoke_guard_link"))

    assert rendered.status_code == 200
    assert "Revoke a retained guard link" in rendered.text
    assert 'name="guard_lineage_id"' in rendered.text
    assert 'name="governed_lineage_id"' in rendered.text
    assert "never deletes either memory" in rendered.text


def test_revoking_a_pair_the_store_never_linked_is_refused_by_name(
    review_ui: ReviewUi,
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a revocation of a link that was never applied passing as a no-op."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import store_one_memory

    _guard_id, guard_lineage_id = store_one_memory(
        synthetic_store,
        clock=SyntheticClock(1_850_002_000.0),
        name="hedge.txt",
        body="That figure is self-reported and not verified.\n",
        statement="The amber-lamp schedule is self-reported and not verified.",
        excerpt="self-reported and not verified",
        kind=MemoryKind.INSIGHT,
    )

    refused = _refuse_edit(
        review_ui,
        "revoke_guard_link",
        [
            ("guard_lineage_id", guard_lineage_id),
            ("governed_lineage_id", review_ui.review.lineage_id),
        ],
    )

    assert refused.status_code == 200
    assert "guard link revocation names no retained live link" in refused.text
    assert guard_lineage_id in refused.text
    assert review_ui.current_revision().revoked_guard_links == ()


def test_a_refused_item_form_comes_back_filled_in(review_ui: ReviewUi) -> None:
    """Catch a refused item edit handing the owner an empty form to retype."""
    review = review_ui.review

    refused = _refuse_edit(
        review_ui, "add_item", _refused_edit_fields("add_item", review)
    )

    assert refused.status_code == 200
    assert '<option value="insight" selected>' in refused.text
    assert '<option value="sensitive" selected>' in refused.text
    assert (
        "A synthetic proposal whose excerpt is not in a source.</textarea>"
        in refused.text
    )
    assert ">owner-added</textarea>" in refused.text
    assert f'<option value="{review.unaccounted_source_id}" selected>' in refused.text
    assert f">{ABSENT_EXCERPT}</textarea>" in refused.text


def test_a_refused_no_memory_reason_comes_back_in_its_box(
    review_ui: ReviewUi,
) -> None:
    """Catch a refused source decision losing the reason the owner wrote."""
    review = review_ui.review
    fields = _refused_edit_fields("set_source_no_memory", review)

    refused = _refuse_edit(review_ui, "set_source_no_memory", fields)

    assert refused.status_code == 200
    assert f'<option value="{review.correction_source_id}" selected>' in refused.text
    assert (
        "Synthetic reviewed decision on a source already used.</textarea>"
        in refused.text
    )


def test_a_refused_statement_comes_back_inert(review_ui: ReviewUi) -> None:
    """Catch a rejected statement reopening the form as markup instead of text."""
    review = review_ui.review
    hostile = "</textarea><script>alert('synthetic-statement')</script>"

    refused = _refuse_edit(
        review_ui,
        "add_item",
        [
            ("kind", "insight"),
            ("statement", hostile),
            ("sensitivity", "normal"),
            ("evidence.0.source_id", review.unaccounted_source_id),
            ("evidence.0.excerpt", ABSENT_EXCERPT),
        ],
    )

    assert refused.status_code == 200
    assert "evidence excerpt was not found" in refused.text
    assert "<script>alert" not in refused.text
    assert "&lt;/textarea&gt;&lt;script&gt;" in refused.text


def test_a_refusal_handle_opens_only_its_own_form_once_it_is_current(
    review_ui: ReviewUi,
) -> None:
    """Catch a retained refusal reopening on another intent, form, or revision."""
    review = review_ui.review
    revision_id = review_ui.current_revision().revision.revision_id
    posted = review_ui.post_form(
        review_ui.edit_path("reject_item"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("item_id", UNKNOWN_ITEM),
        ],
    )
    handle = posted.headers["location"].split("refused=")[1]
    base = f"/reviews/{review.change_set_id}/revisions/{revision_id}/edits"

    own = review_ui.client.get(f"{base}/reject_item?refused={handle}")
    other_intent = review_ui.client.get(f"{base}/restore_item?refused={handle}")
    review_ui.submit("reject_item")
    moved = review_ui.current_revision().revision.revision_id
    other_revision = review_ui.client.get(
        f"/reviews/{review.change_set_id}/revisions/{moved}"
        f"/edits/reject_item?refused={handle}"
    )

    assert own.status_code == 200
    assert UNKNOWN_ITEM in own.text
    assert other_intent.status_code == 200
    assert "data-review-refusal" not in other_intent.text
    assert UNKNOWN_ITEM not in other_intent.text
    assert other_revision.status_code == 200
    assert "data-review-refusal" not in other_revision.text


def test_retained_refusals_expire_and_stay_bounded_per_session(
    review_ui: ReviewUi,
) -> None:
    """Catch retained owner input outliving its lifetime or its session cap."""
    session_id = review_ui.session.session_id
    handles = []
    for ordinal in range(_MAX_REVIEW_REFUSALS + 1):
        posted = review_ui.post_form(
            review_ui.edit_path("reject_item"),
            [
                ("expected_digest", review_ui.current_revision().revision.digest),
                ("item_id", f"{UNKNOWN_ITEM}-{ordinal}"),
            ],
        )
        handles.append(posted.headers["location"].split("refused=")[1])
    now_ns = time.monotonic_ns()

    assert (
        review_ui.sessions.resolve_review_refusal(session_id, handles[0], now_ns=now_ns)
        is None
    )
    newest = review_ui.sessions.resolve_review_refusal(
        session_id,
        handles[-1],
        now_ns=now_ns,
    )
    assert newest is not None
    assert (
        review_ui.sessions.resolve_review_refusal(
            session_id,
            handles[-1],
            now_ns=newest.created_at_ns + UI_REVIEW_REFUSAL_TTL_NS,
        )
        is None
    )


def test_a_submission_too_large_to_retain_is_refused_as_it_always_was(
    review_ui: ReviewUi,
) -> None:
    """Catch the retention budget being spent on a page that cannot render."""
    session_id = review_ui.session.session_id
    # Every field is inside its own cap; together they are far past any edit
    # the form can hold, and past what one refusal page is budgeted to render.
    filler = "x" * MAX_REVIEW_FORM_FIELD_BYTES
    tags = [(f"tag.{index}", filler) for index in range(3)]
    assert len(tags) * MAX_REVIEW_FORM_FIELD_BYTES > MAX_RETAINED_REFUSAL_BYTES

    response = review_ui.post_form(
        review_ui.edit_path("add_item"),
        [
            ("expected_digest", review_ui.current_revision().revision.digest),
            ("kind", "insight"),
            ("statement", "A synthetic proposal carrying unretainable tags."),
            ("sensitivity", "normal"),
            *tags,
            ("evidence.0.source_id", review_ui.review.unaccounted_source_id),
            ("evidence.0.excerpt", review_ui.review.unaccounted_excerpt),
        ],
    )

    assert response.status_code == 400
    assert review_ui.sessions.review_refusal_count(session_id) == 0
    assert review_ui.sessions.pending_review_count(session_id) == 0


def test_a_revision_level_conflict_never_renders_as_a_refusal(
    review_ui: ReviewUi,
) -> None:
    """Catch a stale revision or digest losing the page that names the current one."""
    displayed = review_ui.current_revision()
    session_id = review_ui.session.session_id
    path = review_ui.edit_path("reject_item", displayed.revision.revision_id)
    tampered = review_ui.post_form(
        path,
        [("expected_digest", "0" * 64), ("item_id", review_ui.review.rejected_item_id)],
    )
    fields = review_ui.edit_fields("reject_item")
    _concurrent_unrelated_edit(
        review_ui.review,
        "Synthetic concurrent decision beside a refusal.",
    )

    stale = review_ui.post_form(path, fields)

    assert tampered.status_code == 400
    assert stale.status_code == 303
    assert "refused=" not in stale.headers["location"]
    assert stale.headers["location"].startswith(
        f"/reviews/{review_ui.review.change_set_id}/pending/"
    )
    assert 'data-conflict-proposed-change="reject_item"' in (
        review_ui.client.get(stale.headers["location"]).text
    )
    assert review_ui.sessions.review_refusal_count(session_id) == 0


def test_review_history_shows_every_immutable_revision(review_ui: ReviewUi) -> None:
    """Catch immutable review history collapsing to the current revision."""
    review = review_ui.review
    first = review_ui.current_revision().revision
    latest = review_ui.submit("reject_item").revision
    history = review_ui.client.get(f"/reviews/{review.change_set_id}/revisions")

    assert history.status_code == 200
    assert history.text.count("data-revision-row") == 3
    assert 'data-adapter-origin="owner_ui"' in history.text
    assert 'data-adapter-origin="mcp"' in history.text
    assert 'data-revision-lifecycle="current_draft"' in history.text
    assert 'data-revision-lifecycle="superseded"' in history.text
    assert first.digest in history.text
    assert latest.digest in history.text
    assert (
        f'href="/reviews/{review.change_set_id}/revisions/{first.revision_id}"'
        in history.text
    )


def test_item_comparison_shows_the_target_and_current_predecessor(
    review_ui: ReviewUi,
) -> None:
    """Catch a correction hiding that its expected head is no longer current."""
    review = review_ui.review
    manifest = review_ui.current_revision()
    items = review_ui.client.get(
        f"/reviews/{review.change_set_id}"
        f"/revisions/{manifest.revision.revision_id}/items"
    )

    assert items.status_code == 200
    assert f'data-predecessor-current-head="{review.predecessor_id}"' in items.text
    assert f'data-expected-head="{review.predecessor_id}"' in items.text


def _review_approvals(review_ui: ReviewUi) -> tuple[OwnerApprovalSummary, ...]:
    """Return only approvals recorded for this review's exact change set."""
    return tuple(
        approval
        for approval in review_ui.service.list_approvals(None, 50).items
        if approval.change_set_id == review_ui.review.change_set_id
    )


def _review_applications(review_ui: ReviewUi) -> tuple[OwnerApplicationSummary, ...]:
    """Return only applications recorded for this review's exact change set."""
    return tuple(
        application
        for application in review_ui.service.list_applications(None, 50).items
        if application.change_set_id == review_ui.review.change_set_id
    )


def _approve_path(review_ui: ReviewUi) -> str:
    return f"/reviews/{review_ui.review.change_set_id}/approve"


def _prepare_approval(review_ui: ReviewUi, **overrides: str) -> Any:
    manifest = review_ui.current_revision()
    fields = {
        "revision_id": manifest.revision.revision_id,
        "digest": manifest.revision.digest,
        **overrides,
    }
    return review_ui.post_form(_approve_path(review_ui), list(fields.items()))


def _final_page(review_ui: ReviewUi) -> tuple[str, Any]:
    prepared = _prepare_approval(review_ui)
    assert prepared.status_code == 303, prepared.text
    location = prepared.headers["location"]
    assert location.startswith(f"{_approve_path(review_ui)}/")
    return location, review_ui.client.get(location)


def _repair_to_valid(review_ui: ReviewUi) -> None:
    """Give every batch source one noncontradictory coverage state."""
    review_ui.submit("add_item")
    manifest = review_ui.current_revision()
    assert manifest.validation_state == "valid"


def test_app_registers_the_authenticated_final_approval_routes() -> None:
    """Catch a missing two-stage approval surface or a mutating approval GET."""
    inventory = _route_inventory(RenderOnlyReviewService())

    assert {
        ("/reviews/{change_set_id}/approve", ("POST",)),
        ("/reviews/{change_set_id}/approve/{nonce}", ("GET", "HEAD")),
        ("/reviews/{change_set_id}/approve/{nonce}", ("POST",)),
    } <= inventory


def test_prepare_approval_redirects_to_the_exact_session_bound_final_page(
    review_ui: ReviewUi,
) -> None:
    """Catch approval authority created by a GET or addressed by a guessable URL."""
    _repair_to_valid(review_ui)
    manifest = review_ui.current_revision()

    location, page = _final_page(review_ui)

    nonce = location.rsplit("/", 1)[1]
    assert len(nonce) >= 22
    assert page.status_code == 200, page.text
    assert manifest.revision.revision_id in page.text
    assert manifest.revision.digest in page.text
    base = (
        f"/reviews/{review_ui.review.change_set_id}/revisions/"
        f"{manifest.revision.revision_id}"
    )
    for item in manifest.item_roster:
        assert f'data-roster-item="{item.item_id}"' in page.text
        query = urllib.parse.urlencode({"item_id": item.item_id})
        assert f'href="{base}/items/lookup/exact?{query}"' in page.text
    for source in manifest.source_roster:
        assert f'data-roster-source="{source.source_id}"' in page.text
    assert "/items" in page.text
    assert "/sources" in page.text
    assert "/blockers" in page.text
    assert _review_approvals(review_ui) == ()
    assert review_ui.client.get(_approve_path(review_ui)).status_code == 405


def test_final_approval_get_is_read_only_across_refreshes(
    review_ui: ReviewUi,
) -> None:
    """Catch a refresh creating, refreshing, leasing, or consuming write authority."""
    _repair_to_valid(review_ui)
    before = review_ui.current_revision()

    location, first = _final_page(review_ui)
    second = review_ui.client.get(location)
    third = review_ui.client.get(location)

    assert (first.status_code, second.status_code, third.status_code) == (200, 200, 200)
    assert first.text == second.text == third.text
    after = review_ui.current_revision()
    assert after.revision.revision_id == before.revision.revision_id
    assert after.revision.digest == before.revision.digest
    assert after.revision.lifecycle == "current_draft"
    assert _review_approvals(review_ui) == ()
    assert _review_applications(review_ui) == ()


def test_final_approval_renders_the_exact_complete_escaped_review_before_submit(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch approval after a compact roster hid digest-bearing review content."""
    from synthetic import FakeClock as SyntheticClock
    from synthetic import store_one_memory

    review = _build_synthetic_review(synthetic_store)
    review_ui = _authenticated_review_ui(synthetic_store, review)
    _repair_to_valid(review_ui)
    guard_memory_id, guard_lineage_id = store_one_memory(
        synthetic_store,
        clock=SyntheticClock(1_850_003_000.0),
        name="synthetic-final-approval-guard.md",
        body="Synthetic guard evidence for the final approval review.\n",
        statement="Synthetic guard claim for final approval.",
        excerpt="Synthetic guard evidence",
        kind=MemoryKind.INSIGHT,
    )
    link_batch_id, link_sources = _capture(
        synthetic_store,
        {"synthetic-live-guard-link.md": b"Synthetic retained guard link.\n"},
    )
    link_draft = create_change_set(
        synthetic_store,
        link_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    linked = edit_change_set(
        synthetic_store,
        link_draft.change_set_id,
        link_draft.revision_id,
        (
            SetSourceNoMemory(
                source_id=link_sources["synthetic-live-guard-link.md"].source_id,
                reason="Synthetic accounting for a retained guard link.",
            ),
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id=None,
                    guard_lineage_id=guard_lineage_id,
                    governed_item_id=None,
                    governed_lineage_id=review.lineage_id,
                )
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    _apply(synthetic_store, linked)
    current = review_ui.current_revision()
    exact = edit_change_set(
        synthetic_store,
        review.change_set_id,
        current.revision.revision_id,
        (
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id=review.rejected_item_id,
                    guard_lineage_id=None,
                    governed_item_id=review.correction_item_id,
                    governed_lineage_id=None,
                )
            ),
            RevokeGuardLink(
                link=GuardLinkInput(
                    guard_item_id=None,
                    guard_lineage_id=guard_lineage_id,
                    governed_item_id=None,
                    governed_lineage_id=review.lineage_id,
                )
            ),
            SetSourceNoMemory(
                source_id=review.no_memory_source_id,
                reason="Synthetic <approval-escape> & no-memory reason.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.OWNER_UI,
    )

    compact = review_ui.client.get(
        f"/reviews/{review.change_set_id}/revisions/{exact.revision_id}"
    )
    assert compact.status_code == 200
    assert f'href="/memories/{guard_memory_id}"' in compact.text
    assert f'href="/memories/{review.predecessor_id}"' in compact.text

    location, page = _final_page(review_ui)
    canonical = render_change_set(get_change_set(synthetic_store, review.change_set_id))

    assert page.status_code == 200, page.text
    assert exact.digest in page.text
    assert "data-approval-canonical-review" in page.text
    assert "The synthetic amber lamp is lit on Sunday." in page.text
    assert "A synthetic rejected interpretation of the omission." in page.text
    assert "琥珀灯改在周日点亮" in page.text
    assert review.correction_source_id in page.text
    assert review.unaccounted_source_id in page.text
    assert review.no_memory_source_id in page.text
    assert review.lineage_id in page.text
    assert review.predecessor_id in page.text
    assert review.rejected_item_id in page.text
    assert guard_lineage_id in page.text
    assert "guard_links" in page.text
    assert "revoked_guard_links" in page.text
    assert "&lt;approval-escape&gt; &amp; no-memory reason." in page.text
    assert "Synthetic <approval-escape> & no-memory reason." not in page.text
    assert canonical not in page.text
    assert page.text.index(
        "A synthetic rejected interpretation of the omission."
    ) < page.text.index("Approve and apply this exact revision")
    assert location.endswith("/approve/" + location.rsplit("/", 1)[1])


def test_form_post_cannot_mint_approval_without_os_presence(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a browser submission applying a review without OS-verified presence."""
    review = _build_synthetic_review(synthetic_store)
    review_ui = _authenticated_review_ui(
        synthetic_store,
        review,
        verifier=SyntheticOwnerPresenceAdapter(outcome="cancelled"),
    )
    _repair_to_valid(review_ui)
    location, page = _final_page(review_ui)
    assert page.status_code == 200
    manifest = review_ui.current_revision()

    result = review_ui.post_form(
        location,
        [
            ("revision_id", manifest.revision.revision_id),
            ("digest", manifest.revision.digest),
        ],
    )

    assert result.status_code == 409
    assert review_ui.current_revision().revision.lifecycle == "current_draft"
    assert _review_approvals(review_ui) == ()
    assert _review_applications(review_ui) == ()
    assert review_ui.client.get(location).status_code == 404


def test_verified_owner_presence_applies_exactly_the_displayed_revision(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an approval applying anything other than the exact reviewed revision."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    _repair_to_valid(review_ui)
    location, page = _final_page(review_ui)
    manifest = review_ui.current_revision()
    active = [item for item in manifest.item_roster if item.status == "active"]

    applied = review_ui.post_form(
        location,
        [
            ("revision_id", manifest.revision.revision_id),
            ("digest", manifest.revision.digest),
        ],
    )

    assert applied.status_code == 303, applied.text
    assert applied.headers["location"] == f"/reviews/{review.change_set_id}"
    assert verifier.calls == 1
    approvals = _review_approvals(review_ui)
    applications = _review_applications(review_ui)
    assert len(approvals) == 1
    assert approvals[0].adapter == "local_owner_ui"
    assert approvals[0].revision_id == manifest.revision.revision_id
    assert approvals[0].digest == manifest.revision.digest
    assert len(applications) == 1
    assert applications[0].resulting_memory_count == len(active)
    assert page.status_code == 200


def test_duplicate_submission_and_refresh_never_apply_twice(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a refresh, back navigation, or replay creating a second application."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    _repair_to_valid(review_ui)
    location, _page = _final_page(review_ui)
    manifest = review_ui.current_revision()
    fields = [
        ("revision_id", manifest.revision.revision_id),
        ("digest", manifest.revision.digest),
    ]
    first = review_ui.post_form(location, fields)
    assert first.status_code == 303

    second = review_ui.post_form(location, fields)
    refreshed = review_ui.client.get(location)

    assert second.status_code == 303
    assert second.headers["location"] == first.headers["location"]
    assert refreshed.status_code == 404
    assert verifier.calls == 1
    assert len(_review_applications(review_ui)) == 1
    assert len(_review_approvals(review_ui)) == 1


def test_final_approval_requires_session_exact_origin_and_csrf(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a cross-site or unauthenticated request reaching approval at all."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    _repair_to_valid(review_ui)
    location, _page = _final_page(review_ui)
    manifest = review_ui.current_revision()
    body = urllib.parse.urlencode(
        [
            ("revision_id", manifest.revision.revision_id),
            ("digest", manifest.revision.digest),
        ]
    ).encode("ascii")

    missing_csrf = review_ui.client.post(
        location,
        content=body,
        headers={
            "Origin": PUBLIC_ORIGIN,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    wrong_origin = review_ui.client.post(
        location,
        content=body,
        headers={
            "Origin": "http://memory-00000000000000000000000000000000.localhost:41999",
            "X-Memory-CSRF": review_ui.session.csrf_token,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    review_ui.client.cookies.clear()
    unauthenticated = review_ui.client.post(
        location,
        content=body,
        headers={
            "Origin": PUBLIC_ORIGIN,
            "X-Memory-CSRF": "synthetic",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )

    assert missing_csrf.status_code == 403
    assert wrong_origin.status_code == 403
    assert unauthenticated.status_code == 401
    assert verifier.calls == 0
    assert _review_approvals(review_ui) == ()


def test_approval_form_refuses_a_verifier_proof_or_decision_field(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a browser field injecting a verifier, proof, or approval decision."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    _repair_to_valid(review_ui)
    location, _page = _final_page(review_ui)
    manifest = review_ui.current_revision()

    for injected in (
        ("approved", "true"),
        ("owner_decision", "accept"),
        ("verifier", "tests.SyntheticOwnerPresenceAdapter"),
        ("approval_adapter", "local_owner_ui"),
        ("verified_owner_presence", "1"),
    ):
        refused = review_ui.post_form(
            location,
            [
                ("revision_id", manifest.revision.revision_id),
                ("digest", manifest.revision.digest),
                injected,
            ],
        )
        assert refused.status_code in {400, 409}, injected

    assert verifier.calls == 0
    assert _review_approvals(review_ui) == ()
    assert review_ui.current_revision().revision.lifecycle == "current_draft"


def test_blocked_review_cannot_prepare_or_reach_owner_presence(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch approval offered while the exact revision still has a blocker."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    assert review_ui.current_revision().validation_state == "blocked"

    refused = _prepare_approval(review_ui)

    assert refused.status_code == 409
    assert verifier.calls == 0
    assert _review_approvals(review_ui) == ()


def test_stale_prepare_values_are_refused_before_any_binding_exists(
    review_ui: ReviewUi,
) -> None:
    """Catch a stale browser revision or digest creating approval authority."""
    _repair_to_valid(review_ui)

    stale_revision = _prepare_approval(review_ui, revision_id="csr_" + "9" * 32)
    stale_digest = _prepare_approval(review_ui, digest="9" * 64)

    assert stale_revision.status_code == 409
    assert stale_digest.status_code == 409
    assert _review_approvals(review_ui) == ()


def test_edit_after_preparation_invalidates_the_pending_final_page(
    review_ui: ReviewUi,
) -> None:
    """Catch an approval page surviving an owner edit that changed the digest."""
    _repair_to_valid(review_ui)
    location, page = _final_page(review_ui)
    assert page.status_code == 200

    review_ui.submit("set_source_no_memory")
    stale_page = review_ui.client.get(location)

    assert stale_page.status_code == 404
    assert _review_approvals(review_ui) == ()


def test_maximum_final_approval_roster_renders_and_cap_plus_one_fails_closed() -> None:
    """Catch a maximum complete review truncating before the approval control."""
    padding_prefix = '{"padding":"'
    padding_suffix = 'END"}'
    canonical_payload = (
        padding_prefix
        + "&" * (MAX_DIFF_BYTES - len(padding_prefix) - len(padding_suffix))
        + padding_suffix
    )
    canonical_digest = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    canonical_review = f"Digest: {canonical_digest}\nPayload:\n{canonical_payload}\n"
    at_cap = RenderOnlyReviewService(
        roster_items=256,
        roster_sources=64,
        canonical_review=canonical_review,
        digest=canonical_digest,
    )
    above = RenderOnlyReviewService(roster_items=257, roster_sources=64)

    rendered = _render_approval_page(at_cap)
    overflow = _render_approval_page(above)

    assert rendered.status_code == 200
    assert rendered.text.count("data-roster-item=") == 256
    assert rendered.text.count("data-roster-source=") == 64
    assert "END&#34;}" in rendered.text
    assert rendered.text.index("END&#34;}") < rendered.text.index(
        "Approve and apply this exact revision"
    )
    assert len(rendered.content) <= MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES
    assert overflow.status_code == 413
    assert "data-roster-item=" not in overflow.text
    assert RENDER_DIGEST not in overflow.text


def _render_approval_page(service: RenderOnlyReviewService) -> Any:
    sessions = UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    application = create_ui_app(
        # Deliberately partial in the same way `_render_ui` is: the render-only
        # fake never reaches the apply path, so the members that path would
        # need stay unimplemented.
        cast("OwnerUiService", service),
        sessions,
        UnusedFinder(),
        build_test_orchestrator(service, sessions),
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
    cookie = client.cookies.get("memory_ui_session")
    assert cookie is not None
    session = sessions.resolve_cookie(
        cookie=cookie,
        exact_host=EXACT_HOST,
        now_ns=time.monotonic_ns(),
    )
    assert session is not None
    prepared = client.post(
        f"/reviews/{RENDER_CHANGE_SET_ID}/approve",
        content=urllib.parse.urlencode(
            [("revision_id", RENDER_REVISION_ID), ("digest", service.digest)]
        ).encode("ascii"),
        headers={
            "Origin": PUBLIC_ORIGIN,
            "X-Memory-CSRF": session.csrf_token,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=False,
    )
    assert prepared.status_code == 303, prepared.text
    return client.get(prepared.headers["location"])


def test_approval_binding_expiry_is_the_approved_two_monotonic_minutes() -> None:
    """Catch a widened approval-binding lifetime reaching the browser surface."""
    assert APPROVAL_BINDING_TTL_NS == 120_000_000_000


def test_lost_challenge_lease_during_the_prompt_creates_no_canonical_memory(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an applied review reported as failed after its lease was lost."""
    review = _build_synthetic_review(synthetic_store)
    verifier = SyntheticOwnerPresenceAdapter()
    review_ui = _authenticated_review_ui(synthetic_store, review, verifier=verifier)
    _repair_to_valid(review_ui)
    location, page = _final_page(review_ui)
    assert page.status_code == 200
    manifest = review_ui.current_revision()
    session_id = review_ui.session.session_id
    before = len(review_ui.service.list_memories(None, 50, MemoryFilters()).items)
    verifier.during = lambda: review_ui.approval.attempts.invalidate_session(session_id)

    refused = review_ui.post_form(
        location,
        [
            ("revision_id", manifest.revision.revision_id),
            ("digest", manifest.revision.digest),
        ],
    )

    assert refused.status_code == 409
    assert verifier.calls == 1
    assert _review_approvals(review_ui) == ()
    assert _review_applications(review_ui) == ()
    assert review_ui.current_revision().revision.lifecycle == "current_draft"
    assert (
        len(review_ui.service.list_memories(None, 50, MemoryFilters()).items) == before
    )


def test_review_detail_offers_the_approval_entry_only_for_a_valid_draft(
    review_ui: ReviewUi,
) -> None:
    """Catch the owner's only path to approval vanishing from the review page."""
    review = review_ui.review
    blocked = review_ui.client.get(f"/reviews/{review.change_set_id}")
    assert blocked.status_code == 200
    assert "data-approval-entry" not in blocked.text

    manifest = review_ui.submit("add_item")
    assert manifest.validation_state == "valid"
    page = review_ui.client.get(f"/reviews/{review.change_set_id}")

    assert page.status_code == 200
    assert "data-approval-entry" in page.text
    assert f'action="/reviews/{review.change_set_id}/approve"' in page.text
    assert f'value="{manifest.revision.revision_id}"' in page.text
    assert f'value="{manifest.revision.digest}"' in page.text

    prepared = review_ui.post_form(
        f"/reviews/{review.change_set_id}/approve",
        [
            ("revision_id", manifest.revision.revision_id),
            ("digest", manifest.revision.digest),
        ],
    )
    assert prepared.status_code == 303
    assert prepared.headers["location"].startswith(
        f"/reviews/{review.change_set_id}/approve/"
    )

    historical = review_ui.client.get(
        f"/reviews/{review.change_set_id}/revisions/{review.revision_id}"
    )
    assert historical.status_code == 200
    assert "data-approval-entry" not in historical.text


def test_non_draft_revisions_show_no_approvability_verdict(
    review_ui: ReviewUi,
) -> None:
    """Catch a superseded or applied revision claiming it cannot be approved."""
    review = review_ui.review
    first_revision_id = review.revision_id
    blocked = review_ui.client.get(f"/reviews/{review.change_set_id}")
    assert "cannot be approved" in blocked.text

    review_ui.submit("add_item")
    historical = review_ui.client.get(
        f"/reviews/{review.change_set_id}/revisions/{first_revision_id}"
    )

    assert historical.status_code == 200
    assert "cannot be approved" not in historical.text
    assert "not applicable" in historical.text
