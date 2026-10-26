"""Authenticated complete Memory Review, bounded edits, and retry custody."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from datetime import date
from typing import Protocol, cast

from jinja2 import Environment
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from memory.errors import (
    InvalidArgumentError,
    RequestLimitError,
    StaleCursorError,
    StaleRevisionError,
    StoreBusyError,
    StoreError,
    WrongDigestError,
)
from memory.inbox import MAX_BATCH_FILES
from memory.model import (
    ChangeEdit,
    ClearSourceNoMemory,
    RejectItem,
    ReplaceItem,
    UiReviewRefusal,
    UiSession,
)
from memory.reviews import (
    MAX_CHANGE_ITEMS,
    MAX_EVIDENCE_PER_ITEM,
    MAX_GUARD_LINKS,
    MAX_TAGS,
)
from memory.ui.auth import (
    UI_PENDING_REVIEW_TTL_NS,
    UiSessionStore,
)
from memory.ui.owner_presence import (
    PreparedUiApproval,
    UiApprovalOrchestrator,
)
from memory.ui.presentation import ReviewGuardChange, relevant_guard_changes
from memory.ui.request_limits import (
    MAX_BULK_REVIEW_ITEM_IDS,
    MAX_CONTROL_FORM_BODY_BYTES,
    MAX_CONTROL_FORM_FIELD_BYTES,
    MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES,
    MAX_FORM_FIELDS,
    MAX_REVIEW_EDIT_BODY_BYTES,
    MAX_REVIEW_FORM_FIELD_BYTES,
    MAX_REVIEW_GUARD_CHANGES_PER_ITEM,
    MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
    UI_REVIEW_ITEM_PAGE_LIMIT,
    UI_STANDARD_PAGE_LIMIT,
    parse_bounded_urlencoded,
    read_bounded_body,
)
from memory.ui.review_forms import (
    OWNER_REVIEW_FORM_INTENTS,
    bulk_target_rows,
    normalized_review_fields,
    normalized_submission_fields,
    parse_change_edit_form,
    pending_review_edit,
    retained_review_fields,
    roster_item_id,
    roster_source,
    submission_fingerprint,
    submitted_rows,
    target_rows,
)
from memory.ui.routes._support import (
    page_limit,
    render_html,
    session_of,
    singleton_query,
)
from memory.ui.routes.audit import (
    AuditService,
    StaleAuditError,
    UnknownAuditHandleError,
    resolve_audit_navigation,
    stale_audit_response,
)
from memory.ui.view_models import (
    OwnerChangeSetRevisionSummary,
    OwnerChangeSetSummary,
    OwnerPage,
    OwnerReviewBlocker,
    OwnerReviewEditTarget,
    OwnerReviewFormIntent,
    OwnerReviewItemComparison,
    OwnerReviewItemEditTarget,
    OwnerReviewManifest,
    OwnerSourceDecision,
    OwnerStatus,
    PendingReviewConflictLease,
    PendingReviewLease,
    UiPendingReviewConflict,
    UiPendingReviewForm,
)


class ReviewReadModel(Protocol):
    """The bounded review reads shared by ordinary and audit navigation."""

    def get_review_manifest(
        self,
        change_set_id: str,
        revision_id: str | None = None,
    ) -> OwnerReviewManifest: ...

    def list_review_items(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewItemComparison]: ...

    def get_review_item(
        self,
        change_set_id: str,
        revision_id: str,
        item_id: str,
    ) -> OwnerReviewItemComparison: ...

    def list_review_source_decisions(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerSourceDecision]: ...

    def list_review_blockers(
        self,
        change_set_id: str,
        revision_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerReviewBlocker]: ...

    def list_change_set_revisions(
        self,
        change_set_id: str,
        cursor: str | None,
        limit: int,
    ) -> OwnerPage[OwnerChangeSetRevisionSummary]: ...


class ReviewService(ReviewReadModel, AuditService, Protocol):
    """The exact bounded owner surface consumed by Memory Review routes."""

    def render_approval_review(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str: ...

    def get_status(self) -> OwnerStatus: ...

    def list_change_sets(
        self,
        cursor: str | None,
        limit: int,
        state: str | None,
    ) -> OwnerPage[OwnerChangeSetSummary]: ...

    def get_review_edit_target(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
        edit: ChangeEdit,
    ) -> OwnerReviewEditTarget: ...

    def get_review_edit_targets(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
        edits: Sequence[ChangeEdit],
    ) -> tuple[OwnerReviewEditTarget, ...]: ...

    def edit_review(
        self,
        change_set_id: str,
        expected_revision_id: str,
        edits: Sequence[ChangeEdit],
    ) -> OwnerReviewManifest: ...


def _require_intent(request: Request) -> OwnerReviewFormIntent:
    raw = request.path_params["intent"]
    if raw not in OWNER_REVIEW_FORM_INTENTS:
        raise InvalidArgumentError("review edit intent is invalid")
    return cast(OwnerReviewFormIntent, raw)


def _expected_digest(
    pairs: Sequence[tuple[str, str]],
) -> tuple[str, tuple[tuple[str, str], ...]]:
    declared = [value for name, value in pairs if name == "expected_digest"]
    if len(declared) != 1 or len(declared[0]) != 64:
        raise InvalidArgumentError("review expected digest is invalid")
    return declared[0], tuple(
        (name, value) for name, value in pairs if name != "expected_digest"
    )


_GUARD_LINK_INTENTS = frozenset(
    {"add_guard_link", "remove_guard_link", "revoke_guard_link"}
)


async def _control_fields(request: Request) -> tuple[tuple[str, str], ...]:
    body = await read_bounded_body(
        request.receive,
        headers=request.scope["headers"],
        max_bytes=MAX_CONTROL_FORM_BODY_BYTES,
    )
    return parse_bounded_urlencoded(
        body,
        max_fields=MAX_FORM_FIELDS,
        max_field_bytes=MAX_CONTROL_FORM_FIELD_BYTES,
    )


def review_routes(
    service: ReviewService,
    sessions: UiSessionStore,
    templates: Environment,
    approval: UiApprovalOrchestrator,
    *,
    today: Callable[[], date] = date.today,
) -> tuple[Route, ...]:
    """Build the complete owner Memory Review surface over bounded operations."""

    def pending_location(change_set_id: str, handle: str) -> str:
        return f"/reviews/{change_set_id}/pending/{handle}"

    def approval_location(change_set_id: str, nonce: str) -> str:
        return f"/reviews/{change_set_id}/approve/{nonce}"

    def resolved_fingerprint(
        change_set_id: str,
        revision_id: str,
        digest: str,
        edits: Sequence[ChangeEdit],
    ) -> str:
        try:
            targets = service.get_review_edit_targets(
                change_set_id,
                revision_id,
                digest,
                edits,
            )
        except StoreError:
            return ""
        return submission_fingerprint(
            tuple(target.state_fingerprint for target in targets)
        )

    def apply_leased_edit(
        lease: PendingReviewLease | PendingReviewConflictLease,
        handle: str,
        edits: Sequence[ChangeEdit],
        expected_revision_id: str,
    ) -> Response:
        change_set_id = lease.form.change_set_id
        try:
            service.edit_review(change_set_id, expected_revision_id, edits)
        except StoreBusyError:
            sessions.mark_pending_review_retryable(lease)
            return Response(
                status_code=303,
                headers={"Location": pending_location(change_set_id, handle)},
            )
        except StaleRevisionError, WrongDigestError:
            current = service.get_review_manifest(change_set_id)
            sessions.mark_pending_review_conflict(
                lease,
                current_revision_id=current.revision.revision_id,
                current_digest=current.revision.digest,
                current_target_fingerprint=resolved_fingerprint(
                    change_set_id,
                    current.revision.revision_id,
                    current.revision.digest,
                    edits,
                ),
            )
            return Response(
                status_code=303,
                headers={"Location": pending_location(change_set_id, handle)},
            )
        except BaseException:
            sessions.complete_pending_review(lease)
            raise
        sessions.complete_pending_review(lease)
        return Response(
            status_code=303,
            headers={"Location": f"/reviews/{change_set_id}"},
        )

    def review_reads(
        request: Request,
    ) -> tuple[ReviewReadModel, str | None, OwnerStatus]:
        """Resolve the ordinary or one session-owned snapshot-bound read model."""
        navigation = resolve_audit_navigation(request, sessions, service)
        if navigation is None:
            return service, None, service.get_status()
        return (
            navigation.reader,
            navigation.handle,
            navigation.reader.get_index().store,
        )

    def render_section(
        request: Request,
        *,
        section: str,
        reads: ReviewReadModel,
        handle: str | None,
        status: OwnerStatus,
        items: OwnerPage[object] | None = None,
        sources: OwnerPage[object] | None = None,
        blockers: OwnerPage[object] | None = None,
        revisions: OwnerPage[object] | None = None,
        limit: int = UI_STANDARD_PAGE_LIMIT,
    ) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        change_set_id = request.path_params["change_set_id"]
        revision_id = request.path_params.get("revision_id")
        manifest = reads.get_review_manifest(change_set_id, revision_id)
        if section == "roster" and (
            len(manifest.item_roster) > MAX_CHANGE_ITEMS
            or len(manifest.source_roster) > MAX_BATCH_FILES
            or len(manifest.guard_links) > MAX_GUARD_LINKS
            or len(manifest.revoked_guard_links) > MAX_GUARD_LINKS
        ):
            raise RequestLimitError("review roster exceeds its bounded page budget")
        guard_changes: dict[str, tuple[ReviewGuardChange, ...]] = {}
        if items is not None:
            for raw_item in items.items:
                item = cast(OwnerReviewItemComparison, raw_item)
                guard_changes[item.item_id] = relevant_guard_changes(
                    item.item_id,
                    item.proposal.target_lineage_id,
                    manifest.guard_links,
                    manifest.revoked_guard_links,
                )
        return render_html(
            templates,
            "reviews/detail.html",
            max_bytes=(
                MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES
                if section == "roster"
                else MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES
            ),
            status=status,
            csrf_token=csrf,
            audit_handle=handle,
            change_set_id=change_set_id,
            manifest=manifest,
            section=section,
            items=items,
            sources=sources,
            blockers=blockers,
            revisions=revisions,
            limit=limit,
            intents=OWNER_REVIEW_FORM_INTENTS,
            bulk_limit=MAX_BULK_REVIEW_ITEM_IDS,
            today=today(),
            guard_changes=guard_changes,
            max_guard_changes_per_item=MAX_REVIEW_GUARD_CHANGES_PER_ITEM,
        )

    def audit_bound_section(
        request: Request,
        build: Callable[[ReviewReadModel, str | None, OwnerStatus], Response],
    ) -> Response:
        """Render one review section through the ordinary or bound read model."""
        try:
            reads, handle, status = review_reads(request)
        except UnknownAuditHandleError:
            return PlainTextResponse("Request unavailable", status_code=404)
        except StaleAuditError:
            return stale_audit_response(templates, service, request)
        try:
            return build(reads, handle, status)
        except StaleCursorError:
            if handle is None:
                raise
            return stale_audit_response(templates, service, request)

    async def list_reviews(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        return render_html(
            templates,
            "reviews/list.html",
            max_bytes=MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            drafts=service.list_change_sets(
                singleton_query(request, "draft_cursor"),
                UI_STANDARD_PAGE_LIMIT,
                "draft",
            ),
            applied=service.list_change_sets(
                singleton_query(request, "applied_cursor"),
                UI_STANDARD_PAGE_LIMIT,
                "applied",
            ),
        )

    async def review_roster(request: Request) -> Response:
        return audit_bound_section(
            request,
            lambda reads, handle, status: render_section(
                request,
                section="roster",
                reads=reads,
                handle=handle,
                status=status,
            ),
        )

    async def review_items(request: Request) -> Response:
        limit = page_limit(request, maximum=UI_REVIEW_ITEM_PAGE_LIMIT)

        def build(
            reads: ReviewReadModel,
            handle: str | None,
            status: OwnerStatus,
        ) -> Response:
            page = reads.list_review_items(
                request.path_params["change_set_id"],
                request.path_params["revision_id"],
                singleton_query(request, "cursor"),
                limit,
            )
            return render_section(
                request,
                section="items",
                reads=reads,
                handle=handle,
                status=status,
                items=cast(OwnerPage[object], page),
                limit=limit,
            )

        return audit_bound_section(request, build)

    async def review_item(request: Request) -> Response:
        path_item_id = request.path_params.get("item_id")
        query_item_id = singleton_query(request, "item_id")
        if path_item_id is None:
            if query_item_id is None:
                raise InvalidArgumentError("review item query is required")
            item_id = query_item_id
        else:
            if query_item_id is not None:
                raise InvalidArgumentError("review item query is ambiguous")
            item_id = path_item_id

        def build(
            reads: ReviewReadModel,
            handle: str | None,
            status: OwnerStatus,
        ) -> Response:
            item = reads.get_review_item(
                request.path_params["change_set_id"],
                request.path_params["revision_id"],
                item_id,
            )
            return render_section(
                request,
                section="items",
                reads=reads,
                handle=handle,
                status=status,
                items=cast(
                    OwnerPage[object],
                    OwnerPage(items=(item,), next_cursor=None, has_more=False),
                ),
            )

        return audit_bound_section(request, build)

    async def review_sources(request: Request) -> Response:
        def build(
            reads: ReviewReadModel,
            handle: str | None,
            status: OwnerStatus,
        ) -> Response:
            page = reads.list_review_source_decisions(
                request.path_params["change_set_id"],
                request.path_params["revision_id"],
                singleton_query(request, "cursor"),
                UI_STANDARD_PAGE_LIMIT,
            )
            return render_section(
                request,
                section="sources",
                reads=reads,
                handle=handle,
                status=status,
                sources=cast(OwnerPage[object], page),
            )

        return audit_bound_section(request, build)

    async def review_blockers(request: Request) -> Response:
        def build(
            reads: ReviewReadModel,
            handle: str | None,
            status: OwnerStatus,
        ) -> Response:
            page = reads.list_review_blockers(
                request.path_params["change_set_id"],
                request.path_params["revision_id"],
                singleton_query(request, "cursor"),
                UI_STANDARD_PAGE_LIMIT,
            )
            return render_section(
                request,
                section="blockers",
                reads=reads,
                handle=handle,
                status=status,
                blockers=cast(OwnerPage[object], page),
            )

        return audit_bound_section(request, build)

    async def review_history(request: Request) -> Response:
        def build(
            reads: ReviewReadModel,
            handle: str | None,
            status: OwnerStatus,
        ) -> Response:
            page = reads.list_change_set_revisions(
                request.path_params["change_set_id"],
                singleton_query(request, "cursor"),
                UI_STANDARD_PAGE_LIMIT,
            )
            return render_section(
                request,
                section="revisions",
                reads=reads,
                handle=handle,
                status=status,
                revisions=cast(OwnerPage[object], page),
            )

        return audit_bound_section(request, build)

    def resolved_refusal(
        session: UiSession,
        *,
        intent: OwnerReviewFormIntent,
        change_set_id: str,
        revision_id: str,
        handle: str | None,
    ) -> UiReviewRefusal | None:
        """Resolve one retained refusal, and only onto the form that raised it."""
        if handle is None:
            return None
        refused = sessions.resolve_review_refusal(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        if refused is None:
            return None
        if (refused.change_set_id, refused.revision_id, refused.intent) != (
            change_set_id,
            revision_id,
            intent,
        ):
            return None
        return refused

    def render_edit_form(
        csrf: str,
        *,
        intent: OwnerReviewFormIntent,
        change_set_id: str,
        revision_id: str,
        manifest: OwnerReviewManifest,
        target_rows: tuple[tuple[str, str], ...] = (),
        item_id: str | None = None,
        source_id: str | None = None,
        refused: UiReviewRefusal | None = None,
        prefilled: dict[str, str] | None = None,
    ) -> Response:
        return render_html(
            templates,
            "reviews/edit.html",
            max_bytes=MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            mode="form",
            change_set_id=change_set_id,
            manifest=manifest,
            intent=intent,
            action=(f"/reviews/{change_set_id}/revisions/{revision_id}/edits/{intent}"),
            target_rows=target_rows,
            item_id=item_id,
            source_id=source_id,
            max_tags=MAX_TAGS,
            max_evidence=MAX_EVIDENCE_PER_ITEM,
            refusal=None if refused is None else refused.refusal,
            # A refusal owns every box it retained; only an untouched form can
            # be opened with values a link supplied.
            submitted=(
                dict(refused.fields) if refused is not None else (prefilled or {})
            ),
            submitted_rows=() if refused is None else submitted_rows(refused.fields),
            pending=None,
            conflict=None,
            old_rows=(),
            current_rows=(),
            retry_action=None,
        )

    def leased_edit(
        session: UiSession,
        *,
        intent: OwnerReviewFormIntent,
        change_set_id: str,
        revision_id: str,
        digest: str,
        remaining: tuple[tuple[str, str], ...],
        manifest: OwnerReviewManifest,
    ) -> Response:
        edits = parse_change_edit_form(
            FormData(list(remaining)),
            intent=intent,
            current=manifest,
        )
        targets = service.get_review_edit_targets(
            change_set_id,
            revision_id,
            digest,
            edits,
        )
        handle = sessions.remember_pending_review(
            session.session_id,
            UiPendingReviewForm(
                change_set_id=change_set_id,
                expected_revision_id=revision_id,
                expected_digest=digest,
                operation=intent,
                normalized_fields=normalized_submission_fields(edits),
                base_target_fingerprint=submission_fingerprint(
                    tuple(target.state_fingerprint for target in targets)
                ),
                expires_at_ns=time.monotonic_ns() + UI_PENDING_REVIEW_TTL_NS,
            ),
        )
        lease = sessions.lease_pending_review(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        return apply_leased_edit(lease, handle, edits, revision_id)

    async def edit_form(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        intent = _require_intent(request)
        change_set_id = request.path_params["change_set_id"]
        revision_id = request.path_params["revision_id"]
        manifest = service.get_review_manifest(change_set_id, revision_id)
        refused = resolved_refusal(
            session,
            intent=intent,
            change_set_id=change_set_id,
            revision_id=revision_id,
            handle=singleton_query(request, "refused"),
        )
        submitted = {} if refused is None else dict(refused.fields)
        # A guard-link form may be opened from the candidates panel with both
        # lineages already named. Only opaque Store identifiers travel this
        # way, and only into the two boxes the form owns: nothing an owner
        # typed reaches a URL, which is why the statements stay on the panel
        # and the identifiers are what the link carries.
        if not submitted and intent in _GUARD_LINK_INTENTS:
            submitted = {
                name: value
                for name in ("guard_lineage_id", "governed_lineage_id")
                if (value := singleton_query(request, name)) is not None
            }
        item_id = submitted.get("item_id") or singleton_query(request, "item_id")
        source_id = submitted.get("source_id") or singleton_query(request, "source_id")
        if refused is None and intent == "replace_item" and item_id is None:
            item_id = manifest.item_roster[0].item_id if manifest.item_roster else None
        target: OwnerReviewEditTarget | None = None
        # A refused edit may name a target the draft cannot resolve at all, and
        # reading its current state would raise the very refusal being explained.
        if refused is None:
            if intent in {"replace_item", "reject_item", "restore_item"} and item_id:
                target = service.get_review_edit_target(
                    change_set_id,
                    revision_id,
                    manifest.revision.digest,
                    RejectItem(item_id=roster_item_id(manifest, item_id)),
                )
                if intent == "replace_item" and isinstance(
                    target.state, OwnerReviewItemEditTarget
                ):
                    submitted = dict(
                        normalized_review_fields(
                            ReplaceItem(
                                item_id=target.state.item_id,
                                memory=target.state.memory,
                                evidence=target.state.evidence,
                            )
                        )
                    )
            elif intent.endswith("source_no_memory") and source_id:
                target = service.get_review_edit_target(
                    change_set_id,
                    revision_id,
                    manifest.revision.digest,
                    ClearSourceNoMemory(
                        source_id=roster_source(manifest, source_id).source_id
                    ),
                )
        return render_edit_form(
            csrf,
            intent=intent,
            change_set_id=change_set_id,
            revision_id=revision_id,
            manifest=manifest,
            target_rows=() if target is None else target_rows(target.state),
            item_id=item_id,
            source_id=source_id,
            refused=refused,
            prefilled=submitted,
        )

    async def submit_edit(request: Request) -> Response:
        session = session_of(request)
        intent = _require_intent(request)
        change_set_id = request.path_params["change_set_id"]
        revision_id = request.path_params["revision_id"]
        body = await read_bounded_body(
            request.receive,
            headers=request.scope["headers"],
            max_bytes=MAX_REVIEW_EDIT_BODY_BYTES,
        )
        pairs = parse_bounded_urlencoded(
            body,
            max_fields=MAX_FORM_FIELDS,
            max_field_bytes=MAX_REVIEW_FORM_FIELD_BYTES,
        )
        digest, remaining = _expected_digest(pairs)
        manifest = service.get_review_manifest(change_set_id, revision_id)
        # A refused edit is an ordinary review judgement, not a malformed
        # request: an item the draft cannot resolve, a statement outside its
        # bounds, an excerpt no source contains, a correction target that must
        # pair with an expected head, a source that cannot be both used and
        # no-memory, a guard link that already stands -- each has its own
        # sentence, and the owner reads which one happened instead of the
        # shell's one bare "Request unavailable".
        #
        # It has to be post/redirect/get. The progressive-enhancement handler in
        # ui.js discards any response that is not a followed redirect, so an
        # error status carrying this page would never reach the owner's browser
        # at all -- the same reason the busy and conflict paths redirect. The
        # owner's typing rides in process memory behind a one-session opaque
        # handle rather than in the URL, exactly as a private search does.
        #
        # Every message raised here is a fixed sentence holding no owner text,
        # and the template escapes it regardless.
        try:
            return leased_edit(
                session,
                intent=intent,
                change_set_id=change_set_id,
                revision_id=revision_id,
                digest=digest,
                remaining=remaining,
                manifest=manifest,
            )
        except StaleRevisionError, WrongDigestError:
            # A revision-level conflict is not a validation refusal. The ones
            # raised while applying never reach here at all -- apply_leased_edit
            # returns its own 303 to the conflict page, which is the only page
            # holding the current revision the owner has to move onto. One
            # raised while reading the target keeps that routing rather than
            # reopening a form whose digest can only be refused again.
            raise
        except StoreError as error:
            retained = retained_review_fields(intent, remaining)
            if retained is None:
                raise
            handle = sessions.remember_review_refusal(
                session.session_id,
                UiReviewRefusal(
                    change_set_id=change_set_id,
                    revision_id=revision_id,
                    intent=intent,
                    refusal=str(error),
                    fields=retained,
                    created_at_ns=time.monotonic_ns(),
                ),
            )
            return Response(
                status_code=303,
                headers={
                    "Location": (
                        f"/reviews/{change_set_id}/revisions/{revision_id}"
                        f"/edits/{intent}?refused={handle}"
                    )
                },
            )

    async def pending_review(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        change_set_id = request.path_params["change_set_id"]
        handle = request.path_params["handle"]
        state = sessions.resolve_pending_review(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        form = state.form if isinstance(state, UiPendingReviewConflict) else state
        if form is None or form.change_set_id != change_set_id:
            return PlainTextResponse("Request unavailable", status_code=404)
        old_rows: tuple[tuple[str, str], ...] = ()
        current_rows: tuple[tuple[str, str], ...] = ()
        if isinstance(state, UiPendingReviewConflict):
            old_rows = _bounded_target_rows(
                service,
                form,
                form.expected_revision_id,
                form.expected_digest,
            )
            current_rows = _bounded_target_rows(
                service,
                form,
                state.current_revision_id,
                state.current_digest,
            )
        return render_html(
            templates,
            "reviews/edit.html",
            max_bytes=MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            mode="conflict" if isinstance(state, UiPendingReviewConflict) else "retry",
            change_set_id=change_set_id,
            manifest=service.get_review_manifest(change_set_id),
            intent=form.operation,
            action=None,
            target_rows=(),
            item_id=None,
            source_id=None,
            refusal=None,
            submitted={},
            submitted_rows=(),
            pending=form,
            conflict=state if isinstance(state, UiPendingReviewConflict) else None,
            old_rows=old_rows,
            current_rows=current_rows,
            retry_action=pending_location(change_set_id, handle),
        )

    async def retry_pending_review(request: Request) -> Response:
        session = session_of(request)
        change_set_id = request.path_params["change_set_id"]
        handle = request.path_params["handle"]
        fields = await _control_fields(request)
        if fields != (("csrf", session.csrf_token),):
            raise InvalidArgumentError("review retry form is invalid")
        state = sessions.resolve_pending_review(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        if not isinstance(state, UiPendingReviewForm):
            return PlainTextResponse("Request unavailable", status_code=404)
        if state.change_set_id != change_set_id:
            return PlainTextResponse("Request unavailable", status_code=404)
        manifest = service.get_review_manifest(
            change_set_id,
            state.expected_revision_id,
        )
        edits = pending_review_edit(state, manifest)
        lease = sessions.lease_pending_review(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        return apply_leased_edit(lease, handle, edits, state.expected_revision_id)

    async def retry_against_current(request: Request) -> Response:
        session = session_of(request)
        change_set_id = request.path_params["change_set_id"]
        handle = request.path_params["handle"]
        fields = await _control_fields(request)
        if fields != (("csrf", session.csrf_token),):
            raise InvalidArgumentError("review retry form is invalid")
        state = sessions.resolve_pending_review(
            session.session_id,
            handle,
            now_ns=time.monotonic_ns(),
        )
        if not isinstance(state, UiPendingReviewConflict):
            return PlainTextResponse("Request unavailable", status_code=404)
        if state.form.change_set_id != change_set_id:
            return PlainTextResponse("Request unavailable", status_code=404)
        current = service.get_review_manifest(change_set_id)
        edits: tuple[ChangeEdit, ...] | None
        try:
            edits = pending_review_edit(state.form, current)
            fingerprint = submission_fingerprint(
                tuple(
                    target.state_fingerprint
                    for target in service.get_review_edit_targets(
                        change_set_id,
                        current.revision.revision_id,
                        current.revision.digest,
                        edits,
                    )
                )
            )
        except StoreError:
            edits = None
            fingerprint = ""
        lease = sessions.lease_pending_review_conflict(
            session.session_id,
            handle,
            selected_revision_id=current.revision.revision_id,
            selected_digest=current.revision.digest,
            selected_target_fingerprint=fingerprint,
            now_ns=time.monotonic_ns(),
        )
        if edits is None or fingerprint != state.form.base_target_fingerprint:
            sessions.mark_pending_review_conflict(
                lease,
                current_revision_id=current.revision.revision_id,
                current_digest=current.revision.digest,
                current_target_fingerprint=fingerprint,
            )
            return Response(
                status_code=303,
                headers={"Location": pending_location(change_set_id, handle)},
            )
        return apply_leased_edit(lease, handle, edits, lease.selected_revision_id)

    async def approval_fields(request: Request) -> tuple[str, str]:
        fields = await _control_fields(request)
        if tuple(name for name, _value in fields) != ("revision_id", "digest"):
            raise InvalidArgumentError("review approval form is invalid")
        return fields[0][1], fields[1][1]

    async def prepare_approval(request: Request) -> Response:
        session = session_of(request)
        change_set_id = request.path_params["change_set_id"]
        revision_id, digest = await approval_fields(request)
        try:
            prepared = approval.prepare_approval(
                change_set_id=change_set_id,
                expected_revision_id=revision_id,
                expected_digest=digest,
                session_id=session.session_id,
            )
        except StoreError:
            return PlainTextResponse("Request unavailable", status_code=409)
        return Response(
            status_code=303,
            headers={
                "Location": approval_location(
                    change_set_id,
                    prepared.binding.final_page_nonce,
                )
            },
        )

    def resolved_approval(
        request: Request,
        session: UiSession,
    ) -> PreparedUiApproval | None:
        """Resolve one pending binding for this exact path without leasing it."""
        prepared = approval.resolve_approval_page(
            session_id=session.session_id,
            final_page_nonce=request.path_params["nonce"],
        )
        if prepared is None:
            return None
        if prepared.binding.change_set_id != request.path_params["change_set_id"]:
            return None
        return prepared

    async def final_approval_page(request: Request) -> Response:
        session = session_of(request)
        csrf = session.csrf_token
        prepared = resolved_approval(request, session)
        if prepared is None:
            return PlainTextResponse("Request unavailable", status_code=404)
        manifest = prepared.review
        if (
            len(manifest.item_roster) > MAX_CHANGE_ITEMS
            or len(manifest.source_roster) > MAX_BATCH_FILES
        ):
            raise RequestLimitError("approval roster exceeds its bounded page budget")
        active = sum(1 for item in manifest.item_roster if item.status == "active")
        return render_html(
            templates,
            "reviews/approve.html",
            max_bytes=MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES,
            status=service.get_status(),
            csrf_token=csrf,
            change_set_id=request.path_params["change_set_id"],
            manifest=manifest,
            canonical_review=prepared.canonical_review,
            submit_action=approval_location(
                request.path_params["change_set_id"],
                request.path_params["nonce"],
            ),
            active_count=active,
            rejected_count=len(manifest.item_roster) - active,
            no_memory_count=sum(
                1 for source in manifest.source_roster if source.coverage == "no_memory"
            ),
        )

    async def submit_approval(request: Request) -> Response:
        session = session_of(request)
        change_set_id = request.path_params["change_set_id"]
        revision_id, digest = await approval_fields(request)
        pending = approval.resolve_approval_page(
            session_id=session.session_id,
            final_page_nonce=request.path_params["nonce"],
        )
        if pending is not None and pending.binding.change_set_id != change_set_id:
            return PlainTextResponse("Request unavailable", status_code=404)
        try:
            detail = await approval.submit_approval(
                session_id=session.session_id,
                final_page_nonce=request.path_params["nonce"],
                submitted_revision_id=revision_id,
                submitted_digest=digest,
            )
        except StoreError:
            return PlainTextResponse("Request unavailable", status_code=409)
        if detail.application.change_set_id != change_set_id:
            return PlainTextResponse("Request unavailable", status_code=404)
        return Response(
            status_code=303,
            headers={"Location": f"/reviews/{change_set_id}"},
        )

    return (
        Route("/reviews", list_reviews, methods=["GET"]),
        Route(
            "/reviews/{change_set_id}/approve",
            prepare_approval,
            methods=["POST"],
        ),
        Route(
            "/reviews/{change_set_id}/approve/{nonce}",
            final_approval_page,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/approve/{nonce}",
            submit_approval,
            methods=["POST"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/items/lookup/exact",
            review_item,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/items/{item_id}",
            review_item,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/items",
            review_items,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/sources",
            review_sources,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/blockers",
            review_blockers,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/edits/{intent}",
            edit_form,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}/edits/{intent}",
            submit_edit,
            methods=["POST"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions/{revision_id}",
            review_roster,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/revisions",
            review_history,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/pending/{handle}/current",
            retry_against_current,
            methods=["POST"],
        ),
        Route(
            "/reviews/{change_set_id}/pending/{handle}",
            pending_review,
            methods=["GET"],
        ),
        Route(
            "/reviews/{change_set_id}/pending/{handle}",
            retry_pending_review,
            methods=["POST"],
        ),
        Route("/reviews/{change_set_id}", review_roster, methods=["GET"]),
    )


def _bounded_target_rows(
    service: ReviewService,
    form: UiPendingReviewForm,
    revision_id: str,
    digest: str,
) -> tuple[tuple[str, str], ...]:
    """Resolve one retained submission's target state in one exact revision.

    A selection reports one status row per item it named. The full typed target
    rows carry a statement each, so rendering them for a selection would put
    the conflict page well past its response budget; the statuses are also the
    whole of what a reject or restore was aimed at.
    """
    try:
        manifest = service.get_review_manifest(form.change_set_id, revision_id)
        edits = pending_review_edit(form, manifest)
        if len(edits) > 1:
            return bulk_target_rows(edits, manifest)
        target = service.get_review_edit_target(
            form.change_set_id,
            revision_id,
            digest,
            edits[0],
        )
    except StoreError:
        return (("Target", "Unavailable in this revision"),)
    return target_rows(target.state)
