from __future__ import annotations

import asyncio
import copy
import inspect
import pickle
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import pytest
from ui_support import RefusingOwnerPresenceAdapter

from memory.errors import (
    InvalidArgumentError,
    OwnerApprovalRequiredError,
    StoreError,
)
from memory.model import (
    ApplicationResult,
    ChangeSetAdapterOrigin,
    RuntimeMode,
    StoreStatus,
)
from memory.ui import owner_presence
from memory.ui.auth import UiSessionStore
from memory.ui.owner_presence import (
    APPROVAL_BINDING_TTL_NS,
    APPROVAL_TOMBSTONE_TTL_NS,
    MAX_APPROVAL_ATTEMPTS,
    OWNER_PRESENCE_TIMEOUT_SECONDS,
    ApprovalAttemptStore,
    ApprovalChallengeLease,
    CliApprovalBinding,
    CompletedApprovalAttempt,
    UiApprovalBinding,
    VerifiedOwnerPresence,
    owner_presence_reason,
)
from memory.ui.view_models import (
    InboxStatus,
    MemoryProjectionCoverage,
    OwnerApplicationSummary,
    OwnerAppliedReviewDetail,
    OwnerApprovalSummary,
    OwnerChangeSetRevisionSummary,
    OwnerReviewManifest,
    OwnerReviewRosterItem,
    OwnerReviewRosterSource,
    OwnerStatus,
    ProjectionCoverage,
    SourceProjectionCoverage,
)

BOOTSTRAP = "synthetic-owner-presence-bootstrap"
EXACT_HOST = "memory-synthetic.localhost:41999"
SESSION = "ses-synthetic-owner-presence"
OTHER_SESSION = "ses-synthetic-other-owner"
NONCE = "non-synthetic-final-page"
STORE_ID = "0" * 32
CHANGE_SET_ID = "chg_" + "a" * 32
REVISION_ID = "csr_" + "a" * 32
DIGEST = "b" * 64
APPLICATION_ID = "app_" + "a" * 32


def ui_binding(
    *,
    session_id: str = SESSION,
    final_page_nonce: str = NONCE,
    created_at_ns: int = 1_000_000_000,
    revision_id: str = REVISION_ID,
    digest: str = DIGEST,
) -> UiApprovalBinding:
    """Build one exact pending UI approval binding with its fixed expiry."""
    return UiApprovalBinding(
        store_id=STORE_ID,
        change_set_id=CHANGE_SET_ID,
        revision_id=revision_id,
        digest=digest,
        approval_adapter="local_owner_ui",
        session_id=session_id,
        final_page_nonce=final_page_nonce,
        expires_at_ns=created_at_ns + APPROVAL_BINDING_TTL_NS,
    )


def cli_binding(
    *,
    invocation_nonce: str = "inv-synthetic-owner-presence",
    created_at_ns: int = 1_000_000_000,
) -> CliApprovalBinding:
    """Build one exact pending CLI approval binding with its fixed expiry."""
    return CliApprovalBinding(
        store_id=STORE_ID,
        change_set_id=CHANGE_SET_ID,
        revision_id=REVISION_ID,
        digest=DIGEST,
        approval_adapter="os_owner_presence_cli",
        invocation_nonce=invocation_nonce,
        expires_at_ns=created_at_ns + APPROVAL_BINDING_TTL_NS,
    )


def test_owner_presence_module_declares_the_approved_capability_interface() -> None:
    """Catch omission or signature drift at the owner-presence boundary."""
    assert APPROVAL_BINDING_TTL_NS == 120_000_000_000
    assert APPROVAL_TOMBSTONE_TTL_NS == 600_000_000_000
    assert MAX_APPROVAL_ATTEMPTS == 8
    assert OWNER_PRESENCE_TIMEOUT_SECONDS == 120.0
    assert tuple(UiApprovalBinding.__dataclass_fields__) == (
        "store_id",
        "change_set_id",
        "revision_id",
        "digest",
        "approval_adapter",
        "session_id",
        "final_page_nonce",
        "expires_at_ns",
    )
    assert tuple(CliApprovalBinding.__dataclass_fields__) == (
        "store_id",
        "change_set_id",
        "revision_id",
        "digest",
        "approval_adapter",
        "invocation_nonce",
        "expires_at_ns",
    )
    assert tuple(ApprovalChallengeLease.__dataclass_fields__) == (
        "lease_id",
        "binding",
        "state",
    )
    assert tuple(CompletedApprovalAttempt.__dataclass_fields__) == (
        "binding",
        "application_id",
        "completed_at_ns",
    )
    assert tuple(owner_presence.PreparedUiApproval.__dataclass_fields__) == (
        "review",
        "canonical_review",
        "binding",
    )
    assert tuple(owner_presence.UiApprovalOrchestrator.__dataclass_fields__) == (
        "service",
        "sessions",
        "attempts",
        "verifier",
        "clock",
    )
    assert VerifiedOwnerPresence.__slots__ == (
        "_binding",
        "_lease_id",
        "_verified_at_ns",
    )
    assert tuple(
        inspect.signature(owner_presence.OwnerPresenceVerifier.verify).parameters
    ) == ("self", "lease", "reason")
    assert tuple(
        inspect.signature(
            owner_presence.LocalAuthenticationOwnerPresenceVerifier.verify
        ).parameters
    ) == ("self", "lease", "reason")
    assert tuple(
        inspect.signature(
            owner_presence.UiApprovalOrchestrator.prepare_approval
        ).parameters
    ) == (
        "self",
        "change_set_id",
        "expected_revision_id",
        "expected_digest",
        "session_id",
    )
    assert tuple(
        inspect.signature(
            owner_presence.UiApprovalOrchestrator.resolve_approval_page
        ).parameters
    ) == ("self", "session_id", "final_page_nonce")
    assert tuple(
        inspect.signature(
            owner_presence.UiApprovalOrchestrator.submit_approval
        ).parameters
    ) == (
        "self",
        "session_id",
        "final_page_nonce",
        "submitted_revision_id",
        "submitted_digest",
    )
    assert inspect.iscoroutinefunction(
        owner_presence.UiApprovalOrchestrator.submit_approval
    )
    assert inspect.iscoroutinefunction(
        owner_presence.LocalAuthenticationOwnerPresenceVerifier.verify
    )


def test_verified_owner_presence_has_no_public_constructor_or_serializer() -> None:
    """Catch a browser, model, or CLI value becoming an owner-presence receipt."""
    binding = ui_binding()

    with pytest.raises(TypeError):
        VerifiedOwnerPresence(  # type: ignore[call-arg]
            binding=binding,
            lease_id="les-synthetic",
            verified_at_ns=1,
        )
    with pytest.raises(TypeError):
        VerifiedOwnerPresence(
            object(),
            binding=binding,
            lease_id="les-synthetic",
            verified_at_ns=1,
        )
    receipt = VerifiedOwnerPresence(
        owner_presence._PRESENCE_CONSTRUCTOR,
        binding=binding,
        lease_id="les-synthetic",
        verified_at_ns=1,
    )
    with pytest.raises(TypeError):
        pickle.dumps(receipt)
    with pytest.raises(TypeError):
        copy.copy(receipt)
    with pytest.raises(TypeError):
        copy.deepcopy(receipt)
    assert not hasattr(receipt, "__dict__")


def test_owner_presence_reason_names_the_product_and_only_a_digest_prefix() -> None:
    """Catch a system prompt leaking owner content or a complete digest."""
    binding = ui_binding()

    reason = owner_presence_reason(binding)

    assert "Memory" in reason
    assert DIGEST[:12] in reason
    assert DIGEST not in reason
    assert CHANGE_SET_ID not in reason
    assert REVISION_ID not in reason
    assert SESSION not in reason
    assert NONCE not in reason


def test_pending_ui_binding_resolves_read_only_without_extending_its_expiry() -> None:
    """Catch a refresh creating, refreshing, leasing, or consuming authority."""
    attempts = ApprovalAttemptStore()
    binding = ui_binding()
    attempts.remember_ui_binding(binding)

    first = attempts.resolve_ui_binding(SESSION, NONCE, now_ns=1_000_000_001)
    second = attempts.resolve_ui_binding(
        SESSION,
        NONCE,
        now_ns=1_000_000_000 + APPROVAL_BINDING_TTL_NS - 1,
    )

    assert first == binding
    assert second == binding
    assert first is not None and first.expires_at_ns == binding.expires_at_ns
    leased = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_002)
    assert isinstance(leased, ApprovalChallengeLease)


def test_expired_or_cross_session_bindings_expose_no_usable_approval_page() -> None:
    """Catch an expired or foreign nonce resolving a usable approval binding."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())

    expired = attempts.resolve_ui_binding(
        SESSION,
        NONCE,
        now_ns=1_000_000_000 + APPROVAL_BINDING_TTL_NS,
    )
    attempts.remember_ui_binding(ui_binding())
    foreign = attempts.resolve_ui_binding(OTHER_SESSION, NONCE, now_ns=1_000_000_001)
    unknown = attempts.resolve_ui_binding(SESSION, "non-other", now_ns=1_000_000_001)

    assert expired is None
    assert foreign is None
    assert unknown is None
    with pytest.raises(StoreError):
        attempts.lease_ui(OTHER_SESSION, NONCE, now_ns=1_000_000_001)


def test_lease_takes_one_in_flight_challenge_and_refuses_a_racing_post() -> None:
    """Catch a duplicate submission stealing or restarting an in-flight prompt."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())

    lease = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_001)

    assert isinstance(lease, ApprovalChallengeLease)
    assert lease.state == "in_flight"
    assert lease.binding == ui_binding()
    with pytest.raises(StoreError):
        attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_002)
    assert attempts.resolve_ui_binding(SESSION, NONCE, now_ns=1_000_000_002) is None


def test_completed_attempt_replays_its_application_inside_the_tombstone() -> None:
    """Catch a duplicate submission reminting approval or losing its result."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())
    lease = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_001)
    assert isinstance(lease, ApprovalChallengeLease)

    completed = attempts.complete(lease, APPLICATION_ID, now_ns=1_000_000_002)
    replay = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_003)
    expired = attempts.lease_ui

    assert completed == CompletedApprovalAttempt(
        binding=ui_binding(),
        application_id=APPLICATION_ID,
        completed_at_ns=1_000_000_002,
    )
    assert replay == completed
    with pytest.raises(StoreError):
        expired(
            SESSION,
            NONCE,
            now_ns=1_000_000_002 + APPROVAL_TOMBSTONE_TTL_NS,
        )


def test_failed_attempt_is_consumed_and_can_never_be_leased_again() -> None:
    """Catch a cancelled or failed prompt leaving reusable approval authority."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())
    lease = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_001)
    assert isinstance(lease, ApprovalChallengeLease)

    attempts.consume_failed(lease)

    assert attempts.resolve_ui_binding(SESSION, NONCE, now_ns=1_000_000_002) is None
    with pytest.raises(StoreError):
        attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_002)
    with pytest.raises(StoreError):
        attempts.complete(lease, APPLICATION_ID, now_ns=1_000_000_003)


def test_ui_capacity_rejects_new_attempts_without_evicting_an_in_flight_prompt() -> (
    None
):
    """Catch a ninth attempt evicting an awaited OS prompt or exceeding bounds."""
    attempts = ApprovalAttemptStore()
    for index in range(MAX_APPROVAL_ATTEMPTS):
        attempts.remember_ui_binding(ui_binding(final_page_nonce=f"non-{index}"))
    lease = attempts.lease_ui(SESSION, "non-0", now_ns=1_000_000_001)
    assert isinstance(lease, ApprovalChallengeLease)

    with pytest.raises(StoreError):
        attempts.remember_ui_binding(ui_binding(final_page_nonce="non-overflow"))

    assert attempts.complete(lease, APPLICATION_ID, now_ns=1_000_000_002).binding == (
        lease.binding
    )
    assert (
        attempts.resolve_ui_binding(SESSION, "non-1", now_ns=1_000_000_002) is not None
    )
    assert attempts.resolve_ui_binding(SESSION, "non-overflow", now_ns=1) is None


def test_expired_pending_attempts_free_capacity_for_a_fresh_binding() -> None:
    """Catch a session locked out by bindings that already reached their expiry."""
    attempts = ApprovalAttemptStore()
    for index in range(MAX_APPROVAL_ATTEMPTS):
        attempts.remember_ui_binding(ui_binding(final_page_nonce=f"non-{index}"))

    later = ui_binding(
        final_page_nonce="non-fresh",
        created_at_ns=1_000_000_000 + APPROVAL_BINDING_TTL_NS,
    )
    attempts.remember_ui_binding(later)

    assert (
        attempts.resolve_ui_binding(
            SESSION,
            "non-fresh",
            now_ns=1_000_000_000 + APPROVAL_BINDING_TTL_NS + 1,
        )
        == later
    )


def test_cli_attempts_are_leased_per_process_and_bounded() -> None:
    """Catch an unbounded or unleased CLI approval path reaching the OS prompt."""
    attempts = ApprovalAttemptStore()

    lease = attempts.lease_cli(cli_binding(invocation_nonce="inv-0"), now_ns=1)

    assert isinstance(lease, ApprovalChallengeLease)
    assert lease.binding == cli_binding(invocation_nonce="inv-0")
    for index in range(1, MAX_APPROVAL_ATTEMPTS):
        attempts.lease_cli(cli_binding(invocation_nonce=f"inv-{index}"), now_ns=1)
    with pytest.raises(StoreError):
        attempts.lease_cli(cli_binding(invocation_nonce="inv-overflow"), now_ns=1)
    with pytest.raises(StoreError):
        attempts.lease_cli(cli_binding(invocation_nonce="inv-0"), now_ns=1)


def test_session_invalidation_erases_every_attempt_owned_by_that_session() -> None:
    """Catch approval authority surviving its own invalidated UI session."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())
    attempts.remember_ui_binding(
        ui_binding(session_id=OTHER_SESSION, final_page_nonce="non-other")
    )
    lease = attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_001)
    assert isinstance(lease, ApprovalChallengeLease)

    attempts.invalidate_session(SESSION)

    with pytest.raises(StoreError):
        attempts.lease_ui(SESSION, NONCE, now_ns=1_000_000_002)
    with pytest.raises(StoreError):
        attempts.complete(lease, APPLICATION_ID, now_ns=1_000_000_002)
    assert (
        attempts.resolve_ui_binding(
            OTHER_SESSION,
            "non-other",
            now_ns=1_000_000_002,
        )
        is not None
    )


def test_shutdown_erases_every_retained_ui_and_cli_attempt() -> None:
    """Catch approval authority surviving foreground UI or CLI shutdown."""
    attempts = ApprovalAttemptStore()
    attempts.remember_ui_binding(ui_binding())
    cli_lease = attempts.lease_cli(cli_binding(), now_ns=1)

    attempts.shutdown()

    assert attempts.resolve_ui_binding(SESSION, NONCE, now_ns=1_000_000_002) is None
    with pytest.raises(StoreError):
        attempts.complete(cli_lease, APPLICATION_ID, now_ns=2)
    attempts.remember_ui_binding(ui_binding())
    assert attempts.resolve_ui_binding(SESSION, NONCE, now_ns=1_000_000_001) is not None


def test_attempt_store_rejects_foreign_lease_and_binding_objects() -> None:
    """Catch an arbitrary object being accepted as approval-attempt state."""
    attempts = ApprovalAttemptStore()

    with pytest.raises(InvalidArgumentError):
        attempts.remember_ui_binding(cli_binding())  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        attempts.lease_cli(ui_binding(), now_ns=1)  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        attempts.consume_failed(object())  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        attempts.complete(object(), APPLICATION_ID, now_ns=1)  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentError):
        attempts.holds_lease(object())  # type: ignore[arg-type]


class SyntheticOwnerPresenceAdapter:
    """Test-only owner-presence adapter; never packaged and never production."""

    def __init__(
        self,
        *,
        outcome: str = "verified",
        during: Callable[[], None] | None = None,
        gate: bool = False,
        receipt_binding: object | None = None,
        receipt_lease_id: str | None = None,
        receipt_verified_at_ns: int | None = None,
    ) -> None:
        self.outcome = outcome
        self.during = during
        self.gate = gate
        self.calls = 0
        self.reasons: list[str] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.receipt_binding = receipt_binding
        self.receipt_lease_id = receipt_lease_id
        self.receipt_verified_at_ns = receipt_verified_at_ns

    async def verify(
        self,
        lease: ApprovalChallengeLease,
        *,
        reason: str,
    ) -> VerifiedOwnerPresence:
        self.calls += 1
        self.reasons.append(reason)
        self.started.set()
        if self.during is not None:
            self.during()
        if self.gate:
            await self.release.wait()
        if self.outcome == "cancelled":
            raise OwnerApprovalRequiredError("owner cancelled the system prompt")
        if self.outcome == "unavailable":
            raise OwnerApprovalRequiredError("owner presence is unavailable")
        if self.outcome == "hang":
            await asyncio.Event().wait()
        return VerifiedOwnerPresence(
            owner_presence._PRESENCE_CONSTRUCTOR,
            binding=(
                lease.binding
                if self.receipt_binding is None
                else cast(UiApprovalBinding, self.receipt_binding)
            ),
            lease_id=self.receipt_lease_id or lease.lease_id,
            verified_at_ns=(
                lease.binding.expires_at_ns - 1
                if self.receipt_verified_at_ns is None
                else self.receipt_verified_at_ns
            ),
        )


class SteppingClock:
    """One injected monotonic sampler the test advances explicitly."""

    def __init__(self, start_ns: int = 1_000_000_000) -> None:
        self.now_ns = start_ns
        self.samples: list[int] = []

    def monotonic_ns(self) -> int:
        self.samples.append(self.now_ns)
        return self.now_ns

    def advance(self, delta_ns: int) -> None:
        self.now_ns += delta_ns


def synthetic_owner_status(store_id: str = STORE_ID) -> OwnerStatus:
    """Build one content-free owner status for the approval orchestrator."""
    return OwnerStatus(
        store=StoreStatus(
            product="memory",
            schema_version=1,
            store_id=store_id,
            source_count=3,
            memory_count=1,
            searchable_count=3,
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
                total_captures=3,
                expected_searchable_captures=3,
                indexed_expected_captures=3,
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
        runtime_display_path="Synthetic Store Home",
        inbox=InboxStatus(
            inbox_display_path="Synthetic Inbox",
            staged_visible_entry_count=0,
        ),
    )


def synthetic_manifest(
    *,
    revision_id: str = REVISION_ID,
    digest: str = DIGEST,
    lifecycle: str = "current_draft",
    blocker_count: int = 0,
) -> OwnerReviewManifest:
    """Build one bounded review manifest for the approval orchestrator."""
    return OwnerReviewManifest(
        batch_id="bat_" + "a" * 32,
        batch_sealed_at=2_130_000_000,
        revision=OwnerChangeSetRevisionSummary(
            change_set_id=CHANGE_SET_ID,
            revision_id=revision_id,
            predecessor_revision_id=None,
            digest=digest,
            adapter_origin=ChangeSetAdapterOrigin.MCP,
            recorded_at=2_130_000_000,
            lifecycle=cast(Any, lifecycle),
            item_count=1,
            batch_source_count=1,
            accounted_source_count=1,
            unaccounted_source_count=0,
        ),
        blocker_count=blocker_count,
        item_roster=(
            OwnerReviewRosterItem(
                ordinal=0,
                item_id="itm_" + "a" * 32,
                status="active",
                change_kind="new_memory",
                target_lineage_id=None,
                statement_preview="Synthetic proposed statement.",
                statement_elided=False,
            ),
        ),
        source_roster=(
            OwnerReviewRosterSource(
                ordinal=0,
                source_id="src_" + "a" * 32,
                blob_digest="d" * 64,
                coverage="used",
            ),
        ),
    )


@dataclass(slots=True)
class SyntheticApprovalService:
    """Serve exact bounded review state and record every atomic apply call."""

    manifest: OwnerReviewManifest = field(default_factory=synthetic_manifest)

    def render_approval_review(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str:
        assert change_set_id == CHANGE_SET_ID
        assert revision_id == self.manifest.revision.revision_id
        assert digest == self.manifest.revision.digest
        return f"Digest: {digest}\nPayload:\n{{}}\n"

    store_id: str = STORE_ID
    applied: list[tuple[str, str, str, str]] = field(default_factory=list)
    apply_error: StoreError | None = None

    def get_status(self) -> OwnerStatus:
        return synthetic_owner_status(self.store_id)

    def get_review_manifest(
        self,
        change_set_id: str,
        revision_id: str | None = None,
    ) -> OwnerReviewManifest:
        assert change_set_id == CHANGE_SET_ID
        return self.manifest

    def apply_owner_approved_review(
        self,
        approval: Any,
        *,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> ApplicationResult:
        if self.apply_error is not None:
            raise self.apply_error
        adapter = approval._consume(
            store_id=self.store_id,
            change_set_id=change_set_id,
            revision_id=revision_id,
            digest=digest,
        )
        self.applied.append((adapter, change_set_id, revision_id, digest))
        return ApplicationResult(
            application_id=APPLICATION_ID,
            change_set_id=change_set_id,
            revision_id=revision_id,
            memory_ids=("mem_" + "a" * 32,),
            idempotent_replay=False,
            standing_guard_violations=(),
        )

    def get_application(self, application_id: str) -> OwnerAppliedReviewDetail:
        assert application_id == APPLICATION_ID
        return OwnerAppliedReviewDetail(
            application=OwnerApplicationSummary(
                application_id=APPLICATION_ID,
                change_set_id=CHANGE_SET_ID,
                revision_id=self.manifest.revision.revision_id,
                applied_at=2_130_000_100,
                resulting_memory_count=1,
            ),
            approval=OwnerApprovalSummary(
                approval_id="apr_" + "a" * 32,
                change_set_id=CHANGE_SET_ID,
                revision_id=self.manifest.revision.revision_id,
                digest=self.manifest.revision.digest,
                adapter="local_owner_ui",
                approved_at=2_130_000_100,
            ),
            memory_revision_ids=("mem_" + "a" * 32,),
        )


def new_ui_session(store: UiSessionStore | None = None) -> tuple[UiSessionStore, Any]:
    """Return one authenticated process session for orchestrator tests."""
    sessions = store or UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=0,
    )
    session = sessions.exchange_bootstrap(
        secret=BOOTSTRAP,
        exact_host=EXACT_HOST,
        now_ns=1,
    )
    assert session is not None
    return sessions, session


def build_orchestrator(
    *,
    service: SyntheticApprovalService | None = None,
    verifier: Any | None = None,
    clock: SteppingClock | None = None,
    attempts: ApprovalAttemptStore | None = None,
    sessions: UiSessionStore | None = None,
) -> tuple[Any, SyntheticApprovalService, Any, SteppingClock, Any, UiSessionStore]:
    """Compose one process-owned orchestrator over test-owned collaborators."""
    selected_service = service or SyntheticApprovalService()
    selected_verifier = verifier or SyntheticOwnerPresenceAdapter()
    selected_clock = clock or SteppingClock()
    session_store, session = new_ui_session(sessions)
    orchestrator = owner_presence.UiApprovalOrchestrator(
        service=selected_service,
        sessions=session_store,
        attempts=attempts or ApprovalAttemptStore(),
        verifier=selected_verifier,
        clock=selected_clock,
    )
    return (
        orchestrator,
        selected_service,
        selected_verifier,
        selected_clock,
        session,
        session_store,
    )


def prepared(orchestrator: Any, session: Any) -> Any:
    """Prepare one approval binding for the exact current synthetic revision."""
    return orchestrator.prepare_approval(
        change_set_id=CHANGE_SET_ID,
        expected_revision_id=REVISION_ID,
        expected_digest=DIGEST,
        session_id=session.session_id,
    )


def submit(orchestrator: Any, session: Any, nonce: str) -> Any:
    """Run one complete asynchronous approval submission to completion."""
    return asyncio.run(
        orchestrator.submit_approval(
            session_id=session.session_id,
            final_page_nonce=nonce,
            submitted_revision_id=REVISION_ID,
            submitted_digest=DIGEST,
        )
    )


def test_prepare_binds_the_exact_current_revision_to_one_pending_nonce() -> None:
    """Catch approval preparation that is not bound to the exact review state."""
    orchestrator, _service, _verifier, clock, session, _sessions = build_orchestrator(
        verifier=RefusingOwnerPresenceAdapter()
    )

    preparation = prepared(orchestrator, session)

    binding = preparation.binding
    assert preparation.review == synthetic_manifest()
    assert binding.store_id == STORE_ID
    assert binding.change_set_id == CHANGE_SET_ID
    assert binding.revision_id == REVISION_ID
    assert binding.digest == DIGEST
    assert binding.approval_adapter == "local_owner_ui"
    assert binding.session_id == session.session_id
    assert len(binding.final_page_nonce) >= 22
    assert binding.expires_at_ns == clock.now_ns + APPROVAL_BINDING_TTL_NS
    other = prepared(orchestrator, session)
    assert other.binding.final_page_nonce != binding.final_page_nonce


@pytest.mark.parametrize(
    ("revision_id", "digest", "lifecycle", "blocker_count"),
    [
        ("csr_" + "f" * 32, DIGEST, "current_draft", 0),
        (REVISION_ID, "e" * 64, "current_draft", 0),
        (REVISION_ID, DIGEST, "applied", 0),
        (REVISION_ID, DIGEST, "superseded", 0),
        (REVISION_ID, DIGEST, "current_draft", 1),
    ],
)
def test_prepare_refuses_a_stale_applied_superseded_or_blocked_revision(
    revision_id: str,
    digest: str,
    lifecycle: str,
    blocker_count: int,
) -> None:
    """Catch approval offered for anything but an exact valid current draft."""
    service = SyntheticApprovalService(
        manifest=synthetic_manifest(
            revision_id=revision_id,
            digest=digest,
            lifecycle=lifecycle,
            blocker_count=blocker_count,
        )
    )
    orchestrator, _service, _verifier, _clock, session, _sessions = build_orchestrator(
        service=service,
        verifier=RefusingOwnerPresenceAdapter(),
    )

    with pytest.raises(StoreError):
        prepared(orchestrator, session)


def test_prepare_refuses_an_inactive_session() -> None:
    """Catch approval authority created for an invalidated UI session."""
    orchestrator, _service, _verifier, _clock, session, sessions = build_orchestrator(
        verifier=RefusingOwnerPresenceAdapter()
    )
    sessions.invalidate_session(session.session_id)

    with pytest.raises(StoreError):
        prepared(orchestrator, session)


def test_resolve_approval_page_is_read_only_repeatable_and_never_leases() -> None:
    """Catch a GET creating, refreshing, leasing, or consuming write authority."""
    orchestrator, service, verifier, clock, session, _sessions = build_orchestrator(
        verifier=RefusingOwnerPresenceAdapter()
    )
    preparation = prepared(orchestrator, session)
    nonce = preparation.binding.final_page_nonce

    clock.advance(APPROVAL_BINDING_TTL_NS // 2)
    first = orchestrator.resolve_approval_page(
        session_id=session.session_id,
        final_page_nonce=nonce,
    )
    second = orchestrator.resolve_approval_page(
        session_id=session.session_id,
        final_page_nonce=nonce,
    )

    assert first is not None and second is not None
    assert first.binding == preparation.binding
    assert second.binding == preparation.binding
    assert first.review == service.manifest
    assert verifier is not None
    assert service.applied == []


def test_resolve_approval_page_refuses_expired_foreign_and_stale_bindings() -> None:
    """Catch an unusable binding still rendering an approvable final page."""
    orchestrator, service, _verifier, clock, session, _sessions = build_orchestrator(
        verifier=RefusingOwnerPresenceAdapter()
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    foreign = orchestrator.resolve_approval_page(
        session_id=OTHER_SESSION,
        final_page_nonce=nonce,
    )
    unknown = orchestrator.resolve_approval_page(
        session_id=session.session_id,
        final_page_nonce="non-unknown",
    )
    service.manifest = synthetic_manifest(revision_id="csr_" + "f" * 32)
    now_stale = orchestrator.resolve_approval_page(
        session_id=session.session_id,
        final_page_nonce=nonce,
    )
    service.manifest = synthetic_manifest()
    clock.advance(APPROVAL_BINDING_TTL_NS)
    expired = orchestrator.resolve_approval_page(
        session_id=session.session_id,
        final_page_nonce=nonce,
    )

    assert foreign is None
    assert unknown is None
    assert now_stale is None
    assert expired is None


def test_submit_mints_one_approval_only_after_the_os_prompt_succeeds() -> None:
    """Catch an applied review whose approval never passed owner presence."""
    orchestrator, service, verifier, clock, session, _sessions = build_orchestrator()
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    detail = submit(orchestrator, session, nonce)

    assert verifier.calls == 1
    assert verifier.reasons == [f"Memory: approve Memory Review {DIGEST[:12]}"]
    assert service.applied == [("local_owner_ui", CHANGE_SET_ID, REVISION_ID, DIGEST)]
    assert detail.application.application_id == APPLICATION_ID
    assert clock.samples.count(clock.now_ns) >= 3


@pytest.mark.parametrize("outcome", ["cancelled", "unavailable"])
def test_cancelled_or_unavailable_owner_presence_applies_nothing(
    outcome: str,
) -> None:
    """Catch a refused system prompt still applying the reviewed revision."""
    verifier = SyntheticOwnerPresenceAdapter(outcome=outcome)
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(OwnerApprovalRequiredError):
        submit(orchestrator, session, nonce)

    assert service.applied == []
    assert (
        orchestrator.resolve_approval_page(
            session_id=session.session_id,
            final_page_nonce=nonce,
        )
        is None
    )
    with pytest.raises(StoreError):
        submit(orchestrator, session, nonce)
    assert verifier.calls == 1


def test_expiry_during_the_awaited_prompt_applies_nothing() -> None:
    """Catch a binding applied after its two-minute monotonic expiry passed."""
    clock = SteppingClock()
    verifier = SyntheticOwnerPresenceAdapter(
        during=lambda: clock.advance(APPROVAL_BINDING_TTL_NS)
    )
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier,
        clock=clock,
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(OwnerApprovalRequiredError):
        submit(orchestrator, session, nonce)

    assert service.applied == []
    assert verifier.calls == 1


def test_session_invalidation_during_the_awaited_prompt_applies_nothing() -> None:
    """Catch an applied review whose UI session died while the prompt was open."""
    holder: dict[str, Any] = {}
    verifier = SyntheticOwnerPresenceAdapter(
        during=lambda: holder["sessions"].invalidate_session(holder["session_id"])
    )
    orchestrator, service, _verifier, _clock, session, sessions = build_orchestrator(
        verifier=verifier
    )
    holder["sessions"] = sessions
    holder["session_id"] = session.session_id
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(OwnerApprovalRequiredError):
        submit(orchestrator, session, nonce)

    assert service.applied == []


def test_review_change_during_the_awaited_prompt_applies_nothing() -> None:
    """Catch an approval applying a revision the owner never saw or approved."""
    service = SyntheticApprovalService()
    verifier = SyntheticOwnerPresenceAdapter(
        during=lambda: setattr(
            service,
            "manifest",
            synthetic_manifest(revision_id="csr_" + "f" * 32, digest="e" * 64),
        )
    )
    orchestrator, _service, _verifier, _clock, session, _sessions = build_orchestrator(
        service=service,
        verifier=verifier,
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(StoreError):
        submit(orchestrator, session, nonce)

    assert service.applied == []


def test_racing_duplicate_submission_during_flight_applies_exactly_once() -> None:
    """Catch a second POST restarting, stealing, or duplicating an apply."""
    verifier = SyntheticOwnerPresenceAdapter(gate=True)
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    async def race() -> tuple[Any, BaseException | None]:
        first = asyncio.create_task(
            orchestrator.submit_approval(
                session_id=session.session_id,
                final_page_nonce=nonce,
                submitted_revision_id=REVISION_ID,
                submitted_digest=DIGEST,
            )
        )
        await verifier.started.wait()
        raised: BaseException | None = None
        try:
            await orchestrator.submit_approval(
                session_id=session.session_id,
                final_page_nonce=nonce,
                submitted_revision_id=REVISION_ID,
                submitted_digest=DIGEST,
            )
        except BaseException as error:
            raised = error
        verifier.release.set()
        return await first, raised

    detail, refused = asyncio.run(race())

    assert isinstance(refused, StoreError)
    assert verifier.calls == 1
    assert service.applied == [("local_owner_ui", CHANGE_SET_ID, REVISION_ID, DIGEST)]
    assert detail.application.application_id == APPLICATION_ID


@pytest.mark.parametrize(
    ("revision_id", "digest"),
    [("csr_" + "f" * 32, DIGEST), (REVISION_ID, "e" * 64)],
)
def test_submitted_revision_or_digest_mismatch_never_reaches_the_prompt(
    revision_id: str,
    digest: str,
) -> None:
    """Catch a browser value replacing the exact server-bound revision state."""
    verifier = RefusingOwnerPresenceAdapter()
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(StoreError):
        asyncio.run(
            orchestrator.submit_approval(
                session_id=session.session_id,
                final_page_nonce=nonce,
                submitted_revision_id=revision_id,
                submitted_digest=digest,
            )
        )

    assert service.applied == []
    with pytest.raises(StoreError):
        submit(orchestrator, session, nonce)


def test_completed_duplicate_returns_the_original_application_without_verifying() -> (
    None
):
    """Catch a duplicate submission reminting approval or applying a second time."""
    orchestrator, service, verifier, clock, session, _sessions = build_orchestrator()
    nonce = prepared(orchestrator, session).binding.final_page_nonce
    first = submit(orchestrator, session, nonce)

    clock.advance(1_000)
    replay = submit(orchestrator, session, nonce)

    assert replay == first
    assert verifier.calls == 1
    assert service.applied == [("local_owner_ui", CHANGE_SET_ID, REVISION_ID, DIGEST)]


def test_owner_presence_wait_is_capped_and_consumes_the_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an unbounded OS wait retaining reusable approval authority."""
    monkeypatch.setattr(owner_presence, "OWNER_PRESENCE_TIMEOUT_SECONDS", 0.05)
    verifier = SyntheticOwnerPresenceAdapter(outcome="hang")
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(OwnerApprovalRequiredError):
        submit(orchestrator, session, nonce)

    assert service.applied == []
    with pytest.raises(StoreError):
        submit(orchestrator, session, nonce)


def test_receipt_from_another_lease_or_binding_cannot_mint_approval() -> None:
    """Catch a replayed or forged receipt minting an internal approval."""
    foreign = ui_binding(final_page_nonce="non-foreign")
    for verifier in (
        SyntheticOwnerPresenceAdapter(receipt_lease_id="apl_" + "0" * 32),
        SyntheticOwnerPresenceAdapter(receipt_binding=foreign),
    ):
        orchestrator, service, _v, _clock, session, _sessions = build_orchestrator(
            verifier=verifier
        )
        nonce = prepared(orchestrator, session).binding.final_page_nonce

        with pytest.raises(OwnerApprovalRequiredError):
            submit(orchestrator, session, nonce)

        assert service.applied == []


def test_mint_functions_reject_foreign_receipts_and_the_other_binding_variant() -> None:
    """Catch a UI receipt minting a CLI approval or an arbitrary object minting."""
    ui_receipt = VerifiedOwnerPresence(
        owner_presence._PRESENCE_CONSTRUCTOR,
        binding=ui_binding(),
        lease_id="apl_" + "0" * 32,
        verified_at_ns=1,
    )
    cli_receipt = VerifiedOwnerPresence(
        owner_presence._PRESENCE_CONSTRUCTOR,
        binding=cli_binding(),
        lease_id="apl_" + "0" * 32,
        verified_at_ns=1,
    )

    with pytest.raises(InvalidArgumentError):
        owner_presence._mint_ui_owner_approval(cli_receipt)
    with pytest.raises(InvalidArgumentError):
        owner_presence._mint_cli_owner_approval(ui_receipt)
    for forged in (object(), True, "local_owner_ui", {"approve": True}):
        with pytest.raises(InvalidArgumentError):
            owner_presence._mint_ui_owner_approval(forged)  # type: ignore[arg-type]
        with pytest.raises(InvalidArgumentError):
            owner_presence._mint_cli_owner_approval(forged)  # type: ignore[arg-type]
    assert owner_presence._mint_ui_owner_approval(ui_receipt) is not None
    assert owner_presence._mint_cli_owner_approval(cli_receipt) is not None


class SyntheticLocalAuthenticationContext:
    """Test-only stand-in for one macOS LAContext; never a production type."""

    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.policy: object = None
        self.reason: str | None = None
        self.invalidations = 0
        self.threads: list[threading.Thread] = []

    def evaluatePolicy_localizedReason_reply_(
        self,
        policy: object,
        reason: str,
        reply: Callable[[object, object], None],
    ) -> None:
        self.policy = policy
        self.reason = reason
        if self.behavior == "pending":
            return
        replies: tuple[tuple[object, object], ...]
        if self.behavior == "succeed":
            replies = ((True, None),)
        elif self.behavior == "refuse":
            replies = ((False, "synthetic content-free framework error"),)
        else:
            replies = ((True, None), (True, None), (False, "late"))

        def deliver() -> None:
            for success, error in replies:
                reply(success, error)

        thread = threading.Thread(target=deliver)
        self.threads.append(thread)
        thread.start()
        thread.join(timeout=2)

    def invalidate(self) -> None:
        self.invalidations += 1


class SyntheticLocalAuthenticationVerifier(
    owner_presence.LocalAuthenticationOwnerPresenceVerifier
):
    """Drive the production adapter without ever reaching the real OS prompt."""

    def __init__(self, behavior: str = "succeed") -> None:
        super().__init__()
        self.behavior = behavior
        self.contexts: list[SyntheticLocalAuthenticationContext] = []

    def _new_context(self) -> object:
        context = SyntheticLocalAuthenticationContext(self.behavior)
        self.contexts.append(context)
        return context

    @staticmethod
    def _policy() -> object:
        return "synthetic-device-owner-authentication"


def synthetic_lease(lease_id: str = "apl_" + "c" * 32) -> ApprovalChallengeLease:
    """Build one in-flight challenge lease for adapter-level tests."""
    return ApprovalChallengeLease(
        lease_id=lease_id,
        binding=ui_binding(created_at_ns=1_000_000_000),
        state="in_flight",
    )


def test_local_authentication_adapter_completes_from_a_background_thread() -> None:
    """Catch a blocking event loop or a receipt built off the owning loop."""
    verifier = SyntheticLocalAuthenticationVerifier()
    lease = synthetic_lease()

    receipt = asyncio.run(
        verifier.verify(lease, reason=owner_presence_reason(lease.binding))
    )

    assert isinstance(receipt, VerifiedOwnerPresence)
    assert receipt.binding == lease.binding
    assert receipt.lease_id == lease.lease_id
    assert isinstance(receipt.verified_at_ns, int)
    assert len(verifier.contexts) == 1
    assert verifier.contexts[0].reason == owner_presence_reason(lease.binding)
    assert verifier.contexts[0].policy == "synthetic-device-owner-authentication"
    assert verifier.pending_prompt_count == 0


def test_local_authentication_adapter_refuses_a_failed_prompt_without_details() -> None:
    """Catch a cancelled or failed system prompt returning owner-presence proof."""
    verifier = SyntheticLocalAuthenticationVerifier(behavior="refuse")
    lease = synthetic_lease()

    with pytest.raises(OwnerApprovalRequiredError) as raised:
        asyncio.run(verifier.verify(lease, reason="synthetic reason"))

    assert "synthetic content-free framework error" not in str(raised.value)
    assert verifier.pending_prompt_count == 0


def test_duplicate_and_late_callbacks_complete_the_prompt_exactly_once() -> None:
    """Catch a repeated framework callback reopening or reversing one decision."""
    verifier = SyntheticLocalAuthenticationVerifier(behavior="duplicate")
    lease = synthetic_lease()

    receipt = asyncio.run(verifier.verify(lease, reason="synthetic reason"))

    assert isinstance(receipt, VerifiedOwnerPresence)
    assert verifier.pending_prompt_count == 0


def test_capped_wait_invalidates_a_pending_context_and_returns_no_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an unbounded OS wait or a retained context after the cap elapses."""
    monkeypatch.setattr(owner_presence, "OWNER_PRESENCE_TIMEOUT_SECONDS", 0.05)
    verifier = SyntheticLocalAuthenticationVerifier(behavior="pending")
    lease = synthetic_lease()

    with pytest.raises(OwnerApprovalRequiredError):
        asyncio.run(owner_presence.await_owner_presence(verifier, lease))

    assert verifier.contexts[0].invalidations >= 1
    assert verifier.pending_prompt_count == 0


def test_shutdown_while_the_prompt_is_pending_fails_closed_and_invalidates() -> None:
    """Catch a server shutdown leaving an awaited prompt able to mint approval."""
    verifier = SyntheticLocalAuthenticationVerifier(behavior="pending")
    lease = synthetic_lease()

    async def shutdown_during_prompt() -> None:
        task = asyncio.create_task(verifier.verify(lease, reason="synthetic reason"))
        while verifier.pending_prompt_count == 0:
            await asyncio.sleep(0)
        verifier.shutdown()
        await task

    with pytest.raises(OwnerApprovalRequiredError):
        asyncio.run(shutdown_during_prompt())

    assert verifier.contexts[0].invalidations >= 1
    assert verifier.pending_prompt_count == 0


def test_invalidating_one_lease_leaves_other_pending_prompts_untouched() -> None:
    """Catch one invalidated session cancelling another session's open prompt."""
    verifier = SyntheticLocalAuthenticationVerifier(behavior="pending")
    first = synthetic_lease("apl_" + "1" * 32)
    second = synthetic_lease("apl_" + "2" * 32)

    async def invalidate_one() -> None:
        tasks = [
            asyncio.create_task(verifier.verify(lease, reason="synthetic reason"))
            for lease in (first, second)
        ]
        while verifier.pending_prompt_count < 2:
            await asyncio.sleep(0)
        verifier.invalidate(first.lease_id)
        with pytest.raises(OwnerApprovalRequiredError):
            await tasks[0]
        assert verifier.pending_prompt_count == 1
        tasks[1].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[1]

    asyncio.run(invalidate_one())

    assert verifier.contexts[0].invalidations >= 1
    assert verifier.contexts[1].invalidations >= 1
    assert verifier.pending_prompt_count == 0


def test_production_adapter_selects_device_owner_authentication_without_prompting() -> (
    None
):
    """Catch a weaker policy or a missing LocalAuthentication dependency."""
    # pyobjc ships LocalAuthentication without stubs or a py.typed marker, so
    # the production adapter skips analysing it the same way at its own import.
    from LocalAuthentication import (  # type: ignore[import-untyped]
        LAPolicyDeviceOwnerAuthentication,
    )

    policy = owner_presence.LocalAuthenticationOwnerPresenceVerifier._policy()

    assert policy == LAPolicyDeviceOwnerAuthentication


def test_receipt_verified_after_the_binding_deadline_cannot_mint_approval() -> None:
    """Catch a receipt produced after expiry still reaching the atomic apply."""
    verifier = SyntheticOwnerPresenceAdapter(
        receipt_verified_at_ns=1_000_000_000 + APPROVAL_BINDING_TTL_NS
    )
    orchestrator, service, _verifier, _clock, session, _sessions = build_orchestrator(
        verifier=verifier
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(OwnerApprovalRequiredError):
        submit(orchestrator, session, nonce)

    assert service.applied == []


def test_lost_challenge_lease_during_the_prompt_mints_and_applies_nothing() -> None:
    """Catch an apply that commits after the store lost its in-flight lease."""
    verifier = SyntheticOwnerPresenceAdapter()
    orchestrator, service, _verifier, _clock, session, sessions = build_orchestrator(
        verifier=verifier
    )
    verifier.during = lambda: orchestrator.attempts.invalidate_session(
        session.session_id
    )
    nonce = prepared(orchestrator, session).binding.final_page_nonce

    with pytest.raises(StoreError):
        submit(orchestrator, session, nonce)

    assert service.applied == []
    assert sessions.is_session_active(session.session_id, now_ns=2_000_000_000)
    assert verifier.calls == 1
