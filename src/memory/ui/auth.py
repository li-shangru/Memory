"""Process-local bootstrap, session, search, and audit capabilities."""

from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Container
from dataclasses import dataclass, field
from typing import Protocol

from memory.errors import InvalidArgumentError, StoreBusyError
from memory.model import (
    UiAuditState,
    UiReviewRefusal,
    UiSearchState,
    UiSession,
)
from memory.ui.capture import (
    CORRECTION_FORM_TTL_NS,
    MAX_CORRECTION_INTENTS,
    MAX_CORRECTION_SESSION_RETAINED_BYTES,
    MAX_OWNER_CORRECTION_SOURCE_BYTES,
    CapturedCorrection,
    CorrectionFormBinding,
    CorrectionInProgressView,
    CorrectionLeaseResult,
    CorrectionRetryView,
    CorrectionStatusView,
    CorrectionSubmissionLease,
    PreparedOwnerCorrection,
)
from memory.ui.view_models import (
    AuditSnapshot,
    PendingReviewConflictLease,
    PendingReviewLease,
    UiPendingReviewConflict,
    UiPendingReviewForm,
    UiPendingReviewState,
)

UI_BOOTSTRAP_TTL_NS = 60_000_000_000
UI_SESSION_TTL_NS = 28_800_000_000_000
UI_SEARCH_HANDLE_TTL_NS = 600_000_000_000
UI_AUDIT_HANDLE_TTL_NS = 600_000_000_000
UI_PENDING_REVIEW_TTL_NS = 600_000_000_000
UI_REVIEW_REFUSAL_TTL_NS = 600_000_000_000
CORRECTION_STATUS_TTL_NS = 600_000_000_000
MAX_PENDING_REVIEW_FORMS = 8

_MAX_SEARCH_HANDLES = 16
_MAX_AUDIT_HANDLES = 8
_MAX_REVIEW_REFUSALS = 4
_MEMORY_ID = re.compile(r"mem_[0-9a-f]{32}")
_LINEAGE_ID = re.compile(r"lin_[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CORRECTION_FOLLOWER_WAIT_SECONDS = 5.0


class _TimestampedState(Protocol):
    """Any handle state that knows when it was created."""

    @property
    def created_at_ns(self) -> int: ...


@dataclass(slots=True)
class _HandleRecord[StateT: _TimestampedState]:
    """One session-owned handle: what it holds, and when it was last used.

    Searches, refused review edits, and audit snapshots are the same object
    with three lifetimes. They share this record, and the expiry and eviction
    below, because they are the code that enforces handle expiry and
    clock-regression safety -- three copies of it means three places a fix has
    to land and two places it can be forgotten.
    """

    state: StateT
    last_seen_ns: int


@dataclass(slots=True)
class _CorrectionRecord:
    binding: CorrectionFormBinding
    phase: str = "pending"
    prepared: PreparedOwnerCorrection | None = None
    lease: CorrectionSubmissionLease | None = None
    result: CapturedCorrection | None = None
    owner_text_sha256: str | None = None
    terminal: _TerminalCorrectionRecord | None = None
    status_requested: bool = False


@dataclass(slots=True)
class _TerminalCorrectionRecord:
    lease_id: str
    session_id: str
    form_nonce: str
    selected_memory_id: str
    capture_request_id: str
    reserved_batch_id: str
    lineage_id: str
    expected_head_id: str
    captured_at: int
    source_sha256: str
    byte_length: int
    expires_at_ns: int
    phase: str = "revoked"
    status_available: bool = False
    result: CapturedCorrection | None = None
    completed_at_ns: int | None = None


@dataclass(slots=True)
class _PendingReviewRecord:
    form: UiPendingReviewForm
    last_seen_ns: int
    phase: str = "retryable"
    lease_id: str | None = None
    current_revision_id: str | None = None
    current_digest: str | None = None
    current_target_fingerprint: str | None = None


@dataclass(slots=True)
class _SessionRecord:
    session: UiSession
    last_seen_ns: int
    searches: OrderedDict[str, _HandleRecord[UiSearchState]] = field(
        default_factory=OrderedDict
    )
    audits: OrderedDict[str, _HandleRecord[UiAuditState]] = field(
        default_factory=OrderedDict
    )
    corrections: OrderedDict[str, _CorrectionRecord] = field(
        default_factory=OrderedDict
    )
    pending_reviews: OrderedDict[str, _PendingReviewRecord] = field(
        default_factory=OrderedDict
    )
    review_refusals: OrderedDict[str, _HandleRecord[UiReviewRefusal]] = field(
        default_factory=OrderedDict
    )


class UiSessionStore:
    """Keep every UI authority only in the process that issued it."""

    def __init__(
        self,
        *,
        bootstrap_capability: str,
        exact_host: str,
        created_at_ns: int,
    ) -> None:
        self._bootstrap_capability = bootstrap_capability
        self._exact_host = exact_host
        self._bootstrap_created_at_ns = created_at_ns
        self._bootstrap_consumed = False
        self._sessions: dict[str, _SessionRecord] = {}
        self._orphaned_corrections: dict[str, _TerminalCorrectionRecord] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._correction_wait_timeout_seconds = _CORRECTION_FOLLOWER_WAIT_SECONDS

    @property
    def active_session_count(self) -> int:
        """Return the number of currently retained process sessions."""
        return len(self._sessions)

    def issue_correction_form(
        self,
        session_id: str,
        selected_memory_id: str,
        *,
        now_ns: int,
    ) -> CorrectionFormBinding:
        """Issue one bounded same-session, target-bound correction intent."""
        if (
            not isinstance(selected_memory_id, str)
            or _MEMORY_ID.fullmatch(selected_memory_id) is None
        ):
            raise InvalidArgumentError("correction target is invalid")
        with self._lock:
            record = self._require_session(session_id, now_ns=now_ns)
            self._reap_corrections(record, now_ns=now_ns)
            if len(record.corrections) >= MAX_CORRECTION_INTENTS:
                raise InvalidArgumentError("correction intent capacity is full")
            nonce = self._new_handle(record.corrections)
            binding = CorrectionFormBinding(
                session_id=session_id,
                form_nonce=nonce,
                selected_memory_id=selected_memory_id,
                expires_at_ns=now_ns + CORRECTION_FORM_TTL_NS,
            )
            record.corrections[nonce] = _CorrectionRecord(binding=binding)
            return binding

    def resolve_correction_form(
        self,
        session_id: str,
        form_nonce: str,
        *,
        now_ns: int,
    ) -> CorrectionFormBinding | None:
        """Resolve a submit-capable correction form without refreshing it."""
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or not self.is_session_active(session_id, now_ns=now_ns):
                return None
            self._reap_corrections(record, now_ns=now_ns)
            correction = record.corrections.get(form_nonce)
            if correction is None or correction.phase not in {
                "pending",
                "in_flight",
                "completed",
            }:
                return None
            return correction.binding

    def lease_correction_form(
        self,
        session_id: str,
        form_nonce: str,
        selected_memory_id: str,
        prepared: PreparedOwnerCorrection,
        *,
        now_ns: int,
    ) -> CorrectionLeaseResult:
        """Atomically bind canonical bytes and reserve durable capture IDs."""
        self._validate_prepared(prepared)
        with self._condition:
            session = self._require_session(session_id, now_ns=now_ns)
            self._reap_corrections(session, now_ns=now_ns)
            record = session.corrections.get(form_nonce)
            if (
                record is None
                or record.binding.selected_memory_id != selected_memory_id
            ):
                raise InvalidArgumentError("correction form is unavailable")
            if prepared.selected_memory_id != selected_memory_id:
                raise InvalidArgumentError("prepared correction target is invalid")
            wait_deadline = time.monotonic() + self._correction_wait_timeout_seconds
            while record.phase == "in_flight":
                if (
                    record.lease is None
                    or record.prepared is None
                    or record.prepared.owner_text_sha256 != prepared.owner_text_sha256
                ):
                    raise InvalidArgumentError(
                        "correction submission is already leased"
                    )
                remaining = wait_deadline - time.monotonic()
                if remaining <= 0:
                    record.status_requested = True
                    raise StoreBusyError("correction submission is in flight")
                self._condition.wait(timeout=remaining)
            if record.phase == "completed":
                if (
                    record.result is None
                    or record.owner_text_sha256 != prepared.owner_text_sha256
                ):
                    raise InvalidArgumentError("correction replay does not match")
                return record.result
            if record.phase == "retryable":
                raise StoreBusyError("correction submission is retryable")
            if record.phase == "revoked":
                raise InvalidArgumentError("correction form is unavailable")
            if record.phase != "pending":
                raise InvalidArgumentError("correction form is unavailable")
            retained = self._retained_correction_bytes()
            terminal_count = len(self._orphaned_corrections)
            in_flight_count = sum(
                correction.prepared is not None
                for active in self._sessions.values()
                for correction in active.corrections.values()
            )
            if (
                terminal_count + in_flight_count >= MAX_CORRECTION_INTENTS
                or retained + len(prepared.source_bytes)
                > MAX_CORRECTION_SESSION_RETAINED_BYTES
            ):
                raise InvalidArgumentError("correction byte capacity is full")
            lease = CorrectionSubmissionLease(
                lease_id=f"les_{secrets.token_hex(16)}",
                binding=record.binding,
                prepared=prepared,
                capture_request_id=f"cap_{secrets.token_hex(16)}",
                reserved_batch_id=f"bat_{secrets.token_hex(16)}",
                state="in_flight",
            )
            record.phase = "in_flight"
            record.prepared = prepared
            record.lease = lease
            record.owner_text_sha256 = prepared.owner_text_sha256
            return lease

    def resolve_retryable_correction(
        self,
        session_id: str,
        form_nonce: str,
        *,
        now_ns: int,
    ) -> CorrectionRetryView | None:
        """Return owner text derived from the sole retained canonical buffer."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not self.is_session_active(session_id, now_ns=now_ns):
                return None
            self._reap_corrections(session, now_ns=now_ns)
            record = session.corrections.get(form_nonce)
            if record is None or record.phase != "retryable":
                return None
            prepared = record.prepared
            if prepared is None:
                raise InvalidArgumentError("retryable correction bytes are missing")
            return CorrectionRetryView(
                form_nonce=form_nonce,
                selected_memory_id=record.binding.selected_memory_id,
                owner_text=self._owner_text(prepared),
                expires_at_ns=record.binding.expires_at_ns,
            )

    def resolve_correction_status(
        self,
        session_id: str,
        form_nonce: str,
        *,
        now_ns: int,
    ) -> CorrectionStatusView | None:
        """Read one retained correction status without consuming any authority.

        A completed result is readable repeatedly for its own ten-minute
        tombstone lifetime and is released only by that lifetime, session
        invalidation, or shutdown. Resolving never pops a retained record, so a
        read can never free a `MAX_CORRECTION_INTENTS` slot and thereby permit a
        write the capacity gate would otherwise refuse. The in-flight marks
        below only retain state; they never release it.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not self.is_session_active(
                session_id,
                now_ns=now_ns,
            ):
                return None
            self._reap_corrections(session, now_ns=now_ns)
            record = session.corrections.get(form_nonce)
            if record is not None:
                if record.phase == "completed":
                    if not record.status_requested:
                        return None
                    return record.result
                if record.phase == "in_flight":
                    record.status_requested = True
                    return CorrectionInProgressView(
                        form_nonce=form_nonce,
                        selected_memory_id=record.binding.selected_memory_id,
                        expires_at_ns=record.binding.expires_at_ns,
                    )
                if record.phase != "retryable":
                    return None
                prepared = record.prepared
                if prepared is None:
                    raise InvalidArgumentError("retryable correction bytes are missing")
                return CorrectionRetryView(
                    form_nonce=form_nonce,
                    selected_memory_id=record.binding.selected_memory_id,
                    owner_text=self._owner_text(prepared),
                    expires_at_ns=record.binding.expires_at_ns,
                )
            terminal = self._terminal_for_status(session_id, form_nonce)
            if terminal is None:
                return None
            if terminal.phase == "completed":
                return terminal.result
            if terminal.phase == "in_flight":
                terminal.status_available = True
                return CorrectionInProgressView(
                    form_nonce=form_nonce,
                    selected_memory_id=terminal.selected_memory_id,
                    expires_at_ns=terminal.expires_at_ns,
                )
            return None

    def lease_retryable_correction(
        self,
        session_id: str,
        form_nonce: str,
        *,
        now_ns: int,
    ) -> CorrectionSubmissionLease:
        """Re-lease retained bytes without receiving them from the browser."""
        with self._lock:
            session = self._require_session(session_id, now_ns=now_ns)
            self._reap_corrections(session, now_ns=now_ns)
            record = session.corrections.get(form_nonce)
            if (
                record is None
                or record.phase != "retryable"
                or record.lease is None
                or record.prepared is None
            ):
                raise InvalidArgumentError("retryable correction is unavailable")
            lease = CorrectionSubmissionLease(
                lease_id=f"les_{secrets.token_hex(16)}",
                binding=record.binding,
                prepared=record.prepared,
                capture_request_id=record.lease.capture_request_id,
                reserved_batch_id=record.lease.reserved_batch_id,
                state="in_flight",
            )
            record.phase = "in_flight"
            record.lease = lease
            return lease

    def complete_correction_form(
        self,
        lease: CorrectionSubmissionLease,
        result: CapturedCorrection,
        *,
        now_ns: int,
    ) -> None:
        """Store a content-free replay result and erase terminal source bytes."""
        with self._condition:
            record = self._find_correction_for_lease(lease)
            if (
                result.capture_request_id != lease.capture_request_id
                or result.batch_id != lease.reserved_batch_id
                or result.lineage_id != lease.prepared.lineage_id
                or result.expected_head_id != lease.prepared.expected_head_id
                or result.captured_at != lease.prepared.captured_at
            ):
                raise InvalidArgumentError("captured correction result is mismatched")
            if isinstance(record, _TerminalCorrectionRecord):
                if not self._terminal_matches_lease(record, lease):
                    raise InvalidArgumentError("correction lease is mismatched")
                if record.status_available:
                    record.phase = "completed"
                    record.result = result
                    record.completed_at_ns = now_ns
                else:
                    self._orphaned_corrections.pop(lease.lease_id, None)
                self._condition.notify_all()
                return
            record.phase = "completed"
            record.result = result
            record.owner_text_sha256 = lease.prepared.owner_text_sha256
            if record.status_requested:
                terminal = self._terminal_from_lease(
                    lease,
                    phase="completed",
                    status_available=True,
                    result=result,
                    completed_at_ns=now_ns,
                )
                record.terminal = terminal
                self._orphaned_corrections[lease.lease_id] = terminal
            record.prepared = None
            record.lease = None
            self._condition.notify_all()

    def mark_correction_retryable(
        self,
        lease: CorrectionSubmissionLease,
        *,
        custody_outcome: str = "ambiguous",
    ) -> None:
        """Retain exact bytes and reservations after a retryable custody failure."""
        with self._condition:
            record = self._find_correction_for_lease(lease)
            if custody_outcome not in {"ambiguous", "proven_empty", "durable"}:
                raise InvalidArgumentError("correction custody outcome is invalid")
            if isinstance(record, _TerminalCorrectionRecord):
                if not self._terminal_matches_lease(record, lease):
                    raise InvalidArgumentError("correction lease is mismatched")
                if custody_outcome in {"proven_empty", "durable"}:
                    self._orphaned_corrections.pop(lease.lease_id, None)
                else:
                    record.phase = "ambiguous"
                    record.status_available = False
                    record.result = None
                self._condition.notify_all()
                return
            if lease.state == "revoked" or record.phase == "revoked":
                if custody_outcome in {"proven_empty", "durable"}:
                    self._remove_correction_record(record)
                self._condition.notify_all()
                return
            record.phase = "retryable"
            self._condition.notify_all()

    def revoke_in_flight_correction(
        self,
        lease: CorrectionSubmissionLease,
    ) -> CorrectionSubmissionLease:
        """Revoke browser authority while retaining in-flight custody state."""
        with self._condition:
            record = self._find_correction_for_lease(lease)
            if isinstance(record, _TerminalCorrectionRecord):
                if not self._terminal_matches_lease(record, lease):
                    raise InvalidArgumentError("correction lease is mismatched")
                if record.phase == "completed":
                    self._remove_completed_terminal_mirrors(record)
                    self._condition.notify_all()
                    return CorrectionSubmissionLease(
                        lease_id=lease.lease_id,
                        binding=lease.binding,
                        prepared=lease.prepared,
                        capture_request_id=lease.capture_request_id,
                        reserved_batch_id=lease.reserved_batch_id,
                        state="revoked",
                    )
                record.phase = "revoked"
                record.status_available = False
                record.result = None
                return CorrectionSubmissionLease(
                    lease_id=lease.lease_id,
                    binding=lease.binding,
                    prepared=lease.prepared,
                    capture_request_id=lease.capture_request_id,
                    reserved_batch_id=lease.reserved_batch_id,
                    state="revoked",
                )
            revoked = CorrectionSubmissionLease(
                lease_id=lease.lease_id,
                binding=lease.binding,
                prepared=lease.prepared,
                capture_request_id=lease.capture_request_id,
                reserved_batch_id=lease.reserved_batch_id,
                state="revoked",
            )
            record.phase = "revoked"
            terminal = self._terminal_from_lease(revoked)
            self._orphaned_corrections[lease.lease_id] = terminal
            self._remove_active_correction_record(record)
            record.prepared = None
            record.lease = None
            self._condition.notify_all()
            return revoked

    def consume_proven_empty_correction_failure(
        self,
        lease: CorrectionSubmissionLease,
    ) -> None:
        """Erase retained bytes only after custody proves no durable claim/batch."""
        with self._condition:
            record = self._find_correction_for_lease(lease)
            if isinstance(record, _CorrectionRecord):
                record.phase = "revoked"
                record.prepared = None
                record.lease = None
                record.result = None
                record.status_requested = False
                record.terminal = None
            self._remove_correction_record(record)
            self._condition.notify_all()

    def exchange_bootstrap(
        self,
        *,
        secret: str,
        exact_host: str,
        now_ns: int,
    ) -> UiSession | None:
        """Exchange the exact host-bound bootstrap once within 60 seconds."""
        with self._lock:
            if self._bootstrap_consumed or exact_host != self._exact_host:
                return None
            age_ns = now_ns - self._bootstrap_created_at_ns
            if age_ns < 0 or age_ns >= UI_BOOTSTRAP_TTL_NS:
                self._bootstrap_consumed = True
                self._bootstrap_capability = ""
                return None
            if not secrets.compare_digest(secret, self._bootstrap_capability):
                return None
            self._bootstrap_consumed = True
            self._bootstrap_capability = ""
            csrf = secrets.token_urlsafe(32)
            session = UiSession(
                session_id=secrets.token_urlsafe(32),
                csrf_token=csrf,
                expires_at_ns=now_ns + UI_SESSION_TTL_NS,
            )
            self._sessions[session.session_id] = _SessionRecord(
                session=session,
                last_seen_ns=now_ns,
            )
            return session

    def resolve_cookie(
        self,
        *,
        cookie: str,
        exact_host: str,
        now_ns: int,
    ) -> UiSession | None:
        """Resolve an opaque cookie only for its exact origin and timeline."""
        with self._lock:
            if not cookie or exact_host != self._exact_host:
                return None
            record = self._sessions.get(cookie)
            if record is None:
                return None
            if now_ns < record.last_seen_ns or now_ns >= record.session.expires_at_ns:
                self.invalidate_session(cookie)
                return None
            record.last_seen_ns = now_ns
            return record.session

    def is_session_active(self, session_id: str, *, now_ns: int) -> bool:
        """Check a session without extending its fixed lifetime."""
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return False
            if now_ns < record.last_seen_ns or now_ns >= record.session.expires_at_ns:
                self.invalidate_session(session_id)
                return False
            record.last_seen_ns = now_ns
            return True

    @staticmethod
    def _remember_handle[StateT: _TimestampedState](
        table: OrderedDict[str, _HandleRecord[StateT]],
        state: StateT,
        *,
        limit: int,
    ) -> str:
        """Bind one state to a fresh handle, evicting the oldest past `limit`."""
        handle = UiSessionStore._new_handle(table)
        table[handle] = _HandleRecord(state=state, last_seen_ns=state.created_at_ns)
        while len(table) > limit:
            table.popitem(last=False)
        return handle

    @staticmethod
    def _resolve_handle[StateT: _TimestampedState](
        table: OrderedDict[str, _HandleRecord[StateT]],
        handle: str,
        *,
        now_ns: int,
        ttl_ns: int,
    ) -> StateT | None:
        """Resolve one live handle, dropping it if it expired or the clock went back.

        A `now_ns` behind the handle's own last use is not a young handle: it
        is a clock that moved backwards, and the handle is dropped rather than
        trusted for another lifetime.
        """
        held = table.get(handle)
        if held is None:
            return None
        if now_ns < held.last_seen_ns or now_ns - held.state.created_at_ns >= ttl_ns:
            table.pop(handle, None)
            return None
        held.last_seen_ns = now_ns
        return held.state

    def _active_session_record(
        self,
        session_id: str,
        *,
        now_ns: int,
    ) -> _SessionRecord | None:
        record = self._sessions.get(session_id)
        if record is None or not self.is_session_active(session_id, now_ns=now_ns):
            return None
        return record

    def remember_search(self, session_id: str, search: UiSearchState) -> str:
        """Bind one private search to a bounded opaque session handle."""
        record = self._require_session(session_id, now_ns=search.created_at_ns)
        return self._remember_handle(
            record.searches,
            search,
            limit=_MAX_SEARCH_HANDLES,
        )

    def resolve_search(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> UiSearchState | None:
        """Resolve one same-session search handle within its fixed lifetime."""
        record = self._active_session_record(session_id, now_ns=now_ns)
        if record is None:
            return None
        return self._resolve_handle(
            record.searches,
            handle,
            now_ns=now_ns,
            ttl_ns=UI_SEARCH_HANDLE_TTL_NS,
        )

    def remember_review_refusal(
        self,
        session_id: str,
        refusal: UiReviewRefusal,
    ) -> str:
        """Bind one refused review edit to a bounded opaque session handle."""
        record = self._require_session(session_id, now_ns=refusal.created_at_ns)
        return self._remember_handle(
            record.review_refusals,
            refusal,
            limit=_MAX_REVIEW_REFUSALS,
        )

    def resolve_review_refusal(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> UiReviewRefusal | None:
        """Resolve one same-session refusal handle within its fixed lifetime."""
        record = self._active_session_record(session_id, now_ns=now_ns)
        if record is None:
            return None
        return self._resolve_handle(
            record.review_refusals,
            handle,
            now_ns=now_ns,
            ttl_ns=UI_REVIEW_REFUSAL_TTL_NS,
        )

    def review_refusal_count(self, session_id: str) -> int:
        """Return the number of retained refused owner edits for one session."""
        record = self._sessions.get(session_id)
        return 0 if record is None else len(record.review_refusals)

    def remember_audit(self, session_id: str, audit: UiAuditState) -> str:
        """Bind one immutable audit snapshot to a bounded session handle."""
        record = self._require_session(session_id, now_ns=audit.created_at_ns)
        return self._remember_handle(record.audits, audit, limit=_MAX_AUDIT_HANDLES)

    def resolve_audit(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> AuditSnapshot | None:
        """Resolve one same-session audit snapshot within its fixed lifetime."""
        record = self._active_session_record(session_id, now_ns=now_ns)
        if record is None:
            return None
        state = self._resolve_handle(
            record.audits,
            handle,
            now_ns=now_ns,
            ttl_ns=UI_AUDIT_HANDLE_TTL_NS,
        )
        return None if state is None else state.snapshot

    def remember_pending_review(
        self,
        session_id: str,
        form: UiPendingReviewForm,
    ) -> str:
        """Retain one bounded normalized owner edit behind an opaque handle."""
        if not isinstance(form, UiPendingReviewForm):
            raise InvalidArgumentError("pending review form is invalid")
        created_at_ns = form.expires_at_ns - UI_PENDING_REVIEW_TTL_NS
        with self._lock:
            existing = self._sessions.get(session_id)
            record = self._require_session(
                session_id,
                now_ns=created_at_ns
                if existing is None
                else max(created_at_ns, existing.last_seen_ns),
            )
            self._reap_pending_reviews(record, now_ns=created_at_ns)
            while len(record.pending_reviews) >= MAX_PENDING_REVIEW_FORMS:
                evictable = next(
                    (
                        handle
                        for handle, pending in record.pending_reviews.items()
                        if pending.phase != "in_flight"
                    ),
                    None,
                )
                if evictable is None:
                    raise InvalidArgumentError("pending review capacity is full")
                record.pending_reviews.pop(evictable, None)
            handle = self._new_handle(record.pending_reviews)
            record.pending_reviews[handle] = _PendingReviewRecord(
                form=form,
                last_seen_ns=created_at_ns,
            )
            return handle

    def resolve_pending_review(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> UiPendingReviewState | None:
        """Resolve a pending owner edit without consuming or refreshing it."""
        with self._lock:
            pending = self._live_pending_review(session_id, handle, now_ns=now_ns)
            if pending is None:
                return None
            if pending.phase == "retryable":
                return pending.form
            if pending.phase != "conflict":
                return None
            if (
                pending.current_revision_id is None
                or pending.current_digest is None
                or pending.current_target_fingerprint is None
            ):
                raise InvalidArgumentError("pending review conflict is incomplete")
            return UiPendingReviewConflict(
                form=pending.form,
                current_revision_id=pending.current_revision_id,
                current_digest=pending.current_digest,
                current_target_fingerprint=pending.current_target_fingerprint,
            )

    def lease_pending_review(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> PendingReviewLease:
        """Atomically take exclusive authority over one retryable owner edit."""
        with self._lock:
            pending = self._live_pending_review(session_id, handle, now_ns=now_ns)
            if pending is None or pending.phase != "retryable":
                raise InvalidArgumentError("pending review is unavailable")
            lease = PendingReviewLease(
                lease_id=f"les_{secrets.token_hex(16)}",
                form=pending.form,
                state="in_flight",
            )
            pending.phase = "in_flight"
            pending.lease_id = lease.lease_id
            return lease

    def lease_pending_review_conflict(
        self,
        session_id: str,
        handle: str,
        *,
        selected_revision_id: str,
        selected_digest: str,
        selected_target_fingerprint: str,
        now_ns: int,
    ) -> PendingReviewConflictLease:
        """Bind one conflicted edit to the exact server-selected current state."""
        with self._lock:
            pending = self._live_pending_review(session_id, handle, now_ns=now_ns)
            if pending is None or pending.phase != "conflict":
                raise InvalidArgumentError("pending review conflict is unavailable")
            lease = PendingReviewConflictLease(
                lease_id=f"les_{secrets.token_hex(16)}",
                form=pending.form,
                selected_revision_id=selected_revision_id,
                selected_digest=selected_digest,
                selected_target_fingerprint=selected_target_fingerprint,
                state="in_flight",
            )
            pending.phase = "in_flight"
            pending.lease_id = lease.lease_id
            return lease

    def complete_pending_review(
        self,
        lease: PendingReviewLease | PendingReviewConflictLease,
    ) -> None:
        """Consume one leased owner edit exactly once."""
        with self._lock:
            located = self._pending_review_for_lease(lease)
            if located is None:
                raise InvalidArgumentError("pending review lease is unavailable")
            session_id, handle, _pending = located
            self._sessions[session_id].pending_reviews.pop(handle, None)

    def mark_pending_review_retryable(
        self,
        lease: PendingReviewLease | PendingReviewConflictLease,
    ) -> None:
        """Return one leased edit to its owner-resolvable pre-lease state."""
        with self._lock:
            located = self._pending_review_for_lease(lease)
            if located is None:
                raise InvalidArgumentError("pending review lease is unavailable")
            _session_id, _handle, pending = located
            pending.phase = (
                "conflict"
                if isinstance(lease, PendingReviewConflictLease)
                else "retryable"
            )
            pending.lease_id = None

    def mark_pending_review_conflict(
        self,
        lease: PendingReviewLease | PendingReviewConflictLease,
        *,
        current_revision_id: str,
        current_digest: str,
        current_target_fingerprint: str,
    ) -> None:
        """Retain one unapplied edit against the exact current review state."""
        with self._lock:
            located = self._pending_review_for_lease(lease)
            if located is None:
                raise InvalidArgumentError("pending review lease is unavailable")
            _session_id, _handle, pending = located
            pending.phase = "conflict"
            pending.lease_id = None
            pending.current_revision_id = current_revision_id
            pending.current_digest = current_digest
            pending.current_target_fingerprint = current_target_fingerprint

    def pending_review_count(self, session_id: str) -> int:
        """Return the number of retained pending owner edits for one session."""
        with self._lock:
            record = self._sessions.get(session_id)
            return 0 if record is None else len(record.pending_reviews)

    def _live_pending_review(
        self,
        session_id: str,
        handle: str,
        *,
        now_ns: int,
    ) -> _PendingReviewRecord | None:
        record = self._sessions.get(session_id)
        if record is None or not self.is_session_active(session_id, now_ns=now_ns):
            return None
        self._reap_pending_reviews(record, now_ns=now_ns)
        pending = record.pending_reviews.get(handle)
        if pending is None:
            return None
        if now_ns < pending.last_seen_ns:
            record.pending_reviews.pop(handle, None)
            return None
        pending.last_seen_ns = now_ns
        return pending

    def _pending_review_for_lease(
        self,
        lease: PendingReviewLease | PendingReviewConflictLease,
    ) -> tuple[str, str, _PendingReviewRecord] | None:
        if not isinstance(lease, (PendingReviewLease, PendingReviewConflictLease)):
            raise InvalidArgumentError("pending review lease is invalid")
        for session_id, record in self._sessions.items():
            for handle, pending in record.pending_reviews.items():
                if (
                    pending.lease_id == lease.lease_id
                    and pending.phase == "in_flight"
                    and pending.form == lease.form
                ):
                    return session_id, handle, pending
        return None

    def _reap_pending_reviews(self, record: _SessionRecord, *, now_ns: int) -> None:
        for handle, pending in tuple(record.pending_reviews.items()):
            if now_ns >= pending.form.expires_at_ns:
                record.pending_reviews.pop(handle, None)

    def invalidate_session(self, session_id: str) -> None:
        """Erase one session and all capabilities owned by it."""
        with self._condition:
            record = self._sessions.pop(session_id, None)
            if record is None:
                return
            for lease_id, terminal in tuple(self._orphaned_corrections.items()):
                if terminal.session_id != session_id:
                    continue
                if terminal.phase in {"in_flight", "ambiguous", "revoked"}:
                    terminal.phase = "revoked"
                    terminal.status_available = False
                    terminal.result = None
                else:
                    self._orphaned_corrections.pop(lease_id, None)
            for correction in record.corrections.values():
                if correction.terminal is not None:
                    self._orphaned_corrections.pop(
                        correction.terminal.lease_id,
                        None,
                    )
                    correction.terminal = None
                if correction.phase not in {"in_flight", "revoked"}:
                    continue
                lease = correction.lease
                if lease is None:
                    continue
                if lease.state != "revoked":
                    lease = CorrectionSubmissionLease(
                        lease_id=lease.lease_id,
                        binding=lease.binding,
                        prepared=lease.prepared,
                        capture_request_id=lease.capture_request_id,
                        reserved_batch_id=lease.reserved_batch_id,
                        state="revoked",
                    )
                correction.phase = "revoked"
                self._orphaned_corrections[lease.lease_id] = self._terminal_from_lease(
                    lease
                )
                correction.prepared = None
                correction.lease = None
            record.corrections.clear()
            self._condition.notify_all()

    def invalidate_all(self) -> None:
        """Erase bootstrap and every process-local session on shutdown."""
        with self._condition:
            self._bootstrap_consumed = True
            self._bootstrap_capability = ""
            for session_id in tuple(self._sessions):
                self.invalidate_session(session_id)
            self._condition.notify_all()

    def _require_session(self, session_id: str, *, now_ns: int) -> _SessionRecord:
        if not self.is_session_active(session_id, now_ns=now_ns):
            raise InvalidArgumentError("UI session is unavailable")
        return self._sessions[session_id]

    @staticmethod
    def _validate_prepared(prepared: PreparedOwnerCorrection) -> None:
        if (
            not isinstance(prepared, PreparedOwnerCorrection)
            or not isinstance(prepared.selected_memory_id, str)
            or _MEMORY_ID.fullmatch(prepared.selected_memory_id) is None
            or not isinstance(prepared.lineage_id, str)
            or _LINEAGE_ID.fullmatch(prepared.lineage_id) is None
            or not isinstance(prepared.expected_head_id, str)
            or _MEMORY_ID.fullmatch(prepared.expected_head_id) is None
            or not isinstance(prepared.captured_at, int)
            or isinstance(prepared.captured_at, bool)
            or prepared.captured_at < 0
            or not isinstance(prepared.source_bytes, bytes)
            or not isinstance(prepared.owner_text_sha256, str)
            or _DIGEST.fullmatch(prepared.owner_text_sha256) is None
            or not isinstance(prepared.source_sha256, str)
            or _DIGEST.fullmatch(prepared.source_sha256) is None
        ):
            raise InvalidArgumentError("prepared correction is invalid")
        if not 0 < prepared.owner_text_offset < len(prepared.source_bytes):
            raise InvalidArgumentError("prepared correction offset is invalid")
        if not 1 <= len(prepared.source_bytes) <= MAX_OWNER_CORRECTION_SOURCE_BYTES:
            raise InvalidArgumentError("prepared correction size is invalid")
        if hashlib.sha256(prepared.source_bytes).hexdigest() != prepared.source_sha256:
            raise InvalidArgumentError("prepared correction digest is invalid")
        UiSessionStore._owner_text(prepared)

    @staticmethod
    def _owner_text(prepared: PreparedOwnerCorrection) -> str:
        owner_bytes = prepared.source_bytes[prepared.owner_text_offset :]
        if hashlib.sha256(owner_bytes).hexdigest() != prepared.owner_text_sha256:
            raise InvalidArgumentError("prepared owner text digest is invalid")
        try:
            return owner_bytes.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise InvalidArgumentError("prepared owner text is invalid") from error

    def _retained_correction_bytes(
        self,
        record: _SessionRecord | None = None,
    ) -> int:
        records = (record,) if record is not None else tuple(self._sessions.values())
        return sum(
            len(correction.prepared.source_bytes)
            for session in records
            for correction in session.corrections.values()
            if correction.prepared is not None
        )

    def _reap_corrections(self, record: _SessionRecord, *, now_ns: int) -> None:
        self._reap_completed_correction_statuses(now_ns=now_ns)
        changed = False
        for nonce, correction in tuple(record.corrections.items()):
            if now_ns < correction.binding.expires_at_ns:
                continue
            if correction.phase in {"in_flight", "revoked"}:
                lease = correction.lease
                if lease is not None:
                    self._orphaned_corrections[lease.lease_id] = (
                        self._terminal_from_lease(
                            lease,
                            phase=(
                                "in_flight"
                                if correction.phase == "in_flight"
                                else "revoked"
                            ),
                            status_available=(
                                correction.phase == "in_flight"
                                and correction.status_requested
                            ),
                        )
                    )
                    correction.prepared = None
                    correction.lease = None
                    correction.phase = "revoked"
                    record.corrections.pop(nonce, None)
                    changed = True
                    continue
                correction.phase = "revoked"
                record.corrections.pop(nonce, None)
                changed = True
                continue
            if correction.phase == "completed" and correction.terminal is not None:
                terminal = correction.terminal
                self._orphaned_corrections[terminal.lease_id] = terminal
            record.corrections.pop(nonce, None)
            changed = True
        if changed:
            self._condition.notify_all()

    def _find_correction_for_lease(
        self,
        lease: CorrectionSubmissionLease,
    ) -> _CorrectionRecord | _TerminalCorrectionRecord:
        if not isinstance(lease, CorrectionSubmissionLease):
            raise InvalidArgumentError("correction lease is invalid")
        session = self._sessions.get(lease.binding.session_id)
        if session is not None:
            record = session.corrections.get(lease.binding.form_nonce)
            if (
                record is not None
                and record.lease is not None
                and record.lease.lease_id == lease.lease_id
            ):
                return record
        orphan = self._orphaned_corrections.get(lease.lease_id)
        if orphan is not None:
            return orphan
        raise InvalidArgumentError("correction lease is unavailable")

    def _remove_correction_record(
        self,
        target: _CorrectionRecord | _TerminalCorrectionRecord,
    ) -> None:
        if isinstance(target, _TerminalCorrectionRecord):
            self._orphaned_corrections.pop(target.lease_id, None)
            return
        self._remove_active_correction_record(target)

    def _remove_active_correction_record(self, target: _CorrectionRecord) -> None:
        for session in self._sessions.values():
            for nonce, record in tuple(session.corrections.items()):
                if record is target:
                    session.corrections.pop(nonce, None)

    def _remove_completed_terminal_mirrors(
        self,
        terminal: _TerminalCorrectionRecord,
    ) -> None:
        """Consume both completed status mirrors under the condition lock."""
        self._orphaned_corrections.pop(terminal.lease_id, None)
        for session in self._sessions.values():
            for nonce, record in tuple(session.corrections.items()):
                if record.terminal is not terminal:
                    continue
                record.terminal = None
                record.status_requested = False
                record.result = None
                record.phase = "revoked"
                session.corrections.pop(nonce, None)

    def _reap_completed_correction_statuses(self, *, now_ns: int) -> None:
        """Prune only completed status results after their own TTL.

        Reading a completed result is idempotent for this lifetime, so this TTL,
        session invalidation, and shutdown are the only ways it is released.
        """
        expired: list[_TerminalCorrectionRecord] = []
        for terminal in self._orphaned_corrections.values():
            if (
                terminal.phase == "completed"
                and terminal.completed_at_ns is not None
                and now_ns >= terminal.completed_at_ns
                and now_ns - terminal.completed_at_ns >= CORRECTION_STATUS_TTL_NS
            ):
                expired.append(terminal)
        for terminal in expired:
            self._remove_completed_terminal_mirrors(terminal)
        if expired:
            self._condition.notify_all()

    @staticmethod
    def _terminal_from_lease(
        lease: CorrectionSubmissionLease,
        *,
        phase: str = "revoked",
        status_available: bool = False,
        result: CapturedCorrection | None = None,
        completed_at_ns: int | None = None,
    ) -> _TerminalCorrectionRecord:
        return _TerminalCorrectionRecord(
            lease_id=lease.lease_id,
            session_id=lease.binding.session_id,
            form_nonce=lease.binding.form_nonce,
            selected_memory_id=lease.binding.selected_memory_id,
            capture_request_id=lease.capture_request_id,
            reserved_batch_id=lease.reserved_batch_id,
            lineage_id=lease.prepared.lineage_id,
            expected_head_id=lease.prepared.expected_head_id,
            captured_at=lease.prepared.captured_at,
            source_sha256=lease.prepared.source_sha256,
            byte_length=len(lease.prepared.source_bytes),
            expires_at_ns=lease.binding.expires_at_ns,
            phase=phase,
            status_available=status_available,
            result=result,
            completed_at_ns=completed_at_ns,
        )

    def _terminal_for_status(
        self,
        session_id: str,
        form_nonce: str,
    ) -> _TerminalCorrectionRecord | None:
        for terminal in self._orphaned_corrections.values():
            if (
                terminal.session_id == session_id
                and terminal.form_nonce == form_nonce
                and (terminal.phase == "in_flight" or terminal.status_available)
            ):
                return terminal
        return None

    @staticmethod
    def _terminal_matches_lease(
        terminal: _TerminalCorrectionRecord,
        lease: CorrectionSubmissionLease,
    ) -> bool:
        return (
            terminal.lease_id == lease.lease_id
            and terminal.session_id == lease.binding.session_id
            and terminal.form_nonce == lease.binding.form_nonce
            and terminal.selected_memory_id == lease.binding.selected_memory_id
            and terminal.capture_request_id == lease.capture_request_id
            and terminal.reserved_batch_id == lease.reserved_batch_id
            and terminal.lineage_id == lease.prepared.lineage_id
            and terminal.expected_head_id == lease.prepared.expected_head_id
            and terminal.captured_at == lease.prepared.captured_at
            and terminal.source_sha256 == lease.prepared.source_sha256
            and terminal.byte_length == len(lease.prepared.source_bytes)
        )

    @staticmethod
    def _new_handle(records: Container[str]) -> str:
        while True:
            handle = secrets.token_urlsafe(24)
            if handle not in records:
                return handle
