"""macOS owner-presence adapters and one-use internal approval capabilities.

Only this module converts a successful OS-mediated owner decision into the
internal ``OwnerApproval`` capability. No supported HTTP, CLI, or MCP input
accepts a verifier, proof object, success boolean, or approval capability; the
opaque :class:`VerifiedOwnerPresence` receipt is constructed only inside the
concrete LocalAuthentication adapter's private terminal callback.

This enforces the supported protocol boundary. It does not claim to resist
arbitrary Python import/reflection, code patching, or process-memory control by
a malicious same-owner process, which the approved threat model excludes.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, cast, runtime_checkable

from memory.errors import (
    InvalidArgumentError,
    OwnerApprovalRequiredError,
    StaleRevisionError,
    WrongDigestError,
)
from memory.model import ApplicationResult, RuntimePaths
from memory.reviews import (
    OwnerApproval,
    _mint_bound_owner_approval,
    approve_and_apply,
    get_change_set,
)
from memory.runtime import load_runtime_identity
from memory.ui.auth import UiSessionStore
from memory.ui.view_models import (
    OwnerApplicationDetail,
    OwnerReviewManifest,
)

APPROVAL_BINDING_TTL_NS = 120_000_000_000
APPROVAL_TOMBSTONE_TTL_NS = 600_000_000_000
MAX_APPROVAL_ATTEMPTS = 8
OWNER_PRESENCE_TIMEOUT_SECONDS = 120.0

UI_APPROVAL_ADAPTER = "local_owner_ui"
CLI_APPROVAL_ADAPTER = "os_owner_presence_cli"
OWNER_PRESENCE_REASON_DIGEST_CHARACTERS = 12

_PRESENCE_CONSTRUCTOR = object()


@dataclass(frozen=True, slots=True)
class UiApprovalBinding:
    """One pending server-side approval binding owned by one UI session."""

    store_id: str
    change_set_id: str
    revision_id: str
    digest: str
    approval_adapter: Literal["local_owner_ui"]
    session_id: str
    final_page_nonce: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class CliApprovalBinding:
    """One pending approval binding owned by one foreground CLI process."""

    store_id: str
    change_set_id: str
    revision_id: str
    digest: str
    approval_adapter: Literal["os_owner_presence_cli"]
    invocation_nonce: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class ExportPresenceBinding:
    """One plaintext all-sensitivity export, never a canonical-memory approval."""

    store_id: str
    destination: str
    digest: str
    invocation_nonce: str
    expires_at_ns: int


type ApprovalBinding = UiApprovalBinding | CliApprovalBinding | ExportPresenceBinding


@dataclass(frozen=True, slots=True)
class ApprovalChallengeLease:
    """Exclusive in-flight authority to await exactly one OS-mediated prompt."""

    lease_id: str
    binding: ApprovalBinding
    state: Literal["in_flight"]


@dataclass(frozen=True, slots=True)
class CompletedApprovalAttempt:
    """One bounded tombstone for exact same-session duplicate retrieval."""

    binding: ApprovalBinding
    application_id: str
    completed_at_ns: int


@dataclass(frozen=True, slots=True)
class PreparedUiApproval:
    """The exact final-approval page state resolved for one bound review."""

    review: OwnerReviewManifest
    canonical_review: str
    binding: UiApprovalBinding


class VerifiedOwnerPresence:
    """Opaque adapter receipt; no public constructor or deserializer."""

    __slots__ = ("_binding", "_lease_id", "_verified_at_ns")

    def __init__(
        self,
        constructor: object,
        *,
        binding: ApprovalBinding,
        lease_id: str,
        verified_at_ns: int,
    ) -> None:
        if constructor is not _PRESENCE_CONSTRUCTOR:
            raise TypeError("VerifiedOwnerPresence is an internal adapter receipt")
        self._binding = binding
        self._lease_id = lease_id
        self._verified_at_ns = verified_at_ns

    @property
    def binding(self) -> ApprovalBinding:
        """Return the exact binding the OS-mediated decision was bound to."""
        return self._binding

    @property
    def lease_id(self) -> str:
        """Return the exact in-flight challenge lease this receipt answers."""
        return self._lease_id

    @property
    def verified_at_ns(self) -> int:
        """Return the adapter's monotonic sample taken at the terminal callback."""
        return self._verified_at_ns

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("VerifiedOwnerPresence cannot be serialized")

    def __copy__(self) -> VerifiedOwnerPresence:
        raise TypeError("VerifiedOwnerPresence cannot be copied")

    def __deepcopy__(self, _memo: object) -> VerifiedOwnerPresence:
        raise TypeError("VerifiedOwnerPresence cannot be copied")


class OwnerPresenceVerifier(Protocol):
    """The exact asynchronous OS-mediated owner-presence boundary."""

    async def verify(
        self,
        lease: ApprovalChallengeLease,
        *,
        reason: str,
    ) -> VerifiedOwnerPresence: ...


@runtime_checkable
class InvalidatingOwnerPresenceVerifier(Protocol):
    """A verifier that owns cancellable OS context for its in-flight prompts."""

    def invalidate(self, lease_id: str) -> None: ...

    def shutdown(self) -> None: ...


class MonotonicClock(Protocol):
    """The exact injected monotonic sampler used for every approval bound."""

    def monotonic_ns(self) -> int: ...


class SystemMonotonicClock:
    """Sample the process monotonic clock owned by the foreground UI or CLI."""

    def monotonic_ns(self) -> int:
        """Return one monotonic nanosecond sample."""
        return time.monotonic_ns()


@dataclass(slots=True)
class _PendingPrompt:
    """One retained OS context awaiting exactly one terminal callback."""

    context: object
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[VerifiedOwnerPresence]
    delivered: bool = False
    invalidated: bool = False


class LocalAuthenticationOwnerPresenceVerifier:
    """Bridge macOS device-owner authentication into one awaited asyncio result."""

    def __init__(self) -> None:
        self._prompts: dict[str, _PendingPrompt] = {}
        self._lock = threading.Lock()

    @property
    def pending_prompt_count(self) -> int:
        """Return the number of retained contexts awaiting a terminal callback."""
        with self._lock:
            return len(self._prompts)

    async def verify(
        self,
        lease: ApprovalChallengeLease,
        *,
        reason: str,
    ) -> VerifiedOwnerPresence:
        """Request one OS-controlled owner-presence decision for this lease."""
        if not isinstance(lease, ApprovalChallengeLease) or lease.state != "in_flight":
            raise InvalidArgumentError("approval challenge lease is invalid")
        if not isinstance(reason, str) or not reason:
            raise InvalidArgumentError("owner-presence reason is invalid")
        lease_id = lease.lease_id
        loop = asyncio.get_running_loop()
        future: asyncio.Future[VerifiedOwnerPresence] = loop.create_future()
        prompt = _PendingPrompt(
            context=self._new_context(),
            loop=loop,
            future=future,
        )
        with self._lock:
            if lease_id in self._prompts:
                raise InvalidArgumentError("approval challenge lease is already open")
            self._prompts[lease_id] = prompt

        def deliver(verified: bool) -> None:
            if future.done():
                return
            if not verified:
                future.set_exception(
                    OwnerApprovalRequiredError("owner presence was not verified")
                )
                return
            future.set_result(
                VerifiedOwnerPresence(
                    _PRESENCE_CONSTRUCTOR,
                    binding=lease.binding,
                    lease_id=lease_id,
                    verified_at_ns=time.monotonic_ns(),
                )
            )

        def reply(success: object, _error: object) -> None:
            # Runs on a framework thread; never touch the loop or log LA details.
            with self._lock:
                current = self._prompts.get(lease_id)
                if current is not prompt or prompt.delivered or prompt.invalidated:
                    return
                prompt.delivered = True
            try:
                loop.call_soon_threadsafe(deliver, success is True)
            except RuntimeError:
                return

        try:
            self._evaluate(prompt.context, reason, reply)
            return await future
        except BaseException:
            self._invalidate_context(prompt.context)
            raise
        finally:
            with self._lock:
                if self._prompts.get(lease_id) is prompt:
                    del self._prompts[lease_id]

    def invalidate(self, lease_id: str) -> None:
        """Invalidate one retained OS context and fail its awaited result."""
        with self._lock:
            prompt = self._prompts.get(lease_id)
            if prompt is None:
                return
            prompt.invalidated = True
        self._fail(prompt)

    def shutdown(self) -> None:
        """Invalidate every retained OS context before this process exits."""
        with self._lock:
            pending = tuple(self._prompts.values())
            for prompt in pending:
                prompt.invalidated = True
            self._prompts.clear()
        for prompt in pending:
            self._fail(prompt)

    def _fail(self, prompt: _PendingPrompt) -> None:
        self._invalidate_context(prompt.context)

        def deliver_failure() -> None:
            if not prompt.future.done():
                prompt.future.set_exception(
                    OwnerApprovalRequiredError("owner presence was invalidated")
                )

        try:
            prompt.loop.call_soon_threadsafe(deliver_failure)
        except RuntimeError:
            return

    def _evaluate(
        self,
        context: object,
        reason: str,
        reply: Callable[[object, object], None],
    ) -> None:
        evaluate = getattr(context, "evaluatePolicy_localizedReason_reply_", None)
        if not callable(evaluate):
            raise OwnerApprovalRequiredError("owner presence is unavailable")
        try:
            evaluate(self._policy(), reason, reply)
        except OwnerApprovalRequiredError:
            raise
        except Exception as error:
            raise OwnerApprovalRequiredError("owner presence is unavailable") from error

    def _new_context(self) -> object:
        from LocalAuthentication import LAContext  # type: ignore[import-untyped]

        context = LAContext.alloc().init()
        if context is None:
            raise OwnerApprovalRequiredError("owner presence is unavailable")
        return context

    @staticmethod
    def _policy() -> object:
        from LocalAuthentication import LAPolicyDeviceOwnerAuthentication

        return LAPolicyDeviceOwnerAuthentication

    @staticmethod
    def _invalidate_context(context: object) -> None:
        invalidate = getattr(context, "invalidate", None)
        if not callable(invalidate):
            return
        try:
            invalidate()
        except Exception:
            # LocalAuthentication error details may name the account or device.
            return


@dataclass(slots=True)
class _AttemptRecord:
    """One process-local approval attempt in exactly one bounded phase."""

    binding: ApprovalBinding
    phase: Literal["pending", "in_flight", "completed"]
    lease_id: str | None = None
    application_id: str | None = None
    completed_at_ns: int | None = None


class ApprovalAttemptStore:
    """Keep every approval binding, lease, and tombstone in this process only."""

    def __init__(self) -> None:
        self._ui: dict[str, OrderedDict[str, _AttemptRecord]] = {}
        self._cli: OrderedDict[str, _AttemptRecord] = OrderedDict()
        self._lock = threading.RLock()

    def remember_ui_binding(self, binding: UiApprovalBinding) -> None:
        """Store one pending session-bound binding with its fixed expiry."""
        if (
            not isinstance(binding, UiApprovalBinding)
            or binding.approval_adapter != UI_APPROVAL_ADAPTER
        ):
            raise InvalidArgumentError("UI approval binding is invalid")
        created_at_ns = binding.expires_at_ns - APPROVAL_BINDING_TTL_NS
        with self._lock:
            records = self._ui.setdefault(binding.session_id, OrderedDict())
            self._reap(records, now_ns=created_at_ns)
            if binding.final_page_nonce in records:
                raise InvalidArgumentError("approval binding already exists")
            if len(records) >= MAX_APPROVAL_ATTEMPTS:
                raise InvalidArgumentError("approval attempt capacity is full")
            records[binding.final_page_nonce] = _AttemptRecord(
                binding=binding,
                phase="pending",
            )

    def resolve_ui_binding(
        self,
        session_id: str,
        final_page_nonce: str,
        *,
        now_ns: int,
    ) -> UiApprovalBinding | None:
        """Peek one pending binding without leasing, refreshing, or consuming."""
        with self._lock:
            records = self._ui.get(session_id)
            if records is None:
                return None
            self._reap(records, now_ns=now_ns)
            record = records.get(final_page_nonce)
            if record is None or record.phase != "pending":
                return None
            return cast(UiApprovalBinding, record.binding)

    def lease_ui(
        self,
        session_id: str,
        final_page_nonce: str,
        *,
        now_ns: int,
    ) -> ApprovalChallengeLease | CompletedApprovalAttempt:
        """Atomically take one in-flight challenge or replay a completed one."""
        with self._lock:
            records = self._ui.get(session_id)
            if records is None:
                raise InvalidArgumentError("approval attempt is unavailable")
            self._reap(records, now_ns=now_ns)
            record = records.get(final_page_nonce)
            if record is None:
                raise InvalidArgumentError("approval attempt is unavailable")
            if record.phase == "completed":
                return self._completed(record)
            if record.phase != "pending":
                raise InvalidArgumentError("approval attempt is already in flight")
            return self._take(record)

    def lease_cli(
        self,
        binding: CliApprovalBinding,
        *,
        now_ns: int,
    ) -> ApprovalChallengeLease:
        """Atomically take one in-flight challenge for this foreground process."""
        if (
            not isinstance(binding, CliApprovalBinding)
            or binding.approval_adapter != CLI_APPROVAL_ADAPTER
        ):
            raise InvalidArgumentError("CLI approval binding is invalid")
        with self._lock:
            self._reap(self._cli, now_ns=now_ns)
            if binding.invocation_nonce in self._cli:
                raise InvalidArgumentError("approval binding already exists")
            if len(self._cli) >= MAX_APPROVAL_ATTEMPTS:
                raise InvalidArgumentError("approval attempt capacity is full")
            record = _AttemptRecord(binding=binding, phase="pending")
            self._cli[binding.invocation_nonce] = record
            return self._take(record)

    def complete(
        self,
        lease: ApprovalChallengeLease,
        application_id: str,
        *,
        now_ns: int,
    ) -> CompletedApprovalAttempt:
        """Consume one in-flight challenge into its bounded replay tombstone."""
        if not isinstance(application_id, str) or not application_id:
            raise InvalidArgumentError("application identity is invalid")
        with self._lock:
            record = self._record_for_lease(lease)
            record.phase = "completed"
            record.lease_id = None
            record.application_id = application_id
            record.completed_at_ns = now_ns
            return self._completed(record)

    def consume_failed(self, lease: ApprovalChallengeLease) -> None:
        """Erase one attempt after cancellation, failure, timeout, or mismatch."""
        with self._lock:
            record = self._record_for_lease(lease)
            self._erase(record)

    def holds_lease(self, lease: ApprovalChallengeLease) -> bool:
        """Report whether this store still holds that exact in-flight challenge.

        An adapter receipt only proves the verifier answered this lease object.
        Approval adapters must additionally confirm store-held ownership before
        minting, so a lease lost during the awaited prompt applies nothing.
        """
        if not isinstance(lease, ApprovalChallengeLease):
            raise InvalidArgumentError("approval challenge lease is invalid")
        with self._lock:
            return self._find_lease(lease) is not None

    def invalidate_session(self, session_id: str) -> None:
        """Erase every approval attempt owned by one invalidated UI session."""
        with self._lock:
            self._ui.pop(session_id, None)

    def shutdown(self) -> None:
        """Erase every retained approval attempt before this process exits."""
        with self._lock:
            self._ui.clear()
            self._cli.clear()

    def _take(self, record: _AttemptRecord) -> ApprovalChallengeLease:
        lease = ApprovalChallengeLease(
            lease_id=f"apl_{secrets.token_hex(16)}",
            binding=record.binding,
            state="in_flight",
        )
        record.phase = "in_flight"
        record.lease_id = lease.lease_id
        return lease

    @staticmethod
    def _completed(record: _AttemptRecord) -> CompletedApprovalAttempt:
        if record.application_id is None or record.completed_at_ns is None:
            raise InvalidArgumentError("completed approval attempt is incomplete")
        return CompletedApprovalAttempt(
            binding=record.binding,
            application_id=record.application_id,
            completed_at_ns=record.completed_at_ns,
        )

    def _find_lease(self, lease: ApprovalChallengeLease) -> _AttemptRecord | None:
        for records in (*self._ui.values(), self._cli):
            for record in records.values():
                if (
                    record.lease_id == lease.lease_id
                    and record.phase == "in_flight"
                    and record.binding == lease.binding
                ):
                    return record
        return None

    def _record_for_lease(self, lease: ApprovalChallengeLease) -> _AttemptRecord:
        if not isinstance(lease, ApprovalChallengeLease):
            raise InvalidArgumentError("approval challenge lease is invalid")
        record = self._find_lease(lease)
        if record is None:
            raise InvalidArgumentError("approval challenge lease is unavailable")
        return record

    def _erase(self, target: _AttemptRecord) -> None:
        for records in (*self._ui.values(), self._cli):
            for key, record in tuple(records.items()):
                if record is target:
                    records.pop(key, None)

    @staticmethod
    def _reap(records: OrderedDict[str, _AttemptRecord], *, now_ns: int) -> None:
        for key, record in tuple(records.items()):
            if record.phase == "pending" and now_ns >= record.binding.expires_at_ns:
                records.pop(key, None)
                continue
            if (
                record.phase == "completed"
                and record.completed_at_ns is not None
                and now_ns - record.completed_at_ns >= APPROVAL_TOMBSTONE_TTL_NS
            ):
                records.pop(key, None)


def owner_presence_reason(binding: ApprovalBinding) -> str:
    """Return the localized system-prompt reason naming the product and digest."""
    if isinstance(binding, ExportPresenceBinding):
        return (
            "Memory: export ALL retained data, including sensitive and restricted "
            f"history and sources, as plaintext JSON to {binding.destination} "
            f"({binding.digest[:OWNER_PRESENCE_REASON_DIGEST_CHARACTERS]})"
        )
    if not isinstance(binding, (UiApprovalBinding, CliApprovalBinding)):
        raise InvalidArgumentError("approval binding is invalid")
    prefix = binding.digest[:OWNER_PRESENCE_REASON_DIGEST_CHARACTERS]
    return f"Memory: approve Memory Review {prefix}"


def _mint_ui_owner_approval(verified: VerifiedOwnerPresence) -> OwnerApproval:
    """Mint one internal approval from an exact verified owner-UI receipt."""
    binding = _verified_binding(verified, UiApprovalBinding, UI_APPROVAL_ADAPTER)
    return _mint_bound_owner_approval(
        binding.store_id,
        binding.change_set_id,
        binding.revision_id,
        binding.digest,
        adapter=UI_APPROVAL_ADAPTER,
    )


def _mint_cli_owner_approval(verified: VerifiedOwnerPresence) -> OwnerApproval:
    """Mint one internal approval from an exact verified owner-CLI receipt."""
    binding = _verified_binding(verified, CliApprovalBinding, CLI_APPROVAL_ADAPTER)
    return _mint_bound_owner_approval(
        binding.store_id,
        binding.change_set_id,
        binding.revision_id,
        binding.digest,
        adapter=CLI_APPROVAL_ADAPTER,
    )


def _verified_binding[BindingT: UiApprovalBinding | CliApprovalBinding](
    verified: VerifiedOwnerPresence,
    expected: type[BindingT],
    adapter: str,
) -> BindingT:
    if not isinstance(verified, VerifiedOwnerPresence):
        raise InvalidArgumentError("owner-presence receipt is invalid")
    binding = verified.binding
    if not isinstance(binding, expected) or binding.approval_adapter != adapter:
        raise InvalidArgumentError("owner-presence receipt adapter is invalid")
    if not isinstance(verified.lease_id, str) or not verified.lease_id:
        raise InvalidArgumentError("owner-presence receipt lease is invalid")
    return binding


class ApprovalReviewService(Protocol):
    """The exact bounded owner surface consumed by the approval orchestrator."""

    def get_status(self) -> object: ...

    def get_review_manifest(
        self,
        change_set_id: str,
        revision_id: str | None = None,
    ) -> OwnerReviewManifest: ...

    def render_approval_review(
        self,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str: ...

    def apply_owner_approved_review(
        self,
        approval: OwnerApproval,
        *,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> ApplicationResult: ...

    def get_application(self, application_id: str) -> OwnerApplicationDetail: ...


async def await_owner_presence(
    verifier: OwnerPresenceVerifier,
    lease: ApprovalChallengeLease,
) -> VerifiedOwnerPresence:
    """Await one capped OS-mediated prompt and invalidate its context on loss."""
    reason = owner_presence_reason(lease.binding)
    try:
        return await asyncio.wait_for(
            verifier.verify(lease, reason=reason),
            timeout=OWNER_PRESENCE_TIMEOUT_SECONDS,
        )
    except OwnerApprovalRequiredError:
        raise
    except (TimeoutError, asyncio.CancelledError) as error:
        if isinstance(verifier, InvalidatingOwnerPresenceVerifier):
            verifier.invalidate(lease.lease_id)
        raise OwnerApprovalRequiredError("owner presence did not complete") from error
    except Exception as error:
        if isinstance(verifier, InvalidatingOwnerPresenceVerifier):
            verifier.invalidate(lease.lease_id)
        raise OwnerApprovalRequiredError("owner presence did not complete") from error


def _consume_lost_attempt(
    attempts: ApprovalAttemptStore,
    lease: ApprovalChallengeLease,
) -> None:
    """Consume one failed attempt without masking the failure that caused it."""
    try:
        attempts.consume_failed(lease)
    except InvalidArgumentError:
        # The store already erased this attempt; nothing remains to consume.
        return


def _validate_receipt(
    verified: VerifiedOwnerPresence,
    lease: ApprovalChallengeLease,
    *,
    now_ns: int,
) -> None:
    """Require the exact lease, binding, and monotonic deadline after the prompt."""
    if not isinstance(verified, VerifiedOwnerPresence):
        raise OwnerApprovalRequiredError("owner-presence receipt is invalid")
    if verified.lease_id != lease.lease_id or verified.binding != lease.binding:
        raise OwnerApprovalRequiredError("owner-presence receipt is not this lease")
    if not isinstance(verified.verified_at_ns, int) or isinstance(
        verified.verified_at_ns, bool
    ):
        raise OwnerApprovalRequiredError("owner-presence receipt time is invalid")
    if verified.verified_at_ns >= lease.binding.expires_at_ns:
        raise OwnerApprovalRequiredError("owner presence completed after expiry")
    if now_ns >= lease.binding.expires_at_ns:
        raise OwnerApprovalRequiredError("approval binding expired during the prompt")


@dataclass(frozen=True, slots=True)
class UiApprovalOrchestrator:
    """The only process-owned path from a UI session to an internal approval."""

    service: ApprovalReviewService
    sessions: UiSessionStore
    attempts: ApprovalAttemptStore
    verifier: OwnerPresenceVerifier
    clock: MonotonicClock

    def prepare_approval(
        self,
        *,
        change_set_id: str,
        expected_revision_id: str,
        expected_digest: str,
        session_id: str,
    ) -> PreparedUiApproval:
        """Store one pending binding for the exact approvable current revision."""
        now_ns = self.clock.monotonic_ns()
        self._require_active_session(session_id, now_ns=now_ns)
        review = self._approvable_review(
            change_set_id,
            expected_revision_id,
            expected_digest,
        )
        binding = UiApprovalBinding(
            store_id=self._store_id(),
            change_set_id=change_set_id,
            revision_id=review.revision.revision_id,
            digest=review.revision.digest,
            approval_adapter="local_owner_ui",
            session_id=session_id,
            final_page_nonce=secrets.token_urlsafe(24),
            expires_at_ns=now_ns + APPROVAL_BINDING_TTL_NS,
        )
        canonical_review = self._canonical_review(binding)
        self.attempts.remember_ui_binding(binding)
        return PreparedUiApproval(
            review=review,
            canonical_review=canonical_review,
            binding=binding,
        )

    def resolve_approval_page(
        self,
        *,
        session_id: str,
        final_page_nonce: str,
    ) -> PreparedUiApproval | None:
        """Resolve one pending binding without creating or refreshing authority."""
        now_ns = self.clock.monotonic_ns()
        if not self.sessions.is_session_active(session_id, now_ns=now_ns):
            return None
        binding = self.attempts.resolve_ui_binding(
            session_id,
            final_page_nonce,
            now_ns=now_ns,
        )
        if binding is None:
            return None
        try:
            review = self._approvable_review(
                binding.change_set_id,
                binding.revision_id,
                binding.digest,
            )
        except InvalidArgumentError, OwnerApprovalRequiredError, StaleRevisionError:
            return None
        except WrongDigestError:
            return None
        if self._store_id() != binding.store_id:
            return None
        try:
            canonical_review = self._canonical_review(binding)
        except InvalidArgumentError, OwnerApprovalRequiredError, StaleRevisionError:
            return None
        except WrongDigestError:
            return None
        return PreparedUiApproval(
            review=review,
            canonical_review=canonical_review,
            binding=binding,
        )

    async def submit_approval(
        self,
        *,
        session_id: str,
        final_page_nonce: str,
        submitted_revision_id: str,
        submitted_digest: str,
    ) -> OwnerApplicationDetail:
        """Apply exactly the reviewed revision after verified owner presence."""
        now_ns = self.clock.monotonic_ns()
        self._require_active_session(session_id, now_ns=now_ns)
        leased = self.attempts.lease_ui(session_id, final_page_nonce, now_ns=now_ns)
        if isinstance(leased, CompletedApprovalAttempt):
            self._require_submission(
                leased.binding,
                submitted_revision_id,
                submitted_digest,
            )
            return self.service.get_application(leased.application_id)
        try:
            binding = leased.binding
            if (
                not isinstance(binding, UiApprovalBinding)
                or binding.approval_adapter != UI_APPROVAL_ADAPTER
                or binding.session_id != session_id
            ):
                raise OwnerApprovalRequiredError("approval binding is not this session")
            self._require_submission(binding, submitted_revision_id, submitted_digest)
            self._require_bound_review(binding, now_ns=now_ns)
            verified = await await_owner_presence(self.verifier, leased)
            after_ns = self.clock.monotonic_ns()
            _validate_receipt(verified, leased, now_ns=after_ns)
            self._require_active_session(session_id, now_ns=after_ns)
            self._require_bound_review(binding, now_ns=after_ns)
            if not self.attempts.holds_lease(leased):
                raise OwnerApprovalRequiredError("approval challenge lease was lost")
            approval = _mint_ui_owner_approval(verified)
            result = self.service.apply_owner_approved_review(
                approval,
                change_set_id=binding.change_set_id,
                revision_id=binding.revision_id,
                digest=binding.digest,
            )
        except BaseException:
            _consume_lost_attempt(self.attempts, leased)
            raise
        self.attempts.complete(
            leased,
            result.application_id,
            now_ns=self.clock.monotonic_ns(),
        )
        return self.service.get_application(result.application_id)

    def shutdown(self) -> None:
        """Invalidate every pending OS context then consume every attempt."""
        if isinstance(self.verifier, InvalidatingOwnerPresenceVerifier):
            self.verifier.shutdown()
        self.attempts.shutdown()

    def _store_id(self) -> str:
        status = self.service.get_status()
        store_id = getattr(getattr(status, "store", None), "store_id", None)
        if not isinstance(store_id, str) or not store_id:
            raise InvalidArgumentError("Store identity is unavailable")
        return store_id

    def _require_active_session(self, session_id: str, *, now_ns: int) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise InvalidArgumentError("UI session is invalid")
        if not self.sessions.is_session_active(session_id, now_ns=now_ns):
            raise OwnerApprovalRequiredError("UI session is unavailable")

    def _approvable_review(
        self,
        change_set_id: str,
        expected_revision_id: str,
        expected_digest: str,
    ) -> OwnerReviewManifest:
        review = self.service.get_review_manifest(change_set_id)
        revision = review.revision
        if revision.revision_id != expected_revision_id:
            raise StaleRevisionError(
                "review revision is stale",
                details={"expected_revision_id": revision.revision_id},
            )
        if revision.digest != expected_digest:
            raise WrongDigestError(
                "review digest does not match",
                details={"digest": revision.digest},
            )
        if revision.lifecycle != "current_draft" or review.validation_state != "valid":
            raise OwnerApprovalRequiredError("review is not approvable")
        return review

    def _require_bound_review(
        self,
        binding: UiApprovalBinding,
        *,
        now_ns: int,
    ) -> None:
        if now_ns >= binding.expires_at_ns:
            raise OwnerApprovalRequiredError("approval binding expired")
        if self._store_id() != binding.store_id:
            raise OwnerApprovalRequiredError("Store identity does not match")
        self._approvable_review(
            binding.change_set_id,
            binding.revision_id,
            binding.digest,
        )

    def _canonical_review(self, binding: UiApprovalBinding) -> str:
        """Render only the exact revision and digest bound to this approval."""
        return self.service.render_approval_review(
            binding.change_set_id,
            binding.revision_id,
            binding.digest,
        )

    @staticmethod
    def _require_submission(
        binding: ApprovalBinding,
        submitted_revision_id: str,
        submitted_digest: str,
    ) -> None:
        if not isinstance(binding, (UiApprovalBinding, CliApprovalBinding)):
            raise InvalidArgumentError("review approval binding is invalid")
        if submitted_revision_id != binding.revision_id:
            raise StaleRevisionError("submitted revision does not match the review")
        if submitted_digest != binding.digest:
            raise WrongDigestError("submitted digest does not match the review")


def _production_owner_presence_verifier() -> OwnerPresenceVerifier:
    """Return the sole production macOS owner-presence verifier."""
    return LocalAuthenticationOwnerPresenceVerifier()


def _require_current_cli_review(
    paths: RuntimePaths,
    binding: CliApprovalBinding,
) -> None:
    """Require the exact bound revision to remain the current approvable draft."""
    view = get_change_set(paths, binding.change_set_id)
    if view.revision_id != binding.revision_id:
        raise StaleRevisionError(
            "draft revision is stale",
            details={"expected_revision_id": view.revision_id},
        )
    if view.digest != binding.digest:
        raise WrongDigestError(
            "draft digest does not match",
            details={"digest": view.digest},
        )
    if view.state != "draft":
        raise OwnerApprovalRequiredError("review is not approvable")


async def _approve_with_cli_owner_presence(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
    *,
    verifier: OwnerPresenceVerifier,
    clock: MonotonicClock,
    attempts: ApprovalAttemptStore,
) -> ApplicationResult:
    now_ns = clock.monotonic_ns()
    binding = CliApprovalBinding(
        store_id=load_runtime_identity(paths).store_id,
        change_set_id=change_set_id,
        revision_id=revision_id,
        digest=digest,
        approval_adapter="os_owner_presence_cli",
        invocation_nonce=secrets.token_urlsafe(24),
        expires_at_ns=now_ns + APPROVAL_BINDING_TTL_NS,
    )
    _require_current_cli_review(paths, binding)
    lease = attempts.lease_cli(binding, now_ns=now_ns)
    try:
        verified = await await_owner_presence(verifier, lease)
        after_ns = clock.monotonic_ns()
        _validate_receipt(verified, lease, now_ns=after_ns)
        if load_runtime_identity(paths).store_id != binding.store_id:
            raise OwnerApprovalRequiredError("Store identity does not match")
        _require_current_cli_review(paths, binding)
        if not attempts.holds_lease(lease):
            raise OwnerApprovalRequiredError("approval challenge lease was lost")
        approval = _mint_cli_owner_approval(verified)
        result = approve_and_apply(
            paths,
            change_set_id,
            revision_id,
            digest,
            approval,
        )
    except BaseException:
        _consume_lost_attempt(attempts, lease)
        raise
    attempts.complete(lease, result.application_id, now_ns=clock.monotonic_ns())
    return result


def approve_with_cli_owner_presence(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
    *,
    verifier: OwnerPresenceVerifier | None = None,
    clock: MonotonicClock | None = None,
    attempts: ApprovalAttemptStore | None = None,
) -> ApplicationResult:
    """Apply one exact revision after an OS-mediated CLI owner-presence check.

    TTY state, ``isatty``, typed input, pipes, and PTYs are never owner-presence
    proof; only a successful macOS device-owner authentication mints approval.
    """
    selected_clock = SystemMonotonicClock() if clock is None else clock
    selected_attempts = ApprovalAttemptStore() if attempts is None else attempts
    selected_verifier = (
        _production_owner_presence_verifier() if verifier is None else verifier
    )
    try:
        return asyncio.run(
            _approve_with_cli_owner_presence(
                paths,
                change_set_id,
                revision_id,
                digest,
                verifier=selected_verifier,
                clock=selected_clock,
                attempts=selected_attempts,
            )
        )
    finally:
        if isinstance(selected_verifier, InvalidatingOwnerPresenceVerifier):
            selected_verifier.shutdown()
        selected_attempts.shutdown()


def require_export_owner_presence(
    store_id: str,
    destination: str,
    digest: str,
    *,
    verifier: OwnerPresenceVerifier | None = None,
) -> None:
    """Require one fresh OS receipt for this export; return no reusable capability."""
    selected = _production_owner_presence_verifier() if verifier is None else verifier
    started = time.monotonic_ns()
    binding = ExportPresenceBinding(
        store_id,
        destination,
        digest,
        secrets.token_urlsafe(24),
        started + APPROVAL_BINDING_TTL_NS,
    )
    lease = ApprovalChallengeLease(secrets.token_urlsafe(24), binding, "in_flight")
    try:
        verified = asyncio.run(await_owner_presence(selected, lease))
        _validate_receipt(verified, lease, now_ns=time.monotonic_ns())
        if verified.verified_at_ns < started:
            raise OwnerApprovalRequiredError("export receipt predates this invocation")
    finally:
        if isinstance(selected, InvalidatingOwnerPresenceVerifier):
            selected.shutdown()
