"""Typed, content-free Store failures."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar


class StoreError(RuntimeError):
    """Base class for failures safe to translate at the CLI/MCP boundary."""

    code: ClassVar[str] = "store_error"

    def __init__(
        self,
        message: str = "",
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.details = dict(details) if details is not None else None


class InvalidRuntimeError(StoreError):
    """Raised when runtime metadata is absent, malformed, or inconsistent."""

    code = "wrong_product"


class InitializationError(StoreError):
    """Raised when a runtime cannot be initialized without data loss."""

    code = "invalid_argument"


class KeyAlreadyExistsError(StoreError):
    """Raised when key creation would replace an existing Keychain item."""

    code = "key_unavailable"


class KeyMissingError(StoreError):
    """Raised when an initialized Store has no Keychain item."""

    code = "key_missing"


class KeyUnavailableError(StoreError):
    """Raised when the Keychain cannot safely serve the Store key."""

    code = "key_unavailable"


class KeyMismatchError(KeyUnavailableError):
    """Raised when a Keychain item is malformed or cannot unlock the Store."""


class WrongProductError(StoreError):
    """Raised when a database does not match the selected Store identity."""

    code = "wrong_product"


class StoreOpenError(StoreError):
    """Raised when an encrypted database cannot be opened safely."""

    code = "key_unavailable"


class StoreBusyError(StoreError):
    """Raised when another process owns the nonblocking writer lock."""

    code = "busy"


class StoreUnavailableError(StoreError):
    """Raised when the filesystem environment fails underneath the Store.

    An OSError-caused environment failure -- an evicted iCloud placeholder,
    an unmounted volume, a permission change -- is the owner's to repair, not
    the caller's: no refetch makes a missing filesystem return, so the code
    is deliberately not retryable.
    """

    code = "store_unavailable"


class InvalidArgumentError(StoreError):
    """Raised when a bounded domain input or runtime path is unsafe."""

    code = "invalid_argument"


class RequestLimitError(StoreError):
    """Raised when a UI request or rendered response exceeds a fixed budget."""

    code = "request_too_large"


class NotFoundError(StoreError):
    """Raised when an opaque Store identifier is absent."""

    code = "not_found"


class StaleCursorError(StoreError):
    """Raised when a cursor is malformed or bound to another traversal."""

    code = "stale_cursor"


class NoEligibleSourcesError(StoreError):
    """Raised when one scan can seal no eligible source."""

    code = "no_eligible_sources"


class SourceTooLargeError(StoreError):
    """Raised when every otherwise eligible source exceeds custody limits."""

    code = "source_too_large"


class StaleRevisionError(StoreError):
    """Raised when an edit or apply does not name the current draft revision."""

    code = "stale_revision"


class StaleHeadError(StoreError):
    """Raised when a correction no longer targets the current memory head."""

    code = "stale_head"


class InvalidEvidenceError(StoreError):
    """Raised when proposed or stored evidence cannot be resolved exactly."""

    code = "invalid_evidence"


class AmbiguousEvidenceError(StoreError):
    """Raised when a text excerpt has more than one exact occurrence."""

    code = "ambiguous_evidence"


class IncompleteBatchError(StoreError):
    """Raised when a revision does not account for every sealed-batch source."""

    code = "incomplete_batch"


class WrongDigestError(StoreError):
    """Raised when approval names a digest other than the exact stored revision."""

    code = "wrong_digest"


class OwnerApprovalRequiredError(StoreError):
    """Raised when no trusted adapter supplied an owner approval capability."""

    code = "owner_approval_required"


class OwnerDeclinedError(StoreError):
    """Raised when the owner explicitly declines the displayed revision."""

    code = "owner_declined"
