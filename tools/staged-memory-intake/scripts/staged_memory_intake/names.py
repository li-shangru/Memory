"""Shared deterministic names for exact staged-memory publication."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from staged_memory_intake.model import IntakeError

PLACEHOLDER_TRANSACTION_ID = "tx_" + ("0" * 32)

_TRANSACTION_PATTERN = re.compile(r"tx_[0-9a-f]{32}")
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def _error(code: str) -> IntakeError:
    return IntakeError(code, "state")


def visible_inbox_name(
    transaction_id: str,
    ordinal: int,
    prepared_sha256: str,
    prepared_name: str,
) -> str:
    """Build one full-transaction-bound visible Inbox basename."""
    if _TRANSACTION_PATTERN.fullmatch(transaction_id) is None:
        raise _error("invalid_transaction_id")
    if isinstance(ordinal, bool) or not 0 <= ordinal <= 99:
        raise _error("invalid_candidate_ordinal")
    if _HASH_PATTERN.fullmatch(prepared_sha256) is None:
        raise _error("invalid_prepared_sha256")
    if (
        not prepared_name
        or "\0" in prepared_name
        or PurePosixPath(prepared_name).parts != (prepared_name,)
    ):
        raise _error("invalid_prepared_name")
    name = f"{transaction_id}-{ordinal:02d}-{prepared_sha256[:12]}-{prepared_name}"
    if len(name.encode("utf-8")) > 255:
        raise _error("published_name_too_long")
    return name
