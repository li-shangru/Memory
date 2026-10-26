"""Shared validation for model-writable Store strings."""

from __future__ import annotations

from memory.errors import InvalidArgumentError
from memory.model import Sensitivity

#: The stored rank of each sensitivity level, and its inverse. Ranks are what
#: the schema compares and propagates; the level is what the owner reads.
SENSITIVITY_RANK: dict[Sensitivity, int] = {
    Sensitivity.NORMAL: 0,
    Sensitivity.SENSITIVE: 1,
    Sensitivity.RESTRICTED: 2,
}
_SENSITIVITY_BY_RANK = tuple(SENSITIVITY_RANK)


def sensitivity_from_rank(rank: int) -> Sensitivity:
    """Map one stored rank back to its level, refusing anything outside the set.

    The bound is checked rather than left to the tuple: indexing turns a rank
    of -1 into `restricted`, which is the wrong answer given confidently, and
    integrity is not truth.
    """
    if not 0 <= rank < len(_SENSITIVITY_BY_RANK):
        raise InvalidArgumentError("stored sensitivity is inconsistent")
    return _SENSITIVITY_BY_RANK[rank]


def require_invariant(condition: bool, *, label: str) -> None:
    """Enforce one import-time invariant that has to survive ``python -O``.

    Module-level budgets are what hold a rendered page inside the response
    ceiling its route promises, and what keep two hand-written label sets
    agreeing. ``assert`` states them, but an optimised interpreter discards it,
    leaving them unenforced in exactly the build the owner runs. A failure here
    is a build that must not start, so it is raised, not asserted.
    """
    if not condition:
        raise RuntimeError(f"{label} is inconsistent")


def strict_utf8_bytes(value: object, *, label: str) -> bytes:
    """Return strict UTF-8 bytes or one typed content-free argument failure."""
    if not isinstance(value, str) or "\x00" in value:
        raise InvalidArgumentError(f"{label} is invalid")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise InvalidArgumentError(f"{label} is invalid") from error
