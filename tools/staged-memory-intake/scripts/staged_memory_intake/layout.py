"""Canonical and one-time legacy staged-intake directory names."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class LayoutNames:
    """Exact child names for one staged-intake workflow layout."""

    pending: str
    staged: str
    prepared: str
    inbox: str

    @property
    def children(self) -> tuple[str, str, str, str]:
        """Return every required child in visible workflow order."""
        return (self.pending, self.staged, self.prepared, self.inbox)

    @property
    def parked_children(self) -> tuple[str, str, str]:
        """Return the children left while Memory parks the Inbox."""
        return (self.pending, self.staged, self.prepared)


NUMBERED_LAYOUT: Final = LayoutNames(
    pending="01_Pending",
    staged="02_Staged",
    prepared="03_Prepared",
    inbox="04_Inbox",
)
LEGACY_LAYOUT: Final = LayoutNames(
    pending="Pending",
    staged="Staged",
    prepared="Prepared",
    inbox="Inbox",
)
OBSIDIAN_DIRECTORY: Final = ".obsidian"


__all__ = [
    "LEGACY_LAYOUT",
    "NUMBERED_LAYOUT",
    "OBSIDIAN_DIRECTORY",
    "LayoutNames",
]
