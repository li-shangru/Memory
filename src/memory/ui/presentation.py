"""Deterministic bounded presentation helpers for owner-visible memory text."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from difflib import SequenceMatcher
from typing import Literal
from urllib.parse import quote, urlencode

from memory.reviews import partial_date_bounds
from memory.ui.view_models import OwnerDraftGuardLink

MAX_ROSTER_PREVIEW_CHARS = 160
MAX_FINE_DIFF_TOKENS = 512
_DIFF_TOKEN = re.compile(r"\s+|\w+|[^\w\s]", re.UNICODE)

type ValidityStatus = Literal[
    "no_dates",
    "no_end",
    "future",
    "uncertain_start",
    "recorded_period",
    "ended",
    "uncertain_end",
    "revisit_unrecorded",
    "revisit_future",
    "revisit_due",
    "revisit_uncertain",
]


@dataclass(frozen=True, slots=True)
class StatementChange:
    text: str
    kind: Literal["unchanged", "added", "removed"]


@dataclass(frozen=True, slots=True)
class ValidityPresentation:
    status: ValidityStatus
    start_label: str
    end_label: str
    summary: str
    is_open_loop: bool


@dataclass(frozen=True, slots=True)
class ReviewGuardChange:
    action: Literal[
        "proposed",
        "rejected_proposal",
        "revoked",
        "rejected_revocation",
    ]
    direction: Literal["guards", "governed_by"]
    other_statement: str
    other_elided: bool


def roster_statement_preview(statement: str) -> tuple[str, bool]:
    """Return one whitespace-collapsed, character-bounded statement preview."""
    collapsed = " ".join(statement.split())
    if len(collapsed) <= MAX_ROSTER_PREVIEW_CHARS:
        return collapsed, False
    return collapsed[: MAX_ROSTER_PREVIEW_CHARS - 1] + "…", True


def relevant_guard_changes(
    item_id: str,
    target_lineage_id: str | None,
    proposed: tuple[OwnerDraftGuardLink, ...],
    revoked: tuple[OwnerDraftGuardLink, ...],
) -> tuple[ReviewGuardChange, ...]:
    """Return guard edits naming an item or the lineage its correction targets."""
    endpoints = {("item", item_id)}
    if target_lineage_id is not None:
        endpoints.add(("lineage", target_lineage_id))
    changes: list[ReviewGuardChange] = []
    for links, is_revocation in ((proposed, False), (revoked, True)):
        for link in links:
            if (link.guard_kind, link.guard_ref) in endpoints:
                direction: Literal["guards", "governed_by"] = "guards"
                other = link.governed_statement
            elif (link.governed_kind, link.governed_ref) in endpoints:
                direction = "governed_by"
                other = link.guard_statement
            else:
                continue
            statement, elided = roster_statement_preview(other)
            action: Literal[
                "proposed",
                "rejected_proposal",
                "revoked",
                "rejected_revocation",
            ]
            if is_revocation:
                action = "revoked" if link.status == "active" else "rejected_revocation"
            else:
                action = "proposed" if link.status == "active" else "rejected_proposal"
            changes.append(
                ReviewGuardChange(
                    action=action,
                    direction=direction,
                    other_statement=statement,
                    other_elided=elided,
                )
            )
    return tuple(changes)


def review_item_href(
    review_base: str,
    item_id: str,
    audit_handle: str | None,
) -> str:
    """Build an exact item link without treating its opaque ID as URL syntax."""
    parameters: list[tuple[str, str]] = [("item_id", item_id)]
    if audit_handle is not None:
        parameters.append(("h", audit_handle))
    return f"{review_base}/items/lookup/exact?{urlencode(parameters)}"


def review_item_edit_href(
    review_base: str,
    intent: Literal["replace_item", "reject_item", "restore_item"],
    item_id: str,
) -> str:
    """Build one item edit link without interpreting its opaque ID as a URL."""
    return f"{review_base}/edits/{intent}?{urlencode({'item_id': item_id})}"


def review_guard_endpoint_href(
    review_base: str,
    kind: Literal["item", "lineage"],
    reference: str,
    memory_id: str | None,
    audit_handle: str | None,
) -> str | None:
    """Link a compact guard endpoint to its complete proposal or current head."""
    if kind == "item":
        return review_item_href(review_base, reference, audit_handle)
    if memory_id is None:
        return None
    suffix = "?" + urlencode({"h": audit_handle}) if audit_handle is not None else ""
    return f"/memories/{quote(memory_id, safe='')}{suffix}"


def _coalesce(parts: list[StatementChange]) -> tuple[StatementChange, ...]:
    result: list[StatementChange] = []
    for part in parts:
        if not part.text:
            continue
        if result and result[-1].kind == part.kind:
            previous = result[-1]
            result[-1] = StatementChange(previous.text + part.text, part.kind)
        else:
            result.append(part)
    return tuple(result)


def _linear_statement_comparison(
    predecessor: str,
    proposal: str,
) -> tuple[StatementChange, ...]:
    prefix = 0
    maximum_prefix = min(len(predecessor), len(proposal))
    while prefix < maximum_prefix and predecessor[prefix] == proposal[prefix]:
        prefix += 1
    suffix = 0
    maximum_suffix = min(len(predecessor) - prefix, len(proposal) - prefix)
    while (
        suffix < maximum_suffix
        and predecessor[len(predecessor) - suffix - 1]
        == proposal[len(proposal) - suffix - 1]
    ):
        suffix += 1
    old_end = len(predecessor) - suffix if suffix else len(predecessor)
    new_end = len(proposal) - suffix if suffix else len(proposal)
    return _coalesce(
        [
            StatementChange(predecessor[:prefix], "unchanged"),
            StatementChange(predecessor[prefix:old_end], "removed"),
            StatementChange(proposal[prefix:new_end], "added"),
            StatementChange(predecessor[old_end:], "unchanged"),
        ]
    )


def compare_statements(
    predecessor: str | None,
    proposal: str,
) -> tuple[StatementChange, ...]:
    """Diff exact statement text with bounded work and lossless reconstruction."""
    if predecessor is None:
        return (StatementChange(proposal, "added"),) if proposal else ()
    if predecessor == proposal:
        return (StatementChange(proposal, "unchanged"),) if proposal else ()
    old_tokens = _DIFF_TOKEN.findall(predecessor)
    new_tokens = _DIFF_TOKEN.findall(proposal)
    if len(old_tokens) + len(new_tokens) > MAX_FINE_DIFF_TOKENS:
        return _linear_statement_comparison(predecessor, proposal)
    parts: list[StatementChange] = []
    matcher = SequenceMatcher(a=old_tokens, b=new_tokens, autojunk=False)
    for opcode, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if opcode == "equal":
            parts.append(
                StatementChange("".join(old_tokens[old_start:old_end]), "unchanged")
            )
        elif opcode == "delete":
            parts.append(
                StatementChange("".join(old_tokens[old_start:old_end]), "removed")
            )
        elif opcode == "insert":
            parts.append(
                StatementChange("".join(new_tokens[new_start:new_end]), "added")
            )
        else:
            parts.append(
                StatementChange("".join(old_tokens[old_start:old_end]), "removed")
            )
            parts.append(
                StatementChange("".join(new_tokens[new_start:new_end]), "added")
            )
    return _coalesce(parts)


def _takes_effect(value: str) -> str:
    preposition = "on" if value.count("-") == 2 else "in"
    return f"Recorded information takes effect {preposition} {value}."


def memory_validity(
    valid_from: str | None,
    valid_to: str | None,
    tags: tuple[str, ...],
    *,
    today: date,
) -> ValidityPresentation:
    """Describe recorded applicability without changing or judging the memory."""
    is_open_loop = "loop:open" in tags
    start_label = (
        f"Valid from {valid_from}"
        if valid_from is not None
        else "No start date recorded"
    )
    end_label = (
        f"Revisit horizon {valid_to}"
        if is_open_loop and valid_to is not None
        else "No revisit date recorded"
        if is_open_loop
        else f"Valid to {valid_to}"
        if valid_to is not None
        else "No end date recorded"
    )
    start_note = ""
    start_status: Literal["future", "uncertain_start"] | None = None
    if valid_from is not None:
        start_min, start_max = partial_date_bounds(valid_from)
        if start_min > today:
            start_note = _takes_effect(valid_from)
            start_status = "future"
        elif start_min <= today <= start_max and start_min != start_max:
            start_note = (
                f"The effective date falls within {valid_from}; its partial precision "
                "does not establish applicability today."
            )
            start_status = "uncertain_start"

    if is_open_loop:
        if valid_to is None:
            horizon_status: ValidityStatus = "revisit_unrecorded"
            horizon_note = "Open loop. No revisit date recorded."
        else:
            horizon_min, horizon_max = partial_date_bounds(valid_to)
            if horizon_max < today or horizon_min == horizon_max == today:
                horizon_status = "revisit_due"
                horizon_note = f"Open loop. Revisit is due; its horizon is {valid_to}."
            elif horizon_min > today:
                horizon_status = "revisit_future"
                horizon_note = f"Open loop. Its revisit horizon is {valid_to}."
            else:
                horizon_status = "revisit_uncertain"
                horizon_note = (
                    f"Open loop. The revisit date falls within {valid_to}; partial "
                    "precision does not establish whether it is due yet."
                )
        return ValidityPresentation(
            status=horizon_status,
            start_label=start_label,
            end_label=end_label,
            summary=" ".join(part for part in (start_note, horizon_note) if part),
            is_open_loop=True,
        )

    if valid_to is None:
        status: ValidityStatus
        if start_status is not None:
            status = start_status
        else:
            status = "no_dates" if valid_from is None else "no_end"
        end_note = "No end date recorded."
    else:
        end_min, end_max = partial_date_bounds(valid_to)
        if end_max < today:
            status = "ended"
            end_note = f"The recorded validity period ended {valid_to}."
        elif end_min <= today <= end_max and end_min != end_max:
            status = "uncertain_end"
            end_note = (
                f"The recorded end falls within {valid_to}; the exact day is not "
                "recorded, so applicability today is uncertain."
            )
        else:
            status = start_status or "recorded_period"
            end_note = f"The recorded validity period ends {valid_to}."
    return ValidityPresentation(
        status=status,
        start_label=start_label,
        end_label=end_label,
        summary=" ".join(part for part in (start_note, end_note) if part),
        is_open_loop=False,
    )
