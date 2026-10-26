from __future__ import annotations

from datetime import date

from memory.model import Sensitivity
from memory.ui.presentation import (
    MAX_ROSTER_PREVIEW_CHARS,
    compare_statements,
    memory_validity,
    relevant_guard_changes,
    roster_statement_preview,
)
from memory.ui.view_models import OwnerDraftGuardLink


def test_roster_preview_is_single_line_bounded_and_unicode_safe() -> None:
    statement = "  Synthetic first line.\n\n" + "桥" * MAX_ROSTER_PREVIEW_CHARS

    preview, elided = roster_statement_preview(statement)

    assert "\n" not in preview
    assert len(preview) == MAX_ROSTER_PREVIEW_CHARS
    assert preview.endswith("…")
    assert elided is True


def test_statement_comparison_preserves_both_inputs_and_marks_wording_changes() -> None:
    predecessor = "The synthetic studio opens on Monday."
    proposal = "The synthetic quiet studio opens on Tuesday."

    changes = compare_statements(predecessor, proposal)

    assert (
        "".join(part.text for part in changes if part.kind in {"unchanged", "removed"})
        == predecessor
    )
    assert (
        "".join(part.text for part in changes if part.kind in {"unchanged", "added"})
        == proposal
    )
    assert any(part.kind == "removed" and "Monday" in part.text for part in changes)
    assert any(part.kind == "added" and "Tuesday" in part.text for part in changes)


def test_large_statement_comparison_has_linear_bounded_fallback() -> None:
    predecessor = "start " + "old " * 2_000 + "finish"
    proposal = "start " + "new " * 2_000 + "finish"

    changes = compare_statements(predecessor, proposal)

    assert len(changes) <= 4
    assert (
        "".join(part.text for part in changes if part.kind in {"unchanged", "removed"})
        == predecessor
    )
    assert (
        "".join(part.text for part in changes if part.kind in {"unchanged", "added"})
        == proposal
    )


def test_ordinary_validity_separates_missing_end_future_and_partial_precision() -> None:
    today = date(2032, 5, 15)

    no_end = memory_validity("2032-01", None, (), today=today)
    future = memory_validity("2033", None, (), today=today)
    partial_end = memory_validity(None, "2032-05", (), today=today)

    assert no_end.status == "no_end"
    assert no_end.end_label == "No end date recorded"
    assert "No end date recorded" in no_end.summary
    assert future.status == "future"
    assert "takes effect in 2033" in future.summary
    assert partial_end.status == "uncertain_end"
    assert "exact day is not recorded" in partial_end.summary


def test_open_loop_horizon_is_due_without_calling_the_memory_expired() -> None:
    today = date(2032, 5, 15)

    past = memory_validity(None, "2032-04", ("loop:open",), today=today)
    uncertain = memory_validity(None, "2032", ("loop:open",), today=today)
    absent = memory_validity(None, None, ("loop:open",), today=today)

    assert past.status == "revisit_due"
    assert past.end_label == "Revisit horizon 2032-04"
    assert "Revisit is due" in past.summary
    assert "expired" not in past.summary.lower()
    assert uncertain.status == "revisit_uncertain"
    assert "precision" in uncertain.summary
    assert absent.status == "revisit_unrecorded"
    assert absent.end_label == "No revisit date recorded"


def test_guard_changes_match_a_correction_target_lineage_once() -> None:
    item_id = "synthetic/correction?slot=1#owner%view"
    target_lineage_id = "lin_synthetic_target"
    link = OwnerDraftGuardLink(
        ordinal=3,
        status="active",
        guard_ref=item_id,
        governed_ref=target_lineage_id,
        guard_statement="Synthetic correction proposal.",
        governed_statement="Synthetic current target claim.",
        guard_sensitivity=Sensitivity.NORMAL,
        governed_sensitivity=Sensitivity.NORMAL,
        guard_kind="item",
        governed_kind="lineage",
    )
    lineage_only = OwnerDraftGuardLink(
        ordinal=4,
        status="active",
        guard_ref="lin_synthetic_caveat",
        governed_ref=target_lineage_id,
        guard_statement="Synthetic retained caveat.",
        governed_statement="Synthetic current target claim.",
        guard_sensitivity=Sensitivity.NORMAL,
        governed_sensitivity=Sensitivity.NORMAL,
        guard_kind="lineage",
        governed_kind="lineage",
    )

    changes = relevant_guard_changes(
        item_id,
        target_lineage_id,
        (link,),
        (lineage_only,),
    )

    assert [(change.action, change.direction) for change in changes] == [
        ("proposed", "guards"),
        ("revoked", "governed_by"),
    ]
