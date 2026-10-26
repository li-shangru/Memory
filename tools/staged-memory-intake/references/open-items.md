# Prepare ordinary open items

For an ordinary note with explicit unresolved commitment, reminder, or review
intent, add `loop:open` even when no date is stated. Preserve the intent in the
statement; choose kind from the source's meaning. An observation, past event,
or a retrospective quarterly-review note alone does not create a recurring
commitment. Do not infer future intent merely from a review heading or habit.
The decision-note contract remains unchanged; apply its special mapping through
[Decision notes](decision-notes.md).

Preserve owner-stated recurrence and its anchor in the statement. `valid_to`
holds only the next explicitly supported horizon, never a recurrence rule.
Do not invent a next date from quarterly alone, the last review's occurrence,
or a customary calendar boundary. If the source states a periodic review but
supports no next horizon, keep `loop:open` and leave `valid_to` blank. A
source-supported partial date retains its precision under the shared date
rules; an occurrence date is not automatically a review horizon.

Resolve relative days only from an unambiguous source-stated calendar date
with year, month, and day that the source explicitly ties to the interval.
Never use filesystem, capture, preparation, or current timestamps as the
anchor. Preserve the exact relative intent and any stated anchor in the
statement even when a horizon is computable. For example, a synthetic note
explicitly anchored to 2026-09-20 with a reminder after ten days supports
2026-09-30. An unanchored reminder after ten days keeps that wording and a
blank horizon; an absent anchor does not erase the open intent. Do not guess
between conflicting anchors; use the shared private-clarification rule when
the source's meaning is materially ambiguous.

One note and one item remain the default. For multiple independent follow-ups
with different horizons, use an owner-specified split or preserve each intent
and horizon faithfully in the single statement and leave `valid_to` blank.
Do not collapse those horizons into a misleading single `valid_to` or silently
split the note. Preserve any common horizon only when the source explicitly
applies it to the whole item.

These fields support recall on request or in a relevant conversation. Do not
create a scheduler or promise proactive notifications. Reads never advance a
horizon or close an open item. Closure and re-horizon use the existing
loop-correction route and exact owner-approved Memory Review. For a change to
only one grouped follow-up, use that reference's partial-update route, preserving
the others rather than closing or moving the entire item. Preparation and
recall supply no approval; the shared private review and exact authorization
rules still apply.
