# Review Lifecycle knowledge — 1.0.0

Lookup triggers: draft edits, correction heads, exact approval/application, guard revocation,
Inbox custody and interrupted recovery. Read design §§4.2, 5.2 and 7–8.
Source may change and must be rechecked.

One sealed batch has at most one change set/application, with every source used or
explicitly accounted for. Corrections append history and compare expected heads.
Owner approval is a one-use capability bound to Store/change set/revision/digest;
maintenance/adviser output cannot mint it. Apply is atomic. Exact replay creates no
second approval/application, while compatibility healing and current standing guard
diagnostics can still occur. Conditional digest keys preserve historical digests.
Revocation retains its canonical row and permanently blocks re-adding that pair.
Recovery proves artifact identity, retains unproven artifacts and preserves completed
capture receipts if later work fails. Visible decline/cancellation is not retry input.

Inspect [reviews.py](../../../src/memory/reviews.py),
[inbox.py](../../../src/memory/inbox.py), and
[staging_provenance.py](../../../src/memory/staging_provenance.py).
Check owners: [review tests](../../../tests/test_reviews.py),
[guard lifecycle](../../../tests/test_guard_links.py),
[Inbox recovery](../../../tests/test_inbox.py), and
[observation fairness](../../../tests/test_inbox_observation.py).

Failure-mode lookup: follow the cited authoritative source and test owners for missing coverage, stale identity, refusal/replay, replacement or parity concerns. Catalog metadata owns executable routing and required/optional read lists. This short pack is a source map, not parallel product authority; verify live references.
