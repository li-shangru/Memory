# Client smoke recording template

Status: **not run for this public distribution**.

Copy this blank template to a private location outside the checkout before use.
Leave this tracked template unexecuted; completed trial records stay outside Git,
including content-free outcomes, run identifiers, and installation digests.

Follow [client setup](../client-setup.md#installed-client-smoke) and the
[smoke ceremony](../smoke-ceremony.md). Record client and product versions,
protocol/Skill identities, fixture manifest, fixed slot counts, and outcomes.
Keep raw prompts, answers, private paths, runtime identifiers, authentication
material, and transcripts outside Git. Distinguish failed, blocked, skipped,
ungraded and passed slots with an explicit denominator; do not retry-until-green or change denominators.

No completed client/model trials are claimed by this template.

## Recorded results

| Field | Codex | Claude Code |
| --- | --- | --- |
| Status | `not run` | `not run` |
| MCP contract digest | — | — |
| Skill contract digest | — | — |

## Operator coverage rubric

The following rows are an unexecuted rubric, not observations. Do not include
the hidden coverage IDs in the prompt or require the client to produce them.
The operator maps those observed facts to the rubric after reading the actual
answer. Record missing facts only when the answer identifies them naturally.

| Case | Client | Observed answer | Operator missing-coverage mapping | Outcome |
| --- | --- | --- | --- | --- |
| `SYN-JOURNEY-ENJOYMENT-ZH-003` | Codex | Not run | Expected gaps: candidate activity costs (`SYN-MISSING-CANDIDATE-COSTS-001`); weekend availability (`SYN-MISSING-WEEKEND-AVAILABILITY-002`) | Not run |
| `SYN-JOURNEY-ENJOYMENT-ZH-003` | Claude Code | Not run | Expected gaps: candidate activity costs (`SYN-MISSING-CANDIDATE-COSTS-001`); weekend availability (`SYN-MISSING-WEEKEND-AVAILABILITY-002`) | Not run |
