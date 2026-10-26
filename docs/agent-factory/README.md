# Memory developer factory

Start with [Memory Implement Ticket](../../tools/memory-implement-ticket/SKILL.md)
for substantive repository work. [AGENTS.md](../../AGENTS.md) retains authority over
privacy, review, verification and delivery. This is developer tooling in this
checkout, separate from the generic MCP interface and vendor-neutral packaged Skill.

One coordinator writes and integrates; zero to three explicitly allocated advisers
inspect distinct questions; an actual distinct fresh reviewer checks the final
candidate. Discover all relevant knowledge and risks before choosing advisers.
Users describe the task without naming profiles. The [catalog](catalog.json) owns
canonical pack routing/source metadata and stable legacy adviser compositions:

| Profile | Scope | Explicit risks |
| --- | --- | --- |
| [retrieval-provenance](profiles/retrieval-provenance.md) | Complete reads, snapshots and evidence fidelity | `retrieval`, `provenance`, `pagination` |
| [review-lifecycle](profiles/review-lifecycle.md) | Exact approval, atomic apply and recovery | `approval`, `recovery`, `atomicity` |
| [mcp-contracts](profiles/mcp-contracts.md) | Generic schemas, teaching and wire limits | `mcp`, `contracts`, `wire-budget` |
| [privacy-runtime](profiles/privacy-runtime.md) | Runtime identity and encrypted custody | `privacy`, `runtime-identity`, `custody` |

Selection reads title, description and acceptance, exact path ownership, validated
risk aliases and scoped path/term coupling rules. Latin terms use word boundaries;
Chinese terms can match within continuous text. Recognized `No ... changes`,
`Do not change ...`, `Exclude ...` and `不涉及...` clauses suppress text-only
relevance, including constraint exclusions. They cannot erase explicit/path risks.
Other negation remains a heuristic limitation; inspect reasons and exclusions.

Owned paths and positive expertise matches infer coverage obligations. Selection
prioritizes newly covered critical risks, marginal risk coverage, relevance and
stable profile ID. Scores are not confidence. Unknown work can abstain and use a
generalist. Omitted risks remain blocking until evidenced disposition. Typical work
uses zero to two advisers; a third needs a distinct question. Do not hide a real risk
to reduce the team. Sensitivity/completeness belongs to retrieval; custody/identity
to privacy; approval/guards/recovery to review; wire exposure/teaching to MCP.

## Executable interface

Use Python 3.14 from the repository environment. The Skill wrapper resolves its own
checkout from any working directory. The standard-library runner has no neighboring
repository or model-service dependency:

```console
python3 tools/memory-implement-ticket/scripts/run.py validate
python3 tools/memory-implement-ticket/scripts/run.py --records-root /absolute/records route --task /absolute/records/task.json
python3 tools/memory-implement-ticket/scripts/run.py --records-root /absolute/records context --task /absolute/records/task.json --role implementation --routed
# Record a coordinator allocation against route.discovery_sha256 before init.
python3 tools/memory-implement-ticket/scripts/run.py --records-root /absolute/records init --task /absolute/records/task.json --allocation /absolute/records/allocation.json --run /absolute/records/new-run
```

A task has exactly these fields; retain the real requirements and delivery bounds:

```json
{
  "schema_version": 1,
  "id": "synthetic-pagination",
  "title": "Verify source pagination",
  "description": "Reconstruct invented English and Chinese text through bounded MCP reads.",
  "paths": ["src/memory/retrieval.py", "src/memory/mcp_server.py"],
  "risks": ["retrieval", "mcp"],
  "acceptance": ["Every text chunk reconstructs the exact synthetic bytes and character coordinates."],
  "constraints": ["New disposable synthetic paths only; no connected Memory MCP or owner data."]
}
```

The canonical catalog uses schema 3: four reusable role contracts, four independently
addressable knowledge packs and the stable adviser IDs composed as `advice + pack`.
Packs own facts/pointers, routing vocabulary, risks and required/optional source
lists; profiles are thin compositions and retain domain question templates. No
second editable routing/fact copy remains. Aliases, critical risks, coupling rules,
instructions and the three-adviser cap remain globally canonical. Old catalog 1/2
validation/routing and automatic-allocation callers are compatibility paths; they
produce new schema-3 records but cannot provide composition context. The maintained
normal catalog-3 path requires explicit allocation.

Bounds: four packs per context, 32 required files per pack, 128 deduplicated required
files per discovery/composition, 24 KiB per role/knowledge document, 256 KiB composed
context and 64 applicable instruction files. Refuse overflow without truncating
required knowledge. Validate all local links against declared source/procedure
manifests. Optional missing references remain explicit null identities; they cannot
waive required reads. Required files cannot be waived as tombstones; update their
canonical pack manifest coherently.

Task/catalog source paths must be existing normalized relative files (catalog trigger
paths can be directories). Absolute, hidden, traversing and symlink paths are refused.
Existing path components must use their exact on-disk spelling; case aliases cannot
create a second candidate identity for the same file.
Only `src/`, `tests/`, `tools/`, `docs/`, `third_party/` and root `AGENTS.md`,
`README.md`, `LICENSE`, `pyproject.toml`, `uv.lock` are developer source locations.
The exact public configuration paths `.github/workflows/ci.yml`,
`.github/dependabot.yml`, `.github/CODEOWNERS`, `.github/SECURITY.md`,
`.github/CONTRIBUTING.md`, and the `bug_report.yml`,
`feature_request.yml`, and `config.yml` files under `.github/ISSUE_TEMPLATE/`
are also admitted. Other hidden paths remain excluded. Store/Inbox,
runtime, backups, objects and data directory components are refused even within
those roots; hardlinked files are refused before reading. This is source admission,
not authority to read owner data placed under a misleading source name.
New candidate files can be supplied later. Task text cannot create profiles, grant
permissions, run commands or approve anything. Create a dedicated developer-record
directory outside the repository. Pass its absolute path as the global
`--records-root` option before every subcommand except `validate`. Task, run, result
and evidence paths must be proper children of that root. The root must already exist
and cannot equal, contain, or sit inside the repository. Parent/file symlinks, case
aliases that leave the declared spelling, hardlinked files and nonregular inputs are
refused before content reads; lock files must also be singly linked regular files.
The new run must have an existing parent and not yet exist. Keep generated
runtimes, provider output and private run IDs outside committed source.

## Shared context and explicit allocation

Load the canonical [coordination](roles/coordination.md),
[implementation](roles/implementation.md), [advice](roles/advice.md) or
[independent review](roles/independent-review.md) responsibility with selected packs
using `context --task TASK --role ROLE --routed`, or repeated `--pack PACK_ID`.
`--routed` and `--pack` are exclusive. Unknown IDs, unsafe or missing required files
and overflow refuse. The deterministic `kind: task-context` output returns role and
pack text/versions/digests, required/optional source identities, instructions and
procedure references, original task/acceptance/constraints, explicit omitted text
packs and unresolved risks. Full matched required sources stay visible even with a
text subset. This pure command creates no run, lock, nonce, worker or evidence event.
Advice context additionally requires `--question`; packet uses the same composer.

`route` returns all `matched` lanes and `matched_packs`, `required_sources`, real
risk obligations and `discovery_sha256` before allocation. Capped `selected` lanes
are advisory recommendations. Record this strict external allocation JSON:

```json
{
  "schema_version": 1,
  "task_id": "synthetic-pagination",
  "discovery_sha256": "COPY_CURRENT_ROUTE_DIGEST",
  "selected": [
    {
      "id": "retrieval-provenance",
      "question": "Does the synthetic pagination change confuse search-ladder and detail audit-generation cursor bindings, and which refusal check detects it?",
      "risks": ["pagination"]
    }
  ],
  "omitted": [
    {
      "id": "mcp-contracts",
      "reason": "Implementation owns the public-envelope source and passed reconstruction checks; fresh review checks the final candidate.",
      "coverage_owner": "implementation"
    }
  ]
}
```

This example uses the task above, whose matched lanes are retrieval and MCP. Replace
the digest with the current route identity. Account for **every** matched lane;
selected and omitted IDs cannot overlap. Zero selected advisers is allowed with all
matched lanes omitted and source/check coverage still required. Reject stale/unknown/
duplicate/over-cap IDs, empty/repeated/template questions, incompatible discovered
risks and missing omission reasons/owners. Question task-specificity also needs human
judgment in normal review; deterministic validation is not a semantic judge.

The same discovered packs/source/risk set supports justified zero, one or three
advisers. Allocation changes only actual worker obligations. For every omitted real
risk, retain an actual source/check assessment; omission rationale and loaded packs
supply no execution evidence. Separately required specialized checks remain required.
Allocation is routine coordination, never owner approval. Once established, an ID
cannot be removed by rebind, even after failure/unavailability. Disposition existing
findings before editing allocation. Metadata-only edits use the existing unchanged-
input retry budget; they cannot reset it or clear failed candidate stages. All
historical attempts/findings, exact allocation submissions, supplemental sources and declared candidate paths
remain append-only across allocation/task/HEAD/format round trips.

Example: an invented English/Chinese pagination change loads
[retrieval-provenance](knowledge/retrieval-provenance.md) for the implementer, who owns
vertical source/check changes. A fresh reviewer loads the identical canonical pack
with independent-review responsibilities and current final bytes; the reviewer gets
original requirements, not author rationale or adviser conclusions. Allocate the
retrieval adviser only for the distinct cursor-binding question above. Domain
knowledge loading neither starts that adviser nor performs independent review.

For review use `context --task TASK --role independent-review --routed --run RUN
--candidate CANDIDATE_ID --diff ABSOLUTE_COMPLETE_DIFF`. It requires an existing
current schema-3 candidate, binds exact final bytes/tombstones/HEAD and external diff
identity, refuses missing candidate-required reads and checks snapshot consistency
without locking. It returns no adviser results, contribution decisions or allocation
rationale. Reconcile the complete changed/untracked scope separately. Context or
allocation artifacts are refused as execution, risk-check or review evidence.

The manifest conservatively binds all role/pack contracts and metadata, the whole
catalog/profiles, applicable instructions/procedures, all matched required sources,
task bytes/semantic task, allocation bytes/IDs/questions/reasons/owners and HEAD.
Required role/pack/instruction/allocation drift blocks static capture. Ordinary source
edits after advice remain capturable; fresh review binds the resulting final bytes.
Optional sources become execution dependencies when actually inspected and recorded.
A role boundary is instructed behavior, never a grant or host-enforced sandbox.

## Actual host dispatch

```console
python3 tools/agent_factory.py --records-root /absolute/records packet --run /absolute/records/run --agent SELECTED_ID
# Call the live host's worker tool with this returned prompt; wait for its result.
python3 tools/agent_factory.py --records-root /absolute/records start --run /absolute/records/run --agent SELECTED_ID --worker-id ACTUAL_HOST_ID
python3 tools/agent_factory.py --records-root /absolute/records result --run /absolute/records/run --agent SELECTED_ID --worker-id ACTUAL_HOST_ID --result /absolute/records/returned.json
python3 tools/agent_factory.py --records-root /absolute/records status --run /absolute/records/run
```

The current Codex adapter uses `collaboration.spawn_agent` with `fork_turns: "none"`
and inherited model settings. Read the live tool schema. It explicitly injects the
selected profile into a real worker prompt; it does not register a native custom
agent type. A packet alone has not executed anything. Record IDs from actual host
returns, preserve raw worker output, and explain its contribution to the work.
Advisers cannot edit source, run tests, mutate Git, access owner data or spawn children.
The coordinator schedules all mutations/tests. Read-only instructions are behavioral;
actual permissions remain inherited from the host, with no sandbox added here.

Output JSON must contain `dispatch`, `status`, `summary`, `inspected`, `findings`,
`checks`, `open_questions`, `actions_not_performed`. Copy the packet's `dispatch`
unchanged (`task_id`, `agent_id`, `epoch`, `nonce`, `input_sha256`). Status is
`completed` or `failed`; inspected paths are repository-relative. Findings contain
`severity` (`critical`, `high`, `medium`, `low`, `info`), concrete `evidence` and
`recommendation`. Other lists contain strings. Suggested checks are not executed checks.

Packets include bounded domain questions, match reasons and required reads. Before
dispatch, bindings include applicable in-repository `AGENTS.md` files and declared
developer instructions. Instruction changes also invalidate static candidate checks.
Source/evidence reads retain no-follow ancestor descriptors. Private host/global
instructions are not copied; this manifest covers admitted repository files.

Output acceptance hashes all inspected files, extending dependencies with receipt-time
observations. Keep source stable during advice. These hashes cannot prove which bytes
a worker read earlier. Receipts are coordinator observations, not authenticated host
transcripts; neither hashes nor status labels establish historical truth or approval.

## Failure, resume and risks

The abbreviated commands in this section still require the global `--records-root`
option. Run schema 3 stores the declared canonical root and checks it on every use.
Task schema remains 1; binding manifest is 2, context/allocation schema 1 and new
composition observations schema 2. Historical run schemas 1/2 and earlier manifest
records are status-only. Status returns original task/epoch/dispatch/worker/candidate/
checkpoint identities and outcomes without interpreting opaque candidate IDs,
following old task/source/evidence paths, creating a lock or qualifying current
bindings. A schema-3 run created by catalog-1/2 automatic allocation also becomes
status-only when that catalog path upgrades to schema 3. Classification inspects
only the live catalog's declared schema before old task/source/receipt reads or
locking, preserving the original assignment and outcomes without an allocation.
No silent migration occurs. A legitimate new scope uses a new run; never
use a new run to evade failed bounded work or frozen trials.
Root path/current-directory identity checks are not tamperproof provenance.

`unavailable --run RUN --agent ID --reason TEXT` records a worker that never started.
If host spawn succeeded but `start` refused, interrupt that real worker immediately,
retain its ID/refusal externally, reconcile the drift and rebind before fresh dispatch.
Never fabricate a start receipt or abandon an unrecorded running worker.
A recorded started worker returns an actual failed result, or after a real host interruption
use `interrupt --run RUN --agent ID --worker-id HOST_ID --reason TEXT`.
Interruption can be recorded even after source disappears; new results cannot.

Task, profile, catalog, runner, relevant source or HEAD drift makes existing advice
historical. `rebind --run RUN --reason TEXT` creates a new input epoch and refuses
running workers. Old result dispatch envelopes cannot complete a newer attempt.
Source-linked findings are run-wide obligations, including findings in failed
results. Their stable `finding_id` binds the original agent, actual worker,
immutable result digest and finding ordinal. Exact carried results alias that
origin; identical findings in different results remain separate. `status` exposes
`finding_model_version: 1`, those obligations and `current_binding_sha256`.
Rebind, candidate capture, qualification and passed delivery use the same
run-wide predicate. New empty advice, task/allocation formatting, HEAD changes
and task roundtrips cannot retire an older obligation.

Dispositions are append-only. The latest appended decision is selected before
checking freshness; a deferred or stale decision never falls back to an older
passing decision after source A→B→A. Exact carried contribution prefixes alias
original append events; independently appended decisions remain distinct. New
contribution events use schema 3, recording original finding identity, append
identity, current static/source identities and retained check receipts. Each new
assessment, including a current-result contribution supplied as a plain log,
retains an immutable `finding-assessment` record with the complete context and
exact contribution/evidence/check metadata. Structured check/envelope binding
digests must match that complete context; static and assessed-source projections
must match the sealed context on every read and gate. Editing cached event metadata
cannot relabel an older check as current. This is record coherence, not host
authentication.

Existing unversioned events retain their original evidence and epoch binding
without migration. Intermediate schema-2 events lack a verifiable complete
assessment context; they remain retained and explicitly `unverified` (or deferred),
blocking qualification until a new explicit current-check disposition supersedes
them. The historical bytes are neither migrated nor assigned an invented binding;
`--finding-id` reconsideration remains available under corrected inputs. All cited
sources remain dependencies across later epochs. Source or
global role/pack/profile/instruction/catalog/factory drift makes an assessment
stale until explicitly reconsidered.

For a fresh current result, `contribution --agent ID --finding ORDINAL` retains
its existing evidence form. After correcting bound static inputs or task/allocation
bytes, use `contribution --finding-id ID` with structured current-check evidence,
then rebind and dispatch fresh advice. This path assesses the retained finding
against corrected bytes; it does not refresh old advice, complete workers,
reset retries, capture a candidate or count as independent review.

Execute the relevant checks against the corrected inputs first. Record each
actual command and output in an external JSON check file with exactly:

```json
{
  "schema_version": 1,
  "kind": "finding-check",
  "finding_id": "ID_FROM_STATUS",
  "current_binding_sha256": "CURRENT_DIGEST_FROM_STATUS",
  "source_sha256": {"path/from/advice.py": "CURRENT_SOURCE_SHA256"},
  "name": "Actual corrected-source check",
  "outcome": "passed",
  "command": ["python3.14", "/absolute/records/check_corrected.py"],
  "output": "Actual observed check output"
}
```

The external reconsideration envelope has exactly:

```json
{
  "schema_version": 1,
  "kind": "finding-reconsideration",
  "finding_id": "ID_FROM_STATUS",
  "current_binding_sha256": "CURRENT_DIGEST_FROM_STATUS",
  "source_sha256": {"path/from/advice.py": "CURRENT_SOURCE_SHA256"},
  "checks": [{"name": "Actual corrected-source check", "outcome": "passed", "evidence": "/absolute/records/executed-check.json"}]
}
```

Include every source cited by this finding; additional assessed sources must be
current bound dependencies. Each check must bind the same finding, exact current
context, source map and name as the envelope. Plain old logs, proposed/context
packets, failed checks and stale check bindings cannot supply reconsideration.
The factory retains immutable receipts and rechecks current inputs immediately
before appending. These are coordinator-observed execution records, not
authenticated host execution. Never invent commands or output.

```sh
python3.14 tools/agent_factory.py --records-root /absolute/records contribution --run /absolute/records/run --finding-id FINDING_ID --decision modified --reason 'Correction verified against current inputs' --source path/from/advice.py --line 12 --check 'Actual corrected-source check' --evidence /absolute/records/reconsideration.json
```

`--source` and `--line` identify the original advice location even if correction
moved or removed that line. Current hashes/checks assess the corrected file;
null source hashes represent admitted absence. Required manifest sources still
cannot disappear, and candidate deletion still requires explicit `--delete`.
Unknown/conflicting origins, changed retained evidence, invalid catalogs and unsafe
paths refuse without appending a disposition. A later source or static change
requires another executed check and explicit disposition.

One unchanged-input retry is allowed after failure/unavailability; returning to an
already exhausted input after an intervening different input cannot reset that budget; completed adviser
results and risk dispositions carry forward unchanged. Changed inputs require fresh
advice. Returning to an earlier task scope restores and re-reads its historically
inspected source dependencies before counting attempts; task roundtrips cannot drop
a supplemental dependency to evade the budget. Prior failures remain recorded. Do not retry unchanged failed product checks
into a passing claim. Continue independent work or report a genuine blocker.

Retry and failed-check content identities use the canonical parsed task and exclude
Git revision bookkeeping. A HEAD-only change or task JSON reformat cannot supply
another attempt or clear a failed check. Exact raw task bytes and HEAD remain in
dispatch/freshness bindings, so either change still requires explicit rebind and
new dispatch rather than silently reusing completed advice.

Use `risk --run RUN --risk RISK --disposition coordinator|not-applicable|blocked
--reason TEXT --evidence ABSOLUTE_FILE` for actual assessments. The first two require
evidence and cannot waive a repository gate. Unresolved/blocked risks prevent candidate
capture. A failed required worker remains incomplete even if a candidate is captured;
status does not certify completion. Scope a separate bounded task when necessary.

Risk decisions append events; current dispositions are projections. Catalog-3 omissions, including noncritical risks,
need structured evidence with `risk`, nonempty `sources`, `checks` and
`conclusion`. Each check has `name`, `outcome: passed` and an external `evidence`
file. Assessed source hashes must still match at capture. Generic prose cannot clear
an omitted real risk. Coordinator-recorded checks do not supply owner approval.

## Contribution and measurement records

```console
python3 tools/agent_factory.py --records-root /absolute/records contribution --run /absolute/records/run --agent SELECTED_ID --finding 0 --decision accepted --reason 'Required invariant' --source src/memory/sources.py --line 1 --check 'Actual check reference' --evidence /absolute/records/check.json
python3 tools/agent_factory.py --records-root /absolute/records observe --run /absolute/records/run --observation /absolute/records/observation.json
```

Every retained adviser finding (including a failed result's findings) needs a disposition: `accepted`, `modified`,
`rejected`, `duplicate` or `deferred`. Accepted/modified decisions require a check
reference; all require reason, evidence and an inspected cited source/line. Records
bind the result digest, finding ordinal, advice-time hash and current source hash.
Advice locations are validated when the result is recorded and retained separately
from current bytes, so a repair may remove the cited line or an optional source.
Decisions append. Deferred or stale-source decisions block capture; add a current
decision. A proposed check is not an executed one. Keep author rationale and adviser
conclusions out of the fresh reviewer's input.

Compatibility observation JSON has exactly `schema_version: 1`, `stage`, `worker_id`,
`candidate_id`, `started_at`, `ended_at`, `tool_calls`, `input_tokens`,
`output_tokens`, `cost_usd`, `unavailable_reason`. Stages are advice,
implementation, verification, review and delivery. Supply actual host IDs and
timezone-bearing ISO intervals; unknown candidate/usage values are null. Advice IDs
require recorded starts; author/reviewer identity separation remains enforced.
Unknown usage needs a reason; fully available usage has a null reason. Negative,
nonfinite, boolean or backward measurements refuse. Use interval-attributed usage,
not repeated cumulative totals; cached/reasoning subtotals must not be added again.
Unrepresentable or nonfinite aggregate usage returns a structured refusal; successful
CLI output always uses strict JSON without nonfinite constants.

Corrections append. For the same stage/worker/candidate/interval the latest event is
the aggregate projection, with earlier evidence retained. Status reports unique
adviser starts, unavailable attempts, registered peak advisers, observed interval
concurrency, stage durations and measured/unavailable usage. Carried advice is not
a new start. Observed intervals are not necessarily provider execution time. Missing
stages and unattributable overhead stay unavailable/separate; these observations do
not establish equal compute or productivity.

Composition runs require observation schema 2: the same fields plus `assignment`
with exactly `role_id`, `role_sha256`, `pack_sha256`, `allocation_sha256`,
`context_sha256`, `context_unavailable_reason`. Role/pack identities are the version,
metadata and document identity objects in the bound manifest; allocation must match.
The role corresponds to the measured stage (verification uses implementation).
Context digest is an explicitly coordinator-observed identity, not authenticated
proof of reading; unavailable identity is null with a nonempty reason. The runner
validates current role/pack/allocation identities but cannot attest host telemetry.
Status separates observed loaded pack IDs from actual worker starts. Pure context
creates no observation; compatibility observations never fabricate composition data.

Keep four domains, one writer, cap three, conservative whole-input freshness and
exact unchanged-input reuse. Narrower reuse requires complete manifests and measured
benefit first. Measurement or contribution metadata never resets retry/failed-check
content identities. A wider catalog does not imply more concurrent workers.

## Candidate and independent review

After advice, intentional source edits can be captured without repeating investigation.
Use repeatable `--path` for every changed source/test/instruction/new file. Reconcile
the whole diff, including untracked additions; the runner only knows declared paths.

```console
python3 tools/agent_factory.py --records-root /absolute/records candidate --run /absolute/records/run --path tools/agent_factory.py
python3 tools/agent_factory.py --records-root /absolute/records checkpoint --run /absolute/records/run --candidate CANDIDATE_ID --stage implementation --outcome passed --worker-id AUTHOR_ID --evidence /absolute/records/implementation.json
python3 tools/agent_factory.py --records-root /absolute/records checkpoint --run /absolute/records/run --candidate CANDIDATE_ID --stage verification --outcome passed --evidence /absolute/records/checks.json
python3 tools/agent_factory.py --records-root /absolute/records checkpoint --run /absolute/records/run --candidate CANDIDATE_ID --stage review --outcome passed --worker-id FRESH_REVIEWER_ID --evidence /absolute/records/review.json
```

An authorized deletion uses `--delete old/path`; a rename additionally uses
`--path new/path`. These flags only observe absence; they never delete anything.
Missing sources require explicit tombstones, including a removed parent directory.
Restoration/replacement and changed rename targets invalidate checkpoints. Intake,
new dispatch, results and rebind still require current source references; task,
profile and catalog instruction files cannot disappear. Absence is not authorization.
An absent path never bound as an input or candidate must have exact Git-tracked spelling to be
declared deleted; invented missing paths cannot alter the failed-check identity.
Previously bound paths can still record deletion without Git tracking. Candidate
path declarations persist across matching task/catalog/profile scopes and are
reread on recapture; omitting a prior `--path` does not remove it. An absent retained
path still requires explicit `--delete`, and a restored path binds its current bytes.

Candidate identity binds declared bytes/tombstones, input identity and HEAD. A separate
content identity prevents a new epoch or unchanged-byte commit from erasing failed
verification. Checkpoint stages are implementation, verification, review and delivery;
outcomes are passed, failed or unavailable. A failed stage cannot become passed for
unchanged candidate bytes; allocation/questions/reasons/owners are excluded from
semantic failure/retry identity while bound in exact dispatch freshness. Record genuine no-assertion environment failures as
unavailable, preserving cause. Capture corrections and rerun affected checks.

Review must be fresh, separate from authors/advisers, and receive original requirements,
acceptance, final diff/candidate and failure modes without author rationale or adviser
conclusions. The recorder rejects conflicting identities regardless of receipt order.
A candidate's declared scope is not proof every changed path was included or reviewed.
Candidate capture precedes review. `status.ready_for_delivery` is the shared derived
gate: exact current candidate/bindings, every established adviser actually completed,
current risk/finding evidence and passed implementation/verification/distinct-review
checkpoints for that candidate. A passed delivery checkpoint uses the same gate;
failed/unavailable attempts remain recordable. Empty adviser completion or prepared
context/allocation JSON cannot satisfy it. Normal local delivery gates still apply.

## Verification and delivery

Run `uv run pytest tests/test_agent_factory.py`, `python3 tools/agent_factory.py validate`,
and the required working/final gates from [local delivery](../local-delivery.md).
New adapters require a live synthetic task with actual explicitly allocated workers
and a fresh coordinator starting from AGENTS.md after adapter freeze. Compare bounded
generalist/specialist coverage on the same task, without statistical productivity
claims. Keep unavailable host token/cost metrics explicitly unavailable.

This factory is not in the product wheel or source archive, and product delivery only
synchronizes the two product Skills. The developer Skill is discovered from AGENTS.md;
there is no claim of native loader registration. Developer-only changes do not require
an artificial version bump when all frozen release inputs remain identical. Still run
the normal delivery and finishing gates; immutable input drift requires the prescribed
coupled release, not a bypass. Existing MCP connections require restart/reconnect.

The developer runner is included as part of this project's source. It has no
runtime dependency on another repository. Preserve its lifecycle, replay,
reviewer-identity, path-admission, and deletion protections when updating it.
