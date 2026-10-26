# Maintenance and verification details

Read the sections relevant to the affected code. [AGENTS.md](../AGENTS.md) owns
scope, privacy, authorization and completion; [technical design](technical-design.md)
owns the product contract. Storage changes also require the affected design
sections 4–5; approval and guard changes require sections 6–8.

## Verification details

Both gates type-check `src`, `tests`, and `tools` under `mypy --strict`. The
tests are held to the same standard as the product for one reason: a test
annotated `object` and then asked for an attribute is a test nobody has
checked the shape of, and this suite's fakes stand in for a Store holding the
owner's data. Reach for a real type before `Any`, and never a bare
`# type: ignore` -- every one names its error code. Give it a reason too
wherever the code alone does not explain the choice.

`./tools/fast-check.sh` is the working gate and `./tools/check.sh` is the
finishing one. `tools/install-hooks.sh` installs both git hooks: pre-commit
(format, secrets, forbidden paths) and pre-push, which runs the fast gate so
a push cannot publish a tree the working gate refuses. The difference is the real-browser owner journeys, which are
the only thing that exercises rendered copy, focus order, and drag and drop;
`fast-check` deselects them with `-m 'not browser and not slow'` and needs no
Chromium, so a change to anything owner-visible is not verified until
`check.sh` has run. Both gate `src`, `tests`, and `tools`.

Coverage is measured on request rather than gated, since a percentage is not
an invariant and nothing should be written to chase one:

```
uv run pytest -m 'not browser and not slow' --cov=memory --cov-report=term
```

Read the result with the architecture in mind. `pdf_render` renders in a
subprocess this harness cannot instrument, so its number reads far lower than
its real coverage; `inbox.py`'s missing lines are concentrated in crash paths
reachable only by killing the process at a checkpoint.

## Compatibility and coupled artifacts

Changing any persisted format (`runtime.json`, `store_meta`, the change-set
digest payload, the MCP envelope, or `schema.sql`) is a breaking change to a
Store that already holds owner data; design the compatibility path first and
say so explicitly in the change description. The change-set digest payload's
`guard_links` key is conditional for exactly this reason: present only when a
revision carries a link, never unconditionally, because every revision's
digest is recomputed and reverified on every load; an always-present key,
even empty, would make every revision that predates it fail closed as
`wrong_digest` permanently.

Coupled artifacts that must move together, or fail loudly if they do not:

- The SQLCipher companion revision couples its source patches, build recipe and
  reproducibility hashes with the versioned Release asset, package/lock pin, database
  attestation constant, smoke scripts, delivery transition policy and approved
  artifact digest. Existing wheels remain immutable. Native file identity must
  come from the owning VFS descriptor before key/SQL access; pathname checks are
  insufficient. Review and reproduce any changed companion before delivery.

- Search cursor or rung semantics change with `LADDER_VERSION`
  (`src/memory/retrieval.py`); bump it so in-flight cursors fail closed. It is
  load-bearing in six places: the kernel binding and snapshot digest in each of
  `retrieval.py` and `memories.py`, plus the two owner bindings, which fold it
  in so an owner cursor minted against an older rung ordering fails closed
  rather than resuming into a different one.
- The FTS DDL exists twice with no shared source of truth: `schema.sql` and the
  mirrors in `maintenance.py`. Editing one without the other makes every
  existing Store report `reindex_required` forever with no repair path.
  `source_fts` is also written at capture time in `inbox.py`; a column added to
  the projection and not to that INSERT is a column no Store gains without an
  explicit `memory reindex`.
- Any MCP schema or serializer change moves `contract_digest()`; recompute it
  and update `EXPECTED_MCP_CONTRACT_DIGEST` in `tests/test_mcp.py`, whose
  mirrors must match structurally, not just by digest.
- `SKILL.md` is word-budgeted by `tests/test_skill.py`, and every backticked
  `memory <subcommand>` it names is cross-checked against the registered CLI
  parsers; the wheel ships the exact bytes.
- The guard tables are healed additively at every writer `BEGIN`
  (`_ensure_auxiliary_tables`); new tables for existing Stores follow that
  pattern or state their own migration path. `CREATE TABLE IF NOT EXISTS` does
  not alter an existing table, so a new **column** needs an explicit
  `ALTER TABLE ... ADD COLUMN` guarded by a `PRAGMA table_info` check beside
  it, nullable, and the same column in `schema.sql` so a fresh Store matches.
- The v1.12 scan scheduler tables and history/active-relationship indexes also
  heal at writer entry and are mirrored in `schema.sql`. Reads never heal.
  Scheduling progress is not source custody: interrupted inactive cohorts
  may be retired in bounded transactions, but capture and claim recovery keep
  their existing identity and atomicity checks. Detail cursors bind audit
  generation; scheduler-only commits can therefore stale them. Legacy Stores
  without the new indexes bound Python detail records but may do more SQL work
  until their next normal writer operation.
- Pending new-Store initialization uses its own owned intent; it does not
  change `runtime.json`, Store schema lineage or historical approval digests.
  Never treat an existing identity with a missing database/key as a new intent.
  Initialization helper checkpoints need real subprocess death and fresh retry
  evidence, including safe refusal of incomplete or foreign-owned artifacts.
- Owner-visible copy in `src/memory/ui/templates/` is coupled with
  `tests/browser/` journey assertions; changing rendered wording means
  running the browser suite, not only the fast gate.
- Every fault-injected name in `memory.inbox` is coupled with every caller of
  it, and `tests/test_inbox_seam.py` enforces that. The Inbox suites prove
  durability by replacing an attribute on the `memory.inbox` module object and
  crashing the process at a checkpoint; that reaches only call sites resolving
  the name in `memory.inbox`'s own globals. Moving one such caller into another
  module leaves the patch succeeding, changing nothing, and the suite green.
  This is why `src/memory/inbox.py` is not split: at v1.2.0, 82 of its 193
  definitions — 58% of its lines — call one of the 21 patched names, and the
  dependency graph has no non-trivial cycles, so there is no tangle a split
  would resolve. Those four figures drift with the file and are meant to be
  recounted rather than trusted: the roster is whatever
  `tests/test_inbox_seam.py::_patched_names()` returns, and the rest is one
  `ast` walk over the module. The argument is the proportion, not the digits.
  Adding a `_checkpoint` call means adding it to one of the three inventories
  in that file: exercised, observed, or admitted as coverage debt.
