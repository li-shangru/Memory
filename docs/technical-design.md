# Memory technical design

- **Source version:** v1.13.0, with
  [public source verification](acceptance/v1.13.0-acceptance.md) recorded
  separately. This document is the product contract for the implementation;
  the code and tests in this repository realize it.
- **Scope:** the encrypted Store, capture and review workflow, generic MCP
  surface, packaged Agent Skill, CLI, and local owner UI.
- **Runtime:** Python 3.14 only and MCP Python SDK 2. The stdio server
  supports modern MCP 2026-07-28 discovery and legacy initialize clients while
  preserving the same fourteen-tool `memory.mcp.v1` contract.

## Navigation

Read sections 1–3 first, then follow the [task map](README.md) to the affected
contract. Procedures and measured results have separate owners.

| Sections | Contract |
| --- | --- |
| [1–3](#1-product) | Product, invariants and architecture |
| [4](#4-runtime-and-schema) | Runtime identity, schema and intake companion |
| [5](#5-sources-and-inbox) | Source custody, batch scanning and retrieval |
| [6–8](#6-canonical-memory) | Canonical memory, exact review/approval and guard links |
| [9](#9-generic-mcp-and-skill) | MCP operations and packaged Skill conduct |
| [10](#10-local-owner-ui) | Owner UI, session security, audit and graphs |
| [11](#11-verification) | Source, installed-client and delivery verification |
| [12](#12-limitations-and-operational-notes) | Product limitations |

## 1. Product

Memory is a local encrypted memory store for one owner. It lets Codex, Claude
Code, and compatible LLM agents retrieve retained sources and owner-approved
memory through a generic MCP interface.

The Store does not generate advice. It owns source custody, structured memory,
review state, and retrieval. The client agent searches, reads, assesses
coverage, reasons, and answers.

```text
drop files into the inbox
-> agent scans one batch
-> agent drafts one Memory Review
-> owner edits or rejects individual items
-> owner approves the exact batch revision
-> Store applies the whole revision atomically

ask a question
-> agent searches approved memory and full sources
-> agent reads enough context or reports what is missing
-> agent answers with evidence and inference distinguished
```

- package: `src/memory/`; distribution: `memory`; CLI: `memory`.
- One strict schema v1 with product marker `memory` and schema lineage
  `memory-store-v1`. A foreign or unrecognized database is rejected with
  `wrong_product`; it is never upgraded or repaired into a Store.

## 2. Invariants

1. **The Store supplies evidence; the agent reasons.** No package path imports
   a completion, extraction, advice, or embedding provider.
2. **Full source fallback.** Every retained source is enumerable and completely
   readable even when it is not text-searchable.
3. **No unapproved interpretation.** Only an exact owner-approved-and-applied
   Memory Review creates canonical memory.
4. **Complete batch accounting.** Every source in a batch is explicitly
   covered by proposed memory items or a reviewed `no_memory` decision.
5. **One batch, one approval.** At most one change set total exists per sealed
   batch; one approval covers one immutable revision digest.
6. **Atomic, idempotent apply.** All approved items apply or none; exact retry
   returns the original result.
7. **Append-only history.** Corrections and supersessions append revisions.
8. **Integrity is not truth.** Structural validity, source fidelity, owner
   semantic review, and retrieval coverage remain separate.
9. **Sensitivity is capture-specific.** Byte deduplication never lowers or
   conflates provenance or sensitivity.
10. **Stored content is inert.** Source instructions are untrusted data, never
    Skill, tool, or system instructions.
11. **The runtime fails closed.** Every command validates the persisted
    runtime identity — product, lineage, schema version, Store ID, runtime
    mode, and inbox path — before touching the database or Keychain. Absent,
    unknown, or mismatched identity values refuse without mutation.

## 3. Architecture

```text
inbox (default child or configured external directory)
    │
    ▼
settled batch scanner
    │
    ├─> capture records ──> deduplicated encrypted blobs ──> source FTS
    │
    └─> one change set ──> immutable draft revisions
                              │
                         owner approval
                              │
                              ▼
                  canonical memory revisions + evidence
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
      generic stdio MCP   local owner UI   CLI adapters
              │
      portable Agent Skill
              │
      Codex / Claude Code
```

MCP, CLI, and UI are adapters over one domain layer. They share the same
validation, writer lock, digest calculation, stale-state detection, and atomic
application behavior. No adapter keeps a writable Store connection open: each
mutation obtains the nonblocking writer lock, runs one bounded transaction,
closes, and returns.

## 4. Runtime and schema

### 4.1 Runtime

`memory init` creates a new mode-0700 runtime. Without `--home` it uses the
default root `~/Library/Application Support/Memory`; an explicit `--home`
selects another path, and every command accepts the same optional `--home` to
address that runtime. A relative CLI spelling is expanded lexically against
the caller's current directory and normalized for `.` and `..` before any
derived path, identity read, topology comparison, filesystem side effect, or
Keychain access. This lexical normalization does not resolve symlinks.
Initialization requires the target root to be absent or empty. The owner-facing
`memory paths --json` returns the resolved runtime and inbox paths; MCP never
exposes paths.

```text
store.sqlite3
store.sqlite3-wal / store.sqlite3-shm
inbox/                       # default location; may be configured elsewhere
inbox-claims/
inbox-staging/
runtime.json
.writer.lock                 # created on first writer use and may persist
.inbox-scan.lock             # separate scanner lease; no scheduling authority
.ui-session.lock             # held for the foreground `memory ui` lifetime
```

`inbox-staging/` is a private mode-0700 sibling of `inbox-claims/`. Runtime
repair may restore directory permissions but rejects a symlink or
non-directory. Merely resolving paths never creates lock files.

Initialization generates a random Store ID and 32-byte master key, stores the
key in a distinct macOS Keychain item (service `memory`, account = Store ID),
and writes matching runtime/database identity:

```text
product = memory
schema_lineage = memory-store-v1
schema_version = 1
store_id = random 128-bit ID
runtime_mode = personal
inbox_path = absolute inbox directory
```

Opening an existing Store calls `load_master_key`; it never creates or
replaces a missing key. Missing or mismatched Keychain state fails closed.
Runtime mode is persisted in both `runtime.json` and `store_meta`; `personal`
is the only recognized value, and absent, unknown, or mismatched values fail
before Store mutation. Foreign product, lineage, or Store ID likewise fails
without mutation.

Initialization additionally binds every directory ancestor with no-follow
descriptors and retains those descriptors through the operations they authorize.
Runtime, Inbox, claims and staging must have distinct filesystem identities;
the default Inbox is the only allowed Inbox descendant of the runtime. Valid
external Inbox directories may retain waiting files and must share the runtime's
volume. Lexical normalization remains unchanged, but an initialization spelling
through a symlink ancestor now refuses instead of following the alias. It never
silently rewrites a persisted path. Ordinary existing-Store reads retain their
prior path rules, except that pending initialization refuses before key/database
access. Permissions and publication operate against the validated identities,
not a later pathname lookup.

New-Store creation uses an initialization intent, separate from the unchanged
`runtime.json` identity format. Its ownership binds the directory identities,
random Store ID, exact staged file identities and planned key digest before
Keychain creation. A retry proceeds only when the intent and every present
artifact agree. Publication makes the durably prepared encrypted database
visible without replacing any winner, then publishes matching identity last.
The intent fences ordinary operations until database identity and WAL/FULL
configuration are verified and owned staging is cleaned durably.

The private artifacts are `.initialization.intent.json`,
`.initialization.runtime.json`, and `.initialization.store.sqlite3`. The
`memory-initialization.v1` intent appends canonical complete records: `prepared`
authorizes only the exact unpublished files, and `ready` attests the durable
encrypted schema before publication. A torn later record can be trimmed to its
validated complete prefix through the held, matching intent descriptor; a torn
first record refuses. A prepared intent alongside public artifacts also refuses.
Key creation uses an exclusive Keychain add, so a concurrent account winner is
never replaced. Database construction addresses the held staged file identity;
publication uses stable file-reference moves without overwriting destinations.
Cleanup removes only the attested artifact identity, preserving replacements.

Persisted directory and file identities include the device and inode. Recovery
therefore proves process-death/restart recovery on the same mounted filesystem;
device-number changes after remount safely refuse and retain the artifacts.

Before a complete durable intent exists, an interrupted preparation safely
refuses and retains its artifacts without creating a key. After intent
publication, retry resumes the owned state. A missing key may be newly created
only while the exact owned staged database remains empty and neither public
database nor identity exists; any ciphertext or public artifact makes a
missing key a refusal. An existing or foreign Store never enters that branch.
Recovery does not delete or replace artifacts whose ownership, identity or
content cannot be proven. Process-death tests, including fresh-process retry,
are required for each published transition; catchable exceptions alone do not
establish this protocol.

### 4.2 Configurable inbox

`memory init --inbox PATH` records an external inbox directory in
`runtime.json` as `inbox_path`. The recorded value must be an absolute
normalized path; inside the runtime root only the default `<root>/inbox` is
accepted, and a path that contains the root is rejected. The external
directory may already exist and hold waiting files; initialization creates it
(its parent must exist), enforces mode 0700, and requires it to be on the same
filesystem volume as the Store home so custody renames stay atomic.

Re-running `memory init` with a different `--inbox` for an initialized Store
is refused; the recorded inbox is authoritative and every command validates
that the resolved paths match it. Claims, staging, database, identity, and
locks always remain inside the private Store home regardless of the inbox
location.

An initialized external Inbox moves only through
`memory relocate-inbox --to ABSOLUTE_PATH`. The destination is absent under an
existing owner-controlled mode-0700 directory on the same Store volume. The
command takes the UI-session and Store-writer locks, requires empty private
claims/staging custody, binds the exact Inbox and both parents, durably writes
a private intent, and moves one validated macOS Foundation file reference
without replacing a destination winner. It then atomically advances the
unchanged `runtime.json` identity and removes the intent. A retry with the same
destination completes any unambiguous interrupted phase; every ordinary
command refuses while the intent or either temporary exists. The transition
does not read or enumerate waiting files, change the Store ID, database,
Keychain item, schema, or audit generation, or move the Store home. Long-lived
clients must restart afterward so no process retains the old resolved path.

This supports keeping the visible inbox in an editor-neutral local folder or
in a folder synchronized to other devices. Only unscanned inbox files are ever
exposed to that folder; scanned content lives exclusively in the encrypted
database.

The companion binds every persisted directory identity — configuration,
transaction receipts, and recovery intents — as the containing volume's UUID
plus the inode, not `st_dev` plus the inode: APFS assigns device numbers at
mount time, so they renumber across reboots while the volume UUID and inode
persist. The primary binding reads both fields from one directory descriptor
opened `O_NOFOLLOW` (`fstat` plus `fgetattrlist`), so volume and inode
describe the same observed object; by-name child probes use `getattrlistat`
without opening the entry. A symlinked or replaced root still refuses through `O_NOFOLLOW` and
the inode, and a foreign volume mounted at the path differs by UUID. The
binding requires a volume that reports a UUID at all — effectively APFS or
HFS+; FAT, exFAT, and most network filesystems do not — and that constraint
surfaces as `volume_unidentified` under its own name rather than being
re-coded as authority drift, while a name deleted between two lookups reads
as absent exactly as a stat would. Automatic v1 adoption additionally
refuses a mount-point root (`notes_root_unverifiable`,
`memory_inbox_unverifiable`): volume roots share inode 2, so a stored root
inode distinguishes nothing there, and only the explicit
`relocate --adopt-current-authority` rebind may adopt one. The
persisted forms carrying an identity are versioned together:
`staged-memory-intake.config.v2`, `staged-memory-intake.transaction.v3`,
`staged-memory-intake.root-relocation.v2`,
`staged-memory-intake.layout-migration-intent.v2`, and the
`staged-memory-intake.promotion-manifest.v2` digest payload. The v2 config
carries one optional `pending_drop` boolean written only when true, so a
flag-off record stays byte-identical for older readers, and an older reader
given an enabled record refuses it whole as `invalid_config` rather than
reinterpreting it. A v1 device-bound config is adopted in place on its first
live load: the helper verifies the stored inode against the safely opened
live directory while deliberately ignoring the stale device number,
revalidates the complete layout, and atomically rewrites the config in the
volume-bound form with a strict re-read; an inode mismatch still refuses
`notes_root_changed`. Device-bound receipts and pending intents are refused,
not reinterpreted, so active transactions and recoveries should complete
before upgrading; for state that did not, the explicit `abandon-unsupported`
command quarantines exactly the provably unsupported artifacts under
`abandoned-` names, preserving their bytes, and never touches current-schema
or malformed state. Downgrading the helper has no equivalent escape hatch: a
pending relocation or layout migration should finish first, because a
pre-1.9.0 helper refuses an intent carrying the flag under its own exact-key
parse and `abandon-unsupported` does not quarantine a same-schema intent, so
recovery from that state means reinstalling a 1.9.0+ helper and finishing the
operation. One narrowing is recorded and accepted: a same-UUID block clone
mounted at the expected path passes the identity checks the boot-assigned
device axis refused, because no persistable axis distinguishes a faithful
clone of the same owner's bytes from its original across a reboot.

The repository-owned staged-memory-intake companion keeps shared rules and ordinary
preparation in its `SKILL.md`, routing migration, relocation, decision notes and
loop corrections to bundled Markdown references. Read the matching reference
before acting on that branch; all existing approval and recovery contracts apply.
The frozen bundle includes every reference byte with the root, metadata and helper
files. Missing, extra, unsafe or changed files fail its synchronization checks.

The companion adds a coordinated
`relocate --to ABSOLUTE_NOTES_ROOT` operation for the case where that Inbox is
one child of its configured notes root. Under the helper's private transaction
lock, with no active intake transaction, it records a private phase intent,
uses `memory relocate-inbox` to park the exact Inbox inode temporarily under
the helper's mode-0700 state root, exclusively renames the remaining notes-root
directory, and uses `memory relocate-inbox` again to place the same Inbox at
the new root. It then atomically advances the unchanged
`staged-memory-intake.config.v2` shape and clears the intent. Exact retry
recovers every committed or uncommitted phase; every other helper command
fails closed while the intent exists. The coordinator accepts the four intake
root children plus an optional `.obsidian` metadata directory, binds every
accepted directory's identity and metadata in the intent, and never inventories
any child directory. It changes no Memory persisted format or MCP surface.
An explicit `--adopt-current-authority` mode exists only for an owner-confirmed
configured path whose stored volume/inode binding is stale: before changing the
config it requires no active transaction, the same stored paths, the exact
private expected layout, and Memory's current binding to that exact Inbox. It
atomically refreshes those identities. When the requested root is that same
configured path, it revalidates the rebound authority in place and returns
current without a Memory Inbox relocation or helper relocation intent; for a
different requested root it then enters the ordinary relocation protocol. The
in-place branch does not require authority over the configured root's parent.
It never accepts a new source path.

The companion's one canonical notes-root layout is `01_Pending`, `02_Staged`,
`03_Prepared`, and `04_Inbox`, plus an optional opaque `.obsidian` directory.
`03_Prepared` is the owner's private full-content review surface. The agent
creates candidates before requesting review. Its Prepared-preview output and
session chat emit only a content-free manifest: ordered names and mappings,
hashes, counts, sensitivities, guard endpoints, the per-candidate
`verbatim_statement` marker, and the exact digest. The marker reports whether
the statement equals the staged note's UTF-8 text after trimming surrounding
whitespace; it derives entirely from digest-bound bytes, so it rides the
preview without entering the manifest digest, and in-flight authorizations
keep their digests across the change. Prepared
bodies, statements, front matter, and evidence excerpts remain out of both.
The owner may edit
or tune candidates in place; every edit requires a fresh complete preview, and
approval authorizes only that current digest.

Before any Prepared write, the companion reconciles the complete selected Staged
set against approved memory through `using-memory`: `store.status` first, an
exhaustive queryless `memory.search` walk with `tags_all: ["loop:open"]` and no
aspect, kind, date or sensitivity filters, then relevant bounded memory/source
queries for updates. Every plausible target requires complete current
`memory.get` details, history, guards and material source reads. Thin, conflicting
or unmatched update coverage invokes the Skill's enumeration and full-source
fallback before concluding that no target exists. Matching uses meaning and
provenance rather than filenames or closure headings.

The companion classifies every selected source before writing: genuinely new
item, whole-loop closure, re-horizon or partial correction. Corrections take the
existing direct source-backed route, never a new Prepared item or a silent
omission. Mixed selections resolve correction routing before a preparation
transaction starts; unresolved target or disposition ambiguity blocks the
selection under the private clarification rule. A decision to stop is not proof
that stopping occurred, and one changed follow-up does not close a grouped
memory. Corrections target the current lineage and expected head, preserve
history and unaffected fields, and still require a separate exact owner-approved
Review. Reconciliation exposes only filenames, private locators and route or
issue categories in chat, never Staged or retained content.

For an owner-placed Staged correction, the intake request authorizes agent source
transport and a correction proposal without another owner-copy/UI-capture step.
The direct route preserves the original bytes, publishes a complete private copy
exclusively into the configured Inbox, and uses existing generic MCP operations
to capture and review it against the current lineage and expected head. It never
uses the ordinary new-item Prepared/edit-plan/cleanup receipts. Exact Memory
Review approval remains separate. A conversation-only advisory draft still needs
owner source placement or UI capture before review.

Resolve selected sources by current target lineage/head before transport. Multiple
notes for one lineage produce one complete supported correction citing every
contributing source, preserving chronology and unaffected fields; unresolved
contradictions block dependent work. A Review cannot contain competing successors
for the same lineage. Check complete grouped proposals against existing public
Review bounds before transport; an over-bound group stays untouched with a
content-free capability blocker rather than losing evidence or splitting its
outcome across Reviews. Already owner-placed Inbox sources skip Staged-copy setup but
still require complete source accounting and the normal one-capture Review rules.

The direct route checks for an existing exact capture before publication, reuses
its one batch/change set/application, and resolves a lost scan result only through
complete enumeration. Byte deduplication does not authorize another capture.
Unexpected Inbox entries, uncertain copy ownership or a mismatched sealed roster
stop dependent proposal/application. The generic scanner has no file selector:
concurrent arrivals may be co-captured and are detected by exact roster checks;
the route does not promise atomic isolation against arbitrary arrivals. Staged
originals remain preserved after successor verification because the ordinary
helper cleanup receipt does not cover this direct route.

Ordinary preparation produces one minimum complete memory for each selected
Staged note and preserves that one-to-one mapping unless the owner names a
different operation; it does not combine or split by default. The concise,
self-contained rewrite retains every distinct durable fact, preference,
constraint, condition, exception, relationship, rationale, and uncertainty
while removing repetition, redundant restatements, drafting commentary,
incidental formatting, and generic filler that adds no distinct information. An
example stays when it uniquely establishes scope, a boundary, or an exception,
and a detail stays when its materiality is uncertain. The agent neither
fabricates a conclusion, infers an unsupported preference, nor drops a
qualification to make the note shorter. There is no word, paragraph, or byte
target: length follows distinct material information, and the helper ceiling is
not a quality target.

Use the owner's requested output language for the current operation; otherwise
preserve each source language, including mixed-language passages. This applies to
generated statements, Prepared filenames, and ordinary generated tag text.
`source_note` preserves the exact source filename. Identity-bearing names and terms
and exact quotations remain faithful in any language; never silently translate,
romanize, or ASCII-filter them. Machine keys, reserved tag tokens and prefixes,
and decision-section labels remain unchanged. This prospective generation rule
neither infers nor persists a personal language preference, rewrites existing
notes, nor changes runtime or client configuration.
The reserved `standing` tag remains limited to source-explicit durable
preferences, patterns, or constraints intended to guide future advice.

Ordinary notes stating unresolved commitments, reminders, follow-ups or revisit
intentions receive `loop:open`, including undated intentions. Completed events,
retrospective reviews and hypotheticals alone do not create open items. Preserve
any source-stated cadence and date anchor in the statement; use `valid_to` only
for a supported next horizon. Relative days require an unambiguous source-stated
calendar date, never a filesystem, capture or preparation timestamp. Cadence
alone does not determine a next date. A missing anchor remains explicit
uncertainty with no fabricated horizon. Multiple follow-ups retain their own
dates in the statement; leave the shared horizon blank for distinct dates unless
the owner requested a split. The default one-note/one-item rule remains.

A staged decision note becomes a concise rewrite in the requested or source
language that preserves the
required labeled Question, Options considered, Recommendation, Decision, and
Rationale structure plus Revisit by only when the source states it. Every
material option, recommendation, decision, rationale, condition, and uncertainty
survives. Existing front-matter semantics remain unchanged: the item is an
event, occurrence is the stated decision date, the horizon is the stated
Revisit by date, and `loop:open` appears exactly when that section is present.
The note is neither combined with another note nor split.

Before writing any candidate, the agent performs one semantic plausibility and
consistency pass over the whole selected set. It automatically corrects clear
spelling and typing errors in generated Prepared prose, including meaningful
and domain-specific terms, when source context makes the intended wording
unambiguous. Meaning-safe grammar and presentation cleanup also stay automatic;
these corrections require no error report or owner confirmation. Staged bytes,
source hashes, and exact quotations remain unchanged.

An unresolved suspected typo, implausible or confusable magnitude or unit,
chronology conflict, internal contradiction, or materially ambiguous assertion
blocks every candidate before write or preview. Plausibility alone cannot
supply a factual correction. The chat response remains content-free: it
identifies only the Staged filename, a private location when useful, and the
issue category. The owner corrects or confirms the Staged source privately;
conversation alone is not evidence, and preparation resumes only after rereading
the source's new exact bytes and hash. The pass writes no warning markers into
Prepared content and is not a certification of truth.

Prepared front matter derives `occurred_on`, `valid_from`, and `valid_to` from
semantic occurrence, effective/start, and expiry/horizon/revisit evidence in
the source. It retains source-supported partial precision. A nearby month and
day without a year uses the calendar occurrence nearest the current local date,
subject to explicit past or future wording and year-boundary direction;
filesystem, capture, and preparation timestamps are never occurrence evidence.
Absent or materially ambiguous fields remain blank. These dates stay inside
the private Prepared surface and outside chat and the manifest. The concise
decision-note rewrite and direct closure/re-horizon contracts remain distinct.

An owner-requested `cancel-publication --transaction FULL_ID --digest FULL_DIGEST`
withdraws an exact active `published` promotion only before `scan_started` is true.
It preserves the original v3 receipt and all Staged/Prepared files, including
owner changes or absence, and never resets scan state or changes the Store.
Only the exact receipt-bound published copies may move to a mode-0700 private
archive on the same volume. The whole Inbox, including hidden entries, must
match the promotion before cancellation intent is recorded. Every moved file is
bound by its volume/inode, regular-file mode, byte length and digest, and no
destination may be replaced.

Cancellation uses an additive strict
`staged-memory-intake.publication-cancellation.v1` sidecar and final marker, leaving
existing receipt and authorization digest formats unchanged. Durable intent binds
the transaction, manifest and archive before the first move. Exact retries resume
only unambiguous source-only or archive-only file states; any foreign, missing,
changed or multiply present entry stops recovery. All other helper work is fenced
while cancellation is pending, including the interval after its final marker is
durable but before detaching the matching active pointer. Completion requires the
exact complete archive and empty Inbox, then retires only that transaction's active
pointer. Replaying a completed cancellation never detaches a newer intake. Status
and errors remain content-free. A later preparation needs a new preview and exact
owner decision; earlier authorization is not reused. Once scan intent is durable,
cancellation is forbidden even when its scan result is absent.

Legacy `Pending`, `Staged`, `Prepared`, and `Inbox` labels are accepted only by
the argument-free `migrate-layout` compatibility command. Ordinary commands
recognize an exact legacy layout without writing and return
`layout_migration_required`; after a private migration intent is durable they
return `layout_migration_pending` and only exact `migrate-layout` retry may run.

The migration holds the helper transaction lock, requires no active intake or
root-relocation intent, binds the root and all four legacy directory identities,
and publishes `.layout-migration.intent.json`. It asks `memory relocate-inbox`
to advance the exact Inbox inode to `04_Inbox`, then exclusively renames the
other three entries one at a time with parent fsync and a durable phase after
each side effect. After exact final inventory and Memory-path verification, it
compare-and-swaps the structurally unchanged
`staged-memory-intake.config.v2` record and removes the intent. Every phase
accepts only its adjacent old/new name state; a collision, mixed layout,
identity or permission change, config substitution, or unexpected root entry
fails closed. Migration lists only immediate root labels and never inventories
a workflow child or `.obsidian` contents. It changes no Store, runtime, MCP,
approval, digest, or audit-generation format.

Path B outcome capture: `pending-drop` writes one owner-consented
decision-note draft as a new root-level regular file in `01_Pending`. It
refuses unless the private configuration carries `pending_drop: true` — a
setting only an owner-run `configure --pending-drop on` writes, reported by
`configure` and `status`, and carried unchanged through relocation, layout
migration, and legacy-config adoption. The write is create-only: `O_EXCL`
and no-follow through directory descriptors, mode 0600, fsynced through the
pending directory, so a collision refuses as `pending_note_exists` and
nothing is ever overwritten or followed. Refusals are content-free
(`not_configured`, `pending_drop_disabled`, `pending_note_exists`), and a
refused agent falls back to presenting the draft in conversation. Intake
transactions never read `01_Pending`, so the write needs no transaction
awareness; a pending relocation or layout migration still refuses it like
every other command.

### 4.3 Disposable schema v1

There is one `schema.sql` and no migration ledger; schema version 1 is the
only version. The schema contains:

```text
store_meta
source_blobs              sources
inbox_batches             inbox_batch_sources
inbox_scan_progress       inbox_scan_candidates
inbox_batch_issues        source_fts
memory_fts
memory_lineages           memory_revisions
memory_evidence           current_memory_heads
change_sets               change_set_revisions
change_items              change_item_evidence
batch_source_decisions    approvals
applications              application_memories
memory_guard_links        change_revision_guard_links
change_revision_guard_revocations
```

All ordinary tables are strict, foreign keys are enabled, and destructive SQL
is absent from normal operations. The rebuildable FTS5 virtual tables are the
only `STRICT` exception because SQLite does not support that modifier on
virtual tables.

`store_meta.audit_generation` begins at zero. Every successful bounded writer
transaction that changes either authoritative rows or disposable projections
increments it exactly once in that same transaction. A rolled-back transaction
or a writer session that makes no database change leaves it unchanged. Opening
a database whose generation is missing or structurally invalid fails closed.

### 4.4 Storage kernel

- the repository-owned `memory-sqlcipher3` companion, built from hash-pinned
  SQLCipher 4.17.0, SQLite 3.53.3, and OpenSSL 4.0.1 sources for CPython 3.14,
  macOS 26 Apple arm64;
- SQLCipher with `cipher_page_size=4096`, `kdf_iter=256000`,
  `cipher_hmac_algorithm=HMAC_SHA512`, and
  `cipher_kdf_algorithm=PBKDF2_HMAC_SHA512` pinned on every connection;
- WAL and `synchronous=FULL`;
- a process-level nonblocking writer lock;
- immutable rows for source blobs and applied memory revisions;
- SHA-256 byte identity; and
- read-only connections set `query_only`.

The `.memory1` downstream companion adds `Connection.file_identity()`. Its
private file-control operation calls `fstat` inside the owning Unix VFS on the
actual main-database descriptor; it neither reopens a pathname nor exposes or
closes that descriptor. Bound Store opens compare this device/inode pair with
the retained authority immediately after native connect, before any key, pragma
or schema access, and again before writer configuration, `BEGIN` and commit.
Missing, malformed, busy or unsupported identity reporting fails closed. A
replacement present only during native open cannot pass by restoring the named
leaf before a later pathname check. SQLite owns the idle pin connection so its
lifecycle does not inadvertently release another connection's POSIX locks.
Error classification reads at most the sixteen-byte SQLite header in a bounded
isolated child, returning only an exit status; it never opens and closes a raw
main-database descriptor in the parent process.
Existing-only connections use `mode=rw`/`mode=ro` and never recreate a missing
Store database.

Every connection validates the exact installed companion distribution,
normalized `cipher_status=1`, minimum engine versions, OpenSSL provider, and
the required FTS/RTREE/STAT4/URI/limit compile profile immediately after key
and cipher configuration. Missing, stale, plain-SQLite, or under-featured
engines fail closed before schema or Store content access. The extension is
self-contained and `otool`-gated to macOS `libSystem`; the release artifact is
the Memory wheel plus its committed companion because an unhosted relative
dependency cannot be discovered from a lone Memory wheel.

Source bytes live directly in SQLCipher BLOBs. The limit is 64 MiB per file
and 256 MiB or 64 files per inbox batch; oversize input stays in the inbox and
returns a typed content-free error.

### 4.5 Owner-authenticated plaintext export

`memory export --output PATH` (optional `--home PATH`) writes one UTF-8 JSON
file in format `memory.export.v1`. It includes **all** retained sensitivity
levels (`normal`, `sensitive`, `restricted`) with no filters: current and
superseded memories, source originals, evidence and capture provenance, every
review revision and active/rejected item, no-memory decisions, approvals,
applications, and both active and permanently revoked guard relationships.
The [export format](export-format.md) owns the complete field/table inventory.
This is plaintext intended for machine and LLM consumption; it has no password,
encryption wrapper, import/restore operation, or key export. Captured binary
bytes are lossless base64; captured UTF-8 text is directly readable. Search
projections, transient scan scheduling, uncaptured Inbox files, filesystem
recovery/staging artifacts, runtime configuration and keys are explicit exclusions.

Each invocation pins the runtime identity leaf and no-follow directory chains,
uses the normal native-inode-attested read-only SQLCipher authority, and starts
one explicit read transaction. Its first read fixes the snapshot generation;
all table shapes, counts, records and blobs come from that same snapshot, even
if another writer subsequently commits. Reads never heal legacy schemas or
rebuild search projections. Legacy absent guard tables and older column shapes
remain explicit; unknown ordinary tables fail rather than silently omitting data.

Before creating any plaintext file, a fresh macOS device-owner authentication
must succeed. Its opaque receipt binds the full-scope action, Store/snapshot,
runtime/database/output identities, destination, nonce and monotonic deadline.
Export receipts cannot mint canonical-memory approval. Cancellation, failure,
unavailability, timeout or a foreign/stale receipt stops without retry or output.
No typed input, pipes, PTYs, model argument or prior Review approval substitutes
for OS presence. The system reason names ALL sensitive/restricted history and
sources, plaintext JSON and the chosen destination. The read snapshot may precede
the authentication; this is content export authorization, not a Memory Review.

The destination parent must already exist, be owner-owned and mode 0700, outside
the Store and Inbox/custody trees, with no symlink ancestors or extended ACL
entries. Verify ACL absence on held output directory and file descriptors before
the first plaintext byte and again before publication; POSIX modes alone cannot
exclude inherited macOS grants. Existing targets of
any kind refuse. Hold/revalidate directory, identity-leaf and native database
identities, permissions and identity bytes across authentication and streaming.
Stream to a fresh private mode-0600 file only after authentication. Flush/fsync,
then publish using the macOS inode-bound file reference and exclusive same-directory
move; preserve a competing destination. Verify final identity/privacy and fsync
its parent before acknowledging. Failure cleanup follows only this operation's
file reference; cleanup uncertainty fails and retains the private artifact for
recovery. Process death can retain a private partial temporary, never a partial
final file. No source content goes to stdout/stderr; success returns only format,
destination and row counts. MCP and browser record-export surfaces remain absent.

## 5. Sources and inbox

### 5.1 Blob identity versus capture identity

`SourceBlob` owns deduplicated bytes:

```text
blob_id, sha256, byte_length, original_bytes, utf8_text
```

`Source` owns one capture's metadata:

```text
source_id, blob_id, batch_id, origin, original_name, media_type,
authorship, sensitivity, captured_at
```

`origin` is the Store-assigned custody path, either `inbox` for a scanned
capture or `owner_correction` for an owner correction captured in the local
owner UI.

Equal bytes reuse one blob but receive distinct source records when captured
in different batches. Each capture keeps its declared sensitivity; retrieval
also reports the effective blob sensitivity as the maximum across its
captures. Provenance never collapses and deduplication can never lower
sensitivity.

The scan request supplies batch-level authorship and sensitivity. The Python
kernel's own defaults are `owner` and `restricted` for its explicit callers;
every actual scan door states or defaults its own honest value — the MCP
tool defaults authorship to `unknown`, and the staged-intake companion
always passes `mixed`. Media type comes from a fixed extension allowlist
for UTF-8 text/Markdown/JSON/CSV, PDF, PNG, JPEG, and WebP; unknown types
become `application/octet-stream`. There is no content sniffing, and the
original filename remains capture metadata.

UTF-8 and Markdown blobs receive deterministic searchable text. Every other
media type remains binary-readable and is counted as `unsearchable`; the Store
does not pretend it was searched.

### 5.2 Batch scanning

`inbox.scan` sorts the settled non-symlink regular files visible in one pass,
reports and skips individually ineligible files, and claims the largest
deterministic set of eligible files that fits the batch limits into one stable
random batch. Remaining eligible files stay for the next scan. An oversize
file therefore never blocks later valid files. A file is settled when size and
mtime remain unchanged across the configured five-second window. Claim
recovery reuses the batch ID after a crash.

Scans retain a separate nonblocking scanner lease while they observe a fixed
candidate cohort. Directory discovery, the settling interval, and candidate
hashing run outside the Store writer lock through retained directory authority.
The writer section revalidates the observed file identities, metadata and
content identity, retains the existing post-claim checks, and publishes the
batch atomically. Replacement, append, removal or authority drift never turns
an observation into permission to capture different bytes. Unrelated writers
can proceed during observation; competing scans may receive `busy`.

Scheduling progress is encrypted Store metadata, distinct from source custody.
An immutable sorted cohort is staged in bounded transactions before its active
pointer is published. Each scheduler transaction handles at most 64 names and
16 KiB of filename bytes, releasing the writer between chunks. Inactive cohorts
left by process death are reclaimed in bounded transactions under the scanner
lease. The active cohort records attempted names durably, including candidates
that change after observation; a failed leading prefix cannot reset progress on
restart. New names and renamed files join the next cohort, while missing names
consume their old scheduling slots. Deferred eligible entries remain discoverable
and custody accounting continues to be authoritative. Scheduler writes advance
the ordinary audit generation, so generation-bound cursors can stale even when
no source batch is captured. No source bytes are stored in the scheduler.
For a fixed cohort of N names, each completed non-busy scan retires at least
one scheduling slot, so every member is considered within at most N such scans.
When candidate sizes fit and changes occur only during candidate hashing, the
64-attempt default gives a bound of ceil(N/64) scans. A file eligible and stable
through claim is captured when considered, absent a separate custody or database
failure. Restoration collisions or other recoverable custody failures remain
explicit blockers, not successful scans. Discovery and retained cohort metadata
can scale with N outside the writer lock; each metadata write and each source
batch retains its separate fixed bounds.

Hidden entries whose names begin with a dot — Finder metadata such as
`.DS_Store`, cloud-sync placeholders, and similar OS noise — are silently
ignored by scanning, staged-entry listing, and staged counting, and never
enter custody. Staged uploads may not use hidden names.

The scanner reads through non-following descriptors, rejects path escape,
enforces file/batch limits, inserts blobs, source captures, membership, and
FTS in one transaction, then removes the claimed originals. Failure restores
the claim or leaves it recoverable; no partial batch is readable.

Owner UI uploads stage only beneath the private `inbox-staging/` sibling,
through the exclusive no-follow custody path. A paused, failed, or aborted
upload can leave only an unscannable private artifact; only the complete
published Inbox entry is scan-visible. Inbox scanning reads only the resolved
inbox directory.

Ordinary and exact publishers lease their private payload inode while bytes or
publication state are in flight. The integrated ordinary path
`stage_inbox_entry` retains the original descriptor and lease through
publication. The standalone `stage_private_entry` deliberately returns a
nonempty unlocked staged entry, which remains recovery debt until a caller
publishes it; standalone `publish_staged_inbox_entry` reacquires an
identity-bound lease and retains it through publication cleanup. Recovery
identity-binds the same inode and tries the same nonblocking lease before it
inspects, promotes, rolls back, reclaims, or reports the entry. Contention
means the publisher is live: a bare exact payload before its first intent, a
partially written new-format intent temporary, and an ordinary streaming
payload produce no recovery issue or mutation.

Rollback-slot provenance (`memory.publication-rollback-slot.v2`) binds each
bundle member by name, inode, uid, mode, and file type under a MAC keyed from
the Store master key. It deliberately persists no device number: the kernel
reassigns `st_dev` at every boot, so the v1 format's persisted device
invalidated every stored slot on reboot and burned one entry of the bounded
publication budget per reboot until publication was refused outright. The
device axis is instead a runtime invariant -- every member, and every payload
checked against a persisted recovery-manifest identity, must live on the
staging directory's current device -- which preserves the cross-volume
substitution defense within any one boot. Legacy v1 records still
authenticate and are retired on sight at slot acquisition: a provably idle
bundle is removed member by member under held exclusive locks with the record
unlinked last (absent members tolerated, so a crash mid-retire re-runs), and
a bundle retaining recovery bytes loses only its record through the
durable-manifest proof while its members stay visible as owner recovery
debt. The recovery manifest's own persisted identity keeps its written shape;
only the reader ignores the recorded device in favor of the same staging
invariant. The exact intent and ready manifests' `payload_device` and the
claim manifest's per-entry `device` follow the identical rule: writers still
record the boot's device, and every reader binds the persisted inode on the
containing directory's current device, so crash-left intents, complete ready
corrections, and published claims recover identically before and after a
reboot.

A fully authenticated busy rollback bundle is live only after every recorded
payload, manifest, and withdrawal member is rebound as one group. Idle
descriptor leases remain held through the whole artifact issue inspection so
a publisher cannot reuse the authenticated bundle between discovery and
classification; an unlocked nonempty or otherwise retained bundle remains
recovery debt. Operational inspection I/O propagates from that bound group
rather than becoming custody debt. Only `BlockingIOError`, `EACCES`, and
`EAGAIN` are treated as contention. A non-contention open or `flock` failure
propagates out of recovery and aborts CLI or UI startup without mutation; it is
never swallowed or reclassified as malformed custody.

Public exact recovery and owner-UI startup enter one retained inspection
session before the first exact-capture mutation. That session loads the
validated Store identity once, pins the runtime directory authority,
authenticates and binds rollback-bundle members before recovery preparation can
rewrite staging, then performs deterministic intent/ready normalization,
owner-correction handoff replay, and orphan reclamation. Handoff replay keeps
the durability promise the correction UI makes when it preserves an
irreducibly ambiguous submission and drops its retained copy: each pair whose
payload verifies against its manifest and whose envelope this Store authored
— the manifest supplies the reservation identity and digest, the payload's
own `memory.owner-correction.v1` envelope supplies the lineage, expected
head, and capture time, and the fixed owner-correction policy supplies the
rest, proven by re-rendering the exact envelope — is restaged through the
same intent machinery as the original submission and captured into the
correction's own reserved batch, idempotently against a capture that already
committed. The pair is removed payload-first only once the correction is
provably safe; a pair that cannot be proven, a foreign envelope, or bytes
that no longer match their manifest stay in place as reported custody debt.
Handoff discovery never opens a member a recorded rollback bundle owns. It snapshots intent, ready, claim, and active-claim issue
state exactly once after that normalization and before the first exact-capture
commit. Idle bundle descriptors and the runtime authority remain live through
exact capture and final issue classification. The final issue page is assembled
only from the retained Store ID, bound artifact inspection, normalized-state
snapshot, and in-memory capture receipts; it does not rescan recovery state,
reopen or re-`flock` bundles, or reload runtime identity after a commit. This
makes the CLI result and the UI startup decision two adapters over one retained
fail-before-capture orchestration, rather than a recovery call followed by a
second fallible inspection. A bundle inspection failure still precedes and
therefore changes none of the recovery staging state. Residual cleanup debt
created after the snapshot belongs to the next recovery invocation and cannot
replace or erase a receipt already produced by this one.

An owner correction written in the local owner UI never enters the visible
Inbox queue. The Store stages it through the same private custody path and
then seals exactly one isolated one-source batch for it under the normal
writer boundary, recording `origin=owner_correction`, `authorship=owner`, and
`sensitivity=restricted`. It is never co-batched with visible Inbox files, and
it creates no change set and no canonical memory; the agent reviews that
already sealed batch through the ordinary Memory Review workflow.

A successful mixed scan returns the captured batch plus content-free
`issues[{code, count}]` and `has_more`; these warnings are not errors. If no
eligible file can be captured, the call returns one typed error. Reaching the
batch cap sets `has_more=true` and leaves the remainder for the next scan.

### 5.3 Retrieval

- `source.list(cursor, limit)` uses simple high-water-mark keyset pagination.
- `source.search(query, cursor, limit)` searches all captured UTF-8/Markdown
  text and returns searchable/unsearchable counts.
- `source.read(source_id, cursor, max_bytes)` returns bounded inert text or
  MCP embedded-resource bytes plus media type, opaque continuation, and full
  blob digest. Text chunks end only at UTF-8 code-point boundaries and include
  their canonical `char_start` and `char_end`; binary content uses byte
  coordinates.

Both `source_fts` and `memory_fts` tokenize with `porter unicode61`, so a
query stems before it matches (`love` reaches `loving`). `source.search` and
`memory.search` (6) answer every query with the same deterministic
three-rung ladder: **phrase** (the exact, case-folded phrase) → **all-terms**
(stemmed-FTS AND, the prior behavior) → **any-term** (stemmed-FTS OR). Each
rung combines a stemmed-FTS pass with a literal case-folded substring pass
over the same haystack; a hit keeps the strongest rung either pass reaches,
and every hit reports that rung as `match_strength`. The source haystack is
the retained text plus the capture's `original_name`, and the memory haystack
is the statement plus its tags, so a filename is searchable by both passes
rather than only the stemmed one — `unicode61` keeps one Han run as a single
token, so a literal pass blind to the filename would leave a Chinese filename
reachable only by its whole run.

The substring pass's phrase rung requires the match to sit at a token boundary
on both sides — a mid-word occurrence (`art` inside `smart`) can still satisfy
a lower rung but never earns the phrase label. Han, Hiragana, Katakana
(including standard halfwidth U+FF66–U+FF9F), and Hangul (including standard
halfwidth U+FFA0–U+FFDC) runs are exempt from that requirement, because a
script that does not space its words has no boundary to find and the rule
would otherwise cap every CJK hit at all-terms forever; an exact CJK phrase
therefore earns the phrase label.

Two rules keep the literal pass from overstating a fragment. A Latin term
shorter than three characters admits nothing at the term rungs — below that
length a fragment is not evidence of a match, and the stemmed pass still
answers a genuine short token. The phrase rung carries no length gate and
needs none: it already requires a token boundary on both sides, which is the
stronger condition and the one the length rule approximates. `ai` inside
"chair" and "repair" therefore admits nothing, while `ai` standing as its own
word earns the phrase label like any other exact phrase. And a term found only
inside a longer word caps the hit at any-term rather than all-terms: `art`
occurs in "party", clears the length rule, and is not an all-terms match. Recall is unchanged by the second rule;
only the reported strength moves, onto the rung the Skill already treats as a
lead to verify.

Within a rung, the rank is the negative sum of the count of distinct admitted
literal query terms present and one bonus when the complete phrase occurs at a
valid token boundary. A term qualifies under the same minimum-length/unspaced-script rules
as literal admission. Repeated document occurrences and duplicate query terms
never multiply that score. The capture/head rowid breaks ties deterministically.
This makes broader partial-query coverage outrank repetition of one fragment;
it does not supply semantic similarity or resolve irrelevant exact phrases.
Stemmed-only matches can have rank zero. Rank remains finite and integer-valued.

`LADDER_VERSION = 7` marks this ordering change. Both kernel query bindings and
composition digests, and both owner query bindings, include the version. A search
cursor minted under version 6 fails closed; the caller restarts the search.
List/read cursors, stored sources, historical approval digests and FTS projections
are unchanged; the queryless owner-memory list preserves its exact prior binding,
including `ladder: 6`. No data migration or reindex is required. MCP field shapes stay
the same; updating the rank's schema description moves the contract digest and
the Skill's matching stamp.

An MCP `memory.search` or `source.search` page's cursor binds a SHA-256
snapshot digest computed over the ladder's exact entry composition for that
query and filter set, never over projection identity or audit generation —
but the two compositions differ. A `memory.search` entry is `[strength, rank,
rowid, revision_id, sensitivity_rank]`, so a later capture that raises an
evidence source's effective sensitivity changes that entry and stales the
cursor. A `source.search` entry is `[strength, rank, rowid, source_id]`;
sensitivity plays no part in it, because kernel source search carries no
sensitivity filter to begin with, so a sensitivity change can never alter a
source-search composition. Rebuilding the projections with `memory reindex`
therefore does not, by itself, stale either MCP cursor: an idempotent
rebuild reproduces the identical composition and the walk continues; only a
membership, order, rung, or (for `memory.search` only) sensitivity change
between pages changes the digest and stales the cursor. This scoping is
MCP-only — the owner UI's own list and search cursors bind `audit_generation`
directly instead, and every reindex advances it, staling every one of them
(owner-guide.md §13). A cursor minted before the ladder existed carries no
snapshot at all and is rejected outright as stale rather than reinterpreted.

The literal side compiles one exact matcher per query. Queries with at most
48 folded phrase characters and eight unique terms use a bounded native scan:
at most 42 C-level count/search passes, each needle at most 48 characters,
with no Python work per source coordinate. Escaped literal regular expressions
use only fixed-width boundary assertions and the same wordish/unspaced-script
rules as the automaton; they contain no variable repetition. Non-overlapping
counts and boundary searches can find overlapping evidence without a Python
find-walk; rank uses distinct presence rather than those occurrence counts.
Phrase, term, and prefix priority remain exactly the same. Native and automaton
paths share the version-7 rank and unchanged excerpt semantics. Every page still
validates its exact composition afresh;
no retained-content cache or projection shortcut replaces that validation.

Larger queries use the existing multi-pattern automaton. It partitions unique
terms into fixed blocks of 64 terms, and both ordinary and
boundary Aho-Corasick outputs are sparse block/local masks. At each coordinate,
packed arithmetic touches only blocks with output or live cooldown state. The
per-haystack exact scan collects distinct admitted term presence,
bounded presence, first bounded phrase coordinate, and
the priority needed for a bounded term or prefix excerpt anchor. The visible
source excerpt path reuses that compiled exact scan over the authoritative
text; it does not loop over every term or repeat phrase searches at each
candidate coordinate. Boundary-qualified term matching transforms start, end,
and every structural character boundary into one private marker token and
advances one deterministic Aho-Corasick state. The marker is a private object
rather than a stored or query character, so NUL and every Unicode scalar
remain noncolliding. Exact Python case-fold, Latin/CJK boundaries, rung
membership, phrase coordinates and excerpt semantics agree between both
implementations. Standard halfwidth Katakana and Hangul remain in the
unspaced-script roster introduced under `LADDER_VERSION = 6`.

Both kernel and owner source ladders iterate the corpus cursor one row at a
time, retaining only compact match entries for ordering and the snapshot. They
also stream the selected visible-page rows into ranked result objects one at a
time instead of calling `fetchall()` on a page of authoritative plaintext.
The owner and kernel paths share the same compiled matcher and visible-row
assembly, so this bounded shape is part of their parity rather than a mirrored
optimization.

Owner memory search derives its filtered and unfiltered banner counts from one
corpus pass. Each current head is matched once; filters determine whether a
query match joins the visible composition. Ordering and match strength retain
kernel parity; each path's existing cursor bindings remain unchanged.

Owner source metadata uses a separate bounded summary selector. Ordinary
source list, blob-capture list, source detail, batch detail, and audit reads do
not project `source_blobs.utf8_text` into Python; text presence is derived in
SQLite with `typeof(...) != 'null'`, and projection-fidelity checks likewise
remain inside SQLite. Owner search still streams authoritative corpus and
visible-row text; its owner-specific text-bearing summary wrapper is used only
for those visible excerpts. Thus a small metadata page cannot materialize a
page of complete retained source bodies merely to discard them.

Canonical `source_fts` membership is bound to authoritative custody:
the authoritative capture must have a media type in the fixed searchable
allowlist and non-NULL retained UTF-8 text; `source_fts.rowid`, its unindexed
`capture_rowid` format marker, and `source_fts.source_id` must then all identify
that same `sources` row, while its `utf8_text` and `original_name` must equal
the authoritative values in `source_blobs` and `sources`. A projection without
the marker keeps its legacy source-ID search and capture behavior and reports
`reindex_required` until `memory reindex` installs the rowid-bound shape. This
preserves pre-reindex Stores whose FTS rowids may already diverge across binary
captures rather than partially applying the new invariant.

On the canonical shape, `source.search` uses only that exact row for MATCH and
reads literal-pass text, filenames, visible details, and excerpts from
authoritative custody. Every noncanonical duplicate is corruption and is
ignored by ranking: it cannot promote, hide, fabricate, or restate a hit.
Coordinate-valid text or filename drift makes the capture unsearchable on
every flag, filter, status, coverage, owner, and kernel surface. So does an
otherwise exact row injected for a binary capture whose bytes happen to be
valid UTF-8: media type, not decodability alone, governs search eligibility.
Search itself never reports projection corruption; the owner-facing Sources &
Audit coverage counts that binary capture as inherently unsearchable and its
injected row as unexpected, while drifted text captures report one missing
canonical row plus one unexpected row (10.4). This fidelity correction
advances `LADDER_VERSION` from 3 to 4 so older kernel and owner cursors fail
closed.

`store.status` computes `reindex_required` fresh from live schema on every
call rather than from a persisted flag. **Any noncanonical `source_fts` or
`memory_fts` projection DDL requires explicit `memory reindex`**: this includes
the `porter unicode61` tokenizer and, specifically for `source_fts`, the
canonical authoritative `rowid`, `capture_rowid`, and `original_name` shape.
`memory reindex` drops and repopulates both FTS5 tables from canonical
`source_blobs.utf8_text` and every current `memory_revisions` row in one writer
transaction, advancing `audit_generation` once under the same rule as any
other projection-changing commit (4.3).

Guard auxiliary tables and their additive columns are different compatibility
objects. They heal at the start of every writer session (`CREATE TABLE IF NOT
EXISTS` plus the guarded additive column repair), so an ordinary apply or exact
replay can commit that maintenance and advance `audit_generation`. That heal
does not make a noncanonical FTS projection canonical and never replaces the
explicit reindex requirement.

Both owner-UI searches answer through this same ladder. They did not in
earlier releases — source search issued one all-terms expression and memory
search compared case-folded substrings with no FTS at all — which meant a
query the connected agent could answer returned nothing in the owner's own
browser, most visibly for a mid-run CJK query that only the literal pass
reaches. The two readers are now the same computation, and a parity test
asserts identical hit sets across a fixed English and Chinese corpus. What
stays different is pagination, deliberately: an owner cursor binds its filter
set and `audit_generation` rather than a ladder snapshot, so every reindex
stales it (owner-guide.md §13), and `LADDER_VERSION` is folded into that
binding so a cursor minted against an older rung ordering fails closed rather
than resuming into a different one. The owner view models still expose no
`match_strength`.

Page sizes are 1–500 entries with a default of 50. For MCP `memory.search`,
that item limit is also subject to an 8 MiB MCP `CallToolResult` body ceiling
because every hit occurs once in `structuredContent` and again as escaped JSON
in the text content arm. A fixed 64 KiB reserve covers Store/result-dependent
fixed envelope, coverage, opaque-cursor, and result-key overhead. This is not a
whole JSON-RPC or stdio-message bound: client-supplied JSON-RPC request-ID bytes
are echoed outside the `CallToolResult` body and are excluded, with no new
transport ID bound. The adapter gives the kernel an exact additive hit cost:
compact structured-hit UTF-8 plus its escaped JSON-string fragment, and, after
the first hit, one array comma in each arm.
The kernel loads guard attachments for one considered lineage at a time and
stops before the first later hit that would cross the budget; it never
serializes the growing page to price each candidate. Pricing may materialize
the one excluded candidate's guards, because their exact bytes decide the
stop, but never any later candidate's. The first hit always emits even when
its bounded 256-guard roster exceeds the ordinary budget, so the page can
advance instead of returning an unresumable empty result. The cursor remains
anchored to the last emitted hit, making an excluded hit first on the next
page. This progress exception is per page and can recur if that excluded hit
is itself oversized. This byte stop changes neither the ordered snapshot nor
the owner UI's separate page behavior.

Direct read chunks are at most 4 MiB with a 256 KiB default -- 4 rather than 8
because a binary chunk rides the wire as base64 in an embedded resource, so
4 MiB of source is roughly 5.6 MiB of JSON in one stdio message. That is a
source-byte bound: the storage reader selects only bounded metadata plus the
source BLOB rowid, then uses SQLCipher's read-only incremental BLOB API to
seek and read fixed windows. It never selects the complete `original_bytes`
and duplicate `utf8_text` values per page. Its text-presence projection uses
SQLite's `typeof`-argument optimization, so even that metadata boolean inspects
only the record type instead of materializing an overflow TEXT value. For a
searchable capture it opens both columns incrementally, requires their full
UTF-8 byte lengths to match, and compares each pair of streamed windows before
strictly decoding the authoritative byte BLOB. Thus a complete walk retains
the old byte/text fidelity check with linear 2N work rather than repeating two
whole values on every page. Text decoding retains only the emitted page.

An MCP text `source.read` page has a second, adapter-only stop. Its retained
text appears once in `structuredContent` and again inside the escaped compact
JSON text arm, so the adapter charges every character's exact contribution to
both copies and stops at the largest UTF-8 prefix fitting an 8 MiB
`CallToolResult` body ceiling with a fixed 64 KiB reserve for the result,
Store, coordinates, and opaque cursor. The cursor advances to the last byte
actually emitted, never the end of the raw window. One code point always fits
the reserve, so a nonempty remainder cannot produce an empty progress page.
Binary pages retain the raw 4 MiB behavior.

Read cursors bind source, blob digest, byte length, and next byte coordinate.
New text cursors also carry a validated cumulative character coordinate, so a
continuation does not rescan its prefix. A cursor minted before that optional
coordinate existed remains valid: the first resumed read reconstructs the
count by streaming the prefix once in fixed memory, then returns a new-form
cursor. Both forms validate Store/operation/source binding, integer bounds,
length, and UTF-8 boundary before they resume.

A change-set revision and one edit call each contain at most 256 items, with
at most 16 evidence locators per item and a 4 MiB canonical diff limit.
Measured as UTF-8 bytes, statements are at most 16 KiB, evidence excerpts
4 KiB, `no_memory` reasons 4 KiB, each of at most 64 tags 256 bytes, and
search-result excerpts 1 KiB. Search queries are at most 16 KiB. Empty
required strings, NUL, invalid enums, and values beyond these bounds fail as
`invalid_argument`.

Exhausting `source.list` and `source.read` must reproduce every retained
capture. The trusted owner profile includes normal, sensitive, and restricted
captures.

## 6. Canonical memory

```text
MemoryRevision
  id, lineage_id, predecessor_id
  kind                    fact | event | preference | relation | insight
  statement
  occurred_on             optional validated YYYY | YYYY-MM | YYYY-MM-DD
  valid_from / valid_to   optional validated partial dates
  recorded_at
  tags                    ordered normalized strings
  sensitivity
  application_id
```

Personal open items use the existing `loop:open` tag. Their `valid_to` is a
revisit horizon, not expiry; passing it neither closes nor invalidates the
commitment. A recurring intention retains its cadence in statement text, with
the next supported horizon in `valid_to` when known. No read, time passage or
conversation advances that horizon or completes a cycle. Membership, outcomes
and horizon changes remain source-backed exact owner-approved corrections.
When only part of a grouped item changes, an ordinary correction updates only
the affected statement portion, preserves other commitments/dates, and retains
`loop:open` while any follow-up remains. A shared horizon stays unset unless
evidence supports one for the remaining item. Whole-loop closure and re-horizon
statement-preservation rules do not apply to a partial change.

Every revision has at least one `MemoryEvidence` row binding source ID, blob
SHA-256, and either an exact UTF-8 character span/excerpt or explicit
source-level binary evidence. Statement text and evidence excerpt are
separate. Revision sensitivity cannot be lower than the highest effective
sensitivity of its evidence at apply time. Read and search also return a
derived effective memory sensitivity equal to the maximum of the stored value
and current effective sensitivities of all evidence sources. A later
restricted duplicate therefore raises retrieval metadata without mutating an
accepted revision. `memory_fts` stores only rebuildable current-head text.
Sensitivity filters join through memory evidence to the current per-blob
maximum at query time, so a metadata increase needs no FTS or revision
rewrite.

Only `current_memory_heads` are searchable. Search applies the three-rung
ladder described in 5.3 plus kind, tags, date, and sensitivity filters, and
reports each hit's `match_strength`. A correction creates a new revision and
compares against the expected head; accepted text is never updated in place.
A hit and a historical-or-current `memory.get` detail may also carry guard
attachments; see Guard links (8).

Canonical `memory_fts` membership is exact to authoritative storage: the same
projection row that satisfies MATCH must carry the current revision ID, its
exact statement, and the canonical space-joined sequence of its JSON tags.
Public search coverage and the owner projection audit use that same predicate.
Those two count surfaces materialize exact projection IDs once from an
FTS-outer scan: `memory_fts.revision_id` is UNINDEXED, so correlating one scan
per current head would make every search page and owner audit quadratic. A
drifted row, divergent duplicate, orphan, or historical row cannot fabricate,
promote, or restate a hit. When no exact row remains, coverage reports that
current head as unsearchable; an exact duplicate still collapses to one search
hit but remains unexpected audit debt. Canonical memory storage is always what
search returns and `memory.get` reads. This malformed-projection fidelity
correction advances `LADDER_VERSION` from 4 to 5, so every kernel source/memory
and owner source/memory cursor minted under the old rung and snapshot
assumptions fails closed while a healthy Store's results stay unchanged.

Every `memory_id` is a revision ID. Search returns current revision IDs plus
their lineage IDs. `memory.get(memory_id)` accepts either a current or
historical revision ID and returns that exact revision, its evidence and
predecessor, an `is_current` flag, and the lineage's current head ID. A
correction supplies the returned lineage ID and current head ID as its target
and expectation.

MCP detail retrieval has an 8 MiB UTF-8 encoded `CallToolResult` body ceiling
and a 256-record page-work limit. The byte ceiling includes both structured
content and its escaped JSON text copy, all envelope fields and continuation
metadata; it excludes the outer JSON-RPC message and caller-supplied request ID.
There is no oversized-first-item exception. Complete small responses preserve
the existing single-detail object or ordered bulk array. Larger selections,
including one large detail, use explicitly tagged detail fragments and an
opaque continuation; fragments are never presented as complete details.

Every supported selector remains available: exact current or historical
revision ID, current lineage ID, or an ordered list of at most 50 revision IDs.
Pagination preserves the full selected revision, evidence, ordered history,
guards and governed-memory rosters. A caller follows the same selection and
returned cursor until completion and reconstructs the records without loss or
duplication before treating a detail as complete. The continuation binds the
Store, exact selection and mode, audit generation, and next detail/section/keyset
coordinate. Any intervening Store write conservatively stales the walk; restart
the same selection. A lineage selector cannot silently switch heads mid-walk.

The MCP detail loader emits at most 256 records and prices at most one further
bounded record before stopping. It reserves 64 KiB for fixed envelope and cursor
overhead and verifies the actual SDK-encoded result before returning it. It uses
keyset pages rather than materializing a whole history or relationship roster
to decide whether it fits. Existing kernel/CLI full-detail calls are unchanged;
effective-sensitivity computation still aggregates the related evidence and
capture metadata needed to report the current floor. Additive
history and active-relationship indexes are created for fresh Stores and healed
transactionally at the next writer operation for legacy Stores. Reads never
mutate schema; before that heal they still bound Python materialization, but
SQLite may scan/sort more rows. Historical approval digests and persisted
revision/evidence bytes are unchanged.

## 7. Memory Review

### 7.1 Draft and review

One sealed inbox batch has at most one `ChangeSet` total. Repeating
`change_set.create` returns that same set regardless of state; a batch can
have at most one application. `change_set.edit` creates immutable draft
revisions from bounded operations:

```text
add_item(client_item_id, memory_fields, evidence[])
replace_item(item_id, memory_fields, evidence[])
reject_item(item_id)
restore_item(item_id)
set_source_no_memory(source_id, reason)
clear_source_no_memory(source_id)
add_guard_link(guard: item | lineage, governed: item | lineage)
remove_guard_link(guard: item | lineage, governed: item | lineage)
revoke_guard_link(guard: item | lineage, governed: item | lineage)
```

`add_guard_link`, `remove_guard_link`, and `revoke_guard_link` are detailed
in Guard links (8);
`change_set.create` itself takes only a `batch_id` and carries no edit.

Every created or edited revision stores one immutable Store-assigned
`adapter_origin`: `mcp`, `owner_ui`, `cli`, or `system`. The public MCP schema
does not accept this field; each trusted adapter supplies its own fixed enum
value below argument validation. Idempotent create returns the already-stored
origin, and an edit records the adapter that created the new revision. Unknown
stored values fail closed. This provenance is returned for audit but is not
part of the approval digest.

Client-writable `memory_fields` are exactly `kind`, `statement`,
`occurred_on?`, `valid_from?`, `valid_to?`, ordered `tags`, `sensitivity`,
`target_lineage_id?`, and `expected_head_id?`. Both target fields are null for
a new lineage and both are required for a correction. `replace_item` replaces
a draft item, not an accepted revision. The Store assigns lineage/revision
IDs, `recorded_at`, predecessor, and application ID only during apply.

The owner item editor loads the complete selected proposal from the displayed
immutable revision, including its correction target and expected head, all
64 ordered tags and all 16 text or source-level binary evidence locators.
Selecting another item performs a fresh bounded read and never retargets
values already entered for another item; retained refusal values remain
scoped to their original item. Unchanged statement, tag and excerpt bytes
survive HTML line-ending normalization, while intentional edits and cleared
ordered slots are submitted normally. A wording-only replacement preserves
every other field and locator. Hidden targets, choices, bulk selections, and
guard endpoints preserve opaque draft-item IDs exactly, including distinct
CRLF and LF spellings, without submitting unchecked controls or collapsing
repeated names. Guard draft-item choices use the revision roster and retain
unknown refused endpoints for inspection and retry. Reference validation uses
the Store's 256-character UTF-8 contract; request and retention byte ceilings
still apply. Empty drafts offer adding an item rather than an unbound
replacement. Revision/digest conflict handling and exact approval
remain unchanged. These are owner-form changes only; the persisted review,
digest payload, and MCP contract retain their existing formats.

Proposed text evidence names `source_id`, blob digest, and an exact excerpt.
The server requires that excerpt to occur exactly once, resolves its canonical
`char_start` and `char_end`, and returns those coordinates in the draft. A
repeated excerpt fails as `ambiguous_evidence` until the agent supplies a
longer unique excerpt. Binary evidence names `source_id`, blob digest, and
explicit `source_level=true`. The server resolves and rechecks every locator.

Each revision retains rejected items for the diff. Every batch source has one
coverage state: `used` when one or more active proposed items reference it, or
an explicit `no_memory` decision with a reason. A source may support multiple
items but cannot be both `used` and `no_memory`. A revision with missing or
contradictory source accounting is not approvable.

At most one active item in a draft may target the same existing memory
lineage. Two proposed successors for one expected head are rejected before
approval, so application order can never choose a winner.

`change_set.get` returns the complete current diff and a canonical digest over
the batch, every source decision, every active/rejected item, all memory
fields, evidence, expected heads, ordinals, and every active/rejected guard
link.

The owner UI projects two bounded views over that same immutable revision. Its
compact roster collapses whitespace and clips each proposed statement to 160
Unicode characters, marks clipping explicitly for assistive text, and gives
every row a direct route to the exact item comparison rather than requiring a
pagination walk. The comparison retains both complete statements and all
source-evidence links. It highlights a deterministic token diff for small
statements and uses a lossless common-prefix/suffix comparison above a fixed
512-token work bound; both paths escape stored text. Dates, tags, stored
sensitivity, and draft guard additions or revocations receive textual change
states. A comparison shows at most 12 relevant guard changes and points back
to the complete revision roster when more exist, preserving the fixed
three-item and 4 MiB response budgets. These projections never enter the
digest payload. The compact guard roster applies the same 160-character
statement bound to both endpoints and links each endpoint to its exact draft
comparison or current canonical head; the full statements remain in those
details and in the complete final approval rendering. Item identifiers ride
as encoded query values rather than path segments because they are opaque
client identifiers and may contain URL syntax.

The digest payload has format `memory.change-set-digest.v1`. Every optional
field is present with explicit `null`; integers and booleans use JSON
primitives; strings are encoded exactly as stored with no Unicode
normalization; object keys are sorted; arrays preserve their declared ordinal;
and UTF-8 JSON uses compact separators. Approval binds the lowercase SHA-256
hex digest of those bytes.

```text
DigestPayload
  format, store_id, change_set_id, batch_id, revision_id
  source_decisions[]
    ordinal, source_id, blob_digest, state = used | no_memory, reason?
  items[]
    ordinal, item_id, status = active | rejected
    target_lineage_id?, expected_head_id?
    memory
      kind, statement, occurred_on?, valid_from?, valid_to?,
      tags[], sensitivity
    evidence[]
      ordinal, source_id, blob_digest, mode = text | source_level
      char_start?, char_end?, excerpt?, source_level?
  guard_links[]?
    ordinal, guard_item_id?, guard_lineage_id?,
    governed_item_id?, governed_lineage_id?
  revoked_guard_links[]?
    ordinal, guard_item_id?, guard_lineage_id?,
    governed_item_id?, governed_lineage_id?
```

Source decisions, items, evidence, tags, and guard links use their stored
ordinals. The payload contains no adapter origin, digest, application ID,
`recorded_at`, or other value minted after approval. `change_set.get`, MCP
elicitation, and the CLI render this exact payload plus its digest.
`guard_links` itself is present only when the revision carries at least one
link — see Guard links (8) for why that key is conditional rather than an
always-present, possibly empty, array.

### 7.2 One approval and apply

The state machine is deliberately small:

```text
draft -> applied
```

`change_set.approve_and_apply(change_set_id, revision_id, digest)` rechecks
the exact draft and obtains a direct owner decision. Trusted MCP elicitation
is one authorized adapter and shows the full diff/digest outside model
arguments — and it is available only when the owner starts the server with
`memory mcp --trust-elicitation`, an opt-in the printed configuration entry
carries visibly. Without trusted elicitation — the default, and any client
that does not declare the capability — the tool returns
`owner_approval_required` without applying, carrying the OS-backed approval
handoff. An explicit decline returns `owner_declined` and leaves the draft
unchanged.

The first successful call mints one durable application ID and its immutable
revision and memory IDs. An exact later call is an idempotent replay: it does
not reapply that revision, create a second application, memory, or approval, or
re-prompt the owner. It still enters the standard writer boundary, where a
carried-forward Store can commit additive compatibility healing and advance
`audit_generation`; that maintenance never changes the original application
facts. `idempotent_replay` therefore describes the response to this call, not
a stored property that changes the original application. Its
`standing_guard_violations` companion is intentionally different: it is a
whole-Store diagnostic recomputed as of each successful call, so a replay can
truthfully report a standing inversion introduced or cleared after the first
apply without changing any application fact.

Both refusals carry `approval_handoff` in `error.details`: a `command` naming
the exact approval invocation for that revision, and a `review_path` telling
the owner how to reach it in the owner UI. Neither code means the revision is unapprovable — the
apply validates the revision against the current draft and the digest against
the stored revision *before* it raises either, so the triple echoed back is
already known-good, while a stale revision or a wrong digest fails earlier
under its own code and carries no handoff. The handoff echoes the caller's
exact triple and never substitutes the current draft, because naming a
revision the agent did not present would defeat the exact-revision contract
the approval exists to enforce.

`command` is built with `shlex.join`, so a Store home containing a space
survives being pasted or executed, and it names the console entry point
rather than an interpreter path. `--home` appears only when the runtime root
differs from the default home; the common install therefore puts no
filesystem path on this wire. `review_path` carries a short instruction --
run `memory ui`, then open Pending Reviews -- rather than a URL or a path.
The owner UI binds an ephemeral port and trades a one-shot launch link for a
session, so the MCP process has no stable origin to name and an emitted path
was something the owner could not click. When the Store is not on the default
home it points at `command` for the matching `--home` rather than repeating a
filesystem path on this wire. The field keeps its name so the contract digest
does not move for a copy change.

When no approval prompt was displayed, an agent may run the exact invocation
from `owner_approval_required` or `owner_declined` without another conversational
checkpoint. A harness can return the latter without surfacing an owner
decision. The command renders the exact unapplied review and requires
OS-mediated owner presence; running it supplies no approval. If prompt
visibility is unknown, report the handoff and stop. A visible decline or
cancellation, or a failed or timed-out OS check, stops the workflow; never
retry that handoff or the unapplied MCP call. After successful CLI approval,
the same exact MCP triple may be replayed for its structured application result.

The domain layer accepts only an internal `OwnerApproval` created by a trusted
adapter. The two OS-backed adapters `local_owner_ui` and
`os_owner_presence_cli` may mint that capability after exact revision/digest
review and successful OS-mediated owner presence. UI and CLI approval require
that OS proof: TTY state, `isatty`, typed input, pipes, PTYs, browser fields,
and model arguments are never sufficient. `memory approve` renders the exact
unapplied review and then requires OS-mediated owner presence bound to that
revision, digest, and one-use challenge; it reads no confirmation, and
cancellation, failure, timeout, or a lost challenge applies nothing and
returns `owner_approval_required`. `approvals.adapter` stores exactly one of
`mcp_elicitation`, `local_owner_ui`, or `os_owner_presence_cli`. The model may
request approval but cannot provide the decision field itself.

An exact call for an already-applied revision returns the original application
before requesting another approval. Otherwise, after approval, the same
bounded writer operation revalidates source/blob digests, evidence, batch
completeness, expected memory heads, and revision digest, then writes all
memory revisions, evidence, head changes, approval, and application records
atomically. A stale head returns `stale_head`, writes no semantic rows, and
leaves the draft available for a fresh edit.

## 8. Guard links

A guard link is an owner-approved, append-only relationship between two memory
lineages: the **guard** lineage qualifies, permits, corrects, or restrains
the **governed** lineage. Any memory kind can be a guard; there is no
dedicated kind, no cycle detection (a cycle only causes mutual co-retrieval),
and one lineage may guard, or be governed, any number of times.

```text
memory_guard_links               canonical, lineage-level, append-only
  guard_lineage_id, governed_lineage_id, application_id
  revoked_at?, revoking_application_id?
  PRIMARY KEY (guard_lineage_id, governed_lineage_id)

change_revision_guard_links      draft, revision-authored, mutable pre-apply
  revision_id, ordinal, guard_item_id?, guard_lineage_id?,
  governed_item_id?, governed_lineage_id?
  each side names a draft item XOR an existing lineage

change_revision_guard_revocations  draft, same endpoint shape
  revision_id, ordinal, guard_item_id?, guard_lineage_id?,
  governed_item_id?, governed_lineage_id?
```

`memory_guard_links` rows are keyed by lineage, not revision: superseding
either head preserves the relationship without touching the link. Rows are
never deleted. A guard whose *text* is wrong is corrected the way any memory
is corrected — supersede the guard lineage with clarified text or a lower
sensitivity, and the existing link keeps governing the same claim. A link
that should never have existed is a different failure, and supersession
cannot reach it: it is revoked (8.1). Two
independent ceilings bound how many links exist: `MAX_GUARD_LINKS` (256)
bounds how many links one change-set revision's `guard_links` may carry, and
the same figure caps `memory lint guards`' candidate report, since that
report exists to become edits in one change set; `MAX_GUARDS_PER_LINEAGE`
(256) is the most guards any single governed lineage may accumulate across
every application it has ever had — the apply that would cross it is
refused, naming the governed lineage, before anything commits. That figure
is chosen to equal the `guards` `maxItems` the MCP schemas declare (9), so a
claim's retained guard roster can never outgrow what the wire contract
promises on that one, governed direction. The reverse direction has no
matching cap: one guard lineage may govern arbitrarily many claims, so
`governs` carries no `maxItems` on the wire — deliberately unbounded, the
same adjudication already made for the whole-Store `standing_guard_violations`
report (9).

### Authoring

`change_set.edit` accepts `add_guard_link`, `remove_guard_link`, and
`revoke_guard_link` among its
ordinary edit operations (7.1), each carrying a guard side and a governed
side that name exactly one of an `item_id` in the same draft revision or an
existing `lineage_id`, never both and never neither. `change_set.edit`
resolves and validates every link against the draft's current items and the
Store's current heads before accepting the new revision: an unresolvable
item, an unknown lineage, a self-link, or a link that duplicates another once
both sides resolve to lineages all fail as `invalid_argument`. A link naming
a rejected draft item is itself rejected in the diff and is never
materialized at apply. Resolution is cross-form: the same pair-resolution
logic reads both a freshly edited link and a previously stored, status-
bearing one identically, so editing and apply can never disagree about what a
link resolves to. `change_set.create` itself takes only a `batch_id`; every
guard link enters through the same `change_set.edit` call that carries every
other proposal.

### Digest payload

The canonical digest payload (7.1) gains a `guard_links` array **only when
the revision carries at least one link**; a linkless revision's payload is
byte-identical to one built before guard links existed. This conditional key
is what keeps every digest computed for a pre-guard revision valid: the Store
recomputes and re-verifies a stored revision's digest every time it loads
one — creation replay, `change_set.get`, an `edit`'s current-state load, and
`approve_and_apply` alike — so adding the key unconditionally, even as an
empty array, would change the recomputed digest for every revision that
predates it and make each one fail permanently as `wrong_digest`. The digest
format stays `memory.change-set-digest.v1`; no version bump was needed
because the addition is purely conditional.

Revocation (8.1) follows the same rule with its **own** conditional key,
`revoked_guard_links`, present only when the revision carries at least one
revocation. It is a second key rather than a status field on `guard_links`
entries precisely because a status field would change the payload of every
revision that carries an ordinary link, which is the retroactive
`wrong_digest` failure this precedent exists to prevent.

### 8.1 Revocation

A mis-attached guard rides every retrieval of its lineage forever, and
superseding the guard's text does not detach it. `change_set.edit` therefore
accepts `revoke_guard_link`, resolved by the same cross-form pair logic every
other link uses. Both endpoints must resolve, the resolved pair must name a
retained and not-yet-revoked row, and one revision may not both add and revoke
the same pair.

At apply, inside the same transaction, revocation runs after materialization
and before the guard-violation scan, stamping `revoked_at` and
`revoking_application_id` on the canonical row. The row is never deleted, so
history and the audit keep it. A revoked link is excluded from co-retrieval,
from `memory lint guards`, and from the violation scan — which is the one
place revocation changes an outcome rather than only a view, and it is the
intended one: revoking a mis-attached guard is how a standing violation is
cleared. A revoked pair no longer consumes a `MAX_GUARDS_PER_LINEAGE` slot,
because that ceiling exists to keep the wire's `guards` `maxItems` honest and
`guards` carries only links that still govern. Re-adding a revoked pair is
refused rather than silently ignored: `INSERT OR IGNORE` would leave the row
revoked and hand an owner who approved "add this link" no link and no word of
it. Revocation is final for that exact pair.

The two nullable columns are added to an existing Store by the additive
`ALTER TABLE` heal that runs at every writer `BEGIN`, beside the
`CREATE TABLE IF NOT EXISTS` that heals the tables themselves.

### Apply semantics

At apply time, after every active item in the revision has created or
corrected its memory revision and updated its lineage's current head, the
Store materializes every active guard link as one `memory_guard_links` row
(`INSERT OR IGNORE`, so re-proposing an already-retained pair is a no-op, not
an error) and collects the set of lineages this application **touched**:
every lineage that received a new or corrected head in this application,
plus both sides of every active link this revision resolves to two lineages
— whether that link is newly materialized or already on record from an
earlier application. It then reads every guard whose effective sensitivity
exceeds a claim it governs, ranked from `current_memory_heads` **as just
updated by this same application** — so a correction that raises or lowers a
lineage's own sensitivity is judged by its new state, not its old one — and:

- a violation touching this application's own lineages **blocks the whole
  apply** with `invalid_argument` naming the guard lineage, the governed
  lineage, and both effective sensitivities; nothing in the application
  commits;
- every other violation is **reported, not blocked**, as
  `standing_guard_violations` on the successful `ApplicationResult`.

`standing_guard_violations` is a current whole-Store diagnostic, not a frozen
attribute of the application row. The initial result is computed after that
apply's writes; an exact replay reuses the same application ID, revision ID,
and memory IDs without reapplying them, creating another approval, or
re-prompting the owner, then recomputes this diagnostic as of the replay call.
Its standard writer-start compatibility healing may still commit separately
and advance `audit_generation`.

Two consequences of "touched" surprise a reader who expects only newly added
links to be checked. First, explicitly re-proposing a link that is already a
standing violation blocks the apply: re-asserting it returns both lineages to
the touched set, so the still-present violation is no longer merely reported.
Second, a revision that adds **no** guard link at all can still be refused:
correcting or adding a claim that lands on either end of an existing link is
enough to touch it, so a revision that never mentions a guard can surface —
and block on — a violation that has nothing to do with what it proposed.
`memory approve` and every MCP `change_set.approve_and_apply` report
`standing_guard_violations` under the same field name and the same per-item
keys (`guard_lineage_id`, `guard_sensitivity`, `governed_lineage_id`,
`governed_sensitivity`); `memory lint guards` reports the identical shape
from the same underlying check for the whole Store, independent of any one
apply, and writes nothing itself.

### Co-retrieval

`memory.search` hits and `memory.get` gain the current heads of every
lineage attached on either side of a guard relationship, as roleless stubs:

```text
GuardAttachment  memory_id, lineage_id, kind, statement, effective_sensitivity
```

`memory.search` hits and `memory.get` both carry `guards` (heads that govern
this lineage); `memory.get` additionally carries `governs` (heads this
lineage governs). Nothing on the stub itself says which side it is — the
array it arrived in names the side. A stub returned under `guards` is a
guard. Attachments bypass every filter the query set (kind, tags, date,
sensitivity): a filter is an arbitrary set the caller chose for the claim,
and applying it to the guard too could silently drop a guard sitting below
the sensitivity or outside the kind that admitted the claim it accompanies.
Attachments never consume a page slot and are excluded from the search
snapshot digest (5.3) — attaching or superseding a guard between pages
therefore never stales an in-progress `memory.search` cursor, at the cost of an
already-emitted page not carrying a link added after it was read. A guard
that also independently matches the query keeps its own ordinary hit, ranked
and labeled like any other; the attachment is additive, never a substitute.
A Store that predates the guard-link tables answers every read with empty
`guards`/`governs` instead of failing.

## 9. Generic MCP and Skill

The Store exposes fourteen domain-neutral tools:

```text
store.status
source.list           source.search          source.read
inbox.scan            inbox.list             inbox.read
memory.search         memory.get             memory.facets
change_set.create     change_set.get          change_set.edit
change_set.approve_and_apply
```

`memory.facets` reports the tag and kind vocabulary actually in use, so an
agent can filter on what exists rather than on a guess. It is a tool rather
than a `store.status` field because a tag is owner-authored text and
`store.status` is specified as content-free: the one call an agent makes first
must not start returning content.

There are no health, finance, preference, browser, shopping, or other domain
tools. MCP accepts opaque IDs and bounded values, never paths, SQL, keys, or
database handles.

The normative request/result map is:

| Tool | Request | Result |
|---|---|---|
| `store.status` | none | `StoreStatus` |
| `source.list` | `filters?, cursor?, limit?` | `SourceSummary[]` |
| `source.search` | `query, cursor?, limit?` | `SourceSearchHit[]` |
| `source.read` | `source_id, cursor?, max_bytes?` | `SourceChunk` |
| `inbox.scan` | `authorship?, sensitivity?` | `InboxBatch` |
| `inbox.list` | `cursor?, limit?` | `InboxBatch[]` |
| `inbox.read` | `batch_id` | `BatchDetail` |
| `memory.search` | `query?, filters?, cursor?, limit?` | `MemorySearchHit[]` |
| `memory.get` | `memory_id \| lineage_id \| memory_ids[]`, `cursor?` | `MemoryDetail`, `MemoryDetail[]`, or `MemoryDetailFragments` |
| `memory.facets` | none | `MemoryFacets` |
| `change_set.create` | `batch_id` | `ChangeSetView` |
| `change_set.get` | `change_set_id` | `ChangeSetView` |
| `change_set.edit` | `change_set_id, expected_revision_id, edits[]` | `ChangeSetView` |
| `change_set.approve_and_apply` | `change_set_id, revision_id, digest` | `ApplicationResult` |

The scan defaults are `authorship=unknown` and `sensitivity=restricted` — a
scan that states no authorship is labeled honestly rather than impersonating
the owner, while the Python kernel keeps `owner` for its explicit callers.
They are capture metadata, not retrieval exclusions. `source.read` uses the
coordinate contract in section 5.3. The approval tool has no owner-decision
input.

All responses use `memory.mcp.v1` envelopes with pagination, provenance,
sensitivity, inert-data labels, and coverage where applicable. `memory.search`
uses the item and byte bounds in section 5.3; a short byte-bounded page resumes
through the same opaque cursor its item-bounded pages use.
`memory.get` uses the complete-detail/fragment contract in section 6, with
`page` on every success, including `has_more=false` for a complete legacy-shaped
response. Continuations always remain fragments, including the final page.

The staged-intake `check-memories` cleanup gate accepts a complete bounded
`MemoryDetail[]` envelope with exactly `page: {has_more: false}`, as well as
an older complete envelope without `page`. It refuses partial pages, fragment
responses, cursors and malformed page metadata rather than authorizing cleanup
from incomplete detail. All existing exact item, evidence and relationship
checks still apply; this compatibility handling changes no persisted receipt.

The envelope is the MCP result's `structuredContent`. For a text
`source.read`, `SourceChunk.text` contains the chunk. For a binary read,
`data` contains only metadata and `resource_content_index=0`; MCP `content[0]`
is exactly one standard `EmbeddedResource` whose `BlobResourceContents` has a
`memory://source/<opaque-id>` URI, the declared media type, and base64 `blob`.
The digest and byte range in `SourceChunk` bind that block, and concatenating
decoded blocks in cursor order reconstructs the source.

```text
ToolSuccess
  schema = memory.mcp.v1
  instruction_trust = inert
  data
  page?       {next_cursor?, has_more}
  coverage?   {searchable, unsearchable, enumerated, total}
  issues?     [{code, count}]

ToolFailure
  schema = memory.mcp.v1
  instruction_trust = inert
  error       {code, retryable, details?}
```

`details` carries bounded content-free locators — counts, limits, ordinals,
sensitivities, digests, and opaque item, source, lineage, and
expected-revision IDs — plus the `approval_handoff` of section 7.2. It never
contains source text, filenames, SQL, or keys. The one filesystem path it can
carry is the runtime root, inside a handoff `command` and only when the Store
is not on the default home, so the common install puts no path on this wire
(7.2).

`instruction_trust` is the literal enum value `inert` on every response,
success and failure alike — including source text, embedded resources, and
owner-approved memory. It rides the failure arm because a refusal still
carries Store-derived opaque IDs, and the label saying they are data rather
than instruction should not be the one field that disappears exactly when
something went wrong. Returned content never becomes agent instruction.

Success and error are mutually exclusive. The bounded content-free error set
is `invalid_argument`, `not_found`, `wrong_product`, `key_missing`,
`key_unavailable`, `busy`, `source_too_large`, `no_eligible_sources`,
`stale_cursor`, `stale_revision`, `stale_head`, `invalid_evidence`,
`ambiguous_evidence`, `incomplete_batch`, `wrong_digest`,
`store_unavailable`, `owner_approval_required`, and `owner_declined`.

The named wire types have these required fields; `?` means optional and every
ID is an opaque string:

```text
Sensitivity          normal | sensitive | restricted
Authorship           owner | external | mixed | unknown
MemoryKind           fact | event | preference | relation | insight
SourceCaptureOrigin  inbox | owner_correction
MatchStrength        phrase | all_terms | any_term | enumerated
                     (`enumerated` is memory-side only; a queryless
                      `memory.search` walk emits it and nothing else does)

StoreStatus       product, product_version, schema_version, store_id,
                  source_count, memory_count, searchable_count,
                  unsearchable_count, pending_review_count,
                  reindex_required, mcp_contract_digest, skill_digest
SourceSummary     source_id, origin, blob_digest, original_name, media_type,
                  byte_length, authorship, declared_sensitivity,
                  effective_sensitivity, searchable, captured_at
SourceSearchHit   source: SourceSummary, exact_excerpt, rank, match_strength,
                  excerpt_char_start, excerpt_char_end,
                  match_char_start?, match_char_end?
SourceChunk       source_id, blob_digest, media_type, text? |
                  resource_content_index?,
                  char_start?, char_end?, byte_start, byte_end,
                  next_cursor?, complete
InboxBatch        batch_id, sealed_at, source_count, source_ids[],
                  batch_has_more, issues[], duplicates[],
                  review_state = none | draft | applied,
                  change_set_id?, application_id?
DuplicateCapture  source_id, duplicate_of
MemoryFacets      tags: FacetCount[], kinds: FacetCount[],
                  total_tags, truncated
FacetCount        value, count
BatchDetail       batch: InboxBatch, sources: SourceSummary[]
MemoryFilters     kinds[]?, tags_all[]?, tags_any[]?, occurred_from?,
                  occurred_to?, include_undated?, recorded_from?,
                  recorded_to?, sensitivities[]?
SourceFilters     searchable?, origin?
MemorySummary     memory_id, lineage_id, kind, statement, occurred_on?,
                  valid_from?, valid_to?, tags[], stored_sensitivity,
                  effective_sensitivity, recorded_at
GuardAttachment   memory_id, lineage_id, kind, statement,
                  effective_sensitivity
MemorySearchHit   memory: MemorySummary, match_strength,
                  guards: GuardAttachment[]
MemoryDetail      revision: MemorySummary, is_current, current_head_id,
                  predecessor_id?, revision_ids[], evidence[],
                  guards: GuardAttachment[], governs: GuardAttachment[]
MemoryDetailFragments detail_fragments: MemoryDetailFragment[]
MemoryDetailFragment selection_index, memory_id, section, value
                    section = header | evidence | guards | governs | revision_ids
MemoryDetailHeader  revision: MemorySummary, is_current, current_head_id,
                    predecessor_id?
DraftGuardLink    ordinal, guard_item_id?, guard_lineage_id?,
                  governed_item_id?, governed_lineage_id?,
                  status = active | rejected
ChangeSetView     change_set_id, batch_id, state, revision_id, digest,
                  adapter_origin, items[], source_decisions[],
                  guard_links: DraftGuardLink[],
                  revoked_guard_links: DraftGuardLink[]
GuardViolation    guard_lineage_id, governed_lineage_id,
                  guard_sensitivity, governed_sensitivity
ApplicationResult application_id, change_set_id, revision_id, memory_ids[],
                  idempotent_replay,
                  standing_guard_violations: GuardViolation[]
```

List/search result arrays live in `data`; their cursor and coverage metadata
live only in the envelope's `page` and `coverage` fields. `ChangeEdit` is the
tagged union in section 7.1; draft items return their item ID, status,
complete memory fields, normalized evidence locators, expected head, and
ordinal. Evidence rows always return source ID, blob digest, evidence mode,
and resolved excerpt/span when text.

Detail fragments follow selection order and, within each detail, header,
evidence ordinal, guard lineage ID, governed lineage ID, then revision history
ordered by recorded time and rowid. Each fragment identifies its zero-based
selection index and exact revision ID. A `header` value supplies the scalar
detail fields; the client initializes empty evidence, guards, governs and
revision-ID arrays and appends each later fragment value to its named array.
Evidence values are complete locators, relationship values are complete
`GuardAttachment` objects, and history values are revision-ID strings. Headers
and roster elements are emitted exactly once in a completed cursor walk. A
page can end within any roster and never silently omits the remainder.

Public search descriptions teach `source.read(source_id)` followed by returned
opaque cursors until the needed character range is reached, and through
completion when full context is material. Search coordinates are evidence
locators, not public seek arguments; clients do not construct cursors. Tool
discovery also teaches the existing evidence sensitivity floor at edit/apply,
and the derived current evidence sensitivity on memory search/detail retrieval.
It also teaches the generic open-item tag/horizon convention, complete queryless
enumeration including future and undated items, evidence-bound date anchors,
and the absence of read-side completion or recurrence advancement.
These descriptions and their structural mirrors participate in the MCP digest.

`StoreStatus` includes product and schema identity, content-free aggregate
counts and coverage, whether a reindex is required (5.3), and two SHA-256
contract digests. The MCP digest is over
UTF-8 JSON for the full tool schemas and error envelope with sorted object
keys, compact separators, and declared array order preserved; the Skill
digest is over the packaged `SKILL.md` bytes after LF normalization. Agents
can therefore report the exact contract they used without receiving a
filesystem path.

Beside the tools the server serves four **Prompts** and one read-only
**resource** space.

The prompts are `answer_a_question`, `review_one_inbox_batch`,
`review_one_captured_correction`, and `advise_the_owner`. Each is
argument-free and returns two messages: the Skill's `## Core contract`
section, then that workflow's own section. Every byte on the wire is
packaged Skill sliced at its `##` headings
— no glue sentence is synthesized — so the Skill stays the single source of
truth and `skill_digest` already covers what a prompt serves. Prompt names are
constants rather than derived from headings, so rewording a heading fails the
mapping loudly instead of silently renaming a prompt a client reaches for; a
missing, renamed, or duplicated section raises before the server object
exists, so the process refuses to start rather than serving a partial set.

Core carries the shared exact-review and approval rules, including the
authorized intake workflow's private presentation boundary. A workflow that
needs another section names its existing MCP prompt explicitly so a client
can load the prerequisite when absent; completed orientation is retained.
This does not add a tool, change the two-message shape, or change the MCP
contract digest. Skill prose changes remain covered by `skill_digest`.

`resources/read` resolves exactly the `memory://source/<id>` URIs that
`source.read`'s binary arm has always minted and nothing could previously
resolve. Parsing is purely structural — scheme, host, one path segment, no
query or fragment — so an unrelated URI is unrecognized rather than probed,
and the id then goes through the same `read_source` the tool uses, inheriting
the fail-closed identity check and the read-only connection. A response
carries the capture's own media type and the envelope's two constant fields as
`_meta`. It is bounded by the same 4 MiB ceiling `source.read` enforces, and a
capture above it is **refused, not truncated**: a resource read has no cursor,
so a silent prefix would leave no way to find the rest and no field admitting
the cut, which is exactly what complete source access forbids. A complete text
capture can also expand beyond the 8 MiB encoded resource-result ceiling when
JSON escaping is applied; the adapter measures the real serialized result and
refuses that capture too. The refusal names `source.read`, which has a cursor
and applies its own encoded-byte stop. Binary behavior is unchanged: the raw
4 MiB ceiling already keeps its base64 resource result below the encoded
ceiling.

`resources/list` enumerates nothing, deliberately, and the distinction from
"is not served" matters. The SDK registers the method unconditionally, so the
Store answers it with an empty list rather than a missing method; what it does
not do is enumerate captures there. Enumerating them would be one unbounded
response with no cursor, and `source.list` already enumerates with a cursor,
provenance, sensitivity, and honest coverage. `resources/templates/list`
advertises `memory://source/{source_id}` instead: constant-sized,
content-free, and enough for a client to know the space resolves. A client
that reads the empty listing as "this Store holds nothing" has been told
something false by an SDK default, which is why the template listing is the
surface that answers the question.

Neither prompts nor resources enter `contract_digest()`. It digests the tool
schemas and the error envelope; a prompt body is Skill bytes, which
`skill_digest` covers, and folding them in would move the MCP digest on every
prose edit while telling a reader nothing the Skill digest did not.

The vendor-neutral Skill teaches:

An explicit personal open-item request uses the question workflow's open-item
branch. It walks all current `loop:open` heads across every page and sensitivity,
without an incidental aspect, kind or date filter; loads current details and
guards; and reads material sources completely. A full list includes due,
upcoming, precision-uncertain and undated items. Classification uses a known
owner-local current date: an exact horizon today or earlier, or a wholly past
partial-date range, is due; a containing month/year remains uncertain. Unknown
current date means dates are reported without a due claim. The answer keeps
source-only and pending-review candidates separate from approved tracked items.
Empty or unexpectedly thin walks require the existing coverage fallback, and
unread or pending evidence prevents an unqualified absence claim. The read-only
workflow never scans, captures, retags, applies or schedules notifications.
Conversation-only reminder requests receive a draft for owner placement/capture,
not a claim of persistence. A real relative-day request's draft records the known
owner-local request date and calculated horizon for review; unknown anchors stay
explicit rather than guessed. This is source creation for owner review, not
using processing timestamps to reinterpret an older note. Explicit project-status
questions keep project scope.

```text
question/advice:
  inspect status -> search memory -> search sources (one call answers
  phrase, all-terms, and any-term together)
  -> if coverage is unresolved, enumerate approved heads and all sources
  -> read metadata-uncertain sources and full material context
  -> check current revisions and guards -> disclose missing coverage
  -> distinguish evidence and inference

advise the owner:
  after status and facets, one complete queryless tag walk over the
  reserved standing set without an aspect filter, then one over open
  loops, unconditionally even when bounded facets omit either reserved tag
  (valid_to is the horizon; rebuilt every session, never cached)
  -> keep an explicit hypothetical session-local: note any material
  conflict with retained memory, then reason within the assumption
  -> answer through application, priority, proportionality, freshness,
  and candor: name what retained memory bears on the answer; preserve
  only an explicit ordering; distinguish reversible from irreversible
  steps and uncertain future complications from present effects; report
  expired validity instead of asserting it (open-loop horizons are due, not
  expired commitments); and lead with any guard that
  cuts against the hoped-for answer. Candor shapes conditions and exit
  plans from real constraints; it is not default pessimism
  -> never treat the agent's recommendation as the owner's decision or offer
  a draft before the owner states the decision; after a recommendation meets
  a stated owner decision, offer exactly
  once in the first closing response one complete conversational decision
  note for the owner's intake pipeline; a no-save request does not suppress
  this source-free draft or reduce the response to a decision restatement,
  but a no-offer request or decline ends it
  -> after a stated outcome or new horizon: one closure/re-horizon
  offer (correction; owner places or captures)

inbox:
  scan one batch -> read every source -> create/edit one change set,
  tagging a proposal `standing` when its evidence explicitly states a
  durable preference, pattern, or constraint meant to guide future advice,
  but not for an incidental fact, one-time choice, or temporary state,
  linking a guard to every claim it qualifies, corrects, permits, or
  restrains -> account for every source -> show complete diff/digest through
  the appropriate owner review surface, keeping private intake content off chat
  -> request owner approval through MCP elicitation (owner opt-in)
  -> when no prompt surfaced, continue with the exact OS-backed handoff
  -> unknown prompt visibility, visible refusal, or a failed OS check stops
  -> verify the structured application result; never infer owner approval

owner correction:
  read the already-sealed correction batch without scanning
  -> read its sole owner_correction source completely
  -> create/edit one change set targeting the captured lineage and head
  -> show complete diff/digest -> request one owner approval -> apply
```

Every hit's `match_strength` names the ladder rung that answered it (5.3);
the Skill treats `any_term` as a lead to verify, never an established match,
while `phrase` and `all_terms` establish lexical matches, not relevance or
complete evidence. A hit's `guards` are not
optional context: the Skill never states, summarizes, or acts on a claim
without conveying every attached guard, whether the guard is presented
inline because its own claim is already on the page, or, when it is not, as
its own ordinary hit naming what it governs. A guard applied mid-walk appears
only on pages fetched after that apply, so a final answer leaning on early
pages re-fetches page one first. `store.status` reporting `reindex_required`
is the Skill's cue to tell the owner to run `memory reindex` before it leans
on a thin result.

A Memory coverage gap establishes only what Memory did not establish. It is
not evidence that another bounded system of record the agent is configured
with lacks the fact, and the Skill returns control to task-level routing when
such a system may be authoritative for it. This is the one place the Skill
speaks about anything outside the Store, and it speaks only to deny an
inference: absence here is absence here.

Advice is read-only. A decision alone is not a Source and must not trigger
`inbox.scan` or change-set creation or editing. A durable correction discovered
in conversation becomes a source before it becomes a separate Memory Review:
the owner either places a note in the Inbox or writes it in the local owner UI,
which captures it as one isolated `owner_correction` source batch. Direct
conversation capture does not exist.

The Skill optimizes for answer quality inside the trusted owner session. It
never treats an empty or short ranked result as proof that the Store has no
relevant information. For advice or high-impact questions, it continues
through `source.list` and `source.read` until it has covered all plausible
sources or can name the unresolved coverage. Sensitive and restricted captures
participate in that search exactly like normal captures; sensitivity is
returned as metadata, not used as a silent exclusion.

A complete lexical scan cannot establish semantic coverage: paraphrases and
cross-language evidence can lack query terms. The agent therefore enumerates
approved heads and sources for unresolved or conflicting coverage. A source's
name or preview lacking those terms cannot exclude it; when metadata cannot
establish irrelevance, its complete content must be read or its unread remainder
reported. Previews cannot rule out late caveats. Material source evidence is
checked against current approved heads, their full revision history and every
guard before answering. Superseded source evidence stays available as history;
it is never silently promoted over an approved correction. Binary reconstruction
alone does not establish interpretation, and unresolved binary coverage remains
explicit.

## 10. Local owner UI

### 10.1 Purpose and trust model

`memory ui` serves the one supported human surface: inspection of sources and
memory, Inbox custody, the complete Memory Review, correction capture, and
in-app audit. It runs as one foreground process for one Store, binds only to
loopback, and has no daemon, fixed port, remote binding, or external network
use.

The trusted owner environment consists of agent sessions explicitly connected
to the Store and the local owner UI launched by the same macOS account.
SQLCipher protects data at rest and the macOS Keychain protects the database
key; the UI necessarily receives plaintext so the owner can read it, so its
controls prevent accidental exposure rather than redacting what the owner
requested. The UI defends against cross-site requests, DNS rebinding,
accidental non-loopback binding, stale submissions, content injection,
URL/history leakage, caching, and log leakage. Malware already running as the
owner or a compromised browser profile is outside the protection boundary.

Direct approval remains an owner act. Within the public HTTP, CLI, and MCP
surfaces, no caller can supply a verifier, proof object, success boolean, or
approval capability. The UI approval adapter mints the internal
`OwnerApproval` only after an authenticated UI session renders the complete
current revision, receives an explicit approval submission, and a macOS
owner-presence verifier succeeds. The verified capability is bound to the
Store, change set, revision, digest, UI session, final-page nonce, short
expiry, and one-time consumption, and is revalidated before and after the
asynchronous OS prompt.

Memory list and detail pages describe recorded applicability beside the
statement, separately from whether the selected revision is the current
lineage head. The projection expands partial dates through the same inclusive
year/month/day bounds used by Store filtering. It distinguishes future or
precision-uncertain effective dates, recorded periods that ended, and an
absent end (`No end date recorded`). On an item tagged `loop:open`, `valid_to`
is a revisit horizon: a wholly past partial-date range makes the revisit due,
while a range containing today reports the precision uncertainty. Neither
state says the canonical memory expired, and no presentation read modifies,
suppresses, or expires it.

The memory search form re-renders every active kind, sensitivity, all-of tag,
and occurred-date bound. Repeating or editing a search keeps those values;
choosing a kind facet replaces only the kind selection. Filter text remains
in authenticated POST bodies and session state, never in navigation URLs.

A memory detail's guards and governed memories are separate bounded rosters:
at most 50 relationships per page, with whitespace-normalized 160-character
statement previews and links to each complete revision and its evidence.
The read fetches only that page plus one sentinel row. Each cursor binds the
Store, selected revision, relationship direction, and Store generation (or
the exact bound audit snapshot). Pagination preserves the other detail
panels' cursors and any audit handle. The selected revision's statement and
the agent-facing complete retrieval contract remain unchanged.

### 10.2 Session and web security

1. Bind only to `127.0.0.1` on an OS-selected random port, under a random
   `.localhost` hostname label with at least 128 bits of entropy; reject every
   other `Host`, port, forwarded-host, and proxy header.
2. The launch URL carries a one-use 256-bit bootstrap capability in the URL
   fragment, never the query string; bundled bootstrap JavaScript exchanges it
   once for an opaque in-memory session cookie and removes the fragment from
   history. The bootstrap expires after 60 monotonic seconds; the session has
   one fixed eight-hour monotonic lifetime with no extension.
3. The session cookie is host-only, `HttpOnly`, `SameSite=Strict`, never
   persisted to disk, and invalidated on shutdown.
4. Only the content-free bootstrap shell, bundled static assets, and one-shot
   session exchange are unauthenticated; everything else requires the valid
   process session.
5. Every state-changing request requires a per-session CSRF token and exact
   `Origin` validation; CORS is disabled. Search and filter text is submitted
   through authenticated POST, retained only in bounded process-memory session
   state, and referenced by random opaque handles in URLs — never by value.
   Handles expire and are bounded per session.
6. Every response carries `Cache-Control: no-store`,
   `Referrer-Policy: no-referrer`, a restrictive CSP,
   `X-Content-Type-Options: nosniff`, and `frame-ancestors 'none'`. All assets
   are bundled; no remote scripts, styles, fonts, images, frames, forms,
   telemetry, or service workers.
7. Stored filenames, source text, memory text, tags, evidence, media types,
   and error details are untrusted display data: escaped by default, with only
   a narrow sanitized Markdown subset.
8. Logs and error pages are content-free: bounded event codes and counts only,
   never content, paths, filenames, tokens, queries, digests, or approval
   material.
9. Request, response, upload, pagination, and edit bounds apply before
   allocation or rendering; large content streams.

### 10.3 Error and concurrency behavior

GET requests never mutate Store or domain state and never create, refresh,
lease, consume, or replace write-authority state; read handles are created
only by protected POST and merely resolved by GET. Mutating POSTs are not
automatically retried, and every successful mutation redirects to a fresh
server-rendered view so browser refresh cannot repeat it.

While an enhanced form submission is pending, its controls are disabled after
the request body is captured. A transport failure, HTTP failure, or missing
success redirect restores those controls and displays a focused inline alert
without replacing the page or clearing its entries and unsaved-change warning.
The alert treats the outcome as unknown: a lost response can follow a committed
write, so the owner must check before explicitly submitting again. This
recovery is confined to the current page; it creates no persistent draft or
browser storage. Successful navigation clears only the submitted form's warning.

Typed failures render as actionable owner states: a busy writer retains
bounded form values under a session-bound handle for one explicit retry;
stale revisions reload the current review and highlight what changed; a stale
memory head links to the new current revision; incomplete batches and
ambiguous evidence identify the affected item without offering approval; a
cancelled or unavailable owner-presence prompt applies nothing and retains the
draft; session expiry or shutdown performs no mutation. A second UI process
for the same runtime fails before opening a listener; distinct runtimes remain
independently launchable.

### 10.4 In-app audit

Sources & Audit binds one full-coverage snapshot and reconciles source,
memory, review, approval, and application counts, with navigation from any
source to its batch, review, approval, application, and resulting memories.
Audit is in-app navigation only. There is no record export from the
browser: no ZIP, JSONL, Markdown, database, or bulk-record download. The
owner-authenticated local CLI export is specified in section 4.5. There is
no raw database access, SQL entry point, database path, or Keychain access
from the browser.

### 10.5 Graph lenses

The owner UI draws the Store's approved relations. `memory/graph.py` reads all
three of them — batch custody, source evidence, and guard links — into one
`StoreGraph` value, and `memory/ui/graph_layout.py` turns that value into
placed marks. Nodes belong to one of four layers: aspect, batch, source, and
memory.

Three properties constrain the whole subsystem:

- **It infers nothing.** There is no similarity, no scoring, and no derived
  edge. A picture that draws an unapproved relationship in the same ink as an
  approved one teaches the owner something the Store never asserted. An
  aspect node exists only because a memory carries an approved `aspect:` tag,
  read off the tag rather than inferred from content.
- **It is a disposable projection.** In the sense of §4.3 and of AGENTS.md's
  ninth invariant — not this document's, which is about sensitivity — it is
  computed
  on read and persisted nowhere. Row order is fixed by rowid throughout, so
  the layout is a pure function of the Store and does not shift between two
  reads of an unchanged one.
- **It refuses rather than truncates.** Admission combines node, edge,
  conservative rendered-byte, and layout-work limits. SQL counts the selected
  entities and relations, including revoked guard links, before labels or edges
  are materialised. Aspect markers generated from the admitted memories then
  count toward a second check before edge loading or layout. The read returns
  `within_ceiling=False` when any limit is exceeded, and the view reports the
  selected node and edge counts with guidance to narrow the filters. This
  avoids both a partial picture and a late generic response-size failure.
  The budget measures the **filtered selection**, so a single aspect or kind
  can still draw in a Store that has outgrown the whole-Store view;
  `total_node_count` continues to report the whole Store. `MAX_GRAPH_NODES`
  (2,500) is an upper bound, not a promise that every graph below it fits: its
  relations and rendered representation must fit as well.

Two whole-Store lenses, one read-only panel, and one detail lens ship:

- **Provenance** (`/graph`) draws sources and memories joined by evidence.
  Batch custody is deliberately not drawn here: organizing by day is not what
  the picture is for, and batches remain visible in the Inbox, the audit, and
  every source's detail page.
- **Governance** (`/graph/governance`) drops custody entirely and keeps only
  the guarded subgraph, marking which memory guards and which is governed —
  both are memories, so nothing about either entity says which part it plays.
- **Guard candidates** (`/graph/governance/candidates`) lists what
  `memory lint guards` reports, as pairs the owner can read, each deep-linking
  into the existing `add_guard_link` edit on the open draft. It is read-only:
  a GET creates no write-authority state, takes no writer lock, and runs no
  schema heal, so a Store whose guard tables are unhealed is told to run
  `memory reindex` rather than handed a report computed against columns it
  does not have. Truncation is stated rather than implied.
- **Neighbourhood** is embedded in a memory's detail page: the subject at the
  centre with its one-hop neighbours on a ring, ordered by key so the panel
  does not reshuffle when an unrelated batch is applied. A dedicated owner-only
  SQL read selects the centre lineage's current head, its evidence sources,
  and the current heads at incoming or outgoing guard links, including revoked
  links. Only that local selection consumes the drawing budget; unrelated
  Store growth cannot hide it. Historical detail pages retain the same current
  graph semantics while presenting the selected revision separately. A local
  refusal stays visible, and audit snapshot pages omit this live panel.

Filters live behind the same opaque in-process handle a private search uses,
for the same reason: an owner may type anything into those boxes, and nothing
they type belongs in a URL. A filtered lens redirects to the handle route
beneath its own lens — `/graph/filtered/{handle}` for provenance and
`/graph/governance/filtered/{handle}` for governance — and the filter values
never reach the address bar, history, or a referrer. Both lenses restore every
active checkbox, tag, and date field, and switching lenses retains the opaque
handle so the same selection remains active.

Interaction is viewport-only. `static/graph.js` moves a viewBox, toggles
classes, and on drag rewrites the dragged node's own centre and the path of
every edge incident to it; it simulates nothing. Two
behaviours there are load-bearing rather than decorative: pointer capture is
taken only once a drag has actually started, because capturing on press
retargets the synthesized click to the `<svg>` root and an SVG `<a>` that
never receives a click never navigates — which turns every node into a dead
link; and the click that follows a drag is suppressed on the root, where the
capture puts it, rather than on the node, which would leave a listener armed
to cancel the owner's next genuine click.

## 11. Verification

Automated tests prove:

- fail-closed runtime identity validation, dual-persisted runtime mode, and
  rejection of absent, unknown, or mismatched identity and inbox values;
- external-inbox custody, hidden-file exclusion, and private Inbox-staging
  creation/repair plus symlink and non-directory refusal;
- UI-session lock paths with no premature lock-file creation;
- clean `memory paths` and wrong-product rejection;
- encryption, Keychain missing-key refusal, WAL, and writer contention;
- stable multi-file inbox capture and crash recovery;
- byte dedup with distinct capture metadata;
- exhaustive text/binary reads and honest search coverage;
- canonical-only memory retrieval;
- complete batch accounting;
- edit/reject/restore and exact digest changes;
- immutable Store-assigned change-set adapter origins outside the digest;
- transaction-bound audit generation for authoritative and projection writes;
- direct MCP owner approval plus textual, pipe, and PTY approval refusal;
- OS-backed UI and CLI approval minting bound to revision, digest, session,
  nonce, and one-use challenge, revalidated around the prompt;
- the complete UI session, CSRF, host, origin, header, and handle controls of
  section 10.2, exercised against the real application and in real browsers;
- the graph projection of section 10.5: that it draws only approved
  relations, refuses above its combined drawing budget instead of truncating,
  places the same Store identically on two reads (`tests/test_graph.py` and
  `tests/test_graph_layout.py`), and — in real browsers — that filters never
  reach the address bar, that a node still opens after being dragged, and
  that a press released off the scene leaves no drag armed;
- atomic/idempotent apply and stale-head refusal;
- provider-free MCP imports and clean stdio;
- prompt-injection content remaining inert;
- a synonym-mismatch case that requires enumeration and full-source fallback
  instead of trusting an empty ranked result;
- a plausible-but-incomplete ranked hit whose decisive evidence is found only
  after broadening;
- the staged-intake companion's numbered root, exact legacy detection,
  no-clobber migration, inode preservation, mutual intent exclusion, and exact
  recovery before and after every filesystem/config phase, including proof
  that migration never inventories a workflow child; and
- an intentionally unanswerable case that must name missing coverage instead
  of fabricating a recommendation.

One versioned synthetic manifest (`memory.synthetic-journeys.v1`) fixes case
IDs, questions, source fixtures, required-evidence mappings, and whether
enumeration fallback is required, with at least one Chinese case and one
generated PDF case. A second manifest (`memory.synthetic-ui-acceptance.v1`)
fixes the owner UI acceptance rehearsal. No owner fact or expected answer
appears in the Skill, tools, or fixtures.

The repeated behavioral runner prepares each fixed slot through exact
owner-reviewed synthetic batches, binds a private run/slot/Store marker, and
verifies source custody, guards, and correction history before advice.
Preparation does not attempt a behavioral slot. It records client-launch
attempts separately from operator-observed inference; fixture and harness
tests do not attest installed-client reasoning or owner presence. Historical
blocked slots remain recorded under their original denominators. A metadata
prerequisite probe creates neither a Store nor a behavioral trial.

A developer campaign may continue untouched subscription slots after a reviewed
infrastructure correction only through a versioned, append-only transition. Keep
the fixed roster, approvals, original provenance, failed outcomes and an immutable
pre-transition snapshot. Bind new infrastructure/authentication only to pending
slots and expose both bindings in the continuation report. Candidate product,
client, host, model/effort, Skill, manifest and rubric identities cannot change.
An existing failed slot is never replayed. Continuation requires positive prior
process cleanup, fresh scoped authentication, current isolation capability proof
and a fresh synthetic installed-Memory transport control. These developer records
do not change the Store schema, MCP envelope or historical review digests.

If temporary synthetic fixtures are lost, ordinary continuation cannot reuse
their approvals for new Stores. An explicitly versioned developer campaign
envelope may preserve exact predecessor snapshots as immutable history and give
only wholly unattempted logical slots a new fixture generation. Its fixed roster,
terminal outcomes and product/client/model/Skill/manifest/rubric bindings stay
unchanged. Fresh Stores require fresh exact OS-backed approvals and complete
fixture verification of both cohorts before either activates. One authoritative
campaign identity and head covers both cohorts and generations, with exclusive
allocation for the immutable original bindings, digest-checked activation and a
durable per-logical-slot consumption ledger checked before every launch. A stale
writer, competing generation or interrupted attempt cannot replay a slot.
The fixed per-user developer registrar is separate from campaign output storage,
Store data and credentials. It claims each original cohort digest, binds the
canonical campaign-root identity and publishes the sole authoritative head only
after its immutable bytes are durable. Caller-selected output parents and copied
roots cannot create another authority for the same original cohort. Replaced
authority directories or lock files and missing initialized indexes fail closed.
An anchored immutable publication-digest chain detects a restored older index;
the index remains the sole mapping authority. Incomplete or mismatched publication
refuses, and the named head storage stays bound through publication.
Create the replacement Stores, state, receipts and captures directly in private
durable campaign storage; keep client,
credential and proxy workspaces temporary and isolated. This is not a Store
restore, key export or historical-record rewrite. Existing state/report formats
retain their behavior. The [campaign recovery procedure](smoke-ceremony.md#interrupted-campaign-recovery)
defines the commands and activation prerequisites under this contract.

The Codex executor's bounded native JSON stream supplies completion evidence.
A complete final message and completed turn must already be observable when the
MCP peer closes. Later output or exit cannot repair an earlier disconnect.
Natural client/endpoint exits, fully drained untruncated streams, correlated
replies and verified cleanup are also required. Raw events remain private;
immutable lifecycle receipts retain counters, timing and process/cleanup metadata
after the command context closes, including failed and interrupted attempts.
Separate private recovery receipts retain endpoint identity and exact allocated
cleanup paths, linked to the content-free lifecycle receipt by digest. Public
reports never serialize these paths.

The repository gate is `./tools/check.sh`: `uv lock --check`, the full pytest
suite including real-browser UI journeys, Ruff lint and format, and strict
mypy, followed by installed freshness and fresh MCP verification. Its explicit
`--source-only` mode qualifies a candidate before installation without claiming
delivery. `./tools/deliver.sh run` owns the complete local release/install flow;
[local delivery](local-delivery.md) defines its private profile, immutable artifact
manifest, exact package and Skill checks, failure behavior, and synthetic-only
probe boundary. Existing MCP connections are never inferred to have updated.
`./tools/smoke-wheel.sh` and `./tools/smoke-ui.sh` verify the built
wheel in isolation. `docs/acceptance/v1-acceptance.md` is a blank owner-acceptance
recording template; `docs/client-setup.md` records the installed-client
smoke procedure.

## 12. Limitations and operational notes

Product boundaries a maintainer should know:

1. **No backup or restore tooling.** The Store home is plain files; the owner
   backs it up with ordinary filesystem backups (for example Time Machine).
   The database is useless without the Keychain item, which stays in the macOS
   login keychain — a restore onto a different account or machine needs that
   keychain entry too.
2. **No hard forget.** History and evidence are append-only; corrections
   supersede but do not erase. Plaintext export does not remove retained
   content; hard forgetting still means recreating a Store without it.
3. **No schema migrations.** Schema v1 is the only version; a future schema
   change is a deliberate project, not an incremental upgrade.
4. **Capacity.** Sources live inline in SQLCipher with 64 MiB/file and
   256 MiB/batch bounds; there is no external object store.
5. **Single owner, single machine.** One Store, one macOS account, one
   Keychain. The inbox may be synced across devices; the Store itself must not
   be placed in a synced or shared directory.
6. **Threat model.** Same-account malware and a compromised browser profile
   are outside the UI's protection boundary (section 10.1). Periodic security
   re-review is warranted as the product evolves.

Current source checks are recorded in the [public qualification receipt](acceptance/v1.13.0-acceptance.md). Historical private audit reports are not included.
