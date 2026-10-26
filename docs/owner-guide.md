# Owner guide

Memory is a local encrypted memory store for one owner. You capture notes and
documents into an inbox; a connected agent (Codex, Claude Code, or any MCP
client) scans them, drafts one Memory Review per batch, and nothing becomes
durable memory until you approve the exact revision with a macOS
owner-presence check. This guide covers installing the `memory` command,
creating your Store, everyday use of the local owner UI, the advising
conventions an agent follows when you ask for guidance, the staged-intake
conveyor for notes prepared outside Memory, and the one-time acceptance
rehearsal.

## Find a procedure

| Task | Section |
| --- | --- |
| Install or diagnose the command | [1–3](#1-install-or-update-the-everyday-command) |
| Create a Store, use the UI, approve or correct memory | [4–8](#4-create-your-store) |
| Import notes or troubleshoot | [9–11](#9-importing-an-existing-collection-of-notes) |
| Run synthetic owner acceptance | [12](#12-acceptance-rehearsal-tooling) |
| Reindex, inspect guards or repair relationships | [13–15](#13-search-reindex) |
| Browse, use graphs or terminal commands, back up, or dismiss a batch | [16–20](#16-browsing-and-editing) |
| Ask for advice, draft decisions or close an open loop | [21–23](#21-advising-sessions) |
| Prepare notes through staged intake | [24](#24-the-staged-intake-conveyor-at-a-glance) |

## 1. Install or update the everyday command

Clone the repository or unpack its source archive, then fetch the companion
wheels and install from that checkout:

```console
python3 third_party/fetch-wheels.py
uv tool install --python 3.14 .
```

If you are updating an existing installation of this project, use
`uv tool install --python 3.14 --force .`. Do not install an unrelated package
with the generic name `memory` from a package index.

Maintainers who want exact source/artifact/client parity can separately configure
and run `./tools/deliver.sh run`. That optional
[local delivery workflow](local-delivery.md) is not needed to try Memory or run
the public source checks. It is not configured by this repository.

Always keep the explicit
`--python 3.14` pin; never rely on whatever Python happens to be ambient.
Memory requires the Python 3.14 line, macOS 26 or newer, and Apple arm64.
The fetch command retrieves the versioned [Release assets](https://github.com/li-shangru/Memory/releases/tag/vendored-wheels-1)
into the ignored `third_party/wheels/` cache and verifies their checked-in hashes.
The repository source mapping uses that fetched SQLCipher companion; provide
its path explicitly when installing a standalone Memory wheel. The runtime attests
`memory-sqlcipher3` 0.6.2+sqlcipher4.17.0.memory1, SQLCipher 4.17.0, SQLite 3.53.3,
OpenSSL, and its required compile profile before reading Store content. Memory
uses MCP Python SDK 2 while continuing to serve installed clients that connect
through the legacy stdio initialize era.

To remove it:

```console
uv tool uninstall memory
```

## 2. Find the installed command

```console
uv tool dir --bin
command -v memory
memory --version
```

For an optional configured delivery profile, select this uv tool installation.
The commands below diagnose whether your shell resolves it correctly:

```console
test "$(dirname "$(command -v memory)")" = "$(uv tool dir --bin)"
case "$(command -v memory)" in "$PWD"/*) echo "refusing a checkout executable"; exit 1 ;; esac
```

If zsh reports `command not found: memory`, the uv tool bin directory is not
on your `PATH`. Fix it once, then start a fresh shell and repeat the three
discovery commands above before launching:

```console
uv tool update-shell
```

## 3. Prove the installed tool runs Python 3.14

The installed tool has its own environment. If you configured the optional maintainer delivery profile, its verifier checks
Python 3.14, package metadata/origin and complete source parity together:

```console
./tools/deliver.sh check
```

For an interpreter-only diagnostic that opens no Store:

```console
"$(uv tool dir)/memory/bin/python" -I -c 'import sys; assert sys.version_info[:2] == (3, 14)'
```

Failures name the drift and next step. Run the normal delivery workflow to repair
an outdated installation; changing the ambient Python does not update it.

## 4. Create your Store

`memory init` creates one encrypted Store and its macOS Keychain item. With no
options it uses the default home, `~/Library/Application Support/Memory`, and
an inbox inside it:

```console
memory init
```

To keep the inbox somewhere you can reach from other devices — for example a
folder synced through iCloud Drive so notes written on your phone land in it —
pass `--inbox` once at initialization:

```console
memory init --inbox ~/Documents/Inbox
```

The inbox directory may already contain waiting notes; they are kept and
captured by the first scan. The database, keys, claims, and staging areas
always stay in the private Store home — only the visible inbox may live
outside it, and it must be on the same volume. Hidden files such as
`.DS_Store` and iCloud placeholders are ignored by every scan and never enter
the Store.

Two things about the inbox are worth knowing before you point a synced folder
at it, because both are one-way:

- **A scan removes the original.** Capture takes custody: the file is moved
  into the encrypted Store and unlinked from the inbox. In a synced folder
  that removal syncs to your other devices too. The inbox is a queue, not a
  copy, and it is not a place to keep the only copy of anything.
- **A captured secret stays captured.** There is no redaction and no delete.
  If an API key, a password, or a note you did not mean to keep is scanned, it
  is retained in the Store permanently; corrections supersede a memory but
  never erase the source it came from. Removing it means building a new
  Store without it. Look at what is in the folder before the first scan,
  and keep credentials out of it.

An explicit `--home PATH` creates an additional, fully independent Store —
useful for the disposable rehearsal Store in section 12:

```console
memory init --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME
```

`memory paths --json` (add `--home PATH` for a non-default Store) prints the
resolved home, database, identity, and inbox paths.

Initialization requires real directory paths: a symlinked ancestor is refused.
If new-Store creation is interrupted, rerun the same initialization command with
the same home and Inbox. A complete, matching initialization intent resumes its
owned preparation and publication. Incomplete or changed artifacts, a changed
mount identity, or a missing key for an encrypted or published Store cause a
safe refusal. Keep those artifacts for diagnosis; do not remove them or create
a replacement key to force initialization. An existing Store with a missing
database is also refused. The exact recovery states are defined in
[design §4.1](technical-design.md#41-runtime).

## 5. Launch the local owner UI

```console
memory ui
```

For a non-default Store:

```console
memory ui --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME
```

`memory ui` starts one foreground process for one Store, binds only to
loopback on an unused port with a random one-process hostname, and opens your
default browser through macOS LaunchServices. The launch link is single-use
and is never printed, logged, or placed in a command line. There is no
daemon, no fixed port, no remote binding, and no external network use.

### Repository-development fallback

This is **not** the everyday command. Use it only when you are working on the
repository itself and want the checkout's exact code:

```console
uv sync --locked
uv run memory init --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME
uv run memory ui --home PATH_TO_DISPOSABLE_SYNTHETIC_HOME
```

## 6. Main navigation

The header appears on every page. It shows the Store product and schema
version, the runtime mode, Store availability, the pending-review count, the
staged Inbox-entry count, the source and current-memory counts, and search
coverage including unsearchable binary sources. A **Local Store** banner with
the resolved Store and Inbox paths is always visible. **Store status and
technical details** in the header opens `/status`, which repeats those counts
and adds the Store ID and the MCP and Skill contract digests.

**Pending Reviews** lists every draft and applied Memory Review. Open one to
see its complete item roster, item comparisons, source accounting, validation
blockers, and immutable revision history. Nine bounded operations are
available: add item, replace item, reject item, restore item, record a
no-memory decision, clear a no-memory decision, add a guard link, remove a
guard link, and revoke a retained guard link. Every operation creates a new
immutable draft revision with a new canonical digest; nothing is rebased for
you. Rejecting or restoring accepts a whole selection at once, and still
produces one revision rather than one per item. Leaving a form changes nothing, and unsaved edits warn before you
navigate away.

Each compact-roster item includes a short, bounded statement preview beside
its status and operation type. Its link opens that exact comparison directly,
even when the item would normally fall on a later comparison page. A
correction keeps the complete proposal and predecessor statements and evidence
visible, and marks wording, occurrence, validity, tag, stored-sensitivity, and
relevant guard-relation changes. When one item has more than 12 relationship
changes, its comparison points back to the complete relationship roster. The
compact relationship roster also clips each endpoint statement to a bounded
preview; each preview opens the exact draft comparison or current canonical
memory, where the complete statement and evidence remain available. The
final approval screen still renders the complete canonical review and binds
the same exact revision and digest.

**Inbox** is custody, not interpretation. Drop or choose a complete file and
it becomes one staged entry with its exact filename and byte length. The
navigation badge is a staged-count badge showing how many complete regular
files are staged right now. Staging creates no Source, no batch, and no
memory. The page states the handoff plainly, in these exact words:

> **Staged; ask a connected agent to process the Inbox.**

The connected agent calls the generic `inbox.scan` tool. The UI deliberately
has no scan control. Files that arrive in the inbox directly — dropped in
Finder, or synced in from another device — are captured the same way by the
next scan.

**Memory** lists current canonical memories with search, kind, tag, date, and
sensitivity filters. Search text and filter values are never placed in the
URL or browser history. Open a memory to read its statement, complete
lineage, exact source evidence, and approval/application provenance.

Validity appears beside each statement. **Current revision** identifies the
lineage head; it does not assert that the information still applies. The page
reports recorded start and end dates using their stored precision, calls a
missing end **No end date recorded**, and names future or uncertain effective
dates without filling in a day. For `loop:open`, `valid_to` is shown as a
revisit horizon: once it is past, the revisit is due, while the memory remains
canonical until an approved correction changes it. These labels are read-only
presentation and never suppress or expire a memory.

**Sources & Audit** enumerates every retained capture, including
unsearchable binary sources, and reports search coverage honestly. From there
the in-app Store audit binds one full-coverage snapshot and reconciles its
counts. Audit is in-app navigation only.

**Graph** shows approved source evidence and guard relationships. Section 17
explains its provenance and governance views.

## 7. Approving a review

Open the review, read the complete diff, then choose to approve. The approval
page names the exact revision, the exact canonical digest, and how many active
items, rejected items, and recorded no-memory decisions the approval accepts.

Approval then requires a successful macOS owner-presence check bound to that
exact revision, digest, and one-use challenge. That prompt is controlled by
the operating system. A browser form submission, a typed confirmation, a
pipe, a PTY, or a model argument is never owner-presence proof. Cancelling,
failing, timing out, letting the binding expire, or losing the session applies
nothing.

Compare the digest shown on the approval page with the digest on the review
page before you approve. If they differ, the review moved on and you are
looking at a stale page.

`memory approve CHANGE_SET_ID --revision REVISION_ID --digest DIGEST` is the
equivalent command-line path: it renders the exact unapplied review and then
requires the same macOS owner-presence check. It reads no typed confirmation.

If the exact revision was already applied, repeating the same approval request
does not reapply that revision, create another application, memory, or
approval, or prompt you again. It returns the same application, revision, and
memory identifiers with `idempotent_replay`. A carried-forward Store can still
commit standard writer-start compatibility healing and advance
`audit_generation`; that maintenance does not change the original application.
The result's `standing_guard_violations` is intentionally fresh each time: it
reports any current whole-Store guard sensitivity inversion without changing
the original application.

## 8. Correction notes

Canonical memory is append-only. To correct it, open the memory revision —
current or historical — and choose **Create correction**. The UI resolves the
current head for that lineage and shows it to you. Enter the exact correction
note text and capture it.

A correction note becomes exactly one owner-authored, restricted source in
one isolated single-source batch. It does not change canonical memory. The
Inbox then reports **Captured; awaiting Memory Review** with that already
sealed batch. Give a connected agent that exact batch identifier; it must read
that batch without scanning the Inbox, and it must never co-batch unrelated
staged files.

**Create correction cannot lower a sensitivity.** A memory may never be less
sensitive than the evidence it rests on, and a correction note is always
sealed `restricted`, so a successor drafted from one is restricted too. That
is the right default for something you typed about your own memory, and it
means the route for *lowering* a memory's sensitivity — the repair §14 and §15
call for when a guard sits above the claim it governs — is the ordinary Inbox
instead: write the note as a file, drop it in the Inbox, and tell the agent to
scan that batch at the sensitivity you want the correction to carry. Raising
works by either route only as far as `restricted`, which is the level every
correction note carries; to land on `sensitive` exactly, use the Inbox for
that too.

Give that note new wording rather than re-dropping the text you already
captured. Identical bytes are stored once, and that one blob's effective
sensitivity is the highest of any capture of it, so the same wording dropped
again at a lower level inherits the higher one and refuses exactly as before.

A loop-closure or re-horizon correction can be captured this same way, in
your own words — section 23 covers when an agent offers one and what the
successor carries.

## 9. Importing an existing collection of notes

To bring an existing body of notes into the Store, move or export them into
the inbox as plain files and let the ordinary capture workflow run:

1. Place a set of files in the inbox. A scan captures at most 64 files and
   256 MiB per batch (64 MiB per file); anything beyond that simply waits for
   the next scan, so large collections import over several batches. **Move
   copies, not originals**: a scan takes custody and unlinks the file from the
   inbox, and anything captured by mistake is retained permanently (section 4).
2. Ask a connected agent to scan and draft the batch's Memory Review.
3. Review, edit, and approve each batch in the UI before moving on.

UTF-8 text, Markdown, JSON, and CSV are fully searchable; PDF, PNG, JPEG, and
WebP are retained complete and readable while being reported honestly as
unsearchable. Reviewing batch by batch keeps every imported memory
evidence-linked and owner-approved.

Before each batch:

- Review the full files, including frontmatter, image pixels and metadata.
  Custody preserves those bytes; a later correction cannot redact the source.
- Choose the capture sensitivity before scanning. Recapturing identical bytes
  at a lower level cannot lower their effective sensitivity (section 8).
- Keep a claim's material caveat in its statement and review explicit guard
  relationships. A guard cannot sit above the claim it governs (section 14).
- Draft a correction against the existing lineage and current head instead of
  adding a contradictory second memory (section 8).
- Retain binary evidence when its original form matters, and account for its
  search gap. An empty search is not proof of absence: enumerate and read
  complete sources when coverage matters.

## 10. What the UI deliberately cannot do

- The browser has no record export or download. Use the local, owner-authenticated
  [plaintext JSON export](#plaintext-json-export) when you need all retained records.
- There is no raw database access, no SQL entry point, no database path, and
  no Keychain access from the browser.
- Accepted memory is never edited directly. Every change goes through one
  complete change set, one exact immutable revision and digest, one direct
  owner approval, and the atomic apply.
- The UI never scans the Inbox for you and never interprets a source.

## 11. Shutdown and troubleshooting

Stop the UI with `Ctrl-C` in its terminal, or send it `SIGTERM`. On exit it
invalidates every session, cancels any pending owner-presence prompt, and
releases its UI-session lock.

Logs and error pages are deliberately content-free. A failing request renders
`Request unavailable` and nothing else; the UI never writes your content,
filenames, paths, queries, opaque identifiers, digests, or approval material
to a log.

Common cases:

- **`command not found: memory`** — run `uv tool update-shell`, start a fresh
  shell, and repeat the discovery commands in section 2.
- **The UI refuses to start** — a second UI process for the same runtime fails
  before opening a listener. Stop the other process first. Different runtimes
  remain independently launchable.
- **Startup fails closed** — a missing, locked, or foreign Store is refused by
  design. Initialize the Store first with `memory init`.
- **An edit reports a conflict** — the review advanced to a newer immutable
  revision. Nothing was applied. Read the displayed old and current state and
  retry explicitly if the edit is still correct.
- **The UI or a scan reports recovery issues** — run `memory recover`. It
  repairs crash residue on its own, including a correction the UI preserved
  after an interrupted submission, which it captures into the Store exactly
  as if the submission had completed. An issue that survives `memory
  recover` is real custody debt being reported, not noise; nothing in the
  private staging area is ever deleted by guesswork, and you never need to
  edit that directory by hand.
- **Every staged-intake helper command refuses after an upgrade** — a
  transaction receipt or pending intent written by an older helper version
  is refused rather than reinterpreted. Run the helper's escape hatch once,
  from the installed skill directory:

  ```sh
  python3.14 -B ~/.claude/skills/staged-memory-intake/scripts/staged_memory_intake abandon-unsupported
  ```

  It sets aside exactly the unsupported records, keeps their bytes for you
  under `abandoned-` names, and never touches current or unrecognized
  state. Then restart the interrupted work.

## 12. Acceptance rehearsal tooling

`tools/prepare-ui-acceptance.py` prepares one disposable Store populated with
fixed synthetic cases for the owner acceptance rehearsal. Copy
`docs/acceptance/v1-acceptance.md` to a private location outside the checkout and
record the outcomes there; leave the tracked template unexecuted.
The helper is development tooling, is excluded
from the wheel, and validates the reviewed
`tests/fixtures/synthetic_ui/manifest.yaml` on every run and every resume.

Run every block below in one shell, in this exact order. Each block is
copy-pasteable and uses only variables this section already defined. Every
invocation runs the installed tool environment's own interpreter in isolated
mode, from a temporary working directory outside the repository, with absolute
paths.

### 12.1 Set up the acceptance shell

Replace the two placeholder values with your own absolute paths, then run the
block unchanged. `MEMORY_UI_HOME` must name a disposable home that is absent
or an empty directory; the preparer initializes either one and refuses a path
that already holds unrelated files. Choose a path with no symlinked
components: the Store's custody walk refuses symlinks, and on macOS a raw
`mktemp -d` result traverses the `/var` symlink — canonicalize first with
`cd -P`, or use a directory under your home folder:

```sh
MEMORY_UI_REPO=ABSOLUTE_PATH_TO_THE_REVIEWED_REPOSITORY
MEMORY_UI_HOME=ABSOLUTE_PATH_TO_A_DISPOSABLE_SYNTHETIC_HOME
MEMORY_UI_PYTHON="$(uv tool dir)/memory/bin/python"
MEMORY_UI_CLI="$(uv tool dir --bin)/memory"
MEMORY_UI_TOOL="$MEMORY_UI_REPO/tools/prepare-ui-acceptance.py"
MEMORY_UI_MANIFEST="$MEMORY_UI_REPO/tests/fixtures/synthetic_ui/manifest.yaml"
MEMORY_UI_STATE=$(mktemp -d)
MEMORY_UI_FIXTURE=$(mktemp -d)
cd "$MEMORY_UI_STATE"
"$MEMORY_UI_PYTHON" -I -c 'import sys; assert sys.version_info[:2] == (3, 14)'
```

`MEMORY_UI_STATE` holds the mode-0600 ephemeral acceptance state; delete it
with the disposable Store when the rehearsal ends. `MEMORY_UI_FIXTURE` is the
owner-selected directory the file chooser will read from. Neither is inside
the Store.

### 12.2 Prepare the three capture phases

This pauses twice for the real macOS owner-presence decision. Nothing in the
tool simulates, automates, or bypasses that decision. It is resumable: rerun
the same command after an interruption and it revalidates every recorded
boundary before continuing.

```sh
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE"
```

### 12.3 Write the drag/drop fixture

This writes the one fixed `SYN-UI-UPLOAD-001` file into the owner-selected
directory, outside the Store. It never prints the path and never places the
case in the Store or Inbox.

```sh
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --write-upload-fixture "$MEMORY_UI_FIXTURE"
```

### 12.4 Read the review case in an interactive terminal

The operator view revalidates the recorded manifest digest and renders that
case's exact synthetic text only to a controlling terminal. It refuses
redirected or noninteractive use, and it never copies that text into state,
records, logs, prompts, or client configuration.

```sh
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --operator-view SYN-UI-REVIEW-002
```

### 12.5 Run the isolated upload task

Set the client kind, the validated absolute installed executable, and the
exact model identifier, then launch. The launcher never resolves a client
through `PATH` and never accepts a bare command.

```sh
MEMORY_UI_CLIENT_KIND=codex
MEMORY_UI_CLIENT=ABSOLUTE_PATH_TO_THE_INSTALLED_CLIENT
MEMORY_UI_MODEL=EXACT_MODEL_ID
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --launch-client "$MEMORY_UI_CLIENT_KIND" \
  --client-executable "$MEMORY_UI_CLIENT" \
  --model "$MEMORY_UI_MODEL" \
  --task SYN-UI-UPLOAD-001
```

Use `claude` instead of `codex` for `MEMORY_UI_CLIENT_KIND` to run the same
task with Claude Code, with that client's own absolute executable and model.

### 12.6 Read the correction case in an interactive terminal

```sh
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --operator-view SYN-UI-CORRECTION-004
```

Enter that exact displayed text as a correction note in the local owner UI
from the historical revision, then read the already-sealed batch identifier
the Inbox reports under **Captured; awaiting Memory Review**.

### 12.7 Record the sealed correction batch

This step is **required** before the correction launch. The correction task
binds to exactly this already-sealed batch, and `--launch-client … --task
SYN-UI-CORRECTION-004` refuses to start until it is recorded.

```sh
MEMORY_UI_BATCH=EXACT_SEALED_BATCH_ID_SHOWN_IN_THE_INBOX
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --record-correction-batch "$MEMORY_UI_BATCH"
```

### 12.8 Run the isolated correction task

```sh
MEMORY_UI_CLIENT_KIND=claude
MEMORY_UI_CLIENT=ABSOLUTE_PATH_TO_THE_INSTALLED_CLIENT
MEMORY_UI_MODEL=EXACT_MODEL_ID
"$MEMORY_UI_PYTHON" -I "$MEMORY_UI_TOOL" \
  --manifest "$MEMORY_UI_MANIFEST" \
  --memory "$MEMORY_UI_CLI" \
  --home "$MEMORY_UI_HOME" \
  --state-root "$MEMORY_UI_STATE" \
  --launch-client "$MEMORY_UI_CLIENT_KIND" \
  --client-executable "$MEMORY_UI_CLIENT" \
  --model "$MEMORY_UI_MODEL" \
  --task SYN-UI-CORRECTION-004
```

### 12.9 What the launcher guarantees

Every run binds to the same prepared disposable `--home` that section 12.2
created; none uses a default Store and none edits your client configuration.
Codex runs with `--ephemeral --ignore-user-config`. Claude Code runs with
`--strict-mcp-config --setting-sources project` plus one mode-0600 temporary
MCP configuration that names only that disposable home; the launcher deletes
that file and verifies its absence immediately after the child exits.

Neither task reveals a hidden expected conclusion. The upload task only asks
the client to inspect the prepared Store and call generic `inbox.scan`
exactly once. The correction task only supplies the already-sealed correction
batch identifier and generic read, review, and apply instructions.

Every subcommand revalidates the runtime named by `--home` before it writes a
fixture, records state, renders a case, or starts a client, so a mistyped
home fails closed instead of reaching an installed client.

## 13. Search reindex

A Store needs an explicit projection rebuild whenever its source or memory FTS
DDL is noncanonical. Version 1.2.0 added `original_name` and the canonical
rowid/`capture_rowid` shape that ties each searchable source row to its
authoritative capture. Bring the projections current with one command, run
once:

```console
memory reindex
```

This drops and rebuilds the source and memory search projections from your
retained sources and current memories in one atomic step. It is required for
any noncanonical FTS DDL, including a tokenizer or canonical source-row shape
that is behind. Guard auxiliary tables and columns heal additively when any
writer starts, so an ordinary apply or replay may commit that maintenance; it
does not make noncanonical FTS DDL current. Reindex reads content only to
reproject it: no source, memory, review, or approval changes.

Until you run it, the header banner says so and `store.status` reports
`reindex_required`; a connected agent that sees the same signal tells you to
run it before trusting a thin result instead of searching around the gap.

Reindexing advances the Store's audit generation, the same counter every
owner-UI list and search page is bound to. If you have a browser search or a
paginated list open mid-walk when you reindex, its next page reports a stale
cursor instead of continuing, and you restart that search from the first
page. This is intended: the projection that walk was reading has just been
replaced.

## 14. Guard links

A guard is an owner-approved memory that qualifies, permits, corrects, or
restrains another memory: a hedge ("self-reported, not verified"), a standing
permission, a correction that supersedes an older claim, or a restraint that
counterbalances a preference. A connected agent adds a guard link whenever a
new or existing memory plays that role for another, so that retrieving the
governed claim always retrieves its guard alongside it.

**The sensitivity rule.** A guard can never be more sensitive than the claim
it governs — if the claim is readable, its guard must be too. The Store
enforces this the moment an application touches the link: it refuses the
whole apply with a message naming the guard, the claim it governs, and both
effective sensitivities whenever the guard would end up higher. Lower the
guard's sensitivity, or raise the claim's, and try again.

**Links are append-only.** Once applied, a guard link is never deleted. If a
guard's wording is wrong or needs sharpening, correct it the way you correct
any memory: open its current revision and create a correction that supersedes
it — subject to §8, because the successor still may not outrank the claim it
governs, and **Create correction** can only produce a `restricted` one. The
link is recorded against the lineage, not the wording, so your
correction keeps governing the same claim automatically — you never re-add the
link. If the *link itself* is wrong — the right guard attached to the wrong
claim — supersession cannot help, and §14.1 is the repair.

**In Memory Review**, a proposed guard link renders as a statement pair: the
guard's statement and sensitivity dot, an arrow, then the sensitivity dot and
statement of the claim it governs. Both sensitivities sit side by side, so an
inversion is visible before you approve. The compact roster bounds both
statement previews and links each one to its complete draft comparison or
canonical-memory detail. The approval page keeps the exact pair in full, the
same way it keeps everything else there: never collapsed behind a disclosure.

**In the editor**, open a review's guard links to remove one individually, or
add a new one directly — most links come from the agent while it drafts;
this is your own direct control for the cases it did not cover. The add form
asks for a guard side and a governed side, and each side takes either a
draft item from this same revision or the ID of an existing lineage already
in the Store, never both. If the Store refuses your addition or removal — a
link that already exists, one naming something the draft cannot resolve, or
one that would stand as a violation — the form reappears with a plain
sentence naming what happened and everything you typed still in place;
nothing you entered is lost.

### Two things that can surprise you

**Re-proposing a link that is already a violation blocks the apply.** If you
or an agent explicitly add a guard link the Store already holds, and that
link is currently a sensitivity inversion, applying blocks instead of quietly
reconfirming it — asserting the link again counts as touching it. You cannot
make a standing violation official by restating it; you have to fix the
sensitivity first.

**A review with no guard links at all can still be refused.** Correcting or
adding a claim that happens to sit on either end of an existing guard link is
enough: if that link is a sensitivity inversion, the apply is refused even
though this review never mentions a guard. The refusal names both sides of
the link and both sensitivities, exactly as any other guard refusal does —
read it to see which memory to correct.

### 14.1 Repairing a mis-attached guard

A guard attached to the wrong claim rides along on every retrieval of that
claim, and no amount of rewording moves it: the link names two lineages, and
superseding either one preserves the link exactly as it stands. Revoking the
link is the repair.

Revoking does not delete anything. The link stays on record and the governance
graph keeps drawing it — dashed and faded, never in the red the lens reserves
for a guard standing above the claim it governs, because a link that no longer
governs anything cannot be that. What stops is its effect: the guard no
longer accompanies the claim in `memory.search` or `memory.get`, no longer
appears in the claim's guard roster, and no longer counts toward the guard
invariant — so if the mis-attachment was a standing violation, revoking it is
what clears it.

The recipe:

1. Find both lineage IDs. A memory's detail page in the local owner UI shows
   its lineage, its guards, and what it governs; the governance graph draws the
   same relationship as an arrow from guard to governed claim.
2. Put a short note in the inbox saying what the mis-attachment was, and scan
   it. The note becomes the source that explains the repair, so the change set
   has something to account for. Nothing forces you to create a memory from it
   — mark it no-memory with a reason and the review is complete.
3. In that review, open **Revoke a retained guard link** and enter the guard
   lineage and the governed lineage. Both sides must name lineages the Store
   already holds, and the link between them must still be standing; a pair the
   Store never linked is refused by name rather than accepted as a no-op.
4. Read the approval page. It renders the revocation in its own section, as the
   same statement pair every guard link renders as, so you approve exactly the
   relationship you are withdrawing.
5. Approve. The revocation applies inside the same atomic transaction as
   everything else in the revision, and the result reports no standing
   violation for the pair you just revoked.

**Revocation is final for that exact pair.** Adding the same guard back later
is refused, naming both lineages, rather than silently doing nothing. If the
guard genuinely does belong on that claim, say so as a new memory — a new
guard lineage, linked to the claim. Not a supersession of the revoked guard:
a link is keyed by lineage, and superseding keeps the lineage, so re-linking
the clarified wording names the very pair that was just made final and is
refused. Writing the caveat into the claim itself works too.

**Check the pair before you stage it.** A staged revocation cannot be taken
back out of the review: `remove_guard_link` reaches only proposed links, a
second `revoke_guard_link` is refused as already staged, adding the pair back
is refused as contradictory, and the next revision carries the revocation
forward. One batch has one change set, so there is no fresh review to start
either. A revocation staged in error leaves the review approvable only with
it, or not at all — which is why the approval page renders the pair, and why
step 4 above asks you to read it.

A revoked link also stops consuming one of the claim's guard slots, so
revoking a mis-attachment gives the claim its capacity back rather than
spending it permanently on a mistake.

### Standing violations

An apply — through `memory approve`, the local owner UI, or a connected
agent's MCP apply — can still succeed while reporting standing guard
violations: guards already on record whose effective sensitivity has drifted
above the claim they govern, most often because a later capture raised a
shared source's sensitivity after the link was made. The Store allows the
apply that revealed them, since they are not what that apply touched, but
tells you about them so nothing sensitive quietly rides along an unguarded
claim. Repair each one with an ordinary correction that lowers the guard's
sensitivity — through the Inbox, for the reason §8 gives, not through **Create
correction** — or raise the claim's. If the guard does not belong on that
claim at all, revoking the link (§14.1) clears the violation too, and is the
repair that also stops the wrong guard riding along. The repair review below
finds violations; it does not clear them.

## 15. Review existing guard relationships

Use this review when existing memories contain caveats or constraints whose
guard relationships were never recorded, or when a standing violation needs
repair. The report proposes candidates; only an exact approved review changes
the retained relationships.

1. If the header banner still asks for it, reindex first (section 13).
2. Run `memory lint guards`, or open **Guard candidates** from either graph
   lens, which shows the same report as readable statement pairs with a link
   straight into the review edit. The report is advisory: it writes nothing and
   changes nothing. A candidate requires guard vocabulary in the candidate's
   own wording and a shared evidence source with the memory it would
   govern — both are necessary gates, not hints. Membership in the same
   original batch is the only purely supporting signal: it can strengthen an
   already-qualifying pair but never qualifies one by itself. The same
   report also names every standing violation already on record. Its output
   holds your own memory statements, so keep it off the record — never paste
   it into a file that enters Git, and hand it only to the trusted agent
   doing this repair. The command prints prose by default; add `--json` when
   an agent is going to parse it. If it reports more candidates than one
   change set can hold — the panel says so in words, and `--json` reports
   `truncated_candidate_count` above zero — plan on repairing in more than
   one pass.
3. Drop a one-line note into the Inbox — its only job is to give the repair a
   batch and an audit trail — then ask a connected agent to scan it, read the
   lint report, and build one links-only change set: pruning the report's
   candidates down to the real relationships, and adding any further link
   the lint heuristics missed but the agent can see directly. Lint seeds this
   change set; it does not bound what the agent may propose. The agent marks
   that note's own source no-memory as part of the review — expect to see it
   in the diff; it is not a sign that anything was missed.
4. Before approving, scan the review's guard-link rows for a colour step: a
   guard's sensitivity dot rendered redder than the claim it governs. Reject
   those pairs. Each needs an ordinary correction lowering the guard's
   sensitivity (or raising the claim's) before you re-link it in a later
   pass — a links-only change set cannot fix a sensitivity inversion, and
   the Store refuses the whole apply while one is included. A correction that
   lowers has to arrive through the Inbox at the sensitivity you want; §8
   explains why **Create correction** cannot do it.
5. Review the change set like any other: each proposed pair shows both
   statements and both sensitivities. Reject the misses, then approve once.
6. Run `memory lint guards` again. Candidates you rejected will reappear on
   this and every future run — lint keeps no memory of a rejection. The
   repair is done when every remaining candidate is one you have already
   judged, and every standing violation you intend to fix has been cleared —
   by its correction, or by revoking the link where the guard did not belong
   on that claim at all.

## 16. Browsing and editing

Browsing pages — the memory index, source list, review list, and Inbox —
show no raw identifier or digest; open the collapsed **Technical details**
disclosure on any detail page for the full IDs, digests, and a copy button
for each. Timestamps read as humanized local time, never a raw epoch number.
The UI follows your system's light or dark appearance automatically. Memory
pages show a memory's guards and what it governs beside its statement, not
as a separate lookup. The memory index adds a row of kind chips — fact,
event, preference, relation, insight — each a clickable filter carrying its
own count. The one page that keeps every identifier in full and uncollapsed
is the review approval page: that exact enumeration is what you are
approving, so nothing there is shortened or hidden behind a disclosure.

Search keeps your selected kinds, sensitivity levels, tags, and occurred-date
bounds when you refine it. Choosing a kind chip keeps the other filters.
Guards and governed memories show short previews, with **Next guards** or
**Next governed memories** after 50 entries. Open a linked memory to read its
complete statement and evidence.

While a form is submitting, its controls pause. If the request fails, the
page keeps your entries, restores the controls, and shows an inline notice.
A lost response may still follow a completed action; check the result before
submitting again. Unsaved text stays only on the current page.

## 17. The graph view

**Graph** in the main navigation draws the Store's approved relations. It
draws only those: batch custody, source evidence, and guard links. Nothing on
it is inferred from similarity or wording, so two memories with no line
between them are two memories with no *approved* relationship — not two
unrelated ideas.

**Provenance** answers "what is this resting on?". The picture is organised by
**your own areas** — the `aspect:` tag you put on every memory. Each area owns a
wedge with its name written along the arc, the sources belonging to that area
form the ring inside it, and each memory is placed against the source that
evidences it. A long spoke is a document that produced a lot; a marker on the
ring with no fan is a source that produced nothing at all; a memory drawn inside
the ring rests on two documents and bridges between them.

Three wedges are not areas you wrote. **Across areas** holds sources whose
memories span more than one area. **No area recorded** holds sources whose
memories carry no `aspect:` tag. **No memory retained** holds sources that
produced nothing, which have no area to inherit. An area whose wedge is too
narrow to hold its own name goes unlabelled rather than writing across its
neighbours; hover its nodes, or use the filters.

Inbox batches are deliberately *not* the organising axis. A batch records that
some files were sealed together at one moment — an audit fact, not a subject —
and batches accumulate forever without ever merging, so grouping by them would
make position on the ring mean "arrived the same day" while looking like
relatedness. Batch custody is still on every source's detail page, in the
Inbox, and in the audit.

**Governance** answers "what qualifies this?". It drops custody entirely and
keeps only guards and the claims they govern. A link drawn in the restricted
colour is a guard held above the claim it governs — a standing violation of
the guard invariant, to be repaired through §15, not a rendering fault. A
restricted claim sitting alone with no link is equally worth a look.

Colour on both lenses means one thing: **effective sensitivity**, the same
grey/amber/red the dots use everywhere else in the UI, so a restricted cluster
is visible at a glance. Kind is named in every node's hover label and is
selectable in Filters.

**Size carries weight.** A memory drawn larger rests on more evidence, so a
claim held up by a single excerpt is visibly thinner than one held up by three.
A source drawn larger produced more memories, and a source at the floor size
produced none at all. Area rather than radius carries the count, so a mark
twice as wide means four times as much.

Hovering a node names it and dims everything else; selecting one opens it.
Zoom in past roughly 2.5x and **source filenames appear** beside their markers.
Memory labels appear in the hover panel; open a memory to read its complete
statement and evidence.
You can drag a node to untangle a knot, drag the background to pan, and
scroll to zoom. Every memory detail page carries the same picture clipped to
one hop — the memory, the sources beneath it, and the claims it links to.

Filters mirror the ones on the memory index and behave the same way, with one
consequence worth knowing: a filter asks a question about *memories*, so
sources and batches stay only where they still explain one that survived. A
source that produced nothing cannot answer such a question, so it is hidden
whenever a filter is active. That is not the Store forgetting it — clear the
filters and it is there.

Two honest limits. The view refuses to draw a Store above its node ceiling
rather than drawing part of one and looking complete; if you reach that, it
says so with the real number. And on a Store that predates guard links, the
governance lens says the links are unavailable rather than drawing an empty
picture that would read as "no guards exist".

## 18. Terminal commands beyond the UI

The owner UI is the supported human surface, but a few things are easier — or
only possible — from a terminal, and one of them matters most exactly when the
UI will not start.

```console
memory status --json
```

The same counts the header shows, including how many reviews are waiting, plus
the Store ID and both contract digests. This is the one to reach for when the
UI is down: it opens the Store read-only and answers without a browser.

```console
memory reviews --json
```

Up to 500 of the oldest open drafts, each with its change-set ID, current
revision ID, digest, and batch. A review created by an agent whose session then
ended is otherwise invisible from a terminal; this is how you find it, and the
change-set ID, revision ID, and digest are exactly what `memory approve` wants.
`has_more: true` means additional drafts exist; open the paginated **Pending
Reviews** area in `memory ui` to enumerate the remainder.

```console
memory recover
```

Reconciles interrupted captures and reports anything that needs your
attention. The owner UI runs this at startup, so an owner who uses the UI
never needs it — but a Store driven only by a connected agent never reaches
that path, and this is how it gets reconciled.

```console
memory skill check --target PATH
memory skill install --target PATH
```

Compares, and replaces, one client's copy of the packaged Skill. `check`
never writes. Run `install` for every client copy after upgrading: a stale
copy teaches an agent a contract the Store no longer serves, and the Skill
itself now tells the agent to ask you to run this when it notices.

```console
memory mcp config --format json
memory mcp config --format toml
```

Prints this Store's stdio server entry for a client configuration file, with
`--home` already resolved when the Store is not on the default home. Your
client wraps the entry in its own container key — see
[Client setup](client-setup.md). Add `--trust-elicitation` only if you
deliberately want that client's own elicitation prompt to count as your
approval; by default an MCP apply refuses to the owner-presence handoff
instead, and the printed entry carries the opt-in visibly when you choose
it.

```console
memory relocate-inbox --to ABSOLUTE_PATH
```

Moves an initialized external Inbox without moving the Store home. Stop the
UI and connected clients first, create the new parent as an owner-controlled
mode-0700 directory on the same volume as the Store, and the destination
itself must be absent. Success prints only `relocated`, `recovered`, or
`current` in a JSON status object. If the process is interrupted, rerun the
exact same command and destination — do not move the directory or edit
`runtime.json` by hand; every ordinary Store command refuses until that
recovery completes. The Store home, database, claims, staging, locks, and
Keychain item do not move. Restart connected clients after success so they
resolve the new Inbox path.

The optional staged-memory-intake companion also owns coordinated notes-root
maintenance. Its current folder names are `01_Pending`, `02_Staged`,
`03_Prepared`, and `04_Inbox`. If helper `status` reports
`layout_migration_required`, stop the UI and connected clients and run the
loaded companion helper without supplying any path:

```sh
<python> -B <loaded-skill-directory>/scripts/staged_memory_intake \
  migrate-layout
```

It renames only an exact legacy four-folder layout, preserves every directory
identity, and rebinds Memory's Inbox through the supported relocation
command. Success is `migrated`, `recovered`, or `current`. If interrupted or
reported as `layout_migration_pending`, rerun that same command; every other
helper command stays blocked. Never rename the folders in Finder, use a raw
filesystem move, create aliases or symlinks, edit either private config, or
inspect a child to resolve a refusal. A collision, mixed layout, changed
identity, unexpected root entry, or unsafe permission requires stopping
rather than guessing. Restart connected clients after success.

The companion also owns coordinated notes-root renames. If its configured
`04_Inbox` is a child of the root you want to rename, stop the UI and
connected clients, require helper `status` to report configured with no
active transaction, and run:

```sh
<python> -B <loaded-skill-directory>/scripts/staged_memory_intake \
  relocate --to ABSOLUTE_NOTES_ROOT
```

The destination must be absent. The helper parks the exact `04_Inbox`
privately, renames the existing root without copying it, returns `04_Inbox`
through Memory's supported transition, and rebinds its own configuration. A
root-level `.obsidian` metadata directory is carried without inspecting its
contents. Success is `relocated`, `recovered`, or `current`. An interrupted
move is resumed only by rerunning the exact same command and destination;
every other helper command refuses until that recovery completes. Never
rename that root in Finder, use a raw filesystem move, or edit either
private configuration. Restart connected clients after success.

If the stored directory identity is stale, never edit the helper config. The
companion has an explicit `--adopt-current-authority` relocation mode, but
use it only after you confirm that the already-configured path is the current
intended notes root and `memory paths --json` resolves that root's exact
`04_Inbox` child. Only then rerun the relocation with that flag: it validates the same paths,
expected private layout, and current Memory binding, atomically refreshes
only their device/inode identities, and refuses an unexpected path, layout,
or active transaction. To move elsewhere while authority is stale, add the
flag to the ordinary relocation command; the helper adopts the confirmed
authority before the durable move.

Every command that opens a Store takes `--home PATH` for a non-default one.
`memory skill check|install` is the exception, and deliberately: it compares a
file against the Skill packaged inside the installed tool, so it opens no
Store, needs no Keychain, and takes only `--target`. When a command refuses, it
prints its code and, on the next line, the details naming what to fix.

## 19. Backing up the Store, and moving it to another Mac

There is no backup or restore command. Plaintext JSON export below is a content
copy, not a restorable Store backup. The Store home
is ordinary files, so an ordinary filesystem backup — Time Machine, or any
tool that copies the home while nothing is writing to it — is the whole
mechanism. `memory paths --json` prints the home to back up.

**The database alone is useless.** The encryption key is not in the home. It
lives in a macOS Keychain item under the service `memory` with your Store ID
as the account, in your login keychain. A copy of `store.sqlite3` without that
Keychain item cannot be opened by anything, including this product — that is
the point of the design, and it is also the way a restore goes wrong. Back up
the keychain, or accept that the copy is inert.

Copy the home while the Store is idle. Stop `memory ui` and any connected
agent session first. If you cannot stop every Memory writer, do not make an
ordinary file-level copy; wait until the Store is idle. This release has no
supported online-backup command. Copying `store.sqlite3`,
`store.sqlite3-wal`, and `store.sqlite3-shm` together while writers are active
is still not an atomic backup: a checkpoint or WAL reset can interleave the
separate copies.

To move a Store to another Mac, under the same owner:

1. Stop the UI and every connected agent.
2. Copy the whole Store home to the new machine, **at the same absolute
   path**. Not merely the same layout: the same path, character for character.
3. Move the Keychain item across. Migration Assistant and a login-keychain
   restore both carry it; a fresh account does not. Without this step every
   command fails closed with a missing-key error, which is correct behaviour
   and not corruption.
4. Install the command on the new machine (section 1) and run
   `memory paths --json`. Check the `inbox` it prints is under the new home,
   not merely that the command succeeded — see the caveat below.
5. Re-run `memory mcp config` so connected clients name the right Store.

**The recorded inbox path is absolute, and whether it can be re-pointed
depends on whether the old path still exists.** `memory init` writes the
inbox location into `runtime.json` as a full path and validates its shape on
every load, without checking that it exists. A home that lands anywhere
else — a different short user name, a different folder, a Store you kept
outside the default location — still resolves that old path. `memory paths
--json` and `memory status --json` both succeed while pointing at it, so
neither confirms a move, and `memory init --inbox` refuses to change a
recorded inbox. The relocation transition (section 18) binds to the
existing source directory, so there are exactly two cases: if the recorded
external inbox still exists at its old absolute path on this machine and
the destination shares the new home's volume, one `memory relocate-inbox
--to NEW_ABSOLUTE_PATH` re-points it; if the old path no longer exists, the
transition refuses — keep using the Store on the original machine and treat
re-pointing as unsupported. The internal inbox (`<home>/inbox`) travels
with the home and never needs re-pointing.

The same rule covers an inbox configured outside the home with `--inbox`: it
must exist on the new machine at its recorded path, on the same volume as the
home, before the first command runs.

### Plaintext JSON export

Export **all retained data**, including sensitive/restricted memories, original
source bytes, superseded history, draft/rejected review items, evidence and guard
relationships:

```console
mkdir -m 700 "$HOME/Documents/Memory Exports"
memory export --output "$HOME/Documents/Memory Exports/all-memory.json"
```

For another Store, add `--home PATH`. The output directory must already exist,
be owned by you with mode 0700 and no extended ACL entries, and be outside the
Store and its Inbox. Symlink
paths and existing destination files refuse; choose a new filename for each export.

Each run displays a fresh macOS owner-presence check naming the plaintext full
scope and destination. Cancellation, failure or timeout produces no export; stop
after that attempt. The output is an unencrypted UTF-8 JSON file with mode 0600,
ready for local machine/LLM processing. Providing it to another service discloses
its complete contents. The command prints only a content-free success summary.
It never changes canonical memory.

The versioned [format reference](export-format.md) describes all records and
base64 source bytes. Search indexes, scan scheduling, uncaptured Inbox files,
filesystem recovery state and encryption keys are excluded. There is no JSON
import/restore command. Filesystem backup remains the separate procedure above.
An interrupted export may retain a private `.memory-export-*.tmp` file in the
chosen directory; the final filename appears only after the complete file is
flushed. A cleanup refusal is an error, never a successful export.

## 20. Dismissing a batch without creating memory

Sometimes a scanned batch turns out to hold nothing worth keeping. There is no
"abandon" command, and deliberately so: a batch that was sealed is part of the
audit record, and making it disappear would be the one operation that removes
history. Dismissal is expressed as a review that decides against every source.

1. Open the batch's review and reject every proposed item.
2. Give every source in the batch an explicit no-memory reason — that is what
   "reviewed and decided against" means here, and a review that leaves a
   source unaccounted for cannot be approved at all.
3. Approve the resulting revision once, as you would any other.

The apply creates no memory. The batch, its sources, the reasons you gave, and
the approval all remain readable in Sources & Audit, so the record says the
batch was reviewed and produced nothing — which is a different and more useful
fact than the batch having never existed.

The sources stay in the Store. Dismissing a batch is a decision not to
interpret it, not a delete; see section 4 on what capture is one-way about.

## 21. Advising sessions

When you ask a connected agent for advice, guidance, a decision, or anything
about you as a person — rather than a plain factual lookup — the packaged
Skill has it orient in your own approved memory before answering. Advice
stays read-only: nothing about an advising session writes to the Store.

Orientation rests on two reserved tags you curate like any other memory
content:

- **`standing`** marks the durable preferences, insights, and constraints you
  have approved for exactly this use. At the start of advice the agent walks
  every `standing` memory without an `aspect:` filter and holds what it finds
  against the answer. An `aspect:` area may organize those complete results
  afterward, but cannot exclude standing memory from orientation. The set is
  governed claims — guards attached, sensitivity as metadata — not a persona:
  an agent must never recite it back as a portrait of you. If the walk
  substantially exceeds forty items, the agent reports that the set has
  outgrown its purpose rather than trimming it silently.
- **`loop:open`** marks commitments and follow-ups, with `valid_to` as each
  loop's horizon. The agent rebuilds this list every session — a loop closed
  since the last session must vanish, not linger — and surfaces only loops
  that are due or bear on your question, honoring any guard that restrains
  follow-up.

An explicit hypothetical is local to the session: it does not correct your
retained memory. The agent notes any material conflict with current evidence,
then reasons within the assumption you supplied.

The answer itself passes five checks. *Application*: the agent names which
retained preferences, insights, and guards bear on the answer, or states that
none do. *Priority*: it preserves an ordering only when your retained evidence
or stated scenario supplies one; it does not invent a hierarchy.
*Proportionality*: it distinguishes reversible steps from irreversible
commitments and uncertain future complications from present effects, using
real constraints to shape conditions and exit plans rather than treating every
risk as a veto. *Freshness*: a past open-loop horizon means its revisit is due,
not that its commitment expired. Other expired validity is never asserted as
current, and an old capture date on a claim whose tags signal
volatility is a cue to re-verify before leaning on it. *Candor*: stored
disagreement outranks session agreement — when a guard or your own retained
evidence cuts against the answer you appear to hope for, the agent leads with
it, then advises. Candor does not mean default pessimism.

Membership is review work, not advice. Adding or removing `standing` or
`loop:open` on a memory is an ordinary correction, evidenced by a note or
captured correction in its own batch and approved like anything else. No
advising session retags anything on its own.

### Asking for open items

Ask for personal open items, reminders, or things to revisit. The agent retrieves
the complete current list and shows due, upcoming and undated items, with their
supporting evidence and qualifications. A month/year containing today stays
visibly uncertain until that period has passed. A due item remains open until you
record its completion; reading or discussing it does not close it.

An ordinary note can establish an open item without being a decision note. It
must express an unresolved commitment, reminder or intention to revisit. A note
describing a completed review alone does not create a recurring commitment.
During normal intake, qualifying notes receive the open-loop tag and a supported
next revisit horizon, or no date when the source gives none.

A relative reminder such as "ten days after the date stated in this note" uses
that explicit source date. Without a clear anchor it stays undated rather than
acquiring the date it happened to be processed. A periodic review keeps its
recorded cadence, but the agent does not invent a next date or silently roll it
forward. Record the next horizon or an outcome through the existing correction
workflow. Separate follow-ups within one note retain their individual dates.

If you make a new reminder request in conversation, the agent can draft a note
for you to place or capture for normal review. For "in ten days," that draft
includes the known local request date and calculated horizon for your review.
Conversation alone does not save it. Recall does not scan the Inbox or create a
Review, and pending or unclassified
notes are distinguished from approved tracked items. Missing coverage is stated;
an empty tagged list does not establish that every note contains nothing open.
This is on-demand recall and relevant conversational follow-up; it sends no
background notifications. A question explicitly about project work remains a
project-status question.

## 22. Decision notes at the close of advice

When an advising session's recommendation meets an actual decision you state,
the agent offers exactly once, in its first closing response, a ready-to-save
draft decision note. Before you state a decision it offers no draft: its own
recommendation is not your decision. A request not to save or persist does not
suppress the offer because the draft stays in conversation and writes nothing.
A request not to offer or draft, or a decline, ends the matter: nothing is
written, nothing is pending, and it is not mentioned again. Otherwise the agent
includes the complete draft itself; it does not merely restate your decision or confirm
that nothing was saved.

The note is plain portable Markdown with six labeled sections — Question,
Options considered, Recommendation, Decision, Rationale, Revisit by — in the
words used in the session. Revisit by appears only when you stated a revisit
intent; it is never invented. The agent presents the draft in conversation
for you to place — it never writes the file anywhere itself unless you have
separately enabled that (section 24) and said so. Save it into your staged
notes folder (`02_Staged`) and it rides the ordinary conveyor (section 24) on
your next staged intake.

At preparation the companion uses your requested output language for that operation,
or otherwise preserves the source language, including mixed-language passages.
The concise rewrite preserves required section labels, material details,
identity-bearing names and terms, and exact quotations in any language. This choice
does not set a personal default or rewrite existing notes. It
automatically corrects clear typos when the intended wording is unambiguous;
material ambiguity still requires private source clarification. It derives
the front matter: `kind: event` always, `occurred_on` from the
decision date the note states, `valid_to` from Revisit by (blank without
one), and tags carrying one `aspect:` area, one `subject:` slug mirroring
the staged basename, then `loop:open` exactly when Revisit by is present. A
decision with a revisit horizon therefore becomes an open loop that future
advising sessions surface, when due or bearing on the question, until you
close it.

## 23. Closing or re-horizoning an open loop

For a note containing several independent follow-ups, completing or moving only
one uses an ordinary correction to that part of the note. The other commitments
and dates stay intact, and the item remains open while any follow-up remains.
The whole-loop instructions below apply when the entire item closes or shares
the moved horizon. Partial updates use the same owner-placed note or UI capture
and exact approval, without declaring the entire item closed.

When you state that an open loop is resolved, or that its horizon should
move, the agent may offer — once, at the same close, alongside any
decision-note offer — a draft closure or re-horizon correction. The outcome
or new horizon is always yours: it is never invented, and a decline ends the
matter.

Either way the change is one correction on the loop's own lineage. On a
close, the successor drops `loop:open`, clears `valid_to`, and appends one
final `Outcome (<date>):` line in your stated words. On a re-horizon, it
keeps `loop:open`, sets the stated `valid_to`, and leaves the statement
unchanged. Every other tag and field carries forward, and a correction never
sits below the sensitivity of the note it cites.

Two routes carry it, and they differ on purpose:

- **Capture it in the UI.** Open the loop memory and use **Create
  correction** (section 8), in your own words. This is the direct route; its
  one consequence is section 8's ratchet — a UI capture seals `restricted`,
  so the successor is restricted too.
- **Place a closure note directly in `04_Inbox`.** The agent drafts a small
  three-section note — Loop, Outcome, Disposition, where Disposition is
  Closed or a revisit date, never both — and you place the file straight
  into the inbox, never into `02_Staged` or `03_Prepared`: prepared through
  the conveyor it would mint a new memory instead of closing the loop. With
  no intake transaction mid-flight, one scan captures it (`authorship=mixed`,
  at the target lineage's stored sensitivity; notes for lineages of
  differing sensitivities ride separate batches), and one review carries one
  correction per existing memory, citing all contributing notes.

For an update you already placed in `02_Staged`, asking the companion to process
it is enough for the agent to carry the unchanged source into the configured Inbox
and draft a correction Review. You do not need to copy it again or enter it in the
UI. This uses the existing lineage and preserves its history and unaffected fields;
the full proposal is reviewed privately through Memory's normal exact approval.
Your Staged original stays intact after verification. Conversation-only drafts
still use the placement/capture routes above.

## 24. The staged-intake conveyor at a glance

The optional staged-memory-intake companion coordinates notes you draft
outside Memory through four sibling folders:

1. **`01_Pending`** — your raw notes; the companion never reads it.
2. **`02_Staged`** — notes ready to be prepared for possible retention.
3. **`03_Prepared`** — by default, one faithful candidate per staged note,
   with derived front matter; at most 50 per pass. An explicit request can
   instead rewrite, summarize, combine, or split.
4. **`04_Inbox`** — Memory's configured inbox, where publication lands.

A pass first checks every selected Staged note against approved memory. It reads
Store status, walks all tracked open items across every page and sensitivity,
then checks relevant approved memory and complete source context for updates.
An ordinary note can close, move or partly change an existing loop even without
a closure heading; it takes the direct correction route in section 23 instead
of becoming a new item. A decision to stop does not establish that the action
already stopped, and a partial update preserves every other open follow-up.
Mixed selections resolve correction routing before preparation starts; a material
target or disposition ambiguity needs private source clarification. The routing
report names files and categories only, and corrections still need exact Review
approval.

The agent handles source transport and the correction Review for a ready Staged
update. It reuses a matching existing capture after interruption; it never copies
or scans again merely because a result was lost. Unexpected Inbox entries or an
unproven capture stop dependent work. Direct corrections preserve Staged originals
and bypass ordinary Prepared and cleanup receipts.

For genuinely new items, a pass creates the complete candidate set before asking
you to review it.
Open the files in `03_Prepared` to read, edit, or tune their full contents;
the Prepared-preview helper output and session chat show only a content-free
manifest with names and mappings, each candidate's preparation operation,
hashes, counts, sensitivities, guard endpoints, and the exact digest. It never
repeats a Prepared body, statement, front matter, or evidence excerpt. The
preview marks any candidate whose statement is the staged note's text
unchanged as verbatim, so approving unrewritten words is a decision you see,
never a default that slips through. Every
edit triggers a fresh preview, and your approval authorizes only the current
digest; any later drift invalidates it.
Publication feeds exactly one scan, one sealed batch, one Memory Review, and
the same macOS owner-presence approval as every other review. Only after the
applied memories verify do the originals move to the companion's recoverable
Trash. The conveyor is a workflow beside the ordinary inbox, not a path
around owner approval: nothing it stages becomes memory without your
exact-digest review.

Decision notes (section 22) ride the new-item conveyor. Staged correction and
closure notes (section 23) use agent-operated direct source transport and an
existing-lineage Review. The companion's
maintenance commands — legacy layout migration, notes-root relocation, and
authority adoption — are covered in section 18.

If you stop an intake after publication but before scanning, the agent can run
`cancel-publication --transaction FULL_ID --digest FULL_DIGEST` through the loaded
companion helper. It withdraws only that promotion's exact published copies into
a private recoverable archive, preserves the receipt, and leaves all Staged and
Prepared files untouched, even if you edited or trashed them. It never changes
retained memory. Unexpected files or changed copies block withdrawal. If interrupted,
`status` reports `cancellation_pending`; resume that exact cancellation before any
other intake work. Once `cancelled`, prepare again only when requested, with fresh
review and authorization. Cancellation is unavailable after scanning starts.

### Letting the agent save an offered decision note

Off by default. When an advising session ends in a decision you accept the
draft note for, the agent can save that one draft into `01_Pending` for you —
after you enable the drop by re-running your configure command with the flag:

```sh
python3.14 -B ~/.claude/skills/staged-memory-intake/scripts/staged_memory_intake configure --notes-root <your notes root> --memory-home <your memory home> --pending-drop on
```

Use `off` to disable it again; omitting the flag keeps the current setting,
and `status` reports it as `pending_drop`. The setting is yours alone —
agents are instructed never to enable it. Every save still needs your
in-session consent to that exact draft, the file lands only in `01_Pending`
(which nothing reads until you move it to `02_Staged` yourself), and an
existing name is never overwritten.

## 25. Related documents

- [Documentation map](README.md)
- [Technical design](technical-design.md)
- [Client setup](client-setup.md)
- [Acceptance records](acceptance/)
- [Agent guide](../AGENTS.md)
