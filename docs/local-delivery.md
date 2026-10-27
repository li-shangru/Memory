# Optional maintainer local delivery

This workflow installs and verifies a selected everyday client environment. It
is optional for public source contributions and first-time users; use
`./tools/check.sh --source-only` to qualify source without an installation profile.
After cloning, run `python3 third_party/fetch-wheels.py` to retrieve and verify
the companion Release assets. For an authorized local delivery of a reviewed,
committed candidate:

```console
./tools/deliver.sh run
```

It runs the full source gate, freezes an exact wheel/source archive and the
hash-pinned SQLCipher companion fetched from the Release, rehearses both exact frozen artifacts with the
wheel and UI smokes, installs it in the intended uv tool environment, synchronizes
the two Memory Skills to each selected client, and verifies fresh MCP processes.
It creates the local annotated version tag only after all steps pass. Nothing is
pushed, published remotely, or applied to canonical memory.

The agent performs this work. The owner supplies requirements and reviews the
Git diff and selected documents. Local release authorization does not supply a
Memory owner approval. The delivery tools accept no Store, Inbox, or data path.

After `./tools/deliver.sh run` succeeds, the agent records its verified release and
installation in the version's acceptance receipt before invoking `./tools/check.sh`.
The gate rejects a new release tag whose receipt still has candidate status. Commit
that documentation separately; the existing tag stays on the verified source.

## Private installation profile

Configure the intended installation once using explicit absolute paths obtained
from `uv tool dir`, `uv tool dir --bin`, and the selected clients' command metadata:

```console
./tools/deliver.sh configure \
  --executable ABSOLUTE_UV_TOOL_BIN/memory \
  --python ABSOLUTE_UV_TOOL_DIR/memory/bin/python \
  --codex-config ABSOLUTE_CODEX_CONFIG_TOML \
  --claude-config ABSOLUTE_CLAUDE_CONFIG_JSON \
  --skill-root ABSOLUTE_FIRST_CLIENT_SKILL_ROOT \
  --skill-root ABSOLUTE_SECOND_CLIENT_SKILL_ROOT \
  --workspace ABSOLUTE_MEMORY_CHECKOUT \
  --workspace ABSOLUTE_OTHER_CLIENT_WORKSPACE
```

Use one `--skill-root` per intended client root. Within each root the only write
targets are `using-memory/SKILL.md` and `staged-memory-intake/`. Select every client
that should receive this installation. At least one selected configuration and
Skill root are required. List every workspace in which these clients use Memory;
the current Memory checkout is required. Each workspace must have a verifiable Git
project boundary. The profile checks configuration layers from that root through
the selected directory, plus matching Claude project entries using directory
identity, including case/symlink aliases. A project-specific Memory override fails
closed until the agent reviews it; global parity cannot certify a different
effective command. Custom project-root markers require extending the verifier
before certification.
New client configurations, workspaces or moved installations require
rerunning `configure`; existing configuration files are read, never edited.

The profile is mode 0600 under Git's local common directory as
`memory-delivery.json`. It is neither committed nor packaged. It contains only
installation paths, client configuration file locations, and Skill target roots;
no runtime argument is retained. `--profile ABSOLUTE_PATH` selects an alternative
private profile for an explicitly isolated setup.

The verifier reads each selected configuration's `memory` entry and project-boundary
metadata to validate the command and invocation shape. It permits only `command`,
`args`, `enabled`, `env` and `type` entry keys, with the direct `memory mcp` form and
optional `--home` and `--trust-elicitation`; saved runtime values are never opened,
printed, or replayed. Wrappers, other transports, disabled entries, and configured
environment overrides, forwarding or remote execution fail with an actionable
explanation. The fresh probes always
supply their own generated `--home` and never request trusted elicitation.

The existing uv tool installation is the update baseline. On a new machine, follow
the [owner guide bootstrap](owner-guide.md#1-install-or-update-the-everyday-command)
to create it first, then configure and run the normal workflow. Missing setup fails
closed; it never changes another installation or guesses a real runtime.

## Gates and artifacts

`./tools/check.sh` is the finishing gate: full source checks followed by current
installed-package, Skill and fresh-process checks. Missing delivery configuration
or stale installation makes it fail. `./tools/check.sh --source-only` is the
explicit candidate/source-only boundary used before installation; its output says
that delivery is unverified. `fast-check.sh` remains the working source gate.

`./tools/deliver.sh check` repeats only the delivery portion. It rereads source,
configuration, package metadata, all package files (including instructions and UI
assets), installed dependency inventories and RECORD hashes, the SQLCipher
companion bytes against its frozen wheel, copied Skills and the exact frozen artifacts. It launches new MCP
processes each time. A previous success receipt is never accepted as current proof.
Use this after a suspected stale MCP update or a changed executable/PATH.

`dist/vX.Y.Z/release.json` binds the committed release candidate, all source
package files, project/lock metadata, the canonical staged-intake bundle, and
artifact SHA-256 hashes. The wheel's package inventory and RECORD entries are
checked against source; the source archive is checked when built. Repeating a
delivery reuses these immutable artifacts. Changing release inputs under the same
version refuses rather than silently replacing a local release. Make the coupled
version bump and commit the new candidate first.

The installer captures every existing dependency version and relevant installed
file digest. It constrains rehearsals and installation to those versions with one
reviewed transition: `memory-sqlcipher3` may move from
`0.6.2+sqlcipher4.17.0` to `0.6.2+sqlcipher4.17.0.memory1`, or remain at the latter.
Missing or other companion baselines refuse. This downstream revision adds the
connection-held file identity needed by Store authority checks; upstream engine
versions remain unchanged.

The public v1.13.0 release also has one explicitly reviewed transition from the
older private installation. `tools/public-dependency-transition.json` binds it to
the original public release commit and twelve exact before/after versions, wheel
URLs, filenames and SHA-256 hashes. It does not authorize an arbitrary lockfile
refresh or downgrade. The installer pins those exact local artifacts for both
rehearsals and installation. They live in an immutable sibling cache beside the
release directory; the original release manifest, wheel and tag stay unchanged.

The transition upgrades httpx2/httpcore2 2.12.0 to 2.16.0, mcp/mcp-types 2.1.1 to
2.3.0, opentelemetry-api 1.44.0 to 1.45.1, pillow 12.3.0 to 13.0.0, pydantic
2.13.5 to 2.14.1, pydantic_core 2.46.5 to 2.50.1, pypdfium2 5.13.0 to 5.14.0,
PyJWT 2.13.0 to 2.15.1, starlette 1.6.0 to 1.9.0 and uvicorn 0.52.4 to 0.54.0.
Unknown baseline versions refuse. Repeating delivery on the target versions is
idempotent and must preserve their recorded bytes too.

Installed members of all twelve target distributions must match the approved
wheel bytes, including native libraries and distribution metadata. Generated
console scripts must match their approved entry points and interpreter; unknown
wheel layouts or extra/missing members refuse. Every other dependency version and
recorded byte remains unchanged. The receipt lists each transition and preserved
count separately. Other dependency changes need their own reviewed policy update;
an unrelated update cannot silently perform one.


The probe requires hashes and sizes for all relevant raw RECORD entries and
checks their installed bytes,
including native libraries and generated scripts, while excluding bytecode and
installer-owned RECORD/direct-url/INSTALLER/REQUESTED/uv_cache.json bookkeeping. Missing, unsigned,
symlinked, escaping or altered recorded files refuse. RECORD verification does
not authenticate upstream provenance or enumerate unrelated unrecorded files;
Memory and SQLCipher additionally compare complete package inventories.
`uv pip check` verifies dependency consistency. Any other dependency change needs
its own reviewed policy update; an unrelated update cannot silently perform one.
The newly installed launcher, interpreter, complete package bytes, wheel metadata
and dependencies are qualified before its first CLI command or copied-Skill write.

Private logs live beside the profile in `memory-delivery-logs/`. The mode-0600
`memory-delivery-last.json` records the current attempt, including failures and
whether it completed. A failed installer, timeout, failed fresh probe, cleanup
uncertainty or any drift produces a nonzero exit. Logs contain only code/package
metadata and newly generated synthetic data. Selected, content-free results belong
in the version's [acceptance receipt](acceptance/).

A nonblocking local lock serializes delivery attempts sharing the profile directory.
An overlapping invocation fails without replacing the active attempt's receipt.

## What the evidence means

The shell command, configured command paths and CLI shebang must select the intended
environment. Interpreter prefix, Python version, installed metadata, module origin,
direct wheel URL and complete package bytes must agree with the frozen source.
Matching version numbers alone cannot pass. Editable installs are refused for the
everyday Memory command, with stale editable metadata reported separately.

Both fresh MCP protocol modes check the fourteen-tool inventory, `store.status`
version and contract/Skill digests, the full prompt inventory and every served
prompt message against canonical teaching. One freshly authored English/Chinese
fixture is captured through `inbox.scan`, then fully enumerated and reconstructed
through bounded `source.read` chunks in both new processes. No change set or
canonical apply is involved. New mode-0700 synthetic runtimes receive
explicit paths. Cleanup validates each generated runtime identity, deletes only
that exact synthetic Keychain account, verifies key absence, and removes the runtime.
Uncertain cleanup fails and retains the synthetic path for recovery.

These checks do not prove model answer quality, owner presence, or that an
already-running MCP connection loaded new code. Existing clients need a reconnect
or restart before claiming they use the update. This workflow does not interrupt
owner connections or repoint their saved configuration.

Maintain the implementation and focused regressions in `tools/delivery.py`,
`tools/delivery_probe.py`, and `tests/test_delivery.py`. Keep the existing wheel/UI
smokes and both Skill synchronizers as the underlying owners of their behavior.
Changes to this workflow require the same independent review and project gates as
other executable development tooling.

## Post-merge task cleanup

After successful integration and the final verification, the coordinating agent
removes completed local `codex/` task branches and their disposable linked
worktrees without a further routine approval. This is part of completing the task.

First record the exact task tip and intended integration branch, and verify with
`git merge-base --is-ancestor` that the tip is contained in that branch. A squash
or rebase is not equivalent evidence. Check the live branch/worktree registry and
task/process ownership again immediately before cleanup. Release tags, integration
branches and other protected refs are never cleanup targets.

Account for all tracked, untracked and ignored content in a linked worktree before
removing it. A clean tracked diff alone is insufficient; ignored environments,
artifacts and private evidence can still matter. Preserve anything needed outside
the disposable worktree through an authorized, recoverable handoff, then verify
the handoff. Retain the worktree if ownership or the disposition of any content is
uncertain. Never discard files to make cleanup pass.

Use normal `git worktree remove` and safe `git branch -d`, without force, reset or
discard. Do not remove the primary saved checkout or the executing task's working
directory. When the disposable worktree is still executing, arrange a safe task
handoff or exit before another coordinator removes it; until then it remains
active. For a task using the primary checkout, switch that checkout to the verified
integration branch only after shared users and processes have finished with the
task branch, then delete the merged task branch.

Recheck refs and registered worktrees afterward. The handoff records successful
cleanup or the exact unmerged, dirty, ambiguous or active state that required
retention. A blocked release or unfinished integration keeps its task branch for
resumption. No background monitor is required.
