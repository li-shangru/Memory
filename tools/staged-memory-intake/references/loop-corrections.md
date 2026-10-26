# Close or re-horizon an open loop

An ordinary update can resolve or change an existing loop without a closure
heading. Complete the entrypoint's mandatory reconciliation first, then target
the current lineage and expected head. Preserve current history and every
unaffected field. A decision to stop is not evidence that stopping has occurred:
preserve the distinction between a stated decision, intended action, and completed
action. Never assume a grouped memory closes because one follow-up changed.

## Owner-placed Staged sources

An intake request authorizes the agent to transport each selected owner-placed
Staged correction source and draft its correction Review. Never ask the owner to
copy it to `04_Inbox` or capture it again in the UI. Neither this request nor file
placement supplies exact owner approval. Keep Staged and retained content out of
chat: filenames, private locators, opaque bindings and route/issue categories only.

1. Complete reconciliation and the entire selection's plausibility pass first.
   Require configured, unchanged notes-root/Inbox authority, a settled regular
   source and no active intake transaction or pending helper recovery. Resolve
   the combined supported outcome before transport: group selected sources by
   current target lineage/head before copying or scanning. Several notes for one
   lineage contribute to one complete correction, not competing successors.
   Preserve each source's provenance and stated chronology; unresolved
   contradictions block dependent work under the private clarification rule.
   Validate the complete grouped proposal against existing public Review bounds
   before transport, including the 16-locator limit per item. Over-bound groups
   remain untouched with a content-free capability blocker; never omit evidence,
   silently split the outcome across Reviews, or create competing successors.
   Resolve mixed-selection routing before starting ordinary preparation; finish the
   direct correction group first. Do not use `03_Prepared` or the ordinary
   helper's `authorize`, `publish`, `check-review`, or `cleanup`: those receipts
   and edit plans describe new items, not corrections.
2. Before copying or scanning, enumerate every `inbox.list` page and read plausible
   rosters completely with `inbox.read`. Reuse a uniquely matching prior capture
   and its Review/application; repeated identical bytes still create a new Source.
   Match full published names, blob digests, byte lengths, origin, authorship, and
   sensitivity. Resume only recorded bindings, never adopt an unproven matching
   file. Ambiguous prior capture or interrupted scan state permits enumeration
   only; do not republish or scan to discover whether it already happened.
3. For a new correction group at one capture sensitivity, require an empty Inbox
   including hidden entries. Record content-free source/copy names, exact hashes,
   lengths, file identities, target lineage/head and capture metadata. Copy the
   exact original bytes exclusively into the configured Inbox, with private mode
   and an opaque unique published name; preserve Staged bytes and never overwrite
   a collision. Stage the complete copy in an exclusive hidden mode-0600 temporary
   on the Inbox volume, flush it, then publish atomically without replacement.
   Revalidate authority and both exact source/copy bindings, then require the whole
   Inbox to be precisely that group.
   A recorded incomplete copy is recovery work, never permission to overwrite or
   guess ownership. Preserve uncertain artifacts and stop dependent actions.
4. Record that a scan is being issued, then call `inbox.scan` once with
   `authorship=mixed` at the target lineage's stored sensitivity; notes for lineages
   of differing sensitivities ride separate batches. After an issued scan, a lost
   result permits enumeration only, never another scan. Resolve exactly one sealed
   batch through complete `inbox.list`/`inbox.read` walks and the full bindings.
   Require its entire roster to match the intended group. Report every issue and
   duplicate; extra/missing entries, partial coverage or metadata drift stop the
   proposal. A concurrent Inbox arrival can be co-captured; an exact roster check
   detects this but does not make generic scanning an atomic file selector.
5. Read every captured source fully. One batch, one change set: reopen its recorded
   set or use idempotent `change_set.create`, then make one correction per target
   lineage, citing every contributing source. Set the current target lineage and
   expected head from complete `memory.get` evidence at review time. Reuse a
   populated Review and its recorded
   targets; never replay edits or retarget an interrupted draft by assumption.
   Use the partial/whole-loop rules below and preserve guards and sensitivity
   floors. Show full content only in the normal private Memory Review surface;
   chat carries exact revision/digest and content-free counts.
6. Follow `using-memory`'s normal exact owner approval and OS-backed handoff.
   After successful apply, verify returned same-lineage successors, predecessor
   and immutable source evidence with complete `memory.get` details. Preserve
   Staged originals after verification; ordinary helper cleanup does not cover
   this route. A prior applied correction is verified and reported, not recopied.
   Before starting the next sensitivity group, reconcile its targets against their
   current heads again; never reuse a stale pre-apply head.

## Partial corrections

If only one of several independent follow-ups changes, use an ordinary correction
note against the current target lineage and expected head. Update only the affected
part of the statement, preserve every other commitment and date, and keep
`loop:open` while any follow-up remains unresolved. Leave `valid_to` blank unless
the source supports one horizon shared by the remaining item. The whole-loop rules
below do not apply to a partial update: do not label the entire loop Closed or move
its shared horizon for one sub-item. Exact owner approval is still required.

## Whole-loop changes

A staged note that states the resolution of an existing open loop is a closure
note and follows the agent-operated source route above. On close: remove
`loop:open`, clear `valid_to`, append one final `Outcome (<date>):` line in the
owner's stated words, preserving the current statement verbatim. That date is the
date the owner stated the outcome, not the
date of the underlying event. On re-horizon: keep `loop:open`, set the stated
`valid_to`, and leave the statement unchanged. Carry every other tag and field
forward unchanged. No conversation alone changes retained state.

## Conversational drafts

For conversation-only drafts, an intake request does not authorize capturing words
supplied only in conversation. The owner must place or capture that new source.

An advising agent may close a session by offering one draft closure note after
the owner states that an open loop is resolved or that its horizon moves; never
draft before that, never re-raise after a decline. When in doubt, do not offer.
For a partial update, offer an ordinary correction note naming the affected
follow-up and the owner's stated outcome or new date. For a whole-loop change,
the note is plain Markdown with three labeled sections — Loop, Outcome,
Disposition — in the owner's words. Disposition is Closed or a revisit date,
never both; an outcome or horizon is never invented. If the owner's words leave
the disposition ambiguous between Closed and a revisit date, stop and ask
instead of drafting. Present the complete draft in conversation; the owner
places it directly into `04_Inbox`. Never write it anywhere yourself, never
into `02_Staged` or `03_Prepared`: that would mint a new memory instead of
closing the loop. Once owner-placed in the Inbox, use the same one-capture
source-backed correction Review rules above. Already owner-placed Inbox sources
skip Staged-copy and empty-Inbox setup: enumerate the complete selected Inbox,
resolve targets and sensitivity before one scan, and account for every sealed
source. Unexpected or incompatible entries block that scan; never copy or scan
again to recover an issued capture. The owner may instead capture the
correction, in their own words, in the local owner application; that route seals
at restricted sensitivity, which a correction never sits below. An already
captured UI batch is sealed; review it without calling `inbox.scan`.
