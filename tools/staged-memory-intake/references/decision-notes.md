# Draft or prepare a decision note

Follow `using-memory`'s canonical decision-note offer rule: an actual owner
decision after a recommendation requires one complete draft, never before that
decision or again after a decline. Present it in conversation as one fenced
Markdown block for the owner to place; never write it into `02_Staged` or
`03_Prepared` yourself. After the
owner sees this session's complete draft and says to save it, you may instead
write it through the helper: run `pending-drop` with `--name`, its exact
root-level Markdown basename, and the draft over stdin with `--input -`. The
helper creates one new file in `01_Pending` and never overwrites. On refusal —
unconfigured, disabled, or collision — present the draft for the owner to place
and do not retry. Consent covers one draft, once; permission from an earlier
session never authorizes a write. Never enable or configure the drop yourself.
Use plain portable Markdown with six labeled sections — Question, Options
considered, Recommendation, Decision, Rationale, Revisit by — in the session's
words. Omit Revisit by entirely unless the owner stated a revisit intent; never
invent one.

Rewrite a staged decision note concisely in the owner's requested output language;
otherwise preserve its source language, including mixed-language passages.
Preserve the required
labeled decision structure — Question, Options considered, Recommendation,
Decision, Rationale, and Revisit by — and every material option, recommendation,
decision, rationale, condition, and uncertainty. Include Revisit by only when
the source states it. Existing front-matter and loop-tag semantics remain
unchanged: `kind: event` always; `occurred_on` is the decision date the note
states; `valid_to` is the Revisit by date and stays blank without one; tags carry
one `aspect:` area, one `subject:` slug mirroring the staged basename, then
`loop:open` exactly when Revisit by is present. Do not combine a decision note
with another note, and never split a decision note.
