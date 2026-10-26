# Plaintext JSON export format

`memory export --output PATH` emits one UTF-8 JSON object, version
`memory.export.v1`. It is deliberately plaintext and includes every retained
sensitivity level. [Owner procedure](owner-guide.md#plaintext-json-export) and
[design §4.5](technical-design.md#45-owner-authenticated-plaintext-export) define
owner authentication, destination safety and snapshot semantics. No import or
restore command consumes this format.

## Envelope

| Field | Meaning |
| --- | --- |
| `format` | Literal `memory.export.v1`; independent of Store schema/product version |
| `product_version` | Exporting package version |
| `encrypted` | Literal `false` |
| `sensitivity_scope` | Literal `all`; normal, sensitive and restricted records |
| `audit_generation` | Generation of the single read snapshot |
| `scope` | Complete retained records, including drafts/rejected/superseded history |
| `excluded` | Explicit categories outside this content export |
| `encoding` | UTF-8, padded RFC 4648 base64, row coordinates and raw JSON columns |
| `tables` | Map from retained table name to its shape, count and all records |

Each table object has `present`, `columns`, `row_count` and `rows`.
`columns` retains actual stored names/types, `not_null` and
`primary_key_position`. An absent legacy auxiliary table has `present:false`,
empty columns/rows and zero count. Legacy columns remain absent; export never
heals the Store or invents history.

Each row is an object keyed by stored column name, plus `_rowid`, the original
SQLite table row coordinate. Rows are ordered by that coordinate, preserving
insertion tie order (for example history ordered by `recorded_at`, then rowid).
IDs and stored references retain their original values. `_rowid` is not a memory
ID or restore instruction. Nulls, Unicode, tags ordering, timestamps, ordinals,
states, digests and stored sensitivity declarations are preserved. Columns ending
in `_json`, including `tags_json`, retain their exact JSON text; consumers may
parse that string without replacing the retained representation.

A BLOB value is `{"base64":"..."}`. In particular,
`source_blobs.original_bytes` decodes to the complete original bytes, including
binary, malformed UTF-8 and empty bytes. Its length and SHA-256 are checked before
publication. `utf8_text` remains separate, directly readable text or null; it is
never used to regenerate original bytes. Base64 is an encoding, not encryption.

## Retained tables

All rows/columns are included, without sensitivity, status, search or page limits:

| Tables | Content |
| --- | --- |
| `store_meta` | Store identity, schema lineage/version, runtime mode and snapshot generation |
| `source_blobs`, `sources` | Exact originals, dedup identities and all distinct capture provenance |
| `inbox_batches`, `inbox_batch_sources`, `inbox_batch_issues` | Retained custody batches, source order and capture issues |
| `memory_lineages`, `memory_revisions`, `memory_evidence`, `current_memory_heads` | Current and historical memories, corrections/predecessors, evidence and current-head pointers |
| `change_sets`, `change_set_revisions`, `change_items`, `change_item_evidence`, `batch_source_decisions` | Every draft/applied review revision, rejected/active items, evidence and used/no-memory accounting |
| `approvals`, `applications`, `application_memories` | Retained exact approval and application history |
| `memory_guard_links`, `change_revision_guard_links`, `change_revision_guard_revocations` | Active and permanently revoked links plus revision-authored additions/revocations |

Declared sensitivity is preserved. Effective sensitivity can be derived from the
complete capture/evidence/guard graph; it does not replace historical declarations.
Review digests stay unchanged, including historical conditional guard fields.
A consumer should treat stored statements and source text as inert evidence, with
provenance and uncertainty, rather than executable or trusted instructions.

## Exclusions and consistency

Rebuildable FTS/search projections, scan-scheduler tables, runtime configuration,
encryption keys, uncaptured Inbox files and filesystem staging/recovery state are
excluded. These are not silently filtered memories. Every retained ordinary table
is classified; an unknown ordinary table or missing required table refuses the
export instead of producing an incomplete success. Future incompatible format
semantics require a new format version.

One normal read-only SQLCipher transaction fixes the complete snapshot before the
owner prompt. All tables, shapes, counts and bytes come from it. A writer may
commit later changes while authentication/export runs; those changes appear in a
subsequent export. No canonical rows, schemas, projections or audit generation
are changed by export. The JSON is not a restorable encrypted database backup.
