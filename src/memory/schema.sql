PRAGMA user_version = 1;

CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    product TEXT NOT NULL,
    schema_lineage TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    store_id TEXT NOT NULL CHECK (
        length(store_id) = 32
        AND store_id NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_mode TEXT NOT NULL CHECK (
        runtime_mode = 'personal'
    ),
    audit_generation INTEGER NOT NULL CHECK (audit_generation >= 0)
) STRICT;

CREATE TABLE source_blobs (
    blob_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE CHECK (
        length(sha256) = 64
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    original_bytes BLOB NOT NULL,
    utf8_text TEXT,
    CHECK (byte_length = length(original_bytes))
) STRICT;

CREATE TABLE inbox_scan_progress (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    token TEXT NOT NULL
) STRICT;

CREATE TABLE inbox_scan_candidates (
    token TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    name TEXT NOT NULL,
    PRIMARY KEY (token, ordinal),
    UNIQUE (token, name)
) STRICT;

CREATE TABLE inbox_batches (
    batch_id TEXT PRIMARY KEY,
    capture_request_id TEXT UNIQUE CHECK (
        capture_request_id IS NULL OR (
            length(capture_request_id) = 36
            AND substr(capture_request_id, 1, 4) = 'cap_'
            AND substr(capture_request_id, 5) NOT GLOB '*[^0-9a-f]*'
        )
    ),
    sealed_at INTEGER NOT NULL,
    source_count INTEGER NOT NULL CHECK (source_count BETWEEN 1 AND 64),
    has_more INTEGER NOT NULL CHECK (has_more IN (0, 1))
) STRICT;

CREATE TABLE inbox_batch_issues (
    batch_id TEXT NOT NULL REFERENCES inbox_batches(batch_id),
    code TEXT NOT NULL CHECK (
        code IN (
            'changed',
            'not_regular',
            'path_escape',
            'source_too_large',
            'symlink'
        )
    ),
    count INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (batch_id, code)
) STRICT;

CREATE TABLE sources (
    source_id TEXT PRIMARY KEY,
    blob_id TEXT NOT NULL REFERENCES source_blobs(blob_id),
    batch_id TEXT NOT NULL REFERENCES inbox_batches(batch_id),
    origin TEXT NOT NULL CHECK (origin IN ('inbox', 'owner_correction')),
    original_name TEXT NOT NULL CHECK (length(original_name) > 0),
    media_type TEXT NOT NULL CHECK (length(media_type) > 0),
    authorship TEXT NOT NULL CHECK (
        authorship IN ('owner', 'external', 'mixed', 'unknown')
    ),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('normal', 'sensitive', 'restricted')
    ),
    captured_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_sources_blob_id ON sources(blob_id);

CREATE TABLE inbox_batch_sources (
    batch_id TEXT NOT NULL REFERENCES inbox_batches(batch_id),
    source_id TEXT NOT NULL UNIQUE REFERENCES sources(source_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (batch_id, source_id),
    UNIQUE (batch_id, ordinal)
) STRICT;

CREATE VIRTUAL TABLE source_fts USING fts5(
    source_id UNINDEXED,
    capture_rowid UNINDEXED,
    utf8_text,
    original_name,
    tokenize = 'porter unicode61'
);

CREATE TABLE memory_lineages (
    lineage_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE change_sets (
    change_set_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL UNIQUE REFERENCES inbox_batches(batch_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'applied')),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE change_set_revisions (
    revision_id TEXT PRIMARY KEY,
    change_set_id TEXT NOT NULL REFERENCES change_sets(change_set_id),
    predecessor_id TEXT REFERENCES change_set_revisions(revision_id),
    digest TEXT NOT NULL CHECK (
        length(digest) = 64
        AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    adapter_origin TEXT NOT NULL CHECK (
        adapter_origin IN ('mcp', 'owner_ui', 'cli', 'system')
    ),
    created_at INTEGER NOT NULL,
    UNIQUE (change_set_id, revision_id)
) STRICT;

CREATE TABLE change_items (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    item_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'rejected')),
    kind TEXT NOT NULL CHECK (
        kind IN ('fact', 'event', 'preference', 'relation', 'insight')
    ),
    statement TEXT NOT NULL CHECK (length(statement) > 0),
    occurred_on TEXT,
    valid_from TEXT,
    valid_to TEXT,
    tags_json TEXT NOT NULL CHECK (json_valid(tags_json)),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('normal', 'sensitive', 'restricted')
    ),
    target_lineage_id TEXT REFERENCES memory_lineages(lineage_id),
    expected_head_id TEXT,
    PRIMARY KEY (revision_id, item_id),
    UNIQUE (revision_id, ordinal),
    CHECK (
        (target_lineage_id IS NULL AND expected_head_id IS NULL)
        OR (target_lineage_id IS NOT NULL AND expected_head_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE change_item_evidence (
    revision_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    blob_digest TEXT NOT NULL CHECK (length(blob_digest) = 64),
    mode TEXT NOT NULL CHECK (mode IN ('text', 'source_level')),
    char_start INTEGER,
    char_end INTEGER,
    excerpt TEXT,
    source_level INTEGER CHECK (source_level IN (0, 1)),
    PRIMARY KEY (revision_id, item_id, ordinal),
    FOREIGN KEY (revision_id, item_id)
        REFERENCES change_items(revision_id, item_id),
    CHECK (
        (
            mode = 'text'
            AND char_start IS NOT NULL
            AND char_end IS NOT NULL
            AND char_start >= 0
            AND char_end >= char_start
            AND excerpt IS NOT NULL
            AND source_level IS NULL
        )
        OR (
            mode = 'source_level'
            AND char_start IS NULL
            AND char_end IS NULL
            AND excerpt IS NULL
            AND source_level = 1
        )
    )
) STRICT;

CREATE TABLE batch_source_decisions (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    state TEXT NOT NULL CHECK (state IN ('used', 'no_memory')),
    reason TEXT,
    PRIMARY KEY (revision_id, source_id),
    UNIQUE (revision_id, ordinal),
    CHECK (
        (state = 'used' AND reason IS NULL)
        OR (state = 'no_memory' AND reason IS NOT NULL AND length(reason) > 0)
    )
) STRICT;

CREATE TABLE applications (
    application_id TEXT PRIMARY KEY,
    change_set_id TEXT NOT NULL UNIQUE REFERENCES change_sets(change_set_id),
    revision_id TEXT NOT NULL UNIQUE REFERENCES change_set_revisions(revision_id),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE memory_revisions (
    revision_id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    predecessor_id TEXT REFERENCES memory_revisions(revision_id),
    kind TEXT NOT NULL CHECK (
        kind IN ('fact', 'event', 'preference', 'relation', 'insight')
    ),
    statement TEXT NOT NULL CHECK (length(statement) > 0),
    occurred_on TEXT,
    valid_from TEXT,
    valid_to TEXT,
    recorded_at INTEGER NOT NULL,
    tags_json TEXT NOT NULL CHECK (json_valid(tags_json)),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('normal', 'sensitive', 'restricted')
    ),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    UNIQUE (lineage_id, revision_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_memory_lineage_history
    ON memory_revisions(lineage_id, recorded_at);

CREATE TABLE memory_evidence (
    memory_revision_id TEXT NOT NULL REFERENCES memory_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    blob_digest TEXT NOT NULL CHECK (length(blob_digest) = 64),
    mode TEXT NOT NULL CHECK (mode IN ('text', 'source_level')),
    char_start INTEGER,
    char_end INTEGER,
    excerpt TEXT,
    source_level INTEGER CHECK (source_level IN (0, 1)),
    PRIMARY KEY (memory_revision_id, ordinal),
    CHECK (
        (
            mode = 'text'
            AND char_start IS NOT NULL
            AND char_end IS NOT NULL
            AND char_start >= 0
            AND char_end >= char_start
            AND excerpt IS NOT NULL
            AND source_level IS NULL
        )
        OR (
            mode = 'source_level'
            AND char_start IS NULL
            AND char_end IS NULL
            AND excerpt IS NULL
            AND source_level = 1
        )
    )
) STRICT;

CREATE TABLE current_memory_heads (
    lineage_id TEXT PRIMARY KEY REFERENCES memory_lineages(lineage_id),
    revision_id TEXT NOT NULL UNIQUE REFERENCES memory_revisions(revision_id)
) STRICT;

CREATE VIRTUAL TABLE memory_fts USING fts5(
    revision_id UNINDEXED,
    statement,
    tags,
    tokenize = 'porter unicode61'
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    change_set_id TEXT NOT NULL UNIQUE REFERENCES change_sets(change_set_id),
    revision_id TEXT NOT NULL UNIQUE REFERENCES change_set_revisions(revision_id),
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    approved_at INTEGER NOT NULL,
    adapter TEXT NOT NULL CHECK (
        adapter IN ('mcp_elicitation', 'local_owner_ui', 'os_owner_presence_cli')
    )
) STRICT;

CREATE TABLE application_memories (
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    memory_revision_id TEXT NOT NULL UNIQUE REFERENCES memory_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (application_id, memory_revision_id),
    UNIQUE (application_id, ordinal)
) STRICT;

-- revoked_at and revoking_application_id are nullable and defaultless because
-- an existing store reaches this shape through ALTER TABLE ADD COLUMN, which
-- is legal on a STRICT table for exactly that shape. No table-level CHECK
-- pairs them, deliberately: ALTER TABLE cannot add one, so a healed store
-- could not enforce what a fresh store did, and one enforced invariant that
-- holds on only half the installed base is worse than none.
CREATE TABLE memory_guard_links (
    guard_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    governed_lineage_id TEXT NOT NULL REFERENCES memory_lineages(lineage_id),
    application_id TEXT NOT NULL REFERENCES applications(application_id),
    revoked_at INTEGER,
    revoking_application_id TEXT REFERENCES applications(application_id),
    PRIMARY KEY (guard_lineage_id, governed_lineage_id),
    CHECK (guard_lineage_id <> governed_lineage_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_memory_guard_governed
    ON memory_guard_links(governed_lineage_id, guard_lineage_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_memory_guard_active
    ON memory_guard_links(guard_lineage_id, governed_lineage_id)
    WHERE revoked_at IS NULL;

CREATE TABLE change_revision_guard_links (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    guard_item_id TEXT,
    guard_lineage_id TEXT,
    governed_item_id TEXT,
    governed_lineage_id TEXT,
    PRIMARY KEY (revision_id, ordinal),
    CHECK ((guard_item_id IS NULL) <> (guard_lineage_id IS NULL)),
    CHECK ((governed_item_id IS NULL) <> (governed_lineage_id IS NULL))
) STRICT;

-- A separate table rather than an intent column on change_revision_guard_links:
-- that table's status already means active-or-rejected for a *proposal*, and
-- overloading it would make every existing query read the wrong set unless it
-- were updated. A new table is invisible to every existing query by
-- construction.
CREATE TABLE change_revision_guard_revocations (
    revision_id TEXT NOT NULL REFERENCES change_set_revisions(revision_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    guard_item_id TEXT,
    guard_lineage_id TEXT,
    governed_item_id TEXT,
    governed_lineage_id TEXT,
    PRIMARY KEY (revision_id, ordinal),
    CHECK ((guard_item_id IS NULL) <> (guard_lineage_id IS NULL)),
    CHECK ((governed_item_id IS NULL) <> (governed_lineage_id IS NULL))
) STRICT;
