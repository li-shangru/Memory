# Privacy Runtime knowledge — 1.0.0

Lookup triggers: runtime selection, encryption/kernel checks, database authority, initialization,
filesystem replacement and owner-presence boundaries. Read design §§4–5 and relevant
approval contracts. Verify current source.

Lexical normalization precedes identity decisions. Public/runtime database identities
must agree, and pending initialization/relocation fences ordinary access. Existing-only
opens cannot recreate missing databases or replace missing keys. Bound opens validate
the actual native database inode before key/schema access and around writers. Exact
SQLCipher companion/kernel checks fail closed. Writers use nonblocking locks, WAL/FULL
and one audit-generation increment per changed transaction. Initialization recovery
proves owned artifacts and preserves a foreign winner. Typed input and PTYs do not
establish owner presence. Hash equality establishes bytes, not custody or truth.

Inspect [runtime](../../../src/memory/runtime.py),
[database](../../../src/memory/database.py), [keys](../../../src/memory/keys.py),
[initialization](../../../src/memory/initialization.py),
[filesystem ownership](../../../src/memory/initialization_fs.py), and
[owner presence](../../../src/memory/ui/owner_presence.py).
Check owners: [runtime mode](../../../tests/test_runtime_mode.py),
[database](../../../tests/test_database.py),
[initialization](../../../tests/test_initialization.py),
[owner presence](../../../tests/test_owner_presence.py), and
[delivery probe](../../../tools/delivery_probe.py).

Failure-mode lookup: follow the cited authoritative source and test owners for missing coverage, stale identity, refusal/replay, replacement or parity concerns. Catalog metadata owns executable routing and required/optional read lists. This short pack is a source map, not parallel product authority; verify live references.
