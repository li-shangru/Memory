# Retrieval Provenance knowledge — 1.0.0

Lookup triggers: source/memory search, complete source reads, projections, cursor binding,
fragmented details and evidence fidelity. Read design §§5.3, 6 and 8 before judging
these paths. Recheck current source.

Retained bytes and approved revisions are authority; FTS is rebuildable. Equal bytes
can have distinct captures/provenance. Effective sensitivity takes the highest capture
value and may rise without rewriting a revision. Search's ladder version and composition
binding differ from detail cursors bound to Store audit generation. Do not generalize
one cursor's snapshot contract to another. Complete reads require all bounded pages,
UTF-8-safe character/byte coordinates, final digest and honest partial/binary coverage.
Guard attachments bypass claim filters and do not enter search snapshots; refresh
previously read pages when relevant state changes. A hit is evidence, not truth/advice.

Inspect [retrieval.py](../../../src/memory/retrieval.py),
[sources.py](../../../src/memory/sources.py),
[memories.py](../../../src/memory/memories.py), and
[memory_detail_pages.py](../../../src/memory/memory_detail_pages.py).
Use [source pagination tests](../../../tests/test_sources.py),
[detail reconstruction](../../../tests/test_mcp_detail_pages.py),
[authoritative retrieval](../../../tests/test_retrieval.py), and
[ranking parity](../../../tests/test_retrieval_ranking.py) as concrete check owners.

Search source composition excludes sensitivity; memory-search composition includes effective sensitivity. Detail cursors bind audit generation and exact selection; projection-filtered source enumeration binds eligible membership. These are distinct continuation contracts. Follow the authoritative source and reconstruction tests for the specific path.

Failure-mode lookup: follow the cited authoritative source and test owners for missing coverage, stale identity, refusal/replay, replacement or parity concerns. Catalog metadata owns executable routing and required/optional read lists. This short pack is a source map, not parallel product authority; verify live references.
