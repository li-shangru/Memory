"""Synthetic byte-bound and complete-reconstruction proofs for MCP memory detail."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from mcp.types import CallToolResult
from synthetic import FakeClock, store_one_memory

from memory.database import writer_session
from memory.mcp_server import call_tool
from memory.model import RuntimePaths

BODY_LIMIT = 8 * 1024 * 1024


def encoded_result_size(result: dict[str, object]) -> int:
    """Use the SDK's actual compact body including its isError default."""
    return len(
        CallToolResult.model_validate(result)
        .model_dump_json(by_alias=True, exclude_none=True)
        .encode("utf-8")
    )


def seed_details(paths: RuntimePaths, *, count: int, link: bool) -> list[str]:
    """Extend a public synthetic apply with bounded, schema-valid canonical rows."""
    original, lineage = store_one_memory(
        paths,
        clock=FakeClock(),
        name="synthetic-detail.txt",
        body="Synthetic detail evidence.\n",
        statement="Synthetic detail.",
        excerpt="Synthetic detail evidence.",
    )
    ids = [original]
    with writer_session(paths) as connection:
        application = connection.execute(
            "SELECT application_id FROM memory_revisions WHERE revision_id = ?",
            (original,),
        ).fetchone()
        assert application is not None
        for index in range(count):
            revision_id = f"mem_synthetic_detail_{index:05d}"
            lineage_id = f"lin_synthetic_detail_{index:05d}"
            connection.execute(
                "INSERT INTO memory_lineages(lineage_id, created_at) VALUES (?, ?)",
                (lineage_id, 1_850_000_000),
            )
            connection.execute(
                "INSERT INTO memory_revisions SELECT ?, ?, NULL, kind, ?, occurred_on, valid_from, valid_to, recorded_at, tags_json, sensitivity, application_id FROM memory_revisions WHERE revision_id = ?",
                (revision_id, lineage_id, "\x01" * 16370 + "中文🙂", original),
            )
            connection.execute(
                "INSERT INTO current_memory_heads VALUES (?, ?)",
                (lineage_id, revision_id),
            )
            connection.execute(
                "INSERT INTO memory_evidence SELECT ?, ordinal, source_id, blob_digest, mode, char_start, char_end, excerpt, source_level FROM memory_evidence WHERE memory_revision_id = ?",
                (revision_id, original),
            )
            if link:
                connection.execute(
                    "INSERT INTO memory_guard_links(guard_lineage_id, governed_lineage_id, application_id) VALUES (?, ?, ?)",
                    (lineage, lineage_id, application[0]),
                )
            ids.append(revision_id)
    return ids


@pytest.mark.parametrize("bulk", [False, True])
def test_memory_get_actual_encoded_body_is_bounded(
    synthetic_store: RuntimePaths, bulk: bool
) -> None:
    ids = seed_details(synthetic_store, count=60, link=not bulk)
    arguments: dict[str, object] = (
        {"memory_ids": ids[1:51]} if bulk else {"memory_id": ids[0]}
    )
    result = call_tool(synthetic_store, "memory.get", arguments)
    assert "error" not in cast("dict[str, Any]", result["structuredContent"])
    size = encoded_result_size(result)
    assert size <= BODY_LIMIT, f"actual encoded MCP body is {size} bytes"


def walk_details(
    paths: RuntimePaths, arguments: dict[str, object]
) -> tuple[list[dict[str, Any]], list[int]]:
    """Reconstruct exclusively through the advertised public fragment protocol."""
    import jsonschema  # type: ignore[import-untyped]

    from memory.mcp_schemas import tool_schemas

    schema = next(
        tool["outputSchema"] for tool in tool_schemas() if tool["name"] == "memory.get"
    )
    details: list[dict[str, Any]] = []
    sizes: list[int] = []
    seen_cursors: set[str] = set()
    while True:
        result = call_tool(paths, "memory.get", arguments)
        envelope = cast("dict[str, Any]", result["structuredContent"])
        jsonschema.validate(envelope, schema)
        assert "error" not in envelope, envelope
        sizes.append(encoded_result_size(result))
        assert sizes[-1] <= BODY_LIMIT
        data = envelope["data"]
        if isinstance(data, list) or "detail_fragments" not in data:
            assert not seen_cursors
            return data if isinstance(data, list) else [data], sizes
        fragments = data["detail_fragments"]
        assert 1 <= len(fragments) <= 256
        for fragment in fragments:
            index = fragment["selection_index"]
            section = fragment["section"]
            if section == "header":
                assert index == len(details)
                details.append(
                    {
                        **fragment["value"],
                        "evidence": [],
                        "guards": [],
                        "governs": [],
                        "revision_ids": [],
                    }
                )
            else:
                assert details[index]["revision"]["memory_id"] == fragment["memory_id"]
                details[index][section].append(fragment["value"])
        if not envelope["page"]["has_more"]:
            assert "next_cursor" not in envelope["page"]
            return details, sizes
        cursor = envelope["page"]["next_cursor"]
        assert cursor not in seen_cursors
        seen_cursors.add(cursor)
        arguments = {**arguments, "cursor": cursor}


@pytest.mark.parametrize("bulk", [False, True])
def test_large_details_reconstruct_deterministically_without_loss(
    synthetic_store: RuntimePaths, bulk: bool
) -> None:
    from memory.mcp_server import _memory_detail_data
    from memory.memories import get_memory

    ids = seed_details(synthetic_store, count=60, link=not bulk)
    selected = ids[1:51] if bulk else ids[:1]
    arguments: dict[str, object] = (
        {"memory_ids": selected} if bulk else {"memory_id": selected[0]}
    )
    expected = [
        _memory_detail_data(get_memory(synthetic_store, memory_id))
        for memory_id in selected
    ]
    reconstructed, sizes = walk_details(synthetic_store, arguments)
    repeated, repeated_sizes = walk_details(synthetic_store, arguments)
    assert len(sizes) >= 2
    assert reconstructed == expected == repeated
    assert sizes == repeated_sizes
    # The byte stop, not merely the 256-record stop, is exercised here.
    assert max(sizes) > BODY_LIMIT - 400_000


def seed_history(paths: RuntimePaths, original: str, count: int) -> str:
    with writer_session(paths) as connection:
        row = connection.execute(
            "SELECT lineage_id FROM memory_revisions WHERE revision_id = ?", (original,)
        ).fetchone()
        assert row is not None
        previous = original
        for index in range(count):
            current = f"mem_synthetic_history_{index:06d}"
            connection.execute(
                "INSERT INTO memory_revisions SELECT ?, lineage_id, ?, kind, statement, occurred_on, valid_from, valid_to, recorded_at + ?, tags_json, sensitivity, application_id FROM memory_revisions WHERE revision_id = ?",
                (current, previous, index // 3, original),
            )
            connection.execute(
                "INSERT INTO memory_evidence SELECT ?, ordinal, source_id, blob_digest, mode, char_start, char_end, excerpt, source_level FROM memory_evidence WHERE memory_revision_id = ?",
                (current, original),
            )
            previous = current
        connection.execute(
            "UPDATE current_memory_heads SET revision_id = ? WHERE lineage_id = ?",
            (previous, row[0]),
        )
    return previous


def test_history_evidence_and_both_relationship_directions_page_exactly(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.mcp_server import _memory_detail_data
    from memory.memories import get_memory

    ids = seed_details(synthetic_store, count=280, link=True)
    current = seed_history(synthetic_store, ids[0], 900)
    with writer_session(synthetic_store) as connection:
        row = connection.execute(
            "SELECT lineage_id, application_id FROM memory_revisions WHERE revision_id = ?",
            (ids[0],),
        ).fetchone()
        assert row is not None
        # Distinct 16 evidence locators remain ordered and complete.
        for ordinal in range(1, 16):
            connection.execute(
                "INSERT INTO memory_evidence SELECT memory_revision_id, ?, source_id, blob_digest, mode, char_start, char_end, excerpt, source_level FROM memory_evidence WHERE memory_revision_id = ? AND ordinal = 0",
                (ordinal, ids[0]),
            )
        # Each roster independently exceeds the byte ceiling, and middle
        # lineages appear in both directions without conflating their roles.
        for index in range(60):
            connection.execute(
                "INSERT INTO memory_guard_links(guard_lineage_id, governed_lineage_id, application_id) VALUES (?, ?, ?)",
                (f"lin_synthetic_detail_{index:05d}", row[0], row[1]),
            )
    historical = get_memory(synthetic_store, ids[0])
    selection = [ids[0], current, ids[1]]
    got, sizes = walk_details(synthetic_store, {"memory_ids": selection})
    assert got == [
        _memory_detail_data(get_memory(synthetic_store, item)) for item in selection
    ]
    assert len(sizes) > 5
    assert got[0]["is_current"] is False
    assert got[0]["current_head_id"] == current
    assert got[1]["is_current"] is True
    assert len(got[0]["revision_ids"]) == 901
    assert len(got[0]["evidence"]) == 16
    assert len(got[0]["guards"]) == 60
    assert len(got[0]["governs"]) == 280
    by_lineage, _ = walk_details(
        synthetic_store, {"lineage_id": historical.revision.lineage_id}
    )
    assert by_lineage == [got[1]]


def test_page_work_stops_after_bounded_records_not_complete_history(
    synthetic_store: RuntimePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from memory import memory_detail_pages as paging

    ids = seed_details(synthetic_store, count=0, link=False)
    seed_history(synthetic_store, ids[0], 2000)
    original = paging._records
    yielded = 0

    def measured(*args: Any, **kwargs: Any) -> Iterator[paging.DetailRecord]:
        nonlocal yielded
        for record in original(*args, **kwargs):
            yielded += 1
            yield record

    monkeypatch.setattr(paging, "_records", measured)
    result = call_tool(synthetic_store, "memory.get", {"memory_id": ids[0]})
    envelope = cast("dict[str, Any]", result["structuredContent"])
    assert envelope["page"]["has_more"]
    assert len(envelope["data"]["detail_fragments"]) == 256
    assert yielded == 257


def rewrite_cursor(cursor: str, **updates: object) -> str:
    import base64
    import json

    payload = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    payload.update(updates)
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def test_detail_cursors_reject_invalid_stale_and_cross_bindings(
    synthetic_store: RuntimePaths,
) -> None:
    ids = seed_details(synthetic_store, count=60, link=True)
    first = cast(
        "dict[str, Any]",
        call_tool(synthetic_store, "memory.get", {"memory_id": ids[0]})[
            "structuredContent"
        ],
    )
    cursor = first["page"]["next_cursor"]
    cases: list[dict[str, object]] = [
        {"memory_id": ids[0], "cursor": "not-a-cursor"},
        {"memory_id": ids[1], "cursor": cursor},
        {"memory_ids": [ids[0]], "cursor": cursor},
    ]
    cursor_changes: list[dict[str, object]] = [
        {"store": "0" * 32},
        {"operation": "source.read"},
        {"version": True},
        {"index": -1},
        {"index": True},
        {"index": 50},
        {"section": []},
        {"section": "revision_ids", "after": [1, 2**100]},
        {"section": "revision_ids", "after": [0, 1]},
        {"section": "evidence", "after": True},
        {"section": "governs", "after": "lin_missing"},
    ]
    for updates in cursor_changes:
        cases.append({"memory_id": ids[0], "cursor": rewrite_cursor(cursor, **updates)})
    for arguments in cases:
        result = cast(
            "dict[str, Any]",
            call_tool(synthetic_store, "memory.get", arguments)["structuredContent"],
        )
        assert result["error"]["code"] == "stale_cursor", arguments
    with writer_session(synthetic_store) as connection:
        connection.execute(
            "UPDATE memory_guard_links SET revoked_at = 1850000001 WHERE guard_lineage_id = (SELECT lineage_id FROM memory_revisions WHERE revision_id = ?)",
            (ids[0],),
        )
    result = cast(
        "dict[str, Any]",
        call_tool(
            synthetic_store, "memory.get", {"memory_id": ids[0], "cursor": cursor}
        )["structuredContent"],
    )
    assert result["error"]["code"] == "stale_cursor"


def test_exact_record_budget_has_progress_and_no_oversized_first_exception(
    synthetic_store: RuntimePaths,
) -> None:
    from memory.errors import InvalidArgumentError
    from memory.mcp_server import _detail_record_wire_cost
    from memory.memory_detail_pages import read_detail_page

    ids = seed_details(synthetic_store, count=0, link=False)
    full = read_detail_page(
        synthetic_store, "memory_id", (ids[0],), None, _detail_record_wire_cost
    )
    cost = _detail_record_wire_cost(full.records[0])
    exact = read_detail_page(
        synthetic_store,
        "memory_id",
        (ids[0],),
        None,
        _detail_record_wire_cost,
        budget=cost,
    )
    assert len(exact.records) == 1 and exact.next_cursor
    following = read_detail_page(
        synthetic_store,
        "memory_id",
        (ids[0],),
        exact.next_cursor,
        _detail_record_wire_cost,
    )
    assert [record.section for record in following.records] == [
        "evidence",
        "revision_ids",
    ]
    with pytest.raises(InvalidArgumentError, match="exceeds the response budget"):
        read_detail_page(
            synthetic_store,
            "memory_id",
            (ids[0],),
            None,
            _detail_record_wire_cost,
            budget=cost - 1,
        )


@pytest.mark.parametrize("field", ["statement", "occurred_on", "tags_json"])
def test_invalid_persisted_large_scalar_is_a_bounded_refusal(
    synthetic_store: RuntimePaths,
    field: str,
) -> None:
    ids = seed_details(synthetic_store, count=0, link=False)
    with writer_session(synthetic_store) as connection:
        connection.execute(
            f"UPDATE memory_revisions SET {field} = ? WHERE revision_id = ?",
            (
                ('["' + "x" * (1024 * 1024) + '"]')
                if field == "tags_json"
                else "x" * (1024 * 1024),
                ids[0],
            ),
        )
    result = call_tool(synthetic_store, "memory.get", {"memory_id": ids[0]})
    assert (
        cast("dict[str, Any]", result["structuredContent"])["error"]["code"]
        == "invalid_argument"
    )
    assert encoded_result_size(result) < 1024


def test_history_continuation_seeks_dense_timestamp_ties_without_prefix_rescan(
    synthetic_store: RuntimePaths,
) -> None:
    from itertools import islice

    from memory.memory_detail_pages import _history_rows
    from memory.sources import _read_connection

    ids = seed_details(synthetic_store, count=0, link=False)
    seed_history(synthetic_store, ids[0], 3000)
    with writer_session(synthetic_store) as connection:
        connection.execute("UPDATE memory_revisions SET recorded_at = 1850000000")
        anchor = connection.execute(
            "SELECT lineage_id, recorded_at, rowid FROM memory_revisions WHERE revision_id = ?",
            ("mem_synthetic_history_002700",),
        ).fetchone()
        assert anchor is not None
    with _read_connection(synthetic_store) as (connection, _):
        steps = 0

        def progress() -> int:
            nonlocal steps
            steps += 100
            return 0

        connection.set_progress_handler(progress, 100)
        rows = list(
            islice(
                _history_rows(connection, str(anchor[0]), [anchor[1], anchor[2]]), 257
            )
        )
        connection.set_progress_handler(None, 0)
    assert len(rows) == 257
    assert rows[0][0] == "mem_synthetic_history_002701"
    assert rows[-1][0] == "mem_synthetic_history_002957"
    assert steps < 10_000, f"bounded history window executed {steps} SQLite VM steps"


def test_cursor_from_another_store_refuses_before_resolving_selection(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from synthetic import make_synthetic_store

    ids = seed_details(synthetic_store, count=60, link=True)
    first = cast(
        "dict[str, Any]",
        call_tool(synthetic_store, "memory.get", {"memory_id": ids[0]})[
            "structuredContent"
        ],
    )
    cursor = first["page"]["next_cursor"]
    other = next(make_synthetic_store(tmp_path / "other", monkeypatch))
    refused = cast(
        "dict[str, Any]",
        call_tool(other, "memory.get", {"memory_id": ids[0], "cursor": cursor})[
            "structuredContent"
        ],
    )
    assert refused["error"]["code"] == "stale_cursor"


def test_maximum_evidence_payload_and_tags_reconstruct_across_byte_stop(
    synthetic_store: RuntimePaths,
) -> None:
    from dataclasses import replace

    from synthetic import apply_ready, capture_batch, ready_items, single_item_edit

    from memory.mcp_server import _memory_detail_data
    from memory.memories import get_memory
    from memory.model import EvidenceInput, Sensitivity

    files = {
        f"synthetic-evidence-{index:02d}.txt": f"Evidence {index:02d} 中文🙂 "
        + "\x01" * 4050
        for index in range(16)
    }
    batch, sources = capture_batch(
        synthetic_store, files, sensitivity=Sensitivity.NORMAL, clock=FakeClock()
    )
    first = next(iter(sources.values()))
    item = single_item_edit(
        item_id="synthetic-wide-detail",
        source=first,
        statement="\x01" * 16370 + "中文🙂",
        excerpt=files[first.original_name],
        tags=tuple(f"tag-{index:02d}" + "\x01" * 250 for index in range(64)),
    )
    item = replace(
        item,
        evidence=tuple(
            EvidenceInput(
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                excerpt=files[name],
            )
            for name, source in sources.items()
        ),
    )
    original = apply_ready(
        synthetic_store, ready_items(synthetic_store, batch, (item,))
    ).memory_ids[0]
    selected = [original]
    with writer_session(synthetic_store) as connection:
        for index in range(10):
            revision = f"mem_synthetic_wide_{index}"
            lineage = f"lin_synthetic_wide_{index}"
            connection.execute(
                "INSERT INTO memory_lineages VALUES (?, ?)", (lineage, 1850000000)
            )
            connection.execute(
                "INSERT INTO memory_revisions SELECT ?, ?, NULL, kind, statement, occurred_on, valid_from, valid_to, recorded_at, tags_json, sensitivity, application_id FROM memory_revisions WHERE revision_id = ?",
                (revision, lineage, original),
            )
            connection.execute(
                "INSERT INTO current_memory_heads VALUES (?, ?)", (lineage, revision)
            )
            connection.execute(
                "INSERT INTO memory_evidence SELECT ?, ordinal, source_id, blob_digest, mode, char_start, char_end, excerpt, source_level FROM memory_evidence WHERE memory_revision_id = ?",
                (revision, original),
            )
            selected.append(revision)
    got, sizes = walk_details(synthetic_store, {"memory_ids": selected})
    assert len(sizes) > 1
    assert got == [
        _memory_detail_data(get_memory(synthetic_store, item)) for item in selected
    ]
    assert all(
        len(detail["evidence"]) == 16 and len(detail["revision"]["tags"]) == 64
        for detail in got
    )
