"""Tie discovery teaching to supported synthetic retrieval and review behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, cast

import pytest
from synthetic import FakeClock, apply_ready, capture_text

from memory.errors import InvalidEvidenceError
from memory.mcp_prompts import skill_prompts
from memory.mcp_server import call_tool, create_server
from memory.model import RuntimePaths, Sensitivity, SourceSummary
from memory.reviews import get_change_set


def test_question_prompt_reaches_complete_read_only_open_item_workflow() -> None:
    """An explicit list must not depend on a relevance-filtered advice answer."""
    answer = next(p for p in skill_prompts() if p.name == "answer_a_question")
    assert "### Open items" in answer.workflow
    workflow = " ".join(answer.workflow.split("### Open items", 1)[1].split())
    for obligation in (
        'tags_all: ["loop:open"]',
        "future and undated items",
        "every page",
        "current heads",
        "pending",
        "No tracked open items",
        "never expires the commitment",
        "never advance a recurring item's date",
        "read-only",
    ):
        assert obligation in workflow
    assert "normal, sensitive, and restricted" in " ".join(answer.preamble.split())


def test_tool_discovery_teaches_open_item_convention_without_the_skill(
    synthetic_store: RuntimePaths,
) -> None:
    """A tools-only client must be able to form a complete generic tag walk."""
    descriptions = _descriptions(synthetic_store)
    search = descriptions["memory.search"]
    for obligation in ("loop:open", "valid_to", "future", "undated", "cursor"):
        assert obligation in search
    edit = descriptions["change_set.edit"]
    for obligation in ("loop:open", "source", "anchor", "recurrence"):
        assert obligation in edit


def test_review_prompt_distinguishes_partial_from_whole_loop_corrections() -> None:
    """Closing one grouped commitment must not erase the other open work."""
    review = next(p for p in skill_prompts() if p.name == "review_one_inbox_batch")
    body = " ".join(review.workflow.split())
    for obligation in (
        "only one of several follow-ups changes",
        "update only that part of the statement",
        "preserve the other commitments and dates",
        "keep `loop:open` while any remain unresolved",
        "shared horizon",
        "whole-loop changes",
    ):
        assert obligation in body


def _object(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return cast("dict[str, Any]", value)


def _envelope(
    paths: RuntimePaths, name: str, arguments: Mapping[str, object]
) -> dict[str, Any]:
    return _object(call_tool(paths, name, arguments)["structuredContent"])


def _descriptions(paths: RuntimePaths) -> dict[str, str]:
    return {
        tool.name: tool.description or ""
        for tool in asyncio.run(create_server(paths).list_tools())
    }


def _assert_floor_teaching(description: str) -> None:
    assert "sensitivity" in description
    assert "evidence" in description
    assert "effective" in description
    assert "highest" in description
    assert "apply" in description


def _draft(
    paths: RuntimePaths,
    batch_id: str,
    source: SourceSummary,
    sensitivity: Sensitivity,
) -> dict[str, Any]:
    created = _envelope(paths, "change_set.create", {"batch_id": batch_id})["data"]
    return _envelope(
        paths,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "itm_synthetic_sensitivity",
                    "memory": {
                        "kind": "fact",
                        "statement": "The synthetic amber room opens at dusk. 合成记录。",
                        "tags": ["synthetic"],
                        "sensitivity": sensitivity.value,
                    },
                    "evidence": [
                        {
                            "source_id": source.source_id,
                            "blob_digest": source.blob_digest,
                            "excerpt": "The synthetic amber room opens at dusk. 合成记录。",
                        }
                    ],
                }
            ],
        },
    )


@pytest.mark.parametrize("max_bytes", [None, 37])
def test_discovery_search_locator_reaches_late_bilingual_context_by_cursor_walk(
    synthetic_store: RuntimePaths, max_bytes: int | None
) -> None:
    """A default read cannot reach every hit, but the advertised cursor walk can."""
    prefix = "合成前言🙂 café.\n" * (16_000 if max_bytes is None else 8)
    target = "Synthetic copper lantern 合成铜灯 only opens after the bell.\n"
    body = prefix + target + "后续限制：雨天关闭。 Later caveat: closed during rain.\n"
    _, source = capture_text(
        synthetic_store,
        name="synthetic-late-context.txt",
        body=body,
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    hit = _envelope(synthetic_store, "source.search", {"query": "copper lantern"})[
        "data"
    ][0]
    assert hit["source"]["source_id"] == source.source_id
    match_start, match_end = hit["match_char_start"], hit["match_char_end"]
    assert body[match_start:match_end] == "copper lantern"

    arguments: dict[str, object] = {"source_id": source.source_id}
    if max_bytes is not None:
        arguments["max_bytes"] = max_bytes
    chunks: list[str] = []
    next_character = 0
    next_byte = 0
    first_end = None
    while True:
        chunk = _envelope(synthetic_store, "source.read", arguments)["data"]
        assert chunk["char_start"] == next_character
        assert chunk["byte_start"] == next_byte
        text = chunk["text"]
        assert text == body[chunk["char_start"] : chunk["char_end"]]
        assert chunk["char_end"] - chunk["char_start"] == len(text)
        assert chunk["byte_end"] - chunk["byte_start"] == len(text.encode("utf-8"))
        assert text
        chunks.append(text)
        next_character, next_byte = chunk["char_end"], chunk["byte_end"]
        if first_end is None:
            first_end = next_character
        if chunk["complete"]:
            break
        # Only an opaque cursor returned by the public read is ever supplied.
        arguments["cursor"] = chunk["next_cursor"]

    assert first_end is not None and match_start > first_end
    assert len(chunks) > 1
    reconstructed = "".join(chunks)
    assert reconstructed == body
    assert (
        reconstructed[hit["excerpt_char_start"] : hit["excerpt_char_end"]]
        == (hit["exact_excerpt"])
    )
    assert next_byte == source.byte_length

    discovered = {
        tool.name: tool
        for tool in asyncio.run(create_server(synthetic_store).list_tools())
    }
    read = discovered["source.read"]
    assert set(read.input_schema["properties"]) == {"source_id", "cursor", "max_bytes"}
    for name in ("source.search", "source.read"):
        teaching = discovered[name].description or ""
        assert "next_cursor" in teaching
        assert "one source.read" not in teaching
    search_schema = _object(discovered["source.search"].output_schema)
    locator = search_schema["oneOf"][0]["properties"]["data"]["items"]["properties"][
        "excerpt_char_start"
    ]["description"]
    assert "next_cursor" in locator
    assert "one bounded read" not in locator


@pytest.mark.parametrize("evidence_sensitivity", list(Sensitivity))
@pytest.mark.parametrize("memory_sensitivity", list(Sensitivity))
def test_discovery_floor_matches_edit_and_apply_validation(
    synthetic_store: RuntimePaths,
    evidence_sensitivity: Sensitivity,
    memory_sensitivity: Sensitivity,
) -> None:
    """All three levels enforce the floor, and discovery teaches it before authoring."""
    batch_id, source = capture_text(
        synthetic_store,
        name="synthetic-floor.txt",
        body="The synthetic amber room opens at dusk. 合成记录。\n",
        sensitivity=evidence_sensitivity,
        clock=FakeClock(),
    )
    result = _draft(synthetic_store, batch_id, source, memory_sensitivity)
    ranks = {Sensitivity.NORMAL: 0, Sensitivity.SENSITIVE: 1, Sensitivity.RESTRICTED: 2}
    if ranks[memory_sensitivity] < ranks[evidence_sensitivity]:
        assert result["error"]["code"] == "invalid_evidence"
        assert _envelope(synthetic_store, "memory.search", {})["data"] == []
    else:
        ready = get_change_set(synthetic_store, result["data"]["change_set_id"])
        # This is the existing test-only capability seam, not owner-presence proof.
        applied = apply_ready(synthetic_store, ready)
        memory = _envelope(
            synthetic_store, "memory.get", {"memory_id": applied.memory_ids[0]}
        )["data"]["revision"]
        assert memory["stored_sensitivity"] == memory_sensitivity.value
        assert memory["effective_sensitivity"] == memory_sensitivity.value

    descriptions = _descriptions(synthetic_store)
    _assert_floor_teaching(descriptions["change_set.edit"])
    _assert_floor_teaching(descriptions["change_set.approve_and_apply"])


@pytest.mark.parametrize(
    "initial_sensitivity", [Sensitivity.NORMAL, Sensitivity.SENSITIVE]
)
def test_apply_rechecks_floor_after_more_sensitive_duplicate(
    synthetic_store: RuntimePaths, initial_sensitivity: Sensitivity
) -> None:
    """A valid draft becomes unapplicable when duplicate evidence raises its floor."""
    body = "The synthetic amber room opens at dusk. 合成记录。\n"
    clock = FakeClock()
    batch_id, source = capture_text(
        synthetic_store,
        name="synthetic-before-draft.txt",
        body=body,
        sensitivity=initial_sensitivity,
        clock=clock,
    )
    draft = _draft(synthetic_store, batch_id, source, initial_sensitivity)["data"]
    ready = get_change_set(synthetic_store, draft["change_set_id"])
    capture_text(
        synthetic_store,
        name="synthetic-restricted-duplicate.txt",
        body=body,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    with pytest.raises(InvalidEvidenceError, match="sensitivity is below its evidence"):
        apply_ready(synthetic_store, ready)
    assert get_change_set(synthetic_store, ready.change_set_id) == ready
    assert _envelope(synthetic_store, "memory.search", {})["data"] == []
    _assert_floor_teaching(
        _descriptions(synthetic_store)["change_set.approve_and_apply"]
    )


@pytest.mark.parametrize(
    "initial_sensitivity", [Sensitivity.NORMAL, Sensitivity.SENSITIVE]
)
def test_retrieval_teaching_matches_later_duplicate_without_revision_rewrite(
    synthetic_store: RuntimePaths, initial_sensitivity: Sensitivity
) -> None:
    """Current evidence raises wire sensitivity without changing accepted history."""
    clock = FakeClock()
    body = "The synthetic amber room opens at dusk. 合成记录。\n"
    batch_id, source = capture_text(
        synthetic_store,
        name="synthetic-approved.txt",
        body=body,
        sensitivity=initial_sensitivity,
        clock=clock,
    )
    draft = _draft(synthetic_store, batch_id, source, initial_sensitivity)["data"]
    applied = apply_ready(
        synthetic_store, get_change_set(synthetic_store, draft["change_set_id"])
    )
    selector = {"memory_id": applied.memory_ids[0]}
    before = _envelope(synthetic_store, "memory.get", selector)["data"]
    capture_text(
        synthetic_store,
        name="synthetic-later-restricted.txt",
        body=body,
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    after = _envelope(synthetic_store, "memory.get", selector)["data"]
    assert before["revision"]["effective_sensitivity"] == initial_sensitivity.value
    assert after["revision"]["stored_sensitivity"] == initial_sensitivity.value
    assert after["revision"]["effective_sensitivity"] == "restricted"
    before["revision"]["effective_sensitivity"] = "restricted"
    assert after == before
    search = _envelope(
        synthetic_store,
        "memory.search",
        {"query": "amber room", "filters": {"sensitivities": ["restricted"]}},
    )
    assert search["data"][0]["memory"] == after["revision"]
    assert (
        _envelope(
            synthetic_store,
            "memory.search",
            {"filters": {"sensitivities": ["normal", "sensitive"]}},
        )["data"]
        == []
    )
    descriptions = _descriptions(synthetic_store)
    for name in ("memory.search", "memory.get"):
        teaching = descriptions[name].lower()
        assert "effective sensitivity" in teaching
        assert "stored" in teaching
        assert "current evidence" in teaching
        assert "duplicate" in teaching
