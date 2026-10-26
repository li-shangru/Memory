"""Synthetic contract checks for the companion Skill."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from staged_memory_intake.model import IntakeConfig, IntakeError
from staged_memory_intake.prepared import build_preview
from staged_memory_intake.securefs import directory_identity

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "tools" / "staged-memory-intake"
SKILL_PATH = SKILL_ROOT / "SKILL.md"
REFERENCE_ROOT = SKILL_ROOT / "references"
EXPECTED_REFERENCES = {
    "legacy-layout.md": "Migrate legacy folder names",
    "relocation.md": "Relocate the notes root",
    "decision-notes.md": "Draft or prepare a decision note",
    "loop-corrections.md": "Close or re-horizon an open loop",
    "open-items.md": "Prepare ordinary open items",
}
OPENAI_METADATA_PATH = SKILL_ROOT / "agents" / "openai.yaml"
HELPER_PATH = SKILL_ROOT / "scripts" / "staged_memory_intake"
SCENARIOS_PATH = REPO_ROOT / "tests" / "staged_memory_intake_skill_scenarios.json"
RECONCILIATION_SCENARIOS_PATH = (
    REPO_ROOT / "tests" / "staged_memory_intake_reconciliation_scenarios.json"
)

EXPECTED_FRONTMATTER = (
    "---\n"
    "name: staged-memory-intake\n"
    "description: Use when owner notes are in 02_Staged and need rewriting, "
    "summarizing, combining, or preparing for possible Memory retention, "
    "when an owner-placed closure note should close or re-horizon an open "
    "loop, or when the owner consents to saving an offered decision-note "
    "draft into 01_Pending.\n"
    "---\n"
)
EXPECTED_HEADINGS = [
    "# Staged Memory Intake",
    "## Start or resume",
    "## Choose the operation",
    "## Prepare outside Memory",
    "## Preview and owner-authorize",
    "## Publish and capture once",
    "## Build and verify one Review",
    "## Apply, verify, and Trash",
    "## Stop conditions",
]
EXPECTED_METADATA = (
    "interface:\n"
    '  display_name: "Staged Memory Intake"\n'
    '  short_description: "Prepare 02_Staged notes for Memory"\n'
    '  default_prompt: "Use $staged-memory-intake to prepare every 02_Staged '
    "Markdown note for private 03_Prepared review, show a content-free manifest, "
    "continue after exact owner approval, and complete macOS-backed "
    'Memory approval with verified cleanup."\n'
)
EXPECTED_HELPER_COMMANDS = {
    "authorize",
    "await-approval",
    "begin-scan",
    "cancel-publication",
    "check-batch",
    "check-memories",
    "check-review",
    "cleanup",
    "migrate-layout",
    "pending-drop",
    "preview prepared",
    "preview review",
    "publish",
    "reconcile-cleanup",
    "record-application",
    "record-scan",
    "relocate",
    "status",
}
EXPECTED_CODE_SPANS = {
    "--digest",
    "--input -",
    "--name",
    "--transaction",
    ".obsidian",
    "<loaded-skill-directory>",
    "<python> -B <loaded-skill-directory>/scripts/staged_memory_intake",
    "01_Pending",
    "04_Inbox",
    "03_Prepared",
    "SKILL.md",
    "02_Staged",
    "authorize",
    "cancel-publication",
    "cancellation_pending",
    "cancelled",
    "scan_started=false",
    "authorship=mixed",
    "await-approval",
    "begin-scan",
    "change_set.approve_and_apply",
    "change_set.create",
    "change_set.edit",
    "change_set.get",
    "check-batch",
    "check-memories",
    "check-review",
    "cleanup",
    "complete",
    "inbox.list",
    "inbox.read",
    "inbox.scan",
    "memory.get",
    "memory.search",
    "migrate-layout",
    "migrated",
    "moved",
    "pending-drop",
    "preserved",
    "preview prepared",
    "preview review",
    "publish",
    "published",
    "reconcile-cleanup",
    "record-application",
    "record-scan",
    "recovered",
    "relocate",
    "relocate --to <same exact absolute path> --adopt-current-authority",
    "relocated",
    "restricted",
    "scan_started",
    "status",
    "store.status",
    "source.search",
    "source.read",
    'tags_all: ["loop:open"]',
    "unconfigured",
    "using-memory",
    "verified",
    "current",
    "approved",
    "approval_handoff.command",
    "memory approve",
    "owner_declined",
    "owner_approval_required",
    "layout_migration_pending",
    "layout_migration_required",
    "notes_root_changed",
    "kind: event",
    "occurred_on",
    "valid_to",
    "aspect:",
    "subject:",
    "loop:open",
    "Outcome (<date>):",
    "verbatim_statement",
}


def _skill_text() -> str:
    assert SKILL_PATH.is_file(), "the canonical companion SKILL.md is missing"
    return SKILL_PATH.read_text(encoding="utf-8")


def _skill_body() -> str:
    text = _skill_text()
    assert text.startswith(EXPECTED_FRONTMATTER)
    return text.removeprefix(EXPECTED_FRONTMATTER)


def _reference_text(name: str) -> str:
    return (REFERENCE_ROOT / name).read_text(encoding="utf-8")


def _skill_contract() -> str:
    return "\n\n".join(
        [_skill_body(), *(_reference_text(name) for name in EXPECTED_REFERENCES)]
    )


def _flowed(text: str) -> str:
    return " ".join(text.casefold().split())


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def _strings(value: object) -> list[str]:
    assert isinstance(value, list)
    assert all(isinstance(item, str) for item in value)
    return value


def _scenarios() -> dict[str, tuple[set[str], set[str]]]:
    document = _mapping(json.loads(SCENARIOS_PATH.read_text(encoding="utf-8")))
    assert document["schema"] == "staged-memory-intake.scenarios.v1"
    values = document["scenarios"]
    assert isinstance(values, list)
    result: dict[str, tuple[set[str], set[str]]] = {}
    for value in values:
        scenario = _mapping(value)
        assert set(scenario) == {"id", "request", "must", "must_not"}
        scenario_id = scenario["id"]
        assert isinstance(scenario_id, str) and scenario_id not in result
        assert re.fullmatch(r"[a-z][a-z0-9_]+", scenario_id)
        request = scenario["request"]
        assert isinstance(request, str) and request.strip()
        must = _strings(scenario["must"])
        must_not = _strings(scenario["must_not"])
        assert must and must_not
        assert len(must) == len(set(must)) and len(must_not) == len(set(must_not))
        assert all(re.fullmatch(r"[a-z][a-z0-9_]+", label) for label in must + must_not)
        assert set(must).isdisjoint(must_not)
        result[scenario_id] = (set(must), set(must_not))
    return result


def test_authored_scenarios_preserve_required_safety_contracts() -> None:
    """Prospective cases describe required behavior, not observed model answers."""
    scenarios = _scenarios()
    assert {"wait_exact_owner_approval", "retain_originals"} <= scenarios[
        "detailed_secret_note"
    ][0]
    assert {"reuse_stale_digest", "approval_before_review"} <= scenarios[
        "private_prepared_review"
    ][1]
    assert {"second_scan", "second_review", "trash_any_original"} <= scenarios[
        "verification_mismatch"
    ][1]
    assert {"concise_faithful_rewrite", "requested_or_source_language"} <= scenarios[
        "decision_note_mapping"
    ][0]


def test_skill_has_exact_frontmatter_sections_budget_and_metadata() -> None:
    """Catch discovery metadata, operating sections, or budget drifting."""
    body = _skill_body()

    assert [line for line in body.splitlines() if line.startswith("#")] == (
        EXPECTED_HEADINGS
    )
    # Conditional procedures ship as references. Keep the entrypoint small;
    # the combined allowance includes the ordinary open-item teaching branch.
    # Mandatory reconciliation precedes every ordinary preparation; the
    # correction reference distinguishes Staged transport from advisory capture.
    assert len(body.split()) <= 2_600
    assert len(_skill_contract().split()) <= 4_800
    assert OPENAI_METADATA_PATH.read_text(encoding="utf-8") == EXPECTED_METADATA


def test_skill_routes_supported_operations_to_bundled_references() -> None:
    """Moved procedures must remain reachable from the loaded entrypoint."""
    body = _skill_body()
    linked = re.findall(r"\]\(references/([^()]+)\)", body)
    assert set(linked) == set(EXPECTED_REFERENCES)
    assert len(linked) == len(EXPECTED_REFERENCES)
    for name, heading in EXPECTED_REFERENCES.items():
        assert _reference_text(name).startswith(f"# {heading}\n")
    flowed = _flowed(body)
    assert "read the matching reference before acting on its branch" in flowed
    assert "load only references needed" in flowed
    assert "before writing any prepared candidate" in flowed
    assert "pending migration or relocation blocks every other helper command" in flowed


def test_skill_pins_preparation_and_direct_authorization_rules() -> None:
    """Prevent premature custody and automatic splitting."""
    body = _flowed(_skill_body())

    for required in (
        "never read `01_pending`",
        "never read `01_pending` or edit `02_staged`",
        "write every new root-level candidate to `03_prepared` before preview",
        "length never causes splitting",
        "one prepared file becomes one memory item",
        "preview the complete exact set",
        "an unqualified `approved` response immediately following",
        "earlier approval, approval before preview, or approval after drift does not authorize",
        "never overwrite one",
        "default requested sensitivity is `restricted`",
        "write every new root-level candidate to `03_prepared` before preview",
        "retain the 02_staged and 03_prepared originals",
    ):
        assert required in body

    grammar = (
        "memory_intake_version: 1\n"
        "source_note: <staged-relative-name>\n"
        "source_sha256: <lowercase-sha-256-of-exact-staged-bytes>\n"
        "kind: <fact|event|preference|relation|insight>\n"
        "sensitivity: <normal|sensitive|restricted>\n"
        "occurred_on:\n"
        "valid_from:\n"
        "valid_to:\n"
        "tags: []"
    )
    assert grammar in _skill_body()


def test_skill_keeps_prepared_review_content_out_of_chat() -> None:
    """Make Prepared the private review surface instead of reproducing notes."""
    body = _flowed(_skill_body())

    for required in (
        "prepare every candidate before requesting owner review",
        "`03_prepared` is the owner's private review surface",
        "show only a content-free manifest in chat",
        "the helper output itself must be content-free",
        "never reproduce a prepared body, statement, front matter, or evidence excerpt in chat",
        "the owner may edit prepared files in place",
        "after any edit, run a fresh complete preview",
        "approval authorizes only the digest in that current content-free manifest",
    ):
        assert required in body


def test_skill_defaults_to_every_staged_markdown_without_prompt() -> None:
    """Make an unqualified invocation cover the whole supported Staged scope."""
    body = _flowed(_skill_body())
    for required in (
        "select every visible, root-level regular markdown file in `02_staged`",
        "do not ask the owner to name those files",
        "leave hidden entries and regular non-markdown files untouched",
        "a visible link or directory makes scope uncertain and stops",
        "one-to-one minimum complete memory per selected staged note",
        "retain every distinct durable fact, preference, constraint, condition, "
        "exception, relationship, rationale, and uncertainty",
        "remove repetition, redundant restatements, drafting commentary, incidental "
        "formatting, and generic filler that adds no distinct information",
        "retain an example when it uniquely establishes scope, a boundary, or an exception",
        "when unsure whether a detail is material, retain it",
        "do not impose a word, paragraph, or byte target",
        "length follows the amount of distinct material information",
        "the helper's size ceiling is not a quality target",
        "do not fabricate conclusions, infer unsupported preferences, or discard "
        "qualifications merely to shorten a note",
        "do not combine or split notes by default",
        "an explicit owner-supplied subset or preparation operation overrides",
    ):
        assert required in body

    assert "distilled" not in body


def test_skill_makes_the_preparation_operation_a_conscious_decision() -> None:
    """Keep every selected preparation operation visible through review."""
    body = _flowed(_skill_body())
    for required in (
        "name the operation applied to each candidate in that mapping",
        "faithful, rewrite, summary, combine, or split",
        "never leave it implicit",
        "the operation applied per candidate",
        "every `verbatim_statement` marker",
        "the helper marks each candidate whose statement carries the staged "
        "note's text unchanged with `verbatim_statement`",
        "present every marked candidate as verbatim",
        "a conscious owner decision",
    ):
        assert required in body


def test_skill_requires_portable_markdown_statement_bodies() -> None:
    """Keep editor-specific note markup out of published statement bodies."""
    body = _flowed(_skill_body())
    for required in (
        "write every statement as portable markdown",
        "a wiki-style bracketed link or embed becomes its plain visible text",
        "a callout marker becomes an ordinary blockquote or paragraph",
        "a trailing block-reference anchor and an inline hash-prefixed tag "
        "become plain words or front-matter tags",
        "portable cleanup must not change meaning",
    ):
        assert required in body


def test_skill_uses_requested_or_source_language_without_personal_defaults() -> None:
    """Keep generated language a per-operation choice with faithful identity."""
    body = _flowed(_skill_body())
    for required in (
        "use the owner's requested output language for this operation",
        "otherwise preserve the source language, including mixed-language passages",
        "apply this rule to prepared statements, generated filenames, and ordinary tag text",
        "source_note remains the exact source filename",
        "preserve identity-bearing names and terms and exact quotations in any language",
        "do not silently translate, romanize, or ascii-filter them",
        "keep machine keys, reserved tag tokens and prefixes, and decision-section labels unchanged",
        "do not infer or persist a personal language preference",
        "do not retroactively rewrite existing notes or change runtime or client configuration",
        "reserve standing for a source-explicit durable preference, pattern, "
        "or constraint meant to guide future advice",
    ):
        assert required in body


def test_skill_derives_supported_semantic_dates_without_timestamp_guessing() -> None:
    """Populate source-supported dates while preserving absence and precision."""
    body = _flowed(_skill_body())
    for required in (
        "populate occurred_on for an event or occurrence date, valid_from for an "
        "explicit effective or start date, and valid_to for an explicit expiry, "
        "horizon, or revisit date",
        "preserve the supported precision of partial dates",
        "when a month and day lack a year and are clearly close to preparation, "
        "infer the calendar occurrence nearest the current local date",
        "respect explicit past or future wording",
        "near a year boundary this may be the previous or next year",
        "never use filesystem timestamps, capture time, or preparation time as "
        "occurrence evidence",
        "leave a field blank only when the semantic date is absent or materially ambiguous",
        "keep dates private inside `03_prepared`; never add them to chat or the "
        "content-free manifest",
    ):
        assert required in body


def test_skill_maps_ordinary_open_items_without_inventing_future_intent() -> None:
    """Pin the teaching contract; this does not grade model extraction."""
    body = _flowed(_skill_body())
    assert "[open items](references/open-items.md)" in body
    guidance = _flowed(_reference_text("open-items.md"))
    for required in (
        "explicit unresolved commitment, reminder, or review intent",
        "add `loop:open` even when no date is stated",
        "a retrospective quarterly-review note alone does not create a recurring commitment",
        "preserve owner-stated recurrence and its anchor in the statement",
        "`valid_to` holds only the next explicitly supported horizon",
        "do not invent a next date from quarterly alone",
        "leave `valid_to` blank",
        "one note and one item remain the default",
        "multiple independent follow-ups with different horizons",
        "an owner-specified split",
        "do not collapse those horizons into a misleading single `valid_to`",
        "the decision-note contract remains unchanged",
    ):
        assert required in guidance


def test_skill_bounds_relative_horizons_and_read_only_recall() -> None:
    """Guard source anchors, passive recall, and exact correction authority."""
    body = _flowed(_skill_body())
    assert "[open items](references/open-items.md)" in body
    guidance = _flowed(_reference_text("open-items.md"))
    for required in (
        "resolve relative days only from an unambiguous source-stated calendar date",
        "never use filesystem, capture, preparation, or current timestamps as the anchor",
        "preserve the exact relative intent",
        "an absent anchor does not erase the open intent",
        "recall on request or in a relevant conversation",
        "do not create a scheduler or promise proactive notifications",
        "reads never advance a horizon or close an open item",
        "closure and re-horizon use the existing loop-correction route",
        "exact owner-approved memory review",
    ):
        assert required in guidance


def test_partial_loop_update_preserves_other_open_followups() -> None:
    """The ordinary grouped-note route cannot use whole-loop close semantics."""
    guidance = _flowed(_reference_text("loop-corrections.md"))
    for required in (
        "only one of several independent follow-ups changes",
        "ordinary correction note",
        "update only the affected part of the statement",
        "preserve every other commitment and date",
        "keep `loop:open` while any follow-up remains unresolved",
        "whole-loop rules below do not apply to a partial update",
    ):
        assert required in guidance


def _assert_preparation_reconciliation(body: str) -> None:
    required = (
        "before writing any prepared candidate, reconcile every selected source",
        "call `store.status` first",
        'queryless `memory.search` with `tags_all: ["loop:open"]`',
        "exhaust every page without aspect, kind, date, or sensitivity filters",
        "relevant bounded `memory.search` and `source.search` queries",
        "complete current `memory.get` details, history, guards, and material `source.read` walks",
        "thin, conflicting, or unmatched updates require using-memory's enumeration and full-source fallback",
        "match meaning and provenance, never filenames or closure headings alone",
        "classify every selected source as new, whole-loop closure, re-horizon, or partial correction",
        "route corrections through the loop-corrections reference before any prepared writing",
        "never prepare an existing-loop update as a new item or silently omit it",
        "target or disposition ambiguity blocks the selected preparation",
        "keep reconciliation output content-free",
    )
    for phrase in required:
        assert phrase in body
    reconciliation = body.index(required[0])
    assert reconciliation < body.index("with no explicit operation, create one-to-one")
    assert reconciliation < body.index("write every new root-level candidate")


def test_skill_requires_reconciliation_before_any_prepared_write() -> None:
    """An ordinary update must resolve its current approved target first."""
    _assert_preparation_reconciliation(_flowed(_skill_body()))


def test_skill_cancellation_requires_exact_owner_requested_unscanned_transaction() -> (
    None
):
    """Withdrawal cannot erase a scan or reuse the retired authorization."""
    body = _flowed(_skill_body())
    for phrase in (
        "on an owner request to withdraw a published set before scanning",
        "run `cancel-publication`",
        "recorded full `--transaction` and `--digest`",
        "only `published` with `scan_started=false` is eligible",
        "preserves originals/receipt",
        "`cancellation_pending` blocks other work",
        "`cancelled` is terminal",
        "fresh preview/approval",
        "after scanning starts, cancellation is forbidden",
    ):
        assert phrase in body


def test_reconciliation_gate_rejects_late_or_narrowed_retrieval() -> None:
    """The mandatory step cannot follow a rewrite or suppress future loops."""
    body = _flowed(_skill_body())
    start = body.index("before writing any prepared candidate, reconcile")
    end = body.index("before writing any candidate for the selected set", start)
    reconciliation = body[start:end]
    moved_after_writing = body[:start] + body[end:] + reconciliation
    with pytest.raises(AssertionError):
        _assert_preparation_reconciliation(moved_after_writing)
    narrowed = body.replace(
        "exhaust every page without aspect, kind, date, or sensitivity filters",
        "read the first page of due normal-sensitivity items",
    )
    assert narrowed != body
    with pytest.raises(AssertionError):
        _assert_preparation_reconciliation(narrowed)


def test_reconciliation_preserves_action_state_and_grouped_scope() -> None:
    """A planned stop and one changed follow-up cannot close the entire memory."""
    guidance = _flowed(_reference_text("loop-corrections.md"))
    for phrase in (
        "an ordinary update can resolve or change an existing loop without a closure heading",
        "a decision to stop is not evidence that stopping has occurred",
        "preserve the distinction between a stated decision, intended action, and completed action",
        "never assume a grouped memory closes because one follow-up changed",
        "preserve current history and every unaffected field",
        "target the current lineage and expected head",
        "keep staged and retained content out of chat",
    ):
        assert phrase in guidance


def _assert_agent_operated_staged_correction(guidance: str) -> None:
    start = guidance.index("## owner-placed staged sources")
    end = guidance.index("## conversational drafts", start)
    staged_route = guidance[start:end]
    for required in (
        "an intake request authorizes the agent to transport each selected owner-placed staged correction source",
        "never ask the owner to copy it to `04_inbox` or capture it again in the ui",
        "copy the exact original bytes exclusively",
        "before copying or scanning, enumerate every `inbox.list` page",
        "match full published names, blob digests, byte lengths, origin, authorship, and sensitivity",
        "after an issued scan, a lost result permits enumeration only, never another scan",
        "one batch, one change set",
        "exact owner approval",
        "preserve staged originals after verification",
        "do not use `03_prepared` or the ordinary helper's `authorize`, `publish`, `check-review`, or `cleanup`",
    ):
        assert required in staged_route
    for manual_handoff in (
        "the owner places it directly",
        "ask the owner to place",
        "tell the owner to copy",
    ):
        assert manual_handoff not in staged_route


def test_owner_placed_staged_correction_has_no_manual_copy_checkpoint() -> None:
    """An intake request must carry ready owner evidence into its correction Review."""
    _assert_agent_operated_staged_correction(
        _flowed(_reference_text("loop-corrections.md"))
    )


def test_staged_transport_and_conversation_only_offer_have_distinct_authority() -> None:
    """Removing the Staged handoff cannot authorize capturing an advisory draft."""
    guidance = _flowed(_reference_text("loop-corrections.md"))
    _assert_agent_operated_staged_correction(guidance)
    conversation = guidance[guidance.index("## conversational drafts") :]
    for required in (
        "conversation-only drafts",
        "the owner places it directly into `04_inbox`",
        "never write it anywhere yourself",
        "an intake request does not authorize capturing words supplied only in conversation",
    ):
        assert required in conversation
    regressed = guidance.replace(
        "copy the exact original bytes exclusively",
        "tell the owner to copy the original into the inbox",
    )
    assert regressed != guidance
    with pytest.raises(AssertionError):
        _assert_agent_operated_staged_correction(regressed)


def test_staged_corrections_group_shared_targets_before_transport() -> None:
    """Two contributing notes must not create competing successors for one head."""
    guidance = _flowed(_reference_text("loop-corrections.md"))
    for required in (
        "group selected sources by current target lineage/head before copying or scanning",
        "one correction per target lineage, citing every contributing source",
        "resolve the combined supported outcome before transport",
        "unresolved contradictions block dependent work",
        "validate the complete grouped proposal against existing public review bounds before transport",
        "over-bound groups remain untouched with a content-free capability blocker",
        "already owner-placed inbox sources skip staged-copy and empty-inbox setup",
    ):
        assert required in guidance
    assert "one correction per note" not in guidance


def test_reconciliation_forward_cases_cover_synthetic_en_zh() -> None:
    """Keep authored future client cases distinct from recorded evaluations."""
    document = _mapping(
        json.loads(RECONCILIATION_SCENARIOS_PATH.read_text(encoding="utf-8"))
    )
    assert document["schema"] == "staged-memory-intake.reconciliation-scenarios.v1"
    scenarios = document["scenarios"]
    assert isinstance(scenarios, list)
    languages: set[str] = set()
    routes: set[str] = set()
    ids: set[str] = set()
    for value in scenarios:
        scenario = _mapping(value)
        scenario_id = scenario["id"]
        language = scenario["language"]
        request = scenario["request"]
        route = scenario["expected_route"]
        assert isinstance(scenario_id, str) and scenario_id.startswith("synthetic_")
        assert scenario_id not in ids
        assert isinstance(language, str) and language in {"en", "zh"}
        assert isinstance(request, str) and request
        assert isinstance(route, str)
        assert route in {"whole_loop_closure", "re_horizon", "partial_correction"}
        must = set(_strings(scenario["must"]))
        must_not = set(_strings(scenario["must_not"]))
        assert {
            "status_first",
            "exhaustive_open_loop_walk",
            "current_head_and_complete_evidence",
            "agent_transports_staged_original",
            "reuse_exact_prior_capture",
            "preserve_staged_original_after_verification",
        } <= must
        assert {
            "prepare_as_new_item",
            "private_content_in_chat",
            "ask_owner_to_copy_staged_to_inbox",
            "recapture_on_lost_result",
            "ordinary_helper_correction_receipt",
        } <= must_not
        assert not must & must_not
        if language == "zh":
            assert re.search(r"[\u4e00-\u9fff]", request)
        ids.add(scenario_id)
        languages.add(language)
        routes.add(route)
    assert languages == {"en", "zh"}
    assert routes == {"whole_loop_closure", "re_horizon", "partial_correction"}


def test_skill_blocks_the_whole_selection_for_meaningful_ambiguity() -> None:
    """Separate automatic typo cleanup from unresolved source ambiguity."""
    body = _flowed(_skill_body())
    for required in (
        "before writing any candidate for the selected set, perform a semantic "
        "plausibility and consistency pass over every selected source",
        "automatically correct clear spelling and typing errors in generated "
        "prepared prose, including meaning-bearing or domain-specific terms, when "
        "source context makes the intended wording unambiguous",
        "do not report these as errors or request confirmation",
        "preserve staged bytes, source hashes, and exact quotations",
        "flag only unresolved suspected typos",
        "implausible or easily confused numbers, magnitudes, and units",
        "conflicting dates or chronology",
        "internal contradictions",
        "ambiguous names, relationships, or assertions where different corrections "
        "would change meaning",
        "keep meaning-safe grammar and presentation cleanup automatic too",
        "if clarification is required, block the entire selected preparation before "
        "writing, previewing, authorizing, publishing, or omitting any note",
        "report only the staged filename, a private line or section location when "
        "useful, and the issue category",
        "do not quote private source content unless the owner supplied that exact "
        "text in the current conversation",
        "ask the owner to correct or confirm the source privately in `02_staged`; "
        "never edit `02_staged`",
        "a chat-only correction is not source evidence",
        "after the owner updates the source, reread it and regenerate from the new "
        "exact bytes and source hash",
        "never put warnings, todos, or clarification markers in prepared content or "
        "front matter",
        "a clean plausibility pass does not certify objective truth; integrity is not truth",
    ):
        assert required in body


def test_skill_stops_default_scope_above_candidate_ceiling_before_writes() -> None:
    """Keep a 51-note default scope from creating an unpreviewable draft."""
    body = _flowed(_skill_body())
    for required in (
        "before reading or writing candidates, count eligible names only",
        "never exceed 50 candidates",
        "if default scope exceeds 50, stop before creating any prepared candidate",
        "leave all notes untouched",
        "explicit subset of at most 50",
        "never silently batch, auto-select, or begin a second transaction",
        "explicit subsets and output counts also stay at most 50",
    ):
        assert required in body


def _assert_no_prompt_approval_continuation(body: str) -> None:
    for required in (
        "an unqualified `approved` response immediately following",
        "continue the same transaction without another conversational checkpoint",
        "if no approval prompt was displayed",
        "`owner_approval_required` or `owner_declined`",
        "do not report `owner_declined` as the owner's decision",
        "immediately run `approval_handoff.command` exactly and in the foreground",
        "do not pause for another chat response",
        "do not edit it or append flags",
        "running `memory approve` is not owner approval",
        "macos owner-presence challenge",
        "a visibly displayed prompt",
        "declines or cancels",
        "stops",
        "never runs the handoff",
        "cli owner-presence challenge is declined, cancelled, fails, or times out",
        "do not retry the handoff or replay the mcp triple",
        "call the same exact `change_set.approve_and_apply` triple again",
        "exact replay is idempotent",
        "structured application result",
    ):
        assert required in body


def test_skill_runs_exact_cli_approval_and_recovers_structured_result() -> None:
    """Continue exact Prepared approval through macOS presence and verification."""
    _assert_no_prompt_approval_continuation(_flowed(_skill_body()))


def test_no_prompt_continuation_gate_rejects_owner_decline_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prove the contract rejects relabeling an unsurfaced refusal as owner choice."""
    skill_path = tmp_path / "SKILL.md"
    regressed = _skill_text().replace(
        "Do not report `owner_declined` as\n"
        "the owner's decision. Do not pause for another chat response.",
        "Report `owner_declined` as the owner's decision and stop.\n",
    )
    assert regressed != _skill_text()
    skill_path.write_text(regressed, encoding="utf-8")
    monkeypatch.setitem(globals(), "SKILL_PATH", skill_path)

    with pytest.raises(AssertionError):
        _assert_no_prompt_approval_continuation(_flowed(_skill_body()))


def _write_skill_candidate(
    prepared_root: Path,
    staged_root: Path,
    prepared_name: str,
) -> None:
    source_name = f"{prepared_name.removesuffix('.md')}-source.md"
    source_bytes = f"Synthetic source for {prepared_name}.".encode()
    staged_root.joinpath(source_name).write_bytes(source_bytes)
    prepared_root.joinpath(prepared_name).write_text(
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source_bytes).hexdigest()}\n"
        "kind: fact\n"
        "sensitivity: restricted\n"
        "occurred_on: \n"
        "valid_from: \n"
        "valid_to: \n"
        'tags: ["synthetic"]\n'
        "---\n"
        f"Synthetic prepared statement for {prepared_name}.\n",
        encoding="utf-8",
    )


def test_skill_guard_examples_execute_with_exact_direction(
    tmp_path: Path,
) -> None:
    """Prove the documented endpoint grammar through a real preview."""
    notes_root = tmp_path / "synthetic-notes"
    prepared_root = notes_root / "03_Prepared"
    staged_root = notes_root / "02_Staged"
    inbox = tmp_path / "synthetic-inbox"
    for path in (notes_root, prepared_root, staged_root, inbox):
        path.mkdir(mode=0o700)
    _write_skill_candidate(prepared_root, staged_root, "Guard.md")
    _write_skill_candidate(prepared_root, staged_root, "Claim.md")
    config = IntakeConfig(
        notes_root=notes_root,
        notes_identity=directory_identity(notes_root),
        memory_home=None,
        memory_inbox=inbox,
        inbox_identity=directory_identity(inbox),
    )
    examples = [
        '{"guard":{"prepared_name":"Guard.md"},'
        '"governed":{"prepared_name":"Claim.md"}}',
        '{"guard":{"lineage_id":"lin_existing"},'
        '"governed":{"prepared_name":"Claim.md"}}',
        '{"guard":{"prepared_name":"Guard.md"},'
        '"governed":{"lineage_id":"lin_existing"}}',
    ]

    preview = build_preview(config, ["Guard.md", "Claim.md"], examples)

    assert [
        (
            link.guard.prepared_name,
            link.guard.lineage_id,
            link.governed.prepared_name,
            link.governed.lineage_id,
        )
        for link in preview.guard_links
    ] == [
        ("Guard.md", None, "Claim.md", None),
        (None, "lin_existing", "Claim.md", None),
        ("Guard.md", None, None, "lin_existing"),
    ]

    invalid_examples = [
        '{"guard":{"prepared_name":"Guard.md",'
        '"prepared_name":"Claim.md"},'
        '"governed":{"lineage_id":"lin_existing"}}',
        '{"guard":{"lineage_id":"lin_guard"},"governed":{"lineage_id":"lin_existing"}}',
    ]
    for invalid in invalid_examples:
        with pytest.raises(IntakeError, match="invalid_guard_spec"):
            build_preview(config, ["Guard.md", "Claim.md"], [invalid])


def test_skill_teaches_guard_supersede_and_scan_recovery() -> None:
    """Preserve exact guard direction, supersession and scan-recovery rules."""
    body = _flowed(_skill_body())
    for example in (
        '{"guard":{"prepared_name":"guard.md"},'
        '"governed":{"prepared_name":"claim.md"}}',
        '{"guard":{"lineage_id":"lin_existing"},'
        '"governed":{"prepared_name":"claim.md"}}',
        '{"guard":{"prepared_name":"guard.md"},'
        '"governed":{"lineage_id":"lin_existing"}}',
    ):
        assert example in body
    for required in (
        "each endpoint has exactly one key",
        "duplicate json keys are invalid",
        "existing-to-existing is invalid",
        "at least one endpoint must name a selected prepared candidate",
        "direction matters",
        "fresh complete preview and direct owner decision",
        "exact paired supersede transaction and old digest",
        "--supersede-transaction",
        "--supersede-digest",
        "never abbreviate a transaction id or digest",
        "supersede is forbidden after publication intent",
        "full transaction-bound visible names",
        "zero or multiple matching batches stop",
    ):
        assert required in body


def test_skill_pins_single_capture_review_application_and_cleanup() -> None:
    """Catch a second batch/review or cleanup before exact public verification."""
    body = _flowed(_skill_body())

    for required in (
        "use `using-memory` for every memory call",
        "this skill owns intake coordination, private presentation",
        "call `store.status` first",
        "do not scan unless the transaction is `published` and the 04_inbox is exact",
        "durably observe `scan_started`",
        "call `inbox.scan` exactly once",
        "`authorship=mixed`",
        "the preview's batch sensitivity",
        "enumerate every `inbox.list` page",
        "never call `inbox.scan` again",
        "recover only an exact batch through `inbox.read`",
        "report every duplicate notice",
        "reuse the recorded batch and change set after interruption or decline",
        "apply only memory's exact owner-approved revision",
        "report every standing guard violation",
        "trash originals only after the helper verifies the bounded `memory.get` result",
        "never infer cleanup reconciliation",
        "require the owner's decision for one exact ordinal",
    ):
        assert required in body

    ordered_markers = [
        "`preview prepared`",
        "`authorize`",
        "`publish`",
        "`begin-scan`",
        "`inbox.scan`",
        "`record-scan`",
        "`check-batch`",
        "`change_set.create`",
        "`preview review`",
        "`check-review`",
        "`await-approval`",
        "`change_set.approve_and_apply`",
        "`record-application`",
        "`memory.get`",
        "`check-memories`",
        "`cleanup`",
    ]
    continuation = body[body.index("## preview and owner-authorize") :]
    positions = [continuation.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)


def test_skill_resolves_python_and_uses_only_stdin_for_memory_snapshots() -> None:
    """Catch an incompatible interpreter or persistent contentful snapshots."""
    body = _flowed(_skill_body())
    python_requirement = "resolve a python 3.14 interpreter"
    invocation = "<python> -b <loaded-skill-directory>/scripts/staged_memory_intake"

    assert python_requirement in body
    assert "refuse an older or newer interpreter" in body
    assert invocation in body
    assert body.index(python_requirement) < body.index(invocation)
    assert "pass every memory snapshot over stdin with `--input -`" in body
    assert "never persist a memory snapshot in a workflow file" in body
    assert "if `status` reports `unconfigured`, stop" in body
    assert "do not configure or create `03_prepared`" in body


def test_skill_requires_the_coordinated_relocation_command() -> None:
    """Catch guidance that permits a raw root rename or direct config repair."""
    body = _flowed(_reference_text("relocation.md"))

    for required in (
        "run `relocate` with the exact absolute destination root",
        "stop the owner ui and every connected memory client",
        "rerun the exact same `relocate` command and destination",
        "never rename the configured root in finder, use a raw filesystem move, "
        "create a symlink, edit either private configuration",
        "only after the owner explicitly confirms",
        "`relocate --to <same exact absolute path> --adopt-current-authority`",
        "`relocated`, `recovered`, or `current`",
    ):
        assert required in body


def test_skill_distinguishes_same_path_adoption_from_relocation() -> None:
    """Keep stale-authority recovery distinct from an ordinary root move."""
    body = _flowed(_reference_text("relocation.md"))

    for required in (
        "if `status` reports `notes_root_changed`, stop",
        "only after the owner explicitly confirms",
        "`relocate --to <same exact absolute path> --adopt-current-authority`",
        "atomically adopts current root and inbox identities",
        "moves nothing",
        "never runs memory inbox relocation",
        "must return `current`",
        "require a different absent destination",
        "never rename the configured root in finder, use a raw filesystem move, "
        "create a symlink, edit either private configuration",
        "after success, rerun `status` before reading `02_staged`",
        "restart clients",
    ):
        assert required in body


def test_skill_names_exact_same_path_adoption_cli_syntax() -> None:
    """Keep the owner-authorized recovery command directly executable."""
    body = _flowed(_reference_text("relocation.md"))

    assert "relocate --to <same exact absolute path> --adopt-current-authority" in body


def test_skill_relocation_gate_rejects_permissive_raw_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prove split positive fragments cannot admit a raw-move permission."""
    reference_path = tmp_path / "relocation.md"
    permissive = _reference_text("relocation.md").replace(
        "Never rename the configured root in Finder, use a raw filesystem move,\n",
        "Never rename the configured root in Finder. You may use a raw filesystem move,\n",
    )
    assert permissive != _reference_text("relocation.md")
    reference_path.write_text(permissive, encoding="utf-8")
    monkeypatch.setitem(globals(), "REFERENCE_ROOT", tmp_path)

    with pytest.raises(AssertionError):
        test_skill_requires_the_coordinated_relocation_command()

    with pytest.raises(AssertionError):
        test_skill_distinguishes_same_path_adoption_from_relocation()


def test_skill_requires_explicit_legacy_layout_migration() -> None:
    """Catch an agent renaming legacy folders or bypassing exact recovery."""
    body = _flowed(_reference_text("legacy-layout.md"))

    for required in (
        "if `status` reports `layout_migration_required`",
        "run `migrate-layout` with no path argument",
        "preserves every directory identity",
        "rerun the same `migrate-layout` command",
        "a `layout_migration_pending` result blocks every other helper command",
        "never rename these folders in finder",
        "never create aliases or symlinks",
        "never edit either private configuration",
        "never inspect or enumerate a workflow child during migration",
        "`01_pending`, `02_staged`, `03_prepared`, and `04_inbox`",
        "`migrated`, `recovered`, or `current`",
    ):
        assert required in body


def _assert_named_helper_commands_have_real_help() -> None:
    body = _skill_contract()
    code_spans = set(re.findall(r"`([^`\n]+)`", body))
    assert code_spans == EXPECTED_CODE_SPANS
    named = code_spans & EXPECTED_HELPER_COMMANDS

    assert named == EXPECTED_HELPER_COMMANDS
    assert sys.version_info >= (3, 14)
    for command in sorted(named):
        result = subprocess.run(
            [sys.executable, "-B", str(HELPER_PATH), *command.split(), "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0, (command, result.stderr)
        assert "usage:" in result.stdout.casefold()


def test_every_named_helper_command_has_real_help() -> None:
    """Catch the Skill teaching a helper spelling that the CLI does not accept."""
    _assert_named_helper_commands_have_real_help()


def test_skill_is_vendor_neutral_and_has_no_store_escape_hatch() -> None:
    """Catch owner paths, client coupling, case teaching, or direct Store access."""
    folded = (_skill_text() + _skill_contract()).casefold()
    for forbidden in (
        "/users/",
        "runtime.json",
        "store.sqlite3",
        "keychain",
        "unlink",
        "codex",
        "claude",
        "openai",
        "bitwarden",
        "credential-practice",
        "memory.mcp.v1",
    ):
        assert forbidden not in folded
    assert re.search(r"\bsql\b", folded) is None
    assert re.search(r"\brm\b", folded) is None


def _archive_entries(path: Path) -> list[tuple[str, bytes]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return [
                (entry.filename, archive.read(entry))
                for entry in archive.infolist()
                if not entry.is_dir()
            ]

    entries: list[tuple[str, bytes]] = []
    with tarfile.open(path, "r:*") as archive:
        for entry in archive.getmembers():
            if not entry.isfile():
                continue
            extracted = archive.extractfile(entry)
            assert extracted is not None
            entries.append((entry.name, extracted.read()))
    return entries


def test_wheel_and_sdist_exclude_companion_and_test_data(
    tmp_path: Path,
) -> None:
    """Catch the optional companion crossing the Memory package boundary."""
    completed = subprocess.run(
        ["uv", "build", "--out-dir", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    archives = sorted(
        path
        for path in tmp_path.iterdir()
        if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    assert len([path for path in archives if path.suffix == ".whl"]) == 1
    assert len([path for path in archives if path.name.endswith(".tar.gz")]) == 1

    forbidden_names = (
        "staged-memory-intake",
        "staged_memory_intake",
        "tools/",
        "tests/",
    )
    forbidden_content = (
        b"/Users/",
        b"Users/",
        b"staged-memory-intake.scenarios.v1",
    )
    for archive_path in archives:
        entries = _archive_entries(archive_path)
        for name, content in entries:
            assert not any(fragment in name for fragment in forbidden_names)
            assert not any(fragment in content for fragment in forbidden_content)


def test_helper_command_gate_rejects_unknown_backticked_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not ignore a new misspelled command outside the known-good regex."""
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text(
        _skill_text() + "\nRun `publsih` now.\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(globals(), "SKILL_PATH", skill_path)

    with pytest.raises(AssertionError):
        _assert_named_helper_commands_have_real_help()


def test_skill_maps_decision_notes_and_keeps_the_offer_disciplined() -> None:
    """Catch the decision-note shape or its volume discipline drifting."""
    body = _flowed(_reference_text("decision-notes.md"))
    for required in (
        "follow `using-memory`'s canonical decision-note offer rule",
        "an actual owner decision after a recommendation requires one complete draft",
        "never before that decision or again after a decline",
        "never write it into `02_staged` or `03_prepared`",
        "six labeled sections",
        "question, options considered, recommendation, decision, rationale, revisit by",
        "omit revisit by entirely unless the owner stated a revisit intent",
        "rewrite a staged decision note concisely in the owner's requested output language",
        "otherwise preserve its source language, including mixed-language passages",
        "preserve the required labeled decision structure",
        "every material option, recommendation, decision, rationale, condition, and uncertainty",
        "include revisit by only when the source states it",
        "existing front-matter and loop-tag semantics remain unchanged",
        "`kind: event` always",
        "`valid_to` is the revisit by date and stays blank without one",
        "`loop:open` exactly when revisit by is present",
        "do not combine a decision note with another note",
        "never split a decision note",
        "says to save it, you may instead write it through the helper",
        "run `pending-drop` with `--name`",
        "creates one new file in `01_pending` and never overwrites",
        "present the draft for the owner to place and do not retry",
        "consent covers one draft, once",
        "permission from an earlier session never authorizes a write",
        "never enable or configure the drop yourself",
    ):
        assert required in body

    assert "may close a session" not in body
    assert "when in doubt, do not offer" not in body
    assert "keep the whole body verbatim as the statement" not in body


def test_skill_maps_loop_closure_and_keeps_the_offer_disciplined() -> None:
    """Catch the closure/re-horizon mapping or its discipline drifting."""
    body = _flowed(_reference_text("loop-corrections.md"))
    for required in (
        "one draft closure note",
        "after the owner states that an open loop is resolved or that its horizon moves",
        "never draft before that, never re-raise after a decline",
        "when in doubt, do not offer",
        "three labeled sections — loop, outcome, disposition",
        "an outcome or horizon is never invented",
        "places it directly into `04_inbox`",
        "never write it anywhere yourself",
        "never into `02_staged` or `03_prepared`",
        "would mint a new memory instead of closing the loop",
        "a staged note that states the resolution of an existing open loop is a closure note",
        "no active intake transaction",
        "`authorship=mixed`",
        "at the target lineage's stored sensitivity",
        "notes for lineages of differing sensitivities ride separate batches",
        "one correction per target lineage, citing every contributing source",
        "set the current target lineage and expected head from complete `memory.get` evidence at review time",
        "remove `loop:open`, clear `valid_to`",
        "append one final `outcome (<date>):` line in the owner's stated words",
        "keep `loop:open`, set the stated `valid_to`, and leave the statement unchanged",
        "carry every other tag and field forward unchanged",
        "seals at restricted sensitivity, which a correction never sits below",
        "ambiguous between closed and a revisit date, stop and ask instead of drafting",
        "the date the owner stated the outcome, not the date of the underlying event",
    ):
        assert required in body
