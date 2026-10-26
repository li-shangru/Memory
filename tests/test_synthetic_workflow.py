from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import anyio
import pytest

from memory.inbox import scan_inbox
from memory.mcp_server import call_tool
from memory.model import RuntimePaths, Sensitivity

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "synthetic_journeys"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.yaml"
REPO_ROOT = Path(__file__).resolve().parents[1]
CLIENT_SETUP_PATH = REPO_ROOT / "docs" / "client-setup.md"
SMOKE_CEREMONY_PATH = REPO_ROOT / "docs" / "smoke-ceremony.md"
ACCEPTANCE_PATH = REPO_ROOT / "docs" / "acceptance" / "client-smoke.md"
SKILL_PATH = REPO_ROOT / "src" / "memory" / "skill" / "SKILL.md"
PRIVACY_QUESTION = (
    "Does the invented LanternFox profile fit Vale's confidentiality requirements?"
)
MISSING_COVERAGE_IDS = (
    "SYN-MISSING-CANDIDATE-COSTS-001",
    "SYN-MISSING-WEEKEND-AVAILABILITY-002",
)
SYNTHETIC_CODEX_STORE_ID = "a1" * 16
SYNTHETIC_CLAUDE_STORE_ID = "b2" * 16
SYNTHETIC_UNRELATED_STORE_ID = "c3" * 16
EXPECTED_CASES = {
    "SYN-JOURNEY-APPOINTMENT-001": {
        "topic": "recurring_appointment_preparation",
        "language": "en",
        "fallback": {
            "empty_memory": True,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": True,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-PRIVACY-002": {
        "topic": "privacy_sensitive_software_choice",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": True,
            "no_literal_match": False,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-ENJOYMENT-ZH-003": {
        "topic": "affordable_discretionary_enjoyment",
        "language": "zh",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": True,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": [
            "SYN-MISSING-CANDIDATE-COSTS-001",
            "SYN-MISSING-WEEKEND-AVAILABILITY-002",
        ],
    },
    "SYN-JOURNEY-ORIENT-011": {
        "topic": "standing_orientation_applies_offscreen_preference",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": True,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-STALE-012": {
        "topic": "expired_validity_is_flagged_not_asserted",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": False,
            "intentionally_insufficient": True,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": ["current rental status after 2026-05-31"],
    },
    "SYN-JOURNEY-GUARD-BAIT-013": {
        "topic": "guard_leads_when_answer_invites_agreement",
        "language": "zh",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": False,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-LOOP-014": {
        "topic": "due_loop_surfaces_closed_loop_vanishes",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": True,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-CAPTURE-015": {
        "topic": "decision_note_offered_once_after_stated_decision",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": False,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-NO-CAPTURE-016": {
        "topic": "no_offer_without_stated_decision",
        "language": "zh",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": False,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-CLOSE-017": {
        "topic": "stated_outcome_closes_one_loop_once",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": True,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-REHORIZON-ZH-018": {
        "topic": "stated_new_horizon_moves_loop_without_invention",
        "language": "zh",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": False,
        },
        "missing_coverage": [],
    },
    "SYN-JOURNEY-PRIORITY-019": {
        "topic": "explicit_priority_and_reversibility_cross_aspect",
        "language": "en",
        "fallback": {
            "empty_memory": False,
            "enumeration_required": True,
            "intentionally_insufficient": False,
            "misleading_nonempty_ranked_result": False,
            "no_literal_match": True,
        },
        "missing_coverage": [],
    },
}
EXPECTED_SOURCES = {
    "SYN-SRC-APPOINTMENT-SCHEDULE-001": (
        "sources/appointment-schedule.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-APPOINTMENT-PREP-002": (
        "sources/appointment-preparation.txt",
        "text/plain",
        True,
    ),
    "SYN-SRC-PRIVACY-DISTRACTOR-003": (
        "sources/privacy-ranked-distractor.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-PRIVACY-NEEDS-004": (
        "sources/privacy-needs.txt",
        "text/plain",
        True,
    ),
    "SYN-SRC-PRIVACY-SHEET-005": (
        "sources/privacy-product-sheet.pdf",
        "application/pdf",
        False,
    ),
    "SYN-SRC-ENJOYMENT-BUDGET-ZH-006": (
        "sources/enjoyment-budget-zh.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-ORIENT-STYLE-011": (
        "sources/orientation-working-style.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-ORIENT-CONTROLLER-012": (
        "sources/orientation-watering-controller.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-STALE-RENTAL-013": (
        "sources/stale-cottage-rental.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-GUARD-RESTRAINT-014": (
        "sources/guard-collection-restraint.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-LOOP-COMMIT-015": (
        "sources/loop-commitments.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-LOOP-CLOSE-016": (
        "sources/loop-rain-barrel-complete.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-CAPTURE-OPTIONS-017": (
        "sources/capture-dehumidifier-options.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-NOCAP-SHELF-ZH-018": (
        "sources/capture-shelf-browsing-zh.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-CLOSE-COMMIT-019": (
        "sources/closure-shutter-commitments.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-CLOSE-OUTCOME-020": (
        "sources/closure-shutter-outcome.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-REHORIZON-COMMIT-ZH-021": (
        "sources/closure-vent-commitment-zh.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-REHORIZON-NOTE-ZH-022": (
        "sources/closure-vent-rehorizon-zh.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-PRIORITY-DIRECTION-023": (
        "sources/priority-ilyra-direction.md",
        "text/markdown",
        True,
    ),
    "SYN-SRC-PRIORITY-CHOICE-024": (
        "sources/priority-ilyra-choice.md",
        "text/markdown",
        True,
    ),
}


class FakeClock:
    def __init__(self) -> None:
        self.timestamp = 1_860_000_000.0

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


def _load_manifest() -> dict[str, Any]:
    assert MANIFEST_PATH.is_file(), "the versioned synthetic manifest is missing"
    parsed = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _cases(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case["case_id"]: case for case in manifest["cases"]}


def _sources(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {source["fixture_id"]: source for source in manifest["sources"]}


def _copy_case_sources(
    paths: RuntimePaths,
    manifest: dict[str, Any],
    case_id: str,
) -> None:
    case = _cases(manifest)[case_id]
    sources = _sources(manifest)
    for fixture_id in case["source_fixture_ids"]:
        relative = Path(sources[fixture_id]["path"])
        shutil.copyfile(FIXTURE_ROOT / relative, paths.inbox / relative.name)


def _invoke(
    paths: RuntimePaths,
    name: str,
    arguments: Mapping[str, object],
) -> dict[str, Any]:
    """Invoke one Store tool and read its result as the wire JSON it is.

    Every envelope below the transport boundary is a JSON payload whose shape
    is fixed by the per-tool contract schema, not by any Python type.
    """
    return cast(dict[str, Any], call_tool(paths, name, arguments))


def _read_all_sources(paths: RuntimePaths) -> dict[str, bytes]:
    summaries: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        arguments: dict[str, object] = {"limit": 1}
        if cursor is not None:
            arguments["cursor"] = cursor
        result = _invoke(paths, "source.list", arguments)
        envelope = result["structuredContent"]
        assert envelope["instruction_trust"] == "inert"
        assert len(envelope["data"]) <= 1
        summaries.extend(envelope["data"])
        if not envelope["page"]["has_more"]:
            break
        cursor = envelope["page"]["next_cursor"]

    reconstructed: dict[str, bytes] = {}
    for summary in summaries:
        assert summary["origin"] == "inbox"
        chunks = bytearray()
        cursor = None
        while True:
            arguments = {"source_id": summary["source_id"], "max_bytes": 37}
            if cursor is not None:
                arguments["cursor"] = cursor
            result = _invoke(paths, "source.read", arguments)
            envelope = result["structuredContent"]
            assert envelope["instruction_trust"] == "inert"
            data = envelope["data"]
            if "text" in data:
                chunks.extend(data["text"].encode("utf-8"))
            else:
                assert data["resource_content_index"] == 0
                resource = result["content"][0]
                assert resource["type"] == "resource"
                chunks.extend(
                    base64.b64decode(resource["resource"]["blob"], validate=True)
                )
            if data["complete"]:
                break
            cursor = data["next_cursor"]
        body = bytes(chunks)
        assert hashlib.sha256(body).hexdigest() == summary["blob_digest"]
        reconstructed[summary["original_name"]] = body
    return reconstructed


def _required_markers(
    manifest: dict[str, Any],
    case_id: str,
) -> dict[str, str]:
    case = _cases(manifest)[case_id]
    evidence = {item["evidence_id"]: item for item in manifest["evidence"]}
    sources = _sources(manifest)
    return {
        Path(
            sources[evidence[evidence_id]["source_fixture_id"]]["path"]
        ).name: evidence[evidence_id]["marker"]
        for evidence_id in case["required_evidence_ids"]
    }


def _client_binding_and_safe_cleanup_scripts() -> tuple[str, str]:
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    identity_section = setup.split(
        "Canonicalize and freeze",
        maxsplit=1,
    )[1].split("Do not place the manifest", maxsplit=1)[0]
    bind_setup = identity_section.split("```sh\n", maxsplit=1)[1].split(
        "\n```", maxsplit=1
    )[0]
    cleanup_section = setup.split("## Record and clean up", maxsplit=1)[1]
    cleanup = cleanup_section.split("```sh\n", maxsplit=1)[1].split(
        "\n```", maxsplit=1
    )[0]
    assert cleanup.count("/usr/bin/security") == 2
    cleanup = cleanup.replace(
        "/usr/bin/security",
        '"$MEMORY_SETUP_TEST_SECURITY"',
    )
    assert "/usr/bin/security" not in cleanup
    return bind_setup, cleanup


def test_client_setup_installs_the_skill_from_the_installed_wheel_alone() -> None:
    """Catch Skill installation depending on the checkout or on cleanup state.

    The copied Skill is now placed by the installed command's own
    `skill install`, so the procedure proves what an owner can actually run
    after `uv tool install`. A repository helper would prove the checkout
    instead, and reintroduce preparation-only state the cleanup block must
    never come to depend on.
    """
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    preparation = setup.split(
        "## Prepare one installed wheel and two isolated runtimes",
        maxsplit=1,
    )[1].split("Canonicalize and freeze", maxsplit=1)[0]
    identity_section = setup.split(
        "Canonicalize and freeze",
        maxsplit=1,
    )[1].split("Do not place the manifest", maxsplit=1)[0]
    cleanup_section = setup.split("## Record and clean up", maxsplit=1)[1]
    install = '"$MEMORY_SETUP_CLI" skill install'

    assert "sync-client-skill" not in setup
    assert preparation.count(install) == 2
    assert preparation.count('"$MEMORY_SETUP_CLI" skill check') == 2
    assert preparation.index("uv pip install") < preparation.index(install)
    assert "skill install" not in identity_section
    assert "skill install" not in cleanup_section


def test_claude_headless_multi_turn_smoke_preserves_resumable_sessions() -> None:
    """Catch prompt-history suppression making a rehearsal ID non-resumable."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    ceremony = SMOKE_CEREMONY_PATH.read_text(encoding="utf-8")
    folded = " ".join((setup + "\n" + ceremony).split())

    assert "resumable headless" in folded
    assert "omit `CLAUDE_CODE_SKIP_PROMPT_HISTORY=1`" in folded
    assert "explicit synthetic session id" in folded
    assert "exact client-project directory" in folded


def test_codex_headless_resume_keeps_candidate_skill_provenance() -> None:
    """Catch resume changing cwd and silently loading a different Skill."""
    folded = " ".join(CLIENT_SETUP_PATH.read_text(encoding="utf-8").split())

    assert "resume from the same disposable project" in folded
    assert "exact candidate Skill" in folded
    assert "caller’s current directory" in folded


def _write_synthetic_store_identity(path: Path, store_id: str) -> None:
    path.write_text(
        json.dumps(
            {
                "product": "memory",
                "schema_lineage": "memory-store-v1",
                "schema_version": 1,
                "store_id": store_id,
                "runtime_mode": "personal",
                "inbox_path": str(path.parent / "inbox"),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _run_documented_client_cleanup(
    tmp_path: Path,
    *,
    mutation: str = "",
    delete_failure: str | None = None,
    find_failure: str | None = None,
    shell: str = "/bin/sh",
) -> tuple[
    subprocess.CompletedProcess[str],
    Path,
    tuple[Path, Path],
    list[list[str]],
    list[str],
]:
    bind_setup, cleanup = _client_binding_and_safe_cleanup_scripts()
    root = tmp_path / "memory-smoke-clients.synthetic"
    venv = root / "venv"
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(venv)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    memory = venv / "bin" / "memory"
    memory.write_text(f"#!{venv / 'bin' / 'python'}\n", encoding="utf-8")
    memory.chmod(0o700)

    codex_store = root / "codex-store"
    claude_store = root / "claude-store"
    evidence = (
        codex_store / "inbox" / "synthetic-evidence.txt",
        claude_store / "inbox" / "synthetic-evidence.txt",
    )
    for store, store_id, evidence_path in (
        (codex_store, SYNTHETIC_CODEX_STORE_ID, evidence[0]),
        (claude_store, SYNTHETIC_CLAUDE_STORE_ID, evidence[1]),
    ):
        evidence_path.parent.mkdir(parents=True)
        evidence_path.write_text("synthetic cleanup evidence\n", encoding="utf-8")
        _write_synthetic_store_identity(store / "runtime.json", store_id)

    replacement_identity = tmp_path / "replacement-runtime.json"
    invalid_identity = tmp_path / "invalid-runtime.json"
    _write_synthetic_store_identity(
        replacement_identity,
        SYNTHETIC_UNRELATED_STORE_ID,
    )
    invalid_identity.write_text("{}\n", encoding="utf-8")

    calls_path = tmp_path / "security-calls.jsonl"
    state_path = tmp_path / "security-state.json"
    state_path.write_text(
        json.dumps(
            [
                SYNTHETIC_CODEX_STORE_ID,
                SYNTHETIC_CLAUDE_STORE_ID,
                SYNTHETIC_UNRELATED_STORE_ID,
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_security = tmp_path / "fake-security"
    fake_security.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import pathlib\n"
        "import sys\n"
        f"calls_path = pathlib.Path({str(calls_path)!r})\n"
        f"state_path = pathlib.Path({str(state_path)!r})\n"
        f"delete_failure = {delete_failure!r}\n"
        f"find_failure = {find_failure!r}\n"
        "arguments = sys.argv[1:]\n"
        "with calls_path.open('a', encoding='utf-8') as output:\n"
        "    output.write(json.dumps(arguments) + '\\n')\n"
        "if arguments[2:4] != ['memory', '-a']:\n"
        "    raise SystemExit(2)\n"
        "command = arguments[0]\n"
        "account = arguments[4]\n"
        "state = json.loads(state_path.read_text(encoding='utf-8'))\n"
        "if command == 'delete-generic-password':\n"
        "    if account == delete_failure:\n"
        "        raise SystemExit(7)\n"
        "    if account in state:\n"
        "        state.remove(account)\n"
        "    state_path.write_text(json.dumps(state) + '\\n', encoding='utf-8')\n"
        "    raise SystemExit(0)\n"
        "if command == 'find-generic-password':\n"
        "    if account == find_failure:\n"
        "        raise SystemExit(3)\n"
        "    raise SystemExit(0 if account in state else 44)\n"
        "raise SystemExit(2)\n",
        encoding="utf-8",
    )
    fake_security.chmod(0o700)

    script = "\n".join(
        (
            f"MEMORY_SETUP_TEMP_BASE={shlex.quote(str(tmp_path))}",
            f"MEMORY_SETUP_ROOT={shlex.quote(str(root))}",
            f"MEMORY_SETUP_VENV={shlex.quote(str(tmp_path / 'wrong-venv'))}",
            f"MEMORY_SETUP_PYTHON={shlex.quote(sys.executable)}",
            f"MEMORY_SETUP_CLI={shlex.quote(str(tmp_path / 'wrong-memory'))}",
            f"MEMORY_SETUP_CODEX_STORE={shlex.quote(str(tmp_path / 'wrong-codex'))}",
            f"MEMORY_SETUP_CLAUDE_STORE={shlex.quote(str(tmp_path / 'wrong-claude'))}",
            f"MEMORY_SETUP_TEST_SECURITY={shlex.quote(str(fake_security))}",
            f"MEMORY_SETUP_TEST_REPLACEMENT={shlex.quote(str(replacement_identity))}",
            f"MEMORY_SETUP_TEST_INVALID={shlex.quote(str(invalid_identity))}",
            f"MEMORY_SETUP_TEST_SWAP={shlex.quote(str(tmp_path / 'swap-runtime.json'))}",
            bind_setup,
            mutation,
            "pms_m4_cleanup() {",
            cleanup,
            "}",
            "pms_m4_cleanup",
        )
    )
    result = subprocess.run(
        [shell],
        input=script,
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    calls = (
        [
            json.loads(line)
            for line in calls_path.read_text(encoding="utf-8").splitlines()
        ]
        if calls_path.exists()
        else []
    )
    remaining_ids = json.loads(state_path.read_text(encoding="utf-8"))
    return result, root, evidence, calls, remaining_ids


def test_manifest_fixes_every_required_case_source_and_fallback() -> None:
    """Catch cherry-picking, case replacement, or answer-gold leakage."""
    manifest = _load_manifest()
    assert manifest["schema"] == "memory.synthetic-journeys.v1"
    assert manifest["manifest_version"] == 1
    assert _cases(manifest).keys() == EXPECTED_CASES.keys()
    assert _sources(manifest).keys() == EXPECTED_SOURCES.keys()

    for case_id, expected in EXPECTED_CASES.items():
        case = _cases(manifest)[case_id]
        assert case["topic"] == expected["topic"]
        assert case["language"] == expected["language"]
        assert case["fallback"] == expected["fallback"]
        assert case["missing_coverage"] == expected["missing_coverage"]
        assert isinstance(case["question"], str) and case["question"].strip()
        assert case["source_fixture_ids"]
        assert case["required_evidence_ids"]

    serialized = json.dumps(manifest, ensure_ascii=False, sort_keys=True).casefold()
    for forbidden_key in (
        "expected_answer",
        "gold_answer",
        "recommendation",
        "transcript",
    ):
        assert forbidden_key not in serialized
    assert "/users/" not in serialized
    assert "personal vault" not in serialized
    assert any(case["language"] == "zh" for case in manifest["cases"])
    assert any(
        re.search(r"[\u4e00-\u9fff]", case["question"]) for case in manifest["cases"]
    )
    assert _cases(manifest)["SYN-JOURNEY-PRIVACY-002"]["question"] == (PRIVACY_QUESTION)


def test_client_prompts_hide_missing_ids_and_operator_records_natural_gaps() -> None:
    """Catch hidden manifest IDs becoming client hints or client rubric output."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    skill = SKILL_PATH.read_text(encoding="utf-8")
    acceptance = ACCEPTANCE_PATH.read_text(encoding="utf-8")

    for hidden_id in MISSING_COVERAGE_IDS:
        assert hidden_id not in setup
        assert hidden_id not in skill
        assert hidden_id in acceptance
    assert "| Operator missing-coverage mapping |" in acceptance
    enjoyment_rows = [
        row.split("|")[1:-1]
        for row in acceptance.splitlines()
        if row.startswith("| `SYN-JOURNEY-ENJOYMENT-ZH-003`")
    ]
    assert len(enjoyment_rows) == 2
    for row in enjoyment_rows:
        assert len(row) == 5
        operator_mapping = row[3]
        assert "candidate activity costs" in operator_mapping
        assert "weekend availability" in operator_mapping
        for hidden_id in MISSING_COVERAGE_IDS:
            assert hidden_id in operator_mapping
            assert hidden_id not in "|".join((*row[:3], row[4]))
    assert "The operator maps those observed facts" in re.sub(r"\s+", " ", acceptance)
    assert PRIVACY_QUESTION in re.sub(r"\s+", " ", setup)


CLIENT_SMOKE_DOCUMENTS = (
    "AGENTS.md",
    "README.md",
    "docs/README.md",
    "docs/client-setup.md",
    "docs/owner-guide.md",
    "docs/technical-design.md",
)
RECORDED_RESULTS_HEADING = "## Recorded results"
RECORDED_STATUS_ROW = "Status"
RECORDED_CLIENT_COLUMNS = 2
RECORDED_DIGEST_ROWS = ("MCP contract digest", "Skill contract digest")
CURRENT_CONTRACT_SMOKE_CLAIM = re.compile(
    r"current[- ]contract (?:codex|claude(?: code)?) (?:smoke|run)"
    r"|(?:codex|claude(?: code)?) (?:smoke|run)[^.]{0,80}current contract",
)
ATTESTS_TO_THE_CONTRACT = re.compile(r"attests? to the (?:shipped|current) contract")
CLIENT_SMOKE_PASSED_CLAIM = re.compile(
    r"(?:codex|claude(?: code)?)[^.;]{0,90}\b(?:smoke|run)\b[^.;]{0,90}"
    r"\b(?:passed|passes)\b"
    r"|\b(?:passed|passes)\b[^.;]{0,90}(?:codex|claude(?: code)?)[^.;]{0,90}"
    r"\b(?:smoke|run)\b"
    r"|\bpassed against the final digests\b",
)


def _document_sentences(text: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", text)
    return re.split(r"(?<=[.;]) ", normalized)


def _recorded_result_rows() -> dict[str, tuple[str, ...]]:
    """Map each recorded-results row label to its per-client cells.

    Exactly one such section may exist: a second appended section would
    otherwise be invisible while silently disarming every check below.
    """
    text = ACCEPTANCE_PATH.read_text(encoding="utf-8")
    parts = text.split(RECORDED_RESULTS_HEADING)
    assert len(parts) == 2, (
        "the blank acceptance template must contain exactly one results "
        f"section; found {len(parts) - 1}"
    )
    rows: dict[str, tuple[str, ...]] = {}
    for line in parts[1].split("\n## ", maxsplit=1)[0].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or set("".join(cells)) <= set("-: "):
            continue
        rows[cells[0]] = tuple(cells[1:])
    return rows


def test_public_client_smoke_template_stays_unexecuted() -> None:
    """Observed client trials belong in private external copies of this rubric."""
    rows = _recorded_result_rows()
    assert rows[RECORDED_STATUS_ROW] == ("`not run`",) * RECORDED_CLIENT_COLUMNS
    for label in RECORDED_DIGEST_ROWS:
        assert rows[label] == ("—",) * RECORDED_CLIENT_COLUMNS


def test_no_governing_document_claims_a_current_contract_client_smoke() -> None:
    """Public source checks cannot attest a private installed-client trial."""
    for name in CLIENT_SMOKE_DOCUMENTS:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        for sentence in _document_sentences(text):
            folded = sentence.casefold()
            assert CURRENT_CONTRACT_SMOKE_CLAIM.search(folded) is None, (name, sentence)
            assert CLIENT_SMOKE_PASSED_CLAIM.search(folded) is None, (name, sentence)
            if ATTESTS_TO_THE_CONTRACT.search(folded) is not None:
                assert "neither" in folded or "does not attest" in folded, (
                    name,
                    sentence,
                )


def test_client_setup_has_no_textual_or_pty_approval_fallback() -> None:
    """Catch installed-client guidance reviving the superseded CLI capability."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", setup.replace("\\\n", " "))

    assert '"$MEMORY_SETUP_CLI" approve ' not in normalized
    assert re.search(r"(?m)^\s*memory approve\b", setup) is None
    assert "there is no terminal fallback" in normalized.casefold()


def test_client_smokes_stop_and_skill_handoff_requires_os_owner_approval() -> None:
    """Keep smoke attestation distinct from a real OS-backed approval handoff."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    codex = setup.split("## Codex", maxsplit=1)[1].split("## Claude Code", maxsplit=1)[
        0
    ]
    claude = setup.split("## Claude Code", maxsplit=1)[1].split(
        "## Record and clean up", maxsplit=1
    )[0]
    skill = SKILL_PATH.read_text(encoding="utf-8")
    normalized_codex = re.sub(r"\s+", " ", codex.replace("\\\n", " "))
    normalized_claude = re.sub(r"\s+", " ", claude)

    normalized_skill = re.sub(r"\s+", " ", skill)

    assert (
        "If the result is owner_approval_required, report that nothing was "
        "applied and stop. There is no terminal fallback."
    ) in normalized_codex
    assert (
        "If an owner prompt was surfaced and the owner directly declined, "
        "respect that decision and stop."
    ) in normalized_codex
    assert (
        "If Codex returns `owner_approval_required`, record the run as blocked "
        "by missing trusted elicitation; nothing was applied, so stop."
    ) in normalized_codex
    assert (
        "report that nothing was applied and stop; there is no terminal fallback."
    ) in normalized_claude
    assert (
        "If it returns `owner_declined`, leave the draft unchanged and stop."
    ) in normalized_claude
    assert "memory approve" not in normalized_codex
    assert "memory approve" not in normalized_claude
    assert (
        "On `owner_approval_required` or confirmed unsurfaced `owner_declined`, "
        "nothing was applied."
    ) in normalized_skill
    assert (
        "If no elicitation prompt was displayed, run that invocation exactly as "
        "returned without another chat checkpoint; its macOS owner presence "
        "check supplies approval."
    ) in normalized_skill
    assert (
        "If prompt visibility is unknown, report the handoff and stop"
        in normalized_skill
    )
    assert (
        "After a visible decline or cancellation, or a failed/timed-out "
        "owner-presence check, stop; do not retry the handoff or the unapplied MCP call"
    ) in normalized_skill
    assert "applied replay cannot prompt or apply again" in normalized_skill
    assert "memory approve" not in skill
    # A bare ban on "retry" rejected the explicit prohibition "do not retry".
    # Pin the refusal boundary above while retaining exact applied replay.
    assert "tool_call_mcp_elicitation" not in setup
    assert "auth_elicitation" not in setup


def test_client_cleanup_rederives_and_validates_exact_store_children_first() -> None:
    """Catch mutable or symlinked Store paths selecting unrelated Keychain items."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    cleanup_section = setup.split("## Record and clean up", maxsplit=1)[1]
    cleanup = cleanup_section.split("```sh\n", maxsplit=1)[1].split(
        "\n```", maxsplit=1
    )[0]

    required_before_security = (
        '[ -d "$MEMORY_SETUP_ROOT" ] && [ ! -L "$MEMORY_SETUP_ROOT" ]',
        'case "$MEMORY_SETUP_CODEX_STORE:$MEMORY_SETUP_CLAUDE_STORE" in',
        'for MEMORY_SETUP_STORE in "$MEMORY_SETUP_CODEX_STORE" "$MEMORY_SETUP_CLAUDE_STORE"; do',
        '[ -d "$MEMORY_SETUP_STORE" ] && [ ! -L "$MEMORY_SETUP_STORE" ]',
        'MEMORY_SETUP_RUNTIME="$MEMORY_SETUP_STORE/runtime.json"',
        '[ -f "$MEMORY_SETUP_RUNTIME" ] && [ ! -L "$MEMORY_SETUP_RUNTIME" ]',
        '"$MEMORY_SETUP_CODEX_STORE/runtime.json" "$MEMORY_SETUP_CODEX_STORE_ID"',
        '"$MEMORY_SETUP_CLAUDE_STORE/runtime.json" "$MEMORY_SETUP_CLAUDE_STORE_ID"',
    )
    first_security = cleanup.index("/usr/bin/security")
    for fragment in required_before_security:
        assert fragment in cleanup
        assert cleanup.index(fragment) < first_security

    assert (
        "/usr/bin/security delete-generic-password \\\n"
        '    -s memory -a "$MEMORY_SETUP_STORE_ID" >/dev/null || {'
    ) in cleanup


def test_client_cleanup_refuses_a_replaced_valid_runtime_identity(
    tmp_path: Path,
) -> None:
    """Catch a valid replacement identity selecting an unrelated Keychain item."""
    result, root, evidence, calls, remaining_ids = _run_documented_client_cleanup(
        tmp_path,
        mutation=(
            '/bin/cp "$MEMORY_SETUP_TEST_REPLACEMENT" "$MEMORY_SETUP_CODEX_STORE/runtime.json"'
        ),
    )

    assert result.returncode != 0, calls
    assert root.is_dir()
    assert all(path.is_file() for path in evidence)
    assert calls == []
    assert remaining_ids == [
        SYNTHETIC_CODEX_STORE_ID,
        SYNTHETIC_CLAUDE_STORE_ID,
        SYNTHETIC_UNRELATED_STORE_ID,
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        (
            '/bin/cp "$MEMORY_SETUP_CODEX_STORE/runtime.json" "$MEMORY_SETUP_TEST_SWAP"\n'
            '/bin/cp "$MEMORY_SETUP_CLAUDE_STORE/runtime.json" '
            '"$MEMORY_SETUP_CODEX_STORE/runtime.json"\n'
            '/bin/cp "$MEMORY_SETUP_TEST_SWAP" '
            '"$MEMORY_SETUP_CLAUDE_STORE/runtime.json"'
        ),
        (
            '/bin/cp "$MEMORY_SETUP_TEST_INVALID" "$MEMORY_SETUP_CLAUDE_STORE/runtime.json"'
        ),
        (
            '/bin/mv "$MEMORY_SETUP_ROOT" "${MEMORY_SETUP_ROOT}.saved"\n'
            '/bin/ln -s "${MEMORY_SETUP_ROOT}.saved" "$MEMORY_SETUP_ROOT"'
        ),
        (
            '/bin/mv "$MEMORY_SETUP_CODEX_STORE" '
            '"${MEMORY_SETUP_CODEX_STORE}.saved"\n'
            '/bin/ln -s "${MEMORY_SETUP_CODEX_STORE}.saved" '
            '"$MEMORY_SETUP_CODEX_STORE"'
        ),
        (
            '/bin/mv "$MEMORY_SETUP_CODEX_STORE/runtime.json" '
            '"$MEMORY_SETUP_CODEX_STORE/runtime.saved.json"\n'
            "/bin/ln -s runtime.saved.json "
            '"$MEMORY_SETUP_CODEX_STORE/runtime.json"'
        ),
    ],
    ids=(
        "swapped-identities",
        "invalid-second-identity",
        "symlinked-root",
        "symlinked-store",
        "symlinked-runtime",
    ),
)
def test_client_cleanup_rejects_all_identity_and_path_substitution_before_calls(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Catch either Store being substituted before both identities revalidate."""
    result, root, evidence, calls, remaining_ids = _run_documented_client_cleanup(
        tmp_path,
        mutation=mutation,
    )

    assert result.returncode != 0
    assert root.exists()
    assert all(path.is_file() for path in evidence)
    assert calls == []
    assert remaining_ids == [
        SYNTHETIC_CODEX_STORE_ID,
        SYNTHETIC_CLAUDE_STORE_ID,
        SYNTHETIC_UNRELATED_STORE_ID,
    ]


@pytest.mark.parametrize(
    "variable",
    [
        "MEMORY_SETUP_TEMP_BASE",
        "MEMORY_SETUP_ROOT",
        "MEMORY_SETUP_VENV",
        "MEMORY_SETUP_PYTHON",
        "MEMORY_SETUP_CLI",
        "MEMORY_SETUP_CODEX_STORE",
        "MEMORY_SETUP_CLAUDE_STORE",
        "MEMORY_SETUP_CODEX_STORE_ID",
        "MEMORY_SETUP_CLAUDE_STORE_ID",
    ],
)
def test_client_cleanup_bindings_cannot_be_reassigned(
    tmp_path: Path,
    variable: str,
) -> None:
    """Catch cleanup-sensitive setup state remaining mutable in the open shell."""
    result, root, evidence, calls, remaining_ids = _run_documented_client_cleanup(
        tmp_path,
        mutation=f'{variable}="${{{variable}}}"',
    )

    assert result.returncode != 0
    assert root.is_dir()
    assert all(path.is_file() for path in evidence)
    assert calls == []
    assert remaining_ids == [
        SYNTHETIC_CODEX_STORE_ID,
        SYNTHETIC_CLAUDE_STORE_ID,
        SYNTHETIC_UNRELATED_STORE_ID,
    ]


@pytest.mark.parametrize(
    ("delete_failure", "find_failure", "expected_commands", "remaining_ids"),
    [
        (
            SYNTHETIC_CODEX_STORE_ID,
            None,
            ["delete-generic-password"],
            [
                SYNTHETIC_CODEX_STORE_ID,
                SYNTHETIC_CLAUDE_STORE_ID,
                SYNTHETIC_UNRELATED_STORE_ID,
            ],
        ),
        (
            None,
            SYNTHETIC_CODEX_STORE_ID,
            ["delete-generic-password", "find-generic-password"],
            [SYNTHETIC_CLAUDE_STORE_ID, SYNTHETIC_UNRELATED_STORE_ID],
        ),
    ],
    ids=("delete-failure", "absence-check-failure"),
)
def test_client_cleanup_key_failures_retain_both_evidence_trees(
    tmp_path: Path,
    delete_failure: str | None,
    find_failure: str | None,
    expected_commands: list[str],
    remaining_ids: list[str],
) -> None:
    """Catch a failed key operation discarding either recoverable Store tree."""
    result, root, evidence, calls, actual_remaining = _run_documented_client_cleanup(
        tmp_path,
        delete_failure=delete_failure,
        find_failure=find_failure,
    )

    assert result.returncode != 0
    assert root.is_dir()
    assert all(path.is_file() for path in evidence)
    assert [call[0] for call in calls] == expected_commands
    assert actual_remaining == remaining_ids


@pytest.mark.parametrize("shell", ["/bin/sh", "/bin/zsh"])
def test_client_cleanup_deletes_only_frozen_ids_before_removing_root(
    tmp_path: Path,
    shell: str,
) -> None:
    """Catch successful cleanup deleting another key or retaining temporary data."""
    result, root, evidence, calls, remaining_ids = _run_documented_client_cleanup(
        tmp_path,
        shell=shell,
    )

    assert result.returncode == 0, result.stderr
    assert not root.exists()
    assert not any(path.exists() for path in evidence)
    assert calls == [
        [
            "delete-generic-password",
            "-s",
            "memory",
            "-a",
            SYNTHETIC_CODEX_STORE_ID,
        ],
        [
            "find-generic-password",
            "-s",
            "memory",
            "-a",
            SYNTHETIC_CODEX_STORE_ID,
        ],
        [
            "delete-generic-password",
            "-s",
            "memory",
            "-a",
            SYNTHETIC_CLAUDE_STORE_ID,
        ],
        [
            "find-generic-password",
            "-s",
            "memory",
            "-a",
            SYNTHETIC_CLAUDE_STORE_ID,
        ],
    ]
    assert remaining_ids == [SYNTHETIC_UNRELATED_STORE_ID]


def test_client_setup_keeps_the_exact_venv_python_binding(tmp_path: Path) -> None:
    """Catch canonicalization bypassing the venv entry point and its prefix."""
    setup = CLIENT_SETUP_PATH.read_text(encoding="utf-8")
    identity_section = setup.split(
        "Canonicalize and freeze",
        maxsplit=1,
    )[1].split("Do not place the manifest", maxsplit=1)[0]
    bind_setup = identity_section.split("```sh\n", maxsplit=1)[1].split(
        "\n```", maxsplit=1
    )[0]

    root = tmp_path / "memory-smoke-clients.synthetic"
    venv = root / "venv"
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(venv)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    memory = venv / "bin" / "memory"
    memory.write_text(f"#!{venv / 'bin' / 'python'}\n", encoding="utf-8")
    memory.chmod(0o700)
    for name, store_id in (("codex-store", "a1" * 16), ("claude-store", "b2" * 16)):
        store = root / name
        store.mkdir()
        (store / "runtime.json").write_text(
            json.dumps(
                {
                    "product": "memory",
                    "schema_lineage": "memory-store-v1",
                    "schema_version": 1,
                    "store_id": store_id,
                    "runtime_mode": "personal",
                    "inbox_path": str(store / "inbox"),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    script = "\n".join(
        (
            f"MEMORY_SETUP_TEMP_BASE={shlex.quote(str(tmp_path))}",
            f"MEMORY_SETUP_ROOT={shlex.quote(str(root))}",
            f"MEMORY_SETUP_PYTHON={shlex.quote(str(venv / 'bin' / 'python'))}",
            f"MEMORY_SETUP_CLI={shlex.quote(str(memory))}",
            f"MEMORY_SETUP_CODEX_STORE={shlex.quote(str(root / 'codex-store'))}",
            f"MEMORY_SETUP_CLAUDE_STORE={shlex.quote(str(root / 'claude-store'))}",
            bind_setup,
            'printf "%s\\n" "$MEMORY_SETUP_PYTHON"',
            'printf "%s\\n" "$MEMORY_SETUP_CLI"',
            '"$MEMORY_SETUP_PYTHON" -I -c '
            "'import os, sys; print(os.path.realpath(sys.prefix))'",
        )
    )
    result = subprocess.run(
        ["/bin/sh"],
        input=script,
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        str(venv / "bin" / "python"),
        str(venv / "bin" / "memory"),
        str(venv),
    ]


def test_manifest_fixture_digests_and_required_evidence_are_exact() -> None:
    """Catch fixture drift or required evidence that no retained source contains."""
    manifest = _load_manifest()
    sources = _sources(manifest)
    assert [source["media_type"] for source in manifest["sources"]].count(
        "application/pdf"
    ) == 1
    for fixture_id, (expected_path, media_type, searchable) in EXPECTED_SOURCES.items():
        source = sources[fixture_id]
        assert source["path"] == expected_path
        assert source["media_type"] == media_type
        assert source["searchable"] is searchable
        relative = Path(source["path"])
        assert not relative.is_absolute() and ".." not in relative.parts
        body = (FIXTURE_ROOT / relative).read_bytes()
        assert hashlib.sha256(body).hexdigest() == source["sha256"]
        if media_type.startswith("text/"):
            body.decode("utf-8", errors="strict")
        else:
            from pypdf import PdfReader

            assert body.startswith(b"%PDF-")
            extracted = "\n".join(
                page.extract_text() or ""
                for page in PdfReader(FIXTURE_ROOT / relative).pages
            )
            assert "SYN-EVIDENCE-PRIVACY-OFFLINE-005" in extracted
            assert "SYN-EVIDENCE-PRIVACY-DIAGNOSTICS-006" in extracted

    evidence_ids = set()
    for item in manifest["evidence"]:
        evidence_ids.add(item["evidence_id"])
        source = sources[item["source_fixture_id"]]
        body = (FIXTURE_ROOT / source["path"]).read_bytes()
        assert item["marker"].encode("utf-8") in body
    assert len(evidence_ids) == len(manifest["evidence"])
    assert {
        evidence_id
        for case in manifest["cases"]
        for evidence_id in case["required_evidence_ids"]
    } <= evidence_ids


def test_empty_memory_no_literal_match_requires_complete_source_fallback(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an empty ranked result being mistaken for absent retained evidence."""
    manifest = _load_manifest()
    case_id = "SYN-JOURNEY-APPOINTMENT-001"
    case = _cases(manifest)[case_id]
    _copy_case_sources(synthetic_store, manifest, case_id)
    scan_inbox(synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock())

    memory = _invoke(
        synthetic_store,
        "memory.search",
        {"query": "routine readiness"},
    )["structuredContent"]
    assert memory["data"] == []
    for query in case["search_queries"]:
        search = _invoke(
            synthetic_store,
            "source.search",
            {"query": query},
        )["structuredContent"]
        assert search["data"] == []
        assert search["coverage"] == {
            "enumerated": 2,
            "searchable": 2,
            "total": 2,
            "unsearchable": 0,
        }

    reconstructed = _read_all_sources(synthetic_store)
    for name, marker in _required_markers(manifest, case_id).items():
        assert marker.encode("utf-8") in reconstructed[name]


def test_nonempty_ranked_distractor_omits_decisive_evidence_until_fallback(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a plausible ranked hit stopping retrieval before text and PDF evidence."""
    manifest = _load_manifest()
    case_id = "SYN-JOURNEY-PRIVACY-002"
    case = _cases(manifest)[case_id]
    _copy_case_sources(synthetic_store, manifest, case_id)
    scan_inbox(synthetic_store, sensitivity=Sensitivity.SENSITIVE, clock=FakeClock())

    search = _invoke(
        synthetic_store,
        "source.search",
        {"query": case["search_queries"][0]},
    )["structuredContent"]
    assert search["data"]
    ranked_names = {item["source"]["original_name"] for item in search["data"]}
    # The distractor answers the query on the phrase rung and still leads the
    # page; the weaker any-term rung admits one requirement note behind it.
    assert search["data"][0]["source"]["original_name"] == (
        "privacy-ranked-distractor.md"
    )
    assert ranked_names == {"privacy-ranked-distractor.md", "privacy-needs.txt"}
    assert search["coverage"] == {
        "enumerated": 2,
        "searchable": 2,
        "total": 3,
        "unsearchable": 1,
    }

    decisive_names = set(_required_markers(manifest, case_id))
    # Ranked retrieval still cannot deliver the decisive set, so stopping at the
    # ranked page loses the unsearchable product sheet.
    assert not decisive_names <= ranked_names
    assert decisive_names - ranked_names == {"privacy-product-sheet.pdf"}
    reconstructed = _read_all_sources(synthetic_store)
    for name, marker in _required_markers(manifest, case_id).items():
        assert marker.encode("utf-8") in reconstructed[name]


def test_insufficient_case_exposes_evidence_and_names_missing_coverage(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch an intentionally unanswerable case losing its explicit coverage gap."""
    manifest = _load_manifest()
    case_id = "SYN-JOURNEY-ENJOYMENT-ZH-003"
    case = _cases(manifest)[case_id]
    _copy_case_sources(synthetic_store, manifest, case_id)
    scan_inbox(synthetic_store, sensitivity=Sensitivity.NORMAL, clock=FakeClock())

    reconstructed = _read_all_sources(synthetic_store)
    for name, marker in _required_markers(manifest, case_id).items():
        assert marker.encode("utf-8") in reconstructed[name]
    assert case["fallback"]["intentionally_insufficient"] is True
    assert case["missing_coverage"] == [
        "SYN-MISSING-CANDIDATE-COSTS-001",
        "SYN-MISSING-WEEKEND-AVAILABILITY-002",
    ]


def test_trusted_owner_search_includes_every_sensitivity(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch sensitivity metadata becoming an implicit trusted-owner filter."""
    for index, sensitivity in enumerate(Sensitivity):
        (synthetic_store.inbox / f"synthetic-sensitivity-{index}.txt").write_text(
            f"Synthetic sensitivity marker {index}.\n",
            encoding="utf-8",
        )
        scan_inbox(synthetic_store, sensitivity=sensitivity, clock=FakeClock())

    searched = _invoke(
        synthetic_store,
        "source.search",
        {"query": "synthetic sensitivity marker", "limit": 100},
    )["structuredContent"]
    assert len(searched["data"]) == 3
    assert {item["source"]["declared_sensitivity"] for item in searched["data"]} == {
        "normal",
        "sensitive",
        "restricted",
    }
    assert searched["coverage"] == {
        "enumerated": 3,
        "searchable": 3,
        "total": 3,
        "unsearchable": 0,
    }


def test_complete_synthetic_inbox_review_apply_retrieval_workflow(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch any break across complete source review, one approval, and retrieval."""
    manifest = _load_manifest()
    case_id = "SYN-JOURNEY-APPOINTMENT-001"
    _copy_case_sources(synthetic_store, manifest, case_id)
    batch = scan_inbox(
        synthetic_store,
        sensitivity=Sensitivity.RESTRICTED,
        clock=FakeClock(),
    )
    reconstructed = _read_all_sources(synthetic_store)
    assert len(reconstructed) == 2
    assert (
        _invoke(synthetic_store, "store.status", {})["structuredContent"]["data"][
            "memory_count"
        ]
        == 0
    )

    detail = _invoke(
        synthetic_store,
        "inbox.read",
        {"batch_id": batch.batch_id},
    )["structuredContent"]["data"]
    sources = {source["original_name"]: source for source in detail["sources"]}
    assert {source["origin"] for source in sources.values()} == {"inbox"}
    created = _invoke(
        synthetic_store,
        "change_set.create",
        {"batch_id": batch.batch_id},
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-APPOINTMENT-TIMING-001",
                    "memory": {
                        "kind": "event",
                        "statement": (
                            "The synthetic quarterly consultation is scheduled "
                            "for the second Tuesday at 09:20."
                        ),
                        "tags": ["synthetic", "appointment"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": sources["appointment-schedule.md"][
                                "source_id"
                            ],
                            "blob_digest": sources["appointment-schedule.md"][
                                "blob_digest"
                            ],
                            "excerpt": (
                                "Nila's quarterly consultation is scheduled for "
                                "the second Tuesday at 09:20."
                            ),
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-APPOINTMENT-MATERIALS-002",
                    "memory": {
                        "kind": "fact",
                        "statement": (
                            "The synthetic appointment materials are a blue "
                            "symptoms log and a paper medication list."
                        ),
                        "tags": ["synthetic", "appointment"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": sources["appointment-preparation.txt"][
                                "source_id"
                            ],
                            "blob_digest": sources["appointment-preparation.txt"][
                                "blob_digest"
                            ],
                            "excerpt": (
                                "Nila keeps the blue symptoms log and a paper "
                                "medication list in the side pocket."
                            ),
                        }
                    ],
                },
            ],
        },
    )["structuredContent"]["data"]
    assert len(edited["items"]) == 2
    assert {decision["state"] for decision in edited["source_decisions"]} == {"used"}

    messages: list[str] = []

    from mcp import Client, types
    from mcp.client import ClientRequestContext

    from memory.mcp_server import create_server

    async def accept(
        context: ClientRequestContext,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        messages.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": True})

    async def apply_review() -> dict[str, Any]:
        async with Client(
            create_server(synthetic_store, trust_elicitation=True),
            elicitation_callback=accept,
        ) as client:
            result = await client.call_tool(
                "change_set.approve_and_apply",
                {
                    "change_set_id": edited["change_set_id"],
                    "revision_id": edited["revision_id"],
                    "digest": edited["digest"],
                },
            )
            return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    applied = anyio.run(apply_review)
    assert applied["structuredContent"]["data"]["memory_ids"]
    assert len(messages) == 1 and edited["digest"] in messages[0]

    timing = _invoke(
        synthetic_store,
        "memory.search",
        {"query": "quarterly consultation"},
    )["structuredContent"]["data"]
    materials = _invoke(
        synthetic_store,
        "memory.search",
        {"query": "symptoms medication"},
    )["structuredContent"]["data"]
    assert len(timing) == 1
    assert len(materials) == 1
    for hit in (*timing, *materials):
        assert hit["match_strength"] in {"phrase", "all_terms", "any_term"}
        assert hit["guards"] == []
        detail = _invoke(
            synthetic_store,
            "memory.get",
            {"memory_id": hit["memory"]["memory_id"]},
        )["structuredContent"]["data"]
        assert detail["is_current"] is True
        assert detail["evidence"]
        assert detail["guards"] == []
        assert detail["governs"] == []
        assert detail["revision"]["effective_sensitivity"] == "restricted"

    assert (
        _invoke(synthetic_store, "memory.search", {"query": "skip review"})[
            "structuredContent"
        ]["data"]
        == []
    )
    assert (
        _invoke(synthetic_store, "store.status", {})["structuredContent"]["data"][
            "memory_count"
        ]
        == 2
    )


def _approve_and_apply(paths: RuntimePaths, edited: dict[str, Any]) -> dict[str, Any]:
    """Apply one reviewed revision through trusted MCP elicitation."""
    from mcp import Client, types
    from mcp.client import ClientRequestContext

    from memory.mcp_server import create_server

    async def accept(
        context: ClientRequestContext,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        return types.ElicitResult(action="accept", content={"approve": True})

    async def apply_review() -> dict[str, Any]:
        async with Client(
            create_server(paths, trust_elicitation=True),
            elicitation_callback=accept,
        ) as client:
            result = await client.call_tool(
                "change_set.approve_and_apply",
                {
                    "change_set_id": edited["change_set_id"],
                    "revision_id": edited["revision_id"],
                    "digest": edited["digest"],
                },
            )
            return result.model_dump(mode="json", by_alias=True, exclude_none=True)

    applied = anyio.run(apply_review)
    assert applied["structuredContent"]["data"]["memory_ids"]
    # The envelope below the transport boundary is wire JSON whose shape the
    # per-tool contract schema fixes, not a Python type; the cast states that
    # boundary exactly as `_invoke` documents for the same reason.
    return cast(dict[str, Any], applied["structuredContent"]["data"])


def test_standing_tag_walk_reaches_what_question_terms_miss(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the orientation walk failing to reach an off-query preference."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-ORIENT-011")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    style = sources["orientation-working-style.md"]
    controller = sources["orientation-watering-controller.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-ORIENT-STYLE-011",
                    "memory": {
                        "kind": "preference",
                        "statement": (
                            "Rowan prefers reversible, small-step changes "
                            "over big-bang rewrites."
                        ),
                        "tags": ["standing", "syn-working-style"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": style["source_id"],
                            "blob_digest": style["blob_digest"],
                            "excerpt": (
                                "Rowan prefers reversible, small-step changes "
                                "over big-bang rewrites."
                            ),
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": controller["source_id"],
                    "reason": "Controller detail stays source-only for this case.",
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    walk = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["standing"]}},
    )["structuredContent"]["data"]
    assert len(walk) == 1
    assert walk[0]["match_strength"] == "enumerated"
    assert "reversible" in walk[0]["memory"]["statement"]

    by_query = _invoke(
        synthetic_store,
        "memory.search",
        {"query": "watering controller"},
    )["structuredContent"]["data"]
    assert by_query == []


def test_expired_validity_rides_the_hit_for_the_agent_to_flag(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch valid_to disappearing from the wire between apply and retrieval."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-STALE-012")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    rental = detail["sources"][0]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-STALE-RENTAL-012",
                    "memory": {
                        "kind": "fact",
                        "statement": (
                            "Rowan's cottage rental agreement runs through 2026-05-31."
                        ),
                        "occurred_on": "2026-01",
                        "valid_to": "2026-05-31",
                        "tags": ["syn-housing"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": rental["source_id"],
                            "blob_digest": rental["blob_digest"],
                            "excerpt": (
                                "The current cottage rental agreement runs "
                                "through 2026-05-31."
                            ),
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    hits = _invoke(synthetic_store, "memory.search", {"query": "cottage rental"})[
        "structuredContent"
    ]["data"]
    assert len(hits) == 1
    summary = hits[0]["memory"]
    assert summary["valid_to"] == "2026-05-31"
    assert summary["occurred_on"] == "2026-01"
    assert summary["recorded_at"]

    # Rider: a correction note placed straight in the inbox (no manifest
    # fixture -- authored inline) closes the expired claim. A repeat of the
    # original search must ride the successor only, never the stale head.
    correction_body = (
        b"# Close loop: cottage rental\n\n"
        b"## Loop\n"
        b"The cottage rental agreement expiring 2026-05-31 "
        b"(subject: cottage-rental).\n\n"
        b"## Outcome\n"
        b"Rowan renewed the cottage rental with no fixed end date.\n\n"
        b"## Disposition\n"
        b"Closed.\n"
    )
    (synthetic_store.inbox / "stale-rental-renewal.md").write_bytes(correction_body)
    second = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    second_detail = _invoke(
        synthetic_store, "inbox.read", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    note = second_detail["sources"][0]
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    renewed_statement = "Rowan renewed the cottage rental with no fixed end date."
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-STALE-RENTAL-RENEWAL-012",
                    "memory": {
                        "kind": "fact",
                        "statement": renewed_statement,
                        "occurred_on": "2026-05",
                        "tags": ["syn-housing"],
                        "sensitivity": "restricted",
                        "target_lineage_id": summary["lineage_id"],
                        "expected_head_id": summary["memory_id"],
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": renewed_statement,
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited2)

    walk = _invoke(synthetic_store, "memory.search", {"query": "cottage rental"})[
        "structuredContent"
    ]["data"]
    assert len(walk) == 1
    successor_summary = walk[0]["memory"]
    assert successor_summary["memory_id"] != summary["memory_id"]
    assert successor_summary["statement"] == renewed_statement
    assert successor_summary.get("valid_to") is None

    successor = _invoke(
        synthetic_store,
        "memory.get",
        {"lineage_id": summary["lineage_id"]},
    )["structuredContent"]["data"]
    assert successor["is_current"] is True
    assert successor["current_head_id"] == successor_summary["memory_id"]
    assert len(successor["revision_ids"]) == 2


def test_restraining_guard_travels_with_the_agreeable_claim(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch co-retrieval dropping the restraint the candor check depends on."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-GUARD-BAIT-013")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    note = detail["sources"][0]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-GUARD-FOCUS-013",
                    "memory": {
                        "kind": "preference",
                        "statement": "兰溪喜欢把闲余资金集中投入单一收藏类别。",
                        "tags": ["syn-collection"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": "兰溪喜欢把闲余资金集中投入单一收藏类别",
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-GUARD-PAUSE-013",
                    "memory": {
                        "kind": "insight",
                        "statement": (
                            "兰溪的节制规则：每月收藏支出不超过固定上限，"
                            "想超出时先暂停一周再决定。"
                        ),
                        "tags": ["syn-collection", "syn-restraint"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": (
                                "每月收藏支出不超过固定上限，想超出时先暂停一周再决定"
                            ),
                        }
                    ],
                },
                {
                    "op": "add_guard_link",
                    "guard_item_id": "SYN-ITEM-GUARD-PAUSE-013",
                    "governed_item_id": "SYN-ITEM-GUARD-FOCUS-013",
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    hits = _invoke(synthetic_store, "memory.search", {"query": "收藏"})[
        "structuredContent"
    ]["data"]
    claim = next(h for h in hits if "集中投入" in h["memory"]["statement"])
    assert len(claim["guards"]) == 1
    assert "先暂停一周" in claim["guards"][0]["statement"]


def test_complete_standing_walk_preserves_cross_aspect_priority(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch area narrowing hiding explicit priority and decision style."""
    manifest = _load_manifest()
    case_id = "SYN-JOURNEY-PRIORITY-019"
    _copy_case_sources(synthetic_store, manifest, case_id)
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {source["original_name"]: source for source in detail["sources"]}
    orientation = sources["priority-ilyra-direction.md"]
    choice = sources["priority-ilyra-choice.md"]

    direction = (
        "Ilyra prioritizes accurate astronomy demonstrations over a perfectly "
        "tidy equipment catalogue."
    )

    enjoyment = (
        "Ilyra enjoys clear star charts and hands-on lessons about the night sky."
    )

    decision_style = (
        "Ilyra tests new exhibit routines in short trials before committing "
        "to a full season."
    )

    mobility = (
        "The fictional observatory's dome may close for roof work in 2037, "
        "but no schedule has been approved."
    )

    operations = (
        "Borrowing the portable telescope from Alder Quay for the Larkglass "
        "observatory costs no fee, changes no ownership, and permits return "
        "to the lending collection after a two-week trial."
    )

    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-PRIORITY-DIRECTION-019",
                    "memory": {
                        "kind": "insight",
                        "statement": direction,
                        "tags": ["standing", "aspect:direction"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": orientation["source_id"],
                            "blob_digest": orientation["blob_digest"],
                            "excerpt": direction,
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-PRIORITY-ENJOYMENT-019",
                    "memory": {
                        "kind": "preference",
                        "statement": enjoyment,
                        "tags": ["standing", "aspect:enjoyment"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": orientation["source_id"],
                            "blob_digest": orientation["blob_digest"],
                            "excerpt": enjoyment,
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-PRIORITY-REVERSIBLE-019",
                    "memory": {
                        "kind": "preference",
                        "statement": decision_style,
                        "tags": ["standing", "aspect:decision-style"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": orientation["source_id"],
                            "blob_digest": orientation["blob_digest"],
                            "excerpt": decision_style,
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-PRIORITY-MOBILITY-019",
                    "memory": {
                        "kind": "fact",
                        "statement": mobility,
                        "tags": ["standing", "aspect:mobility"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": choice["source_id"],
                            "blob_digest": choice["blob_digest"],
                            "excerpt": mobility,
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-PRIORITY-OPERATIONS-019",
                    "memory": {
                        "kind": "fact",
                        "statement": operations,
                        "tags": ["aspect:operations"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": choice["source_id"],
                            "blob_digest": choice["blob_digest"],
                            "excerpt": operations,
                        }
                    ],
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    full = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["standing"]}},
    )["structuredContent"]["data"]
    assert {hit["memory"]["statement"] for hit in full} == {
        direction,
        enjoyment,
        decision_style,
        mobility,
    }
    assert {hit["match_strength"] for hit in full} == {"enumerated"}

    narrowed = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["standing", "aspect:mobility"]}},
    )["structuredContent"]["data"]
    assert [hit["memory"]["statement"] for hit in narrowed] == [mobility]

    lexical = _invoke(
        synthetic_store,
        "memory.search",
        {"query": "portable telescope Alder Quay"},
    )["structuredContent"]["data"]
    assert any(hit["memory"]["statement"] == operations for hit in lexical)
    assert not {direction, enjoyment, decision_style} & {
        hit["memory"]["statement"] for hit in lexical
    }


def test_loop_walk_surfaces_due_and_drops_closed(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a closed loop lingering in the loop walk, or a horizon vanishing."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-LOOP-014")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    commitments = sources["loop-commitments.md"]
    closing = sources["loop-rain-barrel-complete.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-LOOP-SUPPLIER-014",
                    "memory": {
                        "kind": "event",
                        "statement": (
                            "Rowan committed to reviewing the greenhouse seed "
                            "supplier agreement before the spring order window "
                            "closes."
                        ),
                        "valid_to": "2026-07-15",
                        "tags": ["loop:open", "syn-garden"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": (
                                "reviewing the greenhouse seed supplier agreement"
                            ),
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-LOOP-BARREL-014",
                    "memory": {
                        "kind": "event",
                        "statement": (
                            "Rowan planned to trial the rain barrel setup this season."
                        ),
                        "tags": ["loop:open", "syn-garden"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": (
                                "Rowan also planned to trial the rain barrel "
                                "setup this season."
                            ),
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": closing["source_id"],
                    "reason": "Closure lands as a correction in its own cycle.",
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    opened = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(opened) == 2
    barrel = next(h for h in opened if "rain barrel" in h["memory"]["statement"])

    # Second cycle: the closing note becomes the correction's evidence, in
    # its own batch (evidence must name a batch source; see the resolved
    # verification item in Global Constraints).
    (synthetic_store.inbox / "loop-rain-barrel-complete.md").write_bytes(
        (FIXTURE_ROOT / "sources" / "loop-rain-barrel-complete.md").read_bytes()
    )
    second = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    second_detail = _invoke(
        synthetic_store, "inbox.read", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    reclosing = second_detail["sources"][0]
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-LOOP-BARREL-CLOSE-014",
                    "memory": {
                        "kind": "event",
                        "statement": (
                            "Rowan completed the rain barrel trial in June; "
                            "the loop is closed."
                        ),
                        "tags": ["syn-garden"],
                        "sensitivity": "restricted",
                        "target_lineage_id": barrel["memory"]["lineage_id"],
                        "expected_head_id": barrel["memory"]["memory_id"],
                    },
                    "evidence": [
                        {
                            "source_id": reclosing["source_id"],
                            "blob_digest": reclosing["blob_digest"],
                            "excerpt": ("The rain barrel trial is complete as of June"),
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited2)

    walk = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(walk) == 1
    assert walk[0]["memory"]["valid_to"] == "2026-07-15"
    assert "seed supplier" in walk[0]["memory"]["statement"]


def test_closure_correction_folds_outcome_and_clears_horizon(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the taught close mapping drifting from what the Store applies."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-CLOSE-017")
    # Cycle 1: seed both open loops from the commitments fixture only; the
    # closure note is accounted as evidence-for-a-later-cycle.
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    commitments = sources["closure-shutter-commitments.md"]
    outcome_note = sources["closure-shutter-outcome.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    shutter_statement = (
        "Sable committed to repainting the studio shutters before the wet season."
    )
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-CLOSE-SHUTTER-017",
                    "memory": {
                        "kind": "event",
                        "statement": shutter_statement,
                        "occurred_on": "2026-07-01",
                        "valid_to": "2026-08-15",
                        "tags": ["loop:open", "syn-studio"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": (
                                "repainting the studio shutters before the wet season"
                            ),
                        }
                    ],
                },
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-CLOSE-FENCE-017",
                    "memory": {
                        "kind": "event",
                        "statement": ("Sable committed to staining the garden fence."),
                        "valid_to": "2026-11-01",
                        "tags": ["loop:open", "syn-studio"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": "staining the garden fence",
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": outcome_note["source_id"],
                    "reason": ("Closure evidence belongs to its own correction cycle."),
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    opened = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(opened) == 2
    shutter = next(h for h in opened if "studio shutters" in h["memory"]["statement"])

    # Cycle 2: the closure note is re-placed as its own batch and becomes the
    # correction's evidence, exactly as the companion teaches.
    (synthetic_store.inbox / "closure-shutter-outcome.md").write_bytes(
        (FIXTURE_ROOT / "sources" / "closure-shutter-outcome.md").read_bytes()
    )
    second = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    second_detail = _invoke(
        synthetic_store, "inbox.read", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    note = second_detail["sources"][0]
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    closed_statement = (
        shutter_statement
        + "\n\nOutcome (2026-08-10): The shutter repaint finished under "
        "budget on 2026-08-10."
    )
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-CLOSE-SHUTTER-CORRECTION-017",
                    "memory": {
                        "kind": "event",
                        "statement": closed_statement,
                        "occurred_on": "2026-07-01",
                        "tags": ["syn-studio"],
                        "sensitivity": "restricted",
                        "target_lineage_id": shutter["memory"]["lineage_id"],
                        "expected_head_id": shutter["memory"]["memory_id"],
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": (
                                "The shutter repaint finished under budget "
                                "on 2026-08-10."
                            ),
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited2)

    walk = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(walk) == 1
    assert "garden fence" in walk[0]["memory"]["statement"]

    successor = _invoke(
        synthetic_store,
        "memory.get",
        {"lineage_id": shutter["memory"]["lineage_id"]},
    )["structuredContent"]["data"]
    assert successor["is_current"] is True
    head = successor["revision"]
    assert head["statement"] == closed_statement
    assert head["statement"].endswith("under budget on 2026-08-10.")
    assert "loop:open" not in head["tags"]
    assert head.get("valid_to") is None
    assert head.get("occurred_on") == "2026-07-01"
    assert len(successor["revision_ids"]) == 2
    assert successor["evidence"]


def test_rehorizon_correction_moves_horizon_and_keeps_loop(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a re-horizon dropping the loop tag or rewriting the statement."""
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-REHORIZON-ZH-018")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    commitment = sources["closure-vent-commitment-zh.md"]
    note_fixture = sources["closure-vent-rehorizon-zh.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    vent_statement = "青芜承诺完成温室通风改造。"
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-REHORIZON-VENT-018",
                    "memory": {
                        "kind": "event",
                        "statement": vent_statement,
                        "valid_to": "2026-09-30",
                        "tags": ["loop:open", "syn-greenhouse"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitment["source_id"],
                            "blob_digest": commitment["blob_digest"],
                            "excerpt": "承诺完成温室通风改造",
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": note_fixture["source_id"],
                    "reason": (
                        "Re-horizon evidence belongs to its own correction cycle."
                    ),
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)
    seeded = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    (vent,) = seeded

    (synthetic_store.inbox / "closure-vent-rehorizon-zh.md").write_bytes(
        (FIXTURE_ROOT / "sources" / "closure-vent-rehorizon-zh.md").read_bytes()
    )
    second = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    note = _invoke(synthetic_store, "inbox.read", {"batch_id": second.batch_id})[
        "structuredContent"
    ]["data"]["sources"][0]
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-REHORIZON-CORRECTION-018",
                    "memory": {
                        "kind": "event",
                        "statement": vent_statement,
                        "valid_to": "2026-11-15",
                        "tags": ["loop:open", "syn-greenhouse"],
                        "sensitivity": "restricted",
                        "target_lineage_id": vent["memory"]["lineage_id"],
                        "expected_head_id": vent["memory"]["memory_id"],
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": "还在等待合成供应商的通风部件",
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited2)

    walk = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(walk) == 1
    assert walk[0]["memory"]["valid_to"] == "2026-11-15"
    assert walk[0]["memory"]["statement"] == vent_statement
    successor = _invoke(
        synthetic_store,
        "memory.get",
        {"lineage_id": vent["memory"]["lineage_id"]},
    )["structuredContent"]["data"]
    assert "loop:open" in successor["revision"]["tags"]
    assert len(successor["revision_ids"]) == 2


def test_closure_below_note_sensitivity_pins_the_floor(
    synthetic_store: RuntimePaths,
) -> None:
    """Pin the OBSERVED sensitivity-floor behavior at the correction boundary.

    The taught rule: a correction never sits below the sensitivity of the
    note it cites. Run once against the product, this is a bounded refusal
    at `change_set.edit` -- `_normalize_evidence` compares the proposed
    item's own sensitivity against its cited evidence source's effective
    sensitivity before any successor is ever drafted, so `normal` citing a
    `restricted` note never reaches `change_set.approve_and_apply`. That
    matches the spec's failure table ("the correction-sensitivity floor
    refuses silently lowering"); this test pins the observed error code so a
    silent switch to elevation would be caught here rather than assumed.
    """
    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-CLOSE-017")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    commitments = sources["closure-shutter-commitments.md"]
    outcome_note = sources["closure-shutter-outcome.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    shutter_statement = (
        "Sable committed to repainting the studio shutters before the wet season."
    )
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-FLOOR-SHUTTER-017",
                    "memory": {
                        "kind": "event",
                        "statement": shutter_statement,
                        "occurred_on": "2026-07-01",
                        "valid_to": "2026-08-15",
                        "tags": ["loop:open", "syn-studio"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": (
                                "repainting the studio shutters before the wet season"
                            ),
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": outcome_note["source_id"],
                    "reason": ("Closure evidence belongs to its own correction cycle."),
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    opened = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(opened) == 1
    (shutter,) = opened

    # Second cycle: the closure note rides its own batch, restricted -- the
    # same sensitivity as the loop it will be cited against.
    (synthetic_store.inbox / "closure-shutter-outcome.md").write_bytes(
        (FIXTURE_ROOT / "sources" / "closure-shutter-outcome.md").read_bytes()
    )
    second = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    second_detail = _invoke(
        synthetic_store, "inbox.read", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]
    note = second_detail["sources"][0]
    assert note["declared_sensitivity"] == "restricted"
    assert note["effective_sensitivity"] == "restricted"
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": second.batch_id}
    )["structuredContent"]["data"]

    # The correction proposes `normal`, below the restricted note it cites.
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-FLOOR-CORRECTION-017",
                    "memory": {
                        "kind": "event",
                        "statement": (
                            shutter_statement
                            + "\n\nOutcome (2026-08-10): The shutter repaint "
                            "finished under budget on 2026-08-10."
                        ),
                        "occurred_on": "2026-07-01",
                        "tags": ["syn-studio"],
                        "sensitivity": "normal",
                        "target_lineage_id": shutter["memory"]["lineage_id"],
                        "expected_head_id": shutter["memory"]["memory_id"],
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": (
                                "The shutter repaint finished under budget "
                                "on 2026-08-10."
                            ),
                        }
                    ],
                }
            ],
        },
    )

    # OBSERVED (a): a bounded refusal, and it happens at `change_set.edit` --
    # the draft is never even built, so `change_set.approve_and_apply` is
    # never reached.
    assert edited2["isError"] is True
    error = edited2["structuredContent"]["error"]
    assert error["code"] == "invalid_evidence"
    assert error["details"]["client_item_id"] == "SYN-ITEM-FLOOR-CORRECTION-017"

    # Nothing applied: the lineage head is exactly the one this cycle opened.
    unchanged = _invoke(
        synthetic_store,
        "memory.get",
        {"lineage_id": shutter["memory"]["lineage_id"]},
    )["structuredContent"]["data"]
    assert unchanged["is_current"] is True
    assert unchanged["current_head_id"] == shutter["memory"]["memory_id"]
    assert "loop:open" in unchanged["revision"]["tags"]
    assert len(unchanged["revision_ids"]) == 1


def test_ui_captured_correction_closes_loop(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch the closure mapping drifting between the MCP and owner-UI routes.

    Seals the correction through the real `OwnerApplicationService`
    `prepare_owner_correction` / `capture_owner_correction` entry points and a
    `UiSessionStore` session/lease -- the same call shape
    `tests/test_ui_inbox.py::test_owner_correction_capture_creates_only_one_sealed_source_and_no_review`
    exercises, and the wire shape `tests/test_inbox.py::_owner_correction_payload`
    documents -- proving the closure mapping composes with the
    owner-correction capture path (spec verification item 3) rather than
    only the agent-drafted one.
    """
    from memory.ui.auth import UiSessionStore
    from memory.ui.capture import CorrectionSubmissionLease
    from memory.ui.service import OwnerApplicationService

    manifest = _load_manifest()
    _copy_case_sources(synthetic_store, manifest, "SYN-JOURNEY-CLOSE-017")
    batch = scan_inbox(
        synthetic_store, sensitivity=Sensitivity.RESTRICTED, clock=FakeClock()
    )
    detail = _invoke(synthetic_store, "inbox.read", {"batch_id": batch.batch_id})[
        "structuredContent"
    ]["data"]
    sources = {s["original_name"]: s for s in detail["sources"]}
    commitments = sources["closure-shutter-commitments.md"]
    outcome_note = sources["closure-shutter-outcome.md"]
    created = _invoke(
        synthetic_store, "change_set.create", {"batch_id": batch.batch_id}
    )["structuredContent"]["data"]
    shutter_statement = (
        "Sable committed to repainting the studio shutters before the wet season."
    )
    edited = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-UI-CLOSE-SHUTTER-017",
                    "memory": {
                        "kind": "event",
                        "statement": shutter_statement,
                        "occurred_on": "2026-07-01",
                        "valid_to": "2026-08-15",
                        "tags": ["loop:open", "syn-studio"],
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": commitments["source_id"],
                            "blob_digest": commitments["blob_digest"],
                            "excerpt": (
                                "repainting the studio shutters before the wet season"
                            ),
                        }
                    ],
                },
                {
                    "op": "set_source_no_memory",
                    "source_id": outcome_note["source_id"],
                    "reason": ("Closure evidence belongs to its own correction cycle."),
                },
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited)

    opened = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert len(opened) == 1
    (shutter,) = opened
    memory_id = shutter["memory"]["memory_id"]

    # Seal one owner correction exactly as the local owner UI does: prepare
    # against the submission-time head, bind it to a session-issued form,
    # lease it, then capture it into its own isolated batch -- the same
    # sequence `OwnerApplicationService` and `UiSessionStore` compose for the
    # real UI route.
    outcome_text = "The shutter repaint finished under budget on 2026-08-10."
    service = OwnerApplicationService(synthetic_store)
    prepared = service.prepare_owner_correction(
        memory_id, outcome_text, clock=FakeClock()
    )
    sessions = UiSessionStore(
        bootstrap_capability="test-boot",
        exact_host="memory-synthetic.localhost:43210",
        created_at_ns=100,
    )
    session = sessions.exchange_bootstrap(
        secret="test-boot",
        exact_host="memory-synthetic.localhost:43210",
        now_ns=101,
    )
    assert session is not None
    binding = sessions.issue_correction_form(session.session_id, memory_id, now_ns=200)
    lease = sessions.lease_correction_form(
        session.session_id, binding.form_nonce, memory_id, prepared, now_ns=201
    )
    assert isinstance(lease, CorrectionSubmissionLease)
    captured = service.capture_owner_correction(lease)
    sessions.complete_correction_form(lease, captured, now_ns=202)

    sealed = _invoke(synthetic_store, "inbox.read", {"batch_id": captured.batch_id})[
        "structuredContent"
    ]["data"]
    assert len(sealed["sources"]) == 1
    note = sealed["sources"][0]
    assert note["origin"] == "owner_correction"
    assert note["authorship"] == "owner"
    assert note["declared_sensitivity"] == "restricted"
    assert note["effective_sensitivity"] == "restricted"

    # Build that batch's one change set exactly as the Step-1 cycle-2 shape:
    # statement plus an appended `Outcome (<date>):` line, `loop:open`
    # removed, no `valid_to`, citing the captured correction source.
    created2 = _invoke(
        synthetic_store, "change_set.create", {"batch_id": captured.batch_id}
    )["structuredContent"]["data"]
    closed_statement = shutter_statement + "\n\nOutcome (2026-08-10): " + outcome_text
    edited2 = _invoke(
        synthetic_store,
        "change_set.edit",
        {
            "change_set_id": created2["change_set_id"],
            "expected_revision_id": created2["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-UI-CLOSE-SHUTTER-CORRECTION-017",
                    "memory": {
                        "kind": "event",
                        "statement": closed_statement,
                        "occurred_on": "2026-07-01",
                        "tags": ["syn-studio"],
                        "sensitivity": "restricted",
                        "target_lineage_id": shutter["memory"]["lineage_id"],
                        "expected_head_id": memory_id,
                    },
                    "evidence": [
                        {
                            "source_id": note["source_id"],
                            "blob_digest": note["blob_digest"],
                            "excerpt": outcome_text,
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    _approve_and_apply(synthetic_store, edited2)

    walk = _invoke(
        synthetic_store,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]["data"]
    assert walk == []

    successor = _invoke(
        synthetic_store,
        "memory.get",
        {"lineage_id": shutter["memory"]["lineage_id"]},
    )["structuredContent"]["data"]
    assert successor["is_current"] is True
    head = successor["revision"]
    assert head["statement"] == closed_statement
    assert "loop:open" not in head["tags"]
    assert head.get("valid_to") is None
    assert len(successor["revision_ids"]) == 2


@pytest.mark.parametrize(
    (
        "original_statement",
        "update_text",
        "successor_statement",
        "unaffected_commitment",
        "update_source_count",
    ),
    [
        pytest.param(
            "Lark committed to fitting the greenhouse shade by 2026-10-08 "
            "and repainting the potting bench by 2026-10-21.",
            "Lark completed the greenhouse shade fitting on 2026-10-04.\r\n"
            "Repainting the potting bench remains planned for 2026-10-21.",
            "Lark completed the greenhouse shade fitting on 2026-10-04 "
            "and remains committed to repainting the potting bench by 2026-10-21.",
            "repainting the potting bench by 2026-10-21",
            1,
            id="fresh-english-partial-grouped-update",
        ),
        pytest.param(
            "明岚承诺于2026-10-08前安装温室遮阳帘，并于2026-10-21前修复工具架。",
            "明岚已于2026-10-04完成温室遮阳帘安装。\r\n"
            "修复工具架仍计划于2026-10-21前完成。",
            "明岚已于2026-10-04完成温室遮阳帘安装，并仍承诺于2026-10-21前修复工具架。",
            "于2026-10-21前修复工具架",
            1,
            id="fresh-chinese-partial-grouped-update",
        ),
        pytest.param(
            "Lark committed to fitting the greenhouse shade by 2026-10-08, "
            "installing the irrigation timer by 2026-10-12, "
            "and repainting the potting bench by 2026-10-21.",
            "Lark completed the greenhouse shade fitting on 2026-10-04.\r\n"
            "Lark moved the irrigation timer installation to 2026-11-03.",
            "Lark completed the greenhouse shade fitting on 2026-10-04, "
            "will install the irrigation timer by 2026-11-03, "
            "and remains committed to repainting the potting bench by 2026-10-21.",
            "repainting the potting bench by 2026-10-21",
            2,
            id="fresh-english-two-notes-one-lineage",
        ),
        pytest.param(
            "明岚承诺于2026-10-08前安装温室遮阳帘、于2026-10-12前安装灌溉传感器，"
            "并于2026-10-21前修复工具架。",
            "明岚已于2026-10-04完成温室遮阳帘安装。\r\n"
            "明岚将灌溉传感器的安装日期改为2026-11-03。",
            "明岚已于2026-10-04完成温室遮阳帘安装、计划于2026-11-03前安装灌溉传感器，"
            "并仍承诺于2026-10-21前修复工具架。",
            "于2026-10-21前修复工具架",
            2,
            id="fresh-chinese-two-notes-one-lineage",
        ),
    ],
)
def test_ready_staged_partial_update_copies_to_one_existing_lineage_review(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    original_statement: str,
    update_text: str,
    successor_statement: str,
    unaffected_commitment: str,
    update_source_count: int,
) -> None:
    """Prove the public-MCP route, not model conduct or real owner presence."""
    from memory.model import RuntimeMode
    from memory.runtime import initialize_runtime, resolve_runtime

    notes = tmp_path / "synthetic-notes"
    staged = notes / "02_Staged"
    staged.mkdir(mode=0o700, parents=True)
    notes.chmod(0o700)
    configured_inbox = notes / "synthetic-configured-inbox"
    home = tmp_path / "synthetic-correction-store"
    initialize_runtime(
        resolve_runtime(home), mode=RuntimeMode.PERSONAL, inbox=configured_inbox
    )
    paths = resolve_runtime(home)
    assert paths.inbox == configured_inbox
    assert synthetic_keychain
    assert not (home / "inbox").exists()
    assert not (notes / "03_Prepared").exists()

    original_body = (
        "# Synthetic grouped commitment\n\n" + original_statement + "\n"
    ).encode("utf-8")
    (paths.inbox / "synthetic-grouped-commitment.md").write_bytes(original_body)
    seeded_batch = _invoke(
        paths, "inbox.scan", {"authorship": "owner", "sensitivity": "restricted"}
    )["structuredContent"]["data"]
    seeded_source = _invoke(
        paths, "inbox.read", {"batch_id": seeded_batch["batch_id"]}
    )["structuredContent"]["data"]["sources"][0]
    seed = _invoke(paths, "change_set.create", {"batch_id": seeded_batch["batch_id"]})[
        "structuredContent"
    ]["data"]
    tags = ["loop:open", "synthetic", "syn-grouped-followup"]
    seeded_review = _invoke(
        paths,
        "change_set.edit",
        {
            "change_set_id": seed["change_set_id"],
            "expected_revision_id": seed["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-GROUPED-ORIGINAL-001",
                    "memory": {
                        "kind": "event",
                        "statement": original_statement,
                        "occurred_on": "2026-09-10",
                        "valid_from": "2026-09-10",
                        "tags": tags,
                        "sensitivity": "restricted",
                    },
                    "evidence": [
                        {
                            "source_id": seeded_source["source_id"],
                            "blob_digest": seeded_source["blob_digest"],
                            "excerpt": original_statement,
                        }
                    ],
                }
            ],
        },
    )["structuredContent"]["data"]
    seed_application = _approve_and_apply(paths, seeded_review)
    original_id = seed_application["memory_ids"][0]
    original_envelope = _invoke(paths, "memory.get", {"memory_id": original_id})[
        "structuredContent"
    ]
    assert original_envelope["page"] == {"has_more": False}
    original = original_envelope["data"]
    lineage_id = original["revision"]["lineage_id"]
    assert original["is_current"] is True
    assert original["current_head_id"] == original_id
    assert original["revision_ids"] == [original_id]

    # Fresh owner-authored, ready Staged evidence is transported unchanged;
    # there is no generated Prepared candidate and no owner recopy step.
    updates = [update_text] if update_source_count == 1 else update_text.split("\r\n")
    assert len(updates) == update_source_count
    staged_sources: list[tuple[Path, bytes, int]] = []
    for ordinal, update in enumerate(updates):
        staged_source = staged / f"synthetic-ready-update-{ordinal}.md"
        update_body = ("# Synthetic ready update\r\n\r\n" + update + "\r\n").encode(
            "utf-8"
        )
        staged_source.write_bytes(update_body)
        staged_source.chmod(0o600)
        staged_sources.append((staged_source, update_body, staged_source.stat().st_ino))
        inbox_copy = paths.inbox / staged_source.name
        with inbox_copy.open("xb") as destination:
            destination.write(staged_source.read_bytes())
        inbox_copy.chmod(0o600)
        assert inbox_copy.read_bytes() == update_body
        assert staged_source.read_bytes() == update_body

    captured = _invoke(
        paths,
        "inbox.scan",
        {"authorship": "mixed", "sensitivity": "restricted"},
    )["structuredContent"]["data"]
    assert captured["source_count"] == update_source_count
    assert captured["batch_has_more"] is False
    assert captured["review_state"] == "none"
    assert captured["issues"] == []
    assert captured["duplicates"] == []
    for staged_source, update_body, staged_inode in staged_sources:
        assert not (paths.inbox / staged_source.name).exists()
        assert staged_source.read_bytes() == update_body
        assert staged_source.stat().st_ino == staged_inode

    # Recovery rediscovers the sealed capture by exact source metadata. It
    # resumes that batch instead of copying/scanning the Staged original again.
    resumed_paths = resolve_runtime(home)
    batches_envelope = _invoke(resumed_paths, "inbox.list", {})["structuredContent"]
    assert batches_envelope["page"] == {"has_more": False}
    assert len(batches_envelope["data"]) == 2
    resumed_batch = next(
        batch
        for batch in batches_envelope["data"]
        if batch["batch_id"] == captured["batch_id"]
    )
    captured_detail = _invoke(
        resumed_paths, "inbox.read", {"batch_id": resumed_batch["batch_id"]}
    )["structuredContent"]["data"]
    assert captured_detail["batch"] == captured
    notes_by_name = {note["original_name"]: note for note in captured_detail["sources"]}
    captured_notes: list[dict[str, Any]] = []
    for staged_source, update_body, _staged_inode in staged_sources:
        note = notes_by_name[staged_source.name]
        captured_notes.append(note)
        assert note["blob_digest"] == hashlib.sha256(update_body).hexdigest()
        assert note["authorship"] == "mixed"
        assert note["byte_length"] == len(update_body)
        assert note["origin"] == "inbox"
        assert note["declared_sensitivity"] == "restricted"
        assert note["effective_sensitivity"] == "restricted"
    assert _read_all_sources(resumed_paths) == {
        "synthetic-grouped-commitment.md": original_body,
        **{
            staged_source.name: update_body
            for staged_source, update_body, _staged_inode in staged_sources
        },
    }

    current_envelope = _invoke(resumed_paths, "memory.get", {"lineage_id": lineage_id})[
        "structuredContent"
    ]
    assert current_envelope["page"] == {"has_more": False}
    current = current_envelope["data"]
    assert current == original
    target = current["revision"]
    created = _invoke(
        resumed_paths, "change_set.create", {"batch_id": captured["batch_id"]}
    )["structuredContent"]["data"]
    assert (
        _invoke(resumed_paths, "change_set.create", {"batch_id": captured["batch_id"]})[
            "structuredContent"
        ]["data"]
        == created
    )
    correction_memory = {
        "kind": target["kind"],
        "statement": successor_statement,
        "occurred_on": target["occurred_on"],
        "valid_from": target["valid_from"],
        "tags": target["tags"],
        "sensitivity": target["stored_sensitivity"],
        "target_lineage_id": target["lineage_id"],
        "expected_head_id": current["current_head_id"],
    }
    correction_evidence = [
        {
            "source_id": note["source_id"],
            "blob_digest": note["blob_digest"],
            "excerpt": update,
        }
        for note, update in zip(captured_notes, updates, strict=True)
    ]
    if update_source_count > 1:
        # The former one-proposal-per-note mapping asks for two successors of
        # one head. Its refusal must preserve the exact empty draft and head.
        separate_proposals = _invoke(
            resumed_paths,
            "change_set.edit",
            {
                "change_set_id": created["change_set_id"],
                "expected_revision_id": created["revision_id"],
                "edits": [
                    {
                        "op": "add_item",
                        "client_item_id": f"SYN-ITEM-SEPARATE-NOTE-{ordinal}",
                        "memory": correction_memory,
                        "evidence": [evidence],
                    }
                    for ordinal, evidence in enumerate(correction_evidence)
                ],
            },
        )["structuredContent"]
        assert separate_proposals["instruction_trust"] == "inert"
        assert separate_proposals["error"]["code"] == "invalid_argument"
        assert (
            separate_proposals["error"]["details"]["governed_lineage_id"] == lineage_id
        )
        assert "data" not in separate_proposals
        assert (
            _invoke(
                resumed_paths,
                "change_set.get",
                {"change_set_id": created["change_set_id"]},
            )["structuredContent"]["data"]
            == created
        )
        assert (
            _invoke(resumed_paths, "memory.get", {"memory_id": original_id})[
                "structuredContent"
            ]["data"]
            == original
        )
    corrected = _invoke(
        resumed_paths,
        "change_set.edit",
        {
            "change_set_id": created["change_set_id"],
            "expected_revision_id": created["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": "SYN-ITEM-GROUPED-CORRECTION-002",
                    "memory": correction_memory,
                    "evidence": correction_evidence,
                }
            ],
        },
    )["structuredContent"]["data"]
    assert len(corrected["items"]) == 1
    item = corrected["items"][0]
    assert item["memory"]["target_lineage_id"] == lineage_id
    assert item["memory"]["expected_head_id"] == original_id
    assert item["memory"]["valid_to"] is None
    assert item["memory"]["tags"] == tags
    assert len(corrected["source_decisions"]) == update_source_count
    assert {decision["source_id"] for decision in corrected["source_decisions"]} == {
        note["source_id"] for note in captured_notes
    }
    assert corrected["source_decisions"] == [
        {
            "ordinal": ordinal,
            "source_id": note["source_id"],
            "blob_digest": note["blob_digest"],
            "state": "used",
            "reason": None,
        }
        for ordinal, note in enumerate(captured_detail["sources"])
    ]
    assert len(item["evidence"]) == update_source_count
    for ordinal, (locator, evidence, update) in enumerate(
        zip(item["evidence"], correction_evidence, updates, strict=True)
    ):
        assert locator["ordinal"] == ordinal
        assert locator["source_id"] == evidence["source_id"]
        assert locator["blob_digest"] == evidence["blob_digest"]
        assert locator["excerpt"] == update
        assert locator["char_end"] - locator["char_start"] == len(update)

    exact_approval = {
        "change_set_id": corrected["change_set_id"],
        "revision_id": corrected["revision_id"],
        "digest": corrected["digest"],
    }
    refused = _invoke(resumed_paths, "change_set.approve_and_apply", exact_approval)[
        "structuredContent"
    ]
    assert refused["instruction_trust"] == "inert"
    assert refused["error"]["code"] == "owner_approval_required"
    command = shlex.split(refused["error"]["details"]["approval_handoff"]["command"])
    assert corrected["change_set_id"] in command
    assert corrected["revision_id"] in command
    assert corrected["digest"] in command
    assert (
        _invoke(resumed_paths, "memory.get", {"memory_id": original_id})[
            "structuredContent"
        ]["data"]
        == original
    )
    assert (
        _invoke(
            resumed_paths, "change_set.get", {"change_set_id": created["change_set_id"]}
        )["structuredContent"]["data"]
        == corrected
    )

    # Existing trusted elicitation is a synthetic adapter seam: it establishes
    # exact state/atomicity behavior without claiming an OS presence ceremony.
    application = _approve_and_apply(resumed_paths, corrected)
    assert application["idempotent_replay"] is False
    assert len(application["memory_ids"]) == 1
    successor_id = application["memory_ids"][0]
    assert successor_id != original_id
    successor_envelope = _invoke(
        resumed_paths, "memory.get", {"lineage_id": lineage_id}
    )["structuredContent"]
    assert successor_envelope["page"] == {"has_more": False}
    successor = successor_envelope["data"]
    assert successor["is_current"] is True
    assert successor["current_head_id"] == successor_id
    assert successor["predecessor_id"] == original_id
    assert successor["revision_ids"] == [original_id, successor_id]
    assert successor["revision"]["lineage_id"] == lineage_id
    assert successor["revision"]["statement"] == successor_statement
    assert unaffected_commitment in successor["revision"]["statement"]
    for field in ("kind", "occurred_on", "valid_from", "tags", "stored_sensitivity"):
        assert successor["revision"][field] == target[field]
    assert "valid_to" not in successor["revision"]
    assert successor["evidence"] == item["evidence"]
    assert successor["guards"] == original["guards"]
    assert successor["governs"] == original["governs"]

    historical = _invoke(resumed_paths, "memory.get", {"memory_id": original_id})[
        "structuredContent"
    ]["data"]
    assert historical["is_current"] is False
    assert historical["current_head_id"] == successor_id
    assert historical["revision"] == original["revision"]
    assert historical["evidence"] == original["evidence"]
    assert historical["revision_ids"] == [original_id, successor_id]
    assert "predecessor_id" not in historical
    open_envelope = _invoke(
        resumed_paths,
        "memory.search",
        {"filters": {"tags_all": ["loop:open"]}},
    )["structuredContent"]
    assert open_envelope["page"] == {"has_more": False}
    assert len(open_envelope["data"]) == 1
    assert open_envelope["data"][0]["memory"] == successor["revision"]
    all_heads = _invoke(resumed_paths, "memory.search", {})["structuredContent"]
    assert all_heads["page"] == {"has_more": False}
    assert len(all_heads["data"]) == 1
    assert all_heads["data"][0]["memory"]["lineage_id"] == lineage_id

    replay = _invoke(resumed_paths, "change_set.approve_and_apply", exact_approval)[
        "structuredContent"
    ]["data"]
    assert replay == {**application, "idempotent_replay": True}
    recovered_set = _invoke(
        resolve_runtime(home), "change_set.create", {"batch_id": captured["batch_id"]}
    )["structuredContent"]["data"]
    assert recovered_set["state"] == "applied"
    for field in (
        "change_set_id",
        "revision_id",
        "digest",
        "items",
        "source_decisions",
    ):
        assert recovered_set[field] == corrected[field]
    applied_batch = _invoke(
        resumed_paths, "inbox.read", {"batch_id": captured["batch_id"]}
    )["structuredContent"]["data"]["batch"]
    assert applied_batch["review_state"] == "applied"
    assert applied_batch["change_set_id"] == corrected["change_set_id"]
    assert applied_batch["application_id"] == application["application_id"]
    status = _invoke(resumed_paths, "store.status", {})["structuredContent"]["data"]
    assert status["source_count"] == 1 + update_source_count
    assert status["memory_count"] == 1
    assert status["pending_review_count"] == 0
    for staged_source, update_body, staged_inode in staged_sources:
        assert staged_source.read_bytes() == update_body
        assert staged_source.stat().st_ino == staged_inode
    assert not (notes / "03_Prepared").exists()
