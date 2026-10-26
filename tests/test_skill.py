from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from memory.model import RuntimePaths

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_PATH = REPO_ROOT / "src" / "memory" / "skill" / "SKILL.md"
CLIENT_SETUP_PATH = REPO_ROOT / "docs" / "client-setup.md"
SQLCIPHER_COMPANION = REPO_ROOT / (
    "third_party/wheels/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-"
    "cp314-cp314-macosx_26_0_arm64.whl"
)
EXPECTED_TOOLS = (
    "store.status",
    "source.list",
    "source.search",
    "source.read",
    "inbox.scan",
    "inbox.list",
    "inbox.read",
    "memory.search",
    "memory.get",
    "memory.facets",
    "change_set.create",
    "change_set.get",
    "change_set.edit",
    "change_set.approve_and_apply",
)
# Matches a backticked owner CLI escape hatch the Skill tells the owner to run
# directly, e.g. `` `memory reindex` `` or `` `memory lint guards` ``. The
# capture is deliberately unrestricted (anything but a backtick), not just
# `[a-z ]+`: a narrower class could silently stop matching a span that later
# grows a flag or other non-lowercase content, which would make the
# cross-check below pass by no longer seeing the command at all.
_MEMORY_CLI_COMMAND = re.compile(r"`memory ([^`]+)`")
EXPECTED_MEMORY_CLI_SUBCOMMANDS = frozenset({"lint", "reindex", "skill"})


def _skill_text() -> str:
    assert SKILL_PATH.is_file(), "the portable Store Skill is missing"
    return SKILL_PATH.read_text(encoding="utf-8")


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    match = re.fullmatch(r"---\n(?P<header>.*?)\n---\n(?P<body>.*)", text, re.DOTALL)
    assert match is not None, "SKILL.md must have one YAML frontmatter block"
    values: dict[str, str] = {}
    for line in match.group("header").splitlines():
        key, separator, value = line.partition(":")
        assert separator == ":" and key and value.strip()
        values[key] = value.strip()
    return values, match.group("body")


def test_skill_is_concise_vendor_neutral_and_uses_only_the_generic_contract() -> None:
    """Catch provider, domain, or escape-hatch guidance entering the Skill."""
    text = _skill_text()
    frontmatter, body = _frontmatter(text)

    assert set(frontmatter) == {"description", "name"}
    assert re.fullmatch(r"[a-z0-9-]{1,64}", frontmatter["name"])
    assert frontmatter["description"].startswith("Use when ")
    assert len(frontmatter["description"]) <= 500
    # Keep the served conduct concise while retaining complete retrieval,
    # approval, correction and advice obligations in one discoverable Skill.
    assert len(body.splitlines()) < 325
    assert len(body.split()) < 2920

    named_contracts = set(re.findall(r"`([a-z_]+(?:\.[a-z_]+)+)`", body))
    assert named_contracts == set(EXPECTED_TOOLS)
    for tool in EXPECTED_TOOLS:
        assert body.count(f"`{tool}`") >= 1

    folded = text.casefold()
    for forbidden in (
        "anthropic",
        "claude",
        "codex",
        "openai",
        "personal vault",
        "provider",
        "/users/",
        "~/",
        "file://",
        "owner_decision",
        "approved=true",
        "approval=true",
    ):
        assert forbidden not in folded
    for forbidden_word in ("ask", "database", "key", "keychain", "sql"):
        assert re.search(rf"\b{forbidden_word}\b", folded) is None

    assert "memory approve" not in folded
    # Flowed, because these phrases are long enough to sit across a wrap; a
    # reflow must not silently drop a rule the approval step has to carry.
    flowed = " ".join(body.split())
    assert "`approval_handoff`" in flowed
    assert "run that invocation exactly as returned" in flowed
    assert "confirmed unsurfaced `owner_declined`" in flowed
    assert "If prompt visibility is unknown, report the handoff and stop" in flowed
    assert "After a visible decline or cancellation" in flowed
    assert "do not retry the handoff or the unapplied MCP call" in flowed
    assert "the authorized intake workflow's private review surface" in flowed
    assert "owner_approval_required" in body
    assert "nothing was applied" in body
    assert "stop" in body
    assert "elicitation" in body


def test_skill_scopes_its_operations_to_memory_and_yields_on_a_coverage_gap() -> None:
    """Catch Memory-only wording trapping task routing after exhaustive fallback."""
    folded = " ".join(_skill_text().casefold().split())

    assert "for memory data, use only these operations:" in folded
    assert (
        "a memory coverage gap establishes only what memory did not establish" in folded
    )
    assert (
        "does not prove that another configured bounded system of record lacks the fact"
        in folded
    )
    assert "return control to task-level routing" in folded
    assert "may be authoritative for the requested fact" in folded
    assert "complete any required fallback before answering" in folded
    assert "answer only after fallback" not in folded
    assert not re.search(r"(?m)^use only these operations:", _skill_text().casefold())

    for forbidden in ("ledger", "finance", "banking", "brokerage"):
        assert forbidden not in folded


def _registered_cli_subcommands() -> frozenset[str]:
    """Read every top-level `memory <word>` subcommand straight from argparse.

    argparse has no public API for enumerating a parser's subcommands, so this
    finds the one `_SubParsersAction` among the parser's actions -- the action
    object `add_subparsers()` returns, and the only kind whose `choices`
    mapping holds every name a later `add_parser` call registered -- rather
    than scraping `--help` text or hand-maintaining a name list that could
    silently drift from `_build_parser`.
    """
    import argparse

    from memory.cli import _build_parser

    parser = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return frozenset(action.choices)
    raise AssertionError("the memory CLI parser registers no subparsers")


def test_skill_named_memory_cli_commands_are_registered_subcommands() -> None:
    """Catch the Skill naming an owner CLI escape hatch the CLI stopped registering."""
    body = _frontmatter(_skill_text())[1]

    named = {match.split()[0] for match in _MEMORY_CLI_COMMAND.findall(body)}
    assert named == EXPECTED_MEMORY_CLI_SUBCOMMANDS

    registered = _registered_cli_subcommands()
    for subcommand in named:
        assert subcommand in registered, (
            f"SKILL.md names `memory {subcommand}`, which the CLI does not register"
        )


def test_skill_digest_is_lf_normalized_and_content_addressed() -> None:
    """Catch status hashing a path, platform line endings, or stale Skill bytes."""
    from memory.mcp_server import skill_digest

    raw = SKILL_PATH.read_bytes()
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    independently_hashed = hashlib.sha256(normalized).hexdigest()

    assert skill_digest() == independently_hashed
    assert re.fullmatch(r"[0-9a-f]{64}", skill_digest())


def test_skill_and_client_guide_pin_the_already_sealed_correction_sequence() -> None:
    """Catch installed agents scanning or co-batching an owner correction."""
    skill = _skill_text()
    guide = CLIENT_SETUP_PATH.read_text(encoding="utf-8")

    for text in (skill, guide):
        correction = " ".join(text.casefold().split("owner correction", 1)[1].split())
        assert "already sealed" in correction
        assert "exact batch" in correction
        assert "must not call `inbox.scan`" in correction
        assert "`inbox.read`" in correction
        assert "owner_correction" in correction
        assert "`owner`" in correction
        assert "`restricted`" in correction
        assert "through completion" in correction
        assert "target lineage" in correction
        assert "expected head" in correction
        assert "only that batch" in correction
        assert "exact reviewed revision and digest" in correction
        assert "same-lineage successor" in correction
        assert "unrelated inbox" in correction


def test_wheel_and_sdist_include_the_exact_skill_bytes(tmp_path: Path) -> None:
    """Catch an editable checkout masking missing package data."""
    result = subprocess.run(
        ["uv", "build", "--out-dir", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    wheels = list(tmp_path.glob("*.whl"))
    sdists = list(tmp_path.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1

    with zipfile.ZipFile(wheels[0]) as wheel:
        wheel_skill = wheel.read("memory/skill/SKILL.md")
    with tarfile.open(sdists[0], mode="r:gz") as sdist:
        skill_members = [
            member
            for member in sdist.getmembers()
            if member.name.endswith("/src/memory/skill/SKILL.md")
        ]
        assert len(skill_members) == 1
        extracted = sdist.extractfile(skill_members[0])
        assert extracted is not None
        sdist_skill = extracted.read()

    expected = SKILL_PATH.read_bytes()
    assert wheel_skill == expected
    assert sdist_skill == expected


def test_clean_wheel_install_discovers_only_its_packaged_skill(tmp_path: Path) -> None:
    """Catch resource discovery accidentally resolving the source checkout."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    built = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    (wheel,) = wheelhouse.glob("*.whl")
    environment = tmp_path / "clean-environment"
    created = subprocess.run(
        ["uv", "venv", "--python", "3.14", str(environment)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert created.returncode == 0, created.stderr
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(environment / "bin" / "python"),
            str(SQLCIPHER_COMPANION),
            str(wheel),
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr

    discovered = subprocess.run(
        [
            environment / "bin" / "python",
            "-I",
            "-c",
            (
                "from importlib.resources import files; "
                "resource=files('memory').joinpath('skill','SKILL.md'); "
                "print(resource); print(resource.read_text(encoding='utf-8'), end='')"
            ),
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        text=True,
    )
    assert discovered.returncode == 0, discovered.stderr
    first_line, installed_text = discovered.stdout.split("\n", 1)
    assert Path(first_line).is_relative_to(environment)
    assert not Path(first_line).is_relative_to(REPO_ROOT)
    assert installed_text == _skill_text()
    assert sys.prefix not in first_line


def test_skill_and_client_guide_pin_the_os_mediated_approval_fallback() -> None:
    """Catch guidance offering a typed, piped, or PTY approval fallback."""
    skill = " ".join(_skill_text().casefold().split())
    guide = " ".join(CLIENT_SETUP_PATH.read_text(encoding="utf-8").casefold().split())

    for text in (skill, guide):
        assert "macos owner presence" in text
        assert "typed input, pipes, and ptys" in text
        assert "local owner application" in text
        assert "owner_approval_required" in text
        assert "nothing was applied" in text
    assert "memory approve" not in skill
    assert "there is no terminal fallback" in guide


def test_skill_freshness_values_name_the_contract_it_was_authored_against(
    synthetic_store: RuntimePaths,
) -> None:
    """Catch a Skill whose stated freshness baseline has drifted from the Store.

    A file cannot carry its own digest, so the Skill carries the two values it
    was written against and tells the reader to trust `store.status` over
    itself when they differ. That is only useful while the stated values are
    the ones a current Store actually reports: a Skill claiming an older
    contract would make every fresh install look stale, and one claiming a
    newer contract would hide a genuinely stale copy.
    """
    from memory import __version__
    from memory.mcp_server import contract_digest
    from memory.sources import get_store_status

    body = SKILL_PATH.read_text(encoding="utf-8")
    status = get_store_status(synthetic_store)

    assert f"`{__version__}`" in body
    assert f"`{contract_digest()}`" in body
    assert status.product_version == __version__
    assert status.mcp_contract_digest == contract_digest()


def test_skill_teaches_the_advising_discipline() -> None:
    """Catch the advising workflow drifting out of the packaged Skill."""
    text = _skill_text()
    _, body = _frontmatter(text)
    assert "## Advise the owner" in body
    flowed = " ".join(body.split())
    assert "never recite them back as a portrait of the owner" in flowed
    assert "a past open-loop horizon is due, not expired" in flowed
    assert "other expired `valid_to` periods are never asserted as current" in flowed
    assert "stored disagreement outranks session agreement" in flowed
    assert "Rebuild this list every session" in flowed
    assert "`standing`" in flowed
    assert "`loop:open`" in flowed
    # Membership changes stay evidence-linked review work.
    assert "evidenced like any correction" in flowed
    # Phase 2: the one-offer outcome-capture conduct rule.
    assert "offer exactly once" in flowed
    assert "first closing response" in flowed
    assert "a decline ends the matter" in flowed
    # Phase 3: the loop-closure / re-horizon conduct rule.
    assert "once, at the same close" in flowed
    assert "an outcome or horizon is never invented" in flowed


def test_skill_makes_standing_classification_deterministic() -> None:
    """Catch a qualifying durable advising claim being left outside standing."""
    folded = " ".join(_skill_text().casefold().split())

    assert "carries the reserved `standing` tag" in folded
    assert "do not infer `standing`" in folded
    assert "incidental fact" in folded
    assert "one-time choice" in folded
    assert "temporary state" in folded
    assert "may carry the reserved `standing` tag" not in folded


def test_skill_requires_one_source_free_decision_note_offer() -> None:
    """Catch an actual decision being ignored or misrouted into Store review."""
    folded = " ".join(_skill_text().casefold().split())
    decision_note = folded.split(
        "when this session's recommendation",
        maxsplit=1,
    )[1].split("when the owner states that an open loop", maxsplit=1)[0]

    assert "offer exactly once" in decision_note
    assert "first closing response" in decision_note
    assert "include the draft itself" in decision_note
    assert "do not merely restate the decision" in decision_note
    assert "the agent's recommendation is not a decision" in decision_note
    assert "before the owner states" in decision_note
    for heading in (
        "question",
        "options considered",
        "recommendation",
        "decision",
        "rationale",
        "revisit by",
    ):
        assert heading in decision_note
    assert "a request not to save" in decision_note
    assert "writes nothing" in decision_note
    assert "the decision alone is not a source" in decision_note
    assert "never call `inbox.scan`" in decision_note
    assert "a decline ends the matter" in decision_note
    assert "may offer" not in decision_note


def test_skill_keeps_decision_offer_through_loop_resolving_closes() -> None:
    """Catch a loop-closure frame swallowing the required decision-note offer."""
    folded = " ".join(_skill_text().casefold().split())
    decision_note = folded.split(
        "when this session's recommendation",
        maxsplit=1,
    )[1].split("when the owner states that an open loop", maxsplit=1)[0]

    assert "still gets this offer" in decision_note
    assert "never replaces it" in decision_note


def test_skill_orients_before_ranked_queries_and_names_the_ordering() -> None:
    """Catch topical queries preempting orientation or a retained ordering going unnamed."""
    _, body = _frontmatter(_skill_text())
    advising = " ".join(body.split("\n## Advise the owner\n", 1)[1].split())

    assert "Orient first, before any ranked query" in advising
    assert "apply it and name it in the answer" in advising


def test_skill_pins_closure_correction_statement_form() -> None:
    """Catch closure corrections inventing successor-statement phrasing."""
    _, body = _frontmatter(_skill_text())
    review = " ".join(
        body.split("\n## Review one inbox batch\n", 1)[1]
        .split("\n## Review one captured correction\n", 1)[0]
        .split()
    )

    assert "keeps the current statement verbatim" in review
    assert "appends one final `Outcome (<date>):` line" in review
    assert "in the owner's stated words" in review
    assert "drops `loop:open`" in review
    assert "clears `valid_to`" in review
    assert "changes `valid_to` alone" in review
    assert "never reworded or translated" in review


def test_skill_never_aspect_narrows_the_initial_standing_walk() -> None:
    """Catch cross-area standing evidence being excluded before advice."""
    _, body = _frontmatter(_skill_text())
    advising = " ".join(body.split("\n## Advise the owner\n", 1)[1].split())

    assert "follow `has_more` to completion" in advising
    assert "Never add an `aspect:` filter to this first walk" in advising
    assert "cannot exclude standing memory from orientation" in advising
    assert "an `aspect:` tag may narrow the walk" not in advising


def test_skill_teaches_scenario_priority_and_reversibility_synthesis() -> None:
    """Catch candor collapsing into invented hierarchy or generic pessimism."""
    _, body = _frontmatter(_skill_text())
    advising = " ".join(body.split("\n## Advise the owner\n", 1)[1].split())

    for required in (
        "Answer through five checks",
        "changes no retained fact",
        "reason within the assumption",
        "Do not infer an ordering",
        "reversible steps from irreversible commitments",
        "uncertain future complications from present effects",
        "Candor is not default pessimism",
    ):
        assert required in advising
