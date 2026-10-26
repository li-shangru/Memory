"""Command-line entry point for Memory."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from memory import __version__, skill_sync
from memory.errors import (
    InvalidArgumentError,
    OwnerApprovalRequiredError,
    StoreError,
)
from memory.model import (
    ApplicationResult,
    CapturedCorrection,
    CaptureRecoveryIssue,
    GuardViolation,
    Page,
    RuntimeMode,
    RuntimePaths,
    StoreStatus,
)
from memory.runtime import (
    authorize_runtime_use,
    default_root,
    initialize_runtime,
    resolve_runtime,
)

_MCP_SERVER_NAME = "memory"
_MCP_COMMAND = "memory"
_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

if TYPE_CHECKING:
    # Deferred: memory.maintenance pulls in memory.database (and so
    # sqlcipher3), which every other command here avoids loading until its own
    # branch runs. `lint_guards` is imported lazily in the `lint` branch below;
    # this import exists only so these two types can be named in annotations.
    from memory.maintenance import GuardCandidate, GuardLintReport
    from memory.ui.view_models import OwnerChangeSetSummary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory")
    parser.add_argument("--version", action="version", version=f"memory {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="initialize an encrypted Store")
    initialize.add_argument("--home", type=Path)
    initialize.add_argument("--inbox", type=Path)
    export = commands.add_parser(
        "export",
        help="export ALL retained data as plaintext JSON after macOS owner authentication",
    )
    export.add_argument("--home", type=Path)
    export.add_argument("--output", type=Path, required=True)
    paths = commands.add_parser("paths", help="show owner-visible Store paths")
    paths.add_argument("--home", type=Path)
    paths.add_argument("--json", action="store_true", required=True)
    relocate = commands.add_parser(
        "relocate-inbox",
        help="move the configured external Inbox without changing the Store",
    )
    relocate.add_argument("--home", type=Path)
    relocate.add_argument("--to", type=Path, required=True)
    mcp = commands.add_parser("mcp", help="serve the generic Store MCP on stdio")
    mcp.add_argument("--home", type=Path)
    # Off by default: trusting a client's elicitation UI to prove the owner's
    # decision is a per-Store owner choice, not a capability grant a harness
    # can claim for itself.
    mcp.add_argument("--trust-elicitation", action="store_true")
    # Optional on purpose: bare `memory mcp` still serves stdio, which is the
    # command every client configuration invokes.
    mcp_commands = mcp.add_subparsers(dest="mcp_command")
    mcp_config = mcp_commands.add_parser(
        "config",
        help="print this Store's stdio MCP server entry",
    )
    # SUPPRESS so both `mcp --home H config` and `mcp config --home H` work: a
    # subparser writes into the same namespace, so an ordinary default here
    # would silently overwrite the home the parent already parsed.
    mcp_config.add_argument("--home", type=Path, default=argparse.SUPPRESS)
    mcp_config.add_argument(
        "--trust-elicitation", action="store_true", default=argparse.SUPPRESS
    )
    mcp_config.add_argument("--format", choices=["json", "toml"], required=True)
    ui = commands.add_parser(
        "ui",
        help="recover exact captures and serve the local owner UI",
    )
    ui.add_argument("--home", type=Path)
    # One internal pair, hidden from `--help` rather than offered. Neither
    # works without the other -- `run_ui` refuses an unpaired invocation --
    # and the descriptor receives the launch envelope, whose URL fragment is a
    # one-use bootstrap capability. Printing that URL to a terminal instead
    # would put a live capability into scrollback, a `script` transcript, a
    # multiplexer buffer, and any shared screen, for no owner gain: `memory
    # ui` opens the browser itself. The pair exists for the acceptance driver
    # and the browser journeys, which read the envelope off the descriptor and
    # never let it reach a stream.
    ui.add_argument("--no-open", action="store_true", help=argparse.SUPPRESS)
    ui.add_argument("--launch-fd", type=int, help=argparse.SUPPRESS)
    approve = commands.add_parser(
        "approve",
        help="render one exact Memory PR revision for owner inspection",
    )
    approve.add_argument("change_set_id")
    approve.add_argument("--revision", required=True)
    approve.add_argument("--digest", required=True)
    approve.add_argument("--home", type=Path)
    approve.add_argument(
        "--json",
        action="store_true",
        help="print the application result as JSON instead of prose",
    )
    reindex = commands.add_parser(
        "reindex",
        help="rebuild the search projections with the current tokenizer",
    )
    reindex.add_argument("--home", type=Path)
    status = commands.add_parser(
        "status",
        help="report Store identity, freshness, and the review backlog",
    )
    status.add_argument("--home", type=Path)
    status.add_argument("--json", action="store_true", required=True)
    reviews = commands.add_parser(
        "reviews",
        help="list Memory Reviews awaiting one owner approval",
    )
    reviews.add_argument("--home", type=Path)
    reviews.add_argument("--json", action="store_true", required=True)
    recover = commands.add_parser(
        "recover",
        help="resume interrupted exact captures without starting the owner UI",
    )
    recover.add_argument("--home", type=Path)
    lint = commands.add_parser(
        "lint",
        help="check retained memories for guard-link issues",
    )
    lint.add_argument("target", choices=["guards"])
    lint.add_argument("--home", type=Path)
    lint.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON instead of prose",
    )
    skill = commands.add_parser(
        "skill",
        help="compare or install one named copy of the packaged Skill",
    )
    skill_commands = skill.add_subparsers(dest="skill_command", required=True)
    for name, description in (
        ("check", "report whether one named Skill copy matches the packaged Skill"),
        ("install", "replace one named Skill copy with the packaged Skill"),
    ):
        skill_command = skill_commands.add_parser(name, help=description)
        skill_command.add_argument("--target", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Store CLI."""
    arguments = _build_parser().parse_args(argv)
    if arguments.command == "skill":
        # Deliberately before any runtime resolution: a client Skill copy is
        # checked and repaired with no Store, no Keychain, and no home.
        return _run_skill(arguments.skill_command, arguments.target)
    paths = resolve_runtime(arguments.home)
    try:
        if arguments.command == "init":
            initialize_runtime(
                paths,
                mode=RuntimeMode.PERSONAL,
                inbox=arguments.inbox,
            )
            paths = resolve_runtime(arguments.home)
            print(f"Inbox: {paths.inbox}")
            return 0
        if arguments.command == "export":
            from memory.export import export_store

            print(
                json.dumps(
                    export_store(paths, arguments.output),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0
        if arguments.command == "paths":
            authorize_runtime_use(paths)
            payload = {
                "database": str(paths.database),
                "home": str(paths.root),
                "identity": str(paths.identity),
                "inbox": str(paths.inbox),
                "inbox_claims": str(paths.inbox_claims),
            }
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0
        if arguments.command == "relocate-inbox":
            from memory.inbox_relocation import relocate_inbox

            result = relocate_inbox(paths, arguments.to)
            print(
                json.dumps(
                    {"status": result.status},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if arguments.command == "mcp":
            trust_elicitation = bool(getattr(arguments, "trust_elicitation", False))
            if arguments.mcp_command == "config":
                # No authorization: an owner must be able to print the entry
                # that connects a client before the Store is ever unlocked.
                print(
                    _mcp_config_block(
                        paths.root,
                        arguments.format,
                        trust_elicitation=trust_elicitation,
                    ),
                    end="",
                )
                return 0
            from memory.mcp_server import run_stdio

            authorize_runtime_use(paths)
            run_stdio(paths, trust_elicitation=trust_elicitation)
            return 0
        if arguments.command == "ui":
            if arguments.no_open != (arguments.launch_fd is not None):
                raise InvalidArgumentError("UI launch options must be paired")
            from memory.ui.app import run_ui

            return run_ui(
                paths,
                open_browser=not arguments.no_open,
                launch_fd=arguments.launch_fd,
            )
        if arguments.command == "approve":
            from memory.reviews import (
                approve_and_apply,
                get_change_set,
                render_change_set,
            )

            authorize_runtime_use(paths)
            try:
                replay = approve_and_apply(
                    paths,
                    arguments.change_set_id,
                    arguments.revision,
                    arguments.digest,
                    approval=None,
                )
            except OwnerApprovalRequiredError:
                replay = None
            if replay is not None:
                print(_application_output(replay, as_json=arguments.json))
                return 0
            view = get_change_set(paths, arguments.change_set_id)
            # The review goes to stderr and only the result to stdout. They are
            # two documents: one is what the owner reads before deciding, the
            # other is what happened. Mixed, a `--json` run is unparseable and
            # a piped run swallows the very diff the owner is about to approve;
            # split, the diff can be paged (`2>&1 >/dev/null | less`) while the
            # OS presence prompt and the result stay on the terminal.
            print(render_change_set(view), end="", file=sys.stderr)
            from memory.ui.owner_presence import (
                approve_with_cli_owner_presence,
            )

            print(
                _application_output(
                    approve_with_cli_owner_presence(
                        paths,
                        arguments.change_set_id,
                        arguments.revision,
                        arguments.digest,
                    ),
                    as_json=arguments.json,
                )
            )
            return 0
        if arguments.command == "reindex":
            from memory.maintenance import rebuild_search_projections

            authorize_runtime_use(paths)
            report = rebuild_search_projections(paths)
            print(
                json.dumps(
                    {
                        "memory_rows": report.memory_rows,
                        "source_rows": report.source_rows,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0
        if arguments.command == "lint":
            from memory.maintenance import lint_guards

            authorize_runtime_use(paths)
            # Stdout only: statements are personal content, so this never
            # writes a file.
            lint_report = lint_guards(paths)
            print(
                _lint_guards_json(lint_report)
                if arguments.json
                else _lint_guards_report(lint_report)
            )
            return 0
        if arguments.command == "status":
            from memory.sources import get_store_status

            authorize_runtime_use(paths)
            # The same record `store.status` serves, so the terminal and an
            # agent cannot disagree about whether this Store needs a reindex.
            # It is exactly the command an owner needs when the UI will not
            # start, so it must not depend on the UI to answer.
            print(_store_status_json(get_store_status(paths)))
            return 0
        if arguments.command == "reviews":
            authorize_runtime_use(paths)
            reviews_page, reviews_has_more = _pending_reviews(paths)
            print(_pending_reviews_json(reviews_page, reviews_has_more))
            return 0
        if arguments.command == "recover":
            from memory.inbox import recover_exact_staged_entries_with_issues
            from memory.sources import MAX_PAGE_SIZE

            authorize_runtime_use(paths)
            # Reconciliation otherwise runs only when the owner UI starts, so
            # an owner who works entirely over MCP never triggers it and an
            # interrupted correction capture stays staged indefinitely.
            recovered, issues = recover_exact_staged_entries_with_issues(
                paths,
                limit=MAX_PAGE_SIZE,
            )
            print(_recovery_json(recovered, issues))
            return 0
    except StoreError as error:
        _print_error(error)
        return 1
    raise AssertionError("argparse accepted an unknown command")


def _print_error(error: StoreError) -> None:
    """Report the code and, when the Store supplied them, the locators.

    `error.details` is the only place the Store names what to fix -- the
    revision an edit should have expected, the digest an approval should have
    carried, the sources a batch left unaccounted for. Printing the code alone
    turns an addressable refusal into a guess, and the CLI offers no verbose
    flag and writes no log, so a dropped detail is simply lost.

    Both lines go to stderr. Stdout carries exactly one document -- the
    command's result, as JSON under `--json` -- and a diagnostic in that
    stream would corrupt the successful shape exactly when a caller is
    handling failure.
    """
    print(f"memory: {error.code}", file=sys.stderr)
    if error.details:
        print(
            json.dumps(error.details, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )


def _stdio_server_argv(root: Path, *, trust_elicitation: bool = False) -> list[str]:
    """Name the arguments that serve this exact Store on stdio.

    `--home` appears only for a Store that is not on the default home, so the
    common install puts no filesystem path in a client's configuration file at
    all. This mirrors the rule the refused-apply approval handoff uses.
    `--trust-elicitation` appears only when the owner printed the entry with
    that opt-in, so the trusting server is always a choice the configuration
    file shows.
    """
    argv = ["mcp"]
    if root != default_root():
        # Absolute, because a client launches this entry from its own working
        # directory: a relative `--home` would name a different path there,
        # and would either refuse for a Store the owner just verified or find
        # a different one. The approval handoff can stay relative because it
        # is pasted back into the shell that produced it; this is not.
        argv.extend(("--home", str(root.resolve())))
    if trust_elicitation:
        argv.append("--trust-elicitation")
    return argv


def _mcp_config_block(
    root: Path, output_format: str, *, trust_elicitation: bool = False
) -> str:
    """Render this Store's stdio server entry in one client-neutral format.

    One entry, named for the server, and nothing around it. The key or table
    path a client files its servers under is that client's own schema, and the
    Store does not know or name it; the setup guide does. What the Store knows
    is the entry itself -- which command, which arguments, which transport --
    and that some clients read JSON while others read TOML.
    """
    argv = _stdio_server_argv(root, trust_elicitation=trust_elicitation)
    if output_format == "json":
        entry = {
            _MCP_SERVER_NAME: {
                "args": argv,
                "command": _MCP_COMMAND,
                "type": "stdio",
            }
        }
        return json.dumps(entry, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    arguments = ", ".join(_toml_string(argument) for argument in argv)
    return (
        f"[{_MCP_SERVER_NAME}]\n"
        f"command = {_toml_string(_MCP_COMMAND)}\n"
        f"args = [{arguments}]\n"
    )


def _toml_string(value: str) -> str:
    """Quote one TOML basic string, escaping everything the format forbids raw.

    A Store home is an owner-chosen path and may hold a quote, a backslash, or
    a control character; emitting it raw would produce a file that silently
    parses as a different command.
    """
    characters: list[str] = []
    for character in value:
        escape = _TOML_ESCAPES.get(character)
        if escape is not None:
            characters.append(escape)
        elif character < "\x20" or character == "\x7f":
            characters.append(f"\\u{ord(character):04X}")
        else:
            characters.append(character)
    return '"' + "".join(characters) + '"'


def _run_skill(command: str, target: Path) -> int:
    """Compare or install one named copy of this package's own Skill.

    Exit 0 means the copy carries the packaged contract, 1 means it is stale
    or absent, and 2 means the request was refused. The refusal names only a
    bounded code: the target is a path in the owner's client workspace, so
    neither it nor any filesystem message belongs on this stream.
    """
    source = skill_sync.packaged_skill_path()
    try:
        status = (
            skill_sync.check_skill(source=source, target=target)
            if command == "check"
            else skill_sync.install_skill(source=source, target=target)
        )
    except skill_sync.SkillSyncError as error:
        print(
            json.dumps({"error": error.code}, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return 2
    print(_skill_status_json(status))
    return 0 if status.status in ("current", "synced") else 1


def _skill_status_json(status: skill_sync.SkillSyncStatus) -> str:
    payload = {
        "byte_exact": status.byte_exact,
        "source_digest": status.source_digest,
        "status": status.status,
        "target_digest": status.target_digest,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _application_json(application: ApplicationResult) -> str:
    payload = {
        "application_id": application.application_id,
        "change_set_id": application.change_set_id,
        "idempotent_replay": application.idempotent_replay,
        "memory_ids": list(application.memory_ids),
        "revision_id": application.revision_id,
        "standing_guard_violations": [
            _guard_violation_json(violation)
            for violation in application.standing_guard_violations
        ],
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _application_output(application: ApplicationResult, *, as_json: bool) -> str:
    """Render one application result for whichever reader asked for it."""
    if as_json:
        return _application_json(application)
    return _application_report(application)


def _application_report(application: ApplicationResult) -> str:
    """Say in prose what the apply did, in the order the owner asks it.

    Whether anything changed comes first, because an idempotent replay and a
    fresh apply are indistinguishable from an exit code and differ in the one
    way the owner cares about.
    """
    memory_ids = list(application.memory_ids)
    counted = "Memory" if len(memory_ids) == 1 else "Memories"
    lines = [
        "Already applied; this run changed nothing."
        if application.idempotent_replay
        else "Applied.",
        f"  {'Memory Review':<15} {application.change_set_id}",
        f"  {'Revision':<15} {application.revision_id}",
        f"  {'Application':<15} {application.application_id}",
        f"  {counted:<15} {len(memory_ids)}",
        *(f"    {memory_id}" for memory_id in memory_ids),
        *_guard_violation_lines(application.standing_guard_violations, indent="  "),
    ]
    return "\n".join(lines)


def _guard_violation_lines(
    violations: Sequence[GuardViolation],
    *,
    indent: str,
) -> list[str]:
    """Name every standing violation, or say plainly that there is none.

    A guard never outranks its claim, and a violation this apply did not touch
    is reported rather than silently repaired -- so silence here would read as
    "none found" when it might only mean "not printed".
    """
    if not violations:
        return [f"{indent}Standing guard violations: none"]
    return [
        f"{indent}Standing guard violations: {len(violations)}",
        *(
            f"{indent}  guard {violation.guard_lineage_id} "
            f"({violation.guard_sensitivity.value}) outranks governed "
            f"{violation.governed_lineage_id} "
            f"({violation.governed_sensitivity.value})"
            for violation in violations
        ),
    ]


def _lint_guards_report(report: GuardLintReport) -> str:
    """Render the guard-repair report as the runbook's reader reads it.

    Statements first and identifiers under them: the owner judges a proposed
    pair by reading the two claims, and only then needs the lineages to hand
    to the agent building the change set.
    """
    truncated = report.truncated_candidate_count
    heading = (
        "Guard-link candidates: none"
        if not report.candidates
        else f"Guard-link candidates: {len(report.candidates)}"
    )
    if truncated:
        heading += (
            f" ({truncated} more qualified than one change set can carry; "
            "repair in more than one pass)"
        )
    lines = [heading]
    for ordinal, candidate in enumerate(report.candidates, start=1):
        lines.extend(
            (
                f"  {ordinal}. guard    {candidate.guard_statement}",
                f"     governs  {candidate.governed_statement}",
                f"     because  {', '.join(candidate.rationales)}",
                f"     guard lineage    {candidate.guard_lineage_id}",
                f"     governed lineage {candidate.governed_lineage_id}",
            )
        )
    lines.extend(_guard_violation_lines(report.standing_violations, indent=""))
    return "\n".join(lines)


def _guard_violation_json(violation: GuardViolation) -> dict[str, object]:
    return {
        "governed_lineage_id": violation.governed_lineage_id,
        "governed_sensitivity": violation.governed_sensitivity.value,
        "guard_lineage_id": violation.guard_lineage_id,
        "guard_sensitivity": violation.guard_sensitivity.value,
    }


def _guard_candidate_json(candidate: GuardCandidate) -> dict[str, object]:
    return {
        "governed_lineage_id": candidate.governed_lineage_id,
        "governed_statement": candidate.governed_statement,
        "guard_lineage_id": candidate.guard_lineage_id,
        "guard_statement": candidate.guard_statement,
        "rationales": list(candidate.rationales),
    }


def _store_status_json(status: StoreStatus) -> str:
    payload = {
        "mcp_contract_digest": status.mcp_contract_digest,
        "memory_count": status.memory_count,
        "pending_review_count": status.pending_review_count,
        "product": status.product,
        "product_version": status.product_version,
        "reindex_required": status.reindex_required,
        "schema_version": status.schema_version,
        "searchable_count": status.searchable_count,
        "skill_digest": status.skill_digest,
        "source_count": status.source_count,
        "store_id": status.store_id,
        "unsearchable_count": status.unsearchable_count,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _pending_reviews(
    paths: RuntimePaths,
) -> tuple[list[OwnerChangeSetSummary], bool]:
    """Read one bounded oldest-first page of draft reviews.

    The terminal listing has no cursor. ``has_more`` tells the owner to use
    the paginated Pending Reviews UI to enumerate the remainder.
    """
    from memory.review_reads import owner_list_change_sets
    from memory.sources import MAX_PAGE_SIZE, _read_connection

    with _read_connection(paths) as (connection, identity):
        page = owner_list_change_sets(
            connection,
            identity,
            cursor=None,
            limit=MAX_PAGE_SIZE,
            state="draft",
        )
        return list(page.items), page.has_more


def _pending_reviews_json(reviews: list[OwnerChangeSetSummary], has_more: bool) -> str:
    payload: dict[str, object] = {
        # Not `pending_review_count`: `store.status` and `memory status` carry
        # that key for the Store's true draft count, and this listing is one
        # bounded page. Two commands answering the same key with different
        # numbers is worse than one of them naming what it actually counted.
        "listed_review_count": len(reviews),
        "has_more": has_more,
        "reviews": [
            {
                "batch_id": review.batch_id,
                "change_set_id": review.change_set_id,
                "created_at": review.created_at,
                "current_adapter_origin": review.current_adapter_origin.value,
                "digest": review.current_digest,
                "item_count": review.item_count,
                "revision_id": review.current_revision_id,
                "unaccounted_source_count": review.unaccounted_source_count,
            }
            for review in reviews
        ],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _recovery_json(
    recovered: tuple[CapturedCorrection, ...],
    issues: Page[CaptureRecoveryIssue],
) -> str:
    payload = {
        "issues": [
            {
                "code": issue.code,
                "detected_at_ns": issue.detected_at_ns,
                "issue_id": issue.issue_id,
            }
            for issue in issues.items
        ],
        "issues_truncated": issues.has_more,
        "recovered": [
            {
                "batch_id": correction.batch_id,
                "expected_head_id": correction.expected_head_id,
                "lineage_id": correction.lineage_id,
                "source_id": correction.source_id,
            }
            for correction in recovered
        ],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _lint_guards_json(report: GuardLintReport) -> str:
    payload = {
        "candidates": [
            _guard_candidate_json(candidate) for candidate in report.candidates
        ],
        "standing_violations": [
            _guard_violation_json(violation) for violation in report.standing_violations
        ],
        "truncated_candidate_count": report.truncated_candidate_count,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess
    raise SystemExit(main())
