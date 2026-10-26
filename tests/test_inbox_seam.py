"""Guard the fault-injection seam `memory.inbox` is verified through.

The Inbox suites prove durability by replacing an attribute on the
`memory.inbox` module object and then crashing the process at a checkpoint.
That works for exactly one reason: every caller of the replaced name resolves
it in `memory.inbox`'s own globals. Move one of those callers into another
module and the patch still succeeds, still changes nothing, and the test still
passes -- proving nothing, silently, forever.

This is not hypothetical. It happened once in this repository: a rollback path
proof had a wrapper production never called and a test that patched it, and
the injection was inert from the day it was written. It was removed in
7dc9dbf. The guard below is what would have caught it.

Everything here derives its roster from the tests themselves. Nothing is
transcribed, because a hand-maintained list of what the tests patch is one
more thing that can quietly stop being true.
"""

from __future__ import annotations

import ast
import dis
import importlib
import pkgutil
import re
import types
from collections.abc import Iterator
from pathlib import Path

import memory

REPO_ROOT = Path(__file__).resolve().parents[1]
INBOX_SUITES = ("test_inbox.py", "test_ui_inbox.py", "test_inbox_observation.py")

#: Names a patched module other than `memory.inbox` is allowed to load.
#: `_writer_transaction` is defined in `memory.database` and used by
#: `writer_session` there; `memory.inbox` from-imports it and calls it bare,
#: which is the only reason patching it on `memory.inbox` reaches the Inbox
#: call site at all. That is a real coupling, and naming it here is the point:
#: it is the one place the seam already spans a module boundary.
ALLOWED_OTHER_MODULES: dict[str, frozenset[str]] = {
    "_writer_transaction": frozenset({"memory.database"}),
    # Public API. `memory.ui.service` calls it to capture an owner correction,
    # and no test patches `memory.inbox` expecting to intercept that call --
    # the one injection aimed at this name drives `recover_exact_staged_entries`,
    # which is inbox-internal. Listed rather than exempted by a rule about
    # leading underscores, so that a second consumer has to be reviewed too.
    "capture_exact_staged_entry": frozenset({"memory.ui.service"}),
}

#: `inbox.os.fsync = ...` reaches through to the real `os` module rather than
#: rebinding an inbox attribute, so it is not part of this seam.
_NOT_AN_INBOX_ATTRIBUTE = frozenset({"os"})

_BARE_ASSIGNMENT = re.compile(r"^\s*inbox[_a-z]*\.(\w+)\s*=(?!=)", re.MULTILINE)


def _patched_names() -> dict[str, int]:
    """Return every `memory.inbox` attribute the Inbox suites replace, with counts.

    Three forms are in use and all three must be found: a `monkeypatch.setattr`
    call, a bare assignment at test scope, and a bare assignment inside a
    string literal -- the subprocess templates that run in a fresh interpreter,
    which no linter or type checker reads.
    """
    found: dict[str, int] = {}

    def record(name: str) -> None:
        if name not in _NOT_AN_INBOX_ATTRIBUTE:
            found[name] = found.get(name, 0) + 1

    for suite in INBOX_SUITES:
        source = (REPO_ROOT / "tests" / suite).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=suite)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and "inbox" in node.args[0].id
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                record(node.args[1].value)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                for match in _BARE_ASSIGNMENT.finditer(node.value):
                    record(match.group(1))
        for match in _BARE_ASSIGNMENT.finditer(source):
            record(match.group(1))
    return found


def _memory_modules() -> Iterator[types.ModuleType]:
    yield memory
    for info in pkgutil.walk_packages(memory.__path__, prefix="memory."):
        yield importlib.import_module(info.name)


def _global_loads(module: types.ModuleType) -> set[str]:
    """Return every global name the code defined in this module reads.

    LOAD_GLOBAL specifically, not `co_names`: the latter also lists attribute
    names, which would report a hit for any `something._checkpoint` anywhere.
    """
    loaded: set[str] = set()

    def walk(code: types.CodeType) -> None:
        for instruction in dis.get_instructions(code):
            if instruction.opname == "LOAD_GLOBAL" and isinstance(
                instruction.argval, str
            ):
                loaded.add(instruction.argval)
        for constant in code.co_consts:
            if isinstance(constant, types.CodeType):
                walk(constant)

    for value in vars(module).values():
        code = getattr(value, "__code__", None)
        if code is not None and getattr(value, "__module__", None) == module.__name__:
            walk(code)
        elif isinstance(value, type) and value.__module__ == module.__name__:
            for member in vars(value).values():
                member_code = getattr(member, "__code__", None)
                if member_code is not None:
                    walk(member_code)
    return loaded


def test_the_inbox_suites_patch_names_that_exist() -> None:
    """Catch a fault injection aimed at a name `memory.inbox` does not have.

    `monkeypatch.setattr` raises on a missing attribute, but the subprocess
    templates assign bare inside a string and can never raise at all -- a typo
    there creates an unused attribute and a test that proves nothing.
    """
    import memory.inbox

    patched = _patched_names()

    assert patched, "no fault injections found; the derivation is broken"
    assert [name for name in patched if not hasattr(memory.inbox, name)] == []


def test_every_fault_injected_name_is_called_only_from_memory_inbox() -> None:
    """Catch a caller of a patched name moving out of `memory.inbox`.

    A patch on the module object reaches only call sites that resolve the name
    in that module's globals. If any other module reads one of these names as a
    global, every injection aimed at it is inert for that module's call sites,
    and the suite goes green anyway. That is the failure this exists to make
    impossible.

    It is also the precondition for ever splitting this file: until this passes
    and keeps passing, moving a definition out of `memory.inbox` cannot be
    distinguished from moving the proof out with it.
    """
    patched = set(_patched_names())
    holders: dict[str, set[str]] = {name: set() for name in patched}
    for module in _memory_modules():
        for name in _global_loads(module) & patched:
            holders[name].add(module.__name__)

    offenders = {
        name: sorted(
            modules - {"memory.inbox"} - ALLOWED_OTHER_MODULES.get(name, frozenset())
        )
        for name, modules in holders.items()
    }

    assert {name: mods for name, mods in offenders.items() if mods} == {}


#: Crash windows a test kills the process at. Each of these is named by an
#: Inbox suite that crashes there and then asserts what the Store looks like.
EXERCISED_CHECKPOINTS = frozenset(
    {
        "scan.observation_complete",
        "scan.progress_commit",
        "scan.roster_chunk_commit",
        "scan.roster_publish_commit",
        "scan.roster_consume_commit",
        "scan.roster_cleanup_commit",
        "claim.capture.manifest_dir_fsync",
        "claim.capture.manifest_file_fsync",
        "claim.capture.manifest_replace",
        "claim.cleanup.claim_dir_fsync_after_files",
        "claim.cleanup.claim_dir_fsync_after_manifest",
        "claim.cleanup.claims_dir_fsync",
        "claim.cleanup.files_dir_fsync",
        "claim.cleanup.files_rmdir",
        "claim.cleanup.hide_rename",
        "claim.cleanup.manifest_unlink",
        "claim.cleanup.source_unlink",
        "claim.create.files_mkdir",
        "claim.create.files_parent_fsync",
        "claim.create.manifest_dir_fsync",
        "claim.create.manifest_file_fsync",
        "claim.create.manifest_replace",
        "claim.create.publish_dir_fsync",
        "claim.create.publish_rename",
        "claim.create.temp_mkdir",
        "claim.create.temp_parent_fsync",
        "claim.custody.files_dir_fsync",
        "claim.custody.inbox_dir_fsync",
        "claim.custody.manifest_dir_fsync",
        "claim.custody.manifest_file_fsync",
        "claim.custody.manifest_replace",
        "claim.custody.source_rename",
        "correction.handoff_existing_directory_fsync",
        "correction.handoff_payload_directory_fsync",
        "correction.handoff_payload_file_fsync",
        "exact.bound_manifest_publish",
        "exact.claim.manifest_dir_fsync",
        "exact.claim.manifest_file_fsync",
        "exact.claim.manifest_replace",
        "exact.claim_files_directory_fsync",
        "exact.claim_manifest_publication",
        "exact.claim_temp_mkdir",
        "exact.cleanup_directory_fsync",
        "exact.custody.manifest_dir_fsync",
        "exact.custody.manifest_file_fsync",
        "exact.custody.manifest_replace",
        "exact.database_commit",
        "exact.incomplete_before_quarantine_rename",
        "exact.incomplete_quarantine_rename",
        "exact.intent_cleanup_directory_fsync",
        "exact.intent_manifest_directory_fsync",
        "exact.intent_manifest_file_fsync",
        "exact.intent_manifest_publish",
        "exact.intent_recovery_directory_fsync",
        "exact.payload_before_file_fsync",
        "exact.payload_directory_fsync",
        "exact.payload_empty_directory_fsync",
        "exact.payload_empty_file_fsync",
        "exact.payload_file_fsync",
        "exact.ready_manifest_directory_fsync",
        "exact.ready_manifest_file_fsync",
        "exact.ready_manifest_publish",
        "exact.ready_manifest_recovery_directory_fsync",
        "exact.recovery_payload_before_file_fsync",
        "exact.recovery_payload_directory_fsync",
        "exact.recovery_payload_file_fsync",
        "exact.staged_to_claim_move",
        "staging.directory_fsync",
        "staging.file_fsync",
        "staging.prepublication_before_cleanup",
        "staging.prepublication_before_descriptor_drain",
        "staging.prepublication_cleanup_directory_fsync",
        "staging.publication_anchor_directory_fsync",
        "staging.publication_slot_record_file_fsync",
        "staging.publication_slot_record_publish",
        "staging.publish_before_rollback",
        "staging.publish_before_rollback_quarantine",
        "staging.publish_directories_fsync",
        "staging.publish_inbox_directory_fsync",
        "staging.publish_rename",
        "staging.publish_rollback_quarantine",
        "staging.publish_staging_directory_fsync",
        "staging.recovery_manifest_directory_fsync",
        "staging.recovery_manifest_file_fsync",
        "staging.recovery_manifest_publish",
        "staging.recovery_manifest_verified_directory_fsync",
        "staging.withdrawal_child_recycled",
        "staging.withdrawal_directory_fsync",
        "staging.withdrawal_directory_rollback_fsync",
    }
)

#: New untested durability windows must be explicitly admitted here.
#: Every previously admitted window now has a process-death recovery regression.
UNEXERCISED_CHECKPOINTS: frozenset[str] = frozenset()

#: Crash windows a test proves are reached, but never kills the process at.
#: `test_anchor_mismatch_cannot_short_circuit_publication_withdrawal` records
#: both rollback barriers and asserts they fired; that is weaker than crashing
#: between them, and counting it as exercised would overstate the coverage the
#: set above claims.
OBSERVED_CHECKPOINTS = frozenset(
    {
        "exact.bound_manifest_directory_fsync",
        "exact.bound_manifest_file_fsync",
        "staging.rollback_inbox_directory_fsync",
        "staging.rollback_staging_directory_fsync",
    }
)

#: Emitters that take their name from the caller rather than writing it out:
#: `_publish_manifest_bytes` reads its three from a `checkpoints=` tuple. They
#: are resolved from those call sites, not from the emitter, so the emitter
#: itself is expected to be unresolvable and is listed here. Anything else
#: unresolvable fails the inventory rather than vanishing from it -- an
#: unreadable crash window is the one that gets forgotten.
CALLER_SUPPLIED_EMITTERS = ("checkpoints[0]", "checkpoints[1]", "checkpoints[2]")


def _string_values(node: ast.expr) -> set[str] | None:
    """Every literal string one expression can evaluate to, or None if unknown."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        taken, other = _string_values(node.body), _string_values(node.orelse)
        return None if taken is None or other is None else taken | other
    return None


def _keyword_literals(tree: ast.Module) -> dict[str, dict[str, set[str]]]:
    """Literal keyword values seen at every call site, by callee and parameter."""
    seen: dict[str, dict[str, set[str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            for keyword in node.keywords:
                values = None if keyword.arg is None else _string_values(keyword.value)
                if keyword.arg is not None and values:
                    seen.setdefault(node.func.id, {}).setdefault(
                        keyword.arg, set()
                    ).update(values)
    return seen


def _enclosing_function(tree: ast.Module, node: ast.expr) -> ast.FunctionDef | None:
    innermost: ast.FunctionDef | None = None
    for candidate in ast.walk(tree):
        if not isinstance(candidate, ast.FunctionDef):
            continue
        ends = candidate.end_lineno
        if ends is None or not candidate.lineno <= node.lineno <= ends:
            continue
        if innermost is None or candidate.lineno > innermost.lineno:
            innermost = candidate
    return innermost


def _local_string_values(
    function: ast.FunctionDef | None,
    name: str,
    keywords: dict[str, dict[str, set[str]]],
) -> set[str]:
    """Resolve one local name to the literal strings it can hold.

    Three shapes appear in `inbox.py`: a plain assignment, iteration over a
    tuple of pairs (directly or through a local holding one), and a parameter
    the callers pass literally.
    """
    if function is None:
        return set()
    found: set[str] = set()
    tuples: dict[str, ast.Tuple] = {
        target.id: node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            found |= _string_values(node.value) or set()
        if isinstance(node, ast.For):
            target = node.target
            bound = (
                [target.id]
                if isinstance(target, ast.Name)
                else [
                    element.id
                    for element in getattr(target, "elts", [])
                    if isinstance(element, ast.Name)
                ]
            )
            if name not in bound:
                continue
            position = bound.index(name)
            iterated = node.iter
            if isinstance(iterated, ast.Name):
                iterated = tuples.get(iterated.id, iterated)
            if not isinstance(iterated, ast.Tuple):
                continue
            for element in iterated.elts:
                item = (
                    element.elts[position]
                    if isinstance(element, ast.Tuple)
                    else element
                )
                found |= _string_values(item) or set()
    return found or keywords.get(function.name, {}).get(name, set())


def _resolve(
    tree: ast.Module,
    node: ast.expr,
    keywords: dict[str, dict[str, set[str]]],
) -> tuple[set[str], list[str]]:
    """Expand one checkpoint-name expression into every name it can emit."""
    direct = _string_values(node)
    if direct:
        return direct, []
    if isinstance(node, ast.Name):
        values = _local_string_values(
            _enclosing_function(tree, node), node.id, keywords
        )
        return (values, []) if values else (set(), [ast.unparse(node)])
    if isinstance(node, ast.JoinedStr):
        built = {""}
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                built = {prefix + piece.value for prefix in built}
            elif isinstance(piece, ast.FormattedValue) and isinstance(
                piece.value, ast.Name
            ):
                values = _local_string_values(
                    _enclosing_function(tree, node), piece.value.id, keywords
                )
                if not values:
                    return set(), [ast.unparse(node)]
                built = {prefix + value for prefix in built for value in values}
            else:
                return set(), [ast.unparse(node)]
        return built, []
    return set(), [ast.unparse(node)]


def _checkpoint_names() -> tuple[set[str], list[str]]:
    """Every crash-window name `inbox.py` can emit, and anything unreadable.

    Two sources, because the shared manifest publisher takes its checkpoints
    as an argument: direct `_checkpoint(...)` calls, and the `checkpoints=`
    tuples its callers pass. Reading only the first is how this guard was
    wrong before -- it saw 56 of 87 names and reported the number as complete.
    """
    source = (REPO_ROOT / "src" / "memory" / "inbox.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename="inbox.py")
    keywords = _keyword_literals(tree)
    names: set[str] = set()
    unresolved: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_checkpoint"
            and node.args
        ):
            found, missing = _resolve(tree, node.args[0], keywords)
            names |= found
            unresolved += missing
        if (
            isinstance(node, ast.keyword)
            and node.arg == "checkpoints"
            and isinstance(node.value, ast.Tuple)
        ):
            for element in node.value.elts:
                found, missing = _resolve(tree, element, keywords)
                names |= found
                unresolved += missing
    return names, unresolved


def test_every_crash_checkpoint_is_inventoried() -> None:
    """Catch a new crash window nobody decided about.

    A `_checkpoint` call is a point at which a test can kill the process, so
    adding one silently adds a durability question the suite does not ask.
    This forces the answer to be written down either way: exercised, or
    admitted as debt. Names reached through a `checkpoints=` tuple or an
    interpolated stage count exactly like written-out ones -- the earlier
    version of this test read only literal calls, saw 56 of 87 names, and
    stated the number as complete.
    """
    names, unresolved = _checkpoint_names()

    assert names == (
        EXERCISED_CHECKPOINTS | OBSERVED_CHECKPOINTS | UNEXERCISED_CHECKPOINTS
    )
    assert not (EXERCISED_CHECKPOINTS & UNEXERCISED_CHECKPOINTS)
    assert not (EXERCISED_CHECKPOINTS & OBSERVED_CHECKPOINTS)
    assert not (OBSERVED_CHECKPOINTS & UNEXERCISED_CHECKPOINTS)
    assert unresolved == list(CALLER_SUPPLIED_EMITTERS)


def test_the_exercised_checkpoints_are_actually_named_by_a_test() -> None:
    """Catch a checkpoint moving to the exercised set without a test naming it."""
    suites = "".join(
        (REPO_ROOT / "tests" / suite).read_text(encoding="utf-8")
        for suite in INBOX_SUITES
    )

    named = EXERCISED_CHECKPOINTS | OBSERVED_CHECKPOINTS
    assert [name for name in named if name not in suites] == []
    assert [name for name in UNEXERCISED_CHECKPOINTS if name in suites] == []
