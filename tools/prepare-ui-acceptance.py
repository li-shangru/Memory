#!/usr/bin/env python3
"""Prepare one deterministic installed local-owner-UI acceptance runtime.

This tool is development tooling. It is excluded from the wheel, it never
imports the source checkout, and it drives only the public installed CLI and
MCP surface of one explicit disposable synthetic Store.

Every case payload, expected mapping, filename, byte length, and conclusion
comes from the reviewed ``tests/fixtures/synthetic_ui/manifest.yaml``. This file
contains no case-specific conclusion of its own.

Owner approval is never automated here: at each pause the tool spawns the exact
validated installed ``memory approve`` command and waits for the operating system
to make the decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

MANIFEST_SCHEMA = "memory.synthetic-ui-acceptance.v1"
STATE_SCHEMA = "memory.ui-acceptance-state.v1"
STATE_FILENAME = "memory-ui-acceptance-state.json"
UPLOAD_CASE = "SYN-UI-UPLOAD-001"
REVIEW_CASE = "SYN-UI-REVIEW-002"
LINEAGE_CASE = "SYN-UI-LINEAGE-003"
CORRECTION_CASE = "SYN-UI-CORRECTION-004"
EXPECTED_CASES = (UPLOAD_CASE, REVIEW_CASE, LINEAGE_CASE, CORRECTION_CASE)
EXPECTED_KINDS = {
    UPLOAD_CASE: "ordinary_upload",
    REVIEW_CASE: "review_repair",
    LINEAGE_CASE: "two_revision_lineage",
    CORRECTION_CASE: "owner_correction",
}
TASK_CASES = (UPLOAD_CASE, CORRECTION_CASE)
CLIENT_KINDS = ("codex", "claude")
CLIENT_VERSION_PATTERNS = {
    "codex": re.compile(r"codex(?:-cli)? \d+\.\d+\.\d+.*"),
    "claude": re.compile(r"\d+\.\d+\.\d+.*\(Claude Code\)"),
}
CLIENT_SKILL_DIRECTORIES = {
    "codex": Path(".agents") / "skills" / "using-memory",
    "claude": Path(".claude") / "skills" / "using-memory",
}
STORE_ID = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
IDENTITY_KEYS = frozenset(
    {
        "inbox_path",
        "product",
        "runtime_mode",
        "schema_lineage",
        "schema_version",
        "store_id",
    }
)
UPLOAD_TASK_PROMPT = """\
Use the using-memory Skill and only the synthetic Store MCP that
this run configured. Do not inspect local files and do not read any manifest.

Call store.status and report its counts. Then call the generic inbox.scan tool
exactly once and report the returned batch identifier and its source count. Do
not create, review, or apply any memory. Do not save an answer, transcript, or
report.
"""
CORRECTION_TASK_PROMPT = """\
Use the using-memory Skill and only the synthetic Store MCP that
this run configured. Do not inspect local files and do not read any manifest.

An owner correction batch is already sealed with this exact identifier:
{batch_id}

Do not scan the inbox. Call inbox.read for exactly that batch, read its sole
source through completion, then create the single change set for only that
batch. Preserve the captured target lineage and expected head. Present the
complete diff, revision, and digest, then call change_set.approve_and_apply once
with only those exact values. If the result is owner_approval_required, report
that nothing was applied and stop. Finally retrieve the resulting memory and
verify its immutable source evidence. Do not save an answer, transcript, or
report.
"""


class AcceptanceError(Exception):
    """One content-free installed-acceptance failure."""


def parse_strict_json(raw: bytes) -> Any:
    """Parse one reviewed document, refusing any duplicated mapping key."""

    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise AcceptanceError("manifest contains a duplicated key")
            seen[key] = value
        return seen

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except AcceptanceError:
        raise
    except (UnicodeDecodeError, ValueError) as error:
        raise AcceptanceError("manifest is not a strict document") from error


@dataclass(frozen=True, slots=True)
class Manifest:
    """The reviewed acceptance manifest and the digest bound to this run."""

    path: Path
    digest: str
    schema: str
    version: int
    cases: dict[str, Any]


def _require(payload: Any, key: str, message: str) -> Any:
    if not isinstance(payload, Mapping) or key not in payload:
        raise AcceptanceError(message)
    return payload[key]


def _require_text(payload: Any, key: str) -> str:
    value = _require(payload, key, f"manifest field {key} is missing")
    if not isinstance(value, str) or not value:
        raise AcceptanceError(f"manifest field {key} is invalid")
    return value


def _validate_artifact(artifact: Any, label: str) -> None:
    content = _require_text(artifact, "utf8_content")
    filename = _require_text(artifact, "filename")
    if "/" in filename or filename.startswith("."):
        raise AcceptanceError(f"{label} filename is unsafe")
    encoded = content.encode("utf-8")
    if _require(artifact, "byte_length", f"{label} byte length is missing") != len(
        encoded
    ):
        raise AcceptanceError(f"{label} byte length does not match its content")
    if _require_text(artifact, "sha256") != hashlib.sha256(encoded).hexdigest():
        raise AcceptanceError(f"{label} digest does not match its content")
    _require_text(artifact, "media_type")


def _validate_memory(memory: Any, label: str, sources: frozenset[str]) -> None:
    for key in (
        "kind",
        "statement",
        "occurred_on",
        "valid_from",
        "valid_to",
        "tags",
        "sensitivity",
        "change_kind",
        "target_lineage_ref",
        "expected_head_ref",
    ):
        _require(memory, key, f"{label} field {key} is missing")
    evidence = _require(memory, "evidence", f"{label} evidence is missing")
    if not isinstance(evidence, list) or not evidence:
        raise AcceptanceError(f"{label} evidence is invalid")
    for locator in evidence:
        _require_text(locator, "excerpt")
        if "source_alias" in locator:
            if locator["source_alias"] not in sources:
                raise AcceptanceError(f"{label} evidence names an unknown source")
        elif _require_text(locator, "source_ref") not in sources:
            raise AcceptanceError(f"{label} evidence names an unknown source")


def _validate_review_case(case: Any) -> None:
    declared = _require(case, "sources", "review case declares no source")
    if not isinstance(declared, list) or len(declared) != 2:
        raise AcceptanceError("review case must declare exactly two sources")
    aliases: list[str] = []
    for source in declared:
        aliases.append(_require_text(source, "alias"))
        _validate_artifact(source, "review source")
    if len(set(aliases)) != len(aliases):
        raise AcceptanceError("review case reuses a source alias")
    known = frozenset(aliases)

    initial = _require(case, "initial_review", "review case declares no initial review")
    decisions = _require(initial, "source_decisions", "initial decisions are missing")
    items = _require(initial, "items", "initial items are missing")
    if not isinstance(decisions, list) or not isinstance(items, list) or not items:
        raise AcceptanceError("initial review is invalid")
    for decision in decisions:
        if _require_text(decision, "source_alias") not in known:
            raise AcceptanceError("initial decision names an unknown source")
        if _require_text(decision, "state") not in {"used", "no_memory"}:
            raise AcceptanceError("initial decision state is invalid")
    item_aliases = set()
    for item in items:
        item_aliases.add(_require_text(item, "item_alias"))
        _require_text(item, "client_item_id")
        _validate_memory(item, "initial item", known)

    operations = _require(case, "repair_operations", "repair operations are missing")
    if not isinstance(operations, list) or len(operations) != 3:
        raise AcceptanceError("repair operations must be an exact ordered list")
    repaired_aliases = set(item_aliases)
    for operation in operations:
        name = _require_text(operation, "operation")
        _require_text(operation, "expected_revision_ref")
        if name == "replace_item":
            if _require_text(operation, "item_ref") not in repaired_aliases:
                raise AcceptanceError("repair operation names an unknown item")
        elif name == "clear_source_no_memory":
            if _require_text(operation, "source_alias") not in known:
                raise AcceptanceError("repair operation names an unknown source")
        elif name == "add_item":
            repaired_aliases.add(_require_text(operation, "item_alias"))
        else:
            raise AcceptanceError("repair operation is unsupported")

    expected = _require(case, "expected_owner_repair", "expected repair is missing")
    for key in (
        "final_revision_ref",
        "adapter_origin_for_each_operation",
        "lifecycle_before_approval",
        "lifecycle_after_approval",
    ):
        _require_text(expected, key)
    final_decisions = _require(
        expected, "source_decisions", "expected decisions are missing"
    )
    if {
        _require_text(decision, "source_alias") for decision in final_decisions
    } != known:
        raise AcceptanceError("expected repair omits a declared source")
    final_items = _require(expected, "items", "expected items are missing")
    if not isinstance(final_items, list) or len(final_items) != 2:
        raise AcceptanceError("expected repair must account for both items")
    for item in final_items:
        reference = item.get("item_ref") or item.get("item_alias")
        if reference not in repaired_aliases:
            raise AcceptanceError("expected repair names an unknown item")
        _validate_memory(item, "expected item", known)


def _validate_lineage_case(case: Any) -> None:
    for role in ("historical", "current"):
        section = _require(case, role, f"lineage case omits its {role} revision")
        _require(section, "agent_scan", f"lineage {role} scan policy is missing")
        _validate_artifact(
            _require(section, "source", f"lineage {role} source is missing"),
            f"lineage {role} source",
        )
        _validate_memory(
            _require(section, "memory", f"lineage {role} memory is missing"),
            f"lineage {role} memory",
            frozenset({"historical.source", "current.source"}),
        )
    current = case["current"]["memory"]
    for key in ("target_lineage_ref", "expected_head_ref", "predecessor_ref"):
        if (
            _require_text(current, key)
            != {
                "target_lineage_ref": "historical.memory.lineage_id",
                "expected_head_ref": "historical.memory.revision_id",
                "predecessor_ref": "historical.memory.revision_id",
            }[key]
        ):
            raise AcceptanceError("lineage successor reference is unresolvable")


def _validate_correction_case(case: Any, cases: Mapping[str, Any]) -> None:
    target = _require_text(case, "target_case_id")
    if target not in cases:
        raise AcceptanceError("correction case names an unknown target case")
    if _require_text(case, "selected_revision") not in {"historical", "current"}:
        raise AcceptanceError("correction case selects an unknown revision")
    _require_text(case, "correction_text")
    expected = _require(case, "expected_successor", "expected successor is missing")
    cardinality = _require(
        expected, "review_cardinality", "successor cardinality is missing"
    )
    for key in (
        "active_items",
        "rejected_items",
        "used_source_decisions",
        "no_memory_source_decisions",
        "applications",
        "applied_memories",
        "require_no_extra_items_or_memories",
    ):
        _require(cardinality, key, f"successor cardinality field {key} is missing")
    for key in ("target_lineage_ref", "expected_head_ref", "predecessor_ref"):
        if not _require_text(expected, key).startswith(f"{target}."):
            raise AcceptanceError("successor reference does not resolve to its target")
    _require(expected, "evidence", "successor evidence is missing")
    _require_text(expected, "statement")


def load_manifest(path: Path) -> Manifest:
    """Validate the reviewed manifest completely and bind it to its digest."""
    if not path.is_file():
        raise AcceptanceError("acceptance manifest is missing")
    raw = path.read_bytes()
    payload = parse_strict_json(raw)
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema",
        "manifest_version",
        "cases",
    }:
        raise AcceptanceError("manifest structure is invalid")
    if payload["schema"] != MANIFEST_SCHEMA:
        raise AcceptanceError("manifest schema is unsupported")
    if payload["manifest_version"] != 1:
        raise AcceptanceError("manifest version is unsupported")
    declared = payload["cases"]
    if not isinstance(declared, list):
        raise AcceptanceError("manifest cases are invalid")
    identifiers = tuple(_require_text(case, "case_id") for case in declared)
    if identifiers != EXPECTED_CASES:
        raise AcceptanceError("manifest roster is not the reviewed four-case roster")
    cases = dict(zip(identifiers, declared, strict=True))
    for case_id, case in cases.items():
        if _require_text(case, "kind") != EXPECTED_KINDS[case_id]:
            raise AcceptanceError("manifest case kind is unexpected")
    _validate_artifact(
        _require(cases[UPLOAD_CASE], "artifact", "upload artifact is missing"),
        "upload artifact",
    )
    for key in ("expected_before_scan", "expected_after_one_agent_scan"):
        _require(cases[UPLOAD_CASE], key, f"upload case field {key} is missing")
    _validate_review_case(cases[REVIEW_CASE])
    _validate_lineage_case(cases[LINEAGE_CASE])
    _validate_correction_case(cases[CORRECTION_CASE], cases)
    return Manifest(
        path=path,
        digest=hashlib.sha256(raw).hexdigest(),
        schema=MANIFEST_SCHEMA,
        version=1,
        cases=cases,
    )


def validate_absolute_executable(candidate: Path) -> Path:
    """Require one absolute, regular, executable command; never a PATH lookup."""
    if not isinstance(candidate, Path) or not candidate.is_absolute():
        raise AcceptanceError("executable path must be absolute")
    if not candidate.exists():
        raise AcceptanceError("executable path does not exist")
    resolved = candidate.resolve()
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise AcceptanceError("executable path is not a regular file")
    if not os.access(resolved, os.X_OK):
        raise AcceptanceError("executable path is not executable")
    return resolved


def _home_needs_initialization(candidate: Path) -> bool:
    """Report whether `memory init` should run for this absent-or-empty target.

    `memory init --home PATH` accepts a target that is absent or empty,
    so the preparer accepts the same two starting states instead of demanding a
    path the owner has not created yet.
    """
    if not candidate.exists():
        return True
    if candidate.is_symlink() or not candidate.is_dir():
        return False
    try:
        return not any(candidate.iterdir())
    except OSError:
        return False


def validate_store_home(candidate: Path) -> str:
    """Require one initialized disposable synthetic runtime; never the default."""
    if not isinstance(candidate, Path) or not candidate.is_absolute():
        raise AcceptanceError("Store home must be an absolute path")
    if candidate.is_symlink() or not candidate.is_dir():
        raise AcceptanceError("Store home is not a directory")
    identity_path = candidate / "runtime.json"
    if identity_path.is_symlink() or not identity_path.is_file():
        raise AcceptanceError(
            "Store home is not an initialized Store; --home must be absent or empty"
        )
    try:
        payload = json.loads(identity_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise AcceptanceError("Store identity is unreadable") from error
    if not isinstance(payload, Mapping) or set(payload) != IDENTITY_KEYS:
        raise AcceptanceError("Store identity is incomplete")
    store_id = payload["store_id"]
    if (
        payload["product"] != "memory"
        or payload["runtime_mode"] != "personal"
        or payload["schema_lineage"] != "memory-store-v1"
        or payload["schema_version"] != 1
        or not isinstance(store_id, str)
        or STORE_ID.fullmatch(store_id) is None
    ):
        raise AcceptanceError("Store identity is not a Memory Store")
    return store_id


def validate_state_root(candidate: Path) -> Path:
    """Require one existing private temporary directory for ephemeral state."""
    if not isinstance(candidate, Path) or not candidate.is_absolute():
        raise AcceptanceError("state root must be an absolute path")
    if candidate.is_symlink() or not candidate.is_dir():
        raise AcceptanceError("state root is not a directory")
    base = Path(tempfile.gettempdir()).resolve()
    resolved = candidate.resolve()
    if not resolved.is_relative_to(base):
        raise AcceptanceError("state root is outside the temporary base")
    return resolved


@dataclass(frozen=True, slots=True)
class Preparation:
    """One validated installed command, synthetic runtime, and manifest binding."""

    memory: Path
    home: Path
    manifest: Manifest
    state_root: Path

    @property
    def state_path(self) -> Path:
        return self.state_root / STATE_FILENAME


@dataclass(frozen=True, slots=True)
class Prepared:
    """The completed preparation and the state the acceptance run consumes."""

    preparation: Preparation
    state: dict[str, Any]
    applied: tuple[tuple[str, str, str], ...] = ()


@dataclass(slots=True)
class StoreClient:
    """A minimal newline-delimited JSON-RPC client for the installed MCP."""

    memory: Path
    home: Path
    _process: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _next_id: int = field(default=0, init=False)

    def __enter__(self) -> StoreClient:
        self._process = subprocess.Popen(
            [str(self.memory), "mcp", "--home", str(self.home)],
            close_fds=True,
            cwd=str(self.home),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "memory-ui-acceptance", "version": "1"},
            },
        )
        self._notify("notifications/initialized", {})
        return self

    def __exit__(self, *_exception: object) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=20)
        if process.stdout is not None:
            process.stdout.close()

    def _write(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise AcceptanceError("the installed Store MCP is unavailable")
        payload = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        process.stdin.write(payload)
        process.stdin.flush()

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        process = self._process
        if process is None or process.stdout is None:
            raise AcceptanceError("the installed Store MCP is unavailable")
        self._next_id += 1
        identifier = self._next_id
        self._write(
            {
                "jsonrpc": "2.0",
                "id": identifier,
                "method": method,
                "params": params,
            }
        )
        while True:
            line = process.stdout.readline()
            if not line:
                raise AcceptanceError("the installed Store MCP closed its transport")
            message = json.loads(line.decode("utf-8"))
            if message.get("id") != identifier:
                continue
            if "error" in message:
                raise AcceptanceError(
                    "the installed Store MCP returned a transport error"
                )
            result = message.get("result")
            if not isinstance(result, dict):
                raise AcceptanceError("the installed Store MCP returned no result")
            return result

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one public Store operation and return its exact envelope."""
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        envelope = result.get("structuredContent")
        if not isinstance(envelope, dict):
            raise AcceptanceError("the Store operation returned no structured result")
        if "error" in envelope:
            code = envelope["error"].get("code", "unknown")
            raise AcceptanceError(f"the Store operation failed: {code}")
        return envelope


def _spawn_owner_approval(
    memory: Path,
    home: Path,
    change_set_id: str,
    revision_id: str,
    digest: str,
) -> None:
    """Spawn the validated installed approval command for one exact revision.

    The macOS operating system owns the decision. Nothing in this tool
    automates or bypasses it, and neither the command nor its path is printed.
    """
    print(
        "Complete the macOS owner-presence prompt for the displayed revision.",
        flush=True,
    )
    completed = subprocess.run(
        [
            str(memory),
            "approve",
            change_set_id,
            "--revision",
            revision_id,
            "--digest",
            digest,
            "--home",
            str(home),
        ],
        check=False,
        close_fds=True,
        cwd=str(home),
    )
    if completed.returncode != 0:
        raise AcceptanceError("owner approval did not complete")


def _visible_inbox_entries(home: Path) -> list[str]:
    inbox = home / "inbox"
    if not inbox.is_dir():
        raise AcceptanceError("synthetic Inbox directory is missing")
    return sorted(entry.name for entry in inbox.iterdir() if entry.is_file())


def _require_empty_inbox(home: Path) -> None:
    if _visible_inbox_entries(home):
        raise AcceptanceError("the visible Inbox was not empty at a phase boundary")


def _stage(home: Path, filename: str, content: str) -> None:
    target = home / "inbox" / filename
    if target.exists():
        raise AcceptanceError("a staged acceptance fixture already exists")
    target.write_bytes(content.encode("utf-8"))


def _memory_arguments(
    memory: Mapping[str, Any],
    *,
    target_lineage_id: str | None,
    expected_head_id: str | None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "kind": memory["kind"],
        "statement": memory["statement"],
        "sensitivity": memory["sensitivity"],
        "tags": list(memory["tags"]),
    }
    for key in ("occurred_on", "valid_from", "valid_to"):
        if memory[key] is not None:
            fields[key] = memory[key]
    if target_lineage_id is not None:
        fields["target_lineage_id"] = target_lineage_id
        fields["expected_head_id"] = expected_head_id
    return fields


def _evidence_arguments(
    memory: Mapping[str, Any],
    digests: Mapping[str, tuple[str, str]],
    resolve: Any,
) -> list[dict[str, Any]]:
    locators = []
    for locator in memory["evidence"]:
        key = resolve(locator)
        source_id, blob_digest = digests[key]
        locators.append(
            {
                "source_id": source_id,
                "blob_digest": blob_digest,
                "excerpt": locator["excerpt"],
            }
        )
    return locators


def _batch_sources(client: StoreClient, batch_id: str) -> list[dict[str, Any]]:
    detail = client.call("inbox.read", {"batch_id": batch_id})["data"]
    return list(detail["sources"])


def _new_state(preparation: Preparation) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "manifest_digest": preparation.manifest.digest,
        "manifest_version": preparation.manifest.version,
        "case_ids": list(EXPECTED_CASES),
        "phase": "pending",
        "phases": [],
        "item_aliases": {},
        "upload_fixture": None,
        "correction_batch_id": None,
        "clients": [],
    }


def _read_state(preparation: Preparation) -> dict[str, Any]:
    path = preparation.state_path
    if not path.is_file():
        return _new_state(preparation)
    if path.is_symlink():
        raise AcceptanceError("acceptance state file is not a regular file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise AcceptanceError("acceptance state file is not private")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        raise AcceptanceError("acceptance state schema is unsupported")
    if payload.get("manifest_digest") != preparation.manifest.digest:
        raise AcceptanceError("acceptance state was recorded for another manifest")
    if payload.get("case_ids") != list(EXPECTED_CASES):
        raise AcceptanceError("acceptance state roster does not match the manifest")
    return payload


def _write_state(preparation: Preparation, payload: dict[str, Any]) -> None:
    path = preparation.state_path
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(payload, target, ensure_ascii=False, sort_keys=True)
        target.write("\n")
    os.chmod(path, 0o600)


def _recorded(state: Mapping[str, Any], phase: int) -> dict[str, Any] | None:
    for entry in state["phases"]:
        if entry["phase"] == phase:
            return dict(entry)
    return None


def _revalidate_phase(client: StoreClient, record: Mapping[str, Any]) -> None:
    """Recheck the exact recorded boundary before resuming a later phase."""
    sources = _batch_sources(client, record["batch_id"])
    if len(sources) != record["source_count"]:
        raise AcceptanceError("a recorded batch no longer matches its source roster")
    view = client.call("change_set.get", {"change_set_id": record["change_set_id"]})[
        "data"
    ]
    if view["batch_id"] != record["batch_id"]:
        raise AcceptanceError("a recorded change set no longer matches its batch")
    expected_state = "applied" if record["applied"] else "draft"
    if view["state"] != expected_state:
        raise AcceptanceError("a recorded review is no longer in its expected state")
    if record["applied"] and view["revision_id"] != record["revision_id"]:
        raise AcceptanceError("a recorded applied revision changed")


def _seal_one_batch(
    client: StoreClient,
    home: Path,
    scan: Mapping[str, Any],
    expected_sources: int,
    known_batches: set[str],
) -> tuple[str, list[dict[str, Any]]]:
    envelope = client.call(
        "inbox.scan",
        {"authorship": scan["authorship"], "sensitivity": scan["sensitivity"]},
    )
    batch = envelope["data"]
    batch_id = batch["batch_id"]
    if batch_id in known_batches:
        raise AcceptanceError("a phase reused an earlier sealed batch")
    if batch["source_count"] != expected_sources:
        raise AcceptanceError("a phase sealed an unexpected number of sources")
    sources = _batch_sources(client, batch_id)
    if len(sources) != expected_sources:
        raise AcceptanceError("a sealed batch roster is inconsistent")
    _require_empty_inbox(home)
    return batch_id, sources


def _create_single_change_set(
    client: StoreClient,
    batch_id: str,
    known_change_sets: set[str],
) -> dict[str, Any]:
    view: dict[str, Any] = client.call("change_set.create", {"batch_id": batch_id})[
        "data"
    ]
    if view["change_set_id"] in known_change_sets:
        raise AcceptanceError("a phase reused an earlier change set")
    if view["batch_id"] != batch_id:
        raise AcceptanceError("a change set was created for another batch")
    return view


def _run_lineage_phase(
    client: StoreClient,
    preparation: Preparation,
    state: dict[str, Any],
    *,
    phase: int,
    role: str,
) -> dict[str, Any]:
    case = preparation.manifest.cases[LINEAGE_CASE]
    section = case[role]
    home = preparation.home
    _require_empty_inbox(home)
    known_batches = {entry["batch_id"] for entry in state["phases"]}
    known_change_sets = {entry["change_set_id"] for entry in state["phases"]}
    _stage(home, section["source"]["filename"], section["source"]["utf8_content"])
    batch_id, sources = _seal_one_batch(
        client,
        home,
        section["agent_scan"],
        1,
        known_batches,
    )
    if sources[0]["blob_digest"] != section["source"]["sha256"]:
        raise AcceptanceError("a captured source digest does not match the manifest")
    digests = {f"{role}.source": (sources[0]["source_id"], sources[0]["blob_digest"])}
    view = _create_single_change_set(client, batch_id, known_change_sets)

    memory = section["memory"]
    target_lineage = None
    expected_head = None
    if memory["target_lineage_ref"] is not None:
        predecessor = _recorded(state, 1)
        if predecessor is None:
            raise AcceptanceError("the successor phase has no recorded predecessor")
        target_lineage = predecessor["lineage_id"]
        expected_head = predecessor["memory_id"]
    view = client.call(
        "change_set.edit",
        {
            "change_set_id": view["change_set_id"],
            "expected_revision_id": view["revision_id"],
            "edits": [
                {
                    "op": "add_item",
                    "client_item_id": f"{LINEAGE_CASE}-{role.upper()}",
                    "memory": _memory_arguments(
                        memory,
                        target_lineage_id=target_lineage,
                        expected_head_id=expected_head,
                    ),
                    "evidence": _evidence_arguments(
                        memory,
                        digests,
                        lambda locator: locator["source_ref"],
                    ),
                }
            ],
        },
    )["data"]
    _spawn_owner_approval(
        preparation.memory,
        preparation.home,
        view["change_set_id"],
        view["revision_id"],
        view["digest"],
    )
    applied = client.call("change_set.get", {"change_set_id": view["change_set_id"]})[
        "data"
    ]
    if applied["state"] != "applied":
        raise AcceptanceError("the owner approval did not apply this revision")
    found = client.call("memory.search", {"query": memory["statement"]})["data"]
    matches = [
        hit for hit in found if hit["memory"]["statement"] == memory["statement"]
    ]
    if len(matches) != 1:
        raise AcceptanceError("the applied lineage revision is not the current head")
    return {
        "phase": phase,
        "case_id": LINEAGE_CASE,
        "role": role,
        "batch_id": batch_id,
        "change_set_id": view["change_set_id"],
        "revision_id": view["revision_id"],
        "digest": view["digest"],
        "source_count": 1,
        "scan_count": 1,
        "inbox_empty_before": True,
        "inbox_empty_after": True,
        "applied": True,
        "memory_id": matches[0]["memory"]["memory_id"],
        "lineage_id": matches[0]["memory"]["lineage_id"],
    }


def _run_review_phase(
    client: StoreClient,
    preparation: Preparation,
    state: dict[str, Any],
) -> dict[str, Any]:
    case = preparation.manifest.cases[REVIEW_CASE]
    home = preparation.home
    _require_empty_inbox(home)
    known_batches = {entry["batch_id"] for entry in state["phases"]}
    known_change_sets = {entry["change_set_id"] for entry in state["phases"]}
    for source in case["sources"]:
        _stage(home, source["filename"], source["utf8_content"])
    batch_id, sources = _seal_one_batch(
        client,
        home,
        case["agent_scan"],
        len(case["sources"]),
        known_batches,
    )
    by_digest = {source["blob_digest"]: source for source in sources}
    digests: dict[str, tuple[str, str]] = {}
    for source in case["sources"]:
        captured = by_digest.get(source["sha256"])
        if captured is None:
            raise AcceptanceError("a declared review source was not captured")
        digests[source["alias"]] = (captured["source_id"], captured["blob_digest"])

    view = _create_single_change_set(client, batch_id, known_change_sets)
    edits: list[dict[str, Any]] = []
    aliases: dict[str, str] = {}
    for item in case["initial_review"]["items"]:
        aliases[item["item_alias"]] = item["statement"]
        edits.append(
            {
                "op": "add_item",
                "client_item_id": item["client_item_id"],
                "memory": _memory_arguments(
                    item,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                "evidence": _evidence_arguments(
                    item,
                    digests,
                    lambda locator: locator["source_alias"],
                ),
            }
        )
    for decision in case["initial_review"]["source_decisions"]:
        if decision["state"] != "no_memory":
            continue
        edits.append(
            {
                "op": "set_source_no_memory",
                "source_id": digests[decision["source_alias"]][0],
                "reason": decision["reason"],
            }
        )
    view = client.call(
        "change_set.edit",
        {
            "change_set_id": view["change_set_id"],
            "expected_revision_id": view["revision_id"],
            "edits": edits,
        },
    )["data"]
    if view["state"] != "draft":
        raise AcceptanceError("the review phase must leave one pending draft")
    _require_empty_inbox(home)
    resolved = {
        alias: next(
            item["item_id"]
            for item in view["items"]
            if item["memory"]["statement"] == statement
        )
        for alias, statement in aliases.items()
    }
    state["item_aliases"].update(resolved)
    return {
        "phase": 3,
        "case_id": REVIEW_CASE,
        "role": "initial_review",
        "batch_id": batch_id,
        "change_set_id": view["change_set_id"],
        "revision_id": view["revision_id"],
        "digest": view["digest"],
        "source_count": len(case["sources"]),
        "scan_count": 1,
        "inbox_empty_before": True,
        "inbox_empty_after": True,
        "applied": False,
    }


def prepare(preparation: Preparation) -> dict[str, Any]:
    """Run every capture phase in order, resuming from validated recorded state."""
    validate_absolute_executable(preparation.memory)
    validate_state_root(preparation.state_root)
    if _home_needs_initialization(preparation.home):
        _initialize_runtime(preparation)
    validate_store_home(preparation.home)
    state = _read_state(preparation)
    with StoreClient(preparation.memory, preparation.home) as client:
        for record in state["phases"]:
            _revalidate_phase(client, record)
        if _recorded(state, 1) is None:
            state["phases"].append(
                _run_lineage_phase(
                    client, preparation, state, phase=1, role="historical"
                )
            )
            state["phase"] = "phase-1"
            _write_state(preparation, state)
        if _recorded(state, 2) is None:
            state["phases"].append(
                _run_lineage_phase(client, preparation, state, phase=2, role="current")
            )
            state["phase"] = "phase-2"
            _write_state(preparation, state)
        if _recorded(state, 3) is None:
            state["phases"].append(_run_review_phase(client, preparation, state))
        state["phase"] = "complete"
        _write_state(preparation, state)
    return {**state, "state_path": str(preparation.state_path)}


def _initialize_runtime(preparation: Preparation) -> None:
    completed = subprocess.run(
        [
            str(preparation.memory),
            "init",
            "--home",
            str(preparation.home),
        ],
        capture_output=True,
        check=False,
        close_fds=True,
    )
    if completed.returncode != 0:
        raise AcceptanceError("the synthetic acceptance runtime could not be created")


def write_upload_fixture(preparation: Preparation, directory: Path) -> dict[str, Any]:
    """Write the one fixed drag/drop fixture outside the Store, silently."""
    validate_store_home(preparation.home)
    if not isinstance(directory, Path) or not directory.is_absolute():
        raise AcceptanceError("the fixture directory must be absolute")
    if directory.is_symlink() or not directory.is_dir():
        raise AcceptanceError("the fixture directory is invalid")
    resolved = directory.resolve()
    if resolved.is_relative_to(preparation.home.resolve()):
        raise AcceptanceError("the fixture directory is inside the Store root")
    artifact = preparation.manifest.cases[UPLOAD_CASE]["artifact"]
    target = resolved / artifact["filename"]
    if target.exists():
        raise AcceptanceError("the fixture already exists in that directory")
    target.write_bytes(artifact["utf8_content"].encode("utf-8"))
    record = {
        "case_id": UPLOAD_CASE,
        "byte_length": artifact["byte_length"],
        "sha256": artifact["sha256"],
    }
    state = _read_state(preparation)
    state["upload_fixture"] = record
    _write_state(preparation, state)
    return record


def record_correction_batch(preparation: Preparation, batch_id: str) -> str:
    """Record the already-sealed correction batch the launcher must bind to."""
    validate_store_home(preparation.home)
    if not isinstance(batch_id, str) or not batch_id:
        raise AcceptanceError("the correction batch identifier is invalid")
    state = _read_state(preparation)
    state["correction_batch_id"] = batch_id
    _write_state(preparation, state)
    return batch_id


def operator_view(
    preparation: Preparation,
    case_id: str,
    *,
    stdin: TextIO | Any = sys.stdin,
    stdout: TextIO | Any = sys.stdout,
) -> None:
    """Render one case's exact synthetic text only to a controlling terminal."""
    validate_store_home(preparation.home)
    state = _read_state(preparation)
    if state.get("manifest_digest") != preparation.manifest.digest:
        raise AcceptanceError("the recorded manifest digest no longer matches")
    if case_id not in preparation.manifest.cases:
        raise AcceptanceError("the requested case is not in the reviewed roster")
    if not (
        callable(getattr(stdin, "isatty", None))
        and stdin.isatty()
        and callable(getattr(stdout, "isatty", None))
        and stdout.isatty()
    ):
        raise AcceptanceError("the operator view requires a controlling terminal")
    case = preparation.manifest.cases[case_id]
    lines = [f"Operator view for {case_id}", ""]
    if case_id == CORRECTION_CASE:
        lines.append("Enter this exact correction text in the local owner UI:")
        lines.append("")
        lines.append(case["correction_text"])
    elif case_id == REVIEW_CASE:
        lines.append("Execute these manifest-defined repair operations in order:")
        for index, operation in enumerate(case["repair_operations"], start=1):
            lines.append(f"  {index}. {operation['operation']}")
        lines.append("")
        for item in case["expected_owner_repair"]["items"]:
            lines.append(f"Statement: {item['statement']}")
            lines.append(f"Tags: {', '.join(item['tags'])}")
            for locator in item["evidence"]:
                lines.append(f"Evidence: {locator['excerpt']}")
            lines.append("")
    elif case_id == LINEAGE_CASE:
        for role in ("historical", "current"):
            lines.append(f"{role}: {case[role]['memory']['statement']}")
    else:
        artifact = case["artifact"]
        lines.append(f"File: {artifact['filename']}")
        lines.append(f"Bytes: {artifact['byte_length']}")
    stdout.write("\n".join(lines) + "\n")
    flush = getattr(stdout, "flush", None)
    if callable(flush):
        flush()


def _probe_client_version(
    executable: Path,
    kind: str,
    environment: Mapping[str, str],
) -> str:
    completed = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        check=False,
        close_fds=True,
        env=dict(environment),
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise AcceptanceError("the client version probe failed")
    version = completed.stdout.strip().splitlines()[0] if completed.stdout else ""
    if CLIENT_VERSION_PATTERNS[kind].fullmatch(version) is None:
        raise AcceptanceError("the client version does not match its declared kind")
    return version


def _client_workspace(preparation: Preparation, kind: str) -> Path:
    workspace = Path(
        tempfile.mkdtemp(
            prefix="memory-ui-acceptance-client.", dir=preparation.state_root
        )
    )
    os.chmod(workspace, 0o700)
    skills = workspace / CLIENT_SKILL_DIRECTORIES[kind]
    skills.mkdir(parents=True)
    packaged = _packaged_skill(preparation)
    shutil.copyfile(packaged, skills / "SKILL.md")
    return workspace


def _packaged_skill(preparation: Preparation) -> Path:
    """Resolve the packaged Skill through the installed environment itself."""
    interpreter = preparation.memory.parent / "python"
    if not interpreter.exists() or not os.access(interpreter, os.X_OK):
        raise AcceptanceError("the installed interpreter was not found")
    completed = subprocess.run(
        [
            str(interpreter),
            "-I",
            "-c",
            (
                "from importlib.resources import files;"
                'print(files("memory").joinpath("skill", "SKILL.md"))'
            ),
        ],
        capture_output=True,
        check=False,
        close_fds=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise AcceptanceError("the installed vendor-neutral Skill was not found")
    packaged = Path(completed.stdout.strip())
    if not packaged.is_absolute() or not packaged.is_file():
        raise AcceptanceError("the installed vendor-neutral Skill was not found")
    return packaged


def _task_prompt(preparation: Preparation, task: str) -> str:
    if task not in TASK_CASES:
        raise AcceptanceError("the acceptance task selector is unsupported")
    if task == UPLOAD_CASE:
        return UPLOAD_TASK_PROMPT
    state = _read_state(preparation)
    batch_id = state.get("correction_batch_id")
    if not batch_id:
        raise AcceptanceError("no sealed correction batch has been recorded")
    return CORRECTION_TASK_PROMPT.format(batch_id=batch_id)


def launch_client(
    preparation: Preparation,
    *,
    kind: str,
    executable: Path,
    model: str,
    task: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Start exactly one isolated installed client against this prepared home."""
    validate_store_home(preparation.home)
    if kind not in CLIENT_KINDS:
        raise AcceptanceError("the client kind is unsupported")
    if not isinstance(model, str) or not model:
        raise AcceptanceError("the client model is invalid")
    prompt = _task_prompt(preparation, task)
    target = validate_absolute_executable(executable)
    child_environment = {
        **os.environ,
        **(dict(environment) if environment else {}),
        "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
    }
    version = _probe_client_version(target, kind, child_environment)
    workspace = _client_workspace(preparation, kind)
    configuration: Path | None = None
    try:
        if kind == "codex":
            command = [
                str(target),
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--skip-git-repo-check",
                "-C",
                str(workspace),
                "--model",
                model,
                "-c",
                f'mcp_servers.memory_ui_acceptance.command="{preparation.memory}"',
                "-c",
                (
                    "mcp_servers.memory_ui_acceptance.args="
                    f'["mcp","--home","{preparation.home}"]'
                ),
                "-c",
                "mcp_servers.memory_ui_acceptance.required=true",
                "-c",
                'mcp_servers.memory_ui_acceptance.default_tools_approval_mode="auto"',
                "-",
            ]
        else:
            configuration = workspace / "claude-mcp.json"
            descriptor = os.open(
                configuration,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as target_file:
                json.dump(
                    {
                        "mcpServers": {
                            "memory_ui_acceptance": {
                                "type": "stdio",
                                "command": str(preparation.memory),
                                "args": ["mcp", "--home", str(preparation.home)],
                            }
                        }
                    },
                    target_file,
                    sort_keys=True,
                )
                target_file.write("\n")
            os.chmod(configuration, 0o600)
            command = [
                str(target),
                "--model",
                model,
                "--setting-sources",
                "project",
                "--strict-mcp-config",
                "--mcp-config",
                str(configuration),
                "--allowedTools",
                "mcp__memory_ui_acceptance",
                "-p",
                prompt,
            ]
        completed = subprocess.run(
            command,
            check=False,
            close_fds=True,
            cwd=str(workspace),
            env=child_environment,
            input=prompt if kind == "codex" else "",
            text=True,
        )
    finally:
        if configuration is not None and configuration.exists():
            configuration.unlink()
            if configuration.exists():
                raise AcceptanceError("the transient client configuration survived")
    record = {
        "kind": kind,
        "model": model,
        "task": task,
        "version": version,
        "executable_target": str(target),
        "exit_status": completed.returncode,
    }
    state = _read_state(preparation)
    state["clients"].append(
        {key: value for key, value in record.items() if key != "executable_target"}
    )
    _write_state(preparation, state)
    return record


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prepare-ui-acceptance",
        description=(
            "Prepare one deterministic installed local owner UI acceptance runtime."
        ),
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--memory", type=Path)
    parser.add_argument("--home", type=Path)
    parser.add_argument("--write-upload-fixture", type=Path)
    parser.add_argument("--operator-view")
    parser.add_argument("--record-correction-batch")
    parser.add_argument("--launch-client", choices=CLIENT_KINDS)
    parser.add_argument("--client-executable", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--task", choices=TASK_CASES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one preparation, fixture, operator-view, or isolated client mode."""
    arguments = _build_parser().parse_args(argv)
    try:
        manifest = load_manifest(arguments.manifest)
        if arguments.memory is None or arguments.home is None:
            raise AcceptanceError("an installed command and Store home are required")
        preparation = Preparation(
            memory=validate_absolute_executable(arguments.memory),
            home=arguments.home,
            manifest=manifest,
            state_root=validate_state_root(arguments.state_root),
        )
        if arguments.write_upload_fixture is not None:
            write_upload_fixture(preparation, arguments.write_upload_fixture)
            print("upload fixture written")
            return 0
        if arguments.operator_view is not None:
            operator_view(preparation, arguments.operator_view)
            return 0
        if arguments.record_correction_batch is not None:
            record_correction_batch(preparation, arguments.record_correction_batch)
            print("correction batch recorded")
            return 0
        if arguments.launch_client is not None:
            if arguments.client_executable is None or arguments.model is None:
                raise AcceptanceError("a client executable and model are required")
            if arguments.task is None:
                raise AcceptanceError("a task selector is required")
            launch_client(
                preparation,
                kind=arguments.launch_client,
                executable=arguments.client_executable,
                model=arguments.model,
                task=arguments.task,
            )
            print("client run complete")
            return 0
        state = prepare(preparation)
        print(f"acceptance preparation {state['phase']}")
        print(f"manifest digest {state['manifest_digest']}")
        print(f"phases recorded {len(state['phases'])}")
        return 0
    except AcceptanceError as error:
        print(f"acceptance preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
