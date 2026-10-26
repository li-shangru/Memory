#!/usr/bin/env python3
"""Run fixed repeated behavioral trials through isolated installed clients.

This is development-only acceptance tooling. Raw prompts, client output,
transcripts, Store identities, and paths stay private. Legacy runs use temporary
state roots; explicit campaign recovery retains fixtures and captures in durable
private storage with separate temporary client workspaces. Public reports contain
fixed labels, provenance digests, counts, and explicit denominators.

Canonical fixtures are supplied by a separately named synthetic seed adapter.
That adapter is test preparation, never evidence for capture, review, approval,
or apply. This tool does not mint or simulate owner approval.
"""

from __future__ import annotations

import argparse
import codecs
import copy
import hashlib
import json
import os
import re
import secrets
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager, nullcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, TextIO, cast

if TYPE_CHECKING:
    from behavioral_campaign import Campaign, Cohort
    from behavioral_client_lifecycle import ClientLifecycle
    from behavioral_codex_auth import CredentialLease, ScopedSession
    from behavioral_continuation import Continuation

MANIFEST_SCHEMA = "memory.synthetic-behavioral-acceptance.v1"
DISCOVERY_MANIFEST_SCHEMA = "memory.synthetic-behavioral-discovery.v1"
STATE_SCHEMA = "memory.behavioral-acceptance-state.v1"
REPORT_SCHEMA = "memory.behavioral-acceptance-report.v1"
STATE_FILENAME = "behavioral-acceptance-state.json"
DEFAULT_TRIALS = 3
MAX_TRIALS = 10
PRIVATE_OUTPUT_LIMIT = 1024 * 1024
CLIENT_TIMEOUT_SECONDS = 600
CLIENT_KINDS = ("codex", "claude")
DIMENSIONS = ("retrieval", "caveat", "freshness", "uncertainty", "final_answer")
EXPECTED_CASES = (
    "SYN-BEHAVIOR-PARAPHRASE-021",
    "SYN-BEHAVIOR-BILINGUAL-ZH-022",
    "SYN-BEHAVIOR-GUARD-ZH-023",
    "SYN-BEHAVIOR-PRIORITY-024",
    "SYN-BEHAVIOR-CORRECTION-ZH-025",
    "SYN-BEHAVIOR-READONLY-026",
)
EXPECTED_CONDITIONS = (
    "non_obvious_paraphrase",
    "bilingual_retrieval",
    "governing_caveat",
    "explicit_priority",
    "conflicting_stale_predecessor_and_approved_correction",
    "read_only_advice",
)
DISCOVERY_CASES = (
    "SYN-BEHAVIOR-DISCOVERY-REPEAT-LATE-EN-027",
    "SYN-BEHAVIOR-DISCOVERY-REPEAT-LATE-ZH-028",
)
DISCOVERY_CONDITIONS = (
    "repeated_distractors_and_late_caveat_en",
    "repeated_distractors_and_late_caveat_zh",
)
DIGEST = re.compile(r"[0-9a-f]{64}")
CLIENT_VERSION_PATTERNS = {
    "codex": re.compile(r"codex(?:-cli)? \d+\.\d+\.\d+.*"),
    "claude": re.compile(r"\d+\.\d+\.\d+.*\(Claude Code\)"),
}
CLIENT_SKILL_DIRECTORIES = {
    "codex": Path(".agents") / "skills" / "using-memory",
    "claude": Path(".claude") / "skills" / "using-memory",
}
CODEX_DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "code_mode",
    "code_mode_host",
    "view_image",
    "shell_snapshot",
    "shell_snapshot_v2",
    "workspace_dependencies",
    "skill_search",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "in_app_browser",
    "image_generation",
    "hooks",
    "plugins",
    "apps",
    "tool_suggest",
    "deferred_executor",
    "executor_capability_discovery",
    "multi_agent",
    "multi_agent_v2",
    "goals",
    "artifact",
    "sleep_tool",
    "request_permissions_tool",
)
STATUS_FIELDS = (
    "product",
    "product_version",
    "schema_version",
    "store_id",
    "source_count",
    "memory_count",
    "searchable_count",
    "unsearchable_count",
    "pending_review_count",
    "reindex_required",
    "mcp_contract_digest",
    "skill_digest",
)
SNAPSHOT_FIELDS = (*STATUS_FIELDS, "audit_generation")
PUBLIC_PROVENANCE_FIELDS = (
    "client_kind",
    "client_version",
    "model",
    "product_version",
    "build_digest",
    "memory_executable_digest",
    "client_executable_digest",
    "seed_executable_digest",
    "installed_distribution_digest",
    "mcp_contract_digest",
    "skill_digest",
    "seed_mode",
    "manifest_schema",
    "manifest_version",
    "manifest_digest",
    "rubric_version",
    "rubric_digest",
)


class AcceptanceError(Exception):
    """One bounded content-free acceptance failure."""


class ClientLaunch:
    """One command and its bounded cleanup before client descendants stop."""

    def __init__(
        self,
        command: Sequence[str],
        before_cleanup: Callable[[], None] | None = None,
        lifecycle: ClientLifecycle | None = None,
    ) -> None:
        self.command = list(command)
        self.before_cleanup = before_cleanup
        self.lifecycle = lifecycle


class TrialBlocked(Exception):
    """One fixed trial that could not be attempted to completion."""

    def __init__(self, label: str) -> None:
        if not _is_label(label):
            raise AcceptanceError("blocked trial label is invalid")
        super().__init__(label)
        self.label = label


class Manifest:
    """One strict manifest plus its complete and rubric-only digests."""

    __slots__ = (
        "cases",
        "digest",
        "path",
        "rubric_digest",
        "rubric_version",
        "schema",
        "version",
    )

    def __init__(
        self,
        *,
        path: Path,
        digest: str,
        schema: str,
        version: int,
        rubric_version: str,
        rubric_digest: str,
        cases: dict[str, dict[str, Any]],
    ) -> None:
        self.path = path
        self.digest = digest
        self.schema = schema
        self.version = version
        self.rubric_version = rubric_version
        self.rubric_digest = rubric_digest
        self.cases = cases


TrialExecutor = Callable[
    [dict[str, Any], int, Path, Path, Path],
    dict[str, Any],
]


def _is_label(value: object) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]*", value) is not None
    )


def _strict_json(raw: bytes) -> Any:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AcceptanceError("document contains a duplicated key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except AcceptanceError:
        raise
    except (UnicodeDecodeError, ValueError) as error:
        raise AcceptanceError("document is not strict UTF-8 JSON") from error


def _require_mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AcceptanceError(message)
    return value


def _require_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise AcceptanceError(f"manifest field {key} is invalid")
    return value


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_seed(case: Mapping[str, Any]) -> None:
    seed = _require_mapping(case.get("seed_profile"), "seed profile is missing")
    if set(seed) != {"mode", "memories"} or seed.get("mode") != "synthetic_adapter":
        raise AcceptanceError("seed profile must name the synthetic adapter")
    memories = seed.get("memories")
    if not isinstance(memories, list) or not memories:
        raise AcceptanceError("seed profile has no memories")
    seen_fixtures: set[str] = set()
    lineage_roles: dict[str, set[str]] = {}
    for raw_memory in memories:
        memory = _require_mapping(raw_memory, "seed memory is invalid")
        expected = {
            "fixture_id",
            "lineage_ref",
            "revision_role",
            "statement",
            "source_text",
            "evidence_excerpt",
            "tags",
            "valid_from",
            "valid_to",
            "guard_of",
        }
        if set(memory) != expected:
            raise AcceptanceError("seed memory structure is invalid")
        fixture_id = _require_text(memory, "fixture_id")
        if re.fullmatch(r"SYN-BEHAVIOR-MEM-[A-Z0-9-]{1,100}", fixture_id) is None:
            raise AcceptanceError("seed fixture identifier is unsafe")
        lineage = _require_text(memory, "lineage_ref")
        role = _require_text(memory, "revision_role")
        if fixture_id in seen_fixtures:
            raise AcceptanceError("seed fixture identifier is duplicated")
        if role not in {"current", "predecessor", "approved_correction"}:
            raise AcceptanceError("seed revision role is invalid")
        seen_fixtures.add(fixture_id)
        lineage_roles.setdefault(lineage, set()).add(role)
        for key in ("statement", "source_text", "evidence_excerpt"):
            _require_text(memory, key)
        tags = memory.get("tags")
        if (
            not isinstance(tags, list)
            or not tags
            or not all(_is_label(tag) for tag in tags)
        ):
            raise AcceptanceError("seed tags are invalid")
        guard = memory.get("guard_of")
        if guard is not None and not isinstance(guard, str):
            raise AcceptanceError("seed guard reference is invalid")
    if case["condition"] == "conflicting_stale_predecessor_and_approved_correction":
        if not any(
            roles == {"predecessor", "approved_correction"}
            for roles in lineage_roles.values()
        ):
            raise AcceptanceError("correction condition lacks one predecessor lineage")


def _validate_rubric(case: Mapping[str, Any]) -> None:
    rubric = _require_mapping(case.get("rubric"), "case rubric is missing")
    if tuple(rubric) != DIMENSIONS and set(rubric) != set(DIMENSIONS):
        raise AcceptanceError("case rubric dimensions are incomplete")
    for dimension in DIMENSIONS:
        rule = _require_mapping(rubric.get(dimension), "rubric rule is invalid")
        if set(rule) != {"applicable", "pass_label", "criterion"}:
            raise AcceptanceError("rubric rule structure is invalid")
        applicable = rule.get("applicable")
        label = rule.get("pass_label")
        criterion = rule.get("criterion")
        if not isinstance(applicable, bool) or not _is_label(label):
            raise AcceptanceError("rubric rule is invalid")
        if (
            not isinstance(criterion, str)
            or criterion.strip() != criterion
            or len(criterion) < 24
        ):
            raise AcceptanceError("rubric criterion is invalid")
        if not applicable and label != "not_applicable":
            raise AcceptanceError("inapplicable rubric rule has a pass label")


def _manifest_roster(schema: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if schema == MANIFEST_SCHEMA:
        return EXPECTED_CASES, EXPECTED_CONDITIONS
    if schema == DISCOVERY_MANIFEST_SCHEMA:
        return DISCOVERY_CASES, DISCOVERY_CONDITIONS
    raise AcceptanceError("manifest version is unsupported")


def load_manifest(path: Path) -> Manifest:
    """Load the exact reviewed synthetic case and rubric roster."""
    if not path.is_file() or path.is_symlink():
        raise AcceptanceError("behavioral manifest is missing")
    raw = path.read_bytes()
    payload = _require_mapping(_strict_json(raw), "manifest root is invalid")
    schema = _require_text(payload, "schema")
    expected_cases, expected_conditions = _manifest_roster(schema)
    required = {"schema", "manifest_version", "rubric_version", "cases"}
    if schema == DISCOVERY_MANIFEST_SCHEMA:
        required.add("trials_per_case_per_client")
    if set(payload) != required:
        raise AcceptanceError("manifest structure is invalid")
    if payload.get("manifest_version") != 1:
        raise AcceptanceError("manifest version is unsupported")
    rubric_version = _require_text(payload, "rubric_version")
    if schema == DISCOVERY_MANIFEST_SCHEMA:
        count = payload["trials_per_case_per_client"]
        if type(count) is not int or count != 3:
            raise AcceptanceError("discovery trials are fixed at three per client case")
        if rubric_version != "behavioral-discovery-rubric-2026-09-05":
            raise AcceptanceError("discovery rubric version is unsupported")
    declared = payload.get("cases")
    if not isinstance(declared, list):
        raise AcceptanceError("manifest cases are invalid")
    cases: dict[str, dict[str, Any]] = {}
    conditions: list[str] = []
    for raw_case in declared:
        case = dict(_require_mapping(raw_case, "manifest case is invalid"))
        if set(case) != {
            "case_id",
            "condition",
            "language",
            "question_variant",
            "seed_profile",
            "rubric",
        }:
            raise AcceptanceError("manifest case structure is invalid")
        case_id = _require_text(case, "case_id")
        condition = _require_text(case, "condition")
        language = _require_text(case, "language")
        _require_text(case, "question_variant")
        if case_id in cases or language not in {"en", "zh"}:
            raise AcceptanceError("manifest case identity is invalid")
        _validate_seed(case)
        _validate_rubric(case)
        cases[case_id] = case
        conditions.append(condition)
    if tuple(cases) != expected_cases or tuple(conditions) != expected_conditions:
        raise AcceptanceError("manifest case roster is not the reviewed roster")
    rubric_payload = {
        "rubric_version": rubric_version,
        "cases": [
            {"case_id": case_id, "rubric": cases[case_id]["rubric"]}
            for case_id in cases
        ],
    }
    return Manifest(
        path=path.resolve(),
        digest=hashlib.sha256(raw).hexdigest(),
        schema=schema,
        version=1,
        rubric_version=rubric_version,
        rubric_digest=_canonical_digest(rubric_payload),
        cases=cases,
    )


def validate_trial_count(value: int | None) -> int:
    """Fix a requested trial count before any slot is attempted."""
    count = DEFAULT_TRIALS if value is None else value
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= MAX_TRIALS
    ):
        raise AcceptanceError("trial count must be between 1 and 10")
    return count


def _validate_provenance(provenance: Mapping[str, object]) -> dict[str, str]:
    required = {
        "client_kind",
        "client_version",
        "model",
        "product_version",
        "build_digest",
        "memory_executable_digest",
        "client_executable_digest",
        "seed_executable_digest",
        "installed_distribution_digest",
        "mcp_contract_digest",
        "skill_digest",
        "seed_mode",
    }
    if "reasoning_effort" in provenance:
        required.add("reasoning_effort")
    required.update(_bound_isolation_provenance(provenance))
    required.update(_bound_authentication_provenance(provenance))
    if set(provenance) != required:
        raise AcceptanceError("run provenance is incomplete")
    normalized = {
        key: value for key, value in provenance.items() if isinstance(value, str)
    }
    if set(normalized) != required:
        raise AcceptanceError("run provenance values are invalid")
    if normalized["client_kind"] not in CLIENT_KINDS:
        raise AcceptanceError("client kind is invalid")
    _bound_reasoning_effort(normalized)
    if normalized["seed_mode"] not in {"synthetic_adapter", "owner_review"}:
        raise AcceptanceError("fixture mode is unsupported")
    for key in (
        "build_digest",
        "memory_executable_digest",
        "client_executable_digest",
        "installed_distribution_digest",
        "mcp_contract_digest",
        "skill_digest",
    ):
        if DIGEST.fullmatch(normalized[key]) is None:
            raise AcceptanceError("run provenance digest is invalid")
    seed_digest = normalized["seed_executable_digest"]
    if seed_digest != "not_present" and DIGEST.fullmatch(seed_digest) is None:
        raise AcceptanceError("run provenance digest is invalid")
    if any(not normalized[key] for key in required):
        raise AcceptanceError("run provenance value is empty")
    return normalized


def _bound_reasoning_effort(provenance: Mapping[str, object]) -> str | None:
    """Preserve absent historical effort without inferring a client default."""
    if "reasoning_effort" not in provenance:
        return None
    value = provenance["reasoning_effort"]
    if (
        provenance.get("client_kind") != "codex"
        or not isinstance(value, str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", value) is None
    ):
        raise AcceptanceError("run reasoning effort is invalid or unsupported")
    return value


def _bound_isolation_provenance(provenance: Mapping[str, object]) -> dict[str, str]:
    """Preserve absent historical bindings; new bindings are a complete pair."""
    fields = {"code_mode_host_digest", "isolation_profile_digest"}
    present = fields.intersection(provenance)
    if not present:
        return {}
    if present != fields or provenance.get("client_kind") != "codex":
        raise AcceptanceError("run isolation provenance is incomplete or unsupported")
    result: dict[str, str] = {}
    for field in fields:
        value = provenance[field]
        if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
            raise AcceptanceError("run isolation provenance digest is invalid")
        result[field] = value
    return result


def _bound_authentication_provenance(
    provenance: Mapping[str, object],
) -> dict[str, str]:
    """Keep historical absence while binding the complete subscription adapter."""
    fields = {"authentication_mode", "authentication_adapter_digest"}
    present = fields.intersection(provenance)
    if not present:
        return {}
    digest = provenance.get("authentication_adapter_digest")
    if (
        present != fields
        or provenance.get("client_kind") != "codex"
        or provenance.get("authentication_mode") != "chatgpt_subscription"
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or not _bound_isolation_provenance(provenance)
    ):
        raise AcceptanceError(
            "run authentication provenance is incomplete or unsupported"
        )
    return {
        "authentication_mode": "chatgpt_subscription",
        "authentication_adapter_digest": digest,
    }


def bind_subscription_authentication(
    state: Mapping[str, Any],
    *,
    auth_root: Path,
    authentication_digest: str,
    isolation_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Bind unconsumed fixed trials without changing fixtures or prior outcomes."""
    _validate_fixed_roster(state)
    provenance = _require_mapping(state.get("provenance"), "run provenance is missing")
    private = _require_mapping(state.get("private"), "run configuration is missing")
    if not auth_root.is_absolute() or not _bound_isolation_provenance(provenance):
        raise AcceptanceError("subscription binding requires an isolated prepared run")
    for slot in state["slots"]:
        if (
            any(
                slot.get(field) is not False
                for field in (
                    "attempted",
                    "completed",
                    "client_launch_attempted",
                    "inference_started",
                )
            )
            or slot.get("execution_outcome") != "pending"
            or slot.get("outcome_label") != "untested"
            or slot.get("mutation_outcome") != "unverified"
            or slot.get("grade_outcome") != "ungraded"
            or slot.get("outcomes") != {}
        ):
            raise AcceptanceError(
                "subscription binding requires every trial unconsumed"
            )
    if set(isolation_binding) != {
        "client_executable_digest",
        "code_mode_host_digest",
        "isolation_profile_digest",
    } or any(
        isolation_binding.get(field) != provenance.get(field)
        for field in ("client_executable_digest", "code_mode_host_digest")
    ):
        raise AcceptanceError("subscription binding cannot change the client or host")
    changed_provenance = {
        **provenance,
        **isolation_binding,
        "authentication_mode": "chatgpt_subscription",
        "authentication_adapter_digest": authentication_digest,
    }
    _bound_authentication_provenance(changed_provenance)
    if _bound_authentication_provenance(provenance):
        if changed_provenance != provenance or private.get(
            "subscription_auth_root"
        ) != str(auth_root):
            raise AcceptanceError("subscription authentication was already bound")
        return copy.deepcopy(dict(state))
    if "subscription_auth_root" in private or "authentication_transitions" in private:
        raise AcceptanceError("subscription transition history is inconsistent")
    changed = copy.deepcopy(dict(state))
    changed["provenance"] = changed_provenance
    changed["private"]["subscription_auth_root"] = str(auth_root)
    changed["private"]["authentication_transitions"] = [
        {
            "previous_provenance": copy.deepcopy(provenance),
            "previous_state_digest": hashlib.sha256(
                json.dumps(state, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest(),
        }
    ]
    return changed


def _behavioral_helper_path() -> None:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)


def _continuation_info(state: Mapping[str, Any]) -> Continuation | None:
    _behavioral_helper_path()
    from behavioral_continuation import ContinuationError, validate_state

    try:
        return validate_state(state)
    except ContinuationError:
        raise AcceptanceError("continuation state is unavailable or changed") from None


def continue_subscription_authentication(
    state: Mapping[str, Any],
    *,
    auth_root: Path,
    authentication_digest: str,
    isolation_binding: Mapping[str, str],
    snapshot_path: Path,
    snapshot_digest: str,
    cleanup_evidence: Path,
    cleanup_digest: str,
) -> dict[str, Any]:
    """Append one reviewed infrastructure binding, retaining every existing slot."""
    _validate_fixed_roster(state)
    _behavioral_helper_path()
    from behavioral_continuation import ContinuationError, make_continuation

    try:
        return make_continuation(
            state,
            auth_root=auth_root,
            authentication_digest=authentication_digest,
            isolation_binding=isolation_binding,
            snapshot_path=snapshot_path,
            snapshot_digest=snapshot_digest,
            cleanup_evidence=cleanup_evidence,
            cleanup_digest=cleanup_digest,
        )
    except ContinuationError:
        raise AcceptanceError("subscription continuation is unavailable") from None


def effective_execution_state(
    state: Mapping[str, Any], *, slot_id: str | None = None
) -> dict[str, Any]:
    """Use a validated temporary view while all persistence retains original state."""
    _behavioral_helper_path()
    from behavioral_continuation import ContinuationError, execution_state

    if _continuation_info(state) is not None:
        _validate_fixed_roster(state)
    try:
        return execution_state(state, slot_id=slot_id)
    except ContinuationError:
        raise AcceptanceError("continuation execution binding is unavailable") from None


def effective_execution_provenance(state: Mapping[str, Any]) -> dict[str, Any]:
    return dict(
        _require_mapping(
            effective_execution_state(state).get("provenance"),
            "execution provenance is unavailable",
        )
    )


def create_run_state(
    manifest: Manifest,
    *,
    trials: int | None,
    provenance: Mapping[str, object],
) -> dict[str, Any]:
    """Create every immutable case/trial slot before execution starts."""
    count = validate_trial_count(trials)
    if manifest.schema == DISCOVERY_MANIFEST_SCHEMA and count != 3:
        raise AcceptanceError("discovery trials are fixed at three per client case")
    bound_provenance: dict[str, object] = {
        **_validate_provenance(provenance),
        "manifest_schema": manifest.schema,
        "manifest_version": manifest.version,
        "manifest_digest": manifest.digest,
        "rubric_version": manifest.rubric_version,
        "rubric_digest": manifest.rubric_digest,
    }
    slots = []
    for case_id in manifest.cases:
        for trial in range(1, count + 1):
            slots.append(
                {
                    "slot_id": f"{case_id}:{trial}",
                    "case_id": case_id,
                    "condition": manifest.cases[case_id]["condition"],
                    "trial": trial,
                    "attempted": False,
                    "completed": False,
                    "execution_outcome": "pending",
                    "outcome_label": "untested",
                    "mutation_outcome": "unverified",
                    "private_trial_directory": None,
                    "grade_outcome": "ungraded",
                    "outcomes": {},
                }
            )
    return {
        "schema": STATE_SCHEMA,
        "requested_trial_count": count,
        "provenance": bound_provenance,
        "slots": slots,
    }


def _validate_fixed_roster(state: Mapping[str, Any]) -> None:
    """Refuse changed case/trial identities before consuming saved evidence."""
    failure = "acceptance fixed trial roster changed"
    provenance = _require_mapping(state.get("provenance"), failure)
    _bound_authentication_provenance(provenance)
    cases, conditions = _manifest_roster(provenance.get("manifest_schema"))
    count = state.get("requested_trial_count")
    if type(count) is not int or not 1 <= count <= MAX_TRIALS:
        raise AcceptanceError(failure)
    if provenance.get("manifest_schema") == DISCOVERY_MANIFEST_SCHEMA and count != 3:
        raise AcceptanceError(failure)
    slots = state.get("slots")
    expected = [
        (f"{case}:{trial}", case, condition, trial)
        for case, condition in zip(cases, conditions, strict=True)
        for trial in range(1, count + 1)
    ]
    if not isinstance(slots, list) or len(slots) != len(expected):
        raise AcceptanceError(failure)
    for raw_slot, identity in zip(slots, expected, strict=True):
        slot = _require_mapping(raw_slot, failure)
        if (
            type(slot.get("trial")) is not int
            or (
                slot.get("slot_id"),
                slot.get("case_id"),
                slot.get("condition"),
                slot.get("trial"),
            )
            != identity
        ):
            raise AcceptanceError(failure)
    _continuation_info(state)


def _private_directory(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def _validate_attempt(
    result: Mapping[str, Any],
) -> tuple[int, dict[str, Any], dict[str, Any], str | None]:
    if set(result) not in (
        {"exit_status", "before_status", "after_status"},
        {"exit_status", "before_status", "after_status", "failure_label"},
    ):
        raise AcceptanceError("trial executor returned an incomplete result")
    exit_status = result["exit_status"]
    if isinstance(exit_status, bool) or not isinstance(exit_status, int):
        raise AcceptanceError("trial exit status is invalid")
    before = dict(_require_mapping(result["before_status"], "before status is invalid"))
    after = dict(_require_mapping(result["after_status"], "after status is invalid"))
    if any(key not in before or key not in after for key in SNAPSHOT_FIELDS):
        raise AcceptanceError("trial status snapshot is incomplete")
    failure_label = result.get("failure_label")
    if failure_label is not None and not _is_label(failure_label):
        raise AcceptanceError("trial failure label is invalid")
    return exit_status, before, after, failure_label


def _status_projection(status: Mapping[str, Any]) -> dict[str, Any]:
    return {key: status[key] for key in SNAPSHOT_FIELDS}


def execute_trials(
    state: dict[str, Any],
    manifest: Manifest,
    private_root: Path,
    *,
    execute: TrialExecutor,
    persist: Callable[[dict[str, Any]], None] | None = None,
    before_attempt: Callable[[], None] | None = None,
    allocate_prepared_trial: Callable[
        [Path, Mapping[str, Any], int], tuple[Path, Path, Path]
    ]
    | None = None,
) -> None:
    """Attempt each pending slot once, preserving failures and blocks in place."""
    if state.get("schema") != STATE_SCHEMA:
        raise AcceptanceError("acceptance state schema is unsupported")
    if state.get("provenance", {}).get("manifest_digest") != manifest.digest:
        raise AcceptanceError("acceptance state belongs to another manifest")
    _validate_fixed_roster(state)
    for ordinal, slot in enumerate(state["slots"], start=1):
        if slot["execution_outcome"] != "pending":
            continue
        if before_attempt is not None:
            before_attempt()
        slot["attempted"] = True
        slot["execution_outcome"] = "interrupted"
        slot["outcome_label"] = "execution_interrupted"
        if persist is not None:
            persist(state)
        private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(private_root, 0o700)
        try:
            if (
                state["provenance"]["seed_mode"] == "owner_review"
                and slot["private_trial_directory"] is not None
            ):
                allocator = allocate_prepared_trial or _allocated_trial
                home, workspace, response_path = allocator(
                    private_root.parent, slot, ordinal
                )
            else:
                trial_root = _private_directory(private_root, f"trial-{ordinal:03d}")
                home = _private_directory(trial_root, "store")
                workspace = _private_directory(trial_root, "client-session")
                response_path = trial_root / "client-response.private"
                descriptor = os.open(
                    response_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                os.close(descriptor)
                slot["private_trial_directory"] = str(trial_root)
            case = manifest.cases[slot["case_id"]]
            result = execute(case, slot["trial"], home, workspace, response_path)
            exit_status, before, after, failure_label = _validate_attempt(result)
            unchanged = _status_projection(before) == _status_projection(after)
            slot["mutation_outcome"] = "unchanged" if unchanged else "changed"
            if not unchanged:
                slot["execution_outcome"] = "failed"
                slot["outcome_label"] = "store_mutated"
            elif failure_label is not None:
                slot["execution_outcome"] = "failed"
                slot["outcome_label"] = failure_label
            elif exit_status != 0:
                slot["execution_outcome"] = "failed"
                slot["outcome_label"] = "client_exit_nonzero"
            else:
                slot["completed"] = True
                slot["execution_outcome"] = "completed"
                slot["outcome_label"] = "awaiting_grade"
        except TrialBlocked as error:
            slot["execution_outcome"] = "blocked"
            slot["outcome_label"] = error.label
        except AcceptanceError, OSError, subprocess.SubprocessError:
            slot["execution_outcome"] = "failed"
            slot["outcome_label"] = "trial_setup_or_transport_failed"
        if persist is not None:
            persist(state)


def grade_trials(
    state: dict[str, Any],
    manifest: Manifest,
    grades: Sequence[Mapping[str, Any]],
) -> None:
    """Bind label-only human grading to every completed fixed slot."""
    if state.get("schema") != STATE_SCHEMA:
        raise AcceptanceError("acceptance state schema is unsupported")
    provenance = _require_mapping(
        state.get("provenance"), "state provenance is missing"
    )
    if (
        provenance.get("manifest_digest") != manifest.digest
        or provenance.get("rubric_digest") != manifest.rubric_digest
    ):
        raise AcceptanceError("prepared manifest provenance changed before grading")
    _validate_fixed_roster(state)
    completed = {
        slot["slot_id"]: slot
        for slot in state["slots"]
        if slot["execution_outcome"] == "completed"
    }
    if any(slot["grade_outcome"] != "ungraded" for slot in completed.values()):
        raise AcceptanceError("completed slot is already graded")
    supplied: dict[str, Mapping[str, Any]] = {}
    for grade in grades:
        slot_id = grade.get("slot_id")
        if not isinstance(slot_id, str) or slot_id in supplied:
            raise AcceptanceError("grade slot identity is invalid")
        supplied[slot_id] = grade
    if set(supplied) != set(completed):
        raise AcceptanceError("grades must cover every completed slot")
    normalized_grades: dict[str, dict[str, dict[str, str]]] = {}
    failed_slots: set[str] = set()
    observed_inference: set[str] = set()
    for slot_id, slot in completed.items():
        grade = supplied[slot_id]
        if set(grade) not in (
            {"slot_id", "outcomes"},
            {"slot_id", "outcomes", "inference_observed"},
        ):
            raise AcceptanceError("grade structure is invalid")
        if "inference_observed" in grade:
            if grade["inference_observed"] is not True:
                raise AcceptanceError("inference observation must be explicit")
            observed_inference.add(slot_id)
        outcomes = _require_mapping(grade["outcomes"], "grade outcomes are invalid")
        if set(outcomes) != set(DIMENSIONS):
            raise AcceptanceError("grade must contain all rubric dimensions")
        case = manifest.cases[slot["case_id"]]
        normalized: dict[str, dict[str, str]] = {}
        failed = False
        for dimension in DIMENSIONS:
            observation = _require_mapping(
                outcomes[dimension], "grade dimension is invalid"
            )
            if set(observation) != {"result", "label"}:
                raise AcceptanceError("grade dimension structure is invalid")
            result = observation.get("result")
            label = observation.get("label")
            rule = case["rubric"][dimension]
            allowed_results = (
                {"passed", "failed"} if rule["applicable"] else {"not_applicable"}
            )
            if result not in allowed_results or not _is_label(label):
                raise AcceptanceError("grade dimension result is invalid")
            if result in {"passed", "not_applicable"} and label != rule["pass_label"]:
                raise AcceptanceError("grade pass label is outside the fixed rubric")
            if result == "failed" and label == rule["pass_label"]:
                raise AcceptanceError("grade failure must name a failure label")
            if result == "failed":
                failed = True
            normalized[dimension] = {"result": str(result), "label": str(label)}
        normalized_grades[slot_id] = normalized
        if failed:
            failed_slots.add(slot_id)
    for slot_id, slot in completed.items():
        failed = slot_id in failed_slots
        slot["outcomes"] = normalized_grades[slot_id]
        slot["grade_outcome"] = "failed" if failed else "passed"
        slot["outcome_label"] = "rubric_failed" if failed else "rubric_passed"
        if slot_id in observed_inference:
            slot["inference_started"] = True


def _trial_report(slot: Mapping[str, Any]) -> dict[str, Any]:
    outcomes: dict[str, Any] = {}
    stored = slot.get("outcomes")
    for dimension in DIMENSIONS:
        if isinstance(stored, Mapping) and dimension in stored:
            outcomes[dimension] = stored[dimension]
        else:
            outcomes[dimension] = {"result": "untested", "label": "untested"}
    outcomes["mutation"] = {
        "result": slot["mutation_outcome"],
        "label": (
            "store_unchanged"
            if slot["mutation_outcome"] == "unchanged"
            else "store_changed"
            if slot["mutation_outcome"] == "changed"
            else "unverified"
        ),
    }
    return {
        "case_id": slot["case_id"],
        "condition": slot["condition"],
        "trial": slot["trial"],
        "attempted": slot["attempted"],
        "completed": slot["completed"],
        "inference_started": slot.get("inference_started"),
        "client_launch_attempted": slot.get("client_launch_attempted"),
        "execution_outcome": slot["execution_outcome"],
        "outcome_label": slot["outcome_label"],
        "grade_outcome": slot["grade_outcome"],
        "outcomes": outcomes,
    }


def build_report(state: Mapping[str, Any]) -> dict[str, Any]:
    """Build the only durable shape: provenance, labels, counts, and rates."""
    _validate_fixed_roster(state)
    provenance = _require_mapping(
        state.get("provenance"), "state provenance is missing"
    )
    if any(key not in provenance for key in PUBLIC_PROVENANCE_FIELDS):
        raise AcceptanceError("state provenance is incomplete")
    public_provenance = {key: provenance[key] for key in PUBLIC_PROVENANCE_FIELDS}
    reasoning_effort = _bound_reasoning_effort(provenance)
    if reasoning_effort is not None:
        public_provenance["reasoning_effort"] = reasoning_effort
    public_provenance.update(_bound_isolation_provenance(provenance))
    public_provenance.update(_bound_authentication_provenance(provenance))
    slots_raw = state.get("slots")
    if not isinstance(slots_raw, list):
        raise AcceptanceError("state slots are invalid")
    slots = [
        dict(_require_mapping(slot, "state slot is invalid")) for slot in slots_raw
    ]
    requested = len(slots)
    attempted = sum(bool(slot["attempted"]) for slot in slots)
    completed = sum(bool(slot["completed"]) for slot in slots)
    passed = sum(slot["grade_outcome"] == "passed" for slot in slots)
    requested_per_condition = state.get("requested_trial_count")
    conditions = []
    _case_roster, condition_roster = _manifest_roster(provenance["manifest_schema"])
    for condition in condition_roster:
        selected = [slot for slot in slots if slot["condition"] == condition]
        condition_passed = sum(slot["grade_outcome"] == "passed" for slot in selected)
        conditions.append(
            {
                "condition": condition,
                "counts": {
                    "requested": len(selected),
                    "attempted": sum(bool(slot["attempted"]) for slot in selected),
                    "completed": sum(bool(slot["completed"]) for slot in selected),
                    "passed": condition_passed,
                },
                "pass_rate": {
                    "numerator": condition_passed,
                    "denominator": requested_per_condition,
                },
            }
        )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "provenance": public_provenance,
        "counts": {
            "requested": requested,
            "attempted": attempted,
            "completed": completed,
            "passed": passed,
        },
        "inference_counts": {
            "started": sum(slot.get("inference_started") is True for slot in slots),
            "not_started": sum(
                slot.get("inference_started") is False for slot in slots
            ),
            "unavailable": sum(slot.get("inference_started") is None for slot in slots),
        },
        "client_launch_counts": {
            "attempted": sum(
                slot.get("client_launch_attempted") is True for slot in slots
            ),
            "not_attempted": sum(
                slot.get("client_launch_attempted") is False for slot in slots
            ),
            "unavailable": sum(
                slot.get("client_launch_attempted") is None for slot in slots
            ),
        },
        "pass_rate": {"numerator": passed, "denominator": requested},
        "conditions": conditions,
        "trials": [_trial_report(slot) for slot in slots],
        "evidence_scope": (
            "owner_approved_synthetic_fixtures_behavior_only"
            if provenance["seed_mode"] == "owner_review"
            else "synthetic_adapter_seeded_behavior_only"
        ),
        "approval_journey_evidence": "not_attested",
    }
    continuation = _continuation_info(state)
    if continuation is not None:
        report["schema"] = "memory.behavioral-acceptance-report.v2"
        report["execution_bindings"] = {
            "original": dict(public_provenance),
            "continued": {
                **public_provenance,
                **continuation.infrastructure_binding,
            },
        }
        report["continuation"] = {
            "schema": "memory.behavioral-subscription-continuation.v1",
            "pending_slot_ids": list(continuation.pending_slot_ids),
        }
        for slot, trial in zip(slots, report["trials"], strict=True):
            trial["execution_binding"] = (
                "continued"
                if slot["slot_id"] in continuation.pending_slot_ids
                else "original"
            )
    return report


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Create one new content-free report without overwriting evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise AcceptanceError("report already exists") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(report, target, ensure_ascii=False, indent=2, sort_keys=True)
        target.write("\n")
    os.chmod(path, 0o600)


def _validate_executable(path: Path) -> Path:
    if not path.is_absolute() or not path.exists():
        raise AcceptanceError("executable must be one absolute existing file")
    resolved = path.resolve()
    if not stat.S_ISREG(resolved.stat().st_mode) or not os.access(resolved, os.X_OK):
        raise AcceptanceError("executable must be a regular executable file")
    return resolved


def _private_root(path: Path, *, require_empty: bool = False) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise AcceptanceError("state root must be an absolute private directory")
    resolved = path.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if not resolved.is_relative_to(temporary):
        raise AcceptanceError("state root must remain under the temporary directory")
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise AcceptanceError("state root must have mode 0700")
    if require_empty and any(resolved.iterdir()):
        raise AcceptanceError("state root must be empty before preparation")
    return resolved


def _run_text(
    command: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    input_text: str | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        check=False,
        close_fds=True,
        cwd=None if cwd is None else str(cwd),
        env=None if environment is None else dict(environment),
        input=input_text,
        text=True,
        timeout=timeout,
    )


def _run_metadata(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run local metadata only with no ambient client home or credentials."""
    with tempfile.TemporaryDirectory(prefix="memory-behavioral-metadata-") as name:
        probe_root = Path(name)
        os.chmod(probe_root, 0o700)
        environment = _client_environment("codex")
        environment.update(
            HOME=str(probe_root),
            CODEX_HOME=str(probe_root),
            CLAUDE_CONFIG_DIR=str(probe_root),
        )
        return _run_text(command, environment=environment, cwd=probe_root)


def _codex_reasoning_efforts(client: Path, model: str) -> frozenset[str]:
    """Read the installed model schema without auth, a thread, or a turn."""
    failure = "client reasoning effort metadata is unavailable"
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    try:
        from behavioral_codex_isolation import CapabilityProbeError, protected_command
    except ImportError:
        raise AcceptanceError(failure) from None
    with tempfile.TemporaryDirectory(prefix="memory-behavioral-effort-") as name:
        root = Path(name)
        os.chmod(root, 0o700)
        home = _private_directory(root, "home")
        workspace = _private_directory(root, "workspace")
        environment = _client_environment("codex")
        environment.update(HOME=str(home), CODEX_HOME=str(home), TMPDIR=str(root))
        command = [
            str(client),
            "app-server",
            "--stdio",
            "--strict-config",
            "-c",
            'cli_auth_credentials_store="file"',
            "-c",
            "analytics.enabled=false",
            "-c",
            "project_doc_max_bytes=0",
        ]
        try:
            command = protected_command(
                command,
                policy_path=root / "startup.sb",
                executable_paths=(client,),
            )
            with subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=workspace,
                env=environment,
                close_fds=True,
                start_new_session=True,
            ) as process:
                assert process.stdin is not None and process.stdout is not None
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        buffer = b""
                        received = 0
                        deadline = time.monotonic() + 20

                        def request(
                            method: str, params: Mapping[str, object], identifier: int
                        ) -> Mapping[str, Any]:
                            nonlocal buffer, received
                            assert (
                                process.stdin is not None and process.stdout is not None
                            )
                            process.stdin.write(
                                (
                                    json.dumps(
                                        {
                                            "id": identifier,
                                            "method": method,
                                            "params": params,
                                        }
                                    )
                                    + "\n"
                                ).encode("utf-8")
                            )
                            process.stdin.flush()
                            while True:
                                while b"\n" in buffer:
                                    line, buffer = buffer.split(b"\n", 1)
                                    message = _require_mapping(
                                        _strict_json(line), failure
                                    )
                                    if message.get("id") == identifier:
                                        if "error" in message:
                                            raise AcceptanceError(failure)
                                        return _require_mapping(
                                            message.get("result"), failure
                                        )
                                remaining = deadline - time.monotonic()
                                if remaining <= 0 or not selector.select(remaining):
                                    raise AcceptanceError(failure)
                                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                                received += len(chunk)
                                if not chunk or received > PRIVATE_OUTPUT_LIMIT:
                                    raise AcceptanceError(failure)
                                buffer += chunk

                        request(
                            "initialize",
                            {
                                "clientInfo": {
                                    "name": "memory_behavioral_effort_probe",
                                    "version": "1.0.0",
                                }
                            },
                            1,
                        )
                        process.stdin.write(b'{"method":"initialized","params":{}}\n')
                        process.stdin.flush()
                        cursor: str | None = None
                        seen_cursors: set[str] = set()
                        matches: list[Mapping[str, Any]] = []
                        for identifier in range(2, 12):
                            params: dict[str, object] = {
                                "limit": 250,
                                "includeHidden": True,
                            }
                            if cursor is not None:
                                params["cursor"] = cursor
                            result = request("model/list", params, identifier)
                            rows = result.get("data")
                            if not isinstance(rows, list):
                                raise AcceptanceError(failure)
                            for raw in rows:
                                row = _require_mapping(raw, failure)
                                if row.get("model") == model:
                                    matches.append(row)
                            cursor = result.get("nextCursor")
                            if cursor is None:
                                break
                            if (
                                not isinstance(cursor, str)
                                or not cursor
                                or len(cursor) > 1024
                                or cursor in seen_cursors
                            ):
                                raise AcceptanceError(failure)
                            seen_cursors.add(cursor)
                        else:
                            raise AcceptanceError(failure)
                        if len(matches) != 1:
                            raise AcceptanceError(failure)
                        options = matches[0].get("supportedReasoningEfforts")
                        if not isinstance(options, list) or not options:
                            raise AcceptanceError(failure)
                        efforts: set[str] = set()
                        for raw_option in options:
                            option = _require_mapping(raw_option, failure)
                            effort = _bound_reasoning_effort(
                                {
                                    "client_kind": "codex",
                                    "reasoning_effort": option.get("reasoningEffort"),
                                }
                            )
                            if effort is None or effort in efforts:
                                raise AcceptanceError(failure)
                            efforts.add(effort)
                        return frozenset(efforts)
                finally:
                    signalled = _kill_client_process(process)
                    process.wait(timeout=5)
                    if not signalled or not _client_group_stopped(process.pid):
                        raise AcceptanceError(failure)
        except (
            AcceptanceError,
            CapabilityProbeError,
            OSError,
            subprocess.SubprocessError,
        ):
            raise AcceptanceError(failure) from None


def _validate_bound_reasoning_effort(state: Mapping[str, Any]) -> str | None:
    provenance = _require_mapping(
        state.get("provenance"), "state provenance is missing"
    )
    effort = _bound_reasoning_effort(provenance)
    if effort is not None:
        private = _require_mapping(
            state.get("private"), "private run configuration is missing"
        )
        client = Path(str(private["client_executable"]))
        if effort not in _codex_reasoning_efforts(client, str(provenance["model"])):
            raise AcceptanceError(
                "client model does not support the bound reasoning effort"
            )
    return effort


def _drain_private_stream(source: BinaryIO, target: BinaryIO) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    remaining = PRIVATE_OUTPUT_LIMIT
    while chunk := source.read(64 * 1024):
        if remaining == 0:
            continue
        encoded = decoder.decode(chunk).encode("utf-8")
        retained = encoded[:remaining].decode("utf-8", errors="ignore").encode("utf-8")
        target.write(retained)
        remaining -= len(retained)
    if remaining:
        encoded = decoder.decode(b"", final=True).encode("utf-8")
        retained = encoded[:remaining].decode("utf-8", errors="ignore").encode("utf-8")
        target.write(retained)
    target.flush()
    os.fsync(target.fileno())


def _kill_client_process(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        if _client_group_has_no_live_members(process.pid):
            return True
        try:
            process.kill()
        except OSError:
            pass
        return False
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
        return False
    return True


def _client_group_has_no_live_members(group: int) -> bool:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_process_cleanup import group_has_no_live_members

    return group_has_no_live_members(group)


def _client_group_stopped(group: int) -> bool:
    """Confirm the owned process group disappeared after its leader was reaped."""
    deadline = time.monotonic() + 5
    while True:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return _client_group_has_no_live_members(group)
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _run_client_to_private_files(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    input_text: str | None,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int | float,
    before_cleanup: Callable[[], None] | None = None,
    lifecycle: ClientLifecycle | None = None,
) -> tuple[int, str | None]:
    """Run one client while draining bounded UTF-8 output directly to disk."""
    if lifecycle is not None:
        return lifecycle.run(
            command,
            environment=environment,
            cwd=cwd,
            input_text=input_text,
            response_path=stdout_path,
            stderr_path=stderr_path,
            timeout=timeout,
            before_cleanup=before_cleanup,
        )
    stdout_descriptor = os.open(
        stdout_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        stderr_descriptor = os.open(
            stderr_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        os.close(stdout_descriptor)
        raise
    os.fchmod(stdout_descriptor, 0o600)
    os.fchmod(stderr_descriptor, 0o600)
    with (
        os.fdopen(stdout_descriptor, "wb") as private_stdout,
        os.fdopen(stderr_descriptor, "wb") as private_stderr,
    ):
        try:
            process = subprocess.Popen(
                list(command),
                close_fds=True,
                cwd=str(cwd),
                env=dict(environment),
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            return 1, "client_transport_failed"
        thread_errors: list[Exception] = []
        stdout_thread: threading.Thread | None = None
        stderr_thread: threading.Thread | None = None
        input_thread: threading.Thread | None = None

        def drain(source: BinaryIO, target: BinaryIO) -> None:
            try:
                _drain_private_stream(source, target)
            except Exception as error:
                thread_errors.append(error)
            finally:
                source.close()

        failure_label: str | None = None
        exit_status = 1
        try:
            assert process.stdout is not None
            assert process.stderr is not None
            stdout_thread = threading.Thread(
                target=drain,
                args=(process.stdout, private_stdout),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=drain,
                args=(process.stderr, private_stderr),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            if input_text is not None:
                assert process.stdin is not None
                client_stdin = process.stdin

                def write_input() -> None:
                    try:
                        client_stdin.write(input_text.encode("utf-8"))
                        client_stdin.flush()
                    except BrokenPipeError:
                        pass
                    except OSError as error:
                        thread_errors.append(error)
                    finally:
                        client_stdin.close()

                input_thread = threading.Thread(target=write_input, daemon=True)
                input_thread.start()
            try:
                exit_status = process.wait(timeout=timeout)
            except OSError, subprocess.SubprocessError:
                failure_label = "client_transport_failed"
        finally:
            try:
                if before_cleanup is not None:
                    before_cleanup()
            except Exception:
                failure_label = "client_transport_failed"
            finally:
                signalled = _kill_client_process(process)
                try:
                    process.wait(timeout=5)
                    if not signalled or not _client_group_stopped(process.pid):
                        failure_label = "client_teardown_unverified"
                except OSError, subprocess.SubprocessError:
                    failure_label = "client_teardown_unverified"
                finally:
                    if stdout_thread is not None:
                        stdout_thread.join(timeout=5)
                    elif process.stdout is not None:
                        process.stdout.close()
                    if stderr_thread is not None:
                        stderr_thread.join(timeout=5)
                    elif process.stderr is not None:
                        process.stderr.close()
                    if input_thread is not None:
                        input_thread.join(timeout=5)
                    elif process.stdin is not None:
                        process.stdin.close()
                    if any(
                        thread is not None and thread.is_alive()
                        for thread in (stdout_thread, stderr_thread, input_thread)
                    ):
                        failure_label = "client_teardown_unverified"
        if thread_errors:
            failure_label = failure_label or "client_transport_failed"
        return exit_status, failure_label


def _probe_version(
    executable: Path,
    kind: str | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> str:
    completed = (
        _run_metadata([str(executable), "--version"])
        if environment is None
        else _run_text([str(executable), "--version"], environment=environment, cwd=cwd)
    )
    if completed.returncode != 0 or not completed.stdout:
        raise AcceptanceError("version probe failed")
    version = completed.stdout.strip().splitlines()[0]
    if kind is not None and CLIENT_VERSION_PATTERNS[kind].fullmatch(version) is None:
        raise AcceptanceError("client version does not match its declared kind")
    return version


def _installed_digests(memory: Path) -> tuple[str, str]:
    interpreter = memory.parent / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise AcceptanceError("installed Memory interpreter was not found")
    program = (
        "import json;"
        "from memory.mcp_server import contract_digest,skill_digest;"
        "print(json.dumps({'mcp':contract_digest(),'skill':skill_digest()}))"
    )
    completed = _run_metadata([str(interpreter), "-I", "-c", program])
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise AcceptanceError("installed contract digest probe failed") from error
    if (
        completed.returncode != 0
        or not isinstance(payload, Mapping)
        or DIGEST.fullmatch(str(payload.get("mcp"))) is None
        or DIGEST.fullmatch(str(payload.get("skill"))) is None
    ):
        raise AcceptanceError("installed contract digest probe failed")
    return str(payload["mcp"]), str(payload["skill"])


def _sha256_file(path: Path) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise AcceptanceError("build artifact must be one absolute regular file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_distribution_digest(memory: Path, build_artifact: Path) -> str:
    """Verify that the installed Memory files came from the exact wheel."""
    interpreter = memory.parent / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise AcceptanceError("installed Memory interpreter was not found")
    program = r"""
import base64
import csv
import hashlib
import io
import json
import sys
import zipfile
from importlib.metadata import distribution
from pathlib import Path, PurePosixPath

matched = False
distribution_digest = None
try:
    artifact = Path(sys.argv[1])
    installed = distribution("memory")
    entries = []
    with zipfile.ZipFile(artifact) as wheel:
        records = [
            name
            for name in wheel.namelist()
            if name.endswith(".dist-info/RECORD")
            and name.rsplit("/", 1)[0].rsplit("/", 1)[-1].startswith("memory-")
        ]
        if len(records) != 1:
            raise ValueError
        rows = csv.reader(io.TextIOWrapper(wheel.open(records[0]), encoding="utf-8"))
        matched = True
        for name, encoded_digest, _size in rows:
            if not encoded_digest.startswith("sha256="):
                continue
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts:
                matched = False
                break
            wheel_bytes = wheel.read(name)
            wheel_digest = hashlib.sha256(wheel_bytes).digest()
            expected = encoded_digest.removeprefix("sha256=")
            expected += "=" * (-len(expected) % 4)
            if wheel_digest != base64.urlsafe_b64decode(expected):
                matched = False
                break
            installed_path = installed.locate_file(name)
            if not installed_path.is_file() or installed_path.is_symlink():
                matched = False
                break
            installed_digest = hashlib.sha256(installed_path.read_bytes()).digest()
            if installed_digest != wheel_digest:
                matched = False
                break
            entries.append(f"{name}:{wheel_digest.hex()}")
        if matched and entries:
            distribution_digest = hashlib.sha256(
                "\n".join(sorted(entries)).encode("utf-8")
            ).hexdigest()
        else:
            matched = False
except Exception:
    matched = False
print(json.dumps({"matched": matched, "distribution_digest": distribution_digest}))
"""
    completed = _run_metadata(
        [str(interpreter), "-I", "-c", program, str(build_artifact)]
    )
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise AcceptanceError("installed distribution probe failed") from error
    digest = (
        payload.get("distribution_digest") if isinstance(payload, Mapping) else None
    )
    if (
        completed.returncode != 0
        or not isinstance(payload, Mapping)
        or payload.get("matched") is not True
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
    ):
        raise AcceptanceError("installed distribution does not match build artifact")
    return digest


def _revalidate_prepared_artifacts(state: Mapping[str, Any]) -> None:
    state = effective_execution_state(state)
    private = _require_mapping(
        state.get("private"), "private run configuration is missing"
    )
    provenance = _require_mapping(
        state.get("provenance"), "state provenance is missing"
    )
    memory = Path(str(private.get("memory_executable")))
    client = Path(str(private.get("client_executable")))
    build_artifact = Path(str(private.get("build_artifact")))
    seed_value = private.get("seed_executable")
    seed = None if seed_value is None else Path(str(seed_value))
    expected = {
        "client_executable_digest": _sha256_file(client),
        "memory_executable_digest": _sha256_file(memory),
        "build_digest": _sha256_file(build_artifact),
    }
    if any(provenance.get(key) != value for key, value in expected.items()):
        raise AcceptanceError("prepared artifact changed")
    if _bound_isolation_provenance(provenance):
        authentication = _bound_authentication_provenance(provenance)
        if authentication:
            if (
                authentication["authentication_adapter_digest"]
                != _subscription_implementation_digest()
            ):
                raise AcceptanceError("prepared artifact changed")
            binding = _codex_artifact_binding(
                client, authentication_mode=authentication["authentication_mode"]
            )
        else:
            binding = _codex_artifact_binding(client)
        if any(provenance.get(key) != value for key, value in binding.items()):
            raise AcceptanceError("prepared artifact changed")
    expected_seed = provenance.get("seed_executable_digest")
    if seed is None:
        if expected_seed != "not_present":
            raise AcceptanceError("prepared artifact changed")
    elif expected_seed != _sha256_file(seed):
        raise AcceptanceError("prepared artifact changed")
    distribution_digest = _installed_distribution_digest(memory, build_artifact)
    if provenance.get("installed_distribution_digest") != distribution_digest:
        raise AcceptanceError("prepared artifact changed")


def _write_state(
    root: Path,
    state: Mapping[str, Any],
    *,
    expected_state_digest: str | None = None,
) -> None:
    _validate_fixed_roster(state)
    _behavioral_helper_path()
    from behavioral_continuation import (
        ContinuationError,
        check_write_progress,
        read_private_bytes,
        state_write_lock,
    )

    path = root / STATE_FILENAME
    temporary = root / f".{STATE_FILENAME}.new"
    created = False
    try:
        with state_write_lock(root):
            previous: Mapping[str, Any] | None = None
            if path.exists() or path.is_symlink():
                raw = read_private_bytes(path)
                previous = _require_mapping(_strict_json(raw), "saved state is invalid")
                if (
                    expected_state_digest is not None
                    and hashlib.sha256(raw).hexdigest() != expected_state_digest
                ):
                    raise AcceptanceError(
                        "acceptance state changed before continuation"
                    )
                check_write_progress(previous, state)
            elif expected_state_digest is not None:
                raise AcceptanceError(
                    "acceptance state disappeared before continuation"
                )
            if (
                previous is not None
                and "continuation" not in previous
                and "continuation" in state
                and expected_state_digest is None
            ):
                raise AcceptanceError(
                    "continuation requires a stale-checked state write"
                )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            created = True
            with os.fdopen(descriptor, "w", encoding="utf-8") as target:
                json.dump(state, target, ensure_ascii=False, sort_keys=True)
                target.write("\n")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            created = False
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except ContinuationError:
        raise AcceptanceError("acceptance state write is unavailable") from None
    finally:
        if created and temporary.exists():
            temporary.unlink()
    os.chmod(path, 0o600)


def _read_state(root: Path) -> dict[str, Any]:
    path = root / STATE_FILENAME
    if (
        not path.is_file()
        or path.is_symlink()
        or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        raise AcceptanceError("private acceptance state is unavailable")
    payload = _strict_json(path.read_bytes())
    if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
        raise AcceptanceError("private acceptance state is invalid")
    _validate_fixed_roster(payload)
    return payload


def _status(memory: Path, home: Path) -> dict[str, Any]:
    completed = _run_text([str(memory), "status", "--home", str(home), "--json"])
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise AcceptanceError("installed Store status failed") from error
    if completed.returncode != 0 or not isinstance(payload, dict):
        raise AcceptanceError("installed Store status failed")
    if any(key not in payload for key in STATUS_FIELDS):
        raise AcceptanceError("installed Store status was incomplete")
    return payload


def _owner_audit_generation(memory: Path, home: Path) -> int:
    """Read one generation through the installed owner snapshot API."""
    interpreter = memory.parent / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise AcceptanceError("installed Memory interpreter was not found")
    program = (
        "import json,sys;"
        "from pathlib import Path;"
        "from memory.runtime import resolve_runtime;"
        "from memory.ui.service import OwnerApplicationService;"
        "snapshot=OwnerApplicationService(resolve_runtime(Path(sys.argv[1])))"
        ".begin_audit_snapshot();"
        "print(json.dumps({'audit_generation':snapshot.generation}))"
    )
    completed = _run_text([str(interpreter), "-I", "-c", program, str(home)], cwd=home)
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise AcceptanceError("installed owner snapshot probe failed") from error
    generation = (
        payload.get("audit_generation") if isinstance(payload, Mapping) else None
    )
    if (
        completed.returncode != 0
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
    ):
        raise AcceptanceError("installed owner snapshot probe failed")
    return generation


def _store_snapshot(memory: Path, home: Path) -> dict[str, Any]:
    snapshot = _status(memory, home)
    snapshot["audit_generation"] = _owner_audit_generation(memory, home)
    return snapshot


def _private_prompt(case: Mapping[str, Any], skill: Path) -> str:
    skill_text = skill.read_text(encoding="utf-8")
    return (
        "Follow the exact packaged using-memory Skill included below. Use only the "
        "Memory MCP configured for this disposable synthetic trial. No local file "
        "access is needed or permitted. This is read-only advice: do not "
        "scan an inbox, create or edit a review, apply anything, or save any answer. "
        "Retrieve enough complete retained evidence, apply governing caveats and "
        "freshness, distinguish uncertainty, and answer the question directly.\n\n"
        f"<using-memory-skill>\n{skill_text}</using-memory-skill>\n\n"
        f"Synthetic question: {case['question_variant']}\n"
    )


def _fixture_call(
    memory: Path, home: Path, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Use the installed public MCP dispatcher with an explicit disposable home."""
    if name not in {
        "store.status",
        "source.list",
        "source.read",
        "inbox.scan",
        "inbox.read",
        "change_set.create",
        "change_set.edit",
        "change_set.get",
        "memory.search",
        "memory.get",
    }:
        raise AcceptanceError("fixture operation is outside preparation")
    program = (
        "import json,sys;from pathlib import Path;"
        "from memory.runtime import resolve_runtime;"
        "from memory.mcp_server import call_tool;"
        "request=json.load(sys.stdin);"
        "print(json.dumps(call_tool(resolve_runtime(Path(sys.argv[1])),"
        "request['name'],request['arguments'])['structuredContent']))"
    )
    completed = _run_text(
        [str(memory.parent / "python"), "-I", "-c", program, str(home)],
        cwd=home,
        input_text=json.dumps({"name": name, "arguments": arguments}),
    )
    envelope = _strict_json(completed.stdout.encode("utf-8"))
    if (
        completed.returncode != 0
        or not isinstance(envelope, dict)
        or "error" in envelope
    ):
        raise AcceptanceError("installed fixture operation failed")
    return envelope


def _fixture_groups(case: Mapping[str, Any]) -> list[list[dict[str, Any]]]:
    memories = case["seed_profile"]["memories"]
    groups = [
        [
            memory
            for memory in memories
            if memory["revision_role"] != "approved_correction"
        ],
        [
            memory
            for memory in memories
            if memory["revision_role"] == "approved_correction"
        ],
    ]
    return [group for group in groups if group]


def _fixture_fields(fixture: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": "fact",
        "statement": fixture["statement"],
        "tags": fixture["tags"],
        "sensitivity": "normal",
        "valid_from": fixture["valid_from"],
        "valid_to": fixture["valid_to"],
    }


def _fixture_current(
    memory: Path,
    home: Path,
    fixtures: Sequence[Mapping[str, Any]],
    phases: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Verify complete source custody, exact revisions, guards, and lineage."""
    sources = _fixture_call(memory, home, "source.list", {"limit": 100})
    if sources.get("page", {}).get("has_more") or len(sources["data"]) != len(fixtures):
        raise AcceptanceError("fixture Store source roster changed")
    by_source = {source["source_id"]: source for source in sources["data"]}
    fixture_sources = {
        fixture_id: source_id
        for phase in phases
        for fixture_id, source_id in phase["sources"].items()
    }
    for fixture in fixtures:
        source = by_source.get(fixture_sources.get(fixture["fixture_id"]))
        expected_digest = hashlib.sha256(
            fixture["source_text"].encode("utf-8")
        ).hexdigest()
        if source is None or source["blob_digest"] != expected_digest:
            raise AcceptanceError("fixture Store source evidence changed")
        chunk = _fixture_call(
            memory, home, "source.read", {"source_id": source["source_id"]}
        )["data"]
        if (
            chunk.get("complete") is not True
            or chunk.get("text") != fixture["source_text"]
        ):
            raise AcceptanceError("fixture Store complete source changed")
    hits = _fixture_call(memory, home, "memory.search", {"limit": 100})
    lineage_refs = {fixture["lineage_ref"] for fixture in fixtures}
    if hits.get("page", {}).get("has_more") or len(hits["data"]) != len(lineage_refs):
        raise AcceptanceError("fixture Store memory roster changed")
    details: dict[str, dict[str, Any]] = {}
    for hit in hits["data"]:
        detail = _fixture_call(
            memory, home, "memory.get", {"memory_id": hit["memory"]["memory_id"]}
        )["data"]
        for revision_id in detail["revision_ids"]:
            details[revision_id] = (
                detail
                if revision_id == detail["revision"]["memory_id"]
                else _fixture_call(
                    memory, home, "memory.get", {"memory_id": revision_id}
                )["data"]
            )
    if len(details) != len(fixtures):
        raise AcceptanceError("fixture Store revision history changed")
    matched: dict[str, dict[str, Any]] = {}
    for fixture in fixtures:
        candidates = [
            detail
            for detail in details.values()
            if detail["revision"]["statement"] == fixture["statement"]
        ]
        if len(candidates) != 1:
            raise AcceptanceError("fixture Store statement changed")
        detail = candidates[0]
        revision = detail["revision"]
        expected = _fixture_fields(fixture)
        for field in ("kind", "statement", "tags", "valid_from", "valid_to"):
            if revision.get(field) != expected[field]:
                raise AcceptanceError("fixture Store memory fields changed")
        if (
            revision.get("occurred_on") is not None
            or revision["stored_sensitivity"] != "normal"
            or revision["effective_sensitivity"] != "normal"
        ):
            raise AcceptanceError("fixture Store memory metadata changed")
        evidence = detail["evidence"]
        if (
            len(evidence) != 1
            or evidence[0]["source_id"] != fixture_sources[fixture["fixture_id"]]
            or evidence[0].get("excerpt") != fixture["evidence_excerpt"]
        ):
            raise AcceptanceError("fixture Store memory evidence changed")
        matched[fixture["fixture_id"]] = detail
    current: dict[str, dict[str, Any]] = {}
    for lineage in lineage_refs:
        members = [fixture for fixture in fixtures if fixture["lineage_ref"] == lineage]
        member_details = [matched[fixture["fixture_id"]] for fixture in members]
        ids = [detail["revision"]["memory_id"] for detail in member_details]
        for index, detail in enumerate(member_details):
            if (
                detail["revision_ids"] != ids
                or detail["is_current"] != (index == len(ids) - 1)
                or detail.get("predecessor_id")
                != (None if index == 0 else ids[index - 1])
            ):
                raise AcceptanceError("fixture Store correction lineage changed")
        current[lineage] = member_details[-1]
    for fixture in fixtures:
        detail = matched[fixture["fixture_id"]]
        expected_guards = {
            current[guard["lineage_ref"]]["revision"]["lineage_id"]
            for guard in fixtures
            if guard["guard_of"] == fixture["lineage_ref"]
        }
        if {guard["lineage_id"] for guard in detail["guards"]} != expected_guards:
            raise AcceptanceError("fixture Store governing guards changed")
    return current


def advance_fixture_preparation(
    memory: Path,
    home: Path,
    case: Mapping[str, Any],
    phases: list[dict[str, Any]],
    *,
    validate_fixture_home: Callable[[Path], Path] | None = None,
) -> str:
    """Prepare at most one exact review; approval is always a separate owner act."""
    if validate_fixture_home is None:
        _private_root(home)
    elif validate_fixture_home(home) != home:
        raise AcceptanceError("campaign fixture home does not match its allocation")
    identity = _require_mapping(
        _strict_json((home / "runtime.json").read_bytes()),
        "fixture Store identity is invalid",
    )
    if (
        identity.get("inbox_path") != str(home / "inbox")
        or identity.get("product") != "memory"
        or identity.get("runtime_mode") != "personal"
        or identity.get("schema_lineage") != "memory-store-v1"
        or identity.get("schema_version") != 1
    ):
        raise AcceptanceError("fixture Store identity is invalid")
    groups = _fixture_groups(case)
    if len(phases) > len(groups):
        raise AcceptanceError("fixture Store has extra preparation phases")
    status = _fixture_call(memory, home, "store.status", {})["data"]
    if (
        status["store_id"] != identity.get("store_id")
        or status["source_count"] != sum(len(group) for group in groups[: len(phases)])
        or status["reindex_required"]
    ):
        raise AcceptanceError("fixture Store contains unaccounted data")
    if not phases and (status["memory_count"] or status["pending_review_count"]):
        raise AcceptanceError("fixture Store is not empty")
    for index, phase in enumerate(phases):
        if phase["fixture_ids"] != [fixture["fixture_id"] for fixture in groups[index]]:
            raise AcceptanceError("fixture Store phase roster changed")
        view = _fixture_call(
            memory, home, "change_set.get", {"change_set_id": phase["change_set_id"]}
        )["data"]
        if any(
            view[key] != phase[key]
            for key in ("change_set_id", "revision_id", "digest", "batch_id")
        ):
            raise AcceptanceError("fixture Store exact review changed")
        if view["state"] != "applied":
            return "owner_presence_prerequisite"
    existing = [fixture for group in groups[: len(phases)] for fixture in group]
    current = _fixture_current(memory, home, existing, phases)
    if len(phases) == len(groups):
        if status["pending_review_count"]:
            raise AcceptanceError("fixture Store has an unexpected pending review")
        return "ready"
    inbox = home / "inbox"
    if inbox.is_symlink() or not inbox.is_dir() or any(inbox.iterdir()):
        raise AcceptanceError("fixture Store inbox is not empty")
    group = groups[len(phases)]
    for fixture in group:
        target = inbox / f"{fixture['fixture_id']}.txt"
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(fixture["source_text"])
    batch = _fixture_call(
        memory, home, "inbox.scan", {"authorship": "owner", "sensitivity": "normal"}
    )["data"]
    if (
        batch["source_count"] != len(group)
        or batch["batch_has_more"]
        or any(inbox.iterdir())
    ):
        raise AcceptanceError("fixture Store capture was incomplete")
    captured = _fixture_call(
        memory, home, "inbox.read", {"batch_id": batch["batch_id"]}
    )["data"]["sources"]
    by_digest = {source["blob_digest"]: source for source in captured}
    view = _fixture_call(
        memory, home, "change_set.create", {"batch_id": batch["batch_id"]}
    )["data"]
    edits = []
    sources = {}
    for fixture in group:
        digest = hashlib.sha256(fixture["source_text"].encode("utf-8")).hexdigest()
        source = by_digest.get(digest)
        if source is None:
            raise AcceptanceError("fixture Store capture differs from manifest")
        sources[fixture["fixture_id"]] = source["source_id"]
        fields = _fixture_fields(fixture)
        if fixture["revision_role"] == "approved_correction":
            predecessor = current[fixture["lineage_ref"]]["revision"]
            fields.update(
                target_lineage_id=predecessor["lineage_id"],
                expected_head_id=predecessor["memory_id"],
            )
        edits.append(
            {
                "op": "add_item",
                "client_item_id": fixture["fixture_id"],
                "memory": fields,
                "evidence": [
                    {
                        "source_id": source["source_id"],
                        "blob_digest": digest,
                        "excerpt": fixture["evidence_excerpt"],
                    }
                ],
            }
        )
    for fixture in group:
        if fixture["guard_of"] is not None:
            governed = next(
                item for item in group if item["lineage_ref"] == fixture["guard_of"]
            )
            edits.append(
                {
                    "op": "add_guard_link",
                    "guard_item_id": fixture["fixture_id"],
                    "governed_item_id": governed["fixture_id"],
                }
            )
    view = _fixture_call(
        memory,
        home,
        "change_set.edit",
        {
            "change_set_id": view["change_set_id"],
            "expected_revision_id": view["revision_id"],
            "edits": edits,
        },
    )["data"]
    phases.append(
        {
            **{
                key: view[key]
                for key in ("change_set_id", "revision_id", "digest", "batch_id")
            },
            "fixture_ids": [fixture["fixture_id"] for fixture in group],
            "sources": sources,
        }
    )
    return "owner_presence_prerequisite"


def _client_environment(kind: str) -> dict[str, str]:
    """Keep transport inputs only; homes and explicit auth are supplied separately."""
    common = {
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TMPDIR",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    }
    environment = {key: os.environ[key] for key in common if key in os.environ}
    if kind == "claude":
        environment["CLAUDE_CODE_SKIP_PROMPT_HISTORY"] = "1"
    return environment


def _client_authentication(kind: str) -> dict[str, str]:
    """Forward explicit client-scoped auth without reading saved credentials."""
    names = (
        ("CODEX_API_KEY",)
        if kind == "codex"
        else ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")
    )
    values = {
        name: value
        for name in names
        if (value := os.environ.get(name)) is not None and value.strip()
    }
    if not values:
        raise TrialBlocked("client_authentication_unavailable")
    return values


def _subscription_implementation_digest() -> str:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_auth import implementation_digest

    return implementation_digest()


def _subscription_session(state: Mapping[str, Any]) -> ScopedSession:
    state = effective_execution_state(state)
    private = _require_mapping(state.get("private"), "run configuration is missing")
    if not _bound_authentication_provenance(state["provenance"]):
        raise TrialBlocked("subscription_authentication_unbound")
    try:
        return _validated_subscription_session(
            Path(str(private.get("subscription_auth_root"))),
            Path(str(private["client_executable"])),
        )
    except AcceptanceError:
        raise TrialBlocked("subscription_authentication_unavailable") from None


def _validated_subscription_session(root: Path, client: Path) -> ScopedSession:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_auth import AuthError, load_session, validate_session

    try:
        session = load_session(root, client)
        validate_session(session)
    except AuthError, OSError:
        raise AcceptanceError("subscription authentication is unavailable") from None
    return session


@contextmanager
def _subscription_lease(
    session: ScopedSession, client_home: Path
) -> Iterator[CredentialLease]:
    from behavioral_codex_auth import AuthError, stage_credentials

    try:
        with stage_credentials(session, client_home) as lease:
            yield lease
    except AuthError, OSError:
        raise AcceptanceError("subscription credential custody failed") from None


def _codex_artifact_binding(
    client: Path, *, authentication_mode: str | None = None
) -> dict[str, str]:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_isolation import CapabilityProbeError, artifact_binding

    try:
        binding = (
            artifact_binding(client)
            if authentication_mode is None
            else artifact_binding(client, authentication_mode=authentication_mode)
        )
    except CapabilityProbeError:
        raise AcceptanceError("client isolation artifacts are unavailable") from None
    return {
        "client_executable_digest": binding.client_executable_digest,
        "code_mode_host_digest": binding.code_mode_host_digest,
        "isolation_profile_digest": binding.isolation_profile_digest,
    }


def _codex_capability_probe(
    client: Path,
    model: str,
    effort: str | None,
    *,
    authentication_mode: str | None = None,
) -> dict[str, object]:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_isolation import CapabilityProbeError, verify_capabilities

    try:
        if authentication_mode is None:
            return verify_capabilities(
                client, model=model, reasoning_effort=effort
            ).to_public_dict()
        return verify_capabilities(
            client,
            model=model,
            reasoning_effort=effort,
            authentication_mode=authentication_mode,
        ).to_public_dict()
    except CapabilityProbeError:
        raise AcceptanceError("client capability probe is unavailable") from None


def _require_codex_capabilities(state: Mapping[str, Any]) -> dict[str, object]:
    state = effective_execution_state(state)
    provenance = _require_mapping(state.get("provenance"), "run provenance is missing")
    binding = _bound_isolation_provenance(provenance)
    if not binding:
        raise TrialBlocked("client_isolation_profile_unbound")
    private = _require_mapping(state.get("private"), "run configuration is missing")
    effort = _bound_reasoning_effort(provenance)
    authentication = _bound_authentication_provenance(provenance)
    try:
        if authentication:
            result = _codex_capability_probe(
                Path(str(private["client_executable"])),
                str(provenance["model"]),
                effort,
                authentication_mode=authentication["authentication_mode"],
            )
        else:
            result = _codex_capability_probe(
                Path(str(private["client_executable"])),
                str(provenance["model"]),
                effort,
            )
    except AcceptanceError:
        raise TrialBlocked("client_isolation_controls_unavailable") from None
    expected = {
        **binding,
        **authentication,
        "client_executable_digest": provenance["client_executable_digest"],
        "schema": "memory.behavioral-capability-probe.v1",
        "client_kind": "codex",
        "model": provenance["model"],
        "reasoning_effort": effort,
        "outcome_label": "client_executor_capabilities_confirmed",
    }
    if result.get("capabilities_confirmed") is not True or any(
        result.get(key) != value for key, value in expected.items()
    ):
        raise TrialBlocked("client_isolation_controls_unavailable")
    return result


def _codex_launch_arguments(
    client: Path,
    workspace: Path,
    model: str,
    effort: str | None,
    *,
    authentication_mode: str | None = None,
) -> list[str]:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_isolation import launch_arguments

    if authentication_mode is None:
        return launch_arguments(client, workspace, model=model, reasoning_effort=effort)
    return launch_arguments(
        client,
        workspace,
        model=model,
        reasoning_effort=effort,
        authentication_mode=authentication_mode,
    )


@contextmanager
def _codex_execution_command(
    client: Path,
    memory: Path,
    home: Path,
    workspace: Path,
    model: str,
    effort: str | None,
    *,
    authentication_mode: str | None = None,
    credential_homes: Sequence[Path] = (),
    credential_canary: Path | None = None,
    public_ca_bundle: Path | None = None,
    events_path: Path | None = None,
    observe_lifecycle: Callable[[ClientLifecycle], None] | None = None,
) -> Iterator[ClientLaunch]:
    """Keep the client restricted while its exact synthetic MCP runs separately."""
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_client_lifecycle import ClientLifecycle, LifecycleError
    from behavioral_codex_isolation import (
        CapabilityProbeError,
        execution_command,
        system_python,
    )
    from behavioral_mcp_bridge import BridgeError, MCPBridge
    from behavioral_memory_endpoint import EndpointError, endpoint_environment

    bridge: MCPBridge | None = None
    lifecycle: ClientLifecycle | None = None
    try:
        lifecycle = ClientLifecycle(events_path or workspace / "client-events.private")
        if observe_lifecycle is not None:
            observe_lifecycle(lifecycle)
        subscription = authentication_mode == "chatgpt_subscription"
        if (
            authentication_mode not in {None, "chatgpt_subscription"}
            or subscription != bool(credential_homes)
            or subscription != (credential_canary is not None)
            or subscription != (public_ca_bundle is not None)
            or (public_ca_bundle is not None and not public_ca_bundle.is_absolute())
        ):
            raise AcceptanceError("isolated subscription boundary is incomplete")
        python = system_python()
        environment = endpoint_environment(workspace)
        endpoint = [str(memory), "mcp", "--home", str(home)]
        endpoint_policy = workspace / "endpoint-policy.private.sb"
        if subscription:
            from behavioral_codex_isolation import endpoint_command

            endpoint = endpoint_command(
                endpoint, policy_path=endpoint_policy, credential_homes=credential_homes
            )
            bridge = MCPBridge(
                root=workspace,
                endpoint_command=endpoint,
                endpoint_environment=environment,
                endpoint_cwd=workspace,
                proxy_python=python,
                credential_homes=credential_homes,
                credential_canary=credential_canary,
                completion_probe=lifecycle.completion_probe,
            )
        else:
            bridge = MCPBridge(
                root=workspace,
                endpoint_command=endpoint,
                endpoint_environment=environment,
                endpoint_cwd=workspace,
                proxy_python=python,
                completion_probe=lifecycle.completion_probe,
            )
        with bridge:
            command = (
                _codex_launch_arguments(
                    client,
                    workspace,
                    model,
                    effort,
                    authentication_mode=authentication_mode,
                )
                if subscription
                else _codex_launch_arguments(client, workspace, model, effort)
            )
            command.extend(
                [
                    "-c",
                    "mcp_servers.memory_behavioral_acceptance.command="
                    + json.dumps(bridge.proxy_command[0]),
                    "-c",
                    "mcp_servers.memory_behavioral_acceptance.args="
                    + json.dumps(bridge.proxy_command[1:]),
                    "-c",
                    "mcp_servers.memory_behavioral_acceptance.required=true",
                    "-c",
                    'mcp_servers.memory_behavioral_acceptance.default_tools_approval_mode="auto"',
                    "-",
                ]
            )
            protected = execution_command(
                command,
                policy_path=workspace / "client-policy.private.sb",
                executable_paths=tuple(
                    dict.fromkeys(
                        (
                            client,
                            client.parent / "codex-code-mode-host",
                            python,
                            *bridge.proxy_executable_paths,
                        )
                    )
                ),
                bridge_socket=bridge.unix_socket_path,
                readable_proxy_files=(
                    *bridge.proxy_read_paths,
                    *((endpoint_policy,) if subscription else ()),
                    *((public_ca_bundle,) if public_ca_bundle is not None else ()),
                ),
                memory_home=home,
                endpoint_environment_root=workspace / ".mcp-endpoint-home",
                credential_homes=credential_homes,
                credential_client=client if subscription else None,
            )

            def finish_client() -> None:
                try:
                    if lifecycle.natural_exit_zero:
                        bridge.finish_client()
                    else:
                        bridge.close()
                finally:
                    lifecycle.record_transport(bridge.lifecycle_metadata)

            try:
                yield ClientLaunch(protected, finish_client, lifecycle)
                if not bridge.wait(timeout=5):
                    raise AcceptanceError(
                        "isolated client MCP transport did not finish"
                    )
            finally:
                lifecycle.record_transport(bridge.lifecycle_metadata)
        # Closing the bridge reaps its endpoint before the advice after-snapshot.
        if (
            bridge.failure_label is not None
            or not bridge.client_completion_confirmed
            or not lifecycle.client_completion_confirmed
            or not bridge.process_cleanup_confirmed
            or not bridge.resources_cleanup_confirmed
            or not bridge.endpoint_started
            or bridge.proxy_auth_environment_absent is not True
            or (subscription and bridge.proxy_environment_isolated is not True)
            or (subscription and bridge.proxy_auth_home_denied is not True)
        ):
            raise AcceptanceError("isolated client MCP transport failed")
    except CapabilityProbeError, BridgeError, EndpointError, LifecycleError, OSError:
        raise AcceptanceError("isolated client transport is unavailable") from None
    finally:
        if lifecycle is not None and bridge is not None:
            lifecycle.record_transport(bridge.lifecycle_metadata)
            endpoint_process = bridge.endpoint_process_metadata
            cleanup_paths = bridge.cleanup_paths
            if endpoint_process is not None or cleanup_paths:
                lifecycle.record_recovery(
                    {
                        "endpoint_process": dict(endpoint_process)
                        if endpoint_process is not None
                        else None,
                        "cleanup_paths": [str(path) for path in cleanup_paths],
                        "process_cleanup_confirmed": bridge.process_cleanup_confirmed,
                        "resources_cleanup_confirmed": bridge.resources_cleanup_confirmed,
                    }
                )


def _require_prepared_artifacts(state: Mapping[str, Any]) -> None:
    try:
        _revalidate_prepared_artifacts(state)
    except AcceptanceError:
        raise TrialBlocked("prepared_artifact_changed") from None


def _codex_isolation_states(client: Path, workspace: Path) -> dict[str, bool] | None:
    probe_home = workspace / ".codex-feature-probe"
    probe_home.mkdir(mode=0o700)
    environment = _client_environment("codex")
    for key in ("HOME", "CODEX_HOME", "OPENAI_API_KEY"):
        environment.pop(key, None)
    environment["HOME"] = str(probe_home)
    environment["CODEX_HOME"] = str(probe_home)
    command = [
        str(client),
        "-c",
        "sandbox_permissions=[]",
        "-c",
        "shell_environment_policy.inherit=none",
    ]
    for feature in CODEX_DISABLED_FEATURES:
        command.extend(("--disable", feature))
    command.extend(("features", "list"))
    try:
        completed = _run_text(
            command,
            environment=environment,
            cwd=workspace,
        )
    finally:
        shutil.rmtree(probe_home)
    if completed.returncode != 0:
        return None
    required = set(CODEX_DISABLED_FEATURES)
    states: dict[str, bool] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] not in required:
            continue
        if len(parts) < 3 or parts[0] in states or parts[-1] not in {"true", "false"}:
            return None
        states[parts[0]] = parts[-1] == "true"
    return states


def _codex_isolation_controls_supported(client: Path, workspace: Path) -> bool:
    states = _codex_isolation_states(client, workspace)
    return (
        states is not None
        and set(states) == set(CODEX_DISABLED_FEATURES)
        and not any(states.values())
    )


def probe_client_isolation(client: Path, kind: str, root: Path) -> dict[str, Any]:
    """Inspect client metadata without an auth input, Store, session, or trial."""
    if kind != "codex":
        raise AcceptanceError("automatic control-state probing supports Codex only")
    client = _validate_executable(client)
    _private_root(root, require_empty=True)
    workspace = _private_directory(root, "client-probe")
    version_home = _private_directory(workspace, "version-home")
    environment = _client_environment(kind)
    for key in ("HOME", "CODEX_HOME", "OPENAI_API_KEY"):
        environment.pop(key, None)
    environment.update(HOME=str(version_home), CODEX_HOME=str(version_home))
    version = _probe_version(client, kind, environment=environment, cwd=workspace)
    states = _codex_isolation_states(client, workspace)
    honored = (
        []
        if states is None
        else [
            feature
            for feature in CODEX_DISABLED_FEATURES
            if states.get(feature) is False
        ]
    )
    missing = [feature for feature in CODEX_DISABLED_FEATURES if feature not in honored]
    return {
        "schema": "memory.behavioral-prerequisite-probe.v1",
        "client_kind": kind,
        "client_version": version,
        "client_executable_digest": _sha256_file(client),
        "required_controls": len(CODEX_DISABLED_FEATURES),
        "confirmed_disabled_controls": len(honored),
        "unhonored_controls": missing,
        "outcome_label": "client_isolation_controls_unavailable"
        if missing
        else "client_isolation_controls_confirmed",
        "inference_launched": False,
        "behavioral_slots_created": 0,
    }


def _actual_executor(
    state: Mapping[str, Any],
    manifest: Manifest,
    *,
    persist: Callable[[], None] | None = None,
    validate_fixture_home: Callable[[Mapping[str, Any], Path], Path] | None = None,
) -> TrialExecutor:
    if _continuation_info(state) is None:
        if validate_fixture_home is None:
            return _actual_executor_bound(state, manifest, persist=persist)
        return _actual_executor_bound(
            state,
            manifest,
            persist=persist,
            validate_fixture_home=validate_fixture_home,
        )

    def execute(
        case: dict[str, Any],
        trial: int,
        home: Path,
        workspace: Path,
        response_path: Path,
    ) -> dict[str, Any]:
        view = effective_execution_state(state, slot_id=f"{case['case_id']}:{trial}")
        # The view shares the slots; this callback always persists original state.
        if validate_fixture_home is None:
            executor = _actual_executor_bound(view, manifest, persist=persist)
        else:
            executor = _actual_executor_bound(
                view,
                manifest,
                persist=persist,
                validate_fixture_home=validate_fixture_home,
            )
        return executor(case, trial, home, workspace, response_path)

    return execute


def _actual_executor_bound(
    state: Mapping[str, Any],
    manifest: Manifest,
    *,
    persist: Callable[[], None] | None = None,
    validate_fixture_home: Callable[[Mapping[str, Any], Path], Path] | None = None,
) -> TrialExecutor:
    private = _require_mapping(
        state.get("private"), "private run configuration is missing"
    )
    memory = Path(str(private["memory_executable"]))
    client = Path(str(private["client_executable"]))
    seed_value = private.get("seed_executable")
    seed = None if seed_value is None else Path(str(seed_value))
    kind = str(state["provenance"]["client_kind"])
    model = str(state["provenance"]["model"])

    def execute(
        case: dict[str, Any],
        _trial: int,
        home: Path,
        workspace: Path,
        response_path: Path,
    ) -> dict[str, Any]:
        slot = next(
            (
                slot
                for slot in state.get("slots", [])
                if slot["case_id"] == case["case_id"] and slot["trial"] == _trial
            ),
            None,
        )
        if slot is not None:
            slot["inference_started"] = False
            slot["client_launch_attempted"] = False
        _require_prepared_artifacts(state)
        try:
            reasoning_effort = _validate_bound_reasoning_effort(state)
        except AcceptanceError:
            raise TrialBlocked("client_reasoning_effort_unavailable") from None
        owner_review = state["provenance"].get("seed_mode") == "owner_review"
        if owner_review:
            preparation = None if slot is None else slot.get("fixture_preparation")
            if preparation != "ready":
                raise TrialBlocked(preparation or "fixture_preparation_required")
        if kind == "codex":
            proof = _require_codex_capabilities(state)
            if slot is not None:
                slot["capability_probe"] = proof
                if persist is not None:
                    persist()
        authentication_binding = _bound_authentication_provenance(state["provenance"])
        subscription = _subscription_session(state) if authentication_binding else None
        authentication = (
            {} if subscription is not None else _client_authentication(kind)
        )
        if owner_review:
            assert slot is not None
            _require_fixture_owner(state, slot, home)
            if len(slot["fixture_phases"]) != len(_fixture_groups(case)):
                raise TrialBlocked("fixture_preparation_required")
            validator = validate_fixture_home
            if validator is None:
                prepared = advance_fixture_preparation(
                    memory, home, case, slot["fixture_phases"]
                )
            else:
                prepared = advance_fixture_preparation(
                    memory,
                    home,
                    case,
                    slot["fixture_phases"],
                    validate_fixture_home=lambda path: validator(slot, path),
                )
            if prepared != "ready":
                raise TrialBlocked("owner_presence_prerequisite")
        elif seed is None:
            raise TrialBlocked("synthetic_seed_adapter_unavailable")
        else:
            initialized = _run_text([str(memory), "init", "--home", str(home)])
            if initialized.returncode != 0:
                raise AcceptanceError("disposable Store initialization failed")
            seeded = _run_text(
                [
                    str(seed),
                    "--manifest",
                    str(manifest.path),
                    "--case-id",
                    case["case_id"],
                    "--memory",
                    str(memory),
                    "--home",
                    str(home),
                ],
                cwd=workspace,
            )
            if seeded.returncode != 0:
                raise AcceptanceError("synthetic seed adapter failed")
        before = _store_snapshot(memory, home)
        if (
            before["mcp_contract_digest"] != state["provenance"]["mcp_contract_digest"]
            or before["skill_digest"] != state["provenance"]["skill_digest"]
        ):
            raise TrialBlocked("installed_contract_drift")
        skill_directory = workspace / CLIENT_SKILL_DIRECTORIES[kind]
        skill_directory.mkdir(parents=True)
        skill = skill_directory / "SKILL.md"
        installed = _run_text(
            [str(memory), "skill", "install", "--target", str(skill)], cwd=workspace
        )
        checked = _run_text(
            [str(memory), "skill", "check", "--target", str(skill)], cwd=workspace
        )
        if installed.returncode != 0 or checked.returncode != 0:
            raise AcceptanceError("exact temporary Skill installation failed")
        prompt = _private_prompt(case, skill)
        prompt_path = response_path.parent / "client-prompt.private"
        prompt_path.write_text(prompt, encoding="utf-8")
        os.chmod(prompt_path, 0o600)
        environment = _client_environment(kind)
        client_home = _private_directory(workspace, ".client-home")
        environment["HOME"] = str(client_home)
        environment["CODEX_HOME" if kind == "codex" else "CLAUDE_CONFIG_DIR"] = str(
            client_home
        )
        environment.update(authentication)
        client_lifecycle: ClientLifecycle | None = None

        def observe_lifecycle(value: ClientLifecycle) -> None:
            nonlocal client_lifecycle
            client_lifecycle = value

        configuration: Path | None = None
        execution: AbstractContextManager[ClientLaunch]
        if kind == "codex":
            execution = _codex_execution_command(
                client,
                memory,
                home,
                workspace,
                model,
                reasoning_effort,
                events_path=response_path.parent / "client-events.private",
                observe_lifecycle=observe_lifecycle,
            )
            input_text = prompt
        else:
            configuration = workspace / "claude-mcp.private.json"
            configuration.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "memory_behavioral_acceptance": {
                                "type": "stdio",
                                "command": str(memory),
                                "args": ["mcp", "--home", str(home)],
                            }
                        }
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(configuration, 0o600)
            command = [
                str(client),
                "--model",
                model,
                "--restricted",
                "--no-session-persistence",
                "--no-chrome",
                "--tools",
                "",
                "--permission-mode",
                "dontAsk",
                "--permission-prompts",
                "none",
                "--strict-mcp-config",
                "--mcp-config",
                str(configuration),
                "--allowedTools",
                "mcp__memory_behavioral_acceptance",
                "-p",
                prompt,
            ]
            execution = nullcontext(ClientLaunch(command))
            input_text = None
        exit_status = 1
        failure_label: str | None = None
        client_launched = False
        stderr_path = response_path.parent / "client-stderr.private"
        try:
            with ExitStack() as credential_scope:
                lease = (
                    credential_scope.enter_context(
                        _subscription_lease(subscription, client_home)
                    )
                    if subscription is not None
                    else None
                )
                if lease is not None:
                    environment["CODEX_CA_CERTIFICATE"] = str(lease.public_ca_bundle)
                    execution = _codex_execution_command(
                        client,
                        memory,
                        home,
                        workspace,
                        model,
                        reasoning_effort,
                        authentication_mode=authentication_binding[
                            "authentication_mode"
                        ],
                        credential_homes=lease.credential_homes,
                        credential_canary=lease.credential_canary,
                        public_ca_bundle=lease.public_ca_bundle,
                        events_path=response_path.parent / "client-events.private",
                        observe_lifecycle=observe_lifecycle,
                    )
                try:
                    with execution as launch:
                        if launch.lifecycle is not None:
                            client_lifecycle = launch.lifecycle
                        if slot is not None:
                            slot["client_launch_attempted"] = True
                            # A launch does not establish that a provider inferred.
                            slot["inference_started"] = None
                            if persist is not None:
                                try:
                                    persist()
                                except BaseException as error:
                                    # No launch call has happened. A failed write
                                    # cannot claim an attempt or unknown inference.
                                    slot["client_launch_attempted"] = False
                                    slot["inference_started"] = False
                                    if isinstance(error, (AcceptanceError, OSError)):
                                        raise TrialBlocked(
                                            "client_launch_state_unavailable"
                                        ) from None
                                    raise
                        client_launched = True
                        exit_status, failure_label = _run_client_to_private_files(
                            launch.command,
                            environment=environment,
                            cwd=workspace,
                            input_text=input_text,
                            stdout_path=response_path,
                            stderr_path=stderr_path,
                            timeout=CLIENT_TIMEOUT_SECONDS,
                            before_cleanup=launch.before_cleanup,
                            lifecycle=launch.lifecycle,
                        )
                finally:
                    if client_lifecycle is not None:
                        try:
                            lifecycle_digest = _campaign_receipt(
                                response_path.parent,
                                {
                                    "schema": "memory.behavioral-client-attempt.v1",
                                    "slot_id": f"{case['case_id']}:{_trial}",
                                    "client_launch_attempted": client_launched,
                                    "lifecycle": client_lifecycle.metadata(),
                                },
                            )
                            recovery = client_lifecycle.private_recovery_metadata()
                            if recovery is not None:
                                _campaign_receipt(
                                    response_path.parent,
                                    {
                                        "schema": "memory.behavioral-client-recovery.v1",
                                        "slot_id": f"{case['case_id']}:{_trial}",
                                        "lifecycle_receipt_digest": lifecycle_digest,
                                        "recovery": recovery,
                                    },
                                )
                        except AcceptanceError, OSError:
                            failure_label = (
                                failure_label or "client_lifecycle_receipt_failed"
                            )
                if lease is not None and failure_label is None:
                    lease.complete()
        except AcceptanceError:
            if not client_launched:
                raise TrialBlocked("client_isolation_controls_unavailable") from None
            exit_status = 1
            failure_label = failure_label or "client_transport_failed"
        except OSError, subprocess.SubprocessError:
            failure_label = "client_transport_failed"
        finally:
            if configuration is not None and configuration.exists():
                configuration.unlink()
            after = _store_snapshot(memory, home)
        return {
            "exit_status": exit_status,
            "before_status": before,
            "after_status": after,
            "failure_label": failure_label,
        }

    return execute


def _load_grades(
    path: Path,
) -> tuple[str, str, list[Mapping[str, Any]]]:
    payload = _strict_json(path.read_bytes())
    root = _require_mapping(payload, "grade file is invalid")
    if set(root) != {"schema", "manifest_digest", "rubric_digest", "grades"}:
        raise AcceptanceError("grade file structure is invalid")
    if root["schema"] != "memory.behavioral-acceptance-grades.v1":
        raise AcceptanceError("grade file schema is unsupported")
    manifest_digest = root["manifest_digest"]
    rubric_digest = root["rubric_digest"]
    if (
        not isinstance(manifest_digest, str)
        or DIGEST.fullmatch(manifest_digest) is None
        or not isinstance(rubric_digest, str)
        or DIGEST.fullmatch(rubric_digest) is None
    ):
        raise AcceptanceError("grade provenance is invalid")
    grades = root["grades"]
    if not isinstance(grades, list):
        raise AcceptanceError("grade entries are invalid")
    return (
        manifest_digest,
        rubric_digest,
        [_require_mapping(grade, "grade entry is invalid") for grade in grades],
    )


def _prepare(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root, require_empty=True)
    manifest = load_manifest(arguments.manifest)
    memory = _validate_executable(arguments.memory)
    client = _validate_executable(arguments.client_executable)
    seed = (
        None
        if arguments.seed_executable is None
        else _validate_executable(arguments.seed_executable)
    )
    fixture_mode = getattr(arguments, "fixture_mode", "owner_review")
    if fixture_mode == "owner_review" and seed is not None:
        raise AcceptanceError("owner review does not use an external seed executable")
    optional_provenance: dict[str, str] = {}
    reasoning_effort = getattr(arguments, "reasoning_effort", None)
    if reasoning_effort is not None:
        validated_effort = _bound_reasoning_effort(
            {"client_kind": arguments.client_kind, "reasoning_effort": reasoning_effort}
        )
        assert validated_effort is not None
        if validated_effort not in _codex_reasoning_efforts(client, arguments.model):
            raise AcceptanceError(
                "client model does not support the requested reasoning effort"
            )
        optional_provenance["reasoning_effort"] = validated_effort
    if arguments.client_kind == "codex":
        binding = _codex_artifact_binding(client)
        optional_provenance.update(
            {
                key: value
                for key, value in binding.items()
                if key != "client_executable_digest"
            }
        )
    client_version = _probe_version(client, arguments.client_kind)
    product_version = _probe_version(memory)
    mcp_digest, skill_digest = _installed_digests(memory)
    build_digest = _sha256_file(arguments.build_artifact)
    build_artifact = arguments.build_artifact.resolve()
    distribution_digest = _installed_distribution_digest(memory, build_artifact)
    state = create_run_state(
        manifest,
        trials=arguments.trials,
        provenance={
            **optional_provenance,
            "client_kind": arguments.client_kind,
            "client_version": client_version,
            "model": arguments.model,
            "product_version": product_version,
            "build_digest": build_digest,
            "memory_executable_digest": _sha256_file(memory),
            "client_executable_digest": _sha256_file(client),
            "seed_executable_digest": (
                "not_present" if seed is None else _sha256_file(seed)
            ),
            "installed_distribution_digest": distribution_digest,
            "mcp_contract_digest": mcp_digest,
            "skill_digest": skill_digest,
            "seed_mode": fixture_mode,
        },
    )
    state["private"] = {
        "manifest_path": str(manifest.path),
        "memory_executable": str(memory),
        "client_executable": str(client),
        "seed_executable": None if seed is None else str(seed),
        "build_artifact": str(build_artifact),
    }
    for slot in state["slots"]:
        slot["inference_started"] = False
        slot["client_launch_attempted"] = False
    _write_state(root, state)
    print(
        json.dumps(
            {
                "status": "prepared",
                "conditions": len(manifest.cases),
                "trials_per_condition": state["requested_trial_count"],
                "slots": len(state["slots"]),
            },
            sort_keys=True,
        )
    )
    return 0


def _allocated_trial(
    root: Path,
    slot: Mapping[str, Any],
    ordinal: int,
) -> tuple[Path, Path, Path]:
    trial_root = root / "private-trials" / f"trial-{ordinal:03d}"
    if slot.get("private_trial_directory") != str(trial_root):
        raise AcceptanceError("prepared trial path changed")
    _private_root(trial_root)
    home = _private_root(trial_root / "store")
    workspace = _private_root(trial_root / "client-session")
    response = trial_root / "client-response.private"
    if (
        response.is_symlink()
        or not response.is_file()
        or stat.S_IMODE(response.stat().st_mode) != 0o600
    ):
        raise AcceptanceError("private trial response is unavailable")
    return home, workspace, response


def _fixture_owner(state: Mapping[str, Any], slot: Mapping[str, Any]) -> dict[str, str]:
    return {
        "schema": "memory.behavioral-fixture-owner.v1",
        "run_id": state["private"]["fixture_run_id"],
        "slot_id": slot["slot_id"],
        "store_id": slot["fixture_store_id"],
    }


def _require_fixture_owner(
    state: Mapping[str, Any], slot: Mapping[str, Any], home: Path
) -> None:
    marker = home.parent / "fixture-owner.private.json"
    if (
        marker.is_symlink()
        or not marker.is_file()
        or stat.S_IMODE(marker.stat().st_mode) != 0o600
    ):
        raise AcceptanceError("fixture Store ownership marker is unavailable")
    if _strict_json(marker.read_bytes()) != _fixture_owner(state, slot):
        raise AcceptanceError("fixture Store ownership changed")
    identity = home / "runtime.json"
    if (
        identity.is_symlink()
        or not identity.is_file()
        or _strict_json(identity.read_bytes()).get("store_id")
        != slot["fixture_store_id"]
    ):
        raise AcceptanceError("fixture Store identity changed")


def _write_owner_handoff(root: Path, state: Mapping[str, Any]) -> None:
    memory = str(state["private"]["memory_executable"])
    lines = [
        "#!/bin/sh",
        "# Private synthetic reviews. Each command requires real macOS owner presence.",
        "set -e",
    ]
    for ordinal, slot in enumerate(state["slots"], start=1):
        if slot.get("fixture_preparation") != "owner_presence_prerequisite":
            continue
        home, _workspace, _response = _allocated_trial(root, slot, ordinal)
        phase = slot["fixture_phases"][-1]
        lines.append(
            shlex.join(
                [
                    memory,
                    "approve",
                    phase["change_set_id"],
                    "--revision",
                    phase["revision_id"],
                    "--digest",
                    phase["digest"],
                    "--home",
                    str(home),
                ]
            )
        )
    temporary = root / ".owner-review.private.new"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, root / "owner-review.private.sh")


def _fixtures(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    if state["provenance"]["seed_mode"] != "owner_review":
        raise AcceptanceError("fixture preparation requires owner_review mode")
    _revalidate_prepared_artifacts(state)
    _validate_bound_reasoning_effort(state)
    manifest = load_manifest(Path(state["private"]["manifest_path"]))
    if manifest.digest != state["provenance"]["manifest_digest"]:
        raise AcceptanceError("prepared manifest changed")
    selected = arguments.slot_id
    if selected is not None and selected not in {
        slot["slot_id"] for slot in state["slots"]
    }:
        raise AcceptanceError("fixture slot is outside the fixed run")
    memory = Path(state["private"]["memory_executable"])
    if "fixture_run_id" not in state["private"]:
        if any(slot.get("fixture_preparation") is not None for slot in state["slots"]):
            raise AcceptanceError("fixture run identity is unavailable")
        state["private"]["fixture_run_id"] = secrets.token_hex(16)
        _write_state(root, state)
    for ordinal, slot in enumerate(state["slots"], start=1):
        if selected is not None and selected != slot["slot_id"]:
            continue
        if slot["attempted"]:
            continue
        outcome = slot.get("fixture_preparation", "pending")
        if outcome in {"fixture_preparation_interrupted", "fixture_preparation_failed"}:
            continue
        slot["fixture_preparation"] = "fixture_preparation_interrupted"
        _write_state(root, state)
        try:
            if outcome == "pending":
                parent = root / "private-trials"
                parent.mkdir(mode=0o700, exist_ok=True)
                _private_root(parent)
                trial = _private_directory(parent, f"trial-{ordinal:03d}")
                _private_directory(trial, "store")
                _private_directory(trial, "client-session")
                response = trial / "client-response.private"
                descriptor = os.open(
                    response,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                os.close(descriptor)
                slot["private_trial_directory"] = str(trial)
                slot["fixture_phases"] = []
                _write_state(root, state)
                home, _workspace, _response = _allocated_trial(root, slot, ordinal)
                initialized = _run_text([str(memory), "init", "--home", str(home)])
                if initialized.returncode != 0:
                    raise AcceptanceError(
                        "disposable fixture Store initialization failed"
                    )
                identity = _require_mapping(
                    _strict_json((home / "runtime.json").read_bytes()),
                    "fixture Store identity is invalid",
                )
                store_id = identity.get("store_id")
                if (
                    not isinstance(store_id, str)
                    or re.fullmatch(r"[0-9a-f]{32}", store_id) is None
                ):
                    raise AcceptanceError("fixture Store identity is invalid")
                slot["fixture_store_id"] = store_id
                marker = home.parent / "fixture-owner.private.json"
                descriptor = os.open(
                    marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(_fixture_owner(state, slot), output, sort_keys=True)
                    output.flush()
                    os.fsync(output.fileno())
                _write_state(root, state)
            home, _workspace, _response = _allocated_trial(root, slot, ordinal)
            _require_fixture_owner(state, slot, home)
            slot["fixture_preparation"] = advance_fixture_preparation(
                memory, home, manifest.cases[slot["case_id"]], slot["fixture_phases"]
            )
        except AcceptanceError, OSError, subprocess.SubprocessError:
            slot["fixture_preparation"] = "fixture_preparation_failed"
        _write_state(root, state)
    _write_owner_handoff(root, state)
    print(
        json.dumps(
            {
                "status": "fixtures_prepared",
                "requested": len(state["slots"]),
                "ready": sum(
                    slot.get("fixture_preparation") == "ready"
                    for slot in state["slots"]
                ),
                "awaiting_owner": sum(
                    slot.get("fixture_preparation") == "owner_presence_prerequisite"
                    for slot in state["slots"]
                ),
                "inference_launched": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _run(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    private = _require_mapping(
        state.get("private"), "private run configuration is missing"
    )
    manifest = load_manifest(Path(str(private["manifest_path"])))
    subscription = bool(_bound_authentication_provenance(state["provenance"]))
    if subscription:
        _require_prepared_artifacts(state)

    def check_subscription() -> None:
        _subscription_session(state)

    executor = _actual_executor(
        state, manifest, persist=lambda: _write_state(root, state)
    )
    label = arguments.blocked_reason
    if label is not None:

        def executor(
            _case: dict[str, Any],
            _trial: int,
            _home: Path,
            _workspace: Path,
            _response_path: Path,
        ) -> dict[str, Any]:
            for slot in state["slots"]:
                if slot["case_id"] == _case["case_id"] and slot["trial"] == _trial:
                    slot["inference_started"] = False
                    slot["client_launch_attempted"] = False
            _require_prepared_artifacts(state)
            raise TrialBlocked(label)

    execute_trials(
        state,
        manifest,
        root / "private-trials",
        execute=executor,
        persist=lambda current: _write_state(root, current),
        # Recheck the shared prerequisite before each durable attempted marker.
        before_attempt=check_subscription if subscription else None,
    )
    _write_state(root, state)
    counts = build_report(state)["counts"]
    print(json.dumps({"status": "executed", **counts}, sort_keys=True))
    return 0


def _grade(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    private = _require_mapping(
        state.get("private"), "private run configuration is missing"
    )
    manifest = load_manifest(Path(str(private["manifest_path"])))
    manifest_digest, rubric_digest, grades = _load_grades(arguments.grades)
    if manifest_digest != manifest.digest or rubric_digest != manifest.rubric_digest:
        raise AcceptanceError("grade provenance does not match the run")
    grade_trials(state, manifest, grades)
    _write_state(root, state)
    print(
        json.dumps(
            {"status": "graded", **build_report(state)["counts"]}, sort_keys=True
        )
    )
    return 0


def _report(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    report = build_report(state)
    write_report(arguments.output, report)
    print(json.dumps({"status": "reported", **report["counts"]}, sort_keys=True))
    return 0


def _bind_subscription(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    private = _require_mapping(state.get("private"), "run configuration is missing")
    client = _validate_executable(Path(str(private["client_executable"])))
    authentication_digest = _subscription_implementation_digest()
    binding = _codex_artifact_binding(
        client, authentication_mode="chatgpt_subscription"
    )
    candidate = bind_subscription_authentication(
        state,
        auth_root=arguments.auth_root,
        authentication_digest=authentication_digest,
        isolation_binding=binding,
    )
    _validated_subscription_session(arguments.auth_root, client)
    manifest = load_manifest(Path(str(private["manifest_path"])))
    if (
        candidate["provenance"]["manifest_digest"] != manifest.digest
        or candidate["provenance"]["rubric_digest"] != manifest.rubric_digest
    ):
        raise AcceptanceError("prepared manifest changed")
    _revalidate_prepared_artifacts(candidate)
    _require_codex_capabilities(candidate)
    _write_state(root, candidate)
    print(
        json.dumps(
            {
                "status": "subscription_bound",
                **build_report(candidate)["counts"],
                "inference_launched": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _require_continuation_cleanup(
    state: Mapping[str, Any],
    cleanup_evidence: Path,
    *,
    state_digest: str,
) -> str:
    _behavioral_helper_path()
    from behavioral_continuation import ContinuationError, verify_cleanup_receipt

    try:
        return verify_cleanup_receipt(
            state, cleanup_evidence, state_digest=state_digest
        )
    except ContinuationError:
        raise AcceptanceError("prior process cleanup is unverified") from None


def _require_memory_transport_readiness(
    state: Mapping[str, Any], *, receipt_root: Path | None = None
) -> dict[str, Any]:
    """Qualify a fresh native endpoint; retain its private scope on any failure."""
    _behavioral_helper_path()
    import behavioral_memory_endpoint
    from behavioral_mcp_bridge import transport_digest

    view = effective_execution_state(state)
    private = _require_mapping(
        view.get("private"), "execution configuration is missing"
    )
    provenance = _require_mapping(
        view.get("provenance"), "execution provenance is missing"
    )
    memory = _validate_executable(Path(str(private["memory_executable"])))
    client = _validate_executable(Path(str(private["client_executable"])))
    verify = getattr(behavioral_memory_endpoint, "verify_endpoint_readiness", None)
    if not callable(verify):
        raise AcceptanceError("native Memory transport readiness is unavailable")
    try:
        interpreter = behavioral_memory_endpoint._memory_interpreter(memory)
        # Keep the helper's venv path for execution and hash its validated target.
        interpreter_digest = _sha256_file(interpreter.resolve(strict=True))
    except behavioral_memory_endpoint.EndpointError, OSError, RuntimeError:
        raise AcceptanceError("native Memory interpreter is unavailable") from None
    expected = {
        "schema": "memory.behavioral-memory-endpoint-readiness.v1",
        "outcome_label": "memory_endpoint_readiness_confirmed",
        "memory_executable_digest": provenance["memory_executable_digest"],
        "memory_interpreter_digest": interpreter_digest,
        "client_executable_digest": provenance["client_executable_digest"],
        "code_mode_host_digest": provenance["code_mode_host_digest"],
        "isolation_profile_digest": provenance["isolation_profile_digest"],
        "endpoint_helper_digest": behavioral_memory_endpoint.implementation_digest(),
        "bridge_transport_digest": transport_digest(),
    }
    workspace = Path(tempfile.mkdtemp(prefix="memory-behavioral-readiness-")).resolve()
    os.chmod(workspace, 0o700)
    print(
        json.dumps(
            {
                "status": "memory_transport_readiness_pending",
                "private_workspace": str(workspace),
            },
            sort_keys=True,
        )
    )
    try:
        result = _require_mapping(
            verify(memory, client, workspace),
            "native Memory readiness result is invalid",
        )
        positive = (
            "ready",
            "memory_initialized",
            "mcp_initialized",
            "proxy_auth_environment_absent",
            "proxy_environment_isolated",
            "proxy_auth_home_denied",
            "endpoint_auth_home_denied",
            "endpoint_auth_environment_absent",
            "processes_reaped",
            "key_cleanup_confirmed",
            "bridge_cleanup_confirmed",
            "runtime_removed",
            "cleanup_confirmed",
            "client_endpoint_environment_read_denied",
            "client_endpoint_environment_write_denied",
            "bindings_unchanged",
        )
        if any(result.get(key) is not True for key in positive) or any(
            result.get(key) != value for key, value in expected.items()
        ):
            raise AcceptanceError("native Memory transport readiness is unverified")
        checkpoint_digest = result.get("checkpoint_digest")
        if (
            not isinstance(checkpoint_digest, str)
            or DIGEST.fullmatch(checkpoint_digest) is None
        ):
            raise AcceptanceError("native Memory readiness checkpoint is unverified")
        from behavioral_continuation import read_private_bytes

        checkpoint = workspace / "readiness-checkpoint.private.json"
        checkpoint_bytes = read_private_bytes(checkpoint)
        if _sha256_bytes(checkpoint_bytes) != checkpoint_digest:
            raise AcceptanceError("native Memory readiness checkpoint changed")
        if receipt_root is not None:
            _campaign_immutable_receipt(receipt_root, checkpoint_bytes)
        shutil.rmtree(workspace)
        return dict(result)
    except Exception:
        # The printed private path is the recovery handoff; never delete a scope
        # whose exact-account key/process cleanup was not confirmed by the helper.
        raise AcceptanceError(
            "native Memory readiness is unavailable; private scope retained"
        ) from None


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _continue_subscription(arguments: argparse.Namespace) -> int:
    root = _private_root(arguments.state_root)
    state = _read_state(root)
    _behavioral_helper_path()
    from behavioral_continuation import (
        ContinuationError,
        infrastructure_candidate,
        pending_slot_ids,
        read_private_bytes,
        write_snapshot,
    )

    try:
        original_bytes = read_private_bytes(root / STATE_FILENAME)
        if _strict_json(original_bytes) != state:
            raise AcceptanceError("acceptance state changed before continuation")
        current_digest = _sha256_bytes(original_bytes)
        existing = _continuation_info(state)
        predecessor = state if existing is None else existing.predecessor
        eligible = pending_slot_ids(predecessor)
        predecessor_digest = (
            current_digest if existing is None else existing.snapshot_digest
        )
        cleanup_digest = _require_continuation_cleanup(
            predecessor,
            arguments.cleanup_evidence,
            state_digest=predecessor_digest,
        )
        private = _require_mapping(
            predecessor.get("private"), "run configuration is missing"
        )
        client = _validate_executable(Path(str(private["client_executable"])))
        authentication_digest = _subscription_implementation_digest()
        binding = _codex_artifact_binding(
            client, authentication_mode="chatgpt_subscription"
        )
        if existing is not None:
            candidate = continue_subscription_authentication(
                state,
                auth_root=arguments.auth_root,
                authentication_digest=authentication_digest,
                isolation_binding=binding,
                snapshot_path=existing.snapshot_path,
                snapshot_digest=existing.snapshot_digest,
                cleanup_evidence=arguments.cleanup_evidence,
                cleanup_digest=cleanup_digest,
            )
            if read_private_bytes(root / STATE_FILENAME) != original_bytes:
                raise AcceptanceError(
                    "acceptance state changed during continuation replay"
                )
            print(
                json.dumps(
                    {
                        "status": "subscription_continuation_unchanged",
                        "pending": len(eligible),
                        "inference_launched": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        view = infrastructure_candidate(
            predecessor,
            auth_root=arguments.auth_root,
            authentication_digest=authentication_digest,
            isolation_binding=binding,
        )
        _validate_fixed_roster(view)
        manifest = load_manifest(Path(str(private["manifest_path"])))
        provenance = _require_mapping(
            view.get("provenance"), "run provenance is missing"
        )
        if (
            provenance["manifest_digest"] != manifest.digest
            or provenance["rubric_digest"] != manifest.rubric_digest
        ):
            raise AcceptanceError("prepared manifest changed")
        _revalidate_prepared_artifacts(view)
        _validated_subscription_session(arguments.auth_root, client)
        _require_codex_capabilities(view)
        _require_memory_transport_readiness(view)
        snapshot, snapshot_digest = write_snapshot(root, original_bytes)
        candidate = continue_subscription_authentication(
            state,
            auth_root=arguments.auth_root,
            authentication_digest=authentication_digest,
            isolation_binding=binding,
            snapshot_path=snapshot,
            snapshot_digest=snapshot_digest,
            cleanup_evidence=arguments.cleanup_evidence,
            cleanup_digest=cleanup_digest,
        )
        _write_state(root, candidate, expected_state_digest=current_digest)
        print(
            json.dumps(
                {
                    "status": "subscription_continued",
                    "pending": len(eligible),
                    **build_report(candidate)["counts"],
                    "inference_launched": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except ContinuationError:
        raise AcceptanceError("subscription continuation is unavailable") from None


def _campaign_immutable_receipt(root: Path, raw: bytes) -> str:
    """Keep checked private evidence durable without replacing a prior receipt."""
    _behavioral_helper_path()
    from behavioral_continuation import read_private_bytes

    receipts = root / "receipts"
    receipts.mkdir(mode=0o700, exist_ok=True)
    if (
        receipts.is_symlink()
        or not receipts.is_dir()
        or stat.S_IMODE(receipts.stat().st_mode) != 0o700
        or receipts.stat().st_uid != os.getuid()
    ):
        raise AcceptanceError("campaign receipt directory is unavailable")
    digest = _sha256_bytes(raw)
    path = receipts / f"{digest}.private.json"
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
        )
    except FileExistsError:
        if read_private_bytes(path, mode=0o400) != raw:
            raise AcceptanceError("campaign receipt changed") from None
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as existing:
            identity = os.fstat(existing.fileno())
            if (
                not stat.S_ISREG(identity.st_mode)
                or stat.S_IMODE(identity.st_mode) != 0o400
                or identity.st_uid != os.getuid()
                or identity.st_nlink != 1
                or existing.read(len(raw) + 1) != raw
            ):
                raise AcceptanceError("campaign receipt changed") from None
            # A prior failed fsync may have left matching but uncommitted bytes.
            os.fsync(existing.fileno())
    else:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    directory = os.open(receipts, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return digest


def _campaign_receipt(root: Path, payload: Mapping[str, object]) -> str:
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode()
    return _campaign_immutable_receipt(root, raw)


def _campaign_source_binding() -> str:
    runner = Path(__file__).resolve()
    files = (runner, *sorted(runner.parent.glob("behavioral_*.py")))
    return _canonical_digest({path.name: _sha256_file(path) for path in files})


def _campaign_state(
    campaign: Campaign, cohort: Cohort, *, active: bool = False
) -> dict[str, Any]:
    from behavioral_campaign import cohort_view

    return dict(
        _require_mapping(
            cohort_view(campaign, cohort, active=active),
            "campaign execution view is invalid",
        )
    )


def _campaign_candidate_view(
    campaign: Campaign, cohort: Cohort, *, auth_root: Path | None = None
) -> dict[str, Any]:
    """Refresh only infrastructure while the original artifact identities hold."""
    _behavioral_helper_path()
    view = _campaign_state(campaign, cohort)
    return _campaign_validate_candidate_view(view, auth_root=auth_root)


def _campaign_validate_candidate_view(
    view: dict[str, Any], *, auth_root: Path | None = None
) -> dict[str, Any]:
    provenance = dict(
        _require_mapping(view["provenance"], "campaign provenance is invalid")
    )
    private = dict(
        _require_mapping(view["private"], "campaign configuration is invalid")
    )
    client = _validate_executable(Path(str(private["client_executable"])))
    binding = _codex_artifact_binding(
        client, authentication_mode="chatgpt_subscription"
    )
    for name in ("client_executable_digest", "code_mode_host_digest"):
        if binding[name] != provenance.get(name):
            raise AcceptanceError("campaign client identity changed")
    provenance["isolation_profile_digest"] = binding["isolation_profile_digest"]
    provenance["authentication_adapter_digest"] = _subscription_implementation_digest()
    if auth_root is not None:
        private["subscription_auth_root"] = str(auth_root)
    view.update(provenance=provenance, private=private)
    _validate_fixed_roster(view)
    _revalidate_prepared_artifacts(view)
    _validate_bound_reasoning_effort(view)
    manifest = load_manifest(Path(str(private["manifest_path"])))
    if manifest.digest != provenance.get(
        "manifest_digest"
    ) or manifest.rubric_digest != provenance.get("rubric_digest"):
        raise AcceptanceError("campaign manifest changed")
    return view


def _campaign_prepare(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import create_campaign, preflight_execution_states
    from behavioral_continuation import read_private_bytes

    archive: dict[str, bytes] = {}
    for path in arguments.archive:
        raw = read_private_bytes(path, mode=0o400)
        digest = _sha256_bytes(raw)
        if digest in archive:
            raise AcceptanceError("campaign archive input is duplicated")
        archive[digest] = raw
    execution_paths = {
        "memory_executable": arguments.memory,
        "client_executable": arguments.client_executable,
        "build_artifact": arguments.build_artifact,
        "base_manifest": arguments.base_manifest,
        "discovery_manifest": arguments.discovery_manifest,
    }
    heads: dict[Cohort, str] = {
        "base": arguments.base_head,
        "discovery": arguments.discovery_head,
    }
    manifests: dict[Cohort, bytes] = {
        "base": arguments.base_manifest.read_bytes(),
        "discovery": arguments.discovery_manifest.read_bytes(),
    }
    previews = preflight_execution_states(
        heads=heads,
        archive=archive,
        manifests=manifests,
        execution_paths=execution_paths,
    )
    for cohort in ("base", "discovery"):
        _campaign_validate_candidate_view(
            dict(
                _require_mapping(previews[cohort], "campaign preflight view is invalid")
            )
        )
    campaign = create_campaign(
        arguments.campaign_parent,
        heads=heads,
        archive=archive,
        manifests=manifests,
        execution_paths=execution_paths,
    )
    print(
        json.dumps(
            {
                "status": "campaign_allocated",
                "private_campaign_root": str(campaign.root),
                "inference_launched": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _campaign_fixture_home(
    campaign: Campaign, cohort: Cohort, slot_id: str, home: Path
) -> Path:
    from behavioral_campaign import validate_fixture_home

    return validate_fixture_home(campaign, cohort, slot_id, home)


def _campaign_fixture_validator(
    campaign: Campaign, cohort: Cohort, slot_id: str
) -> Callable[[Path], Path]:
    return lambda home: _campaign_fixture_home(campaign, cohort, slot_id, home)


def _campaign_sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        identity = os.fstat(descriptor)
        if identity.st_uid != os.getuid() or stat.S_IMODE(identity.st_mode) != 0o700:
            raise AcceptanceError("campaign directory is not private")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _campaign_private_ancestors(campaign: Campaign, parent: Path) -> None:
    """Create only the registered generation's private containing directories."""
    try:
        relative = parent.relative_to(campaign.root)
    except ValueError:
        raise AcceptanceError(
            "campaign fixture parent escaped its allocation"
        ) from None
    current = campaign.root
    for component in relative.parts:
        if component in {".", ".."}:
            raise AcceptanceError("campaign fixture parent is invalid")
        containing = current
        current = current / component
        current.mkdir(mode=0o700, exist_ok=True)
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AcceptanceError("campaign fixture parent is not private")
        _campaign_sync_directory(containing)


def _campaign_write_owner_handoff(campaign: Campaign) -> None:
    from behavioral_campaign import fixture_paths

    lines = [
        "#!/bin/sh",
        "# Each exact synthetic review requires real macOS owner presence.",
        "set -e",
    ]
    for cohort in ("base", "discovery"):
        selected: Cohort = cohort
        view = _campaign_state(campaign, selected)
        for slot in view["slots"]:
            if (
                slot.get("attempted")
                or slot.get("fixture_preparation") != "owner_presence_prerequisite"
            ):
                continue
            paths = fixture_paths(campaign, selected, slot["slot_id"])
            _campaign_fixture_home(campaign, selected, slot["slot_id"], paths.store)
            _require_fixture_owner(view, slot, paths.store)
            phase = slot["fixture_phases"][-1]
            lines.append(
                shlex.join(
                    [
                        str(view["private"]["memory_executable"]),
                        "approve",
                        phase["change_set_id"],
                        "--revision",
                        phase["revision_id"],
                        "--digest",
                        phase["digest"],
                        "--home",
                        str(paths.store),
                    ]
                )
            )
    raw = ("\n".join(lines) + "\n").encode()
    # The stable pointer is a convenience for the operator; exact review digests
    # and all immutable fixture records remain in the authoritative campaign.
    target = campaign.root / "owner-review.private.sh"
    if target.is_symlink() or (
        target.exists()
        and (not target.is_file() or stat.S_IMODE(target.stat().st_mode) != 0o600)
    ):
        raise AcceptanceError("campaign owner handoff is unavailable")
    temporary = campaign.root / (".owner-review-" + secrets.token_hex(12))
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, target)
    directory = os.open(campaign.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _campaign_fixtures(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import (
        fixture_paths,
        load_campaign,
        mark_ready,
        record_fixture,
    )

    campaign = load_campaign(arguments.campaign_root)
    for cohort_name in ("base", "discovery"):
        cohort: Cohort = cohort_name
        view = _campaign_candidate_view(campaign, cohort)
        manifest = load_manifest(Path(view["private"]["manifest_path"]))
        memory = Path(view["private"]["memory_executable"])
        for original_slot in view["slots"]:
            if original_slot.get("attempted"):
                continue
            slot_id = original_slot["slot_id"]
            current = _campaign_state(campaign, cohort)
            slot = next(item for item in current["slots"] if item["slot_id"] == slot_id)
            outcome = slot.get("fixture_preparation", "pending")
            if outcome in {
                "fixture_preparation_interrupted",
                "fixture_preparation_failed",
            }:
                continue
            paths = fixture_paths(campaign, cohort, slot_id)
            phases = copy.deepcopy(slot.get("fixture_phases", []))
            store_id = slot.get("fixture_store_id")
            campaign = record_fixture(
                campaign,
                cohort,
                slot_id,
                preparation="fixture_preparation_interrupted",
                store_id=store_id,
                phases=phases,
            )
            try:
                if outcome == "pending":
                    _campaign_private_ancestors(campaign, paths.trial.parent)
                    paths.trial.mkdir(mode=0o700)
                    paths.store.mkdir(mode=0o700)
                    for output_path in (paths.response, paths.stderr):
                        descriptor = os.open(
                            output_path,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                        )
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                    for directory in (paths.store, paths.trial, paths.trial.parent):
                        _campaign_sync_directory(directory)
                    _campaign_fixture_home(campaign, cohort, slot_id, paths.store)
                    initialized = _run_text(
                        [str(memory), "init", "--home", str(paths.store)]
                    )
                    if initialized.returncode != 0:
                        raise AcceptanceError("campaign fixture initialization failed")
                    identity = _require_mapping(
                        _strict_json((paths.store / "runtime.json").read_bytes()),
                        "campaign fixture identity is invalid",
                    )
                    store_id = identity.get("store_id")
                    if (
                        not isinstance(store_id, str)
                        or re.fullmatch(r"[0-9a-f]{32}", store_id) is None
                    ):
                        raise AcceptanceError("campaign fixture identity is invalid")
                    _campaign_sync_directory(paths.store)
                    campaign = record_fixture(
                        campaign,
                        cohort,
                        slot_id,
                        preparation="fixture_preparation_interrupted",
                        store_id=store_id,
                        phases=phases,
                    )
                    current = _campaign_state(campaign, cohort)
                    slot = next(
                        item for item in current["slots"] if item["slot_id"] == slot_id
                    )
                    marker = paths.trial / "fixture-owner.private.json"
                    descriptor = os.open(
                        marker,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                        json.dump(_fixture_owner(current, slot), output, sort_keys=True)
                        output.flush()
                        os.fsync(output.fileno())
                    _campaign_sync_directory(paths.trial)
                _campaign_fixture_home(campaign, cohort, slot_id, paths.store)
                _require_fixture_owner(current, slot, paths.store)
                outcome = advance_fixture_preparation(
                    memory,
                    paths.store,
                    manifest.cases[slot["case_id"]],
                    phases,
                    validate_fixture_home=_campaign_fixture_validator(
                        campaign, cohort, slot_id
                    ),
                )
            except AcceptanceError, OSError, subprocess.SubprocessError:
                outcome = "fixture_preparation_failed"
            campaign = record_fixture(
                campaign,
                cohort,
                slot_id,
                preparation=outcome,
                store_id=store_id,
                phases=phases,
            )
    states = [_campaign_state(campaign, cohort) for cohort in ("base", "discovery")]
    remaining = [
        slot for state in states for slot in state["slots"] if not slot.get("attempted")
    ]
    if remaining and all(
        slot.get("fixture_preparation") == "ready" for slot in remaining
    ):
        campaign = mark_ready(campaign)
    _campaign_write_owner_handoff(campaign)
    print(
        json.dumps(
            {
                "status": "campaign_fixtures_prepared",
                "selected": len(remaining),
                "ready": sum(
                    slot.get("fixture_preparation") == "ready" for slot in remaining
                ),
                "awaiting_owner": sum(
                    slot.get("fixture_preparation") == "owner_presence_prerequisite"
                    for slot in remaining
                ),
                "inference_launched": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _campaign_reboot_cleanup(campaign: Campaign, pause_receipt: Path) -> str:
    """Prove the imported pause precedes this boot without probing old paths/PIDs."""
    from behavioral_campaign import generation_number, original_heads
    from behavioral_continuation import read_private_bytes

    if generation_number(campaign) != 1:
        raise AcceptanceError(
            "a later campaign generation requires new process cleanup evidence"
        )
    raw = read_private_bytes(pause_receipt)
    pause = _require_mapping(_strict_json(raw), "campaign pause receipt is invalid")
    paused = pause.get("paused_at_utc_epoch")
    cohorts = _require_mapping(
        pause.get("cohorts"), "campaign pause cohorts are invalid"
    )
    if pause.get("schema") != "memory.private-work-pause.v1" or (
        not isinstance(paused, (int, float)) or isinstance(paused, bool)
    ):
        raise AcceptanceError("campaign pause receipt is invalid")
    heads = original_heads(campaign)
    for cohort in ("base", "discovery"):
        entry = _require_mapping(
            cohorts.get("codex-" + cohort), "campaign pause cohort is invalid"
        )
        if entry.get("state_sha256") != heads[cohort]:
            raise AcceptanceError("campaign pause belongs to another imported head")
    boot_result = _run_metadata(["/usr/sbin/sysctl", "-n", "kern.boottime"])
    boot_match = re.fullmatch(
        r"\{ sec = ([0-9]+), usec = ([0-9]+) \}.*", boot_result.stdout.strip()
    )
    session_result = _run_metadata(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])
    if (
        boot_result.returncode != 0
        or session_result.returncode != 0
        or boot_match is None
    ):
        raise AcceptanceError("live OS boot evidence is unavailable")
    try:
        boot_session = str(uuid.UUID(session_result.stdout.strip()))
        seconds, microseconds = (int(value) for value in boot_match.groups())
        boot_time = seconds + microseconds / 1_000_000
        observed = time.time()
        if not (0 <= microseconds < 1_000_000 and 0 < paused < boot_time <= observed):
            raise ValueError
    except ValueError, TypeError, OverflowError:
        raise AcceptanceError(
            "the imported pause is not proven to precede this boot"
        ) from None
    pause_digest = _campaign_immutable_receipt(campaign.root, raw)
    return _campaign_receipt(
        campaign.root,
        {
            "schema": "memory.behavioral-campaign-reboot-cleanup.v1",
            "original_heads": dict(heads),
            "pause_receipt_digest": pause_digest,
            "paused_at_utc_epoch": paused,
            "boot_seconds": seconds,
            "boot_microseconds": microseconds,
            "boot_session_uuid": boot_session,
            "observed_at_utc_epoch": observed,
            "prior_boot_processes_cannot_survive": True,
            "old_paths_or_pids_probed": False,
        },
    )


def _campaign_verify_fixtures(
    campaign: Campaign, views: Mapping[str, dict[str, Any]]
) -> None:
    for cohort_name in ("base", "discovery"):
        cohort: Cohort = cohort_name
        view = views[cohort]
        manifest = load_manifest(Path(view["private"]["manifest_path"]))
        memory = Path(view["private"]["memory_executable"])
        from behavioral_campaign import fixture_paths

        for slot in view["slots"]:
            if slot.get("attempted"):
                continue
            if slot.get("fixture_preparation") != "ready":
                raise AcceptanceError(
                    "both campaign cohorts require complete fixture approval"
                )
            paths = fixture_paths(campaign, cohort, slot["slot_id"])
            _campaign_fixture_home(campaign, cohort, slot["slot_id"], paths.store)
            _require_fixture_owner(view, slot, paths.store)
            phases = copy.deepcopy(slot["fixture_phases"])
            result = advance_fixture_preparation(
                memory,
                paths.store,
                manifest.cases[slot["case_id"]],
                phases,
                validate_fixture_home=_campaign_fixture_validator(
                    campaign, cohort, slot["slot_id"]
                ),
            )
            if result != "ready" or phases != slot["fixture_phases"]:
                raise AcceptanceError("campaign fixture verification is incomplete")


def _campaign_activate(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import activate_campaign, load_campaign

    campaign = load_campaign(arguments.campaign_root)
    source_binding = _campaign_source_binding()
    cleanup_digest = _campaign_reboot_cleanup(campaign, arguments.pause_receipt)
    views = {
        cohort: _campaign_candidate_view(
            campaign, cohort, auth_root=arguments.auth_root
        )
        for cohort in ("base", "discovery")
    }
    _campaign_verify_fixtures(campaign, views)
    base = views["base"]
    shared_fields = (
        "model",
        "reasoning_effort",
        "client_executable_digest",
        "code_mode_host_digest",
        "memory_executable_digest",
        "build_digest",
        "installed_distribution_digest",
        "mcp_contract_digest",
        "skill_digest",
        "isolation_profile_digest",
        "authentication_adapter_digest",
    )
    if any(
        base["provenance"].get(name) != views["discovery"]["provenance"].get(name)
        for name in shared_fields
    ):
        raise AcceptanceError("campaign cohort execution identities differ")
    client = Path(base["private"]["client_executable"])
    _validated_subscription_session(arguments.auth_root, client)
    capability = _require_codex_capabilities(base)
    transport = _require_memory_transport_readiness(base, receipt_root=campaign.root)
    _validated_subscription_session(arguments.auth_root, client)
    if _campaign_source_binding() != source_binding:
        raise AcceptanceError("campaign execution source changed during activation")
    prerequisite = {
        "cleanup_digest": cleanup_digest,
        "capability_digest": _campaign_receipt(campaign.root, capability),
        "memory_transport_digest": _campaign_receipt(campaign.root, transport),
        "source_binding_digest": source_binding,
    }
    campaign = activate_campaign(
        campaign,
        infrastructure_binding={
            name: base["provenance"][name]
            for name in ("isolation_profile_digest", "authentication_adapter_digest")
        },
        auth_roots={"base": arguments.auth_root, "discovery": arguments.auth_root},
        prerequisite_receipt=prerequisite,
    )
    print(
        json.dumps(
            {
                "status": "campaign_activated",
                "inference_launched": False,
                "source_binding_digest": source_binding,
            },
            sort_keys=True,
        )
    )
    return 0


def _campaign_run(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import (
        activation_prerequisites,
        fixture_paths,
        load_campaign,
        record_progress,
        reserve_attempt,
    )

    campaign = load_campaign(arguments.campaign_root)
    source_binding = activation_prerequisites(campaign)["source_binding_digest"]

    def run_cohort(cohort: Cohort) -> None:
        state = _campaign_state(campaign, cohort, active=True)
        manifest = load_manifest(Path(state["private"]["manifest_path"]))

        def persist(current: dict[str, Any]) -> None:
            nonlocal campaign
            if _campaign_source_binding() != source_binding:
                raise AcceptanceError(
                    "campaign execution source changed before state persistence"
                )
            saved = _campaign_state(campaign, cohort, active=True)
            by_id = {slot["slot_id"]: slot for slot in saved["slots"]}
            newly_attempted = [
                slot["slot_id"]
                for slot in current["slots"]
                if slot["attempted"] is True
                and by_id[slot["slot_id"]]["attempted"] is False
            ]
            if len(newly_attempted) > 1:
                raise AcceptanceError(
                    "campaign attempted multiple slots before reservation"
                )
            for slot_id in newly_attempted:
                campaign = reserve_attempt(campaign, cohort, slot_id)
            campaign = record_progress(campaign, cohort, current)

        def before_attempt() -> None:
            if _campaign_source_binding() != source_binding:
                raise AcceptanceError("campaign execution source changed")
            _subscription_session(state)

        def allocate(
            _root: Path, slot: Mapping[str, Any], _ordinal: int
        ) -> tuple[Path, Path, Path]:
            paths = fixture_paths(campaign, cohort, str(slot["slot_id"]))
            _campaign_fixture_home(campaign, cohort, str(slot["slot_id"]), paths.store)
            _require_fixture_owner(state, slot, paths.store)
            scratch = Path(tempfile.mkdtemp(prefix="memory-campaign-client-")).resolve()
            _private_root(scratch)
            workspace = _private_directory(scratch, "client-session")
            _campaign_receipt(
                campaign.root,
                {
                    "schema": "memory.behavioral-campaign-client-allocation.v1",
                    "cohort": cohort,
                    "slot_id": slot["slot_id"],
                    "generation_id": campaign.generation_id,
                    "workspace": str(workspace),
                    "allocated_at_utc_epoch": time.time(),
                    "source_binding_digest": source_binding,
                },
            )
            return paths.store, workspace, paths.response

        def validate_home(slot: Mapping[str, Any], home: Path) -> Path:
            return _campaign_fixture_home(campaign, cohort, str(slot["slot_id"]), home)

        executor = _actual_executor(
            state,
            manifest,
            persist=lambda: persist(state),
            validate_fixture_home=validate_home,
        )
        execute_trials(
            state,
            manifest,
            campaign.root / "private-trials",
            execute=executor,
            persist=persist,
            before_attempt=before_attempt,
            allocate_prepared_trial=allocate,
        )

    for cohort_name in ("base", "discovery"):
        run_cohort(cohort_name)
    print(json.dumps({"status": "campaign_executed"}, sort_keys=True))
    return 0


def _campaign_grade(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import load_campaign, record_progress

    campaign = load_campaign(arguments.campaign_root)
    cohort = cast("Cohort", arguments.cohort)
    state = _campaign_state(campaign, cohort)
    manifest = load_manifest(Path(state["private"]["manifest_path"]))
    manifest_digest, rubric_digest, grades = _load_grades(arguments.grades)
    if manifest_digest != manifest.digest or rubric_digest != manifest.rubric_digest:
        raise AcceptanceError("campaign grade provenance differs")
    grade_trials(state, manifest, grades)
    record_progress(campaign, cohort, state)
    print(
        json.dumps(
            {"status": "campaign_graded", **build_report(state)["counts"]},
            sort_keys=True,
        )
    )
    return 0


def _campaign_report(arguments: argparse.Namespace) -> int:
    _behavioral_helper_path()
    from behavioral_campaign import load_campaign, report_context

    campaign = load_campaign(arguments.campaign_root)
    reports = {}
    for cohort_name in ("base", "discovery"):
        cohort: Cohort = cohort_name
        reports[cohort] = {
            "report": build_report(_campaign_state(campaign, cohort)),
            "campaign": report_context(campaign, cohort),
        }
    write_report(
        arguments.output,
        {"schema": "memory.behavioral-campaign-report.v1", "cohorts": reports},
    )
    print(json.dumps({"status": "campaign_reported"}, sort_keys=True))
    return 0


def _subscription_login(arguments: argparse.Namespace) -> int:
    helper_directory = str(Path(__file__).resolve().parent)
    if helper_directory not in sys.path:
        sys.path.insert(0, helper_directory)
    from behavioral_codex_auth import AuthError, create_session, start_login

    parent = _private_root(arguments.session_parent)
    client = _validate_executable(arguments.client_executable)
    try:
        session = create_session(parent, client)
        with start_login(session, method=arguments.method) as attempt:
            # Both locations are private operational metadata, never a report.
            print(
                json.dumps(
                    {
                        "status": "subscription_sign_in_pending",
                        "session_root": str(session.root),
                        "private_login_output": str(attempt.output_path),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            while not attempt.wait(timeout=10):
                pass
            attempt.finish()
    except AuthError, OSError:
        raise AcceptanceError("subscription sign-in was not completed") from None
    print(json.dumps({"status": "subscription_sign_in_confirmed"}, sort_keys=True))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run-behavioral-acceptance",
        description="Run fixed repeated installed-client behavioral trials.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--manifest", required=True, type=Path)
    prepare.add_argument("--state-root", required=True, type=Path)
    prepare.add_argument("--memory", required=True, type=Path)
    prepare.add_argument("--build-artifact", required=True, type=Path)
    prepare.add_argument("--client-kind", required=True, choices=CLIENT_KINDS)
    prepare.add_argument("--client-executable", required=True, type=Path)
    prepare.add_argument("--model", required=True)
    prepare.add_argument(
        "--reasoning-effort",
        help="Bind one effort advertised by the installed Codex model; omitted for legacy behavior.",
    )
    prepare.add_argument("--trials", type=int)
    prepare.add_argument("--seed-executable", type=Path)
    prepare.add_argument(
        "--fixture-mode",
        choices=("owner_review", "synthetic_adapter"),
        default="owner_review",
    )
    fixtures = commands.add_parser("fixtures")
    fixtures.add_argument("--state-root", required=True, type=Path)
    fixtures.add_argument("--slot-id")
    probe = commands.add_parser("probe")
    probe.add_argument("--state-root", required=True, type=Path)
    probe.add_argument("--client-executable", required=True, type=Path)
    probe.add_argument("--client-kind", choices=("codex",), default="codex")
    probe.add_argument("--output", required=True, type=Path)
    capabilities = commands.add_parser("probe-capabilities")
    capabilities.add_argument("--client-executable", required=True, type=Path)
    capabilities.add_argument("--model", required=True)
    capabilities.add_argument("--reasoning-effort")
    capabilities.add_argument(
        "--authentication-mode", choices=("chatgpt_subscription",)
    )
    capabilities.add_argument("--output", required=True, type=Path)
    subscription_login = commands.add_parser("subscription-login")
    subscription_login.add_argument("--session-parent", required=True, type=Path)
    subscription_login.add_argument("--client-executable", required=True, type=Path)
    subscription_login.add_argument(
        "--method", choices=("browser", "device"), default="browser"
    )
    subscription_bind = commands.add_parser("bind-subscription")
    subscription_bind.add_argument("--state-root", required=True, type=Path)
    subscription_bind.add_argument("--auth-root", required=True, type=Path)
    subscription_continue = commands.add_parser("continue-subscription")
    subscription_continue.add_argument("--state-root", required=True, type=Path)
    subscription_continue.add_argument("--auth-root", required=True, type=Path)
    subscription_continue.add_argument("--cleanup-evidence", required=True, type=Path)
    run = commands.add_parser("run")
    run.add_argument("--state-root", required=True, type=Path)
    run.add_argument("--blocked-reason")
    grade = commands.add_parser("grade")
    grade.add_argument("--state-root", required=True, type=Path)
    grade.add_argument("--grades", required=True, type=Path)
    report = commands.add_parser("report")
    report.add_argument("--state-root", required=True, type=Path)
    report.add_argument("--output", required=True, type=Path)
    campaign_prepare = commands.add_parser("campaign-prepare")
    campaign_prepare.add_argument("--campaign-parent", required=True, type=Path)
    campaign_prepare.add_argument(
        "--archive", required=True, action="append", type=Path
    )
    campaign_prepare.add_argument("--base-head", required=True)
    campaign_prepare.add_argument("--discovery-head", required=True)
    campaign_prepare.add_argument("--memory", required=True, type=Path)
    campaign_prepare.add_argument("--client-executable", required=True, type=Path)
    campaign_prepare.add_argument("--build-artifact", required=True, type=Path)
    campaign_prepare.add_argument("--base-manifest", required=True, type=Path)
    campaign_prepare.add_argument("--discovery-manifest", required=True, type=Path)
    for phase in ("fixtures", "activate", "run", "grade", "report"):
        command = commands.add_parser("campaign-" + phase)
        command.add_argument("--campaign-root", required=True, type=Path)
        if phase == "activate":
            command.add_argument("--auth-root", required=True, type=Path)
            command.add_argument("--pause-receipt", required=True, type=Path)
        elif phase == "grade":
            command.add_argument(
                "--cohort", required=True, choices=("base", "discovery")
            )
            command.add_argument("--grades", required=True, type=Path)
        elif phase == "report":
            command.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None, *, stderr: TextIO | None = None) -> int:
    """Dispatch one bounded acceptance phase with content-free errors."""
    errors = sys.stderr if stderr is None else stderr
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command.startswith("campaign-"):
            _behavioral_helper_path()
            from behavioral_campaign import CampaignError

            campaign_commands = {
                "campaign-prepare": _campaign_prepare,
                "campaign-fixtures": _campaign_fixtures,
                "campaign-activate": _campaign_activate,
                "campaign-run": _campaign_run,
                "campaign-grade": _campaign_grade,
                "campaign-report": _campaign_report,
            }
            try:
                return campaign_commands[arguments.command](arguments)
            except CampaignError:
                raise AcceptanceError(
                    "campaign state is unavailable or changed"
                ) from None
        if arguments.command == "prepare":
            return _prepare(arguments)
        if arguments.command == "run":
            return _run(arguments)
        if arguments.command == "fixtures":
            return _fixtures(arguments)
        if arguments.command == "subscription-login":
            return _subscription_login(arguments)
        if arguments.command == "bind-subscription":
            return _bind_subscription(arguments)
        if arguments.command == "continue-subscription":
            return _continue_subscription(arguments)
        if arguments.command == "probe-capabilities":
            client = _validate_executable(arguments.client_executable)
            result = (
                _codex_capability_probe(
                    client,
                    arguments.model,
                    arguments.reasoning_effort,
                    authentication_mode=arguments.authentication_mode,
                )
                if arguments.authentication_mode is not None
                else _codex_capability_probe(
                    client, arguments.model, arguments.reasoning_effort
                )
            )
            write_report(arguments.output, result)
            print(json.dumps(result, sort_keys=True))
            return 0 if result.get("capabilities_confirmed") is True else 2
        if arguments.command == "probe":
            result = probe_client_isolation(
                arguments.client_executable, arguments.client_kind, arguments.state_root
            )
            write_report(arguments.output, result)
            print(json.dumps(result, sort_keys=True))
            return 0
        if arguments.command == "grade":
            return _grade(arguments)
        if arguments.command == "report":
            return _report(arguments)
        raise AcceptanceError("acceptance command is unsupported")
    except AcceptanceError, OSError, subprocess.SubprocessError:
        errors.write("behavioral_acceptance_error\n")
        return 1
    except TrialBlocked as error:
        errors.write(error.label + "\n")
        return 2


if __name__ == "__main__":
    import sys

    raise SystemExit(main())
