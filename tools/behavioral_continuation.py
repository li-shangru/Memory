"""Narrow, private continuation of untouched behavioral acceptance slots.

The original state and provenance stay authoritative. This helper validates an
immutable predecessor snapshot and produces an ephemeral execution view; it
does not authenticate, approve fixtures, probe processes, or launch a client.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

CONTINUATION_SCHEMA = "memory.behavioral-subscription-continuation.v1"
STATE_SCHEMA = "memory.behavioral-acceptance-state.v1"
REPORT_SCHEMA = "memory.behavioral-acceptance-report.v2"
CLEANUP_SCHEMA = "memory.behavioral-prior-cleanup.v1"
MAX_STATE_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_INFRASTRUCTURE_FIELDS = frozenset(
    ("isolation_profile_digest", "authentication_adapter_digest")
)
_EXECUTION_FIELDS = frozenset(
    (
        "attempted",
        "completed",
        "execution_outcome",
        "outcome_label",
        "mutation_outcome",
        "grade_outcome",
        "outcomes",
        "inference_started",
        "client_launch_attempted",
        "capability_probe",
    )
)


class ContinuationError(Exception):
    """A content-free refusal of a changed or unsupported continuation."""


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ContinuationError("continuation structure is invalid")
    return cast(Mapping[str, object], value)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, allow_nan=False
        ).encode()
    except TypeError, ValueError, UnicodeError:
        raise ContinuationError("continuation structure is invalid") from None


def _same(left: object, right: object) -> bool:
    return _canonical(left) == _canonical(right)


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ContinuationError("continuation digest is invalid")
    return value


def _absolute(value: object) -> Path:
    if not isinstance(value, str):
        raise ContinuationError("continuation path is invalid")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ContinuationError("continuation path is invalid")
    return path


def _slots(state: Mapping[str, object]) -> list[Mapping[str, object]]:
    raw = state.get("slots")
    if not isinstance(raw, list) or not raw:
        raise ContinuationError("continuation roster is invalid")
    slots = [_mapping(value) for value in raw]
    identities = [slot.get("slot_id") for slot in slots]
    if any(not isinstance(identity, str) or not identity for identity in identities):
        raise ContinuationError("continuation roster is invalid")
    if len(set(cast(list[str], identities))) != len(slots):
        raise ContinuationError("continuation roster is invalid")
    return slots


def _pending(slot: Mapping[str, object]) -> bool:
    return (
        all(
            slot.get(field) is False
            for field in (
                "attempted",
                "completed",
                "client_launch_attempted",
                "inference_started",
            )
        )
        and slot.get("execution_outcome") == "pending"
        and slot.get("outcome_label") == "untested"
        and slot.get("mutation_outcome") == "unverified"
        and slot.get("grade_outcome") == "ungraded"
        and slot.get("outcomes") == {}
        and "capability_probe" not in slot
    )


def pending_slot_ids(state: Mapping[str, object]) -> tuple[str, ...]:
    """Accept only untouched fixtures and at most one exact transport failure."""
    provenance = _mapping(state.get("provenance"))
    private = _mapping(state.get("private"))
    if (
        state.get("schema") != STATE_SCHEMA
        or "continuation" in state
        or "continuation" in private
        or provenance.get("client_kind") != "codex"
        or provenance.get("seed_mode") != "owner_review"
        or provenance.get("authentication_mode") != "chatgpt_subscription"
        or not isinstance(provenance.get("reasoning_effort"), str)
    ):
        raise ContinuationError("continuation requires a prepared subscription cohort")
    for field in (
        *_INFRASTRUCTURE_FIELDS,
        "code_mode_host_digest",
        "client_executable_digest",
    ):
        _digest(provenance.get(field))
    _absolute(private.get("subscription_auth_root"))
    pending: list[str] = []
    failed = 0
    for slot in _slots(state):
        if (
            slot.get("fixture_preparation") != "ready"
            or not isinstance(slot.get("fixture_store_id"), str)
            or not isinstance(slot.get("fixture_phases"), list)
            or not slot.get("fixture_phases")
        ):
            raise ContinuationError("continuation fixtures are not ready")
        _absolute(slot.get("private_trial_directory"))
        if _pending(slot):
            pending.append(cast(str, slot["slot_id"]))
        elif (
            slot.get("attempted") is True
            and slot.get("client_launch_attempted") is True
            and slot.get("inference_started") is None
            and slot.get("completed") is False
            and slot.get("execution_outcome") == "failed"
            and slot.get("outcome_label") == "client_transport_failed"
            and slot.get("mutation_outcome") == "unchanged"
            and slot.get("grade_outcome") == "ungraded"
            and slot.get("outcomes") == {}
        ):
            failed += 1
        else:
            raise ContinuationError(
                "continuation cannot consume prior or ambiguous work"
            )
    if failed > 1 or not pending:
        raise ContinuationError("continuation requires untouched pending slots")
    return tuple(pending)


def _layout_root(state: Mapping[str, object]) -> Path:
    slots = _slots(state)
    root = _absolute(slots[0].get("private_trial_directory")).parent.parent
    for ordinal, slot in enumerate(slots, start=1):
        if (
            _absolute(slot.get("private_trial_directory"))
            != root / "private-trials" / f"trial-{ordinal:03d}"
        ):
            raise ContinuationError("continuation fixture path changed")
    return root


def _root(state: Mapping[str, object]) -> Path:
    root = _layout_root(state)
    temporary = Path(tempfile.gettempdir()).resolve()
    if not root.is_relative_to(temporary) or root != root.resolve():
        raise ContinuationError("continuation snapshot root is invalid")
    return root


def read_private_bytes(path: Path, *, mode: int = 0o600) -> bytes:
    """Read one explicitly named regular private file without following links."""
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= MAX_STATE_BYTES
        ):
            raise ContinuationError("continuation private evidence is invalid")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_STATE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (
            len(raw) != before.st_size
            or before[:7] != after[:7]
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ContinuationError("continuation private evidence changed")
        return raw
    except OSError:
        raise ContinuationError(
            "continuation private evidence is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _decode(raw: bytes) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        value: object = json.loads(raw, object_pairs_hook=pairs)
    except ValueError, UnicodeError:
        raise ContinuationError("continuation snapshot is invalid") from None
    return dict(_mapping(value))


@dataclass(frozen=True)
class Continuation:
    pending_slot_ids: tuple[str, ...]
    infrastructure_binding: Mapping[str, str]
    snapshot_path: Path
    snapshot_digest: str
    auth_root: Path
    cleanup_evidence: Path
    cleanup_digest: str
    predecessor: Mapping[str, object]


def _new_auth_root(value: object, predecessor: Mapping[str, object]) -> Path:
    path = _absolute(value)
    original = _absolute(
        _mapping(predecessor.get("private")).get("subscription_auth_root")
    )
    if path.is_relative_to(original) or original.is_relative_to(path):
        raise ContinuationError("continuation requires a fresh authentication scope")
    return path


def _validate_selected_slot(
    slot: Mapping[str, object], before: Mapping[str, object]
) -> None:
    if not _same(
        {key: value for key, value in slot.items() if key not in _EXECUTION_FIELDS},
        {key: value for key, value in before.items() if key not in _EXECUTION_FIELDS},
    ):
        raise ContinuationError("continuation fixture or slot identity changed")
    if slot.get("attempted") is False:
        if not _same(slot, before):
            raise ContinuationError("continuation pending slot changed")
        return
    outcome = slot.get("execution_outcome")
    grade = slot.get("grade_outcome")
    if (
        slot.get("attempted") is not True
        or type(slot.get("completed")) is not bool
        or type(slot.get("client_launch_attempted")) is not bool
        or (
            slot.get("inference_started") is not None
            and type(slot.get("inference_started")) is not bool
        )
        or outcome not in ("interrupted", "blocked", "failed", "completed")
        or (outcome == "completed") != slot.get("completed")
        or grade not in ("ungraded", "passed", "failed")
        or (grade != "ungraded" and outcome != "completed")
        or (grade == "ungraded" and slot.get("outcomes") != {})
        or (slot.get("inference_started") is True and grade == "ungraded")
    ):
        raise ContinuationError("continuation execution state is invalid")


def validate_state(state: Mapping[str, object]) -> Continuation | None:
    """Validate the immutable predecessor and every allowed mutable slot access."""
    return _validate_state(state, snapshots=None)


def validate_archived_state(
    state: Mapping[str, object], snapshots: Mapping[str, bytes]
) -> Continuation | None:
    """Validate supplied predecessor bytes without resolving historical paths."""
    return _validate_state(state, snapshots=snapshots)


def _validate_state(
    state: Mapping[str, object], *, snapshots: Mapping[str, bytes] | None
) -> Continuation | None:
    private_value = state.get("private")
    private = _mapping(private_value) if isinstance(private_value, Mapping) else {}
    if "continuation" not in state and "continuation" not in private:
        return None
    metadata = _mapping(state.get("continuation"))
    custody = _mapping(private.get("continuation"))
    if (
        set(metadata) != {"schema", "pending_slot_ids", "infrastructure_binding"}
        or metadata.get("schema") != CONTINUATION_SCHEMA
    ):
        raise ContinuationError("continuation metadata is invalid")
    if set(custody) != {
        "snapshot_path",
        "snapshot_digest",
        "auth_root",
        "cleanup_evidence",
        "cleanup_digest",
    }:
        raise ContinuationError("continuation custody is invalid")
    digest = _digest(custody.get("snapshot_digest"))
    snapshot = _absolute(custody.get("snapshot_path"))
    if (
        snapshot.parent != (_root(state) if snapshots is None else _layout_root(state))
        or snapshot.name != f"continuation-before-{digest}.private.json"
    ):
        raise ContinuationError("continuation snapshot path changed")
    if snapshots is None:
        raw = read_private_bytes(snapshot, mode=0o400)
    else:
        try:
            raw = snapshots[digest]
        except KeyError:
            raise ContinuationError("continuation snapshot is unavailable") from None
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ContinuationError("continuation snapshot changed")
    predecessor = _decode(raw)
    pending = pending_slot_ids(predecessor)
    if metadata.get("pending_slot_ids") != list(pending):
        raise ContinuationError("continuation pending roster changed")
    binding_raw = _mapping(metadata.get("infrastructure_binding"))
    if set(binding_raw) != _INFRASTRUCTURE_FIELDS:
        raise ContinuationError("continuation infrastructure binding is invalid")
    binding = {
        field: _digest(binding_raw.get(field)) for field in _INFRASTRUCTURE_FIELDS
    }
    if not _same(
        {
            key: value
            for key, value in state.items()
            if key not in ("continuation", "private", "slots")
        },
        {
            key: value
            for key, value in predecessor.items()
            if key not in ("private", "slots")
        },
    ) or not _same(
        {key: value for key, value in private.items() if key != "continuation"},
        predecessor.get("private"),
    ):
        raise ContinuationError("continuation original provenance changed")
    slots, previous_slots = _slots(state), _slots(predecessor)
    if len(slots) != len(previous_slots):
        raise ContinuationError("continuation roster changed")
    for slot, before in zip(slots, previous_slots, strict=True):
        if before.get("slot_id") in pending:
            _validate_selected_slot(slot, before)
        elif not _same(slot, before):
            raise ContinuationError("continuation failed slot changed")
    return Continuation(
        pending,
        binding,
        snapshot,
        digest,
        _new_auth_root(custody.get("auth_root"), predecessor),
        _absolute(custody.get("cleanup_evidence")),
        _digest(custody.get("cleanup_digest")),
        predecessor,
    )


def infrastructure_candidate(
    state: Mapping[str, object],
    *,
    auth_root: Path,
    authentication_digest: str,
    isolation_binding: Mapping[str, str],
) -> dict[str, object]:
    """Construct the preflight view without writing state or touching credentials."""
    pending_slot_ids(state)
    provenance = _mapping(state.get("provenance"))
    private = _mapping(state.get("private"))
    if set(isolation_binding) != {
        "client_executable_digest",
        "code_mode_host_digest",
        "isolation_profile_digest",
    } or any(
        isolation_binding.get(field) != provenance.get(field)
        for field in ("client_executable_digest", "code_mode_host_digest")
    ):
        raise ContinuationError("continuation cannot replace the client or host")
    binding = {
        "isolation_profile_digest": _digest(
            isolation_binding.get("isolation_profile_digest")
        ),
        "authentication_adapter_digest": _digest(authentication_digest),
    }
    result = dict(state)
    result["provenance"] = {**provenance, **binding}
    result["private"] = {
        **private,
        "subscription_auth_root": str(_new_auth_root(str(auth_root), state)),
    }
    return result


def make_continuation(
    state: Mapping[str, object],
    *,
    auth_root: Path,
    authentication_digest: str,
    isolation_binding: Mapping[str, str],
    snapshot_path: Path,
    snapshot_digest: str,
    cleanup_evidence: Path,
    cleanup_digest: str,
) -> dict[str, object]:
    """Append one binding without cloning, resetting, or replacing any slot."""
    existing = validate_state(state)
    predecessor = state if existing is None else existing.predecessor
    view = infrastructure_candidate(
        predecessor,
        auth_root=auth_root,
        authentication_digest=authentication_digest,
        isolation_binding=isolation_binding,
    )
    provenance = _mapping(view["provenance"])
    metadata = {
        "schema": CONTINUATION_SCHEMA,
        "pending_slot_ids": list(pending_slot_ids(predecessor)),
        "infrastructure_binding": {
            field: provenance[field] for field in _INFRASTRUCTURE_FIELDS
        },
    }
    custody = {
        "snapshot_path": str(snapshot_path),
        "snapshot_digest": _digest(snapshot_digest),
        "auth_root": str(auth_root),
        "cleanup_evidence": str(cleanup_evidence),
        "cleanup_digest": _digest(cleanup_digest),
    }
    if existing is not None:
        private = _mapping(state.get("private"))
        if (
            not _same(metadata, state.get("continuation"))
            or not _same(custody, private.get("continuation"))
            or any(
                slot.get("slot_id") in existing.pending_slot_ids and not _pending(slot)
                for slot in _slots(state)
            )
        ):
            raise ContinuationError(
                "continuation cannot be replaced or replayed after an attempt"
            )
        return dict(state)
    changed = dict(state)
    changed["continuation"] = metadata
    changed["private"] = {**_mapping(state.get("private")), "continuation": custody}
    checked = validate_state(changed)
    if checked is None or not _same(checked.predecessor, state):
        raise ContinuationError("continuation snapshot belongs to another state")
    return changed


def execution_state(
    state: Mapping[str, object], *, slot_id: str | None = None
) -> dict[str, object]:
    """Return a validated view sharing the original slot list and slot objects."""
    continuation = validate_state(state)
    if continuation is None:
        return dict(state)
    if slot_id is not None and slot_id not in continuation.pending_slot_ids:
        raise ContinuationError("continuation cannot execute the prior failed slot")
    result = {key: value for key, value in state.items() if key != "continuation"}
    result["provenance"] = {
        **_mapping(state.get("provenance")),
        **continuation.infrastructure_binding,
    }
    result["private"] = {
        **{
            key: value
            for key, value in _mapping(state.get("private")).items()
            if key != "continuation"
        },
        "subscription_auth_root": str(continuation.auth_root),
    }
    return result


def write_snapshot(root: Path, raw: bytes) -> tuple[Path, str]:
    """Create a read-only predecessor file once; an existing file must match."""
    state = _decode(raw)
    pending_slot_ids(state)
    if root != _root(state):
        raise ContinuationError("continuation snapshot root changed")
    digest = hashlib.sha256(raw).hexdigest()
    path = root / f"continuation-before-{digest}.private.json"
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
        )
    except FileExistsError:
        if read_private_bytes(path, mode=0o400) != raw:
            raise ContinuationError(
                "continuation predecessor snapshot changed"
            ) from None
        return path, digest
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path, digest


@contextmanager
def state_write_lock(root: Path) -> Iterator[None]:
    """Serialize short state writes, including a continuation's stale-byte check."""
    descriptor: int | None = None
    try:
        descriptor = os.open(
            root / ".behavioral-state.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ContinuationError("continuation state lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except OSError:
        raise ContinuationError("continuation state write is unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _check_terminal_progress(
    before: Mapping[str, object], after: Mapping[str, object]
) -> None:
    outcome = before.get("execution_outcome")
    if outcome not in ("failed", "blocked", "completed") or _same(before, after):
        return
    if outcome != "completed" or before.get("grade_outcome") != "ungraded":
        raise ContinuationError("continuation terminal evidence is immutable")
    grade = after.get("grade_outcome")
    grading_fields = {"grade_outcome", "outcome_label", "outcomes", "inference_started"}
    if (
        grade not in ("passed", "failed")
        or after.get("outcome_label") != f"rubric_{grade}"
        or not _mapping(after.get("outcomes"))
        or (
            after.get("inference_started") is not before.get("inference_started")
            and after.get("inference_started") is not True
        )
        or not _same(
            {key: value for key, value in before.items() if key not in grading_fields},
            {key: value for key, value in after.items() if key not in grading_fields},
        )
    ):
        raise ContinuationError("continuation completed evidence is immutable")


def check_write_progress(
    previous: Mapping[str, object], current: Mapping[str, object]
) -> None:
    """An older writer cannot remove a continuation or reset its consumed slots."""
    if "continuation" not in previous:
        return
    validate_state(previous)
    validate_state(current)
    if not _same(
        previous.get("continuation"), current.get("continuation")
    ) or not _same(
        _mapping(previous.get("private")).get("continuation"),
        _mapping(current.get("private")).get("continuation"),
    ):
        raise ContinuationError("continuation history cannot be replaced")
    for before, after in zip(_slots(previous), _slots(current), strict=True):
        if any(
            before.get(field) is True and after.get(field) is not True
            for field in (
                "attempted",
                "completed",
                "client_launch_attempted",
                "inference_started",
            )
        ):
            raise ContinuationError("continuation attempts cannot be reset")
        if (
            before.get("execution_outcome") != "pending"
            and after.get("execution_outcome") == "pending"
        ):
            raise ContinuationError("continuation attempts cannot be reset")
        _check_terminal_progress(before, after)


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise ContinuationError("prior cleanup timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ContinuationError("prior cleanup timestamp is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ContinuationError("prior cleanup timestamp is invalid")
    return parsed


def _integer(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContinuationError("prior cleanup numeric evidence is invalid")
    return value


def _cleanup_cohort(provenance: Mapping[str, object]) -> str:
    schema = provenance.get("manifest_schema")
    if schema == "memory.synthetic-behavioral-acceptance.v1":
        return "codex-base"
    if schema == "memory.synthetic-behavioral-discovery.v1":
        return "codex-discovery"
    raise ContinuationError("prior cleanup cohort is unsupported")


def verify_cleanup_receipt(
    state: Mapping[str, object], path: Path, *, state_digest: str
) -> str:
    """Verify one reviewed numeric/source receipt against the exact predecessor.

    This consumes explicitly named immutable evidence files. It does not issue
    an OS observation, infer cleanup from a transport failure, or inspect a
    credential scope, Store, process environment, or process-name inventory.
    """
    pending_slot_ids(state)
    try:
        receipt_mode = stat.S_IMODE(path.lstat().st_mode)
    except OSError:
        raise ContinuationError("prior cleanup receipt is unavailable") from None
    if receipt_mode not in (0o400, 0o600):
        raise ContinuationError("prior cleanup receipt permissions are invalid")
    raw = read_private_bytes(path, mode=receipt_mode)
    if len(raw) > 512 * 1024:
        raise ContinuationError("prior cleanup receipt is too large")
    receipt = _decode(raw)
    fields = {
        "schema",
        "outcome",
        "verification_method",
        "previous_state_digest",
        "old_provenance",
        "old_provenance_serialization",
        "old_artifact_binding",
        "lower_bound_utc",
        "upper_bound_utc",
        "observed_at_utc",
        "recorded_at_utc",
        "observed_uid",
        "current_boot",
        "queried_pid_count",
        "in_window_survivor_count",
        "unknown_query_count",
        "stable_selection",
        "source_commit",
        "evidence",
        "limitations",
    }
    if (
        set(receipt) != fields
        or receipt.get("schema") != CLEANUP_SCHEMA
        or receipt.get("outcome") != "verified"
        or receipt.get("verification_method")
        != "current_uid_birth_time_census_with_exact_startup_source"
        or receipt.get("old_provenance_serialization")
        != "json-sort-keys-compact-ascii-utf8-no-newline.v1"
        or receipt.get("stable_selection") is not True
        or _integer(receipt.get("observed_uid"), minimum=0, maximum=2**32 - 1)
        != os.getuid()
    ):
        raise ContinuationError("prior cleanup receipt is not a supported verification")
    _integer(receipt.get("queried_pid_count"), minimum=1, maximum=65536)
    _integer(receipt.get("in_window_survivor_count"), minimum=0, maximum=0)
    _integer(receipt.get("unknown_query_count"), minimum=0, maximum=0)
    source_commit = receipt.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
    ):
        raise ContinuationError("prior cleanup source binding is invalid")
    boot = _mapping(receipt.get("current_boot"))
    if set(boot) != {"boot_session_uuid", "boot_time_utc", "seconds", "microseconds"}:
        raise ContinuationError("prior cleanup boot evidence is invalid")
    session = boot.get("boot_session_uuid")
    try:
        if not isinstance(session, str) or str(uuid.UUID(session)) != session.lower():
            raise ValueError
    except ValueError:
        raise ContinuationError("prior cleanup boot evidence is invalid") from None
    seconds = _integer(boot.get("seconds"), minimum=1, maximum=2**40)
    microseconds = _integer(boot.get("microseconds"), minimum=0, maximum=999999)
    try:
        boot_instant = datetime.fromtimestamp(seconds, UTC).replace(
            microsecond=microseconds
        )
    except ValueError, OSError, OverflowError:
        raise ContinuationError("prior cleanup boot evidence is invalid") from None
    lower = _utc(receipt.get("lower_bound_utc"))
    upper = _utc(receipt.get("upper_bound_utc"))
    observed = _utc(receipt.get("observed_at_utc"))
    recorded = _utc(receipt.get("recorded_at_utc"))
    if (
        _utc(boot.get("boot_time_utc")) != boot_instant
        or not boot_instant <= lower < upper < observed <= recorded <= datetime.now(UTC)
    ):
        raise ContinuationError("prior cleanup time ordering is invalid")
    provenance = _mapping(state.get("provenance"))
    cohort = _cleanup_cohort(provenance)
    cohort_names = {"codex-base", "codex-discovery"}
    state_bindings = _mapping(receipt.get("previous_state_digest"))
    provenance_bindings = _mapping(receipt.get("old_provenance"))
    artifact_bindings = _mapping(receipt.get("old_artifact_binding"))
    if any(
        set(binding) != cohort_names
        for binding in (state_bindings, provenance_bindings, artifact_bindings)
    ):
        raise ContinuationError("prior cleanup cohort bindings are incomplete")
    for name in cohort_names:
        _digest(state_bindings[name])
        _digest(provenance_bindings[name])
    canonical_provenance = json.dumps(
        provenance,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    artifacts = {
        key: value for key, value in provenance.items() if key.endswith("_digest")
    }
    for name in cohort_names:
        supplied = _mapping(artifact_bindings[name])
        if set(supplied) != set(artifacts):
            raise ContinuationError("prior cleanup artifact binding is incomplete")
        for field, value in supplied.items():
            if field != "seed_executable_digest" or value != "not_present":
                _digest(value)
    if (
        state_bindings[cohort] != _digest(state_digest)
        or provenance_bindings[cohort]
        != hashlib.sha256(canonical_provenance).hexdigest()
        or not _same(artifact_bindings[cohort], artifacts)
    ):
        raise ContinuationError("prior cleanup belongs to different state or artifacts")
    evidence = receipt.get("evidence")
    limitations = receipt.get("limitations")
    if (
        not isinstance(evidence, list)
        or not 1 <= len(evidence) <= 32
        or not isinstance(limitations, list)
        or not 1 <= len(limitations) <= 32
        or any(
            not isinstance(value, str) or not 1 <= len(value) <= 2000
            for value in limitations
        )
    ):
        raise ContinuationError("prior cleanup supporting evidence is invalid")
    seen: set[str] = set()
    total = 0
    for value in evidence:
        entry = _mapping(value)
        evidence_name = entry.get("path")
        if (
            set(entry) != {"path", "sha256", "bytes"}
            or not isinstance(evidence_name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", evidence_name) is None
            or evidence_name in seen
            or evidence_name == path.name
        ):
            raise ContinuationError("prior cleanup evidence path is invalid")
        seen.add(evidence_name)
        expected_size = _integer(entry.get("bytes"), minimum=1, maximum=MAX_STATE_BYTES)
        expected_digest = _digest(entry.get("sha256"))
        evidence_path = path.parent / evidence_name
        try:
            mode = stat.S_IMODE(evidence_path.lstat().st_mode)
        except OSError:
            raise ContinuationError(
                "prior cleanup supporting evidence is unavailable"
            ) from None
        if mode not in (0o400, 0o600):
            raise ContinuationError("prior cleanup evidence permissions are invalid")
        content = read_private_bytes(evidence_path, mode=mode)
        total += len(content)
        if (
            total > 16 * 1024 * 1024
            or len(content) != expected_size
            or hashlib.sha256(content).hexdigest() != expected_digest
        ):
            raise ContinuationError("prior cleanup supporting evidence changed")
    if read_private_bytes(path, mode=receipt_mode) != raw:
        raise ContinuationError("prior cleanup receipt changed during validation")
    return hashlib.sha256(raw).hexdigest()
