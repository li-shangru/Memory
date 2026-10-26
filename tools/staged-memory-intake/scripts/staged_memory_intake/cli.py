"""Content-safe command-line orchestration for staged Memory intake."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, Never, cast

from staged_memory_intake.cancellation import cancel_publication, cancellation_status
from staged_memory_intake.checks import (
    begin_scan,
    build_review_edits,
    check_batch,
    check_memories,
    check_review,
    mark_awaiting_approval,
    parse_success_envelope,
    record_application,
    record_scan,
)
from staged_memory_intake.cleanup import (
    MacOSTrash,
    Trash,
    cleanup,
    reconcile_cleanup,
    replay_complete_cleanup,
)
from staged_memory_intake.config import (
    DEFAULT_STATE_ROOT,
    configure,
    load_config,
    load_config_record,
    require_config,
)
from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.layout_migration import (
    abandon_unsupported_intent as abandon_unsupported_layout_intent,
)
from staged_memory_intake.layout_migration import (
    layout_migration_pending,
    layout_migration_required,
    migrate_layout,
)
from staged_memory_intake.model import (
    MAX_PUBLIC_SNAPSHOT_BYTES,
    CleanupOutcome,
    CommandRunner,
    CompletedCommand,
    IntakeConfig,
    IntakeError,
    NoPublicationFault,
    PublicationFault,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import build_preview, preview_json
from staged_memory_intake.publish import publish, recover_publication
from staged_memory_intake.relocation import (
    abandon_unsupported_intent as abandon_unsupported_relocation_intent,
)
from staged_memory_intake.relocation import relocate_notes_root, relocation_pending
from staged_memory_intake.securefs import create_pending_note
from staged_memory_intake.state import (
    TransactionStore,
    abandon_unsupported_transaction,
)

_PREVIEW_SCHEMA: Final = "staged-memory-intake.preview.v1"
_REVIEW_PLAN_SCHEMA: Final = "staged-memory-intake.review-plan.v1"
_STATUS_SCHEMA: Final = "staged-memory-intake.status.v1"
_RELOCATION_SCHEMA: Final = "staged-memory-intake.relocation.v1"
_LAYOUT_MIGRATION_SCHEMA: Final = "staged-memory-intake.layout-migration.v1"
_ABANDON_SCHEMA: Final = "staged-memory-intake.abandon.v1"
_ERROR_SCHEMA: Final = "staged-memory-intake.error.v1"
_INPUT_LIMIT: Final = MAX_PUBLIC_SNAPSHOT_BYTES
_PENDING_NOTE_LIMIT: Final = 256 * 1024
_INPUT_CHUNK: Final = 64 * 1024
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_TRANSACTION_PATTERN = re.compile(r"tx_[0-9a-f]{32}")
_EXIT_CODES: Mapping[str, int] = {
    "configuration": 2,
    "drift": 3,
    "state": 4,
    "memory": 5,
    "trash": 6,
}
_MUTABLE_FIELDS: Mapping[TransactionState, frozenset[str]] = {
    TransactionState.OWNER_AUTHORIZED: frozenset(),
    TransactionState.PUBLISHING: frozenset(),
    TransactionState.PUBLISHED: frozenset({"published_files", "scan_started"}),
    TransactionState.CAPTURED: frozenset(
        {
            "batch_id",
            "scan_source_ids",
            "scan_issues",
            "scan_has_more",
            "scan_page_has_more",
            "source_bindings",
            "duplicate_notices",
        }
    ),
    TransactionState.REVIEW_READY: frozenset(
        {"change_set_id", "revision_id", "review_digest"}
    ),
    TransactionState.AWAITING_MEMORY_APPROVAL: frozenset(
        {"revision_id", "review_digest"}
    ),
    TransactionState.APPLIED: frozenset(
        {"application_id", "memory_ids", "standing_guard_violations"}
    ),
    TransactionState.VERIFIED: frozenset(),
    TransactionState.CLEANUP_PENDING: frozenset({"cleanup_entries"}),
    TransactionState.COMPLETE: frozenset({"cleanup_entries"}),
}
_INPUT_STATES: Mapping[str, frozenset[TransactionState]] = {
    "record-scan": frozenset({TransactionState.PUBLISHED, TransactionState.CAPTURED}),
    "check-batch": frozenset(
        {
            TransactionState.PUBLISHED,
            TransactionState.CAPTURED,
            TransactionState.REVIEW_READY,
            TransactionState.AWAITING_MEMORY_APPROVAL,
            TransactionState.APPLIED,
            TransactionState.VERIFIED,
        }
    ),
    "check-review": frozenset(
        {
            TransactionState.CAPTURED,
            TransactionState.REVIEW_READY,
            TransactionState.AWAITING_MEMORY_APPROVAL,
        }
    ),
    "record-application": frozenset(
        {
            TransactionState.AWAITING_MEMORY_APPROVAL,
            TransactionState.APPLIED,
        }
    ),
    "check-memories": frozenset({TransactionState.APPLIED, TransactionState.VERIFIED}),
}


class _ParserExit(Exception):
    """Internal zero-status help exit."""


class _OutputFailure(Exception):
    """Content-free classification for one failed stream operation."""

    def __init__(self, mapped: IntakeError) -> None:
        super().__init__()
        self.mapped = mapped


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argparse adapter that never echoes a caller-controlled value."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def error(self, message: str) -> Never:
        del message
        raise IntakeError("invalid_arguments", "configuration")

    def exit(self, status: int = 0, message: str | None = None) -> Never:
        del message
        if status == 0:
            raise _ParserExit
        raise IntakeError("invalid_arguments", "configuration")


@dataclass(frozen=True, slots=True)
class _SubprocessRunner:
    """Production argument-array subprocess boundary."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return CompletedCommand(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


@dataclass(frozen=True, slots=True)
class _MemoryPathsRunner:
    """Map expected process failures at the public paths boundary."""

    runner: CommandRunner

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        try:
            return self.runner.run(argv, timeout_seconds=timeout_seconds)
        except (OSError, subprocess.SubprocessError) as error:
            raise IntakeError(
                "memory_paths_failed",
                "memory",
                retryable=True,
            ) from error


@dataclass(frozen=True, slots=True)
class Dependencies:
    """All operational boundaries injected into the command adapter."""

    memory_paths_runner: CommandRunner
    process_runner: CommandRunner
    trash: Trash
    publication_fault: PublicationFault
    debug_exceptions: bool = False


@dataclass(slots=True)
class _Context:
    state: TransactionState | None = None


def _production_dependencies() -> Dependencies:
    runner = _SubprocessRunner()
    return Dependencies(
        memory_paths_runner=runner,
        process_runner=runner,
        trash=MacOSTrash(runner),
        publication_fault=NoPublicationFault(),
    )


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(prog="staged-memory-intake")
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_SafeArgumentParser,
    )

    configure_parser = commands.add_parser("configure")
    configure_parser.add_argument("--notes-root", type=Path, required=True)
    configure_parser.add_argument("--memory-home", type=Path)
    configure_parser.add_argument("--create-prepared", action="store_true")
    configure_parser.add_argument("--pending-drop", choices=("on", "off"))

    relocate_parser = commands.add_parser("relocate")
    relocate_parser.add_argument("--to", type=Path, required=True)
    relocate_parser.add_argument(
        "--adopt-current-authority",
        action="store_true",
    )
    commands.add_parser("migrate-layout")
    commands.add_parser("abandon-unsupported")

    preview_parser = commands.add_parser("preview")
    previews = preview_parser.add_subparsers(
        dest="preview_command",
        required=True,
        parser_class=_SafeArgumentParser,
    )
    prepared_parser = previews.add_parser("prepared")
    prepared_parser.add_argument("--prepared", action="append", required=True)
    prepared_parser.add_argument("--guard-link", action="append", default=[])
    review_parser = previews.add_parser("review")
    review_parser.add_argument("--transaction", required=True)

    authorize_parser = commands.add_parser("authorize")
    authorize_parser.add_argument("--digest", required=True)
    authorize_parser.add_argument("--prepared", action="append", required=True)
    authorize_parser.add_argument("--guard-link", action="append", default=[])
    authorize_parser.add_argument("--supersede-transaction")
    authorize_parser.add_argument("--supersede-digest")

    status_parser = commands.add_parser("status")
    status_parser.add_argument("--transaction")

    cancel_parser = commands.add_parser("cancel-publication")
    cancel_parser.add_argument("--transaction", required=True)
    cancel_parser.add_argument("--digest", required=True)

    pending_drop_parser = commands.add_parser("pending-drop")
    pending_drop_parser.add_argument("--name", required=True)
    pending_drop_parser.add_argument("--input", required=True)

    for command in ("publish", "begin-scan", "cleanup"):
        command_parser = commands.add_parser(command)
        command_parser.add_argument("--transaction", required=True)

    for command in (
        "record-scan",
        "check-batch",
        "check-review",
        "record-application",
        "check-memories",
    ):
        command_parser = commands.add_parser(command)
        command_parser.add_argument("--transaction", required=True)
        command_parser.add_argument("--input", required=True)

    await_parser = commands.add_parser("await-approval")
    await_parser.add_argument("--transaction", required=True)
    await_parser.add_argument("--revision", required=True)
    await_parser.add_argument("--digest", required=True)

    reconcile_parser = commands.add_parser("reconcile-cleanup")
    reconcile_parser.add_argument("--transaction", required=True)
    reconcile_parser.add_argument("--ordinal", required=True)
    reconcile_parser.add_argument(
        "--outcome",
        choices=("moved", "preserved"),
        required=True,
    )
    return parser


def _emit(payload: Mapping[str, object], *, error: bool = False) -> None:
    record = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream = sys.stderr if error else sys.stdout
    try:
        written = stream.write(record)
        if written != len(record):
            raise OSError
        stream.flush()
    except UnicodeError as output_error:
        raise _OutputFailure(IntakeError("invalid_input", "memory")) from output_error
    except OSError as output_error:
        raise _OutputFailure(IntakeError("filesystem_error", "drift")) from output_error
    except Exception as output_error:
        raise _OutputFailure(IntakeError("internal_error", "state")) from output_error


def _error_json(
    error: IntakeError, state: TransactionState | None
) -> dict[str, object]:
    effective_state = error.state if error.state is not None else state
    return {
        "schema": _ERROR_SCHEMA,
        "code": error.code,
        "state": effective_state.value if effective_state is not None else None,
        "ordinal": error.ordinal,
        "retryable": error.retryable,
    }


def _finish_error(error: IntakeError, context: _Context) -> int:
    """Attempt one canonical error record without letting output escape."""
    exit_code = _EXIT_CODES[error.category]
    try:
        _emit(_error_json(error, context.state), error=True)
    except Exception:
        pass
    return exit_code


def _status_json(receipt: TransactionReceipt) -> dict[str, object]:
    cleanup_failures = [
        {"ordinal": ordinal, "code": entry.failure}
        for ordinal, entry in enumerate(receipt.cleanup_entries)
        if entry.failure is not None
    ]
    return {
        "schema": _STATUS_SCHEMA,
        "status": receipt.state.value,
        "transaction_id": receipt.transaction_id,
        "manifest_digest": receipt.manifest_digest,
        "batch_sensitivity": receipt.batch_sensitivity,
        "candidate_count": len(receipt.candidates),
        "guard_link_count": len(receipt.guard_links),
        "published_count": len(receipt.published_files),
        "scan_started": receipt.scan_started,
        "batch_id": receipt.batch_id,
        "scan_source_count": len(receipt.scan_source_ids),
        "scan_issues": [
            {"code": issue.code, "count": issue.count} for issue in receipt.scan_issues
        ],
        "scan_has_more": receipt.scan_has_more,
        "scan_page_has_more": receipt.scan_page_has_more,
        "source_binding_count": len(receipt.source_bindings),
        "duplicate_notices": [
            {"source_id": notice.source_id, "duplicate_of": notice.duplicate_of}
            for notice in receipt.duplicate_notices
        ],
        "change_set_id": receipt.change_set_id,
        "revision_id": receipt.revision_id,
        "review_digest": receipt.review_digest,
        "application_id": receipt.application_id,
        "memory_ids": list(receipt.memory_ids),
        "standing_guard_violations": [
            {
                "guard_lineage_id": warning.guard_lineage_id,
                "guard_sensitivity": warning.guard_sensitivity,
                "governed_lineage_id": warning.governed_lineage_id,
                "governed_sensitivity": warning.governed_sensitivity,
            }
            for warning in receipt.standing_guard_violations
        ],
        "cleanup_entry_count": len(receipt.cleanup_entries),
        "cleanup_resolved_count": sum(
            entry.outcome is not None for entry in receipt.cleanup_entries
        ),
        "cleanup_failures": cleanup_failures,
    }


def _require_hash(value: str) -> str:
    if _HASH_PATTERN.fullmatch(value) is None:
        raise IntakeError("invalid_arguments", "configuration")
    return value


def _require_transaction_id(value: str) -> str:
    if _TRANSACTION_PATTERN.fullmatch(value) is None:
        raise IntakeError("invalid_arguments", "configuration")
    return value


def _require_ordinal(value: str) -> int:
    if len(value) > 10 or not value.isascii() or not value.isdecimal():
        raise IntakeError("invalid_arguments", "configuration")
    try:
        ordinal = int(value)
    except ValueError as error:
        raise IntakeError("invalid_arguments", "configuration") from error
    if ordinal < 0:
        raise IntakeError("invalid_arguments", "configuration")
    return ordinal


def _require_note_name(value: str) -> str:
    if (
        not value
        or "\0" in value
        or PurePosixPath(value).parts != (value,)
        or value.startswith(".")
        or not value.endswith(".md")
        or len(value) <= len(".md")
        or len(value.encode("utf-8")) > 255
    ):
        raise IntakeError("invalid_arguments", "configuration")
    return value


def _read_stream(stream: BinaryIO) -> bytes:
    chunks: list[bytes] = []
    remaining = _INPUT_LIMIT + 1
    while remaining:
        chunk = stream.read(min(_INPUT_CHUNK, remaining))
        if not isinstance(chunk, bytes):
            raise IntakeError("invalid_input", "memory")
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > _INPUT_LIMIT:
        raise IntakeError("input_too_large", "memory")
    return raw


def _same_input(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_input(value: str) -> bytes:
    if value == "-":
        stream = getattr(sys.stdin, "buffer", None)
        if stream is None or not hasattr(stream, "read"):
            raise IntakeError("invalid_input", "memory")
        return _read_stream(cast(BinaryIO, stream))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(Path(value), flags)
    except OSError as error:
        raise IntakeError("unsafe_input_file", "drift") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise IntakeError("unsafe_input_file", "drift")
        if before.st_size > _INPUT_LIMIT:
            raise IntakeError("input_too_large", "memory")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
            raw = _read_stream(stream)
        after = os.fstat(descriptor)
        if not _same_input(before, after) or len(raw) != before.st_size:
            raise IntakeError("input_changed", "drift")
        return raw
    finally:
        os.close(descriptor)


def _envelope(value: str) -> Mapping[str, object]:
    parsed = parse_success_envelope(_read_input(value))
    if not isinstance(parsed, dict):
        raise IntakeError("invalid_memory_envelope", "memory")
    return parsed


def _load_active(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
) -> TransactionReceipt:
    active = store.active()
    if active is None or active.transaction_id != transaction_id:
        raise IntakeError("inactive_transaction", "state")
    context.state = active.state
    return active


def _load_active_or_complete(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
) -> TransactionReceipt:
    active = store.active()
    if active is not None and active.transaction_id == transaction_id:
        context.state = active.state
        return active
    try:
        receipt = store.load(transaction_id)
    except IntakeError as error:
        raise IntakeError("inactive_transaction", "state") from error
    if receipt.state is not TransactionState.COMPLETE:
        raise IntakeError("inactive_transaction", "state")
    context.state = receipt.state
    return receipt


def _is_inactive_complete(
    store: TransactionStore,
    transaction_id: str,
) -> bool:
    try:
        store.state_root.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise IntakeError("invalid_state_root", "configuration") from error
    with store.lock():
        try:
            receipt = store.load(transaction_id)
        except IntakeError:
            return False
        active = store.active()
        return receipt.state is TransactionState.COMPLETE and active != receipt


def _preflight_input_state(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
    allowed: frozenset[TransactionState],
) -> None:
    with store.lock():
        receipt = _load_active(store, transaction_id, context)
        if receipt.state not in allowed:
            raise IntakeError(
                "invalid_snapshot_state",
                "state",
                state=receipt.state,
            )


def _persist_result(
    store: TransactionStore,
    current: TransactionReceipt,
    result: TransactionReceipt,
) -> TransactionReceipt:
    if result.transaction_id != current.transaction_id:
        raise IntakeError("invalid_transaction_update", "state", state=current.state)
    changed = {
        field.name: getattr(result, field.name)
        for field in fields(TransactionReceipt)
        if field.name != "state"
        and getattr(result, field.name) != getattr(current, field.name)
    }
    if not set(changed) <= _MUTABLE_FIELDS[result.state]:
        raise IntakeError("invalid_transaction_update", "state", state=current.state)
    return store.advance(current, result.state, **changed)


def _mutate(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
    operation: Callable[[TransactionReceipt], TransactionReceipt],
) -> TransactionReceipt:
    with store.lock():
        if cancellation_status(store) is not None:
            raise IntakeError("cancellation_pending", "state", retryable=True)
        current = _load_active(store, transaction_id, context)
        result = operation(current)
        persisted = _persist_result(store, current, result)
        context.state = persisted.state
        return persisted


def _refresh_context(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
) -> None:
    try:
        with store.lock():
            context.state = store.load(transaction_id).state
    except IntakeError:
        pass


def _run_locked_helper(
    store: TransactionStore,
    transaction_id: str,
    context: _Context,
    operation: Callable[[], TransactionReceipt],
    *,
    allow_complete: bool = False,
) -> TransactionReceipt:
    with store.lock():
        if allow_complete:
            _load_active_or_complete(store, transaction_id, context)
        else:
            _load_active(store, transaction_id, context)
    try:
        result = operation()
    except Exception:
        _refresh_context(store, transaction_id, context)
        raise
    context.state = result.state
    return result


def _review_plan(
    receipt: TransactionReceipt,
    config: IntakeConfig,
) -> dict[str, object]:
    return {
        "schema": _REVIEW_PLAN_SCHEMA,
        "transaction_id": receipt.transaction_id,
        "batch_id": receipt.batch_id,
        "change_set_id": receipt.change_set_id,
        "revision_id": receipt.revision_id,
        "edits": list(build_review_edits(receipt, config)),
    }


def _dispatch_locked(
    parsed: argparse.Namespace,
    dependencies: Dependencies,
    context: _Context,
) -> Mapping[str, object]:
    state_root = cast(Path, parsed.state_root)
    if not state_root.is_absolute():
        raise IntakeError("invalid_state_root", "configuration")
    memory_paths_runner = _MemoryPathsRunner(dependencies.memory_paths_runner)
    command = cast(str, parsed.command)
    cancellation_store = TransactionStore.for_operation(state_root)
    pending_cancellation = cancellation_status(cancellation_store)
    if command == "status":
        cancellation = cancellation_status(
            cancellation_store,
            cast(str | None, parsed.transaction),
        )
        if cancellation is not None:
            return cancellation
    elif command != "cancel-publication" and pending_cancellation is not None:
        raise IntakeError("cancellation_pending", "state", retryable=True)
    if command == "cancel-publication":
        cancel_transaction_id = _require_transaction_id(cast(str, parsed.transaction))
        digest = _require_hash(cast(str, parsed.digest))
        if (
            pending_cancellation is not None
            and pending_cancellation["transaction_id"] != cancel_transaction_id
        ):
            raise IntakeError("cancellation_pending", "state", retryable=True)
        if relocation_pending(state_root) or layout_migration_pending(state_root):
            raise IntakeError("cancellation_not_allowed", "state")
        return cancel_publication(
            load_config_record(state_root),
            cancellation_store,
            cancel_transaction_id,
            digest,
            memory_paths_runner,
            dependencies.publication_fault,
        )
    if command == "abandon-unsupported":
        # The hatch exists for state every other gate refuses on; running
        # those gates first would wedge the hatch itself.
        abandoned: list[str] = []
        if abandon_unsupported_layout_intent(state_root):
            abandoned.append("layout_migration_intent")
        if abandon_unsupported_relocation_intent(state_root):
            abandoned.append("relocation_intent")
        if abandon_unsupported_transaction(state_root):
            abandoned.append("transaction")
        if not abandoned:
            raise IntakeError("no_unsupported_state", "state")
        return {
            "schema": _ABANDON_SCHEMA,
            "status": "abandoned",
            "abandoned": abandoned,
        }
    if command != "relocate" and relocation_pending(state_root):
        raise IntakeError("relocation_pending", "state", retryable=True)
    if command != "migrate-layout" and layout_migration_pending(state_root):
        raise IntakeError("layout_migration_pending", "state", retryable=True)
    if command != "migrate-layout" and layout_migration_required(state_root):
        raise IntakeError("layout_migration_required", "state")
    if command == "configure":
        pending_drop_choice = cast(str | None, parsed.pending_drop)
        configured = configure(
            state_root,
            cast(Path, parsed.notes_root),
            cast(Path | None, parsed.memory_home),
            create_prepared=cast(bool, parsed.create_prepared),
            runner=memory_paths_runner,
            pending_drop=(
                None if pending_drop_choice is None else pending_drop_choice == "on"
            ),
        )
        return {
            "schema": _STATUS_SCHEMA,
            "status": "configured",
            "pending_drop": configured.pending_drop,
        }
    if command == "relocate":
        relocation_result = relocate_notes_root(
            state_root,
            cast(Path, parsed.to),
            memory_paths_runner,
            adopt_current_authority=cast(bool, parsed.adopt_current_authority),
        )
        return {"schema": _RELOCATION_SCHEMA, "status": relocation_result.status}
    if command == "migrate-layout":
        migration_result = migrate_layout(state_root, memory_paths_runner)
        return {
            "schema": _LAYOUT_MIGRATION_SCHEMA,
            "status": migration_result.status,
        }
    if command == "status":
        loaded_config = load_config(state_root)
        if loaded_config is None:
            return {"schema": _STATUS_SCHEMA, "status": "unconfigured"}
        store = TransactionStore.for_operation(state_root)
        transaction_id = cast(str | None, parsed.transaction)
        with store.lock():
            receipt = (
                store.load(transaction_id)
                if transaction_id is not None
                else store.active()
            )
        if receipt is None:
            return {
                "schema": _STATUS_SCHEMA,
                "status": "configured",
                "pending_drop": loaded_config.pending_drop,
            }
        context.state = receipt.state
        return _status_json(receipt)

    if command in {"cleanup", "reconcile-cleanup"}:
        transaction_id = cast(str, parsed.transaction)
        store = TransactionStore.for_operation(state_root)
        if _is_inactive_complete(store, transaction_id):
            if command == "cleanup":
                completed = replay_complete_cleanup(store, transaction_id)
            else:
                completed = reconcile_cleanup(
                    store,
                    transaction_id,
                    _require_ordinal(cast(str, parsed.ordinal)),
                    cast(CleanupOutcome, cast(str, parsed.outcome)),
                )
            context.state = completed.state
            return _status_json(completed)

    config = require_config(state_root)
    if command == "pending-drop":
        if not config.pending_drop:
            raise IntakeError("pending_drop_disabled", "configuration")
        note_name = _require_note_name(cast(str, parsed.name))
        raw = _read_input(cast(str, parsed.input))
        if not raw:
            raise IntakeError("invalid_arguments", "configuration")
        if len(raw) > _PENDING_NOTE_LIMIT:
            raise IntakeError("input_too_large", "memory")
        create_pending_note(config.notes_root, NUMBERED_LAYOUT.pending, note_name, raw)
        return {"schema": _STATUS_SCHEMA, "status": "pending_note_created"}
    store = TransactionStore.for_operation(state_root)
    if command == "preview":
        preview_command = cast(str, parsed.preview_command)
        if preview_command == "prepared":
            preview = build_preview(
                config,
                cast(list[str], parsed.prepared),
                cast(list[str], parsed.guard_link),
            )
            payload = preview_json(preview)
            payload["schema"] = _PREVIEW_SCHEMA
            return payload
        transaction_id = cast(str, parsed.transaction)
        with store.lock():
            receipt = _load_active(store, transaction_id, context)
            return _review_plan(receipt, config)
    if command == "authorize":
        approved_digest = _require_hash(cast(str, parsed.digest))
        supersede_transaction_raw = cast(
            str | None,
            parsed.supersede_transaction,
        )
        supersede_digest_raw = cast(str | None, parsed.supersede_digest)
        if (supersede_transaction_raw is None) != (supersede_digest_raw is None):
            raise IntakeError("invalid_arguments", "configuration")
        supersede_transaction_id = (
            None
            if supersede_transaction_raw is None
            else _require_transaction_id(supersede_transaction_raw)
        )
        supersede_manifest_digest = (
            None
            if supersede_digest_raw is None
            else _require_hash(supersede_digest_raw)
        )
        with store.lock():
            active = store.active()
            if active is not None:
                context.state = active.state
                if hmac.compare_digest(active.manifest_digest, approved_digest):
                    if supersede_transaction_id is not None and (
                        active.state is not TransactionState.OWNER_AUTHORIZED
                        or active.transaction_id != supersede_transaction_id
                        or supersede_manifest_digest is None
                        or not hmac.compare_digest(
                            active.manifest_digest,
                            supersede_manifest_digest,
                        )
                    ):
                        raise IntakeError("invalid_supersede", "state")
                    return _status_json(active)
                if supersede_transaction_id is None:
                    raise IntakeError(
                        "transaction_active",
                        "state",
                        state=active.state,
                    )
                if (
                    active.state is not TransactionState.OWNER_AUTHORIZED
                    or active.transaction_id != supersede_transaction_id
                    or supersede_manifest_digest is None
                    or not hmac.compare_digest(
                        active.manifest_digest,
                        supersede_manifest_digest,
                    )
                ):
                    raise IntakeError("invalid_supersede", "state")
            elif supersede_transaction_id is not None:
                raise IntakeError("invalid_supersede", "state")
            preview = build_preview(
                config,
                cast(list[str], parsed.prepared),
                cast(list[str], parsed.guard_link),
            )
            if supersede_transaction_id is None:
                receipt = store.authorize(preview, approved_digest)
            else:
                receipt = store.authorize(
                    preview,
                    approved_digest,
                    supersede_transaction_id=supersede_transaction_id,
                    supersede_manifest_digest=supersede_manifest_digest,
                )
            context.state = receipt.state
            return _status_json(receipt)

    transaction_id = cast(str, parsed.transaction)
    if command in _INPUT_STATES:
        _preflight_input_state(
            store,
            transaction_id,
            context,
            _INPUT_STATES[command],
        )
    if command == "publish":
        with store.lock():
            current = _load_active(store, transaction_id, context)
        if current.state is TransactionState.OWNER_AUTHORIZED:

            def operation() -> TransactionReceipt:
                return publish(
                    config,
                    store,
                    transaction_id,
                    dependencies.publication_fault,
                    memory_paths_runner=memory_paths_runner,
                )

        elif current.state in {TransactionState.PUBLISHING, TransactionState.PUBLISHED}:

            def operation() -> TransactionReceipt:
                return recover_publication(
                    config,
                    store,
                    transaction_id,
                    dependencies.publication_fault,
                    memory_paths_runner=memory_paths_runner,
                )

        else:
            raise IntakeError(
                "publication_not_authorized", "state", state=current.state
            )
        return _status_json(
            _run_locked_helper(store, transaction_id, context, operation)
        )
    if command == "begin-scan":
        return _status_json(_mutate(store, transaction_id, context, begin_scan))
    if command == "record-scan":
        envelope = _envelope(cast(str, parsed.input))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: record_scan(receipt, envelope),
            )
        )
    if command == "check-batch":
        envelope = _envelope(cast(str, parsed.input))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: check_batch(receipt, envelope),
            )
        )
    if command == "check-review":
        envelope = _envelope(cast(str, parsed.input))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: check_review(receipt, envelope),
            )
        )
    if command == "await-approval":
        revision = cast(str, parsed.revision)
        digest = _require_hash(cast(str, parsed.digest))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: mark_awaiting_approval(receipt, revision, digest),
            )
        )
    if command == "record-application":
        envelope = _envelope(cast(str, parsed.input))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: record_application(receipt, envelope),
            )
        )
    if command == "check-memories":
        envelope = _envelope(cast(str, parsed.input))
        return _status_json(
            _mutate(
                store,
                transaction_id,
                context,
                lambda receipt: check_memories(receipt, config, envelope),
            )
        )
    if command == "cleanup":
        return _status_json(
            _run_locked_helper(
                store,
                transaction_id,
                context,
                lambda: cleanup(config, store, transaction_id, dependencies.trash),
                allow_complete=True,
            )
        )
    if command == "reconcile-cleanup":
        ordinal = _require_ordinal(cast(str, parsed.ordinal))
        outcome = cast(str, parsed.outcome)
        return _status_json(
            _run_locked_helper(
                store,
                transaction_id,
                context,
                lambda: reconcile_cleanup(
                    store,
                    transaction_id,
                    ordinal,
                    cast(CleanupOutcome, outcome),
                ),
                allow_complete=True,
            )
        )
    raise IntakeError("invalid_arguments", "configuration")


def _dispatch(
    parsed: argparse.Namespace,
    dependencies: Dependencies,
    context: _Context,
) -> Mapping[str, object]:
    """Keep every existing-root command's recovery fence and action serialized."""
    state_root = cast(Path, parsed.state_root)
    if not state_root.is_absolute():
        raise IntakeError("invalid_state_root", "configuration")
    try:
        state_root.lstat()
    except FileNotFoundError:
        # Unconfigured status is read-only; first configuration owns its
        # existing exclusive-creation protocol and cannot have a prior intent.
        return _dispatch_locked(parsed, dependencies, context)
    with TransactionStore(state_root).lock():
        return _dispatch_locked(parsed, dependencies, context)


def main(
    argv: Sequence[str] | None = None,
    *,
    dependencies: Dependencies | None = None,
) -> int:
    """Run one bounded helper command and emit only its canonical record."""
    active_dependencies = dependencies or _production_dependencies()
    context = _Context()
    try:
        parsed = _parser().parse_args(sys.argv[1:] if argv is None else list(argv))
        payload = _dispatch(parsed, active_dependencies, context)
        _emit(payload)
        return 0
    except _ParserExit:
        return 0
    except IntakeError as error:
        return _finish_error(error, context)
    except _OutputFailure as failure:
        return _finish_error(failure.mapped, context)
    except OSError:
        mapped = IntakeError("filesystem_error", "drift")
        return _finish_error(mapped, context)
    except UnicodeError, json.JSONDecodeError:
        mapped = IntakeError("invalid_input", "memory")
        return _finish_error(mapped, context)
    except subprocess.SubprocessError:
        mapped = IntakeError("external_command_failed", "trash", retryable=True)
        return _finish_error(mapped, context)
    except Exception:
        if active_dependencies.debug_exceptions:
            raise
        mapped = IntakeError("internal_error", "state")
        return _finish_error(mapped, context)
