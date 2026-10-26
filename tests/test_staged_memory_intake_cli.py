"""Content-safe command-line orchestration for staged Memory intake."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast

import pytest
import staged_memory_intake.cleanup as cleanup_module
import staged_memory_intake.prepared as prepared_module
from staged_memory_intake.cli import Dependencies, main
from staged_memory_intake.config import CONFIG_SCHEMA, configure
from staged_memory_intake.layout_migration import migrate_layout
from staged_memory_intake.model import (
    CommandRunner,
    CompletedCommand,
    IntakeError,
    NoPublicationFault,
    PromotionPreview,
    TransactionReceipt,
    TransactionState,
)
from staged_memory_intake.prepared import parse_prepared
from staged_memory_intake.securefs import (
    atomic_private_json,
    directory_identity,
)
from staged_memory_intake.securefs import read_regular as secure_read_regular
from staged_memory_intake.state import TransactionStore
from staged_memory_intake_fakes import FakeMemoryPathsRunner, FakeTrash, NeverRunner

PRIVATE_BODY = "SYNTHETIC-PRIVATE-BODY-7d873c"
PRIVATE_NAME = "SYNTHETIC-PRIVATE-NAME-51f93e.md"
PRIVATE_PATH = "SYNTHETIC-PRIVATE-PATH-0f8c3b"
PRIVATE_ERROR = "SYNTHETIC-PRIVATE-ERROR-bbdc21"
PRIVATE_EVIDENCE = "SYNTHETIC-PRIVATE-EVIDENCE-9db74a"
PRIVATE_TAG = "SYNTHETIC-PRIVATE-TAG-b405f1"
PRIVATE_MARKERS = (
    PRIVATE_BODY,
    PRIVATE_NAME,
    PRIVATE_PATH,
    PRIVATE_ERROR,
    PRIVATE_EVIDENCE,
    PRIVATE_TAG,
)
ERROR_FIELDS = {"schema", "code", "state", "ordinal", "retryable"}
STATUS_FIELDS = {
    "application_id",
    "batch_id",
    "batch_sensitivity",
    "candidate_count",
    "change_set_id",
    "cleanup_entry_count",
    "cleanup_failures",
    "cleanup_resolved_count",
    "duplicate_notices",
    "guard_link_count",
    "manifest_digest",
    "memory_ids",
    "published_count",
    "review_digest",
    "revision_id",
    "scan_has_more",
    "scan_issues",
    "scan_page_has_more",
    "scan_source_count",
    "scan_started",
    "schema",
    "source_binding_count",
    "standing_guard_violations",
    "status",
    "transaction_id",
}


@dataclass
class LayoutMemoryRunner:
    """Synthetic public Memory CLI for one disposable folder migration."""

    home: Path
    inbox: Path
    calls: list[tuple[tuple[str, ...], float]] = field(default_factory=list)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        command = tuple(argv)
        self.calls.append((command, timeout_seconds))
        if command[:2] == ("memory", "paths"):
            return CompletedCommand(
                0,
                json.dumps(
                    {
                        "database": str(self.home / "synthetic-database"),
                        "home": str(self.home),
                        "identity": str(self.home / "synthetic-identity"),
                        "inbox": str(self.inbox),
                        "inbox_claims": str(self.home / "synthetic-claims"),
                    }
                ).encode(),
                b"",
            )
        if command[:2] == ("memory", "relocate-inbox"):
            destination = Path(command[command.index("--to") + 1])
            if destination == self.inbox:
                status = "current"
            else:
                self.inbox.rename(destination)
                self.inbox = destination
                status = "relocated"
            return CompletedCommand(0, f'{{"status":"{status}"}}\n'.encode(), b"")
        raise AssertionError(command)


class SyntheticLayoutCrash(BaseException):
    """Simulate process loss after one migration intent is durable."""


@dataclass(frozen=True)
class CrashAfterLayoutIntent:
    def checkpoint(self, name: str) -> None:
        if name == "intent_published":
            raise SyntheticLayoutCrash


def _legacy_layout_environment(
    tmp_path: Path,
) -> tuple[Path, Path, LayoutMemoryRunner, Dependencies]:
    notes = tmp_path / "synthetic-legacy-captures"
    home = tmp_path / "synthetic-layout-memory-home"
    state_root = tmp_path / "synthetic-layout-state"
    trash_root = tmp_path / "synthetic-layout-trash"
    for path in (
        notes,
        notes / "Pending",
        notes / "Staged",
        notes / "Prepared",
        notes / "Inbox",
        home,
        state_root,
        trash_root,
    ):
        path.mkdir(mode=0o700)
    inbox = notes / "Inbox"
    notes_identity = directory_identity(notes)
    inbox_identity = directory_identity(inbox)
    atomic_private_json(
        state_root / "config.json",
        {
            "schema": CONFIG_SCHEMA,
            "notes_root": str(notes),
            "notes_identity": {
                "volume": notes_identity.volume,
                "inode": notes_identity.inode,
            },
            "memory_home": str(home),
            "memory_inbox": str(inbox),
            "inbox_identity": {
                "volume": inbox_identity.volume,
                "inode": inbox_identity.inode,
            },
        },
    )
    runner = LayoutMemoryRunner(home, inbox)
    dependencies = Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash_root),
        publication_fault=NoPublicationFault(),
    )
    return state_root, notes, runner, dependencies


def _prepared(
    source_name: str,
    source: bytes,
    statement: str,
    *,
    kind: str,
    sensitivity: str,
    tags: str,
) -> bytes:
    return (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(source).hexdigest()}\n"
        f"kind: {kind}\n"
        f"sensitivity: {sensitivity}\n"
        "occurred_on: \n"
        "valid_from: \n"
        "valid_to: \n"
        f"tags: {tags}\n"
        "---\n"
        f"{statement}\n"
    ).encode()


@dataclass(frozen=True)
class CliEnvironment:
    root: Path
    state_root: Path
    notes: Path
    home: Path
    inbox: Path
    trash_root: Path
    paths_runner: FakeMemoryPathsRunner
    process_runner: NeverRunner
    trash: FakeTrash
    dependencies: Dependencies


def _environment(tmp_path: Path) -> CliEnvironment:
    notes = tmp_path / PRIVATE_PATH
    home = tmp_path / "synthetic-memory-home"
    inbox = tmp_path / "synthetic-inbox"
    trash_root = tmp_path / "synthetic-trash"
    for path in (
        notes,
        notes / "01_Pending",
        notes / "02_Staged",
        notes / "03_Prepared",
        home,
        inbox,
        trash_root,
    ):
        path.mkdir(mode=0o700)
    sources = (
        f"{PRIVATE_EVIDENCE} source alpha.".encode(),
        f"{PRIVATE_EVIDENCE} source beta with Unicode 界.".encode(),
    )
    source_names = ("private-alpha-source.md", "private-beta-source.md")
    prepared_names = (PRIVATE_NAME, "private-beta-prepared.md")
    statements = (
        f"{PRIVATE_BODY} {PRIVATE_EVIDENCE} alpha statement.",
        f"{PRIVATE_BODY} {PRIVATE_EVIDENCE} beta statement with Unicode 界.",
    )
    for name, value in zip(source_names, sources, strict=True):
        (notes / "02_Staged" / name).write_bytes(value)
    prepared_values = (
        _prepared(
            source_names[0],
            sources[0],
            statements[0],
            kind="fact",
            sensitivity="normal",
            tags=f'["{PRIVATE_TAG}","alpha"]',
        ),
        _prepared(
            source_names[1],
            sources[1],
            statements[1],
            kind="preference",
            sensitivity="sensitive",
            tags=f'["{PRIVATE_TAG}","beta"]',
        ),
    )
    for name, value in zip(prepared_names, prepared_values, strict=True):
        (notes / "03_Prepared" / name).write_bytes(value)
    paths_runner = FakeMemoryPathsRunner(home=home, inbox=inbox)
    process_runner = NeverRunner()
    trash = FakeTrash(trash_root)
    dependencies = Dependencies(
        memory_paths_runner=paths_runner,
        process_runner=process_runner,
        trash=trash,
        publication_fault=NoPublicationFault(),
    )
    return CliEnvironment(
        root=tmp_path,
        state_root=tmp_path / "synthetic-state",
        notes=notes,
        home=home,
        inbox=inbox,
        trash_root=trash_root,
        paths_runner=paths_runner,
        process_runner=process_runner,
        trash=trash,
        dependencies=dependencies,
    )


def _invoke(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> tuple[int, str, str]:
    result = main(
        ["--state-root", str(environment.state_root), *arguments],
        dependencies=environment.dependencies,
    )
    output = capsys.readouterr()
    contentful_preview = arguments[:2] in (
        ["preview", "prepared"],
        ["preview", "review"],
    ) and bool(output.out)
    if not contentful_preview:
        assert bool(output.out) != bool(output.err)
        operational = output.out or output.err
        for marker in PRIVATE_MARKERS:
            assert marker not in operational
        assert "Traceback" not in operational
        payload = _payload(operational)
        schema = payload.get("schema")
        if schema == "staged-memory-intake.error.v1":
            assert set(payload) == ERROR_FIELDS
        elif payload.get("status") == "configured":
            assert set(payload) == {"schema", "status", "pending_drop"}
        elif payload.get("status") == "pending_note_created":
            assert set(payload) == {"schema", "status"}
        elif schema == "staged-memory-intake.abandon.v1":
            assert set(payload) == {"schema", "status", "abandoned"}
        else:
            assert schema == "staged-memory-intake.status.v1"
            assert set(payload) == STATUS_FIELDS
    return result, output.out, output.err


def _payload(output: str) -> dict[str, object]:
    value = json.loads(output)
    assert isinstance(value, dict)
    assert (
        output
        == json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return value


def _write_input(environment: CliEnvironment, value: object) -> Path:
    path = environment.root / "synthetic-envelope.json"
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _configure(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> dict[str, object]:
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
        ],
    )
    assert code == 0
    assert stderr == ""
    return _payload(stdout)


def _authorize(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> tuple[str, list[dict[str, object]]]:
    _configure(environment, capsys)
    selected = [PRIVATE_NAME, "private-beta-prepared.md"]
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "preview",
            "prepared",
            "--prepared",
            selected[0],
            "--prepared",
            selected[1],
        ],
    )
    assert code == 0
    assert stderr == ""
    preview = _payload(stdout)
    assert preview["schema"] == "staged-memory-intake.preview.v1"
    candidates = cast(list[dict[str, object]], preview["candidates"])
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            cast(str, preview["manifest_digest"]),
            "--prepared",
            selected[0],
            "--prepared",
            selected[1],
        ],
    )
    assert code == 0
    assert stderr == ""
    status = _payload(stdout)
    transaction_id = cast(str, status["transaction_id"])
    return transaction_id, candidates


def _authorize_and_publish(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> tuple[str, list[dict[str, object]]]:
    transaction_id, candidates = _authorize(environment, capsys)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["publish", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "published"
    return transaction_id, candidates


def _awaiting_application_receipt(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> TransactionReceipt:
    transaction_id, _ = _authorize(environment, capsys)
    store = TransactionStore(environment.state_root)
    current = store.load(transaction_id)
    current = store.advance(current, TransactionState.PUBLISHING)
    current = store.advance(current, TransactionState.PUBLISHED)
    current = store.advance(current, TransactionState.CAPTURED)
    current = store.advance(
        current,
        TransactionState.REVIEW_READY,
        change_set_id="chg_synthetic_large",
        revision_id="rev_synthetic_large",
        review_digest="d" * 64,
    )
    return store.advance(current, TransactionState.AWAITING_MEMORY_APPROVAL)


def _application_bytes_of_size(size: int) -> bytes:
    warning = {
        "guard_lineage_id": "lin_guard_",
        "guard_sensitivity": "restricted",
        "governed_lineage_id": "lin_governed_large",
        "governed_sensitivity": "normal",
    }
    envelope = _success(
        {
            "application_id": "app_synthetic_large",
            "change_set_id": "chg_synthetic_large",
            "revision_id": "rev_synthetic_large",
            "memory_ids": ["mem_synthetic_alpha", "mem_synthetic_beta"],
            "idempotent_replay": False,
            "standing_guard_violations": [warning],
        }
    )

    def encoded() -> bytes:
        return json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    baseline = encoded()
    padding = size - len(baseline)
    assert padding >= 0
    warning["guard_lineage_id"] += "x" * padding
    raw = encoded()
    assert len(raw) == size
    return raw


@pytest.fixture
def dependencies(tmp_path: Path) -> Dependencies:
    home = tmp_path / "synthetic-memory-home"
    inbox = tmp_path / "synthetic-inbox"
    trash = tmp_path / "synthetic-trash"
    for path in (home, inbox, trash):
        path.mkdir(mode=0o700)
    runner = FakeMemoryPathsRunner(home=home, inbox=inbox)
    return Dependencies(
        memory_paths_runner=runner,
        process_runner=NeverRunner(),
        trash=FakeTrash(trash),
        publication_fault=NoPublicationFault(),
    )


def test_cli_reports_stale_initial_configuration_without_repointing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    winner_notes = tmp_path / "synthetic-winner-notes"
    for path in (
        winner_notes,
        winner_notes / "01_Pending",
        winner_notes / "02_Staged",
        winner_notes / "03_Prepared",
    ):
        path.mkdir(mode=0o700)
    winner_bytes: list[bytes] = []

    class InterleavingRunner:
        invoked = False

        def run(
            self,
            argv: Sequence[str],
            *,
            timeout_seconds: float,
        ) -> CompletedCommand:
            if not self.invoked:
                self.invoked = True
                configure(
                    environment.state_root,
                    winner_notes,
                    environment.home,
                    create_prepared=False,
                    runner=FakeMemoryPathsRunner(environment.home, environment.inbox),
                )
                winner_bytes.append(
                    (environment.state_root / "config.json").read_bytes()
                )
            return environment.paths_runner.run(
                argv,
                timeout_seconds=timeout_seconds,
            )

    racing = replace(
        environment,
        dependencies=Dependencies(
            memory_paths_runner=InterleavingRunner(),
            process_runner=environment.process_runner,
            trash=environment.trash,
            publication_fault=NoPublicationFault(),
        ),
    )

    code, stdout, stderr = _invoke(
        racing,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
        ],
    )

    assert code == 2
    assert stdout == ""
    assert _payload(stderr)["code"] == "stale_configuration"
    assert len(winner_bytes) == 1
    assert (environment.state_root / "config.json").read_bytes() == winner_bytes[0]


def test_abandon_unsupported_clears_an_upgrade_wedged_state_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch every command refusing forever after an interrupted upgrade.

    A pre-v3 receipt or pre-v2 intent left over from before the upgrade made
    every command refuse with no abandon or cancel path; recovery required
    manual state-root surgery. The explicit hatch removes exactly the
    unsupported artifacts -- quarantined, not deleted -- and reports what it
    abandoned so the owner can restart the interrupted work.
    """
    environment = _environment(tmp_path)
    configured, _, _ = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
            "--create-prepared",
        ],
    )
    assert configured == 0
    state_root = environment.state_root
    transaction_id = "tx_" + "3" * 32
    receipt_path = state_root / f"{transaction_id}.json"
    receipt_path.write_text(
        json.dumps(
            {
                "schema": "staged-memory-intake.transaction.v2",
                "transaction_id": transaction_id,
                "state": "publishing",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    pointer = state_root / "active.json"
    pointer.write_text(
        json.dumps({"transaction_id": transaction_id}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    pointer.chmod(0o600)
    atomic_private_json(
        state_root / ".notes-root-relocation.intent.json",
        {"schema": "staged-memory-intake.root-relocation.v1", "phase": "prepared"},
    )
    atomic_private_json(
        state_root / ".layout-migration.intent.json",
        {
            "schema": "staged-memory-intake.layout-migration-intent.v1",
            "phase": "prepared",
        },
    )

    wedged, _, wedged_error = _invoke(environment, capsys, ["status"])
    assert wedged == 3
    assert _payload(wedged_error)["code"] == "relocation_intent_invalid"

    exit_code, output, error = _invoke(environment, capsys, ["abandon-unsupported"])
    assert exit_code == 0
    assert error == ""
    assert _payload(output) == {
        "schema": "staged-memory-intake.abandon.v1",
        "status": "abandoned",
        "abandoned": [
            "layout_migration_intent",
            "relocation_intent",
            "transaction",
        ],
    }

    unwedged, unwedged_output, _ = _invoke(environment, capsys, ["status"])
    assert unwedged == 0
    assert _payload(unwedged_output)["status"] == "configured"

    repeat, _, repeat_error = _invoke(environment, capsys, ["abandon-unsupported"])
    assert repeat == 4
    assert _payload(repeat_error)["code"] == "no_unsupported_state"


def test_unconfigured_status_is_exact_and_creates_nothing(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_root = tmp_path / "PRIVATE-STATE-MARKER"

    result = main(
        ["--state-root", str(state_root), "status"],
        dependencies=dependencies,
    )

    assert result == 0
    assert capsys.readouterr() == (
        '{"schema":"staged-memory-intake.status.v1","status":"unconfigured"}\n',
        "",
    )
    assert not state_root.exists()


def test_migrate_layout_command_emits_only_exact_content_free_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Expose one argument-free command and no path or identity output."""
    state_root, notes, _, dependencies = _legacy_layout_environment(tmp_path)

    exit_code = main(
        ["--state-root", str(state_root), "migrate-layout"],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    assert _payload(output.out) == {
        "schema": "staged-memory-intake.layout-migration.v1",
        "status": "migrated",
    }
    assert set(os.listdir(notes)) == {
        "01_Pending",
        "02_Staged",
        "03_Prepared",
        "04_Inbox",
    }

    exit_code = main(
        ["--state-root", str(state_root), "migrate-layout"],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    assert _payload(output.out) == {
        "schema": "staged-memory-intake.layout-migration.v1",
        "status": "current",
    }


def test_migrate_layout_command_accepts_no_caller_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep migration bound to the already configured notes authority."""
    state_root, notes, _, dependencies = _legacy_layout_environment(tmp_path)

    exit_code = main(
        [
            "--state-root",
            str(state_root),
            "migrate-layout",
            "--to",
            str(tmp_path / PRIVATE_PATH),
        ],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 2
    assert output.out == ""
    assert _payload(output.err)["code"] == "invalid_arguments"
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}


def test_status_reports_exact_legacy_layout_as_migration_required(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Detect compatibility state without implicitly renaming any folder."""
    state_root, notes, runner, dependencies = _legacy_layout_environment(tmp_path)

    exit_code = main(
        ["--state-root", str(state_root), "status"],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert exit_code == 4
    assert output.out == ""
    assert _payload(output.err) == {
        "schema": "staged-memory-intake.error.v1",
        "code": "layout_migration_required",
        "state": None,
        "ordinal": None,
        "retryable": False,
    }
    assert set(os.listdir(notes)) == {"Pending", "Staged", "Prepared", "Inbox"}
    assert runner.calls == []


def test_only_migrate_layout_runs_while_its_intent_is_pending(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Gate every other parsed helper command before it touches workflow state."""
    state_root, notes, runner, dependencies = _legacy_layout_environment(tmp_path)
    with pytest.raises(SyntheticLayoutCrash):
        migrate_layout(state_root, runner, CrashAfterLayoutIntent())
    transaction_id = "tx_" + "0" * 32
    digest = "0" * 64
    non_migration_commands = [
        ["configure", "--notes-root", str(notes)],
        ["relocate", "--to", str(tmp_path / "synthetic-destination")],
        ["preview", "prepared", "--prepared", "synthetic.md"],
        ["preview", "review", "--transaction", transaction_id],
        ["authorize", "--digest", digest, "--prepared", "synthetic.md"],
        ["status"],
        ["publish", "--transaction", transaction_id],
        ["begin-scan", "--transaction", transaction_id],
        ["cleanup", "--transaction", transaction_id],
        ["record-scan", "--transaction", transaction_id, "--input", "-"],
        ["check-batch", "--transaction", transaction_id, "--input", "-"],
        ["check-review", "--transaction", transaction_id, "--input", "-"],
        [
            "record-application",
            "--transaction",
            transaction_id,
            "--input",
            "-",
        ],
        ["check-memories", "--transaction", transaction_id, "--input", "-"],
        [
            "await-approval",
            "--transaction",
            transaction_id,
            "--revision",
            "rev_synthetic",
            "--digest",
            digest,
        ],
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "preserved",
        ],
    ]
    calls_before = tuple(runner.calls)

    for command in non_migration_commands:
        exit_code = main(
            ["--state-root", str(state_root), *command],
            dependencies=dependencies,
        )
        output = capsys.readouterr()
        assert exit_code == 4
        assert output.out == ""
        assert _payload(output.err) == {
            "schema": "staged-memory-intake.error.v1",
            "code": "layout_migration_pending",
            "state": None,
            "ordinal": None,
            "retryable": True,
        }
        assert tuple(runner.calls) == calls_before

    exit_code = main(
        ["--state-root", str(state_root), "migrate-layout"],
        dependencies=dependencies,
    )
    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    assert _payload(output.out) == {
        "schema": "staged-memory-intake.layout-migration.v1",
        "status": "recovered",
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["preview", "prepared", "--prepared", "PRIVATE-NAME.md"],
        ["authorize", "--digest", "a" * 64, "--prepared", "PRIVATE-NAME.md"],
        ["publish", "--transaction", "tx_" + "a" * 32],
        ["begin-scan", "--transaction", "tx_" + "a" * 32],
        ["record-scan", "--transaction", "tx_" + "a" * 32, "--input", "-"],
        ["check-batch", "--transaction", "tx_" + "a" * 32, "--input", "-"],
        ["preview", "review", "--transaction", "tx_" + "a" * 32],
        ["check-review", "--transaction", "tx_" + "a" * 32, "--input", "-"],
        [
            "await-approval",
            "--transaction",
            "tx_" + "a" * 32,
            "--revision",
            "rev_private",
            "--digest",
            "b" * 64,
        ],
        [
            "record-application",
            "--transaction",
            "tx_" + "a" * 32,
            "--input",
            "-",
        ],
        ["check-memories", "--transaction", "tx_" + "a" * 32, "--input", "-"],
        ["cleanup", "--transaction", "tx_" + "a" * 32],
        [
            "reconcile-cleanup",
            "--transaction",
            "tx_" + "a" * 32,
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    ],
)
def test_unconfigured_commands_fail_without_creating_state_or_running_memory(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    state_root = tmp_path / "PRIVATE-STATE-MARKER"

    result = main(
        ["--state-root", str(state_root), *arguments],
        dependencies=dependencies,
    )

    assert result == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        '{"code":"not_configured","ordinal":null,"retryable":false,'
        '"schema":"staged-memory-intake.error.v1","state":null}\n'
    )
    assert not state_root.exists()
    runner = cast(FakeMemoryPathsRunner, dependencies.memory_paths_runner)
    assert runner.calls == []


@pytest.mark.parametrize(
    "arguments",
    [
        ["stat"],
        ["status", "--trans", "PRIVATE-ARGV-MARKER"],
        ["preview", "prepa", "--prepared", "PRIVATE-ARGV-MARKER"],
    ],
)
def test_command_grammar_has_no_aliases_or_abbreviations_and_hides_values(
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    result = main(arguments, dependencies=dependencies)

    assert result == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "PRIVATE-ARGV-MARKER" not in output.err
    assert output.err == (
        '{"code":"invalid_arguments","ordinal":null,"retryable":false,'
        '"schema":"staged-memory-intake.error.v1","state":null}\n'
    )


def test_begin_scan_command_is_part_of_the_exact_grammar(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_root = tmp_path / "synthetic-state"
    result = main(
        [
            "--state-root",
            str(state_root),
            "begin-scan",
            "--transaction",
            "tx_" + "a" * 32,
        ],
        dependencies=dependencies,
    )

    assert result == 2
    assert '"code":"not_configured"' in capsys.readouterr().err
    assert not state_root.exists()
    runner = cast(FakeMemoryPathsRunner, dependencies.memory_paths_runner)
    assert runner.calls == []


def test_begin_scan_marker_is_durable_and_idempotent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    published = TransactionStore(environment.state_root).load(transaction_id)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["publish", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "published"
    assert TransactionStore(environment.state_root).load(transaction_id) == published

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["scan_started"] is True
    first = TransactionStore(environment.state_root).load(transaction_id)
    assert first.scan_started is True

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["scan_started"] is True
    assert TransactionStore(environment.state_root).load(transaction_id) == first


@pytest.mark.parametrize(
    "arguments",
    [
        ["begin-scan", "--transaction", "TRANSACTION"],
        [
            "record-scan",
            "--transaction",
            "TRANSACTION",
            "--input",
            "INPUT",
        ],
        [
            "check-batch",
            "--transaction",
            "TRANSACTION",
            "--input",
            "INPUT",
        ],
        ["preview", "review", "--transaction", "TRANSACTION"],
        [
            "check-review",
            "--transaction",
            "TRANSACTION",
            "--input",
            "INPUT",
        ],
        [
            "await-approval",
            "--transaction",
            "TRANSACTION",
            "--revision",
            "rev_synthetic_wrong_state",
            "--digest",
            "d" * 64,
        ],
        [
            "record-application",
            "--transaction",
            "TRANSACTION",
            "--input",
            "INPUT",
        ],
        [
            "check-memories",
            "--transaction",
            "TRANSACTION",
            "--input",
            "INPUT",
        ],
        ["cleanup", "--transaction", "TRANSACTION"],
        [
            "reconcile-cleanup",
            "--transaction",
            "TRANSACTION",
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    ],
)
def test_stateful_commands_reject_the_exact_active_receipt_in_a_wrong_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    input_path = _write_input(environment, _success({}))
    command = [
        transaction_id
        if value == "TRANSACTION"
        else str(input_path)
        if value == "INPUT"
        else value
        for value in arguments
    ]

    code, stdout, stderr = _invoke(environment, capsys, command)

    assert code == 4
    assert stdout == ""
    error = _payload(stderr)
    assert error["state"] == "owner_authorized"
    assert TransactionStore(environment.state_root).load(transaction_id).state is (
        TransactionState.OWNER_AUTHORIZED
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["begin-scan", "--transaction", "TRANSACTION"],
        ["cleanup", "--transaction", "TRANSACTION"],
        [
            "reconcile-cleanup",
            "--transaction",
            "TRANSACTION",
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    ],
)
def test_stateful_command_rejects_a_stale_transaction_id_before_receipt_access(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    stale_id = "tx_" + "f" * 32
    assert stale_id != transaction_id

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [stale_id if value == "TRANSACTION" else value for value in arguments],
    )

    assert code == 4
    assert stdout == ""
    assert _payload(stderr) == {
        "schema": "staged-memory-intake.error.v1",
        "code": "inactive_transaction",
        "state": None,
        "ordinal": None,
        "retryable": False,
    }
    assert TransactionStore(environment.state_root).active() is not None
    assert TransactionStore(environment.state_root).load(transaction_id).state is (
        TransactionState.OWNER_AUTHORIZED
    )


@pytest.mark.parametrize(
    "command",
    [
        "record-scan",
        "check-batch",
        "check-review",
        "record-application",
        "check-memories",
    ],
)
@pytest.mark.parametrize("transaction", ["stale", "wrong_state"])
def test_input_commands_check_active_state_before_opening_private_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    transaction: str,
) -> None:
    environment = _environment(tmp_path)
    active_id, _ = _authorize(environment, capsys)
    transaction_id = "tx_" + "f" * 32 if transaction == "stale" else active_id
    missing = environment.root / f"{PRIVATE_PATH}-must-not-open"

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            command,
            "--transaction",
            transaction_id,
            "--input",
            str(missing),
        ],
    )

    assert code == 4
    assert stdout == ""
    error = _payload(stderr)
    if transaction == "stale":
        assert error["code"] == "inactive_transaction"
        assert error["state"] is None
    else:
        assert error["code"] == "invalid_snapshot_state"
        assert error["state"] == "owner_authorized"
    assert not missing.exists()
    assert TransactionStore(environment.state_root).load(active_id).state is (
        TransactionState.OWNER_AUTHORIZED
    )


def test_configure_and_distinct_authorize_reject_an_active_transaction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    assert len(environment.paths_runner.calls) == 1

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
        ],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "transaction_active"
    assert len(environment.paths_runner.calls) == 1

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["preview", "prepared", "--prepared", PRIVATE_NAME],
    )
    assert code == 0
    assert stderr == ""
    preview = _payload(stdout)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            cast(str, preview["manifest_digest"]),
            "--prepared",
            PRIVATE_NAME,
        ],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "transaction_active"
    assert TransactionStore(environment.state_root).load(transaction_id).state is (
        TransactionState.OWNER_AUTHORIZED
    )


def test_exact_fresh_supersede_can_publish_under_retained_transaction_id(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    old = TransactionStore(environment.state_root).load(transaction_id)
    new_source = b"Fresh synthetic CLI supersede source."
    (environment.notes / "02_Staged" / "private-alpha-source.md").write_bytes(
        new_source
    )
    (environment.notes / "03_Prepared" / PRIVATE_NAME).write_bytes(
        _prepared(
            "private-alpha-source.md",
            new_source,
            "Fresh synthetic CLI supersede statement.",
            kind="fact",
            sensitivity="normal",
            tags='["synthetic","supersede"]',
        )
    )
    selected = [PRIVATE_NAME, "private-beta-prepared.md"]
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "preview",
            "prepared",
            "--prepared",
            selected[0],
            "--prepared",
            selected[1],
        ],
    )
    assert code == 0
    assert stderr == ""
    preview = _payload(stdout)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            cast(str, preview["manifest_digest"]),
            "--prepared",
            selected[0],
            "--prepared",
            selected[1],
            "--supersede-transaction",
            transaction_id,
            "--supersede-digest",
            old.manifest_digest,
        ],
    )
    assert code == 0
    assert stderr == ""
    status = _payload(stdout)
    assert status["transaction_id"] == transaction_id
    assert status["manifest_digest"] == preview["manifest_digest"]

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["publish", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "published"
    assert all(
        name.startswith(f"{transaction_id}-") for name in os.listdir(environment.inbox)
    )


@pytest.mark.parametrize(
    "partial",
    [
        ["--supersede-transaction", "tx_" + "0" * 32],
        ["--supersede-digest", "0" * 64],
    ],
)
def test_partial_supersede_arguments_are_rejected_without_receipt_change(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    partial: list[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    receipt_path = environment.state_root / f"{transaction_id}.json"
    before = receipt_path.read_bytes()

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            "0" * 64,
            "--prepared",
            PRIVATE_NAME,
            *partial,
        ],
    )

    assert code == 2
    assert stdout == ""
    assert _payload(stderr)["code"] == "invalid_arguments"
    assert receipt_path.read_bytes() == before


def test_preview_rejects_243_byte_prepared_name_before_authorization(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    _configure(environment, capsys)
    prepared_name = f"{'x' * 240}.md"
    source_name = "long-name-source.md"
    source = b"Synthetic long-name preview source."
    (environment.notes / "02_Staged" / source_name).write_bytes(source)
    (environment.notes / "03_Prepared" / prepared_name).write_bytes(
        _prepared(
            source_name,
            source,
            "Synthetic long-name preview statement.",
            kind="fact",
            sensitivity="normal",
            tags='["synthetic","long-name"]',
        )
    )

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["preview", "prepared", "--prepared", prepared_name],
    )

    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "published_name_too_long"
    assert TransactionStore(environment.state_root).active() is None
    assert tuple(environment.inbox.iterdir()) == ()


def test_distinct_active_authorization_rejects_before_private_content_read(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    active = TransactionStore(environment.state_root).load(transaction_id)
    distinct_digest = "0" * 64
    if distinct_digest == active.manifest_digest:
        distinct_digest = "1" * 64
    reads: list[tuple[Path, str]] = []

    def reject_content_read(root: Path, name: str, *, limit: int) -> bytes:
        del limit
        reads.append((root, name))
        raise AssertionError(PRIVATE_ERROR)

    monkeypatch.setattr(prepared_module, "read_regular", reject_content_read)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            distinct_digest,
            "--prepared",
            PRIVATE_NAME,
        ],
    )

    assert code == 4
    assert stdout == ""
    assert _payload(stderr) == {
        "schema": "staged-memory-intake.error.v1",
        "code": "transaction_active",
        "state": "owner_authorized",
        "ordinal": None,
        "retryable": False,
    }
    assert reads == []
    assert TransactionStore(environment.state_root).load(transaction_id) == active


def test_exact_active_authorization_replay_and_invalid_digest_read_no_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)
    active = TransactionStore(environment.state_root).load(transaction_id)
    reads: list[tuple[Path, str]] = []

    def reject_content_read(root: Path, name: str, *, limit: int) -> bytes:
        del limit
        reads.append((root, name))
        raise AssertionError(PRIVATE_ERROR)

    monkeypatch.setattr(prepared_module, "read_regular", reject_content_read)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            PRIVATE_ERROR,
            "--prepared",
            PRIVATE_NAME,
        ],
    )
    assert code == 2
    assert stdout == ""
    assert _payload(stderr)["code"] == "invalid_arguments"
    assert reads == []

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            active.manifest_digest,
            "--prepared",
            PRIVATE_NAME,
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["transaction_id"] == transaction_id
    assert reads == []
    assert TransactionStore(environment.state_root).load(transaction_id) == active


def test_no_active_authorization_reads_and_persists_under_one_lock(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _configure(environment, capsys)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["preview", "prepared", "--prepared", PRIVATE_NAME],
    )
    assert code == 0
    assert stderr == ""
    digest = cast(str, _payload(stdout)["manifest_digest"])
    real_read = secure_read_regular
    real_authorize = TransactionStore.authorize
    read_roots: list[str] = []
    lock_observations: list[str] = []

    def competing_lock_result() -> str:
        try:
            with TransactionStore(environment.state_root).lock():
                return "acquired"
        except IntakeError as error:
            return error.code

    def checked_read(root: Path, name: str, *, limit: int) -> bytes:
        read_roots.append(root.name)
        lock_observations.append(f"read:{competing_lock_result()}")
        return real_read(root, name, limit=limit)

    def checked_authorize(
        self: TransactionStore,
        preview: PromotionPreview,
        approved_digest: str,
    ) -> TransactionReceipt:
        lock_observations.append(f"authorize:{competing_lock_result()}")
        return real_authorize(self, preview, approved_digest)

    monkeypatch.setattr(prepared_module, "read_regular", checked_read)
    monkeypatch.setattr(TransactionStore, "authorize", checked_authorize)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            digest,
            "--prepared",
            PRIVATE_NAME,
        ],
    )

    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "owner_authorized"
    assert {"03_Prepared", "02_Staged"} <= set(read_roots)
    assert lock_observations
    assert set(lock_observations) == {
        "read:transaction_busy",
        "authorize:transaction_busy",
    }


def test_excessively_long_cleanup_ordinal_is_invalid_arguments(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize(environment, capsys)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "9" * 5_000,
            "--outcome",
            "moved",
        ],
    )

    assert code == 2
    assert stdout == ""
    assert _payload(stderr)["code"] == "invalid_arguments"


def _success(
    data: object,
    *,
    page: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": "memory.mcp.v1",
        "instruction_trust": "inert",
        "data": data,
    }
    if page is not None:
        result["page"] = page
    return result


def _capture_exact_batch(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
    transaction_id: str,
) -> TransactionReceipt:
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["scan_started"] is True
    store = TransactionStore(environment.state_root)
    marked = store.load(transaction_id)
    assert marked.state is TransactionState.PUBLISHED
    assert marked.scan_started is True

    source_ids = ["src_synthetic_alpha", "src_synthetic_beta"]
    batch: dict[str, object] = {
        "batch_id": "bat_synthetic_exact",
        "sealed_at": 1_776_000_000,
        "source_count": 2,
        "source_ids": source_ids,
        "batch_has_more": False,
        "issues": [],
        "duplicates": [],
        "review_state": "none",
    }
    scan_path = _write_input(
        environment,
        _success(batch, page={"has_more": False}),
    )
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            str(scan_path),
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["batch_id"] == "bat_synthetic_exact"

    recorded = store.load(transaction_id)
    summaries: list[dict[str, object]] = []
    for source_id, published in zip(
        source_ids,
        recorded.published_files,
        strict=True,
    ):
        summaries.append(
            {
                "source_id": source_id,
                "origin": "inbox",
                "blob_digest": published.sha256,
                "original_name": published.inbox_name,
                "media_type": "text/markdown",
                "byte_length": published.byte_length,
                "authorship": "mixed",
                "declared_sensitivity": recorded.batch_sensitivity,
                "effective_sensitivity": recorded.batch_sensitivity,
                "searchable": True,
                "captured_at": 1_776_000_000,
            }
        )
    detail_path = _write_input(
        environment,
        _success({"batch": batch, "sources": summaries}),
    )
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "check-batch",
            "--transaction",
            transaction_id,
            "--input",
            str(detail_path),
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "captured"
    return store.load(transaction_id)


def _review_and_verify(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
    transaction_id: str,
) -> TransactionReceipt:
    captured = _capture_exact_batch(environment, capsys, transaction_id)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["preview", "review", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    plan = _payload(stdout)
    assert plan["schema"] == "staged-memory-intake.review-plan.v1"
    assert PRIVATE_BODY in stdout
    assert PRIVATE_EVIDENCE in stdout
    assert PRIVATE_TAG in stdout
    edits = cast(list[dict[str, object]], plan["edits"])
    assert len(edits) == 2

    items: list[dict[str, object]] = []
    decisions: list[dict[str, object]] = []
    parsed_values = []
    for candidate in captured.candidates:
        parsed = parse_prepared(
            candidate.prepared_name,
            (environment.notes / "03_Prepared" / candidate.prepared_name).read_bytes(),
            (environment.notes / "02_Staged" / candidate.source_name).read_bytes(),
        )
        parsed_values.append(parsed)
        binding = captured.source_bindings[candidate.ordinal]
        edit = edits[candidate.ordinal]
        items.append(
            {
                "ordinal": candidate.ordinal,
                "item_id": candidate.client_item_id,
                "status": "active",
                "memory": edit["memory"],
                "evidence": [
                    {
                        "ordinal": 0,
                        "source_id": binding.source_id,
                        "blob_digest": binding.blob_digest,
                        "mode": "text",
                        "char_start": parsed.evidence_char_start,
                        "char_end": parsed.evidence_char_end,
                        "excerpt": parsed.evidence_excerpt,
                    }
                ],
            }
        )
        decisions.append(
            {
                "ordinal": candidate.ordinal,
                "source_id": binding.source_id,
                "blob_digest": binding.blob_digest,
                "state": "used",
                "reason": None,
            }
        )
    review_digest = "c" * 64
    review = _success(
        {
            "change_set_id": "chg_synthetic_exact",
            "batch_id": captured.batch_id,
            "state": "draft",
            "revision_id": "rev_synthetic_exact",
            "digest": review_digest,
            "adapter_origin": "mcp",
            "items": items,
            "source_decisions": decisions,
            "guard_links": [],
            "revoked_guard_links": [],
        }
    )
    review_path = _write_input(environment, review)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "check-review",
            "--transaction",
            transaction_id,
            "--input",
            str(review_path),
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "review_ready"
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "await-approval",
            "--transaction",
            transaction_id,
            "--revision",
            "rev_synthetic_exact",
            "--digest",
            review_digest,
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "awaiting_memory_approval"

    application = _success(
        {
            "application_id": "app_synthetic_exact",
            "change_set_id": "chg_synthetic_exact",
            "revision_id": "rev_synthetic_exact",
            "memory_ids": ["mem_synthetic_alpha", "mem_synthetic_beta"],
            "idempotent_replay": False,
            "standing_guard_violations": [],
        }
    )
    application_path = _write_input(environment, application)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-application",
            "--transaction",
            transaction_id,
            "--input",
            str(application_path),
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["memory_ids"] == [
        "mem_synthetic_alpha",
        "mem_synthetic_beta",
    ]

    applied = TransactionStore(environment.state_root).load(transaction_id)
    details: list[dict[str, object]] = []
    for candidate, parsed, binding, memory_id in zip(
        applied.candidates,
        parsed_values,
        applied.source_bindings,
        applied.memory_ids,
        strict=True,
    ):
        summary: dict[str, object] = {
            "memory_id": memory_id,
            "lineage_id": f"lin_synthetic_{candidate.ordinal}",
            "kind": candidate.metadata.kind,
            "statement": parsed.statement,
            "tags": list(candidate.metadata.tags),
            "stored_sensitivity": applied.batch_sensitivity,
            "effective_sensitivity": applied.batch_sensitivity,
            "recorded_at": 1_776_000_100 + candidate.ordinal,
        }
        details.append(
            {
                "revision": summary,
                "is_current": True,
                "current_head_id": memory_id,
                "revision_ids": [memory_id],
                "evidence": [
                    {
                        "ordinal": 0,
                        "source_id": binding.source_id,
                        "blob_digest": binding.blob_digest,
                        "mode": "text",
                        "char_start": parsed.evidence_char_start,
                        "char_end": parsed.evidence_char_end,
                        "excerpt": parsed.evidence_excerpt,
                    }
                ],
                "guards": [],
                "governs": [],
            }
        )
    memories_path = _write_input(environment, _success(details))
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "check-memories",
            "--transaction",
            transaction_id,
            "--input",
            str(memories_path),
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "verified"
    return TransactionStore(environment.state_root).load(transaction_id)


def test_publish_rejects_an_active_transaction_after_capture(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    captured = _capture_exact_batch(environment, capsys, transaction_id)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["publish", "--transaction", transaction_id],
    )

    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "publication_not_authorized"
    assert TransactionStore(environment.state_root).load(transaction_id) == captured


def test_fake_end_to_end_persists_one_scan_review_application_and_cleanup(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, candidates = _authorize_and_publish(environment, capsys)
    assert len(candidates) == 2

    verified = _review_and_verify(environment, capsys, transaction_id)
    assert verified.batch_id == "bat_synthetic_exact"
    assert verified.change_set_id == "chg_synthetic_exact"
    assert verified.revision_id == "rev_synthetic_exact"
    assert verified.application_id == "app_synthetic_exact"
    assert len({candidate.client_item_id for candidate in verified.candidates}) == 2

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    assert len(environment.trash.moves) == 4
    assert [path.parent.name for path in environment.trash.moves] == [
        "03_Prepared",
        "03_Prepared",
        "02_Staged",
        "02_Staged",
    ]
    assert len(set(environment.trash.moves[:2])) == 2
    assert len(set(environment.trash.moves[2:])) == 2
    assert environment.process_runner.calls == 0
    assert len(environment.paths_runner.calls) == 2
    assert TransactionStore(environment.state_root).load(transaction_id).state is (
        TransactionState.COMPLETE
    )
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["status", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    completed = TransactionStore(environment.state_root).load(transaction_id)
    prior_moves = tuple(environment.trash.moves)
    prior_path_calls = tuple(environment.paths_runner.calls)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    assert TransactionStore(environment.state_root).load(transaction_id) == completed
    assert tuple(environment.trash.moves) == prior_moves
    assert tuple(environment.paths_runner.calls) == prior_path_calls
    assert environment.process_runner.calls == 0
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    assert TransactionStore(environment.state_root).load(transaction_id) == completed
    assert tuple(environment.trash.moves) == prior_moves
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "preserved",
        ],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "cleanup_reconciliation_conflict"
    assert tuple(environment.trash.moves) == prior_moves
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "inactive_transaction"


def test_inactive_complete_cleanup_replays_after_disposable_notes_relocation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    _review_and_verify(environment, capsys, transaction_id)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    completed = TransactionStore(environment.state_root).load(transaction_id)
    relocated = tmp_path / "synthetic-relocated-notes"
    environment.notes.rename(relocated)
    before = (
        tuple(environment.paths_runner.calls),
        environment.process_runner.calls,
        tuple(environment.trash.attempts),
        tuple(environment.trash.moves),
        tuple(environment.trash.descriptors),
        tuple(environment.trash.reference_descriptors),
    )

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    assert TransactionStore(environment.state_root).load(transaction_id) == completed

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"
    assert (
        tuple(environment.paths_runner.calls),
        environment.process_runner.calls,
        tuple(environment.trash.attempts),
        tuple(environment.trash.moves),
        tuple(environment.trash.descriptors),
        tuple(environment.trash.reference_descriptors),
    ) == before

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "preserved",
        ],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "cleanup_reconciliation_conflict"


@pytest.mark.parametrize("size", [4_320_233, 8 * 1024 * 1024])
def test_large_valid_application_warnings_remain_readable_and_complete(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    size: int,
) -> None:
    case_root = tmp_path / f"synthetic-large-{size}"
    case_root.mkdir(mode=0o700)
    environment = _environment(case_root)
    awaiting = _awaiting_application_receipt(environment, capsys)
    raw = _application_bytes_of_size(size)
    input_path = case_root / "synthetic-large-application.json"
    input_path.write_bytes(raw)
    input_path.chmod(0o600)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-application",
            "--transaction",
            awaiting.transaction_id,
            "--input",
            str(input_path),
        ],
    )

    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "applied"
    store = TransactionStore(environment.state_root)
    applied = store.load(awaiting.transaction_id)
    assert len(applied.standing_guard_violations) == 1
    assert applied.standing_guard_violations[0].guard_lineage_id.startswith(
        "lin_guard_"
    )
    verified = store.advance(applied, TransactionState.VERIFIED)
    assert store.load(awaiting.transaction_id) == verified


def test_one_byte_over_public_snapshot_limit_refuses_before_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    awaiting = _awaiting_application_receipt(environment, capsys)
    receipt_path = environment.state_root / f"{awaiting.transaction_id}.json"
    before = receipt_path.read_bytes()
    input_path = tmp_path / "synthetic-over-limit-application.json"
    input_path.write_bytes(_application_bytes_of_size((8 * 1024 * 1024) + 1))
    input_path.chmod(0o600)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-application",
            "--transaction",
            awaiting.transaction_id,
            "--input",
            str(input_path),
        ],
    )

    assert code == 5
    assert stdout == ""
    assert _payload(stderr)["code"] == "input_too_large"
    assert receipt_path.read_bytes() == before
    assert (
        TransactionStore(environment.state_root).load(awaiting.transaction_id)
        == awaiting
    )
    assert (
        tuple(environment.state_root.glob("*.standing-guard-violations-*.jsonl")) == ()
    )


def test_cleanup_interruption_requires_exact_owner_reconciliation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    _review_and_verify(environment, capsys, transaction_id)
    interrupted = False

    def interrupt_after_first_move(name: str, ordinal: int) -> None:
        nonlocal interrupted
        if name == "after_move" and ordinal == 0 and not interrupted:
            interrupted = True
            raise RuntimeError(PRIVATE_ERROR)

    monkeypatch.setattr(cleanup_module, "_checkpoint", interrupt_after_first_move)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "internal_error"
    assert PRIVATE_ERROR not in stderr
    pending = TransactionStore(environment.state_root).load(transaction_id)
    assert pending.state is TransactionState.CLEANUP_PENDING
    assert pending.cleanup_entries[0].intent_recorded is True
    assert pending.cleanup_entries[0].failure is None
    assert pending.cleanup_entries[0].outcome is None

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    )
    assert code == 4
    assert stdout == ""
    assert _payload(stderr)["code"] == "cleanup_reconciliation_not_required"

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 6
    assert stdout == ""
    error = _payload(stderr)
    assert error["code"] == "cleanup_ambiguous"
    assert error["ordinal"] == 0

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "reconcile-cleanup",
            "--transaction",
            transaction_id,
            "--ordinal",
            "0",
            "--outcome",
            "moved",
        ],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["cleanup_resolved_count"] == 1
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["cleanup", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["status"] == "complete"


@dataclass
class ExplodingRunner:
    calls: int = 0

    def run(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        del argv, timeout_seconds
        self.calls += 1
        raise RuntimeError(PRIVATE_ERROR)


@dataclass
class TimingOutRunner:
    calls: int = 0

    def run(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        del argv
        self.calls += 1
        raise subprocess.TimeoutExpired(
            PRIVATE_PATH,
            timeout_seconds,
            stderr=PRIVATE_ERROR.encode(),
        )


@dataclass(frozen=True)
class FailingOutput:
    kind: str

    def write(self, value: str) -> int:
        if self.kind == "unicode":
            raise UnicodeEncodeError("ascii", value, 0, 1, PRIVATE_ERROR)
        raise OSError(PRIVATE_ERROR)


@dataclass
class ObservedOutput:
    write_failure: str | None = None
    flush_failure: str | None = None
    short_by: int = 0
    writes: list[str] = field(default_factory=list)
    flushes: int = 0

    @staticmethod
    def _raise(kind: str, value: str) -> None:
        if kind == "unicode":
            raise UnicodeEncodeError("ascii", value, 0, 1, PRIVATE_ERROR)
        raise OSError(PRIVATE_ERROR)

    def write(self, value: str) -> int:
        self.writes.append(value)
        if self.write_failure is not None:
            self._raise(self.write_failure, value)
        return len(value) - self.short_by

    def flush(self) -> None:
        self.flushes += 1
        if self.flush_failure is not None:
            self._raise(self.flush_failure, PRIVATE_ERROR)


@pytest.mark.parametrize(
    ("kind", "expected_exit", "expected_code"),
    [
        ("unicode", 5, "invalid_input"),
        ("os", 3, "filesystem_error"),
    ],
)
def test_success_output_failure_is_mapped_without_a_traceback(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    expected_exit: int,
    expected_code: str,
) -> None:
    state_root = tmp_path / PRIVATE_PATH
    monkeypatch.setattr(sys, "stdout", FailingOutput(kind))

    result = main(
        ["--state-root", str(state_root), "status"],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    output = capsys.readouterr()
    assert result == expected_exit
    assert output.out == ""
    assert _payload(output.err) == {
        "schema": "staged-memory-intake.error.v1",
        "code": expected_code,
        "state": None,
        "ordinal": None,
        "retryable": False,
    }
    assert PRIVATE_PATH not in output.err
    assert PRIVATE_ERROR not in output.err
    assert "Traceback" not in output.err
    assert not state_root.exists()


@pytest.mark.parametrize("kind", ["os", "unicode"])
def test_failing_error_stream_never_escapes_an_already_failing_command(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    stream = ObservedOutput(write_failure=kind)
    monkeypatch.setattr(sys, "stderr", stream)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), PRIVATE_ERROR],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    assert result == 2
    assert capsys.readouterr() == ("", "")
    assert len(stream.writes) == 1
    assert _payload(stream.writes[0])["code"] == "invalid_arguments"
    assert PRIVATE_ERROR not in stream.writes[0]
    assert PRIVATE_PATH not in stream.writes[0]
    assert "Traceback" not in stream.writes[0]


def test_short_success_write_maps_to_a_canonical_error(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = ObservedOutput(short_by=1)
    monkeypatch.setattr(sys, "stdout", stream)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), "status"],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    output = capsys.readouterr()
    assert result == 3
    assert output.out == ""
    assert _payload(output.err)["code"] == "filesystem_error"
    assert len(stream.writes) == 1
    assert stream.flushes == 0
    for marker in PRIVATE_MARKERS:
        assert marker not in output.err
    assert "Traceback" not in output.err


def test_short_error_write_fails_silently_without_flushing_or_changing_exit(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = ObservedOutput(short_by=1)
    monkeypatch.setattr(sys, "stderr", stream)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), PRIVATE_ERROR],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    assert result == 2
    assert capsys.readouterr() == ("", "")
    assert len(stream.writes) == 1
    assert stream.flushes == 0
    assert PRIVATE_ERROR not in stream.writes[0]
    assert PRIVATE_PATH not in stream.writes[0]
    assert "Traceback" not in stream.writes[0]


def test_stdout_flush_failure_maps_to_a_canonical_error(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = ObservedOutput(flush_failure="os")
    monkeypatch.setattr(sys, "stdout", stream)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), "status"],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    output = capsys.readouterr()
    assert result == 3
    assert output.out == ""
    assert _payload(output.err)["code"] == "filesystem_error"
    assert stream.flushes == 1
    assert PRIVATE_ERROR not in output.err
    assert PRIVATE_PATH not in output.err
    assert "Traceback" not in output.err


def test_stderr_flush_failure_fails_silently_with_the_original_exit(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = ObservedOutput(flush_failure="unicode")
    monkeypatch.setattr(sys, "stderr", stream)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), PRIVATE_ERROR],
        dependencies=dependencies,
    )

    monkeypatch.undo()
    assert result == 2
    assert capsys.readouterr() == ("", "")
    assert stream.flushes == 1
    assert len(stream.writes) == 1
    assert PRIVATE_ERROR not in stream.writes[0]
    assert PRIVATE_PATH not in stream.writes[0]
    assert "Traceback" not in stream.writes[0]


def test_stdout_then_stderr_failure_is_silent_even_in_debug_mode(
    tmp_path: Path,
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = ObservedOutput(write_failure="os")
    stderr = ObservedOutput(write_failure="unicode")
    debug_dependencies = Dependencies(
        memory_paths_runner=dependencies.memory_paths_runner,
        process_runner=dependencies.process_runner,
        trash=dependencies.trash,
        publication_fault=dependencies.publication_fault,
        debug_exceptions=True,
    )
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    result = main(
        ["--state-root", str(tmp_path / PRIVATE_PATH), "status"],
        dependencies=debug_dependencies,
    )

    monkeypatch.undo()
    assert result == 3
    assert capsys.readouterr() == ("", "")
    assert len(stdout.writes) == 1
    assert len(stderr.writes) == 1
    assert _payload(stderr.writes[0])["code"] == "filesystem_error"
    for record in (*stdout.writes, *stderr.writes):
        for marker in PRIVATE_MARKERS:
            assert marker not in record
        assert "Traceback" not in record


def test_memory_paths_timeout_is_a_content_free_memory_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    timing_out = TimingOutRunner()
    dependencies = Dependencies(
        memory_paths_runner=cast(CommandRunner, timing_out),
        process_runner=environment.process_runner,
        trash=environment.trash,
        publication_fault=NoPublicationFault(),
    )

    result = main(
        [
            "--state-root",
            str(environment.state_root),
            "configure",
            "--notes-root",
            str(environment.notes),
        ],
        dependencies=dependencies,
    )

    output = capsys.readouterr()
    assert result == 5
    assert output.out == ""
    assert _payload(output.err) == {
        "schema": "staged-memory-intake.error.v1",
        "code": "memory_paths_failed",
        "state": None,
        "ordinal": None,
        "retryable": True,
    }
    assert PRIVATE_PATH not in output.err
    assert PRIVATE_ERROR not in output.err
    assert timing_out.calls == 1


def test_unexpected_exception_is_content_free_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    exploding = ExplodingRunner()
    dependencies = Dependencies(
        memory_paths_runner=cast(CommandRunner, exploding),
        process_runner=environment.process_runner,
        trash=environment.trash,
        publication_fault=NoPublicationFault(),
    )
    result = main(
        [
            "--state-root",
            str(environment.state_root),
            "configure",
            "--notes-root",
            str(environment.notes),
        ],
        dependencies=dependencies,
    )
    output = capsys.readouterr()
    assert result == 4
    assert output.out == ""
    assert _payload(output.err)["code"] == "internal_error"
    assert PRIVATE_ERROR not in output.err
    assert "Traceback" not in output.err


def test_explicit_test_debug_dependency_reraises_programming_errors(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    exploding = ExplodingRunner()
    dependencies = Dependencies(
        memory_paths_runner=cast(CommandRunner, exploding),
        process_runner=environment.process_runner,
        trash=environment.trash,
        publication_fault=NoPublicationFault(),
        debug_exceptions=True,
    )

    with pytest.raises(RuntimeError, match=PRIVATE_ERROR):
        main(
            [
                "--state-root",
                str(environment.state_root),
                "configure",
                "--notes-root",
                str(environment.notes),
            ],
            dependencies=dependencies,
        )


def test_prepared_preview_emits_only_a_content_free_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    configured = _configure(environment, capsys)
    configured_line = json.dumps(configured, ensure_ascii=False)
    for marker in PRIVATE_MARKERS:
        assert marker not in configured_line

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["preview", "prepared", "--prepared", PRIVATE_NAME],
    )
    assert code == 0
    assert stderr == ""
    assert PRIVATE_NAME in stdout
    assert PRIVATE_BODY not in stdout
    assert PRIVATE_EVIDENCE not in stdout
    assert PRIVATE_TAG not in stdout
    preview = _payload(stdout)
    assert preview["candidate_count"] == 1
    assert preview["guard_link_count"] == 0
    candidates = cast(list[dict[str, object]], preview["candidates"])
    assert set(candidates[0]) == {
        "ordinal",
        "prepared_name",
        "source_name",
        "prepared_sha256",
        "source_sha256",
        "requested_sensitivity",
        "verbatim_statement",
    }
    assert candidates[0]["verbatim_statement"] is False

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "authorize",
            "--digest",
            cast(str, preview["manifest_digest"]),
            "--prepared",
            PRIVATE_NAME,
        ],
    )
    assert code == 0
    assert stderr == ""
    for marker in PRIVATE_MARKERS:
        assert marker not in stdout


@pytest.mark.parametrize("mode", [0o644, 0o400, 0o660])
def test_input_file_requires_exact_private_mode_without_leaking_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: int,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    input_path = environment.root / f"{PRIVATE_PATH}-{mode:o}.json"
    input_path.write_text("{}", encoding="utf-8")
    input_path.chmod(mode)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            str(input_path),
        ],
    )
    assert code == 3
    assert stdout == ""
    assert _payload(stderr)["code"] == "unsafe_input_file"
    assert PRIVATE_PATH not in stderr


def test_input_rejects_symlink_directory_fifo_and_overflow_without_blocking(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    regular = environment.root / "synthetic-regular.json"
    regular.write_text("{}", encoding="utf-8")
    regular.chmod(0o600)
    symlink = environment.root / f"{PRIVATE_PATH}-symlink"
    symlink.symlink_to(regular)
    directory = environment.root / f"{PRIVATE_PATH}-directory"
    directory.mkdir(mode=0o700)
    fifo = environment.root / f"{PRIVATE_PATH}-fifo"
    os.mkfifo(fifo, mode=0o600)
    overflow = environment.root / f"{PRIVATE_PATH}-overflow"
    with overflow.open("wb") as stream:
        stream.truncate((8 * 1024 * 1024) + 1)
    overflow.chmod(0o600)
    for path in (symlink, directory, fifo):
        code, stdout, stderr = _invoke(
            environment,
            capsys,
            [
                "record-scan",
                "--transaction",
                transaction_id,
                "--input",
                str(path),
            ],
        )
        assert code == 3
        assert stdout == ""
        assert _payload(stderr)["code"] == "unsafe_input_file"
        assert PRIVATE_PATH not in stderr
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            str(overflow),
        ],
    )
    assert code == 5
    assert stdout == ""
    assert _payload(stderr)["code"] == "input_too_large"


class BinaryInput:
    def __init__(self, value: bytes) -> None:
        self.buffer = io.BytesIO(value)


def test_valid_memory_snapshot_is_consumed_from_binary_stdin(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    code, _, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    batch = {
        "batch_id": "bat_synthetic_stdin",
        "sealed_at": 1_776_000_000,
        "source_count": 2,
        "source_ids": ["src_synthetic_alpha", "src_synthetic_beta"],
        "batch_has_more": False,
        "issues": [],
        "duplicates": [],
        "review_state": "none",
    }
    raw = json.dumps(
        _success(batch, page={"has_more": False}),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    monkeypatch.setattr(sys, "stdin", BinaryInput(raw))

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        ["record-scan", "--transaction", transaction_id, "--input", "-"],
    )

    assert code == 0
    assert stderr == ""
    assert _payload(stdout)["batch_id"] == "bat_synthetic_stdin"


def test_stdin_is_bounded_and_never_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    monkeypatch.setattr(sys, "stdin", BinaryInput(b"x" * ((8 * 1024 * 1024) + 1)))
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            "-",
        ],
    )
    assert code == 5
    assert stdout == ""
    assert _payload(stderr)["code"] == "input_too_large"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"memory.mcp.v1","schema":"' + PRIVATE_ERROR.encode() + b'"}',
        b'{"schema":"memory.mcp.v1","instruction_trust":"inert",'
        b'"error":{"message":"' + PRIVATE_ERROR.encode() + b'"}}',
        b'{"schema":"memory.mcp.v1","instruction_trust":"inert","data":{}}'
        b" trailing-" + PRIVATE_ERROR.encode(),
    ],
)
def test_invalid_memory_input_never_echoes_body_error_or_parser_text(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    raw: bytes,
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    path = environment.root / f"{PRIVATE_PATH}-invalid.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            str(path),
        ],
    )
    assert code == 5
    assert stdout == ""
    assert _payload(stderr)["code"] == "invalid_memory_envelope"
    for marker in PRIVATE_MARKERS:
        assert marker not in stderr


def test_snapshot_parser_rejects_extra_envelope_keys_without_echoing_them(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment(tmp_path)
    transaction_id, _ = _authorize_and_publish(environment, capsys)
    code, _, stderr = _invoke(
        environment,
        capsys,
        ["begin-scan", "--transaction", transaction_id],
    )
    assert code == 0
    assert stderr == ""
    envelope = _success(
        {
            "batch_id": "bat_synthetic_extra",
            "sealed_at": 1_776_000_000,
            "source_count": 2,
            "source_ids": ["src_synthetic_alpha", "src_synthetic_beta"],
            "batch_has_more": False,
            "issues": [],
            "duplicates": [],
            "review_state": "none",
        },
        page={"has_more": False},
    )
    envelope[PRIVATE_ERROR] = PRIVATE_BODY
    path = _write_input(environment, envelope)

    code, stdout, stderr = _invoke(
        environment,
        capsys,
        [
            "record-scan",
            "--transaction",
            transaction_id,
            "--input",
            str(path),
        ],
    )

    assert code == 5
    assert stdout == ""
    assert _payload(stderr)["code"] == "invalid_scan_snapshot"
    assert PRIVATE_ERROR not in stderr
    assert PRIVATE_BODY not in stderr


def test_configure_and_status_report_pending_drop_default_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _environment(tmp_path)
    configured = _configure(environment, capsys)
    assert configured["pending_drop"] is False
    code, stdout, _ = _invoke(environment, capsys, ["status"])
    assert code == 0
    assert _payload(stdout) == {
        "schema": "staged-memory-intake.status.v1",
        "status": "configured",
        "pending_drop": False,
    }


def test_configure_pending_drop_on_off_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment = _environment(tmp_path)
    _configure(environment, capsys)
    code, stdout, _ = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
            "--pending-drop",
            "on",
        ],
    )
    assert code == 0
    assert _payload(stdout)["pending_drop"] is True
    configured = _configure(environment, capsys)
    assert configured["pending_drop"] is True
    code, stdout, _ = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
            "--pending-drop",
            "off",
        ],
    )
    assert code == 0
    assert _payload(stdout)["pending_drop"] is False


def _enable_pending_drop(
    environment: CliEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = _invoke(
        environment,
        capsys,
        [
            "configure",
            "--notes-root",
            str(environment.notes),
            "--memory-home",
            str(environment.home),
            "--pending-drop",
            "on",
        ],
    )
    assert code == 0
    # Rider (Task 2 review): pin that `status` reports the ENABLED state
    # once persisted, not merely echoing configure's own response.
    code, stdout, _ = _invoke(environment, capsys, ["status"])
    assert code == 0
    assert _payload(stdout) == {
        "schema": "staged-memory-intake.status.v1",
        "status": "configured",
        "pending_drop": True,
    }


def _drop(
    environment: CliEnvironment,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    payload: bytes,
) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "stdin", BinaryInput(payload))
    return _invoke(
        environment,
        capsys,
        ["pending-drop", "--name", name, "--input", "-"],
    )


def test_pending_drop_refuses_unconfigured(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 2
    assert _payload(stderr)["code"] == "not_configured"


def test_pending_drop_refuses_while_disabled(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _configure(environment, capsys)
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 2
    assert _payload(stderr)["code"] == "pending_drop_disabled"
    assert list((environment.notes / "01_Pending").iterdir()) == []


def test_pending_drop_creates_exactly_one_private_pending_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    body = "# Decision: synthetic\n\n## Question\nSynthetic 界?\n".encode()
    code, stdout, _ = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", body
    )
    assert code == 0
    assert _payload(stdout) == {
        "schema": "staged-memory-intake.status.v1",
        "status": "pending_note_created",
    }
    target = environment.notes / "01_Pending" / "synthetic-decision.md"
    assert target.read_bytes() == body
    metadata = target.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600


def test_pending_drop_collision_refuses_and_preserves_bytes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    original = b"owner bytes stay\n"
    (environment.notes / "01_Pending" / "synthetic-decision.md").write_bytes(original)
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"replacement\n"
    )
    assert code == 3
    assert _payload(stderr)["code"] == "pending_note_exists"
    assert (
        environment.notes / "01_Pending" / "synthetic-decision.md"
    ).read_bytes() == original


def test_pending_drop_never_follows_a_symlinked_pending_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A symlinked 01_Pending is refused before pending-drop's own code runs.

    `require_config` already binds every command to
    `_validate_notes_root`, whose pre-existing `role="pending"` check
    (predating this feature; see `f0d1d90`) refuses a non-directory pending
    child for any command. `create_pending_note`'s own O_NOFOLLOW guard on
    the pending directory remains real defense-in-depth for the narrower
    TOCTOU window between that check and the write, but this scenario -- the
    symlink already in place before the command runs -- never reaches it.
    """
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    pending = environment.notes / "01_Pending"
    elsewhere = tmp_path / "synthetic-elsewhere"
    elsewhere.mkdir(mode=0o700)
    pending.rmdir()
    pending.symlink_to(elsewhere)
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 2
    assert _payload(stderr)["code"] == "pending_not_directory"
    assert list(elsewhere.iterdir()) == []


def test_pending_drop_refuses_a_symlink_name_without_following_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    outside = environment.root / "synthetic-outside.md"
    outside.write_bytes(b"outside\n")
    (environment.notes / "01_Pending" / "synthetic-decision.md").symlink_to(outside)
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 3
    assert _payload(stderr)["code"] == "pending_note_exists"
    assert outside.read_bytes() == b"outside\n"


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        ".hidden.md",
        "nested/decision.md",
        "no-extension",
        ".md",
        "a" * 253 + ".md",
        "bad\0name.md",
    ],
)
def test_pending_drop_refuses_unsafe_names(
    bad_name: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    code, _, stderr = _drop(environment, capsys, monkeypatch, bad_name, b"# D\n")
    assert code == 2
    assert _payload(stderr)["code"] == "invalid_arguments"
    assert list((environment.notes / "01_Pending").iterdir()) == []


def test_pending_drop_refuses_empty_and_oversized_payloads(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    code, _, stderr = _drop(environment, capsys, monkeypatch, "synthetic-empty.md", b"")
    assert code == 2
    assert _payload(stderr)["code"] == "invalid_arguments"
    code, _, stderr = _drop(
        environment,
        capsys,
        monkeypatch,
        "synthetic-large.md",
        b"x" * ((256 * 1024) + 1),
    )
    assert code == 5
    assert _payload(stderr)["code"] == "input_too_large"
    assert list((environment.notes / "01_Pending").iterdir()) == []


def test_pending_drop_is_transaction_independent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    transaction_id, _ = _authorize(environment, capsys)
    code, stdout, _ = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 0
    assert _payload(stdout)["status"] == "pending_note_created"
    code, stdout, _ = _invoke(
        environment, capsys, ["status", "--transaction", transaction_id]
    )
    assert code == 0
    assert _payload(stdout)["status"] == "owner_authorized"


def test_pending_drop_respects_the_pending_maintenance_gates(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment(tmp_path)
    _enable_pending_drop(environment, capsys)
    monkeypatch.setattr(
        "staged_memory_intake.cli.relocation_pending", lambda _root: True
    )
    code, _, stderr = _drop(
        environment, capsys, monkeypatch, "synthetic-decision.md", b"# D\n"
    )
    assert code == 4
    assert _payload(stderr)["code"] == "relocation_pending"


def test_directory_entrypoint_help_uses_isolated_python_314_and_writes_no_bytecode(
    tmp_path: Path,
) -> None:
    del tmp_path
    package = (
        Path(__file__).resolve().parents[1]
        / "tools/staged-memory-intake/scripts/staged_memory_intake"
    )
    before = {
        path.relative_to(package)
        for path in package.rglob("*")
        if path.name == "__pycache__" or path.suffix == ".pyc"
    }
    result = subprocess.run(
        [
            "uv",
            "run",
            "--isolated",
            "--no-project",
            "--python",
            "3.14",
            "python",
            "-B",
            str(package),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    for command in (
        "configure",
        "preview",
        "authorize",
        "status",
        "publish",
        "begin-scan",
        "record-scan",
        "check-batch",
        "check-review",
        "await-approval",
        "record-application",
        "check-memories",
        "cleanup",
        "reconcile-cleanup",
    ):
        assert command in result.stdout
    after = {
        path.relative_to(package)
        for path in package.rglob("*")
        if path.name == "__pycache__" or path.suffix == ".pyc"
    }
    assert after == before
