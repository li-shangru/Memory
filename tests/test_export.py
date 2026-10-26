"""Complete plaintext export on freshly authored disposable Stores only."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from synthetic import (
    FakeClock,
    apply_ready,
    capture_text,
    ready_items,
    single_item_edit,
)
from test_owner_presence import SyntheticOwnerPresenceAdapter

from memory import export as export_module
from memory.database import writer_session
from memory.errors import InvalidArgumentError, OwnerApprovalRequiredError
from memory.model import RuntimePaths, Sensitivity


def destination(tmp_path: Path) -> Path:
    parent = tmp_path / "private-exports"
    parent.mkdir(mode=0o700)
    return parent / "all-memory.json"


def test_complete_plaintext_export_contains_all_sensitivities_and_source_bytes(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
) -> None:
    paths = synthetic_store
    for sensitivity in Sensitivity:
        body = f"Synthetic {sensitivity.value}: 蓝色灯笼。\n"
        batch, source = capture_text(
            paths,
            name=f"{sensitivity.value}.md",
            body=body,
            sensitivity=sensitivity,
            clock=FakeClock(),
        )
        ready = ready_items(
            paths,
            batch,
            [
                single_item_edit(
                    item_id="synthetic_item",
                    source=source,
                    statement=body.strip(),
                    excerpt=body.strip(),
                    sensitivity=sensitivity,
                )
            ],
        )
        apply_ready(paths, ready)
    (paths.inbox / "waiting.txt").write_text("uncaptured synthetic marker")
    with writer_session(paths) as connection:
        before = connection.execute(
            "SELECT audit_generation FROM store_meta"
        ).fetchone()[0]
    target = destination(tmp_path)
    verifier = SyntheticOwnerPresenceAdapter()
    report = export_module.export_store(paths, target, verifier=verifier)
    data = json.loads(target.read_text())
    assert data["format"] == "memory.export.v1"
    assert data["encrypted"] is False
    assert data["sensitivity_scope"] == "all"
    assert data["audit_generation"] == before
    tables = data["tables"]
    assert {row["sensitivity"] for row in tables["memory_revisions"]["rows"]} == {
        s.value for s in Sensitivity
    }
    assert len(tables["memory_evidence"]["rows"]) == 3
    assert len(tables["approvals"]["rows"]) == 3
    assert len(tables["applications"]["rows"]) == 3
    for blob in tables["source_blobs"]["rows"]:
        assert (
            base64.b64decode(blob["original_bytes"]["base64"])
            == blob["utf8_text"].encode()
        )
    assert "蓝色灯笼" in target.read_text()
    assert "uncaptured synthetic marker" not in target.read_text()
    assert "source_fts" not in tables and "inbox_scan_candidates" not in tables
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert verifier.calls == 1 and "ALL" in verifier.reasons[0]
    assert report["format"] == data["format"]
    with writer_session(paths) as connection:
        assert (
            connection.execute("SELECT audit_generation FROM store_meta").fetchone()[0]
            == before
        )
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize("outcome", ["cancelled", "unavailable", "hang"])
def test_failed_presence_writes_nothing(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    from memory.ui import owner_presence

    monkeypatch.setattr(owner_presence, "OWNER_PRESENCE_TIMEOUT_SECONDS", 0.01)
    target = destination(tmp_path)
    with pytest.raises(OwnerApprovalRequiredError):
        export_module.export_store(
            synthetic_store,
            target,
            verifier=SyntheticOwnerPresenceAdapter(outcome=outcome),
        )
    assert list(target.parent.iterdir()) == []


def test_wrong_presence_receipt_writes_nothing(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    target = destination(tmp_path)
    with pytest.raises(OwnerApprovalRequiredError):
        export_module.export_store(
            synthetic_store,
            target,
            verifier=SyntheticOwnerPresenceAdapter(
                receipt_lease_id="foreign-synthetic-lease"
            ),
        )
    assert list(target.parent.iterdir()) == []


def test_export_never_overwrites_a_destination(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    target = destination(tmp_path)
    target.write_text("synthetic existing file")
    verifier = SyntheticOwnerPresenceAdapter()
    with pytest.raises(InvalidArgumentError):
        export_module.export_store(synthetic_store, target, verifier=verifier)
    assert target.read_text() == "synthetic existing file" and verifier.calls == 0


def test_destination_winner_during_prompt_is_preserved(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    target = destination(tmp_path)

    def create_winner() -> None:
        target.write_text("synthetic winner")

    verifier = SyntheticOwnerPresenceAdapter(during=create_winner)
    with pytest.raises(InvalidArgumentError):
        export_module.export_store(synthetic_store, target, verifier=verifier)
    assert target.read_text() == "synthetic winner"
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize("place", ["runtime", "inbox", "symlink", "public"])
def test_unsafe_destinations_refuse_before_prompt(
    synthetic_store: RuntimePaths, tmp_path: Path, place: str
) -> None:
    target = destination(tmp_path)
    if place == "runtime":
        target = synthetic_store.root / "export.json"
    elif place == "inbox":
        target = synthetic_store.inbox / "export.json"
    elif place == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(target.parent, target_is_directory=True)
        target = alias / target.name
    else:
        os.chmod(target.parent, 0o755)
    verifier = SyntheticOwnerPresenceAdapter()
    with pytest.raises(InvalidArgumentError):
        export_module.export_store(synthetic_store, target, verifier=verifier)
    assert not target.exists() and verifier.calls == 0


def test_complete_history_binary_dedup_and_legacy_shapes(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    from synthetic import store_one_memory, two_source_linked_apply
    from test_guard_links import (
        _downgrade_to_pre_revocation_shape,
        _lineage_link,
        _revoking_draft,
    )

    from memory.model import ChangeSetAdapterOrigin, RejectItem, SetSourceNoMemory
    from memory.reviews import edit_change_set
    from memory.sources import _read_connection

    paths = synthetic_store
    clock = FakeClock()
    old, lineage = store_one_memory(
        paths,
        clock=clock,
        name="old.txt",
        body="Synthetic old.\n",
        statement="Synthetic old.",
        excerpt="Synthetic old.",
    )
    batch, source = capture_text(
        paths,
        name="correction.txt",
        body="Synthetic corrected.\n",
        sensitivity=Sensitivity.RESTRICTED,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch,
            [
                single_item_edit(
                    item_id="correction",
                    source=source,
                    statement="Synthetic corrected.",
                    excerpt="Synthetic corrected.",
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=lineage,
                    expected_head_id=old,
                )
            ],
        ),
    )
    two_source_linked_apply(paths, clock)
    with _read_connection(paths) as (connection, _):
        pair = connection.execute(
            "SELECT guard_lineage_id, governed_lineage_id FROM memory_guard_links"
        ).fetchone()
    apply_ready(paths, _revoking_draft(paths, clock, _lineage_link(*pair)))
    batch, source = capture_text(
        paths,
        name="unapplied.txt",
        body="Synthetic rejected.\n",
        sensitivity=Sensitivity.SENSITIVE,
        clock=clock,
    )
    draft = ready_items(
        paths,
        batch,
        [
            single_item_edit(
                item_id="rejected",
                source=source,
                statement="Synthetic rejected.",
                excerpt="Synthetic rejected.",
                sensitivity=Sensitivity.SENSITIVE,
            )
        ],
    )
    edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        [
            RejectItem("rejected"),
            SetSourceNoMemory(source.source_id, "Synthetic no-memory reason"),
        ],
        adapter_origin=ChangeSetAdapterOrigin.SYSTEM,
    )
    raw = b"\x00\xff\xfe\r\nSynthetic binary"
    from memory.inbox import scan_inbox

    for sensitivity in [Sensitivity.NORMAL, Sensitivity.RESTRICTED]:
        (paths.inbox / f"binary-{sensitivity.value}.bin").write_bytes(raw)
        scan_inbox(paths, sensitivity=sensitivity, clock=clock)
    with _read_connection(paths) as (connection, _):
        before_schema = connection.execute(
            "SELECT name, sql FROM sqlite_master ORDER BY name"
        ).fetchall()
        before_generation = connection.execute(
            "SELECT audit_generation FROM store_meta"
        ).fetchone()[0]
    target = destination(tmp_path)
    export_module.export_store(paths, target, verifier=SyntheticOwnerPresenceAdapter())
    data = json.loads(target.read_text())
    # Independently compare every stored column and row, including all histories.
    with _read_connection(paths) as (connection, _):
        for table, contents in data["tables"].items():
            cursor = connection.execute(
                f'SELECT rowid, * FROM "{table}" ORDER BY rowid'
            )
            assert cursor.description is not None
            names = ["_rowid", *[column[0] for column in cursor.description[1:]]]
            expected = []
            for row in cursor:
                expected.append(
                    {
                        key: {"base64": base64.b64encode(value).decode()}
                        if isinstance(value, bytes)
                        else value
                        for key, value in zip(names, row, strict=True)
                    }
                )
            assert contents["rows"] == expected
            assert contents["row_count"] == len(expected)
    tables = data["tables"]
    assert len(tables["memory_revisions"]["rows"]) > len(
        tables["current_memory_heads"]["rows"]
    )
    assert any(row["status"] == "rejected" for row in tables["change_items"]["rows"])
    assert tables["memory_guard_links"]["rows"][0]["revoked_at"] is not None
    assert tables["change_revision_guard_revocations"]["rows"]
    assert any(
        row["state"] == "no_memory" for row in tables["batch_source_decisions"]["rows"]
    )
    binaries = [
        row for row in tables["source_blobs"]["rows"] if row["utf8_text"] is None
    ]
    assert (
        len(binaries) == 1
        and base64.b64decode(binaries[0]["original_bytes"]["base64"]) == raw
    )
    assert (
        len(
            [
                s
                for s in tables["sources"]["rows"]
                if s["blob_id"] == binaries[0]["blob_id"]
            ]
        )
        == 2
    )
    with _read_connection(paths) as (connection, _):
        assert (
            connection.execute(
                "SELECT name, sql FROM sqlite_master ORDER BY name"
            ).fetchall()
            == before_schema
        )
        assert (
            connection.execute("SELECT audit_generation FROM store_meta").fetchone()[0]
            == before_generation
        )
    _downgrade_to_pre_revocation_shape(paths)
    export_module.export_store(
        paths, target.with_name("legacy.json"), verifier=SyntheticOwnerPresenceAdapter()
    )
    legacy = json.loads(target.with_name("legacy.json").read_text())["tables"]
    assert legacy["change_revision_guard_revocations"]["present"] is False
    assert len(legacy["memory_guard_links"]["columns"]) == 3
    with _read_connection(paths) as (connection, _):
        assert (
            len(connection.execute("PRAGMA table_info(memory_guard_links)").fetchall())
            == 3
        )


def test_snapshot_excludes_concurrent_later_commit(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    from memory.sources import _read_connection

    paths = synthetic_store
    target = destination(tmp_path)
    with _read_connection(paths) as (connection, _):
        generation = connection.execute(
            "SELECT audit_generation FROM store_meta"
        ).fetchone()[0]

    def commit_during_prompt() -> None:
        capture_text(
            paths,
            name="later.txt",
            body="Synthetic concurrent later source.\n",
            sensitivity=Sensitivity.RESTRICTED,
            clock=FakeClock(),
        )

    export_module.export_store(
        paths,
        target,
        verifier=SyntheticOwnerPresenceAdapter(during=commit_during_prompt),
    )
    data = json.loads(target.read_text())
    assert data["audit_generation"] == generation
    assert data["tables"]["sources"]["rows"] == []
    assert data["tables"]["source_blobs"]["rows"] == []
    other = target.with_name("later.json")
    export_module.export_store(paths, other, verifier=SyntheticOwnerPresenceAdapter())
    assert len(json.loads(other.read_text())["tables"]["sources"]["rows"]) == 1


@pytest.mark.parametrize(
    "change", ["output-mode", "output-parent", "runtime-leaf", "database-leaf"]
)
def test_authority_drift_during_presence_refuses(
    synthetic_store: RuntimePaths, tmp_path: Path, change: str
) -> None:
    paths = synthetic_store
    target = destination(tmp_path)

    def alter() -> None:
        if change == "output-mode":
            target.parent.chmod(0o755)
        elif change == "output-parent":
            target.parent.rename(tmp_path / "moved-private-exports")
            target.parent.mkdir(mode=0o700)
        else:
            leaf = paths.identity if change == "runtime-leaf" else paths.database
            original = leaf.read_bytes()
            leaf.rename(leaf.with_suffix(".saved"))
            leaf.write_bytes(original)
            leaf.chmod(0o600)

    with pytest.raises(InvalidArgumentError):
        export_module.export_store(
            paths, target, verifier=SyntheticOwnerPresenceAdapter(during=alter)
        )
    assert not target.exists()
    assert not list(tmp_path.rglob(".memory-export-*"))


def test_stream_failure_cleans_private_temporary(
    synthetic_store: RuntimePaths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import TextIO

    from memory.database import Connection

    target = destination(tmp_path)

    def fail(connection: Connection, stream: TextIO, generation: int) -> dict[str, int]:
        stream.write("synthetic partial secret")
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(export_module, "_write_snapshot", fail)
    with pytest.raises(InvalidArgumentError):
        export_module.export_store(
            synthetic_store, target, verifier=SyntheticOwnerPresenceAdapter()
        )
    assert list(target.parent.iterdir()) == []


def test_cli_export_reports_only_content_free_summary(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from memory.cli import main
    from memory.ui import owner_presence

    capture_text(
        synthetic_store,
        name="secret.txt",
        body="Synthetic private marker 蓝色。\n",
        sensitivity=Sensitivity.RESTRICTED,
        clock=FakeClock(),
    )
    verifier = SyntheticOwnerPresenceAdapter()
    monkeypatch.setattr(
        owner_presence, "_production_owner_presence_verifier", lambda: verifier
    )
    target = destination(tmp_path)
    assert (
        main(["export", "--home", str(synthetic_store.root), "--output", str(target)])
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["output"] == str(target)
    assert "Synthetic private marker" not in captured.out + captured.err
    assert "Synthetic private marker" in target.read_text()
    assert verifier.calls == 1


def test_no_pagination_cap_and_absent_auxiliary_tables(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    from test_guard_links import _drop_guard_tables

    from memory.sources import _read_connection

    paths = synthetic_store
    _batch, source = capture_text(
        paths,
        name="seed.txt",
        body="Synthetic bulk seed.\n",
        sensitivity=Sensitivity.RESTRICTED,
        clock=FakeClock(),
    )
    with writer_session(paths) as connection:
        blob_id = connection.execute(
            "SELECT blob_id FROM sources WHERE source_id = ?", (source.source_id,)
        ).fetchone()[0]
        for index in range(520):
            batch_id = f"synthetic-bulk-batch-{index}"
            source_id = f"synthetic-bulk-source-{index}"
            connection.execute(
                "INSERT INTO inbox_batches (batch_id,sealed_at,source_count,has_more) VALUES (?,0,1,0)",
                (batch_id,),
            )
            connection.execute(
                "INSERT INTO sources VALUES (?,?,?,'inbox',?,'text/plain','owner','restricted',0)",
                (source_id, blob_id, batch_id, f"synthetic-{index}.txt"),
            )
            connection.execute(
                "INSERT INTO inbox_batch_sources VALUES (?,?,0)", (batch_id, source_id)
            )
    _drop_guard_tables(paths)
    target = destination(tmp_path)
    export_module.export_store(paths, target, verifier=SyntheticOwnerPresenceAdapter())
    data = json.loads(target.read_text())["tables"]
    assert data["sources"]["row_count"] == 521
    assert len(data["sources"]["rows"]) == 521
    assert data["memory_guard_links"] == {
        "present": False,
        "columns": [],
        "row_count": 0,
        "rows": [],
    }
    with _read_connection(paths) as (connection, _):
        assert (
            connection.execute("PRAGMA table_info(memory_guard_links)").fetchall() == []
        )


def test_unknown_authoritative_table_refuses_instead_of_omitting(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    with writer_session(synthetic_store) as connection:
        connection.execute("CREATE TABLE future_retained_record (value TEXT) STRICT")
    target = destination(tmp_path)
    with pytest.raises(InvalidArgumentError, match="inventory"):
        export_module.export_store(
            synthetic_store, target, verifier=SyntheticOwnerPresenceAdapter()
        )
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_winner_at_actual_move_boundary_is_preserved(
    synthetic_store: RuntimePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    from memory.initialization_fs import BoundDirectory

    module = export_module
    target = destination(tmp_path)
    foreign = tmp_path / "synthetic-foreign"
    foreign.write_text("Synthetic foreign marker")
    original = module._absent
    calls = 0

    def race(directory: BoundDirectory, name: str) -> None:
        nonlocal calls
        original(directory, name)
        calls += 1
        if calls == 3:
            if kind == "file":
                target.write_text("Synthetic winner marker")
            else:
                target.symlink_to(foreign)

    monkeypatch.setattr(module, "_absent", race)
    with pytest.raises(InvalidArgumentError):
        module.export_store(
            synthetic_store, target, verifier=SyntheticOwnerPresenceAdapter()
        )
    assert target.read_text() == (
        "Synthetic winner marker" if kind == "file" else "Synthetic foreign marker"
    )
    assert foreign.read_text() == "Synthetic foreign marker"
    assert list(target.parent.iterdir()) == [target]


def test_temporary_substitution_preserves_foreign_leaf(
    synthetic_store: RuntimePaths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typing import TextIO

    from memory.database import Connection

    module = export_module
    target = destination(tmp_path)
    original = module._write_snapshot
    replacement: Path | None = None
    retained = target.parent / "renamed-owned-temporary"

    def substitute(
        connection: Connection, stream: TextIO, generation: int
    ) -> dict[str, int]:
        nonlocal replacement
        replacement = next(target.parent.glob(".memory-export-*.tmp"))
        replacement.rename(retained)
        replacement.write_text("Synthetic replacement marker")
        replacement.chmod(0o600)
        return original(connection, stream, generation)

    monkeypatch.setattr(module, "_write_snapshot", substitute)
    with pytest.raises(InvalidArgumentError):
        module.export_store(
            synthetic_store, target, verifier=SyntheticOwnerPresenceAdapter()
        )
    assert (
        replacement is not None
        and replacement.read_text() == "Synthetic replacement marker"
    )
    assert not retained.exists() and not target.exists()


def test_failure_after_move_removes_only_owned_export(
    synthetic_store: RuntimePaths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from memory.initialization_fs import BoundDirectory

    module = export_module
    target = destination(tmp_path)
    original = module._owned_file

    def fail(directory: BoundDirectory, name: str, descriptor: int) -> None:
        original(directory, name, descriptor)
        if name == target.name:
            raise InvalidArgumentError("synthetic post-move validation failure")

    monkeypatch.setattr(module, "_owned_file", fail)
    with pytest.raises(InvalidArgumentError):
        module.export_store(
            synthetic_store, target, verifier=SyntheticOwnerPresenceAdapter()
        )
    assert list(target.parent.iterdir()) == []


def test_inheritable_acl_refuses_before_authentication(
    synthetic_store: RuntimePaths, tmp_path: Path
) -> None:
    import subprocess

    target = destination(tmp_path)
    subprocess.run(
        [
            "chmod",
            "+a",
            "everyone allow read,search,file_inherit,directory_inherit",
            str(target.parent),
        ],
        check=True,
    )
    verifier = SyntheticOwnerPresenceAdapter()
    try:
        with pytest.raises(InvalidArgumentError, match="ACL"):
            export_module.export_store(synthetic_store, target, verifier=verifier)
        assert verifier.calls == 0 and list(target.parent.iterdir()) == []
    finally:
        subprocess.run(["chmod", "-N", str(target.parent)], check=True)


@pytest.mark.parametrize("boundary", ["stream", "before-move", "after-move"])
def test_process_death_never_exposes_partial_final(
    tmp_path: Path, boundary: str
) -> None:
    import subprocess
    import sys

    script = r"""
import os, sys
from pathlib import Path
import pytest
from synthetic import make_synthetic_store
from test_owner_presence import SyntheticOwnerPresenceAdapter
from memory import export as module
root = Path(sys.argv[1])
boundary = sys.argv[2]
parent = root / "private-exports"
parent.mkdir(mode=0o700)
target = parent / "all.json"
patch = pytest.MonkeyPatch()
fixture = make_synthetic_store(root, patch)
paths = next(fixture)
if boundary == "stream":
    def die(connection, stream, generation):
        stream.write("Synthetic unfinished plaintext")
        stream.flush()
        os._exit(23)
    module._write_snapshot = die
else:
    original = module._owned_file
    calls = 0
    def die(directory, name, descriptor):
        global calls
        original(directory, name, descriptor)
        if name.startswith(".memory-export-"):
            calls += 1
        if (boundary == "before-move" and calls == 2) or (boundary == "after-move" and name == target.name):
            os._exit(23)
    module._owned_file = die
module.export_store(paths, target, verifier=SyntheticOwnerPresenceAdapter())
raise AssertionError("death boundary not reached")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), boundary],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 23, result.stdout + result.stderr
    parent = tmp_path / "private-exports"
    final = parent / "all.json"
    if final.exists():
        assert json.loads(final.read_text())["format"] == "memory.export.v1"
        assert stat.S_IMODE(final.stat().st_mode) == 0o600
    else:
        temporary = list(parent.glob(".memory-export-*.tmp"))
        assert len(temporary) == 1
        assert stat.S_IMODE(temporary[0].stat().st_mode) == 0o600
