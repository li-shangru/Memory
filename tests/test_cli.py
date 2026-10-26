from __future__ import annotations

import base64
import fcntl
import importlib
import io
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest
from test_owner_presence import SyntheticOwnerPresenceAdapter

from memory import model as store_model
from memory.ui import owner_presence

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def never_prompt_the_real_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee no automated test can open the real macOS owner-presence prompt."""

    def refuse_real_context(_self: object) -> object:
        pytest.fail("an automated test attempted the real macOS owner prompt")

    monkeypatch.setattr(
        owner_presence.LocalAuthenticationOwnerPresenceVerifier,
        "_new_context",
        refuse_real_context,
    )


def run_pms(
    *args: str, env_overrides: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(env_overrides or {})
    return subprocess.run(
        [sys.executable, "-m", "memory.cli", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )


def runtime_filesystem_snapshot(root: Path) -> dict[str, object]:
    """Capture metadata that a refused initialization must leave untouched."""
    entries = tuple(sorted(path.name for path in root.iterdir()))
    modes = {
        ".": stat.S_IMODE(root.lstat().st_mode),
        **{path.name: stat.S_IMODE(path.lstat().st_mode) for path in root.iterdir()},
    }
    sidecars = {
        name: (root / name).read_bytes() if (root / name).is_file() else None
        for name in (".writer.lock", "store.sqlite3-wal", "store.sqlite3-shm")
    }
    return {"entries": entries, "modes": modes, "sidecars": sidecars}


def runtime_durable_filesystem_snapshot(root: Path) -> dict[str, object]:
    """Capture durable state while allowing SQLite WAL read marks in SHM."""
    entries = tuple(sorted(path.name for path in root.iterdir()))
    modes = {
        ".": stat.S_IMODE(root.lstat().st_mode),
        **{path.name: stat.S_IMODE(path.lstat().st_mode) for path in root.iterdir()},
    }
    files = {
        path.name: path.read_bytes()
        for path in root.iterdir()
        if path.is_file() and path.name != "store.sqlite3-shm"
    }
    shared_memory = root / "store.sqlite3-shm"
    shm_metadata = (
        (
            stat.S_IMODE(shared_memory.lstat().st_mode),
            shared_memory.stat().st_size,
        )
        if shared_memory.is_file()
        else None
    )
    return {
        "entries": entries,
        "modes": modes,
        "files": files,
        "shm_metadata": shm_metadata,
    }


def test_resolve_runtime_uses_store_default_and_ignores_legacy_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch accidental reuse of the superseded Service runtime namespace."""
    runtime = importlib.import_module("memory.runtime")
    monkeypatch.setenv("HOME", str(tmp_path / "synthetic-owner"))
    monkeypatch.setenv("PMS_HOME", str(tmp_path / "legacy-runtime"))

    assert hasattr(runtime, "resolve_runtime")
    paths = runtime.resolve_runtime(None)

    assert paths.root == (
        tmp_path / "synthetic-owner" / "Library" / "Application Support" / "Memory"
    )
    assert paths.database == paths.root / "store.sqlite3"
    assert paths.inbox == paths.root / "inbox"
    assert paths.inbox_claims == paths.root / "inbox-claims"
    assert paths.inbox_staging == paths.root / "inbox-staging"
    assert paths.identity == paths.root / "runtime.json"
    assert paths.ui_session_lock == paths.root / ".ui-session.lock"


def test_resolve_runtime_explicit_home_takes_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = importlib.import_module("memory.runtime")
    explicit = tmp_path / "explicit-store"
    monkeypatch.setenv("HOME", str(tmp_path / "synthetic-owner"))
    monkeypatch.setenv("PMS_HOME", str(tmp_path / "legacy-runtime"))

    paths = runtime.resolve_runtime(explicit)

    assert paths.root == explicit


def test_relocate_inbox_cli_moves_and_replays_content_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import cli, runtime

    home = tmp_path / "synthetic-store"
    source = tmp_path / "old" / "Inbox"
    destination = tmp_path / "new" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    runtime.initialize_runtime(
        runtime.resolve_runtime(home),
        mode=store_model.RuntimeMode.PERSONAL,
        inbox=source,
    )
    before = source.lstat()

    assert (
        cli.main(
            [
                "relocate-inbox",
                "--home",
                str(home),
                "--to",
                str(destination),
            ]
        )
        == 0
    )
    first = capsys.readouterr()
    assert first.out == '{"status":"relocated"}\n'
    assert first.err == ""
    moved = destination.lstat()
    assert (moved.st_dev, moved.st_ino) == (before.st_dev, before.st_ino)

    assert (
        cli.main(
            [
                "relocate-inbox",
                "--home",
                str(home),
                "--to",
                str(destination),
            ]
        )
        == 0
    )
    replay = capsys.readouterr()
    assert replay.out == '{"status":"current"}\n'
    assert replay.err == ""


def test_relocate_inbox_cli_recovers_one_durable_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import cli, inbox_relocation, runtime

    home = tmp_path / "synthetic-store"
    source = tmp_path / "old" / "Inbox"
    destination = tmp_path / "new" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    runtime.initialize_runtime(
        runtime.resolve_runtime(home),
        mode=store_model.RuntimeMode.PERSONAL,
        inbox=source,
    )

    class SyntheticCrash(BaseException):
        pass

    def interrupt(name: str) -> None:
        if name == "after_directory_move":
            raise SyntheticCrash

    monkeypatch.setattr(
        inbox_relocation,
        "_relocation_checkpoint",
        interrupt,
    )
    with pytest.raises(SyntheticCrash):
        inbox_relocation.relocate_inbox(
            runtime.resolve_runtime(home),
            destination,
        )
    monkeypatch.setattr(
        inbox_relocation,
        "_relocation_checkpoint",
        lambda name: None,
    )

    assert (
        cli.main(
            [
                "relocate-inbox",
                "--home",
                str(home),
                "--to",
                str(destination),
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert output.out == '{"status":"recovered"}\n'
    assert output.err == ""


def test_relocate_inbox_cli_error_is_content_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import cli, runtime

    home = tmp_path / "synthetic-store"
    source = tmp_path / "old-private-marker" / "Inbox"
    destination = tmp_path / "new-private-marker" / "Inbox"
    source.parent.mkdir(mode=0o700)
    destination.parent.mkdir(mode=0o700)
    runtime.initialize_runtime(
        runtime.resolve_runtime(home),
        mode=store_model.RuntimeMode.PERSONAL,
        inbox=source,
    )
    destination.mkdir(mode=0o700)

    assert (
        cli.main(
            [
                "relocate-inbox",
                "--home",
                str(home),
                "--to",
                str(destination),
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "memory: invalid_argument\n"
    assert "old-private-marker" not in output.err
    assert "new-private-marker" not in output.err


def test_relocate_inbox_cli_has_exact_required_grammar() -> None:
    help_result = run_pms("relocate-inbox", "--help")
    missing = run_pms("relocate-inbox")
    extra = run_pms("relocate-inbox", "--to", "/synthetic", "extra")

    assert help_result.returncode == 0
    assert "--to TO" in help_result.stdout
    assert "--home HOME" in help_result.stdout
    assert missing.returncode == 2
    assert extra.returncode == 2


def test_version_reports_the_installed_distribution_version() -> None:
    result = run_pms("--version")

    assert result.returncode == 0
    assert re.fullmatch(r"memory \d+\.\d+\.\d+\n", result.stdout)
    assert result.stderr == ""


def test_initialize_runtime_creates_private_identity_key_database_and_is_idempotent(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch incomplete, non-private, or key-replacing runtime initialization."""
    runtime = importlib.import_module("memory.runtime")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")

    assert hasattr(runtime, "initialize_runtime")
    first = runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    key_items_after_first = synthetic_keychain.copy()
    second = runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert first == second
    assert first.product == "memory"
    assert first.schema_lineage == "memory-store-v1"
    assert first.schema_version == 1
    assert first.runtime_mode is store_model.RuntimeMode.PERSONAL
    assert re.fullmatch(r"[0-9a-f]{32}", first.store_id)
    assert synthetic_keychain == key_items_after_first
    assert set(synthetic_keychain) == {("memory", first.store_id)}
    encoded = synthetic_keychain[("memory", first.store_id)]
    assert len(base64.b64decode(encoded, validate=True)) == 32
    assert paths.database.is_file()
    assert paths.identity.is_file()
    assert stat.S_IMODE(paths.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.inbox.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.inbox_claims.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.identity.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.database.stat().st_mode) == 0o600


def test_initialized_runtime_with_a_missing_key_fails_without_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    identity = runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    paths.writer_lock.unlink()
    paths.root.chmod(0o751)
    paths.inbox.chmod(0o750)
    paths.inbox_claims.chmod(0o755)
    paths.identity.chmod(0o640)
    paths.database.chmod(0o640)
    before = runtime_filesystem_snapshot(paths.root)
    del synthetic_keychain[("memory", identity.store_id)]
    creations: list[str] = []
    monkeypatch.setattr(
        keys,
        "create_master_key",
        lambda _identity: creations.append("created"),
    )

    with pytest.raises(errors.KeyMissingError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert creations == []
    assert synthetic_keychain == {}
    assert runtime_filesystem_snapshot(paths.root) == before


def test_initialized_runtime_with_foreign_identity_fails_before_mutation(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    paths.writer_lock.unlink()
    payload = json.loads(paths.identity.read_text(encoding="utf-8"))
    payload["product"] = "synthetic-foreign-product"
    paths.identity.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    paths.root.chmod(0o751)
    paths.identity.chmod(0o640)
    before = runtime_filesystem_snapshot(paths.root)

    with pytest.raises(errors.InvalidRuntimeError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert runtime_filesystem_snapshot(paths.root) == before
    assert len(synthetic_keychain) == 1


def test_initialized_runtime_with_foreign_database_fails_before_mutation(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    identity = runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    key = base64.b64decode(
        synthetic_keychain[("memory", identity.store_id)],
        validate=True,
    )
    connection = database.open_database(paths, key, read_only=False)
    try:
        connection.execute(
            "UPDATE store_meta SET product = ?",
            ("synthetic-foreign-product",),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    finally:
        connection.close()
    paths.writer_lock.unlink()
    paths.root.chmod(0o751)
    paths.inbox.chmod(0o750)
    paths.inbox_claims.chmod(0o755)
    paths.database.chmod(0o640)
    before = runtime_filesystem_snapshot(paths.root)

    with pytest.raises(errors.WrongProductError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert runtime_filesystem_snapshot(paths.root) == before


@pytest.mark.parametrize(
    "foreign_commit_phase",
    ["before-initialize", "before-lock"],
)
def test_initialize_runtime_rejects_foreign_identity_only_in_live_wal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    foreign_commit_phase: str,
) -> None:
    """Catch initialization validating stale main-file identity before return/repair."""
    runtime = importlib.import_module("memory.runtime")
    database = importlib.import_module("memory.database")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    identity = runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    key = base64.b64decode(
        synthetic_keychain[("memory", identity.store_id)],
        validate=True,
    )
    writer = database.open_database(paths, key, read_only=False)
    writer.execute("PRAGMA wal_autocheckpoint = 0")
    main_before = paths.database.read_bytes()
    refusal_snapshots: list[dict[str, object]] = []

    def commit_foreign_identity() -> None:
        writer.execute(
            "UPDATE store_meta SET product = ?",
            ("synthetic-foreign-product",),
        )
        writer.commit()
        assert paths.database.read_bytes() == main_before
        assert Path(f"{paths.database}-wal").stat().st_size > 0

    if foreign_commit_phase == "before-lock":
        paths.root.chmod(0o751)
        real_needs_repair: Callable[[store_model.RuntimePaths], bool] = (
            runtime._runtime_needs_repair
        )

        def commit_during_repair_check(check_paths: store_model.RuntimePaths) -> bool:
            assert check_paths == paths
            needs_repair = real_needs_repair(paths)
            commit_foreign_identity()
            refusal_snapshots.append(runtime_durable_filesystem_snapshot(paths.root))
            return needs_repair

        monkeypatch.setattr(
            runtime, "_runtime_needs_repair", commit_during_repair_check
        )
    else:
        commit_foreign_identity()
        refusal_snapshots.append(runtime_durable_filesystem_snapshot(paths.root))

    try:
        with pytest.raises(errors.WrongProductError):
            runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

        assert len(refusal_snapshots) == 1
        assert runtime_durable_filesystem_snapshot(paths.root) == refusal_snapshots[0]
    finally:
        writer.close()


def test_failed_database_initialization_preserves_its_key_for_safe_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    initialization = importlib.import_module("memory.initialization")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    real_build = initialization._build_database
    attempted_keys: list[bytes] = []
    identities: list[store_model.StoreIdentity] = []

    def fail_build(
        _root: object, _record: object, identity: store_model.StoreIdentity, key: bytes
    ) -> None:
        attempted_keys.append(key)
        identities.append(identity)
        raise errors.StoreOpenError("synthetic initialization failure")

    monkeypatch.setattr(initialization, "_build_database", fail_build)
    with pytest.raises(errors.StoreOpenError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    with pytest.raises(errors.InvalidRuntimeError):
        runtime.load_runtime_identity(paths)
    assert not paths.identity.exists()
    identity = identities[0]
    stored = synthetic_keychain[("memory", identity.store_id)]
    assert base64.b64decode(stored, validate=True) == attempted_keys[0]

    monkeypatch.setattr(initialization, "_build_database", real_build)
    assert (
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
        == identity
    )


def test_initialization_failure_never_deletes_a_concurrently_replaced_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    initialization = importlib.import_module("memory.initialization")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    concurrent = base64.b64encode(b"z" * 32).decode("ascii")
    identities: list[store_model.StoreIdentity] = []

    def replace_then_fail(
        _root: object, _record: object, identity: store_model.StoreIdentity, _key: bytes
    ) -> None:
        identities.append(identity)
        synthetic_keychain[("memory", identity.store_id)] = concurrent
        raise errors.StoreOpenError("synthetic concurrent initialization failure")

    monkeypatch.setattr(initialization, "_build_database", replace_then_fail)
    with pytest.raises(errors.StoreOpenError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    assert synthetic_keychain[("memory", identities[0].store_id)] == concurrent
    with pytest.raises(errors.InitializationError, match="key ownership"):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    assert synthetic_keychain[("memory", identities[0].store_id)] == concurrent


def test_cli_init_and_paths_json_use_only_the_explicit_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a CLI that resolves or initializes the default/legacy runtime."""
    cli = importlib.import_module("memory.cli")
    explicit = tmp_path / "explicit-store"
    monkeypatch.setenv("PMS_HOME", str(tmp_path / "legacy-runtime"))

    assert cli.main(["init", "--home", str(explicit)]) == 0
    init_output = capsys.readouterr()
    assert str(explicit / "inbox") in init_output.out
    assert init_output.err == ""
    assert cli.main(["paths", "--home", str(explicit), "--json"]) == 0
    paths_output = capsys.readouterr()

    assert json.loads(paths_output.out) == {
        "database": str(explicit / "store.sqlite3"),
        "home": str(explicit),
        "identity": str(explicit / "runtime.json"),
        "inbox": str(explicit / "inbox"),
        "inbox_claims": str(explicit / "inbox-claims"),
    }
    assert paths_output.err == ""
    assert not (tmp_path / "legacy-runtime").exists()
    assert len(synthetic_keychain) == 1


def test_cli_reindex_rebuilds_search_projections_and_reports_row_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch memory reindex failing to run or reporting the wrong wire shape."""
    cli = importlib.import_module("memory.cli")
    store_home = tmp_path / "reindex-store"

    assert cli.main(["init", "--home", str(store_home)]) == 0
    capsys.readouterr()

    assert cli.main(["reindex", "--home", str(store_home)]) == 0
    reindex_output = capsys.readouterr()

    payload = json.loads(reindex_output.out)
    assert set(payload) == {"memory_rows", "source_rows"}
    assert payload == {"memory_rows": 0, "source_rows": 0}
    assert reindex_output.err == ""


def test_ui_launch_recovers_exact_captures_before_ready_or_browser_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch memory ui advertising readiness before durable correction recovery."""
    app = importlib.import_module("memory.ui.app")
    cli = importlib.import_module("memory.cli")
    runtime = importlib.import_module("memory.runtime")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-ui-recovery")
    runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    events: list[str] = []

    def recover(
        observed: object,
        *,
        directory_authority: object,
    ) -> tuple[object, ...]:
        assert observed == paths
        assert directory_authority is not None
        events.append("recover")
        return ()

    def serve(
        _application: object, _socket: object, on_ready: Callable[[], None]
    ) -> None:
        assert events == ["recover"]
        events.append("serve")
        on_ready()

    def open_browser(_url: str) -> None:
        assert events == ["recover", "serve"]
        events.append("browser")

    monkeypatch.setattr(app, "recover_exact_staged_entries", recover)
    monkeypatch.setattr(app, "_serve_ui", serve)
    monkeypatch.setattr(
        app,
        "open_bootstrap_url_with_launch_services",
        open_browser,
    )

    assert cli.main(["ui", "--home", str(paths.root)]) == 0
    assert events == ["recover", "serve", "browser"]
    assert "recover exact captures" in cli._build_parser().format_help()
    assert len(synthetic_keychain) == 1


def test_initialization_refuses_concurrent_writer_without_minting_identity_or_key(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-store")
    paths.root.mkdir(mode=0o700)
    with paths.writer_lock.open("w+b") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(errors.StoreBusyError):
            runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert not paths.identity.exists()
    assert synthetic_keychain == {}


def test_initialization_rejects_a_nonempty_foreign_home_without_mutation(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")
    errors = importlib.import_module("memory.errors")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-foreign-home")
    paths.root.mkdir(mode=0o700)
    marker = paths.root / "synthetic-marker.txt"
    marker.write_text("unchanged\n", encoding="utf-8")

    with pytest.raises(errors.InitializationError):
        runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert {path.name for path in paths.root.iterdir()} == {marker.name}
    assert marker.read_text(encoding="utf-8") == "unchanged\n"
    assert synthetic_keychain == {}


def test_separate_runtimes_receive_distinct_random_store_identities(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    runtime = importlib.import_module("memory.runtime")

    first = runtime.initialize_runtime(
        runtime.resolve_runtime(tmp_path / "first"),
        mode=store_model.RuntimeMode.PERSONAL,
    )
    second = runtime.initialize_runtime(
        runtime.resolve_runtime(tmp_path / "second"),
        mode=store_model.RuntimeMode.PERSONAL,
    )

    assert first.store_id != second.store_id
    assert set(synthetic_keychain) == {
        ("memory", first.store_id),
        ("memory", second.store_id),
    }


class InteractiveText(io.StringIO):
    def isatty(self) -> bool:
        return True


def ready_cli_review(paths: store_model.RuntimePaths) -> store_model.ChangeSetView:
    from memory.inbox import scan_inbox
    from memory.model import (
        AddItem,
        EvidenceInput,
        MemoryFields,
        MemoryKind,
        Sensitivity,
    )
    from memory.reviews import create_change_set, edit_change_set
    from memory.sources import list_sources

    class Clock:
        def time(self) -> float:
            return 1_860_000_000.0

        def sleep(self, _seconds: float) -> None:
            return None

    (paths.inbox / "synthetic-cli.txt").write_text(
        "Synthetic CLI fact: the glass orchard opens at noon.\n",
        encoding="utf-8",
    )
    batch = scan_inbox(paths, sensitivity=Sensitivity.NORMAL, clock=Clock())
    source = list_sources(paths).items[0]
    initial = create_change_set(
        paths,
        batch.batch_id,
        adapter_origin=store_model.ChangeSetAdapterOrigin.SYSTEM,
    )
    return edit_change_set(
        paths,
        initial.change_set_id,
        initial.revision_id,
        (
            AddItem(
                client_item_id="itm_cli",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement="The glass orchard opens at noon.",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("synthetic",),
                    sensitivity=Sensitivity.NORMAL,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt="the glass orchard opens at noon",
                    ),
                ),
            ),
        ),
        adapter_origin=store_model.ChangeSetAdapterOrigin.SYSTEM,
    )


@pytest.mark.parametrize("stream_type", (io.StringIO, InteractiveText))
def test_cli_approve_renders_exact_diff_but_refuses_pipe_and_pty_typed_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    stream_type: type[io.StringIO],
) -> None:
    """Catch any textual or PTY path reading input or minting owner approval."""
    from memory import cli, reviews
    from memory.memories import search_memories
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / f"synthetic-cli-{stream_type.__name__}")
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    ready = ready_cli_review(paths)
    arguments = [
        "approve",
        ready.change_set_id,
        "--revision",
        ready.revision_id,
        "--digest",
        ready.digest,
        "--home",
        str(paths.root),
    ]
    input_stream = stream_type("yes\n")
    output_stream = stream_type()
    error_stream = stream_type()
    monkeypatch.setattr(sys, "stdin", input_stream)
    monkeypatch.setattr(sys, "stdout", output_stream)
    monkeypatch.setattr(sys, "stderr", error_stream)

    def fail_mint(*_args: object, **_kwargs: object) -> object:
        pytest.fail("textual CLI attempted to mint OwnerApproval")

    monkeypatch.setattr(reviews, "_mint_owner_approval", fail_mint)
    monkeypatch.setattr(
        owner_presence,
        "_production_owner_presence_verifier",
        lambda: SyntheticOwnerPresenceAdapter(outcome="cancelled"),
    )

    assert cli.main(arguments) == 1
    assert input_stream.tell() == 0
    # The review the owner reads is one document and the result is another.
    # Nothing was applied, so stdout carries nothing at all.
    assert ready.digest in error_stream.getvalue()
    assert '"format":"memory.change-set-digest.v1"' in error_stream.getvalue()
    assert "The glass orchard opens at noon." in error_stream.getvalue()
    assert error_stream.getvalue().endswith("memory: owner_approval_required\n")
    assert output_stream.getvalue() == ""
    assert search_memories(paths, "glass orchard").items == ()
    assert len(synthetic_keychain) == 1


def test_cli_approve_preserves_exact_already_applied_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the fail-closed CLI regressing exact idempotent replay."""
    from memory import cli
    from memory.reviews import _mint_owner_approval, approve_and_apply
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / "synthetic-cli-replay-store")
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    ready = ready_cli_review(paths)
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )

    input_stream = io.StringIO("yes\n")
    output_stream = io.StringIO()
    error_stream = io.StringIO()
    monkeypatch.setattr(sys, "stdin", input_stream)
    monkeypatch.setattr(sys, "stdout", output_stream)
    monkeypatch.setattr(sys, "stderr", error_stream)

    assert (
        cli.main(
            [
                "approve",
                ready.change_set_id,
                "--revision",
                ready.revision_id,
                "--digest",
                ready.digest,
                "--home",
                str(paths.root),
                "--json",
            ]
        )
        == 0
    )
    assert input_stream.tell() == 0
    assert '"idempotent_replay":true' in output_stream.getvalue()
    assert error_stream.getvalue() == ""


def cli_approve_arguments(
    paths: store_model.RuntimePaths, ready: store_model.ChangeSetView
) -> list[str]:
    """Return the exact bounded argument list for one CLI approval."""
    return [
        "approve",
        ready.change_set_id,
        "--revision",
        ready.revision_id,
        "--digest",
        ready.digest,
        "--home",
        str(paths.root),
    ]


def _reported_failures(stderr: str) -> tuple[list[str], list[dict[str, object]]]:
    """Split the CLI's failure stream into codes and their locator payloads.

    Each refusal prints `memory: <code>` and, when the Store attached any, one
    JSON object naming what to fix. Reading them as a pair is what keeps a test
    from passing on a code whose locators were silently dropped.
    """
    codes: list[str] = []
    payloads: list[dict[str, object]] = []
    for line in stderr.splitlines():
        if line.startswith("memory: "):
            codes.append(line.removeprefix("memory: "))
        else:
            payloads.append(json.loads(line))
    return codes, payloads


def prepared_cli_store(
    tmp_path: Path, name: str
) -> tuple[store_model.RuntimePaths, store_model.ChangeSetView]:
    """Initialize one synthetic runtime holding exactly one complete review."""
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / name)
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    return paths, ready_cli_review(paths)


def test_cli_approve_applies_the_exact_revision_after_verified_owner_presence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the CLI being unable to apply through OS-mediated owner presence."""
    from memory import cli
    from memory.memories import search_memories
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-approve-store")
    verifier = SyntheticOwnerPresenceAdapter()
    monkeypatch.setattr(
        presence,
        "_production_owner_presence_verifier",
        lambda: verifier,
    )
    input_stream = io.StringIO("yes\n")
    output_stream = io.StringIO()
    error_stream = io.StringIO()
    monkeypatch.setattr(sys, "stdin", input_stream)
    monkeypatch.setattr(sys, "stdout", output_stream)
    monkeypatch.setattr(sys, "stderr", error_stream)

    assert cli.main(cli_approve_arguments(paths, ready)) == 0

    assert input_stream.tell() == 0
    assert verifier.calls == 1
    assert verifier.reasons == [f"Memory: approve Memory Review {ready.digest[:12]}"]
    # The default result is prose, and it leads with whether anything changed.
    applied = output_stream.getvalue()
    assert applied.startswith("Applied.\n")
    assert f"Revision        {ready.revision_id}" in applied
    assert f"Memory Review   {ready.change_set_id}" in applied
    assert "Standing guard violations: none" in applied
    # The diff is the other document, and it is the only thing on stderr.
    assert ready.digest in error_stream.getvalue()
    assert "memory:" not in error_stream.getvalue()
    assert search_memories(paths, "glass orchard").items != ()
    from memory.ui.service import OwnerApplicationService

    approvals = OwnerApplicationService(paths).list_approvals(None, 50).items
    assert len(approvals) == 1
    assert approvals[0].adapter == "os_owner_presence_cli"
    assert approvals[0].revision_id == ready.revision_id


@pytest.mark.parametrize("outcome", ["cancelled", "unavailable"])
def test_cli_approve_applies_nothing_when_owner_presence_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    outcome: str,
) -> None:
    """Catch a refused or unavailable system prompt still applying the review."""
    from memory import cli
    from memory.memories import search_memories
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, f"synthetic-cli-{outcome}-store")
    verifier = SyntheticOwnerPresenceAdapter(outcome=outcome)
    monkeypatch.setattr(
        presence,
        "_production_owner_presence_verifier",
        lambda: verifier,
    )
    input_stream = io.StringIO("yes\n")
    output_stream = io.StringIO()
    error_stream = io.StringIO()
    monkeypatch.setattr(sys, "stdin", input_stream)
    monkeypatch.setattr(sys, "stdout", output_stream)
    monkeypatch.setattr(sys, "stderr", error_stream)

    assert cli.main(cli_approve_arguments(paths, ready)) == 1

    assert input_stream.tell() == 0
    assert error_stream.getvalue().endswith("memory: owner_approval_required\n")
    assert ready.digest in error_stream.getvalue()
    assert output_stream.getvalue() == ""
    assert search_memories(paths, "glass orchard").items == ()
    from memory.ui.service import OwnerApplicationService

    assert OwnerApplicationService(paths).list_approvals(None, 50).items == ()


@pytest.mark.parametrize(
    "injected",
    [
        ["--verifier", "tests.SyntheticOwnerPresenceAdapter"],
        ["--approve"],
        ["--owner-decision", "accept"],
        ["--owner-presence", "true"],
        ["--adapter", "os_owner_presence_cli"],
    ],
)
def test_cli_approve_accepts_no_verifier_proof_or_decision_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    injected: list[str],
) -> None:
    """Catch a CLI argument injecting a verifier, proof, or owner decision."""
    from memory import cli
    from memory.memories import search_memories
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-injection-store")

    def refuse(*_args: object, **_kwargs: object) -> object:
        pytest.fail("an injected CLI argument reached owner presence")

    monkeypatch.setattr(presence, "_production_owner_presence_verifier", refuse)

    with pytest.raises(SystemExit) as raised:
        cli.main([*cli_approve_arguments(paths, ready), *injected])

    assert raised.value.code == 2
    assert search_memories(paths, "glass orchard").items == ()


def test_cli_approve_refuses_a_stale_revision_or_digest_before_any_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the CLI requesting owner presence for a revision it cannot apply."""
    from memory import cli
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-stale-store")

    def refuse(*_args: object, **_kwargs: object) -> object:
        pytest.fail("a stale CLI approval reached owner presence")

    monkeypatch.setattr(presence, "_production_owner_presence_verifier", refuse)
    error_stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", error_stream)

    stale_revision = cli.main(
        [
            "approve",
            ready.change_set_id,
            "--revision",
            "csr_" + "9" * 32,
            "--digest",
            ready.digest,
            "--home",
            str(paths.root),
        ]
    )
    stale_digest = cli.main(
        [
            "approve",
            ready.change_set_id,
            "--revision",
            ready.revision_id,
            "--digest",
            "9" * 64,
            "--home",
            str(paths.root),
        ]
    )

    assert (stale_revision, stale_digest) == (1, 1)
    # Each refusal reports its code and the locator the Store attached to it:
    # the revision the caller should have named, then the digest it should
    # have carried. Both are the caller's own next move, not diagnostics.
    codes, payloads = _reported_failures(error_stream.getvalue())
    assert codes == ["stale_revision", "wrong_digest"]
    assert payloads == [
        {"expected_revision_id": ready.revision_id},
        {"digest": ready.digest},
    ]


def test_cli_approve_applies_nothing_when_its_challenge_lease_is_lost(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a CLI apply that commits after the store lost its in-flight lease."""
    from memory.errors import StoreError
    from memory.memories import search_memories
    from memory.ui.owner_presence import (
        ApprovalAttemptStore,
        approve_with_cli_owner_presence,
    )
    from memory.ui.service import OwnerApplicationService

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-lost-lease-store")
    attempts = ApprovalAttemptStore()
    verifier = SyntheticOwnerPresenceAdapter()
    verifier.during = attempts.shutdown

    with pytest.raises(StoreError):
        approve_with_cli_owner_presence(
            paths,
            ready.change_set_id,
            ready.revision_id,
            ready.digest,
            verifier=verifier,
            attempts=attempts,
        )

    assert verifier.calls == 1
    assert search_memories(paths, "glass orchard").items == ()
    service = OwnerApplicationService(paths)
    assert service.list_approvals(None, 50).items == ()
    assert service.list_applications(None, 50).items == ()


def test_cli_lint_guards_reports_candidates_and_standing_violations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch `memory lint guards` dropping either half of its owner-facing report."""
    from synthetic import (
        HEDGE_BODY,
        FakeClock,
        apply_ready,
        capture_text,
        ready_items,
        single_item_edit,
    )

    from memory import cli
    from memory.model import MemoryKind
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / "synthetic-cli-lint-store")
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    clock = FakeClock()
    batch_id, source = capture_text(
        paths,
        name="claim-and-hedge.txt",
        body="The owner reports daily runs.\n" + HEDGE_BODY,
        sensitivity=store_model.Sensitivity.NORMAL,
        clock=clock,
    )
    apply_ready(
        paths,
        ready_items(
            paths,
            batch_id,
            (
                single_item_edit(
                    item_id="itm_claim",
                    source=source,
                    statement="The owner reports daily runs.",
                    excerpt="The owner reports daily runs.",
                ),
                single_item_edit(
                    item_id="itm_hedge",
                    source=source,
                    statement="The daily-runs figure is self-reported and not verified.",
                    excerpt="self-reported and not verified",
                    kind=MemoryKind.INSIGHT,
                ),
            ),
        ),
    )
    capsys.readouterr()

    exit_code = cli.main(["lint", "guards", "--home", str(paths.root), "--json"])

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    payload = json.loads(output.out)
    assert set(payload) == {
        "candidates",
        "standing_violations",
        "truncated_candidate_count",
    }
    assert payload["standing_violations"] == []
    assert payload["truncated_candidate_count"] == 0
    assert len(payload["candidates"]) == 1
    candidate = payload["candidates"][0]
    assert set(candidate) == {
        "governed_lineage_id",
        "governed_statement",
        "guard_lineage_id",
        "guard_statement",
        "rationales",
    }
    assert candidate["guard_statement"] == (
        "The daily-runs figure is self-reported and not verified."
    )
    assert candidate["governed_statement"] == "The owner reports daily runs."
    assert candidate["rationales"] == [
        "guard_vocabulary",
        "same_application",
        "shared_evidence_source",
    ]

    # Same report, read by the human the runbook actually sends here.
    assert cli.main(["lint", "guards", "--home", str(paths.root)]) == 0
    prose = capsys.readouterr()
    assert prose.err == ""
    assert prose.out == (
        "Guard-link candidates: 1\n"
        "  1. guard    The daily-runs figure is self-reported and not verified.\n"
        "     governs  The owner reports daily runs.\n"
        "     because  guard_vocabulary, same_application, shared_evidence_source\n"
        f"     guard lineage    {candidate['guard_lineage_id']}\n"
        f"     governed lineage {candidate['governed_lineage_id']}\n"
        "Standing guard violations: none\n"
    )


def test_cli_lint_guards_says_plainly_when_it_found_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch an empty report reading as a command that failed to print."""
    from memory import cli
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / "synthetic-cli-empty-lint-store")
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    capsys.readouterr()

    assert cli.main(["lint", "guards", "--home", str(paths.root)]) == 0

    output = capsys.readouterr()
    assert output.out == (
        "Guard-link candidates: none\nStanding guard violations: none\n"
    )
    assert output.err == ""


def test_cli_approve_replay_reports_standing_guard_violations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the CLI's idempotent-replay JSON dropping standing_guard_violations."""
    from synthetic import HEDGE_BODY, FakeClock, capture_text, two_source_linked_apply

    from memory import cli
    from memory.reviews import get_change_set
    from memory.runtime import initialize_runtime, resolve_runtime

    paths = resolve_runtime(tmp_path / "synthetic-cli-standing-violation-store")
    initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)
    clock = FakeClock()
    applied = two_source_linked_apply(paths, clock)
    # Same bytes as the guard's own evidence source, recaptured RESTRICTED: this
    # raises the guard's effective sensitivity above its claim's without
    # repointing any head, so replaying the very apply that created the link
    # now finds a standing violation it did not find the first time.
    capture_text(
        paths,
        name="hedge-copy.txt",
        body=HEDGE_BODY,
        sensitivity=store_model.Sensitivity.RESTRICTED,
        clock=clock,
    )
    view = get_change_set(paths, applied.change_set_id)
    assert view.revision_id == applied.revision_id
    capsys.readouterr()

    exit_code = cli.main(
        [
            "approve",
            applied.change_set_id,
            "--revision",
            view.revision_id,
            "--digest",
            view.digest,
            "--home",
            str(paths.root),
            "--json",
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 0
    assert output.err == ""
    payload = json.loads(output.out)
    assert payload["idempotent_replay"] is True
    assert payload["memory_ids"] == list(applied.memory_ids)
    assert len(payload["standing_guard_violations"]) == 1
    violation = payload["standing_guard_violations"][0]
    assert set(violation) == {
        "governed_lineage_id",
        "governed_sensitivity",
        "guard_lineage_id",
        "guard_sensitivity",
    }
    assert violation["guard_sensitivity"] == "restricted"
    assert violation["governed_sensitivity"] == "normal"

    # A guard never outranks its claim, and a violation this apply did not
    # touch is reported rather than repaired -- so the prose must name it too.
    assert (
        cli.main(
            [
                "approve",
                applied.change_set_id,
                "--revision",
                view.revision_id,
                "--digest",
                view.digest,
                "--home",
                str(paths.root),
            ]
        )
        == 0
    )
    prose = capsys.readouterr().out
    assert prose.startswith("Already applied; this run changed nothing.\n")
    assert "  Standing guard violations: 1\n" in prose
    assert (
        f"    guard {violation['guard_lineage_id']} (restricted) outranks "
        f"governed {violation['governed_lineage_id']} (normal)" in prose
    )


def test_cli_approve_json_keeps_stdout_a_single_parseable_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch the review diff leaking into the stream a machine is parsing."""
    from memory import cli
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-json-store")
    monkeypatch.setattr(
        presence,
        "_production_owner_presence_verifier",
        lambda: SyntheticOwnerPresenceAdapter(),
    )
    output_stream = io.StringIO()
    error_stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output_stream)
    monkeypatch.setattr(sys, "stderr", error_stream)

    assert cli.main([*cli_approve_arguments(paths, ready), "--json"]) == 0

    payload = json.loads(output_stream.getvalue())
    assert payload["change_set_id"] == ready.change_set_id
    assert payload["idempotent_replay"] is False
    assert "The glass orchard opens at noon." in error_stream.getvalue()
    assert "The glass orchard opens at noon." not in output_stream.getvalue()


def test_cli_mcp_config_prints_a_json_block_naming_an_explicit_home(
    tmp_path: Path,
) -> None:
    """Catch a printed MCP entry that omits the Store the owner selected."""
    home = tmp_path / "synthetic-config-store"

    result = run_pms("mcp", "config", "--home", str(home), "--format", "json")

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "memory": {
            "args": ["mcp", "--home", str(home)],
            "command": "memory",
            "type": "stdio",
        }
    }


def test_cli_mcp_config_omits_home_for_the_default_runtime_root(
    tmp_path: Path,
) -> None:
    """Catch the common install being told to hard-code a filesystem path."""
    synthetic_owner = tmp_path / "synthetic-owner"

    result = run_pms(
        "mcp",
        "config",
        "--format",
        "json",
        env_overrides={"HOME": str(synthetic_owner)},
    )

    assert result.returncode == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["memory"]["args"] == ["mcp"]
    assert payload["memory"]["command"] == "memory"
    assert str(synthetic_owner) not in result.stdout
    assert "--home" not in result.stdout


def test_cli_mcp_config_carries_the_trust_elicitation_opt_in(
    tmp_path: Path,
) -> None:
    """Catch a printed entry hiding the owner's elicitation-trust choice."""
    home = tmp_path / "synthetic-config-store"

    opted_in = run_pms(
        "mcp",
        "config",
        "--trust-elicitation",
        "--home",
        str(home),
        "--format",
        "json",
    )
    parent_order = run_pms(
        "mcp",
        "--trust-elicitation",
        "--home",
        str(home),
        "config",
        "--format",
        "json",
    )

    assert opted_in.returncode == 0
    assert parent_order.returncode == 0
    for result in (opted_in, parent_order):
        payload = json.loads(result.stdout)
        assert payload["memory"]["args"] == [
            "mcp",
            "--home",
            str(home),
            "--trust-elicitation",
        ]


def test_cli_mcp_config_prints_an_equivalent_toml_block(tmp_path: Path) -> None:
    """Catch the two printed formats describing different servers."""
    import tomllib

    home = tmp_path / "synthetic-config-store"

    toml_result = run_pms("mcp", "config", "--home", str(home), "--format", "toml")
    json_result = run_pms("mcp", "config", "--home", str(home), "--format", "json")

    assert toml_result.returncode == 0
    assert toml_result.stderr == ""
    entry = json.loads(json_result.stdout)["memory"]
    assert tomllib.loads(toml_result.stdout) == {
        "memory": {"args": entry["args"], "command": entry["command"]}
    }


def test_cli_mcp_config_escapes_an_awkward_home_in_both_formats(
    tmp_path: Path,
) -> None:
    """Catch a hand-written TOML string breaking on a quotable Store path."""
    import tomllib

    home = tmp_path / 'synthetic "quoted" \\ store'
    expected = ["mcp", "--home", str(home)]

    toml_result = run_pms("mcp", "config", "--home", str(home), "--format", "toml")
    json_result = run_pms("mcp", "config", "--home", str(home), "--format", "json")

    assert toml_result.returncode == 0
    assert json_result.returncode == 0
    assert tomllib.loads(toml_result.stdout)["memory"]["args"] == expected
    assert json.loads(json_result.stdout)["memory"]["args"] == expected


def test_cli_mcp_config_needs_no_initialized_store_and_names_no_client(
    tmp_path: Path,
) -> None:
    """Catch a config printer that unlocks a Store or hard-codes one client.

    The key or table path a client files its servers under is that client's
    own schema: `tests/test_ui_packaging.py` already forbids the shipped wheel
    from carrying the one a launcher writes. The Store prints one entry, named
    for the server, and the setup guide says where it goes.
    """
    home = tmp_path / "never-initialized-store"
    containers = ("mcpServers", "mcp_servers", "servers", "context_servers")

    for output_format in ("json", "toml"):
        result = run_pms(
            "mcp",
            "config",
            "--home",
            str(home),
            "--format",
            output_format,
        )

        assert result.returncode == 0, result.stderr
        folded = result.stdout.casefold()
        for vendor in ("anthropic", "claude", "codex", "openai"):
            assert vendor not in folded, output_format
        for container in containers:
            assert container not in result.stdout, output_format
    assert not home.exists()


def test_cli_mcp_config_reads_the_same_home_before_or_after_the_subcommand(
    tmp_path: Path,
) -> None:
    """Catch a subcommand default silently discarding the selected Store."""
    home = tmp_path / "synthetic-config-store"

    before = run_pms("mcp", "--home", str(home), "config", "--format", "json")
    after = run_pms("mcp", "config", "--home", str(home), "--format", "json")

    assert before.returncode == 0, before.stderr
    assert after.returncode == 0, after.stderr
    assert json.loads(before.stdout)["memory"]["args"] == ["mcp", "--home", str(home)]
    assert before.stdout == after.stdout


def test_cli_mcp_config_rejects_an_unknown_format(tmp_path: Path) -> None:
    """Catch an unrecognized format silently falling back to another shape."""
    result = run_pms(
        "mcp",
        "config",
        "--home",
        str(tmp_path / "synthetic-config-store"),
        "--format",
        "yaml",
    )

    assert result.returncode == 2
    assert result.stdout == ""


def test_cli_prints_the_locators_a_refusal_carries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a CLI that drops the one field naming what to fix.

    `error.details` is where the Store puts the expected revision, the digest,
    the unaccounted sources, and the approval handoff. Printing only the code
    turns an addressable refusal into a guess, and the owner has no other way
    to read it -- there is no verbose flag and no log.
    """
    from memory import cli
    from memory.ui import owner_presence as presence

    paths, ready = prepared_cli_store(tmp_path, "synthetic-cli-details-store")

    def refuse(*_args: object, **_kwargs: object) -> object:
        pytest.fail("a stale CLI approval reached owner presence")

    monkeypatch.setattr(presence, "_production_owner_presence_verifier", refuse)
    error_stream = io.StringIO()
    out_stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", error_stream)
    monkeypatch.setattr(sys, "stdout", out_stream)

    code = cli.main(
        [
            "approve",
            ready.change_set_id,
            "--revision",
            "csr_" + "9" * 32,
            "--digest",
            "9" * 64,
            "--home",
            str(paths.root),
        ]
    )

    printed = error_stream.getvalue()
    assert code == 1
    assert printed.startswith("memory: stale_revision\n")
    details = json.loads(printed.split("\n", 1)[1])
    assert details == {"expected_revision_id": ready.revision_id}
    # stdout stays machine-clean: details are diagnostics, not output.
    assert out_stream.getvalue() == ""


def test_cli_status_answers_the_freshness_question_without_the_owner_ui(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a terminal owner with no way to read Store freshness at all.

    The UI-down case is exactly when this is needed, so it reuses the same
    record `store.status` serves rather than a second query the two could
    disagree about.
    """
    cli = importlib.import_module("memory.cli")
    memory_package = importlib.import_module("memory")
    store_home = tmp_path / "status-store"

    assert cli.main(["init", "--home", str(store_home)]) == 0
    capsys.readouterr()

    assert cli.main(["status", "--home", str(store_home), "--json"]) == 0
    output = capsys.readouterr()
    payload = json.loads(output.out)

    assert payload["product"] == "memory"
    assert payload["product_version"] == memory_package.__version__
    assert payload["pending_review_count"] == 0
    assert payload["reindex_required"] is False
    assert payload["source_count"] == 0
    assert str(store_home) not in output.out
    assert output.err == ""
    assert len(synthetic_keychain) == 1


def test_cli_reviews_lists_the_pending_backlog_with_approvable_coordinates(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a draft review a terminal owner cannot discover or approve."""
    cli = importlib.import_module("memory.cli")
    runtime = importlib.import_module("memory.runtime")
    test_mcp = importlib.import_module("test_mcp")
    paths = runtime.resolve_runtime(tmp_path / "reviews-store")
    runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert cli.main(["reviews", "--home", str(paths.root), "--json"]) == 0
    empty = json.loads(capsys.readouterr().out)

    ready = test_mcp.ready_review(paths)

    assert cli.main(["reviews", "--home", str(paths.root), "--json"]) == 0
    output = capsys.readouterr()
    payload = json.loads(output.out)

    # `listed_review_count`, not `pending_review_count`: this is one bounded
    # page, and `memory status` carries that other key for the Store's true
    # draft count. Two commands answering the same key with different numbers
    # would be worse than one naming what it actually counted.
    assert empty == {
        "has_more": False,
        "listed_review_count": 0,
        "reviews": [],
    }
    assert payload["listed_review_count"] == 1
    assert payload["has_more"] is False
    # Exactly the triple `memory approve` needs, so discovering a review and
    # approving it are one hop apart rather than a trip through the browser.
    assert payload["reviews"][0]["change_set_id"] == ready.change_set_id
    assert payload["reviews"][0]["revision_id"] == ready.revision_id
    assert payload["reviews"][0]["digest"] == ready.digest
    assert payload["reviews"][0]["item_count"] == 1
    assert "The copper gallery" not in output.out
    assert output.err == ""
    assert len(synthetic_keychain) == 1


def test_cli_recover_runs_reconciliation_outside_the_owner_ui(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch exact-capture recovery reachable only by starting the owner UI.

    Reconciliation runs at owner-UI startup and nowhere else, so an owner
    working entirely over MCP never triggers it and an interrupted correction
    capture stays staged indefinitely.
    """
    cli = importlib.import_module("memory.cli")
    runtime = importlib.import_module("memory.runtime")
    paths = runtime.resolve_runtime(tmp_path / "recover-store")
    runtime.initialize_runtime(paths, mode=store_model.RuntimeMode.PERSONAL)

    assert cli.main(["recover", "--home", str(paths.root)]) == 0
    output = capsys.readouterr()

    assert json.loads(output.out) == {
        "issues": [],
        "issues_truncated": False,
        "recovered": [],
    }
    assert output.err == ""
    assert len(synthetic_keychain) == 1


def test_cli_recover_reports_a_resumed_capture_and_a_quarantined_artifact() -> None:
    """Catch the recovery report losing what it resumed or what it quarantined.

    The shapes are exercised directly: reaching them through the filesystem
    means crashing a real capture at a checkpoint, which the Inbox suites
    already own, and this pins only what the terminal owner is shown.
    """
    cli = importlib.import_module("memory.cli")

    rendered = json.loads(
        cli._recovery_json(
            (
                store_model.CapturedCorrection(
                    capture_request_id="cap_" + "0" * 32,
                    batch_id="bat_synthetic",
                    source_id="src_synthetic",
                    lineage_id="lin_synthetic",
                    expected_head_id="mem_synthetic",
                    captured_at=1_850_000_000,
                ),
            ),
            store_model.Page(
                items=(
                    store_model.CaptureRecoveryIssue(
                        issue_id="iss_synthetic",
                        code="malformed_manifest",
                        detected_at_ns=1_850_000_000_000_000_000,
                    ),
                ),
                next_cursor="cur_synthetic",
                has_more=True,
            ),
        )
    )

    assert rendered == {
        "issues": [
            {
                "code": "malformed_manifest",
                "detected_at_ns": 1_850_000_000_000_000_000,
                "issue_id": "iss_synthetic",
            }
        ],
        "issues_truncated": True,
        "recovered": [
            {
                "batch_id": "bat_synthetic",
                "expected_head_id": "mem_synthetic",
                "lineage_id": "lin_synthetic",
                "source_id": "src_synthetic",
            }
        ],
    }
    # The capture request id is a private staging handle, not something a
    # recovery report owes the owner, so it stays off this stream.
    assert "cap_" not in json.dumps(rendered)


def test_ui_help_offers_no_launch_flag_the_owner_cannot_use() -> None:
    """Catch the harness launch pair being advertised as owner-facing options.

    `--no-open` and `--launch-fd` are one internal pair: neither works without
    the other, and the descriptor receives a one-use bootstrap capability. An
    owner who finds `--no-open` in `--help` finds a flag that can only fail.
    """
    ui_help = run_pms("ui", "--help")
    approve_help = run_pms("approve", "--help")

    assert ui_help.returncode == 0
    assert "--no-open" not in ui_help.stdout
    assert "--launch-fd" not in ui_help.stdout
    assert "--home" in ui_help.stdout
    # The suppression is targeted, not a blanket one on every subparser.
    assert "--revision" in approve_help.stdout
