from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from synthetic import FakeClock

from memory import cli, model, runtime
from memory.database import open_database
from memory.keys import load_master_key
from memory.runtime import (
    default_root,
    initialize_runtime,
    load_runtime_identity,
    resolve_runtime,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_memory(
    *args: str,
    env_overrides: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(env_overrides or {})
    return subprocess.run(
        [sys.executable, "-m", "memory.cli", *args],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )


def identity_payload(
    root: Path,
    *,
    runtime_mode: object = "personal",
    inbox_path: object | None = None,
) -> dict[str, object]:
    return {
        "product": "memory",
        "schema_lineage": "memory-store-v1",
        "schema_version": 1,
        "store_id": "1" * 32,
        "runtime_mode": runtime_mode,
        "inbox_path": str(root / "inbox") if inbox_path is None else inbox_path,
    }


def test_init_uses_the_default_home_when_none_is_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "owner"))

    assert cli.main(["init"]) == 0

    paths = resolve_runtime(None)
    assert paths.root == (
        tmp_path / "owner" / "Library" / "Application Support" / "Memory"
    )
    assert stat.S_IMODE(paths.root.stat().st_mode) == 0o700
    identity = load_runtime_identity(paths)
    assert identity.runtime_mode is model.RuntimeMode.PERSONAL
    assert identity.inbox_path == str(paths.root / "inbox")
    assert capsys.readouterr().out == f"Inbox: {paths.inbox}\n"
    assert runtime.authorize_runtime_use(paths) == identity
    assert len(synthetic_keychain) == 1


def test_dot_segment_home_normalizes_the_default_root_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    synthetic_parent = tmp_path / "synthetic-parent"
    synthetic_owner = tmp_path / "synthetic-owner"
    monkeypatch.setenv("HOME", str(synthetic_parent / ".." / "synthetic-owner"))
    expected = synthetic_owner / "Library" / "Application Support" / "Memory"

    assert default_root() == expected
    assert resolve_runtime(None).root == expected
    assert not synthetic_parent.exists()
    assert not synthetic_owner.exists()
    assert synthetic_keychain == {}


@pytest.mark.parametrize("output_format", ("json", "toml"))
def test_dot_segment_default_home_mcp_config_remains_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
    output_format: str,
) -> None:
    import tomllib

    synthetic_parent = tmp_path / "synthetic-parent"
    synthetic_owner = tmp_path / "synthetic-owner"
    monkeypatch.setenv("HOME", str(synthetic_parent / ".." / "synthetic-owner"))

    assert cli.main(["mcp", "config", "--format", output_format]) == 0

    output = capsys.readouterr()
    payload = (
        json.loads(output.out) if output_format == "json" else tomllib.loads(output.out)
    )
    assert payload["memory"]["args"] == ["mcp"]
    assert output.err == ""
    assert not synthetic_parent.exists()
    assert not synthetic_owner.exists()
    assert synthetic_keychain == {}


def test_dot_segment_default_home_approval_handoff_remains_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory.mcp_server import _approval_handoff

    synthetic_parent = tmp_path / "synthetic-parent"
    synthetic_owner = tmp_path / "synthetic-owner"
    monkeypatch.setenv("HOME", str(synthetic_parent / ".." / "synthetic-owner"))
    handoff = _approval_handoff(
        resolve_runtime(None),
        "chg_synthetic",
        "csr_synthetic",
        "0" * 64,
    )

    assert "--home" not in str(handoff["command"])
    assert handoff["review_path"] == "Run `memory ui`, then open Pending Reviews."
    assert not synthetic_parent.exists()
    assert not synthetic_owner.exists()
    assert synthetic_keychain == {}


def test_relative_cli_home_initializes_reopens_and_captures_at_one_absolute_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch a relative spelling stranding identity or Keychain state."""
    from memory.inbox import scan_inbox

    workspace = tmp_path / "synthetic-workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    selected = Path("unused-segment") / ".." / "synthetic-relative-store"
    expected_root = workspace / "synthetic-relative-store"

    assert cli.main(["init", "--home", os.fspath(selected)]) == 0

    paths = resolve_runtime(selected)
    assert paths.root == expected_root
    assert all(
        path.is_absolute()
        for path in (
            paths.root,
            paths.database,
            paths.inbox,
            paths.inbox_claims,
            paths.inbox_staging,
            paths.identity,
            paths.writer_lock,
            paths.ui_session_lock,
        )
    )
    assert capsys.readouterr().out == f"Inbox: {expected_root / 'inbox'}\n"
    identity = load_runtime_identity(paths)
    assert identity.inbox_path == str(expected_root / "inbox")

    reopened = resolve_runtime(Path("synthetic-relative-store"))
    assert initialize_runtime(reopened, mode=model.RuntimeMode.PERSONAL) == identity
    assert runtime.authorize_runtime_use(reopened) == identity
    (reopened.inbox / "synthetic-courtyard-note.md").write_text(
        "Synthetic courtyard note: the blue lantern is stored indoors.\n",
        encoding="utf-8",
    )
    batch = scan_inbox(reopened, clock=FakeClock())
    assert batch.source_count == 1
    assert batch.source_ids
    assert len(synthetic_keychain) == 1


@pytest.mark.parametrize(
    "inbox_alias",
    ("root", "claims", "staging", "private_descendant"),
)
def test_relative_home_refuses_exact_spelling_private_inbox_alias_before_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    inbox_alias: str,
) -> None:
    """Catch relative/absolute comparison admitting one exact lexical alias."""
    from memory.errors import InitializationError

    workspace = tmp_path / "synthetic-workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    selected = Path("synthetic-relative-store")
    absolute_root = workspace / selected
    invalid_inbox = {
        "root": absolute_root,
        "claims": absolute_root / "inbox-claims",
        "staging": absolute_root / "inbox-staging",
        "private_descendant": absolute_root / "synthetic-private-child",
    }[inbox_alias]

    with pytest.raises(InitializationError):
        initialize_runtime(
            resolve_runtime(selected),
            mode=model.RuntimeMode.PERSONAL,
            inbox=invalid_inbox,
        )

    assert not absolute_root.exists()
    assert synthetic_keychain == {}


def test_resolve_runtime_lexically_normalizes_dot_and_parent_segments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "synthetic-workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    assert resolve_runtime(Path(".")).root == workspace
    assert resolve_runtime(Path("nested") / ".." / "store").root == workspace / "store"
    assert (
        resolve_runtime(Path("nested") / ".." / ".." / "sibling-store").root
        == tmp_path / "sibling-store"
    )


def test_resolve_runtime_keeps_a_symlink_ancestor_lexical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not turn lexical normalization into deferred symlink resolution."""
    workspace = tmp_path / "synthetic-workspace"
    real_parent = tmp_path / "synthetic-real-parent"
    workspace.mkdir()
    real_parent.mkdir()
    alias = workspace / "synthetic-alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.chdir(workspace)

    paths = resolve_runtime(Path("synthetic-alias") / "nested" / ".." / "store")

    assert paths.root == alias / "store"
    assert paths.root != real_parent / "store"
    assert not paths.root.exists()


def test_runtime_identity_and_database_bind_the_personal_mode(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    paths = resolve_runtime(tmp_path / "store")
    identity = initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)

    assert identity.runtime_mode is model.RuntimeMode.PERSONAL
    assert load_runtime_identity(paths) == identity
    assert json.loads(paths.identity.read_text(encoding="utf-8")) == {
        "product": "memory",
        "runtime_mode": "personal",
        "schema_lineage": "memory-store-v1",
        "schema_version": 1,
        "store_id": identity.store_id,
        "inbox_path": str(paths.root / "inbox"),
    }
    with open_database(
        paths,
        load_master_key(identity),
        read_only=True,
    ) as connection:
        row = connection.execute(
            "SELECT runtime_mode FROM store_meta WHERE singleton = 1"
        ).fetchone()
    assert row == ("personal",)
    assert runtime.authorize_runtime_use(paths) == identity
    assert len(synthetic_keychain) == 1


def test_commands_on_an_uninitialized_home_fail_without_side_effects(
    tmp_path: Path,
) -> None:
    for arguments in (
        ("mcp",),
        ("paths", "--json"),
        (
            "approve",
            "chg_synthetic",
            "--revision",
            "csr_synthetic",
            "--digest",
            "0" * 64,
        ),
    ):
        result = run_memory(
            *arguments,
            env_overrides={"HOME": str(tmp_path / "owner")},
        )

        assert result.returncode == 1
        assert result.stderr == "memory: wrong_product\n"
        assert result.stdout == ""
        assert not (tmp_path / "owner").exists()


@pytest.mark.parametrize(
    "mutation",
    (
        "drop_mode",
        "unknown_mode",
        "null_mode",
        "drop_inbox",
        "relative_inbox",
        "inbox_inside_root",
        "inbox_contains_root",
    ),
)
def test_invalid_runtime_identity_fails_without_side_effects(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    mutation: str,
) -> None:
    from memory.errors import InvalidRuntimeError

    root = tmp_path / f"invalid-{mutation}"
    payload = identity_payload(root)
    if mutation == "drop_mode":
        del payload["runtime_mode"]
    elif mutation == "unknown_mode":
        payload["runtime_mode"] = "unknown"
    elif mutation == "null_mode":
        payload["runtime_mode"] = None
    elif mutation == "drop_inbox":
        del payload["inbox_path"]
    elif mutation == "relative_inbox":
        payload["inbox_path"] = "relative/inbox"
    elif mutation == "inbox_inside_root":
        payload["inbox_path"] = str(root / "inbox-staging")
    elif mutation == "inbox_contains_root":
        payload["inbox_path"] = str(root.parent)
    paths = resolve_runtime(root)
    paths.root.mkdir(mode=0o700)
    paths.identity.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    paths.identity.chmod(0o600)
    before = paths.identity.read_bytes()

    with pytest.raises(InvalidRuntimeError):
        runtime.authorize_runtime_use(resolve_runtime(root))

    assert paths.identity.read_bytes() == before
    assert {entry.name for entry in paths.root.iterdir()} == {"runtime.json"}
    assert not paths.database.exists()
    assert not (paths.root / "inbox").exists()
    assert not paths.inbox_claims.exists()
    assert not paths.inbox_staging.exists()
    assert synthetic_keychain == {}


def test_environment_failures_report_store_unavailable_not_wrong_product(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch a filesystem failure being diagnosed as a foreign product.

    `wrong_product` is chartered for a database that is not a Memory store
    and is never repaired; `store_unavailable` (v1.7.0) is chartered for the
    environment failing underneath a real one -- an evicted placeholder, an
    I/O error, a permission change. Sending the terminal diagnosis for a
    permission slip tells the owner their own Store is not a Store. An
    absent identity stays the uninitialized-home diagnosis it always was.
    """
    from memory.errors import InvalidRuntimeError, StoreUnavailableError

    root = tmp_path / "environment-store"
    paths = resolve_runtime(root)
    paths.root.mkdir(mode=0o700)
    paths.identity.write_text(
        json.dumps(identity_payload(root)) + "\n",
        encoding="utf-8",
    )
    paths.identity.chmod(0o600)

    paths.identity.chmod(0o000)
    try:
        with pytest.raises(StoreUnavailableError) as unreadable:
            runtime.load_runtime_identity(resolve_runtime(root))
        assert unreadable.value.code == "store_unavailable"
    finally:
        paths.identity.chmod(0o600)

    paths.identity.unlink()
    with pytest.raises(InvalidRuntimeError) as missing_identity:
        runtime.load_runtime_identity(resolve_runtime(root))
    assert missing_identity.value.code == "wrong_product"
    assert synthetic_keychain == {}


def test_non_enum_initialization_mode_is_refused_before_artifacts(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory.errors import InitializationError

    paths = resolve_runtime(tmp_path / "string-mode")
    with pytest.raises(InitializationError):
        initialize_runtime(paths, mode="personal")  # type: ignore[arg-type]
    assert not paths.root.exists()
    assert synthetic_keychain == {}


def test_database_identity_mismatch_fails_without_repair_or_replacement(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory.errors import WrongProductError

    paths = resolve_runtime(tmp_path / "mismatch")
    identity = initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    key = load_master_key(identity)
    connection = open_database(paths, key, read_only=False)
    try:
        connection.execute(
            "UPDATE store_meta SET store_id = ?",
            ("f" * 32,),
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    finally:
        connection.close()
    identity_before = paths.identity.read_bytes()
    entries_before = {entry.name for entry in paths.root.iterdir()}
    keys_before = synthetic_keychain.copy()

    with pytest.raises(WrongProductError):
        initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)

    assert paths.identity.read_bytes() == identity_before
    assert {entry.name for entry in paths.root.iterdir()} == entries_before
    assert synthetic_keychain == keys_before


def test_init_configures_and_keeps_an_external_inbox(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "store"
    external = tmp_path / "Documents" / "Inbox"
    external.parent.mkdir()
    external.mkdir()
    waiting = external / "phone-note.md"
    waiting.write_text("synthetic waiting note\n", encoding="utf-8")

    assert cli.main(["init", "--home", str(home), "--inbox", str(external)]) == 0

    assert capsys.readouterr().out == f"Inbox: {external}\n"
    paths = resolve_runtime(home)
    assert paths.inbox == external
    assert stat.S_IMODE(external.stat().st_mode) == 0o700
    assert waiting.read_text(encoding="utf-8") == "synthetic waiting note\n"
    identity = load_runtime_identity(paths)
    assert identity.inbox_path == str(external)
    assert not (paths.root / "inbox").exists()
    assert runtime.authorize_runtime_use(paths) == identity

    assert cli.main(["init", "--home", str(home), "--inbox", str(external)]) == 0
    assert cli.main(["init", "--home", str(home)]) == 0

    payload = json.loads(cli_paths_json(home))
    assert payload["inbox"] == str(external)


def cli_paths_json(home: Path) -> str:
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert cli.main(["paths", "--home", str(home), "--json"]) == 0
    return buffer.getvalue()


def test_init_creates_an_absent_external_inbox_directory(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    home = tmp_path / "store"
    external = tmp_path / "Documents" / "Inbox"
    external.parent.mkdir()

    assert cli.main(["init", "--home", str(home), "--inbox", str(external)]) == 0

    assert external.is_dir()
    assert stat.S_IMODE(external.stat().st_mode) == 0o700


def test_init_refuses_a_conflicting_external_inbox_reconfiguration(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory.errors import InitializationError

    home = tmp_path / "store"
    first = tmp_path / "first-inbox"
    second = tmp_path / "second-inbox"
    paths = resolve_runtime(home)
    initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL, inbox=first)
    identity_before = resolve_runtime(home).identity.read_bytes()

    with pytest.raises(InitializationError):
        initialize_runtime(
            resolve_runtime(home),
            mode=model.RuntimeMode.PERSONAL,
            inbox=second,
        )

    assert resolve_runtime(home).identity.read_bytes() == identity_before
    assert not second.exists()


def test_init_refuses_an_inbox_inside_or_containing_the_store_home(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory.errors import InitializationError

    home = tmp_path / "store"
    for invalid in (home / "inbox-staging", home.parent):
        with pytest.raises(InitializationError):
            initialize_runtime(
                resolve_runtime(home),
                mode=model.RuntimeMode.PERSONAL,
                inbox=invalid,
            )
        assert not home.exists()
    assert synthetic_keychain == {}


def test_private_staging_is_created_repaired_and_no_ui_lock_file_is_made(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    paths = resolve_runtime(tmp_path / "staging")
    identity = initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)

    assert paths.inbox_staging.is_dir()
    assert stat.S_IMODE(paths.inbox_staging.stat().st_mode) == 0o700
    assert paths.ui_session_lock == paths.root / ".ui-session.lock"
    assert not paths.ui_session_lock.exists()
    paths.inbox_staging.chmod(0o755)

    assert initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL) == identity
    assert stat.S_IMODE(paths.inbox_staging.stat().st_mode) == 0o700
    assert not paths.ui_session_lock.exists()
    assert len(synthetic_keychain) == 1


@pytest.mark.parametrize("replacement", ("file", "symlink"))
def test_staging_refuses_non_directory_or_symlink_without_mutation(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    replacement: str,
) -> None:
    from memory.errors import InitializationError

    paths = resolve_runtime(tmp_path / f"staging-{replacement}")
    identity = initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    paths.inbox_staging.rmdir()
    if replacement == "file":
        paths.inbox_staging.write_text("synthetic marker\n", encoding="utf-8")
    else:
        paths.inbox_staging.symlink_to(paths.inbox)
    marker = paths.inbox_staging.lstat()
    identity_before = paths.identity.read_bytes()
    keys_before = synthetic_keychain.copy()

    with pytest.raises(InitializationError):
        initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)

    assert paths.inbox_staging.lstat() == marker
    assert paths.identity.read_bytes() == identity_before
    assert load_runtime_identity(paths) == identity
    assert synthetic_keychain == keys_before


def test_exact_capture_recovery_preserves_the_runtime_identity(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch launch recovery changing runtime authority or schema identity."""
    from memory.inbox import (
        recover_exact_staged_entries,
        stage_exact_private_entry,
    )

    paths = resolve_runtime(tmp_path / "synthetic-recovery")
    identity = initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    body = b"Synthetic exact runtime-mode recovery.\n"
    metadata = model.ExactCaptureMetadata(
        capture_request_id="cap_" + "1" * 32,
        batch_id="bat_" + "2" * 32,
        captured_at=2_020_000_000,
        target_lineage_id="lin_" + "3" * 32,
        expected_head_id="mem_" + "4" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=model.SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=model.Authorship.OWNER,
        sensitivity=model.Sensitivity.RESTRICTED,
    )
    stage_exact_private_entry(
        paths,
        display_name="synthetic-runtime-recovery.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )

    recovered = recover_exact_staged_entries(paths)
    assert len(recovered) == 1
    assert recovered[0].capture_request_id == metadata.capture_request_id
    assert recovered[0].batch_id == metadata.batch_id
    assert load_runtime_identity(paths) == identity
    assert identity.runtime_mode is model.RuntimeMode.PERSONAL
    with open_database(paths, load_master_key(identity), read_only=True) as connection:
        assert connection.execute(
            "SELECT runtime_mode FROM store_meta WHERE singleton = 1"
        ).fetchone() == ("personal",)
    assert len(synthetic_keychain) == 1


def test_authorize_on_an_uninitialized_default_home_creates_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from memory.errors import InvalidRuntimeError

    monkeypatch.setenv("HOME", str(tmp_path / "owner"))
    paths = resolve_runtime(None)
    with pytest.raises(InvalidRuntimeError):
        runtime.authorize_runtime_use(paths)
    assert not paths.root.exists()
