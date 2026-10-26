"""Synthetic topology and real process-death initialization regressions."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from memory.errors import InitializationError, InvalidRuntimeError, WrongProductError
from memory.model import RuntimeMode
from memory.runtime import initialize_runtime, load_runtime_identity, resolve_runtime

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("selected", ["ancestor", "leaf"])
def test_initialization_refuses_symlink_ancestor_without_touching_target(
    tmp_path: Path,
    synthetic_keychain: dict[tuple[str, str], str],
    selected: str,
) -> None:
    target = tmp_path / "synthetic-target"
    target.mkdir(mode=0o751)
    alias = tmp_path / "synthetic-alias"
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(InitializationError):
        initialize_runtime(
            resolve_runtime(alias / "store" if selected == "ancestor" else alias),
            mode=RuntimeMode.PERSONAL,
        )

    assert list(target.iterdir()) == []
    assert target.stat().st_mode & 0o777 == 0o751
    assert synthetic_keychain == {}


_INIT_CHILD = r"""
import os
import re
import sys
from pathlib import Path
import keyring
from memory import initialization, keys, runtime
from memory.model import RuntimeMode
root, accounts, crash = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
accounts.mkdir(exist_ok=True)
backend = type("Keyring", (), {})()
type(backend).__module__ = "keyring.backends.macOS"
keyring.get_keyring = lambda: backend

def account_path(service, account):
    assert service == "memory" and re.fullmatch(r"[0-9a-f]{32}", account)
    return accounts / account

def get(service, account):
    path = account_path(service, account)
    return path.read_text() if path.exists() else None

def put(service, account, value):
    path = account_path(service, account)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(accounts, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    if crash == "after_key":
        os._exit(79)
keyring.get_password = get
keyring.set_password = put
keys._store_master_key_exclusive = lambda identity, encoded: put("memory", identity.store_id, encoded)
keyring.delete_password = lambda service, account: account_path(service, account).unlink()
original = keys.create_master_key

def create(identity, *args, **kwargs):
    if crash == "before_key":
        os._exit(79)
    return original(identity, *args, **kwargs)
keys.create_master_key = create

def checkpoint(name):
    if crash == name:
        os._exit(79)
    if crash == "hold_key" and name == "key_durable":
        print("synthetic-writer-held", flush=True)
        sys.stdin.readline()
initialization._init_checkpoint = checkpoint
if crash in {"torn_ready_append", "torn_initial_intent"}:
    original_write = initialization._write_all
    def torn_write(descriptor, value):
        target = b'"phase":"ready"' if crash == "torn_ready_append" else b'"phase":"prepared"'
        if target in value:
            os.write(descriptor, value[:len(value)//2])
            os.fsync(descriptor)
            os._exit(79)
        original_write(descriptor, value)
    initialization._write_all = torn_write
identity = runtime.initialize_runtime(runtime.resolve_runtime(root), mode=RuntimeMode.PERSONAL)
assert runtime.authorize_runtime_use(runtime.resolve_runtime(root)) == identity
print("synthetic-initialization-complete")
"""


def run_initialization_child(
    root: Path, accounts: Path, crash: str = "none"
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-c", _INIT_CHILD, str(root), str(accounts), crash],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


POST_INTENT_CHECKPOINTS = (
    "intent_durable",
    "key_durable",
    "database_started",
    "schema_created",
    "wal_configured",
    "database_ready",
    "database_published",
    "identity_published",
    "staging_removed",
    "intent_removed",
)


@pytest.mark.parametrize(
    "crash", ["before_key", "after_key", "torn_ready_append", *POST_INTENT_CHECKPOINTS]
)
def test_new_initialization_recovers_after_process_death(
    tmp_path: Path, crash: str
) -> None:
    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    interrupted = run_initialization_child(root, accounts, crash)
    assert interrupted.returncode == 79, interrupted.stderr
    resumed = run_initialization_child(root, accounts)
    assert resumed.returncode == 0, resumed.stderr
    assert resumed.stdout == "synthetic-initialization-complete\n"
    assert len(list(accounts.iterdir())) == 1
    assert {entry.name for entry in root.iterdir()} == {
        "runtime.json",
        "store.sqlite3",
        "store.sqlite3-shm",
        "store.sqlite3-wal",
        ".writer.lock",
        "inbox",
        "inbox-claims",
        "inbox-staging",
    }


@pytest.mark.parametrize("crash", ["prepared_files", "torn_initial_intent"])
def test_pre_intent_process_death_refuses_with_no_synthetic_key(
    tmp_path: Path, crash: str
) -> None:
    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    interrupted = run_initialization_child(root, accounts, crash)
    assert interrupted.returncode == 79, interrupted.stderr
    before = {entry.name: entry.stat().st_ino for entry in root.iterdir()}
    resumed = run_initialization_child(root, accounts)
    assert resumed.returncode == 1
    assert (
        "incomplete preparation requires recovery" in resumed.stderr
        or "intent is incomplete; preserve artifacts" in resumed.stderr
    )
    assert list(accounts.iterdir()) == []
    assert {entry.name: entry.stat().st_ino for entry in root.iterdir()} == before


def test_initialization_init_checkpoint_inventory_is_exercised() -> None:
    import ast

    from memory import initialization

    tree = ast.parse(Path(initialization.__file__).read_text())
    found = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_init_checkpoint"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert found == {*POST_INTENT_CHECKPOINTS, "prepared_files"}


def test_existing_store_missing_database_never_reinitializes(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str]
) -> None:
    paths = resolve_runtime(tmp_path / "synthetic-store")
    initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    paths.database.unlink()
    before = {entry.name: entry.stat().st_ino for entry in paths.root.iterdir()}
    keys = synthetic_keychain.copy()
    with pytest.raises(WrongProductError):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert {entry.name: entry.stat().st_ino for entry in paths.root.iterdir()} == before
    assert synthetic_keychain == keys


@pytest.mark.parametrize(
    "leaf", ["root", "inbox", "inbox-claims", "inbox-staging", "ancestor"]
)
def test_directory_replacement_after_intent_never_touches_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    leaf: str,
) -> None:
    from memory import initialization

    parent = tmp_path / "synthetic-parent"
    parent.mkdir()
    paths = resolve_runtime(parent / "store")
    replacement = (
        parent
        if leaf == "ancestor"
        else paths.root
        if leaf == "root"
        else paths.root / leaf
    )
    saved = tmp_path / "synthetic-retained-original"

    def substitute(name: str) -> None:
        if name == "intent_durable":
            replacement.rename(saved)
            replacement.mkdir(mode=0o751)
            (replacement / "synthetic-marker").write_bytes(b"untouched\n")

    monkeypatch.setattr(initialization, "_init_checkpoint", substitute)
    with pytest.raises(InitializationError, match="authority changed"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert list(replacement.iterdir()) == [replacement / "synthetic-marker"]
    assert (replacement / "synthetic-marker").read_bytes() == b"untouched\n"
    assert replacement.stat().st_mode & 0o777 == 0o751
    assert synthetic_keychain == {}


@pytest.mark.parametrize("where", ["root", "inbox", "claims", "staging"])
def test_external_inbox_alias_to_private_layout_is_refused(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str], where: str
) -> None:
    parent = tmp_path / "synthetic-parent"
    parent.mkdir()
    alias = tmp_path / "synthetic-alias"
    alias.symlink_to(parent, target_is_directory=True)
    paths = resolve_runtime(parent / "store")
    relative = {
        "root": Path("store"),
        "inbox": Path("store/inbox"),
        "claims": Path("store/inbox-claims"),
        "staging": Path("store/inbox-staging"),
    }[where]
    with pytest.raises(InitializationError):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL, inbox=alias / relative)
    assert not paths.identity.exists()
    assert synthetic_keychain == {}


def test_pending_intent_refuses_ordinary_open_before_keychain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization, keys

    paths = resolve_runtime(tmp_path / "synthetic-store")

    def pause(name: str) -> None:
        if name == "intent_durable":
            raise RuntimeError("synthetic interruption")

    monkeypatch.setattr(initialization, "_init_checkpoint", pause)
    with pytest.raises(RuntimeError):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)

    def forbidden(identity: object) -> bytes:
        pytest.fail("pending init reached Keychain")

    monkeypatch.setattr(keys, "load_master_key", forbidden)
    with pytest.raises(InvalidRuntimeError):
        load_runtime_identity(paths)
    assert synthetic_keychain == {}


@pytest.mark.parametrize("artifact", ["database", "identity", "intent"])
def test_recovery_refuses_replaced_artifact_without_modification(
    tmp_path: Path, artifact: str
) -> None:
    from memory import initialization

    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    interrupted = run_initialization_child(root, accounts, "key_durable")
    assert interrupted.returncode == 79, interrupted.stderr
    names = {
        "database": initialization.STAGED_DATABASE,
        "identity": initialization.STAGED_IDENTITY,
        "intent": initialization.INTENT,
    }
    selected = root / names[artifact]
    selected.rename(root / "synthetic-retained-original")
    selected.write_bytes(b"unrelated synthetic artifact\n")
    selected.chmod(0o600)
    before = selected.read_bytes()
    key_items = {entry.name: entry.read_bytes() for entry in accounts.iterdir()}
    resumed = run_initialization_child(root, accounts)
    assert resumed.returncode == 1
    assert selected.read_bytes() == before
    assert {entry.name: entry.read_bytes() for entry in accounts.iterdir()} == key_items


def test_opened_stage_must_match_owned_inode_before_truncate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization
    from memory.initialization_fs import BoundDirectory

    paths = resolve_runtime(tmp_path / "synthetic-store")
    from memory.initialization_fs import open_file

    original_open = open_file
    replaced = False
    foreign = b"synthetic foreign content must survive\n"

    def replace_before_open(
        directory: BoundDirectory, name: str, *, writable: bool = False
    ) -> int:
        nonlocal replaced
        if name == initialization.STAGED_DATABASE and writable and not replaced:
            replaced = True
            path = directory.path / name
            path.rename(directory.path / "synthetic-retained-original")
            path.write_bytes(foreign)
            path.chmod(0o600)
        return original_open(directory, name, writable=writable)

    monkeypatch.setattr(initialization, "open_file", replace_before_open)
    with pytest.raises(InitializationError, match="opened artifact ownership changed"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert (paths.root / initialization.STAGED_DATABASE).read_bytes() == foreign


def test_reference_cleanup_preserves_substituted_intent_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization

    paths = resolve_runtime(tmp_path / "synthetic-store")
    original_reference = initialization._file_reference
    foreign = b"synthetic replacement intent\n"

    def replace_after_reference(descriptor: int) -> object:
        reference = original_reference(descriptor)
        pending = paths.root / initialization.INTENT
        if pending.exists() and os.fstat(descriptor).st_ino == pending.stat().st_ino:
            pending.rename(paths.root / "synthetic-retained-intent")
            pending.write_bytes(foreign)
            pending.chmod(0o600)
        return reference

    monkeypatch.setattr(initialization, "_file_reference", replace_after_reference)
    with pytest.raises(InitializationError, match="intent name was replaced"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert (paths.root / initialization.INTENT).read_bytes() == foreign
    assert paths.database.is_file() and paths.identity.is_file()


def test_existing_store_repair_rejects_substituted_authorized_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization
    from memory.initialization_fs import BoundDirectory, open_file

    paths = resolve_runtime(tmp_path / "synthetic-store")
    initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    paths.identity.chmod(0o644)
    foreign = b"unrelated synthetic identity replacement\n"
    replaced = False

    def substitute(
        directory: BoundDirectory, name: str, *, writable: bool = False
    ) -> int:
        nonlocal replaced
        if name == paths.identity.name and not replaced:
            replaced = True
            paths.identity.rename(paths.root / "synthetic-retained-identity")
            paths.identity.write_bytes(foreign)
            paths.identity.chmod(0o644)
        return open_file(directory, name, writable=writable)

    monkeypatch.setattr(initialization, "open_file", substitute)
    with pytest.raises(InitializationError, match="opened artifact ownership changed"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert paths.identity.read_bytes() == foreign
    assert paths.identity.stat().st_mode & 0o777 == 0o644


def test_recovery_append_rejects_substituted_intent_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization
    from memory.initialization_fs import BoundDirectory, open_file

    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    assert run_initialization_child(root, accounts, "intent_durable").returncode == 79
    foreign = b"unrelated synthetic intent replacement\n"
    replaced = False

    def substitute(
        directory: BoundDirectory, name: str, *, writable: bool = False
    ) -> int:
        nonlocal replaced
        if name == initialization.INTENT and writable and not replaced:
            replaced = True
            path = root / name
            path.rename(root / "synthetic-retained-intent")
            path.write_bytes(foreign)
            path.chmod(0o600)
        return open_file(directory, name, writable=writable)

    monkeypatch.setattr(initialization, "open_file", substitute)
    with pytest.raises(InitializationError, match="opened artifact ownership changed"):
        initialize_runtime(resolve_runtime(root), mode=RuntimeMode.PERSONAL)
    assert (root / initialization.INTENT).read_bytes() == foreign
    assert synthetic_keychain == {}


@pytest.mark.parametrize("operation", ["replace_source", "concurrent_destination"])
def test_reference_publication_preserves_foreign_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    operation: str,
) -> None:
    from memory import initialization

    paths = resolve_runtime(tmp_path / "synthetic-store")
    original_reference = initialization._file_reference
    foreign = b"synthetic foreign publication winner\n"
    acted = False
    target = (
        paths.root / initialization.STAGED_DATABASE
        if operation == "replace_source"
        else paths.database
    )

    def substitute(descriptor: int) -> object:
        nonlocal acted
        reference = original_reference(descriptor)
        stage = paths.root / initialization.STAGED_DATABASE
        if (
            not acted
            and stage.exists()
            and os.fstat(descriptor).st_ino == stage.stat().st_ino
        ):
            acted = True
            if operation == "replace_source":
                stage.rename(paths.root / "synthetic-retained-database")
            target.write_bytes(foreign)
            target.chmod(0o600)
        return reference

    monkeypatch.setattr(initialization, "_file_reference", substitute)
    with pytest.raises(InitializationError):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert target.read_bytes() == foreign
    assert not paths.identity.exists()


def test_concurrent_initializer_cannot_clobber_active_winner(tmp_path: Path) -> None:
    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    child = subprocess.Popen(
        [sys.executable, "-c", _INIT_CHILD, str(root), str(accounts), "hold_key"],
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdin is not None
        assert child.stdout.readline() == "synthetic-writer-held\n"
        competing = run_initialization_child(root, accounts)
        assert competing.returncode == 1
        assert "another Store writer is active" in competing.stderr
        stdout, stderr = child.communicate("continue\n", timeout=30)
        assert child.returncode == 0, stderr
        assert stdout == "synthetic-initialization-complete\n"
        assert len(list(accounts.iterdir())) == 1
        assert run_initialization_child(root, accounts).returncode == 0
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=30)


def test_encrypted_pending_store_missing_key_never_mints_replacement(
    tmp_path: Path,
) -> None:
    from memory import initialization

    root, accounts = tmp_path / "synthetic-store", tmp_path / "synthetic-accounts"
    interrupted = run_initialization_child(root, accounts, "schema_created")
    assert interrupted.returncode == 79, interrupted.stderr
    database = root / initialization.STAGED_DATABASE
    assert database.stat().st_size > 0
    before = database.read_bytes()
    items = list(accounts.iterdir())
    assert len(items) == 1
    items[0].unlink()
    resumed = run_initialization_child(root, accounts)
    assert resumed.returncode == 1
    assert "KeyMissingError" in resumed.stderr
    assert list(accounts.iterdir()) == []
    assert database.read_bytes() == before


def test_writer_lock_hardlink_refused_without_chmod(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str]
) -> None:
    paths = resolve_runtime(tmp_path / "synthetic-store")
    paths.root.mkdir(mode=0o700)
    foreign = tmp_path / "synthetic-foreign-lock"
    foreign.write_bytes(b"synthetic lock target\n")
    foreign.chmod(0o640)
    os.link(foreign, paths.writer_lock)
    with pytest.raises(InitializationError, match="writer lock is unsafe"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert foreign.read_bytes() == b"synthetic lock target\n"
    assert foreign.stat().st_mode & 0o777 == 0o640
    assert synthetic_keychain == {}


@pytest.mark.parametrize("alias_target", ["root", "inbox-claims", "inbox-staging"])
def test_case_aliases_cannot_collide_with_private_directory_identities(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str], alias_target: str
) -> None:
    # The supported macOS filesystem can expose different spellings for one
    # directory; exercise real inode aliases where that facility is available.
    probe = tmp_path / "synthetic-probe"
    probe.mkdir()
    if not (tmp_path / "SYNTHETIC-PROBE").exists():
        pytest.skip("case aliases require a case-insensitive test volume")
    paths = resolve_runtime(tmp_path / "synthetic-store")
    alias = tmp_path / "SYNTHETIC-STORE"
    if alias_target != "root":
        alias /= alias_target
    with pytest.raises(
        InitializationError, match=r"identities overlap|topology overlaps"
    ):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL, inbox=alias)
    assert not paths.identity.exists() and not paths.database.exists()
    assert synthetic_keychain == {}


def _native_exclusive_lock_is_blocked(database: Path) -> bool:
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 510, 0x40000002, os.SEEK_SET)
    except BlockingIOError:
        raise SystemExit(23)
finally:
    os.close(fd)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(database)],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode in (0, 23), result.stderr
    return result.returncode == 23


def test_existing_store_initialization_preserves_live_sqlite_reader_lock(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str]
) -> None:
    from memory.database import open_database
    from memory.keys import load_master_key

    paths = resolve_runtime(tmp_path / "synthetic-store")
    identity = initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    reader = open_database(paths, load_master_key(identity), read_only=True)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT store_id FROM store_meta").fetchone()
        assert _native_exclusive_lock_is_blocked(paths.database)
        assert initialize_runtime(paths, mode=RuntimeMode.PERSONAL) == identity
        assert _native_exclusive_lock_is_blocked(paths.database)
    finally:
        reader.close()


def test_database_permission_repair_preserves_other_sqlite_reader_lock(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str]
) -> None:
    from memory import initialization
    from memory.database import open_database
    from memory.initialization_fs import DirectoryPins
    from memory.keys import load_master_key

    paths = resolve_runtime(tmp_path / "synthetic-store")
    identity = initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    reader = open_database(paths, load_master_key(identity), read_only=True)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT store_id FROM store_meta").fetchone()
        assert _native_exclusive_lock_is_blocked(paths.database)
        paths.database.chmod(0o640)
        opened = paths.database.stat()
        with DirectoryPins() as pins:
            root = pins.open(paths.root)
            initialization._repair_database_mode(root, (opened.st_dev, opened.st_ino))
        assert paths.database.stat().st_mode & 0o777 == 0o600
        assert _native_exclusive_lock_is_blocked(paths.database)
    finally:
        reader.close()


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_writer_lock_nonregular_leaf_refuses_without_following(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str], kind: str
) -> None:
    paths = resolve_runtime(tmp_path / "synthetic-store")
    paths.root.mkdir(mode=0o700)
    foreign = tmp_path / "synthetic-foreign-lock"
    foreign.write_bytes(b"synthetic foreign lock target\n")
    foreign.chmod(0o640)
    if kind == "symlink":
        paths.writer_lock.symlink_to(foreign)
    else:
        os.mkfifo(paths.writer_lock, mode=0o600)
    with pytest.raises(InitializationError, match="writer lock is unsafe"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert foreign.read_bytes() == b"synthetic foreign lock target\n"
    assert foreign.stat().st_mode & 0o777 == 0o640
    assert synthetic_keychain == {}


def test_recovery_retains_external_inbox_authority_and_waiting_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization

    root = tmp_path / "synthetic-store"
    inbox = tmp_path / "synthetic-external-inbox"
    inbox.mkdir(mode=0o751)
    waiting = inbox / "synthetic-note.md"
    body = "Synthetic waiting note. 合成等候笔记。\n".encode()
    waiting.write_bytes(body)

    def pause(name: str) -> None:
        if name == "intent_durable":
            raise RuntimeError("synthetic interruption")

    monkeypatch.setattr(initialization, "_init_checkpoint", pause)
    with pytest.raises(RuntimeError):
        initialize_runtime(
            resolve_runtime(root), mode=RuntimeMode.PERSONAL, inbox=inbox
        )
    monkeypatch.setattr(initialization, "_init_checkpoint", lambda _name: None)
    selected = initialize_runtime(resolve_runtime(root), mode=RuntimeMode.PERSONAL)
    assert selected.inbox_path == str(inbox)
    assert resolve_runtime(root).inbox == inbox
    assert waiting.read_bytes() == body
    assert not (root / "inbox").exists()
    assert inbox.stat().st_mode & 0o777 == 0o700
    assert len(synthetic_keychain) == 1


@pytest.mark.parametrize("leaf", ["inbox", "INBOX"])
def test_case_alias_of_default_inbox_keeps_valid_relationship(
    tmp_path: Path, synthetic_keychain: dict[tuple[str, str], str], leaf: str
) -> None:
    probe = tmp_path / "synthetic-probe"
    probe.mkdir()
    if not (tmp_path / "SYNTHETIC-PROBE").exists():
        pytest.skip("case aliases require a case-insensitive test volume")
    paths = resolve_runtime(tmp_path / "synthetic-store")
    aliased_inbox = tmp_path / "SYNTHETIC-STORE" / leaf
    selected = initialize_runtime(paths, mode=RuntimeMode.PERSONAL, inbox=aliased_inbox)
    assert selected.inbox_path == str(aliased_inbox)
    assert (paths.root / "inbox").samefile(aliased_inbox)
    assert (
        initialize_runtime(resolve_runtime(paths.root), mode=RuntimeMode.PERSONAL)
        == selected
    )
    assert len(synthetic_keychain) == 1


def test_default_inbox_alias_allowance_does_not_adopt_unowned_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    from memory import initialization

    paths = resolve_runtime(tmp_path / "synthetic-store")
    foreign = paths.root / "INBOX-OTHER"

    def insert_foreign(name: str) -> None:
        if name == "intent_durable":
            foreign.mkdir(mode=0o751)
            (foreign / "synthetic-marker").write_bytes(b"untouched synthetic marker\n")

    monkeypatch.setattr(initialization, "_init_checkpoint", insert_foreign)
    with pytest.raises(InitializationError, match="unowned entries"):
        initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    assert (
        foreign / "synthetic-marker"
    ).read_bytes() == b"untouched synthetic marker\n"
    assert foreign.stat().st_mode & 0o777 == 0o751
    assert synthetic_keychain == {}
