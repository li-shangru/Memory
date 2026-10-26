"""Store runtime resolution and initialization."""

from __future__ import annotations

import dataclasses
import fcntl
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from memory.errors import (
    InitializationError,
    InvalidRuntimeError,
    StoreBusyError,
    StoreUnavailableError,
)
from memory.model import (
    RuntimeMode,
    RuntimePaths,
    SecretBytes,
    StoreIdentity,
)

DEFAULT_RUNTIME_NAME = "Memory"
PRODUCT = "memory"
SCHEMA_LINEAGE = "memory-store-v1"
SCHEMA_VERSION = 1
_IDENTITY_KEYS = {
    "inbox_path",
    "product",
    "runtime_mode",
    "schema_lineage",
    "schema_version",
    "store_id",
}
_STORE_ID = re.compile(r"[0-9a-f]{32}")
INBOX_RELOCATION_ARTIFACT_NAMES = (
    ".inbox-relocation.intent.json",
    ".inbox-relocation.intent.tmp",
    ".inbox-relocation.runtime.tmp",
)


def _lexical_absolute(path: Path) -> Path:
    """Expand and absolutize one path without following filesystem links."""
    expanded = path.expanduser()
    return Path(os.path.normpath(os.path.abspath(os.fspath(expanded))))


def default_root() -> Path:
    """Return the default Store home used when no explicit home is selected."""
    return _lexical_absolute(
        Path.home() / "Library" / "Application Support" / DEFAULT_RUNTIME_NAME
    )


def resolve_runtime(home: Path | None) -> RuntimePaths:
    """Resolve one Store runtime, honoring a configured external inbox."""
    selected = default_root() if home is None else home
    root = _lexical_absolute(selected)
    paths = RuntimePaths(
        root=root,
        database=root / "store.sqlite3",
        inbox=root / "inbox",
        inbox_claims=root / "inbox-claims",
        inbox_staging=root / "inbox-staging",
        identity=root / "runtime.json",
        writer_lock=root / ".writer.lock",
        ui_session_lock=root / ".ui-session.lock",
    )
    configured = _peek_configured_inbox(paths)
    if configured is not None:
        paths = dataclasses.replace(paths, inbox=configured)
    return paths


def _peek_configured_inbox(paths: RuntimePaths) -> Path | None:
    """Best-effort read of the persisted inbox path; strict checks come later."""
    try:
        raw: Any = json.loads(paths.identity.read_text(encoding="utf-8"))
    except OSError, UnicodeError, json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    try:
        return _validated_inbox_path(paths.root, raw.get("inbox_path"))
    except InvalidRuntimeError:
        return None


def _validated_inbox_path(root: Path, value: object) -> Path:
    """Validate one persisted inbox path against the selected Store root."""
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        raise InvalidRuntimeError("Store runtime identity has an invalid inbox")
    inbox = Path(value)
    if ".." in inbox.parts:
        raise InvalidRuntimeError("Store runtime identity has an invalid inbox")
    if inbox == root / "inbox":
        return inbox
    root_parts = root.parts
    inbox_parts = inbox.parts
    inside_root = inbox_parts[: len(root_parts)] == root_parts
    contains_root = root_parts[: len(inbox_parts)] == inbox_parts
    if inside_root or contains_root:
        raise InvalidRuntimeError("Store runtime identity has an invalid inbox")
    return inbox


def load_runtime_identity(paths: RuntimePaths) -> StoreIdentity:
    """Load and strictly validate the selected runtime's public identity."""
    _require_no_initialization_artifacts(paths)
    _require_no_inbox_relocation_artifacts(paths)
    return _load_runtime_identity_for_relocation(paths)


def _require_no_initialization_artifacts(paths: RuntimePaths) -> None:
    from memory.initialization import ARTIFACTS

    for name in ARTIFACTS:
        try:
            (paths.root / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise StoreUnavailableError(
                "Store initialization state is unavailable"
            ) from error
        raise InvalidRuntimeError("Store initialization requires an exact init retry")


def _require_no_inbox_relocation_artifacts(paths: RuntimePaths) -> None:
    """Fail every ordinary runtime open while relocation needs recovery."""
    for name in INBOX_RELOCATION_ARTIFACT_NAMES:
        try:
            (paths.root / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            # A probe the filesystem refuses to answer is an environment
            # failure, not evidence about the Store's identity.
            raise StoreUnavailableError(
                "Store Inbox relocation state is unavailable"
            ) from error
        raise InvalidRuntimeError("Store Inbox relocation requires recovery")


def _load_runtime_identity_for_relocation(paths: RuntimePaths) -> StoreIdentity:
    """Strictly load identity while the relocation entrypoint owns recovery."""
    try:
        raw: Any = json.loads(paths.identity.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        # An absent identity is the uninitialized-home shape and stays the
        # identity diagnosis; only a filesystem that refuses to answer about
        # an identity that exists is an environment failure.
        raise InvalidRuntimeError("Store runtime identity is unavailable") from error
    except OSError as error:
        # `wrong_product` is chartered for a database that is not a Memory
        # store and is never repaired; a permission change, I/O error, or
        # evicted placeholder underneath a real identity is the owner's
        # environment to repair and must say so.
        raise StoreUnavailableError(
            "Store runtime identity filesystem is unavailable"
        ) from error
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InvalidRuntimeError("Store runtime identity is unavailable") from error
    return _parse_runtime_identity(paths, raw)


def _parse_runtime_identity(paths: RuntimePaths, raw: Any) -> StoreIdentity:
    """Validate the unchanged public identity shape from owned bytes."""
    if not isinstance(raw, dict) or set(raw) != _IDENTITY_KEYS:
        raise InvalidRuntimeError("Store runtime identity is invalid")
    product = raw.get("product")
    lineage = raw.get("schema_lineage")
    version = raw.get("schema_version")
    store_id = raw.get("store_id")
    raw_mode = raw.get("runtime_mode")
    inbox_path = _validated_inbox_path(paths.root, raw.get("inbox_path"))
    try:
        runtime_mode = RuntimeMode(raw_mode) if isinstance(raw_mode, str) else None
    except ValueError as error:
        raise InvalidRuntimeError(
            "Store runtime identity has an unknown mode"
        ) from error
    if (
        product != PRODUCT
        or lineage != SCHEMA_LINEAGE
        or version != SCHEMA_VERSION
        or not isinstance(store_id, str)
        or _STORE_ID.fullmatch(store_id) is None
        or runtime_mode is None
    ):
        raise InvalidRuntimeError("Store runtime identity has the wrong product")
    return StoreIdentity(
        product=product,
        schema_lineage=lineage,
        schema_version=version,
        store_id=store_id,
        runtime_mode=runtime_mode,
        inbox_path=str(inbox_path),
    )


def authorize_runtime_use(paths: RuntimePaths) -> StoreIdentity:
    """Authorize one selected Store runtime without mutating it."""
    identity = load_runtime_identity(paths)
    if Path(identity.inbox_path) != paths.inbox:
        raise InvalidRuntimeError("Store runtime identity changed")
    from memory.database import open_database
    from memory.keys import load_master_key

    connection = open_database(paths, load_master_key(identity), read_only=True)
    connection.close()
    return identity


def _authorize_runtime_use_for_relocation(paths: RuntimePaths) -> StoreIdentity:
    """Authorize the Store while the relocation entrypoint owns artifacts."""
    _require_no_initialization_artifacts(paths)
    identity = _load_runtime_identity_for_relocation(paths)
    if Path(identity.inbox_path) != paths.inbox:
        raise InvalidRuntimeError("Store runtime identity changed")
    from memory.database import _preflight_database
    from memory.keys import load_master_key

    _preflight_database(paths, load_master_key(identity), identity)
    return identity


def initialize_runtime(
    paths: RuntimePaths,
    *,
    mode: RuntimeMode,
    inbox: Path | None = None,
) -> StoreIdentity:
    """Create or safely reopen one private, encrypted Store runtime."""
    if not isinstance(mode, RuntimeMode):
        raise InitializationError("Store runtime mode must be a RuntimeMode")
    from memory.initialization import initialize

    effective = dataclasses.replace(paths, inbox=_requested_inbox(paths, inbox))
    return initialize(effective, mode=mode, inbox_argument=inbox)


def _requested_inbox(paths: RuntimePaths, inbox: Path | None) -> Path:
    """Normalize and validate the requested inbox for this initialization."""
    if inbox is None:
        return paths.inbox
    candidate = os.path.normpath(os.path.abspath(os.fspath(inbox.expanduser())))
    try:
        return _validated_inbox_path(paths.root, candidate)
    except InvalidRuntimeError as error:
        raise InitializationError("Store inbox path is invalid") from error


def _require_matching_runtime(
    identity: StoreIdentity,
    mode: RuntimeMode,
    inbox: Path | None,
    paths: RuntimePaths,
) -> None:
    if identity.runtime_mode is not mode:
        raise InitializationError("Store runtime mode does not match initialization")
    if inbox is not None and Path(identity.inbox_path) != _requested_inbox(
        paths, inbox
    ):
        raise InitializationError("Store inbox is already configured differently")


def _preflight_initialized_runtime(
    paths: RuntimePaths,
) -> tuple[StoreIdentity, SecretBytes, bool, bool]:
    from memory.database import open_database
    from memory.errors import WrongProductError
    from memory.keys import load_master_key

    identity = load_runtime_identity(paths)
    key = load_master_key(identity)
    database_exists = paths.database.exists()
    if not database_exists:
        raise WrongProductError(
            "Store database is missing; no initialization intent owns recovery"
        )
    database_needs_repair = False
    if database_exists:
        connection = open_database(paths, key, read_only=True)
        try:
            database_needs_repair = connection.execute(
                "PRAGMA journal_mode"
            ).fetchone() != ("wal",)
        finally:
            connection.close()
    return identity, key, database_exists, database_needs_repair


@contextmanager
def _writer_lock(
    paths: RuntimePaths,
    *,
    root_descriptor: int | None = None,
) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if root_descriptor is None:
        descriptor = os.open(paths.writer_lock, flags, 0o600)
    else:
        try:
            descriptor = os.open(
                paths.writer_lock.name,
                flags | os.O_NONBLOCK,
                0o600,
                dir_fd=root_descriptor,
            )
        except OSError as error:
            raise InitializationError("Store writer lock is unsafe") from error
    if root_descriptor is not None:
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise InitializationError("Store writer lock is unsafe")
            current = os.stat(
                paths.writer_lock.name, dir_fd=root_descriptor, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise InitializationError("Store writer lock changed")
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            raise
    else:
        os.fchmod(descriptor, 0o600)
    lock_file = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StoreBusyError("another Store writer is active") from error
        if root_descriptor is not None:
            current = os.stat(
                paths.writer_lock.name, dir_fd=root_descriptor, follow_symlinks=False
            )
            opened = os.fstat(lock_file.fileno())
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise InitializationError("Store writer lock changed")
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


@contextmanager
def ui_session_lock(paths: RuntimePaths) -> Iterator[None]:
    """Exclude concurrent owner UI processes for one exact runtime."""
    root_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        root_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        root_flags |= os.O_NOFOLLOW
    try:
        root_descriptor = os.open(paths.root, root_flags)
    except OSError as error:
        raise InvalidRuntimeError("Store runtime directory is unsafe") from error
    descriptor: int | None = None
    locked = False
    try:
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            created = False
            try:
                descriptor = os.open(
                    paths.ui_session_lock.name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=root_descriptor,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(
                    paths.ui_session_lock.name,
                    flags,
                    dir_fd=root_descriptor,
                )
            metadata = os.fstat(descriptor)
            _validate_ui_session_lock_metadata(metadata, require_mode=not created)
            if created:
                os.fchmod(descriptor, 0o600)
                metadata = os.fstat(descriptor)
                _validate_ui_session_lock_metadata(metadata, require_mode=True)
            _revalidate_ui_session_lock_entry(
                root_descriptor,
                paths.ui_session_lock.name,
                metadata,
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise StoreBusyError("another Store owner UI is active") from error
            locked = True
            _revalidate_ui_session_lock_entry(
                root_descriptor,
                paths.ui_session_lock.name,
                metadata,
            )
            yield
        except InvalidRuntimeError, StoreBusyError:
            raise
        except OSError as error:
            raise InvalidRuntimeError("UI session lock is unsafe") from error
        finally:
            if descriptor is not None:
                try:
                    if locked:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _validate_ui_session_lock_metadata(
    metadata: os.stat_result,
    *,
    require_mode: bool,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or (require_mode and stat.S_IMODE(metadata.st_mode) != 0o600)
    ):
        raise InvalidRuntimeError("UI session lock is unsafe")


def _revalidate_ui_session_lock_entry(
    root_descriptor: int,
    name: str,
    opened: os.stat_result,
) -> None:
    entry = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    _validate_ui_session_lock_metadata(entry, require_mode=True)
    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
        raise InvalidRuntimeError("UI session lock directory entry changed")


def _runtime_needs_repair(paths: RuntimePaths) -> bool:
    needs_repair = stat.S_IMODE(paths.root.lstat().st_mode) != 0o700
    needs_repair |= _private_directory_needs_repair(paths.inbox)
    needs_repair |= _private_directory_needs_repair(paths.inbox_claims)
    needs_repair |= _private_directory_needs_repair(paths.inbox_staging)
    needs_repair |= _private_file_needs_repair(paths.identity, 0o600)
    needs_repair |= _private_file_needs_repair(paths.database, 0o600)
    if paths.writer_lock.exists():
        needs_repair |= _private_file_needs_repair(paths.writer_lock, 0o600)
    return needs_repair


def _private_directory_needs_repair(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise InitializationError("Store runtime path is not a private directory")
    return stat.S_IMODE(metadata.st_mode) != 0o700


def _private_file_needs_repair(path: Path, wanted_mode: int) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise InitializationError("Store runtime path is not a private file")
    return stat.S_IMODE(metadata.st_mode) != wanted_mode
