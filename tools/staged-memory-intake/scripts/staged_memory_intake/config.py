"""Private relocatable configuration and public Memory path resolution."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path

from staged_memory_intake.layout import NUMBERED_LAYOUT
from staged_memory_intake.model import (
    CommandRunner,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    MemoryPaths,
    identity_payload,
    parse_identity_payload,
    reraise_volume_unidentified,
)
from staged_memory_intake.securefs import (
    atomic_private_json,
    directory_identity,
    entry_volume,
    read_regular,
)
from staged_memory_intake.state import TransactionStore, validate_reconfiguration

CONFIG_SCHEMA = "staged-memory-intake.config.v2"
DEFAULT_STATE_ROOT = Path.home() / "Library/Application Support/StagedMemoryIntake"
_LEGACY_CONFIG_SCHEMA = "staged-memory-intake.config.v1"
_OPTIONAL_CONFIG_KEYS = frozenset({"pending_drop"})
_CONFIG_NAME = "config.json"
_CONFIG_LIMIT = 64 * 1024
_PATHS_TIMEOUT_SECONDS = 30.0
_MEMORY_PATH_KEYS = {"database", "home", "identity", "inbox", "inbox_claims"}


def _error(code: str) -> IntakeError:
    return IntakeError(code, "configuration")


def _identity_payload(identity: DirectoryIdentity) -> dict[str, object]:
    try:
        return identity_payload(identity)
    except ValueError as error:
        raise _error("invalid_config") from error


def _strict_inode(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _error("invalid_config")
    return value


def _parse_identity(value: object) -> DirectoryIdentity:
    try:
        return parse_identity_payload(value)
    except ValueError as error:
        raise _error("invalid_config") from error


def _parse_legacy_identity(value: object) -> DirectoryIdentity:
    if not isinstance(value, dict) or set(value) != {"device", "inode"}:
        raise _error("invalid_config")
    device = value["device"]
    if not isinstance(device, int) or isinstance(device, bool) or device < 0:
        raise _error("invalid_config")
    # The recorded device is boot-assigned and meaningless after a reboot;
    # only the inode is carried forward. The None volume marks the identity
    # as pre-v2 without smuggling a sentinel through the volume field.
    return DirectoryIdentity(volume=None, inode=_strict_inode(value["inode"]))


def _is_legacy_identity(identity: DirectoryIdentity) -> bool:
    return identity.volume is None


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise _error("invalid_config")
    path = Path(value)
    if not path.is_absolute():
        raise _error("invalid_config")
    return path


def _mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.lstat().st_mode)
    except OSError as error:
        raise _error("invalid_config") from error


def _require_private_state_root(state_root: Path) -> None:
    directory_identity(state_root)
    if _mode(state_root) != 0o700:
        raise _error("state_root_not_private")


def _validate_existing_state_root(state_root: Path) -> None:
    try:
        state_root.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise _error("invalid_config") from error
    _require_private_state_root(state_root)


def _state_root_absent(state_root: Path) -> bool:
    try:
        state_root.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise _error("invalid_config") from error
    return False


def _config_entry_exists(state_root: Path) -> bool:
    descriptor = os.open(
        state_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        try:
            os.stat(
                _CONFIG_NAME,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        except OSError as error:
            raise _error("invalid_config") from error
        return True
    finally:
        os.close(descriptor)


def _require_config_mode(state_root: Path) -> None:
    config_path = state_root / _CONFIG_NAME
    if _mode(config_path) != 0o600:
        raise _error("config_not_private")


def _load_payload(state_root: Path) -> Mapping[str, object]:
    try:
        raw = read_regular(state_root, _CONFIG_NAME, limit=_CONFIG_LIMIT)
        decoded = json.loads(raw)
    except IntakeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _error("invalid_config") from error
    if not isinstance(decoded, dict):
        raise _error("invalid_config")
    return decoded


def _parse_config(payload: Mapping[str, object]) -> IntakeConfig:
    expected = {
        "schema",
        "notes_root",
        "notes_identity",
        "memory_home",
        "memory_inbox",
        "inbox_identity",
    }
    schema = payload.get("schema")
    if (
        not expected <= set(payload)
        or not set(payload) <= expected | _OPTIONAL_CONFIG_KEYS
        or schema not in {CONFIG_SCHEMA, _LEGACY_CONFIG_SCHEMA}
    ):
        raise _error("invalid_config")
    pending_drop = payload.get("pending_drop", False)
    if not isinstance(pending_drop, bool):
        raise _error("invalid_config")
    parse_identity = (
        _parse_identity if schema == CONFIG_SCHEMA else _parse_legacy_identity
    )
    memory_home_value = payload["memory_home"]
    memory_home = (
        None if memory_home_value is None else _absolute_path(memory_home_value)
    )
    return IntakeConfig(
        notes_root=_absolute_path(payload["notes_root"]),
        notes_identity=parse_identity(payload["notes_identity"]),
        memory_home=memory_home,
        memory_inbox=_absolute_path(payload["memory_inbox"]),
        inbox_identity=parse_identity(payload["inbox_identity"]),
        pending_drop=pending_drop,
    )


def _config_payload(config: IntakeConfig) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": CONFIG_SCHEMA,
        "notes_root": str(config.notes_root),
        "notes_identity": _identity_payload(config.notes_identity),
        "memory_home": (
            None if config.memory_home is None else str(config.memory_home)
        ),
        "memory_inbox": str(config.memory_inbox),
        "inbox_identity": _identity_payload(config.inbox_identity),
    }
    if config.pending_drop:
        payload["pending_drop"] = True
    return payload


def _child_directory_identity(
    root: Path,
    name: str,
    *,
    role: str,
) -> DirectoryIdentity:
    root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            metadata = os.stat(
                name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise _error(f"{role}_missing") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise _error(f"{role}_not_directory")
        try:
            volume = entry_volume(root_descriptor, name)
        except FileNotFoundError as error:
            # The child was deleted between the two lookups; that is absence,
            # not a mangled directory.
            raise _error(f"{role}_missing") from error
        except IntakeError as error:
            reraise_volume_unidentified(error)
            raise _error(f"{role}_not_directory") from error
        return DirectoryIdentity(volume=volume, inode=metadata.st_ino)
    finally:
        os.close(root_descriptor)


def _validate_regular_inventory(root: Path, folder: str, *, role: str) -> None:
    root_descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        descriptor = os.open(
            folder,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            for name in os.listdir(descriptor):
                metadata = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(metadata.st_mode):
                    raise _error(f"{role}_entry_not_regular")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise _error(f"{role}_not_directory") from error
    finally:
        os.close(root_descriptor)


def _create_prepared(notes_root: Path) -> None:
    root_descriptor = os.open(
        notes_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        try:
            os.mkdir(NUMBERED_LAYOUT.prepared, mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            pass
        metadata = os.stat(
            NUMBERED_LAYOUT.prepared,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(metadata.st_mode):
            raise _error("prepared_not_directory")
        descriptor = os.open(
            NUMBERED_LAYOUT.prepared,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        try:
            os.fchmod(descriptor, 0o700)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise _error("prepared_not_directory") from error
    finally:
        os.close(root_descriptor)


def _prepared_exists(notes_root: Path) -> bool:
    root_descriptor = os.open(
        notes_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        try:
            metadata = os.stat(
                NUMBERED_LAYOUT.prepared,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(metadata.st_mode):
            raise _error("prepared_not_directory")
        return True
    finally:
        os.close(root_descriptor)


def _validate_notes_root(notes_root: Path, *, require_prepared: bool) -> None:
    if not notes_root.is_absolute():
        raise _error("notes_root_not_absolute")
    directory_identity(notes_root)
    _child_directory_identity(
        notes_root,
        NUMBERED_LAYOUT.pending,
        role="pending",
    )
    _child_directory_identity(
        notes_root,
        NUMBERED_LAYOUT.staged,
        role="staged",
    )
    _validate_regular_inventory(
        notes_root,
        NUMBERED_LAYOUT.staged,
        role="staged",
    )
    if require_prepared:
        _child_directory_identity(
            notes_root,
            NUMBERED_LAYOUT.prepared,
            role="prepared",
        )
        _validate_regular_inventory(
            notes_root,
            NUMBERED_LAYOUT.prepared,
            role="prepared",
        )


def resolve_memory_paths(
    memory_home: Path | None,
    runner: CommandRunner,
) -> MemoryPaths:
    """Resolve authoritative runtime paths through Memory's public CLI."""
    if memory_home is None:
        argv = ["memory", "paths", "--json"]
    else:
        if not memory_home.is_absolute():
            raise _error("memory_home_not_absolute")
        argv = ["memory", "paths", "--home", str(memory_home), "--json"]
    result = runner.run(argv, timeout_seconds=_PATHS_TIMEOUT_SECONDS)
    if result.returncode != 0 or result.stderr:
        raise IntakeError("memory_paths_failed", "memory", retryable=True)
    try:
        payload = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise IntakeError("invalid_memory_paths", "memory") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != _MEMORY_PATH_KEYS
        or not all(isinstance(value, str) for value in payload.values())
    ):
        raise IntakeError("invalid_memory_paths", "memory")
    home = Path(payload["home"])
    inbox = Path(payload["inbox"])
    if not home.is_absolute() or not inbox.is_absolute():
        raise IntakeError("invalid_memory_paths", "memory")
    try:
        directory_identity(home)
        inbox_identity = directory_identity(inbox)
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise IntakeError("invalid_memory_paths", "memory") from error
    if memory_home is not None and home != memory_home:
        raise IntakeError("invalid_memory_paths", "memory")
    return MemoryPaths(home=home, inbox=inbox, inbox_identity=inbox_identity)


def _mount_point_root(path: Path) -> bool:
    """Recognize a directory whose parent lives on another volume.

    Volume roots share inode 2, so a mount-point root's stored inode cannot
    distinguish the configured volume from any other volume mounted at the
    same path. An unreadable parent is treated the same way: unverifiable.
    """
    parent = path.parent
    if parent == path:
        return True
    try:
        return directory_identity(path).volume != directory_identity(parent).volume
    except IntakeError:
        return True


def _adopt_legacy_config(
    state_root: Path,
    legacy: IntakeConfig,
    *,
    validate_layout: bool = True,
) -> IntakeConfig:
    """Rebind one device-bound config whose device numbers a reboot moved."""
    try:
        current_notes = directory_identity(legacy.notes_root)
        current_inbox = directory_identity(legacy.memory_inbox)
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("configured_root_changed") from error
    if current_notes.inode != legacy.notes_identity.inode:
        raise _error("notes_root_changed")
    if current_inbox.inode != legacy.inbox_identity.inode:
        raise _error("memory_inbox_changed")
    if _mount_point_root(legacy.notes_root):
        raise _error("notes_root_unverifiable")
    if _mount_point_root(legacy.memory_inbox):
        raise _error("memory_inbox_unverifiable")
    if validate_layout:
        _validate_notes_root(legacy.notes_root, require_prepared=True)
    updated = IntakeConfig(
        notes_root=legacy.notes_root,
        notes_identity=current_notes,
        memory_home=legacy.memory_home,
        memory_inbox=legacy.memory_inbox,
        inbox_identity=current_inbox,
        pending_drop=legacy.pending_drop,
    )
    # This one-shot upgrade write cannot take the transaction lock (configure()
    # already holds it when it loads), so it mirrors replace_config_paths:
    # compare the persisted record immediately before writing, then strictly
    # re-read the result. The compare refuses any reconfiguration that landed
    # since this adoption read its record; the residual window between compare
    # and write stays open only on the ordinary load path, and the relocate
    # and migrate-layout callers close it by holding the transaction lock
    # around the whole adoption.
    current = _parse_config(_load_payload(state_root))
    if current != legacy:
        raise _error("configured_root_changed")
    atomic_private_json(state_root / _CONFIG_NAME, _config_payload(updated))
    rebound = _parse_config(_load_payload(state_root))
    if rebound != updated:
        raise _error("configured_root_changed")
    return rebound


def load_config(state_root: Path = DEFAULT_STATE_ROOT) -> IntakeConfig | None:
    """Load and rebind private configuration without creating anything."""
    try:
        state_root.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _error("invalid_config") from error
    _require_private_state_root(state_root)
    _require_config_mode(state_root)
    config = _parse_config(_load_payload(state_root))
    if _is_legacy_identity(config.notes_identity) or _is_legacy_identity(
        config.inbox_identity
    ):
        config = _adopt_legacy_config(state_root, config)
    try:
        current_notes = directory_identity(config.notes_root)
        current_inbox = directory_identity(config.memory_inbox)
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("configured_root_changed") from error
    if current_notes != config.notes_identity:
        raise _error("notes_root_changed")
    if current_inbox != config.inbox_identity:
        raise _error("memory_inbox_changed")
    _validate_notes_root(config.notes_root, require_prepared=True)
    return config


def load_config_record(state_root: Path) -> IntakeConfig:
    """Load the exact private config without requiring its paths to be live."""
    _require_private_state_root(state_root)
    _require_config_mode(state_root)
    return _parse_config(_load_payload(state_root))


def adopt_config_record(state_root: Path) -> IntakeConfig:
    """Load the exact config record, rebinding a device-bound one in place.

    `relocate` and `migrate-layout` judge every live authority themselves
    right after this read, and `migrate-layout` is the one command that must
    accept the legacy folder layout, so the rebind here skips the
    numbered-layout validation the ordinary load path performs. Without this,
    a v1 config's first post-upgrade command being either of them falsely
    refused as authority drift, and a v1 config still on the legacy layout
    had no adoption path at all.
    """
    config = load_config_record(state_root)
    if _is_legacy_identity(config.notes_identity) or _is_legacy_identity(
        config.inbox_identity
    ):
        config = _adopt_legacy_config(state_root, config, validate_layout=False)
    return config


def require_config(state_root: Path = DEFAULT_STATE_ROOT) -> IntakeConfig:
    """Load configuration or fail with the valid unconfigured state."""
    config = load_config(state_root)
    if config is None:
        raise IntakeError("not_configured", "configuration")
    return config


def replace_config_paths(
    state_root: Path,
    old: IntakeConfig,
    notes_root: Path,
    notes_identity: DirectoryIdentity,
    memory_inbox: Path,
    inbox_identity: DirectoryIdentity,
) -> IntakeConfig:
    """Atomically advance one exact config to preflight-bound authorities."""
    current = _parse_config(_load_payload(state_root))
    if current != old:
        raise _error("configured_root_changed")
    if (
        directory_identity(notes_root) != notes_identity
        or directory_identity(memory_inbox) != inbox_identity
    ):
        raise _error("configured_root_changed")
    updated = IntakeConfig(
        notes_root=notes_root,
        notes_identity=notes_identity,
        memory_home=old.memory_home,
        memory_inbox=memory_inbox,
        inbox_identity=inbox_identity,
        pending_drop=old.pending_drop,
    )
    atomic_private_json(state_root / _CONFIG_NAME, _config_payload(updated))
    rebound = load_config_record(state_root)
    if rebound != updated:
        raise _error("configured_root_changed")
    return rebound


def configure(
    state_root: Path,
    notes_root: Path,
    memory_home: Path | None,
    *,
    create_prepared: bool,
    runner: CommandRunner,
    pending_drop: bool | None = None,
) -> IntakeConfig:
    """Validate both path authorities fully, then atomically configure."""
    observed_absence = _state_root_absent(state_root)
    _validate_existing_state_root(state_root)
    store = TransactionStore.for_operation(state_root)

    def validate_inputs() -> MemoryPaths:
        _validate_notes_root(notes_root, require_prepared=False)
        paths = resolve_memory_paths(memory_home, runner)
        if not _prepared_exists(notes_root):
            if not create_prepared:
                raise _error("prepared_missing")
            _create_prepared(notes_root)
        _child_directory_identity(
            notes_root,
            NUMBERED_LAYOUT.prepared,
            role="prepared",
        )
        _validate_regular_inventory(
            notes_root,
            NUMBERED_LAYOUT.prepared,
            role="prepared",
        )
        return paths

    def write_locked(old: IntakeConfig | None, paths: MemoryPaths) -> IntakeConfig:
        if old is not None and (
            memory_home != old.memory_home
            or paths.inbox != old.memory_inbox
            or paths.inbox_identity != old.inbox_identity
        ):
            raise _error("memory_inbox_reconfiguration_required")
        validate_reconfiguration(store, old, notes_root)
        config = IntakeConfig(
            notes_root=notes_root,
            notes_identity=directory_identity(notes_root),
            memory_home=memory_home,
            memory_inbox=paths.inbox,
            inbox_identity=paths.inbox_identity,
            pending_drop=(
                (False if old is None else old.pending_drop)
                if pending_drop is None
                else pending_drop
            ),
        )
        atomic_private_json(state_root / _CONFIG_NAME, _config_payload(config))
        return require_config(state_root)

    if observed_absence:
        paths = validate_inputs()
        with store.lock():
            _require_private_state_root(state_root)
            if _config_entry_exists(state_root):
                raise _error("stale_configuration")
            if store.active() is not None:
                raise IntakeError("transaction_active", "state")
            _validate_notes_root(notes_root, require_prepared=True)
            return write_locked(None, paths)
    with store.lock():
        if store.active() is not None:
            raise IntakeError("transaction_active", "state")
        old = load_config(state_root)
        paths = validate_inputs()
        return write_locked(old, paths)
