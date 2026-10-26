"""Crash-recoverable relocation of one configured staged-intake notes root."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from staged_memory_intake.config import (
    adopt_config_record,
    load_config_record,
    replace_config_paths,
    resolve_memory_paths,
)
from staged_memory_intake.layout import NUMBERED_LAYOUT, OBSIDIAN_DIRECTORY
from staged_memory_intake.model import (
    CommandRunner,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    NoRelocationFault,
    RelocationFault,
    RelocationResult,
    require_volume_uuid,
    reraise_volume_unidentified,
)
from staged_memory_intake.securefs import (
    atomic_private_json,
    descriptor_volume,
    directory_identity,
    entry_volume,
    quarantine_state_entry,
    read_private_regular,
)
from staged_memory_intake.state import TransactionStore

_INTENT_NAME: Final = ".notes-root-relocation.intent.json"
_STAGED_INBOX_NAME: Final = ".notes-root-relocation-inbox"
_INTENT_SCHEMA: Final = "staged-memory-intake.root-relocation.v2"
_OPTIONAL_INTENT_KEYS: Final = frozenset({"pending_drop"})
_INTENT_LIMIT: Final = 64 * 1024
_EXPECTED_CHILDREN: Final = NUMBERED_LAYOUT.children
_PARKED_CHILDREN: Final = NUMBERED_LAYOUT.parked_children
_OBSIDIAN_NAME: Final = OBSIDIAN_DIRECTORY
_MEMORY_TIMEOUT_SECONDS: Final = 120.0
_RENAME_EXCL: Final = 0x00000004
_NO_RELOCATION_FAULT: Final = NoRelocationFault()


class _Phase(StrEnum):
    PREPARED = "prepared"
    INBOX_STAGED = "inbox_staged"
    ROOT_MOVED = "root_moved"
    INBOX_FINAL = "inbox_final"
    CONFIG_REPLACED = "config_replaced"


@dataclass(frozen=True, slots=True)
class _DirectoryAuthority:
    identity: DirectoryIdentity
    owner: int
    mode: int


@dataclass(frozen=True, slots=True)
class _Intent:
    phase: _Phase
    source: Path
    destination: Path
    memory_home: Path | None
    notes_identity: DirectoryIdentity
    inbox_identity: DirectoryIdentity
    pending_identity: DirectoryIdentity
    staged_identity: DirectoryIdentity
    prepared_identity: DirectoryIdentity
    source_parent: _DirectoryAuthority
    destination_parent: _DirectoryAuthority
    obsidian: _DirectoryAuthority | None
    pending_drop: bool

    def old_config(self) -> IntakeConfig:
        return IntakeConfig(
            notes_root=self.source,
            notes_identity=self.notes_identity,
            memory_home=self.memory_home,
            memory_inbox=self.source / NUMBERED_LAYOUT.inbox,
            inbox_identity=self.inbox_identity,
            pending_drop=self.pending_drop,
        )

    def new_config(self) -> IntakeConfig:
        return IntakeConfig(
            notes_root=self.destination,
            notes_identity=self.notes_identity,
            memory_home=self.memory_home,
            memory_inbox=self.destination / NUMBERED_LAYOUT.inbox,
            inbox_identity=self.inbox_identity,
            pending_drop=self.pending_drop,
        )


def _error(code: str, *, retryable: bool = False) -> IntakeError:
    return IntakeError(code, "drift", retryable=retryable)


def _configuration_error(code: str) -> IntakeError:
    return IntakeError(code, "configuration")


def _normalized_path(destination: Path) -> Path:
    normalized = Path(os.path.normpath(os.path.abspath(os.fspath(destination))))
    if destination != normalized or not destination.is_absolute():
        raise _configuration_error("relocation_destination_invalid")
    return normalized


def _normalized_destination(
    destination: Path,
    *,
    require_parent_owner: bool = True,
) -> Path:
    normalized = _normalized_path(destination)
    parent_descriptor = _open_bound_directory(
        normalized.parent,
        require_owner=require_parent_owner,
    )
    try:
        try:
            name_limit = os.fpathconf(parent_descriptor, "PC_NAME_MAX")
        except OSError as error:
            raise _configuration_error("relocation_destination_invalid") from error
        if not normalized.name or len(os.fsencode(normalized.name)) > name_limit:
            raise _configuration_error("relocation_destination_invalid")
    finally:
        os.close(parent_descriptor)
    return normalized


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_bound_directory(path: Path, *, require_owner: bool = True) -> int:
    """Open every absolute path component without following a symlink."""
    if (
        not path.is_absolute()
        or ".." in path.parts
        or Path(os.path.normpath(os.fspath(path))) != path
    ):
        raise _configuration_error("relocation_destination_invalid")
    descriptor: int | None = None
    try:
        descriptor = os.open(os.path.sep, _directory_flags())
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                _directory_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or (
            require_owner and metadata.st_uid != os.geteuid()
        ):
            os.close(descriptor)
            descriptor = None
            raise _configuration_error("relocation_destination_invalid")
        return descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise _configuration_error("relocation_destination_invalid") from error


def _directory_authority(
    descriptor: int,
    *,
    require_owner: bool = True,
) -> _DirectoryAuthority:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or (
        require_owner and metadata.st_uid != os.geteuid()
    ):
        raise _error("relocation_authority_changed")
    return _DirectoryAuthority(
        identity=DirectoryIdentity(descriptor_volume(descriptor), metadata.st_ino),
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _open_exact_parent(path: Path, expected: _DirectoryAuthority) -> int:
    descriptor: int | None = None
    try:
        descriptor = _open_bound_directory(path)
        actual = _directory_authority(descriptor)
    except (IntakeError, OSError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("relocation_authority_changed") from error
    if actual != expected:
        os.close(descriptor)
        raise _error("relocation_authority_changed")
    return descriptor


def _parent_authority(
    path: Path,
    *,
    require_owner: bool = True,
) -> _DirectoryAuthority:
    descriptor = _open_bound_directory(path, require_owner=require_owner)
    try:
        return _directory_authority(descriptor, require_owner=require_owner)
    finally:
        os.close(descriptor)


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        second.relative_to(first)
    except ValueError:
        pass
    else:
        return True
    try:
        first.relative_to(second)
    except ValueError:
        return False
    return True


def _identity_payload(
    identity: DirectoryIdentity,
    prefix: str,
) -> dict[str, int | str]:
    return {
        f"{prefix}_volume": require_volume_uuid(identity.volume),
        f"{prefix}_inode": identity.inode,
    }


def _authority_payload(
    authority: _DirectoryAuthority,
    prefix: str,
) -> dict[str, int | str]:
    return {
        **_identity_payload(authority.identity, prefix),
        f"{prefix}_owner": authority.owner,
        f"{prefix}_mode": authority.mode,
    }


def _optional_authority_payload(
    authority: _DirectoryAuthority | None,
    prefix: str,
) -> dict[str, int | str | None]:
    if authority is None:
        return {
            f"{prefix}_volume": None,
            f"{prefix}_inode": None,
            f"{prefix}_owner": None,
            f"{prefix}_mode": None,
        }
    return {
        f"{prefix}_volume": authority.identity.volume,
        f"{prefix}_inode": authority.identity.inode,
        f"{prefix}_owner": authority.owner,
        f"{prefix}_mode": authority.mode,
    }


def _intent_payload(intent: _Intent) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": _INTENT_SCHEMA,
        "phase": intent.phase.value,
        "source": str(intent.source),
        "destination": str(intent.destination),
        "memory_home": (
            None if intent.memory_home is None else str(intent.memory_home)
        ),
        **_identity_payload(intent.notes_identity, "notes"),
        **_identity_payload(intent.inbox_identity, "inbox"),
        **_identity_payload(intent.pending_identity, "pending"),
        **_identity_payload(intent.staged_identity, "staged"),
        **_identity_payload(intent.prepared_identity, "prepared"),
        **_authority_payload(intent.source_parent, "source_parent"),
        **_authority_payload(intent.destination_parent, "destination_parent"),
        **_optional_authority_payload(intent.obsidian, "obsidian"),
    }
    if intent.pending_drop:
        payload["pending_drop"] = True
    return payload


def _strict_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError
    return value


def _parse_path(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        raise ValueError
    return path


def _strict_volume(value: object) -> str:
    return require_volume_uuid(value)


def _parse_identity(raw: dict[str, object], prefix: str) -> DirectoryIdentity:
    return DirectoryIdentity(
        volume=_strict_volume(raw[f"{prefix}_volume"]),
        inode=_strict_int(raw[f"{prefix}_inode"]),
    )


def _parse_authority(
    raw: dict[str, object],
    prefix: str,
) -> _DirectoryAuthority:
    return _DirectoryAuthority(
        identity=_parse_identity(raw, prefix),
        owner=_strict_int(raw[f"{prefix}_owner"]),
        mode=_strict_int(raw[f"{prefix}_mode"]),
    )


def _parse_optional_authority(
    raw: dict[str, object],
    prefix: str,
) -> _DirectoryAuthority | None:
    values = tuple(
        raw[f"{prefix}_{field}"] for field in ("volume", "inode", "owner", "mode")
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError
    return _parse_authority(raw, prefix)


def _parse_intent(encoded: bytes) -> _Intent:
    prefixes = ("notes", "inbox", "pending", "staged", "prepared")
    authority_prefixes = ("source_parent", "destination_parent", "obsidian")
    expected = {
        "schema",
        "phase",
        "source",
        "destination",
        "memory_home",
        *(f"{prefix}_{field}" for prefix in prefixes for field in ("volume", "inode")),
        *(
            f"{prefix}_{field}"
            for prefix in authority_prefixes
            for field in ("volume", "inode", "owner", "mode")
        ),
    }
    try:
        raw = json.loads(encoded)
        if (
            not isinstance(raw, dict)
            or not expected <= set(raw)
            or not set(raw) <= expected | _OPTIONAL_INTENT_KEYS
        ):
            raise ValueError
        pending_drop = raw.get("pending_drop", False)
        if not isinstance(pending_drop, bool):
            raise ValueError
        memory_home_value = raw["memory_home"]
        memory_home = (
            None if memory_home_value is None else _parse_path(memory_home_value)
        )
        intent = _Intent(
            phase=_Phase(raw["phase"]),
            source=_parse_path(raw["source"]),
            destination=_parse_path(raw["destination"]),
            memory_home=memory_home,
            notes_identity=_parse_identity(raw, "notes"),
            inbox_identity=_parse_identity(raw, "inbox"),
            pending_identity=_parse_identity(raw, "pending"),
            staged_identity=_parse_identity(raw, "staged"),
            prepared_identity=_parse_identity(raw, "prepared"),
            source_parent=_parse_authority(raw, "source_parent"),
            destination_parent=_parse_authority(raw, "destination_parent"),
            obsidian=_parse_optional_authority(raw, "obsidian"),
            pending_drop=pending_drop,
        )
        if raw["schema"] != _INTENT_SCHEMA:
            raise ValueError
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise _error("relocation_intent_invalid") from error
    canonical = (
        json.dumps(
            _intent_payload(intent),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    if canonical != encoded:
        raise _error("relocation_intent_invalid")
    return intent


def _load_intent(state_root: Path) -> _Intent | None:
    intent_path = state_root / _INTENT_NAME
    try:
        intent_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _error("relocation_intent_invalid") from error
    try:
        encoded = read_private_regular(
            state_root,
            _INTENT_NAME,
            limit=_INTENT_LIMIT,
        )
    except IntakeError as error:
        raise _error("relocation_intent_invalid") from error
    return _parse_intent(encoded)


def relocation_pending(state_root: Path) -> bool:
    """Report a valid pending relocation without creating helper state."""
    try:
        state_root.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _error("relocation_intent_invalid") from error
    return _load_intent(state_root) is not None


def _write_intent(state_root: Path, intent: _Intent) -> None:
    atomic_private_json(state_root / _INTENT_NAME, _intent_payload(intent))


def _advance(state_root: Path, intent: _Intent, phase: _Phase) -> _Intent:
    updated = _Intent(
        phase=phase,
        source=intent.source,
        destination=intent.destination,
        memory_home=intent.memory_home,
        notes_identity=intent.notes_identity,
        inbox_identity=intent.inbox_identity,
        pending_identity=intent.pending_identity,
        staged_identity=intent.staged_identity,
        prepared_identity=intent.prepared_identity,
        source_parent=intent.source_parent,
        destination_parent=intent.destination_parent,
        obsidian=intent.obsidian,
        pending_drop=intent.pending_drop,
    )
    _write_intent(state_root, updated)
    return updated


def _remove_intent(state_root: Path) -> None:
    descriptor = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.unlink(_INTENT_NAME, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_directory(
    path: Path,
    expected: DirectoryIdentity,
) -> None:
    descriptor: int | None = None
    try:
        descriptor = _open_bound_directory(path)
        metadata = os.fstat(descriptor)
        volume = descriptor_volume(descriptor)
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("relocation_authority_changed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or DirectoryIdentity(volume, metadata.st_ino) != expected
    ):
        raise _error("relocation_authority_changed")


def _path_state(path: Path, expected: DirectoryIdentity) -> str:
    parent_descriptor: int | None = None
    try:
        parent_descriptor = _open_bound_directory(path.parent)
        metadata = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_ino == expected.inode
            and entry_volume(parent_descriptor, path.name) == expected.volume
        ):
            return "exact"
        return "other"
    except FileNotFoundError:
        return "absent"
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("relocation_authority_changed") from error
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _root_inventory(root: Path, expected: DirectoryIdentity) -> tuple[str, ...]:
    descriptor: int | None = None
    try:
        descriptor = _open_bound_directory(root)
        metadata = os.fstat(descriptor)
        if (
            DirectoryIdentity(
                descriptor_volume(descriptor),
                metadata.st_ino,
            )
            != expected
        ):
            raise _error("relocation_authority_changed")
        return tuple(sorted(os.listdir(descriptor)))
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            raise
        raise _error("relocation_authority_changed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_children(root: Path, intent: _Intent, *, inbox: bool) -> None:
    base_names = _EXPECTED_CHILDREN if inbox else _PARKED_CHILDREN
    expected_names = (
        tuple(sorted((*base_names, _OBSIDIAN_NAME)))
        if intent.obsidian is not None
        else base_names
    )
    if _root_inventory(root, intent.notes_identity) != expected_names:
        raise _error("relocation_layout_changed")
    identities = {
        NUMBERED_LAYOUT.pending: intent.pending_identity,
        NUMBERED_LAYOUT.prepared: intent.prepared_identity,
        NUMBERED_LAYOUT.staged: intent.staged_identity,
    }
    if inbox:
        identities[NUMBERED_LAYOUT.inbox] = intent.inbox_identity
    for name, expected in identities.items():
        _require_private_directory(root / name, expected)
    if intent.obsidian is not None:
        descriptor = _open_bound_directory(root / _OBSIDIAN_NAME)
        try:
            if _directory_authority(descriptor) != intent.obsidian:
                raise _error("relocation_authority_changed")
        finally:
            os.close(descriptor)


def _run_memory_relocation(
    intent: _Intent,
    destination: Path,
    runner: CommandRunner,
) -> None:
    argv = ["memory", "relocate-inbox"]
    if intent.memory_home is not None:
        argv.extend(("--home", str(intent.memory_home)))
    argv.extend(("--to", str(destination)))
    try:
        result = runner.run(argv, timeout_seconds=_MEMORY_TIMEOUT_SECONDS)
    except OSError as error:
        raise _error("memory_relocation_failed", retryable=True) from error
    if result.returncode != 0 or result.stderr:
        raise _error("memory_relocation_failed", retryable=True)
    try:
        payload = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _error("memory_relocation_invalid") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"status"}
        or payload["status"] not in {"relocated", "recovered", "current"}
    ):
        raise _error("memory_relocation_invalid")


def _current_memory_inbox(intent: _Intent, runner: CommandRunner) -> Path:
    paths = resolve_memory_paths(intent.memory_home, runner)
    if paths.inbox_identity != intent.inbox_identity:
        raise _error("relocation_authority_changed")
    return paths.inbox


def _require_root_phase(root: Path, intent: _Intent, *, inbox: bool) -> None:
    _require_private_directory(root, intent.notes_identity)
    _require_children(root, intent, inbox=inbox)


def _initial_intent(
    config: IntakeConfig,
    destination: Path,
    *,
    require_parent_authority: bool = True,
) -> _Intent:
    if config.memory_inbox != config.notes_root / NUMBERED_LAYOUT.inbox:
        raise _configuration_error("relocation_layout_invalid")
    inventory = _root_inventory(config.notes_root, config.notes_identity)
    allowed_inventories = {
        _EXPECTED_CHILDREN,
        tuple(sorted((*_EXPECTED_CHILDREN, _OBSIDIAN_NAME))),
    }
    if inventory not in allowed_inventories:
        raise _configuration_error("relocation_layout_invalid")
    _require_private_directory(config.notes_root, config.notes_identity)
    child_identities = {
        name: directory_identity(config.notes_root / name)
        for name in _EXPECTED_CHILDREN
    }
    if child_identities[NUMBERED_LAYOUT.inbox] != config.inbox_identity:
        raise _error("relocation_authority_changed")
    return _Intent(
        phase=_Phase.PREPARED,
        source=config.notes_root,
        destination=destination,
        memory_home=config.memory_home,
        notes_identity=config.notes_identity,
        inbox_identity=config.inbox_identity,
        pending_identity=child_identities[NUMBERED_LAYOUT.pending],
        staged_identity=child_identities[NUMBERED_LAYOUT.staged],
        prepared_identity=child_identities[NUMBERED_LAYOUT.prepared],
        source_parent=_parent_authority(
            config.notes_root.parent,
            require_owner=require_parent_authority,
        ),
        destination_parent=_parent_authority(
            destination.parent,
            require_owner=require_parent_authority,
        ),
        obsidian=(
            _parent_authority(config.notes_root / _OBSIDIAN_NAME)
            if _OBSIDIAN_NAME in inventory
            else None
        ),
        pending_drop=config.pending_drop,
    )


def _require_parent_authorities(intent: _Intent) -> None:
    source_parent = _open_exact_parent(intent.source.parent, intent.source_parent)
    try:
        destination_parent = _open_exact_parent(
            intent.destination.parent,
            intent.destination_parent,
        )
        os.close(destination_parent)
    finally:
        os.close(source_parent)


def _require_initial_topology(
    state_root: Path,
    intent: _Intent,
    runner: CommandRunner,
) -> None:
    if (
        _paths_overlap(intent.source, intent.destination)
        or _paths_overlap(state_root, intent.source)
        or _paths_overlap(state_root, intent.destination)
        or (
            intent.memory_home is not None
            and _paths_overlap(intent.memory_home, intent.destination)
        )
    ):
        raise _configuration_error("relocation_destination_invalid")
    destination_parent_writable = intent.destination_parent.mode & (
        stat.S_IWGRP | stat.S_IWOTH
    )
    if destination_parent_writable or (
        intent.destination_parent != intent.source_parent
        and intent.destination_parent.mode != 0o700
    ):
        raise _configuration_error("relocation_destination_invalid")
    source_parent_descriptor = _open_exact_parent(
        intent.source.parent,
        intent.source_parent,
    )
    destination_parent_descriptor = _open_exact_parent(
        intent.destination.parent,
        intent.destination_parent,
    )
    try:
        state_identity = directory_identity(state_root)
        if (
            descriptor_volume(source_parent_descriptor) != intent.notes_identity.volume
            or descriptor_volume(destination_parent_descriptor)
            != intent.notes_identity.volume
            or state_identity.volume != intent.inbox_identity.volume
        ):
            raise _configuration_error("relocation_destination_invalid")
    finally:
        os.close(source_parent_descriptor)
        os.close(destination_parent_descriptor)
    if _path_state(intent.destination, intent.notes_identity) != "absent":
        raise _configuration_error("relocation_destination_exists")
    staged_inbox = state_root / _STAGED_INBOX_NAME
    if _path_state(staged_inbox, intent.inbox_identity) != "absent":
        raise _error("relocation_artifact_ambiguous")
    _require_private_directory(intent.source, intent.notes_identity)
    _require_children(intent.source, intent, inbox=True)
    paths = resolve_memory_paths(intent.memory_home, runner)
    if (
        paths.inbox != intent.source / NUMBERED_LAYOUT.inbox
        or paths.inbox_identity != intent.inbox_identity
    ):
        raise _error("relocation_authority_changed")


def _require_current_authority(intent: _Intent, runner: CommandRunner) -> None:
    _require_root_phase(intent.source, intent, inbox=True)
    paths = resolve_memory_paths(intent.memory_home, runner)
    if (
        paths.inbox != intent.source / NUMBERED_LAYOUT.inbox
        or paths.inbox_identity != intent.inbox_identity
    ):
        raise _error("relocation_authority_changed")


def _adopt_current_authority(
    state_root: Path,
    config: IntakeConfig,
    destination: Path,
    runner: CommandRunner,
) -> tuple[IntakeConfig, _Intent]:
    """Explicitly bind the configured paths' current exact directories."""
    try:
        rebound = IntakeConfig(
            notes_root=config.notes_root,
            notes_identity=directory_identity(config.notes_root),
            memory_home=config.memory_home,
            memory_inbox=config.memory_inbox,
            inbox_identity=directory_identity(config.memory_inbox),
            pending_drop=config.pending_drop,
        )
    except IntakeError as error:
        raise _error("relocation_authority_changed") from error
    current_path = destination == config.notes_root
    intent = _initial_intent(
        rebound,
        destination,
        require_parent_authority=not current_path,
    )
    if current_path:
        _require_current_authority(intent, runner)
    else:
        if intent.source_parent.mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise _configuration_error("relocation_destination_invalid")
        _require_initial_topology(state_root, intent, runner)
    updated = config
    if rebound != config:
        try:
            updated = replace_config_paths(
                state_root,
                config,
                config.notes_root,
                rebound.notes_identity,
                config.memory_inbox,
                rebound.inbox_identity,
            )
        except IntakeError as error:
            raise _error("relocation_authority_changed") from error
        if updated != rebound:
            raise _error("relocation_authority_changed")
    if current_path:
        persisted = load_config_record(state_root)
        if persisted != rebound:
            raise _error("relocation_authority_changed")
        updated = persisted
        _require_current_authority(intent, runner)
    return updated, intent


def _rename_no_replace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameatx = library.renameatx_np
    except AttributeError as error:  # pragma: no cover - macOS-only workflow
        raise OSError(errno.ENOTSUP, "exclusive rename is unavailable") from error
    renameatx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameatx(
        source_parent,
        os.fsencode(source_name),
        destination_parent,
        os.fsencode(destination_name),
        _RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


def _rename_root(intent: _Intent) -> None:
    source_parent = _open_exact_parent(intent.source.parent, intent.source_parent)
    try:
        destination_parent = _open_exact_parent(
            intent.destination.parent,
            intent.destination_parent,
        )
    except IntakeError:
        os.close(source_parent)
        raise
    source_descriptor: int | None = None
    try:
        source_state = _path_state(intent.source, intent.notes_identity)
        destination_state = _path_state(intent.destination, intent.notes_identity)
        if source_state == "exact" and destination_state == "absent":
            source_descriptor = os.open(
                intent.source.name,
                _directory_flags(),
                dir_fd=source_parent,
            )
            _require_private_directory(intent.source, intent.notes_identity)
            if _path_state(intent.destination, intent.notes_identity) != "absent":
                raise _error("relocation_layout_changed")
            _rename_no_replace(
                source_parent,
                intent.source.name,
                destination_parent,
                intent.destination.name,
            )
            os.fsync(source_parent)
            os.fsync(destination_parent)
            opened = os.fstat(source_descriptor)
            if (
                DirectoryIdentity(
                    descriptor_volume(source_descriptor),
                    opened.st_ino,
                )
                != intent.notes_identity
            ):
                raise _error("relocation_authority_changed")
            return
        if source_state == "absent" and destination_state == "exact":
            os.fsync(source_parent)
            os.fsync(destination_parent)
            return
        raise _error("relocation_layout_changed")
    except OSError as error:
        raise _error("root_relocation_failed", retryable=True) from error
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        os.close(source_parent)
        os.close(destination_parent)


def _replace_config(state_root: Path, intent: _Intent) -> None:
    current = load_config_record(state_root)
    if current == intent.old_config():
        replace_config_paths(
            state_root,
            current,
            intent.destination,
            intent.notes_identity,
            intent.destination / NUMBERED_LAYOUT.inbox,
            intent.inbox_identity,
        )
        return
    if current == intent.new_config():
        rebound = load_config_record(state_root)
        if rebound != current:
            raise _error("relocation_authority_changed")
        return
    raise _error("relocation_config_changed")


def _recover(
    state_root: Path,
    intent: _Intent,
    runner: CommandRunner,
    fault: RelocationFault,
) -> None:
    _require_parent_authorities(intent)
    staged_inbox = state_root / _STAGED_INBOX_NAME
    if intent.phase is _Phase.PREPARED:
        source_inbox_state = _path_state(
            intent.source / NUMBERED_LAYOUT.inbox,
            intent.inbox_identity,
        )
        staged_inbox_state = _path_state(staged_inbox, intent.inbox_identity)
        if source_inbox_state == "exact" and staged_inbox_state == "absent":
            _require_root_phase(intent.source, intent, inbox=True)
        elif source_inbox_state == "absent" and staged_inbox_state == "exact":
            _require_private_directory(staged_inbox, intent.inbox_identity)
            _require_root_phase(intent.source, intent, inbox=False)
        else:
            raise _error("relocation_layout_changed")
        _run_memory_relocation(intent, staged_inbox, runner)
        fault.checkpoint("inbox_staged_uncommitted")
        _require_private_directory(staged_inbox, intent.inbox_identity)
        _require_root_phase(intent.source, intent, inbox=False)
        if _current_memory_inbox(intent, runner) != staged_inbox:
            raise _error("relocation_authority_changed")
        intent = _advance(state_root, intent, _Phase.INBOX_STAGED)
        fault.checkpoint("inbox_staged")
    if intent.phase is _Phase.INBOX_STAGED:
        if _current_memory_inbox(intent, runner) != staged_inbox:
            raise _error("relocation_authority_changed")
        _require_private_directory(staged_inbox, intent.inbox_identity)
        source_state = _path_state(intent.source, intent.notes_identity)
        destination_state = _path_state(intent.destination, intent.notes_identity)
        if source_state == "exact" and destination_state == "absent":
            _require_root_phase(intent.source, intent, inbox=False)
        elif source_state == "absent" and destination_state == "exact":
            _require_root_phase(intent.destination, intent, inbox=False)
        else:
            raise _error("relocation_layout_changed")
        fault.checkpoint("before_root_move")
        _rename_root(intent)
        fault.checkpoint("root_moved_uncommitted")
        _require_root_phase(intent.destination, intent, inbox=False)
        intent = _advance(state_root, intent, _Phase.ROOT_MOVED)
        fault.checkpoint("root_moved")
    if intent.phase is _Phase.ROOT_MOVED:
        staged_inbox_state = _path_state(staged_inbox, intent.inbox_identity)
        final_inbox = intent.destination / NUMBERED_LAYOUT.inbox
        final_inbox_state = _path_state(final_inbox, intent.inbox_identity)
        if staged_inbox_state == "exact" and final_inbox_state == "absent":
            _require_private_directory(staged_inbox, intent.inbox_identity)
            _require_root_phase(intent.destination, intent, inbox=False)
        elif staged_inbox_state == "absent" and final_inbox_state == "exact":
            _require_root_phase(intent.destination, intent, inbox=True)
        else:
            raise _error("relocation_layout_changed")
        _run_memory_relocation(intent, final_inbox, runner)
        fault.checkpoint("inbox_final_uncommitted")
        _require_root_phase(intent.destination, intent, inbox=True)
        if _current_memory_inbox(intent, runner) != final_inbox:
            raise _error("relocation_authority_changed")
        intent = _advance(state_root, intent, _Phase.INBOX_FINAL)
        fault.checkpoint("inbox_final")
    if intent.phase is _Phase.INBOX_FINAL:
        _require_root_phase(intent.destination, intent, inbox=True)
        if (
            _current_memory_inbox(intent, runner)
            != intent.destination / NUMBERED_LAYOUT.inbox
        ):
            raise _error("relocation_authority_changed")
        _replace_config(state_root, intent)
        fault.checkpoint("config_replaced_uncommitted")
        intent = _advance(state_root, intent, _Phase.CONFIG_REPLACED)
        fault.checkpoint("config_replaced")
    if intent.phase is _Phase.CONFIG_REPLACED:
        _require_parent_authorities(intent)
        _require_children(intent.destination, intent, inbox=True)
        if load_config_record(state_root) != intent.new_config():
            raise _error("relocation_config_changed")
        paths = resolve_memory_paths(intent.memory_home, runner)
        if (
            paths.inbox != intent.destination / NUMBERED_LAYOUT.inbox
            or paths.inbox_identity != intent.inbox_identity
        ):
            raise _error("relocation_authority_changed")
        _remove_intent(state_root)
        fault.checkpoint("intent_removed")


def relocate_notes_root(
    state_root: Path,
    destination: Path,
    runner: CommandRunner,
    fault: RelocationFault = _NO_RELOCATION_FAULT,
    *,
    adopt_current_authority: bool = False,
) -> RelocationResult:
    """Relocate one exact configured root through Memory's public transition."""
    target = _normalized_path(destination)
    store = TransactionStore.for_operation(state_root)
    with store.lock():
        active = store.active()
        if active is not None:
            raise IntakeError("transaction_active", "state", state=active.state)
        # Local import avoids a module cycle: layout migration itself consumes
        # this module's public pending-intent check.
        from staged_memory_intake.layout_migration import layout_migration_pending

        if layout_migration_pending(state_root):
            raise IntakeError(
                "layout_migration_pending",
                "state",
                retryable=True,
            )
        intent = _load_intent(state_root)
        if intent is not None:
            target = _normalized_destination(target)
            if intent.destination != target:
                raise _configuration_error("relocation_destination_changed")
            _recover(state_root, intent, runner, fault)
            return RelocationResult("recovered")

        # The explicit owner rebind must see the exact record: automatic
        # adoption refuses a replaced root's changed inode, and that refusal
        # ahead of --adopt-current-authority would cut off the one escape
        # designed for that state.
        config = (
            load_config_record(state_root)
            if adopt_current_authority
            else adopt_config_record(state_root)
        )
        target = _normalized_destination(
            target,
            require_parent_owner=not (
                adopt_current_authority and target == config.notes_root
            ),
        )
        adopted_intent: _Intent | None = None
        if adopt_current_authority:
            config, adopted_intent = _adopt_current_authority(
                state_root,
                config,
                target,
                runner,
            )
        if (
            config.notes_root == target
            and config.memory_inbox == target / NUMBERED_LAYOUT.inbox
        ):
            current_intent = (
                adopted_intent
                if adopted_intent is not None
                else _initial_intent(
                    config,
                    target,
                    require_parent_authority=True,
                )
            )
            _require_current_authority(current_intent, runner)
            if load_config_record(state_root) != config:
                raise _error("relocation_authority_changed")
            return RelocationResult("current")
        intent = _initial_intent(config, target)
        _require_initial_topology(state_root, intent, runner)
        _write_intent(state_root, intent)
        fault.checkpoint("intent_published")
        _recover(state_root, intent, runner, fault)
        return RelocationResult("relocated")


def abandon_unsupported_intent(state_root: Path) -> bool:
    """Quarantine one pre-v2 pending intent so commands can run again.

    A device-bound pending intent is refused, never reinterpreted -- but the
    refusal used to be terminal: every command's pending gate raised on it
    and nothing could remove it. Only a readable JSON object whose schema
    names an older relocation intent qualifies; a current-schema intent is live
    recoverable state and a malformed file is evidence of something else, so
    neither is ever touched. The quarantined bytes stay for the owner.
    """
    store = TransactionStore.for_operation(state_root)
    with store.lock():
        try:
            payload = json.loads(
                read_private_regular(state_root, _INTENT_NAME, limit=_INTENT_LIMIT)
            )
        except IntakeError, UnicodeError, json.JSONDecodeError:
            return False
        if not isinstance(payload, dict):
            return False
        schema = payload.get("schema")
        if (
            not isinstance(schema, str)
            or not schema.startswith("staged-memory-intake.root-relocation.")
            or schema == _INTENT_SCHEMA
        ):
            return False
        quarantine_state_entry(state_root, _INTENT_NAME)
        return True


__all__ = ["NoRelocationFault", "relocate_notes_root", "relocation_pending"]
