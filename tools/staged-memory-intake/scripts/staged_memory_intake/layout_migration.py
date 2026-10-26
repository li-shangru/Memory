"""Crash-recoverable migration from legacy to numbered workflow names."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import stat
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal

from staged_memory_intake.config import (
    adopt_config_record,
    load_config_record,
    replace_config_paths,
    resolve_memory_paths,
)
from staged_memory_intake.layout import (
    LEGACY_LAYOUT,
    NUMBERED_LAYOUT,
    OBSIDIAN_DIRECTORY,
)
from staged_memory_intake.model import (
    CommandRunner,
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    LayoutMigrationFault,
    LayoutMigrationResult,
    NoLayoutMigrationFault,
    require_volume_uuid,
    reraise_volume_unidentified,
)
from staged_memory_intake.relocation import relocation_pending
from staged_memory_intake.securefs import (
    atomic_private_json,
    descriptor_volume,
    directory_identity,
    entry_volume,
    quarantine_state_entry,
    read_private_regular,
)
from staged_memory_intake.state import TransactionStore

_INTENT_NAME: Final = ".layout-migration.intent.json"
_INTENT_SCHEMA: Final = "staged-memory-intake.layout-migration-intent.v2"
_OPTIONAL_INTENT_KEYS: Final = frozenset({"pending_drop"})
_INTENT_LIMIT: Final = 64 * 1024
_MEMORY_TIMEOUT_SECONDS: Final = 120.0
_RENAME_EXCL: Final = 0x00000004
_NO_FAULT: Final = NoLayoutMigrationFault()


class _Phase(StrEnum):
    PREPARED = "prepared"
    INBOX_NUMBERED = "inbox_numbered"
    PENDING_NUMBERED = "pending_numbered"
    STAGED_NUMBERED = "staged_numbered"
    PREPARED_NUMBERED = "prepared_numbered"
    CONFIG_REPLACED = "config_replaced"


_Role = Literal["pending", "staged", "prepared", "inbox"]
_ROLES: Final[tuple[_Role, ...]] = ("pending", "staged", "prepared", "inbox")


@dataclass(frozen=True, slots=True)
class _DirectoryAuthority:
    identity: DirectoryIdentity
    owner: int
    mode: int


@dataclass(frozen=True, slots=True)
class _Intent:
    phase: _Phase
    notes_root: Path
    memory_home: Path | None
    notes_identity: DirectoryIdentity
    inbox_identity: DirectoryIdentity
    pending_identity: DirectoryIdentity
    staged_identity: DirectoryIdentity
    prepared_identity: DirectoryIdentity
    obsidian: _DirectoryAuthority | None
    pending_drop: bool

    def identity(self, role: _Role) -> DirectoryIdentity:
        if role == "pending":
            return self.pending_identity
        if role == "staged":
            return self.staged_identity
        if role == "prepared":
            return self.prepared_identity
        return self.inbox_identity

    def old_config(self) -> IntakeConfig:
        return IntakeConfig(
            notes_root=self.notes_root,
            notes_identity=self.notes_identity,
            memory_home=self.memory_home,
            memory_inbox=self.notes_root / LEGACY_LAYOUT.inbox,
            inbox_identity=self.inbox_identity,
            pending_drop=self.pending_drop,
        )

    def new_config(self) -> IntakeConfig:
        return IntakeConfig(
            notes_root=self.notes_root,
            notes_identity=self.notes_identity,
            memory_home=self.memory_home,
            memory_inbox=self.notes_root / NUMBERED_LAYOUT.inbox,
            inbox_identity=self.inbox_identity,
            pending_drop=self.pending_drop,
        )


def _error(code: str, *, retryable: bool = False) -> IntakeError:
    return IntakeError(code, "drift", retryable=retryable)


def _configuration_error(code: str) -> IntakeError:
    return IntakeError(code, "configuration")


def _identity_payload(
    identity: DirectoryIdentity,
    prefix: str,
) -> dict[str, int | str]:
    return {
        f"{prefix}_volume": require_volume_uuid(identity.volume),
        f"{prefix}_inode": identity.inode,
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
        **_identity_payload(authority.identity, prefix),
        f"{prefix}_owner": authority.owner,
        f"{prefix}_mode": authority.mode,
    }


def _intent_payload(intent: _Intent) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": _INTENT_SCHEMA,
        "phase": intent.phase.value,
        "notes_root": str(intent.notes_root),
        "memory_home": (
            None if intent.memory_home is None else str(intent.memory_home)
        ),
        **_identity_payload(intent.notes_identity, "notes"),
        **_identity_payload(intent.inbox_identity, "inbox"),
        **_identity_payload(intent.pending_identity, "pending"),
        **_identity_payload(intent.staged_identity, "staged"),
        **_identity_payload(intent.prepared_identity, "prepared"),
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
    return _DirectoryAuthority(
        identity=_parse_identity(raw, prefix),
        owner=_strict_int(raw[f"{prefix}_owner"]),
        mode=_strict_int(raw[f"{prefix}_mode"]),
    )


def _parse_intent(encoded: bytes) -> _Intent:
    identity_prefixes = ("notes", "inbox", "pending", "staged", "prepared")
    expected = {
        "schema",
        "phase",
        "notes_root",
        "memory_home",
        *(
            f"{prefix}_{field}"
            for prefix in identity_prefixes
            for field in ("volume", "inode")
        ),
        *(f"obsidian_{field}" for field in ("volume", "inode", "owner", "mode")),
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
            notes_root=_parse_path(raw["notes_root"]),
            memory_home=memory_home,
            notes_identity=_parse_identity(raw, "notes"),
            inbox_identity=_parse_identity(raw, "inbox"),
            pending_identity=_parse_identity(raw, "pending"),
            staged_identity=_parse_identity(raw, "staged"),
            prepared_identity=_parse_identity(raw, "prepared"),
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
        raise _error("layout_migration_intent_invalid") from error
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
        raise _error("layout_migration_intent_invalid")
    return intent


def _load_intent(state_root: Path) -> _Intent | None:
    path = state_root / _INTENT_NAME
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _error("layout_migration_intent_invalid") from error
    try:
        encoded = read_private_regular(state_root, _INTENT_NAME, limit=_INTENT_LIMIT)
    except IntakeError as error:
        raise _error("layout_migration_intent_invalid") from error
    return _parse_intent(encoded)


def layout_migration_pending(state_root: Path) -> bool:
    """Report a valid pending layout migration without creating state."""
    try:
        state_root.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _error("layout_migration_intent_invalid") from error
    return _load_intent(state_root) is not None


def _write_intent(state_root: Path, intent: _Intent) -> None:
    atomic_private_json(state_root / _INTENT_NAME, _intent_payload(intent))


def _advance(state_root: Path, intent: _Intent, phase: _Phase) -> _Intent:
    updated = replace(intent, phase=phase)
    _write_intent(state_root, updated)
    return updated


def _remove_intent(state_root: Path) -> None:
    descriptor = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.unlink(_INTENT_NAME, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_root(intent: _Intent) -> int:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            intent.notes_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        observed = DirectoryIdentity(
            descriptor_volume(descriptor),
            metadata.st_ino,
        )
    except (IntakeError, OSError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or observed != intent.notes_identity
    ):
        os.close(descriptor)
        raise _error("layout_migration_authority_changed")
    return descriptor


def _entry_state(
    root_descriptor: int,
    name: str,
    expected: DirectoryIdentity,
) -> Literal["absent", "exact", "other"]:
    try:
        metadata = os.stat(
            name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700
            and metadata.st_ino == expected.inode
            and entry_volume(root_descriptor, name) == expected.volume
        ):
            return "exact"
        return "other"
    except FileNotFoundError:
        return "absent"
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error


def _layout_for(
    intent: _Intent,
    numbered_roles: frozenset[_Role],
) -> tuple[str, ...]:
    names: list[str] = []
    for role in _ROLES:
        layout = NUMBERED_LAYOUT if role in numbered_roles else LEGACY_LAYOUT
        names.append(getattr(layout, role))
    if intent.obsidian is not None:
        names.append(OBSIDIAN_DIRECTORY)
    return tuple(sorted(names))


def _require_obsidian(root_descriptor: int, intent: _Intent) -> None:
    if intent.obsidian is None:
        return
    try:
        metadata = os.stat(
            OBSIDIAN_DIRECTORY,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        volume = entry_volume(root_descriptor, OBSIDIAN_DIRECTORY)
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error
    observed = _DirectoryAuthority(
        identity=DirectoryIdentity(volume, metadata.st_ino),
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )
    if not stat.S_ISDIR(metadata.st_mode) or observed != intent.obsidian:
        raise _error("layout_migration_authority_changed")


def _require_layout(intent: _Intent, numbered_roles: frozenset[_Role]) -> None:
    descriptor = _open_root(intent)
    try:
        if tuple(sorted(os.listdir(descriptor))) != _layout_for(
            intent,
            numbered_roles,
        ):
            raise _error("layout_migration_layout_changed")
        for role in _ROLES:
            expected_layout = (
                NUMBERED_LAYOUT if role in numbered_roles else LEGACY_LAYOUT
            )
            alternate_layout = (
                LEGACY_LAYOUT if role in numbered_roles else NUMBERED_LAYOUT
            )
            if (
                _entry_state(
                    descriptor,
                    getattr(expected_layout, role),
                    intent.identity(role),
                )
                != "exact"
                or _entry_state(
                    descriptor,
                    getattr(alternate_layout, role),
                    intent.identity(role),
                )
                != "absent"
            ):
                raise _error("layout_migration_layout_changed")
        _require_obsidian(descriptor, intent)
    finally:
        os.close(descriptor)


def _directory_authority(path: Path) -> _DirectoryAuthority:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        volume = descriptor_volume(descriptor)
    except (IntakeError, OSError) as error:
        if isinstance(error, IntakeError):
            reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise _error("layout_migration_authority_changed")
    return _DirectoryAuthority(
        identity=DirectoryIdentity(volume, metadata.st_ino),
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _legacy_intent(config: IntakeConfig) -> _Intent:
    if config.memory_inbox != config.notes_root / LEGACY_LAYOUT.inbox:
        raise _configuration_error("layout_migration_not_legacy")
    try:
        current_notes_identity = directory_identity(config.notes_root)
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error
    if current_notes_identity != config.notes_identity:
        raise _error("layout_migration_authority_changed")
    try:
        identities: dict[_Role, DirectoryIdentity] = {
            role: directory_identity(config.notes_root / getattr(LEGACY_LAYOUT, role))
            for role in _ROLES
        }
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("layout_migration_layout_changed") from error
    if identities["inbox"] != config.inbox_identity:
        raise _error("layout_migration_authority_changed")
    obsidian_path = config.notes_root / OBSIDIAN_DIRECTORY
    try:
        obsidian_path.lstat()
    except FileNotFoundError:
        obsidian = None
    except OSError as error:
        raise _error("layout_migration_authority_changed") from error
    else:
        obsidian = _directory_authority(obsidian_path)
    intent = _Intent(
        phase=_Phase.PREPARED,
        notes_root=config.notes_root,
        memory_home=config.memory_home,
        notes_identity=config.notes_identity,
        inbox_identity=config.inbox_identity,
        pending_identity=identities["pending"],
        staged_identity=identities["staged"],
        prepared_identity=identities["prepared"],
        obsidian=obsidian,
        pending_drop=config.pending_drop,
    )
    _require_layout(intent, frozenset())
    return intent


def _initial_intent(config: IntakeConfig, runner: CommandRunner) -> _Intent:
    intent = _legacy_intent(config)
    paths = resolve_memory_paths(config.memory_home, runner)
    if (
        paths.inbox != config.notes_root / LEGACY_LAYOUT.inbox
        or paths.inbox_identity != config.inbox_identity
    ):
        raise _error("layout_migration_authority_changed")
    return intent


def layout_migration_required(state_root: Path) -> bool:
    """Recognize an exact legacy layout without invoking Memory or mutating it."""
    try:
        state_root.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _error("layout_migration_config_changed") from error
    config = load_config_record(state_root)
    if config.memory_inbox != config.notes_root / LEGACY_LAYOUT.inbox:
        return False
    _legacy_intent(config)
    return True


def _current_intent(config: IntakeConfig, runner: CommandRunner) -> _Intent:
    if config.memory_inbox != config.notes_root / NUMBERED_LAYOUT.inbox:
        raise _configuration_error("layout_migration_config_changed")
    try:
        current_notes_identity = directory_identity(config.notes_root)
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("layout_migration_authority_changed") from error
    if current_notes_identity != config.notes_identity:
        raise _error("layout_migration_authority_changed")
    try:
        identities: dict[_Role, DirectoryIdentity] = {
            role: directory_identity(config.notes_root / getattr(NUMBERED_LAYOUT, role))
            for role in _ROLES
        }
    except IntakeError as error:
        reraise_volume_unidentified(error)
        raise _error("layout_migration_layout_changed") from error
    if identities["inbox"] != config.inbox_identity:
        raise _error("layout_migration_authority_changed")
    obsidian_path = config.notes_root / OBSIDIAN_DIRECTORY
    try:
        obsidian_path.lstat()
    except FileNotFoundError:
        obsidian = None
    except OSError as error:
        raise _error("layout_migration_authority_changed") from error
    else:
        obsidian = _directory_authority(obsidian_path)
    intent = _Intent(
        phase=_Phase.CONFIG_REPLACED,
        notes_root=config.notes_root,
        memory_home=config.memory_home,
        notes_identity=config.notes_identity,
        inbox_identity=config.inbox_identity,
        pending_identity=identities["pending"],
        staged_identity=identities["staged"],
        prepared_identity=identities["prepared"],
        obsidian=obsidian,
        pending_drop=config.pending_drop,
    )
    _require_layout(intent, frozenset(_ROLES))
    paths = resolve_memory_paths(config.memory_home, runner)
    if (
        paths.inbox != config.memory_inbox
        or paths.inbox_identity != config.inbox_identity
    ):
        raise _error("layout_migration_authority_changed")
    return intent


def _run_memory_relocation(intent: _Intent, runner: CommandRunner) -> None:
    destination = intent.notes_root / NUMBERED_LAYOUT.inbox
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


def _require_memory_inbox(intent: _Intent, runner: CommandRunner) -> None:
    paths = resolve_memory_paths(intent.memory_home, runner)
    if (
        paths.inbox != intent.notes_root / NUMBERED_LAYOUT.inbox
        or paths.inbox_identity != intent.inbox_identity
    ):
        raise _error("layout_migration_authority_changed")


def _rename_no_replace(
    parent_descriptor: int,
    source_name: str,
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
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(destination_name),
        _RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


def _rename_role(intent: _Intent, role: _Role) -> None:
    descriptor = _open_root(intent)
    try:
        legacy_name = getattr(LEGACY_LAYOUT, role)
        numbered_name = getattr(NUMBERED_LAYOUT, role)
        legacy_state = _entry_state(descriptor, legacy_name, intent.identity(role))
        numbered_state = _entry_state(
            descriptor,
            numbered_name,
            intent.identity(role),
        )
        if legacy_state == "exact" and numbered_state == "absent":
            _rename_no_replace(descriptor, legacy_name, numbered_name)
            os.fsync(descriptor)
            return
        if legacy_state == "absent" and numbered_state == "exact":
            os.fsync(descriptor)
            return
        raise _error("layout_migration_layout_changed")
    except OSError as error:
        raise _error("layout_migration_rename_failed", retryable=True) from error
    finally:
        os.close(descriptor)


def _replace_config(state_root: Path, intent: _Intent) -> None:
    current = load_config_record(state_root)
    if current == intent.old_config():
        replace_config_paths(
            state_root,
            current,
            intent.notes_root,
            intent.notes_identity,
            intent.notes_root / NUMBERED_LAYOUT.inbox,
            intent.inbox_identity,
        )
        return
    if current == intent.new_config():
        return
    raise _error("layout_migration_config_changed")


def _require_config_phase(state_root: Path, intent: _Intent) -> None:
    try:
        current = load_config_record(state_root)
    except IntakeError as error:
        raise _error("layout_migration_config_changed") from error
    allowed: tuple[IntakeConfig, ...]
    if intent.phase is _Phase.CONFIG_REPLACED:
        allowed = (intent.new_config(),)
    elif intent.phase is _Phase.PREPARED_NUMBERED:
        # Config replacement may have committed before its phase write.
        allowed = (intent.old_config(), intent.new_config())
    else:
        allowed = (intent.old_config(),)
    if current not in allowed:
        raise _error("layout_migration_config_changed")


def _require_adjacent_layout(
    intent: _Intent,
    before: frozenset[_Role],
    after: frozenset[_Role],
) -> frozenset[_Role]:
    try:
        _require_layout(intent, before)
    except IntakeError as error:
        if error.code != "layout_migration_layout_changed":
            raise
        _require_layout(intent, after)
        return after
    return before


def _require_memory_before_relocation(
    intent: _Intent,
    runner: CommandRunner,
    numbered_roles: frozenset[_Role],
) -> None:
    try:
        paths = resolve_memory_paths(intent.memory_home, runner)
    except IntakeError as error:
        # A previously started Memory relocation fails ordinary `paths` closed;
        # only the exact retry below can finish that public transition.
        if error.code == "memory_paths_failed":
            return
        raise
    layout = NUMBERED_LAYOUT if "inbox" in numbered_roles else LEGACY_LAYOUT
    if (
        paths.inbox != intent.notes_root / layout.inbox
        or paths.inbox_identity != intent.inbox_identity
    ):
        raise _error("layout_migration_authority_changed")


def _recover(
    state_root: Path,
    intent: _Intent,
    runner: CommandRunner,
    fault: LayoutMigrationFault,
) -> None:
    _require_config_phase(state_root, intent)
    if intent.phase is _Phase.PREPARED:
        before = frozenset[_Role]()
        after = frozenset[_Role]({"inbox"})
        observed = _require_adjacent_layout(intent, before, after)
        _require_memory_before_relocation(intent, runner, observed)
        _run_memory_relocation(intent, runner)
        fault.checkpoint("inbox_numbered_uncommitted")
        _require_layout(intent, after)
        _require_memory_inbox(intent, runner)
        intent = _advance(state_root, intent, _Phase.INBOX_NUMBERED)
        fault.checkpoint("inbox_numbered")
    if intent.phase is _Phase.INBOX_NUMBERED:
        _require_config_phase(state_root, intent)
        before = frozenset[_Role]({"inbox"})
        after = frozenset[_Role]({"pending", "inbox"})
        _require_adjacent_layout(intent, before, after)
        _require_memory_inbox(intent, runner)
        _rename_role(intent, "pending")
        fault.checkpoint("pending_numbered_uncommitted")
        _require_layout(intent, after)
        intent = _advance(state_root, intent, _Phase.PENDING_NUMBERED)
        fault.checkpoint("pending_numbered")
    if intent.phase is _Phase.PENDING_NUMBERED:
        _require_config_phase(state_root, intent)
        before = frozenset[_Role]({"pending", "inbox"})
        after = frozenset[_Role]({"pending", "staged", "inbox"})
        _require_adjacent_layout(intent, before, after)
        _require_memory_inbox(intent, runner)
        _rename_role(intent, "staged")
        fault.checkpoint("staged_numbered_uncommitted")
        _require_layout(intent, after)
        intent = _advance(state_root, intent, _Phase.STAGED_NUMBERED)
        fault.checkpoint("staged_numbered")
    if intent.phase is _Phase.STAGED_NUMBERED:
        _require_config_phase(state_root, intent)
        before = frozenset[_Role]({"pending", "staged", "inbox"})
        after = frozenset[_Role](_ROLES)
        _require_adjacent_layout(intent, before, after)
        _require_memory_inbox(intent, runner)
        _rename_role(intent, "prepared")
        fault.checkpoint("prepared_numbered_uncommitted")
        _require_layout(intent, after)
        intent = _advance(state_root, intent, _Phase.PREPARED_NUMBERED)
        fault.checkpoint("prepared_numbered")
    if intent.phase is _Phase.PREPARED_NUMBERED:
        _require_config_phase(state_root, intent)
        final_layout = frozenset[_Role](_ROLES)
        _require_layout(intent, final_layout)
        _require_memory_inbox(intent, runner)
        _replace_config(state_root, intent)
        fault.checkpoint("config_replaced_uncommitted")
        intent = _advance(state_root, intent, _Phase.CONFIG_REPLACED)
        fault.checkpoint("config_replaced")
    if intent.phase is _Phase.CONFIG_REPLACED:
        _require_config_phase(state_root, intent)
        _require_layout(intent, frozenset[_Role](_ROLES))
        if load_config_record(state_root) != intent.new_config():
            raise _error("layout_migration_config_changed")
        _require_memory_inbox(intent, runner)
        _remove_intent(state_root)
        fault.checkpoint("intent_removed")


def migrate_layout(
    state_root: Path,
    runner: CommandRunner,
    fault: LayoutMigrationFault = _NO_FAULT,
) -> LayoutMigrationResult:
    """Migrate one configured legacy root through exact durable phases."""
    store = TransactionStore.for_operation(state_root)
    with store.lock():
        active = store.active()
        if active is not None:
            raise IntakeError("transaction_active", "state", state=active.state)
        if relocation_pending(state_root):
            raise IntakeError("relocation_pending", "state", retryable=True)
        intent = _load_intent(state_root)
        if intent is not None:
            _recover(state_root, intent, runner, fault)
            return LayoutMigrationResult("recovered")
        config = adopt_config_record(state_root)
        if config.memory_inbox == config.notes_root / NUMBERED_LAYOUT.inbox:
            _current_intent(config, runner)
            return LayoutMigrationResult("current")
        intent = _initial_intent(config, runner)
        _write_intent(state_root, intent)
        fault.checkpoint("intent_published")
        _recover(state_root, intent, runner, fault)
        return LayoutMigrationResult("migrated")


def abandon_unsupported_intent(state_root: Path) -> bool:
    """Quarantine one pre-v2 pending intent so commands can run again.

    A device-bound pending intent is refused, never reinterpreted -- but the
    refusal used to be terminal: every command's pending gate raised on it
    and nothing could remove it. Only a readable JSON object whose schema
    names an older layout-migration intent qualifies; a current-schema intent is live
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
            or not schema.startswith("staged-memory-intake.layout-migration-intent.")
            or schema == _INTENT_SCHEMA
        ):
            return False
        quarantine_state_entry(state_root, _INTENT_NAME)
        return True


__all__ = [
    "NoLayoutMigrationFault",
    "abandon_unsupported_intent",
    "layout_migration_pending",
    "layout_migration_required",
    "migrate_layout",
]
