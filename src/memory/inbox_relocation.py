"""Crash-recoverable relocation of one configured external Inbox."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from memory.errors import (
    InvalidArgumentError,
    InvalidRuntimeError,
    StoreBusyError,
    StoreUnavailableError,
)
from memory.model import RuntimePaths, StoreIdentity
from memory.runtime import (
    INBOX_RELOCATION_ARTIFACT_NAMES,
    _authorize_runtime_use_for_relocation,
    _validated_inbox_path,
    _writer_lock,
    ui_session_lock,
)

_INTENT_NAME: Final = ".inbox-relocation.intent.json"
_INTENT_TEMP_NAME: Final = ".inbox-relocation.intent.tmp"
_RUNTIME_TEMP_NAME: Final = ".inbox-relocation.runtime.tmp"
_INTENT_SCHEMA: Final = "memory.inbox-relocation.v1"
_INTENT_LIMIT: Final = 64 * 1024
_IDENTITY_LIMIT: Final = 64 * 1024
_MOVER_TIMEOUT_SECONDS: Final = 60.0
_MOVER_OUTPUT_LIMIT: Final = 16 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_STORE_ID = re.compile(r"[0-9a-f]{32}")

CREATE_DIRECTORY_REFERENCE_SCRIPT: Final = r"""ObjC.import('Foundation');
function attributes(manager, url) {
    const path = ObjC.unwrap(url.path);
    const value = manager.attributesOfItemAtPathError($(path), null);
    if (!value) { throw new Error('reference unavailable'); }
    return {
        device: ObjC.unwrap(value.objectForKey($.NSFileSystemNumber).stringValue),
        inode: ObjC.unwrap(value.objectForKey($.NSFileSystemFileNumber).stringValue),
        mode: ObjC.unwrap(value.objectForKey($.NSFilePosixPermissions).stringValue)
    };
}
function run(argv) {
    if (argv.length !== 2) { throw new Error('invalid arguments'); }
    const manager = $.NSFileManager.defaultManager;
    const source = $.NSURL.fileURLWithPath($(argv[0])).fileReferenceURL;
    const parent = $.NSURL.fileURLWithPath($(argv[1])).fileReferenceURL;
    if (!source || !parent) { throw new Error('reference unavailable'); }
    const sourceIdentity = attributes(manager, source);
    const parentIdentity = attributes(manager, parent);
    return JSON.stringify({
        destination_parent_device: parentIdentity.device,
        destination_parent_inode: parentIdentity.inode,
        destination_parent_mode: parentIdentity.mode,
        destination_parent_reference: ObjC.unwrap(parent.absoluteString),
        source_device: sourceIdentity.device,
        source_inode: sourceIdentity.inode,
        source_mode: sourceIdentity.mode,
        source_reference: ObjC.unwrap(source.absoluteString)
    });
}"""

MOVE_DIRECTORY_REFERENCE_SCRIPT: Final = r"""ObjC.import('Foundation');
function identity(manager, url) {
    const path = ObjC.unwrap(url.path);
    const value = manager.attributesOfItemAtPathError($(path), null);
    if (!value) { throw new Error('reference unavailable'); }
    return [
        ObjC.unwrap(value.objectForKey($.NSFileSystemNumber).stringValue),
        ObjC.unwrap(value.objectForKey($.NSFileSystemFileNumber).stringValue),
        ObjC.unwrap(value.objectForKey($.NSFilePosixPermissions).stringValue)
    ];
}
function sameIdentity(observed, argv, offset) {
    return observed[0] === argv[offset] && observed[1] === argv[offset + 1] &&
        observed[2] === argv[offset + 2];
}
function run(argv) {
    if (argv.length !== 10) { throw new Error('invalid arguments'); }
    const manager = $.NSFileManager.defaultManager;
    const source = $.NSURL.URLWithString($(argv[0]));
    const parent = $.NSURL.URLWithString($(argv[1]));
    if (!source || !parent || !source.isFileReferenceURL ||
        !parent.isFileReferenceURL) { throw new Error('invalid reference'); }
    if (!sameIdentity(identity(manager, source), argv, 2) ||
        !sameIdentity(identity(manager, parent), argv, 5)) {
        throw new Error('identity changed');
    }
    const parentPath = ObjC.unwrap(parent.path);
    if (parentPath !== argv[8]) { throw new Error('parent changed'); }
    const destinationPath = parentPath + '/' + argv[9];
    if (manager.fileExistsAtPath($(destinationPath))) {
        throw new Error('destination exists');
    }
    const destination = $.NSURL.fileURLWithPath($(destinationPath));
    const moved = manager.moveItemAtURLToURLError(source, destination, null);
    if (!moved) { throw new Error('move failed'); }
    return '';
}"""


@dataclass(frozen=True, slots=True)
class InboxRelocationResult:
    """Content-free result of one exact Inbox relocation request."""

    status: Literal["current", "relocated", "recovered"]


@dataclass(frozen=True, slots=True)
class CompletedCommand:
    """Bounded subprocess result used by the macOS reference adapter."""

    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    """Argument-array command boundary for the macOS reference adapter."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand: ...


@dataclass(frozen=True, slots=True)
class _SubprocessRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> CompletedCommand:
        result = subprocess.run(
            argv,
            shell=False,
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
class DirectoryMoveSource:
    """One exact open Inbox retained through the same-reference move."""

    path: Path
    descriptor: int
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, slots=True)
class DestinationParent:
    """One exact open destination parent retained through the move."""

    path: Path
    descriptor: int
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, slots=True)
class DirectoryMoveReference:
    """Opaque pair of Foundation file-reference URLs."""

    token: object


@dataclass(frozen=True, slots=True)
class _FoundationReference:
    source_url: str
    destination_parent_url: str


class InboxMover(Protocol):
    """Exact directory-reference move boundary."""

    def create_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
    ) -> DirectoryMoveReference: ...

    def move_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
        destination_name: str,
        reference: DirectoryMoveReference,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class MacOSFileReferenceMover:
    """Move one exact directory via validated Foundation file references."""

    runner: CommandRunner = _SubprocessRunner()

    @staticmethod
    def _require_live_directory(
        descriptor: int,
        expected: tuple[int, int, int],
    ) -> None:
        try:
            metadata = os.fstat(descriptor)
        except OSError as error:
            raise InvalidArgumentError(
                "Inbox relocation identity is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino, metadata.st_mode) != expected
        ):
            raise InvalidArgumentError("Inbox relocation identity changed")

    def _run(self, argv: Sequence[str]) -> CompletedCommand:
        try:
            result = self.runner.run(argv, timeout_seconds=_MOVER_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as error:
            raise InvalidArgumentError("Inbox reference move failed") from error
        if (
            result.returncode != 0
            or result.stderr
            or len(result.stdout) > _MOVER_OUTPUT_LIMIT
        ):
            raise InvalidArgumentError("Inbox reference move failed")
        return result

    def create_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
    ) -> DirectoryMoveReference:
        self._require_live_directory(
            source.descriptor,
            (source.device, source.inode, source.mode),
        )
        self._require_live_directory(
            destination_parent.descriptor,
            (
                destination_parent.device,
                destination_parent.inode,
                destination_parent.mode,
            ),
        )
        result = self._run(
            [
                "/usr/bin/osascript",
                "-l",
                "JavaScript",
                "-e",
                CREATE_DIRECTORY_REFERENCE_SCRIPT,
                str(source.path),
                str(destination_parent.path),
            ]
        )
        try:
            payload: Any = json.loads(result.stdout)
            expected_keys = {
                "destination_parent_device",
                "destination_parent_inode",
                "destination_parent_mode",
                "destination_parent_reference",
                "source_device",
                "source_inode",
                "source_mode",
                "source_reference",
            }
            if not isinstance(payload, dict) or set(payload) != expected_keys:
                raise ValueError
            source_identity = (
                int(payload["source_device"]),
                int(payload["source_inode"]),
                int(payload["source_mode"]),
            )
            parent_identity = (
                int(payload["destination_parent_device"]),
                int(payload["destination_parent_inode"]),
                int(payload["destination_parent_mode"]),
            )
            source_url = payload["source_reference"]
            parent_url = payload["destination_parent_reference"]
            if (
                source_identity
                != (source.device, source.inode, stat.S_IMODE(source.mode))
                or parent_identity
                != (
                    destination_parent.device,
                    destination_parent.inode,
                    stat.S_IMODE(destination_parent.mode),
                )
                or not isinstance(source_url, str)
                or not source_url.startswith("file:")
                or not isinstance(parent_url, str)
                or not parent_url.startswith("file:")
            ):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise InvalidArgumentError("Inbox reference identity is invalid") from error
        return DirectoryMoveReference(_FoundationReference(source_url, parent_url))

    def move_reference(
        self,
        source: DirectoryMoveSource,
        destination_parent: DestinationParent,
        destination_name: str,
        reference: DirectoryMoveReference,
    ) -> None:
        if not isinstance(reference.token, _FoundationReference):
            raise InvalidArgumentError("Inbox reference is invalid")
        self._require_live_directory(
            source.descriptor,
            (source.device, source.inode, source.mode),
        )
        self._require_live_directory(
            destination_parent.descriptor,
            (
                destination_parent.device,
                destination_parent.inode,
                destination_parent.mode,
            ),
        )
        result = self._run(
            [
                "/usr/bin/osascript",
                "-l",
                "JavaScript",
                "-e",
                MOVE_DIRECTORY_REFERENCE_SCRIPT,
                reference.token.source_url,
                reference.token.destination_parent_url,
                str(source.device),
                str(source.inode),
                str(stat.S_IMODE(source.mode)),
                str(destination_parent.device),
                str(destination_parent.inode),
                str(stat.S_IMODE(destination_parent.mode)),
                str(destination_parent.path),
                destination_name,
            ]
        )
        if result.stdout.strip():
            raise InvalidArgumentError("Inbox reference move failed")
        self._require_live_directory(
            source.descriptor,
            (source.device, source.inode, source.mode),
        )


_DEFAULT_MOVER: Final[InboxMover] = MacOSFileReferenceMover()


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int
    mode: int
    owner: int
    link_count: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _DirectoryIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            owner=metadata.st_uid,
            link_count=metadata.st_nlink,
        )

    def matches(self, metadata: os.stat_result) -> bool:
        return self == _DirectoryIdentity.from_stat(metadata)

    def matches_parent(self, metadata: os.stat_result) -> bool:
        """Bind a parent entry while allowing its child-count link change."""
        return (
            self.device,
            self.inode,
            self.mode,
            self.owner,
        ) == (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
        )


@dataclass(frozen=True, slots=True)
class _RelocationIntent:
    schema: str
    store_id: str
    runtime_sha256: str
    source: str
    destination: str
    source_identity: _DirectoryIdentity
    source_parent_identity: _DirectoryIdentity
    destination_parent_identity: _DirectoryIdentity
    replacement_sha256: str


def _relocation_checkpoint(name: str) -> None:
    """Deterministic interruption/race seam; production never interrupts."""
    del name


def _normalized_destination(paths: RuntimePaths, destination: Path) -> Path:
    expanded = destination.expanduser()
    normalized = Path(os.path.normpath(os.path.abspath(os.fspath(expanded))))
    if destination != normalized:
        raise InvalidArgumentError("Inbox destination must be absolute and normalized")
    try:
        validated = _validated_inbox_path(paths.root, str(normalized))
    except InvalidRuntimeError as error:
        raise InvalidArgumentError("Inbox destination is unsafe") from error
    try:
        name_limit = os.pathconf(validated.parent, "PC_NAME_MAX")
    except OSError as error:
        raise StoreUnavailableError(
            "Inbox destination parent is unavailable"
        ) from error
    if len(os.fsencode(validated.name)) > name_limit:
        raise InvalidArgumentError("Inbox destination name is too long")
    return validated


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _identity_bytes(identity: StoreIdentity) -> bytes:
    return _canonical_json_bytes(
        {
            "inbox_path": identity.inbox_path,
            "product": identity.product,
            "runtime_mode": identity.runtime_mode.value,
            "schema_lineage": identity.schema_lineage,
            "schema_version": identity.schema_version,
            "store_id": identity.store_id,
        }
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identity_payload(identity: _DirectoryIdentity, prefix: str) -> dict[str, int]:
    return {
        f"{prefix}_device": identity.device,
        f"{prefix}_inode": identity.inode,
        f"{prefix}_link_count": identity.link_count,
        f"{prefix}_mode": identity.mode,
        f"{prefix}_owner": identity.owner,
    }


def _intent_bytes(intent: _RelocationIntent) -> bytes:
    payload: dict[str, object] = {
        "destination": intent.destination,
        "replacement_sha256": intent.replacement_sha256,
        "runtime_sha256": intent.runtime_sha256,
        "schema": intent.schema,
        "source": intent.source,
        "store_id": intent.store_id,
        **_identity_payload(intent.source_identity, "source"),
        **_identity_payload(intent.source_parent_identity, "source_parent"),
        **_identity_payload(
            intent.destination_parent_identity,
            "destination_parent",
        ),
    }
    encoded = _canonical_json_bytes(payload)
    if len(encoded) > _INTENT_LIMIT:
        raise InvalidArgumentError("Inbox relocation request is too large")
    return encoded


def _strict_int(raw: object) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        raise ValueError
    return raw


def _parsed_identity(raw: dict[str, object], prefix: str) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        device=_strict_int(raw[f"{prefix}_device"]),
        inode=_strict_int(raw[f"{prefix}_inode"]),
        mode=_strict_int(raw[f"{prefix}_mode"]),
        owner=_strict_int(raw[f"{prefix}_owner"]),
        link_count=_strict_int(raw[f"{prefix}_link_count"]),
    )


def _parse_intent(encoded: bytes, paths: RuntimePaths) -> _RelocationIntent:
    if not encoded or len(encoded) > _INTENT_LIMIT:
        raise InvalidRuntimeError("Store Inbox relocation intent is invalid")
    try:
        raw: Any = json.loads(encoded)
        prefixes = ("source", "source_parent", "destination_parent")
        expected_keys = {
            "destination",
            "replacement_sha256",
            "runtime_sha256",
            "schema",
            "source",
            "store_id",
            *(
                f"{prefix}_{suffix}"
                for prefix in prefixes
                for suffix in ("device", "inode", "link_count", "mode", "owner")
            ),
        }
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ValueError
        schema = raw["schema"]
        store_id = raw["store_id"]
        runtime_sha256 = raw["runtime_sha256"]
        replacement_sha256 = raw["replacement_sha256"]
        source_value = raw["source"]
        destination_value = raw["destination"]
        if (
            schema != _INTENT_SCHEMA
            or not isinstance(store_id, str)
            or _STORE_ID.fullmatch(store_id) is None
            or not isinstance(runtime_sha256, str)
            or _DIGEST.fullmatch(runtime_sha256) is None
            or not isinstance(replacement_sha256, str)
            or _DIGEST.fullmatch(replacement_sha256) is None
            or not isinstance(source_value, str)
            or not isinstance(destination_value, str)
        ):
            raise ValueError
        source = _validated_inbox_path(paths.root, source_value)
        destination = _validated_inbox_path(paths.root, destination_value)
        intent = _RelocationIntent(
            schema=schema,
            store_id=store_id,
            runtime_sha256=runtime_sha256,
            source=str(source),
            destination=str(destination),
            source_identity=_parsed_identity(raw, "source"),
            source_parent_identity=_parsed_identity(raw, "source_parent"),
            destination_parent_identity=_parsed_identity(raw, "destination_parent"),
            replacement_sha256=replacement_sha256,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
        InvalidRuntimeError,
    ) as error:
        raise InvalidRuntimeError("Store Inbox relocation intent is invalid") from error
    if _intent_bytes(intent) != encoded:
        raise InvalidRuntimeError("Store Inbox relocation intent is noncanonical")
    return intent


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_read_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _validate_owned_directory(
    metadata: os.stat_result,
    *,
    private: bool,
    message: str,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (private and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise InvalidArgumentError(message)


def _open_bound_directory(
    path: Path,
    *,
    private: bool,
    persisted: bool,
) -> tuple[int, os.stat_result]:
    error_type = InvalidRuntimeError if persisted else InvalidArgumentError
    if (
        not path.is_absolute()
        or ".." in path.parts
        or Path(os.path.normpath(os.fspath(path))) != path
    ):
        raise error_type("Inbox relocation directory is unsafe")
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
        opened = os.fstat(descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise error_type("Inbox relocation directory is unavailable") from error
    try:
        try:
            _validate_owned_directory(
                opened,
                private=private,
                message="Inbox relocation directory is unsafe",
            )
        except InvalidArgumentError as error:
            if persisted:
                raise InvalidRuntimeError(
                    "Inbox relocation directory is unsafe"
                ) from error
            raise
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _read_all(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise InvalidRuntimeError("Store relocation artifact is too large")


def _read_private_file(
    root_descriptor: int,
    name: str,
    *,
    limit: int,
    allowed_links: frozenset[int] = frozenset({1}),
) -> tuple[bytes, os.stat_result]:
    descriptor: int | None = None
    try:
        entry = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or entry.st_uid != os.geteuid()
            or entry.st_nlink not in allowed_links
            or stat.S_IMODE(entry.st_mode) != 0o600
        ):
            raise InvalidRuntimeError("Store relocation artifact is unsafe")
        descriptor = os.open(name, _file_read_flags(), dir_fd=root_descriptor)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
        ) != (
            entry.st_dev,
            entry.st_ino,
            entry.st_mode,
            entry.st_uid,
            entry.st_nlink,
        ):
            raise InvalidRuntimeError("Store relocation artifact changed")
        encoded = _read_all(descriptor, limit)
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            rebound.st_dev,
            rebound.st_ino,
            rebound.st_mode,
            rebound.st_uid,
            rebound.st_nlink,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            len(encoded),
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
        ):
            raise InvalidRuntimeError("Store relocation artifact changed")
        return encoded, opened
    except InvalidRuntimeError:
        raise
    except OSError as error:
        raise InvalidRuntimeError("Store relocation artifact is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _artifact_exists(root_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise InvalidRuntimeError("Store relocation artifact is unavailable") from error
    return True


def _write_all(descriptor: int, encoded: bytes) -> None:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("relocation artifact write made no progress")
        remaining = remaining[written:]


def _write_private_exclusive(
    root_descriptor: int,
    name: str,
    encoded: bytes,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(name, flags, 0o600, dir_fd=root_descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_no_initial_artifacts(root_descriptor: int) -> None:
    if any(
        _artifact_exists(root_descriptor, name)
        for name in INBOX_RELOCATION_ARTIFACT_NAMES
    ):
        raise InvalidRuntimeError("Store Inbox relocation state already exists")


def _publish_intent(root_descriptor: int, encoded: bytes) -> None:
    _require_no_initial_artifacts(root_descriptor)
    try:
        _write_private_exclusive(root_descriptor, _INTENT_TEMP_NAME, encoded)
        _relocation_checkpoint("after_intent_temp_fsync")
        os.link(
            _INTENT_TEMP_NAME,
            _INTENT_NAME,
            src_dir_fd=root_descriptor,
            dst_dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        _relocation_checkpoint("after_intent_publish")
        os.fsync(root_descriptor)
        _relocation_checkpoint("after_intent_root_fsync")
        os.unlink(_INTENT_TEMP_NAME, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except OSError as error:
        raise InvalidRuntimeError(
            "Store Inbox relocation intent cannot be written"
        ) from error


def _load_or_promote_intent(
    paths: RuntimePaths,
    root_descriptor: int,
) -> tuple[_RelocationIntent, bytes] | None:
    final_exists = _artifact_exists(root_descriptor, _INTENT_NAME)
    temporary_exists = _artifact_exists(root_descriptor, _INTENT_TEMP_NAME)
    runtime_temporary_exists = _artifact_exists(root_descriptor, _RUNTIME_TEMP_NAME)
    if not final_exists and not temporary_exists:
        if runtime_temporary_exists:
            raise InvalidRuntimeError("Store Inbox relocation state is incomplete")
        return None
    final: tuple[bytes, os.stat_result] | None = None
    temporary: tuple[bytes, os.stat_result] | None = None
    if final_exists:
        final = _read_private_file(
            root_descriptor,
            _INTENT_NAME,
            limit=_INTENT_LIMIT,
            allowed_links=frozenset({1, 2}),
        )
        _parse_intent(final[0], paths)
    if temporary_exists:
        temporary = _read_private_file(
            root_descriptor,
            _INTENT_TEMP_NAME,
            limit=_INTENT_LIMIT,
            allowed_links=frozenset({1, 2}),
        )
        _parse_intent(temporary[0], paths)
    try:
        if final is not None and temporary is not None:
            if final[0] != temporary[0] or (final[1].st_dev, final[1].st_ino) != (
                temporary[1].st_dev,
                temporary[1].st_ino,
            ):
                raise InvalidRuntimeError("Store Inbox relocation intent is ambiguous")
            os.unlink(_INTENT_TEMP_NAME, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            encoded = final[0]
        elif final is not None:
            encoded = final[0]
        else:
            assert temporary is not None
            os.link(
                _INTENT_TEMP_NAME,
                _INTENT_NAME,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            os.fsync(root_descriptor)
            os.unlink(_INTENT_TEMP_NAME, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            encoded = temporary[0]
    except OSError as error:
        raise InvalidRuntimeError(
            "Store Inbox relocation intent cannot recover"
        ) from error
    return _parse_intent(encoded, paths), encoded


def _require_empty_private_custody(paths: RuntimePaths) -> None:
    root_descriptor, _ = _open_bound_directory(
        paths.root,
        private=True,
        persisted=True,
    )
    try:
        for private_path in (paths.inbox_claims, paths.inbox_staging):
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    private_path.name,
                    _directory_flags(),
                    dir_fd=root_descriptor,
                )
                metadata = os.fstat(descriptor)
                _validate_owned_directory(
                    metadata,
                    private=True,
                    message="Store private Inbox custody is unsafe",
                )
                if os.listdir(descriptor):
                    raise StoreBusyError("Store private Inbox custody is active")
            except StoreBusyError:
                raise
            except OSError as error:
                raise InvalidRuntimeError(
                    "Store private Inbox custody is unavailable"
                ) from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _entry_state(
    parent_descriptor: int,
    name: str,
    expected: _DirectoryIdentity,
) -> Literal["absent", "exact", "other"]:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return "absent"
    except OSError as error:
        raise InvalidRuntimeError("Inbox relocation entry is unavailable") from error
    return "exact" if expected.matches(metadata) else "other"


def _open_exact_entry(
    parent_descriptor: int,
    name: str,
    expected: _DirectoryIdentity,
) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise InvalidRuntimeError("Inbox relocation entry is unavailable") from error
    if not expected.matches(metadata):
        os.close(descriptor)
        raise InvalidRuntimeError("Inbox relocation entry changed")
    return descriptor


def _validate_initial_layout(
    paths: RuntimePaths,
    identity: StoreIdentity,
    destination: Path,
) -> tuple[
    int,
    int,
    int,
    os.stat_result,
    os.stat_result,
    os.stat_result,
]:
    source = Path(identity.inbox_path)
    if source == paths.root / "inbox":
        raise InvalidArgumentError("the Store's internal Inbox cannot be relocated")
    try:
        destination.relative_to(source)
    except ValueError:
        pass
    else:
        raise InvalidArgumentError("Inbox destination cannot be inside the source")
    _require_empty_private_custody(paths)
    source_parent_descriptor, source_parent = _open_bound_directory(
        source.parent,
        private=False,
        persisted=False,
    )
    destination_parent_descriptor: int | None = None
    source_descriptor: int | None = None
    try:
        destination_parent_descriptor, destination_parent = _open_bound_directory(
            destination.parent,
            private=True,
            persisted=False,
        )
        try:
            source_descriptor = os.open(
                source.name,
                _directory_flags(),
                dir_fd=source_parent_descriptor,
            )
            source_metadata = os.fstat(source_descriptor)
        except OSError as error:
            raise StoreUnavailableError("Inbox source is unavailable") from error
        _validate_owned_directory(
            source_metadata,
            private=True,
            message="Inbox source is unsafe",
        )
        source_entry = os.stat(
            source.name,
            dir_fd=source_parent_descriptor,
            follow_symlinks=False,
        )
        if (
            source_entry.st_dev,
            source_entry.st_ino,
            source_entry.st_mode,
            source_entry.st_uid,
            source_entry.st_nlink,
        ) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_mode,
            source_metadata.st_uid,
            source_metadata.st_nlink,
        ):
            raise InvalidArgumentError("Inbox source changed")
        if (
            _entry_state(
                destination_parent_descriptor,
                destination.name,
                _DirectoryIdentity.from_stat(source_metadata),
            )
            != "absent"
        ):
            raise InvalidArgumentError("Inbox destination already exists")
        root_device = paths.root.lstat().st_dev
        if not (
            source_metadata.st_dev
            == source_parent.st_dev
            == destination_parent.st_dev
            == root_device
        ):
            raise InvalidArgumentError("Inbox relocation must remain on one volume")
        return (
            source_parent_descriptor,
            destination_parent_descriptor,
            source_descriptor,
            source_metadata,
            source_parent,
            destination_parent,
        )
    except BaseException:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_parent_descriptor is not None:
            os.close(destination_parent_descriptor)
        os.close(source_parent_descriptor)
        raise


def _build_intent(
    identity: StoreIdentity,
    destination: Path,
    source_metadata: os.stat_result,
    source_parent: os.stat_result,
    destination_parent: os.stat_result,
    current_identity_bytes: bytes,
) -> tuple[_RelocationIntent, bytes]:
    replacement = dataclasses.replace(identity, inbox_path=str(destination))
    intent = _RelocationIntent(
        schema=_INTENT_SCHEMA,
        store_id=identity.store_id,
        runtime_sha256=_sha256(current_identity_bytes),
        source=identity.inbox_path,
        destination=str(destination),
        source_identity=_DirectoryIdentity.from_stat(source_metadata),
        source_parent_identity=_DirectoryIdentity.from_stat(source_parent),
        destination_parent_identity=_DirectoryIdentity.from_stat(destination_parent),
        replacement_sha256=_sha256(_identity_bytes(replacement)),
    )
    return intent, _intent_bytes(intent)


def _read_current_identity_bytes(
    paths: RuntimePaths,
    root_descriptor: int,
) -> bytes:
    encoded, _ = _read_private_file(
        root_descriptor,
        paths.identity.name,
        limit=_IDENTITY_LIMIT,
    )
    return encoded


def _ensure_runtime_identity(
    paths: RuntimePaths,
    root_descriptor: int,
    identity: StoreIdentity,
    intent: _RelocationIntent,
) -> StoreIdentity:
    replacement = dataclasses.replace(identity, inbox_path=intent.destination)
    replacement_bytes = _identity_bytes(replacement)
    current_bytes = _read_current_identity_bytes(paths, root_descriptor)
    current_digest = _sha256(current_bytes)
    if Path(identity.inbox_path) == Path(intent.destination):
        if (
            current_digest != intent.replacement_sha256
            or current_bytes != replacement_bytes
            or _artifact_exists(root_descriptor, _RUNTIME_TEMP_NAME)
        ):
            raise InvalidRuntimeError("Store relocation identity is ambiguous")
        return identity
    if Path(identity.inbox_path) != Path(intent.source):
        raise InvalidRuntimeError("Store relocation identity is ambiguous")
    if current_digest != intent.runtime_sha256 or current_bytes != _identity_bytes(
        identity
    ):
        raise InvalidRuntimeError("Store relocation identity changed")
    if _artifact_exists(root_descriptor, _RUNTIME_TEMP_NAME):
        temporary, _ = _read_private_file(
            root_descriptor,
            _RUNTIME_TEMP_NAME,
            limit=_IDENTITY_LIMIT,
        )
        if temporary != replacement_bytes:
            raise InvalidRuntimeError("Store relocation identity temporary is invalid")
    else:
        try:
            _write_private_exclusive(
                root_descriptor,
                _RUNTIME_TEMP_NAME,
                replacement_bytes,
            )
        except OSError as error:
            raise InvalidRuntimeError(
                "Store relocation identity temporary cannot be written"
            ) from error
    _relocation_checkpoint("after_runtime_temp_fsync")
    if _read_current_identity_bytes(paths, root_descriptor) != current_bytes:
        raise InvalidRuntimeError("Store relocation identity changed")
    try:
        os.replace(
            _RUNTIME_TEMP_NAME,
            paths.identity.name,
            src_dir_fd=root_descriptor,
            dst_dir_fd=root_descriptor,
        )
    except OSError as error:
        raise InvalidRuntimeError(
            "Store relocation identity cannot be replaced"
        ) from error
    _relocation_checkpoint("after_runtime_replace")
    os.fsync(root_descriptor)
    _relocation_checkpoint("after_runtime_root_fsync")
    updated = _authorize_runtime_use_for_relocation(
        dataclasses.replace(paths, inbox=Path(intent.destination))
    )
    if updated != replacement:
        raise InvalidRuntimeError("Store relocation identity replacement is invalid")
    return updated


def _clean_intent(
    root_descriptor: int,
    encoded_intent: bytes,
) -> None:
    encoded, metadata = _read_private_file(
        root_descriptor,
        _INTENT_NAME,
        limit=_INTENT_LIMIT,
    )
    if encoded != encoded_intent or metadata.st_nlink != 1:
        raise InvalidRuntimeError("Store Inbox relocation intent changed")
    try:
        os.unlink(_INTENT_NAME, dir_fd=root_descriptor)
    except OSError as error:
        raise InvalidRuntimeError(
            "Store Inbox relocation intent cannot be removed"
        ) from error
    _relocation_checkpoint("after_intent_unlink")
    os.fsync(root_descriptor)
    if any(
        _artifact_exists(root_descriptor, name)
        for name in INBOX_RELOCATION_ARTIFACT_NAMES
    ):
        raise InvalidRuntimeError("Store Inbox relocation cleanup is incomplete")


def _execute_intent(
    paths: RuntimePaths,
    identity: StoreIdentity,
    destination: Path,
    intent: _RelocationIntent,
    encoded_intent: bytes,
    root_descriptor: int,
    mover: InboxMover,
    *,
    recovering: bool,
    retained: tuple[int, int, int] | None = None,
) -> InboxRelocationResult:
    if intent.store_id != identity.store_id or Path(intent.destination) != destination:
        raise InvalidRuntimeError(
            "Store Inbox relocation request does not match intent"
        )
    source = Path(intent.source)
    source_parent_descriptor: int | None = None
    destination_parent_descriptor: int | None = None
    exact_descriptor: int | None = None
    try:
        if retained is None:
            source_parent_descriptor, source_parent = _open_bound_directory(
                source.parent,
                private=False,
                persisted=True,
            )
            destination_parent_descriptor, destination_parent = _open_bound_directory(
                destination.parent,
                private=True,
                persisted=True,
            )
        else:
            (
                source_parent_descriptor,
                destination_parent_descriptor,
                exact_descriptor,
            ) = retained
            source_parent = os.fstat(source_parent_descriptor)
            destination_parent = os.fstat(destination_parent_descriptor)
        if not intent.source_parent_identity.matches_parent(source_parent) or not (
            intent.destination_parent_identity.matches_parent(destination_parent)
        ):
            raise InvalidRuntimeError("Store Inbox relocation parent changed")
        source_state = _entry_state(
            source_parent_descriptor,
            source.name,
            intent.source_identity,
        )
        destination_state = _entry_state(
            destination_parent_descriptor,
            destination.name,
            intent.source_identity,
        )
        if destination_state == "exact" and source_state in ("absent", "other"):
            if exact_descriptor is None:
                exact_descriptor = _open_exact_entry(
                    destination_parent_descriptor,
                    destination.name,
                    intent.source_identity,
                )
        elif (
            source_state == "exact"
            and destination_state == "absent"
            and Path(identity.inbox_path) == source
        ):
            if exact_descriptor is None:
                exact_descriptor = _open_exact_entry(
                    source_parent_descriptor,
                    source.name,
                    intent.source_identity,
                )
            move_source = DirectoryMoveSource(
                path=source,
                descriptor=exact_descriptor,
                device=intent.source_identity.device,
                inode=intent.source_identity.inode,
                mode=intent.source_identity.mode,
            )
            move_parent = DestinationParent(
                path=destination.parent,
                descriptor=destination_parent_descriptor,
                device=intent.destination_parent_identity.device,
                inode=intent.destination_parent_identity.inode,
                mode=intent.destination_parent_identity.mode,
            )
            _relocation_checkpoint("before_reference_creation")
            reference = mover.create_reference(move_source, move_parent)
            _relocation_checkpoint("after_reference_creation")
            if (
                _entry_state(
                    destination_parent_descriptor,
                    destination.name,
                    intent.source_identity,
                )
                != "absent"
            ):
                raise InvalidArgumentError("Inbox destination changed")
            _relocation_checkpoint("before_reference_move")
            mover.move_reference(
                move_source,
                move_parent,
                destination.name,
                reference,
            )
            if (
                _entry_state(
                    destination_parent_descriptor,
                    destination.name,
                    intent.source_identity,
                )
                != "exact"
            ):
                raise InvalidRuntimeError("Inbox relocation move is ambiguous")
            _relocation_checkpoint("after_directory_move")
            os.fsync(source_parent_descriptor)
            _relocation_checkpoint("after_source_parent_fsync")
            if destination_parent_descriptor != source_parent_descriptor:
                os.fsync(destination_parent_descriptor)
            _relocation_checkpoint("after_destination_parent_fsync")
        else:
            raise InvalidRuntimeError("Store Inbox relocation state is ambiguous")
        updated = _ensure_runtime_identity(
            paths,
            root_descriptor,
            identity,
            intent,
        )
        if Path(updated.inbox_path) != destination:
            raise InvalidRuntimeError("Store Inbox relocation identity is invalid")
        if (
            _entry_state(
                destination_parent_descriptor,
                destination.name,
                intent.source_identity,
            )
            != "exact"
        ):
            raise InvalidRuntimeError("Store Inbox relocation destination changed")
        _clean_intent(root_descriptor, encoded_intent)
        return InboxRelocationResult("recovered" if recovering else "relocated")
    except InvalidArgumentError as error:
        if recovering:
            raise InvalidRuntimeError(
                "Store Inbox relocation recovery is unsafe"
            ) from error
        raise
    finally:
        if exact_descriptor is not None:
            os.close(exact_descriptor)
        if destination_parent_descriptor is not None:
            os.close(destination_parent_descriptor)
        if source_parent_descriptor is not None:
            os.close(source_parent_descriptor)


def _begin_relocation(
    paths: RuntimePaths,
    identity: StoreIdentity,
    destination: Path,
    root_descriptor: int,
    mover: InboxMover,
) -> InboxRelocationResult:
    (
        source_parent_descriptor,
        destination_parent_descriptor,
        source_descriptor,
        source_metadata,
        source_parent,
        destination_parent,
    ) = _validate_initial_layout(paths, identity, destination)
    retained = (
        source_parent_descriptor,
        destination_parent_descriptor,
        source_descriptor,
    )
    handed_off = False
    try:
        current_identity_bytes = _read_current_identity_bytes(paths, root_descriptor)
        if current_identity_bytes != _identity_bytes(identity):
            raise InvalidRuntimeError("Store runtime identity is noncanonical")
        intent, encoded_intent = _build_intent(
            identity,
            destination,
            source_metadata,
            source_parent,
            destination_parent,
            current_identity_bytes,
        )
        _publish_intent(root_descriptor, encoded_intent)
        handed_off = True
        return _execute_intent(
            paths,
            identity,
            destination,
            intent,
            encoded_intent,
            root_descriptor,
            mover,
            recovering=False,
            retained=retained,
        )
    finally:
        if not handed_off:
            for descriptor in reversed(retained):
                os.close(descriptor)


def relocate_inbox(
    paths: RuntimePaths,
    destination: Path,
    *,
    mover: InboxMover = _DEFAULT_MOVER,
) -> InboxRelocationResult:
    """Move one exact configured external Inbox to an absent same-volume path."""
    normalized = _normalized_destination(paths, destination)
    with ui_session_lock(paths):
        with _writer_lock(paths):
            identity = _authorize_runtime_use_for_relocation(paths)
            if Path(identity.inbox_path) == paths.root / "inbox":
                raise InvalidArgumentError(
                    "the Store's internal Inbox cannot be relocated"
                )
            root_descriptor, _ = _open_bound_directory(
                paths.root,
                private=True,
                persisted=True,
            )
            try:
                pending = _load_or_promote_intent(paths, root_descriptor)
                if pending is None:
                    if Path(identity.inbox_path) == normalized:
                        return InboxRelocationResult("current")
                    return _begin_relocation(
                        paths,
                        identity,
                        normalized,
                        root_descriptor,
                        mover,
                    )
                intent, encoded_intent = pending
                return _execute_intent(
                    paths,
                    identity,
                    normalized,
                    intent,
                    encoded_intent,
                    root_descriptor,
                    mover,
                    recovering=True,
                )
            finally:
                os.close(root_descriptor)
