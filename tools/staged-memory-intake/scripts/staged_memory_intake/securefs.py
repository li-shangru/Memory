"""Descriptor-relative, non-following filesystem operations."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath

from staged_memory_intake.model import DirectoryIdentity, IntakeError

_ROOT_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_ATTR_BIT_MAP_COUNT = 5
_ATTR_VOL_INFO = 0x80000000
_ATTR_VOL_UUID = 0x00040000
_FSOPT_NOFOLLOW = 0x00000001
_VOLUME_BUFFER_SIZE = 64
_VOLUME_PAYLOAD_END = 20


class _AttributeList(ctypes.Structure):
    _fields_ = (
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_ushort),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    )


def _open_directory(path: Path) -> int:
    try:
        descriptor = os.open(path, _ROOT_FLAGS)
    except OSError as error:
        raise IntakeError("unsafe_directory", "drift") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise IntakeError("unsafe_directory", "drift")
    return descriptor


def _validate_name(name: str) -> None:
    if "\0" in name or name in {".", ".."} or PurePosixPath(name).parts != (name,):
        raise IntakeError("invalid_relative_name", "drift")


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_regular(
    root: Path,
    name: str,
    *,
    limit: int,
    private: bool,
) -> bytes:
    _validate_name(name)
    if limit < 0:
        raise IntakeError("invalid_read_limit", "configuration")
    root_descriptor = _open_directory(root)
    try:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=root_descriptor)
        except OSError as error:
            raise IntakeError("unsafe_regular_file", "drift") from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or (
                private and stat.S_IMODE(before.st_mode) != 0o600
            ):
                raise IntakeError("unsafe_regular_file", "drift")
            remaining = limit + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if not _same_file(before, after):
                raise IntakeError("file_changed_during_read", "drift")
            payload = b"".join(chunks)
            if len(payload) > limit:
                raise IntakeError("file_too_large", "drift")
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)


def read_regular(root: Path, name: str, *, limit: int) -> bytes:
    """Read one bounded direct-child regular file without following links."""
    return _read_regular(root, name, limit=limit, private=False)


def read_private_regular(root: Path, name: str, *, limit: int) -> bytes:
    """Read one exact mode-0600 direct child without following links."""
    return _read_regular(root, name, limit=limit, private=True)


def sha256_regular(root: Path, name: str, *, limit: int) -> str:
    """Hash one safely opened direct-child regular file."""
    return hashlib.sha256(read_regular(root, name, limit=limit)).hexdigest()


def _volume_request() -> _AttributeList:
    return _AttributeList(
        bitmapcount=_ATTR_BIT_MAP_COUNT,
        volattr=_ATTR_VOL_INFO | _ATTR_VOL_UUID,
    )


def _volume_from_buffer(result: int, raw: bytes) -> str:
    """Decode one volume UUID, or report why the kernel refused one.

    A failed call sets errno, and absence must surface exactly as a stat's
    absence does, so a name deleted between two lookups reads as gone rather
    than as an unidentifiable volume. Everything else -- including a volume
    that reports no UUID at all, which is the effective volume-UUID (APFS and
    HFS+) constraint of this identity binding -- stays `volume_unidentified`.
    """
    if result != 0:
        captured = ctypes.get_errno()
        if captured == errno.ENOENT:
            raise FileNotFoundError(captured, "volume attribute target is absent")
        raise IntakeError("volume_unidentified", "configuration")
    length = int.from_bytes(raw[:4], sys.byteorder)
    payload = raw[4:_VOLUME_PAYLOAD_END]
    if length < _VOLUME_PAYLOAD_END or payload == bytes(16):
        raise IntakeError("volume_unidentified", "configuration")
    return str(uuid.UUID(bytes=payload))


_VOLUME_READERS: tuple[Callable[..., int], Callable[..., int]] | None = None
_VOLUME_READERS_LOADED = False


def _volume_readers() -> tuple[Callable[..., int], Callable[..., int]] | None:
    """The configured `fgetattrlist` and `getattrlistat`, dlopened once.

    Identity reads sit on the hot configuration-load path; re-dlopening libc
    and reconfiguring both signatures on every call was pure overhead.
    """
    global _VOLUME_READERS, _VOLUME_READERS_LOADED
    if _VOLUME_READERS_LOADED:
        return _VOLUME_READERS
    _VOLUME_READERS_LOADED = True
    library = ctypes.CDLL(None, use_errno=True)
    try:
        fgetattrlist = library.fgetattrlist
        getattrlistat = library.getattrlistat
    except AttributeError:  # pragma: no cover - macOS-only workflow
        return None
    fgetattrlist.argtypes = (
        ctypes.c_int,
        ctypes.POINTER(_AttributeList),
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_ulong,
    )
    fgetattrlist.restype = ctypes.c_int
    getattrlistat.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.POINTER(_AttributeList),
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_ulong,
    )
    getattrlistat.restype = ctypes.c_int
    _VOLUME_READERS = (fgetattrlist, getattrlistat)
    return _VOLUME_READERS


def descriptor_volume(descriptor: int) -> str:
    """Read one open file's containing-volume UUID; it survives reboots."""
    readers = _volume_readers()
    if readers is None:  # pragma: no cover - macOS-only workflow
        raise IntakeError("volume_unidentified", "configuration")
    fgetattrlist, _getattrlistat = readers
    request = _volume_request()
    buffer = ctypes.create_string_buffer(_VOLUME_BUFFER_SIZE)
    ctypes.set_errno(0)
    result = fgetattrlist(
        descriptor,
        ctypes.byref(request),
        buffer,
        len(buffer),
        0,
    )
    return _volume_from_buffer(result, buffer.raw)


def entry_volume(parent_descriptor: int, name: str) -> str:
    """Read one direct child's volume UUID without opening or following it."""
    _validate_name(name)
    readers = _volume_readers()
    if readers is None:  # pragma: no cover - macOS-only workflow
        raise IntakeError("volume_unidentified", "configuration")
    _fgetattrlist, getattrlistat = readers
    request = _volume_request()
    buffer = ctypes.create_string_buffer(_VOLUME_BUFFER_SIZE)
    ctypes.set_errno(0)
    result = getattrlistat(
        parent_descriptor,
        os.fsencode(name),
        ctypes.byref(request),
        buffer,
        len(buffer),
        _FSOPT_NOFOLLOW,
    )
    return _volume_from_buffer(result, buffer.raw)


def descriptor_identity(descriptor: int) -> DirectoryIdentity:
    """Bind one open directory descriptor's volume UUID and inode."""
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise IntakeError("unsafe_directory", "drift")
    return DirectoryIdentity(
        volume=descriptor_volume(descriptor),
        inode=metadata.st_ino,
    )


def directory_identity(path: Path) -> DirectoryIdentity:
    """Bind a non-symlink directory's volume UUID and inode."""
    descriptor = _open_directory(path)
    try:
        return descriptor_identity(descriptor)
    finally:
        os.close(descriptor)


def inventory(path: Path) -> tuple[str, ...]:
    """Return every entry name without resolving or following any entry."""
    descriptor = _open_directory(path)
    try:
        return tuple(
            sorted(name for name in os.listdir(descriptor) if name not in {".", ".."})
        )
    finally:
        os.close(descriptor)


def canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    """Encode one canonical JSON object with exactly one terminal LF."""
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def ensure_private_bytes(path: Path, payload: bytes) -> None:
    """Durably create or exact-verify one content-addressed private file."""
    parent_descriptor = _open_directory(path.parent)
    _validate_name(path.name)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                path.name,
                _WRITE_FLAGS,
                0o600,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise IntakeError("private_write_failed", "configuration") from error
            existing = read_private_regular(
                path.parent,
                path.name,
                limit=len(payload),
            )
            if existing != payload:
                raise IntakeError(
                    "unsafe_private_file",
                    "configuration",
                ) from error
            return
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise IntakeError("private_write_failed", "configuration")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def create_pending_note(
    notes_root: Path,
    pending_directory: str,
    name: str,
    payload: bytes,
) -> None:
    """Create one new pending note exclusively; never follow or overwrite.

    The pending-drop write: a root-level regular file inside the notes
    root's pending child, mode 0600, fsynced through the directory. An
    existing entry of any kind refuses content-free.
    """
    _validate_name(pending_directory)
    _validate_name(name)
    root_descriptor = _open_directory(notes_root)
    child_descriptor: int | None = None
    descriptor: int | None = None
    try:
        try:
            child_descriptor = os.open(
                pending_directory, _ROOT_FLAGS, dir_fd=root_descriptor
            )
        except OSError as error:
            raise IntakeError("unsafe_directory", "drift") from error
        metadata = os.fstat(child_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise IntakeError("unsafe_directory", "drift")
        try:
            descriptor = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=child_descriptor)
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise IntakeError("pending_note_exists", "drift") from error
            raise IntakeError("pending_note_write_failed", "drift") from error
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise IntakeError("pending_note_write_failed", "drift")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(child_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if child_descriptor is not None:
            os.close(child_descriptor)
        os.close(root_descriptor)


def quarantine_state_entry(state_root: Path, name: str) -> str:
    """Move one direct child aside under a name no code path reads.

    The bytes are preserved for the owner rather than deleted; the random
    suffix keeps repeated quarantines of the same name from colliding.
    """
    _validate_name(name)
    quarantined = f"abandoned-{name}.{secrets.token_hex(8)}"
    _validate_name(quarantined)
    parent_descriptor = _open_directory(state_root)
    try:
        os.rename(
            name,
            quarantined,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    except OSError as error:
        raise IntakeError("quarantine_failed", "state") from error
    finally:
        os.close(parent_descriptor)
    return quarantined


def atomic_private_json(path: Path, payload: Mapping[str, object]) -> None:
    """Durably replace one direct-child JSON file with mode 0600."""
    encoded = canonical_json_bytes(payload)
    parent = path.parent
    parent_descriptor = _open_directory(parent)
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    _validate_name(path.name)
    _validate_name(temporary_name)
    descriptor: int | None = None
    try:
        try:
            existing = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise IntakeError("unsafe_private_file", "configuration")
        descriptor = os.open(
            temporary_name,
            _WRITE_FLAGS,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise IntakeError("private_write_failed", "configuration")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)
