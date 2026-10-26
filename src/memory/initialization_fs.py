"""Descriptor-held directory authority for Store initialization.

The macOS inode namespace is used only as a transient SQLite filename. Persisted
paths remain the owner's lexical selection; descriptors prevent inode reuse.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from memory.errors import InitializationError


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class BoundDirectory:
    path: Path
    descriptor: int
    metadata: os.stat_result
    ancestors: tuple[tuple[int, int], ...]

    @property
    def identity(self) -> tuple[int, int]:
        return identity(self.metadata)

    @property
    def anchor(self) -> Path:
        device, inode = self.identity
        result = Path(f"/.vol/{device}/{inode}")
        if identity(result.stat()) != self.identity:
            raise InitializationError("Store directory anchor changed")
        return result


class DirectoryPins:
    """Keep every ancestor open, and validate each containing directory entry."""

    def __init__(self) -> None:
        self._descriptors: list[int] = []
        self._links: list[tuple[int, str, int]] = []

    def __enter__(self) -> DirectoryPins:
        return self

    def __exit__(self, *arguments: object) -> None:
        for descriptor in reversed(self._descriptors):
            os.close(descriptor)

    def open(
        self, path: Path, *, create: bool = False, parents: bool = False
    ) -> BoundDirectory:
        if not path.is_absolute() or os.path.normpath(path) != str(path):
            raise InitializationError("Store directory path is unsafe")
        descriptor = os.open("/", directory_flags())
        self._descriptors.append(descriptor)
        ancestors = [identity(os.fstat(descriptor))]
        try:
            for index, component in enumerate(path.parts[1:]):
                last = index == len(path.parts) - 2
                try:
                    child = os.open(component, directory_flags(), dir_fd=descriptor)
                except FileNotFoundError:
                    if not create or not (parents or last):
                        raise
                    self.validate()
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                        os.fsync(descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(component, directory_flags(), dir_fd=descriptor)
                self._descriptors.append(child)
                self._links.append((descriptor, component, child))
                descriptor = child
                ancestors.append(identity(os.fstat(child)))
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid():
                raise InitializationError("Store directory is not owned by this user")
            self.validate()
        except FileNotFoundError:
            raise
        except OSError as error:
            raise InitializationError(
                "Store directory is unsafe or unavailable"
            ) from error
        return BoundDirectory(path, descriptor, metadata, tuple(ancestors[:-1]))

    def validate(self) -> None:
        try:
            for parent, name, descriptor in self._links:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(
                    os.fstat(descriptor)
                ):
                    raise InitializationError("Store directory authority changed")
        except OSError as error:
            raise InitializationError("Store directory authority changed") from error


def file_metadata(directory: BoundDirectory, name: str) -> os.stat_result | None:
    try:
        result = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(result.st_mode) or result.st_uid != os.geteuid():
        raise InitializationError("Store initialization file is unsafe")
    return result


def open_file(directory: BoundDirectory, name: str, *, writable: bool = False) -> int:
    descriptor = os.open(
        name,
        (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory.descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        current = file_metadata(directory, name)
        if current is None or identity(opened) != identity(current):
            raise InitializationError("Store initialization file changed")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def read_file(directory: BoundDirectory, name: str, *, limit: int = 16_384) -> bytes:
    descriptor = open_file(directory, name)
    try:
        value = os.read(descriptor, limit + 1)
        if len(value) > limit:
            raise InitializationError("Store initialization file is oversized")
        current = file_metadata(directory, name)
        if current is None or identity(current) != identity(os.fstat(descriptor)):
            raise InitializationError("Store initialization file changed")
        return value
    finally:
        os.close(descriptor)


def require_distinct_layout(
    root: BoundDirectory,
    inbox: BoundDirectory,
    claims: BoundDirectory | None,
    staging: BoundDirectory | None,
) -> None:
    directories = [
        root,
        inbox,
        *[item for item in (claims, staging) if item is not None],
    ]
    if len({item.identity for item in directories}) != len(directories):
        raise InitializationError("Store private directory identities overlap")
    try:
        default = os.stat("inbox", dir_fd=root.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        is_default = False
    else:
        is_default = (
            stat.S_ISDIR(default.st_mode) and identity(default) == inbox.identity
        )
    if inbox.identity in root.ancestors or (
        root.identity in inbox.ancestors and not is_default
    ):
        raise InitializationError("Store Inbox directory topology overlaps")
    if any(item.identity[0] != root.identity[0] for item in directories):
        raise InitializationError("Store inbox must be on the Store home volume")
