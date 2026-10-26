"""Secret-safe local browser and integration launch helpers."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import socket
import stat
from typing import Protocol

from memory.errors import InvalidArgumentError
from memory.model import RuntimePaths, UiLaunch, UiLaunchEnvelope


class FinderRevealer(Protocol):
    """Narrow injected Finder operation; routes never receive filesystem paths."""

    def reveal_directory_url(self, directory_url: object) -> None: ...


class CocoaFinderRevealer:
    """Reveal an already-authorized directory URL through AppKit in process."""

    def reveal_directory_url(self, directory_url: object) -> None:
        from AppKit import NSWorkspace  # type: ignore[import-untyped]

        NSWorkspace.sharedWorkspace().activateFileViewerSelectingURLs_([directory_url])


def create_ui_launch(paths: RuntimePaths, *, bound_port: int) -> UiLaunch:
    """Create an independent random localhost origin and fragment capability."""
    if not isinstance(paths, RuntimePaths):
        raise InvalidArgumentError("UI runtime paths are invalid")
    if isinstance(bound_port, bool) or not 1 <= bound_port <= 65_535:
        raise InvalidArgumentError("UI port is invalid")
    public_host = f"memory-{secrets.token_hex(16)}.localhost"
    capability = secrets.token_urlsafe(32)
    url = f"http://{public_host}:{bound_port}/bootstrap#{capability}"
    return UiLaunch(
        bind_host="127.0.0.1",
        public_host=public_host,
        port=bound_port,
        bootstrap_capability=capability,
        url=url,
    )


def write_ui_launch_envelope(launch_fd: int, launch: UiLaunch) -> None:
    """Write once, taking ownership only after standard-stream exclusion."""
    _reject_standard_stream_descriptor(launch_fd)
    try:
        _validate_launch_descriptor(launch_fd)
        envelope = UiLaunchEnvelope(
            protocol="memory.ui-launch.v1",
            origin=f"http://{launch.public_host}:{launch.port}",
            bootstrap_url=launch.url,
        )
        payload = (
            json.dumps(
                {
                    "bootstrap_url": envelope.bootstrap_url,
                    "origin": envelope.origin,
                    "protocol": envelope.protocol,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        offset = 0
        while offset < len(payload):
            written = os.write(launch_fd, payload[offset:])
            if written <= 0:
                raise InvalidArgumentError("launch descriptor rejected output")
            offset += written
    except InvalidArgumentError:
        raise
    except OSError as error:
        raise InvalidArgumentError("launch descriptor is unavailable") from error
    finally:
        try:
            os.close(launch_fd)
        except OSError:
            pass


def _reject_standard_stream_descriptor(descriptor: int) -> None:
    if (
        not isinstance(descriptor, int)
        or isinstance(descriptor, bool)
        or descriptor < 0
    ):
        raise InvalidArgumentError("launch descriptor is invalid")
    if descriptor in (0, 1, 2):
        raise InvalidArgumentError("launch descriptor must not be a standard stream")
    try:
        selected = os.fstat(descriptor)
        selected_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        raise InvalidArgumentError("launch descriptor is unavailable") from error
    if not (stat.S_ISFIFO(selected.st_mode) or stat.S_ISSOCK(selected.st_mode)):
        return
    for standard_descriptor in (0, 1, 2):
        try:
            standard = os.fstat(standard_descriptor)
            standard_mode = (
                fcntl.fcntl(standard_descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            )
        except OSError:
            continue
        if (selected.st_dev, selected.st_ino) == (
            standard.st_dev,
            standard.st_ino,
        ) and selected_mode == standard_mode:
            raise InvalidArgumentError("launch descriptor aliases a standard stream")


def _validate_launch_descriptor(descriptor: int) -> None:
    if isinstance(descriptor, bool) or descriptor < 0:
        raise InvalidArgumentError("launch descriptor is invalid")
    metadata = os.fstat(descriptor)
    if os.isatty(descriptor):
        raise InvalidArgumentError("launch descriptor must not be a terminal")
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    if access_mode == os.O_RDONLY:
        raise InvalidArgumentError("launch descriptor is not writable")
    if stat.S_ISFIFO(metadata.st_mode):
        return
    if not stat.S_ISSOCK(metadata.st_mode):
        raise InvalidArgumentError("launch descriptor must be a pipe or socket")
    duplicate = os.dup(descriptor)
    try:
        with socket.socket(fileno=duplicate) as candidate:
            if candidate.family != socket.AF_UNIX:
                raise InvalidArgumentError("launch socket must be local")
            if candidate.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
                raise InvalidArgumentError("launch socket must be a stream")
            try:
                candidate.getpeername()
            except OSError as error:
                raise InvalidArgumentError("launch socket is not connected") from error
    except Exception:
        # The socket context owns ``duplicate`` after successful construction.
        try:
            os.close(duplicate)
        except OSError:
            pass
        raise


def open_bootstrap_url_with_launch_services(url: str) -> None:
    """Open the secret-bearing URL in-process through LaunchServices."""
    from AppKit import NSWorkspace
    from Foundation import NSURL  # type: ignore[import-untyped]

    try:
        cocoa_url = NSURL.URLWithString_(url)
        if cocoa_url is None:
            raise InvalidArgumentError("bootstrap URL is invalid")
        opened = NSWorkspace.sharedWorkspace().openURL_(cocoa_url)
    except InvalidArgumentError:
        raise
    except Exception:
        raise InvalidArgumentError("browser launch failed") from None
    if opened is not True:
        raise InvalidArgumentError("browser launch failed")
