#!/usr/bin/env python3
"""Launch, authenticate, and stop one installed local owner UI process.

The driver runs with the installed environment's own ``bin/python -I`` from a
temporary directory outside the repository. It executes only the validated
absolute installed ``bin/memory`` path, never a bare command, never a shell, and
never a source checkout. The one-use bootstrap envelope stays in memory: it is
never printed, logged, or written anywhere.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path

READY_MARKER = b"memory-ui-ready\n"
READY_TIMEOUT_SECONDS = 60.0
STORE_ID = re.compile(r"[0-9a-f]{32}")
PUBLIC_HOST = re.compile(r"memory-[0-9a-f]{32}\.localhost")
EXPECTED_IDENTITY_KEYS = frozenset(
    {
        "inbox_path",
        "product",
        "runtime_mode",
        "schema_lineage",
        "schema_version",
        "store_id",
    }
)


class SmokeError(Exception):
    """One content-free installed-UI smoke failure."""


def validate_installed_command(candidate: Path) -> Path:
    """Require one absolute, regular, executable installed command path."""
    if not candidate.is_absolute() or candidate.name != "memory":
        raise SmokeError("installed Store command path is invalid")
    metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(candidate.stat().st_mode):
        raise SmokeError("installed Store command is not a regular file")
    if not os.access(candidate, os.X_OK):
        raise SmokeError("installed Store command is not executable")
    return candidate


def validate_store_home(candidate: Path) -> str:
    """Require one initialized Store runtime and return its exact Store ID."""
    if not candidate.is_absolute():
        raise SmokeError("Store home path is invalid")
    if candidate.is_symlink() or not candidate.is_dir():
        raise SmokeError("Store home is not a directory")
    identity_path = candidate / "runtime.json"
    if identity_path.is_symlink() or not identity_path.is_file():
        raise SmokeError("Store identity file is invalid")
    payload = json.loads(identity_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != EXPECTED_IDENTITY_KEYS:
        raise SmokeError("Store identity is incomplete")
    store_id = payload["store_id"]
    if (
        payload["product"] != "memory"
        or payload["runtime_mode"] != "personal"
        or payload["schema_lineage"] != "memory-store-v1"
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or not isinstance(store_id, str)
        or STORE_ID.fullmatch(store_id) is None
    ):
        raise SmokeError("Store identity is not a Memory Store")
    return store_id


def read_exact_line(descriptor: int, deadline: float) -> bytes:
    """Read one newline-terminated line without blocking past the deadline."""
    collected = bytearray()
    while not collected.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeError("the owner UI did not become ready")
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            raise SmokeError("the owner UI did not become ready")
        chunk = os.read(descriptor, 4096)
        if not chunk:
            raise SmokeError("the owner UI closed its launch stream")
        collected.extend(chunk)
        if len(collected) > 16_384:
            raise SmokeError("the owner UI launch stream is oversized")
    return bytes(collected)


def parse_envelope(raw: bytes) -> tuple[str, int, str]:
    """Return the exact host, port, and one-use capability held only in memory."""
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {
        "bootstrap_url",
        "origin",
        "protocol",
    }:
        raise SmokeError("launch envelope is invalid")
    if payload["protocol"] != "memory.ui-launch.v1":
        raise SmokeError("launch envelope protocol is unsupported")
    parsed = urllib.parse.urlsplit(payload["bootstrap_url"])
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or PUBLIC_HOST.fullmatch(parsed.hostname) is None
        or parsed.port is None
        or parsed.path != "/bootstrap"
        or not parsed.fragment
    ):
        raise SmokeError("launch envelope is incomplete")
    if payload["origin"] != f"http://{parsed.netloc}":
        raise SmokeError("launch envelope origin does not match")
    return parsed.netloc, parsed.port, parsed.fragment


def require_loopback_only(port: int) -> None:
    """Require the listener to refuse every non-loopback local address."""
    addresses = set()
    for family, _type, _proto, _name, address in socket.getaddrinfo(
        socket.gethostname(),
        None,
        socket.AF_INET,
    ):
        # An AF_INET sockaddr is (host, port); the annotation covers every
        # family getaddrinfo can return, so narrow before reading the host.
        if family != socket.AF_INET:
            continue
        host = address[0]
        if isinstance(host, str) and not host.startswith("127."):
            addresses.add(host)
    for candidate in sorted(addresses):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(3)
        try:
            probe.connect((candidate, port))
        except OSError:
            continue
        finally:
            probe.close()
        raise SmokeError("the owner UI accepted a non-loopback connection")


def authenticate(exact_host: str, port: int, capability: str) -> None:
    """Exchange the one-use capability and read one authenticated status page."""
    origin = f"http://{exact_host}"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        connection.request("GET", "/bootstrap", headers={"Host": exact_host})
        response = connection.getresponse()
        status = response.status
        response.read()
        if status != 200:
            raise SmokeError("the owner UI refused its bootstrap shell")
        connection.request(
            "POST",
            "/session",
            body=capability.encode("ascii"),
            headers={
                "Content-Type": "text/plain",
                "Host": exact_host,
                "Origin": origin,
            },
        )
        response = connection.getresponse()
        status = response.status
        header = response.getheader("Set-Cookie")
        response.read()
        if status != 303 or header is None:
            raise SmokeError("the owner UI refused its one-use capability")
        cookie = SimpleCookie()
        cookie.load(header)
        if "memory_ui_session" not in cookie:
            raise SmokeError("the owner UI issued no process session")
        session = cookie["memory_ui_session"].value
        connection.request(
            "GET",
            "/status",
            headers={"Cookie": f"memory_ui_session={session}", "Host": exact_host},
        )
        response = connection.getresponse()
        status = response.status
        body = response.read()
        if status != 200 or b"Store status" not in body:
            raise SmokeError("the owner UI refused an authenticated status read")
        connection.request("GET", "/status", headers={"Host": exact_host})
        response = connection.getresponse()
        status = response.status
        response.read()
        if status != 401:
            raise SmokeError("the owner UI served content without a session")
    finally:
        connection.close()


def run(command: Path, home: Path) -> None:
    """Start, authenticate, and stop exactly one installed owner UI process."""
    validate_installed_command(command)
    validate_store_home(home)
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    process = subprocess.Popen(
        [
            str(command),
            "ui",
            "--home",
            str(home),
            "--no-open",
            "--launch-fd",
            str(write_fd),
        ],
        close_fds=True,
        cwd=str(home),
        pass_fds=(write_fd,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(write_fd)
    exact_host = ""
    port = 0
    capability = ""
    try:
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        exact_host, port, capability = parse_envelope(
            read_exact_line(read_fd, deadline)
        )
        if process.stdout is None or process.stderr is None:
            raise SmokeError("the owner UI process streams are unavailable")
        if read_exact_line(process.stdout.fileno(), deadline) != READY_MARKER:
            raise SmokeError("the owner UI emitted an unexpected marker")
        require_loopback_only(port)
        authenticate(exact_host, port, capability)
    finally:
        capability = ""
        os.close(read_fd)
        process.send_signal(signal.SIGTERM)
        try:
            exit_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=30)
            raise SmokeError("the owner UI did not stop on request") from None
        trailing_out = b"" if process.stdout is None else process.stdout.read()
        trailing_err = b"" if process.stderr is None else process.stderr.read()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if exit_code != 0:
        raise SmokeError("the owner UI exited with a failure status")
    if trailing_out or trailing_err:
        raise SmokeError("the owner UI wrote unexpected output")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(5)
    try:
        probe.connect(("127.0.0.1", port))
    except OSError:
        return
    finally:
        probe.close()
    raise SmokeError("the owner UI listener survived shutdown")


def main(argv: list[str] | None = None) -> int:
    """Run one content-free installed owner-UI launch and shutdown probe."""
    parser = argparse.ArgumentParser(
        prog="smoke-ui-driver",
        description="Probe one installed local owner UI without owner approval.",
    )
    parser.add_argument("--memory", required=True, type=Path)
    parser.add_argument("--home", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        run(arguments.memory, arguments.home)
    except SmokeError as error:
        print(f"ui smoke failed: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "ui smoke failed: the installed owner UI was unreachable", file=sys.stderr
        )
        return 1
    print("ui smoke launched and stopped the installed owner UI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
