"""Bounded macOS process-group evidence for development client cleanup.

Only a caller-owned process-group identifier may be supplied. The diagnostic
selects that one group and prints numeric identifiers and state, never process
arguments, environments, files, or an all-process inventory.
"""

from __future__ import annotations

import hashlib
import os
import select
import subprocess
import time
from pathlib import Path

_PS_COMMAND = ("/bin/ps",)
QUERY_TIMEOUT_SECONDS = 2.0
MAX_QUERY_BYTES = 64 * 1024
_STATE_FLAGS = frozenset("+<>AELNSsVWX")


def implementation_digest() -> str:
    """Bind the exact cleanup implementation in the shared execution profile."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _collect_query(process: subprocess.Popen[bytes]) -> tuple[int, bytes] | None:
    assert process.stdout is not None and process.stderr is not None
    output = bytearray()
    standard_output = process.stdout.fileno()
    descriptors = {standard_output, process.stderr.fileno()}
    for descriptor in descriptors:
        os.set_blocking(descriptor, False)
    deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
    while descriptors:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        readable, _, _ = select.select(descriptors, (), (), min(0.05, remaining))
        for descriptor in readable:
            size = (
                min(8192, MAX_QUERY_BYTES + 1 - len(output))
                if descriptor == standard_output
                else 1
            )
            try:
                chunk = os.read(descriptor, size)
            except BlockingIOError:
                continue
            if not chunk:
                descriptors.remove(descriptor)
            elif descriptor != standard_output:
                return None
            else:
                output.extend(chunk)
                if len(output) > MAX_QUERY_BYTES:
                    return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return process.wait(timeout=remaining), bytes(output)


def _query_owned_group(group: int) -> tuple[int, bytes] | None:
    process: subprocess.Popen[bytes] | None = None
    result: tuple[int, bytes] | None = None
    try:
        process = subprocess.Popen(
            [*_PS_COMMAND, "-g", str(group), "-o", "pid=,pgid=,stat="],
            env={"HOME": "/var/empty", "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            cwd="/private/tmp",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        result = _collect_query(process)
    except OSError, ValueError, subprocess.SubprocessError:
        result = None
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=QUERY_TIMEOUT_SECONDS)
            except OSError, subprocess.SubprocessError:
                result = None
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
    return result


def group_has_no_live_members(group: int) -> bool:
    """Accept only a complete empty result or exclusively dead group members."""
    if type(group) is not int or not 1 < group < 2**31:
        return False
    result = _query_owned_group(group)
    if result is None:
        return False
    returncode, output = result
    if returncode == 1:
        return output == b""
    if returncode != 0 or not output or len(output) > MAX_QUERY_BYTES:
        return False
    try:
        rows = output.decode("ascii").splitlines()
    except UnicodeError:
        return False
    seen: set[int] = set()
    for row in rows:
        columns = row.split()
        if len(columns) != 3:
            return False
        pid, pgid, state = columns
        if (
            not pid.isdigit()
            or len(pid) > 10
            or not 0 < int(pid) < 2**31
            or int(pid) in seen
            or not pgid.isdigit()
            or len(pgid) > 10
            or int(pgid) != group
            or not state.startswith("Z")
            or not set(state[1:]) <= _STATE_FLAGS
        ):
            return False
        seen.add(int(pid))
    return True
