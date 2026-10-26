"""Synthetic spawn targets that do not import the UI test suite."""

import os
import signal
import time
from pathlib import Path
from typing import Any


def _worker_success(_source: bytes, output: Any) -> None:
    output.send_bytes(f"{os.getpid()}:synthetic-success".encode("ascii"))


def _worker_crash(_source: bytes, _output: Any) -> None:
    os._exit(23)


def _worker_block(_source: bytes, _output: Any) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(0.05)


def _worker_record_pid_and_block(_source: bytes, _output: Any) -> None:
    path = os.environ["PMS_SYNTHETIC_MEDIA_PID_PATH"]
    Path(path).write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(0.02)


def _worker_exact_ipc(_source: bytes, output: Any) -> None:
    output.send_bytes(b"x" * 1_024)


def _worker_over_ipc(_source: bytes, output: Any) -> None:
    output.send_bytes(b"x" * 1_025)
