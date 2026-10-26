"""Owned-group cleanup evidence uses only fresh inert process fixtures."""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

HELPER = Path(__file__).resolve().parents[1] / "tools/behavioral_process_cleanup.py"


def _module() -> ModuleType:
    name = "behavioral_process_cleanup_test_module"
    spec = importlib.util.spec_from_file_location(name, HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ((1, b""), True),
        ((0, b"  101  71 Z\n"), True),
        ((0, b"101 71 Zs\n102 71 Z+\n"), True),
        ((0, b"101 71 Z<NAELSWXV>\n"), True),
        (None, False),
        ((0, b""), False),
        ((1, b"\n"), False),
        ((1, b"101 71 Z\n"), False),
        ((2, b""), False),
        ((0, b"101 71 S\n"), False),
        ((0, b"101 71 Z\n102 71 S\n"), False),
        ((0, b"101 72 Z\n"), False),
        ((0, b"0 71 Z\n"), False),
        ((0, b"-1 71 Z\n"), False),
        ((0, b"101 71 Zgarbage\n"), False),
        ((0, b"101 71 Z extra\n"), False),
        ((0, b"101 71 Z\n\n"), False),
        ((0, b"101 71 Z\n101 71 Z\n"), False),
        ((0, b"101 71 Z\xff\n"), False),
        ((0, b"9" * 100 + b" 71 Z\n"), False),
    ],
)
def test_only_unambiguous_empty_or_zombie_group_proves_no_live_members(
    monkeypatch: pytest.MonkeyPatch,
    result: tuple[int, bytes] | None,
    expected: bool,
) -> None:
    module = _module()

    def query(group: int) -> tuple[int, bytes] | None:
        assert group == 71
        return result

    monkeypatch.setattr(module, "_query_owned_group", query)
    assert module.group_has_no_live_members(71) is expected


@pytest.mark.parametrize("group", [True, False, -1, 0, 1, 2**31, "71", None])
def test_invalid_group_cannot_expand_query_scope(
    monkeypatch: pytest.MonkeyPatch, group: object
) -> None:
    module = _module()

    def query(_: int) -> None:
        raise AssertionError("invalid group must not query processes")

    monkeypatch.setattr(module, "_query_owned_group", query)
    assert module.group_has_no_live_members(group) is False


def _synthetic_query(
    module: ModuleType,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    script = root / "inert-ps.py"
    script.write_text(source, encoding="utf-8")
    monkeypatch.setattr(
        module,
        "_PS_COMMAND",
        (str(Path(sys.executable).resolve()), "-I", "-S", str(script)),
    )


def test_query_has_exact_owned_group_arguments_and_clean_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setenv("SYNTHETIC_PARENT_SECRET", "not-inherited")
    _synthetic_query(
        module,
        tmp_path,
        monkeypatch,
        "import os,sys\n"
        "assert sys.argv[1:]==['-g','71','-o','pid=,pgid=,stat=']\n"
        "assert os.environ['HOME']=='/var/empty'\n"
        "assert os.environ['PATH']=='/usr/bin:/bin'\n"
        "assert os.environ['LC_ALL']=='C'\n"
        "assert 'SYNTHETIC_PARENT_SECRET' not in os.environ\n"
        "assert os.getcwd()=='/private/tmp'\n"
        "print('101 71 Z')\n",
    )
    assert module.group_has_no_live_members(71) is True


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.write(2,b'unknown')\n",
        "import os\nos.write(1,b'x'*65537)\n",
        "import time\ntime.sleep(60)\n",
    ],
)
def test_ambiguous_or_unbounded_query_is_stopped_and_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    module = _module()
    marker = tmp_path / "query-pid"
    _synthetic_query(
        module,
        tmp_path,
        monkeypatch,
        "import os\nfrom pathlib import Path\n"
        f"Path({str(marker)!r}).write_text(str(os.getpid()))\n" + source,
    )
    monkeypatch.setattr(module, "QUERY_TIMEOUT_SECONDS", 0.15)
    began = time.monotonic()
    assert module.group_has_no_live_members(71) is False
    assert time.monotonic() - began < 2
    query_pid = int(marker.read_text(encoding="utf-8"))
    with pytest.raises(ChildProcessError):
        os.waitpid(query_pid, os.WNOHANG)
    with pytest.raises(ProcessLookupError):
        os.kill(query_pid, 0)


def test_unavailable_query_cannot_prove_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_PS_COMMAND", ("/nonexistent/synthetic-ps",))
    assert module.group_has_no_live_members(71) is False


def test_actual_owned_group_tracks_live_then_stopped_process(tmp_path: Path) -> None:
    module = _module()
    process = subprocess.Popen(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-c",
            "import time;time.sleep(60)",
        ],
        cwd=tmp_path,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        assert module.group_has_no_live_members(process.pid) is False
    finally:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)
    assert module.group_has_no_live_members(process.pid) is True


def test_implementation_digest_binds_exact_helper_bytes() -> None:
    import hashlib

    module = _module()
    assert (
        module.implementation_digest()
        == hashlib.sha256(HELPER.read_bytes()).hexdigest()
    )
