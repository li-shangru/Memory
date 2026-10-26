from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PREPUSH = REPO_ROOT / "tools" / "pre-push.sh"
PRECOMMIT = REPO_ROOT / "tools" / "precommit.sh"
INSTALL_HOOKS = REPO_ROOT / "tools" / "install-hooks.sh"


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        check=False,
        text=True,
    )


def fixture_repo(tmp_path: Path, *, gate_exit: int) -> tuple[Path, Path]:
    """Build one synthetic repo with a stub fast gate and a bare remote."""
    assert PREPUSH.is_file()
    assert INSTALL_HOOKS.is_file()
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    for script in (PREPUSH, PRECOMMIT, INSTALL_HOOKS):
        target = repo / "tools" / script.name
        target.write_bytes(script.read_bytes())
        target.chmod(0o755)
    gate = repo / "tools" / "fast-check.sh"
    gate.write_text(f"#!/bin/sh\nexit {gate_exit}\n", encoding="utf-8")
    gate.chmod(0o755)
    assert git(repo, "init", "-q").returncode == 0
    assert (
        git(repo, "config", "user.email", "synthetic@example.invalid").returncode == 0
    )
    assert git(repo, "config", "user.name", "Synthetic Tester").returncode == 0
    assert git(repo, "add", ".").returncode == 0
    assert git(repo, "commit", "--no-verify", "-qm", "test fixture").returncode == 0
    install = subprocess.run(
        [repo / "tools" / "install-hooks.sh"],
        cwd=repo,
        capture_output=True,
        check=False,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    remote = tmp_path / "remote.git"
    assert git(tmp_path, "init", "-q", "--bare", str(remote)).returncode == 0
    assert git(repo, "remote", "add", "origin", str(remote)).returncode == 0
    return repo, remote


def test_install_hooks_installs_an_executable_pre_push_hook(tmp_path: Path) -> None:
    """Catch the installer skipping the push hook or dropping its mode."""
    repo, _remote = fixture_repo(tmp_path, gate_exit=0)
    hooks_dir = Path(git(repo, "rev-parse", "--git-path", "hooks").stdout.strip())
    if not hooks_dir.is_absolute():
        hooks_dir = repo / hooks_dir
    hook = hooks_dir / "pre-push"

    assert hook.is_file()
    assert stat.S_IMODE(hook.stat().st_mode) == 0o755
    assert hook.read_bytes() == PREPUSH.read_bytes()


def test_failing_fast_gate_blocks_the_push(tmp_path: Path) -> None:
    """Catch a push publishing a tree the fast gate refuses."""
    repo, remote = fixture_repo(tmp_path, gate_exit=1)

    pushed = git(repo, "push", "origin", "HEAD")

    assert pushed.returncode != 0
    listed = git(remote, "show-ref")
    assert listed.stdout.strip() == ""


def test_passing_fast_gate_allows_the_push(tmp_path: Path) -> None:
    """Catch the hook refusing a push the fast gate approved."""
    repo, remote = fixture_repo(tmp_path, gate_exit=0)

    pushed = git(repo, "push", "origin", "HEAD")

    assert pushed.returncode == 0, pushed.stderr
    listed = git(remote, "show-ref")
    assert listed.stdout.strip() != ""


def test_empty_ref_input_skips_the_gate(tmp_path: Path) -> None:
    """Catch an up-to-date push paying the whole gate for pushing nothing.

    This drives the tools copy directly;
    `test_install_hooks_installs_an_executable_pre_push_hook` proves the
    installed hook is byte-identical, so the two together cover the
    installed behavior.
    """
    repo, _remote = fixture_repo(tmp_path, gate_exit=1)

    ran = subprocess.run(
        [repo / "tools" / "pre-push.sh"],
        cwd=repo,
        capture_output=True,
        check=False,
        text=True,
        input="",
        env={**os.environ},
    )

    assert ran.returncode == 0, ran.stderr
