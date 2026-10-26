"""Behavioral contract for the shipped copied-Skill integrity commands."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from memory import skill_sync

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGED_SKILL = REPO_ROOT / "src" / "memory" / "skill" / "SKILL.md"
SYNTHETIC_SKILL = b"---\nname: synthetic-memory\n---\nUse retained evidence.\n"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Invoke the installed command surface, not an importable helper."""
    return subprocess.run(
        [sys.executable, "-m", "memory.cli", *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )


def decoded(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Decode one successful or stale/missing status object."""
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def decoded_error(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Decode one bounded invalid or unsafe-input refusal."""
    payload = json.loads(result.stderr)
    assert isinstance(payload, dict)
    return payload


def normalized_digest(raw: bytes) -> str:
    """Independently reproduce the Store's documented Skill digest."""
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def refusal(call: Callable[[], object]) -> str:
    """Run one bounded call and return only its refusal code."""
    with pytest.raises(skill_sync.SkillSyncError) as raised:
        call()
    return raised.value.code


def test_packaged_source_is_the_shipped_skill_file() -> None:
    """Catch the shipped verifier reading a checkout or client copy instead."""
    source = skill_sync.packaged_skill_path()

    assert source.is_file()
    assert source.read_bytes() == PACKAGED_SKILL.read_bytes()
    assert source.name == "SKILL.md"


def test_packaged_source_digest_is_the_digest_the_store_reports() -> None:
    """Catch the shipped check and `store.status` describing different Skills.

    The whole point of comparing a client's copy is to learn whether it holds
    the contract the running server implements. Two independent readings of
    the packaged resource make that claim only if they agree.
    """
    from memory.mcp_server import skill_digest

    source = skill_sync.packaged_skill_path()

    assert skill_sync.digest(source.read_bytes()) == skill_digest()


def test_check_reports_exact_target_as_current(tmp_path: Path) -> None:
    """Catch byte-identical copied Skills being needlessly rewritten."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)
    target.write_bytes(SYNTHETIC_SKILL)
    before = target.stat().st_mtime_ns

    status = skill_sync.check_skill(source=source, target=target)

    assert status == skill_sync.SkillSyncStatus(
        byte_exact=True,
        source_digest=normalized_digest(SYNTHETIC_SKILL),
        status="current",
        target_digest=normalized_digest(SYNTHETIC_SKILL),
    )
    assert target.stat().st_mtime_ns == before


def test_check_accepts_lf_equivalent_target_but_reports_not_byte_exact(
    tmp_path: Path,
) -> None:
    """Catch platform line endings being confused with contract drift."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)
    target.write_bytes(SYNTHETIC_SKILL.replace(b"\n", b"\r\n"))
    before = target.stat().st_mtime_ns

    status = skill_sync.check_skill(source=source, target=target)

    assert status.status == "current"
    assert status.byte_exact is False
    assert status.source_digest == status.target_digest
    assert target.stat().st_mtime_ns == before


def test_check_reports_stale_without_mutating_target(tmp_path: Path) -> None:
    """Catch a read-only drift check silently overwriting an older Skill."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    stale = b"---\nname: synthetic-memory\n---\nOld guidance.\n"
    source.write_bytes(SYNTHETIC_SKILL)
    target.write_bytes(stale)
    before = target.stat().st_mtime_ns

    status = skill_sync.check_skill(source=source, target=target)

    assert status.status == "stale"
    assert status.target_digest == normalized_digest(stale)
    assert target.read_bytes() == stale
    assert target.stat().st_mtime_ns == before


def test_check_reports_missing_without_creating_target(tmp_path: Path) -> None:
    """Catch a check-only invocation manufacturing a missing client file."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)

    status = skill_sync.check_skill(source=source, target=target)

    assert status == skill_sync.SkillSyncStatus(
        byte_exact=False,
        source_digest=normalized_digest(SYNTHETIC_SKILL),
        status="missing",
        target_digest=None,
    )
    assert not target.exists()


def test_install_writes_exact_bytes_and_a_second_run_is_a_noop(
    tmp_path: Path,
) -> None:
    """Catch repeat installation rewriting an already exact client Skill."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)

    first = skill_sync.install_skill(source=source, target=target)
    first_stat = target.stat()
    second = skill_sync.install_skill(source=source, target=target)

    assert first.status == "synced"
    assert target.read_bytes() == SYNTHETIC_SKILL
    assert stat.S_IMODE(first_stat.st_mode) == 0o644
    assert second.status == "current"
    assert target.stat().st_ino == first_stat.st_ino
    assert target.stat().st_mtime_ns == first_stat.st_mtime_ns


def test_install_replaces_a_crlf_equivalent_target_with_exact_bytes(
    tmp_path: Path,
) -> None:
    """Catch normalized equality preventing an explicitly requested exact install."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)
    target.write_bytes(SYNTHETIC_SKILL.replace(b"\n", b"\r\n"))

    status = skill_sync.install_skill(source=source, target=target)

    assert status.status == "synced"
    assert status.byte_exact is True
    assert target.read_bytes() == SYNTHETIC_SKILL


def test_relative_paths_are_refused_before_any_filesystem_use(
    tmp_path: Path,
) -> None:
    """Catch an ambiguous working-directory-relative path being accepted."""
    absolute = tmp_path / "source-skill.md"
    absolute.write_bytes(SYNTHETIC_SKILL)

    relative_source = refusal(
        lambda: skill_sync.check_skill(
            source=Path("relative-skill.md"),
            target=tmp_path / "target-skill.md",
        )
    )
    relative_target = refusal(
        lambda: skill_sync.install_skill(
            source=absolute,
            target=Path("relative-skill.md"),
        )
    )

    assert relative_source == "path_not_absolute"
    assert relative_target == "path_not_absolute"
    assert not (tmp_path / "target-skill.md").exists()


def test_source_symlink_is_refused_without_target_mutation(tmp_path: Path) -> None:
    """Catch installation following a source link to bytes the caller did not name."""
    real_source = tmp_path / "real-source.md"
    source = tmp_path / "source-link.md"
    target = tmp_path / "target-skill.md"
    real_source.write_bytes(SYNTHETIC_SKILL)
    source.symlink_to(real_source)
    target.write_bytes(b"old\n")

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "unsafe_source"
    assert target.read_bytes() == b"old\n"


def test_missing_source_is_refused(tmp_path: Path) -> None:
    """Catch an absent source being reported as an unsafe or empty Skill."""
    code = refusal(
        lambda: skill_sync.check_skill(
            source=tmp_path / "absent-skill.md",
            target=tmp_path / "target-skill.md",
        )
    )

    assert code == "source_missing"


def test_target_symlink_is_refused_without_following_it(tmp_path: Path) -> None:
    """Catch atomic replacement being redirected through a target symlink."""
    source = tmp_path / "source-skill.md"
    real_target = tmp_path / "real-target.md"
    target = tmp_path / "target-link.md"
    source.write_bytes(SYNTHETIC_SKILL)
    real_target.write_bytes(b"old\n")
    target.symlink_to(real_target)

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "unsafe_target"
    assert real_target.read_bytes() == b"old\n"


def test_nonregular_target_is_refused(tmp_path: Path) -> None:
    """Catch a directory or device being replaced as though it were a Skill."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-directory"
    source.write_bytes(SYNTHETIC_SKILL)
    target.mkdir()

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "unsafe_target"
    assert target.is_dir()


def test_symlinked_target_parent_is_refused(tmp_path: Path) -> None:
    """Catch installation escaping the target directory through its final link."""
    source = tmp_path / "source-skill.md"
    real_parent = tmp_path / "real-parent"
    linked_parent = tmp_path / "linked-parent"
    source.write_bytes(SYNTHETIC_SKILL)
    real_parent.mkdir()
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    code = refusal(
        lambda: skill_sync.install_skill(
            source=source,
            target=linked_parent / "SKILL.md",
        )
    )

    assert code == "unsafe_parent"
    assert not (real_parent / "SKILL.md").exists()


def test_missing_target_parent_is_refused(tmp_path: Path) -> None:
    """Catch installation guessing and creating a client workspace hierarchy."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "missing" / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "unsafe_parent"
    assert not target.exists()


def test_oversized_source_is_refused_without_target_mutation(tmp_path: Path) -> None:
    """Catch a path argument turning installation into an unbounded file copier."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(b"x" * (skill_sync.MAX_SKILL_BYTES + 1))
    target.write_bytes(b"old\n")

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "skill_too_large"
    assert target.read_bytes() == b"old\n"


def test_replace_failure_preserves_target_and_removes_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a failed atomic replace damaging the old Skill or leaving debris."""
    source = tmp_path / "source-skill.md"
    target = tmp_path / "target-skill.md"
    source.write_bytes(SYNTHETIC_SKILL)
    target.write_bytes(b"old\n")

    def fail_replace(
        source_name: str,
        target_name: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        del source_name, target_name, src_dir_fd, dst_dir_fd
        raise OSError("synthetic replacement failure")

    # The module resolves `os.replace` from the shared module object at call
    # time, so replacing it here is what its own atomic step will execute.
    monkeypatch.setattr(os, "replace", fail_replace)

    code = refusal(lambda: skill_sync.install_skill(source=source, target=target))

    assert code == "filesystem_error"
    assert target.read_bytes() == b"old\n"
    assert not any(
        entry.name.startswith(".memory-skill-sync-") for entry in tmp_path.iterdir()
    )


def test_cli_check_reports_the_packaged_skill_against_an_exact_copy(
    tmp_path: Path,
) -> None:
    """Catch the shipped check disagreeing with the Skill bytes in the wheel."""
    target = tmp_path / "client-skill.md"
    target.write_bytes(PACKAGED_SKILL.read_bytes())

    result = run_cli("skill", "check", "--target", str(target))

    assert result.returncode == 0
    assert result.stderr == ""
    assert decoded(result) == {
        "byte_exact": True,
        "source_digest": normalized_digest(PACKAGED_SKILL.read_bytes()),
        "status": "current",
        "target_digest": normalized_digest(PACKAGED_SKILL.read_bytes()),
    }


def test_cli_check_reports_a_stale_copy_without_mutating_or_creating_it(
    tmp_path: Path,
) -> None:
    """Catch the read-only drift check writing the client workspace."""
    stale_target = tmp_path / "stale-skill.md"
    absent_target = tmp_path / "absent-skill.md"
    stale_target.write_bytes(SYNTHETIC_SKILL)

    stale = run_cli("skill", "check", "--target", str(stale_target))
    absent = run_cli("skill", "check", "--target", str(absent_target))

    assert stale.returncode == 1
    assert stale.stderr == ""
    assert decoded(stale)["status"] == "stale"
    assert decoded(stale)["target_digest"] == normalized_digest(SYNTHETIC_SKILL)
    assert stale_target.read_bytes() == SYNTHETIC_SKILL
    assert absent.returncode == 1
    assert decoded(absent)["status"] == "missing"
    assert not absent_target.exists()


def test_cli_install_writes_the_packaged_skill_and_then_checks_current(
    tmp_path: Path,
) -> None:
    """Catch a shipped installer that works on fixtures but not the wheel's Skill."""
    target = tmp_path / "client-skill.md"

    install = run_cli("skill", "install", "--target", str(target))
    check = run_cli("skill", "check", "--target", str(target))

    assert install.returncode == 0
    assert install.stderr == ""
    assert decoded(install)["status"] == "synced"
    assert decoded(install)["byte_exact"] is True
    assert target.read_bytes() == PACKAGED_SKILL.read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert check.returncode == 0
    assert decoded(check)["byte_exact"] is True


def test_cli_refuses_a_relative_target_without_echoing_it(tmp_path: Path) -> None:
    """Catch a refusal that prints the caller's path into a shared transcript."""
    result = run_cli("skill", "check", "--target", "relative-skill.md")

    assert result.returncode == 2
    assert result.stdout == ""
    assert decoded_error(result) == {"error": "path_not_absolute"}
    assert "relative-skill.md" not in result.stderr
    assert not (REPO_ROOT / "relative-skill.md").exists()
    assert not (tmp_path / "relative-skill.md").exists()


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("symlink", "unsafe_target"),
        ("directory", "unsafe_target"),
        ("linked-parent", "unsafe_parent"),
        ("missing-parent", "unsafe_parent"),
    ],
)
def test_cli_install_refuses_unsafe_targets_content_free(
    tmp_path: Path,
    kind: str,
    expected: str,
) -> None:
    """Catch the shipped installer losing one of the helper's target refusals."""
    target = tmp_path / "client-skill.md"
    if kind == "symlink":
        real_target = tmp_path / "real-skill.md"
        real_target.write_bytes(b"old\n")
        target.symlink_to(real_target)
    elif kind == "directory":
        target.mkdir()
    elif kind == "linked-parent":
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        (tmp_path / "linked-parent").symlink_to(real_parent, target_is_directory=True)
        target = tmp_path / "linked-parent" / "SKILL.md"
    else:
        target = tmp_path / "missing" / "SKILL.md"

    result = run_cli("skill", "install", "--target", str(target))

    assert result.returncode == 2
    assert result.stdout == ""
    assert decoded_error(result) == {"error": expected}
    assert str(tmp_path) not in result.stderr


def test_cli_skill_commands_never_open_the_store_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a Skill command that needs an unlocked Store to report drift."""
    from memory import cli

    def refuse_resolution(home: Path | None) -> None:
        del home
        pytest.fail("a Skill command resolved a Store runtime")

    monkeypatch.setattr(cli, "resolve_runtime", refuse_resolution)
    target = tmp_path / "client-skill.md"
    target.write_bytes(PACKAGED_SKILL.read_bytes())

    assert cli.main(["skill", "check", "--target", str(target)]) == 0
