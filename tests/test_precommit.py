from __future__ import annotations

import hashlib
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PRECOMMIT = REPO_ROOT / "tools" / "precommit.sh"
PREPUSH = REPO_ROOT / "tools" / "pre-push.sh"
INSTALL_HOOKS = REPO_ROOT / "tools" / "install-hooks.sh"


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        check=False,
        text=True,
    )


def fixture_repo(tmp_path: Path) -> Path:
    assert PRECOMMIT.is_file()
    assert INSTALL_HOOKS.is_file()
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / ".gitignore", repo / ".gitignore")
    shutil.copy2(REPO_ROOT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(PRECOMMIT, repo / "tools" / "precommit.sh")
    shutil.copy2(PREPUSH, repo / "tools" / "pre-push.sh")
    shutil.copy2(INSTALL_HOOKS, repo / "tools" / "install-hooks.sh")
    ruff = shutil.which("ruff")
    assert ruff is not None
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / ".venv" / "bin" / "ruff").symlink_to(ruff)
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
    return repo


def test_planted_fake_key_blocks_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    fake_key = "Ab3dEf5h" + "Ij7lMn9p" + "Qr2tUv4x" + "Yz6Bcd8F"
    (repo / "credential.txt").write_text(
        f"SERVICE_API_KEY={fake_key}\n",
        encoding="utf-8",
    )
    assert git(repo, "add", "credential.txt").returncode == 0

    result = git(repo, "commit", "-m", "plant synthetic key")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "secret" in result.stderr.lower()


def test_ignored_database_path_blocks_forced_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    (repo / "synthetic.db").write_bytes(b"not a real database")
    assert git(repo, "add", "-f", "synthetic.db").returncode == 0

    result = git(repo, "commit", "-m", "plant synthetic database")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "forbidden path" in result.stderr.lower()


def test_oversized_file_blocks_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    (repo / "oversized.bin").write_bytes(b"x" * (1024 * 1024 + 1))
    assert git(repo, "add", "oversized.bin").returncode == 0

    result = git(repo, "commit", "-m", "plant oversized fixture")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "larger than 1 mb" in result.stderr.lower()


def test_precommit_allowlists_only_the_exact_release_companion_artifacts() -> None:
    """Keep the large-file escape hash-bound to the audited wheels."""
    hook = PRECOMMIT.read_text(encoding="utf-8")
    artifacts = {
        (
            "third_party/wheels/"
            "memory_sqlcipher3-0.6.2+sqlcipher4.17.0-"
            "cp314-cp314-macosx_26_0_arm64.whl"
        ): "ad7e1fcd20de2d7cf94da8fb5a56962f77a941bd46326e9501daf6a0e6011f11",
        (
            "third_party/wheels/"
            "playwright-1.62.0+memory.1-py3-none-macosx_26_0_arm64.whl"
        ): "ab2da760f37867fa775bf565f2fa3d8c59f2d414bf4dc553879f9053c6c1824a",
    }
    artifacts[
        "third_party/wheels/memory_sqlcipher3-0.6.2+sqlcipher4.17.0.memory1-cp314-cp314-macosx_26_0_arm64.whl"
    ] = "3436966d149f0e498f69aa78612bc8be2b9c8340fa44c5fb3f4cc50c5ddf2106"
    for path, expected_digest in artifacts.items():
        assert path in hook
        assert expected_digest in hook
        assert hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest() == (
            expected_digest
        )


def test_unformatted_python_blocks_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    source = repo / "src" / "memory"
    source.mkdir(parents=True)
    (source / "unformatted.py").write_text(
        "def synthetic( ):\n return 1\n",
        encoding="utf-8",
    )
    assert git(repo, "add", "src/memory/unformatted.py").returncode == 0

    result = git(repo, "commit", "-m", "plant unformatted Python")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "ruff format" in result.stderr.lower()


def test_high_entropy_token_blocks_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    token = "aB3dE5fG7hJ9" + "kL2mN4pQ6rS8" + "tU1vW3xY5zA7" + "cD9eF2gH4jK6"
    (repo / "opaque.txt").write_text(f"opaque {token}\n", encoding="utf-8")
    assert git(repo, "add", "opaque.txt").returncode == 0

    result = git(repo, "commit", "-m", "plant opaque token")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "high-entropy" in result.stderr.lower()


@pytest.mark.parametrize(
    ("prefix", "suffix", "allowed"),
    [
        ("", "", True),
        ("X", "", False),
        ("", "/untrustedABC123", False),
        ("token=", "", False),
        ("", "\nopaque " + "aB3dE5fG7hJ9" * 4, False),
    ],
)
def test_public_developer_python_path_is_exact_and_does_not_hide_secrets(
    tmp_path: Path, prefix: str, suffix: str, allowed: bool
) -> None:
    repo = fixture_repo(tmp_path)
    executable = "/Library/Developer/CommandLineTools/usr/bin/python3"
    (repo / "path.txt").write_text(f"{prefix}{executable}{suffix}\n", encoding="utf-8")
    assert git(repo, "add", "path.txt").returncode == 0

    result = git(repo, "commit", "-m", "check synthetic platform path")

    if allowed:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "pre-commit blocked" in result.stderr.lower()


@pytest.mark.parametrize(
    ("prefix", "suffix", "allowed"),
    [
        ("", "", True),
        ('"', '"', False),
        ("", "; secret=" + "aB3dE5fG7hJ9" * 2, False),
        ("", "\nSERVICE_API_KEY=" + "aB3dE5fG7hJ9" * 2, False),
        ("", "\nopaque " + "aB3dE5fG7hJ9" * 4, False),
    ],
)
def test_runtime_random_generation_is_exact_and_does_not_hide_secrets(
    tmp_path: Path, prefix: str, suffix: str, allowed: bool
) -> None:
    repo = fixture_repo(tmp_path)
    assignment = "self._secret = " + "secrets.token_bytes(SECRET_BYTES)"
    (repo / "assignment.txt").write_text(
        f"{prefix}{assignment}{suffix}\n", encoding="utf-8"
    )
    assert git(repo, "add", "assignment.txt").returncode == 0

    result = git(repo, "commit", "-m", "check runtime random generation")

    if allowed:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "pre-commit blocked" in result.stderr.lower()


def test_private_key_header_blocks_commit(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    header = "-----" + "BEGIN PRIVATE KEY-----"
    (repo / "private.txt").write_text(f"{header}\n", encoding="utf-8")
    assert git(repo, "add", "private.txt").returncode == 0

    result = git(repo, "commit", "-m", "plant private key header")

    assert result.returncode != 0
    assert "pre-commit blocked" in result.stderr.lower()
    assert "private key" in result.stderr.lower()


def test_hook_install_is_idempotent_and_exact(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    installed = repo / ".git" / "hooks" / "pre-commit"

    for _ in range(2):
        result = subprocess.run(
            [repo / "tools" / "install-hooks.sh"],
            cwd=repo,
            capture_output=True,
            check=False,
            text=True,
        )
        assert result.returncode == 0

    assert installed.read_bytes() == (repo / "tools" / "precommit.sh").read_bytes()
    assert installed.stat().st_mode & stat.S_IXUSR


def test_never_commit_ignore_section_covers_runtime_fences() -> None:
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith("# Never commit ")
    )
    section: set[str] = set()
    for line in lines[start + 1 :]:
        if not line and section:
            break
        if line and not line.startswith("#"):
            section.add(line)

    assert {
        "*.db",
        "*.db-*",
        "*.sqlite*",
        "*.key",
        "*.pem",
        "*.env",
        ".env*",
        "var/",
        "runtime/",
        "backups/",
        "objects/",
        "*.recovery-kit*",
    } <= section


def test_ordinary_docs_and_store_name_commit_cleanly(tmp_path: Path) -> None:
    repo = fixture_repo(tmp_path)
    (repo / "docs").mkdir()
    source = repo / "src" / "memory"
    source.mkdir(parents=True)
    (repo / "docs" / "boundary.md").write_text("ordinary docs\n", encoding="utf-8")
    (source / "name.py").write_text(
        'PROJECT = "Memory"\n',
        encoding="utf-8",
    )
    assert (
        git(
            repo,
            "add",
            "docs/boundary.md",
            "src/memory/name.py",
        ).returncode
        == 0
    )

    result = git(repo, "commit", "-m", "allow scoped references")

    assert result.returncode == 0, result.stderr
