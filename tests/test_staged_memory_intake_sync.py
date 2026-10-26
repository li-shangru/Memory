"""Deterministic, fail-closed synchronization for the companion Skill bundle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPO_ROOT / "tools"
TOOL = TOOLS_ROOT / "staged_memory_intake_sync.py"
CANONICAL_SOURCE = TOOLS_ROOT / "staged-memory-intake"
sys.path.insert(0, str(TOOLS_ROOT))

import staged_memory_intake_sync as sync  # noqa: E402


def write_bundle(root: Path, *, version: str = "one") -> None:
    (root / "agents").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "SKILL.md").write_text(f"skill {version}\n", encoding="utf-8")
    (root / "agents" / "openai.yaml").write_text(
        f'interface:\n  display_name: "{version}"\n',
        encoding="utf-8",
    )
    (root / "scripts" / "tool.py").write_text(
        f'VALUE = "{version}"\n',
        encoding="utf-8",
    )


def manifest_bytes(manifest: sync.BundleManifest) -> bytes:
    payload = {
        "bundle_digest": manifest.bundle_digest,
        "files": [
            {"path": item.path, "sha256": item.sha256, "size": item.size}
            for item in manifest.files
        ],
        "schema": manifest.schema,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def assert_bundle_error(code: str, operation: Callable[[], object]) -> None:
    with pytest.raises(sync.BundleError) as raised:
        operation()
    assert raised.value.code == code


def test_canonical_bundle_matches_checked_in_manifest() -> None:
    """Catch deploying canonical bytes that were not explicitly frozen."""
    manifest = sync.check_source(CANONICAL_SOURCE)

    assert (CANONICAL_SOURCE / "bundle-manifest.json").read_bytes() == (
        manifest_bytes(manifest)
    )


def test_canonical_copy_requires_refreeze_after_one_helper_byte_changes(
    tmp_path: Path,
) -> None:
    """Prove canonical helper drift fails until a new manifest is frozen."""
    source = tmp_path / "source"
    shutil.copytree(CANONICAL_SOURCE, source)
    original = sync.check_source(source)
    helper = source / "scripts" / "staged_memory_intake" / "__init__.py"
    before = helper.read_bytes()
    after = before.replace(b"Private", b"private", 1)
    assert len(after) == len(before)
    assert after != before
    helper.write_bytes(after)

    assert_bundle_error("source_manifest", lambda: sync.check_source(source))

    updated = sync.freeze_manifest(source)
    assert updated.bundle_digest != original.bundle_digest
    assert sync.check_source(source) == updated


def test_check_source_accepts_git_checkout_manifest_mode(tmp_path: Path) -> None:
    """Catch rejecting the public manifest mode Git materializes on checkout."""
    source = tmp_path / "source"
    write_bundle(source)
    manifest = sync.freeze_manifest(source)
    os.chmod(source / "bundle-manifest.json", 0o644)

    assert sync.check_source(source) == manifest


def test_freeze_install_and_check_are_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "source"
    codex_target = tmp_path / "codex" / "staged-memory-intake"
    claude_target = tmp_path / "claude" / "staged-memory-intake"
    write_bundle(source)

    manifest = sync.freeze_manifest(source)

    assert manifest.schema == "staged-memory-intake.bundle.v1"
    assert [item.path for item in manifest.files] == sorted(
        ["SKILL.md", "agents/openai.yaml", "scripts/tool.py"]
    )
    assert (source / "bundle-manifest.json").read_bytes() == manifest_bytes(manifest)
    assert (source / "bundle-manifest.json").stat().st_mode & 0o777 == 0o600
    assert sync.check_source(source) == manifest
    assert sync.install_bundle(source, codex_target).bundle_digest == (
        manifest.bundle_digest
    )
    assert sync.check_install(source, codex_target) == manifest
    assert sync.install_bundle(source, claude_target) == manifest
    assert (codex_target / "bundle-manifest.json").read_bytes() == (
        source / "bundle-manifest.json"
    ).read_bytes()


def test_markdown_references_are_installed_and_drift_checked(tmp_path: Path) -> None:
    """A routed procedure must ship with the same integrity as its entrypoint."""
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source)
    references = source / "references"
    references.mkdir()
    reference = references / "relocation.md"
    reference.write_text("# Relocation\n\nUse the guarded helper.\n", encoding="utf-8")

    manifest = sync.freeze_manifest(source)
    assert "references/relocation.md" in {item.path for item in manifest.files}
    assert sync.install_bundle(source, target) == manifest
    installed = target / "references" / "relocation.md"
    assert installed.read_bytes() == reference.read_bytes()
    assert sync.check_install(source, target) == manifest

    installed.write_text("# Relocation\n\nSkip the guard.\n", encoding="utf-8")
    assert_bundle_error("target_drift", lambda: sync.check_install(source, target))
    installed.write_bytes(reference.read_bytes())
    installed.unlink()
    installed.parent.rmdir()
    assert_bundle_error("target_drift", lambda: sync.check_install(source, target))


@pytest.mark.parametrize("name", ["references/run.py", "references/nested/guide.md"])
def test_reference_allowlist_rejects_other_resources(tmp_path: Path, name: str) -> None:
    """Supporting prose does not open the bundle to arbitrary resource trees."""
    source = tmp_path / "source"
    write_bundle(source)
    unexpected = source / name
    unexpected.parent.mkdir(parents=True)
    unexpected.write_text("unexpected\n", encoding="utf-8")

    assert_bundle_error("source_extra", lambda: sync.freeze_manifest(source))


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("byte", "target_drift"),
        ("extra", "target_extra"),
        ("extra_directory", "target_extra"),
        ("extra_nested_directory", "target_extra"),
    ],
)
def test_check_install_rejects_drift_and_extras(
    tmp_path: Path,
    mutation: str,
    code: str,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source)
    sync.freeze_manifest(source)
    sync.install_bundle(source, target)
    if mutation == "byte":
        (target / "SKILL.md").write_text("drift\n", encoding="utf-8")
    elif mutation == "extra":
        (target / "foreign.txt").write_text("foreign\n", encoding="utf-8")
    elif mutation == "extra_directory":
        (target / "foreign").mkdir()
    else:
        (target / "scripts" / "foreign").mkdir()

    assert_bundle_error(
        "target_drift" if mutation == "byte" else code,
        lambda: sync.check_install(source, target),
    )


def test_check_source_rejects_corrupt_checked_in_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_bundle(source)
    sync.freeze_manifest(source)
    (source / "bundle-manifest.json").write_text("{}", encoding="utf-8")

    assert_bundle_error("source_manifest", lambda: sync.check_source(source))


@pytest.mark.parametrize(
    "location",
    [
        "source_ancestor",
        "source_root",
        "source_directory",
        "source_file",
        "target_ancestor",
        "target_root",
        "target_directory",
        "target_file",
    ],
)
def test_symlink_at_every_bundle_path_level_is_rejected(
    tmp_path: Path,
    location: str,
) -> None:
    real_source = tmp_path / "real-source"
    source = real_source
    target = tmp_path / "target"
    write_bundle(real_source)
    sync.freeze_manifest(real_source)

    def check_source() -> object:
        return sync.check_source(source)

    def check_target() -> object:
        return sync.check_install(source, target)

    def install_target() -> object:
        return sync.install_bundle(source, target)

    if location == "source_ancestor":
        source_parent = tmp_path / "source-parent"
        source_parent.symlink_to(tmp_path, target_is_directory=True)
        source = source_parent / "real-source"
        operation = check_source
    elif location == "source_root":
        source = tmp_path / "source-link"
        source.symlink_to(real_source, target_is_directory=True)
        operation = check_source
    elif location == "source_directory":
        (real_source / "agents").rename(real_source / "real-agents")
        (real_source / "agents").symlink_to(
            real_source / "real-agents",
            target_is_directory=True,
        )
        operation = check_source
    elif location == "source_file":
        (real_source / "SKILL.md").rename(real_source / "skill-real")
        (real_source / "SKILL.md").symlink_to(real_source / "skill-real")
        operation = check_source
    elif location == "target_ancestor":
        real_target_parent = tmp_path / "real-target-parent"
        real_target_parent.mkdir()
        target_parent = tmp_path / "target-parent"
        target_parent.symlink_to(real_target_parent, target_is_directory=True)
        target = target_parent / "target"
        operation = install_target
    else:
        sync.install_bundle(source, target)
        if location == "target_root":
            real_target = tmp_path / "real-target"
            target.rename(real_target)
            target.symlink_to(real_target, target_is_directory=True)
        elif location == "target_directory":
            (target / "agents").rename(target / "real-agents")
            (target / "agents").symlink_to(
                target / "real-agents",
                target_is_directory=True,
            )
        else:
            (target / "SKILL.md").rename(target / "skill-real")
            (target / "SKILL.md").symlink_to(target / "skill-real")
        operation = check_target

    assert_bundle_error("unsafe_entry", operation)


def test_source_symlink_component_before_parent_escape_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_source = real_parent / "source"
    write_bundle(real_source)
    sync.freeze_manifest(real_source)
    alias = real_parent / "alias"
    alias.symlink_to(real_source, target_is_directory=True)
    bypass = alias / ".." / "source"

    def fail_if_read(path: Path, *, code: str) -> bytes:
        del path, code
        raise AssertionError("source bytes were read through a symlink escape")

    monkeypatch.setattr(sync, "_read_regular", fail_if_read)

    assert_bundle_error("unsafe_entry", lambda: sync.check_source(bypass))


def test_target_symlink_component_before_parent_escape_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_bundle(source)
    sync.freeze_manifest(source)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    real_target = real_parent / "target"
    alias = real_parent / "alias"
    alias.symlink_to(real_target, target_is_directory=True)
    bypass = alias / ".." / "target"
    lock = real_parent / ".target.lock"

    assert_bundle_error("unsafe_entry", lambda: sync.install_bundle(source, bypass))
    assert not real_target.exists()
    assert not lock.exists()


def test_interrupted_update_resumes_only_from_old_or_new_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source, version="one")
    sync.freeze_manifest(source)
    sync.install_bundle(source, target)

    for path in (source / "SKILL.md", source / "agents" / "openai.yaml"):
        path.write_text(
            path.read_text(encoding="utf-8").replace("one", "two"), encoding="utf-8"
        )
    updated = sync.freeze_manifest(source)
    original_replace = sync.replace_file
    deployed_replacements = 0

    def fail_between_replacements(
        old: str | os.PathLike[str], new: str | os.PathLike[str]
    ) -> None:
        nonlocal deployed_replacements
        destination = Path(new)
        if target in destination.parents and destination.name != "bundle-manifest.json":
            deployed_replacements += 1
            if deployed_replacements == 2:
                raise OSError("synthetic interruption")
        original_replace(old, new)

    monkeypatch.setattr(sync, "replace_file", fail_between_replacements)
    assert_bundle_error("install_failed", lambda: sync.install_bundle(source, target))
    monkeypatch.setattr(sync, "replace_file", original_replace)

    assert sync.install_bundle(source, target) == updated
    assert sync.check_install(source, target) == updated


def test_interrupted_first_install_resumes_without_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source)
    manifest = sync.freeze_manifest(source)
    original_replace = sync.replace_file
    deployed_replacements = 0

    def fail_before_manifest(
        old: str | os.PathLike[str], new: str | os.PathLike[str]
    ) -> None:
        nonlocal deployed_replacements
        destination = Path(new)
        if target in destination.parents:
            deployed_replacements += 1
            if deployed_replacements == 2:
                raise OSError("synthetic interruption")
        original_replace(old, new)

    monkeypatch.setattr(sync, "replace_file", fail_before_manifest)
    assert_bundle_error("install_failed", lambda: sync.install_bundle(source, target))
    monkeypatch.setattr(sync, "replace_file", original_replace)

    assert not (target / "bundle-manifest.json").exists()
    assert sync.install_bundle(source, target) == manifest
    assert sync.check_install(source, target) == manifest


def test_manifestless_partial_first_install_refuses_byte_drift(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source)
    sync.freeze_manifest(source)
    target.mkdir()
    (target / "SKILL.md").write_text("arbitrary\n", encoding="utf-8")

    assert_bundle_error("target_drift", lambda: sync.install_bundle(source, target))
    assert (target / "SKILL.md").read_text(encoding="utf-8") == "arbitrary\n"


def test_install_preserves_unlisted_target_entry(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source)
    sync.freeze_manifest(source)
    target.mkdir()
    unlisted = target / "owner-entry.txt"
    unlisted.write_text("preserve\n", encoding="utf-8")

    assert_bundle_error("target_extra", lambda: sync.install_bundle(source, target))
    assert unlisted.read_text(encoding="utf-8") == "preserve\n"


def test_interrupted_update_refuses_arbitrary_drift(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    write_bundle(source, version="one")
    sync.freeze_manifest(source)
    sync.install_bundle(source, target)
    (source / "SKILL.md").write_text("skill two\n", encoding="utf-8")
    sync.freeze_manifest(source)
    (target / "SKILL.md").write_text("arbitrary\n", encoding="utf-8")

    assert_bundle_error("target_drift", lambda: sync.install_bundle(source, target))


def test_cli_errors_are_content_free(tmp_path: Path) -> None:
    secret_path = tmp_path / "private-name"
    completed = subprocess.run(
        [sys.executable, str(TOOL), "check-source", "--source", str(secret_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "bundle_error:source_invalid\n"
    assert str(secret_path) not in completed.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ["/private/synthetic-command"],
        ["check-source", "--source", ".", "--private-/synthetic-option"],
    ],
)
def test_cli_argument_errors_are_content_free(arguments: list[str]) -> None:
    completed = subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "bundle_error:invalid_argument\n"
    assert "/private/" not in completed.stderr


def test_manifest_digest_is_canonical_file_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_bundle(source)
    manifest = sync.build_manifest(source)
    payload = [
        {"path": item.path, "sha256": item.sha256, "size": item.size}
        for item in manifest.files
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    assert manifest.bundle_digest == hashlib.sha256(encoded).hexdigest()
