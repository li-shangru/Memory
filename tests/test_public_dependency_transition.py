"""Artifact custody and exact transition guards use disposable synthetic wheels."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import delivery as d
import dependency_transition as t


def synthetic_wheel(
    tmp_path: Path, *, script: bool = False
) -> tuple[Path, t.Target, dict[str, str]]:
    wheel = tmp_path / "synthetic-2-py3-none-any.whl"
    members = {
        "synthetic/native.so": "synthetic native bytes 合成".encode(),
        "synthetic-2.dist-info/METADATA": b"Name: synthetic\nVersion: 2\n",
        "synthetic-2.dist-info/RECORD": b"synthetic record\n",
    }
    if script:
        members["synthetic-2.dist-info/entry_points.txt"] = (
            b"[console_scripts]\nsynthetic = synthetic.cli:main [optional]\n"
        )
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    installed = tmp_path / "prefix/lib/python3.14/site-packages"
    for name, payload in members.items():
        path = installed / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    target = t.Target(
        "1",
        "2",
        wheel.name,
        "https://files.pythonhosted.org/synthetic.whl",
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
    )
    inventory = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in members.items()
        if not name.endswith("/RECORD")
    }
    return wheel, target, inventory


@pytest.mark.parametrize(
    "drift", ["native", "metadata", "missing", "extra", "artifact"]
)
def test_transition_artifact_and_complete_installed_members_must_match(
    tmp_path: Path, drift: str
) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path)
    t.verify_distribution(
        inventory, wheel, target, tmp_path / "prefix", d.verify_launcher
    )
    if drift == "native":
        inventory["synthetic/native.so"] = "0" * 64
    elif drift == "metadata":
        inventory["synthetic-2.dist-info/METADATA"] = "0" * 64
    elif drift == "missing":
        inventory.pop("synthetic/native.so")
    elif drift == "extra":
        inventory["synthetic/injected.py"] = "0" * 64
    else:
        wheel.write_bytes(b"replaced synthetic wheel")
    with pytest.raises(t.TransitionError, match="dependency_artifact"):
        t.verify_distribution(
            inventory, wheel, target, tmp_path / "prefix", d.verify_launcher
        )


def test_generated_dependency_launcher_is_bound_to_approved_entrypoint(
    tmp_path: Path,
) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path, script=True)
    prefix = tmp_path / "prefix"
    executable = prefix / "bin/synthetic"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        f"#!{prefix}/bin/python\nimport sys\nfrom synthetic.cli import main\nif __name__ == '__main__':\n    sys.exit(main())\n"
    )
    executable.chmod(0o700)
    inventory["../../../bin/synthetic"] = hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    t.verify_distribution(inventory, wheel, target, prefix, d.verify_launcher)
    executable.write_text(executable.read_text() + "print('synthetic injection')\n")
    inventory["../../../bin/synthetic"] = hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    with pytest.raises(d.DeliveryError, match="unsupported_launcher"):
        t.verify_distribution(inventory, wheel, target, prefix, d.verify_launcher)


def test_public_policy_is_bound_to_original_release_identity() -> None:
    commit, version, _ = t.policy()
    assert t.applies({"source_commit": commit, "version": version})
    assert not t.applies({"source_commit": "0" * 40, "version": version})
    assert not t.applies({"source_commit": commit, "version": "9.9.9"})


def test_unreviewed_baseline_version_cannot_join_public_transition() -> None:
    with pytest.raises(t.TransitionError, match="dependency_transition_unapproved"):
        baseline = {name: target.before for name, target in t.policy()[2].items()}
        baseline.update({"memory-sqlcipher3": d.COMPANION_VERSION, "mcp": "2.2.0"})
        d.expected_dependency_versions(baseline, public_release=True)


def test_known_target_same_version_bytes_are_still_preserved() -> None:
    before: dict[str, object] = {
        "mcp": {"mcp/server.py": "1" * 64},
        "synthetic": {"other.py": "2" * 64},
    }
    after: dict[str, object] = {
        "mcp": {"mcp/server.py": "3" * 64},
        "synthetic": {"other.py": "2" * 64},
    }
    with pytest.raises(d.DeliveryError, match="dependency_bytes_changed"):
        d.verify_preserved_dependency_bytes(before, after)
    d.verify_preserved_dependency_bytes(
        before, after, version_changes={"mcp": ("2.1.1", "2.3.0")}
    )
    with pytest.raises(d.DeliveryError, match="dependency_transition_unapproved"):
        d.verify_preserved_dependency_bytes(
            before, after, version_changes={"mcp": ("2.2.0", "2.3.0")}
        )
    with pytest.raises(d.DeliveryError, match="dependency_transition_unapproved"):
        d.verify_preserved_dependency_bytes(
            before, after, version_changes={"synthetic": ("1", "2")}
        )


def test_policy_rejects_escaping_artifact_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = json.loads(t.POLICY.read_text())
    value["dependencies"]["mcp"]["filename"] = "../escaped.whl"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value))
    monkeypatch.setattr(t, "POLICY", path)
    with pytest.raises(t.TransitionError, match="dependency_policy_invalid"):
        t.policy()


def test_unknown_archive_layout_is_not_partially_verified(tmp_path: Path) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "synthetic.data/scripts/unknown", b"unsupported synthetic layout"
        )
    target = t.Target(
        target.before,
        target.after,
        target.filename,
        target.url,
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
    )
    with pytest.raises(t.TransitionError, match="dependency_artifact_layout"):
        t.verify_distribution(inventory, wheel, target, tmp_path, d.verify_launcher)


@pytest.mark.parametrize(
    "relative", ["synthetic/injected.py", "synthetic-2.dist-info/injected.json"]
)
def test_unrecorded_dependency_files_are_rejected(
    tmp_path: Path, relative: str
) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path)
    injected = tmp_path / "prefix/lib/python3.14/site-packages" / relative
    injected.write_bytes(b"unrecorded synthetic injection")
    with pytest.raises(t.TransitionError, match="dependency_artifact_bytes_changed"):
        t.verify_distribution(
            inventory, wheel, target, tmp_path / "prefix", d.verify_launcher
        )


def test_missing_reviewed_dependency_is_rejected_before_rehearsal() -> None:
    baseline = {name: target.before for name, target in t.policy()[2].items()}
    baseline.pop("mcp-types")
    with pytest.raises(t.TransitionError, match="dependency_transition_unapproved"):
        t.expected_versions(baseline)


def test_recorded_shared_namespace_files_remain_owned_by_other_distribution(
    tmp_path: Path,
) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path)
    registered = (
        tmp_path / "prefix/lib/python3.14/site-packages/synthetic/registered.py"
    )
    registered.write_bytes(b"synthetic other distribution namespace member")
    shared = {
        "synthetic/registered.py": hashlib.sha256(registered.read_bytes()).hexdigest()
    }
    t.verify_distribution(
        inventory, wheel, target, tmp_path / "prefix", d.verify_launcher, shared
    )
    registered.write_bytes(b"unapproved change")
    with pytest.raises(t.TransitionError, match="dependency_artifact_bytes_changed"):
        t.verify_distribution(
            inventory, wheel, target, tmp_path / "prefix", d.verify_launcher, shared
        )


def test_other_distribution_cannot_claim_extra_target_metadata(tmp_path: Path) -> None:
    wheel, target, inventory = synthetic_wheel(tmp_path)
    name = "synthetic-2.dist-info/injected.json"
    extra = tmp_path / "prefix/lib/python3.14/site-packages" / name
    extra.write_bytes(b"synthetic extra metadata")
    shared = {name: hashlib.sha256(extra.read_bytes()).hexdigest()}
    with pytest.raises(t.TransitionError, match="dependency_artifact_bytes_changed"):
        t.verify_distribution(
            inventory, wheel, target, tmp_path / "prefix", d.verify_launcher, shared
        )
