"""Distribution boundaries for a fresh public checkout, without owner state."""

from __future__ import annotations

import email
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _contains_client_trial(value: object) -> bool:
    if isinstance(value, dict):
        if {"run_id", "observed_labels"} <= value.keys() and (
            "client" in value or "phase" in value
        ):
            return True
        return any(_contains_client_trial(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_client_trial(item) for item in value)
    return False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"id": "synthetic_case", "must": ["retain_originals"]}, False),
        ({"run_id": "synthetic_run", "phase": "setup"}, False),
        (
            {"run_id": "synthetic_run", "client": "example", "observed_labels": []},
            True,
        ),
        (
            {
                "records": [
                    {"run_id": "invented", "phase": "guided", "observed_labels": []}
                ]
            },
            True,
        ),
    ],
)
def test_trial_detection_does_not_treat_synthetic_labels_as_provenance(
    value: object, expected: bool
) -> None:
    assert _contains_client_trial(value) is expected


def test_public_source_excludes_client_trial_records() -> None:
    """Authored cases belong in source; observed client trials stay external."""
    files = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=REPO_ROOT,
        )
        .decode()
        .split("\0")
    )
    for name in files:
        path = REPO_ROOT / name
        if path.suffix not in {".json", ".jsonl"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        values = (
            [json.loads(line) for line in text.splitlines() if line.strip()]
            if path.suffix == ".jsonl"
            else [json.loads(text)]
        )
        assert not any(_contains_client_trial(value) for value in values), name


def test_built_distributions_include_the_mit_grant(tmp_path: Path) -> None:
    """A source LICENSE alone does not grant rights in a copied wheel."""
    subprocess.run(
        ["uv", "build", "--out-dir", str(tmp_path)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheel = next(tmp_path.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = email.message_from_bytes(archive.read(metadata_name))
        assert metadata["License-Expression"] == "MIT"
        assert metadata["License-File"] == "LICENSE"
        license_name = next(
            name for name in archive.namelist() if name.endswith("/licenses/LICENSE")
        )
        assert archive.read(license_name) == (REPO_ROOT / "LICENSE").read_bytes()
    with tarfile.open(next(tmp_path.glob("*.tar.gz"))) as archive:
        member = next(
            item for item in archive.getmembers() if item.name.endswith("/LICENSE")
        )
        stream = archive.extractfile(member)
        assert stream is not None
        assert stream.read() == (REPO_ROOT / "LICENSE").read_bytes()
