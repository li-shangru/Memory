#!/usr/bin/env python3
"""Fetch the versioned companion wheels and verify their repository manifests."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import urlopen

RELEASE_URL = (
    "https://github.com/li-shangru/Memory/releases/download/vendored-wheels-1/"
)
MANIFESTS = (
    "third_party/memory-sqlcipher3/wheel-hash.txt",
    "third_party/playwright/wheel-hash.txt",
)


def manifest_entries(repo_root: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for manifest in MANIFESTS:
        lines = (repo_root / manifest).read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError(f"Empty wheel manifest: {manifest}")
        for line in lines:
            fields = line.split()
            if len(fields) != 2 or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None:
                raise ValueError(f"Invalid SHA-256 entry in {manifest}")
            digest, relative = fields
            path = PurePosixPath(relative)
            if (
                path.parts != ("third_party", "wheels", path.name)
                or relative != path.as_posix()
                or not path.name.endswith(".whl")
                or path.name in entries
            ):
                raise ValueError(f"Invalid or duplicate wheel path in {manifest}")
            entries[path.name] = digest
    return entries


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch_wheels(repo_root: Path, base_url: str = RELEASE_URL) -> None:
    entries = manifest_entries(repo_root)
    destination = repo_root / "third_party" / "wheels"
    destination.mkdir(parents=True, exist_ok=True)
    for name, expected in entries.items():
        target = destination / name
        if target.is_file() and sha256(target) == expected:
            print(f"Verified cached wheel: {name}")
            continue
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination, prefix=f".{name}.", suffix=".tmp", delete=False
            ) as output:
                temporary = Path(output.name)
                print(f"Downloading: {name}", flush=True)
                with urlopen(base_url + quote(name, safe=""), timeout=60) as response:
                    shutil.copyfileobj(response, output)
            actual = sha256(temporary)
            if actual != expected:
                raise ValueError(
                    f"SHA-256 mismatch for {name}: expected {expected}, got {actual}"
                )
            temporary.replace(target)
            print(f"Verified downloaded wheel: {name}")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        fetch_wheels(Path(__file__).resolve().parents[1])
    except (OSError, URLError, ValueError) as error:
        print(f"Wheel fetch failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
