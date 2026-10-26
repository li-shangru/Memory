from __future__ import annotations

import hashlib
import importlib.util
import threading
from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from urllib.error import HTTPError

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fetcher() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "wheel_fetch", REPO_ROOT / "third_party" / "fetch-wheels.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def wheel_server(tmp_path: Path) -> Iterator[tuple[Path, str]]:
    assets = tmp_path / "assets"
    assets.mkdir()
    handler = partial(SimpleHTTPRequestHandler, directory=str(assets))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield assets, f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def synthetic_checkout(root: Path, assets: Path) -> dict[str, bytes]:
    wheels = {
        "synthetic_sqlcipher-current.whl": b"synthetic current native wheel",
        "synthetic_sqlcipher-previous.whl": b"synthetic previous native wheel",
        "synthetic_playwright+local.whl": b"synthetic browser tooling wheel",
    }
    for name, payload in wheels.items():
        (assets / name).write_bytes(payload)
    for companion in ("memory-sqlcipher3", "playwright"):
        directory = root / "third_party" / companion
        directory.mkdir(parents=True)
        entries = [
            f"{hashlib.sha256(payload).hexdigest()}  third_party/wheels/{name}\n"
            for name, payload in wheels.items()
            if ("sqlcipher" in name) == (companion == "memory-sqlcipher3")
        ]
        (directory / "wheel-hash.txt").write_text("".join(entries), encoding="utf-8")
    return wheels


def test_fetches_every_manifest_entry_and_works_offline_when_cached(
    fetcher: ModuleType, wheel_server: tuple[Path, str], tmp_path: Path
) -> None:
    assets, url = wheel_server
    root = tmp_path / "checkout"
    wheels = synthetic_checkout(root, assets)

    fetcher.fetch_wheels(root, url)

    destination = root / "third_party" / "wheels"
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == wheels
    for asset in assets.iterdir():
        asset.unlink()
    # No network request can succeed after removing the served files.
    fetcher.fetch_wheels(root, url)


def test_repairs_a_corrupt_cached_wheel(
    fetcher: ModuleType, wheel_server: tuple[Path, str], tmp_path: Path
) -> None:
    assets, url = wheel_server
    root = tmp_path / "checkout"
    wheels = synthetic_checkout(root, assets)
    destination = root / "third_party" / "wheels"
    destination.mkdir()
    name = next(iter(wheels))
    (destination / name).write_bytes(b"corrupt cached bytes")

    fetcher.fetch_wheels(root, url)

    assert (destination / name).read_bytes() == wheels[name]


@pytest.mark.parametrize("failure", ["wrong-hash", "missing", "interrupted"])
def test_failed_download_does_not_replace_existing_file_or_leave_partial_bytes(
    fetcher: ModuleType,
    wheel_server: tuple[Path, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    assets, url = wheel_server
    root = tmp_path / "checkout"
    wheels = synthetic_checkout(root, assets)
    destination = root / "third_party" / "wheels"
    destination.mkdir()
    name = next(iter(wheels))
    cached = destination / name
    cached.write_bytes(b"existing corrupt cache")
    if failure == "wrong-hash":
        (assets / name).write_bytes(b"untrusted release bytes")
        expected_error: type[Exception] = ValueError
    elif failure == "missing":
        (assets / name).unlink()
        expected_error = HTTPError
    else:
        original_copy = fetcher.shutil.copyfileobj

        def interrupted_copy(source: object, target: object) -> None:
            original_copy(source, target, length=4)
            raise OSError("synthetic interrupted transfer")

        monkeypatch.setattr(fetcher.shutil, "copyfileobj", interrupted_copy)
        expected_error = OSError

    with pytest.raises(expected_error):
        fetcher.fetch_wheels(root, url)

    assert list(destination.iterdir()) == [cached]
    assert cached.read_bytes() == b"existing corrupt cache"


@pytest.mark.parametrize(
    "entry",
    [
        "invalid-hash  third_party/wheels/fixture.whl\n",
        "{digest}  third_party/wheels/../escaped.whl\n",
        "{digest}  /tmp/escaped.whl\n",
        "{digest}  third_party/wheels/fixture.txt\n",
        "{digest}  third_party/wheels/fixture.whl\n" * 2,
    ],
)
def test_invalid_manifests_fail_before_creating_the_wheelhouse(
    fetcher: ModuleType, tmp_path: Path, entry: str
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    root = tmp_path / "checkout"
    synthetic_checkout(root, assets)
    manifest = root / "third_party" / "memory-sqlcipher3" / "wheel-hash.txt"
    manifest.write_text(entry.format(digest="a" * 64), encoding="utf-8")

    with pytest.raises(ValueError):
        fetcher.fetch_wheels(root, "http://127.0.0.1:1/")

    assert not (root / "third_party" / "wheels").exists()
