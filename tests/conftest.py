"""Fixtures every synthetic suite shares.

The disposable Store fixture used to be pasted into eleven test modules, each
copy differing only in the directory name it happened to pick. One definition
means the Keychain stub, the runtime mode, and the initialization order cannot
drift between suites -- and cannot drift away from what the product actually
does at startup.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import keyring
import pytest
from synthetic import make_synthetic_store, store_synthetic_key_exclusive

from memory import keys
from memory.model import RuntimePaths

STAGED_MEMORY_INTAKE_SCRIPTS = (
    Path(__file__).resolve().parents[1] / "tools" / "staged-memory-intake" / "scripts"
)
# The canonical companion is itself manifest-checked. Test imports must not add
# bytecode files to that source tree before the manifest gate runs.
sys.dont_write_bytecode = True
sys.path.insert(0, str(STAGED_MEMORY_INTAKE_SCRIPTS))


@pytest.fixture
def synthetic_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[RuntimePaths]:
    """One freshly initialized disposable Store on a synthetic Keychain."""
    yield from make_synthetic_store(tmp_path, monkeypatch)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every real-browser journey so a run without Chromium can skip it.

    The marker is applied by location rather than by decorator: the journeys
    are the entire `tests/browser` tree, and a new one should not have to
    remember to opt in to being skippable.
    """
    for item in items:
        if "tests/browser/" in item.nodeid or item.nodeid.startswith("browser/"):
            item.add_marker(pytest.mark.browser)


@pytest.fixture
def synthetic_keychain(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[dict[tuple[str, str], str]]:
    """One in-memory stand-in for the macOS Keychain, shared by every suite.

    Five copies of this existed, and two of them stubbed only get and set.
    A test using one of those and then deleting a key would have reached the
    real Keychain -- which is the owner's, and holds the key to their Store.
    """
    backend = type("Keyring", (), {})()
    type(backend).__module__ = "keyring.backends.macOS"
    items: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    monkeypatch.setattr(
        keyring,
        "get_password",
        lambda service, account: items.get((service, account)),
    )
    monkeypatch.setattr(
        keyring,
        "set_password",
        lambda service, account, value: items.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        keys,
        "_store_master_key_exclusive",
        lambda identity, encoded: store_synthetic_key_exclusive(
            items, identity, encoded
        ),
    )
    monkeypatch.setattr(
        keyring,
        "delete_password",
        lambda service, account: items.pop((service, account)),
    )
    yield items
