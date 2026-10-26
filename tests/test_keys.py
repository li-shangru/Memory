from __future__ import annotations

import base64
import importlib
import sys
from types import ModuleType

import keyring
import pytest
from keyring.errors import KeyringError

from memory.errors import KeyAlreadyExistsError, KeyUnavailableError
from memory.model import StoreIdentity


def synthetic_identity(store_id: str = "1" * 32) -> object:
    model = importlib.import_module("memory.model")
    return model.StoreIdentity(
        product="memory",
        schema_lineage="memory-store-v1",
        schema_version=1,
        store_id=store_id,
        runtime_mode=model.RuntimeMode.PERSONAL,
        inbox_path="/synthetic/inbox",
    )


def test_master_key_uses_distinct_store_namespace_and_random_32_bytes(
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch reuse of the Service Keychain item or a non-256-bit key."""
    keys = importlib.import_module("memory.keys")
    identity = synthetic_identity()

    assert hasattr(keys, "create_master_key")
    created = keys.create_master_key(identity)

    assert keys.KEYCHAIN_SERVICE == "memory"
    assert len(created) == 32
    assert synthetic_keychain == {
        ("memory", "1" * 32): base64.b64encode(created).decode("ascii")
    }
    assert keys.load_master_key(identity) == created


def test_create_master_key_refuses_to_replace_an_existing_item(
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    identity = synthetic_identity()
    original = base64.b64encode(b"k" * 32).decode("ascii")
    synthetic_keychain[("memory", "1" * 32)] = original

    with pytest.raises(errors.KeyAlreadyExistsError):
        keys.create_master_key(identity)

    assert synthetic_keychain[("memory", "1" * 32)] == original


def test_create_master_key_preserves_a_competing_creator_after_absence_check(
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """A competing add after the absence read must survive the losing creator."""
    keys = importlib.import_module("memory.keys")
    identity = synthetic_identity()
    original = base64.b64encode(b"w" * 32).decode("ascii")

    def get_password(service: str, account: str) -> str | None:
        observed = synthetic_keychain.get((service, account))
        if observed is None:
            synthetic_keychain[(service, account)] = original
        return observed

    def store_exclusive(store_identity: StoreIdentity, encoded: str) -> None:
        account = (keys.KEYCHAIN_SERVICE, store_identity.store_id)
        if account in synthetic_keychain:
            raise KeyAlreadyExistsError("synthetic competing item exists")
        synthetic_keychain[account] = encoded

    monkeypatch.setattr(keyring, "get_password", get_password)
    monkeypatch.setattr(keys, "_store_master_key_exclusive", store_exclusive)

    with pytest.raises(KeyAlreadyExistsError):
        keys.create_master_key(identity, material=b"l" * 32)

    assert synthetic_keychain[("memory", "1" * 32)] == original


class SyntheticSecurityAPI(ModuleType):
    """Only the Security add primitive exists; no operation can reach the OS."""

    def __init__(self, status: int = 0) -> None:
        super().__init__("keyring.backends.macOS.api")
        self.status = status
        self.queries: list[dict[str, object]] = []
        self.additions: list[object] = []

    def k_(self, name: str) -> object:
        assert name == "kSecClassGenericPassword"
        return "synthetic-generic-password-class"

    def create_query(self, **attributes: object) -> object:
        self.queries.append(attributes)
        return attributes

    def SecItemAdd(self, query: object, result: None) -> int:
        assert result is None
        self.additions.append(query)
        return self.status


def test_exclusive_key_add_preserves_keyring_item_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = importlib.import_module("memory.keys")
    api = SyntheticSecurityAPI()
    monkeypatch.setitem(sys.modules, api.__name__, api)
    encoded = base64.b64encode(b"s" * 32).decode("ascii")

    keys._store_master_key_exclusive(synthetic_identity(), encoded)

    assert api.queries == [
        {
            "kSecClass": "synthetic-generic-password-class",
            "kSecAttrService": "memory",
            "kSecAttrAccount": "1" * 32,
            "kSecValueData": encoded,
        }
    ]
    assert api.additions == api.queries


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (-25299, KeyAlreadyExistsError),
        (-128, KeyUnavailableError),
        (-25293, KeyUnavailableError),
        (-25308, KeyUnavailableError),
        (-99999, KeyUnavailableError),
    ],
)
def test_exclusive_key_add_maps_duplicate_and_os_refusals_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    expected: type[Exception],
) -> None:
    keys = importlib.import_module("memory.keys")
    api = SyntheticSecurityAPI(status)
    monkeypatch.setitem(sys.modules, api.__name__, api)

    with pytest.raises(expected):
        keys._store_master_key_exclusive(synthetic_identity(), "synthetic-key")

    assert len(api.additions) == 1


def test_create_master_key_verifies_the_exclusively_added_item(
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    keys = importlib.import_module("memory.keys")
    monkeypatch.setattr(keys, "_store_master_key_exclusive", lambda *_args: None)

    with pytest.raises(KeyUnavailableError, match="did not retain"):
        keys.create_master_key(synthetic_identity(), material=b"s" * 32)

    assert synthetic_keychain == {}


def test_load_master_key_fails_closed_when_item_is_missing(
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")

    with pytest.raises(errors.KeyMissingError, match="missing"):
        keys.load_master_key(synthetic_identity())

    assert synthetic_keychain == {}


@pytest.mark.parametrize(
    "stored",
    ["not-base64!", base64.b64encode(b"short").decode("ascii")],
)
def test_load_master_key_rejects_malformed_or_wrong_length_items(
    synthetic_keychain: dict[tuple[str, str], str],
    stored: str,
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    synthetic_keychain[("memory", "1" * 32)] = stored

    with pytest.raises(errors.KeyMismatchError):
        keys.load_master_key(synthetic_identity())

    assert synthetic_keychain[("memory", "1" * 32)] == stored


def test_keychain_unavailability_is_typed_and_never_mints_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    backend = type("Keyring", (), {})()
    type(backend).__module__ = "keyring.backends.macOS"
    writes: list[str] = []
    monkeypatch.setattr(keyring, "get_keyring", lambda: backend)
    monkeypatch.setattr(
        keyring,
        "get_password",
        lambda _service, _account: (_ for _ in ()).throw(
            KeyringError("synthetic locked keychain")
        ),
    )
    monkeypatch.setattr(
        keyring,
        "set_password",
        lambda _service, _account, _value: writes.append("write"),
    )

    with pytest.raises(errors.KeyUnavailableError):
        keys.load_master_key(synthetic_identity())

    assert writes == []


def test_non_macos_backend_refuses_before_keyring_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    accesses: list[str] = []
    monkeypatch.setattr(keyring, "get_keyring", lambda: object())
    monkeypatch.setattr(
        keyring,
        "get_password",
        lambda _service, _account: accesses.append("read"),
    )

    with pytest.raises(errors.KeyUnavailableError, match="macOS Keychain"):
        keys.load_master_key(synthetic_identity())

    assert accesses == []


def test_keychain_backend_discovery_failure_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = importlib.import_module("memory.keys")
    errors = importlib.import_module("memory.errors")
    monkeypatch.setattr(
        keyring,
        "get_keyring",
        lambda: (_ for _ in ()).throw(KeyringError("synthetic unavailable backend")),
    )

    with pytest.raises(errors.KeyUnavailableError):
        keys.load_master_key(synthetic_identity())
