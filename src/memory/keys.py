"""macOS Keychain boundary for the Store master key."""

from __future__ import annotations

import base64
import binascii
import importlib
import re
import secrets
from typing import Protocol, cast

import keyring
from keyring.errors import KeyringError

from memory.errors import (
    KeyAlreadyExistsError,
    KeyMismatchError,
    KeyMissingError,
    KeyUnavailableError,
)
from memory.model import SecretBytes, StoreIdentity

KEYCHAIN_SERVICE = "memory"
MACOS_KEYRING_BACKEND = "keyring.backends.macOS.Keyring"
MASTER_KEY_BYTES = 32
_SEC_DUPLICATE_ITEM = -25299
_STORE_ID = re.compile(r"[0-9a-f]{32}")


class _MacOSKeychainAPI(Protocol):
    def k_(self, name: str) -> object: ...

    def create_query(self, **attributes: object) -> object: ...

    def SecItemAdd(self, query: object, result: None) -> int: ...


def create_master_key(
    identity: StoreIdentity, *, material: SecretBytes | None = None
) -> SecretBytes:
    """Create, store, and verify one new Store key without replacing a key."""
    _validate_store_id(identity.store_id)
    if material is not None and len(material) != MASTER_KEY_BYTES:
        raise ValueError("Store key must be exactly 32 bytes")
    _require_macos_keychain()
    try:
        existing = keyring.get_password(KEYCHAIN_SERVICE, identity.store_id)
        if existing is not None:
            raise KeyAlreadyExistsError(
                "a Keychain item already exists for this Store identity"
            )
        master_key = (
            material if material is not None else secrets.token_bytes(MASTER_KEY_BYTES)
        )
        encoded = base64.b64encode(master_key).decode("ascii")
        _store_master_key_exclusive(identity, encoded)
        stored = keyring.get_password(KEYCHAIN_SERVICE, identity.store_id)
    except KeyAlreadyExistsError:
        raise
    except KeyringError as error:
        raise KeyUnavailableError("macOS Keychain is unavailable") from error
    if stored != encoded:
        raise KeyUnavailableError("macOS Keychain did not retain the Store key")
    return master_key


def _store_master_key_exclusive(identity: StoreIdentity, encoded: str) -> None:
    """Atomically add the item; the ordinary keyring setter deletes first."""
    try:
        api = cast(
            _MacOSKeychainAPI, importlib.import_module("keyring.backends.macOS.api")
        )
    except (ImportError, OSError) as error:
        raise KeyUnavailableError("macOS Keychain is unavailable") from error
    # Preserve keyring's item attributes and default accessibility, but use only
    # SecItemAdd: a prior absence read cannot authorize deleting a later winner.
    query = api.create_query(
        kSecClass=api.k_("kSecClassGenericPassword"),
        kSecAttrService=KEYCHAIN_SERVICE,
        kSecAttrAccount=identity.store_id,
        kSecValueData=encoded,
    )
    status = api.SecItemAdd(query, None)
    if status == _SEC_DUPLICATE_ITEM:
        raise KeyAlreadyExistsError(
            "a Keychain item already exists for this Store identity"
        )
    if status != 0:
        raise KeyUnavailableError("macOS Keychain did not store the Store key")


def load_master_key(identity: StoreIdentity) -> SecretBytes:
    """Load an existing key; missing or malformed state always fails closed."""
    _validate_store_id(identity.store_id)
    _require_macos_keychain()
    try:
        encoded = keyring.get_password(KEYCHAIN_SERVICE, identity.store_id)
    except KeyringError as error:
        raise KeyUnavailableError("macOS Keychain is unavailable") from error
    if encoded is None:
        raise KeyMissingError("Store master key is missing from macOS Keychain")
    try:
        master_key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise KeyMismatchError("Store Keychain item is malformed") from error
    if len(master_key) != MASTER_KEY_BYTES:
        raise KeyMismatchError("Store Keychain item has the wrong key length")
    return master_key


def _validate_store_id(store_id: str) -> None:
    if _STORE_ID.fullmatch(store_id) is None:
        raise KeyMismatchError("Store identity has an invalid Keychain account")


def _require_macos_keychain() -> None:
    try:
        backend_type = type(keyring.get_keyring())
    except KeyringError as error:
        raise KeyUnavailableError("macOS Keychain is unavailable") from error
    backend_name = f"{backend_type.__module__}.{backend_type.__qualname__}"
    if backend_name != MACOS_KEYRING_BACKEND:
        raise KeyUnavailableError("macOS Keychain backend is required")
