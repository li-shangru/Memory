"""Authenticated provenance records for reusable publication rollback slots.

This module is internal and pure: it opens no filesystem path, database, or
Keychain item. It converts content-free runtime identities to and from one
canonical authenticated record so that private-staging custody can prove that
a reusable rollback artifact was created by this Store rather than merely
having an expected-looking name and shape.

The current v2 record binds each member by name, inode, uid, mode, and file
type. It deliberately persists no device number: the kernel reassigns
`st_dev` at every boot, so a persisted device invalidated every stored slot
on reboot and permanently burned the bounded publication budget. The device
axis is instead enforced at verification time as a runtime invariant -- every
member must live on the staging directory's current device -- which preserves
the cross-volume-substitution defense without the reboot fragility. Legacy v1
records, which do carry the device, still authenticate here so custody code
can retire them on sight; the encoder refuses to mint new ones. Both formats
authenticate under the same derived subkey, and the `format` field inside the
MAC'd canonical document keeps their MAC domains separate.
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass
from typing import Literal

from memory.errors import InvalidArgumentError
from memory.model import SecretBytes

PUBLICATION_ROLLBACK_SLOT_FORMAT = "memory.publication-rollback-slot.v2"
PUBLICATION_ROLLBACK_SLOT_FORMAT_LEGACY = "memory.publication-rollback-slot.v1"
PUBLICATION_ROLLBACK_SLOT_KEY_CONTEXT = b"memory.publication-rollback-slot.key.v1\0"
MASTER_KEY_BYTES = 32
MAX_PUBLICATION_ROLLBACK_SLOT_BYTES = 4096

_STORE_ID = re.compile(r"[0-9a-f]{32}")
_SLOT_ID = re.compile(r"[0-9a-f]{32}")
_MAC = re.compile(r"[0-9a-f]{64}")
_MAX_IDENTITY_VALUE = 2**63 - 1
_MEMBER_KEYS = frozenset({"file_type", "inode", "mode", "name", "uid"})
_MEMBER_KEYS_LEGACY = frozenset({"device", "file_type", "inode", "mode", "name", "uid"})
_RECORD_KEYS = frozenset(
    {"format", "mac", "manifest", "payload", "slot_id", "store_id", "withdrawal"}
)
_FILE_TYPES = frozenset({"regular", "directory"})


@dataclass(frozen=True, slots=True)
class StagingArtifactIdentity:
    """One content-free private-staging member bound by its runtime identity.

    `device` is None on every current (v2) member: the device axis is checked
    against the staging directory at runtime, never persisted. An integer
    device appears only on members decoded from a legacy v1 record.
    """

    name: str
    device: int | None
    inode: int
    uid: int
    file_type: Literal["regular", "directory"]
    mode: int


@dataclass(frozen=True, slots=True)
class PublicationRollbackSlotRecord:
    """The three reusable members of one ordinary publication rollback slot."""

    slot_id: str
    payload: StagingArtifactIdentity
    manifest: StagingArtifactIdentity
    withdrawal: StagingArtifactIdentity
    format_version: Literal[1, 2] = 2


def publication_rollback_slot_member_names(slot_id: str) -> tuple[str, str, str]:
    """Return the exact payload, marker, and withdrawal names for one slot."""
    _require_slot_id(slot_id)
    return (
        f".recovery-{slot_id}.stage",
        f".recovery-{slot_id}.json",
        f".withdrawal-{slot_id}",
    )


def encode_publication_rollback_slot(
    record: PublicationRollbackSlotRecord,
    *,
    store_id: str,
    master_key: SecretBytes,
) -> bytes:
    """Render one canonical authenticated slot record with a terminal newline."""
    if record.format_version != 2:
        raise InvalidArgumentError(
            "legacy publication rollback slot records are read-only"
        )
    document = _canonical_document(record, store_id=store_id)
    slot_key = _derive_slot_key(store_id=store_id, master_key=master_key)
    document["mac"] = hmac.digest(slot_key, _canonical_bytes(document), "sha256").hex()
    return _canonical_bytes(document) + b"\n"


def decode_publication_rollback_slot(
    encoded: bytes,
    *,
    expected_store_id: str,
    master_key: SecretBytes,
) -> PublicationRollbackSlotRecord:
    """Authenticate and strictly parse one canonical slot provenance record."""
    slot_key = _derive_slot_key(store_id=expected_store_id, master_key=master_key)
    if (
        not isinstance(encoded, bytes | bytearray)
        or not encoded
        or len(encoded) > MAX_PUBLICATION_ROLLBACK_SLOT_BYTES
        or not encoded.endswith(b"\n")
        or encoded.count(b"\n") != 1
    ):
        raise InvalidArgumentError("publication rollback slot record is unsafe")
    try:
        raw = json.loads(bytes(encoded[:-1]).decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError) as error:
        raise InvalidArgumentError(
            "publication rollback slot record is invalid"
        ) from error
    if not isinstance(raw, dict) or set(raw) != _RECORD_KEYS:
        raise InvalidArgumentError("publication rollback slot record is invalid")
    mac = raw.pop("mac")
    if not isinstance(mac, str) or _MAC.fullmatch(mac) is None:
        raise InvalidArgumentError("publication rollback slot record is invalid")
    format_version: Literal[1, 2]
    if raw["format"] == PUBLICATION_ROLLBACK_SLOT_FORMAT:
        format_version = 2
    elif raw["format"] == PUBLICATION_ROLLBACK_SLOT_FORMAT_LEGACY:
        format_version = 1
    else:
        raise InvalidArgumentError("publication rollback slot record is invalid")
    if raw["store_id"] != expected_store_id:
        raise InvalidArgumentError("publication rollback slot record is foreign")
    slot_id = raw["slot_id"]
    _require_slot_id(slot_id)
    record = PublicationRollbackSlotRecord(
        slot_id=slot_id,
        payload=_decode_member(raw["payload"], format_version=format_version),
        manifest=_decode_member(raw["manifest"], format_version=format_version),
        withdrawal=_decode_member(raw["withdrawal"], format_version=format_version),
        format_version=format_version,
    )
    document = _canonical_document(record, store_id=expected_store_id)
    if not hmac.compare_digest(
        hmac.digest(slot_key, _canonical_bytes(document), "sha256").hex(),
        mac,
    ):
        raise InvalidArgumentError(
            "publication rollback slot record is unauthenticated"
        )
    document["mac"] = mac
    if _canonical_bytes(document) + b"\n" != bytes(encoded):
        raise InvalidArgumentError("publication rollback slot record is noncanonical")
    return record


def _canonical_document(
    record: PublicationRollbackSlotRecord,
    *,
    store_id: str,
) -> dict[str, object]:
    if _STORE_ID.fullmatch(store_id) is None:
        raise InvalidArgumentError("Store identity is invalid")
    _require_slot_id(record.slot_id)
    payload_name, manifest_name, withdrawal_name = (
        publication_rollback_slot_member_names(record.slot_id)
    )
    members = (
        (record.payload, payload_name, "regular"),
        (record.manifest, manifest_name, "regular"),
        (record.withdrawal, withdrawal_name, "directory"),
    )
    for member, expected_name, expected_type in members:
        if (
            not isinstance(member, StagingArtifactIdentity)
            or member.name != expected_name
            or member.file_type != expected_type
        ):
            raise InvalidArgumentError("publication rollback slot member is unbound")
        if record.format_version == 2:
            if member.device is not None:
                raise InvalidArgumentError(
                    "publication rollback slot member is unbound"
                )
        elif (
            not isinstance(member.device, int)
            or isinstance(member.device, bool)
            or not 0 <= member.device <= _MAX_IDENTITY_VALUE
        ):
            raise InvalidArgumentError("publication rollback slot member is unbound")
        for value in (member.inode, member.uid, member.mode):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= _MAX_IDENTITY_VALUE
            ):
                raise InvalidArgumentError(
                    "publication rollback slot member is unbound"
                )
        if member.mode > 0o7777:
            raise InvalidArgumentError("publication rollback slot member is unbound")
    format_name = (
        PUBLICATION_ROLLBACK_SLOT_FORMAT
        if record.format_version == 2
        else PUBLICATION_ROLLBACK_SLOT_FORMAT_LEGACY
    )
    return {
        "format": format_name,
        "manifest": _encode_member(record.manifest),
        "payload": _encode_member(record.payload),
        "slot_id": record.slot_id,
        "store_id": store_id,
        "withdrawal": _encode_member(record.withdrawal),
    }


def _encode_member(member: StagingArtifactIdentity) -> dict[str, object]:
    encoded: dict[str, object] = {
        "file_type": member.file_type,
        "inode": member.inode,
        "mode": member.mode,
        "name": member.name,
        "uid": member.uid,
    }
    if member.device is not None:
        encoded["device"] = member.device
    return encoded


def _decode_member(
    raw: object,
    *,
    format_version: Literal[1, 2],
) -> StagingArtifactIdentity:
    expected_keys = _MEMBER_KEYS if format_version == 2 else _MEMBER_KEYS_LEGACY
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise InvalidArgumentError("publication rollback slot member is invalid")
    name = raw["name"]
    file_type = raw["file_type"]
    if (
        not isinstance(name, str)
        or not isinstance(file_type, str)
        or file_type not in _FILE_TYPES
    ):
        raise InvalidArgumentError("publication rollback slot member is invalid")
    values: list[int] = []
    keys = (
        ("inode", "uid", "mode")
        if format_version == 2
        else (
            "device",
            "inode",
            "uid",
            "mode",
        )
    )
    for key in keys:
        value = raw[key]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= _MAX_IDENTITY_VALUE
        ):
            raise InvalidArgumentError("publication rollback slot member is invalid")
        values.append(value)
    if format_version == 2:
        device = None
        inode, uid, mode = values
    else:
        device, inode, uid, mode = values
    if mode > 0o7777:
        raise InvalidArgumentError("publication rollback slot member is invalid")
    return StagingArtifactIdentity(
        name=name,
        device=device,
        inode=inode,
        uid=uid,
        file_type="regular" if file_type == "regular" else "directory",
        mode=mode,
    )


def _canonical_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_slot_key(*, store_id: str, master_key: SecretBytes) -> bytes:
    if _STORE_ID.fullmatch(store_id) is None:
        raise InvalidArgumentError("Store identity is invalid")
    if not isinstance(master_key, bytes | bytearray) or len(master_key) != (
        MASTER_KEY_BYTES
    ):
        raise InvalidArgumentError("Store key material is unavailable")
    return hmac.digest(
        bytes(master_key),
        PUBLICATION_ROLLBACK_SLOT_KEY_CONTEXT + store_id.encode("ascii"),
        "sha256",
    )


def _require_slot_id(slot_id: object) -> None:
    if not isinstance(slot_id, str) or _SLOT_ID.fullmatch(slot_id) is None:
        raise InvalidArgumentError("publication rollback slot identity is invalid")
