"""Authenticated publication-rollback slot records: MAC, binding, and canon.

These are the tests for `memory.staging_provenance` -- the key derivation and
MAC verification that make a rollback slot record forgery-resistant and bound
to one Store. They lived inside an 8,400-line Inbox suite, where the module
they cover had no test file of its own to notice was missing. They need no
Store and no fixture: a golden vector, a subkey, and a MAC either verify or
they do not.

Two formats are pinned. The current v2 record binds each member by name,
inode, uid, mode, and file type; the device axis is a runtime invariant (the
staging directory's own device), not a persisted number, because the kernel
reassigns `st_dev` at every boot. The legacy v1 vector is retained
deliberately: v1 records persisted `st_dev` per member, and the decoder must
keep authenticating them so live Stores can retire them on sight instead of
leaking them as unreusable budget.
"""

from __future__ import annotations

import hmac
import json

import pytest

from memory.errors import InvalidArgumentError
from memory.staging_provenance import PublicationRollbackSlotRecord

_GOLDEN_SLOT_ID = "a" * 32


_GOLDEN_STORE_ID = "0123456789abcdef0123456789abcdef"


_GOLDEN_MASTER_KEY = b"\x11" * 32


_GOLDEN_CANONICAL_RECORD = '{"format":"memory.publication-rollback-slot.v2","manifest":{"file_type":"regular","inode":202,"mode":384,"name":".recovery-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json","uid":501},"payload":{"file_type":"regular","inode":203,"mode":384,"name":".recovery-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.stage","uid":501},"slot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","store_id":"0123456789abcdef0123456789abcdef","withdrawal":{"file_type":"directory","inode":204,"mode":448,"name":".withdrawal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","uid":501}}'


_GOLDEN_SUBKEY = "677a3640b0f6a4628f0b0c0073d045dc7983163a57c147e41662c9e4fc8c520a"


_GOLDEN_MAC = "5eedd043f94bb8b3cebd3d7764b037b4334379d8a84e8af99b413db10c4f0ad7"


_LEGACY_CANONICAL_RECORD = '{"format":"memory.publication-rollback-slot.v1","manifest":{"device":101,"file_type":"regular","inode":202,"mode":384,"name":".recovery-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json","uid":501},"payload":{"device":101,"file_type":"regular","inode":203,"mode":384,"name":".recovery-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.stage","uid":501},"slot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","store_id":"0123456789abcdef0123456789abcdef","withdrawal":{"device":101,"file_type":"directory","inode":204,"mode":448,"name":".withdrawal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","uid":501}}'


_LEGACY_MAC = "6b5b9fa14ef651f873f963ada50457badeab6466f931ae8af3369d289c25b929"


def _golden_slot_record() -> PublicationRollbackSlotRecord:
    from memory.staging_provenance import StagingArtifactIdentity

    return PublicationRollbackSlotRecord(
        slot_id=_GOLDEN_SLOT_ID,
        payload=StagingArtifactIdentity(
            name=f".recovery-{_GOLDEN_SLOT_ID}.stage",
            device=None,
            inode=203,
            uid=501,
            file_type="regular",
            mode=0o600,
        ),
        manifest=StagingArtifactIdentity(
            name=f".recovery-{_GOLDEN_SLOT_ID}.json",
            device=None,
            inode=202,
            uid=501,
            file_type="regular",
            mode=0o600,
        ),
        withdrawal=StagingArtifactIdentity(
            name=f".withdrawal-{_GOLDEN_SLOT_ID}",
            device=None,
            inode=204,
            uid=501,
            file_type="directory",
            mode=0o700,
        ),
    )


def _legacy_encoded_record() -> bytes:
    """The exact v1 bytes a pre-v2 Store published, rebuilt from the pins."""
    document = json.loads(_LEGACY_CANONICAL_RECORD)
    document["mac"] = _LEGACY_MAC
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def test_publication_rollback_slot_record_matches_its_golden_vector() -> None:
    """Pin the canonical record bytes, derived subkey, and authenticated MAC."""
    from memory.staging_provenance import (
        PUBLICATION_ROLLBACK_SLOT_FORMAT,
        decode_publication_rollback_slot,
        encode_publication_rollback_slot,
    )

    record = _golden_slot_record()
    encoded = encode_publication_rollback_slot(
        record,
        store_id=_GOLDEN_STORE_ID,
        master_key=_GOLDEN_MASTER_KEY,
    )

    assert PUBLICATION_ROLLBACK_SLOT_FORMAT == "memory.publication-rollback-slot.v2"
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    assert encoded.decode("utf-8") == encoded.decode("ascii")
    document = json.loads(encoded.decode("utf-8"))
    mac = document.pop("mac")
    assert (
        json.dumps(document, sort_keys=True, separators=(",", ":"))
        == _GOLDEN_CANONICAL_RECORD
    )
    assert mac == _GOLDEN_MAC
    subkey = hmac.digest(
        _GOLDEN_MASTER_KEY,
        b"memory.publication-rollback-slot.key.v1\x00"
        + _GOLDEN_STORE_ID.encode("ascii"),
        "sha256",
    )
    assert subkey.hex() == _GOLDEN_SUBKEY
    decoded = decode_publication_rollback_slot(
        encoded,
        expected_store_id=_GOLDEN_STORE_ID,
        master_key=_GOLDEN_MASTER_KEY,
    )
    assert decoded == record
    assert decoded.format_version == 2
    assert _GOLDEN_MASTER_KEY.hex() not in repr(record)
    assert _GOLDEN_SUBKEY not in repr(record)


def test_legacy_v1_record_still_authenticates_but_is_read_only() -> None:
    """Keep decoding exact v1 bytes so live Stores can retire them on sight.

    A v1 record bound each member to a boot-assigned device number. The
    decoder must keep authenticating those records -- a Store that stops
    recognizing them would leak every pre-upgrade bundle as an untouchable
    occupant -- but the encoder must never mint another one.
    """
    from memory.staging_provenance import (
        decode_publication_rollback_slot,
        encode_publication_rollback_slot,
    )

    encoded = _legacy_encoded_record()
    record = decode_publication_rollback_slot(
        encoded,
        expected_store_id=_GOLDEN_STORE_ID,
        master_key=_GOLDEN_MASTER_KEY,
    )

    assert record.format_version == 1
    assert record.slot_id == _GOLDEN_SLOT_ID
    for member, inode in (
        (record.payload, 203),
        (record.manifest, 202),
        (record.withdrawal, 204),
    ):
        assert member.device == 101
        assert member.inode == inode
        assert member.uid == 501

    with pytest.raises(InvalidArgumentError):
        encode_publication_rollback_slot(
            record,
            store_id=_GOLDEN_STORE_ID,
            master_key=_GOLDEN_MASTER_KEY,
        )


def test_format_versions_bind_their_own_member_shape() -> None:
    """A v2 record never carries a device; a v1 record always does."""
    from memory.staging_provenance import decode_publication_rollback_slot

    v2_document = json.loads(_GOLDEN_CANONICAL_RECORD)
    for member in ("payload", "manifest", "withdrawal"):
        v2_document[member]["device"] = 101
    subkey = bytes.fromhex(_GOLDEN_SUBKEY)
    v2_with_device = json.dumps(v2_document, sort_keys=True, separators=(",", ":"))
    v2_document["mac"] = hmac.digest(subkey, v2_with_device.encode(), "sha256").hex()
    smuggled_device = (
        json.dumps(v2_document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    v1_document = json.loads(_LEGACY_CANONICAL_RECORD)
    for member in ("payload", "manifest", "withdrawal"):
        del v1_document[member]["device"]
    v1_without_device = json.dumps(v1_document, sort_keys=True, separators=(",", ":"))
    v1_document["mac"] = hmac.digest(subkey, v1_without_device.encode(), "sha256").hex()
    stripped_device = (
        json.dumps(v1_document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    for candidate in (smuggled_device, stripped_device):
        with pytest.raises(InvalidArgumentError):
            decode_publication_rollback_slot(
                candidate,
                expected_store_id=_GOLDEN_STORE_ID,
                master_key=_GOLDEN_MASTER_KEY,
            )


def test_publication_rollback_slot_rejects_tamper_wrong_store_and_wrong_key() -> None:
    """Only the exact Store key over the exact record may authenticate a slot."""
    from memory.staging_provenance import (
        decode_publication_rollback_slot,
        encode_publication_rollback_slot,
    )

    record = _golden_slot_record()
    encoded = encode_publication_rollback_slot(
        record,
        store_id=_GOLDEN_STORE_ID,
        master_key=_GOLDEN_MASTER_KEY,
    )
    document = json.loads(encoded.decode("utf-8"))

    def rendered(payload: dict[str, object]) -> bytes:
        return (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")

    tampered_inode = json.loads(encoded.decode("utf-8"))
    tampered_inode["payload"]["inode"] += 1
    tampered_store = json.loads(encoded.decode("utf-8"))
    tampered_store["store_id"] = "f" * 32
    tampered_mac = json.loads(encoded.decode("utf-8"))
    tampered_mac["mac"] = "0" * 64
    dropped_mac = json.loads(encoded.decode("utf-8"))
    del dropped_mac["mac"]

    rejected: list[tuple[bytes, str, bytes]] = [
        (encoded, "f" * 32, _GOLDEN_MASTER_KEY),
        (encoded, _GOLDEN_STORE_ID, b"\x22" * 32),
        (rendered(tampered_inode), _GOLDEN_STORE_ID, _GOLDEN_MASTER_KEY),
        (rendered(tampered_store), _GOLDEN_STORE_ID, _GOLDEN_MASTER_KEY),
        (rendered(tampered_store), "f" * 32, _GOLDEN_MASTER_KEY),
        (rendered(tampered_mac), _GOLDEN_STORE_ID, _GOLDEN_MASTER_KEY),
        (rendered(dropped_mac), _GOLDEN_STORE_ID, _GOLDEN_MASTER_KEY),
    ]
    for candidate, store_id, key in rejected:
        with pytest.raises(InvalidArgumentError) as captured:
            decode_publication_rollback_slot(
                candidate,
                expected_store_id=store_id,
                master_key=key,
            )
        assert _GOLDEN_MASTER_KEY.hex() not in str(captured.value)
        assert _GOLDEN_SUBKEY not in str(captured.value)
        assert document["mac"] not in str(captured.value)


def test_publication_rollback_slot_rejects_noncanonical_and_unbound_records() -> None:
    """Strict keys, bounds, member binding, and canonical bytes are required."""
    from memory.staging_provenance import (
        StagingArtifactIdentity,
        decode_publication_rollback_slot,
        encode_publication_rollback_slot,
    )

    record = _golden_slot_record()
    encoded = encode_publication_rollback_slot(
        record,
        store_id=_GOLDEN_STORE_ID,
        master_key=_GOLDEN_MASTER_KEY,
    )
    text = encoded.decode("utf-8")

    malformed: list[bytes] = [
        b"",
        encoded[:-1],
        encoded + b"\n",
        b" " + encoded,
        text.replace('{"format"', '{ "format"').encode("utf-8"),
        text.replace('"mode":384', '"mode":  384').encode("utf-8"),
        text.replace('"inode":203', '"inode":203.0').encode("utf-8"),
        text.replace('"uid":501', '"uid":true').encode("utf-8"),
        text.replace('"mode":448', '"mode":4096').encode("utf-8"),
        text.replace('"inode":203', '"inode":-1').encode("utf-8"),
        text.replace('"file_type":"directory"', '"file_type":"regular"').encode(
            "utf-8"
        ),
        text.replace(
            f".withdrawal-{_GOLDEN_SLOT_ID}", ".withdrawal-" + "b" * 32
        ).encode("utf-8"),
        text.replace(
            f'"slot_id":"{_GOLDEN_SLOT_ID}"', '"slot_id":"' + "b" * 32 + '"'
        ).encode("utf-8"),
        text.replace(
            '"format":"memory.publication-rollback-slot.v2"', '"format":"other"'
        ).encode("utf-8"),
        text.replace('"store_id"', '"extra":1,"store_id"').encode("utf-8"),
        text.replace('"slot_id":"' + _GOLDEN_SLOT_ID + '",', "").encode("utf-8"),
        (b"{" + b'"pad":"' + b"p" * 8192 + b'",' + encoded.strip()[1:]),
    ]
    for candidate in malformed:
        with pytest.raises(InvalidArgumentError):
            decode_publication_rollback_slot(
                candidate,
                expected_store_id=_GOLDEN_STORE_ID,
                master_key=_GOLDEN_MASTER_KEY,
            )

    unbound = _golden_slot_record()
    with pytest.raises(InvalidArgumentError):
        encode_publication_rollback_slot(
            type(unbound)(
                slot_id=_GOLDEN_SLOT_ID,
                payload=StagingArtifactIdentity(
                    name=f".recovery-{'b' * 32}.stage",
                    device=None,
                    inode=203,
                    uid=501,
                    file_type="regular",
                    mode=0o600,
                ),
                manifest=unbound.manifest,
                withdrawal=unbound.withdrawal,
            ),
            store_id=_GOLDEN_STORE_ID,
            master_key=_GOLDEN_MASTER_KEY,
        )
    with pytest.raises(InvalidArgumentError):
        encode_publication_rollback_slot(
            record,
            store_id="not-hex",
            master_key=_GOLDEN_MASTER_KEY,
        )
    with pytest.raises(InvalidArgumentError):
        encode_publication_rollback_slot(
            record,
            store_id=_GOLDEN_STORE_ID,
            master_key=b"\x11" * 16,
        )
