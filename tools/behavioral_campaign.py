"""One durable launch authority for fixed, interrupted behavioral cohorts.

This developer helper stores metadata, not credentials or Store contents. It
never opens an archived path, initializes a Store, approves a review, authenticates
or launches a client. The caller performs those operations against explicit fresh
paths and records their results through the bounded transitions below.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import behavioral_continuation as continuation

Cohort = Literal["base", "discovery"]
COHORTS: tuple[Cohort, ...] = ("base", "discovery")
SCHEMA = "memory.behavioral-campaign.v1"
REGISTRAR_SCHEMA = "memory.behavioral-campaign-registrar.v1"
ANCHOR_SCHEMA = "memory.behavioral-campaign-authority.v1"
PUBLICATION_SCHEMA = "memory.behavioral-campaign-publication.v1"
_ANCHOR = "authority.private.json"
_ORPHAN_INDEX = re.compile(r"\.index-[0-9a-f]{32}\.tmp")
_PUBLICATION = re.compile(r"publication-([0-9]{8})-([0-9a-f]{64})\.private\.json")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[0-9a-f]{32}")
_INFRASTRUCTURE = frozenset(
    ("isolation_profile_digest", "authentication_adapter_digest")
)
_PREREQUISITES = frozenset(
    (
        "cleanup_digest",
        "capability_digest",
        "memory_transport_digest",
        "source_binding_digest",
    )
)
_PATHS = frozenset(
    (
        "memory_executable",
        "client_executable",
        "build_artifact",
        "base_manifest",
        "discovery_manifest",
    )
)
_EXECUTION = continuation._EXECUTION_FIELDS
_FIXTURE = frozenset(("fixture_preparation", "fixture_store_id", "fixture_phases"))
_PHASES = frozenset(("allocated", "preparing", "ready", "active", "interrupted"))
_PREPARATION = frozenset(
    (
        "pending",
        "fixture_preparation_interrupted",
        "owner_presence_prerequisite",
        "ready",
        "fixture_preparation_failed",
    )
)


class CampaignError(Exception):
    """A content-free refusal of an unsupported campaign transition."""


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CampaignError("campaign structure is invalid")
    return cast(dict[str, object], value)


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise CampaignError("campaign structure is invalid")
    return cast(list[object], value)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CampaignError("campaign identity is invalid")
    return value


def _digest(value: object) -> str:
    result = _text(value)
    if _DIGEST.fullmatch(result) is None:
        raise CampaignError("campaign digest is invalid")
    return result


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
            + "\n"
        ).encode()
    except TypeError, ValueError, UnicodeError:
        raise CampaignError("campaign structure is invalid") from None


def _decode(raw: bytes) -> dict[str, object]:
    try:
        return continuation._decode(raw)
    except continuation.ContinuationError:
        raise CampaignError("campaign archive is invalid") from None


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(value: object) -> Path:
    try:
        return continuation._absolute(value)
    except continuation.ContinuationError:
        raise CampaignError("campaign path is invalid") from None


def _rows(state: Mapping[str, object]) -> list[dict[str, object]]:
    return [_object(row) for row in _list(state.get("slots"))]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _registrar_root() -> Path:
    """The authority location cannot be redirected by environment or CLI input."""
    account = pwd.getpwuid(os.getuid())
    return (
        _path(account.pw_dir)
        / "Library/Application Support/Memory Behavioral Acceptance/registrar"
    )


def _directory(path: Path, *, private: bool = True) -> int:
    """Open every path component without following a symlink."""
    _path(str(path))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if private and (
            metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise CampaignError("campaign directory is not private")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_directory(path: Path) -> bool:
    parent = _directory(path.parent, private=False)
    created = False
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
            created = True
            os.fsync(parent)
        except FileExistsError:
            pass
    finally:
        os.close(parent)
    descriptor = _directory(path)
    os.close(descriptor)
    return created


def _volume(descriptor: int) -> str:
    # Reuse the maintained macOS UUID implementation; do not create bytecode in
    # the manifest-checked companion source when imported by this developer CLI.
    source = str(Path(__file__).parent / "staged-memory-intake/scripts")
    if source not in sys.path:
        sys.path.insert(0, source)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        from staged_memory_intake.model import IntakeError
        from staged_memory_intake.securefs import descriptor_volume

        try:
            return descriptor_volume(descriptor)
        except IntakeError:
            raise CampaignError("campaign volume identity is unavailable") from None
    finally:
        sys.dont_write_bytecode = previous


def _identity(path: Path) -> dict[str, object]:
    descriptor = _directory(path)
    try:
        return _descriptor_identity(path, descriptor)
    finally:
        os.close(descriptor)


def _descriptor_identity(path: Path, descriptor: int) -> dict[str, object]:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise CampaignError("campaign directory identity is invalid")
    return {
        "path": str(path),
        "uid": metadata.st_uid,
        "inode": metadata.st_ino,
        "volume": _volume(descriptor),
    }


def _fsync(path: Path) -> None:
    descriptor = _directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read(path: Path, *, mode: int) -> bytes:
    parent = _directory(path.parent)
    try:
        return _read_at(parent, path.name, mode=mode)
    finally:
        os.close(parent)


def _read_at(parent: int, name: str, *, mode: int, synchronize: bool = False) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= continuation.MAX_STATE_BYTES
        ):
            raise CampaignError("campaign private metadata is invalid")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(continuation.MAX_STATE_BYTES + 1)
            if synchronize:
                os.fsync(stream.fileno())
            after = os.fstat(stream.fileno())
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or before[:7] != after[:7]
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise CampaignError("campaign private metadata changed while reading")
        return raw
    except OSError:
        raise CampaignError(
            "campaign private metadata is unavailable or changed"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _immutable(directory: Path, raw: bytes) -> str:
    digest = _hash(raw)
    target = directory / (digest + ".private.json")
    parent = _directory(directory)
    try:
        try:
            descriptor = os.open(
                target.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
                dir_fd=parent,
            )
        except FileExistsError:
            if _read_at(parent, target.name, mode=0o400, synchronize=True) != raw:
                raise CampaignError("campaign immutable metadata changed") from None
            os.fsync(parent)
            return digest
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
        return digest
    finally:
        os.close(parent)


@dataclass
class _Authority:
    path: Path
    namespace_descriptor: int
    directory_descriptor: int
    lock_descriptor: int
    publication_descriptor: int
    anchor: Mapping[str, object]
    anchor_bytes: bytes
    index_digest: str | None = None
    publication_sequence: int = 0
    publication_digest: str | None = None
    publication_guard: Callable[[], None] | None = None
    custody_stack: ExitStack = dataclass_field(default_factory=ExitStack)
    closed: bool = False


def _lock_identity(descriptor: int) -> dict[str, object]:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size
    ):
        raise CampaignError("campaign registrar lock is invalid")
    return {"uid": info.st_uid, "inode": info.st_ino, "volume": _volume(descriptor)}


def _assert_authority(authority: _Authority) -> None:
    """Bind both held descriptors and their current names to one immutable anchor."""
    if authority.closed:
        raise CampaignError("campaign authority is closed")
    root = authority.path
    anchor = authority.anchor
    if set(os.listdir(authority.namespace_descriptor)) != {root.name, _ANCHOR}:
        raise CampaignError("campaign authority namespace contains unexpected material")
    if (
        set(anchor) != {"schema", "namespace", "registrar", "lock", "publications"}
        or anchor.get("schema") != ANCHOR_SCHEMA
        or _descriptor_identity(root.parent, authority.namespace_descriptor)
        != anchor["namespace"]
        or _descriptor_identity(root, authority.directory_descriptor)
        != anchor["registrar"]
        or _identity(root.parent) != anchor["namespace"]
        or _identity(root) != anchor["registrar"]
        or _lock_identity(authority.lock_descriptor) != anchor["lock"]
        or _descriptor_identity(root / "publications", authority.publication_descriptor)
        != anchor["publications"]
        or _identity(root / "publications") != anchor["publications"]
        or _read_at(authority.namespace_descriptor, _ANCHOR, mode=0o400)
        != authority.anchor_bytes
    ):
        raise CampaignError("campaign authority identity changed")
    named = os.stat(
        ".lock", dir_fd=authority.directory_descriptor, follow_symlinks=False
    )
    held = os.fstat(authority.lock_descriptor)
    if (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_nlink) != (
        held.st_dev,
        held.st_ino,
        held.st_mode,
        held.st_uid,
        held.st_nlink,
    ):
        raise CampaignError("campaign registrar lock was replaced")


def _publication_state(
    authority: _Authority, *, synchronize: bool = False
) -> tuple[str | None, int, str | None]:
    """Validate every publication witness without deriving an alternate index."""
    parent = authority.publication_descriptor
    previous_index: str | None = None
    previous_record: str | None = None
    sequence = 0
    last_name: str | None = None
    last_raw: bytes | None = None
    for name in sorted(os.listdir(parent)):
        match = _PUBLICATION.fullmatch(name)
        if match is None or int(match.group(1)) != sequence + 1:
            raise CampaignError("campaign publication history is not contiguous")
        raw = _read_at(parent, name, mode=0o400)
        digest = _hash(raw)
        record = _decode(raw)
        if (
            digest != match.group(2)
            or set(record)
            != {
                "schema",
                "sequence",
                "previous_record_digest",
                "previous_index_digest",
                "index_digest",
            }
            or record.get("schema") != PUBLICATION_SCHEMA
            or type(record.get("sequence")) is not int
            or record["sequence"] != sequence + 1
            or record["previous_record_digest"] != previous_record
            or record["previous_index_digest"] != previous_index
        ):
            raise CampaignError("campaign publication history changed")
        previous_index = _digest(record["index_digest"])
        previous_record = digest
        sequence += 1
        last_name, last_raw = name, raw
    if synchronize and last_name is not None:
        if _read_at(parent, last_name, mode=0o400, synchronize=True) != last_raw:
            raise CampaignError("campaign publication changed during synchronization")
        os.fsync(parent)
    return previous_index, sequence, previous_record


def _check_index(authority: _Authority) -> None:
    if _publication_state(authority) != (
        authority.index_digest,
        authority.publication_sequence,
        authority.publication_digest,
    ):
        raise CampaignError("campaign publication head changed while locked")
    if authority.index_digest is None:
        try:
            os.stat(
                "index.private.json",
                dir_fd=authority.directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        raise CampaignError("campaign initial authority was already published")
    raw = _read_at(authority.directory_descriptor, "index.private.json", mode=0o600)
    if _hash(raw) != authority.index_digest:
        raise CampaignError("campaign registrar does not match its publication fence")


def _append_publication(authority: _Authority, index_digest: str) -> None:
    sequence = authority.publication_sequence + 1
    if sequence > 99_999_999:
        raise CampaignError("campaign publication sequence is exhausted")
    raw = _canonical(
        {
            "schema": PUBLICATION_SCHEMA,
            "sequence": sequence,
            "previous_record_digest": authority.publication_digest,
            "previous_index_digest": authority.index_digest,
            "index_digest": index_digest,
        }
    )
    digest = _hash(raw)
    name = f"publication-{sequence:08d}-{digest}.private.json"
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
        dir_fd=authority.publication_descriptor,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(authority.publication_descriptor)
    authority.index_digest = index_digest
    authority.publication_sequence = sequence
    authority.publication_digest = digest


def _publish_index(authority: _Authority, index: Mapping[str, object]) -> None:
    _assert_authority(authority)
    _check_index(authority)
    if authority.publication_guard is not None:
        authority.publication_guard()
    temporary = ".index-" + secrets.token_hex(16) + ".tmp"
    parent = authority.directory_descriptor
    raw = _canonical(index)
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _assert_authority(authority)
        _check_index(authority)
        if authority.publication_guard is not None:
            authority.publication_guard()
        os.replace(
            temporary, "index.private.json", src_dir_fd=parent, dst_dir_fd=parent
        )
        os.fsync(parent)
        _append_publication(authority, _hash(raw))
        _assert_authority(authority)
        _check_index(authority)
        if authority.publication_guard is not None:
            authority.publication_guard()
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def _write_anchor(namespace: int, raw: bytes) -> None:
    descriptor = os.open(
        _ANCHOR,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
        dir_fd=namespace,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(namespace)


def _validate_registrar_entries(authority: _Authority) -> None:
    parent = authority.directory_descriptor
    for name in os.listdir(parent):
        if name in {".lock", "index.private.json", "publications"}:
            continue
        # A killed publisher may leave a private partial temporary file. It is
        # inert evidence, never an alternate head, and is retained for diagnosis.
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _ORPHAN_INDEX.fullmatch(name) is None
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > continuation.MAX_STATE_BYTES
        ):
            raise CampaignError("campaign registrar contains unexpected material")


@contextmanager
def _registrar(
    *, create: bool = False
) -> Iterator[tuple[_Authority, dict[str, object]]]:
    root = _registrar_root()
    namespace: int | None = None
    directory: int | None = None
    lock: int | None = None
    publications: int | None = None
    authority: _Authority | None = None
    try:
        new_namespace = _ensure_directory(root.parent) if create else False
        namespace = _directory(root.parent)
        if new_namespace:
            os.mkdir(root.name, mode=0o700, dir_fd=namespace)
            os.fsync(namespace)
        else:
            # Never infer first use from missing index/lock files. An existing
            # namespace must carry the anchor of its original initialized root.
            _read_at(namespace, _ANCHOR, mode=0o400)
        directory = _directory(root)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if new_namespace:
            flags |= os.O_CREAT | os.O_EXCL
        lock = os.open(".lock", flags, 0o600, dir_fd=directory)
        _lock_identity(lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if new_namespace:
            os.mkdir("publications", mode=0o700, dir_fd=directory)
        publications = os.open(
            "publications",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=directory,
        )
        if new_namespace:
            os.fsync(lock)
            os.fsync(directory)
            anchor: dict[str, object] = {
                "schema": ANCHOR_SCHEMA,
                "namespace": _descriptor_identity(root.parent, namespace),
                "registrar": _descriptor_identity(root, directory),
                "lock": _lock_identity(lock),
                "publications": _descriptor_identity(
                    root / "publications", publications
                ),
            }
            anchor_raw = _canonical(anchor)
            _write_anchor(namespace, anchor_raw)
        else:
            anchor_raw = _read_at(namespace, _ANCHOR, mode=0o400)
            anchor = _decode(anchor_raw)
        authority = _Authority(
            root, namespace, directory, lock, publications, anchor, anchor_raw
        )
        _assert_authority(authority)
        _validate_registrar_entries(authority)
        if new_namespace:
            index: dict[str, object] = {
                "schema": REGISTRAR_SCHEMA,
                "cohorts": {},
                "campaigns": {},
            }
            _publish_index(authority, index)
        else:
            (
                authority.index_digest,
                authority.publication_sequence,
                authority.publication_digest,
            ) = _publication_state(authority, synchronize=True)
            if authority.index_digest is None:
                raise CampaignError(
                    "campaign initialized publication fence is unavailable"
                )
            raw = _read_at(
                directory, "index.private.json", mode=0o600, synchronize=True
            )
            os.fsync(directory)
            if _hash(raw) != authority.index_digest:
                raise CampaignError(
                    "campaign registrar does not match its publication fence"
                )
            index = _decode(raw)
        if (
            set(index) != {"schema", "cohorts", "campaigns"}
            or index.get("schema") != REGISTRAR_SCHEMA
        ):
            raise CampaignError("campaign registrar structure is invalid")
        _object(index["cohorts"])
        _object(index["campaigns"])
        yield authority, index
        _assert_authority(authority)
        _check_index(authority)
        if authority.publication_guard is not None:
            authority.publication_guard()
    except OSError:
        raise CampaignError("campaign authority is unavailable or locked") from None
    finally:
        if authority is not None:
            authority.closed = True
        try:
            if authority is not None:
                authority.custody_stack.close()
        finally:
            for descriptor in (lock, publications, directory, namespace):
                if descriptor is not None:
                    os.close(descriptor)


@dataclass(frozen=True)
class Campaign:
    root: Path
    digest: str
    document: Mapping[str, object]

    @property
    def generation_id(self) -> str:
        return _text(_generation(self.document)["generation_id"])


@dataclass(frozen=True)
class FixturePaths:
    trial: Path
    store: Path
    response: Path
    stderr: Path


def _generation(document: Mapping[str, object]) -> dict[str, object]:
    generations = _list(document.get("generations"))
    if not generations:
        raise CampaignError("campaign generation is unavailable")
    return _object(generations[-1])


def _cohorts(document: Mapping[str, object]) -> dict[str, object]:
    cohorts = _object(document.get("cohorts"))
    if set(cohorts) != set(COHORTS):
        raise CampaignError("campaign requires both cohorts")
    return cohorts


def _key(cohort: Cohort, slot_id: str) -> str:
    return cohort + ":" + slot_id


def _groups(manifest: Mapping[str, object], case_id: object) -> list[list[str]]:
    cases = [_object(case) for case in _list(manifest.get("cases"))]
    case = next((case for case in cases if case.get("case_id") == case_id), None)
    if case is None:
        raise CampaignError("campaign manifest roster changed")
    memories = [
        _object(value) for value in _list(_object(case["seed_profile"])["memories"])
    ]
    groups = [
        [
            _text(memory["fixture_id"])
            for memory in memories
            if (memory.get("revision_role") == "approved_correction") == correction
        ]
        for correction in (False, True)
    ]
    return [group for group in groups if group]


def _validate_manifest(
    state: Mapping[str, object], raw: bytes, cohort: Cohort
) -> dict[str, object]:
    manifest = _decode(raw)
    provenance = _object(state.get("provenance"))
    cases = [_object(case) for case in _list(manifest.get("cases"))]
    rubric = {
        "rubric_version": manifest.get("rubric_version"),
        "cases": [
            {"case_id": case.get("case_id"), "rubric": case.get("rubric")}
            for case in cases
        ],
    }
    rubric_digest = _hash(
        json.dumps(
            rubric, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    )
    expected_schema = (
        "memory.synthetic-behavioral-acceptance.v1"
        if cohort == "base"
        else "memory.synthetic-behavioral-discovery.v1"
    )
    if (
        provenance.get("manifest_digest") != _hash(raw)
        or provenance.get("manifest_schema") != expected_schema
        or manifest.get("schema") != expected_schema
        or provenance.get("rubric_digest") != rubric_digest
        or provenance.get("rubric_version") != manifest.get("rubric_version")
        or state.get("requested_trial_count") != 3
        or len(cases) != (6 if cohort == "base" else 2)
    ):
        raise CampaignError("campaign manifest or rubric binding changed")
    expected = [(case, trial) for case in cases for trial in (1, 2, 3)]
    slots = _rows(state)
    if len(slots) != len(expected):
        raise CampaignError("campaign fixed denominator changed")
    for slot, (case, trial) in zip(slots, expected, strict=True):
        if (
            any(
                slot.get(field) != case.get(field) for field in ("case_id", "condition")
            )
            or slot.get("trial") != trial
            or slot.get("slot_id") != f"{case['case_id']}:{trial}"
        ):
            raise CampaignError("campaign logical roster changed")
    return manifest


def _imported(
    heads: Mapping[Cohort, str],
    archive: Mapping[str, bytes],
    manifests: Mapping[Cohort, bytes],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if set(heads) != set(COHORTS) or set(manifests) != set(COHORTS):
        raise CampaignError("campaign requires both cohorts")
    for digest, raw in archive.items():
        if _hash(raw) != _digest(digest):
            raise CampaignError("campaign archive digest changed")
    origins: dict[str, object] = {}
    cohorts: dict[str, object] = {}
    parsed_manifests: dict[str, object] = {}
    used: set[str] = set()
    for cohort in COHORTS:
        head = _digest(heads[cohort])
        if head not in archive:
            raise CampaignError("campaign archive head is unavailable")
        state = _decode(archive[head])
        try:
            old = continuation.validate_archived_state(state, archive)
            original = state if old is None else old.predecessor
            continuation.pending_slot_ids(original)
        except continuation.ContinuationError:
            raise CampaignError(
                "campaign predecessor or original binding changed"
            ) from None
        chain = [head] if old is None else [head, old.snapshot_digest]
        used.update(chain)
        slots = _rows(state)
        expected_failed = 2 if cohort == "base" else 0
        failed = [slot for slot in slots if not continuation._pending(slot)]
        if len(failed) != expected_failed or any(
            slot.get("execution_outcome") != "failed"
            or slot.get("outcome_label") != "client_transport_failed"
            or slot.get("completed") is not False
            or slot.get("grade_outcome") != "ungraded"
            or slot.get("outcomes") != {}
            or slot.get("client_launch_attempted") is not True
            or slot.get("inference_started") is not None
            or slot.get("mutation_outcome") != "unchanged"
            for slot in failed
        ):
            raise CampaignError("campaign history is not the fixed interrupted cohort")
        private = _object(original.get("private"))
        identity = _hash(
            _canonical(
                {
                    "cohort": cohort,
                    "fixture_run_id": _text(private.get("fixture_run_id")),
                }
            )
        )
        origins[cohort] = {
            "head_digest": head,
            "root_digest": chain[-1],
            "chain": chain,
            "cohort_identity": identity,
            "manifest_digest": _hash(manifests[cohort]),
        }
        cohorts[cohort] = state
        parsed_manifests[cohort] = _validate_manifest(state, manifests[cohort], cohort)
    if used != set(archive):
        raise CampaignError("campaign archive contains unrelated material")
    return origins, cohorts, parsed_manifests


def _historical_consumed(cohorts: Mapping[str, object]) -> dict[str, object]:
    return {
        _key(cohort, _text(slot["slot_id"])): {"generation_id": "historical"}
        for cohort in COHORTS
        for slot in _rows(_object(cohorts[cohort]))
        if not continuation._pending(slot)
    }


def _new_generation(document: Mapping[str, object]) -> dict[str, object]:
    consumed = _object(document["consumed"])
    members = {
        cohort: [
            _text(slot["slot_id"])
            for slot in _rows(_object(_cohorts(document)[cohort]))
            if _key(cohort, _text(slot["slot_id"])) not in consumed
        ]
        for cohort in COHORTS
    }
    if not any(members.values()):
        raise CampaignError("campaign has no untouched logical slots")
    fixtures: dict[str, object] = {
        cohort: {
            slot_id: {
                "fixture_preparation": "pending",
                "fixture_store_id": None,
                "fixture_phases": [],
            }
            for slot_id in members[cohort]
        }
        for cohort in COHORTS
    }
    return {
        "generation_id": secrets.token_hex(16),
        "ordinal": len(_list(document["generations"])) + 1,
        "phase": "allocated",
        "selection_consumed": sorted(consumed),
        "members": members,
        "fixtures": fixtures,
        "activation": None,
    }


def _archives(
    root: Path, document: Mapping[str, object]
) -> tuple[dict[str, bytes], dict[Cohort, bytes], dict[Cohort, str]]:
    origins = _object(document["origins"])
    archive: dict[str, bytes] = {}
    manifests: dict[Cohort, bytes] = {}
    heads: dict[Cohort, str] = {}
    for cohort in COHORTS:
        origin = _object(origins[cohort])
        heads[cohort] = _digest(origin["head_digest"])
        for item in _list(origin["chain"]):
            digest = _digest(item)
            archive[digest] = _read(
                root / "archive" / (digest + ".private.json"), mode=0o400
            )
        digest = _digest(origin["manifest_digest"])
        raw = _read(root / "archive" / (digest + ".private.json"), mode=0o400)
        if _hash(raw) != digest:
            raise CampaignError("campaign manifest archive changed")
        manifests[cohort] = raw
    return archive, manifests, heads


def _validate_fixture(value: object, groups: list[list[str]]) -> None:
    fixture = _object(value)
    if (
        set(fixture) != _FIXTURE
        or fixture.get("fixture_preparation") not in _PREPARATION
    ):
        raise CampaignError("campaign fixture preparation is invalid")
    store_id = fixture.get("fixture_store_id")
    if store_id is not None and (
        not isinstance(store_id, str) or _IDENTIFIER.fullmatch(store_id) is None
    ):
        raise CampaignError("campaign fixture Store identity is invalid")
    phases = _list(fixture.get("fixture_phases"))
    if len(phases) > len(groups) or (store_id is None and phases):
        raise CampaignError("campaign fixture review history is invalid")
    if fixture.get("fixture_preparation") == "ready" and (
        store_id is None or len(phases) != len(groups)
    ):
        raise CampaignError("campaign fixture is not completely prepared")
    for phase_value, group in zip(phases, groups, strict=False):
        phase = _object(phase_value)
        if (
            set(phase)
            != {
                "change_set_id",
                "revision_id",
                "digest",
                "batch_id",
                "fixture_ids",
                "sources",
            }
            or phase.get("fixture_ids") != group
        ):
            raise CampaignError("campaign exact review roster changed")
        for field in ("change_set_id", "revision_id", "batch_id"):
            _text(phase[field])
        _digest(phase["digest"])
        sources = _object(phase["sources"])
        if set(sources) != set(group) or len(
            {_text(source) for source in sources.values()}
        ) != len(group):
            raise CampaignError("campaign exact review source roster changed")


def _validate_document(root: Path, document: Mapping[str, object]) -> None:
    if (
        set(document)
        != {
            "schema",
            "campaign_id",
            "created_at",
            "revision",
            "previous_head",
            "root_identity",
            "heads_identity",
            "archive_identity",
            "origins",
            "execution_paths",
            "cohorts",
            "consumed",
            "generations",
        }
        or document.get("schema") != SCHEMA
        or type(document.get("revision")) is not int
    ):
        raise CampaignError("campaign envelope is invalid")
    if document.get("root_identity") != _identity(root):
        raise CampaignError("campaign root identity changed")
    if document["heads_identity"] != _identity(root / "heads") or document[
        "archive_identity"
    ] != _identity(root / "archive"):
        raise CampaignError("campaign metadata directory identity changed")
    execution_paths = _object(document["execution_paths"])
    if set(execution_paths) != _PATHS:
        raise CampaignError("campaign explicit execution paths are invalid")
    for value in execution_paths.values():
        _path(value)
    archive, manifests, heads = _archives(root, document)
    origins, original, parsed = _imported(heads, archive, manifests)
    if document["origins"] != origins:
        raise CampaignError("campaign original bindings changed")
    consumed = _object(document["consumed"])
    historical = _historical_consumed(original)
    if any(consumed.get(key) != value for key, value in historical.items()):
        raise CampaignError("campaign historical consumption changed")
    cohorts = _cohorts(document)
    pending_roster: dict[str, list[str]] = {}
    old_stores: set[str] = set()
    old_reviews: set[str] = set()
    for cohort in COHORTS:
        before = _object(original[cohort])
        state = _object(cohorts[cohort])
        if {key: value for key, value in state.items() if key != "slots"} != {
            key: value for key, value in before.items() if key != "slots"
        }:
            raise CampaignError("campaign original provenance changed")
        _validate_manifest(state, manifests[cohort], cohort)
        pending_roster[cohort] = []
        for slot, old in zip(_rows(state), _rows(before), strict=True):
            slot_id = _text(slot["slot_id"])
            key = _key(cohort, slot_id)
            old_stores.add(_text(old["fixture_store_id"]))
            for raw_phase in _list(old["fixture_phases"]):
                phase = _object(raw_phase)
                old_reviews.update(
                    _text(phase[field])
                    for field in ("change_set_id", "revision_id", "digest", "batch_id")
                    if field in phase
                )
            if key in historical or key not in consumed:
                if slot != old:
                    raise CampaignError(
                        "campaign unreserved or historical slot changed"
                    )
            else:
                try:
                    continuation._validate_selected_slot(slot, old)
                except continuation.ContinuationError:
                    raise CampaignError("campaign execution state changed") from None
            if continuation._pending(old):
                pending_roster[cohort].append(slot_id)
    generations = [_object(value) for value in _list(document["generations"])]
    known: dict[str, dict[str, object]] = {}
    stores = set(old_stores)
    reviews = set(old_reviews)
    for ordinal, generation in enumerate(generations, 1):
        generation_id = _text(generation.get("generation_id"))
        if (
            set(generation)
            != {
                "generation_id",
                "ordinal",
                "phase",
                "selection_consumed",
                "members",
                "fixtures",
                "activation",
            }
            or _IDENTIFIER.fullmatch(generation_id) is None
            or generation_id in known
            or generation.get("ordinal") != ordinal
            or generation.get("phase") not in _PHASES
            or (ordinal < len(generations) and generation.get("phase") != "interrupted")
        ):
            raise CampaignError("campaign generation identity changed")
        known[generation_id] = generation
        selected_consumed = [
            _text(value) for value in _list(generation["selection_consumed"])
        ]
        if (
            selected_consumed != sorted(set(selected_consumed))
            or not set(historical) <= set(selected_consumed)
            or not set(selected_consumed) <= set(consumed)
        ):
            raise CampaignError("campaign generation selection changed")
        members = _object(generation["members"])
        fixtures = _object(generation["fixtures"])
        expected = {
            cohort: [
                slot_id
                for slot_id in pending_roster[cohort]
                if _key(cohort, slot_id) not in selected_consumed
            ]
            for cohort in COHORTS
        }
        if members != expected or set(fixtures) != set(COHORTS):
            raise CampaignError("campaign generation membership changed")
        for cohort in COHORTS:
            cohort_fixtures = _object(fixtures[cohort])
            if set(cohort_fixtures) != set(expected[cohort]):
                raise CampaignError("campaign fixture generation changed")
            by_slot = {
                _text(slot["slot_id"]): slot for slot in _rows(_object(cohorts[cohort]))
            }
            for slot_id, fixture_value in cohort_fixtures.items():
                fixture = _object(fixture_value)
                _validate_fixture(
                    fixture,
                    _groups(_object(parsed[cohort]), by_slot[slot_id]["case_id"]),
                )
                store_id = fixture["fixture_store_id"]
                if store_id is not None:
                    if _text(store_id) in stores:
                        raise CampaignError("campaign Store identity was already used")
                    stores.add(_text(store_id))
                for raw_phase in _list(fixture["fixture_phases"]):
                    phase = _object(raw_phase)
                    values = {
                        _text(phase[field])
                        for field in (
                            "change_set_id",
                            "revision_id",
                            "digest",
                            "batch_id",
                        )
                    }
                    if len(values) != 4 or reviews & values:
                        raise CampaignError(
                            "campaign approval identity was already used"
                        )
                    reviews.update(values)
            if generation.get("phase") in {"ready", "active"} and any(
                _object(fixture).get("fixture_preparation") != "ready"
                for fixture in cohort_fixtures.values()
            ):
                raise CampaignError("campaign requires both fixture cohorts ready")
        activation = generation["activation"]
        if activation is not None:
            active = _object(activation)
            if (
                set(active)
                != {"infrastructure_binding", "auth_roots", "prerequisite_receipt"}
                or set(_object(active["infrastructure_binding"])) != _INFRASTRUCTURE
                or set(_object(active["auth_roots"])) != set(COHORTS)
                or set(_object(active["prerequisite_receipt"])) != _PREREQUISITES
            ):
                raise CampaignError("campaign activation binding changed")
            for value in (
                *_object(active["infrastructure_binding"]).values(),
                *_object(active["prerequisite_receipt"]).values(),
            ):
                _digest(value)
            for value in _object(active["auth_roots"]).values():
                _path(value)
        elif generation.get("phase") == "active":
            raise CampaignError("campaign activation is unavailable")
    for key, value in consumed.items():
        if key in historical:
            continue
        entry = _object(value)
        if set(entry) != {"generation_id", "reserved_at"}:
            raise CampaignError("campaign reservation is invalid")
        reserved_generation = known.get(_text(entry["generation_id"]))
        _text(entry["reserved_at"])
        if (
            reserved_generation is None
            or reserved_generation.get("activation") is None
            or not any(
                key == _key(cohort, _text(slot_id))
                for cohort in COHORTS
                for slot_id in _list(_object(reserved_generation["members"])[cohort])
            )
        ):
            raise CampaignError("campaign reservation has no active membership")


def _load(root: Path, index: Mapping[str, object]) -> Campaign:
    identity = _identity(root)
    records = _object(index["campaigns"])
    matches = [
        (key, _object(value))
        for key, value in records.items()
        if _object(value).get("root_identity") == identity
    ]
    if len(matches) != 1:
        raise CampaignError("campaign root is not the registered authority")
    campaign_id, record = matches[0]
    if set(record) != {"root_identity", "head_digest"}:
        raise CampaignError("campaign registrar entry changed")
    digest = _digest(record["head_digest"])
    raw = _read(root / "heads" / (digest + ".private.json"), mode=0o400)
    if _hash(raw) != digest:
        raise CampaignError("campaign authoritative head changed")
    document = _decode(raw)
    if document.get("campaign_id") != campaign_id:
        raise CampaignError("campaign identity changed")
    _validate_document(root, document)
    claims = _object(index["cohorts"])
    if any(
        claims.get(_text(_object(origin)["cohort_identity"])) != campaign_id
        for origin in _object(document["origins"]).values()
    ):
        raise CampaignError("campaign cohort ownership changed")
    return Campaign(root, digest, document)


def _checked(campaign: Campaign, index: Mapping[str, object]) -> Campaign:
    if _hash(_canonical(campaign.document)) != campaign.digest:
        raise CampaignError("campaign handle was modified")
    current = _load(campaign.root, index)
    if current.digest != campaign.digest:
        raise CampaignError("campaign head changed; reload before writing")
    return current


@dataclass
class _HeadCustody:
    root: Path
    document: Mapping[str, object]
    root_descriptor: int
    heads_descriptor: int
    archive_descriptor: int
    head_descriptor: int | None = None
    head_name: str | None = None
    head_bytes: bytes | None = None


def _assert_head_custody(custody: _HeadCustody) -> None:
    for path, descriptor, field in (
        (custody.root, custody.root_descriptor, "root_identity"),
        (custody.root / "heads", custody.heads_descriptor, "heads_identity"),
        (custody.root / "archive", custody.archive_descriptor, "archive_identity"),
    ):
        expected = custody.document[field]
        if (
            _descriptor_identity(path, descriptor) != expected
            or _identity(path) != expected
        ):
            raise CampaignError("campaign publication custody changed")
    if custody.head_descriptor is None:
        return
    assert custody.head_name is not None and custody.head_bytes is not None
    held = os.fstat(custody.head_descriptor)
    named = os.stat(
        custody.head_name, dir_fd=custody.heads_descriptor, follow_symlinks=False
    )
    if (
        not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.getuid()
        or held.st_nlink != 1
        or stat.S_IMODE(held.st_mode) != 0o400
        or held.st_size != len(custody.head_bytes)
        or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
        or _read_at(
            custody.heads_descriptor, custody.head_name, mode=0o400, synchronize=True
        )
        != custody.head_bytes
    ):
        raise CampaignError("campaign named publication head changed")
    after = os.stat(
        custody.head_name, dir_fd=custody.heads_descriptor, follow_symlinks=False
    )
    if (after.st_dev, after.st_ino) != (held.st_dev, held.st_ino):
        raise CampaignError("campaign named publication head was replaced")
    os.fsync(custody.heads_descriptor)


@contextmanager
def _head_custody(root: Path, document: Mapping[str, object]) -> Iterator[_HeadCustody]:
    descriptors: list[int] = []
    custody: _HeadCustody | None = None
    try:
        root_descriptor = _directory(root)
        descriptors.append(root_descriptor)
        for name in ("heads", "archive"):
            descriptors.append(
                os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_descriptor,
                )
            )
        custody = _HeadCustody(
            root, document, descriptors[0], descriptors[1], descriptors[2]
        )
        _assert_head_custody(custody)
        yield custody
        _assert_head_custody(custody)
    except OSError:
        raise CampaignError("campaign publication custody is unavailable") from None
    finally:
        if custody is not None and custody.head_descriptor is not None:
            os.close(custody.head_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _publish_head(
    root: Path,
    document: Mapping[str, object],
    authority: _Authority,
    index: dict[str, object],
) -> Campaign:
    custody = authority.custody_stack.enter_context(_head_custody(root, document))
    raw = _canonical(document)
    digest = _immutable(root / "heads", raw)
    _assert_head_custody(custody)
    custody.head_name = digest + ".private.json"
    custody.head_bytes = raw
    custody.head_descriptor = os.open(
        custody.head_name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=custody.heads_descriptor,
    )
    _assert_head_custody(custody)
    _object(index["campaigns"])[_text(document["campaign_id"])] = {
        "root_identity": document["root_identity"],
        "head_digest": digest,
    }
    previous_guard = authority.publication_guard

    def check_head() -> None:
        if previous_guard is not None:
            previous_guard()
        _assert_head_custody(custody)

    authority.publication_guard = check_head
    _publish_index(authority, index)
    _assert_head_custody(custody)
    return Campaign(root, digest, document)


def _commit(
    campaign: Campaign,
    document: dict[str, object],
    registrar: _Authority,
    index: dict[str, object],
) -> Campaign:
    document["previous_head"] = campaign.digest
    revision = campaign.document["revision"]
    assert isinstance(revision, int)
    document["revision"] = revision + 1
    _validate_document(campaign.root, document)
    return _publish_head(campaign.root, document, registrar, index)


def create_campaign(
    parent: Path,
    *,
    heads: Mapping[Cohort, str],
    archive: Mapping[str, bytes],
    manifests: Mapping[Cohort, bytes],
    execution_paths: Mapping[str, Path],
) -> Campaign:
    """Claim both original cohorts once, retaining exact imported bytes."""
    origins, cohorts, _parsed = _imported(heads, archive, manifests)
    paths = _execution_paths(execution_paths)
    with _registrar(create=True) as (registrar, index):
        claims = _object(index["cohorts"])
        identities = [
            _text(_object(origins[cohort])["cohort_identity"]) for cohort in COHORTS
        ]
        if any(identity in claims for identity in identities):
            raise CampaignError("campaign original cohort was already claimed")
        descriptor = _directory(parent)
        os.close(descriptor)
        campaign_id = secrets.token_hex(16)
        root = parent / ("campaign-" + campaign_id)
        root.mkdir(mode=0o700)
        (root / "archive").mkdir(mode=0o700)
        (root / "heads").mkdir(mode=0o700)
        for raw in (*archive.values(), *manifests.values()):
            _immutable(root / "archive", raw)
        document: dict[str, object] = {
            "schema": SCHEMA,
            "campaign_id": campaign_id,
            "created_at": _now(),
            "revision": 0,
            "previous_head": None,
            "root_identity": _identity(root),
            "heads_identity": _identity(root / "heads"),
            "archive_identity": _identity(root / "archive"),
            "origins": origins,
            "execution_paths": paths,
            "cohorts": cohorts,
            "consumed": _historical_consumed(cohorts),
            "generations": [],
        }
        _list(document["generations"]).append(_new_generation(document))
        _validate_document(root, document)
        _fsync(root)
        _fsync(parent)
        for identity in identities:
            claims[identity] = campaign_id
        return _publish_head(root, document, registrar, index)


def _execution_paths(execution_paths: Mapping[str, Path]) -> dict[str, str]:
    if set(execution_paths) != _PATHS:
        raise CampaignError("campaign requires explicit current execution paths")
    return {key: str(_path(str(value))) for key, value in execution_paths.items()}


def _execution_private(
    paths: Mapping[str, object], cohort: Cohort
) -> dict[str, object]:
    return {
        "memory_executable": paths["memory_executable"],
        "client_executable": paths["client_executable"],
        "build_artifact": paths["build_artifact"],
        "manifest_path": paths[cohort + "_manifest"],
        "seed_executable": None,
    }


def preflight_execution_states(
    *,
    heads: Mapping[Cohort, str],
    archive: Mapping[str, bytes],
    manifests: Mapping[Cohort, bytes],
    execution_paths: Mapping[str, Path],
) -> Mapping[Cohort, dict[str, object]]:
    """Pure current-artifact views before any irreversible cohort claim exists."""
    _origins, cohorts, _parsed = _imported(heads, archive, manifests)
    paths = _execution_paths(execution_paths)
    result: dict[Cohort, dict[str, object]] = {}
    for cohort in COHORTS:
        state = copy.deepcopy(_object(cohorts[cohort]))
        state.pop("continuation", None)
        state["private"] = _execution_private(paths, cohort)
        for slot in _rows(state):
            slot["private_trial_directory"] = None
            slot.update(
                fixture_preparation="pending",
                fixture_store_id=None,
                fixture_phases=[],
            )
        result[cohort] = state
    return result


def load_campaign(root: Path) -> Campaign:
    with _registrar() as (_registrar_path, index):
        return _load(root, index)


def _fresh(campaign: Campaign) -> Campaign:
    with _registrar() as (_registrar_path, index):
        return _checked(campaign, index)


def original_heads(campaign: Campaign) -> Mapping[Cohort, str]:
    current = _fresh(campaign)
    return {
        cohort: _digest(
            _object(_object(current.document["origins"])[cohort])["head_digest"]
        )
        for cohort in COHORTS
    }


def generation_number(campaign: Campaign) -> int:
    current = _fresh(campaign)
    value = _generation(current.document)["ordinal"]
    assert isinstance(value, int)
    return value


def activation_prerequisites(campaign: Campaign) -> Mapping[str, str]:
    current = _fresh(campaign)
    activation = _object(_generation(current.document).get("activation"))
    return {
        key: _digest(value)
        for key, value in _object(activation["prerequisite_receipt"]).items()
    }


def _fixture_paths(campaign: Campaign, cohort: Cohort, slot_id: str) -> FixturePaths:
    generation = _generation(campaign.document)
    if cohort not in COHORTS or slot_id not in _list(
        _object(generation["members"])[cohort]
    ):
        raise CampaignError("campaign slot is outside the replacement generation")
    slots = _rows(_object(_cohorts(campaign.document)[cohort]))
    ordinal = next(
        index for index, slot in enumerate(slots, 1) if slot["slot_id"] == slot_id
    )
    trial = (
        campaign.root
        / "generations"
        / campaign.generation_id
        / cohort
        / "private-trials"
        / f"trial-{ordinal:03d}"
    )
    return FixturePaths(
        trial,
        trial / "store",
        trial / "client-response.private",
        trial / "client-stderr.private",
    )


def fixture_paths(campaign: Campaign, cohort: Cohort, slot_id: str) -> FixturePaths:
    return _fixture_paths(_fresh(campaign), cohort, slot_id)


def validate_fixture_home(
    campaign: Campaign, cohort: Cohort, slot_id: str, home: Path
) -> Path:
    current = _fresh(campaign)
    expected = _fixture_paths(current, cohort, slot_id).store
    if home != expected:
        raise CampaignError("campaign fixture home changed")
    for parent in (expected, *expected.parents):
        descriptor = _directory(parent)
        os.close(descriptor)
        if parent == current.root:
            break
    return expected


def _view(campaign: Campaign, cohort: Cohort, *, active: bool) -> dict[str, object]:
    if cohort not in COHORTS:
        raise CampaignError("campaign cohort is invalid")
    generation = _generation(campaign.document)
    if active and generation["phase"] != "active":
        raise CampaignError("campaign generation is not active")
    state = copy.deepcopy(_object(_cohorts(campaign.document)[cohort]))
    state.pop("continuation", None)
    paths = _object(campaign.document["execution_paths"])
    state["private"] = {
        **_execution_private(paths, cohort),
        "fixture_run_id": campaign.generation_id,
    }
    # The old mapping is intentionally not copied: even an unexpected historical
    # path must remain inert unless the new interface explicitly supplies it.
    activation = generation["activation"]
    if activation is not None:
        binding = _object(activation)
        _object(state["provenance"]).update(_object(binding["infrastructure_binding"]))
        _object(state["private"])["subscription_auth_root"] = _object(
            binding["auth_roots"]
        )[cohort]
    fixtures = _object(_object(generation["fixtures"])[cohort])
    for slot in _rows(state):
        slot_id = _text(slot["slot_id"])
        if slot_id in fixtures:
            slot.update(copy.deepcopy(_object(fixtures[slot_id])))
            slot["private_trial_directory"] = str(
                _fixture_paths(campaign, cohort, slot_id).trial
            )
    return state


def cohort_view(
    campaign: Campaign, cohort: Cohort, *, active: bool = False
) -> dict[str, object]:
    return _view(_fresh(campaign), cohort, active=active)


def record_fixture(
    campaign: Campaign,
    cohort: Cohort,
    slot_id: str,
    *,
    preparation: str,
    store_id: str | None,
    phases: Sequence[Mapping[str, object]],
) -> Campaign:
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        _fixture_paths(current, cohort, slot_id)
        document = copy.deepcopy(dict(current.document))
        generation = _generation(document)
        if generation["phase"] not in {"allocated", "preparing"}:
            raise CampaignError("campaign fixture generation is frozen")
        fixtures = _object(_object(generation["fixtures"])[cohort])
        old = _object(fixtures[slot_id])
        new: dict[str, object] = {
            "fixture_preparation": preparation,
            "fixture_store_id": store_id,
            "fixture_phases": [dict(phase) for phase in phases],
        }
        old_phases = _list(old["fixture_phases"])
        if (
            (
                old["fixture_store_id"] is not None
                and old["fixture_store_id"] != store_id
            )
            or list(phases[: len(old_phases)]) != old_phases
            or len(phases) > len(old_phases) + 1
            or (
                old["fixture_preparation"] == "fixture_preparation_failed"
                and new != old
            )
        ):
            raise CampaignError("campaign fixture history cannot be replaced")
        if new == old:
            return current
        fixtures[slot_id] = new
        generation["phase"] = "preparing"
        return _commit(current, document, registrar, index)


def mark_ready(campaign: Campaign) -> Campaign:
    """Record the caller's completed verification of both prepared cohorts."""
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        document = copy.deepcopy(dict(current.document))
        generation = _generation(document)
        if generation["phase"] not in {"allocated", "preparing"}:
            raise CampaignError("campaign readiness transition is unavailable")
        generation["phase"] = "ready"
        return _commit(current, document, registrar, index)


def activate_campaign(
    campaign: Campaign,
    *,
    infrastructure_binding: Mapping[str, str],
    auth_roots: Mapping[Cohort, Path],
    prerequisite_receipt: Mapping[str, str],
) -> Campaign:
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        document = copy.deepcopy(dict(current.document))
        generation = _generation(document)
        if (
            generation["phase"] != "ready"
            or generation["activation"] is not None
            or set(auth_roots) != set(COHORTS)
        ):
            raise CampaignError("campaign activation transition is unavailable")
        historical: list[Path] = []
        for state_value in _cohorts(document).values():
            state = _object(state_value)
            private = _object(state["private"])
            historical.append(_path(private["subscription_auth_root"]))
            if "continuation" in private:
                historical.append(_path(_object(private["continuation"])["auth_root"]))
        for old_value in _list(document["generations"])[:-1]:
            old = _object(old_value)
            if old["activation"] is not None:
                historical.extend(
                    _path(value)
                    for value in _object(
                        _object(old["activation"])["auth_roots"]
                    ).values()
                )
        paths = {cohort: _path(str(auth_roots[cohort])) for cohort in COHORTS}
        if any(
            path.is_relative_to(old) or old.is_relative_to(path)
            for path in paths.values()
            for old in (*historical, current.root)
        ):
            raise CampaignError(
                "campaign authentication scope must be fresh and temporary"
            )
        generation["activation"] = {
            "infrastructure_binding": dict(infrastructure_binding),
            "auth_roots": {cohort: str(path) for cohort, path in paths.items()},
            "prerequisite_receipt": dict(prerequisite_receipt),
        }
        generation["phase"] = "active"
        return _commit(current, document, registrar, index)


def reserve_attempt(campaign: Campaign, cohort: Cohort, slot_id: str) -> Campaign:
    """Consume the logical slot durably before the caller may launch anything."""
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        _fixture_paths(current, cohort, slot_id)
        document = copy.deepcopy(dict(current.document))
        generation = _generation(document)
        key = _key(cohort, slot_id)
        consumed = _object(document["consumed"])
        if generation["phase"] != "active" or key in consumed:
            raise CampaignError("campaign logical slot cannot be reserved again")
        slot = next(
            slot
            for slot in _rows(_object(_cohorts(document)[cohort]))
            if slot["slot_id"] == slot_id
        )
        if not continuation._pending(slot):
            raise CampaignError("campaign attempted slot cannot be reserved")
        consumed[key] = {"generation_id": current.generation_id, "reserved_at": _now()}
        slot.update(
            attempted=True,
            execution_outcome="interrupted",
            outcome_label="execution_interrupted",
        )
        return _commit(current, document, registrar, index)


def record_progress(
    campaign: Campaign, cohort: Cohort, state: Mapping[str, object]
) -> Campaign:
    """Merge only monotone execution results for already reserved logical slots."""
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        expected = _view(current, cohort, active=False)
        if {key: value for key, value in state.items() if key != "slots"} != {
            key: value for key, value in expected.items() if key != "slots"
        }:
            raise CampaignError("campaign execution provenance changed")
        received = _rows(state)
        before = _rows(expected)
        if len(received) != len(before):
            raise CampaignError("campaign execution roster changed")
        document = copy.deepcopy(dict(current.document))
        targets = _rows(_object(_cohorts(document)[cohort]))
        consumed = _object(document["consumed"])
        for slot, prior, target in zip(received, before, targets, strict=True):
            if slot == prior:
                continue
            if {key: value for key, value in slot.items() if key not in _EXECUTION} != {
                key: value for key, value in prior.items() if key not in _EXECUTION
            }:
                raise CampaignError("campaign fixture or logical slot changed")
            entry = _object(consumed.get(_key(cohort, _text(slot["slot_id"]))))
            if entry.get("generation_id") != current.generation_id:
                raise CampaignError("campaign slot has no current attempt reservation")
            if (
                prior["execution_outcome"] in {"failed", "blocked"}
                or prior["grade_outcome"] != "ungraded"
            ):
                raise CampaignError("campaign terminal outcome is immutable")
            if prior["execution_outcome"] == "completed" and any(
                slot.get(field) != prior.get(field)
                for field in _EXECUTION
                - {"grade_outcome", "outcomes", "outcome_label", "inference_started"}
            ):
                raise CampaignError("campaign completed execution cannot be replayed")
            if (
                (
                    prior.get("client_launch_attempted") is True
                    and slot.get("client_launch_attempted") is not True
                )
                or (
                    prior.get("inference_started") is True
                    and slot.get("inference_started") is not True
                )
                or (
                    "capability_probe" in prior
                    and slot.get("capability_probe") != prior["capability_probe"]
                )
            ):
                raise CampaignError("campaign execution evidence cannot be withdrawn")
            for field in _EXECUTION:
                if field in slot:
                    target[field] = copy.deepcopy(slot[field])
                else:
                    target.pop(field, None)
        if document == current.document:
            return current
        return _commit(current, document, registrar, index)


def interrupt_campaign(campaign: Campaign) -> Campaign:
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        document = copy.deepcopy(dict(current.document))
        generation = _generation(document)
        if generation["phase"] == "interrupted":
            return current
        generation["phase"] = "interrupted"
        return _commit(current, document, registrar, index)


def start_generation(campaign: Campaign) -> Campaign:
    with _registrar() as (registrar, index):
        current = _checked(campaign, index)
        document = copy.deepcopy(dict(current.document))
        if _generation(document)["phase"] != "interrupted":
            raise CampaignError("campaign prior generation is not interrupted")
        _list(document["generations"]).append(_new_generation(document))
        return _commit(current, document, registrar, index)


def report_context(campaign: Campaign, cohort: Cohort) -> dict[str, object]:
    """Return public bindings and labels without campaign, Store or path IDs."""
    current = _fresh(campaign)
    state = _object(_cohorts(current.document)[cohort])
    provenance = _object(state["provenance"])
    allowed = {
        "client_kind",
        "client_version",
        "model",
        "reasoning_effort",
        "product_version",
        "build_digest",
        "memory_executable_digest",
        "client_executable_digest",
        "seed_executable_digest",
        "installed_distribution_digest",
        "mcp_contract_digest",
        "skill_digest",
        "seed_mode",
        "manifest_digest",
        "manifest_schema",
        "manifest_version",
        "rubric_digest",
        "rubric_version",
        "code_mode_host_digest",
        "isolation_profile_digest",
        "authentication_mode",
        "authentication_adapter_digest",
    }
    public = {key: value for key, value in provenance.items() if key in allowed}
    bindings: dict[str, object] = {"original": public}
    continued: list[object] = []
    if "continuation" in state:
        metadata = _object(state["continuation"])
        bindings["continued"] = {
            **public,
            **_object(metadata["infrastructure_binding"]),
        }
        continued = _list(metadata["pending_slot_ids"])
    labels = {
        _text(slot["slot_id"]): "continued"
        if slot["slot_id"] in continued
        else "original"
        for slot in _rows(state)
    }
    for value in _list(current.document["generations"]):
        generation = _object(value)
        label = (
            f"replacement_{generation['ordinal']:03d}"
            if isinstance(generation["ordinal"], int)
            else ""
        )
        activation = generation["activation"]
        if activation is not None:
            bindings[label] = {
                **public,
                **_object(_object(activation)["infrastructure_binding"]),
            }
        for slot_id in _list(_object(generation["members"])[cohort]):
            entry = _object(current.document["consumed"]).get(
                _key(cohort, _text(slot_id))
            )
            if (
                entry is None
                or _object(entry).get("generation_id") == generation["generation_id"]
            ):
                labels[_text(slot_id)] = label
    return {"schema": SCHEMA, "execution_bindings": bindings, "slot_bindings": labels}
