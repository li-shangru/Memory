"""Immutable Memory PR review and atomic owner-approved application."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from calendar import monthrange
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from typing import Any, Literal, cast

from memory.database import (
    Connection,
    Row,
    guard_revocations_recorded,
    writer_session,
)
from memory.errors import (
    AmbiguousEvidenceError,
    IncompleteBatchError,
    InvalidArgumentError,
    InvalidEvidenceError,
    NotFoundError,
    OwnerApprovalRequiredError,
    StaleHeadError,
    StaleRevisionError,
    StoreError,
    WrongDigestError,
)
from memory.model import (
    AddGuardLink,
    AddItem,
    ApplicationResult,
    ChangeEdit,
    ChangeSetAdapterOrigin,
    ChangeSetView,
    ClearSourceNoMemory,
    DraftGuardLink,
    DraftItem,
    EvidenceInput,
    EvidenceLocator,
    GuardLinkInput,
    GuardViolation,
    MemoryFields,
    MemoryKind,
    RejectItem,
    RemoveGuardLink,
    ReplaceItem,
    RestoreItem,
    RevokeGuardLink,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceDecision,
)
from memory.runtime import load_runtime_identity
from memory.sources import (
    SEARCHABLE_MEDIA_TYPES,
    _effective_rank_sql,
    _read_connection,
    _validate_opaque_id,
)
from memory.validation import (
    SENSITIVITY_RANK,
    require_invariant,
    sensitivity_from_rank,
    strict_utf8_bytes,
)

DIGEST_FORMAT = "memory.change-set-digest.v1"
MAX_CHANGE_ITEMS = 256
MAX_GUARD_LINKS = 256
# Every guard on a claim rides along on every hit that returns the claim, so
# this ceiling is a wire commitment: it is the guards maxItems the MCP
# schemas declare, and enforcing it here is what makes that bound honest.
MAX_GUARDS_PER_LINEAGE = 256
MAX_EDIT_OPERATIONS = 256
MAX_EVIDENCE_PER_ITEM = 16
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_STATEMENT_BYTES = 16 * 1024
MAX_EVIDENCE_EXCERPT_BYTES = 4 * 1024
MAX_NO_MEMORY_REASON_BYTES = 4 * 1024
MAX_TAGS = 64
#: Most source identifiers any one refusal names. Equal to the sealed-batch
#: file ceiling and to the `source_ids` maxItems the error-details schema
#: declares, so naming every source a batch can hold stays inside the bound
#: the wire promises.
MAX_BATCH_SOURCE_IDS = 64
MAX_TAG_BYTES = 256
_DIGEST = re.compile(r"[0-9a-f]{64}")
#: Read side. `\d` is the whole Nd category in Python's `re`, so this admits a
#: date written in any decimal script -- which is what a revision stored before
#: `_ACCEPTED_PARTIAL_DATE` existed may hold. `_date_bounds` runs against those
#: stored values and asserts its own match, so narrowing this one too would
#: turn a revision an older release accepted into a crash on an ordinary
#: search rather than a value the owner can supersede.
_PARTIAL_DATE = re.compile(r"(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?")
#: Write side, and deliberately narrower. JSON Schema fixes `pattern` to
#: ECMA-262, where `\d` is exactly `[0-9]`, so the declared wire pattern for
#: the three date fields admits ASCII digits and nothing else. Accepting more
#: than that published a value under a declaration that rejects it.
_ACCEPTED_PARTIAL_DATE = re.compile(r"([0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?")
_APPROVAL_ADAPTERS = frozenset(
    {"mcp_elicitation", "local_owner_ui", "os_owner_presence_cli"}
)
_APPROVAL_CONSTRUCTOR = object()

type _ReviewValidationCode = Literal[
    "unaccounted_source",
    "ambiguous_evidence",
    "stale_expected_head",
    "duplicate_lineage_target",
    "invalid_review",
]
type _NumberedGuardLink = tuple[int, GuardLinkInput]

_LINEAGE_EFFECTIVE_RANK_SQL = f"""
SELECT {_effective_rank_sql("mr")}
FROM memory_revisions AS mr
JOIN current_memory_heads AS heads ON heads.revision_id = mr.revision_id
WHERE heads.lineage_id = ?
"""


@dataclass(frozen=True, slots=True)
class _ReviewValidationIssue:
    """One content-free owner blocker bound to an exact core apply failure."""

    code: _ReviewValidationCode
    error: StoreError
    item_id: str | None = None
    source_id: str | None = None
    expected_head_id: str | None = None
    current_head_id: str | None = None


class OwnerApproval:
    """One-use capability minted only after a trusted adapter's direct decision."""

    __slots__ = (
        "_adapter",
        "_change_set_id",
        "_digest",
        "_revision_id",
        "_store_id",
        "_used",
    )

    def __init__(
        self,
        constructor: object,
        *,
        store_id: str,
        change_set_id: str,
        revision_id: str,
        digest: str,
        adapter: str,
    ) -> None:
        if constructor is not _APPROVAL_CONSTRUCTOR:
            raise TypeError("OwnerApproval is an internal capability")
        self._store_id = store_id
        self._change_set_id = change_set_id
        self._revision_id = revision_id
        self._digest = digest
        self._adapter = adapter
        self._used = False

    def _consume(
        self,
        *,
        store_id: str,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> str:
        if self._used:
            raise OwnerApprovalRequiredError(
                "owner approval capability was already used"
            )
        if (
            self._store_id,
            self._change_set_id,
            self._revision_id,
            self._digest,
        ) != (store_id, change_set_id, revision_id, digest):
            raise OwnerApprovalRequiredError("owner approval capability is invalid")
        self._used = True
        return self._adapter


def canonical_digest(payload: Mapping[str, object]) -> tuple[bytes, str]:
    """Encode and hash the exact canonical change-set payload."""
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise InvalidArgumentError("change-set digest payload is invalid") from error
    return encoded, hashlib.sha256(encoded).hexdigest()


def render_change_set(view: ChangeSetView) -> str:
    """Render the exact canonical payload bytes plus their lowercase digest."""
    encoded, digest = canonical_digest(view.digest_payload)
    if digest != view.digest:
        raise InvalidArgumentError("change-set digest is inconsistent")
    return f"Digest: {digest}\nPayload:\n{encoded.decode('utf-8')}\n"


def create_change_set(
    paths: RuntimePaths,
    batch_id: str,
    *,
    adapter_origin: ChangeSetAdapterOrigin,
) -> ChangeSetView:
    """Return the sole immutable-revision review for one sealed inbox batch."""
    _validate_adapter_origin(adapter_origin)
    _validate_opaque_id(batch_id)
    with writer_session(paths) as connection:
        if (
            connection.execute(
                "SELECT 1 FROM inbox_batches WHERE batch_id = ?", (batch_id,)
            ).fetchone()
            is None
        ):
            raise NotFoundError("batch identifier was not found")
        row = connection.execute(
            "SELECT change_set_id FROM change_sets WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is not None:
            return _load_change_set(connection, str(row[0]))
        created_at = int(time.time())
        change_set_id = _new_id("chg")
        revision_id = _new_id("csr")
        identity = load_runtime_identity(paths)
        payload = _digest_payload(
            store_id=identity.store_id,
            change_set_id=change_set_id,
            batch_id=batch_id,
            revision_id=revision_id,
            items=(),
            decisions=(),
            guard_links=(),
            revoked_guard_links=(),
        )
        encoded, digest = canonical_digest(payload)
        _check_diff_size(encoded)
        connection.execute(
            "INSERT INTO change_sets "
            "(change_set_id, batch_id, state, created_at) VALUES (?, ?, 'draft', ?)",
            (change_set_id, batch_id, created_at),
        )
        connection.execute(
            "INSERT INTO change_set_revisions "
            "(revision_id, change_set_id, predecessor_id, digest, "
            "adapter_origin, created_at) VALUES (?, ?, NULL, ?, ?, ?)",
            (
                revision_id,
                change_set_id,
                digest,
                adapter_origin.value,
                created_at,
            ),
        )
        return _load_change_set(connection, change_set_id)


def get_change_set(paths: RuntimePaths, change_set_id: str) -> ChangeSetView:
    """Return the sole change set's complete current immutable revision."""
    _validate_opaque_id(change_set_id)
    with _read_connection(paths) as (connection, _identity):
        return _load_change_set(connection, change_set_id)


def edit_change_set(
    paths: RuntimePaths,
    change_set_id: str,
    expected_revision_id: str,
    edits: Sequence[ChangeEdit],
    *,
    adapter_origin: ChangeSetAdapterOrigin,
) -> ChangeSetView:
    """Create one immutable successor draft from bounded explicit operations."""
    _validate_adapter_origin(adapter_origin)
    _validate_opaque_id(change_set_id)
    _validate_opaque_id(expected_revision_id)
    if (
        isinstance(edits, (str, bytes))
        or not isinstance(edits, Sequence)
        or not 1 <= len(edits) <= MAX_EDIT_OPERATIONS
    ):
        raise InvalidArgumentError("edit operations are invalid")

    with writer_session(paths) as connection:
        current = _load_change_set(connection, change_set_id)
        if current.state != "draft":
            raise StaleRevisionError(
                "applied change set cannot be edited",
                details={"expected_revision_id": current.revision_id},
            )
        if expected_revision_id != current.revision_id:
            raise StaleRevisionError(
                "draft revision is stale",
                details={"expected_revision_id": current.revision_id},
            )

        batch_sources = _batch_sources(connection, current.batch_id)
        items = list(current.items)
        links = [_link_input(link) for link in current.guard_links]
        revocations = [_link_input(link) for link in current.revoked_guard_links]
        no_memory = {
            decision.source_id: decision.reason
            for decision in current.source_decisions
            if decision.state == "no_memory"
        }
        for ordinal, edit in enumerate(edits):
            try:
                if isinstance(edit, AddItem):
                    _validate_opaque_id(edit.client_item_id)
                    if any(item.item_id == edit.client_item_id for item in items):
                        raise InvalidArgumentError(
                            "draft item identifier already exists"
                        )
                    if len(items) >= MAX_CHANGE_ITEMS:
                        raise InvalidArgumentError("change-set item limit exceeded")
                    memory = _normalize_memory(connection, edit.memory)
                    evidence = _normalize_evidence(
                        edit.evidence,
                        batch_sources=batch_sources,
                        memory=memory,
                    )
                    next_ordinal = max((item.ordinal for item in items), default=-1) + 1
                    items.append(
                        DraftItem(
                            ordinal=next_ordinal,
                            item_id=edit.client_item_id,
                            status="active",
                            memory=memory,
                            evidence=evidence,
                        )
                    )
                elif isinstance(edit, ReplaceItem):
                    index = _item_index(items, edit.item_id)
                    memory = _normalize_memory(connection, edit.memory)
                    evidence = _normalize_evidence(
                        edit.evidence,
                        batch_sources=batch_sources,
                        memory=memory,
                    )
                    previous = items[index]
                    items[index] = DraftItem(
                        ordinal=previous.ordinal,
                        item_id=previous.item_id,
                        status=previous.status,
                        memory=memory,
                        evidence=evidence,
                    )
                elif isinstance(edit, RejectItem):
                    index = _item_index(items, edit.item_id)
                    items[index] = replace(items[index], status="rejected")
                elif isinstance(edit, RestoreItem):
                    index = _item_index(items, edit.item_id)
                    items[index] = replace(items[index], status="active")
                elif isinstance(edit, SetSourceNoMemory):
                    _require_batch_source(batch_sources, edit.source_id)
                    no_memory[edit.source_id] = _bounded_string(
                        edit.reason,
                        maximum=MAX_NO_MEMORY_REASON_BYTES,
                        label="no-memory reason",
                        strip=True,
                    )
                elif isinstance(edit, ClearSourceNoMemory):
                    _require_batch_source(batch_sources, edit.source_id)
                    no_memory.pop(edit.source_id, None)
                elif isinstance(edit, AddGuardLink):
                    candidate = _validated_guard_link(edit.link)
                    if candidate in links:
                        raise InvalidArgumentError("guard link already exists")
                    if len(links) >= MAX_GUARD_LINKS:
                        raise InvalidArgumentError("guard link limit exceeded")
                    links.append(candidate)
                elif isinstance(edit, RemoveGuardLink):
                    candidate = _validated_guard_link(edit.link)
                    if candidate not in links:
                        raise InvalidArgumentError("guard link was not found")
                    links.remove(candidate)
                elif isinstance(edit, RevokeGuardLink):
                    candidate = _validated_guard_link(edit.link)
                    if candidate in revocations:
                        raise InvalidArgumentError(
                            "guard link revocation already exists"
                        )
                    if len(revocations) >= MAX_GUARD_LINKS:
                        raise InvalidArgumentError(
                            "guard link revocation limit exceeded"
                        )
                    revocations.append(candidate)
                else:
                    raise InvalidArgumentError("edit operation is invalid")
            except StoreError as error:
                # Every refusal from this dispatch is about one edit, so it
                # carries which one. The locators are content-free and the
                # error keeps its own code and any details it already set.
                raise type(error)(
                    str(error),
                    details={
                        **(error.details or {}),
                        **_edit_locators(ordinal, edit),
                    },
                ) from error

        items.sort(key=lambda item: item.ordinal)
        _validate_active_targets(items)
        linked_pairs = _validate_guard_links(connection, links, items)
        _validate_guard_revocations(connection, revocations, items, linked_pairs)
        numbered_links = tuple(enumerate(links))
        numbered_revocations = tuple(enumerate(revocations))
        used = {
            locator.source_id
            for item in items
            if item.status == "active"
            for locator in item.evidence
        }
        contested = used & set(no_memory)
        if contested:
            # Named for the same reason every other post-dispatch refusal is:
            # both operations cleared the loop that attaches ordinals, so the
            # caller is otherwise told only that something in a 256-operation
            # edit was wrong. A batch holds at most 64 sources, so listing the
            # contested ones stays inside the bound `source_ids` declares.
            raise InvalidArgumentError(
                "a source cannot be used and no-memory",
                details={"source_ids": sorted(contested)[:MAX_BATCH_SOURCE_IDS]},
            )
        decisions = tuple(
            SourceDecision(
                ordinal=source.ordinal,
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                state="used" if source.source_id in used else "no_memory",
                reason=None
                if source.source_id in used
                else cast(str, no_memory[source.source_id]),
            )
            for source in batch_sources.values()
            if source.source_id in used or source.source_id in no_memory
        )
        revision_id = _new_id("csr")
        identity = load_runtime_identity(paths)
        payload = _digest_payload(
            store_id=identity.store_id,
            change_set_id=current.change_set_id,
            batch_id=current.batch_id,
            revision_id=revision_id,
            items=tuple(items),
            decisions=decisions,
            guard_links=numbered_links,
            revoked_guard_links=numbered_revocations,
        )
        encoded, digest = canonical_digest(payload)
        _check_diff_size(encoded)
        connection.execute(
            "INSERT INTO change_set_revisions "
            "(revision_id, change_set_id, predecessor_id, digest, "
            "adapter_origin, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                revision_id,
                current.change_set_id,
                current.revision_id,
                digest,
                adapter_origin.value,
                int(time.time()),
            ),
        )
        _insert_revision_rows(
            connection,
            revision_id,
            tuple(items),
            decisions,
            numbered_links,
            numbered_revocations,
        )
        return _load_change_set(connection, current.change_set_id)


def _mint_bound_owner_approval(
    store_id: str,
    change_set_id: str,
    revision_id: str,
    digest: str,
    *,
    adapter: str,
) -> OwnerApproval:
    """Mint a capability already bound to one exact resolved Store identity."""
    _validate_opaque_id(store_id)
    _validate_opaque_id(change_set_id)
    _validate_opaque_id(revision_id)
    _validate_digest(digest)
    if adapter not in _APPROVAL_ADAPTERS:
        raise InvalidArgumentError("approval adapter is invalid")
    return OwnerApproval(
        _APPROVAL_CONSTRUCTOR,
        store_id=store_id,
        change_set_id=change_set_id,
        revision_id=revision_id,
        digest=digest,
        adapter=adapter,
    )


def _mint_owner_approval(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
    *,
    adapter: str,
) -> OwnerApproval:
    """Mint a capability for a trusted adapter after its direct owner decision."""
    identity = load_runtime_identity(paths)
    return _mint_bound_owner_approval(
        identity.store_id,
        change_set_id,
        revision_id,
        digest,
        adapter=adapter,
    )


def approve_and_apply(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
    approval: OwnerApproval | None,
) -> ApplicationResult:
    """Apply one exact owner-approved revision atomically or return exact replay."""
    _validate_opaque_id(change_set_id)
    _validate_opaque_id(revision_id)
    _validate_digest(digest)
    identity = load_runtime_identity(paths)
    with writer_session(paths) as connection:
        replay = _application_result(connection, change_set_id)
        if replay is not None:
            stored_digest = _revision_digest(connection, replay.revision_id)
            if revision_id != replay.revision_id:
                raise StaleRevisionError(
                    "application revision does not match",
                    details={"expected_revision_id": replay.revision_id},
                )
            if digest != stored_digest:
                raise WrongDigestError(
                    "application digest does not match",
                    details={"digest": stored_digest},
                )
            return replace(replay, idempotent_replay=True)

        view = _load_change_set(connection, change_set_id)
        if revision_id != view.revision_id:
            raise StaleRevisionError(
                "draft revision is stale",
                details={"expected_revision_id": view.revision_id},
            )
        if digest != view.digest:
            raise WrongDigestError(
                "draft digest does not match",
                details={"digest": view.digest},
            )
        if not isinstance(approval, OwnerApproval):
            raise OwnerApprovalRequiredError("direct owner approval is required")
        adapter = approval._consume(
            store_id=identity.store_id,
            change_set_id=change_set_id,
            revision_id=revision_id,
            digest=digest,
        )

        batch_sources = _batch_sources(connection, view.batch_id)
        _revalidate_complete_revision(connection, view, batch_sources)
        application_id = _new_id("app")
        approval_id = _new_id("apr")
        applied_at = int(time.time())
        connection.execute(
            "INSERT INTO approvals "
            "(approval_id, change_set_id, revision_id, digest, approved_at, adapter) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                approval_id,
                change_set_id,
                revision_id,
                digest,
                applied_at,
                adapter,
            ),
        )
        connection.execute(
            "INSERT INTO applications "
            "(application_id, change_set_id, revision_id, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (application_id, change_set_id, revision_id, applied_at),
        )
        memory_ids: list[str] = []
        item_lineages: dict[str, str] = {}
        for application_ordinal, item in enumerate(
            item for item in view.items if item.status == "active"
        ):
            memory_id = _new_id("mem")
            lineage_id = item.memory.target_lineage_id
            predecessor_id = item.memory.expected_head_id
            if lineage_id is None:
                lineage_id = _new_id("lin")
                connection.execute(
                    "INSERT INTO memory_lineages (lineage_id, created_at) VALUES (?, ?)",
                    (lineage_id, applied_at),
                )
            require_invariant(lineage_id is not None, label="applied item lineage")
            connection.execute(
                "INSERT INTO memory_revisions "
                "(revision_id, lineage_id, predecessor_id, kind, statement, "
                "occurred_on, valid_from, valid_to, recorded_at, tags_json, "
                "sensitivity, application_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    memory_id,
                    lineage_id,
                    predecessor_id,
                    item.memory.kind.value,
                    item.memory.statement,
                    item.memory.occurred_on,
                    item.memory.valid_from,
                    item.memory.valid_to,
                    applied_at,
                    _tags_json(item.memory.tags),
                    item.memory.sensitivity.value,
                    application_id,
                ),
            )
            for locator in item.evidence:
                _insert_memory_evidence(connection, memory_id, locator)
            if predecessor_id is None:
                connection.execute(
                    "INSERT INTO current_memory_heads (lineage_id, revision_id) "
                    "VALUES (?, ?)",
                    (lineage_id, memory_id),
                )
            else:
                updated = connection.execute(
                    "UPDATE current_memory_heads SET revision_id = ? "
                    "WHERE lineage_id = ? AND revision_id = ?",
                    (memory_id, lineage_id, predecessor_id),
                )
                if updated.rowcount != 1:
                    raise StaleHeadError("correction target is stale")
                connection.execute(
                    "DELETE FROM memory_fts WHERE revision_id = ?",
                    (predecessor_id,),
                )
            connection.execute(
                "INSERT INTO memory_fts (revision_id, statement, tags) "
                "VALUES (?, ?, ?)",
                (memory_id, item.memory.statement, " ".join(item.memory.tags)),
            )
            connection.execute(
                "INSERT INTO application_memories "
                "(application_id, memory_revision_id, ordinal) VALUES (?, ?, ?)",
                (application_id, memory_id, application_ordinal),
            )
            memory_ids.append(memory_id)
            item_lineages[item.item_id] = lineage_id
        touched, materialized = _materialize_guard_links(
            connection, view.guard_links, item_lineages, application_id
        )
        _revoke_guard_links(
            connection,
            view.revoked_guard_links,
            item_lineages,
            application_id,
            applied_at,
            materialized,
        )
        standing = _enforced_guard_violations(connection, touched)
        connection.execute(
            "UPDATE change_sets SET state = 'applied' WHERE change_set_id = ?",
            (change_set_id,),
        )
        return ApplicationResult(
            application_id=application_id,
            change_set_id=change_set_id,
            revision_id=revision_id,
            memory_ids=tuple(memory_ids),
            idempotent_replay=False,
            standing_guard_violations=standing,
        )


def _revalidate_complete_revision(
    connection: Connection,
    view: ChangeSetView,
    batch_sources: dict[str, _BatchSource],
) -> None:
    issues = _review_validation_issues(connection, view, batch_sources)
    if issues:
        raise issues[0].error


def _review_validation_issues(
    connection: Connection,
    view: ChangeSetView,
    batch_sources: dict[str, _BatchSource],
) -> tuple[_ReviewValidationIssue, ...]:
    """Return every deterministic blocker from the exact core apply checks."""
    issues: list[_ReviewValidationIssue] = []
    decisions = {decision.source_id: decision for decision in view.source_decisions}
    missing_source_ids = set(batch_sources) - set(decisions)
    unexpected_source_ids = set(decisions) - set(batch_sources)
    if missing_source_ids or unexpected_source_ids:
        accounting_error = IncompleteBatchError(
            "change-set revision does not account for every source",
            details={
                "count": len(batch_sources) - len(decisions),
                # A count says how much is missing; the identifiers say which,
                # and a batch holds at most 64 sources, so naming every one
                # stays bounded. Opaque ids only -- no filename, no text.
                "source_ids": sorted(missing_source_ids | unexpected_source_ids)[
                    :MAX_BATCH_SOURCE_IDS
                ],
            },
        )
        issues.extend(
            _ReviewValidationIssue(
                code="unaccounted_source",
                error=accounting_error,
                source_id=source.source_id,
            )
            for source in batch_sources.values()
            if source.source_id in missing_source_ids
        )
        issues.extend(
            _ReviewValidationIssue(
                code="invalid_review",
                error=accounting_error,
                source_id=decision.source_id,
            )
            for decision in view.source_decisions
            if decision.source_id in unexpected_source_ids
        )
    active_used = {
        locator.source_id
        for item in view.items
        if item.status == "active"
        for locator in item.evidence
    }
    for source_id, source in batch_sources.items():
        try:
            _revalidate_source(source)
        except StoreError as error:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=error,
                    source_id=source_id,
                )
            )
        decision = decisions.get(source_id)
        if decision is None:
            continue
        if decision.blob_digest != source.blob_digest:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=InvalidEvidenceError("source decision digest changed"),
                    source_id=source_id,
                )
            )
        if source_id in active_used:
            if decision.state != "used" or decision.reason is not None:
                issues.append(
                    _ReviewValidationIssue(
                        code="invalid_review",
                        error=IncompleteBatchError(
                            "used source accounting is inconsistent"
                        ),
                        source_id=source_id,
                    )
                )
        elif decision.state != "no_memory" or not decision.reason:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=IncompleteBatchError(
                        "no-memory source accounting is inconsistent"
                    ),
                    source_id=source_id,
                )
            )

    active_targets: dict[str, list[DraftItem]] = {}
    for item in view.items:
        if item.status not in {"active", "rejected"}:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=InvalidArgumentError("draft item status is invalid"),
                    item_id=item.item_id,
                )
            )
            continue
        target = item.memory.target_lineage_id if item.status == "active" else None
        if target is not None:
            active_targets.setdefault(target, []).append(item)

    for target, items in active_targets.items():
        if len(items) < 2:
            continue
        current_head = _current_head_id(connection, target)
        for item in items:
            issues.append(
                _ReviewValidationIssue(
                    code="duplicate_lineage_target",
                    error=InvalidArgumentError(
                        "draft has multiple successors for one lineage"
                    ),
                    item_id=item.item_id,
                    expected_head_id=item.memory.expected_head_id,
                    current_head_id=current_head,
                )
            )

    for item in view.items:
        if item.status != "active":
            continue
        if not item.evidence:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=InvalidEvidenceError("active memory has no evidence"),
                    item_id=item.item_id,
                )
            )
        else:
            try:
                expected = _normalize_evidence(
                    item.evidence,
                    batch_sources=batch_sources,
                    memory=item.memory,
                )
            except AmbiguousEvidenceError as error:
                issues.append(
                    _ReviewValidationIssue(
                        code="ambiguous_evidence",
                        error=error,
                        item_id=item.item_id,
                        source_id=_first_invalid_evidence_source_id(
                            item, batch_sources
                        ),
                    )
                )
            except StoreError as error:
                issues.append(
                    _ReviewValidationIssue(
                        code="invalid_review",
                        error=error,
                        item_id=item.item_id,
                        source_id=_first_invalid_evidence_source_id(
                            item, batch_sources
                        ),
                    )
                )
            else:
                if expected != item.evidence:
                    first_changed = next(
                        (
                            locator.source_id
                            for locator, normalized in zip(
                                item.evidence, expected, strict=True
                            )
                            if locator != normalized
                        ),
                        None,
                    )
                    issues.append(
                        _ReviewValidationIssue(
                            code="invalid_review",
                            error=InvalidEvidenceError("evidence locator changed"),
                            item_id=item.item_id,
                            source_id=first_changed,
                        )
                    )
        try:
            _validate_expected_head(connection, item.memory)
        except StaleHeadError as error:
            current_head = _current_head_id(connection, item.memory.target_lineage_id)
            issues.append(
                _ReviewValidationIssue(
                    code="stale_expected_head",
                    error=error,
                    item_id=item.item_id,
                    expected_head_id=item.memory.expected_head_id,
                    current_head_id=current_head,
                )
            )
        except StoreError as error:
            issues.append(
                _ReviewValidationIssue(
                    code="invalid_review",
                    error=error,
                    item_id=item.item_id,
                )
            )

    return tuple(issues)


def _current_head_id(connection: Connection, lineage_id: str | None) -> str | None:
    if lineage_id is None:
        return None
    row = connection.execute(
        "SELECT revision_id FROM current_memory_heads WHERE lineage_id = ?",
        (lineage_id,),
    ).fetchone()
    return None if row is None else str(row[0])


def _first_invalid_evidence_source_id(
    item: DraftItem,
    batch_sources: dict[str, _BatchSource],
) -> str | None:
    """Locate only the content-free source identity for a known evidence error."""
    for locator in item.evidence:
        try:
            _normalize_evidence(
                (locator,),
                batch_sources=batch_sources,
                memory=item.memory,
            )
        except StoreError:
            return locator.source_id
    return None


def _load_change_set(connection: Connection, change_set_id: str) -> ChangeSetView:
    return _load_change_set_revision(connection, change_set_id, None)


def _load_change_set_revision(
    connection: Connection,
    change_set_id: str,
    revision_id: str | None,
) -> ChangeSetView:
    if revision_id is None:
        row = connection.execute(
            "SELECT cs.batch_id, cs.state, csr.revision_id, csr.digest, "
            "csr.adapter_origin "
            "FROM change_sets AS cs "
            "JOIN change_set_revisions AS csr "
            "ON csr.change_set_id = cs.change_set_id "
            "WHERE cs.change_set_id = ? "
            "ORDER BY csr.rowid DESC LIMIT 1",
            (change_set_id,),
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT cs.batch_id, cs.state, csr.revision_id, csr.digest, "
            "csr.adapter_origin "
            "FROM change_sets AS cs "
            "JOIN change_set_revisions AS csr "
            "ON csr.change_set_id = cs.change_set_id "
            "WHERE cs.change_set_id = ? AND csr.revision_id = ?",
            (change_set_id, revision_id),
        ).fetchone()
    if row is None:
        raise NotFoundError("change-set identifier was not found")
    batch_id, state, revision_id, stored_digest = map(str, row[:4])
    try:
        adapter_origin = ChangeSetAdapterOrigin(str(row[4]))
    except ValueError as error:
        raise InvalidArgumentError("stored adapter origin is invalid") from error
    _verified_batch_roster(connection, batch_id)
    item_rows = connection.execute(
        "SELECT item_id, ordinal, status, kind, statement, occurred_on, "
        "valid_from, valid_to, tags_json, sensitivity, target_lineage_id, "
        "expected_head_id FROM change_items WHERE revision_id = ? ORDER BY ordinal",
        (revision_id,),
    ).fetchall()
    items = tuple(
        DraftItem(
            ordinal=int(item[1]),
            item_id=str(item[0]),
            status=str(item[2]),
            memory=MemoryFields(
                kind=MemoryKind(str(item[3])),
                statement=str(item[4]),
                occurred_on=None if item[5] is None else str(item[5]),
                valid_from=None if item[6] is None else str(item[6]),
                valid_to=None if item[7] is None else str(item[7]),
                tags=_parse_tags(item[8]),
                sensitivity=Sensitivity(str(item[9])),
                target_lineage_id=None if item[10] is None else str(item[10]),
                expected_head_id=None if item[11] is None else str(item[11]),
            ),
            evidence=_load_item_evidence(connection, revision_id, str(item[0])),
        )
        for item in item_rows
    )
    decision_rows = connection.execute(
        "SELECT d.ordinal, d.source_id, b.sha256, d.state, d.reason "
        "FROM batch_source_decisions AS d "
        "JOIN sources AS s ON s.source_id = d.source_id "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE d.revision_id = ? ORDER BY d.ordinal",
        (revision_id,),
    ).fetchall()
    decisions = tuple(
        SourceDecision(
            ordinal=int(decision[0]),
            source_id=str(decision[1]),
            blob_digest=str(decision[2]),
            state=str(decision[3]),
            reason=None if decision[4] is None else str(decision[4]),
        )
        for decision in decision_rows
    )
    guard_links = _load_guard_links(connection, revision_id)
    revoked_guard_links = _load_guard_revocations(connection, revision_id)
    store_row = connection.execute(
        "SELECT store_id FROM store_meta WHERE singleton = 1"
    ).fetchone()
    if store_row is None:
        raise InvalidArgumentError("Store identity is unavailable")
    payload = _digest_payload(
        store_id=str(store_row[0]),
        change_set_id=change_set_id,
        batch_id=batch_id,
        revision_id=revision_id,
        items=items,
        decisions=decisions,
        guard_links=guard_links,
        revoked_guard_links=revoked_guard_links,
    )
    encoded, computed_digest = canonical_digest(payload)
    _check_diff_size(encoded)
    if computed_digest != stored_digest:
        raise WrongDigestError(
            "stored change-set digest is inconsistent",
            details={"digest": stored_digest},
        )
    return ChangeSetView(
        change_set_id=change_set_id,
        batch_id=batch_id,
        state=state,
        revision_id=revision_id,
        digest=stored_digest,
        adapter_origin=adapter_origin,
        items=items,
        source_decisions=decisions,
        guard_links=tuple(
            _draft_guard_link(ordinal, link, items) for ordinal, link in guard_links
        ),
        revoked_guard_links=tuple(
            _draft_guard_link(ordinal, link, items)
            for ordinal, link in revoked_guard_links
        ),
        digest_payload=payload,
    )


def _load_guard_links(
    connection: Connection,
    revision_id: str,
) -> tuple[_NumberedGuardLink, ...]:
    """Load one revision's guard links, tolerating stores predating the table."""
    return _load_numbered_links(connection, "change_revision_guard_links", revision_id)


def _load_guard_revocations(
    connection: Connection,
    revision_id: str,
) -> tuple[_NumberedGuardLink, ...]:
    """Load one revision's revocations, tolerating stores predating the table."""
    return _load_numbered_links(
        connection, "change_revision_guard_revocations", revision_id
    )


def _load_numbered_links(
    connection: Connection,
    table: str,
    revision_id: str,
) -> tuple[_NumberedGuardLink, ...]:
    """Read one revision's endpoint pairs out of a draft guard table.

    Tolerating the absent table is what lets a read connection -- which never
    heals -- load a revision stored before that table existed, instead of
    failing a review the Store can still render completely.
    """
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is None
    ):
        return ()
    rows = connection.execute(
        "SELECT ordinal, guard_item_id, guard_lineage_id, governed_item_id, "
        f"governed_lineage_id FROM {table} "
        "WHERE revision_id = ? ORDER BY ordinal",
        (revision_id,),
    ).fetchall()
    return tuple(
        (
            int(row[0]),
            GuardLinkInput(
                guard_item_id=None if row[1] is None else str(row[1]),
                guard_lineage_id=None if row[2] is None else str(row[2]),
                governed_item_id=None if row[3] is None else str(row[3]),
                governed_lineage_id=None if row[4] is None else str(row[4]),
            ),
        )
        for row in rows
    )


def _validate_adapter_origin(adapter_origin: ChangeSetAdapterOrigin) -> None:
    if not isinstance(adapter_origin, ChangeSetAdapterOrigin):
        raise InvalidArgumentError("change-set adapter origin is invalid")


def _insert_revision_rows(
    connection: Connection,
    revision_id: str,
    items: tuple[DraftItem, ...],
    decisions: tuple[SourceDecision, ...],
    guard_links: tuple[_NumberedGuardLink, ...],
    revoked_guard_links: tuple[_NumberedGuardLink, ...],
) -> None:
    for item in items:
        connection.execute(
            "INSERT INTO change_items "
            "(revision_id, item_id, ordinal, status, kind, statement, occurred_on, "
            "valid_from, valid_to, tags_json, sensitivity, target_lineage_id, "
            "expected_head_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                revision_id,
                item.item_id,
                item.ordinal,
                item.status,
                item.memory.kind.value,
                item.memory.statement,
                item.memory.occurred_on,
                item.memory.valid_from,
                item.memory.valid_to,
                _tags_json(item.memory.tags),
                item.memory.sensitivity.value,
                item.memory.target_lineage_id,
                item.memory.expected_head_id,
            ),
        )
        for locator in item.evidence:
            connection.execute(
                "INSERT INTO change_item_evidence "
                "(revision_id, item_id, ordinal, source_id, blob_digest, mode, "
                "char_start, char_end, excerpt, source_level) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    revision_id,
                    item.item_id,
                    locator.ordinal,
                    locator.source_id,
                    locator.blob_digest,
                    locator.mode,
                    locator.char_start,
                    locator.char_end,
                    locator.excerpt,
                    None if locator.source_level is None else int(locator.source_level),
                ),
            )
    for decision in decisions:
        connection.execute(
            "INSERT INTO batch_source_decisions "
            "(revision_id, source_id, ordinal, state, reason) VALUES (?, ?, ?, ?, ?)",
            (
                revision_id,
                decision.source_id,
                decision.ordinal,
                decision.state,
                decision.reason,
            ),
        )
    for table, entries in (
        ("change_revision_guard_links", guard_links),
        ("change_revision_guard_revocations", revoked_guard_links),
    ):
        for ordinal, link in entries:
            connection.execute(
                f"INSERT INTO {table} "
                "(revision_id, ordinal, guard_item_id, guard_lineage_id, "
                "governed_item_id, governed_lineage_id) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    revision_id,
                    ordinal,
                    link.guard_item_id,
                    link.guard_lineage_id,
                    link.governed_item_id,
                    link.governed_lineage_id,
                ),
            )


def _load_item_evidence(
    connection: Connection,
    revision_id: str,
    item_id: str,
) -> tuple[EvidenceLocator, ...]:
    rows = connection.execute(
        "SELECT ordinal, source_id, blob_digest, mode, char_start, char_end, "
        "excerpt, source_level FROM change_item_evidence "
        "WHERE revision_id = ? AND item_id = ? ORDER BY ordinal",
        (revision_id, item_id),
    ).fetchall()
    return tuple(_locator_from_row(row) for row in rows)


def _locator_from_row(row: Row) -> EvidenceLocator:
    return EvidenceLocator(
        ordinal=int(row[0]),
        source_id=str(row[1]),
        blob_digest=str(row[2]),
        mode=str(row[3]),
        char_start=None if row[4] is None else int(row[4]),
        char_end=None if row[5] is None else int(row[5]),
        excerpt=None if row[6] is None else str(row[6]),
        source_level=None if row[7] is None else bool(row[7]),
    )


class _BatchSource:
    __slots__ = (
        "blob_digest",
        "effective_sensitivity",
        "ordinal",
        "original_bytes",
        "source_id",
        "text_evidence_eligible",
        "utf8_text",
    )

    def __init__(
        self,
        *,
        source_id: str,
        ordinal: int,
        blob_digest: str,
        original_bytes: bytes,
        utf8_text: str | None,
        text_evidence_eligible: bool,
        effective_sensitivity: Sensitivity,
    ) -> None:
        self.source_id = source_id
        self.ordinal = ordinal
        self.blob_digest = blob_digest
        self.original_bytes = original_bytes
        self.utf8_text = utf8_text
        self.text_evidence_eligible = text_evidence_eligible
        self.effective_sensitivity = effective_sensitivity


def _batch_sources(
    connection: Connection,
    batch_id: str,
) -> dict[str, _BatchSource]:
    roster = _verified_batch_roster(connection, batch_id)
    rows = connection.execute(
        "SELECT s.source_id, membership.ordinal, b.sha256, b.original_bytes, "
        "b.utf8_text, s.media_type, "
        "(SELECT MAX(CASE effective.sensitivity WHEN 'normal' THEN 0 "
        "WHEN 'sensitive' THEN 1 WHEN 'restricted' THEN 2 END) "
        "FROM sources AS effective WHERE effective.blob_id = s.blob_id) "
        "FROM inbox_batch_sources AS membership "
        "JOIN sources AS s ON s.source_id = membership.source_id "
        "JOIN source_blobs AS b ON b.blob_id = s.blob_id "
        "WHERE membership.batch_id = ? ORDER BY membership.ordinal",
        (batch_id,),
    ).fetchall()
    sources = {
        str(row[0]): _BatchSource(
            source_id=str(row[0]),
            ordinal=int(row[1]),
            blob_digest=str(row[2]),
            original_bytes=bytes(row[3]),
            utf8_text=None if row[4] is None else str(row[4]),
            text_evidence_eligible=(
                str(row[5]) in SEARCHABLE_MEDIA_TYPES and row[4] is not None
            ),
            effective_sensitivity=sensitivity_from_rank(int(row[6])),
        )
        for row in rows
    }
    if (
        tuple((source.source_id, source.ordinal) for source in sources.values())
        != roster
    ):
        raise IncompleteBatchError("sealed batch roster is inconsistent")
    return sources


def _verified_batch_roster(
    connection: Connection,
    batch_id: str,
) -> tuple[tuple[str, int], ...]:
    batch_row = connection.execute(
        "SELECT source_count FROM inbox_batches WHERE batch_id = ?",
        (batch_id,),
    ).fetchone()
    if batch_row is None:
        raise NotFoundError("batch identifier was not found")
    source_count = int(batch_row[0])
    source_ids = {
        str(row[0])
        for row in connection.execute(
            "SELECT source_id FROM sources WHERE batch_id = ?",
            (batch_id,),
        ).fetchall()
    }
    membership_rows = connection.execute(
        "SELECT membership.source_id, membership.ordinal, source.batch_id "
        "FROM inbox_batch_sources AS membership "
        "LEFT JOIN sources AS source ON source.source_id = membership.source_id "
        "WHERE membership.batch_id = ? ORDER BY membership.ordinal",
        (batch_id,),
    ).fetchall()
    roster = tuple((str(row[0]), int(row[1])) for row in membership_rows)
    membership_ids = {source_id for source_id, _ordinal in roster}
    ordinals = tuple(ordinal for _source_id, ordinal in roster)
    if (
        source_count != len(source_ids)
        or source_count != len(roster)
        or membership_ids != source_ids
        or ordinals != tuple(range(source_count))
        or any(row[2] is None or str(row[2]) != batch_id for row in membership_rows)
    ):
        raise IncompleteBatchError("sealed batch roster is inconsistent")
    return roster


def _normalize_memory(
    connection: Connection,
    raw: MemoryFields,
) -> MemoryFields:
    if not isinstance(raw, MemoryFields):
        raise InvalidArgumentError("memory fields are invalid")
    try:
        kind = MemoryKind(raw.kind)
        sensitivity = Sensitivity(raw.sensitivity)
    except (TypeError, ValueError) as error:
        raise InvalidArgumentError("memory enum is invalid") from error
    statement = _bounded_string(
        raw.statement,
        maximum=MAX_STATEMENT_BYTES,
        label="memory statement",
        strip=True,
    )
    occurred_on = _validate_partial_date(raw.occurred_on, "occurred_on")
    valid_from = _validate_partial_date(raw.valid_from, "valid_from")
    valid_to = _validate_partial_date(raw.valid_to, "valid_to")
    if valid_from is not None and valid_to is not None:
        if partial_date_bounds(valid_from)[0] > partial_date_bounds(valid_to)[1]:
            raise InvalidArgumentError("memory validity interval is invalid")
    tags = _normalize_tags(raw.tags)
    target = raw.target_lineage_id
    expected = raw.expected_head_id
    if (target is None) != (expected is None):
        raise InvalidArgumentError("correction target and expected head must pair")
    if target is not None:
        _validate_opaque_id(target)
        assert expected is not None
        _validate_opaque_id(expected)
        lineage = connection.execute(
            "SELECT revision_id FROM current_memory_heads WHERE lineage_id = ?",
            (target,),
        ).fetchone()
        if lineage is None:
            raise NotFoundError("target lineage was not found")
        if str(lineage[0]) != expected:
            raise StaleHeadError(
                "correction target is stale",
                details={"expected_revision_id": str(lineage[0])},
            )
    return MemoryFields(
        kind=kind,
        statement=statement,
        occurred_on=occurred_on,
        valid_from=valid_from,
        valid_to=valid_to,
        tags=tags,
        sensitivity=sensitivity,
        target_lineage_id=target,
        expected_head_id=expected,
    )


def _normalize_evidence(
    raw_evidence: Sequence[EvidenceInput | EvidenceLocator],
    *,
    batch_sources: dict[str, _BatchSource],
    memory: MemoryFields,
) -> tuple[EvidenceLocator, ...]:
    if (
        isinstance(raw_evidence, (str, bytes))
        or not isinstance(raw_evidence, Sequence)
        or not 1 <= len(raw_evidence) <= MAX_EVIDENCE_PER_ITEM
    ):
        raise InvalidEvidenceError("memory evidence count is invalid")
    locators: list[EvidenceLocator] = []
    identities: set[tuple[object, ...]] = set()
    for ordinal, raw in enumerate(raw_evidence):
        if not isinstance(raw, (EvidenceInput, EvidenceLocator)):
            raise InvalidEvidenceError("memory evidence is invalid")
        _validate_opaque_id(raw.source_id)
        _validate_digest(raw.blob_digest, evidence=True)
        source = _require_batch_source(batch_sources, raw.source_id)
        _revalidate_source(source)
        if raw.blob_digest != source.blob_digest:
            raise InvalidEvidenceError("evidence blob digest does not match")
        if raw.source_level is True:
            if raw.excerpt is not None or source.text_evidence_eligible:
                raise InvalidEvidenceError("source-level evidence is invalid")
            locator = EvidenceLocator(
                ordinal=ordinal,
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                mode="source_level",
                char_start=None,
                char_end=None,
                excerpt=None,
                source_level=True,
            )
        else:
            if (
                raw.source_level not in (None, False)
                or not source.text_evidence_eligible
            ):
                raise InvalidEvidenceError("text evidence is invalid")
            excerpt = _bounded_string(
                raw.excerpt,
                maximum=MAX_EVIDENCE_EXCERPT_BYTES,
                label="evidence excerpt",
                strip=False,
            )
            text = source.utf8_text
            if text is None:
                raise InvalidEvidenceError("source has no retained UTF-8 text")
            starts = _occurrences(text, excerpt)
            if not starts:
                raise InvalidEvidenceError("evidence excerpt was not found")
            if len(starts) != 1:
                raise AmbiguousEvidenceError("evidence excerpt is ambiguous")
            start = starts[0]
            locator = EvidenceLocator(
                ordinal=ordinal,
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                mode="text",
                char_start=start,
                char_end=start + len(excerpt),
                excerpt=excerpt,
                source_level=None,
            )
        identity = (
            locator.source_id,
            locator.blob_digest,
            locator.mode,
            locator.char_start,
            locator.char_end,
            locator.excerpt,
            locator.source_level,
        )
        if identity in identities:
            raise InvalidEvidenceError("duplicate evidence locator")
        identities.add(identity)
        locators.append(locator)
        if (
            SENSITIVITY_RANK[memory.sensitivity]
            < SENSITIVITY_RANK[source.effective_sensitivity]
        ):
            raise InvalidEvidenceError("memory sensitivity is below its evidence")
    return tuple(locators)


def _validate_active_targets(items: list[DraftItem]) -> None:
    targets: set[str] = set()
    for item in items:
        if item.status not in {"active", "rejected"}:
            raise InvalidArgumentError("draft item status is invalid")
        target = item.memory.target_lineage_id
        if item.status == "active" and target is not None:
            if target in targets:
                raise InvalidArgumentError(
                    "draft has multiple successors for one lineage",
                    details={
                        "client_item_id": item.item_id,
                        "governed_lineage_id": target,
                    },
                )
            targets.add(target)


def _edit_locators(ordinal: int, edit: ChangeEdit) -> dict[str, object]:
    """Name the one edit a batch refusal came from, content-free.

    One call carries up to 256 operations, so a refusal naming only its code
    leaves the caller bisecting. Both values are already the caller's own: the
    position it supplied and the opaque identifier it chose. A draft item id is
    the same namespace as the `client_item_id` that created it, so the two
    share one key rather than splitting a locator by which operation raised.

    The identifier is echoed only when it is a well-formed opaque id, which is
    the same bound the sibling at the MCP parse boundary applies and the same
    one the error-details schema declares for these two keys. The refusal being
    wrapped is frequently that the identifier is not one -- too long, empty, or
    carrying a lone surrogate -- and `_tool_failure` copies these details
    verbatim, so echoing it unchecked publishes a value the envelope's own
    declared schema rejects. Dropping it costs the caller nothing it does not
    already have: the ordinal still names the operation, and the identifier it
    sent is the identifier it sent.
    """
    locators: dict[str, object] = {"ordinal": ordinal}
    named: tuple[str, str] | None = None
    if isinstance(edit, AddItem):
        named = ("client_item_id", edit.client_item_id)
    elif isinstance(edit, ReplaceItem | RejectItem | RestoreItem):
        named = ("client_item_id", edit.item_id)
    elif isinstance(edit, SetSourceNoMemory | ClearSourceNoMemory):
        named = ("source_id", edit.source_id)
    if named is not None:
        key, value = named
        try:
            _validate_opaque_id(value)
        except InvalidArgumentError:
            return locators
        locators[key] = value
    return locators


def _validated_guard_link(link: GuardLinkInput) -> GuardLinkInput:
    """Require one well-formed item-or-lineage endpoint on each guard-link side."""
    if not isinstance(link, GuardLinkInput):
        raise InvalidArgumentError("guard link is invalid")
    for item_ref, lineage_ref in (
        (link.guard_item_id, link.guard_lineage_id),
        (link.governed_item_id, link.governed_lineage_id),
    ):
        endpoint = item_ref if item_ref is not None else lineage_ref
        if endpoint is None or (item_ref is not None and lineage_ref is not None):
            raise InvalidArgumentError("guard link endpoint must name item or lineage")
        _validate_opaque_id(endpoint)
    return link


def _derived_link_status(link: GuardLinkInput, items: Sequence[DraftItem]) -> str:
    """Derive one link's review status from the statuses of its draft endpoints."""
    statuses = {item.item_id: item.status for item in items}
    for item_ref in (link.guard_item_id, link.governed_item_id):
        if item_ref is not None and statuses.get(item_ref) == "rejected":
            return "rejected"
    return "active"


def _draft_guard_link(
    ordinal: int,
    link: GuardLinkInput,
    items: Sequence[DraftItem],
) -> DraftGuardLink:
    """Derive one stored link's reviewable view, status included."""
    return DraftGuardLink(
        ordinal=ordinal,
        guard_item_id=link.guard_item_id,
        guard_lineage_id=link.guard_lineage_id,
        governed_item_id=link.governed_item_id,
        governed_lineage_id=link.governed_lineage_id,
        status=_derived_link_status(link, items),
    )


def _resolved_endpoint(
    lineage_ref: str | None,
    item_ref: str | None,
    item_lineages: Mapping[str, str],
) -> str | None:
    """Resolve one guard-link side to its lineage, or None when it cannot be."""
    if lineage_ref is not None:
        return lineage_ref
    if item_ref is None:
        return None
    return item_lineages.get(item_ref)


def _link_input(link: DraftGuardLink) -> GuardLinkInput:
    """Read one stored draft entry back as the endpoint pair that authored it."""
    return GuardLinkInput(
        guard_item_id=link.guard_item_id,
        guard_lineage_id=link.guard_lineage_id,
        governed_item_id=link.governed_item_id,
        governed_lineage_id=link.governed_lineage_id,
    )


def _draft_item_lineages(items: Sequence[DraftItem]) -> dict[str, str]:
    """Map every correcting draft item to the lineage it already targets."""
    return {
        item.item_id: item.memory.target_lineage_id
        for item in items
        if item.memory.target_lineage_id is not None
    }


def _validate_endpoints(
    connection: Connection,
    link: GuardLinkInput,
    item_ids: set[str],
) -> None:
    """Require both sides to name something the draft or the Store can resolve.

    These run after the per-edit dispatch loop, so they are outside the wrapper
    that names which operation failed -- and guard links are the family an
    agent submits in bulk, up to `MAX_GUARD_LINKS` of them. Each refusal
    therefore names the endpoint it could not resolve, using the caller's own
    opaque identifier and nothing else.
    """
    for item_ref in (link.guard_item_id, link.governed_item_id):
        if item_ref is not None and item_ref not in item_ids:
            raise InvalidArgumentError(
                "guard link names a missing draft item",
                details={"client_item_id": item_ref},
            )
    for side, lineage_ref in (
        ("guard_lineage_id", link.guard_lineage_id),
        ("governed_lineage_id", link.governed_lineage_id),
    ):
        if lineage_ref is not None and (
            _current_head_id(connection, lineage_ref) is None
        ):
            raise InvalidArgumentError(
                "guard link names an unknown lineage",
                details={side: lineage_ref},
            )
    if link.guard_item_id is not None and link.guard_item_id == link.governed_item_id:
        raise InvalidArgumentError(
            "guard link cannot be a self-link",
            details={"client_item_id": link.guard_item_id},
        )
    if (
        link.guard_lineage_id is not None
        and link.guard_lineage_id == link.governed_lineage_id
    ):
        raise InvalidArgumentError(
            "guard link cannot be a self-link",
            details={
                "governed_lineage_id": link.governed_lineage_id,
                "guard_lineage_id": link.guard_lineage_id,
            },
        )


def _validate_guard_links(
    connection: Connection,
    links: Sequence[GuardLinkInput],
    items: Sequence[DraftItem],
) -> set[tuple[str, str]]:
    """Require every guard-link endpoint to resolve inside the draft or the Store.

    Returns the lineage pairs the active links resolve to, so a revocation in
    the same revision can be refused for naming one of them.
    """
    item_ids = {item.item_id for item in items}
    targets = _draft_item_lineages(items)
    resolved: set[tuple[str, str]] = set()
    for link in links:
        _validate_endpoints(connection, link, item_ids)
        if _derived_link_status(link, items) != "active":
            continue
        pair = _cross_form_pair(link, targets)
        if pair is not None:
            _reject_resolved_conflict(pair, resolved)
            resolved.add(pair)
    return resolved


def _validate_guard_revocations(
    connection: Connection,
    revocations: Sequence[GuardLinkInput],
    items: Sequence[DraftItem],
    linked_pairs: set[tuple[str, str]],
) -> None:
    """Require every revocation to name one retained link.

    Revoking a link that was never applied is a mistake worth reporting rather
    than a no-op, and a pair this same revision also proposes is a revision
    that contradicts itself -- whichever order apply chose would be a coin
    toss the owner never reviewed. A pair the Store already holds as revoked
    is different: revocation is final for that exact pair, so the carried
    intent is satisfied, and refusing it would wedge a draft whose parallel
    reviewer revoked the same pair first -- one batch gets exactly one change
    set, and no edit operation can remove a carried revocation.
    """
    item_ids = {item.item_id for item in items}
    targets = _draft_item_lineages(items)
    resolved: set[tuple[str, str]] = set()
    for link in revocations:
        _validate_endpoints(connection, link, item_ids)
        if _derived_link_status(link, items) != "active":
            continue
        pair = _cross_form_pair(link, targets)
        if pair is None:
            # A draft item that opens a new lineage cannot name a retained
            # link: the lineage it will create does not exist yet. Named like
            # every other refusal in this family -- the endpoint that failed to
            # resolve, using the caller's own opaque identifier -- because this
            # phase runs after the dispatch loop that attaches ordinals, and a
            # revocation batch may carry up to `MAX_GUARD_LINKS` entries.
            raise InvalidArgumentError(
                "guard link revocation must name lineages the Store already holds",
                details=_unresolved_endpoint_details(link, targets),
            )
        _reject_resolved_conflict(pair, resolved)
        resolved.add(pair)
        details = {
            "guard_lineage_id": pair[0],
            "governed_lineage_id": pair[1],
        }
        if pair in linked_pairs:
            raise InvalidArgumentError(
                "guard link cannot be added and revoked by one revision",
                details=details,
            )
        if _retained_link_state(connection, pair) == "absent":
            raise InvalidArgumentError(
                "guard link revocation names no retained live link", details=details
            )


def _unresolved_endpoint_details(
    link: GuardLinkInput,
    item_lineages: Mapping[str, str],
) -> dict[str, object]:
    """Name the side of one link that did not resolve to a lineage."""
    for item_ref, lineage_ref in (
        (link.guard_item_id, link.guard_lineage_id),
        (link.governed_item_id, link.governed_lineage_id),
    ):
        if (
            lineage_ref is None
            and item_ref is not None
            and item_ref not in item_lineages
        ):
            return {"client_item_id": item_ref}
    return {}


def _retained_link_state(
    connection: Connection,
    pair: tuple[str, str],
) -> Literal["absent", "live", "revoked"]:
    """Report how the canonical table currently holds one resolved lineage pair."""
    if not guard_revocations_recorded(connection):
        # Reachable only inside a writer session that has already healed the
        # table, so this guards a genuinely impossible read rather than a
        # tolerated one; a store without the columns holds no revoked link.
        raise InvalidArgumentError("Store cannot record a guard-link revocation")
    row = connection.execute(
        "SELECT revoked_at FROM memory_guard_links "
        "WHERE guard_lineage_id = ? AND governed_lineage_id = ?",
        pair,
    ).fetchone()
    if row is None:
        return "absent"
    return "live" if row[0] is None else "revoked"


def _cross_form_pair(
    link: GuardLinkInput | DraftGuardLink,
    item_lineages: Mapping[str, str],
) -> tuple[str, str] | None:
    """Resolve one link to its lineage pair, or None while a side is unknowable."""
    guard = _resolved_endpoint(link.guard_lineage_id, link.guard_item_id, item_lineages)
    governed = _resolved_endpoint(
        link.governed_lineage_id, link.governed_item_id, item_lineages
    )
    if guard is None or governed is None:
        return None
    return guard, governed


def _reject_resolved_conflict(
    pair: tuple[str, str],
    resolved: set[tuple[str, str]],
) -> None:
    """Refuse a lineage pair that governs itself or repeats within one review."""
    guard_lineage_id, governed_lineage_id = pair
    details = {
        "guard_lineage_id": guard_lineage_id,
        "governed_lineage_id": governed_lineage_id,
    }
    if guard_lineage_id == governed_lineage_id:
        raise InvalidArgumentError(
            "guard link cannot govern its own lineage", details=details
        )
    if pair in resolved:
        raise InvalidArgumentError(
            "guard link is duplicated after resolution", details=details
        )


def _materialize_guard_links(
    connection: Connection,
    guard_links: Sequence[DraftGuardLink],
    item_lineages: Mapping[str, str],
    application_id: str,
) -> tuple[set[str], set[tuple[str, str]]]:
    """Record every active link as a lineage pair; report touched and resolved."""
    resolved: set[tuple[str, str]] = set()
    governed_counts: dict[str, int] = {}
    for link in guard_links:
        if link.status != "active":
            continue
        pair = _cross_form_pair(link, item_lineages)
        if pair is None:
            continue
        _reject_resolved_conflict(pair, resolved)
        resolved.add(pair)
        state = _retained_link_state(connection, pair)
        if state == "revoked":
            # INSERT OR IGNORE would silently do nothing here and leave the
            # link revoked, so an owner who approved "add this guard link"
            # would get no link and no word of it. Revocation is final for the
            # exact pair; say so instead.
            raise InvalidArgumentError(
                "guard link was revoked and cannot be re-added",
                details={
                    "guard_lineage_id": pair[0],
                    "governed_lineage_id": pair[1],
                },
            )
        _reject_guard_link_overflow(
            connection, pair, governed_counts, retained=state == "live"
        )
        connection.execute(
            "INSERT OR IGNORE INTO memory_guard_links "
            "(guard_lineage_id, governed_lineage_id, application_id) "
            "VALUES (?, ?, ?)",
            (pair[0], pair[1], application_id),
        )
    touched = set(item_lineages.values())
    touched.update(lineage_id for pair in resolved for lineage_id in pair)
    return touched, resolved


def _revoke_guard_links(
    connection: Connection,
    revocations: Sequence[DraftGuardLink],
    item_lineages: Mapping[str, str],
    application_id: str,
    revoked_at: int,
    materialized: set[tuple[str, str]],
) -> set[tuple[str, str]]:
    """Stamp every active revocation onto its retained row, or refuse the apply.

    Runs after materialization and before the violation scan, inside the one
    apply transaction: a revoked link leaves the scan entirely, which is how
    revoking a mis-attached guard clears a standing violation.
    """
    resolved: set[tuple[str, str]] = set()
    for link in revocations:
        if link.status != "active":
            continue
        pair = _cross_form_pair(link, item_lineages)
        details = (
            None
            if pair is None
            else {
                "guard_lineage_id": pair[0],
                "governed_lineage_id": pair[1],
            }
        )
        if pair is None or pair in materialized:
            raise InvalidArgumentError(
                "guard link revocation does not resolve to a retained link",
                details=details,
            )
        _reject_resolved_conflict(pair, resolved)
        resolved.add(pair)
        updated = connection.execute(
            "UPDATE memory_guard_links "
            "SET revoked_at = ?, revoking_application_id = ? "
            "WHERE guard_lineage_id = ? AND governed_lineage_id = ? "
            "AND revoked_at IS NULL",
            (revoked_at, application_id, pair[0], pair[1]),
        )
        if updated.rowcount != 1:
            # Revocation is final for the exact pair: a row another applied
            # revision already stamped satisfies this revocation, and the
            # first stamp stays. Only a pair the table does not retain at all
            # is a refusal.
            if _retained_link_state(connection, pair) == "revoked":
                continue
            raise InvalidArgumentError(
                "guard link revocation names no retained live link", details=details
            )
    return resolved


def _reject_guard_link_overflow(
    connection: Connection,
    pair: tuple[str, str],
    governed_counts: dict[str, int],
    *,
    retained: bool,
) -> None:
    """Refuse a link that would push one claim past its retained guard ceiling.

    Re-proposing a pair the table already holds is add-only, so only genuinely
    new rows count toward the cap. A revoked row does not count either: the cap
    exists to keep the wire's `guards` maxItems honest, and `guards` carries
    only links that still govern, so a link that no longer attaches to anything
    cannot overflow the array the cap protects. Counting it would let one
    mis-attachment consume a slot on that claim forever, which is exactly the
    failure revocation exists to undo. This is the sole enforcement point for
    that bound: any future path that writes memory_guard_links rows outside
    `_materialize_guard_links` bypasses it.
    """
    governed_lineage_id = pair[1]
    if governed_lineage_id not in governed_counts:
        governed_counts[governed_lineage_id] = int(
            connection.execute(
                "SELECT count(*) FROM memory_guard_links "
                "WHERE governed_lineage_id = ? AND revoked_at IS NULL",
                (governed_lineage_id,),
            ).fetchone()[0]
        )
    if retained:
        return
    governed_counts[governed_lineage_id] += 1
    if governed_counts[governed_lineage_id] > MAX_GUARDS_PER_LINEAGE:
        raise InvalidArgumentError(
            "guard links on one claim exceed the per-lineage limit",
            details={"governed_lineage_id": governed_lineage_id},
        )


def _enforced_guard_violations(
    connection: Connection,
    touched: set[str],
) -> tuple[GuardViolation, ...]:
    """Block a violation this application touched; report the rest as standing."""
    standing: list[GuardViolation] = []
    for violation in _guard_violations(connection):
        if (
            violation.guard_lineage_id in touched
            or violation.governed_lineage_id in touched
        ):
            raise InvalidArgumentError(
                "guard sensitivity exceeds a governed claim it must accompany; "
                "lower the guard's sensitivity or raise the claim's",
                details={
                    "guard_lineage_id": violation.guard_lineage_id,
                    "guard_sensitivity": violation.guard_sensitivity.value,
                    "governed_lineage_id": violation.governed_lineage_id,
                    "governed_sensitivity": violation.governed_sensitivity.value,
                },
            )
        standing.append(violation)
    return tuple(standing)


def _guard_violations(connection: Connection) -> tuple[GuardViolation, ...]:
    """Report every materialized guard more sensitive than a claim it governs."""
    # Writer-session-only: every writer BEGIN heals the guard tables additively, so
    # the table and its revocation columns are guaranteed present here and need
    # no sqlite_master or PRAGMA tolerance. A revoked link is excluded because a
    # link that no longer governs cannot be a violation -- which is precisely how
    # revoking a mis-attached guard clears a standing one.
    ranks: dict[str, int] = {}
    violations: list[GuardViolation] = []
    rows = connection.execute(
        "SELECT guard_lineage_id, governed_lineage_id FROM memory_guard_links "
        "WHERE revoked_at IS NULL "
        "ORDER BY guard_lineage_id, governed_lineage_id"
    ).fetchall()
    for row in rows:
        guard_lineage_id = str(row[0])
        governed_lineage_id = str(row[1])
        guard_rank = _effective_lineage_rank(connection, guard_lineage_id, ranks)
        governed_rank = _effective_lineage_rank(connection, governed_lineage_id, ranks)
        if guard_rank > governed_rank:
            violations.append(
                GuardViolation(
                    guard_lineage_id=guard_lineage_id,
                    governed_lineage_id=governed_lineage_id,
                    guard_sensitivity=sensitivity_from_rank(guard_rank),
                    governed_sensitivity=sensitivity_from_rank(governed_rank),
                )
            )
    return tuple(violations)


def _effective_lineage_rank(
    connection: Connection,
    lineage_id: str,
    ranks: dict[str, int],
) -> int:
    """Rank one lineage's current head with its cited sources folded in."""
    cached = ranks.get(lineage_id)
    if cached is not None:
        return cached
    row = connection.execute(_LINEAGE_EFFECTIVE_RANK_SQL, (lineage_id,)).fetchone()
    if row is None:
        raise InvalidArgumentError("memory lineage has no current head")
    rank = int(row[0])
    ranks[lineage_id] = rank
    return rank


def _validate_expected_head(connection: Connection, memory: MemoryFields) -> None:
    if memory.target_lineage_id is None:
        if memory.expected_head_id is not None:
            raise InvalidArgumentError("new lineage has an expected head")
        return
    row = connection.execute(
        "SELECT revision_id FROM current_memory_heads WHERE lineage_id = ?",
        (memory.target_lineage_id,),
    ).fetchone()
    if row is None or str(row[0]) != memory.expected_head_id:
        details = None if row is None else {"expected_revision_id": str(row[0])}
        raise StaleHeadError("correction target is stale", details=details)


def _revalidate_source(source: _BatchSource) -> None:
    if hashlib.sha256(source.original_bytes).hexdigest() != source.blob_digest:
        raise InvalidEvidenceError("retained source digest is inconsistent")
    if source.utf8_text is not None:
        try:
            encoded = source.utf8_text.encode("utf-8")
        except UnicodeError as error:
            raise InvalidEvidenceError("retained UTF-8 evidence is invalid") from error
        if encoded != source.original_bytes:
            raise InvalidEvidenceError("retained UTF-8 evidence changed")


def _digest_payload(
    *,
    store_id: str,
    change_set_id: str,
    batch_id: str,
    revision_id: str,
    items: tuple[DraftItem, ...],
    decisions: tuple[SourceDecision, ...],
    guard_links: tuple[_NumberedGuardLink, ...],
    revoked_guard_links: tuple[_NumberedGuardLink, ...],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "format": DIGEST_FORMAT,
        "store_id": store_id,
        "change_set_id": change_set_id,
        "batch_id": batch_id,
        "revision_id": revision_id,
        "source_decisions": [
            {
                "ordinal": decision.ordinal,
                "source_id": decision.source_id,
                "blob_digest": decision.blob_digest,
                "state": decision.state,
                "reason": decision.reason,
            }
            for decision in decisions
        ],
        "items": [
            {
                "ordinal": item.ordinal,
                "item_id": item.item_id,
                "status": item.status,
                "target_lineage_id": item.memory.target_lineage_id,
                "expected_head_id": item.memory.expected_head_id,
                "memory": {
                    "kind": item.memory.kind.value,
                    "statement": item.memory.statement,
                    "occurred_on": item.memory.occurred_on,
                    "valid_from": item.memory.valid_from,
                    "valid_to": item.memory.valid_to,
                    "tags": list(item.memory.tags),
                    "sensitivity": item.memory.sensitivity.value,
                },
                "evidence": [
                    {
                        "ordinal": locator.ordinal,
                        "source_id": locator.source_id,
                        "blob_digest": locator.blob_digest,
                        "mode": locator.mode,
                        "char_start": locator.char_start,
                        "char_end": locator.char_end,
                        "excerpt": locator.excerpt,
                        "source_level": locator.source_level,
                    }
                    for locator in item.evidence
                ],
            }
            for item in items
        ],
    }
    # Two separate conditional keys, each present only when the revision
    # carries that kind of entry. The Store recomputes and re-verifies a
    # stored revision's digest on every load, so a key that appeared
    # unconditionally -- even as an empty array -- would change the recomputed
    # digest of every revision that predates it and fail each one permanently
    # as `wrong_digest`. Revocations get their own key rather than an `intent`
    # field on `guard_links` for the same reason read the other way: an added
    # field would move the payload of every revision carrying an ordinary link.
    if guard_links:
        payload["guard_links"] = _guard_link_payloads(guard_links)
    if revoked_guard_links:
        payload["revoked_guard_links"] = _guard_link_payloads(revoked_guard_links)
    return payload


def _guard_link_payloads(
    links: tuple[_NumberedGuardLink, ...],
) -> list[dict[str, object]]:
    """Encode one numbered link array exactly as both digest keys carry it."""
    return [
        {
            "ordinal": ordinal,
            "guard_item_id": link.guard_item_id,
            "guard_lineage_id": link.guard_lineage_id,
            "governed_item_id": link.governed_item_id,
            "governed_lineage_id": link.governed_lineage_id,
        }
        for ordinal, link in links
    ]


def _application_result(
    connection: Connection,
    change_set_id: str,
) -> ApplicationResult | None:
    row = connection.execute(
        "SELECT application_id, revision_id FROM applications WHERE change_set_id = ?",
        (change_set_id,),
    ).fetchone()
    if row is None:
        return None
    memory_ids = tuple(
        str(memory[0])
        for memory in connection.execute(
            "SELECT memory_revision_id FROM application_memories "
            "WHERE application_id = ? ORDER BY ordinal",
            (str(row[0]),),
        ).fetchall()
    )
    return ApplicationResult(
        application_id=str(row[0]),
        change_set_id=change_set_id,
        revision_id=str(row[1]),
        memory_ids=memory_ids,
        idempotent_replay=False,
        standing_guard_violations=_guard_violations(connection),
    )


def _revision_digest(connection: Connection, revision_id: str) -> str:
    row = connection.execute(
        "SELECT digest FROM change_set_revisions WHERE revision_id = ?",
        (revision_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("change-set revision was not found")
    return str(row[0])


def _insert_memory_evidence(
    connection: Connection,
    memory_id: str,
    locator: EvidenceLocator,
) -> None:
    connection.execute(
        "INSERT INTO memory_evidence "
        "(memory_revision_id, ordinal, source_id, blob_digest, mode, char_start, "
        "char_end, excerpt, source_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            memory_id,
            locator.ordinal,
            locator.source_id,
            locator.blob_digest,
            locator.mode,
            locator.char_start,
            locator.char_end,
            locator.excerpt,
            None if locator.source_level is None else int(locator.source_level),
        ),
    )


def _item_index(items: list[DraftItem], item_id: str) -> int:
    _validate_opaque_id(item_id)
    for index, item in enumerate(items):
        if item.item_id == item_id:
            return index
    raise NotFoundError("draft item identifier was not found")


def _require_batch_source(
    sources: dict[str, _BatchSource],
    source_id: str,
) -> _BatchSource:
    _validate_opaque_id(source_id)
    try:
        return sources[source_id]
    except KeyError as error:
        raise InvalidEvidenceError(
            "evidence source is not in the sealed batch"
        ) from error


def _bounded_string(
    value: object,
    *,
    maximum: int,
    label: str,
    strip: bool,
) -> str:
    strict_utf8_bytes(value, label=label)
    assert isinstance(value, str)
    normalized = value.strip() if strip else value
    encoded = strict_utf8_bytes(normalized, label=label)
    if not normalized or len(encoded) > maximum:
        raise InvalidArgumentError(f"{label} is invalid")
    return normalized


def _normalize_tags(raw: object) -> tuple[str, ...]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise InvalidArgumentError("memory tags are invalid")
    if len(raw) > MAX_TAGS:
        raise InvalidArgumentError("memory tag limit exceeded")
    tags: list[str] = []
    seen: set[str] = set()
    for value in raw:
        tag = _bounded_string(
            value,
            maximum=MAX_TAG_BYTES,
            label="memory tag",
            strip=True,
        )
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tuple(tags)


def _validate_partial_date(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise InvalidArgumentError(f"{label} is invalid")
    match = _ACCEPTED_PARTIAL_DATE.fullmatch(value)
    if match is None:
        raise InvalidArgumentError(f"{label} is invalid")
    year = int(match.group(1))
    month = match.group(2)
    day = match.group(3)
    if year < 1:
        raise InvalidArgumentError(f"{label} is invalid")
    try:
        if month is not None:
            date(year, int(month), 1 if day is None else int(day))
    except ValueError as error:
        raise InvalidArgumentError(f"{label} is invalid") from error
    return value


def partial_date_bounds(value: str) -> tuple[date, date]:
    """Expand one validated stored partial date to inclusive calendar bounds."""
    match = _PARTIAL_DATE.fullmatch(value)
    assert match is not None
    year = int(match.group(1))
    if match.group(2) is None:
        return date(year, 1, 1), date(year, 12, 31)
    month = int(match.group(2))
    if match.group(3) is not None:
        exact = date(year, month, int(match.group(3)))
        return exact, exact
    return date(year, month, 1), date(year, month, monthrange(year, month)[1])


# Internal compatibility name retained for tests and older in-package callers.
_date_bounds = partial_date_bounds


def _occurrences(text: str, excerpt: str) -> list[int]:
    starts: list[int] = []
    after = 0
    while True:
        found = text.find(excerpt, after)
        if found < 0:
            return starts
        starts.append(found)
        if len(starts) > 1:
            return starts
        after = found + 1


def _parse_tags(raw: object) -> tuple[str, ...]:
    try:
        parsed: Any = json.loads(str(raw))
    except (TypeError, json.JSONDecodeError) as error:
        raise InvalidArgumentError("stored memory tags are invalid") from error
    return _normalize_tags(parsed)


def _tags_json(tags: tuple[str, ...]) -> str:
    return json.dumps(list(tags), ensure_ascii=False, separators=(",", ":"))


def _validate_digest(value: object, *, evidence: bool = False) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        if evidence:
            raise InvalidEvidenceError("evidence digest is invalid")
        raise InvalidArgumentError("digest is invalid")


def _check_diff_size(encoded: bytes) -> None:
    if len(encoded) > MAX_DIFF_BYTES:
        raise InvalidArgumentError("canonical change-set diff is too large")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(16)}"
