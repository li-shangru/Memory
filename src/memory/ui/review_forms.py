"""The owner review form codec: submitted pairs in, one bounded edit out.

Nothing here touches the web. It turns the exact pairs an owner's browser
submitted into one `ChangeEdit` the Store will accept, and turns an edit or a
refusal back into the pairs that repopulate the form. It lived inside the
route module, where roughly four hundred lines of it sat between the routes
and made both harder to read; the tests already exercised it directly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import cast

from starlette.datastructures import FormData

from memory.errors import (
    InvalidArgumentError,
)
from memory.model import (
    CHANGE_EDIT_OPERATIONS,
    AddGuardLink,
    AddItem,
    ChangeEdit,
    ClearSourceNoMemory,
    EvidenceInput,
    EvidenceLocator,
    GuardLinkInput,
    MemoryFields,
    MemoryKind,
    RejectItem,
    RemoveGuardLink,
    ReplaceItem,
    RestoreItem,
    RevokeGuardLink,
    Sensitivity,
    SetSourceNoMemory,
)
from memory.reviews import (
    MAX_EVIDENCE_EXCERPT_BYTES,
    MAX_EVIDENCE_PER_ITEM,
    MAX_NO_MEMORY_REASON_BYTES,
    MAX_STATEMENT_BYTES,
    MAX_TAG_BYTES,
    MAX_TAGS,
    _new_id,
)
from memory.sources import _validate_opaque_id
from memory.ui.request_limits import (
    MAX_BULK_REVIEW_ITEM_IDS,
    MAX_RETAINED_REFUSAL_BYTES,
)
from memory.ui.view_models import (
    OwnerReviewAddEditTarget,
    OwnerReviewFormIntent,
    OwnerReviewGuardLinkEditTarget,
    OwnerReviewItemEditTarget,
    OwnerReviewManifest,
    OwnerReviewRosterSource,
    OwnerReviewSourceEditTarget,
    ReviewEditTargetState,
    UiPendingReviewForm,
)
from memory.validation import require_invariant

#: Derived, not restated: the owner UI offers a form for exactly the edits the
#: Store accepts, so a ninth operation cannot reach the MCP surface while the
#: owner's own review still has no way to make it.
OWNER_REVIEW_FORM_INTENTS: tuple[OwnerReviewFormIntent, ...] = cast(
    "tuple[OwnerReviewFormIntent, ...]",
    tuple(CHANGE_EDIT_OPERATIONS),
)
MAX_REVIEW_FORM_INDEX = max(MAX_TAGS, MAX_EVIDENCE_PER_ITEM)
_MEMORY_INTENTS = frozenset({"add_item", "replace_item"})
_MEMORY_SINGLETONS = (
    "kind",
    "statement",
    "occurred_on",
    "valid_from",
    "valid_to",
    "sensitivity",
    "target_lineage_id",
    "expected_head_id",
)
_GUARD_LINK_ENDPOINTS = (
    "guard_item_id",
    "guard_lineage_id",
    "governed_item_id",
    "governed_lineage_id",
)
_SINGLETON_FIELDS: dict[str, frozenset[str]] = {
    "add_item": frozenset(_MEMORY_SINGLETONS),
    "replace_item": frozenset({"item_id", *_MEMORY_SINGLETONS}),
    "reject_item": frozenset({"item_id"}),
    "restore_item": frozenset({"item_id"}),
    "set_source_no_memory": frozenset({"source_id", "reason"}),
    "clear_source_no_memory": frozenset({"source_id"}),
    "add_guard_link": frozenset(_GUARD_LINK_ENDPOINTS),
    "remove_guard_link": frozenset(_GUARD_LINK_ENDPOINTS),
    "revoke_guard_link": frozenset(_GUARD_LINK_ENDPOINTS),
}
#: The two operations one submission may name several times over. Both take a
#: draft item and nothing else, both are reversible by their own counterpart,
#: and neither carries owner-authored content -- so a selection of them is one
#: bounded edit rather than a batch of independent judgements. Anything that
#: writes a statement, an excerpt, a reason, or a link stays one per POST: an
#: owner approving forty of those at once has read none of them.
_BULK_ITEM_EDITS: dict[str, type[RejectItem] | type[RestoreItem]] = {
    "reject_item": RejectItem,
    "restore_item": RestoreItem,
}
_EVIDENCE_FIELDS = frozenset({"source_id", "excerpt", "source_level"})
_GUARD_LINK_EDITS: dict[
    str, type[AddGuardLink] | type[RemoveGuardLink] | type[RevokeGuardLink]
] = {
    "add_guard_link": AddGuardLink,
    "remove_guard_link": RemoveGuardLink,
    "revoke_guard_link": RevokeGuardLink,
}
_ORDERED_ITEM_FIELDS = frozenset(
    (
        *(f"tag.{index}" for index in range(MAX_TAGS)),
        *(
            f"evidence.{index}.{field}"
            for index in range(MAX_EVIDENCE_PER_ITEM)
            for field in _EVIDENCE_FIELDS
        ),
    )
)
# Exactly the boxes each intent's own form can hold. A refusal retains these
# and nothing else, so an arbitrary posted name never reaches a session or a
# rendered page, and the retained bytes stay inside one page's budget.
_RETAINED_FIELDS: dict[str, frozenset[str]] = {
    intent: (names | _ORDERED_ITEM_FIELDS) if intent in _MEMORY_INTENTS else names
    for intent, names in _SINGLETON_FIELDS.items()
}
_FIELD_LABELS: dict[str, str] = {
    "item_id": "Draft item",
    "source_id": "Batch source",
    "reason": "Reviewed no-memory reason",
    "kind": "Kind",
    "statement": "Statement",
    "occurred_on": "Occurred on",
    "valid_from": "Valid from",
    "valid_to": "Valid to",
    "sensitivity": "Sensitivity",
    "target_lineage_id": "Correction target lineage",
    "expected_head_id": "Expected current head",
    "guard_item_id": "Guard draft item",
    "guard_lineage_id": "Guard lineage",
    "governed_item_id": "Governed draft item",
    "governed_lineage_id": "Governed lineage",
}
_EVIDENCE_LABELS: dict[str, str] = {
    "source_id": "source",
    "excerpt": "exact excerpt",
    "source_level": "whole source",
}
require_invariant(
    set(_EVIDENCE_LABELS) == _EVIDENCE_FIELDS,
    label="evidence field labels",
)
require_invariant(
    all(
        name in _FIELD_LABELS for names in _SINGLETON_FIELDS.values() for name in names
    ),
    label="singleton field labels",
)


def _bounded_text(value: str, *, maximum: int, strip: bool) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise InvalidArgumentError("review edit field is invalid")
    normalized = value.strip() if strip else value
    if not normalized or len(normalized.encode("utf-8")) > maximum:
        raise InvalidArgumentError("review edit field is out of bounds")
    return normalized


def _bounded_reference(value: str) -> str:
    _validate_opaque_id(value)
    return value


def _form_index(raw: str) -> int:
    if not raw.isdigit() or (len(raw) > 1 and raw.startswith("0")):
        raise InvalidArgumentError("review edit index is invalid")
    try:
        index = int(raw)
    except ValueError as error:
        raise InvalidArgumentError("review edit index is invalid") from error
    if index >= MAX_REVIEW_FORM_INDEX:
        raise InvalidArgumentError("review edit index is out of bounds")
    return index


def _contiguous[T](indexed: dict[int, T]) -> tuple[T, ...]:
    if sorted(indexed) != list(range(len(indexed))):
        raise InvalidArgumentError("review edit indices are not contiguous")
    return tuple(indexed[index] for index in range(len(indexed)))


def _optional(singles: dict[str, str], name: str) -> str | None:
    value = singles.get(name)
    if value is None or value == "":
        return None
    return value


def _require(singles: dict[str, str], name: str) -> str:
    value = singles.get(name)
    if value is None:
        raise InvalidArgumentError("review edit field is missing")
    return value


def roster_source(
    current: OwnerReviewManifest,
    source_id: str,
) -> OwnerReviewRosterSource:
    for source in current.source_roster:
        if source.source_id == source_id:
            return source
    raise InvalidArgumentError("review source reference is unknown")


def roster_item_id(current: OwnerReviewManifest, item_id: str) -> str:
    for item in current.item_roster:
        if item.item_id == item_id:
            return item.item_id
    raise InvalidArgumentError("review item reference is unknown")


def _memory_from_fields(singles: dict[str, str], tags: tuple[str, ...]) -> MemoryFields:
    try:
        kind = MemoryKind(_require(singles, "kind"))
        sensitivity = Sensitivity(_require(singles, "sensitivity"))
    except ValueError as error:
        raise InvalidArgumentError("review edit enum is invalid") from error
    if len(tags) > MAX_TAGS:
        raise InvalidArgumentError("review edit tag limit exceeded")
    target = _optional(singles, "target_lineage_id")
    expected = _optional(singles, "expected_head_id")
    if (target is None) != (expected is None):
        raise InvalidArgumentError("review correction target must pair")
    return MemoryFields(
        kind=kind,
        statement=_bounded_text(
            _require(singles, "statement"),
            maximum=MAX_STATEMENT_BYTES,
            strip=True,
        ),
        occurred_on=_optional(singles, "occurred_on"),
        valid_from=_optional(singles, "valid_from"),
        valid_to=_optional(singles, "valid_to"),
        tags=tuple(
            _bounded_text(tag, maximum=MAX_TAG_BYTES, strip=True) for tag in tags
        ),
        sensitivity=sensitivity,
        target_lineage_id=None if target is None else _bounded_reference(target),
        expected_head_id=None if expected is None else _bounded_reference(expected),
    )


def _evidence_from_fields(
    slots: tuple[dict[str, str], ...],
    current: OwnerReviewManifest,
) -> tuple[EvidenceInput, ...]:
    if not 1 <= len(slots) <= MAX_EVIDENCE_PER_ITEM:
        raise InvalidArgumentError("review edit evidence count is invalid")
    evidence: list[EvidenceInput] = []
    for slot in slots:
        if set(slot) - _EVIDENCE_FIELDS:
            raise InvalidArgumentError("review evidence field is unknown")
        source = roster_source(current, _bounded_reference(_require(slot, "source_id")))
        excerpt = _optional(slot, "excerpt")
        source_level = _optional(slot, "source_level")
        if (excerpt is None) == (source_level is None):
            raise InvalidArgumentError("review evidence intent is invalid")
        if source_level is not None and source_level != "true":
            raise InvalidArgumentError("review evidence intent is invalid")
        evidence.append(
            EvidenceInput(
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                excerpt=None
                if excerpt is None
                else _bounded_text(
                    excerpt,
                    maximum=MAX_EVIDENCE_EXCERPT_BYTES,
                    strip=False,
                ),
                source_level=None if source_level is None else True,
            )
        )
    return tuple(evidence)


def _guard_link_from_fields(singles: dict[str, str]) -> GuardLinkInput:
    """Build one guard link from the owner form's four endpoint fields.

    Each side names an item or a lineage and never both: the owner types into
    whichever pair of boxes matches the endpoint they mean, and the exclusive
    choice is refused here rather than deep in the kernel's revision writer.
    """
    endpoints = {name: _optional(singles, name) for name in _GUARD_LINK_ENDPOINTS}
    for item_name, lineage_name in (
        ("guard_item_id", "guard_lineage_id"),
        ("governed_item_id", "governed_lineage_id"),
    ):
        item_ref, lineage_ref = endpoints[item_name], endpoints[lineage_name]
        if (item_ref is None) == (lineage_ref is None):
            raise InvalidArgumentError(
                "guard link endpoint must name one item or one lineage"
            )
    return GuardLinkInput(
        **{
            name: None if value is None else _bounded_reference(value)
            for name, value in endpoints.items()
        }
    )


def _bulk_item_edits(
    operation: type[RejectItem] | type[RestoreItem],
    item_ids: Sequence[str],
    current: OwnerReviewManifest,
) -> tuple[ChangeEdit, ...]:
    """Turn one owner selection into one bounded edit per item it names.

    Submission order is kept, because the retained normalized fields have to
    rebuild this exact edit after a busy writer. Naming one item twice is a
    malformed form rather than an emphatic one: the second operation would be
    a no-op the owner never asked for, and refusing says so.
    """
    if not item_ids:
        raise InvalidArgumentError("review edit field is missing")
    if len(item_ids) > MAX_BULK_REVIEW_ITEM_IDS:
        raise InvalidArgumentError("review edit selects too many draft items")
    resolved = tuple(roster_item_id(current, item_id) for item_id in item_ids)
    if len(set(resolved)) != len(resolved):
        raise InvalidArgumentError("review edit names one draft item twice")
    return tuple(operation(item_id=item_id) for item_id in resolved)


def _build_change_edits(
    pairs: Sequence[tuple[str, str]],
    *,
    intent: OwnerReviewFormIntent,
    current: OwnerReviewManifest,
    allow_store_item_id: bool,
) -> tuple[ChangeEdit, ...]:
    if intent not in OWNER_REVIEW_FORM_INTENTS:
        raise InvalidArgumentError("review edit intent is invalid")
    if not isinstance(current, OwnerReviewManifest):
        raise InvalidArgumentError("review manifest is invalid")
    allowed = set(_SINGLETON_FIELDS[intent])
    if allow_store_item_id and intent == "add_item":
        allowed.add("client_item_id")
    bulk_operation = _BULK_ITEM_EDITS.get(intent)
    memory_intent = intent in _MEMORY_INTENTS
    singles: dict[str, str] = {}
    selected: list[str] = []
    tags: dict[int, str] = {}
    evidence: dict[int, dict[str, str]] = {}
    for name, value in pairs:
        if not isinstance(value, str):
            raise InvalidArgumentError("review edit form value is invalid")
        if name in allowed:
            if bulk_operation is not None and name == "item_id":
                selected.append(value)
                continue
            if name in singles:
                raise InvalidArgumentError("review edit field is duplicated")
            singles[name] = value
            continue
        if memory_intent and name.startswith("tag."):
            index = _form_index(name.removeprefix("tag."))
            if index in tags:
                raise InvalidArgumentError("review edit tag index is duplicated")
            tags[index] = value
            continue
        if memory_intent and name.startswith("evidence."):
            raw_index, separator, field_name = name.removeprefix("evidence.").partition(
                "."
            )
            if not separator or field_name not in _EVIDENCE_FIELDS:
                raise InvalidArgumentError("review evidence field is unknown")
            slot = evidence.setdefault(_form_index(raw_index), {})
            if field_name in slot:
                raise InvalidArgumentError("review evidence field is duplicated")
            slot[field_name] = value
            continue
        raise InvalidArgumentError("review edit field is unknown")

    if bulk_operation is not None:
        return _bulk_item_edits(bulk_operation, selected, current)
    if intent == "set_source_no_memory":
        return (
            SetSourceNoMemory(
                source_id=roster_source(
                    current, _bounded_reference(_require(singles, "source_id"))
                ).source_id,
                reason=_bounded_text(
                    _require(singles, "reason"),
                    maximum=MAX_NO_MEMORY_REASON_BYTES,
                    strip=True,
                ),
            ),
        )
    if intent == "clear_source_no_memory":
        return (
            ClearSourceNoMemory(
                source_id=roster_source(
                    current, _bounded_reference(_require(singles, "source_id"))
                ).source_id
            ),
        )
    guard_link_edit = _GUARD_LINK_EDITS.get(intent)
    if guard_link_edit is not None:
        return (guard_link_edit(link=_guard_link_from_fields(singles)),)
    memory = _memory_from_fields(singles, _contiguous(tags))
    locators = _evidence_from_fields(_contiguous(evidence), current)
    if intent == "replace_item":
        return (
            ReplaceItem(
                item_id=roster_item_id(current, _require(singles, "item_id")),
                memory=memory,
                evidence=locators,
            ),
        )
    stored = singles.get("client_item_id")
    return (
        AddItem(
            client_item_id=_bounded_reference(stored) if stored else _new_id("itm"),
            memory=memory,
            evidence=locators,
        ),
    )


def parse_change_edit_form(
    form: FormData,
    *,
    intent: OwnerReviewFormIntent,
    current: OwnerReviewManifest,
) -> tuple[ChangeEdit, ...]:
    """Parse one bounded browser-writable review submission.

    One operation, except for a reject or restore selection, which is several
    of one operation and lands in one revision. Clearing a sealed batch of
    sixty-four files was sixty-four round trips and sixty-four revisions
    before this; it is now one of each.
    """
    if not isinstance(form, FormData):
        raise InvalidArgumentError("review edit form is invalid")
    pairs: list[tuple[str, str]] = []
    for name, value in form.multi_items():
        if not isinstance(value, str):
            raise InvalidArgumentError("review edit form value is invalid")
        pairs.append((name, value))
    return _build_change_edits(
        pairs,
        intent=intent,
        current=current,
        allow_store_item_id=False,
    )


def _memory_form_fields(memory: MemoryFields) -> tuple[tuple[str, str], ...]:
    optional = tuple(
        (name, value)
        for name, value in (
            ("occurred_on", memory.occurred_on),
            ("valid_from", memory.valid_from),
            ("valid_to", memory.valid_to),
            ("target_lineage_id", memory.target_lineage_id),
            ("expected_head_id", memory.expected_head_id),
        )
        if value is not None
    )
    return (
        ("kind", memory.kind.value),
        ("statement", memory.statement),
        ("sensitivity", memory.sensitivity.value),
        *optional,
        *((f"tag.{index}", tag) for index, tag in enumerate(memory.tags)),
    )


def _evidence_form_fields(
    evidence: Sequence[EvidenceInput | EvidenceLocator],
) -> tuple[tuple[str, str], ...]:
    fields: list[tuple[str, str]] = []
    for index, locator in enumerate(evidence):
        fields.append((f"evidence.{index}.source_id", locator.source_id))
        if locator.excerpt is not None:
            fields.append((f"evidence.{index}.excerpt", locator.excerpt))
        else:
            fields.append((f"evidence.{index}.source_level", "true"))
    return tuple(fields)


def normalized_review_fields(edit: ChangeEdit) -> tuple[tuple[str, str], ...]:
    """Return the exact canonical bounded fields retained for one owner edit."""
    if isinstance(edit, AddItem):
        return (
            ("client_item_id", edit.client_item_id),
            *_memory_form_fields(edit.memory),
            *_evidence_form_fields(edit.evidence),
        )
    if isinstance(edit, ReplaceItem):
        return (
            ("item_id", edit.item_id),
            *_memory_form_fields(edit.memory),
            *_evidence_form_fields(edit.evidence),
        )
    if isinstance(edit, (RejectItem, RestoreItem)):
        return (("item_id", edit.item_id),)
    if isinstance(edit, SetSourceNoMemory):
        return (("source_id", edit.source_id), ("reason", edit.reason))
    if isinstance(edit, ClearSourceNoMemory):
        return (("source_id", edit.source_id),)
    if isinstance(edit, (AddGuardLink, RemoveGuardLink, RevokeGuardLink)):
        # Only the two endpoints the owner named: an empty box is absence, and
        # rebuilding the retained edit must refuse the same both-or-neither pair.
        return tuple(
            (name, value)
            for name, value in (
                ("guard_item_id", edit.link.guard_item_id),
                ("guard_lineage_id", edit.link.guard_lineage_id),
                ("governed_item_id", edit.link.governed_item_id),
                ("governed_lineage_id", edit.link.governed_lineage_id),
            )
            if value is not None
        )
    raise InvalidArgumentError("review edit operation is invalid")


def normalized_submission_fields(
    edits: Sequence[ChangeEdit],
) -> tuple[tuple[str, str], ...]:
    """Return the canonical bounded fields retained for one whole submission.

    A selection concatenates: every retained edit contributes its own pairs, in
    submission order, so rebuilding the retained form yields the same edits in
    the same order. For a single edit this is exactly its own fields.
    """
    return tuple(pair for edit in edits for pair in normalized_review_fields(edit))


def submission_fingerprint(fingerprints: Sequence[str]) -> str:
    """Fold one target fingerprint per edit into one fingerprint for the form.

    A single edit keeps its own fingerprint unchanged, so nothing about the
    one-edit path moves. A selection is compared as a whole, which is the
    right question: the owner asked for these items in this state, and any one
    of them shifting under them is the conflict.
    """
    if len(fingerprints) == 1:
        return fingerprints[0]
    digest = hashlib.sha256()
    for fingerprint in fingerprints:
        digest.update(fingerprint.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def pending_review_edit(
    form: UiPendingReviewForm,
    current: OwnerReviewManifest,
) -> tuple[ChangeEdit, ...]:
    """Rebuild one retained submission and revalidate it against a manifest."""
    return _build_change_edits(
        form.normalized_fields,
        intent=form.operation,
        current=current,
        allow_store_item_id=True,
    )


def bulk_target_rows(
    edits: Sequence[ChangeEdit],
    current: OwnerReviewManifest,
) -> tuple[tuple[str, str], ...]:
    """Report each selected item's status in one revision, one row per item.

    A selection's target state is exactly the statuses of the items it names,
    and reading them off the roster costs one manifest rather than one bounded
    read per item. It is also what keeps the conflict page inside its budget:
    the full target rows carry a statement each.
    """
    statuses = {item.item_id: item.status for item in current.item_roster}
    return tuple(
        (
            f"Item {edit.item_id}",
            statuses.get(edit.item_id, "not in this revision"),
        )
        for edit in edits
        if isinstance(edit, (RejectItem, RestoreItem))
    )


def target_rows(state: ReviewEditTargetState) -> tuple[tuple[str, str], ...]:
    if isinstance(state, OwnerReviewItemEditTarget):
        memory = state.memory
        return (
            ("Item", state.item_id),
            ("Ordinal", str(state.ordinal)),
            ("Status", state.status),
            ("Kind", memory.kind.value),
            ("Statement", memory.statement),
            ("Occurred", memory.occurred_on or "Not recorded"),
            ("Valid from", memory.valid_from or "Not recorded"),
            ("Valid to", memory.valid_to or "No end date recorded"),
            ("Tags", ", ".join(memory.tags)),
            ("Sensitivity", memory.sensitivity.value),
            ("Target lineage", memory.target_lineage_id or "New lineage"),
            ("Expected head", memory.expected_head_id or "None"),
            *(
                (f"Evidence {locator.ordinal}", locator.excerpt or locator.mode)
                for locator in state.evidence
            ),
        )
    if isinstance(state, OwnerReviewSourceEditTarget):
        return (
            ("Source", state.source_id),
            ("Blob digest", state.blob_digest),
            ("Coverage", state.coverage),
            ("Reason", state.reason or "None recorded"),
        )
    if isinstance(state, OwnerReviewAddEditTarget):
        return (
            ("Generated item", state.generated_item_id),
            ("Identity absent", "yes" if state.generated_item_id_absent else "no"),
            *(
                (f"Referenced source {source.source_id}", source.coverage)
                for source in state.referenced_sources
            ),
        )
    if isinstance(state, OwnerReviewGuardLinkEditTarget):
        revoking = state.proposal == "revocation"
        return (
            ("Guard item", state.guard_item_id or "None"),
            ("Guard lineage", state.guard_lineage_id or "None"),
            ("Governed item", state.governed_item_id or "None"),
            ("Governed lineage", state.governed_lineage_id or "None"),
            (
                "Already revoked in this revision" if revoking else "Already linked",
                "yes" if state.present else "no",
            ),
            (
                "Revocation status" if revoking else "Link status",
                state.status or ("not revoked" if revoking else "not linked"),
            ),
        )
    raise InvalidArgumentError("review edit target state is invalid")


def retained_review_fields(
    intent: OwnerReviewFormIntent,
    pairs: Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...] | None:
    """Return this intent's own boxes as the owner left them, or None if too big.

    A submission past the retention budget is larger than the largest edit the
    form can legitimately hold, so it is refused exactly as it was before this
    page existed rather than retained into a page that cannot be rendered.
    """
    retained = tuple(
        (name, value) for name, value in pairs if name in _RETAINED_FIELDS[intent]
    )
    kept = sum(len(name) + len(value.encode("utf-8")) for name, value in retained)
    return None if kept > MAX_RETAINED_REFUSAL_BYTES else retained


def _submitted_label(name: str) -> str:
    """Name one retained box the way the form the owner typed into names it."""
    labelled = _FIELD_LABELS.get(name)
    if labelled is not None:
        return labelled
    if name.startswith("tag."):
        return f"Tag {name.removeprefix('tag.')}"
    index, _separator, field = name.removeprefix("evidence.").partition(".")
    return f"Evidence {index} {_EVIDENCE_LABELS[field]}"


def submitted_rows(
    fields: Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    """Return one readable receipt row for every retained box."""
    return tuple((_submitted_label(name), value or "None") for name, value in fields)
