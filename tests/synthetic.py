"""Shared synthetic-store helpers for kernel test modules."""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Literal

import keyring
import pytest

from memory import keys, model
from memory.errors import KeyAlreadyExistsError
from memory.inbox import scan_inbox
from memory.keys import KEYCHAIN_SERVICE
from memory.model import (
    AddGuardLink,
    AddItem,
    ApplicationResult,
    ChangeEdit,
    ChangeSetView,
    EvidenceInput,
    GuardLinkInput,
    MemoryFields,
    MemoryKind,
    RuntimePaths,
    Sensitivity,
    SourceSummary,
    StoreIdentity,
)
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
)
from memory.runtime import (
    initialize_runtime,
    load_runtime_identity,
    resolve_runtime,
)
from memory.sources import list_sources

HEDGE_BODY = "That figure is self-reported and not verified.\n"


class FakeClock:
    def __init__(self, timestamp: float = 1_850_000_000.0) -> None:
        self.timestamp = timestamp

    def time(self) -> float:
        return self.timestamp

    def sleep(self, seconds: float) -> None:
        self.timestamp += seconds


def store_synthetic_key_exclusive(
    items: dict[tuple[str, str], str], identity: StoreIdentity, encoded: str
) -> None:
    """Stand in for the atomic add without ever reaching the OS Keychain."""
    base64.b64decode(encoded, validate=True)
    account = (KEYCHAIN_SERVICE, identity.store_id)
    if account in items:
        raise KeyAlreadyExistsError("synthetic Keychain item already exists")
    items[account] = encoded


def make_synthetic_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    export_keychain_item: str | None = None,
) -> Iterator[RuntimePaths]:
    """Build one disposable Store on an in-memory synthetic Keychain.

    `export_keychain_item` names an environment variable to receive the Store's
    synthetic Keychain entry, for the one suite that has to rebuild this
    fixture inside a subprocess it crashes on purpose.
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

    def set_password(service: str, account: str, value: str) -> None:
        base64.b64decode(value, validate=True)
        items[(service, account)] = value

    monkeypatch.setattr(keyring, "set_password", set_password)
    monkeypatch.setattr(
        keys,
        "_store_master_key_exclusive",
        lambda identity, encoded: store_synthetic_key_exclusive(
            items, identity, encoded
        ),
    )
    paths = resolve_runtime(tmp_path / "synthetic-memory-store")
    initialize_runtime(paths, mode=model.RuntimeMode.PERSONAL)
    if export_keychain_item is not None:
        identity = load_runtime_identity(paths)
        monkeypatch.setenv(
            export_keychain_item,
            items[(KEYCHAIN_SERVICE, identity.store_id)],
        )
    yield paths


def _all_sources(paths: RuntimePaths) -> tuple[SourceSummary, ...]:
    """Enumerate every retained source, following the listing past its page cap."""
    sources: list[SourceSummary] = []
    cursor = None
    while True:
        page = list_sources(paths, cursor, limit=100)
        sources.extend(page.items)
        if page.next_cursor is None:
            return tuple(sources)
        cursor = page.next_cursor


def capture_batch(
    paths: RuntimePaths,
    files: dict[str, str],
    *,
    sensitivity: Sensitivity,
    clock: FakeClock,
) -> tuple[str, dict[str, SourceSummary]]:
    """Capture several inbox files in one scan, keyed by their capture names."""
    before = {source.source_id for source in _all_sources(paths)}
    for name, body in files.items():
        (paths.inbox / name).write_text(body, encoding="utf-8")
    batch = scan_inbox(paths, sensitivity=sensitivity, clock=clock)
    captured = {
        source.original_name: source
        for source in _all_sources(paths)
        if source.source_id not in before
    }
    return batch.batch_id, {name: captured[name] for name in files}


def capture_text(
    paths: RuntimePaths,
    *,
    name: str,
    body: str,
    sensitivity: Sensitivity,
    clock: FakeClock,
) -> tuple[str, SourceSummary]:
    batch_id, captured = capture_batch(
        paths, {name: body}, sensitivity=sensitivity, clock=clock
    )
    return batch_id, captured[name]


def single_item_edit(
    *,
    item_id: str,
    source: SourceSummary,
    statement: str,
    excerpt: str,
    kind: MemoryKind = MemoryKind.FACT,
    tags: tuple[str, ...] = ("synthetic",),
    sensitivity: Sensitivity = Sensitivity.NORMAL,
    target_lineage_id: str | None = None,
    expected_head_id: str | None = None,
) -> AddItem:
    return AddItem(
        client_item_id=item_id,
        memory=MemoryFields(
            kind=kind,
            statement=statement,
            occurred_on=None,
            valid_from=None,
            valid_to=None,
            tags=tags,
            sensitivity=sensitivity,
            target_lineage_id=target_lineage_id,
            expected_head_id=expected_head_id,
        ),
        evidence=(
            EvidenceInput(
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                excerpt=excerpt,
            ),
        ),
    )


def ready_items(
    paths: RuntimePaths, batch_id: str, edits: Sequence[ChangeEdit]
) -> ChangeSetView:
    initial = create_change_set(
        paths,
        batch_id,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    return edit_change_set(
        paths,
        initial.change_set_id,
        initial.revision_id,
        edits,
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )


def apply_ready(paths: RuntimePaths, ready: ChangeSetView) -> ApplicationResult:
    approval = _mint_owner_approval(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        ready.change_set_id,
        ready.revision_id,
        ready.digest,
        approval=approval,
    )


def large_guard_star(
    paths: RuntimePaths, direction: Literal["guards", "governs"]
) -> tuple[str, tuple[str, ...], str]:
    """One short centre and sixty valid statements that expand when escaped."""
    centre = "Synthetic relation audit: the amber lantern stays in the workshop."
    statements = [centre]
    for index in range(60):
        prefix = f"Synthetic caveat {index:03d}: "
        suffix = f" End of synthetic caveat {index:03d}."
        statements.append(prefix + "&" * (16_384 - len(prefix + suffix)) + suffix)
    batch_id, source = capture_text(
        paths,
        name="synthetic-large-relations.txt",
        body="\n".join(statements),
        sensitivity=Sensitivity.NORMAL,
        clock=FakeClock(),
    )
    edits: list[ChangeEdit] = [
        single_item_edit(
            item_id=f"synthetic_relation_{index}",
            source=source,
            statement=statement,
            excerpt=centre if index == 0 else f"Synthetic caveat {index - 1:03d}: ",
        )
        for index, statement in enumerate(statements)
    ]
    for index in range(1, len(statements)):
        guard, governed = f"synthetic_relation_{index}", "synthetic_relation_0"
        if direction == "governs":
            guard, governed = governed, guard
        edits.append(
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id=guard,
                    guard_lineage_id=None,
                    governed_item_id=governed,
                    governed_lineage_id=None,
                )
            )
        )
    applied = apply_ready(paths, ready_items(paths, batch_id, edits))
    return applied.memory_ids[0], applied.memory_ids[1:], statements[-1]


def two_source_linked_apply(paths: RuntimePaths, clock: FakeClock) -> ApplicationResult:
    """Apply a claim and its hedge from two sources, linked guard -> claim."""
    from memory.model import AddGuardLink, GuardLinkInput

    batch_id, captured = capture_batch(
        paths,
        {"claim.txt": "The owner reports daily runs.\n", "hedge.txt": HEDGE_BODY},
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    claim_source = captured["claim.txt"]
    guard_source = captured["hedge.txt"]
    draft = ready_items(
        paths,
        batch_id,
        (
            single_item_edit(
                item_id="itm_claim",
                source=claim_source,
                statement="The owner reports daily runs.",
                excerpt="The owner reports daily runs.",
            ),
            single_item_edit(
                item_id="itm_guard",
                source=guard_source,
                statement="The daily-runs figure is self-reported and not verified.",
                excerpt="self-reported and not verified",
                kind=MemoryKind.INSIGHT,
            ),
        ),
    )
    linked = edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        (
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id="itm_guard",
                    guard_lineage_id=None,
                    governed_item_id="itm_claim",
                    governed_lineage_id=None,
                )
            ),
        ),
        adapter_origin=model.ChangeSetAdapterOrigin.SYSTEM,
    )
    return apply_ready(paths, linked)


def store_one_memory(
    paths: RuntimePaths,
    *,
    clock: FakeClock,
    name: str,
    body: str,
    statement: str,
    excerpt: str,
    kind: MemoryKind = MemoryKind.FACT,
    sensitivity: Sensitivity = Sensitivity.NORMAL,
    source_sensitivity: Sensitivity = Sensitivity.NORMAL,
) -> tuple[str, str]:
    """Capture one file and apply one memory; return (memory_id, lineage_id)."""
    from memory.memories import get_memory

    batch_id, source = capture_text(
        paths, name=name, body=body, sensitivity=source_sensitivity, clock=clock
    )
    applied = apply_ready(
        paths,
        ready_items(
            paths,
            batch_id,
            (
                single_item_edit(
                    item_id=f"itm_{name.replace('.', '_')}",
                    source=source,
                    statement=statement,
                    excerpt=excerpt,
                    kind=kind,
                    sensitivity=sensitivity,
                ),
            ),
        ),
    )
    memory_id = applied.memory_ids[0]
    return memory_id, get_memory(paths, memory_id).revision.lineage_id
