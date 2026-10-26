"""Real-browser security and workflow journeys for the local owner UI.

Every journey runs against a disposable synthetic runtime served on an exact
random loopback origin. The owner-presence adapter used for automated apply is
defined only in this test module; the production macOS prompt is never
automated and never reached here.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

import keyring
import pytest
import uvicorn
from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Route,
    expect,
    sync_playwright,
)
from synthetic import (
    FakeClock,
    capture_batch,
    large_guard_star,
    ready_items,
    single_item_edit,
    store_synthetic_key_exclusive,
)

from memory import keys
from memory import reviews as review_module
from memory.errors import OwnerApprovalRequiredError
from memory.inbox import (
    ScanPolicy,
    bind_runtime_directory_authority,
    scan_inbox,
)
from memory.model import (
    AddGuardLink,
    AddItem,
    ApplicationResult,
    ChangeSetAdapterOrigin,
    ChangeSetView,
    ClearSourceNoMemory,
    EvidenceInput,
    GuardLinkInput,
    MemoryFields,
    MemoryKind,
    RuntimeMode,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
)
from memory.reviews import (
    MAX_EVIDENCE_EXCERPT_BYTES,
    MAX_STATEMENT_BYTES,
    MAX_TAG_BYTES,
    approve_and_apply,
    create_change_set,
    edit_change_set,
    get_change_set,
)
from memory.runtime import (
    _writer_lock,
    initialize_runtime,
    resolve_runtime,
)
from memory.sources import list_sources
from memory.ui import owner_presence as owner_presence_module
from memory.ui.app import _PACKAGE_ROOT, create_ui_app
from memory.ui.auth import UiSessionStore
from memory.ui.owner_presence import (
    ApprovalAttemptStore,
    ApprovalChallengeLease,
    SystemMonotonicClock,
    UiApprovalOrchestrator,
    VerifiedOwnerPresence,
)
from memory.ui.request_limits import MAX_UPLOAD_FILE_BYTES
from memory.ui.service import OwnerApplicationService

ENGLISH_SOURCE = (
    "Synthetic browser journey: Mira keeps the blue folder for the "
    "2026-12-04 rehearsal.\n"
)
CHINESE_SOURCE = "合成浏览器旅程：米拉在二零二六年十二月四日的排练中携带蓝色文件夹。\n"
HISTORICAL_SOURCE = (
    "Synthetic browser lineage: Rowan brings the red notebook on 2026-11-18.\n"
)
CURRENT_SOURCE = (
    "Synthetic browser lineage changed: Rowan brings the green notebook on "
    "2026-11-18.\n"
)
GUARD_CLAIM_SOURCE = "Synthetic browser guard source: the owner runs every day.\n"
GUARD_HEDGE_SOURCE = "Synthetic browser guard source: that figure is self-reported.\n"
GUARD_CLAIM_STATEMENT = "Synthetic browser guard claim: the owner runs every day."
GUARD_HEDGE_STATEMENT = "Synthetic browser guard caveat: the figure is self-reported."
GUARD_CLAIM_EXCERPT = "the owner runs every day."
GUARD_HEDGE_EXCERPT = "that figure is self-reported."
GUARD_CLAIM_ITEM = "SYN-UI-BROWSER-CLAIM-010"
GUARD_HEDGE_ITEM = "SYN-UI-BROWSER-HEDGE-011"
DIGEST_TEXT = re.compile(r"[0-9a-f]{64}")
MALFORMED_MEDIA = b"\x89PNG\r\n\x1a\nsynthetic-not-a-real-image\x00\xff\xfe"
HANDOFF_COPY = "Staged; ask a connected agent to process the Inbox"
UPLOAD_NAME = "syn-ui-browser-upload.txt"
UPLOAD_BODY = b"Synthetic drag and drop payload for the local owner UI.\n"
NAVIGATION_TIMEOUT_MS = 15_000
CROSS_INSTANCE = "cross-instance"


def _declared_colors(source: str) -> dict[str, str]:
    """Return every ``--name: #rrggbb`` declaration in one stylesheet region."""
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-fA-F]{6});", source))


def css_palette(mode: str) -> dict[str, str]:
    """Read one rendered palette straight from the shipped stylesheet.

    Same parse as the packaging suite's ``css_palettes``: the dark block is an
    override on the light defaults. Deriving the expectations here means a
    retuned token never leaves a browser assertion quietly checking the old one.
    """
    css = (_PACKAGE_ROOT / "static" / "app.css").read_text(encoding="utf-8")
    dark_block = re.search(
        r"@media \(prefers-color-scheme: dark\) \{(.*?)\n\}",
        css,
        re.DOTALL,
    )
    assert dark_block is not None, "the owner stylesheet declares no dark palette"
    light = _declared_colors(css[: dark_block.start()])
    if mode == "light":
        return light
    return {**light, **_declared_colors(dark_block.group(1))}


def rgb(token: str) -> str:
    """Render one ``#rrggbb`` token the way ``getComputedStyle`` reports it."""
    red, green, blue = (int(token[index : index + 2], 16) for index in (1, 3, 5))
    return f"rgb({red}, {green}, {blue})"


DARK_BACKGROUND = rgb(css_palette("dark")["--background"])
DARK_TEXT = rgb(css_palette("dark")["--text"])
LIGHT_SURFACE = rgb(css_palette("light")["--surface"])


class BrowserOwnerPresenceAdapter:
    """Test-only owner-presence adapter; never packaged and never production."""

    def __init__(
        self,
        *,
        outcome: str = "verified",
        during: Callable[[], None] | None = None,
    ) -> None:
        self.outcome = outcome
        self.during = during
        self.calls = 0

    async def verify(
        self,
        lease: ApprovalChallengeLease,
        *,
        reason: str,
    ) -> VerifiedOwnerPresence:
        self.calls += 1
        if self.during is not None:
            self.during()
        if self.outcome == "cancelled":
            raise OwnerApprovalRequiredError("owner cancelled the system prompt")
        return VerifiedOwnerPresence(
            owner_presence_module._PRESENCE_CONSTRUCTOR,
            binding=lease.binding,
            lease_id=lease.lease_id,
            verified_at_ns=lease.binding.expires_at_ns - 1,
        )


class ThreadedOwnerUiServer(uvicorn.Server):
    """Serve one already-bound loopback socket without touching signals."""

    def install_signal_handlers(self) -> None:
        return None


@dataclass(slots=True)
class LiveUi:
    """One running loopback owner UI plus the objects the journeys inspect."""

    paths: RuntimePaths
    origin: str
    exact_host: str
    bootstrap_url: str
    service: Any
    sessions: UiSessionStore
    approval: UiApprovalOrchestrator
    verifier: BrowserOwnerPresenceAdapter
    external_requests: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SyntheticWorld:
    """The exact synthetic records every journey navigates."""

    paths: RuntimePaths
    review_change_set_id: str
    review_batch_id: str
    english_source_id: str
    chinese_source_id: str
    malformed_source_id: str
    wrong_item_id: str
    historical_memory_id: str
    current_memory_id: str
    lineage_id: str
    applied_change_set_id: str


class UnusedFinder:
    def reveal_directory_url(self, directory_url: object) -> None:
        raise AssertionError("browser journeys never reveal a Finder window")


@pytest.fixture(scope="module", autouse=True)
def in_process_keychain() -> Iterator[None]:
    """Keep every browser journey inside an in-memory synthetic key boundary."""
    items: dict[tuple[str, str], str] = {}
    backend = type("Keyring", (), {})()
    type(backend).__module__ = "keyring.backends.macOS"
    type(backend).__qualname__ = "Keyring"
    original = (
        keyring.get_keyring,
        keyring.get_password,
        keyring.set_password,
        keys._store_master_key_exclusive,
    )
    keyring.get_keyring = lambda: backend
    keyring.get_password = lambda service, account: items.get(  # type: ignore[assignment]
        (service, account)
    )

    def set_password(service: str, account: str, value: str) -> None:
        base64.b64decode(value, validate=True)
        items[(service, account)] = value

    keyring.set_password = set_password  # type: ignore[assignment]
    keys._store_master_key_exclusive = lambda identity, encoded: (
        store_synthetic_key_exclusive(items, identity, encoded)
    )
    try:
        yield
    finally:
        (
            keyring.get_keyring,
            keyring.get_password,
            keyring.set_password,
            keys._store_master_key_exclusive,
        ) = original


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    """Launch one Chromium instance for every journey in this module."""
    with sync_playwright() as playwright:
        launched = playwright.chromium.launch(
            args=["--host-resolver-rules=MAP *.localhost 127.0.0.1"],
        )
        try:
            yield launched
        finally:
            launched.close()


def stage(paths: RuntimePaths, name: str, body: bytes) -> None:
    (paths.inbox / name).write_bytes(body)


def capture(
    paths: RuntimePaths,
    names: dict[str, bytes],
    *,
    sensitivity: Sensitivity = Sensitivity.RESTRICTED,
) -> tuple[str, dict[str, Any]]:
    """Stage exactly these files and seal one batch out of band."""
    before = {source.source_id for source in list_sources(paths, limit=100).items}
    for name, body in names.items():
        stage(paths, name, body)
    batch = scan_inbox(
        paths, sensitivity=sensitivity, policy=ScanPolicy(settle_seconds=0)
    )
    captured = {
        source.original_name: source
        for source in list_sources(paths, limit=100).items
        if source.source_id not in before
    }
    return batch.batch_id, captured


def apply_out_of_band(paths: RuntimePaths, change_set_id: str) -> ApplicationResult:
    view = get_change_set(paths, change_set_id)
    approval = review_module._mint_owner_approval(
        paths,
        change_set_id,
        view.revision_id,
        view.digest,
        adapter="mcp_elicitation",
    )
    return approve_and_apply(
        paths,
        change_set_id,
        view.revision_id,
        view.digest,
        approval,
    )


def build_world(paths: RuntimePaths) -> SyntheticWorld:
    """Create the historical lineage, current head, and one pending review."""
    red_batch_id, historical = capture(
        paths,
        {"syn-ui-browser-red.txt": HISTORICAL_SOURCE.encode("utf-8")},
    )
    red = historical["syn-ui-browser-red.txt"]
    first = create_change_set(
        paths,
        red_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    first = edit_change_set(
        paths,
        first.change_set_id,
        first.revision_id,
        (
            AddItem(
                client_item_id="SYN-UI-BROWSER-RED-001",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement=(
                        "Synthetic browser lineage: Rowan brings the red notebook."
                    ),
                    occurred_on=None,
                    valid_from="2026-11-18",
                    valid_to=None,
                    tags=("synthetic", "browser", "red-notebook"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=red.source_id,
                        blob_digest=red.blob_digest,
                        excerpt=HISTORICAL_SOURCE.strip(),
                    ),
                ),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    applied_first = apply_out_of_band(paths, first.change_set_id)
    historical_memory_id = applied_first.memory_ids[0]
    lineage_id = _lineage_of(paths, historical_memory_id)

    green_batch_id, current = capture(
        paths,
        {"syn-ui-browser-green.txt": CURRENT_SOURCE.encode("utf-8")},
    )
    green = current["syn-ui-browser-green.txt"]
    second = create_change_set(
        paths,
        green_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    second = edit_change_set(
        paths,
        second.change_set_id,
        second.revision_id,
        (
            AddItem(
                client_item_id="SYN-UI-BROWSER-GREEN-002",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement=(
                        "Synthetic browser lineage: Rowan brings the green notebook."
                    ),
                    occurred_on=None,
                    valid_from="2026-11-18",
                    valid_to=None,
                    tags=("synthetic", "browser", "green-notebook"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=lineage_id,
                    expected_head_id=historical_memory_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=green.source_id,
                        blob_digest=green.blob_digest,
                        excerpt=CURRENT_SOURCE.strip(),
                    ),
                ),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    applied_second = apply_out_of_band(paths, second.change_set_id)
    current_memory_id = applied_second.memory_ids[0]

    review_batch_id, review_sources = capture(
        paths,
        {
            "syn-ui-browser-plan.txt": ENGLISH_SOURCE.encode("utf-8"),
            "syn-ui-browser-中文.txt": CHINESE_SOURCE.encode("utf-8"),
            "syn-ui-browser-broken.png": MALFORMED_MEDIA,
        },
        sensitivity=Sensitivity.NORMAL,
    )
    english = review_sources["syn-ui-browser-plan.txt"]
    chinese = review_sources["syn-ui-browser-中文.txt"]
    malformed = review_sources["syn-ui-browser-broken.png"]
    review = create_change_set(
        paths,
        review_batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    review = edit_change_set(
        paths,
        review.change_set_id,
        review.revision_id,
        (
            AddItem(
                client_item_id="SYN-UI-BROWSER-WRONG-003",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement=(
                        "Synthetic browser journey: Mira keeps the amber folder."
                    ),
                    occurred_on=None,
                    valid_from="2026-12-04",
                    valid_to=None,
                    tags=("synthetic", "browser", "folder"),
                    sensitivity=Sensitivity.NORMAL,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=english.source_id,
                        blob_digest=english.blob_digest,
                        excerpt=ENGLISH_SOURCE.strip(),
                    ),
                ),
            ),
            SetSourceNoMemory(
                source_id=chinese.source_id,
                reason="Synthetic browser omission recorded for repair.",
            ),
            SetSourceNoMemory(
                source_id=malformed.source_id,
                reason="Synthetic malformed media carries no canonical memory.",
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    return SyntheticWorld(
        paths=paths,
        review_change_set_id=review.change_set_id,
        review_batch_id=review_batch_id,
        english_source_id=english.source_id,
        chinese_source_id=chinese.source_id,
        malformed_source_id=malformed.source_id,
        wrong_item_id=review.items[0].item_id,
        historical_memory_id=historical_memory_id,
        current_memory_id=current_memory_id,
        lineage_id=lineage_id,
        applied_change_set_id=second.change_set_id,
    )


def complex_edit_review(world: SyntheticWorld) -> ChangeSetView:
    """Fresh bilingual evidence at every edit capacity, including exact CRLFs."""
    excerpts = []
    for index in range(15):
        prefix = f"Synthetic owner edit evidence {index:02}.\r\n合成证据。"
        excerpts.append(
            prefix + "&" * (MAX_EVIDENCE_EXCERPT_BYTES - len(prefix.encode("utf-8")))
        )
    batch_id, sources = capture(
        world.paths,
        {
            "syn-owner-edit-text.txt": "\n".join(excerpts).encode("utf-8"),
            "syn-owner-edit-binary.bin": b"\x00\xffsynthetic-owner-edit-binary",
        },
        sensitivity=Sensitivity.NORMAL,
    )
    text_source = sources["syn-owner-edit-text.txt"]
    binary_source = sources["syn-owner-edit-binary.bin"]
    tags = []
    for index in range(64):
        prefix = f"syn-owner-tag-{index:02}\r\n"
        tags.append(prefix + "&" * (MAX_TAG_BYTES - len(prefix)))
    prefix = "Synthetic owner editing proposal.\r\n合成修订内容。"
    statement = prefix + "&" * (MAX_STATEMENT_BYTES - len(prefix.encode("utf-8")))
    draft = create_change_set(
        world.paths,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    binary_evidence = EvidenceInput(
        source_id=binary_source.source_id,
        blob_digest=binary_source.blob_digest,
        source_level=True,
    )
    return edit_change_set(
        world.paths,
        draft.change_set_id,
        draft.revision_id,
        (
            AddItem(
                client_item_id="SYN-OWNER-COMPLEX-EDIT",
                memory=MemoryFields(
                    kind=MemoryKind.RELATION,
                    statement=statement,
                    occurred_on="2042-03",
                    valid_from="2042",
                    valid_to="2043-04-05",
                    tags=tuple(tags),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=world.lineage_id,
                    expected_head_id=world.current_memory_id,
                ),
                evidence=(
                    *(
                        EvidenceInput(
                            source_id=text_source.source_id,
                            blob_digest=text_source.blob_digest,
                            excerpt=excerpt,
                        )
                        for excerpt in excerpts
                    ),
                    binary_evidence,
                ),
            ),
            AddItem(
                client_item_id="SYN-OWNER-SECOND-EDIT",
                memory=MemoryFields(
                    kind=MemoryKind.PREFERENCE,
                    statement="合成第二条提案：保留蓝色卡片。",
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=("synthetic-second",),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(binary_evidence,),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )


def opaque_item_edit_review(
    paths: RuntimePaths,
    *,
    include_third: bool = False,
    first_item_id: str = "SYN\r\nONE",
) -> ChangeSetView:
    """Two legal item IDs that collide only after HTML newline normalization."""
    batch_id, sources = capture(
        paths,
        {
            "syn-opaque-item-ids.txt": (
                "Synthetic first proposal records the amber card.\n"
                "合成第二条提案记录蓝色卡片。\n"
                "Synthetic third proposal records the green card.\n"
            ).encode()
        },
        sensitivity=Sensitivity.NORMAL,
    )
    source = sources["syn-opaque-item-ids.txt"]
    draft = create_change_set(
        paths, batch_id, adapter_origin=ChangeSetAdapterOrigin.MCP
    )
    return edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        tuple(
            AddItem(
                client_item_id=item_id,
                memory=MemoryFields(
                    kind=kind,
                    statement=statement,
                    occurred_on=None,
                    valid_from=None,
                    valid_to=None,
                    tags=(tag,),
                    sensitivity=Sensitivity.SENSITIVE,
                    target_lineage_id=None,
                    expected_head_id=None,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=source.source_id,
                        blob_digest=source.blob_digest,
                        excerpt=statement,
                    ),
                ),
            )
            for item_id, kind, statement, tag in (
                (
                    first_item_id,
                    MemoryKind.EVENT,
                    "Synthetic first proposal records the amber card.",
                    "synthetic-first",
                ),
                (
                    "SYN\nONE",
                    MemoryKind.INSIGHT,
                    "合成第二条提案记录蓝色卡片。",
                    "synthetic-second",
                ),
                *(
                    (
                        (
                            "SYN-THIRD",
                            MemoryKind.FACT,
                            "Synthetic third proposal records the green card.",
                            "synthetic-third",
                        ),
                    )
                    if include_third
                    else ()
                ),
            )
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )


def _lineage_of(paths: RuntimePaths, memory_id: str) -> str:
    from memory.memories import get_memory

    return get_memory(paths, memory_id).revision.lineage_id


@dataclass(frozen=True, slots=True)
class GuardDraft:
    """One pending review holding two claims and the link between them."""

    change_set_id: str
    guard_item_id: str
    governed_item_id: str


def _guard_item(
    item_id: str,
    source: Any,
    statement: str,
    excerpt: str,
    kind: MemoryKind,
) -> AddItem:
    return AddItem(
        client_item_id=item_id,
        memory=MemoryFields(
            kind=kind,
            statement=statement,
            occurred_on=None,
            valid_from="2026-10-01",
            valid_to=None,
            tags=("synthetic", "browser", "guard"),
            sensitivity=Sensitivity.NORMAL,
            target_lineage_id=None,
            expected_head_id=None,
        ),
        evidence=(
            EvidenceInput(
                source_id=source.source_id,
                blob_digest=source.blob_digest,
                excerpt=excerpt,
            ),
        ),
    )


def build_guard_draft(paths: RuntimePaths) -> GuardDraft:
    """Seal one batch whose draft proposes a claim, its caveat, and the link."""
    batch_id, captured = capture(
        paths,
        {
            "syn-ui-browser-claim.txt": GUARD_CLAIM_SOURCE.encode("utf-8"),
            "syn-ui-browser-hedge.txt": GUARD_HEDGE_SOURCE.encode("utf-8"),
        },
        sensitivity=Sensitivity.NORMAL,
    )
    draft = create_change_set(
        paths,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    drafted = edit_change_set(
        paths,
        draft.change_set_id,
        draft.revision_id,
        (
            _guard_item(
                GUARD_CLAIM_ITEM,
                captured["syn-ui-browser-claim.txt"],
                GUARD_CLAIM_STATEMENT,
                GUARD_CLAIM_EXCERPT,
                MemoryKind.FACT,
            ),
            _guard_item(
                GUARD_HEDGE_ITEM,
                captured["syn-ui-browser-hedge.txt"],
                GUARD_HEDGE_STATEMENT,
                GUARD_HEDGE_EXCERPT,
                MemoryKind.INSIGHT,
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    edit_change_set(
        paths,
        drafted.change_set_id,
        drafted.revision_id,
        (
            AddGuardLink(
                link=GuardLinkInput(
                    guard_item_id=GUARD_HEDGE_ITEM,
                    guard_lineage_id=None,
                    governed_item_id=GUARD_CLAIM_ITEM,
                    governed_lineage_id=None,
                )
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    return GuardDraft(
        change_set_id=drafted.change_set_id,
        guard_item_id=GUARD_HEDGE_ITEM,
        governed_item_id=GUARD_CLAIM_ITEM,
    )


@pytest.fixture
def runtime(tmp_path: Path) -> RuntimePaths:
    paths = resolve_runtime(tmp_path / "synthetic-browser-store")
    initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    return paths


@pytest.fixture
def world(runtime: RuntimePaths) -> SyntheticWorld:
    return build_world(runtime)


def serve(
    paths: RuntimePaths,
    verifier: BrowserOwnerPresenceAdapter | None = None,
) -> tuple[LiveUi, Callable[[], None]]:
    """Start one exact-origin owner UI on a random loopback port."""
    selected = BrowserOwnerPresenceAdapter() if verifier is None else verifier
    bound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound.bind(("127.0.0.1", 0))
    bound.listen(64)
    port = int(bound.getsockname()[1])
    public_host = f"memory-{secrets.token_hex(16)}.localhost"
    exact_host = f"{public_host}:{port}"
    origin = f"http://{exact_host}"
    capability = secrets.token_urlsafe(32)
    sessions = UiSessionStore(
        bootstrap_capability=capability,
        exact_host=exact_host,
        created_at_ns=time.monotonic_ns(),
    )
    service = OwnerApplicationService(
        paths,
        directory_authority=bind_runtime_directory_authority(paths),
    )
    approval = UiApprovalOrchestrator(
        service=service,
        sessions=sessions,
        attempts=ApprovalAttemptStore(),
        verifier=selected,
        clock=SystemMonotonicClock(),
    )
    application = create_ui_app(
        service,
        sessions,
        UnusedFinder(),
        approval,
        public_origin=origin,
    )
    server = ThreadedOwnerUiServer(
        uvicorn.Config(
            application,
            access_log=False,
            log_config=None,
            log_level="warning",
            lifespan="off",
        )
    )
    thread = threading.Thread(
        target=lambda: asyncio.run(server.serve(sockets=[bound])),
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "the owner UI did not start"
        time.sleep(0.02)

    live = LiveUi(
        paths=paths,
        origin=origin,
        exact_host=exact_host,
        bootstrap_url=f"{origin}/bootstrap#{capability}",
        service=service,
        sessions=sessions,
        approval=approval,
        verifier=selected,
    )

    def stop() -> None:
        server.should_exit = True
        thread.join(timeout=20)
        approval.shutdown()
        sessions.invalidate_all()
        bound.close()

    return live, stop


@pytest.fixture
def live(runtime: RuntimePaths) -> Iterator[LiveUi]:
    ui, stop = serve(runtime)
    try:
        yield ui
    finally:
        stop()


@contextmanager
def guarded_context(
    browser: Browser,
    live: LiveUi,
    **options: Any,
) -> Iterator[BrowserContext]:
    """Open one context that refuses and records every non-loopback request."""
    context = browser.new_context(**options)
    context.set_default_timeout(NAVIGATION_TIMEOUT_MS)
    context.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)

    def guard(route: Route) -> None:
        host = urllib.parse.urlsplit(route.request.url).netloc
        if host != live.exact_host:
            live.external_requests.append(route.request.url)
            route.abort()
            return
        route.continue_()

    context.route("**/*", guard)
    try:
        yield context
    finally:
        context.close()
        assert live.external_requests == []


@pytest.fixture
def page(browser: Browser, live: LiveUi) -> Iterator[Page]:
    """Open one guarded page for one journey."""
    with guarded_context(browser, live) as context:
        yield context.new_page()


def authenticate(page: Page, live: LiveUi) -> None:
    page.goto(live.bootstrap_url)
    page.wait_for_url(re.compile(rf"{re.escape(live.origin)}/(status|reviews)?$"))


def review_manifest(live: LiveUi, change_set_id: str) -> Any:
    return live.service.get_review_manifest(change_set_id)


def edit_url(live: LiveUi, change_set_id: str, operation: str) -> str:
    manifest = review_manifest(live, change_set_id)
    return (
        f"{live.origin}/reviews/{change_set_id}"
        f"/revisions/{manifest.revision.revision_id}/edits/{operation}"
    )


def submit_form(page: Page, selector: str = "form") -> None:
    page.locator(selector).locator('button[type="submit"]').first.click()


def disclose_technical_details(page: Page) -> None:
    """Open the collapsed disclosure every detail page keeps identifiers in."""
    page.locator("details.technical-details").first.evaluate("node => node.open = true")


def rendered_text(page: Page) -> str:
    """Return exactly what the owner can read, with collapsed content excluded."""
    return page.locator("body").inner_text()


def test_journey_01_bootstrap_creates_a_session_and_removes_the_fragment(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the one-use launch capability never survives in browser history."""
    page.goto(live.bootstrap_url)
    page.wait_for_url(re.compile(rf"{re.escape(live.origin)}/(status|reviews)?$"))

    assert "#" not in page.url
    assert page.evaluate("window.location.hash") == ""
    history = page.evaluate("window.history.length")
    assert isinstance(history, int)
    cookies = {cookie["name"] for cookie in page.context.cookies()}
    assert "memory_ui_session" in cookies
    expect(page.locator("h1")).to_have_count(1)

    replayed = page.request.post(
        f"{live.origin}/session",
        data=live.bootstrap_url.rsplit("#", 1)[1],
        headers={"Content-Type": "text/plain", "Origin": live.origin},
    )
    assert replayed.status == 401


def test_journey_02_absent_stale_and_cross_instance_sessions_are_refused(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove no content page renders without this exact process session."""
    authenticate(page, live)
    page.context.clear_cookies()

    absent = page.goto(f"{live.origin}/status")
    assert absent is not None and absent.status == 401

    page.context.add_cookies(
        [
            {
                "name": "memory_ui_session",
                "value": "synthetic-stale-session",
                "url": live.origin,
            }
        ]
    )
    stale = page.goto(f"{live.origin}/status")
    assert stale is not None and stale.status == 401

    other = UiSessionStore(
        bootstrap_capability=CROSS_INSTANCE,
        exact_host=live.exact_host,
        created_at_ns=time.monotonic_ns(),
    )
    foreign = other.exchange_bootstrap(
        secret=CROSS_INSTANCE,
        exact_host=live.exact_host,
        now_ns=time.monotonic_ns(),
    )
    assert foreign is not None
    page.context.clear_cookies()
    page.context.add_cookies(
        [
            {
                "name": "memory_ui_session",
                "value": foreign.session_id,
                "url": live.origin,
            }
        ]
    )
    cross = page.goto(f"{live.origin}/status")
    assert cross is not None and cross.status == 401


def test_journey_03_host_origin_and_csrf_are_exact_and_queries_stay_out_of_urls(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove exact-origin enforcement and owner search text absent from URLs."""
    authenticate(page, live)
    port = live.exact_host.rsplit(":", 1)[1]

    wrong_host = page.request.get(
        f"http://127.0.0.1:{port}/status",
        headers={"Host": f"127.0.0.1:{port}"},
    )
    assert wrong_host.status == 400
    sibling = page.request.get(
        f"{live.origin}/status",
        headers={"Host": f"memory-sibling.localhost:{port}"},
    )
    assert sibling.status == 400

    manifest = review_manifest(live, world.review_change_set_id)
    without_csrf = page.request.post(
        f"{live.origin}/reviews/{world.review_change_set_id}/approve",
        form={
            "revision_id": manifest.revision.revision_id,
            "digest": manifest.revision.digest,
        },
        headers={"Origin": live.origin},
    )
    assert without_csrf.status == 403
    wrong_origin = page.request.post(
        f"{live.origin}/memory/search",
        form={"query": "synthetic"},
        headers={"Origin": "http://attacker.localhost:1"},
    )
    assert wrong_origin.status == 403

    query = "米拉 rehearsal folder"
    page.goto(f"{live.origin}/sources")
    page.fill("#source-query", query)
    submit_form(page, 'form[action="/sources/search"]')
    page.wait_for_url(re.compile(r"/sources/search/[^/?]+$"))

    assert query not in page.url
    assert "米拉" not in page.url
    entries = page.evaluate(
        "Array.from(performance.getEntriesByType('navigation'))"
        ".concat(Array.from(performance.getEntriesByType('resource')))"
        ".map((entry) => entry.name)"
    )
    for entry in entries:
        assert query not in entry
        assert "rehearsal" not in entry


def test_journey_04_drag_and_drop_upload_stays_invisible_until_an_agent_scans(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove staging creates no Source, batch, or memory and hands off explicitly."""
    authenticate(page, live)
    page.goto(f"{live.origin}/inbox")
    expect(page.get_by_text(HANDOFF_COPY)).to_be_visible()
    expect(page.get_by_text("inbox.scan")).to_be_visible()
    assert page.locator('form[action="/inbox/scan"]').count() == 0
    assert page.locator('a[href="/inbox/scan"]').count() == 0
    missing = page.request.post(f"{live.origin}/inbox/scan")
    assert missing.status in (401, 403, 404, 405)

    before = live.service.get_status()

    page.route("**/inbox/upload", lambda route: route.abort())
    drop_file(page, "syn-ui-browser-interrupted.txt", b"Synthetic interrupted body.\n")
    submit_form(page, 'form[action="/inbox/upload"]')
    expect(page.locator("body")).to_contain_text("Request unavailable")
    page.unroute("**/inbox/upload")
    page.goto(f"{live.origin}/inbox")
    assert page.locator("[data-staged-row]").count() == 0

    drop_generated_file(
        page,
        "syn-ui-browser-oversized.txt",
        MAX_UPLOAD_FILE_BYTES + 1024,
    )
    submit_form(page, 'form[action="/inbox/upload"]')
    expect(page.locator("body")).to_contain_text(
        "Request unavailable",
        timeout=120_000,
    )
    page.goto(f"{live.origin}/inbox")
    assert page.locator("[data-staged-row]").count() == 0

    drop_file(page, UPLOAD_NAME, UPLOAD_BODY)
    submit_form(page, 'form[action="/inbox/upload"]')
    page.wait_for_url(re.compile(r"/inbox(\?|$)"))
    rows = page.locator("[data-staged-row]")
    expect(rows).to_have_count(1)
    expect(rows.first).to_contain_text(UPLOAD_NAME)
    expect(rows.first).to_contain_text(str(len(UPLOAD_BODY)))
    expect(page.locator('[data-ui="inbox-count"]')).to_have_text("1")

    drop_file(page, UPLOAD_NAME, UPLOAD_BODY)
    submit_form(page, 'form[action="/inbox/upload"]')
    expect(page.locator("body")).to_contain_text("Request unavailable")
    page.goto(f"{live.origin}/inbox")
    rows = page.locator("[data-staged-row]")
    expect(rows).to_have_count(1)
    expect(rows.first).to_contain_text(str(len(UPLOAD_BODY)))

    after_staging = live.service.get_status()
    assert after_staging.store.source_count == before.store.source_count
    assert after_staging.store.memory_count == before.store.memory_count
    assert after_staging.pending_review_count == before.pending_review_count

    scan_inbox(live.paths, policy=ScanPolicy(settle_seconds=0))
    page.goto(f"{live.origin}/inbox")
    expect(page.locator("[data-staged-row]")).to_have_count(0)
    after_scan = live.service.get_status()
    assert after_scan.store.source_count == before.store.source_count + 1
    assert after_scan.store.memory_count == before.store.memory_count


def drop_file(page: Page, name: str, payload: bytes) -> None:
    """Dispatch one real drag/drop that populates the file input."""
    encoded = base64.b64encode(payload).decode("ascii")
    handle = page.evaluate_handle(
        """([name, encoded]) => {
            const binary = atob(encoded);
            const bytes = new Uint8Array(binary.length);
            for (let index = 0; index < binary.length; index += 1) {
                bytes[index] = binary.charCodeAt(index);
            }
            const transfer = new DataTransfer();
            transfer.items.add(new File([bytes], name, {type: "text/plain"}));
            return transfer;
        }""",
        [name, encoded],
    )
    page.dispatch_event("form[data-drop-zone]", "drop", {"dataTransfer": handle})


def drop_generated_file(page: Page, name: str, size: int) -> None:
    """Dispatch one drag/drop whose oversized bytes never cross the driver."""
    handle = page.evaluate_handle(
        """([name, size]) => {
            const bytes = new Uint8Array(size).fill(83);
            const transfer = new DataTransfer();
            transfer.items.add(new File([bytes], name, {type: "text/plain"}));
            return transfer;
        }""",
        [name, size],
    )
    page.dispatch_event("form[data-drop-zone]", "drop", {"dataTransfer": handle})


def test_journey_05_complete_source_and_historical_memory_inspection(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove full retained text and historical revisions stay inspectable."""
    authenticate(page, live)
    page.goto(f"{live.origin}/sources/{world.english_source_id}")
    expect(page.locator("pre.source-content")).to_contain_text(ENGLISH_SOURCE.strip())

    page.goto(f"{live.origin}/sources/{world.chinese_source_id}")
    expect(page.locator("pre.source-content")).to_contain_text(CHINESE_SOURCE.strip())

    page.goto(f"{live.origin}/memories/{world.historical_memory_id}")
    expect(page.get_by_text("Historical revision")).to_be_visible()
    expect(page.locator(".memory-statement")).to_contain_text("red notebook")
    expect(
        page.locator(f'[data-lineage-id="{world.current_memory_id}"]')
    ).to_be_visible()
    page.click(f'[data-lineage-id="{world.current_memory_id}"] a')
    page.wait_for_url(re.compile(rf"/memories/{re.escape(world.current_memory_id)}$"))
    expect(page.get_by_text("Current revision", exact=True)).to_be_visible()


def test_journey_05b_review_preview_direct_navigation_and_applicability(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the new owner cues and exact-item route in a real browser."""
    authenticate(page, live)
    page.goto(f"{live.origin}/reviews/{world.review_change_set_id}")
    roster = page.locator(f'[data-roster-item="{world.wrong_item_id}"]')
    expect(roster).to_contain_text(
        "Synthetic browser journey: Mira keeps the amber folder."
    )
    roster.locator("a").click()
    page.wait_for_url(
        re.compile(
            rf"/reviews/.+/revisions/.+/items/lookup/exact\?item_id="
            rf"{re.escape(world.wrong_item_id)}$"
        )
    )
    expect(page.locator(f'[data-review-item="{world.wrong_item_id}"]')).to_be_visible()
    expect(page.get_by_text("Open complete retained source")).to_be_visible()

    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    expect(page.get_by_text("Current revision", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Applicability")).to_be_visible()
    expect(page.get_by_text("No end date recorded", exact=True).first).to_be_visible()
    expect(
        page.get_by_text("Revision status and applicability are separate.")
    ).to_be_visible()


@pytest.mark.parametrize("explicit_item", (False, True))
def test_owner_edit_preserves_opaque_item_id_when_saving_wording(
    page: Page, live: LiveUi, explicit_item: bool
) -> None:
    """Catch a CRLF item ID becoming its LF sibling and overwriting that item."""
    original = opaque_item_edit_review(live.paths)
    first, second = original.items
    authenticate(page, live)
    location = edit_url(live, original.change_set_id, "replace_item")
    if explicit_item:
        location += "?" + urllib.parse.urlencode({"item_id": first.item_id})
    page.goto(location)
    expect(page.locator("#edit-statement")).to_have_value(first.memory.statement)
    statement = "Synthetic first proposal now records a revised amber card."
    page.fill("#edit-statement", statement)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    revised = get_change_set(live.paths, original.change_set_id)
    assert revised.items[1] == second
    assert revised.items[0].memory == replace(first.memory, statement=statement)
    assert revised.items[0].item_id == first.item_id
    assert revised.items[0].evidence == first.evidence


def test_owner_edit_selects_exact_opaque_item_ids_without_aliasing(
    page: Page, live: LiveUi
) -> None:
    """Catch selecting one newline spelling opening the sibling's proposal."""
    original = opaque_item_edit_review(live.paths)
    first, second = original.items
    authenticate(page, live)
    location = edit_url(live, original.change_set_id, "replace_item")
    page.goto(location + "?" + urllib.parse.urlencode({"item_id": second.item_id}))

    page.select_option("#edit-item-id", index=0)
    page.wait_for_url(
        location + "?" + urllib.parse.urlencode({"item_id": first.item_id})
    )
    expect(page.locator("#edit-item-id")).to_have_value(first.item_id)
    expect(page.locator("#edit-statement")).to_have_value(first.memory.statement)
    expect(page.locator('form[data-review-edit] input[name="item_id"]')).to_have_value(
        first.item_id
    )

    page.select_option("#edit-item-id", index=1)
    page.wait_for_url(
        location + "?" + urllib.parse.urlencode({"item_id": second.item_id})
    )
    expect(page.locator("#edit-item-id")).to_have_value(second.item_id)
    expect(page.locator("#edit-statement")).to_have_value(second.memory.statement)
    assert get_change_set(live.paths, original.change_set_id) == original


@pytest.mark.parametrize("selection", ("single", "bulk_one", "bulk_both"))
def test_owner_review_rejects_and_restores_exact_opaque_ids(
    page: Page, live: LiveUi, selection: str
) -> None:
    """Catch newline aliasing or unchecked and repeated-name bulk values changing."""
    original = opaque_item_edit_review(live.paths, include_third=True)
    authenticate(page, live)
    selected = (0, 1) if selection == "bulk_both" else (0,)
    for operation, status in (("reject_item", "rejected"), ("restore_item", "active")):
        if selection == "single":
            page.goto(edit_url(live, original.change_set_id, operation))
            page.select_option("#edit-item-id", index=0)
            form = "form[data-review-edit]"
        else:
            page.goto(f"{live.origin}/reviews/{original.change_set_id}")
            form = f'form[data-bulk-edit="{operation}"]'
            for index in selected:
                page.locator(form).locator('input[name="item_id"]').nth(index).check()
        with page.expect_navigation(wait_until="load"):
            submit_form(page, form)
        revised = get_change_set(live.paths, original.change_set_id)
        assert revised.items == tuple(
            replace(item, status=status) if index in selected else item
            for index, item in enumerate(original.items)
        )


def test_owner_review_guard_removal_keeps_exact_opaque_endpoints(
    page: Page, live: LiveUi
) -> None:
    """Catch removing a CRLF guard's link deleting the LF sibling's link."""
    original = opaque_item_edit_review(live.paths)
    first, second = original.items
    links = tuple(
        GuardLinkInput(
            guard_item_id=item.item_id,
            guard_lineage_id=None,
            governed_item_id="SYN-GOVERNED",
            governed_lineage_id=None,
        )
        for item in original.items
    )
    original = edit_change_set(
        live.paths,
        original.change_set_id,
        original.revision_id,
        (
            AddItem(
                client_item_id="SYN-GOVERNED",
                memory=replace(first.memory, statement="Synthetic governed card."),
                evidence=first.evidence,
            ),
            *(AddGuardLink(link=link) for link in links),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "remove_guard_link"))
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    revised = get_change_set(live.paths, original.change_set_id)
    assert len(revised.guard_links) == 1
    assert revised.guard_links[0].guard_item_id == second.item_id
    assert revised.guard_links[0].governed_item_id == "SYN-GOVERNED"
    assert revised.items == original.items


def test_owner_review_guard_authoring_selects_exact_opaque_endpoints(
    page: Page, live: LiveUi
) -> None:
    """Catch an owner being unable to select a legal draft ID without rewriting it."""
    original = opaque_item_edit_review(live.paths)
    first, second = original.items
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "add_guard_link"))
    page.select_option("#edit-guard-item", first.item_id)
    page.select_option("#edit-governed-item", second.item_id)
    submit_form(page, "form[aria-label='Add guard link']")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    revised = get_change_set(live.paths, original.change_set_id)
    assert len(revised.guard_links) == 1
    assert revised.guard_links[0].guard_item_id == first.item_id
    assert revised.guard_links[0].governed_item_id == second.item_id
    assert revised.items == original.items


def test_owner_review_accepts_maximum_unicode_ids_through_guard_retry_and_status(
    page: Page, live: LiveUi
) -> None:
    """Catch the UI's reference codec imposing bytes where the Store allows chars."""
    original = opaque_item_edit_review(live.paths, first_item_id="合" * 256)
    first, second = original.items
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "add_guard_link"))
    page.select_option("#edit-guard-item", first.item_id)
    page.select_option("#edit-governed-item", second.item_id)
    with _writer_lock(live.paths):
        submit_form(page, "form[aria-label='Add guard link']")
        page.wait_for_url(re.compile(r"/pending/|[?]refused="))
        assert "/pending/" in page.url
        assert get_change_set(live.paths, original.change_set_id) == original

    submit_form(page, "form[aria-label='Retry the owner edit']")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    linked = get_change_set(live.paths, original.change_set_id)
    assert len(linked.guard_links) == 1
    assert linked.guard_links[0].guard_item_id == first.item_id
    assert linked.guard_links[0].governed_item_id == second.item_id
    for operation, status in (("reject_item", "rejected"), ("restore_item", "active")):
        page.goto(edit_url(live, original.change_set_id, operation))
        page.select_option("#edit-item-id", first.item_id)
        with page.expect_navigation(wait_until="load"):
            submit_form(page, "form[data-review-edit]")
        revised = get_change_set(live.paths, original.change_set_id)
        assert revised.items[0] == replace(first, status=status)
        assert revised.items[1] == second


def test_owner_edit_wording_only_preserves_full_capacity_proposal(
    page: Page, live: LiveUi, world: SyntheticWorld
) -> None:
    """Catch browser defaults, line endings or hidden capacity losing metadata."""
    original = complex_edit_review(world)
    selected = original.items[0]
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "replace_item"))

    expect(page.locator("#edit-kind")).to_have_value("relation")
    expect(page.locator("#edit-sensitivity")).to_have_value("restricted")
    expect(page.locator("#edit-target-lineage")).to_have_value(world.lineage_id)
    expect(page.locator("#edit-expected-head")).to_have_value(world.current_memory_id)
    expect(page.locator('textarea[name="tag.63"]')).to_have_value(
        selected.memory.tags[63].replace("\r\n", "\n")
    )
    excerpt = selected.evidence[14].excerpt
    assert excerpt is not None
    expect(page.locator('textarea[name="evidence.14.excerpt"]')).to_have_value(
        excerpt.replace("\r\n", "\n")
    )
    expect(page.locator('input[name="evidence.15.source_level"]')).to_be_checked()

    # A no-op replacement must preserve the exact canonical bytes, including
    # line endings HTML controls normalize while presenting them.
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    unchanged = get_change_set(world.paths, original.change_set_id)
    assert unchanged.items == original.items
    assert unchanged.digest != original.digest

    page.goto(edit_url(live, original.change_set_id, "replace_item"))
    statement = "Synthetic revised wording. 合成提案仅修改措辞。"
    page.fill("#edit-statement", statement)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    revised = get_change_set(world.paths, original.change_set_id)
    assert revised.items[0].memory == replace(selected.memory, statement=statement)
    assert revised.items[0].evidence == selected.evidence
    assert revised.items[1] == original.items[1]
    assert revised.state == "draft"


def test_owner_edit_selection_reloads_exact_values_after_a_refusal(
    page: Page, live: LiveUi, world: SyntheticWorld
) -> None:
    """Catch retained edits for one item being posted onto a different item."""
    original = complex_edit_review(world)
    first, second = original.items
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "replace_item"))
    page.fill("#edit-occurred-on", "2042-19")
    page.fill("#edit-statement", "Synthetic unsaved first-item wording.")
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"[?]refused="))
    expect(page.locator("[data-review-refusal]")).to_be_visible()
    expect(page.locator("#edit-occurred-on")).to_have_value("2042-19")
    expect(page.locator('textarea[name="tag.63"]')).to_have_value(
        first.memory.tags[63].replace("\r\n", "\n")
    )
    expect(page.locator('input[name="evidence.15.source_level"]')).to_be_checked()
    assert get_change_set(world.paths, original.change_set_id).items == original.items

    page.select_option("#edit-item-id", second.item_id)
    page.wait_for_url(re.compile(r"[?]item_id=SYN-OWNER-SECOND-EDIT$"))
    assert "refused=" not in page.url
    expect(page.locator("[data-review-refusal]")).to_have_count(0)
    expect(page.locator("#edit-statement")).to_have_value(second.memory.statement)
    expect(page.locator("#edit-kind")).to_have_value("preference")
    expect(page.locator("#edit-sensitivity")).to_have_value("sensitive")
    expect(page.locator("#edit-occurred-on")).to_have_value("")
    expect(page.locator("#edit-target-lineage")).to_have_value("")
    expect(page.locator("#edit-expected-head")).to_have_value("")
    expect(page.locator('textarea[name="tag.0"]')).to_have_value("synthetic-second")
    expect(page.locator('textarea[name="tag.63"]')).to_have_value("")
    expect(page.locator('input[name="evidence.0.source_level"]')).to_be_checked()
    expect(page.locator('input[name="evidence.15.source_level"]')).not_to_be_checked()
    expect(page.locator('textarea[name="evidence.0.excerpt"]')).to_have_value("")

    statement = "合成第二条提案：蓝色卡片仍然保留。"
    page.fill("#edit-statement", statement)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    revised = get_change_set(world.paths, original.change_set_id)
    assert revised.items[0] == first
    assert revised.items[1].memory == replace(second.memory, statement=statement)
    assert revised.items[1].evidence == second.evidence


def test_owner_edit_cancelled_selection_keeps_the_loaded_target(
    page: Page, live: LiveUi, world: SyntheticWorld
) -> None:
    """Catch a cancelled navigation relabelling unsaved fields as another item."""
    original = complex_edit_review(world)
    first, second = original.items
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "replace_item"))
    statement = "Synthetic wording held while the owner considers switching."
    page.fill("#edit-statement", statement)

    page.once("dialog", lambda dialog: dialog.dismiss())
    page.select_option("#edit-item-id", second.item_id)
    expect(page.locator("#edit-item-id")).to_have_value(first.item_id)
    expect(page.locator("#edit-statement")).to_have_value(statement)
    expect(page.locator('form[data-review-edit] input[name="item_id"]')).to_have_value(
        first.item_id
    )

    page.once("dialog", lambda dialog: dialog.accept())
    page.select_option("#edit-item-id", second.item_id)
    page.wait_for_url(re.compile(r"[?]item_id=SYN-OWNER-SECOND-EDIT$"))
    expect(page.locator("#edit-statement")).to_have_value(second.memory.statement)
    assert get_change_set(world.paths, original.change_set_id).items == original.items


def test_owner_edit_can_change_the_last_tag_and_evidence_slots(
    page: Page, live: LiveUi, world: SyntheticWorld
) -> None:
    """Catch added controls rendering at capacity while edits to them vanish."""
    original = complex_edit_review(world)
    first = original.items[0]
    authenticate(page, live)
    page.goto(edit_url(live, original.change_set_id, "replace_item"))
    page.fill('textarea[name="tag.63"]', "合成末尾标签\n保留第二行")
    page.fill(
        'textarea[name="evidence.14.excerpt"]', "Synthetic owner edit evidence 14."
    )
    page.select_option('select[name="evidence.15.source_id"]', "")
    page.uncheck('input[name="evidence.15.source_level"]')
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    revised = get_change_set(world.paths, original.change_set_id)
    assert revised.items[0].memory == replace(
        first.memory, tags=(*first.memory.tags[:-1], "合成末尾标签\n保留第二行")
    )
    assert revised.items[0].evidence[:-1] == first.evidence[:14]
    start = first.evidence[14].char_start
    assert start is not None
    assert revised.items[0].evidence[-1] == replace(
        first.evidence[14],
        excerpt="Synthetic owner edit evidence 14.",
        char_end=start + len("Synthetic owner edit evidence 14."),
    )
    assert revised.items[1] == original.items[1]


def test_journey_06_wrong_no_memory_is_repaired_through_clear_add_and_evidence(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove an omitted source regains complete accounting inside the UI."""
    authenticate(page, live)
    page.goto(edit_url(live, world.review_change_set_id, "clear_source_no_memory"))
    page.select_option("#edit-source-id", world.chinese_source_id)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    manifest = review_manifest(live, world.review_change_set_id)
    coverage = {
        decision.source_id: decision.coverage for decision in manifest.source_roster
    }
    assert coverage[world.chinese_source_id] == "unaccounted"

    page.goto(edit_url(live, world.review_change_set_id, "add_item"))
    page.select_option("#edit-kind", "fact")
    page.fill("#edit-statement", "米拉在排练中携带蓝色文件夹。")
    page.fill("#edit-valid-from", "2026-12-04")
    page.select_option("#edit-sensitivity", "normal")
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.select_option('select[name="evidence.0.source_id"]', world.chinese_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', CHINESE_SOURCE.strip())
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    repaired = review_manifest(live, world.review_change_set_id)
    coverage = {
        decision.source_id: decision.coverage for decision in repaired.source_roster
    }
    assert coverage[world.chinese_source_id] == "used"
    assert repaired.revision.unaccounted_source_count == 0


def test_journey_07_all_six_edit_operations_change_the_canonical_digest(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove every bounded operation creates one new immutable revision."""
    authenticate(page, live)
    digests = [review_manifest(live, world.review_change_set_id).revision.digest]

    page.goto(edit_url(live, world.review_change_set_id, "replace_item"))
    page.select_option("#edit-item-id", world.wrong_item_id)
    page.select_option("#edit-kind", "fact")
    page.fill("#edit-statement", "Mira keeps the blue folder for the rehearsal.")
    page.select_option("#edit-sensitivity", "normal")
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.select_option('select[name="evidence.0.source_id"]', world.english_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', ENGLISH_SOURCE.strip())
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    page.goto(edit_url(live, world.review_change_set_id, "reject_item"))
    page.select_option("#edit-item-id", world.wrong_item_id)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    page.goto(edit_url(live, world.review_change_set_id, "restore_item"))
    page.select_option("#edit-item-id", world.wrong_item_id)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    page.goto(edit_url(live, world.review_change_set_id, "clear_source_no_memory"))
    page.select_option("#edit-source-id", world.chinese_source_id)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    page.goto(edit_url(live, world.review_change_set_id, "set_source_no_memory"))
    page.select_option("#edit-source-id", world.chinese_source_id)
    page.fill("#edit-reason", "Synthetic browser decision: no canonical memory.")
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    page.goto(edit_url(live, world.review_change_set_id, "add_item"))
    page.select_option("#edit-kind", "insight")
    page.fill("#edit-statement", "Synthetic browser added interpretation.")
    page.select_option("#edit-sensitivity", "normal")
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.select_option('select[name="evidence.0.source_id"]', world.english_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', ENGLISH_SOURCE.strip())
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    digests.append(review_manifest(live, world.review_change_set_id).revision.digest)

    assert len(digests) == 7
    assert len(set(digests)) == 7
    manifest = review_manifest(live, world.review_change_set_id)
    assert manifest.revision.adapter_origin.value == "owner_ui"


def test_journey_08_a_stale_edit_applies_nothing_and_needs_one_explicit_retry(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a superseded edit shows both revisions and rebases nothing silently."""
    authenticate(page, live)
    stale_url = edit_url(live, world.review_change_set_id, "reject_item")
    stale_manifest = review_manifest(live, world.review_change_set_id)
    page.goto(stale_url)
    page.select_option("#edit-item-id", world.wrong_item_id)

    edit_change_set(
        live.paths,
        world.review_change_set_id,
        stale_manifest.revision.revision_id,
        (ClearSourceNoMemory(source_id=world.malformed_source_id),),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    current = review_manifest(live, world.review_change_set_id)

    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+/pending/[^/]+$"))
    expect(page.get_by_role("heading", name="Owner edit conflict")).to_be_visible()
    expect(page.locator("[data-conflict-old-target]")).to_be_visible()
    expect(page.locator("[data-conflict-current-target]")).to_be_visible()
    expect(page.get_by_text(stale_manifest.revision.revision_id)).to_be_visible()
    expect(page.get_by_text(current.revision.revision_id)).to_be_visible()
    assert (
        review_manifest(live, world.review_change_set_id).revision.revision_id
        == current.revision.revision_id
    )

    page.locator('form[action$="/current"] button[type="submit"]').click()
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    retried = review_manifest(live, world.review_change_set_id)
    assert retried.revision.revision_id != current.revision.revision_id
    statuses = {item.item_id: item.status for item in retried.item_roster}
    assert statuses[world.wrong_item_id] == "rejected"


def test_journey_09_cancelled_owner_presence_applies_nothing(
    browser: Browser,
    runtime: RuntimePaths,
) -> None:
    """Prove a declined OS decision leaves the review unapplied."""
    world = build_world(runtime)
    ui, stop = serve(runtime, BrowserOwnerPresenceAdapter(outcome="cancelled"))
    guarded = guarded_context(browser, ui)
    page = guarded.__enter__().new_page()
    try:
        authenticate(page, ui)
        manifest = review_manifest(ui, world.review_change_set_id)
        page.goto(f"{ui.origin}/reviews/{world.review_change_set_id}")
        page.request.post(
            f"{ui.origin}/reviews/{world.review_change_set_id}/approve",
            form={
                "revision_id": manifest.revision.revision_id,
                "digest": manifest.revision.digest,
            },
            headers={
                "Origin": ui.origin,
                "X-Memory-CSRF": _csrf(page),
            },
        )
        page.goto(f"{ui.origin}/reviews/{world.review_change_set_id}")
        prepared = page.request.post(
            f"{ui.origin}/reviews/{world.review_change_set_id}/approve",
            form={
                "revision_id": manifest.revision.revision_id,
                "digest": manifest.revision.digest,
            },
            headers={"Origin": ui.origin, "X-Memory-CSRF": _csrf(page)},
            max_redirects=0,
        )
        assert prepared.status == 303
        page.goto(f"{ui.origin}{prepared.headers['location']}")
        expect(page.locator("[data-approval-revision]")).to_be_visible()
        canonical_review = page.locator("[data-approval-canonical-review]")
        expect(canonical_review).to_be_visible()
        expect(canonical_review).to_contain_text(manifest.revision.digest)
        expect(canonical_review).to_contain_text('"source_decisions"')
        submit_form(page, "form[data-review-approval]")
        page.wait_for_timeout(500)

        assert ui.verifier.calls == 1
        assert get_change_set(runtime, world.review_change_set_id).state == "draft"
        assert ui.service.get_status().store.memory_count == 1
    finally:
        guarded.__exit__(None, None, None)
        stop()


def _csrf(page: Page) -> str:
    csrf = page.get_attribute("meta[name=memory-csrf]", "content")
    assert csrf is not None
    return csrf


def test_journey_10_correction_from_history_resolves_the_current_head(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove correction capture is one isolated owner/restricted source batch."""
    authenticate(page, live)
    other = live.paths.inbox / "syn-ui-browser-unrelated.txt"
    other.write_bytes(b"Synthetic unrelated inbox file that must not co-batch.\n")

    page.goto(f"{live.origin}/memories/{world.historical_memory_id}")
    submit_form(page, 'form[action$="/corrections"]')
    page.wait_for_url(re.compile(r"/memory/corrections/[^/]+$"))
    expect(page.get_by_role("heading", name="Owner correction")).to_be_visible()
    expect(page.get_by_text("Current head")).to_be_visible()
    page.fill(
        "#owner-correction-text",
        "The current memory is wrong. Rowan should bring the blue notebook.",
    )
    submit_form(page, "form[aria-label='Owner correction']")
    page.wait_for_url(re.compile(r"/inbox"))

    expect(page.get_by_text("Captured; awaiting Memory Review")).to_be_visible()
    batch_link = page.locator("[data-correction-batch] a").first
    batch_id = batch_link.inner_text()
    batch_link.click()
    page.wait_for_url(re.compile(r"/inbox/batches/[^/]+$"))
    sources = page.locator("[data-batch-source]")
    expect(sources).to_have_count(1)
    sources.first.locator("a").click()
    page.wait_for_url(re.compile(r"/sources/[^/?]+$"))
    expect(page.locator("dl div", has_text="Capture origin")).to_contain_text(
        "owner_correction"
    )
    expect(page.locator("dl div", has_text="Authorship")).to_contain_text("owner")
    expect(page.locator("dl div", has_text="Effective sensitivity")).to_contain_text(
        "restricted"
    )
    assert other.exists()
    assert batch_id


def test_journey_11_a_stale_correction_head_refuses_to_apply(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a superseded expected head blocks the edit and later the approval."""
    authenticate(page, live)
    before = review_manifest(live, world.review_change_set_id).revision.revision_id

    fill_correction_item(page, live, world, expected_head=world.historical_memory_id)
    submit_form(page, "form[data-review-edit]")
    # The shell never fakes success and never blanks to a bare error either:
    # the refusal names the stale head and the whole form comes back filled in.
    refusal = page.locator("[data-review-refusal]")
    expect(refusal).to_be_visible()
    expect(refusal).to_contain_text("correction target is stale")
    expect(page.locator("body")).not_to_contain_text("Request unavailable")
    expect(page.locator("#edit-expected-head")).to_have_value(
        world.historical_memory_id
    )
    expect(page.locator("#edit-statement")).to_have_value(
        "Rowan should bring the blue notebook."
    )
    assert world.historical_memory_id not in page.url
    assert (
        review_manifest(live, world.review_change_set_id).revision.revision_id == before
    )

    fill_correction_item(page, live, world, expected_head=world.current_memory_id)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    accepted = review_manifest(live, world.review_change_set_id)
    assert accepted.revision.revision_id != before
    assert accepted.validation_state != "blocked"

    advance_lineage(live.paths, world)

    stale = review_manifest(live, world.review_change_set_id)
    assert stale.validation_state == "blocked"
    page.goto(
        f"{live.origin}/reviews/{world.review_change_set_id}"
        f"/revisions/{stale.revision.revision_id}/blockers"
    )
    expect(page.locator("[data-blocker-row]").first).to_be_visible()
    expect(page.locator("[data-blocker-row]").first).to_contain_text(
        world.current_memory_id
    )
    refused = page.request.post(
        f"{live.origin}/reviews/{world.review_change_set_id}/approve",
        form={
            "revision_id": stale.revision.revision_id,
            "digest": stale.revision.digest,
        },
        headers={"Origin": live.origin, "X-Memory-CSRF": _csrf(page)},
        max_redirects=0,
    )
    assert refused.status >= 400
    assert get_change_set(live.paths, world.review_change_set_id).state == "draft"


def fill_correction_item(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
    *,
    expected_head: str,
) -> None:
    """Open one replace_item form bound to an exact lineage and expected head."""
    page.goto(edit_url(live, world.review_change_set_id, "replace_item"))
    page.select_option("#edit-item-id", world.wrong_item_id)
    page.select_option("#edit-kind", "fact")
    page.fill("#edit-statement", "Rowan should bring the blue notebook.")
    page.select_option("#edit-sensitivity", "restricted")
    page.fill("#edit-target-lineage", world.lineage_id)
    page.fill("#edit-expected-head", expected_head)
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.select_option('select[name="evidence.0.source_id"]', world.english_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', ENGLISH_SOURCE.strip())


def advance_lineage(paths: RuntimePaths, world: SyntheticWorld) -> str:
    """Apply one out-of-band successor so the draft's expected head goes stale."""
    batch_id, captured = capture(
        paths,
        {
            "syn-ui-browser-amber.txt": (
                b"Synthetic browser lineage changed again: Rowan brings the amber "
                b"notebook on 2026-11-18.\n"
            )
        },
    )
    amber = captured["syn-ui-browser-amber.txt"]
    view = create_change_set(paths, batch_id, adapter_origin=ChangeSetAdapterOrigin.MCP)
    view = edit_change_set(
        paths,
        view.change_set_id,
        view.revision_id,
        (
            AddItem(
                client_item_id="SYN-UI-BROWSER-AMBER-004",
                memory=MemoryFields(
                    kind=MemoryKind.FACT,
                    statement=(
                        "Synthetic browser lineage: Rowan brings the amber notebook."
                    ),
                    occurred_on=None,
                    valid_from="2026-11-18",
                    valid_to=None,
                    tags=("synthetic", "browser", "amber-notebook"),
                    sensitivity=Sensitivity.RESTRICTED,
                    target_lineage_id=world.lineage_id,
                    expected_head_id=world.current_memory_id,
                ),
                evidence=(
                    EvidenceInput(
                        source_id=amber.source_id,
                        blob_digest=amber.blob_digest,
                        excerpt="Rowan brings the amber notebook on 2026-11-18.",
                    ),
                ),
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    return apply_out_of_band(paths, view.change_set_id).memory_ids[0]


def test_journey_12_audit_traverses_source_application_and_memory(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove in-app audit reaches every authoritative record without export."""
    authenticate(page, live)
    page.goto(f"{live.origin}/audit")
    page.locator("[data-audit-begin]").click()
    page.wait_for_selector("[data-audit-generation]", state="attached")
    page.locator("details summary").first.click()
    expect(page.locator("[data-audit-generation]")).to_be_visible()
    expect(page.locator("[data-audit-count-sources]")).to_be_visible()
    assert page.get_by_text("no archive").count() >= 1

    # Provenance links now live inside the memory page's Technical details
    # disclosure. The traversal is unchanged; reaching it costs one open.
    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    disclose_technical_details(page)
    page.get_by_role("link", name=re.compile("^Application ")).click()
    page.wait_for_url(re.compile(r"/audit/applications/[^/?]+"))
    expect(page.locator("h1")).to_have_count(1)
    page.go_back()
    disclose_technical_details(page)
    page.get_by_role("link", name=re.compile("^Approval ")).click()
    page.wait_for_url(re.compile(r"/audit/approvals/[^/?]+"))
    expect(page.locator("h1")).to_have_count(1)


def test_journey_13_busy_writer_keeps_post_redirect_get_and_needs_one_retry(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove writer contention never double-applies and never loses the edit."""
    authenticate(page, live)
    page.goto(edit_url(live, world.review_change_set_id, "reject_item"))
    page.select_option("#edit-item-id", world.wrong_item_id)
    before = review_manifest(live, world.review_change_set_id).revision.revision_id

    with _writer_lock(live.paths):
        submit_form(page, "form[data-review-edit]")
        page.wait_for_url(re.compile(r"/reviews/[^/]+/pending/[^/]+$"))
        expect(page.get_by_role("heading", name="Retry the owner edit")).to_be_visible()
        expect(page.locator("[data-pending-proposed-change]")).to_be_visible()
        assert (
            review_manifest(live, world.review_change_set_id).revision.revision_id
            == before
        )

    submit_form(page, "form[aria-label='Retry the owner edit']")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    after = review_manifest(live, world.review_change_set_id)
    assert after.revision.revision_id != before
    statuses = {item.item_id: item.status for item in after.item_roster}
    assert statuses[world.wrong_item_id] == "rejected"


def test_journey_14_session_invalidation_during_owner_presence_applies_nothing(
    browser: Browser,
    runtime: RuntimePaths,
) -> None:
    """Prove a session lost mid-prompt cannot mint or apply an approval."""
    world = build_world(runtime)
    holder: dict[str, Any] = {}

    def invalidate() -> None:
        holder["sessions"].invalidate_all()

    ui, stop = serve(runtime, BrowserOwnerPresenceAdapter(during=invalidate))
    holder["sessions"] = ui.sessions
    guarded = guarded_context(browser, ui)
    page = guarded.__enter__().new_page()
    try:
        authenticate(page, ui)
        manifest = review_manifest(ui, world.review_change_set_id)
        prepared = page.request.post(
            f"{ui.origin}/reviews/{world.review_change_set_id}/approve",
            form={
                "revision_id": manifest.revision.revision_id,
                "digest": manifest.revision.digest,
            },
            headers={"Origin": ui.origin, "X-Memory-CSRF": _csrf(page)},
            max_redirects=0,
        )
        assert prepared.status == 303
        page.goto(f"{ui.origin}{prepared.headers['location']}")
        submit_form(page, "form[data-review-approval]")
        page.wait_for_timeout(500)

        assert get_change_set(runtime, world.review_change_set_id).state == "draft"
        assert ui.service.get_status().store.memory_count == 1
    finally:
        guarded.__exit__(None, None, None)
        stop()


def test_journey_15_a_stale_audit_restarts_after_authoritative_and_projection_writes(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove an audit bound to an old generation refuses to reconcile silently."""
    authenticate(page, live)
    page.goto(f"{live.origin}/audit")
    page.locator("[data-audit-begin]").click()
    page.wait_for_selector("[data-audit-generation]", state="attached")
    first = page.get_attribute("[data-audit-generation]", "data-audit-generation")

    edit_change_set(
        live.paths,
        world.review_change_set_id,
        review_manifest(live, world.review_change_set_id).revision.revision_id,
        (ClearSourceNoMemory(source_id=world.malformed_source_id),),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )

    page.reload()
    expect(page.locator("[data-audit-stale]")).to_be_visible()
    page.locator("[data-audit-begin]").click()
    page.wait_for_selector("[data-audit-generation]", state="attached")
    second = page.get_attribute("[data-audit-generation]", "data-audit-generation")
    assert first is not None and second is not None
    assert int(second) > int(first)


def test_journey_16_malformed_media_falls_back_to_complete_hex_in_the_inbox_trail(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove an undecodable capture still exposes every retained byte."""
    authenticate(page, live)
    page.goto(f"{live.origin}/inbox/batches/{world.review_batch_id}")
    expect(page.locator("[data-batch-source]")).to_have_count(3)
    page.get_by_role("link", name="syn-ui-browser-broken.png").click()
    page.wait_for_url(re.compile(r"/sources/[^/?]+$"))

    expect(page.get_by_text("inert hex/ASCII")).to_be_visible()
    rendered = page.get_attribute("[data-original-hex]", "data-original-hex")
    assert rendered is not None
    assert rendered.replace(" ", "").lower() == MALFORMED_MEDIA.hex()


def test_journey_18_guard_links_are_readable_removable_and_re_addable(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the owner reads, revokes, and restores a guard link as two claims."""
    authenticate(page, live)
    guard = build_guard_draft(live.paths)

    page.goto(f"{live.origin}/reviews/{guard.change_set_id}")
    links = page.locator("[data-guard-link]")
    expect(links).to_have_count(1)
    expect(links.first).to_contain_text(GUARD_HEDGE_STATEMENT)
    expect(links.first).to_contain_text(GUARD_CLAIM_STATEMENT)
    expect(links.first).to_have_attribute("data-link-status", "active")
    assert links.first.locator(".sensitivity-dot").count() == 2

    page.goto(edit_url(live, guard.change_set_id, "remove_guard_link"))
    expect(page.locator("[data-guard-link]")).to_have_count(1)
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    assert page.locator("[data-guard-link]").count() == 0
    assert review_manifest(live, guard.change_set_id).guard_links == ()

    page.goto(edit_url(live, guard.change_set_id, "add_guard_link"))
    page.select_option("#edit-guard-item", guard.guard_item_id)
    page.select_option("#edit-governed-item", guard.governed_item_id)
    submit_form(page, "form[aria-label='Add guard link']")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))
    restored = page.locator("[data-guard-link]")
    expect(restored).to_have_count(1)
    expect(restored.first).to_contain_text(GUARD_HEDGE_STATEMENT)
    assert len(review_manifest(live, guard.change_set_id).guard_links) == 1


def test_journey_23_a_refused_guard_link_explains_itself_in_the_browser(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a refusal survives the fetch handler that discards non-redirects."""
    authenticate(page, live)
    guard = build_guard_draft(live.paths)
    typed = "itm_synthetic_absent\r\nfrom_this_draft"
    before = review_manifest(live, guard.change_set_id).revision.revision_id

    page.goto(edit_url(live, guard.change_set_id, "add_guard_link"))
    refused = page.request.post(
        edit_url(live, guard.change_set_id, "add_guard_link"),
        form={
            "expected_digest": review_manifest(
                live, guard.change_set_id
            ).revision.digest,
            "guard_item_id": typed,
            "governed_item_id": guard.governed_item_id,
        },
        headers={"Origin": live.origin, "X-Memory-CSRF": _csrf(page)},
        max_redirects=0,
    )
    assert refused.status == 303
    page.goto(f"{live.origin}{refused.headers['location']}")
    expect(page.locator("#edit-guard-item")).to_have_value(typed)
    expect(page.locator("#edit-guard-item option:checked")).to_contain_text(
        "unavailable in this revision"
    )
    # The browser can inspect and explicitly retry the exact refused value,
    # even though the current roster has no item to populate it from.
    submit_form(page, "form[aria-label='Add guard link']")

    refusal = page.locator("[data-review-refusal]")
    expect(refusal).to_be_visible()
    expect(refusal).to_contain_text("guard link names a missing draft item")
    expect(page.locator("#edit-guard-item")).to_have_value(typed)
    expect(page.locator("#edit-governed-item")).to_have_value(guard.governed_item_id)
    assert typed not in page.url
    assert review_manifest(live, guard.change_set_id).revision.revision_id == before


def test_journey_24_a_refused_new_item_keeps_every_box_the_owner_filled(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a refused item edit returns the whole form, not an empty one."""
    authenticate(page, live)
    absent = "Synthetic excerpt that appears in no captured source at all."
    statement = "Rowan keeps a synthetic spare notebook in the hall cupboard."
    before = review_manifest(live, world.review_change_set_id).revision.revision_id

    page.goto(edit_url(live, world.review_change_set_id, "add_item"))
    page.select_option("#edit-kind", "insight")
    page.fill("#edit-statement", statement)
    page.select_option("#edit-sensitivity", "restricted")
    page.fill("#edit-occurred-on", "2026-11-17")
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.fill('textarea[name="tag.1"]', "spare-notebook")
    page.select_option('select[name="evidence.0.source_id"]', world.english_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', absent)
    submit_form(page, "form[data-review-edit]")

    refusal = page.locator("[data-review-refusal]")
    expect(refusal).to_be_visible()
    expect(refusal).to_contain_text("evidence excerpt was not found")
    expect(page.locator("body")).not_to_contain_text("Request unavailable")
    expect(page.locator("#edit-statement")).to_have_value(statement)
    expect(page.locator("#edit-kind")).to_have_value("insight")
    expect(page.locator("#edit-sensitivity")).to_have_value("restricted")
    expect(page.locator("#edit-occurred-on")).to_have_value("2026-11-17")
    expect(page.locator('textarea[name="tag.0"]')).to_have_value("synthetic")
    expect(page.locator('textarea[name="tag.1"]')).to_have_value("spare-notebook")
    expect(page.locator('select[name="evidence.0.source_id"]')).to_have_value(
        world.english_source_id
    )
    expect(page.locator('textarea[name="evidence.0.excerpt"]')).to_have_value(absent)
    assert absent not in page.url
    assert statement not in page.url
    assert (
        review_manifest(live, world.review_change_set_id).revision.revision_id == before
    )


def test_journey_19_applied_guards_reach_memory_detail_and_the_copy_action(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove an applied guard is prominent and disclosed identifiers copy once."""
    authenticate(page, live)
    guard = build_guard_draft(live.paths)
    applied = apply_out_of_band(live.paths, guard.change_set_id)
    statements = {
        memory_id: live.service.get_memory_revision(
            memory_id
        ).summary.revision.statement
        for memory_id in applied.memory_ids
    }
    claim_id = next(
        memory_id
        for memory_id, statement in statements.items()
        if statement == GUARD_CLAIM_STATEMENT
    )

    page.goto(f"{live.origin}/memories/{claim_id}")
    guards = page.locator("[data-guard-id]")
    expect(guards).to_have_count(1)
    expect(guards.first).to_contain_text(GUARD_HEDGE_STATEMENT)

    # Chromium's permission name for the async clipboard; no other engine runs
    # these journeys, and the handler reports a refusal rather than throwing.
    page.context.grant_permissions(["clipboard-write"], origin=live.origin)
    disclose_technical_details(page)
    page.locator("button[data-copy-value]").first.click()
    # Read the live region as it changes instead of racing its 2s self-clear.
    page.wait_for_function(
        "() => document.querySelector('.copy-announce').textContent === 'Copied'"
    )


def test_journey_20_browsing_hides_digests_until_the_owner_discloses_them(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove no browsing page reads out a digest and every detail page can."""
    authenticate(page, live)

    page.goto(f"{live.origin}/memory")
    assert DIGEST_TEXT.search(rendered_text(page)) is None
    page.goto(f"{live.origin}/sources")
    assert DIGEST_TEXT.search(rendered_text(page)) is None

    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    assert DIGEST_TEXT.search(rendered_text(page)) is None
    page.locator("details.technical-details > summary").first.click()
    expect(page.locator("details.technical-details")).to_have_attribute("open", "")
    assert DIGEST_TEXT.search(rendered_text(page)) is not None


def test_journey_21_dark_mode_repaints_the_whole_shell(
    browser: Browser,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the owner's dark system setting reaches the rendered palette."""
    with guarded_context(browser, live, color_scheme="dark") as context:
        page = context.new_page()
        authenticate(page, live)
        page.goto(f"{live.origin}/memory")
        painted = page.evaluate(
            "() => {"
            "  const style = window.getComputedStyle(document.body);"
            "  return [style.backgroundColor, style.color];"
            "}"
        )

        assert painted == [DARK_BACKGROUND, DARK_TEXT]


def test_journey_22_reviews_and_inbox_render_on_the_shared_shell(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove both flow surfaces resolve the one stylesheet and one page shell."""
    authenticate(page, live)

    for path, expected in (("/reviews", "[data-review-row]"), ("/inbox", "form")):
        page.goto(f"{live.origin}{path}")
        expect(page.locator("h1")).to_have_count(1)
        expect(page.locator(expected).first).to_be_visible()
        surface = page.evaluate(
            "() => window.getComputedStyle("
            "document.querySelector('main')).backgroundColor"
        )
        assert surface == LIGHT_SURFACE, path


def test_journey_17_no_owner_journey_reaches_an_external_host(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove every asset and navigation stays on the exact loopback origin."""
    observed: list[str] = []
    page.on("request", lambda request: observed.append(request.url))
    authenticate(page, live)
    for path in (
        "/status",
        "/reviews",
        "/inbox",
        "/memory",
        "/sources",
        "/audit",
        f"/sources/{world.english_source_id}",
        f"/memories/{world.current_memory_id}",
        f"/reviews/{world.review_change_set_id}",
    ):
        page.goto(f"{live.origin}{path}")
        expect(page.locator("h1")).to_have_count(1)

    assert observed
    for url in observed:
        assert url.startswith(live.origin), url
    assert live.external_requests == []
    assert json.dumps(sorted({urllib.parse.urlsplit(u).netloc for u in observed})) == (
        json.dumps([live.exact_host])
    )


def test_journey_25_the_provenance_lens_draws_every_layer_and_navigates(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the graph reaches every layer, names a node, and opens it."""
    authenticate(page, live)
    page.click("nav a[href='/graph']")
    page.wait_for_selector("svg.graph-scene")

    scene = page.locator("svg.graph-scene")
    assert scene.locator(".graph-node--source").count() >= 1
    assert scene.locator(".graph-node--memory").count() >= 1
    assert scene.locator(".graph-edge--evidence").count() >= 1
    # Governance is its own lens; guard chords would drown the evidence lines.
    assert scene.locator(".graph-edge--guard").count() == 0
    # Custody by day is not what the picture is organised by. Batches stay in
    # the Inbox, the audit, and every source's detail page.
    assert scene.locator(".graph-node--batch").count() == 0
    assert scene.locator(".graph-edge--contains").count() == 0

    # The key is always visible, so the colours never carry state alone.
    expect(page.locator(".graph-legend")).to_be_visible()

    memory = scene.locator(".graph-node--memory").first
    target = memory.get_attribute("href")
    memory.hover()
    expect(page.locator(".graph-label")).to_be_visible()
    assert page.locator(".graph-label").inner_text().strip() != ""

    memory.click()
    page.wait_for_url(f"{live.origin}{target}")
    expect(page.locator("h1")).to_have_count(1)


def test_journey_26_the_governance_lens_shows_guards_without_sources(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the second lens drops custody and keeps only the guarded subgraph."""
    # The world ships a guard link as a draft. A draft governs nothing: guard
    # links reach `memory_guard_links` only through an applied review, and the
    # lens reads canonical links, so the link has to be applied first.
    applied = build_guard_draft(world.paths)
    apply_out_of_band(world.paths, applied.change_set_id)

    authenticate(page, live)
    page.goto(f"{live.origin}/graph")
    page.click("a[href='/graph/governance']")
    page.wait_for_selector("svg.graph-scene")

    scene = page.locator("svg.graph-scene")
    assert scene.locator(".graph-edge--guard").count() >= 1
    assert scene.locator(".graph-node--source").count() == 0
    assert scene.locator(".graph-node--batch").count() == 0
    assert "Guards and the claims they govern" in rendered_text(page)


def test_journey_27_memory_detail_carries_its_neighbourhood(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the detail page shows what surrounds a memory, not just its record."""
    authenticate(page, live)
    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    page.wait_for_selector(".graph-neighbourhood svg.graph-scene")

    scene = page.locator(".graph-neighbourhood svg.graph-scene")
    # The subject itself plus at least the source that evidences it.
    assert scene.locator(".graph-node--memory").count() >= 1
    assert scene.locator(".graph-node--source").count() >= 1
    assert scene.locator(".graph-edge--evidence").count() >= 1
    expect(page.locator(".graph-neighbourhood .graph-legend")).to_be_visible()

    source = scene.locator(".graph-node--source").first
    target = source.get_attribute("href")
    source.click()
    page.wait_for_url(f"{live.origin}{target}")


def test_journey_28_graph_filters_narrow_the_picture_and_stay_out_of_the_url(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a graph filter selects memories and never reaches the address bar."""
    authenticate(page, live)
    page.goto(f"{live.origin}/graph")
    page.wait_for_selector("svg.graph-scene")
    before = page.locator("svg.graph-scene .graph-node--memory").count()

    page.click("details.filters summary")
    page.check("input[name='sensitivity'][value='restricted']")
    page.fill("#graph-tag", "syn-ui-browser")
    submit_form(page, "form[aria-label='Graph filters']")
    page.wait_for_url(re.compile(r"/graph/filtered/[^/?]+$"))

    assert "restricted" not in page.url
    assert "syn-ui-browser" not in page.url
    expect(page.get_by_text("Active filters")).to_be_visible()

    after = page.locator("svg.graph-scene .graph-node--memory").count()
    assert after <= before
    # Provenance still comes with whatever survived.
    if after:
        assert page.locator("svg.graph-scene .graph-node--source").count() >= 1


def test_journey_29_a_press_released_off_the_scene_leaves_no_armed_drag(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove a button the scene never saw released cannot pan it on hover."""
    authenticate(page, live)
    page.goto(f"{live.origin}/graph")
    page.wait_for_selector("svg.graph-scene")

    scene = page.locator("svg.graph-scene")
    box = scene.bounding_box()
    assert box is not None
    before = scene.get_attribute("viewBox")
    # The scene is taller than the viewport, so every coordinate below stays
    # inside the band that is actually on screen and can receive a pointer.
    inside_y = box["y"] + 40
    outside_x = box["x"] - 20
    assert outside_x > 0

    # Press inside the scene and release outside it without ever crossing the
    # drag threshold, so no pointer capture was taken and the scene sees no
    # pointerup of its own.
    page.mouse.move(box["x"] + box["width"] / 2, inside_y)
    page.mouse.down()
    page.mouse.move(outside_x, inside_y)
    page.mouse.up()

    # Hovering back across the scene with no button held is not a drag.
    page.mouse.move(box["x"] + box["width"] / 4, inside_y)
    page.mouse.move(box["x"] + box["width"] / 3, inside_y + 20)
    assert scene.get_attribute("viewBox") == before


def test_journey_30_dragging_a_node_leaves_its_own_link_clickable(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the drag click-suppressor never eats the next genuine click."""
    authenticate(page, live)
    page.goto(f"{live.origin}/graph")
    page.wait_for_selector("svg.graph-scene")

    memory = page.locator("svg.graph-scene .graph-node--memory").first
    target = memory.get_attribute("href")
    box = memory.bounding_box()
    assert box is not None
    start_x = box["x"] + box["width"] / 2
    start_y = box["y"] + box["height"] / 2

    page.mouse.move(start_x, start_y)
    page.mouse.down()
    page.mouse.move(start_x + 30, start_y + 30, steps=4)
    page.mouse.up()

    # A drag is not a navigation.
    assert page.url == f"{live.origin}/graph"

    # The very next plain click on that node still opens the memory.
    memory.click()
    page.wait_for_url(f"{live.origin}{target}")


def test_journey_32_one_selection_rejects_every_item_in_one_revision(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove clearing a batch is one submission, not one round trip per item."""
    authenticate(page, live)

    # The world ships one draft item; a selection needs at least two.
    page.goto(edit_url(live, world.review_change_set_id, "add_item"))
    page.select_option("#edit-kind", "insight")
    page.fill("#edit-statement", "Synthetic browser second interpretation.")
    page.select_option("#edit-sensitivity", "normal")
    page.fill('textarea[name="tag.0"]', "synthetic")
    page.select_option('select[name="evidence.0.source_id"]', world.english_source_id)
    page.fill('textarea[name="evidence.0.excerpt"]', ENGLISH_SOURCE.strip())
    submit_form(page, "form[data-review-edit]")
    page.wait_for_url(re.compile(r"/reviews/[^/]+$"))

    before = review_manifest(live, world.review_change_set_id).revision.revision_id
    selection = page.locator('form[data-bulk-edit="reject_item"] input[name="item_id"]')
    assert selection.count() == 2
    selection.nth(0).check()
    selection.nth(1).check()
    submit_form(page, 'form[data-bulk-edit="reject_item"]')
    # The redirect lands back on this same URL, so the reload is what to wait
    # for: the reject form is gone once nothing is left active.
    page.wait_for_selector('form[data-bulk-edit="restore_item"]')
    assert page.locator('form[data-bulk-edit="reject_item"]').count() == 0

    rows = page.locator("[data-roster-item]")
    assert rows.count() == 2
    statuses = {
        rows.nth(index).get_attribute("data-item-status")
        for index in range(rows.count())
    }
    assert statuses == {"rejected"}
    # One immutable revision holds the whole selection.
    after = review_manifest(live, world.review_change_set_id).revision
    assert after.predecessor_revision_id == before
    assert after.adapter_origin.value == "owner_ui"


def test_journey_31_guard_candidates_read_as_pairs_and_open_the_link_form(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """Prove the repair runbook's raw-JSON step has a page the owner can use."""
    # One source carrying a claim and its caveat: a shared evidence source is
    # the necessary gate, so two separate files would qualify nothing.
    batch_id, captured = capture(
        world.paths,
        {
            "syn-ui-browser-pair.txt": (GUARD_CLAIM_SOURCE + GUARD_HEDGE_SOURCE).encode(
                "utf-8"
            ),
        },
        sensitivity=Sensitivity.NORMAL,
    )
    source = captured["syn-ui-browser-pair.txt"]
    draft = create_change_set(
        world.paths,
        batch_id,
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    drafted = edit_change_set(
        world.paths,
        draft.change_set_id,
        draft.revision_id,
        (
            _guard_item(
                GUARD_CLAIM_ITEM,
                source,
                GUARD_CLAIM_STATEMENT,
                GUARD_CLAIM_EXCERPT,
                MemoryKind.FACT,
            ),
            _guard_item(
                GUARD_HEDGE_ITEM,
                source,
                GUARD_HEDGE_STATEMENT,
                GUARD_HEDGE_EXCERPT,
                MemoryKind.INSIGHT,
            ),
        ),
        adapter_origin=ChangeSetAdapterOrigin.MCP,
    )
    apply_out_of_band(world.paths, drafted.change_set_id)

    authenticate(page, live)
    page.goto(f"{live.origin}/graph/governance")
    page.click("a[href='/graph/governance/candidates']")
    page.wait_for_selector("[data-guard-candidate]")

    candidate = page.locator("[data-guard-candidate]").first
    expect(candidate).to_contain_text(GUARD_HEDGE_STATEMENT)
    expect(candidate).to_contain_text(GUARD_CLAIM_STATEMENT)
    expect(candidate).to_contain_text("shared evidence source")
    text = rendered_text(page)
    assert "1 pair qualified." in text
    assert "No standing guard violation is on record." in text

    # Acting on one lands in the review edit form with both endpoints named.
    candidate.locator("[data-add-this-link]").click()
    page.wait_for_selector("#edit-guard-lineage")
    guard_box = page.locator("#edit-guard-lineage")
    governed_box = page.locator("#edit-governed-lineage")
    assert guard_box.input_value().startswith("lin_")
    assert governed_box.input_value().startswith("lin_")
    assert guard_box.input_value() != governed_box.input_value()
    assert page.locator("#edit-guard-item").input_value() == ""


@pytest.mark.parametrize("failure", ["connection", "http", "no_redirect"])
def test_correction_submission_failure_preserves_text_and_unsaved_warning(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
    failure: str,
) -> None:
    """A failed fetch must leave the exact draft recoverable in its form."""
    authenticate(page, live)
    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    submit_form(page, 'form[action$="/corrections"]')
    page.wait_for_url(re.compile(r"/memory/corrections/[^/]+$"))
    correction = "Synthetic correction: the amber lantern stays indoors. 合成更正。"
    page.locator("#owner-correction-text").fill(correction)
    form = page.locator('form[aria-label="Owner correction"]')
    action = form.get_attribute("action")
    assert action is not None
    attempts = 0

    def refuse(route: Route) -> None:
        nonlocal attempts
        attempts += 1
        if failure == "connection":
            route.abort()
        else:
            route.fulfill(
                status=503 if failure == "http" else 200, body="Request unavailable"
            )

    before = live.service.get_status().store.source_count
    page.route(f"**{action}", refuse)
    submit_form(page, 'form[aria-label="Owner correction"]')
    expect(page.get_by_role("alert")).to_contain_text("Request unavailable")
    expect(page.locator("#owner-correction-text")).to_have_value(correction)
    expect(page.locator("#owner-correction-text")).to_be_editable()
    expect(form.get_by_role("button", name="Capture correction source")).to_be_enabled()
    assert page.evaluate(
        "!window.dispatchEvent(new Event('beforeunload', {cancelable: true}))"
    )
    assert attempts == 1
    assert live.service.get_status().store.source_count == before

    page.unroute(f"**{action}", refuse)
    submit_form(page, 'form[aria-label="Owner correction"]')
    page.wait_for_url(re.compile(r"/inbox"))
    expect(page.get_by_text("Captured; awaiting Memory Review")).to_be_visible()
    assert live.service.get_status().store.source_count == before + 1
    assert live.verifier.calls == 0


def test_review_submission_failure_reenables_the_preserved_edit(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """A transport failure must not strand a review behind a disabled submit."""
    authenticate(page, live)
    page.goto(edit_url(live, world.review_change_set_id, "add_item"))
    statement = "Synthetic review draft: retain the quiet workshop preference."
    page.locator("#edit-statement").fill(statement)
    form = page.locator("form[data-review-edit]")
    action = form.get_attribute("action")
    assert action is not None
    page.route(f"**{action}", lambda route: route.abort())
    submit_form(page, "form[data-review-edit]")
    expect(page.get_by_role("alert")).to_contain_text("Request unavailable")
    expect(page.locator("#edit-statement")).to_have_value(statement)
    expect(page.locator("#edit-statement")).to_be_editable()
    expect(form.locator('button[type="submit"]')).to_be_enabled()


def test_pending_correction_keeps_its_submitted_text_and_prevents_duplicates(
    page: Page,
    live: LiveUi,
    world: SyntheticWorld,
) -> None:
    """A pending save cannot accept edits that its successful redirect would lose."""
    authenticate(page, live)
    page.goto(f"{live.origin}/memories/{world.current_memory_id}")
    submit_form(page, 'form[action$="/corrections"]')
    page.wait_for_url(re.compile(r"/memory/corrections/[^/]+$"))
    statement = "Synthetic correction: the copper lantern stays in the workshop."
    text = page.locator("#owner-correction-text")
    text.fill(statement)
    form = page.locator('form[aria-label="Owner correction"]')
    action = form.get_attribute("action")
    assert action is not None
    pending: list[Route] = []

    def hold(route: Route) -> None:
        pending.append(route)

    page.route(f"**{action}", hold)
    submit_form(page, 'form[aria-label="Owner correction"]')
    expect(
        form.get_by_role("button", name="Capture correction source")
    ).to_be_disabled()
    expect(text).to_be_disabled()
    form.evaluate("node => node.requestSubmit()")
    expect(text).to_have_value(statement)
    assert len(pending) == 1
    body = pending[0].request.post_data
    assert body is not None
    assert statement in urllib.parse.unquote_plus(body)
    before = live.service.get_status().store.source_count
    pending[0].continue_()
    page.wait_for_url(re.compile(r"/inbox"))
    expect(page.get_by_text("Captured; awaiting Memory Review")).to_be_visible()
    assert live.service.get_status().store.source_count == before + 1
    assert live.verifier.calls == 0


@pytest.mark.parametrize("next_action", ["search", "facet"])
def test_memory_search_keeps_filters_when_refining_results(
    page: Page,
    live: LiveUi,
    next_action: str,
) -> None:
    """Repeating a query or choosing a kind must not discard other filters."""
    bodies = {
        "synthetic-amber-workshop.txt": "Synthetic lantern workshop opens at noon.\n",
        "synthetic-amber-garden.txt": "Synthetic lantern garden closes at dusk.\n",
        "synthetic-amber-zh.txt": "合成灯笼记录：lantern 在花园中使用。\n",
    }
    batch_id, sources = capture_batch(
        live.paths, bodies, sensitivity=Sensitivity.NORMAL, clock=FakeClock()
    )
    edits = tuple(
        single_item_edit(
            item_id=f"synthetic_filter_{index}",
            source=sources[name],
            statement=body.strip(),
            excerpt=body.strip(),
            tags=("aspect:workshop", "synthetic")
            if index == 0
            else ("aspect:garden", "synthetic"),
        )
        for index, (name, body) in enumerate(bodies.items())
    )
    dated_edits = tuple(
        replace(edit, memory=replace(edit.memory, occurred_on="2039-04-10"))
        for edit in edits
    )
    ready = ready_items(live.paths, batch_id, dated_edits)
    apply_out_of_band(live.paths, ready.change_set_id)
    authenticate(page, live)
    page.goto(f"{live.origin}/memory")
    page.locator("details.filters summary").click()
    page.locator("#memory-query").fill("lantern")
    page.locator("#memory-tag").fill("aspect:workshop")
    page.locator("#occurred-from").fill("2039-04")
    page.locator("#occurred-to").fill("2039-05")
    page.get_by_role("checkbox", name="fact", exact=True).check()
    page.get_by_role("checkbox", name="normal", exact=True).check()
    submit_form(page, 'form[aria-label="Memory search and filters"]')
    page.wait_for_url(re.compile(r"/memory/search/[^/]+$"))
    expect(page.locator("[data-memory-row]")).to_have_count(1)
    expect(page.locator("#memory-tag")).to_have_value("aspect:workshop")
    expect(page.get_by_role("checkbox", name="fact", exact=True)).to_be_checked()
    expect(page.get_by_role("checkbox", name="normal", exact=True)).to_be_checked()
    # Add a second all-of tag through the rendered form, then refine again.
    previous_url = page.url
    page.locator("#memory-tag-new").fill("synthetic")
    submit_form(page, 'form[aria-label="Memory search and filters"]')
    page.wait_for_url(lambda url: str(url) != previous_url)
    expect(page.locator("#memory-tag-2")).to_have_value("synthetic")
    previous_url = page.url
    if next_action == "search":
        submit_form(page, 'form[aria-label="Memory search and filters"]')
    else:
        page.locator("form[data-facet-kind]").filter(has_text="fact").get_by_role(
            "button"
        ).click()
    page.wait_for_url(lambda url: str(url) != previous_url)
    expect(page.locator("[data-memory-row]")).to_have_count(1)
    expect(page.locator("#memory-tag")).to_have_value("aspect:workshop")
    expect(page.locator("#memory-tag-2")).to_have_value("synthetic")
    expect(page.locator("#occurred-from")).to_have_value("2039-04")
    expect(page.locator("#occurred-to")).to_have_value("2039-05")
    expect(page.get_by_role("checkbox", name="fact", exact=True)).to_be_checked()
    expect(page.get_by_role("checkbox", name="normal", exact=True)).to_be_checked()
    assert "aspect" not in page.url and "lantern" not in page.url


@pytest.mark.parametrize("direction", ["guards", "governs"])
def test_large_memory_relationships_open_in_full_from_preview_pages(
    page: Page,
    live: LiveUi,
    direction: Literal["guards", "governs"],
) -> None:
    centre, related, complete_statement = large_guard_star(live.paths, direction)
    authenticate(page, live)
    response = page.goto(f"{live.origin}/memories/{centre}")
    assert response is not None and response.status == 200
    attribute = "data-guard-id" if direction == "guards" else "data-governs-id"
    rows = page.locator(f"[{attribute}]")
    expect(rows).to_have_count(50)
    assert all(len(text) < 400 for text in rows.all_inner_texts())
    expect(rows.first).to_contain_text("statement preview ends here")
    page.locator(f"[data-next-{direction}]").click()
    expect(rows).to_have_count(10)
    assert page.locator(f"[data-next-{direction}]").count() == 0
    page.locator(f'a[href="/memories/{related[-1]}"]').first.click()
    page.wait_for_url(f"**/memories/{related[-1]}")
    expect(page.locator(".memory-statement")).to_have_text(complete_statement)
    expect(
        page.get_by_role("link", name="Open complete retained source")
    ).to_be_visible()


@pytest.mark.parametrize("lens", ["provenance", "governance"])
def test_graph_filters_survive_repeat_and_lens_switch(
    page: Page, live: LiveUi, world: SyntheticWorld, lens: str
) -> None:
    """Catch active controls resetting the selection on repeat or lens switch."""
    from synthetic import apply_ready

    clock = FakeClock()
    batch, sources = capture_batch(
        world.paths,
        {"graph-filter.txt": "Synthetic amber lens. 合成琥珀镜片。\n"},
        sensitivity=Sensitivity.NORMAL,
        clock=clock,
    )
    source = sources["graph-filter.txt"]
    edits = tuple(
        single_item_edit(
            item_id=f"itm_lens_{index}",
            source=source,
            statement=f"Synthetic amber lens {index}.",
            excerpt="Synthetic amber lens.",
            tags=("synthetic-lens", "琥珀") if index < 2 else ("synthetic-lens",),
        )
        for index in range(4)
    )
    dated = tuple(
        replace(edit, memory=replace(edit.memory, occurred_on="2038-04-12"))
        for edit in edits
    )
    links = tuple(
        AddGuardLink(
            link=GuardLinkInput(
                guard_item_id=f"itm_lens_{index}",
                guard_lineage_id=None,
                governed_item_id=f"itm_lens_{index + 1}",
                governed_lineage_id=None,
            )
        )
        for index in (0, 2)
    )
    apply_ready(world.paths, ready_items(world.paths, batch, (*dated, *links)))
    authenticate(page, live)
    path = "/graph" if lens == "provenance" else "/graph/governance"
    page.goto(f"{live.origin}{path}")
    page.locator("details.filters summary").click()
    form = page.locator("form[aria-label='Graph filters']")
    form.locator("input[name='kind'][value='fact']").check()
    form.locator("input[name='sensitivity'][value='normal']").check()
    page.fill("#graph-tag", "synthetic-lens")
    page.fill("#graph-occurred-from", "2038-04")
    page.fill("#graph-occurred-to", "2038-05")
    previous = page.url
    submit_form(page, "form[aria-label='Graph filters']")
    page.wait_for_url(re.compile(r"^(?!" + re.escape(previous) + r"$).+"))
    expect(form.locator("input[name='kind'][value='fact']")).to_be_checked()
    # A blank additional tag control allows an all-of selection without
    # overwriting a tag already applied.
    form.locator("input[name='tag']").last.fill("琥珀")
    previous = page.url
    submit_form(page, "form[aria-label='Graph filters']")
    page.wait_for_url(re.compile(r"^(?!" + re.escape(previous) + r"$).+"))
    for destination in ("Governance", "Provenance", "Governance", "Provenance"):
        link = page.get_by_role("navigation", name="Graph lens").get_by_role(
            "link", name=destination, exact=True
        )
        target = link.get_attribute("href")
        link.click()
        page.wait_for_url(f"{live.origin}{target}")
        assert "/filtered/" in page.url
        assert "synthetic-lens" not in page.url and "2038" not in page.url
        expect(form.locator("input[name='kind'][value='fact']")).to_be_checked()
        expect(
            form.locator("input[name='sensitivity'][value='normal']")
        ).to_be_checked()
        expect(page.locator("#graph-occurred-from")).to_have_value("2038-04")
        expect(page.locator("#graph-occurred-to")).to_have_value("2038-05")
        assert form.locator("input[name='tag']").evaluate_all(
            "els => els.map(el => el.value)"
        ) == ["synthetic-lens", "琥珀", ""]
        previous = page.url
        submit_form(page, "form[aria-label='Graph filters']")
        page.wait_for_url(re.compile(r"^(?!" + re.escape(previous) + r"$).+"))
        expect(page.locator("svg.graph-scene .graph-node--memory")).to_have_count(2)
