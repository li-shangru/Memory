from __future__ import annotations

import asyncio
import fcntl
import hashlib
import html
import http.client
import importlib
import json
import os
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from starlette.testclient import TestClient
from ui_support import (
    RefusingOwnerPresenceAdapter,
    build_test_orchestrator,
    load_ui_module,
)

from memory.errors import StoreBusyError, StoreError
from memory.graph import (
    GraphEdge,
    GraphEdgeKind,
    GraphLayer,
    GraphNode,
    StoreGraph,
)
from memory.model import (
    Authorship,
    ExactCaptureMetadata,
    MemoryFilters,
    MemoryKind,
    RuntimeMode,
    Sensitivity,
    SourceCaptureOrigin,
    StoreStatus,
)
from memory.runtime import resolve_runtime
from memory.ui.auth import UiSessionStore
from memory.ui.owner_presence import UiApprovalOrchestrator
from memory.ui.view_models import (
    AuditCounts,
    AuditSnapshot,
    InboxStatus,
    MemoryProjectionCoverage,
    OwnerGuardCandidate,
    OwnerGuardLintPanel,
    OwnerGuardRepairTarget,
    OwnerMemorySearchPage,
    OwnerPage,
    OwnerSourceSummary,
    OwnerStatus,
    ProjectionCoverage,
    SourceProjectionCoverage,
)

PUBLIC_HOST = "memory-11111111111111111111111111111111.localhost"
PUBLIC_PORT = 43123
EXACT_HOST = f"{PUBLIC_HOST}:{PUBLIC_PORT}"
PUBLIC_ORIGIN = f"http://{EXACT_HOST}"
BOOTSTRAP = "synthetic-bootstrap-capability"
REPO_ROOT = Path(__file__).resolve().parents[1]


def new_sessions(*, created_at_ns: int = 100) -> Any:
    return load_ui_module("auth").UiSessionStore(
        bootstrap_capability=BOOTSTRAP,
        exact_host=EXACT_HOST,
        created_at_ns=created_at_ns,
    )


def exchange(sessions: Any, *, now_ns: int = 100) -> Any:
    return sessions.exchange_bootstrap(
        secret=BOOTSTRAP,
        exact_host=EXACT_HOST,
        now_ns=now_ns,
    )


def synthetic_audit_snapshot(generation: int) -> AuditSnapshot:
    source_coverage = SourceProjectionCoverage(
        total_captures=generation,
        expected_searchable_captures=0,
        indexed_expected_captures=0,
        missing_expected_rows=0,
        inherently_unsearchable_captures=generation,
        unexpected_or_duplicate_rows=0,
    )
    memory_coverage = MemoryProjectionCoverage(
        current_heads=0,
        indexed_current_heads=0,
        missing_current_head_rows=0,
        unexpected_or_duplicate_noncurrent_rows=0,
        historical_revisions_not_expected=0,
    )
    return AuditSnapshot(
        store_id="0" * 32,
        generation=generation,
        high_water_marks=(("sources", generation),),
        counts=AuditCounts(
            batch_count=0,
            batch_issue_row_count=0,
            batch_issue_occurrence_count=0,
            source_count=generation,
            change_set_count=0,
            change_set_revision_count=0,
            approval_count=0,
            application_count=0,
            lineage_count=0,
            memory_revision_count=0,
        ),
        projection_coverage=ProjectionCoverage(
            sources=source_coverage,
            memories=memory_coverage,
        ),
    )


class SyntheticOwnerService:
    def __init__(self, *, staged_entry_count: int = 3) -> None:
        self.status_calls = 0
        self._status = OwnerStatus(
            store=StoreStatus(
                product="memory",
                schema_version=1,
                store_id="0" * 32,
                source_count=7,
                memory_count=2,
                searchable_count=5,
                unsearchable_count=2,
                reindex_required=False,
                mcp_contract_digest="1" * 64,
                skill_digest="2" * 64,
                pending_review_count=1,
            ),
            runtime_mode=RuntimeMode.PERSONAL,
            availability="available",
            pending_review_count=1,
            projections=ProjectionCoverage(
                sources=SourceProjectionCoverage(
                    total_captures=7,
                    expected_searchable_captures=5,
                    indexed_expected_captures=5,
                    missing_expected_rows=0,
                    inherently_unsearchable_captures=2,
                    unexpected_or_duplicate_rows=0,
                ),
                memories=MemoryProjectionCoverage(
                    current_heads=2,
                    indexed_current_heads=2,
                    missing_current_head_rows=0,
                    unexpected_or_duplicate_noncurrent_rows=0,
                    historical_revisions_not_expected=1,
                ),
            ),
            runtime_display_path="Synthetic Store Home",
            inbox=InboxStatus(
                inbox_display_path="Synthetic Inbox",
                staged_visible_entry_count=staged_entry_count,
            ),
        )

    def get_status(self) -> OwnerStatus:
        self.status_calls += 1
        return self._status

    def read_store_graph(self, filters: MemoryFilters = MemoryFilters()) -> StoreGraph:
        """One batch, one source, two claims, one guard link.

        Small on purpose, but never empty: the shell tests assert real rendered
        markup, and an empty graph would take the "nothing to draw" branch and
        prove nothing about the scene.
        """
        nodes = (
            GraphNode(
                key="batch:bat_synthetic",
                layer=GraphLayer.BATCH,
                entity_id="bat_synthetic",
                label="1 source",
                kind=None,
                sensitivity=Sensitivity.NORMAL,
                detail_path="/inbox/batches/bat_synthetic",
            ),
            GraphNode(
                key="source:src_synthetic",
                layer=GraphLayer.SOURCE,
                entity_id="src_synthetic",
                label="kettle-notes.txt",
                kind=None,
                sensitivity=Sensitivity.NORMAL,
                detail_path="/sources/src_synthetic",
            ),
            GraphNode(
                key="memory:lin_claim",
                layer=GraphLayer.MEMORY,
                entity_id="mem_claim",
                label="The kettle was descaled in March.",
                kind=MemoryKind.FACT,
                sensitivity=Sensitivity.NORMAL,
                detail_path="/memories/mem_claim",
            ),
            GraphNode(
                key="memory:lin_guard",
                layer=GraphLayer.MEMORY,
                entity_id="mem_guard",
                label="The descaling date is self-reported.",
                kind=MemoryKind.INSIGHT,
                sensitivity=Sensitivity.NORMAL,
                detail_path="/memories/mem_guard",
            ),
        )
        edges = (
            GraphEdge(
                GraphEdgeKind.CONTAINS, "batch:bat_synthetic", "source:src_synthetic"
            ),
            GraphEdge(
                GraphEdgeKind.EVIDENCE, "source:src_synthetic", "memory:lin_claim"
            ),
            GraphEdge(
                GraphEdgeKind.EVIDENCE, "source:src_synthetic", "memory:lin_guard"
            ),
            GraphEdge(GraphEdgeKind.GUARD, "memory:lin_guard", "memory:lin_claim"),
        )
        return StoreGraph(
            nodes=nodes,
            edges=edges,
            total_node_count=len(nodes),
            measured_node_count=len(nodes),
            within_ceiling=True,
            guard_links_available=True,
        )

    def read_guard_lint(self) -> OwnerGuardLintPanel:
        """One qualifying pair with an open draft to write it into.

        Never empty, for the same reason the graph above is not: the shell
        tests assert real rendered markup, and the "nothing to propose" branch
        would prove nothing about the panel.
        """
        return OwnerGuardLintPanel(
            available=True,
            candidates=(
                OwnerGuardCandidate(
                    guard_lineage_id="lin_guard",
                    governed_lineage_id="lin_claim",
                    guard_revision_id="mem_guard",
                    governed_revision_id="mem_claim",
                    guard_statement="The descaling date is self-reported.",
                    governed_statement="The kettle was descaled in March.",
                    guard_elided=False,
                    governed_elided=False,
                    rationales=("guard_vocabulary", "shared_evidence_source"),
                ),
            ),
            shown_candidate_count=1,
            reported_candidate_count=1,
            truncated_candidate_count=0,
            standing_violations=(),
            truncated_violation_count=0,
            repair_target=OwnerGuardRepairTarget(
                batch_id="bat_synthetic_panel",
                open_draft_count=1,
                change_set_id="chg_synthetic",
                revision_id="csr_synthetic",
            ),
        )

    def list_change_sets(
        self,
        _cursor: str | None,
        _limit: int,
        _state: str | None,
    ) -> OwnerPage[object]:
        return OwnerPage(items=(), next_cursor=None, has_more=False)

    def list_sources(
        self,
        _cursor: str | None,
        _limit: int,
    ) -> OwnerPage[OwnerSourceSummary]:
        return OwnerPage(items=(), next_cursor=None, has_more=False)

    def list_memories(
        self,
        _cursor: str | None,
        _limit: int,
        filters: MemoryFilters,
    ) -> OwnerMemorySearchPage:
        return OwnerMemorySearchPage(
            items=(),
            next_cursor=None,
            has_more=False,
            filters=filters,
            unfiltered_query_match_count=0,
            filtered_match_count=0,
            hidden_by_filters_count=0,
            projection_coverage=self._status.projections.memories,
        )

    def list_staged_inbox_entries(
        self,
        _cursor: str | None,
        _limit: int,
    ) -> OwnerPage[Any]:
        return OwnerPage(items=(), next_cursor=None, has_more=False)

    def list_recent_correction_batches(
        self,
        _cursor: str | None,
        _limit: int,
    ) -> OwnerPage[Any]:
        return OwnerPage(items=(), next_cursor=None, has_more=False)

    def list_capture_recovery_issues(
        self,
        _cursor: str | None,
        _limit: int,
    ) -> OwnerPage[Any]:
        return OwnerPage(items=(), next_cursor=None, has_more=False)


class FailFastFinder:
    def reveal_directory_url(self, _directory_url: object) -> None:
        pytest.fail("inspection route attempted to reveal a directory")


@dataclass(slots=True)
class UiHarness:
    client: TestClient
    sessions: Any
    service: SyntheticOwnerService

    @property
    def session_cookie(self) -> str:
        value = self.client.cookies.get("memory_ui_session")
        assert value is not None
        return value

    @property
    def session(self) -> Any:
        value = self.sessions.resolve_cookie(
            cookie=self.session_cookie,
            exact_host=EXACT_HOST,
            now_ns=time.monotonic_ns(),
        )
        assert value is not None
        return value


def build_ui_harness(*, staged_entry_count: int = 3) -> UiHarness:
    sessions = new_sessions(created_at_ns=time.monotonic_ns())
    service = SyntheticOwnerService(staged_entry_count=staged_entry_count)
    application = load_ui_module("app").create_ui_app(
        service,
        sessions,
        FailFastFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    return UiHarness(
        client=TestClient(application, base_url=PUBLIC_ORIGIN),
        sessions=sessions,
        service=service,
    )


def authenticate(harness: UiHarness) -> Any:
    response = harness.client.post(
        "/session",
        content=BOOTSTRAP,
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response


class NavigationParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_navigation = False
        self.current_href: str | None = None
        self.links: list[tuple[str, str]] = []
        self.inbox_badges: list[str] = []
        self.in_inbox_badge = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "nav" and attributes.get("aria-label") == "Primary":
            self.in_navigation = True
        if self.in_navigation and tag == "a":
            self.current_href = attributes.get("href")
        if attributes.get("data-ui") == "inbox-count":
            self.in_inbox_badge = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "nav" and self.in_navigation:
            self.in_navigation = False
        if tag == "a":
            self.current_href = None
        if tag == "span" and self.in_inbox_badge:
            self.in_inbox_badge = False

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if self.current_href is not None and text:
            self.links.append((self.current_href, text))
        if self.in_inbox_badge and text:
            self.inbox_badges.append(text)


def test_secure_ui_modules_are_importable() -> None:
    """Catch a build that omits the secure local server shell."""
    for module_name in (
        "memory.ui.app",
        "memory.ui.auth",
        "memory.ui.browser_launch",
        "memory.ui.request_limits",
    ):
        importlib.import_module(module_name)


def test_session_store_exchanges_bootstrap_once() -> None:
    """Catch replay of the one-use process bootstrap capability."""
    sessions = new_sessions()

    first = exchange(sessions)
    second = exchange(sessions, now_ns=101)

    assert first.session_id
    assert second is None


@pytest.mark.parametrize(
    ("now_offset", "accepted"),
    [
        (-1, False),
        (0, True),
        (60_000_000_000 - 1, True),
        (60_000_000_000, False),
        (60_000_000_001, False),
    ],
)
def test_bootstrap_uses_a_fail_closed_monotonic_lifetime(
    now_offset: int,
    accepted: bool,
) -> None:
    """Catch expiry-boundary or clock-rollback bootstrap acceptance."""
    sessions = new_sessions(created_at_ns=1_000)

    result = exchange(sessions, now_ns=1_000 + now_offset)

    assert (result is not None) is accepted


def test_bootstrap_is_exact_host_bound_without_consuming_on_mismatch() -> None:
    """Catch sibling-host exchange or denial of the legitimate first exchange."""
    sessions = new_sessions()

    sibling = sessions.exchange_bootstrap(
        secret=BOOTSTRAP,
        exact_host=f"memory-{'2' * 32}.localhost:{PUBLIC_PORT}",
        now_ns=100,
    )

    assert sibling is None
    assert exchange(sessions) is not None


def test_session_has_fixed_eight_hour_lifetime_without_activity_extension() -> None:
    """Catch idle activity extending a process session beyond its fixed expiry."""
    auth = load_ui_module("auth")
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None

    midpoint = 100 + auth.UI_SESSION_TTL_NS // 2
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=midpoint,
        )
        == session
    )
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=100 + auth.UI_SESSION_TTL_NS - 1,
        )
        == session
    )
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=100 + auth.UI_SESSION_TTL_NS,
        )
        is None
    )


def test_session_rejects_absent_cross_instance_host_and_clock_rollback() -> None:
    """Catch reuse outside the issuing process, host, or monotonic timeline."""
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None
    other_process = new_sessions()

    assert sessions.resolve_cookie(cookie="", exact_host=EXACT_HOST, now_ns=100) is None
    assert (
        other_process.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=100,
        )
        is None
    )
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=f"memory-{'2' * 32}.localhost:{PUBLIC_PORT}",
            now_ns=100,
        )
        is None
    )
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=200,
        )
        == session
    )
    assert (
        sessions.resolve_cookie(
            cookie=session.session_id,
            exact_host=EXACT_HOST,
            now_ns=199,
        )
        is None
    )
    assert not sessions.is_session_active(session.session_id, now_ns=200)


def test_search_handles_are_bounded_opaque_expiring_and_session_owned() -> None:
    """Catch private search values leaking into URLs or unbounded session state."""
    auth = load_ui_module("auth")
    model = importlib.import_module("memory.model")
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None
    handles: list[str] = []
    for ordinal in range(17):
        handles.append(
            sessions.remember_search(
                session.session_id,
                model.UiSearchState(
                    scope="sources",
                    query=f"synthetic private query {ordinal}",
                    filters=(("tag", f"synthetic-filter-{ordinal}"),),
                    created_at_ns=100 + ordinal,
                ),
            )
        )

    assert sessions.resolve_search(session.session_id, handles[0], now_ns=116) is None
    current = sessions.resolve_search(session.session_id, handles[-1], now_ns=116)
    assert current is not None
    assert current.query == "synthetic private query 16"
    assert sessions.resolve_search("cross_session", handles[-1], now_ns=116) is None
    assert sessions.resolve_search(session.session_id, "unknown", now_ns=116) is None
    url = f"/sources/search/{handles[-1]}"
    assert current.query not in url
    assert current.filters[0][1] not in url
    assert (
        sessions.resolve_search(
            session.session_id,
            handles[-1],
            now_ns=116 + auth.UI_SEARCH_HANDLE_TTL_NS - 1,
        )
        == current
    )
    assert (
        sessions.resolve_search(
            session.session_id,
            handles[-1],
            now_ns=116 + auth.UI_SEARCH_HANDLE_TTL_NS,
        )
        is None
    )


def test_search_handle_clock_rollback_and_session_invalidation_fail_closed() -> None:
    """Catch rollback replay or retained query state after logout/shutdown."""
    model = importlib.import_module("memory.model")
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None
    handle = sessions.remember_search(
        session.session_id,
        model.UiSearchState(
            scope="memories",
            query="synthetic private query",
            filters=(),
            created_at_ns=100,
        ),
    )

    assert sessions.resolve_search(session.session_id, handle, now_ns=200) is not None
    assert sessions.resolve_search(session.session_id, handle, now_ns=199) is None
    sessions.invalidate_session(session.session_id)
    assert sessions.resolve_search(session.session_id, handle, now_ns=200) is None


def test_audit_handles_are_bounded_expiring_and_process_session_owned() -> None:
    """Catch audit snapshots escaping their bounded issuing session."""
    auth = load_ui_module("auth")
    model = importlib.import_module("memory.model")
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None
    handles: list[str] = []
    snapshots: list[AuditSnapshot] = []
    for generation in range(9):
        snapshot = synthetic_audit_snapshot(generation)
        snapshots.append(snapshot)
        handles.append(
            sessions.remember_audit(
                session.session_id,
                model.UiAuditState(snapshot=snapshot, created_at_ns=100 + generation),
            )
        )

    assert sessions.resolve_audit(session.session_id, handles[0], now_ns=108) is None
    assert (
        sessions.resolve_audit(session.session_id, handles[-1], now_ns=108)
        == snapshots[-1]
    )
    assert sessions.resolve_audit("cross_session", handles[-1], now_ns=108) is None
    assert (
        new_sessions().resolve_audit(session.session_id, handles[-1], now_ns=108)
        is None
    )
    assert (
        sessions.resolve_audit(
            session.session_id,
            handles[-1],
            now_ns=108 + auth.UI_AUDIT_HANDLE_TTL_NS - 1,
        )
        == snapshots[-1]
    )
    assert (
        sessions.resolve_audit(
            session.session_id,
            handles[-1],
            now_ns=108 + auth.UI_AUDIT_HANDLE_TTL_NS,
        )
        is None
    )


def test_audit_handle_clock_rollback_and_invalidate_all_fail_closed() -> None:
    """Catch rollback replay or snapshots retained after process shutdown."""
    model = importlib.import_module("memory.model")
    sessions = new_sessions()
    session = exchange(sessions)
    assert session is not None
    handle = sessions.remember_audit(
        session.session_id,
        model.UiAuditState(
            snapshot=synthetic_audit_snapshot(1),
            created_at_ns=100,
        ),
    )

    assert sessions.resolve_audit(session.session_id, handle, now_ns=200) is not None
    assert sessions.resolve_audit(session.session_id, handle, now_ns=199) is None
    sessions.invalidate_all()
    assert sessions.resolve_audit(session.session_id, handle, now_ns=200) is None


def test_bootstrap_shell_and_exact_static_assets_are_the_only_public_gets() -> None:
    """Catch an unauthenticated content/media route or broad static mount."""
    harness = build_ui_harness()

    assert harness.client.get("/bootstrap").status_code == 200
    for asset in ("bootstrap.js", "ui.js", "app.css"):
        assert harness.client.get(f"/static/{asset}").status_code == 200
    for protected in (
        "/",
        "/status",
        "/reviews",
        "/inbox",
        "/memory",
        "/graph",
        "/sources",
        "/sources/src_synthetic/media",
        "/audit",
        "/static/not-packaged.js",
        "/service-worker.js",
    ):
        response = harness.client.get(protected)
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"


def test_content_route_requires_process_session() -> None:
    harness = build_ui_harness()

    response = harness.client.get("/sources")

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert harness.service.status_calls == 0


def test_bootstrap_is_one_use_and_cookie_is_host_only_strict_and_http_only() -> None:
    """Catch replayable bootstrap exchange or browser-persisted/shared cookies."""
    harness = build_ui_harness()

    first = authenticate(harness)
    second = harness.client.post(
        "/session",
        content=BOOTSTRAP,
        headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
        follow_redirects=False,
    )

    assert first.headers["location"] == "/"
    assert second.status_code == 401
    parsed = SimpleCookie()
    parsed.load(first.headers["set-cookie"])
    morsel = parsed["memory_ui_session"]
    assert morsel["httponly"] is True
    assert morsel["samesite"].lower() == "strict"
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    assert morsel["expires"] == ""
    assert morsel["max-age"] == ""


def test_session_exchange_requires_exact_origin_host_and_port() -> None:
    """Catch cross-site or sibling-origin bootstrap exchange."""
    for headers in (
        {"Content-Type": "text/plain"},
        {"Origin": "https://evil.invalid", "Content-Type": "text/plain"},
        {
            "Origin": f"http://{PUBLIC_HOST}:{PUBLIC_PORT + 1}",
            "Content-Type": "text/plain",
        },
    ):
        harness = build_ui_harness()
        assert (
            harness.client.post(
                "/session",
                content=BOOTSTRAP,
                headers=headers,
                follow_redirects=False,
            ).status_code
            == 403
        )


def test_session_exchange_rejects_duplicate_origin_headers() -> None:
    """Catch ambiguous duplicate Origin values bypassing exact-origin validation."""
    harness = build_ui_harness()

    response = harness.client.post(
        "/session",
        content=BOOTSTRAP,
        headers=[
            ("Origin", PUBLIC_ORIGIN),
            ("Origin", PUBLIC_ORIGIN),
            ("Content-Type", "text/plain"),
        ],
        follow_redirects=False,
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "host",
    [
        PUBLIC_HOST,
        f"{PUBLIC_HOST}:{PUBLIC_PORT + 1}",
        f"memory-{'2' * 32}.localhost:{PUBLIC_PORT}",
        f"127.0.0.1:{PUBLIC_PORT}",
        "localhost:43123",
        "evil.invalid",
    ],
)
def test_every_request_rejects_wrong_host_or_port(host: str) -> None:
    """Catch DNS-rebinding aliases or cookie reuse on another local origin."""
    harness = build_ui_harness()
    response = harness.client.get("/bootstrap", headers={"Host": host})

    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "header",
    [
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Prefix",
        "X-Forwarded-Port",
        "X-Forwarded-Proto",
        "X-Forwarded-Server",
        "X-Original-Host",
        "X-Original-URL",
        "X-Real-IP",
        "X-Rewrite-URL",
    ],
)
def test_every_request_rejects_forwarded_or_proxy_headers(header: str) -> None:
    """Catch proxy metadata overriding the exact public origin boundary."""
    harness = build_ui_harness()

    response = harness.client.get("/bootstrap", headers={header: "synthetic"})

    assert response.status_code == 400


@pytest.mark.parametrize(
    "header",
    [
        pytest.param("X-Cluster-Client-IP", id="identity-cluster"),
        pytest.param("X-Azure-ClientIP", id="identity-azure"),
        pytest.param("X-Appengine-User-IP", id="identity-appengine"),
        pytest.param("Fly-Client-IP", id="identity-fly"),
        pytest.param("X-Envoy-Original-Path", id="routing-envoy"),
        pytest.param("Front-End-Https", id="tls-front-end"),
        pytest.param("CloudFront-Forwarded-Proto", id="tls-cloudfront"),
        pytest.param("X-Url-Scheme", id="tls-url-scheme"),
    ],
)
def test_every_request_rejects_independently_curated_proxy_metadata(
    header: str,
) -> None:
    """Catch identity, routing, and TLS metadata outside familiar prefixes."""
    harness = build_ui_harness()

    response = harness.client.get("/bootstrap", headers={header: "synthetic"})

    assert response.status_code == 400


@settings(max_examples=24, deadline=None)
@given(
    suffix=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
        min_size=1,
        max_size=24,
    )
)
def test_every_request_rejects_generated_unapproved_custom_headers(
    suffix: str,
) -> None:
    """Catch a finite proxy blacklist accepting a new custom header name."""
    harness = build_ui_harness()

    response = harness.client.get(
        "/bootstrap",
        headers={f"X-Synthetic-{suffix}": "synthetic"},
    )

    assert response.status_code == 400


def test_current_browser_request_headers_remain_accepted() -> None:
    """Catch the fail-closed policy blocking ordinary local browser requests."""
    harness = build_ui_harness()

    response = harness.client.get(
        "/bootstrap",
        headers={
            "Accept": "text/html",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-CA,en;q=0.9",
            "Cache-Control": "max-age=0",
            "DNT": "1",
            "Priority": "u=0, i",
            "Referer": f"{PUBLIC_ORIGIN}/",
            "Sec-CH-UA": '"Synthetic Browser";v="1"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "SyntheticBrowser/1.0",
        },
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "header",
    ["Sec-CH-Client-IP", "Sec-Fetch-Forwarded-For"],
)
def test_browser_reserved_prefixes_do_not_allow_unrecognized_metadata(
    header: str,
) -> None:
    """Catch a broad browser-prefix exception reopening custom metadata."""
    harness = build_ui_harness()

    response = harness.client.get("/bootstrap", headers={header: "synthetic"})

    assert response.status_code == 400


def test_duplicate_host_header_is_rejected() -> None:
    """Catch ambiguous Host parsing between middleware and routing layers."""
    harness = build_ui_harness()

    response = harness.client.get(
        "/bootstrap",
        headers=[("Host", EXACT_HOST), ("Host", EXACT_HOST)],
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "raw_limit",
    [
        pytest.param("²", id="non-decimal-digit"),
        pytest.param("9" * 5_000, id="oversized-integer"),
    ],
)
def test_malformed_page_limits_return_a_content_free_client_refusal(
    raw_limit: str,
) -> None:
    """Catch numeric conversion escaping pagination validation as HTTP 500."""
    harness = build_ui_harness()
    authenticate(harness)

    response = harness.client.get("/sources", params={"limit": raw_limit})

    assert response.status_code == 400
    assert response.text == "Request unavailable"
    assert response.headers["cache-control"] == "no-store"
    assert harness.service.status_calls == 0


def test_sibling_host_request_with_valid_cookie_is_rejected_before_content() -> None:
    """Catch port-agnostic cookie reuse across random localhost siblings."""
    harness = build_ui_harness()
    authenticate(harness)

    response = harness.client.get(
        "/sources",
        headers={"Host": f"memory-{'2' * 32}.localhost:{PUBLIC_PORT}"},
    )

    assert response.status_code == 400
    assert harness.service.status_calls == 0


def test_absent_stale_and_cross_process_cookies_are_denied() -> None:
    """Catch cookie shape alone being treated as authenticated authority."""
    issued = build_ui_harness()
    authenticate(issued)
    cookie = issued.session_cookie
    for value in ("", "unknown", cookie):
        target = build_ui_harness()
        if value:
            target.client.cookies.set("memory_ui_session", value, path="/")
        assert target.client.get("/status").status_code == 401


def test_state_change_requires_exact_origin_and_csrf() -> None:
    harness = build_ui_harness()
    authenticate(harness)

    assert (
        harness.client.post(
            "/inbox",
            headers={"Origin": "https://evil.invalid"},
        ).status_code
        == 403
    )
    assert (
        harness.client.post(
            "/inbox",
            headers={"Origin": PUBLIC_ORIGIN},
        ).status_code
        == 403
    )
    assert (
        harness.client.post(
            "/inbox",
            headers={
                "Origin": PUBLIC_ORIGIN,
                "X-Memory-CSRF": "synthetic-wrong-csrf",
            },
        ).status_code
        == 403
    )
    assert (
        harness.client.post(
            "/inbox",
            headers={
                "Origin": PUBLIC_ORIGIN,
                "X-Memory-CSRF": harness.session.csrf_token,
            },
        ).status_code
        == 405
    )


def test_state_change_rejects_duplicate_origin_or_csrf_headers() -> None:
    """Catch duplicate singleton headers becoming ambiguous mutation authority."""
    for duplicated_header in ("Origin", "X-Memory-CSRF"):
        harness = build_ui_harness()
        authenticate(harness)
        headers = [
            ("Origin", PUBLIC_ORIGIN),
            ("X-Memory-CSRF", harness.session.csrf_token),
        ]
        value = (
            PUBLIC_ORIGIN
            if duplicated_header == "Origin"
            else harness.session.csrf_token
        )
        headers.append((duplicated_header, value))

        response = harness.client.post("/inbox", headers=headers)

        assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    ["/bootstrap", "/static/app.css", "/sources", "/missing"],
)
def test_every_success_and_error_response_has_security_headers(path: str) -> None:
    """Catch cache, referrer, sniffing, or framing exposure on any response path."""
    harness = build_ui_harness()
    if path in {"/sources", "/missing"}:
        authenticate(harness)

    response = harness.client.get(path)

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_status_shell_has_exact_five_destinations_and_inbox_count_badge() -> None:
    """Catch navigation drift or an Inbox badge disconnected from owner status."""
    harness = build_ui_harness(staged_entry_count=3)
    authenticate(harness)

    response = harness.client.get("/")
    parser = NavigationParser()
    parser.feed(response.text)

    assert response.status_code == 200
    assert parser.links == [
        ("/reviews", "Pending Reviews"),
        ("/inbox", "Inbox"),
        ("/memory", "Memory"),
        ("/graph", "Graph"),
        ("/sources", "Sources & Audit"),
    ]
    assert parser.inbox_badges == ["3"]
    assert "<header" in response.text
    assert "<main" in response.text
    assert "Local Store" in response.text
    assert "Synthetic Store Home" in response.text
    assert "Synthetic Inbox" in response.text
    assert len(response.content) <= 4_194_304


STORE_STATUS_HEADER_FIELDS = (
    ("runtime-mode", "personal"),
    ("availability", "available"),
    ("pending-review-count", "1"),
    ("staged-entry-count", "3"),
    ("source-count", "7"),
    ("memory-count", "2"),
    ("searchable-count", "5"),
    ("unsearchable-count", "2"),
)


class StatusHeaderParser(HTMLParser):
    """Collect the Store-status header fields rendered outside primary nav."""

    def __init__(self) -> None:
        super().__init__()
        self.current: str | None = None
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        marker = dict(attrs).get("data-ui")
        if marker is not None and marker != "inbox-count":
            self.current = marker

    def handle_endtag(self, tag: str) -> None:
        self.current = None

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if self.current is not None and text:
            self.fields[self.current] = text


def test_every_page_carries_the_complete_store_status_header() -> None:
    """Design section 10.1 requires the full Store header on every page."""
    harness = build_ui_harness(staged_entry_count=3)
    authenticate(harness)

    for path in (
        "/",
        "/status",
        "/reviews",
        "/inbox",
        "/memory",
        "/graph",
        "/graph/governance",
        "/graph/governance/candidates",
        "/sources",
    ):
        response = harness.client.get(path)
        assert response.status_code == 200
        header = StatusHeaderParser()
        header.feed(response.text)
        for marker, value in STORE_STATUS_HEADER_FIELDS:
            assert header.fields.get(marker) == value
        assert 'href="/status"' in response.text
        assert "Local Store" in response.text
        assert "Synthetic Store Home" in response.text
        assert "Synthetic Inbox" in response.text
        assert len(response.content) <= 4_194_304
        navigation = NavigationParser()
        navigation.feed(response.text)
        assert [href for href, _text in navigation.links] == [
            "/reviews",
            "/inbox",
            "/memory",
            "/graph",
            "/sources",
        ]
        if path != "/status":
            # Store IDs and contract digests belong to the technical disclosure.
            assert "1" * 64 not in response.text
            assert "2" * 64 not in response.text


def test_guard_candidate_panel_is_a_read_that_deep_links_into_the_review() -> None:
    """Catch the governance panel losing either half of what it is for.

    It replaces reading raw `memory lint guards` JSON by eye, so the pair has
    to be readable, and acting on one has to land in the review edit form that
    already exists rather than in a second way to write a link.
    """
    harness = build_ui_harness()
    authenticate(harness)

    response = harness.client.get("/graph/governance/candidates")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "The descaling date is self-reported." in response.text
    assert "The kettle was descaled in March." in response.text
    assert "guard vocabulary" in response.text
    assert (
        "/reviews/chg_synthetic/revisions/csr_synthetic/edits/add_guard_link"
        "?guard_lineage_id=lin_guard&amp;governed_lineage_id=lin_claim"
    ) in response.text
    # Read-only: the page offers no way to write a link from here.
    assert "data-authenticated-post" not in response.text
    assert "<form" not in response.text


def test_store_status_stays_reachable_behind_a_pending_review_landing() -> None:
    """Catch the status page becoming unreachable once a draft exists."""
    harness = build_ui_harness()
    authenticate(harness)

    landing = harness.client.get("/", follow_redirects=False)
    assert landing.status_code == 303
    assert landing.headers["location"] == "/reviews"
    reviews = harness.client.get("/reviews")
    assert reviews.status_code == 200
    assert 'href="/status"' in reviews.text
    assert harness.client.get("/status").status_code == 200


def test_shell_routes_are_server_rendered_and_get_has_no_side_effect_adapter() -> None:
    """Catch a client-side application shell or GET-triggered Finder action."""
    harness = build_ui_harness()
    authenticate(harness)

    for path in (
        "/",
        "/status",
        "/reviews",
        "/inbox",
        "/memory",
        "/graph",
        "/graph/governance",
        "/graph/governance/candidates",
        "/sources",
    ):
        response = harness.client.get(path)
        assert response.status_code == 200
        assert '<script src="/static/ui.js"' in response.text
        assert "http://" not in response.text
        assert "https://" not in response.text


def test_request_errors_and_logs_do_not_echo_content_or_capabilities(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catch tokens, queries, identifiers, or filenames entering errors/logs."""
    harness = build_ui_harness()
    private_values = (
        BOOTSTRAP,
        "synthetic-private-query",
        "synthetic-private-filename.txt",
        "src_synthetic_private",
        "0" * 64,
    )

    response = harness.client.get(
        f"/sources/{private_values[3]}?query={private_values[1]}",
        headers={"Host": "evil.invalid", "X-Synthetic-Filename": private_values[2]},
    )

    combined = response.text + "\n" + caplog.text
    assert response.status_code == 400
    for value in private_values:
        assert value not in combined


class SyntheticReceive:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)
        self.calls = 0

    async def __call__(self) -> dict[str, object]:
        self.calls += 1
        try:
            chunk = next(self._chunks)
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.request", "body": chunk, "more_body": True}


class CountingSink:
    def __init__(self) -> None:
        self.byte_count = 0

    def write(self, value: bytes) -> int:
        self.byte_count += len(value)
        return len(value)


async def multipart_chunks(
    *,
    boundary: bytes,
    filename: str = "synthetic.txt",
    file_bytes: int = 1,
    trailer_bytes: int = 0,
) -> AsyncIterator[bytes]:
    yield (
        b"--"
        + boundary
        + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n'
        + b"synthetic-csrf\r\n--"
        + boundary
        + b'\r\nContent-Disposition: form-data; name="file"; filename="'
        + filename.encode("utf-8")
        + b'"\r\nContent-Type: text/plain\r\n\r\n'
    )
    block = b"x" * (1024 * 1024)
    remaining = file_bytes
    while remaining:
        chunk = block if remaining >= len(block) else block[:remaining]
        yield chunk
        remaining -= len(chunk)
    yield b"\r\n--" + boundary + b"--\r\n"
    if trailer_bytes:
        tail = b"z" * (1024 * 1024)
        remaining = trailer_bytes
        while remaining:
            chunk = tail if remaining >= len(tail) else tail[:remaining]
            yield chunk
            remaining -= len(chunk)


def multipart_document(
    boundary: bytes,
    parts: list[tuple[str, bytes, str | None, tuple[tuple[str, str], ...]]],
) -> bytes:
    output = bytearray()
    for name, value, filename, extra_headers in parts:
        output.extend(b"--" + boundary + b"\r\n")
        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        output.extend(f"Content-Disposition: {disposition}\r\n".encode())
        for header_name, header_value in extra_headers:
            output.extend(f"{header_name}: {header_value}\r\n".encode())
        output.extend(b"\r\n")
        output.extend(value)
        output.extend(b"\r\n")
    output.extend(b"--" + boundary + b"--\r\n")
    return bytes(output)


async def one_chunk(value: bytes) -> AsyncIterator[bytes]:
    yield value


def response_chunks(total: int) -> Iterator[bytes]:
    block = b"x" * 65_536
    remaining = total
    while remaining:
        chunk = block if remaining >= len(block) else block[:remaining]
        yield chunk
        remaining -= len(chunk)


def test_request_limit_formulas_are_derived_from_live_core_bounds() -> None:
    """Catch response/request budgets drifting away from accepted core values."""
    inbox = importlib.import_module("memory.inbox")
    retrieval = importlib.import_module("memory.retrieval")
    reviews = importlib.import_module("memory.reviews")
    limits = load_ui_module("request_limits")
    view_models = load_ui_module("view_models")

    assert limits.MAX_CONTROL_FORM_BODY_BYTES == (
        3 * (retrieval.MAX_QUERY_BYTES + reviews.MAX_TAGS * reviews.MAX_TAG_BYTES)
        + 65_536
    )
    assert limits.MAX_REVIEW_EDIT_BODY_BYTES == 524_288
    assert limits.MAX_CORRECTION_FORM_BODY_BYTES == 3_211_264
    assert limits.MAX_UPLOAD_FILE_BYTES == 67_108_864
    assert limits.MAX_UPLOAD_REQUEST_BYTES == 67_174_400
    assert limits.MAX_MULTIPART_HEADER_BYTES == 8_192
    assert limits.MAX_MULTIPART_PARTS == 2
    assert limits.MAX_UPLOAD_FILES == 1
    assert limits.MAX_UPLOAD_FILENAME_BYTES == 255
    assert limits.MAX_FORM_FIELDS == 160
    assert limits.MAX_CONTROL_FORM_FIELD_BYTES == 16_384
    assert limits.MAX_REVIEW_FORM_FIELD_BYTES == 65_536
    assert limits.MAX_CORRECTION_TEXT_BYTES == 1_048_576
    assert limits.MAX_STANDARD_HTML_RESPONSE_BYTES == 4_194_304
    assert limits.STANDARD_PAGE_CHROME_BYTES == 262_144
    assert limits.MAX_STANDARD_LIST_ROW_HTML_BYTES == 65_536
    assert limits.UI_STANDARD_PAGE_LIMIT == 50
    assert limits.MAX_ESCAPED_MEMORY_SUMMARY_BYTES == 5 * (
        reviews.MAX_STATEMENT_BYTES + reviews.MAX_TAGS * reviews.MAX_TAG_BYTES + 4_096
    )
    assert limits.UI_MEMORY_PAGE_LIMIT == 21
    assert limits.UI_REVIEW_ITEM_PAGE_LIMIT == view_models.OWNER_REVIEW_ITEM_PAGE_LIMIT
    assert (
        limits.UI_REVIEW_ITEM_PAGE_LIMIT
        <= (limits.MAX_STANDARD_HTML_RESPONSE_BYTES - limits.STANDARD_PAGE_CHROME_BYTES)
        // limits.MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES
    )
    assert (
        limits.STANDARD_PAGE_CHROME_BYTES
        + (reviews.MAX_CHANGE_ITEMS + inbox.MAX_BATCH_FILES)
        * limits.MAX_REVIEW_ROSTER_ROW_HTML_BYTES
        <= limits.MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES
    )


@pytest.mark.parametrize(
    "cap_name",
    [
        "MAX_CONTROL_FORM_BODY_BYTES",
        "MAX_REVIEW_EDIT_BODY_BYTES",
        "MAX_CORRECTION_FORM_BODY_BYTES",
        "MAX_UPLOAD_REQUEST_BYTES",
    ],
)
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_every_route_body_cap_checks_declared_length_before_allocation(
    cap_name: str,
    offset: int,
) -> None:
    """Catch off-by-one acceptance or body reads after declared oversize."""
    limits = load_ui_module("request_limits")
    cap = getattr(limits, cap_name)
    headers = [(b"content-length", str(cap + offset).encode("ascii"))]

    if offset <= 0:
        assert limits.validate_content_length(headers, cap) == cap + offset
    else:
        with pytest.raises(StoreError):
            limits.validate_content_length(headers, cap)


def test_declared_oversize_is_rejected_without_calling_receive() -> None:
    """Catch framework body reads occurring before the common preflight."""
    limits = load_ui_module("request_limits")
    receive = SyntheticReceive([b"private body"])

    with pytest.raises(StoreError):
        asyncio.run(
            limits.read_bounded_body(
                receive,
                headers=[(b"content-length", b"5")],
                max_bytes=4,
            )
        )

    assert receive.calls == 0


@pytest.mark.parametrize(
    ("headers", "chunks", "expected"),
    [
        ([], [b"abc", b"d"], b"abcd"),
        ([(b"content-length", b"4")], [b"ab", b"cd"], b"abcd"),
    ],
)
def test_bounded_receive_accepts_missing_or_exact_honest_lengths(
    headers: list[tuple[bytes, bytes]],
    chunks: list[bytes],
    expected: bytes,
) -> None:
    """Catch absence of Content-Length disabling actual-byte accounting."""
    limits = load_ui_module("request_limits")
    receive = SyntheticReceive(chunks)

    assert (
        asyncio.run(limits.read_bounded_body(receive, headers=headers, max_bytes=4))
        == expected
    )


def test_bounded_receive_stops_before_joining_oversize_or_dishonest_body() -> None:
    """Catch cap-crossing chunks entering a joined parser allocation."""
    limits = load_ui_module("request_limits")
    receive = SyntheticReceive([b"abc", b"de", b"must-not-be-read"])

    with pytest.raises(StoreError):
        asyncio.run(limits.read_bounded_body(receive, headers=[], max_bytes=4))

    assert receive.calls == 2
    dishonest = SyntheticReceive([b"ab"])
    with pytest.raises(StoreError):
        asyncio.run(
            limits.read_bounded_body(
                dishonest,
                headers=[(b"content-length", b"1")],
                max_bytes=4,
            )
        )


def test_content_length_refuses_duplicates_invalid_numbers_and_underflow() -> None:
    """Catch ambiguous or malformed declared lengths bypassing accounting."""
    limits = load_ui_module("request_limits")
    for headers in (
        [(b"content-length", b"1"), (b"content-length", b"1")],
        [(b"content-length", b"-1")],
        [(b"content-length", b"synthetic")],
        [(b"content-length", b"")],
    ):
        with pytest.raises(StoreError):
            limits.validate_content_length(headers, 4)


def test_control_cap_fits_worst_case_query_and_all_maximum_tags() -> None:
    """Catch the control cap becoming smaller than one maximum valid search."""
    retrieval = importlib.import_module("memory.retrieval")
    reviews = importlib.import_module("memory.reviews")
    limits = load_ui_module("request_limits")
    query = "\x7f" * retrieval.MAX_QUERY_BYTES
    tag = "\x7f" * reviews.MAX_TAG_BYTES
    fields = [("query", query), *[("tag", tag)] * reviews.MAX_TAGS]
    encoded = urllib.parse.urlencode(fields).encode("ascii")

    assert len(encoded) <= limits.MAX_CONTROL_FORM_BODY_BYTES
    parsed = limits.parse_bounded_urlencoded(
        encoded,
        max_fields=limits.MAX_FORM_FIELDS,
        max_field_bytes=limits.MAX_CONTROL_FORM_FIELD_BYTES,
    )
    assert parsed[0] == ("query", query)
    assert len(parsed) == reviews.MAX_TAGS + 1


def test_urlencoded_parser_rejects_too_many_or_oversized_fields() -> None:
    """Catch bounded bodies expanding into unbounded form structures."""
    limits = load_ui_module("request_limits")
    too_many = urllib.parse.urlencode(
        [(f"f{index}", "x") for index in range(limits.MAX_FORM_FIELDS + 1)]
    ).encode("ascii")
    too_large = urllib.parse.urlencode(
        [("query", "x" * (limits.MAX_CONTROL_FORM_FIELD_BYTES + 1))]
    ).encode("ascii")

    with pytest.raises(StoreError):
        limits.parse_bounded_urlencoded(
            too_many,
            max_fields=limits.MAX_FORM_FIELDS,
            max_field_bytes=limits.MAX_CONTROL_FORM_FIELD_BYTES,
        )
    with pytest.raises(StoreError):
        limits.parse_bounded_urlencoded(
            too_large,
            max_fields=limits.MAX_FORM_FIELDS,
            max_field_bytes=limits.MAX_CONTROL_FORM_FIELD_BYTES,
        )


def test_multipart_parser_accepts_one_csrf_field_and_one_streamed_file() -> None:
    """Catch the common upload parser losing ordered field/file accounting."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    sink = CountingSink()

    result = asyncio.run(
        limits.parse_bounded_multipart(
            multipart_chunks(boundary=boundary, file_bytes=4),
            boundary=boundary,
            file_sink=sink,
        )
    )

    assert result.fields == (("csrf", "synthetic-csrf"),)
    assert result.file is not None
    assert result.file.field_name == "file"
    assert result.file.filename == "synthetic.txt"
    assert result.file.byte_length == 4
    assert sink.byte_count == 4


@pytest.mark.parametrize(
    "parts",
    [
        [
            ("first", b"1", None, ()),
            ("second", b"2", None, ()),
            ("third", b"3", None, ()),
        ],
        [
            ("first", b"1", "first.txt", ()),
            ("second", b"2", "second.txt", ()),
        ],
    ],
)
def test_multipart_parser_rejects_too_many_parts_or_files(
    parts: list[tuple[str, bytes, str | None, tuple[tuple[str, str], ...]]],
) -> None:
    """Catch multipart structure exceeding one file plus one CSRF field."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    document = multipart_document(boundary, parts)

    with pytest.raises(StoreError):
        asyncio.run(
            limits.parse_bounded_multipart(
                one_chunk(document),
                boundary=boundary,
                file_sink=CountingSink(),
            )
        )


def test_multipart_parser_rejects_header_field_and_utf8_filename_overflow() -> None:
    """Catch per-part metadata allocating past explicit byte budgets."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    overlong_filename = "é" * 128
    documents = (
        multipart_document(
            boundary,
            [
                (
                    "file",
                    b"x",
                    "synthetic.txt",
                    (("X-Synthetic", "x" * limits.MAX_MULTIPART_HEADER_BYTES),),
                )
            ],
        ),
        multipart_document(
            boundary,
            [("csrf", b"x" * (limits.MAX_CONTROL_FORM_FIELD_BYTES + 1), None, ())],
        ),
        multipart_document(
            boundary,
            [("file", b"x", overlong_filename, ())],
        ),
    )

    for document in documents:
        with pytest.raises(StoreError):
            asyncio.run(
                limits.parse_bounded_multipart(
                    one_chunk(document),
                    boundary=boundary,
                    file_sink=CountingSink(),
                )
            )


def test_multipart_utf8_filename_accepts_exactly_255_bytes() -> None:
    """Catch character-count validation replacing the byte-count contract."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    filename = "é" * 127 + "a"
    document = multipart_document(
        boundary,
        [("file", b"x", filename, ())],
    )

    result = asyncio.run(
        limits.parse_bounded_multipart(
            one_chunk(document),
            boundary=boundary,
            file_sink=CountingSink(),
        )
    )

    assert result.file is not None
    assert result.file.filename == filename


@pytest.mark.slow
@pytest.mark.parametrize("offset", [0, 1])
def test_streaming_upload_enforces_exact_file_byte_boundary(offset: int) -> None:
    """Catch streaming file content crossing the 64 MiB custody bound."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    sink = CountingSink()
    operation = limits.parse_bounded_multipart(
        multipart_chunks(
            boundary=boundary,
            file_bytes=limits.MAX_UPLOAD_FILE_BYTES + offset,
        ),
        boundary=boundary,
        file_sink=sink,
    )

    if offset == 0:
        result = asyncio.run(operation)
        assert result.file is not None
        assert result.file.byte_length == limits.MAX_UPLOAD_FILE_BYTES
        assert sink.byte_count == limits.MAX_UPLOAD_FILE_BYTES
    else:
        with pytest.raises(StoreError):
            asyncio.run(operation)
        assert sink.byte_count <= limits.MAX_UPLOAD_FILE_BYTES


@pytest.mark.slow
def test_streaming_multipart_parser_enforces_total_request_bound() -> None:
    """Catch oversized multipart tails reaching the bounded parser or sink."""
    limits = load_ui_module("request_limits")
    boundary = b"synthetic-boundary"
    sink = CountingSink()

    with pytest.raises(StoreError):
        asyncio.run(
            limits.parse_bounded_multipart(
                multipart_chunks(
                    boundary=boundary,
                    file_bytes=limits.MAX_UPLOAD_FILE_BYTES,
                    trailer_bytes=limits.MAX_UPLOAD_REQUEST_BYTES,
                ),
                boundary=boundary,
                file_sink=sink,
            )
        )

    assert sink.byte_count <= limits.MAX_UPLOAD_FILE_BYTES


@pytest.mark.parametrize(
    "cap_name",
    [
        "MAX_STANDARD_HTML_RESPONSE_BYTES",
        "MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES",
        "MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES",
        "MAX_CORRECTION_HTML_RESPONSE_BYTES",
    ],
)
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_bounded_renderer_accepts_exact_caps_and_fails_closed_above(
    cap_name: str,
    offset: int,
) -> None:
    """Catch response truncation or off-by-one rendering beyond page budgets."""
    limits = load_ui_module("request_limits")
    cap = getattr(limits, cap_name)
    chunks = response_chunks(cap + offset)

    if offset <= 0:
        rendered = limits.render_bounded_chunks(chunks, max_bytes=cap)
        assert len(rendered) == cap + offset
    else:
        with pytest.raises(StoreError):
            limits.render_bounded_chunks(chunks, max_bytes=cap)


def test_bounded_renderer_stops_at_first_over_cap_chunk() -> None:
    """Catch continued generator consumption after a response is known unsafe."""
    limits = load_ui_module("request_limits")

    def chunks() -> Iterator[bytes]:
        yield b"1234"
        yield b"5"
        pytest.fail("renderer consumed after the first over-cap chunk")

    with pytest.raises(StoreError):
        limits.render_bounded_chunks(chunks(), max_bytes=4)


def test_correction_response_cap_covers_worst_case_html_escaping() -> None:
    """Catch a maximum valid correction becoming unrenderable or silently cut."""
    limits = load_ui_module("request_limits")
    escaped = html.escape("&" * limits.MAX_CORRECTION_TEXT_BYTES).encode("utf-8")
    exact = limits.STANDARD_PAGE_CHROME_BYTES + len(escaped) + 65_536

    assert exact == limits.MAX_CORRECTION_HTML_RESPONSE_BYTES
    assert exact + len(html.escape("&").encode("utf-8")) > (
        limits.MAX_CORRECTION_HTML_RESPONSE_BYTES
    )


def test_ui_session_lock_excludes_same_runtime_but_not_different_runtime(
    tmp_path: Path,
) -> None:
    """Catch concurrent UI sessions sharing one runtime or a global lock."""
    runtime = importlib.import_module("memory.runtime")
    first = resolve_runtime(tmp_path / "synthetic-first")
    second = resolve_runtime(tmp_path / "synthetic-second")
    first.root.mkdir(mode=0o700)
    second.root.mkdir(mode=0o700)

    with runtime.ui_session_lock(first):
        assert stat.S_IMODE(first.ui_session_lock.stat().st_mode) == 0o600
        with pytest.raises(StoreBusyError):
            with runtime.ui_session_lock(first):
                pytest.fail("same-runtime UI lock was acquired twice")
        with runtime.ui_session_lock(second):
            assert stat.S_IMODE(second.ui_session_lock.stat().st_mode) == 0o600


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_ui_session_lock_refuses_symlink_or_non_file(
    tmp_path: Path,
    replacement: str,
) -> None:
    """Catch lock-path following or locking an attacker-selected object type."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / f"synthetic-{replacement}")
    paths.root.mkdir(mode=0o700)
    if replacement == "symlink":
        target = paths.root / "synthetic-target"
        target.write_text("unchanged\n", encoding="utf-8")
        paths.ui_session_lock.symlink_to(target.name)
    else:
        paths.ui_session_lock.mkdir(mode=0o700)

    with pytest.raises(StoreError):
        with runtime.ui_session_lock(paths):
            pytest.fail("unsafe UI lock target was accepted")


def test_ui_session_lock_rejects_hard_link_without_chmodding_target(
    tmp_path: Path,
) -> None:
    """Catch an existing hard link mutating or locking an unrelated file."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-hard-link")
    paths.root.mkdir(mode=0o700)
    unrelated = tmp_path / "synthetic-unrelated"
    unrelated.write_bytes(b"synthetic unrelated bytes\n")
    unrelated.chmod(0o640)
    os.link(unrelated, paths.ui_session_lock)
    before = unrelated.stat()

    with pytest.raises(StoreError):
        with runtime.ui_session_lock(paths):
            pytest.fail("hard-linked UI lock was accepted")

    after = unrelated.stat()
    assert unrelated.read_bytes() == b"synthetic unrelated bytes\n"
    assert stat.S_IMODE(after.st_mode) == 0o640
    assert (after.st_dev, after.st_ino, after.st_nlink) == (
        before.st_dev,
        before.st_ino,
        2,
    )


def test_ui_session_lock_rejects_existing_unsafe_mode_without_repair(
    tmp_path: Path,
) -> None:
    """Catch an untrusted existing lock being chmod-repaired before validation."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-unsafe-mode")
    paths.root.mkdir(mode=0o700)
    paths.ui_session_lock.write_bytes(b"")
    paths.ui_session_lock.chmod(0o644)

    with pytest.raises(StoreError):
        with runtime.ui_session_lock(paths):
            pytest.fail("unsafe-mode UI lock was accepted")

    assert stat.S_IMODE(paths.ui_session_lock.stat().st_mode) == 0o644


def test_ui_session_lock_rejects_directory_entry_replaced_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch locking an inode no longer named by the runtime directory entry."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-entry-race")
    paths.root.mkdir(mode=0o700)
    paths.ui_session_lock.write_bytes(b"")
    paths.ui_session_lock.chmod(0o600)
    original_inode = paths.ui_session_lock.stat().st_ino
    real_open = runtime.os.open
    replacement_made = False

    def replace_after_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replacement_made
        descriptor: int = real_open(path, flags, mode, dir_fd=dir_fd)
        if (
            path == paths.ui_session_lock.name
            and dir_fd is not None
            and not flags & os.O_EXCL
            and not replacement_made
        ):
            os.unlink(path, dir_fd=dir_fd)
            replacement = real_open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            os.close(replacement)
            replacement_made = True
        return descriptor

    monkeypatch.setattr(runtime.os, "open", replace_after_open)

    with pytest.raises(StoreError):
        with runtime.ui_session_lock(paths):
            pytest.fail("replaced UI lock directory entry was accepted")

    assert replacement_made
    assert paths.ui_session_lock.stat().st_ino != original_inode


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("synthetic startup failure"), KeyboardInterrupt()],
)
def test_ui_session_lock_releases_after_startup_failure_or_signal(
    tmp_path: Path,
    failure: BaseException,
) -> None:
    """Catch startup/signal unwinding leaving a runtime permanently excluded."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-lock-release")
    paths.root.mkdir(mode=0o700)

    with pytest.raises(type(failure)):
        with runtime.ui_session_lock(paths):
            raise failure

    with runtime.ui_session_lock(paths):
        pass


def test_ui_session_lock_releases_after_normal_shutdown(tmp_path: Path) -> None:
    """Catch ordinary context exit retaining the process-level lock."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-lock-normal")
    paths.root.mkdir(mode=0o700)

    with runtime.ui_session_lock(paths):
        pass
    with runtime.ui_session_lock(paths):
        pass


def test_cli_ui_option_pairing_fails_before_runtime_access(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch launch descriptors being optional, browser-opened, or used with defaults."""
    cli = importlib.import_module("memory.cli")
    root = tmp_path / "must-remain-absent"
    cases = (
        ["ui", "--home", str(root), "--no-open"],
        ["ui", "--home", str(root), "--launch-fd", "9"],
    )

    for arguments in cases:
        assert cli.main(arguments) == 1
        output = capsys.readouterr()
        assert output.out == ""
        assert output.err == "memory: invalid_argument\n"
        assert not root.exists()


def test_run_ui_prebinds_loopback_holds_only_ui_lock_and_opens_after_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch port reopen races, early browser launch, or lifetime writer locking."""
    app = load_ui_module("app")
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-run-ui")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    opened: list[str] = []

    def fake_open(url: str) -> None:
        opened.append(url)

    def fake_serve(
        application: Any, bound_socket: socket.socket, on_ready: Any
    ) -> None:
        assert opened == []
        assert bound_socket.family == socket.AF_INET
        assert bound_socket.getsockname()[0] == "127.0.0.1"
        assert bound_socket.getsockname()[1] != 0
        assert application.state.public_origin.endswith(
            f":{bound_socket.getsockname()[1]}"
        )
        with runtime._writer_lock(paths):
            pass
        on_ready()

    monkeypatch.setattr(app, "open_bootstrap_url_with_launch_services", fake_open)
    monkeypatch.setattr(app, "_serve_ui", fake_serve)

    assert (
        app.run_ui(
            paths,
            open_browser=True,
            launch_fd=None,
        )
        == 0
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""
    assert len(opened) == 1
    assert opened[0].startswith("http://memory-")
    assert "/bootstrap#" in opened[0]
    with runtime.ui_session_lock(paths):
        pass
    assert len(synthetic_keychain) == 1


def test_run_ui_binds_one_directory_authority_before_recovery_and_reuses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch startup recovery running before or outside the service authority."""
    app = load_ui_module("app")
    inbox = importlib.import_module("memory.inbox")
    runtime = importlib.import_module("memory.runtime")
    service_module = load_ui_module("service")
    paths = resolve_runtime(tmp_path / "synthetic-authority-handoff")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    authority = inbox.bind_runtime_directory_authority(paths)
    real_service = service_module.OwnerApplicationService
    events: list[str] = []

    def bind(selected_paths: object) -> object:
        assert selected_paths == paths
        events.append("bind")
        return authority

    def recover(
        selected_paths: object,
        *,
        directory_authority: object,
    ) -> tuple[object, ...]:
        assert selected_paths == paths
        assert directory_authority is authority
        events.append("recover")
        return ()

    def service_factory(
        selected_paths: object,
        *,
        directory_authority: object,
    ) -> object:
        assert selected_paths == paths
        assert directory_authority is authority
        events.append("service")
        return real_service(
            selected_paths,
            directory_authority=directory_authority,
        )

    def serve(_application: object, _socket: socket.socket, on_ready: object) -> None:
        assert events == ["bind", "recover", "service"]
        on_ready()  # type: ignore[operator]

    monkeypatch.setattr(app, "bind_runtime_directory_authority", bind, raising=False)
    monkeypatch.setattr(app, "recover_exact_staged_entries", recover)
    monkeypatch.setattr(service_module, "OwnerApplicationService", service_factory)
    monkeypatch.setattr(app, "_serve_ui", serve)
    monkeypatch.setattr(
        app, "open_bootstrap_url_with_launch_services", lambda _url: None
    )

    assert (
        app.run_ui(
            paths,
            open_browser=True,
            launch_fd=None,
        )
        == 0
    )
    assert events == ["bind", "recover", "service"]
    assert len(synthetic_keychain) == 1


def test_ui_startup_keeps_exact_capture_when_postflight_inspection_would_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """UI startup must not hide a capture behind a second state inspection."""
    from memory.database import open_database
    from memory.keys import load_master_key

    app = load_ui_module("app")
    inbox = importlib.import_module("memory.inbox")
    runtime = importlib.import_module("memory.runtime")
    service_module = load_ui_module("service")
    paths = resolve_runtime(tmp_path / "synthetic-ui-postflight-inspection")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    identity = runtime.load_runtime_identity(paths)
    captured_at = 1_920_000_000
    recorded_at = (
        datetime.fromtimestamp(captured_at, UTC).isoformat().replace("+00:00", "Z")
    )
    body = (
        "---\n"
        "format: memory.owner-correction.v1\n"
        f"store_id: {identity.store_id}\n"
        f"target_lineage_id: lin_{'f' * 32}\n"
        f"expected_head_id: mem_{'f' * 32}\n"
        f"recorded_at: {recorded_at}\n"
        "---\n"
        "# Owner correction\n\n"
        "Synthetic UI postflight correction / 合成界面后检纠正。\n"
    ).encode()
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "f" * 32,
        batch_id="bat_" + "f" * 32,
        captured_at=captured_at,
        target_lineage_id="lin_" + "f" * 32,
        expected_head_id="mem_" + "f" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    inbox.stage_exact_private_entry(
        paths,
        display_name="synthetic-ui-postflight.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    original_capture = inbox.capture_exact_staged_entry
    original_inspection = inbox._exact_ready_issues
    captured = False

    def capture(*args: object, **kwargs: object) -> object:
        nonlocal captured
        batch = original_capture(*args, **kwargs)
        captured = True
        return batch

    def inspect(*args: object, **kwargs: object) -> object:
        if captured:
            raise OSError(5, "synthetic UI postflight inspection failure")
        return original_inspection(*args, **kwargs)

    monkeypatch.setattr(inbox, "capture_exact_staged_entry", capture)
    monkeypatch.setattr(inbox, "_exact_ready_issues", inspect)
    monkeypatch.setattr(
        service_module, "OwnerApplicationService", lambda *_a, **_k: object()
    )
    monkeypatch.setattr(app, "_serve_ui", lambda _a, _s, on_ready: on_ready())
    monkeypatch.setattr(
        app, "open_bootstrap_url_with_launch_services", lambda _url: None
    )

    assert app.run_ui(paths, open_browser=True, launch_fd=None) == 0
    connection = open_database(paths, load_master_key(identity), read_only=True)
    try:
        row = connection.execute(
            "SELECT audit_generation, (SELECT count(*) FROM inbox_batches), "
            "(SELECT count(*) FROM sources) FROM store_meta WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert captured
    assert row == (1, 1, 1)
    assert len(synthetic_keychain) == 1


@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_ui_recovery_lease_io_failure_aborts_before_socket_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    fault_operation: str,
) -> None:
    """Catch UI startup treating recovery EIO as debt and opening a listener."""
    from memory.database import open_database
    from memory.errors import InvalidArgumentError
    from memory.keys import load_master_key

    app = load_ui_module("app")
    runtime = importlib.import_module("memory.runtime")
    service_module = load_ui_module("service")
    paths = resolve_runtime(tmp_path / "synthetic-ui-recovery-eio")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    payload = paths.inbox_staging / f"ent_{'d' * 32}.stage"
    payload.write_bytes(b"")
    payload.chmod(0o600)
    payload_identity = payload.lstat()
    before_staging = {
        child.name: (child.lstat().st_ino, child.read_bytes())
        for child in paths.inbox_staging.iterdir()
    }

    def generation() -> int:
        identity = runtime.load_runtime_identity(paths)
        connection = open_database(
            paths,
            load_master_key(identity),
            read_only=True,
        )
        try:
            row = connection.execute(
                "SELECT audit_generation FROM store_meta WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
        assert row is not None
        return int(row[0])

    before_generation = generation()
    original_flock = fcntl.flock
    original_open = os.open

    def fail_payload_flock(descriptor: int, operation: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            payload_identity.st_dev,
            payload_identity.st_ino,
        ):
            raise OSError(5, "synthetic recovery lease I/O failure")
        original_flock(descriptor, operation)

    def fail_payload_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == payload.name:
            raise OSError(5, "synthetic recovery open I/O failure")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def unexpected_socket(*_args: Any, **_kwargs: Any) -> socket.socket:
        pytest.fail("recovery failure reached socket creation")

    def unexpected_service(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("recovery failure reached UI service construction")

    def unexpected_side_effect(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("recovery failure reached UI launch or serving")

    if fault_operation == "flock":
        monkeypatch.setattr(fcntl, "flock", fail_payload_flock)
    else:
        monkeypatch.setattr(os, "open", fail_payload_open)
    monkeypatch.setattr(app.socket, "socket", unexpected_socket)
    monkeypatch.setattr(service_module, "OwnerApplicationService", unexpected_service)
    monkeypatch.setattr(app, "_serve_ui", unexpected_side_effect)
    monkeypatch.setattr(
        app,
        "open_bootstrap_url_with_launch_services",
        unexpected_side_effect,
    )
    monkeypatch.setattr(app, "write_ui_launch_envelope", unexpected_side_effect)

    with pytest.raises(InvalidArgumentError, match="lease"):
        app.run_ui(paths, open_browser=True, launch_fd=None)

    assert generation() == before_generation
    assert {
        child.name: (child.lstat().st_ino, child.read_bytes())
        for child in paths.inbox_staging.iterdir()
    } == before_staging
    assert len(synthetic_keychain) == 1


@pytest.mark.parametrize("fault_operation", ["flock", "open"])
def test_ui_inspects_idle_bundle_before_exact_capture_or_startup_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    fault_operation: str,
) -> None:
    """A bundle lease failure aborts before exact capture or UI startup."""
    from memory.database import open_database
    from memory.errors import InvalidArgumentError
    from memory.keys import load_master_key

    app = load_ui_module("app")
    inbox = importlib.import_module("memory.inbox")
    runtime = importlib.import_module("memory.runtime")
    service_module = load_ui_module("service")
    paths = resolve_runtime(tmp_path / "synthetic-ui-bundle-preflight")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    identity = runtime.load_runtime_identity(paths)
    captured_at = 1_910_000_000
    recorded_at = (
        datetime.fromtimestamp(captured_at, UTC).isoformat().replace("+00:00", "Z")
    )
    body = (
        "---\n"
        "format: memory.owner-correction.v1\n"
        f"store_id: {identity.store_id}\n"
        f"target_lineage_id: lin_{'e' * 32}\n"
        f"expected_head_id: mem_{'e' * 32}\n"
        f"recorded_at: {recorded_at}\n"
        "---\n"
        "# Owner correction\n\n"
        "Synthetic UI correction / 合成界面纠正：周六浇水。\n"
    ).encode()
    metadata = ExactCaptureMetadata(
        capture_request_id="cap_" + "e" * 32,
        batch_id="bat_" + "e" * 32,
        captured_at=captured_at,
        target_lineage_id="lin_" + "e" * 32,
        expected_head_id="mem_" + "e" * 32,
        payload_sha256=hashlib.sha256(body).hexdigest(),
        source_origin=SourceCaptureOrigin.OWNER_CORRECTION,
        authorship=Authorship.OWNER,
        sensitivity=Sensitivity.RESTRICTED,
    )
    exact_entry = inbox.stage_exact_private_entry(
        paths,
        display_name="synthetic-ui-preflight-correction.md",
        chunks=(body,),
        max_bytes=len(body),
        metadata=metadata,
    )
    inbox.stage_inbox_entry(
        paths,
        owner_filename="synthetic-ui-preflight-bundle.md",
        chunks=("Synthetic UI rollback bundle / 合成回滚束。\n".encode(),),
    )
    payloads = sorted(paths.inbox_staging.glob(".recovery-*.stage"))
    assert len(payloads) == 1
    payload = payloads[0].lstat()

    def staging_snapshot() -> dict[str, tuple[object, ...]]:
        snapshot: dict[str, tuple[object, ...]] = {}
        for child in sorted(paths.inbox_staging.iterdir()):
            child_metadata = child.lstat()
            snapshot[child.name] = (
                child_metadata.st_dev,
                child_metadata.st_ino,
                child_metadata.st_mode,
                child.read_bytes()
                if stat.S_ISREG(child_metadata.st_mode)
                else tuple(sorted(item.name for item in child.iterdir())),
            )
        return snapshot

    def store_snapshot() -> tuple[int, int, int]:
        connection = open_database(
            paths,
            load_master_key(identity),
            read_only=True,
        )
        try:
            row = connection.execute(
                "SELECT audit_generation, "
                "(SELECT count(*) FROM inbox_batches), "
                "(SELECT count(*) FROM sources) "
                "FROM store_meta WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
        assert row is not None
        return int(row[0]), int(row[1]), int(row[2])

    before_staging = staging_snapshot()
    before_store = store_snapshot()
    assert exact_entry.entry_id in before_staging
    original_flock = fcntl.flock
    original_open = os.open

    def fail_payload_flock(descriptor: int, operation: int) -> None:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) == (payload.st_dev, payload.st_ino):
            raise OSError(5, "synthetic UI rollback-bundle flock failure")
        original_flock(descriptor, operation)

    def fail_payload_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == payloads[0].name:
            raise OSError(5, "synthetic UI rollback-bundle open failure")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def unexpected_socket(*_args: Any, **_kwargs: Any) -> socket.socket:
        pytest.fail("bundle inspection failure reached socket creation")

    def unexpected_service(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("bundle inspection failure reached UI service construction")

    def unexpected_side_effect(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("bundle inspection failure reached UI launch or serving")

    if fault_operation == "flock":
        monkeypatch.setattr(fcntl, "flock", fail_payload_flock)
    else:
        monkeypatch.setattr(os, "open", fail_payload_open)
    monkeypatch.setattr(app.socket, "socket", unexpected_socket)
    monkeypatch.setattr(service_module, "OwnerApplicationService", unexpected_service)
    monkeypatch.setattr(app, "_serve_ui", unexpected_side_effect)
    monkeypatch.setattr(
        app,
        "open_bootstrap_url_with_launch_services",
        unexpected_side_effect,
    )
    monkeypatch.setattr(app, "write_ui_launch_envelope", unexpected_side_effect)

    with pytest.raises(InvalidArgumentError, match="bundle lease"):
        app.run_ui(paths, open_browser=True, launch_fd=None)

    assert staging_snapshot() == before_staging
    assert store_snapshot() == before_store
    assert len(synthetic_keychain) == 1


def test_run_ui_integration_writes_one_envelope_and_only_ready_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch integration secrets escaping the inherited descriptor envelope."""
    app = load_ui_module("app")
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / "synthetic-run-ui-integration")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    read_fd, write_fd = os.pipe()

    def fake_serve(_application: Any, _socket: socket.socket, on_ready: Any) -> None:
        on_ready()

    monkeypatch.setattr(app, "_serve_ui", fake_serve)
    monkeypatch.setattr(
        app,
        "open_bootstrap_url_with_launch_services",
        lambda _url: pytest.fail("integration mode opened a browser"),
    )
    try:
        assert (
            app.run_ui(
                paths,
                open_browser=False,
                launch_fd=write_fd,
            )
            == 0
        )
        envelope = os.read(read_fd, 16_384)
        assert os.read(read_fd, 1) == b""
    finally:
        os.close(read_fd)

    output = capsys.readouterr()
    assert output.out == "memory-ui-ready\n"
    assert output.err == ""
    payload = json.loads(envelope)
    assert payload["protocol"] == "memory.ui-launch.v1"
    assert payload["bootstrap_url"].startswith(payload["origin"] + "/bootstrap#")
    assert payload["bootstrap_url"] not in output.out + output.err
    assert len(synthetic_keychain) == 1


def read_process_line(descriptor: int, *, timeout: float = 10.0) -> bytes:
    """Read one small content-free process protocol line with a hard deadline."""
    deadline = time.monotonic() + timeout
    output = bytearray()
    while b"\n" not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail("timed out waiting for process readiness")
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            pytest.fail("timed out waiting for process readiness")
        chunk = os.read(descriptor, 4_096)
        if not chunk:
            pytest.fail("process protocol closed before readiness")
        output.extend(chunk)
        if len(output) > 16_384:
            pytest.fail("process readiness output exceeded its bound")
    if output.count(b"\n") != 1 or not output.endswith(b"\n"):
        pytest.fail("process emitted more than one readiness line")
    return bytes(output)


def launch_real_ui_process(
    runtime_root: Path,
    launch_write: int,
) -> subprocess.Popen[bytes]:
    """Start the real Uvicorn path with an isolated in-process synthetic keyring."""
    script = r"""
import sys
from pathlib import Path

import keyring

from memory import keys
from memory.errors import KeyAlreadyExistsError
from memory.model import RuntimeMode
from memory.runtime import initialize_runtime, resolve_runtime
from memory.ui.app import run_ui

backend = type("Keyring", (), {})()
type(backend).__module__ = "keyring.backends.macOS"
items = {}
keyring.get_keyring = lambda: backend
keyring.get_password = lambda service, account: items.get((service, account))
keyring.set_password = lambda service, account, value: items.__setitem__((service, account), value)
def store_exclusive(identity, encoded):
    account = (keys.KEYCHAIN_SERVICE, identity.store_id)
    if account in items:
        raise KeyAlreadyExistsError("synthetic Keychain item already exists")
    items[account] = encoded
keys._store_master_key_exclusive = store_exclusive
paths = resolve_runtime(Path(sys.argv[1]))
initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
raise SystemExit(
    run_ui(
        paths,
        open_browser=False,
        launch_fd=int(sys.argv[2]),
    )
)
"""
    return subprocess.Popen(
        [sys.executable, "-c", script, str(runtime_root), str(launch_write)],
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(launch_write,),
    )


@pytest.mark.parametrize(
    "shutdown_signal",
    [signal.SIGINT, signal.SIGTERM],
    ids=["sigint", "sigterm"],
)
def test_real_uvicorn_readiness_and_signal_shutdown_release_every_capability(
    tmp_path: Path,
    shutdown_signal: signal.Signals,
) -> None:
    """Catch early readiness or signal exit retaining server, descriptor, or lock."""
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / f"synthetic-real-ui-{shutdown_signal.name}")
    launch_read, launch_write = os.pipe()
    process = launch_real_ui_process(paths.root, launch_write)
    os.close(launch_write)
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        envelope_bytes = read_process_line(launch_read)
        readable, _, _ = select.select([launch_read], [], [], 5)
        assert readable
        assert os.read(launch_read, 1) == b""
        assert read_process_line(process.stdout.fileno()) == b"memory-ui-ready\n"
        envelope = json.loads(envelope_bytes)
        parsed = urllib.parse.urlsplit(envelope["bootstrap_url"])
        if parsed.hostname is None or parsed.port is None or not parsed.fragment:
            pytest.fail("launch envelope was incomplete")
        exact_host = parsed.netloc
        origin = f"http://{exact_host}"

        connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=5)
        connection.request("GET", "/bootstrap", headers={"Host": exact_host})
        bootstrap_response = connection.getresponse()
        assert bootstrap_response.status == 200
        bootstrap_response.read()
        connection.request(
            "POST",
            "/session",
            body=parsed.fragment.encode(),
            headers={
                "Content-Type": "text/plain",
                "Host": exact_host,
                "Origin": origin,
            },
        )
        session_response = connection.getresponse()
        assert session_response.status == 303
        cookie_header = session_response.getheader("Set-Cookie")
        session_response.read()
        if cookie_header is None:
            pytest.fail("session exchange omitted its cookie")
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        if "memory_ui_session" not in cookie:
            pytest.fail("session exchange omitted its process cookie")
        session_value = cookie["memory_ui_session"].value
        connection.request(
            "GET",
            "/status",
            headers={
                "Cookie": f"memory_ui_session={session_value}",
                "Host": exact_host,
            },
        )
        status_response = connection.getresponse()
        assert status_response.status == 200
        status_response.read()
        connection.close()

        process.send_signal(shutdown_signal)
        assert process.wait(timeout=10) == 0
        stdout_tail = process.stdout.read()
        stderr = process.stderr.read()
        if stdout_tail or stderr:
            pytest.fail("UI process emitted non-protocol output")
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", parsed.port), timeout=0.5)
        with runtime.ui_session_lock(paths):
            pass
    finally:
        os.close(launch_read)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize(
    ("failure", "expected_result"),
    [(RuntimeError("synthetic startup failure"), None), (KeyboardInterrupt(), 0)],
)
def test_run_ui_invalidates_sessions_and_releases_lock_on_failure_or_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
    failure: BaseException,
    expected_result: int | None,
) -> None:
    """Catch shutdown paths retaining cookies, sockets, or same-runtime exclusion."""
    app = load_ui_module("app")
    auth = load_ui_module("auth")
    runtime = importlib.import_module("memory.runtime")
    paths = resolve_runtime(tmp_path / f"synthetic-run-ui-{type(failure).__name__}")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    created: list[Any] = []
    real_store = auth.UiSessionStore

    def session_factory(*args: object, **kwargs: object) -> Any:
        store = real_store(*args, **kwargs)
        created.append(store)
        return store

    def fail_serve(_application: Any, _socket: socket.socket, _ready: Any) -> None:
        raise failure

    monkeypatch.setattr(app, "UiSessionStore", session_factory)
    monkeypatch.setattr(app, "_serve_ui", fail_serve)
    if expected_result is None:
        with pytest.raises(type(failure)):
            app.run_ui(
                paths,
                open_browser=True,
                launch_fd=None,
            )
    else:
        assert (
            app.run_ui(
                paths,
                open_browser=True,
                launch_fd=None,
            )
            == expected_result
        )

    assert len(created) == 1
    assert created[0].active_session_count == 0
    with runtime.ui_session_lock(paths):
        pass


def test_run_ui_refuses_default_or_unauthorized_runtime_before_socket_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch UI listener creation before explicit synthetic authorization."""
    app = load_ui_module("app")

    monkeypatch.setattr(
        app.socket,
        "socket",
        lambda *_args, **_kwargs: pytest.fail("unauthorized UI created a socket"),
    )
    with pytest.raises(StoreError):
        app.run_ui(
            resolve_runtime(tmp_path / "absent-runtime"),
            open_browser=True,
            launch_fd=None,
        )


def test_run_ui_consumes_approval_and_sessions_before_releasing_its_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    synthetic_keychain: dict[tuple[str, str], str],
) -> None:
    """Catch approval or session authority surviving until after the UI lock."""
    from contextlib import contextmanager

    app = load_ui_module("app")
    runtime = importlib.import_module("memory.runtime")
    paths = runtime.resolve_runtime(tmp_path / "synthetic-ui-shutdown-store")
    runtime.initialize_runtime(paths, mode=RuntimeMode.PERSONAL)
    order: list[str] = []

    class RecordingOrchestrator(UiApprovalOrchestrator):
        def shutdown(self) -> None:
            order.append("approval")
            super().shutdown()

    class RecordingSessions(UiSessionStore):
        def invalidate_all(self) -> None:
            order.append("sessions")
            super().invalidate_all()

    real_lock = runtime.ui_session_lock

    @contextmanager
    def recording_lock(selected: Any) -> Any:
        try:
            with real_lock(selected) as held:
                yield held
        finally:
            order.append("lock")

    monkeypatch.setattr(app, "ui_session_lock", recording_lock)
    monkeypatch.setattr(app, "UiApprovalOrchestrator", RecordingOrchestrator)
    monkeypatch.setattr(app, "UiSessionStore", RecordingSessions)
    monkeypatch.setattr(
        app,
        "LocalAuthenticationOwnerPresenceVerifier",
        RefusingOwnerPresenceAdapter,
    )

    def refuse_to_serve(*_args: Any, **_kwargs: Any) -> None:
        raise StoreError("synthetic serve failure")

    monkeypatch.setattr(app, "_serve_ui", refuse_to_serve)

    with pytest.raises(StoreError):
        app.run_ui(paths, open_browser=True, launch_fd=None)

    # The idempotent outer safety net may repeat both; the lock must come after.
    assert order[:3] == ["approval", "sessions", "lock"]
    assert set(order[3:]) <= {"approval", "sessions"}
