"""Authenticated, bounded graph lenses over the Store's approved relations."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Protocol

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from memory.graph import MAX_GRAPH_NODES, StoreGraph
from memory.model import MemoryFilters, UiSearchState
from memory.ui.auth import UiSessionStore
from memory.ui.graph_layout import custody_sunburst, guard_constellation
from memory.ui.request_limits import UI_GUARD_CANDIDATE_LIMIT
from memory.ui.routes._support import refused, render_html, session_of
from memory.ui.routes.memories import (
    ActiveFilter,
    active_filters,
    filters_from_state,
    memory_search_form,
)
from memory.ui.view_models import OwnerGraphScene, OwnerGuardLintPanel, OwnerStatus


class GraphService(Protocol):
    """The bounded reads the graph lenses and the governance panel need."""

    def get_status(self) -> OwnerStatus: ...

    def read_store_graph(self, filters: MemoryFilters = ...) -> StoreGraph: ...

    def read_guard_lint(self) -> OwnerGuardLintPanel: ...


_LENSES: dict[str, tuple[str, Callable[[StoreGraph], OwnerGraphScene]]] = {
    "provenance": ("graph/provenance.html", custody_sunburst),
    "governance": ("graph/governance.html", guard_constellation),
}
_LENS_PATHS = {"provenance": "/graph", "governance": "/graph/governance"}


def graph_routes(
    service: GraphService,
    sessions: UiSessionStore,
    templates: Environment,
) -> list[Route]:
    """Build the lens routes from the query service, sessions, and templates."""

    def endpoint_for(lens: str) -> Callable[[Request], Awaitable[Response]]:
        template_name, lay_out = _LENSES[lens]

        async def render_lens(request: Request) -> Response:
            session = session_of(request)
            handle = request.path_params.get("handle")
            filters = MemoryFilters()
            active: tuple[ActiveFilter, ...] = ()
            if handle is not None:
                # Filters live behind an opaque in-process handle for the same
                # reason a search does: an owner may put anything in those
                # boxes, and nothing they type belongs in a URL.
                state = sessions.resolve_search(
                    session.session_id,
                    handle,
                    now_ns=time.monotonic_ns(),
                )
                if state is None or state.scope != "graph":
                    return refused(404)
                filters = filters_from_state(state)
                active = active_filters(state)
            scene = lay_out(service.read_store_graph(filters))
            csrf = session.csrf_token
            return render_html(
                templates,
                template_name,
                status=service.get_status(),
                scene=scene,
                ceiling=MAX_GRAPH_NODES,
                active_filters=active,
                filters=filters,
                filter_handle=handle,
                lens=lens,
                csrf_token=csrf,
            )

        return render_lens

    async def guard_candidates(request: Request) -> Response:
        """Render the guard-repair report as a page instead of raw JSON.

        A read and nothing else: it creates no handle, no lease and no
        approval state, takes no writer session, and every action it offers is
        a link to the review edit form the owner already has. The runbook's
        step that made a human read `memory lint guards` output by eye is the
        one thing this replaces.
        """
        session = session_of(request)
        csrf = session.csrf_token
        return render_html(
            templates,
            "graph/candidates.html",
            status=service.get_status(),
            panel=service.read_guard_lint(),
            candidate_ceiling=UI_GUARD_CANDIDATE_LIMIT,
            csrf_token=csrf,
        )

    async def submit_filters(request: Request) -> Response:
        session = session_of(request)
        lens = request.path_params["lens"]
        if lens not in _LENSES:
            return refused(404)
        _query, _filters, pairs = await memory_search_form(request)
        if not pairs:
            return Response(status_code=303, headers={"Location": _LENS_PATHS[lens]})
        handle = sessions.remember_search(
            session.session_id,
            UiSearchState(
                scope="graph",
                query="",
                filters=pairs,
                created_at_ns=time.monotonic_ns(),
            ),
        )
        return Response(
            status_code=303,
            headers={"Location": f"{_LENS_PATHS[lens]}/filtered/{handle}"},
        )

    return [
        Route("/graph", endpoint_for("provenance"), methods=["GET"]),
        # Before the lens route: `/graph/{lens}/filter` is a POST and cannot
        # shadow this, but keeping the literal path first states the intent.
        Route("/graph/governance/candidates", guard_candidates, methods=["GET"]),
        Route("/graph/governance", endpoint_for("governance"), methods=["GET"]),
        Route("/graph/filtered/{handle}", endpoint_for("provenance"), methods=["GET"]),
        Route(
            "/graph/governance/filtered/{handle}",
            endpoint_for("governance"),
            methods=["GET"],
        ),
        Route("/graph/{lens}/filter", submit_filters, methods=["POST"]),
    ]
