"""Helpers every owner-UI suite needs, defined once.

`build_test_orchestrator` existed four times across the UI suites and had
already drifted: two of the copies could not accept a verifier at all, so a
suite that wanted one wrote its own orchestrator by hand. The point of these
helpers is that no test ever composes an approval path out of production
fakes, and four copies of that rule is four places it can quietly stop being
true.

Not a test module: pytest does not collect it.
"""

from __future__ import annotations

import importlib
from typing import Any

from memory.ui.auth import UiSessionStore
from memory.ui.owner_presence import (
    ApprovalAttemptStore,
    ApprovalChallengeLease,
    SystemMonotonicClock,
    UiApprovalOrchestrator,
    VerifiedOwnerPresence,
)


def load_ui_module(name: str) -> Any:
    """Import one `memory.ui` submodule by name, without a static import.

    Several suites reach a module only to read its constants or to monkeypatch
    it, and want the module object rather than its contents.
    """
    return importlib.import_module(f"memory.ui.{name}")


class RefusingOwnerPresenceAdapter:
    """Prove a path never reaches the OS-mediated owner-presence boundary."""

    async def verify(
        self,
        lease: ApprovalChallengeLease,
        *,
        reason: str,
    ) -> VerifiedOwnerPresence:
        raise AssertionError("this path must not request owner presence")


def build_test_orchestrator(
    service: Any,
    sessions: UiSessionStore,
    verifier: Any | None = None,
) -> UiApprovalOrchestrator:
    """Compose one test-owned approval orchestrator; never a production fake.

    The default verifier refuses outright, so any test that reaches the
    owner-presence boundary without meaning to fails loudly instead of
    silently taking a path only a real prompt should reach.
    """
    return UiApprovalOrchestrator(
        service=service,
        sessions=sessions,
        attempts=ApprovalAttemptStore(),
        verifier=RefusingOwnerPresenceAdapter() if verifier is None else verifier,
        clock=SystemMonotonicClock(),
    )
