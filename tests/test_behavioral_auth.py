"""Real client auth is invocation-scoped and never borrowed from saved homes."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_behavioral_acceptance_tool import MANIFEST_PATH, _provenance, _tool


def test_codex_auth_uses_only_its_supported_invocation_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-codex-key")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-other-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-other-token")

    assert tool._client_authentication("codex") == {
        "CODEX_API_KEY": "synthetic-codex-key"
    }
    assert (
        not {"CODEX_API_KEY", "OPENAI_API_KEY"}
        & tool._client_environment("codex").keys()
    )


@pytest.mark.parametrize("value", [None, "", " \n\t"])
def test_missing_codex_auth_blocks_before_fixture_or_inference_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    tool = _tool()
    if value is None:
        monkeypatch.delenv("CODEX_API_KEY", raising=False)
    else:
        monkeypatch.setenv("CODEX_API_KEY", value)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-unsupported-auth-source")
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = tool.create_run_state(manifest, trials=1, provenance=_provenance())
    state["private"] = {
        "memory_executable": str(tmp_path / "memory"),
        "client_executable": str(tmp_path / "codex"),
        "seed_executable": str(tmp_path / "seed"),
    }
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(tool, "_require_codex_capabilities", lambda _state: {})

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("missing scoped auth reached fixture or model work")

    monkeypatch.setattr(tool, "_run_text", forbidden)
    monkeypatch.setattr(tool, "_run_client_to_private_files", forbidden)

    with pytest.raises(tool.TrialBlocked) as captured:
        tool._actual_executor(state, manifest)(
            manifest.cases[state["slots"][0]["case_id"]],
            1,
            tmp_path / "store",
            tmp_path / "workspace",
            tmp_path / "response",
        )
    assert captured.value.label == "client_authentication_unavailable"
    assert state["slots"][0]["inference_started"] is False
    assert state["slots"][0]["client_launch_attempted"] is False


def test_claude_auth_remains_scoped_to_its_two_supported_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _tool()
    monkeypatch.setenv("CODEX_API_KEY", "synthetic-unrelated-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-anthropic-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-claude-token")

    assert tool._client_authentication("claude") == {
        "ANTHROPIC_API_KEY": "synthetic-anthropic-key",
        "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-claude-token",
    }
