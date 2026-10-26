"""Deterministic installed-acceptance preparer contract.

Every owner-gated pause is exercised through a test-owned injection point. No
test in this module triggers a real macOS owner-presence decision or starts an
installed Codex or Claude Code client.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

type Mutation = Callable[[dict[str, Any]], object]

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "tools" / "prepare-ui-acceptance.py"
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "synthetic_ui" / "manifest.yaml"
DEV_PMS = REPO_ROOT / ".venv" / "bin" / "memory"
CASE_IDS = (
    "SYN-UI-UPLOAD-001",
    "SYN-UI-REVIEW-002",
    "SYN-UI-LINEAGE-003",
    "SYN-UI-CORRECTION-004",
)
FAKE_CODEX = """\
import json
import os
import pathlib
import sys

record = pathlib.Path(os.environ["PMS_FAKE_CLIENT_RECORD"])
if sys.argv[1:] == ["--version"]:
    print(os.environ.get("PMS_FAKE_CLIENT_VERSION", "codex-cli 0.146.0"))
    raise SystemExit(0)
payload = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "stdin": sys.stdin.read(),
}
with record.open("a", encoding="utf-8") as output:
    output.write(json.dumps(payload, sort_keys=True) + "\\n")
"""
FAKE_CLAUDE = """\
import json
import os
import pathlib
import sys

record = pathlib.Path(os.environ["PMS_FAKE_CLIENT_RECORD"])
if sys.argv[1:] == ["--version"]:
    print(os.environ.get("PMS_FAKE_CLIENT_VERSION", "2.1.220 (Claude Code)"))
    raise SystemExit(0)
configs = [
    sys.argv[index + 1]
    for index, value in enumerate(sys.argv)
    if value == "--mcp-config"
]
observed = {}
for path in configs:
    target = pathlib.Path(path)
    observed[path] = {
        "mode": oct(target.stat().st_mode & 0o777),
        "payload": json.loads(target.read_text(encoding="utf-8")),
    }
payload = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "configs": observed,
    "stdin": sys.stdin.read(),
}
with record.open("a", encoding="utf-8") as output:
    output.write(json.dumps(payload, sort_keys=True) + "\\n")
"""


class Terminal:
    """A test-owned interactive stream stub for the operator view."""

    def __init__(self) -> None:
        self.written: list[str] = []

    def isatty(self) -> bool:
        return True

    def write(self, text: str) -> int:
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        return None


def load_tool() -> ModuleType:
    """Load the excluded-from-wheel preparer from its exact repository path."""
    assert TOOL_PATH.is_file(), "the installed-acceptance preparer is missing"
    specification = importlib.util.spec_from_file_location(
        "memory_prepare_ui_acceptance",
        TOOL_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return load_tool()


@pytest.fixture(scope="module")
def manifest_payload() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return payload


def write_manifest(directory: Path, payload: object) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "manifest.yaml"
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return target


def delete_synthetic_key(store_id: str) -> None:
    subprocess.run(
        [
            "/usr/bin/security",
            "delete-generic-password",
            "-s",
            "memory",
            "-a",
            store_id,
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def isolated_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTHON", "UV_"))
        and name not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}
    }


@pytest.fixture(scope="module")
def prepared(
    tool: ModuleType,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Any]:
    """Run every non-owner phase once against one disposable synthetic runtime."""
    assert DEV_PMS.is_file(), "run `uv sync --locked` before the acceptance tests"
    root = tmp_path_factory.mktemp("memory-ui-acceptance")
    home = root / "synthetic-acceptance-home"
    state_root = root / "acceptance-state"
    state_root.mkdir(mode=0o700)
    preparation = tool.Preparation(
        memory=DEV_PMS.resolve(),
        home=home,
        manifest=tool.load_manifest(MANIFEST_PATH),
        state_root=state_root,
    )
    applied: list[tuple[str, str, str]] = []

    def fake_owner_approval(
        memory: Path,
        home_path: Path,
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> None:
        """Stand in for the real macOS decision without ever prompting."""
        from memory.reviews import (
            _mint_owner_approval,
            approve_and_apply,
        )
        from memory.runtime import resolve_runtime

        assert memory == DEV_PMS.resolve()
        assert home_path == home
        paths = resolve_runtime(home_path)
        approval = _mint_owner_approval(
            paths,
            change_set_id,
            revision_id,
            digest,
            adapter="mcp_elicitation",
        )
        approve_and_apply(paths, change_set_id, revision_id, digest, approval)
        applied.append((change_set_id, revision_id, digest))

    injection = pytest.MonkeyPatch()
    injection.setattr(tool, "_spawn_owner_approval", fake_owner_approval)
    store_id = ""
    try:
        state = tool.prepare(preparation)
        store_id = json.loads((home / "runtime.json").read_text(encoding="utf-8"))[
            "store_id"
        ]
        yield tool.Prepared(
            preparation=preparation,
            state=state,
            applied=tuple(applied),
        )
    finally:
        injection.undo()
        if store_id:
            delete_synthetic_key(store_id)


def test_manifest_parser_rejects_a_duplicate_key(
    tool: ModuleType, tmp_path: Path
) -> None:
    """Catch a silently overwritten case, mapping, or digest in the manifest."""
    duplicated = (
        b'{"schema": "memory.synthetic-ui-acceptance.v1", "manifest_version": 1,'
        b' "manifest_version": 2, "cases": []}'
    )

    with pytest.raises(tool.AcceptanceError):
        tool.parse_strict_json(duplicated)


def test_manifest_validation_requires_the_exact_reviewed_roster(
    tool: ModuleType,
    manifest_payload: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Catch a preparer that would accept an unreviewed acceptance roster."""
    manifest = tool.load_manifest(MANIFEST_PATH)

    assert manifest.schema == "memory.synthetic-ui-acceptance.v1"
    assert manifest.version == 1
    assert tuple(manifest.cases) == CASE_IDS
    assert manifest.digest == hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()

    mutations: tuple[Mutation, ...] = (
        lambda payload: payload.__setitem__("schema", "memory.other.v1"),
        lambda payload: payload.__setitem__("manifest_version", 2),
        lambda payload: payload["cases"].pop(),
        lambda payload: payload["cases"].append(copy.deepcopy(payload["cases"][0])),
    )
    for mutate in mutations:
        payload = copy.deepcopy(manifest_payload)
        mutate(payload)
        target = write_manifest(tmp_path / str(id(mutate)), payload)
        with pytest.raises(tool.AcceptanceError):
            tool.load_manifest(target)


def test_manifest_validation_requires_exact_inline_digests_and_lengths(
    tool: ModuleType,
    manifest_payload: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Catch an artifact whose declared bytes no longer match its content."""
    mutations: tuple[Mutation, ...] = (
        lambda payload: payload["cases"][0]["artifact"].__setitem__("byte_length", 57),
        lambda payload: payload["cases"][0]["artifact"].__setitem__("sha256", "0" * 64),
        lambda payload: payload["cases"][1]["sources"][0].__setitem__("byte_length", 1),
        lambda payload: payload["cases"][2]["historical"]["source"].__setitem__(
            "sha256", "1" * 64
        ),
    )
    for index, mutate in enumerate(mutations):
        payload = copy.deepcopy(manifest_payload)
        mutate(payload)
        target = write_manifest(tmp_path / f"digest-{index}", payload)
        with pytest.raises(tool.AcceptanceError):
            tool.load_manifest(target)


def test_manifest_validation_resolves_every_cross_case_reference(
    tool: ModuleType,
    manifest_payload: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Catch a correction or repair mapping pointing at a missing declaration."""
    mutations: tuple[Mutation, ...] = (
        lambda payload: payload["cases"][3].__setitem__(
            "target_case_id", "SYN-UI-MISSING-999"
        ),
        lambda payload: payload["cases"][3].__setitem__("selected_revision", "future"),
        lambda payload: payload["cases"][1]["repair_operations"][0].__setitem__(
            "item_ref", "unknown_item"
        ),
        lambda payload: payload["cases"][1]["initial_review"]["source_decisions"][
            0
        ].__setitem__("source_alias", "unknown_source"),
        lambda payload: payload["cases"][1]["expected_owner_repair"]["items"][0][
            "evidence"
        ][0].__setitem__("source_alias", "unknown_source"),
    )
    for index, mutate in enumerate(mutations):
        payload = copy.deepcopy(manifest_payload)
        mutate(payload)
        target = write_manifest(tmp_path / f"reference-{index}", payload)
        with pytest.raises(tool.AcceptanceError):
            tool.load_manifest(target)


def test_manifest_validation_requires_complete_expected_mappings(
    tool: ModuleType,
    manifest_payload: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Catch a review, lineage, or correction expectation the owner cannot check."""
    mutations: tuple[Mutation, ...] = (
        lambda payload: payload["cases"][1].pop("expected_owner_repair"),
        lambda payload: payload["cases"][1]["repair_operations"].pop(),
        lambda payload: payload["cases"][2]["current"]["memory"].pop("predecessor_ref"),
        lambda payload: payload["cases"][3]["expected_successor"].pop(
            "review_cardinality"
        ),
        lambda payload: payload["cases"][3].pop("correction_text"),
    )
    for index, mutate in enumerate(mutations):
        payload = copy.deepcopy(manifest_payload)
        mutate(payload)
        target = write_manifest(tmp_path / f"mapping-{index}", payload)
        with pytest.raises(tool.AcceptanceError):
            tool.load_manifest(target)


def test_preparer_never_imports_the_source_checkout_or_a_bare_executable(
    tool: ModuleType,
) -> None:
    """Catch the acceptance tool depending on this repository or on PATH."""
    source = TOOL_PATH.read_text(encoding="utf-8")

    assert "import memory" not in source
    assert "from memory" not in source
    assert "shutil.which" not in source
    assert "shell=True" not in source
    with pytest.raises(tool.AcceptanceError):
        tool.validate_absolute_executable(Path("memory"))
    with pytest.raises(tool.AcceptanceError):
        tool.validate_absolute_executable(Path("./memory"))


def test_preparer_refuses_an_unvalidated_home_or_state_root(
    tool: ModuleType,
    tmp_path: Path,
) -> None:
    """Catch acceptance touching a default runtime or an unvalidated state root."""
    missing = tmp_path / "absent-home"
    with pytest.raises(tool.AcceptanceError):
        tool.validate_store_home(missing)

    foreign = tmp_path / "foreign-home"
    foreign.mkdir()
    (foreign / "runtime.json").write_text(
        json.dumps(
            {
                "product": "personal-memory-service",
                "runtime_mode": "live",
                "schema_lineage": "memory-store-v1",
                "schema_version": 1,
                "store_id": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(tool.AcceptanceError):
        tool.validate_store_home(foreign)

    store = tmp_path / "state-inside-store"
    store.mkdir()
    with pytest.raises(tool.AcceptanceError):
        tool.validate_state_root(store / "absent")


def test_preparer_initializes_an_absent_or_empty_acceptance_home(
    tool: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`memory init` accepts an absent or empty target; the preparer must agree."""

    class Initialized(RuntimeError):
        pass

    state_root = tmp_path / "acceptance-state"
    state_root.mkdir(mode=0o700)
    manifest = tool.load_manifest(MANIFEST_PATH)
    calls: list[Path] = []

    def record(preparation: Any) -> None:
        calls.append(preparation.home)
        raise Initialized

    monkeypatch.setattr(tool, "_initialize_runtime", record)
    for name, precreate in (("absent-home", False), ("empty-home", True)):
        home = tmp_path / name
        if precreate:
            home.mkdir(mode=0o700)
        preparation = tool.Preparation(
            memory=DEV_PMS.resolve(),
            home=home,
            manifest=manifest,
            state_root=state_root,
        )
        with pytest.raises(Initialized):
            tool.prepare(preparation)
    assert calls == [tmp_path / "absent-home", tmp_path / "empty-home"]

    occupied = tmp_path / "occupied-home"
    occupied.mkdir(mode=0o700)
    (occupied / "unrelated.txt").write_text("synthetic", encoding="utf-8")
    with pytest.raises(tool.AcceptanceError, match="absent or empty"):
        tool.prepare(
            tool.Preparation(
                memory=DEV_PMS.resolve(),
                home=occupied,
                manifest=manifest,
                state_root=state_root,
            )
        )
    assert calls == [tmp_path / "absent-home", tmp_path / "empty-home"]


def test_preparer_creates_exactly_three_isolated_ordered_capture_phases(
    prepared: Any,
) -> None:
    """Catch a phase co-batching sources or skipping its empty-Inbox boundary."""
    state = prepared.state

    assert state["phase"] == "complete"
    assert state["schema"] == "memory.ui-acceptance-state.v1"
    assert [entry["phase"] for entry in state["phases"]] == [1, 2, 3]
    batches = [entry["batch_id"] for entry in state["phases"]]
    change_sets = [entry["change_set_id"] for entry in state["phases"]]
    assert len(set(batches)) == 3
    assert len(set(change_sets)) == 3
    assert [entry["source_count"] for entry in state["phases"]] == [1, 1, 2]
    assert [entry["scan_count"] for entry in state["phases"]] == [1, 1, 1]
    assert [entry["inbox_empty_before"] for entry in state["phases"]] == [
        True,
        True,
        True,
    ]
    assert state["phases"][2]["inbox_empty_after"] is True
    assert state["phases"][0]["applied"] is True
    assert state["phases"][1]["applied"] is True
    assert state["phases"][2]["applied"] is False


def test_prepared_runtime_holds_the_expected_lineage_and_pending_review(
    tool: ModuleType,
    prepared: Any,
) -> None:
    """Catch a preparation that does not leave the exact acceptance starting state."""
    with tool.StoreClient(
        prepared.preparation.memory,
        prepared.preparation.home,
    ) as client:
        status = client.call("store.status", {})["data"]
        batches = client.call("inbox.list", {"limit": 100})["data"]
        memories = client.call("memory.search", {"query": "notebook"})["data"]

    assert status["memory_count"] == 1
    assert status["source_count"] == 4
    assert len(batches) == 3
    assert len(memories) == 1
    assert "green notebook" in memories[0]["memory"]["statement"]
    assert memories[0]["guards"] == []


def test_owner_pauses_use_only_the_validated_installed_command(
    tool: ModuleType,
    prepared: Any,
) -> None:
    """Catch a simulated decision, a shell, or an unvalidated approval command."""
    source = TOOL_PATH.read_text(encoding="utf-8")

    assert source.count("def _spawn_owner_approval(") == 1
    body = source.split("def _spawn_owner_approval(", 1)[1].split("\ndef ", 1)[0]
    assert '"approve"' in body
    assert "--revision" in body
    assert "--digest" in body
    assert "--home" in body
    assert "shell" not in body
    assert "simulate" not in source.lower()
    assert len(prepared.applied) == 2
    for _change_set, revision, digest in prepared.applied:
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert revision


def test_acceptance_state_is_mode_0600_and_content_free(prepared: Any) -> None:
    """Catch owner content, prompts, or manifest text entering preparer state."""
    path = Path(prepared.state["state_path"])

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert payload["manifest_digest"] == prepared.preparation.manifest.digest
    assert set(payload["case_ids"]) == set(CASE_IDS)
    for forbidden in (
        "blue folder",
        "amber folder",
        "red notebook",
        "green notebook",
        "printed checklist",
        "The current memory is wrong",
    ):
        assert forbidden not in raw


def test_resume_revalidates_the_manifest_digest_and_recorded_boundaries(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch a resume that trusts stale state or a replaced manifest."""
    state_path = Path(prepared.state["state_path"])
    original = state_path.read_text(encoding="utf-8")
    try:
        tampered = json.loads(original)
        tampered["manifest_digest"] = "0" * 64
        state_path.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(tool.AcceptanceError):
            tool.prepare(prepared.preparation)

        tampered = json.loads(original)
        tampered["phases"][0]["batch_id"] = "bat_synthetic_missing"
        state_path.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(tool.AcceptanceError):
            tool.prepare(prepared.preparation)
    finally:
        state_path.write_text(original, encoding="utf-8")

    resumed = tool.prepare(prepared.preparation)
    assert resumed["phase"] == "complete"
    assert [entry["batch_id"] for entry in resumed["phases"]] == [
        entry["batch_id"] for entry in prepared.state["phases"]
    ]


def test_upload_fixture_is_written_outside_the_store_and_never_captured(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catch the drag/drop fixture entering the Store, Inbox, or the console."""
    chooser = tmp_path / "owner-selected"
    chooser.mkdir()

    record = tool.write_upload_fixture(prepared.preparation, chooser)

    captured = capsys.readouterr()
    written = chooser / "syn-ui-upload-001.txt"
    assert written.is_file()
    assert written.read_bytes() == (
        b"Synthetic upload fixture for local owner UI acceptance.\n"
    )
    assert record == {
        "case_id": "SYN-UI-UPLOAD-001",
        "byte_length": 56,
        "sha256": ("9bb81753577b8258dcb028f408982796df9ae08657eee8290c4af83374b6e61c"),
    }
    assert str(chooser) not in captured.out
    assert str(chooser) not in captured.err
    assert not list(prepared.preparation.home.glob("inbox/*"))
    with tool.StoreClient(
        prepared.preparation.memory,
        prepared.preparation.home,
    ) as client:
        sources = client.call("source.list", {"limit": 100})["data"]
    assert all("syn-ui-upload-001" not in source["original_name"] for source in sources)

    with pytest.raises(tool.AcceptanceError):
        tool.write_upload_fixture(prepared.preparation, prepared.preparation.home)


def test_operator_view_refuses_a_redirected_or_noninteractive_display(
    tool: ModuleType,
    prepared: Any,
) -> None:
    """Catch synthetic case text leaving the controlling terminal."""

    class Redirected:
        def isatty(self) -> bool:
            return False

        def write(self, text: str) -> int:  # pragma: no cover - never reached
            raise AssertionError("redirected operator view must not write")

    with pytest.raises(tool.AcceptanceError):
        tool.operator_view(
            prepared.preparation,
            "SYN-UI-CORRECTION-004",
            stdin=Redirected(),
            stdout=Redirected(),
        )


def test_operator_view_renders_exact_case_text_only_to_a_terminal(
    tool: ModuleType,
    prepared: Any,
) -> None:
    """Catch a case view that omits its text or copies it into state."""

    class Terminal:
        def __init__(self) -> None:
            self.written: list[str] = []

        def isatty(self) -> bool:
            return True

        def write(self, text: str) -> int:
            self.written.append(text)
            return len(text)

        def flush(self) -> None:
            return None

    terminal = Terminal()
    tool.operator_view(
        prepared.preparation,
        "SYN-UI-CORRECTION-004",
        stdin=Terminal(),
        stdout=terminal,
    )
    rendered = "".join(terminal.written)

    assert "The current memory is wrong." in rendered
    assert "blue notebook" in rendered
    state = Path(prepared.state["state_path"]).read_text(encoding="utf-8")
    assert "blue notebook" not in state

    with pytest.raises(tool.AcceptanceError):
        tool.operator_view(
            prepared.preparation,
            "SYN-UI-MISSING-999",
            stdin=Terminal(),
            stdout=Terminal(),
        )


def write_fake_client(directory: Path, name: str, body: str) -> Path:
    target = directory / name
    target.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    target.chmod(0o700)
    return target


def test_client_launcher_requires_an_absolute_canonical_validated_executable(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch PATH resolution, a bare command, or an unvalidated client binary."""
    record = tmp_path / "client-record"
    codex = write_fake_client(tmp_path, "synthetic-codex", FAKE_CODEX)

    for candidate in (Path("codex"), Path("./codex"), tmp_path / "absent-codex"):
        with pytest.raises(tool.AcceptanceError):
            tool.launch_client(
                prepared.preparation,
                kind="codex",
                executable=candidate,
                model="synthetic-model-1",
                task="SYN-UI-UPLOAD-001",
                environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
            )

    link = tmp_path / "linked-codex"
    link.symlink_to(codex)
    launched = tool.launch_client(
        prepared.preparation,
        kind="codex",
        executable=link,
        model="synthetic-model-1",
        task="SYN-UI-UPLOAD-001",
        environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
    )

    assert launched["executable_target"] == str(codex.resolve())
    assert launched["kind"] == "codex"
    assert launched["model"] == "synthetic-model-1"
    assert launched["version"] == "codex-cli 0.146.0"
    assert set(launched) == {
        "executable_target",
        "exit_status",
        "kind",
        "model",
        "task",
        "version",
    }
    content_free = {
        key: value for key, value in launched.items() if key != "executable_target"
    }
    assert not any("/" in str(value) for value in content_free.values())
    assert str(tmp_path) not in json.dumps(content_free)


def test_client_launcher_refuses_a_kind_and_version_mismatch(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch a Claude binary accepted as Codex or an unrecognized version probe."""
    record = tmp_path / "client-record"
    claude = write_fake_client(tmp_path, "synthetic-claude", FAKE_CLAUDE)
    codex = write_fake_client(tmp_path, "synthetic-codex", FAKE_CODEX)

    with pytest.raises(tool.AcceptanceError):
        tool.launch_client(
            prepared.preparation,
            kind="codex",
            executable=claude,
            model="synthetic-model-1",
            task="SYN-UI-UPLOAD-001",
            environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
        )
    with pytest.raises(tool.AcceptanceError):
        tool.launch_client(
            prepared.preparation,
            kind="claude",
            executable=codex,
            model="synthetic-model-1",
            task="SYN-UI-UPLOAD-001",
            environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
        )
    with pytest.raises(tool.AcceptanceError):
        tool.launch_client(
            prepared.preparation,
            kind="codex",
            executable=codex,
            model="synthetic-model-1",
            task="SYN-UI-UPLOAD-001",
            environment={
                "PMS_FAKE_CLIENT_RECORD": str(record),
                "PMS_FAKE_CLIENT_VERSION": "totally-unknown 9",
            },
        )
    with pytest.raises(tool.AcceptanceError):
        tool.launch_client(
            prepared.preparation,
            kind="codex",
            executable=codex,
            model="synthetic-model-1",
            task="SYN-UI-LINEAGE-003",
            environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
        )


def test_codex_launcher_isolates_configuration_and_binds_the_same_home(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch a Codex run reading user configuration or another Store home."""
    record = tmp_path / "client-record"
    codex = write_fake_client(tmp_path, "synthetic-codex", FAKE_CODEX)

    tool.launch_client(
        prepared.preparation,
        kind="codex",
        executable=codex,
        model="synthetic-model-2",
        task="SYN-UI-UPLOAD-001",
        environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
    )

    observed = json.loads(record.read_text(encoding="utf-8").splitlines()[-1])
    argv = observed["argv"]
    assert argv[0] == "exec"
    assert "--ephemeral" in argv
    assert "--ignore-user-config" in argv
    assert "--model" in argv and argv[argv.index("--model") + 1] == "synthetic-model-2"
    joined = " ".join(argv)
    assert str(prepared.preparation.home) in joined
    assert str(prepared.preparation.memory) in joined
    assert "inbox.scan" in observed["stdin"]
    assert "exactly once" in observed["stdin"]
    for hidden in ("blue folder", "amber folder", "blue notebook"):
        assert hidden not in observed["stdin"]
    workspace = Path(observed["cwd"])
    assert (workspace / ".agents" / "skills").is_dir()


def test_claude_launcher_deletes_its_transient_mode_0600_configuration(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch a retained Claude MCP file or a nonprivate transient configuration."""
    record = tmp_path / "client-record"
    claude = write_fake_client(tmp_path, "synthetic-claude", FAKE_CLAUDE)
    tool.record_correction_batch(prepared.preparation, "bat_synthetic_claude")

    launched = tool.launch_client(
        prepared.preparation,
        kind="claude",
        executable=claude,
        model="synthetic-model-3",
        task="SYN-UI-CORRECTION-004",
        environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
    )

    observed = json.loads(record.read_text(encoding="utf-8").splitlines()[-1])
    argv = observed["argv"]
    assert "--strict-mcp-config" in argv
    assert argv[argv.index("--setting-sources") + 1] == "project"
    assert argv[argv.index("--allowedTools") + 1] == "mcp__memory_ui_acceptance"
    configuration = observed["configs"]
    assert len(configuration) == 1
    config_path, details = next(iter(configuration.items()))
    assert details["mode"] == "0o600"
    servers = details["payload"]["mcpServers"]
    assert len(servers) == 1
    only = next(iter(servers.values()))
    assert only["command"] == str(prepared.preparation.memory)
    assert only["args"] == ["mcp", "--home", str(prepared.preparation.home)]
    assert not Path(config_path).exists()
    assert launched["version"] == "2.1.220 (Claude Code)"
    workspace = Path(observed["cwd"])
    assert (workspace / ".claude" / "skills").is_dir()


def test_correction_task_supplies_only_the_sealed_batch_and_generic_steps(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch an acceptance prompt revealing a hidden expected conclusion."""
    record = tmp_path / "client-record"
    codex = write_fake_client(tmp_path, "synthetic-codex", FAKE_CODEX)
    sealed = tool.record_correction_batch(prepared.preparation, "bat_synthetic_example")

    tool.launch_client(
        prepared.preparation,
        kind="codex",
        executable=codex,
        model="synthetic-model-4",
        task="SYN-UI-CORRECTION-004",
        environment={"PMS_FAKE_CLIENT_RECORD": str(record)},
    )

    observed = json.loads(record.read_text(encoding="utf-8").splitlines()[-1])
    prompt = observed["stdin"]
    assert sealed in prompt
    assert "inbox.read" in prompt
    assert "inbox.scan" not in prompt.replace("without calling inbox.scan", "")
    for hidden in ("blue notebook", "green notebook", "same-lineage successor field"):
        assert hidden not in prompt


def test_preparer_command_line_runs_isolated_from_the_repository(
    tmp_path: Path,
) -> None:
    """Catch a preparer that cannot run with `python -I` outside the checkout."""
    outside = tmp_path / "outside-the-repository"
    outside.mkdir()

    result = subprocess.run(
        [sys.executable, "-I", str(TOOL_PATH), "--help"],
        cwd=outside,
        capture_output=True,
        check=False,
        env=isolated_environment(),
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    for option in (
        "--operator-view",
        "--launch-client",
        "--client-executable",
        "--write-upload-fixture",
        "--manifest",
        "--home",
        "--memory",
        "--state-root",
    ):
        assert option in result.stdout


def test_every_acceptance_subcommand_validates_the_synthetic_home(
    tool: ModuleType,
    prepared: Any,
    tmp_path: Path,
) -> None:
    """Catch a mistyped --home reaching a client, the fixture, or the state."""
    unprepared = tmp_path / "unprepared-home"
    unprepared.mkdir()
    state_root = tmp_path / "isolated-state"
    state_root.mkdir(mode=0o700)
    chooser = tmp_path / "owner-chooser"
    chooser.mkdir()
    codex = write_fake_client(tmp_path, "synthetic-codex", FAKE_CODEX)
    broken = tool.Preparation(
        memory=prepared.preparation.memory,
        home=unprepared,
        manifest=prepared.preparation.manifest,
        state_root=state_root,
    )

    with pytest.raises(tool.AcceptanceError):
        tool.write_upload_fixture(broken, chooser)
    with pytest.raises(tool.AcceptanceError):
        tool.record_correction_batch(broken, "bat_synthetic_example")
    with pytest.raises(tool.AcceptanceError):
        tool.operator_view(
            broken,
            "SYN-UI-CORRECTION-004",
            stdin=Terminal(),
            stdout=Terminal(),
        )
    with pytest.raises(tool.AcceptanceError):
        tool.launch_client(
            broken,
            kind="codex",
            executable=codex,
            model="synthetic-model-5",
            task="SYN-UI-UPLOAD-001",
            environment={"PMS_FAKE_CLIENT_RECORD": str(tmp_path / "unused-record")},
        )

    assert not list(chooser.iterdir())
    assert not list(state_root.iterdir())
    assert not (tmp_path / "unused-record").exists()
