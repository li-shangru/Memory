"""Campaign execution separates durable synthetic evidence from client scratch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast

import pytest
from test_behavioral_acceptance_tool import (
    MANIFEST_PATH,
    _connect_synthetic_mcp,
    _provenance,
    _TestClientLaunch,
    _tool,
)

from memory.model import RuntimePaths

if TYPE_CHECKING:
    from behavioral_campaign import Campaign, Cohort


@pytest.mark.parametrize(
    "failure",
    [None, "interrupt", "enter", "enter_interrupt", "recovery", "recovery_failure"],
)
def test_actual_executor_keeps_lifecycle_receipt_after_context_cleanup_and_scratch_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    from test_behavioral_execution_isolation import _execution_state

    tool = _tool()
    tool._behavioral_helper_path()
    from behavioral_client_lifecycle import ClientLifecycle

    state = _execution_state(tool, tmp_path, monkeypatch)
    durable = tmp_path / "durable-trial"
    durable.mkdir(mode=0o700)
    lifecycle = ClientLifecycle(durable / "client-events.private")
    recovery_path = tmp_path / "owned-bridge-scratch"

    def private_recovery() -> Mapping[str, object] | None:
        assert lifecycle.metadata()["transport"] == {"cleanup_confirmed": True}
        if failure not in {"recovery", "recovery_failure"}:
            return None
        return {
            "endpoint_process": {"pid": 123, "pgid": 123, "reaped": True},
            "cleanup_paths": [str(recovery_path)],
        }

    monkeypatch.setattr(
        lifecycle, "private_recovery_metadata", private_recovery, raising=False
    )
    original_receipt = tool._campaign_receipt

    def receipt(root: Path, payload: Mapping[str, object]) -> str:
        if (
            failure == "recovery_failure"
            and payload["schema"] == "memory.behavioral-client-recovery.v1"
        ):
            raise OSError("synthetic private recovery write failure")
        return str(original_receipt(root, payload))

    monkeypatch.setattr(tool, "_campaign_receipt", receipt)

    @contextmanager
    def command(*_args: object, **_kwargs: object) -> Iterator[_TestClientLaunch]:
        observer = _kwargs.get("observe_lifecycle")
        if callable(observer):
            observer(lifecycle)
        try:
            if failure == "enter":
                raise tool.AcceptanceError("synthetic setup failure")
            if failure == "enter_interrupt":
                raise KeyboardInterrupt
            yield cast(
                _TestClientLaunch,
                tool.ClientLaunch(["/synthetic/client"], lifecycle=lifecycle),
            )
        finally:
            lifecycle.record_transport({"cleanup_confirmed": True})

    def run(*_args: object, **_kwargs: object) -> tuple[int, str | None]:
        if failure == "interrupt":
            raise KeyboardInterrupt
        return 0, None

    snapshot = {
        "mcp_contract_digest": state["provenance"]["mcp_contract_digest"],
        "skill_digest": state["provenance"]["skill_digest"],
    }
    monkeypatch.setattr(tool, "_store_snapshot", lambda *_args: dict(snapshot))
    monkeypatch.setattr(tool, "_codex_execution_command", command)
    monkeypatch.setattr(tool, "_run_client_to_private_files", run)
    manifest = tool.load_manifest(MANIFEST_PATH)
    slot = state["slots"][0]

    def execute() -> object:
        return tool._actual_executor(state, manifest)(
            manifest.cases[slot["case_id"]],
            slot["trial"],
            tmp_path / "store",
            tmp_path / "workspace",
            durable / "response.private",
        )

    if failure in {"interrupt", "enter_interrupt"}:
        with pytest.raises(KeyboardInterrupt):
            execute()
    elif failure == "enter":
        with pytest.raises(tool.TrialBlocked) as captured:
            execute()
        assert captured.value.label == "client_isolation_controls_unavailable"
    else:
        result = cast(dict[str, object], execute())
        assert result["failure_label"] == (
            "client_lifecycle_receipt_failed" if failure == "recovery_failure" else None
        )
    shutil.rmtree(tmp_path / "workspace")
    receipts = list((durable / "receipts").glob("*.private.json"))
    assert len(receipts) == (2 if failure == "recovery" else 1)
    by_schema = {json.loads(path.read_bytes())["schema"]: path for path in receipts}
    raw = by_schema["memory.behavioral-client-attempt.v1"].read_bytes()
    attempt = json.loads(raw)
    assert attempt["slot_id"] == slot["slot_id"]
    assert attempt["client_launch_attempted"] is (
        failure not in {"enter", "enter_interrupt"}
    )
    assert attempt["lifecycle"]["transport"] == {"cleanup_confirmed": True}
    assert attempt["lifecycle"]["process"] == {}
    assert str(tmp_path).encode() not in raw
    assert all(path.stat().st_mode & 0o777 == 0o400 for path in receipts)
    if failure == "recovery":
        recovery = json.loads(
            by_schema["memory.behavioral-client-recovery.v1"].read_bytes()
        )
        assert recovery["slot_id"] == slot["slot_id"]
        assert recovery["lifecycle_receipt_digest"] == hashlib.sha256(raw).hexdigest()
        assert recovery["recovery"]["cleanup_paths"] == [str(recovery_path)]
        assert recovery["recovery"]["endpoint_process"] == {
            "pid": 123,
            "pgid": 123,
            "reaped": True,
        }


def test_retrying_private_receipt_syncs_existing_file_and_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = _tool()
    real_fsync = os.fsync
    failed = False
    calls: list[bool] = []

    def sync(descriptor: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("synthetic first sync interruption")
        calls.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
        real_fsync(descriptor)

    monkeypatch.setattr(tool.os, "fsync", sync)
    raw = b'{"schema":"synthetic-private-receipt.v1"}\n'
    with pytest.raises(OSError, match="synthetic first sync"):
        tool._campaign_immutable_receipt(tmp_path, raw)
    assert tool._campaign_immutable_receipt(tmp_path, raw) == tool._sha256_bytes(raw)
    assert False in calls and True in calls


@pytest.mark.parametrize("interrupted", [False, True])
def test_real_command_exposes_lifecycle_before_startup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    tool = _tool()
    tool._behavioral_helper_path()
    import behavioral_codex_isolation as isolation
    from behavioral_client_lifecycle import ClientLifecycle

    observed: list[ClientLifecycle] = []

    def fail_before_resources() -> Path:
        assert len(observed) == 1
        if interrupted:
            raise KeyboardInterrupt
        raise OSError("synthetic startup failure")

    monkeypatch.setattr(isolation, "system_python", fail_before_resources)
    with pytest.raises(KeyboardInterrupt if interrupted else tool.AcceptanceError):
        with tool._codex_execution_command(
            tmp_path / "synthetic-client",
            tmp_path / "synthetic-memory",
            tmp_path / "synthetic-store",
            tmp_path / "synthetic-workspace",
            "synthetic-model",
            None,
            events_path=tmp_path / "durable-events.private",
            observe_lifecycle=observed.append,
        ):
            pytest.fail("startup failure reached the launch boundary")
    assert len(observed) == 1
    assert observed[0].metadata()["process"] == {}
    assert observed[0].metadata()["transport"] is None


@pytest.mark.parametrize("failure", [None, "trial", "parent", "marker"])
def test_fixture_namespaces_are_synced_before_dependent_progress_and_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    from test_behavioral_campaign import _campaign

    module = _campaign()
    real_fsync, real_record = os.fsync, module.record_fixture
    synced: dict[tuple[int, int], bool] = {}
    injected = False
    prepared = 0

    def sync(descriptor: int) -> None:
        nonlocal injected
        identity = os.fstat(descriptor)
        if stat.S_ISDIR(identity.st_mode):
            names = os.listdir(descriptor)
            kind = (
                "marker"
                if "fixture-owner.private.json" in names
                else "trial"
                if "store" in names
                else "parent"
                if any(name.startswith("trial-") for name in names)
                else None
            )
            if failure is not None and kind == failure and not injected:
                injected = True
                raise OSError("synthetic fixture directory sync failure")
            real_fsync(descriptor)
            synced[(identity.st_dev, identity.st_ino)] = kind == "marker"
        else:
            real_fsync(descriptor)

    def record(
        current: Campaign,
        cohort: Cohort,
        slot_id: str,
        *,
        preparation: str,
        store_id: str | None,
        phases: Sequence[Mapping[str, object]],
    ) -> Campaign:
        nonlocal prepared
        if store_id is not None and preparation != "fixture_preparation_failed":
            paths = module.fixture_paths(current, cohort, slot_id)
            for directory in (paths.trial.parent, paths.trial, paths.store):
                identity = directory.stat()
                assert (identity.st_dev, identity.st_ino) in synced
            if preparation in {"owner_presence_prerequisite", "ready"}:
                identity = paths.trial.stat()
                assert synced[(identity.st_dev, identity.st_ino)] is True
                prepared += 1
        return cast(
            "Campaign",
            real_record(
                current,
                cohort,
                slot_id,
                preparation=preparation,
                store_id=store_id,
                phases=phases,
            ),
        )

    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(module, "record_fixture", record)
    _tool_module, module, campaign, _initialized = _prepared_campaign(
        tmp_path, monkeypatch, ready=False
    )
    assert injected is (failure is not None)
    assert prepared == (22 if failure is None else 21)
    states = [module.cohort_view(campaign, cohort) for cohort in ("base", "discovery")]
    failed = [
        slot
        for state in states
        for slot in state["slots"]
        if slot.get("fixture_preparation") == "fixture_preparation_failed"
    ]
    assert len(failed) == (0 if failure is None else 1)
    handoff = (campaign.root / "owner-review.private.sh").read_text(encoding="utf-8")
    assert (
        len([line for line in handoff.splitlines() if " approve " in line]) == prepared
    )


@pytest.mark.parametrize("interrupted", [False, True])
def test_prepared_execution_retains_evidence_after_temporary_client_loss(
    tmp_path: Path, interrupted: bool
) -> None:
    tool = _tool()
    manifest = tool.load_manifest(MANIFEST_PATH)
    state = cast(
        dict[str, Any],
        tool.create_run_state(
            manifest,
            trials=1,
            provenance={**_provenance(), "seed_mode": "owner_review"},
        ),
    )
    durable = tmp_path / "durable-campaign"
    durable.mkdir(mode=0o700)
    trial = durable / "private-trials" / "trial-001"
    trial.mkdir(mode=0o700, parents=True)
    home = trial / "store"
    home.mkdir(mode=0o700)
    synthetic_store = home / "synthetic-store-marker"
    synthetic_store.write_text("Fresh synthetic fixture identity.", encoding="utf-8")
    response = trial / "client-response.private"
    response.touch(mode=0o600)
    scratch = tmp_path / "temporary-client"
    scratch.mkdir(mode=0o700)
    saved = durable / "consumed-state.private.json"
    first = state["slots"][0]
    first["private_trial_directory"] = str(trial)
    for slot in state["slots"][1:]:
        slot["execution_outcome"] = "blocked"

    def persist(current: dict[str, Any]) -> None:
        saved.write_text(json.dumps(current), encoding="utf-8")

    def allocate(
        root: Path, selected: Mapping[str, Any], ordinal: int
    ) -> tuple[Path, Path, Path]:
        assert root == durable
        assert selected is first and ordinal == 1
        prior = json.loads(saved.read_text(encoding="utf-8"))["slots"][0]
        assert prior["attempted"] is True
        assert prior["execution_outcome"] == "interrupted"
        workspace = scratch / "fresh-client-session"
        workspace.mkdir(mode=0o700)
        return home, workspace, response

    def execute(
        _case: dict[str, Any],
        _trial: int,
        actual_home: Path,
        workspace: Path,
        capture: Path,
    ) -> dict[str, Any]:
        assert actual_home == home
        assert workspace.is_relative_to(scratch)
        assert capture == response
        capture.write_text("Synthetic observed output.", encoding="utf-8")
        if interrupted:
            raise KeyboardInterrupt
        snapshot = dict.fromkeys(tool.SNAPSHOT_FIELDS, "synthetic")
        return {
            "exit_status": 0,
            "before_status": snapshot,
            "after_status": dict(snapshot),
        }

    def run() -> None:
        tool.execute_trials(
            state,
            manifest,
            durable / "private-trials",
            execute=execute,
            persist=persist,
            allocate_prepared_trial=allocate,
        )

    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            run()
    else:
        run()
    shutil.rmtree(scratch)
    retained = json.loads(saved.read_text(encoding="utf-8"))["slots"][0]
    assert retained["attempted"] is True
    assert retained["execution_outcome"] == (
        "interrupted" if interrupted else "completed"
    )
    assert (
        synthetic_store.read_text(encoding="utf-8")
        == "Fresh synthetic fixture identity."
    )
    assert response.read_text(encoding="utf-8") == "Synthetic observed output."


@pytest.mark.parametrize("scope_matches", [True, False])
def test_campaign_fixture_scope_is_checked_before_any_store_operation(
    synthetic_store: RuntimePaths,
    monkeypatch: pytest.MonkeyPatch,
    scope_matches: bool,
) -> None:
    tool = _tool()
    case = tool.load_manifest(MANIFEST_PATH).cases["SYN-BEHAVIOR-GUARD-ZH-023"]
    operations = _connect_synthetic_mcp(tool, synthetic_store, monkeypatch)
    validated: list[Path] = []

    def validate(home: Path) -> Path:
        validated.append(home)
        return home if scope_matches else home.parent

    def temporary_only(_home: Path) -> Path:
        raise tool.AcceptanceError("synthetic fixture is outside temporary storage")

    monkeypatch.setattr(tool, "_private_root", temporary_only)
    phases: list[dict[str, Any]] = []

    def prepare() -> object:
        return tool.advance_fixture_preparation(
            Path("/synthetic/bin/memory"),
            synthetic_store.root,
            case,
            phases,
            validate_fixture_home=validate,
        )

    if scope_matches:
        assert prepare() == "owner_presence_prerequisite"
        assert len(phases) == 1
        assert "change_set.approve_and_apply" not in operations
    else:
        with pytest.raises(tool.AcceptanceError, match="fixture home"):
            prepare()
        assert not operations and not phases
    assert validated == [synthetic_store.root]


@pytest.mark.parametrize("failure", [None, "head", "same_boot", "later_generation"])
def test_reboot_cleanup_binds_imported_heads_and_never_probes_old_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    from test_behavioral_campaign import _create

    module, campaign, heads, _archive, _manifests = _create(tmp_path, monkeypatch)
    tool = _tool()
    now = int(time.time())
    receipt = tmp_path / "pause.private.json"
    cohort_payload = {
        "codex-" + cohort: {
            "state_sha256": digest,
            "state_path": "/SYNTHETIC-ABSENT-HISTORICAL-STATE",
        }
        for cohort, digest in heads.items()
    }
    payload = {
        "schema": "memory.private-work-pause.v1",
        "paused_at_utc_epoch": now - 1200,
        "cohorts": cohort_payload,
    }
    if failure == "head":
        cohort_payload["codex-base"]["state_sha256"] = "00" * 32
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    receipt.chmod(0o600)
    if failure == "later_generation":
        monkeypatch.setattr(module, "generation_number", lambda _campaign: 2)
    commands: list[list[str]] = []

    def metadata(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        boot = now - (1800 if failure == "same_boot" else 600)
        output = (
            f"{{ sec = {boot}, usec = 0 }} synthetic date"
            if command[-1] == "kern.boottime"
            else str(uuid.uuid4())
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(tool, "_run_metadata", metadata)
    if failure is None:
        digest = tool._campaign_reboot_cleanup(campaign, receipt)
        saved = json.loads(
            (campaign.root / "receipts" / f"{digest}.private.json").read_bytes()
        )
        assert saved["original_heads"] == heads
        assert saved["prior_boot_processes_cannot_survive"] is True
        assert saved["old_paths_or_pids_probed"] is False
    else:
        with pytest.raises(tool.AcceptanceError):
            tool._campaign_reboot_cleanup(campaign, receipt)
    assert all(command[:2] == ["/usr/sbin/sysctl", "-n"] for command in commands)


def _prepared_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ready: bool,
) -> tuple[ModuleType, ModuleType, Campaign, list[Path]]:
    from test_behavioral_campaign import _create

    module, campaign, _heads, _archive, _manifests = _create(tmp_path, monkeypatch)
    tool = _tool()
    initialized: list[Path] = []
    monkeypatch.setattr(
        tool,
        "_campaign_candidate_view",
        lambda current, cohort, **_kwargs: module.cohort_view(current, cohort),
    )

    def initialize(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        assert command[1:3] == ["init", "--home"]
        home = Path(command[-1])
        assert home.is_relative_to(campaign.root)
        assert not (home / "runtime.json").exists()
        initialized.append(home)
        (home / "runtime.json").write_text(
            json.dumps({"store_id": uuid.uuid4().hex}), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def advance(
        _memory: Path,
        home: Path,
        case: Mapping[str, Any],
        phases: list[dict[str, Any]],
        *,
        validate_fixture_home: Callable[[Path], Path],
    ) -> str:
        assert validate_fixture_home(home) == home
        groups = tool._fixture_groups(case)
        if not phases or (ready and len(phases) < len(groups)):
            for group in groups[len(phases) : len(phases) + 1]:
                fixture_ids = [item["fixture_id"] for item in group]
                phases.append(
                    {
                        "change_set_id": uuid.uuid4().hex,
                        "revision_id": uuid.uuid4().hex,
                        "batch_id": uuid.uuid4().hex,
                        "digest": uuid.uuid4().hex + uuid.uuid4().hex,
                        "fixture_ids": fixture_ids,
                        "sources": {name: uuid.uuid4().hex for name in fixture_ids},
                    }
                )
        return (
            "ready"
            if ready and len(phases) == len(groups)
            else "owner_presence_prerequisite"
        )

    monkeypatch.setattr(tool, "_run_text", initialize)
    monkeypatch.setattr(tool, "advance_fixture_preparation", advance)
    assert tool._campaign_fixtures(argparse.Namespace(campaign_root=campaign.root)) == 0
    if ready:
        assert (
            tool._campaign_fixtures(argparse.Namespace(campaign_root=campaign.root))
            == 0
        )
    return tool, module, module.load_campaign(campaign.root), initialized


def test_campaign_fixture_preparation_preserves_failures_and_never_supplies_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool, module, campaign, initialized = _prepared_campaign(
        tmp_path, monkeypatch, ready=False
    )
    assert len(initialized) == 22
    states = [module.cohort_view(campaign, cohort) for cohort in ("base", "discovery")]
    assert (
        sum(
            slot["execution_outcome"] == "failed"
            for state in states
            for slot in state["slots"]
        )
        == 2
    )
    assert (
        sum(
            slot.get("fixture_preparation") == "owner_presence_prerequisite"
            for state in states
            for slot in state["slots"]
            if not slot["attempted"]
        )
        == 22
    )
    handoff = (campaign.root / "owner-review.private.sh").read_text(encoding="utf-8")
    assert handoff.count(" approve ") == 22
    assert tool._campaign_fixtures(argparse.Namespace(campaign_root=campaign.root)) == 0
    assert len(initialized) == 22


@pytest.mark.parametrize("interrupted", [False, True])
def test_campaign_reserves_each_slot_before_client_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    tool, module, campaign, _initialized = _prepared_campaign(
        tmp_path, monkeypatch, ready=True
    )
    auth = tmp_path / "fresh-auth"
    auth.mkdir(mode=0o700)
    campaign = module.activate_campaign(
        campaign,
        infrastructure_binding={
            "isolation_profile_digest": "bc" * 32,
            "authentication_adapter_digest": "cd" * 32,
        },
        auth_roots={"base": auth, "discovery": auth},
        prerequisite_receipt=dict.fromkeys(
            (
                "cleanup_digest",
                "capability_digest",
                "memory_transport_digest",
                "source_binding_digest",
            ),
            "ef" * 32,
        ),
    )
    monkeypatch.setattr(tool, "_campaign_source_binding", lambda: "ef" * 32)
    monkeypatch.setattr(tool, "_subscription_session", lambda _state: None)
    launched: list[str] = []

    def executor(
        state: dict[str, Any],
        _manifest: object,
        *,
        persist: Callable[[], None],
        validate_fixture_home: Callable[[Mapping[str, Any], Path], Path],
    ) -> Callable[[dict[str, Any], int, Path, Path, Path], dict[str, Any]]:
        cohort = "base" if len(state["slots"]) == 18 else "discovery"

        def execute(
            case: dict[str, Any],
            trial: int,
            _home: Path,
            workspace: Path,
            response: Path,
        ) -> dict[str, Any]:
            slot_id = f"{case['case_id']}:{trial}"
            authoritative = module.cohort_view(
                module.load_campaign(campaign.root), cohort, active=True
            )
            slot = next(
                item for item in authoritative["slots"] if item["slot_id"] == slot_id
            )
            assert slot["attempted"] is True
            assert slot["execution_outcome"] == "interrupted"
            assert validate_fixture_home(slot, _home) == _home
            assert not workspace.is_relative_to(campaign.root)
            assert response.is_relative_to(campaign.root)
            assert slot_id not in launched
            launched.append(slot_id)
            if interrupted:
                raise KeyboardInterrupt
            snapshot = dict.fromkeys(tool.SNAPSHOT_FIELDS, "synthetic")
            response.write_text("Synthetic final answer.", encoding="utf-8")
            return {
                "exit_status": 0,
                "before_status": snapshot,
                "after_status": dict(snapshot),
            }

        return execute

    monkeypatch.setattr(tool, "_actual_executor", executor)
    arguments = argparse.Namespace(campaign_root=campaign.root)
    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            tool._campaign_run(arguments)
    else:
        assert tool._campaign_run(arguments) == 0
    states = [
        module.cohort_view(module.load_campaign(campaign.root), cohort)
        for cohort in ("base", "discovery")
    ]
    assert len(launched) == (1 if interrupted else 22)
    assert (
        sum(
            slot["execution_outcome"] == "failed"
            for state in states
            for slot in state["slots"]
        )
        == 2
    )
    assert sum(
        slot["execution_outcome"] == "interrupted"
        for state in states
        for slot in state["slots"]
    ) == (1 if interrupted else 0)


def test_actual_executor_revalidates_a_durable_fixture_through_its_campaign_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_behavioral_execution_isolation import _execution_state

    tool = _tool()
    state = _execution_state(tool, tmp_path, monkeypatch)
    state["provenance"]["seed_mode"] = "owner_review"
    state["private"]["fixture_run_id"] = "SYN-NEW-GENERATION"
    manifest = tool.load_manifest(MANIFEST_PATH)
    slot = state["slots"][0]
    case = manifest.cases[slot["case_id"]]
    groups = tool._fixture_groups(case)
    phases = [
        {
            "change_set_id": f"SYN-REVIEW-{index}",
            "revision_id": f"SYN-REVISION-{index}",
            "batch_id": f"SYN-BATCH-{index}",
            "digest": "ad" * 32,
            "fixture_ids": [item["fixture_id"] for item in group],
            "sources": {},
        }
        for index, group in enumerate(groups)
    ]
    slot.update(
        fixture_preparation="ready",
        fixture_store_id="SYN-NEW-STORE",
        fixture_phases=phases,
    )
    trial = tmp_path / "durable-trial"
    home = trial / "store"
    home.mkdir(mode=0o700, parents=True)
    (home / "runtime.json").write_text(
        json.dumps(
            {
                "store_id": slot["fixture_store_id"],
                "product": "memory",
                "runtime_mode": "personal",
                "schema_lineage": "memory-store-v1",
                "schema_version": 1,
                "inbox_path": str(home / "inbox"),
            }
        ),
        encoding="utf-8",
    )
    marker = trial / "fixture-owner.private.json"
    marker.write_text(json.dumps(tool._fixture_owner(state, slot)), encoding="utf-8")
    marker.chmod(0o600)
    observed: list[Path] = []

    def temporary_only(path: Path) -> Path:
        if path == home:
            raise tool.AcceptanceError(
                "synthetic durable home is outside temporary storage"
            )
        return path

    def validate(selected: Mapping[str, Any], path: Path) -> Path:
        assert selected["slot_id"] == slot["slot_id"] and path == home
        observed.append(path)
        return path

    def fixture_call(
        _memory: Path, path: Path, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        assert path == home
        if name == "store.status":
            return {
                "data": {
                    "store_id": slot["fixture_store_id"],
                    "source_count": sum(len(group) for group in groups),
                    "reindex_required": False,
                    "pending_review_count": 0,
                }
            }
        assert name == "change_set.get"
        phase = next(
            item
            for item in phases
            if item["change_set_id"] == arguments["change_set_id"]
        )
        return {"data": {**phase, "state": "applied"}}

    @contextmanager
    def launch(*_args: object, **_kwargs: object) -> Iterator[_TestClientLaunch]:
        yield cast(_TestClientLaunch, tool.ClientLaunch(["/synthetic/client"]))

    snapshot = dict.fromkeys(tool.SNAPSHOT_FIELDS, "synthetic")
    snapshot.update(
        mcp_contract_digest=state["provenance"]["mcp_contract_digest"],
        skill_digest=state["provenance"]["skill_digest"],
    )
    monkeypatch.setattr(tool, "_private_root", temporary_only)
    monkeypatch.setattr(tool, "_fixture_call", fixture_call)
    monkeypatch.setattr(tool, "_fixture_current", lambda *_args: {})
    monkeypatch.setattr(tool, "_store_snapshot", lambda *_args: dict(snapshot))
    monkeypatch.setattr(tool, "_codex_execution_command", launch)
    monkeypatch.setattr(
        tool, "_run_client_to_private_files", lambda *_args, **_kwargs: (0, None)
    )
    execute = tool._actual_executor(state, manifest, validate_fixture_home=validate)
    result = execute(
        case, slot["trial"], home, tmp_path / "workspace", trial / "response.private"
    )
    assert result["exit_status"] == 0 and result["failure_label"] is None
    assert observed == [home]


def test_rejected_artifact_preflight_does_not_claim_campaign_cohorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_behavioral_campaign import _campaign, _execution_paths, _inputs

    module, tool = _campaign(), _tool()
    registrar = tmp_path / "authority-namespace" / "registrar"
    monkeypatch.setattr(module, "_registrar_root", lambda: registrar)
    parent = tmp_path / "durable"
    parent.mkdir(mode=0o700)
    heads, archive, _manifests = _inputs(tmp_path)
    archive_paths = []
    for digest, raw in archive.items():
        path = tmp_path / f"{digest}.private.json"
        path.write_bytes(raw)
        path.chmod(0o400)
        archive_paths.append(path)
    paths = _execution_paths()
    arguments = argparse.Namespace(
        campaign_parent=parent,
        archive=archive_paths,
        base_head=heads["base"],
        discovery_head=heads["discovery"],
        memory=Path("/synthetic/wrong-memory"),
        client_executable=paths["client_executable"],
        build_artifact=paths["build_artifact"],
        base_manifest=paths["base_manifest"],
        discovery_manifest=paths["discovery_manifest"],
    )

    def validate(view: dict[str, Any], **_kwargs: object) -> dict[str, Any]:
        if view["private"]["memory_executable"] != str(paths["memory_executable"]):
            raise tool.AcceptanceError("prepared artifact changed")
        return view

    monkeypatch.setattr(tool, "_campaign_validate_candidate_view", validate)
    with pytest.raises(tool.AcceptanceError, match="artifact changed"):
        tool._campaign_prepare(arguments)
    assert not registrar.exists()
    assert not list(parent.iterdir())
    arguments.memory = paths["memory_executable"]
    assert tool._campaign_prepare(arguments) == 0
    index = json.loads((registrar / "index.private.json").read_bytes())
    assert len(index["cohorts"]) == 2
    assert len(index["campaigns"]) == 1


def test_source_drift_during_real_executor_setup_prevents_client_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool, module, campaign, _initialized = _prepared_campaign(
        tmp_path, monkeypatch, ready=True
    )
    auth = tmp_path / "fresh-auth"
    auth.mkdir(mode=0o700)
    campaign = module.activate_campaign(
        campaign,
        infrastructure_binding={
            "isolation_profile_digest": "bc" * 32,
            "authentication_adapter_digest": "cd" * 32,
        },
        auth_roots={"base": auth, "discovery": auth},
        prerequisite_receipt=dict.fromkeys(
            (
                "cleanup_digest",
                "capability_digest",
                "memory_transport_digest",
                "source_binding_digest",
            ),
            "ef" * 32,
        ),
    )
    drifted = False
    launched: list[bool] = []
    monkeypatch.setattr(
        tool, "_campaign_source_binding", lambda: ("aa" if drifted else "ef") * 32
    )
    monkeypatch.setattr(tool, "_subscription_session", lambda _state: object())
    monkeypatch.setattr(tool, "_require_prepared_artifacts", lambda _state: None)
    monkeypatch.setattr(tool, "_validate_bound_reasoning_effort", lambda _state: "max")
    monkeypatch.setattr(tool, "_require_codex_capabilities", lambda _state: {})
    view = module.cohort_view(campaign, "base")
    snapshot = dict.fromkeys(tool.SNAPSHOT_FIELDS, "synthetic")
    snapshot.update(
        mcp_contract_digest=view["provenance"]["mcp_contract_digest"],
        skill_digest=view["provenance"]["skill_digest"],
    )
    monkeypatch.setattr(tool, "_store_snapshot", lambda *_args: dict(snapshot))

    def skill(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        assert command[1] == "skill"
        if command[2] == "install":
            Path(command[-1]).write_text("Synthetic checked Skill.", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    class Lease:
        credential_homes = (auth, tmp_path / "client-home")
        credential_canary = tmp_path / "synthetic-canary"
        public_ca_bundle = tmp_path / "synthetic-public-ca"

        def complete(self) -> None:
            pytest.fail("failed prelaunch scope cannot complete a credential lease")

    @contextmanager
    def lease(_session: object, _home: Path) -> Iterator[Lease]:
        yield Lease()

    @contextmanager
    def protected(*_args: object, **_kwargs: object) -> Iterator[_TestClientLaunch]:
        nonlocal drifted
        drifted = True
        yield cast(_TestClientLaunch, tool.ClientLaunch(["/synthetic/client"]))

    def launch(*_args: object, **_kwargs: object) -> tuple[int, None]:
        launched.append(True)
        return 0, None

    monkeypatch.setattr(tool, "_run_text", skill)
    monkeypatch.setattr(tool, "_subscription_lease", lease)
    monkeypatch.setattr(tool, "_codex_execution_command", protected)
    monkeypatch.setattr(tool, "_run_client_to_private_files", launch)
    with pytest.raises(tool.AcceptanceError, match="source changed"):
        tool._campaign_run(argparse.Namespace(campaign_root=campaign.root))
    assert not launched
    saved = module.cohort_view(module.load_campaign(campaign.root), "base")
    consumed = saved["slots"][2]
    assert consumed["attempted"] is True
    assert consumed["client_launch_attempted"] is False
    assert consumed["inference_started"] is False
    assert consumed["execution_outcome"] == "interrupted"
    assert sum(slot["attempted"] for slot in saved["slots"]) == 3
