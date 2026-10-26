"""Durable recovery preserves fixed logical trials and one launch authority."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from test_behavioral_acceptance_tool import (
    MANIFEST_PATH,
    REPO_ROOT,
    _passing_grades,
    _tool,
)
from test_behavioral_continuation import (
    CLEANUP_DIGEST,
    CONTINUATION_SCHEMA,
    NEW_ADAPTER,
    NEW_PROFILE,
    _serialized,
    _state,
)


def _campaign() -> ModuleType:
    _tool()._behavioral_helper_path()
    return importlib.import_module("behavioral_campaign")


def _inputs(root: Path) -> tuple[dict[str, str], dict[str, bytes], dict[str, bytes]]:
    heads: dict[str, str] = {}
    archive: dict[str, bytes] = {}
    manifests = {
        "base": MANIFEST_PATH.read_bytes(),
        "discovery": (
            REPO_ROOT / "tests/fixtures/synthetic_behavioral_discovery/manifest.json"
        ).read_bytes(),
    }
    for cohort in ("base", "discovery"):
        lost = root / ("absent-original-" + cohort)
        predecessor = _state(_tool(), lost, discovery=cohort == "discovery")
        raw = _serialized(predecessor)
        digest = hashlib.sha256(raw).hexdigest()
        archive[digest] = raw
        state = copy.deepcopy(predecessor)
        state["continuation"] = {
            "schema": CONTINUATION_SCHEMA,
            "pending_slot_ids": [
                slot["slot_id"] for slot in state["slots"] if not slot["attempted"]
            ],
            "infrastructure_binding": {
                "isolation_profile_digest": NEW_PROFILE,
                "authentication_adapter_digest": NEW_ADAPTER,
            },
        }
        state["private"]["continuation"] = {
            "snapshot_path": str(lost / f"continuation-before-{digest}.private.json"),
            "snapshot_digest": digest,
            "auth_root": str(lost / "continued-auth"),
            "cleanup_evidence": str(lost / "cleanup.private.json"),
            "cleanup_digest": CLEANUP_DIGEST,
        }
        if cohort == "base":
            state["slots"][1].update(
                attempted=True,
                client_launch_attempted=True,
                inference_started=None,
                execution_outcome="failed",
                outcome_label="client_transport_failed",
                mutation_outcome="unchanged",
            )
        raw = _serialized(state)
        heads[cohort] = hashlib.sha256(raw).hexdigest()
        archive[heads[cohort]] = raw
    return heads, archive, manifests


def _create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, Any, dict[str, str], dict[str, bytes], dict[str, bytes]]:
    module = _campaign()
    registrar = tmp_path / "authority-namespace" / "registrar"
    monkeypatch.setattr(module, "_registrar_root", lambda: registrar)
    parent = tmp_path / "durable"
    parent.mkdir(mode=0o700)
    heads, archive, manifests = _inputs(tmp_path)
    campaign = module.create_campaign(
        parent,
        heads=heads,
        archive=archive,
        manifests=manifests,
        execution_paths=_execution_paths(),
    )
    return module, campaign, heads, archive, manifests


def _execution_paths() -> dict[str, Path]:
    return {
        "memory_executable": Path("/synthetic/current-memory"),
        "client_executable": Path("/synthetic/current-codex"),
        "build_artifact": Path("/synthetic/current-memory.whl"),
        "base_manifest": MANIFEST_PATH,
        "discovery_manifest": (
            REPO_ROOT / "tests/fixtures/synthetic_behavioral_discovery/manifest.json"
        ),
    }


def test_archive_recovery_never_requires_lost_paths_and_preserves_all_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, heads, archive, _manifests = _create(tmp_path, monkeypatch)
    assert not (tmp_path / "absent-original-base").exists()
    assert not (tmp_path / "absent-original-discovery").exists()
    for cohort, count, pending in (("base", 18, 16), ("discovery", 6, 6)):
        original = json.loads(archive[heads[cohort]])
        assert campaign.document["cohorts"][cohort] == original
        view = module.cohort_view(campaign, cohort)
        assert len(view["slots"]) == count
        assert sum(not slot["attempted"] for slot in view["slots"]) == pending
        assert view["private"]["fixture_run_id"] == campaign.generation_id
        assert "continuation" not in view
        for slot in view["slots"]:
            if not slot["attempted"]:
                assert slot["fixture_preparation"] == "pending"
                assert slot["fixture_store_id"] is None
                assert slot["fixture_phases"] == []
    loaded = module.load_campaign(campaign.root)
    assert loaded.digest == campaign.digest
    assert loaded.document == campaign.document


def test_another_output_parent_cannot_create_a_second_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, heads, archive, manifests = _create(tmp_path, monkeypatch)
    alternate = tmp_path / "another-durable-parent"
    alternate.mkdir(mode=0o700)
    with pytest.raises(module.CampaignError, match="claimed"):
        module.create_campaign(
            alternate,
            heads=heads,
            archive=archive,
            manifests=manifests,
            execution_paths=_execution_paths(),
        )
    assert list(alternate.iterdir()) == []
    assert module.load_campaign(campaign.root).digest == campaign.digest


def _pending(module: ModuleType, campaign: Any, cohort: str = "base") -> str:
    result = next(
        slot["slot_id"]
        for slot in module.cohort_view(campaign, cohort)["slots"]
        if not slot["attempted"]
    )
    assert isinstance(result, str)
    return result


def _prepare_cohort(module: ModuleType, campaign: Any, cohort: str) -> Any:
    manifest = json.loads(_inputs(Path("/synthetic/not-opened"))[2][cohort])
    for slot in module.cohort_view(campaign, cohort)["slots"]:
        if slot["attempted"]:
            continue
        slot_id = slot["slot_id"]
        store_id = hashlib.sha256(
            f"{campaign.generation_id}:{cohort}:{slot_id}".encode()
        ).hexdigest()[:32]
        groups = module._groups(manifest, slot["case_id"])
        phases = []
        for ordinal, fixture_ids in enumerate(groups, 1):
            identity = f"SYN-{campaign.generation_id}-{cohort}-{slot_id}-{ordinal}"
            phase = {
                "change_set_id": identity + "-change",
                "revision_id": identity + "-revision",
                "digest": hashlib.sha256(identity.encode()).hexdigest(),
                "batch_id": identity + "-batch",
                "fixture_ids": fixture_ids,
                "sources": {
                    fixture_id: identity + "-source-" + str(index)
                    for index, fixture_id in enumerate(fixture_ids)
                },
            }
            phases.append(phase)
            campaign = module.record_fixture(
                campaign,
                cohort,
                slot_id,
                preparation="ready"
                if ordinal == len(groups)
                else "owner_presence_prerequisite",
                store_id=store_id,
                phases=phases,
            )
    return campaign


def _ready(module: ModuleType, campaign: Any) -> Any:
    for cohort in ("base", "discovery"):
        campaign = _prepare_cohort(module, campaign, cohort)
    return module.mark_ready(campaign)


def _activate(module: ModuleType, campaign: Any, root: Path) -> Any:
    return module.activate_campaign(
        campaign,
        infrastructure_binding={
            "isolation_profile_digest": "ab" * 32,
            "authentication_adapter_digest": "ac" * 32,
        },
        auth_roots=dict.fromkeys(("base", "discovery"), root / "fresh-authentication"),
        prerequisite_receipt={
            "cleanup_digest": "ba" * 32,
            "capability_digest": "bb" * 32,
            "memory_transport_digest": "bc" * 32,
            "source_binding_digest": "bd" * 32,
        },
    )


def test_preflight_is_pure_and_never_uses_archived_configuration_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _campaign()
    heads, archive, manifests = _inputs(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("preflight attempted filesystem or authority access")

    monkeypatch.setattr(module, "_registrar_root", forbidden)
    monkeypatch.setattr(module, "_directory", forbidden)
    monkeypatch.setattr(module, "_read", forbidden)
    before = dict(archive)
    views = module.preflight_execution_states(
        heads=heads,
        archive=archive,
        manifests=manifests,
        execution_paths=_execution_paths(),
    )
    assert archive == before
    for cohort, state in views.items():
        assert state["private"]["client_executable"] == "/synthetic/current-codex"
        assert state["private"]["manifest_path"] == str(
            _execution_paths()[cohort + "_manifest"]
        )
        assert state["private"]["seed_executable"] is None
        assert "fixture_run_id" not in state["private"]
        assert "subscription_auth_root" not in state["private"]
        assert "continuation" not in state
        assert all(slot["private_trial_directory"] is None for slot in state["slots"])


@pytest.mark.parametrize(
    "failure", ["missing_predecessor", "changed_bytes", "source_binding"]
)
def test_invalid_archive_never_allocates_or_claims_a_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    module = _campaign()
    registrar = tmp_path / "authority-namespace" / "registrar"
    monkeypatch.setattr(module, "_registrar_root", lambda: registrar)
    heads, archive, manifests = _inputs(tmp_path)
    if failure == "missing_predecessor":
        head = json.loads(archive[heads["base"]])
        del archive[head["private"]["continuation"]["snapshot_digest"]]
    elif failure == "changed_bytes":
        archive[heads["base"]] += b" "
    else:
        head = json.loads(archive.pop(heads["base"]))
        head["provenance"]["model"] = "SYN-CHANGED-MODEL"
        raw = _serialized(head)
        heads["base"] = hashlib.sha256(raw).hexdigest()
        archive[heads["base"]] = raw
    with pytest.raises(module.CampaignError):
        module.create_campaign(
            tmp_path,
            heads=heads,
            archive=archive,
            manifests=manifests,
            execution_paths=_execution_paths(),
        )
    assert not registrar.exists()
    assert not list(tmp_path.glob("campaign-*"))


def test_copied_roots_and_symbolic_aliases_never_load_as_the_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    copied = tmp_path / "copied-campaign"
    shutil.copytree(campaign.root, copied)
    with pytest.raises(module.CampaignError, match="registered"):
        module.load_campaign(copied)
    alias = tmp_path / "aliased-campaign"
    alias.symlink_to(campaign.root, target_is_directory=True)
    with pytest.raises(module.CampaignError):
        module.load_campaign(alias)
    relocated_archive = tmp_path / "relocated-archive"
    (campaign.root / "archive").rename(relocated_archive)
    (campaign.root / "archive").symlink_to(relocated_archive, target_is_directory=True)
    with pytest.raises(module.CampaignError):
        module.load_campaign(campaign.root)


def test_all_writers_compare_the_authoritative_head_and_detect_handle_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    stale = module.load_campaign(campaign.root)
    slot_id = _pending(module, campaign)
    campaign = module.record_fixture(
        campaign,
        "base",
        slot_id,
        preparation="fixture_preparation_interrupted",
        store_id=None,
        phases=[],
    )
    with pytest.raises(module.CampaignError, match="head changed"):
        module.record_fixture(
            stale,
            "base",
            slot_id,
            preparation="fixture_preparation_interrupted",
            store_id="aa" * 16,
            phases=[],
        )
    altered = copy.deepcopy(campaign)
    altered.document["generations"][0]["members"]["base"].pop()
    with pytest.raises(module.CampaignError, match="handle was modified"):
        module.mark_ready(altered)
    assert module.load_campaign(campaign.root).digest == campaign.digest


def test_both_cohorts_require_complete_fresh_exact_reviews_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    with pytest.raises(module.CampaignError):
        _activate(module, campaign, tmp_path)
    campaign = _prepare_cohort(module, campaign, "base")
    with pytest.raises(module.CampaignError, match="both fixture cohorts"):
        module.mark_ready(campaign)
    campaign = _prepare_cohort(module, campaign, "discovery")
    campaign = module.mark_ready(campaign)
    campaign = _activate(module, campaign, tmp_path)
    assert module.generation_number(campaign) == 1
    assert set(module.activation_prerequisites(campaign)) == {
        "cleanup_digest",
        "capability_digest",
        "memory_transport_digest",
        "source_binding_digest",
    }
    view = module.cohort_view(campaign, "base", active=True)
    assert view["provenance"]["model"] == "synthetic-model"
    assert view["provenance"]["isolation_profile_digest"] == "ab" * 32
    assert view["private"]["subscription_auth_root"] == str(
        tmp_path / "fresh-authentication"
    )


def test_replacement_store_and_approval_identities_cannot_be_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    view = module.cohort_view(campaign, "base")
    slots = [slot for slot in view["slots"] if not slot["attempted"]]
    campaign = module.record_fixture(
        campaign,
        "base",
        slots[0]["slot_id"],
        preparation="fixture_preparation_interrupted",
        store_id="aa" * 16,
        phases=[],
    )
    with pytest.raises(module.CampaignError, match="Store identity was already used"):
        module.record_fixture(
            campaign,
            "base",
            slots[1]["slot_id"],
            preparation="fixture_preparation_interrupted",
            store_id="aa" * 16,
            phases=[],
        )
    # Build one valid new phase, then try to attach an archived approval digest.
    campaign = module.interrupt_campaign(campaign)
    campaign = module.start_generation(campaign)
    campaign = _prepare_cohort(module, campaign, "base")
    first = next(
        slot
        for slot in module.cohort_view(campaign, "base")["slots"]
        if not slot["attempted"]
    )
    phases = copy.deepcopy(first["fixture_phases"])
    phases[0]["digest"] = "ad" * 32
    with pytest.raises(module.CampaignError, match="history cannot be replaced"):
        module.record_fixture(
            campaign,
            "base",
            first["slot_id"],
            preparation="ready",
            store_id=first["fixture_store_id"],
            phases=phases,
        )


def test_durable_reservation_survives_lost_temporary_work_and_cannot_be_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    before = module.cohort_view(campaign, "base", active=True)
    slot = next(slot for slot in before["slots"] if slot["slot_id"] == slot_id)
    slot.update(
        attempted=True,
        execution_outcome="interrupted",
        outcome_label="execution_interrupted",
    )
    with pytest.raises(module.CampaignError):
        module.record_progress(campaign, "base", before)
    stale = module.load_campaign(campaign.root)
    campaign = module.reserve_attempt(campaign, "base", slot_id)
    campaign = module.record_progress(campaign, "base", before)
    paths = module.fixture_paths(campaign, "base", slot_id)
    for parent in reversed((paths.trial, *paths.trial.parents)):
        if parent.is_relative_to(campaign.root):
            parent.mkdir(mode=0o700, exist_ok=True)
    paths.store.mkdir(mode=0o700)
    paths.response.write_bytes(
        b"SYNTHETIC completed output retained independently of temporary work"
    )
    paths.response.chmod(0o600)
    temporary = tmp_path / "fresh-client-session"
    temporary.mkdir(mode=0o700)
    shutil.rmtree(temporary)
    reloaded = module.load_campaign(campaign.root)
    assert reloaded.digest == campaign.digest
    assert (
        module.validate_fixture_home(reloaded, "base", slot_id, paths.store)
        == paths.store
    )
    assert paths.response.read_bytes().startswith(b"SYNTHETIC")
    with pytest.raises(module.CampaignError, match="head changed"):
        module.reserve_attempt(stale, "base", slot_id)
    with pytest.raises(module.CampaignError, match="cannot be reserved again"):
        module.reserve_attempt(reloaded, "base", slot_id)
    interrupted = module.interrupt_campaign(reloaded)
    replacement = module.start_generation(interrupted)
    assert module.generation_number(replacement) == 2
    replacement_view = module.cohort_view(replacement, "base")
    assert sum(not slot["attempted"] for slot in replacement_view["slots"]) == 15
    assert (
        next(slot for slot in replacement_view["slots"] if slot["slot_id"] == slot_id)[
            "execution_outcome"
        ]
        == "interrupted"
    )
    assert (
        interrupted.document["generations"][0] == replacement.document["generations"][0]
    )
    with pytest.raises(module.CampaignError):
        module.fixture_paths(replacement, "base", slot_id)


def test_reservation_commit_failure_never_returns_a_launch_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    publish = module._publish_index

    def failed_before(_root: Path, _index: Mapping[str, object]) -> None:
        raise OSError("synthetic interruption before publication")

    monkeypatch.setattr(module, "_publish_index", failed_before)
    with pytest.raises(module.CampaignError):
        module.reserve_attempt(campaign, "base", slot_id)
    monkeypatch.setattr(module, "_publish_index", publish)
    unchanged = module.load_campaign(campaign.root)
    assert unchanged.digest == campaign.digest

    def failed_after(root: Path, index: Mapping[str, object]) -> None:
        publish(root, index)
        raise OSError("synthetic interruption after durable publication")

    monkeypatch.setattr(module, "_publish_index", failed_after)
    with pytest.raises(module.CampaignError):
        module.reserve_attempt(unchanged, "base", slot_id)
    monkeypatch.setattr(module, "_publish_index", publish)
    consumed = module.load_campaign(campaign.root)
    assert consumed.digest != unchanged.digest
    with pytest.raises(module.CampaignError, match="cannot be reserved again"):
        module.reserve_attempt(consumed, "base", slot_id)


def test_a_single_cohort_claim_blocks_pairing_it_with_a_different_cohort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, heads, archive, manifests = _create(tmp_path, monkeypatch)
    state = json.loads(archive.pop(heads["discovery"]))
    prior_digest = state["private"]["continuation"]["snapshot_digest"]
    predecessor = json.loads(archive.pop(prior_digest))
    predecessor["private"]["fixture_run_id"] = "SYN-DIFFERENT-DISCOVERY-COHORT"
    raw = _serialized(predecessor)
    digest = hashlib.sha256(raw).hexdigest()
    archive[digest] = raw
    state["private"]["fixture_run_id"] = predecessor["private"]["fixture_run_id"]
    custody = state["private"]["continuation"]
    custody["snapshot_digest"] = digest
    custody["snapshot_path"] = str(
        Path(custody["snapshot_path"]).parent
        / f"continuation-before-{digest}.private.json"
    )
    raw = _serialized(state)
    heads["discovery"] = hashlib.sha256(raw).hexdigest()
    archive[heads["discovery"]] = raw
    another = tmp_path / "another-parent"
    another.mkdir(mode=0o700)
    with pytest.raises(module.CampaignError, match="already claimed"):
        module.create_campaign(
            another,
            heads=heads,
            archive=archive,
            manifests=manifests,
            execution_paths=_execution_paths(),
        )
    assert not list(another.iterdir())
    assert module.load_campaign(campaign.root).digest == campaign.digest


def test_old_review_cannot_approve_a_fresh_store_even_as_its_first_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    slot_id = _pending(module, campaign)
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    groups = module._groups(manifest, slot_id.rsplit(":", 1)[0])
    phase = {
        "change_set_id": "SYN-NEW-CHANGE",
        "revision_id": "SYN-NEW-REVISION",
        "digest": "ad" * 32,
        "batch_id": "SYN-NEW-BATCH",
        "fixture_ids": groups[0],
        "sources": {
            fixture_id: f"SYN-SOURCE-{ordinal}"
            for ordinal, fixture_id in enumerate(groups[0])
        },
    }
    with pytest.raises(
        module.CampaignError, match="approval identity was already used"
    ):
        module.record_fixture(
            campaign,
            "base",
            slot_id,
            preparation="owner_presence_prerequisite",
            store_id="aa" * 16,
            phases=[phase],
        )
    assert module.load_campaign(campaign.root).digest == campaign.digest


def test_only_new_completed_answers_can_be_graded_once_and_public_report_is_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    campaign = module.reserve_attempt(campaign, "base", slot_id)
    view = module.cohort_view(campaign, "base", active=True)
    target = next(slot for slot in view["slots"] if slot["slot_id"] == slot_id)
    target.update(
        client_launch_attempted=True,
        inference_started=None,
        completed=True,
        execution_outcome="completed",
        outcome_label="awaiting_grade",
        mutation_outcome="unchanged",
    )
    campaign = module.record_progress(campaign, "base", view)
    manifest = _tool().load_manifest(MANIFEST_PATH)
    grades = [
        {**grade, "inference_observed": True}
        for grade in _passing_grades(view, manifest)
    ]
    _tool().grade_trials(view, manifest, grades)
    campaign = module.record_progress(campaign, "base", view)
    assert target["grade_outcome"] == "passed"
    assert target["inference_started"] is True
    changed = copy.deepcopy(view)
    changed["slots"][0].update(completed=True, grade_outcome="passed")
    with pytest.raises(module.CampaignError):
        module.record_progress(campaign, "base", changed)
    target["grade_outcome"] = "failed"
    with pytest.raises(module.CampaignError, match="terminal outcome is immutable"):
        module.record_progress(campaign, "base", view)
    report = module.report_context(campaign, "base")
    assert set(report["execution_bindings"]) == {
        "original",
        "continued",
        "replacement_001",
    }
    assert report["slot_bindings"][slot_id] == "replacement_001"
    assert report["slot_bindings"][view["slots"][0]["slot_id"]] == "original"
    assert report["slot_bindings"][view["slots"][1]["slot_id"]] == "continued"
    raw = json.dumps(report)
    for private in (
        str(campaign.root),
        campaign.generation_id,
        "SYN-CONTINUATION-RUN",
        *module.original_heads(campaign).values(),
    ):
        assert private not in raw


def test_a_ready_fixture_may_be_reverified_without_changing_its_identity_or_reviews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _prepare_cohort(module, campaign, "base")
    slot_id = _pending(module, campaign)
    slot = next(
        slot
        for slot in module.cohort_view(campaign, "base")["slots"]
        if slot["slot_id"] == slot_id
    )
    for preparation in ("fixture_preparation_interrupted", "ready"):
        campaign = module.record_fixture(
            campaign,
            "base",
            slot_id,
            preparation=preparation,
            store_id=slot["fixture_store_id"],
            phases=slot["fixture_phases"],
        )
    new = next(
        slot
        for slot in module.cohort_view(campaign, "base")["slots"]
        if slot["slot_id"] == slot_id
    )
    assert new == slot


def test_replacing_the_lock_cannot_create_a_second_writer_or_publish_stale_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _campaign()
    registrar = tmp_path / "authority-namespace" / "registrar"
    monkeypatch.setattr(module, "_registrar_root", lambda: registrar)
    with pytest.raises(module.CampaignError):
        with module._registrar(create=True) as (first_authority, first_index):
            (registrar / ".lock").unlink()
            (registrar / ".lock").touch(mode=0o600)
            with pytest.raises(module.CampaignError):
                with module._registrar(create=True):
                    pytest.fail("replacement lock admitted a second writer")
            with pytest.raises(module.CampaignError):
                module._publish_index(first_authority, first_index)


@pytest.mark.parametrize("remove", ["index", "registrar", "anchor"])
def test_lost_initialized_authority_is_never_reconstructed_as_an_empty_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, remove: str
) -> None:
    module, campaign, heads, archive, manifests = _create(tmp_path, monkeypatch)
    registrar = module._registrar_root()
    if remove == "index":
        (registrar / "index.private.json").unlink()
    elif remove == "registrar":
        shutil.rmtree(registrar)
    else:
        (registrar.parent / module._ANCHOR).unlink()
    parent = tmp_path / "second-parent"
    parent.mkdir(mode=0o700)
    with pytest.raises(module.CampaignError):
        module.create_campaign(
            parent,
            heads=heads,
            archive=archive,
            manifests=manifests,
            execution_paths=_execution_paths(),
        )
    assert list(parent.iterdir()) == []
    assert campaign.root.exists()


def test_a_moved_and_copied_registrar_cannot_rebind_its_directory_or_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    registrar = module._registrar_root()
    with pytest.raises(module.CampaignError):
        with module._registrar() as (authority, index):
            moved = tmp_path / "moved-registrar"
            registrar.rename(moved)
            shutil.copytree(moved, registrar)
            with pytest.raises(module.CampaignError):
                module._publish_index(authority, index)
            with pytest.raises(module.CampaignError):
                module.load_campaign(campaign.root)


def test_matching_immutable_retry_synchronizes_the_file_and_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _campaign()
    immutable = tmp_path / "immutable"
    immutable.mkdir(mode=0o700)
    raw = b'{"schema":"SYN-IMMUTABLE-RETRY"}\n'
    real_fsync = os.fsync

    def interrupted(_descriptor: int) -> None:
        raise OSError("synthetic failure after writing before file durability")

    monkeypatch.setattr(module.os, "fsync", interrupted)
    with pytest.raises(OSError):
        module._immutable(immutable, raw)
    observed: list[int] = []

    def synchronized(descriptor: int) -> None:
        observed.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr(module.os, "fsync", synchronized)
    assert module._immutable(immutable, raw) == hashlib.sha256(raw).hexdigest()
    assert len(observed) == 2
    assert stat.S_ISREG(observed[0])
    assert stat.S_ISDIR(observed[1])


def test_orphan_index_temp_is_inert_but_an_incomplete_immutable_blob_refuses_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    orphan = module._registrar_root() / (".index-" + "fa" * 16 + ".tmp")
    orphan.write_bytes(b'{"schema":')
    orphan.chmod(0o600)
    assert module.load_campaign(campaign.root).digest == campaign.digest
    assert orphan.read_bytes() == b'{"schema":'
    raw = b'{"schema":"SYN-INCOMPLETE-BLOB"}\n'
    incomplete = (
        campaign.root / "heads" / (hashlib.sha256(raw).hexdigest() + ".private.json")
    )
    incomplete.write_bytes(raw[:10])
    incomplete.chmod(0o400)
    with pytest.raises(module.CampaignError, match="immutable metadata changed"):
        module._immutable(campaign.root / "heads", raw)
    assert incomplete.read_bytes() == raw[:10]
    assert module.load_campaign(campaign.root).digest == campaign.digest


def test_restoring_a_valid_older_index_cannot_make_a_consumed_slot_pending_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    index_path = module._registrar_root() / "index.private.json"
    old_index = index_path.read_bytes()
    campaign = module.reserve_attempt(campaign, "base", slot_id)
    reserved_digest = campaign.digest
    index_path.write_bytes(old_index)
    with pytest.raises(module.CampaignError):
        restored = module.load_campaign(campaign.root)
        module.reserve_attempt(restored, "base", slot_id)
    assert campaign.digest == reserved_digest


@pytest.mark.parametrize("stage", ["before_open", "after_open"])
def test_process_death_during_publication_never_releases_an_unpaired_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    script = """
import os
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import behavioral_campaign as campaign
campaign._registrar_root = lambda: Path(sys.argv[2])
real_replace, real_open = os.replace, os.open
published = False
def replace(source, target, **kwargs):
    global published
    result = real_replace(source, target, **kwargs)
    if target == 'index.private.json':
        published = True
    return result
def opening(path, *args, **kwargs):
    fence = published and str(path).startswith('publication-')
    if fence and sys.argv[5] == 'before_open':
        os._exit(73)
    descriptor = real_open(path, *args, **kwargs)
    if fence:
        os._exit(73)
    return descriptor
os.replace, os.open = replace, opening
state = campaign.load_campaign(Path(sys.argv[3]))
campaign.reserve_attempt(state, 'base', sys.argv[4])
os._exit(74)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(REPO_ROOT / "tools"),
            str(module._registrar_root()),
            str(campaign.root),
            slot_id,
            stage,
        ],
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 73, result.stderr.decode()
    with pytest.raises(module.CampaignError):
        module.load_campaign(campaign.root)


def test_complete_but_unsynchronized_fence_is_revalidated_without_releasing_the_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    publications = module._registrar_root() / "publications"
    publication_inode = publications.stat().st_ino
    real_replace, real_fsync = os.replace, os.fsync
    published = False

    def replace(source: str, target: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
        nonlocal published
        real_replace(source, target, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        if target == "index.private.json":
            published = True

    def synchronize(descriptor: int) -> None:
        if published and os.fstat(descriptor).st_ino == publication_inode:
            raise OSError("synthetic loss after fence file sync before directory sync")
        real_fsync(descriptor)

    monkeypatch.setattr(module.os, "replace", replace)
    monkeypatch.setattr(module.os, "fsync", synchronize)
    with pytest.raises(module.CampaignError):
        module.reserve_attempt(campaign, "base", slot_id)
    monkeypatch.setattr(module.os, "replace", real_replace)
    monkeypatch.setattr(module.os, "fsync", real_fsync)
    reloaded = module.load_campaign(campaign.root)
    assert reloaded.digest != campaign.digest
    with pytest.raises(module.CampaignError, match="cannot be reserved again"):
        module.reserve_attempt(reloaded, "base", slot_id)


def test_publication_directory_substitution_and_trailing_partial_records_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    publications = module._registrar_root() / "publications"
    with pytest.raises(module.CampaignError):
        with module._registrar() as (authority, index):
            moved = tmp_path / "moved-publications"
            publications.rename(moved)
            shutil.copytree(moved, publications)
            with pytest.raises(module.CampaignError):
                module._publish_index(authority, index)
    with pytest.raises(module.CampaignError):
        module.load_campaign(campaign.root)


def test_a_trailing_partial_publication_is_not_ignored_as_an_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    publications = module._registrar_root() / "publications"
    raw = b'{"schema":'
    number = len(list(publications.iterdir())) + 1
    partial = (
        publications
        / f"publication-{number:08d}-{hashlib.sha256(raw).hexdigest()}.private.json"
    )
    partial.write_bytes(raw)
    partial.chmod(0o400)
    with pytest.raises(module.CampaignError):
        module.load_campaign(campaign.root)


def test_displacing_the_head_after_write_cannot_publish_a_missing_named_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    index_path = module._registrar_root() / "index.private.json"
    before_index = index_path.read_bytes()
    immutable = module._immutable

    def displaced(directory: Path, raw: bytes) -> str:
        digest = immutable(directory, raw)
        if directory == campaign.root / "heads":
            directory.rename(campaign.root / "displaced-heads")
            directory.mkdir(mode=0o700)
        assert isinstance(digest, str)
        return digest

    monkeypatch.setattr(module, "_immutable", displaced)
    with pytest.raises(module.CampaignError):
        module.reserve_attempt(campaign, "base", slot_id)
    assert index_path.read_bytes() == before_index


def test_replacing_the_named_blob_after_pointer_publication_never_returns_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, campaign, *_rest = _create(tmp_path, monkeypatch)
    campaign = _activate(module, _ready(module, campaign), tmp_path)
    slot_id = _pending(module, campaign)
    publish = module._publish_index

    def substituted(authority: object, index: dict[str, Any]) -> None:
        publish(authority, index)
        digest = index["campaigns"][campaign.document["campaign_id"]]["head_digest"]
        path = campaign.root / "heads" / (digest + ".private.json")
        raw = path.read_bytes()
        path.rename(campaign.root / "displaced-head.private.json")
        path.write_bytes(raw)
        path.chmod(0o400)

    monkeypatch.setattr(module, "_publish_index", substituted)
    with pytest.raises(module.CampaignError, match="named publication head changed"):
        module.reserve_attempt(campaign, "base", slot_id)
    monkeypatch.setattr(module, "_publish_index", publish)
    # The same bytes still describe a consumed slot. Reopening can never retry it.
    consumed = module.load_campaign(campaign.root)
    with pytest.raises(module.CampaignError, match="cannot be reserved again"):
        module.reserve_attempt(consumed, "base", slot_id)
