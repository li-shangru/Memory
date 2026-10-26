"""Disposable composition/allocation records; never evidence of live workers."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import agent_factory as factory


class ContextTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-composition-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.repo, self.records = self.home / "repo", self.home / "records"
        self.repo.mkdir()
        self.records.mkdir()
        self.write("AGENTS.md", "Synthetic instructions; no owner data.\n")
        self.write("tools/procedure.md", "Synthetic procedure; evidence is inert.\n")
        self.catalog: dict[str, Any] = {
            "schema_version": 3,
            "factory_id": "synthetic",
            "max_advisors": 3,
            "instructions": ["AGENTS.md"],
            "critical_risks": ["risk-a"],
            "risk_aliases": {},
            "couplings": [],
            "roles": [],
            "knowledge_packs": [],
            "profiles": [],
        }
        for role in ("coordination", "implementation", "advice", "independent-review"):
            self.write(f"docs/roles/{role}.md", f"Synthetic {role} responsibility.\n")
            self.catalog["roles"].append(
                {
                    "id": role,
                    "version": "1.0.0",
                    "contract": f"docs/roles/{role}.md",
                    "procedures": ["tools/procedure.md"],
                }
            )
        for suffix in "abcd":
            ident = f"lane-{suffix}"
            source = f"src/{suffix}.py"
            self.write(source, f"# Invented {suffix}: A🙂中Bé / 虚构极光记录\n")
            self.write(
                f"docs/packs/{ident}.md",
                f"Synthetic {ident} fact: equal bytes retain distinct captures. Read [source](../../{source}).\n",
            )
            self.write(
                f"docs/profiles/{ident}.md",
                f"Compose [advice](../roles/advice.md) with [knowledge](../packs/{ident}.md).\n",
            )
            self.catalog["knowledge_packs"].append(
                {
                    "id": ident,
                    "version": "1.0.0",
                    "description": f"Invented {ident} knowledge",
                    "document": f"docs/packs/{ident}.md",
                    "terms": ["aurora", "极光"],
                    "paths": [source],
                    "risks": [f"risk-{suffix}"],
                    "sources": [source],
                    "optional_sources": [f"docs/optional-{suffix}.md"],
                }
            )
            self.catalog["profiles"].append(
                {
                    "id": ident,
                    "version": "1.2.0",
                    "description": f"Investigate {ident}",
                    "profile": f"docs/profiles/{ident}.md",
                    "role": "advice",
                    "knowledge_packs": [ident],
                    "questions": [f"Which {ident} invariant needs a check?"],
                }
            )
        self.task: dict[str, Any] = {
            "schema_version": 1,
            "id": "synthetic-context",
            "title": "Inspect aurora / 极光",
            "description": "Preserve invented bilingual source behavior.",
            "paths": ["src/a.py"],
            "risks": [],
            "acceptance": [
                "Reconstruct all invented bytes and preserve source identity."
            ],
            "constraints": ["Disposable synthetic fixtures only."],
        }
        self.task_file = self.records / "task.json"
        self.run_dir = self.records / "run"
        self.allocation_file = self.records / "allocation.json"
        self.persist()

    def write(self, name: str, text: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def persist(self) -> None:
        (self.repo / "docs/catalog.json").write_text(json.dumps(self.catalog))
        self.task_file.write_text(json.dumps(self.task, ensure_ascii=False))

    def cli(self, *args: str | Path, expected: int = 0) -> dict[str, Any]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = factory.main(
                    [
                        "--repo",
                        str(self.repo),
                        "--catalog",
                        "docs/catalog.json",
                        "--records-root",
                        str(self.records),
                        *map(str, args),
                    ]
                )
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 2
        self.assertEqual(code, expected, out.getvalue() + err.getvalue())
        return cast(dict[str, Any], json.loads(out.getvalue() or err.getvalue()))

    def allocate(self, count: int, *, tag: str = "initial") -> dict[str, Any]:
        discovery = self.cli("route", "--task", self.task_file)
        ids = [entry["id"] for entry in discovery["matched"]]
        selected = ids[:count]
        allocation = {
            "schema_version": 1,
            "task_id": self.task["id"],
            "discovery_sha256": discovery["discovery_sha256"],
            "selected": [
                {
                    "id": ident,
                    "question": f"For {self.task['id']}, does {ident} preserve invented aurora bytes under {tag} reconstruction?",
                    "risks": ["risk-" + ident[-1]],
                }
                for ident in selected
            ],
            "omitted": [
                {
                    "id": ident,
                    "reason": f"Coordinator owns the {tag} source reconstruction checks.",
                    "coverage_owner": "implementation",
                }
                for ident in ids
                if ident not in selected
            ],
        }
        self.allocation_file.write_text(json.dumps(allocation))
        return discovery

    def initialize(self, count: int = 0) -> dict[str, Any]:
        self.allocate(count)
        return self.cli(
            "init",
            "--task",
            self.task_file,
            "--allocation",
            self.allocation_file,
            "--run",
            self.run_dir,
        )

    def assess(self) -> None:
        check = self.records / "actual-check.txt"
        oracle = "A🙂中Bé / 虚构极光记录"
        self.assertEqual(oracle.encode().decode(), oracle)
        for suffix in "abcd":
            expected = f"# Invented {suffix}: A🙂中Bé / 虚构极光记录\n".encode()
            self.assertEqual((self.repo / f"src/{suffix}.py").read_bytes(), expected)
        check.write_text(
            "Executed synthetic UTF-8 roundtrip and exact source-byte assertions for src/a.py, src/b.py, src/c.py, src/d.py: passed.\n"
        )
        for suffix in "abcd":
            evidence = self.records / f"risk-{suffix}.json"
            evidence.write_text(
                json.dumps(
                    {
                        "risk": f"risk-{suffix}",
                        "sources": [f"src/{suffix}.py"],
                        "checks": [
                            {
                                "name": "Executed synthetic UTF-8 roundtrip",
                                "outcome": "passed",
                                "evidence": str(check),
                            }
                        ],
                        "conclusion": "Invented source fixture preserves its declared bytes.",
                    }
                )
            )
            self.cli(
                "risk",
                "--run",
                self.run_dir,
                "--risk",
                f"risk-{suffix}",
                "--disposition",
                "coordinator",
                "--reason",
                "Executed source-backed synthetic check",
                "--evidence",
                evidence,
            )

    def checkpoint(
        self,
        candidate: str,
        stage: str,
        *,
        worker: str | None = None,
        outcome: str = "passed",
        expected: int = 0,
        evidence: Path | None = None,
    ) -> dict[str, Any]:
        if evidence is None:
            evidence = self.records / "synthetic-checkpoint.txt"
            evidence.write_text(
                "Synthetic state-machine receipt; no live host claim.\n"
            )
        args = [
            "checkpoint",
            "--run",
            str(self.run_dir),
            "--candidate",
            candidate,
            "--stage",
            stage,
            "--outcome",
            outcome,
            "--evidence",
            str(evidence),
        ]
        if worker:
            args += ["--worker-id", worker]
        return self.cli(*args, expected=expected)

    def test_pure_context_and_same_discovery_for_zero_one_three(self) -> None:
        before = sorted(p.name for p in self.records.iterdir())
        first = self.cli(
            "context", "--task", self.task_file, "--role", "implementation", "--routed"
        )
        self.assertEqual(
            first,
            self.cli(
                "context",
                "--task",
                self.task_file,
                "--role",
                "implementation",
                "--routed",
            ),
        )
        self.assertEqual(before, sorted(p.name for p in self.records.iterdir()))
        self.assertEqual(len(first["packs"]), 4)
        self.assertIsNone(first["optional_sources"]["docs/optional-a.md"])
        discoveries = []
        source_bindings = []
        for count in (0, 1, 3):
            self.run_dir = self.records / f"run-{count}"
            self.allocation_file = self.records / f"allocation-{count}.json"
            discoveries.append(self.allocate(count))
            self.cli(
                "init",
                "--task",
                self.task_file,
                "--allocation",
                self.allocation_file,
                "--run",
                self.run_dir,
            )
            state = json.loads((self.run_dir / "run.json").read_text())
            self.assertEqual(state["schema_version"], 3)
            source_bindings.append(state["epochs"][0]["binding"]["source_sha256"])
            self.assertEqual(len(state["epochs"][0]["workers"]), count)
            self.assertTrue(
                {f"src/{s}.py" for s in "abcd"}
                <= set(state["epochs"][0]["binding"]["source_sha256"])
            )
            self.assertEqual(
                self.cli("status", "--run", self.run_dir)["metrics"][
                    "actual_adviser_starts"
                ],
                0,
            )
        self.assertEqual(discoveries[0], discoveries[1])
        self.assertEqual(discoveries[0], discoveries[2])
        self.assertEqual(source_bindings[0], source_bindings[1])
        self.assertEqual(source_bindings[0], source_bindings[2])

    def test_zero_needs_all_risk_evidence_and_distinct_candidate_review(self) -> None:
        self.initialize()
        self.cli("candidate", "--run", self.run_dir, expected=2)
        evidence = self.records / "reason.txt"
        evidence.write_text("Coordinator says safe, not execution evidence.")
        self.cli(
            "risk",
            "--run",
            self.run_dir,
            "--risk",
            "risk-b",
            "--disposition",
            "coordinator",
            "--reason",
            "Inspected",
            "--evidence",
            evidence,
            expected=2,
        )
        self.assess()
        candidate = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        self.assertFalse(
            self.cli("status", "--run", self.run_dir)["ready_for_delivery"]
        )
        self.checkpoint(candidate, "delivery", expected=2)
        self.checkpoint(candidate, "implementation", worker="synthetic/author")
        self.checkpoint(candidate, "verification")
        self.checkpoint(candidate, "review", worker="synthetic/author", expected=2)
        self.assertFalse(
            self.cli("status", "--run", self.run_dir)["ready_for_delivery"]
        )
        self.checkpoint(candidate, "review", worker="synthetic/distinct-reviewer")
        self.assertTrue(self.cli("status", "--run", self.run_dir)["ready_for_delivery"])
        self.checkpoint(candidate, "delivery")

    def test_normal_init_requires_allocation_and_context_cannot_be_evidence(
        self,
    ) -> None:
        self.cli("init", "--task", self.task_file, "--run", self.run_dir, expected=2)
        self.initialize()
        self.assess()
        candidate = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        context = self.cli(
            "context", "--task", self.task_file, "--role", "implementation", "--routed"
        )
        artifact = self.records / "context.json"
        artifact.write_text(json.dumps(context))
        self.checkpoint(
            candidate,
            "review",
            worker="synthetic/reviewer",
            evidence=artifact,
            expected=2,
        )
        self.checkpoint(
            candidate,
            "review",
            worker="synthetic/reviewer",
            evidence=self.allocation_file,
            expected=2,
        )

    def test_cannot_remove_established_pending_failed_or_unavailable_lane(self) -> None:
        for status in ("pending", "failed", "unavailable"):
            self.run_dir = self.records / f"run-{status}"
            self.initialize(1)
            if status == "unavailable":
                self.cli(
                    "unavailable",
                    "--run",
                    self.run_dir,
                    "--agent",
                    "lane-a",
                    "--reason",
                    "Synthetic unavailable",
                )
            if status == "failed":
                self.cli(
                    "start",
                    "--run",
                    self.run_dir,
                    "--agent",
                    "lane-a",
                    "--worker-id",
                    "synthetic/failed",
                )
                self.cli(
                    "interrupt",
                    "--run",
                    self.run_dir,
                    "--agent",
                    "lane-a",
                    "--worker-id",
                    "synthetic/failed",
                    "--reason",
                    "Synthetic observed interruption",
                )
            self.allocate(0)
            before = (self.run_dir / "run.json").read_bytes()
            self.cli(
                "rebind",
                "--run",
                self.run_dir,
                "--reason",
                "Omit old obligation",
                expected=2,
            )
            self.assertEqual(before, (self.run_dir / "run.json").read_bytes())

    def test_writer_reviewer_share_pack_and_review_snapshot_is_pure(self) -> None:
        self.initialize()
        self.assess()
        candidate = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        diff = self.records / "final.diff"
        diff.write_text("Synthetic declared complete diff; no source mutation.\n")
        writer = self.cli(
            "context", "--task", self.task_file, "--role", "implementation", "--routed"
        )
        before = {
            str(p): p.read_bytes() for p in self.records.rglob("*") if p.is_file()
        }
        review_args = (
            "context",
            "--task",
            self.task_file,
            "--role",
            "independent-review",
            "--routed",
            "--run",
            self.run_dir,
            "--candidate",
            candidate,
            "--diff",
            diff,
        )
        review = self.cli(*review_args)
        self.assertEqual(writer["packs"], review["packs"])
        self.assertNotEqual(writer["role"], review["role"])
        self.assertEqual(review["candidate"]["candidate_id"], candidate)
        self.assertNotIn("Coordinator owns", json.dumps(review))
        self.assertEqual(
            before,
            {str(p): p.read_bytes() for p in self.records.rglob("*") if p.is_file()},
        )
        self.write("src/a.py", "# Genuine changed final synthetic source.\n")
        self.cli(*review_args, expected=2)

    def test_unknown_unsafe_missing_and_unmanifested_context_sources_refuse(
        self,
    ) -> None:
        self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "invented-role",
            "--routed",
            expected=2,
        )
        self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "implementation",
            "--pack",
            "unknown-pack",
            expected=2,
        )
        self.catalog["knowledge_packs"][0]["sources"].append("docs/runtime/secret.md")
        self.write(
            "docs/runtime/secret.md", "Synthetic private sentinel must not be loaded.\n"
        )
        self.persist()
        refused = self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "implementation",
            "--routed",
            expected=2,
        )
        self.assertNotIn("private sentinel", json.dumps(refused))
        self.catalog["knowledge_packs"][0]["sources"].pop()
        self.write("docs/packs/lane-a.md", "Read [not-manifested](../../src/b.py).\n")
        self.persist()
        self.cli("validate", expected=2)
        self.write("docs/packs/lane-a.md", "Synthetic bounded knowledge.\n")
        (self.repo / "src/a.py").unlink()
        self.cli("validate", expected=2)

    def test_allocation_validation_and_stale_question_identity(self) -> None:
        self.allocate(1)
        original = json.loads(self.allocation_file.read_text())
        variants = []
        bad = json.loads(json.dumps(original))
        bad["selected"][0]["id"] = "unknown"
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["omitted"].pop()
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["selected"][0]["question"] = self.catalog["profiles"][0]["questions"][0]
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["selected"][0]["risks"] = ["risk-b"]
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["omitted"][0]["coverage_owner"] = ""
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["discovery_sha256"] = "0" * 64
        variants.append(bad)
        bad = json.loads(json.dumps(original))
        bad["selected"] *= 4
        variants.append(bad)
        for value in variants:
            self.allocation_file.write_text(json.dumps(value))
            self.cli(
                "init",
                "--task",
                self.task_file,
                "--allocation",
                self.allocation_file,
                "--run",
                self.run_dir,
                expected=2,
            )
            self.assertFalse(self.run_dir.exists())
        self.allocation_file.write_text(json.dumps(original))
        self.cli(
            "init",
            "--task",
            self.task_file,
            "--allocation",
            self.allocation_file,
            "--run",
            self.run_dir,
        )
        packet = self.cli("packet", "--run", self.run_dir, "--agent", "lane-a")
        self.assertEqual(
            packet["question"]["questions"], [original["selected"][0]["question"]]
        )
        self.allocate(1, tag="changed")
        self.cli("packet", "--run", self.run_dir, "--agent", "lane-a", expected=2)
        self.cli("candidate", "--run", self.run_dir, expected=2)

    def test_allocation_metadata_cannot_clear_failed_candidate_or_retry_budget(
        self,
    ) -> None:
        self.initialize()
        self.assess()
        first = self.cli("candidate", "--run", self.run_dir)
        self.checkpoint(first["candidate_id"], "verification", outcome="failed")
        self.allocate(0, tag="second")
        self.cli("rebind", "--run", self.run_dir, "--reason", "Explicit changed plan")
        self.assess()
        second = self.cli("candidate", "--run", self.run_dir)
        self.assertEqual(first["content_id"], second["content_id"])
        self.checkpoint(second["candidate_id"], "verification", expected=2)
        self.allocate(0, tag="initial")
        self.cli(
            "rebind", "--run", self.run_dir, "--reason", "Plan roundtrip", expected=2
        )
        self.assertEqual(
            len(json.loads((self.run_dir / "run.json").read_text())["checkpoints"]), 1
        )

    def test_role_pack_instruction_and_unallocated_source_drift_fail_closed(
        self,
    ) -> None:
        for name in (
            "docs/roles/implementation.md",
            "docs/packs/lane-d.md",
            "AGENTS.md",
            "src/d.py",
        ):
            self.run_dir = self.records / ("run-" + name.replace("/", "-"))
            self.initialize(1)
            path = self.repo / name
            before = path.read_text()
            path.write_text(before + "Changed synthetic identity.\n")
            self.cli("packet", "--run", self.run_dir, "--agent", "lane-a", expected=2)
            if name != "src/d.py":
                self.cli("candidate", "--run", self.run_dir, expected=2)
            path.write_text(before)

    def test_historical_status_preserves_original_outcomes_without_old_reads_or_lock(
        self,
    ) -> None:
        for schema in (1, 2):
            self.run_dir = self.records / f"historical-{schema}"
            self.run_dir.mkdir()
            state = {
                "schema_version": schema,
                "repo": str(self.repo),
                "catalog": "docs/catalog.json",
                "task_file": "/absent/old/task.json",
                "task_id": "synthetic-old",
                "created_at": "old",
                "epochs": [
                    {
                        "number": 1,
                        "binding": {
                            "source_sha256": {"/absent/old/source": "original"}
                        },
                        "workers": {
                            "legacy": {
                                "status": "failed",
                                "dispatch": {
                                    "input_sha256": "original-opaque-identity"
                                },
                                "result": {"path": "/absent/old/evidence"},
                            }
                        },
                    }
                ],
                "candidates": [{"candidate_id": "original-opaque-candidate"}],
                "checkpoints": [{"outcome": "failed", "evidence": "/absent/old/check"}],
                "observation_boundary": "Original recorded interpretation",
            }
            if schema == 2:
                state["records_root"] = str(self.records)
            record = self.run_dir / "run.json"
            record.write_text(json.dumps(state))
            before = record.read_bytes()
            observed = self.cli("status", "--run", self.run_dir)
            self.assertEqual(observed["epochs"], state["epochs"])
            self.assertEqual(observed["candidates"], state["candidates"])
            self.assertEqual(observed["checkpoints"], state["checkpoints"])
            self.assertIsNone(observed["current_binding_matches"])
            self.cli(
                "rebind", "--run", self.run_dir, "--reason", "No migration", expected=2
            )
            self.assertFalse((self.run_dir / ".lock").exists())
            self.assertEqual(record.read_bytes(), before)

    def test_observation_two_binds_assignment_without_inventing_starts(self) -> None:
        self.initialize()
        context = self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "implementation",
            "--routed",
            "--allocation",
            self.allocation_file,
        )
        binding = context["binding"]
        observation: dict[str, Any] = {
            "schema_version": 2,
            "stage": "implementation",
            "worker_id": "synthetic/author",
            "candidate_id": None,
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:00:01Z",
            "tool_calls": None,
            "input_tokens": None,
            "output_tokens": None,
            "cost_usd": None,
            "unavailable_reason": "Synthetic test has no host usage",
            "assignment": {
                "role_id": "implementation",
                "role_sha256": binding["role_sha256"]["implementation"],
                "pack_sha256": binding["pack_sha256"],
                "allocation_sha256": binding["allocation_sha256"],
                "context_sha256": context["context_sha256"],
                "context_unavailable_reason": None,
            },
        }
        path = self.records / "observed.json"
        path.write_text(json.dumps(observation))
        self.cli("observe", "--run", self.run_dir, "--observation", path)
        status = self.cli("status", "--run", self.run_dir)
        self.assertEqual(status["metrics"]["actual_adviser_starts"], 0)
        self.assertEqual(len(status["metrics"]["observed_loaded_pack_ids"]), 4)
        self.assertFalse(status["ready_for_delivery"])
        observation["assignment"]["allocation_sha256"] = "0" * 64
        path.write_text(json.dumps(observation))
        self.cli("observe", "--run", self.run_dir, "--observation", path, expected=2)

    def test_pack_symlink_hardlink_and_oversized_document_refuse(self) -> None:
        source = self.repo / "src/d.py"
        original = source.read_bytes()
        external = self.records / "synthetic-sentinel.txt"
        external.write_text("Fictional private sentinel must never be returned.\n")
        source.unlink()
        source.symlink_to(external)
        refused = self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "implementation",
            "--routed",
            expected=2,
        )
        self.assertNotIn("Fictional private", json.dumps(refused))
        source.unlink()
        import os

        os.link(external, source)
        self.cli("validate", expected=2)
        source.unlink()
        source.write_bytes(original)
        self.write("docs/packs/lane-d.md", "X" * (24 * 1024 + 1))
        self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "implementation",
            "--routed",
            expected=2,
        )

    def test_failed_and_stale_noncritical_risk_checks_cannot_clear_coverage(
        self,
    ) -> None:
        self.initialize()
        check = self.records / "risk-check.txt"
        check.write_text("Actual synthetic negative assertion failed.\n")
        evidence = self.records / "risk-b-evidence.json"
        assessment = {
            "risk": "risk-b",
            "sources": ["src/b.py"],
            "checks": [
                {
                    "name": "Synthetic failed check",
                    "outcome": "failed",
                    "evidence": str(check),
                }
            ],
            "conclusion": "Unresolved.",
        }
        evidence.write_text(json.dumps(assessment))
        args = (
            "risk",
            "--run",
            self.run_dir,
            "--risk",
            "risk-b",
            "--disposition",
            "coordinator",
            "--reason",
            "Cannot waive a failed assertion",
            "--evidence",
            evidence,
        )
        self.cli(*args, expected=2)
        self.assess()
        self.write("src/b.py", "# Changed assessed noncritical source\n")
        self.cli("candidate", "--run", self.run_dir, expected=2)

    def test_question_change_cannot_erase_retained_findings(self) -> None:
        self.initialize(1)
        packet = self.cli("packet", "--run", self.run_dir, "--agent", "lane-a")
        self.cli(
            "start",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--worker-id",
            "synthetic/adviser",
        )
        actual_result = {
            "dispatch": packet["dispatch"],
            "status": "completed",
            "summary": "Synthetic retained finding",
            "inspected": ["src/a.py"],
            "findings": [
                {
                    "severity": "medium",
                    "evidence": "src/a.py:1",
                    "recommendation": "Check invented byte completeness",
                }
            ],
            "checks": ["Proposed check; not executed"],
            "open_questions": [],
            "actions_not_performed": ["No real host execution"],
        }
        result_file = self.records / "synthetic-result.json"
        result_file.write_text(json.dumps(actual_result))
        self.cli(
            "result",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--worker-id",
            "synthetic/adviser",
            "--result",
            result_file,
        )
        self.allocate(1, tag="changed-question")
        before = (self.run_dir / "run.json").read_bytes()
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Cannot erase a finding",
            expected=2,
        )
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())

    def test_task_format_and_semantic_roundtrip_cannot_reset_consumed_retry(
        self,
    ) -> None:
        self.initialize(1)
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--reason",
            "Synthetic unavailable first attempt",
        )
        self.task_file.write_text(json.dumps(self.task, indent=4))
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "One explicit retry after task reformat",
        )
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--reason",
            "Synthetic unavailable second attempt",
        )
        self.task["description"] = (
            "A genuinely different invented requirement, same sources and risks."
        )
        self.persist()
        self.allocate(1, tag="different-task")
        self.cli("rebind", "--run", self.run_dir, "--reason", "Semantic task B")
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--reason",
            "Synthetic unavailable B",
        )
        self.task["description"] = "Preserve invented bilingual source behavior."
        self.persist()
        self.allocate(1)
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "A-B-A cannot reset consumed retry",
            expected=2,
        )
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(
            [item["workers"]["lane-a"]["status"] for item in state["epochs"]],
            ["unavailable", "unavailable", "unavailable"],
        )

    def test_review_context_preserves_explicit_deleted_task_source(self) -> None:
        self.write("src/extra.py", "# Invented deletable task-only source.\n")
        self.task["paths"].append("src/extra.py")
        self.persist()
        self.initialize()
        self.assess()
        (self.repo / "src/extra.py").unlink()
        candidate = self.cli(
            "candidate", "--run", self.run_dir, "--delete", "src/extra.py"
        )["candidate_id"]
        diff = self.records / "deleted.diff"
        diff.write_text("Synthetic complete deletion diff for src/extra.py\n")
        context = self.cli(
            "context",
            "--task",
            self.task_file,
            "--role",
            "independent-review",
            "--routed",
            "--run",
            self.run_dir,
            "--candidate",
            candidate,
            "--diff",
            diff,
        )
        self.assertIn("src/extra.py", context["required_sources"])
        self.assertIsNone(context["candidate"]["source_sha256"]["src/extra.py"])
        self.assertIsNone(context["required_sources"]["src/extra.py"])

    def assert_automatic_catalog_upgrade_is_historical(self, origin: int) -> None:
        original = json.loads(json.dumps(self.catalog))
        profile_text = {
            item["profile"]: (self.repo / item["profile"]).read_text()
            for item in original["profiles"]
        }
        legacy = factory.load_catalog(self.repo, "docs/catalog.json")
        legacy["schema_version"] = origin
        del legacy["roles"], legacy["knowledge_packs"]
        for profile in legacy["profiles"]:
            del profile["role"], profile["knowledge_packs"]
            if origin == 1:
                del profile["questions"]
            self.write(profile["profile"], "Synthetic automatic-allocation adviser.\n")
        if origin == 1:
            for name in ("instructions", "risk_aliases", "critical_risks", "couplings"):
                del legacy[name]
        self.catalog = legacy
        self.persist()
        self.cli("init", "--task", self.task_file, "--run", self.run_dir)
        self.cli(
            "start",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--worker-id",
            "synthetic/completed",
        )
        packet = self.cli("packet", "--run", self.run_dir, "--agent", "lane-a")
        result_file = self.records / "automatic-result.json"
        result_file.write_text(
            json.dumps(
                {
                    "dispatch": packet["dispatch"],
                    "status": "completed",
                    "summary": "Synthetic compatibility result",
                    "inspected": ["src/a.py"],
                    "findings": [],
                    "checks": [],
                    "open_questions": [],
                    "actions_not_performed": ["No real host execution"],
                }
            )
        )
        self.cli(
            "result",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--worker-id",
            "synthetic/completed",
            "--result",
            result_file,
        )
        self.cli(
            "start",
            "--run",
            self.run_dir,
            "--agent",
            "lane-b",
            "--worker-id",
            "synthetic/interrupted",
        )
        self.cli(
            "interrupt",
            "--run",
            self.run_dir,
            "--agent",
            "lane-b",
            "--worker-id",
            "synthetic/interrupted",
            "--reason",
            "Synthetic observed interruption",
        )
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-c",
            "--reason",
            "Synthetic unavailable adviser",
        )
        evidence = self.records / "synthetic-negative.txt"
        self.assertIn("虚构极光记录", (self.repo / "src/d.py").read_text())
        evidence.write_text(
            "Synthetic source assertion passed; negative candidate check intentionally retained.\n"
        )
        self.cli(
            "risk",
            "--run",
            self.run_dir,
            "--risk",
            "risk-d",
            "--disposition",
            "coordinator",
            "--reason",
            "Synthetic source assertion",
            "--evidence",
            evidence,
        )
        candidate = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        self.checkpoint(candidate, "verification", outcome="failed", evidence=evidence)
        self.assertTrue(
            self.cli("status", "--run", self.run_dir)["current_binding_matches"]
        )
        record = self.run_dir / "run.json"
        original_bytes = record.read_bytes()
        recorded = json.loads(original_bytes)
        self.assertEqual(recorded["schema_version"], 3)
        self.assertIsNone(recorded["epochs"][0]["allocation_file"])
        self.assertEqual(
            {item["status"] for item in recorded["epochs"][0]["workers"].values()},
            {"completed", "failed", "unavailable"},
        )

        self.catalog = original
        self.persist()
        for name, text in profile_text.items():
            self.write(name, text)
        (self.run_dir / ".lock").unlink()
        observed = self.cli("status", "--run", self.run_dir)
        self.assertTrue(observed["historical_read_only"])

        # Once the same catalog path has composition semantics, the old task,
        # source and receipt paths need not exist to inspect original outcomes.
        self.task_file.unlink()
        (self.repo / "src/a.py").unlink()
        for item in (self.run_dir / "evidence").iterdir():
            item.unlink()
        with (
            patch.object(
                factory, "load_task", side_effect=AssertionError("Obsolete task read")
            ),
            patch.object(
                factory,
                "load_catalog",
                side_effect=AssertionError("Obsolete source manifest read"),
            ),
            patch.object(
                factory,
                "read_state",
                side_effect=AssertionError("Obsolete receipt read"),
            ),
            patch.object(
                factory,
                "locked",
                side_effect=AssertionError("Historical lock creation"),
            ),
            patch.object(factory, "read_bytes", wraps=factory.read_bytes) as reads,
        ):
            observed = self.cli("status", "--run", self.run_dir)
            self.cli(
                "rebind", "--run", self.run_dir, "--reason", "No migration", expected=2
            )
            self.cli("candidate", "--run", self.run_dir, expected=2)
            self.assertTrue(
                all(
                    call.args[0] in {record, self.repo / "docs/catalog.json"}
                    for call in reads.call_args_list
                )
            )
        self.assertIsNone(observed["current_binding_matches"])
        self.assertFalse(observed["ready_for_delivery"])
        for field in ("epochs", "candidates", "checkpoints"):
            self.assertEqual(observed[field], recorded[field])
        self.assertEqual(record.read_bytes(), original_bytes)
        self.assertFalse((self.run_dir / ".lock").exists())

    def test_catalog_one_automatic_run_stays_inspectable_after_composition_upgrade(
        self,
    ) -> None:
        self.assert_automatic_catalog_upgrade_is_historical(1)

    def test_catalog_two_automatic_run_stays_inspectable_after_composition_upgrade(
        self,
    ) -> None:
        self.assert_automatic_catalog_upgrade_is_historical(2)

    def finding_advice(
        self,
        worker: str,
        *,
        finding: bool = True,
        status: str = "completed",
        stale_result: Path | None = None,
        source: str = "src/a.py",
        agent: str = "lane-a",
        line: int = 1,
    ) -> Path:
        packet = self.cli("packet", "--run", self.run_dir, "--agent", agent)
        self.cli(
            "start", "--run", self.run_dir, "--agent", agent, "--worker-id", worker
        )
        if stale_result is not None:
            self.cli(
                "result",
                "--run",
                self.run_dir,
                "--agent",
                agent,
                "--worker-id",
                worker,
                "--result",
                stale_result,
                expected=2,
            )
        result = self.records / (worker.replace("/", "-") + ".json")
        result.write_text(
            json.dumps(
                {
                    "dispatch": packet["dispatch"],
                    "status": status,
                    "summary": "Synthetic finding preservation advice",
                    "inspected": [source],
                    "findings": [
                        {
                            "severity": "high",
                            "evidence": source + ":" + str(line),
                            "recommendation": "Resolve the invented material source defect.",
                        }
                    ]
                    if finding
                    else [],
                    "checks": [],
                    "open_questions": [],
                    "actions_not_performed": ["No real host execution"],
                }
            )
        )
        self.cli(
            "result",
            "--run",
            self.run_dir,
            "--agent",
            agent,
            "--worker-id",
            worker,
            "--result",
            result,
        )
        return result

    def finding_disposition(self, *, decision: str = "modified") -> None:
        source = self.repo / "src/a.py"
        actual = source.read_bytes()
        self.assertIn("虚构", actual.decode())
        self.assertEqual(actual.decode().encode(), actual)
        check = self.records / (
            "finding-" + str(len(list(self.records.glob("finding-*.txt")))) + ".txt"
        )
        check.write_text(
            "Executed exact synthetic UTF-8 source roundtrip assertion: passed.\n"
        )
        self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--finding",
            "0",
            "--decision",
            decision,
            "--reason",
            "Explicit reconsideration of the current invented source",
            "--source",
            "src/a.py",
            "--line",
            "1",
            "--check",
            "Executed synthetic source roundtrip assertion",
            "--evidence",
            check,
        )

    def synthetic_finding_revision(self) -> None:
        environment = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        if not (self.repo / ".git").exists():
            subprocess.run(
                ["git", "init", "-q", str(self.repo)], env=environment, check=True
            )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Synthetic Finding Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "Synthetic metadata-only revision",
            ],
            env=environment,
            check=True,
        )

    def assert_rebind_preserves_unresolved_finding(
        self, drift: str, *, decision: str | None = None, failed: bool = False
    ) -> None:
        if drift == "head":
            self.synthetic_finding_revision()
        self.initialize(1)
        original_result = self.finding_advice(
            "synthetic/original", status="failed" if failed else "completed"
        )
        if decision is not None:
            self.finding_disposition(decision=decision)
        if drift == "allocation-format":
            self.allocation_file.write_text(
                json.dumps(json.loads(self.allocation_file.read_text()), indent=4)
            )
        elif drift == "task-format":
            self.task_file.write_text(json.dumps(self.task, indent=4))
        elif drift == "head":
            self.synthetic_finding_revision()
        before = (self.run_dir / "run.json").read_bytes()
        refusal = self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Metadata cannot clear a material finding",
            expected=2,
        )
        self.assertIn("finding", refusal["error"].lower())
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        # Without a valid new epoch, a replacement empty result cannot start or
        # supersede the retained original result; capture remains unqualified.
        self.cli(
            "start",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--worker-id",
            "synthetic/empty-replacement",
            expected=2,
        )
        self.cli("candidate", "--run", self.run_dir, expected=2)
        observed = self.cli("status", "--run", self.run_dir)
        self.assertFalse(observed["ready_for_delivery"])
        self.assertEqual(
            observed["workers"]["lane-a"]["worker_id"], "synthetic/original"
        )
        self.assertEqual(
            json.loads(original_result.read_text())["findings"][0]["severity"], "high"
        )
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())

    def test_rebind_finding_survives_allocation_format(self) -> None:
        self.assert_rebind_preserves_unresolved_finding("allocation-format")

    def test_rebind_finding_survives_task_format(self) -> None:
        self.assert_rebind_preserves_unresolved_finding("task-format")

    def test_rebind_finding_survives_head_only_change(self) -> None:
        self.assert_rebind_preserves_unresolved_finding("head")

    def test_rebind_finding_survives_deferred_decision_and_format(self) -> None:
        self.assert_rebind_preserves_unresolved_finding(
            "allocation-format", decision="deferred"
        )

    def test_rebind_finding_in_failed_result_blocks_exact_retry(self) -> None:
        self.assert_rebind_preserves_unresolved_finding("none", failed=True)

    def test_rebind_finding_survives_semantic_task_roundtrip(self) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/original")
        original_task = self.task_file.read_bytes()
        original_allocation = self.allocation_file.read_bytes()
        before = (self.run_dir / "run.json").read_bytes()
        self.task["description"] = (
            "A different synthetic requirement still owns the original finding."
        )
        self.persist()
        self.allocate(1, tag="semantic-task-b")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Task B cannot remove original finding",
            expected=2,
        )
        self.task_file.write_bytes(original_task)
        self.allocation_file.write_bytes(original_allocation)
        self.task = json.loads(original_task)
        self.task_file.write_text(json.dumps(self.task, indent=4))
        refusal = self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Task A roundtrip still owns original finding",
            expected=2,
        )
        self.assertIn("finding", refusal["error"].lower())
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())

    def test_rebind_finding_source_reconsideration_requires_current_disposition(
        self,
    ) -> None:
        self.initialize(1)
        original_result = self.finding_advice("synthetic/original")
        self.finding_disposition()
        original_epoch = json.loads((self.run_dir / "run.json").read_text())["epochs"][
            0
        ]
        original_allocation = self.allocation_file.read_bytes()
        self.write("src/a.py", "# Explicitly repaired invented bytes / 虚构修复\n")
        self.allocate(1)
        refusal = self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Old disposition is stale after source correction",
            expected=2,
        )
        self.assertIn("finding", refusal["error"].lower())
        self.allocation_file.write_bytes(original_allocation)
        # Source changes make an earlier decision stale. Reconsider explicitly
        # under the still-bound task/allocation before requesting fresh advice.
        self.assertEqual(
            (self.repo / "src/a.py").read_text(),
            "# Explicitly repaired invented bytes / 虚构修复\n",
        )
        self.finding_disposition()
        prior = json.loads((self.run_dir / "run.json").read_text())["epochs"][0]
        self.assertNotEqual(
            prior["contributions"][0]["source_sha256"],
            prior["contributions"][1]["source_sha256"],
        )
        self.assertEqual(
            prior["contributions"][1]["advice_source_sha256"],
            original_epoch["workers"]["lane-a"]["inspected_sha256"]["src/a.py"],
        )
        self.allocate(1)
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Current-source disposition precedes legitimate new source advice",
        )
        self.finding_advice(
            "synthetic/empty-after-disposition",
            finding=False,
            stale_result=original_result,
        )
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(state["epochs"][0], prior)
        self.assertEqual(state["epochs"][1]["workers"]["lane-a"]["status"], "completed")
        self.assertEqual(len(state["epochs"][0]["contributions"]), 2)
        self.assertNotEqual(
            state["epochs"][0]["workers"]["lane-a"]["dispatch"],
            state["epochs"][1]["workers"]["lane-a"]["dispatch"],
        )
        self.assertFalse(
            self.cli("status", "--run", self.run_dir)["ready_for_delivery"]
        )

    def test_rebind_finding_disposition_preserves_exact_input_reuse_and_retry_limit(
        self,
    ) -> None:
        self.initialize(2)
        self.finding_advice("synthetic/original")
        self.finding_disposition()
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-b",
            "--reason",
            "Synthetic unavailable first attempt",
        )
        prior = json.loads((self.run_dir / "run.json").read_text())["epochs"][0]
        reused = self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "One exact-input availability retry after explicit disposition",
        )
        self.assertEqual(reused["completed_advice_reused"], ["lane-a"])
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(state["epochs"][0], prior)
        self.assertEqual(state["epochs"][1]["contributions"], prior["contributions"])
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-b",
            "--reason",
            "Synthetic unavailable second attempt",
        )
        refusal = self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Disposition does not reset exhausted retry budget",
            expected=2,
        )
        self.assertIn("budget", refusal["error"].lower())

    def cover_omitted_finding_risks(self) -> None:
        observed = self.cli("status", "--run", self.run_dir)
        for risk in observed["risk_dispositions"]:
            source = "src/" + risk[-1] + ".py"
            self.assertEqual(
                (self.repo / source).read_bytes(),
                f"# Invented {risk[-1]}: A🙂中Bé / 虚构极光记录\n".encode(),
            )
            check = self.records / (risk + "-completed.txt")
            check.write_text(
                "Executed independent exact synthetic source-byte assertion: passed.\n"
            )
            assessment = self.records / (risk + "-assessment.json")
            assessment.write_text(
                json.dumps(
                    {
                        "risk": risk,
                        "sources": [source],
                        "checks": [
                            {
                                "name": "Exact current synthetic bytes",
                                "outcome": "passed",
                                "evidence": str(check),
                            }
                        ],
                        "conclusion": "Current invented source bytes checked.",
                    }
                )
            )
            self.cli(
                "risk",
                "--run",
                self.run_dir,
                "--risk",
                risk,
                "--disposition",
                "coordinator",
                "--reason",
                "Executed source assertion",
                "--evidence",
                assessment,
            )

    def test_runwide_finding_remains_active_after_empty_advice_and_later_source_drift(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/original-finding")
        self.finding_disposition()
        self.allocation_file.write_text(
            json.dumps(json.loads(self.allocation_file.read_text()), indent=4)
        )
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Equivalent allocation formatting",
        )
        self.finding_advice("synthetic/empty-next-epoch", finding=False)
        self.cover_omitted_finding_risks()
        self.write(
            "src/a.py",
            "# Drift after valid reconsideration and empty advice / 虚构漂移\n",
        )
        self.cli("candidate", "--run", self.run_dir, expected=2)
        self.assertFalse(
            self.cli("status", "--run", self.run_dir)["ready_for_delivery"]
        )

    def reconsideration_evidence(
        self, source: str, agent: str = "lane-a", ordinal: int = 0, origin: int = 0
    ) -> tuple[Path, str]:
        state = json.loads((self.run_dir / "run.json").read_text())
        worker = state["epochs"][origin]["workers"][agent]
        finding_id = factory.digest(
            factory.encoded(
                {
                    "agent_id": agent,
                    "worker_id": worker["worker_id"],
                    "result_sha256": worker["result"]["sha256"],
                    "finding": ordinal,
                }
            )
        )
        _, _, actual = factory.current(self.repo, state, missing_sources=True)
        source_path = self.repo / source
        current_bytes = source_path.read_bytes() if source_path.exists() else None
        if current_bytes is not None:
            self.assertEqual(current_bytes.decode().encode(), current_bytes)
        else:
            self.assertFalse(source_path.exists())
        sources = {
            source: factory.digest(current_bytes) if current_bytes is not None else None
        }
        check = self.records / (
            "executed-current-" + source.replace("/", "-") + ".json"
        )
        check.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "finding-check",
                    "finding_id": finding_id,
                    "current_binding_sha256": factory.digest(factory.encoded(actual)),
                    "source_sha256": sources,
                    "name": "Current corrected source assertion",
                    "outcome": "passed",
                    "command": ["unittest", self.id()],
                    "output": "Executed current synthetic UTF-8 roundtrip or declared deletion assertion: passed.",
                }
            )
        )
        envelope = self.records / ("reconsider-" + finding_id + ".json")
        envelope.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "finding-reconsideration",
                    "finding_id": finding_id,
                    "current_binding_sha256": factory.digest(factory.encoded(actual)),
                    "source_sha256": sources,
                    "checks": [
                        {
                            "name": "Current corrected source assertion",
                            "outcome": "passed",
                            "evidence": str(check),
                        }
                    ],
                }
            )
        )
        return envelope, finding_id

    def test_runwide_finding_can_be_dispositioned_for_corrected_static_role(
        self,
    ) -> None:
        self.initialize(1)
        source = "docs/roles/implementation.md"
        old_result = self.finding_advice("synthetic/contract-adviser", source=source)
        self.write(
            source,
            (self.repo / source).read_text()
            + "Required bilingual responsibility / 虚构职责.\n",
        )
        self.assertIn("虚构职责", (self.repo / source).read_text())
        self.allocate(1)
        envelope, _ = self.reconsideration_evidence(source)
        self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--agent",
            "lane-a",
            "--finding",
            "0",
            "--decision",
            "modified",
            "--reason",
            "Executed check of corrected responsibility",
            "--source",
            source,
            "--line",
            "1",
            "--check",
            "Current corrected source assertion",
            "--evidence",
            envelope,
        )
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Fresh dispatch for corrected role after explicit current-source disposition",
        )
        self.finding_advice(
            "synthetic/fresh-contract-advice", finding=False, stale_result=old_result
        )

    def reconsider(
        self,
        source: str = "src/a.py",
        *,
        origin: int = 0,
        agent: str = "lane-a",
        decision: str = "modified",
        line: int = 1,
        evidence: Path | None = None,
        expected: int = 0,
    ) -> dict[str, Any]:
        prepared, identity = self.reconsideration_evidence(
            source, agent=agent, origin=origin
        )
        return self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--finding-id",
            identity,
            "--decision",
            decision,
            "--reason",
            "Executed explicit synthetic current-input assessment",
            "--source",
            source,
            "--line",
            str(line),
            "--check",
            "Current corrected source assertion",
            "--evidence",
            evidence or prepared,
            expected=expected,
        )

    def obligations(self) -> list[dict[str, Any]]:
        return cast(
            list[dict[str, Any]],
            self.cli("status", "--run", self.run_dir)["finding_obligations"],
        )

    def test_runwide_repeated_empty_results_preserve_original_identity_and_source_dependency(
        self,
    ) -> None:
        self.initialize(1)
        original = self.finding_advice("synthetic/original-repeated")
        self.finding_disposition()
        identity = self.obligations()[0]["finding_id"]
        for index in range(2):
            if index:
                self.write("src/a.py", "# Explicit second corrected input / 虚构修复\n")
                self.allocate(1)
                self.reconsider()
            self.allocation_file.write_text(
                json.dumps(
                    json.loads(self.allocation_file.read_text()), indent=index + 3
                )
            )
            self.cli(
                "rebind", "--run", self.run_dir, "--reason", "Equivalent formatting"
            )
            self.finding_advice(
                "synthetic/empty-" + str(index), finding=False, stale_result=original
            )
        self.assertEqual(len(self.obligations()), 1)
        self.assertEqual(self.obligations()[0]["finding_id"], identity)
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.write("src/a.py", "# Later source drift / 虚构漂移\n")
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Cannot drop old source",
            expected=2,
        )
        self.reconsider()
        self.assertEqual(self.obligations()[0]["status"], "resolved")

    def test_runwide_distinct_result_origins_with_same_agent_ordinal_and_text_do_not_merge(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/first-origin")
        self.finding_disposition()
        first = self.obligations()[0]["finding_id"]
        self.allocation_file.write_text(
            json.dumps(json.loads(self.allocation_file.read_text()), indent=4)
        )
        self.cli("rebind", "--run", self.run_dir, "--reason", "Fresh second result")
        self.finding_advice("synthetic/second-origin")
        origins = self.obligations()
        self.assertEqual([item["finding"] for item in origins], [0, 0])
        self.assertNotEqual(first, origins[1]["finding_id"])
        self.assertEqual(
            [item["status"] for item in origins], ["resolved", "unresolved"]
        )
        self.reconsider(origin=0)
        self.assertEqual(
            [item["status"] for item in self.obligations()], ["resolved", "unresolved"]
        )
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Other ordinal remains",
            expected=2,
        )
        self.reconsider(origin=1)
        self.assertEqual(
            [item["status"] for item in self.obligations()], ["resolved", "resolved"]
        )

    def test_runwide_multiple_workers_and_failed_result_each_keep_obligations(
        self,
    ) -> None:
        self.initialize(2)
        self.finding_advice("synthetic/completed-origin")
        self.finding_advice("synthetic/failed-origin", agent="lane-b", status="failed")
        self.finding_disposition()
        self.assertEqual(
            [item["status"] for item in self.obligations()], ["resolved", "unresolved"]
        )
        self.reconsider(agent="lane-b", decision="deferred")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Deferred failed-result finding",
            expected=2,
        )
        self.reconsider(agent="lane-b")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "One conservative actual failed worker retry",
        )
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(state["epochs"][0]["workers"]["lane-b"]["status"], "failed")
        self.assertEqual(
            state["epochs"][1]["workers"]["lane-a"]["worker_id"],
            "synthetic/completed-origin",
        )
        self.finding_advice(
            "synthetic/failed-retry", agent="lane-b", finding=False, status="failed"
        )
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Retry remains exhausted",
            expected=2,
        )
        self.assertEqual(len(self.obligations()), 2)

    def test_runwide_latest_append_wins_across_source_A_B_A_and_later_deferred(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/source-roundtrip")
        original = (self.repo / "src/a.py").read_bytes()
        self.reconsider()
        self.write("src/a.py", "# Corrected B / 虚构乙\n")
        self.reconsider()
        (self.repo / "src/a.py").write_bytes(original)
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.reconsider()
        with patch.object(factory, "now", return_value="2026-10-22T00:00:00+00:00"):
            self.reconsider(decision="deferred")
            self.reconsider(decision="deferred")
        state = json.loads((self.run_dir / "run.json").read_text())
        events = state["epochs"][0]["contributions"]
        self.assertNotEqual(events[-2]["disposition_id"], events[-1]["disposition_id"])
        self.assertEqual(len(factory.contribution_events(state)), 5)
        self.assertEqual(self.obligations()[0]["status"], "deferred")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "No older passing fallback",
            expected=2,
        )

    def test_runwide_current_context_reconsideration_supports_task_A_B_A_and_format_head(
        self,
    ) -> None:
        self.synthetic_finding_revision()
        self.initialize(1)
        original = self.finding_advice("synthetic/task-A")
        self.reconsider()
        task_a = self.task_file.read_bytes()
        self.task["description"] = "Different synthetic B obligations / 虚构乙."
        self.persist()
        self.allocate(1, tag="task-b")
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.reconsider()
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Current explicit task B assessment",
        )
        self.finding_advice("synthetic/task-B", finding=False, stale_result=original)
        self.task = json.loads(task_a)
        self.persist()
        self.allocate(1)
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "No resurrected A assessment",
            expected=2,
        )
        self.reconsider()
        self.task_file.write_text(json.dumps(self.task, indent=4))
        self.synthetic_finding_revision()
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Task A explicit assessment plus metadata drift",
        )
        self.finding_advice(
            "synthetic/task-A-fresh", finding=False, stale_result=original
        )

    def test_runwide_reconsideration_keeps_advice_line_after_move_or_declared_deletion(
        self,
    ) -> None:
        source = "src/extra.py"
        self.write(source, "# First invented line\n# Original cited line / 虚构原行\n")
        self.task["paths"].append(source)
        self.persist()
        self.initialize(1)
        self.finding_advice("synthetic/line-origin", source=source, line=2)
        self.cover_omitted_finding_risks()
        self.write(source, "# Corrected one-line source / 虚构修复\n")
        self.reconsider(source, line=2)
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        (self.repo / source).unlink()
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.reconsider(source, line=2)
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.cli("candidate", "--run", self.run_dir, expected=2)
        self.cli("candidate", "--run", self.run_dir, "--delete", source)

    def test_runwide_corrected_static_inputs_allow_current_check_then_fresh_dispatch(
        self,
    ) -> None:
        categories = [
            "docs/packs/lane-a.md",
            "docs/profiles/lane-a.md",
            "AGENTS.md",
            "tools/procedure.md",
            "docs/catalog.json",
            "factory",
        ]
        for source in categories:
            with self.subTest(source=source):
                if source != categories[0]:
                    self.setUp()
                self.initialize(1)
                advice_source = source if source != "factory" else "src/a.py"
                old = self.finding_advice(
                    "synthetic/static-original", source=advice_source
                )
                real_read = factory.read_bytes

                def corrected_read(
                    path: Path,
                    limit: int = factory.LIMIT,
                    reader: Callable[[Path, int], bytes] = real_read,
                ) -> bytes:
                    data = reader(path, limit)
                    return (
                        data + b"# synthetic factory correction\n"
                        if path == Path(factory.__file__).resolve()
                        else data
                    )

                with (
                    patch.object(factory, "read_bytes", side_effect=corrected_read)
                    if source == "factory"
                    else contextlib.nullcontext()
                ):
                    if source == "docs/catalog.json":
                        self.catalog["profiles"][0]["description"] += " corrected"
                        self.persist()
                    elif source != "factory":
                        self.write(
                            source,
                            (self.repo / source).read_text()
                            + "Current correction / 虚构修复.\n",
                        )
                    self.allocate(1)
                    self.cli(
                        "rebind",
                        "--run",
                        self.run_dir,
                        "--reason",
                        "Needs current assessment",
                        expected=2,
                    )
                    self.reconsider(advice_source)
                    self.cli(
                        "rebind",
                        "--run",
                        self.run_dir,
                        "--reason",
                        "Corrected inputs with explicit current check",
                    )
                    self.finding_advice(
                        "synthetic/static-fresh", finding=False, stale_result=old
                    )
                    self.assertEqual(self.obligations()[0]["status"], "resolved")

    def test_runwide_stale_failed_unbound_or_changed_check_cannot_append_disposition(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/check-origin")
        envelope, identity = self.reconsideration_evidence("src/a.py")
        original_envelope = envelope.read_bytes()
        payload = json.loads(original_envelope)
        check = Path(payload["checks"][0]["evidence"])
        original_check = check.read_bytes()
        before = (self.run_dir / "run.json").read_bytes()
        for mutation in (
            "failed",
            "old-binding",
            "context",
            "plain-old-log",
            "unknown-origin",
            "empty-command",
        ):
            with self.subTest(mutation=mutation):
                envelope.write_bytes(original_envelope)
                check.write_bytes(original_check)
                data = json.loads(original_check)
                if mutation == "failed":
                    data["outcome"] = "failed"
                elif mutation == "old-binding":
                    data["current_binding_sha256"] = "0" * 64
                elif mutation == "context":
                    data = {"kind": "task-context", "schema_version": 1}
                elif mutation == "unknown-origin":
                    data["finding_id"] = "f" * 64
                elif mutation == "empty-command":
                    data["command"] = []
                if mutation == "plain-old-log":
                    check.write_text("An old passed log without correction binding.\n")
                else:
                    check.write_text(json.dumps(data))
                self.cli(
                    "contribution",
                    "--run",
                    self.run_dir,
                    "--finding-id",
                    identity,
                    "--decision",
                    "modified",
                    "--reason",
                    "Invalid executed evidence",
                    "--source",
                    "src/a.py",
                    "--line",
                    "1",
                    "--check",
                    "Current corrected source assertion",
                    "--evidence",
                    envelope,
                    expected=2,
                )
                self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        check.write_bytes(original_check)
        envelope.write_bytes(original_envelope)
        self.write("src/a.py", "# Actual later drift / 虚构漂移\n")
        self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--finding-id",
            identity,
            "--decision",
            "modified",
            "--reason",
            "Stale prepared envelope",
            "--source",
            "src/a.py",
            "--line",
            "1",
            "--check",
            "Current corrected source assertion",
            "--evidence",
            envelope,
            expected=2,
        )
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        self.reconsider()
        state = json.loads((self.run_dir / "run.json").read_text())
        retained = state["epochs"][0]["contributions"][-1]["checks"][0]["receipt"]
        (self.run_dir / retained["path"]).write_text("Changed retained check.\n")
        self.cli("status", "--run", self.run_dir, expected=2)

    def test_runwide_legacy_disposition_keeps_original_semantics_without_migration(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/legacy-event")
        self.finding_disposition()
        state = json.loads((self.run_dir / "run.json").read_text())
        event = state["epochs"][0]["contributions"][0]
        for name in (
            "schema_version",
            "assessment",
            "append_index",
            "disposition_id",
            "finding_id",
            "origin_epoch",
            "assessment_static",
            "assessed_source_sha256",
            "current_binding_sha256",
            "checks",
        ):
            del event[name]
        (self.run_dir / "run.json").write_text(json.dumps(state))
        original = (self.run_dir / "run.json").read_bytes()
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.assertEqual(original, (self.run_dir / "run.json").read_bytes())
        self.write("AGENTS.md", "Corrected static instructions / 虚构修复.\n")
        self.assertEqual(self.obligations()[0]["status"], "stale")
        self.reconsider()
        self.assertEqual(
            json.loads((self.run_dir / "run.json").read_text())["epochs"][0][
                "contributions"
            ][0],
            event,
        )

    def test_runwide_carried_prefix_aliases_only_original_append_and_later_decision_wins(
        self,
    ) -> None:
        self.initialize(2)
        self.finding_advice("synthetic/carried-origin")
        self.reconsider()
        self.cli(
            "unavailable",
            "--run",
            self.run_dir,
            "--agent",
            "lane-b",
            "--reason",
            "Synthetic slot unavailable",
        )
        self.cli("rebind", "--run", self.run_dir, "--reason", "Exact carried prefix")
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(len(factory.contribution_events(state)), 1)
        self.assertEqual(len(self.obligations()), 1)
        self.reconsider(decision="deferred")
        state = json.loads((self.run_dir / "run.json").read_text())
        self.assertEqual(len(factory.contribution_events(state)), 2)
        self.assertEqual(self.obligations()[0]["status"], "deferred")
        self.assertEqual(
            state["epochs"][0]["contributions"][0],
            state["epochs"][1]["contributions"][0],
        )
        state["epochs"][1]["contributions"][0]["reason"] = "Changed copied prefix"
        (self.run_dir / "run.json").write_text(json.dumps(state))
        self.cli("status", "--run", self.run_dir, expected=2)

    def test_runwide_prepared_assessment_static_drift_unknown_origin_and_tampered_result_refuse(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/safe-origin")
        envelope, identity = self.reconsideration_evidence("src/a.py")
        before = (self.run_dir / "run.json").read_bytes()
        args: list[str | Path] = [
            "contribution",
            "--run",
            self.run_dir,
            "--finding-id",
            identity,
            "--decision",
            "modified",
            "--reason",
            "Prepared assessment",
            "--source",
            "src/a.py",
            "--line",
            "1",
            "--check",
            "Current corrected source assertion",
            "--evidence",
            envelope,
        ]
        self.write("docs/roles/coordination.md", "Changed after check / 虚构漂移\n")
        self.cli(*args, expected=2)
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        self.reconsider()
        state = json.loads((self.run_dir / "run.json").read_text())
        receipt = state["epochs"][0]["workers"]["lane-a"]["result"]
        (self.run_dir / receipt["path"]).write_text("Changed original advice result\n")
        self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--finding-id",
            "f" * 64,
            "--decision",
            "modified",
            "--reason",
            "Unknown identity",
            "--source",
            "src/a.py",
            "--line",
            "1",
            "--check",
            "No execution",
            "--evidence",
            envelope,
            expected=2,
        )
        self.cli("status", "--run", self.run_dir, expected=2)

    def test_runwide_reconsideration_refuses_unbound_paths_or_required_source_loss(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/admission-origin")
        envelope, identity = self.reconsideration_evidence("src/a.py")
        original = envelope.read_bytes()
        before = (self.run_dir / "run.json").read_bytes()
        for source in ("../outside.py", "src/unbound.py"):
            data = json.loads(original)
            data["source_sha256"][source] = None
            envelope.write_text(json.dumps(data))
            self.cli(
                "contribution",
                "--run",
                self.run_dir,
                "--finding-id",
                identity,
                "--decision",
                "modified",
                "--reason",
                "Unsafe or unbound assessment",
                "--source",
                "src/a.py",
                "--line",
                "1",
                "--check",
                "Current corrected source assertion",
                "--evidence",
                envelope,
                expected=2,
            )
            self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        envelope.write_bytes(original)
        (self.repo / "src/a.py").unlink()
        self.cli(
            "contribution",
            "--run",
            self.run_dir,
            "--finding-id",
            identity,
            "--decision",
            "modified",
            "--reason",
            "Required pack source missing",
            "--source",
            "src/a.py",
            "--line",
            "1",
            "--check",
            "Current corrected source assertion",
            "--evidence",
            envelope,
            expected=2,
        )
        self.assertEqual(before, (self.run_dir / "run.json").read_bytes())

    def test_runwide_check_exact_context_expires_after_task_allocation_or_HEAD_edit(
        self,
    ) -> None:
        self.synthetic_finding_revision()
        self.initialize(1)
        self.finding_advice("synthetic/exact-check-origin")
        for change in ("task-format", "allocation-format", "head"):
            with self.subTest(change=change):
                envelope, identity = self.reconsideration_evidence("src/a.py")
                before = (self.run_dir / "run.json").read_bytes()
                if change == "task-format":
                    self.task_file.write_text(json.dumps(self.task, indent=4))
                elif change == "allocation-format":
                    self.allocation_file.write_text(
                        json.dumps(
                            json.loads(self.allocation_file.read_text()), indent=4
                        )
                    )
                else:
                    self.synthetic_finding_revision()
                self.cli(
                    "contribution",
                    "--run",
                    self.run_dir,
                    "--finding-id",
                    identity,
                    "--decision",
                    "modified",
                    "--reason",
                    "Old check context must refuse",
                    "--source",
                    "src/a.py",
                    "--line",
                    "1",
                    "--check",
                    "Current corrected source assertion",
                    "--evidence",
                    envelope,
                    expected=2,
                )
                self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
                self.reconsider()
                self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Only current context disposition permits fresh dispatch",
        )

    def test_runwide_lost_or_conflicting_finding_metadata_is_not_an_empty_result(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/immutable-finding-origin")
        original = (self.run_dir / "run.json").read_bytes()
        for locations in ({}, {"0": [{"source": "src/a.py", "line": 999}]}):
            with self.subTest(locations=locations):
                state = json.loads(original)
                state["epochs"][0]["workers"]["lane-a"]["finding_locations"] = locations
                (self.run_dir / "run.json").write_text(json.dumps(state))
                self.cli("status", "--run", self.run_dir, expected=2)
                self.cli(
                    "rebind",
                    "--run",
                    self.run_dir,
                    "--reason",
                    "Cannot erase original finding",
                    expected=2,
                )
        (self.run_dir / "run.json").write_bytes(original)
        self.assertEqual(self.obligations()[0]["status"], "unresolved")

    def test_assessment_metadata_cannot_relabel_untouched_old_check_after_instruction_drift(
        self,
    ) -> None:
        self.initialize(1)
        original_result = self.finding_advice("synthetic/coherence-original")
        self.reconsider()
        self.cover_omitted_finding_risks()
        candidate = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        self.checkpoint(
            candidate, "implementation", worker="synthetic/coherence-writer"
        )
        self.checkpoint(candidate, "verification")
        self.checkpoint(candidate, "review", worker="synthetic/coherence-reviewer")
        self.assertTrue(self.cli("status", "--run", self.run_dir)["ready_for_delivery"])
        self.write(
            "AGENTS.md", "Corrected required synthetic instructions / 虚构新约束.\n"
        )
        self.allocate(1)
        self.assertEqual(self.obligations()[0]["status"], "stale")
        original_state = (self.run_dir / "run.json").read_bytes()
        sealed = {
            path: path.read_bytes() for path in (self.run_dir / "evidence").iterdir()
        }
        state = json.loads(original_state)
        _, _, actual = factory.current(self.repo, state, missing_sources=True)
        event = state["epochs"][0]["contributions"][0]
        original_event = json.loads(json.dumps(event))
        event["assessment_static"] = factory.assessment_static(actual)
        self.assertEqual(
            {key: value for key, value in event.items() if key != "assessment_static"},
            {
                key: value
                for key, value in original_event.items()
                if key != "assessment_static"
            },
        )
        (self.run_dir / "run.json").write_text(json.dumps(state))
        altered_state = (self.run_dir / "run.json").read_bytes()
        self.cli("status", "--run", self.run_dir, expected=2)
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Cannot relabel an old check context",
            expected=2,
        )
        self.cli("candidate", "--run", self.run_dir, expected=2)
        self.checkpoint(candidate, "delivery", expected=2)
        self.assertEqual(altered_state, (self.run_dir / "run.json").read_bytes())
        self.assertEqual(
            sealed,
            {path: path.read_bytes() for path in (self.run_dir / "evidence").iterdir()},
        )
        (self.run_dir / "run.json").write_bytes(original_state)
        self.reconsider()
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "New actual current-input check and disposition",
        )
        self.finding_advice(
            "synthetic/coherence-fresh", finding=False, stale_result=original_result
        )
        self.cover_omitted_finding_risks()
        current = self.cli("candidate", "--run", self.run_dir)["candidate_id"]
        self.checkpoint(
            current, "implementation", worker="synthetic/coherence-current-writer"
        )
        self.checkpoint(current, "verification")
        self.checkpoint(
            current, "review", worker="synthetic/coherence-current-reviewer"
        )
        self.assertTrue(self.cli("status", "--run", self.run_dir)["ready_for_delivery"])

    def test_assessment_metadata_legacy_form_new_contribution_also_seals_complete_context(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/plain-log-assessment")
        self.finding_disposition()
        state = json.loads((self.run_dir / "run.json").read_text())
        event = state["epochs"][0]["contributions"][0]
        self.assertEqual(event["checks"], [])
        recorded = factory.read_json(self.run_dir / event["assessment"]["path"])
        self.assertEqual(
            factory.digest(factory.encoded(recorded["binding"])),
            event["current_binding_sha256"],
        )
        self.assertEqual(
            recorded["contribution"],
            {key: value for key, value in event.items() if key != "assessment"},
        )
        original_state = (self.run_dir / "run.json").read_bytes()
        self.write(
            "AGENTS.md",
            "Different required plain-form assessment context / 虚构新约束.\n",
        )
        self.allocate(1)
        self.assertEqual(self.obligations()[0]["status"], "stale")
        _, _, actual = factory.current(self.repo, state, missing_sources=True)
        event["assessment_static"] = factory.assessment_static(actual)
        (self.run_dir / "run.json").write_text(json.dumps(state))
        self.cli("status", "--run", self.run_dir, expected=2)
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "Plain log cannot refresh its context",
            expected=2,
        )
        (self.run_dir / "run.json").write_bytes(original_state)
        self.reconsider()
        self.assertEqual(self.obligations()[0]["status"], "resolved")
        self.cli(
            "rebind",
            "--run",
            self.run_dir,
            "--reason",
            "New structured current-context assessment",
        )

    def test_assessment_metadata_source_and_complete_binding_projections_must_match_sealed_checks(
        self,
    ) -> None:
        self.initialize(1)
        self.finding_advice("synthetic/projection-origin")
        self.reconsider()
        original = (self.run_dir / "run.json").read_bytes()
        original_event = json.loads(original)["epochs"][0]["contributions"][0]
        original_record = factory.read_json(
            self.run_dir / original_event["assessment"]["path"]
        )
        self.write("AGENTS.md", "Changed assessment instructions / 虚构新约束.\n")
        self.write("src/a.py", "# Changed assessed source / 虚构新字节\n")
        self.allocate(1)
        _, _, actual = factory.current(
            self.repo, json.loads(original), missing_sources=True
        )
        external = self.records / "synthetic-resealed-assessment.json"
        for mutation in (
            "source-only",
            "context-digest-only",
            "receipt-only",
            "resealed-static",
            "resealed-binding",
            "resealed-current-with-old-check",
        ):
            with self.subTest(mutation=mutation):
                state = json.loads(original)
                event = state["epochs"][0]["contributions"][0]
                recorded = json.loads(json.dumps(original_record))
                if mutation == "source-only":
                    event["assessed_source_sha256"]["src/a.py"] = actual[
                        "source_sha256"
                    ]["src/a.py"]
                elif mutation == "context-digest-only":
                    event["current_binding_sha256"] = factory.digest(
                        factory.encoded(actual)
                    )
                elif mutation == "receipt-only":
                    event["assessment"] = event["evidence"]
                else:
                    event["assessment_static"] = factory.assessment_static(actual)
                    if mutation in {
                        "resealed-binding",
                        "resealed-current-with-old-check",
                    }:
                        recorded["binding"] = actual
                    if mutation == "resealed-current-with-old-check":
                        event["current_binding_sha256"] = factory.digest(
                            factory.encoded(actual)
                        )
                        event["source_sha256"] = actual["source_sha256"]["src/a.py"]
                        event["assessed_source_sha256"] = {
                            "src/a.py": actual["source_sha256"]["src/a.py"]
                        }
                    recorded["contribution"] = {
                        key: value
                        for key, value in event.items()
                        if key != "assessment"
                    }
                    external.write_bytes(factory.encoded(recorded))
                    event["assessment"] = factory.keep_evidence(self.run_dir, external)
                (self.run_dir / "run.json").write_text(json.dumps(state))
                before = (self.run_dir / "run.json").read_bytes()
                self.cli("status", "--run", self.run_dir, expected=2)
                self.cli(
                    "rebind",
                    "--run",
                    self.run_dir,
                    "--reason",
                    "Inconsistent retained context",
                    expected=2,
                )
                self.assertEqual(before, (self.run_dir / "run.json").read_bytes())
        (self.run_dir / "run.json").write_bytes(original)
        self.reconsider()
        self.assertEqual(self.obligations()[0]["status"], "resolved")

    def test_assessment_metadata_intermediate_versions_block_without_migration_or_reconsideration_deadlock(
        self,
    ) -> None:
        for form in ("structured", "plain"):
            with self.subTest(form=form):
                if form == "plain":
                    self.setUp()
                self.initialize(1)
                self.finding_advice("synthetic/intermediate-" + form)
                self.reconsider() if form == "structured" else self.finding_disposition()
                state = json.loads((self.run_dir / "run.json").read_text())
                event = state["epochs"][0]["contributions"][0]
                del event["assessment"]
                event["schema_version"] = 2
                (self.run_dir / "run.json").write_text(json.dumps(state))
                old = (self.run_dir / "run.json").read_bytes()
                self.assertEqual(self.obligations()[0]["status"], "unverified")
                self.assertEqual(old, (self.run_dir / "run.json").read_bytes())
                self.cli(
                    "rebind",
                    "--run",
                    self.run_dir,
                    "--reason",
                    "No invented historical context",
                    expected=2,
                )
                self.assertEqual(old, (self.run_dir / "run.json").read_bytes())
                self.write(
                    "docs/roles/implementation.md",
                    "Corrected responsibility / 虚构新职责.\n",
                )
                self.allocate(1)
                self.reconsider()
                after = json.loads((self.run_dir / "run.json").read_text())
                self.assertEqual(after["epochs"][0]["contributions"][0], event)
                self.assertEqual(
                    after["epochs"][0]["contributions"][1]["schema_version"], 3
                )
                self.assertEqual(self.obligations()[0]["status"], "resolved")
                self.cli(
                    "rebind",
                    "--run",
                    self.run_dir,
                    "--reason",
                    "Explicit newly verified context supersedes old unverified event",
                )


if __name__ == "__main__":
    unittest.main()
