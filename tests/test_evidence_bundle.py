from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from devops_stack_composer.evidence_bundle import (
    AUTHENTICITY_STATUS,
    BUNDLE_SCHEMA_VERSION,
    EvidenceBundleError,
    REQUIRED_BUNDLE_FILES,
    assemble_evidence_bundle,
    update_sealed_resource_record,
    verify_evidence_bundle,
)
from devops_stack_composer.evidence_store import EvidenceStore, EvidenceStoreError
from devops_stack_composer.execution_models import (
    ArtifactIntent,
    ExecutionRun,
    StageResult,
    StageStatus,
)
from devops_stack_composer.execution_plan import ExecutionPlan
from devops_stack_composer.execution_state import (
    ExecutionErrorCategory,
    ExecutionState,
    ExecutionStateMachine,
    StateTransition,
)
from devops_stack_composer.filesystem import sha256_file
from devops_stack_composer.policies import profile_policy
from devops_stack_composer.registry import (
    CONTAINER_NAME_LABEL,
    MANAGED_BY_LABEL,
    REGISTRY_IMAGE,
    RESOURCE_LABEL,
    RUN_ID_LABEL,
)


RUN_ID = "20260830T120000Z-abcdef123456"
OTHER_RUN_ID = "20260830T120001Z-123456abcdef"
TIMESTAMP = "2026-08-30T12:00:00Z"
SOURCE_REVISION = "a" * 40


def execution_plan(*, run_id: str = RUN_ID) -> ExecutionPlan:
    intent = ArtifactIntent(
        application_name="sample-app",
        registry="localhost:5000",
        repository="team/sample-app",
        requested_tag="run-1",
        platforms=("linux/amd64",),
        source_revision=SOURCE_REVISION,
        build_context=".",
        dockerfile="generated/docker/Dockerfile",
        template_revision="b" * 40,
        normalized_model_hash="c" * 64,
    )
    return ExecutionPlan.create(
        run_id=run_id,
        profile="static",
        environment="staging",
        artifact_intent=intent,
    )


def execution_run(
    plan: ExecutionPlan,
    *,
    failed_stage: str | None = None,
    stage_evidence: dict[str, tuple[str, ...]] | None = None,
) -> ExecutionRun:
    stage_evidence = stage_evidence or {}
    stages: list[StageResult] = []
    for planned in plan.stages:
        failed = planned.stage_id == failed_stage
        stages.append(
            StageResult(
                stage_id=planned.stage_id,
                description=planned.description,
                status=StageStatus.FAILED if failed else StageStatus.PASSED,
                start_time=TIMESTAMP,
                end_time=TIMESTAMP,
                command=("devops-stack", planned.stage_id),
                tool="devops-stack",
                sanitized_output="sanitized output",
                evidence_paths=stage_evidence.get(planned.stage_id, ()),
                failure_reason="injected failure" if failed else None,
                remediation="inspect the evidence" if failed else None,
            )
        )
        if failed:
            break
    final_status = StageStatus.FAILED if failed_stage else StageStatus.PASSED
    return ExecutionRun(
        run_id=plan.run_id,
        project_path=".",
        config_hash="d" * 64,
        template_lock_hash="e" * 64,
        source_revision=SOURCE_REVISION,
        start_time=TIMESTAMP,
        end_time=TIMESTAMP,
        execution_profile=plan.profile.value,
        stage_results=tuple(stages),
        final_status=final_status,
        failure_reason="injected failure" if failed_stage else None,
        tool_versions={"devops-stack": "0.2.0"},
    )


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_terminal_state(
    store: EvidenceStore, plan: ExecutionPlan, run: ExecutionRun
) -> None:
    machine = ExecutionStateMachine()
    if run.final_status == StageStatus.PASSED:
        states = (
            ExecutionState.PLANNED,
            ExecutionState.VALIDATED,
            ExecutionState.BUILDING,
            ExecutionState.BUILT,
            ExecutionState.PUSHING,
            ExecutionState.DIGEST_RESOLVED,
            ExecutionState.CLUSTER_PREPARING,
            ExecutionState.APPLYING,
            ExecutionState.WAITING_READY,
            ExecutionState.SMOKE_TESTING,
            ExecutionState.ATTESTING,
            ExecutionState.COLLECTING_EVIDENCE,
            ExecutionState.SUCCEEDED,
        )
    else:
        states = (ExecutionState.PLANNED, ExecutionState.FAILED)
    for state in states:
        machine.append(
            StateTransition(
                state=state,
                previous_state=machine.current_state,
                started_at=TIMESTAMP,
                finished_at=TIMESTAMP,
                input_subject=plan.build_plan_hash,
                exit_code=0 if state != ExecutionState.FAILED else None,
                error_category=(
                    ExecutionErrorCategory.VALIDATION
                    if state == ExecutionState.FAILED
                    else None
                ),
            )
        )
    store.write_json("state.json", machine.to_dict(store.run_id))


def assemble(
    store: EvidenceStore, plan: ExecutionPlan, run: ExecutionRun
):
    write_terminal_state(store, plan, run)
    return assemble_evidence_bundle(store, plan, run)


def reseal(store: EvidenceStore) -> None:
    entries = []
    for path in store._material_files():
        relative = path.relative_to(store.root).as_posix()
        if relative == "checksums.json":
            continue
        entries.append({"path": relative, "sha256": sha256_file(path)})
    checksums = load_json(store.path("checksums.json"))
    checksums["files"] = entries
    payload = "".join(
        f"{entry['sha256']}  {entry['path']}\n" for entry in entries
    ).encode("utf-8")
    checksums["manifestSha256"] = hashlib.sha256(payload).hexdigest()
    store.write_json("checksums.json", checksums, overwrite=True)
    store.write_checksums(overwrite=True)


def resource_document(status: str) -> dict[str, object]:
    name = "devops-stack-registry-20260830t120000z-abc-0123456789ab"
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "runId": RUN_ID,
        "registry": {
            "status": status,
            "name": name,
            "containerId": "1" * 64,
            "host": "127.0.0.1",
            "hostPort": 49153,
            "containerPort": 5000,
            "image": REGISTRY_IMAGE,
            "localTestOnly": True,
            "labels": {
                MANAGED_BY_LABEL: "devops-stack-composer",
                RESOURCE_LABEL: "ephemeral-registry",
                RUN_ID_LABEL: RUN_ID,
                CONTAINER_NAME_LABEL: name,
            },
        },
        "kind": None,
    }
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        **payload,
        "contentDigest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)

    def store(self) -> EvidenceStore:
        return EvidenceStore.create(self.project, run_id=RUN_ID)

    def assembled(self) -> tuple[EvidenceStore, ExecutionPlan, ExecutionRun]:
        store = self.store()
        plan = execution_plan()
        run = execution_run(plan)
        assemble(store, plan, run)
        return store, plan, run

    def test_assembles_stable_deterministic_closed_bundle(self) -> None:
        store = self.store()
        store.write_text("logs/config-schema.log", "validation passed\n")
        plan = execution_plan()
        run = execution_run(
            plan,
            stage_evidence={"config-schema": ("logs/config-schema.log",)},
        )

        result = assemble(store, plan, run)
        inventory = store.verify_checksums()

        self.assertTrue(REQUIRED_BUNDLE_FILES <= set(inventory))
        self.assertIn("logs/config-schema.log", inventory)
        self.assertTrue(result.execution_succeeded)
        self.assertFalse(result.incomplete)
        self.assertFalse(result.authenticity_established)
        self.assertEqual(result.to_dict()["authenticity"], AUTHENTICITY_STATUS)
        for relative in REQUIRED_BUNDLE_FILES - {"summary.md"}:
            value = load_json(store.path(relative))
            self.assertEqual(value["schemaVersion"], BUNDLE_SCHEMA_VERSION)
            expected = json.dumps(
                value,
                indent=2,
                sort_keys=True,
                allow_nan=False,
                ensure_ascii=False,
            ) + "\n"
            self.assertEqual(
                store.path(relative).read_text(encoding="utf-8"), expected
            )
        summary = store.path("summary.md").read_text(encoding="utf-8")
        self.assertIn("schemaVersion: 1.0.0", summary)
        self.assertIn("Authenticity: **not established**", summary)

    def test_partial_failure_is_valid_but_never_successful(self) -> None:
        store = self.store()
        plan = execution_plan()
        run = execution_run(plan, failed_stage="config-schema")

        result = assemble(store, plan, run)
        reopened = verify_evidence_bundle(store)

        self.assertEqual(result.final_status, "FAILED")
        self.assertTrue(result.incomplete)
        self.assertFalse(result.execution_succeeded)
        self.assertEqual(reopened, result)
        summary = store.path("summary.md").read_text(encoding="utf-8")
        self.assertIn("Execution result: **FAILED**", summary)
        self.assertIn("Incomplete: **yes**", summary)

    def test_terminal_state_is_required_before_assembly(self) -> None:
        store = self.store()
        plan = execution_plan()

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_STATE_REQUIRED"):
            assemble_evidence_bundle(store, plan, execution_run(plan))
        self.assertFalse(store.path("run.json").exists())

    def test_matching_preexecution_plan_and_policy_are_finalized_safely(self) -> None:
        store = self.store()
        plan = execution_plan()
        run = execution_run(plan)
        write_terminal_state(store, plan, run)
        store.write_json("plan.json", plan.to_dict())
        store.write_json("policy.json", profile_policy(plan.profile).to_dict())

        result = assemble_evidence_bundle(store, plan, run)

        self.assertTrue(result.execution_succeeded)
        policy = load_json(store.path("policy.json"))
        self.assertEqual(policy["schemaVersion"], BUNDLE_SCHEMA_VERSION)
        self.assertEqual(policy["policy"], profile_policy(plan.profile).to_dict())

    def test_state_plan_subject_is_cross_checked(self) -> None:
        store = self.store()
        plan = execution_plan()
        run = execution_run(plan)
        write_terminal_state(store, plan, run)
        state = load_json(store.path("state.json"))
        transitions = state["transitions"]
        assert isinstance(transitions, list)
        first = transitions[0]
        assert isinstance(first, dict)
        first["inputSubject"] = "f" * 64
        store.write_json("state.json", state, overwrite=True)

        with self.assertRaisesRegex(
            EvidenceBundleError, "BUNDLE_STATE_PLAN_MISMATCH"
        ):
            assemble_evidence_bundle(store, plan, run)

    def test_changed_missing_and_unexpected_files_fail_closed(self) -> None:
        cases = ("changed", "missing", "unexpected")
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    project = Path(directory)
                    store = EvidenceStore.create(project, run_id=RUN_ID)
                    plan = execution_plan()
                    assemble(store, plan, execution_run(plan))
                    if case == "changed":
                        store.write_text("summary.md", "changed\n", overwrite=True)
                    elif case == "missing":
                        store.path("policy.json").unlink()
                    else:
                        store.write_text("unexpected.json", "{}\n")

                    with self.assertRaisesRegex(
                        EvidenceBundleError, "BUNDLE_INTEGRITY_INVALID"
                    ):
                        verify_evidence_bundle(store)

    def test_missing_required_file_is_detected_even_after_manifest_reseal(self) -> None:
        store, _, _ = self.assembled()
        store.path("policy.json").unlink()
        reseal(store)

        with self.assertRaisesRegex(
            EvidenceBundleError, "BUNDLE_REQUIRED_FILE_MISSING"
        ):
            verify_evidence_bundle(store)

    def test_resealed_undeclared_file_is_still_unexpected(self) -> None:
        store, _, _ = self.assembled()
        store.write_json("unrelated.json", {"schemaVersion": "1.0.0"})
        reseal(store)

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_UNEXPECTED_FILE"):
            verify_evidence_bundle(store)

    def test_manifest_tamper_is_detected_even_when_sha256sums_is_rewritten(self) -> None:
        store, _, _ = self.assembled()
        checksums = load_json(store.path("checksums.json"))
        checksums["manifestSha256"] = "f" * 64
        store.write_json("checksums.json", checksums, overwrite=True)
        store.write_checksums(overwrite=True)

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_MANIFEST_MISMATCH"):
            verify_evidence_bundle(store)

    def test_authorized_resource_update_reseals_and_reverifies(self) -> None:
        store = self.store()
        store.write_json("resources.json", resource_document("active"))
        plan = execution_plan()
        run = execution_run(plan)
        assemble(store, plan, run)
        previous_manifest = store.path("SHA256SUMS").read_text(encoding="utf-8")

        result = update_sealed_resource_record(
            store, resource_document("removed")
        )

        self.assertTrue(result.execution_succeeded)
        self.assertEqual(
            load_json(store.path("resources.json"))["registry"]["status"],
            "removed",
        )
        self.assertNotEqual(
            store.path("SHA256SUMS").read_text(encoding="utf-8"),
            previous_manifest,
        )
        self.assertEqual(verify_evidence_bundle(store), result)

    def test_mixed_run_is_rejected_after_internal_checksums_are_rewritten(self) -> None:
        store, _, _ = self.assembled()
        other_plan = execution_plan(run_id=OTHER_RUN_ID)
        other_run = execution_run(other_plan)
        store.write_json("plan.json", other_plan.to_dict(), overwrite=True)
        store.write_json("run.json", other_run.to_dict(), overwrite=True)
        reseal(store)

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_RUN_ID_MISMATCH"):
            verify_evidence_bundle(store)

    def test_coordinated_success_flip_conflicts_with_derived_records(self) -> None:
        store = self.store()
        plan = execution_plan()
        failed_stage = plan.stages[-1].stage_id
        assemble(store, plan, execution_run(plan, failed_stage=failed_stage))
        run = load_json(store.path("run.json"))
        stages = run["stageResults"]
        assert isinstance(stages, list)
        last = stages[-1]
        assert isinstance(last, dict)
        last["status"] = "PASSED"
        last["failureReason"] = None
        last["remediation"] = None
        run["finalStatus"] = "PASSED"
        run["failureReason"] = None
        counts = run["statusCounts"]
        assert isinstance(counts, dict)
        counts["PASSED"] = len(stages)
        counts["FAILED"] = 0
        store.write_json("run.json", run, overwrite=True)
        reseal(store)

        with self.assertRaisesRegex(
            EvidenceBundleError, "BUNDLE_STATE_OUTCOME_MISMATCH"
        ):
            verify_evidence_bundle(store)

    def test_symlink_and_non_regular_file_are_rejected(self) -> None:
        for case in ("symlink", "fifo"):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    project = Path(directory)
                    store = EvidenceStore.create(project, run_id=RUN_ID)
                    if case == "symlink":
                        target = project / "outside.log"
                        target.write_text("outside\n", encoding="utf-8")
                        (store.root / "logs" / "linked.log").symlink_to(target)
                    else:
                        os.mkfifo(store.root / "logs" / "blocked")

                    with self.assertRaises(EvidenceStoreError):
                        plan = execution_plan()
                        assemble(store, plan, execution_run(plan))

    def test_unredacted_log_is_rejected_before_canonical_records_are_written(self) -> None:
        store = self.store()
        store.write_text("logs/build.log", "Authorization: Bearer should-not-leak\n")

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_SECRET_EXPOSURE"):
            plan = execution_plan()
            assemble(store, plan, execution_run(plan))
        self.assertFalse(store.path("run.json").exists())

    def test_unredacted_plan_value_is_rejected(self) -> None:
        store = self.store()
        # Keep the plan internally valid so this specifically exercises the
        # evidence redaction boundary rather than hash validation.
        rebuilt_intent = ArtifactIntent(
            application_name="sample-app",
            registry="localhost:5000",
            repository="team/sample-app",
            requested_tag="run-1",
            platforms=("linux/amd64",),
            source_revision=SOURCE_REVISION,
            build_context=".",
            dockerfile="generated/docker/Dockerfile",
            template_revision="b" * 40,
            normalized_model_hash="c" * 64,
            build_arguments={"API_TOKEN": "should-not-leak"},
        )
        secret_plan = ExecutionPlan.create(
            run_id=RUN_ID,
            profile="static",
            environment="staging",
            artifact_intent=rebuilt_intent,
        )
        run = execution_run(secret_plan)
        write_terminal_state(store, secret_plan, run)

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_SECRET_EXPOSURE"):
            assemble_evidence_bundle(store, secret_plan, run)

    def test_nested_sha256sums_name_remains_part_of_closed_inventory(self) -> None:
        store = self.store()
        store.write_text("logs/SHA256SUMS", "tool output, not the bundle manifest\n")

        plan = execution_plan()
        assemble(store, plan, execution_run(plan))

        self.assertIn("logs/SHA256SUMS", store.verify_checksums())

    def test_declared_evidence_must_exist(self) -> None:
        store = self.store()
        plan = execution_plan()
        run = execution_run(
            plan,
            stage_evidence={"config-schema": ("logs/missing.log",)},
        )

        with self.assertRaisesRegex(
            EvidenceBundleError, "BUNDLE_DECLARED_FILE_MISSING"
        ):
            assemble(store, plan, run)

    def test_reserved_record_conflict_is_rejected_without_overwrite(self) -> None:
        store = self.store()
        store.write_json("smoke.json", {"schemaVersion": "raw"})

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_RECORD_CONFLICT"):
            plan = execution_plan()
            assemble(store, plan, execution_run(plan))
        self.assertEqual(load_json(store.path("smoke.json"))["schemaVersion"], "raw")

    def test_duplicate_json_field_is_rejected_after_reseal(self) -> None:
        store, _, _ = self.assembled()
        policy = store.path("policy.json").read_text(encoding="utf-8")
        store.write_text(
            "policy.json",
            policy.replace("{\n", '{\n  "schemaVersion": "1.0.0",\n', 1),
            overwrite=True,
        )
        reseal(store)

        with self.assertRaisesRegex(EvidenceBundleError, "BUNDLE_JSON_INVALID"):
            verify_evidence_bundle(store)


if __name__ == "__main__":
    unittest.main()
