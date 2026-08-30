from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.execution_models import (
    ArtifactIntent,
    DeploymentEvidence,
    ResolvedArtifact,
    SupplyChainEvidence,
)
from devops_stack_composer.execution_plan import ExecutionPlan, PlannedStage
from devops_stack_composer.execution_state import ExecutionJournal, ExecutionState
from devops_stack_composer.local_execution import (
    EnvironmentBlockedError,
    ExecutionProducts,
    LocalKindOrchestrator,
    StageExecutionEvidence,
)
from devops_stack_composer.runtime_validation import validate_runtime_records


RUN_ID = "20260831T010203Z-012345abcdef"
DIGEST = "sha256:" + "a" * 64
CONFIG_DIGEST = "sha256:" + "b" * 64
REVISION = "c" * 40
CONFIG_HASH = "d" * 64
LOCK_HASH = "e" * 64
REPOSITORY = "localhost:49153/team/service"
REFERENCE = f"{REPOSITORY}@{DIGEST}"


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 31, 1, 2, 3, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.value
        self.value += timedelta(milliseconds=1)
        return value


def plan() -> ExecutionPlan:
    intent = ArtifactIntent(
        application_name="service",
        registry="auto",
        repository="team/service",
        requested_tag=f"run-{RUN_ID.lower()}",
        platforms=("linux/amd64",),
        source_revision=REVISION,
        build_context=".",
        dockerfile="generated/docker/Dockerfile",
        template_revision="f" * 40,
        normalized_model_hash=CONFIG_HASH,
    )
    return ExecutionPlan.create(
        run_id=RUN_ID,
        profile="kind-e2e",
        environment="staging",
        artifact_intent=intent,
    )


def artifact(execution_plan: ExecutionPlan) -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=REFERENCE,
        repository=REPOSITORY,
        tag=execution_plan.artifact_intent.requested_tag,
        manifest_digest=DIGEST,
        platform_digest=DIGEST,
        media_type="application/vnd.oci.image.manifest.v1+json",
        architecture="amd64",
        operating_system="linux",
        image_size=1024,
        config_digest=CONFIG_DIGEST,
        source_revision=REVISION,
        build_plan_hash=execution_plan.build_plan_hash,
        created_by_tool_version="0.2.0",
        registry_endpoint="localhost:49153",
        build_invocation_count=1,
    )


def supply() -> SupplyChainEvidence:
    return SupplyChainEvidence(
        artifact_digest=DIGEST,
        sbom_path="sbom.spdx.json",
        sbom_format="spdx-json",
        sbom_hash="1" * 64,
        sbom_generator="syft-1.42.3",
        vulnerability_report_path="vulnerabilities.json",
        vulnerability_report_hash="2" * 64,
        scanner_name="trivy",
        scanner_version="0.69.0",
        scanner_database_metadata={"updatedAt": "2026-08-31T00:00:00Z"},
        policy_result={"passed": True},
        provenance_path="provenance.json",
        provenance_hash="3" * 64,
        provenance_type="https://slsa.dev/provenance/v1",
        attestation_subject=REFERENCE,
        verification_status=(
            "CHECKSUM_ONLY_FILE_EVIDENCE:signature=false,attachment=false,crypto=false"
        ),
        evidence_generation_time="2026-08-31T01:02:03Z",
    )


def deployment() -> DeploymentEvidence:
    return DeploymentEvidence(
        environment="staging",
        namespace="service-staging",
        cluster_type="kind",
        cluster_identifier="dsc-kind-test",
        manifest_hash="4" * 64,
        deployed_image_reference=REFERENCE,
        expected_digest=DIGEST,
        actual_pod_image_id=f"containerd://{DIGEST}",
        rollout_status="PASSED",
        ready_replica_count=1,
        health_endpoint_result={"status": 200},
        readiness_endpoint_result={"status": 200},
        rollback_attempted=True,
        rollback_result="PASSED",
        final_revision="2",
        final_digest=DIGEST,
    )


class FakeStageExecutor:
    def __init__(self, execution_plan: ExecutionPlan, fail_stage: str | None = None):
        self.plan = execution_plan
        self.fail_stage = fail_stage
        self.calls: list[str] = []
        self.cleanup_calls = 0
        self._artifact: ResolvedArtifact | None = None
        self._supply: SupplyChainEvidence | None = None
        self._deployment: DeploymentEvidence | None = None

    def execute(self, stage: PlannedStage) -> StageExecutionEvidence:
        self.calls.append(stage.stage_id)
        if stage.stage_id == self.fail_stage:
            raise EnvironmentBlockedError(f"required tool missing at {stage.stage_id}")
        if stage.stage_id == "resolve-digest":
            self._artifact = artifact(self.plan)
        if stage.stage_id == "sbom":
            self._supply = supply()
        if stage.stage_id == "deployment":
            self._deployment = deployment()
        return StageExecutionEvidence(
            subject=self.plan.build_plan_hash,
            command=("fake-tool", stage.stage_id),
            tool="fake-tool",
            sanitized_output=f"verified {stage.stage_id}",
            evidence_paths=("plan.json",),
            cleanup_performed=stage.stage_id == "cleanup",
        )

    def cleanup_after_failure(self) -> StageExecutionEvidence:
        self.cleanup_calls += 1
        return StageExecutionEvidence(
            self.plan.build_plan_hash,
            command=("fake-tool", "cleanup"),
            cleanup_performed=True,
        )

    def products(self) -> ExecutionProducts:
        return ExecutionProducts(
            self._artifact,
            self._supply,
            self._deployment,
            {"fake-tool": "1.0.0"},
        )


class Finalizer:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def __call__(self, *, store, plan, run, policy):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated bundle seal failure")
        store.write_json("run.json", run.to_dict())
        verification = validate_runtime_records(plan.to_dict(), run.to_dict())
        store.write_checksums()
        store.verify_checksums()
        return verification


class LocalKindOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)

    def orchestrator(
        self,
        executor: FakeStageExecutor,
        finalizer: Finalizer,
        *,
        suffix: str = "",
        **kwargs,
    ) -> LocalKindOrchestrator:
        selected_plan = executor.plan
        if suffix:
            selected_plan = ExecutionPlan.create(
                run_id=RUN_ID[:-1] + suffix,
                profile="kind-e2e",
                environment="staging",
                artifact_intent=selected_plan.artifact_intent,
            )
            executor.plan = selected_plan
        store = EvidenceStore.create(self.project, run_id=selected_plan.run_id)
        return LocalKindOrchestrator(
            store,
            selected_plan,
            executor,
            finalizer,
            project_path=".",
            config_hash=CONFIG_HASH,
            template_lock_hash=LOCK_HASH,
            clock=Clock(),
            **kwargs,
        )

    def test_full_fake_flow_runs_exact_policy_order_and_seals_success(self) -> None:
        selected = plan()
        executor = FakeStageExecutor(selected)
        finalizer = Finalizer()

        outcome = self.orchestrator(executor, finalizer).run()

        self.assertTrue(outcome.succeeded)
        self.assertEqual(
            executor.calls,
            [stage.stage_id for stage in selected.stages],
        )
        self.assertEqual(finalizer.calls, 1)
        self.assertEqual(outcome.state, ExecutionState.CLEANED)
        journal = ExecutionJournal.open(
            EvidenceStore.open(self.project, selected.run_id)
        )
        self.assertEqual(
            [transition.state for transition in journal.machine.transitions],
            [
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
                ExecutionState.CLEANED,
            ],
        )

    def test_required_tool_failure_is_exact_prefix_and_cleanup_is_recorded(self) -> None:
        selected = plan()
        executor = FakeStageExecutor(selected, fail_stage="deployment")
        finalizer = Finalizer()

        outcome = self.orchestrator(
            executor,
            finalizer,
            suffix="1",
        ).run()

        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.final_status.value, "BLOCKED_MISSING_REQUIRED_TOOL")
        self.assertEqual(executor.calls[-1], "deployment")
        self.assertNotIn("rollout", executor.calls)
        self.assertEqual(executor.cleanup_calls, 1)
        self.assertTrue(outcome.cleanup_performed)
        run = __import__("json").loads(
            EvidenceStore.open(self.project, RUN_ID[:-1] + "1")
            .path("run.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(run["stageResults"][-1]["stageId"], "deployment")
        self.assertEqual(
            run["stageResults"][-1]["status"],
            "BLOCKED_MISSING_REQUIRED_TOOL",
        )

    def test_keep_environment_on_failure_skips_cleanup(self) -> None:
        executor = FakeStageExecutor(plan(), fail_stage="build-once")
        outcome = self.orchestrator(
            executor,
            Finalizer(),
            suffix="2",
            keep_environment_on_failure=True,
        ).run()

        self.assertFalse(outcome.succeeded)
        self.assertEqual(executor.cleanup_calls, 0)
        self.assertFalse(outcome.cleanup_performed)
        self.assertEqual(outcome.state, ExecutionState.FAILED)

    def test_unsealed_terminal_bundle_never_returns_success(self) -> None:
        executor = FakeStageExecutor(plan())
        with self.assertRaisesRegex(RuntimeError, "bundle seal failure"):
            self.orchestrator(executor, Finalizer(fail=True), suffix="3").run()


if __name__ == "__main__":
    unittest.main()
