from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
from typing import Any, Callable
import unittest

from devops_stack_composer.evidence_validation import ArtifactContractError
from devops_stack_composer.execution_models import (
    ArtifactIntent,
    DeploymentEvidence,
    ExecutionRun,
    ResolvedArtifact,
    StageResult,
    StageStatus,
    SupplyChainEvidence,
)
from devops_stack_composer.execution_plan import ExecutionPlan
from devops_stack_composer.runtime_validation import (
    MAX_RUNTIME_JSON_BYTES,
    MAX_STAGE_CAPTURE_BYTES,
    MAX_STAGE_COMMAND_ARGUMENTS,
    RuntimeValidationError,
    validate_runtime_files,
    validate_runtime_records,
)
from devops_stack_composer.supply_chain import CHECKSUM_ONLY_VERIFICATION_STATUS


DIGEST = "sha256:" + "a" * 64
PLATFORM_DIGEST = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
OTHER_DIGEST = "sha256:" + "d" * 64
SOURCE_REVISION = "e" * 40
RUN_ID = "20260830T120000Z-012345abcdef"
IMAGE_REPOSITORY = "localhost:5000/team/app"
IMMUTABLE_IMAGE = f"{IMAGE_REPOSITORY}@{DIGEST}"
TIMESTAMP = "2026-08-30T12:00:00Z"


def execution_plan(
    profile: str,
    *,
    platforms: tuple[str, ...] = ("linux/amd64",),
) -> dict[str, Any]:
    intent = ArtifactIntent(
        application_name="sample-app",
        registry="localhost:5000",
        repository="team/app",
        requested_tag="run-1",
        platforms=platforms,
        source_revision=SOURCE_REVISION,
        build_context=".",
        dockerfile="generated/docker/Dockerfile",
        template_revision="1" * 40,
        normalized_model_hash="2" * 64,
        build_arguments={"BUILD_MODE": "release"},
        target_stage="runtime",
    )
    return ExecutionPlan.create(
        run_id=RUN_ID,
        profile=profile,
        environment="staging",
        artifact_intent=intent,
    ).to_dict()


def resolved_artifact(
    plan: dict[str, Any],
    *,
    manifest_digest: str = DIGEST,
    platform_digest: str = DIGEST,
    build_invocation_count: int = 1,
) -> ResolvedArtifact:
    media_type = (
        "application/vnd.oci.image.index.v1+json"
        if manifest_digest != platform_digest
        else "application/vnd.oci.image.manifest.v1+json"
    )
    return ResolvedArtifact(
        immutable_image_reference=f"{IMAGE_REPOSITORY}@{manifest_digest}",
        repository=IMAGE_REPOSITORY,
        tag="run-1",
        manifest_digest=manifest_digest,
        platform_digest=platform_digest,
        media_type=media_type,
        architecture="amd64",
        operating_system="linux",
        image_size=1024,
        config_digest=CONFIG_DIGEST,
        source_revision=SOURCE_REVISION,
        build_plan_hash=str(plan["buildPlanHash"]),
        created_by_tool_version="0.2.0",
        registry_endpoint="localhost:5000",
        build_invocation_count=build_invocation_count,
    )


def supply_chain_evidence(
    *,
    artifact_digest: str = DIGEST,
    policy_passed: bool = True,
) -> SupplyChainEvidence:
    return SupplyChainEvidence(
        artifact_digest=artifact_digest,
        sbom_path="sbom.spdx.json",
        sbom_format="spdx-json",
        sbom_hash="3" * 64,
        sbom_generator="syft 1.51.1",
        vulnerability_report_path="vulnerabilities.json",
        vulnerability_report_hash="4" * 64,
        scanner_name="trivy",
        scanner_version="0.66.0",
        scanner_database_metadata={"updatedAt": TIMESTAMP},
        policy_result={"passed": policy_passed, "violations": 0},
        provenance_path="provenance.json",
        provenance_hash="5" * 64,
        provenance_type="https://slsa.dev/provenance/v1",
        attestation_subject=IMMUTABLE_IMAGE,
        verification_status=CHECKSUM_ONLY_VERIFICATION_STATUS,
        evidence_generation_time=TIMESTAMP,
    )


def deployment_evidence(
    *,
    expected_digest: str = DIGEST,
    actual_digest: str = DIGEST,
    final_digest: str = DIGEST,
) -> DeploymentEvidence:
    return DeploymentEvidence(
        environment="staging",
        namespace="sample-staging",
        cluster_type="kind",
        cluster_identifier="devops-stack-run-1",
        manifest_hash="6" * 64,
        deployed_image_reference=IMMUTABLE_IMAGE,
        expected_digest=expected_digest,
        actual_pod_image_id=f"containerd://{actual_digest}",
        rollout_status="PASSED",
        ready_replica_count=1,
        health_endpoint_result={"status": 200},
        readiness_endpoint_result={"status": 200},
        rollback_attempted=True,
        rollback_result="PASSED",
        final_revision="2",
        final_digest=final_digest,
        diagnostics_paths=("diagnostics/events.txt",),
    )


def successful_evidence(
    plan: dict[str, Any],
    *,
    platform_digest: str = DIGEST,
) -> dict[str, Any]:
    profile = str(plan["profile"])
    stage_results = tuple(
        StageResult(
            stage_id=str(stage["stageId"]),
            description=str(stage["description"]),
            status=StageStatus.PASSED,
            start_time=TIMESTAMP,
            end_time=TIMESTAMP,
            command=("devops-stack", str(stage["stageId"])),
            tool="devops-stack",
            sanitized_output="stage passed",
            evidence_paths=(),
        )
        for stage in plan["stages"]
    )
    artifact = None
    supply = None
    deployment = None
    if profile != "static":
        artifact = resolved_artifact(plan, platform_digest=platform_digest)
        supply = supply_chain_evidence()
    if profile in {"kind-e2e", "release"}:
        deployment = deployment_evidence()
    tool_versions = {
        "devops-stack-composer": "0.2.0",
    }
    if profile != "static":
        tool_versions.update(
            {
                "docker": "28.0.0",
                "docker-buildx": "0.24.0",
                "syft": "1.30.0",
                "trivy": "0.66.0",
            }
        )
    if profile in {"kind-e2e", "release"}:
        tool_versions.update(
            {
                "kind": "0.30.0",
                "kubectl": "1.33.0",
                "kubeconform": "0.7.0",
            }
        )
    if profile == "release":
        tool_versions["gh"] = "2.76.0"
    return ExecutionRun(
        run_id=RUN_ID,
        project_path=".",
        config_hash="7" * 64,
        template_lock_hash="8" * 64,
        source_revision=SOURCE_REVISION,
        start_time=TIMESTAMP,
        end_time=TIMESTAMP,
        execution_profile=profile,
        stage_results=stage_results,
        final_status=StageStatus.PASSED,
        tool_versions=tool_versions,
        artifact_record=artifact,
        supply_chain_evidence=supply,
        deployment_evidence=deployment,
        source_repository="https://github.com/example/sample-app",
        template_revisions={
            "docker": "3" * 40,
            "jenkins": "4" * 40,
            "kubernetes": "5" * 40,
        },
        evidence_checksums={"logs/config-schema.log": "6" * 64},
    ).to_dict()


def refresh_status_counts(evidence: dict[str, Any]) -> None:
    stages = evidence["stageResults"]
    assert isinstance(stages, list)
    evidence["statusCounts"] = {
        status.value: sum(stage["status"] == status.value for stage in stages)
        for status in StageStatus
    }


def assert_code(
    test: unittest.TestCase,
    code: str,
    action: Callable[[], object],
) -> None:
    with test.assertRaises((RuntimeValidationError, ArtifactContractError)) as caught:
        action()
    test.assertEqual(caught.exception.code, code)


class RuntimeValidationTests(unittest.TestCase):
    def test_every_profile_accepts_complete_success_evidence(self) -> None:
        for profile in ("static", "supply-chain", "kind-e2e", "release"):
            with self.subTest(profile=profile):
                plan = execution_plan(profile)
                result = validate_runtime_records(plan, successful_evidence(plan))

                self.assertEqual(result.profile, profile)
                self.assertEqual(result.final_status, "PASSED")
                self.assertFalse(result.incomplete)
                self.assertEqual(result.stage_count, len(plan["stages"]))
                self.assertEqual(
                    result.authoritative_digest,
                    None if profile == "static" else DIGEST,
                )

    def test_legacy_1_0_record_does_not_require_1_1_metadata(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        evidence["schemaVersion"] = "1.0.0"
        for field in (
            "sourceRepository",
            "templateRevisions",
            "evidenceChecksums",
            "evidenceChecksumPaths",
            "limitations",
        ):
            evidence.pop(field)
        evidence["toolVersions"] = {}
        for stage in evidence["stageResults"]:
            stage["command"] = []
            stage["tool"] = None

        result = validate_runtime_records(plan, evidence)

        self.assertEqual(result.final_status, "PASSED")
        self.assertFalse(result.incomplete)

    def test_current_metadata_requires_profile_tools_and_stage_invocations(self) -> None:
        plan = execution_plan("supply-chain")
        missing_tool = successful_evidence(plan)
        missing_tool["toolVersions"].pop("docker")
        assert_code(
            self,
            "RUNTIME_SCHEMA_INVALID",
            lambda: validate_runtime_records(plan, missing_tool),
        )

        invocationless = successful_evidence(plan)
        invocationless["stageResults"][0]["command"] = []
        invocationless["stageResults"][0]["tool"] = None
        assert_code(
            self,
            "RUNTIME_SCHEMA_INVALID",
            lambda: validate_runtime_records(plan, invocationless),
        )

        credentialed_source = successful_evidence(plan)
        credentialed_source["sourceRepository"] = (
            "https://token@example.com/example/sample-app"
        )
        assert_code(
            self,
            "EVIDENCE_RECORD_INVALID",
            lambda: validate_runtime_records(plan, credentialed_source),
        )

    def test_supply_chain_index_can_use_a_distinct_platform_digest(self) -> None:
        plan = execution_plan(
            "supply-chain",
            platforms=("linux/amd64", "linux/arm64"),
        )

        result = validate_runtime_records(
            plan,
            successful_evidence(plan, platform_digest=PLATFORM_DIGEST),
        )

        self.assertEqual(result.authoritative_digest, DIGEST)

    def test_kind_contract_rejects_a_distinct_platform_digest(self) -> None:
        plan = execution_plan("kind-e2e")
        evidence = successful_evidence(plan, platform_digest=PLATFORM_DIGEST)

        assert_code(
            self,
            "KIND_PLATFORM_DIGEST_MISMATCH",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_supply_chain_non_index_cannot_use_a_distinct_platform_digest(self) -> None:
        plan = execution_plan("supply-chain")
        evidence = successful_evidence(plan, platform_digest=PLATFORM_DIGEST)
        evidence["artifact"]["mediaType"] = (
            "application/vnd.oci.image.manifest.v1+json"
        )

        assert_code(
            self,
            "ARTIFACT_PLATFORM_DIGEST_MISMATCH",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_runtime_files_validate_strict_json_against_packaged_schemas(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            evidence_path = root / "run.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            result = validate_runtime_files(plan_path, evidence_path)

            self.assertEqual(result.run_id, RUN_ID)
            duplicate = json.dumps(plan)
            duplicate = duplicate.replace(
                "{",
                '{"runId":"duplicate",',
                1,
            )
            plan_path.write_text(duplicate, encoding="utf-8")
            assert_code(
                self,
                "RUNTIME_FILE_INVALID",
                lambda: validate_runtime_files(plan_path, evidence_path),
            )

    def test_runtime_files_reject_symlinks_and_oversized_records(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_plan = root / "real-plan.json"
            linked_plan = root / "linked-plan.json"
            evidence_path = root / "run.json"
            real_plan.write_text(json.dumps(plan), encoding="utf-8")
            linked_plan.symlink_to(real_plan)
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            assert_code(
                self,
                "RUNTIME_FILE_INVALID",
                lambda: validate_runtime_files(linked_plan, evidence_path),
            )

            oversized = root / "oversized-plan.json"
            oversized.write_bytes(b"x" * (MAX_RUNTIME_JSON_BYTES + 1))
            assert_code(
                self,
                "RUNTIME_FILE_TOO_LARGE",
                lambda: validate_runtime_files(oversized, evidence_path),
            )

    def test_schema_rejects_unknown_runtime_fields(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        evidence["unexpected"] = True

        assert_code(
            self,
            "RUNTIME_SCHEMA_INVALID",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_recomputed_plan_hash_and_exact_stage_order_are_required(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        tampered_hash = deepcopy(plan)
        tampered_hash["buildPlanHash"] = "9" * 64
        assert_code(
            self,
            "PLAN_HASH_MISMATCH",
            lambda: validate_runtime_records(tampered_hash, evidence),
        )

        reordered = deepcopy(plan)
        reordered["stages"][0], reordered["stages"][1] = (
            reordered["stages"][1],
            reordered["stages"][0],
        )
        assert_code(
            self,
            "PLAN_STAGE_ORDER_MISMATCH",
            lambda: validate_runtime_records(reordered, evidence),
        )

    def test_run_profile_source_and_artifact_plan_hash_are_cross_checked(self) -> None:
        plan = execution_plan("supply-chain")
        cases = (
            ("runId", "another-run", "RUN_ID_MISMATCH"),
            ("executionProfile", "static", "PROFILE_MISMATCH"),
            ("sourceRevision", "f" * 40, "SOURCE_REVISION_MISMATCH"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                evidence = successful_evidence(plan)
                evidence[field] = value
                assert_code(
                    self,
                    code,
                    lambda evidence=evidence: validate_runtime_records(plan, evidence),
                )

        evidence = successful_evidence(plan)
        evidence["artifact"]["buildPlanHash"] = "9" * 64
        assert_code(
            self,
            "BUILD_PLAN_HASH_MISMATCH",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_status_counts_and_complete_stage_order_are_required(self) -> None:
        plan = execution_plan("static")
        counts = successful_evidence(plan)
        counts["statusCounts"]["PASSED"] -= 1
        assert_code(
            self,
            "STATUS_COUNTS_MISMATCH",
            lambda: validate_runtime_records(plan, counts),
        )

        incomplete = successful_evidence(plan)
        incomplete["stageResults"].pop()
        refresh_status_counts(incomplete)
        assert_code(
            self,
            "REQUIRED_STAGE_MISMATCH",
            lambda: validate_runtime_records(plan, incomplete),
        )

        reordered = successful_evidence(plan)
        reordered["stageResults"][0], reordered["stageResults"][1] = (
            reordered["stageResults"][1],
            reordered["stageResults"][0],
        )
        assert_code(
            self,
            "REQUIRED_STAGE_MISMATCH",
            lambda: validate_runtime_records(plan, reordered),
        )

    def test_final_status_must_follow_stage_results(self) -> None:
        plan = execution_plan("static")
        failed_without_failure = successful_evidence(plan)
        failed_without_failure["finalStatus"] = "FAILED"
        failed_without_failure["failureReason"] = "claimed failure"
        assert_code(
            self,
            "FINAL_STATUS_INCONSISTENT",
            lambda: validate_runtime_records(plan, failed_without_failure),
        )

        passed_with_nonpassing = successful_evidence(plan)
        passed_with_nonpassing["stageResults"][0]["status"] = "NOT_APPLICABLE"
        refresh_status_counts(passed_with_nonpassing)
        assert_code(
            self,
            "FINAL_STATUS_INCONSISTENT",
            lambda: validate_runtime_records(plan, passed_with_nonpassing),
        )

    def test_success_requires_profile_specific_evidence(self) -> None:
        supply_plan = execution_plan("supply-chain")
        missing_artifact = successful_evidence(supply_plan)
        missing_artifact["artifact"] = None
        missing_artifact["supplyChainEvidence"] = None
        assert_code(
            self,
            "REQUIRED_EVIDENCE_MISSING",
            lambda: validate_runtime_records(supply_plan, missing_artifact),
        )

        kind_plan = execution_plan("kind-e2e")
        missing_deployment = successful_evidence(kind_plan)
        missing_deployment["deploymentEvidence"] = None
        assert_code(
            self,
            "REQUIRED_EVIDENCE_MISSING",
            lambda: validate_runtime_records(kind_plan, missing_deployment),
        )

    def test_success_requires_passing_supply_and_deployment_evidence(self) -> None:
        supply_plan = execution_plan("supply-chain")
        failed_policy = successful_evidence(supply_plan)
        failed_policy["supplyChainEvidence"]["policyResult"]["passed"] = False
        assert_code(
            self,
            "SUPPLY_CHAIN_POLICY_FAILED",
            lambda: validate_runtime_records(supply_plan, failed_policy),
        )

        kind_plan = execution_plan("kind-e2e")
        failed_health = successful_evidence(kind_plan)
        failed_health["deploymentEvidence"]["healthEndpointResult"]["status"] = 500
        assert_code(
            self,
            "DEPLOYMENT_EVIDENCE_INVALID",
            lambda: validate_runtime_records(kind_plan, failed_health),
        )

    def test_build_is_invoked_exactly_once(self) -> None:
        plan = execution_plan("supply-chain")
        evidence = successful_evidence(plan)
        evidence["artifact"]["buildInvocationCount"] = 2

        assert_code(
            self,
            "BUILD_INVOKED_MORE_THAN_ONCE",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_top_level_evidence_must_match_the_manifest_digest(self) -> None:
        plan = execution_plan("supply-chain")
        evidence = successful_evidence(plan, platform_digest=PLATFORM_DIGEST)
        evidence["supplyChainEvidence"]["artifactDigest"] = OTHER_DIGEST

        assert_code(
            self,
            "ARTIFACT_DIGEST_MISMATCH",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_kind_runtime_digest_must_match_the_manifest(self) -> None:
        plan = execution_plan("kind-e2e")
        evidence = successful_evidence(plan)
        evidence["deploymentEvidence"]["actualPodImageId"] = (
            f"containerd://{OTHER_DIGEST}"
        )

        assert_code(
            self,
            "ARTIFACT_DIGEST_MISMATCH",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_stage_capture_is_bounded_and_secret_redacted(self) -> None:
        plan = execution_plan("static")
        cases = (
            (
                "sanitizedOutput",
                "x" * (MAX_STAGE_CAPTURE_BYTES + 1),
                "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            ),
            (
                "sanitizedOutput",
                "Authorization: Bearer unredacted-token",
                "EVIDENCE_SECRET_EXPOSURE",
            ),
            (
                "command",
                ["curl", "--token", "unredacted-token"],
                "EVIDENCE_SECRET_EXPOSURE",
            ),
            (
                "command",
                ["x" * (MAX_STAGE_CAPTURE_BYTES + 1)],
                "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            ),
            (
                "command",
                ["x"] * (MAX_STAGE_COMMAND_ARGUMENTS + 1),
                "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            ),
        )
        for field, value, code in cases:
            with self.subTest(field=field, code=code):
                evidence = successful_evidence(plan)
                evidence["stageResults"][0][field] = value
                assert_code(
                    self,
                    code,
                    lambda evidence=evidence: validate_runtime_records(plan, evidence),
                )

    def test_failed_run_can_preserve_complete_failure_evidence(self) -> None:
        plan = execution_plan("kind-e2e")
        evidence = successful_evidence(plan)
        evidence["artifact"] = None
        evidence["supplyChainEvidence"] = None
        evidence["deploymentEvidence"] = None
        evidence["finalStatus"] = "FAILED"
        evidence["failureReason"] = "build failed"
        evidence["stageResults"][0]["status"] = "FAILED"
        evidence["stageResults"][0]["failureReason"] = "invalid configuration"
        evidence["stageResults"] = evidence["stageResults"][:1]
        refresh_status_counts(evidence)

        result = validate_runtime_records(plan, evidence)

        self.assertEqual(result.final_status, "FAILED")
        self.assertTrue(result.incomplete)
        self.assertTrue(result.to_dict()["incomplete"])
        self.assertIsNone(result.authoritative_digest)

    def test_failed_run_cannot_pad_unexecuted_stages_after_the_failure(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        evidence["finalStatus"] = "FAILED"
        evidence["failureReason"] = "configuration failed"
        evidence["stageResults"][0]["status"] = "FAILED"
        evidence["stageResults"][0]["failureReason"] = "invalid configuration"
        for stage in evidence["stageResults"][1:]:
            stage["status"] = "NOT_APPLICABLE"
        refresh_status_counts(evidence)

        assert_code(
            self,
            "FINAL_STATUS_INCONSISTENT",
            lambda: validate_runtime_records(plan, evidence),
        )

    def test_failure_at_the_final_planned_stage_is_still_marked_incomplete(self) -> None:
        plan = execution_plan("static")
        evidence = successful_evidence(plan)
        evidence["finalStatus"] = "FAILED"
        evidence["failureReason"] = "rendering failed"
        evidence["stageResults"][-1]["status"] = "FAILED"
        evidence["stageResults"][-1]["failureReason"] = "renderer returned non-zero"
        refresh_status_counts(evidence)

        result = validate_runtime_records(plan, evidence)

        self.assertTrue(result.incomplete)

    def test_failed_supply_policy_is_valid_failure_evidence(self) -> None:
        plan = execution_plan("supply-chain")
        evidence = successful_evidence(plan)
        evidence["finalStatus"] = "FAILED"
        evidence["failureReason"] = "vulnerability policy failed"
        failed_index = next(
            index
            for index, stage in enumerate(evidence["stageResults"])
            if stage["stageId"] == "vulnerability-scan"
        )
        evidence["stageResults"][failed_index]["status"] = "FAILED"
        evidence["stageResults"][failed_index]["failureReason"] = (
            "critical vulnerability"
        )
        evidence["stageResults"] = evidence["stageResults"][: failed_index + 1]
        evidence["supplyChainEvidence"]["policyResult"]["passed"] = False
        refresh_status_counts(evidence)

        result = validate_runtime_records(plan, evidence)

        self.assertEqual(result.final_status, "FAILED")
        self.assertTrue(result.incomplete)
        self.assertEqual(result.authoritative_digest, DIGEST)

    def test_blocked_run_accepts_the_exact_prefix_through_the_blocker(self) -> None:
        plan = execution_plan("kind-e2e")
        evidence = successful_evidence(plan)
        blocked_index = next(
            index
            for index, stage in enumerate(evidence["stageResults"])
            if stage["stageId"] == "registry-lifecycle"
        )
        evidence["stageResults"][blocked_index]["status"] = (
            "BLOCKED_MISSING_REQUIRED_TOOL"
        )
        evidence["stageResults"][blocked_index]["failureReason"] = (
            "docker is unavailable"
        )
        evidence["stageResults"] = evidence["stageResults"][: blocked_index + 1]
        evidence["artifact"] = None
        evidence["supplyChainEvidence"] = None
        evidence["deploymentEvidence"] = None
        evidence["finalStatus"] = "BLOCKED_MISSING_REQUIRED_TOOL"
        evidence["failureReason"] = "required build engine is unavailable"
        refresh_status_counts(evidence)

        result = validate_runtime_records(plan, evidence)

        self.assertEqual(result.final_status, "BLOCKED_MISSING_REQUIRED_TOOL")
        self.assertTrue(result.incomplete)
        self.assertIsNone(result.authoritative_digest)


if __name__ == "__main__":
    unittest.main()
