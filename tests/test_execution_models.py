from __future__ import annotations

import json
import unittest

from devops_stack_composer.execution_models import (
    ArtifactIntent,
    DeploymentEvidence,
    EXECUTION_EVIDENCE_SCHEMA_VERSION,
    ExecutionRun,
    LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
    ResolvedArtifact,
    StageResult,
    StageStatus,
    SupplyChainEvidence,
)


DIGEST = "sha256:" + "a" * 64
PLATFORM_DIGEST = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
REVISION = "d" * 40
HASH = "e" * 64


def artifact() -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=f"localhost:5000/team/app@{DIGEST}",
        repository="localhost:5000/team/app",
        tag="run-1",
        manifest_digest=DIGEST,
        platform_digest=PLATFORM_DIGEST,
        media_type="application/vnd.oci.image.manifest.v1+json",
        architecture="amd64",
        operating_system="linux",
        image_size=1024,
        config_digest=CONFIG_DIGEST,
        source_revision=REVISION,
        build_plan_hash=HASH,
        created_by_tool_version="0.2.0",
        registry_endpoint="localhost:5000",
        build_invocation_count=1,
    )


def supply_chain() -> SupplyChainEvidence:
    return SupplyChainEvidence(
        artifact_digest=DIGEST,
        sbom_path="sbom.spdx.json",
        sbom_format="spdx-json",
        sbom_hash="1" * 64,
        sbom_generator="syft 1.0.0",
        vulnerability_report_path="vulnerabilities.json",
        vulnerability_report_hash="2" * 64,
        scanner_name="trivy",
        scanner_version="1.2.3",
        scanner_database_metadata={"updatedAt": "2026-08-30T00:00:00Z"},
        policy_result={"passed": True, "violations": 0},
        provenance_path="provenance.json",
        provenance_hash="3" * 64,
        provenance_type="https://slsa.dev/provenance/v1",
        attestation_subject=f"localhost:5000/team/app@{DIGEST}",
        verification_status="VERIFIED_FILE_EVIDENCE",
        evidence_generation_time="2026-08-30T09:00:00+09:00",
    )


def deployment() -> DeploymentEvidence:
    return DeploymentEvidence(
        environment="staging",
        namespace="sample-staging",
        cluster_type="kind",
        cluster_identifier="devops-stack-run-1",
        manifest_hash="4" * 64,
        deployed_image_reference=f"localhost:5000/team/app@{DIGEST}",
        expected_digest=DIGEST,
        actual_pod_image_id=f"containerd://{DIGEST}",
        rollout_status="PASSED",
        ready_replica_count=1,
        health_endpoint_result={"status": 200, "body": {"status": "healthy"}},
        readiness_endpoint_result={"status": 200, "body": {"status": "ready"}},
        rollback_attempted=True,
        rollback_result="PASSED",
        final_revision="2",
        final_digest=DIGEST,
        diagnostics_paths=("diagnostics/events.txt",),
    )


class ExecutionModelTests(unittest.TestCase):
    def test_artifact_intent_serializes_deterministically(self) -> None:
        intent = ArtifactIntent(
            application_name="sample-app",
            registry="localhost:5000",
            repository="team/sample-app",
            requested_tag="run-1",
            platforms=("linux/amd64",),
            source_revision=REVISION,
            build_context=".",
            dockerfile="Dockerfile",
            template_revision="f" * 40,
            normalized_model_hash=HASH,
            build_arguments={"ZED": "last", "ALPHA": "first"},
        )

        self.assertEqual(intent.image_reference, "localhost:5000/team/sample-app:run-1")
        self.assertEqual(list(intent.to_dict()["buildArguments"]), ["ALPHA", "ZED"])

    def test_resolved_artifact_requires_reference_identity_consistency(self) -> None:
        self.assertEqual(artifact().digest, DIGEST)
        with self.assertRaisesRegex(ValueError, "manifest_digest"):
            ResolvedArtifact(
                **{
                    **artifact().__dict__,
                    "manifest_digest": "sha256:" + "f" * 64,
                }
            )
        with self.assertRaisesRegex(ValueError, "positive integer"):
            ResolvedArtifact(**{**artifact().__dict__, "build_invocation_count": 0})

    def test_evidence_records_preserve_mismatches_for_later_contract_validation(self) -> None:
        evidence = supply_chain()
        mismatched = SupplyChainEvidence(
            **{
                **evidence.__dict__,
                "attestation_subject": "sha256:" + "f" * 64,
            }
        )

        self.assertNotEqual(
            mismatched.to_dict()["artifactDigest"],
            mismatched.to_dict()["attestationSubject"],
        )

    def test_stage_status_supports_not_applicable_and_strict_failures(self) -> None:
        stage = StageResult(
            stage_id="production-apply",
            description="Production apply is outside the local-kind profile",
            status=StageStatus.NOT_APPLICABLE,
            start_time="2026-08-30T00:00:00Z",
            end_time="2026-08-30T00:00:00Z",
        )
        self.assertEqual(stage.to_dict()["status"], "NOT_APPLICABLE")

        with self.assertRaisesRegex(ValueError, "failure_reason"):
            StageResult(
                stage_id="build-once",
                description="Build image",
                status=StageStatus.FAILED,
                start_time="2026-08-30T00:00:00Z",
                end_time="2026-08-30T00:00:01Z",
            )

    def test_execution_run_serializes_complete_evidence(self) -> None:
        passed = StageResult(
            stage_id="build-once",
            description="Build and push exactly once",
            status=StageStatus.PASSED,
            start_time="2026-08-30T00:00:00Z",
            end_time="2026-08-30T00:00:01Z",
            command=("docker", "buildx", "build"),
            evidence_paths=("artifact.json",),
        )
        run = ExecutionRun(
            run_id="run-1",
            project_path=".",
            config_hash=HASH,
            template_lock_hash="f" * 64,
            source_revision=REVISION,
            start_time="2026-08-30T09:00:00+09:00",
            end_time="2026-08-30T00:01:00Z",
            execution_profile="kind-e2e",
            stage_results=(passed,),
            final_status=StageStatus.PASSED,
            tool_versions={
                "devops-stack-composer": "0.2.0",
                "docker": "28.0.0",
                "docker-buildx": "0.24.0",
                "syft": "1.30.0",
                "trivy": "0.66.0",
                "kind": "0.30.0",
                "kubectl": "1.33.0",
                "kubeconform": "0.7.0",
            },
            artifact_record=artifact(),
            supply_chain_evidence=supply_chain(),
            deployment_evidence=deployment(),
            source_repository="https://github.com/example/sample-app",
            template_revisions={
                "docker": "1" * 40,
                "jenkins": "2" * 40,
                "kubernetes": "3" * 40,
            },
            evidence_checksums={"artifact.json": "4" * 64},
        )

        value = json.loads(run.to_json())
        self.assertEqual(value["schemaVersion"], EXECUTION_EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(value["startTime"], "2026-08-30T00:00:00Z")
        self.assertEqual(value["artifact"]["buildInvocationCount"], 1)
        self.assertEqual(value["supplyChainEvidence"]["artifactDigest"], DIGEST)
        self.assertEqual(value["deploymentEvidence"]["finalDigest"], DIGEST)
        self.assertEqual(value["statusCounts"]["NOT_APPLICABLE"], 0)

    def test_run_rejects_absolute_paths_duplicate_stages_and_false_passes(self) -> None:
        passed = StageResult(
            "one",
            "first",
            StageStatus.PASSED,
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:00Z",
        )
        base = {
            "run_id": "run-1",
            "project_path": ".",
            "config_hash": HASH,
            "template_lock_hash": "f" * 64,
            "source_revision": REVISION,
            "start_time": "2026-08-30T00:00:00Z",
            "end_time": "2026-08-30T00:00:01Z",
            "execution_profile": "static",
            "stage_results": (passed,),
            "final_status": StageStatus.PASSED,
            "tool_versions": {},
            "schema_version": LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
        }
        with self.assertRaisesRegex(ValueError, "relative path"):
            ExecutionRun(**{**base, "project_path": "/home/alice/project"})
        with self.assertRaisesRegex(ValueError, "unique stage IDs"):
            ExecutionRun(**{**base, "stage_results": (passed, passed)})

        failed = StageResult(
            "two",
            "second",
            StageStatus.FAILED,
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:01Z",
            failure_reason="expected fixture failure",
        )
        with self.assertRaisesRegex(ValueError, "cannot have final_status PASSED"):
            ExecutionRun(**{**base, "stage_results": (failed,)})

    def test_legacy_run_preserves_the_exact_1_0_field_contract(self) -> None:
        stage = StageResult(
            "config-schema",
            "Validate configuration",
            StageStatus.PASSED,
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:00Z",
        )
        value = ExecutionRun(
            run_id="run-1",
            project_path=".",
            config_hash=HASH,
            template_lock_hash="f" * 64,
            source_revision=REVISION,
            start_time="2026-08-30T00:00:00Z",
            end_time="2026-08-30T00:00:01Z",
            execution_profile="static",
            stage_results=(stage,),
            final_status=StageStatus.PASSED,
            tool_versions={},
            schema_version=LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
        ).to_dict()

        self.assertEqual(value["schemaVersion"], "1.0.0")
        self.assertNotIn("sourceRepository", value)
        self.assertNotIn("templateRevisions", value)
        self.assertNotIn("evidenceChecksums", value)
        self.assertNotIn("evidenceChecksumPaths", value)
        self.assertNotIn("limitations", value)

    def test_current_run_requires_complete_metadata(self) -> None:
        stage = StageResult(
            "config-schema",
            "Validate configuration",
            StageStatus.PASSED,
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:00Z",
            tool="devops-stack-composer",
        )
        base = {
            "run_id": "run-1",
            "project_path": ".",
            "config_hash": HASH,
            "template_lock_hash": "f" * 64,
            "source_revision": REVISION,
            "start_time": "2026-08-30T00:00:00Z",
            "end_time": "2026-08-30T00:00:01Z",
            "execution_profile": "static",
            "stage_results": (stage,),
            "final_status": StageStatus.PASSED,
            "tool_versions": {"devops-stack-composer": "0.2.0"},
            "source_repository": "https://github.com/example/sample-app",
            "template_revisions": {
                "docker": "1" * 40,
                "jenkins": "2" * 40,
                "kubernetes": "3" * 40,
            },
            "evidence_checksums": {"config.json": "4" * 64},
        }

        ExecutionRun(**base)
        with self.assertRaisesRegex(ValueError, "exactly docker"):
            ExecutionRun(**{**base, "template_revisions": {"docker": "1" * 40}})
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            ExecutionRun(**{**base, "evidence_checksums": {}})
        with self.assertRaisesRegex(ValueError, "missing required tools"):
            ExecutionRun(**{**base, "tool_versions": {"docker": "28.0.0"}})
        failed = StageResult(
            "config-schema",
            "Validate configuration",
            StageStatus.FAILED,
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:00Z",
            tool="devops-stack-composer",
            failure_reason="validation failed",
        )
        with self.assertRaisesRegex(ValueError, "missing required tools"):
            ExecutionRun(
                **{
                    **base,
                    "execution_profile": "release",
                    "stage_results": (failed,),
                    "final_status": StageStatus.FAILED,
                    "failure_reason": "validation failed",
                }
            )
        with self.assertRaisesRegex(ValueError, "exact checksum manifests"):
            ExecutionRun(
                **{
                    **base,
                    "evidence_checksum_paths": ("inputs/Dockerfile",),
                }
            )
        with self.assertRaisesRegex(ValueError, "require a command or tool"):
            ExecutionRun(
                **{
                    **base,
                    "stage_results": (
                        StageResult(
                            "config-schema",
                            "Validate configuration",
                            StageStatus.PASSED,
                            "2026-08-30T00:00:00Z",
                            "2026-08-30T00:00:00Z",
                        ),
                    ),
                }
            )


if __name__ == "__main__":
    unittest.main()
