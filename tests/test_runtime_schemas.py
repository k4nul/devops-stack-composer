from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from jsonschema import Draft7Validator, FormatChecker, RefResolver
from jsonschema.exceptions import ValidationError

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


SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / "schemas"
SCHEMA_NAMES = (
    "execution-plan.schema.json",
    "execution-evidence.schema.json",
    "execution-report.schema.json",
)

DIGEST = "sha256:" + "a" * 64
PLATFORM_DIGEST = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
SOURCE_REVISION = "d" * 40
CONFIG_HASH = "e" * 64
TEMPLATE_LOCK_HASH = "f" * 64
IMAGE_REPOSITORY = "localhost:5000/team/app"
IMMUTABLE_IMAGE = f"{IMAGE_REPOSITORY}@{DIGEST}"


def load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIRECTORY / name).read_text(encoding="utf-8"))


def schema_validator(name: str) -> Draft7Validator:
    schemas = {schema_name: load_schema(schema_name) for schema_name in SCHEMA_NAMES}
    schema = schemas[name]
    store = {
        str(candidate["$id"]): candidate
        for candidate in schemas.values()
    }
    resolver = RefResolver.from_schema(schema, store=store)
    return Draft7Validator(
        schema,
        resolver=resolver,
        format_checker=FormatChecker(),
    )


def artifact_intent() -> ArtifactIntent:
    return ArtifactIntent(
        application_name="sample-app",
        registry="localhost:5000",
        repository="team/app",
        requested_tag="run-1",
        platforms=("linux/amd64", "linux/arm64/v8"),
        source_revision=SOURCE_REVISION,
        build_context=".",
        dockerfile="generated/docker/Dockerfile",
        template_revision="1" * 40,
        normalized_model_hash="2" * 64,
        build_arguments={"BUILD_MODE": "release"},
        target_stage="runtime",
    )


def execution_plan() -> ExecutionPlan:
    return ExecutionPlan.create(
        run_id="20260830T000000Z-012345abcdef",
        profile="kind-e2e",
        environment="staging",
        artifact_intent=artifact_intent(),
    )


def resolved_artifact() -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=IMMUTABLE_IMAGE,
        repository=IMAGE_REPOSITORY,
        tag="run-1",
        manifest_digest=DIGEST,
        platform_digest=PLATFORM_DIGEST,
        media_type="application/vnd.oci.image.manifest.v1+json",
        architecture="amd64",
        operating_system="linux",
        image_size=1024,
        config_digest=CONFIG_DIGEST,
        source_revision=SOURCE_REVISION,
        build_plan_hash=execution_plan().build_plan_hash,
        created_by_tool_version="0.2.0",
        registry_endpoint="localhost:5000",
        build_invocation_count=1,
    )


def supply_chain_evidence() -> SupplyChainEvidence:
    return SupplyChainEvidence(
        artifact_digest=DIGEST,
        sbom_path="sbom.spdx.json",
        sbom_format="spdx-json",
        sbom_hash="3" * 64,
        sbom_generator="syft 1.0.0",
        vulnerability_report_path="vulnerabilities.json",
        vulnerability_report_hash="4" * 64,
        scanner_name="trivy",
        scanner_version="1.2.3",
        scanner_database_metadata={"updatedAt": "2026-08-30T00:00:00Z"},
        policy_result={"passed": True, "violations": 0},
        provenance_path="provenance.json",
        provenance_hash="5" * 64,
        provenance_type="https://slsa.dev/provenance/v1",
        attestation_subject=IMMUTABLE_IMAGE,
        verification_status=(
            "CHECKSUM_ONLY_FILE_EVIDENCE:signature=false,attachment=false,crypto=false"
        ),
        evidence_generation_time="2026-08-30T09:00:00+09:00",
    )


def deployment_evidence() -> DeploymentEvidence:
    return DeploymentEvidence(
        environment="staging",
        namespace="sample-staging",
        cluster_type="kind",
        cluster_identifier="devops-stack-run-1",
        manifest_hash="6" * 64,
        deployed_image_reference=IMMUTABLE_IMAGE,
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


def execution_run() -> ExecutionRun:
    passed = StageResult(
        stage_id="build-once",
        description="Build and push exactly once",
        status=StageStatus.PASSED,
        start_time="2026-08-30T09:00:00+09:00",
        end_time="2026-08-30T00:00:01Z",
        command=("docker", "buildx", "build"),
        tool="docker",
        sanitized_output="built immutable image",
        evidence_paths=("artifact.json",),
    )
    not_applicable = StageResult(
        stage_id="production-apply",
        description="Production apply is outside this staging run",
        status=StageStatus.NOT_APPLICABLE,
        start_time="2026-08-30T00:00:01Z",
        end_time="2026-08-30T00:00:01Z",
    )
    return ExecutionRun(
        run_id="20260830T000000Z-012345abcdef",
        project_path=".",
        config_hash=CONFIG_HASH,
        template_lock_hash=TEMPLATE_LOCK_HASH,
        source_revision=SOURCE_REVISION,
        start_time="2026-08-30T09:00:00+09:00",
        end_time="2026-08-30T00:01:00Z",
        execution_profile="kind-e2e",
        stage_results=(passed, not_applicable),
        final_status=StageStatus.PASSED,
        tool_versions={"docker": "28.0.0", "kind": "0.30.0"},
        artifact_record=resolved_artifact(),
        supply_chain_evidence=supply_chain_evidence(),
        deployment_evidence=deployment_evidence(),
    )


class RuntimeSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan_validator = schema_validator("execution-plan.schema.json")
        cls.evidence_validator = schema_validator("execution-evidence.schema.json")
        cls.report_validator = schema_validator("execution-report.schema.json")

    def assert_invalid(
        self,
        validator: Draft7Validator,
        value: dict[str, object],
    ) -> None:
        with self.assertRaises(ValidationError):
            validator.validate(value)

    def test_runtime_schemas_are_valid_draft_7_schemas(self) -> None:
        for name in SCHEMA_NAMES:
            with self.subTest(schema=name):
                schema = load_schema(name)
                self.assertEqual(
                    schema["$schema"],
                    "http://json-schema.org/draft-07/schema#",
                )
                Draft7Validator.check_schema(schema)

    def test_execution_plan_domain_serialization_validates(self) -> None:
        value = execution_plan().to_dict()

        self.plan_validator.validate(value)

        self.assertEqual(value["artifactIntent"], artifact_intent().to_dict())

    def test_execution_evidence_and_report_domain_serialization_validate(self) -> None:
        value = execution_run().to_dict()

        self.evidence_validator.validate(value)
        self.report_validator.validate(value)

        self.assertEqual(value["statusCounts"]["NOT_APPLICABLE"], 1)
        self.assertEqual(
            load_schema("execution-report.schema.json")["title"],
            "DevOps Stack durable execution report",
        )

        value["unexpected"] = True
        self.assert_invalid(self.report_validator, value)

    def test_unknown_fields_are_rejected_at_domain_record_boundaries(self) -> None:
        plan_cases = []
        root_plan = execution_plan().to_dict()
        root_plan["unexpected"] = True
        plan_cases.append(root_plan)
        intent_plan = execution_plan().to_dict()
        intent_plan["artifactIntent"]["unexpected"] = True
        plan_cases.append(intent_plan)
        stage_plan = execution_plan().to_dict()
        stage_plan["stages"][0]["unexpected"] = True
        plan_cases.append(stage_plan)

        for value in plan_cases:
            with self.subTest(record="execution-plan"):
                self.assert_invalid(self.plan_validator, value)

        evidence_paths = (
            (),
            ("stageResults", 0),
            ("statusCounts",),
            ("artifact",),
            ("supplyChainEvidence",),
            ("deploymentEvidence",),
        )
        for path in evidence_paths:
            value = execution_run().to_dict()
            target: object = value
            for part in path:
                target = target[part]  # type: ignore[index]
            target["unexpected"] = True  # type: ignore[index]
            with self.subTest(record="execution-evidence", path=path):
                self.assert_invalid(self.evidence_validator, value)

    def test_tampered_status_hash_git_path_and_time_values_are_rejected(self) -> None:
        mutations = (
            (("finalStatus",), "SUCCESS"),
            (("configHash",), "E" * 64),
            (("sourceRevision",), "d" * 39),
            (("projectPath",), "/tmp/project"),
            (("stageResults", 0, "evidencePaths", 0), "../artifact.json"),
            (("stageResults", 0, "evidencePaths", 0), "artifacts/"),
            (("stageResults", 0, "startTime"), "2026-08-30T00:00:00"),
            (("supplyChainEvidence", "sbomHash"), "sha256:" + "3" * 64),
            (("deploymentEvidence", "manifestHash"), "6" * 63),
        )

        for path, replacement in mutations:
            value = execution_run().to_dict()
            target: object = value
            for part in path[:-1]:
                target = target[part]  # type: ignore[index]
            target[path[-1]] = replacement  # type: ignore[index]
            with self.subTest(path=path):
                self.assert_invalid(self.evidence_validator, value)

    def test_failed_statuses_require_a_failure_reason(self) -> None:
        value = execution_run().to_dict()
        value["stageResults"][0]["status"] = "FAILED"
        value["stageResults"][0]["failureReason"] = None
        self.assert_invalid(self.evidence_validator, value)

        value = execution_run().to_dict()
        value["finalStatus"] = "BLOCKED_MISSING_REQUIRED_TOOL"
        value["failureReason"] = None
        self.assert_invalid(self.evidence_validator, value)

    def test_mutable_image_references_are_rejected_from_evidence(self) -> None:
        mutations = (
            ("artifact", "immutableImageReference", f"{IMAGE_REPOSITORY}:latest"),
            ("supplyChainEvidence", "attestationSubject", f"{IMAGE_REPOSITORY}:latest"),
            ("deploymentEvidence", "deployedImageReference", f"{IMAGE_REPOSITORY}:latest"),
            (
                "deploymentEvidence",
                "actualPodImageId",
                f"containerd://{IMAGE_REPOSITORY}:latest",
            ),
        )

        original = execution_run().to_dict()
        for record, field, mutable_reference in mutations:
            value = deepcopy(original)
            value[record][field] = mutable_reference
            with self.subTest(record=record, field=field):
                self.assert_invalid(self.evidence_validator, value)


if __name__ == "__main__":
    unittest.main()
