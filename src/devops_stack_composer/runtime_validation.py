"""Offline semantic verification for execution plans and durable evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Any

from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.evidence_validation import (
    ArtifactVerification,
    validate_artifact_contract,
)
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
from devops_stack_composer.policies import ValidationProfile, profile_policy
from devops_stack_composer.report import redact_sensitive
from devops_stack_composer.resources import schema_path


MAX_RUNTIME_JSON_BYTES = 4 * 1024 * 1024
MAX_STAGE_CAPTURE_BYTES = 16_384
MAX_STAGE_COMMAND_ARGUMENTS = 128


class RuntimeValidationError(DevOpsStackError):
    """A stable fail-closed error raised for invalid runtime evidence."""

    def __init__(self, code: str, message: str, *, evidence_path: str | None = None):
        self.code = code
        self.evidence_path = evidence_path
        suffix = f"; evidence: {evidence_path}" if evidence_path else ""
        super().__init__(f"{code}: {message}{suffix}")


@dataclass(frozen=True)
class RuntimeVerification:
    """Safe summary returned after all schema and semantic gates pass."""

    run_id: str
    profile: str
    build_plan_hash: str
    final_status: str
    stage_count: int
    incomplete: bool
    authoritative_digest: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": True,
            "runId": self.run_id,
            "profile": self.profile,
            "buildPlanHash": self.build_plan_hash,
            "finalStatus": self.final_status,
            "stageCount": self.stage_count,
            "incomplete": self.incomplete,
            "authoritativeDigest": self.authoritative_digest,
        }


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink():
        raise RuntimeValidationError(
            "RUNTIME_FILE_INVALID",
            f"{label} must be a regular non-symlink file",
            evidence_path=str(path),
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeValidationError(
            "RUNTIME_FILE_INVALID",
            f"cannot open {label} as a regular non-symlink file",
            evidence_path=str(path),
        ) from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeValidationError(
                    "RUNTIME_FILE_INVALID",
                    f"{label} must be a regular file",
                    evidence_path=str(path),
                )
            if metadata.st_size > MAX_RUNTIME_JSON_BYTES:
                raise RuntimeValidationError(
                    "RUNTIME_FILE_TOO_LARGE",
                    f"{label} exceeds the {MAX_RUNTIME_JSON_BYTES}-byte limit",
                    evidence_path=str(path),
                )
            payload = stream.read(MAX_RUNTIME_JSON_BYTES + 1)
    except RuntimeValidationError:
        raise
    except OSError as exc:
        raise RuntimeValidationError(
            "RUNTIME_FILE_INVALID",
            f"cannot read {label}",
            evidence_path=str(path),
        ) from exc
    if len(payload) > MAX_RUNTIME_JSON_BYTES:
        raise RuntimeValidationError(
            "RUNTIME_FILE_TOO_LARGE",
            f"{label} exceeds the {MAX_RUNTIME_JSON_BYTES}-byte limit",
            evidence_path=str(path),
        )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError) as exc:
        raise RuntimeValidationError(
            "RUNTIME_FILE_INVALID",
            f"{label} is not strict JSON: {exc}",
            evidence_path=str(path),
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeValidationError(
            "RUNTIME_FILE_INVALID",
            f"{label} must contain one JSON object",
            evidence_path=str(path),
        )
    return value


def _load_schema(name: str) -> dict[str, Any]:
    path = schema_path(name)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeValidationError(
            "RUNTIME_SCHEMA_UNAVAILABLE",
            f"packaged schema {name} cannot be loaded",
            evidence_path=name,
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeValidationError(
            "RUNTIME_SCHEMA_UNAVAILABLE",
            f"packaged schema {name} is not an object",
            evidence_path=name,
        )
    try:
        Draft7Validator.check_schema(value)
    except SchemaError as exc:
        raise RuntimeValidationError(
            "RUNTIME_SCHEMA_UNAVAILABLE",
            f"packaged schema {name} is invalid",
            evidence_path=name,
        ) from exc
    return value


def _json_path(parts: Sequence[object]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def _validate_schema(value: Mapping[str, Any], name: str) -> None:
    validator = Draft7Validator(_load_schema(name), format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (_json_path(tuple(error.absolute_path)), error.message),
    )
    if errors:
        error = errors[0]
        path = _json_path(tuple(error.absolute_path))
        raise RuntimeValidationError(
            "RUNTIME_SCHEMA_INVALID",
            f"{name} rejects {path}: {error.message}",
            evidence_path=path,
        )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):  # Schema validation should make this unreachable.
        raise RuntimeValidationError("RUNTIME_RECORD_INVALID", f"{name} must be an object")
    return value


def _artifact_intent(value: Mapping[str, Any]) -> ArtifactIntent:
    return ArtifactIntent(
        application_name=value["applicationName"],
        registry=value["registry"],
        repository=value["repository"],
        requested_tag=value["requestedTag"],
        platforms=tuple(value["platforms"]),
        source_revision=value["sourceRevision"],
        build_context=value["buildContext"],
        dockerfile=value["dockerfile"],
        build_arguments=value["buildArguments"],
        target_stage=value["targetStage"],
        template_revision=value["templateRevision"],
        normalized_model_hash=value["normalizedModelHash"],
    )


def _execution_plan(value: Mapping[str, Any]) -> ExecutionPlan:
    try:
        plan = ExecutionPlan.create(
            run_id=value["runId"],
            profile=value["profile"],
            environment=value["environment"],
            artifact_intent=_artifact_intent(_mapping(value["artifactIntent"], "artifactIntent")),
            production_apply_approved=value["productionApplyApproved"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeValidationError(
            "PLAN_RECORD_INVALID", str(exc), evidence_path="plan.json"
        ) from exc
    expected_stages = [stage.to_dict() for stage in plan.stages]
    if value["stages"] != expected_stages:
        raise RuntimeValidationError(
            "PLAN_STAGE_ORDER_MISMATCH",
            "planned stages must exactly match the selected profile order and descriptions",
            evidence_path="plan.json",
        )
    if value["buildPlanHash"] != plan.build_plan_hash:
        raise RuntimeValidationError(
            "PLAN_HASH_MISMATCH",
            f"plan records {value['buildPlanHash']}, recomputed {plan.build_plan_hash}",
            evidence_path="plan.json",
        )
    return plan


def _resolved_artifact(value: Mapping[str, Any]) -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=value["immutableImageReference"],
        repository=value["repository"],
        tag=value["tag"],
        manifest_digest=value["manifestDigest"],
        platform_digest=value["platformDigest"],
        media_type=value["mediaType"],
        architecture=value["architecture"],
        operating_system=value["operatingSystem"],
        image_size=value["imageSize"],
        config_digest=value["configDigest"],
        source_revision=value["sourceRevision"],
        build_plan_hash=value["buildPlanHash"],
        created_by_tool_version=value["createdByToolVersion"],
        registry_endpoint=value["registryEndpoint"],
        build_invocation_count=value["buildInvocationCount"],
    )


def _supply_chain(value: Mapping[str, Any]) -> SupplyChainEvidence:
    return SupplyChainEvidence(
        artifact_digest=value["artifactDigest"],
        sbom_path=value["sbomPath"],
        sbom_format=value["sbomFormat"],
        sbom_hash=value["sbomHash"],
        sbom_generator=value["sbomGenerator"],
        vulnerability_report_path=value["vulnerabilityReportPath"],
        vulnerability_report_hash=value["vulnerabilityReportHash"],
        scanner_name=value["scannerName"],
        scanner_version=value["scannerVersion"],
        scanner_database_metadata=value["scannerDatabaseMetadata"],
        policy_result=value["policyResult"],
        provenance_path=value["provenancePath"],
        provenance_hash=value["provenanceHash"],
        provenance_type=value["provenanceType"],
        attestation_subject=value["attestationSubject"],
        verification_status=value["verificationStatus"],
        evidence_generation_time=value["evidenceGenerationTime"],
    )


def _deployment(value: Mapping[str, Any]) -> DeploymentEvidence:
    return DeploymentEvidence(
        environment=value["environment"],
        namespace=value["namespace"],
        cluster_type=value["clusterType"],
        cluster_identifier=value["clusterIdentifier"],
        manifest_hash=value["manifestHash"],
        deployed_image_reference=value["deployedImageReference"],
        expected_digest=value["expectedDigest"],
        actual_pod_image_id=value["actualPodImageId"],
        rollout_status=value["rolloutStatus"],
        ready_replica_count=value["readyReplicaCount"],
        health_endpoint_result=value["healthEndpointResult"],
        readiness_endpoint_result=value["readinessEndpointResult"],
        rollback_attempted=value["rollbackAttempted"],
        rollback_result=value["rollbackResult"],
        final_revision=value["finalRevision"],
        final_digest=value["finalDigest"],
        diagnostics_paths=tuple(value["diagnosticsPaths"]),
    )


def _stage(value: Mapping[str, Any]) -> StageResult:
    return StageResult(
        stage_id=value["stageId"],
        description=value["description"],
        status=StageStatus(value["status"]),
        start_time=value["startTime"],
        end_time=value["endTime"],
        command=tuple(value["command"]),
        tool=value["tool"],
        sanitized_output=value["sanitizedOutput"],
        evidence_paths=tuple(value["evidencePaths"]),
        failure_reason=value["failureReason"],
        remediation=value["remediation"],
    )


def _execution_run(value: Mapping[str, Any]) -> ExecutionRun:
    try:
        artifact_value = value["artifact"]
        supply_value = value["supplyChainEvidence"]
        deployment_value = value["deploymentEvidence"]
        return ExecutionRun(
            run_id=value["runId"],
            project_path=value["projectPath"],
            config_hash=value["configHash"],
            template_lock_hash=value["templateLockHash"],
            source_revision=value["sourceRevision"],
            start_time=value["startTime"],
            end_time=value["endTime"],
            execution_profile=value["executionProfile"],
            stage_results=tuple(
                _stage(_mapping(stage, "stageResults item"))
                for stage in value["stageResults"]
            ),
            final_status=StageStatus(value["finalStatus"]),
            tool_versions=value["toolVersions"],
            artifact_record=(
                _resolved_artifact(_mapping(artifact_value, "artifact"))
                if artifact_value is not None
                else None
            ),
            supply_chain_evidence=(
                _supply_chain(_mapping(supply_value, "supplyChainEvidence"))
                if supply_value is not None
                else None
            ),
            deployment_evidence=(
                _deployment(_mapping(deployment_value, "deploymentEvidence"))
                if deployment_value is not None
                else None
            ),
            failure_reason=value["failureReason"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeValidationError(
            "EVIDENCE_RECORD_INVALID", str(exc), evidence_path="run.json"
        ) from exc


def _validate_stage_capture(stage: StageResult) -> None:
    if len(stage.command) > MAX_STAGE_COMMAND_ARGUMENTS:
        raise RuntimeValidationError(
            "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            f"stage {stage.stage_id} records too many command arguments",
            evidence_path="run.json",
        )
    command_text = " ".join(stage.command)
    if len(command_text.encode("utf-8")) > MAX_STAGE_CAPTURE_BYTES:
        raise RuntimeValidationError(
            "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            f"stage {stage.stage_id} command exceeds the evidence limit",
            evidence_path="run.json",
        )
    if redact_sensitive(command_text) != command_text:
        raise RuntimeValidationError(
            "EVIDENCE_SECRET_EXPOSURE",
            f"stage {stage.stage_id} command contains unredacted sensitive data",
            evidence_path="run.json",
        )
    output = stage.sanitized_output or ""
    if len(output.encode("utf-8")) > MAX_STAGE_CAPTURE_BYTES:
        raise RuntimeValidationError(
            "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            f"stage {stage.stage_id} output exceeds the evidence limit",
            evidence_path="run.json",
        )
    if redact_sensitive(output) != output:
        raise RuntimeValidationError(
            "EVIDENCE_SECRET_EXPOSURE",
            f"stage {stage.stage_id} output contains unredacted sensitive data",
            evidence_path="run.json",
        )


def _validate_final_status(run: ExecutionRun) -> None:
    statuses = tuple(stage.status for stage in run.stage_results)
    if run.final_status == StageStatus.PASSED:
        if any(status != StageStatus.PASSED for status in statuses):
            raise RuntimeValidationError(
                "FINAL_STATUS_INCONSISTENT",
                "a successful run requires every planned stage to pass",
                evidence_path="run.json",
            )
        return
    if run.final_status == StageStatus.FAILED:
        if StageStatus.FAILED not in statuses:
            raise RuntimeValidationError(
                "FINAL_STATUS_INCONSISTENT",
                "FAILED final status requires a failed stage",
                evidence_path="run.json",
            )
        return
    if run.final_status == StageStatus.BLOCKED_MISSING_REQUIRED_TOOL:
        if (
            StageStatus.FAILED in statuses
            or StageStatus.BLOCKED_MISSING_REQUIRED_TOOL not in statuses
        ):
            raise RuntimeValidationError(
                "FINAL_STATUS_INCONSISTENT",
                "blocked final status requires a blocked stage and no failed stage",
                evidence_path="run.json",
            )
        return
    raise RuntimeValidationError(
        "FINAL_STATUS_INCONSISTENT",
        f"{run.final_status.value} is not a terminal run status",
        evidence_path="run.json",
    )


def _validate_stage_sequence(plan: ExecutionPlan, run: ExecutionRun) -> bool:
    planned_ids = tuple(stage.stage_id for stage in plan.stages)
    evidence_ids = tuple(stage.stage_id for stage in run.stage_results)
    if run.final_status == StageStatus.PASSED:
        if evidence_ids != planned_ids:
            raise RuntimeValidationError(
                "REQUIRED_STAGE_MISMATCH",
                "successful evidence must contain every planned stage in exact order",
            )
        return False
    if evidence_ids != planned_ids[: len(evidence_ids)]:
        raise RuntimeValidationError(
            "REQUIRED_STAGE_MISMATCH",
            "failed evidence stages must be an exact ordered prefix of the plan",
        )
    terminal_status = {
        StageStatus.FAILED: StageStatus.FAILED,
        StageStatus.BLOCKED_MISSING_REQUIRED_TOOL: (
            StageStatus.BLOCKED_MISSING_REQUIRED_TOOL
        ),
    }.get(run.final_status)
    if terminal_status is None:
        return True
    if not run.stage_results or run.stage_results[-1].status != terminal_status:
        raise RuntimeValidationError(
            "FINAL_STATUS_INCONSISTENT",
            "failed evidence must end at the stage that set the final status",
            evidence_path="run.json",
        )
    if any(
        stage.status != StageStatus.PASSED for stage in run.stage_results[:-1]
    ):
        raise RuntimeValidationError(
            "FINAL_STATUS_INCONSISTENT",
            "every stage before the terminal failure must have passed",
            evidence_path="run.json",
        )
    return True


def _validate_evidence_requirements(plan: ExecutionPlan, run: ExecutionRun) -> None:
    profile = plan.profile
    artifact = run.artifact_record
    supply = run.supply_chain_evidence
    deployment = run.deployment_evidence
    if supply is not None and artifact is None:
        raise RuntimeValidationError(
            "ORPHAN_EVIDENCE", "supply-chain evidence has no artifact record"
        )
    if deployment is not None and (artifact is None or supply is None):
        raise RuntimeValidationError(
            "ORPHAN_EVIDENCE",
            "deployment evidence requires artifact and supply-chain evidence",
        )
    if profile == ValidationProfile.STATIC and any(
        item is not None for item in (artifact, supply, deployment)
    ):
        raise RuntimeValidationError(
            "PROFILE_EVIDENCE_UNEXPECTED",
            "static profile cannot claim build or deployment evidence",
        )
    if profile == ValidationProfile.SUPPLY_CHAIN and deployment is not None:
        raise RuntimeValidationError(
            "PROFILE_EVIDENCE_UNEXPECTED",
            "supply-chain profile cannot claim unplanned deployment evidence",
        )
    if run.final_status == StageStatus.PASSED:
        if profile != ValidationProfile.STATIC and artifact is None:
            raise RuntimeValidationError(
                "REQUIRED_EVIDENCE_MISSING", "successful profile requires artifact evidence"
            )
        if profile in {
            ValidationProfile.SUPPLY_CHAIN,
            ValidationProfile.KIND_E2E,
            ValidationProfile.RELEASE,
        } and supply is None:
            raise RuntimeValidationError(
                "REQUIRED_EVIDENCE_MISSING",
                "successful profile requires supply-chain evidence",
            )
        if profile in {ValidationProfile.KIND_E2E, ValidationProfile.RELEASE}:
            if deployment is None:
                raise RuntimeValidationError(
                    "REQUIRED_EVIDENCE_MISSING",
                    "successful profile requires deployment evidence",
                )
    if (
        run.final_status == StageStatus.PASSED
        and supply is not None
        and supply.policy_result.get("passed") is not True
    ):
        raise RuntimeValidationError(
            "SUPPLY_CHAIN_POLICY_FAILED",
            "supply-chain policy evidence does not record an exact passed=true result",
        )
    if deployment is not None:
        if deployment.environment != plan.environment or deployment.cluster_type != "kind":
            raise RuntimeValidationError(
                "DEPLOYMENT_EVIDENCE_INVALID",
                "deployment environment or cluster type differs from the plan",
            )
        checks = (
            deployment.rollout_status == "PASSED",
            deployment.ready_replica_count > 0,
            deployment.health_endpoint_result.get("status") == 200,
            deployment.readiness_endpoint_result.get("status") == 200,
            deployment.rollback_attempted,
            deployment.rollback_result == "PASSED",
        )
        if run.final_status == StageStatus.PASSED and not all(checks):
            raise RuntimeValidationError(
                "DEPLOYMENT_EVIDENCE_INVALID",
                "successful kind evidence must prove rollout, readiness, smoke, and rollback",
            )


def _verify_artifact_identity(
    plan: ExecutionPlan,
    run: ExecutionRun,
) -> ArtifactVerification | None:
    artifact = run.artifact_record
    if artifact is None:
        return None
    if artifact.build_plan_hash != plan.build_plan_hash:
        raise RuntimeValidationError(
            "BUILD_PLAN_HASH_MISMATCH",
            "artifact was not produced from the verified execution plan",
            evidence_path="run.json",
        )
    if artifact.source_revision != run.source_revision:
        raise RuntimeValidationError(
            "SOURCE_REVISION_MISMATCH",
            "artifact source revision differs from the execution run",
            evidence_path="run.json",
        )
    require_platform_identity = plan.profile in {
        ValidationProfile.KIND_E2E,
        ValidationProfile.RELEASE,
    }
    if require_platform_identity and artifact.manifest_digest != artifact.platform_digest:
        raise RuntimeValidationError(
            "KIND_PLATFORM_DIGEST_MISMATCH",
            "v0.2 kind execution requires manifest and selected platform digests to match",
            evidence_path="run.json",
        )
    return validate_artifact_contract(
        artifact,
        run.supply_chain_evidence,
        run.deployment_evidence,
        require_platform_identity=require_platform_identity,
    )


def validate_runtime_records(
    plan_value: Mapping[str, Any],
    evidence_value: Mapping[str, Any],
) -> RuntimeVerification:
    """Validate two already-loaded runtime records without network or subprocesses."""

    _validate_schema(plan_value, "execution-plan.schema.json")
    _validate_schema(evidence_value, "execution-evidence.schema.json")
    plan = _execution_plan(plan_value)
    run = _execution_run(evidence_value)

    if run.run_id != plan.run_id:
        raise RuntimeValidationError("RUN_ID_MISMATCH", "plan and evidence run IDs differ")
    if run.execution_profile != plan.profile.value:
        raise RuntimeValidationError(
            "PROFILE_MISMATCH", "plan and evidence profiles differ"
        )
    if run.source_revision != plan.artifact_intent.source_revision:
        raise RuntimeValidationError(
            "SOURCE_REVISION_MISMATCH", "plan and evidence source revisions differ"
        )
    _validate_final_status(run)
    incomplete = _validate_stage_sequence(plan, run)
    for planned, actual in zip(plan.stages, run.stage_results):
        if planned.description != actual.description:
            raise RuntimeValidationError(
                "REQUIRED_STAGE_MISMATCH",
                f"evidence description differs for stage {planned.stage_id}",
            )
        _validate_stage_capture(actual)
    if evidence_value["statusCounts"] != run.status_counts:
        raise RuntimeValidationError(
            "STATUS_COUNTS_MISMATCH", "recorded status counts do not match stage results"
        )
    if run.final_status == StageStatus.PASSED:
        failures = profile_policy(plan.profile).required_stage_failures(run.stage_results)
        if failures:
            raise RuntimeValidationError(
                "REQUIRED_STAGE_NOT_PASSED",
                "successful run has non-passing required stages: "
                + ", ".join(f"{key}={value}" for key, value in sorted(failures.items())),
            )
    _validate_evidence_requirements(plan, run)
    verification = _verify_artifact_identity(plan, run)
    return RuntimeVerification(
        run_id=run.run_id,
        profile=plan.profile.value,
        build_plan_hash=plan.build_plan_hash,
        final_status=run.final_status.value,
        stage_count=len(run.stage_results),
        incomplete=incomplete,
        authoritative_digest=(
            verification.authoritative_digest if verification is not None else None
        ),
    )


def validate_runtime_files(plan_path: Path, evidence_path: Path) -> RuntimeVerification:
    """Load strict JSON files and perform complete offline runtime verification."""

    return validate_runtime_records(
        _read_json_object(Path(plan_path), label="execution plan"),
        _read_json_object(Path(evidence_path), label="execution evidence"),
    )


__all__ = [
    "MAX_RUNTIME_JSON_BYTES",
    "MAX_STAGE_CAPTURE_BYTES",
    "MAX_STAGE_COMMAND_ARGUMENTS",
    "RuntimeValidationError",
    "RuntimeVerification",
    "validate_runtime_files",
    "validate_runtime_records",
]
