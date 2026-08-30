"""Immutable domain records for build-once execution evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping

from devops_stack_composer.oci import (
    digest_from_image_id,
    digest_from_subject,
    parse_digest,
    parse_oci_reference,
    validate_registry,
    validate_repository,
    validate_sha256_hex,
    validate_tag,
)


_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PLATFORM = re.compile(r"^[a-z0-9]+/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?$")
_TOOL_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+.-][A-Za-z0-9.-]+)?$")


def _nonempty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError(f"{name} must not contain surrounding whitespace or control characters")
    return value


def _identifier(name: str, value: str) -> str:
    value = _nonempty(name, value)
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must use lowercase identifier syntax")
    return value


def _git_revision(name: str, value: str) -> str:
    value = _nonempty(name, value)
    if not _GIT_REVISION.fullmatch(value):
        raise ValueError(f"{name} must be a full 40-character lowercase Git commit")
    return value


def _relative_path(name: str, value: str, *, allow_dot: bool = False) -> str:
    value = _nonempty(name, value)
    if "\\" in value:
        raise ValueError(f"{name} must use POSIX separators")
    if value == ".":
        if allow_dot:
            return value
        raise ValueError(f"{name} must name a file or directory below the run root")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"{name} must be a normalized relative path")
    return value


def _timestamp(name: str, value: str) -> str:
    value = _nonempty(name, value)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    utc = parsed.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds")
    return rendered.replace("+00:00", "Z")


def _ordered_json_mapping(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    if any(not isinstance(key, str) or not key for key in value):
        raise ValueError(f"{name} keys must be non-empty strings")
    try:
        encoded = json.dumps(dict(value), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain JSON-compatible finite values") from exc
    decoded = json.loads(encoded)
    return {key: decoded[key] for key in sorted(decoded)}


def _string_mapping(name: str, value: Mapping[str, str]) -> dict[str, str]:
    normalized = _ordered_json_mapping(name, value)
    if any(not isinstance(item, str) for item in normalized.values()):
        raise ValueError(f"{name} values must be strings")
    return normalized


class StageStatus(str, Enum):
    """Execution status compatible with existing validation statuses."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED_MISSING_OPTIONAL_TOOL = "SKIPPED_MISSING_OPTIONAL_TOOL"
    BLOCKED_MISSING_REQUIRED_TOOL = "BLOCKED_MISSING_REQUIRED_TOOL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ArtifactIntent:
    """The deterministic build request before an image digest exists."""

    application_name: str
    registry: str
    repository: str
    requested_tag: str
    platforms: tuple[str, ...]
    source_revision: str
    build_context: str
    dockerfile: str
    template_revision: str
    normalized_model_hash: str
    build_arguments: Mapping[str, str] = field(default_factory=dict)
    target_stage: str | None = None

    def __post_init__(self) -> None:
        _identifier("application_name", self.application_name)
        validate_registry(self.registry)
        validate_repository(self.repository)
        validate_tag(self.requested_tag)
        parse_oci_reference(f"{self.registry}/{self.repository}:{self.requested_tag}")
        platforms = tuple(self.platforms)
        if not platforms or len(set(platforms)) != len(platforms):
            raise ValueError("platforms must contain unique values")
        if any(
            not isinstance(platform, str) or not _PLATFORM.fullmatch(platform)
            for platform in platforms
        ):
            raise ValueError("platforms must use os/architecture[/variant] syntax")
        object.__setattr__(self, "platforms", platforms)
        _git_revision("source_revision", self.source_revision)
        _relative_path("build_context", self.build_context, allow_dot=True)
        _relative_path("dockerfile", self.dockerfile)
        _git_revision("template_revision", self.template_revision)
        validate_sha256_hex(self.normalized_model_hash)
        object.__setattr__(
            self,
            "build_arguments",
            _string_mapping("build_arguments", self.build_arguments),
        )
        if self.target_stage is not None:
            _identifier("target_stage", self.target_stage)

    @property
    def image_reference(self) -> str:
        return f"{self.registry}/{self.repository}:{self.requested_tag}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicationName": self.application_name,
            "registry": self.registry,
            "repository": self.repository,
            "requestedTag": self.requested_tag,
            "platforms": list(self.platforms),
            "sourceRevision": self.source_revision,
            "buildContext": self.build_context,
            "dockerfile": self.dockerfile,
            "buildArguments": dict(self.build_arguments),
            "targetStage": self.target_stage,
            "templateRevision": self.template_revision,
            "normalizedModelHash": self.normalized_model_hash,
        }


@dataclass(frozen=True)
class ResolvedArtifact:
    """Registry-resolved immutable identity produced by one build invocation."""

    immutable_image_reference: str
    repository: str
    tag: str
    manifest_digest: str
    platform_digest: str
    media_type: str
    architecture: str
    operating_system: str
    image_size: int
    config_digest: str
    source_revision: str
    build_plan_hash: str
    created_by_tool_version: str
    registry_endpoint: str
    build_invocation_count: int

    def __post_init__(self) -> None:
        reference = parse_oci_reference(self.immutable_image_reference)
        if reference.digest is None or reference.tag is not None:
            raise ValueError(
                "immutable_image_reference must use repository@sha256:digest without a tag"
            )
        validate_repository(self.repository)
        if reference.repository != self.repository:
            raise ValueError("immutable_image_reference repository does not match repository")
        manifest_digest = parse_digest(self.manifest_digest)
        if reference.digest != manifest_digest:
            raise ValueError("immutable_image_reference digest does not match manifest_digest")
        validate_tag(self.tag)
        parse_digest(self.platform_digest)
        parse_digest(self.config_digest)
        _nonempty("media_type", self.media_type)
        _nonempty("architecture", self.architecture)
        _nonempty("operating_system", self.operating_system)
        if (
            isinstance(self.image_size, bool)
            or not isinstance(self.image_size, int)
            or self.image_size < 0
        ):
            raise ValueError("image_size must be a non-negative integer")
        _git_revision("source_revision", self.source_revision)
        validate_sha256_hex(self.build_plan_hash)
        if not _TOOL_VERSION.fullmatch(
            _nonempty("created_by_tool_version", self.created_by_tool_version)
        ):
            raise ValueError("created_by_tool_version must be a semantic version")
        validate_registry(self.registry_endpoint)
        if (
            isinstance(self.build_invocation_count, bool)
            or not isinstance(self.build_invocation_count, int)
            or self.build_invocation_count < 1
        ):
            raise ValueError("build_invocation_count must be a positive integer")

    @property
    def digest(self) -> str:
        return self.manifest_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "immutableImageReference": self.immutable_image_reference,
            "repository": self.repository,
            "tag": self.tag,
            "manifestDigest": self.manifest_digest,
            "platformDigest": self.platform_digest,
            "mediaType": self.media_type,
            "architecture": self.architecture,
            "operatingSystem": self.operating_system,
            "imageSize": self.image_size,
            "configDigest": self.config_digest,
            "sourceRevision": self.source_revision,
            "buildPlanHash": self.build_plan_hash,
            "createdByToolVersion": self.created_by_tool_version,
            "registryEndpoint": self.registry_endpoint,
            "buildInvocationCount": self.build_invocation_count,
        }


@dataclass(frozen=True)
class SupplyChainEvidence:
    """SBOM, vulnerability, and provenance evidence for one OCI subject."""

    artifact_digest: str
    sbom_path: str
    sbom_format: str
    sbom_hash: str
    sbom_generator: str
    vulnerability_report_path: str
    vulnerability_report_hash: str
    scanner_name: str
    scanner_version: str
    scanner_database_metadata: Mapping[str, Any]
    policy_result: Mapping[str, Any]
    provenance_path: str
    provenance_hash: str
    provenance_type: str
    attestation_subject: str
    verification_status: str
    evidence_generation_time: str

    def __post_init__(self) -> None:
        parse_digest(self.artifact_digest)
        _relative_path("sbom_path", self.sbom_path)
        _nonempty("sbom_format", self.sbom_format)
        validate_sha256_hex(self.sbom_hash)
        _nonempty("sbom_generator", self.sbom_generator)
        _relative_path("vulnerability_report_path", self.vulnerability_report_path)
        validate_sha256_hex(self.vulnerability_report_hash)
        _nonempty("scanner_name", self.scanner_name)
        _nonempty("scanner_version", self.scanner_version)
        object.__setattr__(
            self,
            "scanner_database_metadata",
            _ordered_json_mapping("scanner_database_metadata", self.scanner_database_metadata),
        )
        object.__setattr__(
            self,
            "policy_result",
            _ordered_json_mapping("policy_result", self.policy_result),
        )
        _relative_path("provenance_path", self.provenance_path)
        validate_sha256_hex(self.provenance_hash)
        _nonempty("provenance_type", self.provenance_type)
        digest_from_subject(self.attestation_subject)
        _nonempty("verification_status", self.verification_status)
        object.__setattr__(
            self,
            "evidence_generation_time",
            _timestamp("evidence_generation_time", self.evidence_generation_time),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifactDigest": self.artifact_digest,
            "sbomPath": self.sbom_path,
            "sbomFormat": self.sbom_format,
            "sbomHash": self.sbom_hash,
            "sbomGenerator": self.sbom_generator,
            "vulnerabilityReportPath": self.vulnerability_report_path,
            "vulnerabilityReportHash": self.vulnerability_report_hash,
            "scannerName": self.scanner_name,
            "scannerVersion": self.scanner_version,
            "scannerDatabaseMetadata": dict(self.scanner_database_metadata),
            "policyResult": dict(self.policy_result),
            "provenancePath": self.provenance_path,
            "provenanceHash": self.provenance_hash,
            "provenanceType": self.provenance_type,
            "attestationSubject": self.attestation_subject,
            "verificationStatus": self.verification_status,
            "evidenceGenerationTime": self.evidence_generation_time,
        }


@dataclass(frozen=True)
class DeploymentEvidence:
    """Observed Kubernetes rollout, endpoint, and rollback evidence."""

    environment: str
    namespace: str
    cluster_type: str
    cluster_identifier: str
    manifest_hash: str
    deployed_image_reference: str
    expected_digest: str
    actual_pod_image_id: str
    rollout_status: str
    ready_replica_count: int
    health_endpoint_result: Mapping[str, Any]
    readiness_endpoint_result: Mapping[str, Any]
    rollback_attempted: bool
    rollback_result: str
    final_revision: str
    final_digest: str
    diagnostics_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier("environment", self.environment)
        _identifier("namespace", self.namespace)
        _identifier("cluster_type", self.cluster_type)
        _nonempty("cluster_identifier", self.cluster_identifier)
        validate_sha256_hex(self.manifest_hash)
        reference = parse_oci_reference(self.deployed_image_reference)
        if reference.digest is None:
            raise ValueError("deployed_image_reference must be digest-pinned")
        parse_digest(self.expected_digest)
        digest_from_image_id(self.actual_pod_image_id)
        _nonempty("rollout_status", self.rollout_status)
        if (
            isinstance(self.ready_replica_count, bool)
            or not isinstance(self.ready_replica_count, int)
            or self.ready_replica_count < 0
        ):
            raise ValueError("ready_replica_count must be a non-negative integer")
        object.__setattr__(
            self,
            "health_endpoint_result",
            _ordered_json_mapping("health_endpoint_result", self.health_endpoint_result),
        )
        object.__setattr__(
            self,
            "readiness_endpoint_result",
            _ordered_json_mapping("readiness_endpoint_result", self.readiness_endpoint_result),
        )
        if not isinstance(self.rollback_attempted, bool):
            raise ValueError("rollback_attempted must be boolean")
        _nonempty("rollback_result", self.rollback_result)
        _nonempty("final_revision", self.final_revision)
        parse_digest(self.final_digest)
        diagnostics = tuple(
            _relative_path("diagnostics_path", path) for path in self.diagnostics_paths
        )
        if len(set(diagnostics)) != len(diagnostics):
            raise ValueError("diagnostics_paths must be unique")
        object.__setattr__(self, "diagnostics_paths", diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "namespace": self.namespace,
            "clusterType": self.cluster_type,
            "clusterIdentifier": self.cluster_identifier,
            "manifestHash": self.manifest_hash,
            "deployedImageReference": self.deployed_image_reference,
            "expectedDigest": self.expected_digest,
            "actualPodImageId": self.actual_pod_image_id,
            "rolloutStatus": self.rollout_status,
            "readyReplicaCount": self.ready_replica_count,
            "healthEndpointResult": dict(self.health_endpoint_result),
            "readinessEndpointResult": dict(self.readiness_endpoint_result),
            "rollbackAttempted": self.rollback_attempted,
            "rollbackResult": self.rollback_result,
            "finalRevision": self.final_revision,
            "finalDigest": self.final_digest,
            "diagnosticsPaths": list(self.diagnostics_paths),
        }


@dataclass(frozen=True)
class StageResult:
    """One bounded execution stage and its evidence references."""

    stage_id: str
    description: str
    status: StageStatus
    start_time: str
    end_time: str
    command: tuple[str, ...] = ()
    tool: str | None = None
    sanitized_output: str | None = None
    evidence_paths: tuple[str, ...] = ()
    failure_reason: str | None = None
    remediation: str | None = None

    def __post_init__(self) -> None:
        _identifier("stage_id", self.stage_id)
        _nonempty("description", self.description)
        try:
            status = (
                self.status
                if isinstance(self.status, StageStatus)
                else StageStatus(self.status)
            )
        except ValueError as exc:
            raise ValueError(f"unsupported stage status: {self.status!r}") from exc
        object.__setattr__(self, "status", status)
        start = _timestamp("start_time", self.start_time)
        end = _timestamp("end_time", self.end_time)
        if datetime.fromisoformat(end.replace("Z", "+00:00")) < datetime.fromisoformat(
            start.replace("Z", "+00:00")
        ):
            raise ValueError("end_time must not precede start_time")
        object.__setattr__(self, "start_time", start)
        object.__setattr__(self, "end_time", end)
        command = tuple(_nonempty("command argument", argument) for argument in self.command)
        object.__setattr__(self, "command", command)
        if self.tool is not None:
            _nonempty("tool", self.tool)
        if self.sanitized_output is not None and "\x00" in self.sanitized_output:
            raise ValueError("sanitized_output must not contain NUL bytes")
        evidence_paths = tuple(
            _relative_path("evidence_path", path) for path in self.evidence_paths
        )
        if len(set(evidence_paths)) != len(evidence_paths):
            raise ValueError("evidence_paths must be unique")
        object.__setattr__(self, "evidence_paths", evidence_paths)
        if status in {StageStatus.FAILED, StageStatus.BLOCKED_MISSING_REQUIRED_TOOL}:
            if self.failure_reason is None:
                raise ValueError(f"{status.value} stages require failure_reason")
        if self.failure_reason is not None:
            _nonempty("failure_reason", self.failure_reason)
        if self.remediation is not None:
            _nonempty("remediation", self.remediation)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stageId": self.stage_id,
            "description": self.description,
            "status": self.status.value,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "command": list(self.command),
            "tool": self.tool,
            "sanitizedOutput": self.sanitized_output,
            "evidencePaths": list(self.evidence_paths),
            "failureReason": self.failure_reason,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ExecutionRun:
    """Complete serializable record of one execution profile run."""

    run_id: str
    project_path: str
    config_hash: str
    template_lock_hash: str
    source_revision: str
    start_time: str
    end_time: str
    execution_profile: str
    stage_results: tuple[StageResult, ...]
    final_status: StageStatus
    tool_versions: Mapping[str, str]
    artifact_record: ResolvedArtifact | None = None
    supply_chain_evidence: SupplyChainEvidence | None = None
    deployment_evidence: DeploymentEvidence | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not _RUN_ID.fullmatch(self.run_id):
            raise ValueError("run_id must use safe filename characters")
        _relative_path("project_path", self.project_path, allow_dot=True)
        validate_sha256_hex(self.config_hash)
        validate_sha256_hex(self.template_lock_hash)
        _git_revision("source_revision", self.source_revision)
        start = _timestamp("start_time", self.start_time)
        end = _timestamp("end_time", self.end_time)
        if datetime.fromisoformat(end.replace("Z", "+00:00")) < datetime.fromisoformat(
            start.replace("Z", "+00:00")
        ):
            raise ValueError("end_time must not precede start_time")
        object.__setattr__(self, "start_time", start)
        object.__setattr__(self, "end_time", end)
        _identifier("execution_profile", self.execution_profile)
        stages = tuple(self.stage_results)
        if any(not isinstance(stage, StageResult) for stage in stages):
            raise ValueError("stage_results must contain StageResult values")
        stage_ids = [stage.stage_id for stage in stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("stage_results must use unique stage IDs")
        object.__setattr__(self, "stage_results", stages)
        try:
            final_status = (
                self.final_status
                if isinstance(self.final_status, StageStatus)
                else StageStatus(self.final_status)
            )
        except ValueError as exc:
            raise ValueError(f"unsupported final status: {self.final_status!r}") from exc
        object.__setattr__(self, "final_status", final_status)
        object.__setattr__(
            self,
            "tool_versions",
            _string_mapping("tool_versions", self.tool_versions),
        )
        blocking = {
            StageStatus.FAILED,
            StageStatus.BLOCKED_MISSING_REQUIRED_TOOL,
        }
        if final_status == StageStatus.PASSED and any(stage.status in blocking for stage in stages):
            raise ValueError("a run with failed or blocked stages cannot have final_status PASSED")
        if final_status in blocking and self.failure_reason is None:
            raise ValueError(f"{final_status.value} runs require failure_reason")
        if self.failure_reason is not None:
            _nonempty("failure_reason", self.failure_reason)

    @property
    def status_counts(self) -> dict[str, int]:
        return {
            status.value: sum(stage.status == status for stage in self.stage_results)
            for status in StageStatus
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "1.0.0",
            "runId": self.run_id,
            "projectPath": self.project_path,
            "configHash": self.config_hash,
            "templateLockHash": self.template_lock_hash,
            "sourceRevision": self.source_revision,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "executionProfile": self.execution_profile,
            "stageResults": [stage.to_dict() for stage in self.stage_results],
            "statusCounts": self.status_counts,
            "artifact": self.artifact_record.to_dict() if self.artifact_record else None,
            "supplyChainEvidence": (
                self.supply_chain_evidence.to_dict() if self.supply_chain_evidence else None
            ),
            "deploymentEvidence": (
                self.deployment_evidence.to_dict() if self.deployment_evidence else None
            ),
            "finalStatus": self.final_status.value,
            "failureReason": self.failure_reason,
            "toolVersions": dict(self.tool_versions),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"
