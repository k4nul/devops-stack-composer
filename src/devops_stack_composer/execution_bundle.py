"""Strict, offline loading and verification of execution evidence bundles.

The loader deliberately has no command runner or registry client.  It first
verifies the bundle's closed checksum inventory, then parses and relates only
the bytes covered by that inventory.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TypeVar

from devops_stack_composer.errors import DevOpsStackError, UnsafePathError
from devops_stack_composer.evidence_store import EvidenceStore, EvidenceStoreError
from devops_stack_composer.evidence_validation import (
    ArtifactContractError,
    ArtifactVerification,
    parse_kubernetes_yaml,
    validate_artifact_contract,
    validate_kubernetes_documents,
)
from devops_stack_composer.execution_models import (
    ArtifactIntent,
    DeploymentEvidence,
    EXECUTION_EVIDENCE_SCHEMA_VERSION,
    ExecutionRun,
    LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
    ResolvedArtifact,
    StageResult,
    SupplyChainEvidence,
)
from devops_stack_composer.execution_plan import ExecutionPlan, PlannedStage
from devops_stack_composer.filesystem import contained_path, project_root
from devops_stack_composer.oci import digest_from_subject, parse_digest
from devops_stack_composer.policies import profile_policy
from devops_stack_composer.supply_chain import (
    PROVENANCE_VERIFICATION_COMMAND,
    SupplyChainError,
    verify_provenance_evidence,
    verify_sbom_evidence,
    verify_vulnerability_evidence,
)


class ExecutionBundleError(DevOpsStackError):
    """Raised when stored execution evidence is unsafe or contradictory."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        evidence_path: str | None = None,
        reproduction_command: str = (
            "devops-stack artifact verify --project . --run $RUN_ID"
        ),
    ):
        self.code = code
        self.detail = message
        self.evidence_path = evidence_path
        self.reproduction_command = reproduction_command
        suffix = f"; evidence: {evidence_path}" if evidence_path else ""
        super().__init__(
            f"{code}: {message}{suffix}; reproduce: {reproduction_command}"
        )


@dataclass(frozen=True)
class BundleInspection:
    """Concise artifact projection suitable for human or JSON CLI output."""

    run_id: str
    profile: str | None
    final_status: str | None
    repository: str | None
    tag: str | None
    digest: str | None
    platform: str | None
    config_digest: str | None
    sbom: str | None
    scan: str | None
    provenance: str | None
    verification_status: str | None
    deployment_environment: str | None
    checksum_file_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            "profile": self.profile,
            "finalStatus": self.final_status,
            "repository": self.repository,
            "tag": self.tag,
            "digest": self.digest,
            "platform": self.platform,
            "configDigest": self.config_digest,
            "sbom": self.sbom,
            "scan": self.scan,
            "provenance": self.provenance,
            "verificationStatus": self.verification_status,
            "deploymentEnvironment": self.deployment_environment,
            "checksumFileCount": self.checksum_file_count,
        }


@dataclass(frozen=True)
class BundleVerification:
    """Fresh offline verification result, independent of the stored claim."""

    passed: bool
    run_id: str
    authoritative_digest: str | None
    subjects: Mapping[str, str]
    checks: tuple[str, ...]
    checksum_file_count: int
    stored_verification_matches: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "runId": self.run_id,
            "authoritativeDigest": self.authoritative_digest,
            "subjects": dict(sorted(self.subjects.items())),
            "checks": list(self.checks),
            "checksumFileCount": self.checksum_file_count,
            "storedVerificationMatches": self.stored_verification_matches,
        }


@dataclass(frozen=True)
class ExecutionBundle:
    """Rehydrated records whose source bytes passed the closed inventory gate."""

    store: EvidenceStore
    checksums: Mapping[str, str]
    record_paths: Mapping[str, tuple[str, ...]]
    plan: ExecutionPlan | None = None
    artifact: ResolvedArtifact | None = None
    supply_chain: SupplyChainEvidence | None = None
    deployment: DeploymentEvidence | None = None
    execution_run: ExecutionRun | None = None
    stored_verification: ArtifactVerification | None = None

    @property
    def run_id(self) -> str:
        return self.store.run_id

    @property
    def root(self) -> Path:
        return self.store.root

    def inspect(self) -> BundleInspection:
        artifact = self.artifact
        supply_chain = self.supply_chain
        deployment = self.deployment
        profile = (
            self.plan.profile.value
            if self.plan is not None
            else self.execution_run.execution_profile
            if self.execution_run is not None
            else None
        )
        return BundleInspection(
            run_id=self.run_id,
            profile=profile,
            final_status=(
                self.execution_run.final_status.value
                if self.execution_run is not None
                else None
            ),
            repository=artifact.repository if artifact else None,
            tag=artifact.tag if artifact else None,
            digest=artifact.manifest_digest if artifact else None,
            platform=(
                f"{artifact.operating_system}/{artifact.architecture}"
                if artifact
                else None
            ),
            config_digest=artifact.config_digest if artifact else None,
            sbom=supply_chain.sbom_path if supply_chain else None,
            scan=(supply_chain.vulnerability_report_path if supply_chain else None),
            provenance=supply_chain.provenance_path if supply_chain else None,
            verification_status=(
                supply_chain.verification_status
                if supply_chain
                else "STORED_VERIFICATION_UNCHECKED"
                if self.stored_verification
                else None
            ),
            deployment_environment=deployment.environment if deployment else None,
            checksum_file_count=len(self.checksums),
        )

    def verify(self) -> BundleVerification:
        checks = ["closed-checksum-inventory", "strict-record-json"]
        _verify_record_relationships(self)

        if self.artifact is None:
            if any(
                value is not None
                for value in (
                    self.supply_chain,
                    self.deployment,
                    self.stored_verification,
                )
            ):
                raise ExecutionBundleError(
                    "ARTIFACT_RECORD_MISSING",
                    "subject evidence exists without artifact.json or a report artifact",
                )
            return BundleVerification(
                True,
                self.run_id,
                None,
                {},
                tuple(checks),
                len(self.checksums),
                None,
            )

        artifact = self.artifact
        if self.supply_chain is not None:
            evidence = self.supply_chain
            legacy_run = (
                self.execution_run is not None
                and self.execution_run.schema_version
                == LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION
            )
            source_repository = (
                self.execution_run.source_repository
                if self.execution_run is not None and not legacy_run
                else None
            )
            try:
                generator = verify_sbom_evidence(
                    self.root,
                    evidence.sbom_path,
                    evidence.sbom_hash,
                    artifact.immutable_image_reference,
                    require_source_metadata=not legacy_run,
                    source_repository=source_repository,
                    source_revision=(None if legacy_run else artifact.source_revision),
                )
                if generator != evidence.sbom_generator:
                    raise ExecutionBundleError(
                        "SBOM_GENERATOR_MISMATCH",
                        "the SBOM creator differs from supply-chain.json",
                    )
                verify_vulnerability_evidence(
                    self.root,
                    evidence.vulnerability_report_path,
                    evidence.vulnerability_report_hash,
                    artifact.immutable_image_reference,
                )
                verify_provenance_evidence(
                    self.root,
                    evidence.provenance_path,
                    evidence.provenance_hash,
                    artifact.immutable_image_reference,
                    source_revision=artifact.source_revision,
                    build_plan_hash=artifact.build_plan_hash,
                    source_repository=source_repository,
                    verification_command=(
                        None if legacy_run else PROVENANCE_VERIFICATION_COMMAND
                    ),
                    reproduction_command=(
                        None
                        if legacy_run
                        else "devops-stack artifact verify --project . --run "
                        f"{self.run_id}"
                    ),
                    generator_tool_name=(
                        None if legacy_run else "devops-stack-composer"
                    ),
                    generator_tool_version=(
                        None
                        if legacy_run or self.execution_run is None
                        else self.execution_run.tool_versions.get(
                            "devops-stack-composer"
                        )
                    ),
                    buildx_version=(
                        None if legacy_run else artifact.created_by_tool_version
                    ),
                    require_verification_metadata=not legacy_run,
                )
            except SupplyChainError as exc:
                raise ExecutionBundleError(exc.code, str(exc)) from exc
            checks.extend(("spdx-subject", "trivy-subject", "provenance-subject"))

        if self.deployment is not None:
            manifest_path = _deployment_manifest_path(self)
            payload = _checked_bytes(self.store, self.checksums, manifest_path)
            try:
                content = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ExecutionBundleError(
                    "KUBERNETES_MANIFEST_INVALID",
                    f"{manifest_path} is not UTF-8",
                ) from exc
            try:
                documents = parse_kubernetes_yaml(content)
                validate_kubernetes_documents(
                    documents,
                    immutable_reference=artifact.immutable_image_reference,
                )
            except ArtifactContractError as exc:
                raise ExecutionBundleError(exc.code, str(exc)) from exc
            checks.append("kubernetes-subject")

        try:
            fresh = validate_artifact_contract(
                artifact,
                self.supply_chain,
                self.deployment,
            )
        except ArtifactContractError as exc:
            raise ExecutionBundleError(exc.code, str(exc)) from exc
        checks.append("artifact-digest-contract")

        stored_matches: bool | None = None
        if self.stored_verification is not None:
            stored_matches = self.stored_verification.to_dict() == fresh.to_dict()
            if not stored_matches:
                raise ExecutionBundleError(
                    "STORED_VERIFICATION_MISMATCH",
                    "verification.json does not equal a fresh offline verification",
                )
            checks.append("stored-verification")

        return BundleVerification(
            True,
            self.run_id,
            fresh.authoritative_digest,
            fresh.subjects,
            tuple(checks),
            len(self.checksums),
            stored_matches,
        )


_T = TypeVar("_T")
_Parser = Callable[[Mapping[str, Any], str], _T]

_PLAN_PATHS = ("plan.json", "execution-plan.json")
_ARTIFACT_PATHS = ("artifact.json",)
_SUPPLY_CHAIN_PATHS = ("supply-chain.json", "supply-chain-evidence.json")
_DEPLOYMENT_PATHS = ("deployment-evidence.json",)
_RUN_PATHS = ("run.json", "execution-evidence.json", "report.json")
_VERIFICATION_PATH = "verification.json"
_EVIDENCE_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")


def _load_execution_bundle(
    project: Path,
    run_id: str,
    *,
    work_directory: str = ".devops-stack/runs",
) -> ExecutionBundle:
    """Load a project-contained run without invoking subprocesses or the network."""

    if not isinstance(run_id, str) or not _EVIDENCE_RUN_ID.fullmatch(run_id):
        raise ExecutionBundleError(
            "BUNDLE_PATH_UNSAFE",
            "run_id must be a generated execution ID, not a path",
        )
    try:
        store = EvidenceStore.open(
            project,
            run_id,
            work_directory=work_directory,
        )
        checksums = store.verify_checksums()
    except UnsafePathError as exc:
        raise ExecutionBundleError("BUNDLE_PATH_UNSAFE", str(exc)) from exc
    except EvidenceStoreError as exc:
        raise ExecutionBundleError("BUNDLE_CHECKSUM_INVALID", str(exc)) from exc

    records: dict[str, tuple[str, ...]] = {}
    plan, paths = _load_matching_records(
        store,
        checksums,
        _PLAN_PATHS,
        _parse_plan,
        "execution plan",
    )
    if paths:
        records["executionPlan"] = paths

    artifact, paths = _load_matching_records(
        store,
        checksums,
        _ARTIFACT_PATHS,
        _parse_artifact,
        "artifact",
    )
    if paths:
        records["artifact"] = paths
    supply_chain, paths = _load_matching_records(
        store,
        checksums,
        _SUPPLY_CHAIN_PATHS,
        _parse_supply_chain,
        "supply-chain evidence",
    )
    if paths:
        records["supplyChainEvidence"] = paths
    deployment, paths = _load_matching_records(
        store,
        checksums,
        _DEPLOYMENT_PATHS,
        _parse_deployment,
        "deployment evidence",
    )
    if paths:
        records["deploymentEvidence"] = paths
    execution_run, run_paths = _load_matching_records(
        store,
        checksums,
        _RUN_PATHS,
        _parse_execution_run,
        "execution report",
    )
    if run_paths:
        records["executionRun"] = run_paths

    if execution_run is not None:
        artifact = _merge_optional_record(
            artifact,
            execution_run.artifact_record,
            "artifact",
            run_paths,
        )
        supply_chain = _merge_optional_record(
            supply_chain,
            execution_run.supply_chain_evidence,
            "supply-chain evidence",
            run_paths,
        )
        deployment = _merge_optional_record(
            deployment,
            execution_run.deployment_evidence,
            "deployment evidence",
            run_paths,
        )

    stored_verification = None
    if _VERIFICATION_PATH in checksums:
        stored_verification = _parse_checked(
            store,
            checksums,
            _VERIFICATION_PATH,
            _parse_verification,
        )
        records["verification"] = (_VERIFICATION_PATH,)

    if not records:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_MISSING",
            "the checksummed bundle contains no recognized execution record",
        )

    bundle = ExecutionBundle(
        store=store,
        checksums=dict(checksums),
        record_paths=records,
        plan=plan,
        artifact=artifact,
        supply_chain=supply_chain,
        deployment=deployment,
        execution_run=execution_run,
        stored_verification=stored_verification,
    )
    _verify_record_relationships(bundle)
    return bundle


def _bundle_reproduction_command(
    project: Path, run_id: str, work_directory: str
) -> str:
    return (
        "devops-stack artifact verify"
        f" --project {shlex.quote(str(Path(project).resolve()))}"
        f" --run {shlex.quote(run_id)}"
        f" --output {shlex.quote(work_directory)}"
    )


def load_execution_bundle(
    project: Path,
    run_id: str,
    *,
    work_directory: str = ".devops-stack/runs",
) -> ExecutionBundle:
    """Load a bundle and attach its exact offline reproduction command."""

    try:
        return _load_execution_bundle(
            project,
            run_id,
            work_directory=work_directory,
        )
    except ExecutionBundleError as exc:
        raise ExecutionBundleError(
            exc.code,
            exc.detail,
            evidence_path=exc.evidence_path or "SHA256SUMS",
            reproduction_command=_bundle_reproduction_command(
                project, run_id, work_directory
            ),
        ) from exc


def inspect_execution_bundle(
    project: Path,
    run_id: str,
    *,
    work_directory: str = ".devops-stack/runs",
) -> BundleInspection:
    return load_execution_bundle(
        project,
        run_id,
        work_directory=work_directory,
    ).inspect()


def verify_execution_bundle(
    project: Path,
    run_id: str,
    *,
    work_directory: str = ".devops-stack/runs",
) -> BundleVerification:
    try:
        return load_execution_bundle(
            project,
            run_id,
            work_directory=work_directory,
        ).verify()
    except ExecutionBundleError as exc:
        command = _bundle_reproduction_command(project, run_id, work_directory)
        if exc.reproduction_command == command:
            raise
        raise ExecutionBundleError(
            exc.code,
            exc.detail,
            evidence_path=exc.evidence_path or "SHA256SUMS",
            reproduction_command=command,
        ) from exc


def parse_strict_json(
    payload: str | bytes,
    *,
    source: str = "JSON input",
) -> Mapping[str, Any]:
    """Parse one finite, duplicate-free JSON object without schema assumptions."""

    try:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        if not isinstance(text, str):
            raise TypeError("payload must be text or bytes")
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutionBundleError(
            "BUNDLE_JSON_INVALID", f"{source} is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise ExecutionBundleError(
            "BUNDLE_JSON_INVALID", f"{source} must contain a JSON object"
        )
    return value


def load_strict_json_file(
    project: Path,
    relative_path: str,
) -> Mapping[str, Any]:
    """Read one project-relative, symlink-free strict JSON input file."""

    try:
        root = project_root(project)
        path = contained_path(root, relative_path)
    except UnsafePathError as exc:
        raise ExecutionBundleError("BUNDLE_PATH_UNSAFE", str(exc)) from exc
    if path.is_symlink() or not path.is_file():
        raise ExecutionBundleError(
            "EVIDENCE_FILE_MISSING", f"{relative_path} is not a regular input file"
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ExecutionBundleError(
            "EVIDENCE_FILE_MISSING", f"could not read {relative_path}"
        ) from exc
    return parse_strict_json(payload, source=relative_path)


def parse_resolved_artifact(
    value: Mapping[str, Any],
    *,
    source: str = "artifact.json",
) -> ResolvedArtifact:
    """Strictly rehydrate the canonical execution artifact record."""

    try:
        return _parse_artifact(_mapping(value, source), source)
    except ExecutionBundleError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source}: {exc}"
        ) from exc


def load_resolved_artifact_file(
    project: Path,
    relative_path: str,
) -> ResolvedArtifact:
    """Load a project-contained canonical artifact record for file-mode CLI use."""

    return parse_resolved_artifact(
        load_strict_json_file(project, relative_path),
        source=relative_path,
    )


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON property {key!r}")
        value[key] = item
    return value


def _checked_bytes(
    store: EvidenceStore,
    checksums: Mapping[str, str],
    relative_path: str,
) -> bytes:
    expected = checksums.get(relative_path)
    if expected is None:
        raise ExecutionBundleError(
            "EVIDENCE_FILE_MISSING",
            f"{relative_path} is not covered by SHA256SUMS",
        )
    try:
        path = store.path(relative_path)
    except UnsafePathError as exc:
        raise ExecutionBundleError("BUNDLE_PATH_UNSAFE", str(exc)) from exc
    if path.is_symlink() or not path.is_file():
        raise ExecutionBundleError(
            "EVIDENCE_FILE_MISSING",
            f"{relative_path} is not a regular evidence file",
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ExecutionBundleError(
            "EVIDENCE_FILE_MISSING", f"could not read {relative_path}"
        ) from exc
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ExecutionBundleError(
            "BUNDLE_CHECKSUM_INVALID",
            f"{relative_path} changed after closed-inventory verification",
        )
    return payload


def _strict_json(
    store: EvidenceStore,
    checksums: Mapping[str, str],
    relative_path: str,
) -> Mapping[str, Any]:
    payload = _checked_bytes(store, checksums, relative_path)
    return parse_strict_json(payload, source=relative_path)


def _parse_checked(
    store: EvidenceStore,
    checksums: Mapping[str, str],
    relative_path: str,
    parser: _Parser[_T],
) -> _T:
    value = _strict_json(store, checksums, relative_path)
    try:
        return parser(value, relative_path)
    except ExecutionBundleError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{relative_path}: {exc}"
        ) from exc


def _load_matching_records(
    store: EvidenceStore,
    checksums: Mapping[str, str],
    candidates: tuple[str, ...],
    parser: _Parser[_T],
    record_name: str,
) -> tuple[_T | None, tuple[str, ...]]:
    paths = tuple(path for path in candidates if path in checksums)
    records = tuple(_parse_checked(store, checksums, path, parser) for path in paths)
    if not records:
        return None, ()
    first = records[0]
    if any(_record_value(record) != _record_value(first) for record in records[1:]):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_MISMATCH",
            f"duplicate {record_name} records do not match: {', '.join(paths)}",
        )
    return first, paths


def _record_value(value: Any) -> Any:
    to_dict = getattr(value, "to_dict", None)
    return to_dict() if callable(to_dict) else value


def _merge_optional_record(
    standalone: _T | None,
    nested: _T | None,
    record_name: str,
    report_paths: tuple[str, ...],
) -> _T | None:
    if standalone is None:
        return nested
    if nested is None or _record_value(standalone) != _record_value(nested):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_MISMATCH",
            f"standalone {record_name} differs from {', '.join(report_paths)}",
        )
    return standalone


def _expect_keys(
    value: Mapping[str, Any],
    expected: set[str],
    source: str,
) -> None:
    received = set(value)
    if received != expected:
        missing = sorted(expected - received)
        unknown = sorted(received - expected)
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID",
            f"{source} has missing keys {missing} and unknown keys {unknown}",
        )


def _mapping(value: Any, source: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} must be a JSON object"
        )
    return value


def _list(value: Any, source: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} must be a JSON array"
        )
    return value


def _parse_artifact(value: Mapping[str, Any], source: str) -> ResolvedArtifact:
    _expect_keys(
        value,
        {
            "immutableImageReference",
            "repository",
            "tag",
            "manifestDigest",
            "platformDigest",
            "mediaType",
            "architecture",
            "operatingSystem",
            "imageSize",
            "configDigest",
            "sourceRevision",
            "buildPlanHash",
            "createdByToolVersion",
            "registryEndpoint",
            "buildInvocationCount",
        },
        source,
    )
    record = ResolvedArtifact(
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
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} is not canonical artifact JSON"
        )
    return record


def _parse_supply_chain(
    value: Mapping[str, Any], source: str
) -> SupplyChainEvidence:
    _expect_keys(
        value,
        {
            "artifactDigest",
            "sbomPath",
            "sbomFormat",
            "sbomHash",
            "sbomGenerator",
            "vulnerabilityReportPath",
            "vulnerabilityReportHash",
            "scannerName",
            "scannerVersion",
            "scannerDatabaseMetadata",
            "policyResult",
            "provenancePath",
            "provenanceHash",
            "provenanceType",
            "attestationSubject",
            "verificationStatus",
            "evidenceGenerationTime",
        },
        source,
    )
    record = SupplyChainEvidence(
        artifact_digest=value["artifactDigest"],
        sbom_path=value["sbomPath"],
        sbom_format=value["sbomFormat"],
        sbom_hash=value["sbomHash"],
        sbom_generator=value["sbomGenerator"],
        vulnerability_report_path=value["vulnerabilityReportPath"],
        vulnerability_report_hash=value["vulnerabilityReportHash"],
        scanner_name=value["scannerName"],
        scanner_version=value["scannerVersion"],
        scanner_database_metadata=_mapping(
            value["scannerDatabaseMetadata"],
            f"{source}.scannerDatabaseMetadata",
        ),
        policy_result=_mapping(value["policyResult"], f"{source}.policyResult"),
        provenance_path=value["provenancePath"],
        provenance_hash=value["provenanceHash"],
        provenance_type=value["provenanceType"],
        attestation_subject=value["attestationSubject"],
        verification_status=value["verificationStatus"],
        evidence_generation_time=value["evidenceGenerationTime"],
    )
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} is not canonical supply-chain JSON"
        )
    return record


def _parse_deployment(value: Mapping[str, Any], source: str) -> DeploymentEvidence:
    _expect_keys(
        value,
        {
            "environment",
            "namespace",
            "clusterType",
            "clusterIdentifier",
            "manifestHash",
            "deployedImageReference",
            "expectedDigest",
            "actualPodImageId",
            "rolloutStatus",
            "readyReplicaCount",
            "healthEndpointResult",
            "readinessEndpointResult",
            "rollbackAttempted",
            "rollbackResult",
            "finalRevision",
            "finalDigest",
            "diagnosticsPaths",
        },
        source,
    )
    record = DeploymentEvidence(
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
        health_endpoint_result=_mapping(
            value["healthEndpointResult"], f"{source}.healthEndpointResult"
        ),
        readiness_endpoint_result=_mapping(
            value["readinessEndpointResult"],
            f"{source}.readinessEndpointResult",
        ),
        rollback_attempted=value["rollbackAttempted"],
        rollback_result=value["rollbackResult"],
        final_revision=value["finalRevision"],
        final_digest=value["finalDigest"],
        diagnostics_paths=tuple(
            _list(value["diagnosticsPaths"], f"{source}.diagnosticsPaths")
        ),
    )
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} is not canonical deployment JSON"
        )
    return record


def _parse_artifact_intent(value: Mapping[str, Any], source: str) -> ArtifactIntent:
    _expect_keys(
        value,
        {
            "applicationName",
            "registry",
            "repository",
            "requestedTag",
            "platforms",
            "sourceRevision",
            "buildContext",
            "dockerfile",
            "buildArguments",
            "targetStage",
            "templateRevision",
            "normalizedModelHash",
        },
        source,
    )
    return ArtifactIntent(
        application_name=value["applicationName"],
        registry=value["registry"],
        repository=value["repository"],
        requested_tag=value["requestedTag"],
        platforms=tuple(_list(value["platforms"], f"{source}.platforms")),
        source_revision=value["sourceRevision"],
        build_context=value["buildContext"],
        dockerfile=value["dockerfile"],
        build_arguments=_mapping(value["buildArguments"], f"{source}.buildArguments"),
        target_stage=value["targetStage"],
        template_revision=value["templateRevision"],
        normalized_model_hash=value["normalizedModelHash"],
    )


def _parse_plan(value: Mapping[str, Any], source: str) -> ExecutionPlan:
    _expect_keys(
        value,
        {
            "schemaVersion",
            "runId",
            "profile",
            "environment",
            "artifactIntent",
            "stages",
            "productionApplyApproved",
            "buildPlanHash",
        },
        source,
    )
    if value["schemaVersion"] != "1.0.0":
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} has an unsupported schemaVersion"
        )
    intent = _parse_artifact_intent(
        _mapping(value["artifactIntent"], f"{source}.artifactIntent"),
        f"{source}.artifactIntent",
    )
    stages: list[PlannedStage] = []
    for index, item in enumerate(_list(value["stages"], f"{source}.stages")):
        stage_source = f"{source}.stages[{index}]"
        stage = _mapping(item, stage_source)
        _expect_keys(stage, {"stageId", "description", "required"}, stage_source)
        stages.append(
            PlannedStage(stage["stageId"], stage["description"], stage["required"])
        )
    record = ExecutionPlan(
        run_id=value["runId"],
        profile=value["profile"],
        environment=value["environment"],
        artifact_intent=intent,
        stages=tuple(stages),
        production_apply_approved=value["productionApplyApproved"],
    )
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID",
            f"{source} buildPlanHash or canonical fields do not match",
        )
    return record


def _parse_stage(value: Mapping[str, Any], source: str) -> StageResult:
    _expect_keys(
        value,
        {
            "stageId",
            "description",
            "status",
            "startTime",
            "endTime",
            "command",
            "tool",
            "sanitizedOutput",
            "evidencePaths",
            "failureReason",
            "remediation",
        },
        source,
    )
    return StageResult(
        stage_id=value["stageId"],
        description=value["description"],
        status=value["status"],
        start_time=value["startTime"],
        end_time=value["endTime"],
        command=tuple(_list(value["command"], f"{source}.command")),
        tool=value["tool"],
        sanitized_output=value["sanitizedOutput"],
        evidence_paths=tuple(
            _list(value["evidencePaths"], f"{source}.evidencePaths")
        ),
        failure_reason=value["failureReason"],
        remediation=value["remediation"],
    )


def _parse_execution_run(value: Mapping[str, Any], source: str) -> ExecutionRun:
    legacy_fields = {
        "schemaVersion",
        "runId",
        "projectPath",
        "configHash",
        "templateLockHash",
        "sourceRevision",
        "startTime",
        "endTime",
        "executionProfile",
        "stageResults",
        "statusCounts",
        "artifact",
        "supplyChainEvidence",
        "deploymentEvidence",
        "finalStatus",
        "failureReason",
        "toolVersions",
    }
    extension_fields = {
        "sourceRepository",
        "templateRevisions",
        "evidenceChecksums",
        "evidenceChecksumPaths",
        "limitations",
    }
    schema_version = value.get("schemaVersion")
    if schema_version == LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION:
        expected_fields = legacy_fields
    elif schema_version == EXECUTION_EVIDENCE_SCHEMA_VERSION:
        expected_fields = legacy_fields | extension_fields
    else:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} has an unsupported schemaVersion"
        )
    _expect_keys(
        value,
        expected_fields,
        source,
    )
    stages = tuple(
        _parse_stage(
            _mapping(item, f"{source}.stageResults[{index}]"),
            f"{source}.stageResults[{index}]",
        )
        for index, item in enumerate(
            _list(value["stageResults"], f"{source}.stageResults")
        )
    )
    artifact_value = value["artifact"]
    supply_value = value["supplyChainEvidence"]
    deployment_value = value["deploymentEvidence"]
    record = ExecutionRun(
        run_id=value["runId"],
        project_path=value["projectPath"],
        config_hash=value["configHash"],
        template_lock_hash=value["templateLockHash"],
        source_revision=value["sourceRevision"],
        start_time=value["startTime"],
        end_time=value["endTime"],
        execution_profile=value["executionProfile"],
        stage_results=stages,
        final_status=value["finalStatus"],
        tool_versions=_mapping(value["toolVersions"], f"{source}.toolVersions"),
        artifact_record=(
            _parse_artifact(_mapping(artifact_value, f"{source}.artifact"), source)
            if artifact_value is not None
            else None
        ),
        supply_chain_evidence=(
            _parse_supply_chain(
                _mapping(supply_value, f"{source}.supplyChainEvidence"), source
            )
            if supply_value is not None
            else None
        ),
        deployment_evidence=(
            _parse_deployment(
                _mapping(deployment_value, f"{source}.deploymentEvidence"), source
            )
            if deployment_value is not None
            else None
        ),
        failure_reason=value["failureReason"],
        schema_version=schema_version,
        source_repository=value.get(
            "sourceRepository", "urn:devops-stack:source:unspecified"
        ),
        template_revisions=_mapping(
            value.get("templateRevisions", {}), f"{source}.templateRevisions"
        ),
        evidence_checksums=_mapping(
            value.get("evidenceChecksums", {}), f"{source}.evidenceChecksums"
        ),
        evidence_checksum_paths=tuple(
            _list(
                value.get("evidenceChecksumPaths", ["SHA256SUMS"]),
                f"{source}.evidenceChecksumPaths",
            )
        ),
        limitations=tuple(
            _list(
                value.get("limitations", ["legacy schema 1.0 record"]),
                f"{source}.limitations",
            )
        ),
    )
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID",
            f"{source} status counts or canonical fields do not match",
        )
    return record


def _parse_verification(
    value: Mapping[str, Any], source: str
) -> ArtifactVerification:
    _expect_keys(
        value,
        {
            "passed",
            "authoritativeDigest",
            "subjects",
            "mutableImages",
            "placeholderImages",
        },
        source,
    )
    if value["passed"] is not True:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source}.passed must be true"
        )
    subjects = _mapping(value["subjects"], f"{source}.subjects")
    if any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in subjects.items()
    ):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source}.subjects must map strings to strings"
        )
    mutable = tuple(_list(value["mutableImages"], f"{source}.mutableImages"))
    placeholders = tuple(
        _list(value["placeholderImages"], f"{source}.placeholderImages")
    )
    if any(not isinstance(item, str) for item in (*mutable, *placeholders)):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} image lists must contain strings"
        )
    record = ArtifactVerification(
        True,
        value["authoritativeDigest"],
        dict(subjects),
        mutable,
        placeholders,
    )
    try:
        parse_digest(record.authoritative_digest)
        for subject in record.subjects.values():
            digest_from_subject(subject)
    except (TypeError, ValueError) as exc:
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID",
            f"{source} contains an invalid subject digest",
        ) from exc
    if record.to_dict() != dict(value):
        raise ExecutionBundleError(
            "BUNDLE_RECORD_INVALID", f"{source} is not canonical verification JSON"
        )
    return record


def _verify_record_relationships(bundle: ExecutionBundle) -> None:
    if bundle.plan is not None and bundle.plan.run_id != bundle.run_id:
        raise ExecutionBundleError(
            "BUNDLE_RUN_ID_MISMATCH",
            "execution-plan.json runId differs from its run directory",
        )
    run = bundle.execution_run
    if run is not None and run.run_id != bundle.run_id:
        raise ExecutionBundleError(
            "BUNDLE_RUN_ID_MISMATCH", "report runId differs from its run directory"
        )
    if bundle.plan is not None and run is not None:
        if run.execution_profile != bundle.plan.profile.value:
            raise ExecutionBundleError(
                "BUNDLE_RECORD_MISMATCH",
                "execution plan and report profiles differ",
            )
        planned = tuple(stage.stage_id for stage in bundle.plan.stages)
        reported = tuple(stage.stage_id for stage in run.stage_results)
        exact_stage_order = (
            planned == reported
            if run.final_status.value == "PASSED"
            else reported == planned[: len(reported)]
        )
        if not exact_stage_order:
            raise ExecutionBundleError(
                "BUNDLE_RECORD_MISMATCH",
                "report stages are not the exact executed prefix of the plan",
            )
    if run is not None and run.final_status.value == "PASSED":
        failures = profile_policy(run.execution_profile).required_stage_failures(
            run.stage_results
        )
        if failures:
            raise ExecutionBundleError(
                "FALSE_COMPLETION_CLAIM",
                f"PASSED report has unsatisfied required stages: {failures}",
            )

    artifact = bundle.artifact
    if artifact is not None and bundle.plan is not None:
        intent = bundle.plan.artifact_intent
        expected_repository = f"{intent.registry}/{intent.repository}"
        platform = f"{artifact.operating_system}/{artifact.architecture}"
        if (
            artifact.repository != expected_repository
            or artifact.tag != intent.requested_tag
            or artifact.source_revision != intent.source_revision
            or artifact.build_plan_hash != bundle.plan.build_plan_hash
            or not any(
                candidate == platform or candidate.startswith(platform + "/")
                for candidate in intent.platforms
            )
        ):
            raise ExecutionBundleError(
                "BUNDLE_RECORD_MISMATCH",
                "artifact identity does not match execution-plan.json",
            )
    if artifact is not None and run is not None:
        if artifact.source_revision != run.source_revision:
            raise ExecutionBundleError(
                "BUNDLE_RECORD_MISMATCH",
                "artifact source revision differs from the execution report",
            )

    if run is not None:
        if run.schema_version == EXECUTION_EVIDENCE_SCHEMA_VERSION:
            expected_checksum_paths = (
                ("SHA256SUMS", "checksums.json")
                if "checksums.json" in bundle.checksums
                else ("SHA256SUMS",)
            )
            if run.evidence_checksum_paths != expected_checksum_paths:
                raise ExecutionBundleError(
                    "BUNDLE_CHECKSUM_MANIFEST_MISMATCH",
                    "reported checksum manifests do not match the bundle layout",
                    evidence_path="report.json",
                )
            if "checksums.json" in run.evidence_checksum_paths:
                from devops_stack_composer.evidence_bundle import (
                    EvidenceBundleError,
                    verify_evidence_bundle,
                )

                try:
                    verify_evidence_bundle(bundle.store)
                except EvidenceBundleError as exc:
                    raise ExecutionBundleError(
                        "BUNDLE_CHECKSUM_MANIFEST_MISMATCH",
                        "checksums.json is not a valid canonical bundle manifest",
                        evidence_path="checksums.json",
                    ) from exc
            for relative_path, expected_digest in run.evidence_checksums.items():
                inventory_digest = bundle.checksums.get(relative_path)
                if inventory_digest is None:
                    raise ExecutionBundleError(
                        "EVIDENCE_FILE_MISSING",
                        "reported evidence checksum path is absent from SHA256SUMS: "
                        f"{relative_path}",
                    )
                if inventory_digest != expected_digest:
                    raise ExecutionBundleError(
                        "EVIDENCE_CHECKSUM_MISMATCH",
                        "reported evidence checksum differs from SHA256SUMS: "
                        f"{relative_path}",
                    )
                _checked_bytes(bundle.store, bundle.checksums, relative_path)
        for stage in run.stage_results:
            for relative_path in stage.evidence_paths:
                if relative_path not in bundle.checksums:
                    raise ExecutionBundleError(
                        "EVIDENCE_FILE_MISSING",
                        "reported evidence path is absent from SHA256SUMS: "
                        f"{relative_path}",
                    )
    if bundle.supply_chain is not None:
        for relative_path in (
            bundle.supply_chain.sbom_path,
            bundle.supply_chain.vulnerability_report_path,
            bundle.supply_chain.provenance_path,
        ):
            if relative_path not in bundle.checksums:
                raise ExecutionBundleError(
                    "EVIDENCE_FILE_MISSING",
                    f"supply-chain evidence is absent from SHA256SUMS: {relative_path}",
                )
    if bundle.deployment is not None:
        for relative_path in bundle.deployment.diagnostics_paths:
            if relative_path not in bundle.checksums:
                raise ExecutionBundleError(
                    "EVIDENCE_FILE_MISSING",
                    f"deployment diagnostic is absent from SHA256SUMS: {relative_path}",
                )


def _deployment_manifest_path(bundle: ExecutionBundle) -> str:
    assert bundle.deployment is not None
    expected_hash = bundle.deployment.manifest_hash
    preferred = "kubernetes/resolved.yaml"
    if preferred in bundle.checksums:
        if bundle.checksums[preferred] != expected_hash:
            raise ExecutionBundleError(
                "KUBERNETES_MANIFEST_HASH_MISMATCH",
                f"{preferred} differs from deployment.json manifestHash",
            )
        return preferred
    candidates = tuple(
        path
        for path, digest in bundle.checksums.items()
        if path.startswith("kubernetes/")
        and path.endswith((".yaml", ".yml"))
        and digest == expected_hash
    )
    if len(candidates) != 1:
        raise ExecutionBundleError(
            "KUBERNETES_MANIFEST_HASH_MISMATCH",
            "deployment.json must identify exactly one checksummed resolved manifest",
        )
    return candidates[0]
