"""Fail-closed orchestration for build-once execution profiles."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from devops_stack_composer import __version__
from devops_stack_composer.build_once import (
    BuildOnceExecutor,
    BuildRequest,
    BuildResult,
)
from devops_stack_composer.composition import Composition
from devops_stack_composer.config import canonical_hash
from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.evidence_store import EvidenceStore
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
from devops_stack_composer.filesystem import (
    contained_path,
    normalize_relative_path,
    sha256_file,
)
from devops_stack_composer.kind_cluster import KindCluster
from devops_stack_composer.kubernetes_runtime import render_resolved_environment
from devops_stack_composer.oci import validate_tag
from devops_stack_composer.policies import (
    ValidationProfile,
    VulnerabilityAllowlistEntry,
    VulnerabilityPolicy,
    profile_policy,
)
from devops_stack_composer.registry import EphemeralRegistry
from devops_stack_composer.report import redact_sensitive
from devops_stack_composer.supply_chain import SupplyChainGenerator


Clock = Callable[[], datetime]
SourceRevisionResolver = Callable[[Path], str]
RegistryFactory = Callable[[str], EphemeralRegistry]
KindFactory = Callable[[str], KindCluster]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class ExecutionError(DevOpsStackError):
    """A stable execution failure that can be recorded without leaking input."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ExecutionOptions:
    """Explicit operator choices for one execution run."""

    environment: str = "staging"
    profile: str | ValidationProfile = ValidationProfile.STATIC
    work_directory: str = ".devops-stack/runs"
    image_tag: str | None = None
    approve_production: bool = False
    keep_resources: bool = False
    run_id: str | None = None

    def __post_init__(self) -> None:
        if self.environment not in {"dev", "staging", "production"}:
            raise ValueError("environment must be dev, staging, or production")
        object.__setattr__(self, "profile", ValidationProfile.parse(self.profile))
        object.__setattr__(
            self,
            "work_directory",
            normalize_relative_path(self.work_directory),
        )
        if self.image_tag is not None:
            validate_tag(self.image_tag)
        if not isinstance(self.approve_production, bool):
            raise ValueError("approve_production must be boolean")
        if not isinstance(self.keep_resources, bool):
            raise ValueError("keep_resources must be boolean")
        if self.run_id is not None and not isinstance(self.run_id, str):
            raise ValueError("run_id must be a string")


@dataclass(frozen=True)
class ExecutionResult:
    """Persisted result returned even when a bounded stage fails."""

    store: EvidenceStore
    plan: ExecutionPlan
    run: ExecutionRun
    verification: ArtifactVerification | None = None
    retained_resources: bool = False

    @property
    def passed(self) -> bool:
        return self.run.final_status == StageStatus.PASSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run.run_id,
            "runDirectory": self.store.relative_root,
            "finalStatus": self.run.final_status.value,
            "failureReason": self.run.failure_reason,
            "artifact": (
                self.run.artifact_record.to_dict()
                if self.run.artifact_record is not None
                else None
            ),
            "verification": (
                self.verification.to_dict() if self.verification is not None else None
            ),
            "retainedResources": self.retained_resources,
        }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("execution clock must return timezone-aware datetimes")
    utc = value.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds")
    return rendered.replace("+00:00", "Z")


def _default_source_revision(project: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            cwd=project,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ExecutionError(
            "SOURCE_REVISION_UNAVAILABLE",
            f"Git source revision could not be read ({type(exc).__name__})",
        ) from exc
    revision = result.stdout.strip()
    if result.returncode != 0 or len(revision) != 40:
        raise ExecutionError(
            "SOURCE_REVISION_UNAVAILABLE",
            "execution requires a full Git commit for the project source",
        )
    try:
        int(revision, 16)
    except ValueError as exc:
        raise ExecutionError(
            "SOURCE_REVISION_UNAVAILABLE",
            "Git returned a malformed source revision",
        ) from exc
    if revision != revision.lower():
        raise ExecutionError(
            "SOURCE_REVISION_UNAVAILABLE",
            "Git source revision must use lowercase hexadecimal",
        )
    return revision


def vulnerability_policy_from_model(value: Mapping[str, Any]) -> VulnerabilityPolicy:
    """Translate both the v0.1 scan shape and the v0.2 policy shape."""

    current = value.get("vulnerability")
    if isinstance(current, Mapping):
        allowlist = tuple(
            VulnerabilityAllowlistEntry(
                vulnerability_id=item["id"],
                package=item["package"],
                reason=item["reason"],
                owner=item["owner"],
                expires_on=item["expiresAt"],
            )
            for item in current.get("allowlist", ())
        )
        return VulnerabilityPolicy(
            severities=tuple(current["severities"]),
            maximum_allowed=current["maximumAllowed"],
            ignore_unfixed=current["ignoreUnfixed"],
            allowlist=allowlist,
        )

    legacy = value.get("scan")
    if not isinstance(legacy, Mapping):
        raise ExecutionError(
            "VULNERABILITY_POLICY_MISSING",
            "supply-chain execution requires a vulnerability or scan policy",
        )
    threshold = legacy.get("failOn")
    severities = {
        "critical": ("CRITICAL",),
        "high": ("HIGH", "CRITICAL"),
        "medium": ("MEDIUM", "HIGH", "CRITICAL"),
        "never": ("UNKNOWN",),
    }.get(threshold)
    if severities is None:
        raise ExecutionError(
            "VULNERABILITY_POLICY_INVALID",
            "legacy scan.failOn is not supported",
        )
    # The legacy `never` form remains non-blocking for known scanner severities.
    maximum = 2**31 - 1 if threshold == "never" else 0
    return VulnerabilityPolicy(
        severities=severities,
        maximum_allowed=maximum,
        ignore_unfixed=False,
    )


def _safe_failure(error: BaseException) -> str:
    value = redact_sensitive(str(error))
    rendered = value if isinstance(value, str) else type(error).__name__
    rendered = rendered.strip().replace("\x00", "")
    return rendered[-4000:] or type(error).__name__


def _safe_log(*values: bytes | str) -> str:
    pieces: list[str] = []
    for value in values:
        if isinstance(value, bytes):
            pieces.append(value.decode("utf-8", errors="replace"))
        else:
            pieces.append(value)
    redacted = redact_sensitive("\n".join(pieces))
    if not isinstance(redacted, str):  # pragma: no cover - string input invariant
        return ""
    return redacted.replace("\x00", "")[-16000:]


class ExecutionOrchestrator:
    """Execute a profile once and persist independently verifiable evidence."""

    def __init__(
        self,
        *,
        build_executor: BuildOnceExecutor | None = None,
        supply_chain_generator: SupplyChainGenerator | None = None,
        registry_factory: RegistryFactory = EphemeralRegistry,
        kind_factory: KindFactory = KindCluster,
        kubernetes_executor: object | None = None,
        schema_command_runner: CommandRunner | None = None,
        source_revision_resolver: SourceRevisionResolver | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._build_executor = build_executor or BuildOnceExecutor()
        self._supply_chain_generator = supply_chain_generator or SupplyChainGenerator()
        self._registry_factory = registry_factory
        self._kind_factory = kind_factory
        self._kubernetes_executor = kubernetes_executor
        self._schema_command_runner = schema_command_runner or subprocess.run
        self._source_revision_resolver = (
            source_revision_resolver or _default_source_revision
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> str:
        return _timestamp(self._clock())

    @staticmethod
    def _artifact(composition: Composition, path: str) -> str:
        matches = [artifact.content for artifact in composition.artifacts if artifact.path == path]
        if len(matches) != 1:
            raise ExecutionError(
                "GENERATED_ARTIFACT_MISSING",
                f"execution requires exactly one generated {path}",
            )
        return matches[0]

    @staticmethod
    def _resolved_artifact(
        result: BuildResult,
        *,
        source_revision: str,
        build_plan_hash: str,
        registry_endpoint: str,
    ) -> ResolvedArtifact:
        if len(result.platforms) != 1:
            raise ExecutionError(
                "MULTI_PLATFORM_EXECUTION_UNSUPPORTED",
                "v0.2 runtime identity requires exactly one platform manifest",
            )
        platform = result.platforms[0]
        if platform.digest != result.digest:
            raise ExecutionError(
                "ARTIFACT_DIGEST_MISMATCH",
                "the top-level manifest and selected platform digest differ",
            )
        config_digest = result.config_digest or platform.config_digest
        if config_digest != platform.config_digest:
            raise ExecutionError(
                "ARTIFACT_DIGEST_MISMATCH",
                "Buildx and registry config digests differ",
            )
        return ResolvedArtifact(
            immutable_image_reference=result.immutable_reference,
            repository=result.repository,
            tag=result.tag,
            manifest_digest=result.digest,
            platform_digest=platform.digest,
            media_type=result.media_type or platform.media_type,
            architecture=platform.architecture,
            operating_system=platform.operating_system,
            image_size=result.size or platform.size,
            config_digest=config_digest,
            source_revision=source_revision,
            build_plan_hash=build_plan_hash,
            created_by_tool_version=__version__,
            registry_endpoint=registry_endpoint,
            build_invocation_count=result.build_invocation_count,
        )

    def _stage(
        self,
        plan: ExecutionPlan,
        stage_id: str,
        status: StageStatus,
        *,
        started: str | None = None,
        command: Sequence[str] = (),
        tool: str | None = None,
        output: str | None = None,
        evidence_paths: Sequence[str] = (),
        failure_reason: str | None = None,
        remediation: str | None = None,
    ) -> StageResult:
        stage = next(item for item in plan.stages if item.stage_id == stage_id)
        return StageResult(
            stage_id=stage_id,
            description=stage.description,
            status=status,
            start_time=started or self._now(),
            end_time=self._now(),
            command=tuple(command),
            tool=tool,
            sanitized_output=output,
            evidence_paths=tuple(evidence_paths),
            failure_reason=failure_reason,
            remediation=remediation,
        )

    @staticmethod
    def _preflight(composition: Composition, options: ExecutionOptions) -> None:
        if not composition.validation.passed:
            raise ExecutionError(
                "STATIC_VALIDATION_FAILED",
                "composition validation must pass before execution side effects",
            )
        profile = options.profile
        assert isinstance(profile, ValidationProfile)
        if profile != ValidationProfile.STATIC:
            if len(composition.loaded_config.model.architectures) != 1:
                raise ExecutionError(
                    "MULTI_PLATFORM_EXECUTION_UNSUPPORTED",
                    "v0.2 execution accepts exactly one configured platform",
                )
            model = composition.loaded_config.model
            if model.registry["repository"] != model.image_repository:
                raise ExecutionError(
                    "ARTIFACT_REPOSITORY_MISMATCH",
                    "registry.repository must equal image.repository for resolved execution",
                )
            if profile in {ValidationProfile.KIND_E2E, ValidationProfile.RELEASE}:
                if model.registry["mode"] != "ephemeral-local":
                    raise ExecutionError(
                        "KIND_REGISTRY_MODE_UNSUPPORTED",
                        "v0.2 kind execution requires registry.mode ephemeral-local",
                    )
        if options.environment == "production" and profile in {
            ValidationProfile.KIND_E2E,
            ValidationProfile.RELEASE,
        } and not options.approve_production:
            raise ExecutionError(
                "PRODUCTION_APPROVAL_REQUIRED",
                "production apply requires --approve-production",
            )
        if options.keep_resources and profile == ValidationProfile.RELEASE:
            raise ExecutionError(
                "RELEASE_RESOURCE_RETENTION_FORBIDDEN",
                "release validation cannot retain run-owned resources",
            )

    def _write_build_inputs(self, store: EvidenceStore, composition: Composition) -> Path:
        dockerfile = store.write_text(
            "inputs/Dockerfile",
            self._artifact(composition, "docker/Dockerfile"),
        )
        ignore = [
            artifact.content
            for artifact in composition.artifacts
            if artifact.path == "docker/Dockerfile.dockerignore"
        ]
        if len(ignore) > 1:
            raise ExecutionError(
                "GENERATED_ARTIFACT_DUPLICATED",
                "generated Dockerfile ignore input is duplicated",
            )
        if ignore:
            store.write_text("inputs/Dockerfile.dockerignore", ignore[0])
        return dockerfile

    @staticmethod
    def _report_markdown(
        run: ExecutionRun,
        plan: ExecutionPlan,
        composition: Composition,
        verification: ArtifactVerification | None,
        *,
        retained_resources: bool,
    ) -> str:
        artifact = run.artifact_record
        supply = run.supply_chain_evidence
        deployment = run.deployment_evidence
        lines = [
            "# DevOps Stack Execution Report",
            "",
            f"Overall result: **{run.final_status.value}**",
            "",
            f"- Run: `{run.run_id}`",
            f"- Profile: `{run.execution_profile}`",
            f"- Source commit: `{run.source_revision}`",
            f"- Configuration hash: `{run.config_hash}`",
            f"- Build plan hash: `{plan.build_plan_hash}`",
            f"- Run-owned resources retained: `{'yes' if retained_resources else 'no'}`",
            "",
            "## Locked template revisions",
            "",
        ]
        for key in ("docker", "jenkins", "kubernetes"):
            lines.append(f"- {key}: `{composition.lock.pin(key).commit}`")
        if artifact is not None:
            lines.extend(
                [
                    "",
                    "## Authoritative artifact",
                    "",
                    f"- Repository: `{artifact.repository}`",
                    f"- Informational tag: `{artifact.tag}`",
                    f"- Digest: `{artifact.manifest_digest}`",
                    f"- Platform: `{artifact.operating_system}/{artifact.architecture}`",
                    f"- Config digest: `{artifact.config_digest}`",
                    f"- Build invocations: `{artifact.build_invocation_count}`",
                ]
            )
        if supply is not None:
            lines.extend(
                [
                    "",
                    "## Supply-chain evidence",
                    "",
                    f"- SBOM: `{supply.sbom_path}` (`{supply.sbom_hash}`)",
                    f"- Vulnerability report: `{supply.vulnerability_report_path}` (`{supply.vulnerability_report_hash}`)",
                    f"- Vulnerability policy passed: `{str(bool(supply.policy_result.get('passed'))).lower()}`",
                    f"- Provenance: `{supply.provenance_path}` (`{supply.provenance_hash}`)",
                    f"- Verification: `{supply.verification_status}`",
                ]
            )
        if deployment is not None:
            lines.extend(
                [
                    "",
                    "## Kubernetes evidence",
                    "",
                    f"- Environment: `{deployment.environment}`",
                    f"- Namespace: `{deployment.namespace}`",
                    f"- Deployed image: `{deployment.deployed_image_reference}`",
                    f"- Pod image ID: `{deployment.actual_pod_image_id}`",
                    f"- Rollout: `{deployment.rollout_status}`",
                    f"- Health: `{deployment.health_endpoint_result.get('status')}`",
                    f"- Readiness: `{deployment.readiness_endpoint_result.get('status')}`",
                    f"- Rollback: `{deployment.rollback_result}`",
                ]
            )
        if verification is not None:
            lines.extend(
                [
                    "",
                    "## Artifact identity",
                    "",
                    f"All recorded subjects resolve to `{verification.authoritative_digest}`.",
                ]
            )
        lines.extend(
            [
                "",
                "## Stage results",
                "",
                "| Stage | Status | Evidence |",
                "| --- | --- | --- |",
            ]
        )
        for stage in run.stage_results:
            evidence = ", ".join(f"`{path}`" for path in stage.evidence_paths) or "none"
            lines.append(f"| `{stage.stage_id}` | {stage.status.value} | {evidence} |")
        lines.extend(
            [
                "",
                "## Assurance limits",
                "",
                "- Local provenance is unsigned, unattached file evidence; its SHA-256 checksum is not a signature.",
                "- kind proves the recorded local Kubernetes API, kubelet, Service, and rollback observations only; it is not production-cluster certification.",
                "- Vulnerability results reflect the scanner database metadata recorded at execution time and do not prove absence of vulnerabilities.",
                "- The generated Jenkins pipeline is statically validated; no Jenkins controller executed it in v0.2.",
            ]
        )
        if run.failure_reason:
            lines.extend(["", "## Failure", "", run.failure_reason])
        return "\n".join(lines).rstrip() + "\n"

    def _write_final_records(
        self,
        *,
        store: EvidenceStore,
        plan: ExecutionPlan,
        run: ExecutionRun,
        composition: Composition,
        verification: ArtifactVerification | None,
        retained_resources: bool,
    ) -> None:
        store.write_json("execution-evidence.json", run.to_dict())
        store.write_json("report.json", run.to_dict())
        store.write_text(
            "report.md",
            self._report_markdown(
                run,
                plan,
                composition,
                verification,
                retained_resources=retained_resources,
            ),
        )
        store.write_checksums()
        store.verify_checksums()

    def execute(
        self,
        composition: Composition,
        options: ExecutionOptions,
    ) -> ExecutionResult:
        """Execute the selected profile and close its checksum inventory."""

        if not isinstance(composition, Composition):
            raise ValueError("composition must be a Composition")
        if not isinstance(options, ExecutionOptions):
            raise ValueError("options must be ExecutionOptions")
        self._preflight(composition, options)

        model = composition.loaded_config.model
        profile = options.profile
        assert isinstance(profile, ValidationProfile)
        source_revision = self._source_revision_resolver(composition.project)
        store = EvidenceStore.create(
            composition.project,
            work_directory=options.work_directory,
            run_id=options.run_id,
        )
        started_at = self._now()
        selected_tag = options.image_tag or source_revision[:12]
        validate_tag(selected_tag)

        stage_results: dict[str, StageResult] = {}
        artifact: ResolvedArtifact | None = None
        supply_chain: SupplyChainEvidence | None = None
        deployment: DeploymentEvidence | None = None
        verification: ArtifactVerification | None = None
        registry: EphemeralRegistry | None = None
        cluster: KindCluster | None = None
        registry_endpoint = model.image_registry
        repository_path = model.image_repository
        retained_resources = False
        failure_reason: str | None = None
        failure_status = StageStatus.FAILED
        current_stage = "config-schema"
        plan: ExecutionPlan | None = None

        try:
            static_time = self._now()
            for stage_id in (
                "config-schema",
                "template-lock",
                "adapter-contracts",
                "generated-files",
            ):
                current_stage = stage_id
                # The Composition constructor path already ran the schema, exact
                # source locks, adapter contracts, and deterministic rendering.
                # A passed stage here is therefore backed by executable validation.
                stage_results[stage_id] = StageResult(
                    stage_id=stage_id,
                    description={
                        "config-schema": "Validate the declarative configuration schema",
                        "template-lock": "Resolve exact read-only template revisions",
                        "adapter-contracts": "Validate Docker, Jenkins, and Kubernetes contracts",
                        "generated-files": "Render deterministic static artifacts",
                    }[stage_id],
                    status=StageStatus.PASSED,
                    start_time=static_time,
                    end_time=self._now(),
                )

            if profile != ValidationProfile.STATIC:
                current_stage = "registry-lifecycle"
                registry_started = self._now()
                if model.registry["mode"] == "ephemeral-local":
                    registry = self._registry_factory(store.run_id)
                    handle = registry.start()
                    registry_endpoint = f"localhost:{handle.host_port}"
                    repository_path = model.registry["repository"]
                    store.write_json("registry-ownership.json", handle.to_dict())
                    registry_output = (
                        "Isolated loopback registry started for local test execution"
                    )
                    registry_evidence = ("registry-ownership.json",)
                else:
                    registry_endpoint = model.registry["host"]
                    repository_path = model.registry["repository"]
                    registry_output = (
                        "Existing registry selected; authentication remains delegated "
                        "to the Docker credential helper"
                    )
                    registry_evidence = ()
            else:
                registry_started = self._now()
                registry_output = "No execution registry is required by the static profile"
                registry_evidence = ()

            dockerfile = self._write_build_inputs(store, composition)
            dockerfile_relative = dockerfile.relative_to(composition.project).as_posix()
            intent = ArtifactIntent(
                application_name=model.application_name,
                registry=registry_endpoint,
                repository=repository_path,
                requested_tag=selected_tag,
                platforms=tuple(model.architectures),
                source_revision=source_revision,
                build_context=model.build_context,
                dockerfile=dockerfile_relative,
                build_arguments={},
                target_stage=None,
                template_revision=composition.lock.pin("docker").commit,
                normalized_model_hash=canonical_hash(model.contract()),
            )
            plan = ExecutionPlan.create(
                run_id=store.run_id,
                profile=profile,
                environment=options.environment,
                artifact_intent=intent,
                production_apply_approved=options.approve_production,
            )
            store.write_json("execution-plan.json", plan.to_dict())

            if profile == ValidationProfile.STATIC:
                # The static profile deliberately performs no image or cluster side effect.
                pass
            else:
                stage_results["registry-lifecycle"] = self._stage(
                    plan,
                    "registry-lifecycle",
                    StageStatus.PASSED,
                    started=registry_started,
                    tool="docker",
                    output=registry_output,
                    evidence_paths=registry_evidence,
                )

                current_stage = "build-once"
                build_started = self._now()
                build_result = self._build_executor.execute(
                    BuildRequest(
                        project=composition.project,
                        context=(
                            composition.project
                            if model.build_context == "."
                            else contained_path(composition.project, model.build_context)
                        ),
                        dockerfile=dockerfile,
                        repository=f"{registry_endpoint}/{repository_path}",
                        tag=selected_tag,
                        platforms=tuple(model.architectures),
                        metadata_path=store.path("build-metadata.json"),
                        invocation_marker=store.path("build-invocation.txt"),
                        oci_title=model.application_name,
                        oci_description=(
                            f"Build-once execution image for {model.application_name}"
                        ),
                        oci_source=f"urn:devops-stack:git:{source_revision}",
                        oci_revision=source_revision,
                        oci_created=started_at,
                    )
                )
                build_finished = self._now()
                store.write_text(
                    "logs/build.log",
                    _safe_log(build_result.stdout, build_result.stderr),
                )
                stage_results["build-once"] = self._stage(
                    plan,
                    "build-once",
                    StageStatus.PASSED,
                    started=build_started,
                    command=("docker", "buildx", "build", "--push", "<project-context>"),
                    tool="docker-buildx",
                    output="One direct-to-registry Buildx invocation completed",
                    evidence_paths=(
                        "build-invocation.txt",
                        "build-metadata.json",
                        "logs/build.log",
                    ),
                )

                current_stage = "resolve-digest"
                resolve_started = self._now()
                artifact = self._resolved_artifact(
                    build_result,
                    source_revision=source_revision,
                    build_plan_hash=plan.build_plan_hash,
                    registry_endpoint=registry_endpoint,
                )
                validate_artifact_contract(artifact)
                self._build_executor.verify_tag_unchanged(
                    build_result,
                    project=composition.project,
                )
                store.write_json("artifact.json", artifact.to_dict())
                stage_results["resolve-digest"] = self._stage(
                    plan,
                    "resolve-digest",
                    StageStatus.PASSED,
                    started=resolve_started,
                    command=("docker", "buildx", "imagetools", "inspect", "--raw", "<tag>"),
                    tool="docker-buildx",
                    output=f"Registry bytes resolved to {artifact.manifest_digest}",
                    evidence_paths=("artifact.json", "build-metadata.json"),
                )

                current_stage = "sbom"
                supply_started = self._now()
                policy = vulnerability_policy_from_model(model.supply_chain)
                supply_chain = self._supply_chain_generator.generate(
                    run_root=store.root,
                    artifact=artifact,
                    policy=policy,
                    builder_id=(
                        "https://github.com/k4nul/devops-stack-composer/"
                        "build-once/v0.2"
                    ),
                    build_started_on=build_started,
                    build_finished_on=build_finished,
                )
                store.write_json("supply-chain.json", supply_chain.to_dict())
                stage_results["sbom"] = self._stage(
                    plan,
                    "sbom",
                    StageStatus.PASSED,
                    started=supply_started,
                    command=("syft", "<immutable-reference>", "-o", "spdx-json@2.3"),
                    tool=supply_chain.sbom_generator,
                    output="SPDX 2.3 package inventory validated against the immutable subject",
                    evidence_paths=(supply_chain.sbom_path, "supply-chain.json"),
                )
                policy_passed = supply_chain.policy_result.get("passed") is True
                stage_results["vulnerability-scan"] = self._stage(
                    plan,
                    "vulnerability-scan",
                    StageStatus.PASSED if policy_passed else StageStatus.FAILED,
                    started=supply_started,
                    command=("trivy", "image", "--format", "json", "<immutable-reference>"),
                    tool=f"trivy-{supply_chain.scanner_version}",
                    output="Trivy report and database metadata were structurally validated",
                    evidence_paths=(
                        supply_chain.vulnerability_report_path,
                        "supply-chain.json",
                    ),
                    failure_reason=(
                        None
                        if policy_passed
                        else "VULNERABILITY_POLICY_FAILED: scanner findings exceeded policy"
                    ),
                    remediation=(
                        None
                        if policy_passed
                        else "Remediate findings or add a scoped, owned, expiring exception"
                    ),
                )
                stage_results["provenance"] = self._stage(
                    plan,
                    "provenance",
                    StageStatus.PASSED,
                    started=supply_started,
                    tool="devops-stack-composer",
                    output=(
                        "Unsigned and unattached SLSA v1 file evidence generated; "
                        "checksum is not a signature"
                    ),
                    evidence_paths=(supply_chain.provenance_path, "supply-chain.json"),
                )
                if not policy_passed:
                    current_stage = "vulnerability-scan"
                    raise ExecutionError(
                        "VULNERABILITY_POLICY_FAILED",
                        "scanner findings exceeded the configured policy",
                    )

                current_stage = "artifact-contract"
                contract_started = self._now()
                self._build_executor.verify_tag_unchanged(
                    build_result,
                    project=composition.project,
                )
                verification = validate_artifact_contract(artifact, supply_chain)
                store.write_json("verification.json", verification.to_dict())
                stage_results["artifact-contract"] = self._stage(
                    plan,
                    "artifact-contract",
                    StageStatus.PASSED,
                    started=contract_started,
                    tool="devops-stack-composer",
                    output=(
                        f"Build, registry, SBOM, scan, and provenance resolve to "
                        f"{verification.authoritative_digest}"
                    ),
                    evidence_paths=(
                        "artifact.json",
                        "supply-chain.json",
                        "verification.json",
                    ),
                )

                if profile in {ValidationProfile.KIND_E2E, ValidationProfile.RELEASE}:
                    current_stage = "kubernetes-schema"
                    render_started = self._now()
                    configured = tuple(model.kubernetes_e2e["serverSideDryRunEnvironments"])
                    environments = tuple(
                        dict.fromkeys((*configured, options.environment))
                    )
                    manifests = tuple(
                        render_resolved_environment(
                            composition.artifacts,
                            model,
                            environment,
                            artifact.immutable_image_reference,
                        )
                        for environment in environments
                    )
                    manifest_paths: list[str] = []
                    for manifest in manifests:
                        relative = f"kubernetes/{manifest.environment}.yaml"
                        store.write_text(relative, manifest.content)
                        manifest_paths.append(relative)
                    schema_result = self._schema_command_runner(
                        [
                            "kubeconform",
                            "-strict",
                            "-summary",
                            *[str(store.path(path)) for path in manifest_paths],
                        ],
                        cwd=composition.project,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=120,
                    )
                    if schema_result.returncode != 0:
                        raise ExecutionError(
                            "KUBERNETES_SCHEMA_FAILED",
                            "kubeconform rejected one or more resolved manifests",
                        )
                    schema_output = _safe_log(
                        schema_result.stdout or "",
                        schema_result.stderr or "",
                    )
                    store.write_text("logs/kubeconform.log", schema_output)
                    stage_results["kubernetes-schema"] = self._stage(
                        plan,
                        "kubernetes-schema",
                        StageStatus.PASSED,
                        started=render_started,
                        command=("kubeconform", "-strict", "-summary", "kubernetes/*.yaml"),
                        tool="kubeconform",
                        output=schema_output[-4000:] or "Resolved Kubernetes schemas passed",
                        evidence_paths=(*manifest_paths, "logs/kubeconform.log"),
                    )

                    current_stage = "server-side-dry-run"
                    cluster_started = self._now()
                    assert registry is not None
                    cluster = self._kind_factory(store.run_id)
                    cluster_handle = cluster.create()
                    store.write_json("kind-cluster-ownership.json", cluster_handle.to_dict())
                    cluster.configure_local_registry(registry)
                    kubeconfig = cluster.kubeconfig_path
                    if kubeconfig is None:
                        raise ExecutionError(
                            "KUBECONFIG_UNAVAILABLE",
                            "owned kind cluster has no private runtime kubeconfig",
                        )
                    if self._kubernetes_executor is None:
                        from devops_stack_composer.kubernetes_execution import (
                            KubernetesExecutor,
                        )

                        kubernetes_executor = KubernetesExecutor()
                    else:
                        kubernetes_executor = self._kubernetes_executor
                    from devops_stack_composer.kubernetes_execution import (
                        KubernetesExecutionRequest,
                    )

                    environment_model = model.environment(options.environment)
                    request = KubernetesExecutionRequest(
                        kubeconfig_path=kubeconfig,
                        manifests=manifests,
                        environment=options.environment,
                        deployment_name=model.application_name,
                        service_name=model.service_name,
                        service_port=environment_model.service_port,
                        health_path=model.kubernetes_e2e["healthPath"],
                        readiness_path=model.kubernetes_e2e["readinessPath"],
                        artifact=artifact,
                        cluster_type="kind",
                        cluster_identifier=cluster_handle.name,
                        run_id=store.run_id,
                        rollout_timeout_seconds=model.kubernetes_e2e[
                            "rolloutTimeoutSeconds"
                        ],
                        approve_production=options.approve_production,
                    )
                    kubernetes_result = kubernetes_executor.execute(request)
                    for record in kubernetes_result.diagnostics:
                        store.write_text(record.path, record.content)
                    deployment = kubernetes_result.deployment
                    store.write_json("deployment.json", deployment.to_dict())
                    store.write_json(
                        "kubernetes/execution-result.json",
                        kubernetes_result.to_dict(),
                    )
                    verification = validate_artifact_contract(
                        artifact,
                        supply_chain,
                        deployment,
                    )
                    store.write_json(
                        "verification.json",
                        verification.to_dict(),
                        overwrite=True,
                    )
                    kubernetes_evidence = (
                        *manifest_paths,
                        "deployment.json",
                        "kubernetes/execution-result.json",
                        *deployment.diagnostics_paths,
                    )
                    for stage_id in (
                        "server-side-dry-run",
                        "deployment",
                        "rollout",
                        "pod-image",
                        "health",
                        "readiness",
                        "rollback",
                    ):
                        stage_results[stage_id] = self._stage(
                            plan,
                            stage_id,
                            StageStatus.PASSED,
                            started=cluster_started,
                            tool="kubectl",
                            output={
                                "server-side-dry-run": (
                                    "Every configured environment was accepted by the "
                                    "identified Kubernetes API server"
                                ),
                                "deployment": "Selected digest-pinned manifest was applied",
                                "rollout": "Deployment became available with expected replicas",
                                "pod-image": (
                                    f"Observed pod image ID matched {artifact.manifest_digest}"
                                ),
                                "health": "Service /health contract returned a successful response",
                                "readiness": "Service /ready contract returned a successful response",
                                "rollback": (
                                    "Same-digest readiness failure was observed, undone, and "
                                    "recovered"
                                ),
                            }[stage_id],
                            evidence_paths=kubernetes_evidence,
                        )

        except BaseException as error:
            failure_reason = _safe_failure(error)
            if getattr(error, "code", None) == "REQUIRED_TOOL_MISSING":
                failure_status = StageStatus.BLOCKED_MISSING_REQUIRED_TOOL
            if plan is not None and current_stage in {
                stage.stage_id for stage in plan.stages
            } and current_stage not in stage_results:
                stage_results[current_stage] = self._stage(
                    plan,
                    current_stage,
                    failure_status,
                    failure_reason=failure_reason,
                )
        finally:
            if plan is None:
                # No external side effect occurs before a plan can be created except
                # an owned registry.  Clean that boundary and surface the original
                # error instead of manufacturing an unverifiable partial bundle.
                if registry is not None:
                    try:
                        registry.cleanup()
                    except BaseException:
                        pass
                raise ExecutionError(
                    "EXECUTION_PLAN_UNAVAILABLE",
                    failure_reason or "execution plan could not be created",
                )

            if "cleanup" in {stage.stage_id for stage in plan.stages}:
                cleanup_started = self._now()
                cleanup_failure: str | None = None
                current_stage = "cleanup"
                if options.keep_resources and (cluster is not None or registry is not None):
                    if cluster is not None:
                        cluster.detach()
                    retained_resources = True
                    stage_results["cleanup"] = self._stage(
                        plan,
                        "cleanup",
                        StageStatus.NOT_APPLICABLE,
                        started=cleanup_started,
                        output=(
                            "Operator requested resource retention; this required stage "
                            "therefore does not pass"
                        ),
                        evidence_paths=tuple(
                            path
                            for path in (
                                "registry-ownership.json" if registry is not None else None,
                                "kind-cluster-ownership.json" if cluster is not None else None,
                            )
                            if path is not None
                        ),
                        remediation=(
                            "Use cluster kind destroy for retained clusters, then remove the "
                            "owned registry with a verified lifecycle"
                        ),
                    )
                else:
                    if cluster is not None:
                        try:
                            if cluster.diagnostics:
                                store.write_text(
                                    "diagnostics/kind-lifecycle.log",
                                    cluster.diagnostics,
                                )
                            cluster.destroy()
                        except BaseException as error:
                            cleanup_failure = _safe_failure(error)
                    if registry is not None:
                        try:
                            registry_log = registry.logs()
                            store.write_text("logs/registry.log", registry_log or "")
                            registry.cleanup()
                        except BaseException as error:
                            detail = _safe_failure(error)
                            cleanup_failure = (
                                f"{cleanup_failure}; {detail}"
                                if cleanup_failure
                                else detail
                            )
                    stage_results["cleanup"] = self._stage(
                        plan,
                        "cleanup",
                        (
                            StageStatus.FAILED
                            if cleanup_failure is not None
                            else StageStatus.PASSED
                        ),
                        started=cleanup_started,
                        tool="kind/docker",
                        output=(
                            None
                            if cleanup_failure is not None
                            else "All run-owned resources were removed or none were created"
                        ),
                        evidence_paths=tuple(
                            path
                            for path in (
                                "logs/registry.log" if registry is not None else None,
                                (
                                    "diagnostics/kind-lifecycle.log"
                                    if cluster is not None
                                    and store.path("diagnostics/kind-lifecycle.log").exists()
                                    else None
                                ),
                            )
                            if path is not None
                        ),
                        failure_reason=cleanup_failure,
                        remediation=(
                            "Inspect persisted ownership records and remove only verified "
                            "run-owned resources"
                            if cleanup_failure is not None
                            else None
                        ),
                    )
                    if cleanup_failure is not None:
                        failure_reason = (
                            f"{failure_reason}; cleanup: {cleanup_failure}"
                            if failure_reason
                            else f"cleanup: {cleanup_failure}"
                        )

        assert plan is not None
        for planned in plan.stages:
            if planned.stage_id not in stage_results:
                stage_results[planned.stage_id] = self._stage(
                    plan,
                    planned.stage_id,
                    StageStatus.NOT_APPLICABLE,
                    output="Stage did not execute because an earlier required stage failed",
                )
        ordered_stages = tuple(stage_results[stage.stage_id] for stage in plan.stages)
        policy_failures = profile_policy(profile).required_stage_failures(ordered_stages)
        if policy_failures and failure_reason is None:
            failure_reason = "Required stages did not pass: " + ", ".join(
                f"{key}={value}" for key, value in policy_failures.items()
            )
        final_status = (
            StageStatus.PASSED
            if not policy_failures and failure_reason is None
            else (
                StageStatus.BLOCKED_MISSING_REQUIRED_TOOL
                if any(
                    value == StageStatus.BLOCKED_MISSING_REQUIRED_TOOL.value
                    for value in policy_failures.values()
                )
                else StageStatus.FAILED
            )
        )
        tool_versions = {"devops-stack-composer": __version__}
        if supply_chain is not None:
            tool_versions["syft"] = supply_chain.sbom_generator
            tool_versions["trivy"] = supply_chain.scanner_version
        run = ExecutionRun(
            run_id=store.run_id,
            project_path=".",
            config_hash=composition.loaded_config.config_hash,
            template_lock_hash=sha256_file(composition.lock.path),
            source_revision=source_revision,
            start_time=started_at,
            end_time=self._now(),
            execution_profile=profile.value,
            stage_results=ordered_stages,
            final_status=final_status,
            tool_versions=tool_versions,
            artifact_record=artifact,
            supply_chain_evidence=supply_chain,
            deployment_evidence=deployment,
            failure_reason=failure_reason,
        )
        self._write_final_records(
            store=store,
            plan=plan,
            run=run,
            composition=composition,
            verification=verification,
            retained_resources=retained_resources,
        )
        return ExecutionResult(
            store=store,
            plan=plan,
            run=run,
            verification=verification,
            retained_resources=retained_resources,
        )
