"""Fail-closed orchestration for build-once execution profiles."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, replace
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
from devops_stack_composer.evidence_bundle import (
    EvidenceBundleVerification,
    assemble_evidence_bundle,
)
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
from devops_stack_composer.execution_state import (
    ExecutionErrorCategory,
    ExecutionJournal,
    ExecutionState,
    StateTransition,
)
from devops_stack_composer.filesystem import (
    contained_path,
    normalize_relative_path,
    sha256_file,
)
from devops_stack_composer.kind_cluster import KindCluster
from devops_stack_composer.kubernetes_execution import (
    KubernetesExecutionError,
    KubernetesExecutionResult,
    KubernetesExecutor,
)
from devops_stack_composer.kubernetes_runtime import render_resolved_environment
from devops_stack_composer.oci import validate_tag
from devops_stack_composer.policies import (
    ValidationProfile,
    VulnerabilityAllowlistEntry,
    VulnerabilityPolicy,
    profile_policy,
)
from devops_stack_composer.registry import EphemeralRegistry, RegistryHandle
from devops_stack_composer.resource_recovery import ResourceRecoveryStore
from devops_stack_composer.report import redact_sensitive
from devops_stack_composer.process_compat import (
    SafeBuildCommandRunner,
    SafeSubprocessAdapter,
)
from devops_stack_composer.process_runner import (
    DEFAULT_ALLOWED_ENVIRONMENT_KEYS,
    ProcessErrorCategory,
    ProcessExecutionError,
    ProcessResult,
    SafeProcessRunner,
    redact_process_output,
)
from devops_stack_composer.supply_chain import SupplyChainGenerator


Clock = Callable[[], datetime]
SourceRevisionResolver = Callable[[Path], str]
RegistryFactory = Callable[[str], EphemeralRegistry]
KindFactory = Callable[[str], KindCluster]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], str | None]
ProcessRunnerFactory = Callable[[Path], SafeProcessRunner]

_EXECUTION_TOOLS = frozenset(
    {
        "cosign",
        "docker",
        "gh",
        "git",
        "kind",
        "kubeconform",
        "kubectl",
        "syft",
        "trivy",
    }
)
_EXECUTION_ENVIRONMENT_KEYS = frozenset(
    (*DEFAULT_ALLOWED_ENVIRONMENT_KEYS, "SYFT_REGISTRY_INSECURE_USE_HTTP")
)
_MAX_EXECUTION_OUTPUT_BYTES = 1024 * 1024
_OVERALL_EXECUTION_TIMEOUT_SECONDS = 3600.0


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
    keep_environment_on_failure: bool = False
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
        if not isinstance(self.keep_environment_on_failure, bool):
            raise ValueError("keep_environment_on_failure must be boolean")
        if self.keep_resources and self.keep_environment_on_failure:
            raise ValueError(
                "keep_resources and keep_environment_on_failure are mutually exclusive"
            )
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
    bundle_verification: EvidenceBundleVerification | None = None

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
            "bundleVerification": (
                self.bundle_verification.to_dict()
                if self.bundle_verification is not None
                else None
            ),
        }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("execution clock must return timezone-aware datetimes")
    utc = value.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds")
    return rendered.replace("+00:00", "Z")


def _default_source_revision(
    project: Path,
    command_runner: CommandRunner = subprocess.run,
) -> str:
    try:
        result = command_runner(
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


_PROCESS_ERROR_CATEGORIES = {
    ProcessErrorCategory.COMMAND_NOT_FOUND: ExecutionErrorCategory.COMMAND_NOT_FOUND,
    ProcessErrorCategory.PERMISSION: ExecutionErrorCategory.PERMISSION,
    ProcessErrorCategory.TIMEOUT: ExecutionErrorCategory.TIMEOUT,
    ProcessErrorCategory.CANCELLED: ExecutionErrorCategory.CANCELLED,
    ProcessErrorCategory.NONZERO: ExecutionErrorCategory.NON_ZERO_EXIT,
}


class _ExecutionProgress:
    """Persist the strict v0.2 state journal alongside the live kind run."""

    def __init__(
        self,
        store: EvidenceStore,
        plan: ExecutionPlan,
        now: Callable[[], str],
    ) -> None:
        self.journal = ExecutionJournal(store)
        self.plan = plan
        self._now = now
        self._attested = False

    @property
    def state(self) -> ExecutionState | None:
        return self.journal.current_state

    def start(self) -> None:
        self._append(
            ExecutionState.PLANNED,
            outputs={"runId": self.plan.run_id},
            checksum=self.plan.build_plan_hash,
        )
        self._append(
            ExecutionState.VALIDATED,
            outputs={"plannedStage": "generated-files"},
        )

    def building(self) -> None:
        self._append(
            ExecutionState.BUILDING,
            outputs={"plannedStage": "registry-lifecycle"},
            command=("docker", "<owned-registry-start>"),
        )

    def built_and_pushed(self) -> None:
        self._append(
            ExecutionState.BUILT,
            outputs={"plannedStage": "build-once", "buildInvocationCount": 1},
            command=("docker", "buildx", "build", "--push", "<project-context>"),
        )
        self._append(
            ExecutionState.PUSHING,
            outputs={"plannedStage": "build-once", "pushCompleted": True},
            command=("docker", "buildx", "build", "--push", "<project-context>"),
        )

    def digest_resolved(self, digest: str) -> None:
        self._append(
            ExecutionState.DIGEST_RESOLVED,
            outputs={"plannedStage": "resolve-digest", "digest": digest},
            command=("docker", "buildx", "imagetools", "inspect", "<tag>"),
            digest=digest,
        )

    def kubernetes_event(self, event: str, outputs: Mapping[str, Any]) -> None:
        if event == "cluster_prepared":
            self._append_if_next(
                ExecutionState.CLUSTER_PREPARING,
                outputs={"plannedStage": "server-side-dry-run", **dict(outputs)},
                command=("kind", "create", "cluster", "<run-owned-cluster>"),
            )
        elif event == "applied":
            self._append_if_next(
                ExecutionState.APPLYING,
                outputs={"plannedStage": "deployment", **dict(outputs)},
                command=("kubectl", "apply", "<digest-pinned-manifest>"),
            )
        elif event == "ready":
            self._append_if_next(
                ExecutionState.WAITING_READY,
                outputs={"plannedStage": "rollout", **dict(outputs)},
                command=("kubectl", "rollout", "status", "<deployment>"),
            )
        elif event == "attested":
            self._attested = True
        elif event == "smoked":
            self._append_if_next(
                ExecutionState.SMOKE_TESTING,
                outputs={"plannedStage": "health/readiness", **dict(outputs)},
                command=("http", "GET", "<loopback-health-and-readiness>"),
            )
            if self._attested:
                self._append_if_next(
                    ExecutionState.ATTESTING,
                    outputs={"plannedStage": "pod-image"},
                    command=("kubectl", "get", "pods", "<digest-attestation>"),
                )
        elif event == "evidence_collected":
            self._append_if_next(
                ExecutionState.COLLECTING_EVIDENCE,
                outputs={"plannedStage": "rollback", **dict(outputs)},
            )

    def complete_kubernetes(self) -> None:
        for state, stage in (
            (ExecutionState.CLUSTER_PREPARING, "server-side-dry-run"),
            (ExecutionState.APPLYING, "deployment"),
            (ExecutionState.WAITING_READY, "rollout"),
            (ExecutionState.SMOKE_TESTING, "health/readiness"),
            (ExecutionState.ATTESTING, "pod-image"),
            (ExecutionState.COLLECTING_EVIDENCE, "rollback"),
        ):
            self._append_if_next(state, outputs={"plannedStage": stage})

    def fail(self, stage: str, error: BaseException) -> None:
        if self.state in {ExecutionState.FAILED, ExecutionState.CLEANED}:
            return
        process = self._process_result(error)
        category = ExecutionErrorCategory.VALIDATION
        if isinstance(error, ProcessExecutionError):
            category = _PROCESS_ERROR_CATEGORIES[error.category]
        elif process is not None and process.error_category is not None:
            category = _PROCESS_ERROR_CATEGORIES[process.error_category]
        elif "ownership" in type(error).__name__.lower():
            category = ExecutionErrorCategory.OWNERSHIP
        command = ()
        stdout = ""
        stderr = _safe_failure(error)
        exit_code = None
        if process is not None:
            command = (
                (process.argv[0], "<arguments-redacted>")
                if process.argv
                else ()
            )
            stdout = _safe_log(process.stdout)
            stderr = _safe_log(process.stderr or str(error))
            exit_code = process.returncode
        self._append(
            ExecutionState.FAILED,
            outputs={"failedStage": stage},
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=category == ExecutionErrorCategory.TIMEOUT,
            error_category=category,
            retryable=category
            in {ExecutionErrorCategory.TIMEOUT, ExecutionErrorCategory.CANCELLED},
        )

    def succeeded(self) -> None:
        self._append(
            ExecutionState.SUCCEEDED,
            outputs={"finalStatus": StageStatus.PASSED.value},
        )

    def cleaned(self) -> None:
        if self.state not in {ExecutionState.SUCCEEDED, ExecutionState.FAILED}:
            return
        self._append(
            ExecutionState.CLEANED,
            outputs={"cleanupPerformed": True},
            command=("docker/kind", "<verified-owned-resource-cleanup>"),
        )

    def _append_if_next(
        self,
        state: ExecutionState,
        *,
        outputs: Mapping[str, Any],
        command: Sequence[str] = (),
    ) -> None:
        if any(
            transition.state == state
            for transition in self.journal.machine.transitions
        ):
            return
        self._append(state, outputs=outputs, command=command)

    def _append(
        self,
        state: ExecutionState,
        *,
        outputs: Mapping[str, Any],
        command: Sequence[str] = (),
        exit_code: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
        error_category: ExecutionErrorCategory | None = None,
        checksum: str | None = None,
        digest: str | None = None,
        retryable: bool = False,
    ) -> None:
        timestamp = self._now()
        self.journal.append(
            StateTransition(
                state=state,
                previous_state=self.state,
                started_at=timestamp,
                finished_at=timestamp,
                input_subject=self.plan.build_plan_hash,
                outputs=dict(outputs),
                command=tuple(redact_process_output(value) for value in command),
                exit_code=exit_code,
                stdout=_safe_log(stdout),
                stderr=_safe_log(stderr),
                timed_out=timed_out,
                error_category=error_category,
                checksum=checksum,
                digest=digest,
                retryable=retryable,
            )
        )

    @staticmethod
    def _process_result(error: BaseException) -> ProcessResult | None:
        if isinstance(error, ProcessExecutionError):
            return error.result
        value = getattr(error, "process_result", None)
        return value if isinstance(value, ProcessResult) else None


class ExecutionOrchestrator:
    """Execute a profile once and persist independently verifiable evidence."""

    def __init__(
        self,
        *,
        build_executor: BuildOnceExecutor | None = None,
        supply_chain_generator: SupplyChainGenerator | None = None,
        registry_factory: RegistryFactory | None = None,
        kind_factory: KindFactory | None = None,
        kubernetes_executor: object | None = None,
        schema_command_runner: CommandRunner | None = None,
        tool_resolver: ToolResolver | None = None,
        source_revision_resolver: SourceRevisionResolver | None = None,
        process_runner_factory: ProcessRunnerFactory | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._build_executor = build_executor
        self._supply_chain_generator = supply_chain_generator
        self._registry_factory = registry_factory
        self._kind_factory = kind_factory
        self._kubernetes_executor = kubernetes_executor
        self._schema_command_runner = schema_command_runner
        self._tool_resolver = tool_resolver or shutil.which
        self._source_revision_resolver = source_revision_resolver
        self._process_runner_factory = process_runner_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _process_runner(self, project: Path) -> SafeProcessRunner:
        if self._process_runner_factory is not None:
            runner = self._process_runner_factory(project)
            if not isinstance(runner, SafeProcessRunner):
                raise TypeError("process_runner_factory must return SafeProcessRunner")
            return runner
        return SafeProcessRunner(
            project,
            allowed_executables=_EXECUTION_TOOLS,
            allowed_environment_keys=_EXECUTION_ENVIRONMENT_KEYS,
            max_output_bytes=_MAX_EXECUTION_OUTPUT_BYTES,
            default_timeout=300.0,
            overall_deadline=time.monotonic() + _OVERALL_EXECUTION_TIMEOUT_SECONDS,
        )

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
        if (
            options.keep_resources or options.keep_environment_on_failure
        ) and profile == ValidationProfile.RELEASE:
            raise ExecutionError(
                "RELEASE_RESOURCE_RETENTION_FORBIDDEN",
                "release validation cannot retain run-owned resources",
            )

    def _missing_required_tools(
        self,
        profile: ValidationProfile,
        *,
        registry_mode: str,
    ) -> tuple[tuple[str, str], ...]:
        if profile == ValidationProfile.STATIC:
            return ()
        required: list[tuple[str, str]] = [
            (
                "docker",
                "registry-lifecycle"
                if registry_mode == "ephemeral-local"
                else "build-once",
            ),
            ("syft", "sbom"),
            ("trivy", "vulnerability-scan"),
        ]
        if profile in {ValidationProfile.KIND_E2E, ValidationProfile.RELEASE}:
            required.extend(
                (
                    ("kubeconform", "kubernetes-schema"),
                    ("kind", "server-side-dry-run"),
                    ("kubectl", "server-side-dry-run"),
                )
            )
        if profile == ValidationProfile.RELEASE:
            required.extend(
                (
                    ("cosign", "release-assets"),
                    ("gh", "release-download-verification"),
                )
            )
        return tuple(
            (tool, stage_id)
            for tool, stage_id in required
            if not self._tool_resolver(tool)
        )

    @staticmethod
    def _kubernetes_progress(
        error: KubernetesExecutionError,
    ) -> tuple[tuple[str, ...], str]:
        initial_stages = (
            "server-side-dry-run",
            "deployment",
            "rollout",
            "pod-image",
            "health",
            "readiness",
        )
        stage = error.stage.split(":", 1)[0]
        if stage in {
            "manifest-validation",
            "persist-manifest",
            "namespace-server-side-dry-run",
            "namespace-bootstrap",
            "server-side-dry-run",
        }:
            return (), "server-side-dry-run"
        if stage in {"apply", "applied-deployment", "applied-service"}:
            return initial_stages[:1], "deployment"
        if stage == "rollout":
            return initial_stages[:2], "rollout"
        if stage == "runtime-attestation":
            return initial_stages[:3], "pod-image"
        if stage in {"smoke", "health"}:
            return initial_stages[:4], "health"
        if stage == "readiness":
            return initial_stages[:5], "readiness"
        if stage in {"rollback", "persist-result"}:
            return initial_stages, "rollback"
        return (), "server-side-dry-run"

    def _record_kubernetes_failure(
        self,
        *,
        error: KubernetesExecutionError,
        store: EvidenceStore,
        plan: ExecutionPlan,
        stage_results: dict[str, StageResult],
        manifest_paths: Sequence[str],
        started: str,
    ) -> tuple[str, str]:
        completed_stages, failure_stage = self._kubernetes_progress(error)
        persistence_failures: list[str] = []
        diagnostic_paths: list[str] = []
        for relative in error.diagnostics_paths:
            try:
                path = store.path(relative)
                if not path.is_file() or path.is_symlink():
                    raise OSError("diagnostic evidence is missing or not a regular file")
                diagnostic_paths.append(relative)
            except (DevOpsStackError, OSError, ValueError) as write_error:
                persistence_failures.append(
                    f"{relative}: {_safe_failure(write_error)}"
                )

        error_record_path = "kubernetes/execution-error.json"
        try:
            store.write_json(
                error_record_path,
                {
                    "schemaVersion": "1.0.0",
                    "code": error.code,
                    "stage": error.stage,
                    "failureStage": failure_stage,
                    "completedStages": list(completed_stages),
                    "identity": error.identity.to_dict(),
                    "diagnosticsPaths": diagnostic_paths,
                    "failureReason": _safe_failure(error),
                },
            )
        except BaseException as write_error:
            persistence_failures.append(
                f"{error_record_path}: {_safe_failure(write_error)}"
            )
            error_record_path = ""

        evidence_paths = tuple(
            (
                *manifest_paths,
                *(
                    ("kubernetes/server-side-dry-run.json",)
                    if store.path("kubernetes/server-side-dry-run.json").is_file()
                    else ()
                ),
                *(
                    ("kind-cluster-ownership.json",)
                    if store.path("kind-cluster-ownership.json").is_file()
                    else ()
                ),
                *error.evidence_paths,
                *diagnostic_paths,
                *((error_record_path,) if error_record_path else ()),
            )
        )
        for stage_id in completed_stages:
            if stage_id not in stage_results:
                stage_results[stage_id] = self._stage(
                    plan,
                    stage_id,
                    StageStatus.PASSED,
                    started=started,
                    tool="kubectl",
                    output=(
                        f"The Kubernetes executor completed {stage_id} before "
                        f"the reported {error.stage} failure"
                    ),
                    evidence_paths=evidence_paths,
                )

        failure_reason = f"{error.code}: {_safe_failure(error)}"
        if persistence_failures:
            failure_reason += "; diagnostics persistence: " + "; ".join(
                persistence_failures
            )
        stage_results[failure_stage] = self._stage(
            plan,
            failure_stage,
            StageStatus.FAILED,
            started=started,
            tool="kubectl",
            evidence_paths=evidence_paths,
            failure_reason=failure_reason,
        )
        return failure_stage, failure_reason

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
        canonical_bundle = profile == ValidationProfile.KIND_E2E
        process_runner = self._process_runner(composition.project)
        subprocess_adapter = SafeSubprocessAdapter(process_runner)
        build_executor = self._build_executor or BuildOnceExecutor(
            SafeBuildCommandRunner(subprocess_adapter)
        )
        supply_chain_generator = self._supply_chain_generator or SupplyChainGenerator(
            subprocess_adapter
        )
        registry_factory = self._registry_factory or (
            lambda run_id: EphemeralRegistry(
                run_id,
                command_runner=subprocess_adapter,
            )
        )
        kind_factory = self._kind_factory or (
            lambda run_id: KindCluster(
                run_id,
                command_runner=subprocess_adapter,
            )
        )
        schema_command_runner = self._schema_command_runner or subprocess_adapter
        missing_tools = self._missing_required_tools(
            profile,
            registry_mode=model.registry["mode"],
        )
        source_revision = (
            self._source_revision_resolver(composition.project)
            if self._source_revision_resolver is not None
            else _default_source_revision(composition.project, subprocess_adapter)
        )
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
        bundle_verification: EvidenceBundleVerification | None = None
        registry: EphemeralRegistry | None = None
        cluster: KindCluster | None = None
        registry_endpoint = model.image_registry
        repository_path = model.image_repository
        retained_resources = False
        failure_reason: str | None = None
        failure_status = StageStatus.FAILED
        current_stage = "config-schema"
        plan: ExecutionPlan | None = None
        kubernetes_manifest_paths: tuple[str, ...] = ()
        cluster_started = started_at
        progress: _ExecutionProgress | None = None
        failure_error: BaseException | None = None
        cleanup_completed = False
        recovery = ResourceRecoveryStore(store) if canonical_bundle else None
        recovery_recorded = False

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

            dockerfile = self._write_build_inputs(store, composition)
            dockerfile_relative = dockerfile.relative_to(composition.project).as_posix()
            input_paths = tuple(
                path
                for path in (
                    "inputs/Dockerfile",
                    "inputs/Dockerfile.dockerignore",
                )
                if store.path(path).is_file()
            )
            stage_results["generated-files"] = replace(
                stage_results["generated-files"],
                evidence_paths=input_paths,
            )
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

            if missing_tools:
                if canonical_bundle:
                    store.write_json("plan.json", plan.to_dict())
                    store.write_json("policy.json", profile_policy(profile).to_dict())
                    progress = _ExecutionProgress(store, plan, self._now)
                    progress.start()
                else:
                    store.write_json("execution-plan.json", plan.to_dict())
                current_stage = "registry-lifecycle"
                missing_names = ", ".join(tool for tool, _stage_id in missing_tools)
                raise ExecutionError(
                    "REQUIRED_TOOL_MISSING",
                    f"profile {profile.value} requires unavailable tools: {missing_names}",
                )

            if profile != ValidationProfile.STATIC:
                current_stage = "registry-lifecycle"
                registry_started = self._now()
                if model.registry["mode"] == "ephemeral-local":
                    registry = registry_factory(store.run_id)
                    handle = registry.start()
                    registry_endpoint = f"localhost:{handle.host_port}"
                    repository_path = model.registry["repository"]
                    store.write_json("registry-ownership.json", handle.to_dict())
                    if recovery is not None and isinstance(handle, RegistryHandle):
                        recovery.record_registry(handle)
                        recovery_recorded = True
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
                if (
                    registry_endpoint != intent.registry
                    or repository_path != intent.repository
                ):
                    intent = replace(
                        intent,
                        registry=registry_endpoint,
                        repository=repository_path,
                    )
                    plan = ExecutionPlan.create(
                        run_id=store.run_id,
                        profile=profile,
                        environment=options.environment,
                        artifact_intent=intent,
                        production_apply_approved=options.approve_production,
                    )
            else:
                registry_started = self._now()
                registry_output = "No execution registry is required by the static profile"
                registry_evidence = ()

            if canonical_bundle:
                store.write_json("plan.json", plan.to_dict())
                store.write_json("policy.json", profile_policy(profile).to_dict())
                progress = _ExecutionProgress(store, plan, self._now)
                progress.start()
            else:
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
                if progress is not None:
                    progress.building()

                current_stage = "build-once"
                build_started = self._now()
                build_result = build_executor.execute(
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
                if progress is not None:
                    progress.built_and_pushed()

                current_stage = "resolve-digest"
                resolve_started = self._now()
                artifact = self._resolved_artifact(
                    build_result,
                    source_revision=source_revision,
                    build_plan_hash=plan.build_plan_hash,
                    registry_endpoint=registry_endpoint,
                )
                validate_artifact_contract(artifact)
                build_executor.verify_tag_unchanged(
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
                if progress is not None:
                    progress.digest_resolved(artifact.manifest_digest)

                current_stage = "sbom"
                supply_started = self._now()
                policy = vulnerability_policy_from_model(model.supply_chain)
                supply_chain = supply_chain_generator.generate(
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
                build_executor.verify_tag_unchanged(
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
                    kubernetes_manifest_paths = tuple(manifest_paths)
                    schema_result = schema_command_runner(
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
                    cluster = kind_factory(store.run_id)
                    cluster_handle = cluster.create()
                    store.write_json("kind-cluster-ownership.json", cluster_handle.to_dict())
                    if recovery is not None and isinstance(cluster, KindCluster):
                        cluster_identity = cluster.recovery_identity
                        if cluster_identity is not None:
                            recovery.record_kind(cluster_identity)
                            recovery_recorded = True
                    cluster.configure_local_registry(registry)
                    kubeconfig = cluster.kubeconfig_path
                    if kubeconfig is None:
                        raise ExecutionError(
                            "KUBECONFIG_UNAVAILABLE",
                            "owned kind cluster has no private runtime kubeconfig",
                        )
                    environment_model = model.environment(options.environment)
                    if self._kubernetes_executor is None:
                        kubernetes_executor = KubernetesExecutor(
                            process_runner,
                            store,
                            kubeconfig=kubeconfig,
                            app_name=model.service_name,
                            deployment_name=model.service_name,
                            service_name=model.service_name,
                            service_port=environment_model.service_port,
                            health_path=model.kubernetes_e2e["healthPath"],
                            readiness_path=model.kubernetes_e2e["readinessPath"],
                            rollout_timeout_seconds=model.kubernetes_e2e[
                                "rolloutTimeoutSeconds"
                            ],
                            progress_callback=(
                                progress.kubernetes_event
                                if progress is not None
                                else None
                            ),
                        )
                    else:
                        kubernetes_executor = self._kubernetes_executor
                    preflight_result = kubernetes_executor.server_side_dry_run(
                        manifests
                    )
                    selected_manifests = tuple(
                        manifest
                        for manifest in manifests
                        if manifest.environment == options.environment
                    )
                    if len(selected_manifests) != 1:
                        raise ExecutionError(
                            "KUBERNETES_ENVIRONMENT_INVALID",
                            "execution requires exactly one selected environment manifest",
                        )
                    selected_manifest = selected_manifests[0]
                    kubernetes_result = kubernetes_executor.execute(
                        selected_manifest,
                        expected_image_reference=artifact.immutable_image_reference,
                        expected_digest=artifact.manifest_digest,
                    )
                    if not isinstance(kubernetes_result, KubernetesExecutionResult):
                        raise ExecutionError(
                            "KUBERNETES_RESULT_INVALID",
                            "Kubernetes executor returned an unsupported result",
                        )
                    identity = kubernetes_result.identity
                    if (
                        identity.applied_image_reference is None
                        or identity.runtime_image_id is None
                        or identity.runtime_digest is None
                    ):
                        raise ExecutionError(
                            "KUBERNETES_IDENTITY_INCOMPLETE",
                            "Kubernetes result omitted required runtime identity evidence",
                        )
                    kubernetes_paths = tuple(
                        dict.fromkeys(
                            (
                                preflight_result.evidence_path,
                                *preflight_result.evidence_paths,
                                *kubernetes_result.evidence_paths,
                                kubernetes_result.manifest_path,
                                kubernetes_result.applied_deployment_path,
                                kubernetes_result.applied_service_path,
                                kubernetes_result.runtime_pods_path,
                                "kubernetes/smoke.json",
                                kubernetes_result.rollback_path,
                                "kubernetes/deployment.json",
                            )
                        )
                    )
                    deployment = DeploymentEvidence(
                        environment=options.environment,
                        namespace=kubernetes_result.namespace,
                        cluster_type="kind",
                        cluster_identifier=cluster_handle.name,
                        manifest_hash=selected_manifest.sha256,
                        deployed_image_reference=identity.applied_image_reference,
                        expected_digest=artifact.manifest_digest,
                        actual_pod_image_id=identity.runtime_image_id,
                        rollout_status="PASSED",
                        ready_replica_count=kubernetes_result.ready_replica_count,
                        health_endpoint_result={
                            "status": kubernetes_result.health.status_code,
                            "path": kubernetes_result.health.path,
                            "body": kubernetes_result.health.body,
                            "truncated": kubernetes_result.health.truncated,
                        },
                        readiness_endpoint_result={
                            "status": kubernetes_result.readiness.status_code,
                            "path": kubernetes_result.readiness.path,
                            "body": kubernetes_result.readiness.body,
                            "truncated": kubernetes_result.readiness.truncated,
                        },
                        rollback_attempted=True,
                        rollback_result="PASSED",
                        final_revision=kubernetes_result.final_revision,
                        final_digest=identity.runtime_digest,
                        diagnostics_paths=kubernetes_paths,
                    )
                    store.write_json(
                        "deployment-evidence.json", deployment.to_dict()
                    )
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
                    kubernetes_evidence = tuple(
                        dict.fromkeys(
                            (
                                *manifest_paths,
                                "kind-cluster-ownership.json",
                                "deployment-evidence.json",
                                "kubernetes/execution-result.json",
                                *kubernetes_paths,
                            )
                        )
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
                    if progress is not None:
                        progress.complete_kubernetes()

        except KubernetesExecutionError as error:
            assert plan is not None
            failure_error = error
            current_stage, failure_reason = self._record_kubernetes_failure(
                error=error,
                store=store,
                plan=plan,
                stage_results=stage_results,
                manifest_paths=kubernetes_manifest_paths,
                started=cluster_started,
            )
            if progress is not None:
                progress.fail(current_stage, error)
        except BaseException as error:
            failure_error = error
            failure_reason = _safe_failure(error)
            if getattr(error, "code", None) == "REQUIRED_TOOL_MISSING":
                failure_status = StageStatus.BLOCKED_MISSING_REQUIRED_TOOL
            if plan is not None and current_stage in {
                stage.stage_id for stage in plan.stages
            } and current_stage not in stage_results:
                failure_evidence = tuple(
                    path
                    for path in (
                        *kubernetes_manifest_paths,
                        "kind-cluster-ownership.json",
                    )
                    if store.path(path).is_file()
                )
                stage_results[current_stage] = self._stage(
                    plan,
                    current_stage,
                    failure_status,
                    evidence_paths=failure_evidence,
                    failure_reason=failure_reason,
                )
            if progress is not None:
                progress.fail(current_stage, error)
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
                retain_resources = options.keep_resources or (
                    options.keep_environment_on_failure and failure_reason is not None
                )
                if retain_resources and (cluster is not None or registry is not None):
                    if cluster is not None:
                        cluster.detach()
                    retained_resources = True
                    stage_results["cleanup"] = self._stage(
                        plan,
                        "cleanup",
                        StageStatus.NOT_APPLICABLE,
                        started=cleanup_started,
                        output=(
                            "Operator policy retained run-owned resources; this required "
                            "stage therefore does not pass"
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
                    cleanup_failures: list[str] = []
                    cleanup_evidence: list[str] = []
                    if cluster is not None:
                        try:
                            if cluster.diagnostics:
                                store.write_text(
                                    "diagnostics/kind-lifecycle.log",
                                    cluster.diagnostics,
                                )
                                cleanup_evidence.append(
                                    "diagnostics/kind-lifecycle.log"
                                )
                        except BaseException as error:
                            cleanup_failures.append(
                                f"cluster diagnostics: {_safe_failure(error)}"
                            )
                        try:
                            cluster.destroy()
                        except BaseException as error:
                            cleanup_failures.append(
                                f"cluster cleanup: {_safe_failure(error)}"
                            )
                    if registry is not None:
                        try:
                            registry_log = registry.logs()
                        except BaseException as error:
                            cleanup_failures.append(
                                f"registry diagnostics: {_safe_failure(error)}"
                            )
                        else:
                            try:
                                store.write_text("logs/registry.log", registry_log or "")
                                cleanup_evidence.append("logs/registry.log")
                            except BaseException as error:
                                cleanup_failures.append(
                                    f"registry diagnostics: {_safe_failure(error)}"
                                )
                        try:
                            registry.cleanup()
                        except BaseException as error:
                            cleanup_failures.append(
                                f"registry cleanup: {_safe_failure(error)}"
                            )
                    if recovery is not None and recovery_recorded and not cleanup_failures:
                        try:
                            recovered = recovery.cleanup(
                                command_runner=subprocess_adapter,
                                command_timeout_seconds=60.0,
                            )
                            if not recovered.complete:
                                cleanup_failures.append(
                                    "resource recovery record did not confirm complete cleanup"
                                )
                        except BaseException as error:
                            cleanup_failures.append(
                                f"resource recovery state: {_safe_failure(error)}"
                            )
                    cleanup_failure = (
                        "; ".join(cleanup_failures) if cleanup_failures else None
                    )
                    cleanup_completed = cleanup_failure is None
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
                        evidence_paths=tuple(cleanup_evidence),
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
        if canonical_bundle and failure_reason is not None:
            cleanup_result = stage_results.get("cleanup")
            if cleanup_result is not None and cleanup_result.evidence_paths:
                failed_result = next(
                    (
                        result
                        for result in stage_results.values()
                        if result.status != StageStatus.PASSED
                        and result.stage_id != "cleanup"
                    ),
                    None,
                )
                if failed_result is not None:
                    stage_results[failed_result.stage_id] = replace(
                        failed_result,
                        evidence_paths=tuple(
                            dict.fromkeys(
                                (
                                    *failed_result.evidence_paths,
                                    *cleanup_result.evidence_paths,
                                )
                            )
                        ),
                    )
            strict_prefix: list[StageResult] = []
            for planned in plan.stages:
                result = stage_results.get(planned.stage_id)
                if result is None:
                    break
                strict_prefix.append(result)
                if result.status != StageStatus.PASSED:
                    break
            ordered_stages = tuple(strict_prefix)
        else:
            for planned in plan.stages:
                if planned.stage_id not in stage_results:
                    stage_results[planned.stage_id] = self._stage(
                        plan,
                        planned.stage_id,
                        StageStatus.NOT_APPLICABLE,
                        output=(
                            "Stage did not execute because an earlier required stage failed"
                        ),
                    )
            ordered_stages = tuple(
                stage_results[stage.stage_id] for stage in plan.stages
            )
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
        if canonical_bundle:
            assert progress is not None
            if final_status == StageStatus.PASSED:
                progress.complete_kubernetes()
                progress.succeeded()
            else:
                terminal_error = failure_error or ExecutionError(
                    "EXECUTION_POLICY_FAILED",
                    failure_reason or "one or more required stages did not pass",
                )
                progress.fail(current_stage, terminal_error)
            if cleanup_completed:
                progress.cleaned()
            bundle_verification = assemble_evidence_bundle(store, plan, run)
        else:
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
            bundle_verification=bundle_verification,
        )
