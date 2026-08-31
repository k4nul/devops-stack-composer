"""Strict stage orchestration for one execution-backed local-kind run."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.execution_models import (
    DeploymentEvidence,
    ExecutionRun,
    LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
    ResolvedArtifact,
    StageResult,
    StageStatus,
    SupplyChainEvidence,
)
from devops_stack_composer.execution_plan import ExecutionPlan, PlannedStage
from devops_stack_composer.execution_state import (
    ExecutionErrorCategory,
    ExecutionJournal,
    ExecutionState,
    StateTransition,
)
from devops_stack_composer.policies import profile_policy
from devops_stack_composer.process_runner import (
    CommandNotFoundError,
    ProcessErrorCategory,
    ProcessExecutionError,
    ProcessResult,
    redact_process_output,
)
from devops_stack_composer.runtime_validation import (
    RuntimeVerification,
    validate_runtime_records,
)


Clock = Callable[[], datetime]


class LocalExecutionError(RuntimeError):
    """Raised when the orchestration contract itself is invalid."""


class EnvironmentBlockedError(LocalExecutionError):
    """A required local execution capability is unavailable."""


@dataclass(frozen=True)
class StageExecutionEvidence:
    """Bounded evidence returned by one exact planned stage."""

    subject: str
    command: tuple[str, ...] = ()
    tool: str | None = None
    sanitized_output: str | None = None
    evidence_paths: tuple[str, ...] = ()
    process: ProcessResult | None = None
    cleanup_performed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject:
            raise ValueError("stage subject must be a non-empty string")
        if self.process is not None and not isinstance(self.process, ProcessResult):
            raise ValueError("process must be ProcessResult or null")
        if not isinstance(self.cleanup_performed, bool):
            raise ValueError("cleanup_performed must be boolean")


@dataclass(frozen=True)
class ExecutionProducts:
    """Typed products collected by a stage executor."""

    artifact: ResolvedArtifact | None = None
    supply_chain: SupplyChainEvidence | None = None
    deployment: DeploymentEvidence | None = None
    tool_versions: Mapping[str, str] = field(default_factory=dict)


class LocalKindStageExecutor(Protocol):
    """Side-effect boundary injected into the deterministic orchestrator."""

    def execute(self, stage: PlannedStage) -> StageExecutionEvidence: ...

    def cleanup_after_failure(self) -> StageExecutionEvidence: ...

    def products(self) -> ExecutionProducts: ...


class EvidenceBundleFinalizer(Protocol):
    """Seal and verify the authoritative evidence bundle."""

    def __call__(
        self,
        *,
        store: EvidenceStore,
        plan: ExecutionPlan,
        run: ExecutionRun,
        policy: Mapping[str, Any],
    ) -> RuntimeVerification: ...


@dataclass(frozen=True)
class LocalExecutionOutcome:
    run_id: str
    state: ExecutionState
    final_status: StageStatus
    verification: RuntimeVerification | None
    failure_reason: str | None
    cleanup_performed: bool
    cleanup_failed: bool

    @property
    def succeeded(self) -> bool:
        return (
            self.final_status == StageStatus.PASSED
            and self.verification is not None
            and self.verification.final_status == StageStatus.PASSED.value
            and self.state in {ExecutionState.SUCCEEDED, ExecutionState.CLEANED}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            "state": self.state.value,
            "finalStatus": self.final_status.value,
            "succeeded": self.succeeded,
            "failureReason": self.failure_reason,
            "cleanupPerformed": self.cleanup_performed,
            "cleanupFailed": self.cleanup_failed,
            "verification": (
                self.verification.to_dict() if self.verification is not None else None
            ),
        }


_PROCESS_CATEGORIES = {
    ProcessErrorCategory.COMMAND_NOT_FOUND: ExecutionErrorCategory.COMMAND_NOT_FOUND,
    ProcessErrorCategory.PERMISSION: ExecutionErrorCategory.PERMISSION,
    ProcessErrorCategory.TIMEOUT: ExecutionErrorCategory.TIMEOUT,
    ProcessErrorCategory.CANCELLED: ExecutionErrorCategory.CANCELLED,
    ProcessErrorCategory.NONZERO: ExecutionErrorCategory.NON_ZERO_EXIT,
}

_STATE_BOUNDARIES: Mapping[str, tuple[ExecutionState, ...]] = {
    "generated-files": (ExecutionState.VALIDATED,),
    "registry-lifecycle": (ExecutionState.BUILDING,),
    "build-once": (ExecutionState.BUILT, ExecutionState.PUSHING),
    "resolve-digest": (ExecutionState.DIGEST_RESOLVED,),
    "server-side-dry-run": (ExecutionState.CLUSTER_PREPARING,),
    "deployment": (ExecutionState.APPLYING,),
    "rollout": (ExecutionState.WAITING_READY,),
    "readiness": (ExecutionState.SMOKE_TESTING, ExecutionState.ATTESTING),
    "rollback": (ExecutionState.COLLECTING_EVIDENCE,),
}


class LocalKindOrchestrator:
    """Execute every required profile stage in exact policy order.

    A terminal journal state is necessary but not sufficient for success. The
    returned outcome is successful only after the finalizer verifies the closed
    evidence inventory and its semantic cross-record invariants.
    """

    def __init__(
        self,
        store: EvidenceStore,
        plan: ExecutionPlan,
        executor: LocalKindStageExecutor,
        finalizer: EvidenceBundleFinalizer,
        *,
        project_path: str,
        config_hash: str,
        template_lock_hash: str,
        cleanup_policy: str = "always",
        keep_environment_on_failure: bool = False,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(store, EvidenceStore):
            raise TypeError("store must be an EvidenceStore")
        if not isinstance(plan, ExecutionPlan):
            raise TypeError("plan must be an ExecutionPlan")
        if plan.run_id != store.run_id:
            raise LocalExecutionError("plan and evidence store run IDs differ")
        if plan.profile.value != "kind-e2e":
            raise LocalExecutionError("local-kind orchestration requires kind-e2e")
        if cleanup_policy not in {"always", "on-success", "never"}:
            raise LocalExecutionError("unsupported cleanup policy")
        if not isinstance(keep_environment_on_failure, bool):
            raise TypeError("keep_environment_on_failure must be boolean")
        if not callable(finalizer):
            raise TypeError("finalizer must be callable")
        self.store = store
        self.plan = plan
        self.executor = executor
        self.finalizer = finalizer
        self.project_path = project_path
        self.config_hash = config_hash
        self.template_lock_hash = template_lock_hash
        self.cleanup_policy = cleanup_policy
        self.keep_environment_on_failure = keep_environment_on_failure
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self) -> LocalExecutionOutcome:
        started = self._now()
        journal = ExecutionJournal(self.store)
        journal.append(
            StateTransition(
                ExecutionState.PLANNED,
                started,
                started,
                self.plan.build_plan_hash,
                outputs={"runId": self.plan.run_id},
                exit_code=0,
            )
        )
        self.store.write_json("plan.json", self.plan.to_dict())
        policy = profile_policy(self.plan.profile).to_dict()
        self.store.write_json("policy.json", policy)

        results: list[StageResult] = []
        cleanup_performed = False
        for stage in self.plan.stages:
            stage_started = self._now()
            try:
                evidence = self.executor.execute(stage)
                if not isinstance(evidence, StageExecutionEvidence):
                    raise LocalExecutionError(
                        f"stage executor returned invalid evidence for {stage.stage_id}"
                    )
            except Exception as error:
                stage_finished = self._now()
                failed = self._failed_stage(stage, stage_started, stage_finished, error)
                results.append(failed)
                self._append_failed_state(journal, stage, stage_started, stage_finished, error)
                cleanup_failed = False
                if self._cleanup_after_failure_required():
                    try:
                        cleanup = self.executor.cleanup_after_failure()
                        cleanup_performed = cleanup.cleanup_performed
                        if cleanup_performed:
                            self._append_cleaned_state(journal, cleanup)
                    except Exception as cleanup_error:
                        cleanup_failed = True
                        cleanup_path = self._write_cleanup_failure(cleanup_error)
                        results[-1] = replace(
                            results[-1],
                            evidence_paths=tuple(
                                dict.fromkeys(
                                    (*results[-1].evidence_paths, cleanup_path)
                                )
                            ),
                        )
                run = self._run_record(
                    started,
                    self._now(),
                    tuple(results),
                    failed.status,
                    self._safe_error(error),
                )
                verification = self._finalize_failure(run, policy)
                return LocalExecutionOutcome(
                    self.store.run_id,
                    journal.current_state or ExecutionState.FAILED,
                    failed.status,
                    verification,
                    self._safe_error(error),
                    cleanup_performed,
                    cleanup_failed,
                )

            stage_finished = self._now()
            results.append(
                self._passed_stage(stage, stage_started, stage_finished, evidence)
            )
            cleanup_performed = cleanup_performed or evidence.cleanup_performed
            self._append_boundaries(journal, stage, stage_started, stage_finished, evidence)

        run = self._run_record(
            started,
            self._now(),
            tuple(results),
            StageStatus.PASSED,
            None,
        )
        # Reject a false success candidate before mutating the journal terminal state.
        validate_runtime_records(self.plan.to_dict(), run.to_dict())
        terminal = self._now()
        journal.append(
            StateTransition(
                ExecutionState.SUCCEEDED,
                terminal,
                terminal,
                self.plan.build_plan_hash,
                previous_state=ExecutionState.COLLECTING_EVIDENCE,
                outputs={"cleanupPerformed": cleanup_performed},
                exit_code=0,
            )
        )
        if cleanup_performed:
            self._append_cleaned_state(
                journal,
                StageExecutionEvidence(
                    self.plan.build_plan_hash,
                    sanitized_output="run-owned resources removed",
                    cleanup_performed=True,
                ),
            )
        verification = self.finalizer(
            store=self.store,
            plan=self.plan,
            run=run,
            policy=policy,
        )
        return LocalExecutionOutcome(
            self.store.run_id,
            journal.current_state or ExecutionState.SUCCEEDED,
            StageStatus.PASSED,
            verification,
            None,
            cleanup_performed,
            False,
        )

    def _finalize_failure(
        self,
        run: ExecutionRun,
        policy: Mapping[str, Any],
    ) -> RuntimeVerification | None:
        try:
            validate_runtime_records(self.plan.to_dict(), run.to_dict())
            return self.finalizer(
                store=self.store,
                plan=self.plan,
                run=run,
                policy=policy,
            )
        except Exception as error:
            self.store.write_json(
                "diagnostics/evidence-finalization.json",
                {
                    "schemaVersion": "1.0.0",
                    "runId": self.store.run_id,
                    "error": self._safe_error(error),
                },
                overwrite=self.store.path(
                    "diagnostics/evidence-finalization.json"
                ).exists(),
            )
            return None

    def _run_record(
        self,
        started: str,
        finished: str,
        stages: tuple[StageResult, ...],
        final_status: StageStatus,
        failure_reason: str | None,
    ) -> ExecutionRun:
        products = self.executor.products()
        if not isinstance(products, ExecutionProducts):
            raise LocalExecutionError("stage executor returned invalid execution products")
        return ExecutionRun(
            run_id=self.store.run_id,
            project_path=self.project_path,
            config_hash=self.config_hash,
            template_lock_hash=self.template_lock_hash,
            source_revision=self.plan.artifact_intent.source_revision,
            start_time=started,
            end_time=finished,
            execution_profile=self.plan.profile.value,
            stage_results=stages,
            final_status=final_status,
            tool_versions=dict(products.tool_versions),
            artifact_record=products.artifact,
            supply_chain_evidence=products.supply_chain,
            deployment_evidence=products.deployment,
            failure_reason=failure_reason,
            schema_version=LEGACY_EXECUTION_EVIDENCE_SCHEMA_VERSION,
        )

    def _passed_stage(
        self,
        stage: PlannedStage,
        started: str,
        finished: str,
        evidence: StageExecutionEvidence,
    ) -> StageResult:
        process = evidence.process
        command = process.argv if process is not None else evidence.command
        output = evidence.sanitized_output
        if output is None and process is not None:
            output = "\n".join(value for value in (process.stdout, process.stderr) if value)
        return StageResult(
            stage.stage_id,
            stage.description,
            StageStatus.PASSED,
            started,
            finished,
            command=tuple(redact_process_output(argument) for argument in command),
            tool=evidence.tool,
            sanitized_output=(self._bounded_text(output) if output else None),
            evidence_paths=tuple(evidence.evidence_paths),
        )

    def _failed_stage(
        self,
        stage: PlannedStage,
        started: str,
        finished: str,
        error: Exception,
    ) -> StageResult:
        process = self._process_result(error)
        blocked = isinstance(error, (CommandNotFoundError, EnvironmentBlockedError))
        status = (
            StageStatus.BLOCKED_MISSING_REQUIRED_TOOL if blocked else StageStatus.FAILED
        )
        remediation = (
            "Install the required pinned local execution tool and rerun this run as a new run ID."
            if blocked
            else None
        )
        output = None
        if process is not None:
            output = "\n".join(value for value in (process.stdout, process.stderr) if value)
        return StageResult(
            stage.stage_id,
            stage.description,
            status,
            started,
            finished,
            command=process.argv if process is not None else (),
            tool=(process.argv[0] if process is not None and process.argv else None),
            sanitized_output=(self._bounded_text(output) if output else None),
            failure_reason=self._safe_error(error),
            remediation=remediation,
        )

    def _append_boundaries(
        self,
        journal: ExecutionJournal,
        stage: PlannedStage,
        started: str,
        finished: str,
        evidence: StageExecutionEvidence,
    ) -> None:
        for index, target in enumerate(_STATE_BOUNDARIES.get(stage.stage_id, ())):
            process = evidence.process
            boundary_started = started if index == 0 else finished
            journal.append(
                StateTransition(
                    target,
                    boundary_started,
                    finished,
                    evidence.subject,
                    previous_state=journal.current_state,
                    outputs={"plannedStage": stage.stage_id},
                    command=process.argv if process is not None else evidence.command,
                    exit_code=process.returncode if process is not None else 0,
                    stdout=process.stdout if process is not None else "",
                    stderr=process.stderr if process is not None else "",
                )
            )

    def _append_failed_state(
        self,
        journal: ExecutionJournal,
        stage: PlannedStage,
        started: str,
        finished: str,
        error: Exception,
    ) -> None:
        process = self._process_result(error)
        category = ExecutionErrorCategory.VALIDATION
        if isinstance(error, ProcessExecutionError):
            category = _PROCESS_CATEGORIES[error.category]
        elif isinstance(error, EnvironmentBlockedError):
            category = ExecutionErrorCategory.COMMAND_NOT_FOUND
        journal.append(
            StateTransition(
                ExecutionState.FAILED,
                started,
                finished,
                self.plan.build_plan_hash,
                previous_state=journal.current_state,
                outputs={"failedStage": stage.stage_id},
                command=process.argv if process is not None else (),
                exit_code=process.returncode if process is not None else None,
                stdout=process.stdout if process is not None else "",
                stderr=(process.stderr if process is not None else self._safe_error(error)),
                timed_out=category == ExecutionErrorCategory.TIMEOUT,
                error_category=category,
                retryable=category
                in {ExecutionErrorCategory.TIMEOUT, ExecutionErrorCategory.CANCELLED},
            )
        )

    def _append_cleaned_state(
        self,
        journal: ExecutionJournal,
        evidence: StageExecutionEvidence,
    ) -> None:
        timestamp = self._now()
        journal.append(
            StateTransition(
                ExecutionState.CLEANED,
                timestamp,
                timestamp,
                evidence.subject,
                previous_state=journal.current_state,
                outputs={"cleanupPerformed": True},
                command=evidence.command,
                exit_code=0,
            )
        )

    def _cleanup_after_failure_required(self) -> bool:
        return (
            self.cleanup_policy == "always"
            and not self.keep_environment_on_failure
        )

    def _write_cleanup_failure(self, error: Exception) -> str:
        relative = "diagnostics/cleanup-failure.json"
        self.store.write_json(
            relative,
            {
                "schemaVersion": "1.0.0",
                "runId": self.store.run_id,
                "error": self._safe_error(error),
                "retryable": True,
            },
            overwrite=self.store.path(relative).exists(),
        )
        return relative

    def _now(self) -> str:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise LocalExecutionError("clock must return timezone-aware datetime values")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _process_result(error: Exception) -> ProcessResult | None:
        if isinstance(error, ProcessExecutionError):
            return error.result
        candidate = getattr(error, "process_result", None)
        return candidate if isinstance(candidate, ProcessResult) else None

    @staticmethod
    def _safe_error(error: BaseException) -> str:
        return redact_process_output(str(error))[:8_000] or type(error).__name__

    @staticmethod
    def _bounded_text(value: str, limit: int = 16_384) -> str:
        sanitized = redact_process_output(value)
        payload = sanitized.encode("utf-8")
        if len(payload) <= limit:
            return sanitized
        marker = b"\n...[output truncated]"
        available = max(0, limit - len(marker))
        prefix = payload[:available].decode("utf-8", errors="ignore")
        return prefix + marker.decode("ascii")


__all__ = [
    "EnvironmentBlockedError",
    "EvidenceBundleFinalizer",
    "ExecutionProducts",
    "LocalExecutionError",
    "LocalExecutionOutcome",
    "LocalKindOrchestrator",
    "LocalKindStageExecutor",
    "StageExecutionEvidence",
]
