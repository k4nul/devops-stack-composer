"""Derive executable v0.2 plans from one validated composition."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from dataclasses import dataclass
from typing import Any

from devops_stack_composer.composition import Composition
from devops_stack_composer.execution_models import ArtifactIntent
from devops_stack_composer.execution_plan import ExecutionPlan
from devops_stack_composer.policies import ValidationProfile


_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")


class ExecutionPlanningError(ValueError):
    """Raised when validated configuration cannot produce an executable plan."""


@dataclass(frozen=True)
class PlannedExecution:
    plan: ExecutionPlan
    config_hash: str
    template_lock_hash: str
    source_revision: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "identities": {
                "configHash": self.config_hash,
                "templateLockHash": self.template_lock_hash,
                "sourceRevision": self.source_revision,
            },
        }


def template_lock_hash(composition: Composition) -> str:
    payload = json.dumps(
        composition.lock.data,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def create_execution_plan(
    composition: Composition,
    *,
    run_id: str,
    source_revision: str,
    profile: str | ValidationProfile | None = None,
    environment: str | None = None,
    image_tag: str | None = None,
    production_apply_approved: bool = False,
) -> PlannedExecution:
    """Create the deterministic logical plan before any runtime port is allocated."""

    if not isinstance(composition, Composition):
        raise TypeError("composition must be a Composition")
    if not composition.validation.passed:
        raise ExecutionPlanningError(
            "composition validation must pass before an execution plan is created"
        )
    if not isinstance(source_revision, str) or not _GIT_REVISION.fullmatch(source_revision):
        raise ExecutionPlanningError(
            "source_revision must be the full lowercase Git commit validated for this run"
        )

    model = composition.loaded_config.model
    if model.execution["profile"] != model.validation_profile:
        raise ExecutionPlanningError(
            "normalized execution and validation profiles must match"
        )
    selected_profile = ValidationProfile.parse(
        profile if profile is not None else model.execution["profile"]
    )
    selected_environment = environment or model.kubernetes_e2e["environment"]
    registry = model.registry
    logical_registry = "auto" if registry["mode"] == "ephemeral-local" else registry["host"]
    requested_tag = image_tag or f"run-{run_id.lower()}"
    build_arguments = {
        "OCI_REVISION": source_revision,
        "OCI_TITLE": model.application_name,
    }
    combined_context = (
        PurePosixPath(model.application_root) / model.build_context
    ).as_posix()
    intent = ArtifactIntent(
        application_name=model.application_name,
        registry=logical_registry,
        repository=registry["repository"],
        requested_tag=requested_tag,
        platforms=tuple(model.architectures),
        source_revision=source_revision,
        build_context=combined_context,
        dockerfile="generated/docker/Dockerfile",
        template_revision=composition.lock.pin("docker").commit,
        normalized_model_hash=composition.loaded_config.config_hash,
        build_arguments=build_arguments,
    )
    plan = ExecutionPlan.create(
        run_id=run_id,
        profile=selected_profile,
        environment=selected_environment,
        artifact_intent=intent,
        production_apply_approved=production_apply_approved,
    )
    return PlannedExecution(
        plan,
        composition.loaded_config.config_hash,
        template_lock_hash(composition),
        source_revision,
    )


def validate_local_kind_plan(planned: PlannedExecution) -> None:
    """Fail before side effects when the exact same-digest pilot cannot be proven."""

    plan = planned.plan
    if plan.profile.value != "kind-e2e":
        raise ExecutionPlanningError(
            "--local-kind requires the canonical kind-e2e execution profile"
        )
    if plan.artifact_intent.registry != "auto":
        raise ExecutionPlanningError(
            "--local-kind requires an ephemeral-local registry with host auto"
        )
    if len(plan.artifact_intent.platforms) != 1:
        raise ExecutionPlanningError(
            "--local-kind same-digest attestation currently requires exactly one image platform"
        )
    if plan.environment == "production":
        raise ExecutionPlanningError(
            "--local-kind does not apply the production environment"
        )
