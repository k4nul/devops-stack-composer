"""Deterministic execution plans derived from artifact intent and profile policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from devops_stack_composer.execution_models import ArtifactIntent
from devops_stack_composer.policies import ValidationProfile, profile_policy


_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")

_DESCRIPTIONS = {
    "config-schema": "Validate the declarative configuration schema",
    "template-lock": "Resolve exact read-only template revisions",
    "adapter-contracts": "Validate Docker, Jenkins, and Kubernetes contracts",
    "generated-files": "Render deterministic static artifacts",
    "registry-lifecycle": "Start an isolated loopback registry",
    "build-once": "Build and push the application exactly once",
    "resolve-digest": "Resolve and verify immutable registry bytes",
    "sbom": "Generate an SPDX inventory from the immutable image",
    "vulnerability-scan": "Scan the immutable image and evaluate policy",
    "provenance": "Generate digest-bound SLSA provenance evidence",
    "artifact-contract": "Require one digest across all evidence",
    "kubernetes-schema": "Validate resolved Kubernetes schemas",
    "server-side-dry-run": "Ask a real Kubernetes API to dry-run every environment",
    "deployment": "Apply the staging digest-pinned manifests",
    "rollout": "Wait for Deployment availability",
    "pod-image": "Verify the runtime pod image ID",
    "health": "Verify the application health endpoint",
    "readiness": "Verify the application readiness endpoint",
    "rollback": "Fail one same-digest revision and restore it",
    "cleanup": "Remove only run-owned local resources",
    "package": "Build and inspect wheel and source distribution",
    "release-assets": "Assemble the complete release asset manifest",
    "release-download-verification": "Download and re-verify published assets",
    "working-tree": "Require a clean release worktree",
    "tag-commit": "Require the release tag at the validated commit",
}


@dataclass(frozen=True)
class PlannedStage:
    stage_id: str
    description: str
    required: bool

    def __post_init__(self) -> None:
        if self.stage_id not in _DESCRIPTIONS:
            raise ValueError(f"unsupported execution stage: {self.stage_id}")
        if not isinstance(self.description, str) or not self.description:
            raise ValueError("stage description must be non-empty")
        if not isinstance(self.required, bool):
            raise ValueError("stage required flag must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stageId": self.stage_id,
            "description": self.description,
            "required": self.required,
        }


@dataclass(frozen=True)
class ExecutionPlan:
    run_id: str
    profile: ValidationProfile
    environment: str
    artifact_intent: ArtifactIntent
    stages: tuple[PlannedStage, ...]
    production_apply_approved: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not _RUN_ID.fullmatch(self.run_id):
            raise ValueError("run_id contains unsafe characters")
        profile = ValidationProfile.parse(self.profile)
        object.__setattr__(self, "profile", profile)
        if not isinstance(self.environment, str) or not _DNS_LABEL.fullmatch(self.environment):
            raise ValueError("environment must be a lowercase DNS label")
        if not isinstance(self.artifact_intent, ArtifactIntent):
            raise ValueError("artifact_intent must be an ArtifactIntent")
        stages = tuple(self.stages)
        if any(not isinstance(stage, PlannedStage) for stage in stages):
            raise ValueError("stages must contain PlannedStage values")
        expected = profile_policy(profile).required_stages
        if tuple(stage.stage_id for stage in stages) != expected:
            raise ValueError("planned stages must exactly match profile policy order")
        if any(not stage.required for stage in stages):
            raise ValueError("profile policy stages must remain required")
        object.__setattr__(self, "stages", stages)
        if not isinstance(self.production_apply_approved, bool):
            raise ValueError("production_apply_approved must be boolean")
        if self.environment == "production" and "deployment" in expected:
            if not self.production_apply_approved:
                raise ValueError(
                    "production apply requires explicit approval; server-side dry-run does not"
                )

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        profile: str | ValidationProfile,
        environment: str,
        artifact_intent: ArtifactIntent,
        production_apply_approved: bool = False,
    ) -> "ExecutionPlan":
        selected = ValidationProfile.parse(profile)
        stages = tuple(
            PlannedStage(stage_id, _DESCRIPTIONS[stage_id], True)
            for stage_id in profile_policy(selected).required_stages
        )
        return cls(
            run_id,
            selected,
            environment,
            artifact_intent,
            stages,
            production_apply_approved,
        )

    def _deterministic_value(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "environment": self.environment,
            "artifactIntent": self.artifact_intent.to_dict(),
            "stages": [stage.to_dict() for stage in self.stages],
            "productionApplyApproved": self.production_apply_approved,
        }

    @property
    def build_plan_hash(self) -> str:
        payload = json.dumps(
            self._deterministic_value(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "1.0.0",
            "runId": self.run_id,
            **self._deterministic_value(),
            "buildPlanHash": self.build_plan_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"

