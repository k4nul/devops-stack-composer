from __future__ import annotations

import json
import unittest

from devops_stack_composer.execution_models import ArtifactIntent
from devops_stack_composer.execution_plan import ExecutionPlan


def intent() -> ArtifactIntent:
    return ArtifactIntent(
        application_name="service",
        registry="registry.example",
        repository="acme/service",
        requested_tag="run-1",
        platforms=("linux/amd64",),
        source_revision="a" * 40,
        build_context=".",
        dockerfile="generated/docker/Dockerfile",
        template_revision="b" * 40,
        normalized_model_hash="c" * 64,
    )


class ExecutionPlanTests(unittest.TestCase):
    def test_plan_is_profile_ordered_and_hash_ignores_run_id(self) -> None:
        first = ExecutionPlan.create(
            run_id="run-one",
            profile="supply-chain",
            environment="staging",
            artifact_intent=intent(),
        )
        second = ExecutionPlan.create(
            run_id="run-two",
            profile="supply-chain",
            environment="staging",
            artifact_intent=intent(),
        )

        self.assertEqual(first.build_plan_hash, second.build_plan_hash)
        self.assertEqual(first.stages[-1].stage_id, "artifact-contract")
        self.assertTrue(all(stage.required for stage in first.stages))
        self.assertEqual(json.loads(first.to_json())["buildPlanHash"], first.build_plan_hash)

    def test_profile_changes_hash_and_required_stages(self) -> None:
        supply = ExecutionPlan.create(
            run_id="run-one",
            profile="supply-chain",
            environment="staging",
            artifact_intent=intent(),
        )
        kind = ExecutionPlan.create(
            run_id="run-one",
            profile="kind-e2e",
            environment="staging",
            artifact_intent=intent(),
        )
        self.assertNotEqual(supply.build_plan_hash, kind.build_plan_hash)
        self.assertIn("rollback", [stage.stage_id for stage in kind.stages])

    def test_production_apply_needs_explicit_approval(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            ExecutionPlan.create(
                run_id="run-one",
                profile="kind-e2e",
                environment="production",
                artifact_intent=intent(),
            )
        approved = ExecutionPlan.create(
            run_id="run-one",
            profile="kind-e2e",
            environment="production",
            artifact_intent=intent(),
            production_apply_approved=True,
        )
        self.assertTrue(approved.production_apply_approved)

    def test_static_production_plan_does_not_imply_apply(self) -> None:
        plan = ExecutionPlan.create(
            run_id="run-one",
            profile="static",
            environment="production",
            artifact_intent=intent(),
        )
        self.assertNotIn("deployment", [stage.stage_id for stage in plan.stages])


if __name__ == "__main__":
    unittest.main()
