from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from devops_stack_composer.composition import Composition
from devops_stack_composer.config import LoadedConfig, load_config
from devops_stack_composer.execution_planning import (
    ExecutionPlanningError,
    create_execution_plan,
    template_lock_hash,
    validate_local_kind_plan,
)
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.validation import (
    CheckResult,
    ValidationReport,
    ValidationStatus,
)


SOURCE_REVISION = "a" * 40
RUN_ID = "20260830T160000Z-012345abcdef"


class ExecutionPlanningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = Path(__file__).resolve().parents[1]
        cls.fixture = cls.repository / "tests" / "fixtures" / "configs" / "valid.yaml"
        cls.lock = TemplateLock.load(cls.repository / "templates.lock.json")
        loaded = load_config(cls.fixture)
        cls.base_composition = Composition(
            cls.repository,
            loaded,
            cls.lock,
            {},
            (),
            (),
            ValidationReport(
                (
                    CheckResult(
                        "fixture",
                        ValidationStatus.PASSED,
                        "fixture composition is valid",
                    ),
                )
            ),
        )

    def with_v02_model(self, *, platforms=("linux/amd64",)):
        composition = self.base_composition
        model = composition.loaded_config.model
        execution = {
            **model.execution,
            "profile": "kind-e2e",
        }
        registry = {
            "mode": "ephemeral-local",
            "host": "auto",
            "repository": model.image_repository,
            "insecureLocalhostOnly": True,
        }
        v02_model = replace(
            model,
            execution=execution,
            registry=registry,
            validation_profile="kind-e2e",
            architectures=tuple(platforms),
        )
        loaded = LoadedConfig(
            composition.loaded_config.path,
            composition.loaded_config.raw,
            v02_model,
            composition.loaded_config.config_hash,
        )
        return replace(composition, loaded_config=loaded)

    def test_plan_keeps_auto_logical_until_runtime_port_resolution(self) -> None:
        composition = self.with_v02_model()

        planned = create_execution_plan(
            composition,
            run_id=RUN_ID,
            source_revision=SOURCE_REVISION,
        )

        self.assertEqual(planned.plan.profile.value, "kind-e2e")
        self.assertEqual(planned.plan.artifact_intent.registry, "auto")
        self.assertEqual(planned.plan.artifact_intent.platforms, ("linux/amd64",))
        self.assertEqual(
            planned.plan.artifact_intent.template_revision,
            self.lock.pin("docker").commit,
        )
        self.assertEqual(len(planned.template_lock_hash), 64)
        self.assertEqual(planned.template_lock_hash, template_lock_hash(composition))
        validate_local_kind_plan(planned)

    def test_run_specific_tag_prevents_stale_plan_reuse(self) -> None:
        composition = self.with_v02_model()
        first = create_execution_plan(
            composition,
            run_id=RUN_ID,
            source_revision=SOURCE_REVISION,
        )
        second = create_execution_plan(
            composition,
            run_id="20260830T160001Z-ffffffffffff",
            source_revision=SOURCE_REVISION,
        )

        self.assertNotEqual(first.plan.build_plan_hash, second.plan.build_plan_hash)
        self.assertNotEqual(first.plan.run_id, second.plan.run_id)
        self.assertNotEqual(
            first.plan.artifact_intent.requested_tag,
            second.plan.artifact_intent.requested_tag,
        )

    def test_operator_overrides_are_reflected_without_runtime_allocation(self) -> None:
        planned = create_execution_plan(
            self.with_v02_model(),
            run_id=RUN_ID,
            source_revision=SOURCE_REVISION,
            profile="supply-chain",
            environment="dev",
            image_tag="candidate-2",
        )

        self.assertEqual(planned.plan.profile.value, "supply-chain")
        self.assertEqual(planned.plan.environment, "dev")
        self.assertEqual(planned.plan.artifact_intent.requested_tag, "candidate-2")
        self.assertEqual(planned.plan.artifact_intent.registry, "auto")

    def test_local_kind_rejects_multi_platform_before_side_effects(self) -> None:
        planned = create_execution_plan(
            self.with_v02_model(platforms=("linux/amd64", "linux/arm64")),
            run_id=RUN_ID,
            source_revision=SOURCE_REVISION,
        )

        with self.assertRaisesRegex(ExecutionPlanningError, "exactly one image platform"):
            validate_local_kind_plan(planned)

    def test_invalid_source_cannot_plan(self) -> None:
        composition = self.with_v02_model()
        with self.assertRaisesRegex(ExecutionPlanningError, "source_revision"):
            create_execution_plan(
                composition,
                run_id=RUN_ID,
                source_revision="main",
            )


if __name__ == "__main__":
    unittest.main()
