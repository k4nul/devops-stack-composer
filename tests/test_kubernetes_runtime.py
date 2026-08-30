from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from devops_stack_composer.adapters.kubernetes import KubernetesAdapter
from devops_stack_composer.config import load_config
from devops_stack_composer.kubernetes_runtime import (
    KubernetesRenderError,
    render_intentional_readiness_failure,
    render_resolved_environment,
)
from devops_stack_composer.sources import SourceResolution


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
LOCAL_REFERENCE = "127.0.0.1:49153/k4nul/devops-stack-composer-example@" + DIGEST


class KubernetesRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = load_config(ROOT / "examples/python-service/devops-stack.yaml").model
        source = SourceResolution(
            "kubernetes",
            ROOT / "tests/fixtures/templates/docker",
            "fixture",
            "c" * 40,
            None,
            True,
        )
        cls.artifacts = KubernetesAdapter(source).render(
            cls.model, validate_upstream=False
        ).artifacts

    def test_renders_each_environment_with_only_exact_digest_images(self) -> None:
        for environment in ("dev", "staging", "production"):
            with self.subTest(environment=environment):
                manifest = render_resolved_environment(
                    self.artifacts,
                    self.model,
                    environment,
                    LOCAL_REFERENCE,
                )
                self.assertEqual(manifest.environment, environment)
                self.assertEqual(len(manifest.sha256), 64)
                self.assertNotIn("__IMAGE_TAG__", manifest.content)
                self.assertNotIn(":latest", manifest.content)
                images = []
                for document in manifest.documents:
                    if document.get("kind") == "Deployment":
                        images.extend(
                            container["image"]
                            for container in document["spec"]["template"]["spec"]["containers"]
                        )
                self.assertEqual(images, [LOCAL_REFERENCE])

    def test_failure_revision_changes_only_configuration_not_image(self) -> None:
        manifest = render_resolved_environment(
            self.artifacts,
            self.model,
            "staging",
            LOCAL_REFERENCE,
        )
        failure = render_intentional_readiness_failure(
            manifest,
            deployment_name=self.model.service_name,
            run_id="run-123",
        )
        deployment = yaml.safe_load(failure)
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], LOCAL_REFERENCE)
        self.assertEqual(
            container["readinessProbe"]["httpGet"]["path"],
            "/__devops-stack-intentional-readiness-failure__",
        )
        self.assertEqual(
            deployment["metadata"]["annotations"]["devops-stack.io/rollback-test"],
            "run-123",
        )

    def test_rejects_tagged_and_unrelated_repositories(self) -> None:
        with self.assertRaisesRegex(KubernetesRenderError, "without a tag"):
            render_resolved_environment(
                self.artifacts,
                self.model,
                "staging",
                "127.0.0.1:49153/k4nul/devops-stack-composer-example:mutable@" + DIGEST,
            )
        with self.assertRaisesRegex(KubernetesRenderError, "does not match"):
            render_resolved_environment(
                self.artifacts,
                self.model,
                "staging",
                "127.0.0.1:49153/other/service@" + DIGEST,
            )

    def test_rejects_unsafe_or_missing_overlay_inventory(self) -> None:
        values = list(self.artifacts)
        for index, artifact in enumerate(values):
            if artifact.path == "k8s/overlays/staging/kustomization.yaml":
                parsed = yaml.safe_load(artifact.content)
                parsed["patches"].append({"path": "../escape.yaml"})
                values[index] = type(artifact)(
                    artifact.path,
                    yaml.safe_dump(parsed, sort_keys=False),
                    artifact.mode,
                    artifact.origins,
                )
                break
        with self.assertRaisesRegex(KubernetesRenderError, "unsafe patch"):
            render_resolved_environment(values, self.model, "staging", LOCAL_REFERENCE)


if __name__ == "__main__":
    unittest.main()
