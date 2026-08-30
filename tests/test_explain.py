from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.errors import ManifestValidationError
from devops_stack_composer.explain import explain_config_value, explain_generated_file
from devops_stack_composer.manifest import ArtifactWriter
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


class ExplainTests(unittest.TestCase):
    def test_sensitive_configuration_value_is_redacted(self) -> None:
        explanation = explain_config_value(
            {"deployment": {"environment": {"API_TOKEN": "must-not-leak"}}},
            "config:$.deployment.environment.API_TOKEN",
        )

        self.assertEqual(explanation["value"], "<redacted>")

    def test_consumer_mapping_is_path_aware(self) -> None:
        credential = explain_config_value(
            {"ci": {"jenkins": {"credentialId": "registry-id"}}},
            "$.ci.jenkins.credentialId",
        )
        annotations = explain_config_value(
            {"metadata": {"annotations": {"owner": "platform"}}},
            "$.metadata.annotations",
        )

        self.assertEqual(credential["consumers"], ["jenkins"])
        self.assertEqual(credential["value"], "registry-id")
        self.assertEqual(annotations["consumers"], [])

    def test_consumer_mapping_does_not_overclaim_application_or_probe_fields(self) -> None:
        config = {
            "application": {
                "root": ".",
                "runCommand": "python app.py",
                "buildArtifact": "app.py",
            },
            "deployment": {
                "health": {"path": "/health"},
                "readiness": {"path": "/ready"},
            },
        }

        self.assertEqual(
            explain_config_value(config, "$.application.root")["consumers"],
            ["docker"],
        )
        self.assertEqual(
            explain_config_value(config, "$.application.runCommand")["consumers"],
            ["docker"],
        )
        self.assertEqual(
            explain_config_value(config, "$.application.buildArtifact")["consumers"],
            ["docker", "contract-validator"],
        )
        for path in ("$.deployment.health.path", "$.deployment.readiness.path"):
            with self.subTest(path=path):
                self.assertEqual(
                    explain_config_value(config, path)["consumers"],
                    ["kubernetes", "contract-validator"],
                )

    def test_explain_returns_config_and_template_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = GeneratedArtifact(
                "docker/Dockerfile",
                "FROM scratch\n",
                origins=("$.application.type", "docker-build-template:build-contract"),
            )
            results = tuple(
                AdapterResult(
                    name,
                    "1.0.0",
                    prefix * 40,
                    (artifact,) if name == "docker" else (),
                    {},
                )
                for name, prefix in (("docker", "d"), ("jenkins", "e"), ("kubernetes", "f"))
            )
            ArtifactWriter(root).write(
                (artifact,),
                config_hash="a" * 64,
                results=results,
                validation=ValidationReport(
                    (CheckResult("contract", ValidationStatus.PASSED, "ok"),)
                ),
                environments=("dev", "staging", "production"),
            )

            explanation = explain_generated_file(root, "generated/docker/Dockerfile")

            self.assertEqual(explanation["adapter"], "docker")
            self.assertEqual(explanation["template"]["commit"], "d" * 40)
            self.assertIn("$.application.type", explanation["origins"])

    def test_untracked_file_cannot_be_explained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ManifestValidationError, "no generated manifest"):
                explain_generated_file(Path(directory), "generated/unknown")


if __name__ == "__main__":
    unittest.main()
