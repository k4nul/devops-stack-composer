from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.config import validate_config
from devops_stack_composer.inspector import initial_config, inspect_application


class ApplicationInspectorTests(unittest.TestCase):
    def test_checked_in_node_fixture_is_detected_and_executable(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "apps" / "node-service"

        result = inspect_application(fixture)

        self.assertEqual(result.runtime.application_type, "nodejs")
        self.assertEqual(result.build_command, "npm install --no-package-lock && npm run build")
        self.assertEqual(result.test_command, "npm test")
        self.assertEqual(result.run_command, "npm start")
        self.assertEqual(result.health_endpoint, "/health")
        self.assertEqual(result.readiness_endpoint, "/ready")

    def test_node_application_uses_package_scripts_and_detects_existing_devops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "build": "tsc",
                            "test": "node --test",
                            "start": "node dist/server.js",
                        }
                    }
                ),
                encoding="utf-8",
            )
            (root / "server.js").write_text(
                "const PORT = 4321; app.get('/health', ok); app.get('/ready', ok);\n",
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text("FROM node:22-alpine\nEXPOSE 4321\n", encoding="utf-8")
            (root / "Jenkinsfile").write_text("pipeline {}\n", encoding="utf-8")
            (root / "deployment.yaml").write_text(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n",
                encoding="utf-8",
            )

            result = inspect_application(root)

            self.assertEqual(result.runtime.application_type, "nodejs")
            self.assertEqual(
                result.build_command,
                "npm install --no-package-lock && npm run build",
            )
            self.assertEqual(result.port, 4321)
            self.assertEqual(result.health_endpoint, "/health")
            self.assertEqual(result.readiness_endpoint, "/ready")
            self.assertEqual(result.dockerfiles, ("Dockerfile",))
            self.assertEqual(result.jenkinsfiles, ("Jenkinsfile",))
            self.assertEqual(result.kubernetes_files, ("deployment.yaml",))

    def test_python_application_detects_main_script(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
            (root / "app").mkdir()
            (root / "app" / "server.py").write_text(
                "PORT = 8080\nHEALTH = '/health'\nREADY = '/ready'\n",
                encoding="utf-8",
            )

            result = inspect_application(root)

            self.assertEqual(result.runtime.application_type, "python")
            self.assertEqual(result.run_command, "python app/server.py")
            self.assertEqual(result.port, 8080)

    def test_multiple_language_markers_are_reported_as_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.invalid/app\n", encoding="utf-8")
            (root / "Cargo.toml").write_text("[package]\nname='app'\n", encoding="utf-8")

            result = inspect_application(root)

            self.assertIn("multiple application types detected", result.conflicts[0])

    def test_initial_config_is_schema_valid_and_marks_inference(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sample-api-") as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.invalid/app\n", encoding="utf-8")
            inspection = inspect_application(root)

            config = initial_config(inspection)

            validate_config(config)
            self.assertEqual(config["application"]["type"], "go")
            self.assertEqual(config["metadata"]["annotations"]["devops-stack.io/review-required"], "true")
            self.assertEqual(config["environments"]["production"]["replicas"], 3)

    def test_unknown_application_lists_missing_information(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = inspect_application(Path(directory))

            self.assertIsNone(result.runtime.application_type)
            self.assertIn("application type", result.missing)
            self.assertIn("health endpoint", result.missing)


if __name__ == "__main__":
    unittest.main()
