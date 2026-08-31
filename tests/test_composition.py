from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

from devops_stack_composer.composition import (
    _adapter_provenance_report,
    compose,
    generated_integrity_report,
)
from devops_stack_composer.locks import TEMPLATE_KEYS, TemplateLock
from devops_stack_composer.manifest import ArtifactWriter
from devops_stack_composer.sources import REQUIRED_MARKERS, SourceResolver
from devops_stack_composer.validation import ValidationStatus


ROOT = Path(__file__).resolve().parents[1]
CONFIG_FIXTURE = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"
DOCKER_TEMPLATE_FIXTURE = ROOT / "tests" / "fixtures" / "templates" / "docker"
V01_CONFIG_SHA256 = "b762d4b970c3a285c59b03b0ee37445f807105cef5e45e25b0f385d5c8b1a976"
V02_ARTIFACT_PATHS_FOR_V01_CONFIG = (
    "docker/Dockerfile",
    "docker/Dockerfile.dockerignore",
    "docker/build.sh",
    "docker/image.env",
    "docker/metadata.json",
    "jenkins/Jenkinsfile",
    "jenkins/README.md",
    "jenkins/artifact-contract.json",
    "jenkins/environments/dev.json",
    "jenkins/environments/production.json",
    "jenkins/environments/staging.json",
    "jenkins/job-dsl.groovy",
    "k8s/base/configmap.yaml",
    "k8s/base/deployment.yaml",
    "k8s/base/kustomization.yaml",
    "k8s/base/service.yaml",
    "k8s/base/serviceaccount.yaml",
    "k8s/overlays/dev/configmap.yaml",
    "k8s/overlays/dev/deployment.yaml",
    "k8s/overlays/dev/kustomization.yaml",
    "k8s/overlays/dev/namespace.yaml",
    "k8s/overlays/dev/service.yaml",
    "k8s/overlays/production/configmap.yaml",
    "k8s/overlays/production/deployment.yaml",
    "k8s/overlays/production/kustomization.yaml",
    "k8s/overlays/production/namespace.yaml",
    "k8s/overlays/production/service.yaml",
    "k8s/overlays/staging/configmap.yaml",
    "k8s/overlays/staging/deployment.yaml",
    "k8s/overlays/staging/kustomization.yaml",
    "k8s/overlays/staging/namespace.yaml",
    "k8s/overlays/staging/service.yaml",
    "k8s/platform-context.json",
)


def _run_git(*arguments: str, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def _fixture_repository(root: Path, key: str) -> str:
    if key == "docker":
        shutil.copytree(DOCKER_TEMPLATE_FIXTURE, root)
    else:
        root.mkdir(parents=True)
    for marker in REQUIRED_MARKERS[key]:
        path = root / marker
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if marker == "LICENSE":
            content = "MIT License\n\nOffline composition fixture.\n"
        elif path.suffix == ".ps1":
            content = "# Offline composition fixture; upstream execution is disabled.\n"
        elif path.name.endswith("Jenkinsfile"):
            content = "pipeline { agent none }\n"
        else:
            content = "# Offline composition fixture.\n"
        path.write_text(content, encoding="utf-8")

    _run_git("init", "--quiet", str(root))
    _run_git("-C", str(root), "config", "user.email", "fixture@example.invalid")
    _run_git("-C", str(root), "config", "user.name", "Fixture")
    _run_git("-C", str(root), "add", ".")
    commit_environment = dict(os.environ)
    commit_environment.update(
        {
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
    )
    _run_git(
        "-C",
        str(root),
        "commit",
        "--quiet",
        "-m",
        "offline fixture",
        environment=commit_environment,
    )
    return _run_git("-C", str(root), "rev-parse", "HEAD")


class OfflineCompositionTests(unittest.TestCase):
    def test_frozen_v01_config_composes_deterministically_and_manifest_clean(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONFIG_FIXTURE.read_bytes()).hexdigest(),
            V01_CONFIG_SHA256,
        )
        with tempfile.TemporaryDirectory(prefix="composition-e2e-") as directory:
            temporary = Path(directory)
            project = temporary / "project"
            project.mkdir()

            config = copy.deepcopy(
                yaml.safe_load(CONFIG_FIXTURE.read_text(encoding="utf-8"))
            )
            config["image"]["architectures"] = ["linux/amd64"]
            config["build"]["cache"] = {
                "enabled": False,
                "from": [],
                "to": [],
            }
            config_path = project / "devops-stack.yaml"
            config_path.write_text(
                yaml.safe_dump(config, sort_keys=False),
                encoding="utf-8",
            )

            sources: dict[str, Path] = {}
            commits: dict[str, str] = {}
            for key in TEMPLATE_KEYS:
                source = temporary / "templates" / key
                sources[key] = source
                commits[key] = _fixture_repository(source, key)

            lock_data = copy.deepcopy(
                TemplateLock.load(ROOT / "templates.lock.json").data
            )
            for key in TEMPLATE_KEYS:
                lock_data["templates"][key]["commit"] = commits[key]
            lock_path = project / "templates.lock.json"
            lock_path.write_text(
                json.dumps(lock_data, indent=2) + "\n",
                encoding="utf-8",
            )
            lock = TemplateLock.load(lock_path)

            with (
                patch.object(
                    SourceResolver,
                    "_fetch_locked",
                    side_effect=AssertionError("offline test attempted a network fetch"),
                ) as fetch,
                patch(
                    "devops_stack_composer.adapters.kubernetes.shutil.which",
                    return_value=None,
                ),
            ):
                first = compose(
                    project=project,
                    config_path=config_path,
                    lock=lock,
                    explicit_template_paths=sources,
                    fetch_templates=False,
                    validate_upstream=False,
                )
                second = compose(
                    project=project,
                    config_path=config_path,
                    lock=lock,
                    explicit_template_paths=sources,
                    fetch_templates=False,
                    validate_upstream=False,
                )
            fetch.assert_not_called()

            self.assertEqual(
                tuple(result.adapter for result in first.results),
                TEMPLATE_KEYS,
            )
            for key in TEMPLATE_KEYS:
                self.assertEqual(first.sources[key].origin, "cli")
                self.assertEqual(first.sources[key].path, sources[key].resolve())
            self.assertTrue(first.validation.passed, first.validation.checks)
            self.assertFalse(
                any(
                    check.status
                    in {
                        ValidationStatus.FAILED,
                        ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL,
                    }
                    for check in first.validation.checks
                )
            )
            checks = {check.check: check for check in first.validation.checks}
            results = {result.adapter: result for result in first.results}
            for key in TEMPLATE_KEYS:
                self.assertEqual(
                    checks[f"template.{key}.locked-commit"].status,
                    ValidationStatus.PASSED,
                )
                self.assertEqual(
                    checks[f"contract.{key}.artifacts"].status,
                    ValidationStatus.PASSED,
                )
                self.assertEqual(
                    results[key].contract,
                    first.loaded_config.model.contract(),
                )
                self.assertEqual(
                    checks[f"template.{key}.adapter-provenance"].status,
                    ValidationStatus.PASSED,
                )

            tampered_results = list(first.results)
            tampered_results[2] = replace(
                tampered_results[2],
                template_commit="0" * 40,
                adapter_version="99.0.0",
            )
            provenance = _adapter_provenance_report(
                lock,
                first.sources,
                tuple(tampered_results),
            )
            kubernetes_provenance = next(
                check
                for check in provenance.checks
                if check.check == "template.kubernetes.adapter-provenance"
            )
            self.assertEqual(
                kubernetes_provenance.status,
                ValidationStatus.FAILED,
            )

            self.assertEqual(first.artifacts, second.artifacts)
            artifact_paths = tuple(artifact.path for artifact in first.artifacts)
            self.assertEqual(artifact_paths, V02_ARTIFACT_PATHS_FOR_V01_CONFIG)
            self.assertEqual(first.loaded_config.model.execution["profile"], "static")
            self.assertEqual(first.loaded_config.model.validation_profile, "static")
            self.assertEqual(first.loaded_config.model.registry["mode"], "existing")
            self.assertFalse(
                first.loaded_config.model.supply_chain["verification"][
                    "requireDigestPinnedDeployment"
                ]
            )
            self.assertEqual(
                {path.split("/", 1)[0] for path in artifact_paths},
                {"docker", "jenkins", "k8s"},
            )

            writer = ArtifactWriter(project)
            initial_plan = writer.plan(first.artifacts, previous=None)
            self.assertTrue(initial_plan.files)
            self.assertTrue(all(item.action == "create" for item in initial_plan.files))
            manifest = writer.write(
                first.artifacts,
                config_hash=first.loaded_config.config_hash,
                results=first.results,
                validation=first.validation,
                environments=("dev", "staging", "production"),
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )

            self.assertTrue(manifest.verify(project).clean)
            self.assertEqual(set(manifest.file_map()), set(artifact_paths))
            self.assertEqual(manifest.file_map()["docker/build.sh"]["mode"], "0755")
            loaded_manifest, integrity = generated_integrity_report(second)
            self.assertIsNotNone(loaded_manifest)
            self.assertTrue(integrity.passed, integrity.checks)
            self.assertTrue(
                all(check.status == ValidationStatus.PASSED for check in integrity.checks)
            )
            regenerated_plan = writer.plan(second.artifacts, loaded_manifest)
            self.assertTrue(
                all(item.action == "unchanged" for item in regenerated_plan.files)
            )

            manifest_path = project / "generated" / ".devops-stack-manifest.json"
            original_manifest = manifest_path.read_text(encoding="utf-8")
            manifest_data = json.loads(original_manifest)
            manifest_data["files"][0]["origins"] = [
                "fabricated-origin",
                "secret=plaintext",
            ]
            manifest_path.write_text(
                json.dumps(manifest_data, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            _, provenance_drift = generated_integrity_report(second)
            planned_content = next(
                check
                for check in provenance_drift.checks
                if check.check == "generated.planned-content"
            )
            self.assertEqual(planned_content.status, ValidationStatus.FAILED)
            manifest_path.write_text(original_manifest, encoding="utf-8")

            jenkinsfile = project / "generated" / "jenkins" / "Jenkinsfile"
            jenkinsfile.write_text(
                jenkinsfile.read_text(encoding="utf-8") + "// drift\n",
                encoding="utf-8",
            )
            _, drift = generated_integrity_report(second)
            file_integrity = next(
                check
                for check in drift.checks
                if check.check == "generated.file-integrity"
            )
            self.assertFalse(drift.passed)
            self.assertEqual(file_integrity.status, ValidationStatus.FAILED)
            self.assertEqual(
                file_integrity.details["modified"],
                ["jenkins/Jenkinsfile"],
            )


if __name__ == "__main__":
    unittest.main()
