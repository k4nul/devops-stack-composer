from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.build_once import BuildResult, PlatformDescriptor
from devops_stack_composer.composition import Composition
from devops_stack_composer.config import load_config
from devops_stack_composer.execution import (
    ExecutionError,
    ExecutionOptions,
    ExecutionOrchestrator,
    vulnerability_policy_from_model,
)
from devops_stack_composer.execution_bundle import verify_execution_bundle
from devops_stack_composer.execution_models import SupplyChainEvidence
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"
REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def composition(project: Path) -> Composition:
    loaded = load_config(CONFIG)
    loaded = replace(
        loaded,
        model=replace(loaded.model, architectures=("linux/amd64",)),
    )
    lock = TemplateLock.load(ROOT / "templates.lock.json")
    sources = {
        key: SourceResolution(
            key=key,
            path=project,
            origin="fixture",
            commit=lock.pin(key).commit,
            remote=lock.pin(key).repository,
            matches_lock=True,
        )
        for key in ("docker", "jenkins", "kubernetes")
    }
    artifacts = (
        GeneratedArtifact(
            "docker/Dockerfile",
            "FROM scratch\n",
            origins=("$.build",),
        ),
        GeneratedArtifact(
            "docker/Dockerfile.dockerignore",
            ".git\n",
            origins=("$.build",),
        ),
        GeneratedArtifact(
            "jenkins/Jenkinsfile",
            "pipeline {}\n",
            origins=("$.ci",),
        ),
    )
    results = tuple(
        AdapterResult(
            adapter=key,
            adapter_version=lock.pin(key).adapter_version,
            template_commit=lock.pin(key).commit,
            artifacts=tuple(
                artifact
                for artifact in artifacts
                if artifact.path.startswith("k8s/" if key == "kubernetes" else f"{key}/")
            ),
            contract=loaded.model.contract(),
        )
        for key in ("docker", "jenkins", "kubernetes")
    )
    validation = ValidationReport(
        (
            CheckResult(
                "fixture",
                ValidationStatus.PASSED,
                "executable fixture validation passed",
            ),
        )
    )
    return Composition(project, loaded, lock, sources, results, artifacts, validation)


class FakeBuildExecutor:
    def __init__(self) -> None:
        self.execute_count = 0
        self.tag_checks = 0

    def execute(self, request):
        self.execute_count += 1
        request.metadata_path.write_text("{}\n", encoding="utf-8")
        request.invocation_marker.write_text("1\n", encoding="utf-8")
        return BuildResult(
            repository=request.repository,
            tag=request.tag,
            digest=DIGEST,
            media_type="application/vnd.oci.image.manifest.v1+json",
            size=123,
            config_digest=CONFIG_DIGEST,
            platforms=(
                PlatformDescriptor(
                    operating_system="linux",
                    architecture="amd64",
                    digest=DIGEST,
                    media_type="application/vnd.oci.image.manifest.v1+json",
                    size=123,
                    config_digest=CONFIG_DIGEST,
                ),
            ),
            build_invocation_count=1,
            build_metadata_path=request.metadata_path,
            command=("docker", "buildx", "build"),
            stdout=b"built\n",
            stderr=b"",
        )

    def verify_tag_unchanged(self, result, *, project, environment=None):
        self.tag_checks += 1


class FakeSupplyChainGenerator:
    def generate(self, *, run_root, artifact, policy, **kwargs):
        files = {
            "sbom.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
            "vulnerabilities.json": b'{"SchemaVersion":2,"Results":[]}\n',
            "provenance.json": b'{"_type":"https://in-toto.io/Statement/v1"}\n',
        }
        for relative, payload in files.items():
            (run_root / relative).write_bytes(payload)
        return SupplyChainEvidence(
            artifact_digest=artifact.manifest_digest,
            sbom_path="sbom.spdx.json",
            sbom_format="spdx-json",
            sbom_hash=hashlib.sha256(files["sbom.spdx.json"]).hexdigest(),
            sbom_generator="syft-1.51.1",
            vulnerability_report_path="vulnerabilities.json",
            vulnerability_report_hash=hashlib.sha256(
                files["vulnerabilities.json"]
            ).hexdigest(),
            scanner_name="trivy",
            scanner_version="0.74.0",
            scanner_database_metadata={"Version": 2},
            policy_result={"passed": True},
            provenance_path="provenance.json",
            provenance_hash=hashlib.sha256(files["provenance.json"]).hexdigest(),
            provenance_type="https://slsa.dev/provenance/v1",
            attestation_subject=artifact.immutable_image_reference,
            verification_status=(
                "CHECKSUM_ONLY_FILE_EVIDENCE:signature=false,attachment=false,crypto=false"
            ),
            evidence_generation_time="2026-08-30T12:00:00Z",
        )


class ExecutionTests(unittest.TestCase):
    def orchestrator(self, *, build_executor=None, supply_chain_generator=None):
        return ExecutionOrchestrator(
            build_executor=build_executor,
            supply_chain_generator=supply_chain_generator,
            source_revision_resolver=lambda project: REVISION,
            clock=lambda: NOW,
        )

    def test_static_profile_closes_a_verifiable_run_without_external_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            result = self.orchestrator().execute(
                composition(project),
                ExecutionOptions(
                    profile="static",
                    run_id="20260830T120000Z-0123456789ab",
                ),
            )

            self.assertTrue(result.passed)
            self.assertIsNone(result.run.artifact_record)
            self.assertEqual(
                [stage.status.value for stage in result.run.stage_results],
                ["PASSED", "PASSED", "PASSED", "PASSED"],
            )
            checksums = result.store.verify_checksums()
            self.assertIn("execution-plan.json", checksums)
            self.assertIn("execution-evidence.json", checksums)
            self.assertIn("report.md", checksums)
            self.assertNotIn("SHA256SUMS", checksums)
            fresh = verify_execution_bundle(
                project,
                result.run.run_id,
            )
            self.assertTrue(fresh.passed)
            self.assertIsNone(fresh.authoritative_digest)

    def test_supply_chain_builds_once_rechecks_tag_and_closes_same_digest(self) -> None:
        build = FakeBuildExecutor()
        supply = FakeSupplyChainGenerator()
        with tempfile.TemporaryDirectory() as directory:
            result = self.orchestrator(
                build_executor=build,
                supply_chain_generator=supply,
            ).execute(
                composition(Path(directory)),
                ExecutionOptions(
                    profile="supply-chain",
                    image_tag="run-test",
                    run_id="20260830T120000Z-abcdef012345",
                ),
            )

            self.assertTrue(result.passed)
            self.assertEqual(build.execute_count, 1)
            self.assertEqual(build.tag_checks, 2)
            self.assertEqual(result.run.artifact_record.manifest_digest, DIGEST)
            self.assertEqual(result.verification.authoritative_digest, DIGEST)
            self.assertEqual(
                result.run.stage_results[-1].stage_id,
                "cleanup",
            )
            self.assertEqual(result.run.stage_results[-1].status.value, "PASSED")
            self.assertEqual(result.store.verify_checksums()["artifact.json"], hashlib.sha256(
                result.store.path("artifact.json").read_bytes()
            ).hexdigest())

    def test_multi_platform_execution_fails_before_any_build(self) -> None:
        build = FakeBuildExecutor()
        value = composition(Path(tempfile.mkdtemp()))
        model = replace(value.loaded_config.model, architectures=("linux/amd64", "linux/arm64"))
        loaded = replace(value.loaded_config, model=model)
        value = replace(value, loaded_config=loaded)

        with self.assertRaisesRegex(
            ExecutionError,
            "MULTI_PLATFORM_EXECUTION_UNSUPPORTED",
        ):
            self.orchestrator(build_executor=build).execute(
                value,
                ExecutionOptions(profile="supply-chain"),
            )

        self.assertEqual(build.execute_count, 0)

    def test_legacy_and_current_vulnerability_shapes_map_explicitly(self) -> None:
        legacy = vulnerability_policy_from_model(
            {"scan": {"enabled": True, "failOn": "high"}}
        )
        current = vulnerability_policy_from_model(
            {
                "vulnerability": {
                    "required": True,
                    "severities": ["CRITICAL"],
                    "ignoreUnfixed": True,
                    "maximumAllowed": 0,
                    "allowlist": [
                        {
                            "id": "CVE-2026-1",
                            "package": "sample",
                            "reason": "bounded exception",
                            "owner": "security",
                            "expiresAt": "2026-12-01",
                        }
                    ],
                }
            }
        )

        self.assertEqual(legacy.severities, ("HIGH", "CRITICAL"))
        self.assertFalse(legacy.ignore_unfixed)
        self.assertEqual(current.severities, ("CRITICAL",))
        self.assertEqual(current.allowlist[0].vulnerability_id, "CVE-2026-1")


if __name__ == "__main__":
    unittest.main()
