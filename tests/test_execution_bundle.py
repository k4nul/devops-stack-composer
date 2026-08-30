from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.evidence_validation import validate_artifact_contract
from devops_stack_composer.execution_bundle import (
    ExecutionBundleError,
    inspect_execution_bundle,
    load_execution_bundle,
    load_resolved_artifact_file,
    load_strict_json_file,
    parse_strict_json,
    verify_execution_bundle,
)
from devops_stack_composer.execution_models import (
    ArtifactIntent,
    DeploymentEvidence,
    ExecutionRun,
    ResolvedArtifact,
    StageResult,
    StageStatus,
    SupplyChainEvidence,
)
from devops_stack_composer.execution_plan import ExecutionPlan
from devops_stack_composer.filesystem import sha256_file
from devops_stack_composer.supply_chain import (
    CHECKSUM_ONLY_VERIFICATION_STATUS,
    SUBJECT_ANNOTATION_PREFIX,
    create_provenance_statement,
)


DIGEST = "sha256:" + "a" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
SOURCE_REVISION = "d" * 40
REFERENCE = f"localhost:5000/team/app@{DIGEST}"
RUN_ID = "20260830T120000Z-abcdef123456"


def _spdx(reference: str = REFERENCE) -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "name": "team-app",
        "documentNamespace": "https://example.invalid/spdx/team-app",
        "creationInfo": {
            "created": "2026-08-30T12:00:00Z",
            "creators": ["Tool: syft-1.44.0"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-app",
                "name": "app",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "annotations": [
            {
                "annotationDate": "2026-08-30T12:00:00Z",
                "annotationType": "OTHER",
                "annotator": "Tool: devops-stack-composer-0.2.0",
                "comment": SUBJECT_ANNOTATION_PREFIX + reference,
            }
        ],
    }


def _trivy(reference: str = REFERENCE) -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactName": reference,
        "ArtifactType": "container_image",
        "Results": [],
    }


class BundleFixture:
    def __init__(self, project: Path):
        self.project = project
        self.store = EvidenceStore.create(project, run_id=RUN_ID)

        intent = ArtifactIntent(
            application_name="sample-app",
            registry="localhost:5000",
            repository="team/app",
            requested_tag="run-1",
            platforms=("linux/amd64",),
            source_revision=SOURCE_REVISION,
            build_context=".",
            dockerfile="generated/docker/Dockerfile",
            template_revision="e" * 40,
            normalized_model_hash="f" * 64,
        )
        self.plan = ExecutionPlan.create(
            run_id=RUN_ID,
            profile="kind-e2e",
            environment="staging",
            artifact_intent=intent,
        )
        self.artifact = ResolvedArtifact(
            immutable_image_reference=REFERENCE,
            repository="localhost:5000/team/app",
            tag="run-1",
            manifest_digest=DIGEST,
            platform_digest=DIGEST,
            media_type="application/vnd.oci.image.manifest.v1+json",
            architecture="amd64",
            operating_system="linux",
            image_size=1024,
            config_digest=CONFIG_DIGEST,
            source_revision=SOURCE_REVISION,
            build_plan_hash=self.plan.build_plan_hash,
            created_by_tool_version="0.2.0",
            registry_endpoint="localhost:5000",
            build_invocation_count=1,
        )

        self.store.write_json("sbom.spdx.json", _spdx())
        self.store.write_json("vulnerabilities.json", _trivy())
        self.store.write_json(
            "provenance.json",
            create_provenance_statement(
                self.artifact,
                builder_id="https://ci.example.invalid/builders/offline-test",
                tool_name="devops-stack-composer",
                generated_at="2026-08-30T12:00:00Z",
            ),
        )
        self.supply_chain = SupplyChainEvidence(
            artifact_digest=DIGEST,
            sbom_path="sbom.spdx.json",
            sbom_format="spdx-json",
            sbom_hash=sha256_file(self.store.path("sbom.spdx.json")),
            sbom_generator="syft-1.44.0",
            vulnerability_report_path="vulnerabilities.json",
            vulnerability_report_hash=sha256_file(
                self.store.path("vulnerabilities.json")
            ),
            scanner_name="trivy",
            scanner_version="0.69.0",
            scanner_database_metadata={"Version": 2},
            policy_result={"passed": True, "violatingFindings": []},
            provenance_path="provenance.json",
            provenance_hash=sha256_file(self.store.path("provenance.json")),
            provenance_type="https://slsa.dev/provenance/v1",
            attestation_subject=REFERENCE,
            verification_status=CHECKSUM_ONLY_VERIFICATION_STATUS,
            evidence_generation_time="2026-08-30T12:00:00Z",
        )

        manifest = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: app\n"
            "  namespace: sample-staging\n"
            "spec:\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app: sample\n"
            "  template:\n"
            "    metadata:\n"
            "      labels:\n"
            "        app: sample\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            f"          image: {REFERENCE}\n"
        )
        self.store.write_text("kubernetes/resolved.yaml", manifest)
        self.store.write_text("diagnostics/events.txt", "No warning events.\n")
        self.deployment = DeploymentEvidence(
            environment="staging",
            namespace="sample-staging",
            cluster_type="kind",
            cluster_identifier="devops-stack-run-1",
            manifest_hash=sha256_file(self.store.path("kubernetes/resolved.yaml")),
            deployed_image_reference=REFERENCE,
            expected_digest=DIGEST,
            actual_pod_image_id=f"containerd://{DIGEST}",
            rollout_status="PASSED",
            ready_replica_count=1,
            health_endpoint_result={"status": 200},
            readiness_endpoint_result={"status": 200},
            rollback_attempted=True,
            rollback_result="PASSED",
            final_revision="2",
            final_digest=DIGEST,
            diagnostics_paths=("diagnostics/events.txt",),
        )

        stages = tuple(
            StageResult(
                stage_id=stage.stage_id,
                description=stage.description,
                status=StageStatus.PASSED,
                start_time="2026-08-30T12:00:00Z",
                end_time="2026-08-30T12:00:01Z",
                evidence_paths=("artifact.json",)
                if stage.stage_id == "build-once"
                else (),
            )
            for stage in self.plan.stages
        )
        self.run = ExecutionRun(
            run_id=RUN_ID,
            project_path=".",
            config_hash="1" * 64,
            template_lock_hash="2" * 64,
            source_revision=SOURCE_REVISION,
            start_time="2026-08-30T12:00:00Z",
            end_time="2026-08-30T12:01:00Z",
            execution_profile="kind-e2e",
            stage_results=stages,
            final_status=StageStatus.PASSED,
            tool_versions={"docker": "29.1.5", "kind": "0.33.0"},
            artifact_record=self.artifact,
            supply_chain_evidence=self.supply_chain,
            deployment_evidence=self.deployment,
        )
        self.verification = validate_artifact_contract(
            self.artifact,
            self.supply_chain,
            self.deployment,
        )
        for relative, value in (
            ("execution-plan.json", self.plan.to_dict()),
            ("artifact.json", self.artifact.to_dict()),
            ("supply-chain.json", self.supply_chain.to_dict()),
            ("deployment.json", self.deployment.to_dict()),
            ("verification.json", self.verification.to_dict()),
            ("report.json", self.run.to_dict()),
        ):
            self.store.write_json(relative, value)
        self.reseal()

    def read_json(self, relative: str) -> dict[str, object]:
        return json.loads(self.store.path(relative).read_text(encoding="utf-8"))

    def rewrite_json(self, relative: str, value: object) -> None:
        self.store.write_json(relative, value, overwrite=True)

    def reseal(self) -> None:
        self.store.write_checksums(overwrite=self.store.path("SHA256SUMS").exists())


class ExecutionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.fixture = BundleFixture(self.project)

    def test_load_inspect_and_verify_complete_bundle_offline(self) -> None:
        bundle = load_execution_bundle(self.project, RUN_ID)
        inspection = bundle.inspect().to_dict()
        verification = bundle.verify().to_dict()

        self.assertEqual(inspection["repository"], "localhost:5000/team/app")
        self.assertEqual(inspection["digest"], DIGEST)
        self.assertEqual(inspection["platform"], "linux/amd64")
        self.assertEqual(inspection["sbom"], "sbom.spdx.json")
        self.assertEqual(verification["authoritativeDigest"], DIGEST)
        self.assertTrue(verification["storedVerificationMatches"])
        self.assertIn("kubernetes-subject", verification["checks"])
        self.assertEqual(
            inspect_execution_bundle(self.project, RUN_ID).digest,
            DIGEST,
        )
        self.assertTrue(verify_execution_bundle(self.project, RUN_ID).passed)

    def test_checksum_tampering_fails_before_record_parsing(self) -> None:
        artifact = self.fixture.read_json("artifact.json")
        artifact["unknown"] = True
        self.fixture.rewrite_json("artifact.json", artifact)

        with self.assertRaisesRegex(
            ExecutionBundleError, "BUNDLE_CHECKSUM_INVALID.*checksum mismatch"
        ):
            load_execution_bundle(self.project, RUN_ID)

    def test_rehashed_sbom_subject_mismatch_still_fails_semantically(self) -> None:
        self.fixture.rewrite_json(
            "sbom.spdx.json",
            _spdx("localhost:5000/team/app@sha256:" + "b" * 64),
        )
        supply = self.fixture.read_json("supply-chain.json")
        supply["sbomHash"] = sha256_file(self.fixture.store.path("sbom.spdx.json"))
        self.fixture.rewrite_json("supply-chain.json", supply)
        report = self.fixture.read_json("report.json")
        report["supplyChainEvidence"]["sbomHash"] = supply["sbomHash"]
        self.fixture.rewrite_json("report.json", report)
        self.fixture.reseal()

        with self.assertRaisesRegex(ExecutionBundleError, "SBOM_SUBJECT_MISMATCH"):
            verify_execution_bundle(self.project, RUN_ID)

    def test_unknown_duplicate_and_nonfinite_record_json_are_rejected(self) -> None:
        cases = ("unknown", "duplicate", "nonfinite")
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = BundleFixture(Path(directory))
                    artifact = fixture.read_json("artifact.json")
                    if case == "unknown":
                        artifact["surprise"] = True
                        fixture.rewrite_json("artifact.json", artifact)
                    else:
                        rendered = json.dumps(artifact, sort_keys=True)
                        if case == "duplicate":
                            rendered = rendered.replace(
                                '"tag": "run-1"',
                                '"tag": "run-1", "tag": "run-1"',
                            )
                        else:
                            rendered = rendered.replace('"imageSize": 1024', '"imageSize": NaN')
                        fixture.store.write_text(
                            "artifact.json", rendered + "\n", overwrite=True
                        )
                    fixture.reseal()
                    expected = (
                        "BUNDLE_RECORD_INVALID"
                        if case == "unknown"
                        else "BUNDLE_JSON_INVALID"
                    )
                    with self.assertRaisesRegex(ExecutionBundleError, expected):
                        load_execution_bundle(Path(directory), RUN_ID)

    def test_absolute_traversal_and_symlink_inputs_are_rejected(self) -> None:
        for unsafe in ("../escape", "/tmp/escape"):
            with self.subTest(run_id=unsafe):
                with self.assertRaisesRegex(ExecutionBundleError, "BUNDLE_PATH_UNSAFE"):
                    load_execution_bundle(self.project, unsafe)

        outside = self.project / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        artifact_path = self.fixture.store.path("artifact.json")
        artifact_path.unlink()
        artifact_path.symlink_to(outside)
        with self.assertRaisesRegex(ExecutionBundleError, "symbolic link"):
            load_execution_bundle(self.project, RUN_ID)

    def test_checksum_inventory_disagreement_is_rejected(self) -> None:
        self.fixture.store.write_text("untracked.txt", "unexpected\n")

        with self.assertRaisesRegex(ExecutionBundleError, "inventory mismatch"):
            load_execution_bundle(self.project, RUN_ID)

    def test_duplicate_record_and_stored_verification_disagreements_fail(self) -> None:
        report = self.fixture.read_json("report.json")
        report["artifact"]["tag"] = "different"
        self.fixture.rewrite_json("report.json", report)
        self.fixture.reseal()
        with self.assertRaisesRegex(ExecutionBundleError, "BUNDLE_RECORD_MISMATCH"):
            load_execution_bundle(self.project, RUN_ID)

        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory))
            verification = fixture.read_json("verification.json")
            verification["subjects"]["sbom"] = "sha256:" + "b" * 64
            fixture.rewrite_json("verification.json", verification)
            fixture.reseal()
            with self.assertRaisesRegex(
                ExecutionBundleError, "STORED_VERIFICATION_MISMATCH"
            ):
                verify_execution_bundle(Path(directory), RUN_ID)

    def test_public_file_loaders_are_strict_and_project_contained(self) -> None:
        artifact_path = f".devops-stack/runs/{RUN_ID}/artifact.json"
        artifact = load_resolved_artifact_file(self.project, artifact_path)
        self.assertEqual(artifact.manifest_digest, DIGEST)
        self.assertEqual(
            load_strict_json_file(
                self.project,
                ".devops-stack/runs/" + RUN_ID + "/artifact.json",
            )["manifestDigest"],
            DIGEST,
        )
        with self.assertRaisesRegex(ExecutionBundleError, "BUNDLE_PATH_UNSAFE"):
            load_strict_json_file(self.project, "/tmp/artifact.json")
        with self.assertRaisesRegex(ExecutionBundleError, "BUNDLE_JSON_INVALID"):
            parse_strict_json('{"a": 1, "a": 2}')

    def test_verification_never_invokes_process_or_network(self) -> None:
        with patch("subprocess.run") as run, patch(
            "socket.create_connection"
        ) as connect, patch("urllib.request.urlopen") as urlopen:
            result = verify_execution_bundle(self.project, RUN_ID)

        self.assertTrue(result.passed)
        run.assert_not_called()
        connect.assert_not_called()
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
