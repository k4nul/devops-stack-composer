from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.evidence_validation import ArtifactContractError
from devops_stack_composer.jenkins_evidence import verify_jenkins_artifact_files
from devops_stack_composer.policies import VulnerabilityPolicy


DIGEST = "sha256:" + "a" * 64
REPOSITORY = "registry.example/acme/service"
REFERENCE = f"{REPOSITORY}@{DIGEST}"


def write_json(root: Path, name: str, value) -> None:
    (root / name).write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class JenkinsEvidenceTests(unittest.TestCase):
    def records(self, root: Path) -> None:
        write_json(
            root,
            "artifact.json",
            {
                "schemaVersion": "jenkins-artifact-v1",
                "repository": REPOSITORY,
                "tag": "build-1",
                "tagReference": f"{REPOSITORY}:build-1",
                "manifestDigest": DIGEST,
                "immutableImageReference": REFERENCE,
                "sourceRevision": "b" * 40,
                "buildPlanHash": "c" * 64,
                "buildInvocationCount": 1,
                "verificationStatus": "RESOLVED_UNVERIFIED",
            },
        )
        write_json(
            root,
            "sbom.json",
            {
                "spdxVersion": "SPDX-2.3",
                "creationInfo": {"creators": ["Tool: syft-1.51.1"]},
                "packages": [{"name": "service"}],
                "annotations": [
                    {"comment": f"devops-stack.io/subject={REFERENCE}"}
                ],
            },
        )
        write_json(
            root,
            "scan.json",
            {"ArtifactName": REFERENCE, "Results": []},
        )
        write_json(
            root,
            "provenance.json",
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": REPOSITORY, "digest": {"sha256": "a" * 64}}
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"buildDefinition": {}, "runDetails": {}},
            },
        )

    def test_verifies_every_compact_jenkins_subject_without_registry_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)

            result = verify_jenkins_artifact_files(
                root,
                "artifact.json",
                sbom_path="sbom.json",
                scan_path="scan.json",
                provenance_path="provenance.json",
            )

        self.assertTrue(result.passed)
        self.assertEqual(result.authoritative_digest, DIGEST)
        self.assertEqual(
            set(result.subjects),
            {"jenkins-manifest", "jenkins-artifact", "sbom", "scan", "provenance"},
        )

    def test_rejects_tampered_subject_and_a_second_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)
            artifact = json.loads((root / "artifact.json").read_text(encoding="utf-8"))
            artifact["buildInvocationCount"] = 2
            write_json(root, "artifact.json", artifact)
            with self.assertRaisesRegex(
                ArtifactContractError,
                "BUILD_INVOKED_MORE_THAN_ONCE",
            ):
                verify_jenkins_artifact_files(root, "artifact.json")

            self.records(root)
            scan = {"ArtifactName": f"{REPOSITORY}@sha256:" + "f" * 64, "Results": []}
            write_json(root, "scan.json", scan)
            with self.assertRaisesRegex(
                ArtifactContractError,
                "SCAN_SUBJECT_MISMATCH",
            ):
                verify_jenkins_artifact_files(
                    root,
                    "artifact.json",
                    scan_path="scan.json",
                )

    def test_applies_configured_policy_to_complete_trivy_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)
            write_json(
                root,
                "scan.json",
                {
                    "SchemaVersion": 2,
                    "ArtifactName": REFERENCE,
                    "ArtifactType": "container_image",
                    "Results": [
                        {
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-1",
                                    "PkgName": "sample",
                                    "InstalledVersion": "1.0",
                                    "FixedVersion": "2.0",
                                    "Severity": "CRITICAL",
                                    "Status": "affected",
                                }
                            ]
                        }
                    ],
                },
            )

            with self.assertRaisesRegex(
                ArtifactContractError,
                "VULNERABILITY_POLICY_FAILED",
            ):
                verify_jenkins_artifact_files(
                    root,
                    "artifact.json",
                    scan_path="scan.json",
                    vulnerability_policy=VulnerabilityPolicy(ignore_unfixed=False),
                )


if __name__ == "__main__":
    unittest.main()
