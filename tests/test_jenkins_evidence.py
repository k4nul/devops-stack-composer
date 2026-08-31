from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer import __version__
from devops_stack_composer.evidence_validation import ArtifactContractError
from devops_stack_composer.jenkins_evidence import verify_jenkins_artifact_files
from devops_stack_composer.policies import VulnerabilityPolicy
from devops_stack_composer.supply_chain import PROVENANCE_VERIFICATION_COMMAND


DIGEST = "sha256:" + "a" * 64
REPOSITORY = "registry.example/acme/service"
REFERENCE = f"{REPOSITORY}@{DIGEST}"
SOURCE_REPOSITORY = "https://github.com/acme/service"
SOURCE_REVISION = "b" * 40
BUILD_PLAN_HASH = "c" * 64
WORKFLOW_IDENTITY = "https://jenkins.example/job/acme-service/1/"
BUILDX_VERSION = "github.com/docker/buildx v0.31.1"
REPRODUCTION_COMMAND = (
    "devops-stack artifact verify --artifact artifact.json --sbom sbom.json "
    "--scan scan.json --provenance provenance.json"
)


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
                "schemaVersion": "jenkins-artifact-v2",
                "repository": REPOSITORY,
                "tag": "build-1",
                "tagReference": f"{REPOSITORY}:build-1",
                "manifestDigest": DIGEST,
                "immutableImageReference": REFERENCE,
                "sourceRepository": SOURCE_REPOSITORY,
                "sourceRevision": SOURCE_REVISION,
                "buildPlanHash": BUILD_PLAN_HASH,
                "workflowIdentity": WORKFLOW_IDENTITY,
                "composerVersion": __version__,
                "dockerBuildxVersion": BUILDX_VERSION,
                "buildInvocationCount": 1,
                "verificationStatus": "RESOLVED_UNVERIFIED",
            },
        )
        write_json(
            root,
            "sbom.json",
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "service",
                "documentNamespace": "https://sbom.example/acme/service",
                "creationInfo": {
                    "created": "2026-08-30T01:02:03Z",
                    "creators": ["Tool: syft-1.51.1"],
                },
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-service",
                        "name": "service",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                    }
                ],
                "annotations": [
                    {
                        "annotationDate": "2026-08-30T01:02:03Z",
                        "annotationType": "OTHER",
                        "annotator": f"Tool: devops-stack-composer-{__version__}",
                        "comment": f"devops-stack.io/subject={REFERENCE}",
                    },
                    {
                        "annotationDate": "2026-08-30T01:02:03Z",
                        "annotationType": "OTHER",
                        "annotator": f"Tool: devops-stack-composer-{__version__}",
                        "comment": (
                            "devops-stack.io/source-repository=" + SOURCE_REPOSITORY
                        ),
                    },
                    {
                        "annotationDate": "2026-08-30T01:02:03Z",
                        "annotationType": "OTHER",
                        "annotator": f"Tool: devops-stack-composer-{__version__}",
                        "comment": "devops-stack.io/source-revision=" + SOURCE_REVISION,
                    },
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
                "predicate": {
                    "buildDefinition": {
                        "buildType": (
                            "https://github.com/k4nul/devops-stack-composer/"
                            "build-types/build-once/v0.2"
                        ),
                        "externalParameters": {
                            "artifactReference": REFERENCE,
                            "sourceRepository": SOURCE_REPOSITORY,
                            "sourceRevision": SOURCE_REVISION,
                            "buildPlanHash": BUILD_PLAN_HASH,
                            "workflowIdentity": WORKFLOW_IDENTITY,
                            "verificationCommand": PROVENANCE_VERIFICATION_COMMAND,
                            "verificationResult": "PASSED",
                            "reproductionCommand": REPRODUCTION_COMMAND,
                        },
                        "internalParameters": {},
                        "resolvedDependencies": [
                            {
                                "name": "source",
                                "uri": SOURCE_REPOSITORY,
                                "digest": {"gitCommit": SOURCE_REVISION},
                            },
                            {
                                "name": "build-plan",
                                "digest": {"sha256": BUILD_PLAN_HASH},
                            },
                        ],
                    },
                    "runDetails": {
                        "builder": {
                            "id": "https://www.jenkins.io/",
                            "version": {
                                "devops-stack-composer": __version__,
                                "docker-buildx": BUILDX_VERSION,
                            },
                        },
                        "metadata": {},
                        "byproducts": [],
                    },
                    "devopsStack_fileEvidence": {
                        "mode": "file-only",
                        "generatedAt": "2026-08-30T01:02:03Z",
                        "signatureGenerated": False,
                        "signatureVerified": False,
                        "attachedToRegistry": False,
                        "cryptographicallyVerified": False,
                        "checksumIsSignature": False,
                        "verificationCommand": PROVENANCE_VERIFICATION_COMMAND,
                        "verificationResult": "PASSED",
                        "reproductionCommand": REPRODUCTION_COMMAND,
                    },
                },
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

    def test_rejects_source_provenance_and_tool_version_tampering(self) -> None:
        cases = (
            (
                "sbom.json",
                ("annotations", 1, "comment"),
                "devops-stack.io/source-repository=https://github.com/acme/other",
                "SBOM_SOURCE_MISMATCH",
            ),
            (
                "provenance.json",
                (
                    "predicate",
                    "buildDefinition",
                    "externalParameters",
                    "sourceRevision",
                ),
                "d" * 40,
                "PROVENANCE_INVALID",
            ),
            (
                "provenance.json",
                (
                    "predicate",
                    "runDetails",
                    "builder",
                    "version",
                    "docker-buildx",
                ),
                "github.com/docker/buildx v0.1.0",
                "PROVENANCE_INVALID",
            ),
            (
                "provenance.json",
                (
                    "predicate",
                    "buildDefinition",
                    "externalParameters",
                    "verificationResult",
                ),
                "FAILED",
                "PROVENANCE_INVALID",
            ),
        )
        for filename, path, value, code in cases:
            with self.subTest(filename=filename, path=path):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.records(root)
                    document = json.loads((root / filename).read_text(encoding="utf-8"))
                    target = document
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
                    write_json(root, filename, document)

                    with self.assertRaisesRegex(ArtifactContractError, code):
                        verify_jenkins_artifact_files(
                            root,
                            "artifact.json",
                            sbom_path="sbom.json",
                            scan_path="scan.json",
                            provenance_path="provenance.json",
                        )

    def test_preserves_v1_artifact_and_full_evidence_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.records(root)
            artifact = json.loads((root / "artifact.json").read_text(encoding="utf-8"))
            artifact["schemaVersion"] = "jenkins-artifact-v1"
            for field in (
                "sourceRepository",
                "workflowIdentity",
                "composerVersion",
                "dockerBuildxVersion",
            ):
                del artifact[field]
            write_json(root, "artifact.json", artifact)
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

            result = verify_jenkins_artifact_files(root, "artifact.json")
            self.assertTrue(result.passed)
            result = verify_jenkins_artifact_files(
                root,
                "artifact.json",
                sbom_path="sbom.json",
                scan_path="scan.json",
                provenance_path="provenance.json",
            )
            self.assertTrue(result.passed)
            self.assertEqual(
                set(result.subjects),
                {
                    "jenkins-manifest",
                    "jenkins-artifact",
                    "sbom",
                    "scan",
                    "provenance",
                },
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
