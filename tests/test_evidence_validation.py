from __future__ import annotations

import copy
import unittest

from devops_stack_composer.evidence_validation import (
    ArtifactContractError,
    parse_kubernetes_yaml,
    validate_artifact_contract,
    validate_kubernetes_documents,
    validate_provenance_subject,
    validate_sbom_subject,
    validate_scan_subject,
)
from devops_stack_composer.execution_models import ResolvedArtifact


DIGEST = "sha256:" + "a" * 64
REFERENCE = "registry.example/acme/service@" + DIGEST
SOURCE_REPOSITORY = "https://github.com/acme/service"
SOURCE_REVISION = "c" * 40
BUILD_PLAN_HASH = "d" * 64
WORKFLOW_IDENTITY = "https://ci.example/runs/123"
VERIFICATION_COMMAND = (
    "devops_stack_composer.supply_chain.validate_provenance_statement"
)
REPRODUCTION_COMMAND = "devops-stack artifact verify --project . --run run-1"


def spdx_document() -> dict:
    annotation = {
        "annotationDate": "2026-08-30T01:02:03Z",
        "annotationType": "OTHER",
        "annotator": "Tool: devops-stack-composer-0.2.0",
    }
    return {
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
            {**annotation, "comment": f"devops-stack.io/subject={REFERENCE}"},
            {
                **annotation,
                "comment": (
                    "devops-stack.io/source-repository=" + SOURCE_REPOSITORY
                ),
            },
            {
                **annotation,
                "comment": "devops-stack.io/source-revision=" + SOURCE_REVISION,
            },
        ],
    }


def provenance_statement() -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "registry.example/acme/service",
                "digest": {"sha256": "a" * 64},
            }
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
                    "verificationCommand": VERIFICATION_COMMAND,
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
                    "id": "https://ci.example/builders/jenkins",
                    "version": {
                        "devops-stack-composer": "0.2.0",
                        "docker-buildx": "0.31.1",
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
                "verificationCommand": VERIFICATION_COMMAND,
                "verificationResult": "PASSED",
                "reproductionCommand": REPRODUCTION_COMMAND,
            },
        },
    }


def artifact(**overrides):
    values = {
        "immutable_image_reference": REFERENCE,
        "repository": "registry.example/acme/service",
        "tag": "run-1",
        "manifest_digest": DIGEST,
        "platform_digest": DIGEST,
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "architecture": "amd64",
        "operating_system": "linux",
        "image_size": 100,
        "config_digest": "sha256:" + "b" * 64,
        "source_revision": "c" * 40,
        "build_plan_hash": "d" * 64,
        "created_by_tool_version": "0.2.0",
        "registry_endpoint": "registry.example",
        "build_invocation_count": 1,
    }
    values.update(overrides)
    return ResolvedArtifact(**values)


class EvidenceValidationTests(unittest.TestCase):
    def test_artifact_contract_requires_manifest_and_platform_identity(self) -> None:
        result = validate_artifact_contract(artifact())
        self.assertTrue(result.passed)
        self.assertEqual(result.authoritative_digest, DIGEST)

        with self.assertRaisesRegex(ArtifactContractError, "ARTIFACT_DIGEST_MISMATCH"):
            validate_artifact_contract(artifact(platform_digest="sha256:" + "e" * 64))

    def test_supply_chain_index_can_bind_top_level_evidence_without_child_identity(self) -> None:
        child_digest = "sha256:" + "e" * 64

        result = validate_artifact_contract(
            artifact(
                platform_digest=child_digest,
                media_type="application/vnd.oci.image.index.v1+json",
            ),
            require_platform_identity=False,
        )

        self.assertEqual(result.authoritative_digest, DIGEST)
        self.assertNotIn("platform-manifest", result.subjects)

    def test_non_index_cannot_claim_a_distinct_child_digest(self) -> None:
        with self.assertRaisesRegex(
            ArtifactContractError,
            "ARTIFACT_PLATFORM_DIGEST_MISMATCH",
        ):
            validate_artifact_contract(
                artifact(platform_digest="sha256:" + "e" * 64),
                require_platform_identity=False,
            )

    def test_artifact_contract_rejects_multiple_builds(self) -> None:
        with self.assertRaisesRegex(ArtifactContractError, "BUILD_INVOKED_MORE_THAN_ONCE"):
            validate_artifact_contract(artifact(build_invocation_count=2))

    def test_validates_composer_bound_nonempty_syft_spdx(self) -> None:
        document = spdx_document()
        validate_sbom_subject(
            document,
            immutable_reference=REFERENCE,
            source_repository=SOURCE_REPOSITORY,
            source_revision=SOURCE_REVISION,
        )
        tampered = copy.deepcopy(document)
        tampered["annotations"][0]["comment"] = (
            "devops-stack.io/subject=registry.example/acme/service@sha256:"
            + "f" * 64
        )
        with self.assertRaisesRegex(ArtifactContractError, "SBOM_SUBJECT_MISMATCH"):
            validate_sbom_subject(tampered, immutable_reference=REFERENCE)

    def test_sbom_requires_one_valid_source_repository_and_full_commit(self) -> None:
        cases = {}
        duplicate_repository = spdx_document()
        duplicate_repository["annotations"].append(
            copy.deepcopy(duplicate_repository["annotations"][1])
        )
        cases["duplicate repository"] = duplicate_repository

        missing_repository = spdx_document()
        del missing_repository["annotations"][1]
        cases["missing repository"] = missing_repository

        credentialed_repository = spdx_document()
        credentialed_repository["annotations"][1]["comment"] = (
            "devops-stack.io/source-repository=https://user:secret@example.com/acme/service"
        )
        cases["credentialed repository"] = credentialed_repository

        short_revision = spdx_document()
        short_revision["annotations"][2]["comment"] = (
            "devops-stack.io/source-revision=" + "c" * 39
        )
        cases["short revision"] = short_revision

        for name, tampered in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    ArtifactContractError,
                    "SBOM_(?:INVALID|SOURCE_MISMATCH)",
                ):
                    validate_sbom_subject(
                        tampered,
                        immutable_reference=REFERENCE,
                        require_source_metadata=True,
                    )

        with self.assertRaisesRegex(ArtifactContractError, "SBOM_SOURCE_MISMATCH"):
            validate_sbom_subject(
                spdx_document(),
                immutable_reference=REFERENCE,
                source_repository="https://github.com/acme/other",
                source_revision=SOURCE_REVISION,
            )

    def test_validates_trivy_target(self) -> None:
        validate_scan_subject({"ArtifactName": REFERENCE, "Results": []}, expected_digest=DIGEST)
        with self.assertRaisesRegex(ArtifactContractError, "SCAN_SUBJECT_MISMATCH"):
            validate_scan_subject(
                {"ArtifactName": "registry.example/acme/service:mutable", "Results": []},
                expected_digest=DIGEST,
            )

    def test_validates_slsa_subject(self) -> None:
        statement = provenance_statement()
        validate_provenance_subject(
            statement,
            repository="registry.example/acme/service",
            expected_digest=DIGEST,
            source_repository=SOURCE_REPOSITORY,
            source_revision=SOURCE_REVISION,
            workflow_identity=WORKFLOW_IDENTITY,
            build_plan_hash=BUILD_PLAN_HASH,
            verification_command=VERIFICATION_COMMAND,
            reproduction_command=REPRODUCTION_COMMAND,
        )
        tampered = copy.deepcopy(statement)
        tampered["subject"][0]["digest"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ArtifactContractError, "PROVENANCE_SUBJECT_MISMATCH"):
            validate_provenance_subject(
                tampered,
                repository="registry.example/acme/service",
                expected_digest=DIGEST,
            )

    def test_provenance_requires_source_workflow_plan_and_verification(self) -> None:
        external_path = ("predicate", "buildDefinition", "externalParameters")
        extension_path = ("predicate", "devopsStack_fileEvidence")
        cases = (
            (external_path, "sourceRepository", "not-a-uri"),
            (external_path, "sourceRevision", "c" * 39),
            (external_path, "workflowIdentity", "https://user:secret@ci.example/run"),
            (external_path, "buildPlanHash", "d" * 63),
            (external_path, "verificationCommand", ""),
            (external_path, "verificationResult", "FAILED"),
            (external_path, "reproductionCommand", ""),
            (extension_path, "mode", "registry-attached"),
            (extension_path, "verificationResult", "FAILED"),
            (extension_path, "verificationCommand", "different command"),
            (extension_path, "reproductionCommand", "different command"),
        )
        for path, field, value in cases:
            with self.subTest(path=path, field=field):
                tampered = provenance_statement()
                target = tampered
                for key in path:
                    target = target[key]
                target[field] = value
                with self.assertRaisesRegex(
                    ArtifactContractError,
                    "PROVENANCE_INVALID",
                ):
                    validate_provenance_subject(
                        tampered,
                        repository="registry.example/acme/service",
                        expected_digest=DIGEST,
                        require_verification_metadata=True,
                    )

        for field in (
            "sourceRepository",
            "sourceRevision",
            "workflowIdentity",
            "buildPlanHash",
            "verificationCommand",
            "verificationResult",
            "reproductionCommand",
        ):
            with self.subTest(field=field, missing=True):
                tampered = provenance_statement()
                del tampered["predicate"]["buildDefinition"][
                    "externalParameters"
                ][field]
                with self.assertRaisesRegex(
                    ArtifactContractError,
                    "PROVENANCE_INVALID",
                ):
                    validate_provenance_subject(
                        tampered,
                        repository="registry.example/acme/service",
                        expected_digest=DIGEST,
                        require_verification_metadata=True,
                    )

        for field, value in (
            ("verificationCommand", "other.validator"),
            ("reproductionCommand", "echo not-an-artifact-verification"),
        ):
            with self.subTest(field=field, matching_but_invalid=True):
                tampered = provenance_statement()
                external = tampered["predicate"]["buildDefinition"][
                    "externalParameters"
                ]
                file_evidence = tampered["predicate"][
                    "devopsStack_fileEvidence"
                ]
                external[field] = value
                file_evidence[field] = value
                with self.assertRaisesRegex(
                    ArtifactContractError,
                    "PROVENANCE_INVALID",
                ):
                    validate_provenance_subject(
                        tampered,
                        repository="registry.example/acme/service",
                        expected_digest=DIGEST,
                        require_verification_metadata=True,
                    )

    def test_provenance_expected_source_identity_is_tamper_evident(self) -> None:
        statement = provenance_statement()
        expected_values = {
            "source_repository": SOURCE_REPOSITORY,
            "source_revision": SOURCE_REVISION,
            "workflow_identity": WORKFLOW_IDENTITY,
            "build_plan_hash": BUILD_PLAN_HASH,
            "verification_command": VERIFICATION_COMMAND,
            "reproduction_command": REPRODUCTION_COMMAND,
        }
        for argument, other in (
            ("source_repository", "https://github.com/acme/other"),
            ("source_revision", "e" * 40),
            ("workflow_identity", "https://ci.example/runs/other"),
            ("build_plan_hash", "e" * 64),
            ("verification_command", "other.validator"),
            ("reproduction_command", "devops-stack artifact verify --run other"),
        ):
            with self.subTest(argument=argument):
                expectations = {**expected_values, argument: other}
                with self.assertRaisesRegex(
                    ArtifactContractError,
                    "PROVENANCE_INVALID",
                ):
                    validate_provenance_subject(
                        statement,
                        repository="registry.example/acme/service",
                        expected_digest=DIGEST,
                        **expectations,
                    )

    def test_kubernetes_requires_exact_immutable_image_in_all_containers(self) -> None:
        documents = (
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "service", "namespace": "staging"},
                "spec": {
                    "template": {
                        "spec": {
                            "initContainers": [{"name": "init", "image": REFERENCE}],
                            "containers": [{"name": "service", "image": REFERENCE}],
                        }
                    }
                },
            },
        )
        images = validate_kubernetes_documents(documents, immutable_reference=REFERENCE)
        self.assertEqual(images, (REFERENCE, REFERENCE))
        mutable = copy.deepcopy(documents)
        mutable[0]["spec"]["template"]["spec"]["containers"][0]["image"] = "registry.example/acme/service:latest"
        with self.assertRaisesRegex(ArtifactContractError, "MUTABLE_TAG_DEPLOYMENT"):
            validate_kubernetes_documents(mutable, immutable_reference=REFERENCE)

    def test_kubernetes_rejects_placeholder_and_duplicates(self) -> None:
        yaml_text = """apiVersion: v1
kind: Pod
metadata:
  name: service
  namespace: staging
spec:
  containers:
    - name: service
      image: __DEVOPS_STACK_IMAGE_DIGEST__
"""
        with self.assertRaisesRegex(ArtifactContractError, "UNRESOLVED_IMAGE_PLACEHOLDER"):
            validate_kubernetes_documents(
                parse_kubernetes_yaml(yaml_text), immutable_reference=REFERENCE
            )
        valid = yaml_text.replace("__DEVOPS_STACK_IMAGE_DIGEST__", REFERENCE)
        documents = parse_kubernetes_yaml(valid + "---\n" + valid)
        with self.assertRaisesRegex(ArtifactContractError, "KUBERNETES_DUPLICATE_RESOURCE"):
            validate_kubernetes_documents(documents, immutable_reference=REFERENCE)


if __name__ == "__main__":
    unittest.main()
