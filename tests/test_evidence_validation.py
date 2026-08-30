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
        document = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Tool: syft-1.51.1"]},
            "packages": [{"name": "service"}],
            "annotations": [{"comment": f"devops-stack.io/subject={REFERENCE}"}],
        }
        validate_sbom_subject(document, immutable_reference=REFERENCE)
        tampered = copy.deepcopy(document)
        tampered["annotations"][0]["comment"] = "devops-stack.io/subject=registry.example/acme/service@sha256:" + "f" * 64
        with self.assertRaisesRegex(ArtifactContractError, "SBOM_SUBJECT_MISMATCH"):
            validate_sbom_subject(tampered, immutable_reference=REFERENCE)

    def test_validates_trivy_target(self) -> None:
        validate_scan_subject({"ArtifactName": REFERENCE, "Results": []}, expected_digest=DIGEST)
        with self.assertRaisesRegex(ArtifactContractError, "SCAN_SUBJECT_MISMATCH"):
            validate_scan_subject(
                {"ArtifactName": "registry.example/acme/service:mutable", "Results": []},
                expected_digest=DIGEST,
            )

    def test_validates_slsa_subject(self) -> None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "registry.example/acme/service", "digest": {"sha256": "a" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"buildDefinition": {}, "runDetails": {}},
        }
        validate_provenance_subject(
            statement,
            repository="registry.example/acme/service",
            expected_digest=DIGEST,
        )
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ArtifactContractError, "PROVENANCE_SUBJECT_MISMATCH"):
            validate_provenance_subject(
                statement,
                repository="registry.example/acme/service",
                expected_digest=DIGEST,
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
