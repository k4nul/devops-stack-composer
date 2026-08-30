"""Pure validation that every execution record names one immutable OCI subject."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import yaml

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.execution_models import (
    DeploymentEvidence,
    ResolvedArtifact,
    SupplyChainEvidence,
)
from devops_stack_composer.oci import (
    OciReferenceError,
    digest_from_image_id,
    digest_from_subject,
    parse_oci_reference,
    require_same_digest,
)


class ArtifactContractError(DevOpsStackError):
    """A stable artifact-identity violation with an actionable evidence location."""

    def __init__(self, code: str, message: str, *, evidence_path: str | None = None):
        self.code = code
        self.evidence_path = evidence_path
        suffix = f"; evidence: {evidence_path}" if evidence_path else ""
        super().__init__(f"{code}: {message}{suffix}")


@dataclass(frozen=True)
class ArtifactVerification:
    passed: bool
    authoritative_digest: str
    subjects: Mapping[str, str]
    mutable_images: tuple[str, ...] = ()
    placeholder_images: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "authoritativeDigest": self.authoritative_digest,
            "subjects": dict(sorted(self.subjects.items())),
            "mutableImages": list(self.mutable_images),
            "placeholderImages": list(self.placeholder_images),
        }


def _same_digest(subjects: Mapping[str, str], *, code: str, evidence_path: str) -> str:
    try:
        return str(require_same_digest(subjects))
    except OciReferenceError as exc:
        raise ArtifactContractError(code, str(exc), evidence_path=evidence_path) from exc


def validate_sbom_subject(
    document: Mapping[str, Any],
    *,
    immutable_reference: str,
) -> None:
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ArtifactContractError(
            "SBOM_INVALID", "SBOM must be SPDX 2.3 JSON", evidence_path="sbom.spdx.json"
        )
    creation = document.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, Mapping) else None
    if not isinstance(creators, list) or not any(
        isinstance(value, str) and value.startswith("Tool: syft-") for value in creators
    ):
        raise ArtifactContractError(
            "SBOM_INVALID", "SBOM does not identify Syft as its generator", evidence_path="sbom.spdx.json"
        )
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ArtifactContractError(
            "SBOM_INVALID", "SBOM package inventory is empty", evidence_path="sbom.spdx.json"
        )
    annotations = document.get("annotations")
    expected = f"devops-stack.io/subject={immutable_reference}"
    comments = [
        item.get("comment")
        for item in annotations or ()
        if isinstance(item, Mapping)
    ]
    if comments.count(expected) != 1:
        raise ArtifactContractError(
            "SBOM_SUBJECT_MISMATCH",
            "SBOM must contain one exact composer subject annotation",
            evidence_path="sbom.spdx.json",
        )


def validate_scan_subject(
    document: Mapping[str, Any],
    *,
    expected_digest: str,
) -> None:
    artifact_name = document.get("ArtifactName")
    if not isinstance(artifact_name, str):
        raise ArtifactContractError(
            "SCAN_SUBJECT_MISMATCH",
            "scanner output has no ArtifactName",
            evidence_path="vulnerabilities.json",
        )
    try:
        received = str(digest_from_subject(artifact_name))
    except OciReferenceError as exc:
        raise ArtifactContractError(
            "SCAN_SUBJECT_MISMATCH",
            "scanner ArtifactName is not digest-pinned",
            evidence_path="vulnerabilities.json",
        ) from exc
    if received != expected_digest:
        raise ArtifactContractError(
            "SCAN_SUBJECT_MISMATCH",
            f"scanner targeted {received}, expected {expected_digest}",
            evidence_path="vulnerabilities.json",
        )
    results = document.get("Results")
    if not isinstance(results, list):
        raise ArtifactContractError(
            "SCAN_OUTPUT_INVALID",
            "scanner Results must be an array",
            evidence_path="vulnerabilities.json",
        )


def validate_provenance_subject(
    statement: Mapping[str, Any],
    *,
    repository: str,
    expected_digest: str,
) -> None:
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ArtifactContractError(
            "PROVENANCE_INVALID",
            "provenance must be an in-toto Statement v1",
            evidence_path="provenance.json",
        )
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ArtifactContractError(
            "PROVENANCE_INVALID",
            "provenance must use the SLSA v1 predicate",
            evidence_path="provenance.json",
        )
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ArtifactContractError(
            "PROVENANCE_SUBJECT_MISMATCH",
            "provenance must contain exactly one subject",
            evidence_path="provenance.json",
        )
    subject = subjects[0]
    subject_digest = subject.get("digest") if isinstance(subject, Mapping) else None
    sha256 = subject_digest.get("sha256") if isinstance(subject_digest, Mapping) else None
    name = subject.get("name") if isinstance(subject, Mapping) else None
    if name != repository or not isinstance(sha256, str):
        raise ArtifactContractError(
            "PROVENANCE_SUBJECT_MISMATCH",
            "provenance subject name or SHA-256 is missing",
            evidence_path="provenance.json",
        )
    received = f"sha256:{sha256}"
    if received != expected_digest:
        raise ArtifactContractError(
            "PROVENANCE_SUBJECT_MISMATCH",
            f"provenance subject is {received}, expected {expected_digest}",
            evidence_path="provenance.json",
        )
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        raise ArtifactContractError(
            "PROVENANCE_INVALID", "provenance predicate is missing", evidence_path="provenance.json"
        )


def _pod_specs(document: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    kind = document.get("kind")
    spec = document.get("spec")
    if not isinstance(spec, Mapping):
        return ()
    pod_spec: Any = None
    if kind == "Pod":
        pod_spec = spec
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        template = spec.get("template")
        pod_spec = template.get("spec") if isinstance(template, Mapping) else None
    elif kind == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, Mapping) else None
        template = job_spec.get("template") if isinstance(job_spec, Mapping) else None
        pod_spec = template.get("spec") if isinstance(template, Mapping) else None
    return (pod_spec,) if isinstance(pod_spec, Mapping) else ()


def validate_kubernetes_documents(
    documents: Iterable[Mapping[str, Any]],
    *,
    immutable_reference: str,
) -> tuple[str, ...]:
    expected_digest = str(digest_from_subject(immutable_reference))
    images: list[str] = []
    identities: set[tuple[str, str, str, str]] = set()
    for document in documents:
        if not isinstance(document, Mapping):
            raise ArtifactContractError(
                "KUBERNETES_MANIFEST_INVALID",
                "every YAML document must be an object",
                evidence_path="kubernetes/resolved.yaml",
            )
        metadata = document.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        identity = (
            str(document.get("apiVersion", "")),
            str(document.get("kind", "")),
            str(metadata.get("namespace", "")),
            str(metadata.get("name", "")),
        )
        if identity in identities:
            raise ArtifactContractError(
                "KUBERNETES_DUPLICATE_RESOURCE",
                f"duplicate resource {identity}",
                evidence_path="kubernetes/resolved.yaml",
            )
        identities.add(identity)
        for pod_spec in _pod_specs(document):
            for field in ("initContainers", "containers"):
                containers = pod_spec.get(field, [])
                if not isinstance(containers, list):
                    raise ArtifactContractError(
                        "KUBERNETES_MANIFEST_INVALID",
                        f"{field} must be an array",
                        evidence_path="kubernetes/resolved.yaml",
                    )
                for container in containers:
                    image = container.get("image") if isinstance(container, Mapping) else None
                    if not isinstance(image, str):
                        raise ArtifactContractError(
                            "ARTIFACT_DIGEST_MISSING",
                            "Kubernetes container has no image",
                            evidence_path="kubernetes/resolved.yaml",
                        )
                    images.append(image)
    if not images:
        raise ArtifactContractError(
            "ARTIFACT_DIGEST_MISSING",
            "Kubernetes manifests contain no workload image",
            evidence_path="kubernetes/resolved.yaml",
        )
    placeholders = tuple(sorted({image for image in images if "__" in image}))
    if placeholders:
        raise ArtifactContractError(
            "UNRESOLVED_IMAGE_PLACEHOLDER",
            "Kubernetes manifests contain unresolved image placeholders",
            evidence_path="kubernetes/resolved.yaml",
        )
    mutable: list[str] = []
    for image in images:
        try:
            reference = parse_oci_reference(image)
        except OciReferenceError as exc:
            raise ArtifactContractError(
                "KUBERNETES_IMAGE_INVALID", str(exc), evidence_path="kubernetes/resolved.yaml"
            ) from exc
        if reference.digest is None:
            mutable.append(image)
            continue
        if str(reference.digest) != expected_digest or reference.immutable_reference != immutable_reference:
            raise ArtifactContractError(
                "ARTIFACT_DIGEST_MISMATCH",
                f"Kubernetes image {image} does not equal {immutable_reference}",
                evidence_path="kubernetes/resolved.yaml",
            )
    if mutable:
        raise ArtifactContractError(
            "MUTABLE_TAG_DEPLOYMENT",
            "Kubernetes manifests contain mutable images: " + ", ".join(sorted(set(mutable))),
            evidence_path="kubernetes/resolved.yaml",
        )
    return tuple(images)


def parse_kubernetes_yaml(content: str) -> tuple[Mapping[str, Any], ...]:
    try:
        values = tuple(value for value in yaml.safe_load_all(content) if value is not None)
    except yaml.YAMLError as exc:
        raise ArtifactContractError(
            "KUBERNETES_MANIFEST_INVALID",
            "resolved Kubernetes YAML cannot be parsed",
            evidence_path="kubernetes/resolved.yaml",
        ) from exc
    if any(not isinstance(value, Mapping) for value in values):
        raise ArtifactContractError(
            "KUBERNETES_MANIFEST_INVALID",
            "resolved Kubernetes YAML documents must be objects",
            evidence_path="kubernetes/resolved.yaml",
        )
    return values


def validate_artifact_contract(
    artifact: ResolvedArtifact,
    supply_chain: SupplyChainEvidence | None = None,
    deployment: DeploymentEvidence | None = None,
) -> ArtifactVerification:
    if artifact.build_invocation_count != 1:
        raise ArtifactContractError(
            "BUILD_INVOKED_MORE_THAN_ONCE",
            f"artifact records {artifact.build_invocation_count} build invocations",
            evidence_path="artifact.json",
        )
    subjects: dict[str, str] = {
        "build-metadata": artifact.manifest_digest,
        "platform-manifest": artifact.platform_digest,
        "artifact-record": artifact.immutable_image_reference,
    }
    if supply_chain is not None:
        subjects.update(
            {
                "sbom": supply_chain.artifact_digest,
                "scan": supply_chain.artifact_digest,
                "provenance": supply_chain.attestation_subject,
            }
        )
    if deployment is not None:
        subjects.update(
            {
                "deployment-manifest": deployment.deployed_image_reference,
                "deployment-expected": deployment.expected_digest,
                "pod-image": str(digest_from_image_id(deployment.actual_pod_image_id)),
                "deployment-final": deployment.final_digest,
            }
        )
    authoritative = _same_digest(
        subjects,
        code="ARTIFACT_DIGEST_MISMATCH",
        evidence_path="verification.json",
    )
    return ArtifactVerification(True, authoritative, subjects)
