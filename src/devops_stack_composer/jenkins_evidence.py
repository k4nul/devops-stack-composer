"""Offline verification for the compact artifact files emitted by Jenkins."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from devops_stack_composer.evidence_validation import (
    ArtifactContractError,
    ArtifactVerification,
    validate_provenance_subject,
    validate_sbom_subject,
    validate_scan_subject,
)
from devops_stack_composer.execution_bundle import load_strict_json_file
from devops_stack_composer.oci import (
    digest_from_subject,
    parse_digest,
    parse_oci_reference,
    require_same_digest,
    validate_sha256_hex,
    validate_tag,
)
from devops_stack_composer.policies import VulnerabilityPolicy
from devops_stack_composer.supply_chain import parse_trivy_findings


_FIELDS = {
    "schemaVersion",
    "repository",
    "tag",
    "tagReference",
    "manifestDigest",
    "immutableImageReference",
    "sourceRevision",
    "buildPlanHash",
    "buildInvocationCount",
    "verificationStatus",
}


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            f"{name} must be a non-empty string without surrounding whitespace",
            evidence_path="artifact.json",
        )
    return value


def _validate_cyclonedx_subject(
    document: Mapping[str, Any],
    immutable_reference: str,
) -> None:
    if document.get("bomFormat") != "CycloneDX":
        raise ArtifactContractError(
            "SBOM_INVALID",
            "SBOM must be SPDX 2.3 or CycloneDX JSON",
            evidence_path="sbom.json",
        )
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise ArtifactContractError(
            "SBOM_INVALID",
            "CycloneDX component inventory is empty",
            evidence_path="sbom.json",
        )
    properties = document.get("properties")
    subjects = [
        item.get("value")
        for item in properties or ()
        if isinstance(item, Mapping)
        and item.get("name") == "devops-stack.io/subject"
    ]
    if subjects != [immutable_reference]:
        raise ArtifactContractError(
            "SBOM_SUBJECT_MISMATCH",
            "CycloneDX SBOM must contain one exact composer subject property",
            evidence_path="sbom.json",
        )


def verify_jenkins_artifact_files(
    project: Path,
    artifact_path: str,
    *,
    sbom_path: str | None = None,
    scan_path: str | None = None,
    provenance_path: str | None = None,
    vulnerability_policy: VulnerabilityPolicy | None = None,
) -> ArtifactVerification:
    """Strictly compare every supplied Jenkins evidence subject offline."""

    artifact = load_strict_json_file(project, artifact_path)
    if set(artifact) != _FIELDS:
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "artifact.json fields do not match jenkins-artifact-v1",
            evidence_path=artifact_path,
        )
    if artifact.get("schemaVersion") != "jenkins-artifact-v1":
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "artifact.json schemaVersion is unsupported",
            evidence_path=artifact_path,
        )
    repository = _text(artifact.get("repository"), "repository")
    tag = validate_tag(_text(artifact.get("tag"), "tag"))
    manifest_digest = str(
        parse_digest(_text(artifact.get("manifestDigest"), "manifestDigest"))
    )
    tagged = parse_oci_reference(
        _text(artifact.get("tagReference"), "tagReference")
    )
    immutable = parse_oci_reference(
        _text(artifact.get("immutableImageReference"), "immutableImageReference")
    )
    if (
        tagged.repository != repository
        or tagged.tag != tag
        or tagged.digest is not None
        or immutable.repository != repository
        or immutable.tag is not None
        or immutable.digest is None
        or str(immutable.digest) != manifest_digest
    ):
        raise ArtifactContractError(
            "ARTIFACT_DIGEST_MISMATCH",
            "Jenkins repository, tag, manifest digest, and immutable reference disagree",
            evidence_path=artifact_path,
        )
    source_revision = _text(artifact.get("sourceRevision"), "sourceRevision")
    if len(source_revision) != 40:
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "sourceRevision must be a full Git commit",
            evidence_path=artifact_path,
        )
    try:
        int(source_revision, 16)
    except ValueError as exc:
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "sourceRevision must be lowercase hexadecimal",
            evidence_path=artifact_path,
        ) from exc
    if source_revision != source_revision.lower():
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "sourceRevision must be lowercase hexadecimal",
            evidence_path=artifact_path,
        )
    validate_sha256_hex(_text(artifact.get("buildPlanHash"), "buildPlanHash"))
    if artifact.get("buildInvocationCount") != 1:
        raise ArtifactContractError(
            "BUILD_INVOKED_MORE_THAN_ONCE",
            "Jenkins artifact must record exactly one build invocation",
            evidence_path=artifact_path,
        )
    if artifact.get("verificationStatus") != "RESOLVED_UNVERIFIED":
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "stored Jenkins verification status is not the expected pre-verification state",
            evidence_path=artifact_path,
        )

    immutable_reference = immutable.immutable_reference
    subjects: dict[str, str] = {
        "jenkins-manifest": manifest_digest,
        "jenkins-artifact": immutable_reference,
    }
    if sbom_path is not None:
        sbom = load_strict_json_file(project, sbom_path)
        if sbom.get("spdxVersion") == "SPDX-2.3":
            validate_sbom_subject(sbom, immutable_reference=immutable_reference)
        else:
            _validate_cyclonedx_subject(sbom, immutable_reference)
        subjects["sbom"] = immutable_reference
    if scan_path is not None:
        scan = load_strict_json_file(project, scan_path)
        validate_scan_subject(scan, expected_digest=manifest_digest)
        if vulnerability_policy is not None:
            result = vulnerability_policy.evaluate(
                parse_trivy_findings(scan, immutable_reference)
            )
            if not result.passed:
                raise ArtifactContractError(
                    "VULNERABILITY_POLICY_FAILED",
                    "Jenkins scanner findings exceed the configured policy",
                    evidence_path=scan_path,
                )
        artifact_name = scan["ArtifactName"]
        assert isinstance(artifact_name, str)
        subjects["scan"] = str(digest_from_subject(artifact_name))
    if provenance_path is not None:
        provenance = load_strict_json_file(project, provenance_path)
        validate_provenance_subject(
            provenance,
            repository=repository,
            expected_digest=manifest_digest,
        )
        subjects["provenance"] = immutable_reference

    authoritative = require_same_digest(subjects)
    return ArtifactVerification(
        passed=True,
        authoritative_digest=str(authoritative),
        subjects=subjects,
    )
