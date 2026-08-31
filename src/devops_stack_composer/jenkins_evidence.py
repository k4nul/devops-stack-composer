"""Offline verification for the compact artifact files emitted by Jenkins."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from devops_stack_composer.evidence_validation import (
    ArtifactContractError,
    ArtifactVerification,
    validate_provenance_subject,
    validate_sbom_subject,
    validate_scan_subject,
)
from devops_stack_composer.execution_bundle import load_strict_json_file
from devops_stack_composer.filesystem import normalize_relative_path
from devops_stack_composer.oci import (
    digest_from_subject,
    parse_digest,
    parse_oci_reference,
    require_same_digest,
    validate_sha256_hex,
    validate_tag,
)
from devops_stack_composer.policies import VulnerabilityPolicy
from devops_stack_composer.supply_chain import (
    PROVENANCE_VERIFICATION_COMMAND,
    parse_trivy_findings,
)


_V1_FIELDS = {
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
_V2_FIELDS = _V1_FIELDS | {
    "sourceRepository",
    "workflowIdentity",
    "composerVersion",
    "dockerBuildxVersion",
}


def _text(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            f"{name} must be non-empty and contain no surrounding whitespace or controls",
            evidence_path="artifact.json",
        )
    return value


def _uri(value: Any, name: str) -> str:
    value = _text(value, name)
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.username is not None or parsed.password is not None:
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            f"{name} must be an absolute URI without userinfo",
            evidence_path="artifact.json",
        )
    return value


def _reproduction_command(
    artifact_path: str,
    *,
    sbom_path: str | None,
    scan_path: str | None,
    provenance_path: str,
) -> str:
    arguments = ["--artifact", normalize_relative_path(artifact_path)]
    if sbom_path is not None:
        arguments.extend(("--sbom", normalize_relative_path(sbom_path)))
    if scan_path is not None:
        arguments.extend(("--scan", normalize_relative_path(scan_path)))
    arguments.extend(("--provenance", normalize_relative_path(provenance_path)))
    return "devops-stack artifact verify " + " ".join(arguments)


def _validate_cyclonedx_subject(
    document: Mapping[str, Any],
    immutable_reference: str,
    *,
    source_repository: str | None = None,
    source_revision: str | None = None,
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
    expected_properties = {"devops-stack.io/subject": immutable_reference}
    if source_repository is not None and source_revision is not None:
        expected_properties.update(
            {
                "devops-stack.io/source-repository": source_repository,
                "devops-stack.io/source-revision": source_revision,
            }
        )
    recorded = {
        name: [
            item.get("value")
            for item in properties or ()
            if isinstance(item, Mapping) and item.get("name") == name
        ]
        for name in expected_properties
    }
    if any(recorded[name] != [expected] for name, expected in expected_properties.items()):
        raise ArtifactContractError(
            "SBOM_SUBJECT_MISMATCH",
            "CycloneDX SBOM must contain one exact subject and source identity property",
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
    schema_version = artifact.get("schemaVersion")
    expected_fields = (
        _V1_FIELDS
        if schema_version == "jenkins-artifact-v1"
        else _V2_FIELDS
        if schema_version == "jenkins-artifact-v2"
        else None
    )
    if expected_fields is None or set(artifact) != expected_fields:
        raise ArtifactContractError(
            "JENKINS_ARTIFACT_INVALID",
            "artifact.json fields do not match its Jenkins artifact schema version",
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
    build_plan_hash = validate_sha256_hex(
        _text(artifact.get("buildPlanHash"), "buildPlanHash")
    )
    source_repository = (
        _uri(artifact.get("sourceRepository"), "sourceRepository")
        if schema_version == "jenkins-artifact-v2"
        else None
    )
    workflow_identity = (
        _uri(artifact.get("workflowIdentity"), "workflowIdentity")
        if schema_version == "jenkins-artifact-v2"
        else None
    )
    composer_version = (
        _text(artifact.get("composerVersion"), "composerVersion")
        if schema_version == "jenkins-artifact-v2"
        else None
    )
    buildx_version = (
        _text(artifact.get("dockerBuildxVersion"), "dockerBuildxVersion")
        if schema_version == "jenkins-artifact-v2"
        else None
    )
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
            validate_sbom_subject(
                sbom,
                immutable_reference=immutable_reference,
                source_repository=source_repository,
                source_revision=(
                    source_revision if source_repository is not None else None
                ),
                require_source_metadata=source_repository is not None,
            )
        else:
            _validate_cyclonedx_subject(
                sbom,
                immutable_reference,
                source_repository=source_repository,
                source_revision=source_revision,
            )
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
        if not isinstance(artifact_name, str):
            raise ArtifactContractError(
                "SCAN_SUBJECT_MISMATCH",
                "Jenkins scan ArtifactName must be a string",
                evidence_path=scan_path,
            )
        subjects["scan"] = str(digest_from_subject(artifact_name))
    if provenance_path is not None:
        provenance = load_strict_json_file(project, provenance_path)
        if schema_version == "jenkins-artifact-v1":
            validate_provenance_subject(
                provenance,
                repository=repository,
                expected_digest=manifest_digest,
            )
        else:
            if (
                source_repository is None
                or workflow_identity is None
                or composer_version is None
                or buildx_version is None
            ):  # pragma: no cover - exact v2 fields were parsed above
                raise ArtifactContractError(
                    "JENKINS_ARTIFACT_INVALID",
                    "jenkins-artifact-v2 source and tool metadata is incomplete",
                    evidence_path=artifact_path,
                )
            reproduction_command = _reproduction_command(
                artifact_path,
                sbom_path=sbom_path,
                scan_path=scan_path,
                provenance_path=provenance_path,
            )
            validate_provenance_subject(
                provenance,
                repository=repository,
                expected_digest=manifest_digest,
                source_repository=source_repository,
                source_revision=source_revision,
                workflow_identity=workflow_identity,
                build_plan_hash=build_plan_hash,
                verification_command=PROVENANCE_VERIFICATION_COMMAND,
                reproduction_command=reproduction_command,
                generator_tool_name="devops-stack-composer",
                generator_tool_version=composer_version,
                buildx_version=buildx_version,
                require_verification_metadata=True,
            )
        subjects["provenance"] = immutable_reference

    authoritative = require_same_digest(subjects)
    return ArtifactVerification(
        passed=True,
        authoritative_digest=str(authoritative),
        subjects=subjects,
    )
