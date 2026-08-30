"""Digest-bound SBOM, vulnerability, and file-only provenance evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from devops_stack_composer.errors import (
    DevOpsStackError,
    GeneratedFileConflictError,
)
from devops_stack_composer.execution_models import (
    ResolvedArtifact,
    SupplyChainEvidence,
)
from devops_stack_composer.filesystem import (
    atomic_write,
    contained_path,
    normalize_relative_path,
    project_root,
    sha256_file,
)
from devops_stack_composer.oci import (
    OciReferenceError,
    parse_oci_reference,
    validate_sha256_hex,
)
from devops_stack_composer.policies import (
    VulnerabilityFinding,
    VulnerabilityPolicy,
)


SPDX_VERSION = "SPDX-2.3"
SPDX_FORMAT = "spdx-json"
SYFT_OUTPUT_FORMAT = "spdx-json@2.3"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/k4nul/devops-stack-composer/build-types/build-once/v0.2"
SUBJECT_ANNOTATION_PREFIX = "devops-stack.io/subject="
FILE_ONLY_EXTENSION = "devopsStack_fileEvidence"
CHECKSUM_ONLY_VERIFICATION_STATUS = (
    "CHECKSUM_ONLY_FILE_EVIDENCE:signature=false,attachment=false,crypto=false"
)

_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
_SYFT_CREATOR = re.compile(r"^Tool: syft-(\S+)$")

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
Clock = Callable[[], datetime]


class SupplyChainError(DevOpsStackError):
    """Raised when generated supply-chain evidence is invalid or mismatched."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _required_text(name: str, value: Any, *, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise SupplyChainError(code, f"{name} must be a non-empty string")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise SupplyChainError(
            code,
            f"{name} must not contain surrounding whitespace or control characters",
        )
    return value


def _required_uri(name: str, value: Any, *, code: str) -> str:
    value = _required_text(name, value, code=code)
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.username is not None or parsed.password is not None:
        raise SupplyChainError(code, f"{name} must be an absolute URI without userinfo")
    return value


def _parse_rfc3339(name: str, value: Any, *, code: str) -> datetime:
    value = _required_text(name, value, code=code)
    if not _RFC3339.fullmatch(value):
        raise SupplyChainError(code, f"{name} must be an RFC 3339 timestamp")
    try:
        # Python 3.10 accepts microseconds while Go tools commonly emit RFC 3339
        # nanoseconds.  Truncate only for validation; the original evidence value
        # remains unchanged.
        parseable = re.sub(r"(\.\d{6})\d+(?=Z|[+-])", r"\1", value)
        parsed = datetime.fromisoformat(
            parseable[:-1] + "+00:00" if parseable.endswith("Z") else parseable
        )
    except ValueError as exc:
        raise SupplyChainError(code, f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SupplyChainError(code, f"{name} must include a timezone")
    return parsed


def _normalize_timestamp(name: str, value: str | datetime, *, code: str) -> str:
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise SupplyChainError(code, f"{name} must include a timezone")
    else:
        parsed = _parse_rfc3339(name, value, code=code)
    utc = parsed.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds")
    return rendered.replace("+00:00", "Z")


def _immutable_reference(value: Any, *, code: str) -> Any:
    value = _required_text("immutable image reference", value, code=code)
    try:
        reference = parse_oci_reference(value)
    except OciReferenceError as exc:
        raise SupplyChainError(code, "image subject is not a valid OCI reference") from exc
    if (
        reference.digest is None
        or reference.tag is not None
        or value != reference.immutable_reference
    ):
        raise SupplyChainError(
            code,
            "image subject must use the exact repository@sha256:<digest> form",
        )
    return reference


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON property {key!r}")
        result[key] = value
    return result


def _json_object(payload: str | bytes, *, source: str, code: str) -> dict[str, Any]:
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SupplyChainError(code, f"{source} is not UTF-8 JSON") from exc
    if not isinstance(payload, str) or not payload:
        raise SupplyChainError(code, f"{source} did not contain JSON output")
    try:
        value = json.loads(
            payload,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SupplyChainError(code, f"{source} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise SupplyChainError(code, f"{source} must be a JSON object")
    return value


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        rendered = json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:  # pragma: no cover - validated inputs
        raise SupplyChainError(
            "EVIDENCE_SERIALIZATION_FAILED",
            "validated evidence could not be encoded as JSON",
        ) from exc
    return (rendered + "\n").encode("utf-8")


def _mapping(name: str, value: Any, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SupplyChainError(code, f"{name} must be a JSON object")
    return value


def _validate_spdx_annotation(value: Any) -> Mapping[str, Any]:
    code = "MALFORMED_SBOM"
    annotation = _mapping("SPDX annotation", value, code=code)
    required = {"annotationDate", "annotationType", "annotator", "comment"}
    if set(annotation) != required:
        raise SupplyChainError(
            code,
            "SPDX annotations must contain only annotationDate, annotationType, "
            "annotator, and comment",
        )
    _parse_rfc3339("SPDX annotationDate", annotation["annotationDate"], code=code)
    if annotation["annotationType"] not in {"OTHER", "REVIEW"}:
        raise SupplyChainError(code, "SPDX annotationType must be OTHER or REVIEW")
    annotator = _required_text("SPDX annotator", annotation["annotator"], code=code)
    if not annotator.startswith(("Person: ", "Organization: ", "Tool: ")):
        raise SupplyChainError(code, "SPDX annotator must identify a person, organization, or tool")
    _required_text("SPDX annotation comment", annotation["comment"], code=code)
    return annotation


def validate_spdx_document(
    document: Mapping[str, Any],
    immutable_image_reference: str,
    *,
    require_subject_annotation: bool = True,
) -> str:
    """Validate the required SPDX 2.3 structure and exact OCI subject binding.

    Returns the Syft creator string without the SPDX ``Tool:`` prefix.
    """

    code = "MALFORMED_SBOM"
    document = _mapping("SPDX document", document, code=code)
    expected = _immutable_reference(
        immutable_image_reference,
        code="SBOM_SUBJECT_MISMATCH",
    ).immutable_reference
    if document.get("spdxVersion") != SPDX_VERSION:
        raise SupplyChainError(code, f"SBOM spdxVersion must be {SPDX_VERSION}")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SupplyChainError(code, "SBOM document SPDXID must be SPDXRef-DOCUMENT")
    if document.get("dataLicense") != "CC0-1.0":
        raise SupplyChainError(code, "SBOM dataLicense must be CC0-1.0")
    _required_text("SBOM name", document.get("name"), code=code)
    _required_uri("SBOM documentNamespace", document.get("documentNamespace"), code=code)

    creation = _mapping("SBOM creationInfo", document.get("creationInfo"), code=code)
    _parse_rfc3339("SBOM creationInfo.created", creation.get("created"), code=code)
    creators = creation.get("creators")
    if not isinstance(creators, list) or not creators:
        raise SupplyChainError(code, "SBOM creationInfo.creators must be a non-empty array")
    syft_creators: list[str] = []
    for creator in creators:
        creator = _required_text("SBOM creator", creator, code=code)
        match = _SYFT_CREATOR.fullmatch(creator)
        if match:
            syft_creators.append(creator.removeprefix("Tool: "))
    if not syft_creators:
        raise SupplyChainError(
            code,
            "SBOM creationInfo.creators must identify a versioned Syft tool",
        )

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SupplyChainError(code, "SBOM packages must be a non-empty array")
    package_ids: set[str] = set()
    for index, package_value in enumerate(packages):
        package = _mapping(f"SBOM package {index}", package_value, code=code)
        package_id = _required_text(
            f"SBOM package {index} SPDXID", package.get("SPDXID"), code=code
        )
        if not package_id.startswith("SPDXRef-"):
            raise SupplyChainError(code, f"SBOM package {index} has an invalid SPDXID")
        if package_id in package_ids:
            raise SupplyChainError(code, f"SBOM package SPDXID {package_id!r} is duplicated")
        package_ids.add(package_id)
        _required_text(f"SBOM package {index} name", package.get("name"), code=code)
        _required_text(
            f"SBOM package {index} downloadLocation",
            package.get("downloadLocation"),
            code=code,
        )
        if not isinstance(package.get("filesAnalyzed"), bool):
            raise SupplyChainError(code, f"SBOM package {index} filesAnalyzed must be boolean")
        for field in ("licenseConcluded", "licenseDeclared", "copyrightText"):
            _required_text(
                f"SBOM package {index} {field}", package.get(field), code=code
            )

    annotations = document.get("annotations", [])
    if not isinstance(annotations, list):
        raise SupplyChainError(code, "SBOM annotations must be an array")
    validated_annotations = [
        _validate_spdx_annotation(annotation) for annotation in annotations
    ]
    expected_comment = SUBJECT_ANNOTATION_PREFIX + expected
    if require_subject_annotation and not any(
        annotation["annotationType"] == "OTHER"
        and annotation["comment"] == expected_comment
        for annotation in validated_annotations
    ):
        raise SupplyChainError(
            "SBOM_SUBJECT_MISMATCH",
            "SBOM has no valid top-level annotation for the exact OCI subject",
        )
    return syft_creators[0]


def _bind_spdx_subject(
    document: dict[str, Any],
    immutable_image_reference: str,
    *,
    generated_at: str,
    annotator: str,
) -> None:
    annotations = document.setdefault("annotations", [])
    if not isinstance(annotations, list):
        raise SupplyChainError("MALFORMED_SBOM", "SBOM annotations must be an array")
    annotations.append(
        {
            "annotationDate": generated_at,
            "annotationType": "OTHER",
            "annotator": annotator,
            "comment": SUBJECT_ANNOTATION_PREFIX + immutable_image_reference,
        }
    )


def parse_trivy_findings(
    report: Mapping[str, Any],
    immutable_image_reference: str,
) -> tuple[VulnerabilityFinding, ...]:
    """Validate a Trivy image JSON report and return every vulnerability finding."""

    code = "MALFORMED_VULNERABILITY_REPORT"
    report = _mapping("Trivy report", report, code=code)
    expected = _immutable_reference(
        immutable_image_reference,
        code="SCAN_SUBJECT_MISMATCH",
    )
    schema_version = report.get("SchemaVersion")
    if isinstance(schema_version, bool) or schema_version != 2:
        raise SupplyChainError(code, "Trivy SchemaVersion must be 2")
    if report.get("ArtifactType") != "container_image":
        raise SupplyChainError(code, "Trivy ArtifactType must be container_image")
    artifact_name = report.get("ArtifactName")
    try:
        scanned = _immutable_reference(artifact_name, code="SCAN_SUBJECT_MISMATCH")
    except SupplyChainError as exc:
        if exc.code == "SCAN_SUBJECT_MISMATCH":
            raise
        raise SupplyChainError(
            "SCAN_SUBJECT_MISMATCH", "Trivy ArtifactName is not digest-pinned"
        ) from exc
    if scanned.immutable_reference != expected.immutable_reference:
        raise SupplyChainError(
            "SCAN_SUBJECT_MISMATCH",
            "Trivy ArtifactName does not match the requested immutable OCI subject",
        )

    metadata = report.get("Metadata")
    if metadata is not None:
        _mapping("Trivy Metadata", metadata, code=code)
    trivy_metadata = report.get("Trivy")
    if trivy_metadata is not None:
        _mapping("Trivy generator metadata", trivy_metadata, code=code)

    results = report.get("Results")
    if not isinstance(results, list):
        raise SupplyChainError(code, "Trivy Results must be an array")
    findings: list[VulnerabilityFinding] = []
    for result_index, result_value in enumerate(results):
        result = _mapping(f"Trivy result {result_index}", result_value, code=code)
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise SupplyChainError(
                code,
                f"Trivy result {result_index} Vulnerabilities must be an array or null",
            )
        for finding_index, finding_value in enumerate(vulnerabilities):
            finding = _mapping(
                f"Trivy vulnerability {result_index}:{finding_index}",
                finding_value,
                code=code,
            )
            vulnerability_id = _required_text(
                "Trivy VulnerabilityID", finding.get("VulnerabilityID"), code=code
            )
            package = _required_text("Trivy PkgName", finding.get("PkgName"), code=code)
            installed_version = _required_text(
                "Trivy InstalledVersion", finding.get("InstalledVersion"), code=code
            )
            severity = _required_text("Trivy Severity", finding.get("Severity"), code=code)
            fixed_version = finding.get("FixedVersion")
            if fixed_version in (None, ""):
                fixed_version = None
            elif not isinstance(fixed_version, str):
                raise SupplyChainError(code, "Trivy FixedVersion must be a string or null")
            status = finding.get("Status")
            if status in (None, ""):
                status = "affected"
            elif not isinstance(status, str):
                raise SupplyChainError(code, "Trivy Status must be a string or null")
            try:
                findings.append(
                    VulnerabilityFinding(
                        vulnerability_id=vulnerability_id,
                        package=package,
                        installed_version=installed_version,
                        fixed_version=fixed_version,
                        severity=severity,
                        status=status,
                    )
                )
            except ValueError as exc:
                raise SupplyChainError(code, "Trivy vulnerability is malformed") from exc
    return tuple(findings)


def parse_trivy_database_metadata(
    value: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Parse ``trivy version --format json`` scanner and vulnerability DB data."""

    code = "MALFORMED_SCANNER_METADATA"
    value = _mapping("Trivy version output", value, code=code)
    scanner_version = _required_text("Trivy Version", value.get("Version"), code=code)
    database = _mapping("Trivy VulnerabilityDB", value.get("VulnerabilityDB"), code=code)
    database_version = database.get("Version")
    if (
        isinstance(database_version, bool)
        or not isinstance(database_version, int)
        or database_version < 1
    ):
        raise SupplyChainError(code, "Trivy VulnerabilityDB.Version must be a positive integer")
    for field in ("UpdatedAt", "DownloadedAt"):
        _parse_rfc3339(f"Trivy VulnerabilityDB.{field}", database.get(field), code=code)
    if database.get("NextUpdate") is not None:
        _parse_rfc3339(
            "Trivy VulnerabilityDB.NextUpdate", database.get("NextUpdate"), code=code
        )
    try:
        normalized = json.loads(json.dumps(dict(database), sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise SupplyChainError(code, "Trivy VulnerabilityDB must contain finite JSON data") from exc
    return scanner_version, normalized


def create_provenance_statement(
    artifact: ResolvedArtifact,
    *,
    builder_id: str,
    tool_name: str,
    generated_at: str,
    build_started_on: str | datetime | None = None,
    build_finished_on: str | datetime | None = None,
) -> dict[str, Any]:
    """Create an unsigned, unattached file-only in-toto SLSA v1 statement."""

    if not isinstance(artifact, ResolvedArtifact):
        raise SupplyChainError("MALFORMED_PROVENANCE", "artifact must be a ResolvedArtifact")
    reference = _immutable_reference(
        artifact.immutable_image_reference,
        code="PROVENANCE_SUBJECT_MISMATCH",
    )
    builder_id = _required_uri(
        "provenance builder id", builder_id, code="MALFORMED_PROVENANCE"
    )
    tool_name = _required_text(
        "provenance tool name", tool_name, code="MALFORMED_PROVENANCE"
    )
    if not _TOOL_NAME.fullmatch(tool_name):
        raise SupplyChainError(
            "MALFORMED_PROVENANCE", "provenance tool name uses invalid syntax"
        )
    generated_at = _normalize_timestamp(
        "provenance generation time",
        generated_at,
        code="MALFORMED_PROVENANCE",
    )
    metadata: dict[str, Any] = {}
    if build_started_on is not None:
        metadata["startedOn"] = _normalize_timestamp(
            "build start time", build_started_on, code="MALFORMED_PROVENANCE"
        )
    if build_finished_on is not None:
        metadata["finishedOn"] = _normalize_timestamp(
            "build finish time", build_finished_on, code="MALFORMED_PROVENANCE"
        )
    if "startedOn" in metadata and "finishedOn" in metadata:
        started = _parse_rfc3339(
            "build start time", metadata["startedOn"], code="MALFORMED_PROVENANCE"
        )
        finished = _parse_rfc3339(
            "build finish time", metadata["finishedOn"], code="MALFORMED_PROVENANCE"
        )
        if finished < started:
            raise SupplyChainError(
                "MALFORMED_PROVENANCE", "build finish time precedes build start time"
            )

    statement: dict[str, Any] = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": reference.repository,
                "digest": {"sha256": reference.digest.hex_value},
            }
        ],
        "predicateType": SLSA_PROVENANCE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "artifactReference": reference.immutable_reference,
                    "sourceRevision": artifact.source_revision,
                    "buildPlanHash": artifact.build_plan_hash,
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "name": "source",
                        "digest": {"gitCommit": artifact.source_revision},
                    },
                    {
                        "name": "build-plan",
                        "digest": {"sha256": artifact.build_plan_hash},
                    },
                ],
            },
            "runDetails": {
                "builder": {
                    "id": builder_id,
                    "version": {tool_name: artifact.created_by_tool_version},
                },
                "metadata": metadata,
                "byproducts": [],
            },
            FILE_ONLY_EXTENSION: {
                "mode": "file-only",
                "generatedAt": generated_at,
                "signatureGenerated": False,
                "signatureVerified": False,
                "attachedToRegistry": False,
                "cryptographicallyVerified": False,
                "checksumIsSignature": False,
            },
        },
    }
    validate_provenance_statement(
        statement,
        reference.immutable_reference,
        source_revision=artifact.source_revision,
        build_plan_hash=artifact.build_plan_hash,
    )
    return statement


def validate_provenance_statement(
    statement: Mapping[str, Any],
    immutable_image_reference: str,
    *,
    source_revision: str | None = None,
    build_plan_hash: str | None = None,
) -> None:
    """Structurally validate an in-toto SLSA v1 file-only provenance statement."""

    code = "MALFORMED_PROVENANCE"
    statement = _mapping("provenance statement", statement, code=code)
    expected = _immutable_reference(
        immutable_image_reference,
        code="PROVENANCE_SUBJECT_MISMATCH",
    )
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise SupplyChainError(code, "provenance _type must be the in-toto Statement v1 URI")
    if statement.get("predicateType") != SLSA_PROVENANCE_TYPE:
        raise SupplyChainError(code, "provenance predicateType must be SLSA provenance v1")
    if "signatures" in statement or "payload" in statement:
        raise SupplyChainError(code, "file-only provenance must be a bare unsigned statement")

    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise SupplyChainError(code, "provenance must contain exactly one subject")
    subject = _mapping("provenance subject", subjects[0], code=code)
    digest = _mapping("provenance subject digest", subject.get("digest"), code=code)
    if set(digest) != {"sha256"}:
        raise SupplyChainError(code, "provenance subject must contain only a sha256 digest")
    if subject.get("name") != expected.repository or digest.get("sha256") != expected.digest.hex_value:
        raise SupplyChainError(
            "PROVENANCE_SUBJECT_MISMATCH",
            "provenance subject does not match the exact OCI repository and digest",
        )

    predicate = _mapping("provenance predicate", statement.get("predicate"), code=code)
    build_definition = _mapping(
        "provenance buildDefinition", predicate.get("buildDefinition"), code=code
    )
    if build_definition.get("buildType") != BUILD_TYPE:
        raise SupplyChainError(code, "provenance buildType is not the build-once type")
    external = _mapping(
        "provenance externalParameters",
        build_definition.get("externalParameters"),
        code=code,
    )
    if external.get("artifactReference") != expected.immutable_reference:
        raise SupplyChainError(
            "PROVENANCE_SUBJECT_MISMATCH",
            "provenance externalParameters target a different OCI subject",
        )
    recorded_revision = _required_text(
        "provenance sourceRevision", external.get("sourceRevision"), code=code
    )
    if not _GIT_REVISION.fullmatch(recorded_revision):
        raise SupplyChainError(code, "provenance sourceRevision must be a full Git commit")
    recorded_plan_hash = _required_text(
        "provenance buildPlanHash", external.get("buildPlanHash"), code=code
    )
    try:
        validate_sha256_hex(recorded_plan_hash)
    except OciReferenceError as exc:
        raise SupplyChainError(code, "provenance buildPlanHash must be a SHA-256 value") from exc
    if source_revision is not None and recorded_revision != source_revision:
        raise SupplyChainError(code, "provenance sourceRevision does not match the artifact")
    if build_plan_hash is not None and recorded_plan_hash != build_plan_hash:
        raise SupplyChainError(code, "provenance buildPlanHash does not match the artifact")
    _mapping(
        "provenance internalParameters",
        build_definition.get("internalParameters"),
        code=code,
    )
    dependencies = build_definition.get("resolvedDependencies")
    if not isinstance(dependencies, list):
        raise SupplyChainError(code, "provenance resolvedDependencies must be an array")
    source_dependency = False
    plan_dependency = False
    for index, dependency_value in enumerate(dependencies):
        dependency = _mapping(
            f"provenance dependency {index}", dependency_value, code=code
        )
        dependency_digest = _mapping(
            f"provenance dependency {index} digest",
            dependency.get("digest"),
            code=code,
        )
        if dependency.get("name") == "source" and dependency_digest.get("gitCommit") == recorded_revision:
            source_dependency = True
        if dependency.get("name") == "build-plan" and dependency_digest.get("sha256") == recorded_plan_hash:
            plan_dependency = True
    if not source_dependency or not plan_dependency:
        raise SupplyChainError(
            code,
            "provenance dependencies must bind the source revision and build-plan hash",
        )

    run_details = _mapping("provenance runDetails", predicate.get("runDetails"), code=code)
    builder = _mapping("provenance builder", run_details.get("builder"), code=code)
    _required_uri("provenance builder id", builder.get("id"), code=code)
    versions = _mapping("provenance builder version", builder.get("version"), code=code)
    if not versions:
        raise SupplyChainError(code, "provenance builder version must not be empty")
    for name, version in versions.items():
        if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
            raise SupplyChainError(code, "provenance builder version has an invalid tool name")
        _required_text(f"provenance builder version {name}", version, code=code)
    metadata = _mapping("provenance metadata", run_details.get("metadata"), code=code)
    started = finished = None
    if metadata.get("startedOn") is not None:
        started = _parse_rfc3339(
            "provenance metadata.startedOn", metadata["startedOn"], code=code
        )
    if metadata.get("finishedOn") is not None:
        finished = _parse_rfc3339(
            "provenance metadata.finishedOn", metadata["finishedOn"], code=code
        )
    if started is not None and finished is not None and finished < started:
        raise SupplyChainError(code, "provenance finish time precedes start time")
    if not isinstance(run_details.get("byproducts"), list):
        raise SupplyChainError(code, "provenance byproducts must be an array")

    file_evidence = _mapping(
        "provenance file-only extension", predicate.get(FILE_ONLY_EXTENSION), code=code
    )
    if file_evidence.get("mode") != "file-only":
        raise SupplyChainError(code, "provenance evidence mode must be file-only")
    _parse_rfc3339(
        "provenance file evidence generatedAt", file_evidence.get("generatedAt"), code=code
    )
    false_fields = (
        "signatureGenerated",
        "signatureVerified",
        "attachedToRegistry",
        "cryptographicallyVerified",
        "checksumIsSignature",
    )
    if any(file_evidence.get(field) is not False for field in false_fields):
        raise SupplyChainError(
            code,
            "file-only provenance must explicitly mark signature, attachment, and "
            "cryptographic verification false",
        )


def verify_evidence_checksum(
    run_root: Path,
    relative_path: str,
    expected_sha256: str,
) -> str:
    """Verify one project-contained evidence file against a bare SHA-256 value."""

    try:
        validate_sha256_hex(expected_sha256)
    except OciReferenceError as exc:
        raise SupplyChainError(
            "EVIDENCE_CHECKSUM_INVALID", "expected evidence checksum is not SHA-256"
        ) from exc
    path = contained_path(run_root, relative_path)
    if not path.is_file():
        raise SupplyChainError(
            "EVIDENCE_FILE_MISSING", f"evidence file is missing: {relative_path}"
        )
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise SupplyChainError(
            "EVIDENCE_CHECKSUM_MISMATCH",
            f"evidence checksum does not match: {relative_path}",
        )
    return actual


def _verified_json_file(
    run_root: Path,
    relative_path: str,
    expected_sha256: str,
    *,
    source: str,
    code: str,
) -> dict[str, Any]:
    verify_evidence_checksum(run_root, relative_path, expected_sha256)
    path = contained_path(run_root, relative_path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SupplyChainError("EVIDENCE_FILE_MISSING", f"could not read {relative_path}") from exc
    return _json_object(payload, source=source, code=code)


def verify_sbom_evidence(
    run_root: Path,
    relative_path: str,
    expected_sha256: str,
    immutable_image_reference: str,
) -> str:
    document = _verified_json_file(
        run_root,
        relative_path,
        expected_sha256,
        source="stored SPDX SBOM",
        code="MALFORMED_SBOM",
    )
    return validate_spdx_document(document, immutable_image_reference)


def verify_vulnerability_evidence(
    run_root: Path,
    relative_path: str,
    expected_sha256: str,
    immutable_image_reference: str,
) -> tuple[VulnerabilityFinding, ...]:
    report = _verified_json_file(
        run_root,
        relative_path,
        expected_sha256,
        source="stored Trivy report",
        code="MALFORMED_VULNERABILITY_REPORT",
    )
    return parse_trivy_findings(report, immutable_image_reference)


def verify_provenance_evidence(
    run_root: Path,
    relative_path: str,
    expected_sha256: str,
    immutable_image_reference: str,
    *,
    source_revision: str | None = None,
    build_plan_hash: str | None = None,
) -> None:
    statement = _verified_json_file(
        run_root,
        relative_path,
        expected_sha256,
        source="stored provenance",
        code="MALFORMED_PROVENANCE",
    )
    validate_provenance_statement(
        statement,
        immutable_image_reference,
        source_revision=source_revision,
        build_plan_hash=build_plan_hash,
    )


def _write_json_evidence(
    run_root: Path,
    relative_path: str,
    value: Mapping[str, Any],
) -> str:
    payload = _json_bytes(value)
    expected = hashlib.sha256(payload).hexdigest()
    path = atomic_write(run_root, relative_path, payload)
    actual = sha256_file(path)
    if actual != expected:  # pragma: no cover - filesystem integrity failure
        raise SupplyChainError(
            "EVIDENCE_CHECKSUM_MISMATCH",
            f"persisted evidence checksum changed while writing {relative_path}",
        )
    return actual


class SupplyChainGenerator:
    """Generate and validate evidence without rebuilding the resolved artifact."""

    def __init__(
        self,
        command_runner: CommandRunner | None = None,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._command_runner = command_runner or subprocess.run
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _run_json(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        source: str,
        code: str,
        environment: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        options: dict[str, Any] = {
            "cwd": cwd,
            "capture_output": True,
            "text": True,
            "check": False,
            "shell": False,
            "timeout": timeout_seconds,
        }
        if environment is not None:
            options["env"] = dict(environment)
        try:
            completed = self._command_runner(
                list(command),
                **options,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SupplyChainError(
                "SUPPLY_CHAIN_TOOL_FAILED",
                f"{command[0]} could not be executed ({type(exc).__name__})",
            ) from exc
        returncode = getattr(completed, "returncode", None)
        if isinstance(returncode, bool) or not isinstance(returncode, int):
            raise SupplyChainError(
                "SUPPLY_CHAIN_TOOL_FAILED", f"{command[0]} returned an invalid status"
            )
        if returncode != 0:
            raise SupplyChainError(
                "SUPPLY_CHAIN_TOOL_FAILED",
                f"{command[0]} exited with status {returncode}",
            )
        return _json_object(
            getattr(completed, "stdout", None),
            source=source,
            code=code,
        )

    def generate(
        self,
        *,
        run_root: Path,
        artifact: ResolvedArtifact,
        policy: VulnerabilityPolicy,
        builder_id: str,
        generated_at: datetime | None = None,
        tool_name: str = "devops-stack-composer",
        build_started_on: str | datetime | None = None,
        build_finished_on: str | datetime | None = None,
        sbom_path: str = "sbom.spdx.json",
        vulnerability_report_path: str = "vulnerabilities.json",
        provenance_path: str = "provenance.json",
        timeout_seconds: int = 900,
        insecure_local_registry: bool = False,
    ) -> SupplyChainEvidence:
        """Generate all evidence for one immutable ``repository@sha256`` subject."""

        if not isinstance(artifact, ResolvedArtifact):
            raise ValueError("artifact must be a ResolvedArtifact")
        if not isinstance(policy, VulnerabilityPolicy):
            raise ValueError("policy must be a VulnerabilityPolicy")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive integer")
        if not isinstance(insecure_local_registry, bool):
            raise ValueError("insecure_local_registry must be boolean")
        if insecure_local_registry and artifact.registry_endpoint.split(":", 1)[0] not in {
            "127.0.0.1",
            "localhost",
        }:
            raise SupplyChainError(
                "INSECURE_REGISTRY_FORBIDDEN",
                "plain HTTP scanning is restricted to a loopback registry",
            )
        root = project_root(Path(run_root))
        reference = _immutable_reference(
            artifact.immutable_image_reference,
            code="ARTIFACT_DIGEST_INVALID",
        )
        paths = (
            normalize_relative_path(sbom_path),
            normalize_relative_path(vulnerability_report_path),
            normalize_relative_path(provenance_path),
        )
        if len(set(paths)) != len(paths):
            raise ValueError("supply-chain evidence paths must be distinct")
        sbom_path, vulnerability_report_path, provenance_path = paths
        for relative_path in paths:
            target = contained_path(root, relative_path)
            if target.exists():
                raise GeneratedFileConflictError(
                    f"refusing to overwrite existing file: {relative_path}"
                )

        current_time = generated_at if generated_at is not None else self._clock()
        if not isinstance(current_time, datetime):
            raise ValueError("generated_at and the injected clock must return datetime")
        generation_time = _normalize_timestamp(
            "evidence generation time",
            current_time,
            code="EVIDENCE_TIME_INVALID",
        )
        annotator = f"Tool: {tool_name}-{artifact.created_by_tool_version}"

        immutable_reference = reference.immutable_reference
        sbom_document = self._run_json(
            ("syft", immutable_reference, "-o", SYFT_OUTPUT_FORMAT),
            cwd=root,
            timeout_seconds=timeout_seconds,
            source="Syft SPDX output",
            code="MALFORMED_SBOM",
            environment=(
                {"SYFT_REGISTRY_INSECURE_USE_HTTP": "true"}
                if insecure_local_registry
                else None
            ),
        )
        sbom_generator = validate_spdx_document(
            sbom_document,
            immutable_reference,
            require_subject_annotation=False,
        )
        _bind_spdx_subject(
            sbom_document,
            immutable_reference,
            generated_at=generation_time,
            annotator=annotator,
        )
        validate_spdx_document(sbom_document, immutable_reference)

        vulnerability_report = self._run_json(
            (
                "trivy",
                "image",
                *(("--insecure",) if insecure_local_registry else ()),
                "--format",
                "json",
                immutable_reference,
            ),
            cwd=root,
            timeout_seconds=timeout_seconds,
            source="Trivy image scan output",
            code="MALFORMED_VULNERABILITY_REPORT",
        )
        findings = parse_trivy_findings(vulnerability_report, immutable_reference)
        version_output = self._run_json(
            ("trivy", "version", "--format", "json"),
            cwd=root,
            timeout_seconds=timeout_seconds,
            source="Trivy version output",
            code="MALFORMED_SCANNER_METADATA",
        )
        scanner_version, database_metadata = parse_trivy_database_metadata(version_output)
        report_generator = vulnerability_report.get("Trivy")
        if isinstance(report_generator, Mapping) and report_generator.get("Version") is not None:
            if report_generator.get("Version") != scanner_version:
                raise SupplyChainError(
                    "SCANNER_VERSION_MISMATCH",
                    "Trivy scan and version metadata report different scanner versions",
                )
        policy_result = policy.evaluate(
            findings,
            on_date=_parse_rfc3339(
                "evidence generation time",
                generation_time,
                code="EVIDENCE_TIME_INVALID",
            ).date(),
        )

        provenance = create_provenance_statement(
            artifact,
            builder_id=builder_id,
            tool_name=tool_name,
            generated_at=generation_time,
            build_started_on=build_started_on,
            build_finished_on=build_finished_on,
        )

        # Nothing is persisted until every tool result and derived statement is valid.
        sbom_hash = _write_json_evidence(root, sbom_path, sbom_document)
        vulnerability_hash = _write_json_evidence(
            root, vulnerability_report_path, vulnerability_report
        )
        provenance_hash = _write_json_evidence(root, provenance_path, provenance)

        verify_sbom_evidence(root, sbom_path, sbom_hash, immutable_reference)
        verify_vulnerability_evidence(
            root,
            vulnerability_report_path,
            vulnerability_hash,
            immutable_reference,
        )
        verify_provenance_evidence(
            root,
            provenance_path,
            provenance_hash,
            immutable_reference,
            source_revision=artifact.source_revision,
            build_plan_hash=artifact.build_plan_hash,
        )

        return SupplyChainEvidence(
            artifact_digest=str(reference.digest),
            sbom_path=sbom_path,
            sbom_format=SPDX_FORMAT,
            sbom_hash=sbom_hash,
            sbom_generator=sbom_generator,
            vulnerability_report_path=vulnerability_report_path,
            vulnerability_report_hash=vulnerability_hash,
            scanner_name="trivy",
            scanner_version=scanner_version,
            scanner_database_metadata=database_metadata,
            policy_result=policy_result.to_dict(),
            provenance_path=provenance_path,
            provenance_hash=provenance_hash,
            provenance_type=SLSA_PROVENANCE_TYPE,
            attestation_subject=immutable_reference,
            verification_status=CHECKSUM_ONLY_VERIFICATION_STATUS,
            evidence_generation_time=generation_time,
        )
