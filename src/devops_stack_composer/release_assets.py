"""Deterministic assembly and offline verification of release asset sets."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit
import zipfile

from jsonschema import Draft7Validator, FormatChecker, RefResolver
from jsonschema.exceptions import SchemaError
import yaml

from devops_stack_composer.errors import DevOpsStackError, UnsafePathError
from devops_stack_composer.execution_bundle import (
    ExecutionBundleError,
    load_execution_bundle,
    parse_strict_json,
)
from devops_stack_composer.filesystem import (
    atomic_write,
    contained_path,
    normalize_relative_path,
    project_root,
)


_DISTRIBUTION = "devops-stack-composer"
_SCHEMA_VERSION = "release-assets-v1"
_VERIFICATION_SCHEMA_VERSION = "release-verification-v1"
_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
_TOP_LEVEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MAX_EVIDENCE_FILES = 10_000
_MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
_MAX_RELEASE_FILE_BYTES = 256 * 1024 * 1024
_MAX_RELEASE_JSON_BYTES = 4 * 1024 * 1024
_MAX_PACKAGE_FILES = 10_000
_MAX_PACKAGE_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_PACKAGE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024

_STATIC_ASSETS = {
    "configuration-schema": "devops-stack.schema.json",
    "report-schema": "execution-report.schema.json",
    "execution-evidence-schema": "execution-evidence.schema.json",
    "example-config": "devops-stack.example.yaml",
    "example-evidence": "example-evidence.tar.gz",
    "package-sbom": "package.spdx.json",
    "provenance-verification": "provenance-verification.json",
}
_PAYLOAD_ROLES = frozenset({"wheel", "sdist", *_STATIC_ASSETS})
_SENSITIVE_PATH_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        "kubeconfig",
        "docker-config.json",
        "credentials",
        "credentials.json",
    }
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)(?:password|token|secret|authorization|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*(?!\"?(?:<redacted>|\[redacted\]|REDACTED)\"?)([^\s,}\]]+)"
)


class ReleaseAssetError(DevOpsStackError):
    """Raised when a release asset set is unsafe, incomplete, or contradictory."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ReleaseAssemblyRequest:
    project: Path
    output_directory: str
    version: str
    source_commit: str
    wheel_path: str
    sdist_path: str
    configuration_schema_path: str
    report_schema_path: str
    execution_evidence_schema_path: str
    example_config_path: str
    package_sbom_path: str
    provenance_verification_path: str
    evidence_run_id: str
    evidence_work_directory: str = ".devops-stack/runs"

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_commit(self.source_commit)
        normalize_relative_path(self.output_directory)
        for value in (
            self.wheel_path,
            self.sdist_path,
            self.configuration_schema_path,
            self.report_schema_path,
            self.execution_evidence_schema_path,
            self.example_config_path,
            self.package_sbom_path,
            self.provenance_verification_path,
            self.evidence_work_directory,
        ):
            normalize_relative_path(value)


@dataclass(frozen=True)
class ReleaseMaterialRequest:
    project: Path
    output_directory: str
    version: str
    source_commit: str
    source_repository: str
    created_at: str
    wheel_path: str
    sdist_path: str

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_commit(self.source_commit)
        normalize_relative_path(self.output_directory)
        normalize_relative_path(self.wheel_path)
        normalize_relative_path(self.sdist_path)
        object.__setattr__(self, "created_at", _normalized_timestamp(self.created_at))
        _validate_repository_url(self.source_repository)


@dataclass(frozen=True)
class ReleaseMaterialResult:
    package_sbom: Path
    provenance_verification: Path
    wheel_sha256: str
    sdist_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "packageSbom": str(self.package_sbom),
            "provenanceVerification": str(self.provenance_verification),
            "wheelSha256": self.wheel_sha256,
            "sdistSha256": self.sdist_sha256,
        }


@dataclass(frozen=True)
class ReleaseAssetRecord:
    name: str
    role: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        _validate_top_level_name(self.name)
        if self.role not in _PAYLOAD_ROLES:
            raise ValueError(f"unsupported release asset role: {self.role}")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("release asset SHA-256 must be lowercase hexadecimal")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or self.size < 0
        ):
            raise ValueError("release asset size must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class ReleaseManifest:
    version: str
    source_commit: str
    assets: tuple[ReleaseAssetRecord, ...]
    evidence_run_id: str
    evidence_digest: str
    provenance_mode: str
    cryptographically_verified: bool

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_commit(self.source_commit)
        values = tuple(self.assets)
        if any(not isinstance(item, ReleaseAssetRecord) for item in values):
            raise ValueError("manifest assets must be ReleaseAssetRecord values")
        if len({item.name for item in values}) != len(values):
            raise ValueError("manifest asset names must be unique")
        roles = {item.role for item in values}
        if roles != _PAYLOAD_ROLES or len(values) != len(_PAYLOAD_ROLES):
            raise ValueError(
                "manifest must contain exactly one asset for every required role"
            )
        object.__setattr__(
            self, "assets", tuple(sorted(values, key=lambda item: item.name))
        )
        if not isinstance(self.evidence_run_id, str) or not self.evidence_run_id:
            raise ValueError("evidence run ID must be non-empty")
        _validate_oci_digest(self.evidence_digest)
        if self.provenance_mode not in {"file-provenance", "keyless-attestation"}:
            raise ValueError("unsupported provenance verification mode")
        if not isinstance(self.cryptographically_verified, bool):
            raise ValueError("cryptographicallyVerified must be boolean")
        if (
            self.provenance_mode == "file-provenance"
            and self.cryptographically_verified
        ):
            raise ValueError("file provenance cannot claim cryptographic verification")
        if (
            self.provenance_mode == "keyless-attestation"
            and not self.cryptographically_verified
        ):
            raise ValueError(
                "keyless attestation must record cryptographic verification"
            )

    @property
    def tag(self) -> str:
        return f"v{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": _SCHEMA_VERSION,
            "distribution": _DISTRIBUTION,
            "version": self.version,
            "tag": self.tag,
            "sourceCommit": self.source_commit,
            "assets": [item.to_dict() for item in self.assets],
            "evidence": {
                "archive": _STATIC_ASSETS["example-evidence"],
                "runId": self.evidence_run_id,
                "authoritativeDigest": self.evidence_digest,
            },
            "provenance": {
                "asset": _STATIC_ASSETS["provenance-verification"],
                "mode": self.provenance_mode,
                "cryptographicallyVerified": self.cryptographically_verified,
            },
        }


@dataclass(frozen=True)
class ReleaseAssetVerification:
    passed: bool
    directory: Path
    manifest: ReleaseManifest
    checksums: Mapping[str, str]
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "directory": str(self.directory),
            "version": self.manifest.version,
            "tag": self.manifest.tag,
            "sourceCommit": self.manifest.source_commit,
            "assets": [item.to_dict() for item in self.manifest.assets],
            "evidenceRunId": self.manifest.evidence_run_id,
            "evidenceDigest": self.manifest.evidence_digest,
            "provenanceMode": self.manifest.provenance_mode,
            "cryptographicallyVerified": self.manifest.cryptographically_verified,
            "checksums": dict(sorted(self.checksums.items())),
            "checks": list(self.checks),
        }


class ReleaseAssetAssembler:
    """Assemble a new release directory without overwriting existing output."""

    def assemble(self, request: ReleaseAssemblyRequest) -> ReleaseAssetVerification:
        if not isinstance(request, ReleaseAssemblyRequest):
            raise ReleaseAssetError(
                "RELEASE_INPUT_INVALID", "request has the wrong type"
            )
        project = project_root(request.project)
        output = _contained(project, request.output_directory)
        if output.exists():
            raise ReleaseAssetError(
                "RELEASE_OUTPUT_EXISTS",
                f"refusing to overwrite release output: {request.output_directory}",
            )

        sources = {
            "wheel": _source_file(project, request.wheel_path),
            "sdist": _source_file(project, request.sdist_path),
            "configuration-schema": _source_file(
                project, request.configuration_schema_path
            ),
            "report-schema": _source_file(project, request.report_schema_path),
            "execution-evidence-schema": _source_file(
                project, request.execution_evidence_schema_path
            ),
            "example-config": _source_file(project, request.example_config_path),
            "package-sbom": _source_file(project, request.package_sbom_path),
            "provenance-verification": _source_file(
                project, request.provenance_verification_path
            ),
        }
        resolved_sources = [path.resolve() for path in sources.values()]
        if len(set(resolved_sources)) != len(resolved_sources):
            raise ReleaseAssetError(
                "RELEASE_INPUT_DUPLICATED",
                "release inputs must be distinct regular files",
            )

        _validate_package_archive_names(
            sources["wheel"].name,
            sources["sdist"].name,
            request.version,
        )
        source_payloads = {
            role: _read_regular(
                path,
                maximum=_MAX_RELEASE_FILE_BYTES,
                label=path.name,
            )
            for role, path in sources.items()
        }
        wheel_hash = _sha256(source_payloads["wheel"])
        sdist_hash = _sha256(source_payloads["sdist"])
        _validate_wheel_payload(source_payloads["wheel"], request.version)
        _validate_sdist_payload(source_payloads["sdist"], request.version)
        schemas = _validate_schemas(
            source_payloads["configuration-schema"],
            source_payloads["report-schema"],
            source_payloads["execution-evidence-schema"],
        )
        _validate_example_config(source_payloads["example-config"], schemas[0])
        _validate_package_sbom(
            source_payloads["package-sbom"],
            {sources["wheel"].name: wheel_hash, sources["sdist"].name: sdist_hash},
        )
        provenance = _validate_provenance_material(
            source_payloads["provenance-verification"],
            version=request.version,
            source_commit=request.source_commit,
            package_subjects={
                sources["wheel"].name: wheel_hash,
                sources["sdist"].name: sdist_hash,
            },
        )
        try:
            bundle = load_execution_bundle(
                project,
                request.evidence_run_id,
                work_directory=request.evidence_work_directory,
            )
            bundle_verification = bundle.verify()
        except ExecutionBundleError as exc:
            raise ReleaseAssetError("RELEASE_EVIDENCE_INVALID", str(exc)) from exc
        _require_complete_successful_bundle(
            bundle,
            bundle_verification.authoritative_digest,
            source_commit=request.source_commit,
        )
        evidence_archive = _build_evidence_archive(bundle)

        parent = output.parent
        parent_relative = parent.relative_to(project).as_posix()
        if parent_relative != ".":
            _contained(project, parent_relative).mkdir(parents=True, exist_ok=True)
            if _contained(project, parent_relative) != parent:
                raise ReleaseAssetError("RELEASE_PATH_UNSAFE", "output parent changed")
        stage = Path(tempfile.mkdtemp(prefix=".release-assets.", dir=parent))
        os.chmod(stage, 0o700)
        try:
            names: dict[str, str] = {
                "wheel": sources["wheel"].name,
                "sdist": sources["sdist"].name,
                **_STATIC_ASSETS,
            }
            payloads = {
                role: (
                    evidence_archive
                    if role == "example-evidence"
                    else source_payloads[role]
                )
                for role in _PAYLOAD_ROLES
            }
            records = tuple(
                ReleaseAssetRecord(
                    name=names[role],
                    role=role,
                    sha256=_sha256(payload),
                    size=len(payload),
                )
                for role, payload in payloads.items()
            )
            manifest = ReleaseManifest(
                version=request.version,
                source_commit=request.source_commit,
                assets=records,
                evidence_run_id=request.evidence_run_id,
                evidence_digest=bundle_verification.authoritative_digest or "",
                provenance_mode=provenance["mode"],
                cryptographically_verified=provenance["cryptographicallyVerified"],
            )
            for role, payload in payloads.items():
                atomic_write(stage, names[role], payload, mode=0o644)
            manifest_payload = _json_bytes(manifest.to_dict())
            atomic_write(stage, "release-manifest.json", manifest_payload, mode=0o644)
            checksum_values = {
                **{item.name: item.sha256 for item in records},
                "release-manifest.json": _sha256(manifest_payload),
            }
            atomic_write(
                stage,
                "SHA256SUMS",
                _checksum_bytes(checksum_values),
                mode=0o644,
            )
            stage_relative = stage.relative_to(project).as_posix()
            verification = ReleaseAssetVerifier().verify(
                project,
                stage_relative,
                expected_version=request.version,
                expected_commit=request.source_commit,
            )
            os.replace(stage, output)
            return ReleaseAssetVerification(
                verification.passed,
                output,
                verification.manifest,
                verification.checksums,
                verification.checks,
            )
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise


class ReleaseAssetVerifier:
    """Verify an existing release directory without subprocesses or network access."""

    def verify(
        self,
        project: Path,
        relative_directory: str,
        *,
        expected_version: str | None = None,
        expected_commit: str | None = None,
    ) -> ReleaseAssetVerification:
        root = project_root(project)
        directory = _contained(root, relative_directory)
        if directory.is_symlink() or not directory.is_dir():
            raise ReleaseAssetError(
                "RELEASE_DIRECTORY_INVALID",
                "release directory is not a regular directory",
            )
        paths = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
        if any(path.is_symlink() or not path.is_file() for path in paths):
            raise ReleaseAssetError(
                "RELEASE_ASSET_UNSAFE",
                "release directory may contain only regular files",
            )
        if len({path.name for path in paths}) != len(
            paths
        ):  # pragma: no cover - filesystem
            raise ReleaseAssetError("RELEASE_ASSET_DUPLICATED", "duplicate asset names")

        checksum_path = directory / "SHA256SUMS"
        manifest_path = directory / "release-manifest.json"
        if not checksum_path.is_file() or not manifest_path.is_file():
            raise ReleaseAssetError(
                "RELEASE_ASSET_MISSING",
                "SHA256SUMS and release-manifest.json are required",
            )
        physical = {path.name: path for path in paths}
        payloads = {
            name: _read_regular(
                path,
                maximum=(
                    _MAX_RELEASE_JSON_BYTES
                    if name in {"SHA256SUMS", "release-manifest.json"}
                    else _MAX_RELEASE_FILE_BYTES
                ),
                label=name,
            )
            for name, path in physical.items()
        }
        checksums = _parse_checksums(payloads["SHA256SUMS"])
        if set(checksums) != set(physical) - {"SHA256SUMS"}:
            raise ReleaseAssetError(
                "RELEASE_INVENTORY_MISMATCH",
                "SHA256SUMS must cover every other release file exactly once",
            )
        for name, expected in checksums.items():
            if _sha256(payloads[name]) != expected:
                raise ReleaseAssetError(
                    "RELEASE_CHECKSUM_MISMATCH", f"release checksum differs: {name}"
                )

        manifest_value = _strict_json_bytes(
            payloads["release-manifest.json"], "release-manifest.json"
        )
        if payloads["release-manifest.json"] != _json_bytes(manifest_value):
            raise ReleaseAssetError(
                "RELEASE_MANIFEST_INVALID", "release manifest must use canonical JSON"
            )
        manifest = _parse_manifest(manifest_value)
        if expected_version is not None and manifest.version != expected_version:
            raise ReleaseAssetError(
                "RELEASE_VERSION_MISMATCH",
                "manifest version differs from expected version",
            )
        if expected_commit is not None and manifest.source_commit != expected_commit:
            raise ReleaseAssetError(
                "RELEASE_COMMIT_MISMATCH",
                "manifest commit differs from expected commit",
            )
        expected_files = {item.name for item in manifest.assets} | {
            "release-manifest.json",
            "SHA256SUMS",
        }
        if set(physical) != expected_files:
            raise ReleaseAssetError(
                "RELEASE_INVENTORY_MISMATCH",
                "manifest asset inventory differs from files",
            )
        for item in manifest.assets:
            if (
                checksums[item.name] != item.sha256
                or len(payloads[item.name]) != item.size
            ):
                raise ReleaseAssetError(
                    "RELEASE_MANIFEST_MISMATCH",
                    f"manifest metadata differs: {item.name}",
                )

        by_role = {item.role: item for item in manifest.assets}
        for role, name in _STATIC_ASSETS.items():
            if by_role[role].name != name:
                raise ReleaseAssetError(
                    "RELEASE_MANIFEST_INVALID",
                    f"{role} must use the canonical filename",
                )
        wheel = physical[by_role["wheel"].name]
        sdist = physical[by_role["sdist"].name]
        _validate_package_archive_names(wheel.name, sdist.name, manifest.version)
        _validate_wheel_payload(payloads[wheel.name], manifest.version)
        _validate_sdist_payload(payloads[sdist.name], manifest.version)
        schemas = _validate_schemas(
            payloads[by_role["configuration-schema"].name],
            payloads[by_role["report-schema"].name],
            payloads[by_role["execution-evidence-schema"].name],
        )
        _validate_example_config(payloads[by_role["example-config"].name], schemas[0])
        package_subjects = {
            wheel.name: by_role["wheel"].sha256,
            sdist.name: by_role["sdist"].sha256,
        }
        _validate_package_sbom(payloads[by_role["package-sbom"].name], package_subjects)
        provenance = _validate_provenance_material(
            payloads[by_role["provenance-verification"].name],
            version=manifest.version,
            source_commit=manifest.source_commit,
            package_subjects=package_subjects,
        )
        if (
            provenance["mode"] != manifest.provenance_mode
            or provenance["cryptographicallyVerified"]
            != manifest.cryptographically_verified
        ):
            raise ReleaseAssetError(
                "RELEASE_PROVENANCE_MISMATCH",
                "manifest and provenance verification material differ",
            )
        evidence_digest, evidence_source_commit = _verify_evidence_archive(
            physical[by_role["example-evidence"].name], manifest.evidence_run_id
        )
        if evidence_digest != manifest.evidence_digest:
            raise ReleaseAssetError(
                "RELEASE_EVIDENCE_MISMATCH",
                "manifest and example evidence authoritative digests differ",
            )
        if evidence_source_commit != manifest.source_commit:
            raise ReleaseAssetError(
                "RELEASE_EVIDENCE_MISMATCH",
                "manifest and example evidence source commits differ",
            )
        for name, expected in checksums.items():
            current = _read_regular(
                physical[name], maximum=_MAX_RELEASE_FILE_BYTES, label=name
            )
            if _sha256(current) != expected:
                raise ReleaseAssetError(
                    "RELEASE_ASSET_CHANGED",
                    f"release asset changed during verification: {name}",
                )
        current_checksum_payload = _read_regular(
            checksum_path,
            maximum=_MAX_RELEASE_JSON_BYTES,
            label="SHA256SUMS",
        )
        if current_checksum_payload != payloads["SHA256SUMS"]:
            raise ReleaseAssetError(
                "RELEASE_ASSET_CHANGED",
                "SHA256SUMS changed during verification",
            )
        current_paths = tuple(directory.iterdir())
        if any(path.is_symlink() or not path.is_file() for path in current_paths):
            raise ReleaseAssetError(
                "RELEASE_ASSET_CHANGED",
                "release file type changed during verification",
            )
        current_names = tuple(sorted(path.name for path in current_paths))
        if current_names != tuple(sorted(physical)):
            raise ReleaseAssetError(
                "RELEASE_ASSET_CHANGED",
                "release inventory changed during verification",
            )
        return ReleaseAssetVerification(
            passed=True,
            directory=directory,
            manifest=manifest,
            checksums=checksums,
            checks=(
                "closed-inventory",
                "package-metadata",
                "schemas",
                "example-config",
                "package-sbom-subjects",
                "provenance-subjects",
                "example-evidence",
            ),
        )


def assemble_release_assets(
    request: ReleaseAssemblyRequest,
) -> ReleaseAssetVerification:
    return ReleaseAssetAssembler().assemble(request)


def prepare_release_materials(request: ReleaseMaterialRequest) -> ReleaseMaterialResult:
    """Write deterministic package SBOM and truthful file-provenance records."""

    if not isinstance(request, ReleaseMaterialRequest):
        raise ReleaseAssetError("RELEASE_INPUT_INVALID", "request has the wrong type")
    project = project_root(request.project)
    output = _contained(project, request.output_directory)
    if output.exists():
        raise ReleaseAssetError(
            "RELEASE_OUTPUT_EXISTS",
            f"refusing to overwrite release output: {request.output_directory}",
        )
    wheel = _source_file(project, request.wheel_path)
    sdist = _source_file(project, request.sdist_path)
    _validate_package_archive_names(wheel.name, sdist.name, request.version)
    package_payloads = {
        wheel.name: _read_regular(
            wheel, maximum=_MAX_RELEASE_FILE_BYTES, label=wheel.name
        ),
        sdist.name: _read_regular(
            sdist, maximum=_MAX_RELEASE_FILE_BYTES, label=sdist.name
        ),
    }
    _validate_wheel_payload(package_payloads[wheel.name], request.version)
    _validate_sdist_payload(package_payloads[sdist.name], request.version)
    subjects = {name: _sha256(payload) for name, payload in package_payloads.items()}
    namespace = (
        request.source_repository.rstrip("/")
        + f"/releases/tag/v{request.version}/package.spdx.json"
    )
    files = [
        {
            "SPDXID": f"SPDXRef-File-{index}",
            "fileName": name,
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        for index, (name, digest) in enumerate(sorted(subjects.items()), start=1)
    ]
    sbom: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "name": f"{_DISTRIBUTION}-{request.version}-release-assets",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": request.created_at,
            "creators": [f"Tool: {_DISTRIBUTION}-{request.version}"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": _DISTRIBUTION,
                "versionInfo": request.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": item["SPDXID"],
            }
            for item in files
        ],
    }
    provenance: dict[str, Any] = {
        "schemaVersion": _VERIFICATION_SCHEMA_VERSION,
        "mode": "file-provenance",
        "cryptographicallyVerified": False,
        "verificationTool": {
            "name": _DISTRIBUTION,
            "version": request.version,
        },
        "sourceRepository": request.source_repository,
        "sourceCommit": request.source_commit,
        "tag": f"v{request.version}",
        "subjects": [
            {"name": name, "sha256": digest}
            for name, digest in sorted(subjects.items())
        ],
    }
    sbom_payload = _json_bytes(sbom)
    provenance_payload = _json_bytes(provenance)
    _validate_package_sbom(sbom_payload, subjects)
    _validate_provenance_material(
        provenance_payload,
        version=request.version,
        source_commit=request.source_commit,
        package_subjects=subjects,
    )
    parent = output.parent
    parent_relative = parent.relative_to(project).as_posix()
    if parent_relative != ".":
        _contained(project, parent_relative).mkdir(parents=True, exist_ok=True)
    try:
        output.mkdir(mode=0o700)
        atomic_write(output, "package.spdx.json", sbom_payload, mode=0o644)
        atomic_write(
            output,
            "provenance-verification.json",
            provenance_payload,
            mode=0o644,
        )
    except BaseException:
        if output.is_dir() and not output.is_symlink():
            shutil.rmtree(output)
        raise
    return ReleaseMaterialResult(
        output / "package.spdx.json",
        output / "provenance-verification.json",
        subjects[wheel.name],
        subjects[sdist.name],
    )


def verify_release_assets(
    project: Path,
    relative_directory: str,
    *,
    expected_version: str | None = None,
    expected_commit: str | None = None,
) -> ReleaseAssetVerification:
    return ReleaseAssetVerifier().verify(
        project,
        relative_directory,
        expected_version=expected_version,
        expected_commit=expected_commit,
    )


def _validate_version(value: str) -> None:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("release version must use semantic version syntax")


def _validate_commit(value: str) -> None:
    if not isinstance(value, str) or not _COMMIT.fullmatch(value):
        raise ValueError("source commit must be a full lowercase Git SHA")


def _normalized_timestamp(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("release creation time must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise ValueError("release creation time must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("release creation time must include a timezone")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _validate_repository_url(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("source repository URL must be HTTPS")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("source repository URL must be credential-free HTTPS")


def _validate_oci_digest(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("authoritative digest must be a lowercase SHA-256 OCI digest")


def _validate_top_level_name(value: str) -> None:
    if not isinstance(value, str) or not _TOP_LEVEL_NAME.fullmatch(value):
        raise ValueError("release asset name must be one safe top-level filename")


def _contained(root: Path, relative: str) -> Path:
    try:
        return contained_path(root, relative)
    except UnsafePathError as exc:
        raise ReleaseAssetError("RELEASE_PATH_UNSAFE", str(exc)) from exc


def _source_file(project: Path, relative: str) -> Path:
    path = _contained(project, relative)
    if path.is_symlink() or not path.is_file():
        raise ReleaseAssetError(
            "RELEASE_INPUT_INVALID", f"release input is not a regular file: {relative}"
        )
    return path


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseAssetError(
            "RELEASE_INPUT_INVALID", f"cannot open regular file: {label}"
        ) from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ReleaseAssetError(
                    "RELEASE_INPUT_INVALID", f"not a regular file: {label}"
                )
            if metadata.st_size > maximum:
                raise ReleaseAssetError(
                    "RELEASE_INPUT_TOO_LARGE",
                    f"{label} exceeds the {maximum}-byte limit",
                )
            payload = stream.read(maximum + 1)
    except ReleaseAssetError:
        raise
    except OSError as exc:
        raise ReleaseAssetError(
            "RELEASE_INPUT_INVALID", f"cannot read regular file: {label}"
        ) from exc
    if len(payload) > maximum:
        raise ReleaseAssetError(
            "RELEASE_INPUT_TOO_LARGE", f"{label} exceeds the {maximum}-byte limit"
        )
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                dict(value),
                indent=2,
                sort_keys=True,
                allow_nan=False,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseAssetError(
            "RELEASE_JSON_INVALID", "release JSON is not finite and serializable"
        ) from exc


def _strict_json_bytes(payload: bytes, source: str) -> Mapping[str, Any]:
    try:
        return parse_strict_json(payload, source=source)
    except ExecutionBundleError as exc:
        raise ReleaseAssetError("RELEASE_JSON_INVALID", str(exc)) from exc


def _checksum_bytes(values: Mapping[str, str]) -> bytes:
    return "".join(f"{values[name]}  {name}\n" for name in sorted(values)).encode()


def _parse_checksums(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseAssetError(
            "RELEASE_CHECKSUMS_INVALID", "SHA256SUMS is not UTF-8"
        ) from exc
    lines = text.splitlines(keepends=True)
    if not lines or any(not line.endswith("\n") for line in lines):
        raise ReleaseAssetError(
            "RELEASE_CHECKSUMS_INVALID",
            "SHA256SUMS must be non-empty and newline-terminated",
        )
    result: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line[:-1])
        if match is None:
            raise ReleaseAssetError(
                "RELEASE_CHECKSUMS_INVALID", "invalid SHA256SUMS line"
            )
        digest, name = match.groups()
        if name == "SHA256SUMS" or name in result:
            raise ReleaseAssetError(
                "RELEASE_ASSET_DUPLICATED",
                f"duplicate or recursive checksum name: {name}",
            )
        result[name] = digest
        order.append(name)
    if order != sorted(order):
        raise ReleaseAssetError(
            "RELEASE_CHECKSUMS_INVALID", "SHA256SUMS must be sorted"
        )
    return result


def _validate_package_archive_names(wheel: str, sdist: str, version: str) -> None:
    escaped = re.escape(version)
    if re.fullmatch(rf"devops_stack_composer-{escaped}-[^/]+\.whl", wheel) is None:
        raise ReleaseAssetError(
            "RELEASE_VERSION_MISMATCH", "wheel filename does not match release version"
        )
    if re.fullmatch(rf"devops[_-]stack[_-]composer-{escaped}\.tar\.gz", sdist) is None:
        raise ReleaseAssetError(
            "RELEASE_VERSION_MISMATCH", "sdist filename does not match release version"
        )


def _safe_archive_name(value: str) -> PurePosixPath:
    if not value or "\\" in value or value.startswith("/") or "\x00" in value:
        raise ReleaseAssetError(
            "RELEASE_ARCHIVE_UNSAFE", f"unsafe archive path: {value!r}"
        )
    path = PurePosixPath(value)
    if path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseAssetError(
            "RELEASE_ARCHIVE_UNSAFE", f"unsafe archive path: {value!r}"
        )
    return path


def _metadata_headers(payload: bytes, source: str) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseAssetError(
            "RELEASE_PACKAGE_INVALID", f"{source} is not UTF-8"
        ) from exc
    headers: dict[str, str] = {}
    for line in lines:
        if not line:
            break
        if line.startswith((" ", "\t")):
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ReleaseAssetError(
                "RELEASE_PACKAGE_INVALID", f"invalid {source} header"
            )
        if name in headers:
            raise ReleaseAssetError(
                "RELEASE_PACKAGE_INVALID", f"duplicate {source} header: {name}"
            )
        headers[name] = value.strip()
    return headers


def _validate_wheel_payload(compressed: bytes, version: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(compressed)) as archive:
            members = archive.infolist()
            if len(members) > _MAX_PACKAGE_FILES:
                raise ReleaseAssetError(
                    "RELEASE_PACKAGE_INVALID", "wheel contains too many members"
                )
            names: set[str] = set()
            metadata: list[bytes] = []
            total = 0
            for info in members:
                name = info.filename[:-1] if info.is_dir() else info.filename
                _safe_archive_name(name)
                if info.filename in names:
                    raise ReleaseAssetError(
                        "RELEASE_ASSET_DUPLICATED", "wheel path duplicated"
                    )
                names.add(info.filename)
                mode = info.external_attr >> 16
                if mode and stat.S_ISLNK(mode):
                    raise ReleaseAssetError(
                        "RELEASE_ARCHIVE_UNSAFE", "wheel contains a symlink"
                    )
                if info.flag_bits & 0x1:
                    raise ReleaseAssetError(
                        "RELEASE_ARCHIVE_UNSAFE", "wheel contains an encrypted member"
                    )
                if not info.is_dir():
                    total += info.file_size
                    if (
                        info.file_size > _MAX_PACKAGE_MEMBER_BYTES
                        or total > _MAX_PACKAGE_UNCOMPRESSED_BYTES
                    ):
                        raise ReleaseAssetError(
                            "RELEASE_PACKAGE_INVALID",
                            "wheel uncompressed content exceeds the release limit",
                        )
                if info.filename.endswith(".dist-info/METADATA"):
                    payload = archive.read(info)
                    if len(payload) != info.file_size:
                        raise ReleaseAssetError(
                            "RELEASE_PACKAGE_INVALID", "wheel metadata is truncated"
                        )
                    metadata.append(payload)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReleaseAssetError(
            "RELEASE_PACKAGE_INVALID", "wheel is not a valid ZIP"
        ) from exc
    if len(metadata) != 1:
        raise ReleaseAssetError(
            "RELEASE_PACKAGE_INVALID", "wheel must contain exactly one METADATA file"
        )
    headers = _metadata_headers(metadata[0], "wheel METADATA")
    if headers.get("Name") != _DISTRIBUTION or headers.get("Version") != version:
        raise ReleaseAssetError(
            "RELEASE_VERSION_MISMATCH", "wheel metadata name or version does not match"
        )


def _validate_sdist_payload(compressed: bytes, version: str) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > _MAX_PACKAGE_FILES:
                raise ReleaseAssetError(
                    "RELEASE_PACKAGE_INVALID", "sdist contains too many members"
                )
            names: set[str] = set()
            metadata: list[bytes] = []
            roots: set[str] = set()
            total = 0
            for member in members:
                name = (
                    member.name[:-1]
                    if member.isdir() and member.name.endswith("/")
                    else member.name
                )
                parsed = _safe_archive_name(name)
                roots.add(parsed.parts[0])
                if name in names:
                    raise ReleaseAssetError(
                        "RELEASE_ASSET_DUPLICATED", "sdist path duplicated"
                    )
                names.add(name)
                if not (member.isdir() or member.isfile()):
                    raise ReleaseAssetError(
                        "RELEASE_ARCHIVE_UNSAFE",
                        "sdist contains a link or special file",
                    )
                if member.isfile():
                    total += member.size
                    if (
                        member.size > _MAX_PACKAGE_MEMBER_BYTES
                        or total > _MAX_PACKAGE_UNCOMPRESSED_BYTES
                    ):
                        raise ReleaseAssetError(
                            "RELEASE_PACKAGE_INVALID",
                            "sdist uncompressed content exceeds the release limit",
                        )
                if (
                    member.isfile()
                    and parsed.name == "PKG-INFO"
                    and len(parsed.parts) == 2
                ):
                    extracted = archive.extractfile(member)
                    if extracted is None:  # pragma: no cover - tarfile invariant
                        raise ReleaseAssetError(
                            "RELEASE_PACKAGE_INVALID", "PKG-INFO unreadable"
                        )
                    payload = extracted.read(_MAX_PACKAGE_MEMBER_BYTES + 1)
                    if len(payload) != member.size:
                        raise ReleaseAssetError(
                            "RELEASE_PACKAGE_INVALID", "sdist metadata is truncated"
                        )
                    metadata.append(payload)
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseAssetError(
            "RELEASE_PACKAGE_INVALID", "sdist is not valid tar.gz"
        ) from exc
    if len(roots) != 1 or len(metadata) != 1:
        raise ReleaseAssetError(
            "RELEASE_PACKAGE_INVALID", "sdist needs one root and one root PKG-INFO"
        )
    headers = _metadata_headers(metadata[0], "sdist PKG-INFO")
    if headers.get("Name") != _DISTRIBUTION or headers.get("Version") != version:
        raise ReleaseAssetError(
            "RELEASE_VERSION_MISMATCH", "sdist metadata name or version does not match"
        )


def _validate_schemas(
    configuration: bytes,
    report: bytes,
    execution_evidence: bytes,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    values = (
        _strict_json_bytes(configuration, "devops-stack.schema.json"),
        _strict_json_bytes(report, "execution-report.schema.json"),
        _strict_json_bytes(execution_evidence, "execution-evidence.schema.json"),
    )
    try:
        for value in values:
            Draft7Validator.check_schema(value)
        evidence_id = values[2].get("$id")
        store = {"execution-evidence.schema.json": values[2]}
        if isinstance(evidence_id, str):
            store[evidence_id] = values[2]
        validator = Draft7Validator(
            values[1], resolver=RefResolver.from_schema(values[1], store=store)
        )
        tuple(validator.iter_errors({}))
    except (SchemaError, Exception) as exc:
        if isinstance(exc, ReleaseAssetError):
            raise
        raise ReleaseAssetError(
            "RELEASE_SCHEMA_INVALID", "release schema is invalid"
        ) from exc
    return values


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.YAMLError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _validate_example_config(payload: bytes, schema: Mapping[str, Any]) -> None:
    try:
        value = yaml.load(payload.decode("utf-8"), Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ReleaseAssetError(
            "RELEASE_EXAMPLE_INVALID", "example config is invalid YAML"
        ) from exc
    if not isinstance(value, Mapping):
        raise ReleaseAssetError(
            "RELEASE_EXAMPLE_INVALID", "example config must be an object"
        )
    errors = sorted(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise ReleaseAssetError(
            "RELEASE_EXAMPLE_INVALID",
            f"example config violates schema: {errors[0].message}",
        )


def _validate_package_sbom(payload: bytes, package_subjects: Mapping[str, str]) -> None:
    value = _strict_json_bytes(payload, "package.spdx.json")
    if (
        value.get("spdxVersion") != "SPDX-2.3"
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or value.get("dataLicense") != "CC0-1.0"
    ):
        raise ReleaseAssetError("RELEASE_SBOM_INVALID", "package SBOM is not SPDX 2.3")
    creation = value.get("creationInfo")
    creators = creation.get("creators") if isinstance(creation, Mapping) else None
    if not isinstance(creators, list) or not any(
        isinstance(item, str) and item.startswith("Tool: ") for item in creators
    ):
        raise ReleaseAssetError(
            "RELEASE_SBOM_INVALID", "package SBOM has no tool creator"
        )
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseAssetError(
            "RELEASE_SBOM_INVALID", "package SBOM package list is empty"
        )
    files = value.get("files")
    if not isinstance(files, list):
        raise ReleaseAssetError(
            "RELEASE_SBOM_INVALID", "package SBOM files must be an array"
        )
    found: dict[str, str] = {}
    for item in files:
        if not isinstance(item, Mapping):
            raise ReleaseAssetError(
                "RELEASE_SBOM_INVALID", "package SBOM file is invalid"
            )
        name = item.get("fileName")
        if not isinstance(name, str) or name not in package_subjects:
            continue
        if name in found:
            raise ReleaseAssetError(
                "RELEASE_ASSET_DUPLICATED", f"duplicate SBOM file: {name}"
            )
        checksums = item.get("checksums")
        matches = [
            entry.get("checksumValue")
            for entry in checksums or ()
            if isinstance(entry, Mapping) and entry.get("algorithm") == "SHA256"
        ]
        if len(matches) != 1 or not isinstance(matches[0], str):
            raise ReleaseAssetError(
                "RELEASE_SBOM_INVALID", f"package SBOM has no unique SHA256 for {name}"
            )
        found[name] = matches[0]
    if found != dict(package_subjects):
        raise ReleaseAssetError(
            "RELEASE_SBOM_SUBJECT_MISMATCH",
            "package SBOM subjects differ from packages",
        )


def _validate_provenance_material(
    payload: bytes,
    *,
    version: str,
    source_commit: str,
    package_subjects: Mapping[str, str],
) -> Mapping[str, Any]:
    value = _strict_json_bytes(payload, "provenance-verification.json")
    required = {
        "schemaVersion",
        "mode",
        "cryptographicallyVerified",
        "verificationTool",
        "sourceRepository",
        "sourceCommit",
        "tag",
        "subjects",
    }
    if (
        set(value) != required
        or value.get("schemaVersion") != _VERIFICATION_SCHEMA_VERSION
    ):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "provenance material fields do not match"
        )
    mode = value.get("mode")
    crypto = value.get("cryptographicallyVerified")
    if mode not in {"file-provenance", "keyless-attestation"} or not isinstance(
        crypto, bool
    ):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "provenance mode is invalid"
        )
    if (mode == "file-provenance" and crypto) or (
        mode == "keyless-attestation" and not crypto
    ):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID",
            "provenance mode overclaims or underclaims verification",
        )
    if value.get("sourceCommit") != source_commit or value.get("tag") != f"v{version}":
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_MISMATCH", "provenance source commit or tag differs"
        )
    repository = value.get("sourceRepository")
    if not isinstance(repository, str):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "source repository is missing"
        )
    try:
        _validate_repository_url(repository)
    except ValueError as exc:
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "source repository URL is unsafe"
        ) from exc
    tool = value.get("verificationTool")
    if (
        not isinstance(tool, Mapping)
        or set(tool) != {"name", "version"}
        or not all(isinstance(tool.get(key), str) and tool.get(key) for key in tool)
    ):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "verification tool is invalid"
        )
    subjects = value.get("subjects")
    if not isinstance(subjects, list):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_INVALID", "subjects must be an array"
        )
    found: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, Mapping) or set(subject) != {"name", "sha256"}:
            raise ReleaseAssetError("RELEASE_PROVENANCE_INVALID", "subject is invalid")
        name = subject.get("name")
        digest = subject.get("sha256")
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
        ):
            raise ReleaseAssetError(
                "RELEASE_PROVENANCE_INVALID", "subject fields are invalid"
            )
        if name in found:
            raise ReleaseAssetError(
                "RELEASE_ASSET_DUPLICATED", f"duplicate subject: {name}"
            )
        found[name] = digest
    if found != dict(package_subjects):
        raise ReleaseAssetError(
            "RELEASE_PROVENANCE_SUBJECT_MISMATCH",
            "provenance subjects differ from packages",
        )
    return value


def _require_complete_successful_bundle(
    bundle: Any,
    digest: str | None,
    *,
    source_commit: str | None = None,
) -> None:
    run = bundle.execution_run
    if (
        digest is None
        or run is None
        or run.final_status.value != "PASSED"
        or bundle.artifact is None
        or bundle.supply_chain is None
        or bundle.deployment is None
        or bundle.stored_verification is None
    ):
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_INVALID",
            "example evidence must be a complete successful deployment run",
        )
    if source_commit is not None and run.source_revision != source_commit:
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_MISMATCH",
            "example evidence source commit differs from the release commit",
        )


def _sanitize_evidence(relative: str, payload: bytes) -> None:
    path = PurePosixPath(relative)
    for part in path.parts:
        lowered = part.lower()
        if lowered in _SENSITIVE_PATH_NAMES or lowered.endswith(
            (".pem", ".key", ".p12")
        ):
            raise ReleaseAssetError(
                "RELEASE_EVIDENCE_SENSITIVE", f"sensitive evidence filename: {relative}"
            )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_SENSITIVE", f"example evidence is not text: {relative}"
        ) from exc
    if (
        "-----BEGIN " in text
        or "/home/" in text
        or "/Users/" in text
        or re.search(r"[A-Za-z]:\\Users\\", text)
        or re.search(r"(?m)^\s*kind:\s*Secret\s*$", text)
        or re.search(r'"kind"\s*:\s*"Secret"', text)
        or _SENSITIVE_ASSIGNMENT.search(text)
    ):
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_SENSITIVE",
            f"example evidence contains sensitive data: {relative}",
        )


def _build_evidence_archive(bundle: Any) -> bytes:
    root = bundle.root
    entries = tuple(
        sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    )
    files = [path for path in entries if path.is_file()]
    if len(files) > _MAX_EVIDENCE_FILES:
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_INVALID", "example evidence has too many files"
        )
    payloads: dict[str, bytes] = {}
    total = 0
    for path in files:
        if path.is_symlink():
            raise ReleaseAssetError(
                "RELEASE_ARCHIVE_UNSAFE", "evidence contains a symlink"
            )
        relative = path.relative_to(root).as_posix()
        payload = _read_regular(
            path,
            maximum=_MAX_EVIDENCE_BYTES,
            label=relative,
        )
        total += len(payload)
        if total > _MAX_EVIDENCE_BYTES:
            raise ReleaseAssetError(
                "RELEASE_EVIDENCE_INVALID", "example evidence is too large"
            )
        _sanitize_evidence(relative, payload)
        payloads[relative] = payload

    prefix = PurePosixPath(".devops-stack", "runs", bundle.run_id)
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            directories = {prefix, prefix.parent, prefix.parent.parent}
            directories.update(
                prefix / path.relative_to(root) for path in entries if path.is_dir()
            )
            for directory in sorted(
                directories, key=lambda item: (len(item.parts), item.as_posix())
            ):
                info = tarfile.TarInfo(directory.as_posix())
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                info.mtime = info.uid = info.gid = 0
                archive.addfile(info)
            for relative, payload in sorted(payloads.items()):
                info = tarfile.TarInfo((prefix / relative).as_posix())
                info.size = len(payload)
                info.mode = 0o600
                info.mtime = info.uid = info.gid = 0
                archive.addfile(info, io.BytesIO(payload))
    return raw.getvalue()


def _verify_evidence_archive(path: Path, run_id: str) -> tuple[str, str]:
    prefix = PurePosixPath(".devops-stack", "runs", run_id)
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    names: set[str] = set()
    total = 0
    try:
        compressed = _read_regular(
            path, maximum=_MAX_RELEASE_FILE_BYTES, label=path.name
        )
        with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
            archive_members = archive.getmembers()
            if len(archive_members) > _MAX_EVIDENCE_FILES:
                raise ReleaseAssetError(
                    "RELEASE_EVIDENCE_INVALID",
                    "example evidence archive has too many members",
                )
            for member in archive_members:
                parsed = _safe_archive_name(member.name)
                if member.name in names:
                    raise ReleaseAssetError(
                        "RELEASE_ASSET_DUPLICATED",
                        "example evidence archive path duplicated",
                    )
                names.add(member.name)
                if (
                    parsed != prefix
                    and parsed not in prefix.parents
                    and prefix not in parsed.parents
                ):
                    raise ReleaseAssetError(
                        "RELEASE_ARCHIVE_UNSAFE",
                        "evidence archive has an unexpected root",
                    )
                if not (member.isdir() or member.isfile()):
                    raise ReleaseAssetError(
                        "RELEASE_ARCHIVE_UNSAFE",
                        "evidence archive contains a special file",
                    )
                payload = None
                if member.isfile():
                    total += member.size
                    if member.size > _MAX_EVIDENCE_BYTES or total > _MAX_EVIDENCE_BYTES:
                        raise ReleaseAssetError(
                            "RELEASE_EVIDENCE_INVALID",
                            "example evidence archive is too large",
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:  # pragma: no cover - tarfile invariant
                        raise ReleaseAssetError(
                            "RELEASE_EVIDENCE_INVALID",
                            "example evidence member unreadable",
                        )
                    payload = extracted.read(member.size + 1)
                    if len(payload) != member.size:
                        raise ReleaseAssetError(
                            "RELEASE_EVIDENCE_INVALID",
                            "example evidence member is truncated",
                        )
                    relative = parsed.relative_to(prefix).as_posix()
                    _sanitize_evidence(relative, payload)
                members.append((member, payload))
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_INVALID", "example evidence is not valid tar.gz"
        ) from exc
    if (prefix / "SHA256SUMS").as_posix() not in names:
        raise ReleaseAssetError(
            "RELEASE_EVIDENCE_INVALID", "evidence archive lacks SHA256SUMS"
        )

    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary)
        for member, payload in members:
            if member.isdir():
                target = project.joinpath(*PurePosixPath(member.name).parts)
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                assert payload is not None
                atomic_write(project, member.name, payload, mode=0o600)
        try:
            bundle = load_execution_bundle(project, run_id)
            verification = bundle.verify()
        except ExecutionBundleError as exc:
            raise ReleaseAssetError("RELEASE_EVIDENCE_INVALID", str(exc)) from exc
        _require_complete_successful_bundle(bundle, verification.authoritative_digest)
        assert verification.authoritative_digest is not None
        assert bundle.execution_run is not None
        return verification.authoritative_digest, bundle.execution_run.source_revision


def _parse_manifest(value: Mapping[str, Any]) -> ReleaseManifest:
    required = {
        "schemaVersion",
        "distribution",
        "version",
        "tag",
        "sourceCommit",
        "assets",
        "evidence",
        "provenance",
    }
    if set(value) != required or value.get("schemaVersion") != _SCHEMA_VERSION:
        raise ReleaseAssetError(
            "RELEASE_MANIFEST_INVALID", "manifest fields do not match"
        )
    if value.get("distribution") != _DISTRIBUTION:
        raise ReleaseAssetError("RELEASE_MANIFEST_INVALID", "distribution name differs")
    version = value.get("version")
    source_commit = value.get("sourceCommit")
    if not isinstance(version, str) or value.get("tag") != f"v{version}":
        raise ReleaseAssetError(
            "RELEASE_VERSION_MISMATCH", "manifest tag/version differs"
        )
    if not isinstance(source_commit, str):
        raise ReleaseAssetError("RELEASE_MANIFEST_INVALID", "source commit is missing")
    raw_assets = value.get("assets")
    if not isinstance(raw_assets, list):
        raise ReleaseAssetError("RELEASE_MANIFEST_INVALID", "assets must be an array")
    assets: list[ReleaseAssetRecord] = []
    try:
        for item in raw_assets:
            if not isinstance(item, Mapping) or set(item) != {
                "name",
                "role",
                "sha256",
                "size",
            }:
                raise ValueError("asset fields differ")
            assets.append(
                ReleaseAssetRecord(
                    name=item["name"],
                    role=item["role"],
                    sha256=item["sha256"],
                    size=item["size"],
                )
            )
        evidence = value.get("evidence")
        provenance = value.get("provenance")
        if not isinstance(evidence, Mapping) or set(evidence) != {
            "archive",
            "runId",
            "authoritativeDigest",
        }:
            raise ValueError("evidence fields differ")
        if evidence.get("archive") != _STATIC_ASSETS["example-evidence"]:
            raise ValueError("evidence archive name differs")
        if not isinstance(provenance, Mapping) or set(provenance) != {
            "asset",
            "mode",
            "cryptographicallyVerified",
        }:
            raise ValueError("provenance fields differ")
        if provenance.get("asset") != _STATIC_ASSETS["provenance-verification"]:
            raise ValueError("provenance asset name differs")
        manifest = ReleaseManifest(
            version=version,
            source_commit=source_commit,
            assets=tuple(assets),
            evidence_run_id=evidence["runId"],
            evidence_digest=evidence["authoritativeDigest"],
            provenance_mode=provenance["mode"],
            cryptographically_verified=provenance["cryptographicallyVerified"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseAssetError("RELEASE_MANIFEST_INVALID", str(exc)) from exc
    if manifest.to_dict() != dict(value):
        raise ReleaseAssetError("RELEASE_MANIFEST_INVALID", "manifest is not canonical")
    return manifest
