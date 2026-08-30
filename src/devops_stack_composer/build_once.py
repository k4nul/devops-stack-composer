"""Single-invocation Buildx execution and immutable registry identity resolution."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.oci import parse_oci_reference


class BuildOnceError(DevOpsStackError):
    """Raised when the one-build or registry-identity contract is violated."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run one argument-vector command without invoking a shell."""


class SubprocessRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class PlatformDescriptor:
    operating_system: str
    architecture: str
    digest: str
    media_type: str
    size: int
    config_digest: str

    @property
    def platform(self) -> str:
        return f"{self.operating_system}/{self.architecture}"


@dataclass(frozen=True)
class BuildResult:
    repository: str
    tag: str
    digest: str
    media_type: str
    size: int
    config_digest: str | None
    platforms: tuple[PlatformDescriptor, ...]
    build_invocation_count: int
    build_metadata_path: Path
    command: tuple[str, ...]
    stdout: bytes
    stderr: bytes

    @property
    def tagged_reference(self) -> str:
        return f"{self.repository}:{self.tag}"

    @property
    def immutable_reference(self) -> str:
        return f"{self.repository}@{self.digest}"


class BuildInvocationGuard:
    """Persistently rejects a second image-build attempt for one run directory."""

    def __init__(self, path: Path):
        self.path = path

    def claim(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise BuildOnceError(
                "BUILD_INVOKED_MORE_THAN_ONCE",
                f"build invocation marker already exists: {self.path.name}",
            ) from exc
        try:
            os.write(descriptor, b"1\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @property
    def count(self) -> int:
        if not self.path.is_file() or self.path.is_symlink():
            return 0
        try:
            return int(self.path.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return 0


@dataclass(frozen=True)
class BuildRequest:
    project: Path
    context: Path
    dockerfile: Path
    repository: str
    tag: str
    platforms: tuple[str, ...]
    metadata_path: Path
    invocation_marker: Path
    oci_title: str
    oci_description: str
    oci_source: str
    oci_revision: str
    oci_created: str
    oci_licenses: str = "MIT"
    # Inline BuildKit attestations turn a single-platform image into an OCI index.
    # Execution profiles generate digest-bound SBOM/provenance after this push, so
    # both defaults are explicitly disabled to keep the registry and pod image IDs
    # identical. Callers may opt in only when their identity policy models an index.
    sbom: str | None = "false"
    provenance: str | None = "false"
    timeout_seconds: int = 1800


_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_digest(value: Any, *, source: str) -> str:
    if not isinstance(value, str):
        raise BuildOnceError("ARTIFACT_DIGEST_MISSING", f"{source} has no digest")
    if len(value) != 71 or not value.startswith("sha256:"):
        raise BuildOnceError("ARTIFACT_DIGEST_INVALID", f"{source} has invalid digest {value!r}")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise BuildOnceError(
            "ARTIFACT_DIGEST_INVALID", f"{source} has invalid digest {value!r}"
        ) from exc
    if value != value.lower():
        raise BuildOnceError("ARTIFACT_DIGEST_INVALID", f"{source} digest must be lowercase")
    return value


def _json_object(payload: bytes, *, source: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildOnceError("ARTIFACT_METADATA_INVALID", f"{source} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BuildOnceError("ARTIFACT_METADATA_INVALID", f"{source} must be a JSON object")
    return value


def parse_build_metadata(path: Path) -> tuple[str, str, int, str | None]:
    if path.is_symlink() or not path.is_file():
        raise BuildOnceError(
            "ARTIFACT_DIGEST_MISSING", f"Buildx metadata file is missing: {path.name}"
        )
    value = _json_object(path.read_bytes(), source="Buildx metadata")
    digest = _require_digest(value.get("containerimage.digest"), source="Buildx metadata")
    descriptor = value.get("containerimage.descriptor")
    if not isinstance(descriptor, dict):
        descriptor = {}
    descriptor_digest = descriptor.get("digest")
    if descriptor_digest is not None and _require_digest(
        descriptor_digest, source="Buildx descriptor"
    ) != digest:
        raise BuildOnceError(
            "ARTIFACT_DIGEST_MISMATCH",
            "Buildx containerimage.digest differs from its descriptor digest",
        )
    media_type = descriptor.get("mediaType", "")
    if not isinstance(media_type, str):
        media_type = ""
    size = descriptor.get("size", 0)
    if not isinstance(size, int) or size < 0:
        size = 0
    config_digest = value.get("containerimage.config.digest")
    if config_digest is not None:
        config_digest = _require_digest(config_digest, source="Buildx config metadata")
    return digest, media_type, size, config_digest


def _platform_descriptors(
    *,
    repository: str,
    top_digest: str,
    top_manifest: dict[str, Any],
    requested_platforms: tuple[str, ...],
    runner: CommandRunner,
    cwd: Path,
    environment: Mapping[str, str] | None,
) -> tuple[PlatformDescriptor, ...]:
    media_type = str(top_manifest.get("mediaType", ""))
    if media_type in _MANIFEST_MEDIA_TYPES:
        config = top_manifest.get("config")
        config_digest = _require_digest(
            config.get("digest") if isinstance(config, dict) else None,
            source="image manifest config",
        )
        operating_system, architecture = requested_platforms[0].split("/", 1)
        return (
            PlatformDescriptor(
                operating_system,
                architecture,
                top_digest,
                media_type,
                0,
                config_digest,
            ),
        )
    if media_type not in _INDEX_MEDIA_TYPES:
        raise BuildOnceError(
            "ARTIFACT_METADATA_INVALID", f"unsupported registry media type {media_type!r}"
        )
    manifests = top_manifest.get("manifests")
    if not isinstance(manifests, list):
        raise BuildOnceError("ARTIFACT_METADATA_INVALID", "image index has no manifest list")
    by_platform: dict[str, dict[str, Any]] = {}
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            continue
        annotations = descriptor.get("annotations")
        if isinstance(annotations, dict) and annotations.get(
            "vnd.docker.reference.type"
        ) == "attestation-manifest":
            continue
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            continue
        operating_system = platform.get("os")
        architecture = platform.get("architecture")
        if isinstance(operating_system, str) and isinstance(architecture, str):
            by_platform[f"{operating_system}/{architecture}"] = descriptor
    resolved: list[PlatformDescriptor] = []
    for requested in requested_platforms:
        descriptor = by_platform.get(requested)
        if descriptor is None:
            raise BuildOnceError(
                "ARTIFACT_PLATFORM_MISSING", f"registry index has no {requested} image manifest"
            )
        digest = _require_digest(descriptor.get("digest"), source=f"{requested} descriptor")
        raw = runner.run(
            ("docker", "buildx", "imagetools", "inspect", "--raw", f"{repository}@{digest}"),
            cwd=cwd,
            environment=environment,
            timeout=120,
        )
        if raw.returncode != 0:
            raise BuildOnceError(
                "REGISTRY_UNREACHABLE", f"cannot inspect immutable {requested} manifest"
            )
        if _sha256(raw.stdout) != digest:
            raise BuildOnceError(
                "ARTIFACT_DIGEST_MISMATCH",
                f"registry bytes for {requested} do not match descriptor digest",
            )
        manifest = _json_object(raw.stdout, source=f"{requested} manifest")
        config = manifest.get("config")
        config_digest = _require_digest(
            config.get("digest") if isinstance(config, dict) else None,
            source=f"{requested} config",
        )
        descriptor_media_type = descriptor.get("mediaType")
        descriptor_size = descriptor.get("size")
        resolved.append(
            PlatformDescriptor(
                operating_system=requested.split("/", 1)[0],
                architecture=requested.split("/", 1)[1],
                digest=digest,
                media_type=(
                    descriptor_media_type if isinstance(descriptor_media_type, str) else ""
                ),
                size=descriptor_size if isinstance(descriptor_size, int) else len(raw.stdout),
                config_digest=config_digest,
            )
        )
    return tuple(resolved)


class BuildOnceExecutor:
    """Run one Buildx solve, push directly, and verify registry-returned bytes."""

    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or SubprocessRunner()

    @staticmethod
    def _command(request: BuildRequest) -> tuple[str, ...]:
        command: list[str] = [
            "docker",
            "buildx",
            "build",
            "--platform",
            ",".join(request.platforms),
            "--file",
            str(request.dockerfile),
            "--tag",
            f"{request.repository}:{request.tag}",
            "--build-arg",
            f"OCI_TITLE={request.oci_title}",
            "--build-arg",
            f"OCI_DESCRIPTION={request.oci_description}",
            "--build-arg",
            f"OCI_SOURCE={request.oci_source}",
            "--build-arg",
            f"OCI_REVISION={request.oci_revision}",
            "--build-arg",
            f"OCI_CREATED={request.oci_created}",
            "--build-arg",
            f"OCI_LICENSES={request.oci_licenses}",
        ]
        if request.sbom is not None:
            command.extend(("--sbom", request.sbom))
        if request.provenance is not None:
            command.extend(("--provenance", request.provenance))
        command.extend(
            (
                "--push",
                "--metadata-file",
                str(request.metadata_path),
                str(request.context),
            )
        )
        return tuple(command)

    def execute(
        self,
        request: BuildRequest,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> BuildResult:
        try:
            image_reference = parse_oci_reference(
                f"{request.repository}:{request.tag}"
            )
        except ValueError as exc:
            raise BuildOnceError("ARTIFACT_REFERENCE_INVALID", str(exc)) from exc
        if image_reference.tag is None or image_reference.digest is not None:
            raise BuildOnceError(
                "ARTIFACT_REFERENCE_INVALID", "build output requires one concrete tag"
            )
        if not request.platforms or any("/" not in value for value in request.platforms):
            raise BuildOnceError("ARTIFACT_PLATFORM_MISSING", "at least one os/architecture is required")
        for path, label in (
            (request.project, "project"),
            (request.context, "build context"),
        ):
            if path.is_symlink() or not path.is_dir():
                raise BuildOnceError("UNSAFE_BUILD_PATH", f"{label} is not a regular directory")
        if request.dockerfile.is_symlink() or not request.dockerfile.is_file():
            raise BuildOnceError("UNSAFE_BUILD_PATH", "Dockerfile is not a regular file")
        project = request.project.resolve(strict=True)
        context = request.context.resolve(strict=True)
        for candidate, label in (
            (context, "build context"),
            (request.dockerfile.resolve(strict=True), "Dockerfile"),
            (request.metadata_path.resolve(strict=False), "Buildx metadata"),
            (request.invocation_marker.resolve(strict=False), "build invocation marker"),
        ):
            try:
                candidate.relative_to(project)
            except ValueError as exc:
                raise BuildOnceError(
                    "UNSAFE_BUILD_PATH", f"{label} leaves the project root"
                ) from exc
        if request.metadata_path == request.invocation_marker:
            raise BuildOnceError(
                "UNSAFE_BUILD_PATH", "metadata and invocation marker paths must differ"
            )
        guard = BuildInvocationGuard(request.invocation_marker)
        guard.claim()
        request.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        if request.metadata_path.exists() or request.metadata_path.is_symlink():
            raise BuildOnceError(
                "ARTIFACT_METADATA_EXISTS", "refusing to replace existing Buildx metadata"
            )
        command = self._command(request)
        completed = self.runner.run(
            command,
            cwd=project,
            environment=environment,
            timeout=request.timeout_seconds,
        )
        if completed.returncode != 0:
            raise BuildOnceError(
                "IMAGE_BUILD_FAILED",
                f"the single Buildx invocation failed with exit code {completed.returncode}",
            )
        digest, metadata_media_type, metadata_size, config_digest = parse_build_metadata(
            request.metadata_path
        )

        tag_reference = f"{request.repository}:{request.tag}"
        raw = self.runner.run(
            ("docker", "buildx", "imagetools", "inspect", "--raw", tag_reference),
            cwd=project,
            environment=environment,
            timeout=120,
        )
        if raw.returncode != 0:
            raise BuildOnceError("REGISTRY_UNREACHABLE", "cannot resolve the pushed registry tag")
        registry_digest = _sha256(raw.stdout)
        if registry_digest != digest:
            raise BuildOnceError(
                "ARTIFACT_DIGEST_MISMATCH",
                f"Buildx metadata digest {digest} differs from registry digest {registry_digest}",
            )
        top_manifest = _json_object(raw.stdout, source="registry manifest")
        manifest_media_type = top_manifest.get("mediaType")
        media_type = (
            manifest_media_type
            if isinstance(manifest_media_type, str)
            else metadata_media_type
        )
        if metadata_media_type and media_type and metadata_media_type != media_type:
            raise BuildOnceError(
                "ARTIFACT_DIGEST_MISMATCH",
                "Buildx descriptor media type differs from the registry manifest",
            )
        platforms = _platform_descriptors(
            repository=request.repository,
            top_digest=digest,
            top_manifest=top_manifest,
            requested_platforms=request.platforms,
            runner=self.runner,
            cwd=project,
            environment=environment,
        )
        if len(platforms) == 1 and platforms[0].digest == digest:
            config_digest = platforms[0].config_digest
        return BuildResult(
            repository=request.repository,
            tag=request.tag,
            digest=digest,
            media_type=media_type,
            size=metadata_size or len(raw.stdout),
            config_digest=config_digest,
            platforms=platforms,
            build_invocation_count=guard.count,
            build_metadata_path=request.metadata_path,
            command=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def verify_tag_unchanged(
        self,
        result: BuildResult,
        *,
        project: Path,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        raw = self.runner.run(
            (
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                "--raw",
                result.tagged_reference,
            ),
            cwd=project,
            environment=environment,
            timeout=120,
        )
        if raw.returncode != 0:
            raise BuildOnceError("REGISTRY_UNREACHABLE", "cannot recheck the registry tag")
        current = _sha256(raw.stdout)
        if current != result.digest:
            raise BuildOnceError(
                "REGISTRY_TAG_MOVED",
                f"tag now resolves to {current}, expected {result.digest}",
            )
