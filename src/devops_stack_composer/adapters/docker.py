"""Docker build-template projection and isolated upstream validation."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from devops_stack_composer.adapters.base import (
    AdapterDiagnostic,
    AdapterResult,
    GeneratedArtifact,
)
from devops_stack_composer.archives import extract_locked_source
from devops_stack_composer.errors import SourceResolutionError
from devops_stack_composer.model import IMAGE_TAG_PLACEHOLDER, NormalizedDevOpsModel
from devops_stack_composer.sources import SourceResolution


ADAPTER_VERSION = "1.0.0"

PASSED = "PASSED"
FAILED = "FAILED"
SKIPPED_MISSING_OPTIONAL_TOOL = "SKIPPED_MISSING_OPTIONAL_TOOL"
BLOCKED_MISSING_REQUIRED_TOOL = "BLOCKED_MISSING_REQUIRED_TOOL"

UPSTREAM_IMAGE_ENV_KEYS = (
    "REGISTRY",
    "IMAGE_NAME",
    "IMAGE_TAG",
    "CONTEXT",
    "DOCKERFILE",
    "PLATFORMS",
    "PUSH",
    "SBOM",
    "PROVENANCE",
    "OCI_TITLE",
    "OCI_DESCRIPTION",
    "OCI_SOURCE",
    "OCI_REVISION",
    "OCI_CREATED",
    "OCI_LICENSES",
)

UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS = (
    ".git",
    ".devops-stack",
    "config/*.env",
    "config/image.env",
    ".env",
    ".env.*",
    ".codex",
    "AGENTS.md",
    "docs/management",
    "out",
    "generated",
    "generated-preview",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".cache",
    ".npm",
    "*.log",
    "*.tar",
    "*.tar.gz",
    "*.oci",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
)

_CONTEXT_COPY_IGNORES = tuple(
    dict.fromkeys(
        (
            *UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS,
            ".gitignore",
            ".dockerignore",
            "Dockerfile*",
            "__pycache__",
            "*.pyc",
            "*.env",
        )
    )
)
_DOCKER_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "TMPDIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "BUILDX_BUILDER",
    "BUILDX_CONFIG",
    "XDG_RUNTIME_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


_IMAGE_PAIRS = {
    "nodejs": ("node:22-alpine", "node:22-alpine"),
    "python": ("python:3.12-slim", "python:3.12-slim"),
    "java": ("eclipse-temurin:21-jdk-jammy", "eclipse-temurin:21-jre-jammy"),
    "go": ("golang:1.23-alpine", "alpine:3.20"),
    "rust": ("rust:1.83-alpine", "alpine:3.20"),
    "static": ("node:22-alpine", "python:3.12-slim"),
}

_SAFE_IMAGE_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_OUTPUT_URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_OUTPUT_AUTHORIZATION = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*"
)
_OUTPUT_INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_OUTPUT_SECRET_FLAG = re.compile(
    r"(?ix)(--(?:password|passphrase|token|secret|private-key|access-key|api-key)(?:\s+|=))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_OUTPUT_CURL_USER = re.compile(
    r"(?i)(?<!\S)(?P<prefix>--user(?:\s+|=)|-u(?:\s+|=)|"
    r"-u(?=[^\s;]*:))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;]+)"
)


def _sanitize_command_output(value: str | None) -> str:
    if not isinstance(value, str):
        return ""
    sanitized = _OUTPUT_URL_USERINFO.sub(r"\1<redacted>@", value)
    sanitized = _OUTPUT_AUTHORIZATION.sub(r"\1<redacted>", sanitized)
    sanitized = _OUTPUT_INLINE_SECRET.sub(r"\1<redacted>", sanitized)
    sanitized = _OUTPUT_SECRET_FLAG.sub(r"\1<redacted>", sanitized)
    sanitized = _OUTPUT_CURL_USER.sub(r"\g<prefix><redacted>", sanitized)
    return sanitized.strip()[-4000:]


class DockerBuildAdapter:
    """Render Docker assets and invoke the locked template without modifying it."""

    def __init__(
        self,
        source: SourceResolution,
        *,
        command_runner: CommandRunner | None = None,
    ):
        if source.key != "docker":
            raise ValueError(f"DockerBuildAdapter requires a docker source, received {source.key}")
        self.source = source
        self._command_runner = command_runner or subprocess.run

    def render(
        self,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path | None = None,
        validate_upstream: bool = False,
    ) -> AdapterResult:
        """Return deterministic generated files without invoking external tools."""

        dockerfile, dockerfile_origin, runtime_diagnostic = self._dockerfile(
            model,
            project_root=project_root,
        )
        artifacts = (
            GeneratedArtifact(
                path="docker/Dockerfile",
                content=dockerfile,
                origins=(dockerfile_origin, "docker-build-template:dockerfile-contract"),
            ),
            GeneratedArtifact(
                path="docker/Dockerfile.dockerignore",
                content=self._dockerignore(),
                origins=(
                    "docker-build-template:.dockerignore-contract",
                    "docker:dockerfile-specific-ignore-contract",
                ),
            ),
            GeneratedArtifact(
                path="docker/image.env",
                content=self._image_env(model),
                origins=("docker-build-template:config/image.env.example",),
            ),
            GeneratedArtifact(
                path="docker/build.sh",
                content=self._build_script(model),
                mode=0o755,
                origins=("docker-build-template:scripts/build-image.sh",),
            ),
            GeneratedArtifact(
                path="docker/metadata.json",
                content=self._metadata(model),
                origins=("normalized-devops-model", "templates.lock.json:docker"),
            ),
        )
        cache = model.build.get("cache", {})
        diagnostics: list[AdapterDiagnostic] = [
            AdapterDiagnostic(
                status=PASSED,
                check="docker-render",
                message="Rendered deterministic Docker adapter artifacts.",
                details={"artifactCount": len(artifacts)},
            ),
            AdapterDiagnostic(
                status=PASSED,
                check="docker-upstream-capabilities",
                message=(
                    "Upstream OCI metadata, platforms, SBOM, and provenance controls "
                    "are represented without extending its official 15-key contract."
                ),
                details={
                    "scanWired": False,
                },
            ),
        ]
        if runtime_diagnostic is not None:
            diagnostics.append(runtime_diagnostic)
        cache_requested = bool(
            cache.get("enabled") or cache.get("from") or cache.get("to")
        )
        if cache_requested:
            diagnostics.append(
                AdapterDiagnostic(
                    status=FAILED,
                    check="docker-cache-capability",
                    message=(
                        "Cache from/to was requested, but docker-build-template has no "
                        "official cache input; no cache flags were emitted."
                    ),
                    details={
                        "cacheRequested": cache_requested,
                        "cacheFrom": list(cache.get("from", [])),
                        "cacheTo": list(cache.get("to", [])),
                        "cacheWired": False,
                    },
                )
            )
        result = AdapterResult(
            adapter="docker",
            adapter_version=ADAPTER_VERSION,
            template_commit=self.source.commit or "unknown",
            artifacts=artifacts,
            contract=model.contract(),
            diagnostics=tuple(diagnostics),
        )
        if validate_upstream:
            if project_root is None:
                raise ValueError("project_root is required when validate_upstream is true")
            return self._validate_and_optionally_build(
                result,
                model,
                project_root=project_root,
                local_build=False,
                image_tag=None,
            )
        return result

    def generate(
        self,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path,
        validate_upstream: bool = True,
        local_build: bool = False,
        image_tag: str | None = None,
    ) -> AdapterResult:
        """Render, validate through the official template, and optionally build locally."""

        result = self.render(model, project_root=project_root)
        if not validate_upstream and not local_build:
            return result
        return self._validate_and_optionally_build(
            result,
            model,
            project_root=project_root,
            local_build=local_build,
            image_tag=image_tag,
        )

    def _dockerfile(
        self,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path | None,
    ) -> tuple[str, str, AdapterDiagnostic | None]:
        if model.dockerfile_strategy == "generated":
            return self._generated_dockerfile(model), "normalized-devops-model", None
        if model.dockerfile_strategy != "existing":
            raise ValueError(f"unsupported Dockerfile strategy: {model.dockerfile_strategy}")
        if project_root is None or model.dockerfile_path is None:
            raise ValueError(
                "project_root and dockerfile_path are required for existing Dockerfiles"
            )
        application_root = self._resolve_within(
            project_root,
            Path(project_root) / model.application_root,
            label="application root",
            expect_directory=True,
        )
        dockerfile_path = self._resolve_within(
            application_root,
            application_root / model.dockerfile_path,
            label="existing Dockerfile",
            expect_directory=False,
        )
        content = dockerfile_path.read_text(encoding="utf-8")
        return (
            content,
            f"application:{model.dockerfile_path}",
            self._existing_runtime_diagnostic(content, model),
        )

    @staticmethod
    def _existing_runtime_diagnostic(
        dockerfile: str,
        model: NormalizedDevOpsModel,
    ) -> AdapterDiagnostic:
        lines = dockerfile.splitlines()
        final_from = -1
        for index, line in enumerate(lines):
            if re.match(r"^\s*FROM(?:\s|$)", line, re.IGNORECASE):
                final_from = index
        runtime_users = []
        for line in lines[final_from + 1 :]:
            match = re.match(r"^\s*USER\s+([^\s#]+)", line, re.IGNORECASE)
            if match:
                runtime_users.append(match.group(1))

        expected_user = str(model.runtime_user)
        actual_user = runtime_users[-1] if runtime_users else None
        verified = (
            model.runtime_user > 0
            and actual_user is not None
            and (
                actual_user == expected_user
                or actual_user.startswith(f"{expected_user}:")
            )
        )
        if verified:
            return AdapterDiagnostic(
                status=PASSED,
                check="docker-existing-runtime-user",
                message="Existing Dockerfile final stage uses the normalized non-root UID.",
                details={"runtimeUser": actual_user},
            )
        return AdapterDiagnostic(
            status=FAILED,
            check="docker-existing-runtime-user",
            message=(
                "Existing Dockerfile non-root runtime identity is unverified; its final "
                f"stage must declare USER {expected_user} or {expected_user}:<gid>."
            ),
            details={"runtimeUser": actual_user, "expectedUid": model.runtime_user},
        )

    def _generated_dockerfile(self, model: NormalizedDevOpsModel) -> str:
        try:
            builder_image, runtime_image = _IMAGE_PAIRS[model.application_type]
        except KeyError as exc:
            raise ValueError(
                f"unsupported application type for Docker generation: {model.application_type}"
            ) from exc

        build_steps: list[str] = []
        if model.application_type == "python":
            build_steps.append(
                "if [ -f requirements.txt ]; then "
                "python -m pip install --no-cache-dir -r requirements.txt; fi"
            )
        elif model.application_type in {"nodejs", "static"}:
            build_steps.append(
                "if [ -f package-lock.json ]; then npm ci; "
                "elif [ -f package.json ]; then npm install; fi"
            )
        build_steps.append(model.build_command)

        if not model.build.get("multiStage"):
            lines = [
                "# Generated by DevOps Stack Composer. Do not place secrets in build arguments.",
                f"ARG RUNTIME_IMAGE={builder_image}",
                "FROM ${RUNTIME_IMAGE} AS runtime",
                *self._oci_metadata_lines(),
                "WORKDIR /app",
                f"COPY --chown={model.runtime_user}:{model.runtime_user} . /app",
            ]
            lines.extend(self._json_run(command) for command in build_steps)
            lines.extend(self._runtime_lines(model))
            return "\n".join(lines)

        lines = [
            "# Generated by DevOps Stack Composer. Do not place secrets in build arguments.",
            f"ARG BUILDER_IMAGE={builder_image}",
            f"ARG RUNTIME_IMAGE={runtime_image}",
            "FROM ${BUILDER_IMAGE} AS build",
            "WORKDIR /workspace",
            "COPY . .",
        ]
        lines.extend(self._json_run(command) for command in build_steps)
        lines.extend(
            [
                "",
                "FROM ${RUNTIME_IMAGE} AS runtime",
                *self._oci_metadata_lines(),
                "WORKDIR /app",
            ]
        )
        if model.application_type == "python":
            lines.append("COPY --from=build /usr/local /usr/local")
        lines.append(
            "COPY --from=build "
            f"--chown={model.runtime_user}:{model.runtime_user} /workspace /app"
        )
        lines.extend(self._runtime_lines(model))
        return "\n".join(lines)

    @staticmethod
    def _oci_metadata_lines() -> list[str]:
        return [
            'ARG OCI_TITLE="Application"',
            'ARG OCI_DESCRIPTION="Generated application image"',
            'ARG OCI_SOURCE="unknown"',
            'ARG OCI_REVISION="unknown"',
            'ARG OCI_CREATED="1970-01-01T00:00:00Z"',
            'ARG OCI_LICENSES="NOASSERTION"',
            'LABEL org.opencontainers.image.title="${OCI_TITLE}" \\',
            '      org.opencontainers.image.description="${OCI_DESCRIPTION}" \\',
            '      org.opencontainers.image.source="${OCI_SOURCE}" \\',
            '      org.opencontainers.image.revision="${OCI_REVISION}" \\',
            '      org.opencontainers.image.created="${OCI_CREATED}" \\',
            '      org.opencontainers.image.licenses="${OCI_LICENSES}"',
        ]

    @staticmethod
    def _runtime_lines(model: NormalizedDevOpsModel) -> list[str]:
        return [
            f"USER {model.runtime_user}:{model.runtime_user}",
            f"EXPOSE {model.environments[0].container_port}",
            f"CMD {json.dumps(['sh', '-c', model.run_command], separators=(',', ':'))}",
            "",
        ]

    @staticmethod
    def _json_run(command: str) -> str:
        return f"RUN {json.dumps(['sh', '-c', command], separators=(',', ':'))}"

    @staticmethod
    def _dockerignore() -> str:
        extra = (
            ".gitignore",
            ".dockerignore",
            "Dockerfile*",
            "docker-bake.hcl",
            "docker/build.sh",
            "docker/image.env",
            "docker/metadata.json",
            "*.swp",
            ".DS_Store",
        )
        return "\n".join((*UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS, *extra)) + "\n"

    def _image_env_values(self, model: NormalizedDevOpsModel) -> dict[str, str]:
        sbom_enabled = bool(model.supply_chain.get("sbom", {}).get("enabled"))
        provenance = model.supply_chain.get("provenance", {})
        provenance_value = (
            f"mode={provenance.get('mode', 'min')}"
            if provenance.get("enabled")
            else "false"
        )
        return {
            "REGISTRY": f"{model.image_registry}/",
            "IMAGE_NAME": model.image_repository,
            "IMAGE_TAG": model.image_tag,
            "CONTEXT": "application",
            "DOCKERFILE": "generated/docker/Dockerfile",
            "PLATFORMS": ",".join(model.architectures),
            "PUSH": "false",
            "SBOM": "true" if sbom_enabled else "false",
            "PROVENANCE": provenance_value,
            "OCI_TITLE": model.application_name,
            "OCI_DESCRIPTION": f"{model.service_name} application image",
            "OCI_SOURCE": "unknown",
            "OCI_REVISION": "unknown",
            "OCI_CREATED": "1970-01-01T00:00:00Z",
            "OCI_LICENSES": "NOASSERTION",
        }

    def _image_env(self, model: NormalizedDevOpsModel) -> str:
        values = self._image_env_values(model)
        return "\n".join(f"{key}={values[key]}" for key in UPSTREAM_IMAGE_ENV_KEYS) + "\n"

    def _build_script(self, model: NormalizedDevOpsModel) -> str:
        relative_context = PurePosixPath(model.application_root) / model.build_context
        context_value = shlex.quote(relative_context.as_posix())
        cache = model.build.get("cache", {})
        cache_requested = bool(cache.get("enabled") or cache.get("from") or cache.get("to"))
        expected_template_commit = shlex.quote(self.source.commit or "")
        return f"""#!/usr/bin/env sh
set -eu

MODE=${{1:---validate}}
if [ "$#" -gt 1 ]; then
  printf '%s\n' "Usage: $0 [--validate|--load|--push]" >&2
  exit 2
fi
case "$MODE" in
  --validate|--load|--push) ;;
  *)
    printf '%s\n' "Usage: $0 [--validate|--load|--push]" >&2
    exit 2
    ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)
TEMPLATE_ROOT=${{DEVOPS_STACK_DOCKER_TEMPLATE:-}}
CONTEXT_RELATIVE={context_value}
EXPECTED_TEMPLATE_COMMIT={expected_template_commit}

if [ -z "$TEMPLATE_ROOT" ] || [ ! -f "$TEMPLATE_ROOT/scripts/build-image.sh" ]; then
  printf '%s\n' "Set DEVOPS_STACK_DOCKER_TEMPLATE to a resolved docker-build-template checkout" >&2
  exit 2
fi

if [ -L "$TEMPLATE_ROOT" ]; then
  printf '%s\n' "Docker template source must not be a symlink: $TEMPLATE_ROOT" >&2
  exit 2
fi
TEMPLATE_ROOT=$(CDPATH= cd -- "$TEMPLATE_ROOT" && pwd -P)
PROJECT_ROOT=$(CDPATH= cd -- "$PROJECT_ROOT" && pwd -P)
CONTEXT_PATH=$(CDPATH= cd -- "$PROJECT_ROOT/$CONTEXT_RELATIVE" && pwd -P)

case "$CONTEXT_PATH" in
  "$PROJECT_ROOT"|"$PROJECT_ROOT"/*) ;;
  *)
    printf '%s\n' "Docker build context must stay inside project root" >&2
    exit 2
    ;;
esac

if find "$TEMPLATE_ROOT" -type l -print -quit | grep . >/dev/null; then
  printf '%s\n' "Docker template source must not contain symlinks" >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
  printf '%s\n' "git and tar are required to stage the locked Docker template" >&2
  exit 2
fi
ACTUAL_TEMPLATE_COMMIT=$(git -C "$TEMPLATE_ROOT" rev-parse HEAD 2>/dev/null || true)
if [ -z "$EXPECTED_TEMPLATE_COMMIT" ] || [ "$ACTUAL_TEMPLATE_COMMIT" != "$EXPECTED_TEMPLATE_COMMIT" ]; then
  printf '%s\n' "Docker template checkout does not match the generated lock commit" >&2
  exit 2
fi
if git -C "$TEMPLATE_ROOT" ls-tree -r "$EXPECTED_TEMPLATE_COMMIT" | grep '^120000 ' >/dev/null; then
  printf '%s\n' "Locked Docker template commit must not contain symlinks" >&2
  exit 2
fi
if find "$CONTEXT_PATH" -type l -print -quit | grep . >/dev/null; then
  printf '%s\n' "Docker build context must not contain symlinks" >&2
  exit 2
fi

RESOLVED_IMAGE_TAG=${{IMAGE_TAG:-}}
case "$MODE" in
  --load|--push)
    case "$RESOLVED_IMAGE_TAG" in
      ''|'{IMAGE_TAG_PLACEHOLDER}'|.*|-*|*[!A-Za-z0-9_.-]*)
        printf '%s\n' "Set IMAGE_TAG to a concrete Docker tag before $MODE" >&2
        exit 2
        ;;
    esac
    if [ "${{#RESOLVED_IMAGE_TAG}}" -gt 128 ]; then
      printf '%s\n' "IMAGE_TAG must be 128 characters or fewer" >&2
      exit 2
    fi
    if [ "{str(cache_requested).lower()}" = "true" ]; then
      printf '%s\n' "Requested cache wiring is unsupported by docker-build-template" >&2
      exit 2
    fi
    ;;
esac

if [ "$MODE" = "--load" ] && [ {len(model.architectures)} -ne 1 ]; then
  printf '%s\n' "Local --load requires exactly one platform; use --push for multi-platform output" >&2
  exit 2
fi

STAGE_PARENT=$(mktemp -d "${{TMPDIR:-/tmp}}/devops-stack-docker.XXXXXX")
STAGE_PARENT=$(CDPATH= cd -- "$STAGE_PARENT" && pwd -P)
TEMPLATE_STAGE="$STAGE_PARENT/template"
TEMPLATE_ARCHIVE="$STAGE_PARENT/template.tar"
APPLICATION_STAGE="$TEMPLATE_STAGE/application"
cleanup() {{
  rm -rf "$STAGE_PARENT"
}}
trap cleanup EXIT HUP INT TERM

for destination in "$TEMPLATE_STAGE" "$APPLICATION_STAGE" \
  "$TEMPLATE_STAGE/generated/docker/Dockerfile" \
  "$TEMPLATE_STAGE/generated/docker/Dockerfile.dockerignore" \
  "$TEMPLATE_STAGE/generated/docker/image.env" \
  "$TEMPLATE_STAGE/generated/docker/build.sh" \
  "$TEMPLATE_STAGE/generated/docker/metadata.json"; do
  case "$destination" in
    "$STAGE_PARENT"/*) ;;
    *)
      printf '%s\n' "Refusing stage destination outside temporary root" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$TEMPLATE_STAGE"
git -C "$TEMPLATE_ROOT" archive --format=tar \
  --output="$TEMPLATE_ARCHIVE" "$EXPECTED_TEMPLATE_COMMIT"
tar -xf "$TEMPLATE_ARCHIVE" -C "$TEMPLATE_STAGE"
mkdir -p "$APPLICATION_STAGE"
tar -C "$CONTEXT_PATH" \
  --exclude='./generated' \
  --exclude='./generated/*' \
  --exclude='./generated-preview' \
  --exclude='./generated-preview/*' \
  --exclude='./.devops-stack' \
  --exclude='./.devops-stack/*' \
  -cf - . | tar -xf - -C "$APPLICATION_STAGE"
mkdir -p "$TEMPLATE_STAGE/generated/docker" "$TEMPLATE_STAGE/out"
cp "$SCRIPT_DIR/Dockerfile" "$TEMPLATE_STAGE/generated/docker/Dockerfile"
cp "$SCRIPT_DIR/Dockerfile.dockerignore" \
  "$TEMPLATE_STAGE/generated/docker/Dockerfile.dockerignore"
# The upstream validator currently checks the context-root file. Keep this exact
# mirror only in the ephemeral stage; Docker consumes Dockerfile.dockerignore.
cp "$SCRIPT_DIR/Dockerfile.dockerignore" "$APPLICATION_STAGE/.dockerignore"
cp "$SCRIPT_DIR/image.env" "$TEMPLATE_STAGE/generated/docker/image.env"
cp "$SCRIPT_DIR/build.sh" "$TEMPLATE_STAGE/generated/docker/build.sh"
cp "$SCRIPT_DIR/metadata.json" "$TEMPLATE_STAGE/generated/docker/metadata.json"

set -- env -i \
  "PATH=${{PATH:-/usr/bin:/bin}}" \
  "HOME=${{HOME:-/tmp}}" \
  "CONFIG_FILE=$TEMPLATE_STAGE/generated/docker/image.env" \
  "BAKE_PLAN_OUTPUT=$TEMPLATE_STAGE/out/docker-bake-plan.json" \
  "PUSH=false"

[ -z "$RESOLVED_IMAGE_TAG" ] || set -- "$@" "IMAGE_TAG=$RESOLVED_IMAGE_TAG"
[ -z "${{OCI_REVISION:-}}" ] || set -- "$@" "OCI_REVISION=$OCI_REVISION"
[ -z "${{OCI_CREATED:-}}" ] || set -- "$@" "OCI_CREATED=$OCI_CREATED"
[ -z "${{DOCKER_HOST:-}}" ] || set -- "$@" "DOCKER_HOST=$DOCKER_HOST"
[ -z "${{DOCKER_CONTEXT:-}}" ] || set -- "$@" "DOCKER_CONTEXT=$DOCKER_CONTEXT"
[ -z "${{DOCKER_CONFIG:-}}" ] || set -- "$@" "DOCKER_CONFIG=$DOCKER_CONFIG"
[ -z "${{BUILDX_BUILDER:-}}" ] || set -- "$@" "BUILDX_BUILDER=$BUILDX_BUILDER"
[ -z "${{BUILDX_CONFIG:-}}" ] || set -- "$@" "BUILDX_CONFIG=$BUILDX_CONFIG"
[ -z "${{XDG_RUNTIME_DIR:-}}" ] || set -- "$@" "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"

# A Docker --load result cannot carry registry attestations. Keep the configured
# SBOM/provenance values for validation and push, but disable attestations only for
# this local image load; Jenkins runs its local Syft/Trivy checks afterwards.
if [ "$MODE" = "--load" ]; then
  set -- "$@" "SBOM=false" "PROVENANCE=false"
fi

case "$MODE" in
  --validate)
    (cd "$TEMPLATE_STAGE" && "$@" sh scripts/validate-build-plan.sh)
    ;;
  --load)
    (cd "$TEMPLATE_STAGE" && "$@" sh scripts/validate-build-plan.sh)
    (cd "$TEMPLATE_STAGE" && "$@" sh scripts/build-image.sh)
    ;;
  --push)
    (cd "$TEMPLATE_STAGE" && "$@" sh scripts/push-image.sh)
    ;;
esac
"""

    def _metadata(self, model: NormalizedDevOpsModel) -> str:
        cache = model.build.get("cache", {})
        cache_requested = bool(
            cache.get("enabled") or cache.get("from") or cache.get("to")
        )
        sbom = model.supply_chain.get("sbom", {})
        provenance = model.supply_chain.get("provenance", {})
        scan = model.supply_chain.get("scan", {})
        value: dict[str, Any] = {
            "adapterVersion": ADAPTER_VERSION,
            "applicationType": model.application_type,
            "build": {
                "artifact": model.build_artifact,
                "context": model.build_context,
                "dockerfileStrategy": model.dockerfile_strategy,
                "ignoreFile": "docker/Dockerfile.dockerignore",
                "upstreamValidationIgnoreMirror": "application/.dockerignore (ephemeral only)",
                "multiStage": bool(model.build.get("multiStage")),
                "reproducibility": {
                    "requested": bool(model.build.get("reproducible")),
                    "upstreamGuarantee": "deterministic-metadata-only",
                },
            },
            "capabilities": {
                "cache": {
                    "requested": cache_requested,
                    "from": list(cache.get("from", [])),
                    "to": list(cache.get("to", [])),
                    "supportedByUpstream": False,
                    "wired": False,
                },
                "ociLabels": {"supportedByUpstream": True, "wired": True},
                "provenance": {
                    "requested": bool(provenance.get("enabled")),
                    "mode": provenance.get("mode"),
                    "supportedByUpstream": True,
                    "wired": True,
                },
                "sbom": {
                    "format": sbom.get("format"),
                    "formatConfigurableUpstream": False,
                    "requested": bool(sbom.get("enabled")),
                    "supportedByUpstream": True,
                    "wired": True,
                },
                "scan": {
                    "requested": bool(scan.get("enabled")),
                    "supportedByUpstream": False,
                    "wired": False,
                },
            },
            "image": {
                "architectures": list(model.architectures),
                "reference": model.image_reference,
                "tag": model.image_tag,
                "tagExpression": model.image_tag_expression,
                "tagStrategy": model.image_tag_strategy,
            },
            "runtime": {
                "containerPort": model.environments[0].container_port,
                "runAsNonRoot": bool(model.security.get("runAsNonRoot")),
                "user": model.runtime_user,
            },
                "scriptModes": {
                    "default": "--validate",
                    "load": (
                        "single-platform, explicit IMAGE_TAG, registry attestations disabled"
                    ),
                "push": "official scripts/push-image.sh, explicit IMAGE_TAG",
                "validate": "official scripts/validate-build-plan.sh",
            },
            "template": {
                "commit": self.source.commit,
                "matchesLock": self.source.matches_lock,
                "schemaVersion": "docker-env-v1",
            },
        }
        return json.dumps(value, indent=2, sort_keys=True) + "\n"

    def _validate_and_optionally_build(
        self,
        result: AdapterResult,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path,
        local_build: bool,
        image_tag: str | None,
    ) -> AdapterResult:
        if not self.source.matches_lock:
            diagnostic = AdapterDiagnostic(
                status=FAILED,
                check="docker-template-lock",
                message="Resolved Docker template commit does not match the lock file.",
                details={"resolvedCommit": self.source.commit},
            )
            return replace(result, diagnostics=(*result.diagnostics, diagnostic))

        tag_diagnostic = self._resolved_tag_diagnostic(
            image_tag,
            required=local_build,
        )
        if tag_diagnostic is not None and tag_diagnostic.status != PASSED:
            return replace(result, diagnostics=(*result.diagnostics, tag_diagnostic))

        try:
            context = self._application_context(project_root, model)
        except (OSError, ValueError) as exc:
            diagnostic = AdapterDiagnostic(
                status=FAILED,
                check="docker-application-context",
                message=str(exc),
            )
            return replace(result, diagnostics=(*result.diagnostics, diagnostic))

        diagnostics: list[AdapterDiagnostic] = []
        try:
            with tempfile.TemporaryDirectory(prefix="devops-stack-docker-") as directory:
                stage_parent = Path(directory).resolve(strict=True)
                stage = self._safe_stage_destination(stage_parent, "template")
                extract_locked_source(self.source, stage)
                diagnostics.append(
                    AdapterDiagnostic(
                        status=PASSED,
                        check="docker-template-archive",
                        message=(
                            "Upstream validation uses archived bytes from the locked "
                            "Git commit."
                        ),
                        details={"commit": self.source.commit},
                    )
                )
                validate_script = stage / "scripts" / "validate-build-plan.sh"
                if not validate_script.is_file():
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=BLOCKED_MISSING_REQUIRED_TOOL,
                            check="docker-template-validation",
                            message=(
                                "Required upstream validator is missing from the locked "
                                "Docker template commit."
                            ),
                        )
                    )
                    return replace(
                        result,
                        diagnostics=(*result.diagnostics, *diagnostics),
                    )
                staged_context = self._safe_stage_destination(stage, "application")
                shutil.copytree(
                    context,
                    staged_context,
                    symlinks=True,
                    ignore=shutil.ignore_patterns(*_CONTEXT_COPY_IGNORES),
                )
                self._overlay_stage(stage, staged_context, result)
                environment = self._minimal_environment(stage, image_tag=image_tag)
                validate_command = ("sh", "scripts/validate-build-plan.sh")
                validation = self._invoke(validate_command, cwd=stage, environment=environment)
                diagnostics.append(
                    self._command_diagnostic(
                        validation,
                        check="docker-template-validation",
                        command=validate_command,
                        optional_tool=False,
                        success_message="Official Docker template no-push validation passed.",
                    )
                )
                if validation.returncode != 0:
                    return replace(result, diagnostics=(*result.diagnostics, *diagnostics))

                if local_build:
                    execution_blockers = [
                        diagnostic
                        for diagnostic in result.diagnostics
                        if diagnostic.status == FAILED
                        and diagnostic.check
                        in {"docker-cache-capability", "docker-existing-runtime-user"}
                    ]
                    if execution_blockers:
                        diagnostics.append(
                            AdapterDiagnostic(
                                status=FAILED,
                                check="docker-local-build",
                                message=(
                                    "Local build was not started because Docker adapter "
                                    "capability checks failed."
                                ),
                                details={
                                    "blockingChecks": [
                                        diagnostic.check for diagnostic in execution_blockers
                                    ]
                                },
                            )
                        )
                    elif len(model.architectures) != 1:
                        diagnostics.append(
                            AdapterDiagnostic(
                                status=FAILED,
                                check="docker-local-build",
                                message=(
                                    "Local --load builds require exactly one platform; "
                                    "multi-platform output is reserved for the validated push path."
                                ),
                                details={"platforms": list(model.architectures)},
                            )
                        )
                    else:
                        build_script = stage / "scripts" / "build-image.sh"
                        if not build_script.is_file():
                            diagnostics.append(
                                AdapterDiagnostic(
                                    status=BLOCKED_MISSING_REQUIRED_TOOL,
                                    check="docker-local-build",
                                    message=(
                                        "Required upstream build script is missing: "
                                        f"{build_script}"
                                    ),
                                )
                            )
                        else:
                            build_command = ("sh", "scripts/build-image.sh")
                            build_environment = {
                                **environment,
                                "SBOM": "false",
                                "PROVENANCE": "false",
                            }
                            build = self._invoke(
                                build_command,
                                cwd=stage,
                                environment=build_environment,
                                timeout=300,
                            )
                            diagnostics.append(
                                self._command_diagnostic(
                                    build,
                                    check="docker-local-build",
                                    command=build_command,
                                    optional_tool=True,
                                    success_message=(
                                        "Optional single-platform local Docker build passed; "
                                        "registry attestations remain reserved for push."
                                    ),
                                )
                            )
        except (
            OSError,
            SourceResolutionError,
            ValueError,
            shutil.Error,
            subprocess.TimeoutExpired,
        ) as exc:
            diagnostics.append(
                AdapterDiagnostic(
                    status=FAILED,
                    check="docker-template-staging",
                    message=f"Docker template staging or invocation failed: {exc}",
                )
            )
        return replace(result, diagnostics=(*result.diagnostics, *diagnostics))

    @staticmethod
    def _resolved_tag_diagnostic(
        image_tag: str | None,
        *,
        required: bool,
    ) -> AdapterDiagnostic | None:
        if image_tag is None and not required:
            return None
        if (
            image_tag is None
            or image_tag == IMAGE_TAG_PLACEHOLDER
            or not _SAFE_IMAGE_TAG.fullmatch(image_tag)
        ):
            return AdapterDiagnostic(
                status=FAILED,
                check="docker-image-tag",
                message=(
                    "A concrete Docker-safe image_tag is required before any local "
                    "build; placeholders are validation-only."
                ),
                details={"placeholderRejected": image_tag == IMAGE_TAG_PLACEHOLDER},
            )
        return AdapterDiagnostic(
            status=PASSED,
            check="docker-image-tag",
            message="Resolved image tag is safe for executable Docker operations.",
            details={"imageTag": image_tag},
        )

    def _application_context(
        self,
        project_root: Path,
        model: NormalizedDevOpsModel,
    ) -> Path:
        root = Path(project_root).resolve(strict=True)
        application_root = self._resolve_within(
            root,
            root / model.application_root,
            label="application root",
            expect_directory=True,
        )
        context = self._resolve_within(
            application_root,
            application_root / model.build_context,
            label="Docker build context",
            expect_directory=True,
        )
        for entry in context.rglob("*"):
            if entry.is_symlink():
                raise ValueError(
                    f"Docker build context must not contain symlinks: {entry}"
                )
        return context

    @staticmethod
    def _safe_stage_destination(stage_root: Path, relative: str) -> Path:
        root = Path(stage_root).resolve(strict=True)
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"unsafe Docker stage destination: {relative}")
        candidate = root / relative_path
        current = root
        for part in relative_path.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"Docker stage destination crosses a symlink: {current}")
            if current.exists():
                try:
                    current.resolve(strict=True).relative_to(root)
                except ValueError as exc:
                    raise ValueError(
                        f"Docker stage destination leaves temporary root: {current}"
                    ) from exc
        return candidate

    @staticmethod
    def _resolve_within(
        root: Path,
        candidate: Path,
        *,
        label: str,
        expect_directory: bool,
    ) -> Path:
        resolved_root = Path(root).resolve(strict=True)
        resolved = Path(candidate).resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"{label} must stay inside {resolved_root}: {candidate}") from exc
        if expect_directory and not resolved.is_dir():
            raise ValueError(f"{label} is not a directory: {resolved}")
        if not expect_directory and not resolved.is_file():
            raise ValueError(f"{label} is not a file: {resolved}")
        return resolved

    @classmethod
    def _overlay_stage(
        cls,
        stage: Path,
        staged_context: Path,
        result: AdapterResult,
    ) -> None:
        dockerignore = result.artifact("docker/Dockerfile.dockerignore")
        for artifact in result.artifacts:
            destination = cls._safe_stage_destination(
                stage,
                f"generated/{artifact.path}",
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(artifact.content, encoding="utf-8")
            destination.chmod(artifact.mode)

        # docker-build-template validates the context-root ignore file. Mirror the
        # exact generated Dockerfile-specific file only inside the ephemeral stage.
        context_ignore_path = cls._safe_stage_destination(stage, "application/.dockerignore")
        if context_ignore_path.parent.resolve(strict=True) != staged_context.resolve(strict=True):
            raise ValueError("Docker context ignore destination does not match staged context")
        context_ignore_path.write_text(dockerignore.content, encoding="utf-8")
        context_ignore_path.chmod(dockerignore.mode)

        cls._safe_stage_destination(stage, "out").mkdir(exist_ok=True)

    @staticmethod
    def _minimal_environment(
        stage: Path,
        *,
        image_tag: str | None,
    ) -> dict[str, str]:
        environment = {
            key: os.environ[key]
            for key in _DOCKER_ENV_ALLOWLIST
            if key in os.environ and os.environ[key]
        }
        environment.setdefault("PATH", "/usr/bin:/bin")
        environment.setdefault("HOME", "/tmp")
        environment.update(
            {
                "LC_ALL": "C",
                "LANG": "C",
                "CONFIG_FILE": str(stage / "generated" / "docker" / "image.env"),
                "BAKE_PLAN_OUTPUT": str(stage / "out" / "docker-bake-plan.json"),
                "PUSH": "false",
            }
        )
        if image_tag is not None:
            environment["IMAGE_TAG"] = image_tag
        return environment

    def _invoke(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._command_runner(
                list(command),
                cwd=cwd,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(
                args=list(command),
                returncode=127,
                stdout="",
                stderr=str(exc),
            )

    @staticmethod
    def _command_diagnostic(
        result: subprocess.CompletedProcess[str],
        *,
        check: str,
        command: tuple[str, ...],
        optional_tool: bool,
        success_message: str,
    ) -> AdapterDiagnostic:
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        details = {
            "returnCode": result.returncode,
            "stdout": _sanitize_command_output(stdout),
            "stderr": _sanitize_command_output(stderr),
        }
        if result.returncode == 0:
            return AdapterDiagnostic(
                status=PASSED,
                check=check,
                message=success_message,
                command=command,
                details=details,
            )
        lowered_stderr = stderr.lower()
        missing_buildx = "buildx" in lowered_stderr and any(
            marker in lowered_stderr
            for marker in (
                "is not a docker command",
                "unknown command",
                "command not found",
                "not installed",
                "component is missing",
                "no such file or directory",
            )
        )
        missing_tool = (
            result.returncode == 127
            or "command not found" in lowered_stderr
            or "docker: not found" in lowered_stderr
            or missing_buildx
        )
        if missing_tool:
            status = (
                SKIPPED_MISSING_OPTIONAL_TOOL
                if optional_tool
                else BLOCKED_MISSING_REQUIRED_TOOL
            )
            message = "Docker tooling required by the upstream command is unavailable."
        else:
            status = FAILED
            message = "Upstream Docker template command failed."
        return AdapterDiagnostic(
            status=status,
            check=check,
            message=message,
            command=command,
            details=details,
        )


DockerAdapter = DockerBuildAdapter


__all__ = [
    "ADAPTER_VERSION",
    "BLOCKED_MISSING_REQUIRED_TOOL",
    "DockerAdapter",
    "DockerBuildAdapter",
    "FAILED",
    "PASSED",
    "SKIPPED_MISSING_OPTIONAL_TOOL",
    "UPSTREAM_IMAGE_ENV_KEYS",
    "UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS",
]
