"""Typed validation results and cross-template contract checks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import yaml

from devops_stack_composer.adapters.base import AdapterResult
from devops_stack_composer.model import NormalizedDevOpsModel


class ValidationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED_MISSING_OPTIONAL_TOOL = "SKIPPED_MISSING_OPTIONAL_TOOL"
    BLOCKED_MISSING_REQUIRED_TOOL = "BLOCKED_MISSING_REQUIRED_TOOL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: ValidationStatus
    message: str
    scope: str = "composer"
    command: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "check": self.check,
            "scope": self.scope,
            "status": self.status.value,
            "message": self.message,
        }
        if self.command:
            value["command"] = list(self.command)
        if self.details:
            value["details"] = self.details
        return value


@dataclass(frozen=True)
class ValidationReport:
    checks: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        return not any(
            check.status
            in {ValidationStatus.FAILED, ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL}
            for check in self.checks
        )

    @property
    def counts(self) -> dict[str, int]:
        return {
            status.value: sum(check.status == status for check in self.checks)
            for status in ValidationStatus
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "counts": self.counts,
            "checks": [check.to_dict() for check in self.checks],
        }


def merge_reports(*reports: ValidationReport) -> ValidationReport:
    return ValidationReport(tuple(check for report in reports for check in report.checks))


def adapter_diagnostic_report(results: Iterable[AdapterResult]) -> ValidationReport:
    checks: list[CheckResult] = []
    for result in results:
        for diagnostic in result.diagnostics:
            try:
                status = ValidationStatus(diagnostic.status)
            except ValueError:
                status = ValidationStatus.FAILED
                message = (
                    f"adapter returned unsupported status {diagnostic.status!r}: "
                    f"{diagnostic.message}"
                )
            else:
                message = diagnostic.message
            checks.append(
                CheckResult(
                    check=f"adapter.{result.adapter}.{diagnostic.check}",
                    status=status,
                    message=message,
                    scope=result.adapter,
                    command=diagnostic.command,
                    details=diagnostic.details,
                )
            )
    return ValidationReport(tuple(checks))


def _flatten(value: Any, prefix: str = "$") -> dict[str, Any]:
    if isinstance(value, dict):
        flattened: dict[str, Any] = {}
        for key in sorted(value):
            flattened.update(_flatten(value[key], f"{prefix}.{key}"))
        return flattened
    if isinstance(value, list):
        flattened = {}
        for index, item in enumerate(value):
            flattened.update(_flatten(item, f"{prefix}[{index}]"))
        if not value:
            flattened[prefix] = []
        return flattened
    return {prefix: value}


def _artifact_map(result: AdapterResult) -> dict[str, str]:
    return {artifact.path: artifact.content for artifact in result.artifacts}


def _closed_artifact_mismatches(
    result: AdapterResult,
    expected: dict[str, tuple[str | None, int, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    """Compare the complete generated path, content, and mode inventory."""

    mismatches: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for artifact in result.artifacts:
        counts[artifact.path] = counts.get(artifact.path, 0) + 1
    duplicates = sorted(path for path, count in counts.items() if count != 1)
    if duplicates:
        mismatches.append(
            {
                "path": f"{result.adapter}.artifacts.duplicates",
                "expected": [],
                "received": duplicates,
            }
        )
    actual = {artifact.path: artifact for artifact in result.artifacts}
    if set(actual) != set(expected):
        mismatches.append(
            {
                "path": f"{result.adapter}.artifacts.paths",
                "expected": sorted(expected),
                "received": sorted(actual),
            }
        )
    for path in sorted(set(actual) & set(expected)):
        artifact = actual[path]
        expected_content, expected_mode, expected_origins = expected[path]
        _mismatch(
            mismatches,
            f"{path}.mode",
            f"0{expected_mode:03o}",
            f"0{artifact.mode:03o}",
        )
        _mismatch(
            mismatches,
            f"{path}.origins",
            list(expected_origins),
            list(artifact.origins),
        )
        if expected_content is None:
            continue
        if artifact.content != expected_content:
            mismatches.append(
                {
                    "path": f"{path}.content",
                    "expected": hashlib.sha256(
                        expected_content.encode("utf-8")
                    ).hexdigest(),
                    "received": hashlib.sha256(
                        artifact.content.encode("utf-8")
                    ).hexdigest(),
                }
            )
    return mismatches


def _mismatch(
    values: list[dict[str, Any]],
    path: str,
    expected: Any,
    received: Any,
) -> None:
    if expected != received:
        values.append({"path": path, "expected": expected, "received": received})


def _groovy_literal(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return f"'{escaped}'"


_JENKINS_STAGE_LINE = re.compile(
    r"(?m)^[ \t]*stage\('([^'\r\n]+)'\)[ \t]*\{[ \t]*$"
)
_JENKINS_SHELL_LITERAL = re.compile(
    r"(?m)^[ \t]*sh[ \t]+('(?:\\.|[^'\\])*')[ \t]*$"
)
_GENERATED_IMAGE_PAIRS = {
    "nodejs": ("node:22-alpine", "node:22-alpine"),
    "python": ("python:3.12-slim", "python:3.12-slim"),
    "java": ("eclipse-temurin:21-jdk-jammy", "eclipse-temurin:21-jre-jammy"),
    "go": ("golang:1.23-alpine", "alpine:3.20"),
    "rust": ("rust:1.83-alpine", "alpine:3.20"),
    "static": ("node:22-alpine", "python:3.12-slim"),
}


def _jenkins_stage_blocks(content: str) -> dict[str, list[tuple[int, str]]]:
    matches = list(_JENKINS_STAGE_LINE.finditer(content))
    blocks: dict[str, list[tuple[int, str]]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
        blocks.setdefault(match.group(1), []).append(
            (match.start(), content[match.start() : end])
        )
    return blocks


def _jenkins_route_mismatch(
    block: str,
    branches: tuple[str, ...],
) -> tuple[bool, dict[str, Any]]:
    expected_lines = [
        f"branch pattern: {_groovy_literal(branch)}, comparator: 'GLOB'"
        for branch in branches
    ]
    actual_lines = [
        line.strip()
        for line in block.splitlines()
        if re.match(r"^[ \t]*branch\b", line)
    ]
    when_count = sum(
        bool(re.fullmatch(r"[ \t]*when[ \t]*\{[ \t]*", line))
        for line in block.splitlines()
    )
    any_of_count = sum(
        bool(re.fullmatch(r"[ \t]*anyOf[ \t]*\{[ \t]*", line))
        for line in block.splitlines()
    )
    disabled_count = sum(
        bool(
            re.fullmatch(
                r"[ \t]*expression[ \t]*\{[ \t]*return false[ \t]*\}[ \t]*",
                line,
            )
        )
        for line in block.splitlines()
    )
    shape_matches = (
        when_count == 1
        and (
            (bool(branches) and any_of_count == 1 and disabled_count == 0)
            or (not branches and any_of_count == 0 and disabled_count == 1)
        )
    )
    return actual_lines != expected_lines or not shape_matches, {
        "branches": actual_lines,
        "whenBlocks": when_count,
        "anyOfBlocks": any_of_count,
        "disabledExpressions": disabled_count,
    }


def _jenkins_scan_severities(fail_on: str) -> str:
    thresholds = {
        "low": "LOW,MEDIUM,HIGH,CRITICAL",
        "medium": "MEDIUM,HIGH,CRITICAL",
        "high": "HIGH,CRITICAL",
        "critical": "CRITICAL",
    }
    return thresholds.get(fail_on.lower(), fail_on.upper())


def _jenkins_deployment_render_script(
    model: NormalizedDevOpsModel,
    environment: Any,
) -> str:
    """Return the exact deployment transaction expected in an executable stage."""

    return f'''set -eu
case "${{IMAGE_REF:-}}" in
  "$IMAGE_REPOSITORY":*)
    image_tag=${{IMAGE_REF#"$IMAGE_REPOSITORY":}}
    ;;
  *)
    printf '%s\n' 'IMAGE_REF must use IMAGE_REPOSITORY and a concrete tag resolved by Jenkins' >&2
    exit 2
    ;;
esac
case "$image_tag" in
  ''|__IMAGE_TAG__|.*|-*|*[!A-Za-z0-9_.-]*)
    printf '%s\n' 'IMAGE_REF contains an invalid or unresolved Docker tag' >&2
    exit 2
    ;;
esac
if [ "${{#image_tag}}" -gt 128 ]; then
  printf '%s\n' 'IMAGE_REF tag must be 128 characters or fewer' >&2
  exit 2
fi
render_root=$(mktemp -d "${{TMPDIR:-/tmp}}/devops-stack-kustomize.XXXXXX")
cleanup() {{
  rm -rf "$render_root"
}}
trap cleanup EXIT HUP INT TERM
cp -R generated/k8s "$render_root/k8s"
overlay="$render_root/k8s/overlays/{environment.name}"
(
  cd "$overlay"
  kustomize edit set image "$IMAGE_REPOSITORY=$IMAGE_REF"
)
kustomize build "$overlay" > "$render_root/rendered.yaml"
if grep -F '__IMAGE_TAG__' "$render_root/rendered.yaml" >/dev/null; then
  printf '%s\n' 'Rendered Kubernetes manifests still contain an unresolved image tag' >&2
  exit 2
fi
set +e
apply_output=$(kubectl apply -f "$render_root/rendered.yaml")
apply_status=$?
set -e
printf '%s\n' "$apply_output" >&2
if printf '%s\n' "$apply_output" | grep -E '^deployment\.apps/{model.service_name} (created|configured)$' >/dev/null; then
  rollout_started=true
else
  rollout_started=false
fi
printf '%s|%s' "$rollout_started" "$apply_status"'''


def _docker_artifact_mismatches(
    model: NormalizedDevOpsModel,
    result: AdapterResult,
) -> list[dict[str, Any]]:
    artifact_objects = {artifact.path: artifact for artifact in result.artifacts}
    artifacts = _artifact_map(result)
    required = (
        "docker/image.env",
        "docker/metadata.json",
        "docker/Dockerfile",
        "docker/Dockerfile.dockerignore",
        "docker/build.sh",
    )
    missing = [path for path in required if path not in artifacts]
    mismatches: list[dict[str, Any]] = [
        {"path": path, "expected": "generated artifact", "received": None}
        for path in missing
    ]
    if missing:
        return mismatches
    from devops_stack_composer.adapters.docker import DockerBuildAdapter
    from devops_stack_composer.sources import SourceResolution

    expected_adapter = DockerBuildAdapter(
        SourceResolution(
            key="docker",
            path=Path("."),
            origin="artifact-contract",
            commit=result.template_commit,
            remote=None,
            matches_lock=True,
        )
    )
    if model.dockerfile_strategy == "generated":
        expected_inventory = {
            artifact.path: (
                artifact.content,
                artifact.mode,
                artifact.origins,
            )
            for artifact in expected_adapter.render(model).artifacts
        }
    else:
        expected_inventory = {
            "docker/Dockerfile": (
                None,
                0o644,
                (
                    f"application:{model.dockerfile_path}",
                    "docker-build-template:dockerfile-contract",
                ),
            ),
            "docker/Dockerfile.dockerignore": (
                expected_adapter._dockerignore(),
                0o644,
                (
                    "docker-build-template:.dockerignore-contract",
                    "docker:dockerfile-specific-ignore-contract",
                ),
            ),
            "docker/image.env": (
                expected_adapter._image_env(model),
                0o644,
                ("docker-build-template:config/image.env.example",),
            ),
            "docker/build.sh": (
                expected_adapter._build_script(model),
                0o755,
                ("docker-build-template:scripts/build-image.sh",),
            ),
            "docker/metadata.json": (
                expected_adapter._metadata(model),
                0o644,
                ("normalized-devops-model", "templates.lock.json:docker"),
            ),
        }
    mismatches.extend(
        _closed_artifact_mismatches(result, expected_inventory)
    )
    expected_wrapper = expected_adapter._build_script(model)
    expected_ignore = expected_adapter._dockerignore()
    for path, expected_content, expected_mode in (
        ("docker/build.sh", expected_wrapper, 0o755),
        ("docker/Dockerfile.dockerignore", expected_ignore, 0o644),
    ):
        artifact = artifact_objects[path]
        if artifact.content != expected_content:
            mismatches.append(
                {
                    "path": path,
                    "expected": hashlib.sha256(
                        expected_content.encode("utf-8")
                    ).hexdigest(),
                    "received": hashlib.sha256(
                        artifact.content.encode("utf-8")
                    ).hexdigest(),
                }
            )
        _mismatch(
            mismatches,
            f"{path}.mode",
            f"0{expected_mode:03o}",
            f"0{artifact.mode & 0o777:03o}",
        )
    environment: dict[str, str] = {}
    for line in artifacts["docker/image.env"].splitlines():
        key, separator, value = line.partition("=")
        if separator:
            environment[key] = value
    _mismatch(mismatches, "docker.image.registry", model.image_registry + "/", environment.get("REGISTRY"))
    _mismatch(mismatches, "docker.image.repository", model.image_repository, environment.get("IMAGE_NAME"))
    _mismatch(mismatches, "docker.image.tag", model.image_tag, environment.get("IMAGE_TAG"))
    _mismatch(
        mismatches,
        "docker.image.architectures",
        list(model.architectures),
        (environment.get("PLATFORMS") or "").split(","),
    )
    _mismatch(mismatches, "docker.application.name", model.application_name, environment.get("OCI_TITLE"))
    _mismatch(mismatches, "docker.build.context", "application", environment.get("CONTEXT"))
    _mismatch(
        mismatches,
        "docker.build.dockerfile",
        "generated/docker/Dockerfile",
        environment.get("DOCKERFILE"),
    )
    _mismatch(mismatches, "docker.build.push", "false", environment.get("PUSH"))
    _mismatch(
        mismatches,
        "docker.supplyChain.sbom",
        "true" if model.supply_chain.get("sbom", {}).get("enabled") else "false",
        environment.get("SBOM"),
    )
    provenance = model.supply_chain.get("provenance", {})
    _mismatch(
        mismatches,
        "docker.supplyChain.provenance",
        f"mode={provenance.get('mode', 'min')}"
        if provenance.get("enabled")
        else "false",
        environment.get("PROVENANCE"),
    )
    try:
        metadata = json.loads(artifacts["docker/metadata.json"])
    except (TypeError, json.JSONDecodeError) as exc:
        mismatches.append(
            {
                "path": "docker/metadata.json",
                "expected": "valid JSON",
                "received": type(exc).__name__,
            }
        )
        metadata = {}
    if not isinstance(metadata, dict):
        mismatches.append(
            {
                "path": "docker.metadata.json",
                "expected": "JSON object",
                "received": type(metadata).__name__,
            }
        )
        metadata = {}
    build = metadata.get("build")
    image = metadata.get("image")
    runtime = metadata.get("runtime")
    capabilities = metadata.get("capabilities")
    _mismatch(
        mismatches,
        "docker.build.artifact",
        model.build_artifact,
        build.get("artifact") if isinstance(build, dict) else None,
    )
    _mismatch(
        mismatches,
        "docker.runtime.user",
        model.runtime_user,
        runtime.get("user") if isinstance(runtime, dict) else None,
    )
    _mismatch(
        mismatches,
        "docker.runtime.containerPort",
        model.environments[0].container_port,
        runtime.get("containerPort") if isinstance(runtime, dict) else None,
    )
    _mismatch(
        mismatches,
        "docker.metadata.image.tagStrategy",
        model.image_tag_strategy,
        image.get("tagStrategy") if isinstance(image, dict) else None,
    )
    _mismatch(
        mismatches,
        "docker.metadata.image.tagExpression",
        model.image_tag_expression,
        image.get("tagExpression") if isinstance(image, dict) else None,
    )
    for path, expected, received in (
        (
            "docker.metadata.build.context",
            model.build_context,
            build.get("context") if isinstance(build, dict) else None,
        ),
        (
            "docker.metadata.build.dockerfileStrategy",
            model.dockerfile_strategy,
            build.get("dockerfileStrategy") if isinstance(build, dict) else None,
        ),
        (
            "docker.metadata.build.multiStage",
            bool(model.build.get("multiStage")),
            build.get("multiStage") if isinstance(build, dict) else None,
        ),
        (
            "docker.metadata.build.reproducible",
            bool(model.build.get("reproducible")),
            (
                build.get("reproducibility", {}).get("requested")
                if isinstance(build, dict)
                and isinstance(build.get("reproducibility"), dict)
                else None
            ),
        ),
        (
            "docker.metadata.runtime.runAsNonRoot",
            bool(model.security.get("runAsNonRoot")),
            runtime.get("runAsNonRoot") if isinstance(runtime, dict) else None,
        ),
    ):
        _mismatch(mismatches, path, expected, received)
    capability_expectations = {
        "sbom": bool(model.supply_chain.get("sbom", {}).get("enabled")),
        "provenance": bool(provenance.get("enabled")),
        "scan": bool(model.supply_chain.get("scan", {}).get("enabled")),
        "cache": bool(
            model.build.get("cache", {}).get("enabled")
            or model.build.get("cache", {}).get("from")
            or model.build.get("cache", {}).get("to")
        ),
    }
    for name, expected in capability_expectations.items():
        capability = (
            capabilities.get(name) if isinstance(capabilities, dict) else None
        )
        _mismatch(
            mismatches,
            f"docker.metadata.capabilities.{name}.requested",
            expected,
            capability.get("requested") if isinstance(capability, dict) else None,
        )
    dockerfile = artifacts["docker/Dockerfile"]
    lines = dockerfile.splitlines()
    final_from = -1
    for index, line in enumerate(lines):
        if re.match(r"^\s*FROM(?:\s|$)", line, re.IGNORECASE):
            final_from = index
    final_stage = "\n".join(lines[final_from + 1 :]) if final_from >= 0 else ""
    final_user = re.findall(r"(?im)^\s*USER\s+([^\s#]+)", final_stage)
    exposed = re.findall(r"(?im)^\s*EXPOSE\s+([0-9]+)", final_stage)
    commands = re.findall(r"(?im)^\s*CMD\s+(.+?)\s*$", final_stage)
    from_count = sum(
        bool(re.match(r"^\s*FROM(?:\s|$)", line, re.IGNORECASE))
        for line in lines
    )
    if final_from < 0:
        mismatches.append(
            {
                "path": "docker.Dockerfile.finalStage",
                "expected": "a FROM instruction",
                "received": None,
            }
        )
    _mismatch(
        mismatches,
        "docker.Dockerfile.finalUser",
        str(model.runtime_user),
        final_user[-1].split(":", 1)[0] if final_user else None,
    )
    if model.dockerfile_strategy == "generated":
        builder_image, runtime_image = _GENERATED_IMAGE_PAIRS[model.application_type]
        if model.build.get("multiStage"):
            expected_image_lines = [
                f"ARG BUILDER_IMAGE={builder_image}",
                f"ARG RUNTIME_IMAGE={runtime_image}",
                "FROM ${BUILDER_IMAGE} AS build",
                "FROM ${RUNTIME_IMAGE} AS runtime",
            ]
        else:
            expected_image_lines = [
                f"ARG RUNTIME_IMAGE={builder_image}",
                "FROM ${RUNTIME_IMAGE} AS runtime",
            ]
        actual_image_lines = [
            line.strip()
            for line in lines
            if re.match(
                r"^\s*(?:ARG\s+(?:BUILDER_IMAGE|RUNTIME_IMAGE)=|FROM\s+)",
                line,
                re.IGNORECASE,
            )
        ]
        _mismatch(
            mismatches,
            "docker.Dockerfile.baseImages",
            expected_image_lines,
            actual_image_lines,
        )
        _mismatch(
            mismatches,
            "docker.Dockerfile.exposedPort",
            model.environments[0].container_port,
            int(exposed[-1]) if exposed else None,
        )
        _mismatch(
            mismatches,
            "docker.Dockerfile.command",
            json.dumps(["sh", "-c", model.run_command], separators=(",", ":")),
            commands[-1] if commands else None,
        )
        _mismatch(
            mismatches,
            "docker.Dockerfile.stageCount",
            2 if model.build.get("multiStage") else 1,
            from_count,
        )
        expected_build = (
            "RUN "
            + json.dumps(["sh", "-c", model.build_command], separators=(",", ":"))
        )
        if expected_build not in lines:
            mismatches.append(
                {
                    "path": "docker.Dockerfile.buildCommand",
                    "expected": model.build_command,
                    "received": None,
                }
            )
    return mismatches


def _jenkins_v2_artifact_mismatches(
    model: NormalizedDevOpsModel,
    result: AdapterResult,
) -> list[dict[str, Any]]:
    """Validate the v0.2 build-once, immutable-digest Jenkins projection."""

    artifacts = _artifact_map(result)
    required = [
        "jenkins/Jenkinsfile",
        "jenkins/job-dsl.groovy",
        "jenkins/artifact-contract.json",
        "jenkins/README.md",
        *(f"jenkins/environments/{environment.name}.json" for environment in model.environments),
    ]
    mismatches: list[dict[str, Any]] = [
        {"path": path, "expected": "generated artifact", "received": None}
        for path in required
        if path not in artifacts
    ]
    if mismatches:
        return mismatches

    from devops_stack_composer.adapters.jenkins import JenkinsPipelineAdapter
    from devops_stack_composer.sources import SourceResolution

    expected_result = JenkinsPipelineAdapter(
        SourceResolution(
            key="jenkins",
            path=Path("."),
            origin="artifact-contract",
            commit=result.template_commit,
            remote=None,
            matches_lock=True,
        )
    ).render(model, validate_upstream=False)
    mismatches.extend(
        _closed_artifact_mismatches(
            result,
            {
                artifact.path: (artifact.content, artifact.mode, artifact.origins)
                for artifact in expected_result.artifacts
            },
        )
    )

    try:
        contract = json.loads(artifacts["jenkins/artifact-contract.json"])
    except (TypeError, json.JSONDecodeError) as exc:
        mismatches.append(
            {
                "path": "jenkins.artifactContract",
                "expected": "valid JSON object",
                "received": type(exc).__name__,
            }
        )
        contract = {}
    if not isinstance(contract, dict):
        mismatches.append(
            {
                "path": "jenkins.artifactContract",
                "expected": "JSON object",
                "received": type(contract).__name__,
            }
        )
        contract = {}
    expected_contract_values = (
        ("schemaVersion", "jenkins-artifact-contract-v1"),
        ("verificationScope", "generated-static-plan-only"),
        ("jenkinsExecutionVerified", False),
    )
    for key, expected in expected_contract_values:
        _mismatch(
            mismatches,
            f"jenkins.artifactContract.{key}",
            expected,
            contract.get(key),
        )
    build_contract = contract.get("build")
    build_contract = build_contract if isinstance(build_contract, dict) else {}
    _mismatch(
        mismatches,
        "jenkins.artifactContract.build.maximumImageBuildInvocations",
        1,
        build_contract.get("maximumImageBuildInvocations"),
    )
    _mismatch(
        mismatches,
        "jenkins.artifactContract.build.command",
        "./generated/docker/build.sh --push",
        build_contract.get("command"),
    )
    deployment_contract = contract.get("deployment")
    deployment_contract = (
        deployment_contract if isinstance(deployment_contract, dict) else {}
    )
    _mismatch(
        mismatches,
        "jenkins.artifactContract.deployment.mutableTagsAllowed",
        False,
        deployment_contract.get("mutableTagsAllowed"),
    )
    _mismatch(
        mismatches,
        "jenkins.artifactContract.deployment.rollbackRebuildAllowed",
        False,
        deployment_contract.get("rollbackRebuildAllowed"),
    )

    for environment in model.environments:
        path = f"jenkins/environments/{environment.name}.json"
        try:
            value = json.loads(artifacts[path])
        except (TypeError, json.JSONDecodeError) as exc:
            mismatches.append(
                {"path": path, "expected": "valid JSON", "received": type(exc).__name__}
            )
            continue
        if not isinstance(value, dict):
            mismatches.append(
                {"path": path, "expected": "JSON object", "received": type(value).__name__}
            )
            continue
        prefix = f"jenkins.environments.{environment.name}"
        for key, expected in (
            ("environment", environment.name),
            ("image", model.image_reference),
            ("imageContract", "resolved-digest"),
            ("imageTagExpression", model.image_tag_expression),
            (
                "deploymentImageSource",
                "out/execution/artifact.json#immutableImageReference",
            ),
            ("mutableTagDeploymentAllowed", False),
            ("namespace", environment.namespace),
            ("branchPatterns", list(model.branch_environment_map[environment.name])),
        ):
            _mismatch(mismatches, f"{prefix}.{key}", expected, value.get(key))

    jenkinsfile = artifacts["jenkins/Jenkinsfile"]
    environment_match = re.search(
        r"(?ms)^\s*environment\s*\{\s*(.*?)^\s*\}\s*$",
        jenkinsfile,
    )
    environment_body = environment_match.group(1) if environment_match else ""
    for path, key, expected in (
        ("jenkins.Jenkinsfile.registry", "IMAGE_REGISTRY", model.image_registry),
        ("jenkins.Jenkinsfile.repository", "IMAGE_REPOSITORY", model.image_name),
        (
            "jenkins.Jenkinsfile.registryCredentialId",
            "REGISTRY_CREDENTIAL_ID",
            model.credential_id,
        ),
    ):
        assignments = re.findall(
            rf"(?m)^[ \t]*{key}[ \t]*=[ \t]*(.+?)[ \t]*$",
            environment_body,
        )
        expected_assignment = _groovy_literal(expected)
        if assignments != [expected_assignment]:
            mismatches.append(
                {
                    "path": path,
                    "expected": expected_assignment,
                    "received": assignments,
                }
            )

    stage_blocks = _jenkins_stage_blocks(jenkinsfile)
    expected_jenkinsfile = expected_result.artifact("jenkins/Jenkinsfile").content
    expected_stage_blocks = _jenkins_stage_blocks(expected_jenkinsfile)

    def exact_stage(name: str) -> tuple[int, str] | None:
        entries = stage_blocks.get(name, [])
        if len(entries) != 1:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.stages.{name}",
                    "expected": "exactly one executable stage",
                    "received": len(entries),
                }
            )
            return None
        return entries[0]

    ordered_names = [
        "Checkout",
        "Resolve Image Intent",
        "Resolve Docker Template",
        "Application Build",
        "Test",
        "Container Plan Validation",
        "Build Once",
        "Resolve Digest",
        "Generate SBOM",
        "Scan Same Digest",
        "Produce Provenance",
        "Verify Artifact Contract",
        "Deploy Same Digest dev",
        "Verify Rollout dev",
        "Deploy Same Digest staging",
        "Verify Rollout staging",
    ]
    if model.production_approval:
        ordered_names.append("Production Approval")
    ordered_names.extend(
        ["Deploy Same Digest production", "Verify Rollout production"]
    )
    entries = {name: exact_stage(name) for name in ordered_names}
    semantic_stage_paths = {
        "Resolve Image Intent": "jenkins.Jenkinsfile.imageTagResolution",
        "Resolve Docker Template": "jenkins.Jenkinsfile.dockerTemplateResolution",
        "Container Plan Validation": "jenkins.Jenkinsfile.containerPlanValidation",
        "Generate SBOM": "jenkins.Jenkinsfile.supplyChain.sbom",
        "Scan Same Digest": "jenkins.Jenkinsfile.supplyChain.scan",
        "Produce Provenance": "jenkins.Jenkinsfile.supplyChain.provenance",
        "Production Approval": "jenkins.Jenkinsfile.productionApproval",
    }
    for name, path in semantic_stage_paths.items():
        expected_blocks = expected_stage_blocks.get(name, [])
        actual_blocks = stage_blocks.get(name, [])
        expected_contents = [block for _, block in expected_blocks]
        actual_contents = [block for _, block in actual_blocks]
        if actual_contents != expected_contents:
            mismatches.append(
                {
                    "path": path,
                    "expected": (
                        expected_contents[0]
                        if len(expected_contents) == 1
                        else len(expected_contents)
                    ),
                    "received": (
                        actual_contents[0]
                        if len(actual_contents) == 1
                        else len(actual_contents)
                    ),
                }
            )
    positions = [entries[name][0] for name in ordered_names if entries[name] is not None]
    if len(positions) == len(ordered_names) and positions != sorted(positions):
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.stageOrdering",
                "expected": ordered_names,
                "received": sorted(ordered_names, key=lambda name: entries[name][0]),
            }
        )
    if not model.production_approval and stage_blocks.get("Production Approval"):
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.productionApproval",
                "expected": "disabled",
                "received": "generated",
            }
        )

    routed_branches = tuple(
        dict.fromkeys(
            branch
            for environment_name in ("dev", "staging", "production")
            for branch in model.branch_environment_map[environment_name]
        )
    )
    for name in (
        "Build Once",
        "Resolve Digest",
        "Generate SBOM",
        "Scan Same Digest",
        "Produce Provenance",
        "Verify Artifact Contract",
    ):
        entry = entries.get(name)
        if entry is None:
            continue
        differs, received = _jenkins_route_mismatch(entry[1], routed_branches)
        if differs:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.branchRouting.{name}",
                    "expected": {"branches": list(routed_branches), "comparator": "GLOB"},
                    "received": received,
                }
            )

    build_entry = entries.get("Build Once")
    expected_build_blocks = expected_stage_blocks.get("Build Once", [])
    actual_build_blocks = stage_blocks.get("Build Once", [])
    if (
        [block for _, block in actual_build_blocks]
        != [block for _, block in expected_build_blocks]
    ):
        expected_binding = (
            "withCredentials([usernamePassword(credentialsId: "
            "env.REGISTRY_CREDENTIAL_ID, usernameVariable: 'REGISTRY_USER', "
            "passwordVariable: 'REGISTRY_PASSWORD')]) {"
        )
        actual_binding_count = (
            0 if build_entry is None else build_entry[1].count(expected_binding)
        )
        if actual_binding_count != 1:
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.registryCredentialBinding",
                    "expected": expected_binding,
                    "received": actual_binding_count,
                }
            )
    build_count = jenkinsfile.count("./generated/docker/build.sh --push")
    load_count = jenkinsfile.count("./generated/docker/build.sh --load")
    raw_build_count = len(
        re.findall(r"(?m)(?<![A-Za-z0-9_-])docker\s+build(?:\s|$)|docker\s+buildx\s+build(?:\s|$)", jenkinsfile)
    )
    if (
        build_entry is None
        or build_entry[1].count("./generated/docker/build.sh --push") != 1
        or "out/execution/build-invocation.json" not in build_entry[1]
        or "BUILD_INVOKED_MORE_THAN_ONCE" not in build_entry[1]
        or build_count != 1
        or load_count != 0
        or raw_build_count != 0
    ):
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.buildOnce",
                "expected": {
                    "officialPushWrapperCount": 1,
                    "loadCount": 0,
                    "rawBuildCount": 0,
                    "persistentInvocationMarker": True,
                },
                "received": {
                    "officialPushWrapperCount": build_count,
                    "loadCount": load_count,
                    "rawBuildCount": raw_build_count,
                    "persistentInvocationMarker": bool(
                        build_entry
                        and "out/execution/build-invocation.json" in build_entry[1]
                    ),
                },
            }
        )

    resolve_entry = entries.get("Resolve Digest")
    resolve_required = (
        'docker buildx imagetools inspect --raw "$IMAGE_TAG_REF"',
        "tag_recheck_digest=",
        "Image tag moved while the registry digest was being resolved",
        'env.IMAGE_REF = "${env.IMAGE_REPOSITORY}@${env.IMAGE_DIGEST}"',
        "out/execution/artifact.json",
        "manifestDigest: env.IMAGE_DIGEST",
        "buildInvocationCount: 1",
    )
    if resolve_entry is None or any(
        marker not in resolve_entry[1] for marker in resolve_required
    ):
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.digestResolution",
                "expected": list(resolve_required),
                "received": None if resolve_entry is None else resolve_entry[1],
            }
        )
    if resolve_entry is not None:
        downstream = jenkinsfile[resolve_entry[0] :]
        if (
            "./generated/docker/build.sh --push" in downstream
            or "./generated/docker/build.sh --load" in downstream
            or re.search(r"docker\s+buildx\s+build(?:\s|$)", downstream)
        ):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.downstreamRebuild",
                    "expected": "no image build after digest resolution",
                    "received": "build command found",
                }
            )

    evidence_expectations = {
        "Generate SBOM": (
            bool(model.supply_chain.get("sbom", {}).get("enabled", False)),
            'syft "$IMAGE_REF"',
        ),
        "Scan Same Digest": (
            bool(model.supply_chain.get("scan", {}).get("enabled", False)),
            'trivy image --format json --output out/supply-chain/vulnerabilities.json',
        ),
        "Produce Provenance": (
            bool(model.supply_chain.get("provenance", {}).get("enabled", False)),
            "subject: [[name: env.IMAGE_REPOSITORY, digest: [sha256: env.IMAGE_DIGEST.substring(7)]]]",
        ),
    }
    for name, (enabled, marker) in evidence_expectations.items():
        entry = entries.get(name)
        received = 0 if entry is None else entry[1].count(marker)
        if received != int(enabled):
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.evidence.{name}",
                    "expected": {"enabled": enabled, "digestSubjectCount": int(enabled)},
                    "received": received,
                }
            )
    verify_entry = entries.get("Verify Artifact Contract")
    expected_verify = "devops-stack artifact verify --artifact out/execution/artifact.json"
    if verify_entry is None or verify_entry[1].count(expected_verify) != 1:
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.artifactVerification",
                "expected": expected_verify,
                "received": None if verify_entry is None else verify_entry[1],
            }
        )

    for environment in model.environments:
        deploy_name = f"Deploy Same Digest {environment.name}"
        rollout_name = f"Verify Rollout {environment.name}"
        deploy_entry = entries.get(deploy_name)
        rollout_entry = entries.get(rollout_name)
        branches = model.branch_environment_map[environment.name]
        for name, entry in ((deploy_name, deploy_entry), (rollout_name, rollout_entry)):
            if entry is None:
                continue
            differs, received = _jenkins_route_mismatch(entry[1], branches)
            if differs:
                mismatches.append(
                    {
                        "path": f"jenkins.Jenkinsfile.branchRouting.{name}",
                        "expected": {"branches": list(branches), "comparator": "GLOB"},
                        "received": received,
                    }
                )
        deploy_markers = (
            '"$IMAGE_REPOSITORY"@sha256:*',
            'kustomize edit set image "$IMAGE_REPOSITORY=$IMAGE_REF"',
            f'out/execution/rendered-{environment.name}.sha256',
            'kubectl apply -f "$render_root/rendered.yaml"',
        )
        if deploy_entry is None or any(
            marker not in deploy_entry[1] for marker in deploy_markers
        ):
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.deployment.{environment.name}",
                    "expected": list(deploy_markers),
                    "received": None if deploy_entry is None else deploy_entry[1],
                }
            )
        rollout_command = (
            f"kubectl rollout status deployment/{model.service_name} "
            f"--namespace {environment.namespace} --timeout=5m"
        )
        if rollout_entry is None or rollout_entry[1].count(rollout_command) != 1:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.rollout.{environment.name}",
                    "expected": rollout_command,
                    "received": None if rollout_entry is None else rollout_entry[1],
                }
            )
        rollback_command = (
            f"kubectl rollout undo deployment/{model.service_name} "
            f"--namespace {environment.namespace}"
        )
        rollback_count = sum(
            entry[1].count(rollback_command)
            for entry in (deploy_entry, rollout_entry)
            if entry is not None
        )
        expected_rollback_count = 2 if environment.rollback.get("enabled", False) else 0
        if rollback_count != expected_rollback_count:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.rollback.{environment.name}",
                    "expected": expected_rollback_count,
                    "received": rollback_count,
                }
            )

    job_dsl = artifacts["jenkins/job-dsl.groovy"]
    for marker in (
        f"multibranchPipelineJob({_groovy_literal(model.application_name)})",
        "branchSources {",
        "workflowBranchProjectFactory {",
        "scriptPath('generated/jenkins/Jenkinsfile')",
    ):
        if marker not in job_dsl:
            mismatches.append(
                {
                    "path": "jenkins.jobDsl",
                    "expected": marker,
                    "received": None,
                }
            )
    return mismatches


def _jenkins_artifact_mismatches(
    model: NormalizedDevOpsModel,
    result: AdapterResult,
) -> list[dict[str, Any]]:
    if result.adapter_version == "2.0.0":
        return _jenkins_v2_artifact_mismatches(model, result)
    artifacts = _artifact_map(result)
    required = ["jenkins/Jenkinsfile", "jenkins/job-dsl.groovy"] + [
        f"jenkins/environments/{environment.name}.json"
        for environment in model.environments
    ]
    mismatches: list[dict[str, Any]] = [
        {"path": path, "expected": "generated artifact", "received": None}
        for path in required
        if path not in artifacts
    ]
    if mismatches:
        return mismatches
    from devops_stack_composer.adapters.jenkins import (
        JenkinsPipelineAdapter,
        _render_jenkinsfile,
        _render_job_dsl,
    )
    from devops_stack_composer.sources import SourceResolution

    expected_result = JenkinsPipelineAdapter(
        SourceResolution(
            key="jenkins",
            path=Path("."),
            origin="artifact-contract",
            commit=result.template_commit,
            remote=None,
            matches_lock=True,
        )
    ).render(model, validate_upstream=False)
    mismatches.extend(
        _closed_artifact_mismatches(
            result,
            {
                artifact.path: (
                    artifact.content,
                    artifact.mode,
                    artifact.origins,
                )
                for artifact in expected_result.artifacts
            },
        )
    )

    for path, expected_content in (
        ("jenkins/Jenkinsfile", _render_jenkinsfile(model)),
        ("jenkins/job-dsl.groovy", _render_job_dsl(model)),
    ):
        if artifacts[path] != expected_content:
            mismatches.append(
                {
                    "path": f"{path}.content",
                    "expected": hashlib.sha256(
                        expected_content.encode("utf-8")
                    ).hexdigest(),
                    "received": hashlib.sha256(
                        artifacts[path].encode("utf-8")
                    ).hexdigest(),
                }
            )
    for environment in model.environments:
        path = f"jenkins/environments/{environment.name}.json"
        try:
            value = json.loads(artifacts[path])
        except (TypeError, json.JSONDecodeError) as exc:
            mismatches.append(
                {"path": path, "expected": "valid JSON", "received": type(exc).__name__}
            )
            continue
        if not isinstance(value, dict):
            mismatches.append(
                {
                    "path": path,
                    "expected": "JSON object",
                    "received": type(value).__name__,
                }
            )
            continue
        prefix = f"jenkins.environments.{environment.name}"
        _mismatch(mismatches, f"{prefix}.environment", environment.name, value.get("environment"))
        _mismatch(mismatches, f"{prefix}.image", model.image_reference, value.get("image"))
        _mismatch(mismatches, f"{prefix}.tagExpression", model.image_tag_expression, value.get("imageTagExpression"))
        _mismatch(mismatches, f"{prefix}.namespace", environment.namespace, value.get("namespace"))
        _mismatch(
            mismatches,
            f"{prefix}.branches",
            list(model.branch_environment_map[environment.name]),
            value.get("branchPatterns"),
        )
    jenkinsfile = artifacts["jenkins/Jenkinsfile"]
    environment_match = re.search(
        r"(?ms)^\s*environment\s*\{\s*(.*?)^\s*\}\s*$",
        jenkinsfile,
    )
    environment_body = environment_match.group(1) if environment_match else ""
    for path, key, expected in (
        ("jenkins.Jenkinsfile.registry", "IMAGE_REGISTRY", model.image_registry),
        ("jenkins.Jenkinsfile.repository", "IMAGE_REPOSITORY", model.image_name),
        (
            "jenkins.Jenkinsfile.registryCredentialId",
            "REGISTRY_CREDENTIAL_ID",
            model.credential_id,
        ),
    ):
        assignments = re.findall(
            rf"(?m)^[ \t]*{key}[ \t]*=[ \t]*(.+?)[ \t]*$",
            environment_body,
        )
        expected_assignment = _groovy_literal(expected)
        if assignments != [expected_assignment]:
            mismatches.append(
                {
                    "path": path,
                    "expected": expected_assignment,
                    "received": assignments,
                }
            )
    for stage, path, expected in (
        ("Build", "jenkins.Jenkinsfile.buildCommand", model.build_command),
        ("Test", "jenkins.Jenkinsfile.testCommand", model.test_command),
    ):
        stage_pattern = (
            rf"(?ms)^\s*stage\('{re.escape(stage)}'\)\s*\{{\s*"
            rf"steps\s*\{{\s*sh\s+{re.escape(_groovy_literal(expected))}\s*\}}\s*\}}"
        )
        if re.search(stage_pattern, jenkinsfile) is None:
            mismatches.append({"path": path, "expected": expected, "received": None})

    stage_blocks = _jenkins_stage_blocks(jenkinsfile)

    def exact_stage(name: str) -> tuple[int, str] | None:
        entries = stage_blocks.get(name, [])
        if len(entries) != 1:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.stages.{name}",
                    "expected": "exactly one executable stage",
                    "received": len(entries),
                }
            )
            return None
        return entries[0]

    routed_branches = tuple(
        dict.fromkeys(
            branch
            for environment_name in ("dev", "staging", "production")
            for branch in model.branch_environment_map[environment_name]
        )
    )
    executable_stages: dict[str, tuple[int, str] | None] = {
        name: exact_stage(name)
        for name in (
            "Resolve Image Tag",
            "Resolve Docker Template",
            "Container Plan Validation",
            "Container Build",
            "Supply Chain Scan",
            "Registry Push",
            *(f"Deploy {environment.name}" for environment in model.environments),
        )
    }

    resolver_entry = executable_stages["Resolve Docker Template"]
    if resolver_entry is not None:
        resolver_markers = (
            "String templateRoot =",
            "if (!templateRoot)",
            "templateRoot =",
            "error('Unable to resolve",
            "env.DEVOPS_STACK_DOCKER_TEMPLATE =",
        )
        expected_resolver_lines = [
            "String templateRoot = env.DEVOPS_STACK_DOCKER_TEMPLATE?.trim()",
            "if (!templateRoot) {",
            "templateRoot = sh(script: 'devops-stack templates path docker', returnStdout: true).trim()",
            "if (!templateRoot) {",
            "error('Unable to resolve the locked Docker template checkout.')",
            "env.DEVOPS_STACK_DOCKER_TEMPLATE = templateRoot",
        ]
        actual_resolver_lines = [
            line.strip()
            for line in resolver_entry[1].splitlines()
            if any(line.strip().startswith(marker) for marker in resolver_markers)
        ]
        if actual_resolver_lines != expected_resolver_lines:
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.dockerTemplateResolution",
                    "expected": expected_resolver_lines,
                    "received": actual_resolver_lines,
                }
            )

    plan_entry = executable_stages["Container Plan Validation"]
    if plan_entry is not None:
        expected_plan_command = "sh './generated/docker/build.sh --validate'"
        actual_plan_commands = [
            line.strip()
            for line in plan_entry[1].splitlines()
            if line.strip().startswith("sh ")
        ]
        if (
            actual_plan_commands != [expected_plan_command]
            or jenkinsfile.count("./generated/docker/build.sh --validate") != 1
        ):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.containerPlanValidation",
                    "expected": [expected_plan_command],
                    "received": actual_plan_commands,
                }
            )

    tag_entry = executable_stages["Resolve Image Tag"]
    if tag_entry is not None:
        tag_block = tag_entry[1]
        git_sha_line = (
            "env.GIT_COMMIT_SHA = sh(script: 'git rev-parse --short=12 HEAD', "
            "returnStdout: true).trim()"
        )
        if model.image_tag_strategy == "fixed":
            strategy_lines = [
                f"env.IMAGE_TAG = {_groovy_literal(model.image_tag)}"
            ]
        elif model.image_tag_strategy == "git-sha":
            strategy_lines = ['env.IMAGE_TAG = "${env.GIT_COMMIT_SHA}"']
        elif model.image_tag_strategy == "semver":
            strategy_lines = [
                "if (!params.VERSION?.trim()) {",
                "error('VERSION is required for the semver image tag strategy.')",
                "env.IMAGE_TAG = params.VERSION.trim()",
            ]
        else:
            strategy_lines = [
                "String branchSlug = (env.BRANCH_NAME ?: 'detached').toLowerCase().replaceAll('[^a-z0-9._-]+', '-').replaceAll('^[.-]+|[.-]+$', '')",
                "if (!branchSlug) { branchSlug = 'detached' }",
                "env.BRANCH_SLUG = branchSlug.take(115)",
                'env.IMAGE_TAG = "${env.BRANCH_SLUG}-${env.GIT_COMMIT_SHA}"',
            ]
        expected_tag_lines = [
            git_sha_line,
            *strategy_lines,
            "if (!(env.IMAGE_TAG ==~ /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/) || env.IMAGE_TAG == '__IMAGE_TAG__') {",
            "error('Resolved image tag is not Docker-safe.')",
            'env.IMAGE_REF = "${env.IMAGE_REPOSITORY}:${env.IMAGE_TAG}"',
            'env.OCI_REVISION = "${env.GIT_COMMIT_SHA}"',
            "env.OCI_CREATED = sh(script: 'git show -s --format=%cI HEAD', returnStdout: true).trim()",
        ]
        tag_markers = (
            "env.GIT_COMMIT_SHA =",
            "env.IMAGE_TAG =",
            "String branchSlug =",
            "if (!branchSlug)",
            "env.BRANCH_SLUG =",
            "if (!(env.IMAGE_TAG",
            "error('Resolved image tag",
            "if (!params.VERSION",
            "error('VERSION is required",
            "env.IMAGE_REF =",
            "env.OCI_REVISION =",
            "env.OCI_CREATED =",
        )
        actual_tag_lines = [
            line.strip()
            for line in tag_block.splitlines()
            if any(line.strip().startswith(marker) for marker in tag_markers)
        ]
        expected_parameter_lines = (
            [
                "string(name: 'VERSION', defaultValue: '', description: "
                "'Semantic version used as the image tag.')"
            ]
            if model.image_tag_strategy == "semver"
            else []
        )
        actual_parameter_lines = [
            line.strip()
            for line in jenkinsfile.splitlines()
            if line.strip().startswith("string(name: 'VERSION'")
        ]
        if (
            actual_tag_lines != expected_tag_lines
            or actual_parameter_lines != expected_parameter_lines
        ):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.imageTagResolution",
                    "expected": {
                        "strategy": model.image_tag_strategy,
                        "stageLines": expected_tag_lines,
                        "parameterLines": expected_parameter_lines,
                    },
                    "received": {
                        "stageLines": actual_tag_lines,
                        "parameterLines": actual_parameter_lines,
                    },
                }
            )
    route_expectations = {
        "Container Build": routed_branches,
        "Supply Chain Scan": routed_branches,
        "Registry Push": routed_branches,
        **{
            f"Deploy {environment.name}": model.branch_environment_map[
                environment.name
            ]
            for environment in model.environments
        },
    }
    for stage_name, branches in route_expectations.items():
        entry = executable_stages[stage_name]
        if entry is None:
            continue
        route_differs, received = _jenkins_route_mismatch(entry[1], branches)
        if route_differs:
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.branchRouting.{stage_name}",
                    "expected": {
                        "branches": list(branches),
                        "comparator": "GLOB",
                    },
                    "received": received,
                }
            )

    push_entry = executable_stages["Registry Push"]
    if push_entry is not None:
        push_block = push_entry[1]
        expected_binding = (
            "withCredentials([usernamePassword(credentialsId: "
            "env.REGISTRY_CREDENTIAL_ID, usernameVariable: 'REGISTRY_USER', "
            "passwordVariable: 'REGISTRY_PASSWORD')]) {"
        )
        actual_bindings = [
            line.strip()
            for line in push_block.splitlines()
            if "withCredentials" in line or "credentialsId:" in line
        ]
        push_count = push_block.count("./generated/docker/build.sh --push")
        if actual_bindings != [expected_binding] or push_count != 1:
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.registryCredentialBinding",
                    "expected": {
                        "binding": expected_binding,
                        "officialPushWrapperCount": 1,
                    },
                    "received": {
                        "bindings": actual_bindings,
                        "officialPushWrapperCount": push_count,
                    },
                }
            )

    production_entry = executable_stages["Deploy production"]
    approval_entries = stage_blocks.get("Production Approval", [])
    if model.production_approval:
        approval_entry = exact_stage("Production Approval")
        if approval_entry is not None:
            route_differs, received = _jenkins_route_mismatch(
                approval_entry[1],
                model.branch_environment_map["production"],
            )
            if route_differs:
                mismatches.append(
                    {
                        "path": "jenkins.Jenkinsfile.branchRouting.Production Approval",
                        "expected": {
                            "branches": list(
                                model.branch_environment_map["production"]
                            ),
                            "comparator": "GLOB",
                        },
                        "received": received,
                    }
                )
            approval_lines = [line.strip() for line in approval_entry[1].splitlines()]
            expected_input = (
                "input message: "
                + _groovy_literal(
                    f"Approve production deployment for {model.application_name}?"
                )
                + ", ok: 'Deploy to production'"
            )
            expected_timeout = "timeout(time: 1, unit: 'HOURS') {"
            received_inputs = [
                line for line in approval_lines if line.startswith("input ")
            ]
            received_timeouts = [
                line for line in approval_lines if line.startswith("timeout(")
            ]
            before_deploy = (
                production_entry is not None
                and approval_entry[0] < production_entry[0]
            )
            if (
                received_inputs != [expected_input]
                or received_timeouts != [expected_timeout]
                or not before_deploy
            ):
                mismatches.append(
                    {
                        "path": "jenkins.Jenkinsfile.productionApproval",
                        "expected": {
                            "input": expected_input,
                            "timeout": expected_timeout,
                            "beforeDeployProduction": True,
                        },
                        "received": {
                            "inputs": received_inputs,
                            "timeouts": received_timeouts,
                            "beforeDeployProduction": before_deploy,
                        },
                    }
                )
    elif approval_entries:
        mismatches.append(
            {
                "path": "jenkins.Jenkinsfile.productionApproval",
                "expected": "disabled",
                "received": f"{len(approval_entries)} approval stage(s)",
            }
        )

    for environment in model.environments:
        entry = executable_stages[f"Deploy {environment.name}"]
        if entry is None:
            continue
        block = entry[1]
        lines = [line.strip() for line in block.splitlines()]
        rollout_flag = f"DEPLOY_{environment.name.upper()}_ROLLOUT_STARTED"
        expected_deployment_lines = [
            f"env.{rollout_flag} = 'false'",
            (
                "String deploymentResult = sh(script: "
                f"{_groovy_literal(_jenkins_deployment_render_script(model, environment))}, "
                "returnStdout: true).trim()"
            ),
            "List deploymentParts = deploymentResult.tokenize('|')",
            "if (deploymentParts.size() != 2 || !['true', 'false'].contains(deploymentParts[0]) || !(deploymentParts[1] ==~ /[0-9]+/)) {",
            "error('kubectl apply returned an invalid rollout-state result.')",
            f"env.{rollout_flag} = deploymentParts[0]",
            "if (deploymentParts[1] != '0') {",
            "error('kubectl apply failed after rollout-state detection.')",
            (
                "sh "
                + _groovy_literal(
                    f"kubectl rollout status deployment/{model.service_name} "
                    f"--namespace {environment.namespace} --timeout=5m"
                )
            ),
        ]
        deployment_markers = (
            f"env.{rollout_flag} =",
            "String deploymentResult =",
            "List deploymentParts =",
            "if (deploymentParts.size()",
            "error('kubectl apply returned",
            "if (deploymentParts[1]",
            "error('kubectl apply failed",
            "sh 'kubectl rollout status",
        )
        actual_deployment_lines = [
            line
            for line in lines
            if any(line.startswith(marker) for marker in deployment_markers)
        ]
        executable_occurrences = {
            marker: block.count(marker)
            for marker in (
                "kustomize edit set image",
                "kustomize build",
                "grep -F \\'__IMAGE_TAG__\\'",
                "kubectl apply -f",
                "kubectl rollout status",
            )
        }
        if (
            actual_deployment_lines != expected_deployment_lines
            or any(count != 1 for count in executable_occurrences.values())
        ):
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.deployment.{environment.name}",
                    "expected": {
                        "lines": expected_deployment_lines,
                        "executableOccurrences": {
                            key: 1 for key in executable_occurrences
                        },
                    },
                    "received": {
                        "lines": actual_deployment_lines,
                        "executableOccurrences": executable_occurrences,
                    },
                }
            )
        command = (
            f"kubectl rollout undo deployment/{model.service_name} "
            f"--namespace {environment.namespace}"
        )
        expected_command = f"sh {_groovy_literal(command)}"
        actual_commands = [
            line
            for line in lines
            if line.startswith("sh ") and "kubectl rollout undo" in line
        ]
        occurrence_count = block.count("kubectl rollout undo")
        rollback_enabled = bool(environment.rollback.get("enabled", False))
        failure_gate = False
        if rollback_enabled:
            rollout_flag = f"DEPLOY_{environment.name.upper()}_ROLLOUT_STARTED"
            expected_gate = f"if (env.{rollout_flag} == 'true') {{"
            required_lines = ("post {", "failure {", expected_gate, expected_command)
            positions = [
                lines.index(required) if required in lines else -1
                for required in required_lines
            ]
            failure_gate = all(position >= 0 for position in positions) and positions == sorted(
                positions
            )
        expected_commands = [expected_command] if rollback_enabled else []
        if (
            actual_commands != expected_commands
            or occurrence_count != int(rollback_enabled)
            or (rollback_enabled and not failure_gate)
        ):
            mismatches.append(
                {
                    "path": f"jenkins.Jenkinsfile.rollback.{environment.name}",
                    "expected": {
                        "commands": expected_commands,
                        "failureGate": rollback_enabled,
                    },
                    "received": {
                        "commands": actual_commands,
                        "occurrences": occurrence_count,
                        "failureGate": failure_gate,
                    },
                }
            )

    supply_entry = executable_stages["Supply Chain Scan"]
    if supply_entry is not None:
        supply_block = supply_entry[1]
        shell_literals = _JENKINS_SHELL_LITERAL.findall(supply_block)
        executable_supply_lines = [
            line.strip()
            for line in supply_block.splitlines()
            if line.strip() and not line.lstrip().startswith("//")
        ]
        sbom = model.supply_chain.get("sbom", {})
        sbom_enabled = bool(sbom.get("enabled", False))
        sbom_command = (
            "mkdir -p out/supply-chain && "
            f"syft \"$IMAGE_REF\" -o {sbom.get('format', 'spdx-json')}="
            "out/supply-chain/sbom.json"
        )
        expected_sbom = [_groovy_literal(sbom_command)] if sbom_enabled else []
        actual_sbom = [literal for literal in shell_literals if "syft" in literal]
        archive_lines = [
            line.strip()
            for line in supply_block.splitlines()
            if line.strip().startswith("archiveArtifacts")
        ]
        expected_archive = (
            [
                "archiveArtifacts artifacts: 'out/supply-chain/sbom.json', "
                "fingerprint: true, onlyIfSuccessful: true"
            ]
            if sbom_enabled
            else []
        )
        sbom_occurrences = sum("syft" in line for line in executable_supply_lines)
        archive_occurrences = sum(
            "archiveArtifacts" in line for line in executable_supply_lines
        )
        if (
            actual_sbom != expected_sbom
            or archive_lines != expected_archive
            or sbom_occurrences != int(sbom_enabled)
            or archive_occurrences != int(sbom_enabled)
        ):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.supplyChain.sbom",
                    "expected": {
                        "commands": expected_sbom,
                        "archives": expected_archive,
                    },
                    "received": {
                        "commands": actual_sbom,
                        "archives": archive_lines,
                        "commandOccurrences": sbom_occurrences,
                        "archiveOccurrences": archive_occurrences,
                    },
                }
            )

        scan = model.supply_chain.get("scan", {})
        scan_enabled = bool(scan.get("enabled", False))
        fail_on = str(scan.get("failOn", "high"))
        severities = (
            "LOW,MEDIUM,HIGH,CRITICAL"
            if fail_on == "never"
            else _jenkins_scan_severities(fail_on)
        )
        scan_command = (
            f"trivy image --exit-code {0 if fail_on == 'never' else 1} "
            f"--severity {severities} \"$IMAGE_REF\""
        )
        expected_scan = [_groovy_literal(scan_command)] if scan_enabled else []
        actual_scan = [literal for literal in shell_literals if "trivy image" in literal]
        scan_occurrences = sum(
            "trivy image" in line for line in executable_supply_lines
        )
        if actual_scan != expected_scan or scan_occurrences != int(scan_enabled):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.supplyChain.scan",
                    "expected": expected_scan,
                    "received": {
                        "commands": actual_scan,
                        "occurrences": scan_occurrences,
                    },
                }
            )

        provenance = model.supply_chain.get("provenance", {})
        provenance_enabled = bool(provenance.get("enabled", False))
        provenance_command = (
            "echo 'Provenance mode "
            f"{provenance.get('mode', 'max')} is delegated to docker/build.sh.'"
        )
        expected_provenance = (
            [_groovy_literal(provenance_command)] if provenance_enabled else []
        )
        actual_provenance = [
            literal for literal in shell_literals if "Provenance mode" in literal
        ]
        provenance_occurrences = sum(
            "Provenance mode" in line for line in executable_supply_lines
        )
        provenance_push_count = (
            push_entry[1].count("./generated/docker/build.sh --push")
            if push_entry is not None
            else 0
        )
        if (
            actual_provenance != expected_provenance
            or provenance_occurrences != int(provenance_enabled)
            or (provenance_enabled and provenance_push_count != 1)
        ):
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.supplyChain.provenance",
                    "expected": {
                        "commands": expected_provenance,
                        "officialPushWrapperCount": 1 if provenance_enabled else None,
                    },
                    "received": {
                        "commands": actual_provenance,
                        "occurrences": provenance_occurrences,
                        "officialPushWrapperCount": provenance_push_count,
                    },
                }
            )

    container_entry = executable_stages["Container Build"]
    if container_entry is not None:
        container_lines = [line.strip() for line in container_entry[1].splitlines()]
        local_checks_requested = bool(
            model.supply_chain.get("sbom", {}).get("enabled", False)
            or model.supply_chain.get("scan", {}).get("enabled", False)
        )
        if local_checks_requested and len(model.architectures) == 1:
            expected_local_intent = "sh './generated/docker/build.sh --load'"
        elif local_checks_requested:
            expected_local_intent = (
                "error('Local SBOM and image scanning require exactly one configured "
                "architecture before registry publication.')"
            )
        else:
            expected_local_intent = (
                "echo 'Local image build is not required because local SBOM and image "
                "scanning are disabled.'"
            )
        local_markers = (
            "./generated/docker/build.sh --load",
            "Local SBOM and image scanning require exactly one configured architecture",
            "Local image build is not required because local SBOM and image scanning are disabled",
        )
        actual_local_intent = [
            line
            for line in container_lines
            if any(marker in line for marker in local_markers)
        ]
        if actual_local_intent != [expected_local_intent]:
            mismatches.append(
                {
                    "path": "jenkins.Jenkinsfile.supplyChain.localImage",
                    "expected": expected_local_intent,
                    "received": actual_local_intent,
                }
            )

    job_dsl = artifacts["jenkins/job-dsl.groovy"]
    job_pattern = (
        rf"(?m)^\s*multibranchPipelineJob\("
        rf"{re.escape(_groovy_literal(model.application_name))}\)\s*\{{"
    )
    if re.search(job_pattern, job_dsl) is None:
        mismatches.append(
            {
                "path": "jenkins.jobDsl.applicationName",
                "expected": model.application_name,
                "received": None,
            }
        )
    return mismatches


def _yaml_mapping(content: str) -> dict[str, Any] | None:
    try:
        value = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    return value if isinstance(value, dict) else None


def _kubernetes_artifact_mismatches(
    model: NormalizedDevOpsModel,
    result: AdapterResult,
) -> list[dict[str, Any]]:
    artifacts = _artifact_map(result)
    mismatches: list[dict[str, Any]] = []
    from devops_stack_composer.adapters.kubernetes import KubernetesAdapter
    from devops_stack_composer.sources import SourceResolution

    expected_adapter = KubernetesAdapter(
        SourceResolution(
            key="kubernetes",
            path=Path("."),
            origin="artifact-contract",
            commit=result.template_commit,
            remote=None,
            matches_lock=True,
        )
    )
    default_context = {
        "schemaVersion": "k8s-integration-summary-v1",
        "selection": {
            "profile": "minimal-application",
            "applications": ["nginx-web"],
        },
        "source": {
            "commit": result.template_commit,
            "matchesLock": True,
        },
        "queries": {},
        "render": {"status": "NOT_RUN"},
        "validators": {},
    }
    context_summary = next(
        (
            diagnostic.details.get("summary")
            for diagnostic in result.diagnostics
            if diagnostic.check == "kubernetes.platform-context-contract"
            and isinstance(diagnostic.details.get("summary"), dict)
        ),
        None,
    )
    expected_inventory = {
        artifact.path: (
            artifact.content,
            artifact.mode,
            artifact.origins,
        )
        for artifact in expected_adapter._render_artifacts(
            model,
            context_summary or default_context,
        )
    }
    mismatches.extend(
        _closed_artifact_mismatches(
            result,
            expected_inventory,
        )
    )
    has_config_map = any(environment.environment for environment in model.environments)
    base_resources = [
        "serviceaccount.yaml",
        "deployment.yaml",
        "service.yaml",
    ]
    if has_config_map:
        base_resources.append("configmap.yaml")
    for name in (*base_resources[1:], "kustomization.yaml"):
        path = f"k8s/base/{name}"
        if path not in artifacts:
            mismatches.append(
                {
                    "path": path,
                    "expected": "generated artifact",
                    "received": None,
                }
            )
    base_kustomization = _yaml_mapping(
        artifacts.get("k8s/base/kustomization.yaml", "")
    )
    if "k8s/base/kustomization.yaml" in artifacts:
        if base_kustomization is None:
            mismatches.append(
                {
                    "path": "k8s/base/kustomization.yaml",
                    "expected": "one YAML mapping",
                    "received": None,
                }
            )
        else:
            _mismatch(
                mismatches,
                "kubernetes.base.kustomization.apiVersion",
                "kustomize.config.k8s.io/v1beta1",
                base_kustomization.get("apiVersion"),
            )
            _mismatch(
                mismatches,
                "kubernetes.base.kustomization.kind",
                "Kustomization",
                base_kustomization.get("kind"),
            )
            _mismatch(
                mismatches,
                "kubernetes.base.kustomization.resources",
                base_resources,
                base_kustomization.get("resources"),
            )
    service_account_path = "k8s/base/serviceaccount.yaml"
    if service_account_path not in artifacts:
        mismatches.append(
            {
                "path": service_account_path,
                "expected": "generated artifact",
                "received": None,
            }
        )
    else:
        service_account = _yaml_mapping(artifacts[service_account_path])
        if service_account is None:
            mismatches.append(
                {
                    "path": service_account_path,
                    "expected": "one YAML mapping",
                    "received": None,
                }
            )
        else:
            _mismatch(
                mismatches,
                "kubernetes.serviceAccount.apiVersion",
                "v1",
                service_account.get("apiVersion"),
            )
            _mismatch(
                mismatches,
                "kubernetes.serviceAccount.kind",
                "ServiceAccount",
                service_account.get("kind"),
            )
            account_metadata = service_account.get("metadata")
            _mismatch(
                mismatches,
                "kubernetes.serviceAccount.name",
                str(model.security["serviceAccount"]),
                account_metadata.get("name")
                if isinstance(account_metadata, dict)
                else None,
            )
            _mismatch(
                mismatches,
                "kubernetes.serviceAccount.automount",
                False,
                service_account.get("automountServiceAccountToken"),
            )
    for environment in model.environments:
        root = f"k8s/overlays/{environment.name}"
        required = {
            "deployment": f"{root}/deployment.yaml",
            "service": f"{root}/service.yaml",
            "namespace": f"{root}/namespace.yaml",
            "kustomization": f"{root}/kustomization.yaml",
        }
        if has_config_map:
            required["configmap"] = f"{root}/configmap.yaml"
        if any(path not in artifacts for path in required.values()):
            mismatches.extend(
                {"path": path, "expected": "generated artifact", "received": None}
                for path in required.values()
                if path not in artifacts
            )
            continue
        documents = {
            name: _yaml_mapping(artifacts[path]) for name, path in required.items()
        }
        for name, document in documents.items():
            if document is None:
                mismatches.append(
                    {
                        "path": required[name],
                        "expected": "one YAML mapping",
                        "received": None,
                    }
                )
        if any(document is None for document in documents.values()):
            continue
        expected_identities = {
            "deployment": ("apps/v1", "Deployment"),
            "service": ("v1", "Service"),
            "namespace": ("v1", "Namespace"),
            "kustomization": (
                "kustomize.config.k8s.io/v1beta1",
                "Kustomization",
            ),
            "configmap": ("v1", "ConfigMap"),
        }
        for name, document in documents.items():
            if document is None:
                continue
            api_version, kind = expected_identities[name]
            _mismatch(
                mismatches,
                f"kubernetes.environments.{environment.name}.{name}.apiVersion",
                api_version,
                document.get("apiVersion"),
            )
            _mismatch(
                mismatches,
                f"kubernetes.environments.{environment.name}.{name}.kind",
                kind,
                document.get("kind"),
            )
        deployment = documents["deployment"] or {}
        service = documents["service"] or {}
        namespace = documents["namespace"] or {}
        kustomization = documents["kustomization"] or {}
        configmap = documents.get("configmap") or {}
        prefix = f"kubernetes.environments.{environment.name}"
        metadata = deployment.get("metadata", {})
        labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
        spec = deployment.get("spec", {})
        expected_deployment_spec_fields = {
            "replicas",
            "revisionHistoryLimit",
            "strategy",
            "selector",
            "template",
        }
        if environment.name == "production":
            expected_deployment_spec_fields.update(
                {"minReadySeconds", "progressDeadlineSeconds"}
            )
        _mismatch(
            mismatches,
            f"{prefix}.deploymentSpecFields",
            sorted(expected_deployment_spec_fields),
            sorted(spec) if isinstance(spec, dict) else None,
        )
        template = spec.get("template", {}) if isinstance(spec, dict) else {}
        pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
        containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
        container = containers[0] if containers and isinstance(containers[0], dict) else {}
        _mismatch(
            mismatches,
            f"{prefix}.containerCount",
            1,
            len(containers) if isinstance(containers, list) else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.containerName",
            model.service_name,
            container.get("name") if isinstance(container, dict) else None,
        )
        expected_pod_fields = {
            "serviceAccountName",
            "automountServiceAccountToken",
            "securityContext",
            "containers",
            "terminationGracePeriodSeconds",
            "nodeSelector",
        }
        _mismatch(
            mismatches,
            f"{prefix}.podFields",
            sorted(expected_pod_fields),
            sorted(pod_spec) if isinstance(pod_spec, dict) else None,
        )
        expected_container_fields = {
            "name",
            "image",
            "imagePullPolicy",
            "ports",
            "resources",
            "livenessProbe",
            "readinessProbe",
            "securityContext",
        }
        if has_config_map:
            expected_container_fields.add("envFrom")
        if environment.secret_refs:
            expected_container_fields.add("env")
        _mismatch(
            mismatches,
            f"{prefix}.containerFields",
            sorted(expected_container_fields),
            sorted(container) if isinstance(container, dict) else None,
        )
        _mismatch(mismatches, f"{prefix}.applicationName", model.application_name, labels.get("app.kubernetes.io/instance"))
        _mismatch(mismatches, f"{prefix}.serviceName", model.service_name, metadata.get("name") if isinstance(metadata, dict) else None)
        annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
        architecture_value = ",".join(model.architectures)
        _mismatch(
            mismatches,
            f"{prefix}.architectures",
            architecture_value,
            annotations.get("devops-stack.io/image-architectures")
            if isinstance(annotations, dict)
            else None,
        )
        _mismatch(mismatches, f"{prefix}.image", model.image_reference, container.get("image"))
        _mismatch(
            mismatches,
            f"{prefix}.imagePullPolicy",
            "IfNotPresent",
            container.get("imagePullPolicy") if isinstance(container, dict) else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.replicas",
            environment.replicas,
            spec.get("replicas") if isinstance(spec, dict) else None,
        )
        expected_revision_history = (
            int(environment.rollback["revisionHistoryLimit"])
            if environment.rollback.get("enabled", False)
            else 0
        )
        _mismatch(
            mismatches,
            f"{prefix}.revisionHistoryLimit",
            expected_revision_history,
            spec.get("revisionHistoryLimit") if isinstance(spec, dict) else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.rollout",
            {
                "type": environment.rollout["strategy"],
                "rollingUpdate": {
                    "maxUnavailable": environment.rollout["maxUnavailable"],
                    "maxSurge": environment.rollout["maxSurge"],
                },
            },
            spec.get("strategy") if isinstance(spec, dict) else None,
        )
        ports = container.get("ports", []) if isinstance(container, dict) else []
        port = ports[0].get("containerPort") if ports and isinstance(ports[0], dict) else None
        _mismatch(mismatches, f"{prefix}.containerPort", environment.container_port, port)
        _mismatch(
            mismatches,
            f"{prefix}.containerPorts",
            [
                {
                    "name": "http",
                    "containerPort": environment.container_port,
                    "protocol": "TCP",
                }
            ],
            ports,
        )
        liveness = container.get("livenessProbe", {}).get("httpGet", {}) if isinstance(container, dict) else {}
        readiness = container.get("readinessProbe", {}).get("httpGet", {}) if isinstance(container, dict) else {}
        _mismatch(mismatches, f"{prefix}.health", environment.health_path, liveness.get("path"))
        _mismatch(mismatches, f"{prefix}.readiness", environment.readiness_path, readiness.get("path"))
        liveness_probe = container.get("livenessProbe", {}) if isinstance(container, dict) else {}
        readiness_probe = container.get("readinessProbe", {}) if isinstance(container, dict) else {}
        _mismatch(
            mismatches,
            f"{prefix}.healthProbe",
            {
                "httpGet": {
                    "path": environment.health_path,
                    "port": environment.container_port,
                    "scheme": "HTTP",
                },
                "initialDelaySeconds": environment.health_initial_delay_seconds,
                "periodSeconds": environment.health_period_seconds,
                "timeoutSeconds": 2,
                "failureThreshold": 3,
            },
            liveness_probe,
        )
        _mismatch(
            mismatches,
            f"{prefix}.readinessProbe",
            {
                "httpGet": {
                    "path": environment.readiness_path,
                    "port": environment.container_port,
                    "scheme": "HTTP",
                },
                "initialDelaySeconds": environment.readiness_initial_delay_seconds,
                "periodSeconds": environment.readiness_period_seconds,
                "timeoutSeconds": 2,
                "failureThreshold": 3,
            },
            readiness_probe,
        )
        for probe_name, expected_probe, probe in (
            (
                "health",
                {
                    "initialDelaySeconds": environment.health_initial_delay_seconds,
                    "periodSeconds": environment.health_period_seconds,
                },
                liveness_probe,
            ),
            (
                "readiness",
                {
                    "initialDelaySeconds": environment.readiness_initial_delay_seconds,
                    "periodSeconds": environment.readiness_period_seconds,
                },
                readiness_probe,
            ),
        ):
            for field, expected in expected_probe.items():
                _mismatch(
                    mismatches,
                    f"{prefix}.{probe_name}.{field}",
                    expected,
                    probe.get(field) if isinstance(probe, dict) else None,
                )
        security = container.get("securityContext", {}) if isinstance(container, dict) else {}
        expected_container_security: dict[str, Any] = {
            "runAsNonRoot": bool(model.security["runAsNonRoot"]),
            "runAsUser": model.runtime_user,
            "allowPrivilegeEscalation": bool(
                model.security["allowPrivilegeEscalation"]
            ),
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {
                "type": model.security.get("seccompProfile", "RuntimeDefault")
            },
        }
        if model.security.get("readOnlyRootFilesystem"):
            expected_container_security["readOnlyRootFilesystem"] = True
        _mismatch(
            mismatches,
            f"{prefix}.containerSecurity",
            expected_container_security,
            security,
        )
        _mismatch(
            mismatches,
            f"{prefix}.resources",
            environment.resources,
            container.get("resources") if isinstance(container, dict) else None,
        )
        template_metadata = (
            template.get("metadata", {}) if isinstance(template, dict) else {}
        )
        pod_annotations = (
            template_metadata.get("annotations", {})
            if isinstance(template_metadata, dict)
            else {}
        )
        _mismatch(
            mismatches,
            f"{prefix}.podArchitectures",
            architecture_value,
            pod_annotations.get("devops-stack.io/image-architectures")
            if isinstance(pod_annotations, dict)
            else None,
        )
        node_selector = (
            pod_spec.get("nodeSelector", {}) if isinstance(pod_spec, dict) else {}
        )
        expected_selector = {"kubernetes.io/os": "linux"}
        if len(model.architectures) == 1:
            expected_selector["kubernetes.io/arch"] = model.architectures[0].split(
                "/", 1
            )[1]
        _mismatch(
            mismatches,
            f"{prefix}.nodeSelector",
            expected_selector,
            node_selector,
        )
        expected_pod_labels = {
            "app.kubernetes.io/name": model.service_name,
            "app.kubernetes.io/instance": model.application_name,
            "app.kubernetes.io/managed-by": "devops-stack-composer",
            "devops-stack.io/environment": environment.name,
        }
        _mismatch(
            mismatches,
            f"{prefix}.deploymentSelector",
            {"app.kubernetes.io/name": model.service_name},
            spec.get("selector", {}).get("matchLabels")
            if isinstance(spec.get("selector"), dict)
            else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.podLabels",
            expected_pod_labels,
            template_metadata.get("labels")
            if isinstance(template_metadata, dict)
            else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.serviceAccount",
            str(model.security["serviceAccount"]),
            pod_spec.get("serviceAccountName")
            if isinstance(pod_spec, dict)
            else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.automountServiceAccountToken",
            False,
            pod_spec.get("automountServiceAccountToken")
            if isinstance(pod_spec, dict)
            else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.terminationGracePeriodSeconds",
            30,
            pod_spec.get("terminationGracePeriodSeconds")
            if isinstance(pod_spec, dict)
            else None,
        )
        expected_pod_security = {
            "runAsNonRoot": bool(model.security["runAsNonRoot"]),
            "runAsUser": model.runtime_user,
            "seccompProfile": {
                "type": model.security.get("seccompProfile", "RuntimeDefault")
            },
        }
        _mismatch(
            mismatches,
            f"{prefix}.podSecurity",
            expected_pod_security,
            pod_spec.get("securityContext") if isinstance(pod_spec, dict) else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.configMapRef",
            (
                [{"configMapRef": {"name": f"{model.service_name}-config"}}]
                if has_config_map
                else None
            ),
            container.get("envFrom") if isinstance(container, dict) else None,
        )
        service_spec = service.get("spec", {})
        _mismatch(
            mismatches,
            f"{prefix}.serviceSpecFields",
            ["ports", "selector", "type"],
            sorted(service_spec) if isinstance(service_spec, dict) else None,
        )
        service_ports = service_spec.get("ports", []) if isinstance(service_spec, dict) else []
        service_port = service_ports[0] if service_ports and isinstance(service_ports[0], dict) else {}
        _mismatch(mismatches, f"{prefix}.servicePort", environment.service_port, service_port.get("port"))
        _mismatch(mismatches, f"{prefix}.targetPort", environment.container_port, service_port.get("targetPort"))
        _mismatch(
            mismatches,
            f"{prefix}.servicePorts",
            [
                {
                    "name": "http",
                    "port": environment.service_port,
                    "targetPort": environment.container_port,
                    "protocol": "TCP",
                }
            ],
            service_ports,
        )
        _mismatch(
            mismatches,
            f"{prefix}.serviceType",
            environment.service_type,
            service_spec.get("type") if isinstance(service_spec, dict) else None,
        )
        _mismatch(
            mismatches,
            f"{prefix}.serviceSelector",
            {"app.kubernetes.io/name": model.service_name},
            service_spec.get("selector") if isinstance(service_spec, dict) else None,
        )
        namespace_metadata = namespace.get("metadata", {})
        _mismatch(mismatches, f"{prefix}.namespaceResource", environment.namespace, namespace_metadata.get("name") if isinstance(namespace_metadata, dict) else None)
        _mismatch(mismatches, f"{prefix}.kustomizeNamespace", environment.namespace, kustomization.get("namespace"))
        expected_patches = ["deployment.yaml", "service.yaml"]
        if has_config_map:
            expected_patches.append("configmap.yaml")
        _mismatch(
            mismatches,
            f"{prefix}.kustomizeResources",
            ["../../base", "namespace.yaml"],
            kustomization.get("resources"),
        )
        _mismatch(
            mismatches,
            f"{prefix}.kustomizePatches",
            [{"path": path} for path in expected_patches],
            kustomization.get("patches"),
        )
        for name in ("deployment", "service", *(('configmap',) if has_config_map else ())):
            _mismatch(
                mismatches,
                f"{prefix}.{name}.patchStrategy",
                "replace",
                documents[name].get("$patch")
                if isinstance(documents.get(name), dict)
                else None,
            )
        actual_secret_refs: list[dict[str, str | None]] = []
        for item in container.get("env", []) if isinstance(container, dict) else []:
            if not isinstance(item, dict):
                continue
            value_from = item.get("valueFrom")
            reference = (
                value_from.get("secretKeyRef")
                if isinstance(value_from, dict)
                else None
            )
            if isinstance(reference, dict):
                actual_secret_refs.append(
                    {
                        "key": item.get("name"),
                        "name": reference.get("name"),
                        "secretKey": reference.get("key"),
                    }
                )
        expected_secret_refs = sorted(
            (
                {"key": str(key), "name": str(reference["name"]), "secretKey": str(key)}
                for reference in environment.secret_refs
                for key in reference.get("keys", ())
            ),
            key=lambda item: (item["key"], item["name"]),
        )
        _mismatch(
            mismatches,
            f"{prefix}.secretRefs",
            expected_secret_refs,
            sorted(
                actual_secret_refs,
                key=lambda item: (str(item["key"]), str(item["name"])),
            ),
        )
        expected_secret_environment = [
            {
                "name": str(key),
                "valueFrom": {
                    "secretKeyRef": {
                        "name": str(reference["name"]),
                        "key": str(key),
                    }
                },
            }
            for reference in environment.secret_refs
            for key in reference.get("keys", ())
        ]
        _mismatch(
            mismatches,
            f"{prefix}.secretEnvironment",
            expected_secret_environment or None,
            container.get("env") if isinstance(container, dict) else None,
        )
        if has_config_map:
            expected_environment = {
                key: (
                    "true"
                    if value is True
                    else "false"
                    if value is False
                    else str(value)
                )
                for key, value in sorted(environment.environment.items())
            }
            _mismatch(
                mismatches,
                f"{prefix}.environment",
                expected_environment,
                configmap.get("data") if isinstance(configmap, dict) else None,
            )
            configmap_metadata = (
                configmap.get("metadata") if isinstance(configmap, dict) else None
            )
            _mismatch(
                mismatches,
                f"{prefix}.configMapName",
                f"{model.service_name}-config",
                configmap_metadata.get("name")
                if isinstance(configmap_metadata, dict)
                else None,
            )
        namespace_labels = (
            namespace_metadata.get("labels", {})
            if isinstance(namespace_metadata, dict)
            else {}
        )
        _mismatch(
            mismatches,
            f"{prefix}.namespaceEnvironmentLabel",
            environment.name,
            namespace_labels.get("devops-stack.io/environment")
            if isinstance(namespace_labels, dict)
            else None,
        )
        if environment.name == "production":
            _mismatch(
                mismatches,
                f"{prefix}.minReadySeconds",
                10,
                spec.get("minReadySeconds") if isinstance(spec, dict) else None,
            )
            _mismatch(
                mismatches,
                f"{prefix}.progressDeadlineSeconds",
                600,
                spec.get("progressDeadlineSeconds")
                if isinstance(spec, dict)
                else None,
            )
            for label, expected in (
                ("pod-security.kubernetes.io/enforce", "restricted"),
                ("pod-security.kubernetes.io/enforce-version", "v1.30"),
                ("pod-security.kubernetes.io/audit", "restricted"),
                ("pod-security.kubernetes.io/warn", "restricted"),
            ):
                _mismatch(
                    mismatches,
                    f"{prefix}.{label}",
                    expected,
                    namespace_labels.get(label)
                    if isinstance(namespace_labels, dict)
                    else None,
                )
    return mismatches


def _artifact_contract_checks(
    model: NormalizedDevOpsModel,
    results: Iterable[AdapterResult],
) -> list[CheckResult]:
    validators = {
        "docker": _docker_artifact_mismatches,
        "jenkins": _jenkins_artifact_mismatches,
        "kubernetes": _kubernetes_artifact_mismatches,
    }
    checks: list[CheckResult] = []
    for result in results:
        validator = validators.get(result.adapter)
        if validator is None:
            continue
        try:
            shape_mismatches: list[dict[str, Any]] = []
            for index, artifact in enumerate(result.artifacts):
                if not isinstance(artifact.path, str) or not artifact.path:
                    shape_mismatches.append(
                        {
                            "path": f"{result.adapter}.artifacts[{index}].path",
                            "expected": "non-empty string",
                            "received": type(artifact.path).__name__,
                        }
                    )
                if not isinstance(artifact.content, str):
                    shape_mismatches.append(
                        {
                            "path": f"{result.adapter}.artifacts[{index}].content",
                            "expected": "string",
                            "received": type(artifact.content).__name__,
                        }
                    )
                if (
                    not isinstance(artifact.mode, int)
                    or isinstance(artifact.mode, bool)
                    or artifact.mode < 0
                    or artifact.mode > 0o7777
                ):
                    shape_mismatches.append(
                        {
                            "path": f"{result.adapter}.artifacts[{index}].mode",
                            "expected": "permission bits from 0000 through 07777",
                            "received": repr(artifact.mode),
                        }
                    )
                if not isinstance(artifact.origins, tuple) or any(
                    not isinstance(origin, str) or not origin
                    for origin in artifact.origins
                ):
                    shape_mismatches.append(
                        {
                            "path": f"{result.adapter}.artifacts[{index}].origins",
                            "expected": "tuple of non-empty strings",
                            "received": type(artifact.origins).__name__,
                        }
                    )
            if shape_mismatches:
                mismatches = shape_mismatches
            else:
                control_mismatches = [
                    {
                        "path": artifact.path,
                        "expected": "generated text without C0 control characters",
                        "received": "control character present",
                    }
                    for artifact in result.artifacts
                    if re.search(
                        r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]",
                        artifact.content,
                    )
                ]
                mismatches = [*control_mismatches, *validator(model, result)]
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            mismatches = [
                {
                    "path": f"{result.adapter}.artifact-shape",
                    "expected": "valid adapter artifact shapes",
                    "received": type(exc).__name__,
                }
            ]
        checks.append(
            CheckResult(
                check=f"contract.{result.adapter}.artifacts",
                scope=result.adapter,
                status=ValidationStatus.FAILED if mismatches else ValidationStatus.PASSED,
                message=(
                    f"{len(mismatches)} rendered contract value(s) differ"
                    if mismatches
                    else "rendered artifacts preserve the normalized contract"
                ),
                details={"mismatches": mismatches},
            )
        )
    return checks


def _contract_checks(
    model: NormalizedDevOpsModel,
    results: Iterable[AdapterResult],
) -> list[CheckResult]:
    from devops_stack_composer.adapters.docker import (
        ADAPTER_VERSION as DOCKER_ADAPTER_VERSION,
    )
    from devops_stack_composer.adapters.jenkins import (
        ADAPTER_VERSION as JENKINS_ADAPTER_VERSION,
    )
    from devops_stack_composer.adapters.kubernetes import (
        ADAPTER_VERSION as KUBERNETES_ADAPTER_VERSION,
    )

    expected = _flatten(model.contract())
    checks: list[CheckResult] = []
    materialized = tuple(results)
    result_map = {result.adapter: result for result in materialized}
    required = ("docker", "jenkins", "kubernetes")
    missing = [adapter for adapter in required if adapter not in result_map]
    received = [result.adapter for result in materialized]
    duplicates = sorted(
        adapter for adapter in required if received.count(adapter) > 1
    )
    unexpected = sorted(
        adapter
        for adapter in set(received)
        if adapter not in required
    )
    inventory_invalid = bool(missing or duplicates or unexpected)
    checks.append(
        CheckResult(
            check="contract.adapters-present",
            status=(
                ValidationStatus.FAILED
                if inventory_invalid
                else ValidationStatus.PASSED
            ),
            message=(
                "adapter result inventory is incomplete, duplicated, or unexpected"
                if inventory_invalid
                else "Docker, Jenkins, and Kubernetes adapter results are present"
            ),
            details={
                "missing": missing,
                "duplicates": duplicates,
                "unexpected": unexpected,
            },
        )
    )
    expected_versions = {
        "docker": DOCKER_ADAPTER_VERSION,
        "jenkins": JENKINS_ADAPTER_VERSION,
        "kubernetes": KUBERNETES_ADAPTER_VERSION,
    }
    metadata_mismatches: list[dict[str, Any]] = []
    for adapter, result in result_map.items():
        if adapter not in expected_versions:
            metadata_mismatches.append(
                {
                    "path": "$.adapters",
                    "expected": list(required),
                    "received": adapter,
                }
            )
            continue
        _mismatch(
            metadata_mismatches,
            f"$.adapters.{adapter}.adapterVersion",
            expected_versions[adapter],
            result.adapter_version,
        )
        if (
            not isinstance(result.template_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", result.template_commit) is None
            or result.template_commit == "0" * 40
        ):
            metadata_mismatches.append(
                {
                    "path": f"$.adapters.{adapter}.templateCommit",
                    "expected": "non-zero 40-character lowercase Git commit",
                    "received": result.template_commit,
                }
            )
    checks.append(
        CheckResult(
            check="contract.adapter-metadata",
            status=(
                ValidationStatus.FAILED
                if metadata_mismatches
                else ValidationStatus.PASSED
            ),
            message=(
                f"{len(metadata_mismatches)} adapter metadata value(s) differ"
                if metadata_mismatches
                else "adapter versions and commit identities have valid current shapes"
            ),
            details={"mismatches": metadata_mismatches},
        )
    )

    for adapter in required:
        if adapter not in result_map:
            continue
        actual = _flatten(result_map[adapter].contract)
        mismatches = []
        for path in sorted(set(expected) | set(actual)):
            if expected.get(path) != actual.get(path):
                mismatches.append(
                    {"path": path, "expected": expected.get(path), "received": actual.get(path)}
                )
        checks.append(
            CheckResult(
                check=f"contract.{adapter}",
                scope=adapter,
                status=ValidationStatus.FAILED if mismatches else ValidationStatus.PASSED,
                message=(
                    f"{len(mismatches)} normalized contract value(s) differ"
                    if mismatches
                    else "adapter contract matches the normalized model"
                ),
                details={"mismatches": mismatches},
            )
        )
    return checks


def _cpu_millicores(value: str) -> int:
    if value.endswith("m"):
        return int(value[:-1])
    return int(float(value) * 1000)


MEMORY_FACTORS = {
    "Ki": 1024,
    "Mi": 1024**2,
    "Gi": 1024**3,
    "Ti": 1024**4,
}


def _memory_bytes(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)(Ki|Mi|Gi|Ti)", value)
    if not match:
        raise ValueError(value)
    return int(match.group(1)) * MEMORY_FACTORS[match.group(2)]


def _semantic_checks(model: NormalizedDevOpsModel) -> list[CheckResult]:
    checks: list[CheckResult] = []
    container_ports = {environment.container_port for environment in model.environments}
    checks.append(
        CheckResult(
            check="contract.container-port",
            status=(ValidationStatus.PASSED if len(container_ports) == 1 else ValidationStatus.FAILED),
            message=(
                f"container port is consistently {next(iter(container_ports))}"
                if len(container_ports) == 1
                else "container port differs by environment and cannot map to one image contract"
            ),
            details={
                environment.name: environment.container_port for environment in model.environments
            },
        )
    )

    health_paths = {environment.health_path for environment in model.environments}
    readiness_paths = {environment.readiness_path for environment in model.environments}
    probes_consistent = len(health_paths) == 1 and len(readiness_paths) == 1
    checks.append(
        CheckResult(
            check="contract.health-endpoints",
            status=ValidationStatus.PASSED if probes_consistent else ValidationStatus.FAILED,
            message=(
                "health and readiness endpoints are consistent across environments"
                if probes_consistent
                else "health or readiness endpoint differs by environment"
            ),
            details={
                environment.name: {
                    "health": environment.health_path,
                    "readiness": environment.readiness_path,
                }
                for environment in model.environments
            },
        )
    )

    duplicate_branches: dict[str, list[str]] = {}
    for environment, patterns in model.branch_environment_map.items():
        for pattern in patterns:
            duplicate_branches.setdefault(pattern, []).append(environment)
    duplicates = {
        pattern: environments
        for pattern, environments in duplicate_branches.items()
        if len(environments) > 1
    }
    checks.append(
        CheckResult(
            check="contract.branch-environment-map",
            status=ValidationStatus.FAILED if duplicates else ValidationStatus.PASSED,
            message=(
                "branch patterns map to exactly one deployment environment"
                if not duplicates
                else "branch patterns map to multiple deployment environments"
            ),
            details={"duplicates": duplicates},
        )
    )

    resource_failures = []
    for environment in model.environments:
        requests = environment.resources["requests"]
        limits = environment.resources["limits"]
        if _cpu_millicores(requests["cpu"]) > _cpu_millicores(limits["cpu"]):
            resource_failures.append(f"{environment.name}: cpu request exceeds limit")
        if _memory_bytes(requests["memory"]) > _memory_bytes(limits["memory"]):
            resource_failures.append(f"{environment.name}: memory request exceeds limit")
    checks.append(
        CheckResult(
            check="policy.resource-units",
            status=ValidationStatus.FAILED if resource_failures else ValidationStatus.PASSED,
            message=(
                "; ".join(resource_failures)
                if resource_failures
                else "resource requests use valid units and do not exceed limits"
            ),
        )
    )

    production = model.environment("production")
    policy = model.policies["production"]
    production_failures = []
    if production.replicas < policy["minimumReplicas"]:
        production_failures.append(
            f"replicas {production.replicas} is below required {policy['minimumReplicas']}"
        )
    if policy["requireApproval"] and not model.production_approval:
        production_failures.append("production approval is required")
    if policy["requireResourceLimits"] and not production.resources.get("limits"):
        production_failures.append("production resource limits are required")
    if policy["requireResourceLimits"]:
        production_requests = production.resources["requests"]
        production_limits = production.resources["limits"]
        if (
            _cpu_millicores(production_requests["cpu"]) <= 0
            or _memory_bytes(production_requests["memory"]) <= 0
        ):
            production_failures.append("production resource requests must be positive")
        if (
            _cpu_millicores(production_limits["cpu"]) <= 0
            or _memory_bytes(production_limits["memory"]) <= 0
        ):
            production_failures.append("production resource limits must be positive")
    if policy["requireReadOnlyRootFilesystem"] and not model.security["readOnlyRootFilesystem"]:
        production_failures.append("readOnlyRootFilesystem is required")
    if not model.security["runAsNonRoot"] or model.runtime_user == 0:
        production_failures.append("non-root runtime is required")
    if model.security["allowPrivilegeEscalation"]:
        production_failures.append("privilege escalation must be disabled")
    if not production.rollback["enabled"]:
        production_failures.append("rollback history must be enabled")
    checks.append(
        CheckResult(
            check="policy.production-safety",
            status=ValidationStatus.FAILED if production_failures else ValidationStatus.PASSED,
            message=(
                "; ".join(production_failures)
                if production_failures
                else "production replicas, approval, resources, runtime security, and rollback satisfy policy"
            ),
            details={"failures": production_failures},
        )
    )

    duplicate_secret_keys: dict[str, list[str]] = {}
    plain_secret_collisions: dict[str, list[str]] = {}
    for environment in model.environments:
        seen: set[str] = set()
        duplicates_for_environment: list[str] = []
        for reference in environment.secret_refs:
            for key in reference["keys"]:
                if key in seen:
                    duplicates_for_environment.append(key)
                seen.add(key)
        if duplicates_for_environment:
            duplicate_secret_keys[environment.name] = sorted(set(duplicates_for_environment))
        collisions = sorted(set(environment.environment) & seen)
        if collisions:
            plain_secret_collisions[environment.name] = collisions
    secret_failures = bool(duplicate_secret_keys or plain_secret_collisions)
    checks.append(
        CheckResult(
            check="contract.secret-references",
            status=ValidationStatus.FAILED if secret_failures else ValidationStatus.PASSED,
            message=(
                "secret keys are unique and do not collide with plaintext environment values"
                if not secret_failures
                else "secret keys are duplicated or collide with plaintext environment values"
            ),
            details={
                "duplicates": duplicate_secret_keys,
                "plaintextCollisions": plain_secret_collisions,
            },
        )
    )

    rollout_failures: list[str] = []
    for environment in model.environments:
        unavailable = environment.rollout["maxUnavailable"]
        surge = environment.rollout["maxSurge"]
        if unavailable in {0, "0%"} and surge in {0, "0%"}:
            rollout_failures.append(
                f"{environment.name}: maxUnavailable and maxSurge cannot both be zero"
            )
        if environment.name == "production" and (
            unavailable == "100%"
            or (isinstance(unavailable, int) and unavailable >= environment.replicas)
        ):
            rollout_failures.append(
                "production: maxUnavailable can make every replica unavailable"
            )
    checks.append(
        CheckResult(
            check="policy.rollout-availability",
            status=(
                ValidationStatus.FAILED
                if rollout_failures
                else ValidationStatus.PASSED
            ),
            message=(
                "; ".join(rollout_failures)
                if rollout_failures
                else "rollout settings preserve at least one update path and production availability"
            ),
            details={"failures": rollout_failures},
        )
    )
    return checks


def validate_cross_project_contract(
    model: NormalizedDevOpsModel,
    results: Iterable[AdapterResult],
) -> ValidationReport:
    materialized = tuple(results)
    return ValidationReport(
        tuple(
            _contract_checks(model, materialized)
            + _artifact_contract_checks(model, materialized)
            + _semantic_checks(model)
        )
    )
