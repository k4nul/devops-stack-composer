"""Deterministic Jenkins projection of the normalized DevOps model."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable

from devops_stack_composer.adapters.base import (
    AdapterDiagnostic,
    AdapterResult,
    GeneratedArtifact,
)
from devops_stack_composer.model import EnvironmentModel, NormalizedDevOpsModel
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationStatus


ADAPTER_VERSION = "1.0.0"
GENERATED_ROOT = "generated"
MAX_UPSTREAM_JSON_BYTES = 256 * 1024
MAX_UPSTREAM_ENTRIES = 1000
MAX_UPSTREAM_EXPORT_BYTES = 1024 * 1024
PASSED = ValidationStatus.PASSED.value
FAILED = ValidationStatus.FAILED.value
SKIPPED_MISSING_OPTIONAL_TOOL = ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value
BLOCKED_MISSING_REQUIRED_TOOL = ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value

_TOKEN_LIKE_VALUE = re.compile(
    r"(?:ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|glpat-[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,})"
)
_BEARER_TOKEN = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{6,}")
_INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:api[-_]?key|credential|password|private[-_]?key|secret|token)\b\s*[:=]\s*)"
    r'(?:"[^"]*"|\'[^\']*\'|[^\s,;]+)'
)
_AUTHORIZATION_HEADER = re.compile(r"(?i)(\bauthorization\s*:\s*)[^\r\n,;]+")
_URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_EMBEDDED_WINDOWS_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s,;]+)")
_EMBEDDED_POSIX_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9._>\-])/(?:[^\s,;]+)")

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _groovy_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return f"'{escaped}'"


def _branch_when_lines(branches: tuple[str, ...], indent: str) -> list[str]:
    lines = [f"{indent}when {{"]
    if branches:
        lines.append(f"{indent}    anyOf {{")
        for branch in branches:
            lines.append(
                f"{indent}        branch pattern: {_groovy_string(branch)}, comparator: 'GLOB'"
            )
        lines.append(f"{indent}    }}")
    else:
        lines.append(f"{indent}    expression {{ return false }}")
    lines.append(f"{indent}}}")
    return lines


def _rollback_command(model: NormalizedDevOpsModel, environment: EnvironmentModel) -> str:
    return (
        f"kubectl rollout undo deployment/{model.service_name} "
        f"--namespace {environment.namespace}"
    )


def _deployment_render_script(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel,
) -> str:
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
  ''|{'__IMAGE_TAG__'}|.*|-*|*[!A-Za-z0-9_.-]*)
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
cp -R {GENERATED_ROOT}/k8s "$render_root/k8s"
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


def _deployment_stage_lines(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel,
) -> list[str]:
    rollout_flag = f"DEPLOY_{environment.name.upper()}_ROLLOUT_STARTED"
    rollout_command = (
        f"kubectl rollout status deployment/{model.service_name} "
        f"--namespace {environment.namespace} --timeout=5m"
    )
    lines = [f"        stage('Deploy {environment.name}') {{"]
    lines.extend(
        _branch_when_lines(model.branch_environment_map[environment.name], "            ")
    )
    lines.extend(
        [
            "            steps {",
            "                script {",
            f"                    env.{rollout_flag} = 'false'",
            f"                    String deploymentResult = sh(script: {_groovy_string(_deployment_render_script(model, environment))}, returnStdout: true).trim()",
            "                    List deploymentParts = deploymentResult.tokenize('|')",
            "                    if (deploymentParts.size() != 2 || !['true', 'false'].contains(deploymentParts[0]) || !(deploymentParts[1] ==~ /[0-9]+/)) {",
            "                        error('kubectl apply returned an invalid rollout-state result.')",
            "                    }",
            f"                    env.{rollout_flag} = deploymentParts[0]",
            "                    if (deploymentParts[1] != '0') {",
            "                        error('kubectl apply failed after rollout-state detection.')",
            "                    }",
            f"                    sh {_groovy_string(rollout_command)}",
            "                }",
            "            }",
            "            post {",
            "                failure {",
        ]
    )
    if environment.rollback.get("enabled", False):
        lines.extend(
            [
                "                    script {",
                f"                        if (env.{rollout_flag} == 'true') {{",
                f"                            sh {_groovy_string(_rollback_command(model, environment))}",
                "                        } else {",
                f"                            echo {_groovy_string(f'Rollback skipped for {environment.name}: apply did not start a rollout.')}",
                "                        }",
                "                    }",
            ]
        )
    else:
        lines.append(
            f"                    echo {_groovy_string(f'Rollback is disabled for {environment.name}.')}"
        )
    lines.extend(
        [
            "                }",
            "            }",
            "        }",
            "",
        ]
    )
    return lines


def _image_tag_stage_lines(model: NormalizedDevOpsModel) -> list[str]:
    lines = [
        "        stage('Resolve Image Tag') {",
        "            steps {",
        "                script {",
        "                    env.GIT_COMMIT_SHA = sh(script: 'git rev-parse --short=12 HEAD', returnStdout: true).trim()",
    ]
    if model.image_tag_strategy == "fixed":
        lines.append(f"                    env.IMAGE_TAG = {_groovy_string(model.image_tag)}")
    elif model.image_tag_strategy == "git-sha":
        lines.append('                    env.IMAGE_TAG = "${env.GIT_COMMIT_SHA}"')
    elif model.image_tag_strategy == "semver":
        lines.extend(
            [
                "                    if (!params.VERSION?.trim()) {",
                "                        error('VERSION is required for the semver image tag strategy.')",
                "                    }",
                "                    env.IMAGE_TAG = params.VERSION.trim()",
            ]
        )
    else:
        lines.extend(
            [
                "                    String branchSlug = (env.BRANCH_NAME ?: 'detached').toLowerCase().replaceAll('[^a-z0-9._-]+', '-').replaceAll('^[.-]+|[.-]+$', '')",
                "                    if (!branchSlug) { branchSlug = 'detached' }",
                "                    env.BRANCH_SLUG = branchSlug.take(115)",
                '                    env.IMAGE_TAG = "${env.BRANCH_SLUG}-${env.GIT_COMMIT_SHA}"',
            ]
        )
    lines.extend(
        [
            "                    if (!(env.IMAGE_TAG ==~ /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/) || env.IMAGE_TAG == '__IMAGE_TAG__') {",
            "                        error('Resolved image tag is not Docker-safe.')",
            "                    }",
            '                    env.IMAGE_REF = "${env.IMAGE_REPOSITORY}:${env.IMAGE_TAG}"',
            '                    env.OCI_REVISION = "${env.GIT_COMMIT_SHA}"',
            "                    env.OCI_CREATED = sh(script: 'git show -s --format=%cI HEAD', returnStdout: true).trim()",
            "                }",
            "            }",
            "        }",
            "",
        ]
    )
    return lines


def _scan_severities(fail_on: str) -> str:
    thresholds = {
        "low": "LOW,MEDIUM,HIGH,CRITICAL",
        "medium": "MEDIUM,HIGH,CRITICAL",
        "high": "HIGH,CRITICAL",
        "critical": "CRITICAL",
    }
    return thresholds.get(fail_on.lower(), fail_on.upper())


def _supply_chain_lines(
    model: NormalizedDevOpsModel,
    routed_branches: tuple[str, ...],
) -> list[str]:
    commands: list[str] = []
    sbom = model.supply_chain.get("sbom", {})
    scan = model.supply_chain.get("scan", {})
    provenance = model.supply_chain.get("provenance", {})

    if sbom.get("enabled", False):
        output_format = str(sbom.get("format", "spdx-json"))
        commands.append(
            "mkdir -p out/supply-chain && "
            f"syft \"$IMAGE_REF\" -o {output_format}=out/supply-chain/sbom.json"
        )
    if scan.get("enabled", False):
        fail_on = str(scan.get("failOn", "high"))
        severities = (
            "LOW,MEDIUM,HIGH,CRITICAL" if fail_on == "never" else _scan_severities(fail_on)
        )
        exit_code = 0 if fail_on == "never" else 1
        commands.append(
            f'trivy image --exit-code {exit_code} --severity {severities} "$IMAGE_REF"'
        )
    if provenance.get("enabled", False):
        mode = str(provenance.get("mode", "max"))
        commands.append(
            f"echo 'Provenance mode {mode} is delegated to docker/build.sh.'"
        )
    if not commands:
        commands.append("echo 'Supply-chain checks are disabled by the normalized model.'")

    lines = [
        "        stage('Supply Chain Scan') {",
    ]
    lines.extend(_branch_when_lines(routed_branches, "            "))
    lines.append("            steps {")
    lines.extend(f"                sh {_groovy_string(command)}" for command in commands)
    if sbom.get("enabled", False):
        lines.extend(
            [
                "                archiveArtifacts artifacts: 'out/supply-chain/sbom.json', fingerprint: true, onlyIfSuccessful: true",
            ]
        )
    lines.extend(
        [
            "            }",
            "        }",
            "",
        ]
    )
    return lines


def _docker_template_stage_lines() -> list[str]:
    return [
        "        stage('Resolve Docker Template') {",
        "            steps {",
        "                script {",
        "                    String templateRoot = env.DEVOPS_STACK_DOCKER_TEMPLATE?.trim()",
        "                    if (!templateRoot) {",
        "                        templateRoot = sh(script: 'devops-stack templates path docker', returnStdout: true).trim()",
        "                    }",
        "                    if (!templateRoot) {",
        "                        error('Unable to resolve the locked Docker template checkout.')",
        "                    }",
        "                    env.DEVOPS_STACK_DOCKER_TEMPLATE = templateRoot",
        "                }",
        "            }",
        "        }",
        "",
    ]


def _authenticated_push_script() -> str:
    return f"""set +x
set -eu
docker_config=$(mktemp -d "${{TMPDIR:-/tmp}}/devops-stack-docker-config.XXXXXX")
export DOCKER_CONFIG="$docker_config"
cleanup() {{
  docker logout "$IMAGE_REGISTRY" >/dev/null 2>&1 || true
  rm -rf "$docker_config"
}}
trap cleanup EXIT HUP INT TERM
printf '%s' "$REGISTRY_PASSWORD" | docker login "$IMAGE_REGISTRY" --username "$REGISTRY_USER" --password-stdin
./{GENERATED_ROOT}/docker/build.sh --push"""


def _render_jenkinsfile(model: NormalizedDevOpsModel) -> str:
    all_branches = tuple(
        dict.fromkeys(
            branch
            for environment in ("dev", "staging", "production")
            for branch in model.branch_environment_map[environment]
        )
    )
    local_supply_chain_requested = bool(
        model.supply_chain.get("sbom", {}).get("enabled", False)
        or model.supply_chain.get("scan", {}).get("enabled", False)
    )
    lines = [
        "// Generated by devops-stack-composer. Do not store credential values here.",
        "pipeline {",
        "    agent any",
        "",
        "    options {",
        "        timestamps()",
        "        disableConcurrentBuilds()",
        "    }",
    ]
    if model.image_tag_strategy == "semver":
        lines.extend(
            [
                "",
                "    parameters {",
                "        string(name: 'VERSION', defaultValue: '', description: 'Semantic version used as the image tag.')",
                "    }",
            ]
        )
    lines.extend(
        [
            "",
            "    environment {",
            f"        IMAGE_REGISTRY = {_groovy_string(model.image_registry)}",
            f"        IMAGE_REPOSITORY = {_groovy_string(model.image_name)}",
            f"        REGISTRY_CREDENTIAL_ID = {_groovy_string(model.credential_id)}",
            "    }",
            "",
            "    stages {",
        ]
    )
    lines.extend(_image_tag_stage_lines(model))
    lines.extend(_docker_template_stage_lines())
    lines.extend(
        [
            "        stage('Build') {",
            "            steps {",
            f"                sh {_groovy_string(model.build_command)}",
            "            }",
            "        }",
            "",
            "        stage('Test') {",
            "            steps {",
            f"                sh {_groovy_string(model.test_command)}",
            "            }",
            "        }",
            "",
            "        stage('Container Plan Validation') {",
            "            steps {",
            f"                sh './{GENERATED_ROOT}/docker/build.sh --validate'",
            "            }",
            "        }",
            "",
        ]
    )
    lines.append("        stage('Container Build') {")
    lines.extend(_branch_when_lines(all_branches, "            "))
    lines.append("            steps {")
    if local_supply_chain_requested and len(model.architectures) == 1:
        lines.append(f"                sh './{GENERATED_ROOT}/docker/build.sh --load'")
    elif local_supply_chain_requested:
        lines.append(
            "                error('Local SBOM and image scanning require exactly one configured architecture before registry publication.')"
        )
    else:
        lines.append(
            "                echo 'Local image build is not required because local SBOM and image scanning are disabled.'"
        )
    lines.extend(["            }", "        }", ""])
    lines.extend(_supply_chain_lines(model, all_branches))
    lines.extend(["        stage('Registry Push') {"])
    lines.extend(_branch_when_lines(all_branches, "            "))
    lines.extend(
        [
            "            steps {",
            "                withCredentials([usernamePassword(credentialsId: env.REGISTRY_CREDENTIAL_ID, usernameVariable: 'REGISTRY_USER', passwordVariable: 'REGISTRY_PASSWORD')]) {",
            f"                    sh {_groovy_string(_authenticated_push_script())}",
            "                }",
            "            }",
            "        }",
            "",
        ]
    )
    lines.extend(_deployment_stage_lines(model, model.environment("dev")))
    lines.extend(_deployment_stage_lines(model, model.environment("staging")))

    if model.production_approval:
        lines.append("        stage('Production Approval') {")
        lines.extend(
            _branch_when_lines(model.branch_environment_map["production"], "            ")
        )
        lines.extend(
            [
                "            steps {",
                "                timeout(time: 1, unit: 'HOURS') {",
                f"                    input message: {_groovy_string(f'Approve production deployment for {model.application_name}?')}, ok: 'Deploy to production'",
                "                }",
                "            }",
                "        }",
                "",
            ]
        )

    lines.extend(_deployment_stage_lines(model, model.environment("production")))
    lines.extend(
        [
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_job_dsl(model: NormalizedDevOpsModel) -> str:
    return "\n".join(
        [
            "// Generated by devops-stack-composer.",
            "// SCM values are seed bindings owned by external controller/JCasC configuration.",
            "String repositoryUrl = binding.hasVariable('SCM_REPOSITORY_URL') ? binding.getVariable('SCM_REPOSITORY_URL').toString() : 'REPLACE_WITH_SCM_REPOSITORY_URL'",
            "String branchIncludes = binding.hasVariable('SCM_BRANCH_INCLUDES') ? binding.getVariable('SCM_BRANCH_INCLUDES').toString() : '**'",
            "String scmCredentialsId = binding.hasVariable('SCM_CREDENTIALS_ID') ? binding.getVariable('SCM_CREDENTIALS_ID').toString() : ''",
            "",
            "if (repositoryUrl == 'REPLACE_WITH_SCM_REPOSITORY_URL') {",
            "    throw new IllegalArgumentException('SCM_REPOSITORY_URL must be supplied by the seed job.')",
            "}",
            "if (repositoryUrl.contains('\\r') || repositoryUrl.contains('\\n')) {",
            "    throw new IllegalArgumentException('SCM_REPOSITORY_URL must not contain control characters.')",
            "}",
            "int schemeSeparator = repositoryUrl.indexOf('://')",
            "if (schemeSeparator >= 0) {",
            "    String authority = repositoryUrl.substring(schemeSeparator + 3).tokenize('/')[0]",
            "    if (authority.contains('@')) {",
            "        throw new IllegalArgumentException('SCM_REPOSITORY_URL must not contain credentials or URL userinfo.')",
            "    }",
            "}",
            "",
            f"multibranchPipelineJob({_groovy_string(model.application_name)}) {{",
            "    description('Generated multibranch DevOps pipeline. Runtime policy lives in generated/jenkins/Jenkinsfile.')",
            "    branchSources {",
            "        git {",
            f"            id({_groovy_string(f'{model.application_name}-scm')})",
            "            remote(repositoryUrl)",
            "            if (scmCredentialsId?.trim()) {",
            "                credentialsId(scmCredentialsId)",
            "            }",
            "            includes(branchIncludes)",
            "        }",
            "    }",
            "    factory {",
            "        workflowBranchProjectFactory {",
            f"            scriptPath('{GENERATED_ROOT}/jenkins/Jenkinsfile')",
            "        }",
            "    }",
            "    orphanedItemStrategy {",
            "        discardOldItems {",
            "            numToKeep(30)",
            "        }",
            "    }",
            "}",
            "",
        ]
    )


def _render_boundary(model: NormalizedDevOpsModel, template_commit: str) -> str:
    routes = [
        f"- `{environment}`: {', '.join(model.branch_environment_map[environment]) or 'none'}"
        for environment in ("dev", "staging", "production")
    ]
    return "\n".join(
        [
            "# Jenkins ownership boundary",
            "",
            "This directory is generated by `devops-stack-composer` from the normalized model",
            f"and Jenkins template commit `{template_commit}`.",
            "",
            "- **Job DSL** (`job-dsl.groovy`) owns the SCM-backed multibranch job, checkout",
            "  configuration, script path, and retention. Its repository URL, branch includes,",
            "  and optional SCM credential ID are supplied as seed bindings.",
            "- **Pipeline DSL** (`Jenkinsfile`) owns build, test, image, supply-chain, push,",
            "  branch routing, production approval, deployment, and rollback behavior.",
            "- **External JCasC/controller configuration** owns plugin installation, the seed",
            "  job, agents and tools, security realms, authorization, and credential values.",
            "  Credential values must never be committed or passed through this adapter.",
            f"- Generated paths assume the default `{GENERATED_ROOT}/` output directory.",
            "- Jenkins resolves the locked Docker template from `DEVOPS_STACK_DOCKER_TEMPLATE`",
            "  or `devops-stack templates path docker` on a clean agent.",
            "- Kubernetes image overrides are rendered in a temporary copy; generated files",
            "  remain immutable during deployment.",
            "",
            f"Registry operations reference Jenkins credential ID `{model.credential_id}` only.",
            "",
            "## Branch routing",
            "",
            *routes,
            "",
        ]
    )


def _render_environment(model: NormalizedDevOpsModel, environment: EnvironmentModel) -> str:
    value = {
        "schemaVersion": "1.0.0",
        "environment": environment.name,
        "branchPatterns": list(model.branch_environment_map[environment.name]),
        "image": model.image_reference,
        "imageTagExpression": model.image_tag_expression,
        "kubernetesOverlay": f"{GENERATED_ROOT}/k8s/overlays/{environment.name}",
        "namespace": environment.namespace,
        "productionApproval": (
            model.production_approval if environment.name == "production" else False
        ),
        "replicas": environment.replicas,
    }
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _sanitize_upstream_string(value: str, source_roots: tuple[Path, ...]) -> str:
    sanitized = value
    for source_root in source_roots:
        sanitized = sanitized.replace(str(source_root), "__TEMPLATE_SOURCE__")
    sanitized = _TOKEN_LIKE_VALUE.sub("<redacted-token>", sanitized)
    sanitized = _BEARER_TOKEN.sub(r"\1<redacted>", sanitized)
    sanitized = _AUTHORIZATION_HEADER.sub(r"\1<redacted>", sanitized)
    sanitized = _INLINE_SECRET.sub(r"\1<redacted>", sanitized)
    sanitized = _URL_USERINFO.sub(r"\1<redacted>@", sanitized)
    if Path(sanitized).is_absolute() or _WINDOWS_ABSOLUTE.match(sanitized):
        return "<absolute-path>"
    sanitized = _EMBEDDED_WINDOWS_ABSOLUTE.sub("<absolute-path>", sanitized)
    sanitized = _EMBEDDED_POSIX_ABSOLUTE.sub("<absolute-path>", sanitized)
    return sanitized.replace("__TEMPLATE_SOURCE__", "<template-source>")


def _bounded_names(values: list[dict[str, Any]]) -> list[str]:
    return sorted(
        str(value.get("Name", ""))[:128]
        for value in values[:50]
        if isinstance(value.get("Name"), str) and value.get("Name")
    )


def _summarize_upstream_plan(
    check: str,
    payload: Any,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(payload, dict):
        return None, ["plan root must be a JSON object"]
    issues: list[str] = []
    if check == "jenkins_upstream_job_plan":
        selections = payload.get("Selections")
        service_jobs = payload.get("ServiceJobs")
        for key in ("JobRoot", "ServiceJobRoot"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                issues.append(f"{key} must be a non-empty string")
        if not isinstance(selections, list):
            issues.append("Selections must be an array")
            selections = []
        elif len(selections) > MAX_UPSTREAM_ENTRIES:
            issues.append(
                f"Selections must contain at most {MAX_UPSTREAM_ENTRIES} entries"
            )
            selections = selections[:MAX_UPSTREAM_ENTRIES]
        if not isinstance(service_jobs, list):
            issues.append("ServiceJobs must be an array")
            service_jobs = []
        elif len(service_jobs) > MAX_UPSTREAM_ENTRIES:
            issues.append(
                f"ServiceJobs must contain at most {MAX_UPSTREAM_ENTRIES} entries"
            )
            service_jobs = service_jobs[:MAX_UPSTREAM_ENTRIES]
        if payload.get("SelectionCount") != len(selections):
            issues.append("SelectionCount must equal the Selections length")
        if payload.get("ServiceJobCount") != len(service_jobs):
            issues.append("ServiceJobCount must equal the ServiceJobs length")
        for index, selection in enumerate(selections):
            if not isinstance(selection, dict):
                issues.append(f"Selections[{index}] must be an object")
                continue
            if not isinstance(selection.get("Name"), str) or not selection["Name"]:
                issues.append(f"Selections[{index}].Name must be non-empty")
            if not isinstance(selection.get("PipelineJobs"), list):
                issues.append(f"Selections[{index}].PipelineJobs must be an array")
            elif len(selection["PipelineJobs"]) > MAX_UPSTREAM_ENTRIES:
                issues.append(
                    f"Selections[{index}].PipelineJobs exceeds the entry limit"
                )
        for index, service_job in enumerate(service_jobs):
            if not isinstance(service_job, dict):
                issues.append(f"ServiceJobs[{index}] must be an object")
            elif not isinstance(service_job.get("Name"), str) or not service_job["Name"]:
                issues.append(f"ServiceJobs[{index}].Name must be non-empty")
        if issues:
            return None, issues[:20]
        return (
            {
                "schemaVersion": "jenkins-job-plan-summary-v1",
                "jobRoot": payload["JobRoot"][:128],
                "serviceJobRoot": payload["ServiceJobRoot"][:128],
                "selectionCount": len(selections),
                "selectionNames": _bounded_names(selections),
                "serviceJobCount": len(service_jobs),
                "serviceJobNames": _bounded_names(
                    [item for item in service_jobs if isinstance(item, dict)]
                ),
            },
            [],
        )

    services = payload.get("Services")
    common_environment = payload.get("CommonEnvironmentVariables")
    if not isinstance(services, list) or not services:
        issues.append("Services must be a non-empty array")
        services = []
    elif len(services) > MAX_UPSTREAM_ENTRIES:
        issues.append(f"Services must contain at most {MAX_UPSTREAM_ENTRIES} entries")
        services = services[:MAX_UPSTREAM_ENTRIES]
    if not isinstance(common_environment, list):
        issues.append("CommonEnvironmentVariables must be an array")
        common_environment = []
    elif len(common_environment) > MAX_UPSTREAM_ENTRIES:
        issues.append(
            "CommonEnvironmentVariables exceeds the upstream entry limit"
        )
        common_environment = common_environment[:MAX_UPSTREAM_ENTRIES]
    categories: dict[str, int] = {}
    for index, service in enumerate(services):
        if not isinstance(service, dict):
            issues.append(f"Services[{index}] must be an object")
            continue
        for key in ("Name", "ImageName", "Category"):
            if not isinstance(service.get(key), str) or not service[key]:
                issues.append(f"Services[{index}].{key} must be non-empty")
        if not isinstance(service.get("RequiredFiles"), list):
            issues.append(f"Services[{index}].RequiredFiles must be an array")
        if not isinstance(service.get("HasJenkinsfile"), bool):
            issues.append(f"Services[{index}].HasJenkinsfile must be boolean")
        category = service.get("Category")
        if isinstance(category, str) and category:
            categories[category[:128]] = categories.get(category[:128], 0) + 1
    if issues:
        return None, issues[:20]
    return (
        {
            "schemaVersion": "jenkins-service-plan-summary-v1",
            "serviceCount": len(services),
            "serviceNames": _bounded_names(services),
            "categories": dict(sorted(categories.items())),
            "commonEnvironmentVariableCount": len(common_environment),
        },
        [],
    )


def _local_supply_chain_capability(model: NormalizedDevOpsModel) -> AdapterDiagnostic:
    requested = tuple(
        name
        for name in ("sbom", "scan")
        if model.supply_chain.get(name, {}).get("enabled", False)
    )
    if requested and len(model.architectures) != 1:
        return AdapterDiagnostic(
            status=FAILED,
            check="jenkins_local_supply_chain_capability",
            message=(
                "Local pre-push SBOM and image scanning require exactly one "
                "architecture; the final registry tag will not be published."
            ),
            details={
                "architectures": list(model.architectures),
                "requested": list(requested),
            },
        )
    return AdapterDiagnostic(
        status=PASSED,
        check="jenkins_local_supply_chain_capability",
        message="The requested pre-push supply-chain checks have a local image path.",
        details={
            "architectures": list(model.architectures),
            "requested": list(requested),
        },
    )


def _docker_cache_capability(model: NormalizedDevOpsModel) -> AdapterDiagnostic:
    cache = model.build.get("cache", {})
    requested = bool(cache.get("enabled") or cache.get("from") or cache.get("to"))
    return AdapterDiagnostic(
        status=FAILED if requested else PASSED,
        check="jenkins_docker_cache_capability",
        message=(
            "Requested Docker cache inputs are unsupported by the locked Docker template; "
            "the Jenkins build and push path is blocked."
            if requested
            else "No unsupported Docker cache inputs were requested."
        ),
        details={"requested": requested},
    )


def _internal_structure_diagnostic(
    jenkinsfile: str,
    job_dsl: str,
) -> AdapterDiagnostic:
    issues: list[str] = []
    if jenkinsfile.count("{") != jenkinsfile.count("}"):
        issues.append("Jenkinsfile braces are unbalanced")
    if job_dsl.count("{") != job_dsl.count("}"):
        issues.append("Job DSL braces are unbalanced")
    required_jenkins = (
        "pipeline {",
        "stage('Container Plan Validation')",
        "stage('Supply Chain Scan')",
        "stage('Registry Push')",
        "kustomize edit set image",
    )
    for required in required_jenkins:
        if required not in jenkinsfile:
            issues.append(f"Jenkinsfile is missing {required}")
    required_job_dsl = (
        "multibranchPipelineJob(",
        "branchSources {",
        "workflowBranchProjectFactory {",
        f"scriptPath('{GENERATED_ROOT}/jenkins/Jenkinsfile')",
    )
    for required in required_job_dsl:
        if required not in job_dsl:
            issues.append(f"Job DSL is missing {required}")
    ordered_stages = (
        "stage('Build')",
        "stage('Test')",
        "stage('Container Plan Validation')",
        "stage('Container Build')",
        "stage('Supply Chain Scan')",
        "stage('Registry Push')",
    )
    positions = [jenkinsfile.find(stage) for stage in ordered_stages]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        issues.append("build, test, local scan, and final push stages are out of order")
    return AdapterDiagnostic(
        status=FAILED if issues else PASSED,
        check="jenkins_generated_structure",
        message=(
            "Generated Jenkins structural checks failed."
            if issues
            else (
                "Generated Jenkins structural invariants passed; this is not a "
                "controller-backed Declarative or Job DSL parse."
            )
        ),
        details={"issues": issues, "scope": "structural-only"},
    )


class JenkinsPipelineAdapter:
    """Render application-specific Jenkins artifacts and inspect upstream plans."""

    def __init__(
        self,
        source: SourceResolution,
        *,
        runner: CommandRunner = subprocess.run,
        pwsh_executable: str | None = None,
    ):
        if source.key != "jenkins":
            raise ValueError(
                f"JenkinsPipelineAdapter requires a jenkins source, received {source.key!r}"
            )
        self.source = source
        self._runner = runner
        self._pwsh_executable = pwsh_executable

    def render(
        self,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path | None = None,
        validate_upstream: bool = True,
    ) -> AdapterResult:
        del project_root  # Rendering is in-memory; callers own safe writes.
        template_commit = self.source.commit or "unknown"
        origin = f"jenkins-pipeline-template@{template_commit}"
        jenkinsfile = _render_jenkinsfile(model)
        job_dsl = _render_job_dsl(model)
        diagnostics: list[AdapterDiagnostic] = []
        if validate_upstream and not self.source.matches_lock:
            diagnostics.append(
                AdapterDiagnostic(
                    status=FAILED,
                    check="jenkins_template_lock",
                    message="Resolved Jenkins template commit does not match the lock file; upstream code was not executed.",
                    details={"resolvedCommit": self.source.commit},
                )
            )
        elif validate_upstream:
            diagnostics.extend(self._validate_upstream())
        diagnostics.extend(
            (
                _local_supply_chain_capability(model),
                _docker_cache_capability(model),
                _internal_structure_diagnostic(jenkinsfile, job_dsl),
            )
        )
        if validate_upstream:
            diagnostics.extend(self._external_syntax_diagnostics(jenkinsfile, job_dsl))
        artifacts = [
            GeneratedArtifact(
                path="jenkins/Jenkinsfile",
                content=jenkinsfile,
                origins=("normalized-model", origin),
            ),
            GeneratedArtifact(
                path="jenkins/job-dsl.groovy",
                content=job_dsl,
                origins=("normalized-model", origin),
            ),
            GeneratedArtifact(
                path="jenkins/README.md",
                content=_render_boundary(model, template_commit),
                origins=("normalized-model", origin),
            ),
        ]
        artifacts.extend(
            GeneratedArtifact(
                path=f"jenkins/environments/{environment.name}.json",
                content=_render_environment(model, environment),
                origins=("normalized-model", origin),
            )
            for environment in model.environments
        )
        return AdapterResult(
            adapter="jenkins",
            adapter_version=ADAPTER_VERSION,
            template_commit=template_commit,
            artifacts=tuple(artifacts),
            contract=model.contract(),
            diagnostics=tuple(diagnostics),
        )

    def generate(
        self,
        model: NormalizedDevOpsModel,
        *,
        project_root: Path | None = None,
        validate_upstream: bool = True,
    ) -> AdapterResult:
        return self.render(
            model,
            project_root=project_root,
            validate_upstream=validate_upstream,
        )

    def _pwsh(self) -> str | None:
        if self._pwsh_executable is not None:
            return self._pwsh_executable or None
        if self._runner is not subprocess.run:
            return "pwsh"
        return shutil.which("pwsh")

    @staticmethod
    def _minimal_environment(stage: Path) -> dict[str, str]:
        home = stage / ".home"
        temporary = stage / ".tmp"
        home.mkdir(exist_ok=True)
        temporary.mkdir(exist_ok=True)
        environment = {
            key: os.environ[key]
            for key in ("JAVA_HOME", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR")
            if key in os.environ and os.environ[key]
        }
        environment.setdefault("PATH", "/usr/bin:/bin")
        environment.update(
            {
                "DOTNET_CLI_HOME": str(home),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "POWERSHELL_TELEMETRY_OPTOUT": "1",
                "TMPDIR": str(temporary),
            }
        )
        return environment

    def _stage_locked_source(self, parent: Path) -> tuple[Path | None, AdapterDiagnostic]:
        commit = self.source.commit or ""
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
            return None, AdapterDiagnostic(
                status=FAILED,
                check="jenkins_template_archive",
                message="A full locked Git commit is required before upstream execution.",
            )
        try:
            archived = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.source.path),
                    "archive",
                    "--format=tar",
                    commit,
                ],
                check=False,
                capture_output=True,
                timeout=30,
                env=self._minimal_environment(parent),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, AdapterDiagnostic(
                status=FAILED,
                check="jenkins_template_archive",
                message=f"Locked Jenkins template archive could not run: {type(exc).__name__}.",
            )
        if archived.returncode != 0:
            stderr = archived.stderr.decode("utf-8", errors="replace")
            return None, AdapterDiagnostic(
                status=FAILED,
                check="jenkins_template_archive",
                message="Locked Jenkins template commit could not be archived.",
                details={
                    "returncode": archived.returncode,
                    "stderr": _sanitize_upstream_string(
                        stderr[-4000:],
                        (self.source.path,),
                    ),
                },
            )

        stage = parent / "template"
        stage.mkdir()
        try:
            with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
                members = archive.getmembers()
                for member in members:
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in member.name
                        or not (member.isfile() or member.isdir())
                    ):
                        raise ValueError(f"unsafe Git archive member: {member.name}")
                archive.extractall(stage, members=members)
        except (OSError, tarfile.TarError, ValueError) as exc:
            return None, AdapterDiagnostic(
                status=FAILED,
                check="jenkins_template_archive",
                message=f"Locked Jenkins template archive was unsafe or unreadable: {type(exc).__name__}.",
            )
        return stage, AdapterDiagnostic(
            status=PASSED,
            check="jenkins_template_archive",
            message="Upstream validation uses archived bytes from the locked Git commit.",
            details={"commit": commit},
        )

    def _external_syntax_diagnostics(
        self,
        jenkinsfile: str,
        job_dsl: str,
    ) -> tuple[AdapterDiagnostic, ...]:
        diagnostics: list[AdapterDiagnostic] = []
        groovy = shutil.which("groovy")
        if not groovy:
            diagnostics.append(
                AdapterDiagnostic(
                    status=SKIPPED_MISSING_OPTIONAL_TOOL,
                    check="jenkins_external_groovy_parse",
                    message="Groovy is unavailable; generated files received structural checks only.",
                    command=("groovy",),
                    details={"tool": "groovy"},
                )
            )
        else:
            with tempfile.TemporaryDirectory(prefix="devops-stack-groovy-") as directory:
                root = Path(directory)
                jenkinsfile_path = root / "Jenkinsfile"
                job_dsl_path = root / "job-dsl.groovy"
                jenkinsfile_path.write_text(jenkinsfile, encoding="utf-8")
                job_dsl_path.write_text(job_dsl, encoding="utf-8")
                command = (
                    groovy,
                    "-e",
                    "args.each { new GroovyShell().parse(new File(it)) }",
                    str(jenkinsfile_path),
                    str(job_dsl_path),
                )
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=self._minimal_environment(root),
                )
            diagnostics.append(
                AdapterDiagnostic(
                    status=PASSED if completed.returncode == 0 else FAILED,
                    check="jenkins_external_groovy_parse",
                    message=(
                        "Groovy parsed the generated Jenkinsfile and Job DSL."
                        if completed.returncode == 0
                        else "Groovy could not parse the generated Jenkinsfile or Job DSL."
                    ),
                    command=("groovy", "-e", "<parse-generated-groovy>"),
                    details={
                        "returncode": completed.returncode,
                        "stderr": _sanitize_upstream_string(
                            (completed.stderr or "")[-4000:],
                            (),
                        ),
                    },
                )
            )
        diagnostics.append(
            AdapterDiagnostic(
                status=SKIPPED_MISSING_OPTIONAL_TOOL,
                check="jenkins_declarative_lint",
                message=(
                    "No controller-backed Jenkins Declarative linter is configured; "
                    "Groovy parsing does not prove Jenkins plugin semantics."
                ),
                details={"tool": "Jenkins Declarative Linter"},
            )
        )
        return tuple(diagnostics)

    def _validate_upstream(self) -> tuple[AdapterDiagnostic, ...]:
        pwsh = self._pwsh()
        if not pwsh:
            return (
                AdapterDiagnostic(
                    status=BLOCKED_MISSING_REQUIRED_TOOL,
                    check="jenkins_upstream_validation",
                    message="PowerShell 7 (pwsh) is required to validate Jenkins template plans.",
                    command=("pwsh",),
                    details={"tool": "pwsh"},
                ),
            )

        diagnostics: list[AdapterDiagnostic] = []
        with tempfile.TemporaryDirectory(prefix="devops-stack-jenkins-") as directory:
            stage, archive_diagnostic = self._stage_locked_source(Path(directory))
            diagnostics.append(archive_diagnostic)
            if stage is None:
                return tuple(diagnostics)
            environment = self._minimal_environment(stage)
            checks = (
                ("jenkins_upstream_job_plan", "scripts/show-jenkins-job-plan.ps1"),
                (
                    "jenkins_upstream_service_pipeline_plan",
                    "scripts/show-service-pipeline-plan.ps1",
                ),
            )
            for check, script in checks:
                display_command = (
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    script,
                    "-Format",
                    "json",
                )
                command = (pwsh, *display_command[1:])
                try:
                    completed = self._runner(
                        command,
                        cwd=stage,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                except FileNotFoundError:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=BLOCKED_MISSING_REQUIRED_TOOL,
                            check=check,
                            message="PowerShell 7 (pwsh) was not found while validating the Jenkins template.",
                            command=display_command,
                            details={"tool": "pwsh"},
                        )
                    )
                    break
                except (OSError, subprocess.SubprocessError) as exc:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message=f"Jenkins upstream validation command could not run: {type(exc).__name__}",
                            command=display_command,
                        )
                    )
                    continue

                if completed.returncode != 0:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message="Jenkins upstream validation command failed.",
                            command=display_command,
                            details={
                                "returncode": completed.returncode,
                                "stderr": _sanitize_upstream_string(
                                    (completed.stderr or "")[-4000:],
                                    (stage, self.source.path),
                                ),
                            },
                        )
                    )
                    continue

                stdout = completed.stdout
                if not isinstance(stdout, str):
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message="Jenkins upstream validation did not return text output.",
                            command=display_command,
                        )
                    )
                    continue
                output_bytes = len(stdout.encode("utf-8"))
                if output_bytes > MAX_UPSTREAM_JSON_BYTES:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message=(
                                "Jenkins upstream validation exceeded the "
                                f"{MAX_UPSTREAM_JSON_BYTES}-byte JSON output limit."
                            ),
                            command=display_command,
                            details={"outputBytes": output_bytes},
                        )
                    )
                    continue
                try:
                    payload = json.loads(stdout)
                except json.JSONDecodeError as exc:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message="Jenkins upstream validation returned invalid JSON.",
                            command=display_command,
                            details={
                                "error": (
                                    f"JSONDecodeError at line {exc.lineno} "
                                    f"column {exc.colno}"
                                )
                            },
                        )
                    )
                    continue

                summary, issues = _summarize_upstream_plan(check, payload)
                if issues:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check=check,
                            message="Jenkins upstream plan did not match its expected interface.",
                            command=display_command,
                            details={"issues": issues},
                        )
                    )
                    continue

                diagnostics.append(
                    AdapterDiagnostic(
                        status=PASSED,
                        check=check,
                        message="Jenkins upstream plan rendered successfully.",
                        command=display_command,
                        details={"summary": summary},
                    )
                )

            exporter_output = "out/composer-job-dsl.groovy"
            exporter_display = (
                "pwsh",
                "-NoProfile",
                "-File",
                "scripts/export-jenkins-job-dsl.ps1",
                "-EnvironmentPreset",
                "dev",
                "-OutputPath",
                exporter_output,
            )
            exporter_command = (pwsh, *exporter_display[1:])
            try:
                exported = self._runner(
                    exporter_command,
                    cwd=stage,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except FileNotFoundError:
                diagnostics.append(
                    AdapterDiagnostic(
                        status=BLOCKED_MISSING_REQUIRED_TOOL,
                        check="jenkins_upstream_job_dsl_export",
                        message="PowerShell 7 (pwsh) was not found while validating the Job DSL exporter.",
                        command=exporter_display,
                        details={"tool": "pwsh"},
                    )
                )
            except (OSError, subprocess.SubprocessError) as exc:
                diagnostics.append(
                    AdapterDiagnostic(
                        status=FAILED,
                        check="jenkins_upstream_job_dsl_export",
                        message=f"Jenkins upstream Job DSL exporter could not run: {type(exc).__name__}",
                        command=exporter_display,
                    )
                )
            else:
                output_path = stage / exporter_output
                output_is_safe = (
                    output_path.is_file()
                    and not output_path.is_symlink()
                    and output_path.resolve().is_relative_to(stage.resolve())
                )
                if exported.returncode != 0 or not output_is_safe:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=FAILED,
                            check="jenkins_upstream_job_dsl_export",
                            message=(
                                "Jenkins upstream Job DSL exporter failed or returned an "
                                "unsafe output in the isolated stage."
                            ),
                            command=exporter_display,
                            details={
                                "returncode": exported.returncode,
                                "stderr": _sanitize_upstream_string(
                                    (exported.stderr or "")[-4000:],
                                    (stage, self.source.path),
                                ),
                            },
                        )
                    )
                else:
                    payload = output_path.read_bytes()
                    export_issues: list[str] = []
                    if not payload:
                        export_issues.append("exported Job DSL must not be empty")
                    if len(payload) > MAX_UPSTREAM_EXPORT_BYTES:
                        export_issues.append(
                            "exported Job DSL exceeds the bounded output limit"
                        )
                    try:
                        job_dsl = payload.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        job_dsl = ""
                        export_issues.append("exported Job DSL must be UTF-8 text")
                    for marker in (
                        "// Generated by scripts/export-jenkins-job-dsl.ps1.",
                        "pipelineJob('",
                    ):
                        if marker not in job_dsl:
                            export_issues.append(
                                f"exported Job DSL is missing marker {marker!r}"
                            )
                    if export_issues:
                        diagnostics.append(
                            AdapterDiagnostic(
                                status=FAILED,
                                check="jenkins_upstream_job_dsl_export",
                                message=(
                                    "Jenkins upstream Job DSL exporter output did not "
                                    "match its expected interface."
                                ),
                                command=exporter_display,
                                details={"issues": export_issues[:10]},
                            )
                        )
                    else:
                        diagnostics.append(
                            AdapterDiagnostic(
                                status=PASSED,
                                check="jenkins_upstream_job_dsl_export",
                                message="Jenkins upstream Job DSL exporter passed in the isolated stage.",
                                command=exporter_display,
                                details={
                                    "bytes": len(payload),
                                    "sha256": hashlib.sha256(payload).hexdigest(),
                                },
                            )
                        )
        return tuple(diagnostics)


JenkinsAdapter = JenkinsPipelineAdapter

__all__ = ["JenkinsAdapter", "JenkinsPipelineAdapter"]
