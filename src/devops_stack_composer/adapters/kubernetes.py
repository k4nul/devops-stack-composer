"""Render deterministic Kubernetes manifests from the normalized stack model."""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from devops_stack_composer.adapters.base import (
    AdapterDiagnostic,
    AdapterResult,
    GeneratedArtifact,
)
from devops_stack_composer.model import EnvironmentModel, NormalizedDevOpsModel
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationStatus


ADAPTER_VERSION = "1.0.0"
UPSTREAM_PROFILE = "minimal-application"
UPSTREAM_APPLICATION = "nginx-web"

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

_UPSTREAM_QUERIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("profileCatalog", "show-profile-catalog.ps1", ()),
    ("environmentPresetPlan", "show-environment-preset-plan.ps1", ()),
    ("renderMatrix", "show-render-matrix.ps1", ()),
    (
        "platformPlan",
        "show-platform-plan.ps1",
        (
            "-Profile",
            UPSTREAM_PROFILE,
            "-Applications",
            UPSTREAM_APPLICATION,
        ),
    ),
)

_VOLATILE_KEYS = {"generatedat", "generatedatutc"}
_SENSITIVE_KEY_PARTS = (
    "apikey",
    "authorization",
    "connectionstring",
    "credential",
    "password",
    "privatekey",
    "secret",
    "token",
)
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_EMBEDDED_WINDOWS_ABSOLUTE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s'\"<>]+)"
)
_EMBEDDED_POSIX_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9:/.])/(?:[^\s'\"<>]+)")


def _validation_status(status: ValidationStatus) -> str:
    return status.value


def _sanitize_string(value: str, source_root: Path) -> str:
    """Remove machine-specific absolute roots while preserving useful context."""

    source_text = str(source_root.resolve())
    if value == source_text:
        return "<template-source>"
    if source_text in value:
        return value.replace(source_text, "<template-source>")

    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(source_root.resolve()).as_posix() or "."
        except ValueError:
            return f"<absolute-path>/{path.name}"

    if _WINDOWS_ABSOLUTE.match(value):
        windows_path = PureWindowsPath(value)
        return f"<absolute-path>/{windows_path.name}"

    value = _EMBEDDED_WINDOWS_ABSOLUTE.sub("<absolute-path>", value)
    return _EMBEDDED_POSIX_ABSOLUTE.sub("<absolute-path>", value)


def sanitize_upstream_payload(value: Any, source_root: Path) -> Any:
    """Canonicalize JSON from read-only upstream inspection scripts."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key in sorted(value, key=str):
            normalized_key = re.sub(r"[_-]", "", str(key)).lower()
            if normalized_key in _VOLATILE_KEYS:
                continue
            if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
                sanitized[str(key)] = "<redacted>"
            else:
                sanitized[str(key)] = sanitize_upstream_payload(value[key], source_root)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize_upstream_payload(item, source_root) for item in value]
    if isinstance(value, str):
        return _sanitize_string(value, source_root)
    return value


def _yaml_document(value: Mapping[str, Any]) -> str:
    return yaml.safe_dump(
        dict(value),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def _labels(model: NormalizedDevOpsModel) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": model.service_name,
        "app.kubernetes.io/instance": model.application_name,
        "app.kubernetes.io/managed-by": "devops-stack-composer",
    }


def _config_value(value: str | int | float | bool) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _resources(environment: EnvironmentModel) -> dict[str, dict[str, str]]:
    return {
        key: {name: values[name] for name in sorted(values)}
        for key, values in sorted(environment.resources.items())
    }


def _secret_environment(environment: EnvironmentModel) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    pairs = sorted(
        (str(key), str(reference["name"]))
        for reference in environment.secret_refs
        for key in reference.get("keys", ())
    )
    for key, secret_name in pairs:
        references.append(
            {
                "name": key,
                "valueFrom": {
                    "secretKeyRef": {
                        "name": secret_name,
                        "key": key,
                    }
                },
            }
        )
    return references


def _security_context(model: NormalizedDevOpsModel) -> dict[str, Any]:
    security = model.security
    context: dict[str, Any] = {
        "runAsNonRoot": bool(security["runAsNonRoot"]),
        "runAsUser": model.runtime_user,
        "allowPrivilegeEscalation": bool(security["allowPrivilegeEscalation"]),
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": security.get("seccompProfile", "RuntimeDefault")},
    }
    if security.get("readOnlyRootFilesystem"):
        context["readOnlyRootFilesystem"] = True
    return context


def _pod_security_context(model: NormalizedDevOpsModel) -> dict[str, Any]:
    return {
        "runAsNonRoot": bool(model.security["runAsNonRoot"]),
        "runAsUser": model.runtime_user,
        "seccompProfile": {
            "type": model.security.get("seccompProfile", "RuntimeDefault"),
        },
    }


def _rollout_strategy(environment: EnvironmentModel) -> dict[str, Any]:
    return {
        "type": environment.rollout["strategy"],
        "rollingUpdate": {
            "maxUnavailable": environment.rollout["maxUnavailable"],
            "maxSurge": environment.rollout["maxSurge"],
        },
    }


def _revision_history_limit(environment: EnvironmentModel) -> int:
    if not environment.rollback.get("enabled", False):
        return 0
    return int(environment.rollback["revisionHistoryLimit"])


def _deployment(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel,
    *,
    has_config_map: bool,
    patch: bool,
) -> dict[str, Any]:
    labels = _labels(model)
    labels["devops-stack.io/environment"] = environment.name
    architecture_value = ",".join(model.architectures)
    container: dict[str, Any] = {
        "name": model.service_name,
        "image": model.image_reference,
        "imagePullPolicy": "IfNotPresent",
        "ports": [
            {
                "name": "http",
                "containerPort": environment.container_port,
                "protocol": "TCP",
            }
        ],
        "resources": _resources(environment),
        "livenessProbe": {
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
        "readinessProbe": {
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
        "securityContext": _security_context(model),
    }
    if has_config_map:
        container["envFrom"] = [
            {"configMapRef": {"name": f"{model.service_name}-config"}}
        ]
    secret_environment = _secret_environment(environment)
    if secret_environment:
        container["env"] = secret_environment

    pod_spec: dict[str, Any] = {
        "serviceAccountName": str(model.security["serviceAccount"]),
        "automountServiceAccountToken": False,
        "securityContext": _pod_security_context(model),
        "containers": [container],
        "terminationGracePeriodSeconds": 30,
        "nodeSelector": {"kubernetes.io/os": "linux"},
    }
    if len(model.architectures) == 1:
        pod_spec["nodeSelector"]["kubernetes.io/arch"] = model.architectures[0].split(
            "/", 1
        )[1]
    specification: dict[str, Any] = {
        "replicas": environment.replicas,
        "revisionHistoryLimit": _revision_history_limit(environment),
        "strategy": _rollout_strategy(environment),
        "selector": {"matchLabels": {"app.kubernetes.io/name": model.service_name}},
        "template": {
            "metadata": {
                "labels": labels,
                "annotations": {
                    "devops-stack.io/image-architectures": architecture_value
                },
            },
            "spec": pod_spec,
        },
    }
    if environment.name == "production":
        specification["minReadySeconds"] = 10
        specification["progressDeadlineSeconds"] = 600

    document: dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": model.service_name,
            "labels": _labels(model),
            "annotations": {
                "devops-stack.io/image-architectures": architecture_value
            },
        },
    }
    if patch:
        document["$patch"] = "replace"
    document["spec"] = specification
    return document


def _service(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel,
    *,
    patch: bool,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": model.service_name, "labels": _labels(model)},
    }
    if patch:
        document["$patch"] = "replace"
    document["spec"] = {
        "type": environment.service_type,
        "selector": {"app.kubernetes.io/name": model.service_name},
        "ports": [
            {
                "name": "http",
                "port": environment.service_port,
                "targetPort": environment.container_port,
                "protocol": "TCP",
            }
        ],
    }
    return document


def _config_map(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel | None,
    *,
    patch: bool,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": f"{model.service_name}-config",
            "labels": _labels(model),
        },
    }
    if patch:
        document["$patch"] = "replace"
    document["data"] = (
        {}
        if environment is None
        else {
            key: _config_value(environment.environment[key])
            for key in sorted(environment.environment)
        }
    )
    return document


def _namespace(
    model: NormalizedDevOpsModel,
    environment: EnvironmentModel,
) -> dict[str, Any]:
    labels = _labels(model)
    labels["devops-stack.io/environment"] = environment.name
    if environment.name == "production":
        labels.update(
            {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "v1.30",
                "pod-security.kubernetes.io/audit": "restricted",
                "pod-security.kubernetes.io/warn": "restricted",
            }
        )
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": environment.namespace,
            "labels": labels,
        },
    }


def _service_account(model: NormalizedDevOpsModel) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": str(model.security["serviceAccount"]),
            "labels": _labels(model),
        },
        "automountServiceAccountToken": False,
    }


def _kustomization(
    *,
    resources: Sequence[str],
    namespace: str | None = None,
    patches: Sequence[str] = (),
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
    }
    if namespace is not None:
        document["namespace"] = namespace
    document["resources"] = list(resources)
    if patches:
        document["patches"] = [{"path": path} for path in patches]
    return document


def _reference_exists(
    artifact_path: str,
    reference: str,
    artifact_paths: set[str],
) -> bool:
    base = PurePosixPath(artifact_path).parent
    candidate = posixpath.normpath(str(base / reference))
    return candidate in artifact_paths or f"{candidate}/kustomization.yaml" in artifact_paths


def _integer_in_range(value: Any, minimum: int, maximum: int | None = None) -> bool:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        return False
    return maximum is None or value <= maximum


def _tree_inventory(root: Path) -> tuple[list[Path], list[str]]:
    """List regular files and symlinks without traversing symbolic-link directories."""

    files: list[Path] = []
    symlinks: list[str] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        retained_directories: list[str] = []
        for name in directory_names:
            path = directory_path / name
            if path.is_symlink():
                symlinks.append(path.relative_to(root).as_posix())
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in file_names:
            path = directory_path / name
            if path.is_symlink():
                symlinks.append(path.relative_to(root).as_posix())
            elif path.is_file():
                files.append(path)
    return sorted(files), sorted(symlinks)


def _validate_probe(
    path: str,
    name: str,
    probe: Any,
    container_ports: set[int],
    errors: list[str],
) -> None:
    prefix = f"{path}: {name}"
    if not isinstance(probe, dict):
        errors.append(f"{prefix} must be a mapping")
        return
    http_get = probe.get("httpGet")
    if not isinstance(http_get, dict):
        errors.append(f"{prefix}.httpGet must be a mapping")
    else:
        endpoint = http_get.get("path")
        if not isinstance(endpoint, str) or not endpoint.startswith("/"):
            errors.append(f"{prefix}.httpGet.path must be an absolute HTTP path")
        port = http_get.get("port")
        if not _integer_in_range(port, 1, 65535) or port not in container_ports:
            errors.append(f"{prefix}.httpGet.port must match a container port")
    if not _integer_in_range(probe.get("initialDelaySeconds"), 0):
        errors.append(f"{prefix}.initialDelaySeconds must be a non-negative integer")
    if not _integer_in_range(probe.get("periodSeconds"), 1):
        errors.append(f"{prefix}.periodSeconds must be a positive integer")


def _validate_security_context(
    path: str,
    context: Any,
    errors: list[str],
    *,
    container: bool,
) -> None:
    if not isinstance(context, dict):
        errors.append(f"{path}: securityContext must be a mapping")
        return
    if not isinstance(context.get("runAsNonRoot"), bool):
        errors.append(f"{path}: securityContext.runAsNonRoot must be boolean")
    if not _integer_in_range(context.get("runAsUser"), 1):
        errors.append(f"{path}: securityContext.runAsUser must be a positive UID")
    seccomp = context.get("seccompProfile")
    if not isinstance(seccomp, dict) or seccomp.get("type") != "RuntimeDefault":
        errors.append(f"{path}: securityContext.seccompProfile.type must be RuntimeDefault")
    if not container:
        return
    if not isinstance(context.get("allowPrivilegeEscalation"), bool):
        errors.append(
            f"{path}: securityContext.allowPrivilegeEscalation must be boolean"
        )
    capabilities = context.get("capabilities")
    dropped = capabilities.get("drop") if isinstance(capabilities, dict) else None
    if not isinstance(dropped, list) or "ALL" not in dropped:
        errors.append(f"{path}: securityContext.capabilities.drop must include ALL")
    if "readOnlyRootFilesystem" in context and not isinstance(
        context["readOnlyRootFilesystem"], bool
    ):
        errors.append(
            f"{path}: securityContext.readOnlyRootFilesystem must be boolean when present"
        )


def _validate_resources(path: str, resources: Any, errors: list[str]) -> None:
    if not isinstance(resources, dict):
        errors.append(f"{path}: resources must be a mapping")
        return
    patterns = {
        "cpu": re.compile(r"^(?:[0-9]+m|[0-9]+(?:\.[0-9]+)?)$"),
        "memory": re.compile(r"^[0-9]+(?:Ki|Mi|Gi|Ti)$"),
    }
    for category in ("requests", "limits"):
        quantities = resources.get(category)
        if not isinstance(quantities, dict):
            errors.append(f"{path}: resources.{category} must be a mapping")
            continue
        for name, pattern in patterns.items():
            value = quantities.get(name)
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                errors.append(
                    f"{path}: resources.{category}.{name} is not a supported quantity"
                )


def _valid_int_or_percent(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"(?:0|[1-9][0-9]?|100)%", value)
    return match is not None


def _validate_deployment(path: str, document: Mapping[str, Any], errors: list[str]) -> None:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        errors.append(f"{path}: Deployment spec must be a mapping")
        return
    if not _integer_in_range(spec.get("replicas"), 0):
        errors.append(f"{path}: Deployment replicas must be a non-negative integer")
    if not _integer_in_range(spec.get("revisionHistoryLimit"), 0):
        errors.append(
            f"{path}: Deployment revisionHistoryLimit must be a non-negative integer"
        )
    strategy = spec.get("strategy")
    if not isinstance(strategy, dict) or strategy.get("type") != "RollingUpdate":
        errors.append(f"{path}: Deployment strategy must be RollingUpdate")
    elif not isinstance(strategy.get("rollingUpdate"), dict):
        errors.append(f"{path}: Deployment rollingUpdate settings are required")
    else:
        rolling_update = strategy["rollingUpdate"]
        for field in ("maxUnavailable", "maxSurge"):
            value = rolling_update.get(field)
            if not _valid_int_or_percent(value):
                errors.append(f"{path}: Deployment rollingUpdate.{field} is invalid")
        if rolling_update.get("maxUnavailable") in {0, "0%"} and rolling_update.get(
            "maxSurge"
        ) in {0, "0%"}:
            errors.append(
                f"{path}: Deployment rollingUpdate cannot set both controls to zero"
            )

    metadata = document.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    architecture_value = (
        annotations.get("devops-stack.io/image-architectures")
        if isinstance(annotations, dict)
        else None
    )
    architectures = (
        architecture_value.split(",")
        if isinstance(architecture_value, str) and architecture_value
        else []
    )
    if not architectures or any(
        architecture not in {"linux/amd64", "linux/arm64"}
        for architecture in architectures
    ):
        errors.append(f"{path}: Deployment image architecture annotation is invalid")

    selector = spec.get("selector")
    match_labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    template = spec.get("template")
    template_metadata = template.get("metadata") if isinstance(template, dict) else None
    pod_labels = (
        template_metadata.get("labels") if isinstance(template_metadata, dict) else None
    )
    pod_annotations = (
        template_metadata.get("annotations")
        if isinstance(template_metadata, dict)
        else None
    )
    if (
        not isinstance(pod_annotations, dict)
        or pod_annotations.get("devops-stack.io/image-architectures")
        != architecture_value
    ):
        errors.append(
            f"{path}: pod template image architecture annotation must match Deployment"
        )
    if not isinstance(match_labels, dict) or not match_labels:
        errors.append(f"{path}: Deployment selector.matchLabels is required")
    elif not isinstance(pod_labels, dict) or any(
        pod_labels.get(key) != value for key, value in match_labels.items()
    ):
        errors.append(f"{path}: Deployment selector must match pod template labels")

    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        errors.append(f"{path}: Deployment pod spec must be a mapping")
        return
    node_selector = pod_spec.get("nodeSelector")
    if (
        not isinstance(node_selector, dict)
        or node_selector.get("kubernetes.io/os") != "linux"
    ):
        errors.append(f"{path}: Linux image requires kubernetes.io/os nodeSelector")
    if len(architectures) == 1:
        expected_architecture = architectures[0].split("/", 1)[1]
        if (
            not isinstance(node_selector, dict)
            or node_selector.get("kubernetes.io/arch") != expected_architecture
        ):
            errors.append(
                f"{path}: single-architecture image requires matching nodeSelector"
            )
    if not isinstance(pod_spec.get("serviceAccountName"), str) or not pod_spec.get(
        "serviceAccountName"
    ):
        errors.append(f"{path}: Deployment serviceAccountName is required")
    if not isinstance(pod_spec.get("automountServiceAccountToken"), bool):
        errors.append(f"{path}: Deployment automountServiceAccountToken must be boolean")
    _validate_security_context(
        f"{path}: pod",
        pod_spec.get("securityContext"),
        errors,
        container=False,
    )

    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not containers:
        errors.append(f"{path}: Deployment must contain at least one container")
        return
    names: set[str] = set()
    for index, container in enumerate(containers):
        prefix = f"{path}: container[{index}]"
        if not isinstance(container, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        name = container.get("name")
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"{prefix}.name must be non-empty and unique")
        else:
            names.add(name)
        image = container.get("image")
        if not isinstance(image, str) or not image or ":" not in image:
            errors.append(f"{prefix}.image must include an explicit tag")
        ports = container.get("ports")
        container_ports: set[int] = set()
        if isinstance(ports, list):
            for port_index, item in enumerate(ports):
                if not isinstance(item, dict) or not _integer_in_range(
                    item.get("containerPort"), 1, 65535
                ):
                    errors.append(
                        f"{prefix}.ports[{port_index}].containerPort is invalid"
                    )
                else:
                    container_ports.add(item["containerPort"])
        if not container_ports:
            errors.append(f"{prefix}.ports must include a valid containerPort")
        _validate_probe(
            prefix,
            "livenessProbe",
            container.get("livenessProbe"),
            container_ports,
            errors,
        )
        _validate_probe(
            prefix,
            "readinessProbe",
            container.get("readinessProbe"),
            container_ports,
            errors,
        )
        _validate_resources(prefix, container.get("resources"), errors)
        _validate_security_context(
            prefix,
            container.get("securityContext"),
            errors,
            container=True,
        )
        environment_entries = container.get("env", [])
        if not isinstance(environment_entries, list):
            errors.append(f"{prefix}.env must be a list")
            environment_entries = []
        for item in environment_entries:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                errors.append(f"{prefix}.env entries require names")
                continue
            value_from = item.get("valueFrom")
            secret_ref = (
                value_from.get("secretKeyRef") if isinstance(value_from, dict) else None
            )
            if (
                "value" in item
                or not isinstance(secret_ref, dict)
                or not isinstance(secret_ref.get("name"), str)
                or not isinstance(secret_ref.get("key"), str)
                or set(secret_ref) - {"name", "key", "optional"}
            ):
                errors.append(
                    f"{prefix}.env entries must use name/key-only secretKeyRef values"
                )
        environment_from = container.get("envFrom", [])
        if not isinstance(environment_from, list):
            errors.append(f"{prefix}.envFrom must be a list")
        else:
            for item in environment_from:
                config_map_ref = (
                    item.get("configMapRef") if isinstance(item, dict) else None
                )
                if (
                    not isinstance(config_map_ref, dict)
                    or not isinstance(config_map_ref.get("name"), str)
                    or not config_map_ref.get("name")
                ):
                    errors.append(
                        f"{prefix}.envFrom entries require configMapRef.name"
                    )


def _validate_service(path: str, document: Mapping[str, Any], errors: list[str]) -> None:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        errors.append(f"{path}: Service spec must be a mapping")
        return
    if spec.get("type") not in {"ClusterIP", "NodePort", "LoadBalancer"}:
        errors.append(f"{path}: Service type is unsupported")
    if not isinstance(spec.get("selector"), dict) or not spec["selector"]:
        errors.append(f"{path}: Service selector is required")
    ports = spec.get("ports")
    if not isinstance(ports, list) or not ports:
        errors.append(f"{path}: Service must expose at least one port")
        return
    for index, port in enumerate(ports):
        if not isinstance(port, dict):
            errors.append(f"{path}: Service port[{index}] must be a mapping")
            continue
        if not _integer_in_range(port.get("port"), 1, 65535):
            errors.append(f"{path}: Service port[{index}].port is invalid")
        if not _integer_in_range(port.get("targetPort"), 1, 65535):
            errors.append(f"{path}: Service port[{index}].targetPort is invalid")


def validate_yaml_artifacts(
    artifacts: Sequence[GeneratedArtifact],
) -> AdapterDiagnostic:
    """Perform deterministic structural and Kubernetes semantic checks."""

    errors: list[str] = []
    artifact_paths = {artifact.path for artifact in artifacts}
    artifacts_by_path = {artifact.path: artifact for artifact in artifacts}
    if len(artifact_paths) != len(artifacts):
        errors.append("generated artifact paths are not unique")

    yaml_artifacts = [artifact for artifact in artifacts if artifact.path.endswith(".yaml")]
    parsed_documents: dict[str, dict[str, Any]] = {}
    for artifact in sorted(yaml_artifacts, key=lambda item: item.path):
        try:
            documents = list(yaml.safe_load_all(artifact.content))
        except yaml.YAMLError as exc:
            errors.append(f"{artifact.path}: invalid YAML: {exc}")
            continue
        if len(documents) != 1 or not isinstance(documents[0], dict):
            errors.append(f"{artifact.path}: expected exactly one YAML mapping")
            continue
        document = documents[0]
        parsed_documents[artifact.path] = document
        api_version = document.get("apiVersion")
        kind = document.get("kind")
        if not isinstance(api_version, str) or not api_version:
            errors.append(f"{artifact.path}: apiVersion is required")
        if not isinstance(kind, str) or not kind:
            errors.append(f"{artifact.path}: kind is required")
            continue
        if kind == "Secret":
            errors.append(f"{artifact.path}: generated Secret resources are forbidden")
        if kind == "Kustomization":
            resources = document.get("resources")
            if not isinstance(resources, list) or not resources:
                errors.append(f"{artifact.path}: Kustomization resources are required")
                resource_entries: list[Any] = []
            else:
                resource_entries = resources
                for reference in resources:
                    if not isinstance(reference, str) or not _reference_exists(
                        artifact.path, reference, artifact_paths
                    ):
                        errors.append(
                            f"{artifact.path}: missing resource reference {reference!r}"
                        )
            patches = document.get("patches", [])
            if not isinstance(patches, list):
                errors.append(f"{artifact.path}: Kustomization patches must be a list")
                patches = []
            for patch in patches:
                path = patch.get("path") if isinstance(patch, dict) else None
                if not isinstance(path, str) or not _reference_exists(
                    artifact.path, path, artifact_paths
                ):
                    errors.append(f"{artifact.path}: missing patch reference {path!r}")
            if "/overlays/" in artifact.path:
                namespace = document.get("namespace")
                namespace_path = str(PurePosixPath(artifact.path).parent / "namespace.yaml")
                namespace_document = parsed_documents.get(namespace_path)
                if namespace_document is None and namespace_path in artifacts_by_path:
                    try:
                        loaded_namespace = yaml.safe_load(
                            artifacts_by_path[namespace_path].content
                        )
                    except yaml.YAMLError:
                        loaded_namespace = None
                    if isinstance(loaded_namespace, dict):
                        namespace_document = loaded_namespace
                if not isinstance(namespace, str) or not namespace:
                    errors.append(f"{artifact.path}: overlay namespace is required")
                if "namespace.yaml" not in resource_entries:
                    errors.append(
                        f"{artifact.path}: overlay must include its Namespace resource"
                    )
                namespace_metadata = (
                    namespace_document.get("metadata")
                    if isinstance(namespace_document, dict)
                    else None
                )
                if (
                    not isinstance(namespace_document, dict)
                    or namespace_document.get("kind") != "Namespace"
                    or not isinstance(namespace_metadata, dict)
                    or namespace_metadata.get("name") != namespace
                ):
                    errors.append(
                        f"{artifact.path}: overlay Namespace identity must match namespace"
                    )
            continue
        metadata = document.get("metadata")
        if (
            not isinstance(metadata, dict)
            or not isinstance(metadata.get("name"), str)
            or not metadata.get("name")
        ):
            errors.append(f"{artifact.path}: metadata.name is required")
        if kind == "ConfigMap":
            data = document.get("data", {})
            if not isinstance(data, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in data.items()
            ):
                errors.append(f"{artifact.path}: ConfigMap data must contain only strings")
        elif kind == "Deployment":
            _validate_deployment(artifact.path, document, errors)
        elif kind == "Service":
            _validate_service(artifact.path, document, errors)
        elif kind == "ServiceAccount" and not isinstance(
            document.get("automountServiceAccountToken"), bool
        ):
            errors.append(
                f"{artifact.path}: ServiceAccount automountServiceAccountToken must be boolean"
            )

    return AdapterDiagnostic(
        status=_validation_status(
            ValidationStatus.FAILED if errors else ValidationStatus.PASSED
        ),
        check="kubernetes.yaml-structure",
        message=(
            f"{len(errors)} structural YAML error(s) found"
            if errors
            else f"{len(yaml_artifacts)} YAML artifacts are structurally and semantically valid"
        ),
        details={"errors": errors} if errors else {"artifactCount": len(yaml_artifacts)},
    )


class KubernetesAdapter:
    """Compose application manifests while querying upstream in read-only mode."""

    adapter_version = ADAPTER_VERSION

    def __init__(
        self,
        source: SourceResolution,
        *,
        runner: CommandRunner = subprocess.run,
    ) -> None:
        if source.key != "kubernetes":
            raise ValueError(
                f"KubernetesAdapter requires a kubernetes source, received {source.key!r}"
            )
        self.source = source
        self._runner = runner

    def render(
        self,
        model: NormalizedDevOpsModel,
        *,
        validate_upstream: bool = True,
    ) -> AdapterResult:
        if validate_upstream:
            upstream, upstream_diagnostics = self._read_upstream(model)
        else:
            upstream = {
                "schemaVersion": "k8s-integration-summary-v1",
                "selection": {
                    "profile": UPSTREAM_PROFILE,
                    "applications": [UPSTREAM_APPLICATION],
                },
                "source": {
                    "commit": self.source.commit or "unknown",
                    "matchesLock": self.source.matches_lock,
                },
                "queries": {},
                "render": {"status": "NOT_RUN"},
                "validators": {},
            }
            upstream_diagnostics = []
        artifacts = self._render_artifacts(model, upstream)
        diagnostics = [*upstream_diagnostics, validate_yaml_artifacts(artifacts)]
        diagnostics.extend(self._external_diagnostics(artifacts))
        return AdapterResult(
            adapter="kubernetes",
            adapter_version=self.adapter_version,
            template_commit=self.source.commit or "unknown",
            artifacts=tuple(sorted(artifacts, key=lambda item: item.path)),
            contract=model.contract(),
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _query_summary(key: str, payload: Any, template_root: Path) -> dict[str, Any]:
        sanitized = sanitize_upstream_payload(payload, template_root)
        document = sanitized if isinstance(sanitized, dict) else {}
        if key == "profileCatalog":
            profiles = document.get("Profiles", [])
            names = {
                item["Name"]
                for item in profiles
                if isinstance(item, dict) and isinstance(item.get("Name"), str)
            } if isinstance(profiles, list) else set()
            return {
                "profileCount": len(profiles) if isinstance(profiles, list) else 0,
                "selectedProfileAvailable": UPSTREAM_PROFILE in names,
            }
        if key == "environmentPresetPlan":
            presets = document.get("Presets", [])
            return {"presetCount": len(presets) if isinstance(presets, list) else 0}
        if key == "renderMatrix":
            entries = document.get("Entries", [])
            return {
                "entryCount": len(entries) if isinstance(entries, list) else 0
            }
        components = document.get("Components", [])
        profile = document.get("Profile")
        return {
            "profile": UPSTREAM_PROFILE if profile == UPSTREAM_PROFILE else "unexpected",
            "applicationCount": len(document.get("Applications", []))
            if isinstance(document.get("Applications"), list)
            else 0,
            "componentCount": len(components) if isinstance(components, list) else 0,
        }

    @staticmethod
    def _copy_template_source(source: Path, destination: Path) -> None:
        if not source.is_dir() or source.is_symlink():
            raise ValueError("template source must be a real directory")
        shutil.copytree(
            source,
            destination,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "out", "__pycache__", "*.pyc"),
        )
        _, symlinks = _tree_inventory(destination)
        if symlinks:
            raise ValueError("template source contains symbolic links")

    @staticmethod
    def _pwsh_command(script: str, *arguments: str) -> tuple[str, ...]:
        return (
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            f"scripts/{script}",
            *arguments,
        )

    def _read_upstream(
        self,
        model: NormalizedDevOpsModel,
    ) -> tuple[dict[str, Any], list[AdapterDiagnostic]]:
        summary: dict[str, Any] = {
            "schemaVersion": "k8s-integration-summary-v1",
            "selection": {
                "profile": UPSTREAM_PROFILE,
                "applications": [UPSTREAM_APPLICATION],
            },
            "source": {
                "commit": self.source.commit or "unknown",
                "matchesLock": self.source.matches_lock,
            },
            "queries": {},
            "render": {"status": "NOT_RUN"},
            "validators": {},
        }
        diagnostics: list[AdapterDiagnostic] = []
        if not self.source.matches_lock:
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(ValidationStatus.FAILED),
                    check="kubernetes.source-lock",
                    message="Kubernetes template source does not match the locked commit",
                    details={"commit": self.source.commit or "unknown"},
                )
            )
            return summary, diagnostics

        diagnostics.append(
            AdapterDiagnostic(
                status=_validation_status(ValidationStatus.PASSED),
                check="kubernetes.source-lock",
                message="Kubernetes template source matches the locked commit",
                details={"commit": self.source.commit or "unknown"},
            )
        )

        with tempfile.TemporaryDirectory(
            prefix="devops-stack-kubernetes-upstream-"
        ) as temporary:
            temporary_root = Path(temporary)
            template_root = temporary_root / "template"
            rendered_root = temporary_root / "rendered"
            try:
                self._copy_template_source(self.source.path, template_root)
            except (OSError, ValueError) as exc:
                diagnostics.append(
                    AdapterDiagnostic(
                        status=_validation_status(ValidationStatus.FAILED),
                        check="kubernetes.upstream.isolated-copy",
                        message=(
                            "Kubernetes template could not be copied into a symlink-safe "
                            f"ephemeral directory: {type(exc).__name__}"
                        ),
                    )
                )
                summary["render"] = {"status": ValidationStatus.FAILED.value}
                return summary, diagnostics
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(ValidationStatus.PASSED),
                    check="kubernetes.upstream.isolated-copy",
                    message="Kubernetes template was copied without source out/ or symlinks",
                )
            )

            for key, script_name, arguments in _UPSTREAM_QUERIES:
                command = self._pwsh_command(
                    script_name,
                    *arguments,
                    "-Format",
                    "json",
                )
                check_name = f"kubernetes.upstream.{key}"
                try:
                    completed = self._runner(
                        command,
                        cwd=template_root,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                except FileNotFoundError:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=_validation_status(
                                ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL
                            ),
                            check=check_name,
                            message="pwsh is required to inspect the Kubernetes template",
                            command=command,
                        )
                    )
                    summary["queries"][key] = {
                        "status": ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value
                    }
                    break
                except (OSError, subprocess.TimeoutExpired) as exc:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=_validation_status(ValidationStatus.FAILED),
                            check=check_name,
                            message=f"read-only upstream query failed: {type(exc).__name__}",
                            command=command,
                        )
                    )
                    summary["queries"][key] = {
                        "status": ValidationStatus.FAILED.value
                    }
                    continue

                if completed.returncode != 0:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=_validation_status(ValidationStatus.FAILED),
                            check=check_name,
                            message=(
                                "read-only upstream query exited with code "
                                f"{completed.returncode}"
                            ),
                            command=command,
                            details={"exitCode": completed.returncode},
                        )
                    )
                    summary["queries"][key] = {
                        "status": ValidationStatus.FAILED.value
                    }
                    continue
                try:
                    parsed = json.loads(completed.stdout)
                except (TypeError, json.JSONDecodeError):
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=_validation_status(ValidationStatus.FAILED),
                            check=check_name,
                            message="read-only upstream query did not return valid JSON",
                            command=command,
                        )
                    )
                    summary["queries"][key] = {
                        "status": ValidationStatus.FAILED.value
                    }
                    continue

                summary["queries"][key] = {
                    "status": ValidationStatus.PASSED.value,
                    **self._query_summary(key, parsed, template_root),
                }
                diagnostics.append(
                    AdapterDiagnostic(
                        status=_validation_status(ValidationStatus.PASSED),
                        check=check_name,
                        message=f"read-only upstream query {script_name} returned JSON",
                        command=command,
                    )
                )

            render_succeeded = self._render_upstream_source(
                model,
                template_root,
                rendered_root,
                summary,
                diagnostics,
            )
            self._validate_upstream_render(
                template_root,
                rendered_root,
                render_succeeded,
                summary,
                diagnostics,
            )

        return summary, diagnostics

    def _render_upstream_source(
        self,
        model: NormalizedDevOpsModel,
        template_root: Path,
        rendered_root: Path,
        summary: dict[str, Any],
        diagnostics: list[AdapterDiagnostic],
    ) -> bool:
        values_file = template_root / "config" / "platform-values.env.example"
        script = template_root / "scripts" / "render-platform-assets.ps1"
        display_command = self._pwsh_command(
            "render-platform-assets.ps1",
            "-RepoRoot",
            "<isolated-template>",
            "-OutputPath",
            "<ephemeral-render>",
            "-DockerRegistry",
            model.image_registry,
            "-Version",
            "0.0.0-composer-validation",
            "-ValuesFile",
            "<isolated-template>/config/platform-values.env.example",
            "-Profile",
            UPSTREAM_PROFILE,
            "-Applications",
            UPSTREAM_APPLICATION,
            "-FailOnUnresolvedToken",
        )
        if not script.is_file() or not values_file.is_file():
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(ValidationStatus.FAILED),
                    check="kubernetes.upstream.renderPlatformAssets",
                    message="official renderer or checked-in example values are missing",
                    command=display_command,
                )
            )
            summary["render"] = {"status": ValidationStatus.FAILED.value}
            return False
        command = self._pwsh_command(
            "render-platform-assets.ps1",
            "-RepoRoot",
            str(template_root),
            "-OutputPath",
            str(rendered_root),
            "-DockerRegistry",
            model.image_registry,
            "-Version",
            "0.0.0-composer-validation",
            "-ValuesFile",
            str(values_file),
            "-Profile",
            UPSTREAM_PROFILE,
            "-Applications",
            UPSTREAM_APPLICATION,
            "-FailOnUnresolvedToken",
        )
        try:
            completed = self._runner(
                command,
                cwd=template_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(
                        ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL
                    ),
                    check="kubernetes.upstream.renderPlatformAssets",
                    message="pwsh is required to run the official Kubernetes renderer",
                    command=display_command,
                )
            )
            summary["render"] = {
                "status": ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value
            }
            return False
        except (OSError, subprocess.TimeoutExpired) as exc:
            completed = None
            failure_type = type(exc).__name__
        else:
            failure_type = ""

        if completed is None or completed.returncode != 0:
            exit_code = completed.returncode if completed is not None else None
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(ValidationStatus.FAILED),
                    check="kubernetes.upstream.renderPlatformAssets",
                    message=(
                        f"official renderer failed: {failure_type}"
                        if failure_type
                        else f"official renderer exited with code {exit_code}"
                    ),
                    command=display_command,
                    details={"exitCode": exit_code},
                )
            )
            summary["render"] = {"status": ValidationStatus.FAILED.value}
            return False

        try:
            files, symlinks = _tree_inventory(rendered_root)
        except OSError as exc:
            symlinks = []
            files = []
            failure_type = type(exc).__name__
        yaml_files = [path for path in files if path.suffix.lower() in {".yaml", ".yml"}]
        if (
            failure_type
            or not rendered_root.is_dir()
            or symlinks
            or not (rendered_root / "k8s").is_dir()
            or not yaml_files
        ):
            diagnostics.append(
                AdapterDiagnostic(
                    status=_validation_status(ValidationStatus.FAILED),
                    check="kubernetes.upstream.renderPlatformAssets",
                    message="official renderer produced an unsafe or incomplete bundle",
                    command=display_command,
                )
            )
            summary["render"] = {"status": ValidationStatus.FAILED.value}
            return False

        summary["render"] = {
            "status": ValidationStatus.PASSED.value,
            "fileCount": len(files),
            "yamlFileCount": len(yaml_files),
        }
        diagnostics.append(
            AdapterDiagnostic(
                status=_validation_status(ValidationStatus.PASSED),
                check="kubernetes.upstream.renderPlatformAssets",
                message="official renderer produced an isolated minimal-application bundle",
                command=display_command,
                details={"fileCount": len(files), "yamlFileCount": len(yaml_files)},
            )
        )
        return True

    def _validate_upstream_render(
        self,
        template_root: Path,
        rendered_root: Path,
        render_succeeded: bool,
        summary: dict[str, Any],
        diagnostics: list[AdapterDiagnostic],
    ) -> None:
        validators = (
            (
                "renderedBundle",
                "validate-rendered-bundle.ps1",
                ("-RenderedPath", str(rendered_root), "-SchemaValidator", "auto"),
                ("-RenderedPath", "<ephemeral-render>", "-SchemaValidator", "auto"),
            ),
            (
                "securityBaseline",
                "validate-kubernetes-security-baseline.ps1",
                ("-Path", str(rendered_root), "-FailOnHighFinding"),
                ("-Path", "<ephemeral-render>", "-FailOnHighFinding"),
            ),
            (
                "placeholders",
                "check-placeholders.ps1",
                ("-Path", str(rendered_root)),
                ("-Path", "<ephemeral-render>"),
            ),
        )
        for key, script_name, arguments, display_arguments in validators:
            check_name = f"kubernetes.upstream.{key}"
            display_command = self._pwsh_command(script_name, *display_arguments)
            if not render_succeeded:
                status = ValidationStatus.FAILED.value
                diagnostics.append(
                    AdapterDiagnostic(
                        status=status,
                        check=check_name,
                        message="validator was not run because official rendering failed",
                        command=display_command,
                    )
                )
                summary["validators"][key] = {"status": status}
                continue
            if not (template_root / "scripts" / script_name).is_file():
                status = ValidationStatus.FAILED.value
                diagnostics.append(
                    AdapterDiagnostic(
                        status=status,
                        check=check_name,
                        message=f"upstream validator {script_name} is missing",
                        command=display_command,
                    )
                )
                summary["validators"][key] = {"status": status}
                continue
            command = self._pwsh_command(script_name, *arguments)
            try:
                completed = self._runner(
                    command,
                    cwd=template_root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except FileNotFoundError:
                status = ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value
                diagnostics.append(
                    AdapterDiagnostic(
                        status=status,
                        check=check_name,
                        message="pwsh is required to run upstream validators",
                        command=display_command,
                    )
                )
                summary["validators"][key] = {"status": status}
                continue
            except (OSError, subprocess.TimeoutExpired) as exc:
                status = ValidationStatus.FAILED.value
                diagnostics.append(
                    AdapterDiagnostic(
                        status=status,
                        check=check_name,
                        message=f"upstream validator failed: {type(exc).__name__}",
                        command=display_command,
                    )
                )
                summary["validators"][key] = {"status": status}
                continue

            output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
            status = (
                ValidationStatus.PASSED.value
                if completed.returncode == 0
                else ValidationStatus.FAILED.value
            )
            message = f"upstream validator {script_name} completed"
            if key == "renderedBundle" and completed.returncode == 0 and (
                "Skipping rendered manifest validation" in output
                or "Neither kubeconform nor kubectl is installed" in output
            ):
                status = ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value
                message = (
                    "upstream structural preflight passed; optional schema validator is missing"
                )
            validator_summary: dict[str, Any] = {"status": status}
            if key == "securityBaseline":
                finding_match = re.search(
                    r"findings:\s*high=(\d+),\s*medium=(\d+),\s*low=(\d+)",
                    output,
                    re.IGNORECASE,
                )
                if finding_match:
                    validator_summary["findings"] = {
                        "high": int(finding_match.group(1)),
                        "medium": int(finding_match.group(2)),
                        "low": int(finding_match.group(3)),
                    }
            elif key == "placeholders":
                placeholder_match = re.search(
                    r"Found\s+(\d+)\s+placeholder matches",
                    output,
                    re.IGNORECASE,
                )
                validator_summary["matchCount"] = (
                    int(placeholder_match.group(1)) if placeholder_match else 0
                )
            summary["validators"][key] = validator_summary
            diagnostics.append(
                AdapterDiagnostic(
                    status=status,
                    check=check_name,
                    message=message,
                    command=display_command,
                    details={"exitCode": completed.returncode},
                )
            )

    def _render_artifacts(
        self,
        model: NormalizedDevOpsModel,
        upstream: Mapping[str, Any],
    ) -> list[GeneratedArtifact]:
        origin = (
            "normalized-model",
            f"k8s-platform-template@{self.source.commit or 'unknown'}",
        )
        artifacts: list[GeneratedArtifact] = []

        def add(path: str, value: Mapping[str, Any]) -> None:
            artifacts.append(
                GeneratedArtifact(path=path, content=_yaml_document(value), origins=origin)
            )

        environments = tuple(model.environments)
        if not environments:
            raise ValueError("Kubernetes rendering requires at least one environment")
        base_environment = environments[0]
        has_config_map = any(environment.environment for environment in environments)

        add("k8s/base/serviceaccount.yaml", _service_account(model))
        add(
            "k8s/base/deployment.yaml",
            _deployment(
                model,
                base_environment,
                has_config_map=has_config_map,
                patch=False,
            ),
        )
        add("k8s/base/service.yaml", _service(model, base_environment, patch=False))
        base_resources = [
            "serviceaccount.yaml",
            "deployment.yaml",
            "service.yaml",
        ]
        if has_config_map:
            add("k8s/base/configmap.yaml", _config_map(model, None, patch=False))
            base_resources.append("configmap.yaml")
        add(
            "k8s/base/kustomization.yaml",
            _kustomization(resources=base_resources),
        )

        for environment in environments:
            directory = f"k8s/overlays/{environment.name}"
            add(f"{directory}/namespace.yaml", _namespace(model, environment))
            add(
                f"{directory}/deployment.yaml",
                _deployment(
                    model,
                    environment,
                    has_config_map=has_config_map,
                    patch=True,
                ),
            )
            add(
                f"{directory}/service.yaml",
                _service(model, environment, patch=True),
            )
            patch_names = ["deployment.yaml", "service.yaml"]
            if has_config_map:
                add(
                    f"{directory}/configmap.yaml",
                    _config_map(model, environment, patch=True),
                )
                patch_names.append("configmap.yaml")
            add(
                f"{directory}/kustomization.yaml",
                _kustomization(
                    resources=("../../base", "namespace.yaml"),
                    namespace=environment.namespace,
                    patches=patch_names,
                ),
            )

        artifacts.append(
            GeneratedArtifact(
                path="k8s/platform-context.json",
                content=json.dumps(upstream, indent=2, sort_keys=True) + "\n",
                origins=tuple(
                    f"scripts/{script_name}" for _, script_name, _ in _UPSTREAM_QUERIES
                )
                + (
                    "scripts/render-platform-assets.ps1",
                    "scripts/validate-rendered-bundle.ps1",
                    "scripts/validate-kubernetes-security-baseline.ps1",
                    "scripts/check-placeholders.ps1",
                ),
            )
        )
        return artifacts

    def _run_external_builder(
        self,
        executable: str,
        tool: str,
        root: Path,
    ) -> tuple[AdapterDiagnostic, dict[str, str]]:
        results: dict[str, dict[str, Any]] = {}
        rendered: dict[str, str] = {}
        for environment in ("dev", "staging", "production"):
            overlay = root / "k8s" / "overlays" / environment
            arguments = (
                [executable, "build", str(overlay)]
                if tool == "kustomize"
                else [executable, "kustomize", str(overlay)]
            )
            try:
                completed = self._runner(
                    arguments,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                results[environment] = {"exitCode": completed.returncode}
                if completed.returncode == 0:
                    rendered[environment] = completed.stdout
            except (OSError, subprocess.TimeoutExpired) as exc:
                results[environment] = {"error": type(exc).__name__}

        failed = len(rendered) != 3
        return (
            AdapterDiagnostic(
                status=_validation_status(
                    ValidationStatus.FAILED if failed else ValidationStatus.PASSED
                ),
                check=f"kubernetes.external.{tool}",
                message=(
                    f"{tool} could not render every environment"
                    if failed
                    else f"{tool} rendered every environment"
                ),
                command=(
                    tool,
                    "build" if tool == "kustomize" else "kustomize",
                    "k8s/overlays/<environment>",
                ),
                details={"environments": results},
            ),
            rendered,
        )

    def _external_diagnostics(
        self,
        artifacts: Sequence[GeneratedArtifact],
    ) -> list[AdapterDiagnostic]:
        diagnostics: list[AdapterDiagnostic] = []
        with tempfile.TemporaryDirectory(prefix="devops-stack-kubernetes-") as temporary:
            root = Path(temporary)
            for artifact in artifacts:
                destination = root / artifact.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(artifact.content, encoding="utf-8", newline="\n")

            rendered: dict[str, str] = {}
            builder_available = False
            for tool in ("kustomize", "kubectl"):
                executable = shutil.which(tool)
                if executable is None:
                    diagnostics.append(
                        AdapterDiagnostic(
                            status=_validation_status(
                                ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL
                            ),
                            check=f"kubernetes.external.{tool}",
                            message=f"optional tool {tool} is not installed",
                            command=(
                                tool,
                                "build" if tool == "kustomize" else "kustomize",
                                "k8s/overlays/<environment>",
                            ),
                        )
                    )
                    continue
                builder_available = True
                diagnostic, output = self._run_external_builder(
                    executable, tool, root
                )
                diagnostics.append(diagnostic)
                for environment, content in output.items():
                    rendered.setdefault(environment, content)

            kubeconform = shutil.which("kubeconform")
            if kubeconform is None:
                diagnostics.append(
                    AdapterDiagnostic(
                        status=_validation_status(
                            ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL
                        ),
                        check="kubernetes.external.kubeconform",
                        message="optional tool kubeconform is not installed",
                        command=("kubeconform", "-strict", "-summary", "-"),
                    )
                )
            elif not rendered:
                diagnostics.append(
                    AdapterDiagnostic(
                        status=_validation_status(
                            ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL
                            if not builder_available
                            else ValidationStatus.FAILED
                        ),
                        check="kubernetes.external.kubeconform",
                        message=(
                            "kubeconform requires optional kustomize or kubectl rendering"
                            if not builder_available
                            else "kubeconform was blocked by failed Kustomize rendering"
                        ),
                        command=("kubeconform", "-strict", "-summary", "-"),
                    )
                )
            else:
                results: dict[str, dict[str, Any]] = {}
                for environment in ("dev", "staging", "production"):
                    if environment not in rendered:
                        results[environment] = {"error": "render unavailable"}
                        continue
                    try:
                        completed = self._runner(
                            [kubeconform, "-strict", "-summary", "-"],
                            input=rendered[environment],
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=60,
                        )
                        results[environment] = {"exitCode": completed.returncode}
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        results[environment] = {"error": type(exc).__name__}
                failed = any(result.get("exitCode") != 0 for result in results.values())
                diagnostics.append(
                    AdapterDiagnostic(
                        status=_validation_status(
                            ValidationStatus.FAILED if failed else ValidationStatus.PASSED
                        ),
                        check="kubernetes.external.kubeconform",
                        message=(
                            "kubeconform rejected one or more rendered environments"
                            if failed
                            else "kubeconform accepted every rendered environment"
                        ),
                        command=("kubeconform", "-strict", "-summary", "-"),
                        details={"environments": results},
                    )
                )

        return diagnostics
