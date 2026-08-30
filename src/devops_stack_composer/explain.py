"""Explain generated-file provenance from the ownership manifest."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from devops_stack_composer.errors import ManifestValidationError
from devops_stack_composer.filesystem import normalize_relative_path
from devops_stack_composer.manifest import GeneratedManifest


SENSITIVE_CONFIG_PATH = re.compile(
    r"(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)",
    re.IGNORECASE,
)


def _deployment_consumers(path: str) -> list[str]:
    field = path.split(".", 1)[0] if path else ""
    return {
        "namespace": ["jenkins", "kubernetes", "contract-validator"],
        "replicas": ["jenkins", "kubernetes", "contract-validator"],
        "containerPort": ["docker", "kubernetes", "contract-validator"],
        "service": ["kubernetes", "contract-validator"],
        "health": ["kubernetes", "contract-validator"],
        "readiness": ["kubernetes", "contract-validator"],
        "environment": ["kubernetes", "contract-validator"],
        "secretRefs": ["kubernetes", "contract-validator"],
        "resources": ["kubernetes", "contract-validator"],
        "rollout": ["kubernetes", "contract-validator"],
        "rollback": ["jenkins", "kubernetes", "contract-validator"],
        "": ["docker", "jenkins", "kubernetes", "contract-validator"],
    }.get(field, [])


def _config_consumers(path: str) -> list[str]:
    application = {
        "name": ["docker", "jenkins", "kubernetes", "contract-validator"],
        "serviceName": ["docker", "jenkins", "kubernetes", "contract-validator"],
        "type": ["docker"],
        "root": ["docker"],
        "buildCommand": ["docker", "jenkins"],
        "testCommand": ["jenkins"],
        "runCommand": ["docker"],
        "buildArtifact": ["docker", "contract-validator"],
    }
    if path == "application":
        return ["docker", "jenkins", "kubernetes", "contract-validator"]
    if path.startswith("application."):
        return application.get(path.split(".", 1)[1], [])
    if path == "image" or path.startswith("image."):
        return ["docker", "jenkins", "kubernetes", "contract-validator"]
    if path == "build":
        return ["docker", "jenkins"]
    if path.startswith("build.cache"):
        return ["docker", "jenkins"]
    if path.startswith("build."):
        return ["docker"]
    if path == "ci":
        return ["jenkins", "contract-validator"]
    if path == "ci.jenkins" or path.startswith("ci.jenkins."):
        return ["jenkins"]
    if path == "ci.branches" or path.startswith("ci.branches."):
        return ["jenkins", "contract-validator"]
    if path == "ci.approval" or path.startswith("ci.approval."):
        return ["jenkins", "contract-validator"]
    if path == "deployment":
        return _deployment_consumers("")
    if path.startswith("deployment."):
        return _deployment_consumers(path.split(".", 1)[1])
    environment_match = re.match(
        r"^environments\.(?:dev|staging|production)(?:\.(.*))?$",
        path,
    )
    if path == "environments":
        return _deployment_consumers("")
    if environment_match:
        return _deployment_consumers(environment_match.group(1) or "")
    if path == "supplyChain" or path.startswith("supplyChain."):
        return ["docker", "jenkins"]
    if path == "security":
        return ["docker", "kubernetes", "contract-validator"]
    if path.startswith("security.runAsUser") or path.startswith("security.runAsNonRoot"):
        return ["docker", "kubernetes", "contract-validator"]
    if path.startswith("security."):
        return ["kubernetes", "contract-validator"]
    if path == "policies" or path.startswith("policies."):
        return ["contract-validator"]
    return []


def explain_generated_file(
    project: Path,
    requested_path: str,
    *,
    output_directory: str = "generated",
) -> dict[str, Any]:
    manifest = GeneratedManifest.load(project, output_directory)
    if manifest is None:
        raise ManifestValidationError(
            f"no generated manifest exists under {output_directory}; run generate --write first"
        )
    requested = normalize_relative_path(requested_path)
    output_prefix = normalize_relative_path(output_directory) + "/"
    relative = requested[len(output_prefix) :] if requested.startswith(output_prefix) else requested
    entry = manifest.file_map().get(relative)
    if entry is None:
        raise ManifestValidationError(f"generated file is not tracked by the manifest: {requested_path}")
    adapter = relative.split("/", 1)[0]
    template = manifest.data["templates"].get(adapter)
    return {
        "path": relative,
        "outputPath": f"{manifest.data['outputDirectory']}/{relative}",
        "sha256": entry["sha256"],
        "mode": entry["mode"],
        "origins": entry["origins"],
        "adapter": adapter,
        "template": template,
        "configHash": manifest.data["configHash"],
        "generatedAt": manifest.data["generatedAt"],
    }


def explain_config_value(config: dict[str, Any], requested_path: str) -> dict[str, Any]:
    """Explain one declarative input and the adapters that consume its model value."""

    value_path = requested_path.removeprefix("config:").removeprefix("$").lstrip(".")
    if not value_path:
        raise ManifestValidationError("configuration explanation requires a dotted value path")
    value: Any = config
    traversed: list[str] = []
    for part in value_path.split("."):
        traversed.append(part)
        if not isinstance(value, dict) or part not in value:
            raise ManifestValidationError(
                "configuration value does not exist: $." + ".".join(traversed)
            )
        value = value[part]
    consumers = _config_consumers(value_path)
    normalized_path = re.sub(r"[_-]", "", value_path).lower()
    is_safe_reference = "secretrefs" in normalized_path
    return {
        "path": f"$.{value_path}",
        "value": (
            "<redacted>"
            if SENSITIVE_CONFIG_PATH.search(value_path) and not is_safe_reference
            else value
        ),
        "origin": "devops-stack.yaml",
        "derivation": (
            "validated input -> normalized DevOps model -> adapter projection"
            if consumers
            else "validated input; no generated adapter projection consumes this field"
        ),
        "consumers": consumers,
    }
