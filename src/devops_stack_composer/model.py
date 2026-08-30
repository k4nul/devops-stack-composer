"""Normalized values shared by every template adapter."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


ENVIRONMENT_ORDER = ("dev", "staging", "production")

TAG_EXPRESSIONS = {
    "branch-sha": "${BRANCH_SLUG}-${GIT_COMMIT_SHA}",
    "git-sha": "${GIT_COMMIT_SHA}",
    "semver": "${VERSION}",
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge mappings recursively; scalars and lists replace the base value."""

    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


@dataclass(frozen=True)
class EnvironmentModel:
    name: str
    namespace: str
    replicas: int
    container_port: int
    service_type: str
    service_port: int
    health_path: str
    readiness_path: str
    environment: dict[str, str | int | float | bool]
    secret_names: tuple[str, ...]
    secret_refs: tuple[dict[str, Any], ...]
    resources: dict[str, dict[str, str]]
    rollout: dict[str, Any]
    rollback: dict[str, Any]


@dataclass(frozen=True)
class NormalizedDevOpsModel:
    application_name: str
    service_name: str
    application_type: str
    application_root: str
    build_context: str
    dockerfile_strategy: str
    dockerfile_path: str | None
    build_command: str
    test_command: str
    run_command: str
    build_artifact: str
    image_registry: str
    image_repository: str
    image_tag: str
    image_tag_strategy: str
    architectures: tuple[str, ...]
    runtime_user: int
    credential_id: str
    branch_environment_map: dict[str, tuple[str, ...]]
    production_approval: bool
    build: dict[str, Any]
    environments: tuple[EnvironmentModel, ...]
    supply_chain: dict[str, Any]
    security: dict[str, Any]
    policies: dict[str, Any]

    @property
    def image_name(self) -> str:
        return f"{self.image_registry}/{self.image_repository}"

    @property
    def image_reference(self) -> str:
        return f"{self.image_name}:{self.image_tag}"

    def environment(self, name: str) -> EnvironmentModel:
        for environment in self.environments:
            if environment.name == name:
                return environment
        raise KeyError(name)

    def contract(self) -> dict[str, Any]:
        """Return the complete cross-project contract in canonical form."""

        return {
            "applicationName": self.application_name,
            "serviceName": self.service_name,
            "imageRegistry": self.image_registry,
            "imageRepository": self.image_repository,
            "imageTag": self.image_tag,
            "architectures": list(self.architectures),
            "containerPort": self.environments[0].container_port,
            "servicePorts": {
                environment.name: environment.service_port
                for environment in self.environments
            },
            "healthEndpoint": self.environments[0].health_path,
            "readinessEndpoint": self.environments[0].readiness_path,
            "runtimeUser": self.runtime_user,
            "environmentNames": [environment.name for environment in self.environments],
            "namespaces": {
                environment.name: environment.namespace
                for environment in self.environments
            },
            "secretNames": {
                environment.name: list(environment.secret_names)
                for environment in self.environments
            },
            "buildArtifact": self.build_artifact,
            "branchEnvironmentMap": {
                name: list(branches)
                for name, branches in self.branch_environment_map.items()
            },
        }


def normalize_config(config: dict[str, Any]) -> NormalizedDevOpsModel:
    tag = config["image"]["tag"]
    image_tag = (
        tag["value"] if tag["strategy"] == "fixed" else TAG_EXPRESSIONS[tag["strategy"]]
    )

    environments: list[EnvironmentModel] = []
    for name in ENVIRONMENT_ORDER:
        values = deep_merge(config["deployment"], config["environments"][name])
        secret_refs = tuple(deepcopy(values["secretRefs"]))
        environments.append(
            EnvironmentModel(
                name=name,
                namespace=values["namespace"],
                replicas=values["replicas"],
                container_port=values["containerPort"],
                service_type=values["service"]["type"],
                service_port=values["service"]["port"],
                health_path=values["health"]["path"],
                readiness_path=values["readiness"]["path"],
                environment=deepcopy(values["environment"]),
                secret_names=tuple(item["name"] for item in secret_refs),
                secret_refs=secret_refs,
                resources=deepcopy(values["resources"]),
                rollout=deepcopy(values["rollout"]),
                rollback=deepcopy(values["rollback"]),
            )
        )

    application = config["application"]
    build = config["build"]
    return NormalizedDevOpsModel(
        application_name=application["name"],
        service_name=application["serviceName"],
        application_type=application["type"],
        application_root=application["root"],
        build_context=build["context"],
        dockerfile_strategy=build["dockerfile"]["strategy"],
        dockerfile_path=build["dockerfile"].get("path"),
        build_command=application["buildCommand"],
        test_command=application["testCommand"],
        run_command=application["runCommand"],
        build_artifact=application["buildArtifact"],
        image_registry=config["image"]["registry"].rstrip("/"),
        image_repository=config["image"]["repository"].strip("/"),
        image_tag=image_tag,
        image_tag_strategy=tag["strategy"],
        architectures=tuple(config["image"]["architectures"]),
        runtime_user=config["security"]["runAsUser"],
        credential_id=config["ci"]["jenkins"]["credentialId"],
        branch_environment_map={
            name: tuple(config["ci"]["branches"][name])
            for name in ENVIRONMENT_ORDER
        },
        production_approval=config["ci"]["approval"]["production"],
        build=deepcopy(build),
        environments=tuple(environments),
        supply_chain=deepcopy(config["supplyChain"]),
        security=deepcopy(config["security"]),
        policies=deepcopy(config["policies"]),
    )
