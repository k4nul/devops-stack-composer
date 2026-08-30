from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from devops_stack_composer.adapters.base import (
    AdapterDiagnostic,
    AdapterResult,
    GeneratedArtifact,
)
from devops_stack_composer.adapters.docker import DockerBuildAdapter
from devops_stack_composer.adapters.kubernetes import (
    KubernetesAdapter,
    validate_yaml_artifacts,
)
from devops_stack_composer.config import parse_config, validate_config
from devops_stack_composer.model import normalize_config
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationStatus, validate_cross_project_contract
from devops_stack_composer.adapters.jenkins import JenkinsPipelineAdapter


FIXTURE = Path(__file__).parent / "fixtures" / "configs" / "valid.yaml"
VALIDATION_COMMITS = {
    "docker": "d" * 40,
    "jenkins": "e" * 40,
    "kubernetes": "c" * 40,
}


def artifacts_for(adapter: str, model) -> tuple[GeneratedArtifact, ...]:
    if adapter == "docker":
        image_environment = "\n".join(
            (
                f"REGISTRY={model.image_registry}/",
                f"IMAGE_NAME={model.image_repository}",
                f"IMAGE_TAG={model.image_tag}",
                f"PLATFORMS={','.join(model.architectures)}",
                f"OCI_TITLE={model.application_name}",
                "CONTEXT=application",
                "DOCKERFILE=generated/docker/Dockerfile",
                "PUSH=false",
                "SBOM="
                + (
                    "true"
                    if model.supply_chain.get("sbom", {}).get("enabled")
                    else "false"
                ),
                "PROVENANCE="
                + (
                    f"mode={model.supply_chain.get('provenance', {}).get('mode', 'min')}"
                    if model.supply_chain.get("provenance", {}).get("enabled")
                    else "false"
                ),
                "",
            )
        )
        metadata = {
            "image": {
                "tagStrategy": model.image_tag_strategy,
                "tagExpression": model.image_tag_expression,
            },
            "build": {
                "artifact": model.build_artifact,
                "context": model.build_context,
                "dockerfileStrategy": model.dockerfile_strategy,
                "multiStage": bool(model.build.get("multiStage")),
                "reproducibility": {
                    "requested": bool(model.build.get("reproducible"))
                },
            },
            "runtime": {
                "user": model.runtime_user,
                "containerPort": model.environments[0].container_port,
                "runAsNonRoot": bool(model.security.get("runAsNonRoot")),
            },
            "capabilities": {
                "sbom": {
                    "requested": bool(
                        model.supply_chain.get("sbom", {}).get("enabled")
                    )
                },
                "provenance": {
                    "requested": bool(
                        model.supply_chain.get("provenance", {}).get("enabled")
                    )
                },
                "scan": {
                    "requested": bool(
                        model.supply_chain.get("scan", {}).get("enabled")
                    )
                },
                "cache": {
                    "requested": bool(
                        model.build.get("cache", {}).get("enabled")
                        or model.build.get("cache", {}).get("from")
                        or model.build.get("cache", {}).get("to")
                    )
                },
            },
        }
        image_pairs = {
            "nodejs": ("node:22-alpine", "node:22-alpine"),
            "python": ("python:3.12-slim", "python:3.12-slim"),
            "java": (
                "eclipse-temurin:21-jdk-jammy",
                "eclipse-temurin:21-jre-jammy",
            ),
            "go": ("golang:1.23-alpine", "alpine:3.20"),
            "rust": ("rust:1.83-alpine", "alpine:3.20"),
            "static": ("node:22-alpine", "python:3.12-slim"),
        }
        builder_image, runtime_image = image_pairs[model.application_type]
        dockerfile_lines = []
        if model.build.get("multiStage"):
            dockerfile_lines.extend(
                (
                    f"ARG BUILDER_IMAGE={builder_image}",
                    f"ARG RUNTIME_IMAGE={runtime_image}",
                    "FROM ${BUILDER_IMAGE} AS build",
                    "RUN true",
                    "FROM ${RUNTIME_IMAGE} AS runtime",
                )
            )
        else:
            dockerfile_lines.extend(
                (
                    f"ARG RUNTIME_IMAGE={builder_image}",
                    "FROM ${RUNTIME_IMAGE} AS runtime",
                )
            )
        dockerfile_lines.extend(
            (
                "RUN "
                + json.dumps(
                    ["sh", "-c", model.build_command],
                    separators=(",", ":"),
                ),
                f"USER {model.runtime_user}:{model.runtime_user}",
                f"EXPOSE {model.environments[0].container_port}",
                "CMD "
                + json.dumps(
                    ["sh", "-c", model.run_command],
                    separators=(",", ":"),
                ),
                "",
            )
        )
        return (
            GeneratedArtifact("docker/image.env", image_environment),
            GeneratedArtifact("docker/metadata.json", json.dumps(metadata)),
            GeneratedArtifact(
                "docker/Dockerfile",
                "\n".join(dockerfile_lines),
            ),
            GeneratedArtifact(
                "docker/Dockerfile.dockerignore",
                DockerBuildAdapter._dockerignore(),
            ),
            GeneratedArtifact(
                "docker/build.sh",
                DockerBuildAdapter(
                    SourceResolution(
                        key="docker",
                        path=Path("."),
                        origin="validation-fixture",
                        commit="d" * 40,
                        remote=None,
                        matches_lock=True,
                    )
                )._build_script(model),
                mode=0o755,
            ),
        )
    if adapter == "jenkins":
        source = SourceResolution(
            key="jenkins",
            path=Path("."),
            origin="validation-fixture",
            commit="1" * 40,
            remote=None,
            matches_lock=True,
        )
        return JenkinsPipelineAdapter(source).render(
            model,
            validate_upstream=False,
        ).artifacts
    artifacts: list[GeneratedArtifact] = [
        GeneratedArtifact(
            "k8s/base/serviceaccount.yaml",
            yaml.safe_dump(
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": str(model.security["serviceAccount"])},
                    "automountServiceAccountToken": False,
                },
                sort_keys=False,
            ),
        )
    ]
    has_config_map = any(environment.environment for environment in model.environments)
    base_resources = ["serviceaccount.yaml", "deployment.yaml", "service.yaml"]
    if has_config_map:
        base_resources.append("configmap.yaml")
    artifacts.append(
        GeneratedArtifact(
            "k8s/base/kustomization.yaml",
            yaml.safe_dump(
                {
                    "apiVersion": "kustomize.config.k8s.io/v1beta1",
                    "kind": "Kustomization",
                    "resources": base_resources,
                },
                sort_keys=False,
            ),
        )
    )
    for environment in model.environments:
        root = f"k8s/overlays/{environment.name}"
        labels = {
            "app.kubernetes.io/name": model.service_name,
            "app.kubernetes.io/instance": model.application_name,
            "app.kubernetes.io/managed-by": "devops-stack-composer",
        }
        namespace_labels = {
            **labels,
            "devops-stack.io/environment": environment.name,
        }
        if environment.name == "production":
            namespace_labels.update(
                {
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/enforce-version": "v1.30",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                }
            )
        container_security = {
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
            container_security["readOnlyRootFilesystem"] = True
        secret_environment = [
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
        node_selector = {"kubernetes.io/os": "linux"}
        if len(model.architectures) == 1:
            node_selector["kubernetes.io/arch"] = model.architectures[0].split(
                "/", 1
            )[1]
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "$patch": "replace",
            "metadata": {
                "name": model.service_name,
                "labels": labels,
                "annotations": {
                    "devops-stack.io/image-architectures": ",".join(
                        model.architectures
                    )
                },
            },
            "spec": {
                "replicas": environment.replicas,
                "revisionHistoryLimit": (
                    int(environment.rollback["revisionHistoryLimit"])
                    if environment.rollback.get("enabled", False)
                    else 0
                ),
                "strategy": {
                    "type": environment.rollout["strategy"],
                    "rollingUpdate": {
                        "maxUnavailable": environment.rollout["maxUnavailable"],
                        "maxSurge": environment.rollout["maxSurge"],
                    },
                },
                "selector": {
                    "matchLabels": {"app.kubernetes.io/name": model.service_name}
                },
                "template": {
                    "metadata": {
                        "labels": {
                            **labels,
                            "app.kubernetes.io/managed-by": "devops-stack-composer",
                            "devops-stack.io/environment": environment.name,
                        },
                        "annotations": {
                            "devops-stack.io/image-architectures": ",".join(
                                model.architectures
                            )
                        }
                    },
                    "spec": {
                        "nodeSelector": node_selector,
                        "serviceAccountName": str(model.security["serviceAccount"]),
                        "automountServiceAccountToken": False,
                        "securityContext": {
                            "runAsNonRoot": bool(model.security["runAsNonRoot"]),
                            "runAsUser": model.runtime_user,
                            "seccompProfile": {
                                "type": model.security.get(
                                    "seccompProfile", "RuntimeDefault"
                                )
                            },
                        },
                        "containers": [
                            {
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
                                "securityContext": container_security,
                                "resources": environment.resources,
                                **({"env": secret_environment} if secret_environment else {}),
                                **(
                                    {
                                        "envFrom": [
                                            {
                                                "configMapRef": {
                                                    "name": f"{model.service_name}-config"
                                                }
                                            }
                                        ]
                                    }
                                    if has_config_map
                                    else {}
                                ),
                            }
                        ],
                        "terminationGracePeriodSeconds": 30,
                    }
                }
            },
        }
        if environment.name == "production":
            deployment["spec"]["minReadySeconds"] = 10
            deployment["spec"]["progressDeadlineSeconds"] = 600
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "$patch": "replace",
            "spec": {
                "type": environment.service_type,
                "selector": {"app.kubernetes.io/name": model.service_name},
                "ports": [
                    {
                        "name": "http",
                        "port": environment.service_port,
                        "targetPort": environment.container_port,
                        "protocol": "TCP",
                    }
                ]
            },
        }
        namespace = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": environment.namespace,
                "labels": namespace_labels,
            },
        }
        patches = ["deployment.yaml", "service.yaml"]
        if has_config_map:
            patches.append("configmap.yaml")
        kustomization = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "namespace": environment.namespace,
            "resources": ["../../base", "namespace.yaml"],
            "patches": [{"path": path} for path in patches],
        }
        documents = [
            ("deployment", deployment),
            ("service", service),
            ("namespace", namespace),
            ("kustomization", kustomization),
        ]
        if has_config_map:
            documents.append(
                (
                    "configmap",
                    {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "$patch": "replace",
                        "metadata": {"name": f"{model.service_name}-config"},
                        "data": {
                            key: (
                                "true"
                                if value is True
                                else "false"
                                if value is False
                                else str(value)
                            )
                            for key, value in sorted(environment.environment.items())
                        },
                    },
                )
            )
        for name, value in documents:
            artifacts.append(
                GeneratedArtifact(
                    f"{root}/{name}.yaml",
                    yaml.safe_dump(value, sort_keys=False),
                )
            )
            if environment.name == "dev" and name in {
                "deployment",
                "service",
                "configmap",
            }:
                base_value = copy.deepcopy(value)
                base_value.pop("$patch", None)
                artifacts.append(
                    GeneratedArtifact(
                        f"k8s/base/{name}.yaml",
                        yaml.safe_dump(base_value, sort_keys=False),
                    )
                )
    artifacts.append(
        GeneratedArtifact(
            "k8s/platform-context.json",
            json.dumps(
                {
                    "schemaVersion": "k8s-integration-summary-v1",
                    "selection": {
                        "profile": "minimal-application",
                        "applications": ["nginx-web"],
                    },
                    "source": {
                        "commit": VALIDATION_COMMITS["kubernetes"],
                        "matchesLock": True,
                    },
                    "queries": {},
                    "render": {"status": "NOT_RUN"},
                    "validators": {},
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
    )
    return tuple(artifacts)


def result(adapter: str, contract: dict, model) -> AdapterResult:
    source = SourceResolution(
        key=adapter,
        path=Path("."),
        origin="validation-fixture",
        commit=VALIDATION_COMMITS[adapter],
        remote=None,
        matches_lock=True,
    )
    if adapter == "docker":
        if model.dockerfile_strategy == "existing":
            rendered = AdapterResult(
                adapter="docker",
                adapter_version="1.0.0",
                template_commit=source.commit or "unknown",
                artifacts=artifacts_for(adapter, model),
                contract=model.contract(),
            )
        else:
            rendered = DockerBuildAdapter(source).render(model)
    elif adapter == "jenkins":
        rendered = JenkinsPipelineAdapter(source).render(
            model,
            validate_upstream=False,
        )
    elif adapter == "kubernetes":
        context = {
            "schemaVersion": "k8s-integration-summary-v1",
            "selection": {
                "profile": "minimal-application",
                "applications": ["nginx-web"],
            },
            "source": {
                "commit": source.commit,
                "matchesLock": True,
            },
            "queries": {},
            "render": {"status": "NOT_RUN"},
            "validators": {},
        }
        kubernetes = KubernetesAdapter(source)
        rendered = AdapterResult(
            adapter="kubernetes",
            adapter_version=kubernetes.adapter_version,
            template_commit=source.commit or "unknown",
            artifacts=tuple(
                sorted(
                    kubernetes._render_artifacts(model, context),
                    key=lambda artifact: artifact.path,
                )
            ),
            contract=model.contract(),
            diagnostics=(
                AdapterDiagnostic(
                    status="PASSED",
                    check="kubernetes.platform-context-contract",
                    message="validation fixture context",
                    details={"summary": context},
                ),
            ),
        )
    else:
        raise ValueError(f"unsupported validation fixture adapter: {adapter}")
    return AdapterResult(
        adapter=adapter,
        adapter_version=rendered.adapter_version,
        template_commit=source.commit or "unknown",
        artifacts=rendered.artifacts,
        contract=contract,
        diagnostics=rendered.diagnostics,
    )


def matching_results(model) -> list[AdapterResult]:
    return [
        result(name, model.contract(), model)
        for name in ("docker", "jenkins", "kubernetes")
    ]


def replace_jenkinsfile(
    results: list[AdapterResult],
    content: str,
) -> None:
    jenkins = results[1]
    results[1] = AdapterResult(
        jenkins.adapter,
        jenkins.adapter_version,
        jenkins.template_commit,
        tuple(
            GeneratedArtifact(artifact.path, content, artifact.mode)
            if artifact.path == "jenkins/Jenkinsfile"
            else artifact
            for artifact in jenkins.artifacts
        ),
        jenkins.contract,
    )


class CrossProjectValidationTests(unittest.TestCase):
    def test_plain_environment_and_secret_reference_cannot_share_a_key(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["deployment"]["environment"]["PUBLIC"] = "not-secret"
        raw["deployment"]["secretRefs"] = [
            {"name": "runtime-secrets", "keys": ["PUBLIC"]}
        ]
        model = normalize_config(raw)

        report = validate_cross_project_contract(model, matching_results(model))

        check = next(
            item for item in report.checks if item.check == "contract.secret-references"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertEqual(
            check.details["plaintextCollisions"],
            {
                "dev": ["PUBLIC"],
                "staging": ["PUBLIC"],
                "production": ["PUBLIC"],
            },
        )

    def test_production_rollout_cannot_make_every_replica_unavailable(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["environments"]["production"]["rollout"] = {"maxUnavailable": "100%"}
        model = normalize_config(raw)

        report = validate_cross_project_contract(model, matching_results(model))

        check = next(
            item for item in report.checks if item.check == "policy.rollout-availability"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)

    def setUp(self) -> None:
        self.raw = parse_config(FIXTURE.read_text(encoding="utf-8"))
        validate_config(self.raw)
        self.model = normalize_config(self.raw)

    def test_identical_adapter_contracts_pass(self) -> None:
        results = matching_results(self.model)

        report = validate_cross_project_contract(self.model, results)

        self.assertTrue(report.passed)
        self.assertTrue(all(check.status == ValidationStatus.PASSED for check in report.checks))

    def test_image_mismatch_fails_with_exact_path(self) -> None:
        wrong = copy.deepcopy(self.model.contract())
        wrong["imageRepository"] = "someone/other-image"
        results = [
            result("docker", self.model.contract(), self.model),
            result("jenkins", wrong, self.model),
            result("kubernetes", self.model.contract(), self.model),
        ]

        report = validate_cross_project_contract(self.model, results)

        check = next(check for check in report.checks if check.check == "contract.jenkins")
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertEqual(check.details["mismatches"][0]["path"], "$.imageRepository")

    def test_rendered_artifact_drift_fails_even_when_declared_contract_matches(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content.replace(
                    f"IMAGE_NAME={self.model.image_repository}",
                    "IMAGE_NAME=someone/drifted",
                ),
            )
            if artifact.path == "docker/image.env"
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.docker.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "docker.image.repository",
            {
                mismatch["path"]
                for mismatch in check.details["mismatches"]
            },
        )

    def test_docker_contract_uses_only_the_final_stage(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content + "FROM scratch AS actual-runtime\n",
                artifact.mode,
            )
            if artifact.path == "docker/Dockerfile"
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.docker.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertTrue(
            {
                "docker.Dockerfile.finalUser",
                "docker.Dockerfile.exposedPort",
                "docker.Dockerfile.command",
            }.issubset(
                {mismatch["path"] for mismatch in check.details["mismatches"]}
            )
        )

    def test_docker_supply_chain_intent_is_recovered_from_artifacts(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content.replace("SBOM=true", "SBOM=false").replace(
                    "PROVENANCE=mode=max",
                    "PROVENANCE=false",
                ),
                artifact.mode,
            )
            if artifact.path == "docker/image.env"
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.docker.artifacts"
        )
        paths = {mismatch["path"] for mismatch in check.details["mismatches"]}
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn("docker.supplyChain.sbom", paths)
        self.assertIn("docker.supplyChain.provenance", paths)

    def test_valid_but_wrong_kubernetes_deploy_settings_fail_contract(self) -> None:
        results = matching_results(self.model)
        kubernetes = results[2]
        replacements: dict[str, str] = {}
        deployment_path = "k8s/overlays/production/deployment.yaml"
        deployment = yaml.safe_load(kubernetes.artifact(deployment_path).content)
        deployment["spec"]["replicas"] = 99
        deployment["spec"]["revisionHistoryLimit"] = 99
        deployment["spec"]["strategy"]["rollingUpdate"] = {
            "maxUnavailable": "99%",
            "maxSurge": "99%",
        }
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        container["resources"] = {
            "requests": {"cpu": "999m", "memory": "999Mi"},
            "limits": {"cpu": "999m", "memory": "999Mi"},
        }
        container["securityContext"]["runAsUser"] = 20002
        deployment["spec"]["selector"]["matchLabels"] = {
            "app.kubernetes.io/name": "orphan"
        }
        deployment["spec"]["template"]["metadata"]["labels"][
            "app.kubernetes.io/name"
        ] = "orphan"
        container["envFrom"] = [{"configMapRef": {"name": "wrong-config"}}]
        replacements[deployment_path] = yaml.safe_dump(deployment, sort_keys=False)
        service_path = "k8s/overlays/production/service.yaml"
        service = yaml.safe_load(kubernetes.artifact(service_path).content)
        service["spec"]["type"] = "LoadBalancer"
        service["spec"]["selector"] = {
            "app.kubernetes.io/name": "different"
        }
        replacements[service_path] = yaml.safe_dump(service, sort_keys=False)
        config_path = "k8s/overlays/production/configmap.yaml"
        configmap = yaml.safe_load(kubernetes.artifact(config_path).content)
        configmap["data"] = {"LOG_LEVEL": "wrong"}
        configmap["metadata"]["name"] = "wrong-config"
        replacements[config_path] = yaml.safe_dump(configmap, sort_keys=False)
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                replacements.get(artifact.path, artifact.content),
                artifact.mode,
            )
            for artifact in kubernetes.artifacts
        )
        results[2] = AdapterResult(
            kubernetes.adapter,
            kubernetes.adapter_version,
            kubernetes.template_commit,
            artifacts,
            kubernetes.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item
            for item in report.checks
            if item.check == "contract.kubernetes.artifacts"
        )
        paths = {mismatch["path"] for mismatch in check.details["mismatches"]}
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertTrue(
            {
                "kubernetes.environments.production.replicas",
                "kubernetes.environments.production.revisionHistoryLimit",
                "kubernetes.environments.production.rollout",
                "kubernetes.environments.production.resources",
                "kubernetes.environments.production.containerSecurity",
                "kubernetes.environments.production.serviceType",
                "kubernetes.environments.production.environment",
                "kubernetes.environments.production.deploymentSelector",
                "kubernetes.environments.production.podLabels",
                "kubernetes.environments.production.serviceSelector",
                "kubernetes.environments.production.configMapRef",
                "kubernetes.environments.production.configMapName",
            }.issubset(paths)
        )

    def test_kubernetes_identity_must_match_exact_generated_kind(self) -> None:
        results = matching_results(self.model)
        kubernetes = results[2]
        path = "k8s/overlays/production/deployment.yaml"
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content.replace("apiVersion: apps/v1", "apiVersion: nonsense/v99")
                .replace("kind: Deployment", "kind: InventedWorkload"),
                artifact.mode,
            )
            if artifact.path == path
            else artifact
            for artifact in kubernetes.artifacts
        )
        results[2] = AdapterResult(
            kubernetes.adapter,
            kubernetes.adapter_version,
            kubernetes.template_commit,
            artifacts,
            kubernetes.contract,
        )

        report = validate_cross_project_contract(self.model, results)
        structure = validate_yaml_artifacts(artifacts)

        contract = next(
            item
            for item in report.checks
            if item.check == "contract.kubernetes.artifacts"
        )
        self.assertEqual(contract.status, ValidationStatus.FAILED)
        self.assertEqual(structure.status, ValidationStatus.FAILED.value)

    def test_kubernetes_production_availability_controls_are_artifact_contract(self) -> None:
        results = matching_results(self.model)
        kubernetes = results[2]
        path = "k8s/overlays/production/deployment.yaml"
        deployment = yaml.safe_load(kubernetes.artifact(path).content)
        deployment["spec"].pop("minReadySeconds")
        deployment["spec"].pop("progressDeadlineSeconds")
        deployment["spec"]["template"]["spec"]["containers"][0][
            "imagePullPolicy"
        ] = "Always"
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                yaml.safe_dump(deployment, sort_keys=False),
                artifact.mode,
            )
            if artifact.path == path
            else artifact
            for artifact in kubernetes.artifacts
        )
        results[2] = AdapterResult(
            kubernetes.adapter,
            kubernetes.adapter_version,
            kubernetes.template_commit,
            artifacts,
            kubernetes.contract,
        )

        report = validate_cross_project_contract(self.model, results)
        check = next(
            item
            for item in report.checks
            if item.check == "contract.kubernetes.artifacts"
        )
        paths = {mismatch["path"] for mismatch in check.details["mismatches"]}
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertTrue(
            {
                "kubernetes.environments.production.minReadySeconds",
                "kubernetes.environments.production.progressDeadlineSeconds",
                "kubernetes.environments.production.imagePullPolicy",
            }.issubset(paths)
        )

    def test_missing_primary_adapter_artifact_fails_strict_contract_check(self) -> None:
        results = matching_results(self.model)
        jenkins = results[1]
        results[1] = AdapterResult(
            jenkins.adapter,
            jenkins.adapter_version,
            jenkins.template_commit,
            tuple(
                artifact
                for artifact in jenkins.artifacts
                if artifact.path != "jenkins/Jenkinsfile"
            ),
            jenkins.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.jenkins.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)

    def test_malformed_primary_artifact_shapes_fail_without_crashing(self) -> None:
        malformed = {
            "docker": ("docker/metadata.json", "[]"),
            "jenkins": (
                f"jenkins/environments/{self.model.environments[0].name}.json",
                "[]",
            ),
            "kubernetes": (
                f"k8s/overlays/{self.model.environments[0].name}/deployment.yaml",
                "metadata: []\nspec:\n  template:\n    spec:\n      containers: invalid\n",
            ),
        }
        for adapter_name, (path, content) in malformed.items():
            with self.subTest(adapter=adapter_name):
                results = matching_results(self.model)
                index = ("docker", "jenkins", "kubernetes").index(adapter_name)
                original = results[index]
                artifacts = tuple(
                    GeneratedArtifact(artifact.path, content, artifact.mode)
                    if artifact.path == path
                    else artifact
                    for artifact in original.artifacts
                )
                results[index] = AdapterResult(
                    original.adapter,
                    original.adapter_version,
                    original.template_commit,
                    artifacts,
                    original.contract,
                )

                report = validate_cross_project_contract(self.model, results)

                check = next(
                    item
                    for item in report.checks
                    if item.check == f"contract.{adapter_name}.artifacts"
                )
                self.assertEqual(check.status, ValidationStatus.FAILED)

    def test_non_string_artifact_content_fails_without_crashing(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                None,  # type: ignore[arg-type]
                artifact.mode,
                artifact.origins,
            )
            if artifact.path == "docker/Dockerfile"
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)
        check = next(
            item
            for item in report.checks
            if item.check == "contract.docker.artifacts"
        )

        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "docker.artifacts[0].content",
            {mismatch["path"] for mismatch in check.details["mismatches"]},
        )

    def test_docker_metadata_tag_strategy_and_expression_are_executable_contract(self) -> None:
        for key, expected_path in (
            ("tagStrategy", "docker.metadata.image.tagStrategy"),
            ("tagExpression", "docker.metadata.image.tagExpression"),
        ):
            with self.subTest(key=key):
                results = matching_results(self.model)
                docker = results[0]
                metadata = json.loads(docker.artifact("docker/metadata.json").content)
                metadata["image"][key] = "incorrect"
                artifacts = tuple(
                    GeneratedArtifact(
                        artifact.path,
                        json.dumps(metadata),
                        artifact.mode,
                    )
                    if artifact.path == "docker/metadata.json"
                    else artifact
                    for artifact in docker.artifacts
                )
                results[0] = AdapterResult(
                    docker.adapter,
                    docker.adapter_version,
                    docker.template_commit,
                    artifacts,
                    docker.contract,
                )

                report = validate_cross_project_contract(self.model, results)

                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.docker.artifacts"
                )
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(
                    expected_path,
                    [mismatch["path"] for mismatch in check.details["mismatches"]],
                )

    def test_existing_dockerfile_contract_requires_provable_uid_not_generated_shape(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["build"]["dockerfile"] = {
            "strategy": "existing",
            "path": "Dockerfile",
        }
        model = normalize_config(raw)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "Dockerfile").write_text(
                "FROM python:3.12-slim\nUSER 10001:10001\n",
                encoding="utf-8",
            )
            source = SourceResolution(
                key="docker",
                path=project,
                origin="validation-fixture",
                commit="0" * 40,
                remote=None,
                matches_lock=True,
            )
            docker = DockerBuildAdapter(source).render(
                model,
                project_root=project,
            )

        results = matching_results(model)
        results[0] = docker
        report = validate_cross_project_contract(model, results)

        check = next(
            item
            for item in report.checks
            if item.check == "contract.docker.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.PASSED)

    def test_generated_dockerfile_base_image_drift_fails_artifact_contract(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content.replace(
                    "ARG BUILDER_IMAGE=python:3.12-slim",
                    "ARG BUILDER_IMAGE=attacker.invalid/pwn:latest",
                ),
                artifact.mode,
            )
            if artifact.path == "docker/Dockerfile"
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item
            for item in report.checks
            if item.check == "contract.docker.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "docker.Dockerfile.baseImages",
            [mismatch["path"] for mismatch in check.details["mismatches"]],
        )

    def test_docker_wrapper_and_ignore_policy_are_executable_contracts(self) -> None:
        cases = (
            ("docker/build.sh", "#!/usr/bin/env sh\nexit 0\n", 0o644),
            ("docker/Dockerfile.dockerignore", ".git\n", 0o644),
        )
        for path, content, mode in cases:
            with self.subTest(path=path):
                results = matching_results(self.model)
                docker = results[0]
                artifacts = tuple(
                    GeneratedArtifact(path, content, mode)
                    if artifact.path == path
                    else artifact
                    for artifact in docker.artifacts
                )
                results[0] = AdapterResult(
                    docker.adapter,
                    docker.adapter_version,
                    docker.template_commit,
                    artifacts,
                    docker.contract,
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.docker.artifacts"
                )
                paths = {
                    mismatch["path"] for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(path, paths)

    def test_generated_dockerfile_rejects_unrequested_instructions(self) -> None:
        results = matching_results(self.model)
        docker = results[0]
        dockerfile = docker.artifact("docker/Dockerfile")
        mutated = dockerfile.content.replace(
            f"USER {self.model.runtime_user}:{self.model.runtime_user}",
            (
                "RUN echo CONTRACT_BYPASS\n"
                f"USER {self.model.runtime_user}:{self.model.runtime_user}"
            ),
            1,
        )
        self.assertNotEqual(mutated, dockerfile.content)
        artifacts = tuple(
            GeneratedArtifact(artifact.path, mutated, artifact.mode)
            if artifact.path == dockerfile.path
            else artifact
            for artifact in docker.artifacts
        )
        results[0] = AdapterResult(
            docker.adapter,
            docker.adapter_version,
            docker.template_commit,
            artifacts,
            docker.contract,
        )

        report = validate_cross_project_contract(self.model, results)
        check = next(
            item
            for item in report.checks
            if item.check == "contract.docker.artifacts"
        )

        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "docker/Dockerfile.content",
            {mismatch["path"] for mismatch in check.details["mismatches"]},
        )

    def test_generated_control_characters_fail_without_optional_linters(self) -> None:
        results = matching_results(self.model)
        jenkins = results[1]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content + "\x00",
                artifact.mode,
            )
            if artifact.path == "jenkins/Jenkinsfile"
            else artifact
            for artifact in jenkins.artifacts
        )
        results[1] = AdapterResult(
            jenkins.adapter,
            jenkins.adapter_version,
            jenkins.template_commit,
            artifacts,
            jenkins.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.jenkins.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "jenkins/Jenkinsfile",
            [mismatch["path"] for mismatch in check.details["mismatches"]],
        )

    def test_jenkins_contract_requires_exact_environment_assignment(self) -> None:
        results = matching_results(self.model)
        jenkins = results[1]
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content.replace(
                    f"IMAGE_REGISTRY = '{self.model.image_registry}'",
                    f"IMAGE_REGISTRY = '{self.model.image_registry.replace('.', 'X', 1)}'",
                )
                + f"\n// {self.model.image_registry}\n",
                artifact.mode,
            )
            if artifact.path == "jenkins/Jenkinsfile"
            else artifact
            for artifact in jenkins.artifacts
        )
        results[1] = AdapterResult(
            jenkins.adapter,
            jenkins.adapter_version,
            jenkins.template_commit,
            artifacts,
            jenkins.contract,
        )

        report = validate_cross_project_contract(self.model, results)

        check = next(
            item for item in report.checks if item.check == "contract.jenkins.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            "jenkins.Jenkinsfile.registry",
            [mismatch["path"] for mismatch in check.details["mismatches"]],
        )

    def test_jenkins_executable_intent_rejects_comment_decoys(self) -> None:
        cases = (
            (
                "branch-routing",
                "branch pattern: 'develop', comparator: 'GLOB'",
                "branch pattern: 'unrouted', comparator: 'GLOB'",
                "jenkins.Jenkinsfile.branchRouting.Build Once",
            ),
            (
                "credential-id",
                "REGISTRY_CREDENTIAL_ID = 'ghcr-credentials'",
                "REGISTRY_CREDENTIAL_ID = 'wrong-credentials'",
                "jenkins.Jenkinsfile.registryCredentialId",
            ),
            (
                "credential-binding",
                "credentialsId: env.REGISTRY_CREDENTIAL_ID",
                "credentialsId: 'wrong-credentials'",
                "jenkins.Jenkinsfile.registryCredentialBinding",
            ),
            (
                "production-approval",
                "input message: 'Approve production deployment for sample-api?', ok: 'Deploy to production'",
                "echo 'production approval bypassed'",
                "jenkins.Jenkinsfile.productionApproval",
            ),
            (
                "rollback",
                "sh 'kubectl rollout undo deployment/sample-api --namespace sample-api-dev'",
                "sh 'kubectl rollout undo deployment/sample-api --namespace wrong-dev'",
                "jenkins.Jenkinsfile.rollback.dev",
            ),
            (
                "sbom",
                'syft "$IMAGE_REF" -o spdx-json=out/supply-chain/sbom.json',
                'syft "$IMAGE_REF" -o cyclonedx-json=out/supply-chain/sbom.json',
                "jenkins.Jenkinsfile.supplyChain.sbom",
            ),
            (
                "scan",
                "trivy image --format json --output out/supply-chain/vulnerabilities.json "
                '--exit-code 1 --severity HIGH,CRITICAL "$IMAGE_REF"',
                "trivy image --format json --output out/supply-chain/vulnerabilities.json "
                '--exit-code 0 --severity CRITICAL "$IMAGE_REF"',
                "jenkins.Jenkinsfile.supplyChain.scan",
            ),
            (
                "provenance",
                "subject: [[name: env.IMAGE_REPOSITORY, digest: [sha256: env.IMAGE_DIGEST.substring(7)]]],",
                "subject: [[name: env.IMAGE_REPOSITORY, digest: [sha256: '0' * 64]]],",
                "jenkins.Jenkinsfile.supplyChain.provenance",
            ),
        )
        for name, expected_text, replacement, expected_path in cases:
            with self.subTest(intent=name):
                results = matching_results(self.model)
                jenkinsfile = results[1].artifact("jenkins/Jenkinsfile").content
                self.assertIn(expected_text, jenkinsfile)
                mutated = jenkinsfile.replace(expected_text, replacement, 1)
                mutated += f"\n// decoy: {expected_text}\n"
                replace_jenkinsfile(results, mutated)

                report = validate_cross_project_contract(self.model, results)

                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                paths = {
                    mismatch["path"] for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(expected_path, paths)

    def test_jenkins_required_workflow_steps_cannot_be_replaced_by_decoys(self) -> None:
        cases = (
            (
                "container-plan",
                "sh './generated/docker/build.sh --validate'",
                "echo 'validation bypassed'",
                "jenkins.Jenkinsfile.containerPlanValidation",
            ),
            (
                "template-resolution",
                "templateRoot = sh(script: 'devops-stack templates path docker', returnStdout: true).trim()",
                "templateRoot = '/tmp/untrusted'",
                "jenkins.Jenkinsfile.dockerTemplateResolution",
            ),
            (
                "deployment-apply",
                'apply_output=$(kubectl apply -f "$render_root/rendered.yaml")',
                "apply_output='deployment.apps/sample-api configured'",
                "jenkins.Jenkinsfile.deployment.dev",
            ),
            (
                "rollout-status",
                "sh 'kubectl rollout status deployment/sample-api --namespace sample-api-dev --timeout=5m'",
                "echo 'rollout assumed healthy'",
                "jenkins.Jenkinsfile.rollout.dev",
            ),
        )
        for name, original, replacement, expected_path in cases:
            with self.subTest(workflow=name):
                results = matching_results(self.model)
                jenkinsfile = results[1].artifact("jenkins/Jenkinsfile").content
                self.assertIn(original, jenkinsfile)
                replace_jenkinsfile(
                    results,
                    jenkinsfile.replace(original, replacement, 1),
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                paths = {
                    mismatch["path"] for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(expected_path, paths)

    def test_jenkins_authentication_and_job_dsl_are_closed_world_contracts(self) -> None:
        cases = (
            (
                "jenkins/Jenkinsfile",
                "set +x",
                "set -x",
            ),
            (
                "jenkins/Jenkinsfile",
                r'''printf \'%s\' "$REGISTRY_PASSWORD" | docker login "$IMAGE_REGISTRY" --username "$REGISTRY_USER" --password-stdin''',
                "echo 'registry login bypassed'",
            ),
            (
                "jenkins/Jenkinsfile",
                'rm -rf "$docker_config"',
                ": # cleanup disabled",
            ),
            (
                "jenkins/job-dsl.groovy",
                "scriptPath('generated/jenkins/Jenkinsfile')",
                "scriptPath('attacker/Jenkinsfile')",
            ),
            (
                "jenkins/job-dsl.groovy",
                "if (authority.contains('@')) {",
                "if (false) {",
            ),
        )
        for path, original, replacement in cases:
            with self.subTest(path=path, original=original):
                results = matching_results(self.model)
                jenkins = results[1]
                artifacts = tuple(
                    GeneratedArtifact(
                        artifact.path,
                        artifact.content.replace(original, replacement, 1),
                        artifact.mode,
                    )
                    if artifact.path == path
                    else artifact
                    for artifact in jenkins.artifacts
                )
                self.assertTrue(
                    any(
                        artifact.path == path and replacement in artifact.content
                        for artifact in artifacts
                    )
                )
                results[1] = AdapterResult(
                    jenkins.adapter,
                    jenkins.adapter_version,
                    jenkins.template_commit,
                    artifacts,
                    jenkins.contract,
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(
                    f"{path}.content",
                    {
                        mismatch["path"]
                        for mismatch in check.details["mismatches"]
                    },
                )

    def test_jenkins_auxiliary_artifacts_are_closed_world_contracts(self) -> None:
        cases = (
            ("jenkins/README.md", 0o644),
            ("jenkins/environments/dev.json", 0o777),
        )
        for path, mode in cases:
            with self.subTest(path=path):
                results = matching_results(self.model)
                jenkins = results[1]
                original = jenkins.artifact(path).content
                if path.endswith(".json"):
                    value = json.loads(original)
                    value["unrequested"] = True
                    mutated = json.dumps(value, indent=2, sort_keys=True) + "\n"
                else:
                    mutated = original + "\nUNREQUESTED\n"
                artifacts = tuple(
                    GeneratedArtifact(
                        artifact.path,
                        mutated,
                        mode,
                    )
                    if artifact.path == path
                    else artifact
                    for artifact in jenkins.artifacts
                )
                results[1] = AdapterResult(
                    jenkins.adapter,
                    jenkins.adapter_version,
                    jenkins.template_commit,
                    artifacts,
                    jenkins.contract,
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                paths = {
                    mismatch["path"]
                    for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(f"{path}.content", paths)
                if mode != 0o644:
                    self.assertIn(f"{path}.mode", paths)

    def test_artifact_origins_are_part_of_the_closed_contract(self) -> None:
        results = matching_results(self.model)
        jenkins = results[1]
        path = "jenkins/Jenkinsfile"
        artifacts = tuple(
            GeneratedArtifact(
                artifact.path,
                artifact.content,
                artifact.mode,
                ("fabricated-origin", "secret=plaintext"),
            )
            if artifact.path == path
            else artifact
            for artifact in jenkins.artifacts
        )
        results[1] = AdapterResult(
            jenkins.adapter,
            jenkins.adapter_version,
            jenkins.template_commit,
            artifacts,
            jenkins.contract,
        )

        report = validate_cross_project_contract(self.model, results)
        check = next(
            item
            for item in report.checks
            if item.check == "contract.jenkins.artifacts"
        )

        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn(
            f"{path}.origins",
            {mismatch["path"] for mismatch in check.details["mismatches"]},
        )

    def test_kubernetes_complete_inventory_rejects_unrequested_content(self) -> None:
        cases = (
            ("base-image", "k8s/base/deployment.yaml"),
            ("pod-annotation", "k8s/overlays/dev/deployment.yaml"),
            ("platform-context", "k8s/platform-context.json"),
            ("extra-artifact", "k8s/unrequested.yaml"),
        )
        for mutation, path in cases:
            with self.subTest(mutation=mutation):
                results = matching_results(self.model)
                kubernetes = results[2]
                artifacts = list(kubernetes.artifacts)
                if mutation == "extra-artifact":
                    artifacts.append(
                        GeneratedArtifact(path, "apiVersion: v1\nkind: Secret\n")
                    )
                else:
                    index = next(
                        position
                        for position, artifact in enumerate(artifacts)
                        if artifact.path == path
                    )
                    artifact = artifacts[index]
                    if mutation == "platform-context":
                        document = json.loads(artifact.content)
                        document["unrequested"] = True
                        content = json.dumps(document, indent=2, sort_keys=True) + "\n"
                        mode = 0o777
                    else:
                        document = yaml.safe_load(artifact.content)
                        if mutation == "base-image":
                            document["spec"]["template"]["spec"]["containers"][0][
                                "image"
                            ] = "attacker.invalid/rootkit:latest"
                        else:
                            document["spec"]["template"]["metadata"][
                                "annotations"
                            ]["sidecar.istio.io/inject"] = "true"
                        content = yaml.safe_dump(document, sort_keys=False)
                        mode = artifact.mode
                    artifacts[index] = GeneratedArtifact(path, content, mode)
                results[2] = AdapterResult(
                    kubernetes.adapter,
                    kubernetes.adapter_version,
                    kubernetes.template_commit,
                    tuple(artifacts),
                    kubernetes.contract,
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.kubernetes.artifacts"
                )
                paths = {
                    mismatch["path"]
                    for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                if mutation == "extra-artifact":
                    self.assertIn("kubernetes.artifacts.paths", paths)
                else:
                    self.assertIn(f"{path}.content", paths)
                if mutation == "platform-context":
                    self.assertIn(f"{path}.mode", paths)

    def test_kubernetes_topology_and_pod_security_mutations_fail(self) -> None:
        cases = (
            ("second-container", "kubernetes.environments.dev.containerCount"),
            ("host-network", "kubernetes.environments.dev.podFields"),
            (
                "paused-deployment",
                "kubernetes.environments.dev.deploymentSpecFields",
            ),
            (
                "external-service",
                "kubernetes.environments.dev.serviceSpecFields",
            ),
            ("missing-base", "k8s/base/kustomization.yaml"),
            (
                "missing-replace",
                "kubernetes.environments.dev.deployment.patchStrategy",
            ),
        )
        for mutation, expected_path in cases:
            with self.subTest(mutation=mutation):
                results = matching_results(self.model)
                kubernetes = results[2]
                artifacts = list(kubernetes.artifacts)
                if mutation == "missing-base":
                    artifacts = [
                        artifact
                        for artifact in artifacts
                        if artifact.path != "k8s/base/kustomization.yaml"
                    ]
                else:
                    path = (
                        "k8s/overlays/dev/service.yaml"
                        if mutation == "external-service"
                        else "k8s/overlays/dev/deployment.yaml"
                    )
                    index = next(
                        position
                        for position, artifact in enumerate(artifacts)
                        if artifact.path == path
                    )
                    document = yaml.safe_load(artifacts[index].content)
                    if mutation == "second-container":
                        document["spec"]["template"]["spec"]["containers"].append(
                            {
                                "name": "privileged-sidecar",
                                "image": "attacker.invalid/sidecar:latest",
                                "securityContext": {"privileged": True},
                            }
                        )
                    elif mutation == "host-network":
                        document["spec"]["template"]["spec"]["hostNetwork"] = True
                    elif mutation == "paused-deployment":
                        document["spec"]["paused"] = True
                    elif mutation == "external-service":
                        document["spec"]["externalIPs"] = ["203.0.113.10"]
                        document["spec"]["loadBalancerSourceRanges"] = [
                            "0.0.0.0/0"
                        ]
                    else:
                        document.pop("$patch")
                    artifacts[index] = GeneratedArtifact(
                        path,
                        yaml.safe_dump(document, sort_keys=False),
                        artifacts[index].mode,
                    )
                results[2] = AdapterResult(
                    kubernetes.adapter,
                    kubernetes.adapter_version,
                    kubernetes.template_commit,
                    tuple(artifacts),
                    kubernetes.contract,
                )

                report = validate_cross_project_contract(self.model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.kubernetes.artifacts"
                )
                paths = {
                    mismatch["path"] for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(expected_path, paths)

    def test_jenkins_single_platform_supply_chain_intent_passes(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["image"]["architectures"] = ["linux/amd64"]
        model = normalize_config(raw)

        report = validate_cross_project_contract(model, matching_results(model))

        check = next(
            item
            for item in report.checks
            if item.check == "contract.jenkins.artifacts"
        )
        self.assertEqual(check.status, ValidationStatus.PASSED)

    def test_jenkins_image_tag_resolution_is_exact_for_every_strategy(self) -> None:
        strategies = (
            {"strategy": "branch-sha"},
            {"strategy": "git-sha"},
            {"strategy": "semver"},
            {"strategy": "fixed", "value": "release-1.2.3"},
        )
        for tag in strategies:
            with self.subTest(strategy=tag["strategy"]):
                raw = copy.deepcopy(self.raw)
                raw["image"]["tag"] = tag
                model = normalize_config(raw)
                results = matching_results(model)
                baseline = validate_cross_project_contract(model, results)
                baseline_check = next(
                    item
                    for item in baseline.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                self.assertEqual(baseline_check.status, ValidationStatus.PASSED)

                jenkinsfile = results[1].artifact("jenkins/Jenkinsfile").content
                mutated = jenkinsfile.replace(
                    next(
                        line
                        for line in jenkinsfile.splitlines()
                        if line.strip().startswith("env.IMAGE_TAG =")
                    ),
                    "                    env.IMAGE_TAG = 'latest'",
                    1,
                )
                replace_jenkinsfile(results, mutated)

                report = validate_cross_project_contract(model, results)
                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(
                    "jenkins.Jenkinsfile.imageTagResolution",
                    [mismatch["path"] for mismatch in check.details["mismatches"]],
                )

    def test_jenkins_disabled_intent_rejects_executable_steps(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["ci"]["approval"]["production"] = False
        raw["deployment"]["rollback"]["enabled"] = False
        for capability in ("sbom", "scan", "provenance"):
            raw["supplyChain"][capability]["enabled"] = False
        model = normalize_config(raw)
        results = matching_results(model)
        baseline = validate_cross_project_contract(model, results)
        baseline_check = next(
            item
            for item in baseline.checks
            if item.check == "contract.jenkins.artifacts"
        )
        self.assertEqual(baseline_check.status, ValidationStatus.PASSED)
        production_marker = "        stage('Deploy Same Digest production') {"
        unexpected_approval = "\n".join(
            (
                "        stage('Production Approval') {",
                "            when {",
                "                anyOf {",
                "                    branch pattern: 'main', comparator: 'GLOB'",
                "                }",
                "            }",
                "            steps {",
                "                timeout(time: 1, unit: 'HOURS') {",
                "                    input message: 'unexpected', ok: 'Deploy to production'",
                "                }",
                "            }",
                "        }",
                "",
                production_marker,
            )
        )
        cases = (
            (
                "sbom",
                "echo 'SBOM generation is disabled by the normalized model.'",
                'sh \'syft "$IMAGE_REF" -o spdx-json=out/supply-chain/sbom.json\'',
                "jenkins.Jenkinsfile.supplyChain.sbom",
            ),
            (
                "scan",
                "echo 'Vulnerability scanning is disabled by the normalized model.'",
                'sh \'trivy image --format json --output out/supply-chain/vulnerabilities.json --exit-code 1 --severity HIGH,CRITICAL "$IMAGE_REF"\'',
                "jenkins.Jenkinsfile.supplyChain.scan",
            ),
            (
                "provenance",
                "echo 'Provenance generation is disabled by the normalized model.'",
                "sh 'echo unsafe provenance'",
                "jenkins.Jenkinsfile.supplyChain.provenance",
            ),
            (
                "approval",
                production_marker,
                unexpected_approval,
                "jenkins.Jenkinsfile.productionApproval",
            ),
            (
                "rollback",
                "echo 'Rollback is disabled for dev.'",
                "sh 'kubectl rollout undo deployment/sample-api --namespace sample-api-dev'",
                "jenkins.Jenkinsfile.rollback.dev",
            ),
        )
        for name, original, replacement, expected_path in cases:
            with self.subTest(intent=name):
                mutated_results = matching_results(model)
                jenkinsfile = mutated_results[1].artifact(
                    "jenkins/Jenkinsfile"
                ).content
                self.assertIn(original, jenkinsfile)
                mutated = jenkinsfile.replace(original, replacement, 1)
                replace_jenkinsfile(mutated_results, mutated)

                report = validate_cross_project_contract(model, mutated_results)

                check = next(
                    item
                    for item in report.checks
                    if item.check == "contract.jenkins.artifacts"
                )
                paths = {
                    mismatch["path"] for mismatch in check.details["mismatches"]
                }
                self.assertEqual(check.status, ValidationStatus.FAILED)
                self.assertIn(expected_path, paths)

    def test_missing_adapter_fails(self) -> None:
        report = validate_cross_project_contract(
            self.model,
            [
                result("docker", self.model.contract(), self.model),
                result("jenkins", self.model.contract(), self.model),
            ],
        )

        check = next(check for check in report.checks if check.check == "contract.adapters-present")
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertEqual(check.details["missing"], ["kubernetes"])

    def test_adapter_metadata_rejects_fabricated_version_and_commit(self) -> None:
        results = matching_results(self.model)
        kubernetes = results[2]
        results[2] = AdapterResult(
            kubernetes.adapter,
            "99.0.0",
            "0" * 40,
            kubernetes.artifacts,
            kubernetes.contract,
            kubernetes.diagnostics,
        )

        report = validate_cross_project_contract(self.model, results)
        check = next(
            item
            for item in report.checks
            if item.check == "contract.adapter-metadata"
        )

        self.assertFalse(report.passed)
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertEqual(
            {
                mismatch["path"]
                for mismatch in check.details["mismatches"]
            },
            {
                "$.adapters.kubernetes.adapterVersion",
                "$.adapters.kubernetes.templateCommit",
            },
        )

    def test_duplicate_branch_mapping_fails(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["ci"]["branches"]["staging"].append("main")
        model = normalize_config(raw)
        results = matching_results(model)

        report = validate_cross_project_contract(model, results)

        check = next(check for check in report.checks if check.check == "contract.branch-environment-map")
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertEqual(check.details["duplicates"], {"main": ["staging", "production"]})

    def test_production_policy_failure_is_not_hidden_by_matching_adapters(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["environments"]["production"]["replicas"] = 1
        model = normalize_config(raw)
        results = matching_results(model)

        report = validate_cross_project_contract(model, results)

        check = next(check for check in report.checks if check.check == "policy.production-safety")
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn("below required", check.message)

    def test_resource_request_must_not_exceed_limit(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["deployment"]["resources"]["requests"]["memory"] = "1Gi"
        model = normalize_config(raw)
        results = matching_results(model)

        report = validate_cross_project_contract(model, results)

        check = next(check for check in report.checks if check.check == "policy.resource-units")
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn("memory request exceeds limit", check.message)

    def test_production_resources_must_be_positive(self) -> None:
        raw = copy.deepcopy(self.raw)
        raw["environments"]["production"]["resources"] = {
            "requests": {"cpu": "0m", "memory": "0Mi"},
            "limits": {"cpu": "0m", "memory": "0Mi"},
        }
        model = normalize_config(raw)

        report = validate_cross_project_contract(model, matching_results(model))

        check = next(
            item for item in report.checks if item.check == "policy.production-safety"
        )
        self.assertEqual(check.status, ValidationStatus.FAILED)
        self.assertIn("requests must be positive", check.message)
        self.assertIn("limits must be positive", check.message)


if __name__ == "__main__":
    unittest.main()
