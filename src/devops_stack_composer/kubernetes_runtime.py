"""Digest-pinned Kubernetes rendering and same-image rollback-test revisions."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import yaml

from devops_stack_composer.adapters.base import GeneratedArtifact
from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.evidence_validation import validate_kubernetes_documents
from devops_stack_composer.model import ENVIRONMENT_ORDER, NormalizedDevOpsModel
from devops_stack_composer.oci import parse_oci_reference


class KubernetesRenderError(DevOpsStackError):
    """Raised when static artifacts cannot become a closed digest-pinned manifest."""


@dataclass(frozen=True)
class ResolvedKubernetesManifest:
    environment: str
    namespace: str
    immutable_image_reference: str
    content: str
    sha256: str
    resource_ids: tuple[str, ...]

    @property
    def documents(self) -> tuple[Mapping[str, Any], ...]:
        values = tuple(value for value in yaml.safe_load_all(self.content) if value is not None)
        if any(not isinstance(value, Mapping) for value in values):
            raise KubernetesRenderError("resolved YAML contains a non-object document")
        return values


_ORDER = {
    "Namespace": 0,
    "ServiceAccount": 1,
    "ConfigMap": 2,
    "Secret": 3,
    "Service": 4,
    "Deployment": 5,
    "StatefulSet": 6,
    "DaemonSet": 7,
    "Job": 8,
    "CronJob": 9,
}


def _load_artifact(artifacts: Mapping[str, GeneratedArtifact], path: str) -> dict[str, Any]:
    artifact = artifacts.get(path)
    if artifact is None:
        raise KubernetesRenderError(f"required generated Kubernetes artifact is missing: {path}")
    try:
        value = yaml.safe_load(artifact.content)
    except yaml.YAMLError as exc:
        raise KubernetesRenderError(f"generated artifact is invalid YAML: {path}") from exc
    if not isinstance(value, dict):
        raise KubernetesRenderError(f"generated artifact must be one YAML object: {path}")
    value.pop("$patch", None)
    return value


def _resource_id(document: Mapping[str, Any]) -> str:
    metadata = document.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    return "/".join(
        (
            str(document.get("apiVersion", "")),
            str(document.get("kind", "")),
            str(metadata.get("namespace", "")),
            str(metadata.get("name", "")),
        )
    )


def _replace_images(
    document: dict[str, Any],
    *,
    intended_repository: str,
    immutable_reference: str,
) -> None:
    kind = document.get("kind")
    specification = document.get("spec")
    if not isinstance(specification, dict):
        return
    pod_spec: Any = None
    if kind == "Pod":
        pod_spec = specification
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        template = specification.get("template")
        pod_spec = template.get("spec") if isinstance(template, dict) else None
    elif kind == "CronJob":
        job_template = specification.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
        template = job_spec.get("template") if isinstance(job_spec, dict) else None
        pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        return
    for field in ("initContainers", "containers"):
        containers = pod_spec.get(field, [])
        if not isinstance(containers, list):
            raise KubernetesRenderError(f"{kind} {field} must be an array")
        for container in containers:
            if not isinstance(container, dict) or not isinstance(container.get("image"), str):
                raise KubernetesRenderError(f"{kind} container has no image")
            current = parse_oci_reference(container["image"])
            if current.repository != intended_repository:
                raise KubernetesRenderError(
                    f"unapproved additional image repository: {current.repository}"
                )
            container["image"] = immutable_reference


def render_resolved_environment(
    artifacts: Iterable[GeneratedArtifact],
    model: NormalizedDevOpsModel,
    environment: str,
    immutable_image_reference: str,
) -> ResolvedKubernetesManifest:
    if environment not in ENVIRONMENT_ORDER:
        raise KubernetesRenderError(
            f"unsupported environment {environment!r}; expected {', '.join(ENVIRONMENT_ORDER)}"
        )
    immutable = parse_oci_reference(immutable_image_reference)
    if immutable.digest is None or immutable.tag is not None:
        raise KubernetesRenderError(
            "resolved Kubernetes image must be repository@sha256:digest without a tag"
        )
    _registry, separator, resolved_repository = immutable.repository.partition("/")
    if not separator or resolved_repository != model.image_repository:
        # Ephemeral execution intentionally replaces only the registry endpoint;
        # the complete repository path remains exact.
        raise KubernetesRenderError(
            "resolved image repository does not match the configured image repository"
        )
    artifact_map = {artifact.path: artifact for artifact in artifacts}
    prefix = f"k8s/overlays/{environment}"
    namespace_document = _load_artifact(artifact_map, f"{prefix}/namespace.yaml")
    namespace = namespace_document.get("metadata", {}).get("name")
    if not isinstance(namespace, str) or not namespace:
        raise KubernetesRenderError("environment namespace artifact has no name")

    overlay_kustomization = _load_artifact(artifact_map, f"{prefix}/kustomization.yaml")
    patches = overlay_kustomization.get("patches")
    if not isinstance(patches, list):
        raise KubernetesRenderError("environment kustomization has no patch list")
    documents: list[dict[str, Any]] = [namespace_document]
    documents.append(_load_artifact(artifact_map, "k8s/base/serviceaccount.yaml"))
    for patch in patches:
        path = patch.get("path") if isinstance(patch, Mapping) else None
        if not isinstance(path, str) or "/" in path or path in {"", ".", ".."}:
            raise KubernetesRenderError("environment kustomization contains an unsafe patch path")
        documents.append(_load_artifact(artifact_map, f"{prefix}/{path}"))

    for document in documents:
        if document.get("kind") != "Namespace":
            metadata = document.setdefault("metadata", {})
            if not isinstance(metadata, dict):
                raise KubernetesRenderError("resource metadata must be an object")
            metadata["namespace"] = namespace
        _replace_images(
            document,
            intended_repository=model.image_name,
            immutable_reference=immutable_image_reference,
        )
    documents.sort(
        key=lambda value: (
            _ORDER.get(str(value.get("kind", "")), 99),
            _resource_id(value),
        )
    )
    validate_kubernetes_documents(
        documents,
        immutable_reference=immutable_image_reference,
    )
    content = "---\n".join(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
        for document in documents
    )
    digest = hashlib.sha256(content.encode()).hexdigest()
    return ResolvedKubernetesManifest(
        environment=environment,
        namespace=namespace,
        immutable_image_reference=immutable_image_reference,
        content=content,
        sha256=digest,
        resource_ids=tuple(_resource_id(document) for document in documents),
    )


def render_intentional_readiness_failure(
    manifest: ResolvedKubernetesManifest,
    *,
    deployment_name: str,
    run_id: str,
) -> str:
    documents = [copy.deepcopy(dict(document)) for document in manifest.documents]
    deployments = [
        document
        for document in documents
        if document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") == deployment_name
    ]
    if len(deployments) != 1:
        raise KubernetesRenderError(
            f"expected exactly one Deployment named {deployment_name}"
        )
    deployment = deployments[0]
    metadata = deployment.setdefault("metadata", {})
    annotations = metadata.setdefault("annotations", {})
    if not isinstance(annotations, dict):
        raise KubernetesRenderError("Deployment annotations must be an object")
    annotations["devops-stack.io/rollback-test"] = run_id
    containers = deployment["spec"]["template"]["spec"].get("containers")
    if not isinstance(containers, list) or not containers:
        raise KubernetesRenderError("Deployment has no containers")
    for container in containers:
        readiness = container.get("readinessProbe")
        http_get = readiness.get("httpGet") if isinstance(readiness, dict) else None
        if not isinstance(http_get, dict):
            raise KubernetesRenderError("Deployment container has no HTTP readiness probe")
        http_get["path"] = "/__devops-stack-intentional-readiness-failure__"
    validate_kubernetes_documents(
        (deployment,),
        immutable_reference=manifest.immutable_image_reference,
    )
    return yaml.safe_dump(deployment, sort_keys=False, allow_unicode=True)
