"""Template-specific projections of the normalized DevOps model."""

from typing import Any

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact


def __getattr__(name: str) -> Any:
    """Load adapter implementations lazily to avoid validation import cycles."""

    if name == "DockerBuildAdapter":
        from devops_stack_composer.adapters.docker import DockerBuildAdapter

        return DockerBuildAdapter
    if name == "JenkinsPipelineAdapter":
        from devops_stack_composer.adapters.jenkins import JenkinsPipelineAdapter

        return JenkinsPipelineAdapter
    if name in {"KubernetesAdapter", "KubernetesPlatformAdapter"}:
        from devops_stack_composer.adapters.kubernetes import KubernetesAdapter

        return KubernetesAdapter
    raise AttributeError(name)

__all__ = [
    "AdapterResult",
    "DockerBuildAdapter",
    "GeneratedArtifact",
    "JenkinsPipelineAdapter",
    "KubernetesAdapter",
    "KubernetesPlatformAdapter",
]
