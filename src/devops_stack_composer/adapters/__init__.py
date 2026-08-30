"""Template-specific projections of the normalized DevOps model."""

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.adapters.docker import DockerBuildAdapter
from devops_stack_composer.adapters.jenkins import JenkinsPipelineAdapter
from devops_stack_composer.adapters.kubernetes import KubernetesAdapter

KubernetesPlatformAdapter = KubernetesAdapter

__all__ = [
    "AdapterResult",
    "DockerBuildAdapter",
    "GeneratedArtifact",
    "JenkinsPipelineAdapter",
    "KubernetesAdapter",
    "KubernetesPlatformAdapter",
]
