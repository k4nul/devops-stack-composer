"""Execute digest-pinned manifests against a real Kubernetes API.

The executor deliberately accepts already-resolved manifests and an immutable
artifact record.  It does not build images, discover credentials, or claim
production-cluster compatibility.  Every external operation is an argv-only
``kubectl`` invocation through an injectable runner.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.execution_models import DeploymentEvidence, ResolvedArtifact
from devops_stack_composer.kubernetes_runtime import (
    KubernetesRenderError,
    ResolvedKubernetesManifest,
    render_intentional_readiness_failure,
)
from devops_stack_composer.oci import digest_from_image_id, parse_digest


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_KUBECTL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HTTP_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_LABEL_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$")
_LABEL_PREFIX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_LABEL_VALUE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?$")
_REVISION = re.compile(r"^[1-9][0-9]*$")
_URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_AUTHORIZATION = re.compile(r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*")
_INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key)"
    r"\b[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_SECRET_FLAG = re.compile(
    r"(?ix)(--(?:password|passphrase|token|secret|private-key|access-key|api-key)"
    r"(?:\s+|=))(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_ABSOLUTE_FILESYSTEM_PATH = re.compile(
    r"(?<![A-Za-z0-9])/(?:home|root|tmp|var|etc|Users)(?:/[^\s:'\"<>|]+)+"
)
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:password|passphrase|token|secret|private.?key|access.?key|api.?key)"
)

_MAX_JSON_OUTPUT = 1_000_000
_DIAGNOSTIC_LIMIT = 12_000
_TOTAL_DIAGNOSTIC_LIMIT = 60_000
_INTENTIONAL_READINESS_PATH = "/__devops-stack-intentional-readiness-failure__"


class KubernetesExecutionError(DevOpsStackError):
    """A bounded Kubernetes execution failure with safe diagnostic evidence."""

    def __init__(
        self,
        code: str,
        phase: str,
        detail: str,
        *,
        diagnostics: Sequence["DiagnosticRecord"] = (),
        rollback_attempted: bool = False,
        rollback_succeeded: bool = False,
    ) -> None:
        self.code = code
        self.phase = phase
        self.detail = detail
        self.diagnostics = tuple(diagnostics)
        self.rollback_attempted = rollback_attempted
        self.rollback_succeeded = rollback_succeeded
        super().__init__(f"{phase}: {detail}")


@dataclass(frozen=True)
class KubernetesExecutionRequest:
    """Closed inputs for one environment deployment and rollback exercise."""

    kubeconfig_path: Path
    manifests: tuple[ResolvedKubernetesManifest, ...]
    environment: str
    deployment_name: str
    service_name: str
    service_port: int
    health_path: str
    readiness_path: str
    artifact: ResolvedArtifact
    cluster_type: str
    cluster_identifier: str
    run_id: str
    rollout_timeout_seconds: int = 180
    approve_production: bool = False

    def __post_init__(self) -> None:
        kubeconfig = Path(self.kubeconfig_path)
        if not kubeconfig.is_absolute():
            raise ValueError("kubeconfig_path must be absolute and passed explicitly")
        object.__setattr__(self, "kubeconfig_path", kubeconfig)
        manifests = tuple(self.manifests)
        if not manifests:
            raise ValueError("manifests must include every configured environment")
        if len({manifest.environment for manifest in manifests}) != len(manifests):
            raise ValueError("manifests must have unique environments")
        if self.environment not in {manifest.environment for manifest in manifests}:
            raise ValueError("selected environment has no resolved manifest")
        object.__setattr__(self, "manifests", manifests)
        _require_dns_label("environment", self.environment)
        _require_dns_label("deployment_name", self.deployment_name)
        _require_dns_label("service_name", self.service_name)
        _require_identifier("cluster_type", self.cluster_type)
        _require_dns_label("cluster_identifier", self.cluster_identifier)
        if not _RUN_ID.fullmatch(self.run_id):
            raise ValueError("run_id has invalid syntax")
        if (
            isinstance(self.service_port, bool)
            or not isinstance(self.service_port, int)
            or not 1 <= self.service_port <= 65535
        ):
            raise ValueError("service_port must be between 1 and 65535")
        _require_http_path("health_path", self.health_path)
        _require_http_path("readiness_path", self.readiness_path)
        if (
            isinstance(self.rollout_timeout_seconds, bool)
            or not isinstance(self.rollout_timeout_seconds, int)
            or not 5 <= self.rollout_timeout_seconds <= 900
        ):
            raise ValueError("rollout_timeout_seconds must be between 5 and 900")
        if not isinstance(self.approve_production, bool):
            raise ValueError("approve_production must be boolean")
        if self.artifact.manifest_digest != self.artifact.platform_digest:
            raise ValueError(
                "Kubernetes execution requires one manifest digest to equal its platform digest"
            )
        for manifest in manifests:
            if manifest.immutable_image_reference != self.artifact.immutable_image_reference:
                raise ValueError("every manifest must use the resolved artifact reference")
            if not re.fullmatch(r"[0-9a-f]{64}", manifest.sha256):
                raise ValueError("manifest sha256 must be lowercase hexadecimal")
            actual_hash = hashlib.sha256(manifest.content.encode()).hexdigest()
            if actual_hash != manifest.sha256:
                raise ValueError("manifest content does not match its sha256")


@dataclass(frozen=True)
class DiagnosticRecord:
    """A relative evidence path and bounded, redacted content."""

    path: str
    content: str

    def __post_init__(self) -> None:
        path = PurePosixPath(self.path)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != self.path
            or self.path in {"", "."}
        ):
            raise ValueError("diagnostic path must be a normalized relative path")
        if len(self.content) > _DIAGNOSTIC_LIMIT:
            raise ValueError("diagnostic content exceeds its evidence bound")

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "content": self.content}


@dataclass(frozen=True)
class DryRunEvidence:
    environment: str
    namespace: str
    manifest_hash: str
    resource_ids: tuple[str, ...]
    scope: str = "Kubernetes API server-side dry-run acceptance"

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "namespace": self.namespace,
            "manifestHash": self.manifest_hash,
            "resourceIds": list(self.resource_ids),
            "accepted": True,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class PodObservation:
    name: str
    image_ids: tuple[str, ...]
    ready: bool
    restart_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "imageIds": list(self.image_ids),
            "ready": self.ready,
            "restartCount": self.restart_count,
        }


@dataclass(frozen=True)
class IntentionalFailureEvidence:
    observed: bool
    cause: str
    image_reference: str
    rollout_exit_code: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed": self.observed,
            "cause": self.cause,
            "imageReference": self.image_reference,
            "rolloutExitCode": self.rollout_exit_code,
        }


@dataclass(frozen=True)
class KubernetesExecutionResult:
    """Observed evidence; assurance is intentionally limited to the tested API."""

    deployment: DeploymentEvidence
    dry_runs: tuple[DryRunEvidence, ...]
    initial_pods: tuple[PodObservation, ...]
    recovered_pods: tuple[PodObservation, ...]
    intentional_failure: IntentionalFailureEvidence
    diagnostics: tuple[DiagnosticRecord, ...]
    assurance_scope: tuple[str, ...] = (
        "Kubernetes API server acceptance in the identified cluster",
        "observed rollout and Pod readiness",
        "HTTP requests through the Kubernetes API Service proxy",
        "same-digest configuration rollback recovery",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "deployment": self.deployment.to_dict(),
            "dryRuns": [item.to_dict() for item in self.dry_runs],
            "initialPods": [item.to_dict() for item in self.initial_pods],
            "recoveredPods": [item.to_dict() for item in self.recovered_pods],
            "intentionalFailure": self.intentional_failure.to_dict(),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "assuranceScope": list(self.assurance_scope),
        }


@dataclass(frozen=True)
class _DeploymentState:
    desired_replicas: int
    ready_replicas: int
    selector: str
    revision: str


def _require_plain(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be a non-empty plain string")
    return value


def _require_identifier(name: str, value: str) -> str:
    value = _require_plain(name, value)
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must use lowercase identifier syntax")
    return value


def _require_dns_label(name: str, value: str) -> str:
    if not isinstance(value, str) or not _DNS_LABEL.fullmatch(value):
        raise ValueError(f"{name} must be a DNS label")
    return value


def _require_http_path(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HTTP_PATH.fullmatch(value):
        raise ValueError(f"{name} must be a safe absolute HTTP path")
    if any(part == ".." for part in value.split("/")):
        raise ValueError(f"{name} must not traverse path segments")
    return value


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _sanitize(value: object, kubeconfig: Path, *, limit: int) -> str:
    if limit <= 0:
        return ""
    text = _text(value).replace(str(kubeconfig), "<private-kubeconfig>")
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _AUTHORIZATION.sub(r"\1<redacted>", text)
    text = _INLINE_SECRET.sub(r"\1<redacted>", text)
    text = _SECRET_FLAG.sub(r"\1<redacted>", text)
    text = _ABSOLUTE_FILESYSTEM_PATH.sub("<absolute-path>", text)
    text = "".join(
        character
        for character in text
        if character in "\n\r\t" or 32 <= ord(character) < 127
    ).strip()
    if len(text) <= limit:
        return text
    suffix = "\n...[truncated]"
    if limit <= len(suffix):
        return suffix[:limit]
    return text[: max(0, limit - len(suffix))] + suffix


def _safe_json_value(value: Any, kubeconfig: Path) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "<redacted>"
                if _SENSITIVE_KEY.search(str(key))
                else _safe_json_value(item, kubeconfig)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_json_value(item, kubeconfig) for item in value]
    if isinstance(value, str):
        return _sanitize(value, kubeconfig, limit=4096)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize(str(value), kubeconfig, limit=4096)


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KubernetesExecutionError(
            "MALFORMED_KUBECTL_JSON", context, "kubectl JSON root must be an object"
        )
    return value


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise KubernetesExecutionError(
            "MALFORMED_KUBECTL_JSON", context, "kubectl returned an invalid integer field"
        )
    return value


def _revision(document: Mapping[str, Any], context: str) -> str:
    metadata = _mapping(document.get("metadata"), context)
    annotations = metadata.get("annotations", {})
    annotations = _mapping(annotations, context)
    value = annotations.get("deployment.kubernetes.io/revision")
    if not isinstance(value, str) or not _REVISION.fullmatch(value):
        raise KubernetesExecutionError(
            "MALFORMED_KUBECTL_JSON", context, "Deployment revision annotation is missing"
        )
    return value


class KubernetesExecutor:
    """Perform a real rollout, endpoint check, failure, and rollback cycle."""

    def __init__(
        self,
        *,
        command_runner: CommandRunner | None = None,
        kubectl: str = "kubectl",
        command_timeout_seconds: float = 60.0,
        diagnostic_timeout_seconds: float = 20.0,
    ) -> None:
        if not _KUBECTL.fullmatch(kubectl):
            raise ValueError("kubectl must be a safe executable name")
        if not 1 <= command_timeout_seconds <= 300:
            raise ValueError("command_timeout_seconds must be between 1 and 300")
        if not 1 <= diagnostic_timeout_seconds <= 60:
            raise ValueError("diagnostic_timeout_seconds must be between 1 and 60")
        self._runner = command_runner or subprocess.run
        self._kubectl = kubectl
        self._command_timeout = float(command_timeout_seconds)
        self._diagnostic_timeout = float(diagnostic_timeout_seconds)

    def execute(self, request: KubernetesExecutionRequest) -> KubernetesExecutionResult:
        self._validate_kubeconfig(request.kubeconfig_path)
        if request.environment == "production" and not request.approve_production:
            raise KubernetesExecutionError(
                "PRODUCTION_APPROVAL_REQUIRED",
                "preflight",
                "production apply requires explicit approval",
            )
        manifest = next(
            item for item in request.manifests if item.environment == request.environment
        )
        selector, desired_replicas = self._local_workload_contract(request, manifest)

        try:
            dry_runs = self._dry_run_all(request)
            self._apply(request, manifest.content, phase="apply")
            self._rollout_status(request, expect_success=True, phase="rollout")
            initial_deployment = self._deployment_state(
                request,
                selector,
                require_available=True,
                expected_readiness_path=request.readiness_path,
                phase="rollout",
            )
            if initial_deployment.desired_replicas != desired_replicas:
                raise KubernetesExecutionError(
                    "REPLICA_CONTRACT_MISMATCH",
                    "rollout",
                    "live Deployment replica count differs from the resolved manifest",
                )
            initial_pods, initial_image_id = self._pod_state(
                request, selector, desired_replicas, phase="rollout"
            )
            health = self._probe(request, request.health_path, "health")
            readiness = self._probe(request, request.readiness_path, "readiness")
        except KubernetesExecutionError as exc:
            diagnostics = self._collect_diagnostics(request, selector, manifest, None)
            raise self._with_diagnostics(exc, diagnostics) from exc

        try:
            failure_manifest = render_intentional_readiness_failure(
                manifest,
                deployment_name=request.deployment_name,
                run_id=request.run_id,
            )
        except KubernetesRenderError as exc:
            raise KubernetesExecutionError(
                "FAILURE_REVISION_RENDER_FAILED",
                "rollback-smoke",
                str(exc),
            ) from exc

        try:
            self._apply(request, failure_manifest, phase="rollback-smoke")
        except KubernetesExecutionError as exc:
            diagnostics = self._collect_diagnostics(
                request, selector, manifest, failure_manifest
            )
            raise self._with_diagnostics(exc, diagnostics) from exc

        diagnostics: tuple[DiagnosticRecord, ...] = ()
        pending_failure: KubernetesExecutionError | None = None
        failure_evidence: IntentionalFailureEvidence | None = None
        try:
            self._deployment_state(
                request,
                selector,
                require_available=False,
                expected_readiness_path=_INTENTIONAL_READINESS_PATH,
                phase="rollback-smoke",
            )
            failed_rollout = self._rollout_status(
                request,
                expect_success=False,
                phase="rollback-smoke",
            )
            diagnostics = self._collect_diagnostics(
                request, selector, manifest, failure_manifest
            )
            if failed_rollout.returncode == 0:
                pending_failure = KubernetesExecutionError(
                    "EXPECTED_ROLLOUT_FAILURE_NOT_OBSERVED",
                    "rollback-smoke",
                    "the intentional readiness failure unexpectedly completed its rollout",
                )
            elif not self._readiness_failure_observed(diagnostics, failed_rollout):
                pending_failure = KubernetesExecutionError(
                    "EXPECTED_READINESS_FAILURE_NOT_OBSERVED",
                    "rollback-smoke",
                    "rollout failed, but evidence did not show the intentional readiness failure",
                )
            else:
                failure_evidence = IntentionalFailureEvidence(
                    observed=True,
                    cause="intentional HTTP readiness probe failure",
                    image_reference=request.artifact.immutable_image_reference,
                    rollout_exit_code=failed_rollout.returncode,
                )
        except KubernetesExecutionError as exc:
            pending_failure = exc
            diagnostics = self._collect_diagnostics(
                request, selector, manifest, failure_manifest
            )

        try:
            self._checked(
                request,
                [
                    "rollout",
                    "undo",
                    f"deployment/{request.deployment_name}",
                    "--namespace",
                    manifest.namespace,
                ],
                phase="rollback",
                code="ROLLBACK_FAILED",
                operation="undo the intentional Deployment revision",
            )
            self._rollout_status(request, expect_success=True, phase="rollback")
            recovered_deployment = self._deployment_state(
                request,
                selector,
                require_available=True,
                expected_readiness_path=request.readiness_path,
                phase="rollback",
            )
            if recovered_deployment.desired_replicas != desired_replicas:
                raise KubernetesExecutionError(
                    "REPLICA_CONTRACT_MISMATCH",
                    "rollback",
                    "recovered Deployment replica count differs from the resolved manifest",
                )
            if int(recovered_deployment.revision) <= int(initial_deployment.revision):
                raise KubernetesExecutionError(
                    "ROLLBACK_REVISION_NOT_OBSERVED",
                    "rollback",
                    "undo did not produce an observed recovery revision",
                )
            recovered_pods, recovered_image_id = self._pod_state(
                request, selector, desired_replicas, phase="rollback"
            )
            recovered_health = self._probe(request, request.health_path, "post-rollback-health")
            recovered_readiness = self._probe(
                request, request.readiness_path, "post-rollback-readiness"
            )
        except KubernetesExecutionError as exc:
            rollback_diagnostics = self._collect_diagnostics(
                request, selector, manifest, failure_manifest
            )
            all_diagnostics = self._merge_diagnostics(diagnostics, rollback_diagnostics)
            rollback_error = KubernetesExecutionError(
                "ROLLBACK_FAILED",
                "rollback",
                exc.detail,
                diagnostics=all_diagnostics,
                rollback_attempted=True,
                rollback_succeeded=False,
            )
            raise rollback_error from exc

        if pending_failure is not None:
            raise KubernetesExecutionError(
                pending_failure.code,
                pending_failure.phase,
                pending_failure.detail,
                diagnostics=diagnostics,
                rollback_attempted=True,
                rollback_succeeded=True,
            )
        assert failure_evidence is not None
        if health != recovered_health or readiness != recovered_readiness:
            raise KubernetesExecutionError(
                "ENDPOINT_RECOVERY_MISMATCH",
                "rollback",
                "post-rollback endpoint responses differ from the initial healthy revision",
                diagnostics=diagnostics,
                rollback_attempted=True,
                rollback_succeeded=True,
            )

        deployment = DeploymentEvidence(
            environment=request.environment,
            namespace=manifest.namespace,
            cluster_type=request.cluster_type,
            cluster_identifier=request.cluster_identifier,
            manifest_hash=manifest.sha256,
            deployed_image_reference=request.artifact.immutable_image_reference,
            expected_digest=request.artifact.manifest_digest,
            actual_pod_image_id=initial_image_id,
            rollout_status="PASSED",
            ready_replica_count=initial_deployment.ready_replicas,
            health_endpoint_result=health,
            readiness_endpoint_result=readiness,
            rollback_attempted=True,
            rollback_result="PASSED",
            final_revision=recovered_deployment.revision,
            final_digest=str(digest_from_image_id(recovered_image_id)),
            diagnostics_paths=tuple(record.path for record in diagnostics),
        )
        return KubernetesExecutionResult(
            deployment=deployment,
            dry_runs=dry_runs,
            initial_pods=initial_pods,
            recovered_pods=recovered_pods,
            intentional_failure=failure_evidence,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _validate_kubeconfig(path: Path) -> None:
        try:
            details = os.lstat(path)
        except OSError as exc:
            raise KubernetesExecutionError(
                "PRIVATE_KUBECONFIG_INVALID",
                "preflight",
                "the explicit private kubeconfig is unavailable",
            ) from exc
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o077
            or details.st_size == 0
        ):
            raise KubernetesExecutionError(
                "PRIVATE_KUBECONFIG_INVALID",
                "preflight",
                "the explicit kubeconfig must be a non-empty owner-only regular file",
            )

    def _local_workload_contract(
        self,
        request: KubernetesExecutionRequest,
        manifest: ResolvedKubernetesManifest,
    ) -> tuple[str, int]:
        deployments = [
            document
            for document in manifest.documents
            if document.get("kind") == "Deployment"
            and _mapping(document.get("metadata"), "preflight").get("name")
            == request.deployment_name
        ]
        if len(deployments) != 1:
            raise KubernetesExecutionError(
                "WORKLOAD_CONTRACT_INVALID",
                "preflight",
                "resolved manifest must contain exactly one selected Deployment",
            )
        services = [
            document
            for document in manifest.documents
            if document.get("kind") == "Service"
            and _mapping(document.get("metadata"), "preflight").get("name")
            == request.service_name
        ]
        if len(services) != 1:
            raise KubernetesExecutionError(
                "WORKLOAD_CONTRACT_INVALID",
                "preflight",
                "resolved manifest must contain exactly one selected Service",
            )
        deployment = deployments[0]
        specification = _mapping(deployment.get("spec"), "preflight")
        desired = _integer(specification.get("replicas"), "preflight", minimum=1)
        selector = self._selector(specification, "preflight")
        self._require_deployment_images(request, deployment, "preflight")
        self._require_readiness_path(deployment, request.readiness_path, "preflight")
        service_spec = _mapping(services[0].get("spec"), "preflight")
        ports = service_spec.get("ports")
        if not isinstance(ports, list) or not any(
            isinstance(item, Mapping) and item.get("port") == request.service_port
            for item in ports
        ):
            raise KubernetesExecutionError(
                "WORKLOAD_CONTRACT_INVALID",
                "preflight",
                "selected Service does not expose the configured service port",
            )
        return selector, desired

    def _dry_run_all(
        self, request: KubernetesExecutionRequest
    ) -> tuple[DryRunEvidence, ...]:
        evidence: list[DryRunEvidence] = []
        for manifest in request.manifests:
            namespace_documents = [
                document for document in manifest.documents if document.get("kind") == "Namespace"
            ]
            if len(namespace_documents) != 1:
                raise KubernetesExecutionError(
                    "NAMESPACE_CONTRACT_INVALID",
                    "server-side-dry-run",
                    "each resolved environment must contain exactly one Namespace",
                )
            namespace_content = yaml.safe_dump(
                dict(namespace_documents[0]), sort_keys=False, allow_unicode=True
            )
            self._checked(
                request,
                [
                    "apply",
                    "--server-side",
                    "--dry-run=server",
                    "--field-manager=devops-stack-composer",
                    "--filename=-",
                ],
                stdin=namespace_content,
                phase="server-side-dry-run",
                code="SERVER_DRY_RUN_FAILED",
                operation=f"server-side dry-run the {manifest.environment} Namespace",
            )
            self._checked(
                request,
                [
                    "apply",
                    "--server-side",
                    "--field-manager=devops-stack-composer",
                    "--filename=-",
                ],
                stdin=namespace_content,
                phase="namespace-bootstrap",
                code="NAMESPACE_BOOTSTRAP_FAILED",
                operation=f"create the {manifest.environment} test namespace",
            )
            self._checked(
                request,
                [
                    "apply",
                    "--server-side",
                    "--dry-run=server",
                    "--field-manager=devops-stack-composer",
                    "--filename=-",
                ],
                stdin=manifest.content,
                phase="server-side-dry-run",
                code="SERVER_DRY_RUN_FAILED",
                operation=f"server-side dry-run the {manifest.environment} manifest",
            )
            evidence.append(
                DryRunEvidence(
                    environment=manifest.environment,
                    namespace=manifest.namespace,
                    manifest_hash=manifest.sha256,
                    resource_ids=manifest.resource_ids,
                )
            )
        return tuple(evidence)

    def _apply(
        self,
        request: KubernetesExecutionRequest,
        content: str,
        *,
        phase: str,
    ) -> None:
        self._checked(
            request,
            [
                "apply",
                "--server-side",
                "--field-manager=devops-stack-composer",
                "--filename=-",
            ],
            stdin=content,
            phase=phase,
            code="APPLY_FAILED",
            operation="apply the digest-pinned manifest",
        )

    def _rollout_status(
        self,
        request: KubernetesExecutionRequest,
        *,
        expect_success: bool,
        phase: str,
    ) -> subprocess.CompletedProcess[str]:
        manifest = next(
            item for item in request.manifests if item.environment == request.environment
        )
        result = self._invoke(
            request,
            [
                "rollout",
                "status",
                f"deployment/{request.deployment_name}",
                "--namespace",
                manifest.namespace,
                f"--timeout={request.rollout_timeout_seconds}s",
            ],
            phase=phase,
            timeout=float(request.rollout_timeout_seconds + 15),
        )
        if expect_success and result.returncode != 0:
            self._raise_command_failure(
                request,
                result,
                code="ROLLOUT_FAILED",
                phase=phase,
                operation="wait for Deployment rollout",
            )
        return result

    def _deployment_state(
        self,
        request: KubernetesExecutionRequest,
        expected_selector: str,
        *,
        require_available: bool,
        expected_readiness_path: str,
        phase: str,
    ) -> _DeploymentState:
        manifest = next(
            item for item in request.manifests if item.environment == request.environment
        )
        result = self._checked(
            request,
            [
                "get",
                "deployment",
                request.deployment_name,
                "--namespace",
                manifest.namespace,
                "--output=json",
            ],
            phase=phase,
            code="DEPLOYMENT_INSPECTION_FAILED",
            operation="inspect the live Deployment",
        )
        document = self._json_document(request, result, phase)
        self._require_deployment_images(request, document, phase)
        self._require_readiness_path(document, expected_readiness_path, phase)
        specification = _mapping(document.get("spec"), phase)
        selector = self._selector(specification, phase)
        if selector != expected_selector:
            raise KubernetesExecutionError(
                "SELECTOR_CONTRACT_MISMATCH",
                phase,
                "live Deployment selector differs from the resolved manifest",
            )
        desired = _integer(specification.get("replicas"), phase, minimum=1)
        status_value = document.get("status", {})
        status_value = _mapping(status_value, phase)
        ready = status_value.get("readyReplicas", 0)
        ready = _integer(ready, phase)
        if require_available:
            metadata = _mapping(document.get("metadata"), phase)
            generation = _integer(metadata.get("generation"), phase, minimum=1)
            observed = _integer(status_value.get("observedGeneration"), phase, minimum=1)
            conditions = status_value.get("conditions")
            if not isinstance(conditions, list):
                raise KubernetesExecutionError(
                    "MALFORMED_KUBECTL_JSON", phase, "Deployment conditions must be an array"
                )
            available = any(
                isinstance(condition, Mapping)
                and condition.get("type") == "Available"
                and condition.get("status") == "True"
                for condition in conditions
            )
            replica_fields = (
                ready,
                _integer(status_value.get("availableReplicas", 0), phase),
                _integer(status_value.get("updatedReplicas", 0), phase),
                _integer(status_value.get("replicas", 0), phase),
            )
            unavailable = _integer(status_value.get("unavailableReplicas", 0), phase)
            if (
                observed < generation
                or not available
                or any(value != desired for value in replica_fields)
                or unavailable != 0
            ):
                raise KubernetesExecutionError(
                    "DEPLOYMENT_NOT_AVAILABLE",
                    phase,
                    "Deployment availability and replica evidence is incomplete",
                )
        return _DeploymentState(
            desired_replicas=desired,
            ready_replicas=ready,
            selector=selector,
            revision=_revision(document, phase),
        )

    def _pod_state(
        self,
        request: KubernetesExecutionRequest,
        selector: str,
        desired_replicas: int,
        *,
        phase: str,
    ) -> tuple[tuple[PodObservation, ...], str]:
        manifest = next(
            item for item in request.manifests if item.environment == request.environment
        )
        result = self._checked(
            request,
            [
                "get",
                "pods",
                "--namespace",
                manifest.namespace,
                "--selector",
                selector,
                "--output=json",
            ],
            phase=phase,
            code="POD_INSPECTION_FAILED",
            operation="inspect rolled-out Pods",
        )
        document = self._json_document(request, result, phase)
        items = document.get("items")
        if not isinstance(items, list):
            raise KubernetesExecutionError(
                "MALFORMED_KUBECTL_JSON", phase, "Pod list items must be an array"
            )
        active = [
            item
            for item in items
            if isinstance(item, Mapping)
            and _mapping(item.get("metadata"), phase).get("deletionTimestamp") is None
        ]
        if len(active) != desired_replicas:
            raise KubernetesExecutionError(
                "POD_REPLICA_MISMATCH",
                phase,
                "active Pod count does not equal the desired replica count",
            )
        observations: list[PodObservation] = []
        actual_ids: list[str] = []
        for pod in sorted(active, key=lambda item: str(item.get("metadata", {}).get("name", ""))):
            metadata = _mapping(pod.get("metadata"), phase)
            name = metadata.get("name")
            if not isinstance(name, str) or not _DNS_LABEL.fullmatch(name):
                raise KubernetesExecutionError(
                    "MALFORMED_KUBECTL_JSON", phase, "Pod has an invalid name"
                )
            status_value = _mapping(pod.get("status"), phase)
            if status_value.get("phase") != "Running":
                raise KubernetesExecutionError(
                    "POD_NOT_READY", phase, "a selected Pod is not Running"
                )
            conditions = status_value.get("conditions")
            pod_ready = isinstance(conditions, list) and any(
                isinstance(condition, Mapping)
                and condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions
            )
            statuses: list[Mapping[str, Any]] = []
            for field in ("initContainerStatuses", "containerStatuses"):
                raw_statuses = status_value.get(field, [])
                if not isinstance(raw_statuses, list) or any(
                    not isinstance(item, Mapping) for item in raw_statuses
                ):
                    raise KubernetesExecutionError(
                        "MALFORMED_KUBECTL_JSON", phase, "container statuses must be arrays"
                    )
                statuses.extend(raw_statuses)
            if not statuses:
                raise KubernetesExecutionError(
                    "POD_NOT_READY", phase, "Pod has no observed container status"
                )
            image_ids: list[str] = []
            restart_count = 0
            for container in statuses:
                image_id = container.get("imageID")
                if not isinstance(image_id, str):
                    raise KubernetesExecutionError(
                        "MALFORMED_KUBECTL_JSON", phase, "container imageID is missing"
                    )
                try:
                    actual_digest = digest_from_image_id(image_id)
                except ValueError as exc:
                    raise KubernetesExecutionError(
                        "MALFORMED_KUBECTL_JSON", phase, "container imageID is invalid"
                    ) from exc
                if actual_digest != parse_digest(request.artifact.platform_digest):
                    raise KubernetesExecutionError(
                        "POD_IMAGE_DIGEST_MISMATCH",
                        phase,
                        "Pod imageID does not map to the resolved artifact digest",
                    )
                if container.get("ready") is not True:
                    raise KubernetesExecutionError(
                        "POD_NOT_READY", phase, "a selected Pod container is not ready"
                    )
                restart_count += _integer(container.get("restartCount"), phase)
                image_ids.append(image_id)
                actual_ids.append(image_id)
            if restart_count != 0:
                raise KubernetesExecutionError(
                    "POD_RESTART_OBSERVED",
                    phase,
                    "a selected Pod container restarted during the verified revision",
                )
            if not pod_ready:
                raise KubernetesExecutionError(
                    "POD_NOT_READY", phase, "a selected Pod lacks Ready=True"
                )
            observations.append(
                PodObservation(
                    name=name,
                    image_ids=tuple(image_ids),
                    ready=True,
                    restart_count=restart_count,
                )
            )
        return tuple(observations), sorted(actual_ids)[0]

    def _probe(
        self,
        request: KubernetesExecutionRequest,
        path: str,
        phase: str,
    ) -> dict[str, Any]:
        manifest = next(
            item for item in request.manifests if item.environment == request.environment
        )
        raw_path = (
            f"/api/v1/namespaces/{manifest.namespace}/services/"
            f"http:{request.service_name}:{request.service_port}/proxy{path}"
        )
        result = self._invoke(request, ["get", "--raw", raw_path], phase=phase)
        if result.returncode != 0:
            code = "HEALTH_PROBE_FAILED" if "health" in phase else "READINESS_PROBE_FAILED"
            self._raise_command_failure(
                request,
                result,
                code=code,
                phase=phase,
                operation=f"request {path} through the Kubernetes Service proxy",
            )
        raw_body = _text(result.stdout)
        if not raw_body or len(raw_body.encode("utf-8")) > 65_536:
            raise KubernetesExecutionError(
                "HTTP_RESPONSE_INVALID", phase, "endpoint returned an empty or oversized body"
            )
        try:
            body: Any = json.loads(raw_body)
        except json.JSONDecodeError:
            body = _sanitize(raw_body, request.kubeconfig_path, limit=4096)
        else:
            body = _safe_json_value(body, request.kubeconfig_path)
        return {
            "status": 200,
            "body": body,
            "transport": "kubernetes-api-service-proxy",
        }

    def _require_deployment_images(
        self,
        request: KubernetesExecutionRequest,
        deployment: Mapping[str, Any],
        phase: str,
    ) -> None:
        specification = _mapping(deployment.get("spec"), phase)
        template = _mapping(specification.get("template"), phase)
        pod_spec = _mapping(template.get("spec"), phase)
        images: list[str] = []
        for field in ("initContainers", "containers"):
            containers = pod_spec.get(field, [])
            if not isinstance(containers, list) or any(
                not isinstance(container, Mapping) for container in containers
            ):
                raise KubernetesExecutionError(
                    "MALFORMED_KUBECTL_JSON", phase, "Deployment containers must be arrays"
                )
            for container in containers:
                image = container.get("image")
                if not isinstance(image, str):
                    raise KubernetesExecutionError(
                        "MALFORMED_KUBECTL_JSON", phase, "Deployment container image is missing"
                    )
                images.append(image)
        if not images or any(
            image != request.artifact.immutable_image_reference for image in images
        ):
            raise KubernetesExecutionError(
                "DEPLOYMENT_IMAGE_DIGEST_MISMATCH",
                phase,
                "Deployment does not use the exact resolved artifact reference",
            )

    @staticmethod
    def _require_readiness_path(
        deployment: Mapping[str, Any], expected_path: str, phase: str
    ) -> None:
        specification = _mapping(deployment.get("spec"), phase)
        template = _mapping(specification.get("template"), phase)
        pod_spec = _mapping(template.get("spec"), phase)
        containers = pod_spec.get("containers")
        if not isinstance(containers, list) or not containers:
            raise KubernetesExecutionError(
                "MALFORMED_KUBECTL_JSON", phase, "Deployment has no application containers"
            )
        for container in containers:
            container = _mapping(container, phase)
            readiness = _mapping(container.get("readinessProbe"), phase)
            http_get = _mapping(readiness.get("httpGet"), phase)
            if http_get.get("path") != expected_path:
                raise KubernetesExecutionError(
                    "READINESS_REVISION_MISMATCH",
                    phase,
                    "live Deployment readiness path does not match the expected revision",
                )

    @staticmethod
    def _selector(specification: Mapping[str, Any], phase: str) -> str:
        selector_document = _mapping(specification.get("selector"), phase)
        labels = _mapping(selector_document.get("matchLabels"), phase)
        if not labels:
            raise KubernetesExecutionError(
                "SELECTOR_CONTRACT_INVALID", phase, "Deployment matchLabels must not be empty"
            )
        rendered: list[str] = []
        for key, value in sorted(labels.items()):
            if not isinstance(key, str) or not isinstance(value, str):
                raise KubernetesExecutionError(
                    "SELECTOR_CONTRACT_INVALID", phase, "Deployment labels must be strings"
                )
            prefix, separator, name = key.rpartition("/")
            if separator:
                valid_key = bool(_LABEL_PREFIX.fullmatch(prefix) and _LABEL_NAME.fullmatch(name))
            else:
                valid_key = bool(_LABEL_NAME.fullmatch(key))
            if not valid_key or not _LABEL_VALUE.fullmatch(value):
                raise KubernetesExecutionError(
                    "SELECTOR_CONTRACT_INVALID", phase, "Deployment selector is unsafe"
                )
            rendered.append(f"{key}={value}")
        return ",".join(rendered)

    def _json_document(
        self,
        request: KubernetesExecutionRequest,
        result: subprocess.CompletedProcess[str],
        phase: str,
    ) -> Mapping[str, Any]:
        raw = _text(result.stdout)
        if len(raw.encode("utf-8")) > _MAX_JSON_OUTPUT:
            raise KubernetesExecutionError(
                "MALFORMED_KUBECTL_JSON", phase, "kubectl JSON exceeded the input bound"
            )
        try:
            return _mapping(json.loads(raw), phase)
        except json.JSONDecodeError as exc:
            raise KubernetesExecutionError(
                "MALFORMED_KUBECTL_JSON", phase, "kubectl returned malformed JSON"
            ) from exc

    def _collect_diagnostics(
        self,
        request: KubernetesExecutionRequest,
        selector: str,
        manifest: ResolvedKubernetesManifest,
        failure_manifest: str | None,
    ) -> tuple[DiagnosticRecord, ...]:
        commands = (
            (
                "kubernetes/diagnostics/events.txt",
                [
                    "get",
                    "events",
                    "--namespace",
                    manifest.namespace,
                    "--sort-by=.metadata.creationTimestamp",
                    "--output=yaml",
                ],
            ),
            (
                "kubernetes/diagnostics/deployment-describe.txt",
                [
                    "describe",
                    "deployment",
                    request.deployment_name,
                    "--namespace",
                    manifest.namespace,
                ],
            ),
            (
                "kubernetes/diagnostics/replicasets.yaml",
                [
                    "get",
                    "replicasets",
                    "--namespace",
                    manifest.namespace,
                    "--selector",
                    selector,
                    "--output=yaml",
                ],
            ),
            (
                "kubernetes/diagnostics/pods-describe.txt",
                [
                    "describe",
                    "pods",
                    "--namespace",
                    manifest.namespace,
                    "--selector",
                    selector,
                ],
            ),
            (
                "kubernetes/diagnostics/container-logs.txt",
                [
                    "logs",
                    "--namespace",
                    manifest.namespace,
                    "--selector",
                    selector,
                    "--all-containers=true",
                    "--tail=100",
                    "--prefix=true",
                ],
            ),
            (
                "kubernetes/diagnostics/rollout-history.txt",
                [
                    "rollout",
                    "history",
                    f"deployment/{request.deployment_name}",
                    "--namespace",
                    manifest.namespace,
                ],
            ),
        )
        records: list[DiagnosticRecord] = []
        used = 0
        for path, arguments in commands:
            try:
                result = self._invoke(
                    request,
                    arguments,
                    phase="diagnostics",
                    timeout=self._diagnostic_timeout,
                )
                combined = "\n".join(
                    part for part in (_text(result.stdout), _text(result.stderr)) if part
                )
                if result.returncode != 0:
                    combined = f"exit={result.returncode}\n{combined}"
            except KubernetesExecutionError as exc:
                combined = f"collection-error: {exc.detail}"
            remaining = max(0, _TOTAL_DIAGNOSTIC_LIMIT - used)
            if remaining == 0:
                break
            content = _sanitize(
                combined or "<empty>",
                request.kubeconfig_path,
                limit=min(_DIAGNOSTIC_LIMIT, remaining),
            )
            if not content:
                break
            records.append(DiagnosticRecord(path, content))
            used += len(content)
        manifest_content = manifest.content
        if failure_manifest is not None:
            manifest_content += "\n---\n" + failure_manifest
        remaining = max(0, _TOTAL_DIAGNOSTIC_LIMIT - used)
        if remaining:
            records.append(
                DiagnosticRecord(
                    "kubernetes/diagnostics/final-manifests.yaml",
                    _sanitize(
                        manifest_content,
                        request.kubeconfig_path,
                        limit=min(_DIAGNOSTIC_LIMIT, remaining),
                    ),
                )
            )
        return tuple(records)

    @staticmethod
    def _readiness_failure_observed(
        diagnostics: Iterable[DiagnosticRecord],
        rollout: subprocess.CompletedProcess[str],
    ) -> bool:
        text = "\n".join(
            [
                _text(rollout.stdout),
                _text(rollout.stderr),
                *(
                    record.content
                    for record in diagnostics
                    if not record.path.endswith("final-manifests.yaml")
                ),
            ]
        ).lower()
        return any(
            marker in text
            for marker in (
                "readiness probe failed",
                "readinessprobe",
                "statuscode: 404",
            )
        )

    @staticmethod
    def _merge_diagnostics(
        first: Sequence[DiagnosticRecord], second: Sequence[DiagnosticRecord]
    ) -> tuple[DiagnosticRecord, ...]:
        merged = {record.path: record for record in first}
        merged.update({record.path: record for record in second})
        return tuple(merged[path] for path in sorted(merged))

    @staticmethod
    def _with_diagnostics(
        error: KubernetesExecutionError,
        diagnostics: Sequence[DiagnosticRecord],
    ) -> KubernetesExecutionError:
        return KubernetesExecutionError(
            error.code,
            error.phase,
            error.detail,
            diagnostics=diagnostics,
            rollback_attempted=error.rollback_attempted,
            rollback_succeeded=error.rollback_succeeded,
        )

    def _checked(
        self,
        request: KubernetesExecutionRequest,
        arguments: Sequence[str],
        *,
        phase: str,
        code: str,
        operation: str,
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = self._invoke(
            request,
            arguments,
            phase=phase,
            stdin=stdin,
            timeout=timeout,
        )
        if result.returncode != 0:
            self._raise_command_failure(
                request,
                result,
                code=code,
                phase=phase,
                operation=operation,
            )
        return result

    def _invoke(
        self,
        request: KubernetesExecutionRequest,
        arguments: Sequence[str],
        *,
        phase: str,
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        resolved_timeout = self._command_timeout if timeout is None else timeout
        request_timeout = max(1, int(resolved_timeout))
        command = [
            self._kubectl,
            "--kubeconfig",
            str(request.kubeconfig_path),
            f"--request-timeout={request_timeout}s",
            *arguments,
        ]
        try:
            result = self._runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                input=stdin,
                timeout=resolved_timeout,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise KubernetesExecutionError(
                "KUBECTL_UNAVAILABLE", phase, "kubectl is unavailable"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            detail = _sanitize(
                exc.stderr or exc.stdout,
                request.kubeconfig_path,
                limit=1000,
            )
            suffix = f": {detail}" if detail else ""
            raise KubernetesExecutionError(
                "KUBECTL_TIMEOUT", phase, f"kubectl timed out{suffix}"
            ) from exc
        except OSError as exc:
            detail = _sanitize(str(exc), request.kubeconfig_path, limit=1000)
            raise KubernetesExecutionError(
                "KUBECTL_EXECUTION_FAILED", phase, f"kubectl could not run: {detail}"
            ) from exc
        if not isinstance(result.returncode, int):
            raise KubernetesExecutionError(
                "KUBECTL_EXECUTION_FAILED", phase, "kubectl runner returned no exit status"
            )
        return result

    @staticmethod
    def _raise_command_failure(
        request: KubernetesExecutionRequest,
        result: subprocess.CompletedProcess[str],
        *,
        code: str,
        phase: str,
        operation: str,
    ) -> None:
        detail = _sanitize(
            result.stderr or result.stdout,
            request.kubeconfig_path,
            limit=2000,
        )
        suffix = f": {detail}" if detail else ""
        raise KubernetesExecutionError(
            code,
            phase,
            f"could not {operation} (exit {result.returncode}){suffix}",
        )


__all__ = [
    "DiagnosticRecord",
    "DryRunEvidence",
    "IntentionalFailureEvidence",
    "KubernetesExecutionError",
    "KubernetesExecutionRequest",
    "KubernetesExecutionResult",
    "KubernetesExecutor",
    "PodObservation",
]
