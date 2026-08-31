"""Execute and attest one digest-pinned Kubernetes workload on a local cluster."""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import stat
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

import yaml

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.evidence_validation import (
    parse_kubernetes_yaml,
    validate_kubernetes_documents,
)
from devops_stack_composer.kubernetes_runtime import (
    ResolvedKubernetesManifest,
    render_intentional_readiness_failure,
)
from devops_stack_composer.oci import (
    digest_from_image_id,
    parse_digest,
    parse_oci_reference,
)
from devops_stack_composer.process_runner import (
    CancellationToken,
    ManagedProcess,
    ProcessErrorCategory,
    ProcessExecutionError,
    ProcessResult,
    SafeProcessRunner,
    redact_process_output,
)


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_APP_LABEL = "app.kubernetes.io/name"
_MAX_HTTP_BODY_BYTES = 4096
_MAX_DIAGNOSTIC_BYTES = 16_384
_MAX_ROLLBACK_OBSERVATIONS = 32


class KubernetesExecutionRunner(Protocol):
    """The subset of :class:`SafeProcessRunner` used by this executor."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ProcessResult: ...

    def start(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ManagedProcess: ...


@dataclass(frozen=True)
class KubernetesArtifactIdentity:
    """Artifact identity observed at each Kubernetes execution boundary."""

    expected_image_reference: str
    expected_digest: str
    manifest_image_reference: str | None = None
    applied_image_reference: str | None = None
    pod_spec_image_reference: str | None = None
    runtime_image_id: str | None = None
    runtime_digest: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "expectedImageReference": self.expected_image_reference,
            "expectedDigest": self.expected_digest,
            "manifestImageReference": self.manifest_image_reference,
            "appliedImageReference": self.applied_image_reference,
            "podSpecImageReference": self.pod_spec_image_reference,
            "runtimeImageId": self.runtime_image_id,
            "runtimeDigest": self.runtime_digest,
        }


@dataclass(frozen=True)
class HttpSmokeResult:
    """One bounded loopback HTTP response."""

    path: str
    status_code: int
    body: str
    truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "statusCode": self.status_code,
            "body": self.body,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class KubernetesExecutionResult:
    """Successful rollout, runtime attestation, and smoke evidence."""

    identity: KubernetesArtifactIdentity
    namespace: str
    deployment_name: str
    service_name: str
    pod_name: str
    ready_replica_count: int
    manifest_path: str
    applied_deployment_path: str
    applied_service_path: str
    runtime_pods_path: str
    rollback_path: str
    final_revision: str
    health: HttpSmokeResult
    readiness: HttpSmokeResult
    evidence_paths: tuple[str, ...] = ()
    initial_health: HttpSmokeResult | None = None
    initial_readiness: HttpSmokeResult | None = None
    rollback_failure_cause: str | None = None
    rollback_failure_cause_verified: bool = False
    rollback_observation_path: str | None = None
    post_rollback_smoke_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": "1.0.0",
            "namespace": self.namespace,
            "deploymentName": self.deployment_name,
            "serviceName": self.service_name,
            "podName": self.pod_name,
            "readyReplicaCount": self.ready_replica_count,
            "manifestPath": self.manifest_path,
            "appliedDeploymentPath": self.applied_deployment_path,
            "appliedServicePath": self.applied_service_path,
            "runtimePodsPath": self.runtime_pods_path,
            "rollbackPath": self.rollback_path,
            "rollbackAttempted": True,
            "rollbackResult": "PASSED",
            "finalRevision": self.final_revision,
            "finalDigest": self.identity.runtime_digest,
            "identity": self.identity.to_dict(),
            "health": self.health.to_dict(),
            "readiness": self.readiness.to_dict(),
            "initialHealth": (
                self.initial_health.to_dict()
                if self.initial_health is not None
                else None
            ),
            "initialReadiness": (
                self.initial_readiness.to_dict()
                if self.initial_readiness is not None
                else None
            ),
            "rollbackFailureCause": self.rollback_failure_cause,
            "rollbackFailureCauseVerified": self.rollback_failure_cause_verified,
            "rollbackObservationPath": self.rollback_observation_path,
            "postRollbackHealth": (
                self.health.to_dict()
                if self.post_rollback_smoke_path is not None
                else None
            ),
            "postRollbackReadiness": (
                self.readiness.to_dict()
                if self.post_rollback_smoke_path is not None
                else None
            ),
            "postRollbackSmokePath": self.post_rollback_smoke_path,
            "evidencePaths": list(self.evidence_paths),
            "passed": True,
        }


@dataclass(frozen=True)
class KubernetesPreflightResult:
    """Server-side validation evidence for every configured environment."""

    environments: tuple[str, ...]
    namespaces: tuple[str, ...]
    evidence_path: str
    evidence_paths: tuple[str, ...] = ()


class KubernetesExecutionError(DevOpsStackError):
    """A typed execution failure with the last observed artifact identity."""

    def __init__(
        self,
        code: str,
        stage: str,
        message: str,
        *,
        identity: KubernetesArtifactIdentity,
        process_result: ProcessResult | None = None,
        diagnostics_paths: Sequence[str] = (),
        evidence_paths: Sequence[str] = (),
    ) -> None:
        self.code = code
        self.stage = stage
        self.identity = identity
        self.process_result = process_result
        self.diagnostics_paths = tuple(diagnostics_paths)
        self.evidence_paths = tuple(evidence_paths)
        super().__init__(f"{code} during {stage}: {message}")

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": "1.0.0",
            "code": self.code,
            "stage": self.stage,
            "message": str(self),
            "identity": self.identity.to_dict(),
            "diagnosticsPaths": list(self.diagnostics_paths),
            "evidencePaths": list(self.evidence_paths),
            "process": (
                {
                    "argv": list(self.process_result.argv),
                    "returnCode": self.process_result.returncode,
                    "category": (
                        self.process_result.error_category.value
                        if self.process_result.error_category
                        else None
                    ),
                }
                if self.process_result is not None
                else None
            ),
        }


HttpGetter = Callable[[str, int, str, float], HttpSmokeResult]
ProgressCallback = Callable[[str, Mapping[str, Any]], None]


@dataclass(frozen=True)
class _ValidatedManifest:
    identity: KubernetesArtifactIdentity
    documents: tuple[Mapping[str, object], ...]
    namespace_document: Mapping[str, object]
    service_target_port: int


@dataclass(frozen=True)
class _ReadinessFailureObservation:
    verified: bool
    pod_names: tuple[str, ...]
    pods_path: str
    events_path: str


@dataclass(frozen=True)
class _RollbackResult:
    identity: KubernetesArtifactIdentity
    final_revision: str
    rollback_path: str
    observation_path: str
    failure_cause: str
    post_rollback_health: HttpSmokeResult
    post_rollback_readiness: HttpSmokeResult
    post_rollback_smoke_path: str


def _loopback_http_get(
    host: str,
    port: int,
    path: str,
    timeout: float,
) -> HttpSmokeResult:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        payload = response.read(_MAX_HTTP_BODY_BYTES + 1)
    finally:
        connection.close()
    truncated = len(payload) > _MAX_HTTP_BODY_BYTES
    value = payload[:_MAX_HTTP_BODY_BYTES].decode("utf-8", errors="replace")
    return HttpSmokeResult(path, int(response.status), value, truncated)


class KubernetesExecutor:
    """Run kubectl with one immutable artifact and collect bounded evidence."""

    def __init__(
        self,
        runner: SafeProcessRunner | KubernetesExecutionRunner,
        evidence_store: EvidenceStore,
        *,
        kubeconfig: Path,
        app_name: str,
        deployment_name: str,
        service_name: str,
        service_port: int,
        health_path: str,
        readiness_path: str,
        command_timeout_seconds: float = 60.0,
        rollout_timeout_seconds: float = 180.0,
        port_forward_start_timeout_seconds: float = 15.0,
        port_forward_timeout_seconds: float = 60.0,
        port_forward_cleanup_timeout_seconds: float = 5.0,
        http_timeout_seconds: float = 5.0,
        http_getter: HttpGetter | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        if not isinstance(evidence_store, EvidenceStore):
            raise ValueError("evidence_store must be an EvidenceStore")
        self.runner = runner
        self.store = evidence_store
        self.kubeconfig, self.context = self._private_kubeconfig(kubeconfig)
        self.cache_dir = self._private_cache_directory(self.kubeconfig.parent)
        self.app_name = self._dns_label("app_name", app_name)
        self.deployment_name = self._dns_label("deployment_name", deployment_name)
        self.service_name = self._dns_label("service_name", service_name)
        if (
            isinstance(service_port, bool)
            or not isinstance(service_port, int)
            or not 1 <= service_port <= 65535
        ):
            raise ValueError("service_port must be an integer from 1 through 65535")
        self.service_port = service_port
        self.health_path = self._http_path("health_path", health_path)
        self.readiness_path = self._http_path("readiness_path", readiness_path)
        self.command_timeout = self._duration(
            "command_timeout_seconds", command_timeout_seconds
        )
        self.rollout_timeout = self._duration(
            "rollout_timeout_seconds", rollout_timeout_seconds
        )
        self.port_forward_start_timeout = self._duration(
            "port_forward_start_timeout_seconds", port_forward_start_timeout_seconds
        )
        self.port_forward_timeout = self._duration(
            "port_forward_timeout_seconds", port_forward_timeout_seconds
        )
        self.port_forward_cleanup_timeout = self._duration(
            "port_forward_cleanup_timeout_seconds", port_forward_cleanup_timeout_seconds
        )
        self.http_timeout = self._duration("http_timeout_seconds", http_timeout_seconds)
        self._http_get = http_getter or _loopback_http_get
        if progress_callback is not None and not callable(progress_callback):
            raise ValueError("progress_callback must be callable or null")
        self._progress_callback = progress_callback

    def server_side_dry_run(
        self,
        manifests: Sequence[ResolvedKubernetesManifest],
    ) -> KubernetesPreflightResult:
        """Validate all environments without applying any workload resource."""

        if isinstance(manifests, (str, bytes)):
            raise ValueError("manifests must be a sequence of resolved manifests")
        selected = tuple(manifests)
        if not selected:
            raise ValueError("manifests must contain every configured environment")

        environments: list[str] = []
        namespaces: list[str] = []
        validated_manifests: list[
            tuple[ResolvedKubernetesManifest, _ValidatedManifest]
        ] = []
        for manifest in selected:
            if not isinstance(manifest, ResolvedKubernetesManifest):
                raise ValueError("manifests must contain resolved Kubernetes manifests")
            environment = self._dns_label(
                "manifest environment",
                manifest.environment,
            )
            try:
                parsed_reference = parse_oci_reference(
                    manifest.immutable_image_reference
                )
                expected_digest = (
                    str(parsed_reference.digest)
                    if parsed_reference.digest is not None
                    else ""
                )
            except ValueError as exc:
                identity = KubernetesArtifactIdentity(
                    manifest.immutable_image_reference,
                    "invalid",
                )
                raise KubernetesExecutionError(
                    "EXPECTED_IMAGE_INVALID",
                    "server-side-dry-run",
                    str(exc),
                    identity=identity,
                ) from exc
            validated = self._validate_manifest_identity(
                manifest,
                expected_image_reference=manifest.immutable_image_reference,
                expected_digest=expected_digest,
            )
            environments.append(environment)
            namespaces.append(manifest.namespace)
            validated_manifests.append((manifest, validated))

        if len(set(environments)) != len(environments):
            raise ValueError("preflight environments must be unique")
        if len(set(namespaces)) != len(namespaces):
            raise ValueError("preflight namespaces must be unique")

        records: list[dict[str, object]] = []
        for manifest, validated in validated_manifests:
            prefix = f"kubernetes/preflight/{manifest.environment}"
            manifest_path = self.store.write_text(
                f"{prefix}-resolved.yaml",
                manifest.content,
            )
            namespace_content = yaml.safe_dump(
                dict(validated.namespace_document),
                sort_keys=False,
                allow_unicode=True,
            )
            namespace_path = self.store.write_text(
                f"{prefix}-namespace-bootstrap.yaml",
                namespace_content,
            )
            try:
                namespace_dry_run = self._kubectl(
                    "apply",
                    "--server-side",
                    "--dry-run=server",
                    "--field-manager=devops-stack-composer",
                    "--filename",
                    str(namespace_path),
                    "--output",
                    "name",
                )
                namespace_apply = self._kubectl(
                    "apply",
                    "--server-side",
                    "--field-manager=devops-stack-composer",
                    "--filename",
                    str(namespace_path),
                    "--output",
                    "name",
                )
                workload_dry_run = self._kubectl(
                    "apply",
                    "--server-side",
                    "--dry-run=server",
                    "--field-manager=devops-stack-composer",
                    "--filename",
                    str(manifest_path),
                    "--output",
                    "name",
                )
            except ProcessExecutionError as exc:
                raise KubernetesExecutionError(
                    "KUBERNETES_PREFLIGHT_FAILED",
                    f"server-side-dry-run:{manifest.environment}",
                    f"kubectl preflight failed with {exc.category.value}",
                    identity=validated.identity,
                    process_result=exc.result,
                ) from exc
            records.append(
                {
                    "environment": manifest.environment,
                    "namespace": manifest.namespace,
                    "manifestPath": manifest_path.relative_to(
                        self.store.root
                    ).as_posix(),
                    "manifestHash": manifest.sha256,
                    "namespacePath": namespace_path.relative_to(
                        self.store.root
                    ).as_posix(),
                    "namespaceDryRun": self._process_summary(namespace_dry_run),
                    "namespaceApply": self._process_summary(namespace_apply),
                    "workloadDryRun": self._process_summary(workload_dry_run),
                    "passed": True,
                }
            )

        evidence_path = self.store.write_json(
            "kubernetes/server-side-dry-run.json",
            {
                "schemaVersion": "1.0.0",
                "environments": records,
                "passed": True,
            },
        )
        self._notify_progress(
            "cluster_prepared",
            {
                "environments": list(environments),
                "evidencePath": evidence_path.relative_to(self.store.root).as_posix(),
            },
        )
        return KubernetesPreflightResult(
            environments=tuple(environments),
            namespaces=tuple(namespaces),
            evidence_path=evidence_path.relative_to(self.store.root).as_posix(),
            evidence_paths=self._evidence_paths(),
        )

    def execute(
        self,
        manifest: ResolvedKubernetesManifest,
        *,
        expected_image_reference: str,
        expected_digest: str,
    ) -> KubernetesExecutionResult:
        validated = self._validate_manifest_identity(
            manifest,
            expected_image_reference=expected_image_reference,
            expected_digest=expected_digest,
        )
        identity = validated.identity
        self._active_namespace = manifest.namespace
        resources_may_exist = False
        stage = "persist-manifest"

        try:
            manifest_path = self.store.write_text(
                "kubernetes/resolved.yaml",
                manifest.content,
            )
            manifest_relative = manifest_path.relative_to(self.store.root).as_posix()
            namespace_content = yaml.safe_dump(
                dict(validated.namespace_document),
                sort_keys=False,
                allow_unicode=True,
            )
            namespace_path = self.store.write_text(
                "kubernetes/namespace-bootstrap.yaml",
                namespace_content,
            )

            # A dry-run Namespace is not persisted for admission checks on later
            # namespaced resources. Validate and create only that boundary first,
            # then dry-run the complete manifest before applying the workload.
            stage = "namespace-server-side-dry-run"
            self._kubectl(
                "apply",
                "--server-side",
                "--dry-run=server",
                "--field-manager=devops-stack-composer",
                "--filename",
                str(namespace_path),
                "--output",
                "name",
            )
            stage = "namespace-bootstrap"
            resources_may_exist = True
            self._kubectl(
                "apply",
                "--server-side",
                "--field-manager=devops-stack-composer",
                "--filename",
                str(namespace_path),
                "--output",
                "name",
            )

            stage = "server-side-dry-run"
            self._kubectl(
                "apply",
                "--server-side",
                "--dry-run=server",
                "--field-manager=devops-stack-composer",
                "--filename",
                str(manifest_path),
                "--output",
                "name",
            )
            stage = "apply"
            self._kubectl(
                "apply",
                "--server-side",
                "--field-manager=devops-stack-composer",
                "--filename",
                str(manifest_path),
                "--output",
                "name",
            )
            self._notify_progress(
                "applied",
                {"manifestPath": manifest_relative, "namespace": manifest.namespace},
            )

            stage = "rollout"
            self._kubectl(
                "rollout",
                "status",
                f"deployment/{self.deployment_name}",
                "--namespace",
                manifest.namespace,
                "--timeout",
                f"{math.ceil(self.rollout_timeout)}s",
                timeout=self.rollout_timeout + 5.0,
            )
            self._notify_progress(
                "ready",
                {
                    "deployment": self.deployment_name,
                    "namespace": manifest.namespace,
                },
            )

            stage = "applied-deployment"
            deployment_result = self._kubectl(
                "get",
                "deployment",
                self.deployment_name,
                "--namespace",
                manifest.namespace,
                "--output",
                "json",
            )
            deployment = self._json_object(deployment_result, stage, identity)
            deployment_path = self.store.write_json(
                "kubernetes/applied-deployment.json", deployment
            )
            applied_reference = self._deployment_image(
                deployment,
                namespace=manifest.namespace,
                identity=identity,
                stage=stage,
            )
            identity = replace(identity, applied_image_reference=applied_reference)
            self._require_exact_reference(applied_reference, identity, stage)

            stage = "applied-service"
            service_result = self._kubectl(
                "get",
                "service",
                self.service_name,
                "--namespace",
                manifest.namespace,
                "--output",
                "json",
            )
            service = self._json_object(service_result, stage, identity)
            service_path = self.store.write_json(
                "kubernetes/applied-service.json", service
            )
            applied_target_port = self._service_contract(
                service,
                namespace=manifest.namespace,
                identity=identity,
                stage=stage,
            )
            if applied_target_port != validated.service_target_port:
                raise KubernetesExecutionError(
                    "SERVICE_TARGET_PORT_MISMATCH",
                    stage,
                    "applied Service targetPort differs from the validated manifest",
                    identity=identity,
                )

            stage = "runtime-attestation"
            pod_result = self._kubectl(
                "get",
                "pods",
                "--namespace",
                manifest.namespace,
                "--selector",
                f"{_APP_LABEL}={self.app_name}",
                "--output",
                "json",
            )
            pods = self._json_object(pod_result, stage, identity)
            pods_path = self.store.write_json("kubernetes/runtime-pods.json", pods)
            (
                pod_name,
                pod_reference,
                image_id,
                runtime_digest,
                ready_replica_count,
            ) = self._ready_pod(
                pods,
                identity=identity,
            )
            identity = replace(
                identity,
                pod_spec_image_reference=pod_reference,
                runtime_image_id=image_id,
                runtime_digest=runtime_digest,
            )
            self._require_exact_reference(pod_reference, identity, stage)
            if runtime_digest != identity.expected_digest:
                raise KubernetesExecutionError(
                    "RUNTIME_DIGEST_MISMATCH",
                    stage,
                    f"pod image digest {runtime_digest} does not match the expected digest",
                    identity=identity,
                )
            self._notify_progress(
                "attested",
                {
                    "digest": runtime_digest,
                    "pod": pod_name,
                    "readyReplicaCount": ready_replica_count,
                },
            )

            stage = "smoke"
            initial_health, initial_readiness = self._smoke(
                manifest.namespace,
                identity,
                target_port=applied_target_port,
            )
            for probe in (initial_health, initial_readiness):
                if probe.status_code != 200:
                    raise KubernetesExecutionError(
                        "SMOKE_HTTP_FAILED",
                        stage,
                        f"{probe.path} returned HTTP {probe.status_code}",
                        identity=identity,
                    )
            self.store.write_json(
                "kubernetes/smoke.json",
                {
                    "schemaVersion": "1.0.0",
                    "phase": "pre-rollback",
                    "expectedDigest": identity.expected_digest,
                    "health": initial_health.to_dict(),
                    "readiness": initial_readiness.to_dict(),
                    "passed": True,
                },
            )
            self._notify_progress(
                "smoked",
                {
                    "healthStatus": initial_health.status_code,
                    "readinessStatus": initial_readiness.status_code,
                },
            )

            stage = "rollback"
            rollback = self._rollback(
                manifest,
                identity,
                target_port=applied_target_port,
            )
            identity = rollback.identity

            result = KubernetesExecutionResult(
                identity=identity,
                namespace=manifest.namespace,
                deployment_name=self.deployment_name,
                service_name=self.service_name,
                pod_name=pod_name,
                ready_replica_count=ready_replica_count,
                manifest_path=manifest_relative,
                applied_deployment_path=deployment_path.relative_to(
                    self.store.root
                ).as_posix(),
                applied_service_path=service_path.relative_to(
                    self.store.root
                ).as_posix(),
                runtime_pods_path=pods_path.relative_to(self.store.root).as_posix(),
                rollback_path=rollback.rollback_path,
                final_revision=rollback.final_revision,
                health=rollback.post_rollback_health,
                readiness=rollback.post_rollback_readiness,
                initial_health=initial_health,
                initial_readiness=initial_readiness,
                rollback_failure_cause=rollback.failure_cause,
                rollback_failure_cause_verified=True,
                rollback_observation_path=rollback.observation_path,
                post_rollback_smoke_path=rollback.post_rollback_smoke_path,
            )
            stage = "persist-result"
            self.store.write_json("kubernetes/deployment.json", result.to_dict())
            self._notify_progress(
                "evidence_collected",
                {
                    "rollbackPath": rollback.rollback_path,
                    "rollbackObservationPath": rollback.observation_path,
                    "postRollbackSmokePath": rollback.post_rollback_smoke_path,
                    "finalDigest": identity.runtime_digest,
                },
            )
            return replace(result, evidence_paths=self._evidence_paths())
        except KubernetesExecutionError as exc:
            if resources_may_exist:
                exc.diagnostics_paths = tuple(
                    dict.fromkeys((*exc.diagnostics_paths, *self._collect_diagnostics()))
                )
            exc.evidence_paths = self._evidence_paths()
            raise
        except ProcessExecutionError as exc:
            diagnostics = self._write_process_failure(stage, exc.result)
            if resources_may_exist:
                diagnostics += self._collect_diagnostics()
            raise KubernetesExecutionError(
                "KUBECTL_COMMAND_FAILED",
                stage,
                f"kubectl failed with {exc.category.value}",
                identity=identity,
                process_result=exc.result,
                diagnostics_paths=tuple(dict.fromkeys(diagnostics)),
                evidence_paths=self._evidence_paths(),
            ) from exc
        except (DevOpsStackError, OSError) as exc:
            diagnostics = self._collect_diagnostics() if resources_may_exist else ()
            raise KubernetesExecutionError(
                "EVIDENCE_IO_FAILED",
                stage,
                "execution evidence could not be persisted safely",
                identity=identity,
                diagnostics_paths=diagnostics,
                evidence_paths=self._evidence_paths(),
            ) from exc

    def _validate_manifest_identity(
        self,
        manifest: ResolvedKubernetesManifest,
        *,
        expected_image_reference: str,
        expected_digest: str,
    ) -> _ValidatedManifest:
        stage = "manifest-validation"
        try:
            expected = parse_oci_reference(expected_image_reference)
            digest = str(parse_digest(expected_digest))
        except ValueError as exc:
            empty = KubernetesArtifactIdentity(expected_image_reference, expected_digest)
            raise KubernetesExecutionError(
                "EXPECTED_IMAGE_INVALID", stage, str(exc), identity=empty
            ) from exc
        identity = KubernetesArtifactIdentity(expected_image_reference, digest)
        if expected.digest is None or expected.tag is not None:
            raise KubernetesExecutionError(
                "EXPECTED_IMAGE_MUTABLE",
                stage,
                "expected image must use repository@sha256:digest without a tag",
                identity=identity,
            )
        if str(expected.digest) != digest:
            raise KubernetesExecutionError(
                "EXPECTED_DIGEST_MISMATCH",
                stage,
                "expected image reference and expected digest differ",
                identity=identity,
            )
        if not isinstance(manifest, ResolvedKubernetesManifest):
            raise KubernetesExecutionError(
                "MANIFEST_INVALID", stage, "manifest has the wrong type", identity=identity
            )
        if not isinstance(manifest.content, str) or not isinstance(manifest.sha256, str):
            raise KubernetesExecutionError(
                "MANIFEST_INVALID",
                stage,
                "manifest content and checksum must be strings",
                identity=identity,
            )
        try:
            namespace = self._dns_label("manifest namespace", manifest.namespace)
        except ValueError as exc:
            raise KubernetesExecutionError(
                "MANIFEST_NAMESPACE_INVALID", stage, str(exc), identity=identity
            ) from exc
        actual_hash = hashlib.sha256(manifest.content.encode()).hexdigest()
        if manifest.sha256 != actual_hash:
            raise KubernetesExecutionError(
                "MANIFEST_CHECKSUM_MISMATCH",
                stage,
                "manifest content does not match its recorded SHA-256",
                identity=identity,
            )
        try:
            documents = parse_kubernetes_yaml(manifest.content)
            namespace_document = self._manifest_namespace(
                documents,
                namespace=namespace,
                identity=identity,
            )
            manifest_reference = self._manifest_image(
                documents,
                namespace=namespace,
                identity=identity,
            )
            service_target_port = self._manifest_service(
                documents,
                namespace=namespace,
                identity=identity,
            )
            identity = replace(identity, manifest_image_reference=manifest_reference)
            validate_kubernetes_documents(
                documents,
                immutable_reference=expected_image_reference,
            )
        except KubernetesExecutionError:
            raise
        except (ValueError, DevOpsStackError) as exc:
            raise KubernetesExecutionError(
                "MANIFEST_INVALID", stage, str(exc), identity=identity
            ) from exc
        if manifest.immutable_image_reference != expected_image_reference:
            raise KubernetesExecutionError(
                "MANIFEST_IDENTITY_MISMATCH",
                stage,
                "manifest identity does not equal the expected immutable reference",
                identity=identity,
            )
        self._require_exact_reference(manifest_reference, identity, stage)
        return _ValidatedManifest(
            identity,
            documents,
            namespace_document,
            service_target_port,
        )

    def _manifest_namespace(
        self,
        documents: Sequence[Mapping[str, object]],
        *,
        namespace: str,
        identity: KubernetesArtifactIdentity,
    ) -> Mapping[str, object]:
        namespaces = [
            document
            for document in documents
            if document.get("kind") == "Namespace"
        ]
        matches = [
            document
            for document in namespaces
            if isinstance(document.get("metadata"), Mapping)
            and document["metadata"].get("name") == namespace  # type: ignore[index]
        ]
        if len(namespaces) != 1 or len(matches) != 1:
            raise KubernetesExecutionError(
                "MANIFEST_NAMESPACE_INVALID",
                "manifest-validation",
                f"expected exactly one Namespace named {namespace}",
                identity=identity,
            )
        metadata = matches[0].get("metadata")
        if isinstance(metadata, Mapping) and metadata.get("namespace") is not None:
            raise KubernetesExecutionError(
                "MANIFEST_NAMESPACE_INVALID",
                "manifest-validation",
                "Namespace metadata must not itself declare a namespace",
                identity=identity,
            )
        outside_namespace = []
        for document in documents:
            if document.get("kind") == "Namespace":
                continue
            metadata = document.get("metadata")
            document_namespace = (
                metadata.get("namespace") if isinstance(metadata, Mapping) else None
            )
            if document_namespace != namespace:
                outside_namespace.append(str(document.get("kind", "<unknown>")))
        if outside_namespace:
            raise KubernetesExecutionError(
                "MANIFEST_SCOPE_INVALID",
                "manifest-validation",
                "all non-Namespace resources must remain in the target namespace",
                identity=identity,
            )
        return matches[0]

    def _manifest_service(
        self,
        documents: Sequence[Mapping[str, object]],
        *,
        namespace: str,
        identity: KubernetesArtifactIdentity,
    ) -> int:
        matches = [
            document
            for document in documents
            if document.get("kind") == "Service"
            and isinstance(document.get("metadata"), Mapping)
            and document["metadata"].get("name") == self.service_name  # type: ignore[index]
        ]
        if len(matches) != 1:
            raise KubernetesExecutionError(
                "MANIFEST_SERVICE_INVALID",
                "manifest-validation",
                f"expected exactly one Service named {self.service_name}",
                identity=identity,
            )
        return self._service_contract(
            matches[0],
            namespace=namespace,
            identity=identity,
            stage="manifest-validation",
        )

    def _manifest_image(
        self,
        documents: Sequence[Mapping[str, object]],
        *,
        namespace: str,
        identity: KubernetesArtifactIdentity,
    ) -> str:
        matches = [
            document
            for document in documents
            if document.get("kind") == "Deployment"
            and isinstance(document.get("metadata"), Mapping)
            and document["metadata"].get("name") == self.deployment_name  # type: ignore[index]
        ]
        if len(matches) != 1:
            raise KubernetesExecutionError(
                "MANIFEST_DEPLOYMENT_INVALID",
                "manifest-validation",
                f"expected exactly one Deployment named {self.deployment_name}",
                identity=identity,
            )
        return self._deployment_image(
            matches[0],
            namespace=namespace,
            identity=identity,
            stage="manifest-validation",
        )

    def _deployment_image(
        self,
        deployment: Mapping[str, object],
        *,
        namespace: str,
        identity: KubernetesArtifactIdentity,
        stage: str,
    ) -> str:
        metadata = deployment.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        if metadata.get("name") != self.deployment_name or metadata.get("namespace") != namespace:
            raise KubernetesExecutionError(
                "DEPLOYMENT_IDENTITY_MISMATCH",
                stage,
                "Deployment name or namespace differs from the execution target",
                identity=identity,
            )
        spec = deployment.get("spec")
        selector = spec.get("selector") if isinstance(spec, Mapping) else None
        match_labels = (
            selector.get("matchLabels") if isinstance(selector, Mapping) else None
        )
        if (
            not isinstance(match_labels, Mapping)
            or match_labels.get(_APP_LABEL) != self.app_name
        ):
            raise KubernetesExecutionError(
                "DEPLOYMENT_SELECTOR_MISMATCH",
                stage,
                "Deployment selector does not use the stable application label",
                identity=identity,
            )
        template = spec.get("template") if isinstance(spec, Mapping) else None
        template_metadata = (
            template.get("metadata") if isinstance(template, Mapping) else None
        )
        labels = (
            template_metadata.get("labels")
            if isinstance(template_metadata, Mapping)
            else None
        )
        if not isinstance(labels, Mapping) or labels.get(_APP_LABEL) != self.app_name:
            raise KubernetesExecutionError(
                "DEPLOYMENT_SELECTOR_MISMATCH",
                stage,
                "Deployment pod template does not carry the stable application label",
                identity=identity,
            )
        template_spec = template.get("spec") if isinstance(template, Mapping) else None
        containers = (
            template_spec.get("containers") if isinstance(template_spec, Mapping) else None
        )
        matches = [
            value
            for value in containers or ()
            if isinstance(value, Mapping) and value.get("name") == self.app_name
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("image"), str):
            raise KubernetesExecutionError(
                "DEPLOYMENT_CONTAINER_INVALID",
                stage,
                f"Deployment must contain one {self.app_name} container image",
                identity=identity,
            )
        selected_image = str(matches[0]["image"])
        observed_identity = identity
        if stage == "manifest-validation":
            observed_identity = replace(
                identity, manifest_image_reference=selected_image
            )
        elif stage == "applied-deployment":
            observed_identity = replace(
                identity, applied_image_reference=selected_image
            )
        for field in ("initContainers", "containers"):
            values = (
                template_spec.get(field, [])
                if isinstance(template_spec, Mapping)
                else None
            )
            if not isinstance(values, list):
                raise KubernetesExecutionError(
                    "DEPLOYMENT_CONTAINER_INVALID",
                    stage,
                    f"Deployment {field} must be an array",
                    identity=identity,
                )
            for value in values:
                image = value.get("image") if isinstance(value, Mapping) else None
                if not isinstance(image, str):
                    raise KubernetesExecutionError(
                        "DEPLOYMENT_CONTAINER_INVALID",
                        stage,
                        f"Deployment {field} entry has no image",
                        identity=observed_identity,
                    )
                self._require_exact_reference(image, observed_identity, stage)
        return selected_image

    def _service_contract(
        self,
        service: Mapping[str, object],
        *,
        namespace: str,
        identity: KubernetesArtifactIdentity,
        stage: str,
    ) -> int:
        metadata = service.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        if metadata.get("name") != self.service_name or metadata.get("namespace") != namespace:
            raise KubernetesExecutionError(
                "SERVICE_IDENTITY_MISMATCH",
                stage,
                "Service name or namespace differs from the execution target",
                identity=identity,
            )
        spec = service.get("spec")
        selector = spec.get("selector") if isinstance(spec, Mapping) else None
        if not isinstance(selector, Mapping) or selector.get(_APP_LABEL) != self.app_name:
            raise KubernetesExecutionError(
                "SERVICE_SELECTOR_MISMATCH",
                stage,
                "Service does not select the stable application label",
                identity=identity,
            )
        ports = spec.get("ports") if isinstance(spec, Mapping) else None
        matches = [
            port
            for port in ports or ()
            if isinstance(port, Mapping)
            and port.get("port") == self.service_port
            and port.get("protocol", "TCP") == "TCP"
        ]
        if len(matches) != 1:
            raise KubernetesExecutionError(
                "SERVICE_PORT_MISMATCH",
                stage,
                f"Service must expose one TCP port {self.service_port}",
                identity=identity,
            )
        target_port = matches[0].get("targetPort")
        if (
            isinstance(target_port, bool)
            or not isinstance(target_port, int)
            or not 1 <= target_port <= 65535
        ):
            raise KubernetesExecutionError(
                "SERVICE_TARGET_PORT_INVALID",
                stage,
                "Service targetPort must be an integer from 1 through 65535",
                identity=identity,
            )
        return target_port

    def _ready_pod(
        self,
        document: Mapping[str, object],
        *,
        identity: KubernetesArtifactIdentity,
        stage: str = "runtime-attestation",
    ) -> tuple[str, str, str, str, int]:
        items = document.get("items")
        if not isinstance(items, list):
            raise KubernetesExecutionError(
                "POD_INVENTORY_INVALID",
                stage,
                "kubectl pod inventory is not an array",
                identity=identity,
            )
        ready: list[tuple[str, str, str, str]] = []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            if metadata.get("deletionTimestamp") is not None:
                continue
            labels = metadata.get("labels")
            if (
                metadata.get("namespace") != self._active_namespace
                or not isinstance(labels, Mapping)
                or labels.get(_APP_LABEL) != self.app_name
            ):
                continue
            status = item.get("status")
            status = status if isinstance(status, Mapping) else {}
            conditions = status.get("conditions")
            pod_ready = any(
                isinstance(condition, Mapping)
                and condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions or ()
            )
            if status.get("phase") != "Running" or not pod_ready:
                continue
            spec = item.get("spec")
            spec_containers = spec.get("containers") if isinstance(spec, Mapping) else None
            for field in ("initContainers", "containers"):
                values = spec.get(field, []) if isinstance(spec, Mapping) else None
                if not isinstance(values, list):
                    raise KubernetesExecutionError(
                        "POD_CONTAINER_INVALID",
                        stage,
                        f"ready pod {field} must be an array",
                        identity=identity,
                    )
                for value in values:
                    image = value.get("image") if isinstance(value, Mapping) else None
                    if not isinstance(image, str):
                        raise KubernetesExecutionError(
                            "POD_CONTAINER_INVALID",
                            stage,
                            f"ready pod {field} entry has no image",
                            identity=identity,
                        )
                    self._require_exact_reference(image, identity, stage)
            spec_matches = [
                value
                for value in spec_containers or ()
                if isinstance(value, Mapping) and value.get("name") == self.app_name
            ]
            statuses = status.get("containerStatuses")
            status_matches = [
                value
                for value in statuses or ()
                if isinstance(value, Mapping) and value.get("name") == self.app_name
            ]
            if (
                len(spec_matches) != 1
                or len(status_matches) != 1
                or not isinstance(spec_matches[0].get("image"), str)
                or not isinstance(status_matches[0].get("imageID"), str)
                or status_matches[0].get("ready") is not True
                or not isinstance(metadata.get("name"), str)
            ):
                continue
            reference = str(spec_matches[0]["image"])
            image_id = str(status_matches[0]["imageID"])
            try:
                digest = str(digest_from_image_id(image_id))
            except ValueError as exc:
                raise KubernetesExecutionError(
                    "RUNTIME_IMAGE_ID_INVALID",
                    stage,
                    str(exc),
                    identity=replace(identity, runtime_image_id=image_id),
                ) from exc
            ready.append((str(metadata["name"]), reference, image_id, digest))
        if not ready:
            raise KubernetesExecutionError(
                "READY_POD_MISSING",
                stage,
                "no non-terminating ready pod matched the stable application label",
                identity=identity,
            )
        ready.sort(key=lambda value: value[0])
        for pod_name, reference, image_id, digest in ready:
            observed = replace(
                identity,
                pod_spec_image_reference=reference,
                runtime_image_id=image_id,
                runtime_digest=digest,
            )
            self._require_exact_reference(reference, observed, stage)
            if digest != identity.expected_digest:
                raise KubernetesExecutionError(
                    "RUNTIME_DIGEST_MISMATCH",
                    stage,
                    f"ready pod {pod_name} has runtime digest {digest}",
                    identity=observed,
                )
        return (*ready[0], len(ready))

    def _rollback(
        self,
        manifest: ResolvedKubernetesManifest,
        identity: KubernetesArtifactIdentity,
        *,
        target_port: int,
    ) -> _RollbackResult:
        try:
            failure_content = render_intentional_readiness_failure(
                manifest,
                deployment_name=self.deployment_name,
                run_id=self.store.run_id,
            )
            failure_document = yaml.safe_load(failure_content)
        except (DevOpsStackError, yaml.YAMLError) as exc:
            raise KubernetesExecutionError(
                "ROLLBACK_MANIFEST_INVALID",
                "rollback",
                "the intentional readiness-failure revision could not be rendered",
                identity=identity,
            ) from exc
        if not isinstance(failure_document, Mapping):
            raise KubernetesExecutionError(
                "ROLLBACK_MANIFEST_INVALID",
                "rollback",
                "the intentional readiness-failure revision is not one object",
                identity=identity,
            )
        failure_reference = self._deployment_image(
            failure_document,
            namespace=manifest.namespace,
            identity=identity,
            stage="rollback",
        )
        self._require_exact_reference(failure_reference, identity, "rollback")
        injected_readiness_path = self._deployment_readiness_path(
            failure_document,
            identity=identity,
        )
        failure_manifest_path = self.store.write_text(
            "kubernetes/rollback-failure.yaml",
            failure_content,
        )

        try:
            self._kubectl(
                "apply",
                "--server-side",
                "--field-manager=devops-stack-composer",
                "--filename",
                str(failure_manifest_path),
                "--output",
                "name",
            )
        except ProcessExecutionError as exc:
            raise KubernetesExecutionError(
                "ROLLBACK_FAILURE_APPLY_FAILED",
                "rollback",
                f"intentional readiness-failure revision apply failed: {exc.category.value}",
                identity=identity,
                process_result=exc.result,
            ) from exc

        failure_rollout: ProcessResult
        try:
            unexpected_success = self._kubectl(
                "rollout",
                "status",
                f"deployment/{self.deployment_name}",
                "--namespace",
                manifest.namespace,
                "--timeout",
                f"{math.ceil(self.rollout_timeout)}s",
                timeout=self.rollout_timeout + 5.0,
            )
        except ProcessExecutionError as exc:
            failure_rollout = exc.result
            if exc.category != ProcessErrorCategory.NONZERO:
                self._persist_rollback_observation(
                    failure_rollout,
                    observed=False,
                    cause_verified=False,
                    injected_readiness_path=injected_readiness_path,
                )
                raise KubernetesExecutionError(
                    "ROLLBACK_FAILURE_OBSERVATION_FAILED",
                    "rollback",
                    "intentional rollout did not reach a bounded Kubernetes failure",
                    identity=identity,
                    process_result=exc.result,
                ) from exc
        else:
            self._persist_rollback_observation(
                unexpected_success,
                observed=False,
                cause_verified=False,
                injected_readiness_path=injected_readiness_path,
            )
            raise KubernetesExecutionError(
                "ROLLBACK_FAILURE_NOT_OBSERVED",
                "rollback",
                "intentional readiness failure unexpectedly rolled out successfully",
                identity=identity,
                process_result=unexpected_success,
            )

        try:
            failure_cause = self._observe_readiness_failure(
                manifest.namespace,
                identity,
                injected_readiness_path=injected_readiness_path,
            )
        except (KubernetesExecutionError, ProcessExecutionError) as exc:
            observation_path = self._persist_rollback_observation(
                failure_rollout,
                observed=True,
                cause_verified=False,
                injected_readiness_path=injected_readiness_path,
            )
            process_result = (
                exc.result
                if isinstance(exc, ProcessExecutionError)
                else exc.process_result
            )
            raise KubernetesExecutionError(
                "ROLLBACK_FAILURE_CAUSE_OBSERVATION_FAILED",
                "rollback",
                "the intentional rollout failed, but its readiness-probe cause "
                "could not be inspected",
                identity=identity,
                process_result=process_result,
                diagnostics_paths=(observation_path,),
            ) from exc

        observation_path = self._persist_rollback_observation(
            failure_rollout,
            observed=True,
            cause_verified=failure_cause.verified,
            injected_readiness_path=injected_readiness_path,
            pod_names=failure_cause.pod_names,
            pods_path=failure_cause.pods_path,
            events_path=failure_cause.events_path,
        )
        cause_evidence_paths = (
            observation_path,
            failure_cause.pods_path,
            failure_cause.events_path,
        )
        if not failure_cause.verified:
            raise KubernetesExecutionError(
                "ROLLBACK_FAILURE_CAUSE_NOT_OBSERVED",
                "rollback",
                "rollout failure was not backed by a matching unready pod and "
                "Readiness probe failed event for the injected path",
                identity=identity,
                process_result=failure_rollout,
                diagnostics_paths=cause_evidence_paths,
            )
        try:
            undo_result = self._kubectl(
                "rollout",
                "undo",
                f"deployment/{self.deployment_name}",
                "--namespace",
                manifest.namespace,
            )
        except ProcessExecutionError as exc:
            raise KubernetesExecutionError(
                "ROLLBACK_UNDO_FAILED",
                "rollback",
                f"kubectl rollout undo failed: {exc.category.value}",
                identity=identity,
                process_result=exc.result,
                diagnostics_paths=cause_evidence_paths,
            ) from exc
        try:
            restored_rollout = self._kubectl(
                "rollout",
                "status",
                f"deployment/{self.deployment_name}",
                "--namespace",
                manifest.namespace,
                "--timeout",
                f"{math.ceil(self.rollout_timeout)}s",
                timeout=self.rollout_timeout + 5.0,
            )
        except ProcessExecutionError as exc:
            raise KubernetesExecutionError(
                "ROLLBACK_RECOVERY_FAILED",
                "rollback",
                f"restored revision did not roll out: {exc.category.value}",
                identity=identity,
                process_result=exc.result,
                diagnostics_paths=cause_evidence_paths,
            ) from exc

        deployment_result = self._kubectl(
            "get",
            "deployment",
            self.deployment_name,
            "--namespace",
            manifest.namespace,
            "--output",
            "json",
        )
        deployment = self._json_object(deployment_result, "rollback", identity)
        deployment_path = self.store.write_json(
            "kubernetes/rollback-restored-deployment.json",
            deployment,
        )
        restored_reference = self._deployment_image(
            deployment,
            namespace=manifest.namespace,
            identity=identity,
            stage="rollback",
        )
        self._require_exact_reference(restored_reference, identity, "rollback")
        final_revision = self._deployment_revision(deployment, identity)

        pods_result = self._kubectl(
            "get",
            "pods",
            "--namespace",
            manifest.namespace,
            "--selector",
            f"{_APP_LABEL}={self.app_name}",
            "--output",
            "json",
        )
        pods = self._json_object(pods_result, "rollback", identity)
        pods_path = self.store.write_json(
            "kubernetes/rollback-restored-pods.json",
            pods,
        )
        _, pod_reference, image_id, runtime_digest, _ = self._ready_pod(
            pods,
            identity=identity,
            stage="rollback",
        )
        restored_identity = replace(
            identity,
            applied_image_reference=restored_reference,
            pod_spec_image_reference=pod_reference,
            runtime_image_id=image_id,
            runtime_digest=runtime_digest,
        )
        self._require_exact_reference(pod_reference, restored_identity, "rollback")
        if runtime_digest != identity.expected_digest:
            raise KubernetesExecutionError(
                "ROLLBACK_DIGEST_MISMATCH",
                "rollback",
                "restored pod does not run the original immutable digest",
                identity=restored_identity,
                diagnostics_paths=cause_evidence_paths,
            )

        post_smoke_relative = "kubernetes/post-rollback-smoke.json"
        try:
            post_health, post_readiness = self._smoke(
                manifest.namespace,
                restored_identity,
                target_port=target_port,
                stage="rollback",
            )
        except KubernetesExecutionError as exc:
            post_smoke_path = self.store.write_json(
                post_smoke_relative,
                {
                    "schemaVersion": "1.0.0",
                    "phase": "post-rollback",
                    "expectedDigest": identity.expected_digest,
                    "finalDigest": runtime_digest,
                    "finalRevision": final_revision,
                    "health": None,
                    "readiness": None,
                    "errorCode": exc.code,
                    "passed": False,
                },
            )
            post_smoke_evidence = post_smoke_path.relative_to(
                self.store.root
            ).as_posix()
            exc.diagnostics_paths = tuple(
                dict.fromkeys(
                    (*exc.diagnostics_paths, *cause_evidence_paths, post_smoke_evidence)
                )
            )
            raise

        post_smoke_passed = all(
            probe.status_code == 200 for probe in (post_health, post_readiness)
        )
        post_smoke_path = self.store.write_json(
            post_smoke_relative,
            {
                "schemaVersion": "1.0.0",
                "phase": "post-rollback",
                "expectedDigest": identity.expected_digest,
                "finalDigest": runtime_digest,
                "finalRevision": final_revision,
                "health": post_health.to_dict(),
                "readiness": post_readiness.to_dict(),
                "passed": post_smoke_passed,
            },
        )
        post_smoke_evidence = post_smoke_path.relative_to(self.store.root).as_posix()
        if not post_smoke_passed:
            failed_probe = next(
                probe
                for probe in (post_health, post_readiness)
                if probe.status_code != 200
            )
            raise KubernetesExecutionError(
                "ROLLBACK_SMOKE_HTTP_FAILED",
                "rollback",
                f"post-rollback {failed_probe.path} returned HTTP "
                f"{failed_probe.status_code}",
                identity=restored_identity,
                diagnostics_paths=(
                    *cause_evidence_paths,
                    post_smoke_evidence,
                ),
            )

        rollback_path = self.store.write_json(
            "kubernetes/rollback.json",
            {
                "schemaVersion": "1.0.0",
                "attempted": True,
                "failureObserved": True,
                "failureCause": "readiness-probe",
                "failureCauseVerified": True,
                "injectedReadinessPath": injected_readiness_path,
                "failingPods": list(failure_cause.pod_names),
                "failureManifestPath": failure_manifest_path.relative_to(
                    self.store.root
                ).as_posix(),
                "failureObservationPath": observation_path,
                "failurePodsPath": failure_cause.pods_path,
                "failureEventsPath": failure_cause.events_path,
                "undo": self._process_summary(undo_result),
                "restoredRollout": self._process_summary(restored_rollout),
                "restoredDeploymentPath": deployment_path.relative_to(
                    self.store.root
                ).as_posix(),
                "restoredPodsPath": pods_path.relative_to(self.store.root).as_posix(),
                "postRollbackSmokePath": post_smoke_evidence,
                "postRollbackHealth": post_health.to_dict(),
                "postRollbackReadiness": post_readiness.to_dict(),
                "finalRevision": final_revision,
                "finalDigest": runtime_digest,
                "passed": True,
            },
        )
        return _RollbackResult(
            identity=restored_identity,
            final_revision=final_revision,
            rollback_path=rollback_path.relative_to(self.store.root).as_posix(),
            observation_path=observation_path,
            failure_cause="readiness-probe",
            post_rollback_health=post_health,
            post_rollback_readiness=post_readiness,
            post_rollback_smoke_path=post_smoke_evidence,
        )

    def _deployment_readiness_path(
        self,
        deployment: Mapping[str, object],
        *,
        identity: KubernetesArtifactIdentity,
    ) -> str:
        spec = deployment.get("spec")
        template = spec.get("template") if isinstance(spec, Mapping) else None
        pod_spec = template.get("spec") if isinstance(template, Mapping) else None
        containers = (
            pod_spec.get("containers") if isinstance(pod_spec, Mapping) else None
        )
        matches = [
            container
            for container in containers or ()
            if isinstance(container, Mapping) and container.get("name") == self.app_name
        ]
        if len(matches) != 1:
            raise KubernetesExecutionError(
                "ROLLBACK_MANIFEST_INVALID",
                "rollback",
                "intentional failure Deployment must contain one application container",
                identity=identity,
            )
        readiness = matches[0].get("readinessProbe")
        http_get = readiness.get("httpGet") if isinstance(readiness, Mapping) else None
        path = http_get.get("path") if isinstance(http_get, Mapping) else None
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path == self.readiness_path
        ):
            raise KubernetesExecutionError(
                "ROLLBACK_MANIFEST_INVALID",
                "rollback",
                "intentional failure Deployment must inject a distinct HTTP readiness path",
                identity=identity,
            )
        return path

    def _observe_readiness_failure(
        self,
        namespace: str,
        identity: KubernetesArtifactIdentity,
        *,
        injected_readiness_path: str,
    ) -> _ReadinessFailureObservation:
        pods_result = self._kubectl(
            "get",
            "pods",
            "--namespace",
            namespace,
            "--selector",
            f"{_APP_LABEL}={self.app_name}",
            "--output",
            "json",
        )
        pods = self._json_object(pods_result, "rollback", identity)
        events_result = self._kubectl(
            "get",
            "events",
            "--namespace",
            namespace,
            "--sort-by=.lastTimestamp",
            "--output",
            "json",
        )
        events = self._json_object(events_result, "rollback", identity)
        pod_items = pods.get("items")
        event_items = events.get("items")
        if not isinstance(pod_items, list) or not isinstance(event_items, list):
            raise KubernetesExecutionError(
                "ROLLBACK_FAILURE_CAUSE_EVIDENCE_INVALID",
                "rollback",
                "rollback failure pod and event inventories must be arrays",
                identity=identity,
            )

        candidates: dict[tuple[str, str], dict[str, object]] = {}
        pod_summaries: list[dict[str, object]] = []
        for item in pod_items:
            if not isinstance(item, Mapping):
                continue
            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            name = metadata.get("name")
            uid = metadata.get("uid")
            labels = metadata.get("labels")
            if (
                metadata.get("namespace") != namespace
                or metadata.get("deletionTimestamp") is not None
                or not isinstance(labels, Mapping)
                or labels.get(_APP_LABEL) != self.app_name
                or not isinstance(name, str)
                or not name
                or not isinstance(uid, str)
                or not uid
            ):
                continue
            spec = item.get("spec")
            containers = spec.get("containers") if isinstance(spec, Mapping) else None
            app_containers = [
                container
                for container in containers or ()
                if isinstance(container, Mapping)
                and container.get("name") == self.app_name
            ]
            if len(app_containers) != 1:
                continue
            container = app_containers[0]
            readiness = container.get("readinessProbe")
            http_get = (
                readiness.get("httpGet") if isinstance(readiness, Mapping) else None
            )
            path = http_get.get("path") if isinstance(http_get, Mapping) else None
            if path != injected_readiness_path:
                continue
            image = container.get("image")
            if not isinstance(image, str):
                continue
            self._require_exact_reference(image, identity, "rollback")

            status = item.get("status")
            status = status if isinstance(status, Mapping) else {}
            conditions = status.get("conditions")
            pod_ready_false = any(
                isinstance(condition, Mapping)
                and condition.get("type") == "Ready"
                and condition.get("status") == "False"
                for condition in conditions or ()
            )
            statuses = status.get("containerStatuses")
            app_statuses = [
                container_status
                for container_status in statuses or ()
                if isinstance(container_status, Mapping)
                and container_status.get("name") == self.app_name
            ]
            container_ready_false = (
                len(app_statuses) == 1 and app_statuses[0].get("ready") is False
            )
            summary = {
                "name": name,
                "uid": uid,
                "image": image,
                "injectedReadinessPath": path,
                "podReadyFalse": pod_ready_false,
                "containerReadyFalse": container_ready_false,
            }
            if len(pod_summaries) < _MAX_ROLLBACK_OBSERVATIONS:
                pod_summaries.append(summary)
            if pod_ready_false and container_ready_false:
                candidates[(name, uid)] = summary

        matched_pods: set[str] = set()
        event_summaries: list[dict[str, object]] = []
        for item in event_items:
            if not isinstance(item, Mapping):
                continue
            involved = item.get("involvedObject")
            involved = involved if isinstance(involved, Mapping) else {}
            name = involved.get("name")
            uid = involved.get("uid")
            message = item.get("message")
            if (
                item.get("reason") != "Unhealthy"
                or involved.get("kind") != "Pod"
                or involved.get("namespace") != namespace
                or not isinstance(name, str)
                or not isinstance(uid, str)
                or not uid
                or not isinstance(message, str)
                or re.search(r"\breadiness probe failed\b", message, re.IGNORECASE)
                is None
            ):
                continue
            matching_key = (name, uid) if (name, uid) in candidates else None
            if matching_key is None:
                continue
            matched_pods.add(name)
            if len(event_summaries) < _MAX_ROLLBACK_OBSERVATIONS:
                safe_message = self._bounded_redacted_text(message, 4096)
                event_summaries.append(
                    {
                        "reason": "Unhealthy",
                        "involvedPod": name,
                        "involvedPodUid": uid,
                        "readinessProbeFailure": True,
                        "message": safe_message,
                        "messageSha256": hashlib.sha256(message.encode()).hexdigest(),
                    }
                )

        verified = bool(matched_pods)
        pods_path = self.store.write_json(
            "kubernetes/rollback-failure-pods.json",
            {
                "schemaVersion": "1.0.0",
                "command": self._process_summary(pods_result),
                "injectedReadinessPath": injected_readiness_path,
                "candidates": pod_summaries,
                "matchedPods": sorted(matched_pods),
            },
        )
        events_path = self.store.write_json(
            "kubernetes/rollback-failure-events.json",
            {
                "schemaVersion": "1.0.0",
                "command": self._process_summary(events_result),
                "expectedReason": "Unhealthy",
                "expectedMessage": "Readiness probe failed",
                "matchingEvents": event_summaries,
            },
        )
        return _ReadinessFailureObservation(
            verified=verified,
            pod_names=tuple(sorted(matched_pods)),
            pods_path=pods_path.relative_to(self.store.root).as_posix(),
            events_path=events_path.relative_to(self.store.root).as_posix(),
        )

    def _persist_rollback_observation(
        self,
        result: ProcessResult,
        *,
        observed: bool,
        cause_verified: bool,
        injected_readiness_path: str,
        pod_names: Sequence[str] = (),
        pods_path: str | None = None,
        events_path: str | None = None,
    ) -> str:
        content = "\n".join(value for value in (result.stdout, result.stderr) if value)
        content = redact_process_output(content or "<empty>")
        encoded = content.encode("utf-8")
        if len(encoded) > _MAX_DIAGNOSTIC_BYTES:
            marker = "\n...[output truncated]"
            available = _MAX_DIAGNOSTIC_BYTES - len(marker.encode())
            content = encoded[:available].decode("utf-8", errors="ignore") + marker
        output_path = self.store.write_text(
            "kubernetes/rollback-failure-output.txt",
            content.rstrip() + "\n",
        )
        evidence_path = self.store.write_json(
            "kubernetes/rollback-observation.json",
            {
                "schemaVersion": "1.0.0",
                "failureObserved": observed,
                "expectedFailureCause": "readiness-probe",
                "expectedFailureCauseVerified": cause_verified,
                "injectedReadinessPath": injected_readiness_path,
                "failingPods": list(pod_names),
                "failurePodsPath": pods_path,
                "failureEventsPath": events_path,
                "command": self._process_summary(result),
                "outputPath": output_path.relative_to(self.store.root).as_posix(),
            },
        )
        return evidence_path.relative_to(self.store.root).as_posix()

    def _process_summary(self, result: ProcessResult) -> dict[str, object]:
        return {
            "argv": [self._evidence_argument(value) for value in result.argv],
            "returnCode": result.returncode,
            "category": (
                result.error_category.value if result.error_category is not None else None
            ),
            "stdoutTruncated": result.stdout_truncated,
            "stderrTruncated": result.stderr_truncated,
        }

    def _evidence_argument(self, value: str) -> str:
        if value == str(self.kubeconfig):
            return "<private-kubeconfig>"
        if value == str(self.cache_dir):
            return "<private-kubectl-cache>"
        try:
            candidate = Path(value)
            if candidate.is_absolute() and candidate.is_relative_to(self.store.root):
                return candidate.relative_to(self.store.root).as_posix()
        except (OSError, ValueError):
            pass
        return redact_process_output(value)

    def _notify_progress(self, event: str, outputs: Mapping[str, Any]) -> None:
        callback = self._progress_callback
        if callback is not None:
            callback(event, dict(outputs))

    def _evidence_paths(self) -> tuple[str, ...]:
        values: list[str] = []
        for directory in (self.store.path("kubernetes"), self.store.path("diagnostics")):
            for path in sorted(directory.rglob("*")):
                if path.is_symlink():
                    raise DevOpsStackError("Kubernetes evidence contains a symbolic link")
                if path.is_file():
                    values.append(path.relative_to(self.store.root).as_posix())
        return tuple(values)

    def _deployment_revision(
        self,
        deployment: Mapping[str, object],
        identity: KubernetesArtifactIdentity,
    ) -> str:
        metadata = deployment.get("metadata")
        annotations = (
            metadata.get("annotations") if isinstance(metadata, Mapping) else None
        )
        revision = (
            annotations.get("deployment.kubernetes.io/revision")
            if isinstance(annotations, Mapping)
            else None
        )
        if not isinstance(revision, str) or not re.fullmatch(r"[1-9][0-9]*", revision):
            raise KubernetesExecutionError(
                "ROLLBACK_REVISION_INVALID",
                "rollback",
                "restored Deployment has no valid Kubernetes revision annotation",
                identity=identity,
            )
        return revision

    def _smoke(
        self,
        namespace: str,
        identity: KubernetesArtifactIdentity,
        *,
        target_port: int,
        stage: str = "smoke",
    ) -> tuple[HttpSmokeResult, HttpSmokeResult]:
        parent_token = getattr(self.runner, "cancellation_token", None)
        if parent_token is not None and not isinstance(parent_token, CancellationToken):
            parent_token = None
        readiness = re.compile(
            rf"(?m)^Forwarding from 127\.0\.0\.1:([1-9][0-9]{{0,4}})"
            rf" -> {target_port}\r?$"
        )
        try:
            managed = self._start_kubectl(
                "port-forward",
                "--namespace",
                namespace,
                "--address",
                "127.0.0.1",
                f"service/{self.service_name}",
                f":{self.service_port}",
                timeout=self.port_forward_timeout,
                cancellation_token=parent_token,
            )
        except ProcessExecutionError as exc:
            raise KubernetesExecutionError(
                "PORT_FORWARD_START_FAILED",
                stage,
                f"kubectl port-forward could not start: {exc.category.value}",
                identity=identity,
                process_result=exc.result,
            ) from exc
        except Exception as exc:
            raise KubernetesExecutionError(
                "PORT_FORWARD_START_FAILED",
                stage,
                "the managed kubectl port-forward could not start",
                identity=identity,
            ) from exc

        cleanup_failure: KubernetesExecutionError | None = None
        try:
            try:
                match = managed.wait_for_output(
                    readiness,
                    timeout=self.port_forward_start_timeout,
                )
            except TimeoutError as exc:
                stdout, stderr = managed.output()
                if "Forwarding from" in stdout or "Forwarding from" in stderr:
                    raise KubernetesExecutionError(
                        "PORT_FORWARD_READINESS_INVALID",
                        stage,
                        "kubectl reported a forwarding endpoint that did not match "
                        "the requested loopback service port",
                        identity=identity,
                    ) from exc
                raise KubernetesExecutionError(
                    "PORT_FORWARD_TIMEOUT",
                    stage,
                    "kubectl did not report its selected loopback port before the deadline",
                    identity=identity,
                ) from exc
            except ProcessExecutionError as exc:
                raise KubernetesExecutionError(
                    "PORT_FORWARD_FAILED",
                    stage,
                    f"kubectl port-forward failed with {exc.category.value}",
                    identity=identity,
                    process_result=exc.result,
                ) from exc
            except RuntimeError as exc:
                raise KubernetesExecutionError(
                    "PORT_FORWARD_STOPPED",
                    stage,
                    "kubectl port-forward exited before reporting readiness",
                    identity=identity,
                ) from exc
            local_port = int(match.group(1))
            if local_port > 65535:
                raise KubernetesExecutionError(
                    "PORT_FORWARD_READINESS_INVALID",
                    stage,
                    "kubectl reported an invalid selected loopback port",
                    identity=identity,
                )

            try:
                health = self._bounded_http_result(
                    self._http_get(
                        "127.0.0.1", local_port, self.health_path, self.http_timeout
                    ),
                    self.health_path,
                )
                readiness = self._bounded_http_result(
                    self._http_get(
                        "127.0.0.1",
                        local_port,
                        self.readiness_path,
                        self.http_timeout,
                    ),
                    self.readiness_path,
                )
            except Exception as exc:
                raise KubernetesExecutionError(
                    "SMOKE_HTTP_REQUEST_FAILED",
                    stage,
                    "a loopback HTTP smoke request failed or returned invalid evidence",
                    identity=identity,
                ) from exc
            if not managed.is_running:
                raise KubernetesExecutionError(
                    "PORT_FORWARD_STOPPED",
                    stage,
                    "kubectl port-forward stopped during smoke execution",
                    identity=identity,
                )
            return health, readiness
        finally:
            if not managed.close(timeout=self.port_forward_cleanup_timeout):
                cleanup_failure = KubernetesExecutionError(
                    "PORT_FORWARD_CLEANUP_FAILED",
                    stage,
                    "kubectl port-forward was not terminated and reaped before the deadline",
                    identity=identity,
                )
            if cleanup_failure is not None:
                raise cleanup_failure

    def _start_kubectl(
        self,
        *arguments: str,
        timeout: float,
        cancellation_token: CancellationToken | None = None,
    ) -> ManagedProcess:
        return self.runner.start(
            (
                "kubectl",
                "--kubeconfig",
                str(self.kubeconfig),
                "--context",
                self.context,
                "--cache-dir",
                str(self.cache_dir),
                *arguments,
            ),
            cwd=self.store.project,
            timeout=timeout,
            cancellation_token=cancellation_token,
        )

    def _kubectl(
        self,
        *arguments: str,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ProcessResult:
        return self.runner.run(
            (
                "kubectl",
                "--kubeconfig",
                str(self.kubeconfig),
                "--context",
                self.context,
                "--cache-dir",
                str(self.cache_dir),
                *arguments,
            ),
            cwd=self.store.project,
            timeout=self.command_timeout if timeout is None else timeout,
            cancellation_token=cancellation_token,
        )

    def _json_object(
        self,
        result: ProcessResult,
        stage: str,
        identity: KubernetesArtifactIdentity,
    ) -> Mapping[str, object]:
        if result.stdout_truncated:
            raise KubernetesExecutionError(
                "KUBECTL_OUTPUT_TRUNCATED",
                stage,
                "kubectl JSON exceeded the bounded process output limit",
                identity=identity,
                process_result=result,
            )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise KubernetesExecutionError(
                "KUBECTL_JSON_INVALID",
                stage,
                "kubectl returned malformed or truncated JSON",
                identity=identity,
                process_result=result,
            ) from exc
        if not isinstance(value, Mapping):
            raise KubernetesExecutionError(
                "KUBECTL_JSON_INVALID",
                stage,
                "kubectl JSON result must be an object",
                identity=identity,
                process_result=result,
            )
        return value

    def _require_exact_reference(
        self,
        value: str,
        identity: KubernetesArtifactIdentity,
        stage: str,
    ) -> None:
        try:
            reference = parse_oci_reference(value)
        except ValueError as exc:
            raise KubernetesExecutionError(
                "WORKLOAD_IMAGE_INVALID", stage, str(exc), identity=identity
            ) from exc
        if reference.digest is None:
            raise KubernetesExecutionError(
                "MUTABLE_IMAGE_REJECTED",
                stage,
                "workload image is not digest-pinned",
                identity=identity,
            )
        if reference.tag is not None or value != identity.expected_image_reference:
            raise KubernetesExecutionError(
                "WORKLOAD_IMAGE_MISMATCH",
                stage,
                "workload image does not equal the expected immutable reference",
                identity=identity,
            )

    def _collect_diagnostics(self) -> tuple[str, ...]:
        commands = (
            (
                "diagnostics/events.json",
                (
                    "get",
                    "events",
                    "--namespace",
                    self._active_namespace,
                    "--sort-by=.lastTimestamp",
                    "--output",
                    "json",
                ),
            ),
            (
                "diagnostics/deployment-describe.txt",
                (
                    "describe",
                    "deployment",
                    self.deployment_name,
                    "--namespace",
                    self._active_namespace,
                ),
            ),
            (
                "diagnostics/replicasets.json",
                (
                    "get",
                    "replicasets",
                    "--namespace",
                    self._active_namespace,
                    "--selector",
                    f"{_APP_LABEL}={self.app_name}",
                    "--output",
                    "json",
                ),
            ),
            (
                "diagnostics/replicasets-describe.txt",
                (
                    "describe",
                    "replicasets",
                    "--namespace",
                    self._active_namespace,
                    "--selector",
                    f"{_APP_LABEL}={self.app_name}",
                ),
            ),
            (
                "diagnostics/pods-describe.txt",
                (
                    "describe",
                    "pods",
                    "--namespace",
                    self._active_namespace,
                    "--selector",
                    f"{_APP_LABEL}={self.app_name}",
                ),
            ),
            (
                "diagnostics/pod-logs.txt",
                (
                    "logs",
                    "--namespace",
                    self._active_namespace,
                    "--selector",
                    f"{_APP_LABEL}={self.app_name}",
                    "--all-containers=true",
                    "--tail=200",
                    "--prefix=true",
                ),
            ),
            (
                "diagnostics/rollout-history.txt",
                (
                    "rollout",
                    "history",
                    f"deployment/{self.deployment_name}",
                    "--namespace",
                    self._active_namespace,
                ),
            ),
            (
                "diagnostics/final-manifests.yaml",
                (
                    "get",
                    "deployment,replicaset,pod,service",
                    "--namespace",
                    self._active_namespace,
                    "--selector",
                    f"{_APP_LABEL}={self.app_name}",
                    "--output",
                    "yaml",
                ),
            ),
        )
        paths: list[str] = []
        for relative, arguments in commands:
            try:
                result = self._kubectl(*arguments)
                content = result.stdout or result.stderr or "<empty>"
            except ProcessExecutionError as exc:
                content = "\n".join(
                    value
                    for value in (exc.result.stdout, exc.result.stderr)
                    if value
                ) or f"diagnostic command failed: {exc.category.value}"
            except Exception as exc:
                content = f"diagnostic command failed: {type(exc).__name__}"
            path = self._write_bounded_text(relative, content)
            if path is not None:
                paths.append(path)
        return tuple(paths)

    @property
    def _active_namespace(self) -> str:
        # execute() validates and assigns this immediately before invoking kubectl.
        return self.__active_namespace

    @_active_namespace.setter
    def _active_namespace(self, value: str) -> None:
        self.__active_namespace = value

    def _write_process_failure(
        self, stage: str, result: ProcessResult
    ) -> tuple[str, ...]:
        content = "\n".join(value for value in (result.stdout, result.stderr) if value)
        content = content or f"process failed: {result.error_category}"
        path = self._write_bounded_text(f"diagnostics/{stage}-command.txt", content)
        return (path,) if path is not None else ()

    def _write_bounded_text(self, relative: str, content: str) -> str | None:
        value = self._bounded_redacted_text(content, _MAX_DIAGNOSTIC_BYTES)
        try:
            path = self.store.write_text(relative, value.rstrip() + "\n")
        except (DevOpsStackError, OSError):
            return None
        return path.relative_to(self.store.root).as_posix()

    @staticmethod
    def _bounded_redacted_text(content: str, maximum_bytes: int) -> str:
        value = redact_process_output(content).replace("\x00", "")
        encoded = value.encode("utf-8")
        if len(encoded) <= maximum_bytes:
            return value
        marker = "\n...[output truncated]"
        available = maximum_bytes - len(marker.encode())
        return encoded[:available].decode("utf-8", errors="ignore") + marker

    @staticmethod
    def _private_kubeconfig(path: Path) -> tuple[Path, str]:
        try:
            candidate = Path(path)
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise ValueError("kubeconfig must be an existing regular file") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("kubeconfig must be a non-symlink regular file")
        resolved_metadata = resolved.stat()
        if os.name == "posix":
            if resolved_metadata.st_uid != os.geteuid():
                raise ValueError("kubeconfig must be owned by the current user")
            if stat.S_IMODE(resolved_metadata.st_mode) & 0o077:
                raise ValueError("kubeconfig must not be accessible by group or other users")
        try:
            document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ValueError("kubeconfig must be readable YAML") from exc
        if not isinstance(document, Mapping):
            raise ValueError("kubeconfig must contain one configuration object")
        context = document.get("current-context")
        if (
            not isinstance(context, str)
            or not context
            or len(context.encode("utf-8")) > 1024
            or any(ord(character) < 32 or ord(character) == 127 for character in context)
        ):
            raise ValueError("kubeconfig must declare a bounded current-context")
        contexts = document.get("contexts")
        context_entries = [
            value
            for value in contexts or ()
            if isinstance(value, Mapping) and value.get("name") == context
        ]
        if len(context_entries) != 1:
            raise ValueError("kubeconfig current-context must resolve exactly once")
        context_value = context_entries[0].get("context")
        cluster_name = (
            context_value.get("cluster") if isinstance(context_value, Mapping) else None
        )
        user_name = (
            context_value.get("user") if isinstance(context_value, Mapping) else None
        )
        if not isinstance(cluster_name, str) or not isinstance(user_name, str):
            raise ValueError("kubeconfig current-context must name one cluster and user")
        clusters = document.get("clusters")
        cluster_entries = [
            value
            for value in clusters or ()
            if isinstance(value, Mapping) and value.get("name") == cluster_name
        ]
        users = document.get("users")
        user_entries = [
            value
            for value in users or ()
            if isinstance(value, Mapping) and value.get("name") == user_name
        ]
        if len(cluster_entries) != 1 or len(user_entries) != 1:
            raise ValueError("kubeconfig context targets must resolve exactly once")
        cluster = cluster_entries[0].get("cluster")
        user = user_entries[0].get("user")
        if not isinstance(cluster, Mapping) or not isinstance(user, Mapping):
            raise ValueError("kubeconfig cluster and user entries must be objects")
        server = cluster.get("server")
        try:
            parsed_server = urlsplit(server if isinstance(server, str) else "")
            port = parsed_server.port
        except ValueError as exc:
            raise ValueError("kubeconfig cluster server is invalid") from exc
        if (
            parsed_server.scheme != "https"
            or parsed_server.hostname not in {"127.0.0.1", "::1", "localhost"}
            or port is None
            or parsed_server.path not in {"", "/"}
            or parsed_server.query
            or parsed_server.fragment
            or parsed_server.username is not None
        ):
            raise ValueError("kubeconfig cluster server must be loopback HTTPS with a port")
        if "proxy-url" in cluster:
            raise ValueError("kubeconfig proxy-url is not allowed")
        if "exec" in user or "auth-provider" in user:
            raise ValueError("kubeconfig executable authentication plugins are not allowed")
        for file_key in ("certificate-authority", "client-certificate", "client-key"):
            if file_key in cluster or file_key in user:
                raise ValueError("kubeconfig credential file references are not allowed")
        return resolved, context

    @staticmethod
    def _private_cache_directory(parent: Path) -> Path:
        path = parent / "kubectl-cache"
        try:
            path.mkdir(mode=0o700, exist_ok=True)
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("kubectl cache directory could not be created safely") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("kubectl cache path must be a non-symlink directory")
        resolved_metadata = resolved.stat()
        if os.name == "posix" and (
            resolved_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(resolved_metadata.st_mode) & 0o077
        ):
            raise ValueError("kubectl cache directory must be private and user-owned")
        return resolved

    @staticmethod
    def _dns_label(name: str, value: str) -> str:
        if not isinstance(value, str) or not _DNS_LABEL.fullmatch(value):
            raise ValueError(f"{name} must be one lowercase Kubernetes DNS label")
        return value

    @staticmethod
    def _http_path(name: str, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or len(value) > 2048
            or any(character.isspace() or ord(character) < 32 for character in value)
            or any(character in value for character in ("\x7f", "#"))
            or "://" in value
        ):
            raise ValueError(f"{name} must be a bounded absolute HTTP path")
        return value

    @staticmethod
    def _duration(name: str, value: float) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{name} must be a positive finite number")
        return float(value)

    @staticmethod
    def _bounded_http_result(result: HttpSmokeResult, path: str) -> HttpSmokeResult:
        if not isinstance(result, HttpSmokeResult):
            raise ValueError("http_getter must return HttpSmokeResult")
        if result.path != path:
            raise ValueError("http_getter returned evidence for the wrong path")
        if (
            isinstance(result.status_code, bool)
            or not isinstance(result.status_code, int)
            or not 100 <= result.status_code <= 599
        ):
            raise ValueError("http_getter returned an invalid status code")
        sanitized = redact_process_output(result.body)
        payload = sanitized.encode("utf-8")
        truncated = result.truncated or len(payload) > _MAX_HTTP_BODY_BYTES
        if len(payload) > _MAX_HTTP_BODY_BYTES:
            sanitized = payload[:_MAX_HTTP_BODY_BYTES].decode("utf-8", errors="ignore")
        return HttpSmokeResult(path, result.status_code, sanitized, truncated)


__all__ = [
    "HttpSmokeResult",
    "KubernetesArtifactIdentity",
    "KubernetesExecutionError",
    "KubernetesExecutionResult",
    "KubernetesExecutor",
    "KubernetesPreflightResult",
]
