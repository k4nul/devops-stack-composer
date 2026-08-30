from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest

import yaml

from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.kubernetes_execution import (
    HttpSmokeResult,
    KubernetesExecutionError,
    KubernetesExecutor,
)
from devops_stack_composer.kubernetes_runtime import ResolvedKubernetesManifest
from devops_stack_composer.process_runner import (
    CancellationToken,
    NonZeroExitError,
    ProcessCancelledError,
    ProcessErrorCategory,
    ProcessResult,
)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
REFERENCE = "127.0.0.1:49153/team/service@" + DIGEST
OTHER_REFERENCE = "127.0.0.1:49153/team/service@" + OTHER_DIGEST


def resolved_manifest(image: str = REFERENCE) -> ResolvedKubernetesManifest:
    content = f"""apiVersion: v1
kind: Namespace
metadata:
  name: staging
---
apiVersion: v1
kind: Service
metadata:
  name: service
  namespace: staging
spec:
  selector:
    app.kubernetes.io/name: service
  ports:
  - name: http
    port: 8080
    targetPort: 8000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: service
  namespace: staging
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: service
  template:
    metadata:
      labels:
        app.kubernetes.io/name: service
    spec:
      containers:
      - name: service
        image: {image}
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
"""
    return ResolvedKubernetesManifest(
        environment="staging",
        namespace="staging",
        immutable_image_reference=image,
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        resource_ids=(
            "v1/Namespace//staging",
            "v1/Service/staging/service",
            "apps/v1/Deployment/staging/service",
        ),
    )


def environment_manifest(
    environment: str,
    *,
    namespace: str | None = None,
) -> ResolvedKubernetesManifest:
    selected_namespace = namespace or environment
    source = resolved_manifest()
    content = source.content.replace("staging", selected_namespace)
    return ResolvedKubernetesManifest(
        environment=environment,
        namespace=selected_namespace,
        immutable_image_reference=source.immutable_image_reference,
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        resource_ids=tuple(
            resource.replace("staging", selected_namespace)
            for resource in source.resource_ids
        ),
    )


class FakeManagedProcess:
    def __init__(
        self,
        runner: FakeKubectlRunner,
        command: tuple[str, ...],
        cancellation_token: CancellationToken | None,
    ) -> None:
        self.runner = runner
        self.command = command
        self.cancellation_token = cancellation_token
        self._running = True

    @property
    def is_running(self) -> bool:
        return self._running

    def output(self) -> tuple[str, str]:
        return self.runner.forward_readiness, ""

    def wait_for_output(
        self,
        pattern: re.Pattern[str],
        *,
        timeout: float,
    ) -> re.Match[str]:
        del timeout
        if self.cancellation_token is not None and self.cancellation_token.is_cancelled():
            self._running = False
            result = self.runner._result(
                self.command,
                returncode=-15,
                category=ProcessErrorCategory.CANCELLED,
            )
            raise ProcessCancelledError(ProcessErrorCategory.CANCELLED, result)
        match = pattern.search(self.runner.forward_readiness)
        if match is None:
            raise TimeoutError("simulated readiness timeout")
        return match

    def close(self, timeout: float | None = None) -> bool:
        del timeout
        self._running = False
        self.runner.forward_stopped.set()
        return self.runner.forward_cleanup_succeeds


class FakeKubectlRunner:
    def __init__(self, project: Path) -> None:
        self.project = project
        self.calls: list[tuple[str, ...]] = []
        self.applied_reference = REFERENCE
        self.pod_reference = REFERENCE
        self.runtime_image_id = f"containerd://{DIGEST}"
        self.rollout_failure = False
        self.rollback_failure_observed = True
        self.rollback_undo_failure = False
        self.rollback_recovery_failure = False
        self.rollback_failure_applied = False
        self.rollback_undone = False
        self.restored_reference = REFERENCE
        self.restored_runtime_image_id = f"containerd://{DIGEST}"
        self.pod_output_truncated = False
        self.forward_started = threading.Event()
        self.forward_stopped = threading.Event()
        self.service_target_port = 8000
        self.forward_readiness = "Forwarding from 127.0.0.1:45123 -> 8000\n"
        self.forward_cleanup_succeeds = True
        self.cancellation_token: CancellationToken | None = None

    def run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ProcessResult:
        command = tuple(argv)
        self.calls.append(command)
        action = command[7:]
        if action and action[0] == "apply" and any(
            value.endswith("rollback-failure.yaml") for value in action
        ):
            self.rollback_failure_applied = True
        if action[:2] == ("rollout", "undo"):
            if self.rollback_undo_failure:
                self._raise_nonzero(command, "rollback undo failed")
            self.rollback_undone = True
        if action[:2] == ("rollout", "status") and self.rollback_failure_applied:
            if not self.rollback_undone and self.rollback_failure_observed:
                self._raise_nonzero(command, "intentional rollout failed")
            if self.rollback_undone and self.rollback_recovery_failure:
                self._raise_nonzero(command, "restored rollout failed")
        elif action[:2] == ("rollout", "status") and self.rollout_failure:
            result = self._result(
                command,
                returncode=1,
                stderr="password=rollout-secret\nrollout failed\n",
                category=ProcessErrorCategory.NONZERO,
            )
            raise NonZeroExitError(ProcessErrorCategory.NONZERO, result)
        if action[:2] == ("get", "deployment"):
            return self._result(command, stdout=json.dumps(self._deployment()))
        if action[:2] == ("get", "service"):
            return self._result(command, stdout=json.dumps(self._service()))
        if action and action[0] == "get" and "pods" in action:
            return self._result(
                command,
                stdout=("{\"items\":[" if self.pod_output_truncated else json.dumps(self._pods())),
                stdout_truncated=self.pod_output_truncated,
            )
        if action[:2] == ("get", "events"):
            return self._result(command, stdout='{"items":[{"reason":"Unhealthy"}]}')
        if action and action[0] == "logs":
            return self._result(command, stdout="bounded pod diagnostic\n")
        return self._result(command, stdout="ok\n")

    def _raise_nonzero(self, command: tuple[str, ...], message: str) -> None:
        result = self._result(
            command,
            returncode=1,
            stderr=message + "\n",
            category=ProcessErrorCategory.NONZERO,
        )
        raise NonZeroExitError(ProcessErrorCategory.NONZERO, result)

    def start(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> FakeManagedProcess:
        del cwd, timeout
        command = tuple(argv)
        self.calls.append(command)
        action = command[7:]
        if not action or action[0] != "port-forward":
            raise AssertionError("only port-forward may use the managed process API")
        self.forward_started.set()
        return FakeManagedProcess(self, command, cancellation_token)

    def _result(
        self,
        command: tuple[str, ...],
        *,
        returncode: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        category: ProcessErrorCategory | None = None,
        stdout_truncated: bool = False,
    ) -> ProcessResult:
        return ProcessResult(
            command,
            self.project,
            returncode,
            stdout,
            stderr,
            0.01,
            category,
            stdout_truncated=stdout_truncated,
        )

    def _deployment(self) -> dict[str, object]:
        reference = self.restored_reference if self.rollback_undone else self.applied_reference
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "service",
                "namespace": "staging",
                "annotations": {
                    "deployment.kubernetes.io/revision": (
                        "3" if self.rollback_undone else "1"
                    )
                },
            },
            "spec": {
                "selector": {
                    "matchLabels": {"app.kubernetes.io/name": "service"}
                },
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "service"}},
                    "spec": {
                        "containers": [
                            {"name": "service", "image": reference}
                        ]
                    },
                }
            },
        }

    def _pods(self) -> dict[str, object]:
        reference = self.restored_reference if self.rollback_undone else self.pod_reference
        image_id = (
            self.restored_runtime_image_id
            if self.rollback_undone
            else self.runtime_image_id
        )
        return {
            "items": [
                {
                    "metadata": {
                        "name": "service-abc",
                        "namespace": "staging",
                        "labels": {"app.kubernetes.io/name": "service"},
                    },
                    "spec": {
                        "containers": [
                            {"name": "service", "image": reference}
                        ]
                    },
                    "status": {
                        "phase": "Running",
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "containerStatuses": [
                            {
                                "name": "service",
                                "ready": True,
                                "imageID": image_id,
                            }
                        ],
                    },
                }
            ]
        }

    def _service(self) -> dict[str, object]:
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "service", "namespace": "staging"},
            "spec": {
                "selector": {"app.kubernetes.io/name": "service"},
                "ports": [
                    {
                        "name": "http",
                        "port": 8080,
                        "targetPort": self.service_target_port,
                        "protocol": "TCP",
                    }
                ],
            },
        }


class FakeHttpGetter:
    def __init__(self, statuses: dict[str, int] | None = None) -> None:
        self.statuses = statuses or {}
        self.calls: list[tuple[str, int, str, float]] = []
        self.failure_path: str | None = None

    def __call__(
        self, host: str, port: int, path: str, timeout: float
    ) -> HttpSmokeResult:
        self.calls.append((host, port, path, timeout))
        if path == self.failure_path:
            raise ConnectionRefusedError("simulated loopback failure")
        return HttpSmokeResult(
            path,
            self.statuses.get(path, 200),
            f'{{"path":"{path}","token":"should-redact"}}',
        )


class KubernetesExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.kubeconfig = self.project / "kubeconfig"
        self.kubeconfig.write_text(
            """apiVersion: v1
kind: Config
current-context: kind-test
clusters:
- name: kind-test
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: ZmFrZQ==
contexts:
- name: kind-test
  context:
    cluster: kind-test
    user: kind-test
users:
- name: kind-test
  user:
    client-certificate-data: ZmFrZQ==
    client-key-data: ZmFrZQ==
""",
            encoding="utf-8",
        )
        self.kubeconfig.chmod(0o600)
        self.store = EvidenceStore.create(
            self.project,
            run_id="20260830T120000Z-abcdef123456",
        )
        self.runner = FakeKubectlRunner(self.project)
        self.http = FakeHttpGetter()

    def executor(self, *, progress_callback=None) -> KubernetesExecutor:
        return KubernetesExecutor(
            self.runner,
            self.store,
            kubeconfig=self.kubeconfig,
            app_name="service",
            deployment_name="service",
            service_name="service",
            service_port=8080,
            health_path="/health",
            readiness_path="/ready",
            http_getter=self.http,
            progress_callback=progress_callback,
        )

    def test_server_side_dry_run_covers_every_environment_without_workload_apply(
        self,
    ) -> None:
        result = self.executor().server_side_dry_run(
            tuple(
                environment_manifest(environment)
                for environment in ("development", "staging", "production")
            )
        )

        self.assertEqual(
            result.environments,
            ("development", "staging", "production"),
        )
        self.assertEqual(len(self.runner.calls), 9)
        for offset in range(0, 9, 3):
            namespace_dry_run, namespace_apply, workload_dry_run = self.runner.calls[
                offset : offset + 3
            ]
            self.assertIn("--dry-run=server", namespace_dry_run)
            self.assertNotIn("--dry-run=server", namespace_apply)
            self.assertTrue(
                namespace_apply[namespace_apply.index("--filename") + 1].endswith(
                    "-namespace-bootstrap.yaml"
                )
            )
            self.assertIn("--dry-run=server", workload_dry_run)
            self.assertTrue(
                workload_dry_run[
                    workload_dry_run.index("--filename") + 1
                ].endswith("-resolved.yaml")
            )
        evidence = json.loads(
            self.store.path("kubernetes/server-side-dry-run.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(evidence["passed"])
        self.assertEqual(
            [item["environment"] for item in evidence["environments"]],
            ["development", "staging", "production"],
        )
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(str(self.kubeconfig), serialized)
        self.assertNotIn(str(self.project / "kubectl-cache"), serialized)
        self.assertIn("<private-kubeconfig>", serialized)
        self.assertIn("<private-kubectl-cache>", serialized)
        self.assertIn(result.evidence_path, result.evidence_paths)

    def test_reports_ordered_progress_and_complete_evidence_inventory(self) -> None:
        events: list[tuple[str, dict[str, object]]] = []
        executor = self.executor(
            progress_callback=lambda event, outputs: events.append(
                (event, dict(outputs))
            )
        )

        preflight = executor.server_side_dry_run((environment_manifest("staging"),))
        result = executor.execute(
            resolved_manifest(),
            expected_image_reference=REFERENCE,
            expected_digest=DIGEST,
        )

        self.assertEqual(
            [event for event, _outputs in events],
            [
                "cluster_prepared",
                "applied",
                "ready",
                "attested",
                "smoked",
                "evidence_collected",
            ],
        )
        self.assertIn(preflight.evidence_path, result.evidence_paths)
        self.assertIn("kubernetes/deployment.json", result.evidence_paths)
        self.assertIn("kubernetes/rollback.json", result.evidence_paths)

    def test_server_side_dry_run_validates_the_whole_set_before_namespace_apply(
        self,
    ) -> None:
        manifests = (
            environment_manifest("development", namespace="shared"),
            environment_manifest("staging", namespace="shared"),
        )

        with self.assertRaisesRegex(ValueError, "namespaces must be unique"):
            self.executor().server_side_dry_run(manifests)

        self.assertEqual(self.runner.calls, [])

    def test_executes_apply_attestation_and_loopback_smoke_with_one_digest(self) -> None:
        result = self.executor().execute(
            resolved_manifest(),
            expected_image_reference=REFERENCE,
            expected_digest=DIGEST,
        )

        self.assertEqual(result.identity.manifest_image_reference, REFERENCE)
        self.assertEqual(result.identity.applied_image_reference, REFERENCE)
        self.assertEqual(result.identity.pod_spec_image_reference, REFERENCE)
        self.assertEqual(result.identity.runtime_digest, DIGEST)
        self.assertEqual(result.identity.runtime_image_id, f"containerd://{DIGEST}")
        self.assertEqual(result.pod_name, "service-abc")
        self.assertEqual(result.ready_replica_count, 1)
        self.assertTrue(self.runner.forward_stopped.wait(1))
        actions = [call[7] for call in self.runner.calls]
        self.assertEqual(
            actions[:8],
            ["apply", "apply", "apply", "apply", "rollout", "get", "get", "get"],
        )
        self.assertIn("--dry-run=server", self.runner.calls[0])
        self.assertIn("namespace-bootstrap.yaml", self.runner.calls[0][-3])
        self.assertIn("--dry-run=server", self.runner.calls[2])
        self.assertIn("port-forward", actions)
        forward_call = next(
            call for call in self.runner.calls if call[7] == "port-forward"
        )
        self.assertIn(":8080", forward_call)
        self.assertNotIn("45123:8080", forward_call)
        self.assertEqual([call[2] for call in self.http.calls], ["/health", "/ready"])
        self.assertEqual(
            self.store.path("kubernetes/resolved.yaml").read_text(encoding="utf-8"),
            resolved_manifest().content,
        )
        deployment = json.loads(
            self.store.path("kubernetes/deployment.json").read_text(encoding="utf-8")
        )
        self.assertEqual(deployment["identity"]["runtimeDigest"], DIGEST)
        self.assertEqual(deployment["rollbackResult"], "PASSED")
        self.assertEqual(deployment["finalRevision"], "3")
        self.assertEqual(
            deployment["appliedServicePath"], "kubernetes/applied-service.json"
        )
        rollback = json.loads(
            self.store.path("kubernetes/rollback.json").read_text(encoding="utf-8")
        )
        self.assertTrue(rollback["failureObserved"])
        self.assertEqual(rollback["finalDigest"], DIGEST)
        self.assertEqual(result.rollback_path, "kubernetes/rollback.json")
        failure_revision = yaml.safe_load(
            self.store.path("kubernetes/rollback-failure.yaml").read_text(
                encoding="utf-8"
            )
        )
        failure_container = failure_revision["spec"]["template"]["spec"][
            "containers"
        ][0]
        self.assertEqual(failure_container["image"], REFERENCE)
        self.assertEqual(
            failure_container["readinessProbe"]["httpGet"]["path"],
            "/__devops-stack-intentional-readiness-failure__",
        )
        observation = json.loads(
            self.store.path("kubernetes/rollback-observation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(observation["command"]["category"], "nonzero")
        rollback_actions = [call[7:9] for call in self.runner.calls]
        self.assertIn(("rollout", "undo"), rollback_actions)
        smoke = self.store.path("kubernetes/smoke.json").read_text(encoding="utf-8")
        self.assertNotIn("should-redact", smoke)
        self.assertIn("<redacted>", smoke)

    def test_rejects_mutable_manifest_and_applied_mismatch_before_smoke(self) -> None:
        mutable = resolved_manifest("127.0.0.1:49153/team/service:latest")
        with self.assertRaises(KubernetesExecutionError) as mutable_error:
            self.executor().execute(
                mutable,
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )
        self.assertEqual(mutable_error.exception.stage, "manifest-validation")
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.http.calls, [])

        self.runner.applied_reference = OTHER_REFERENCE
        with self.assertRaises(KubernetesExecutionError) as mismatch:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )
        self.assertEqual(mismatch.exception.code, "WORKLOAD_IMAGE_MISMATCH")
        self.assertEqual(
            mismatch.exception.identity.applied_image_reference, OTHER_REFERENCE
        )
        self.assertFalse(self.runner.forward_started.is_set())
        self.assertEqual(self.http.calls, [])

    def test_rejects_runtime_digest_mismatch_before_port_forward(self) -> None:
        self.runner.runtime_image_id = f"containerd://{OTHER_DIGEST}"

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "RUNTIME_DIGEST_MISMATCH")
        self.assertEqual(raised.exception.identity.runtime_digest, OTHER_DIGEST)
        self.assertFalse(self.runner.forward_started.is_set())
        self.assertEqual(self.http.calls, [])

    def test_rejects_applied_service_target_port_drift_before_smoke(self) -> None:
        self.runner.service_target_port = 9090

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "SERVICE_TARGET_PORT_MISMATCH")
        self.assertFalse(self.runner.forward_started.is_set())
        self.assertEqual(self.http.calls, [])

    def test_rejects_truncated_kubectl_json_before_parsing_or_smoke(self) -> None:
        self.runner.pod_output_truncated = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "KUBECTL_OUTPUT_TRUNCATED")
        self.assertEqual(raised.exception.stage, "runtime-attestation")
        self.assertFalse(self.runner.forward_started.is_set())
        self.assertEqual(self.http.calls, [])

    def test_rollout_failure_collects_bounded_diagnostics(self) -> None:
        self.runner.rollout_failure = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        error = raised.exception
        self.assertEqual(error.code, "KUBECTL_COMMAND_FAILED")
        self.assertEqual(error.stage, "rollout")
        self.assertEqual(
            set(error.diagnostics_paths),
            {
                "diagnostics/rollout-command.txt",
                "diagnostics/events.json",
                "diagnostics/pod-logs.txt",
            },
        )
        failure = self.store.path("diagnostics/rollout-command.txt").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("rollout-secret", failure)
        self.assertIn("<redacted>", failure)
        self.assertFalse(self.runner.forward_started.is_set())

    def test_http_failure_still_cancels_port_forward(self) -> None:
        self.http.statuses["/ready"] = 503

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "SMOKE_HTTP_FAILED")
        self.assertTrue(self.runner.forward_started.is_set())
        self.assertTrue(self.runner.forward_stopped.wait(1))

    def test_http_transport_error_is_typed_and_cancels_port_forward(self) -> None:
        self.http.failure_path = "/ready"

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "SMOKE_HTTP_REQUEST_FAILED")
        self.assertTrue(self.runner.forward_started.is_set())
        self.assertTrue(self.runner.forward_stopped.wait(1))

    def test_wrong_port_readiness_cannot_accept_a_foreign_loopback_service(self) -> None:
        self.runner.forward_readiness = (
            "Forwarding from 127.0.0.1:45123 -> 9090\n"
        )

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "PORT_FORWARD_READINESS_INVALID")
        self.assertEqual(self.http.calls, [])
        self.assertTrue(self.runner.forward_stopped.wait(1))

    def test_malformed_port_forward_readiness_is_rejected(self) -> None:
        self.runner.forward_readiness = (
            "Forwarding from localhost:not-a-port -> 8080\n"
        )

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "PORT_FORWARD_READINESS_INVALID")
        self.assertEqual(self.http.calls, [])

    def test_port_forward_cancellation_is_typed_and_reaped(self) -> None:
        token = CancellationToken()
        token.cancel()
        self.runner.cancellation_token = token

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "PORT_FORWARD_FAILED")
        self.assertIsNotNone(raised.exception.process_result)
        self.assertEqual(
            raised.exception.process_result.error_category,
            ProcessErrorCategory.CANCELLED,
        )
        self.assertTrue(self.runner.forward_stopped.wait(1))

    def test_port_forward_cleanup_failure_is_not_hidden(self) -> None:
        self.runner.forward_cleanup_succeeds = False

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "PORT_FORWARD_CLEANUP_FAILED")
        self.assertTrue(self.runner.forward_stopped.wait(1))

    def test_rollback_requires_observed_failure_before_undo(self) -> None:
        self.runner.rollback_failure_observed = False

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "ROLLBACK_FAILURE_NOT_OBSERVED")
        self.assertFalse(self.runner.rollback_undone)
        observation = json.loads(
            self.store.path("kubernetes/rollback-observation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(observation["failureObserved"])

    def test_rollback_undo_and_recovery_failures_are_typed(self) -> None:
        self.runner.rollback_undo_failure = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "ROLLBACK_UNDO_FAILED")
        self.assertTrue(
            self.store.path("kubernetes/rollback-observation.json").is_file()
        )

    def test_rollback_recovery_must_roll_out_and_keep_the_original_digest(self) -> None:
        self.runner.rollback_recovery_failure = True

        with self.assertRaises(KubernetesExecutionError) as rollout_error:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(rollout_error.exception.code, "ROLLBACK_RECOVERY_FAILED")

    def test_rollback_rejects_a_changed_runtime_digest(self) -> None:
        self.runner.restored_runtime_image_id = f"containerd://{OTHER_DIGEST}"

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.executor().execute(
                resolved_manifest(),
                expected_image_reference=REFERENCE,
                expected_digest=DIGEST,
            )

        self.assertEqual(raised.exception.code, "RUNTIME_DIGEST_MISMATCH")
        self.assertEqual(raised.exception.stage, "rollback")
        self.assertEqual(raised.exception.identity.runtime_digest, OTHER_DIGEST)


if __name__ == "__main__":
    unittest.main()
