from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from typing import Any

import yaml

from devops_stack_composer.execution_models import ResolvedArtifact
from devops_stack_composer.kubernetes_execution import (
    KubernetesExecutionError,
    KubernetesExecutionRequest,
    KubernetesExecutor,
)
from devops_stack_composer.kubernetes_runtime import ResolvedKubernetesManifest


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMAGE = f"localhost:5000/team/sample@{DIGEST}"


def deployment_document(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "sample-api", "namespace": namespace},
        "spec": {
            "replicas": 2,
            "revisionHistoryLimit": 10,
            "selector": {"matchLabels": {"app.kubernetes.io/name": "sample-api"}},
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "sample-api"}},
                "spec": {
                    "containers": [
                        {
                            "name": "sample-api",
                            "image": IMAGE,
                            "ports": [{"containerPort": 8000}],
                            "livenessProbe": {"httpGet": {"path": "/health", "port": 8000}},
                            "readinessProbe": {"httpGet": {"path": "/ready", "port": 8000}},
                        }
                    ]
                },
            },
        },
    }


def resolved_manifest(environment: str) -> ResolvedKubernetesManifest:
    namespace = f"sample-{environment}"
    documents = (
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": namespace},
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "sample-api", "namespace": namespace},
            "spec": {
                "selector": {"app.kubernetes.io/name": "sample-api"},
                "ports": [{"name": "http", "port": 80, "targetPort": 8000}],
            },
        },
        deployment_document(namespace),
    )
    content = "---\n".join(
        yaml.safe_dump(document, sort_keys=False) for document in documents
    )
    return ResolvedKubernetesManifest(
        environment=environment,
        namespace=namespace,
        immutable_image_reference=IMAGE,
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        resource_ids=tuple(
            f"{document['apiVersion']}/{document['kind']}/"
            f"{document['metadata'].get('namespace', '')}/{document['metadata']['name']}"
            for document in documents
        ),
    )


def artifact() -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=IMAGE,
        repository="localhost:5000/team/sample",
        tag="run-1",
        manifest_digest=DIGEST,
        platform_digest=DIGEST,
        media_type="application/vnd.oci.image.manifest.v1+json",
        architecture="amd64",
        operating_system="linux",
        image_size=100,
        config_digest="sha256:" + "c" * 64,
        source_revision="d" * 40,
        build_plan_hash="e" * 64,
        created_by_tool_version="0.2.0",
        registry_endpoint="localhost:5000",
        build_invocation_count=1,
    )


class FixtureKubectlRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.failure_applied = False
        self.undo_attempted = False
        self.undone = False
        self.pod_digest = DIGEST
        self.pod_restart_count = 0
        self.health_failure = False
        self.readiness_failure = False
        self.intentional_rollout_succeeds = False
        self.rollback_failure = False
        self.malformed_deployment_json = False
        self.include_readiness_diagnostic = True

    def __call__(
        self, command: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(command), dict(kwargs)))
        arguments = command[4:]
        stdin = kwargs.get("input") or ""
        if arguments and arguments[0] == "apply":
            if "__devops-stack-intentional-readiness-failure__" in stdin:
                self.failure_applied = True
            return self.result(command)
        if arguments[:2] == ["rollout", "undo"]:
            self.undo_attempted = True
            if self.rollback_failure:
                return self.result(command, 1, stderr="rollback denied")
            self.undone = True
            return self.result(command, stdout="deployment.apps/sample-api rolled back\n")
        if arguments[:2] == ["rollout", "status"]:
            if self.failure_applied and not self.undone:
                if self.intentional_rollout_succeeds:
                    return self.result(command, stdout="successfully rolled out\n")
                return self.result(command, 1, stderr="timed out waiting for the condition")
            return self.result(command, stdout="successfully rolled out\n")
        if arguments[:2] == ["get", "deployment"]:
            if self.malformed_deployment_json:
                return self.result(command, stdout="{not-json")
            return self.result(command, stdout=json.dumps(self.deployment_fixture()))
        if arguments[:2] == ["get", "pods"]:
            return self.result(command, stdout=json.dumps(self.pods_fixture()))
        if arguments[:2] == ["get", "--raw"]:
            path = arguments[2]
            if path.endswith("/health"):
                if self.health_failure:
                    return self.result(command, 1, stderr="HTTP 503")
                return self.result(command, stdout='{"status":"healthy"}')
            if path.endswith("/ready"):
                if self.readiness_failure:
                    return self.result(command, 1, stderr="HTTP 503")
                return self.result(command, stdout='{"status":"ready"}')
        if arguments[:2] == ["get", "events"]:
            marker = (
                "Readiness probe failed: HTTP probe failed with statuscode: 404"
                if self.include_readiness_diagnostic
                else "deployment exceeded its progress deadline"
            )
            return self.result(
                command,
                stdout=f"{marker}\ntoken=diagnostic-secret\n/tmp/private/runtime.log\n",
            )
        if arguments and arguments[0] in {"describe", "logs"}:
            return self.result(command, stdout="bounded diagnostic\n")
        if arguments[:2] == ["get", "replicasets"]:
            return self.result(command, stdout="items: []\n")
        if arguments[:2] == ["rollout", "history"]:
            return self.result(command, stdout="REVISION  CHANGE-CAUSE\n1 <none>\n2 <none>\n")
        return self.result(command, 1, stderr=f"unexpected fixture command: {arguments!r}")

    def deployment_fixture(self) -> dict[str, Any]:
        document = deployment_document("sample-staging")
        if self.failure_applied and not self.undone:
            document["spec"]["template"]["spec"]["containers"][0][
                "readinessProbe"
            ]["httpGet"][
                "path"
            ] = "/__devops-stack-intentional-readiness-failure__"
        document["metadata"].update(
            {
                "generation": 3 if self.failure_applied else 2,
                "annotations": {
                    "deployment.kubernetes.io/revision": (
                        "3" if self.undone else "2" if self.failure_applied else "1"
                    )
                },
            }
        )
        document["status"] = {
            "observedGeneration": 3 if self.failure_applied else 2,
            "replicas": 2,
            "updatedReplicas": 2,
            "availableReplicas": 2,
            "readyReplicas": 2,
            "conditions": [{"type": "Available", "status": "True"}],
        }
        return document

    def pods_fixture(self) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [self.pod_fixture(index) for index in range(2)],
        }

    def pod_fixture(self, index: int) -> dict[str, Any]:
        return {
            "metadata": {"name": f"sample-api-fixture-{index}"},
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [
                    {
                        "name": "sample-api",
                        "ready": True,
                        "restartCount": self.pod_restart_count,
                        "imageID": f"containerd://{self.pod_digest}",
                    }
                ],
            },
        }

    @staticmethod
    def result(
        command: list[str],
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class KubernetesExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = tempfile.TemporaryDirectory()
        self.kubeconfig = Path(self.runtime.name) / "kubeconfig"
        self.kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
        os.chmod(self.kubeconfig, 0o600)
        self.runner = FixtureKubectlRunner()

    def tearDown(self) -> None:
        self.runtime.cleanup()

    def request(self, **overrides: Any) -> KubernetesExecutionRequest:
        values: dict[str, Any] = {
            "kubeconfig_path": self.kubeconfig,
            "manifests": tuple(
                resolved_manifest(environment)
                for environment in ("dev", "staging", "production")
            ),
            "environment": "staging",
            "deployment_name": "sample-api",
            "service_name": "sample-api",
            "service_port": 80,
            "health_path": "/health",
            "readiness_path": "/ready",
            "artifact": artifact(),
            "cluster_type": "kind",
            "cluster_identifier": "devops-stack-fixture",
            "run_id": "run-20260830",
            "rollout_timeout_seconds": 5,
        }
        values.update(overrides)
        return KubernetesExecutionRequest(**values)

    def execute(self):
        return KubernetesExecutor(
            command_runner=self.runner,
            command_timeout_seconds=5,
            diagnostic_timeout_seconds=5,
        ).execute(self.request())

    def test_executes_full_same_digest_success_and_recovery_flow(self) -> None:
        result = self.execute()

        self.assertEqual(
            tuple(item.environment for item in result.dry_runs),
            ("dev", "staging", "production"),
        )
        self.assertEqual(result.deployment.expected_digest, DIGEST)
        self.assertEqual(result.deployment.final_digest, DIGEST)
        self.assertEqual(result.deployment.ready_replica_count, 2)
        self.assertEqual(len(result.initial_pods), 2)
        self.assertEqual(len(result.recovered_pods), 2)
        self.assertTrue(result.intentional_failure.observed)
        self.assertTrue(self.runner.undo_attempted)
        self.assertTrue(self.runner.undone)
        dry_run_calls = [
            call
            for call, _options in self.runner.calls
            if "--dry-run=server" in call
        ]
        self.assertEqual(len(dry_run_calls), 6)
        for command, options in self.runner.calls:
            self.assertEqual(command[1:3], ["--kubeconfig", str(self.kubeconfig)])
            self.assertIs(options["shell"], False)
            self.assertIs(options["check"], False)
            self.assertTrue(options["capture_output"])
        serialized = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(str(self.kubeconfig), serialized)
        self.assertNotIn("diagnostic-secret", serialized)
        self.assertNotIn("/tmp/private", serialized)
        self.assertIn("<redacted>", serialized)
        self.assertIn("<absolute-path>", serialized)

    def test_rejects_pod_running_with_unexpected_digest(self) -> None:
        self.runner.pod_digest = OTHER_DIGEST

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "POD_IMAGE_DIGEST_MISMATCH")
        self.assertFalse(raised.exception.rollback_attempted)
        self.assertTrue(raised.exception.diagnostics)

    def test_failed_health_endpoint_stops_before_failure_revision(self) -> None:
        self.runner.health_failure = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "HEALTH_PROBE_FAILED")
        self.assertFalse(self.runner.failure_applied)
        self.assertFalse(self.runner.undo_attempted)

    def test_restarted_pod_is_not_treated_as_clean_rollout_evidence(self) -> None:
        self.runner.pod_restart_count = 1

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "POD_RESTART_OBSERVED")

    def test_intentional_rollout_must_actually_fail(self) -> None:
        self.runner.intentional_rollout_succeeds = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(
            raised.exception.code, "EXPECTED_ROLLOUT_FAILURE_NOT_OBSERVED"
        )
        self.assertTrue(raised.exception.rollback_attempted)
        self.assertTrue(raised.exception.rollback_succeeded)
        self.assertTrue(self.runner.undone)

    def test_failed_rollout_must_show_expected_readiness_cause(self) -> None:
        self.runner.include_readiness_diagnostic = False

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(
            raised.exception.code, "EXPECTED_READINESS_FAILURE_NOT_OBSERVED"
        )
        self.assertTrue(raised.exception.rollback_succeeded)

    def test_rollback_failure_preserves_redacted_diagnostics(self) -> None:
        self.runner.rollback_failure = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "ROLLBACK_FAILED")
        self.assertTrue(raised.exception.rollback_attempted)
        self.assertFalse(raised.exception.rollback_succeeded)
        serialized = json.dumps(
            [item.to_dict() for item in raised.exception.diagnostics], sort_keys=True
        )
        self.assertNotIn("diagnostic-secret", serialized)
        self.assertNotIn(str(self.kubeconfig), serialized)

    def test_malformed_kubectl_json_fails_closed(self) -> None:
        self.runner.malformed_deployment_json = True

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "MALFORMED_KUBECTL_JSON")
        self.assertEqual(raised.exception.phase, "rollout")

    def test_private_kubeconfig_permissions_are_required_before_commands(self) -> None:
        os.chmod(self.kubeconfig, 0o644)

        with self.assertRaises(KubernetesExecutionError) as raised:
            self.execute()

        self.assertEqual(raised.exception.code, "PRIVATE_KUBECONFIG_INVALID")
        self.assertEqual(self.runner.calls, [])

    def test_production_apply_requires_explicit_approval(self) -> None:
        executor = KubernetesExecutor(command_runner=self.runner)
        with self.assertRaises(KubernetesExecutionError) as raised:
            executor.execute(self.request(environment="production"))
        self.assertEqual(raised.exception.code, "PRODUCTION_APPROVAL_REQUIRED")
        self.assertEqual(self.runner.calls, [])

    def test_tampered_manifest_is_rejected_by_request(self) -> None:
        manifests = list(self.request().manifests)
        manifests[0] = ResolvedKubernetesManifest(
            environment=manifests[0].environment,
            namespace=manifests[0].namespace,
            immutable_image_reference=manifests[0].immutable_image_reference,
            content=manifests[0].content + "\n",
            sha256=manifests[0].sha256,
            resource_ids=manifests[0].resource_ids,
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.request(manifests=tuple(manifests))


if __name__ == "__main__":
    unittest.main()
