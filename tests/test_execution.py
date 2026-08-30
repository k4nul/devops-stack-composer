from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.build_once import BuildResult, PlatformDescriptor
from devops_stack_composer.composition import Composition
from devops_stack_composer.config import load_config
from devops_stack_composer.execution import (
    ExecutionError,
    ExecutionOptions,
    ExecutionOrchestrator,
    vulnerability_policy_from_model,
)
from devops_stack_composer.execution_bundle import verify_execution_bundle
from devops_stack_composer.evidence_bundle import verify_evidence_bundle
from devops_stack_composer.execution_models import StageStatus, SupplyChainEvidence
from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.execution_state import ExecutionJournal, ExecutionState
from devops_stack_composer.kubernetes_execution import (
    HttpSmokeResult,
    KubernetesArtifactIdentity,
    KubernetesExecutionError,
    KubernetesExecutionResult,
    KubernetesPreflightResult,
)
from devops_stack_composer.kubernetes_runtime import ResolvedKubernetesManifest
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"
REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
CONFIG_DIGEST = "sha256:" + "c" * 64
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def composition(project: Path) -> Composition:
    loaded = load_config(CONFIG)
    loaded = replace(
        loaded,
        model=replace(loaded.model, architectures=("linux/amd64",)),
    )
    lock = TemplateLock.load(ROOT / "templates.lock.json")
    sources = {
        key: SourceResolution(
            key=key,
            path=project,
            origin="fixture",
            commit=lock.pin(key).commit,
            remote=lock.pin(key).repository,
            matches_lock=True,
        )
        for key in ("docker", "jenkins", "kubernetes")
    }
    artifacts = (
        GeneratedArtifact(
            "docker/Dockerfile",
            "FROM scratch\n",
            origins=("$.build",),
        ),
        GeneratedArtifact(
            "docker/Dockerfile.dockerignore",
            ".git\n",
            origins=("$.build",),
        ),
        GeneratedArtifact(
            "jenkins/Jenkinsfile",
            "pipeline {}\n",
            origins=("$.ci",),
        ),
    )
    results = tuple(
        AdapterResult(
            adapter=key,
            adapter_version=lock.pin(key).adapter_version,
            template_commit=lock.pin(key).commit,
            artifacts=tuple(
                artifact
                for artifact in artifacts
                if artifact.path.startswith("k8s/" if key == "kubernetes" else f"{key}/")
            ),
            contract=loaded.model.contract(),
        )
        for key in ("docker", "jenkins", "kubernetes")
    )
    validation = ValidationReport(
        (
            CheckResult(
                "fixture",
                ValidationStatus.PASSED,
                "executable fixture validation passed",
            ),
        )
    )
    return Composition(project, loaded, lock, sources, results, artifacts, validation)


def kind_composition(project: Path) -> Composition:
    value = composition(project)
    model = replace(
        value.loaded_config.model,
        registry={
            "mode": "ephemeral-local",
            "host": "localhost",
            "repository": value.loaded_config.model.image_repository,
            "insecureLocalhostOnly": True,
        },
    )
    return replace(value, loaded_config=replace(value.loaded_config, model=model))


def resolved_manifest(_artifacts, _model, environment, immutable_reference):
    content = f"apiVersion: v1\nkind: List\nmetadata:\n  name: {environment}\n"
    return ResolvedKubernetesManifest(
        environment=environment,
        namespace=f"sample-api-{environment}",
        immutable_image_reference=immutable_reference,
        content=content,
        sha256=hashlib.sha256(content.encode()).hexdigest(),
        resource_ids=(f"v1/List//{environment}",),
    )


class FakeBuildExecutor:
    def __init__(self) -> None:
        self.execute_count = 0
        self.tag_checks = 0

    def execute(self, request):
        self.execute_count += 1
        request.metadata_path.write_text("{}\n", encoding="utf-8")
        request.invocation_marker.write_text("1\n", encoding="utf-8")
        return BuildResult(
            repository=request.repository,
            tag=request.tag,
            digest=DIGEST,
            media_type="application/vnd.oci.image.manifest.v1+json",
            size=123,
            config_digest=CONFIG_DIGEST,
            platforms=(
                PlatformDescriptor(
                    operating_system="linux",
                    architecture="amd64",
                    digest=DIGEST,
                    media_type="application/vnd.oci.image.manifest.v1+json",
                    size=123,
                    config_digest=CONFIG_DIGEST,
                ),
            ),
            build_invocation_count=1,
            build_metadata_path=request.metadata_path,
            command=("docker", "buildx", "build"),
            stdout=b"built\n",
            stderr=b"",
        )

    def verify_tag_unchanged(self, result, *, project, environment=None):
        self.tag_checks += 1


class FakeSupplyChainGenerator:
    def generate(self, *, run_root, artifact, policy, **kwargs):
        files = {
            "sbom.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
            "vulnerabilities.json": b'{"SchemaVersion":2,"Results":[]}\n',
            "provenance.json": b'{"_type":"https://in-toto.io/Statement/v1"}\n',
        }
        for relative, payload in files.items():
            (run_root / relative).write_bytes(payload)
        return SupplyChainEvidence(
            artifact_digest=artifact.manifest_digest,
            sbom_path="sbom.spdx.json",
            sbom_format="spdx-json",
            sbom_hash=hashlib.sha256(files["sbom.spdx.json"]).hexdigest(),
            sbom_generator="syft-1.51.1",
            vulnerability_report_path="vulnerabilities.json",
            vulnerability_report_hash=hashlib.sha256(
                files["vulnerabilities.json"]
            ).hexdigest(),
            scanner_name="trivy",
            scanner_version="0.74.0",
            scanner_database_metadata={"Version": 2},
            policy_result={"passed": True},
            provenance_path="provenance.json",
            provenance_hash=hashlib.sha256(files["provenance.json"]).hexdigest(),
            provenance_type="https://slsa.dev/provenance/v1",
            attestation_subject=artifact.immutable_image_reference,
            verification_status=(
                "CHECKSUM_ONLY_FILE_EVIDENCE:signature=false,attachment=false,crypto=false"
            ),
            evidence_generation_time="2026-08-30T12:00:00Z",
        )


class FakeRegistryHandle:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.name = "fake-registry"
        self.container_id = "d" * 64
        self.host_port = 5001

    def to_dict(self):
        return {
            "runId": self.run_id,
            "name": self.name,
            "containerId": self.container_id,
            "hostPort": self.host_port,
        }


class FakeRegistry:
    def __init__(self, run_id: str) -> None:
        self.handle = FakeRegistryHandle(run_id)
        self.start_count = 0
        self.cleanup_count = 0
        self.cleanup_error: BaseException | None = None

    def start(self):
        self.start_count += 1
        return self.handle

    def logs(self):
        return "registry diagnostics"

    def cleanup(self):
        self.cleanup_count += 1
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return True


class FakeRegistryFactory:
    def __init__(self) -> None:
        self.calls = 0
        self.instance: FakeRegistry | None = None
        self.cleanup_error: BaseException | None = None

    def __call__(self, run_id: str):
        self.calls += 1
        self.instance = FakeRegistry(run_id)
        self.instance.cleanup_error = self.cleanup_error
        return self.instance


class FakeKindHandle:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.name = "fake-kind"

    def to_dict(self):
        return {
            "runId": self.run_id,
            "name": self.name,
            "nodeImage": "fake@sha256:" + "e" * 64,
            "nodes": [],
        }


class FakeKindCluster:
    def __init__(self, run_id: str) -> None:
        self.handle = FakeKindHandle(run_id)
        self.kubeconfig_path = Path("/private/fake-kubeconfig")
        self.diagnostics = "kind diagnostics"
        self.create_count = 0
        self.destroy_count = 0
        self.detach_count = 0
        self.destroy_error: BaseException | None = None

    def create(self):
        self.create_count += 1
        return self.handle

    def configure_local_registry(self, registry):
        return None

    def destroy(self):
        self.destroy_count += 1
        if self.destroy_error is not None:
            raise self.destroy_error
        return True

    def detach(self):
        self.detach_count += 1


class FakeKindFactory:
    def __init__(self) -> None:
        self.calls = 0
        self.instance: FakeKindCluster | None = None
        self.destroy_error: BaseException | None = None

    def __call__(self, run_id: str):
        self.calls += 1
        self.instance = FakeKindCluster(run_id)
        self.instance.destroy_error = self.destroy_error
        return self.instance


class FailingKubernetesExecutor:
    def __init__(
        self,
        root: Path,
        *,
        code: str = "READINESS_PROBE_FAILED",
        stage: str = "readiness",
        diagnostics: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.root = root
        self.code = code
        self.stage = stage
        self.diagnostics = diagnostics
        self.execute_count = 0

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def server_side_dry_run(self, manifests):
        selected = tuple(manifests)
        relative = "kubernetes/server-side-dry-run.json"
        self._write(relative, '{"passed":true}\n')
        return KubernetesPreflightResult(
            tuple(manifest.environment for manifest in selected),
            tuple(manifest.namespace for manifest in selected),
            relative,
        )

    def execute(self, manifest, *, expected_image_reference, expected_digest):
        self.execute_count += 1
        for relative, content in self.diagnostics:
            self._write(relative, content)
        raise KubernetesExecutionError(
            self.code,
            self.stage,
            "the requested endpoint did not become ready",
            identity=KubernetesArtifactIdentity(
                expected_image_reference,
                expected_digest,
                manifest_image_reference=manifest.immutable_image_reference,
            ),
            diagnostics_paths=tuple(relative for relative, _ in self.diagnostics),
        )


class SuccessfulKubernetesExecutor(FailingKubernetesExecutor):
    def execute(self, manifest, *, expected_image_reference, expected_digest):
        self.execute_count += 1
        paths = {
            "kubernetes/resolved.yaml": manifest.content,
            "kubernetes/applied-deployment.json": "{}\n",
            "kubernetes/applied-service.json": "{}\n",
            "kubernetes/runtime-pods.json": "{}\n",
            "kubernetes/smoke.json": "{}\n",
            "kubernetes/rollback.json": "{}\n",
            "kubernetes/deployment.json": "{}\n",
        }
        for relative, content in paths.items():
            self._write(relative, content)
        identity = KubernetesArtifactIdentity(
            expected_image_reference,
            expected_digest,
            manifest_image_reference=expected_image_reference,
            applied_image_reference=expected_image_reference,
            pod_spec_image_reference=expected_image_reference,
            runtime_image_id=f"containerd://{expected_digest}",
            runtime_digest=expected_digest,
        )
        return KubernetesExecutionResult(
            identity=identity,
            namespace=manifest.namespace,
            deployment_name="sample-api",
            service_name="sample-api",
            pod_name="sample-api-abc",
            ready_replica_count=1,
            manifest_path="kubernetes/resolved.yaml",
            applied_deployment_path="kubernetes/applied-deployment.json",
            applied_service_path="kubernetes/applied-service.json",
            runtime_pods_path="kubernetes/runtime-pods.json",
            rollback_path="kubernetes/rollback.json",
            final_revision="3",
            health=HttpSmokeResult("/health", 200, '{"status":"healthy"}'),
            readiness=HttpSmokeResult("/ready", 200, '{"status":"ready"}'),
            # The real executor returns a complete inventory which overlaps the
            # legacy named path fields. The orchestrator must deduplicate it.
            evidence_paths=tuple(paths),
        )


def schema_success(command, **kwargs):
    return subprocess.CompletedProcess(command, 0, stdout="schema passed\n", stderr="")


class ExecutionTests(unittest.TestCase):
    def orchestrator(
        self,
        *,
        build_executor=None,
        supply_chain_generator=None,
        registry_factory=None,
        kind_factory=None,
        kubernetes_executor=None,
        schema_command_runner=None,
        tool_resolver=None,
    ):
        return ExecutionOrchestrator(
            build_executor=build_executor,
            supply_chain_generator=supply_chain_generator,
            **(
                {"registry_factory": registry_factory}
                if registry_factory is not None
                else {}
            ),
            **({"kind_factory": kind_factory} if kind_factory is not None else {}),
            kubernetes_executor=kubernetes_executor,
            **(
                {"schema_command_runner": schema_command_runner}
                if schema_command_runner is not None
                else {}
            ),
            tool_resolver=tool_resolver or (lambda name: f"/tools/{name}"),
            source_revision_resolver=lambda project: REVISION,
            clock=lambda: NOW,
        )

    @staticmethod
    def stage(result, stage_id: str):
        return next(stage for stage in result.run.stage_results if stage.stage_id == stage_id)

    def test_static_profile_closes_a_verifiable_run_without_external_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            result = self.orchestrator().execute(
                composition(project),
                ExecutionOptions(
                    profile="static",
                    run_id="20260830T120000Z-0123456789ab",
                ),
            )

            self.assertTrue(result.passed)
            self.assertIsNone(result.run.artifact_record)
            self.assertEqual(
                [stage.status.value for stage in result.run.stage_results],
                ["PASSED", "PASSED", "PASSED", "PASSED"],
            )
            checksums = result.store.verify_checksums()
            self.assertIn("execution-plan.json", checksums)
            self.assertIn("execution-evidence.json", checksums)
            self.assertIn("report.md", checksums)
            self.assertNotIn("SHA256SUMS", checksums)
            fresh = verify_execution_bundle(
                project,
                result.run.run_id,
            )
            self.assertTrue(fresh.passed)
            self.assertIsNone(fresh.authoritative_digest)

    def test_supply_chain_builds_once_rechecks_tag_and_closes_same_digest(self) -> None:
        build = FakeBuildExecutor()
        supply = FakeSupplyChainGenerator()
        with tempfile.TemporaryDirectory() as directory:
            result = self.orchestrator(
                build_executor=build,
                supply_chain_generator=supply,
            ).execute(
                composition(Path(directory)),
                ExecutionOptions(
                    profile="supply-chain",
                    image_tag="run-test",
                    run_id="20260830T120000Z-abcdef012345",
                ),
            )

            self.assertTrue(result.passed)
            self.assertEqual(build.execute_count, 1)
            self.assertEqual(build.tag_checks, 2)
            self.assertEqual(result.run.artifact_record.manifest_digest, DIGEST)
            self.assertEqual(result.verification.authoritative_digest, DIGEST)
            self.assertEqual(
                result.run.stage_results[-1].stage_id,
                "cleanup",
            )
            self.assertEqual(result.run.stage_results[-1].status.value, "PASSED")
            self.assertEqual(result.store.verify_checksums()["artifact.json"], hashlib.sha256(
                result.store.path("artifact.json").read_bytes()
            ).hexdigest())

    def test_multi_platform_execution_fails_before_any_build(self) -> None:
        build = FakeBuildExecutor()
        value = composition(Path(tempfile.mkdtemp()))
        model = replace(value.loaded_config.model, architectures=("linux/amd64", "linux/arm64"))
        loaded = replace(value.loaded_config, model=model)
        value = replace(value, loaded_config=loaded)

        with self.assertRaisesRegex(
            ExecutionError,
            "MULTI_PLATFORM_EXECUTION_UNSUPPORTED",
        ):
            self.orchestrator(build_executor=build).execute(
                value,
                ExecutionOptions(profile="supply-chain"),
            )

        self.assertEqual(build.execute_count, 0)

    def test_required_tool_preflight_blocks_before_registry_or_build_side_effects(self) -> None:
        build = FakeBuildExecutor()
        registry_factory = FakeRegistryFactory()
        with tempfile.TemporaryDirectory() as directory:
            result = self.orchestrator(
                build_executor=build,
                supply_chain_generator=FakeSupplyChainGenerator(),
                registry_factory=registry_factory,
                tool_resolver=(
                    lambda name: None if name == "kubectl" else f"/tools/{name}"
                ),
            ).execute(
                kind_composition(Path(directory)),
                ExecutionOptions(
                    profile="kind-e2e",
                    run_id="20260830T120000Z-111111111111",
                ),
            )

            self.assertEqual(
                result.run.final_status,
                StageStatus.BLOCKED_MISSING_REQUIRED_TOOL,
            )
            self.assertEqual(
                self.stage(result, "registry-lifecycle").status,
                StageStatus.BLOCKED_MISSING_REQUIRED_TOOL,
            )
            self.assertIn("REQUIRED_TOOL_MISSING", result.run.failure_reason)
            self.assertIn("kubectl", result.run.failure_reason)
            self.assertEqual(registry_factory.calls, 0)
            self.assertEqual(build.execute_count, 0)
            self.assertFalse(result.store.path("registry-ownership.json").exists())
            self.assertEqual(
                [stage.stage_id for stage in result.run.stage_results],
                [
                    "config-schema",
                    "template-lock",
                    "adapter-contracts",
                    "generated-files",
                    "registry-lifecycle",
                ],
            )
            self.assertFalse(result.bundle_verification.execution_succeeded)
            verify_evidence_bundle(result.store)

    def test_kubernetes_failure_persists_diagnostics_and_truthful_stage_progress(self) -> None:
        registry_factory = FakeRegistryFactory()
        kind_factory = FakeKindFactory()
        with tempfile.TemporaryDirectory() as directory, patch(
            "devops_stack_composer.execution.render_resolved_environment",
            side_effect=resolved_manifest,
        ):
            project = Path(directory)
            run_id = "20260830T120000Z-222222222222"
            kubernetes = FailingKubernetesExecutor(
                project / ".devops-stack" / "runs" / run_id,
                diagnostics=(
                    (
                        "kubernetes/diagnostics/events.txt",
                        "bounded readiness diagnostics\n",
                    ),
                ),
            )
            result = self.orchestrator(
                build_executor=FakeBuildExecutor(),
                supply_chain_generator=FakeSupplyChainGenerator(),
                registry_factory=registry_factory,
                kind_factory=kind_factory,
                kubernetes_executor=kubernetes,
                schema_command_runner=schema_success,
            ).execute(
                kind_composition(project),
                ExecutionOptions(
                    profile="kind-e2e",
                    run_id=run_id,
                ),
            )

            for stage_id in (
                "server-side-dry-run",
                "deployment",
                "rollout",
                "pod-image",
                "health",
            ):
                self.assertEqual(self.stage(result, stage_id).status, StageStatus.PASSED)
            self.assertEqual(
                self.stage(result, "readiness").status,
                StageStatus.FAILED,
            )
            self.assertNotIn(
                "rollback", [stage.stage_id for stage in result.run.stage_results]
            )
            self.assertIn("READINESS_PROBE_FAILED", result.run.failure_reason)
            self.assertEqual(
                result.store.path("kubernetes/diagnostics/events.txt").read_text(
                    encoding="utf-8"
                ),
                "bounded readiness diagnostics\n",
            )
            error_record = json.loads(
                result.store.path("kubernetes/execution-error.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(error_record["code"], "READINESS_PROBE_FAILED")
            self.assertEqual(error_record["stage"], "readiness")
            self.assertEqual(error_record["failureStage"], "readiness")
            self.assertEqual(
                error_record["completedStages"],
                [
                    "server-side-dry-run",
                    "deployment",
                    "rollout",
                    "pod-image",
                    "health",
                ],
            )
            self.assertEqual(kind_factory.instance.destroy_count, 1)
            self.assertEqual(registry_factory.instance.cleanup_count, 1)
            verify_evidence_bundle(result.store)

    def test_keep_environment_on_failure_retains_only_a_failed_run(self) -> None:
        registry_factory = FakeRegistryFactory()
        kind_factory = FakeKindFactory()
        with tempfile.TemporaryDirectory() as directory, patch(
            "devops_stack_composer.execution.render_resolved_environment",
            side_effect=resolved_manifest,
        ):
            project = Path(directory)
            run_id = "20260830T120000Z-333333333333"
            result = self.orchestrator(
                build_executor=FakeBuildExecutor(),
                supply_chain_generator=FakeSupplyChainGenerator(),
                registry_factory=registry_factory,
                kind_factory=kind_factory,
                kubernetes_executor=FailingKubernetesExecutor(
                    project / ".devops-stack" / "runs" / run_id
                ),
                schema_command_runner=schema_success,
            ).execute(
                kind_composition(project),
                ExecutionOptions(
                    profile="kind-e2e",
                    run_id=run_id,
                    keep_environment_on_failure=True,
                ),
            )

            self.assertFalse(result.passed)
            self.assertTrue(result.retained_resources)
            self.assertEqual(kind_factory.instance.destroy_count, 0)
            self.assertEqual(kind_factory.instance.detach_count, 1)
            self.assertEqual(registry_factory.instance.cleanup_count, 0)
            self.assertEqual(
                ExecutionJournal.open(result.store).current_state,
                ExecutionState.FAILED,
            )
            verify_evidence_bundle(result.store)

    def test_kind_success_maps_managed_runtime_identity_into_closed_evidence(self) -> None:
        registry_factory = FakeRegistryFactory()
        kind_factory = FakeKindFactory()
        with tempfile.TemporaryDirectory() as directory, patch(
            "devops_stack_composer.execution.render_resolved_environment",
            side_effect=resolved_manifest,
        ):
            project = Path(directory)
            run_id = "20260830T120000Z-444444444444"
            kubernetes = SuccessfulKubernetesExecutor(
                project / ".devops-stack" / "runs" / run_id
            )
            result = self.orchestrator(
                build_executor=FakeBuildExecutor(),
                supply_chain_generator=FakeSupplyChainGenerator(),
                registry_factory=registry_factory,
                kind_factory=kind_factory,
                kubernetes_executor=kubernetes,
                schema_command_runner=schema_success,
            ).execute(
                kind_composition(project),
                ExecutionOptions(
                    profile="kind-e2e",
                    run_id=run_id,
                    keep_environment_on_failure=True,
                ),
            )

            self.assertTrue(result.passed)
            self.assertEqual(kubernetes.execute_count, 1)
            self.assertEqual(
                result.run.deployment_evidence.expected_digest,
                DIGEST,
            )
            self.assertEqual(
                result.run.deployment_evidence.actual_pod_image_id,
                f"containerd://{DIGEST}",
            )
            self.assertEqual(result.run.deployment_evidence.ready_replica_count, 1)
            self.assertEqual(
                [
                    self.stage(result, stage_id).status
                    for stage_id in (
                        "server-side-dry-run",
                        "deployment",
                        "rollout",
                        "pod-image",
                        "health",
                        "readiness",
                        "rollback",
                    )
                ],
                [StageStatus.PASSED] * 7,
            )
            self.assertEqual(kind_factory.instance.destroy_count, 1)
            self.assertEqual(registry_factory.instance.cleanup_count, 1)
            self.assertTrue(result.bundle_verification.execution_succeeded)
            self.assertTrue(result.store.path("run.json").is_file())
            self.assertTrue(result.store.path("state.json").is_file())
            self.assertFalse(result.store.path("execution-evidence.json").exists())
            self.assertEqual(
                ExecutionJournal.open(result.store).current_state,
                ExecutionState.CLEANED,
            )
            verify_evidence_bundle(result.store)

    def test_cleanup_attempts_are_independent_and_aggregate_write_and_remove_failures(self) -> None:
        registry_factory = FakeRegistryFactory()
        kind_factory = FakeKindFactory()
        registry_factory.cleanup_error = RuntimeError("registry cleanup failed")
        kind_factory.destroy_error = RuntimeError("kind destroy failed")
        original_write_text = EvidenceStore.write_text

        def failing_lifecycle_writes(store, relative, content, **kwargs):
            if relative == "diagnostics/kind-lifecycle.log":
                raise OSError("kind diagnostic write failed")
            if relative == "logs/registry.log":
                raise OSError("registry log write failed")
            return original_write_text(store, relative, content, **kwargs)

        with tempfile.TemporaryDirectory() as directory, patch(
            "devops_stack_composer.execution.render_resolved_environment",
            side_effect=resolved_manifest,
        ), patch.object(EvidenceStore, "write_text", new=failing_lifecycle_writes):
            project = Path(directory)
            run_id = "20260830T120000Z-333333333333"
            kubernetes = FailingKubernetesExecutor(
                project / ".devops-stack" / "runs" / run_id
            )
            result = self.orchestrator(
                build_executor=FakeBuildExecutor(),
                supply_chain_generator=FakeSupplyChainGenerator(),
                registry_factory=registry_factory,
                kind_factory=kind_factory,
                kubernetes_executor=kubernetes,
                schema_command_runner=schema_success,
            ).execute(
                kind_composition(project),
                ExecutionOptions(
                    profile="kind-e2e",
                    run_id=run_id,
                ),
            )

            self.assertEqual(kind_factory.instance.destroy_count, 1)
            self.assertEqual(registry_factory.instance.cleanup_count, 1)
            self.assertNotIn(
                "cleanup", [stage.stage_id for stage in result.run.stage_results]
            )
            self.assertIn("kind destroy failed", result.run.failure_reason)
            self.assertIn("registry cleanup failed", result.run.failure_reason)
            self.assertEqual(
                ExecutionJournal.open(result.store).current_state,
                ExecutionState.FAILED,
            )
            verify_evidence_bundle(result.store)

    def test_legacy_and_current_vulnerability_shapes_map_explicitly(self) -> None:
        legacy = vulnerability_policy_from_model(
            {"scan": {"enabled": True, "failOn": "high"}}
        )
        current = vulnerability_policy_from_model(
            {
                "vulnerability": {
                    "required": True,
                    "severities": ["CRITICAL"],
                    "ignoreUnfixed": True,
                    "maximumAllowed": 0,
                    "allowlist": [
                        {
                            "id": "CVE-2026-1",
                            "package": "sample",
                            "reason": "bounded exception",
                            "owner": "security",
                            "expiresAt": "2026-12-01",
                        }
                    ],
                }
            }
        )

        self.assertEqual(legacy.severities, ("HIGH", "CRITICAL"))
        self.assertFalse(legacy.ignore_unfixed)
        self.assertEqual(current.severities, ("CRITICAL",))
        self.assertEqual(current.allowlist[0].vulnerability_id, "CVE-2026-1")


if __name__ == "__main__":
    unittest.main()
