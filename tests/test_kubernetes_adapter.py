from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from devops_stack_composer.adapters.base import GeneratedArtifact
from devops_stack_composer.adapters.kubernetes import (
    KubernetesAdapter,
    sanitize_upstream_payload,
    validate_yaml_artifacts,
)
from devops_stack_composer.config import load_config, parse_config
from devops_stack_composer.model import normalize_config
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationStatus


CONFIG_FIXTURE = Path(__file__).parent / "fixtures" / "configs" / "valid.yaml"


class FakeRunner:
    def __init__(
        self,
        source_root: Path,
        *,
        generation: int = 0,
        schema_tools_missing: bool = False,
    ) -> None:
        self.source_root = source_root
        self.generation = generation
        self.schema_tools_missing = schema_tools_missing
        self.calls: list[tuple[tuple[str, ...], dict]] = []
        self.copied_source_contained_out = False

    def __call__(self, command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append((tuple(command), kwargs))
        if command[0] != "pwsh":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="apiVersion: v1\nkind: Namespace\nmetadata:\n  name: rendered\n",
                stderr="",
            )

        script = Path(command[command.index("-File") + 1]).name
        isolated_root = Path(kwargs["cwd"])
        self.copied_source_contained_out = (
            self.copied_source_contained_out or (isolated_root / "out").exists()
        )
        if script == "render-platform-assets.ps1":
            output = Path(command[command.index("-OutputPath") + 1])
            manifest = output / "k8s" / "100_namespace" / "namespace.yaml"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: rendered\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="Rendered profile 'minimal-application' to an ephemeral path\n",
                stderr="",
            )
        validator_output = {
            "validate-rendered-bundle.ps1": (
                "WARNING: Neither kubeconform nor kubectl is installed. "
                "Skipping rendered manifest validation.\n"
                "Rendered manifest structural preflight completed successfully.\n"
                if self.schema_tools_missing
                else "Rendered manifest validator: fake\n"
                "Rendered manifest validation completed successfully.\n"
            ),
            "validate-kubernetes-security-baseline.ps1": (
                "Kubernetes security baseline findings: high=0, medium=1, low=1\n"
            ),
            "check-placeholders.ps1": "Found 4 placeholder matches.\n",
        }
        if script in validator_output:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=validator_output[script],
                stderr="",
            )

        common = {
            "GeneratedAt": f"2099-01-01T00:00:{self.generation:02d}",
            "RepoRoot": str(isolated_root),
        }
        payloads = {
            "show-profile-catalog.ps1": {
                **common,
                "Profiles": [
                    {
                        "Name": "minimal-application",
                        "ExampleApplications": ["nginx-web", "whoami"],
                    }
                ],
            },
            "show-environment-preset-plan.ps1": {
                **common,
                "Presets": [
                    {
                        "Name": "dev",
                        "PresetPath": str(
                            isolated_root / "config/environments/dev.psd1"
                        ),
                    }
                ],
            },
            "show-render-matrix.ps1": {
                **common,
                "Entries": [
                    {
                        "Name": "minimal-application",
                        "ValuesFileResolved": "/tmp/private/platform-values.env",
                    }
                ],
            },
            "show-platform-plan.ps1": {
                "Profile": "minimal-application",
                "Applications": ["nginx-web"],
                "Components": [{"Directory": "100_namespace"}],
            },
        }
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(payloads[script]),
            stderr="",
        )


class KubernetesAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = load_config(CONFIG_FIXTURE).model
        self.source_temporary = tempfile.TemporaryDirectory(
            prefix="kubernetes-adapter-source-"
        )
        self.addCleanup(self.source_temporary.cleanup)
        self.source_root = Path(self.source_temporary.name) / "template"
        scripts = self.source_root / "scripts"
        scripts.mkdir(parents=True)
        for script in (
            "show-profile-catalog.ps1",
            "show-environment-preset-plan.ps1",
            "show-render-matrix.ps1",
            "show-platform-plan.ps1",
            "render-platform-assets.ps1",
            "validate-rendered-bundle.ps1",
            "validate-kubernetes-security-baseline.ps1",
            "check-placeholders.ps1",
        ):
            (scripts / script).write_text("# fake fixture\n", encoding="utf-8")
        values = self.source_root / "config" / "platform-values.env.example"
        values.parent.mkdir(parents=True)
        values.write_text("BASE_DOMAIN=example.com\n", encoding="utf-8")
        source_out = self.source_root / "out"
        source_out.mkdir()
        (source_out / "must-not-copy.txt").write_text("sentinel\n", encoding="utf-8")
        self.source = SourceResolution(
            key="kubernetes",
            path=self.source_root,
            origin="test",
            commit="2" * 40,
            remote="https://example.invalid/k8s-platform-template.git",
            matches_lock=True,
        )
        self.runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            self.result = KubernetesAdapter(
                self.source,
                runner=self.runner,
            ).render(self.model)

    def yaml_artifact(self, path: str) -> dict:
        document = yaml.safe_load(self.result.artifact(path).content)
        self.assertIsInstance(document, dict)
        return document

    def test_all_environment_overlays_and_base_resources_render(self) -> None:
        paths = [artifact.path for artifact in self.result.artifacts]

        self.assertEqual(paths, sorted(paths))
        for base_name in (
            "serviceaccount.yaml",
            "deployment.yaml",
            "service.yaml",
            "configmap.yaml",
            "kustomization.yaml",
        ):
            self.assertIn(f"k8s/base/{base_name}", paths)
        self.assertNotIn("k8s/base/namespace.yaml", paths)
        for environment in ("dev", "staging", "production"):
            for name in (
                "namespace.yaml",
                "deployment.yaml",
                "service.yaml",
                "configmap.yaml",
                "kustomization.yaml",
            ):
                self.assertIn(f"k8s/overlays/{environment}/{name}", paths)
            kustomization = self.yaml_artifact(
                f"k8s/overlays/{environment}/kustomization.yaml"
            )
            self.assertEqual(
                kustomization["namespace"],
                self.model.environment(environment).namespace,
            )
            self.assertEqual(
                kustomization["resources"],
                ["../../base", "namespace.yaml"],
            )
            namespace = self.yaml_artifact(
                f"k8s/overlays/{environment}/namespace.yaml"
            )
            self.assertEqual(namespace["kind"], "Namespace")
            self.assertEqual(
                namespace["metadata"]["name"],
                self.model.environment(environment).namespace,
            )

    def test_each_environment_preserves_workload_and_service_contracts(self) -> None:
        for name in ("dev", "staging", "production"):
            with self.subTest(environment=name):
                expected = self.model.environment(name)
                deployment = self.yaml_artifact(
                    f"k8s/overlays/{name}/deployment.yaml"
                )
                service = self.yaml_artifact(f"k8s/overlays/{name}/service.yaml")
                container = deployment["spec"]["template"]["spec"]["containers"][0]

                self.assertEqual(deployment["$patch"], "replace")
                self.assertEqual(deployment["spec"]["replicas"], expected.replicas)
                self.assertEqual(
                    deployment["spec"]["revisionHistoryLimit"],
                    expected.rollback["revisionHistoryLimit"],
                )
                self.assertEqual(
                    deployment["spec"]["strategy"]["type"],
                    expected.rollout["strategy"],
                )
                self.assertEqual(
                    deployment["spec"]["strategy"]["rollingUpdate"],
                    {
                        "maxUnavailable": expected.rollout["maxUnavailable"],
                        "maxSurge": expected.rollout["maxSurge"],
                    },
                )
                self.assertEqual(container["image"], self.model.image_reference)
                self.assertIn("__IMAGE_TAG__", container["image"])
                self.assertEqual(
                    container["ports"][0]["containerPort"],
                    expected.container_port,
                )
                self.assertEqual(
                    container["livenessProbe"]["httpGet"],
                    {
                        "path": expected.health_path,
                        "port": expected.container_port,
                        "scheme": "HTTP",
                    },
                )
                self.assertEqual(
                    container["readinessProbe"]["httpGet"],
                    {
                        "path": expected.readiness_path,
                        "port": expected.container_port,
                        "scheme": "HTTP",
                    },
                )
                self.assertEqual(
                    container["livenessProbe"]["initialDelaySeconds"],
                    expected.health_initial_delay_seconds,
                )
                self.assertEqual(
                    container["livenessProbe"]["periodSeconds"],
                    expected.health_period_seconds,
                )
                self.assertEqual(
                    container["readinessProbe"]["initialDelaySeconds"],
                    expected.readiness_initial_delay_seconds,
                )
                self.assertEqual(
                    container["readinessProbe"]["periodSeconds"],
                    expected.readiness_period_seconds,
                )
                self.assertEqual(container["resources"], expected.resources)
                self.assertEqual(service["spec"]["type"], expected.service_type)
                self.assertEqual(service["spec"]["ports"][0]["port"], expected.service_port)
                self.assertEqual(
                    service["spec"]["ports"][0]["targetPort"],
                    expected.container_port,
                )

    def test_security_and_secret_refs_are_safe_by_construction(self) -> None:
        deployment = self.yaml_artifact("k8s/overlays/production/deployment.yaml")
        pod = deployment["spec"]["template"]["spec"]
        container = pod["containers"][0]
        security = container["securityContext"]

        self.assertEqual(pod["serviceAccountName"], "sample-api")
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(security["runAsNonRoot"])
        self.assertEqual(security["runAsUser"], 10001)
        self.assertFalse(security["allowPrivilegeEscalation"])
        self.assertEqual(security["capabilities"], {"drop": ["ALL"]})
        self.assertEqual(security["seccompProfile"], {"type": "RuntimeDefault"})
        self.assertTrue(security["readOnlyRootFilesystem"])
        self.assertEqual(
            container["env"],
            [
                {
                    "name": "DATABASE_URL",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "sample-api-secrets",
                            "key": "DATABASE_URL",
                        }
                    },
                }
            ],
        )
        self.assertNotIn("value", container["env"][0])
        self.assertFalse(
            any("kind: Secret" in artifact.content for artifact in self.result.artifacts)
        )

    def test_config_values_exist_only_in_environment_config_maps(self) -> None:
        dev_config = self.yaml_artifact("k8s/overlays/dev/configmap.yaml")
        dev_deployment = self.yaml_artifact("k8s/overlays/dev/deployment.yaml")
        container = dev_deployment["spec"]["template"]["spec"]["containers"][0]

        self.assertEqual(
            dev_config["data"],
            {"FEATURE_FLAG": "false", "LOG_LEVEL": "debug"},
        )
        self.assertEqual(
            container["envFrom"],
            [{"configMapRef": {"name": "sample-api-config"}}],
        )
        deployment_content = self.result.artifact(
            "k8s/overlays/dev/deployment.yaml"
        ).content
        self.assertNotIn("LOG_LEVEL", deployment_content)
        self.assertNotIn("debug", deployment_content)

    def test_environment_specific_ports_probes_config_and_secrets_replace_base(self) -> None:
        raw = parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))
        raw["environments"]["staging"].update(
            {
                "containerPort": 9090,
                "service": {"type": "LoadBalancer", "port": 8081},
                "health": {
                    "path": "/live",
                    "initialDelaySeconds": 17,
                    "periodSeconds": 23,
                },
                "readiness": {
                    "path": "/startup-ready",
                    "initialDelaySeconds": 7,
                    "periodSeconds": 11,
                },
                "environment": {"REGION": "staging"},
                "secretRefs": [
                    {"name": "staging-secrets", "keys": ["API_TOKEN"]}
                ],
            }
        )
        model = normalize_config(raw)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(model)
        deployment = yaml.safe_load(
            result.artifact("k8s/overlays/staging/deployment.yaml").content
        )
        service = yaml.safe_load(
            result.artifact("k8s/overlays/staging/service.yaml").content
        )
        config_map = yaml.safe_load(
            result.artifact("k8s/overlays/staging/configmap.yaml").content
        )
        container = deployment["spec"]["template"]["spec"]["containers"][0]

        self.assertEqual(container["ports"][0]["containerPort"], 9090)
        self.assertEqual(container["livenessProbe"]["httpGet"]["path"], "/live")
        self.assertEqual(
            container["readinessProbe"]["httpGet"]["path"],
            "/startup-ready",
        )
        self.assertEqual(container["livenessProbe"]["initialDelaySeconds"], 17)
        self.assertEqual(container["livenessProbe"]["periodSeconds"], 23)
        self.assertEqual(container["readinessProbe"]["initialDelaySeconds"], 7)
        self.assertEqual(container["readinessProbe"]["periodSeconds"], 11)
        self.assertEqual(service["spec"]["type"], "LoadBalancer")
        self.assertEqual(service["spec"]["ports"][0]["port"], 8081)
        self.assertEqual(service["spec"]["ports"][0]["targetPort"], 9090)
        self.assertEqual(config_map["data"]["REGION"], "staging")
        self.assertEqual(
            container["env"],
            [
                {
                    "name": "API_TOKEN",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "staging-secrets",
                            "key": "API_TOKEN",
                        }
                    },
                }
            ],
        )

    def test_read_only_root_filesystem_is_optional(self) -> None:
        raw = parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))
        raw["security"]["readOnlyRootFilesystem"] = False
        model = normalize_config(raw)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(model)
        deployment = yaml.safe_load(
            result.artifact("k8s/overlays/dev/deployment.yaml").content
        )
        security = deployment["spec"]["template"]["spec"]["containers"][0][
            "securityContext"
        ]

        self.assertNotIn("readOnlyRootFilesystem", security)

    def test_configured_security_booleans_are_preserved_for_policy_validation(self) -> None:
        raw = parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))
        raw["security"]["runAsNonRoot"] = False
        raw["security"]["allowPrivilegeEscalation"] = True
        model = normalize_config(raw)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(model)
        deployment = yaml.safe_load(
            result.artifact("k8s/overlays/production/deployment.yaml").content
        )
        pod = deployment["spec"]["template"]["spec"]
        container_security = pod["containers"][0]["securityContext"]

        self.assertFalse(pod["securityContext"]["runAsNonRoot"])
        self.assertFalse(container_security["runAsNonRoot"])
        self.assertTrue(container_security["allowPrivilegeEscalation"])
        self.assertEqual(container_security["capabilities"], {"drop": ["ALL"]})

    def test_production_has_restricted_defaults_and_rollback_history(self) -> None:
        namespace = self.yaml_artifact("k8s/overlays/production/namespace.yaml")
        deployment = self.yaml_artifact("k8s/overlays/production/deployment.yaml")

        self.assertEqual(
            namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"],
            "restricted",
        )
        self.assertEqual(
            namespace["metadata"]["labels"][
                "pod-security.kubernetes.io/enforce-version"
            ],
            "v1.30",
        )
        self.assertEqual(deployment["spec"]["replicas"], 3)
        self.assertEqual(deployment["spec"]["minReadySeconds"], 10)
        self.assertEqual(deployment["spec"]["progressDeadlineSeconds"], 600)
        self.assertEqual(deployment["spec"]["revisionHistoryLimit"], 10)
        self.assertEqual(deployment["spec"]["strategy"]["type"], "RollingUpdate")
        self.assertEqual(
            deployment["spec"]["strategy"]["rollingUpdate"],
            {"maxUnavailable": 0, "maxSurge": 1},
        )

    def test_contract_and_artifacts_are_deterministic(self) -> None:
        second_runner = FakeRunner(self.source_root, generation=59)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            second = KubernetesAdapter(
                self.source,
                runner=second_runner,
            ).render(self.model)

        self.assertEqual(self.result.contract, self.model.contract())
        self.assertEqual(self.result.artifacts, second.artifacts)
        context = self.result.artifact("k8s/platform-context.json").content
        context_document = json.loads(context)
        self.assertNotIn("GeneratedAt", context)
        self.assertNotIn(str(self.source_root), context)
        self.assertNotIn("/tmp/private", context)
        self.assertLess(len(context), 4096)
        self.assertEqual(
            context_document["schemaVersion"],
            "k8s-integration-summary-v1",
        )
        self.assertEqual(
            context_document["queries"]["profileCatalog"]["profileCount"],
            1,
        )
        self.assertNotIn("Profiles", context_document["queries"]["profileCatalog"])
        self.assertEqual(context_document["render"]["status"], "PASSED")
        self.assertEqual(
            context_document["validators"]["securityBaseline"]["findings"],
            {"high": 0, "medium": 1, "low": 1},
        )
        self.assertEqual(
            context_document["validators"]["placeholders"]["matchCount"],
            4,
        )

    def test_architecture_contract_is_visible_to_the_scheduler(self) -> None:
        multiarch = self.yaml_artifact("k8s/overlays/dev/deployment.yaml")
        self.assertEqual(
            multiarch["metadata"]["annotations"][
                "devops-stack.io/image-architectures"
            ],
            "linux/amd64,linux/arm64",
        )
        self.assertEqual(
            multiarch["spec"]["template"]["spec"]["nodeSelector"],
            {"kubernetes.io/os": "linux"},
        )

        raw = parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))
        raw["image"]["architectures"] = ["linux/arm64"]
        model = normalize_config(raw)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(model)
        deployment = yaml.safe_load(
            result.artifact("k8s/overlays/dev/deployment.yaml").content
        )
        self.assertEqual(
            deployment["spec"]["template"]["spec"]["nodeSelector"],
            {"kubernetes.io/os": "linux", "kubernetes.io/arch": "arm64"},
        )

    def test_upstream_queries_render_and_validators_use_only_isolated_copy(self) -> None:
        pwsh_calls = [call for call in self.runner.calls if call[0][0] == "pwsh"]

        self.assertEqual(len(pwsh_calls), 8)
        scripts = {
            Path(command[command.index("-File") + 1]).name
            for command, _ in pwsh_calls
        }
        self.assertEqual(
            scripts,
            {
                "show-profile-catalog.ps1",
                "show-environment-preset-plan.ps1",
                "show-render-matrix.ps1",
                "show-platform-plan.ps1",
                "render-platform-assets.ps1",
                "validate-rendered-bundle.ps1",
                "validate-kubernetes-security-baseline.ps1",
                "check-placeholders.ps1",
            },
        )
        for command, kwargs in pwsh_calls:
            self.assertNotEqual(kwargs["cwd"], self.source_root)
            self.assertNotIn(str(self.source_root), " ".join(command))
            self.assertNotIn("invoke-bundle-delivery.ps1", " ".join(command))
        query_calls = [
            (command, kwargs)
            for command, kwargs in pwsh_calls
            if Path(command[command.index("-File") + 1]).name.startswith("show-")
        ]
        self.assertEqual(len(query_calls), 4)
        for command, _ in query_calls:
            self.assertEqual(command[-2:], ("-Format", "json"))
            self.assertNotIn("OutputPath", command)
        platform_command = next(
            command
            for command, _ in query_calls
            if any(value.endswith("show-platform-plan.ps1") for value in command)
        )
        self.assertIn("minimal-application", platform_command)
        self.assertIn("nginx-web", platform_command)
        render_command, render_kwargs = next(
            (command, kwargs)
            for command, kwargs in pwsh_calls
            if any(value.endswith("render-platform-assets.ps1") for value in command)
        )
        isolated_root = Path(render_kwargs["cwd"])
        output_path = Path(render_command[render_command.index("-OutputPath") + 1])
        values_path = Path(render_command[render_command.index("-ValuesFile") + 1])
        self.assertFalse(output_path.is_relative_to(isolated_root))
        self.assertTrue(values_path.is_relative_to(isolated_root))
        self.assertEqual(values_path.name, "platform-values.env.example")
        self.assertIn("-FailOnUnresolvedToken", render_command)
        self.assertFalse(self.runner.copied_source_contained_out)

    def test_missing_external_tools_are_skipped_not_passed(self) -> None:
        diagnostics = {diagnostic.check: diagnostic for diagnostic in self.result.diagnostics}

        self.assertEqual(
            diagnostics["kubernetes.yaml-structure"].status,
            ValidationStatus.PASSED.value,
        )
        for tool in ("kustomize", "kubectl", "kubeconform"):
            self.assertEqual(
                diagnostics[f"kubernetes.external.{tool}"].status,
                ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value,
            )

    def test_upstream_schema_validation_skip_is_not_reported_as_passed(self) -> None:
        runner = FakeRunner(self.source_root, schema_tools_missing=True)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(self.model)
        diagnostics = {diagnostic.check: diagnostic for diagnostic in result.diagnostics}

        self.assertEqual(
            diagnostics["kubernetes.upstream.renderedBundle"].status,
            ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value,
        )

    def test_unlocked_source_fails_without_executing_upstream_scripts(self) -> None:
        unlocked = SourceResolution(
            key="kubernetes",
            path=self.source_root,
            origin="test",
            commit="f" * 40,
            remote=None,
            matches_lock=False,
        )
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(unlocked, runner=runner).render(self.model)
        diagnostics = {diagnostic.check: diagnostic for diagnostic in result.diagnostics}

        self.assertEqual(runner.calls, [])
        self.assertEqual(
            diagnostics["kubernetes.source-lock"].status,
            ValidationStatus.FAILED.value,
        )
        context = json.loads(result.artifact("k8s/platform-context.json").content)
        self.assertFalse(context["source"]["matchesLock"])
        self.assertEqual(context["queries"], {})

    def test_explicitly_disabled_upstream_validation_executes_no_source_scripts(self) -> None:
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(
                self.model,
                validate_upstream=False,
            )

        self.assertEqual(runner.calls, [])
        context = json.loads(result.artifact("k8s/platform-context.json").content)
        self.assertEqual(context["render"]["status"], "NOT_RUN")
        self.assertEqual(
            next(
                item
                for item in result.diagnostics
                if item.check == "kubernetes.yaml-structure"
            ).status,
            ValidationStatus.PASSED.value,
        )

    def test_symlinked_template_content_fails_before_script_execution(self) -> None:
        (self.source_root / "escape").symlink_to(Path("/tmp"), target_is_directory=True)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(self.model)
        diagnostics = {diagnostic.check: diagnostic for diagnostic in result.diagnostics}

        self.assertEqual(runner.calls, [])
        self.assertEqual(
            diagnostics["kubernetes.upstream.isolated-copy"].status,
            ValidationStatus.FAILED.value,
        )

    def test_installed_external_tools_report_real_passes(self) -> None:
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            side_effect=lambda tool: f"/tools/{tool}",
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(self.model)
        diagnostics = {diagnostic.check: diagnostic for diagnostic in result.diagnostics}

        for tool in ("kustomize", "kubectl", "kubeconform"):
            self.assertEqual(
                diagnostics[f"kubernetes.external.{tool}"].status,
                ValidationStatus.PASSED.value,
            )

    def test_internal_semantic_validation_rejects_adversarial_workload_shapes(self) -> None:
        artifacts = list(self.result.artifacts)

        def replace_yaml(path: str, document: dict) -> None:
            index = next(
                position
                for position, artifact in enumerate(artifacts)
                if artifact.path == path
            )
            original = artifacts[index]
            artifacts[index] = GeneratedArtifact(
                path=path,
                content=yaml.safe_dump(document, sort_keys=False),
                mode=original.mode,
                origins=original.origins,
            )

        deployment_path = "k8s/overlays/dev/deployment.yaml"
        deployment = yaml.safe_load(self.result.artifact(deployment_path).content)
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        container["livenessProbe"]["httpGet"]["port"] = 65535
        container["readinessProbe"]["periodSeconds"] = 0
        container["resources"]["limits"]["cpu"] = "unbounded"
        container["securityContext"]["capabilities"]["drop"] = []
        replace_yaml(deployment_path, deployment)

        service_path = "k8s/overlays/dev/service.yaml"
        service = yaml.safe_load(self.result.artifact(service_path).content)
        service["spec"]["ports"][0]["targetPort"] = 70000
        replace_yaml(service_path, service)

        namespace_path = "k8s/overlays/dev/namespace.yaml"
        namespace = yaml.safe_load(self.result.artifact(namespace_path).content)
        namespace["metadata"]["name"] = "wrong-namespace"
        replace_yaml(namespace_path, namespace)

        diagnostic = validate_yaml_artifacts(tuple(artifacts))
        messages = "\n".join(diagnostic.details["errors"])

        self.assertEqual(diagnostic.status, ValidationStatus.FAILED.value)
        self.assertIn("livenessProbe.httpGet.port", messages)
        self.assertIn("readinessProbe.periodSeconds", messages)
        self.assertIn("resources.limits.cpu", messages)
        self.assertIn("capabilities.drop", messages)
        self.assertIn("Service port[0].targetPort", messages)
        self.assertIn("overlay Namespace identity", messages)

    def test_unrecognized_secret_fields_never_leak_into_artifacts(self) -> None:
        raw = parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))
        raw["deployment"]["secretRefs"][0]["value"] = "DO-NOT-LEAK"
        model = normalize_config(raw)
        runner = FakeRunner(self.source_root)
        with patch(
            "devops_stack_composer.adapters.kubernetes.shutil.which",
            return_value=None,
        ):
            result = KubernetesAdapter(self.source, runner=runner).render(model)

        self.assertNotIn(
            "DO-NOT-LEAK",
            "".join(artifact.content for artifact in result.artifacts),
        )

    def test_internal_validator_rejects_invalid_rollout_values(self) -> None:
        artifacts = list(self.result.artifacts)
        index = next(
            index
            for index, artifact in enumerate(artifacts)
            if artifact.path == "k8s/base/deployment.yaml"
        )
        document = yaml.safe_load(artifacts[index].content)
        document["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] = "invalid"
        artifacts[index] = GeneratedArtifact(
            artifacts[index].path,
            yaml.safe_dump(document, sort_keys=False),
        )

        diagnostic = validate_yaml_artifacts(artifacts)

        self.assertEqual(diagnostic.status, ValidationStatus.FAILED.value)


class KubernetesSanitizerAndValidationTests(unittest.TestCase):
    def test_sanitizer_removes_timestamps_and_absolute_paths_recursively(self) -> None:
        source_root = Path("/opt/templates/kubernetes")
        sanitized = sanitize_upstream_payload(
            {
                "GeneratedAt": "2099-01-01T00:00:00",
                "generated_at": "2099-01-01T00:00:01",
                "RepoRoot": str(source_root),
                "Nested": {
                    "SourceFile": str(source_root / "config/example.psd1"),
                    "Outside": "/var/private/token.txt",
                    "Windows": r"C:\Users\person\values.env",
                    "Message": (
                        "failed at /tmp/render/output.yaml and "
                        r"C:\Users\person\private.env"
                    ),
                    "ApiToken": "do-not-expose",
                    "DatabasePassword": "also-do-not-expose",
                },
            },
            source_root,
        )

        self.assertNotIn("GeneratedAt", sanitized)
        self.assertNotIn("generated_at", sanitized)
        self.assertEqual(sanitized["RepoRoot"], "<template-source>")
        self.assertEqual(
            sanitized["Nested"]["SourceFile"],
            "<template-source>/config/example.psd1",
        )
        self.assertEqual(sanitized["Nested"]["Outside"], "<absolute-path>/token.txt")
        self.assertEqual(sanitized["Nested"]["Windows"], "<absolute-path>/values.env")
        self.assertNotIn("/tmp/render", sanitized["Nested"]["Message"])
        self.assertNotIn(r"C:\Users", sanitized["Nested"]["Message"])
        self.assertEqual(sanitized["Nested"]["ApiToken"], "<redacted>")
        self.assertEqual(sanitized["Nested"]["DatabasePassword"], "<redacted>")

    def test_internal_validator_rejects_secret_resources(self) -> None:
        diagnostic = validate_yaml_artifacts(
            (
                GeneratedArtifact(
                    path="k8s/secret.yaml",
                    content=(
                        "apiVersion: v1\n"
                        "kind: Secret\n"
                        "metadata:\n"
                        "  name: forbidden\n"
                    ),
                ),
            )
        )

        self.assertEqual(diagnostic.status, ValidationStatus.FAILED.value)
        self.assertIn("generated Secret resources are forbidden", diagnostic.details["errors"][0])


if __name__ == "__main__":
    unittest.main()
