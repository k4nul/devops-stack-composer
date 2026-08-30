from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer.adapters.jenkins import (
    JenkinsPipelineAdapter,
    _authenticated_push_script,
    _deployment_render_script,
)
from devops_stack_composer.config import load_config
from devops_stack_composer.model import normalize_config
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationStatus


ROOT = Path(__file__).resolve().parents[1]
CONFIG_FIXTURE = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"
UPSTREAM_SCRIPTS = (
    "scripts/show-jenkins-job-plan.ps1",
    "scripts/show-service-pipeline-plan.ps1",
    "scripts/export-jenkins-job-dsl.ps1",
)


def make_source(path: Path) -> SourceResolution:
    for script in UPSTREAM_SCRIPTS:
        target = path / script
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# fixture for {target.name}\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "fixture@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Fixture"],
        check=True,
    )
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    commit_environment = dict(os.environ)
    commit_environment.update(
        {
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
    )
    subprocess.run(
        ["git", "-C", str(path), "commit", "--quiet", "-m", "fixture"],
        check=True,
        env=commit_environment,
    )
    commit = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return SourceResolution(
        key="jenkins",
        path=path.resolve(),
        origin="test",
        commit=commit,
        remote="https://example.invalid/jenkins-pipeline-template.git",
        matches_lock=True,
    )


def source_snapshot(path: Path) -> dict[str, bytes]:
    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in sorted(path.rglob("*"))
        if item.is_file() and ".git" not in item.relative_to(path).parts
    }


def executable_model():
    raw = copy.deepcopy(load_config(CONFIG_FIXTURE).raw)
    raw["image"]["architectures"] = ["linux/amd64"]
    raw["build"]["cache"] = {"enabled": False, "from": [], "to": []}
    return normalize_config(raw)


class FakePwsh:
    def __init__(
        self,
        *,
        generated_at: str = "2026-08-30T00:00:00Z",
        external_path: str = "/private/runner/jenkins-plan.json",
    ) -> None:
        self.generated_at = generated_at
        self.external_path = external_path
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        self.executed_script_contents: list[str] = []

    def __call__(
        self,
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        normalized = tuple(command)
        self.calls.append((normalized, kwargs))
        source_root = Path(str(kwargs["cwd"]))
        script = normalized[3]
        self.executed_script_contents.append(
            (source_root / script).read_text(encoding="utf-8")
        )
        if script == "scripts/export-jenkins-job-dsl.ps1":
            output_index = normalized.index("-OutputPath") + 1
            output = source_root / normalized[output_index]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("multibranchPipelineJob('fixture') {}\n", encoding="utf-8")
            return subprocess.CompletedProcess(
                normalized,
                0,
                stdout="exported fixture Job DSL\n",
                stderr="",
            )
        payload = {
            "GeneratedAt": self.generated_at,
            "RepoRoot": str(source_root),
            "Plan": {
                "Name": Path(script).stem,
                "OutputPath": str(source_root / "out" / "plan.json"),
                "ExternalPath": self.external_path,
                "SourceNote": f"source={source_root}",
                "MixedPaths": f"source={source_root}; external={self.external_path}",
                "AccessToken": "ghp_fixturetoken123456789",
                "LogLine": (
                    "Authorization: Bearer arbitrary-fixture-bearer; "
                    "password='arbitrary fixture password'"
                ),
            },
        }
        return subprocess.CompletedProcess(
            normalized,
            0,
            stdout=json.dumps(payload),
            stderr="",
        )


class JenkinsAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = load_config(CONFIG_FIXTURE).model
        cls.executable_model = executable_model()

    def render_without_validation(
        self,
        source: SourceResolution,
        *,
        model=None,
    ):
        return JenkinsPipelineAdapter(source).render(
            model or self.executable_model,
            validate_upstream=False,
        )

    def test_jenkinsfile_contains_required_pipeline_and_rollback_stages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(make_source(Path(directory)))

        jenkinsfile = result.artifact("jenkins/Jenkinsfile").content
        for stage in (
            "Build",
            "Test",
            "Resolve Docker Template",
            "Container Plan Validation",
            "Container Build",
            "Supply Chain Scan",
            "Registry Push",
            "Deploy dev",
            "Deploy staging",
            "Production Approval",
            "Deploy production",
        ):
            self.assertIn(f"stage('{stage}')", jenkinsfile)

        self.assertIn("sh './generated/docker/build.sh --validate'", jenkinsfile)
        self.assertIn("./generated/docker/build.sh --load", jenkinsfile)
        self.assertIn("./generated/docker/build.sh --push", jenkinsfile)
        self.assertIn("devops-stack templates path docker", jenkinsfile)
        self.assertIn("syft \"$IMAGE_REF\"", jenkinsfile)
        self.assertIn("trivy image --exit-code 1 --severity HIGH,CRITICAL", jenkinsfile)
        self.assertNotIn("docker push \"$IMAGE_REF\"", jenkinsfile)
        self.assertLess(
            jenkinsfile.index("stage('Supply Chain Scan')"),
            jenkinsfile.index("stage('Registry Push')"),
        )
        for environment in self.model.environments:
            self.assertIn(f'overlays/{environment.name}', jenkinsfile)
            self.assertIn('kustomize edit set image', jenkinsfile)
            self.assertIn('kubectl apply -f "$render_root/rendered.yaml"', jenkinsfile)
            self.assertIn(
                "kubectl rollout undo "
                f"deployment/{self.model.service_name} --namespace {environment.namespace}",
                jenkinsfile,
            )
            rollout_flag = f"DEPLOY_{environment.name.upper()}_ROLLOUT_STARTED"
            self.assertIn(f"env.{rollout_flag} = 'false'", jenkinsfile)
            self.assertIn(
                f"env.{rollout_flag} = deploymentParts[0]",
                jenkinsfile,
            )
            self.assertIn(f"if (env.{rollout_flag} == 'true')", jenkinsfile)
        self.assertNotIn("kubectl apply -k generated/", jenkinsfile)
        self.assertEqual(jenkinsfile.count("post {\n                failure {"), 3)

    def test_branch_routes_and_production_input_are_derived_from_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(make_source(Path(directory)))

        jenkinsfile = result.artifact("jenkins/Jenkinsfile").content
        for environment, branches in self.model.branch_environment_map.items():
            stage_start = jenkinsfile.index(f"stage('Deploy {environment}')")
            stage_end = jenkinsfile.find("\n        stage(", stage_start + 1)
            stage = jenkinsfile[
                stage_start : stage_end if stage_end != -1 else len(jenkinsfile)
            ]
            for branch in branches:
                self.assertIn(
                    f"branch pattern: '{branch}', comparator: 'GLOB'",
                    stage,
                )

        self.assertIn("stage('Production Approval')", jenkinsfile)
        self.assertIn("timeout(time: 1, unit: 'HOURS')", jenkinsfile)
        self.assertIn(
            "input message: 'Approve production deployment for sample-api?', "
            "ok: 'Deploy to production'",
            jenkinsfile,
        )
        approval = jenkinsfile.index("stage('Production Approval')")
        production = jenkinsfile.index("stage('Deploy production')")
        self.assertLess(approval, production)

    def test_registry_credential_is_referenced_by_id_without_a_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(make_source(Path(directory)))

        artifacts = "\n".join(artifact.content for artifact in result.artifacts)
        self.assertIn("REGISTRY_CREDENTIAL_ID = 'ghcr-credentials'", artifacts)
        self.assertIn("credentialsId: env.REGISTRY_CREDENTIAL_ID", artifacts)
        self.assertIn("passwordVariable: 'REGISTRY_PASSWORD'", artifacts)
        self.assertIn("--password-stdin", artifacts)
        self.assertIn("set +x", artifacts)
        self.assertIn("docker_config=$(mktemp -d", artifacts)
        self.assertIn('export DOCKER_CONFIG="$docker_config"', artifacts)
        self.assertIn('rm -rf "$docker_config"', artifacts)
        self.assertNotIn("registry-password-value", artifacts)
        self.assertNotIn("REGISTRY_PASSWORD =", artifacts)

    def test_job_dsl_is_scm_backed_and_documents_external_jcasc_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(make_source(Path(directory)))

            self.assertEqual(
                tuple(artifact.path for artifact in result.artifacts),
                (
                    "jenkins/Jenkinsfile",
                    "jenkins/job-dsl.groovy",
                    "jenkins/README.md",
                    "jenkins/environments/dev.json",
                    "jenkins/environments/staging.json",
                    "jenkins/environments/production.json",
                ),
            )
        job_dsl = result.artifact("jenkins/job-dsl.groovy").content
        self.assertIn("multibranchPipelineJob('sample-api')", job_dsl)
        self.assertIn("branchSources {", job_dsl)
        self.assertIn("workflowBranchProjectFactory {", job_dsl)
        self.assertIn("remote(repositoryUrl)", job_dsl)
        self.assertIn("credentialsId(scmCredentialsId)", job_dsl)
        self.assertIn("includes(branchIncludes)", job_dsl)
        self.assertIn("scriptPath('generated/jenkins/Jenkinsfile')", job_dsl)
        self.assertIn("must not contain credentials or URL userinfo", job_dsl)

        production = json.loads(
            result.artifact("jenkins/environments/production.json").content
        )
        self.assertEqual(production["namespace"], "sample-api-production")
        self.assertEqual(production["branchPatterns"], ["main"])
        self.assertTrue(production["productionApproval"])

        boundary = result.artifact("jenkins/README.md").content
        self.assertIn("Job DSL", boundary)
        self.assertIn("External JCasC/controller configuration", boundary)
        self.assertIn("credential values", boundary)
        self.assertIn("seed bindings", boundary)
        self.assertEqual(result.contract, self.executable_model.contract())

    def test_upstream_queries_are_read_only_and_do_not_modify_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = make_source(Path(directory))
            before = source_snapshot(source.path)
            runner = FakePwsh()

            with patch.dict(os.environ, {"JENKINS_ADAPTER_SECRET": "must-not-leak"}):
                result = JenkinsPipelineAdapter(source, runner=runner).render(
                    self.executable_model
                )

            self.assertEqual(source_snapshot(source.path), before)
            self.assertFalse((source.path / "out").exists())

        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(
            tuple(call[0][3] for call in runner.calls),
            UPSTREAM_SCRIPTS,
        )
        for command, kwargs in runner.calls:
            self.assertEqual(command[:3], ("pwsh", "-NoProfile", "-File"))
            self.assertNotEqual(kwargs["cwd"], source.path)
            self.assertFalse(kwargs["check"])
            self.assertNotIn("JENKINS_ADAPTER_SECRET", kwargs["env"])
            self.assertEqual(kwargs["env"]["POWERSHELL_TELEMETRY_OPTOUT"], "1")
            rendered_command = " ".join(command).lower()
            self.assertNotIn("delivery", rendered_command)
            self.assertNotIn("deploy", rendered_command)
        self.assertFalse(
            any(
                diagnostic.status
                in {
                    ValidationStatus.FAILED.value,
                    ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value,
                }
                for diagnostic in result.diagnostics
            ),
            result.diagnostics,
        )

    def test_upstream_json_is_sanitized_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first_source = make_source(base / "checkout-a")
            second_source = make_source(base / "checkout-b")
            first = JenkinsPipelineAdapter(
                first_source,
                runner=FakePwsh(
                    generated_at="2025-01-01T00:00:00Z",
                    external_path="/private/run-a/plan.json",
                ),
            ).render(self.model)
            second = JenkinsPipelineAdapter(
                second_source,
                runner=FakePwsh(
                    generated_at="2026-08-30T09:10:11Z",
                    external_path="/opt/run-b/plan.json",
                ),
            ).render(self.model)

        self.assertEqual(first, second)
        details = json.dumps(
            [diagnostic.details for diagnostic in first.diagnostics],
            sort_keys=True,
        )
        self.assertNotIn("GeneratedAt", details)
        self.assertNotIn("RepoRoot", details)
        self.assertNotIn(str(first_source.path), details)
        self.assertNotIn("/private/", details)
        self.assertNotIn("ghp_fixturetoken", details)
        self.assertNotIn("arbitrary-fixture-bearer", details)
        self.assertNotIn("arbitrary fixture password", details)
        self.assertIn("<template-source>/out/plan.json", details)
        self.assertIn("<absolute-path>", details)
        self.assertIn('"AccessToken": "<redacted>"', details)

    def test_locked_archive_rejects_symlinks_without_upstream_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = make_source(Path(directory))
            link = source.path / "scripts" / "unsafe-link.ps1"
            link.symlink_to("/etc/passwd")
            subprocess.run(["git", "-C", str(source.path), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(source.path), "commit", "--quiet", "-m", "symlink"],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(source.path), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            runner = FakePwsh()

            result = JenkinsPipelineAdapter(
                replace(source, commit=commit),
                runner=runner,
            ).render(self.executable_model)

        archive = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "jenkins_template_archive"
        )
        self.assertEqual(archive.status, ValidationStatus.FAILED.value)
        self.assertEqual(runner.calls, [])

    def test_missing_pwsh_is_a_required_tool_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = make_source(Path(directory))
            with patch(
                "devops_stack_composer.adapters.jenkins.shutil.which",
                return_value=None,
            ):
                result = JenkinsPipelineAdapter(source).render(self.model)

        diagnostic = next(
            item
            for item in result.diagnostics
            if item.check == "jenkins_upstream_validation"
        )
        self.assertEqual(
            diagnostic.status,
            ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL.value,
        )
        self.assertEqual(diagnostic.command, ("pwsh",))

    def test_lock_mismatch_fails_without_executing_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = replace(make_source(Path(directory)), matches_lock=False)
            runner = FakePwsh()

            result = JenkinsPipelineAdapter(source, runner=runner).render(self.model)

        self.assertEqual(runner.calls, [])
        self.assertEqual(result.diagnostics[0].status, ValidationStatus.FAILED.value)
        self.assertEqual(result.diagnostics[0].check, "jenkins_template_lock")

    def test_multiarch_local_supply_chain_is_an_explicit_failed_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(
                make_source(Path(directory)),
                model=self.model,
            )

        capability = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "jenkins_local_supply_chain_capability"
        )
        self.assertEqual(capability.status, ValidationStatus.FAILED.value)
        self.assertEqual(capability.details["architectures"], ["linux/amd64", "linux/arm64"])
        cache = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "jenkins_docker_cache_capability"
        )
        self.assertEqual(cache.status, ValidationStatus.FAILED.value)
        jenkinsfile = result.artifact("jenkins/Jenkinsfile").content
        self.assertIn(
            "Local SBOM and image scanning require exactly one configured architecture",
            jenkinsfile,
        )
        self.assertNotIn("docker/build.sh --load", jenkinsfile)

    def test_single_platform_scans_local_image_before_official_push(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.render_without_validation(make_source(Path(directory)))

        capability = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "jenkins_local_supply_chain_capability"
        )
        self.assertEqual(capability.status, ValidationStatus.PASSED.value)
        jenkinsfile = result.artifact("jenkins/Jenkinsfile").content
        local_build = jenkinsfile.index("docker/build.sh --load")
        sbom = jenkinsfile.index('syft \"$IMAGE_REF\"')
        scan = jenkinsfile.index('trivy image')
        push = jenkinsfile.index("docker/build.sh --push")
        self.assertLess(local_build, sbom)
        self.assertLess(sbom, scan)
        self.assertLess(scan, push)
        supply_start = jenkinsfile.index("stage('Supply Chain Scan')")
        supply_end = jenkinsfile.index("stage('Registry Push')")
        supply_stage = jenkinsfile[supply_start:supply_end]
        self.assertIn("branch pattern: 'main', comparator: 'GLOB'", supply_stage)

    def test_generated_shell_fragments_are_syntactically_valid(self) -> None:
        scripts = [_authenticated_push_script()]
        scripts.extend(
            _deployment_render_script(self.executable_model, environment)
            for environment in self.executable_model.environments
        )
        for script in scripts:
            with self.subTest(first_line=script.splitlines()[0]):
                completed = subprocess.run(
                    ["sh", "-n"],
                    input=script,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_dirty_worktree_bytes_are_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = make_source(Path(directory))
            dirty_marker = "DIRTY_BYTES_MUST_NOT_EXECUTE"
            script = source.path / "scripts" / "show-jenkins-job-plan.ps1"
            script.write_text(dirty_marker + "\n", encoding="utf-8")
            runner = FakePwsh()

            result = JenkinsPipelineAdapter(source, runner=runner).render(
                self.executable_model
            )

            self.assertEqual(script.read_text(encoding="utf-8"), dirty_marker + "\n")
        self.assertTrue(runner.executed_script_contents)
        self.assertFalse(
            any(dirty_marker in content for content in runner.executed_script_contents)
        )
        archive = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "jenkins_template_archive"
        )
        self.assertEqual(archive.status, ValidationStatus.PASSED.value)

    def test_syntax_diagnostics_distinguish_structure_from_missing_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = make_source(Path(directory))
            with patch(
                "devops_stack_composer.adapters.jenkins.shutil.which",
                side_effect=lambda name: "pwsh" if name == "pwsh" else None,
            ):
                result = JenkinsPipelineAdapter(source, runner=FakePwsh()).render(
                    self.executable_model
                )

        statuses = {diagnostic.check: diagnostic.status for diagnostic in result.diagnostics}
        self.assertEqual(statuses["jenkins_generated_structure"], ValidationStatus.PASSED.value)
        self.assertEqual(
            statuses["jenkins_external_groovy_parse"],
            ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value,
        )
        self.assertEqual(
            statuses["jenkins_declarative_lint"],
            ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL.value,
        )


if __name__ == "__main__":
    unittest.main()
