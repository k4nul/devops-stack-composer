from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer.adapters.docker import (
    BLOCKED_MISSING_REQUIRED_TOOL,
    FAILED,
    PASSED,
    SKIPPED_MISSING_OPTIONAL_TOOL,
    DockerBuildAdapter,
    UPSTREAM_IMAGE_ENV_KEYS,
    UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS,
)
from devops_stack_composer.adapters.base import AdapterResult
from devops_stack_composer.config import parse_config
from devops_stack_composer.model import normalize_config
from devops_stack_composer.sources import SourceResolution


ROOT = Path(__file__).resolve().parents[1]
CONFIG_FIXTURE = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"
SOURCE_FIXTURE = ROOT / "tests" / "fixtures" / "templates" / "docker"


def source_resolution(
    *,
    matches_lock: bool = True,
    path: Path = SOURCE_FIXTURE,
    commit: str = "bbd6c4ba184c0e68dcaf65d4eb26ea622847c8c3",
) -> SourceResolution:
    return SourceResolution(
        key="docker",
        path=path.resolve(),
        origin="fixture",
        commit=commit,
        remote="https://example.invalid/docker-build-template.git",
        matches_lock=matches_lock,
    )


def make_git_source(path: Path) -> SourceResolution:
    shutil.copytree(SOURCE_FIXTURE, path)
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
    subprocess.run(
        ["git", "-C", str(path), "commit", "--quiet", "-m", "fixture"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return source_resolution(path=path, commit=commit)


def raw_config() -> dict[str, object]:
    return parse_config(CONFIG_FIXTURE.read_text(encoding="utf-8"))


def source_snapshot(path: Path) -> dict[str, tuple[bytes, int]]:
    return {
        item.relative_to(path).as_posix(): (item.read_bytes(), item.stat().st_mode & 0o777)
        for item in sorted(path.rglob("*"))
        if item.is_file() and ".git" not in item.relative_to(path).parts
    }


def write_python_application(root: Path) -> None:
    app = root / "app"
    app.mkdir(parents=True)
    (app / "server.py").write_text(
        "from http.server import HTTPServer, SimpleHTTPRequestHandler\n"
        "HTTPServer(('0.0.0.0', 8080), SimpleHTTPRequestHandler).serve_forever()\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("", encoding="utf-8")


def disable_cache(raw: dict[str, object]) -> None:
    raw["build"]["cache"] = {"enabled": False, "from": [], "to": []}


def materialize_artifacts(result: AdapterResult, output_root: Path) -> None:
    for artifact in result.artifacts:
        destination = output_root / artifact.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(artifact.content, encoding="utf-8")
        destination.chmod(artifact.mode)


class DockerBuildAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.source_directory.cleanup)
        self.source = make_git_source(Path(self.source_directory.name) / "source")
        self.model = normalize_config(raw_config())
        self.adapter = DockerBuildAdapter(self.source)

    def test_render_is_deterministic_and_uses_only_official_image_env_keys(self) -> None:
        first = self.adapter.render(self.model)
        second = self.adapter.render(self.model)

        self.assertEqual(first, second)
        self.assertEqual(
            [artifact.path for artifact in first.artifacts],
            [
                "docker/Dockerfile",
                "docker/Dockerfile.dockerignore",
                "docker/image.env",
                "docker/build.sh",
                "docker/metadata.json",
            ],
        )

        env_content = first.artifact("docker/image.env").content
        env_values = dict(
            line.split("=", 1) for line in env_content.splitlines() if line
        )
        self.assertEqual(tuple(env_values), UPSTREAM_IMAGE_ENV_KEYS)
        self.assertEqual(env_values["REGISTRY"], "ghcr.io/")
        self.assertEqual(env_values["IMAGE_NAME"], "k4nul/sample-api")
        self.assertEqual(env_values["IMAGE_TAG"], "__IMAGE_TAG__")
        self.assertEqual(env_values["PLATFORMS"], "linux/amd64,linux/arm64")
        self.assertEqual(env_values["PUSH"], "false")
        self.assertEqual(env_values["SBOM"], "true")
        self.assertEqual(env_values["PROVENANCE"], "mode=max")

        dockerignore = first.artifact(
            "docker/Dockerfile.dockerignore"
        ).content.splitlines()
        for pattern in UPSTREAM_REQUIRED_DOCKERIGNORE_PATTERNS:
            self.assertIn(pattern, dockerignore)

        build_script = first.artifact("docker/build.sh")
        self.assertEqual(build_script.mode, 0o755)
        self.assertIn("scripts/build-image.sh", build_script.content)
        self.assertNotIn("cache-from", build_script.content)
        self.assertNotIn("cache-to", build_script.content)
        shell_check = subprocess.run(
            ["sh", "-n"],
            input=build_script.content,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)

        metadata = json.loads(first.artifact("docker/metadata.json").content)
        self.assertEqual(metadata["image"]["tag"], "__IMAGE_TAG__")
        self.assertEqual(
            metadata["image"]["tagExpression"],
            "${BRANCH_SLUG}-${GIT_COMMIT_SHA}",
        )
        self.assertTrue(metadata["capabilities"]["cache"]["requested"])
        self.assertFalse(metadata["capabilities"]["cache"]["supportedByUpstream"])
        self.assertFalse(metadata["capabilities"]["cache"]["wired"])
        self.assertFalse(metadata["capabilities"]["scan"]["supportedByUpstream"])
        self.assertEqual(metadata["build"]["ignoreFile"], "docker/Dockerfile.dockerignore")
        cache_diagnostic = next(
            diagnostic
            for diagnostic in first.diagnostics
            if diagnostic.check == "docker-cache-capability"
        )
        self.assertEqual(cache_diagnostic.status, FAILED)

    def test_cache_references_are_truthfully_recorded_as_unsupported_requests(self) -> None:
        raw = raw_config()
        raw["build"]["cache"] = {
            "enabled": False,
            "from": ["type=registry,ref=example.invalid/cache"],
            "to": [],
        }

        result = self.adapter.render(normalize_config(raw))
        metadata = json.loads(result.artifact("docker/metadata.json").content)
        diagnostic = next(
            item
            for item in result.diagnostics
            if item.check == "docker-cache-capability"
        )

        self.assertTrue(metadata["capabilities"]["cache"]["requested"])
        self.assertFalse(metadata["capabilities"]["cache"]["wired"])
        self.assertEqual(diagnostic.status, FAILED)
        self.assertTrue(diagnostic.details["cacheRequested"])

    def test_generated_dockerfiles_cover_every_declared_application_type(self) -> None:
        cases = {
            "nodejs": ("node:22-alpine", "npm run build", "node server.js", "dist"),
            "python": (
                "python:3.12-slim",
                "python -m compileall app",
                "python app/server.py",
                "app",
            ),
            "java": (
                "eclipse-temurin:21-jdk-jammy",
                "./mvnw package",
                "java -jar target/app.jar",
                "target/app.jar",
            ),
            "go": ("golang:1.23-alpine", "go build -o bin/app ./cmd/app", "./bin/app", "bin/app"),
            "rust": (
                "rust:1.83-alpine",
                "cargo build --release",
                "./target/release/app",
                "target/release/app",
            ),
            "static": ("node:22-alpine", "npm run build", "python -m http.server 8080", "dist"),
        }

        for application_type, (builder, build_command, run_command, artifact) in cases.items():
            with self.subTest(application_type=application_type):
                raw = copy.deepcopy(raw_config())
                raw["application"]["type"] = application_type
                raw["application"]["buildCommand"] = build_command
                raw["application"]["runCommand"] = run_command
                raw["application"]["buildArtifact"] = artifact
                model = normalize_config(raw)

                dockerfile = self.adapter.render(model).artifact("docker/Dockerfile").content

                self.assertIn(f"ARG BUILDER_IMAGE={builder}", dockerfile)
                self.assertIn("FROM ${BUILDER_IMAGE} AS build", dockerfile)
                self.assertIn("FROM ${RUNTIME_IMAGE} AS runtime", dockerfile)
                self.assertIn('ARG OCI_CREATED="1970-01-01T00:00:00Z"', dockerfile)
                self.assertIn(
                    'org.opencontainers.image.created="${OCI_CREATED}"',
                    dockerfile,
                )
                self.assertIn("USER 10001:10001", dockerfile)
                self.assertIn("EXPOSE 8080", dockerfile)
                expected_command = json.dumps(
                    ["sh", "-c", run_command], separators=(",", ":")
                )
                self.assertIn(expected_command, dockerfile)
                if application_type == "static":
                    self.assertIn(
                        "if [ -f package-lock.json ]; then npm ci;",
                        dockerfile,
                    )

        python_dockerfile = self.adapter.render(self.model).artifact("docker/Dockerfile").content
        self.assertIn("pip install --no-cache-dir -r requirements.txt", python_dockerfile)
        self.assertIn("COPY --from=build /usr/local /usr/local", python_dockerfile)
        self.assertIn("COPY --from=build --chown=10001:10001 /workspace /app", python_dockerfile)

    def test_single_stage_setting_does_not_claim_or_emit_a_builder_stage(self) -> None:
        raw = raw_config()
        raw["build"]["multiStage"] = False
        model = normalize_config(raw)

        result = self.adapter.render(model)
        dockerfile = result.artifact("docker/Dockerfile").content
        metadata = json.loads(result.artifact("docker/metadata.json").content)

        self.assertNotIn("AS build", dockerfile)
        self.assertIn("ARG RUNTIME_IMAGE=python:3.12-slim", dockerfile)
        self.assertIn("COPY --chown=10001:10001 . /app", dockerfile)
        self.assertFalse(metadata["build"]["multiStage"])

    def test_generate_invokes_self_contained_source_without_touching_it(self) -> None:
        before = source_snapshot(self.source.path)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            with patch.dict(
                os.environ,
                {"DOCKER_ADAPTER_SECRET_SHOULD_NOT_LEAK": "sensitive"},
            ):
                result = self.adapter.generate(self.model, project_root=project_root)

        after = source_snapshot(self.source.path)
        validation = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        self.assertEqual(validation.status, PASSED)
        self.assertEqual(validation.command, ("sh", "scripts/validate-build-plan.sh"))
        self.assertIn("fixture docker template validation passed", validation.details["stdout"])
        self.assertEqual(before, after)

    def test_upstream_diagnostics_redact_captured_credentials(self) -> None:
        secret_output = """Authorization: Bearer TOP-SECRET
Proxy-Authorization: Basic PROXY-SECRET
https://alice:swordfish@example.invalid/private
TOKEN=INLINE-SECRET
curl --user bob:hunter2 https://example.invalid
curl -ucompact:password https://example.invalid
"""

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, secret_output, secret_output)

        adapter = DockerBuildAdapter(self.source, command_runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            result = adapter.generate(self.model, project_root=project_root)

        diagnostic = next(
            item
            for item in result.diagnostics
            if item.check == "docker-template-validation"
        )
        serialized = json.dumps(diagnostic.details, sort_keys=True)
        for secret in (
            "TOP-SECRET",
            "PROXY-SECRET",
            "alice:swordfish",
            "INLINE-SECRET",
            "bob:hunter2",
            "compact:password",
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn("<redacted>", serialized)

    def test_application_staging_excludes_generated_and_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            for relative in (
                "generated/unowned-secrets.txt",
                "generated-preview/preview.txt",
                ".devops-stack/reports/private.txt",
            ):
                target = project_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("must not enter build context\n", encoding="utf-8")

            result = self.adapter.generate(self.model, project_root=project_root)

        validation = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        self.assertEqual(validation.status, PASSED)

    def test_dirty_template_worktree_bytes_are_not_executed(self) -> None:
        dirty_script = self.source.path / "scripts" / "validate-build-plan.sh"
        dirty_script.write_text("#!/usr/bin/env sh\nexit 99\n", encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)

            result = self.adapter.generate(self.model, project_root=project_root)

        validation = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        archive = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-archive"
        )
        self.assertEqual(validation.status, PASSED)
        self.assertIn("fixture docker template validation passed", validation.details["stdout"])
        self.assertEqual(archive.status, PASSED)

    def test_optional_local_build_runs_only_for_an_explicit_single_platform_request(self) -> None:
        raw = raw_config()
        raw["image"]["architectures"] = ["linux/amd64"]
        disable_cache(raw)
        model = normalize_config(raw)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            without_build = self.adapter.generate(model, project_root=project_root)
            with_build = self.adapter.generate(
                model,
                project_root=project_root,
                local_build=True,
                image_tag="test-sha-123",
            )

        self.assertFalse(
            any(
                diagnostic.check == "docker-local-build"
                for diagnostic in without_build.diagnostics
            )
        )
        build = next(
            diagnostic
            for diagnostic in with_build.diagnostics
            if diagnostic.check == "docker-local-build"
        )
        self.assertEqual(build.status, PASSED)
        self.assertIn("fixture docker local build passed", build.details["stdout"])

    def test_multi_platform_local_build_fails_after_no_push_validation(self) -> None:
        raw = raw_config()
        disable_cache(raw)
        model = normalize_config(raw)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            result = self.adapter.generate(
                model,
                project_root=project_root,
                local_build=True,
                image_tag="test-sha-123",
            )

        validation = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        build = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-local-build"
        )
        self.assertEqual(validation.status, PASSED)
        self.assertEqual(build.status, FAILED)
        self.assertIn("exactly one platform", build.message)

    def test_required_and_optional_missing_tools_use_exact_statuses(self) -> None:
        calls = 0

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return subprocess.CompletedProcess(command, 0, "validated\n", "")
            return subprocess.CompletedProcess(command, 127, "", "docker: not found\n")

        raw = raw_config()
        raw["image"]["architectures"] = ["linux/amd64"]
        disable_cache(raw)
        adapter = DockerBuildAdapter(self.source, command_runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            result = adapter.generate(
                normalize_config(raw),
                project_root=project_root,
                local_build=True,
                image_tag="test-sha-123",
            )

        build = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-local-build"
        )
        self.assertEqual(build.status, SKIPPED_MISSING_OPTIONAL_TOOL)

        def missing_shell(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 127, "", "sh: not found\n")

        blocked_adapter = DockerBuildAdapter(self.source, command_runner=missing_shell)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            blocked = blocked_adapter.generate(self.model, project_root=project_root)
        validation = next(
            diagnostic
            for diagnostic in blocked.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        self.assertEqual(validation.status, BLOCKED_MISSING_REQUIRED_TOOL)

    def test_missing_buildx_is_a_required_tool_blocker(self) -> None:
        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "docker: 'buildx' is not a docker command.\n",
            )

        adapter = DockerBuildAdapter(self.source, command_runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            result = adapter.generate(self.model, project_root=project_root)

        validation = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-validation"
        )
        self.assertEqual(validation.status, BLOCKED_MISSING_REQUIRED_TOOL)

    def test_local_build_rejects_missing_or_placeholder_tag_before_invocation(self) -> None:
        called = False

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            nonlocal called
            called = True
            return subprocess.CompletedProcess(command, 0, "", "")

        raw = raw_config()
        raw["image"]["architectures"] = ["linux/amd64"]
        disable_cache(raw)
        adapter = DockerBuildAdapter(self.source, command_runner=runner)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            missing = adapter.generate(
                normalize_config(raw),
                project_root=project_root,
                local_build=True,
            )
            placeholder = adapter.generate(
                normalize_config(raw),
                project_root=project_root,
                local_build=True,
                image_tag="__IMAGE_TAG__",
            )

        for result in (missing, placeholder):
            tag = next(
                diagnostic
                for diagnostic in result.diagnostics
                if diagnostic.check == "docker-image-tag"
            )
            self.assertEqual(tag.status, FAILED)
        self.assertFalse(called)

    def test_existing_dockerfile_requires_verified_final_stage_non_root_uid(self) -> None:
        raw = raw_config()
        raw["build"]["dockerfile"] = {"strategy": "existing", "path": "Dockerfile"}
        model = normalize_config(raw)
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            dockerfile = project_root / "Dockerfile"
            dockerfile.write_text("FROM python:3.12-slim\nCMD [\"python\"]\n", encoding="utf-8")

            unverified = self.adapter.render(model, project_root=project_root)
            dockerfile.write_text(
                "FROM python:3.12-slim\nUSER 10001:10001\nCMD [\"python\"]\n",
                encoding="utf-8",
            )
            verified = self.adapter.render(model, project_root=project_root)

        unverified_user = next(
            diagnostic
            for diagnostic in unverified.diagnostics
            if diagnostic.check == "docker-existing-runtime-user"
        )
        verified_user = next(
            diagnostic
            for diagnostic in verified.diagnostics
            if diagnostic.check == "docker-existing-runtime-user"
        )
        self.assertEqual(unverified_user.status, FAILED)
        self.assertEqual(verified_user.status, PASSED)

    def test_template_symlink_and_stage_traversal_are_rejected(self) -> None:
        called = False

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            nonlocal called
            called = True
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source_resolution_value = make_git_source(base / "source")
            source = source_resolution_value.path
            outside = base / "outside.txt"
            outside.write_text("do not copy\n", encoding="utf-8")
            (source / "unsafe-link").symlink_to(outside)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(source), "commit", "--quiet", "-m", "symlink"],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            project_root = base / "project"
            project_root.mkdir()
            write_python_application(project_root)
            adapter = DockerBuildAdapter(
                replace(source_resolution_value, commit=commit),
                command_runner=runner,
            )

            result = adapter.generate(self.model, project_root=project_root)
            with self.assertRaisesRegex(ValueError, "unsafe Docker stage destination"):
                adapter._safe_stage_destination(base, "../escape")

        staging = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-staging"
        )
        self.assertEqual(staging.status, FAILED)
        self.assertIn("non-regular entry", staging.message)
        self.assertFalse(called)

    def test_application_context_rejects_all_symlinks_consistently(self) -> None:
        for absolute in (False, True):
            with self.subTest(absolute=absolute), tempfile.TemporaryDirectory() as directory:
                project_root = Path(directory)
                write_python_application(project_root)
                target = project_root / "app" / "target.txt"
                target.write_text("content\n", encoding="utf-8")
                link = project_root / "app" / "link.txt"
                link.symlink_to(target if absolute else Path("target.txt"))

                result = self.adapter.generate(
                    self.model,
                    project_root=project_root,
                )

                diagnostic = next(
                    item
                    for item in result.diagnostics
                    if item.check == "docker-application-context"
                )
                self.assertEqual(diagnostic.status, FAILED)
                self.assertIn("must not contain symlinks", diagnostic.message)

    def test_generated_build_script_modes_use_only_official_template_entrypoints(self) -> None:
        raw = raw_config()
        disable_cache(raw)
        model = normalize_config(raw)
        result = self.adapter.render(model)

        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            generated_root = project_root / "generated"
            materialize_artifacts(result, generated_root)
            script = generated_root / "docker" / "build.sh"
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
                "DEVOPS_STACK_DOCKER_TEMPLATE": str(self.source.path),
                "DEVOPS_STACK_PROJECT_ROOT": str(project_root.parent / "outside"),
            }
            (self.source.path / "scripts" / "validate-build-plan.sh").write_text(
                "#!/usr/bin/env sh\nexit 99\n",
                encoding="utf-8",
            )

            validation = subprocess.run(
                [str(script)],
                cwd=project_root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            push = subprocess.run(
                [str(script), "--push"],
                cwd=project_root,
                env={**environment, "IMAGE_TAG": "sha-123"},
                capture_output=True,
                text=True,
                check=False,
            )
            multi_load = subprocess.run(
                [str(script), "--load"],
                cwd=project_root,
                env={**environment, "IMAGE_TAG": "sha-123"},
                capture_output=True,
                text=True,
                check=False,
            )
            placeholder_push = subprocess.run(
                [str(script), "--push"],
                cwd=project_root,
                env={**environment, "IMAGE_TAG": "__IMAGE_TAG__"},
                capture_output=True,
                text=True,
                check=False,
            )

            single_raw = raw_config()
            single_raw["image"]["architectures"] = ["linux/amd64"]
            disable_cache(single_raw)
            materialize_artifacts(
                self.adapter.render(normalize_config(single_raw)),
                generated_root,
            )
            single_load = subprocess.run(
                [str(script), "--load"],
                cwd=project_root,
                env={**environment, "IMAGE_TAG": "sha-123"},
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(validation.returncode, 0, validation.stderr)
        self.assertIn("fixture docker template validation passed", validation.stdout)
        self.assertEqual(push.returncode, 0, push.stderr)
        self.assertIn("fixture docker official push passed", push.stdout)
        self.assertNotIn("docker buildx build --push", result.artifact("docker/build.sh").content)
        self.assertNotIn(
            "DEVOPS_STACK_PROJECT_ROOT",
            result.artifact("docker/build.sh").content,
        )
        self.assertNotEqual(multi_load.returncode, 0)
        self.assertIn("exactly one platform", multi_load.stderr)
        self.assertNotEqual(placeholder_push.returncode, 0)
        self.assertIn("concrete Docker tag", placeholder_push.stderr)
        self.assertEqual(single_load.returncode, 0, single_load.stderr)
        self.assertIn("fixture docker local build passed", single_load.stdout)

    def test_lock_mismatch_fails_before_template_invocation(self) -> None:
        called = False

        def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            nonlocal called
            called = True
            return subprocess.CompletedProcess(command, 0, "", "")

        adapter = DockerBuildAdapter(
            replace(self.source, matches_lock=False),
            command_runner=runner,
        )
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            write_python_application(project_root)
            result = adapter.generate(self.model, project_root=project_root)

        lock = next(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.check == "docker-template-lock"
        )
        self.assertEqual(lock.status, FAILED)
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
