from __future__ import annotations

from pathlib import Path
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from devops_stack_composer.process_runner import (
    NonZeroExitError,
    ProcessErrorCategory,
    ProcessResult,
)
from devops_stack_composer.release_assets import (
    ReleaseAssemblyRequest,
    ReleaseMaterialRequest,
    assemble_release_assets,
    prepare_release_materials,
)
from devops_stack_composer.release_validation import (
    ReleaseGateError,
    ReleaseGateRequest,
    validate_published_release,
)
from tests.test_execution_bundle import BundleFixture, RUN_ID, SOURCE_REVISION
from tests.test_release_assets import REPOSITORY, ROOT, VERSION, _sdist, _wheel


def _release(project: Path) -> Path:
    BundleFixture(project)
    dist = project / "dist"
    dist.mkdir()
    wheel = dist / f"devops_stack_composer-{VERSION}-py3-none-any.whl"
    sdist = dist / f"devops_stack_composer-{VERSION}.tar.gz"
    _wheel(wheel)
    _sdist(sdist)
    inputs = project / "inputs"
    inputs.mkdir()
    for source, target in (
        (ROOT / "schemas" / "devops-stack.schema.json", "devops-stack.schema.json"),
        (
            ROOT / "schemas" / "execution-report.schema.json",
            "execution-report.schema.json",
        ),
        (
            ROOT / "schemas" / "execution-evidence.schema.json",
            "execution-evidence.schema.json",
        ),
        (ROOT / "tests" / "fixtures" / "configs" / "valid.yaml", "example.yaml"),
    ):
        shutil.copyfile(source, inputs / target)
    prepare_release_materials(
        ReleaseMaterialRequest(
            project=project,
            output_directory="dist/materials",
            version=VERSION,
            source_commit=SOURCE_REVISION,
            source_repository=REPOSITORY,
            created_at="2026-08-30T12:00:00Z",
            wheel_path=wheel.relative_to(project).as_posix(),
            sdist_path=sdist.relative_to(project).as_posix(),
        )
    )
    result = assemble_release_assets(
        ReleaseAssemblyRequest(
            project=project,
            output_directory="dist/release",
            version=VERSION,
            source_commit=SOURCE_REVISION,
            wheel_path=wheel.relative_to(project).as_posix(),
            sdist_path=sdist.relative_to(project).as_posix(),
            configuration_schema_path="inputs/devops-stack.schema.json",
            report_schema_path="inputs/execution-report.schema.json",
            execution_evidence_schema_path="inputs/execution-evidence.schema.json",
            example_config_path="inputs/example.yaml",
            package_sbom_path="dist/materials/package.spdx.json",
            provenance_verification_path="dist/materials/provenance-verification.json",
            evidence_run_id=RUN_ID,
        )
    )
    return result.directory


class FakeRunner:
    def __init__(self, release: Path) -> None:
        self.release = release
        self.commands: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.dirty = False
        self.download_tampered = False
        self.attestation_failure_name: str | None = None
        self.head_commit = SOURCE_REVISION
        self.tag_commit = SOURCE_REVISION

    def run(self, argv, *, cwd=None, environment=None, timeout=None):
        command = tuple(argv)
        self.commands.append(command)
        self.environments.append(dict(environment or {}))
        stdout = ""
        if command[:3] == ("gh", "release", "download"):
            target = Path(command[command.index("--dir") + 1])
            for source in self.release.iterdir():
                shutil.copyfile(source, target / source.name)
            if self.download_tampered:
                manifest = target / "release-manifest.json"
                manifest.write_bytes(manifest.read_bytes() + b"changed")
        elif command[:3] == ("gh", "attestation", "verify"):
            if self.attestation_failure_name == Path(command[3]).name:
                result = ProcessResult(
                    argv=command,
                    cwd=Path(cwd),
                    returncode=1,
                    stdout="",
                    stderr="attestation rejected",
                    duration_seconds=0.01,
                )
                raise NonZeroExitError(ProcessErrorCategory.NONZERO, result)
            stdout = "[]\n"
        elif command[:2] == ("git", "status"):
            stdout = "?? private-name.txt\n" if self.dirty else ""
        elif command == ("git", "rev-parse", "--verify", "HEAD^{commit}"):
            stdout = self.head_commit + "\n"
        elif command[:3] == ("git", "rev-parse", "--verify"):
            stdout = self.tag_commit + "\n"
        else:  # pragma: no cover - closed fake command inventory
            raise AssertionError(command)
        return ProcessResult(
            argv=command,
            cwd=Path(cwd),
            returncode=0,
            stdout=stdout,
            stderr="",
            duration_seconds=0.01,
        )


class ReleaseValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.release = _release(self.project)
        self.runner = FakeRunner(self.release)
        self.request = ReleaseGateRequest(
            project=self.project,
            local_assets_directory=self.release.relative_to(self.project).as_posix(),
            version=VERSION,
            source_commit=SOURCE_REVISION,
            repository="k4nul/devops-stack-composer",
        )

    def test_validates_local_downloaded_worktree_and_tag_gates(self) -> None:
        result = validate_published_release(self.request, self.runner)

        self.assertEqual(
            [stage.stage_id for stage in result.stages],
            [
                "package",
                "release-assets",
                "release-download-verification",
                "working-tree",
                "tag-commit",
            ],
        )
        self.assertEqual(result.local.checksums, result.downloaded.checksums)
        self.assertTrue(result.to_dict()["downloadedFromGitHub"])
        self.assertTrue(result.to_dict()["githubArtifactAttestationsVerified"])
        self.assertEqual(
            result.verified_attestation_count,
            len(result.downloaded.checksums) + 1,
        )
        parent = self.project / ".devops-stack" / "release-downloads"
        self.assertEqual(tuple(parent.iterdir()), ())

    def test_download_tampering_fails_at_download_gate_and_is_cleaned(self) -> None:
        self.runner.download_tampered = True

        with self.assertRaisesRegex(
            ReleaseGateError, "RELEASE_DOWNLOAD_INVALID"
        ) as raised:
            validate_published_release(self.request, self.runner)

        self.assertEqual(raised.exception.stage_id, "release-download-verification")
        parent = self.project / ".devops-stack" / "release-downloads"
        self.assertEqual(tuple(parent.iterdir()), ())

    def test_dirty_worktree_fails_without_echoing_file_names(self) -> None:
        self.runner.dirty = True

        with self.assertRaisesRegex(
            ReleaseGateError, "RELEASE_WORKTREE_DIRTY"
        ) as raised:
            validate_published_release(self.request, self.runner)

        self.assertEqual(raised.exception.stage_id, "working-tree")
        self.assertNotIn("private-name", str(raised.exception))
        self.assertEqual(len(raised.exception.completed_stages), 3)

    def test_tag_head_and_expected_commit_must_match(self) -> None:
        self.runner.tag_commit = "f" * 40

        with self.assertRaisesRegex(ReleaseGateError, "RELEASE_TAG_COMMIT_MISMATCH"):
            validate_published_release(self.request, self.runner)

    def test_one_missing_github_attestation_fails_the_download_gate(self) -> None:
        self.runner.attestation_failure_name = "SHA256SUMS"

        with self.assertRaisesRegex(
            ReleaseGateError, "RELEASE_ATTESTATION_INVALID"
        ) as raised:
            validate_published_release(self.request, self.runner)

        self.assertEqual(raised.exception.stage_id, "release-download-verification")

    def test_repository_argument_is_closed_before_process_execution(self) -> None:
        with self.assertRaisesRegex(ValueError, "safe GitHub OWNER/REPO"):
            ReleaseGateRequest(
                project=self.project,
                local_assets_directory="dist/release",
                version=VERSION,
                source_commit=SOURCE_REVISION,
                repository="owner/repo --pattern *",
            )

        self.assertEqual(self.runner.commands, [])

    def test_github_token_is_scoped_to_download_and_not_serialized(self) -> None:
        with patch.dict(os.environ, {"GH_TOKEN": "release-token"}):
            result = validate_published_release(self.request, self.runner)

        download_index = self.runner.commands.index(
            next(
                command
                for command in self.runner.commands
                if command[:3] == ("gh", "release", "download")
            )
        )
        self.assertEqual(
            self.runner.environments[download_index],
            {"GH_TOKEN": "release-token"},
        )
        github_indexes = {
            index
            for index, command in enumerate(self.runner.commands)
            if command[:2] == ("gh", "attestation")
            or command[:3] == ("gh", "release", "download")
        }
        self.assertTrue(
            all(
                environment == {"GH_TOKEN": "release-token"}
                if index in github_indexes
                else environment == {}
                for index, environment in enumerate(self.runner.environments)
            )
        )
        self.assertNotIn("release-token", str(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
