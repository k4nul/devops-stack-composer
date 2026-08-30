from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.composition import generated_integrity_report
from devops_stack_composer.errors import GeneratedFileConflictError, ManifestValidationError
from devops_stack_composer.manifest import ArtifactWriter, GeneratedManifest
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


def result(name: str, artifacts: tuple[GeneratedArtifact, ...] = ()) -> AdapterResult:
    commit_prefix = {"docker": "d", "jenkins": "e", "kubernetes": "f"}[name]
    return AdapterResult(
        adapter=name,
        adapter_version="1.0.0",
        template_commit=commit_prefix * 40,
        artifacts=artifacts,
        contract={},
    )


class GeneratedManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.results = (
            result("docker"),
            result("jenkins"),
            result("kubernetes"),
        )
        self.validation = ValidationReport(
            (CheckResult("test", ValidationStatus.PASSED, "passed"),)
        )

    def test_write_and_verify_manifest(self) -> None:
        artifacts = (
            GeneratedArtifact("docker/Dockerfile", "FROM scratch\n", origins=("$.build",)),
            GeneratedArtifact("jenkins/Jenkinsfile", "pipeline {}\n", origins=("$.ci",)),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writer = ArtifactWriter(root)
            manifest = writer.write(
                artifacts,
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
                generated_at=datetime(2026, 8, 30, tzinfo=timezone.utc),
            )

            self.assertTrue(manifest.verify(root).clean)
            self.assertEqual(manifest.data["generatedAt"], "2026-08-30T00:00:00Z")
            self.assertEqual(manifest.file_map()["docker/Dockerfile"]["mode"], "0644")

    def test_modified_file_is_conflict_without_force(self) -> None:
        artifact = GeneratedArtifact("docker/Dockerfile", "FROM scratch\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writer = ArtifactWriter(root)
            writer.write(
                (artifact,),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            (root / "generated" / "docker" / "Dockerfile").write_text(
                "# user edit\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(GeneratedFileConflictError, "Dockerfile"):
                writer.write(
                    (artifact,),
                    config_hash="a" * 64,
                    results=self.results,
                    validation=self.validation,
                    environments=("dev", "staging", "production"),
                )
            writer.write(
                (artifact,),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
                force=True,
            )
            self.assertEqual(
                (root / "generated" / "docker" / "Dockerfile").read_text(encoding="utf-8"),
                "FROM scratch\n",
            )

    def test_existing_unowned_file_is_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "generated" / "docker" / "Dockerfile"
            target.parent.mkdir(parents=True)
            target.write_text("user owned\n", encoding="utf-8")
            plan = ArtifactWriter(root).plan(
                (GeneratedArtifact("docker/Dockerfile", "planned\n"),),
                previous=None,
            )

            self.assertEqual(plan.conflicts[0].reason, "existing file is not owned by the manifest")

    def test_force_blocks_nonregular_target_before_any_write(self) -> None:
        artifacts = (
            GeneratedArtifact("a.txt", "old-a\n"),
            GeneratedArtifact("z.txt", "old-z\n"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writer = ArtifactWriter(root)
            writer.write(
                artifacts,
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            (root / "generated" / "z.txt").unlink()
            (root / "generated" / "z.txt").mkdir()
            changed = (
                GeneratedArtifact("a.txt", "new-a\n"),
                GeneratedArtifact("z.txt", "new-z\n"),
            )

            with self.assertRaisesRegex(GeneratedFileConflictError, "--force cannot"):
                writer.write(
                    changed,
                    config_hash="a" * 64,
                    results=self.results,
                    validation=self.validation,
                    environments=("dev", "staging", "production"),
                    force=True,
                )

            self.assertEqual(
                (root / "generated" / "a.txt").read_text(encoding="utf-8"),
                "old-a\n",
            )

    def test_unrelated_unowned_output_file_blocks_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "generated" / "user-notes.txt"
            target.parent.mkdir(parents=True)
            target.write_text("keep me\n", encoding="utf-8")

            plan = ArtifactWriter(root).plan(
                (GeneratedArtifact("docker/Dockerfile", "planned\n"),),
                previous=None,
            )

            self.assertEqual([item.path for item in plan.unowned], ["user-notes.txt"])

    def test_stale_generated_file_is_never_deleted_even_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writer = ArtifactWriter(root)
            stale = GeneratedArtifact("docker/old.txt", "old\n")
            writer.write(
                (stale,),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )

            with self.assertRaisesRegex(GeneratedFileConflictError, "delete obsolete"):
                writer.write(
                    (),
                    config_hash="a" * 64,
                    results=self.results,
                    validation=self.validation,
                    environments=("dev", "staging", "production"),
                    force=True,
                )
            self.assertTrue((root / "generated" / "docker" / "old.txt").is_file())

    def test_duplicate_adapter_paths_are_rejected(self) -> None:
        artifact = GeneratedArtifact("shared/file", "one")
        with self.assertRaisesRegex(ManifestValidationError, "same path"):
            ArtifactWriter.collect((result("docker", (artifact,)), result("jenkins", (artifact,))))

    def test_verify_detects_missing_modified_and_untracked_files(self) -> None:
        artifacts = (
            GeneratedArtifact("a.txt", "a"),
            GeneratedArtifact("b.txt", "b"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = ArtifactWriter(root).write(
                artifacts,
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            (root / "generated" / "a.txt").write_text("changed", encoding="utf-8")
            (root / "generated" / "b.txt").unlink()
            (root / "generated" / "extra.txt").write_text("extra", encoding="utf-8")

            verification = manifest.verify(root)

            self.assertEqual(verification.modified, ("a.txt",))
            self.assertEqual(verification.missing, ("b.txt",))
            self.assertEqual(verification.untracked, ("extra.txt",))

    def test_verify_detects_mode_changes_and_symlink_replacements(self) -> None:
        artifacts = (
            GeneratedArtifact("docker/build.sh", "#!/bin/sh\n", mode=0o755),
            GeneratedArtifact("docker/data.txt", "same\n"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = ArtifactWriter(root).write(
                artifacts,
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            build_script = root / "generated" / "docker" / "build.sh"
            build_script.chmod(0o644)
            data = root / "generated" / "docker" / "data.txt"
            replacement = root / "replacement.txt"
            replacement.write_text("same\n", encoding="utf-8")
            data.unlink()
            data.symlink_to(replacement)

            verification = manifest.verify(root)

            plan = ArtifactWriter(root).plan(artifacts, manifest)

            self.assertEqual(
                verification.modified,
                ("docker/build.sh", "docker/data.txt"),
            )
            self.assertEqual(
                [item.path for item in plan.conflicts],
                ["docker/build.sh"],
            )
            self.assertEqual(
                [item.path for item in plan.unsafe],
                ["docker/data.txt"],
            )

    def test_nested_manifest_named_file_is_untracked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = ArtifactWriter(root).write(
                (GeneratedArtifact("a.txt", "a"),),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            nested = root / "generated" / "nested" / ".devops-stack-manifest.json"
            nested.parent.mkdir()
            nested.write_text("{}\n", encoding="utf-8")

            self.assertEqual(
                manifest.verify(root).untracked,
                ("nested/.devops-stack-manifest.json",),
            )

    def test_directory_symlink_inside_output_is_never_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            manifest = ArtifactWriter(root).write(
                (GeneratedArtifact("a.txt", "a"),),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            (root / "generated" / "linkdir").symlink_to(
                outside,
                target_is_directory=True,
            )

            self.assertEqual(manifest.verify(root).untracked, ("linkdir",))
            self.assertEqual(
                [item.path for item in ArtifactWriter(root).plan((), manifest).unowned],
                ["linkdir"],
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are unavailable")
    def test_nonregular_output_entry_is_untracked_and_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = ArtifactWriter(root).write(
                (GeneratedArtifact("a.txt", "a"),),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            os.mkfifo(root / "generated" / "pipe")

            self.assertEqual(manifest.verify(root).untracked, ("pipe",))
            self.assertEqual(
                [item.path for item in ArtifactWriter(root).plan((), manifest).unsafe],
                ["pipe"],
            )

    def test_manifest_rejects_duplicate_paths_and_inconsistent_passed_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = ArtifactWriter(root).write(
                (GeneratedArtifact("a.txt", "a"),),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            duplicate = dict(manifest.data)
            duplicate["files"] = [*manifest.data["files"], manifest.data["files"][0]]
            with self.assertRaisesRegex(ManifestValidationError, "unique"):
                GeneratedManifest.validate_data(duplicate)

            inconsistent = dict(manifest.data)
            inconsistent["validation"] = {
                **manifest.data["validation"],
                "passed": False,
            }
            with self.assertRaisesRegex(ManifestValidationError, "inconsistent"):
                GeneratedManifest.validate_data(inconsistent)

    def test_currentness_detects_desired_mode_change_with_identical_content(self) -> None:
        old = GeneratedArtifact("docker/build.sh", "#!/bin/sh\n", mode=0o644)
        new = GeneratedArtifact("docker/build.sh", "#!/bin/sh\n", mode=0o755)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ArtifactWriter(root).write(
                (old,),
                config_hash="a" * 64,
                results=self.results,
                validation=self.validation,
                environments=("dev", "staging", "production"),
            )
            composition = SimpleNamespace(
                project=root,
                loaded_config=SimpleNamespace(config_hash="a" * 64),
                results=self.results,
                artifacts=(new,),
            )

            _, report = generated_integrity_report(composition)

            check = next(
                item
                for item in report.checks
                if item.check == "generated.planned-content"
            )
            self.assertEqual(check.status, ValidationStatus.FAILED)
            self.assertEqual(check.details["paths"], ["docker/build.sh"])

    def test_non_directory_output_root_is_unsafe_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.write_text("user-owned\n", encoding="utf-8")
            writer = ArtifactWriter(root)
            artifact = GeneratedArtifact("docker/Dockerfile", "FROM scratch\n")

            plan = writer.plan((artifact,), previous=None)

            self.assertEqual(
                [(item.path, item.action) for item in plan.files],
                [("generated", "unsafe")],
            )
            with self.assertRaisesRegex(
                GeneratedFileConflictError,
                "generated",
            ):
                writer.write(
                    (artifact,),
                    config_hash="a" * 64,
                    results=self.results,
                    validation=self.validation,
                    environments=("dev", "staging", "production"),
                    force=True,
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "user-owned\n")


if __name__ == "__main__":
    unittest.main()
