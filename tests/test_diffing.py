from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.diffing import diff_artifacts, render_human, render_json
from devops_stack_composer.manifest import ArtifactWriter
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus



def adapter_result(name: str) -> AdapterResult:
    prefix = {"docker": "d", "jenkins": "e", "kubernetes": "f"}[name]
    return AdapterResult(name, "1.0.0", prefix * 40, (), {})


def write_manifest(root: Path, artifacts: tuple[GeneratedArtifact, ...]) -> None:
    validation = ValidationReport(
        (CheckResult("fixture", ValidationStatus.PASSED, "passed"),)
    )
    results = tuple(
        adapter_result(name) for name in ("docker", "jenkins", "kubernetes")
    )
    ArtifactWriter(root).write(
        artifacts,
        config_hash="a" * 64,
        results=results,
        validation=validation,
        environments=("dev", "staging", "production"),
    )


class DiffTests(unittest.TestCase):
    def test_generated_diff_reports_added_modified_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifest(
                root,
                (
                    GeneratedArtifact("docker/same", "same\n"),
                    GeneratedArtifact("docker/changed", "before\n"),
                ),
            )
            artifacts = (
                GeneratedArtifact("docker/same", "same\n"),
                GeneratedArtifact("docker/changed", "after\n"),
                GeneratedArtifact("docker/new", "new\n"),
            )

            diffs = diff_artifacts(root, artifacts)

            self.assertEqual([item.status for item in diffs], ["modified", "added", "unchanged"])
            self.assertIn("-before", render_human(diffs))
            parsed = json.loads(render_json(diffs))
            self.assertEqual(parsed[0]["path"], "docker/changed")

    def test_project_diff_maps_conventional_root_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM old\n", encoding="utf-8")
            (root / "Dockerfile.dockerignore").write_text("old\n", encoding="utf-8")

            diffs = diff_artifacts(
                root,
                (
                    GeneratedArtifact("docker/Dockerfile", "FROM new\n"),
                    GeneratedArtifact("docker/Dockerfile.dockerignore", "new\n"),
                ),
                against="project",
            )

            self.assertEqual(diffs[0].compared_path, "Dockerfile")
            self.assertEqual(diffs[1].compared_path, "Dockerfile.dockerignore")
            self.assertTrue(all(item.status == "modified" for item in diffs))

    def test_mode_only_drift_is_reported_as_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_manifest(
                root,
                (GeneratedArtifact("docker/build.sh", "#!/bin/sh\n", mode=0o644),),
            )

            diffs = diff_artifacts(
                root,
                (GeneratedArtifact("docker/build.sh", "#!/bin/sh\n", mode=0o755),),
            )

            self.assertEqual(diffs[0].status, "modified")
            self.assertEqual(diffs[0].actual_mode, "0644")
            self.assertEqual(diffs[0].expected_mode, "0755")
            self.assertIn("[mode 0644 -> 0755]", render_human(diffs))
            parsed = json.loads(render_json(diffs))
            self.assertEqual(parsed[0]["actualMode"], "0644")
            self.assertEqual(parsed[0]["expectedMode"], "0755")

    def test_generated_diff_without_manifest_marks_every_entry_unowned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / "generated" / "docker" / "Dockerfile"
            dockerfile.parent.mkdir(parents=True)
            dockerfile.write_text("FROM scratch\n", encoding="utf-8")
            dockerfile.chmod(0o644)
            (root / "generated" / "EXTRA.txt").write_text(
                "not composer-owned\n",
                encoding="utf-8",
            )

            diffs = diff_artifacts(
                root,
                (GeneratedArtifact("docker/Dockerfile", "FROM scratch\n"),),
            )

            self.assertEqual(
                [(item.path, item.status) for item in diffs],
                [
                    ("EXTRA.txt", "unowned"),
                    ("docker/Dockerfile", "unowned"),
                ],
            )

    def test_generated_diff_rejects_a_non_directory_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "generated").write_text("user-owned\n", encoding="utf-8")

            diffs = diff_artifacts(
                root,
                (GeneratedArtifact("docker/Dockerfile", "FROM scratch\n"),),
            )

            self.assertEqual(
                [(item.path, item.status) for item in diffs],
                [("generated", "unsafe")],
            )

    def test_diff_outputs_redact_sensitive_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "generated" / "docker" / "values.env"
            target.parent.mkdir(parents=True)
            target.write_text("API_TOKEN=old-secret\nSAFE=old\n", encoding="utf-8")

            diffs = diff_artifacts(
                root,
                (GeneratedArtifact("docker/values.env", "API_TOKEN=new-secret\nSAFE=new\n"),),
            )
            human = render_human(diffs)
            machine = render_json(diffs)

            self.assertNotIn("old-secret", human + machine)
            self.assertNotIn("new-secret", human + machine)
            self.assertIn("SAFE=new", human)

    def test_diff_redacts_headers_urls_blocks_docker_env_and_json_commas(self) -> None:
        baseline = """curl -H "Authorization: Bearer abcdefghi"
Authorization: Basic dXNlcjpwYXNz
Proxy-Authorization: Digest username="admin", response="digest-old"
curl --user admin:swordfish https://example.invalid
curl -ucompact:old-secret https://example.invalid
url=https://user:pass@example.invalid/x
PASSWORD: |
  line-secret
ENV TOKEN=old-token
{"token": "json-old", "safe": true}
"""
        planned = baseline.replace("abcdefghi", "newbearer").replace(
            "old-token", "new-token"
        ).replace("dXNlcjpwYXNz", "bmV3OnBhc3M=").replace(
            "digest-old", "digest-new"
        ).replace("admin:swordfish", "newuser:newpass").replace(
            "compact:old-secret", "compact:new-secret"
        ).replace(
            '"safe": true', '"safe": false'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "generated" / "docker" / "secrets.txt"
            target.parent.mkdir(parents=True)
            target.write_text(baseline, encoding="utf-8")

            rendered = render_human(
                diff_artifacts(
                    root,
                    (GeneratedArtifact("docker/secrets.txt", planned),),
                )
            )

        for secret in (
            "abcdefghi",
            "newbearer",
            "user:pass",
            "line-secret",
            "old-token",
            "new-token",
            "json-old",
            "dXNlcjpwYXNz",
            "bmV3OnBhc3M=",
            "digest-old",
            "digest-new",
            "admin:swordfish",
            "newuser:newpass",
            "compact:old-secret",
            "compact:new-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn('"token": <redacted>, "safe": true}', rendered)

    def test_generated_diff_reports_retired_manifest_paths_as_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validation = ValidationReport(
                (CheckResult("fixture", ValidationStatus.PASSED, "passed"),)
            )
            results = tuple(
                adapter_result(name)
                for name in ("docker", "jenkins", "kubernetes")
            )
            ArtifactWriter(root).write(
                (
                    GeneratedArtifact("docker/current", "same\n"),
                    GeneratedArtifact("docker/retired", "old\n"),
                ),
                config_hash="a" * 64,
                results=results,
                validation=validation,
                environments=("dev", "staging", "production"),
            )

            diffs = diff_artifacts(
                root,
                (GeneratedArtifact("docker/current", "same\n"),),
            )

            self.assertEqual(
                [(item.path, item.status) for item in diffs],
                [("docker/current", "unchanged"), ("docker/retired", "removed")],
            )

    def test_generated_diff_reports_unowned_and_unsafe_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = GeneratedArtifact("docker/current", "same\n")
            validation = ValidationReport(
                (CheckResult("fixture", ValidationStatus.PASSED, "passed"),)
            )
            results = tuple(
                adapter_result(name)
                for name in ("docker", "jenkins", "kubernetes")
            )
            ArtifactWriter(root).write(
                (artifact,),
                config_hash="a" * 64,
                results=results,
                validation=validation,
                environments=("dev", "staging", "production"),
            )
            (root / "generated" / "UNOWNED.txt").write_text(
                "user file\n",
                encoding="utf-8",
            )
            (root / "generated" / "unsafe-link").symlink_to(
                root / "outside.txt"
            )

            diffs = diff_artifacts(root, (artifact,))

            self.assertEqual(
                [(item.path, item.status) for item in diffs],
                [
                    ("UNOWNED.txt", "unowned"),
                    ("docker/current", "unchanged"),
                    ("unsafe-link", "unsafe"),
                ],
            )


if __name__ == "__main__":
    unittest.main()
