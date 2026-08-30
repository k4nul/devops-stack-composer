from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.cli import build_parser, main
from devops_stack_composer.composition import Composition
from devops_stack_composer.composition import _preflight_local_build_output
from devops_stack_composer.config import load_config
from devops_stack_composer.errors import GeneratedFileConflictError
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tests" / "fixtures" / "configs" / "valid.yaml"


def fake_composition(project: Path, *, passed: bool = True) -> Composition:
    loaded = load_config(CONFIG)
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
        GeneratedArtifact("docker/Dockerfile", "FROM scratch\n", origins=("$.build",)),
        GeneratedArtifact("jenkins/Jenkinsfile", "pipeline {}\n", origins=("$.ci",)),
        GeneratedArtifact("k8s/base/service.yaml", "kind: Service\n", origins=("$.deployment",)),
    )
    results = tuple(
        AdapterResult(
            adapter=key,
            adapter_version="1.0.0",
            template_commit=lock.pin(key).commit,
            artifacts=tuple(
                artifact for artifact in artifacts if artifact.path.split("/", 1)[0] == (
                    "k8s" if key == "kubernetes" else key
                )
            ),
            contract=loaded.model.contract(),
        )
        for key in ("docker", "jenkins", "kubernetes")
    )
    validation = ValidationReport(
        (
            CheckResult(
                "fixture",
                ValidationStatus.PASSED if passed else ValidationStatus.FAILED,
                "fixture result",
            ),
        )
    )
    return Composition(project, loaded, lock, sources, results, artifacts, validation)


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), "devops-stack 0.1.0\n")

    def test_implicit_project_lock_cannot_cross_symlink_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            outside = Path(directory) / "outside-lock.json"
            outside.write_text(
                (ROOT / "templates.lock.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (root / "templates.lock.json").symlink_to(outside)
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                result = main(
                    [
                        "templates",
                        "list",
                        "--project",
                        str(root),
                        "--no-fetch",
                    ]
                )

            self.assertEqual(result, 2)
            self.assertIn("symbolic link", stderr.getvalue())

    def test_implicit_project_lock_directory_is_not_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates.lock.json").mkdir()
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                result = main(
                    [
                        "templates",
                        "list",
                        "--project",
                        str(root),
                        "--no-fetch",
                    ]
                )

            self.assertEqual(result, 2)
            self.assertIn("not a regular file", stderr.getvalue())

    def test_init_is_safe_and_marks_inference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
            (root / "app.py").write_text("# /health /ready PORT=8000\n", encoding="utf-8")

            self.assertEqual(main(["init", "--project", str(root)]), 0)
            config = root / "devops-stack.yaml"
            content = config.read_text(encoding="utf-8")
            self.assertIn("devops-stack.io/review-required: 'true'", content)
            self.assertEqual(main(["init", "--project", str(root)]), 2)

    def test_generate_previews_then_writes_only_on_explicit_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composition = fake_composition(root)
            output = io.StringIO()
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["generate", "--project", str(root)]), 0)
                self.assertFalse((root / "generated").exists())
                self.assertIn("PREVIEW", output.getvalue())

                self.assertEqual(
                    main(["generate", "--project", str(root), "--write"]),
                    0,
                )
            self.assertTrue((root / "generated" / ".devops-stack-manifest.json").is_file())

    def test_generate_preview_never_runs_an_optional_local_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for preview_mode in ([], ["--dry-run"]):
                with self.subTest(preview_mode=preview_mode):
                    with patch("devops_stack_composer.cli._composition") as composition:
                        stderr = io.StringIO()
                        with contextlib.redirect_stderr(stderr):
                            result = main(
                                [
                                    "generate",
                                    "--project",
                                    str(root),
                                    *preview_mode,
                                    "--build-image",
                                    "--image-tag",
                                    "local-smoke",
                                ]
                            )
                    self.assertEqual(result, 2)
                    self.assertIn(
                        "--build-image is only valid together with --write",
                        stderr.getvalue(),
                    )
                    composition.assert_not_called()
                    self.assertFalse((root / "generated").exists())

    def test_generate_blocks_user_edits_unless_force_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composition = fake_composition(root)
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                self.assertEqual(
                    main(["generate", "--project", str(root), "--write"]),
                    0,
                )
                dockerfile = root / "generated" / "docker" / "Dockerfile"
                dockerfile.write_text("# user change\n", encoding="utf-8")
                self.assertEqual(
                    main(["generate", "--project", str(root), "--write"]),
                    1,
                )
                self.assertEqual(dockerfile.read_text(encoding="utf-8"), "# user change\n")
                self.assertEqual(
                    main(
                        [
                            "generate",
                            "--project",
                            str(root),
                            "--write",
                            "--force",
                        ]
                    ),
                    0,
                )
            self.assertEqual(dockerfile.read_text(encoding="utf-8"), "FROM scratch\n")

    def test_generate_never_writes_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composition = fake_composition(root, passed=False)
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                self.assertEqual(
                    main(["generate", "--project", str(root), "--write"]),
                    1,
                )
            self.assertFalse((root / "generated").exists())

    def test_force_never_absorbs_unowned_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unowned = root / "generated" / "notes.txt"
            unowned.parent.mkdir(parents=True)
            unowned.write_text("user owned\n", encoding="utf-8")
            composition = fake_composition(root)
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                self.assertEqual(
                    main(
                        [
                            "generate",
                            "--project",
                            str(root),
                            "--write",
                            "--force",
                        ]
                    ),
                    1,
                )
            self.assertEqual(unowned.read_text(encoding="utf-8"), "user owned\n")
            self.assertFalse((root / "generated" / ".devops-stack-manifest.json").exists())

    def test_validate_checks_manifest_bytes_against_fresh_render(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composition = fake_composition(root)
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                self.assertEqual(
                    main(["generate", "--project", str(root), "--write"]),
                    0,
                )
                self.assertEqual(main(["validate", "--project", str(root)]), 0)
                (root / "generated" / "jenkins" / "Jenkinsfile").write_text(
                    "user edit\n", encoding="utf-8"
                )
                self.assertEqual(main(["validate", "--project", str(root)]), 1)

    def test_diff_is_a_gate_for_content_and_mode_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composition = fake_composition(root)
            with patch("devops_stack_composer.cli._composition", return_value=composition):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["diff", "--project", str(root)]), 1)
                    self.assertEqual(
                        main(["generate", "--project", str(root), "--write"]),
                        0,
                    )
                    self.assertEqual(main(["diff", "--project", str(root)]), 0)

                    dockerfile = root / "generated" / "docker" / "Dockerfile"
                    dockerfile.chmod(0o755)
                    self.assertEqual(main(["diff", "--project", str(root)]), 1)

    def test_local_build_preflight_blocks_unowned_generated_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "generated"
            generated.mkdir()
            (generated / "unowned-secrets.txt").write_text(
                "must not enter an image\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                GeneratedFileConflictError,
                "blocked.*without an ownership manifest",
            ):
                _preflight_local_build_output(root)

    def test_human_explain_redacts_embedded_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = CONFIG.read_text(encoding="utf-8").replace(
                "python -m compileall app",
                (
                    "curl --user alice:swordfish "
                    "https://bob:hunter2@example.invalid/build"
                ),
            )
            (root / "devops-stack.yaml").write_text(config, encoding="utf-8")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "explain",
                            "--project",
                            str(root),
                            "config:$.application.buildCommand",
                        ]
                    ),
                    0,
                )

            rendered = output.getvalue()
            self.assertNotIn("alice:swordfish", rendered)
            self.assertNotIn("bob:hunter2", rendered)
            self.assertIn("<redacted>", rendered)

    def test_execution_and_evidence_subcommands_have_closed_argument_shapes(self) -> None:
        execute = build_parser().parse_args(
            [
                "execute",
                "--environment",
                "staging",
                "--profile",
                "kind-e2e",
                "--keep-resources",
                "--json",
            ]
        )
        inspect = build_parser().parse_args(
            ["artifact", "inspect", "--run", "20260830T120000Z-abcdef012345"]
        )
        verify = build_parser().parse_args(
            [
                "artifact",
                "verify",
                "--artifact",
                "out/execution/artifact.json",
                "--sbom",
                "out/supply-chain/sbom.json",
            ]
        )
        cluster = build_parser().parse_args(
            ["cluster", "kind", "destroy", "--run", "20260830T120000Z-abcdef012345"]
        )
        report = build_parser().parse_args(
            ["report", "--run", "20260830T120000Z-abcdef012345", "--json"]
        )

        self.assertEqual(execute.profile, "kind-e2e")
        self.assertTrue(execute.keep_resources)
        self.assertEqual(inspect.artifact_command, "inspect")
        self.assertEqual(verify.artifact, "out/execution/artifact.json")
        self.assertEqual(cluster.kind_command, "destroy")
        self.assertEqual(report.run, "20260830T120000Z-abcdef012345")


if __name__ == "__main__":
    unittest.main()
