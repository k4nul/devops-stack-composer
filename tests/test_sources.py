from __future__ import annotations

import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from devops_stack_composer.errors import SourceResolutionError
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.sources import ENVIRONMENT_PATHS, REQUIRED_MARKERS, SourceResolver


ROOT = Path(__file__).resolve().parents[1]


def make_template(path: Path, key: str) -> str:
    path.mkdir(parents=True)
    for marker in REQUIRED_MARKERS[key]:
        target = path / marker
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "--quiet", "-m", "test fixture"],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class SourceResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = TemplateLock.load(ROOT / "templates.lock.json")

    def test_explicit_path_has_highest_priority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            explicit = base / "explicit"
            environment = base / "environment"
            make_template(explicit, "docker")
            make_template(environment, "docker")
            resolver = SourceResolver(
                self.lock,
                explicit_paths={"docker": explicit},
                environment={ENVIRONMENT_PATHS["docker"]: str(environment)},
                default_base=base / "defaults",
                cache_root=base / "cache",
            )

            result = resolver.resolve("docker", fetch=False)

            self.assertEqual(result.path, explicit.resolve())
            self.assertEqual(result.origin, "cli")

    def test_environment_path_precedes_default_and_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            environment = base / "environment"
            default = base / "defaults" / self.lock.pin("jenkins").name
            make_template(environment, "jenkins")
            make_template(default, "jenkins")
            resolver = SourceResolver(
                self.lock,
                environment={ENVIRONMENT_PATHS["jenkins"]: str(environment)},
                default_base=base / "defaults",
                cache_root=base / "cache",
            )

            result = resolver.resolve("jenkins", fetch=False)

            self.assertEqual(result.path, environment.resolve())
            self.assertEqual(result.origin, "environment")

    def test_default_path_precedes_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pin = self.lock.pin("kubernetes")
            default = base / "defaults" / pin.name
            cached = base / "cache" / pin.name / pin.commit
            make_template(default, "kubernetes")
            make_template(cached, "kubernetes")
            resolver = SourceResolver(
                self.lock,
                environment={},
                default_base=base / "defaults",
                cache_root=base / "cache",
            )

            result = resolver.resolve("kubernetes", fetch=False)

            self.assertEqual(result.path, default.resolve())
            self.assertEqual(result.origin, "default-local")

    def test_missing_markers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid"
            invalid.mkdir()
            resolver = SourceResolver(
                self.lock,
                explicit_paths={"docker": invalid},
                environment={},
                default_base=Path(directory) / "defaults",
                cache_root=Path(directory) / "cache",
            )

            with self.assertRaisesRegex(SourceResolutionError, "missing required files"):
                resolver.resolve("docker", fetch=False)

    def test_docker_push_entrypoint_is_a_required_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "docker"
            make_template(source, "docker")
            (source / "scripts" / "push-image.sh").unlink()
            resolver = SourceResolver(
                self.lock,
                explicit_paths={"docker": source},
                environment={},
                default_base=base / "defaults",
                cache_root=base / "cache",
            )

            with self.assertRaisesRegex(
                SourceResolutionError,
                "scripts/push-image.sh",
            ):
                resolver.resolve("docker", fetch=False)

    def test_all_directly_invoked_upstream_scripts_are_required_markers(self) -> None:
        expected = {
            "docker": {
                "scripts/validate-build-plan.sh",
                "scripts/build-image.sh",
                "scripts/push-image.sh",
            },
            "jenkins": {
                "scripts/show-jenkins-job-plan.ps1",
                "scripts/show-service-pipeline-plan.ps1",
                "scripts/export-jenkins-job-dsl.ps1",
            },
            "kubernetes": {
                "scripts/show-profile-catalog.ps1",
                "scripts/show-environment-preset-plan.ps1",
                "scripts/show-render-matrix.ps1",
                "scripts/show-platform-plan.ps1",
                "scripts/render-platform-assets.ps1",
                "scripts/validate-rendered-bundle.ps1",
                "scripts/validate-kubernetes-security-baseline.ps1",
                "scripts/check-placeholders.ps1",
            },
        }

        for key, scripts in expected.items():
            self.assertLessEqual(scripts, set(REQUIRED_MARKERS[key]))

    def test_fetch_disabled_reports_every_search_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            resolver = SourceResolver(
                self.lock,
                environment={},
                default_base=base / "defaults",
                cache_root=base / "cache",
            )

            with self.assertRaisesRegex(SourceResolutionError, "without network fetch"):
                resolver.resolve("docker", fetch=False)

    def test_default_cache_honors_environment_without_reading_process_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resolver = SourceResolver(
                self.lock,
                environment={"DEVOPS_STACK_CACHE": directory, "UNRELATED_TOKEN": "sensitive"},
                default_base=Path(directory) / "defaults",
            )

            self.assertEqual(resolver.cache_root, Path(directory))
            self.assertNotIn("UNRELATED_TOKEN", repr(resolver.cache_root))

    def test_cache_path_defensively_rejects_traversal_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            resolver = SourceResolver(
                self.lock,
                environment={},
                default_base=Path(directory) / "defaults",
                cache_root=Path(directory) / "cache",
            )
            unsafe_pin = replace(self.lock.pin("docker"), name="../../escaped")

            with self.assertRaisesRegex(SourceResolutionError, "unsafe cache path"):
                resolver._cache_path(unsafe_pin)


if __name__ == "__main__":
    unittest.main()
