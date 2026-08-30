from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.build_once import (
    BuildInvocationGuard,
    BuildOnceError,
    BuildOnceExecutor,
    BuildRequest,
    CommandResult,
)


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class FakeRunner:
    def __init__(self, manifests: list[bytes], *, metadata_digest: str | None = None):
        self.manifests = list(manifests)
        self.metadata_digest = metadata_digest
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, *, cwd, environment=None, timeout=None):
        value = tuple(command)
        self.commands.append(value)
        if value[:3] == ("docker", "buildx", "build"):
            metadata_path = Path(value[value.index("--metadata-file") + 1])
            expected = self.metadata_digest or digest(self.manifests[0])
            metadata_path.write_text(
                json.dumps(
                    {
                        "containerimage.digest": expected,
                        "containerimage.descriptor": {
                            "digest": expected,
                            "mediaType": json.loads(self.manifests[0])["mediaType"],
                            "size": len(self.manifests[0]),
                        },
                    }
                ),
                encoding="utf-8",
            )
            return CommandResult(0, b"built", b"")
        if value[:5] == (
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            "--raw",
        ):
            if not self.manifests:
                raise AssertionError("unexpected registry inspection")
            return CommandResult(0, self.manifests.pop(0), b"")
        raise AssertionError(value)


class BuildOnceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.dockerfile = self.project / "Dockerfile"
        self.dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        self.run_directory = self.project / ".devops-stack" / "runs" / "test"
        self.manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:" + "c" * 64,
                    "size": 10,
                },
                "layers": [],
            },
            separators=(",", ":"),
        ).encode()

    def request(self) -> BuildRequest:
        return BuildRequest(
            project=self.project,
            context=self.project,
            dockerfile=self.dockerfile,
            repository="127.0.0.1:5001/example/service",
            tag="run-123",
            platforms=("linux/amd64",),
            metadata_path=self.run_directory / "build-metadata.json",
            invocation_marker=self.run_directory / "build-invocation.count",
            oci_title="service",
            oci_description="service image",
            oci_source="https://github.com/example/service",
            oci_revision="a" * 40,
            oci_created="2026-01-01T00:00:00Z",
        )

    def test_builds_and_pushes_once_then_resolves_exact_registry_bytes(self) -> None:
        runner = FakeRunner([self.manifest])

        result = BuildOnceExecutor(runner).execute(self.request())

        build_commands = [command for command in runner.commands if command[:3] == ("docker", "buildx", "build")]
        self.assertEqual(len(build_commands), 1)
        self.assertEqual(result.build_invocation_count, 1)
        self.assertEqual(result.digest, digest(self.manifest))
        self.assertEqual(result.immutable_reference, f"127.0.0.1:5001/example/service@{digest(self.manifest)}")
        self.assertEqual(result.platforms[0].digest, result.digest)
        self.assertIn("--push", build_commands[0])
        self.assertIn("--metadata-file", build_commands[0])
        self.assertNotIn("--load", build_commands[0])
        self.assertEqual(
            build_commands[0][build_commands[0].index("--sbom") + 1], "false"
        )
        self.assertEqual(
            build_commands[0][build_commands[0].index("--provenance") + 1],
            "false",
        )

    def test_persistent_guard_rejects_second_build_before_subprocess(self) -> None:
        runner = FakeRunner([self.manifest])
        executor = BuildOnceExecutor(runner)
        request = self.request()
        executor.execute(request)

        with self.assertRaisesRegex(BuildOnceError, "BUILD_INVOKED_MORE_THAN_ONCE"):
            executor.execute(request)

        build_commands = [command for command in runner.commands if command[:3] == ("docker", "buildx", "build")]
        self.assertEqual(len(build_commands), 1)

    def test_registry_digest_mismatch_fails(self) -> None:
        runner = FakeRunner([self.manifest], metadata_digest="sha256:" + "d" * 64)

        with self.assertRaisesRegex(BuildOnceError, "ARTIFACT_DIGEST_MISMATCH"):
            BuildOnceExecutor(runner).execute(self.request())

    def test_resolves_platform_manifest_from_attested_index(self) -> None:
        platform_manifest = self.manifest
        platform_digest = digest(platform_manifest)
        index = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": platform_digest,
                        "size": len(platform_manifest),
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:" + "e" * 64,
                        "size": 1,
                        "platform": {"os": "unknown", "architecture": "unknown"},
                        "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                    },
                ],
            },
            separators=(",", ":"),
        ).encode()
        runner = FakeRunner([index, platform_manifest])

        result = BuildOnceExecutor(runner).execute(self.request())

        self.assertEqual(result.digest, digest(index))
        self.assertEqual(result.platforms[0].digest, platform_digest)
        self.assertEqual(result.platforms[0].config_digest, "sha256:" + "c" * 64)

    def test_tag_movement_is_detected_without_rebuilding(self) -> None:
        runner = FakeRunner([self.manifest])
        executor = BuildOnceExecutor(runner)
        result = executor.execute(self.request())
        runner.manifests.append(b'{"different":true}')

        with self.assertRaisesRegex(BuildOnceError, "REGISTRY_TAG_MOVED"):
            executor.verify_tag_unchanged(result, project=self.project)

        build_commands = [command for command in runner.commands if command[:3] == ("docker", "buildx", "build")]
        self.assertEqual(len(build_commands), 1)

    def test_guard_rejects_existing_marker(self) -> None:
        marker = self.run_directory / "count"
        marker.parent.mkdir(parents=True)
        marker.write_text("1\n", encoding="ascii")

        with self.assertRaisesRegex(BuildOnceError, "BUILD_INVOKED_MORE_THAN_ONCE"):
            BuildInvocationGuard(marker).claim()

    def test_rejects_reference_and_output_paths_outside_project(self) -> None:
        request = self.request()
        invalid_reference = BuildRequest(
            **{
                **request.__dict__,
                "repository": "https://user:password@registry.example/service",
            }
        )
        with self.assertRaisesRegex(BuildOnceError, "ARTIFACT_REFERENCE_INVALID"):
            BuildOnceExecutor(FakeRunner([self.manifest])).execute(invalid_reference)

        outside = self.project.parent / "outside-build-metadata.json"
        escaped = BuildRequest(**{**request.__dict__, "metadata_path": outside})
        with self.assertRaisesRegex(BuildOnceError, "UNSAFE_BUILD_PATH"):
            BuildOnceExecutor(FakeRunner([self.manifest])).execute(escaped)


if __name__ == "__main__":
    unittest.main()
