from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from devops_stack_composer.release_assets import (
    ReleaseAssemblyRequest,
    ReleaseAssetError,
    ReleaseMaterialRequest,
    assemble_release_assets,
    prepare_release_materials,
    verify_release_assets,
)
from tests.test_execution_bundle import BundleFixture, RUN_ID, SOURCE_REVISION


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
REPOSITORY = "https://github.com/k4nul/devops-stack-composer"


def _wheel(path: Path, extra_metadata: str = "") -> None:
    metadata = (
        f"Metadata-Version: 2.1\nName: devops-stack-composer\nVersion: {VERSION}\n"
        "Classifier: Programming Language :: Python :: 3\n"
        f"Classifier: Programming Language :: Python :: 3.12\n{extra_metadata}\n"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"devops_stack_composer-{VERSION}.dist-info/METADATA",
            metadata,
        )
        archive.writestr("devops_stack_composer/__init__.py", "__version__ = '0.2.0'\n")


def _sdist(path: Path, extra_metadata: str = "") -> None:
    metadata = (
        f"Metadata-Version: 2.1\nName: devops-stack-composer\nVersion: {VERSION}\n"
        "Classifier: Programming Language :: Python :: 3\n"
        f"Classifier: Programming Language :: Python :: 3.12\n{extra_metadata}\n"
    ).encode()
    root = f"devops_stack_composer-{VERSION}"
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        info = tarfile.TarInfo(f"{root}/PKG-INFO")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        BundleFixture(self.project)
        (self.project / "dist").mkdir()
        self.wheel = (
            self.project / "dist" / f"devops_stack_composer-{VERSION}-py3-none-any.whl"
        )
        self.sdist = self.project / "dist" / f"devops_stack_composer-{VERSION}.tar.gz"
        _wheel(self.wheel)
        _sdist(self.sdist)
        inputs = self.project / "inputs"
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

    def materials(
        self,
        output: str = "dist/materials",
        *,
        commit: str = SOURCE_REVISION,
    ):
        return prepare_release_materials(
            ReleaseMaterialRequest(
                project=self.project,
                output_directory=output,
                version=VERSION,
                source_commit=commit,
                source_repository=REPOSITORY,
                created_at="2026-08-30T12:00:00+00:00",
                wheel_path=self.wheel.relative_to(self.project).as_posix(),
                sdist_path=self.sdist.relative_to(self.project).as_posix(),
            )
        )

    def request(self, output: str, *, commit: str = SOURCE_REVISION):
        return ReleaseAssemblyRequest(
            project=self.project,
            output_directory=output,
            version=VERSION,
            source_commit=commit,
            wheel_path=self.wheel.relative_to(self.project).as_posix(),
            sdist_path=self.sdist.relative_to(self.project).as_posix(),
            configuration_schema_path="inputs/devops-stack.schema.json",
            report_schema_path="inputs/execution-report.schema.json",
            execution_evidence_schema_path="inputs/execution-evidence.schema.json",
            example_config_path="inputs/example.yaml",
            package_sbom_path="dist/materials/package.spdx.json",
            provenance_verification_path=(
                "dist/materials/provenance-verification.json"
            ),
            evidence_run_id=RUN_ID,
        )

    def test_prepares_digest_bound_materials_and_closed_release_assets(self) -> None:
        materials = self.materials()
        sbom = json.loads(materials.package_sbom.read_text(encoding="utf-8"))
        provenance = json.loads(
            materials.provenance_verification.read_text(encoding="utf-8")
        )

        self.assertEqual(sbom["creationInfo"]["created"], "2026-08-30T12:00:00Z")
        self.assertFalse(provenance["cryptographicallyVerified"])
        self.assertEqual(provenance["mode"], "file-provenance")
        self.assertEqual(
            {item["name"]: item["sha256"] for item in provenance["subjects"]},
            {
                self.wheel.name: hashlib.sha256(self.wheel.read_bytes()).hexdigest(),
                self.sdist.name: hashlib.sha256(self.sdist.read_bytes()).hexdigest(),
            },
        )

        assembled = assemble_release_assets(self.request("release/v0.2.0"))
        verified = verify_release_assets(
            self.project,
            "release/v0.2.0",
            expected_version=VERSION,
            expected_commit=SOURCE_REVISION,
        )

        self.assertTrue(assembled.passed)
        self.assertEqual(verified.manifest.evidence_run_id, RUN_ID)
        self.assertEqual(
            {item.role for item in verified.manifest.assets},
            {
                "wheel",
                "sdist",
                "configuration-schema",
                "report-schema",
                "execution-evidence-schema",
                "example-config",
                "example-evidence",
                "package-sbom",
                "provenance-verification",
            },
        )

    def test_evidence_commit_mismatch_fails_closed(self) -> None:
        self.materials(commit="e" * 40)
        with self.assertRaisesRegex(ReleaseAssetError, "RELEASE_EVIDENCE_MISMATCH"):
            assemble_release_assets(self.request("release/mismatch", commit="e" * 40))
        self.assertFalse((self.project / "release" / "mismatch").exists())

    def test_tampering_fails_closed(self) -> None:
        self.materials()
        assemble_release_assets(self.request("release/tampered"))
        packaged_wheel = self.project / "release" / "tampered" / self.wheel.name
        packaged_wheel.write_bytes(packaged_wheel.read_bytes() + b"changed")
        with self.assertRaisesRegex(ReleaseAssetError, "RELEASE_CHECKSUM_MISMATCH"):
            verify_release_assets(self.project, "release/tampered")

    def test_outputs_are_never_overwritten(self) -> None:
        self.materials()
        with self.assertRaisesRegex(ReleaseAssetError, "RELEASE_OUTPUT_EXISTS"):
            self.materials()
        assemble_release_assets(self.request("release/once"))
        with self.assertRaisesRegex(ReleaseAssetError, "RELEASE_OUTPUT_EXISTS"):
            assemble_release_assets(self.request("release/once"))

    def test_package_archive_traversal_is_rejected_before_output(self) -> None:
        with zipfile.ZipFile(self.wheel, "a") as archive:
            archive.writestr("../outside.txt", "escape")

        with self.assertRaisesRegex(ReleaseAssetError, "RELEASE_ARCHIVE_UNSAFE"):
            self.materials()

        self.assertFalse((self.project / "dist" / "materials").exists())

    def test_repeated_package_identity_header_is_rejected(self) -> None:
        _wheel(self.wheel, "Name: substituted-distribution\n")

        with self.assertRaisesRegex(ReleaseAssetError, "exactly one Name header"):
            self.materials()

        self.assertFalse((self.project / "dist" / "materials").exists())


if __name__ == "__main__":
    unittest.main()
