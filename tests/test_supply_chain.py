from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from devops_stack_composer.evidence_validation import (
    validate_provenance_subject,
    validate_sbom_subject,
    validate_scan_subject,
)
from devops_stack_composer.errors import UnsafePathError
from devops_stack_composer.execution_models import ResolvedArtifact
from devops_stack_composer.filesystem import sha256_file
from devops_stack_composer.policies import VulnerabilityPolicy
from devops_stack_composer.supply_chain import (
    CHECKSUM_ONLY_VERIFICATION_STATUS,
    FILE_ONLY_EXTENSION,
    SUBJECT_ANNOTATION_PREFIX,
    SupplyChainError,
    SupplyChainGenerator,
    create_provenance_statement,
    validate_provenance_statement,
    verify_provenance_evidence,
    verify_sbom_evidence,
    verify_vulnerability_evidence,
)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
PLATFORM_DIGEST = "sha256:" + "c" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64
REVISION = "e" * 40
PLAN_HASH = "f" * 64
REPOSITORY = "registry.example/team/service"
REFERENCE = f"{REPOSITORY}@{DIGEST}"
OTHER_REFERENCE = f"{REPOSITORY}@{OTHER_DIGEST}"
GENERATED_AT = datetime(2026, 8, 30, 1, 2, 3, tzinfo=timezone.utc)


def artifact() -> ResolvedArtifact:
    return ResolvedArtifact(
        immutable_image_reference=REFERENCE,
        repository=REPOSITORY,
        tag="run-1",
        manifest_digest=DIGEST,
        platform_digest=PLATFORM_DIGEST,
        media_type="application/vnd.oci.image.manifest.v1+json",
        architecture="amd64",
        operating_system="linux",
        image_size=1024,
        config_digest=CONFIG_DIGEST,
        source_revision=REVISION,
        build_plan_hash=PLAN_HASH,
        created_by_tool_version="0.2.0",
        registry_endpoint="registry.example",
        build_invocation_count=1,
    )


def spdx_fixture() -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "service",
        "documentNamespace": "https://anchore.example/syft/service",
        "creationInfo": {
            "created": "2026-08-30T01:02:03Z",
            "creators": ["Organization: Anchore, Inc", "Tool: syft-1.44.0"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-apk-busybox",
                "name": "busybox",
                "versionInfo": "1.37.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "GPL-2.0-only",
                "copyrightText": "NOASSERTION",
            }
        ],
    }


def trivy_fixture() -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactName": REFERENCE,
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": DIGEST},
        "Trivy": {"Version": "0.69.0"},
        "Results": [
            {
                "Target": "service (alpine 3.22)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "busybox",
                        "InstalledVersion": "1.37.0-r1",
                        "FixedVersion": "1.37.0-r2",
                        "Status": "fixed",
                        "Severity": "LOW",
                    }
                ],
            }
        ],
    }


def trivy_version_fixture() -> dict[str, object]:
    return {
        "Version": "0.69.0",
        "VulnerabilityDB": {
            "Version": 2,
            "UpdatedAt": "2026-08-30T00:00:00.123456789Z",
            "NextUpdate": "2026-08-31T00:00:00Z",
            "DownloadedAt": "2026-08-30T00:01:00Z",
        },
    }


class FixtureRunner:
    def __init__(
        self,
        *,
        sbom: dict[str, object] | None = None,
        scan: dict[str, object] | None = None,
        version: dict[str, object] | None = None,
    ) -> None:
        self.sbom = sbom if sbom is not None else spdx_fixture()
        self.scan = scan if scan is not None else trivy_fixture()
        self.version = version if version is not None else trivy_version_fixture()
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(
        self, command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        value = tuple(command)
        self.calls.append((value, dict(kwargs)))
        if value == ("syft", REFERENCE, "-o", "spdx-json@2.3"):
            output = self.sbom
        elif value == ("trivy", "image", "--format", "json", REFERENCE):
            output = self.scan
        elif value == ("trivy", "version", "--format", "json"):
            output = self.version
        else:
            raise AssertionError(f"unexpected command: {value}")
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")


class SupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_root = Path(self.temporary.name)

    def generate(
        self,
        runner: FixtureRunner | None = None,
        *,
        policy: VulnerabilityPolicy | None = None,
    ):
        runner = runner or FixtureRunner()
        evidence = SupplyChainGenerator(
            runner,
            clock=lambda: GENERATED_AT,
        ).generate(
            run_root=self.run_root,
            artifact=artifact(),
            policy=policy or VulnerabilityPolicy(),
            builder_id="https://ci.example/builders/local",
            build_started_on="2026-08-30T01:00:00Z",
            build_finished_on="2026-08-30T01:01:00Z",
        )
        return runner, evidence

    def rewrite_json(self, relative_path: str, value: object) -> str:
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        (self.run_root / relative_path).write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    def test_generates_digest_bound_evidence_without_building(self) -> None:
        runner, evidence = self.generate()

        self.assertEqual(
            [call[0] for call in runner.calls],
            [
                ("syft", REFERENCE, "-o", "spdx-json@2.3"),
                ("trivy", "image", "--format", "json", REFERENCE),
                ("trivy", "version", "--format", "json"),
            ],
        )
        for command, options in runner.calls:
            self.assertFalse(options["shell"], command)
            self.assertTrue(options["capture_output"], command)
            self.assertTrue(options["text"], command)
            self.assertFalse(options["check"], command)
        self.assertFalse(any("build" in argument for call, _ in runner.calls for argument in call))
        self.assertEqual(evidence.artifact_digest, DIGEST)
        self.assertEqual(evidence.sbom_generator, "syft-1.44.0")
        self.assertEqual(evidence.scanner_version, "0.69.0")
        self.assertEqual(evidence.policy_result["evaluatedCount"], 1)
        self.assertTrue(evidence.policy_result["passed"])
        self.assertEqual(evidence.attestation_subject, REFERENCE)
        self.assertEqual(evidence.verification_status, CHECKSUM_ONLY_VERIFICATION_STATUS)
        for relative_path, checksum in (
            (evidence.sbom_path, evidence.sbom_hash),
            (evidence.vulnerability_report_path, evidence.vulnerability_report_hash),
            (evidence.provenance_path, evidence.provenance_hash),
        ):
            self.assertEqual(sha256_file(self.run_root / relative_path), checksum)

        sbom = json.loads((self.run_root / evidence.sbom_path).read_text())
        self.assertIn(
            {
                "annotationDate": "2026-08-30T01:02:03Z",
                "annotationType": "OTHER",
                "annotator": "Tool: devops-stack-composer-0.2.0",
                "comment": SUBJECT_ANNOTATION_PREFIX + REFERENCE,
            },
            sbom["annotations"],
        )
        validate_sbom_subject(sbom, immutable_reference=REFERENCE)
        validate_scan_subject(
            json.loads((self.run_root / evidence.vulnerability_report_path).read_text()),
            expected_digest=DIGEST,
        )
        provenance = json.loads((self.run_root / evidence.provenance_path).read_text())
        self.assertEqual(provenance["subject"][0]["digest"], {"sha256": "a" * 64})
        self.assertEqual(
            provenance["predicate"]["buildDefinition"]["externalParameters"],
            {
                "artifactReference": REFERENCE,
                "buildPlanHash": PLAN_HASH,
                "sourceRevision": REVISION,
            },
        )
        file_evidence = provenance["predicate"][FILE_ONLY_EXTENSION]
        self.assertEqual(file_evidence["mode"], "file-only")
        self.assertFalse(file_evidence["signatureGenerated"])
        self.assertFalse(file_evidence["signatureVerified"])
        self.assertFalse(file_evidence["attachedToRegistry"])
        self.assertFalse(file_evidence["cryptographicallyVerified"])
        self.assertFalse(file_evidence["checksumIsSignature"])
        self.assertNotIn("signatures", provenance)
        validate_provenance_subject(
            provenance,
            repository=REPOSITORY,
            expected_digest=DIGEST,
        )

    def test_policy_failure_is_preserved_as_valid_evidence(self) -> None:
        _, evidence = self.generate(
            policy=VulnerabilityPolicy(
                severities=("LOW",),
                maximum_allowed=0,
                ignore_unfixed=False,
            )
        )

        self.assertFalse(evidence.policy_result["passed"])
        self.assertEqual(len(evidence.policy_result["violatingFindings"]), 1)
        self.assertTrue((self.run_root / evidence.provenance_path).is_file())

    def test_empty_or_non_syft_spdx_is_rejected_before_any_write(self) -> None:
        for mutation in ("packages", "creator"):
            with self.subTest(mutation=mutation):
                invalid = spdx_fixture()
                if mutation == "packages":
                    invalid["packages"] = []
                else:
                    invalid["creationInfo"]["creators"] = ["Tool: other-1.0.0"]
                runner = FixtureRunner(sbom=invalid)

                with self.assertRaisesRegex(SupplyChainError, "MALFORMED_SBOM"):
                    SupplyChainGenerator(runner, clock=lambda: GENERATED_AT).generate(
                        run_root=self.run_root,
                        artifact=artifact(),
                        policy=VulnerabilityPolicy(),
                        builder_id="https://ci.example/builders/local",
                    )

                self.assertFalse((self.run_root / "sbom.spdx.json").exists())

    def test_trivy_artifact_digest_mismatch_is_rejected_before_any_write(self) -> None:
        scan = trivy_fixture()
        scan["ArtifactName"] = OTHER_REFERENCE
        runner = FixtureRunner(scan=scan)

        with self.assertRaisesRegex(SupplyChainError, "SCAN_SUBJECT_MISMATCH"):
            SupplyChainGenerator(runner, clock=lambda: GENERATED_AT).generate(
                run_root=self.run_root,
                artifact=artifact(),
                policy=VulnerabilityPolicy(),
                builder_id="https://ci.example/builders/local",
            )

        self.assertFalse((self.run_root / "sbom.spdx.json").exists())
        self.assertFalse((self.run_root / "vulnerabilities.json").exists())

    def test_malformed_finding_and_database_metadata_fail_closed(self) -> None:
        malformed_scan = trivy_fixture()
        del malformed_scan["Results"][0]["Vulnerabilities"][0]["Severity"]
        cases = (
            (FixtureRunner(scan=malformed_scan), "MALFORMED_VULNERABILITY_REPORT"),
            (
                FixtureRunner(version={"Version": "0.69.0", "VulnerabilityDB": {}}),
                "MALFORMED_SCANNER_METADATA",
            ),
        )
        for runner, error_code in cases:
            with self.subTest(error_code=error_code):
                with self.assertRaisesRegex(SupplyChainError, error_code):
                    SupplyChainGenerator(runner, clock=lambda: GENERATED_AT).generate(
                        run_root=self.run_root,
                        artifact=artifact(),
                        policy=VulnerabilityPolicy(),
                        builder_id="https://ci.example/builders/local",
                    )
                self.assertFalse((self.run_root / "sbom.spdx.json").exists())

    def test_checksum_tampering_is_detected(self) -> None:
        _, evidence = self.generate()
        path = self.run_root / evidence.sbom_path
        path.write_bytes(path.read_bytes() + b" ")

        with self.assertRaisesRegex(SupplyChainError, "EVIDENCE_CHECKSUM_MISMATCH"):
            verify_sbom_evidence(
                self.run_root,
                evidence.sbom_path,
                evidence.sbom_hash,
                REFERENCE,
            )

    def test_rehashed_sbom_subject_tampering_is_still_detected(self) -> None:
        _, evidence = self.generate()
        sbom = json.loads((self.run_root / evidence.sbom_path).read_text())
        sbom["annotations"][-1]["comment"] = SUBJECT_ANNOTATION_PREFIX + OTHER_REFERENCE
        tampered_hash = self.rewrite_json(evidence.sbom_path, sbom)

        with self.assertRaisesRegex(SupplyChainError, "SBOM_SUBJECT_MISMATCH"):
            verify_sbom_evidence(
                self.run_root,
                evidence.sbom_path,
                tampered_hash,
                REFERENCE,
            )

    def test_rehashed_scan_subject_tampering_is_still_detected(self) -> None:
        _, evidence = self.generate()
        report = json.loads(
            (self.run_root / evidence.vulnerability_report_path).read_text()
        )
        report["ArtifactName"] = OTHER_REFERENCE
        tampered_hash = self.rewrite_json(evidence.vulnerability_report_path, report)

        with self.assertRaisesRegex(SupplyChainError, "SCAN_SUBJECT_MISMATCH"):
            verify_vulnerability_evidence(
                self.run_root,
                evidence.vulnerability_report_path,
                tampered_hash,
                REFERENCE,
            )

    def test_rehashed_provenance_subject_tampering_is_still_detected(self) -> None:
        _, evidence = self.generate()
        provenance = json.loads((self.run_root / evidence.provenance_path).read_text())
        provenance["subject"][0]["digest"]["sha256"] = "b" * 64
        tampered_hash = self.rewrite_json(evidence.provenance_path, provenance)

        with self.assertRaisesRegex(SupplyChainError, "PROVENANCE_SUBJECT_MISMATCH"):
            verify_provenance_evidence(
                self.run_root,
                evidence.provenance_path,
                tampered_hash,
                REFERENCE,
                source_revision=REVISION,
                build_plan_hash=PLAN_HASH,
            )

    def test_provenance_rejects_false_crypto_claim_becoming_true(self) -> None:
        statement = create_provenance_statement(
            artifact(),
            builder_id="https://ci.example/builders/local",
            tool_name="devops-stack-composer",
            generated_at="2026-08-30T01:02:03Z",
        )
        tampered = deepcopy(statement)
        tampered["predicate"][FILE_ONLY_EXTENSION]["signatureGenerated"] = True

        with self.assertRaisesRegex(SupplyChainError, "MALFORMED_PROVENANCE"):
            validate_provenance_statement(tampered, REFERENCE)

    def test_unsafe_output_path_is_rejected_before_subprocess(self) -> None:
        runner = FixtureRunner()

        with self.assertRaisesRegex(UnsafePathError, "inside the project root"):
            SupplyChainGenerator(runner, clock=lambda: GENERATED_AT).generate(
                run_root=self.run_root,
                artifact=artifact(),
                policy=VulnerabilityPolicy(),
                builder_id="https://ci.example/builders/local",
                sbom_path="../outside.json",
            )

        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
