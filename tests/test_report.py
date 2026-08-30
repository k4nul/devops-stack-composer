from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from devops_stack_composer.adapters.base import AdapterDiagnostic, AdapterResult
from devops_stack_composer.errors import GeneratedFileConflictError
from devops_stack_composer.report import build_report, write_report_files
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


class ReportTests(unittest.TestCase):
    def test_report_contains_exact_statuses_and_redacts_sensitive_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {
                name: SourceResolution(
                    name,
                    root,
                    "fixture",
                    prefix * 40,
                    "https://example.invalid/template.git",
                    True,
                )
                for name, prefix in (("docker", "d"), ("jenkins", "e"), ("kubernetes", "f"))
            }
            adapters = tuple(
                AdapterResult(
                    name,
                    "1.0.0",
                    sources[name].commit or "",
                    (),
                    {},
                    (
                        AdapterDiagnostic(
                            "SKIPPED_MISSING_OPTIONAL_TOOL",
                            "tool.optional",
                            "Authorization: Bearer BEARER-MUST-NOT-LEAK",
                            details={
                                "token": "must-not-leak",
                                "credentialId": "safe-id",
                                "stderr": (
                                    "failed contacting "
                                    "https://alice:URL-MUST-NOT-LEAK@example.invalid; "
                                    "password=INLINE-MUST-NOT-LEAK\n"
                                    "Authorization: Basic BASIC-MUST-NOT-LEAK\n"
                                    "Proxy-Authorization: Digest DIGEST-MUST-NOT-LEAK\n"
                                    "curl --user admin:CURL-USER-MUST-NOT-LEAK "
                                    "https://example.invalid\n"
                                    "curl -ucompact:CURL-COMPACT-MUST-NOT-LEAK "
                                    "https://example.invalid"
                                ),
                                "stdout": "docker --password FLAG-MUST-NOT-LEAK",
                            },
                        ),
                    ),
                )
                for name in ("docker", "jenkins", "kubernetes")
            )
            validation = ValidationReport(
                (
                    CheckResult("contract", ValidationStatus.PASSED, "contracts match"),
                    CheckResult(
                        "kubeconform",
                        ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL,
                        "not installed",
                    ),
                )
            )
            report = build_report(
                project=root,
                config_hash="a" * 64,
                sources=sources,
                adapters=adapters,
                validation=validation,
                generated_at=datetime(2026, 8, 30, tzinfo=timezone.utc),
            )

            json_text = report.to_json()
            markdown = report.to_markdown()

            self.assertNotIn("must-not-leak", json_text)
            for secret in (
                "BEARER-MUST-NOT-LEAK",
                "URL-MUST-NOT-LEAK",
                "INLINE-MUST-NOT-LEAK",
                "FLAG-MUST-NOT-LEAK",
                "BASIC-MUST-NOT-LEAK",
                "DIGEST-MUST-NOT-LEAK",
                "CURL-USER-MUST-NOT-LEAK",
                "CURL-COMPACT-MUST-NOT-LEAK",
            ):
                self.assertNotIn(secret, json_text + markdown)
            self.assertIn("<redacted>", json_text)
            self.assertIn("safe-id", json_text)
            self.assertIn("SKIPPED_MISSING_OPTIONAL_TOOL", markdown)
            parsed = json.loads(json_text)
            self.assertEqual(parsed["generatedAt"], "2026-08-30T00:00:00Z")

    def test_redaction_handles_nested_secret_names_without_hiding_references(self) -> None:
        value = {
            "API_SECRET": "must-not-leak",
            "clientSecret": "must-not-leak-either",
            "secretRefs": [{"name": "orders-secret", "keys": ["API_TOKEN"]}],
            "credentialId": "jenkins-reference-only",
        }

        from devops_stack_composer.report import redact_sensitive

        redacted = redact_sensitive(value)

        self.assertEqual(redacted["API_SECRET"], "<redacted>")
        self.assertEqual(redacted["clientSecret"], "<redacted>")
        self.assertEqual(redacted["secretRefs"], value["secretRefs"])
        self.assertEqual(redacted["credentialId"], "jenkins-reference-only")

    def test_redaction_removes_generic_url_user_information(self) -> None:
        from devops_stack_composer.report import redact_sensitive

        redacted = redact_sensitive(
            {"remote": "https://operator:secret@example.invalid/template.git"}
        )

        self.assertEqual(
            redacted["remote"],
            "https://<redacted>@example.invalid/template.git",
        )

    def test_report_writes_stay_inside_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = type("Report", (), {"to_markdown": lambda self: "# report\n", "to_json": lambda self: "{}\n"})()

            markdown, machine = write_report_files(root, report)

            self.assertEqual(
                markdown,
                root / ".devops-stack" / "reports" / "devops-stack-report.md",
            )
            self.assertEqual(
                machine,
                root / ".devops-stack" / "reports" / "devops-stack-report.json",
            )

            with self.assertRaisesRegex(GeneratedFileConflictError, "--force"):
                write_report_files(root, report)

            write_report_files(root, report, overwrite=True)


if __name__ == "__main__":
    unittest.main()
