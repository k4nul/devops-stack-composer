from __future__ import annotations

from datetime import date
import unittest

from devops_stack_composer.execution_models import StageResult, StageStatus
from devops_stack_composer.policies import (
    ValidationProfile,
    VulnerabilityAllowlistEntry,
    VulnerabilityFinding,
    VulnerabilityPolicy,
    evaluate_vulnerabilities,
    profile_policy,
)


def finding(
    vulnerability_id: str = "CVE-2026-0001",
    *,
    package: str = "example",
    severity: str = "CRITICAL",
    fixed_version: str | None = "2.0",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id=vulnerability_id,
        package=package,
        installed_version="1.0",
        fixed_version=fixed_version,
        severity=severity,
    )


class ProfilePolicyTests(unittest.TestCase):
    def test_profiles_are_cumulative_and_release_is_strictest(self) -> None:
        static = profile_policy("static")
        supply_chain = profile_policy(ValidationProfile.SUPPLY_CHAIN)
        kind = profile_policy("kind-e2e")
        release = profile_policy("release")

        self.assertLess(len(static.required_stages), len(supply_chain.required_stages))
        self.assertLess(len(supply_chain.required_stages), len(kind.required_stages))
        self.assertLess(len(kind.required_stages), len(release.required_stages))
        self.assertEqual(static.required_capabilities, ())
        self.assertTrue(release.require_clean_working_tree)
        self.assertTrue(release.require_tag_at_head)
        self.assertTrue(release.require_verified_release_artifacts)
        with self.assertRaisesRegex(ValueError, "unknown validation profile"):
            profile_policy("best-effort")

    def test_required_stage_skips_are_not_accepted_as_passes(self) -> None:
        stage = StageResult(
            stage_id="config-schema",
            description="schema",
            status=StageStatus.SKIPPED_MISSING_OPTIONAL_TOOL,
            start_time="2026-08-30T00:00:00Z",
            end_time="2026-08-30T00:00:00Z",
        )

        failures = profile_policy("static").required_stage_failures((stage,))

        self.assertEqual(failures["config-schema"], "SKIPPED_MISSING_OPTIONAL_TOOL")
        self.assertEqual(failures["template-lock"], "MISSING")


class VulnerabilityPolicyTests(unittest.TestCase):
    def test_zero_vulnerabilities_passes(self) -> None:
        result = evaluate_vulnerabilities(
            (),
            VulnerabilityPolicy(),
            on_date=date(2026, 8, 30),
        )

        self.assertTrue(result.passed)
        self.assertEqual(result.evaluated_count, 0)

    def test_threshold_counts_only_selected_unallowed_findings(self) -> None:
        policy = VulnerabilityPolicy(
            severities=("HIGH", "CRITICAL"),
            maximum_allowed=1,
            ignore_unfixed=False,
        )
        within = policy.evaluate(
            (finding(severity="LOW"), finding("CVE-2026-0002", severity="HIGH")),
            on_date=date(2026, 8, 30),
        )
        exceeded = policy.evaluate(
            (
                finding("CVE-2026-0002", severity="HIGH"),
                finding("CVE-2026-0003", severity="CRITICAL"),
            ),
            on_date=date(2026, 8, 30),
        )

        self.assertTrue(within.passed)
        self.assertEqual(within.severity_match_count, 1)
        self.assertFalse(exceeded.passed)
        self.assertEqual(len(exceeded.violating_findings), 2)

    def test_active_allowlist_is_exact_by_vulnerability_and_package(self) -> None:
        entry = VulnerabilityAllowlistEntry(
            vulnerability_id="CVE-2026-0001",
            package="example",
            reason="Temporary upstream exception",
            owner="platform-security",
            expires_on=date(2026, 9, 1),
        )
        policy = VulnerabilityPolicy(ignore_unfixed=False, allowlist=(entry,))

        allowed = policy.evaluate((finding(),), on_date=date(2026, 8, 30))
        wrong_package = policy.evaluate(
            (finding(package="different"),),
            on_date=date(2026, 8, 30),
        )

        self.assertTrue(allowed.passed)
        self.assertEqual(allowed.allowed_count, 1)
        self.assertFalse(wrong_package.passed)

    def test_expired_allowlist_fails_even_without_a_matching_finding(self) -> None:
        expired = VulnerabilityAllowlistEntry(
            vulnerability_id="CVE-2026-0001",
            package="example",
            reason="Expired exception",
            owner="platform-security",
            expires_on="2026-08-29",
        )

        result = VulnerabilityPolicy(allowlist=(expired,)).evaluate(
            (),
            on_date=date(2026, 8, 30),
        )

        self.assertFalse(result.passed)
        self.assertEqual(result.expired_allowlist_entries, (expired,))

    def test_ignore_unfixed_is_explicit(self) -> None:
        unfixed = finding(fixed_version=None)
        ignored = VulnerabilityPolicy(ignore_unfixed=True).evaluate(
            (unfixed,), on_date=date(2026, 8, 30)
        )
        enforced = VulnerabilityPolicy(ignore_unfixed=False).evaluate(
            (unfixed,), on_date=date(2026, 8, 30)
        )

        self.assertTrue(ignored.passed)
        self.assertEqual(ignored.ignored_unfixed_count, 1)
        self.assertFalse(enforced.passed)

    def test_unknown_scanner_severity_fails_closed(self) -> None:
        unknown = finding(severity="urgent")

        result = VulnerabilityPolicy().evaluate(
            (unknown,), on_date=date(2026, 8, 30)
        )

        self.assertFalse(result.passed)
        self.assertEqual(result.unknown_severity_findings, (unknown,))
        self.assertEqual(
            result.to_dict()["unknownSeverityFindings"][0]["severity"],
            "URGENT",
        )


if __name__ == "__main__":
    unittest.main()
