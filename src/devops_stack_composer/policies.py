"""Execution-profile and vulnerability-policy definitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Any, Iterable

from devops_stack_composer.execution_models import StageResult, StageStatus


class ValidationProfile(str, Enum):
    STATIC = "static"
    SUPPLY_CHAIN = "supply-chain"
    KIND_E2E = "kind-e2e"
    RELEASE = "release"

    @classmethod
    def parse(cls, value: str | "ValidationProfile") -> "ValidationProfile":
        if isinstance(value, cls):
            return value
        if value == "local-kind":
            value = cls.KIND_E2E.value
        try:
            return cls(value)
        except ValueError as exc:
            allowed = ", ".join(profile.value for profile in cls)
            raise ValueError(
                f"unknown validation profile {value!r}; expected one of {allowed}"
            ) from exc


_STATIC_STAGES = (
    "config-schema",
    "template-lock",
    "adapter-contracts",
    "generated-files",
)
_SUPPLY_CHAIN_CORE_STAGES = _STATIC_STAGES + (
    "registry-lifecycle",
    "build-once",
    "resolve-digest",
    "sbom",
    "vulnerability-scan",
    "provenance",
    "artifact-contract",
)
_SUPPLY_CHAIN_STAGES = _SUPPLY_CHAIN_CORE_STAGES + ("cleanup",)
_KIND_STAGES = _SUPPLY_CHAIN_CORE_STAGES + (
    "kubernetes-schema",
    "server-side-dry-run",
    "deployment",
    "rollout",
    "pod-image",
    "health",
    "readiness",
    "rollback",
    "cleanup",
)
_RELEASE_STAGES = _KIND_STAGES + (
    "package",
    "release-assets",
    "release-download-verification",
    "working-tree",
    "tag-commit",
)


@dataclass(frozen=True)
class ProfilePolicy:
    """Required capabilities and evidence gates for one execution profile."""

    profile: ValidationProfile
    required_stages: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    require_clean_working_tree: bool = False
    require_tag_at_head: bool = False
    require_verified_release_artifacts: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", ValidationProfile.parse(self.profile))
        if len(set(self.required_stages)) != len(self.required_stages):
            raise ValueError("required_stages must be unique")
        if len(set(self.required_capabilities)) != len(self.required_capabilities):
            raise ValueError("required_capabilities must be unique")

    def required_stage_failures(
        self,
        stages: Iterable[StageResult],
    ) -> dict[str, str]:
        """Return missing or non-passing required stages by stable stage ID."""

        by_id = {stage.stage_id: stage for stage in stages}
        failures: dict[str, str] = {}
        for stage_id in self.required_stages:
            stage = by_id.get(stage_id)
            if stage is None:
                failures[stage_id] = "MISSING"
            elif stage.status != StageStatus.PASSED:
                failures[stage_id] = stage.status.value
        return failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "requiredStages": list(self.required_stages),
            "requiredCapabilities": list(self.required_capabilities),
            "requireCleanWorkingTree": self.require_clean_working_tree,
            "requireTagAtHead": self.require_tag_at_head,
            "requireVerifiedReleaseArtifacts": self.require_verified_release_artifacts,
        }


_PROFILE_POLICIES = {
    ValidationProfile.STATIC: ProfilePolicy(
        ValidationProfile.STATIC,
        _STATIC_STAGES,
        (),
    ),
    ValidationProfile.SUPPLY_CHAIN: ProfilePolicy(
        ValidationProfile.SUPPLY_CHAIN,
        _SUPPLY_CHAIN_STAGES,
        (
            "build-engine",
            "registry",
            "sbom-generator",
            "vulnerability-scanner",
            "provenance-generator",
            "artifact-validator",
        ),
    ),
    ValidationProfile.KIND_E2E: ProfilePolicy(
        ValidationProfile.KIND_E2E,
        _KIND_STAGES,
        (
            "build-engine",
            "registry",
            "sbom-generator",
            "vulnerability-scanner",
            "provenance-generator",
            "artifact-validator",
            "kind",
            "kubectl",
            "kubernetes-schema-validator",
        ),
    ),
    ValidationProfile.RELEASE: ProfilePolicy(
        ValidationProfile.RELEASE,
        _RELEASE_STAGES,
        (
            "build-engine",
            "registry",
            "sbom-generator",
            "vulnerability-scanner",
            "provenance-generator",
            "artifact-validator",
            "kind",
            "kubectl",
            "kubernetes-schema-validator",
            "package-builder",
            "artifact-attestation",
        ),
        require_clean_working_tree=True,
        require_tag_at_head=True,
        require_verified_release_artifacts=True,
    ),
}


def profile_policy(profile: str | ValidationProfile) -> ProfilePolicy:
    """Return the immutable policy for a supported validation profile."""

    return _PROFILE_POLICIES[ValidationProfile.parse(profile)]


_KNOWN_SEVERITIES = frozenset({"UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


def _required_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError(f"{name} must not contain surrounding whitespace or control characters")
    return value


@dataclass(frozen=True)
class VulnerabilityFinding:
    vulnerability_id: str
    package: str
    installed_version: str
    fixed_version: str | None
    severity: str
    status: str = "affected"

    def __post_init__(self) -> None:
        _required_text("vulnerability_id", self.vulnerability_id)
        _required_text("package", self.package)
        _required_text("installed_version", self.installed_version)
        if self.fixed_version == "":
            object.__setattr__(self, "fixed_version", None)
        elif self.fixed_version is not None:
            _required_text("fixed_version", self.fixed_version)
        severity = _required_text("severity", self.severity).upper()
        object.__setattr__(self, "severity", severity)
        _required_text("status", self.status)

    @property
    def is_fixed(self) -> bool:
        return self.fixed_version is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerabilityId": self.vulnerability_id,
            "package": self.package,
            "installedVersion": self.installed_version,
            "fixedVersion": self.fixed_version,
            "severity": self.severity,
            "status": self.status,
        }


@dataclass(frozen=True)
class VulnerabilityAllowlistEntry:
    vulnerability_id: str
    package: str
    reason: str
    owner: str
    expires_on: date

    def __post_init__(self) -> None:
        _required_text("vulnerability_id", self.vulnerability_id)
        _required_text("package", self.package)
        _required_text("reason", self.reason)
        _required_text("owner", self.owner)
        if isinstance(self.expires_on, str):
            try:
                object.__setattr__(self, "expires_on", date.fromisoformat(self.expires_on))
            except ValueError as exc:
                raise ValueError("expires_on must use YYYY-MM-DD") from exc
        elif not isinstance(self.expires_on, date):
            raise ValueError("expires_on must be a date")

    def matches(self, finding: VulnerabilityFinding) -> bool:
        return (
            self.vulnerability_id == finding.vulnerability_id
            and self.package == finding.package
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerabilityId": self.vulnerability_id,
            "package": self.package,
            "reason": self.reason,
            "owner": self.owner,
            "expiresOn": self.expires_on.isoformat(),
        }


@dataclass(frozen=True)
class VulnerabilityPolicy:
    severities: tuple[str, ...] = ("CRITICAL",)
    maximum_allowed: int = 0
    ignore_unfixed: bool = True
    allowlist: tuple[VulnerabilityAllowlistEntry, ...] = ()

    def __post_init__(self) -> None:
        severities = tuple(severity.upper() for severity in self.severities)
        if not severities or len(set(severities)) != len(severities):
            raise ValueError("severities must contain unique values")
        unknown = sorted(set(severities) - _KNOWN_SEVERITIES)
        if unknown:
            raise ValueError("unsupported policy severities: " + ", ".join(unknown))
        object.__setattr__(self, "severities", severities)
        if (
            isinstance(self.maximum_allowed, bool)
            or not isinstance(self.maximum_allowed, int)
            or self.maximum_allowed < 0
        ):
            raise ValueError("maximum_allowed must be a non-negative integer")
        if not isinstance(self.ignore_unfixed, bool):
            raise ValueError("ignore_unfixed must be boolean")
        allowlist = tuple(self.allowlist)
        if any(not isinstance(entry, VulnerabilityAllowlistEntry) for entry in allowlist):
            raise ValueError("allowlist must contain VulnerabilityAllowlistEntry values")
        keys = [(entry.vulnerability_id, entry.package) for entry in allowlist]
        if len(keys) != len(set(keys)):
            raise ValueError("allowlist entries must be unique by vulnerability and package")
        object.__setattr__(self, "allowlist", allowlist)

    def evaluate(
        self,
        findings: Iterable[VulnerabilityFinding],
        *,
        on_date: date | None = None,
    ) -> "VulnerabilityPolicyResult":
        return evaluate_vulnerabilities(findings, self, on_date=on_date)


@dataclass(frozen=True)
class VulnerabilityPolicyResult:
    passed: bool
    evaluated_on: date
    evaluated_count: int
    severity_match_count: int
    allowed_count: int
    ignored_unfixed_count: int
    violating_findings: tuple[VulnerabilityFinding, ...] = ()
    expired_allowlist_entries: tuple[VulnerabilityAllowlistEntry, ...] = ()
    unknown_severity_findings: tuple[VulnerabilityFinding, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "evaluatedOn": self.evaluated_on.isoformat(),
            "evaluatedCount": self.evaluated_count,
            "severityMatchCount": self.severity_match_count,
            "allowedCount": self.allowed_count,
            "ignoredUnfixedCount": self.ignored_unfixed_count,
            "violatingFindings": [finding.to_dict() for finding in self.violating_findings],
            "expiredAllowlistEntries": [
                entry.to_dict() for entry in self.expired_allowlist_entries
            ],
            "unknownSeverityFindings": [
                finding.to_dict() for finding in self.unknown_severity_findings
            ],
        }


def evaluate_vulnerabilities(
    findings: Iterable[VulnerabilityFinding],
    policy: VulnerabilityPolicy,
    *,
    on_date: date | None = None,
) -> VulnerabilityPolicyResult:
    """Evaluate scanner findings without depending on a live vulnerability database."""

    if not isinstance(policy, VulnerabilityPolicy):
        raise ValueError("policy must be a VulnerabilityPolicy")
    evaluated_on = on_date or date.today()
    if not isinstance(evaluated_on, date):
        raise ValueError("on_date must be a date")
    values = tuple(findings)
    if any(not isinstance(finding, VulnerabilityFinding) for finding in values):
        raise ValueError("findings must contain VulnerabilityFinding values")

    expired = tuple(entry for entry in policy.allowlist if entry.expires_on < evaluated_on)
    active = tuple(entry for entry in policy.allowlist if entry.expires_on >= evaluated_on)
    violating: list[VulnerabilityFinding] = []
    unknown: list[VulnerabilityFinding] = []
    severity_match_count = 0
    allowed_count = 0
    ignored_unfixed_count = 0

    for finding in values:
        if finding.severity not in _KNOWN_SEVERITIES:
            unknown.append(finding)
            continue
        if finding.severity not in policy.severities:
            continue
        severity_match_count += 1
        if policy.ignore_unfixed and not finding.is_fixed:
            ignored_unfixed_count += 1
            continue
        if any(entry.matches(finding) for entry in active):
            allowed_count += 1
            continue
        violating.append(finding)

    passed = (
        len(violating) <= policy.maximum_allowed
        and not expired
        and not unknown
    )
    return VulnerabilityPolicyResult(
        passed=passed,
        evaluated_on=evaluated_on,
        evaluated_count=len(values),
        severity_match_count=severity_match_count,
        allowed_count=allowed_count,
        ignored_unfixed_count=ignored_unfixed_count,
        violating_findings=tuple(violating),
        expired_allowlist_entries=expired,
        unknown_severity_findings=tuple(unknown),
    )
