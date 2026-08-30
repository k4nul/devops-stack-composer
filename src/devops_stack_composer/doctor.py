"""Host, template, lock, and optional-validator diagnostics."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.policies import ValidationProfile
from devops_stack_composer.sources import ENVIRONMENT_PATHS, SourceResolver
from devops_stack_composer.validation import CheckResult, ValidationReport, ValidationStatus


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    version: str | None = None
    error: str | None = None


class ToolProbe:
    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, command: Sequence[str], *, timeout: int = 10) -> ProbeResult:
        if not self.which(command[0]):
            return ProbeResult(False)
        try:
            result = subprocess.run(
                list(command),
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            return ProbeResult(True, error=str(exc))
        output = (result.stdout or result.stderr).strip().splitlines()
        return ProbeResult(True, version=output[0][:200] if output else "available")


def _tool_check(
    probe: ToolProbe,
    *,
    name: str,
    command: Sequence[str],
    required: bool,
    purpose: str,
) -> CheckResult:
    result = probe.run(command)
    if not result.available:
        status = (
            ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL
            if required
            else ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL
        )
        return CheckResult(
            f"doctor.tool.{name}",
            status,
            f"{name} is not installed; {purpose}",
            scope="doctor",
            command=tuple(command),
        )
    if result.error:
        return CheckResult(
            f"doctor.tool.{name}",
            ValidationStatus.FAILED,
            f"{name} is installed but unusable: {result.error}",
            scope="doctor",
            command=tuple(command),
        )
    return CheckResult(
        f"doctor.tool.{name}",
        ValidationStatus.PASSED,
        f"{name}: {result.version}",
        scope="doctor",
        command=tuple(command),
    )


def run_doctor(
    *,
    lock: TemplateLock,
    resolver: SourceResolver,
    environment: Mapping[str, str] | None = None,
    probe: ToolProbe | None = None,
    check_remote: bool = False,
    fetch_templates: bool = False,
    profile: str | ValidationProfile | None = None,
) -> ValidationReport:
    environment = dict(os.environ if environment is None else environment)
    probe = probe or ToolProbe()
    checks: list[CheckResult] = [
        CheckResult(
            "doctor.runtime.python",
            ValidationStatus.PASSED,
            f"Python {sys.version.split()[0]}",
            scope="doctor",
        )
    ]
    selected_profile = ValidationProfile.parse(profile) if profile is not None else None
    required_by_profile = {
        ValidationProfile.STATIC: frozenset(),
        ValidationProfile.SUPPLY_CHAIN: frozenset(
            {"git", "pwsh", "docker", "buildx", "syft", "trivy"}
        ),
        ValidationProfile.KIND_E2E: frozenset(
            {
                "git",
                "pwsh",
                "docker",
                "buildx",
                "syft",
                "trivy",
                "kind",
                "kubectl",
                "kubeconform",
            }
        ),
        ValidationProfile.RELEASE: frozenset(
            {
                "git",
                "pwsh",
                "docker",
                "buildx",
                "syft",
                "trivy",
                "kind",
                "kubectl",
                "kubeconform",
                "cosign",
                "gh",
            }
        ),
    }
    profile_required = required_by_profile.get(selected_profile, frozenset())
    specifications = (
        ("git", ("git", "--version"), True, "template resolution and lock verification are blocked"),
        ("pwsh", ("pwsh", "--version"), True, "Jenkins and Kubernetes upstream adapters are blocked"),
        ("docker", ("docker", "version", "--format", "{{.Client.Version}}"), True, "the official Docker build-plan validator is blocked"),
        ("buildx", ("docker", "buildx", "version"), True, "the official Docker build-plan validator is blocked"),
        ("java", ("java", "-version"), False, "Jenkins JVM validation will be skipped"),
        ("groovy", ("groovy", "--version"), False, "standalone Groovy syntax validation will be skipped"),
        ("kustomize", ("kustomize", "version"), False, "external overlay rendering will be skipped"),
        (
            "kubectl",
            ("kubectl", "version", "--client"),
            False,
            "kubectl kustomize cross-check will be skipped",
        ),
        ("kubeconform", ("kubeconform", "-v"), False, "strict Kubernetes schema validation will be skipped"),
        ("helm", ("helm", "version", "--short"), False, "upstream Helm rendering will be skipped"),
        ("syft", ("syft", "version"), False, "standalone SBOM inspection will be skipped"),
        ("trivy", ("trivy", "version"), False, "standalone image vulnerability scanning will be skipped"),
        ("cosign", ("cosign", "version"), False, "standalone provenance verification will be skipped"),
        ("kind", ("kind", "version"), False, "kind cluster execution will be skipped"),
        ("gh", ("gh", "--version"), False, "GitHub artifact attestation verification will be skipped"),
    )
    checks.extend(
        _tool_check(
            probe,
            name=name,
            command=command,
            required=(name in profile_required if selected_profile is not None else required),
            purpose=purpose,
        )
        for name, command, required, purpose in specifications
    )

    for pin in lock.pins():
        try:
            source = resolver.resolve(pin.key, fetch=fetch_templates)
        except Exception as exc:  # The diagnostic boundary turns domain failures into a result.
            checks.append(
                CheckResult(
                    f"doctor.template.{pin.key}",
                    ValidationStatus.FAILED,
                    f"template source cannot be resolved locally: {exc}",
                    scope="doctor",
                )
            )
            continue
        checks.append(
            CheckResult(
                f"doctor.template.{pin.key}",
                ValidationStatus.PASSED if source.matches_lock else ValidationStatus.FAILED,
                (
                    f"resolved locked commit {pin.commit} from {source.origin}"
                    if source.matches_lock
                    else f"resolved commit {source.commit or 'unknown'}, expected {pin.commit}"
                ),
                scope="doctor",
                details={
                    "origin": source.origin,
                    "path": str(source.path),
                    "commit": source.commit,
                    "expectedCommit": pin.commit,
                },
            )
        )

    for key, variable in ENVIRONMENT_PATHS.items():
        checks.append(
            CheckResult(
                f"doctor.environment.{variable}",
                ValidationStatus.PASSED,
                f"{variable} is {'set' if environment.get(variable) else 'not set (optional)'}",
                scope="doctor",
                details={"template": key, "set": bool(environment.get(variable))},
            )
        )

    if check_remote:
        try:
            updates = lock.check_remote_updates()
        except Exception as exc:  # Network and Git failures are report data here.
            checks.append(
                CheckResult(
                    "doctor.templates.remote-access",
                    ValidationStatus.FAILED,
                    f"cannot query one or more template remotes: {exc}",
                    scope="doctor",
                )
            )
        else:
            changed = [update.key for update in updates if update.changed]
            checks.append(
                CheckResult(
                    "doctor.templates.remote-access",
                    ValidationStatus.PASSED,
                    (
                        f"remote access succeeded; updates available for {', '.join(changed)}"
                        if changed
                        else "remote access succeeded; every locked commit equals remote main"
                    ),
                    scope="doctor",
                    details={"updatesAvailable": changed},
                )
            )
    return ValidationReport(tuple(checks))
