from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.doctor import ProbeResult, ToolProbe, run_doctor
from devops_stack_composer.locks import TemplateLock
from devops_stack_composer.sources import SourceResolution, SourceResolver
from devops_stack_composer.validation import ValidationStatus


ROOT = Path(__file__).resolve().parents[1]


class FakeProbe(ToolProbe):
    def __init__(self, available: set[str]):
        self.available = available

    def which(self, name: str) -> str | None:
        return f"/fake/{name}" if name in self.available else None

    def run(self, command, *, timeout: int = 10):
        if command[0] not in self.available:
            return ProbeResult(False)
        return ProbeResult(True, version=f"{command[0]} test-version")


class FakeResolver:
    def __init__(self, lock: TemplateLock, root: Path):
        self.lock = lock
        self.root = root

    def resolve(self, key: str, *, fetch: bool = False) -> SourceResolution:
        pin = self.lock.pin(key)
        return SourceResolution(key, self.root, "fixture", pin.commit, pin.repository, True)


class DoctorTests(unittest.TestCase):
    def test_required_and_optional_missing_tools_are_distinguished(self) -> None:
        lock = TemplateLock.load(ROOT / "templates.lock.json")
        with tempfile.TemporaryDirectory() as directory:
            report = run_doctor(
                lock=lock,
                resolver=FakeResolver(lock, Path(directory)),  # type: ignore[arg-type]
                environment={"DEVOPS_STACK_DOCKER_TEMPLATE": "/sensitive/local/path"},
                probe=FakeProbe({"git"}),
            )

        pwsh = next(check for check in report.checks if check.check == "doctor.tool.pwsh")
        docker = next(check for check in report.checks if check.check == "doctor.tool.docker")
        trivy = next(check for check in report.checks if check.check == "doctor.tool.trivy")
        self.assertEqual(pwsh.status, ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL)
        self.assertEqual(docker.status, ValidationStatus.BLOCKED_MISSING_REQUIRED_TOOL)
        self.assertEqual(trivy.status, ValidationStatus.SKIPPED_MISSING_OPTIONAL_TOOL)
        self.assertFalse(report.passed)

    def test_environment_diagnostic_never_outputs_value(self) -> None:
        lock = TemplateLock.load(ROOT / "templates.lock.json")
        secret_path = "/private/operator/location"
        with tempfile.TemporaryDirectory() as directory:
            report = run_doctor(
                lock=lock,
                resolver=FakeResolver(lock, Path(directory)),  # type: ignore[arg-type]
                environment={"DEVOPS_STACK_DOCKER_TEMPLATE": secret_path},
                probe=FakeProbe({"git", "pwsh"}),
            )

        rendered = str([check.to_dict() for check in report.checks])
        self.assertNotIn(secret_path, rendered)
        environment = next(
            check
            for check in report.checks
            if check.check == "doctor.environment.DEVOPS_STACK_DOCKER_TEMPLATE"
        )
        self.assertEqual(environment.details["set"], True)


if __name__ == "__main__":
    unittest.main()
