"""Domain errors with stable, actionable user-facing messages."""

from __future__ import annotations

from dataclasses import dataclass


class DevOpsStackError(Exception):
    """Base class for expected command failures."""


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    expected: str
    received: str
    example: str
    message: str

    def __str__(self) -> str:
        return (
            f"{self.path}: {self.message}; expected {self.expected}; "
            f"received {self.received}; example {self.example}"
        )


class ConfigValidationError(DevOpsStackError):
    def __init__(self, issues: list[ValidationIssue]):
        self.issues = issues
        details = "\n".join(f"  - {issue}" for issue in issues)
        super().__init__(f"configuration validation failed:\n{details}")


class ConfigParseError(DevOpsStackError):
    """Raised when YAML cannot be parsed into a mapping."""


class LockValidationError(DevOpsStackError):
    """Raised when the committed template lock is invalid."""


class SourceResolutionError(DevOpsStackError):
    """Raised when a pinned template source cannot be resolved safely."""
