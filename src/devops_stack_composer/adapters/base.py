"""Shared immutable adapter output contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GeneratedArtifact:
    path: str
    content: str
    mode: int = 0o644
    origins: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterDiagnostic:
    status: str
    check: str
    message: str
    command: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterResult:
    adapter: str
    adapter_version: str
    template_commit: str
    artifacts: tuple[GeneratedArtifact, ...]
    contract: dict[str, Any]
    diagnostics: tuple[AdapterDiagnostic, ...] = ()

    def artifact(self, path: str) -> GeneratedArtifact:
        for artifact in self.artifacts:
            if artifact.path == path:
                return artifact
        raise KeyError(path)
