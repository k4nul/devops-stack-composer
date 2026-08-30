"""Machine-readable and operator-readable composition reports."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from devops_stack_composer import __version__
from devops_stack_composer.adapters.base import AdapterResult
from devops_stack_composer.errors import GeneratedFileConflictError
from devops_stack_composer.filesystem import atomic_write, contained_path
from devops_stack_composer.manifest import GeneratedManifest, ManifestVerification
from devops_stack_composer.sources import SourceResolution
from devops_stack_composer.validation import ValidationReport


SENSITIVE_KEY = re.compile(
    r"(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)",
    re.IGNORECASE,
)
SAFE_REFERENCE_KEYS = {
    "credentialid",
    "credentialids",
    "secretname",
    "secretnames",
    "secretref",
    "secretrefs",
}
URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
BEARER_TOKEN = re.compile(
    r"(?i)(\bauthorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"
)
AUTHORIZATION_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*"
)
INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
SECRET_FLAG = re.compile(
    r"(?ix)(--(?:password|passphrase|token|secret|private-key|access-key|api-key)\s+(?:=\s*)?)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
CURL_USER = re.compile(
    r"(?i)(?<!\S)(?P<prefix>--user(?:\s+|=)|-u(?:\s+|=)|"
    r"-u(?=[^\s;]*:))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;]+)"
)


def _redact_string(value: str) -> str:
    redacted = URL_USERINFO.sub(r"\1<redacted>@", value)
    redacted = AUTHORIZATION_HEADER.sub(r"\1<redacted>", redacted)
    redacted = BEARER_TOKEN.sub(r"\1<redacted>", redacted)
    redacted = INLINE_SECRET.sub(r"\1<redacted>", redacted)
    redacted = SECRET_FLAG.sub(r"\1<redacted>", redacted)
    return CURL_USER.sub(r"\g<prefix><redacted>", redacted)


def redact_sensitive(value: Any, key: str = "") -> Any:
    normalized_key = key.replace("_", "").lower()
    if normalized_key not in SAFE_REFERENCE_KEYS and SENSITIVE_KEY.search(normalized_key):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(child): redact_sensitive(item, str(child)) for child, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


@dataclass(frozen=True)
class CompositionReport:
    data: dict[str, Any]

    def to_json(self) -> str:
        return (
            json.dumps(
                redact_sensitive(self.data),
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )

    def to_markdown(self) -> str:
        data = redact_sensitive(self.data)
        counts = data["validation"]["counts"]
        lines = [
            "# DevOps Stack Composition Report",
            "",
            f"Overall result: **{'PASSED' if data['validation']['passed'] else 'FAILED'}**",
            "",
            f"- Generated: `{data['generatedAt']}`",
            f"- Tool version: `{data['toolVersion']}`",
            f"- Configuration hash: `{data['configHash']}`",
            f"- Project: `{data['project']}`",
            "",
            "## Validation summary",
            "",
            "| Status | Count |",
            "| --- | ---: |",
        ]
        for status in (
            "PASSED",
            "FAILED",
            "SKIPPED_MISSING_OPTIONAL_TOOL",
            "BLOCKED_MISSING_REQUIRED_TOOL",
        ):
            lines.append(f"| {status} | {counts.get(status, 0)} |")
        lines.extend(["", "## Template sources", "", "| Template | Origin | Commit | Lock match |", "| --- | --- | --- | --- |"])
        for key in ("docker", "jenkins", "kubernetes"):
            source = data["sources"][key]
            lines.append(
                f"| {key} | {source['origin']} | `{source.get('commit') or 'unknown'}` | "
                f"{'yes' if source['matchesLock'] else 'no'} |"
            )
        lines.extend(["", "## Checks", "", "| Status | Scope | Check | Result |", "| --- | --- | --- | --- |"])
        for check in data["validation"]["checks"]:
            message = str(check["message"]).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {check['status']} | {check['scope']} | `{check['check']}` | {message} |"
            )
        lines.extend(["", "## Adapter integration", ""])
        for adapter in data["adapters"]:
            lines.extend(
                [
                    f"### {adapter['name'].title()}",
                    "",
                    f"Adapter version `{adapter['adapterVersion']}` against template commit "
                    f"`{adapter['templateCommit']}` generated {adapter['artifactCount']} file(s).",
                    "",
                ]
            )
            if adapter["diagnostics"]:
                for diagnostic in adapter["diagnostics"]:
                    lines.append(
                        f"- {diagnostic['status']} `{diagnostic['check']}`: {diagnostic['message']}"
                    )
                lines.append("")
        manifest = data.get("manifest")
        if manifest:
            lines.extend(
                [
                    "## Generated-file integrity",
                    "",
                    f"Manifest: `{manifest['path']}`",
                    "",
                    f"Integrity clean: **{'yes' if manifest['clean'] else 'no'}**",
                    "",
                ]
            )
            for category in ("modified", "missing", "untracked"):
                values = manifest[category]
                lines.append(f"- {category}: {', '.join(values) if values else 'none'}")
            lines.append("")
        if data.get("limitations"):
            lines.extend(["## Known limitations", ""])
            lines.extend(f"- {item}" for item in data["limitations"])
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def build_report(
    *,
    project: Path,
    config_hash: str,
    sources: Mapping[str, SourceResolution],
    adapters: Iterable[AdapterResult],
    validation: ValidationReport,
    manifest: GeneratedManifest | None = None,
    manifest_verification: ManifestVerification | None = None,
    inspection: dict[str, Any] | None = None,
    limitations: Iterable[str] = (),
    generated_at: datetime | None = None,
) -> CompositionReport:
    timestamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    adapter_values = []
    for result in sorted(adapters, key=lambda item: item.adapter):
        adapter_values.append(
            {
                "name": result.adapter,
                "adapterVersion": result.adapter_version,
                "templateCommit": result.template_commit,
                "artifactCount": len(result.artifacts),
                "diagnostics": [
                    {
                        "status": diagnostic.status,
                        "check": diagnostic.check,
                        "message": diagnostic.message,
                        **({"command": list(diagnostic.command)} if diagnostic.command else {}),
                        **({"details": diagnostic.details} if diagnostic.details else {}),
                    }
                    for diagnostic in result.diagnostics
                ],
            }
        )
    manifest_data = None
    if manifest is not None:
        verification = manifest_verification or manifest.verify(project)
        manifest_data = {
            "path": str(manifest.path.relative_to(project.resolve())),
            "clean": verification.clean,
            "modified": list(verification.modified),
            "missing": list(verification.missing),
            "untracked": list(verification.untracked),
        }
    data = {
        "schemaVersion": "1.0.0",
        "toolVersion": __version__,
        "generatedAt": timestamp.isoformat().replace("+00:00", "Z"),
        "project": str(project.resolve()),
        "configHash": config_hash,
        "sources": {
            key: {
                "path": str(value.path),
                "origin": value.origin,
                "commit": value.commit,
                "remote": value.remote,
                "matchesLock": value.matches_lock,
            }
            for key, value in sorted(sources.items())
        },
        "adapters": adapter_values,
        "validation": validation.to_dict(),
        "manifest": manifest_data,
        "inspection": inspection,
        "limitations": list(limitations),
    }
    return CompositionReport(redact_sensitive(data))


def write_report_files(
    project: Path,
    report: CompositionReport,
    *,
    markdown_path: str = ".devops-stack/reports/devops-stack-report.md",
    json_path: str = ".devops-stack/reports/devops-stack-report.json",
    overwrite: bool = False,
) -> tuple[Path, Path]:
    targets = (
        contained_path(project, markdown_path),
        contained_path(project, json_path),
    )
    if not overwrite:
        existing = [str(path.relative_to(project.resolve())) for path in targets if path.exists()]
        if existing:
            raise GeneratedFileConflictError(
                "refusing to overwrite existing report files: "
                + ", ".join(existing)
                + "; rerun report with --force"
            )
    markdown = atomic_write(
        project,
        markdown_path,
        report.to_markdown(),
        overwrite=overwrite,
    )
    machine = atomic_write(
        project,
        json_path,
        report.to_json(),
        overwrite=overwrite,
    )
    return markdown, machine
