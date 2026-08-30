"""Human-readable and JSON diffs for planned generated artifacts."""

from __future__ import annotations

import difflib
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from devops_stack_composer.adapters.base import GeneratedArtifact
from devops_stack_composer.errors import UnsafePathError
from devops_stack_composer.filesystem import contained_path, normalize_relative_path
from devops_stack_composer.manifest import MANIFEST_NAME, GeneratedManifest


PROJECT_PATHS = {
    "docker/Dockerfile": "Dockerfile",
    "docker/Dockerfile.dockerignore": "Dockerfile.dockerignore",
    "jenkins/Jenkinsfile": "Jenkinsfile",
}
SENSITIVE_NAME = re.compile(
    r"(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)",
    re.IGNORECASE,
)
ASSIGNMENT = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*)"
    r"(?P<value>.*?)(?P<suffix>,?\s*)(?P<newline>\r?\n)?$"
)
YAML_SECRET_BLOCK = re.compile(
    r"^(?P<indent>\s*)[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*:\s*[>|][-+0-9]*\s*(?:\r?\n)?$"
)
DOCKER_ASSIGNMENT = re.compile(
    r"^(?P<prefix>\s*(?:ENV|ARG)\s+)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<separator>\s*(?:=|\s)\s*)(?P<value>.*?)(?P<newline>\r?\n)?$",
    re.IGNORECASE,
)
BEARER_TOKEN = re.compile(
    r"(?i)(\bauthorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"
)
AUTHORIZATION_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*"
)
URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
CURL_USER = re.compile(
    r"(?i)(?<!\S)(?P<prefix>--user(?:\s+|=)|-u(?:\s+|=)|"
    r"-u(?=[^\s;]*:))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;]+)"
)


@dataclass(frozen=True)
class FileDiff:
    path: str
    compared_path: str
    status: str
    unified_diff: str
    expected_mode: str | None
    actual_mode: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "path": self.path,
            "comparedPath": self.compared_path,
            "status": self.status,
            "diff": self.unified_diff,
            "expectedMode": self.expected_mode,
            "actualMode": self.actual_mode,
        }


def _baseline_path(path: str, *, output_directory: str, against: str) -> str:
    if against == "generated":
        return f"{normalize_relative_path(output_directory)}/{path}"
    if against == "project":
        return PROJECT_PATHS.get(path, path)
    raise ValueError(f"unsupported diff baseline {against!r}; expected generated or project")


def _redact_content(content: str) -> str:
    redacted: list[str] = []
    secret_block_indent: int | None = None
    for line in content.splitlines(keepends=True):
        indentation = len(line) - len(line.lstrip())
        if secret_block_indent is not None:
            if not line.strip() or indentation > secret_block_indent:
                newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
                redacted.append(" " * indentation + "<redacted>" + newline)
                continue
            secret_block_indent = None
        block = YAML_SECRET_BLOCK.match(line)
        if block and SENSITIVE_NAME.search(block.group("key")):
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            redacted.append(
                f"{block.group('indent')}{block.group('key')}: <redacted>{newline}"
            )
            secret_block_indent = len(block.group("indent"))
            continue
        match = ASSIGNMENT.match(line)
        if match and SENSITIVE_NAME.search(match.group("key")):
            redacted.append(
                match.group("prefix")
                + "<redacted>"
                + match.group("suffix")
                + (match.group("newline") or "")
            )
            continue
        docker = DOCKER_ASSIGNMENT.match(line)
        if docker and SENSITIVE_NAME.search(docker.group("key")):
            redacted.append(
                docker.group("prefix")
                + docker.group("key")
                + docker.group("separator")
                + "<redacted>"
                + (docker.group("newline") or "")
            )
            continue
        line = AUTHORIZATION_HEADER.sub(r"\1<redacted>", line)
        line = BEARER_TOKEN.sub(r"\1<redacted>", line)
        line = URL_USERINFO.sub(r"\1<redacted>@", line)
        line = INLINE_SECRET.sub(r"\1<redacted>", line)
        line = CURL_USER.sub(r"\g<prefix><redacted>", line)
        redacted.append(line)
    return "".join(redacted)


def diff_artifacts(
    project: Path,
    artifacts: Iterable[GeneratedArtifact],
    *,
    output_directory: str = "generated",
    against: str = "generated",
) -> tuple[FileDiff, ...]:
    materialized = tuple(artifacts)
    diffs = []
    desired_paths: set[str] = set()
    manifest = (
        GeneratedManifest.load(project, output_directory)
        if against == "generated"
        else None
    )
    output_root = (
        contained_path(project, output_directory)
        if against == "generated"
        else None
    )
    if output_root is not None and output_root.exists() and not output_root.is_dir():
        mode = output_root.lstat().st_mode
        return (
            FileDiff(
                normalize_relative_path(output_directory),
                normalize_relative_path(output_directory),
                "unsafe",
                "",
                None,
                f"0{stat.S_IMODE(mode):03o}",
            ),
        )
    if manifest is not None:
        untracked_paths = set(manifest.verify(project).untracked)
    elif output_root is not None and output_root.exists():
        untracked_paths = {
            candidate.relative_to(output_root).as_posix()
            for candidate in output_root.rglob("*")
            if candidate.is_symlink()
            or (
                not candidate.is_dir()
                and candidate.relative_to(output_root).as_posix() != MANIFEST_NAME
            )
        }
    else:
        untracked_paths = set()
    for artifact in sorted(materialized, key=lambda item: item.path):
        path = normalize_relative_path(artifact.path)
        desired_paths.add(path)
        baseline_relative = _baseline_path(path, output_directory=output_directory, against=against)
        expected_mode = f"0{artifact.mode & 0o777:03o}"
        try:
            baseline = contained_path(project, baseline_relative)
        except UnsafePathError:
            unsafe = project.resolve(strict=True).joinpath(
                *Path(baseline_relative).parts
            )
            actual_mode = (
                f"0{stat.S_IMODE(unsafe.lstat().st_mode):03o}"
                if unsafe.is_symlink() or unsafe.exists()
                else None
            )
            diffs.append(
                FileDiff(
                    path,
                    baseline_relative,
                    "unsafe",
                    "",
                    expected_mode,
                    actual_mode,
                )
            )
            continue
        baseline_exists = baseline.exists()
        baseline_is_file = baseline.is_file()
        previous_raw = baseline.read_text(encoding="utf-8") if baseline_is_file else ""
        previous = _redact_content(previous_raw)
        planned = _redact_content(artifact.content)
        actual_mode = (
            f"0{stat.S_IMODE(baseline.stat().st_mode):03o}"
            if baseline_exists
            else None
        )
        if path in untracked_paths:
            status = "unowned" if baseline_is_file else "unsafe"
        elif not baseline_exists:
            status = "added"
        elif (
            baseline_is_file
            and previous_raw == artifact.content
            and actual_mode == expected_mode
        ):
            status = "unchanged"
        else:
            status = "modified"
        unified = "".join(
            difflib.unified_diff(
                previous.splitlines(keepends=True),
                planned.splitlines(keepends=True),
                fromfile=baseline_relative,
                tofile=f"planned/{path}",
            )
        )
        diffs.append(
            FileDiff(
                path,
                baseline_relative,
                status,
                unified,
                expected_mode,
                actual_mode,
            )
        )
    if against == "generated":
        if manifest is not None:
            for path in sorted(set(manifest.file_map()) - desired_paths):
                baseline_relative = _baseline_path(
                    path,
                    output_directory=output_directory,
                    against=against,
                )
                baseline = contained_path(project, baseline_relative)
                previous = (
                    _redact_content(baseline.read_text(encoding="utf-8"))
                    if baseline.is_file() and not baseline.is_symlink()
                    else ""
                )
                actual_mode = (
                    f"0{stat.S_IMODE(baseline.stat().st_mode):03o}"
                    if baseline.exists()
                    else None
                )
                unified = "".join(
                    difflib.unified_diff(
                        previous.splitlines(keepends=True),
                        [],
                        fromfile=baseline_relative,
                        tofile=f"planned/{path}",
                    )
                )
                diffs.append(
                    FileDiff(
                        path,
                        baseline_relative,
                        "removed",
                        unified,
                        None,
                        actual_mode,
                    )
                )
        if output_root is not None:
            for path in sorted(untracked_paths - desired_paths):
                baseline_relative = _baseline_path(
                    path,
                    output_directory=output_directory,
                    against=against,
                )
                candidate = output_root.joinpath(*Path(path).parts)
                mode = candidate.lstat().st_mode
                status = "unowned" if stat.S_ISREG(mode) else "unsafe"
                diffs.append(
                    FileDiff(
                        path,
                        baseline_relative,
                        status,
                        "",
                        None,
                        f"0{stat.S_IMODE(mode):03o}",
                    )
                )
    return tuple(sorted(diffs, key=lambda item: item.path))


def render_human(diffs: Iterable[FileDiff]) -> str:
    sections = []
    for item in diffs:
        sections.append(
            f"{item.status.upper():9} {item.path} "
            f"[mode {item.actual_mode or '-'} -> {item.expected_mode or '-'}]"
        )
        if item.unified_diff:
            sections.append(item.unified_diff.rstrip("\n"))
    return "\n".join(sections) + ("\n" if sections else "")


def render_json(diffs: Iterable[FileDiff]) -> str:
    return json.dumps([item.to_dict() for item in diffs], indent=2, sort_keys=True) + "\n"
