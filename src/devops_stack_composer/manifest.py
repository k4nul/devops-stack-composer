"""Generated-file ownership, collision detection, and integrity tracking."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft7Validator, FormatChecker

from devops_stack_composer import __version__
from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.errors import (
    GeneratedFileConflictError,
    ManifestValidationError,
    UnsafePathError,
)
from devops_stack_composer.filesystem import atomic_write, contained_path, normalize_relative_path, sha256_file
from devops_stack_composer.resources import schema_path
from devops_stack_composer.validation import ValidationReport


MANIFEST_NAME = ".devops-stack-manifest.json"
MANIFEST_SCHEMA = schema_path("generated-manifest.schema.json")


def sha256_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PlannedFile:
    path: str
    action: str
    reason: str


@dataclass(frozen=True)
class WritePlan:
    files: tuple[PlannedFile, ...]

    @property
    def conflicts(self) -> tuple[PlannedFile, ...]:
        return tuple(file for file in self.files if file.action == "conflict")

    @property
    def stale(self) -> tuple[PlannedFile, ...]:
        return tuple(file for file in self.files if file.action == "stale")

    @property
    def unowned(self) -> tuple[PlannedFile, ...]:
        return tuple(file for file in self.files if file.action == "unowned")

    @property
    def unsafe(self) -> tuple[PlannedFile, ...]:
        return tuple(file for file in self.files if file.action == "unsafe")

    @property
    def changed(self) -> tuple[PlannedFile, ...]:
        return tuple(
            file
            for file in self.files
            if file.action
            in {"create", "replace", "conflict", "stale", "unowned", "unsafe"}
        )


@dataclass(frozen=True)
class ManifestVerification:
    modified: tuple[str, ...]
    missing: tuple[str, ...]
    untracked: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not (self.modified or self.missing or self.untracked)


class GeneratedManifest:
    def __init__(self, path: Path, data: dict[str, Any]):
        self.path = path
        self.data = data

    @classmethod
    def validate_data(cls, data: dict[str, Any]) -> None:
        schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
        errors = sorted(
            Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(data),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            details = "\n  - ".join(
                "$" + "".join(f".{part}" for part in error.absolute_path) + f": {error.message}"
                for error in errors
            )
            raise ManifestValidationError(f"generated manifest validation failed:\n  - {details}")
        paths = [entry["path"] for entry in data["files"]]
        if len(paths) != len(set(paths)):
            raise ManifestValidationError(
                "generated manifest validation failed: file paths must be unique"
            )
        counts = data["validation"]["counts"]
        expected_passed = (
            counts["FAILED"] == 0
            and counts["BLOCKED_MISSING_REQUIRED_TOOL"] == 0
        )
        if data["validation"]["passed"] != expected_passed:
            raise ManifestValidationError(
                "generated manifest validation failed: validation.passed is inconsistent with counts"
            )

    @classmethod
    def load(cls, project: Path, output_directory: str) -> "GeneratedManifest | None":
        relative = f"{normalize_relative_path(output_directory)}/{MANIFEST_NAME}"
        path = contained_path(project, relative)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestValidationError(f"cannot read generated manifest {path}: {exc}") from exc
        cls.validate_data(data)
        if data["outputDirectory"] != normalize_relative_path(output_directory):
            raise ManifestValidationError(
                "generated manifest outputDirectory does not match the requested output directory"
            )
        return cls(path, data)

    def file_map(self) -> dict[str, dict[str, Any]]:
        return {entry["path"]: entry for entry in self.data["files"]}

    def verify(self, project: Path) -> ManifestVerification:
        output = self.data["outputDirectory"]
        tracked = self.file_map()
        modified: list[str] = []
        missing: list[str] = []
        for relative, entry in tracked.items():
            try:
                target = contained_path(project, f"{output}/{relative}")
            except UnsafePathError:
                modified.append(relative)
                continue
            if not target.is_file():
                missing.append(relative)
            elif target.is_symlink():
                modified.append(relative)
            elif (
                sha256_file(target) != entry["sha256"]
                or stat.S_IMODE(target.stat().st_mode) != int(entry["mode"], 8)
            ):
                modified.append(relative)
        output_path = contained_path(project, output)
        untracked: list[str] = []
        if output_path.exists():
            for candidate in sorted(output_path.rglob("*")):
                relative = candidate.relative_to(output_path).as_posix()
                if candidate.is_symlink():
                    if relative not in tracked:
                        untracked.append(relative)
                    continue
                if not candidate.is_dir() and not candidate.is_file():
                    untracked.append(relative)
                    continue
                if (
                    candidate.is_file()
                    and relative != MANIFEST_NAME
                    and relative not in tracked
                ):
                    untracked.append(relative)
        return ManifestVerification(tuple(modified), tuple(missing), tuple(untracked))


class ArtifactWriter:
    def __init__(self, project: Path, output_directory: str = "generated"):
        self.project = project.resolve(strict=True)
        self.output_directory = normalize_relative_path(output_directory)

    @staticmethod
    def collect(results: Iterable[AdapterResult]) -> tuple[GeneratedArtifact, ...]:
        artifacts: dict[str, GeneratedArtifact] = {}
        for result in results:
            for artifact in result.artifacts:
                path = normalize_relative_path(artifact.path)
                if path in artifacts:
                    raise ManifestValidationError(f"multiple adapters generated the same path: {path}")
                artifacts[path] = artifact
        return tuple(artifacts[path] for path in sorted(artifacts))

    def plan(
        self,
        artifacts: Iterable[GeneratedArtifact],
        previous: GeneratedManifest | None,
    ) -> WritePlan:
        previous_files = previous.file_map() if previous else {}
        planned: list[PlannedFile] = []
        seen: set[str] = set()
        try:
            output_path = contained_path(self.project, self.output_directory)
        except UnsafePathError as exc:
            return WritePlan(
                (
                    PlannedFile(
                        self.output_directory,
                        "unsafe",
                        str(exc),
                    ),
                )
            )
        if output_path.exists() and not output_path.is_dir():
            return WritePlan(
                (
                    PlannedFile(
                        self.output_directory,
                        "unsafe",
                        "generated output root is not a directory",
                    ),
                )
            )
        for artifact in sorted(artifacts, key=lambda item: item.path):
            relative = normalize_relative_path(artifact.path)
            if relative in seen:
                raise ManifestValidationError(f"duplicate generated path: {relative}")
            seen.add(relative)
            try:
                target = contained_path(
                    self.project,
                    f"{self.output_directory}/{relative}",
                )
            except UnsafePathError as exc:
                planned.append(PlannedFile(relative, "unsafe", str(exc)))
                continue
            desired_hash = sha256_content(artifact.content)
            if not target.exists():
                planned.append(PlannedFile(relative, "create", "file does not exist"))
                continue
            if target.is_symlink() or not target.is_file():
                planned.append(
                    PlannedFile(relative, "unsafe", "target is not a regular file")
                )
                continue
            actual_hash = sha256_file(target)
            actual_mode = stat.S_IMODE(target.stat().st_mode)
            tracked = previous_files.get(relative)
            if tracked is None:
                planned.append(PlannedFile(relative, "conflict", "existing file is not owned by the manifest"))
            elif (
                actual_hash != tracked["sha256"]
                or actual_mode != int(tracked["mode"], 8)
            ):
                planned.append(PlannedFile(relative, "conflict", "generated file was modified by the user"))
            elif actual_hash == desired_hash and actual_mode == artifact.mode & 0o777:
                planned.append(PlannedFile(relative, "unchanged", "content hash matches"))
            else:
                planned.append(PlannedFile(relative, "replace", "tracked generated content changed"))
        if output_path.exists():
            for candidate in sorted(output_path.rglob("*")):
                relative = candidate.relative_to(output_path).as_posix()
                if candidate.is_symlink():
                    if relative not in seen:
                        planned.append(
                            PlannedFile(
                                relative,
                                "unowned",
                                "symbolic links are forbidden inside generated output",
                            )
                        )
                    continue
                if candidate.is_dir():
                    continue
                if not candidate.is_file():
                    planned.append(
                        PlannedFile(
                            relative,
                            "unsafe",
                            "non-regular entries are forbidden inside generated output",
                        )
                    )
                    continue
                if relative == MANIFEST_NAME:
                    continue
                # Revalidate each discovered path so an output symlink cannot turn
                # the inventory walk into an out-of-project read.
                contained_path(self.project, f"{self.output_directory}/{relative}")
                if relative in seen:
                    continue
                if relative in previous_files:
                    planned.append(
                        PlannedFile(
                            relative,
                            "stale",
                            "previously generated artifact is no longer planned; remove it explicitly",
                        )
                    )
                else:
                    planned.append(
                        PlannedFile(
                            relative,
                            "unowned",
                            "unowned file exists inside the generated output directory",
                        )
                    )
        return WritePlan(tuple(planned))

    def write(
        self,
        artifacts: Iterable[GeneratedArtifact],
        *,
        config_hash: str,
        results: Iterable[AdapterResult],
        validation: ValidationReport,
        environments: Iterable[str],
        force: bool = False,
        generated_at: datetime | None = None,
    ) -> GeneratedManifest:
        materialized_artifacts = tuple(artifacts)
        materialized_results = tuple(results)
        result_map = {result.adapter: result for result in materialized_results}
        missing = [name for name in ("docker", "jenkins", "kubernetes") if name not in result_map]
        if missing:
            raise ManifestValidationError(
                f"cannot write manifest without adapter results: {', '.join(missing)}"
            )
        previous = GeneratedManifest.load(self.project, self.output_directory)
        plan = self.plan(materialized_artifacts, previous)
        if plan.stale:
            paths = ", ".join(file.path for file in plan.stale)
            raise GeneratedFileConflictError(
                "refusing to delete obsolete generated files automatically: "
                f"{paths}; remove them explicitly and rerun generation"
            )
        if plan.unowned:
            paths = ", ".join(file.path for file in plan.unowned)
            raise GeneratedFileConflictError(
                "refusing to absorb unowned files into generated output: "
                f"{paths}; move them outside the generated directory"
            )
        if plan.unsafe:
            paths = ", ".join(file.path for file in plan.unsafe)
            raise GeneratedFileConflictError(
                "refusing to write unsafe or non-regular generated paths: "
                f"{paths}; --force cannot bypass this check"
            )
        if plan.conflicts and not force:
            paths = ", ".join(file.path for file in plan.conflicts)
            raise GeneratedFileConflictError(
                f"refusing to overwrite generated-file conflicts: {paths}; rerun with --force to replace"
            )

        entries = [
            {
                "path": normalize_relative_path(artifact.path),
                "sha256": sha256_content(artifact.content),
                "mode": f"0{artifact.mode & 0o777:03o}",
                "origins": sorted(set(artifact.origins)),
            }
            for artifact in sorted(materialized_artifacts, key=lambda item: item.path)
        ]
        timestamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        data = {
            "schemaVersion": "1.0.0",
            "toolVersion": __version__,
            "generatedAt": timestamp.isoformat().replace("+00:00", "Z"),
            "configHash": config_hash,
            "outputDirectory": self.output_directory,
            "templates": {
                name: {
                    "commit": result_map[name].template_commit,
                    "adapterVersion": result_map[name].adapter_version,
                }
                for name in ("docker", "jenkins", "kubernetes")
            },
            "environments": list(environments),
            "validation": {
                "passed": validation.passed,
                "counts": validation.counts,
            },
            "files": entries,
        }
        GeneratedManifest.validate_data(data)

        for artifact in sorted(materialized_artifacts, key=lambda item: item.path):
            relative = normalize_relative_path(artifact.path)
            atomic_write(
                self.project,
                f"{self.output_directory}/{relative}",
                artifact.content,
                mode=artifact.mode,
                overwrite=True,
            )
        manifest_content = json.dumps(data, indent=2, sort_keys=True) + "\n"
        relative_manifest = f"{self.output_directory}/{MANIFEST_NAME}"
        atomic_write(self.project, relative_manifest, manifest_content, overwrite=True)
        loaded = GeneratedManifest.load(self.project, self.output_directory)
        if loaded is None:  # pragma: no cover - atomic_write above makes this unreachable.
            raise ManifestValidationError("manifest disappeared after atomic write")
        return loaded
