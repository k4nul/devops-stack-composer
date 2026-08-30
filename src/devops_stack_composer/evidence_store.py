"""Symlink-safe persistence and checksum verification for execution evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devops_stack_composer.errors import DevOpsStackError, UnsafePathError
from devops_stack_composer.filesystem import (
    atomic_write,
    contained_path,
    normalize_relative_path,
    project_root,
    sha256_file,
)


_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_CHECKSUM = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")


class EvidenceStoreError(DevOpsStackError):
    """Raised when an evidence bundle is unsafe, incomplete, or tampered."""


def new_run_id(*, now: datetime | None = None, random_hex: str | None = None) -> str:
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    suffix = random_hex or uuid.uuid4().hex[:12]
    value = timestamp.strftime("%Y%m%dT%H%M%SZ-") + suffix
    if not _RUN_ID.fullmatch(value):
        raise EvidenceStoreError("generated run ID is not safe")
    return value


@dataclass(frozen=True)
class EvidenceStore:
    project: Path
    relative_root: str
    run_id: str

    @classmethod
    def create(
        cls,
        project: Path,
        *,
        work_directory: str = ".devops-stack/runs",
        run_id: str | None = None,
    ) -> "EvidenceStore":
        resolved_project = project_root(project)
        work_directory = normalize_relative_path(work_directory)
        selected = run_id or new_run_id()
        if not _RUN_ID.fullmatch(selected):
            raise EvidenceStoreError(
                "run ID must use YYYYMMDDTHHMMSSZ followed by 12 lowercase hex characters"
            )
        relative_root = f"{work_directory}/{selected}"
        root = contained_path(resolved_project, relative_root)
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        contained_path(resolved_project, work_directory)
        try:
            root.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise EvidenceStoreError(f"run ID collision: {selected}") from exc
        if root.is_symlink() or contained_path(resolved_project, relative_root) != root:
            raise UnsafePathError("run directory changed during creation")
        os.chmod(root, 0o700)
        for name in ("logs", "kubernetes", "diagnostics"):
            child = root / name
            child.mkdir(mode=0o700)
        return cls(resolved_project, relative_root, selected)

    @classmethod
    def open(
        cls,
        project: Path,
        run_id: str,
        *,
        work_directory: str = ".devops-stack/runs",
    ) -> "EvidenceStore":
        resolved_project = project_root(project)
        if not _RUN_ID.fullmatch(run_id):
            raise EvidenceStoreError("invalid run ID")
        relative_root = f"{normalize_relative_path(work_directory)}/{run_id}"
        root = contained_path(resolved_project, relative_root)
        if not root.is_dir() or root.is_symlink():
            raise EvidenceStoreError(f"execution run does not exist: {run_id}")
        return cls(resolved_project, relative_root, run_id)

    @property
    def root(self) -> Path:
        return contained_path(self.project, self.relative_root)

    def path(self, relative: str) -> Path:
        normalized = normalize_relative_path(relative)
        return contained_path(self.project, f"{self.relative_root}/{normalized}")

    def write_json(self, relative: str, value: Any, *, overwrite: bool = False) -> Path:
        try:
            payload = json.dumps(
                value,
                indent=2,
                sort_keys=True,
                allow_nan=False,
                ensure_ascii=False,
            ) + "\n"
        except (TypeError, ValueError) as exc:
            raise EvidenceStoreError("evidence JSON must contain finite JSON values") from exc
        return self.write_text(relative, payload, overwrite=overwrite)

    def write_text(
        self,
        relative: str,
        content: str,
        *,
        mode: int = 0o600,
        overwrite: bool = False,
    ) -> Path:
        normalized = normalize_relative_path(relative)
        if "\x00" in content:
            raise EvidenceStoreError("evidence text must not contain NUL bytes")
        return atomic_write(
            self.project,
            f"{self.relative_root}/{normalized}",
            content,
            mode=mode,
            overwrite=overwrite,
        )

    def _material_files(self) -> tuple[Path, ...]:
        root = self.root
        values: list[Path] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise EvidenceStoreError(
                    f"evidence bundle contains a symbolic link: {path.relative_to(root)}"
                )
            if path.is_file() and path.name != "SHA256SUMS":
                values.append(path)
        return tuple(values)

    def write_checksums(self, *, overwrite: bool = False) -> Path:
        root = self.root
        lines = [
            f"{sha256_file(path)}  {path.relative_to(root).as_posix()}"
            for path in self._material_files()
        ]
        if not lines:
            raise EvidenceStoreError("cannot checksum an empty evidence bundle")
        return self.write_text(
            "SHA256SUMS",
            "\n".join(lines) + "\n",
            overwrite=overwrite,
        )

    def verify_checksums(self) -> dict[str, str]:
        checksum_path = self.path("SHA256SUMS")
        if checksum_path.is_symlink() or not checksum_path.is_file():
            raise EvidenceStoreError("evidence bundle has no regular SHA256SUMS file")
        expected: dict[str, str] = {}
        for line_number, line in enumerate(
            checksum_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = _CHECKSUM.fullmatch(line)
            if not match:
                raise EvidenceStoreError(f"invalid SHA256SUMS line {line_number}")
            digest, relative = match.groups()
            normalized = normalize_relative_path(relative)
            if normalized == "SHA256SUMS" or normalized in expected:
                raise EvidenceStoreError(f"invalid or duplicate checksum path: {relative}")
            expected[normalized] = digest
        actual_paths = {
            path.relative_to(self.root).as_posix(): path
            for path in self._material_files()
        }
        if set(expected) != set(actual_paths):
            missing = sorted(set(expected) - set(actual_paths))
            untracked = sorted(set(actual_paths) - set(expected))
            raise EvidenceStoreError(
                f"checksum inventory mismatch; missing={missing}; untracked={untracked}"
            )
        mismatched = [
            relative
            for relative, path in actual_paths.items()
            if sha256_file(path) != expected[relative]
        ]
        if mismatched:
            raise EvidenceStoreError(
                "evidence checksum mismatch: " + ", ".join(sorted(mismatched))
            )
        return expected

