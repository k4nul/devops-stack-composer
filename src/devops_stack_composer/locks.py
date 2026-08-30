"""Validated, explicit-only template lock management."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker

from devops_stack_composer.errors import LockValidationError


LOCK_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "templates-lock.schema.json"
TEMPLATE_KEYS = ("docker", "jenkins", "kubernetes")


@dataclass(frozen=True)
class TemplatePin:
    key: str
    name: str
    repository: str
    commit: str
    adapter_version: str
    schema_version: str
    checked_at: str
    license_spdx: str
    license_file: str


@dataclass(frozen=True)
class TemplateUpdate:
    key: str
    current_commit: str
    remote_commit: str

    @property
    def changed(self) -> bool:
        return self.current_commit != self.remote_commit


class TemplateLock:
    def __init__(self, path: Path, data: dict[str, Any]):
        self.path = path
        self.data = data

    @classmethod
    def load(cls, path: Path) -> "TemplateLock":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LockValidationError(f"cannot read template lock {path}: {exc}") from exc
        schema = json.loads(LOCK_SCHEMA_PATH.read_text(encoding="utf-8"))
        errors = sorted(
            Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(data),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            rendered = []
            for error in errors:
                path_text = "$" + "".join(f".{part}" for part in error.absolute_path)
                rendered.append(f"{path_text}: {error.message}")
            raise LockValidationError("template lock validation failed:\n  - " + "\n  - ".join(rendered))
        return cls(path.resolve(), data)

    def pin(self, key: str) -> TemplatePin:
        if key not in TEMPLATE_KEYS:
            raise LockValidationError(
                f"unknown template {key!r}; expected one of {', '.join(TEMPLATE_KEYS)}"
            )
        value = self.data["templates"][key]
        return TemplatePin(
            key=key,
            name=value["name"],
            repository=value["repository"],
            commit=value["commit"],
            adapter_version=value["adapterVersion"],
            schema_version=value["schemaVersion"],
            checked_at=value["checkedAt"],
            license_spdx=value["license"]["spdx"],
            license_file=value["license"]["file"],
        )

    def pins(self) -> tuple[TemplatePin, ...]:
        return tuple(self.pin(key) for key in TEMPLATE_KEYS)

    def check_remote_updates(self, *, timeout: int = 30) -> tuple[TemplateUpdate, ...]:
        updates = []
        for pin in self.pins():
            command = ["git", "ls-remote", "--heads", pin.repository, "main"]
            try:
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise LockValidationError(
                    f"cannot inspect remote main for {pin.key} ({pin.repository}): {exc}"
                ) from exc
            fields = result.stdout.strip().split()
            if len(fields) != 2 or len(fields[0]) != 40:
                raise LockValidationError(
                    f"remote {pin.repository} did not return a valid main commit"
                )
            updates.append(TemplateUpdate(pin.key, pin.commit, fields[0]))
        return tuple(updates)

    def with_updates(
        self,
        updates: tuple[TemplateUpdate, ...],
        *,
        checked_at: date | None = None,
    ) -> "TemplateLock":
        data = deepcopy(self.data)
        today = (checked_at or date.today()).isoformat()
        for update in updates:
            if update.key not in TEMPLATE_KEYS:
                raise LockValidationError(f"cannot update unknown template {update.key!r}")
            data["templates"][update.key]["commit"] = update.remote_commit
            data["templates"][update.key]["checkedAt"] = today
        return TemplateLock(self.path, data)

    def write(self) -> None:
        """Atomically persist this lock. Callers must explicitly choose this operation."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            dir=self.path.parent,
            text=True,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
