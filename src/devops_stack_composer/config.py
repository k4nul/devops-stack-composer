"""Strict YAML loading and JSON Schema validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from devops_stack_composer.errors import (
    ConfigParseError,
    ConfigValidationError,
    ValidationIssue,
)
from devops_stack_composer.model import NormalizedDevOpsModel, normalize_config


SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "devops-stack.schema.json"
SENSITIVE_NAME = re.compile(r"(?:secret|token|password|credential|private.?key)", re.IGNORECASE)


@dataclass(frozen=True)
class LoadedConfig:
    path: Path
    raw: dict[str, Any]
    model: NormalizedDevOpsModel
    config_hash: str


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_path(error: ValidationError) -> str:
    parts = [str(part) for part in error.absolute_path]
    if error.validator == "additionalProperties":
        match = re.search(r"\('([^']+)' was unexpected\)", error.message)
        if match:
            parts.append(match.group(1))
    return "$" + "".join(f"[{part}]" if part.isdigit() else f".{part}" for part in parts)


def _expected(error: ValidationError) -> str:
    if error.validator == "type":
        expected = error.validator_value
        if isinstance(expected, list):
            return " or ".join(expected)
        return str(expected)
    if error.validator == "enum":
        return "one of " + ", ".join(json.dumps(value) for value in error.validator_value)
    if error.validator == "const":
        return json.dumps(error.validator_value)
    if error.validator == "required":
        missing = re.search(r"'([^']+)' is a required property", error.message)
        return f"required field {missing.group(1) if missing else error.validator_value}"
    if error.validator == "additionalProperties":
        return "a documented field name"
    if error.validator in {"minimum", "maximum", "minLength", "maxLength", "pattern"}:
        return f"{error.validator} {error.validator_value}"
    return str(error.validator_value)


def _example(error: ValidationError) -> str:
    schema = error.schema
    if "examples" in schema and schema["examples"]:
        return json.dumps(schema["examples"][0])
    if "default" in schema:
        return json.dumps(schema["default"])
    if "enum" in schema and schema["enum"]:
        return json.dumps(schema["enum"][0])
    if error.validator == "additionalProperties":
        properties = schema.get("properties", {})
        if properties:
            return json.dumps(next(iter(properties)))
    if error.validator == "required":
        missing = re.search(r"'([^']+)' is a required property", error.message)
        if missing:
            return json.dumps({missing.group(1): "<value>"})
    return "a value matching the schema"


def _received(error: ValidationError, path: str) -> str:
    if SENSITIVE_NAME.search(path):
        return "<redacted>"
    try:
        rendered = json.dumps(error.instance, sort_keys=True)
    except TypeError:
        rendered = repr(error.instance)
    return rendered if len(rendered) <= 160 else rendered[:157] + "..."


def _issue(error: ValidationError) -> ValidationIssue:
    path = _json_path(error)
    message = error.message
    if SENSITIVE_NAME.search(path):
        message = f"value does not satisfy {error.validator} constraint"
    return ValidationIssue(
        path=path,
        expected=_expected(error),
        received=_received(error, path),
        example=_example(error),
        message=message,
    )


def parse_config(text: str, *, source: str = "<memory>") -> dict[str, Any]:
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigParseError(f"cannot parse YAML from {source}{location}: {exc}") from exc
    if not isinstance(value, dict):
        received = type(value).__name__
        raise ConfigParseError(
            f"configuration root in {source} must be a mapping; received {received}"
        )
    return value


def validate_config(config: dict[str, Any], *, schema: dict[str, Any] | None = None) -> None:
    validator = Draft7Validator(schema or load_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(config), key=lambda error: list(error.absolute_path))
    if errors:
        raise ConfigValidationError([_issue(error) for error in errors])


def load_config(path: Path) -> LoadedConfig:
    resolved = path.resolve(strict=True)
    raw = parse_config(resolved.read_text(encoding="utf-8"), source=str(resolved))
    validate_config(raw)
    return LoadedConfig(
        path=resolved,
        raw=raw,
        model=normalize_config(raw),
        config_hash=canonical_hash(raw),
    )
