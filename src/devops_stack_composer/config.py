"""Strict YAML loading and JSON Schema validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from devops_stack_composer.errors import (
    ConfigParseError,
    ConfigValidationError,
    ValidationIssue,
)
from devops_stack_composer.model import NormalizedDevOpsModel, normalize_config
from devops_stack_composer.resources import schema_path


SCHEMA_PATH = schema_path("devops-stack.schema.json")
SENSITIVE_NAME = re.compile(r"(?:secret|token|password|credential|private.?key)", re.IGNORECASE)


class StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: StrictSafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class LoadedConfig:
    path: Path
    raw: dict[str, Any]
    model: NormalizedDevOpsModel
    config_hash: str


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _non_finite_issues(value: Any, path: str = "$") -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if isinstance(value, float) and not math.isfinite(value):
        issues.append(
            ValidationIssue(
                path=path,
                expected="a finite number",
                received="non-finite number",
                example="0",
                message="NaN and infinity are not supported",
            )
        )
        return issues
    if isinstance(value, dict):
        for key, child in value.items():
            issues.extend(_non_finite_issues(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_non_finite_issues(child, f"{path}[{index}]"))
    return issues


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


def _cross_field_issues(config: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    validation_profile = config.get("validation", {}).get("profile", "static")
    configured_execution = config.get("execution")
    execution_profile = (
        configured_execution.get("profile", validation_profile)
        if isinstance(configured_execution, dict)
        else validation_profile
    )
    canonical_execution_profile = (
        "kind-e2e" if execution_profile == "local-kind" else execution_profile
    )
    if canonical_execution_profile != validation_profile:
        issues.append(
            ValidationIssue(
                path="$.execution.profile",
                expected=f"the validation profile {validation_profile!r}",
                received=json.dumps(execution_profile),
                example=json.dumps(validation_profile),
                message=(
                    "execution and validation profiles must select the same policy; "
                    "local-kind is only an alias for kind-e2e"
                ),
            )
        )

    execution_cleanup = (
        configured_execution.get("cleanup", "always")
        if isinstance(configured_execution, dict)
        else "always"
    )
    configured_kubernetes = config.get("kubernetes")
    kubernetes_e2e = (
        configured_kubernetes.get("e2e", {})
        if isinstance(configured_kubernetes, dict)
        else {}
    )
    kubernetes_cleanup = (
        kubernetes_e2e.get("cleanup", execution_cleanup)
        if isinstance(kubernetes_e2e, dict)
        else execution_cleanup
    )
    if kubernetes_cleanup != execution_cleanup:
        issues.append(
            ValidationIssue(
                path="$.kubernetes.e2e.cleanup",
                expected=f"the authoritative execution cleanup policy {execution_cleanup!r}",
                received=json.dumps(kubernetes_cleanup),
                example=json.dumps(execution_cleanup),
                message="execution.cleanup and kubernetes.e2e.cleanup must match",
            )
        )
    return issues


def parse_config(text: str, *, source: str = "<memory>") -> dict[str, Any]:
    try:
        value = yaml.load(text, Loader=StrictSafeLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", "")
        reason = (
            "duplicate mapping key"
            if isinstance(problem, str) and "duplicate mapping key" in problem
            else "invalid YAML syntax"
        )
        raise ConfigParseError(
            f"cannot parse YAML from {source}{location}: {reason}"
        ) from exc
    if not isinstance(value, dict):
        received = type(value).__name__
        raise ConfigParseError(
            f"configuration root in {source} must be a mapping; received {received}"
        )
    return value


def validate_config(config: dict[str, Any], *, schema: dict[str, Any] | None = None) -> None:
    validator = Draft7Validator(schema or load_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(config), key=lambda error: list(error.absolute_path))
    issues = [_issue(error) for error in errors]
    issues.extend(_non_finite_issues(config))
    if not issues:
        issues.extend(_cross_field_issues(config))
    if issues:
        raise ConfigValidationError(issues)
    registry = config.get("image", {}).get("registry")
    if isinstance(registry, str) and ":" in registry:
        port_text = registry.rsplit(":", 1)[1]
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise ConfigValidationError(
                [
                    ValidationIssue(
                        path="$.image.registry",
                        expected="registry port from 1 through 65535",
                        received=json.dumps(registry),
                        example='"registry.example:5000"',
                        message="registry port is outside the valid TCP range",
                    )
                ]
            )


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
