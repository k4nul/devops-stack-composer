"""Command-line entry point for DevOps Stack Composer."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from devops_stack_composer import __version__
from devops_stack_composer.composition import (
    Composition,
    compose,
    generated_integrity_report,
)
from devops_stack_composer.diffing import diff_artifacts, render_human, render_json
from devops_stack_composer.doctor import run_doctor
from devops_stack_composer.errors import DevOpsStackError, UnsafePathError
from devops_stack_composer.explain import explain_config_value, explain_generated_file
from devops_stack_composer.filesystem import (
    atomic_write,
    contained_path,
    project_root,
    sha256_file,
)
from devops_stack_composer.inspector import initial_config, inspect_application
from devops_stack_composer.locks import TEMPLATE_KEYS, TemplateLock
from devops_stack_composer.manifest import ArtifactWriter, GeneratedManifest
from devops_stack_composer.report import (
    build_report,
    redact_sensitive,
    write_report_files,
)
from devops_stack_composer.resources import default_lock_path
from devops_stack_composer.sources import SourceResolver
from devops_stack_composer.validation import (
    CheckResult,
    ValidationReport,
    ValidationStatus,
    merge_reports,
)


DEFAULT_CONFIG = "devops-stack.yaml"
DEFAULT_OUTPUT = "generated"


def _template_path(value: str) -> tuple[str, Path]:
    key, separator, raw_path = value.partition("=")
    if not separator or key not in TEMPLATE_KEYS or not raw_path:
        raise argparse.ArgumentTypeError(
            "template path must be docker=PATH, jenkins=PATH, or kubernetes=PATH"
        )
    return key, Path(raw_path)


def _add_project_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project",
        type=Path,
        default=Path.cwd(),
        help="application project root (default: current directory)",
    )


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"configuration path relative to the project (default: {DEFAULT_CONFIG})",
    )


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lock", help="template lock path relative to the project")
    parser.add_argument(
        "--template",
        action="append",
        type=_template_path,
        default=[],
        metavar="NAME=PATH",
        help="explicit local template path; may be repeated",
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="do not fetch a missing locked template into the cache",
    )


def _add_composition_arguments(parser: argparse.ArgumentParser) -> None:
    _add_project_argument(parser)
    _add_config_argument(parser)
    _add_source_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devops-stack",
        description=(
            "Compose Docker, Jenkins, and Kubernetes delivery artifacts from "
            "one application contract."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="inspect an application and create configuration")
    _add_project_argument(init)
    _add_config_argument(init)
    init.add_argument("--dry-run", action="store_true", help="print YAML without writing")
    init.add_argument("--force", action="store_true", help="replace an existing configuration")
    init.set_defaults(handler=_run_init)

    inspect = commands.add_parser("inspect", help="inspect application and existing DevOps files")
    _add_project_argument(inspect)
    inspect.add_argument("--json", action="store_true", dest="json_output")
    inspect.set_defaults(handler=_run_inspect)

    generate = commands.add_parser("generate", help="preview or write composed artifacts")
    _add_composition_arguments(generate)
    write_mode = generate.add_mutually_exclusive_group()
    write_mode.add_argument("--write", action="store_true", help="write the generated directory")
    write_mode.add_argument("--dry-run", action="store_true", help="preview only (the default)")
    generate.add_argument("--force", action="store_true", help="replace user-modified generated files")
    generate.add_argument("--build-image", action="store_true", help="also run an optional local Docker build")
    generate.add_argument("--image-tag", help="concrete tag used by --build-image")
    generate.add_argument("--json", action="store_true", dest="json_output")
    generate.set_defaults(handler=_run_generate)

    validate = commands.add_parser(
        "validate",
        help="validate configuration, adapters, contracts, and generated files",
    )
    _add_composition_arguments(validate)
    validate.add_argument("--build-image", action="store_true", help="also run an optional local Docker build")
    validate.add_argument("--image-tag", help="concrete tag used by --build-image")
    validate.add_argument("--json", action="store_true", dest="json_output")
    validate.set_defaults(handler=_run_validate)

    diff = commands.add_parser("diff", help="compare planned artifacts with a baseline")
    _add_composition_arguments(diff)
    diff.add_argument("--against", choices=("generated", "project"), default="generated")
    diff.add_argument("--json", action="store_true", dest="json_output")
    diff.set_defaults(handler=_run_diff)

    doctor = commands.add_parser("doctor", help="diagnose tools, template paths, and locks")
    _add_project_argument(doctor)
    _add_source_arguments(doctor)
    doctor.add_argument("--remote", action="store_true", help="also query template remotes")
    doctor.add_argument("--json", action="store_true", dest="json_output")
    doctor.set_defaults(handler=_run_doctor)

    templates = commands.add_parser("templates", help="inspect or update locked templates")
    template_commands = templates.add_subparsers(dest="templates_command", required=True)
    templates_list = template_commands.add_parser("list", help="list locked and resolved versions")
    _add_project_argument(templates_list)
    _add_source_arguments(templates_list)
    templates_list.add_argument("--json", action="store_true", dest="json_output")
    templates_list.set_defaults(handler=_run_templates_list)
    templates_update = template_commands.add_parser("update", help="preview or write remote main pins")
    _add_project_argument(templates_update)
    templates_update.add_argument("--lock", help="lock path relative to the project")
    templates_update.add_argument("--write", action="store_true", help="explicitly update the lock")
    templates_update.add_argument("--json", action="store_true", dest="json_output")
    templates_update.set_defaults(handler=_run_templates_update)
    templates_path = template_commands.add_parser("path", help="resolve one template path for automation")
    _add_project_argument(templates_path)
    _add_source_arguments(templates_path)
    templates_path.add_argument("template_name", choices=TEMPLATE_KEYS)
    templates_path.set_defaults(handler=_run_templates_path)

    explain = commands.add_parser("explain", help="explain a generated file or configuration value")
    _add_project_argument(explain)
    _add_config_argument(explain)
    explain.add_argument("target", help="generated path or config:$.image.registry")
    explain.add_argument("--json", action="store_true", dest="json_output")
    explain.set_defaults(handler=_run_explain)

    report = commands.add_parser("report", help="write Markdown and JSON validation reports")
    _add_composition_arguments(report)
    report.add_argument("--force", action="store_true", help="replace existing report files")
    report.add_argument("--json", action="store_true", dest="json_output")
    report.set_defaults(handler=_run_report)
    return parser


def _resolved_project(args: argparse.Namespace) -> Path:
    return project_root(args.project)


def _lock_path(args: argparse.Namespace, project: Path) -> Path:
    if getattr(args, "lock", None):
        return contained_path(project, args.lock)
    local = contained_path(project, "templates.lock.json")
    if local.exists():
        if not local.is_file():
            raise UnsafePathError(
                "project templates.lock.json is not a regular file"
            )
        return local
    return default_lock_path()


def _load_lock(args: argparse.Namespace, project: Path) -> TemplateLock:
    return TemplateLock.load(_lock_path(args, project))


def _explicit_templates(args: argparse.Namespace) -> dict[str, Path]:
    values: dict[str, Path] = {}
    for key, path in getattr(args, "template", []):
        if key in values:
            raise ValueError(f"template path was supplied more than once: {key}")
        values[key] = path
    return values


def _composition(args: argparse.Namespace) -> Composition:
    project = _resolved_project(args)
    if getattr(args, "image_tag", None) and not getattr(args, "build_image", False):
        raise ValueError("--image-tag is only valid together with --build-image")
    return compose(
        project=project,
        config_path=contained_path(project, args.config),
        lock=_load_lock(args, project),
        explicit_template_paths=_explicit_templates(args),
        fetch_templates=not args.no_fetch,
        local_docker_build=getattr(args, "build_image", False),
        image_tag=getattr(args, "image_tag", None),
    )


def _safe_json(value: Any) -> str:
    return (
        json.dumps(
            redact_sensitive(value),
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )


def _print_validation(report: ValidationReport) -> None:
    for check in report.checks:
        print(f"{check.status.value:38} {check.scope:12} {check.check}: {check.message}")
    counts = ", ".join(f"{key}={value}" for key, value in report.counts.items())
    print(f"overall={'PASSED' if report.passed else 'FAILED'} ({counts})")


def _run_init(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    inspection = inspect_application(project)
    content = yaml.safe_dump(initial_config(inspection), sort_keys=False, allow_unicode=True)
    if args.dry_run:
        print(content, end="")
        return 0
    target = atomic_write(project, args.config, content, overwrite=args.force)
    print(f"created {target.relative_to(project)}; inferred values are marked for review")
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    inspection = inspect_application(_resolved_project(args))
    value = inspection.to_dict()
    if args.json_output:
        print(_safe_json(value), end="")
        return 0
    runtime = value["runtime"]
    print(
        f"runtime: {runtime['application_type'] or 'unknown'} "
        f"({runtime['confidence']} confidence; inferred, review required)"
    )
    for name in (
        "build_command",
        "test_command",
        "run_command",
        "build_artifact",
        "port",
        "health_endpoint",
        "readiness_endpoint",
    ):
        print(f"{name.replace('_', '-')}: {value[name] if value[name] is not None else 'unknown'}")
    for name in (
        "dockerfiles",
        "jenkinsfiles",
        "kubernetes_files",
        "conflicts",
        "missing",
    ):
        rendered = ", ".join(value[name]) if value[name] else "none"
        print(f"{name.replace('_', '-')}: {rendered}")
    return 0


def _plan_value(composition: Composition, writer: ArtifactWriter) -> dict[str, Any]:
    previous = GeneratedManifest.load(composition.project, DEFAULT_OUTPUT)
    plan = writer.plan(composition.artifacts, previous)
    return {
        "write": False,
        "outputDirectory": DEFAULT_OUTPUT,
        "validation": composition.validation.to_dict(),
        "files": [
            {"path": item.path, "action": item.action, "reason": item.reason}
            for item in plan.files
        ],
        "conflicts": [item.path for item in plan.conflicts],
        "stale": [item.path for item in plan.stale],
        "unowned": [item.path for item in plan.unowned],
        "unsafe": [item.path for item in plan.unsafe],
    }


def _run_generate(args: argparse.Namespace) -> int:
    if args.force and not args.write:
        raise ValueError("--force is only valid together with --write")
    if args.build_image and not args.write:
        raise ValueError("--build-image is only valid together with --write for generate")
    composition = _composition(args)
    writer = ArtifactWriter(composition.project, DEFAULT_OUTPUT)
    value = _plan_value(composition, writer)
    conflicts = value["conflicts"]
    if conflicts:
        conflict_report = ValidationReport(
            (
                CheckResult(
                    "generated.write-safety",
                    (
                        ValidationStatus.PASSED
                        if args.force
                        else ValidationStatus.FAILED
                    ),
                    (
                        "explicit --force permits replacing the listed generated paths"
                        if args.force
                        else "one or more generated paths would overwrite user changes"
                    ),
                    scope="generated",
                    details={"paths": conflicts},
                ),
            )
        )
        composition = replace(
            composition,
            validation=merge_reports(composition.validation, conflict_report),
        )
        value["validation"] = composition.validation.to_dict()
    if value["stale"]:
        stale_report = ValidationReport(
            (
                CheckResult(
                    "generated.stale-files",
                    ValidationStatus.FAILED,
                    "obsolete generated paths require explicit manual removal",
                    scope="generated",
                    details={"paths": value["stale"]},
                ),
            )
        )
        composition = replace(
            composition,
            validation=merge_reports(composition.validation, stale_report),
        )
        value["validation"] = composition.validation.to_dict()
    if value["unowned"]:
        unowned_report = ValidationReport(
            (
                CheckResult(
                    "generated.unowned-files",
                    ValidationStatus.FAILED,
                    "unowned files inside generated output are never bypassed by --force",
                    scope="generated",
                    details={"paths": value["unowned"]},
                ),
            )
        )
        composition = replace(
            composition,
            validation=merge_reports(composition.validation, unowned_report),
        )
        value["validation"] = composition.validation.to_dict()
    if value["unsafe"]:
        unsafe_report = ValidationReport(
            (
                CheckResult(
                    "generated.unsafe-paths",
                    ValidationStatus.FAILED,
                    "unsafe or non-regular generated paths are never bypassed by --force",
                    scope="generated",
                    details={"paths": value["unsafe"]},
                ),
            )
        )
        composition = replace(
            composition,
            validation=merge_reports(composition.validation, unsafe_report),
        )
        value["validation"] = composition.validation.to_dict()
    if args.write and composition.validation.passed:
        manifest = writer.write(
            composition.artifacts,
            config_hash=composition.loaded_config.config_hash,
            results=composition.results,
            validation=composition.validation,
            environments=("dev", "staging", "production"),
            force=args.force,
        )
        value["write"] = True
        value["manifest"] = str(manifest.path.relative_to(composition.project))
    elif args.write:
        value["writeBlocked"] = "validation failed; no artifact was written"
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        mode = "WRITE" if value["write"] else "PREVIEW"
        print(f"{mode}: {DEFAULT_OUTPUT}/")
        for item in value["files"]:
            print(f"{item['action'].upper():9} {item['path']} — {item['reason']}")
        _print_validation(composition.validation)
        if value.get("writeBlocked"):
            print(value["writeBlocked"], file=sys.stderr)
    return 0 if composition.validation.passed else 1


def _run_validate(args: argparse.Namespace) -> int:
    composition = _composition(args)
    _, integrity = generated_integrity_report(composition, output_directory=DEFAULT_OUTPUT)
    validation = merge_reports(composition.validation, integrity)
    if args.json_output:
        print(_safe_json(validation.to_dict()), end="")
    else:
        _print_validation(validation)
    return 0 if validation.passed else 1


def _run_diff(args: argparse.Namespace) -> int:
    composition = _composition(args)
    differences = diff_artifacts(
        composition.project,
        composition.artifacts,
        output_directory=DEFAULT_OUTPUT,
        against=args.against,
    )
    if args.json_output:
        print(render_json(differences), end="")
    else:
        print(render_human(differences), end="")
    has_changes = any(item.status != "unchanged" for item in differences)
    return 0 if composition.validation.passed and not has_changes else 1


def _run_doctor(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    lock = _load_lock(args, project)
    resolver = SourceResolver(lock, explicit_paths=_explicit_templates(args))
    report = run_doctor(
        lock=lock,
        resolver=resolver,
        check_remote=args.remote,
        fetch_templates=not args.no_fetch,
    )
    if args.json_output:
        print(_safe_json(report.to_dict()), end="")
    else:
        _print_validation(report)
    return 0 if report.passed else 1


def _template_values(args: argparse.Namespace) -> dict[str, Any]:
    project = _resolved_project(args)
    lock = _load_lock(args, project)
    resolver = SourceResolver(lock, explicit_paths=_explicit_templates(args))
    sources: dict[str, Any] = {}
    for key in TEMPLATE_KEYS:
        source = resolver.resolve(key, fetch=not args.no_fetch)
        pin = lock.pin(key)
        sources[key] = {
            "name": pin.name,
            "repository": pin.repository,
            "commit": pin.commit,
            "resolvedCommit": source.commit,
            "origin": source.origin,
            "matchesLock": source.matches_lock,
            "adapterVersion": pin.adapter_version,
            "schemaVersion": pin.schema_version,
            "checkedAt": pin.checked_at,
            "license": pin.license_spdx,
        }
    return sources


def _run_templates_list(args: argparse.Namespace) -> int:
    values = _template_values(args)
    if args.json_output:
        print(_safe_json(values), end="")
    else:
        for key in TEMPLATE_KEYS:
            value = values[key]
            match = "locked" if value["matchesLock"] else "MISMATCH"
            print(
                f"{key:10} {value['commit']} adapter={value['adapterVersion']} "
                f"schema={value['schemaVersion']} origin={value['origin']} {match}"
            )
    return 0 if all(value["matchesLock"] for value in values.values()) else 1


def _run_templates_update(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    loaded_path = _lock_path(args, project)
    lock = TemplateLock.load(loaded_path)
    loaded_hash = sha256_file(loaded_path)
    updates = lock.check_remote_updates()
    update_values = [
        {
            "template": update.key,
            "currentCommit": update.current_commit,
            "remoteCommit": update.remote_commit,
            "changed": update.changed,
        }
        for update in updates
    ]
    value = {
        "write": args.write,
        "updates": update_values,
    }
    updated = lock.with_updates(updates)
    changed_values = {
        item["template"]: item for item in update_values if item["changed"]
    }
    if changed_values:
        with tempfile.TemporaryDirectory(
            prefix="devops-stack-template-update-"
        ) as temporary:
            verification_root = Path(temporary)
            current_resolver = SourceResolver(
                lock,
                environment={},
                default_base=verification_root / "no-local-sources",
                cache_root=verification_root / "cache",
            )
            candidate_resolver = SourceResolver(
                updated,
                environment={},
                default_base=verification_root / "no-local-sources",
                cache_root=verification_root / "cache",
            )
            for update in updates:
                if not update.changed:
                    continue
                current = current_resolver.resolve(update.key, fetch=True)
                source = candidate_resolver.resolve(update.key, fetch=True)
                pin = updated.pin(update.key)
                current_license = current.path / pin.license_file
                candidate_license = source.path / pin.license_file
                if (
                    not current.matches_lock
                    or not source.matches_lock
                    or not current_license.is_file()
                    or not candidate_license.is_file()
                ):
                    raise ValueError(
                        f"remote candidate for {update.key} failed marker or license verification"
                    )
                license_unchanged = (
                    sha256_file(current_license) == sha256_file(candidate_license)
                )
                changed_values[update.key].update(
                    {
                        "candidateVerified": True,
                        "requiredMarkers": "verified",
                        "interfaceSchema": pin.schema_version,
                        "license": pin.license_spdx,
                        "licenseUnchanged": license_unchanged,
                    }
                )
                if args.write and not license_unchanged:
                    raise ValueError(
                        f"remote candidate for {update.key} changed {pin.license_file}; "
                        "review the license explicitly before updating the lock"
                    )
    if args.write:
        target = contained_path(project, args.lock or "templates.lock.json")
        if loaded_path == target and sha256_file(loaded_path) != loaded_hash:
            raise ValueError(
                "templates.lock.json changed during update; rerun to avoid overwriting concurrent edits"
            )
        TemplateLock(target, updated.data).write()
        value["lockPath"] = str(target.relative_to(project))
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print("WRITE" if args.write else "PREVIEW (rerun with --write to update)")
        for update in updates:
            state = "UPDATE" if update.changed else "CURRENT"
            print(f"{state:7} {update.key}: {update.current_commit} -> {update.remote_commit}")
            if update.changed:
                details = changed_values[update.key]
                print(
                    " " * 9
                    + f"markers={details['requiredMarkers']} "
                    + f"interface={details['interfaceSchema']} "
                    + f"license-unchanged={str(details['licenseUnchanged']).lower()}"
                )
    return 0 if all(item.get("licenseUnchanged", True) for item in update_values) else 1


def _run_templates_path(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    lock = _load_lock(args, project)
    source = SourceResolver(
        lock,
        explicit_paths=_explicit_templates(args),
    ).resolve(args.template_name, fetch=not args.no_fetch)
    if not source.matches_lock:
        raise ValueError(
            f"resolved {args.template_name} commit does not match templates.lock.json"
        )
    print(source.path)
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    if args.target.startswith(("config:", "$")):
        from devops_stack_composer.config import load_config

        loaded = load_config(contained_path(project, args.config))
        value = explain_config_value(loaded.raw, args.target)
    else:
        value = explain_generated_file(project, args.target, output_directory=DEFAULT_OUTPUT)
    value = redact_sensitive(value)
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        for key, item in value.items():
            rendered = ", ".join(item) if isinstance(item, list) else item
            print(f"{key}: {rendered}")
    return 0


def _run_report(args: argparse.Namespace) -> int:
    composition = _composition(args)
    manifest, integrity = generated_integrity_report(
        composition,
        output_directory=DEFAULT_OUTPUT,
    )
    validation = merge_reports(composition.validation, integrity)
    inspection = inspect_application(composition.project)
    report = build_report(
        project=composition.project,
        config_hash=composition.loaded_config.config_hash,
        sources=composition.sources,
        adapters=composition.results,
        validation=validation,
        manifest=manifest,
        inspection=inspection.to_dict(),
        limitations=(
            "docker-build-template has no official cache from/to input; requested cache fails validation",
            "dynamic image tags are resolved by the generated Jenkins pipeline, not stored as mutable latest tags",
            (
                "pre-push Syft and Trivy checks inspect a separately loaded single-platform build; "
                "the official push wrapper rebuilds, so this release does not claim digest identity "
                "between the checked local image and published bytes"
            ),
            "missing optional external validators are reported as skipped, never as passed",
        ),
    )
    markdown, machine = write_report_files(
        composition.project,
        report,
        overwrite=args.force,
    )
    if args.json_output:
        print(report.to_json(), end="")
    else:
        print(f"wrote {markdown.relative_to(composition.project)}")
        print(f"wrote {machine.relative_to(composition.project)}")
        _print_validation(validation)
    return 0 if validation.passed else 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.handler(args))
    except (DevOpsStackError, FileNotFoundError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
