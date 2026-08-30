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
from devops_stack_composer.evidence_bundle import verify_evidence_bundle
from devops_stack_composer.evidence_store import EvidenceStore, new_run_id
from devops_stack_composer.execution import (
    ExecutionOptions,
    ExecutionOrchestrator,
    _default_source_revision,
    vulnerability_policy_from_model,
)
from devops_stack_composer.execution_bundle import (
    inspect_execution_bundle,
    load_strict_json_file,
    verify_execution_bundle,
)
from devops_stack_composer.execution_planning import (
    PlannedExecution,
    create_execution_plan,
    validate_local_kind_plan,
)
from devops_stack_composer.execution_state import ExecutionJournal
from devops_stack_composer.explain import explain_config_value, explain_generated_file
from devops_stack_composer.filesystem import (
    atomic_write,
    contained_path,
    project_root,
    sha256_file,
)
from devops_stack_composer.inspector import initial_config, inspect_application
from devops_stack_composer.jenkins_evidence import verify_jenkins_artifact_files
from devops_stack_composer.kind_cluster import KindCluster, KindClusterHandle
from devops_stack_composer.locks import TEMPLATE_KEYS, TemplateLock
from devops_stack_composer.manifest import ArtifactWriter, GeneratedManifest
from devops_stack_composer.process_compat import SafeSubprocessAdapter
from devops_stack_composer.process_runner import SafeProcessRunner
from devops_stack_composer.report import (
    build_report,
    redact_sensitive,
    write_report_files,
)
from devops_stack_composer.registry import EphemeralRegistry, RegistryHandle
from devops_stack_composer.release_assets import (
    ReleaseAssemblyRequest,
    ReleaseMaterialRequest,
    assemble_release_assets,
    prepare_release_materials,
    verify_release_assets,
)
from devops_stack_composer.resource_recovery import ResourceRecoveryStore
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

    execute = commands.add_parser(
        "execute",
        help="run build-once supply-chain and Kubernetes validation profiles",
    )
    _add_composition_arguments(execute)
    execute.add_argument(
        "--environment",
        choices=("dev", "staging", "production"),
        help="environment selected for an actual deployment (default: configuration)",
    )
    execute.add_argument(
        "--profile",
        choices=("static", "supply-chain", "kind-e2e", "release"),
        help="strict cumulative execution profile (default: configuration)",
    )
    execute.add_argument(
        "--output",
        help="run directory root relative to the project (default: configuration value)",
    )
    execute.add_argument("--image-tag", help="informational tag for the one pushed build")
    execute.add_argument("--run", help="explicit safe execution run ID")
    execute.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the logical plan without writes or runtime side effects",
    )
    execute.add_argument(
        "--approve-production",
        action="store_true",
        help="explicitly approve a production apply; dry-run does not require this",
    )
    retention = execute.add_mutually_exclusive_group()
    retention.add_argument(
        "--keep-resources",
        action="store_true",
        help="retain verified run-owned resources for debugging; cleanup will not pass",
    )
    retention.add_argument(
        "--keep-environment-on-failure",
        action="store_true",
        help="retain run-owned resources only when execution fails",
    )
    execute.add_argument("--json", action="store_true", dest="json_output")
    execute.set_defaults(handler=_run_execute)

    diff = commands.add_parser("diff", help="compare planned artifacts with a baseline")
    _add_composition_arguments(diff)
    diff.add_argument("--against", choices=("generated", "project"), default="generated")
    diff.add_argument("--json", action="store_true", dest="json_output")
    diff.set_defaults(handler=_run_diff)

    doctor = commands.add_parser("doctor", help="diagnose tools, template paths, and locks")
    _add_project_argument(doctor)
    _add_source_arguments(doctor)
    doctor.add_argument("--remote", action="store_true", help="also query template remotes")
    doctor.add_argument(
        "--profile",
        choices=("static", "supply-chain", "kind-e2e", "release"),
        help="classify tools against one v0.2 validation profile",
    )
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

    execution = commands.add_parser(
        "execution",
        help="plan, inspect, or safely clean one execution run",
    )
    execution_commands = execution.add_subparsers(
        dest="execution_command", required=True
    )
    execution_plan = execution_commands.add_parser(
        "plan",
        help="validate and print a side-effect-free logical execution plan",
    )
    _add_composition_arguments(execution_plan)
    execution_plan.add_argument(
        "--environment",
        choices=("dev", "staging", "production"),
        help="environment selected by the plan (default: configuration)",
    )
    execution_plan.add_argument(
        "--profile",
        choices=("static", "supply-chain", "kind-e2e", "release"),
        help="validation profile selected by the plan (default: configuration)",
    )
    execution_plan.add_argument("--image-tag", help="requested image tag")
    execution_plan.add_argument("--run", help="explicit safe execution run ID")
    execution_plan.add_argument(
        "--approve-production",
        action="store_true",
        help="record explicit production approval in the plan",
    )
    execution_plan.add_argument("--json", action="store_true", dest="json_output")
    execution_plan.set_defaults(handler=_run_execution_plan)

    for name, help_text, handler in (
        ("show", "freshly verify and show one execution run", _run_execution_show),
        (
            "cleanup",
            "remove only resources whose exact ownership is sealed in a run",
            _run_execution_cleanup,
        ),
    ):
        command = execution_commands.add_parser(name, help=help_text)
        _add_project_argument(command)
        command.add_argument("--run", required=True, help="execution run ID")
        command.add_argument(
            "--output",
            default=".devops-stack/runs",
            help="run directory root relative to the project",
        )
        command.add_argument("--json", action="store_true", dest="json_output")
        command.set_defaults(handler=handler)

    artifact = commands.add_parser("artifact", help="inspect or verify immutable evidence")
    artifact_commands = artifact.add_subparsers(dest="artifact_command", required=True)
    artifact_inspect = artifact_commands.add_parser(
        "inspect",
        help="inspect one closed execution bundle",
    )
    _add_project_argument(artifact_inspect)
    artifact_inspect.add_argument("--run", required=True, help="execution run ID")
    artifact_inspect.add_argument(
        "--output",
        default=".devops-stack/runs",
        help="run directory root relative to the project",
    )
    artifact_inspect.add_argument("--json", action="store_true", dest="json_output")
    artifact_inspect.set_defaults(handler=_run_artifact_inspect)

    artifact_verify = artifact_commands.add_parser(
        "verify",
        help="freshly verify a bundle or Jenkins evidence files offline",
    )
    _add_project_argument(artifact_verify)
    verification_source = artifact_verify.add_mutually_exclusive_group(required=True)
    verification_source.add_argument("--run", help="execution run ID")
    verification_source.add_argument(
        "--artifact",
        help="Jenkins artifact JSON path relative to the project",
    )
    artifact_verify.add_argument("--sbom", help="Jenkins SBOM JSON path")
    artifact_verify.add_argument("--scan", help="Jenkins vulnerability JSON path")
    artifact_verify.add_argument("--provenance", help="Jenkins provenance JSON path")
    artifact_verify.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="configuration used to evaluate Jenkins vulnerability policy",
    )
    artifact_verify.add_argument(
        "--output",
        default=".devops-stack/runs",
        help="run directory root relative to the project",
    )
    artifact_verify.add_argument("--json", action="store_true", dest="json_output")
    artifact_verify.set_defaults(handler=_run_artifact_verify)

    evidence = commands.add_parser("evidence", help="verify canonical execution evidence")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_verify = evidence_commands.add_parser(
        "verify",
        help="verify closed inventory and same-digest semantics offline",
    )
    _add_project_argument(evidence_verify)
    evidence_verify.add_argument("--run", required=True, help="execution run ID")
    evidence_verify.add_argument(
        "--output",
        default=".devops-stack/runs",
        help="run directory root relative to the project",
    )
    evidence_verify.add_argument("--json", action="store_true", dest="json_output")
    evidence_verify.set_defaults(handler=_run_evidence_verify)

    release = commands.add_parser(
        "release",
        help="prepare, assemble, or verify a closed release asset set",
    )
    release_commands = release.add_subparsers(dest="release_command", required=True)
    release_materials = release_commands.add_parser(
        "materials",
        help="generate digest-bound package SBOM and file provenance",
    )
    _add_project_argument(release_materials)
    release_materials.add_argument("--version", default=__version__)
    release_materials.add_argument("--commit", help="full source commit (default: HEAD)")
    release_materials.add_argument("--wheel", help="wheel path relative to the project")
    release_materials.add_argument("--sdist", help="sdist path relative to the project")
    release_materials.add_argument(
        "--repository-url",
        default="https://github.com/k4nul/devops-stack-composer",
        help="credential-free HTTPS source repository URL",
    )
    release_materials.add_argument(
        "--created-at",
        help="RFC 3339 creation time (default: source commit time)",
    )
    release_materials.add_argument(
        "--output",
        default="dist/release-materials",
        help="new output directory relative to the project",
    )
    release_materials.add_argument("--json", action="store_true", dest="json_output")
    release_materials.set_defaults(handler=_run_release_materials)

    release_assemble = release_commands.add_parser(
        "assemble",
        help="assemble and re-verify the complete v0.2 release asset set",
    )
    _add_project_argument(release_assemble)
    release_assemble.add_argument("--version", default=__version__)
    release_assemble.add_argument("--commit", help="full source commit (default: HEAD)")
    release_assemble.add_argument("--wheel", help="wheel path relative to the project")
    release_assemble.add_argument("--sdist", help="sdist path relative to the project")
    release_assemble.add_argument(
        "--materials",
        default="dist/release-materials",
        help="directory containing package.spdx.json and provenance-verification.json",
    )
    release_assemble.add_argument(
        "--evidence-run", required=True, help="successful kind-e2e run ID"
    )
    release_assemble.add_argument(
        "--evidence-output",
        default=".devops-stack/runs",
        help="evidence run directory root relative to the project",
    )
    release_assemble.add_argument(
        "--example-config",
        default="examples/python-service/devops-stack.yaml",
    )
    release_assemble.add_argument(
        "--output",
        help="new release directory (default: dist/release-vVERSION)",
    )
    release_assemble.add_argument("--json", action="store_true", dest="json_output")
    release_assemble.set_defaults(handler=_run_release_assemble)

    release_verify = release_commands.add_parser(
        "verify",
        help="offline-verify a release directory, including archived example evidence",
    )
    _add_project_argument(release_verify)
    release_verify.add_argument("--directory", required=True)
    release_verify.add_argument("--version")
    release_verify.add_argument("--commit")
    release_verify.add_argument("--json", action="store_true", dest="json_output")
    release_verify.set_defaults(handler=_run_release_verify)

    cluster = commands.add_parser("cluster", help="manage verified local clusters")
    cluster_commands = cluster.add_subparsers(dest="cluster_command", required=True)
    cluster_kind = cluster_commands.add_parser("kind", help="manage a run-owned kind cluster")
    kind_commands = cluster_kind.add_subparsers(dest="kind_command", required=True)
    kind_create = kind_commands.add_parser(
        "create",
        help="create a pinned kind cluster and isolated registry",
    )
    _add_project_argument(kind_create)
    kind_create.add_argument("--run", help="explicit safe run ID")
    kind_create.add_argument(
        "--output",
        default=".devops-stack/runs",
        help="run directory root relative to the project",
    )
    kind_create.add_argument("--json", action="store_true", dest="json_output")
    kind_create.set_defaults(handler=_run_cluster_kind_create)
    for name, help_text, handler in (
        ("status", "inspect exact persisted resource ownership", _run_cluster_kind_status),
        ("destroy", "delete only exact persisted run-owned resources", _run_cluster_kind_destroy),
    ):
        command = kind_commands.add_parser(name, help=help_text)
        _add_project_argument(command)
        command.add_argument("--run", required=True, help="execution run ID")
        command.add_argument(
            "--output",
            default=".devops-stack/runs",
            help="run directory root relative to the project",
        )
        command.add_argument("--json", action="store_true", dest="json_output")
        command.set_defaults(handler=handler)

    explain = commands.add_parser("explain", help="explain a generated file or configuration value")
    _add_project_argument(explain)
    _add_config_argument(explain)
    explain.add_argument("target", help="generated path or config:$.image.registry")
    explain.add_argument("--json", action="store_true", dest="json_output")
    explain.set_defaults(handler=_run_explain)

    report = commands.add_parser("report", help="write Markdown and JSON validation reports")
    _add_composition_arguments(report)
    report.add_argument("--run", help="read and freshly verify an execution run")
    report.add_argument(
        "--output",
        default=".devops-stack/runs",
        help="run directory root used together with --run",
    )
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


def _execution_composition(
    args: argparse.Namespace,
    *,
    fetch_templates: bool,
) -> Composition:
    project = _resolved_project(args)
    return compose(
        project=project,
        config_path=contained_path(project, args.config),
        lock=_load_lock(args, project),
        explicit_template_paths=_explicit_templates(args),
        fetch_templates=fetch_templates,
        # Execution reuses only immutable adapter output and runs its own runtime
        # validators. Read-only upstream smoke queries remain part of `validate`,
        # where transient template-tool latency cannot occur after resources start.
        validate_upstream=False,
    )


def _planned_execution(
    args: argparse.Namespace,
    composition: Composition,
) -> PlannedExecution:
    planned = create_execution_plan(
        composition,
        run_id=args.run or new_run_id(),
        source_revision=_default_source_revision(composition.project),
        profile=args.profile,
        environment=args.environment,
        image_tag=args.image_tag,
        production_apply_approved=args.approve_production,
    )
    if planned.plan.profile.value == "kind-e2e":
        validate_local_kind_plan(planned)
    return planned


def _run_execution_plan(
    args: argparse.Namespace,
    *,
    composition: Composition | None = None,
) -> int:
    selected = composition or _execution_composition(args, fetch_templates=False)
    planned = _planned_execution(args, selected)
    value = {**planned.to_dict(), "sideEffects": False}
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        plan = planned.plan
        print(f"run: {plan.run_id}")
        print(f"profile: {plan.profile.value}")
        print(f"environment: {plan.environment}")
        print(f"registry: {plan.artifact_intent.registry} (logical; not allocated)")
        print(f"image-tag: {plan.artifact_intent.requested_tag}")
        print("side-effects: false")
        print("stages:")
        for stage in plan.stages:
            print(f"- {stage.stage_id}: {stage.description}")
    return 0


def _run_execute(args: argparse.Namespace) -> int:
    if args.dry_run:
        if args.keep_resources or args.keep_environment_on_failure:
            raise ValueError("resource retention options are not valid with --dry-run")
        return _run_execution_plan(
            args,
            composition=_execution_composition(args, fetch_templates=False),
        )
    composition = _execution_composition(args, fetch_templates=not args.no_fetch)
    work_directory = args.output or composition.loaded_config.model.execution[
        "workDirectory"
    ]
    profile = args.profile or composition.loaded_config.model.execution["profile"]
    environment = args.environment or composition.loaded_config.model.kubernetes_e2e[
        "environment"
    ]
    result = ExecutionOrchestrator().execute(
        composition,
        ExecutionOptions(
            environment=environment,
            profile=profile,
            work_directory=work_directory,
            image_tag=args.image_tag,
            approve_production=args.approve_production,
            keep_resources=args.keep_resources,
            keep_environment_on_failure=args.keep_environment_on_failure,
            run_id=args.run,
        ),
    )
    value = result.to_dict()
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"run: {value['runId']}")
        print(f"evidence: {value['runDirectory']}")
        print(f"status: {value['finalStatus']}")
        artifact = value.get("artifact")
        if isinstance(artifact, dict):
            print(f"image: {artifact['immutableImageReference']}")
            print(f"build-invocations: {artifact['buildInvocationCount']}")
        if value.get("failureReason"):
            print(f"failure: {value['failureReason']}", file=sys.stderr)
    return 0 if result.passed else 1


def _run_execution_show(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    store = EvidenceStore.open(
        project,
        args.run,
        work_directory=args.output,
    )
    subject_verification = verify_execution_bundle(
        project,
        args.run,
        work_directory=args.output,
    )
    summary = inspect_execution_bundle(
        project,
        args.run,
        work_directory=args.output,
    ).to_dict()
    canonical = None
    state = None
    resources = None
    if store.path("checksums.json").is_file():
        canonical = verify_evidence_bundle(store).to_dict()
        journal = ExecutionJournal.open(store)
        state = journal.machine.to_dict(store.run_id)
        if store.path("resources.json").is_file():
            owned = ResourceRecoveryStore(store).load()
            resources = {
                "cleaned": owned.cleaned,
                "kindStatus": owned.kind.status if owned.kind is not None else None,
                "registryStatus": (
                    owned.registry.status if owned.registry is not None else None
                ),
            }
    value = {
        "summary": summary,
        "bundleVerification": canonical,
        "subjectVerification": subject_verification.to_dict(),
        "state": state,
        "resources": resources,
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"run: {summary['runId']}")
        print(f"profile: {summary['profile']}")
        print(f"status: {summary['finalStatus']}")
        print(f"digest: {summary['digest'] or 'none'}")
        print(
            "state: "
            + (state["currentState"] if state is not None else "legacy-unavailable")
        )
        if resources is not None:
            print(f"resources-cleaned: {str(resources['cleaned']).lower()}")
        print(f"checksummed-files: {summary['checksumFileCount']}")
    return 0


def _run_execution_cleanup(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    store = EvidenceStore.open(
        project,
        args.run,
        work_directory=args.output,
    )
    recovery = ResourceRecoveryStore(store)
    recovery.load()
    runner = SafeProcessRunner(
        project,
        allowed_executables=("docker", "kind"),
        max_output_bytes=1024 * 1024,
        default_timeout=60.0,
    )
    result = recovery.cleanup(
        command_runner=SafeSubprocessAdapter(runner),
        command_timeout_seconds=60.0,
    )
    verification = verify_evidence_bundle(store)
    value = {
        "runId": result.run_id,
        "kindRemoved": result.kind_removed,
        "registryRemoved": result.registry_removed,
        "complete": result.complete,
        "bundleVerification": verification.to_dict(),
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"run: {result.run_id}")
        print(f"kind-removed: {str(result.kind_removed).lower()}")
        print(f"registry-removed: {str(result.registry_removed).lower()}")
        print(f"cleanup-complete: {str(result.complete).lower()}")
    return 0 if result.complete else 1


def _run_evidence_verify(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    store = EvidenceStore.open(
        project,
        args.run,
        work_directory=args.output,
    )
    canonical = verify_evidence_bundle(store)
    subjects = verify_execution_bundle(
        project,
        args.run,
        work_directory=args.output,
    )
    value = {
        "bundleVerification": canonical.to_dict(),
        "subjectVerification": subjects.to_dict(),
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print("verified: true")
        print(f"execution-succeeded: {str(canonical.execution_succeeded).lower()}")
        print(f"final-status: {canonical.final_status}")
        print(f"incomplete: {str(canonical.incomplete).lower()}")
        print(f"artifact-digest: {canonical.artifact_digest or 'none'}")
        print(f"checksummed-files: {canonical.material_file_count}")
        print("authenticity: NOT_ESTABLISHED")
    return 0


def _release_package_paths(
    project: Path,
    version: str,
    wheel_value: str | None,
    sdist_value: str | None,
) -> tuple[str, str]:
    def select(explicit: str | None, patterns: tuple[str, ...], label: str) -> str:
        if explicit is not None:
            candidate = contained_path(project, explicit)
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError(f"{label} is not a regular project file")
            return candidate.relative_to(project).as_posix()
        distribution = contained_path(project, "dist")
        if not distribution.is_dir() or distribution.is_symlink():
            raise ValueError("dist is missing; build wheel and sdist first")
        matches = tuple(
            sorted(
                {
                    path
                    for pattern in patterns
                    for path in distribution.glob(pattern)
                    if path.is_file() and not path.is_symlink()
                }
            )
        )
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one {label} for version {version}; found {len(matches)}"
            )
        return matches[0].relative_to(project).as_posix()

    return (
        select(
            wheel_value,
            (f"devops_stack_composer-{version}-*.whl",),
            "wheel",
        ),
        select(
            sdist_value,
            (
                f"devops_stack_composer-{version}.tar.gz",
                f"devops-stack-composer-{version}.tar.gz",
            ),
            "sdist",
        ),
    )


def _release_commit_time(project: Path, commit: str) -> str:
    runner = SafeProcessRunner(
        project,
        allowed_executables=("git",),
        max_output_bytes=4096,
        default_timeout=20.0,
    )
    result = runner.run(
        ("git", "show", "-s", "--format=%cI", commit),
        cwd=project,
    )
    value = result.stdout.strip()
    if not value:
        raise ValueError("Git returned no source commit timestamp")
    return value


def _run_release_materials(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    commit = args.commit or _default_source_revision(project)
    wheel, sdist = _release_package_paths(
        project, args.version, args.wheel, args.sdist
    )
    result = prepare_release_materials(
        ReleaseMaterialRequest(
            project=project,
            output_directory=args.output,
            version=args.version,
            source_commit=commit,
            source_repository=args.repository_url,
            created_at=args.created_at or _release_commit_time(project, commit),
            wheel_path=wheel,
            sdist_path=sdist,
        )
    )
    value = {
        **result.to_dict(),
        "packageSbom": result.package_sbom.relative_to(project).as_posix(),
        "provenanceVerification": (
            result.provenance_verification.relative_to(project).as_posix()
        ),
        "version": args.version,
        "sourceCommit": commit,
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"package-sbom: {value['packageSbom']}")
        print(f"provenance-verification: {value['provenanceVerification']}")
        print("cryptographically-verified: false")
    return 0


def _run_release_assemble(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    commit = args.commit or _default_source_revision(project)
    wheel, sdist = _release_package_paths(
        project, args.version, args.wheel, args.sdist
    )
    materials = args.materials.rstrip("/")
    output = args.output or f"dist/release-v{args.version}"
    result = assemble_release_assets(
        ReleaseAssemblyRequest(
            project=project,
            output_directory=output,
            version=args.version,
            source_commit=commit,
            wheel_path=wheel,
            sdist_path=sdist,
            configuration_schema_path="schemas/devops-stack.schema.json",
            report_schema_path="schemas/execution-report.schema.json",
            execution_evidence_schema_path="schemas/execution-evidence.schema.json",
            example_config_path=args.example_config,
            package_sbom_path=f"{materials}/package.spdx.json",
            provenance_verification_path=(
                f"{materials}/provenance-verification.json"
            ),
            evidence_run_id=args.evidence_run,
            evidence_work_directory=args.evidence_output,
        )
    )
    value = result.to_dict()
    value["directory"] = result.directory.relative_to(project).as_posix()
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"release-directory: {value['directory']}")
        print(f"tag: {value['tag']}")
        print(f"source-commit: {value['sourceCommit']}")
        print(f"checks: {', '.join(value['checks'])}")
    return 0


def _run_release_verify(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    result = verify_release_assets(
        project,
        args.directory,
        expected_version=args.version,
        expected_commit=args.commit,
    )
    value = result.to_dict()
    value["directory"] = result.directory.relative_to(project).as_posix()
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print("passed: true")
        print(f"tag: {value['tag']}")
        print(f"source-commit: {value['sourceCommit']}")
        print(f"evidence-digest: {value['evidenceDigest']}")
        print(f"checks: {', '.join(value['checks'])}")
    return 0


def _run_artifact_inspect(args: argparse.Namespace) -> int:
    value = inspect_execution_bundle(
        _resolved_project(args),
        args.run,
        work_directory=args.output,
    ).to_dict()
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        for key in (
            "runId",
            "profile",
            "finalStatus",
            "repository",
            "tag",
            "digest",
            "platform",
            "configDigest",
            "sbom",
            "scan",
            "provenance",
            "verificationStatus",
            "deploymentEnvironment",
            "checksumFileCount",
        ):
            print(f"{key}: {value[key] if value[key] is not None else 'none'}")
    return 0


def _run_artifact_verify(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    if args.run is not None:
        if any((args.sbom, args.scan, args.provenance)):
            raise ValueError(
                "--sbom, --scan, and --provenance are only valid with --artifact"
            )
        verification = verify_execution_bundle(
            project,
            args.run,
            work_directory=args.output,
        )
        value = verification.to_dict()
        store = EvidenceStore.open(
            project,
            args.run,
            work_directory=args.output,
        )
        if store.path("checksums.json").is_file():
            value["bundleVerification"] = verify_evidence_bundle(store).to_dict()
    else:
        vulnerability_policy = None
        if args.scan is not None:
            from devops_stack_composer.config import load_config

            loaded = load_config(contained_path(project, args.config))
            vulnerability_policy = vulnerability_policy_from_model(
                loaded.model.supply_chain
            )
        verification = verify_jenkins_artifact_files(
            project,
            args.artifact,
            sbom_path=args.sbom,
            scan_path=args.scan,
            provenance_path=args.provenance,
            vulnerability_policy=vulnerability_policy,
        )
        value = verification.to_dict()
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"passed: {str(value['passed']).lower()}")
        print(f"authoritative-digest: {value['authoritativeDigest']}")
        for name, subject in sorted(value["subjects"].items()):
            print(f"subject.{name}: {subject}")
    return 0


def _lifecycle_values(project: Path, run_id: str, work_directory: str):
    store = EvidenceStore.open(
        project,
        run_id,
        work_directory=work_directory,
    )
    store.verify_checksums()
    cluster_path = store.path("kind-cluster-ownership.json")
    registry_path = store.path("registry-ownership.json")
    cluster_handle = (
        KindClusterHandle.from_dict(
            load_strict_json_file(
                project,
                f"{store.relative_root}/kind-cluster-ownership.json",
            )
        )
        if cluster_path.is_file()
        else None
    )
    registry_handle = (
        RegistryHandle.from_dict(
            load_strict_json_file(
                project,
                f"{store.relative_root}/registry-ownership.json",
            )
        )
        if registry_path.is_file()
        else None
    )
    if cluster_handle is None and registry_handle is None:
        raise ValueError("run has no persisted cluster or registry ownership record")
    return (
        store,
        cluster_handle,
        registry_handle,
    )


def _run_cluster_kind_create(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    store = EvidenceStore.create(
        project,
        work_directory=args.output,
        run_id=args.run,
    )
    registry = EphemeralRegistry(store.run_id)
    cluster = KindCluster(store.run_id)
    registry_handle = None
    cluster_handle = None
    try:
        registry_handle = registry.start()
        store.write_json("registry-ownership.json", registry_handle.to_dict())
        cluster_handle = cluster.create()
        store.write_json("kind-cluster-ownership.json", cluster_handle.to_dict())
        configuration = cluster.configure_local_registry(registry)
        value = {
            "runId": store.run_id,
            "cluster": cluster_handle.to_dict(),
            "registry": registry_handle.to_dict(),
            "registryConfiguration": {
                "hostEndpoint": configuration.host_endpoint,
                "containerEndpoint": configuration.container_endpoint,
                "nodes": list(configuration.nodes),
                "localTestOnly": True,
            },
        }
        store.write_json("cluster-lifecycle.json", value)
        store.write_checksums()
        store.verify_checksums()
        cluster.detach()
    except BaseException:
        try:
            if cluster_handle is not None:
                cluster.destroy()
            else:
                cluster.close()
        finally:
            if registry_handle is not None:
                registry.cleanup()
        raise
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"run: {store.run_id}")
        print(f"cluster: {cluster_handle.name}")
        print(f"registry: {configuration.host_endpoint} (local test only)")
    return 0


def _run_cluster_kind_status(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    _store, cluster_handle, registry_handle = _lifecycle_values(
        project,
        args.run,
        args.output,
    )
    cluster = KindCluster.reopen(cluster_handle) if cluster_handle is not None else None
    try:
        cluster_status = cluster.status() if cluster is not None else None
        registry_status = (
            EphemeralRegistry.reopen(registry_handle).status()
            if registry_handle is not None
            else None
        )
    finally:
        if cluster is not None:
            cluster.detach()
    value = {
        "runId": args.run,
        "cluster": (
            {
                "name": cluster_status.name,
                "exists": cluster_status.exists,
                "owned": cluster_status.owned,
                "ready": cluster_status.ready,
                "nodes": list(cluster_status.nodes),
                "error": cluster_status.error,
            }
            if cluster_status is not None
            else None
        ),
        "registry": (
            {
                "name": registry_status.name,
                "exists": registry_status.exists,
                "owned": registry_status.owned,
                "running": registry_status.running,
                "ready": registry_status.ready,
                "state": registry_status.state,
                "hostPort": registry_status.host_port,
            }
            if registry_status is not None
            else None
        ),
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        if cluster_status is None:
            print("cluster: not-created")
        else:
            print(
                f"cluster: {cluster_status.name} "
                f"owned={str(cluster_status.owned).lower()} "
                f"ready={str(cluster_status.ready).lower()}"
            )
        if registry_status is None:
            print("registry: not-created")
        else:
            print(
                f"registry: {registry_status.name} "
                f"owned={str(registry_status.owned).lower()} "
                f"running={str(registry_status.running).lower()} "
                f"ready={str(registry_status.ready).lower()}"
            )
    cluster_passed = cluster_status is None or cluster_status.ready
    registry_passed = registry_status is None or registry_status.ready
    return 0 if cluster_passed and registry_passed else 1


def _run_cluster_kind_destroy(args: argparse.Namespace) -> int:
    project = _resolved_project(args)
    _store, cluster_handle, registry_handle = _lifecycle_values(
        project,
        args.run,
        args.output,
    )
    errors: list[str] = []
    cluster = None
    registry = None
    if cluster_handle is not None:
        try:
            cluster = KindCluster.reopen(cluster_handle)
        except DevOpsStackError as exc:
            errors.append(str(exc))
    if registry_handle is not None:
        try:
            registry = EphemeralRegistry.reopen(registry_handle)
        except DevOpsStackError as exc:
            errors.append(str(exc))
    cluster_removed = False
    registry_removed = False
    if cluster is not None:
        try:
            cluster_removed = cluster.destroy()
        except DevOpsStackError as exc:
            errors.append(str(exc))
    if registry is not None:
        try:
            registry_removed = registry.cleanup()
        except DevOpsStackError as exc:
            errors.append(str(exc))
    value = {
        "runId": args.run,
        "clusterRemoved": cluster_removed,
        "registryRemoved": registry_removed,
        "errors": errors,
    }
    if args.json_output:
        print(_safe_json(value), end="")
    else:
        print(f"cluster-removed: {str(cluster_removed).lower()}")
        print(f"registry-removed: {str(registry_removed).lower()}")
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
    return 0 if not errors else 1


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
        profile=args.profile,
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
    if args.run is not None:
        if args.force:
            raise ValueError("--force is not valid when reading an execution --run")
        project = _resolved_project(args)
        verification = verify_execution_bundle(
            project,
            args.run,
            work_directory=args.output,
        )
        store = EvidenceStore.open(
            project,
            args.run,
            work_directory=args.output,
        )
        canonical = store.path("run.json").is_file()
        report_json = store.path("run.json" if canonical else "report.json")
        report_markdown = store.path("summary.md" if canonical else "report.md")
        if args.json_output:
            print(report_json.read_text(encoding="utf-8"), end="")
        else:
            print(f"report: {report_markdown.relative_to(project)}")
            print(f"machine-report: {report_json.relative_to(project)}")
            print(
                "fresh-verification: passed "
                f"({verification.checksum_file_count} checksummed files)"
            )
        return 0

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
