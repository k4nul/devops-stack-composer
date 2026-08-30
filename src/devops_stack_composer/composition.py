"""End-to-end composition orchestration shared by CLI commands and tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from devops_stack_composer.adapters.base import AdapterResult, GeneratedArtifact
from devops_stack_composer.adapters.docker import (
    ADAPTER_VERSION as DOCKER_ADAPTER_VERSION,
    DockerBuildAdapter,
)
from devops_stack_composer.adapters.jenkins import (
    ADAPTER_VERSION as JENKINS_ADAPTER_VERSION,
    JenkinsPipelineAdapter,
)
from devops_stack_composer.adapters.kubernetes import (
    ADAPTER_VERSION as KUBERNETES_ADAPTER_VERSION,
    KubernetesAdapter,
)
from devops_stack_composer.config import LoadedConfig, load_config
from devops_stack_composer.errors import GeneratedFileConflictError
from devops_stack_composer.filesystem import contained_path
from devops_stack_composer.locks import TEMPLATE_KEYS, TemplateLock
from devops_stack_composer.manifest import (
    ArtifactWriter,
    GeneratedManifest,
    sha256_content,
)
from devops_stack_composer.sources import SourceResolution, SourceResolver
from devops_stack_composer.validation import (
    CheckResult,
    ValidationReport,
    ValidationStatus,
    adapter_diagnostic_report,
    merge_reports,
    validate_cross_project_contract,
)


@dataclass(frozen=True)
class Composition:
    project: Path
    loaded_config: LoadedConfig
    lock: TemplateLock
    sources: Mapping[str, SourceResolution]
    results: tuple[AdapterResult, ...]
    artifacts: tuple[GeneratedArtifact, ...]
    validation: ValidationReport


_ADAPTER_VERSIONS = {
    "docker": DOCKER_ADAPTER_VERSION,
    "jenkins": JENKINS_ADAPTER_VERSION,
    "kubernetes": KUBERNETES_ADAPTER_VERSION,
}


def _preflight_local_build_output(project: Path) -> None:
    """Block Docker side effects when the generated ownership boundary is dirty."""

    output = contained_path(project, "generated")
    manifest = GeneratedManifest.load(project, "generated")
    if manifest is None:
        if output.exists() and (
            not output.is_dir() or any(output.iterdir())
        ):
            raise GeneratedFileConflictError(
                "local Docker build is blocked because generated output exists "
                "without an ownership manifest"
            )
        return
    verification = manifest.verify(project)
    if not verification.clean:
        raise GeneratedFileConflictError(
            "local Docker build is blocked because generated output is modified, "
            "missing, or untracked; run validate and resolve its integrity findings"
        )


def _source_report(
    lock: TemplateLock,
    sources: Mapping[str, SourceResolution],
) -> ValidationReport:
    checks: list[CheckResult] = []
    for key in TEMPLATE_KEYS:
        source = sources[key]
        pin = lock.pin(key)
        checks.append(
            CheckResult(
                check=f"template.{key}.locked-commit",
                scope=key,
                status=(
                    ValidationStatus.PASSED
                    if source.matches_lock
                    else ValidationStatus.FAILED
                ),
                message=(
                    f"resolved locked commit {pin.commit} from {source.origin}"
                    if source.matches_lock
                    else (
                        f"resolved commit {source.commit or 'unknown'}, "
                        f"expected locked commit {pin.commit}"
                    )
                ),
                details={
                    "origin": source.origin,
                    "commit": source.commit,
                    "expectedCommit": pin.commit,
                },
            )
        )
        license_path = source.path / pin.license_file
        checks.append(
            CheckResult(
                check=f"template.{key}.license",
                scope=key,
                status=(
                    ValidationStatus.PASSED
                    if license_path.is_file()
                    else ValidationStatus.FAILED
                ),
                message=(
                    f"{pin.license_spdx} license file is present"
                    if license_path.is_file()
                    else f"locked license file is missing: {pin.license_file}"
                ),
                details={"spdx": pin.license_spdx, "file": pin.license_file},
            )
        )
    return ValidationReport(tuple(checks))


def _adapter_provenance_report(
    lock: TemplateLock,
    sources: Mapping[str, SourceResolution],
    results: tuple[AdapterResult, ...],
) -> ValidationReport:
    """Bind every adapter result to its resolved source, lock pin, and code version."""

    checks: list[CheckResult] = []
    received_adapters = [result.adapter for result in results]
    inventory_matches = (
        len(received_adapters) == len(TEMPLATE_KEYS)
        and all(received_adapters.count(key) == 1 for key in TEMPLATE_KEYS)
        and set(received_adapters) == set(TEMPLATE_KEYS)
        and set(sources) == set(TEMPLATE_KEYS)
    )
    checks.append(
        CheckResult(
            check="template.adapter-provenance-inventory",
            status=(
                ValidationStatus.PASSED
                if inventory_matches
                else ValidationStatus.FAILED
            ),
            message=(
                "adapter results and resolved sources have one exact entry per template"
                if inventory_matches
                else "adapter result or resolved source inventory is incomplete or duplicated"
            ),
            details={
                "expected": list(TEMPLATE_KEYS),
                "resultAdapters": received_adapters,
                "sourceKeys": sorted(sources),
            },
        )
    )
    for key in TEMPLATE_KEYS:
        pin = lock.pin(key)
        source = sources.get(key)
        matching_results = [result for result in results if result.adapter == key]
        result = matching_results[0] if len(matching_results) == 1 else None
        current_version = _ADAPTER_VERSIONS[key]
        matches = (
            source is not None
            and source.key == key
            and source.matches_lock
            and source.commit == pin.commit
            and result is not None
            and result.adapter == key
            and result.template_commit == source.commit
            and result.adapter_version == pin.adapter_version
            and result.adapter_version == current_version
        )
        checks.append(
            CheckResult(
                check=f"template.{key}.adapter-provenance",
                scope=key,
                status=(
                    ValidationStatus.PASSED
                    if matches
                    else ValidationStatus.FAILED
                ),
                message=(
                    "adapter result is bound to the locked source and adapter version"
                    if matches
                    else "adapter result provenance differs from its source, lock, or code version"
                ),
                details={
                    "expected": {
                        "adapter": key,
                        "commit": pin.commit,
                        "adapterVersion": current_version,
                        "lockAdapterVersion": pin.adapter_version,
                    },
                    "received": {
                        "sourceKey": source.key if source is not None else None,
                        "sourceCommit": source.commit if source is not None else None,
                        "sourceMatchesLock": (
                            source.matches_lock if source is not None else None
                        ),
                        "resultCount": len(matching_results),
                        "resultCommit": (
                            result.template_commit if result is not None else None
                        ),
                        "resultAdapterVersion": (
                            result.adapter_version if result is not None else None
                        ),
                    },
                },
            )
        )
    return ValidationReport(tuple(checks))


def compose(
    *,
    project: Path,
    config_path: Path,
    lock: TemplateLock,
    explicit_template_paths: Mapping[str, Path] | None = None,
    fetch_templates: bool = True,
    validate_upstream: bool = True,
    local_docker_build: bool = False,
    image_tag: str | None = None,
) -> Composition:
    """Resolve locked sources, project one model, and strictly validate the result."""

    resolved_project = project.resolve(strict=True)
    loaded = load_config(config_path)
    if local_docker_build:
        _preflight_local_build_output(resolved_project)
    resolver = SourceResolver(lock, explicit_paths=explicit_template_paths)
    sources = resolver.resolve_all(fetch=fetch_templates)

    results = (
        DockerBuildAdapter(sources["docker"]).generate(
            loaded.model,
            project_root=resolved_project,
            validate_upstream=validate_upstream,
            local_build=local_docker_build,
            image_tag=image_tag,
        ),
        JenkinsPipelineAdapter(sources["jenkins"]).generate(
            loaded.model,
            project_root=resolved_project,
            validate_upstream=validate_upstream,
        ),
        KubernetesAdapter(sources["kubernetes"]).render(
            loaded.model,
            validate_upstream=validate_upstream,
        ),
    )
    artifacts = ArtifactWriter.collect(results)
    validation = merge_reports(
        _source_report(lock, sources),
        _adapter_provenance_report(lock, sources, results),
        adapter_diagnostic_report(results),
        validate_cross_project_contract(loaded.model, results),
    )
    return Composition(
        project=resolved_project,
        loaded_config=loaded,
        lock=lock,
        sources=sources,
        results=results,
        artifacts=artifacts,
        validation=validation,
    )


def generated_integrity_report(
    composition: Composition,
    *,
    output_directory: str = "generated",
) -> tuple[GeneratedManifest | None, ValidationReport]:
    """Compare the manifest, disk, current config, locks, and freshly rendered bytes."""

    manifest = GeneratedManifest.load(composition.project, output_directory)
    if manifest is None:
        return None, ValidationReport(
            (
                CheckResult(
                    check="generated.manifest-present",
                    status=ValidationStatus.FAILED,
                    message="no generated manifest exists; run generate --write first",
                    scope="generated",
                ),
            )
        )

    checks: list[CheckResult] = []
    verification = manifest.verify(composition.project)
    checks.append(
        CheckResult(
            check="generated.file-integrity",
            status=(ValidationStatus.PASSED if verification.clean else ValidationStatus.FAILED),
            message=(
                "tracked generated files match their manifest hashes"
                if verification.clean
                else "generated files are modified, missing, or untracked"
            ),
            scope="generated",
            details={
                "modified": list(verification.modified),
                "missing": list(verification.missing),
                "untracked": list(verification.untracked),
            },
        )
    )

    config_matches = manifest.data["configHash"] == composition.loaded_config.config_hash
    checks.append(
        CheckResult(
            check="generated.config-hash",
            status=ValidationStatus.PASSED if config_matches else ValidationStatus.FAILED,
            message=(
                "generated files use the current configuration"
                if config_matches
                else "configuration changed after the last generation"
            ),
            scope="generated",
        )
    )

    result_map = {result.adapter: result for result in composition.results}
    template_mismatches = {
        key: {
            "manifest": manifest.data["templates"][key],
            "current": {
                "commit": result_map[key].template_commit,
                "adapterVersion": result_map[key].adapter_version,
            },
        }
        for key in TEMPLATE_KEYS
        if manifest.data["templates"][key]
        != {
            "commit": result_map[key].template_commit,
            "adapterVersion": result_map[key].adapter_version,
        }
    }
    checks.append(
        CheckResult(
            check="generated.template-versions",
            status=(
                ValidationStatus.FAILED
                if template_mismatches
                else ValidationStatus.PASSED
            ),
            message=(
                "generated files use current template and adapter versions"
                if not template_mismatches
                else "template or adapter versions changed after the last generation"
            ),
            scope="generated",
            details={"mismatches": template_mismatches},
        )
    )

    desired = {
        artifact.path: (
            sha256_content(artifact.content),
            f"0{artifact.mode & 0o777:03o}",
            tuple(sorted(set(artifact.origins))),
        )
        for artifact in composition.artifacts
    }
    tracked = {
        path: (
            entry["sha256"],
            entry["mode"],
            tuple(entry["origins"]),
        )
        for path, entry in manifest.file_map().items()
    }
    content_mismatches = sorted(
        path
        for path in set(desired) | set(tracked)
        if desired.get(path) != tracked.get(path)
    )
    checks.append(
        CheckResult(
            check="generated.planned-content",
            status=(
                ValidationStatus.FAILED
                if content_mismatches
                else ValidationStatus.PASSED
            ),
            message=(
                "freshly rendered artifacts match the generated manifest"
                if not content_mismatches
                else "freshly rendered artifacts differ from the generated manifest"
            ),
            scope="generated",
            details={"paths": content_mismatches},
        )
    )
    return manifest, ValidationReport(tuple(checks))
