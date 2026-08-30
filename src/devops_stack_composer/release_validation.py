"""Post-publication release gates for the cumulative release profile."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from devops_stack_composer.filesystem import (
    contained_path,
    normalize_relative_path,
    project_root,
)
from devops_stack_composer.process_runner import (
    ProcessExecutionError,
    ProcessResult,
)
from devops_stack_composer.release_assets import (
    ReleaseAssetError,
    ReleaseAssetVerification,
    verify_release_assets,
)


_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}$")
_STAGES = (
    "package",
    "release-assets",
    "release-download-verification",
    "working-tree",
    "tag-commit",
)


class ReleaseCommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> ProcessResult: ...


class ReleaseGateError(RuntimeError):
    """A stable release failure tied to the first unproved gate."""

    def __init__(
        self,
        code: str,
        stage_id: str,
        message: str,
        *,
        completed_stages: Sequence["ReleaseGateStage"] = (),
        process_result: ProcessResult | None = None,
    ) -> None:
        if stage_id not in _STAGES:
            raise ValueError("release gate error stage is invalid")
        self.code = code
        self.stage_id = stage_id
        self.completed_stages = tuple(completed_stages)
        self.process_result = process_result
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ReleaseGateStage:
    stage_id: str
    tool: str
    command: tuple[str, ...]
    output: str

    def __post_init__(self) -> None:
        if self.stage_id not in _STAGES:
            raise ValueError("release gate stage is invalid")
        if not self.tool or not self.command or not self.output:
            raise ValueError("release gate evidence must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stageId": self.stage_id,
            "tool": self.tool,
            "command": list(self.command),
            "output": self.output,
        }


@dataclass(frozen=True)
class ReleaseGateRequest:
    project: Path
    local_assets_directory: str
    version: str
    source_commit: str
    repository: str

    def __post_init__(self) -> None:
        normalize_relative_path(self.local_assets_directory)
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("release version must use semantic version syntax")
        if not isinstance(self.source_commit, str) or not _COMMIT.fullmatch(
            self.source_commit
        ):
            raise ValueError("release source commit must be a full lowercase Git SHA")
        if (
            not isinstance(self.repository, str)
            or not _REPOSITORY.fullmatch(self.repository)
            or ".." in self.repository
            or self.repository.endswith((".", "-"))
        ):
            raise ValueError(
                "release repository must be a safe GitHub OWNER/REPO value"
            )


@dataclass(frozen=True)
class ReleaseGateResult:
    request: ReleaseGateRequest
    local: ReleaseAssetVerification
    downloaded: ReleaseAssetVerification
    stages: tuple[ReleaseGateStage, ...]
    head_commit: str
    tag_commit: str
    verified_attestation_count: int

    def __post_init__(self) -> None:
        if tuple(stage.stage_id for stage in self.stages) != _STAGES:
            raise ValueError("release gate result must contain every gate in order")
        if (
            isinstance(self.verified_attestation_count, bool)
            or not isinstance(self.verified_attestation_count, int)
            or self.verified_attestation_count < 1
        ):
            raise ValueError("release gate result must verify at least one attestation")

    def to_dict(self) -> dict[str, Any]:
        manifest = self.local.manifest
        return {
            "schemaVersion": "1.0.0",
            "version": self.request.version,
            "tag": f"v{self.request.version}",
            "repository": self.request.repository,
            "sourceCommit": self.request.source_commit,
            "localAssetsDirectory": self.request.local_assets_directory,
            "localChecksums": dict(sorted(self.local.checksums.items())),
            "downloadedChecksums": dict(sorted(self.downloaded.checksums.items())),
            "evidenceDigest": manifest.evidence_digest,
            "provenanceMode": manifest.provenance_mode,
            "cryptographicallyVerified": manifest.cryptographically_verified,
            "githubArtifactAttestationsVerified": True,
            "verifiedAttestationSubjectCount": self.verified_attestation_count,
            "downloadedFromGitHub": True,
            "workingTreeClean": True,
            "headCommit": self.head_commit,
            "tagCommit": self.tag_commit,
            "stages": [stage.to_dict() for stage in self.stages],
        }


def _run(
    runner: ReleaseCommandRunner,
    argv: Sequence[str],
    *,
    project: Path,
    timeout: float,
    stage_id: str,
    code: str,
    completed: Sequence[ReleaseGateStage],
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    try:
        return runner.run(
            tuple(argv),
            cwd=project,
            environment=environment,
            timeout=timeout,
        )
    except ProcessExecutionError as exc:
        raise ReleaseGateError(
            code,
            stage_id,
            "required command did not complete successfully",
            completed_stages=completed,
            process_result=exc.result,
        ) from exc


def _commit_output(
    result: ProcessResult,
    *,
    stage_id: str,
    code: str,
    completed: Sequence[ReleaseGateStage],
) -> str:
    value = result.stdout.strip()
    if not _COMMIT.fullmatch(value):
        raise ReleaseGateError(
            code,
            stage_id,
            "Git did not return one full lowercase commit",
            completed_stages=completed,
            process_result=result,
        )
    return value


def _verify_local(request: ReleaseGateRequest) -> ReleaseAssetVerification:
    try:
        return verify_release_assets(
            request.project,
            request.local_assets_directory,
            expected_version=request.version,
            expected_commit=request.source_commit,
        )
    except ReleaseAssetError as exc:
        raise ReleaseGateError(
            "RELEASE_LOCAL_ASSETS_INVALID",
            "package",
            str(exc),
        ) from exc


def _verify_downloaded(
    request: ReleaseGateRequest,
    relative: str,
    local: ReleaseAssetVerification,
    completed: Sequence[ReleaseGateStage],
) -> ReleaseAssetVerification:
    try:
        downloaded = verify_release_assets(
            request.project,
            relative,
            expected_version=request.version,
            expected_commit=request.source_commit,
        )
    except ReleaseAssetError as exc:
        raise ReleaseGateError(
            "RELEASE_DOWNLOAD_INVALID",
            "release-download-verification",
            str(exc),
            completed_stages=completed,
        ) from exc
    if downloaded.manifest.to_dict() != local.manifest.to_dict() or dict(
        downloaded.checksums
    ) != dict(local.checksums):
        raise ReleaseGateError(
            "RELEASE_DOWNLOAD_MISMATCH",
            "release-download-verification",
            "downloaded release assets differ from the locally verified asset set",
            completed_stages=completed,
        )
    return downloaded


def validate_published_release(
    request: ReleaseGateRequest,
    runner: ReleaseCommandRunner,
) -> ReleaseGateResult:
    """Validate local assets, independently download them, and prove Git gates."""

    if not isinstance(request, ReleaseGateRequest):
        raise TypeError("request must be a ReleaseGateRequest")
    project = project_root(request.project)
    local = _verify_local(request)
    github_token = os.environ.get("GH_TOKEN")
    completed: list[ReleaseGateStage] = [
        ReleaseGateStage(
            "package",
            "devops-stack-composer",
            ("devops-stack", "release", "verify", "<local-assets>"),
            "Wheel and source distribution metadata match the release version",
        ),
        ReleaseGateStage(
            "release-assets",
            "devops-stack-composer",
            ("devops-stack", "release", "verify", "<local-assets>"),
            "Local closed release inventory, subjects, schemas, and evidence passed",
        ),
    ]

    download_parent = contained_path(project, ".devops-stack/release-downloads")
    if download_parent.exists() and (
        download_parent.is_symlink() or not download_parent.is_dir()
    ):
        raise ReleaseGateError(
            "RELEASE_DOWNLOAD_PATH_UNSAFE",
            "release-download-verification",
            "release download parent is not a regular directory",
            completed_stages=completed,
        )
    download_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    verified_parent = contained_path(project, ".devops-stack/release-downloads")
    if verified_parent != download_parent:
        raise ReleaseGateError(
            "RELEASE_DOWNLOAD_PATH_UNSAFE",
            "release-download-verification",
            "release download parent changed during validation",
            completed_stages=completed,
        )

    with tempfile.TemporaryDirectory(
        prefix=f"v{request.version}-", dir=download_parent
    ) as temporary:
        session_directory = Path(temporary)
        downloaded_directory = session_directory / "assets"
        github_config_directory = session_directory / "gh-config"
        github_state_directory = session_directory / "xdg-state"
        for directory in (
            downloaded_directory,
            github_config_directory,
            github_state_directory,
        ):
            directory.mkdir(mode=0o700)
        github_environment = {
            "GH_CONFIG_DIR": str(github_config_directory),
            "XDG_STATE_HOME": str(github_state_directory),
        }
        if github_token:
            github_environment["GH_TOKEN"] = github_token
        relative = downloaded_directory.relative_to(project).as_posix()
        command = (
            "gh",
            "release",
            "download",
            f"v{request.version}",
            "--repo",
            request.repository,
            "--dir",
            str(downloaded_directory),
        )
        _run(
            runner,
            command,
            project=project,
            timeout=300.0,
            stage_id="release-download-verification",
            code="RELEASE_DOWNLOAD_FAILED",
            completed=completed,
            environment=github_environment,
        )
        downloaded = _verify_downloaded(request, relative, local, completed)
        downloaded_names = tuple(sorted({*downloaded.checksums, "SHA256SUMS"}))
        for name in downloaded_names:
            _run(
                runner,
                (
                    "gh",
                    "attestation",
                    "verify",
                    str(downloaded_directory / name),
                    "--repo",
                    request.repository,
                    "--signer-workflow",
                    f"{request.repository}/.github/workflows/release.yml",
                    "--source-digest",
                    request.source_commit,
                    "--source-ref",
                    f"refs/tags/v{request.version}",
                    "--format",
                    "json",
                ),
                project=project,
                timeout=120.0,
                stage_id="release-download-verification",
                code="RELEASE_ATTESTATION_INVALID",
                completed=completed,
                environment=github_environment,
            )
    completed.append(
        ReleaseGateStage(
            "release-download-verification",
            "gh/devops-stack-composer",
            (
                "gh",
                "release",
                "download",
                f"v{request.version}",
                "--repo",
                request.repository,
                "--dir",
                "<private-temporary-directory>",
            ),
            (
                "Fresh GitHub release download exactly matched the local closed asset set; "
                f"{len(downloaded_names)} GitHub artifact attestations passed"
            ),
        )
    )

    status = _run(
        runner,
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        project=project,
        timeout=30.0,
        stage_id="working-tree",
        code="RELEASE_WORKTREE_CHECK_FAILED",
        completed=completed,
    )
    if status.stdout:
        raise ReleaseGateError(
            "RELEASE_WORKTREE_DIRTY",
            "working-tree",
            "release validation requires a clean Git working tree",
            completed_stages=completed,
            process_result=status,
        )
    completed.append(
        ReleaseGateStage(
            "working-tree",
            "git",
            ("git", "status", "--porcelain=v1", "--untracked-files=all"),
            "Git working tree is clean, including untracked non-ignored files",
        )
    )

    head_result = _run(
        runner,
        ("git", "rev-parse", "--verify", "HEAD^{commit}"),
        project=project,
        timeout=30.0,
        stage_id="tag-commit",
        code="RELEASE_HEAD_CHECK_FAILED",
        completed=completed,
    )
    head_commit = _commit_output(
        head_result,
        stage_id="tag-commit",
        code="RELEASE_HEAD_INVALID",
        completed=completed,
    )
    tag_result = _run(
        runner,
        (
            "git",
            "rev-parse",
            "--verify",
            f"refs/tags/v{request.version}^{{commit}}",
        ),
        project=project,
        timeout=30.0,
        stage_id="tag-commit",
        code="RELEASE_TAG_CHECK_FAILED",
        completed=completed,
    )
    tag_commit = _commit_output(
        tag_result,
        stage_id="tag-commit",
        code="RELEASE_TAG_INVALID",
        completed=completed,
    )
    if head_commit != request.source_commit or tag_commit != request.source_commit:
        raise ReleaseGateError(
            "RELEASE_TAG_COMMIT_MISMATCH",
            "tag-commit",
            "release tag, HEAD, and validated source commit must be identical",
            completed_stages=completed,
        )
    completed.append(
        ReleaseGateStage(
            "tag-commit",
            "git",
            (
                "git",
                "rev-parse",
                "--verify",
                f"refs/tags/v{request.version}^{{commit}}",
            ),
            "Release tag, HEAD, and validated source commit are identical",
        )
    )
    return ReleaseGateResult(
        request=request,
        local=local,
        downloaded=downloaded,
        stages=tuple(completed),
        head_commit=head_commit,
        tag_commit=tag_commit,
        verified_attestation_count=len(downloaded_names),
    )


__all__ = [
    "ReleaseGateError",
    "ReleaseGateRequest",
    "ReleaseGateResult",
    "ReleaseGateStage",
    "validate_published_release",
]
