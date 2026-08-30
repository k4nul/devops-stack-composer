"""Resolve independent template repositories without local-path coupling."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from devops_stack_composer.errors import SourceResolutionError
from devops_stack_composer.locks import TEMPLATE_KEYS, TemplateLock, TemplatePin


ENVIRONMENT_PATHS = {
    "docker": "DEVOPS_STACK_DOCKER_TEMPLATE",
    "jenkins": "DEVOPS_STACK_JENKINS_TEMPLATE",
    "kubernetes": "DEVOPS_STACK_KUBERNETES_TEMPLATE",
}

REQUIRED_MARKERS = {
    "docker": (
        "LICENSE",
        "scripts/validate-build-plan.sh",
        "scripts/build-image.sh",
        "buildx/docker-bake.hcl",
    ),
    "jenkins": (
        "LICENSE",
        "scripts/show-jenkins-job-plan.ps1",
        "scripts/export-jenkins-job-dsl.ps1",
        "jenkins/job-seed.Jenkinsfile",
    ),
    "kubernetes": (
        "LICENSE",
        "scripts/show-platform-plan.ps1",
        "scripts/render-platform-assets.ps1",
        "k8s/render-manifests.ps1",
    ),
}


@dataclass(frozen=True)
class SourceResolution:
    key: str
    path: Path
    origin: str
    commit: str | None
    remote: str | None
    matches_lock: bool


class SourceResolver:
    """Resolve sources in the documented five-level priority order."""

    def __init__(
        self,
        lock: TemplateLock,
        *,
        explicit_paths: Mapping[str, Path] | None = None,
        environment: Mapping[str, str] | None = None,
        default_base: Path = Path("/home/k4nul/git/devops"),
        cache_root: Path | None = None,
    ):
        unknown = set(explicit_paths or {}) - set(TEMPLATE_KEYS)
        if unknown:
            raise SourceResolutionError(
                f"unknown explicit template path keys: {', '.join(sorted(unknown))}"
            )
        self.lock = lock
        self.explicit_paths = dict(explicit_paths or {})
        self.environment = dict(os.environ if environment is None else environment)
        self.default_base = default_base
        self.cache_root = cache_root or self._default_cache_root()

    def _default_cache_root(self) -> Path:
        override = self.environment.get("DEVOPS_STACK_CACHE")
        if override:
            return Path(override).expanduser()
        xdg = self.environment.get("XDG_CACHE_HOME")
        if xdg:
            return Path(xdg).expanduser() / "devops-stack-composer" / "templates"
        return Path.home() / ".cache" / "devops-stack-composer" / "templates"

    def resolve_all(self, *, fetch: bool = True) -> dict[str, SourceResolution]:
        return {key: self.resolve(key, fetch=fetch) for key in TEMPLATE_KEYS}

    def resolve(self, key: str, *, fetch: bool = True) -> SourceResolution:
        pin = self.lock.pin(key)
        candidates: list[tuple[str, Path]] = []
        if key in self.explicit_paths:
            candidates.append(("cli", self.explicit_paths[key]))
        environment_path = self.environment.get(ENVIRONMENT_PATHS[key])
        if environment_path:
            candidates.append(("environment", Path(environment_path)))
        candidates.append(("default-local", self.default_base / pin.name))
        candidates.append(("cache", self._cache_path(pin)))

        for origin, candidate in candidates:
            if candidate.exists():
                return self._inspect_candidate(key, candidate, origin, pin)

        if not fetch:
            searched = ", ".join(str(path) for _, path in candidates)
            raise SourceResolutionError(
                f"cannot resolve {key} template without network fetch; searched {searched}"
            )
        cached = self._fetch_locked(pin)
        return self._inspect_candidate(key, cached, "lock-remote", pin)

    def _cache_path(self, pin: TemplatePin) -> Path:
        return self.cache_root / pin.name / pin.commit

    def _inspect_candidate(
        self,
        key: str,
        candidate: Path,
        origin: str,
        pin: TemplatePin,
    ) -> SourceResolution:
        path = candidate.expanduser().resolve(strict=True)
        if not path.is_dir():
            raise SourceResolutionError(f"{key} template source is not a directory: {path}")
        missing = [marker for marker in REQUIRED_MARKERS[key] if not (path / marker).is_file()]
        if missing:
            raise SourceResolutionError(
                f"{key} template source {path} is missing required files: {', '.join(missing)}"
            )
        commit = self._git_output(path, ["rev-parse", "HEAD"], required=False)
        remote = self._git_output(path, ["config", "--get", "remote.origin.url"], required=False)
        return SourceResolution(
            key=key,
            path=path,
            origin=origin,
            commit=commit,
            remote=remote,
            matches_lock=commit == pin.commit,
        )

    def _fetch_locked(self, pin: TemplatePin) -> Path:
        target = self._cache_path(pin)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{pin.name}.", dir=target.parent))
        try:
            self._run(["git", "init", "--quiet", str(temporary)])
            self._run(["git", "-C", str(temporary), "remote", "add", "origin", pin.repository])
            self._run(
                [
                    "git",
                    "-C",
                    str(temporary),
                    "fetch",
                    "--quiet",
                    "--depth",
                    "1",
                    "origin",
                    pin.commit,
                ]
            )
            self._run(
                ["git", "-C", str(temporary), "checkout", "--quiet", "--detach", "FETCH_HEAD"]
            )
            actual = self._git_output(temporary, ["rev-parse", "HEAD"])
            if actual != pin.commit:
                raise SourceResolutionError(
                    f"fetched {pin.key} commit {actual}, expected locked commit {pin.commit}"
                )
            try:
                temporary.rename(target)
            except FileExistsError:
                # A concurrent resolver won the race; verify that cache below.
                shutil.rmtree(temporary)
            return target
        except BaseException:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    @staticmethod
    def _run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise SourceResolutionError(f"template source command failed: {command[0]}: {exc}") from exc

    @staticmethod
    def _git_output(path: Path, arguments: list[str], *, required: bool = True) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), *arguments],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            if required:
                raise SourceResolutionError(f"cannot inspect Git source {path}: {exc}") from exc
            return None
        value = result.stdout.strip()
        return value or None
