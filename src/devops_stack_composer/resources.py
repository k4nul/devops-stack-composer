"""Locate committed data in a source checkout or an installed distribution."""

from __future__ import annotations

import sysconfig
import site
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Iterable


_PACKAGE_PATH = Path(__file__).resolve()
_SOURCE_ROOT = _PACKAGE_PATH.parents[2]
_INSTALLED_ROOT = (
    Path(sysconfig.get_path("data")) / "share" / "devops-stack-composer"
)
_USER_ROOT = Path(site.USER_BASE) / "share" / "devops-stack-composer"


def _distribution_candidates(relative: str) -> Iterable[Path]:
    """Locate data-files using the installed wheel's own RECORD entries."""

    try:
        installed = distribution("devops-stack-composer")
    except PackageNotFoundError:
        return ()
    suffix = ("share", "devops-stack-composer", *Path(relative).parts)
    return tuple(
        Path(installed.locate_file(entry))
        for entry in (installed.files or ())
        if len(entry.parts) >= len(suffix)
        and tuple(entry.parts[-len(suffix) :]) == suffix
    )


def _prefix_candidates(relative: str) -> Iterable[Path]:
    """Cover virtualenv, --target, and --prefix layouts near the module."""

    return tuple(
        ancestor / "share" / "devops-stack-composer" / relative
        for ancestor in _PACKAGE_PATH.parents
    )


def resource_path(relative: str) -> Path:
    """Return a required project resource from source or installed data files."""

    candidates: list[Path] = []
    source_module = _SOURCE_ROOT / "src" / "devops_stack_composer" / "resources.py"
    if source_module.is_file() and source_module.resolve() == _PACKAGE_PATH:
        candidates.append(_SOURCE_ROOT / relative)
    candidates.extend(_distribution_candidates(relative))
    candidates.extend(_prefix_candidates(relative))
    candidates.append(_INSTALLED_ROOT / relative)
    candidates.append(_USER_ROOT / relative)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"devops-stack-composer resource is missing: {relative}; "
        "reinstall the package or run from a complete source checkout"
    )


def default_lock_path() -> Path:
    return resource_path("templates.lock.json")


def schema_path(name: str) -> Path:
    return resource_path(f"schemas/{name}")
