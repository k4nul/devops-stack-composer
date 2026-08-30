"""Project-contained, symlink-aware, atomic file operations."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path, PurePosixPath

from devops_stack_composer.errors import GeneratedFileConflictError, UnsafePathError


def project_root(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise UnsafePathError(f"project root does not exist: {path}") from exc
    if not resolved.is_dir():
        raise UnsafePathError(f"project root is not a directory: {resolved}")
    return resolved


def normalize_relative_path(value: str) -> str:
    if not value or "\x00" in value:
        raise UnsafePathError("path must be a non-empty relative path without NUL bytes")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise UnsafePathError(f"path must stay inside the project root: {value!r}")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise UnsafePathError(f"path must identify a file: {value!r}")
    return normalized


def contained_path(root: Path, relative: str) -> Path:
    resolved_root = project_root(root)
    normalized = normalize_relative_path(relative)
    candidate = resolved_root.joinpath(*PurePosixPath(normalized).parts)
    current = resolved_root
    for part in PurePosixPath(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise UnsafePathError(
                f"path crosses a symbolic link inside the project: {relative!r}"
            )
    try:
        resolved_candidate = candidate.resolve(strict=False)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise UnsafePathError(
            f"path resolves outside project root {resolved_root}: {relative!r}"
        ) from exc
    return candidate


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(
    root: Path,
    relative: str,
    content: str | bytes,
    *,
    mode: int = 0o644,
    overwrite: bool = False,
) -> Path:
    target = contained_path(root, relative)
    if target.exists() and not overwrite:
        raise GeneratedFileConflictError(f"refusing to overwrite existing file: {relative}")
    if target.exists() and not target.is_file():
        raise UnsafePathError(f"write target is not a regular file: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Re-resolve after directory creation to catch a concurrent symlink boundary change.
    verified = contained_path(root, relative)
    if verified != target:
        raise UnsafePathError(f"write target changed during validation: {relative}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        dir=target.parent,
    )
    try:
        payload = content.encode("utf-8") if isinstance(content, str) else content
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, stat.S_IMODE(mode))
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return target
