"""Safe materialization of the exact Git bytes named by a template lock."""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

from devops_stack_composer.errors import SourceResolutionError
from devops_stack_composer.sources import SourceResolution


def extract_locked_source(source: SourceResolution, destination: Path) -> None:
    """Write only regular files/directories from the resolved locked Git commit."""

    if not source.matches_lock or source.commit is None:
        raise SourceResolutionError(
            f"{source.key} source cannot be archived because it does not match the lock"
        )
    try:
        head = subprocess.run(
            ["git", "-C", str(source.path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        archived = subprocess.run(
            [
                "git",
                "-C",
                str(source.path),
                "archive",
                "--format=tar",
                source.commit,
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SourceResolutionError(
            f"cannot archive locked {source.key} template commit: {type(exc).__name__}"
        ) from exc
    if head.stdout.strip() != source.commit:
        raise SourceResolutionError(
            f"{source.key} source HEAD changed after resolution; expected {source.commit}"
        )

    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve(strict=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
            for member in archive.getmembers():
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                    or "\\" in member.name
                ):
                    raise SourceResolutionError(
                        f"unsafe path in locked {source.key} Git archive"
                    )
                target = root.joinpath(*relative.parts)
                try:
                    target.resolve(strict=False).relative_to(root)
                except ValueError as exc:
                    raise SourceResolutionError(
                        f"locked {source.key} Git archive leaves its staging root"
                    ) from exc
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise SourceResolutionError(
                        f"locked {source.key} Git archive contains a non-regular entry"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SourceResolutionError(
                        f"locked {source.key} Git archive contains an unreadable file"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as handle:
                    handle.write(extracted.read())
                os.chmod(target, member.mode & 0o777)
    except (OSError, tarfile.TarError) as exc:
        raise SourceResolutionError(
            f"cannot extract locked {source.key} template commit: {type(exc).__name__}"
        ) from exc
