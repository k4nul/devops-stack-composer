#!/usr/bin/env python3
"""Validate repository-local links in tracked Markdown documents."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

INLINE_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)(?:\s+[^)]*)?\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)", re.MULTILINE)
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$", re.MULTILINE)
EXTERNAL_SCHEMES = {"http", "https", "mailto"}


def tracked_markdown(root: Path) -> tuple[Path, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return tuple(root / value.decode() for value in result.stdout.split(b"\0") if value)


def github_anchors(path: Path) -> set[str]:
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for match in HEADING.finditer(path.read_text(encoding="utf-8")):
        title = re.sub(r"<[^>]+>", "", match.group("title")).strip().lower()
        slug = re.sub(r"[^\w\- ]", "", title, flags=re.UNICODE)
        slug = re.sub(r"\s+", "-", slug)
        suffix = counts.get(slug, 0)
        counts[slug] = suffix + 1
        anchors.add(slug if suffix == 0 else f"{slug}-{suffix}")
    return anchors


def targets(document: Path) -> tuple[str, ...]:
    content = document.read_text(encoding="utf-8")
    return tuple(
        match.group("target").strip("<>")
        for pattern in (INLINE_LINK, REFERENCE_LINK)
        for match in pattern.finditer(content)
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for document in tracked_markdown(root):
        for target in targets(document):
            parsed = urlsplit(target)
            if parsed.scheme.lower() in EXTERNAL_SCHEMES or parsed.netloc:
                continue
            path_text = unquote(parsed.path)
            destination = document if not path_text else document.parent / path_text
            try:
                resolved = destination.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                errors.append(
                    f"{document.relative_to(root)}: missing or unsafe link: {target}"
                )
                continue
            if not resolved.is_file() and parsed.fragment:
                errors.append(
                    f"{document.relative_to(root)}: anchor target is not a file: {target}"
                )
                continue
            if parsed.fragment and resolved.suffix.lower() == ".md":
                anchors = anchor_cache.setdefault(resolved, github_anchors(resolved))
                fragment = unquote(parsed.fragment).lower()
                if fragment not in anchors:
                    errors.append(
                        f"{document.relative_to(root)}: missing anchor: {target}"
                    )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"validated local links in {len(tracked_markdown(root))} tracked Markdown files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
