"""Command-line entry point for DevOps Stack Composer."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from devops_stack_composer import __version__


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
