"""Install and verify both Python distributions from one closed release set."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SENSITIVE_ENVIRONMENT = re.compile(
    r"(?:AUTH|COOKIE|CREDENTIAL|PASSWORD|SECRET|SESSION|TOKEN|PRIVATE_KEY|ACCESS_KEY|API_KEY)",
    re.IGNORECASE,
)
UNTRUSTED_PACKAGE_ENVIRONMENT_KEYS = frozenset(
    {"GIT_ASKPASS", "NETRC", "PIP_EXTRA_INDEX_URL", "PIP_INDEX_URL", "SSH_ASKPASS"}
)


def sanitized_environment() -> dict[str, str]:
    """Keep normal build inputs while withholding credentials from package code."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in UNTRUSTED_PACKAGE_ENVIRONMENT_KEYS
        and SENSITIVE_ENVIRONMENT.search(key) is None
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INPUT": "1",
        }
    )
    return environment


def verify_distribution(
    distribution: Path,
    assets: Path,
    expected_version: str,
    expected_commit: str,
) -> None:
    temporary_parent = os.environ.get("RUNNER_TEMP")
    with tempfile.TemporaryDirectory(dir=temporary_parent) as directory:
        root = Path(directory)
        environment = root / "venv"
        child_environment = sanitized_environment()
        subprocess.run(
            [sys.executable, "-m", "venv", str(environment)],
            check=True,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
        )
        python = environment / "bin" / "python"
        executable = environment / "bin" / "devops-stack"
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "--disable-pip-version-check",
                "install",
                str(distribution),
            ],
            check=True,
            cwd=root,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
        )
        subprocess.run(
            [str(python), "-m", "pip", "check"],
            check=True,
            cwd=root,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
        )
        version = subprocess.run(
            [str(executable), "--version"],
            check=True,
            capture_output=True,
            text=True,
            cwd=root,
            env=child_environment,
            stdin=subprocess.DEVNULL,
        )
        assert version.stdout.strip() == f"devops-stack {expected_version}", (
            version.stdout
        )

        check = r"""
import json
import os
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
import yaml

from devops_stack_composer import __version__
from devops_stack_composer.release_assets import verify_release_assets
from devops_stack_composer.resources import schema_path

expected_version = os.environ["RELEASE_VERSION"]
expected_commit = os.environ["RELEASE_COMMIT"]
assets = Path(os.environ["ASSET_DIRECTORY"])
assert __version__ == expected_version, __version__
verification = verify_release_assets(
    assets.parent,
    assets.name,
    expected_version=expected_version,
    expected_commit=expected_commit,
)
assert verification.manifest.version == expected_version, verification
assert verification.manifest.source_commit == expected_commit, verification
schema_names = (
    "devops-stack.schema.json",
    "execution-report.schema.json",
    "execution-evidence.schema.json",
)
schemas = {}
for name in schema_names:
    packaged = json.loads(schema_path(name).read_text())
    downloaded = json.loads((assets / name).read_text())
    Draft7Validator.check_schema(packaged)
    Draft7Validator.check_schema(downloaded)
    assert packaged == downloaded, name
    schemas[name] = packaged
config = yaml.safe_load((assets / "devops-stack.example.yaml").read_text())
errors = tuple(
    Draft7Validator(
        schemas["devops-stack.schema.json"],
        format_checker=FormatChecker(),
    ).iter_errors(config)
)
assert not errors, errors
"""
        child_environment.update(
            {
                "ASSET_DIRECTORY": str(assets),
                "RELEASE_COMMIT": expected_commit,
                "RELEASE_VERSION": expected_version,
            }
        )
        subprocess.run(
            [str(python), "-c", check],
            check=True,
            cwd=root,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
        )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: verify-release-distributions.py <asset-directory> <version> <commit>",
            file=sys.stderr,
        )
        return 2
    requested_assets = Path(sys.argv[1])
    if requested_assets.is_symlink():
        raise ValueError("asset directory must not be a symbolic link")
    assets = requested_assets.resolve(strict=True)
    expected_version = sys.argv[2]
    expected_commit = sys.argv[3]
    if not assets.is_dir():
        raise ValueError("asset directory must be a regular directory")
    if VERSION.fullmatch(expected_version) is None:
        raise ValueError("release version must be a stable semantic version")
    if COMMIT.fullmatch(expected_commit) is None:
        raise ValueError("release commit must be a full lowercase Git SHA")

    distributions = sorted(
        (
            *assets.glob("devops_stack_composer-*.whl"),
            *assets.glob("devops_stack_composer-*.tar.gz"),
        )
    )
    if len(distributions) != 2:
        raise ValueError(
            "release must contain exactly one wheel and one source distribution"
        )
    if (
        sum(path.name.endswith(".whl") for path in distributions) != 1
        or sum(path.name.endswith(".tar.gz") for path in distributions) != 1
    ):
        raise ValueError(
            "release must contain exactly one wheel and one source distribution"
        )
    if any(not path.is_file() or path.is_symlink() for path in distributions):
        raise ValueError("release distributions must be regular files")

    for distribution in distributions:
        verify_distribution(distribution, assets, expected_version, expected_commit)
    print(
        json.dumps(
            {
                "commit": expected_commit,
                "distributions": [path.name for path in distributions],
                "passed": True,
                "version": expected_version,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
