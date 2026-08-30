from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from devops_stack_composer import resources


class PackageImportTests(unittest.TestCase):
    def test_validation_and_lazy_adapter_exports_import_in_a_clean_process(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                "-c",
                (
                    "import devops_stack_composer.validation; "
                    "from devops_stack_composer.adapters import "
                    "DockerBuildAdapter, JenkinsPipelineAdapter, "
                    "KubernetesAdapter, KubernetesPlatformAdapter; "
                    "assert KubernetesAdapter is KubernetesPlatformAdapter"
                ),
            ),
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_resource_lookup_supports_an_isolated_prefix_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "local"
            package_file = (
                prefix
                / "lib"
                / "python3.10"
                / "site-packages"
                / "devops_stack_composer"
                / "resources.py"
            )
            expected = (
                prefix
                / "share"
                / "devops-stack-composer"
                / "templates.lock.json"
            )
            expected.parent.mkdir(parents=True)
            expected.write_text("{}\n", encoding="utf-8")

            with patch.object(resources, "_PACKAGE_PATH", package_file), patch.object(
                resources,
                "_distribution_candidates",
                return_value=(),
            ):
                actual = resources.resource_path("templates.lock.json")

            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
