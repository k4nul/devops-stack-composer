from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from devops_stack_composer.process_compat import (
    SafeBuildCommandRunner,
    SafeSubprocessAdapter,
)
from devops_stack_composer.process_runner import (
    SafeProcessRunner,
    UnsafeProcessRequestError,
)


class ProcessCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.runner = SafeProcessRunner(
            self.project,
            allowed_executables={sys.executable},
            allowed_environment_keys=(),
            inherited_environment_keys=(),
            base_environment={},
            max_output_bytes=4096,
        )
        self.adapter = SafeSubprocessAdapter(self.runner)

    def test_text_adapter_preserves_nonzero_for_existing_component_checks(self) -> None:
        completed = self.adapter(
            [sys.executable, "-c", "import sys; print('failed'); sys.exit(7)"],
            cwd=self.project,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            timeout=2,
        )

        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, "failed\n")
        with self.assertRaises(subprocess.CalledProcessError):
            self.adapter(
                [sys.executable, "-c", "raise SystemExit(7)"],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_build_adapter_returns_bounded_exact_utf8_bytes(self) -> None:
        result = SafeBuildCommandRunner(self.adapter).run(
            [sys.executable, "-c", "print('{\"schemaVersion\":2}', end='')"],
            cwd=self.project,
            timeout=2,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'{"schemaVersion":2}')
        self.assertEqual(result.stderr, b"")

    def test_shell_stdin_and_uncaptured_output_are_rejected(self) -> None:
        invalid = (
            lambda: self.adapter([sys.executable], shell=True),
            lambda: self.adapter([sys.executable], input="payload"),
            lambda: self.adapter([sys.executable], capture_output=False),
        )
        for action in invalid:
            with self.subTest(action=action):
                with self.assertRaises(UnsafeProcessRequestError):
                    action()


if __name__ == "__main__":
    unittest.main()
