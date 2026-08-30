from __future__ import annotations

import contextlib
import io
import unittest

from devops_stack_composer.cli import main


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), "devops-stack 0.1.0\n")


if __name__ == "__main__":
    unittest.main()
