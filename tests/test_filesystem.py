from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.errors import GeneratedFileConflictError, UnsafePathError
from devops_stack_composer.filesystem import atomic_write, contained_path


class FilesystemSafetyTests(unittest.TestCase):
    def test_path_traversal_and_absolute_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ("../outside", "/tmp/outside", "nested/../../outside"):
                with self.subTest(value=value), self.assertRaises(UnsafePathError):
                    contained_path(root, value)

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "linked").symlink_to(Path(outside), target_is_directory=True)

            with self.assertRaises(UnsafePathError):
                atomic_write(root, "linked/escape.txt", "blocked")

            self.assertFalse((Path(outside) / "escape.txt").exists())

    def test_internal_directory_symlink_is_rejected_for_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user_files = root / "user-files"
            user_files.mkdir()
            (root / "generated").symlink_to(user_files, target_is_directory=True)

            with self.assertRaises(UnsafePathError):
                atomic_write(root, "generated/new.txt", "blocked")

            self.assertFalse((user_files / "new.txt").exists())

    def test_atomic_write_preserves_mode_and_requires_overwrite_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = atomic_write(root, "generated/script.sh", "#!/bin/sh\n", mode=0o755)

            self.assertEqual(target.read_text(encoding="utf-8"), "#!/bin/sh\n")
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
            with self.assertRaises(GeneratedFileConflictError):
                atomic_write(root, "generated/script.sh", "changed\n")
            atomic_write(root, "generated/script.sh", "changed\n", overwrite=True)
            self.assertEqual(target.read_text(encoding="utf-8"), "changed\n")


if __name__ == "__main__":
    unittest.main()
