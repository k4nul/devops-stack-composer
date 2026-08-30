from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from devops_stack_composer.errors import LockValidationError
from devops_stack_composer.locks import TemplateLock, TemplateUpdate


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "templates.lock.json"


class TemplateLockTests(unittest.TestCase):
    def test_committed_lock_is_valid_and_complete(self) -> None:
        lock = TemplateLock.load(LOCK_PATH)

        self.assertEqual([pin.key for pin in lock.pins()], ["docker", "jenkins", "kubernetes"])
        self.assertEqual(len(lock.pin("docker").commit), 40)
        self.assertEqual(lock.pin("kubernetes").license_spdx, "MIT")

    def test_unknown_lock_field_is_rejected(self) -> None:
        data = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        data["templates"]["docker"]["floatingBranch"] = "main"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "templates.lock.json"
            path.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(LockValidationError, "floatingBranch"):
                TemplateLock.load(path)

    def test_updates_are_in_memory_until_explicit_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "templates.lock.json"
            path.write_text(LOCK_PATH.read_text(encoding="utf-8"), encoding="utf-8")
            original = path.read_text(encoding="utf-8")
            lock = TemplateLock.load(path)
            replacement = "a" * 40

            updated = lock.with_updates(
                (TemplateUpdate("docker", lock.pin("docker").commit, replacement),),
                checked_at=date(2026, 8, 31),
            )

            self.assertEqual(path.read_text(encoding="utf-8"), original)
            updated.write()
            reloaded = TemplateLock.load(path)
            self.assertEqual(reloaded.pin("docker").commit, replacement)
            self.assertEqual(reloaded.pin("docker").checked_at, "2026-08-31")

    def test_unknown_template_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(LockValidationError, "unknown template"):
            TemplateLock.load(LOCK_PATH).pin("terraform")


if __name__ == "__main__":
    unittest.main()
