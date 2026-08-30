from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from devops_stack_composer.evidence_store import (
    EvidenceStore,
    EvidenceStoreError,
    new_run_id,
)
from devops_stack_composer.errors import UnsafePathError


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.run_id = "20260830T120000Z-abcdef123456"

    def test_run_id_is_stable_with_injected_inputs(self) -> None:
        value = new_run_id(
            now=datetime(2026, 8, 30, 12, tzinfo=timezone.utc),
            random_hex="abcdef123456",
        )
        self.assertEqual(value, self.run_id)

    def test_creates_private_bundle_and_verifies_closed_checksum_inventory(self) -> None:
        store = EvidenceStore.create(self.project, run_id=self.run_id)
        store.write_json("artifact.json", {"digest": "sha256:" + "a" * 64})
        store.write_text("logs/build.log", "sanitized\n")
        store.write_checksums()

        checksums = store.verify_checksums()

        self.assertEqual(set(checksums), {"artifact.json", "logs/build.log"})
        self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(store.path("artifact.json").stat().st_mode & 0o777, 0o600)

    def test_tampering_fails_verification(self) -> None:
        store = EvidenceStore.create(self.project, run_id=self.run_id)
        store.write_text("artifact.json", "{}\n")
        store.write_checksums()
        store.write_text("artifact.json", '{"tampered":true}\n', overwrite=True)

        with self.assertRaisesRegex(EvidenceStoreError, "checksum mismatch"):
            store.verify_checksums()

    def test_added_untracked_file_fails_verification(self) -> None:
        store = EvidenceStore.create(self.project, run_id=self.run_id)
        store.write_text("artifact.json", "{}\n")
        store.write_checksums()
        store.write_text("unexpected.json", "{}\n")

        with self.assertRaisesRegex(EvidenceStoreError, "inventory mismatch"):
            store.verify_checksums()

    def test_run_collision_is_rejected(self) -> None:
        EvidenceStore.create(self.project, run_id=self.run_id)
        with self.assertRaisesRegex(EvidenceStoreError, "collision"):
            EvidenceStore.create(self.project, run_id=self.run_id)

    def test_symlink_escape_is_rejected(self) -> None:
        outside = self.project.parent / "outside-evidence"
        run_root = self.project / ".devops-stack" / "runs" / self.run_id
        run_root.parent.mkdir(parents=True)
        run_root.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(UnsafePathError):
            EvidenceStore.create(self.project, run_id=self.run_id)

    def test_open_requires_safe_existing_run(self) -> None:
        store = EvidenceStore.create(self.project, run_id=self.run_id)
        reopened = EvidenceStore.open(self.project, self.run_id)
        self.assertEqual(reopened.root, store.root)
        with self.assertRaisesRegex(EvidenceStoreError, "invalid run ID"):
            EvidenceStore.open(self.project, "../escape")


if __name__ == "__main__":
    unittest.main()
