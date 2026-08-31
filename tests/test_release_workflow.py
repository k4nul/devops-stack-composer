from __future__ import annotations

import unittest
from pathlib import Path

import yaml

RELEASE_WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_draft_consumers_have_required_visibility_before_publication(self) -> None:
        workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
        jobs = workflow["jobs"]

        self.assertEqual(jobs["validate-draft"]["permissions"]["contents"], "write")
        self.assertEqual(jobs["verify-draft"]["permissions"]["contents"], "write")
        self.assertIn("verify-draft", jobs["publish-github"]["needs"])
        self.assertEqual(jobs["post-publication"]["permissions"]["contents"], "read")


if __name__ == "__main__":
    unittest.main()
