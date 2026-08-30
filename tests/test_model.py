from __future__ import annotations

import unittest

from devops_stack_composer.model import TAG_EXPRESSIONS, deep_merge


class ModelTests(unittest.TestCase):
    def test_deep_merge_does_not_mutate_inputs(self) -> None:
        base = {"nested": {"left": 1}, "list": [1]}
        override = {"nested": {"right": 2}, "list": [2]}

        result = deep_merge(base, override)
        result["nested"]["left"] = 99

        self.assertEqual(base, {"nested": {"left": 1}, "list": [1]})
        self.assertEqual(override, {"nested": {"right": 2}, "list": [2]})

    def test_tag_expressions_are_adapter_neutral(self) -> None:
        self.assertEqual(TAG_EXPRESSIONS["git-sha"], "${GIT_COMMIT_SHA}")
        self.assertNotIn("jenkins", TAG_EXPRESSIONS["branch-sha"].lower())


if __name__ == "__main__":
    unittest.main()
