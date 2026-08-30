from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.execution_state import (
    ExecutionErrorCategory,
    ExecutionJournal,
    ExecutionState,
    ExecutionStateError,
    ExecutionStateMachine,
    StateTransition,
)


RUN_ID = "20260830T140000Z-012345abcdef"
STATE_ORDER = (
    ExecutionState.PLANNED,
    ExecutionState.VALIDATED,
    ExecutionState.BUILDING,
    ExecutionState.BUILT,
    ExecutionState.PUSHING,
    ExecutionState.DIGEST_RESOLVED,
    ExecutionState.CLUSTER_PREPARING,
    ExecutionState.APPLYING,
    ExecutionState.WAITING_READY,
    ExecutionState.SMOKE_TESTING,
    ExecutionState.ATTESTING,
    ExecutionState.COLLECTING_EVIDENCE,
    ExecutionState.SUCCEEDED,
    ExecutionState.CLEANED,
)


def transition(
    state: ExecutionState,
    previous: ExecutionState | None,
    **kwargs: object,
) -> StateTransition:
    if state == ExecutionState.FAILED:
        if previous is None:
            raise AssertionError("failed test transitions require a previous state")
        index = STATE_ORDER.index(previous) + 1
    else:
        index = STATE_ORDER.index(state)
    values: dict[str, object] = {
        "state": state,
        "previous_state": previous,
        "started_at": f"2026-08-30T14:00:{index * 2:02d}Z",
        "finished_at": f"2026-08-30T14:00:{index * 2 + 1:02d}Z",
        "input_subject": "example@sha256:" + "a" * 64,
        "outputs": {"stage": state.value},
        "exit_code": 0,
    }
    values.update(kwargs)
    return StateTransition(**values)  # type: ignore[arg-type]


class ExecutionStateTests(unittest.TestCase):
    def test_complete_state_sequence_is_persisted_and_reopened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore.create(Path(directory), run_id=RUN_ID)
            journal = ExecutionJournal(store)
            previous = None
            states = STATE_ORDER
            for state in states:
                journal.append(transition(state, previous))
                previous = state

            reopened = ExecutionJournal.open(store)

            self.assertEqual(reopened.current_state, ExecutionState.CLEANED)
            self.assertEqual(
                [item.state for item in reopened.machine.transitions],
                list(states),
            )
            value = json.loads(store.path("state.json").read_text(encoding="utf-8"))
            self.assertEqual(value["runId"], RUN_ID)
            self.assertEqual(value["currentState"], "cleaned")

    def test_skip_repeated_build_and_success_to_failure_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore.create(Path(directory), run_id=RUN_ID)
            journal = ExecutionJournal(store)
            journal.append(transition(ExecutionState.PLANNED, None))
            with self.assertRaisesRegex(ExecutionStateError, "invalid execution transition"):
                journal.append(
                    transition(ExecutionState.BUILDING, ExecutionState.PLANNED)
                )
            journal.append(
                transition(ExecutionState.VALIDATED, ExecutionState.PLANNED)
            )
            journal.append(
                transition(ExecutionState.BUILDING, ExecutionState.VALIDATED)
            )
            journal.append(transition(ExecutionState.BUILT, ExecutionState.BUILDING))
            with self.assertRaisesRegex(ExecutionStateError, "invalid execution transition"):
                journal.append(transition(ExecutionState.BUILDING, ExecutionState.BUILT))

        with tempfile.TemporaryDirectory() as directory:
            machine = ExecutionJournal(
                EvidenceStore.create(Path(directory), run_id=RUN_ID)
            )
            previous = None
            for state in (
                ExecutionState.PLANNED,
                ExecutionState.VALIDATED,
                ExecutionState.BUILDING,
                ExecutionState.BUILT,
                ExecutionState.PUSHING,
                ExecutionState.DIGEST_RESOLVED,
                ExecutionState.CLUSTER_PREPARING,
                ExecutionState.APPLYING,
                ExecutionState.WAITING_READY,
                ExecutionState.SMOKE_TESTING,
                ExecutionState.ATTESTING,
                ExecutionState.COLLECTING_EVIDENCE,
                ExecutionState.SUCCEEDED,
            ):
                machine.append(transition(state, previous))
                previous = state
            with self.assertRaisesRegex(
                ExecutionStateError, "invalid execution transition"
            ):
                machine.append(
                    transition(
                        ExecutionState.FAILED,
                        ExecutionState.SUCCEEDED,
                        exit_code=1,
                        error_category=ExecutionErrorCategory.NON_ZERO_EXIT,
                    )
                )

    def test_failure_can_only_cleanup_and_preserves_error_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore.create(Path(directory), run_id=RUN_ID)
            journal = ExecutionJournal(store)
            journal.append(transition(ExecutionState.PLANNED, None))
            failed = transition(
                ExecutionState.FAILED,
                ExecutionState.PLANNED,
                exit_code=124,
                timed_out=True,
                error_category=ExecutionErrorCategory.TIMEOUT,
                retryable=True,
                stderr="registry readiness timed out",
            )
            journal.append(failed)
            with self.assertRaisesRegex(ExecutionStateError, "invalid execution transition"):
                journal.append(
                    transition(ExecutionState.VALIDATED, ExecutionState.FAILED)
                )
            journal.append(transition(ExecutionState.CLEANED, ExecutionState.FAILED))

            reopened = ExecutionJournal.open(store)
            self.assertEqual(
                reopened.machine.transitions[1].error_category,
                ExecutionErrorCategory.TIMEOUT,
            )
            self.assertTrue(reopened.machine.transitions[1].retryable)

    def test_journal_rejects_other_run_tampering_and_closed_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            store = EvidenceStore.create(project, run_id=RUN_ID)
            journal = ExecutionJournal(store)
            journal.append(transition(ExecutionState.PLANNED, None))
            value = json.loads(store.path("state.json").read_text(encoding="utf-8"))
            value["runId"] = "20260830T140001Z-ffffffffffff"
            store.write_json("state.json", value, overwrite=True)

            with self.assertRaisesRegex(ExecutionStateError, "another run"):
                ExecutionJournal.open(store)

    def test_transition_rejects_unbounded_output_and_invalid_failure_shape(self) -> None:
        with self.assertRaisesRegex(ExecutionStateError, "evidence limit"):
            transition(ExecutionState.PLANNED, None, stdout="x" * 16_385)
        with self.assertRaisesRegex(ExecutionStateError, "error category"):
            transition(
                ExecutionState.FAILED,
                ExecutionState.PLANNED,
                exit_code=1,
            )
        with self.assertRaisesRegex(ExecutionStateError, "timeout error category"):
            transition(
                ExecutionState.FAILED,
                ExecutionState.PLANNED,
                exit_code=1,
                timed_out=True,
                error_category=ExecutionErrorCategory.NON_ZERO_EXIT,
            )

    def test_journal_rejects_non_monotonic_time_and_non_array_command(self) -> None:
        machine = ExecutionStateMachine()
        machine.append(transition(ExecutionState.PLANNED, None))
        with self.assertRaisesRegex(ExecutionStateError, "previous stage finished"):
            machine.append(
                transition(
                    ExecutionState.VALIDATED,
                    ExecutionState.PLANNED,
                    started_at="2026-08-30T13:59:59Z",
                )
            )
        value = transition(ExecutionState.PLANNED, None).to_dict()
        value["command"] = "docker version"
        with self.assertRaisesRegex(ExecutionStateError, "command must be an array"):
            StateTransition.from_dict(value)


if __name__ == "__main__":
    unittest.main()
