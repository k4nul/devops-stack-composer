"""Strict execution state transitions and resumable run journals."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Mapping

from devops_stack_composer.evidence_store import EvidenceStore, EvidenceStoreError
from devops_stack_composer.oci import parse_digest, validate_sha256_hex


_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_MAX_CAPTURE_BYTES = 16_384


class ExecutionStateError(EvidenceStoreError):
    """Raised when a run journal is invalid or attempts an unsafe transition."""


class ExecutionState(str, Enum):
    PLANNED = "planned"
    VALIDATED = "validated"
    BUILDING = "building"
    BUILT = "built"
    PUSHING = "pushing"
    DIGEST_RESOLVED = "digest_resolved"
    CLUSTER_PREPARING = "cluster_preparing"
    APPLYING = "applying"
    WAITING_READY = "waiting_ready"
    SMOKE_TESTING = "smoke_testing"
    ATTESTING = "attesting"
    COLLECTING_EVIDENCE = "collecting_evidence"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CLEANED = "cleaned"


class ExecutionErrorCategory(str, Enum):
    COMMAND_NOT_FOUND = "command_not_found"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    NON_ZERO_EXIT = "non_zero_exit"
    VALIDATION = "validation"
    OWNERSHIP = "ownership"
    INTERNAL = "internal"


_LINEAR_NEXT: Mapping[ExecutionState, ExecutionState] = {
    ExecutionState.PLANNED: ExecutionState.VALIDATED,
    ExecutionState.VALIDATED: ExecutionState.BUILDING,
    ExecutionState.BUILDING: ExecutionState.BUILT,
    ExecutionState.BUILT: ExecutionState.PUSHING,
    ExecutionState.PUSHING: ExecutionState.DIGEST_RESOLVED,
    ExecutionState.DIGEST_RESOLVED: ExecutionState.CLUSTER_PREPARING,
    ExecutionState.CLUSTER_PREPARING: ExecutionState.APPLYING,
    ExecutionState.APPLYING: ExecutionState.WAITING_READY,
    ExecutionState.WAITING_READY: ExecutionState.SMOKE_TESTING,
    ExecutionState.SMOKE_TESTING: ExecutionState.ATTESTING,
    ExecutionState.ATTESTING: ExecutionState.COLLECTING_EVIDENCE,
    ExecutionState.COLLECTING_EVIDENCE: ExecutionState.SUCCEEDED,
}

def _timestamp(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExecutionStateError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ExecutionStateError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutionStateError(f"{name} must include a timezone")
    rendered = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds" if parsed.microsecond else "seconds"
    )
    return rendered.replace("+00:00", "Z")


def _safe_text(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ExecutionStateError(f"{name} must be a string")
    if "\x00" in value:
        raise ExecutionStateError(f"{name} must not contain NUL bytes")
    if len(value.encode("utf-8")) > _MAX_CAPTURE_BYTES:
        raise ExecutionStateError(
            f"{name} exceeds the {_MAX_CAPTURE_BYTES}-byte evidence limit"
        )
    return value


def _json_mapping(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionStateError(f"{name} must be a mapping")
    try:
        encoded = json.dumps(dict(value), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ExecutionStateError(f"{name} must contain finite JSON values") from exc
    decoded = json.loads(encoded)
    if any(not isinstance(key, str) or not key for key in decoded):
        raise ExecutionStateError(f"{name} keys must be non-empty strings")
    return {key: decoded[key] for key in sorted(decoded)}


@dataclass(frozen=True)
class StateTransition:
    state: ExecutionState
    started_at: str
    finished_at: str
    input_subject: str
    previous_state: ExecutionState | None = None
    outputs: Mapping[str, Any] = field(default_factory=dict)
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error_category: ExecutionErrorCategory | None = None
    checksum: str | None = None
    digest: str | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        try:
            state = self.state if isinstance(self.state, ExecutionState) else ExecutionState(self.state)
            previous = (
                self.previous_state
                if self.previous_state is None or isinstance(self.previous_state, ExecutionState)
                else ExecutionState(self.previous_state)
            )
        except ValueError as exc:
            raise ExecutionStateError("unsupported execution state") from exc
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "previous_state", previous)
        started = _timestamp("started_at", self.started_at)
        finished = _timestamp("finished_at", self.finished_at)
        if datetime.fromisoformat(finished.replace("Z", "+00:00")) < datetime.fromisoformat(
            started.replace("Z", "+00:00")
        ):
            raise ExecutionStateError("finished_at must not precede started_at")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "finished_at", finished)
        _safe_text("input_subject", self.input_subject)
        object.__setattr__(self, "outputs", _json_mapping("outputs", self.outputs))
        command = tuple(_safe_text("command argument", value) for value in self.command)
        object.__setattr__(self, "command", command)
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise ExecutionStateError("exit_code must be an integer or null")
        _safe_text("stdout", self.stdout, allow_empty=True)
        _safe_text("stderr", self.stderr, allow_empty=True)
        if not isinstance(self.timed_out, bool) or not isinstance(self.retryable, bool):
            raise ExecutionStateError("timed_out and retryable must be boolean")
        category = self.error_category
        if category is not None and not isinstance(category, ExecutionErrorCategory):
            try:
                category = ExecutionErrorCategory(category)
            except ValueError as exc:
                raise ExecutionStateError("unsupported execution error category") from exc
            object.__setattr__(self, "error_category", category)
        if self.timed_out and category != ExecutionErrorCategory.TIMEOUT:
            raise ExecutionStateError("timed_out transitions require timeout error category")
        if state == ExecutionState.FAILED and category is None:
            raise ExecutionStateError("failed transitions require an error category")
        if state != ExecutionState.FAILED and category is not None:
            raise ExecutionStateError("only failed transitions may carry an error category")
        if state != ExecutionState.FAILED and self.exit_code not in (None, 0):
            raise ExecutionStateError("successful transitions cannot record non-zero exit codes")
        if self.checksum is not None:
            validate_sha256_hex(self.checksum)
        if self.digest is not None:
            parse_digest(self.digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "previousState": self.previous_state.value if self.previous_state else None,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "inputSubject": self.input_subject,
            "outputs": dict(self.outputs),
            "command": list(self.command),
            "exitCode": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timedOut": self.timed_out,
            "errorCategory": self.error_category.value if self.error_category else None,
            "checksum": self.checksum,
            "digest": self.digest,
            "retryable": self.retryable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StateTransition":
        if not isinstance(value, Mapping):
            raise ExecutionStateError("state transition must be an object")
        required = {
            "state",
            "previousState",
            "startedAt",
            "finishedAt",
            "inputSubject",
            "outputs",
            "command",
            "exitCode",
            "stdout",
            "stderr",
            "timedOut",
            "errorCategory",
            "checksum",
            "digest",
            "retryable",
        }
        if set(value) != required:
            raise ExecutionStateError("state transition fields do not match schema")
        command = value["command"]
        if not isinstance(command, list):
            raise ExecutionStateError("state transition command must be an array")
        try:
            return cls(
                state=ExecutionState(value["state"]),
                previous_state=(
                    ExecutionState(value["previousState"])
                    if value["previousState"] is not None
                    else None
                ),
                started_at=value["startedAt"],
                finished_at=value["finishedAt"],
                input_subject=value["inputSubject"],
                outputs=value["outputs"],
                command=tuple(command),
                exit_code=value["exitCode"],
                stdout=value["stdout"],
                stderr=value["stderr"],
                timed_out=value["timedOut"],
                error_category=(
                    ExecutionErrorCategory(value["errorCategory"])
                    if value["errorCategory"] is not None
                    else None
                ),
                checksum=value["checksum"],
                digest=value["digest"],
                retryable=value["retryable"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExecutionStateError("state transition value is invalid") from exc


@dataclass
class ExecutionStateMachine:
    transitions: list[StateTransition] = field(default_factory=list)

    @property
    def current_state(self) -> ExecutionState | None:
        return self.transitions[-1].state if self.transitions else None

    def append(self, transition: StateTransition) -> None:
        current = self.current_state
        if transition.previous_state != current:
            raise ExecutionStateError(
                f"transition previous state {transition.previous_state!r} does not match {current!r}"
            )
        if current is None:
            allowed = transition.state == ExecutionState.PLANNED
        elif current in _LINEAR_NEXT:
            allowed = transition.state in {_LINEAR_NEXT[current], ExecutionState.FAILED}
        elif current in {ExecutionState.SUCCEEDED, ExecutionState.FAILED}:
            allowed = transition.state == ExecutionState.CLEANED
        else:
            allowed = False
        if not allowed:
            raise ExecutionStateError(
                f"invalid execution transition: {current!r} -> {transition.state.value}"
            )
        if self.transitions and datetime.fromisoformat(
            transition.started_at.replace("Z", "+00:00")
        ) < datetime.fromisoformat(
            self.transitions[-1].finished_at.replace("Z", "+00:00")
        ):
            raise ExecutionStateError("transition started before the previous stage finished")
        self.transitions.append(transition)

    def to_dict(self, run_id: str) -> dict[str, Any]:
        if not _RUN_ID.fullmatch(run_id):
            raise ExecutionStateError("journal run ID is invalid")
        return {
            "schemaVersion": "1.0.0",
            "runId": run_id,
            "currentState": self.current_state.value if self.current_state else None,
            "transitions": [transition.to_dict() for transition in self.transitions],
        }

    @classmethod
    def from_dict(cls, run_id: str, value: Mapping[str, Any]) -> "ExecutionStateMachine":
        if not isinstance(value, Mapping):
            raise ExecutionStateError("execution journal must be an object")
        if set(value) != {"schemaVersion", "runId", "currentState", "transitions"}:
            raise ExecutionStateError("execution journal fields do not match schema")
        if value["schemaVersion"] != "1.0.0" or value["runId"] != run_id:
            raise ExecutionStateError("execution journal belongs to another run or schema")
        transitions = value["transitions"]
        if not isinstance(transitions, list):
            raise ExecutionStateError("execution journal transitions must be an array")
        machine = cls()
        for item in transitions:
            if not isinstance(item, Mapping):
                raise ExecutionStateError("execution journal transition must be an object")
            machine.append(StateTransition.from_dict(item))
        current = machine.current_state.value if machine.current_state else None
        if value["currentState"] != current:
            raise ExecutionStateError("execution journal current state is inconsistent")
        return machine


@dataclass
class ExecutionJournal:
    store: EvidenceStore
    machine: ExecutionStateMachine = field(default_factory=ExecutionStateMachine)

    @classmethod
    def open(cls, store: EvidenceStore) -> "ExecutionJournal":
        path = store.path("state.json")
        if path.is_symlink() or not path.is_file():
            raise ExecutionStateError("execution journal is missing")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExecutionStateError("execution journal is not valid JSON") from exc
        if not isinstance(value, Mapping):
            raise ExecutionStateError("execution journal must be an object")
        return cls(store, ExecutionStateMachine.from_dict(store.run_id, value))

    def append(self, transition: StateTransition) -> None:
        candidate = ExecutionStateMachine(list(self.machine.transitions))
        candidate.append(transition)
        self.store.write_json(
            "state.json",
            candidate.to_dict(self.store.run_id),
            overwrite=self.store.path("state.json").exists(),
        )
        self.machine = candidate

    @property
    def current_state(self) -> ExecutionState | None:
        return self.machine.current_state
