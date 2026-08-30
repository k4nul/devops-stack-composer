"""Deterministic assembly and fail-closed verification of execution evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from devops_stack_composer.errors import UnsafePathError
from devops_stack_composer.evidence_store import EvidenceStore, EvidenceStoreError
from devops_stack_composer.execution_models import ExecutionRun
from devops_stack_composer.execution_plan import ExecutionPlan
from devops_stack_composer.execution_state import (
    ExecutionState,
    ExecutionStateMachine,
    ExecutionStateError,
)
from devops_stack_composer.filesystem import normalize_relative_path, sha256_file
from devops_stack_composer.policies import profile_policy
from devops_stack_composer.report import redact_sensitive
from devops_stack_composer.runtime_validation import (
    RuntimeVerification,
    validate_runtime_records,
)


BUNDLE_SCHEMA_VERSION = "1.0.0"
MAX_BUNDLE_JSON_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_LOG_BYTES = 1024 * 1024
AUTHENTICITY_STATUS = "NOT_ESTABLISHED"

_JSON_FILES = (
    "run.json",
    "plan.json",
    "state.json",
    "policy.json",
    "artifacts.json",
    "commands.json",
    "deployment.json",
    "attestation.json",
    "smoke.json",
    "checksums.json",
)
REQUIRED_BUNDLE_FILES = frozenset((*_JSON_FILES, "summary.md"))
_ASSEMBLER_JSON_FILES = tuple(
    relative
    for relative in _JSON_FILES
    if relative not in {"state.json", "plan.json", "policy.json"}
)
_ASSEMBLER_FILES = frozenset(
    (*_ASSEMBLER_JSON_FILES, "summary.md", "SHA256SUMS")
)


class EvidenceBundleError(EvidenceStoreError):
    """A stable error raised when a bundle is incomplete or inconsistent."""

    def __init__(self, code: str, message: str, *, evidence_path: str | None = None):
        self.code = code
        self.evidence_path = evidence_path
        suffix = f"; evidence: {evidence_path}" if evidence_path else ""
        super().__init__(f"{code}: {message}{suffix}")


@dataclass(frozen=True)
class EvidenceBundleVerification:
    """A verification result that distinguishes integrity from execution success."""

    run_id: str
    profile: str
    build_plan_hash: str
    final_status: str
    incomplete: bool
    artifact_digest: str | None
    material_file_count: int

    @property
    def execution_succeeded(self) -> bool:
        return self.final_status == "PASSED" and not self.incomplete

    @property
    def authenticity_established(self) -> bool:
        # SHA-256 detects changes relative to this bundle's own manifest. With no
        # external signature or trusted digest, it cannot identify who created it.
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": True,
            "runId": self.run_id,
            "profile": self.profile,
            "buildPlanHash": self.build_plan_hash,
            "finalStatus": self.final_status,
            "incomplete": self.incomplete,
            "executionSucceeded": self.execution_succeeded,
            "artifactDigest": self.artifact_digest,
            "materialFileCount": self.material_file_count,
            "authenticity": AUTHENTICITY_STATUS,
        }


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _read_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    if path.is_symlink():
        raise EvidenceBundleError(
            "BUNDLE_FILE_INVALID",
            f"{label} must be a regular non-symlink file",
            evidence_path=label,
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceBundleError(
            "BUNDLE_FILE_INVALID",
            f"cannot open {label}",
            evidence_path=label,
        ) from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceBundleError(
                    "BUNDLE_FILE_INVALID",
                    f"{label} must be a regular file",
                    evidence_path=label,
                )
            if metadata.st_size > maximum:
                raise EvidenceBundleError(
                    "BUNDLE_FILE_TOO_LARGE",
                    f"{label} exceeds the {maximum}-byte limit",
                    evidence_path=label,
                )
            payload = stream.read(maximum + 1)
    except EvidenceBundleError:
        raise
    except OSError as exc:
        raise EvidenceBundleError(
            "BUNDLE_FILE_INVALID",
            f"cannot read {label}",
            evidence_path=label,
        ) from exc
    if len(payload) > maximum:
        raise EvidenceBundleError(
            "BUNDLE_FILE_TOO_LARGE",
            f"{label} exceeds the {maximum}-byte limit",
            evidence_path=label,
        )
    return payload


def _read_json(store: EvidenceStore, relative: str, expected_digest: str) -> dict[str, Any]:
    payload = _read_regular_file(
        store.path(relative), maximum=MAX_BUNDLE_JSON_BYTES, label=relative
    )
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise EvidenceBundleError(
            "BUNDLE_FILE_CHANGED",
            f"{relative} changed while it was being verified",
            evidence_path=relative,
        )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError) as exc:
        raise EvidenceBundleError(
            "BUNDLE_JSON_INVALID",
            f"{relative} is not strict JSON: {exc}",
            evidence_path=relative,
        ) from exc
    if not isinstance(value, dict):
        raise EvidenceBundleError(
            "BUNDLE_JSON_INVALID",
            f"{relative} must contain one JSON object",
            evidence_path=relative,
        )
    return value


def _as_record(value: Mapping[str, Any] | ExecutionPlan | ExecutionRun) -> dict[str, Any]:
    if isinstance(value, (ExecutionPlan, ExecutionRun)):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("execution plan and run evidence must be mappings or domain records")
    try:
        payload = json.dumps(
            dict(value), sort_keys=True, allow_nan=False, ensure_ascii=False
        )
        decoded = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise EvidenceBundleError(
            "BUNDLE_RECORD_INVALID", "bundle inputs must contain finite JSON values"
        ) from exc
    if not isinstance(decoded, dict):
        raise EvidenceBundleError(
            "BUNDLE_RECORD_INVALID", "bundle inputs must be JSON objects"
        )
    return decoded


def _identity(plan: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runId": run["runId"],
        "projectPath": run["projectPath"],
        "configHash": run["configHash"],
        "templateLockHash": run["templateLockHash"],
        "sourceRevision": run["sourceRevision"],
        "buildPlanHash": plan["buildPlanHash"],
    }


def _require_redacted(value: Mapping[str, Any], *, label: str) -> None:
    if redact_sensitive(dict(value)) != dict(value):
        raise EvidenceBundleError(
            "BUNDLE_SECRET_EXPOSURE",
            f"{label} contains sensitive data that was not redacted",
            evidence_path=label,
        )


def _verify_state_record(
    state: Mapping[str, Any],
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    verification: RuntimeVerification,
) -> None:
    try:
        machine = ExecutionStateMachine.from_dict(verification.run_id, state)
    except ExecutionStateError as exc:
        raise EvidenceBundleError(
            "BUNDLE_STATE_INVALID", str(exc), evidence_path="state.json"
        ) from exc
    transitions = machine.transitions
    if not transitions:
        raise EvidenceBundleError(
            "BUNDLE_STATE_NOT_TERMINAL",
            "state journal has no terminal transition",
            evidence_path="state.json",
        )
    states = tuple(transition.state for transition in transitions)
    plan_subject = str(plan["buildPlanHash"])
    if transitions[0].input_subject != plan_subject:
        raise EvidenceBundleError(
            "BUNDLE_STATE_PLAN_MISMATCH",
            "planned state does not reference the verified build plan hash",
            evidence_path="state.json",
        )
    terminal_records = tuple(
        transition
        for transition in transitions
        if transition.state in {ExecutionState.SUCCEEDED, ExecutionState.FAILED}
    )
    if not terminal_records or terminal_records[-1].input_subject != plan_subject:
        raise EvidenceBundleError(
            "BUNDLE_STATE_PLAN_MISMATCH",
            "terminal state does not reference the verified build plan hash",
            evidence_path="state.json",
        )
    if verification.final_status == "PASSED":
        consistent = (
            ExecutionState.SUCCEEDED in states
            and ExecutionState.FAILED not in states
            and machine.current_state
            in {ExecutionState.SUCCEEDED, ExecutionState.CLEANED}
        )
    else:
        consistent = (
            ExecutionState.FAILED in states
            and ExecutionState.SUCCEEDED not in states
            and machine.current_state in {ExecutionState.FAILED, ExecutionState.CLEANED}
        )
    if not consistent:
        raise EvidenceBundleError(
            "BUNDLE_STATE_OUTCOME_MISMATCH",
            "terminal state does not match the verified execution outcome",
            evidence_path="state.json",
        )
    if state["runId"] != run["runId"]:
        raise EvidenceBundleError(
            "BUNDLE_STATE_RUN_MISMATCH",
            "state journal belongs to a different execution run",
            evidence_path="state.json",
        )


def _envelope(
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    verification: RuntimeVerification,
) -> dict[str, Any]:
    return {
        "schemaVersion": BUNDLE_SCHEMA_VERSION,
        "identity": _identity(plan, run),
        "finalStatus": verification.final_status,
        "incomplete": verification.incomplete,
    }


def _derived_records(
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    verification: RuntimeVerification,
) -> dict[str, dict[str, Any]]:
    base = _envelope(plan, run, verification)
    artifact = run["artifact"]
    supply = run["supplyChainEvidence"]
    deployment = run["deploymentEvidence"]
    policy = profile_policy(str(plan["profile"])).to_dict()
    commands = [
        {
            "stageId": stage["stageId"],
            "status": stage["status"],
            "argv": stage["command"],
            "tool": stage["tool"],
        }
        for stage in run["stageResults"]
    ]
    smoke = {
        "expectedDigest": None,
        "actualPodImageId": None,
        "finalDigest": None,
        "health": None,
        "readiness": None,
    }
    if deployment is not None:
        smoke = {
            "expectedDigest": deployment["expectedDigest"],
            "actualPodImageId": deployment["actualPodImageId"],
            "finalDigest": deployment["finalDigest"],
            "health": deployment["healthEndpointResult"],
            "readiness": deployment["readinessEndpointResult"],
        }
    return {
        "policy.json": {
            **base,
            "executionProfile": plan["profile"],
            "policy": policy,
        },
        "artifacts.json": {
            **base,
            "artifact": artifact,
        },
        "commands.json": {
            **base,
            "redactionApplied": True,
            "commands": commands,
        },
        "deployment.json": {
            **base,
            "deploymentEvidence": deployment,
        },
        "attestation.json": {
            **base,
            "artifactDigest": (
                artifact["manifestDigest"] if artifact is not None else None
            ),
            "supplyChainEvidence": supply,
        },
        "smoke.json": {
            **base,
            **smoke,
        },
    }


def _summary(
    plan: Mapping[str, Any],
    verification: RuntimeVerification,
) -> str:
    digest = verification.authoritative_digest or "not produced"
    return "\n".join(
        (
            f"<!-- schemaVersion: {BUNDLE_SCHEMA_VERSION} -->",
            "# DevOps Stack Execution Evidence",
            "",
            f"- Run ID: `{verification.run_id}`",
            f"- Profile: `{verification.profile}`",
            f"- Environment: `{plan['environment']}`",
            f"- Build plan hash: `{verification.build_plan_hash}`",
            f"- Execution result: **{verification.final_status}**",
            f"- Incomplete: **{'yes' if verification.incomplete else 'no'}**",
            f"- Artifact digest: `{digest}`",
            "- Redaction applied: **yes**",
            "- Integrity: SHA-256 closed-file inventory",
            "- Authenticity: **not established** (the bundle is not signed)",
            "",
        )
    )


def _checksum_entries(store: EvidenceStore) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for path in store._material_files():
        relative = path.relative_to(store.root).as_posix()
        if relative == "checksums.json":
            continue
        entries.append({"path": relative, "sha256": sha256_file(path)})
    return entries


def _manifest_payload(entries: list[dict[str, str]]) -> bytes:
    return "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries).encode(
        "utf-8"
    )


def _checksums_record(
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    verification: RuntimeVerification,
    entries: list[dict[str, str]],
) -> dict[str, Any]:
    artifact = run["artifact"]
    return {
        "schemaVersion": BUNDLE_SCHEMA_VERSION,
        "algorithm": "sha256",
        "authenticity": AUTHENTICITY_STATUS,
        "identity": _identity(plan, run),
        "outcome": {
            "finalStatus": verification.final_status,
            "incomplete": verification.incomplete,
            "artifactDigest": (
                artifact["manifestDigest"] if artifact is not None else None
            ),
        },
        "files": entries,
        "manifestSha256": hashlib.sha256(_manifest_payload(entries)).hexdigest(),
    }


def _verify_required_paths(inventory: Mapping[str, str]) -> None:
    missing = sorted(REQUIRED_BUNDLE_FILES - set(inventory))
    if missing:
        raise EvidenceBundleError(
            "BUNDLE_REQUIRED_FILE_MISSING",
            "required evidence records are missing: " + ", ".join(missing),
        )


def _verify_log_redaction(store: EvidenceStore, inventory: Mapping[str, str]) -> None:
    for relative in sorted(path for path in inventory if path.startswith("logs/")):
        payload = _read_regular_file(
            store.path(relative), maximum=MAX_EVIDENCE_LOG_BYTES, label=relative
        )
        if hashlib.sha256(payload).hexdigest() != inventory[relative]:
            raise EvidenceBundleError(
                "BUNDLE_FILE_CHANGED",
                f"{relative} changed while it was being verified",
                evidence_path=relative,
            )
        try:
            content = payload.decode("utf-8")
        except UnicodeError as exc:
            raise EvidenceBundleError(
                "BUNDLE_LOG_INVALID",
                "evidence logs must be bounded UTF-8 text",
                evidence_path=relative,
            ) from exc
        if "\x00" in content or redact_sensitive(content) != content:
            raise EvidenceBundleError(
                "BUNDLE_SECRET_EXPOSURE",
                "evidence log contains unredacted sensitive data",
                evidence_path=relative,
            )


def _verify_declared_files(
    run: Mapping[str, Any], inventory: Mapping[str, str]
) -> set[str]:
    declared: dict[str, str | None] = {}

    def add(relative: str, digest: str | None) -> None:
        previous = declared.get(relative)
        if previous is not None and digest is not None and previous != digest:
            raise EvidenceBundleError(
                "BUNDLE_DECLARED_HASH_MISMATCH",
                f"runtime evidence records conflicting hashes for {relative}",
                evidence_path=relative,
            )
        if relative not in declared or digest is not None:
            declared[relative] = digest

    for stage in run["stageResults"]:
        for path in stage["evidencePaths"]:
            add(path, None)
    supply = run["supplyChainEvidence"]
    if supply is not None:
        add(supply["sbomPath"], supply["sbomHash"])
        add(
            supply["vulnerabilityReportPath"],
            supply["vulnerabilityReportHash"],
        )
        add(supply["provenancePath"], supply["provenanceHash"])
    deployment = run["deploymentEvidence"]
    if deployment is not None:
        for path in deployment["diagnosticsPaths"]:
            add(path, None)
    for relative, digest in sorted(declared.items()):
        try:
            normalized = normalize_relative_path(relative)
        except UnsafePathError as exc:
            raise EvidenceBundleError(
                "BUNDLE_DECLARED_PATH_INVALID",
                f"runtime evidence declares an unsafe path: {relative!r}",
            ) from exc
        actual = inventory.get(normalized)
        if actual is None:
            raise EvidenceBundleError(
                "BUNDLE_DECLARED_FILE_MISSING",
                f"runtime evidence declares a file absent from the bundle: {normalized}",
                evidence_path=normalized,
            )
        if digest is not None and actual != digest:
            raise EvidenceBundleError(
                "BUNDLE_DECLARED_HASH_MISMATCH",
                f"runtime evidence hash differs for {normalized}",
                evidence_path=normalized,
            )
    return {normalize_relative_path(relative) for relative in declared}


def _verify_allowed_paths(
    inventory: Mapping[str, str], declared_paths: set[str]
) -> None:
    exact = set(REQUIRED_BUNDLE_FILES) | declared_paths | {"resources.json"}
    unexpected = sorted(
        relative
        for relative in inventory
        if relative not in exact and not relative.startswith("logs/")
    )
    if unexpected:
        raise EvidenceBundleError(
            "BUNDLE_UNEXPECTED_FILE",
            "evidence bundle contains undeclared files: " + ", ".join(unexpected),
        )


def _verify_resource_record(
    store: EvidenceStore, inventory: Mapping[str, str]
) -> dict[str, Any] | None:
    relative = "resources.json"
    if relative not in inventory:
        return None
    value = _read_json(store, relative, inventory[relative])
    expected_fields = {
        "schemaVersion",
        "runId",
        "registry",
        "kind",
        "contentDigest",
    }
    if set(value) != expected_fields:
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            "resources.json fields do not match the recovery record contract",
            evidence_path=relative,
        )
    if (
        not isinstance(value["schemaVersion"], int)
        or isinstance(value["schemaVersion"], bool)
        or value["schemaVersion"] != 1
        or value["runId"] != store.run_id
    ):
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            "resources.json schema or run ID does not match this bundle",
            evidence_path=relative,
        )
    payload = {
        key: value[key] for key in ("schemaVersion", "runId", "registry", "kind")
    }
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if value["contentDigest"] != expected_digest:
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            "resources.json content digest does not match",
            evidence_path=relative,
        )
    _require_redacted(value, label=relative)
    # Import lazily because resource recovery calls back into the narrow sealed
    # update helper after cleanup. The pure validator performs the full ownership
    # contract checks without invoking Docker, kind, or any other side effect.
    from devops_stack_composer.resource_recovery import (
        ResourceRecordError,
        validate_resource_document,
    )

    try:
        validate_resource_document(value, store.run_id)
    except ResourceRecordError as exc:
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            str(exc),
            evidence_path=relative,
        ) from exc
    return value


def _write_seals(
    store: EvidenceStore,
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    verification: RuntimeVerification,
    *,
    overwrite: bool,
) -> None:
    entries = _checksum_entries(store)
    store.write_json(
        "checksums.json",
        _checksums_record(plan, run, verification, entries),
        overwrite=overwrite,
    )
    store.write_checksums(overwrite=overwrite)


def assemble_evidence_bundle(
    store: EvidenceStore,
    plan: Mapping[str, Any] | ExecutionPlan,
    run: Mapping[str, Any] | ExecutionRun,
) -> EvidenceBundleVerification:
    """Write the canonical records, seal them, and verify the resulting bundle.

    Runtime-specific raw evidence and bounded logs may already exist below the
    store. The canonical top-level records are reserved for this assembler.
    """

    if not isinstance(store, EvidenceStore):
        raise TypeError("store must be an EvidenceStore")
    plan_record = _as_record(plan)
    run_record = _as_record(run)
    _require_redacted(plan_record, label="plan.json")
    _require_redacted(run_record, label="run.json")
    verification = validate_runtime_records(plan_record, run_record)
    if verification.run_id != store.run_id:
        raise EvidenceBundleError(
            "BUNDLE_RUN_ID_MISMATCH",
            "execution run ID does not match its evidence directory",
        )
    state_path = store.path("state.json")
    if not state_path.is_file() or state_path.is_symlink():
        raise EvidenceBundleError(
            "BUNDLE_STATE_REQUIRED",
            "a regular terminal state.json is required before bundle assembly",
            evidence_path="state.json",
        )
    state_record = _read_json(store, "state.json", sha256_file(state_path))
    _require_redacted(state_record, label="state.json")
    _verify_state_record(state_record, plan_record, run_record, verification)
    derived = _derived_records(plan_record, run_record, verification)
    plan_path = store.path("plan.json")
    if plan_path.exists():
        existing_plan = _read_json(store, "plan.json", sha256_file(plan_path))
        if existing_plan != plan_record:
            raise EvidenceBundleError(
                "BUNDLE_RECORD_CONFLICT",
                "pre-execution plan.json differs from the finalized plan",
                evidence_path="plan.json",
            )
    policy_path = store.path("policy.json")
    if policy_path.exists():
        existing_policy = _read_json(
            store, "policy.json", sha256_file(policy_path)
        )
        allowed_policy_values = (
            profile_policy(str(plan_record["profile"])).to_dict(),
            derived["policy.json"],
        )
        if existing_policy not in allowed_policy_values:
            raise EvidenceBundleError(
                "BUNDLE_RECORD_CONFLICT",
                "pre-execution policy.json differs from the selected profile policy",
                evidence_path="policy.json",
            )
    conflicts = sorted(
        relative for relative in _ASSEMBLER_FILES if store.path(relative).exists()
    )
    if conflicts:
        raise EvidenceBundleError(
            "BUNDLE_RECORD_CONFLICT",
            "canonical evidence records already exist: " + ", ".join(conflicts),
        )

    # Validate any pre-existing logs before they become part of the sealed bundle.
    existing = {
        path.relative_to(store.root).as_posix(): sha256_file(path)
        for path in store._material_files()
    }
    _verify_log_redaction(store, existing)

    store.write_json("run.json", run_record)
    if not plan_path.exists():
        store.write_json("plan.json", plan_record)
    for relative, value in derived.items():
        store.write_json(
            relative,
            value,
            overwrite=relative == "policy.json" and policy_path.exists(),
        )
    store.write_text("summary.md", _summary(plan_record, verification))

    _write_seals(store, plan_record, run_record, verification, overwrite=False)
    return verify_evidence_bundle(store)


def verify_evidence_bundle(store: EvidenceStore) -> EvidenceBundleVerification:
    """Verify closed-file integrity and all offline semantic cross-links."""

    if not isinstance(store, EvidenceStore):
        raise TypeError("store must be an EvidenceStore")
    try:
        inventory = store.verify_checksums()
    except EvidenceStoreError as exc:
        raise EvidenceBundleError("BUNDLE_INTEGRITY_INVALID", str(exc)) from exc
    _verify_required_paths(inventory)
    records = {
        relative: _read_json(store, relative, inventory[relative])
        for relative in _JSON_FILES
    }
    plan = records["plan.json"]
    run = records["run.json"]
    state = records["state.json"]
    _require_redacted(plan, label="plan.json")
    _require_redacted(run, label="run.json")
    _require_redacted(state, label="state.json")
    verification = validate_runtime_records(plan, run)
    if verification.run_id != store.run_id:
        raise EvidenceBundleError(
            "BUNDLE_RUN_ID_MISMATCH",
            "verified run ID does not match its evidence directory",
        )
    _verify_state_record(state, plan, run, verification)

    derived = _derived_records(plan, run, verification)
    for relative, expected in derived.items():
        if records[relative] != expected:
            raise EvidenceBundleError(
                "BUNDLE_CROSS_RECORD_MISMATCH",
                f"{relative} does not match the verified plan and run",
                evidence_path=relative,
            )

    checksum_record = records["checksums.json"]
    entries = [
        {"path": relative, "sha256": digest}
        for relative, digest in sorted(inventory.items())
        if relative != "checksums.json"
    ]
    expected_checksums = _checksums_record(plan, run, verification, entries)
    if checksum_record != expected_checksums:
        raise EvidenceBundleError(
            "BUNDLE_MANIFEST_MISMATCH",
            "checksums.json does not match the closed SHA256SUMS inventory",
            evidence_path="checksums.json",
        )

    summary_payload = _read_regular_file(
        store.path("summary.md"),
        maximum=MAX_BUNDLE_JSON_BYTES,
        label="summary.md",
    )
    if hashlib.sha256(summary_payload).hexdigest() != inventory["summary.md"]:
        raise EvidenceBundleError(
            "BUNDLE_FILE_CHANGED",
            "summary.md changed while it was being verified",
            evidence_path="summary.md",
        )
    if summary_payload != _summary(plan, verification).encode("utf-8"):
        raise EvidenceBundleError(
            "BUNDLE_CROSS_RECORD_MISMATCH",
            "summary.md does not match the verified execution outcome",
            evidence_path="summary.md",
        )

    _verify_resource_record(store, inventory)
    declared_paths = _verify_declared_files(run, inventory)
    _verify_allowed_paths(inventory, declared_paths)
    _verify_log_redaction(store, inventory)
    try:
        final_inventory = store.verify_checksums()
    except EvidenceStoreError as exc:
        raise EvidenceBundleError("BUNDLE_INTEGRITY_INVALID", str(exc)) from exc
    if final_inventory != inventory:
        raise EvidenceBundleError(
            "BUNDLE_FILE_CHANGED", "evidence inventory changed during verification"
        )

    artifact = run["artifact"]
    return EvidenceBundleVerification(
        run_id=verification.run_id,
        profile=verification.profile,
        build_plan_hash=verification.build_plan_hash,
        final_status=verification.final_status,
        incomplete=verification.incomplete,
        artifact_digest=(artifact["manifestDigest"] if artifact is not None else None),
        material_file_count=len(inventory),
    )


def update_sealed_resource_record(
    store: EvidenceStore, value: Mapping[str, Any]
) -> EvidenceBundleVerification:
    """Replace only ``resources.json`` in an already valid sealed bundle.

    This is intentionally not a general reseal API: permitting arbitrary files
    to be rewritten would let callers turn tampering into a new internally
    consistent manifest. Resource cleanup is the one expected post-run mutation.
    """

    if not isinstance(store, EvidenceStore):
        raise TypeError("store must be an EvidenceStore")
    if not isinstance(value, Mapping):
        raise TypeError("resource record must be a mapping")
    verify_evidence_bundle(store)
    inventory = store.verify_checksums()
    if "resources.json" not in inventory:
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_MISSING",
            "cannot add resources.json after the bundle has been sealed",
            evidence_path="resources.json",
        )
    plan = _read_json(store, "plan.json", inventory["plan.json"])
    run = _read_json(store, "run.json", inventory["run.json"])
    verification = validate_runtime_records(plan, run)
    try:
        payload = json.dumps(
            dict(value), sort_keys=True, allow_nan=False, ensure_ascii=False
        )
        candidate = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            "resources.json must contain finite JSON values",
            evidence_path="resources.json",
        ) from exc
    if not isinstance(candidate, dict):  # pragma: no cover - Mapping encodes as object
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_RECORD_INVALID",
            "resources.json must contain one JSON object",
            evidence_path="resources.json",
        )
    _require_redacted(candidate, label="resources.json")

    record_path = store.path("resources.json")
    previous = _read_regular_file(
        record_path, maximum=MAX_BUNDLE_JSON_BYTES, label="resources.json"
    )
    try:
        store.write_json("resources.json", candidate, overwrite=True)
        # The previous manifest is now expected to fail only because the
        # authorized record changed; regenerate both coupled manifests at once.
        _write_seals(store, plan, run, verification, overwrite=True)
        return verify_evidence_bundle(store)
    except Exception as exc:
        try:
            store.write_text(
                "resources.json", previous.decode("utf-8"), overwrite=True
            )
            _write_seals(store, plan, run, verification, overwrite=True)
        except Exception:
            pass
        if isinstance(exc, EvidenceBundleError):
            raise
        raise EvidenceBundleError(
            "BUNDLE_RESOURCE_UPDATE_FAILED",
            "could not update and reseal resources.json",
            evidence_path="resources.json",
        ) from exc


__all__ = [
    "AUTHENTICITY_STATUS",
    "BUNDLE_SCHEMA_VERSION",
    "EvidenceBundleError",
    "EvidenceBundleVerification",
    "MAX_BUNDLE_JSON_BYTES",
    "MAX_EVIDENCE_LOG_BYTES",
    "REQUIRED_BUNDLE_FILES",
    "assemble_evidence_bundle",
    "update_sealed_resource_record",
    "verify_evidence_bundle",
]
