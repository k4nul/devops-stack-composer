"""Durable, fail-closed cleanup of run-owned local execution resources."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Sequence

from devops_stack_composer.evidence_store import EvidenceStore, EvidenceStoreError
from devops_stack_composer.errors import DevOpsStackError, UnsafePathError
from devops_stack_composer.kind_cluster import (
    KIND_CLUSTER_LABEL,
    KIND_NODE_IMAGE,
    KIND_ROLE_LABEL,
    KindClusterRecoveryIdentity,
)
from devops_stack_composer.registry import (
    CONTAINER_NAME_LABEL,
    MANAGED_BY_LABEL,
    REGISTRY_CONTAINER_PORT,
    REGISTRY_HOST,
    REGISTRY_IMAGE,
    RESOURCE_LABEL,
    RUN_ID_LABEL,
    RegistryHandle,
)


RESOURCE_RECORD = "resources.json"
RESOURCE_RECORD_VERSION = 1

_ACTIVE = "active"
_REMOVED = "removed"
_STATUSES = {_ACTIVE, _REMOVED}
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_MAX_RECORD_BYTES = 64 * 1024
_URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_AUTHORIZATION = re.compile(r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*")
_INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key)"
    r"\b[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_SECRET_FLAG = re.compile(
    r"(?ix)(--(?:password|passphrase|token|secret|private-key|access-key|api-key)"
    r"(?:\s+|=))(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class ResourceRecoveryError(DevOpsStackError):
    """Raised when durable resource recovery cannot proceed safely."""


class ResourceRecordError(ResourceRecoveryError):
    """Raised when a durable resource record is missing, unsafe, or tampered."""


class ResourceOwnershipError(ResourceRecoveryError):
    """Raised before cleanup could affect a resource with mismatched ownership."""


@dataclass(frozen=True)
class RegistryResource:
    status: str
    name: str
    container_id: str
    host: str
    host_port: int
    container_port: int
    image: str
    local_test_only: bool
    labels: Mapping[str, str]


@dataclass(frozen=True)
class KindNodeResource:
    name: str
    container_id: str
    role: str


@dataclass(frozen=True)
class KindResource:
    status: str
    name: str
    context: str
    node_image: str
    nodes: tuple[KindNodeResource, ...]


@dataclass(frozen=True)
class RunResources:
    run_id: str
    registry: RegistryResource | None = None
    kind: KindResource | None = None

    @property
    def cleaned(self) -> bool:
        return all(
            resource is None or resource.status == _REMOVED
            for resource in (self.kind, self.registry)
        )


@dataclass(frozen=True)
class CleanupResult:
    run_id: str
    kind_removed: bool
    registry_removed: bool
    complete: bool


def _sanitize(value: object, *, limit: int = 2000) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        text = ""
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _AUTHORIZATION.sub(r"\1<redacted>", text)
    text = _INLINE_SECRET.sub(r"\1<redacted>", text)
    text = _SECRET_FLAG.sub(r"\1<redacted>", text)
    return text.strip()[-limit:]


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _content_digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ResourceRecordError(f"resource record contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ResourceRecordError(f"resource record contains non-finite number {value}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], subject: str) -> None:
    observed = set(value)
    if observed != expected:
        raise ResourceRecordError(
            f"{subject} fields do not match the v{RESOURCE_RECORD_VERSION} contract; "
            f"missing={sorted(expected - observed)}; unexpected={sorted(observed - expected)}"
        )


def _required_text(value: object, subject: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ResourceRecordError(f"{subject} must be non-empty text")
    return value


def _expected_registry_name(run_id: str) -> re.Pattern[str]:
    slug = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    slug = slug[:20].rstrip("-") or "run"
    return re.compile(rf"^devops-stack-registry-{re.escape(slug)}-[a-f0-9]{{12}}$")


def _expected_kind_name(run_id: str) -> re.Pattern[str]:
    slug = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    slug = slug[:10].rstrip("-") or "run"
    return re.compile(rf"^dsc-kind-{re.escape(slug)}-[a-f0-9]{{12}}$")


def _expected_registry_labels(run_id: str, name: str) -> dict[str, str]:
    return {
        MANAGED_BY_LABEL: "devops-stack-composer",
        RESOURCE_LABEL: "ephemeral-registry",
        RUN_ID_LABEL: run_id,
        CONTAINER_NAME_LABEL: name,
    }


def _registry_to_json(resource: RegistryResource) -> dict[str, Any]:
    return {
        "status": resource.status,
        "name": resource.name,
        "containerId": resource.container_id,
        "host": resource.host,
        "hostPort": resource.host_port,
        "containerPort": resource.container_port,
        "image": resource.image,
        "localTestOnly": resource.local_test_only,
        "labels": dict(resource.labels),
    }


def _node_to_json(resource: KindNodeResource) -> dict[str, Any]:
    return {
        "name": resource.name,
        "containerId": resource.container_id,
        "role": resource.role,
    }


def _kind_to_json(resource: KindResource) -> dict[str, Any]:
    return {
        "status": resource.status,
        "name": resource.name,
        "context": resource.context,
        "nodeImage": resource.node_image,
        "nodes": [_node_to_json(node) for node in resource.nodes],
    }


def _payload(resources: RunResources) -> dict[str, Any]:
    return {
        "schemaVersion": RESOURCE_RECORD_VERSION,
        "runId": resources.run_id,
        "registry": (
            _registry_to_json(resources.registry) if resources.registry is not None else None
        ),
        "kind": _kind_to_json(resources.kind) if resources.kind is not None else None,
    }


def _document(resources: RunResources) -> dict[str, Any]:
    payload = _payload(resources)
    return {**payload, "contentDigest": _content_digest(payload)}


def _parse_registry(value: object, run_id: str) -> RegistryResource | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ResourceRecordError("registry resource must be an object or null")
    _exact_keys(
        value,
        {
            "status",
            "name",
            "containerId",
            "host",
            "hostPort",
            "containerPort",
            "image",
            "localTestOnly",
            "labels",
        },
        "registry resource",
    )
    status = _required_text(value["status"], "registry status")
    name = _required_text(value["name"], "registry name")
    container_id = _required_text(value["containerId"], "registry container ID")
    host = _required_text(value["host"], "registry host")
    image = _required_text(value["image"], "registry image")
    local_test_only = value["localTestOnly"]
    host_port = value["hostPort"]
    container_port = value["containerPort"]
    labels = value["labels"]
    if status not in _STATUSES:
        raise ResourceRecordError("registry status is invalid")
    if not _expected_registry_name(run_id).fullmatch(name):
        raise ResourceRecordError("registry name does not belong to this run")
    if not _CONTAINER_ID.fullmatch(container_id):
        raise ResourceRecordError("registry container ID is invalid")
    if host != REGISTRY_HOST:
        raise ResourceRecordError("registry host is not loopback")
    if (
        not isinstance(host_port, int)
        or isinstance(host_port, bool)
        or host_port < 1
        or host_port > 65535
    ):
        raise ResourceRecordError("registry host port is invalid")
    if (
        not isinstance(container_port, int)
        or isinstance(container_port, bool)
        or container_port != REGISTRY_CONTAINER_PORT
    ):
        raise ResourceRecordError("registry container port is invalid")
    if image != REGISTRY_IMAGE:
        raise ResourceRecordError("registry image does not match the pinned image")
    if local_test_only is not True:
        raise ResourceRecordError("registry resource is not restricted to local test use")
    expected_labels = _expected_registry_labels(run_id, name)
    if labels != expected_labels:
        raise ResourceRecordError("registry ownership labels do not belong to this run")
    return RegistryResource(
        status,
        name,
        container_id,
        host,
        host_port,
        container_port,
        image,
        True,
        expected_labels,
    )


def _parse_kind(value: object, run_id: str) -> KindResource | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ResourceRecordError("kind resource must be an object or null")
    _exact_keys(value, {"status", "name", "context", "nodeImage", "nodes"}, "kind resource")
    status = _required_text(value["status"], "kind status")
    name = _required_text(value["name"], "kind cluster name")
    context = _required_text(value["context"], "kind context")
    node_image = _required_text(value["nodeImage"], "kind node image")
    raw_nodes = value["nodes"]
    if status not in _STATUSES:
        raise ResourceRecordError("kind status is invalid")
    if not _expected_kind_name(run_id).fullmatch(name):
        raise ResourceRecordError("kind cluster name does not belong to this run")
    if context != f"kind-{name}":
        raise ResourceRecordError("kind context does not match the cluster name")
    if node_image != KIND_NODE_IMAGE:
        raise ResourceRecordError("kind node image does not match the pinned image")
    if not isinstance(raw_nodes, list) or len(raw_nodes) != 1:
        raise ResourceRecordError("v0.2 recovery requires exactly one kind node")
    nodes: list[KindNodeResource] = []
    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict):
            raise ResourceRecordError("kind node identity must be an object")
        _exact_keys(raw_node, {"name", "containerId", "role"}, "kind node identity")
        node_name = _required_text(raw_node["name"], "kind node name")
        container_id = _required_text(raw_node["containerId"], "kind node container ID")
        role = _required_text(raw_node["role"], "kind node role")
        if node_name != f"{name}-control-plane" or not _DNS_LABEL.fullmatch(node_name):
            raise ResourceRecordError("kind node name does not match the cluster")
        if not _CONTAINER_ID.fullmatch(container_id):
            raise ResourceRecordError("kind node container ID is invalid")
        if role != "control-plane":
            raise ResourceRecordError("kind node role is invalid")
        nodes.append(KindNodeResource(node_name, container_id, role))
    return KindResource(status, name, context, node_image, tuple(nodes))


def _parse_document(text: str, expected_run_id: str) -> RunResources:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except ResourceRecordError:
        raise
    except (TypeError, json.JSONDecodeError) as exc:
        raise ResourceRecordError("resource record is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ResourceRecordError("resource record must be an object")
    _exact_keys(
        value,
        {"schemaVersion", "runId", "registry", "kind", "contentDigest"},
        "resource record",
    )
    if (
        not isinstance(value["schemaVersion"], int)
        or isinstance(value["schemaVersion"], bool)
        or value["schemaVersion"] != RESOURCE_RECORD_VERSION
    ):
        raise ResourceRecordError("unsupported resource record schema version")
    run_id = _required_text(value["runId"], "resource record run ID")
    if run_id != expected_run_id:
        raise ResourceRecordError("resource record run ID does not match its evidence run")
    digest = _required_text(value["contentDigest"], "resource record content digest")
    payload = {key: value[key] for key in ("schemaVersion", "runId", "registry", "kind")}
    if not _DIGEST.fullmatch(digest) or digest != _content_digest(payload):
        raise ResourceRecordError("resource record content digest does not match")
    registry = _parse_registry(value["registry"], run_id)
    kind = _parse_kind(value["kind"], run_id)
    if (
        registry is not None
        and kind is not None
        and registry.container_id in {node.container_id for node in kind.nodes}
    ):
        raise ResourceRecordError("resource record mixes registry and kind identities")
    return RunResources(run_id, registry, kind)


def validate_resource_document(
    value: Mapping[str, Any], expected_run_id: str
) -> RunResources:
    """Validate one already-decoded recovery document with the full contract."""

    if not isinstance(value, Mapping):
        raise ResourceRecordError("resource record must be an object")
    try:
        rendered = json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ResourceRecordError(
            "resource record must contain finite JSON values"
        ) from exc
    return _parse_document(rendered, expected_run_id)


def _read_regular(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ResourceRecordError("resource record is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ResourceRecordError("resource record is not a regular file")
        if metadata.st_size > _MAX_RECORD_BYTES:
            raise ResourceRecordError("resource record exceeds the 64 KiB limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(_MAX_RECORD_BYTES + 1)
        if len(payload) > _MAX_RECORD_BYTES:
            raise ResourceRecordError("resource record exceeds the 64 KiB limit")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResourceRecordError("resource record is not UTF-8") from exc
    finally:
        os.close(descriptor)


class ResourceRecoveryStore:
    """Persist identities and clean them after an execution-process restart."""

    def __init__(self, evidence: EvidenceStore) -> None:
        if not isinstance(evidence, EvidenceStore):
            raise TypeError("evidence must be an EvidenceStore")
        self.evidence = evidence

    def load(self) -> RunResources:
        resources, _checksummed, _raw = self._load(required=True)
        return resources

    def record_registry(self, handle: RegistryHandle) -> RunResources:
        if not isinstance(handle, RegistryHandle):
            raise TypeError("handle must be a RegistryHandle")
        if handle.run_id != self.evidence.run_id:
            raise ResourceRecordError("registry handle belongs to a different run")
        resource = RegistryResource(
            _ACTIVE,
            handle.name,
            handle.container_id,
            handle.host,
            handle.host_port,
            REGISTRY_CONTAINER_PORT,
            handle.image,
            handle.local_test_only,
            _expected_registry_labels(handle.run_id, handle.name),
        )
        resources, checksummed, raw = self._load(required=False)
        candidate = replace(resources, registry=resource)
        self._validate_capture(resources.registry, resource, "registry")
        self._save(candidate, checksummed=checksummed, previous=raw)
        return candidate

    def record_kind(self, identity: KindClusterRecoveryIdentity) -> RunResources:
        if not isinstance(identity, KindClusterRecoveryIdentity):
            raise TypeError("identity must be a KindClusterRecoveryIdentity")
        if identity.run_id != self.evidence.run_id:
            raise ResourceRecordError("kind identity belongs to a different run")
        resource = KindResource(
            _ACTIVE,
            identity.name,
            identity.context,
            identity.node_image,
            tuple(
                KindNodeResource(node.name, node.container_id, node.role)
                for node in identity.nodes
            ),
        )
        resources, checksummed, raw = self._load(required=False)
        candidate = replace(resources, kind=resource)
        self._validate_capture(resources.kind, resource, "kind")
        self._save(candidate, checksummed=checksummed, previous=raw)
        return candidate

    def cleanup(
        self,
        *,
        command_runner: CommandRunner | None = None,
        command_timeout_seconds: float = 60.0,
    ) -> CleanupResult:
        if (
            not isinstance(command_timeout_seconds, (int, float))
            or isinstance(command_timeout_seconds, bool)
            or not math.isfinite(command_timeout_seconds)
            or command_timeout_seconds <= 0
        ):
            raise ValueError("command_timeout_seconds must be a positive finite number")
        runner = command_runner or subprocess.run
        resources, checksummed, raw = self._load(required=True)
        kind_removed = False
        registry_removed = False

        if resources.kind is not None and resources.kind.status == _ACTIVE:
            kind_removed = self._cleanup_kind(
                resources.kind,
                runner,
                float(command_timeout_seconds),
            )
            updated = replace(resources, kind=replace(resources.kind, status=_REMOVED))
            self._save(updated, checksummed=checksummed, previous=raw)
            resources = updated
            raw = self._read_record_text()

        if resources.registry is not None and resources.registry.status == _ACTIVE:
            registry_removed = self._cleanup_registry(
                resources.registry,
                runner,
                float(command_timeout_seconds),
            )
            updated = replace(
                resources,
                registry=replace(resources.registry, status=_REMOVED),
            )
            self._save(updated, checksummed=checksummed, previous=raw)
            resources = updated

        return CleanupResult(
            resources.run_id,
            kind_removed,
            registry_removed,
            resources.cleaned,
        )

    @staticmethod
    def _validate_capture(
        current: RegistryResource | KindResource | None,
        candidate: RegistryResource | KindResource,
        subject: str,
    ) -> None:
        if current is None or current == candidate:
            return
        raise ResourceRecordError(
            f"refusing to replace the persisted {subject} identity for this run"
        )

    def _load(self, *, required: bool) -> tuple[RunResources, bool, str | None]:
        try:
            checksum_path = self.evidence.path("SHA256SUMS")
            checksummed = checksum_path.exists()
            if checksummed:
                self.evidence.verify_checksums()
                if self.evidence.path("checksums.json").exists():
                    # A final evidence bundle has coupled semantic manifests in
                    # addition to SHA256SUMS. Validate those before any cleanup.
                    from devops_stack_composer.evidence_bundle import (
                        verify_evidence_bundle,
                    )

                    verify_evidence_bundle(self.evidence)
            record_path = self.evidence.path(RESOURCE_RECORD)
        except (EvidenceStoreError, UnsafePathError) as exc:
            raise ResourceRecordError(
                f"resource evidence is unsafe: {_sanitize(str(exc))}"
            ) from exc
        if not record_path.exists():
            if required:
                raise ResourceRecordError("execution run has no resource record")
            if checksummed:
                raise ResourceRecordError(
                    "cannot add a resource record after the evidence inventory was sealed"
                )
            return RunResources(self.evidence.run_id), False, None
        try:
            raw = _read_regular(record_path)
        except (ResourceRecordError, UnsafePathError):
            raise
        return _parse_document(raw, self.evidence.run_id), checksummed, raw

    def _read_record_text(self) -> str:
        try:
            return _read_regular(self.evidence.path(RESOURCE_RECORD))
        except UnsafePathError as exc:
            raise ResourceRecordError("resource record path is unsafe") from exc

    def _save(
        self,
        resources: RunResources,
        *,
        checksummed: bool,
        previous: str | None,
    ) -> None:
        # Parsing the exact document before writing keeps capture-time validation
        # and recovery-time validation on the same strict contract.
        document = _document(resources)
        rendered = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        _parse_document(rendered, self.evidence.run_id)
        if checksummed and self.evidence.path("checksums.json").exists():
            try:
                from devops_stack_composer.evidence_bundle import (
                    update_sealed_resource_record,
                )

                update_sealed_resource_record(self.evidence, document)
                return
            except Exception as exc:
                raise ResourceRecordError(
                    f"could not update sealed resource recovery state: {_sanitize(str(exc))}"
                ) from exc
        try:
            self.evidence.write_text(
                RESOURCE_RECORD,
                rendered,
                overwrite=previous is not None,
            )
            if checksummed:
                self.evidence.write_checksums(overwrite=True)
        except Exception as exc:
            if checksummed and previous is not None:
                try:
                    self.evidence.write_text(RESOURCE_RECORD, previous, overwrite=True)
                except Exception:
                    pass
            raise ResourceRecordError(
                f"could not persist resource recovery state: {_sanitize(str(exc))}"
            ) from exc

    def _cleanup_kind(
        self,
        resource: KindResource,
        runner: CommandRunner,
        timeout: float,
    ) -> bool:
        clusters = self._kind_clusters(runner, timeout)
        if resource.name not in clusters:
            remaining = [
                node.name
                for node in resource.nodes
                if self._inspect_container(
                    node.container_id,
                    runner,
                    timeout,
                    allow_missing=True,
                    subject="kind node",
                )
                is not None
            ]
            if remaining:
                raise ResourceOwnershipError(
                    "kind cluster inventory is absent but recorded node containers remain: "
                    + ", ".join(remaining)
                )
            return False

        result = self._run(
            runner,
            ["kind", "get", "nodes", "--name", resource.name],
            timeout,
            "list recorded kind nodes",
        )
        self._require_success(result, "list recorded kind nodes")
        names = tuple(
            sorted(
                line.strip()
                for line in _text(result.stdout).splitlines()
                if line.strip()
            )
        )
        expected_names = tuple(sorted(node.name for node in resource.nodes))
        if names != expected_names:
            raise ResourceOwnershipError("kind node inventory does not match the recovery record")
        for node in resource.nodes:
            inspected = self._inspect_container(
                node.container_id,
                runner,
                timeout,
                allow_missing=False,
                subject="kind node",
            )
            assert inspected is not None
            self._verify_kind_node(resource, node, inspected)

        result = self._run(
            runner,
            ["kind", "delete", "cluster", "--name", resource.name],
            timeout,
            "delete recorded kind cluster",
        )
        self._require_success(result, "delete recorded kind cluster")
        if resource.name in self._kind_clusters(runner, timeout):
            raise ResourceRecoveryError(
                "kind still reports the cluster after the delete command"
            )
        remaining = [
            node.name
            for node in resource.nodes
            if self._inspect_container(
                node.container_id,
                runner,
                timeout,
                allow_missing=True,
                subject="kind node",
            )
            is not None
        ]
        if remaining:
            raise ResourceRecoveryError(
                "kind node containers remain after the delete command: " + ", ".join(remaining)
            )
        return True

    def _cleanup_registry(
        self,
        resource: RegistryResource,
        runner: CommandRunner,
        timeout: float,
    ) -> bool:
        inspected = self._inspect_container(
            resource.name,
            runner,
            timeout,
            allow_missing=True,
            subject="registry",
        )
        if inspected is None:
            by_id = self._inspect_container(
                resource.container_id,
                runner,
                timeout,
                allow_missing=True,
                subject="registry",
            )
            if by_id is not None:
                raise ResourceOwnershipError(
                    "registry immutable ID still exists under an unexpected name"
                )
            return False
        self._verify_registry(resource, inspected)
        result = self._run(
            runner,
            ["docker", "rm", "--force", "--volumes", resource.container_id],
            timeout,
            "remove recorded registry",
        )
        self._require_success(result, "remove recorded registry")
        for target in (resource.name, resource.container_id):
            if self._inspect_container(
                target,
                runner,
                timeout,
                allow_missing=True,
                subject="registry",
            ) is not None:
                raise ResourceRecoveryError(
                    "registry still exists after the remove command"
                )
        return True

    def _kind_clusters(self, runner: CommandRunner, timeout: float) -> set[str]:
        result = self._run(
            runner,
            ["kind", "get", "clusters"],
            timeout,
            "list kind clusters",
        )
        self._require_success(result, "list kind clusters")
        lines = [line.strip() for line in _text(result.stdout).splitlines() if line.strip()]
        if lines == ["No kind clusters found."]:
            return set()
        if len(lines) != len(set(lines)) or any(
            not _DNS_LABEL.fullmatch(line) for line in lines
        ):
            raise ResourceRecoveryError("kind returned a malformed cluster inventory")
        return set(lines)

    def _inspect_container(
        self,
        target: str,
        runner: CommandRunner,
        timeout: float,
        *,
        allow_missing: bool,
        subject: str,
    ) -> Mapping[str, Any] | None:
        result = self._run(
            runner,
            ["docker", "inspect", target],
            timeout,
            f"inspect recorded {subject}",
        )
        if result.returncode != 0:
            detail = f"{_text(result.stderr)}\n{_text(result.stdout)}".lower()
            missing = any(
                marker in detail
                for marker in ("no such object", "no such container", "not found")
            )
            if missing:
                if allow_missing:
                    return None
                raise ResourceOwnershipError(
                    f"recorded {subject} immutable identity no longer exists"
                )
            self._require_success(result, f"inspect recorded {subject}")
        try:
            value = json.loads(_text(result.stdout), object_pairs_hook=_strict_object)
        except (ResourceRecordError, json.JSONDecodeError) as exc:
            raise ResourceRecoveryError(
                f"Docker returned malformed {subject} inspection data"
            ) from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise ResourceRecoveryError(
                f"Docker returned unexpected {subject} inspection data"
            )
        return value[0]

    @staticmethod
    def _verify_kind_node(
        cluster: KindResource,
        node: KindNodeResource,
        inspected: Mapping[str, Any],
    ) -> None:
        config = inspected.get("Config")
        config = config if isinstance(config, dict) else {}
        labels = config.get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        if inspected.get("Id") != node.container_id or inspected.get("Name") != f"/{node.name}":
            raise ResourceOwnershipError("kind node immutable identity or name changed")
        if (
            labels.get(KIND_CLUSTER_LABEL) != cluster.name
            or labels.get(KIND_ROLE_LABEL) != node.role
        ):
            raise ResourceOwnershipError("kind node ownership labels do not match")
        if config.get("Image") != cluster.node_image:
            raise ResourceOwnershipError("kind node image does not match the recovery record")

    @staticmethod
    def _verify_registry(
        resource: RegistryResource,
        inspected: Mapping[str, Any],
    ) -> None:
        config = inspected.get("Config")
        config = config if isinstance(config, dict) else {}
        labels = config.get("Labels")
        if (
            inspected.get("Id") != resource.container_id
            or inspected.get("Name") != f"/{resource.name}"
        ):
            raise ResourceOwnershipError("registry immutable identity or name changed")
        if not isinstance(labels, dict) or any(
            labels.get(key) != value for key, value in resource.labels.items()
        ):
            raise ResourceOwnershipError("registry ownership labels do not match")
        if config.get("Image") != resource.image:
            raise ResourceOwnershipError("registry image does not match the recovery record")
        network = inspected.get("NetworkSettings")
        network = network if isinstance(network, dict) else {}
        ports = network.get("Ports")
        ports = ports if isinstance(ports, dict) else {}
        bindings = ports.get(f"{resource.container_port}/tcp")
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], dict)
            or bindings[0].get("HostIp") != resource.host
            or bindings[0].get("HostPort") != str(resource.host_port)
        ):
            raise ResourceOwnershipError("registry loopback port binding changed")

    @staticmethod
    def _run(
        runner: CommandRunner,
        command: Sequence[str],
        timeout: float,
        operation: str,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        try:
            return runner(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise ResourceRecoveryError(f"{argv[0]} CLI is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            detail = _sanitize(exc.stderr or exc.stdout)
            suffix = f": {detail}" if detail else ""
            raise ResourceRecoveryError(f"{operation} timed out{suffix}") from exc
        except OSError as exc:
            raise ResourceRecoveryError(
                f"{operation} could not run: {_sanitize(str(exc))}"
            ) from exc

    @staticmethod
    def _require_success(
        result: subprocess.CompletedProcess[str],
        operation: str,
    ) -> None:
        if result.returncode == 0:
            return
        detail = _sanitize(result.stderr or result.stdout)
        suffix = f": {detail}" if detail else ""
        raise ResourceRecoveryError(
            f"could not {operation} (exit {result.returncode}){suffix}"
        )


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


__all__ = [
    "CleanupResult",
    "KindNodeResource",
    "KindResource",
    "RESOURCE_RECORD",
    "RESOURCE_RECORD_VERSION",
    "RegistryResource",
    "ResourceOwnershipError",
    "ResourceRecordError",
    "ResourceRecoveryError",
    "ResourceRecoveryStore",
    "RunResources",
    "validate_resource_document",
]
