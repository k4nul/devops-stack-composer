"""Owned, loopback-only kind cluster lifecycle for local execution."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from devops_stack_composer.errors import DevOpsStackError
from devops_stack_composer.registry import (
    REGISTRY_CONTAINER_PORT,
    REGISTRY_HOST,
    EphemeralRegistry,
    RegistryHandle,
)


KIND_VERSION = "v0.33.0"
KIND_NODE_IMAGE = (
    "kindest/node:v1.36.4@"
    "sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
)
KIND_NETWORK_NAME = "kind"
KIND_CLUSTER_LABEL = "io.x-k8s.kind.cluster"
KIND_ROLE_LABEL = "io.x-k8s.kind.role"
API_SERVER_ADDRESS = "127.0.0.1"
LOCAL_REGISTRY_CONFIGMAP = "local-registry-hosting"
LOCAL_REGISTRY_NAMESPACE = "kube-public"
LOCAL_REGISTRY_HELP = "https://kind.sigs.k8s.io/docs/user/local-registry/"

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_KIND_VERSION_LINE = re.compile(r"^kind v0\.33\.0(?:\s+.*)?$")
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


class KindClusterError(DevOpsStackError):
    """Raised when an ephemeral kind cluster cannot be managed safely."""


class KindVersionError(KindClusterError):
    """Raised when the installed kind CLI is not the pinned version."""


class KindClusterCollisionError(KindClusterError):
    """Raised when a generated cluster name is already in use."""


class KindClusterOwnershipError(KindClusterError):
    """Raised before an operation could affect nodes not owned by this run."""


@dataclass(frozen=True)
class KindClusterHandle:
    """Serializable-safe identity for one run-owned cluster.

    The private kubeconfig path intentionally remains lifecycle runtime state on
    :class:`KindCluster`, rather than becoming part of this handle.
    """

    run_id: str
    name: str
    context: str
    node_image: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class KindClusterStatus:
    """Current owned-cluster state with bounded, sanitized diagnostics."""

    name: str
    exists: bool
    owned: bool
    ready: bool = False
    nodes: tuple[str, ...] = ()
    error: str = ""
    diagnostics: str = ""


@dataclass(frozen=True)
class LocalRegistryConfiguration:
    """Non-secret result of configuring a run-owned registry for kind."""

    host_endpoint: str
    container_endpoint: str
    nodes: tuple[str, ...]


@dataclass(frozen=True)
class _NodeIdentity:
    name: str
    container_id: str
    role: str


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _sanitize_output(value: object, *, limit: int = 8000) -> str:
    sanitized = _URL_USERINFO.sub(r"\1<redacted>@", _text(value))
    sanitized = _AUTHORIZATION.sub(r"\1<redacted>", sanitized)
    sanitized = _INLINE_SECRET.sub(r"\1<redacted>", sanitized)
    sanitized = _SECRET_FLAG.sub(r"\1<redacted>", sanitized)
    return sanitized.strip()[-limit:]


def _cluster_name(run_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    slug = slug[:10].rstrip("-") or "run"
    # Keep the name short enough that kind's ``-control-plane`` suffix remains
    # comfortably within DNS and container-name limits.
    name = f"dsc-kind-{slug}-{secrets.token_hex(6)}"
    if len(name) > 63 or not _DNS_LABEL.fullmatch(name):  # pragma: no cover - invariant
        raise KindClusterError("could not generate a DNS-safe kind cluster name")
    return name


class KindCluster:
    """Create, configure, inspect, and destroy one isolated kind cluster."""

    def __init__(
        self,
        run_id: str,
        *,
        command_runner: CommandRunner | None = None,
        command_timeout_seconds: float = 60.0,
        create_timeout_seconds: float = 300.0,
    ) -> None:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError(
                "run_id must start with an alphanumeric character and contain only "
                "letters, numbers, periods, underscores, or dashes (maximum 64 characters)"
            )
        for label, value in (
            ("command_timeout_seconds", command_timeout_seconds),
            ("create_timeout_seconds", create_timeout_seconds),
        ):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{label} must be a positive finite number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{label} must be a positive finite number")

        self.run_id = run_id
        self.name = _cluster_name(run_id)
        self._command_runner = command_runner or subprocess.run
        self._command_timeout = float(command_timeout_seconds)
        self._create_timeout = float(create_timeout_seconds)
        self._runtime_directory: tempfile.TemporaryDirectory[str] | None = None
        self._config_path: Path | None = None
        self._kubeconfig_path: Path | None = None
        self._create_attempted = False
        self._owned_nodes: tuple[_NodeIdentity, ...] = ()
        self._handle: KindClusterHandle | None = None
        self._registry_configuration: LocalRegistryConfiguration | None = None
        self._diagnostics: list[str] = []

    @property
    def handle(self) -> KindClusterHandle | None:
        return self._handle

    @property
    def kubeconfig_path(self) -> Path | None:
        """Return the private runtime kubeconfig path while the lifecycle is active."""

        return self._kubeconfig_path

    @property
    def config_path(self) -> Path | None:
        """Return the private runtime kind-config path while it exists."""

        return self._config_path

    @property
    def registry_configuration(self) -> LocalRegistryConfiguration | None:
        return self._registry_configuration

    @property
    def diagnostics(self) -> str:
        return "\n".join(self._diagnostics)[-8000:]

    def __enter__(self) -> "KindCluster":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        try:
            if self._owned_nodes:
                self.destroy()
            else:
                self._cleanup_runtime_files()
        except KindClusterError as cleanup_error:
            self._remember_diagnostic("context cleanup", str(cleanup_error))
            try:
                self._cleanup_runtime_files()
            except KindClusterError as runtime_error:
                self._remember_diagnostic("runtime file cleanup", str(runtime_error))
            if exc_type is None:
                raise cleanup_error
        return False

    def create(self) -> KindClusterHandle:
        """Create a single-control-plane cluster using only the pinned tool/image."""

        if self._create_attempted:
            raise KindClusterError("kind cluster lifecycle has already attempted creation")

        self._verify_kind_version()
        if self.name in self._get_clusters():
            raise KindClusterCollisionError(
                f"generated kind cluster name is already in use: {self.name}"
            )

        self._allocate_runtime_files()
        self._create_attempted = True
        assert self._config_path is not None
        assert self._kubeconfig_path is not None
        command = [
            "kind",
            "create",
            "cluster",
            "--name",
            self.name,
            "--image",
            KIND_NODE_IMAGE,
            "--kubeconfig",
            str(self._kubeconfig_path),
            "--config",
            str(self._config_path),
            "--wait",
            f"{self._create_timeout:g}s",
            "--retain",
        ]
        try:
            result = self._run(command, timeout=self._create_timeout)
            self._require_success(result, "create pinned kind cluster")
            self._ensure_private_kubeconfig()

            try:
                owned_nodes = self._discover_nodes()
            except KindClusterError as exc:
                self._remember_diagnostic("post-create ownership verification", str(exc))
                raise KindClusterOwnershipError(
                    "kind reported successful creation, but node ownership could not be "
                    "established; retained resources require manual inspection"
                ) from exc

            self._owned_nodes = owned_nodes
            self._handle = KindClusterHandle(
                run_id=self.run_id,
                name=self.name,
                context=f"kind-{self.name}",
                node_image=KIND_NODE_IMAGE,
                nodes=tuple(node.name for node in owned_nodes),
            )
            return self._handle
        except BaseException:
            # A failed create is deliberately retained by kind for diagnostics,
            # but credentials and config are never left behind by this lifecycle.
            try:
                self._cleanup_runtime_files()
            except KindClusterError as cleanup_error:
                self._remember_diagnostic("failed-create runtime cleanup", str(cleanup_error))
            raise

    def status(self) -> KindClusterStatus:
        """Report state without adopting or exposing details from a foreign cluster."""

        clusters = self._get_clusters()
        if self.name not in clusters:
            return KindClusterStatus(
                name=self.name,
                exists=False,
                owned=False,
                diagnostics=self.diagnostics,
            )
        if not self._owned_nodes:
            return KindClusterStatus(
                name=self.name,
                exists=True,
                owned=False,
                error="cluster identity was not established by this lifecycle",
                diagnostics=self.diagnostics,
            )

        try:
            nodes = self._verify_owned_nodes()
        except KindClusterOwnershipError as exc:
            return KindClusterStatus(
                name=self.name,
                exists=True,
                owned=False,
                error=_sanitize_output(str(exc), limit=1000),
                diagnostics=self.diagnostics,
            )

        ready, error = self._read_node_readiness(nodes)
        return KindClusterStatus(
            name=self.name,
            exists=True,
            owned=True,
            ready=ready,
            nodes=tuple(node.name for node in nodes),
            error=error,
            diagnostics=self.diagnostics,
        )

    def configure_local_registry(
        self,
        registry: EphemeralRegistry,
    ) -> LocalRegistryConfiguration:
        """Apply kind's official post-create local-registry configuration."""

        if self._handle is None or not self._owned_nodes:
            raise KindClusterError("kind cluster must be created before registry configuration")
        registry_handle = registry.handle
        self._validate_registry_handle(registry_handle)
        assert registry_handle is not None
        nodes = self._verify_owned_nodes()

        registry_directory = (
            f"/etc/containerd/certs.d/localhost:{registry_handle.host_port}"
        )
        hosts_path = f"{registry_directory}/hosts.toml"
        hosts_toml = (
            f'[host."http://{registry_handle.name}:{REGISTRY_CONTAINER_PORT}"]\n'
        )
        for node in nodes:
            mkdir = self._run(
                ["docker", "exec", node.container_id, "mkdir", "-p", registry_directory]
            )
            self._require_success(mkdir, f"create containerd registry directory on {node.name}")
            copy = self._run(
                [
                    "docker",
                    "exec",
                    "-i",
                    node.container_id,
                    "cp",
                    "/dev/stdin",
                    hosts_path,
                ],
                stdin=hosts_toml,
            )
            self._require_success(copy, f"write containerd registry alias on {node.name}")
            read_back = self._run(
                ["docker", "exec", node.container_id, "cat", hosts_path]
            )
            self._require_success(read_back, f"verify containerd registry alias on {node.name}")
            if _text(read_back.stdout) != hosts_toml:
                self._remember_diagnostic(
                    f"verify containerd registry alias on {node.name}",
                    "written hosts.toml did not round-trip exactly",
                )
                raise KindClusterError(
                    f"containerd registry alias verification failed on {node.name}"
                )

        registry.connect_kind_network(KIND_NETWORK_NAME)
        if registry.handle != registry_handle:
            raise KindClusterOwnershipError(
                "registry identity changed while configuring the kind cluster"
            )

        manifest, configmap_data = self._registry_configmap(registry_handle.host_port)
        kubeconfig = self._require_kubeconfig_path()
        apply_result = self._run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "apply", "-f", "-"],
            stdin=manifest,
        )
        self._require_success(apply_result, "publish local-registry-hosting ConfigMap")
        self._verify_registry_configmap(configmap_data)

        configured = LocalRegistryConfiguration(
            host_endpoint=f"localhost:{registry_handle.host_port}",
            container_endpoint=(
                f"http://{registry_handle.name}:{REGISTRY_CONTAINER_PORT}"
            ),
            nodes=tuple(node.name for node in nodes),
        )
        self._registry_configuration = configured
        return configured

    def destroy(self) -> bool:
        """Delete only the cluster whose captured node ownership still matches."""

        clusters = self._get_clusters()
        if self.name not in clusters:
            self._handle = None
            self._owned_nodes = ()
            self._registry_configuration = None
            self._cleanup_runtime_files()
            return False
        if not self._owned_nodes:
            raise KindClusterOwnershipError(
                "refusing to delete a cluster whose node identity was not established"
            )

        self._verify_owned_nodes()
        kubeconfig = self._require_kubeconfig_path()
        result = self._run(
            [
                "kind",
                "delete",
                "cluster",
                "--name",
                self.name,
                "--kubeconfig",
                str(kubeconfig),
            ]
        )
        self._require_success(result, "delete owned kind cluster")
        if self.name in self._get_clusters():
            self._remember_diagnostic(
                "delete owned kind cluster",
                "kind still reports the cluster after a successful delete command",
            )
            raise KindClusterError("kind cluster deletion could not be confirmed")

        self._handle = None
        self._owned_nodes = ()
        self._registry_configuration = None
        self._cleanup_runtime_files()
        return True

    def close(self) -> bool:
        """Context-manager friendly alias for safe destruction/credential cleanup."""

        if self._owned_nodes:
            return self.destroy()
        self._cleanup_runtime_files()
        return False

    def _verify_kind_version(self) -> None:
        result = self._run(["kind", "version"])
        self._require_success(result, "read kind version")
        lines = [line.strip() for line in _text(result.stdout).splitlines() if line.strip()]
        if len(lines) != 1 or not _KIND_VERSION_LINE.fullmatch(lines[0]):
            reported = _sanitize_output(result.stdout, limit=500) or "<empty>"
            raise KindVersionError(
                f"kind {KIND_VERSION} is required; installed CLI reported: {reported}"
            )

    def _get_clusters(self) -> set[str]:
        result = self._run(["kind", "get", "clusters"])
        self._require_success(result, "list kind clusters")
        raw_lines = [line.strip() for line in _text(result.stdout).splitlines() if line.strip()]
        if raw_lines == ["No kind clusters found."]:
            return set()
        if any(not _DNS_LABEL.fullmatch(line) for line in raw_lines):
            raise KindClusterError("kind returned malformed cluster inventory")
        return set(raw_lines)

    def _discover_nodes(self) -> tuple[_NodeIdentity, ...]:
        names = self._get_node_names()
        expected_name = f"{self.name}-control-plane"
        if names != (expected_name,):
            raise KindClusterOwnershipError(
                "created kind cluster did not contain the expected single control-plane node"
            )
        result = self._run(["docker", "inspect", *names])
        self._require_success(result, "inspect created kind nodes")
        inspected = self._parse_inspection(result.stdout, expected_count=len(names))
        return self._node_identities(inspected, names)

    def _verify_owned_nodes(self) -> tuple[_NodeIdentity, ...]:
        current_names = self._get_node_names()
        expected_names = tuple(node.name for node in self._owned_nodes)
        if current_names != expected_names:
            raise KindClusterOwnershipError(
                "kind node set changed after ownership was established"
            )

        result = self._run(
            ["docker", "inspect", *(node.container_id for node in self._owned_nodes)]
        )
        if result.returncode != 0:
            self._remember_result("re-inspect owned kind nodes", result)
            raise KindClusterOwnershipError(
                "owned kind node identities could not be re-inspected"
            )
        inspected = self._parse_inspection(result.stdout, expected_count=len(self._owned_nodes))
        current = self._node_identities(inspected, expected_names)
        if current != self._owned_nodes:
            raise KindClusterOwnershipError(
                "kind node immutable identity or ownership labels changed"
            )
        return current

    def _get_node_names(self) -> tuple[str, ...]:
        result = self._run(["kind", "get", "nodes", "--name", self.name])
        if result.returncode != 0:
            self._remember_result("list kind nodes", result)
            raise KindClusterOwnershipError("could not list nodes for the owned kind cluster")
        names = tuple(
            sorted(line.strip() for line in _text(result.stdout).splitlines() if line.strip())
        )
        if not names or len(set(names)) != len(names):
            raise KindClusterOwnershipError("kind returned an invalid node inventory")
        if any(not _DNS_LABEL.fullmatch(name) for name in names):
            raise KindClusterOwnershipError("kind returned a malformed node name")
        return names

    def _node_identities(
        self,
        inspected: Sequence[Mapping[str, Any]],
        expected_names: Sequence[str],
    ) -> tuple[_NodeIdentity, ...]:
        by_name: dict[str, _NodeIdentity] = {}
        for item in inspected:
            raw_name = item.get("Name")
            name = raw_name[1:] if isinstance(raw_name, str) and raw_name.startswith("/") else ""
            container_id = item.get("Id")
            config = item.get("Config")
            config = config if isinstance(config, dict) else {}
            labels = config.get("Labels")
            labels = labels if isinstance(labels, dict) else {}
            role = labels.get(KIND_ROLE_LABEL)
            if name not in expected_names:
                raise KindClusterOwnershipError("Docker returned an unexpected kind node name")
            if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
                raise KindClusterOwnershipError("kind node has an invalid immutable identity")
            if labels.get(KIND_CLUSTER_LABEL) != self.name or role != "control-plane":
                raise KindClusterOwnershipError(
                    "kind node ownership labels do not match this cluster"
                )
            if config.get("Image") != KIND_NODE_IMAGE:
                raise KindClusterOwnershipError("kind node image does not match the pinned image")
            if name in by_name:
                raise KindClusterOwnershipError("Docker returned a duplicate kind node")
            by_name[name] = _NodeIdentity(name, container_id, role)
        if set(by_name) != set(expected_names):
            raise KindClusterOwnershipError("Docker omitted an expected kind node")
        return tuple(by_name[name] for name in expected_names)

    @staticmethod
    def _parse_inspection(
        output: object,
        *,
        expected_count: int,
    ) -> list[Mapping[str, Any]]:
        try:
            payload = json.loads(_text(output))
        except json.JSONDecodeError as exc:
            raise KindClusterOwnershipError(
                "Docker returned malformed kind node inspection data"
            ) from exc
        if (
            not isinstance(payload, list)
            or len(payload) != expected_count
            or any(not isinstance(item, dict) for item in payload)
        ):
            raise KindClusterOwnershipError(
                "Docker returned unexpected kind node inspection data"
            )
        return payload

    def _read_node_readiness(
        self,
        nodes: Sequence[_NodeIdentity],
    ) -> tuple[bool, str]:
        kubeconfig = self._require_kubeconfig_path()
        result = self._run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "get", "nodes", "-o", "json"]
        )
        if result.returncode != 0:
            self._remember_result("read kind node readiness", result)
            return False, _sanitize_output(result.stderr or result.stdout, limit=1000)
        try:
            payload = json.loads(_text(result.stdout))
        except json.JSONDecodeError:
            return False, "kubectl returned malformed node status data"
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return False, "kubectl returned unexpected node status data"

        expected_names = {node.name for node in nodes}
        if len(items) != len(expected_names):
            return False, "Kubernetes node set does not match the owned kind nodes"
        observed_names: set[str] = set()
        all_ready = True
        for item in items:
            if not isinstance(item, dict):
                return False, "kubectl returned unexpected node status data"
            metadata = item.get("metadata")
            status = item.get("status")
            metadata = metadata if isinstance(metadata, dict) else {}
            status = status if isinstance(status, dict) else {}
            name = metadata.get("name")
            if not isinstance(name, str) or name not in expected_names:
                return False, "Kubernetes node set does not match the owned kind nodes"
            observed_names.add(name)
            conditions = status.get("conditions")
            conditions = conditions if isinstance(conditions, list) else []
            ready = any(
                isinstance(condition, dict)
                and condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions
            )
            all_ready = all_ready and ready
        if observed_names != expected_names:
            return False, "Kubernetes node set does not match the owned kind nodes"
        return all_ready, ""

    def _validate_registry_handle(self, handle: RegistryHandle | None) -> None:
        if not isinstance(handle, RegistryHandle):
            raise KindClusterError("an active registry handle is required")
        if handle.run_id != self.run_id:
            raise KindClusterOwnershipError(
                "registry run ownership does not match the kind cluster run"
            )
        if not handle.local_test_only or handle.host != REGISTRY_HOST:
            raise KindClusterOwnershipError("registry is not restricted to local test use")
        if not isinstance(handle.name, str) or not _DNS_LABEL.fullmatch(handle.name):
            raise KindClusterOwnershipError("registry container name is invalid")
        if (
            not isinstance(handle.container_id, str)
            or not _CONTAINER_ID.fullmatch(handle.container_id)
        ):
            raise KindClusterOwnershipError("registry immutable identity is invalid")
        if not isinstance(handle.host_port, int) or isinstance(handle.host_port, bool):
            raise KindClusterOwnershipError("registry host port is invalid")
        if handle.host_port < 1 or handle.host_port > 65535:
            raise KindClusterOwnershipError("registry host port is invalid")

    @staticmethod
    def _registry_configmap(host_port: int) -> tuple[str, str]:
        data = (
            f'host: "localhost:{host_port}"\n'
            f'help: "{LOCAL_REGISTRY_HELP}"\n'
        )
        manifest = (
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            f"  name: {LOCAL_REGISTRY_CONFIGMAP}\n"
            f"  namespace: {LOCAL_REGISTRY_NAMESPACE}\n"
            "data:\n"
            "  localRegistryHosting.v1: |\n"
            f"    host: \"localhost:{host_port}\"\n"
            f"    help: \"{LOCAL_REGISTRY_HELP}\"\n"
        )
        return manifest, data

    def _verify_registry_configmap(self, expected_data: str) -> None:
        kubeconfig = self._require_kubeconfig_path()
        result = self._run(
            [
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "get",
                "configmap",
                LOCAL_REGISTRY_CONFIGMAP,
                "--namespace",
                LOCAL_REGISTRY_NAMESPACE,
                "-o",
                "json",
            ]
        )
        self._require_success(result, "verify local-registry-hosting ConfigMap")
        try:
            payload = json.loads(_text(result.stdout))
        except json.JSONDecodeError as exc:
            raise KindClusterError(
                "kubectl returned malformed local-registry-hosting ConfigMap data"
            ) from exc
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict) or data.get("localRegistryHosting.v1") != expected_data:
            raise KindClusterError(
                "local-registry-hosting ConfigMap verification failed"
            )

    def _allocate_runtime_files(self) -> None:
        if self._runtime_directory is not None:  # pragma: no cover - lifecycle invariant
            raise KindClusterError("kind runtime files already exist")
        runtime = tempfile.TemporaryDirectory(prefix="devops-stack-kind-")
        directory = Path(runtime.name)
        try:
            os.chmod(directory, 0o700)
            config_path = directory / "kind-config.yaml"
            kubeconfig_path = directory / "kubeconfig"
            self._write_private_file(config_path, self._kind_config())
            self._write_private_file(kubeconfig_path, "")
        except BaseException:
            runtime.cleanup()
            raise
        self._runtime_directory = runtime
        self._config_path = config_path
        self._kubeconfig_path = kubeconfig_path

    @staticmethod
    def _write_private_file(path: Path, content: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            payload = content.encode("utf-8")
            while payload:
                written = os.write(descriptor, payload)
                payload = payload[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _kind_config() -> str:
        return (
            "kind: Cluster\n"
            "apiVersion: kind.x-k8s.io/v1alpha4\n"
            "networking:\n"
            f'  apiServerAddress: "{API_SERVER_ADDRESS}"\n'
            "nodes:\n"
            "- role: control-plane\n"
        )

    def _ensure_private_kubeconfig(self) -> None:
        path = self._require_kubeconfig_path()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise KindClusterError("kind did not create the private kubeconfig") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise KindClusterError("kind kubeconfig is not a private regular file")
        os.chmod(path, 0o600)

    def _require_kubeconfig_path(self) -> Path:
        if self._kubeconfig_path is None:
            raise KindClusterError("private kind kubeconfig is unavailable")
        return self._kubeconfig_path

    def _cleanup_runtime_files(self) -> None:
        runtime = self._runtime_directory
        if runtime is None:
            return
        runtime_path = Path(runtime.name)
        try:
            runtime.cleanup()
        except OSError as exc:
            raise KindClusterError(
                f"could not remove private kind runtime directory: {runtime_path.name}"
            ) from exc
        self._runtime_directory = None
        self._config_path = None
        self._kubeconfig_path = None

    def _run(
        self,
        command: Sequence[str],
        *,
        stdin: str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = list(command)
        try:
            return self._command_runner(
                argv,
                check=False,
                capture_output=True,
                text=True,
                input=stdin,
                timeout=self._command_timeout if timeout is None else timeout,
            )
        except FileNotFoundError as exc:
            raise KindClusterError(f"{argv[0]} CLI is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            detail = _sanitize_output(exc.stderr or exc.stdout, limit=1000)
            suffix = f": {detail}" if detail else ""
            raise KindClusterError(f"{argv[0]} command timed out{suffix}") from exc
        except OSError as exc:
            detail = _sanitize_output(str(exc), limit=1000)
            raise KindClusterError(f"{argv[0]} command could not run: {detail}") from exc

    def _require_success(
        self,
        result: subprocess.CompletedProcess[str],
        operation: str,
    ) -> None:
        if result.returncode == 0:
            return
        self._remember_result(operation, result)
        detail = _sanitize_output(result.stderr or result.stdout, limit=2000)
        suffix = f": {detail}" if detail else ""
        raise KindClusterError(
            f"could not {operation} (exit {result.returncode}){suffix}"
        )

    def _remember_result(
        self,
        operation: str,
        result: subprocess.CompletedProcess[str],
    ) -> None:
        combined = "\n".join(
            part for part in (_text(result.stdout), _text(result.stderr)) if part
        )
        self._remember_diagnostic(operation, combined or f"exit {result.returncode}")

    def _remember_diagnostic(self, operation: str, detail: object) -> None:
        sanitized = _sanitize_output(detail, limit=2000) or "<empty>"
        self._diagnostics.append(f"{operation}: {sanitized}")
        while len("\n".join(self._diagnostics)) > 8000 and len(self._diagnostics) > 1:
            self._diagnostics.pop(0)


__all__ = [
    "API_SERVER_ADDRESS",
    "KIND_CLUSTER_LABEL",
    "KIND_NETWORK_NAME",
    "KIND_NODE_IMAGE",
    "KIND_ROLE_LABEL",
    "KIND_VERSION",
    "LOCAL_REGISTRY_CONFIGMAP",
    "LOCAL_REGISTRY_HELP",
    "LOCAL_REGISTRY_NAMESPACE",
    "KindCluster",
    "KindClusterCollisionError",
    "KindClusterError",
    "KindClusterHandle",
    "KindClusterOwnershipError",
    "KindClusterStatus",
    "KindVersionError",
    "LocalRegistryConfiguration",
]
