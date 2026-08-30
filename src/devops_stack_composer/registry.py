"""Owned, loopback-only registry lifecycle for local kind execution."""

from __future__ import annotations

import json
import math
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from devops_stack_composer.errors import DevOpsStackError


REGISTRY_IMAGE = (
    "docker.io/library/registry:3.1.1@"
    "sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33"
)
REGISTRY_HOST = "127.0.0.1"
REGISTRY_CONTAINER_PORT = 5000

MANAGED_BY_LABEL = "io.devops-stack-composer.managed-by"
RESOURCE_LABEL = "io.devops-stack-composer.resource"
RUN_ID_LABEL = "io.devops-stack-composer.run-id"
CONTAINER_NAME_LABEL = "io.devops-stack-composer.container-name"

_MANAGED_BY = "devops-stack-composer"
_RESOURCE = "ephemeral-registry"
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
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
HttpOpener = Callable[..., Any]


class RegistryError(DevOpsStackError):
    """Raised when the isolated registry cannot be managed safely."""


class RegistryOwnershipError(RegistryError):
    """Raised before an operation could affect a container not owned by this run."""


class RegistryReadinessError(RegistryError):
    """Raised when the registry does not become ready within its deadline."""


@dataclass(frozen=True)
class RegistryHandle:
    """Immutable connection details for one run-owned local registry."""

    run_id: str
    name: str
    container_id: str
    host_port: int
    image: str = REGISTRY_IMAGE
    host: str = REGISTRY_HOST
    local_test_only: bool = True

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.host_port}"

    @property
    def v2_url(self) -> str:
        return f"http://{self.endpoint}/v2/"


@dataclass(frozen=True)
class RegistryStatus:
    """Sanitized status and optional logs for a registry container."""

    name: str
    exists: bool
    owned: bool
    running: bool = False
    state: str = ""
    exit_code: int | None = None
    error: str = ""
    container_id: str = ""
    host_port: int | None = None
    networks: tuple[str, ...] = ()
    logs: str = ""


def _sanitize_output(value: object, *, limit: int = 8000) -> str:
    if not isinstance(value, str):
        return ""
    sanitized = _URL_USERINFO.sub(r"\1<redacted>@", value)
    sanitized = _AUTHORIZATION.sub(r"\1<redacted>", sanitized)
    sanitized = _INLINE_SECRET.sub(r"\1<redacted>", sanitized)
    sanitized = _SECRET_FLAG.sub(r"\1<redacted>", sanitized)
    return sanitized.strip()[-limit:]


def _registry_name(run_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    slug = slug[:20].rstrip("-") or "run"
    name = f"devops-stack-registry-{slug}-{secrets.token_hex(6)}"
    if len(name) > 63 or not _DNS_LABEL.fullmatch(name):  # pragma: no cover - invariant
        raise RegistryError("could not generate a DNS-safe registry container name")
    return name


class EphemeralRegistry:
    """Create and remove one isolated registry owned by an execution run."""

    def __init__(
        self,
        run_id: str,
        *,
        command_runner: CommandRunner | None = None,
        http_opener: HttpOpener | None = None,
        readiness_timeout_seconds: float = 20.0,
        poll_interval_seconds: float = 0.2,
        command_timeout_seconds: float = 30.0,
    ) -> None:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError(
                "run_id must start with an alphanumeric character and contain only "
                "letters, numbers, periods, underscores, or dashes (maximum 64 characters)"
            )
        for label, value in (
            ("readiness_timeout_seconds", readiness_timeout_seconds),
            ("poll_interval_seconds", poll_interval_seconds),
            ("command_timeout_seconds", command_timeout_seconds),
        ):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{label} must be a positive finite number")

        self.run_id = run_id
        self.name = _registry_name(run_id)
        self._command_runner = command_runner or subprocess.run
        self._http_opener = http_opener or urlopen
        self._readiness_timeout = float(readiness_timeout_seconds)
        self._poll_interval = float(poll_interval_seconds)
        self._command_timeout = float(command_timeout_seconds)
        self._container_id: str | None = None
        self._handle: RegistryHandle | None = None
        self._created = False
        self._labels = {
            MANAGED_BY_LABEL: _MANAGED_BY,
            RESOURCE_LABEL: _RESOURCE,
            RUN_ID_LABEL: run_id,
            CONTAINER_NAME_LABEL: self.name,
        }

    @property
    def handle(self) -> RegistryHandle | None:
        return self._handle

    @property
    def ownership_labels(self) -> Mapping[str, str]:
        return dict(self._labels)

    def start(self) -> RegistryHandle:
        """Start the pinned registry and wait for its loopback `/v2/` endpoint."""
        if self._created:
            raise RegistryError("registry lifecycle has already been started")

        command = ["docker", "run", "--detach", "--name", self.name]
        for key, value in self._labels.items():
            command.extend(("--label", f"{key}={value}"))
        command.extend(
            (
                "--publish",
                f"{REGISTRY_HOST}::{REGISTRY_CONTAINER_PORT}",
                REGISTRY_IMAGE,
            )
        )
        result = self._run(command)
        self._require_success(result, "start local registry")
        self._created = True
        candidate_id = (result.stdout or "").strip()
        if _CONTAINER_ID.fullmatch(candidate_id):
            self._container_id = candidate_id

        try:
            inspected = self._inspect_required()
            self._assert_owned(inspected)
            container_id = self._container_id_from(inspected)
            self._container_id = container_id
            host_port = self._host_port_from(inspected)
            handle = RegistryHandle(
                run_id=self.run_id,
                name=self.name,
                container_id=container_id,
                host_port=host_port,
            )
            self._handle = handle
            self._wait_until_ready(handle)
            return handle
        except RegistryError as exc:
            self._raise_start_failure(exc)
        raise AssertionError("unreachable")

    def connect_kind_network(self, network_name: str) -> bool:
        """Connect the owned registry to a caller-selected kind network."""
        if not isinstance(network_name, str) or not _DNS_LABEL.fullmatch(network_name):
            raise ValueError("kind network name must be one DNS-safe label")
        inspected = self._inspect_required()
        self._assert_owned(inspected)
        networks = self._networks_from(inspected)
        if network_name in networks:
            return False

        container_id = self._container_id_from(inspected)
        result = self._run(["docker", "network", "connect", network_name, container_id])
        self._require_success(result, "connect registry to kind network")

        confirmed = self._inspect_required()
        self._assert_owned(confirmed)
        if network_name not in self._networks_from(confirmed):
            raise RegistryError("Docker did not report the requested kind network connection")
        return True

    def status(self, *, include_logs: bool = False) -> RegistryStatus:
        """Capture state without exposing foreign-container details."""
        inspected = self._inspect(allow_missing=True)
        if inspected is None:
            return RegistryStatus(self.name, exists=False, owned=False)
        try:
            self._assert_owned(inspected)
        except RegistryOwnershipError:
            return RegistryStatus(self.name, exists=True, owned=False)

        state = inspected.get("State")
        state = state if isinstance(state, dict) else {}
        state_name = state.get("Status") if isinstance(state.get("Status"), str) else ""
        exit_code = state.get("ExitCode")
        if not isinstance(exit_code, int):
            exit_code = None
        error = _sanitize_output(state.get("Error"))
        container_id = self._container_id_from(inspected)
        try:
            host_port = self._host_port_from(inspected)
        except RegistryError:
            host_port = None
        logs = self._read_logs(container_id) if include_logs else ""
        return RegistryStatus(
            name=self.name,
            exists=True,
            owned=True,
            running=bool(state.get("Running")),
            state=state_name,
            exit_code=exit_code,
            error=error,
            container_id=container_id,
            host_port=host_port,
            networks=tuple(sorted(self._networks_from(inspected))),
            logs=logs,
        )

    def logs(self, *, tail: int = 200) -> str:
        """Capture bounded, sanitized logs from the verified owned container."""
        if not isinstance(tail, int) or isinstance(tail, bool) or tail < 1 or tail > 10_000:
            raise ValueError("tail must be an integer between 1 and 10000")
        inspected = self._inspect_required()
        self._assert_owned(inspected)
        return self._read_logs(self._container_id_from(inspected), tail=tail)

    def cleanup(self) -> bool:
        """Remove only the exact container whose ownership can be re-verified."""
        if not self._created:
            return False
        inspected = self._inspect(allow_missing=True)
        if inspected is None:
            self._handle = None
            return False
        self._assert_owned(inspected)
        container_id = self._container_id_from(inspected)
        result = self._run(
            ["docker", "rm", "--force", "--volumes", container_id],
            timeout=self._command_timeout,
        )
        self._require_success(result, "remove owned local registry")
        self._handle = None
        return True

    def _wait_until_ready(self, handle: RegistryHandle) -> None:
        deadline = time.monotonic() + self._readiness_timeout
        max_attempts = max(1, math.ceil(self._readiness_timeout / self._poll_interval) + 1)
        last_error = "no response"
        request = Request(handle.v2_url, headers={"Accept": "application/json"}, method="GET")

        for attempt in range(max_attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                probe_timeout = max(0.001, min(1.0, remaining))
                with self._http_opener(request, timeout=probe_timeout) as response:
                    status = getattr(response, "status", None)
                    if status is None:
                        status = response.getcode()
                    response.read(4096)
                if status == 200:
                    return
                last_error = f"HTTP {status}"
            except HTTPError as exc:
                last_error = f"HTTP {exc.code}"
            except (URLError, TimeoutError, OSError) as exc:
                last_error = _sanitize_output(str(exc), limit=1000) or type(exc).__name__

            if attempt + 1 < max_attempts:
                sleep_for = min(self._poll_interval, max(0.0, deadline - time.monotonic()))
                if sleep_for > 0:
                    time.sleep(sleep_for)

        raise RegistryReadinessError(
            f"registry readiness timed out after {self._readiness_timeout:g}s: {last_error}"
        )

    def _raise_start_failure(self, failure: RegistryError) -> None:
        diagnostic = ""
        try:
            status = self.status(include_logs=True)
            if status.owned:
                diagnostic = (
                    f"; state={status.state or 'unknown'}; exitCode={status.exit_code}; "
                    f"logs={status.logs or '<empty>'}"
                )
        except RegistryError as exc:
            diagnostic = f"; diagnostics unavailable: {_sanitize_output(str(exc), limit=1000)}"

        cleanup_note = ""
        try:
            self.cleanup()
        except RegistryError as exc:
            cleanup_note = f"; cleanup refused or failed: {_sanitize_output(str(exc), limit=1000)}"
        message = _sanitize_output(str(failure), limit=2000)
        raise RegistryError(
            f"local registry start failed: {message}{diagnostic}{cleanup_note}"
        ) from failure

    def _read_logs(self, container_id: str, *, tail: int = 200) -> str:
        result = self._run(
            ["docker", "logs", "--tail", str(tail), container_id],
            timeout=self._command_timeout,
        )
        self._require_success(result, "capture local registry logs")
        combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
        return _sanitize_output(combined)

    def _inspect_required(self) -> dict[str, Any]:
        inspected = self._inspect(allow_missing=False)
        if inspected is None:  # pragma: no cover - allow_missing=False invariant
            raise RegistryError("registry container does not exist")
        return inspected

    def _inspect(self, *, allow_missing: bool) -> dict[str, Any] | None:
        result = self._run(
            ["docker", "inspect", self.name],
            timeout=self._command_timeout,
        )
        if result.returncode != 0:
            output = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
            if allow_missing and (
                "no such object" in output
                or "no such container" in output
                or "not found" in output
            ):
                return None
            self._require_success(result, "inspect local registry ownership")
        try:
            payload = json.loads(result.stdout or "")
        except (TypeError, json.JSONDecodeError) as exc:
            raise RegistryError("Docker returned malformed registry inspection data") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise RegistryError("Docker returned unexpected registry inspection data")
        return payload[0]

    def _assert_owned(self, inspected: Mapping[str, Any]) -> None:
        if inspected.get("Name") != f"/{self.name}":
            raise RegistryOwnershipError("registry container name ownership check failed")
        config = inspected.get("Config")
        config = config if isinstance(config, dict) else {}
        labels = config.get("Labels")
        labels_match = isinstance(labels, dict) and all(
            labels.get(key) == value for key, value in self._labels.items()
        )
        if not labels_match:
            raise RegistryOwnershipError(
                "registry container ownership labels do not match this run"
            )
        if config.get("Image") != REGISTRY_IMAGE:
            raise RegistryOwnershipError("registry container image ownership check failed")
        container_id = self._container_id_from(inspected)
        if self._container_id and container_id != self._container_id:
            raise RegistryOwnershipError("registry container identity changed during the run")

    @staticmethod
    def _container_id_from(inspected: Mapping[str, Any]) -> str:
        container_id = inspected.get("Id")
        if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
            raise RegistryOwnershipError("registry container has an invalid immutable identity")
        return container_id

    @staticmethod
    def _host_port_from(inspected: Mapping[str, Any]) -> int:
        network_settings = inspected.get("NetworkSettings")
        network_settings = network_settings if isinstance(network_settings, dict) else {}
        ports = network_settings.get("Ports")
        ports = ports if isinstance(ports, dict) else {}
        bindings = ports.get(f"{REGISTRY_CONTAINER_PORT}/tcp")
        valid_bindings = (
            isinstance(bindings, list)
            and len(bindings) == 1
            and isinstance(bindings[0], dict)
        )
        if not valid_bindings:
            raise RegistryError("registry did not receive exactly one dynamic host-port binding")
        binding = bindings[0]
        if binding.get("HostIp") != REGISTRY_HOST:
            raise RegistryError("registry host port is not restricted to loopback")
        raw_port = binding.get("HostPort")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise RegistryError("registry host port is invalid") from exc
        if port < 1 or port > 65535:
            raise RegistryError("registry host port is outside the valid range")
        return port

    @staticmethod
    def _networks_from(inspected: Mapping[str, Any]) -> set[str]:
        network_settings = inspected.get("NetworkSettings")
        network_settings = network_settings if isinstance(network_settings, dict) else {}
        networks = network_settings.get("Networks")
        if not isinstance(networks, dict):
            return set()
        return {name for name in networks if isinstance(name, str)}

    def _run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._command_runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._command_timeout if timeout is None else timeout,
            )
        except FileNotFoundError as exc:
            raise RegistryError("Docker CLI is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            detail = _sanitize_output(exc.stderr or exc.stdout, limit=1000)
            suffix = f": {detail}" if detail else ""
            raise RegistryError(f"Docker command timed out{suffix}") from exc
        except OSError as exc:
            detail = _sanitize_output(str(exc), limit=1000)
            raise RegistryError(f"Docker command could not run: {detail}") from exc

    @staticmethod
    def _require_success(result: subprocess.CompletedProcess[str], operation: str) -> None:
        if result.returncode == 0:
            return
        detail = _sanitize_output(result.stderr or result.stdout, limit=2000)
        suffix = f": {detail}" if detail else ""
        raise RegistryError(f"could not {operation} (exit {result.returncode}){suffix}")


__all__ = [
    "CONTAINER_NAME_LABEL",
    "EphemeralRegistry",
    "MANAGED_BY_LABEL",
    "REGISTRY_CONTAINER_PORT",
    "REGISTRY_HOST",
    "REGISTRY_IMAGE",
    "RESOURCE_LABEL",
    "RUN_ID_LABEL",
    "RegistryError",
    "RegistryHandle",
    "RegistryOwnershipError",
    "RegistryReadinessError",
    "RegistryStatus",
]
