"""Constrained, cancellable subprocess execution for orchestration commands."""

from __future__ import annotations

import errno
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO, Callable, Iterable, Mapping, Protocol, Sequence


DEFAULT_ALLOWED_ENVIRONMENT_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    }
)
DEFAULT_MAX_OUTPUT_BYTES = 16_384
MAX_ARGUMENT_BYTES = 8_192
MAX_COMMAND_BYTES = 65_536
MAX_ENVIRONMENT_VALUE_BYTES = 16_384

_ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_KEY = re.compile(
    r"(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)",
    re.IGNORECASE,
)
_URL_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]*"
)
_INLINE_SECRET = re.compile(
    r"(?ix)(\b(?:password|passphrase|token|secret|private.?key|access.?key|api.?key|authorization)\b[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_SECRET_FLAG = re.compile(
    r"(?ix)(--(?:password|passphrase|token|secret|private-key|access-key|api-key)(?:\s+|=))"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_CURL_USER = re.compile(
    r"(?i)(?<!\S)(?P<prefix>--user(?:\s+|=)|-u(?:\s+|=)|"
    r"-u(?=[^\s;]*:))(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;]+)"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_SECRET_OPTION = re.compile(
    r"(?i)^--(?:password|passphrase|token|secret|private-key|access-key|api-key)$"
)
_TRUNCATION_MARKER = b"\n...[output truncated]"
_REDACTION_WINDOW_BYTES = 8_192


class ProcessErrorCategory(str, Enum):
    """Stable classifications for expected process execution failures."""

    COMMAND_NOT_FOUND = "command_not_found"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    NONZERO = "nonzero"
    NON_ZERO_EXIT = "nonzero"


@dataclass(frozen=True)
class ProcessResult:
    """Sanitized, size-bounded evidence from one process invocation."""

    argv: tuple[str, ...]
    cwd: Path
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    error_category: ProcessErrorCategory | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def command(self) -> tuple[str, ...]:
        return self.argv

    @property
    def exit_code(self) -> int | None:
        return self.returncode

    @property
    def succeeded(self) -> bool:
        return self.error_category is None and self.returncode == 0

    @property
    def category(self) -> ProcessErrorCategory | None:
        return self.error_category


class ProcessExecutionError(RuntimeError):
    """Base class for a classified failure with sanitized process evidence."""

    def __init__(self, category: ProcessErrorCategory, result: ProcessResult):
        self.category = category
        self.result = result
        detail = (
            f" with exit code {result.returncode}"
            if category == ProcessErrorCategory.NONZERO
            else ""
        )
        super().__init__(f"process execution failed: {category.value}{detail}")


class CommandNotFoundError(ProcessExecutionError):
    """The allowlisted executable could not be resolved by the operating system."""


class ProcessPermissionError(ProcessExecutionError):
    """The operating system refused to execute the command."""


class ProcessTimeoutError(ProcessExecutionError):
    """The per-command timeout or overall deadline expired."""


class ProcessCancelledError(ProcessExecutionError):
    """Cancellation was requested before the command completed."""


class NonZeroExitError(ProcessExecutionError):
    """The process completed with a non-zero exit status."""


class UnsafeProcessRequestError(ValueError):
    """A process request crossed a configured execution boundary."""


class CancellationToken:
    """Thread-safe cooperative cancellation shared by orchestration commands."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self.is_cancelled()


class _ProcessHandle(Protocol):
    pid: int
    stdout: BinaryIO | None
    stderr: BinaryIO | None
    returncode: int | None

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class _BoundedStream:
    """Drain a pipe completely while retaining only a fixed-size prefix."""

    def __init__(
        self,
        stream: BinaryIO,
        limit: int,
        on_update: Callable[[], None] | None = None,
    ):
        self._stream = stream
        self._limit = limit
        self._value = bytearray()
        self._truncated = False
        self._lock = threading.Lock()
        self._on_update = on_update
        self._thread = threading.Thread(target=self._read, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()

    @property
    def value(self) -> bytes:
        with self._lock:
            return bytes(self._value)

    @property
    def truncated(self) -> bool:
        with self._lock:
            return self._truncated

    def _read(self) -> None:
        try:
            while True:
                chunk = self._stream.read(8192)
                if not chunk:
                    return
                with self._lock:
                    remaining = self._limit - len(self._value)
                    if remaining > 0:
                        self._value.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self._truncated = True
                if self._on_update is not None:
                    self._on_update()
        except (OSError, ValueError):
            # A process killed at a deadline may close a pipe during a read.
            return
        finally:
            try:
                self._stream.close()
            except OSError:
                pass
            if self._on_update is not None:
                self._on_update()


def redact_process_output(value: str, secret_values: Iterable[str] = ()) -> str:
    """Redact common credentials and explicitly supplied secret values."""

    redacted = value
    secrets = sorted(
        {secret for secret in secret_values if isinstance(secret, str) and secret},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        redacted = redacted.replace(secret, "<redacted>")
    redacted = _PRIVATE_KEY_BLOCK.sub("<redacted-private-key>", redacted)
    redacted = _URL_USERINFO.sub(r"\1<redacted>@", redacted)
    redacted = _AUTHORIZATION_HEADER.sub(r"\1<redacted>", redacted)
    redacted = _INLINE_SECRET.sub(r"\1<redacted>", redacted)
    redacted = _SECRET_FLAG.sub(r"\1<redacted>", redacted)
    return _CURL_USER.sub(r"\g<prefix><redacted>", redacted)


class SafeProcessRunner:
    """Execute only explicitly allowed commands inside one project boundary.

    ``deadline`` values are absolute readings from the injected monotonic clock.
    The runner never invokes a shell and never inherits the full host environment.
    """

    def __init__(
        self,
        project_root: Path,
        *,
        allowed_executables: Iterable[str],
        allowed_environment_keys: Iterable[str] = DEFAULT_ALLOWED_ENVIRONMENT_KEYS,
        inherited_environment_keys: Iterable[str] | None = None,
        base_environment: Mapping[str, str] | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        default_timeout: float | None = None,
        overall_deadline: float | None = None,
        cancellation_token: CancellationToken | None = None,
        poll_interval: float = 0.05,
        termination_grace: float = 1.0,
        launcher: Callable[..., _ProcessHandle] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
        process_group_kill: Callable[[int, int], None] | None = None,
        redactor: Callable[[str], str] | None = None,
    ):
        try:
            root = Path(project_root).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise UnsafeProcessRequestError("project_root must be an existing directory") from exc
        if not root.is_dir():
            raise UnsafeProcessRequestError("project_root must be an existing directory")

        executables = self._string_set("allowed_executables", allowed_executables)
        if not executables:
            raise UnsafeProcessRequestError("allowed_executables must not be empty")
        allowed_keys = self._environment_key_set(
            "allowed_environment_keys", allowed_environment_keys
        )
        inherited_keys = (
            allowed_keys.intersection(DEFAULT_ALLOWED_ENVIRONMENT_KEYS)
            if inherited_environment_keys is None
            else self._environment_key_set(
                "inherited_environment_keys", inherited_environment_keys
            )
        )
        if not inherited_keys.issubset(allowed_keys):
            raise UnsafeProcessRequestError(
                "inherited_environment_keys must be allowed environment keys"
            )
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or max_output_bytes < 1
        ):
            raise UnsafeProcessRequestError("max_output_bytes must be a positive integer")
        self._validate_duration("default_timeout", default_timeout, optional=True)
        self._validate_deadline("overall_deadline", overall_deadline)
        self._validate_duration("poll_interval", poll_interval)
        self._validate_duration("termination_grace", termination_grace, allow_zero=True)

        environment_source = os.environ if base_environment is None else base_environment
        if not isinstance(environment_source, Mapping):
            raise UnsafeProcessRequestError("base_environment must be a mapping")
        inherited_environment: dict[str, str] = {}
        for key in sorted(inherited_keys):
            if key not in environment_source:
                continue
            value = environment_source[key]
            if (
                not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > MAX_ENVIRONMENT_VALUE_BYTES
            ):
                raise UnsafeProcessRequestError(
                    "inherited environment values must be bounded strings without NUL bytes"
                )
            inherited_environment[key] = value

        self.project_root = root
        self.allowed_executables = executables
        self.allowed_environment_keys = allowed_keys
        self.inherited_environment_keys = inherited_keys
        self._inherited_environment = inherited_environment
        self.max_output_bytes = max_output_bytes
        self.default_timeout = default_timeout
        self.overall_deadline = overall_deadline
        self.cancellation_token = cancellation_token
        self.poll_interval = poll_interval
        self.termination_grace = termination_grace
        self._launcher = launcher or subprocess.Popen
        self._clock = monotonic or time.monotonic
        self._sleep = sleeper or time.sleep
        self._redactor = redactor or (lambda value: redact_process_output(value))
        self._uses_process_groups = os.name == "posix"
        self._process_group_kill = process_group_kill
        if self._uses_process_groups and self._process_group_kill is None:
            self._process_group_kill = os.killpg

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
        deadline: float | None = None,
        cancellation_token: CancellationToken | None = None,
        redact_values: Iterable[str] = (),
    ) -> ProcessResult:
        """Run an argument-vector command or raise a classified execution error."""

        command = self._validate_argv(argv)
        working_directory = self._resolve_cwd(cwd)
        child_environment = self._environment(environment)
        selected_timeout = self.default_timeout if timeout is None else timeout
        self._validate_duration("timeout", selected_timeout, optional=True)
        self._validate_deadline("deadline", deadline)
        token = cancellation_token or self.cancellation_token
        if token is not None and not isinstance(token, CancellationToken):
            raise UnsafeProcessRequestError(
                "cancellation_token must be a CancellationToken"
            )
        secrets = self._secret_values(environment, redact_values)
        sanitized_argv = self._sanitize_argv(command, secrets)
        started = self._clock()
        effective_deadline = self._effective_deadline(started, selected_timeout, deadline)

        if token is not None and token.is_cancelled():
            self._raise_without_process(
                ProcessErrorCategory.CANCELLED,
                sanitized_argv,
                working_directory,
                started,
            )
        if effective_deadline is not None and started >= effective_deadline:
            self._raise_without_process(
                ProcessErrorCategory.TIMEOUT,
                sanitized_argv,
                working_directory,
                started,
            )

        options: dict[str, object] = {
            "cwd": str(working_directory),
            "env": child_environment,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "close_fds": True,
            "bufsize": 0,
        }
        if self._uses_process_groups:
            options["start_new_session"] = True
        try:
            process = self._launcher(list(command), **options)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
                self._raise_without_process(
                    ProcessErrorCategory.COMMAND_NOT_FOUND,
                    sanitized_argv,
                    working_directory,
                    started,
                )
            if isinstance(exc, PermissionError) or exc.errno in {errno.EACCES, errno.EPERM}:
                self._raise_without_process(
                    ProcessErrorCategory.PERMISSION,
                    sanitized_argv,
                    working_directory,
                    started,
                )
            raise

        if process.stdout is None or process.stderr is None:
            self._terminate(process, ())
            raise RuntimeError("process launcher did not provide captured output pipes")

        raw_limit = self.max_output_bytes + _REDACTION_WINDOW_BYTES
        stdout = _BoundedStream(process.stdout, raw_limit)
        stderr = _BoundedStream(process.stderr, raw_limit)
        collectors = (stdout, stderr)
        for collector in collectors:
            collector.start()

        category: ProcessErrorCategory | None = None
        while process.poll() is None:
            now = self._clock()
            if token is not None and token.is_cancelled():
                category = ProcessErrorCategory.CANCELLED
                break
            if effective_deadline is not None and now >= effective_deadline:
                category = ProcessErrorCategory.TIMEOUT
                break
            delay = self.poll_interval
            if effective_deadline is not None:
                delay = min(delay, max(0.0, effective_deadline - now))
            self._sleep(delay)

        if category is not None:
            self._terminate(process, collectors)
        else:
            process.wait()
            self._join_collectors(process, collectors)

        returncode = process.poll()
        if returncode is None:
            returncode = process.returncode
        result = self._result(
            sanitized_argv,
            working_directory,
            returncode,
            stdout,
            stderr,
            started,
            category,
            secrets,
        )
        if category is not None:
            self._raise(category, result)
        if returncode != 0:
            failed = ProcessResult(
                **{
                    **result.__dict__,
                    "error_category": ProcessErrorCategory.NONZERO,
                }
            )
            self._raise(ProcessErrorCategory.NONZERO, failed)
        return result

    def start(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
        deadline: float | None = None,
        cancellation_token: CancellationToken | None = None,
        redact_values: Iterable[str] = (),
    ) -> ManagedProcess:
        """Start one managed process whose output and lifetime remain bounded.

        The returned handle continuously enforces cancellation and deadline
        policy. Callers must close it (or use it as a context manager) so the
        complete process group is terminated and reaped.
        """

        command = self._validate_argv(argv)
        working_directory = self._resolve_cwd(cwd)
        child_environment = self._environment(environment)
        selected_timeout = self.default_timeout if timeout is None else timeout
        self._validate_duration("timeout", selected_timeout, optional=True)
        self._validate_deadline("deadline", deadline)
        token = cancellation_token or self.cancellation_token
        if token is not None and not isinstance(token, CancellationToken):
            raise UnsafeProcessRequestError(
                "cancellation_token must be a CancellationToken"
            )
        secrets = self._secret_values(environment, redact_values)
        sanitized_argv = self._sanitize_argv(command, secrets)
        started = self._clock()
        effective_deadline = self._effective_deadline(started, selected_timeout, deadline)

        if token is not None and token.is_cancelled():
            self._raise_without_process(
                ProcessErrorCategory.CANCELLED,
                sanitized_argv,
                working_directory,
                started,
            )
        if effective_deadline is not None and started >= effective_deadline:
            self._raise_without_process(
                ProcessErrorCategory.TIMEOUT,
                sanitized_argv,
                working_directory,
                started,
            )

        options: dict[str, object] = {
            "cwd": str(working_directory),
            "env": child_environment,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "close_fds": True,
            "bufsize": 0,
        }
        if self._uses_process_groups:
            options["start_new_session"] = True
        try:
            process = self._launcher(list(command), **options)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
                self._raise_without_process(
                    ProcessErrorCategory.COMMAND_NOT_FOUND,
                    sanitized_argv,
                    working_directory,
                    started,
                )
            if isinstance(exc, PermissionError) or exc.errno in {errno.EACCES, errno.EPERM}:
                self._raise_without_process(
                    ProcessErrorCategory.PERMISSION,
                    sanitized_argv,
                    working_directory,
                    started,
                )
            raise

        if process.stdout is None or process.stderr is None:
            self._terminate(process, ())
            raise RuntimeError("process launcher did not provide captured output pipes")
        try:
            return ManagedProcess(
                self,
                process,
                sanitized_argv,
                working_directory,
                started,
                effective_deadline,
                token,
                secrets,
            )
        except BaseException:
            self._terminate(process, ())
            raise

    @staticmethod
    def _string_set(name: str, values: Iterable[str]) -> frozenset[str]:
        if isinstance(values, (str, bytes)):
            raise UnsafeProcessRequestError(f"{name} must be an iterable of strings")
        try:
            normalized = frozenset(values)
        except TypeError as exc:
            raise UnsafeProcessRequestError(f"{name} must contain strings") from exc
        if any(
            not isinstance(value, str) or not value or "\x00" in value
            for value in normalized
        ):
            raise UnsafeProcessRequestError(
                f"{name} must contain non-empty strings without NUL bytes"
            )
        return normalized

    @classmethod
    def _environment_key_set(
        cls, name: str, values: Iterable[str]
    ) -> frozenset[str]:
        normalized = cls._string_set(name, values)
        if any(not _ENVIRONMENT_KEY.fullmatch(value) for value in normalized):
            raise UnsafeProcessRequestError(
                f"{name} contains an invalid environment variable name"
            )
        return normalized

    @staticmethod
    def _validate_duration(
        name: str,
        value: float | None,
        *,
        optional: bool = False,
        allow_zero: bool = False,
    ) -> None:
        if value is None and optional:
            return
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or (value == 0 and not allow_zero)
        ):
            qualifier = "non-negative" if allow_zero else "positive"
            raise UnsafeProcessRequestError(f"{name} must be a finite {qualifier} number")

    @staticmethod
    def _validate_deadline(name: str, value: float | None) -> None:
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise UnsafeProcessRequestError(f"{name} must be a finite monotonic timestamp")

    def _validate_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)):
            raise UnsafeProcessRequestError("argv must be a sequence, not a shell command")
        try:
            command = tuple(argv)
        except TypeError as exc:
            raise UnsafeProcessRequestError("argv must be a sequence of strings") from exc
        if not command:
            raise UnsafeProcessRequestError("argv must not be empty")
        if any(not isinstance(value, str) or "\x00" in value for value in command):
            raise UnsafeProcessRequestError("argv values must be strings without NUL bytes")
        encoded_lengths = tuple(len(value.encode("utf-8")) for value in command)
        if any(length > MAX_ARGUMENT_BYTES for length in encoded_lengths):
            raise UnsafeProcessRequestError("argv contains an oversized argument")
        if sum(encoded_lengths) > MAX_COMMAND_BYTES:
            raise UnsafeProcessRequestError("argv exceeds the command size limit")
        if not command[0]:
            raise UnsafeProcessRequestError("argv executable must not be empty")
        if command[0] not in self.allowed_executables:
            raise UnsafeProcessRequestError("executable is not allowlisted")
        return command

    def _resolve_cwd(self, cwd: Path | None) -> Path:
        requested = self.project_root if cwd is None else cwd
        try:
            resolved = Path(requested).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise UnsafeProcessRequestError("cwd must be an existing project directory") from exc
        if not resolved.is_dir():
            raise UnsafeProcessRequestError("cwd must be an existing project directory")
        try:
            resolved.relative_to(self.project_root)
        except ValueError as exc:
            raise UnsafeProcessRequestError("cwd must remain within project_root") from exc
        return resolved

    def _environment(self, additions: Mapping[str, str] | None) -> dict[str, str]:
        environment = dict(self._inherited_environment)
        if additions is None:
            return environment
        if not isinstance(additions, Mapping):
            raise UnsafeProcessRequestError("environment must be a mapping")
        for key, value in additions.items():
            if not isinstance(key, str) or key not in self.allowed_environment_keys:
                raise UnsafeProcessRequestError("environment contains a non-allowlisted key")
            if (
                not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > MAX_ENVIRONMENT_VALUE_BYTES
            ):
                raise UnsafeProcessRequestError(
                    "environment values must be bounded strings without NUL bytes"
                )
            if key in self._inherited_environment and value != self._inherited_environment[key]:
                raise UnsafeProcessRequestError(
                    "environment cannot override an inherited execution value"
                )
            environment[key] = value
        return environment

    def _secret_values(
        self,
        additions: Mapping[str, str] | None,
        explicit: Iterable[str],
    ) -> tuple[str, ...]:
        values = self._string_set("redact_values", explicit)
        if any(len(value.encode("utf-8")) > _REDACTION_WINDOW_BYTES for value in values):
            raise UnsafeProcessRequestError("redact_values contains an oversized secret")
        sensitive = {
            value
            for key, value in self._inherited_environment.items()
            if value and _SENSITIVE_KEY.search(key)
        }
        if additions is not None:
            sensitive.update(
                value
                for key, value in additions.items()
                if value and _SENSITIVE_KEY.search(key)
            )
        return tuple(sorted(values.union(sensitive), key=len, reverse=True))

    def _effective_deadline(
        self, started: float, timeout: float | None, deadline: float | None
    ) -> float | None:
        deadlines = [
            value
            for value in (self.overall_deadline, deadline)
            if value is not None
        ]
        if timeout is not None:
            deadlines.append(started + timeout)
        return min(deadlines) if deadlines else None

    def _sanitize_argv(
        self, argv: tuple[str, ...], secrets: tuple[str, ...]
    ) -> tuple[str, ...]:
        sanitized: list[str] = []
        redact_next = False
        for argument in argv:
            if redact_next:
                sanitized.append("<redacted>")
                redact_next = False
                continue
            value = redact_process_output(argument, secrets)
            value = self._redactor(value)
            if not isinstance(value, str):
                raise UnsafeProcessRequestError("redactor must return a string")
            sanitized.append(value)
            redact_next = bool(_SECRET_OPTION.fullmatch(argument))
        return tuple(sanitized)

    def _raise_without_process(
        self,
        category: ProcessErrorCategory,
        argv: tuple[str, ...],
        cwd: Path,
        started: float,
    ) -> None:
        result = ProcessResult(
            argv,
            cwd,
            None,
            "",
            "",
            max(0.0, self._clock() - started),
            category,
        )
        self._raise(category, result)

    def _terminate(
        self,
        process: _ProcessHandle,
        collectors: tuple[_BoundedStream, ...],
    ) -> None:
        self._signal(process, signal.SIGTERM)
        stop_at = self._clock() + self.termination_grace
        while process.poll() is None and self._clock() < stop_at:
            self._sleep(min(self.poll_interval, max(0.0, stop_at - self._clock())))
        if process.poll() is None:
            self._signal(process, signal.SIGKILL)
        try:
            process.wait(timeout=self.termination_grace)
        except (subprocess.TimeoutExpired, TimeoutError):
            self._signal(process, signal.SIGKILL)
            try:
                process.wait(timeout=self.termination_grace)
            except (subprocess.TimeoutExpired, TimeoutError):
                pass
        for collector in collectors:
            collector.join(self.termination_grace)

    def _signal(self, process: _ProcessHandle, requested_signal: int) -> None:
        try:
            if self._uses_process_groups:
                if self._process_group_kill is None:  # pragma: no cover - invariant
                    raise RuntimeError("POSIX process-group signaling is unavailable")
                self._process_group_kill(process.pid, requested_signal)
            elif requested_signal == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
        except (ProcessLookupError, PermissionError):
            pass

    def _join_collectors(
        self,
        process: _ProcessHandle,
        collectors: tuple[_BoundedStream, _BoundedStream],
    ) -> None:
        for collector in collectors:
            collector.join(self.termination_grace)
        if any(collector.alive for collector in collectors):
            # Descendants retaining the inherited pipes belong to this invocation.
            self._terminate(process, collectors)

    def _result(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        returncode: int | None,
        stdout_capture: _BoundedStream,
        stderr_capture: _BoundedStream,
        started: float,
        category: ProcessErrorCategory | None,
        secrets: tuple[str, ...],
    ) -> ProcessResult:
        stdout, stdout_truncated = self._render_capture(stdout_capture, secrets)
        stderr, stderr_truncated = self._render_capture(stderr_capture, secrets)
        return ProcessResult(
            argv=argv,
            cwd=cwd,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=max(0.0, self._clock() - started),
            error_category=category,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def _render_capture(
        self, capture: _BoundedStream, secrets: tuple[str, ...]
    ) -> tuple[str, bool]:
        value = capture.value.decode("utf-8", errors="replace")
        value = redact_process_output(value, secrets)
        value = self._redactor(value)
        if not isinstance(value, str):
            raise RuntimeError("process output redactor must return a string")
        return self._bound_text(value, capture.truncated)

    def _bound_text(self, value: str, already_truncated: bool) -> tuple[str, bool]:
        encoded = value.encode("utf-8")
        truncated = already_truncated or len(encoded) > self.max_output_bytes
        if not truncated:
            return value, False
        marker = _TRUNCATION_MARKER[: self.max_output_bytes]
        available = max(0, self.max_output_bytes - len(marker))
        prefix = encoded[:available].decode("utf-8", errors="ignore")
        return prefix + marker.decode("ascii"), True

    @staticmethod
    def _raise(category: ProcessErrorCategory, result: ProcessResult) -> None:
        errors: Mapping[ProcessErrorCategory, type[ProcessExecutionError]] = {
            ProcessErrorCategory.COMMAND_NOT_FOUND: CommandNotFoundError,
            ProcessErrorCategory.PERMISSION: ProcessPermissionError,
            ProcessErrorCategory.TIMEOUT: ProcessTimeoutError,
            ProcessErrorCategory.CANCELLED: ProcessCancelledError,
            ProcessErrorCategory.NONZERO: NonZeroExitError,
        }
        raise errors[category](category, result)


class ManagedProcess:
    """A process kept alive under the same safety policy as synchronous runs."""

    def __init__(
        self,
        runner: SafeProcessRunner,
        process: _ProcessHandle,
        argv: tuple[str, ...],
        cwd: Path,
        started: float,
        deadline: float | None,
        cancellation_token: CancellationToken | None,
        secrets: tuple[str, ...],
    ) -> None:
        self._runner = runner
        self._process = process
        self._argv = argv
        self._cwd = cwd
        self._started = started
        self._deadline = deadline
        self._cancellation_token = cancellation_token
        self._secrets = secrets
        self._condition = threading.Condition()
        self._stop_requested = threading.Event()
        self._result_value: ProcessResult | None = None
        self._monitor_error: BaseException | None = None
        raw_limit = runner.max_output_bytes + _REDACTION_WINDOW_BYTES
        self._stdout = _BoundedStream(
            process.stdout,  # type: ignore[arg-type]
            raw_limit,
            self._notify,
        )
        self._stderr = _BoundedStream(
            process.stderr,  # type: ignore[arg-type]
            raw_limit,
            self._notify,
        )
        self._collectors = (self._stdout, self._stderr)
        self._monitor = threading.Thread(
            target=self._monitor_process,
            name=f"managed-process-{process.pid}",
            daemon=True,
        )
        for collector in self._collectors:
            collector.start()
        self._monitor.start()

    @property
    def is_running(self) -> bool:
        return self._process.poll() is None and self._result_value is None

    def output(self) -> tuple[str, str]:
        """Return the current sanitized, bounded stdout and stderr snapshots."""

        stdout, _ = self._runner._render_capture(self._stdout, self._secrets)
        stderr, _ = self._runner._render_capture(self._stderr, self._secrets)
        return stdout, stderr

    def wait_for_output(
        self,
        pattern: re.Pattern[str],
        *,
        timeout: float,
    ) -> re.Match[str]:
        """Wait for a pattern in this process's own stdout or stderr."""

        if not isinstance(pattern, re.Pattern):
            raise UnsafeProcessRequestError("pattern must be a compiled text regex")
        self._runner._validate_duration("timeout", timeout)
        stop_at = self._runner._clock() + timeout
        while True:
            stdout, stderr = self.output()
            match = pattern.search(stdout) or pattern.search(stderr)
            if match is not None and self.is_running:
                return match
            if self._result_value is not None or self._monitor_error is not None:
                result = self.wait()
                raise RuntimeError(
                    "managed process exited before the requested output was observed: "
                    f"exit code {result.returncode}"
                )
            remaining = stop_at - self._runner._clock()
            if remaining <= 0:
                raise TimeoutError("managed process output was not observed before timeout")
            with self._condition:
                self._condition.wait(min(self._runner.poll_interval, remaining))

    def wait(self, timeout: float | None = None) -> ProcessResult:
        """Wait for completion and raise the existing classified error on failure."""

        self._runner._validate_duration("timeout", timeout, optional=True)
        self._monitor.join(timeout)
        if self._monitor.is_alive():
            raise TimeoutError("managed process is still running")
        if self._monitor_error is not None:
            raise RuntimeError("managed process monitor failed") from self._monitor_error
        result = self._result_value
        if result is None:  # pragma: no cover - monitor invariant
            raise RuntimeError("managed process completed without a result")
        if result.error_category is not None:
            self._runner._raise(result.error_category, result)
        return result

    def close(self, timeout: float | None = None) -> bool:
        """Terminate and reap this process group; return false on cleanup timeout."""

        self._runner._validate_duration("timeout", timeout, optional=True)
        self._stop_requested.set()
        self._notify()
        self._monitor.join(timeout)
        return not self._monitor.is_alive() and self._process.poll() is not None

    def __enter__(self) -> ManagedProcess:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _notify(self) -> None:
        with self._condition:
            self._condition.notify_all()

    def _monitor_process(self) -> None:
        category: ProcessErrorCategory | None = None
        try:
            while self._process.poll() is None:
                now = self._runner._clock()
                if self._stop_requested.is_set() or (
                    self._cancellation_token is not None
                    and self._cancellation_token.is_cancelled()
                ):
                    category = ProcessErrorCategory.CANCELLED
                    break
                if self._deadline is not None and now >= self._deadline:
                    category = ProcessErrorCategory.TIMEOUT
                    break
                delay = self._runner.poll_interval
                if self._deadline is not None:
                    delay = min(delay, max(0.0, self._deadline - now))
                self._runner._sleep(delay)

            if category is not None:
                self._runner._terminate(self._process, self._collectors)
            else:
                self._process.wait()
                self._runner._join_collectors(self._process, self._collectors)

            returncode = self._process.poll()
            if returncode is None:
                returncode = self._process.returncode
            if category is None and returncode != 0:
                category = ProcessErrorCategory.NONZERO
            self._result_value = self._runner._result(
                self._argv,
                self._cwd,
                returncode,
                self._stdout,
                self._stderr,
                self._started,
                category,
                self._secrets,
            )
        except BaseException as exc:  # surfaced by wait(), never lost in a daemon
            self._monitor_error = exc
        finally:
            self._notify()


# A concise alias for callers that prefer the failure terminology.
ProcessFailureCategory = ProcessErrorCategory
