"""Narrow adapters from the safe runner to existing v0.2 command seams."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from devops_stack_composer.process_runner import (
    CommandNotFoundError,
    NonZeroExitError,
    ProcessPermissionError,
    ProcessResult,
    ProcessTimeoutError,
    SafeProcessRunner,
    UnsafeProcessRequestError,
)


class SafeSubprocessAdapter:
    """Expose ``subprocess.run``-shaped calls through ``SafeProcessRunner``.

    This exists only to connect the already-tested registry, kind, and supply-chain
    components without duplicating process management. New code should call the
    safe runner directly.
    """

    def __init__(self, runner: SafeProcessRunner):
        if not isinstance(runner, SafeProcessRunner):
            raise TypeError("runner must be a SafeProcessRunner")
        self.runner = runner

    def __call__(
        self,
        args: Sequence[str],
        *,
        cwd: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        input: str | bytes | None = None,
        timeout: float | None = None,
        check: bool = False,
        capture_output: bool = True,
        text: bool = False,
        shell: bool = False,
        **unsupported: Any,
    ) -> subprocess.CompletedProcess[Any]:
        if unsupported:
            raise UnsafeProcessRequestError(
                "unsupported subprocess options: " + ", ".join(sorted(unsupported))
            )
        if shell:
            raise UnsafeProcessRequestError("shell execution is forbidden")
        if not capture_output:
            raise UnsafeProcessRequestError("safe compatibility calls must capture output")
        if input is not None:
            raise UnsafeProcessRequestError(
                "safe compatibility calls do not accept process stdin; use a bounded project file"
            )
        working_directory = Path(cwd) if cwd is not None else None
        try:
            result = self.runner.run(
                args,
                cwd=working_directory,
                environment=env,
                timeout=timeout,
            )
        except NonZeroExitError as exc:
            result = exc.result
        except CommandNotFoundError as exc:
            raise FileNotFoundError(args[0]) from exc
        except ProcessPermissionError as exc:
            raise PermissionError(args[0]) from exc
        except ProcessTimeoutError as exc:
            output, error = self._streams(exc.result, text=text)
            raise subprocess.TimeoutExpired(
                list(args),
                timeout,
                output=output,
                stderr=error,
            ) from exc

        stdout, stderr = self._streams(result, text=text)
        completed = subprocess.CompletedProcess(
            list(args),
            result.returncode if result.returncode is not None else 1,
            stdout,
            stderr,
        )
        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                completed.args,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return completed

    @staticmethod
    def _streams(result: ProcessResult, *, text: bool) -> tuple[Any, Any]:
        if text:
            return result.stdout, result.stderr
        return result.stdout.encode("utf-8"), result.stderr.encode("utf-8")


class SafeBuildCommandRunner:
    """Implement the BuildOnce runner protocol with bounded byte streams."""

    def __init__(self, adapter: SafeSubprocessAdapter):
        if not isinstance(adapter, SafeSubprocessAdapter):
            raise TypeError("adapter must be a SafeSubprocessAdapter")
        self.adapter = adapter

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str] | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.adapter(
            command,
            cwd=cwd,
            env=environment,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=False,
            shell=False,
        )
