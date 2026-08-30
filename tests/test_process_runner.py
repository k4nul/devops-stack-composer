from __future__ import annotations

import io
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from devops_stack_composer.process_runner import (
    CancellationToken,
    CommandNotFoundError,
    NonZeroExitError,
    ProcessCancelledError,
    ProcessErrorCategory,
    ProcessPermissionError,
    ProcessTimeoutError,
    SafeProcessRunner,
    UnsafeProcessRequestError,
)


class FakeClock:
    def __init__(self, *, on_sleep=None):
        self.value = 0.0
        self.on_sleep = on_sleep
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.value += duration
        if self.on_sleep is not None:
            self.on_sleep()


class FakeProcess:
    def __init__(
        self,
        returncode: int | None = 0,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ):
        self.pid = 4242
        self.returncode = returncode
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -signal.SIGTERM

    def kill(self) -> None:
        self.killed = True
        self.returncode = -signal.SIGKILL


class FakeLauncher:
    def __init__(self, process: FakeProcess | BaseException):
        self.process = process
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **options: object) -> FakeProcess:
        self.calls.append((command, options))
        if isinstance(self.process, BaseException):
            raise self.process
        return self.process


class SafeProcessRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.child = self.root / "child"
        self.child.mkdir()

    def runner(self, launcher, **options) -> SafeProcessRunner:
        return SafeProcessRunner(
            self.root,
            allowed_executables={"tool"},
            allowed_environment_keys={"PATH", "SAFE", "API_TOKEN"},
            inherited_environment_keys={"PATH"},
            base_environment={
                "PATH": "/trusted/bin",
                "HOME": "/must-not-leak",
                "HOST_TOKEN": "must-not-leak",
            },
            launcher=launcher,
            poll_interval=0.01,
            termination_grace=0.03,
            **options,
        )

    def test_launches_only_an_argv_without_a_shell_or_full_host_environment(self) -> None:
        launcher = FakeLauncher(FakeProcess(stdout=b"ok\n"))
        result = self.runner(launcher).run(
            ["tool", "inspect", "value with spaces"],
            cwd=self.child,
            environment={"SAFE": "yes"},
        )

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stdout, "ok\n")
        command, options = launcher.calls[0]
        self.assertEqual(command, ["tool", "inspect", "value with spaces"])
        self.assertIs(options["shell"], False)
        self.assertEqual(options["cwd"], str(self.child.resolve()))
        self.assertEqual(options["env"], {"PATH": "/trusted/bin", "SAFE": "yes"})
        self.assertNotIn("HOME", options["env"])
        self.assertNotIn("HOST_TOKEN", options["env"])
        if os.name == "posix":
            self.assertIs(options["start_new_session"], True)

    def test_rejects_shell_strings_unlisted_tools_escaped_cwd_and_environment(self) -> None:
        launcher = FakeLauncher(FakeProcess())
        runner = self.runner(launcher)
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        escape = self.root / "escape"
        escape.symlink_to(outside, target_is_directory=True)

        invalid_calls = (
            lambda: runner.run("tool inspect"),
            lambda: runner.run(["other"]),
            lambda: runner.run(["tool"], cwd=outside),
            lambda: runner.run(["tool"], cwd=escape),
            lambda: runner.run(["tool"], environment={"SECRET": "value"}),
            lambda: runner.run(["tool"], environment={"PATH": "/attacker/bin"}),
            lambda: runner.run(["tool", "x" * 8193]),
            lambda: runner.run(["tool"], environment={"SAFE": "x" * 16385}),
            lambda: runner.run(["tool"], redact_values=("x" * 8193,)),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(UnsafeProcessRequestError):
                    call()

        self.assertEqual(launcher.calls, [])

    def test_bounds_and_redacts_both_streams_and_recorded_argv(self) -> None:
        process = FakeProcess(
            stdout=b"raw-api-secret\npassword=hunter2\n" + b"x" * 500,
            stderr=b"failed https://user:password@example.invalid/path\n",
        )
        launcher = FakeLauncher(process)
        runner = self.runner(launcher, max_output_bytes=80)

        result = runner.run(
            [
                "tool",
                "--token",
                "argument-secret",
                "https://name:password@example.invalid/resource",
            ],
            environment={"API_TOKEN": "raw-api-secret"},
        )

        self.assertNotIn("raw-api-secret", result.stdout)
        self.assertNotIn("hunter2", result.stdout)
        self.assertIn("<redacted>", result.stdout)
        self.assertTrue(result.stdout_truncated)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 80)
        self.assertNotIn("user:password", result.stderr)
        self.assertIn("<redacted>", result.stderr)
        self.assertEqual(result.argv[2], "<redacted>")
        self.assertNotIn("name:password", result.argv[3])
        self.assertEqual(launcher.calls[0][0][2], "argument-secret")

    def test_classifies_launch_and_nonzero_failures_with_sanitized_results(self) -> None:
        cases = (
            (
                FakeLauncher(FileNotFoundError("not found")),
                CommandNotFoundError,
                ProcessErrorCategory.COMMAND_NOT_FOUND,
            ),
            (
                FakeLauncher(PermissionError("denied")),
                ProcessPermissionError,
                ProcessErrorCategory.PERMISSION,
            ),
            (
                FakeLauncher(
                    FakeProcess(
                        7,
                        stderr=b"authorization: Bearer should-not-leak\n",
                    )
                ),
                NonZeroExitError,
                ProcessErrorCategory.NONZERO,
            ),
        )

        for launcher, error_type, category in cases:
            with self.subTest(category=category):
                with self.assertRaises(error_type) as raised:
                    self.runner(launcher).run(["tool"])
                self.assertEqual(raised.exception.category, category)
                self.assertEqual(raised.exception.result.category, category)
                self.assertNotIn("should-not-leak", raised.exception.result.stderr)
                self.assertNotIn("should-not-leak", str(raised.exception))
                if category == ProcessErrorCategory.NONZERO:
                    self.assertEqual(raised.exception.result.returncode, 7)
                else:
                    self.assertIsNone(raised.exception.result.returncode)

    def test_per_command_timeout_terminates_then_kills_the_posix_process_group(self) -> None:
        process = FakeProcess(None, stdout=b"partial output\n")
        launcher = FakeLauncher(process)
        clock = FakeClock()
        sent_signals: list[tuple[int, int]] = []

        def kill_group(pid: int, requested_signal: int) -> None:
            sent_signals.append((pid, requested_signal))
            if requested_signal == signal.SIGKILL:
                process.returncode = -requested_signal

        runner = self.runner(
            launcher,
            monotonic=clock,
            sleeper=clock.sleep,
            process_group_kill=kill_group,
        )

        with self.assertRaises(ProcessTimeoutError) as raised:
            runner.run(["tool"], timeout=0.025)

        self.assertEqual(raised.exception.category, ProcessErrorCategory.TIMEOUT)
        self.assertEqual(raised.exception.result.stdout, "partial output\n")
        if os.name == "posix":
            self.assertEqual(
                sent_signals,
                [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)],
            )
        else:
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)

    def test_overall_deadline_wins_over_a_longer_per_command_timeout(self) -> None:
        process = FakeProcess(None)
        launcher = FakeLauncher(process)
        clock = FakeClock()

        def kill_group(_pid: int, requested_signal: int) -> None:
            process.returncode = -requested_signal

        runner = self.runner(
            launcher,
            overall_deadline=0.02,
            monotonic=clock,
            sleeper=clock.sleep,
            process_group_kill=kill_group,
        )

        with self.assertRaises(ProcessTimeoutError) as raised:
            runner.run(["tool"], timeout=10)

        self.assertGreaterEqual(raised.exception.result.duration_seconds, 0.02)
        self.assertLess(raised.exception.result.duration_seconds, 10)

    def test_cancellation_prevents_launch_and_stops_an_active_process(self) -> None:
        before_launch = CancellationToken()
        before_launch.cancel()
        unused_launcher = FakeLauncher(FakeProcess())
        with self.assertRaises(ProcessCancelledError):
            self.runner(unused_launcher).run(
                ["tool"], cancellation_token=before_launch
            )
        self.assertEqual(unused_launcher.calls, [])

        token = CancellationToken()
        process = FakeProcess(None)
        launcher = FakeLauncher(process)
        clock = FakeClock(on_sleep=token.cancel)
        sent_signals: list[int] = []

        def kill_group(_pid: int, requested_signal: int) -> None:
            sent_signals.append(requested_signal)
            process.returncode = -requested_signal

        runner = self.runner(
            launcher,
            monotonic=clock,
            sleeper=clock.sleep,
            process_group_kill=kill_group,
        )
        with self.assertRaises(ProcessCancelledError) as raised:
            runner.run(["tool"], cancellation_token=token)

        self.assertEqual(raised.exception.category, ProcessErrorCategory.CANCELLED)
        if os.name == "posix":
            self.assertEqual(sent_signals, [signal.SIGTERM])
        else:
            self.assertTrue(process.terminated)

    def test_expired_deadline_is_typed_and_does_not_launch(self) -> None:
        launcher = FakeLauncher(FakeProcess())
        clock = FakeClock()
        runner = self.runner(
            launcher,
            overall_deadline=0.0,
            monotonic=clock,
            sleeper=clock.sleep,
        )

        with self.assertRaises(ProcessTimeoutError) as raised:
            runner.run(["tool"])

        self.assertEqual(raised.exception.category.value, "timeout")
        self.assertEqual(launcher.calls, [])

    def test_real_process_round_trip_uses_the_same_bounded_text_contract(self) -> None:
        runner = SafeProcessRunner(
            self.root,
            allowed_executables={sys.executable},
            allowed_environment_keys=(),
            inherited_environment_keys=(),
            base_environment={},
            max_output_bytes=128,
        )

        result = runner.run(
            [sys.executable, "-c", "print('token=real-secret'); print('done')"],
            timeout=2,
        )

        self.assertTrue(result.succeeded)
        self.assertNotIn("real-secret", result.stdout)
        self.assertIn("token=<redacted>", result.stdout)
        self.assertIn("done", result.stdout)

    def test_managed_process_waits_for_its_own_output_then_reaps_on_close(self) -> None:
        process = FakeProcess(
            None,
            stdout=b"Forwarding from 127.0.0.1:45123 -> 8080\n",
        )
        launcher = FakeLauncher(process)

        def kill_group(_pid: int, requested_signal: int) -> None:
            process.returncode = -requested_signal

        runner = self.runner(launcher, process_group_kill=kill_group)
        managed = runner.start(
            ["tool", "port-forward", ":8080"],
            cwd=self.child,
            environment={"SAFE": "yes"},
            timeout=10,
        )

        match = managed.wait_for_output(
            re.compile(r"(?m)^Forwarding from 127\.0\.0\.1:([0-9]+) -> 8080$"),
            timeout=1,
        )

        self.assertEqual(match.group(1), "45123")
        self.assertTrue(managed.close(timeout=1))
        self.assertIsNotNone(process.returncode)
        command, options = launcher.calls[0]
        self.assertEqual(command, ["tool", "port-forward", ":8080"])
        self.assertEqual(options["cwd"], str(self.child.resolve()))
        self.assertEqual(options["env"], {"PATH": "/trusted/bin", "SAFE": "yes"})
        self.assertIs(options["shell"], False)

    def test_managed_process_external_cancellation_is_classified_and_reaped(self) -> None:
        token = CancellationToken()
        process = FakeProcess(None, stderr=b"password=managed-secret\n")
        launcher = FakeLauncher(process)

        def kill_group(_pid: int, requested_signal: int) -> None:
            process.returncode = -requested_signal

        managed = self.runner(
            launcher,
            process_group_kill=kill_group,
        ).start(["tool"], cancellation_token=token, timeout=10)
        token.cancel()

        with self.assertRaises(ProcessCancelledError) as raised:
            managed.wait(timeout=1)

        self.assertIsNotNone(process.returncode)
        self.assertNotIn("managed-secret", raised.exception.result.stderr)
        self.assertIn("<redacted>", raised.exception.result.stderr)

    def test_managed_process_deadline_is_classified_and_reaped(self) -> None:
        process = FakeProcess(None)
        launcher = FakeLauncher(process)
        clock = FakeClock()

        def kill_group(_pid: int, requested_signal: int) -> None:
            process.returncode = -requested_signal

        managed = self.runner(
            launcher,
            monotonic=clock,
            sleeper=clock.sleep,
            process_group_kill=kill_group,
        ).start(["tool"], timeout=0.025)

        with self.assertRaises(ProcessTimeoutError) as raised:
            managed.wait(timeout=1)

        self.assertEqual(raised.exception.category, ProcessErrorCategory.TIMEOUT)
        self.assertIsNotNone(process.returncode)

    def test_real_managed_process_streams_readiness_before_exit(self) -> None:
        runner = SafeProcessRunner(
            self.root,
            allowed_executables={sys.executable},
            allowed_environment_keys=(),
            inherited_environment_keys=(),
            base_environment={},
            max_output_bytes=256,
        )
        managed = runner.start(
            [
                sys.executable,
                "-c",
                (
                    "import time; "
                    "print('Forwarding from 127.0.0.1:45123 -> 8080', flush=True); "
                    "time.sleep(10)"
                ),
            ],
            timeout=2,
        )

        match = managed.wait_for_output(
            re.compile(r"(?m)^Forwarding from 127\.0\.0\.1:([0-9]+) -> 8080$"),
            timeout=1,
        )

        self.assertEqual(match.group(1), "45123")
        self.assertTrue(managed.close(timeout=1))


if __name__ == "__main__":
    unittest.main()
