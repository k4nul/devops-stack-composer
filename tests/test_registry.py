from __future__ import annotations

import json
import re
import subprocess
import unittest
from typing import Any
from unittest.mock import patch
from urllib.error import URLError

from devops_stack_composer.registry import (
    CONTAINER_NAME_LABEL,
    MANAGED_BY_LABEL,
    REGISTRY_IMAGE,
    RESOURCE_LABEL,
    RUN_ID_LABEL,
    EphemeralRegistry,
    RegistryError,
    RegistryHandle,
    RegistryOwnershipError,
)


CONTAINER_ID = "a" * 64


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"{}") -> None:
        self.status = status
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, limit: int = -1) -> bytes:
        return self.body[:limit]


class SequenceOpener:
    def __init__(self, *outcomes: int | BaseException) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[Any, float]] = []
        self.index = 0

    def __call__(self, request: Any, *, timeout: float) -> FakeResponse:
        self.calls.append((request, timeout))
        if not self.outcomes:
            raise AssertionError("no HTTP outcome configured")
        outcome = self.outcomes[min(self.index, len(self.outcomes) - 1)]
        self.index += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(outcome)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeDockerRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.call_options: list[dict[str, object]] = []
        self.exists = False
        self.inspect_data: dict[str, Any] | None = None
        self.host_ip = "127.0.0.1"
        self.host_port = "49153"
        self.run_failure: subprocess.CompletedProcess[str] | None = None
        self.network_failure: subprocess.CompletedProcess[str] | None = None
        self.confirm_network = True
        self.malformed_inspect = False
        self.log_stdout = ""
        self.log_stderr = "registry listening\n"
        self.raise_on_run: BaseException | None = None
        self.remove_persists = False

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        self.call_options.append(dict(kwargs))

        if command[:3] == ["docker", "run", "--detach"]:
            if self.raise_on_run is not None:
                raise self.raise_on_run
            if self.run_failure is not None:
                return self.run_failure
            name = command[command.index("--name") + 1]
            labels: dict[str, str] = {}
            for index, value in enumerate(command):
                if value == "--label":
                    key, label_value = command[index + 1].split("=", 1)
                    labels[key] = label_value
            self.exists = True
            self.inspect_data = {
                "Id": CONTAINER_ID,
                "Name": f"/{name}",
                "Config": {"Image": command[-1], "Labels": labels},
                "State": {"Running": True, "Status": "running", "ExitCode": 0, "Error": ""},
                "NetworkSettings": {
                    "Ports": {
                        "5000/tcp": [
                            {"HostIp": self.host_ip, "HostPort": self.host_port}
                        ]
                    },
                    "Networks": {"bridge": {}},
                },
            }
            return subprocess.CompletedProcess(command, 0, f"{CONTAINER_ID}\n", "")

        if command[:2] == ["docker", "inspect"]:
            if not self.exists:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "[]\n",
                    f"Error: No such object: {command[-1]}\n",
                )
            if self.malformed_inspect:
                return subprocess.CompletedProcess(command, 0, "not-json", "")
            return subprocess.CompletedProcess(command, 0, json.dumps([self.inspect_data]), "")

        if command[:3] == ["docker", "network", "connect"]:
            if self.network_failure is not None:
                return self.network_failure
            if self.confirm_network:
                assert self.inspect_data is not None
                self.inspect_data["NetworkSettings"]["Networks"][command[3]] = {}
            return subprocess.CompletedProcess(command, 0, "", "")

        if command[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(
                command,
                0,
                self.log_stdout,
                self.log_stderr,
            )

        if command[:2] == ["docker", "rm"]:
            if not self.remove_persists:
                self.exists = False
            return subprocess.CompletedProcess(command, 0, f"{command[-1]}\n", "")

        raise AssertionError(f"unexpected command: {command}")


class RegistryTests(unittest.TestCase):
    def make_registry(
        self,
        runner: FakeDockerRunner,
        opener: SequenceOpener | None = None,
        **kwargs: object,
    ) -> EphemeralRegistry:
        with patch("devops_stack_composer.registry.secrets.token_hex", return_value="0123456789ab"):
            return EphemeralRegistry(
                "Run_2026.08.30",
                command_runner=runner,
                http_opener=opener or SequenceOpener(200),
                **kwargs,
            )

    def test_start_uses_pinned_image_dynamic_loopback_port_and_ownership_labels(self) -> None:
        runner = FakeDockerRunner()
        opener = SequenceOpener(200)
        registry = self.make_registry(runner, opener)

        handle = registry.start()

        command = runner.calls[0]
        self.assertEqual(command[:3], ["docker", "run", "--detach"])
        self.assertEqual(command[-1], REGISTRY_IMAGE)
        self.assertEqual(
            REGISTRY_IMAGE,
            "docker.io/library/registry:3.1.1@"
            "sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33",
        )
        self.assertEqual(command[command.index("--publish") + 1], "127.0.0.1::5000")
        self.assertNotIn("--restart", command)
        self.assertNotIn("--rm", command)
        self.assertNotIn("0.0.0.0", " ".join(command))
        labels = {
            command[index + 1].split("=", 1)[0]: command[index + 1].split("=", 1)[1]
            for index, value in enumerate(command)
            if value == "--label"
        }
        self.assertEqual(labels[MANAGED_BY_LABEL], "devops-stack-composer")
        self.assertEqual(labels[RESOURCE_LABEL], "ephemeral-registry")
        self.assertEqual(labels[RUN_ID_LABEL], "Run_2026.08.30")
        self.assertEqual(labels[CONTAINER_NAME_LABEL], registry.name)
        self.assertRegex(registry.name, r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        self.assertLessEqual(len(registry.name), 63)
        self.assertEqual(handle.container_id, CONTAINER_ID)
        self.assertEqual(handle.host_port, 49153)
        self.assertEqual(handle.endpoint, "127.0.0.1:49153")
        self.assertEqual(handle.v2_url, "http://127.0.0.1:49153/v2/")
        self.assertTrue(handle.local_test_only)
        request, probe_timeout = opener.calls[0]
        self.assertEqual(request.full_url, handle.v2_url)
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertGreater(probe_timeout, 0)
        for options in runner.call_options:
            self.assertEqual(options["check"], False)
            self.assertEqual(options["capture_output"], True)
            self.assertEqual(options["text"], True)

    def test_handle_round_trip_and_reopen_verify_exact_owned_container(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        handle = registry.start()
        payload = handle.to_dict()

        self.assertEqual(
            set(payload),
            {"schemaVersion", "runId", "name", "containerId", "hostPort", "image"},
        )
        serialized = json.dumps(payload).lower()
        self.assertNotIn("path", serialized)
        self.assertNotIn("credential", serialized)
        self.assertNotIn("token", serialized)
        self.assertEqual(RegistryHandle.from_dict(payload), handle)

        before = len(runner.calls)
        reopened = EphemeralRegistry.reopen(
            payload,
            command_runner=runner,
            http_opener=SequenceOpener(200),
        )

        self.assertEqual(runner.calls[before:], [["docker", "inspect", registry.name]])
        self.assertEqual(reopened.handle, handle)
        self.assertTrue(reopened.status().owned)
        self.assertTrue(reopened.connect_kind_network("kind"))
        self.assertTrue(reopened.cleanup())

    def test_handle_parser_rejects_unknown_path_missing_and_invalid_identity_data(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        handle = registry.start()
        payload = handle.to_dict()

        invalid_payloads: list[object] = [
            [],
            {**payload, "dockerConfigPath": "/tmp/foreign"},
            {key: value for key, value in payload.items() if key != "containerId"},
            {**payload, "schemaVersion": "registry-ownership-v2"},
            {**payload, "runId": "-invalid"},
            {**payload, "name": "foreign-registry"},
            {**payload, "containerId": "b" * 63},
            {**payload, "hostPort": True},
            {**payload, "hostPort": 65536},
            {**payload, "image": "registry:latest"},
            {**payload, "host": "0.0.0.0"},
        ]
        for invalid in invalid_payloads:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                RegistryHandle.from_dict(invalid)  # type: ignore[arg-type]

        registry.cleanup()

    def test_reopen_refuses_foreign_replacement_or_changed_port_without_removal(self) -> None:
        for mutation in ("labels", "identity", "port", "image"):
            with self.subTest(mutation=mutation):
                runner = FakeDockerRunner()
                registry = self.make_registry(runner)
                payload = registry.start().to_dict()
                assert runner.inspect_data is not None
                if mutation == "labels":
                    runner.inspect_data["Config"]["Labels"][RUN_ID_LABEL] = "foreign"
                elif mutation == "identity":
                    runner.inspect_data["Id"] = "c" * 64
                elif mutation == "port":
                    runner.inspect_data["NetworkSettings"]["Ports"]["5000/tcp"][0][
                        "HostPort"
                    ] = "49154"
                else:
                    runner.inspect_data["Config"]["Image"] = "registry:latest"
                before = len(runner.calls)

                with self.assertRaises((RegistryError, RegistryOwnershipError)):
                    EphemeralRegistry.reopen(
                        payload,
                        command_runner=runner,
                        http_opener=SequenceOpener(200),
                    )

                self.assertTrue(runner.exists)
                self.assertFalse(
                    any(command[:2] == ["docker", "rm"] for command in runner.calls[before:])
                )

    def test_reopened_cleanup_rechecks_persisted_host_port(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        reopened = EphemeralRegistry.reopen(
            registry.start().to_dict(),
            command_runner=runner,
            http_opener=SequenceOpener(200),
        )
        assert runner.inspect_data is not None
        runner.inspect_data["NetworkSettings"]["Ports"]["5000/tcp"][0]["HostPort"] = (
            "49154"
        )

        with self.assertRaisesRegex(RegistryOwnershipError, "host-port binding changed"):
            reopened.cleanup()

        self.assertTrue(runner.exists)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_generated_names_are_unique_and_dns_safe(self) -> None:
        with patch(
            "devops_stack_composer.registry.secrets.token_hex",
            side_effect=("000000000001", "000000000002"),
        ):
            first = EphemeralRegistry("A_RUN")
            second = EphemeralRegistry("A_RUN")

        self.assertNotEqual(first.name, second.name)
        self.assertTrue(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", first.name))
        self.assertTrue(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", second.name))

    def test_invalid_run_ids_and_timeouts_are_rejected_without_docker(self) -> None:
        runner = FakeDockerRunner()
        for run_id in ("", "-leading", "space value", "x" * 65):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                EphemeralRegistry(run_id, command_runner=runner)
        for field in (
            "readiness_timeout_seconds",
            "poll_interval_seconds",
            "command_timeout_seconds",
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                EphemeralRegistry("run", command_runner=runner, **{field: 0})
        self.assertEqual(runner.calls, [])

    def test_start_failure_redacts_sensitive_docker_output(self) -> None:
        runner = FakeDockerRunner()
        runner.run_failure = subprocess.CompletedProcess(
            ["docker", "run"],
            125,
            "",
            (
                "Authorization: Bearer top-secret\n"
                "password=hunter2\n"
                "https://operator:credential@example.invalid/v2/\n"
            ),
        )
        registry = self.make_registry(runner)

        with self.assertRaises(RegistryError) as raised:
            registry.start()

        rendered = str(raised.exception)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("top-secret", rendered)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("operator:credential", rendered)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_readiness_timeout_captures_redacted_logs_then_removes_owned_container(self) -> None:
        runner = FakeDockerRunner()
        runner.log_stderr = "token=registry-secret\nfailed to listen\n"
        opener = SequenceOpener(URLError("password=probe-secret"))
        clock = FakeClock()
        registry = self.make_registry(
            runner,
            opener,
            readiness_timeout_seconds=0.03,
            poll_interval_seconds=0.01,
        )

        with patch(
            "devops_stack_composer.registry.time.monotonic",
            side_effect=clock.monotonic,
        ), patch(
            "devops_stack_composer.registry.time.sleep",
            side_effect=clock.sleep,
        ), self.assertRaises(RegistryError) as raised:
            registry.start()

        rendered = str(raised.exception)
        self.assertIn("readiness timed out", rendered)
        self.assertIn("failed to listen", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("registry-secret", rendered)
        self.assertNotIn("probe-secret", rendered)
        remove = next(command for command in runner.calls if command[:2] == ["docker", "rm"])
        self.assertEqual(remove, ["docker", "rm", "--force", "--volumes", CONTAINER_ID])
        self.assertFalse(runner.exists)
        self.assertTrue(clock.sleeps)

    def test_non_loopback_binding_is_rejected_and_owned_container_is_cleaned(self) -> None:
        runner = FakeDockerRunner()
        runner.host_ip = "0.0.0.0"
        registry = self.make_registry(runner)

        with self.assertRaisesRegex(RegistryError, "not restricted to loopback"):
            registry.start()

        self.assertFalse(runner.exists)
        self.assertTrue(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_cleanup_reinspects_labels_and_refuses_foreign_container(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()
        assert runner.inspect_data is not None
        runner.inspect_data["Config"]["Labels"][RUN_ID_LABEL] = "different-run"

        with self.assertRaisesRegex(RegistryOwnershipError, "ownership labels"):
            registry.cleanup()

        self.assertTrue(runner.exists)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_cleanup_refuses_replacement_with_same_name_and_labels(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()
        assert runner.inspect_data is not None
        runner.inspect_data["Id"] = "b" * 64

        with self.assertRaisesRegex(RegistryOwnershipError, "identity changed"):
            registry.cleanup()

        self.assertTrue(runner.exists)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_cleanup_targets_verified_immutable_id_and_is_idempotent(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()

        self.assertTrue(registry.cleanup())
        self.assertFalse(registry.cleanup())

        removes = [command for command in runner.calls if command[:2] == ["docker", "rm"]]
        self.assertEqual(removes, [["docker", "rm", "--force", "--volumes", CONTAINER_ID]])
        self.assertIsNone(registry.handle)

    def test_cleanup_requires_post_delete_absence(self) -> None:
        runner = FakeDockerRunner()
        runner.remove_persists = True
        registry = self.make_registry(runner)
        registry.start()

        with self.assertRaisesRegex(RegistryError, "still exists"):
            registry.cleanup()

        self.assertTrue(runner.exists)
        self.assertIsNotNone(registry.handle)

    def test_cleanup_before_start_never_inspects_or_removes(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)

        self.assertFalse(registry.cleanup())
        self.assertEqual(runner.calls, [])

    def test_connect_kind_network_is_owned_verified_and_idempotent(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()

        self.assertTrue(registry.connect_kind_network("kind"))
        self.assertFalse(registry.connect_kind_network("kind"))

        connects = [
            command for command in runner.calls if command[:3] == ["docker", "network", "connect"]
        ]
        self.assertEqual(connects, [["docker", "network", "connect", "kind", CONTAINER_ID]])
        self.assertIn("kind", registry.status().networks)

    def test_invalid_kind_network_name_is_rejected_before_docker(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()
        call_count = len(runner.calls)

        for name in ("", "Kind", "kind_default", "-kind", "kind/other"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                registry.connect_kind_network(name)

        self.assertEqual(len(runner.calls), call_count)

    def test_network_failure_is_redacted_and_does_not_remove_registry(self) -> None:
        runner = FakeDockerRunner()
        runner.network_failure = subprocess.CompletedProcess(
            ["docker", "network", "connect"],
            1,
            "",
            "token=network-secret",
        )
        registry = self.make_registry(runner)
        registry.start()

        with self.assertRaises(RegistryError) as raised:
            registry.connect_kind_network("kind")

        rendered = str(raised.exception)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("network-secret", rendered)
        self.assertTrue(runner.exists)

    def test_status_and_logs_are_bounded_and_redacted(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()
        assert runner.inspect_data is not None
        runner.inspect_data["State"] = {
            "Running": False,
            "Status": "exited",
            "ExitCode": 1,
            "Error": "password=state-secret",
        }
        runner.log_stdout = "Authorization: Bearer log-secret\nuseful diagnostic\n"
        runner.log_stderr = ""

        status = registry.status(include_logs=True)

        self.assertTrue(status.exists)
        self.assertTrue(status.owned)
        self.assertFalse(status.running)
        self.assertEqual(status.state, "exited")
        self.assertEqual(status.exit_code, 1)
        self.assertIn("<redacted>", status.error)
        self.assertIn("useful diagnostic", status.logs)
        self.assertNotIn("state-secret", status.error)
        self.assertNotIn("log-secret", status.logs)
        registry.logs(tail=12)
        self.assertIn(["docker", "logs", "--tail", "12", CONTAINER_ID], runner.calls)

    def test_foreign_status_does_not_capture_or_expose_details(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()
        assert runner.inspect_data is not None
        runner.inspect_data["Config"]["Labels"] = {"secret": "foreign-value"}
        before = len([command for command in runner.calls if command[:2] == ["docker", "logs"]])

        status = registry.status(include_logs=True)

        after = len([command for command in runner.calls if command[:2] == ["docker", "logs"]])
        self.assertTrue(status.exists)
        self.assertFalse(status.owned)
        self.assertEqual(status.container_id, "")
        self.assertEqual(status.logs, "")
        self.assertEqual(before, after)

    def test_malformed_inspect_never_triggers_unverified_removal(self) -> None:
        runner = FakeDockerRunner()
        runner.malformed_inspect = True
        registry = self.make_registry(runner)

        with self.assertRaisesRegex(RegistryError, "malformed registry inspection"):
            registry.start()

        self.assertTrue(runner.exists)
        self.assertFalse(any(command[:2] == ["docker", "rm"] for command in runner.calls))

    def test_command_timeout_is_safely_reported(self) -> None:
        runner = FakeDockerRunner()
        runner.raise_on_run = subprocess.TimeoutExpired(
            ["docker", "run"],
            30,
            stderr="password=timeout-secret",
        )
        registry = self.make_registry(runner)

        with self.assertRaises(RegistryError) as raised:
            registry.start()

        rendered = str(raised.exception)
        self.assertIn("timed out", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("timeout-secret", rendered)

    def test_readiness_retries_non_200_response_then_succeeds(self) -> None:
        runner = FakeDockerRunner()
        opener = SequenceOpener(503, 200)
        registry = self.make_registry(runner, opener, poll_interval_seconds=0.001)

        handle = registry.start()

        self.assertEqual(handle.host_port, 49153)
        self.assertEqual(len(opener.calls), 2)
        self.assertTrue(runner.exists)

    def test_second_start_is_blocked_without_another_docker_run(self) -> None:
        runner = FakeDockerRunner()
        registry = self.make_registry(runner)
        registry.start()

        with self.assertRaisesRegex(RegistryError, "already been started"):
            registry.start()

        runs = [command for command in runner.calls if command[:3] == ["docker", "run", "--detach"]]
        self.assertEqual(len(runs), 1)


if __name__ == "__main__":
    unittest.main()
