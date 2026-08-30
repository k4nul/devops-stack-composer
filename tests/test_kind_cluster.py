from __future__ import annotations

import json
from pathlib import Path
import re
import stat
import subprocess
import unittest
from typing import Any
from unittest.mock import patch

from devops_stack_composer.kind_cluster import (
    API_SERVER_ADDRESS,
    KIND_CLUSTER_LABEL,
    KIND_NETWORK_NAME,
    KIND_NODE_IMAGE,
    KIND_ROLE_LABEL,
    KIND_VERSION,
    KindCluster,
    KindClusterCollisionError,
    KindClusterError,
    KindClusterHandle,
    KindClusterOwnershipError,
    KindVersionError,
)
from devops_stack_composer.registry import REGISTRY_IMAGE, RegistryHandle


NODE_ID = "a" * 64
REGISTRY_ID = "b" * 64


class FakeKindRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.call_options: list[dict[str, object]] = []
        self.version_output = "kind v0.33.0 go1.25.0 linux/amd64\n"
        self.clusters: set[str] = set()
        self.nodes: dict[str, list[str]] = {}
        self.containers: dict[str, dict[str, Any]] = {}
        self.created_config = ""
        self.config_mode: int | None = None
        self.kubeconfig_mode: int | None = None
        self.container_files: dict[tuple[str, str], str] = {}
        self.configmap_data: str | None = None
        self.create_failure: subprocess.CompletedProcess[str] | None = None
        self.delete_failure: subprocess.CompletedProcess[str] | None = None
        self.copy_round_trip_override: str | None = None
        self.kubeconfig_failure: subprocess.CompletedProcess[str] | None = None
        self.ready = True

    def __call__(
        self,
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        self.call_options.append(dict(kwargs))

        if command == ["kind", "version"]:
            return self._completed(command, stdout=self.version_output)

        if command == ["kind", "get", "clusters"]:
            stdout = "".join(f"{name}\n" for name in sorted(self.clusters))
            return self._completed(command, stdout=stdout)

        if command[:3] == ["kind", "create", "cluster"]:
            if self.create_failure is not None:
                return self.create_failure
            name = command[command.index("--name") + 1]
            image = command[command.index("--image") + 1]
            config = Path(command[command.index("--config") + 1])
            kubeconfig = Path(command[command.index("--kubeconfig") + 1])
            self.created_config = config.read_text(encoding="utf-8")
            self.config_mode = stat.S_IMODE(config.stat().st_mode)
            self.kubeconfig_mode = stat.S_IMODE(kubeconfig.stat().st_mode)
            kubeconfig.write_text("apiVersion: v1\n", encoding="utf-8")
            node_name = f"{name}-control-plane"
            self.clusters.add(name)
            self.nodes[name] = [node_name]
            self.containers[NODE_ID] = {
                "Id": NODE_ID,
                "Name": f"/{node_name}",
                "Config": {
                    "Image": image,
                    "Labels": {
                        KIND_CLUSTER_LABEL: name,
                        KIND_ROLE_LABEL: "control-plane",
                    },
                },
            }
            return self._completed(command, stderr=f'Created cluster "{name}"\n')

        if command[:4] == ["kind", "get", "nodes", "--name"]:
            name = command[4]
            if name not in self.clusters:
                return self._completed(command, 1, stderr="No kind nodes found.\n")
            return self._completed(
                command,
                stdout="".join(f"{node}\n" for node in self.nodes[name]),
            )

        if command[:4] == ["kind", "get", "kubeconfig", "--name"]:
            if self.kubeconfig_failure is not None:
                return self.kubeconfig_failure
            name = command[4]
            if name not in self.clusters:
                return self._completed(command, 1, stderr="cluster does not exist\n")
            return self._completed(
                command,
                stdout=(
                    "apiVersion: v1\n"
                    "kind: Config\n"
                    f"current-context: kind-{name}\n"
                ),
            )

        if command[:2] == ["docker", "inspect"]:
            inspected: list[dict[str, Any]] = []
            for target in command[2:]:
                match = self.containers.get(target)
                if match is None:
                    match = next(
                        (
                            item
                            for item in self.containers.values()
                            if item.get("Name") == f"/{target}"
                        ),
                        None,
                    )
                if match is None:
                    return self._completed(command, 1, stderr="No such object\n")
                inspected.append(match)
            return self._completed(command, stdout=json.dumps(inspected))

        if command[:3] == ["docker", "exec", NODE_ID]:
            if command[3:5] == ["mkdir", "-p"]:
                return self._completed(command)
            if command[3] == "cat":
                content = self.container_files.get((NODE_ID, command[4]), "")
                if self.copy_round_trip_override is not None:
                    content = self.copy_round_trip_override
                return self._completed(command, stdout=content)

        if command[:2] == ["docker", "cp"]:
            source = Path(command[2])
            container_id, separator, destination = command[3].partition(":")
            if container_id == NODE_ID and separator:
                self.container_files[(NODE_ID, destination)] = source.read_text(
                    encoding="utf-8"
                )
                return self._completed(command)

        if command[:3] == ["kubectl", "--kubeconfig", command[2]]:
            if command[3] != "--cache-dir":
                raise AssertionError("kubectl must use the private cache directory")
            cache_path = Path(command[4])
            if not cache_path.is_dir():
                raise AssertionError("kubectl cache directory must exist")
            if stat.S_IMODE(cache_path.stat().st_mode) != 0o700:
                raise AssertionError("kubectl cache directory must be private")
            action = command[5:]
            if action[:2] == ["apply", "-f"]:
                manifest_path = Path(action[2])
                manifest = manifest_path.read_text(encoding="utf-8")
                host_line = next(
                    line.strip()
                    for line in manifest.splitlines()
                    if line.strip().startswith("host:")
                )
                help_line = next(
                    line.strip()
                    for line in manifest.splitlines()
                    if line.strip().startswith("help:")
                )
                self.configmap_data = f"{host_line}\n{help_line}\n"
                return self._completed(
                    command,
                    stdout="configmap/local-registry-hosting configured\n",
                )
            if action[:4] == ["get", "nodes", "-o", "json"]:
                items = []
                for names in self.nodes.values():
                    for name in names:
                        items.append(
                            {
                                "metadata": {"name": name},
                                "status": {
                                    "conditions": [
                                        {
                                            "type": "Ready",
                                            "status": "True" if self.ready else "False",
                                        }
                                    ]
                                },
                            }
                        )
                return self._completed(command, stdout=json.dumps({"items": items}))
            if action[:3] == ["get", "configmap", "local-registry-hosting"]:
                return self._completed(
                    command,
                    stdout=json.dumps(
                        {"data": {"localRegistryHosting.v1": self.configmap_data}}
                    ),
                )

        if command[:3] == ["kind", "delete", "cluster"]:
            if self.delete_failure is not None:
                return self.delete_failure
            name = command[command.index("--name") + 1]
            node_names = set(self.nodes.pop(name, []))
            self.clusters.discard(name)
            self.containers = {
                container_id: item
                for container_id, item in self.containers.items()
                if str(item.get("Name", "")).removeprefix("/") not in node_names
            }
            return self._completed(command, stdout=f"Deleted nodes: {sorted(node_names)!r}\n")

        raise AssertionError(f"unexpected command: {command}")

    @staticmethod
    def _completed(
        command: list[str],
        returncode: int = 0,
        *,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class FakeRegistryLifecycle:
    def __init__(self, run_id: str, *, port: int = 49153) -> None:
        slug = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
        slug = slug[:20].rstrip("-") or "run"
        self.handle: RegistryHandle | None = RegistryHandle(
            run_id=run_id,
            name=f"devops-stack-registry-{slug}-0123456789ab",
            container_id=REGISTRY_ID,
            host_port=port,
            image=REGISTRY_IMAGE,
        )
        self.connect_calls: list[str] = []

    def connect_kind_network(self, network_name: str) -> bool:
        self.connect_calls.append(network_name)
        return True


class KindClusterTests(unittest.TestCase):
    def make_cluster(self, runner: FakeKindRunner, **kwargs: object) -> KindCluster:
        with patch(
            "devops_stack_composer.kind_cluster.secrets.token_hex",
            return_value="0123456789ab",
        ):
            return KindCluster("Run_2026.08.30", command_runner=runner, **kwargs)

    def test_create_uses_exact_pins_loopback_config_and_private_runtime_files(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)

        handle = cluster.create()

        self.assertEqual(KIND_VERSION, "v0.33.0")
        self.assertEqual(
            KIND_NODE_IMAGE,
            "kindest/node:v1.36.4@"
            "sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed",
        )
        create = next(
            command
            for command in runner.calls
            if command[:3] == ["kind", "create", "cluster"]
        )
        self.assertEqual(create[create.index("--image") + 1], KIND_NODE_IMAGE)
        self.assertIn("--retain", create)
        self.assertIn('apiServerAddress: "127.0.0.1"', runner.created_config)
        self.assertNotIn("0.0.0.0", runner.created_config)
        self.assertEqual(API_SERVER_ADDRESS, "127.0.0.1")
        self.assertEqual(runner.config_mode, 0o600)
        self.assertEqual(runner.kubeconfig_mode, 0o600)
        assert cluster.config_path is not None
        assert cluster.kubeconfig_path is not None
        self.assertEqual(stat.S_IMODE(cluster.config_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(cluster.config_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(cluster.kubeconfig_path.stat().st_mode), 0o600)
        self.assertFalse(hasattr(handle, "kubeconfig_path"))
        self.assertEqual(handle.node_image, KIND_NODE_IMAGE)
        self.assertEqual(handle.context, f"kind-{cluster.name}")
        self.assertEqual(handle.nodes, (f"{cluster.name}-control-plane",))
        self.assertEqual(handle.node_container_ids, (NODE_ID,))
        recovery = cluster.recovery_identity
        assert recovery is not None
        self.assertEqual(recovery.run_id, cluster.run_id)
        self.assertEqual(recovery.name, cluster.name)
        self.assertEqual(recovery.context, handle.context)
        self.assertEqual(recovery.node_image, KIND_NODE_IMAGE)
        self.assertEqual(recovery.nodes[0].name, handle.nodes[0])
        self.assertEqual(recovery.nodes[0].container_id, NODE_ID)
        self.assertEqual(recovery.nodes[0].role, "control-plane")
        for options in runner.call_options:
            self.assertFalse(options["check"])
            self.assertTrue(options["capture_output"])
            self.assertTrue(options["text"])
            self.assertNotIn("input", options)
        cluster.destroy()
        self.assertIsNone(cluster.recovery_identity)

    def test_generated_names_are_unique_dns_safe_and_run_scoped(self) -> None:
        with patch(
            "devops_stack_composer.kind_cluster.secrets.token_hex",
            side_effect=("000000000001", "000000000002"),
        ):
            first = KindCluster("A_RUN")
            second = KindCluster("A_RUN")

        self.assertNotEqual(first.name, second.name)
        self.assertRegex(first.name, r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        self.assertLessEqual(len(first.name), 63)
        self.assertIn("a-run", first.name)

    def test_invalid_run_ids_and_timeouts_do_not_invoke_tools(self) -> None:
        runner = FakeKindRunner()
        for run_id in ("", "-run", "space value", "x" * 65):
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                KindCluster(run_id, command_runner=runner)
        for field in ("command_timeout_seconds", "create_timeout_seconds"):
            for value in (0, float("inf"), True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    KindCluster("run", command_runner=runner, **{field: value})
        self.assertEqual(runner.calls, [])

    def test_wrong_kind_version_fails_before_inventory_or_tempfiles(self) -> None:
        runner = FakeKindRunner()
        runner.version_output = "kind v0.33.1 go1.25.0 linux/amd64\n"
        cluster = self.make_cluster(runner)

        with self.assertRaisesRegex(KindVersionError, "v0.33.0"):
            cluster.create()

        self.assertEqual(runner.calls, [["kind", "version"]])
        self.assertIsNone(cluster.config_path)
        self.assertIsNone(cluster.kubeconfig_path)

    def test_name_collision_is_detected_before_create_or_tempfiles(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        runner.clusters.add(cluster.name)

        with self.assertRaises(KindClusterCollisionError):
            cluster.create()

        self.assertFalse(
            any(
                command[:3] == ["kind", "create", "cluster"]
                for command in runner.calls
            )
        )
        self.assertIsNone(cluster.kubeconfig_path)

    def test_create_failure_is_retained_and_sensitive_diagnostics_are_redacted(self) -> None:
        runner = FakeKindRunner()
        runner.create_failure = subprocess.CompletedProcess(
            ["kind", "create", "cluster"],
            1,
            "",
            "Authorization: Bearer cluster-secret\npassword=hunter2\ncreate failed\n",
        )
        cluster = self.make_cluster(runner)

        with self.assertRaises(KindClusterError) as raised:
            cluster.create()

        rendered = f"{raised.exception}\n{cluster.diagnostics}"
        self.assertIn("create failed", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("cluster-secret", rendered)
        self.assertNotIn("hunter2", rendered)
        create = next(
            command
            for command in runner.calls
            if command[:3] == ["kind", "create", "cluster"]
        )
        self.assertIn("--retain", create)
        self.assertFalse(
            any(
                command[:3] == ["kind", "delete", "cluster"]
                for command in runner.calls
            )
        )
        kubeconfig = Path(create[create.index("--kubeconfig") + 1])
        self.assertFalse(kubeconfig.parent.exists())
        self.assertIsNone(cluster.kubeconfig_path)

    def test_unverifiable_post_create_nodes_are_retained_not_deleted(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)

        original = runner.__call__

        def corrupting_runner(
            command: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            result = original(command, **kwargs)
            if command[:3] == ["kind", "create", "cluster"]:
                runner.containers[NODE_ID]["Config"]["Labels"][KIND_CLUSTER_LABEL] = "foreign"
            return result

        cluster._command_runner = corrupting_runner
        with self.assertRaisesRegex(KindClusterOwnershipError, "manual inspection"):
            cluster.create()

        self.assertTrue(runner.clusters)
        self.assertFalse(
            any(
                command[:3] == ["kind", "delete", "cluster"]
                for command in runner.calls
            )
        )
        self.assertIsNone(cluster.kubeconfig_path)
        cluster.close()
        self.assertTrue(runner.clusters)

    def test_status_reports_ready_owned_cluster_and_fails_closed_on_replacement(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()

        status = cluster.status()

        self.assertTrue(status.exists)
        self.assertTrue(status.owned)
        self.assertTrue(status.ready)
        self.assertEqual(status.nodes, (f"{cluster.name}-control-plane",))

        runner.containers[NODE_ID]["Id"] = "c" * 64
        kubectl_before = len([call for call in runner.calls if call[0] == "kubectl"])
        replaced = cluster.status()
        kubectl_after = len([call for call in runner.calls if call[0] == "kubectl"])

        self.assertTrue(replaced.exists)
        self.assertFalse(replaced.owned)
        self.assertFalse(replaced.ready)
        self.assertEqual(kubectl_before, kubectl_after)
        cluster.detach()

    def test_handle_round_trip_detach_and_reopen_verify_before_private_kubeconfig(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        handle = cluster.create()
        payload = handle.to_dict()
        assert cluster.kubeconfig_path is not None
        first_runtime = cluster.kubeconfig_path.parent

        self.assertEqual(
            set(payload),
            {"schemaVersion", "runId", "name", "nodeImage", "nodes"},
        )
        self.assertNotIn("kubeconfig", json.dumps(payload).lower())
        self.assertNotIn("path", json.dumps(payload).lower())
        self.assertEqual(KindClusterHandle.from_dict(payload), handle)
        self.assertEqual(cluster.detach(), handle)
        self.assertFalse(first_runtime.exists())
        self.assertFalse(
            any(command[:3] == ["kind", "delete", "cluster"] for command in runner.calls)
        )

        reopen_call_start = len(runner.calls)
        reopened = KindCluster.reopen(payload, command_runner=runner)

        calls = runner.calls[reopen_call_start:]
        kubeconfig_call = ["kind", "get", "kubeconfig", "--name", handle.name]
        self.assertIn(kubeconfig_call, calls)
        self.assertLess(calls.index(["docker", "inspect", NODE_ID]), calls.index(kubeconfig_call))
        self.assertEqual(reopened.handle, handle)
        assert reopened.kubeconfig_path is not None
        self.assertEqual(stat.S_IMODE(reopened.kubeconfig_path.stat().st_mode), 0o600)
        self.assertIn(
            f"current-context: kind-{handle.name}",
            reopened.kubeconfig_path.read_text(encoding="utf-8"),
        )
        self.assertTrue(reopened.status().owned)
        self.assertTrue(reopened.destroy())

    def test_handle_parser_rejects_unknown_path_missing_and_invalid_identity_data(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        handle = cluster.create()
        payload = handle.to_dict()
        cluster.detach()

        invalid_payloads: list[object] = [
            [],
            {**payload, "kubeconfigPath": "/tmp/foreign"},
            {key: value for key, value in payload.items() if key != "nodeImage"},
            {**payload, "schemaVersion": "kind-cluster-ownership-v2"},
            {**payload, "runId": "-invalid"},
            {**payload, "name": "foreign-control-plane"},
            {**payload, "nodeImage": "kindest/node:latest"},
            {**payload, "nodes": []},
            {
                **payload,
                "nodes": [
                    {
                        "name": handle.nodes[0],
                        "containerId": NODE_ID,
                        "kubeconfigPath": "/tmp/foreign",
                    }
                ],
            },
            {
                **payload,
                "nodes": [{"name": handle.nodes[0], "containerId": "b" * 63}],
            },
        ]
        for invalid in invalid_payloads:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                KindClusterHandle.from_dict(invalid)  # type: ignore[arg-type]

        reopened = KindCluster.reopen(payload, command_runner=runner)
        reopened.destroy()

    def test_reopen_refuses_replacement_before_kubeconfig_or_delete(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        payload = cluster.create().to_dict()
        cluster.detach()
        replacement = dict(runner.containers.pop(NODE_ID))
        replacement["Id"] = "c" * 64
        runner.containers["c" * 64] = replacement
        before = len(runner.calls)

        with self.assertRaises(KindClusterOwnershipError):
            KindCluster.reopen(payload, command_runner=runner)

        calls = runner.calls[before:]
        self.assertFalse(any(command[:3] == ["kind", "delete", "cluster"] for command in calls))
        self.assertFalse(any(command[:3] == ["kind", "get", "kubeconfig"] for command in calls))

    def test_reopen_kubeconfig_failure_never_persists_stdout_or_runtime_files(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        payload = cluster.create().to_dict()
        cluster.detach()
        runner.kubeconfig_failure = subprocess.CompletedProcess(
            ["kind", "get", "kubeconfig"],
            1,
            "token=stdout-secret\n",
            "Authorization: Bearer stderr-secret\nfailed\n",
        )

        with self.assertRaises(KindClusterError) as raised:
            KindCluster.reopen(payload, command_runner=runner)

        rendered = str(raised.exception)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("stdout-secret", rendered)
        self.assertNotIn("stderr-secret", rendered)

    def test_configure_registry_uses_official_hosts_alias_network_api_and_configmap(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        registry = FakeRegistryLifecycle(cluster.run_id, port=49153)

        configured = cluster.configure_local_registry(registry)  # type: ignore[arg-type]

        registry_directory = "/etc/containerd/certs.d/localhost:49153"
        hosts_path = f"{registry_directory}/hosts.toml"
        expected_hosts = (
            '[host."http://devops-stack-registry-run-2026-08-30-0123456789ab:5000"]\n'
        )
        self.assertIn(
            ["docker", "exec", NODE_ID, "mkdir", "-p", registry_directory],
            runner.calls,
        )
        copy_index = next(
            index
            for index, command in enumerate(runner.calls)
            if command[:2] == ["docker", "cp"]
        )
        copy = runner.calls[copy_index]
        hosts_source = Path(copy[2])
        self.assertEqual(copy[3], f"{NODE_ID}:{hosts_path}")
        self.assertEqual(hosts_source.read_text(encoding="utf-8"), expected_hosts)
        self.assertEqual(stat.S_IMODE(hosts_source.stat().st_mode), 0o600)
        self.assertNotIn("input", runner.call_options[copy_index])
        self.assertIn(["docker", "exec", NODE_ID, "cat", hosts_path], runner.calls)
        self.assertEqual(registry.connect_calls, [KIND_NETWORK_NAME])
        apply_index = next(
            index
            for index, command in enumerate(runner.calls)
            if command[0] == "kubectl" and "apply" in command
        )
        apply = runner.calls[apply_index]
        cache_path = Path(apply[apply.index("--cache-dir") + 1])
        kubeconfig_path = Path(apply[apply.index("--kubeconfig") + 1])
        self.assertEqual(cache_path.parent, kubeconfig_path.parent)
        self.assertEqual(stat.S_IMODE(cache_path.stat().st_mode), 0o700)
        manifest_path = Path(apply[apply.index("-f") + 1])
        manifest = manifest_path.read_text(encoding="utf-8")
        self.assertIn('host: "localhost:49153"', manifest)
        self.assertIn("name: local-registry-hosting", manifest)
        self.assertIn("namespace: kube-public", manifest)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        self.assertNotIn("input", runner.call_options[apply_index])
        self.assertEqual(configured.host_endpoint, "localhost:49153")
        self.assertEqual(
            configured.container_endpoint,
            "http://devops-stack-registry-run-2026-08-30-0123456789ab:5000",
        )
        self.assertEqual(cluster.registry_configuration, configured)
        cluster.destroy()

    def test_registry_from_another_run_is_rejected_before_any_modification(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        registry = FakeRegistryLifecycle("different-run")
        before = len(runner.calls)

        with self.assertRaisesRegex(KindClusterOwnershipError, "run ownership"):
            cluster.configure_local_registry(registry)  # type: ignore[arg-type]

        self.assertEqual(len(runner.calls), before)
        self.assertEqual(registry.connect_calls, [])
        cluster.destroy()

    def test_hosts_alias_round_trip_failure_stops_before_network_or_configmap(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        runner.copy_round_trip_override = "foreign content\n"
        registry = FakeRegistryLifecycle(cluster.run_id)

        with self.assertRaisesRegex(KindClusterError, "alias verification failed"):
            cluster.configure_local_registry(registry)  # type: ignore[arg-type]

        self.assertEqual(registry.connect_calls, [])
        self.assertFalse(any(call[0] == "kubectl" and "apply" in call for call in runner.calls))
        cluster.destroy()

    def test_destroy_rechecks_node_labels_and_id_then_cleans_private_files(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        assert cluster.kubeconfig_path is not None
        runtime = cluster.kubeconfig_path.parent

        self.assertTrue(cluster.destroy())

        delete = next(
            command
            for command in runner.calls
            if command[:3] == ["kind", "delete", "cluster"]
        )
        self.assertEqual(delete[delete.index("--name") + 1], cluster.name)
        inspect = [command for command in runner.calls if command[:2] == ["docker", "inspect"]]
        self.assertEqual(inspect[-1], ["docker", "inspect", NODE_ID])
        self.assertFalse(runtime.exists())
        self.assertIsNone(cluster.kubeconfig_path)
        self.assertIsNone(cluster.config_path)
        self.assertIsNone(cluster.handle)
        self.assertFalse(cluster.destroy())

    def test_destroy_refuses_foreign_labels_without_deleting_or_credentials_cleanup(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        assert cluster.kubeconfig_path is not None
        runtime = cluster.kubeconfig_path.parent
        runner.containers[NODE_ID]["Config"]["Labels"][KIND_CLUSTER_LABEL] = "foreign"

        with self.assertRaisesRegex(KindClusterOwnershipError, "ownership labels"):
            cluster.destroy()

        self.assertTrue(runner.clusters)
        self.assertTrue(runtime.exists())
        self.assertFalse(
            any(
                command[:3] == ["kind", "delete", "cluster"]
                for command in runner.calls
            )
        )
        cluster.detach()

    def test_destroy_refuses_replacement_container_with_same_name_and_labels(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        replacement = dict(runner.containers.pop(NODE_ID))
        replacement["Id"] = "c" * 64
        runner.containers["c" * 64] = replacement

        with self.assertRaisesRegex(KindClusterOwnershipError, "re-inspected"):
            cluster.destroy()

        self.assertTrue(runner.clusters)
        self.assertFalse(
            any(
                command[:3] == ["kind", "delete", "cluster"]
                for command in runner.calls
            )
        )
        cluster.detach()

    def test_missing_owned_cluster_is_not_deleted_and_credentials_are_removed(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        assert cluster.kubeconfig_path is not None
        runtime = cluster.kubeconfig_path.parent
        runner.clusters.clear()
        runner.nodes.clear()
        runner.containers.clear()

        self.assertFalse(cluster.destroy())

        self.assertFalse(
            any(
                command[:3] == ["kind", "delete", "cluster"]
                for command in runner.calls
            )
        )
        self.assertFalse(runtime.exists())

    def test_delete_failure_preserves_redacted_diagnostics_and_runtime_files(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)
        cluster.create()
        assert cluster.kubeconfig_path is not None
        runtime = cluster.kubeconfig_path.parent
        runner.delete_failure = subprocess.CompletedProcess(
            ["kind", "delete", "cluster"],
            1,
            "",
            "token=delete-secret\ndelete diagnostic\n",
        )

        with self.assertRaises(KindClusterError) as raised:
            cluster.destroy()

        rendered = f"{raised.exception}\n{cluster.diagnostics}"
        self.assertIn("delete diagnostic", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertNotIn("delete-secret", rendered)
        self.assertTrue(runtime.exists())
        cluster.detach()

    def test_context_manager_destroys_owned_cluster_and_removes_runtime_files(self) -> None:
        runner = FakeKindRunner()
        cluster = self.make_cluster(runner)

        with cluster as active:
            active.create()
            assert active.kubeconfig_path is not None
            runtime = active.kubeconfig_path.parent

        self.assertFalse(runner.clusters)
        self.assertFalse(runtime.exists())


if __name__ == "__main__":
    unittest.main()
