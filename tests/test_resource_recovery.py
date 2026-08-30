from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from typing import Any

from devops_stack_composer.evidence_bundle import (
    assemble_evidence_bundle,
    verify_evidence_bundle,
)
from devops_stack_composer.evidence_store import EvidenceStore
from devops_stack_composer.kind_cluster import (
    KIND_CLUSTER_LABEL,
    KIND_NODE_IMAGE,
    KIND_ROLE_LABEL,
    KindClusterRecoveryIdentity,
    KindNodeRecoveryIdentity,
)
from devops_stack_composer.registry import (
    CONTAINER_NAME_LABEL,
    MANAGED_BY_LABEL,
    REGISTRY_IMAGE,
    RESOURCE_LABEL,
    RUN_ID_LABEL,
    RegistryHandle,
)
from devops_stack_composer.resource_recovery import (
    RESOURCE_RECORD,
    ResourceOwnershipError,
    ResourceRecordError,
    ResourceRecoveryError,
    ResourceRecoveryStore,
)
from tests.test_evidence_bundle import execution_plan, execution_run, write_terminal_state


RUN_ID = "20260830T120000Z-abcdef123456"
REGISTRY_ID = "a" * 64
NODE_ID = "b" * 64


def _slug(run_id: str, limit: int) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", run_id.lower()).strip("-")
    return value[:limit].rstrip("-") or "run"


REGISTRY_NAME = f"devops-stack-registry-{_slug(RUN_ID, 20)}-0123456789ab"
CLUSTER_NAME = f"dsc-kind-{_slug(RUN_ID, 10)}-0123456789ab"
NODE_NAME = f"{CLUSTER_NAME}-control-plane"


def registry_labels() -> dict[str, str]:
    return {
        MANAGED_BY_LABEL: "devops-stack-composer",
        RESOURCE_LABEL: "ephemeral-registry",
        RUN_ID_LABEL: RUN_ID,
        CONTAINER_NAME_LABEL: REGISTRY_NAME,
    }


def registry_handle(*, container_id: str = REGISTRY_ID) -> RegistryHandle:
    return RegistryHandle(
        run_id=RUN_ID,
        name=REGISTRY_NAME,
        container_id=container_id,
        host_port=49153,
    )


def kind_identity(*, container_id: str = NODE_ID) -> KindClusterRecoveryIdentity:
    return KindClusterRecoveryIdentity(
        run_id=RUN_ID,
        name=CLUSTER_NAME,
        context=f"kind-{CLUSTER_NAME}",
        node_image=KIND_NODE_IMAGE,
        nodes=(KindNodeRecoveryIdentity(NODE_NAME, container_id, "control-plane"),),
    )


class FakeRecoveryRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.clusters: set[str] = {CLUSTER_NAME}
        self.nodes: dict[str, tuple[str, ...]] = {CLUSTER_NAME: (NODE_NAME,)}
        self.containers: dict[str, dict[str, Any]] = {
            NODE_ID: {
                "Id": NODE_ID,
                "Name": f"/{NODE_NAME}",
                "Config": {
                    "Image": KIND_NODE_IMAGE,
                    "Labels": {
                        KIND_CLUSTER_LABEL: CLUSTER_NAME,
                        KIND_ROLE_LABEL: "control-plane",
                    },
                },
            },
            REGISTRY_ID: {
                "Id": REGISTRY_ID,
                "Name": f"/{REGISTRY_NAME}",
                "Config": {
                    "Image": REGISTRY_IMAGE,
                    "Labels": registry_labels(),
                },
                "NetworkSettings": {
                    "Ports": {
                        "5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "49153"}]
                    }
                },
            },
        }
        self.kind_delete_failure: subprocess.CompletedProcess[str] | None = None
        self.registry_remove_failure: subprocess.CompletedProcess[str] | None = None
        self.leave_kind_after_delete = False
        self.leave_registry_after_remove = False

    def __call__(
        self,
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        self._assert_options(kwargs)
        if command == ["kind", "get", "clusters"]:
            return self._completed(
                command,
                stdout="".join(f"{name}\n" for name in sorted(self.clusters)),
            )
        if command[:4] == ["kind", "get", "nodes", "--name"]:
            name = command[4]
            if name not in self.clusters:
                return self._completed(command, 1, stderr="No kind nodes found\n")
            return self._completed(
                command,
                stdout="".join(f"{name}\n" for name in self.nodes[name]),
            )
        if command[:4] == ["kind", "delete", "cluster", "--name"]:
            if self.kind_delete_failure is not None:
                return self.kind_delete_failure
            name = command[4]
            if not self.leave_kind_after_delete:
                self.clusters.discard(name)
                for node_name in self.nodes.pop(name, ()):
                    container_id = self._id_for_name(node_name)
                    if container_id is not None:
                        self.containers.pop(container_id, None)
            return self._completed(command)
        if command[:2] == ["docker", "inspect"]:
            target = command[2]
            value = self.containers.get(target)
            if value is None:
                value = next(
                    (
                        item
                        for item in self.containers.values()
                        if item.get("Name") == f"/{target}"
                    ),
                    None,
                )
            if value is None:
                return self._completed(command, 1, stderr="Error: No such object\n")
            return self._completed(command, stdout=json.dumps([value]))
        if command[:2] == ["docker", "rm"]:
            if self.registry_remove_failure is not None:
                return self.registry_remove_failure
            container_id = command[-1]
            if not self.leave_registry_after_remove:
                self.containers.pop(container_id, None)
            return self._completed(command, stdout=f"{container_id}\n")
        raise AssertionError(f"unexpected recovery command: {command}")

    def _id_for_name(self, name: str) -> str | None:
        return next(
            (
                container_id
                for container_id, value in self.containers.items()
                if value.get("Name") == f"/{name}"
            ),
            None,
        )

    @staticmethod
    def _assert_options(options: dict[str, object]) -> None:
        assert options["check"] is False
        assert options["capture_output"] is True
        assert options["text"] is True
        assert isinstance(options["timeout"], float)

    @staticmethod
    def _completed(
        command: list[str],
        returncode: int = 0,
        *,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class ResourceRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.evidence = EvidenceStore.create(self.project, run_id=RUN_ID)
        self.recovery = ResourceRecoveryStore(self.evidence)

    def record_all(self) -> None:
        self.recovery.record_registry(registry_handle())
        self.recovery.record_kind(kind_identity())

    def test_records_only_non_secret_exact_resource_identity(self) -> None:
        self.record_all()

        record = self.evidence.path(RESOURCE_RECORD)
        rendered = record.read_text(encoding="utf-8")
        resources = self.recovery.load()

        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(resources.registry.container_id, REGISTRY_ID)  # type: ignore[union-attr]
        self.assertEqual(resources.registry.host_port, 49153)  # type: ignore[union-attr]
        self.assertEqual(resources.kind.name, CLUSTER_NAME)  # type: ignore[union-attr]
        self.assertEqual(resources.kind.nodes[0].container_id, NODE_ID)  # type: ignore[union-attr]
        for forbidden in ("kubeconfig", "credential", "authorization", "privatekey"):
            self.assertNotIn(forbidden, rendered.lower())

    def test_restart_cleanup_verifies_then_deletes_exact_ids_and_is_idempotent(self) -> None:
        self.record_all()
        self.evidence.write_checksums()
        runner = FakeRecoveryRunner()
        reopened = ResourceRecoveryStore(EvidenceStore.open(self.project, RUN_ID))

        result = reopened.cleanup(command_runner=runner)

        self.assertTrue(result.kind_removed)
        self.assertTrue(result.registry_removed)
        self.assertTrue(result.complete)
        self.assertIn(
            ["kind", "delete", "cluster", "--name", CLUSTER_NAME],
            runner.calls,
        )
        self.assertNotIn("--kubeconfig", [part for call in runner.calls for part in call])
        self.assertIn(
            ["docker", "rm", "--force", "--volumes", REGISTRY_ID],
            runner.calls,
        )
        kind_delete = runner.calls.index(
            ["kind", "delete", "cluster", "--name", CLUSTER_NAME]
        )
        registry_delete = runner.calls.index(
            ["docker", "rm", "--force", "--volumes", REGISTRY_ID]
        )
        self.assertLess(kind_delete, registry_delete)
        self.assertEqual(reopened.load().kind.status, "removed")  # type: ignore[union-attr]
        self.assertEqual(reopened.load().registry.status, "removed")  # type: ignore[union-attr]
        self.evidence.verify_checksums()

        before = len(runner.calls)
        repeated = reopened.cleanup(command_runner=runner)
        self.assertEqual(len(runner.calls), before)
        self.assertFalse(repeated.kind_removed)
        self.assertFalse(repeated.registry_removed)
        self.assertTrue(repeated.complete)

    def test_cleanup_reseals_and_preserves_a_semantically_valid_evidence_bundle(self) -> None:
        self.record_all()
        plan = execution_plan()
        run = execution_run(plan)
        write_terminal_state(self.evidence, plan, run)
        assemble_evidence_bundle(self.evidence, plan, run)
        runner = FakeRecoveryRunner()

        result = self.recovery.cleanup(command_runner=runner)

        self.assertTrue(result.complete)
        verified = verify_evidence_bundle(self.evidence)
        self.assertTrue(verified.execution_succeeded)
        resources = self.recovery.load()
        self.assertEqual(resources.kind.status, "removed")  # type: ignore[union-attr]
        self.assertEqual(resources.registry.status, "removed")  # type: ignore[union-attr]

    def test_partial_failure_preserves_completed_kind_and_retries_registry_only(self) -> None:
        self.record_all()
        runner = FakeRecoveryRunner()
        runner.registry_remove_failure = subprocess.CompletedProcess(
            ["docker", "rm"],
            1,
            "",
            "token=delete-secret\nregistry busy\n",
        )

        with self.assertRaises(ResourceRecoveryError) as raised:
            self.recovery.cleanup(command_runner=runner)

        self.assertIn("registry busy", str(raised.exception))
        self.assertIn("<redacted>", str(raised.exception))
        self.assertNotIn("delete-secret", str(raised.exception))
        persisted = self.recovery.load()
        self.assertEqual(persisted.kind.status, "removed")  # type: ignore[union-attr]
        self.assertEqual(persisted.registry.status, "active")  # type: ignore[union-attr]

        runner.registry_remove_failure = None
        runner.calls.clear()
        result = self.recovery.cleanup(command_runner=runner)
        self.assertTrue(result.registry_removed)
        self.assertFalse(any(call[0] == "kind" for call in runner.calls))
        self.assertTrue(result.complete)

    def test_kind_delete_failure_preserves_both_resources_for_retry(self) -> None:
        self.record_all()
        runner = FakeRecoveryRunner()
        runner.kind_delete_failure = subprocess.CompletedProcess(
            ["kind", "delete", "cluster"],
            1,
            "",
            "cluster is busy\n",
        )

        with self.assertRaisesRegex(ResourceRecoveryError, "cluster is busy"):
            self.recovery.cleanup(command_runner=runner)

        persisted = self.recovery.load()
        self.assertEqual(persisted.kind.status, "active")  # type: ignore[union-attr]
        self.assertEqual(persisted.registry.status, "active")  # type: ignore[union-attr]
        self.assertFalse(any(call[:2] == ["docker", "rm"] for call in runner.calls))

    def test_foreign_registry_labels_refuse_deletion_and_preserve_active_state(self) -> None:
        self.recovery.record_registry(registry_handle())
        runner = FakeRecoveryRunner()
        runner.containers[REGISTRY_ID]["Config"]["Labels"][RUN_ID_LABEL] = "foreign"

        with self.assertRaisesRegex(ResourceOwnershipError, "ownership labels"):
            self.recovery.cleanup(command_runner=runner)

        self.assertFalse(any(call[:2] == ["docker", "rm"] for call in runner.calls))
        self.assertEqual(self.recovery.load().registry.status, "active")  # type: ignore[union-attr]

    def test_replacement_registry_id_refuses_deletion(self) -> None:
        self.recovery.record_registry(registry_handle())
        runner = FakeRecoveryRunner()
        replacement = runner.containers.pop(REGISTRY_ID)
        replacement["Id"] = "c" * 64
        runner.containers["c" * 64] = replacement

        with self.assertRaisesRegex(ResourceOwnershipError, "identity"):
            self.recovery.cleanup(command_runner=runner)

        self.assertFalse(any(call[:2] == ["docker", "rm"] for call in runner.calls))
        self.assertIn("c" * 64, runner.containers)

    def test_replacement_kind_id_and_mixed_node_inventory_refuse_cluster_delete(self) -> None:
        self.recovery.record_kind(kind_identity())
        runner = FakeRecoveryRunner()
        replacement = runner.containers.pop(NODE_ID)
        replacement["Id"] = "c" * 64
        runner.containers["c" * 64] = replacement

        with self.assertRaisesRegex(ResourceOwnershipError, "no longer exists"):
            self.recovery.cleanup(command_runner=runner)

        self.assertFalse(any(call[:3] == ["kind", "delete", "cluster"] for call in runner.calls))
        runner = FakeRecoveryRunner()
        runner.nodes[CLUSTER_NAME] = (NODE_NAME, "foreign-control-plane")
        with self.assertRaisesRegex(ResourceOwnershipError, "inventory"):
            self.recovery.cleanup(command_runner=runner)
        self.assertFalse(any(call[:3] == ["kind", "delete", "cluster"] for call in runner.calls))

    def test_missing_inventory_with_remaining_node_fails_closed(self) -> None:
        self.recovery.record_kind(kind_identity())
        runner = FakeRecoveryRunner()
        runner.clusters.clear()

        with self.assertRaisesRegex(ResourceOwnershipError, "containers remain"):
            self.recovery.cleanup(command_runner=runner)

        self.assertIn(NODE_ID, runner.containers)
        self.assertEqual(self.recovery.load().kind.status, "active")  # type: ignore[union-attr]

    def test_confirmed_external_removal_is_recorded_without_delete_commands(self) -> None:
        self.record_all()
        runner = FakeRecoveryRunner()
        runner.clusters.clear()
        runner.nodes.clear()
        runner.containers.clear()

        result = self.recovery.cleanup(command_runner=runner)

        self.assertFalse(result.kind_removed)
        self.assertFalse(result.registry_removed)
        self.assertTrue(result.complete)
        self.assertFalse(any("delete" in call or "rm" in call for call in runner.calls))

    def test_success_without_confirmed_absence_preserves_active_state(self) -> None:
        self.recovery.record_registry(registry_handle())
        runner = FakeRecoveryRunner()
        runner.leave_registry_after_remove = True

        with self.assertRaisesRegex(ResourceRecoveryError, "still exists"):
            self.recovery.cleanup(command_runner=runner)

        self.assertEqual(self.recovery.load().registry.status, "active")  # type: ignore[union-attr]

    def test_record_tampering_and_sealed_bundle_tampering_are_rejected_before_tools(self) -> None:
        self.recovery.record_registry(registry_handle())
        record = self.evidence.path(RESOURCE_RECORD)
        value = json.loads(record.read_text(encoding="utf-8"))
        value["registry"]["hostPort"] = 49154
        record.write_text(json.dumps(value), encoding="utf-8")
        runner = FakeRecoveryRunner()

        with self.assertRaisesRegex(ResourceRecordError, "content digest"):
            self.recovery.cleanup(command_runner=runner)
        self.assertEqual(runner.calls, [])

        value["registry"]["hostPort"] = 49153
        payload = {key: value[key] for key in ("schemaVersion", "runId", "registry", "kind")}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        value["contentDigest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
        record.write_text(json.dumps(value), encoding="utf-8")
        self.evidence.write_checksums()
        value["registry"]["hostPort"] = 49154
        record.write_text(json.dumps(value), encoding="utf-8")

        with self.assertRaisesRegex(ResourceRecordError, "unsafe"):
            self.recovery.cleanup(command_runner=runner)
        self.assertEqual(runner.calls, [])

    def test_mixed_run_duplicate_keys_and_symlink_record_are_rejected(self) -> None:
        self.recovery.record_registry(registry_handle())
        record = self.evidence.path(RESOURCE_RECORD)
        value = json.loads(record.read_text(encoding="utf-8"))
        value["runId"] = "20260830T120000Z-000000000000"
        record.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ResourceRecordError, "run ID does not match"):
            self.recovery.load()

        record.write_text('{"schemaVersion":1,"schemaVersion":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(ResourceRecordError, "duplicate key"):
            self.recovery.load()

        outside = self.project / "outside.json"
        outside.write_text("{}\n", encoding="utf-8")
        record.unlink()
        record.symlink_to(outside)
        with self.assertRaisesRegex(ResourceRecordError, "unsafe"):
            self.recovery.load()

    def test_capture_refuses_cross_run_replacement_and_identity_collision(self) -> None:
        self.recovery.record_registry(registry_handle())
        other_run = "20260830T120000Z-000000000000"
        with self.assertRaisesRegex(ResourceRecordError, "different run"):
            self.recovery.record_registry(
                RegistryHandle(
                    run_id=other_run,
                    name=(
                        f"devops-stack-registry-{_slug(other_run, 20)}-"
                        "000000000000"
                    ),
                    container_id=REGISTRY_ID,
                    host_port=49153,
                )
            )
        with self.assertRaisesRegex(ResourceRecordError, "mixes"):
            self.recovery.record_kind(kind_identity(container_id=REGISTRY_ID))

        changed = RegistryHandle(
            run_id=RUN_ID,
            name=REGISTRY_NAME.replace("0123456789ab", "ffffffffffff"),
            container_id="d" * 64,
            host_port=49154,
        )
        with self.assertRaisesRegex(ResourceRecordError, "replace"):
            self.recovery.record_registry(changed)

        with self.assertRaisesRegex(ValueError, "local test"):
            RegistryHandle(
                run_id=RUN_ID,
                name=REGISTRY_NAME,
                container_id=REGISTRY_ID,
                host_port=49153,
                local_test_only=False,
            )


if __name__ == "__main__":
    unittest.main()
