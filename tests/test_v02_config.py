from __future__ import annotations

import copy
import unittest
from pathlib import Path

from devops_stack_composer.config import parse_config, validate_config
from devops_stack_composer.errors import ConfigValidationError
from devops_stack_composer.model import normalize_config


FIXTURE = Path(__file__).parent / "fixtures" / "configs" / "valid.yaml"


def v01_config() -> dict:
    return parse_config(FIXTURE.read_text(encoding="utf-8"))


def v02_config() -> dict:
    config = v01_config()
    config["execution"] = {
        "profile": "local-kind",
        "workDirectory": ".devops-stack/runs",
        "cleanup": "always",
        "retainFailureEvidence": True,
    }
    config["registry"] = {
        "mode": "ephemeral-local",
        "host": "auto",
        "repository": "sample/python-service",
        "insecureLocalhostOnly": True,
    }
    config["kubernetes"] = {
        "e2e": {
            "provider": "kind",
            "environment": "staging",
            "serverSideDryRunEnvironments": ["dev", "staging", "production"],
            "rolloutTimeoutSeconds": 180,
            "healthPath": "/health",
            "readinessPath": "/ready",
            "rollbackTest": True,
            "cleanup": "always",
        }
    }
    config["validation"] = {"profile": "kind-e2e"}
    config["supplyChain"] = {
        "sbom": {"required": True, "format": "spdx-json"},
        "provenance": {"required": True},
        "vulnerability": {
            "required": True,
            "severities": ["CRITICAL", "HIGH"],
            "ignoreUnfixed": True,
            "maximumAllowed": 0,
            "allowlist": [
                {
                    "id": "CVE-2026-12345",
                    "package": "openssl",
                    "reason": "No reachable vulnerable code path",
                    "owner": "security-team",
                    "expiresAt": "2026-12-31",
                }
            ],
        },
        "verification": {
            "requireSingleDigest": True,
            "requireDigestPinnedDeployment": True,
        },
    }
    return config


class V02ConfigTests(unittest.TestCase):
    def test_v01_configuration_gets_static_execution_defaults(self) -> None:
        raw = v01_config()
        original = copy.deepcopy(raw)

        validate_config(raw)
        model = normalize_config(raw)

        self.assertEqual(raw, original)
        self.assertEqual(model.validation_profile, "static")
        self.assertEqual(
            model.execution,
            {
                "profile": "static",
                "workDirectory": ".devops-stack/runs",
                "cleanup": "always",
                "retainFailureEvidence": True,
            },
        )
        self.assertEqual(
            model.registry,
            {
                "mode": "existing",
                "host": raw["image"]["registry"],
                "repository": raw["image"]["repository"],
                "insecureLocalhostOnly": False,
            },
        )
        self.assertEqual(
            model.kubernetes_e2e,
            {
                "provider": "kind",
                "environment": "staging",
                "serverSideDryRunEnvironments": ["dev", "staging", "production"],
                "rolloutTimeoutSeconds": 180,
                "healthPath": "/health",
                "readinessPath": "/ready",
                "rollbackTest": True,
                "cleanup": "always",
            },
        )
        self.assertTrue(model.supply_chain["sbom"]["enabled"])
        self.assertTrue(model.supply_chain["sbom"]["required"])
        self.assertTrue(model.supply_chain["provenance"]["enabled"])
        self.assertTrue(model.supply_chain["provenance"]["required"])
        self.assertEqual(model.supply_chain["scan"], raw["supplyChain"]["scan"])
        self.assertEqual(
            model.supply_chain["verification"],
            {
                "requireSingleDigest": False,
                "requireDigestPinnedDeployment": False,
            },
        )

    def test_v02_configuration_validates_and_normalizes_required_capabilities(self) -> None:
        raw = v02_config()

        validate_config(raw)
        model = normalize_config(raw)

        self.assertEqual(model.validation_profile, "kind-e2e")
        self.assertEqual(
            model.execution,
            {**raw["execution"], "profile": "kind-e2e"},
        )
        self.assertEqual(model.registry, raw["registry"])
        self.assertEqual(model.kubernetes_e2e, raw["kubernetes"]["e2e"])
        self.assertTrue(model.supply_chain["sbom"]["enabled"])
        self.assertTrue(model.supply_chain["provenance"]["enabled"])
        self.assertEqual(model.supply_chain["provenance"]["mode"], "max")
        self.assertEqual(
            model.supply_chain["vulnerability"]["allowlist"][0]["id"],
            "CVE-2026-12345",
        )
        self.assertNotIn("scan", model.supply_chain)

    def test_validation_profile_drives_default_execution_profile(self) -> None:
        raw = v01_config()
        raw["validation"] = {"profile": "release"}

        validate_config(raw)
        model = normalize_config(raw)

        self.assertEqual(model.validation_profile, "release")
        self.assertEqual(model.execution["profile"], "release")

    def test_new_sections_reject_unknown_fields_with_exact_paths(self) -> None:
        mutations = (
            ("execution", lambda value: value["execution"].__setitem__("workDir", "runs")),
            ("registry", lambda value: value["registry"].__setitem__("password", "secret")),
            (
                "kubernetes-e2e",
                lambda value: value["kubernetes"]["e2e"].__setitem__("cluster", "default"),
            ),
            ("validation", lambda value: value["validation"].__setitem__("strict", True)),
            (
                "allowlist",
                lambda value: value["supplyChain"]["vulnerability"]["allowlist"][0].__setitem__(
                    "approved", True
                ),
            ),
        )
        expected_paths = (
            "$.execution.workDir",
            "$.registry.password",
            "$.kubernetes.e2e.cluster",
            "$.validation.strict",
            "$.supplyChain.vulnerability.allowlist[0].approved",
        )

        for (name, mutate), expected_path in zip(mutations, expected_paths):
            with self.subTest(name=name):
                invalid = v02_config()
                mutate(invalid)
                with self.assertRaises(ConfigValidationError) as raised:
                    validate_config(invalid)
                self.assertIn(expected_path, str(raised.exception))

    def test_new_sections_enforce_profiles_registry_boundary_and_allowlist_expiry(self) -> None:
        mutations = (
            lambda value: value["validation"].__setitem__("profile", "best-effort"),
            lambda value: value["execution"].__setitem__("workDirectory", "../runs"),
            lambda value: value["registry"].__setitem__("host", "registry.example"),
            lambda value: value["registry"].__setitem__("insecureLocalhostOnly", False),
            lambda value: value["registry"].update(
                {
                    "mode": "existing",
                    "host": "registry.example:65536",
                    "insecureLocalhostOnly": False,
                }
            ),
            lambda value: value["supplyChain"]["vulnerability"]["allowlist"][0].__setitem__(
                "expiresAt", "not-a-date"
            ),
        )

        for mutate in mutations:
            with self.subTest(mutate=mutate):
                invalid = v02_config()
                mutate(invalid)
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

        existing = v02_config()
        existing["registry"] = {
            "mode": "existing",
            "host": "registry.example:5000",
            "repository": "sample/python-service",
            "insecureLocalhostOnly": False,
        }
        validate_config(existing)

        existing["registry"]["host"] = "auto"
        with self.assertRaises(ConfigValidationError):
            validate_config(existing)

    def test_required_capability_cannot_be_explicitly_disabled(self) -> None:
        for capability in ("sbom", "provenance"):
            with self.subTest(capability=capability):
                invalid = v02_config()
                invalid["supplyChain"][capability]["enabled"] = False
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_execution_profile_and_cleanup_policies_cannot_diverge(self) -> None:
        invalid_profile = v02_config()
        invalid_profile["execution"]["profile"] = "supply-chain"
        with self.assertRaises(ConfigValidationError) as profile_error:
            validate_config(invalid_profile)
        self.assertIn("$.execution.profile", str(profile_error.exception))

        invalid_cleanup = v02_config()
        invalid_cleanup["kubernetes"]["e2e"]["cleanup"] = "on-success"
        with self.assertRaises(ConfigValidationError) as cleanup_error:
            validate_config(invalid_cleanup)
        self.assertIn("$.kubernetes.e2e.cleanup", str(cleanup_error.exception))

        valid_alias = v02_config()
        validate_config(valid_alias)
        self.assertEqual(normalize_config(valid_alias).execution["profile"], "kind-e2e")

    def test_execution_only_accepts_runtime_policies_it_enforces(self) -> None:
        mutations = (
            lambda value: value["execution"].__setitem__("cleanup", "on-success"),
            lambda value: value["execution"].__setitem__("retainFailureEvidence", False),
            lambda value: value["kubernetes"]["e2e"].__setitem__(
                "serverSideDryRunEnvironments", ["staging"]
            ),
            lambda value: value["kubernetes"]["e2e"].__setitem__(
                "rolloutTimeoutSeconds", 4
            ),
            lambda value: value["kubernetes"]["e2e"].__setitem__("rollbackTest", False),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                invalid = v02_config()
                mutate(invalid)
                if invalid["execution"]["cleanup"] != "always":
                    invalid["kubernetes"]["e2e"]["cleanup"] = invalid["execution"]["cleanup"]
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_new_blocks_are_complete_when_present(self) -> None:
        required_fields = (
            ("execution", "cleanup"),
            ("registry", "repository"),
            ("kubernetes-e2e", "rolloutTimeoutSeconds"),
            ("validation", "profile"),
        )
        for block, field in required_fields:
            with self.subTest(block=block, field=field):
                invalid = v02_config()
                if block == "kubernetes-e2e":
                    del invalid["kubernetes"]["e2e"][field]
                else:
                    del invalid[block][field]
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)


if __name__ == "__main__":
    unittest.main()
