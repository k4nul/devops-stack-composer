from __future__ import annotations

import copy
import unittest
from pathlib import Path

from devops_stack_composer.config import canonical_hash, load_config, parse_config, validate_config
from devops_stack_composer.errors import ConfigParseError, ConfigValidationError
from devops_stack_composer.model import deep_merge, normalize_config


FIXTURE = Path(__file__).parent / "fixtures" / "configs" / "valid.yaml"


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = parse_config(FIXTURE.read_text(encoding="utf-8"))

    def test_valid_configuration_loads_and_normalizes(self) -> None:
        loaded = load_config(FIXTURE)

        self.assertEqual(loaded.model.image_name, "ghcr.io/k4nul/sample-api")
        self.assertEqual(
            loaded.model.image_reference,
            "ghcr.io/k4nul/sample-api:__IMAGE_TAG__",
        )
        self.assertEqual(
            loaded.model.image_tag_expression,
            "${BRANCH_SLUG}-${GIT_COMMIT_SHA}",
        )
        self.assertEqual(loaded.model.environment("production").replicas, 3)

    def test_unknown_field_is_rejected_with_actionable_path(self) -> None:
        self.raw["application"]["servceName"] = "typo"

        with self.assertRaises(ConfigValidationError) as raised:
            validate_config(self.raw)

        message = str(raised.exception)
        self.assertIn("$.application.servceName", message)
        self.assertIn("expected a documented field name", message)
        self.assertIn("received", message)
        self.assertIn("example", message)

    def test_wrong_type_reports_expected_and_received_values(self) -> None:
        self.raw["deployment"]["containerPort"] = "8080"

        with self.assertRaises(ConfigValidationError) as raised:
            validate_config(self.raw)

        message = str(raised.exception)
        self.assertIn("$.deployment.containerPort", message)
        self.assertIn("expected integer", message)
        self.assertIn('received "8080"', message)
        self.assertIn("example 8080", message)

    def test_registry_rejects_shell_and_url_syntax(self) -> None:
        for registry in (
            "https://ghcr.io",
            "ghcr.io;touch-pwned",
            "ghcr.io\nPUSH=true",
            "example..com:5000",
            "example.com:99999",
            "example.com:0",
        ):
            with self.subTest(registry=registry):
                invalid = copy.deepcopy(self.raw)
                invalid["image"]["registry"] = registry
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_repository_rejects_ambiguous_path_components(self) -> None:
        for repository in (
            "acme//orders",
            "acme/../orders/",
            "/acme/orders",
            "acme/orders/",
        ):
            with self.subTest(repository=repository):
                invalid = copy.deepcopy(self.raw)
                invalid["image"]["repository"] = repository
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_emitted_free_form_strings_reject_control_characters(self) -> None:
        mutations = (
            ("command", lambda value: value["application"].__setitem__("buildCommand", "echo ok\x00bad")),
            ("branch", lambda value: value["ci"]["branches"]["dev"].__setitem__(0, "feature\x01bad")),
            ("credential", lambda value: value["ci"]["jenkins"].__setitem__("credentialId", "registry\x7fsecret")),
            ("environment", lambda value: value["deployment"]["environment"].__setitem__("LOG_LEVEL", "info\x02bad")),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                invalid = copy.deepcopy(self.raw)
                mutate(invalid)
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_plain_environment_rejects_secret_shaped_keys(self) -> None:
        for key in (
            "API_TOKEN",
            "CLIENT_SECRET",
            "DATABASE_PASSWORD",
            "API_KEY",
            "APIKEY",
            "PRIVATEKEY",
            "ACCESSKEY",
            "PASSPHRASE",
            "CREDENTIAL",
        ):
            with self.subTest(key=key):
                invalid = copy.deepcopy(self.raw)
                invalid["deployment"]["environment"][key] = "must-not-be-plain-text"
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

    def test_cpu_quantity_rejects_sub_millicore_precision(self) -> None:
        invalid = copy.deepcopy(self.raw)
        invalid["deployment"]["resources"]["requests"]["cpu"] = "0.0001"

        with self.assertRaises(ConfigValidationError):
            validate_config(invalid)

    def test_rollout_values_require_nonnegative_int_or_percent(self) -> None:
        for value in (-1, "not-a-percent", "101%", "01%"):
            with self.subTest(value=value):
                invalid = copy.deepcopy(self.raw)
                invalid["deployment"]["rollout"]["maxUnavailable"] = value
                with self.assertRaises(ConfigValidationError):
                    validate_config(invalid)

        for value in (0, 3, "0%", "100%"):
            with self.subTest(value=value):
                valid = copy.deepcopy(self.raw)
                valid["deployment"]["rollout"]["maxUnavailable"] = value
                validate_config(valid)

    def test_fixed_tag_requires_value(self) -> None:
        self.raw["image"]["tag"] = {"strategy": "fixed"}

        with self.assertRaises(ConfigValidationError) as raised:
            validate_config(self.raw)

        self.assertIn("required field value", str(raised.exception))

    def test_non_fixed_tag_rejects_value(self) -> None:
        self.raw["image"]["tag"]["value"] = "latest"

        with self.assertRaises(ConfigValidationError):
            validate_config(self.raw)

    def test_yaml_root_must_be_mapping(self) -> None:
        with self.assertRaisesRegex(ConfigParseError, "must be a mapping"):
            parse_config("- invalid\n- root\n")

    def test_duplicate_yaml_keys_are_rejected_at_every_depth(self) -> None:
        for text in (
            "apiVersion: first\napiVersion: second\n",
            "application:\n  name: first\n  name: second\n",
        ):
            with self.subTest(text=text), self.assertRaisesRegex(
                ConfigParseError,
                "duplicate mapping key",
            ):
                parse_config(text)

    def test_malformed_yaml_error_does_not_echo_secret_source_text(self) -> None:
        secret = "TOPSECRET-MUST-NOT-LEAK"

        with self.assertRaises(ConfigParseError) as raised:
            parse_config(f'token: "{secret}\n', source="devops-stack.yaml")

        message = str(raised.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("token:", message)
        self.assertIn("devops-stack.yaml", message)
        self.assertIn("line", message)

    def test_hash_is_independent_of_mapping_order(self) -> None:
        reversed_mapping = dict(reversed(list(self.raw.items())))
        self.assertEqual(canonical_hash(self.raw), canonical_hash(reversed_mapping))

    def test_non_finite_yaml_numbers_are_rejected(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        for scalar in (".nan", ".inf", "-.inf"):
            with self.subTest(scalar=scalar):
                invalid = parse_config(
                    source.replace("FEATURE_FLAG: false", f"FEATURE_FLAG: {scalar}")
                )
                with self.assertRaises(ConfigValidationError) as raised:
                    validate_config(invalid)

                self.assertIn("$.deployment.environment.FEATURE_FLAG", str(raised.exception))
                self.assertIn("finite number", str(raised.exception))

    def test_canonical_hash_refuses_non_standard_json_numbers(self) -> None:
        with self.assertRaises(ValueError):
            canonical_hash({"value": float("nan")})

    def test_environment_maps_merge_and_lists_replace(self) -> None:
        merged = deep_merge(
            {
                "environment": {"LOG_LEVEL": "info", "REGION": "global"},
                "secretRefs": [{"name": "base", "keys": ["TOKEN"]}],
                "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            },
            {
                "environment": {"LOG_LEVEL": "debug"},
                "secretRefs": [{"name": "dev", "keys": ["TOKEN"]}],
                "resources": {"limits": {"memory": "512Mi"}},
            },
        )

        self.assertEqual(merged["environment"], {"LOG_LEVEL": "debug", "REGION": "global"})
        self.assertEqual(merged["secretRefs"], [{"name": "dev", "keys": ["TOKEN"]}])
        self.assertEqual(merged["resources"]["limits"], {"cpu": "500m", "memory": "512Mi"})

    def test_normalized_contract_covers_shared_values(self) -> None:
        validate_config(self.raw)
        model = normalize_config(self.raw)
        contract = model.contract()

        self.assertEqual(contract["applicationName"], "sample-api")
        self.assertEqual(contract["architectures"], ["linux/amd64", "linux/arm64"])
        self.assertEqual(contract["imageTagStrategy"], "branch-sha")
        self.assertEqual(
            contract["imageTagExpression"],
            "${BRANCH_SLUG}-${GIT_COMMIT_SHA}",
        )
        self.assertEqual(contract["servicePorts"]["production"], 80)
        self.assertEqual(contract["namespaces"]["dev"], "sample-api-dev")
        self.assertEqual(contract["secretNames"]["staging"], ["sample-api-secrets"])
        self.assertEqual(contract["branchEnvironmentMap"]["production"], ["main"])
        self.assertEqual(model.environment("dev").health_initial_delay_seconds, 5)
        self.assertEqual(model.environment("production").readiness_period_seconds, 5)

    def test_error_values_for_sensitive_paths_are_redacted(self) -> None:
        invalid = copy.deepcopy(self.raw)
        invalid["ci"]["jenkins"]["credentialId"] = 12345

        with self.assertRaises(ConfigValidationError) as raised:
            validate_config(invalid)

        self.assertIn("received <redacted>", str(raised.exception))
        self.assertNotIn("12345", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
