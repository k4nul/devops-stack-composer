from __future__ import annotations

import unittest

from devops_stack_composer.oci import (
    OciReferenceError,
    digest_from_image_id,
    parse_digest,
    parse_oci_reference,
    require_same_digest,
    validate_registry,
)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class OciTests(unittest.TestCase):
    def test_sha256_digest_is_strict_and_round_trips(self) -> None:
        parsed = parse_digest(DIGEST)

        self.assertEqual(parsed.algorithm, "sha256")
        self.assertEqual(parsed.hex_value, "a" * 64)
        self.assertEqual(str(parsed), DIGEST)

        for invalid in (
            "sha256:" + "a" * 63,
            "sha256:" + "A" * 64,
            "sha512:" + "a" * 64,
            " sha256:" + "a" * 64,
            "sha256:" + "g" * 64,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(OciReferenceError):
                parse_digest(invalid)

    def test_reference_parses_registry_port_tag_and_digest(self) -> None:
        reference = parse_oci_reference(
            f"localhost:5000/team/service:release-1@{DIGEST}"
        )

        self.assertEqual(reference.repository, "localhost:5000/team/service")
        self.assertEqual(reference.tag, "release-1")
        self.assertEqual(str(reference.digest), DIGEST)
        self.assertTrue(reference.is_immutable)
        self.assertEqual(
            reference.immutable_reference,
            f"localhost:5000/team/service@{DIGEST}",
        )

    def test_reference_rejects_url_userinfo_and_invalid_names(self) -> None:
        for invalid in (
            f"https://registry.example/team/service@{DIGEST}",
            f"user@registry.example/team/service@{DIGEST}",
            f"registry.example/Team/service@{DIGEST}",
            "registry.example/team//service:tag",
            "registry.example/team/service:",
            "registry.example/team/service:bad tag",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(OciReferenceError):
                parse_oci_reference(invalid)

    def test_registry_port_is_bounded(self) -> None:
        self.assertEqual(validate_registry("127.0.0.1:5000"), "127.0.0.1:5000")
        for invalid in ("https://registry.example", "registry.example:0", "registry.example:65536"):
            with self.subTest(invalid=invalid), self.assertRaises(OciReferenceError):
                validate_registry(invalid)

    def test_digest_extraction_supports_kubernetes_runtime_image_ids(self) -> None:
        self.assertEqual(
            str(digest_from_image_id(f"docker-pullable://registry.example/team/app@{DIGEST}")),
            DIGEST,
        )
        self.assertEqual(str(digest_from_image_id(f"containerd://{DIGEST}")), DIGEST)
        with self.assertRaises(OciReferenceError):
            digest_from_image_id(f"unknown-runtime://{DIGEST}")

    def test_same_digest_comparison_is_structural(self) -> None:
        resolved = require_same_digest(
            {
                "build": DIGEST,
                "registry": f"registry.example/team/app@{DIGEST}",
                "deployment": parse_oci_reference(f"registry.example/team/app:tag@{DIGEST}"),
            }
        )
        self.assertEqual(str(resolved), DIGEST)

        with self.assertRaisesRegex(OciReferenceError, "deployment"):
            require_same_digest({"build": DIGEST, "deployment": OTHER_DIGEST})
        with self.assertRaises(OciReferenceError):
            require_same_digest({})


if __name__ == "__main__":
    unittest.main()
