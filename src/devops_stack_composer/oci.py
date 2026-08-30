"""Strict OCI digest and image-reference parsing.

The execution layer treats an OCI digest, rather than a mutable tag, as artifact
identity.  This module deliberately supports only lowercase ``sha256`` digests.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping


_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_REGISTRY_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_REPOSITORY_COMPONENT = re.compile(
    r"^[a-z0-9]+(?:(?:[._]|-+)[a-z0-9]+)*$"
)
_RUNTIME_SCHEMES = frozenset({"containerd", "cri-o", "docker", "docker-pullable"})


class OciReferenceError(ValueError):
    """Raised when an OCI digest, repository, or reference is malformed."""


def _plain_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise OciReferenceError(f"{name} must be a non-empty string")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise OciReferenceError(f"{name} must not contain whitespace or control characters")
    return value


def validate_sha256_hex(value: str) -> str:
    """Validate a bare, lowercase SHA-256 hexadecimal value."""

    value = _plain_text("SHA-256 value", value)
    if not _SHA256_HEX.fullmatch(value):
        raise OciReferenceError(
            "SHA-256 value must contain exactly 64 lowercase hexadecimal characters"
        )
    return value


def validate_tag(value: str) -> str:
    """Validate an explicit OCI/Docker tag without applying an implicit latest tag."""

    value = _plain_text("image tag", value)
    if not _TAG.fullmatch(value):
        raise OciReferenceError("image tag must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
    return value


def validate_registry(value: str) -> str:
    """Validate a lowercase DNS-like registry endpoint with an optional TCP port."""

    value = _plain_text("registry", value)
    if any(character in value for character in "/@?#\\") or "://" in value:
        raise OciReferenceError("registry must be a host with an optional port, not a URL")
    if value.count(":") > 1:
        raise OciReferenceError("IPv6 registry literals are not supported")

    host, separator, port_text = value.rpartition(":")
    if not separator:
        host = value
    else:
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            raise OciReferenceError("registry port must be an integer from 1 through 65535")
    if not host or any(not _REGISTRY_LABEL.fullmatch(label) for label in host.split(".")):
        raise OciReferenceError("registry host must contain lowercase DNS labels")
    return value


def validate_repository(value: str) -> str:
    """Validate a lowercase repository, optionally prefixed by a registry endpoint."""

    value = _plain_text("repository", value)
    if len(value) > 255:
        raise OciReferenceError("repository must be 255 characters or fewer")
    if value.startswith("/") or value.endswith("/") or "//" in value:
        raise OciReferenceError("repository must not contain empty path components")
    if any(character in value for character in "@?#\\") or "://" in value:
        raise OciReferenceError("repository contains URL or reference syntax")

    components = value.split("/")
    first = components[0]
    has_registry = "." in first or ":" in first or first == "localhost"
    repository_components = components
    if has_registry:
        validate_registry(first)
        repository_components = components[1:]
        if not repository_components:
            raise OciReferenceError("a registry-prefixed repository requires an image path")
    if any(not _REPOSITORY_COMPONENT.fullmatch(component) for component in repository_components):
        raise OciReferenceError("repository path components must use lowercase OCI name syntax")
    return value


@dataclass(frozen=True, order=True)
class OciDigest:
    """A parsed lowercase SHA-256 OCI digest."""

    algorithm: str
    hex_value: str

    def __post_init__(self) -> None:
        if self.algorithm != "sha256":
            raise OciReferenceError("only sha256 OCI digests are supported")
        validate_sha256_hex(self.hex_value)

    @classmethod
    def parse(cls, value: str) -> "OciDigest":
        value = _plain_text("OCI digest", value)
        match = _SHA256.fullmatch(value)
        if not match:
            raise OciReferenceError(
                "OCI digest must use sha256 followed by exactly 64 lowercase hexadecimal characters"
            )
        return cls("sha256", match.group(1))

    def __str__(self) -> str:
        return f"{self.algorithm}:{self.hex_value}"


def parse_digest(value: str) -> OciDigest:
    """Parse a strict sha256 OCI digest."""

    return OciDigest.parse(value)


@dataclass(frozen=True)
class OciReference:
    """A parsed OCI repository with an optional explicit tag and digest."""

    repository: str
    tag: str | None = None
    digest: OciDigest | None = None

    def __post_init__(self) -> None:
        validate_repository(self.repository)
        if self.tag is not None:
            validate_tag(self.tag)
        if self.digest is not None and not isinstance(self.digest, OciDigest):
            raise OciReferenceError("reference digest must be an OciDigest")

    @classmethod
    def parse(cls, value: str) -> "OciReference":
        value = _plain_text("OCI reference", value)
        if any(character in value for character in "?#\\") or "://" in value:
            raise OciReferenceError("OCI reference must not use URL syntax")
        if value.count("@") > 1:
            raise OciReferenceError("OCI reference may contain at most one digest separator")

        name_and_tag, separator, digest_text = value.partition("@")
        digest = parse_digest(digest_text) if separator else None
        if separator and not name_and_tag:
            raise OciReferenceError("OCI reference is missing its repository")

        last_slash = name_and_tag.rfind("/")
        last_colon = name_and_tag.rfind(":")
        tag: str | None = None
        repository = name_and_tag
        if last_colon > last_slash:
            repository, tag = name_and_tag[:last_colon], name_and_tag[last_colon + 1 :]
            if not repository:
                raise OciReferenceError("OCI reference is missing its repository")
        return cls(repository=repository, tag=tag, digest=digest)

    @property
    def is_immutable(self) -> bool:
        return self.digest is not None

    @property
    def immutable_reference(self) -> str:
        """Return repository@digest, deliberately dropping any informational tag."""

        if self.digest is None:
            raise OciReferenceError("an immutable reference requires a digest")
        return f"{self.repository}@{self.digest}"

    def __str__(self) -> str:
        value = self.repository
        if self.tag is not None:
            value += f":{self.tag}"
        if self.digest is not None:
            value += f"@{self.digest}"
        return value


def parse_oci_reference(value: str) -> OciReference:
    """Parse an OCI reference without inventing a default tag."""

    return OciReference.parse(value)


def digest_from_subject(value: str | OciDigest | OciReference) -> OciDigest:
    """Extract a digest from a digest string or digest-pinned OCI subject."""

    if isinstance(value, OciDigest):
        return value
    if isinstance(value, OciReference):
        if value.digest is None:
            raise OciReferenceError("OCI subject is not digest-pinned")
        return value.digest
    try:
        return parse_digest(value)
    except OciReferenceError:
        reference = parse_oci_reference(value)
        if reference.digest is None:
            raise OciReferenceError("OCI subject is not digest-pinned") from None
        return reference.digest


def digest_from_image_id(value: str) -> OciDigest:
    """Extract the digest from a Kubernetes container ``imageID`` value."""

    value = _plain_text("container image ID", value)
    if "://" not in value:
        return digest_from_subject(value)
    scheme, payload = value.split("://", 1)
    if scheme not in _RUNTIME_SCHEMES or not payload:
        raise OciReferenceError("container image ID uses an unsupported runtime scheme")
    return digest_from_subject(payload)


def require_same_digest(
    subjects: Mapping[str, str | OciDigest | OciReference],
) -> OciDigest:
    """Require every named subject to resolve to one exact OCI digest."""

    if not subjects:
        raise OciReferenceError("at least one OCI subject is required")
    resolved = {name: digest_from_subject(subject) for name, subject in subjects.items()}
    expected = next(iter(resolved.values()))
    mismatches = sorted(name for name, digest in resolved.items() if digest != expected)
    if mismatches:
        raise OciReferenceError(
            "OCI subject digest mismatch for: " + ", ".join(mismatches)
        )
    return expected
