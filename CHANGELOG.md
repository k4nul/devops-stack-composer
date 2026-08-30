# Changelog

## 0.2.0 - 2026-08-31

- Add cumulative static, supply-chain, kind E2E, and release validation profiles.
- Build and push an application image once, then bind SBOM, vulnerability,
  provenance, Kubernetes deployment, runtime pod, and report evidence to the same
  immutable OCI digest.
- Add an owned loopback registry and pinned kind cluster lifecycle with strict
  ownership checks, server-side dry-runs, rollout and endpoint verification, and a
  same-digest rollback test.
- Add closed offline evidence bundles, runtime JSON schemas, artifact inspection and
  verification commands, and Jenkins digest-propagation contracts.
- Preserve the v0.1 configuration and static generation workflow without requiring
  execution tooling.

## 0.1.0 - 2026-08-29

- Initial declarative Docker, Jenkins, and Kubernetes composition release.
