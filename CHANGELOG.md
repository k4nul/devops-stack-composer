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
- Add explicit execution planning, inspection, recovery cleanup, and cumulative
  `static`, `supply-chain`, `kind-e2e`, and post-publication `release` CLI flows.
- Add deterministic wheel/sdist inspection, package SBOM, closed release assets,
  GitHub artifact attestations, and independent published-download verification.
- Add checksum-pinned real kind CI, dependency/static quality gates, a tag-driven
  release workflow, and execution, evidence, threat-model, and release guides.
- Preserve the v0.1 configuration and static generation workflow without requiring
  execution tooling.

## 0.1.0 - 2026-08-29

- Initial declarative Docker, Jenkins, and Kubernetes composition release.
