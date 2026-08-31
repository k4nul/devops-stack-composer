# Changelog

## 0.2.2 - 2026-08-31

- Bind schema 1.1 execution evidence to exact source, template, tool, checksum,
  SBOM, vulnerability, provenance, deployment, and runtime identities while
  preserving verification of exact 1.0 bundles from v0.2.1.
- Emit source-bound Jenkins artifact v2 evidence, retain v1 verification
  compatibility, and archive successful provenance only after offline validation.
- Pin the generated Node.js and Python base-image defaults by digest and require
  observable post-rollback recovery evidence.
- Stage resumable no-clobber draft releases, complete cumulative validation before
  publication, verify the live tag target around publication, and reinstall both
  distributions from fresh public downloads without pip-cache reuse.
- Enforce cached quality-tool provenance and Python 3.10-3.12 CI matrix gates before
  release workflows can proceed.

## 0.2.1 - 2026-08-31

- Isolate GitHub CLI configuration and state in a cleaned runtime directory so the
  strict post-publication worktree gate cannot be dirtied by CLI device metadata.

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
