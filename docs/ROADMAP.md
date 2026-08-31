# Roadmap

DevOps Stack Composer `0.2.2` is an alpha integration with a deliberately small public
contract: one schema version, three pinned adapters, three environments, Kustomize
output, Jenkins-owned delivery, and an explicit local execution/evidence path.

## v0.3 candidates

These are candidates, not commitments, and none changes the v0.2 contract:

1. Jenkins Test Harness validation.
2. A documented Jenkins controller/plugin compatibility matrix.
3. Execution of the generated Jenkins pipeline on a real controller.
4. Full Jenkins-to-registry-to-kind end-to-end validation.
5. Runtime validation of generated Job DSL.
6. Runtime validation of Jenkins credential binding and redaction.
7. Actual Jenkins execution of production approval and deployment rollback paths.
8. Multi-service composition and evidence.
9. First-class monorepo discovery, selection, and ownership.
10. Explicit cloud-registry integration with credential and cleanup boundaries.

## Upstream Docker template candidates

Cache support remains blocked until `docker-build-template` provides all of:

- an official `cache-from`/`cache-to` input contract;
- versioned cache capability metadata;
- validation of cache sources and destinations; and
- cache provenance that can be related to the build result.

Composer support would follow only after those upstream interfaces and their
end-to-end evidence exist. No cache flags are inferred in v0.2.

## Other later candidates

- configure and verify PyPI trusted publishing after the owner establishes the
  external publisher and environment;
- add signed template provenance or an allowlisted verification policy on top of
  full commit pins, marker checks, and license checks;
- expand release and installation validation across supported Python versions;
- support environment sets beyond `dev`, `staging`, and `production` only in a future
  API version; and
- consider upstream-supported Helm composition only if it preserves the current
  artifact and evidence contracts.

## Non-goals without a design change

The composer will not silently track remote `main`, store credential values, manage a
Jenkins controller, mutate a Kubernetes cluster during generation, or absorb arbitrary
files into its ownership manifest. It will not claim a requested capability until the
relevant upstream interface and executable validation exist.

Roadmap items are intentions, not implemented guarantees. Current behavior is defined
by the schema, CLI help, generated artifacts, and executable tests documented in this
repository.
