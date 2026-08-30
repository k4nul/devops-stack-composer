# Roadmap

DevOps Stack Composer `0.1.0` is an alpha integration with a deliberately small public
contract: one schema version, three pinned adapters, three environments, Kustomize
output, and Jenkins-owned delivery.

## Near-term priorities

1. Add a reproducible controller-backed Jenkins Declarative and Job DSL validation
   fixture so plugin semantics can move from an explicit skip to executable evidence.
2. Bind pre-push SBOM/scan evidence to the published digest, either through a
   promote-without-rebuild interface or immutable post-push digest verification.
3. Coordinate an official cache interface in `docker-build-template`, then add cache
   projection only after upstream validation and end-to-end tests exist.
4. Design a pre-publication multi-architecture SBOM and scan path that validates each
   platform without weakening the current no-push-before-scan ordering.
5. Add signed template provenance or an allowlisted verification policy on top of full
   commit pins, marker checks, and license checks.
6. Expand release and installation validation across supported Python versions and
   add a second production-shaped example with a distinct runtime/build layout.

## Candidate improvements

- configurable report destinations and a stable report schema compatibility policy;
- richer diff mapping for existing project-native Kubernetes and pipeline layouts;
- optional live cluster dry-run and admission-policy checks with explicit credentials
  and no default cluster mutation;
- registry-backed verification of generated SBOM and provenance attestations;
- adapter compatibility metadata for reviewed template commit ranges;
- a structured inspection-confidence override workflow for monorepos;
- environment sets beyond the fixed `dev`, `staging`, and `production` contract in a
  future API version;
- upstream-supported Helm composition if it can preserve the same artifact and
  contract evidence as Kustomize.

## Non-goals without a design change

The composer will not silently track remote `main`, store credential values, manage a
Jenkins controller, mutate a Kubernetes cluster during generation, or absorb arbitrary
files into its ownership manifest. It will not claim a requested capability until the
relevant upstream interface and executable validation exist.

Roadmap items are intentions, not implemented guarantees. Current behavior is defined
by the schema, CLI help, generated artifacts, and executable tests documented in this
repository.
