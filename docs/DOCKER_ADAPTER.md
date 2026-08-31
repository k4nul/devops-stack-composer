# Docker adapter

`DockerBuildAdapter` converts the normalized application and image contract into the
official input shape of `docker-build-template` and validates that projection in an
ephemeral checkout.

## Generated files

| Path below `generated/` | Purpose |
| --- | --- |
| `docker/Dockerfile` | Generated runtime/build stages, or a copied existing Dockerfile. |
| `docker/Dockerfile.dockerignore` | Dockerfile-specific exclusions for source, credentials, build output, and management files. |
| `docker/image.env` | Exact 15-key upstream build-plan contract. |
| `docker/build.sh` | Safe wrapper with `--validate`, `--load`, and `--push` modes. |
| `docker/metadata.json` | Adapter, capability, image, runtime, and template metadata. |

The wrapper defaults to `--validate`. It requires
`DEVOPS_STACK_DOCKER_TEMPLATE` to point at the resolved locked checkout when invoked
directly. The generated Jenkinsfile sets that path from its environment or from
`devops-stack templates path docker`.

## Dockerfile strategies

For `generated`, the adapter chooses a maintained builder/runtime image pair for
Node.js, Python, Java, Go, Rust, or a static site. It places configured build steps in
the image, writes OCI labels, exposes the normalized container port, declares the
configured positive UID/GID, and uses the configured run command. With `multiStage:
true`, build and runtime stages are separate; Python copies installed packages and all
types copy the workspace into the runtime stage.

For `existing`, `build.dockerfile.path` is resolved beneath `application.root` and
copied to generated output. Strict validation scans the final stage and requires its
last `USER` instruction to contain the configured numeric UID (optionally with a GID).
This is a deliberately narrow proof; named users are not assumed to equal that UID.

## Official environment contract

`docker/image.env` contains only:

```text
REGISTRY IMAGE_NAME IMAGE_TAG CONTEXT DOCKERFILE PLATFORMS PUSH
SBOM PROVENANCE OCI_TITLE OCI_DESCRIPTION OCI_SOURCE OCI_REVISION
OCI_CREATED OCI_LICENSES
```

The generated values keep `PUSH=false` for plan validation, express all selected
platforms, and route OCI and supply-chain settings through documented upstream
inputs. Dynamic tags remain `__IMAGE_TAG__` until Jenkins or an explicit local build
provides a concrete value.

## Execution modes

- `generated/docker/build.sh --validate` runs the official no-push plan validator.
- `IMAGE_TAG=my-tag generated/docker/build.sh --load` validates and calls the official
  build script. It requires exactly one architecture. Because a locally loaded Docker
  image cannot carry registry attestations, this mode overrides only `SBOM` and
  `PROVENANCE` to `false` for both its plan check and build. Direct `--validate` and
  `--push` modes retain the configured values.
- `IMAGE_TAG=my-tag generated/docker/build.sh --push` calls the official push script.
  Registry authentication is intentionally external; Jenkins supplies it through a
  temporary Docker configuration.
- `devops-stack generate --write --build-image --image-tag my-tag` performs the
  optional single-platform local load build during composition. Generation requires
  `--write` before it may run this side effect, and `--image-tag` is invalid without
  `--build-image`.

Application context and template content are copied to a temporary stage. Destination
paths are checked against that stage, external context symlinks are rejected, and the
real source repositories are not modified. The upstream validator sees a temporary
`.dockerignore` mirror because its current interface checks the context-root name;
the persistent artifact remains the Dockerfile-specific
`Dockerfile.dockerignore`.

The staged context and generated ignore file both exclude `generated/`,
`generated-preview/`, and `.devops-stack/`, preventing prior reports or output from
entering a later build. An explicitly requested local image build is blocked before
Docker runs when generated output exists without a manifest or manifest verification
finds modified, missing, or untracked entries.

## Capability truth table

| Capability | Current behavior |
| --- | --- |
| Architectures | Passed through `PLATFORMS`. Local load is single-platform; push supports multiple platforms. |
| OCI labels | Wired through official metadata inputs and emitted in generated Dockerfiles. |
| SBOM | Boolean enablement is wired upstream for push. Local load disables Buildx attestations; after its single push Jenkins uses Syft against the resolved registry digest. The requested format is recorded, but is not configurable through the upstream input. |
| Provenance | Enabled/disabled and `min`/`max` mode are wired upstream for push; local load cannot retain registry attestations. |
| Scan | Not an upstream Docker capability; after its single push the Jenkins adapter uses Trivy against the resolved registry digest. |
| Cache | Unsupported by the locked template. Any enablement or from/to entry is a `FAILED` capability check. |
| Reproducibility | Requested intent and deterministic metadata are recorded; bit-for-bit image identity is not claimed. |

## Validation results

The adapter checks the template lock, context containment, generated or existing
runtime UID, exact environment projection, official no-push plan, and optionally a
local build. Missing tooling required for the upstream plan is
`BLOCKED_MISSING_REQUIRED_TOOL`. Docker/buildx absence during an explicitly optional
local build is `SKIPPED_MISSING_OPTIONAL_TOOL`; other non-zero upstream results are
`FAILED`.

Cross-project validation independently recovers registry, repository, tag,
architectures, application name, build artifact, runtime UID, and port from
`image.env`, `metadata.json`, and the Dockerfile. A matching adapter-declared contract
cannot hide mutated Docker output.
