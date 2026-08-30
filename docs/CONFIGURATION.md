# Configuration

The default input is `devops-stack.yaml`. It is validated against
[`schemas/devops-stack.schema.json`](../schemas/devops-stack.schema.json), JSON
Schema draft 7. The root and all defined nested objects reject unknown properties, so
misspellings are errors rather than ignored configuration.

```yaml
apiVersion: devops-stack.io/v1alpha1
kind: DevOpsStack
metadata: {name: orders-api}
application: {}
image: {}
build: {}
ci: {}
environments: {dev: {}, staging: {}, production: {}}
deployment: {}
supplyChain: {}
security: {}
policies: {}
```

Every top-level field shown above is required. For a complete working document, use
[`examples/python-service/devops-stack.yaml`](../examples/python-service/devops-stack.yaml).

## Metadata and application

`metadata.name`, `application.name`, and `application.serviceName` are lowercase DNS
labels of at most 63 characters. Metadata annotations are string pairs without ASCII
control characters.

`application` requires:

| Field | Meaning |
| --- | --- |
| `name` | Application identity used in image metadata and Jenkins job naming. |
| `serviceName` | Workload and Service identity used in Kubernetes. |
| `type` | One of `nodejs`, `python`, `java`, `go`, `rust`, or `static`. |
| `root` | Application root relative to the project. |
| `buildCommand` | Shell command used by the generated Dockerfile and Jenkins build stage. |
| `testCommand` | Shell command used by Jenkins test stage. |
| `runCommand` | Runtime command placed in the generated Dockerfile. |
| `buildArtifact` | Relative path recorded in the cross-project contract. |

Relative paths must not be absolute or contain a `..` segment. Commands are trusted
project input and execute during builds; configuration review is therefore a security
boundary.

## Image and build

`image.registry` is a lowercase host with an optional port. `image.repository` can
contain lowercase path segments. `image.architectures` is a unique, non-empty list of
`linux/amd64` and/or `linux/arm64`.

Tag strategies are:

| Strategy | Generated value | Jenkins resolution |
| --- | --- | --- |
| `branch-sha` | `__IMAGE_TAG__` | Sanitized branch slug plus the 12-character Git SHA. |
| `git-sha` | `__IMAGE_TAG__` | The 12-character Git SHA. |
| `semver` | `__IMAGE_TAG__` | Required Jenkins `VERSION` parameter. |
| `fixed` | The configured `value` | Used directly. |

Only `fixed` accepts and requires `image.tag.value`. A concrete tag must start with an
alphanumeric or underscore, contain only Docker-safe tag characters, and be at most
128 characters.

`build.context` is relative to `application.root`. `build.dockerfile.strategy` is
`generated` or `existing`; the existing strategy requires a relative `path`. An
existing Dockerfile must prove that the final stage uses the configured non-root UID,
or strict validation fails.

`multiStage` controls generated Dockerfile shape. `reproducible` records the requested
intent, but the locked Docker template guarantees deterministic metadata rather than
bit-for-bit image reproducibility. `cache` always contains `enabled`, `from`, and
`to`. Any requested cache wiring currently fails validation because the locked Docker
template has no official cache input; no unsupported flags are invented.

## CI and environment routing

`ci.jenkins.credentialId` is a Jenkins credential reference, never a credential value.
Each of `ci.branches.dev`, `staging`, and `production` is a non-empty unique list of
Jenkins GLOB branch patterns. The same pattern must not occur in more than one
environment. `ci.approval.production` controls generation of the production input
gate; production policy can require it to remain enabled.

## Deployment defaults and overrides

`deployment` supplies complete defaults. `environments.dev`, `staging`, and
`production` contain partial overrides. The merge is recursive for mappings; scalars
and lists replace their base value. For example:

```yaml
deployment:
  namespace: orders
  replicas: 1
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: 500m, memory: 256Mi}
  # Other required deployment fields omitted here.
environments:
  dev:
    namespace: orders-dev
  staging:
    namespace: orders-staging
    replicas: 2
  production:
    namespace: orders-production
    replicas: 3
    resources:
      limits: {cpu: "1", memory: 512Mi}
```

The nested production `limits` replaces those keys while inherited `requests` remain.
A list such as `secretRefs` replaces the inherited list in full.

Deployment fields cover namespace, replicas, container port, Service type and port,
liveness/readiness HTTP paths and timings, plain environment values, secret
references, resource requests/limits, RollingUpdate controls, and rollback history.

- Ports are integers from 1 through 65535.
- Probe paths start with `/`; delays are non-negative and periods are positive.
- Service type is `ClusterIP`, `NodePort`, or `LoadBalancer`.
- CPU quantities use whole/decimal cores or integer millicores; memory uses `Ki`,
  `Mi`, `Gi`, or `Ti`.
- Requests must not exceed limits after normalization.
- `maxUnavailable` and `maxSurge` are non-negative integers or `0%` through `100%`.
  They cannot both be zero, and production cannot permit every replica to be
  unavailable.
- Rollback history requires a positive `revisionHistoryLimit` when configured.

The container port, health path, and readiness path must remain consistent across all
environments because they are part of one image contract. Service ports and
namespaces can differ by environment.

## Plain environment and secret references

Plain environment keys use uppercase shell-style names. Names that look like secret,
token, password, private-key, access-key, API-key, or authorization fields are
rejected. Values can be strings, numbers, or booleans and become ConfigMap strings.

Secrets are references only:

```yaml
secretRefs:
  - name: orders-api-secrets
    keys: [DATABASE_URL, API_TOKEN]
```

The composer emits container `secretKeyRef` entries that expect those Secret objects
and keys to exist. It does not generate Secret resources. A key cannot be duplicated
across references or also appear in the plain environment mapping for the same
environment.

## Supply chain and security

`supplyChain.sbom` selects `spdx-json` or `cyclonedx-json`; the locked Docker template
can enable SBOM generation but cannot configure that format itself. Jenkins uses the
selected format with Syft for its local pre-push SBOM. Provenance can be enabled in
`min` or `max` mode. Image scanning can fail at `critical`, `high`, or `medium`, or use
`never` to report findings without failing Trivy.

`security` controls non-root execution, positive runtime UID, read-only root
filesystem, privilege escalation, `RuntimeDefault` seccomp, and the ServiceAccount
name. Kubernetes also drops every Linux capability and disables automatic service
account token mounting.

`policies.production` supplies strict gates: minimum replicas (at least two), required
approval, resource limits, and read-only root filesystem. Independent semantic checks
also require non-root execution, disabled privilege escalation, and enabled rollback
for production.

## Validation errors

Schema failures identify the JSON path, constraint or expected type, received value,
and an example. Values at sensitive-looking paths are redacted. YAML must contain one
mapping at the root; syntax errors include line and column when available.
