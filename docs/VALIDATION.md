# Validation

Validation is evidence-based and layered. A declaration such as a matching adapter
contract or an existing file is not accepted as proof that rendered behavior is
correct.

## Status model

Every check has exactly one status:

| Status | Meaning | Overall result |
| --- | --- | --- |
| `PASSED` | The named check executed and its acceptance condition held. | Does not fail the report. |
| `FAILED` | The check executed, or could be evaluated internally, and found an error. | Fails the report. |
| `SKIPPED_MISSING_OPTIONAL_TOOL` | An optional executable was unavailable, or an optional downstream check had no renderer. | Does not by itself fail the report. |
| `BLOCKED_MISSING_REQUIRED_TOOL` | Required evidence could not be produced because its tool was unavailable. | Fails the report. |

Overall `passed` is true only when no check is `FAILED` or
`BLOCKED_MISSING_REQUIRED_TOOL`. Skips remain visible in human output, JSON, the
manifest summary, and reports; they are never upgraded to passes.

## Validation layers

### Configuration schema

YAML must parse to a mapping and satisfy the complete draft-7 JSON Schema. Unknown
fields, invalid relative paths, wrong types, missing values, invalid enums, unsafe
rollout strings, secret-looking plaintext environment keys, and malformed resource
quantities fail before adapter execution.

### Template resolution

Each template must resolve to the lock's full commit and contain required interface
markers and its declared MIT license file. A different local `HEAD` is a failure, not
an implicit upgrade.

### Adapter evidence

Adapters report deterministic render checks and results from official upstream seams:

- Docker's no-push build-plan validator, plus an optional local build when requested;
- Jenkins JSON job and pipeline plans plus Job DSL export;
- Kubernetes profile/plan/render/security scripts;
- optional Groovy, Kustomize, kubectl, and kubeconform checks.

The upstream Kubernetes bundle validator is pinned to offline `kubeconform` mode;
its built-in structural preflight still runs when kubeconform is absent. Separate
`kustomize build` and `kubectl kustomize` checks exercise overlay rendering without
contacting a cluster.

Commands run in temporary staging directories with timeouts. Their bounded diagnostic
details are available in JSON output and reports.

### Cross-project contract

The validator first requires Docker, Jenkins, and Kubernetes results. It compares
each adapter's canonical contract with the normalized model at exact paths, then
derives critical values from primary artifacts rather than trusting only those
declarations.

Artifact-derived checks cover Docker environment/metadata/Dockerfile values, Jenkins
environment records and exact pipeline assignments, and each Kubernetes overlay's
Deployment, Service, Namespace, Kustomization, probes, security, secrets, image, and
architecture scheduling. Missing, malformed, wrong-shaped, or mutated primary
artifacts fail cleanly.

Semantic checks additionally enforce:

- one container port and one pair of health/readiness endpoints across environments;
- one deployment environment per branch pattern;
- resource requests not exceeding limits;
- unique secret keys with no plaintext collision;
- at least one possible rolling-update path and production availability;
- production replica, approval, resource, runtime-security, and rollback policy.

### Generated-file integrity

`devops-stack validate` composes fresh artifacts and then requires an existing
`generated/.devops-stack-manifest.json`. It verifies:

- tracked SHA-256 hashes and POSIX modes;
- missing, modified, symlink-replaced, and untracked paths;
- the canonical hash of the current configuration;
- current template commits and adapter versions;
- equality between freshly rendered content and manifest content.

If no manifest exists, validation fails with guidance to run `generate --write`.
Use `generate` for a pre-write validation and plan.

## Command behavior

```sh
# Compose and validate, but do not write.
devops-stack generate --project .

# Write only when every required gate passes.
devops-stack generate --project . --write

# Recompose and verify the previously written tree.
devops-stack validate --project .

# Include an actual single-platform Docker load build.
devops-stack validate --project . --build-image --image-tag validation-smoke

# Machine-readable checks and details.
devops-stack validate --project . --json
```

`generate`, `validate`, `diff`, and `report` all compose the adapters and therefore
exercise their normal upstream validation by default. `diff` can still print planned
differences when composition has failures. It exits non-zero when validation fails or
when any planned file is added, modified (including mode-only changes), or removed, so
an exit code of zero is a strict no-change CI gate.

The CLI returns zero for a passing command, one for a completed validation result that
did not pass, and two for invalid arguments or a domain/IO error caught at the command
boundary.

## Tool requirements

`doctor` classifies Git, PowerShell 7, Docker, and Buildx as required for normal
locked composition. The official Docker no-push plan validator uses Docker and
Buildx even when no local image build is requested. Java, Groovy, Kustomize,
kubectl, kubeconform, Helm, Syft, Trivy, and Cosign are optional host probes. An
enabled Jenkins SBOM or scan stage still requires Syft or Trivy, respectively, on
the Jenkins agent; the local doctor probe does not prove controller/agent readiness.

The current generated Kubernetes source has a strong internal YAML validator even
when external Kubernetes tools are absent. That internal pass does not change the
external checks from `SKIPPED_MISSING_OPTIONAL_TOOL`.

## Project tests

The repository test suite exercises schema errors, override normalization, source and
lock handling, all adapters, malformed artifact contracts, path and symlink defenses,
manifest ownership, diff redaction, CLI write gates, missing-tool semantics, example
inspection, and composition workflows.

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tests -p 'test_validation.py' -v
```

Run the narrowest relevant test first. A missing external executable must be reported
as skipped or blocked according to its role; it must not be described as a successful
tool-backed validation.
