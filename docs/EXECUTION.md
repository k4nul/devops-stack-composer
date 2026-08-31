# Execution-backed validation

Version 0.2 adds an opt-in execution path alongside deterministic composition. It
builds the selected application image once, resolves the registry manifest digest,
binds every later subject to that immutable reference, and closes a checksummed
evidence bundle. The `kind-e2e` and `release` profiles push only to a run-owned
loopback registry and deploy to a run-owned kind cluster. `supply-chain` may instead
use an explicitly configured existing registry; authentication remains delegated to
the operator's Docker credential helper.

Generation remains side-effect free by default. `execute` is the explicit boundary
that may create Docker and Kubernetes resources.

## Profiles

Profiles are cumulative. A later profile must pass every required stage from the
profiles before it.

| Profile | Required proof |
| --- | --- |
| `static` | Configuration, template lock, adapter contracts, and generated-file plan. |
| `supply-chain` | Static proof plus configured registry, one build/push, canonical digest, SBOM, vulnerability policy, file provenance, and artifact contract. |
| `kind-e2e` | Supply-chain proof plus Kubernetes schemas, server-side dry-run, apply, rollout, pod image, health, readiness, rollback, and cleanup. |
| `release` | A complete kind run plus package and closed asset verification, fresh GitHub download, GitHub artifact attestations, clean worktree, and exact tag/HEAD/source commit equality. |

A missing required executable blocks the selected profile. It is never converted to
a passing static check.

## Operator command map

The v0.2 command surface is intentionally explicit:

| Command | Purpose |
| --- | --- |
| `devops-stack doctor --profile PROFILE` | Classify installed tools against one cumulative profile. |
| `devops-stack execution plan` | Print the validated logical stages without allocating resources. |
| `devops-stack execute` | Cross the side-effect boundary; `--dry-run` is an equivalent plan-only entry point. |
| `devops-stack execution show` | Freshly verify and show one completed run. |
| `devops-stack artifact inspect` | Summarize immutable artifact identity and the recorded SBOM, scan, provenance, and deployment environment. |
| `devops-stack artifact verify` | Offline-verify a run, or generated Jenkins evidence supplied with `--artifact` and its optional evidence-file arguments. |
| `devops-stack evidence verify` | Verify the closed inventory and same-digest semantics of a canonical run. |
| `devops-stack report --run RUN_ID` | Read the stored human or JSON run report after fresh offline verification. |
| `devops-stack execution cleanup` | Recover after interruption by removing only exact sealed resource IDs. |
| `devops-stack cluster kind create`, `status`, or `destroy` | Explicitly manage the low-level run-owned kind/registry lifecycle; normal executions manage it automatically. |
| `devops-stack release materials`, `assemble`, or `verify` | Create package evidence, close the release asset set around a successful kind run, and verify it offline. |

Run-scoped readers accept `--output` when the evidence root differs from
`.devops-stack/runs`. `execute --keep-resources` and
`--keep-environment-on-failure` are debugging options: retained cleanup is
`NOT_APPLICABLE`, so the required cleanup gate does not pass. Full release assembly
arguments are in [Release](RELEASE.md).

## Host requirements

The real `kind-e2e` path requires Docker with Buildx, PowerShell 7, Git, kind
`v0.33.0`, kubectl `v1.36.4`, kubeconform `v0.8.0`, Syft `1.51.1`, and Trivy
`0.74.0`. The release profile additionally requires GitHub CLI `2.95.0` or a
compatible version with artifact-attestation verification.

GitHub-hosted Linux jobs install these exact binaries from checksummed upstream
archives:

```sh
scripts/install-kind-e2e-tools.sh "$RUNNER_TEMP/devops-stack-tools"
export PATH="$RUNNER_TEMP/devops-stack-tools:$PATH"
```

The installer accepts only Linux x86-64 and refuses to replace an existing target.
On another platform, install the documented versions through the platform's normal
package mechanism and confirm them with `doctor`.

## Plan without side effects

The following commands validate inputs and print the logical target without creating
a registry, building an image, or contacting a cluster:

```sh
devops-stack execution plan \
  --project examples/python-service \
  --environment staging \
  --profile kind-e2e \
  --image-tag local-e2e

devops-stack execute \
  --project examples/python-service \
  --environment staging \
  --profile kind-e2e \
  --image-tag local-e2e \
  --dry-run --json
```

Use `doctor --profile kind-e2e` before the first real run. Resolve locked templates
once without `--no-fetch`; subsequent offline runs may use `--no-fetch`.

## Run the real kind path

```sh
devops-stack execute \
  --project examples/python-service \
  --environment staging \
  --profile kind-e2e \
  --output .devops-stack/runs \
  --image-tag local-e2e \
  --json
```

The default policy cleans the exact registry container and kind node recorded for
the run, on success and on failure. `--keep-environment-on-failure` is an explicit
debugging exception. `--keep-resources` deliberately makes the cleanup gate fail and
must not be used as release evidence.

Production execution requires `--approve-production`. This approval permits the
isolated local validation apply only; it does not authorize a cloud deployment or an
external registry push.

## State and recovery

Each run gets a non-reusable ID and its own directory. The durable state transitions
are:

```text
planned -> validated -> building -> built -> pushing -> digest_resolved
        -> cluster_preparing -> applying -> waiting_ready -> smoke_testing
        -> attesting -> collecting_evidence -> succeeded|failed -> cleaned
```

Every transition records bounded, redacted command evidence, timestamps, inputs,
outputs, error category, retryability, and the previous state. Invalid skips and a
change from success back to failure are rejected.

Inspect or re-verify a run without contacting its old registry or cluster:

```sh
devops-stack execution show --project examples/python-service --run RUN_ID --json
devops-stack artifact verify --project examples/python-service --run RUN_ID --json
```

If a process was interrupted after resources were created, cleanup reads the sealed
ownership and recovery records and removes only exact IDs that still match:

```sh
devops-stack execution cleanup --project examples/python-service --run RUN_ID --json
```

Never delete an unknown Docker container or cluster merely because its name resembles
a composer name. A missing or contradictory ownership record is a blocker, not
permission to guess.

## Release profile

`release` is a GitHub-release gate. It needs a locally assembled asset set and an
unpublished draft or public GitHub release at the same `vVERSION` tag. It repeats the
real Docker/kind run, downloads every release asset into a private temporary
directory, checks exact bytes, verifies each GitHub artifact attestation against this
repository's release workflow and tag commit, then proves that the checkout is clean
and tagged at the same source commit. The tag-driven workflow runs this profile while
the release is still a draft.

```sh
GH_TOKEN="$(gh auth token)" devops-stack execute \
  --project examples/python-service \
  --environment staging \
  --profile release \
  --release-assets .devops-stack/release-v0.2.2 \
  --release-version 0.2.2 \
  --release-repository k4nul/devops-stack-composer \
  --json
```

`GH_TOKEN` is passed only to the two GitHub CLI operations and is included in the
safe runner's redaction set. The release workflow performs this command on a clean,
tagged GitHub-hosted runner; local operators may instead rely on their GitHub CLI
credential store.

## Limits

- The runtime is local-only and supports one Linux architecture per execution.
- The ephemeral registry used by `kind-e2e` and `release` is unauthenticated because
  it is bound to loopback and exists only for the isolated run. An explicitly selected
  existing registry is supported only by the supply-chain path and receives no
  implicit credential.
- The generated file provenance is checksummed file evidence, not a signature.
  Published release files receive separate GitHub/Sigstore artifact attestations.
- Local evidence reports `authenticity: NOT_ESTABLISHED`; checksums establish internal
  integrity, not who created the run.
- A `production` environment run is still isolated local kind validation, not a
  production-cluster deployment or certification.
- Generated Jenkins syntax and contracts are validated statically; no Jenkins
  controller, plugin matrix, credential binding, apply, approval, or rollback is run
  by this repository's v0.2 tests.
- The composer does not select an external registry, cloud cluster, production
  account, or credential implicitly.
