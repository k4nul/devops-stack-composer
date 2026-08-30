# Execution evidence

An execution result is accepted only when its closed evidence bundle verifies from
disk. Console output and the existence of a run directory are not completion proof.

## Bundle layout

The canonical root contains, among other bounded material files:

| File | Purpose |
| --- | --- |
| `run.json` | Final profile, stage outcomes, failure stage, source identity, and artifact digest. |
| `plan.json` / `policy.json` | Immutable intended stages and required profile gates. |
| `state.json` | Ordered durable state transitions. |
| `artifact.json` / `artifacts.json` | Build-once count, canonical digest, immutable image reference, and service mapping. |
| `commands.json` | Redacted, bounded process summaries. |
| `supply-chain.json` | SBOM, vulnerability, provenance, and subject linkage. |
| `deployment.json` | Rendered, applied, workload, and runtime digest linkage. |
| `smoke.json` | Actual health and readiness request results. |
| `attestation.json` | Closed run identity, final status, and evidence subjects. |
| `resources.json` | Exact registry and kind ownership plus cleanup status. |
| `verification.json` | Independent bundle-verifier result. |
| `SHA256SUMS` / `checksums.json` | Closed inventory and content digests. |
| `summary.md` | Human-readable result generated from the same run data. |

Kubernetes manifests and observations are under `kubernetes/`; bounded tool output is
under `logs/`. All stored paths are relative to the run root. Symlinks, special files,
path traversal, unknown files, missing files, duplicate names, and checksum changes
fail verification.

## Same-digest proof

For each service, the verifier relates four independent observations:

```text
registry build/push digest
        = rendered Deployment image digest
        = API-observed Deployment image digest
        = running Pod imageID digest
```

The image is built once. A tag is retained as informational build intent, but every
Kubernetes execution target uses `repository@sha256:...`. A missing digest, a second
build, a mutable workload reference, swapped service digest, stale subject, or runtime
digest mismatch fails before the run can be closed as successful.

## Verify offline

```sh
devops-stack artifact verify \
  --project examples/python-service \
  --run RUN_ID \
  --output .devops-stack/runs \
  --json

devops-stack evidence verify \
  --project examples/python-service \
  --run RUN_ID \
  --output .devops-stack/runs \
  --json
```

Verification recomputes every material digest and the canonical manifest, parses the
strict schemas, rechecks cross-file identities, and refuses a bundle that changes a
failed result to success. It does not need Docker, kind, a registry, or the old
cluster.

`authenticity: NOT_ESTABLISHED` is expected for a local bundle: checksums prove
internal integrity, not who created it. A v0.2 GitHub release separately signs its
published files through GitHub artifact attestations and the post-publication release
profile verifies their repository, signer workflow, source tag, and commit.

## Failed and interrupted runs

When execution reaches the evidence boundary after a failure, the bundle is still
closed with `incomplete: true`, the first failing stage, and cleanup evidence. The
verifier may report that the bundle is structurally authentic to itself while
`executionSucceeded` remains false. This distinction prevents a valid checksum from
being mistaken for a successful deployment.

If interruption prevents canonical closure, keep the directory for diagnosis but do
not publish it as example evidence. Use the persisted recovery record for exact
cleanup, then start a new run ID; an old run is never resumed as a new success.

## Release evidence

`devops-stack release assemble` creates a deterministic `example-evidence.tar.gz`
from one successful `kind-e2e` bundle. The archive has a closed file count and byte
limit and rejects links and unsafe paths. The release verifier extracts only into a
private temporary directory, re-verifies the nested bundle, and confirms that its
source commit equals the package and release manifest commit.

`SHA256SUMS` is the root inventory for the release set. It checks the wheel, source
distribution, schemas, example configuration, package SBOM, file-provenance record,
evidence archive, and release manifest. The checksum file cannot list itself.
