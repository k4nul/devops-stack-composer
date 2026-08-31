# Migrating from v0.1

Version 0.2 keeps the configuration API at `devops-stack.io/v1alpha1`. A valid v0.1
document remains valid, and its normal `generate`, `validate`, `diff`, `explain`, and
`report` workflow remains static. No Docker build, registry push, kind cluster, or
supply-chain execution begins merely because the CLI was upgraded.

## Compatibility defaults

When the four v0.2 runtime blocks are absent, normalization supplies:

| Model area | v0.1-compatible default |
| --- | --- |
| Validation | `profile: static` |
| Execution | `profile: static`, `.devops-stack/runs`, cleanup always, failure evidence retained |
| Registry | `mode: existing`, with host and repository copied from `image`, and `insecureLocalhostOnly: false` |
| Kubernetes E2E | kind, staging, dry-run for all three environments, 180-second timeout, resolved staging probe paths, rollback enabled, cleanup always |
| Supply chain | `sbom.enabled` and `provenance.enabled` also become their `required` values; provenance mode defaults to `max`; legacy `scan` remains accepted; both digest-verification flags default to false |

These are normalized values, not permission to perform runtime work. `execute` is
always an explicit side-effect boundary. In particular, overriding an old config
with `execute --profile supply-chain` can select its existing `image.registry`; review
`execution plan` and add an explicit registry block before doing that.

## Preview the upgrade

Keep the old generated tree until the current plan has been reviewed:

```sh
devops-stack generate --project PATH
devops-stack diff --project PATH --against generated
devops-stack generate --project PATH --write
devops-stack validate --project PATH
devops-stack report --project PATH
```

`generate` is preview-only without `--write`. `validate` verifies the bytes and
ownership manifest already on disk, so run it after the reviewed write rather than as
a replacement for the preview.

## Intentional generated-tree delta: 32 to 33

For the same v0.1 example and locked template commits, v0.2 changes the planned
adapter-owned artifact count from 32 to 33, excluding
`generated/.devops-stack-manifest.json`. The sole added path is
`generated/jenkins/artifact-contract.json`.

That file is intentional evidence, not unexplained render drift. It declares one
official push invocation, registry-digest resolution, digest-subject SBOM, scan, and
provenance paths, digest-only deployment, and no rollback rebuild. The ownership
manifest remains a separate generated control file and records the new path.

This count does not describe an execution evidence bundle. Run evidence has its own
closed inventory and includes required operator-facing `execution-plan.json`,
`report.json`, and `report.md` records alongside compatibility records; its verifier
reports the actual checksummed file count for that run.

The Docker, Jenkins-template, and Kubernetes source commit pins are unchanged from
v0.1.0. `templates.lock.json` changes only the Jenkins adapter version from `1.0.0`
to `2.0.0`, reflecting the new generated contract and pipeline semantics.

## Update policy fields

Legacy supply-chain keys remain supported, but the v0.2 form makes enforcement and
digest expectations explicit:

| v0.1 field | v0.2 field or decision |
| --- | --- |
| `supplyChain.sbom.enabled` | `supplyChain.sbom.required` |
| `supplyChain.provenance.enabled` | `supplyChain.provenance.required`; retain or add `mode` |
| `supplyChain.scan.enabled/failOn` | `supplyChain.vulnerability.required`, `severities`, `ignoreUnfixed`, and `maximumAllowed` |
| No exception metadata | Optional allowlist entries with vulnerability ID, package, reason, owner, and expiry |
| No digest policy | `verification.requireSingleDigest` and `requireDigestPinnedDeployment` |
| No runtime selection | Matching `validation.profile` and `execution.profile` |
| Image registry only | Explicit `registry` mode, host, repository, and localhost policy |
| No E2E policy | Complete `kubernetes.e2e` block |

There is no automatic one-field translation for `scan.failOn: never`; choose the
v0.2 severities and permitted finding count deliberately. Expired exceptions fail
policy.

## Opt in to execution

Choose one cumulative profile: `static`, `supply-chain`, `kind-e2e`, or `release`.
For a local kind run, add complete matching runtime blocks like the ones in the
[configuration reference](CONFIGURATION.md), use `registry.mode: ephemeral-local`,
keep one Linux architecture, and preview before execution:

```sh
devops-stack doctor --project PATH --profile kind-e2e --json
devops-stack execution plan \
  --project PATH \
  --profile kind-e2e \
  --environment staging \
  --image-tag migration-preview
devops-stack execute \
  --project PATH \
  --profile kind-e2e \
  --environment staging \
  --image-tag migration-e2e \
  --json
```

`local-kind` is accepted only as an `execution.profile` compatibility alias and
normalizes to `kind-e2e`; use `kind-e2e` in new files. Production selection requires
`--approve-production` but still targets isolated local kind, not a production
cluster. See [Execution](EXECUTION.md) for evidence inspection, cleanup, and release
commands.
