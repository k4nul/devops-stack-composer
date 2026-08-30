# Troubleshooting

Start with a local-only diagnosis when network access is uncertain:

```sh
devops-stack doctor --project . --no-fetch
devops-stack templates list --project . --no-fetch
```

Add `--json` when exact check details are needed. Use `doctor --remote` only when a
network query is intended.

## Template cannot be resolved

The resolver checks CLI overrides, template-specific environment variables, the
default local repository directory, and the cache before fetching the locked remote
commit. Confirm the chosen checkout has the required scripts and a Git `HEAD` equal to
the lock:

```sh
git -C /path/to/template rev-parse HEAD
devops-stack templates list --project . \
  --template docker=/path/to/docker-build-template
```

An explicit path is not an override for commit integrity. Use `templates update` to
review a new commit; do not bypass the mismatch.

## Required PowerShell is blocked

Normal Jenkins and Kubernetes upstream validation uses PowerShell 7. If `pwsh` is
missing, the result is `BLOCKED_MISSING_REQUIRED_TOOL` and the command fails. Install
PowerShell 7 and rerun `doctor`. Windows PowerShell is not treated as the equivalent
executable.

## Optional validator is skipped

Missing Groovy, Kustomize, kubectl, or kubeconform is reported as
`SKIPPED_MISSING_OPTIONAL_TOOL`. This is expected on a minimal workstation and does
not mean that tool's check passed. Install the tool and rerun the same command to gain
that evidence. The Jenkins controller-backed Declarative linter is not configured by
this project and remains an explicit skip.

## `validate` says the manifest is missing

`validate` checks previously written bytes as well as fresh composition. First run:

```sh
devops-stack generate --project .
devops-stack generate --project . --write
devops-stack validate --project .
```

The first command is a safe preview. If the write remains blocked, fix its failed or
required-blocked checks rather than creating a manifest manually.

## Generated file conflict

A planned target either differs from its recorded hash/mode or already exists without
manifest ownership. Review it with `diff` and the generation plan. If replacement is
intended, rerun `generate --write --force`. Without `--force`, the file is preserved.

`--force` does not solve these distinct cases:

- `stale`: a previously generated path is no longer planned; review and remove it
  manually;
- `unowned`: an unrelated file or symlink inside `generated/` is not in the current
  plan or manifest; move it outside the generated tree;
- non-regular target: replace it with a safe regular-file location after investigating
  why it exists.

Generation never automatically deletes those paths.

## Report already exists

Reports are also protected from accidental overwrite. Review
`.devops-stack/reports/devops-stack-report.{md,json}`, then use:

```sh
devops-stack report --project . --force
```

## Docker cache capability failed

The locked Docker template has no official cache from/to input. Set all of:

```yaml
cache:
  enabled: false
  from: []
  to: []
```

The composer intentionally fails a requested cache instead of generating unverified
Buildx flags.

## Local image build failed before starting

`--build-image` requires `--image-tag` with a concrete Docker-safe tag and exactly one
architecture. It also refuses to run when cache capability or existing-Dockerfile UID
validation failed. Check Docker and Buildx with `doctor`, then use a value such as
`local-smoke`.

## Multi-platform supply-chain check failed

The generated Jenkins pipeline runs Syft/Trivy before publication, which needs a
locally loaded image. Docker cannot load a multi-platform manifest as one local image.
For the current adapter, choose one architecture when SBOM or scan is enabled, or
disable those local checks after a deliberate policy review. Final multi-platform
push remains available when local pre-push checks are not requested.

## Existing Dockerfile runtime is unverified

The final stage must contain `USER <configured runAsUser>` or
`USER <configured runAsUser>:<gid>`. A named user is not treated as proof of its UID.
Align the Dockerfile and `security.runAsUser`, or use the generated strategy.

## Production policy failed

Check the resolved production override, not only `deployment` defaults. Common causes
are replicas below `minimumReplicas`, approval disabled, missing limits, writable root
filesystem, root UID, privilege escalation, rollback disabled, or `maxUnavailable`
that can remove all production replicas.

## Secret or environment validation failed

Do not put credential-like values in `deployment.environment` or an environment
override. Create the Secret externally and list its name and keys under `secretRefs`.
Ensure the same key is not both plain and secret-backed, and is not repeated across
two Secret references for one environment.

## Branch routing failed

Each exact Jenkins GLOB string may belong to only one environment. Patterns are not
analyzed for semantic overlap, so keep them visibly disjoint and avoid repeating the
same string in two lists.

## Semver pipeline stops at tag resolution

The `semver` strategy creates a required Jenkins `VERSION` parameter. Supply a
non-empty Docker-safe value for that build. The composer validates tag syntax but
does not independently prove semantic-version ordering.

## Exit code 2

Exit code 2 indicates an argument, path, configuration, lock, source-resolution, or
IO error caught at the CLI boundary. Exit code 1 means the command completed enough to
produce a validation report, but at least one required check did not pass. Use JSON
output and the first failing check to distinguish them.
