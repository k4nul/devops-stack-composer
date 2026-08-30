# Release process

Version 0.2 uses a tag-driven GitHub release with a closed asset set, real kind
evidence, GitHub artifact attestations, a fresh-download comparison, and a cumulative
post-publication release run.

## Preconditions

- `main` is clean and synchronized with `origin/main`.
- CI and Execution E2E pass for the exact release commit.
- `pyproject.toml`, `devops_stack_composer.__version__`, and `CHANGELOG.md` name the
  same semantic version.
- Docker and the checksum-pinned execution tools can complete `kind-e2e`.
- The release tag and GitHub release do not already exist.
- No credential, `.env`, local management file, runtime cache, or evidence directory
  is tracked.

Run the local quality and package checks documented in the README, then produce a
fresh successful kind run for the exact final commit:

```sh
devops-stack execute \
  --project examples/python-service \
  --environment staging \
  --profile kind-e2e \
  --output .devops-stack/release-runs \
  --image-tag release-candidate \
  --json
```

Record the returned run ID. Build and close the release set:

```sh
python -m build
python -m twine check dist/*.whl dist/*.tar.gz

devops-stack release materials \
  --project . \
  --version 0.2.1 \
  --commit "$(git rev-parse HEAD)" \
  --output dist/release-materials

devops-stack release assemble \
  --project . \
  --version 0.2.1 \
  --commit "$(git rev-parse HEAD)" \
  --materials dist/release-materials \
  --evidence-run RUN_ID \
  --evidence-output examples/python-service/.devops-stack/release-runs \
  --output dist/release-v0.2.1

devops-stack release verify \
  --project . \
  --directory dist/release-v0.2.1 \
  --version 0.2.1 \
  --commit "$(git rev-parse HEAD)"
```

These directories are ignored local products. They are inputs to validation, not
source files.

## Tag-triggered workflow

After all checks pass, create one annotated tag at the clean `main` commit and push
it without force:

```sh
git tag -a v0.2.1 -m "release: v0.2.1"
git push origin v0.2.1
```

`.github/workflows/release.yml` then performs the release independently:

1. proves tag, checkout, package version, source commit, and clean worktree equality;
2. runs every unit/integration test and a fresh real `kind-e2e` execution;
3. builds and inspects wheel and source distribution;
4. creates package SBOM, file provenance, and the closed asset set;
5. re-verifies the nested example evidence and every checksum offline;
6. gives each release file a GitHub/Sigstore build-provenance attestation;
7. creates the GitHub Release and uploads the exact files;
8. downloads all files into a fresh directory and compares their bytes;
9. verifies every attestation against this repository, `.github/workflows/release.yml`,
   the tag ref, and the exact source commit;
10. repeats Docker/kind execution under the `release` profile and records the
    post-publication gates.

The workflow uses minimal permissions per job. Only the publication job receives
`contents: write`; only attestation and trusted-publishing jobs receive an OIDC token.
Every third-party or GitHub action is pinned to an immutable commit SHA.

## Published asset set

The release directory contains exactly one of every required role:

- wheel and source distribution;
- `devops-stack.schema.json`, `execution-report.schema.json`, and
  `execution-evidence.schema.json`;
- `devops-stack.example.yaml`;
- `package.spdx.json`;
- `provenance-verification.json` (truthfully marked file provenance, not a signature);
- `example-evidence.tar.gz` from the successful real run;
- `release-manifest.json`;
- `SHA256SUMS` covering every preceding file.

GitHub artifact attestations are stored by GitHub separately from these portable
files. Verify a downloaded file with:

```sh
gh attestation verify PATH \
  --repo k4nul/devops-stack-composer \
  --signer-workflow k4nul/devops-stack-composer/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.1 \
  --source-digest COMMIT
```

## PyPI publication

Python publication is deliberately disabled until the owner configures a PyPI
trusted publisher for this repository, the `release.yml` workflow, and the `pypi`
environment. Once configured, set the repository Actions variable
`PUBLISH_TO_PYPI=true`. The isolated final job downloads the already verified set,
selects only its wheel and source distribution, and publishes with OIDC; it never
receives a long-lived PyPI token.

Absence of that external account configuration does not weaken or block the GitHub
Release. It remains a clearly reported optional publication channel.

## Failure and retry policy

Do not move or overwrite a published tag, replace assets under the same version, use
force-push, or mark a failed workflow successful manually. Fix the cause on `main`,
increment the version, and create a new release. If publication fails before a GitHub
Release is created, the unmodified tag workflow may be rerun after an external outage;
if assets may have become visible, inspect them before any retry.
