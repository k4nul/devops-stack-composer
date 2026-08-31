# Release process

Version 0.2 uses a tag-driven GitHub release with a closed asset set, real kind
evidence, GitHub artifact attestations, cumulative validation while the release is
still a draft, and a fresh post-publication download and installation check.

## Preconditions

- `main` is clean and synchronized with `origin/main`.
- CI and Execution E2E pass for the exact release commit.
- `pyproject.toml`, `devops_stack_composer.__version__`, and `CHANGELOG.md` name the
  same semantic version.
- Docker and the checksum-pinned execution tools can complete `kind-e2e`.
- The release tag does not already exist before it is pushed. A GitHub release for
  that tag must either be absent or be an unpublished, non-prerelease draft whose
  existing assets are an exact subset of the newly built closed set.
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
2. checks that hosted Docker and Buildx are inside reviewed version ranges, records
   their exact versions, runs every unit/integration test, and completes a fresh real
   `kind-e2e` execution;
3. builds and inspects one wheel and one source distribution;
4. creates package SBOM, file provenance, and the closed asset set;
5. re-verifies the nested example evidence and every checksum offline, then installs
   and verifies both locally built distributions in separate temporary environments;
6. creates an empty GitHub draft when none exists, or verifies every asset already in
   an existing draft as an exact byte-identical subset of the closed set;
7. attests every release file and uploads only missing draft assets without clobbering
   or deleting an existing asset;
8. downloads the complete draft into a fresh directory, compares every byte, and
   verifies every attestation against this repository, `.github/workflows/release.yml`,
   the tag ref, and the exact source commit;
9. repeats Docker/kind execution under the cumulative `release` profile while the
   release is still private and records fresh offline evidence verification;
10. on another runner, freshly downloads the draft and installs both distributions
    without using a package cache;
11. immediately before publication, downloads and compares the candidate again,
    re-verifies every attestation, and proves that the live server-side tag resolves
    to the exact workflow commit;
12. publishes only that unchanged draft, then uses a fresh post-publication runner to
    download and compare the public files, re-verify attestations, install both
    distributions without a package cache, and reconfirm the live tag commit.

All gates that authorize publication, including cumulative execution and a complete
draft-distribution installation check, therefore finish before the draft becomes
public. The final job independently repeats the distribution check over the bytes
that are actually public; it is not a substitute for a pre-publication check.

The workflow uses minimal permissions per job. The draft-staging and publication jobs
receive `contents: write`; only draft staging receives `attestations: write` and an
OIDC token. `GH_TOKEN` is never job-wide: it is mapped only onto individual trusted
steps that invoke GitHub CLI operations, while checkout disables persisted
credentials and distribution installation receives no GitHub token. Every third-party
or GitHub action is pinned to an immutable commit SHA, and the workflow installs a
checksum-pinned GitHub CLI.

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

Version 0.2 does not publish to PyPI. The release workflow has no PyPI job, credential,
environment, or enablement variable; the GitHub Release is its only publication
target. Adding PyPI publication requires a separately reviewed workflow change after
the owner configures and verifies a trusted publisher. It must use OIDC rather than a
long-lived PyPI token.

## Failure and retry policy

Do not move or overwrite a published tag, replace assets under the same version, use
force-push, or mark a failed workflow successful manually. Fix a release defect on
`main`, increment the version, and create a new release.

If draft creation or upload is interrupted, rerun the failed jobs without changing the
tag or source. The staging job downloads every existing draft asset, requires the
draft to contain only a byte-identical subset of the current closed set, and uploads
only missing names without `--clobber`. An unexpected name or changed byte stops the
run; the workflow never repairs that condition by overwriting or deleting evidence.

If a job loses contact immediately after publication, a failed-job retry accepts the
already-public release only after repeating the exact byte, attestation, release-state,
and live-tag checks. A post-publication verification failure must not be hidden or
used as permission to replace public assets. Preserve its diagnostics, investigate,
and rerun only the unchanged failed verification when appropriate.
