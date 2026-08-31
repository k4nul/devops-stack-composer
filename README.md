# DevOps Stack Composer

DevOps Stack Composer turns one declarative application contract into a coherent
Docker build, Jenkins delivery pipeline, and Kubernetes deployment tree. It is an
orchestration layer over three independent public templates: it pins and invokes
their supported interfaces instead of copying their repositories into this one.

The current release is `v0.2.5` and the configuration API remains
`devops-stack.io/v1alpha1`.

## What it provides

- strict YAML and JSON Schema validation with unknown-field rejection;
- application inspection and an explicitly review-required initial config;
- locked, commit-exact Docker, Jenkins, and Kubernetes source resolution;
- a single normalized model shared by all three adapters;
- generated Docker, Jenkins, and Kubernetes artifacts with environment overlays;
- artifact-derived cross-project contract and production-policy checks;
- preview-first, atomic, project-contained writes with ownership and mode tracking;
- human and JSON diff, validation, provenance explanation, doctor, and reports;
- opt-in build-once supply-chain and real Docker/registry/kind execution profiles;
- immutable digest propagation through rendered, applied, and running workloads;
- closed, tamper-evident execution and release evidence with safe recovery cleanup;
- explicit `PASSED`, `FAILED`, `SKIPPED_MISSING_OPTIONAL_TOOL`,
  `BLOCKED_MISSING_REQUIRED_TOOL`, and `NOT_APPLICABLE` evidence states.

## Requirements and installation

Python 3.10-3.12, Git, PowerShell 7 (`pwsh`), Docker, and Docker Buildx are required for
normal locked-template composition. Java/Groovy and Kubernetes or supply-chain
validators are optional for static composition and remain visible as skipped when
unavailable. A real `kind-e2e` run makes kind, kubectl, kubeconform, Syft, and Trivy
required; exact supported versions are listed in
[execution-backed validation](docs/EXECUTION.md).

```sh
git clone https://github.com/k4nul/devops-stack-composer.git
cd devops-stack-composer
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
devops-stack doctor --project .
```

Template sources resolve in this order: explicit `--template NAME=PATH`, documented
environment variables, sibling development checkouts, the local cache, then the
public URL and exact commit in [`templates.lock.json`](templates.lock.json). A
different local `HEAD` is reported as a mismatch; it is never treated as an upgrade.

## Quick start

The included Python service has `/health`, `/ready`, tests, and a production zipapp
build. These commands inspect it, preview all generated files, write them explicitly,
verify the written tree, and produce reports:

```sh
devops-stack inspect --project examples/python-service
devops-stack generate --project examples/python-service
devops-stack generate --project examples/python-service --write
devops-stack validate --project examples/python-service
devops-stack diff --project examples/python-service --against generated
devops-stack report --project examples/python-service
```

`generate` is preview-only unless `--write` is present. `diff` exits non-zero for an
addition, content or mode change, removal, or failed composition, making a zero exit
code a strict no-change gate. Reports are written under `.devops-stack/reports/` and
require `--force` to replace existing report files.

An optional local image build is also side-effecting, so `generate --build-image`
requires `--write`. Docker's local load cannot retain registry attestations; that mode
disables Buildx SBOM/provenance attestations. The generated Jenkins path instead
builds and pushes exactly once, resolves the registry digest, and runs Syft, Trivy,
and deployment against that immutable subject.

The written tree includes:

```text
generated/
├── docker/       # Dockerfile, ignore rules, build wrapper, metadata
├── jenkins/      # Jenkinsfile, Job DSL, digest contract, environment intent
├── k8s/          # base plus dev, staging, and production overlays
└── .devops-stack-manifest.json
```

Useful follow-on commands:

```sh
devops-stack explain --project examples/python-service \
  generated/k8s/overlays/production/deployment.yaml
devops-stack explain --project examples/python-service config:$.image.registry
devops-stack templates list --project examples/python-service
devops-stack templates update --project examples/python-service   # preview only
devops-stack validate --project examples/python-service \
  --build-image --image-tag local-smoke
```

Static `generate` and `validate` never push an image. With the included configuration,
the explicit `execute` boundary pushes only to a run-owned loopback registry; an
explicit `supply-chain` configuration may instead select an existing registry. The
generated Jenkins pipeline owns authenticated external publication. Composer-managed
credential and Secret fields contain references only; user-supplied commands and
annotations are trusted verbatim and must never contain secret values.

## Complete v0.2 operator flow

Run the following sequence from a clean checkout. Record the `runId` returned by each
`execute` command as `SUPPLY_RUN_ID` or `KIND_RUN_ID` for the later read-only steps.
Execution plans can be previewed first with the same arguments under
`devops-stack execution plan` or with `execute --dry-run`.

1. Install the CLI in an isolated environment.

   ```sh
   python3 -m venv .venv
   . .venv/bin/activate
   python3 -m pip install -e .
   ```

2. Preview and write the deterministic static artifacts.

   ```sh
   devops-stack generate --project examples/python-service
   devops-stack generate --project examples/python-service --write
   ```

3. Validate the written tree.

   ```sh
   devops-stack validate --project examples/python-service
   ```

4. Check every tool required by the supply-chain profile.

   ```sh
   devops-stack doctor \
     --project examples/python-service \
     --profile supply-chain \
     --json
   ```

5. Run the build-once supply-chain profile.

   ```sh
   devops-stack execute \
     --project examples/python-service \
     --environment staging \
     --profile supply-chain \
     --image-tag local-supply-chain \
     --json
   ```

6. Inspect the artifact record and canonical registry digest.

   ```sh
   devops-stack artifact inspect \
     --project examples/python-service \
     --run SUPPLY_RUN_ID \
     --json
   ```

   The inspection must show a lowercase `sha256:` digest for the recorded repository;
   the next step independently enforces the one-build and subject-linkage contracts.

7. Re-evaluate the SBOM and complete Trivy JSON report against the configured
   vulnerability policy, and verify every subject linkage.

   ```sh
   devops-stack artifact verify \
     --project examples/python-service \
     --run SUPPLY_RUN_ID \
     --json
   ```

8. Run the real registry-and-kind profile.

   ```sh
   devops-stack doctor \
     --project examples/python-service \
     --profile kind-e2e \
     --json
   devops-stack execute \
     --project examples/python-service \
     --environment staging \
     --profile kind-e2e \
     --image-tag local-e2e \
     --json
   ```

9. Inspect the automatic rollback stage and independently verify the closed run.
   Rollback is part of `kind-e2e`; there is no separate rollback mutation command.

   ```sh
   sed -n '/## Kubernetes evidence/,/## Artifact identity/p' \
     examples/python-service/.devops-stack/runs/KIND_RUN_ID/report.md
   devops-stack evidence verify \
     --project examples/python-service \
     --run KIND_RUN_ID \
     --json
   ```

   The report must record a successful rollback result, and the offline verifier must
   pass the profile's required rollback stage.

10. Read the run report after fresh offline verification.

    ```sh
    devops-stack report \
      --project examples/python-service \
      --run KIND_RUN_ID
    ```

11. After assembling release assets as documented in the release guide, verify the
    closed asset directory independently.

    ```sh
    devops-stack release verify \
      --project . \
      --directory dist/release-v0.2.5 \
      --version 0.2.5 \
      --commit "$(git rev-parse HEAD)" \
      --json
    ```

The real kind path builds once, pushes only to a run-owned loopback registry,
resolves one canonical digest, deploys that digest to a run-owned kind cluster,
verifies rollout, HTTP health/readiness, rollback, and the running Pod `imageID`,
closes the evidence, then removes only resources whose immutable ownership was
recorded for that run. This local workflow never selects an external registry or
cloud cluster.

See [Execution](docs/EXECUTION.md) and [Evidence](docs/EVIDENCE.md) for profiles,
tool versions, cleanup recovery, and the same-digest proof.

## Documentation

- [Product and operating model](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Migrating from v0.1](docs/MIGRATING_FROM_V0_1.md)
- [Template resolution and locks](docs/TEMPLATE_INTEGRATION.md)
- [Validation evidence](docs/VALIDATION.md)
- [Execution-backed validation](docs/EXECUTION.md)
- [Evidence bundle and same-digest proof](docs/EVIDENCE.md)
- [Security boundaries](docs/SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Release process](docs/RELEASE.md)
- [Examples](docs/EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Roadmap](docs/ROADMAP.md)

Adapter-specific behavior is documented in
[Docker](docs/DOCKER_ADAPTER.md), [Jenkins](docs/JENKINS_ADAPTER.md), and
[Kubernetes](docs/KUBERNETES_ADAPTER.md).

## Development

After the editable install above:

```sh
python3 -m pip install \
  build==1.6.0 mypy==2.3.1 pip-audit==2.10.1 ruff==0.16.5 \
  twine==7.0.0 types-PyYAML==6.0.12.20260815
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests examples/python-service
ruff check src tests --select F
mypy --follow-imports=skip --ignore-missing-imports \
  src/devops_stack_composer/release_assets.py \
  src/devops_stack_composer/release_validation.py
python3 -m build
python3 -m twine check dist/*.whl dist/*.tar.gz
git diff --check
```

CI installs the built wheel, audits dependencies, runs static checks and all tests,
resolves the real public locked commits from an empty cache, performs the complete
example workflow, checks deterministic rerendering and source cleanliness, and runs a
single-platform local Docker build without push. A separate workflow runs the real
owned registry and kind execution, verifies its closed evidence, confirms cleanup,
and uploads the evidence for inspection.

## License

DevOps Stack Composer is released under the [MIT License](LICENSE). Resolved source
templates remain independent MIT-licensed projects and are not vendored here; their
origin and commit are recorded in the lock and generated manifest.
