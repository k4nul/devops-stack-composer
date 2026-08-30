# DevOps Stack Composer

DevOps Stack Composer turns one declarative application contract into a coherent
Docker build, Jenkins delivery pipeline, and Kubernetes deployment tree. It is an
orchestration layer over three independent public templates: it pins and invokes
their supported interfaces instead of copying their repositories into this one.

The current release is `v0.1.0` and the configuration API is
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
- explicit `PASSED`, `FAILED`, `SKIPPED_MISSING_OPTIONAL_TOOL`, and
  `BLOCKED_MISSING_REQUIRED_TOOL` evidence states.

## Requirements and installation

Python 3.10-3.12, Git, PowerShell 7 (`pwsh`), Docker, and Docker Buildx are required for
normal locked-template composition. Java/Groovy and Kubernetes or supply-chain
validators are optional and remain visible as skipped when unavailable.

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
disables Buildx SBOM/provenance attestations while the Jenkins push path retains the
configured settings and performs its documented local Syft/Trivy checks first.

The written tree includes:

```text
generated/
├── docker/       # Dockerfile, ignore rules, build wrapper, metadata
├── jenkins/      # Jenkinsfile, Job DSL, per-environment intent
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

No command pushes an image during local validation. Registry publication remains an
authenticated Jenkins responsibility. Composer-managed credential and Secret fields
contain references only; user-supplied commands and annotations are trusted verbatim
and must never contain secret values.

## Documentation

- [Product and operating model](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Template resolution and locks](docs/TEMPLATE_INTEGRATION.md)
- [Validation evidence](docs/VALIDATION.md)
- [Security boundaries](docs/SECURITY.md)
- [Examples](docs/EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

Adapter-specific behavior is documented in
[Docker](docs/DOCKER_ADAPTER.md), [Jenkins](docs/JENKINS_ADAPTER.md), and
[Kubernetes](docs/KUBERNETES_ADAPTER.md).

## Development

After the editable install above:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests examples/python-service
git diff --check
```

CI also installs the built wheel, resolves the real public locked commits from an
empty cache, performs the complete example workflow, checks deterministic rerendering
and source cleanliness, and runs a single-platform local Docker build without push.

## License

DevOps Stack Composer is released under the [MIT License](LICENSE). Resolved source
templates remain independent MIT-licensed projects and are not vendored here; their
origin and commit are recorded in the lock and generated manifest.
