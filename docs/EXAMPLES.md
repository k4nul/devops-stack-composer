# Examples

The repository includes one runnable Python HTTP service and one smaller Node.js
inspection fixture.

## Install the CLI for development

From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
devops-stack --version
```

Python 3.10-3.12 is required. The source templates can resolve from the documented
local locations, a cache, or their locked public remotes.

## Python service

[`examples/python-service`](../examples/python-service) is a standard-library HTTP
server with `/health`, `/ready`, a 404 response, unit tests, and a production zipapp.

Run application behavior and build checks:

```sh
cd examples/python-service
python3 -m unittest discover -s tests -v
mkdir -p build
python3 -m zipapp app -o build/service.pyz
python3 build/service.pyz
```

The service listens on port 8000 by default. In another terminal:

```sh
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/ready
```

Use `Ctrl-C` to stop it.

From the repository root, inspect and compose the example:

```sh
devops-stack inspect --project examples/python-service
devops-stack init --project examples/python-service --dry-run
devops-stack generate --project examples/python-service
devops-stack generate --project examples/python-service --write
devops-stack validate --project examples/python-service
devops-stack diff --project examples/python-service --against generated
devops-stack explain --project examples/python-service \
  generated/k8s/overlays/production/deployment.yaml
devops-stack explain --project examples/python-service config:$.image.registry
devops-stack report --project examples/python-service
```

The supplied config deliberately keeps Docker cache disabled because the locked
template has no cache input. It selects one `linux/amd64` architecture so enabled
Syft/Trivy pre-push checks have a valid local-image route in the generated Jenkins
pipeline. Staging and production refer to an external `python-service-secrets` Secret
key named `API_TOKEN`; no value or Secret resource is generated.

After a successful write, inspect:

```text
examples/python-service/generated/docker/
examples/python-service/generated/jenkins/
examples/python-service/generated/k8s/base/
examples/python-service/generated/k8s/overlays/dev/
examples/python-service/generated/k8s/overlays/staging/
examples/python-service/generated/k8s/overlays/production/
examples/python-service/generated/.devops-stack-manifest.json
examples/python-service/.devops-stack/reports/
```

To include a real local Docker load build during validation:

```sh
devops-stack validate --project examples/python-service \
  --build-image --image-tag local-smoke
```

This requires a working Docker daemon and Buildx. It does not push. The regular
generated Jenkins pipeline owns authenticated publication.

## JSON output and project comparison

Most inspection and workflow commands support JSON:

```sh
devops-stack inspect --project examples/python-service --json
devops-stack generate --project examples/python-service --json
devops-stack validate --project examples/python-service --json
devops-stack diff --project examples/python-service --against project --json
```

`--against project` maps generated Dockerfile, Dockerfile-specific ignore file, and
Jenkinsfile to conventional root paths when present; remaining generated paths use
their relative names. It is a comparison only and never overwrites those project
files.

## Node.js fixture

[`tests/fixtures/apps/node-service`](../tests/fixtures/apps/node-service) exists to
exercise runtime detection and a structurally different build. It is a test fixture,
not a second supported production example.

```sh
cd tests/fixtures/apps/node-service
npm test
npm run build
```

When no lockfile is present, inspection proposes
`npm install --no-package-lock && npm run build`; it does not create a lockfile as a
side effect of inspection.
