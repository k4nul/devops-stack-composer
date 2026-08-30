# Jenkins adapter

`JenkinsPipelineAdapter` generates an application delivery pipeline while keeping
Jenkins controller configuration and credential values outside the repository.

## Generated files

| Path below `generated/` | Purpose |
| --- | --- |
| `jenkins/Jenkinsfile` | Declarative build, test, supply-chain, publication, and deployment workflow. |
| `jenkins/job-dsl.groovy` | SCM-backed multibranch job definition. |
| `jenkins/README.md` | Generated ownership boundary and branch routing. |
| `jenkins/environments/{dev,staging,production}.json` | Resolved routing, image expression, namespace, replicas, overlay, and approval facts. |

The Job DSL expects seed bindings `SCM_REPOSITORY_URL`, optional
`SCM_BRANCH_INCLUDES`, and optional `SCM_CREDENTIALS_ID`. It refuses a placeholder
repository, control characters, and URL userinfo. It points each branch job at
`generated/jenkins/Jenkinsfile` and retains 30 orphaned items.

The adapter does not generate JCasC. Jenkins plugins, agents, tools, security realm,
authorization, seed job, SCM credentials, and registry credential values remain
controller/operator responsibilities.

## Pipeline order

The generated stages are ordered as follows:

1. resolve and validate a concrete image tag;
2. resolve the locked Docker template path;
3. run the application build command;
4. run the application test command;
5. validate the container build plan without pushing;
6. optionally load a single-platform image for local SBOM or scan work;
7. run the supply-chain stage;
8. authenticate and publish the image;
9. deploy the branch-routed environment, with the production approval stage before
   production when configured.

Branch conditions use the GLOB patterns declared for each environment. A semantic
validator rejects one pattern mapped to multiple environments.

For `branch-sha`, the pipeline sanitizes and bounds the branch slug and appends the
12-character Git SHA. `git-sha` uses that SHA, `semver` requires a non-empty
`VERSION` parameter, and `fixed` uses the declared value. Every strategy is checked
against Docker tag syntax before load, push, or deployment.

## Supply chain and publication

When enabled, the pipeline uses Syft to write
`out/supply-chain/sbom.json` and archives it, then uses Trivy at the configured
severity threshold. These checks occur before registry publication. `failOn: never`
runs Trivy with exit code zero while retaining all severities.

The locked Docker template's load and push modes are separate Buildx executions.
Consequently, this release proves the local pre-push build was scanned but does not
claim that its digest is identical to the bytes rebuilt by the official push wrapper.
Digest-bound promotion or post-push digest verification is a documented next step.

Local SBOM or scan commands need a loadable image and therefore exactly one selected
architecture. Requesting either with multiple architectures is a `FAILED` capability
check and blocks final publication. Provenance is delegated to the Docker build
wrapper and official template's push path. The preceding local `--load` disables
Buildx SBOM/provenance attestations because Docker cannot attach them to a locally
loaded image; Syft and Trivy still inspect that local image before publication.

Registry publication wraps `docker login --password-stdin` in Jenkins
`withCredentials`. Only the configured credential ID is generated. A temporary
`DOCKER_CONFIG` is removed on exit and shell tracing is disabled around authentication.

## Deployment and rollback

For the routed environment, Jenkins copies its Kustomize overlay to a temporary
directory, sets the concrete image with `kustomize edit set image`, renders it, checks
that no `__IMAGE_TAG__` remains, and applies the result with `kubectl`. It then waits
up to five minutes for Deployment rollout status.

On failure, rollback is attempted only when `kubectl apply` reported that the target
Deployment was created or configured. This avoids undoing an earlier healthy revision
when the apply never began a rollout. Rollback can be disabled per environment.

## Validation boundary

PowerShell 7 is required for the locked Jenkins template's official plan and export
interfaces. The adapter archives the exact locked Git commit into an ephemeral stage,
runs both JSON plan scripts, and verifies the Job DSL exporter output without writing
the source checkout. Output is bounded and scrubbed of volatile paths and sensitive
material.

Generated Groovy receives deterministic structural checks. If standalone `groovy` is
installed, both files also receive a parser check; otherwise that check is
`SKIPPED_MISSING_OPTIONAL_TOOL`. The controller-backed Declarative/Job DSL linter is
not configured by this project and is always reported as skipped. A standalone
Groovy parse does not prove Jenkins plugin semantics.

Cross-project validation reads each environment JSON record and exact Jenkins
environment assignments, and checks Job DSL application identity. This is separate
from the adapter's canonical contract declaration.

## Agent prerequisites

A Jenkins agent needs the application build/test toolchain, Git, the
`devops-stack` command or an explicit `DEVOPS_STACK_DOCKER_TEMPLATE`, Docker with
Buildx, and Kubernetes `kustomize` plus `kubectl`. Syft and Trivy are required when
their features are enabled. The controller must provide the configured registry
credential and any required cluster authentication.
