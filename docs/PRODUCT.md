# Product

DevOps Stack Composer turns one declarative application contract into coordinated
Docker, Jenkins, and Kubernetes artifacts. It is an orchestration layer over three
independent template repositories; it does not vendor those repositories or replace
their specialist tooling.

## Problem

Container, pipeline, and deployment configuration often repeat the same facts. An
image repository can drift between a build and a deployment, a service can expose a
different port than its container, or production policy can be documented without
being enforced. The composer validates one input, normalizes those shared facts once,
projects them through three adapters, and then checks the rendered bytes against the
same model.

The shared contract includes application and service identity, image coordinates and
tag strategy, architectures, ports, probes, runtime user, environment names,
namespaces, secret references, build artifact, and branch-to-environment routing.

## Operator workflow

1. Run `devops-stack inspect` to review detected runtime and existing DevOps files.
2. Run `devops-stack init` to create a conservative, explicitly review-marked
   `devops-stack.yaml`.
3. Edit the file until it represents the application and production policy.
4. Run `devops-stack doctor` to distinguish required tooling from optional tooling.
5. Run `devops-stack generate` to preview the complete plan.
6. Run `devops-stack generate --write` to write each validated artifact atomically
   under `generated/` and record their ownership manifest.
7. Run `devops-stack validate`, `diff`, `explain`, and `report` as review and CI gates.

Generation is preview-only unless `--write` is present. A failed validation never
writes generated artifacts. `--force` permits replacement of explicitly listed
conflicts at planned output paths; it does not delete stale files or absorb unrelated
unowned files elsewhere in the generated tree.

## Outputs

The current adapters generate:

- a Dockerfile or isolated copy of an existing Dockerfile, a Dockerfile-specific
  ignore file, the official template's 15-key environment contract, a build wrapper,
  and capability metadata;
- a Declarative Jenkinsfile, multibranch Job DSL, an ownership-boundary README, and
  one pipeline environment record for each of `dev`, `staging`, and `production`;
- a Kustomize base, three environment overlays, Namespace resources, and a sanitized
  platform-integration context record;
- `generated/.devops-stack-manifest.json`, containing hashes, modes, provenance,
  template commits, adapter versions, configuration hash, environments, and the
  validation summary.

Reports are written separately to `.devops-stack/reports/` in Markdown and JSON.

## Guarantees and limits

The composer provides deterministic rendering for a fixed configuration and fixed
template commits, strict schema and semantic validation, safe project-contained
writes, and explicit status reporting. `PASSED` is never substituted for an
unavailable validator: optional gaps are `SKIPPED_MISSING_OPTIONAL_TOOL`, while
missing required tooling is `BLOCKED_MISSING_REQUIRED_TOOL` and fails the run.

The composer is not a Jenkins controller, a Kubernetes cluster manager, a registry,
or a secrets manager. It does not create credentials or Kubernetes Secret values.
It does not claim Docker cache wiring because the locked Docker template has no
official cache input. Standalone Groovy parsing, when installed, is not equivalent to
controller-backed Jenkins plugin validation.

The project is currently version `0.1.0` and classified as alpha. Review generated
artifacts and validate them in the same toolchain used for deployment.

## Independence and licensing

The composer and each source template are independent MIT-licensed projects. Only
documented template interfaces and executable scripts are invoked. Template sources
remain in their own repositories and are resolved at commits recorded in
[`templates.lock.json`](../templates.lock.json).
