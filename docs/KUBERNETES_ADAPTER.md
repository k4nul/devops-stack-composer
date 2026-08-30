# Kubernetes adapter

`KubernetesAdapter` creates a Kustomize application layout from the normalized model
and uses `k8s-platform-template` as a read-only platform compatibility and security
validation source.

## Generated layout

```text
generated/k8s/
├── base/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── serviceaccount.yaml
│   ├── configmap.yaml          # only when any environment has plain values
│   └── kustomization.yaml
├── overlays/
│   ├── dev/
│   ├── staging/
│   └── production/
│       ├── namespace.yaml
│       ├── deployment.yaml
│       ├── service.yaml
│       ├── configmap.yaml      # when applicable
│       └── kustomization.yaml
└── platform-context.json
```

Each overlay references `../../base` and its own Namespace, sets that Namespace in
Kustomize, and uses replacement patches for the environment's Deployment, Service,
and optional ConfigMap. This makes the fully resolved environment values visible in
the generated source rather than depending on implicit patch accumulation.

The image initially contains the normalized fixed value or `__IMAGE_TAG__`. The
Jenkins pipeline replaces it in a temporary overlay immediately before deployment;
it does not mutate checked-in or generated files.

## Workload contract

Every environment receives its resolved replica count, namespace, Service type and
port, container port, probes and timings, resources, rollout controls, and rollback
history limit. Plain environment data becomes ConfigMap string data. Secret
references become container `secretKeyRef` entries; the adapter never creates a
Kubernetes Secret or stores its value.

The pod and container security contexts include the configured positive UID,
`runAsNonRoot`, `RuntimeDefault` seccomp, disabled privilege escalation, and all Linux
capabilities dropped. `readOnlyRootFilesystem` is emitted when enabled. The pod and
ServiceAccount both disable automatic service-account-token mounting.

Deployments record selected image architectures on both Deployment and pod-template
annotations. All pods select `kubernetes.io/os: linux`. A single-platform image also
selects its matching `kubernetes.io/arch`; a multi-platform image leaves architecture
scheduling to the cluster while retaining the complete annotation.

## Production differences

Production inherits the same secure container baseline as the other environments and
adds:

- Namespace Pod Security Admission labels enforcing, auditing, and warning at the
  `restricted` profile, version `v1.30` for enforcement;
- `minReadySeconds: 10` and `progressDeadlineSeconds: 600` on the Deployment;
- semantic policy gates for minimum replicas, approval, resource limits, read-only
  root filesystem, non-root UID, disabled privilege escalation, enabled rollback,
  and rollout availability.

The actual replica and resource values remain declarative environment overrides; the
adapter does not silently rewrite them to pass policy.

## Upstream platform integration

With upstream validation enabled, the adapter uses PowerShell 7 to query the profile
catalog, environment presets, render matrix, and a platform plan. It exercises the
`minimal-application` profile with the template's `nginx-web` application, invokes
the official platform renderer, then runs the official rendered-bundle,
security-baseline, and placeholder checks in an isolated temporary source tree.
Public example values are copied to a private, temporary validation-values file and
known documentation placeholders are replaced with reserved `.invalid` validation
names. The placeholder validator is scoped to the rendered deployable `k8s/` tree;
example input files remain documentation and are not treated as workload manifests.

`platform-context.json` contains a compact, deterministic summary: the selected
integration probe, lock state, query counts/statuses, render evidence, and validator
statuses. Volatile timestamps, absolute source paths, and sensitive-looking values
are removed. The rendered upstream platform bundle itself is not copied into the
application output.

## Validation

An internal validator parses every YAML artifact and enforces mapping shape,
Kustomize references, Namespace consistency, workload selectors, architectures,
probes, ports, resource quantities, rolling-update safety, secret references,
security context, and ServiceAccount token behavior.

If installed, `kustomize build` and `kubectl kustomize` render all three overlays.
`kubeconform -strict -summary -` then validates each available render. Missing
`kustomize`, `kubectl`, or `kubeconform` is
`SKIPPED_MISSING_OPTIONAL_TOOL`, never `PASSED`. A present tool that rejects an
overlay is `FAILED`. PowerShell is required for the official upstream integration and
its absence is `BLOCKED_MISSING_REQUIRED_TOOL`.

The official rendered-bundle check is explicitly pinned to its `kubeconform` mode.
This keeps repository validation offline: if kubeconform is unavailable, the
upstream structural preflight runs and the schema check is reported as skipped.
Composer does not allow the upstream `auto` mode to select `kubectl apply`, which
may require API discovery even with client-side dry-run.

The adapter does not contact a cluster, run `kubectl apply`, or generate Helm charts.
Application deployment is the generated Jenkins pipeline's responsibility.
