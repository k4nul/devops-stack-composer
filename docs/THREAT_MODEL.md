# Threat model

DevOps Stack Composer reduces risk around local execution and evidence handling. It
is not a sandbox for untrusted application source or unreviewed template commits.

## Protected assets

- the operator's existing Docker containers and Kubernetes clusters;
- source files and generated-file ownership;
- credentials and private process output;
- the image identity carried from build through runtime;
- the integrity and source identity of published release files;
- the truthfulness of passing, failing, skipped, and incomplete evidence.

## Trust boundaries and controls

| Surface | Primary controls |
| --- | --- |
| CLI arguments and identifiers | Closed enums, length/character validation, normalized relative paths, no shell execution. |
| Project filesystem | Resolved project root, symlink rejection, containment recheck, atomic writes, closed evidence inventories. |
| Child processes | Executable allowlist, argument arrays, project-contained working directories, environment allowlist, timeout/deadline, cancellation, process-group termination, bounded output, redaction. |
| Template input | Full Git commit pins, interface markers, isolated staging, archive traversal/link rejection, executable validation seams. |
| Registry | Loopback binding, random name and port, immutable container ID, run labels, readiness deadline, exact ownership before reuse or deletion. |
| kind cluster | Random run-bound name, pinned node image digest, private kubeconfig, exact node IDs/roles, no default-context mutation, ownership check before cleanup. |
| Artifact identity | One build invocation, registry-resolved digest, digest-only workload references, rendered/applied/runtime comparison. |
| Evidence | Strict schemas, stable JSON, byte/file bounds, redaction, closed SHA-256 inventory, cross-file subject linkage, explicit incomplete/failure state. |
| Release archives | Regular-file-only inputs, canonical top-level names, compressed/uncompressed limits, duplicate/path/link rejection, metadata and nested evidence validation. |
| Publication | Exact tag/HEAD/source equality, clean worktree, closed local set, fresh download equality, GitHub/Sigstore attestation verification constrained to repository, workflow, tag ref, and source commit. |

## Attacks explicitly covered

- Shell metacharacters remain literal arguments because no orchestration command uses
  a shell.
- `..`, absolute paths, NUL bytes, symlinks, and changed containment boundaries are
  rejected before reads or writes.
- Malicious project, image, registry, namespace, and run names are rejected by their
  closed grammars before resource creation.
- A colliding resource name is not accepted without matching immutable IDs, labels,
  image, role, and run identity.
- Cleanup does not use a name prefix or broad label query as authority to delete.
- Process output is capped and common secret forms plus explicit secret environment
  values are redacted.
- A stale tag, missing registry digest, second build, mutable deployment image, or
  changed Pod image ID cannot satisfy the same-digest gate.
- Evidence checksum changes, unknown files, missing files, mixed run identities, and
  success-bit edits are detected.
- Wheels and tarballs are inspected without extracting into the project; nested
  release evidence is extracted only after path, type, count, and size checks.
- GitHub download arguments use a validated `OWNER/REPO` value. `GH_TOKEN` is scoped
  only to GitHub CLI verification calls and is never serialized.

## Residual risks

- Application builds and pinned template scripts execute code. Review both before
  running them on a machine that holds valuable credentials.
- A compromised Docker daemon or host kernel can defeat process and container
  boundaries.
- SHA-256 evidence without a signature establishes integrity relative to the same
  bundle, not creator identity. Only published assets with verified GitHub
  attestations add signing identity.
- The local registry is intentionally unauthenticated and HTTP-only. Loopback binding
  and short lifetime limit exposure; it is unsuitable for shared or production use.
- Vulnerability results depend on the scanner database available at execution time.
  The database metadata is recorded, but a clean scan is not a permanent guarantee.
- A workflow with permission to change the release workflow can create valid future
  attestations. Branch protection and repository access control remain owner duties.
- TOCTOU is reduced through immutable IDs, digest references, and containment rechecks
  but cannot be eliminated against a hostile local administrator.

## Security review rule

Do not weaken a required gate, enlarge a timeout without diagnosing the blocked
operation, or convert an unavailable tool into `PASSED`. New external commands need
an argument-vector call, explicit executable and environment allowlists, bounded
output, a timeout, redaction tests, and failure classification.
