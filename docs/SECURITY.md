# Security

DevOps Stack Composer treats project paths, template checkouts, configuration,
subprocess output, and generated ownership as security boundaries. It reduces risk at
those boundaries but is not a sandbox for untrusted code.

## Trust model

The following inputs must be reviewed as code:

- `devops-stack.yaml`, especially build, test, and run commands;
- the three full Git commits in `templates.lock.json`;
- an existing Dockerfile selected by configuration;
- application source copied into Docker build context;
- generated Jenkins and Kubernetes artifacts before production use.

Adapters invoke locked template scripts, and generated Jenkins pipelines execute
declared application commands. Do not compose an untrusted branch with production
credentials merely because its YAML passes schema validation.

## Persistent write safety

All writes use project-relative normalized paths. Absolute paths, empty file paths,
NUL bytes, `..` traversal, and resolved paths outside the project root are rejected.
Containment is checked again after parent creation to reduce symlink race exposure.
Files are written to a same-directory temporary file, flushed and synced, assigned an
explicit mode, and atomically replaced.

Generation is preview-only by default. Persistent artifacts are written only after
composition validation passes and `--write` is explicit. Existing unowned paths and
non-regular targets are conflicts. The generated manifest records hashes and modes so
later user modifications are detectable.

`--force` is deliberately narrow: it can replace a conflict at a path in the current
artifact plan, including a colliding file not owned by an earlier manifest. The plan
shows that replacement before the write. It cannot absorb unrelated content elsewhere
in `generated/`, follow a symlink to write outside the project, or delete a stale
artifact. Stale paths require explicit operator review and removal.

Reports also refuse to overwrite existing files unless `report --force` is explicit.
Lock updates require `templates update --write` and use an atomic replacement.

## Template execution

Resolution verifies interface markers and the locked Git commit. Upstream commands
run from ephemeral staging directories with fixed timeouts and reduced environment
allowlists. Source repositories are not used as output directories and are not
modified. Archive/staging extraction rejects traversal, backslash ambiguity, links,
and non-regular archive members.

The lock proves content identity, not that content is benign. Review upstream changes
before updating a pin. The updater fetches and checks candidate markers and license,
but adapter compatibility and security review remain human/test gates.

## Secrets and credentials

Plain deployment environment names that look sensitive are rejected by schema.
Secrets are represented only as Kubernetes Secret names and keys. The composer never
creates a Secret value. Jenkins output includes a registry credential ID only; the
controller supplies its value through `withCredentials`.

Registry authentication uses `--password-stdin`, disables shell tracing, stores
Docker client state in a temporary `DOCKER_CONFIG`, logs out on exit, and removes the
directory. SCM Job DSL rejects URL userinfo, and template repository URLs should never
contain embedded credentials.

Diagnostics and report serializers redact password, token, secret, private-key,
access-key, API-key, and authorization fields while preserving safe references such
as a credential ID or Secret name. Upstream Jenkins/Kubernetes payload sanitizers also
remove token-like values, sensitive keys, volatile timestamps, and absolute source
paths. Diff output redacts sensitive assignment values, and doctor reports whether a
template environment variable is set without printing its value.

Redaction is a final safety layer, not permission to pass secrets through arbitrary
free-form command output. Template and application commands should avoid printing
credentials. Inspect report files before publishing them: they intentionally contain
non-secret operational data such as project identity, source origins, commits,
commands, and bounded stderr.

## Generated workload security

Generated Dockerfiles run as the configured positive UID. Existing Dockerfiles must
prove that UID in their final stage. Generated Kubernetes containers run non-root,
drop all capabilities, use `RuntimeDefault` seccomp, and can enforce a read-only root
filesystem. Pods and ServiceAccounts disable automatic API token mounting. Production
Namespaces enable the Kubernetes `restricted` Pod Security profile.

These settings do not replace image vulnerability review, registry policy, network
policy, admission controls, RBAC, or cluster hardening. The composer currently does
not generate RBAC grants or NetworkPolicy objects.

## Reporting a vulnerability

Do not put credentials, exploit details for a live system, or private source URLs in a
public issue. Use the repository owner's private security-reporting channel once the
GitHub repository publishes one. Until then, contact the owner privately and include
the affected version, reproducible impact, and a minimal redacted demonstration.
