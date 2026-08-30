# Writing an adapter

An adapter is a deterministic projection from `NormalizedDevOpsModel` plus one
resolved template source to immutable artifacts and typed evidence. It must preserve
the shared contract, use the upstream project's real interface, and leave all
persistent writes to `ArtifactWriter`.

## Core result types

Adapters return the types in `adapters/base.py`:

```python
GeneratedArtifact(path, content, mode=0o644, origins=())
AdapterDiagnostic(status, check, message, command=(), details={})
AdapterResult(
    adapter,
    adapter_version,
    template_commit,
    artifacts,
    contract,
    diagnostics=(),
)
```

Artifact paths are POSIX-style paths relative to `generated/`. They must be unique
across all adapters, deterministic, and free from host-specific absolute paths.
Record a precise mode and useful origins; the manifest uses both for ownership,
integrity, and `explain` output.

The adapter name is currently one of `docker`, `jenkins`, or `kubernetes`. The
manifest and cross-validator require all three. Adding another first-class adapter is
therefore a product/schema change, not a plug-in-only edit.

## Implementation rules

1. Consume the normalized model; do not re-read YAML or recalculate shared image,
   port, namespace, probe, or routing facts independently.
2. Keep rendering in memory. Do not write the application project or source template.
3. Prefer an upstream documented script or file contract. If none exists, make the
   file/subprocess boundary explicit and version it in the template lock.
4. Check the source matches the lock before executing it. Stage the exact locked Git
   content under a new temporary root, reject unsafe archive members and symlinks,
   and overlay only generated inputs needed by the command.
5. Run subprocesses without a shell-built command string, with a timeout, constrained
   environment, captured output, and no credential values.
6. Bound and sanitize stdout/stderr before diagnostics. Do not expose template source
   absolute paths, tokens, authorization headers, or volatile output.
7. Report exactly `PASSED`, `FAILED`, `SKIPPED_MISSING_OPTIONAL_TOOL`, or
   `BLOCKED_MISSING_REQUIRED_TOOL`. A structural approximation cannot be labeled as a
   parser or integration pass.
8. Describe unsupported upstream capabilities as failures when the user requests
   them. Never invent flags or claim a feature was wired.

Use the rendering entry point's `validate_upstream` flag in tests that need pure,
deterministic projection. Normal composition enables upstream validation. An adapter
can have a separate execution option, such as Docker's local build, but it must not
change default no-push behavior.

## Contract validation

Set `AdapterResult.contract` to `model.contract()`. That declaration is necessary but
not sufficient. Add an artifact-derived validator in `validation.py` that parses the
primary files and compares their actual values with the model. It must:

- fail on a missing primary artifact;
- fail, rather than crash, on malformed JSON/YAML or an unexpected shape;
- compare exact assignments or structured values instead of substring presence;
- report mismatch paths with expected and received values;
- cover every shared value represented by that adapter.

Also add semantic checks when correctness depends on relationships across
environments or adapters rather than one artifact.

## Source and lock changes

If the adapter uses a new upstream interface, update its `schemaVersion` and marker
requirements deliberately. A new template requires coordinated edits to the lock
schema, `TEMPLATE_KEYS`, resolver environment variables and markers, composition,
manifest schema, CLI choices, reports, docs, and tests. Do not make runtime discovery
silently accept an unpinned repository.

## Tests

At minimum, cover:

- deterministic artifacts, paths, modes, and origins;
- projection of every adapter-owned model field;
- the official upstream success path in an isolated fixture repository;
- wrong locked commit and missing required script behavior;
- missing optional and required tools with exact statuses;
- non-zero, timeout, invalid JSON, unsafe path/member, symlink, and sensitive-output
  cases;
- dirty working-tree resistance by proving execution uses locked bytes;
- artifact mutations and malformed shapes through cross-contract validation;
- no mutation of source repositories or the application during preview.

Run the focused adapter and cross-validation tests before the complete suite. Review
the final diff for accidental fixture output, absolute paths, captured secrets, and
new dependencies.
